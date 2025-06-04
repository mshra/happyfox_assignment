import pprint
import time
import os.path
import base64
import datetime
import json
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import db

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def perform_action(service, msg_id):
    actions = rules.get('actions')

    for action in actions:
        action_type  = action.get('type')
        action_value = action.get('value')

        match action_type:
            case "mark_as_read":
                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={'removeLabelIds': ['UNREAD']}
                ).execute()
            case "mark_as_unread":
                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={'addLabelIds': ['UNREAD']}
                ).execute()
            case "move_to":
                target_label = action_value.upper()
                labels = service.users().labels().list(userId='me').execute().get('labels', [])

                # if the label is not present then create a new label
                if not any(label['name'] == target_label for label in labels):
                    new_label = {
                        'name': target_label,
                        'labelListVisibility': 'labelShow',
                        'messageListVisibility': 'show'
                    }
                    service.users().labels().create(userId='me', body=new_label).execute()

                new_body = {'addLabelIds': [target_label]}

                if target_label != 'INBOX':
                    new_body['removeLabelIds'] = ['INBOX']

                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body=new_body
                ).execute()

def check_condition(field_value, predicate, rule_value):
    if predicate == "contains":
        return rule_value.lower() in field_value.lower()
    elif predicate == "does_not_contain":
        return rule_value.lower() not in field_value.lower()
    elif predicate == "equals":
        return field_value.lower() == rule_value.lower()
    elif predicate == "does_not_equal":
        return field_value.lower() != rule_value.lower()
    elif predicate in ["less_than_days", "greater_than_days", "less_than_months", "greater_than_months"]:
        email_date = parsedate_to_datetime(field_value)
        current_date = datetime.datetime.now(email_date.tzinfo)

        if "days" in predicate:
            diff_days = (current_date - email_date).days
            if predicate == "less_than_days":
                return diff_days < int(rule_value)
            else:
                return diff_days > int(rule_value)

        elif "months" in predicate:
            diff_months = (current_date.year - email_date.year) * 12 + (current_date.month - email_date.month)
            if predicate == "less_than_months":
                return diff_months < int(rule_value)
            else:
                return diff_months > int(rule_value)
    else:
        return False

def evalute_rules(data, service):
    predicate = rules.get('predicate')
    results = []

    for rule in rules.get('rules'):
        rule_field     = rule.get('field')
        rule_predicate = rule.get('predicate')
        rule_value     = rule.get('value')

        value = ''
        match rule_field:
            case "from":
                value = data.get('From')
            case "subject":
                value = data.get('Subject')
            case "message":
                value = data.get('Snippet')

                # if the value was not found in snippet of the email,
                # then check the whole body of email for value.
                if not check_condition(value, rule_predicate, rule_value):
                    email_body = service.users().messages().get(userId='me', id=data.get('id'), format='full').execute()['payload']['parts'][0]['body']['data']
                    value = str(base64.b64decode(email_body), encoding='utf-8')
            case "date_received":
                value = data.get('Date')

        results.append(check_condition(value, rule_predicate, rule_value))
    if predicate == "all":
        return all(results)
    else:
        return any(results)

def process_message(msg, service):
    if evalute_rules(msg, service):
        perform_action(service, msg['id'])

def read_messages(service, messages):
    extract_header = lambda headers, name: next((h['value'] for h in headers if h['name'] == name),'')

    msg_data   = []
    db_records = []

    for msg in messages:
        id         = msg['id']
        snippet    = msg['snippet']
        subject    = extract_header(msg['payload']['headers'], 'Subject')
        from_email = extract_header(msg['payload']['headers'], 'From')
        date       = extract_header(msg['payload']['headers'], 'Date')

        db_records.append((id, subject, from_email, date, snippet))
        msg_data.append({
            'id': id,
            'Subject': subject,
            'From': from_email,
            'Date': date,
            'Snippet': snippet
        })

    db.batch_insert(db_records)

    with ThreadPoolExecutor(max_workers=5) as exec:
        future_to_message = {
            exec.submit(process_message, msg, service): msg
            for msg in msg_data
        }

def main():
  creds = None
  # The file token.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first time.
  if os.path.exists("token.json"):
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)

  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())
    else:
      flow = InstalledAppFlow.from_client_secrets_file(
          "credentials.json", SCOPES
      )
      creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open("token.json", "w") as token:
      token.write(creds.to_json())

  try:
    service = build("gmail", "v1", credentials=creds)

    nextPageToken  = None

    failed = []
    while True:
        resp = service.users().messages().list(userId="me", labelIds=['INBOX'], pageToken=nextPageToken).execute()
        message_ids = resp.get('messages')
        nextPageToken = resp.get('nextPageToken')

        messages = []
        batch = service.new_batch_http_request(callback=lambda req_id, resp, excp : messages.append(resp) if excp is None else failed.append(excp))

        for message_id in message_ids:
            request = service.users().messages().get(userId='me', id=message_id['id'], format='metadata')
            batch.add(request)

        batch.execute()
        read_messages(service, messages)

        if not nextPageToken:
            break

        time.sleep(1) # to avoid overwhelming the api
  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
    # load the rules file in memory
    with open('rules.json') as r:
        rules = json.load(r)

    main()
