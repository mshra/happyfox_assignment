import pprint
import os.path
import base64
import datetime
import json

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
                # build this as well
                pass

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
        email_date = parse_email_date(field_value)
        current_date = datetime.datetime.now(email_date.tzinfo)

        # Calculate difference
        if "days" in predicate:
            diff_days = (current_date - email_date).days
            if predicate == "less_than_days":
                return diff_days < int(rule_value)
            else:  # greater_than_days
                return diff_days > int(rule_value)

        elif "months" in predicate:
            diff_months = (current_date.year - email_date.year) * 12 + (current_date.month - email_date.month)
            if predicate == "less_than_months":
                return diff_months < int(rule_value)
            else:  # greater_than_months
                return diff_months > int(rule_value)
    else:
        return False

def evalute_rules(data):
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
            case "date_received":
                value = data.get('Date')

        results.append(check_condition(value, rule_predicate, rule_value))

    if predicate == "all":
        return all(results)
    else:
        return any(results)

def extract_data(message, service):
    # initially store the snippet of the message
    data = {
        'Snippet': message['snippet']
    }

    headers = message['payload']['headers']

    for header in headers:
        if header['name'] in ["Subject", "From", "Date"]:
            data.update({ header['name']: header['value']})

    db.insert(message['id'], data['Subject'], data['From'], data['Date'], data['Snippet'])

    # perform rule based action on the message metadata
    if evalute_rules(data):
        perform_action(service, msg_id=message.get('id'))

def read_message(service, msg_id):
    # fetch the data of message
    message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    extract_data(message, service)

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

    messages      = []
    nextPageToken = None

    while True:
        resp = service.users().messages().list(userId="me", pageToken=nextPageToken).execute()
        messages += resp.get('messages')
        nextPageToken = resp.get('nextPageToken')

        # parsing first message for testing
        messages = [messages[0]]
        break

        if not nextPageToken:
            break

    read_message(service, msg_id=messages[0]['id'])
  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
    # load the rules file in memory
    with open('rules.json') as r:
        rules = json.load(r)

    main()
