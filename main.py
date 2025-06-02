import pprint
import os.path
import base64
import datetime

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import db

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def extract_metadata(message, msg_id):
    metadata = {}

    headers = message['payload']['headers']

    for header in headers:
        if header['name'] in ["Subject", "From", "Date"]:
            metadata.update({ header['name']: header['value']})

    db.insert(msg_id, metadata['Subject'], metadata['From'], metadata['Date'])
    return metadata

def read_message(service, msg_id):
    # fetch the metadata of message
    message = service.users().messages().get(userId='me', id=msg_id, format='metadata').execute()
    pprint.pp(extract_metadata(message, msg_id))

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
    messages = service.users().messages().list(userId="me").execute()['messages']

    for idx in range(5):
        read_message(service, msg_id=messages[idx]['id'])
  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()
