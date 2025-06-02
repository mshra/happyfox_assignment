import pprint
import os.path
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def print_parts(part):
    filename = part.get('filename') or 'index.html'
    data = part['body']['data']
    mimeType = part['mimeType']

    match mimeType:
        case "text/plain":
            print(str(base64.b64decode(data), encoding='utf-8'))
        case "text/html":
            filepath = os.path.join(os.getcwd(), filename)

            print('saving html to:', filepath)

            with open(filepath, "wb") as f:
                f.write(base64.urlsafe_b64decode(data))
        case _:
            raise Exception(f"Unsupported MIME type: f{mimeType}")

def read_message(service, msg_id):
    parts = service.users().messages().get(userId='me', id=msg_id, format='full').execute()['payload']['parts']
    for part in parts:
        print_parts(part)

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

    read_message(service, msg_id=messages[0]['id'])
  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()
