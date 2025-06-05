# Mail Rule Engine

A gmail rule engine that processes emails and performs automated actions based on rules

## Installation

1. Clone the repository

```bash
git clone https://github.com/mshra/mail_rule_engine
cd mail_rule_engine
```

2. Make a virtual environment & install dependencies

```bash
python python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Google API Setup

- Go to [google cloud console](https://console.cloud.google.com/)
- Create or select an existing project
- Enable the Gmail API
- Create desktop application type credentials
- Download and save the credentials.json in the project root

4. Configure rules

Edit `rules.json` to define your email processing rules.

5. Run the application

```bash
python main.py
```

## Limitations

- GMAIL API quota and rate limiting
- No exception and API error handling
- No type validations
- Fields are case sensitive
