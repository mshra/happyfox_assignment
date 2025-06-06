import pytest
from unittest.mock import Mock, patch, MagicMock, call
import datetime
from email.utils import formatdate
import base64
import json

import main

class TestIntegration:
    def test_complete_workflow(self):
        email_data = {
            'id': '19329efa64d10c49',
            'Subject': 'Lorem Ipsum Email',
            'From': 'Aaryan Mishra <aaryan.mshra@gmail.com>',
            'Date': 'Sun, 1 Jun 2025 10:50:48 +0530',
            'Snippet': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
        }

        rules = {
            'predicate': 'any',
            'rules': [
                {
                      "field": "from",
                      "predicate": "contains",
                      "value": "tenmiles.com"
                    },
                    {
                      "field": "subject",
                      "predicate": "contains",
                      "value": "Email"
                    },
                    {
                      "field": "date_received",
                      "predicate": "less_than_days",
                      "value": "2"
                    }
            ],
            'actions': [
                { "type": "move_to", "value": "spam" },
                { "type": "mark_as_read", "value": "" }
            ]
        }

        mock_service = Mock()
        mock_service.users().messages().modify.return_value.execute.return_value = {}
        mock_service.users().labels().create.return_value.execute.return_value = {}

        labels = [{'name': 'INBOX', 'id': 'INBOX'}]

        should_apply_rules = main.evaluate_rules(email_data, mock_service, rules)
        assert should_apply_rules == True

        if should_apply_rules:
            main.perform_action(mock_service, email_data['id'], labels, rules)

        assert mock_service.users().messages().modify.call_count == 2
        mock_service.users().labels().create.assert_called_once()
