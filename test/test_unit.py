import pytest
from unittest.mock import Mock, patch, MagicMock, call
import datetime
from email.utils import formatdate
import base64
import json

import main

class TestCheckCondition:
    def test_contains_predicate_true(self):
        assert main.check_condition("Hello World", "contains", "world") == True
        assert main.check_condition("Test Email Subject", "contains", "email") == True

    def test_equals_predicate_true(self):
        assert main.check_condition("Hello", "equals", "hello") == True
        assert main.check_condition("TEST", "equals", "test") == True

    def test_less_than_days_predicate_true(self):
        past_date = formatdate((datetime.datetime.now() - datetime.timedelta(days=2)).timestamp())
        assert main.check_condition(past_date, "less_than_days", "5") == True

class TestEvaluateRules:
    @pytest.fixture
    def sample_email_data(self):
        return {
            'id': '19729efa64d10c49',
            'Subject': 'Lorem Ipsum Email',
            'From': 'Aaryan Mishra <aaryan.mshra@gmail.com>',
            'Date': 'Sun, 1 Jun 2025 10:50:48 +0530',
            'Snippet': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
        }

    @pytest.fixture
    def mock_service(self):
        service = Mock()
        email_body = base64.b64encode(b"This is the full email body content").decode('utf-8')
        service.users().messages().get.return_value.execute.return_value = {
            'payload': {
                'parts': [{
                    'body': {
                        'data': email_body
                    }
                }]
            }
        }

        return service

    def test_any_predicate(self, sample_email_data, mock_service):
        rules = {
            'predicate': 'any',
            'rules': [
                {'field': 'from', 'predicate': 'contains', 'value': 'aaryan'},
                {'field': 'subject', 'predicate': 'contains', 'value': 'nonexistent'}
            ]
        }
        assert main.evaluate_rules(sample_email_data, mock_service, rules) == True

    def test_all_predicate(self, sample_email_data, mock_service):
        rules = {
            'predicate': 'all',
            'rules': [
                {'field': 'from', 'predicate': 'contains', 'value': 'aaryan'},
                {'field': 'subject', 'predicate': 'contains', 'value': 'lorem'}
            ]
        }
        assert main.evaluate_rules(sample_email_data, mock_service, rules) == True

    def test_message_field_full_body_fallback(self, sample_email_data, mock_service):
        rules = {
            'predicate': 'any',
            'rules': [
                {'field': 'message', 'predicate': 'contains', 'value': 'full email body'}
            ]
        }
        assert main.evaluate_rules(sample_email_data, mock_service, rules) == True
        mock_service.users().messages().get.assert_called_once()

class TestPerformAction:
    @pytest.fixture
    def mock_service(self):
        service = Mock()
        service.users().messages().modify.return_value.execute.return_value = {}
        service.users().labels().create.return_value.execute.return_value = {}
        return service

    @pytest.fixture
    def sample_labels(self):
        return [
            {'name': 'INBOX', 'id': 'INBOX'},
            {'name': 'SENT', 'id': 'SENT'},
            {'name': 'EXISTING_LABEL', 'id': 'Label_1'}
        ]

    def test_mark_as_read_action(self, mock_service, sample_labels):
        rules = {
            'actions': [
                {'type': 'mark_as_read'}
            ]
        }

        main.perform_action(mock_service, 'msg123', sample_labels, rules)

        mock_service.users().messages().modify.assert_called_once_with(
            userId='me',
            id='msg123',
            body={'removeLabelIds': ['UNREAD']}
        )

    def test_move_to_new_label(self, mock_service, sample_labels):
        rules = {
            'actions': [
                {'type': 'move_to', 'value': 'new_label'}
            ]
        }

        main.perform_action(mock_service, 'msg123', sample_labels, rules)

        mock_service.users().labels().create.assert_called_once_with(
            userId='me',
            body={
                'name': 'NEW_LABEL',
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
        )

        mock_service.users().messages().modify.assert_called_once_with(
            userId='me',
            id='msg123',
            body={'addLabelIds': ['NEW_LABEL'], 'removeLabelIds': ['INBOX']}
        )
