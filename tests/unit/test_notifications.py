"""Tests for Notifications module"""
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def webhook_config():
    return {
        'webhooks': [
            {'type': 'slack', 'url': 'https://hooks.slack.com/test', 'events': ['scan_complete', 'critical'], 'name': 'slack-main'},
            {'type': 'teams', 'url': 'https://outlook.webhook.office.com/test', 'events': ['all'], 'name': 'teams-sec'},
            {'type': 'discord', 'url': 'https://discord.com/api/webhooks/test', 'events': ['critical']},
            {'type': 'generic', 'url': 'https://api.example.com/webhook', 'events': ['scan_complete']}
        ]
    }


class TestNotificationType:
    def test_enum_values(self):
        from modules.notifications import NotificationType

        assert NotificationType.SCAN_START.value == 'scan_start'
        assert NotificationType.SCAN_COMPLETE.value == 'scan_complete'
        assert NotificationType.CRITICAL_FINDING.value == 'critical'
        assert NotificationType.HIGH_FINDING.value == 'high'
        assert NotificationType.ERROR.value == 'error'


class TestWebhookType:
    def test_enum_values(self):
        from modules.notifications import WebhookType

        assert WebhookType.SLACK.value == 'slack'
        assert WebhookType.TEAMS.value == 'teams'
        assert WebhookType.DISCORD.value == 'discord'
        assert WebhookType.GENERIC.value == 'generic'


class TestWebhookConfig:
    def test_create_config(self):
        from modules.notifications import WebhookConfig, WebhookType

        config = WebhookConfig(
            type=WebhookType.SLACK,
            url='https://hooks.slack.com/test',
            events=['scan_complete'],
            name='test-webhook'
        )

        assert config.type == WebhookType.SLACK
        assert config.url == 'https://hooks.slack.com/test'
        assert 'scan_complete' in config.events


class TestNotificationManager:
    def test_init(self, webhook_config):
        from modules.notifications import NotificationManager

        manager = NotificationManager(webhook_config)

        assert len(manager.webhooks) == 4

    def test_init_empty(self):
        from modules.notifications import NotificationManager

        manager = NotificationManager()

        assert len(manager.webhooks) == 0

    def test_load_webhooks_invalid(self):
        from modules.notifications import NotificationManager

        config = {'webhooks': [{'invalid': 'config'}]}
        manager = NotificationManager(config)

        assert len(manager.webhooks) == 0

    @patch('modules.notifications.create_http_session')
    def test_notify_filters_by_event(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify(NotificationType.CRITICAL_FINDING, {'alert': 'SQL Injection'})

        # Should match: teams (all), discord (critical), slack (critical)
        assert len(results) == 3

    @patch('modules.notifications.create_http_session')
    def test_notify_scan_complete(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify(NotificationType.SCAN_COMPLETE, {'target': 'https://api.com', 'alerts_count': 5})

        # slack, teams (all), generic
        assert len(results) == 3

    @patch('modules.notifications.create_http_session')
    def test_send_webhook_success(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify(NotificationType.SCAN_START, {'target': 'https://api.com'})

        # Only teams has 'all' events
        assert any(r['success'] for r in results)

    @patch('modules.notifications.create_http_session')
    def test_send_webhook_failure(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        mock_response = Mock()
        mock_response.status_code = 500
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify(NotificationType.SCAN_START, {'target': 'https://api.com'})

        assert not any(r['success'] for r in results)

    @patch('modules.notifications.create_http_session')
    def test_send_webhook_exception(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        mock_session.return_value.post.side_effect = Exception('Connection error')

        manager = NotificationManager(webhook_config)
        results = manager.notify(NotificationType.SCAN_START, {'target': 'https://api.com'})

        assert all('error' in r for r in results)

    def test_format_slack_scan_start(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_slack(NotificationType.SCAN_START, {'target': 'https://api.com'})

        assert 'attachments' in payload
        assert payload['attachments'][0]['color'] == '#36a64f'

    def test_format_slack_scan_complete(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_slack(NotificationType.SCAN_COMPLETE, {
            'target': 'https://api.com', 'alerts_count': 10, 'high_count': 2
        })

        assert 'attachments' in payload
        blocks = payload['attachments'][0]['blocks']
        assert any(b.get('type') == 'header' for b in blocks)

    def test_format_slack_critical(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_slack(NotificationType.CRITICAL_FINDING, {
            'alert': 'SQL Injection', 'url': 'https://api.com/user', 'risk': 'High',
            'description': 'SQL injection vulnerability found'
        })

        assert payload['attachments'][0]['color'] == '#FF0000'

    def test_format_teams(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_teams(NotificationType.SCAN_COMPLETE, {
            'target': 'https://api.com', 'alerts_count': 5
        })

        assert payload['@type'] == 'MessageCard'
        assert 'sections' in payload
        assert any(f['name'] == 'Target' for f in payload['sections'][0]['facts'])

    def test_format_discord(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_discord(NotificationType.HIGH_FINDING, {
            'alert': 'XSS Vulnerability', 'target': 'https://api.com'
        })

        assert 'embeds' in payload
        assert payload['embeds'][0]['color'] == 0xFF9800

    def test_format_generic(self, webhook_config):
        from modules.notifications import NotificationManager, NotificationType

        manager = NotificationManager(webhook_config)
        payload = manager._format_generic(NotificationType.ERROR, {'error': 'Scan failed'})

        assert payload['event'] == 'error'
        assert payload['data']['error'] == 'Scan failed'

    @patch('modules.notifications.create_http_session')
    def test_notify_scan_start(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify_scan_start('https://api.com', scan_id='scan-123')

        assert isinstance(results, list)

    @patch('modules.notifications.create_http_session')
    def test_notify_scan_complete_helper(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify_scan_complete({'target': 'https://api.com', 'alerts_count': 10})

        assert isinstance(results, list)

    @patch('modules.notifications.create_http_session')
    def test_notify_critical_finding(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        alert = {'alert': 'SQL Injection', 'url': 'https://api.com', 'risk': 'High',
                 'description': 'SQL injection', 'cweid': '89'}
        results = manager.notify_critical_finding(alert)

        assert isinstance(results, list)

    @patch('modules.notifications.create_http_session')
    def test_notify_error(self, mock_session, webhook_config):
        from modules.notifications import NotificationManager

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        manager = NotificationManager(webhook_config)
        results = manager.notify_error('Connection failed', context={'target': 'https://api.com'})

        assert isinstance(results, list)
