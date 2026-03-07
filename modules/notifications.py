"""
Notifications - Webhook notifications for Slack, Teams, Discord.
"""
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .utils import get_logger, create_http_session

logger = get_logger("notifications")


class NotificationType(Enum):
    SCAN_START = 'scan_start'
    SCAN_COMPLETE = 'scan_complete'
    CRITICAL_FINDING = 'critical'
    HIGH_FINDING = 'high'
    ERROR = 'error'


class WebhookType(Enum):
    SLACK = 'slack'
    TEAMS = 'teams'
    DISCORD = 'discord'
    GENERIC = 'generic'


@dataclass
class WebhookConfig:
    type: WebhookType
    url: str
    events: List[str]
    name: Optional[str] = None


class NotificationManager:
    """Manager for sending webhook notifications."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.session = create_http_session()
        self.webhooks: List[WebhookConfig] = []

        self._load_webhooks()

    def _load_webhooks(self):
        """Load webhook configurations."""
        webhooks_config = self.config.get('webhooks', [])

        for wh in webhooks_config:
            try:
                self.webhooks.append(WebhookConfig(
                    type=WebhookType(wh.get('type', 'generic')),
                    url=wh['url'],
                    events=wh.get('events', ['scan_complete']),
                    name=wh.get('name')
                ))
            except Exception as e:
                logger.warning("webhook_config_error", error=str(e))

        logger.debug("webhooks_loaded", count=len(self.webhooks))

    def notify(self, event_type: NotificationType, data: Dict[str, Any]) -> List[Dict]:
        """Send notification for an event."""
        results = []

        for webhook in self.webhooks:
            if event_type.value in webhook.events or 'all' in webhook.events:
                result = self._send_webhook(webhook, event_type, data)
                results.append(result)

        return results

    def _send_webhook(
        self,
        webhook: WebhookConfig,
        event_type: NotificationType,
        data: Dict[str, Any]
    ) -> Dict:
        """Send notification to a specific webhook."""
        result = {
            'webhook': webhook.name or webhook.url[:30],
            'type': webhook.type.value,
            'event': event_type.value,
            'success': False
        }

        try:
            if webhook.type == WebhookType.SLACK:
                payload = self._format_slack(event_type, data)
            elif webhook.type == WebhookType.TEAMS:
                payload = self._format_teams(event_type, data)
            elif webhook.type == WebhookType.DISCORD:
                payload = self._format_discord(event_type, data)
            else:
                payload = self._format_generic(event_type, data)

            response = self.session.post(
                webhook.url,
                json=payload,
                timeout=10
            )

            result['success'] = response.status_code in [200, 201, 204]
            result['status_code'] = response.status_code

            if result['success']:
                logger.info("notification_sent", **result)
            else:
                logger.warning("notification_failed", **result)

        except Exception as e:
            result['error'] = str(e)
            logger.error("notification_error", **result)

        return result

    def _format_slack(self, event_type: NotificationType, data: Dict) -> Dict:
        """Format notification for Slack."""
        colors = {
            NotificationType.SCAN_START: '#36a64f',
            NotificationType.SCAN_COMPLETE: '#2196F3',
            NotificationType.CRITICAL_FINDING: '#FF0000',
            NotificationType.HIGH_FINDING: '#FF9800',
            NotificationType.ERROR: '#F44336',
        }

        blocks = []

        # Header
        if event_type == NotificationType.SCAN_START:
            title = ":rocket: Security Scan Started"
        elif event_type == NotificationType.SCAN_COMPLETE:
            title = ":white_check_mark: Security Scan Complete"
        elif event_type == NotificationType.CRITICAL_FINDING:
            title = ":rotating_light: Critical Security Finding"
        elif event_type == NotificationType.HIGH_FINDING:
            title = ":warning: High Severity Finding"
        else:
            title = ":x: Scan Error"

        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": title}
        })

        # Content
        if event_type in [NotificationType.SCAN_START, NotificationType.SCAN_COMPLETE]:
            fields = []
            if 'target' in data:
                fields.append({"type": "mrkdwn", "text": f"*Target:*\n{data['target']}"})
            if 'alerts_count' in data:
                fields.append({"type": "mrkdwn", "text": f"*Alerts:*\n{data['alerts_count']}"})
            if 'high_count' in data:
                fields.append({"type": "mrkdwn", "text": f"*High:*\n{data['high_count']}"})
            if 'duration' in data:
                fields.append({"type": "mrkdwn", "text": f"*Duration:*\n{data['duration']}"})

            if fields:
                blocks.append({"type": "section", "fields": fields})

        elif event_type in [NotificationType.CRITICAL_FINDING, NotificationType.HIGH_FINDING]:
            text = f"*{data.get('alert', 'Unknown')}*\n"
            text += f"URL: {data.get('url', 'N/A')}\n"
            text += f"Risk: {data.get('risk', 'N/A')}\n"
            if 'description' in data:
                text += f"\n{data['description'][:200]}"

            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

        return {
            "attachments": [{
                "color": colors.get(event_type, '#808080'),
                "blocks": blocks
            }]
        }

    def _format_teams(self, event_type: NotificationType, data: Dict) -> Dict:
        """Format notification for Microsoft Teams."""
        colors = {
            NotificationType.SCAN_START: '36a64f',
            NotificationType.SCAN_COMPLETE: '2196F3',
            NotificationType.CRITICAL_FINDING: 'FF0000',
            NotificationType.HIGH_FINDING: 'FF9800',
            NotificationType.ERROR: 'F44336',
        }

        titles = {
            NotificationType.SCAN_START: "Security Scan Started",
            NotificationType.SCAN_COMPLETE: "Security Scan Complete",
            NotificationType.CRITICAL_FINDING: "Critical Security Finding",
            NotificationType.HIGH_FINDING: "High Severity Finding",
            NotificationType.ERROR: "Scan Error",
        }

        facts = []
        if 'target' in data:
            facts.append({"name": "Target", "value": data['target']})
        if 'alerts_count' in data:
            facts.append({"name": "Total Alerts", "value": str(data['alerts_count'])})
        if 'high_count' in data:
            facts.append({"name": "High Severity", "value": str(data['high_count'])})
        if 'duration' in data:
            facts.append({"name": "Duration", "value": data['duration']})
        if 'alert' in data:
            facts.append({"name": "Alert", "value": data['alert']})
        if 'url' in data:
            facts.append({"name": "URL", "value": data['url']})

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": colors.get(event_type, '808080'),
            "summary": titles.get(event_type, 'Notification'),
            "sections": [{
                "activityTitle": titles.get(event_type, 'Notification'),
                "facts": facts,
                "markdown": True
            }]
        }

    def _format_discord(self, event_type: NotificationType, data: Dict) -> Dict:
        """Format notification for Discord."""
        colors = {
            NotificationType.SCAN_START: 0x36a64f,
            NotificationType.SCAN_COMPLETE: 0x2196F3,
            NotificationType.CRITICAL_FINDING: 0xFF0000,
            NotificationType.HIGH_FINDING: 0xFF9800,
            NotificationType.ERROR: 0xF44336,
        }

        titles = {
            NotificationType.SCAN_START: "Security Scan Started",
            NotificationType.SCAN_COMPLETE: "Security Scan Complete",
            NotificationType.CRITICAL_FINDING: "Critical Security Finding",
            NotificationType.HIGH_FINDING: "High Severity Finding",
            NotificationType.ERROR: "Scan Error",
        }

        fields = []
        if 'target' in data:
            fields.append({"name": "Target", "value": data['target'], "inline": True})
        if 'alerts_count' in data:
            fields.append({"name": "Alerts", "value": str(data['alerts_count']), "inline": True})
        if 'high_count' in data:
            fields.append({"name": "High", "value": str(data['high_count']), "inline": True})
        if 'alert' in data:
            fields.append({"name": "Finding", "value": data['alert'][:100], "inline": False})

        return {
            "embeds": [{
                "title": titles.get(event_type, 'Notification'),
                "color": colors.get(event_type, 0x808080),
                "fields": fields,
                "footer": {"text": "HAR-ZAP Security Scanner"}
            }]
        }

    def _format_generic(self, event_type: NotificationType, data: Dict) -> Dict:
        """Format notification for generic webhooks."""
        return {
            "event": event_type.value,
            "timestamp": data.get('timestamp'),
            "data": data
        }

    def notify_scan_start(self, target: str, scan_id: Optional[str] = None):
        """Send scan start notification."""
        return self.notify(NotificationType.SCAN_START, {
            'target': target,
            'scan_id': scan_id
        })

    def notify_scan_complete(self, summary: Dict):
        """Send scan complete notification."""
        return self.notify(NotificationType.SCAN_COMPLETE, summary)

    def notify_critical_finding(self, alert: Dict):
        """Send immediate notification for critical finding."""
        return self.notify(NotificationType.CRITICAL_FINDING, {
            'alert': alert.get('alert'),
            'url': alert.get('url'),
            'risk': alert.get('risk'),
            'description': alert.get('description'),
            'cweid': alert.get('cweid'),
            'wascid': alert.get('wascid')
        })

    def notify_high_finding(self, alert: Dict):
        """Send notification for high severity finding."""
        return self.notify(NotificationType.HIGH_FINDING, {
            'alert': alert.get('alert'),
            'url': alert.get('url'),
            'risk': alert.get('risk'),
            'description': alert.get('description')
        })

    def notify_error(self, error: str, context: Optional[Dict] = None):
        """Send error notification."""
        data = {'error': error}
        if context:
            data.update(context)
        return self.notify(NotificationType.ERROR, data)
