"""
SIEM Alert & Notification Webhook Engine.
Dispatches JSON alert payloads to SIEM endpoints, Slack, or Discord webhooks when high-severity threats are detected.
"""
import urllib.request
import json
from datetime import datetime

class AlertDispatcher:
    def __init__(self):
        self.webhook_url = None
        self.alert_history = []

    def configure_webhook(self, url):
        self.webhook_url = url
        return True

    def dispatch_alert(self, threat_event):
        """Sends alert webhook if threat is high severity."""
        if not threat_event.get('is_attack'):
            return False

        alert_payload = {
            "text": f"🚨 NIDS CRITICAL ALERT: [{threat_event.get('category')}] detected from IP {threat_event.get('src_ip')}",
            "timestamp": datetime.now().isoformat(),
            "event": threat_event
        }

        self.alert_history.append(alert_payload)

        if self.webhook_url:
            try:
                data = json.dumps(alert_payload).encode('utf-8')
                req = urllib.request.Request(self.webhook_url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=2)
                return True
            except Exception as e:
                print(f"[Alert Dispatcher] Webhook dispatch error: {e}")
                return False
        return False

global_alerts = AlertDispatcher()
