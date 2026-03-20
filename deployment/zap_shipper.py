#!/usr/bin/env python3
"""
ZAP Log Shipper - Polls ZAP and ships logs to Loki or Elasticsearch

Environment variables:
  ZAP_URL: ZAP API URL (default: http://localhost:8080)
  LOG_BACKEND: loki | elasticsearch (default: loki)
  LOKI_URL: Loki push URL (default: http://localhost:3100)
  ELASTICSEARCH_URL: Elasticsearch URL (default: http://localhost:9200)
  POLL_INTERVAL: Seconds between polls (default: 5)
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests
from zapv2 import ZAPv2


# Configuration
ZAP_URL = os.getenv('ZAP_URL', 'http://localhost:8080')
LOG_BACKEND = os.getenv('LOG_BACKEND', 'loki').lower()
LOKI_URL = os.getenv('LOKI_URL', 'http://localhost:3100')
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '5'))

# State tracking
last_alert_id = 0
last_message_id = 0


def get_zap_client() -> ZAPv2:
    """Initialize ZAP client"""
    return ZAPv2(apikey='', proxies={'http': ZAP_URL, 'https': ZAP_URL})


def risk_to_level(risk: int) -> str:
    """Convert ZAP risk int to string"""
    return {0: 'INFO', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH'}.get(risk, 'UNKNOWN')


def confidence_to_level(confidence: int) -> str:
    """Convert ZAP confidence int to string"""
    return {0: 'FALSE_POSITIVE', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CONFIRMED'}.get(confidence, 'UNKNOWN')


# =============================================================================
# LOKI BACKEND
# =============================================================================

def push_to_loki(streams: List[Dict]):
    """Push log entries to Loki"""
    if not streams:
        return

    payload = {"streams": streams}

    try:
        resp = requests.post(
            f"{LOKI_URL}/loki/api/v1/push",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if resp.status_code not in (200, 204):
            print(f"[Loki] Push failed: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[Loki] Error: {e}")


def format_alert_for_loki(alert: Dict) -> Dict:
    """Format ZAP alert for Loki"""
    timestamp = str(int(datetime.now().timestamp() * 1e9))

    labels = {
        "job": "zap",
        "type": "alert",
        "risk": risk_to_level(int(alert.get('risk', 0))),
        "confidence": confidence_to_level(int(alert.get('confidence', 0))),
        "attack_type": alert.get('name', 'unknown').replace(' ', '_').lower()[:50]
    }

    log_entry = {
        "id": alert.get('id'),
        "name": alert.get('name'),
        "risk": risk_to_level(int(alert.get('risk', 0))),
        "confidence": confidence_to_level(int(alert.get('confidence', 0))),
        "url": alert.get('url'),
        "param": alert.get('param'),
        "attack": alert.get('attack'),
        "evidence": alert.get('evidence', '')[:500],
        "description": alert.get('description', '')[:200],
        "solution": alert.get('solution', '')[:200],
        "cweid": alert.get('cweid'),
        "wascid": alert.get('wascid')
    }

    return {
        "stream": labels,
        "values": [[timestamp, json.dumps(log_entry)]]
    }


def format_message_for_loki(msg: Dict) -> Dict:
    """Format ZAP HTTP message for Loki"""
    timestamp = str(int(datetime.now().timestamp() * 1e9))

    # Extract method and status from message
    req_header = msg.get('requestHeader', '')
    method = req_header.split(' ')[0] if req_header else 'UNKNOWN'

    resp_header = msg.get('responseHeader', '')
    status = '0'
    if resp_header:
        parts = resp_header.split(' ')
        if len(parts) > 1:
            status = parts[1]

    labels = {
        "job": "zap",
        "type": "request",
        "method": method,
        "status": status
    }

    log_entry = {
        "id": msg.get('id'),
        "method": method,
        "url": msg.get('requestHeader', '').split('\n')[0] if msg.get('requestHeader') else '',
        "status": status,
        "response_length": len(msg.get('responseBody', '')),
        "timestamp": msg.get('timestamp', '')
    }

    return {
        "stream": labels,
        "values": [[timestamp, json.dumps(log_entry)]]
    }


# =============================================================================
# ELASTICSEARCH BACKEND
# =============================================================================

def push_to_elasticsearch(docs: List[Dict], index_prefix: str = "zap"):
    """Push documents to Elasticsearch"""
    if not docs:
        return

    # Use bulk API
    bulk_body = ""
    date_suffix = datetime.now().strftime("%Y.%m.%d")
    index_name = f"{index_prefix}-{date_suffix}"

    for doc in docs:
        action = json.dumps({"index": {"_index": index_name}})
        document = json.dumps(doc)
        bulk_body += f"{action}\n{document}\n"

    try:
        resp = requests.post(
            f"{ELASTICSEARCH_URL}/_bulk",
            data=bulk_body,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=10
        )
        if resp.status_code not in (200, 201):
            print(f"[ES] Bulk push failed: {resp.status_code}")
    except Exception as e:
        print(f"[ES] Error: {e}")


def format_alert_for_es(alert: Dict) -> Dict:
    """Format ZAP alert for Elasticsearch"""
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "alert",
        "alert_id": alert.get('id'),
        "name": alert.get('name'),
        "risk": risk_to_level(int(alert.get('risk', 0))),
        "risk_score": int(alert.get('risk', 0)),
        "confidence": confidence_to_level(int(alert.get('confidence', 0))),
        "confidence_score": int(alert.get('confidence', 0)),
        "url": alert.get('url'),
        "param": alert.get('param'),
        "attack": alert.get('attack'),
        "evidence": alert.get('evidence', '')[:1000],
        "description": alert.get('description'),
        "solution": alert.get('solution'),
        "cweid": alert.get('cweid'),
        "wascid": alert.get('wascid'),
        "tags": ["zap", "security", "vulnerability"]
    }


def format_message_for_es(msg: Dict) -> Dict:
    """Format ZAP HTTP message for Elasticsearch"""
    req_header = msg.get('requestHeader', '')
    method = req_header.split(' ')[0] if req_header else 'UNKNOWN'

    resp_header = msg.get('responseHeader', '')
    status = 0
    if resp_header:
        parts = resp_header.split(' ')
        if len(parts) > 1:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    # Extract URL from request line
    url = ''
    if req_header:
        lines = req_header.split('\n')
        if lines:
            parts = lines[0].split(' ')
            if len(parts) > 1:
                url = parts[1]

    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "request",
        "message_id": msg.get('id'),
        "method": method,
        "url": url,
        "status_code": status,
        "request_header": req_header[:2000],
        "response_length": len(msg.get('responseBody', '')),
        "tags": ["zap", "http", "request"]
    }


# =============================================================================
# MAIN POLLING LOOP
# =============================================================================

def poll_and_ship(zap: ZAPv2):
    """Poll ZAP for new alerts and messages, ship to backend"""
    global last_alert_id, last_message_id

    # Get new alerts
    try:
        alerts = zap.core.alerts(start=last_alert_id)
        if alerts:
            print(f"[ZAP] Found {len(alerts)} new alerts")

            if LOG_BACKEND == 'loki':
                streams = [format_alert_for_loki(a) for a in alerts]
                push_to_loki(streams)
            else:
                docs = [format_alert_for_es(a) for a in alerts]
                push_to_elasticsearch(docs, "zap-alerts")

            # Update last ID
            last_alert_id = max(int(a.get('id', 0)) for a in alerts) + 1
    except Exception as e:
        print(f"[ZAP] Error fetching alerts: {e}")

    # Get new messages (HTTP history)
    try:
        messages = zap.core.messages(start=last_message_id, count=100)
        if messages:
            print(f"[ZAP] Found {len(messages)} new messages")

            if LOG_BACKEND == 'loki':
                streams = [format_message_for_loki(m) for m in messages]
                push_to_loki(streams)
            else:
                docs = [format_message_for_es(m) for m in messages]
                push_to_elasticsearch(docs, "zap-requests")

            # Update last ID
            last_message_id = max(int(m.get('id', 0)) for m in messages) + 1
    except Exception as e:
        print(f"[ZAP] Error fetching messages: {e}")


def wait_for_zap() -> ZAPv2:
    """Wait for ZAP to be ready"""
    print(f"[ZAP] Waiting for ZAP at {ZAP_URL}...")

    while True:
        try:
            zap = get_zap_client()
            version = zap.core.version
            print(f"[ZAP] Connected! Version: {version}")
            return zap
        except Exception as e:
            print(f"[ZAP] Not ready: {e}")
            time.sleep(5)


def wait_for_backend():
    """Wait for logging backend to be ready"""
    if LOG_BACKEND == 'loki':
        print(f"[Loki] Waiting for Loki at {LOKI_URL}...")
        while True:
            try:
                resp = requests.get(f"{LOKI_URL}/ready", timeout=5)
                if resp.status_code == 200:
                    print("[Loki] Ready!")
                    return
            except Exception:
                pass
            time.sleep(2)
    else:
        print(f"[ES] Waiting for Elasticsearch at {ELASTICSEARCH_URL}...")
        while True:
            try:
                resp = requests.get(f"{ELASTICSEARCH_URL}/_cluster/health", timeout=5)
                if resp.status_code == 200:
                    print("[ES] Ready!")
                    return
            except Exception:
                pass
            time.sleep(2)


def main():
    print("=" * 60)
    print("HAR.ZAP Log Shipper")
    print(f"Backend: {LOG_BACKEND.upper()}")
    print(f"Poll interval: {POLL_INTERVAL}s")
    print("=" * 60)

    wait_for_backend()
    zap = wait_for_zap()

    print(f"[Shipper] Starting poll loop...")

    while True:
        try:
            poll_and_ship(zap)
        except Exception as e:
            print(f"[Shipper] Error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
