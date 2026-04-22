"""
Outbound webhook sender for `finding.discovered` and `scan.completed` events.

Design:
- Subscriptions are stored in a small JSON file (`.harzap_webhooks.json`) so they
  persist across CLI / Streamlit / FastAPI restarts without needing a database.
- Payloads are HMAC-SHA256-signed with the subscription's `secret` and sent in
  the `X-HARZAP-Signature` header. Receivers should verify the signature
  before trusting the payload.
- Retries are bounded: 3 attempts with exponential backoff (0.5s, 1s, 2s).
- Failures are swallowed so a broken receiver never blocks a scan.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Optional

DEFAULT_PATH = Path(os.environ.get("HARZAP_WEBHOOKS_FILE", "./.harzap_webhooks.json"))
SIGNATURE_HEADER = "X-HARZAP-Signature"
EVENT_HEADER = "X-HARZAP-Event"
ID_HEADER = "X-HARZAP-Delivery"

SUPPORTED_EVENTS = ("finding.discovered", "scan.completed", "scan.failed", "*")


@dataclass
class Webhook:
    id: str
    url: str
    secret: str
    events: List[str] = field(default_factory=lambda: ["*"])
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""

    def matches(self, event: str) -> bool:
        return self.enabled and ("*" in self.events or event in self.events)

    def to_dict(self, *, reveal_secret: bool = False) -> Dict[str, Any]:
        d = asdict(self)
        if not reveal_secret:
            d["secret"] = "•" * 8
        return d


def sign(secret: str, body: bytes) -> str:
    """Return the hex-encoded HMAC-SHA256 signature.

    Côté receveur, vérifier la signature avec `hmac.compare_digest(expected,
    received)` — **jamais** `==` — pour éviter une attaque par timing sur la
    comparaison octet par octet.
    """
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


class WebhookStore:
    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = Path(path)
        self._hooks: Dict[str, Webhook] = {}
        self._lock = RLock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for raw in data.get("webhooks", []):
            hook = Webhook(**{k: raw[k] for k in raw if k in Webhook.__annotations__})
            self._hooks[hook.id] = hook

    def _save(self) -> None:
        with self._lock:
            payload = {"version": 1, "webhooks": [asdict(h) for h in self._hooks.values()]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add(
        self,
        url: str,
        secret: str,
        events: Optional[List[str]] = None,
        description: str = "",
    ) -> Webhook:
        hook_id = uuid.uuid4().hex[:12]
        events = list(events or ["*"])
        for ev in events:
            if ev not in SUPPORTED_EVENTS:
                raise ValueError(f"unsupported event: {ev}")
        hook = Webhook(id=hook_id, url=url, secret=secret, events=events, description=description)
        with self._lock:
            self._hooks[hook_id] = hook
        self._save()
        return hook

    def remove(self, hook_id: str) -> bool:
        with self._lock:
            existed = self._hooks.pop(hook_id, None) is not None
        if existed:
            self._save()
        return existed

    def list(self, *, reveal_secrets: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            return [h.to_dict(reveal_secret=reveal_secrets) for h in self._hooks.values()]

    def get(self, hook_id: str) -> Optional[Webhook]:
        with self._lock:
            return self._hooks.get(hook_id)

    def for_event(self, event: str) -> List[Webhook]:
        with self._lock:
            return [h for h in self._hooks.values() if h.matches(event)]


# Pluggable transport so tests can inject a fake without network.
def _default_http_post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> int:
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec
        return resp.status


def emit(
    event: str,
    payload: Dict[str, Any],
    *,
    store: Optional[WebhookStore] = None,
    transport: Optional[Callable[..., int]] = None,
    max_retries: int = 3,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Send `event` to every matching webhook. Returns a list of delivery reports.

    Delivery is synchronous but per-hook errors are isolated — one dead receiver
    does not block the others. Backoff on retry is 0.5s, 1s, 2s.

    The `transport` parameter defaults to the module-level `_default_http_post`
    via runtime lookup so tests can monkey-patch it without rebinding.
    """
    store = store or get_store()
    if transport is None:
        transport = _default_http_post
    matches = store.for_event(event)
    body = json.dumps(
        {
            "event": event,
            "payload": payload,
            "emitted_at": datetime.now(timezone.utc).isoformat(),
        },
        default=str,
    ).encode("utf-8")

    reports: List[Dict[str, Any]] = []
    for hook in matches:
        delivery_id = uuid.uuid4().hex
        signature = sign(hook.secret, body)
        headers = {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: f"sha256={signature}",
            EVENT_HEADER: event,
            ID_HEADER: delivery_id,
        }
        report = {
            "webhook_id": hook.id,
            "delivery_id": delivery_id,
            "event": event,
            "url": hook.url,
            "status": None,
            "attempts": 0,
            "error": None,
        }
        # Backoff exponentiel : 0.5s, 1s, 2s. `max_retries` est volontairement
        # bas (3 par défaut) pour qu'une livraison ne bloque jamais un scan
        # plus de ~3.5s au total, même si le receveur est tombé. Les exceptions
        # (DNS, timeout, connexion refusée) sont capturées et tracées dans le
        # rapport de livraison plutôt que propagées à l'appelant : un webhook
        # en panne ne doit pas casser le pentest en cours.
        #
        # Erreurs 4xx : pas de retry — une signature rejetée ou un payload
        # mal formé ne sera pas mieux accepté à la seconde tentative. On
        # économise des appels inutiles sur des receveurs qui renvoient 401
        # tant que la clé n'est pas corrigée côté config.
        for attempt in range(max_retries):
            report["attempts"] = attempt + 1
            try:
                status = transport(hook.url, body, headers, timeout)
                report["status"] = status
                if 200 <= status < 300:
                    break
                report["error"] = f"http {status}"
                if 400 <= status < 500:
                    break
            except Exception as e:     # noqa: BLE001
                report["error"] = str(e)
            time.sleep(0.5 * (2 ** attempt))
        reports.append(report)
    return reports


_singleton: Optional[WebhookStore] = None


def get_store() -> WebhookStore:
    global _singleton
    if _singleton is None:
        _singleton = WebhookStore()
    return _singleton


def reset_for_tests(path: Optional[Path] = None) -> WebhookStore:
    global _singleton
    _singleton = WebhookStore(path=path or DEFAULT_PATH)
    return _singleton
