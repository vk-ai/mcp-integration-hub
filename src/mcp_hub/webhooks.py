"""Inbound webhook verification and normalisation.

- GitHub: `X-Hub-Signature-256` = "sha256=" + HMAC-SHA256(secret, raw body).
- Slack: `X-Slack-Signature` = "v0=" + HMAC-SHA256(secret, "v0:{ts}:{body}"),
  rejected when the timestamp is more than 5 minutes off (replay window).
- HubSpot v3: `X-HubSpot-Signature-v3` = base64(HMAC-SHA256(secret,
  method + uri + body + timestamp_ms)), same 5 minute window.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


class SignatureError(Exception):
    pass


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def verify_github(secret: str, body: bytes, signature: str | None) -> None:
    if not signature or not signature.startswith("sha256="):
        raise SignatureError("missing or non-sha256 signature")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not _eq(expected, signature):
        raise SignatureError("signature mismatch")


def verify_slack(secret: str, body: bytes, timestamp: str | None, signature: str | None, now: float, window_s: int = 300) -> None:
    try:
        ts = int(timestamp or "")
    except ValueError as e:
        raise SignatureError("bad timestamp") from e
    if abs(now - ts) > window_s:
        raise SignatureError(f"stale timestamp ({int(abs(now - ts))}s off)")
    expected = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    if not signature or not _eq(expected, signature):
        raise SignatureError("signature mismatch")


def verify_hubspot_v3(secret: str, method: str, uri: str, body: bytes, timestamp_ms: str | None,
                      signature: str | None, now: float, window_s: int = 300) -> None:
    try:
        ts = int(timestamp_ms or "")
    except ValueError as e:
        raise SignatureError("bad timestamp") from e
    if abs(now - ts / 1000) > window_s:
        raise SignatureError(f"stale timestamp ({int(abs(now - ts / 1000))}s off)")
    msg = f"{method}{uri}{body.decode()}{ts}".encode()
    expected = base64.b64encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest()).decode()
    if not signature or not _eq(expected, signature):
        raise SignatureError("signature mismatch")


@dataclass(frozen=True)
class Event:
    source: str
    type: str
    id: str
    payload: dict


def parse_github(event_name: str, delivery_id: str, body: bytes) -> list[Event]:
    data = json.loads(body)
    return [Event("github", f"github.{event_name}.{data.get('action', 'received')}", f"github:{delivery_id}", data)]


def parse_slack(body: bytes) -> list[Event] | dict:
    data = json.loads(body)
    if data.get("type") == "url_verification":
        return {"challenge": data["challenge"]}
    ev = data.get("event", {})
    return [Event("slack", f"slack.{ev.get('type', 'event')}", f"slack:{data.get('event_id', '')}", ev)]


def parse_hubspot(body: bytes) -> list[Event]:
    return [Event("hubspot", f"hubspot.{item.get('subscriptionType', 'event')}", f"hubspot:{item.get('eventId')}", item)
            for item in json.loads(body)]


class Deduper:
    """Remember recently seen delivery ids so retried webhooks don't re-run workflows."""

    def __init__(self, ttl_s: float = 3600, clock=time.time):
        self.ttl_s, self.clock = ttl_s, clock
        self._seen: dict[str, float] = {}

    def first_time(self, key: str) -> bool:
        now = self.clock()
        for k, exp in list(self._seen.items()):
            if exp < now:
                del self._seen[k]
        if key in self._seen:
            return False
        self._seen[key] = now + self.ttl_s
        return True
