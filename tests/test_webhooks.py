import base64
import hashlib
import hmac
import json

import pytest

from mcp_hub.webhooks import (
    Deduper, SignatureError, parse_github, parse_hubspot, parse_slack, verify_github, verify_hubspot_v3,
    verify_slack,
)

NOW = 1_800_000_000


def gh_sig(secret, body):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def slack_sig(secret, ts, body):
    return "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()


def hs_sig(secret, method, uri, body, ts):
    msg = f"{method}{uri}{body.decode()}{ts}".encode()
    return base64.b64encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest()).decode()


def test_github_signature_ok_and_tampered():
    body = b'{"action":"opened"}'
    verify_github("s3", body, gh_sig("s3", body))
    with pytest.raises(SignatureError):
        verify_github("s3", body + b" ", gh_sig("s3", body))
    with pytest.raises(SignatureError):
        verify_github("s3", body, None)
    with pytest.raises(SignatureError):
        verify_github("s3", body, "sha1=" + "0" * 40)  # legacy SHA-1 header not accepted


def test_slack_signature_and_replay_window():
    body = b"payload"
    verify_slack("ss", body, str(NOW), slack_sig("ss", NOW, body), now=NOW + 10)
    with pytest.raises(SignatureError, match="stale"):
        verify_slack("ss", body, str(NOW), slack_sig("ss", NOW, body), now=NOW + 301)
    with pytest.raises(SignatureError):
        verify_slack("ss", body, str(NOW), slack_sig("other", NOW, body), now=NOW)
    with pytest.raises(SignatureError):
        verify_slack("ss", body, "not-a-number", "v0=x", now=NOW)


def test_hubspot_v3_signature():
    body = b'[{"eventId":1}]'
    uri = "https://hub.test/webhooks/hubspot"
    ts = str(NOW * 1000)  # HubSpot uses milliseconds
    verify_hubspot_v3("hs", "POST", uri, body, ts, hs_sig("hs", "POST", uri, body, ts), now=NOW)
    with pytest.raises(SignatureError, match="stale"):
        verify_hubspot_v3("hs", "POST", uri, body, ts, hs_sig("hs", "POST", uri, body, ts), now=NOW + 400)
    with pytest.raises(SignatureError):
        verify_hubspot_v3("hs", "POST", uri + "?x=1", body, ts, hs_sig("hs", "POST", uri, body, ts), now=NOW)


def test_parse_github():
    payload = {"action": "opened", "issue": {"title": "Bug", "number": 7}}
    [e] = parse_github("issues", "d-1", json.dumps(payload).encode())
    assert (e.source, e.type, e.id) == ("github", "github.issues.opened", "github:d-1")
    assert e.payload["issue"]["title"] == "Bug"


def test_parse_slack_url_verification_and_event():
    ch = parse_slack(json.dumps({"type": "url_verification", "challenge": "abc"}).encode())
    assert ch == {"challenge": "abc"}
    [e] = parse_slack(json.dumps({"type": "event_callback", "event_id": "Ev1",
                                  "event": {"type": "app_mention", "text": "hi"}}).encode())
    assert e.type == "slack.app_mention" and e.id == "slack:Ev1"


def test_parse_hubspot_batch():
    body = json.dumps([{"eventId": 1, "subscriptionType": "contact.creation", "objectId": 55},
                       {"eventId": 2, "subscriptionType": "contact.deletion", "objectId": 56}]).encode()
    events = parse_hubspot(body)
    assert [e.type for e in events] == ["hubspot.contact.creation", "hubspot.contact.deletion"]
    assert events[0].payload["objectId"] == 55


def test_deduper_ttl():
    now = [0.0]
    d = Deduper(ttl_s=60, clock=lambda: now[0])
    assert d.first_time("a") and not d.first_time("a")
    now[0] = 61
    assert d.first_time("a")
