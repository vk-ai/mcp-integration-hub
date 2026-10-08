import hashlib
import hmac
import json
import base64
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_hub.http_app import create_app
from conftest import HUB_BASE, connect

OP = {"X-API-Key": "dev-operator-key"}
VIEW = {"X-API-Key": "dev-viewer-key"}
ADMIN = {"X-API-Key": "dev-admin-key"}


@pytest.fixture
async def api(hub):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(hub)), base_url=HUB_BASE) as c:
        yield c


async def test_agent_card(api):
    for path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
        card = (await api.get(path)).json()
        assert card["name"] == "mcp-integration-hub"
        assert card["url"] == f"{HUB_BASE}/a2a" and card["preferredTransport"] == "JSONRPC"
        assert card["protocolVersion"] == "0.3.0"
        ids = {s["id"] for s in card["skills"]}
        assert {"github_create_issue", "slack_post_message", "hubspot_create_contact"} <= ids
        assert "apiKey" in card["securitySchemes"] and card["capabilities"]["streaming"] is False


async def test_oauth_connect_over_http(api, http, hub):
    assert (await api.get("/connect/slack")).status_code == 401
    r = await api.get("/connect/slack", headers=OP)
    assert r.status_code == 302
    authz = r.headers["location"]
    assert authz.startswith("http://sandbox/slack/oauth/authorize") and "code_challenge=" in authz
    back = await http.get(authz)  # the user's browser at the provider
    cb = urlparse(back.headers["location"])
    assert f"{cb.scheme}://{cb.netloc}{cb.path}" == f"{HUB_BASE}/oauth/slack/callback"
    r = await api.get(cb.path + "?" + cb.query)
    assert r.status_code == 200 and r.json()["provider"] == "slack"
    conns = (await api.get("/connections", headers=OP)).json()
    assert [c["provider"] for c in conns] == ["slack"]
    assert "access_token" not in json.dumps(conns)


async def test_oauth_callback_errors(api):
    r = await api.get("/oauth/slack/callback?code=x&state=forged")
    assert r.status_code == 400
    r = await api.get("/oauth/slack/callback?error=access_denied&state=s")
    assert r.status_code == 400 and r.json()["detail"] == "provider returned error: access_denied"


def gh_headers(body, event="issues", delivery="d-1", secret="dev-github-webhook-secret"):
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {"X-Hub-Signature-256": sig, "X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
            "Content-Type": "application/json"}


async def test_github_webhook_runs_workflow_and_dedupes(api, hub, http, connect_all, alice, sandbox):
    await connect_all(alice)
    body = json.dumps({"action": "opened", "issue": {"title": "Crash on save", "html_url": "u"}}).encode()
    r = await api.post("/webhooks/github", content=body, headers=gh_headers(body))
    assert r.status_code == 202
    assert r.json()["runs"] == [{"workflow": "github-issue-to-slack", "status": "succeeded", "error": None}]
    assert sandbox.slack_messages[-1]["text"] == "New issue: Crash on save u"
    again = await api.post("/webhooks/github", content=body, headers=gh_headers(body))
    assert again.status_code == 200 and again.json() == {"duplicate": True}
    assert len(sandbox.slack_messages) == 1


async def test_github_webhook_bad_signature(api, sandbox):
    body = b'{"action":"opened"}'
    r = await api.post("/webhooks/github", content=body, headers=gh_headers(body, secret="wrong"))
    assert r.status_code == 401
    assert sandbox.slack_messages == []


async def test_slack_url_verification(api, clock):
    body = json.dumps({"type": "url_verification", "challenge": "c-123"}).encode()
    ts = str(int(clock()))
    sig = "v0=" + hmac.new(b"dev-slack-webhook-secret", f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    r = await api.post("/webhooks/slack", content=body,
                       headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig})
    assert r.status_code == 200 and r.json() == {"challenge": "c-123"}


async def test_hubspot_webhook_v3(api, hub, http, connect_all, alice, clock, sandbox):
    await connect_all(alice)
    body = json.dumps([{"eventId": 77, "subscriptionType": "contact.creation", "objectId": 901}]).encode()
    ts = str(int(clock() * 1000))
    uri = f"{HUB_BASE}/webhooks/hubspot"
    sig = base64.b64encode(hmac.new(b"dev-hubspot-webhook-secret", f"POST{uri}{body.decode()}{ts}".encode(),
                                    hashlib.sha256).digest()).decode()
    r = await api.post("/webhooks/hubspot", content=body,
                       headers={"X-HubSpot-Signature-v3": sig, "X-HubSpot-Request-Timestamp": ts})
    assert r.status_code == 202
    assert sandbox.issues["acme/crm-followups"][0]["title"] == "Follow up with HubSpot contact 901"


def a2a(method, params, id_=1):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}


def send(skill, arguments):
    return a2a("message/send", {"message": {"role": "user", "messageId": "m1",
                                            "parts": [{"kind": "data", "data": {"skill": skill, "arguments": arguments}}]}})


async def test_a2a_message_send_runs_skill(api, hub, http, alice, sandbox):
    await connect(hub, http, alice, "github")
    r = (await api.post("/a2a", json=send("github_create_issue", {"repo": "acme/app", "title": "From A2A"}),
                        headers=OP)).json()
    task = r["result"]
    assert task["kind"] == "task" and task["status"]["state"] == "completed"
    assert task["artifacts"][0]["parts"][0]["data"]["title"] == "From A2A"
    got = (await api.post("/a2a", json=a2a("tasks/get", {"id": task["id"]}), headers=OP)).json()
    assert got["result"]["id"] == task["id"]


async def test_a2a_policy_denied_is_rejected_task(api, hub, http, victor):
    r = (await api.post("/a2a", json=send("slack_post_message", {"channel": "#eng", "text": "x"}),
                        headers=VIEW)).json()
    assert r["result"]["status"]["state"] == "rejected"
    assert "role_not_permitted" in r["result"]["status"]["message"]["parts"][0]["text"]


async def test_a2a_errors(api):
    assert (await api.post("/a2a", json=send("x", {}))).status_code == 401
    r = (await api.post("/a2a", json=a2a("tasks/cancel", {}), headers=OP)).json()
    assert r["error"]["code"] == -32601
    bad = a2a("message/send", {"message": {"role": "user", "messageId": "m", "parts": [{"kind": "text", "text": "hi"}]}})
    assert (await api.post("/a2a", json=bad, headers=OP)).json()["error"]["code"] == -32602


async def test_audit_verify_is_admin_only(api):
    assert (await api.get("/audit/verify", headers=OP)).status_code == 403
    r = await api.get("/audit/verify", headers=ADMIN)
    assert r.status_code == 200 and r.json()["intact"] is True
