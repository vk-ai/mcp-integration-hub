"""pytest-bdd scenarios (features/webhook_workflows.feature)."""
import asyncio
import hashlib
import hmac
import json

import httpx
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from mcp_hub.gateway import PolicyDenied
from mcp_hub.http_app import create_app
from conftest import HUB_BASE

scenarios("webhook_workflows.feature")


@pytest.fixture
def ctx():
    return {}



@pytest.fixture
def loop():
    lp = asyncio.new_event_loop()
    asyncio.set_event_loop(lp)
    yield lp
    lp.close()


@pytest.fixture
def sync_hub(fake, clock, tmp_path, loop):
    from mcp_hub.credentials import InMemoryCredentialStore
    from mcp_hub.hub import Hub, sandbox_settings
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake), base_url="http://sandbox")
    hub = Hub.build(sandbox_settings("http://sandbox", HUB_BASE), http=http, clock=clock,
                    audit_path=tmp_path / "audit.jsonl", credentials=InMemoryCredentialStore())
    hub._test_http = http
    return hub


@given("the acme tenant has connected GitHub, Slack and HubSpot")
def connected(sync_hub, loop):
    from conftest import connect
    from mcp_hub.policy import Principal
    alice = Principal("alice", "acme", frozenset({"operator"}))
    for p in ("github", "slack", "hubspot"):
        loop.run_until_complete(connect(sync_hub, sync_hub._test_http, alice, p))


def _post_webhook(hub, loop, body, secret):
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(hub)), base_url=HUB_BASE) as c:
            return await c.post("/webhooks/github", content=body, headers={
                "X-Hub-Signature-256": sig, "X-GitHub-Event": "issues", "X-GitHub-Delivery": "bdd-1"})
    return loop.run_until_complete(go())


@when(parsers.parse('GitHub sends a signed "issues" webhook for a new issue titled "{title}"'))
def signed_webhook(sync_hub, loop, ctx, title):
    body = json.dumps({"action": "opened", "issue": {"title": title, "html_url": ""}}).encode()
    ctx["resp"] = _post_webhook(sync_hub, loop, body, "dev-github-webhook-secret")


@when(parsers.parse('someone sends an "issues" webhook with a bad signature'))
def forged_webhook(sync_hub, loop, ctx):
    ctx["resp"] = _post_webhook(sync_hub, loop, b'{"action":"opened","issue":{"title":"x"}}', "guess")


@when(parsers.parse('viewer "{who}" calls "{tool}" on "{channel}"'))
def viewer_call(sync_hub, loop, ctx, who, tool, channel):
    from mcp_hub.policy import Principal
    p = Principal(who, "acme", frozenset({"viewer"}))
    try:
        loop.run_until_complete(sync_hub.gateway.call(p, tool, {"channel": channel, "text": "hi"}))
    except PolicyDenied as e:
        ctx["denied"] = e.reason


@then(parsers.parse('Slack channel "{channel}" receives "{text}"'))
def slack_receives(fake, channel, text):
    msg = fake.state.sandbox.slack_messages[-1]
    assert msg["channel"] == channel and msg["text"].strip() == text


@then("the audit log chain is intact")
def audit_ok(sync_hub):
    assert sync_hub.audit.verify() == (True, None)


@then(parsers.parse("the hub answers {status:d}"))
def hub_answers(ctx, status):
    assert ctx["resp"].status_code == status


@then("Slack receives nothing")
def slack_nothing(fake):
    assert fake.state.sandbox.slack_messages == []


@then(parsers.parse('the call is denied with "{reason}"'))
def denied_with(ctx, reason):
    assert ctx["denied"] == reason


@then("the denial is in the audit log")
def denial_logged(sync_hub):
    e = sync_hub.audit.tail(1)[0]
    assert e["decision"] == "deny" and e["actor"] == "victor"
