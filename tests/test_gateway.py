import pytest

from mcp_hub.gateway import PolicyDenied
from mcp_hub.tokens import ReauthRequired
from conftest import connect


async def test_tool_call_hits_provider_and_is_audited(hub, http, alice, sandbox):
    await connect(hub, http, alice, "github")
    out = await hub.gateway.call(alice, "github_create_issue", {"repo": "acme/app", "title": "Flaky test"})
    assert out["number"] == 1 and sandbox.issues["acme/app"][0]["title"] == "Flaky test"
    e = hub.audit.tail(1)[0]
    assert (e["action"], e["actor"], e["tool"], e["decision"], e["outcome"]) == \
        ("tool_call", "alice", "github_create_issue", "allow", "ok")
    assert e["tenant"] == "acme" and e["duration_ms"] >= 0


async def test_denied_call_never_touches_provider(hub, http, victor, sandbox):
    await connect(hub, http, victor, "slack")
    with pytest.raises(PolicyDenied) as ei:
        await hub.gateway.call(victor, "slack_post_message", {"channel": "#eng", "text": "hi"})
    assert ei.value.reason == "role_not_permitted"
    assert sandbox.slack_messages == []
    e = hub.audit.tail(1)[0]
    assert e["decision"] == "deny" and e["reason"] == "role_not_permitted"


async def test_expired_token_refreshed_transparently(hub, http, alice, clock, sandbox):
    await connect(hub, http, alice, "slack")
    clock.advance(4000)
    out = await hub.gateway.call(alice, "slack_post_message", {"channel": "#eng", "text": "after refresh"})
    assert out["ok"] and sandbox.slack_messages[-1]["text"] == "after refresh"


async def test_not_connected_is_reported_and_audited(hub, alice):
    with pytest.raises(ReauthRequired):
        await hub.gateway.call(alice, "hubspot_search_contacts", {"query": "x"})
    e = hub.audit.tail(1)[0]
    assert e["decision"] == "allow" and e["outcome"] == "reauth_required"


async def test_provider_error_is_audited(hub, http, alice):
    from mcp_hub.connectors import ConnectorError
    await connect(hub, http, alice, "hubspot")
    await hub.gateway.call(alice, "hubspot_create_contact", {"email": "a@x.io"})
    with pytest.raises(ConnectorError):
        await hub.gateway.call(alice, "hubspot_create_contact", {"email": "a@x.io"})
    assert hub.audit.tail(1)[0]["outcome"] == "error"


async def test_tenants_are_isolated(hub, http, alice):
    from mcp_hub.policy import Principal
    await connect(hub, http, alice, "github")
    other = Principal(id="bob", tenant="globex", roles=frozenset({"operator"}))
    with pytest.raises(ReauthRequired):
        await hub.gateway.call(other, "github_list_issues", {"repo": "acme/app"})


async def test_unknown_tool(hub, admin):
    with pytest.raises(PolicyDenied):
        await hub.gateway.call(admin, "rm_rf", {})


async def test_audit_chain_intact_after_many_calls(hub, http, alice):
    await connect(hub, http, alice, "github")
    for i in range(3):
        await hub.gateway.call(alice, "github_list_issues", {"repo": "acme/app"})
    assert hub.audit.verify() == (True, None)
    assert {e["action"] for e in hub.audit.tail()} == {"connect", "tool_call"}
