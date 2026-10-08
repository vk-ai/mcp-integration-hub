import json

from mcp.client import Client

from mcp_hub.mcp_server import build_mcp_server
from mcp_hub.policy import Principal
from conftest import connect

SAAS_TOOLS = {"github_list_issues", "github_create_issue", "slack_list_channels", "slack_post_message",
              "hubspot_search_contacts", "hubspot_create_contact"}


def _payload(result):
    return json.loads(result.content[0].text)


async def test_lists_connector_tools_with_schemas(hub):
    async with Client(build_mcp_server(hub)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert SAAS_TOOLS | {"list_connections"} <= set(tools)
    schema = tools["slack_post_message"].input_schema
    assert set(schema["required"]) == {"channel", "text"}
    assert "Slack" in tools["slack_post_message"].description


async def test_tool_call_reaches_provider(hub, http, sandbox):
    await connect(hub, http, hub.settings.mcp_principal, "slack")
    async with Client(build_mcp_server(hub)) as c:
        r = await c.call_tool("slack_post_message", {"channel": "#alerts", "text": "disk 91%"})
    assert not r.is_error
    assert _payload(r)["ok"] is True
    assert sandbox.slack_messages[-1]["text"] == "disk 91%"
    assert hub.audit.tail(1)[0]["actor"] == "mcp-client"


async def test_policy_denial_is_a_tool_error(hub, http, sandbox):
    hub.settings.mcp_principal = Principal("viewer-bot", "acme", frozenset({"viewer"}))
    async with Client(build_mcp_server(hub)) as c:
        r = await c.call_tool("slack_post_message", {"channel": "#eng", "text": "hi"})
    assert r.is_error and "role_not_permitted" in r.content[0].text
    assert sandbox.slack_messages == []


async def test_not_connected_tells_user_to_reconnect(hub):
    async with Client(build_mcp_server(hub)) as c:
        r = await c.call_tool("github_list_issues", {"repo": "acme/app"})
    assert r.is_error and "reconnect" in r.content[0].text


async def test_list_connections_has_no_secrets(hub, http):
    from mcp_hub.policy import Principal
    hub.settings.mcp_principal = Principal("admin-bot", "acme", frozenset({"admin"}))
    await connect(hub, http, hub.settings.mcp_principal, "github")
    async with Client(build_mcp_server(hub)) as c:
        r = await c.call_tool("list_connections", {})
    text = r.content[0].text
    assert "github" in text and "access_token" not in text and "-at-" not in text
