"""The MCP server over a real stdio transport (subprocess)."""
import os
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters


async def test_stdio_server_lists_tools_and_reports_reconnect(tmp_path):
    env = {**os.environ, "MCP_HUB_AUDIT_PATH": str(tmp_path / "audit.jsonl")}
    env.pop("VAULT_ADDR", None)
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_hub.cli", "mcp"], env=env)
    async with Client(params) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"github_create_issue", "slack_post_message", "hubspot_create_contact"} <= names
        r = await c.call_tool("slack_list_channels", {})
        assert r.is_error and "not connected" in r.content[0].text
    assert "reauth_required" in (tmp_path / "audit.jsonl").read_text()
