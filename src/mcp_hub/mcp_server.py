"""MCP server (official `mcp` Python SDK, v2 `MCPServer`) exposing the hub's
connector tools. Every call goes through ToolGateway (policy, token refresh,
audit) as `settings.mcp_principal`.

    mcp-hub mcp                      # stdio, for Claude Desktop / Cursor / any MCP client
    mcp-hub mcp --http --port 8001   # streamable HTTP
"""
from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .connectors import ConnectorError
from .gateway import PolicyDenied
from .hub import Hub
from .tokens import ReauthRequired

TOOL_DOCS = {
    "github_list_issues": "List GitHub issues in a repository (owner/name).",
    "github_create_issue": "Create a GitHub issue in a repository (owner/name).",
    "slack_list_channels": "List Slack channels in the connected workspace.",
    "slack_post_message": "Post a message to a Slack channel (policy restricts which channels).",
    "hubspot_search_contacts": "Search HubSpot CRM contacts by free-text query.",
    "hubspot_create_contact": "Create a HubSpot CRM contact.",
}


def build_mcp_server(hub: Hub) -> MCPServer:
    srv = MCPServer(
        "mcp-integration-hub",
        instructions="Tools for GitHub, Slack and HubSpot. Calls are policy-checked and audited; "
                     "if a tool says to reconnect, the user must re-run the OAuth connect flow.",
        version="0.1.0",
    )

    async def _call(tool: str, args: dict[str, Any]):
        try:
            return await hub.gateway.call(hub.settings.mcp_principal, tool, args)
        except PolicyDenied as e:
            raise ToolError(f"denied by policy: {e.reason}") from e
        except ReauthRequired as e:
            raise ToolError(f"{e.provider} is not connected for tenant {e.tenant}: {e.reason}; reconnect via the hub") from e
        except ConnectorError as e:
            raise ToolError(f"{e.provider} API error {e.status}: {e.detail[:200]}") from e

    @srv.tool(description=TOOL_DOCS["github_list_issues"])
    async def github_list_issues(repo: str, state: str = "open") -> list[dict]:
        return await _call("github_list_issues", {"repo": repo, "state": state})

    @srv.tool(description=TOOL_DOCS["github_create_issue"])
    async def github_create_issue(repo: str, title: str, body: str = "") -> dict:
        return await _call("github_create_issue", {"repo": repo, "title": title, "body": body})

    @srv.tool(description=TOOL_DOCS["slack_list_channels"])
    async def slack_list_channels() -> list[dict]:
        return await _call("slack_list_channels", {})

    @srv.tool(description=TOOL_DOCS["slack_post_message"])
    async def slack_post_message(channel: str, text: str) -> dict:
        return await _call("slack_post_message", {"channel": channel, "text": text})

    @srv.tool(description=TOOL_DOCS["hubspot_search_contacts"])
    async def hubspot_search_contacts(query: str) -> dict:
        return await _call("hubspot_search_contacts", {"query": query})

    @srv.tool(description=TOOL_DOCS["hubspot_create_contact"])
    async def hubspot_create_contact(email: str, firstname: str = "", lastname: str = "") -> dict:
        return await _call("hubspot_create_contact", {"email": email, "firstname": firstname, "lastname": lastname})

    @srv.tool(description="List this tenant's connected providers (no secrets). Admin only.")
    async def list_connections() -> list[dict]:
        p = hub.settings.mcp_principal
        try:
            await hub.gateway._check_pin({"action": "tool_call", "actor": p.id, "tenant": p.tenant,
                                          "tool": "list_connections", "args": {}, "workflow": None}, "list_connections")
        except PolicyDenied as e:
            raise ToolError(f"denied by policy: {e.reason}") from e
        d = hub.policy.evaluate(p, "list_connections", {})
        if not d.allowed:
            hub.audit.append({"action": "tool_call", "actor": p.id, "tenant": p.tenant, "tool": "list_connections",
                              "decision": "deny", "reason": d.reason, "outcome": "denied"})
            raise ToolError(f"denied by policy: {d.reason}")
        hub.audit.append({"action": "tool_call", "actor": p.id, "tenant": p.tenant, "tool": "list_connections",
                          "decision": "allow", "outcome": "ok"})
        return hub.connections(p.tenant)

    hub.attach_mcp_server(srv)
    return srv
