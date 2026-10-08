"""A2A (Agent2Agent, protocol 0.3) agent card and a minimal JSON-RPC handler.

Supported: `message/send` with a DataPart `{"skill": <tool>, "arguments": {...}}`
and `tasks/get`. Not supported: streaming, push notifications, free-text
messages (there is no LLM here to interpret them), task cancellation.
"""
from __future__ import annotations

import uuid

from .connectors import ConnectorError
from .gateway import PolicyDenied
from .hub import Hub
from .mcp_server import TOOL_DOCS
from .policy import Principal
from .tokens import ReauthRequired


def agent_card(hub: Hub) -> dict:
    base = hub.settings.public_base_url
    return {
        "protocolVersion": "0.3.0",
        "name": "mcp-integration-hub",
        "description": "Policy-checked, audited GitHub, Slack and HubSpot actions for other agents.",
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": "0.1.0",
        "provider": {"organization": "vk-ai (learning project)", "url": "https://github.com/vk-ai/mcp-integration-hub"},
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "securitySchemes": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
        "security": [{"apiKey": []}],
        "skills": [
            {"id": tool, "name": tool.replace("_", " "), "description": doc,
             "tags": [tool.split("_")[0]], "inputModes": ["application/json"], "outputModes": ["application/json"],
             "examples": [f'{{"skill": "{tool}", "arguments": {{...}}}}']}
            for tool, doc in TOOL_DOCS.items()
        ],
    }


class A2AHandler:
    def __init__(self, hub: Hub):
        self.hub = hub
        self.tasks: dict[str, tuple[str, dict]] = {}  # task id -> (tenant, task)

    @staticmethod
    def _err(id_, code, msg):
        return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}

    @staticmethod
    def _task(state: str, result=None, message: str | None = None, context_id: str | None = None) -> dict:
        t = {"kind": "task", "id": uuid.uuid4().hex, "contextId": context_id or uuid.uuid4().hex,
             "status": {"state": state}}
        if message:
            t["status"]["message"] = {"kind": "message", "role": "agent", "messageId": uuid.uuid4().hex,
                                      "parts": [{"kind": "text", "text": message}]}
        if result is not None:
            t["artifacts"] = [{"artifactId": uuid.uuid4().hex, "name": "result",
                               "parts": [{"kind": "data", "data": result if isinstance(result, dict) else {"items": result}}]}]
        return t

    async def handle(self, principal: Principal, req: dict) -> dict:
        id_ = req.get("id")
        if req.get("jsonrpc") != "2.0" or "method" not in req:
            return self._err(id_, -32600, "invalid request")
        method, params = req["method"], req.get("params") or {}
        if method == "tasks/get":
            entry = self.tasks.get(params.get("id", ""))
            if entry is None or entry[0] != principal.tenant:
                return self._err(id_, -32001, "task not found")
            return {"jsonrpc": "2.0", "id": id_, "result": entry[1]}
        if method != "message/send":
            return self._err(id_, -32601, f"method not supported: {method}")
        parts = (params.get("message") or {}).get("parts") or []
        data = next((p.get("data") for p in parts if p.get("kind") == "data"), None)
        if not isinstance(data, dict) or "skill" not in data:
            return self._err(id_, -32602, "expected a data part with {skill, arguments}")
        ctx = (params.get("message") or {}).get("contextId")
        try:
            result = await self.hub.gateway.call(principal, data["skill"], dict(data.get("arguments") or {}))
            task = self._task("completed", result, context_id=ctx)
        except PolicyDenied as e:
            task = self._task("rejected", message=f"denied by policy: {e.reason}", context_id=ctx)
        except ReauthRequired as e:
            task = self._task("failed", message=str(e), context_id=ctx)
        except (ConnectorError, TypeError) as e:
            task = self._task("failed", message=f"{type(e).__name__}: {e}", context_id=ctx)
        self.tasks[task["id"]] = (principal.tenant, task)
        return {"jsonrpc": "2.0", "id": id_, "result": task}
