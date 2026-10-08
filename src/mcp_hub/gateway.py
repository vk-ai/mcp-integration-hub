"""The one place tool calls go through: policy -> token -> connector -> audit."""
from __future__ import annotations

import time

from .audit import AuditLog
from .connectors import SaaSConnectors
from .policy import Decision, PolicyEngine, Principal
from .tokens import ReauthRequired


class PolicyDenied(Exception):
    def __init__(self, decision: Decision):
        super().__init__(f"denied: {decision.reason}")
        self.reason = decision.reason


class ToolGateway:
    def __init__(self, policy: PolicyEngine, connectors: SaaSConnectors, audit: AuditLog, clock=time.time):
        self.policy, self.connectors, self.audit, self.clock = policy, connectors, audit, clock

    async def call(self, principal: Principal, tool: str, args: dict, *, workflow: str | None = None) -> dict | list:
        started = self.clock()
        decision = self.policy.evaluate(principal, tool, args)
        base = {"action": "tool_call", "actor": principal.id, "tenant": principal.tenant, "tool": tool,
                "args": args, "workflow": workflow}
        if not decision.allowed:
            self.audit.append({**base, "decision": "deny", "reason": decision.reason, "outcome": "denied",
                               "duration_ms": 0})
            raise PolicyDenied(decision)
        try:
            result = await getattr(self.connectors, tool)(principal.tenant, **args)
        except ReauthRequired:
            self.audit.append({**base, "decision": "allow", "outcome": "reauth_required",
                               "duration_ms": int((self.clock() - started) * 1000)})
            raise
        except Exception as e:
            self.audit.append({**base, "decision": "allow", "outcome": "error", "error": f"{type(e).__name__}",
                               "duration_ms": int((self.clock() - started) * 1000)})
            raise
        self.audit.append({**base, "decision": "allow", "outcome": "ok",
                           "duration_ms": int((self.clock() - started) * 1000)})
        return result
