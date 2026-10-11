"""The one place tool calls go through: policy -> token -> connector -> audit."""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from .audit import AuditLog
from .connectors import SaaSConnectors
from .pinning import ToolPinStore
from .policy import Decision, PolicyEngine, Principal
from .tokens import ReauthRequired


DefinitionsProvider = Callable[[], Awaitable[dict[str, dict]]]


class PolicyDenied(Exception):
    def __init__(self, decision: Decision):
        super().__init__(f"denied: {decision.reason}")
        self.reason = decision.reason


class ToolGateway:
    def __init__(self, policy: PolicyEngine, connectors: SaaSConnectors, audit: AuditLog, clock=time.time,
                 pins: ToolPinStore | None = None, definitions: DefinitionsProvider | None = None):
        self.policy, self.connectors, self.audit, self.clock = policy, connectors, audit, clock
        # Pinning is opt-in (None = off) so existing deployments keep working; see pinning.py.
        self.pins, self.definitions = pins, definitions

    async def _check_pin(self, base: dict, tool: str) -> None:
        if self.pins is None:
            return
        defs = await self.definitions() if self.definitions else {}
        chk = self.pins.check(tool, defs.get(tool))
        if chk.ok:
            return
        if chk.reason == "definition_changed":
            self.audit.append({"action": "tool_definition_drift", "tool": tool, "pinned_fingerprint": chk.pinned,
                               "current_fingerprint": chk.current, "changed_fields": list(chk.changed),
                               "actor": base["actor"], "tenant": base["tenant"]})
        self.audit.append({**base, "decision": "deny", "reason": f"tool_{chk.reason}", "outcome": "denied",
                           "pinned_fingerprint": chk.pinned, "current_fingerprint": chk.current, "duration_ms": 0})
        raise PolicyDenied(Decision(False, f"tool_{chk.reason}"))

    async def call(self, principal: Principal, tool: str, args: dict, *, workflow: str | None = None) -> dict | list:
        started = self.clock()
        decision = self.policy.evaluate(principal, tool, args)
        base = {"action": "tool_call", "actor": principal.id, "tenant": principal.tenant, "tool": tool,
                "args": args, "workflow": workflow}
        await self._check_pin(base, tool)  # before policy, so a drifted tool never consumes rate limit
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
