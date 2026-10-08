"""RBAC policy: roles (with inheritance), per-tool argument allowlists and
per-(principal, tool) rate limits. Default deny for unknown tools."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import json


@dataclass(frozen=True)
class Principal:
    id: str
    tenant: str
    roles: frozenset[str]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = "ok"
    matched_role: str | None = None


@dataclass
class _Window:
    start: float = 0.0
    count: int = 0


class PolicyEngine:
    def __init__(self, policy: dict, clock=time.time):
        self.policy = policy
        self.clock = clock
        self._windows: dict[tuple, _Window] = {}
        self._validate()

    def _validate(self) -> None:
        roles = self.policy.get("roles", {})
        for name, spec in roles.items():
            for parent in spec.get("inherits", []):
                if parent not in roles:
                    raise ValueError(f"role {name!r} inherits unknown role {parent!r}")
            seen = set()

            def walk(r):
                if r in seen:
                    raise ValueError(f"role inheritance cycle at {r!r}")
                seen.add(r)
                for p in roles.get(r, {}).get("inherits", []):
                    walk(p)

            seen.clear()
            walk(name)

    def effective_roles(self, roles: frozenset[str]) -> set[str]:
        out: set[str] = set()

        def walk(r):
            if r in out or r not in self.policy["roles"]:
                return
            out.add(r)
            for p in self.policy["roles"][r].get("inherits", []):
                walk(p)

        for r in roles:
            walk(r)
        return out

    def tools_for(self, principal: Principal) -> set[str]:
        tools: set[str] = set()
        for r in self.effective_roles(principal.roles):
            tools.update(self.policy["roles"][r].get("tools", []))
        return tools

    def evaluate(self, principal: Principal, tool: str, args: dict) -> Decision:
        spec = self.policy["tools"].get(tool)
        if spec is None:
            return Decision(False, "unknown_tool")
        matched = next((r for r in self.effective_roles(principal.roles)
                        if tool in self.policy["roles"][r].get("tools", [])), None)
        if matched is None:
            return Decision(False, "role_not_permitted")
        for arg, rule in spec.get("args", {}).items():
            value = str(args.get(arg, ""))
            if "allow" in rule and value not in rule["allow"]:
                return Decision(False, f"arg_not_allowed:{arg}")
            if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
                return Decision(False, f"arg_not_allowed:{arg}")
        limit = spec.get("rate_limit")
        if limit and not self._consume(principal, tool, limit):
            return Decision(False, "rate_limited")
        return Decision(True, "ok", matched)

    def _consume(self, principal: Principal, tool: str, limit: dict) -> bool:
        key = (principal.tenant, principal.id, tool)
        w = self._windows.setdefault(key, _Window())
        now = self.clock()
        if now - w.start >= limit["per_seconds"]:
            w.start, w.count = now, 0
        if w.count >= limit["max"]:
            return False
        w.count += 1
        return True


def load_default_policy() -> dict:
    return json.loads((Path(__file__).parent / "config" / "policy.json").read_text())
