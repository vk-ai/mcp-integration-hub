"""Tool-definition pinning: MCP "rug pull" protection.

An MCP tool's *definition* (name, description, inputSchema, annotations) is
what a model reads to decide how to call it. A malicious or compromised server
can ship a harmless definition, wait for approval, then change the description
or schema (CVE-2025-54136 "MCPoison" is this pattern). Static scans at install
time miss it.

So: when an admin approves a tool we store a SHA-256 fingerprint of its
canonical definition. Before every call the gateway re-fingerprints the
definition currently being served and denies the call (and audit-logs the
drift, including which fields changed) if it no longer matches. Re-approving is
an explicit admin action. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

PINNED_FIELDS = ("name", "description", "inputSchema", "annotations")


def canonical_definition(defn: dict) -> dict:
    """The fields that change model behaviour; missing/None fields are normalised away."""
    out = {}
    for f in PINNED_FIELDS:
        v = defn.get(f)
        if v is None and f == "inputSchema":
            v = defn.get("input_schema")
        if v not in (None, {}, ""):
            out[f] = v
    return out


def fingerprint(defn: dict) -> str:
    body = json.dumps(canonical_definition(defn), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


def changed_fields(old: dict, new: dict) -> list[str]:
    a, b = canonical_definition(old), canonical_definition(new)
    return [f for f in PINNED_FIELDS if a.get(f) != b.get(f)]


@dataclass(frozen=True)
class PinCheck:
    ok: bool
    reason: str  # ok | not_pinned | definition_missing | definition_changed
    pinned: str | None = None
    current: str | None = None
    changed: tuple[str, ...] = ()


class ToolPinStore:
    """Approved fingerprints, optionally persisted as a JSON file (``MCP_HUB_TOOL_PINS``)."""

    def __init__(self, path: str | Path | None = None, clock=time.time):
        self.path = Path(path) if path else None
        self.clock = clock
        self._lock = threading.Lock()
        self._pins: dict[str, dict] = {}
        if self.path and self.path.exists():
            self._pins = json.loads(self.path.read_text()).get("tools", {})

    def _save(self) -> None:
        if self.path:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps({"version": 1, "tools": self._pins}, indent=2, sort_keys=True) + "\n")
            tmp.replace(self.path)

    def approve(self, defn: dict, approved_by: str) -> dict:
        name = defn["name"]
        rec = {"fingerprint": fingerprint(defn), "approved_by": approved_by, "approved_at": self.clock(),
               "definition": canonical_definition(defn)}
        with self._lock:
            self._pins[name] = rec
            self._save()
        return rec

    def revoke(self, name: str) -> bool:
        with self._lock:
            gone = self._pins.pop(name, None) is not None
            self._save()
        return gone

    def get(self, name: str) -> dict | None:
        return self._pins.get(name)

    def names(self) -> list[str]:
        return sorted(self._pins)

    def check(self, name: str, defn: dict | None) -> PinCheck:
        pin = self._pins.get(name)
        if pin is None:
            return PinCheck(False, "not_pinned", current=fingerprint(defn) if defn else None)
        if defn is None:
            return PinCheck(False, "definition_missing", pin["fingerprint"])
        cur = fingerprint(defn)
        if cur != pin["fingerprint"]:
            return PinCheck(False, "definition_changed", pin["fingerprint"], cur,
                            tuple(changed_fields(pin["definition"], defn)))
        return PinCheck(True, "ok", cur, cur)


def tool_to_dict(tool) -> dict:
    """mcp ``Tool`` model (or a plain dict) -> wire-format dict."""
    if isinstance(tool, dict):
        return tool
    return tool.model_dump(by_alias=True, exclude_none=True, mode="json")
