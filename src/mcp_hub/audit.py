"""Append-only audit log with a hash chain.

Each entry carries `seq`, `prev_hash` and `hash = SHA256(prev_hash || canonical
JSON of the entry)`. `verify()` re-walks the chain and reports the first entry
whose hash or predecessor doesn't match, which catches edits, deletions and
reordering. It detects tampering after the fact; it is not a tamper-proof store
(whoever can write the file can rewrite the whole chain).
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

_SECRET_KEYS = {"access_token", "refresh_token", "id_token", "client_secret", "authorization",
                "code", "code_verifier", "token", "password"}
GENESIS = "0" * 64


def redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in _SECRET_KEYS else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def _canonical(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def hash_entry(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256(f"{prev_hash}|{_canonical(entry)}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._entries.append(json.loads(line))

    def append(self, event: dict) -> dict:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else GENESIS
            entry = {**redact(event), "seq": len(self._entries) + 1, "prev_hash": prev, "hash": ""}
            entry["hash"] = hash_entry(prev, entry)
            self._entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")
            return entry

    def tail(self, n: int | None = None) -> list[dict]:
        return self._entries[-n:] if n else list(self._entries)

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if the chain is intact, else (False, seq of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(self._entries, start=1):
            if e.get("seq") != i or e.get("prev_hash") != prev or e.get("hash") != hash_entry(prev, e):
                return False, e.get("seq", i)
            prev = e["hash"]
        return True, None
