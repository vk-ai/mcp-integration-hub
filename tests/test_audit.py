import json

from mcp_hub.audit import AuditLog


def test_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.append({"actor": "alice", "action": "tool_call", "tool": "x", "n": i})
    ok, bad = log.verify()
    assert ok and bad is None
    entries = log.tail(10)
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[1]["prev_hash"] == entries[0]["hash"]


def test_tampering_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.append({"actor": "alice", "action": "tool_call", "n": i})
    lines = p.read_text().splitlines()
    e = json.loads(lines[1])
    e["actor"] = "mallory"
    lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    ok, bad = AuditLog(p).verify()
    assert not ok and bad == 2


def test_deleted_line_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.append({"action": "x", "n": i})
    lines = p.read_text().splitlines()
    del lines[2]
    p.write_text("\n".join(lines) + "\n")
    ok, bad = AuditLog(p).verify()
    assert not ok and bad == 4  # seq jumps / prev_hash no longer matches


def test_reopen_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"action": "a"})
    log2 = AuditLog(p)
    e = log2.append({"action": "b"})
    assert e["seq"] == 2
    assert log2.verify() == (True, None)


def test_secrets_are_redacted(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    e = log.append({"action": "tool_call", "args": {"text": "hi", "access_token": "abc",
                                                    "nested": {"client_secret": "s", "Authorization": "Bearer x"}}})
    assert e["args"]["access_token"] == "[REDACTED]"
    assert e["args"]["nested"]["client_secret"] == "[REDACTED]"
    assert e["args"]["nested"]["Authorization"] == "[REDACTED]"
    assert e["args"]["text"] == "hi"
    assert "abc" not in (tmp_path / "a.jsonl").read_text()


def test_in_memory_mode():
    log = AuditLog(None)
    log.append({"action": "a"})
    assert log.verify() == (True, None) and len(log.tail()) == 1
