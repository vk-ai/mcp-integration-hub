import os
import uuid

import pytest

from mcp_hub.credentials import InMemoryCredentialStore, VaultCredentialStore, store_from_env


def _exercise(store):
    t = f"tenant-{uuid.uuid4().hex[:6]}"
    assert store.get(t, "slack") is None
    store.put(t, "slack", {"access_token": "a1", "refresh_token": "r1"})
    store.put(t, "github", {"access_token": "g1"})
    assert store.get(t, "slack")["access_token"] == "a1"
    store.put(t, "slack", {"access_token": "a2", "refresh_token": "r2"})
    assert store.get(t, "slack")["access_token"] == "a2"
    assert sorted(store.list(t)) == ["github", "slack"]
    store.delete(t, "slack")
    assert store.get(t, "slack") is None
    assert store.list(t) == ["github"]
    assert store.list("nobody-" + t) == []


def test_in_memory_store():
    _exercise(InMemoryCredentialStore())


def test_in_memory_returns_copies():
    s = InMemoryCredentialStore()
    s.put("t", "p", {"access_token": "x"})
    s.get("t", "p")["access_token"] = "mutated"
    assert s.get("t", "p")["access_token"] == "x"


def test_rejects_path_traversal_in_names():
    s = InMemoryCredentialStore()
    for bad in ("../x", "a/b", "", "a b"):
        with pytest.raises(ValueError):
            s.put(bad, "slack", {})
        with pytest.raises(ValueError):
            s.put("t", bad, {})


def test_store_from_env_falls_back_to_memory(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    assert isinstance(store_from_env(), InMemoryCredentialStore)


@pytest.mark.vault
@pytest.mark.skipif(not os.getenv("VAULT_ADDR"), reason="set VAULT_ADDR and VAULT_TOKEN to run Vault tests")
def test_vault_kv2_store():
    import hvac
    client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    store = VaultCredentialStore(client, mount="secret", prefix=f"mcp-hub-test-{uuid.uuid4().hex[:6]}")
    _exercise(store)


@pytest.mark.vault
@pytest.mark.skipif(not os.getenv("VAULT_ADDR"), reason="set VAULT_ADDR and VAULT_TOKEN to run Vault tests")
def test_vault_keeps_versions():
    import hvac
    client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    store = VaultCredentialStore(client, mount="secret", prefix=f"mcp-hub-test-{uuid.uuid4().hex[:6]}")
    store.put("acme", "slack", {"access_token": "v1"})
    store.put("acme", "slack", {"access_token": "v2"})
    meta = client.secrets.kv.v2.read_secret_metadata(path=store.path("acme", "slack"), mount_point="secret")
    assert meta["data"]["current_version"] == 2
