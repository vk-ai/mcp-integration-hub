"""Credential storage: Vault KV v2 when VAULT_ADDR is set, in-memory otherwise.

Both stores implement the same small interface and keep one secret per
(tenant, provider) holding the serialized TokenSet plus connection metadata.
"""
from __future__ import annotations

import os
import re
from typing import Protocol

_NAME = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


def _check(tenant: str, provider: str) -> None:
    if not (_NAME.match(tenant) and _NAME.match(provider)):
        raise ValueError(f"invalid tenant/provider name: {tenant!r}/{provider!r}")


class CredentialStore(Protocol):
    def put(self, tenant: str, provider: str, data: dict) -> None: ...
    def get(self, tenant: str, provider: str) -> dict | None: ...
    def delete(self, tenant: str, provider: str) -> None: ...
    def list(self, tenant: str) -> list[str]: ...


class InMemoryCredentialStore:
    """Test/dev fallback. NOT durable and NOT encrypted; never use it for real tokens."""

    def __init__(self):
        self._data: dict[tuple[str, str], dict] = {}

    def put(self, tenant, provider, data):
        _check(tenant, provider)
        self._data[(tenant, provider)] = dict(data)

    def get(self, tenant, provider):
        _check(tenant, provider)
        v = self._data.get((tenant, provider))
        return dict(v) if v is not None else None

    def delete(self, tenant, provider):
        _check(tenant, provider)
        self._data.pop((tenant, provider), None)

    def list(self, tenant):
        _check(tenant, "_")
        return sorted(p for (t, p) in self._data if t == tenant)


class VaultCredentialStore:
    """HashiCorp Vault KV v2 via hvac. Each write is a new version, so previous
    token sets remain recoverable for forensics."""

    def __init__(self, client, mount: str = "secret", prefix: str = "mcp-hub"):
        self.client = client
        self.mount = mount
        self.prefix = prefix

    def path(self, tenant: str, provider: str) -> str:
        _check(tenant, provider)
        return f"{self.prefix}/{tenant}/{provider}"

    def put(self, tenant, provider, data):
        self.client.secrets.kv.v2.create_or_update_secret(
            path=self.path(tenant, provider), secret=data, mount_point=self.mount)

    def get(self, tenant, provider):
        import hvac.exceptions
        try:
            r = self.client.secrets.kv.v2.read_secret_version(
                path=self.path(tenant, provider), mount_point=self.mount, raise_on_deleted_version=True)
        except hvac.exceptions.InvalidPath:
            return None
        return dict(r["data"]["data"])

    def delete(self, tenant, provider):
        self.client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=self.path(tenant, provider), mount_point=self.mount)

    def list(self, tenant):
        import hvac.exceptions
        _check(tenant, "_")
        try:
            r = self.client.secrets.kv.v2.list_secrets(path=f"{self.prefix}/{tenant}", mount_point=self.mount)
        except hvac.exceptions.InvalidPath:
            return []
        return sorted(r["data"]["keys"])


def store_from_env() -> CredentialStore:
    addr = os.getenv("VAULT_ADDR")
    if not addr:
        return InMemoryCredentialStore()
    import hvac
    client = hvac.Client(url=addr, token=os.getenv("VAULT_TOKEN", ""))
    return VaultCredentialStore(client, mount=os.getenv("VAULT_MOUNT", "secret"),
                                prefix=os.getenv("VAULT_PREFIX", "mcp-hub"))
