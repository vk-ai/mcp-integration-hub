"""Per-(tenant, provider) token access with refresh-on-demand and single-flight
refresh, so concurrent tool calls don't rotate the same refresh token twice
(which the provider would treat as reuse and revoke)."""
from __future__ import annotations

import asyncio
import time

from .credentials import CredentialStore
from .oauth import OAuthClient, OAuthError, TokenSet


class ReauthRequired(Exception):
    def __init__(self, tenant: str, provider: str, reason: str):
        super().__init__(f"{tenant}/{provider}: {reason}; reconnect via /connect/{provider}")
        self.tenant, self.provider, self.reason = tenant, provider, reason


class TokenManager:
    def __init__(self, store: CredentialStore, clients: dict[str, OAuthClient], clock=time.time):
        self.store = store
        self.clients = clients
        self.clock = clock
        self._locks: dict[tuple, asyncio.Lock] = {}

    def save(self, tenant: str, provider: str, ts: TokenSet, subject: str) -> None:
        self.store.put(tenant, provider, {**ts.to_dict(), "subject": subject})

    async def access_token(self, tenant: str, provider: str) -> str:
        lock = self._locks.setdefault((tenant, provider), asyncio.Lock())
        async with lock:
            data = self.store.get(tenant, provider)
            if data is None:
                raise ReauthRequired(tenant, provider, "not connected")
            ts = TokenSet.from_dict(data)
            if not ts.expired(self.clock()):
                return ts.access_token
            try:
                fresh = await self.clients[provider].refresh(ts)
            except OAuthError as e:
                self.store.delete(tenant, provider)
                raise ReauthRequired(tenant, provider, f"refresh failed ({e.error})") from e
            self.save(tenant, provider, fresh, data.get("subject", ""))
            return fresh.access_token
