import asyncio

import pytest

from mcp_hub.tokens import ReauthRequired
from conftest import connect


async def test_connect_stores_tokens_in_credential_store(hub, http, alice):
    summary = await connect(hub, http, alice, "slack")
    assert summary == {"tenant": "acme", "provider": "slack", "subject": "sandbox-user",
                       "scope": "openid chat:write channels:read"}
    stored = hub.credentials.get("acme", "slack")
    assert stored["access_token"].startswith("slack-at-") and stored["refresh_token"]
    assert "id_token" not in stored  # only what is needed is kept


async def test_unknown_or_replayed_state_rejected(hub, http, alice):
    from urllib.parse import parse_qs, urlparse
    url = hub.begin_connect(alice, "github")
    q = parse_qs(urlparse((await http.get(url)).headers["location"]).query)
    await hub.complete_connect("github", q["code"][0], q["state"][0])
    with pytest.raises(PermissionError):
        await hub.complete_connect("github", q["code"][0], q["state"][0])
    with pytest.raises(PermissionError):
        await hub.complete_connect("github", "code", "forged-state")


async def test_state_bound_to_provider(hub, http, alice):
    from urllib.parse import parse_qs, urlparse
    url = hub.begin_connect(alice, "github")
    q = parse_qs(urlparse((await http.get(url)).headers["location"]).query)
    with pytest.raises(PermissionError):
        await hub.complete_connect("slack", q["code"][0], q["state"][0])


async def test_expired_access_token_is_refreshed(hub, http, alice, clock, sandbox):
    await connect(hub, http, alice, "slack")
    old = hub.credentials.get("acme", "slack")
    clock.advance(3600)
    tok = await hub.tokens.access_token("acme", "slack")
    new = hub.credentials.get("acme", "slack")
    assert tok == new["access_token"] != old["access_token"]
    assert new["refresh_token"] != old["refresh_token"]  # rotated and persisted


async def test_concurrent_callers_refresh_once(hub, http, alice, clock, sandbox):
    await connect(hub, http, alice, "slack")
    clock.advance(3600)
    before = sandbox.token_requests
    toks = await asyncio.gather(*[hub.tokens.access_token("acme", "slack") for _ in range(5)])
    assert len(set(toks)) == 1
    assert sandbox.token_requests == before + 1


async def test_not_connected_requires_reauth(hub):
    with pytest.raises(ReauthRequired):
        await hub.tokens.access_token("acme", "hubspot")


async def test_dead_refresh_token_requires_reauth_and_clears(hub, http, alice, clock):
    await connect(hub, http, alice, "slack")
    stored = hub.credentials.get("acme", "slack")
    hub.credentials.put("acme", "slack", {**stored, "refresh_token": "revoked", "expires_at": 1})
    with pytest.raises(ReauthRequired):
        await hub.tokens.access_token("acme", "slack")
    assert hub.credentials.get("acme", "slack") is None
