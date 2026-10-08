from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_hub.oauth import OAuthClient, OAuthError, PendingAuthStore, TokenSet
from mcp_hub.pkce import new_verifier
from mcp_hub.hub import sandbox_settings
from conftest import HUB_BASE


@pytest.fixture
def cfg():
    return sandbox_settings("http://sandbox", HUB_BASE).providers["slack"]


@pytest.fixture
def client(cfg, http, clock):
    return OAuthClient(cfg, http, clock=clock)


async def _code(http, url):
    r = await http.get(url)
    assert r.status_code == 302
    return parse_qs(urlparse(r.headers["location"]).query)


def test_authorization_url_has_pkce_and_state(client):
    url = client.authorization_url(state="st", verifier="v" * 43, nonce="n1")
    q = parse_qs(urlparse(url).query)
    assert q["response_type"] == ["code"] and q["code_challenge_method"] == ["S256"]
    assert q["state"] == ["st"] and q["nonce"] == ["n1"]
    assert q["redirect_uri"] == [f"{HUB_BASE}/oauth/slack/callback"]
    assert "openid" in q["scope"][0]
    assert "code_verifier" not in q  # the verifier never leaves the server


async def test_full_code_exchange_with_oidc(client, http):
    v = new_verifier()
    q = await _code(http, client.authorization_url("s", v, nonce="abc"))
    ts = await client.exchange_code(q["code"][0], v, nonce="abc")
    assert ts.access_token.startswith("slack-at-") and ts.refresh_token
    assert ts.expires_at == pytest.approx(client.clock() + 3600)
    assert ts.id_claims["sub"] == "sandbox-user" and ts.id_claims["email"] == "sandbox-user@example.com"


async def test_wrong_verifier_rejected(client, http):
    q = await _code(http, client.authorization_url("s", new_verifier()))
    with pytest.raises(OAuthError) as ei:
        await client.exchange_code(q["code"][0], new_verifier())
    assert ei.value.error == "invalid_grant"


async def test_code_is_single_use(client, http):
    v = new_verifier()
    q = await _code(http, client.authorization_url("s", v))
    await client.exchange_code(q["code"][0], v)
    with pytest.raises(OAuthError):
        await client.exchange_code(q["code"][0], v)


async def test_nonce_mismatch_rejected(client, http):
    v = new_verifier()
    q = await _code(http, client.authorization_url("s", v, nonce="expected"))
    with pytest.raises(OAuthError) as ei:
        await client.exchange_code(q["code"][0], v, nonce="different")
    assert ei.value.error == "invalid_id_token"


async def test_id_token_audience_checked(cfg, http, clock):
    other = OAuthClient(cfg.model_copy(update={"client_id": "slack-client"}), http, clock=clock)
    v = new_verifier()
    q = await _code(http, other.authorization_url("s", v, nonce="n"))
    # Same token but validated as if we were a different client id.
    tampered = OAuthClient(cfg.model_copy(update={"expected_audience": "someone-else"}), http, clock=clock)
    with pytest.raises(OAuthError) as ei:
        await tampered.exchange_code(q["code"][0], v, nonce="n")
    assert ei.value.error == "invalid_id_token"


async def test_refresh_rotates_and_reuse_is_detected(client, http):
    v = new_verifier()
    q = await _code(http, client.authorization_url("s", v))
    first = await client.exchange_code(q["code"][0], v)
    second = await client.refresh(first)
    assert second.access_token != first.access_token
    assert second.refresh_token != first.refresh_token
    with pytest.raises(OAuthError) as ei:
        await client.refresh(first)  # old refresh token replayed
    assert ei.value.error == "invalid_grant"


async def test_refresh_keeps_old_refresh_token_if_provider_does_not_rotate(cfg, clock):
    def handler(req):
        return httpx.Response(200, json={"access_token": "new", "expires_in": 60, "token_type": "bearer"})
    c = OAuthClient(cfg, httpx.AsyncClient(transport=httpx.MockTransport(handler)), clock=clock)
    out = await c.refresh(TokenSet(access_token="old", refresh_token="keep-me", expires_at=0))
    assert out.access_token == "new" and out.refresh_token == "keep-me"


async def test_github_style_error_in_200_body(cfg, clock):
    # GitHub's token endpoint returns HTTP 200 with an "error" field.
    def handler(req):
        return httpx.Response(200, json={"error": "bad_verification_code", "error_description": "expired"})
    c = OAuthClient(cfg, httpx.AsyncClient(transport=httpx.MockTransport(handler)), clock=clock)
    with pytest.raises(OAuthError) as ei:
        await c.exchange_code("x", "v" * 43)
    assert ei.value.error == "bad_verification_code"


async def test_bad_client_secret(cfg, http, clock):
    c = OAuthClient(cfg.model_copy(update={"client_secret": "wrong"}), http, clock=clock)
    with pytest.raises(OAuthError) as ei:
        await c.refresh(TokenSet(access_token="a", refresh_token="r", expires_at=0))
    assert ei.value.error == "invalid_client"


def test_tokenset_expiry_and_roundtrip():
    t = TokenSet(access_token="a", refresh_token="r", expires_at=1000.0, scope="x")
    assert t.expired(now=950, skew=60) and not t.expired(now=900, skew=60)
    assert TokenSet.from_dict(t.to_dict()) == t
    assert not TokenSet(access_token="a").expired(now=10**12)


def test_pending_auth_is_single_use_and_expires(clock):
    s = PendingAuthStore(ttl_s=600, clock=clock)
    s.put("st1", {"provider": "slack"})
    assert s.pop("st1")["provider"] == "slack"
    assert s.pop("st1") is None
    s.put("st2", {"provider": "slack"})
    clock.advance(601)
    assert s.pop("st2") is None
