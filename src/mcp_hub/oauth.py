"""OAuth2 authorization-code + PKCE client with OIDC id_token checks and
refresh-token rotation. Works against the fake sandbox and, with real
credentials, against GitHub / Slack / HubSpot (see config/providers.json).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
import jwt

from .pkce import challenge_s256


class OAuthError(Exception):
    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}".rstrip(": "))
        self.error = error
        self.description = description


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...]
    authorize_url: str
    token_url: str
    api_base: str
    issuer: str | None = None
    jwks_url: str | None = None
    expected_audience: str | None = None  # defaults to client_id
    auth_style: str = "body"  # "body" (form) or "basic" (Authorization header)

    def model_copy(self, update: dict) -> "ProviderConfig":
        return ProviderConfig(**{**self.__dict__, **update})


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None = None
    expires_at: float = 0.0
    scope: str = ""
    id_claims: dict | None = field(default=None, compare=False)
    raw_id_token: str | None = field(default=None, repr=False, compare=False)

    def expired(self, now: float, skew: float = 60.0) -> bool:
        return bool(self.expires_at) and now >= self.expires_at - skew

    def to_dict(self) -> dict:
        return {"access_token": self.access_token, "refresh_token": self.refresh_token,
                "expires_at": self.expires_at, "scope": self.scope}

    @classmethod
    def from_dict(cls, d: dict) -> "TokenSet":
        return cls(d["access_token"], d.get("refresh_token"), d.get("expires_at", 0.0), d.get("scope", ""))


class PendingAuthStore:
    """In-memory state -> {verifier, nonce, principal, provider}, single-use, with TTL."""

    def __init__(self, ttl_s: float = 600.0, clock=time.time):
        self.ttl_s = ttl_s
        self.clock = clock
        self._items: dict[str, tuple[float, dict]] = {}

    def put(self, state: str, data: dict) -> None:
        self._items[state] = (self.clock() + self.ttl_s, data)

    def pop(self, state: str) -> dict | None:
        item = self._items.pop(state, None)
        if item is None or item[0] < self.clock():
            return None
        return item[1]


class OAuthClient:
    def __init__(self, cfg: ProviderConfig, http: httpx.AsyncClient, clock=time.time):
        self.cfg = cfg
        self.http = http
        self.clock = clock
        self._jwks: dict | None = None

    def authorization_url(self, state: str, verifier: str, nonce: str | None = None) -> str:
        q = {
            "response_type": "code",
            "client_id": self.cfg.client_id,
            "redirect_uri": self.cfg.redirect_uri,
            "scope": " ".join(self.cfg.scopes),
            "state": state,
            "code_challenge": challenge_s256(verifier),
            "code_challenge_method": "S256",
        }
        if nonce:
            q["nonce"] = nonce
        return f"{self.cfg.authorize_url}?{urlencode(q)}"

    async def exchange_code(self, code: str, verifier: str, nonce: str | None = None) -> TokenSet:
        ts = await self._token({"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": self.cfg.redirect_uri, "code_verifier": verifier})
        if self.cfg.jwks_url:
            ts.id_claims = await self._verify_id_token(ts.raw_id_token, nonce)
        return ts

    async def refresh(self, current: TokenSet) -> TokenSet:
        ts = await self._token({"grant_type": "refresh_token", "refresh_token": current.refresh_token})
        if ts.refresh_token is None:  # provider did not rotate; keep the old one
            ts.refresh_token = current.refresh_token
        return ts

    async def _token(self, fields: dict) -> TokenSet:
        headers, data = {}, {**fields}
        if self.cfg.auth_style == "basic":
            headers["Authorization"] = httpx.BasicAuth(self.cfg.client_id, self.cfg.client_secret)._auth_header
        else:
            data.update({"client_id": self.cfg.client_id, "client_secret": self.cfg.client_secret})
        try:
            resp = await self.http.post(self.cfg.token_url, data=data, headers=headers)
        except httpx.HTTPError as e:
            raise OAuthError("transport_error", type(e).__name__) from e
        body = resp.json() if resp.content else {}
        if resp.status_code >= 400 or "error" in body:  # GitHub reports errors with HTTP 200
            raise OAuthError(body.get("error", f"http_{resp.status_code}"), body.get("error_description", ""))
        ts = TokenSet(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token"),
            expires_at=self.clock() + body["expires_in"] if "expires_in" in body else 0.0,
            scope=body.get("scope", ""),
        )
        ts.raw_id_token = body.get("id_token")
        return ts

    async def _verify_id_token(self, token: str | None, nonce: str | None) -> dict:
        if not token:
            raise OAuthError("invalid_id_token", "no id_token returned")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_id_token", str(e)) from e
        jwks = await self._get_jwks()
        key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if key is None:
            raise OAuthError("invalid_id_token", f"unknown kid {header.get('kid')}")
        try:
            claims = jwt.decode(
                token, jwt.PyJWK(key).key, algorithms=["RS256"],
                audience=self.cfg.expected_audience or self.cfg.client_id, issuer=self.cfg.issuer,
                # Time claims are checked below against our (injectable) clock.
                options={"require": ["exp", "iat", "sub"], "verify_exp": False, "verify_iat": False,
                         "verify_nbf": False},
            )
        except jwt.PyJWTError as e:
            raise OAuthError("invalid_id_token", str(e)) from e
        now = self.clock()
        if claims["exp"] < now - 30:
            raise OAuthError("invalid_id_token", "id_token expired")
        if claims["iat"] > now + 30:
            raise OAuthError("invalid_id_token", "id_token issued in the future")
        if nonce is not None and claims.get("nonce") != nonce:
            raise OAuthError("invalid_id_token", "nonce mismatch")
        return claims

    async def _get_jwks(self) -> dict:
        if self._jwks is None:
            self._jwks = (await self.http.get(self.cfg.jwks_url)).json()
        return self._jwks
