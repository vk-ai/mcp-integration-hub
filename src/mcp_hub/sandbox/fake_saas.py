"""A local fake of three SaaS providers (GitHub, Slack, HubSpot): an OAuth2 /
OIDC authorization server per provider plus a tiny slice of each REST API.

It is strict where it matters for testing the client: PKCE S256 is verified,
codes are single-use and short-lived, redirect URIs must match, refresh tokens
rotate and a reused refresh token is rejected, access tokens expire, and
`id_token`s are RS256-signed with a published JWKS.

Run standalone: `uvicorn mcp_hub.sandbox.fake_saas:app --port 9000`.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

PROVIDERS = ("github", "slack", "hubspot")


@dataclass
class ClientReg:
    client_id: str
    client_secret: str
    redirect_uris: list[str]


@dataclass
class Grant:
    provider: str
    client_id: str
    redirect_uri: str
    challenge: str
    method: str
    scope: str
    nonce: str | None
    subject: str
    created: float


@dataclass
class SandboxState:
    clients: dict[str, ClientReg] = field(default_factory=dict)  # key: f"{provider}:{client_id}"
    codes: dict[str, Grant] = field(default_factory=dict)
    access: dict[str, tuple[str, float, str]] = field(default_factory=dict)  # token -> (provider, exp, subject)
    refresh: dict[str, tuple[str, str, str, str]] = field(default_factory=dict)  # token -> (provider, client, scope, sub)
    used_refresh: set[str] = field(default_factory=set)
    issues: dict[str, list[dict]] = field(default_factory=dict)
    slack_messages: list[dict] = field(default_factory=list)
    contacts: list[dict] = field(default_factory=list)
    token_requests: int = 0
    access_ttl: float = 3600.0
    clock: object = time.time


def create_fake_saas(base_url: str = "http://sandbox", access_ttl: float = 3600.0, clock=time.time) -> FastAPI:
    app = FastAPI(title="fake-saas-sandbox")
    st = SandboxState(access_ttl=access_ttl, clock=clock)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "sandbox-1"
    app.state.sandbox = st
    app.state.base_url = base_url.rstrip("/")

    def register(provider: str, client_id: str, client_secret: str, redirect_uris: list[str]) -> None:
        st.clients[f"{provider}:{client_id}"] = ClientReg(client_id, client_secret, redirect_uris)

    def expire_access_tokens() -> None:
        for t, (p, _, sub) in list(st.access.items()):
            st.access[t] = (p, 0.0, sub)

    app.state.register = register
    app.state.expire_access_tokens = expire_access_tokens

    def issuer(p: str) -> str:
        return f"{app.state.base_url}/{p}"

    def check_provider(p: str) -> None:
        if p not in PROVIDERS:
            raise HTTPException(404, "unknown provider")

    # ---- OAuth2 / OIDC -----------------------------------------------------
    @app.get("/{p}/.well-known/openid-configuration")
    def discovery(p: str):
        check_provider(p)
        return {
            "issuer": issuer(p),
            "authorization_endpoint": f"{issuer(p)}/oauth/authorize",
            "token_endpoint": f"{issuer(p)}/oauth/token",
            "jwks_uri": f"{issuer(p)}/jwks",
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    @app.get("/{p}/jwks")
    def jwks(p: str):
        check_provider(p)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    @app.get("/{p}/oauth/authorize")
    def authorize(p: str, response_type: str, client_id: str, redirect_uri: str, state: str,
                  code_challenge: str = "", code_challenge_method: str = "", scope: str = "",
                  nonce: str | None = None, login_hint: str = "sandbox-user"):
        check_provider(p)
        reg = st.clients.get(f"{p}:{client_id}")
        if reg is None or redirect_uri not in reg.redirect_uris:
            raise HTTPException(400, "invalid client or redirect_uri")  # never redirect to an unknown URI
        if response_type != "code":
            return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'unsupported_response_type', 'state': state})}")
        if not code_challenge or code_challenge_method != "S256":
            return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'invalid_request', 'error_description': 'PKCE S256 required', 'state': state})}")
        code = secrets.token_urlsafe(24)
        st.codes[code] = Grant(p, client_id, redirect_uri, code_challenge, code_challenge_method, scope, nonce,
                               login_hint, st.clock())
        # Auto-consent: a real provider would show a login + consent screen here.
        return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302)

    def oauth_error(error: str, desc: str, status: int = 400):
        return JSONResponse({"error": error, "error_description": desc}, status_code=status)

    def client_auth(p: str, client_id: str | None, client_secret: str | None, authorization: str | None):
        if authorization and authorization.lower().startswith("basic "):
            raw = base64.b64decode(authorization[6:]).decode()
            client_id, _, client_secret = raw.partition(":")
        reg = st.clients.get(f"{p}:{client_id}")
        if reg is None or not secrets.compare_digest(reg.client_secret, client_secret or ""):
            return None
        return reg

    def issue(p: str, client_id: str, scope: str, sub: str, nonce: str | None, with_id_token: bool) -> dict:
        at, rt = f"{p}-at-{secrets.token_urlsafe(16)}", f"{p}-rt-{secrets.token_urlsafe(16)}"
        st.access[at] = (p, st.clock() + st.access_ttl, sub)
        st.refresh[rt] = (p, client_id, scope, sub)
        body = {"access_token": at, "token_type": "bearer", "expires_in": int(st.access_ttl),
                "refresh_token": rt, "scope": scope}
        if with_id_token and "openid" in scope.split():
            now = int(st.clock())
            claims = {"iss": issuer(p), "sub": sub, "aud": client_id, "iat": now, "exp": now + 600,
                      "email": f"{sub}@example.com"}
            if nonce:
                claims["nonce"] = nonce
            body["id_token"] = jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})
        return body

    @app.post("/{p}/oauth/token")
    def token(p: str, grant_type: str = Form(...), code: str | None = Form(None),
              redirect_uri: str | None = Form(None), code_verifier: str | None = Form(None),
              refresh_token: str | None = Form(None), client_id: str | None = Form(None),
              client_secret: str | None = Form(None), authorization: str | None = Header(None)):
        check_provider(p)
        st.token_requests += 1
        reg = client_auth(p, client_id, client_secret, authorization)
        if reg is None:
            return oauth_error("invalid_client", "bad client credentials", 401)
        if grant_type == "authorization_code":
            g = st.codes.pop(code or "", None)  # single use
            if g is None or g.provider != p or g.client_id != reg.client_id:
                return oauth_error("invalid_grant", "unknown or used code")
            if st.clock() - g.created > 60:
                return oauth_error("invalid_grant", "code expired")
            if redirect_uri != g.redirect_uri:
                return oauth_error("invalid_grant", "redirect_uri mismatch")
            digest = base64.urlsafe_b64encode(hashlib.sha256((code_verifier or "").encode()).digest()).rstrip(b"=")
            if not secrets.compare_digest(digest.decode(), g.challenge):
                return oauth_error("invalid_grant", "PKCE verification failed")
            return issue(p, reg.client_id, g.scope, g.subject, g.nonce, with_id_token=True)
        if grant_type == "refresh_token":
            if refresh_token in st.used_refresh:
                # Reuse of a rotated refresh token: revoke the whole family (RFC 9700 §4.14).
                for t, (pp, cid, _, _) in list(st.refresh.items()):
                    if pp == p and cid == reg.client_id:
                        del st.refresh[t]
                return oauth_error("invalid_grant", "refresh token reuse detected")
            entry = st.refresh.pop(refresh_token or "", None)
            if entry is None or entry[0] != p or entry[1] != reg.client_id:
                return oauth_error("invalid_grant", "unknown refresh token")
            st.used_refresh.add(refresh_token)
            return issue(p, reg.client_id, entry[2], entry[3], None, with_id_token=False)
        return oauth_error("unsupported_grant_type", grant_type)

    # ---- API slices ----------------------------------------------------------
    def bearer(p: str, authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        entry = st.access.get(authorization[7:])
        if entry is None or entry[0] != p:
            raise HTTPException(401, "invalid token")
        if entry[1] <= st.clock():
            raise HTTPException(401, "token expired")
        return entry[2]

    @app.get("/github/api/repos/{owner}/{repo}/issues")
    def gh_list(owner: str, repo: str, state: str = "open", authorization: str | None = Header(None)):
        bearer("github", authorization)
        return [i for i in st.issues.get(f"{owner}/{repo}", []) if state == "all" or i["state"] == state]

    @app.post("/github/api/repos/{owner}/{repo}/issues", status_code=201)
    async def gh_create(owner: str, repo: str, request: Request, authorization: str | None = Header(None)):
        sub = bearer("github", authorization)
        body = await request.json()
        issues = st.issues.setdefault(f"{owner}/{repo}", [])
        n = len(issues) + 1
        issue = {"number": n, "title": body["title"], "body": body.get("body", ""), "state": "open",
                 "user": {"login": sub}, "html_url": f"https://github.example/{owner}/{repo}/issues/{n}"}
        issues.append(issue)
        return issue

    @app.get("/slack/api/conversations.list")
    def slack_channels(authorization: str | None = Header(None)):
        bearer("slack", authorization)
        return {"ok": True, "channels": [{"id": "C01", "name": "eng"}, {"id": "C02", "name": "alerts"},
                                         {"id": "C03", "name": "random"}]}

    @app.post("/slack/api/chat.postMessage")
    async def slack_post(request: Request, authorization: str | None = Header(None)):
        bearer("slack", authorization)
        body = await request.json()
        if body.get("channel", "").lstrip("#") not in ("eng", "alerts", "random", "C01", "C02", "C03"):
            return {"ok": False, "error": "channel_not_found"}  # Slack returns 200 + ok:false
        msg = {"channel": body["channel"], "text": body.get("text", ""), "ts": f"{len(st.slack_messages) + 1}.000"}
        st.slack_messages.append(msg)
        return {"ok": True, **msg}

    @app.post("/hubspot/api/crm/v3/objects/contacts", status_code=201)
    async def hs_create(request: Request, authorization: str | None = Header(None)):
        bearer("hubspot", authorization)
        props = (await request.json()).get("properties", {})
        if any(c["properties"].get("email") == props.get("email") for c in st.contacts):
            raise HTTPException(409, "Contact already exists")
        c = {"id": str(1000 + len(st.contacts)), "properties": props}
        st.contacts.append(c)
        return c

    @app.post("/hubspot/api/crm/v3/objects/contacts/search")
    async def hs_search(request: Request, authorization: str | None = Header(None)):
        bearer("hubspot", authorization)
        q = (await request.json()).get("query", "").lower()
        hits = [c for c in st.contacts if any(q in str(v).lower() for v in c["properties"].values())]
        return {"total": len(hits), "results": hits}

    return app


app = create_fake_saas("http://127.0.0.1:9000")
for _p in PROVIDERS:
    app.state.register(_p, f"{_p}-client", f"{_p}-secret", [f"http://127.0.0.1:8000/oauth/{_p}/callback"])
