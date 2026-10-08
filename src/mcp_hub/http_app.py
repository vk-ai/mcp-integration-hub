"""HTTP surface: A2A card + endpoint, OAuth connect/callback, signed webhooks,
connection listing and audit verification."""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .a2a import A2AHandler, agent_card
from .hub import Hub
from .oauth import OAuthError
from .policy import Principal
from .webhooks import (Deduper, SignatureError, parse_github, parse_hubspot, parse_slack, verify_github,
                       verify_hubspot_v3, verify_slack)


def create_app(hub: Hub) -> FastAPI:
    app = FastAPI(title="mcp-integration-hub", version="0.1.0")
    a2a = A2AHandler(hub)
    dedupe = Deduper(ttl_s=24 * 3600, clock=hub.clock)
    app.state.hub = hub

    def principal(x_api_key: str | None = Header(default=None)) -> Principal:
        p = hub.settings.api_keys.get(x_api_key or "")
        if p is None:
            raise HTTPException(401, "missing or invalid X-API-Key")
        return p

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/.well-known/agent-card.json")
    @app.get("/.well-known/agent.json")  # pre-0.3 path, kept for older clients
    def card():
        return agent_card(hub)

    @app.post("/a2a")
    async def a2a_rpc(request: Request, p: Principal = Depends(principal)):
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse(A2AHandler._err(None, -32700, "parse error"))
        return JSONResponse(await a2a.handle(p, body))

    @app.get("/connect/{provider}")
    def connect(provider: str, p: Principal = Depends(principal)):
        try:
            return RedirectResponse(hub.begin_connect(p, provider), status_code=302)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e

    @app.get("/oauth/{provider}/callback")
    async def callback(provider: str, state: str = "", code: str | None = None, error: str | None = None):
        if error:
            raise HTTPException(400, f"provider returned error: {error}")
        try:
            return await hub.complete_connect(provider, code or "", state)
        except PermissionError as e:
            raise HTTPException(400, str(e)) from e
        except OAuthError as e:
            raise HTTPException(400, f"token exchange failed: {e.error}") from e

    @app.get("/connections")
    def connections(p: Principal = Depends(principal)):
        return hub.connections(p.tenant)

    @app.get("/audit/verify")
    def audit_verify(p: Principal = Depends(principal)):
        if "admin" not in hub.policy.effective_roles(p.roles):
            raise HTTPException(403, "admin only")
        ok, bad = hub.audit.verify()
        return {"intact": ok, "first_bad_seq": bad, "entries": len(hub.audit.tail())}

    @app.post("/webhooks/{provider}")
    async def webhook(provider: str, request: Request):
        body = await request.body()
        secret = hub.settings.webhook_secrets.get(provider)
        if not secret:
            raise HTTPException(404, "no webhook secret configured for provider")
        h = request.headers
        try:
            if provider == "github":
                verify_github(secret, body, h.get("x-hub-signature-256"))
                events = parse_github(h.get("x-github-event", "unknown"), h.get("x-github-delivery", ""), body)
            elif provider == "slack":
                verify_slack(secret, body, h.get("x-slack-request-timestamp"), h.get("x-slack-signature"), hub.clock())
                events = parse_slack(body)
                if isinstance(events, dict):  # url_verification handshake
                    return events
            elif provider == "hubspot":
                uri = f"{hub.settings.public_base_url}{request.url.path}"
                if request.url.query:
                    uri += f"?{request.url.query}"
                verify_hubspot_v3(secret, request.method, uri, body, h.get("x-hubspot-request-timestamp"),
                                  h.get("x-hubspot-signature-v3"), hub.clock())
                events = parse_hubspot(body)
            else:
                raise HTTPException(404, "unknown provider")
        except SignatureError as e:
            hub.audit.append({"action": "webhook", "provider": provider, "outcome": "bad_signature",
                              "reason": str(e)})
            raise HTTPException(401, "invalid signature") from e
        fresh = [e for e in events if dedupe.first_time(e.id)]
        if not fresh:
            return JSONResponse({"duplicate": True}, status_code=200)
        runs = []
        for ev in fresh:
            hub.audit.append({"action": "webhook", "provider": provider, "event": ev.type, "event_id": ev.id,
                              "outcome": "accepted"})
            runs.extend(await hub.workflows.handle_event(ev))
        return JSONResponse({"runs": [{"workflow": r.workflow, "status": r.status, "error": r.error} for r in runs]},
                            status_code=202)

    return app
