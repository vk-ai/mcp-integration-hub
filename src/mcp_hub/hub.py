"""Wires everything together: settings -> OAuth clients, credential store,
token manager, policy, audit log, gateway and workflow engine."""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .audit import AuditLog
from .connectors import SaaSConnectors
from .credentials import CredentialStore, store_from_env
from .gateway import ToolGateway
from .oauth import OAuthClient, PendingAuthStore, ProviderConfig
from .pkce import new_state, new_verifier
from .pinning import ToolPinStore, tool_to_dict
from .policy import PolicyEngine, Principal, load_default_policy
from .tokens import TokenManager
from .workflows import WorkflowEngine, default_workflows

PROVIDER_SCOPES = {
    "github": ("repo",),
    "slack": ("chat:write", "channels:read"),
    "hubspot": ("crm.objects.contacts.read", "crm.objects.contacts.write"),
}

LIVE_ENDPOINTS = {
    "github": ("https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token",
               "https://api.github.com"),
    "slack": ("https://slack.com/oauth/v2/authorize", "https://slack.com/api/oauth.v2.access",
              "https://slack.com/api"),
    "hubspot": ("https://app.hubspot.com/oauth/authorize", "https://api.hubapi.com/oauth/v1/token",
                "https://api.hubapi.com"),
}


@dataclass
class Settings:
    providers: dict[str, ProviderConfig]
    public_base_url: str
    webhook_secrets: dict[str, str]
    api_keys: dict[str, Principal] = field(default_factory=dict)
    mcp_principal: Principal = Principal("mcp-client", "acme", frozenset({"operator"}))
    tool_pins_path: str | None = None  # set => tool-definition pinning is enforced (MCP_HUB_TOOL_PINS)


def _principal(d: dict) -> Principal:
    return Principal(d["id"], d["tenant"], frozenset(d["roles"]))


DEV_API_KEYS = {
    "dev-operator-key": Principal("alice", "acme", frozenset({"operator"})),
    "dev-viewer-key": Principal("victor", "acme", frozenset({"viewer"})),
    "dev-admin-key": Principal("root", "acme", frozenset({"admin"})),
}


def sandbox_settings(sandbox_base: str, hub_base: str) -> Settings:
    """All three providers point at the local fake (OIDC-enabled)."""
    sb, hb = sandbox_base.rstrip("/"), hub_base.rstrip("/")
    providers = {
        p: ProviderConfig(
            name=p, client_id=f"{p}-client", client_secret=f"{p}-secret",
            redirect_uri=f"{hb}/oauth/{p}/callback", scopes=("openid",) + scopes,
            authorize_url=f"{sb}/{p}/oauth/authorize", token_url=f"{sb}/{p}/oauth/token",
            api_base=f"{sb}/{p}/api", issuer=f"{sb}/{p}", jwks_url=f"{sb}/{p}/jwks",
        )
        for p, scopes in PROVIDER_SCOPES.items()
    }
    return Settings(providers, hb, {p: f"dev-{p}-webhook-secret" for p in PROVIDER_SCOPES}, dict(DEV_API_KEYS))


def settings_from_env() -> Settings:
    """MCP_HUB_MODE=sandbox (default) or live. Live mode enables each provider
    whose <P>_CLIENT_ID / <P>_CLIENT_SECRET are set."""
    hub_base = os.getenv("MCP_HUB_PUBLIC_URL", "http://127.0.0.1:8000")
    if os.getenv("MCP_HUB_MODE", "sandbox") == "sandbox":
        s = sandbox_settings(os.getenv("MCP_HUB_SANDBOX_URL", "http://127.0.0.1:9000"), hub_base)
    else:
        providers = {}
        for p, (auth, token, api) in LIVE_ENDPOINTS.items():
            cid, sec = os.getenv(f"{p.upper()}_CLIENT_ID"), os.getenv(f"{p.upper()}_CLIENT_SECRET")
            if cid and sec:
                providers[p] = ProviderConfig(p, cid, sec, f"{hub_base}/oauth/{p}/callback", PROVIDER_SCOPES[p],
                                              auth, token, api)
        secrets_ = {p: os.getenv(f"{p.upper()}_WEBHOOK_SECRET", "") for p in LIVE_ENDPOINTS}
        s = Settings(providers, hub_base, secrets_, {})
    if os.getenv("MCP_HUB_API_KEYS"):
        s.api_keys = {k: _principal(v) for k, v in json.loads(os.environ["MCP_HUB_API_KEYS"]).items()}
    if os.getenv("MCP_HUB_TOOL_PINS"):
        s.tool_pins_path = os.environ["MCP_HUB_TOOL_PINS"]
    if os.getenv("MCP_HUB_PRINCIPAL"):
        s.mcp_principal = _principal(json.loads(os.environ["MCP_HUB_PRINCIPAL"]))
    return s


class Hub:
    def __init__(self, settings: Settings, http: httpx.AsyncClient, credentials: CredentialStore,
                 audit: AuditLog, clock=time.time):
        self.settings, self.http, self.clock = settings, http, clock
        self.credentials = credentials
        self.audit = audit
        self.oauth = {p: OAuthClient(cfg, http, clock=clock) for p, cfg in settings.providers.items()}
        self.pending = PendingAuthStore(ttl_s=600, clock=clock)
        self.tokens = TokenManager(credentials, self.oauth, clock=clock)
        self.policy = PolicyEngine(load_default_policy(), clock=clock)
        self.connectors = SaaSConnectors(http, self.tokens, {p: c.api_base for p, c in settings.providers.items()})
        self.tool_pins = ToolPinStore(settings.tool_pins_path, clock=clock) if settings.tool_pins_path else None
        self.gateway = ToolGateway(self.policy, self.connectors, audit, clock=clock, pins=self.tool_pins,
                                   definitions=self.tool_definitions)
        self._mcp_server = None
        self.workflows = WorkflowEngine(self.gateway, clock=clock)
        for wf in default_workflows():
            self.workflows.register(wf)

    @classmethod
    def build(cls, settings: Settings, http: httpx.AsyncClient | None = None, clock=time.time,
              audit_path: str | Path | None = None, credentials: CredentialStore | None = None) -> "Hub":
        return cls(settings, http or httpx.AsyncClient(timeout=15), credentials or store_from_env(),
                   AuditLog(audit_path), clock)

    # ---- tool definitions + pinning ------------------------------------------
    def enable_tool_pinning(self, path: str | Path | None = None) -> ToolPinStore:
        self.tool_pins = self.gateway.pins = ToolPinStore(path, clock=self.clock)
        return self.tool_pins

    def attach_mcp_server(self, srv) -> None:
        """The definitions checked against pins are the ones this server is serving right now."""
        self._mcp_server = srv

    async def tool_definitions(self) -> dict[str, dict]:
        if self._mcp_server is None:
            from .mcp_server import build_mcp_server  # local import: mcp_server imports hub
            build_mcp_server(self)
        return {d["name"]: d for d in (tool_to_dict(t) for t in await self._mcp_server.list_tools())}

    async def approve_tools(self, approved_by: str, names: list[str] | None = None) -> dict[str, str]:
        if self.tool_pins is None:
            raise RuntimeError("tool pinning is not enabled")
        defs = await self.tool_definitions()
        missing = set(names or []) - set(defs)
        if missing:
            raise KeyError(f"unknown tools: {sorted(missing)}")
        out = {}
        for n in names or sorted(defs):
            out[n] = self.tool_pins.approve(defs[n], approved_by)["fingerprint"]
            self.audit.append({"action": "tool_pin_approved", "actor": approved_by, "tool": n, "fingerprint": out[n]})
        return out

    async def verify_tools(self) -> dict[str, dict]:
        """name -> {ok, reason, pinned, current, changed} for every served or pinned tool."""
        defs = await self.tool_definitions()
        pins = self.tool_pins or ToolPinStore()
        return {n: pins.check(n, defs.get(n)).__dict__ for n in sorted(set(defs) | set(pins.names()))}

    # ---- OAuth connect flow ------------------------------------------------
    def begin_connect(self, principal: Principal, provider: str) -> str:
        if provider not in self.oauth:
            raise KeyError(f"provider {provider!r} not configured")
        state, verifier = new_state(), new_verifier()
        nonce = secrets.token_urlsafe(16) if self.settings.providers[provider].jwks_url else None
        self.pending.put(state, {"provider": provider, "verifier": verifier, "nonce": nonce,
                                 "tenant": principal.tenant, "actor": principal.id})
        return self.oauth[provider].authorization_url(state, verifier, nonce)

    async def complete_connect(self, provider: str, code: str, state: str) -> dict:
        pending = self.pending.pop(state)
        if pending is None or pending["provider"] != provider:
            self.audit.append({"action": "connect", "provider": provider, "outcome": "bad_state"})
            raise PermissionError("unknown, expired or mismatched OAuth state")
        ts = await self.oauth[provider].exchange_code(code, pending["verifier"], pending["nonce"])
        subject = (ts.id_claims or {}).get("sub", "")
        self.tokens.save(pending["tenant"], provider, ts, subject)
        self.audit.append({"action": "connect", "actor": pending["actor"], "tenant": pending["tenant"],
                           "provider": provider, "subject": subject, "outcome": "ok"})
        return {"tenant": pending["tenant"], "provider": provider, "subject": subject, "scope": ts.scope}

    def connections(self, tenant: str) -> list[dict]:
        out = []
        for p in self.credentials.list(tenant):
            d = self.credentials.get(tenant, p) or {}
            out.append({"provider": p, "subject": d.get("subject", ""), "scope": d.get("scope", ""),
                        "expires_at": d.get("expires_at")})
        return out

    def disconnect(self, principal: Principal, provider: str) -> None:
        self.credentials.delete(principal.tenant, provider)
        self.audit.append({"action": "disconnect", "actor": principal.id, "tenant": principal.tenant,
                           "provider": provider, "outcome": "ok"})
