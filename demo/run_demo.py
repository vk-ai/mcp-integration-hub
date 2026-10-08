"""End-to-end demo against the local fake SaaS sandbox (offline).

    python demo/run_demo.py                     # in-memory credentials
    VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root python demo/run_demo.py   # tokens in Vault KV v2

Time is simulated with a fake clock so token expiry and the daily schedule can
be shown in a few seconds.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.client import Client

from mcp_hub.audit import AuditLog
from mcp_hub.credentials import store_from_env
from mcp_hub.http_app import create_app
from mcp_hub.hub import Hub, sandbox_settings
from mcp_hub.mcp_server import build_mcp_server
from mcp_hub.sandbox.fake_saas import PROVIDERS, create_fake_saas

HUB = "http://hub.local"


class Clock:
    t = 1_800_000_000.0

    def __call__(self):
        return self.t


def gh_sig(body: bytes, secret="dev-github-webhook-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def main() -> None:
    for name in ("httpx", "mcp"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    clock = Clock()
    fake = create_fake_saas("http://sandbox", clock=clock)
    for p in PROVIDERS:
        fake.state.register(p, f"{p}-client", f"{p}-secret", [f"{HUB}/oauth/{p}/callback"])
    sb = fake.state.sandbox
    audit_path = Path(tempfile.mkdtemp()) / "audit.jsonl"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fake), base_url="http://sandbox") as saas:
        store = store_from_env()
        hub = Hub.build(sandbox_settings("http://sandbox", HUB), http=saas, clock=clock, audit_path=audit_path,
                        credentials=store)
        api = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(hub)), base_url=HUB)
        op = {"X-API-Key": "dev-operator-key"}
        print(f"credential store: {type(store).__name__}" + (f" ({os.environ['VAULT_ADDR']})" if os.getenv("VAULT_ADDR") else ""))

        card = (await api.get("/.well-known/agent-card.json")).json()
        print(f"\n== 1. A2A agent card: {card['name']} protocol {card['protocolVersion']}, "
              f"{len(card['skills'])} skills, endpoint {card['url']}")

        print("\n== 2. OAuth2 auth-code + PKCE (+ OIDC id_token) for each provider")
        for p in PROVIDERS:
            r = await api.get(f"/connect/{p}", headers=op)
            q = parse_qs(urlparse(r.headers["location"]).query)
            back = await saas.get(r.headers["location"])  # browser at the provider (auto-consent)
            cb = urlparse(back.headers["location"])
            res = (await api.get(f"{cb.path}?{cb.query}")).json()
            print(f"   {p:8s} challenge={q['code_challenge'][0][:12]}... method={q['code_challenge_method'][0]} "
                  f"-> connected, id_token sub={res['subject']}, scope='{res['scope']}'")
        print(f"   stored for tenant acme: {[c['provider'] for c in hub.connections('acme')]} (tokens never returned)")

        print("\n== 3. MCP client calls tools (in-process transport, principal=mcp-client/operator)")
        async with Client(build_mcp_server(hub)) as mcp:
            tools = [t.name for t in (await mcp.list_tools()).tools]
            print(f"   tools: {tools}")
            r = await mcp.call_tool("github_create_issue", {"repo": "acme/app", "title": "Checkout times out"})
            print(f"   github_create_issue -> #{json.loads(r.content[0].text)['number']}")
            r = await mcp.call_tool("slack_post_message", {"channel": "#alerts", "text": "deploy started"})
            print(f"   slack_post_message #alerts -> ok={json.loads(r.content[0].text)['ok']}")
            r = await mcp.call_tool("slack_post_message", {"channel": "#random", "text": "hello"})
            print(f"   slack_post_message #random -> is_error={r.is_error}: {r.content[0].text}")

            print("\n== 4. access token expires (clock +1h): next call refreshes and rotates the refresh token")
            before = sb.token_requests
            clock.t += 3601
            r = await mcp.call_tool("hubspot_create_contact", {"email": "ana@example.com", "firstname": "Ana"})
            print(f"   hubspot_create_contact -> id={json.loads(r.content[0].text)['id']}; "
                  f"token endpoint calls during this step: {sb.token_requests - before}")

        print("\n== 5. signed webhooks -> event-driven workflows")
        body = json.dumps({"action": "opened", "issue": {"title": "Login loop on Safari", "html_url": "https://gh/42"}}).encode()
        hdr = {"X-Hub-Signature-256": gh_sig(body), "X-GitHub-Event": "issues", "X-GitHub-Delivery": "dlv-1"}
        r = await api.post("/webhooks/github", content=body, headers=hdr)
        print(f"   github issues.opened -> {r.status_code} {r.json()['runs']}")
        print(f"   slack now has: {sb.slack_messages[-1]['channel']} '{sb.slack_messages[-1]['text']}'")
        r = await api.post("/webhooks/github", content=body, headers=hdr)
        print(f"   same delivery again -> {r.status_code} {r.json()}")
        r = await api.post("/webhooks/github", content=body, headers={**hdr, "X-Hub-Signature-256": gh_sig(body, "guess")})
        print(f"   forged signature -> {r.status_code}")
        hs = json.dumps([{"eventId": 7, "subscriptionType": "contact.creation", "objectId": 1001}]).encode()
        ts = str(int(clock() * 1000))
        sig = base64.b64encode(hmac.new(b"dev-hubspot-webhook-secret",
                                        f"POST{HUB}/webhooks/hubspot{hs.decode()}{ts}".encode(), hashlib.sha256).digest()).decode()
        r = await api.post("/webhooks/hubspot", content=hs,
                           headers={"X-HubSpot-Signature-v3": sig, "X-HubSpot-Request-Timestamp": ts})
        print(f"   hubspot contact.creation -> {r.status_code}; github issue: "
              f"'{sb.issues['acme/crm-followups'][-1]['title']}'")

        print("\n== 6. scheduled workflow (clock +1 day)")
        clock.t += 86400
        for run in await hub.workflows.tick():
            print(f"   {run.workflow}: {run.status} -> slack '{sb.slack_messages[-1]['text']}'")

        print("\n== 7. A2A message/send (another agent invokes a skill)")
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
            "role": "user", "messageId": "m-1",
            "parts": [{"kind": "data", "data": {"skill": "hubspot_search_contacts", "arguments": {"query": "ana"}}}]}}}
        task = (await api.post("/a2a", json=rpc, headers=op)).json()["result"]
        print(f"   task {task['status']['state']}: {task['artifacts'][0]['parts'][0]['data']['total']} contact(s) found")
        rpc["params"]["message"]["parts"][0]["data"] = {"skill": "slack_post_message", "arguments": {"channel": "#eng", "text": "x"}}
        task = (await api.post("/a2a", json=rpc, headers={"X-API-Key": "dev-viewer-key"})).json()["result"]
        print(f"   as viewer: task {task['status']['state']}: {task['status']['message']['parts'][0]['text']}")

        print("\n== 8. audit log (hash-chained JSONL)")
        entries = hub.audit.tail()
        kinds = {}
        for e in entries:
            k = f"{e['action']}:{e.get('decision', e.get('outcome'))}"
            kinds[k] = kinds.get(k, 0) + 1
        print(f"   {len(entries)} entries {dict(sorted(kinds.items()))}; chain intact: {hub.audit.verify()[0]}")
        lines = audit_path.read_text().splitlines()
        e = json.loads(lines[3]); e["actor"] = "mallory"; lines[3] = json.dumps(e)
        tampered = audit_path.with_name("tampered.jsonl"); tampered.write_text("\n".join(lines) + "\n")
        print(f"   after editing entry 4 in a copy: verify -> {AuditLog(tampered).verify()}")
        await api.aclose()
        if os.getenv("VAULT_ADDR"):
            for p in PROVIDERS:
                store.delete("acme", p)  # leave the dev Vault clean


if __name__ == "__main__":
    asyncio.run(main())
