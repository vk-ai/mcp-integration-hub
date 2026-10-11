# mcp-integration-hub

Secure SaaS connectors for AI agents. It's an **MCP server** (official `mcp`
Python SDK) and an **A2A agent** that let agents act on GitHub, Slack and
HubSpot through OAuth2/OIDC connections. Signed webhooks drive event-based
and scheduled workflows. Tokens are kept in **HashiCorp Vault**, and every call
goes through **RBAC and per-tool policy** and lands in a **hash-chained audit log**.

> **Learning project.** I built this, test-first, to learn integration-platform
> security patterns. It has only ever talked to a **local fake** of the three
> SaaS providers, never to real GitHub, Slack or HubSpot accounts, and it is not
> used in production. See [What is real vs stubbed](#what-is-real-vs-stubbed).

## Architecture

```
 MCP client (Cursor, Claude, ...) ──stdio/HTTP──► MCP server ─┐
 Another agent ──A2A JSON-RPC (X-API-Key)──► /a2a ────────────┤
 GitHub/Slack/HubSpot ──signed webhook──► /webhooks/{p} ──► WorkflowEngine (event + interval triggers)
                                                              │
                                                              ▼
                                   ToolGateway: PolicyEngine (RBAC, arg allowlists, rate limits)
                                                → TokenManager (refresh on expiry, single-flight)
                                                → SaaS API call
                                                → AuditLog (append-only, SHA-256 hash chain)
                                                              │
 User's browser ──/connect/{p}──► OAuth2 auth code + PKCE S256 (+ OIDC id_token check) ──► tokens → Vault KV v2
```

| Area | What's implemented |
|---|---|
| MCP | `MCPServer` (mcp SDK v2) with 7 tools: `github_list_issues`, `github_create_issue`, `slack_list_channels`, `slack_post_message`, `hubspot_search_contacts`, `hubspot_create_contact`, `list_connections`. Runs over stdio or streamable HTTP. Policy denials and "reconnect" cases come back as MCP tool errors with a clear message. |
| A2A | Agent card at `/.well-known/agent-card.json` (protocol 0.3.0, with `/agent.json` kept as an alias) that lists one skill per tool and an API-key security scheme. `POST /a2a` handles JSON-RPC `message/send` with a data part `{skill, arguments}`, plus `tasks/get`. |
| OAuth2 / OIDC | Authorization code with **PKCE S256**, single-use `state` with a 10-minute TTL and bound to provider and tenant, and an OIDC `id_token` check (RS256 via JWKS, `iss`, `aud`, `exp`, `iat`, `nonce`). Refresh-token rotation is handled. Errors are handled whether they arrive as HTTP errors or in a 200 response (GitHub's style). |
| Token refresh | Tokens are refreshed when they're about to expire. Concurrent callers share one refresh (a per-key lock), so a rotated refresh token is never replayed. A dead refresh token clears the connection and raises `ReauthRequired`. |
| Webhooks | GitHub `X-Hub-Signature-256` (SHA-256 only), Slack `v0` signatures with a 5-minute replay window and the `url_verification` handshake, and HubSpot v3 signatures (method + URI + body + timestamp in ms). Delivery IDs are deduplicated. |
| Workflows | `event:<type>` and `interval:<seconds>` triggers, templated step arguments (`{event.payload.issue.title}`, `{steps.0.result.length}`), and a service principal that goes through the same policy and audit path. Three are built in: GitHub issue → Slack, HubSpot contact → GitHub follow-up issue, and a daily digest of open issues → Slack. |
| Credentials | `VaultCredentialStore` (hvac, KV v2, one versioned secret per tenant/provider) when `VAULT_ADDR` is set, otherwise `InMemoryCredentialStore` for tests and dev. Tenant and provider names are validated so they can't be used for path traversal. |
| RBAC / policy | `config/policy.json` defines `viewer` → `operator` → `admin` with inheritance, default deny for unknown tools, per-tool argument allowlists and regexes (for example, Slack channels and the GitHub org), and per-principal, per-tool rate limits. Denied calls don't use up any rate limit. |
| Tool pinning | **MCP rug-pull protection** (`pinning.py`). An admin approves tools with `mcp-hub tools approve --by <id>`, which stores a SHA-256 fingerprint of each tool's canonical definition (`name`, `description`, `inputSchema`, `annotations`). With `MCP_HUB_TOOL_PINS` set, every call (MCP, A2A, workflows) re-fingerprints the definition the MCP server is serving *now*; an unpinned or changed tool is denied before policy runs, and the drift is written to the audit chain with the old and new fingerprints and the changed fields. Re-approval is explicit. `mcp-hub tools verify` exits 1 on drift, so it can run in CI. Standard library only. |
| Audit | JSONL with `seq`, `prev_hash` and `hash`. `verify()` pinpoints the first edited, deleted or reordered entry. Tokens, secrets, codes and `Authorization` headers are redacted before anything is written. |

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                      # 87 passed, 2 skipped (Vault) - no network needed
python demo/run_demo.py        # end-to-end demo, output below
```

Run it for real over HTTP, with three processes:

```bash
mcp-hub sandbox --port 9000                    # fake GitHub/Slack/HubSpot: OAuth + OIDC + API
vault server -dev -dev-root-token-id=dev-root  # or: docker compose up vault
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root mcp-hub serve --port 8000

curl -i -H 'X-API-Key: dev-operator-key' localhost:8000/connect/github   # 302 to the sandbox; open it in a browser
curl -H 'X-API-Key: dev-operator-key' localhost:8000/connections
curl localhost:8000/.well-known/agent-card.json
```

Use it from an MCP client (stdio):

```json
{ "mcpServers": { "integration-hub": {
    "command": "mcp-hub", "args": ["mcp"],
    "env": { "VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_TOKEN": "dev-root",
             "MCP_HUB_PRINCIPAL": "{\"id\":\"me\",\"tenant\":\"acme\",\"roles\":[\"operator\"]}" } } } }
```

`docker compose up --build` starts Vault (dev mode), the sandbox and the hub.

### Configuration

| Env var | Default | |
|---|---|---|
| `MCP_HUB_MODE` | `sandbox` | `live` uses the real provider endpoints for any provider with `<P>_CLIENT_ID` and `<P>_CLIENT_SECRET` set |
| `MCP_HUB_SANDBOX_URL` / `MCP_HUB_PUBLIC_URL` | `http://127.0.0.1:9000` / `:8000` | Sandbox location, and the hub's public URL (used for OAuth redirects and the HubSpot signature URI) |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT`, `VAULT_PREFIX` | unset, `secret`, `mcp-hub` | Turns on the Vault KV v2 credential store |
| `<P>_WEBHOOK_SECRET` | `dev-<p>-webhook-secret` in sandbox | Webhook signing secrets in live mode |
| `MCP_HUB_API_KEYS` | three dev keys | JSON `{key: {id, tenant, roles}}` for the HTTP and A2A API |
| `MCP_HUB_PRINCIPAL` | `mcp-client` / `acme` / `operator` | Who the MCP server acts as |
| `MCP_HUB_AUDIT_PATH` | `audit.jsonl` | Audit log file |
| `MCP_HUB_TOOL_PINS` | unset (pinning off) | Pin file for tool-definition pinning. When set, unpinned or changed tools are denied |

## Demo run

`python demo/run_demo.py`, here with `VAULT_ADDR` pointing at a local dev
Vault. A fake clock simulates token expiry and the daily schedule.

```text
credential store: VaultCredentialStore (http://127.0.0.1:8200)

== 1. A2A agent card: mcp-integration-hub protocol 0.3.0, 6 skills, endpoint http://hub.local/a2a

== 2. OAuth2 auth-code + PKCE (+ OIDC id_token) for each provider
   github   challenge=NtDszOKpe0Es... method=S256 -> connected, id_token sub=sandbox-user, scope='openid repo'
   slack    challenge=_I848ye4nRbM... method=S256 -> connected, id_token sub=sandbox-user, scope='openid chat:write channels:read'
   hubspot  challenge=iCkEgNxKB0J6... method=S256 -> connected, id_token sub=sandbox-user, scope='openid crm.objects.contacts.read crm.objects.contacts.write'
   stored for tenant acme: ['github', 'hubspot', 'slack'] (tokens never returned)

== 3. MCP client calls tools (in-process transport, principal=mcp-client/operator)
   tools: ['github_list_issues', 'github_create_issue', 'slack_list_channels', 'slack_post_message', 'hubspot_search_contacts', 'hubspot_create_contact', 'list_connections']
   github_create_issue -> #1
   slack_post_message #alerts -> ok=True
   slack_post_message #random -> is_error=True: Error executing tool slack_post_message: denied by policy: arg_not_allowed:channel

== 4. access token expires (clock +1h): next call refreshes and rotates the refresh token
   hubspot_create_contact -> id=1000; token endpoint calls during this step: 1

== 5. signed webhooks -> event-driven workflows
   github issues.opened -> 202 [{'workflow': 'github-issue-to-slack', 'status': 'succeeded', 'error': None}]
   slack now has: #eng 'New issue: Login loop on Safari https://gh/42'
   same delivery again -> 200 {'duplicate': True}
   forged signature -> 401
   hubspot contact.creation -> 202; github issue: 'Follow up with HubSpot contact 1001'

== 6. scheduled workflow (clock +1 day)
   daily-open-issues-digest: succeeded -> slack 'Daily digest: 1 open issues in acme/app'

== 7. A2A message/send (another agent invokes a skill)
   task completed: 1 contact(s) found
   as viewer: task rejected: denied by policy: role_not_permitted

== 8. audit log (hash-chained JSONL)
   16 entries {'connect:ok': 3, 'tool_call:allow': 8, 'tool_call:deny': 2, 'webhook:accepted': 2, 'webhook:bad_signature': 1}; chain intact: True
   after editing entry 4 in a copy: verify -> (False, 4)
```

## Built test-first

For each core module (OAuth/PKCE, tokens, credentials, policy, audit,
webhooks, gateway, workflows, MCP server, HTTP/A2A), I wrote the tests before
the code. The git history keeps that order, with each `test:` commit before
its `feat:` commit. The fake sandbox (test infrastructure) and the CLI were
written first and tested afterwards. There are 96 tests (the 7 pinning tests were added later, in a feature PR), and coverage is about 89% (the CLI is
covered by a subprocess test, which isn't counted):

| File | Covers |
|---|---|
| `test_pkce.py`, `test_oauth.py` | Verifier format, S256, full code exchange against the fake, wrong verifier, code reuse, nonce and audience checks, refresh rotation and reuse detection, providers that don't rotate refresh tokens, GitHub-style 200 errors, bad client secret, single-use state with a TTL |
| `test_tokens.py` | Connect stores only what's needed, forged, replayed or cross-provider state, refresh on expiry, **5 concurrent callers → 1 refresh**, a dead refresh token → reauth |
| `test_policy.py` | Inheritance, default deny, argument allowlists and regexes (they apply to admins too), rate limit windows per principal, denied calls not counting toward the limit, rejection of bad inheritance |
| `test_audit.py` | Chain verifies, and edits and deletions are detected, the chain continues after a reopen, redaction |
| `test_webhooks.py` | GitHub, Slack and HubSpot v3 signatures, replay windows, parsing, dedupe TTL |
| `test_gateway.py`, `test_workflows.py` | Policy → token → API → audit, tenant isolation, provider errors, event and interval workflows, step chaining, workflows subject to policy, a failed step stops the run |
| `test_mcp_server.py`, `test_stdio.py` | An in-process MCP client, plus a real **stdio subprocess**: tool schemas, calls, policy errors, the reconnect message, no secrets in output |
| `test_http_app.py` | Agent card, the OAuth connect flow over HTTP, webhook endpoints (including a duplicate and a forged one), A2A send, get and errors, admin-only audit verify |
| `test_bdd_workflows.py` | **pytest-bdd** scenarios in `tests/features/webhook_workflows.feature` |
| `test_pinning.py` | Canonical fingerprints (key order ignored; description, schema, annotation and name changes all detected), pin file persistence, off-by-default, unpinned → deny, a **rug pull through a real MCP client** (tool swapped after approval with a poisoned description → blocked, drift audited, chain still verifies), re-approval, the non-MCP call path, and the `tools approve/verify` CLI |
| `test_credentials.py` | In-memory store, plus a **real Vault** KV v2 store with versioning (`-m vault`) |

CI (`.github/workflows/ci.yml`) runs everything on Python 3.11 and 3.12 with no
network, plus a second job with a `hashicorp/vault` dev service container that
runs the Vault tests and the demo with Vault-backed tokens.

## What is real vs stubbed

**Real (it runs, and is tested here):**
- The official `mcp` SDK server over in-process and stdio transports.
- PKCE, `state`, OIDC `id_token` verification (PyJWT + JWKS), refresh rotation, and the webhook HMAC checks. These follow the published GitHub, Slack, HubSpot and RFC 7636 schemes.
- The Vault KV v2 store, tested against a real `vault server -dev` (1.17) locally and in CI.
- The policy engine, the hash-chained audit log, and the workflow engine.
- An HTTP run over real sockets: sandbox, hub and Vault as separate processes, with the OAuth connect going through `curl`.

**Stubbed or not verified:**
- **The SaaS providers are fakes.** `mcp_hub/sandbox/fake_saas.py` implements OAuth and OIDC plus a tiny slice of each API. Live mode builds requests against the real endpoints, but **no real GitHub, Slack or HubSpot app has been connected**. Real quirks aren't handled: Slack's bot vs user tokens in `oauth.v2.access` and its separate OIDC endpoints, GitHub App vs OAuth App refresh behaviour, and HubSpot's portal scoping.
- **OIDC is only exercised against the fake.** It issues `id_token`s for all three providers, but among the real ones only Slack offers OIDC, and through different endpoints.
- **API keys authenticate the hub's own users.** There's no SSO or OIDC login to the hub itself.
- **Workflows run inline in the webhook request.** There's no queue, retry or dead-letter handling, and webhook dedupe state and A2A tasks live only in memory.
- **The scheduler is a simple interval loop** (`mcp-hub scheduler`), not cron, and it doesn't coordinate across replicas.
- **The audit log is tamper-evident, not tamper-proof.** Anyone who can rewrite the file can rebuild the chain; anchoring the hashes externally isn't implemented.
- **Vault runs in dev mode with a root token.** There's no AppRole, Kubernetes auth or token renewal.
- **A2A support is minimal.** It covers `message/send` with structured data parts and `tasks/get`, but not streaming, push notifications, cancellation or free-text messages (there's no LLM here to interpret text).
- **Tool pinning protects against definition changes, not against a tool that was malicious when approved.** The approval is a human looking at the definition; there is no poisoning scanner. The hub's own tools are defined in this repo, so in practice drift here means a code or dependency change; the rug-pull test simulates a swapped definition in-process. Pinning is off unless `MCP_HUB_TOOL_PINS` is set, and the pin file is a plain JSON file (anyone who can write it can re-pin).
- **The Docker Compose file is untested.** The build machine has no Docker, so the same stack was run as plain processes instead.

## Layout

```
src/mcp_hub/   pkce · oauth · tokens · credentials (Vault) · policy · audit · webhooks · workflows
               connectors · gateway · hub (wiring) · mcp_server · a2a · http_app · cli
               config/policy.json · sandbox/fake_saas.py
tests/         96 tests + features/webhook_workflows.feature
demo/          run_demo.py
```

## License

MIT
