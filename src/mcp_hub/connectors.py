"""SaaS API calls for GitHub, Slack and HubSpot.

The request shapes follow the real REST APIs (GitHub `/repos/{o}/{r}/issues`,
Slack `chat.postMessage` / `conversations.list`, HubSpot CRM v3 contacts), and
the fake sandbox implements the same slice. Only the sandbox is exercised in
tests and CI; the live APIs have not been called from this repo."""
from __future__ import annotations

import httpx

from .tokens import TokenManager


class ConnectorError(Exception):
    def __init__(self, provider: str, status: int, detail: str):
        super().__init__(f"{provider} API {status}: {detail}")
        self.provider, self.status, self.detail = provider, status, detail


class SaaSConnectors:

    def __init__(self, http: httpx.AsyncClient, tokens: TokenManager, bases: dict[str, str]):
        self.http, self.tokens, self.bases = http, tokens, bases

    async def _request(self, provider: str, tenant: str, method: str, path: str, json=None, params=None) -> dict | list:
        token = await self.tokens.access_token(tenant, provider)
        url = self.bases[provider].rstrip("/") + path
        headers = {"Authorization": f"Bearer {token}", "User-Agent": "mcp-integration-hub"}
        if provider == "github":
            headers["Accept"] = "application/vnd.github+json"
        resp = await self.http.request(method, url, headers=headers, json=json, params=params)
        if resp.status_code == 401:  # token revoked between refresh and call
            from .tokens import ReauthRequired
            raise ReauthRequired(tenant, provider, "api rejected token")
        if resp.status_code >= 400:
            raise ConnectorError(provider, resp.status_code, resp.text[:300])
        body = resp.json()
        if isinstance(body, dict) and body.get("ok") is False:  # Slack style
            raise ConnectorError(provider, 200, body.get("error", "ok:false"))
        return body

    async def github_list_issues(self, tenant: str, repo: str, state: str = "open"):
        owner, _, name = repo.partition("/")
        return await self._request("github", tenant, "GET", f"/repos/{owner}/{name}/issues", params={"state": state})

    async def github_create_issue(self, tenant: str, repo: str, title: str, body: str = ""):
        owner, _, name = repo.partition("/")
        return await self._request("github", tenant, "POST", f"/repos/{owner}/{name}/issues", {"title": title, "body": body})

    async def slack_list_channels(self, tenant: str):
        return (await self._request("slack", tenant, "GET", "/conversations.list"))["channels"]

    async def slack_post_message(self, tenant: str, channel: str, text: str):
        return await self._request("slack", tenant, "POST", "/chat.postMessage", {"channel": channel, "text": text})

    async def hubspot_search_contacts(self, tenant: str, query: str):
        return await self._request("hubspot", tenant, "POST", "/crm/v3/objects/contacts/search", {"query": query})

    async def hubspot_create_contact(self, tenant: str, email: str, firstname: str = "", lastname: str = ""):
        props = {"email": email, "firstname": firstname, "lastname": lastname}
        return await self._request("hubspot", tenant, "POST", "/crm/v3/objects/contacts", {"properties": props})
