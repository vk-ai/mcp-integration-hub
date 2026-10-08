from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_hub.credentials import InMemoryCredentialStore
from mcp_hub.hub import Hub, sandbox_settings
from mcp_hub.policy import Principal
from mcp_hub.sandbox.fake_saas import PROVIDERS, create_fake_saas

HUB_BASE = "http://hub.test"


class FakeClock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def fake(clock):
    app = create_fake_saas("http://sandbox", access_ttl=3600, clock=clock)
    for p in PROVIDERS:
        app.state.register(p, f"{p}-client", f"{p}-secret", [f"{HUB_BASE}/oauth/{p}/callback"])
    return app


@pytest.fixture
def sandbox(fake):
    return fake.state.sandbox


@pytest.fixture
async def http(fake):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fake), base_url="http://sandbox") as c:
        yield c


@pytest.fixture
def hub(http, clock, tmp_path):
    return Hub.build(sandbox_settings("http://sandbox", HUB_BASE), http=http, clock=clock,
                     audit_path=tmp_path / "audit.jsonl", credentials=InMemoryCredentialStore())


@pytest.fixture
def alice():
    return Principal(id="alice", tenant="acme", roles=frozenset({"operator"}))


@pytest.fixture
def victor():
    return Principal(id="victor", tenant="acme", roles=frozenset({"viewer"}))


@pytest.fixture
def admin():
    return Principal(id="root", tenant="acme", roles=frozenset({"admin"}))


async def connect(hub, http, principal, provider):
    """Drive the full browser leg of auth-code + PKCE against the fake provider."""
    url = hub.begin_connect(principal, provider)
    resp = await http.get(url)
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    return await hub.complete_connect(provider, q["code"][0], q["state"][0])


@pytest.fixture
def connect_all(hub, http):
    async def _go(principal):
        for p in PROVIDERS:
            await connect(hub, http, principal, p)
    return _go
