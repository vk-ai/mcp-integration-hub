"""mcp-hub CLI.

    mcp-hub sandbox [--port 9000]        run the fake GitHub/Slack/HubSpot (OAuth + API)
    mcp-hub serve   [--port 8000]        HTTP: A2A card, OAuth connect, webhooks
    mcp-hub mcp     [--http --port 8001] MCP server (stdio by default)
    mcp-hub scheduler [--every 60]       run due scheduled workflows in a loop
"""
from __future__ import annotations

import argparse
import asyncio
import os


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mcp-hub")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sb = sub.add_parser("sandbox")
    sb.add_argument("--port", type=int, default=9000)
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    m = sub.add_parser("mcp")
    m.add_argument("--http", action="store_true")
    m.add_argument("--port", type=int, default=8001)
    sc = sub.add_parser("scheduler")
    sc.add_argument("--every", type=float, default=60.0)
    a = ap.parse_args(argv)

    if a.cmd == "sandbox":
        import uvicorn
        uvicorn.run("mcp_hub.sandbox.fake_saas:app", host="127.0.0.1", port=a.port)
        return

    from .hub import Hub, settings_from_env
    hub = Hub.build(settings_from_env(), audit_path=os.getenv("MCP_HUB_AUDIT_PATH", "audit.jsonl"))

    if a.cmd == "serve":
        import uvicorn
        from .http_app import create_app
        uvicorn.run(create_app(hub), host=a.host, port=a.port)
    elif a.cmd == "mcp":
        from .mcp_server import build_mcp_server
        srv = build_mcp_server(hub)
        if a.http:
            srv.run("streamable-http", port=a.port)
        else:
            srv.run("stdio")
    elif a.cmd == "scheduler":
        async def loop():
            while True:
                for r in await hub.workflows.tick():
                    print(f"{r.workflow}: {r.status} {r.error or ''}", flush=True)
                await asyncio.sleep(a.every)
        asyncio.run(loop())


if __name__ == "__main__":  # pragma: no cover
    main()
