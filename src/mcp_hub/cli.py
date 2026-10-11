"""mcp-hub CLI.

    mcp-hub sandbox [--port 9000]        run the fake GitHub/Slack/HubSpot (OAuth + API)
    mcp-hub serve   [--port 8000]        HTTP: A2A card, OAuth connect, webhooks
    mcp-hub mcp     [--http --port 8001] MCP server (stdio by default)
    mcp-hub scheduler [--every 60]       run due scheduled workflows in a loop
    mcp-hub tools verify                 compare served tool definitions to MCP_HUB_TOOL_PINS (exit 1 on drift)
    mcp-hub tools approve --by NAME [TOOL ...]   pin the current definitions (all tools if none named)
    mcp-hub tools revoke TOOL ...
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
    t = sub.add_parser("tools", help="tool-definition pinning (rug-pull protection)")
    t.add_argument("action", choices=["verify", "approve", "revoke"])
    t.add_argument("names", nargs="*")
    t.add_argument("--by", help="approver id, recorded in the pin file and the audit log")
    t.add_argument("--pins", default=os.getenv("MCP_HUB_TOOL_PINS"), help="pin file (default $MCP_HUB_TOOL_PINS)")
    a = ap.parse_args(argv)

    if a.cmd == "sandbox":
        import uvicorn
        uvicorn.run("mcp_hub.sandbox.fake_saas:app", host="127.0.0.1", port=a.port)
        return

    from .hub import Hub, settings_from_env
    hub = Hub.build(settings_from_env(), audit_path=os.getenv("MCP_HUB_AUDIT_PATH", "audit.jsonl"))

    if a.cmd == "tools":
        raise SystemExit(_tools(hub, a))

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


def _tools(hub, a) -> int:
    import json

    if not a.pins:
        print("set --pins or MCP_HUB_TOOL_PINS", flush=True)
        return 2
    hub.enable_tool_pinning(a.pins)
    if a.action == "approve":
        if not a.by:
            print("--by is required for approve")
            return 2
        print(json.dumps(asyncio.run(hub.approve_tools(a.by, a.names or None)), indent=2))
        return 0
    if a.action == "revoke":
        for n in a.names:
            print(n, "revoked" if hub.tool_pins.revoke(n) else "was not pinned")
        return 0
    res = asyncio.run(hub.verify_tools())
    for n, r in res.items():
        extra = f" changed={','.join(r['changed'])}" if r["changed"] else ""
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {n}: {r['reason']}{extra}")
    return 0 if all(r["ok"] for r in res.values()) else 1


if __name__ == "__main__":  # pragma: no cover
    main()
