"""MCP server for the panel (Streamable HTTP transport, plain JSON responses).

Lets Claude Desktop (or any MCP client) manage the panel through tools.

Auth (either one works):
  * header  Authorization: Bearer <MCP_TOKEN>
  * or the token inside the URL:  <BASE>/mcp/<MCP_TOKEN>   (for clients that cannot send headers)

Enable it by setting the MCP_TOKEN environment variable (16+ characters). Without it the
endpoint does not exist at all (it answers like any unknown page).
"""
import json, os, secrets
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

PROTOCOL = "2025-03-26"
MIN_TOKEN = 16


def _obj(props=None, required=None):
    return {"type": "object", "properties": props or {}, "required": required or []}


NUM = {"type": "number"}
INT = {"type": "integer"}
STR = {"type": "string"}
BOOL = {"type": "boolean"}

TOOLS = [
    ("panel_stats", "Overall usage: account counts, total up/down bytes, last 14 days.", _obj()),
    ("list_endpoints", "List endpoints (id, remark, kind, mode, number of accounts).", _obj()),
    ("create_endpoint", "Create an endpoint. kind: web-http | web-ws | edge-tcp | edge-http. mode: packet-up | stream-up | stream-one (xhttp kinds only).",
     _obj({"remark": STR, "kind": STR, "mode": STR}, ["remark", "kind"])),
    ("edit_endpoint", "Rename an endpoint and/or change its xhttp transfer mode.",
     _obj({"id": INT, "remark": STR, "mode": STR}, ["id"])),
    ("rotate_endpoint", "Give an endpoint a new secret path (and Reality short id). Existing links stop working.",
     _obj({"id": INT}, ["id"])),
    ("delete_endpoint", "Delete an endpoint and ALL its accounts. Irreversible.", _obj({"id": INT}, ["id"])),
    ("list_accounts", "List accounts with usage, quota, expiry, speed limits, state and subscription URL.", _obj()),
    ("create_account", "Create an account. gb=0 unlimited quota, days=0 never expires, *_mbps=0 unlimited speed.",
     _obj({"endpoint_id": INT, "name": STR, "gb": NUM, "days": INT, "down_mbps": NUM, "up_mbps": NUM},
          ["endpoint_id", "name"])),
    ("edit_account", "Change name, quota (gb), expiry (YYYY-MM-DD or empty = never) or speed limits of an account. Only pass what should change.",
     _obj({"id": INT, "name": STR, "gb": NUM, "expiry": STR, "down_mbps": NUM, "up_mbps": NUM}, ["id"])),
    ("set_speed_limit", "Set an account's speed limit in Mbps (0 = unlimited).",
     _obj({"id": INT, "down_mbps": NUM, "up_mbps": NUM}, ["id"])),
    ("toggle_account", "Enable/disable an account (flips the current state).", _obj({"id": INT}, ["id"])),
    ("reset_account_usage", "Reset an account's usage counters to zero.", _obj({"id": INT}, ["id"])),
    ("renew_account", "Renew: new quota (gb) and validity (days), usage reset, account enabled. 0 = unlimited / never.",
     _obj({"id": INT, "gb": NUM, "days": INT}, ["id"])),
    ("delete_account", "Delete an account. Irreversible.", _obj({"id": INT}, ["id"])),
    ("get_settings", "Read panel settings (domains, addresses, fingerprint, alpn, padding, fragment, vless encryption).", _obj()),
    ("update_settings", "Change panel settings. Only pass the fields that should change.",
     _obj({"domains": STR, "addresses": STR, "fp": STR, "alpn": STR, "alpn_ws": STR, "padding": STR,
           "xhttp_obfs": BOOL, "frag": BOOL, "frag_len": STR, "frag_int": STR, "vlessenc": BOOL,
           "regen_keys": BOOL})),
    ("diagnose", "DNS check of the panel domains/addresses; front=true also checks the Reality target (TLS 1.3 / h2).",
     _obj({"front": BOOL})),
]


def register(app, M):
    """M is the main module (it holds the models, engine and the endpoint functions)."""
    token = os.getenv("MCP_TOKEN", "").strip()
    if len(token) < MIN_TOKEN:
        print("MCP: disabled (set MCP_TOKEN, 16+ characters, to enable)", flush=True)
        return
    base = M.BASE + "/mcp"

    def ok_token(request: Request, path_token: str | None):
        got = path_token or ""
        h = request.headers.get("authorization", "")
        if h.lower().startswith("bearer "):
            got = h[7:].strip()
        return bool(got) and secrets.compare_digest(got, token)

    def acc_row(request, db, c):
        st = M.m.get_settings(db)
        host = M.hosts_of(request, st)[0]
        return {"id": c.id, "name": c.name, "endpoint": c.endpoint.remark, "used": c.used_bytes or 0,
                "up": c.up_bytes or 0, "down": c.down_bytes or 0, "total": c.total_bytes or 0,
                "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "", "enable": c.enable,
                "active": M.eng.is_active(c), "limit_down_kbps": c.limit_down_kbps or 0,
                "limit_up_kbps": c.limit_up_kbps or 0, "sub_url": f"https://{host}/sub/{c.sub_token}"}

    def call(name, a, request, db):
        if name == "panel_stats":
            return M.stats(db)
        if name == "list_endpoints":
            return M.list_endpoints(db)
        if name == "create_endpoint":
            return M.add_endpoint(M.EndpointIn(**a), db)
        if name == "edit_endpoint":
            i = a.pop("id")
            return M.edit_endpoint(i, M.EndpointEdit(**a), db)
        if name == "rotate_endpoint":
            return M.rotate_endpoint(a["id"], db)
        if name == "delete_endpoint":
            return M.del_endpoint(a["id"], db)
        if name == "list_accounts":
            return [acc_row(request, db, c) for c in db.query(M.m.Account).all()]
        if name == "create_account":
            r = M.add_client(M.AccountIn(**a), db)
            return acc_row(request, db, db.get(M.m.Account, r["id"]))
        if name == "edit_account":
            i = a.pop("id")
            return M.edit_account(i, M.AccountEdit(**a), db)
        if name == "set_speed_limit":
            i = a.pop("id")
            return M.set_limit(i, M.LimitIn(**a), db)
        if name == "toggle_account":
            return M.toggle_client(a["id"], db)
        if name == "reset_account_usage":
            return M.reset_client(a["id"], db)
        if name == "renew_account":
            i = a.pop("id")
            return M.renew_account(i, M.RenewIn(**a), db)
        if name == "delete_account":
            return M.del_client(a["id"], db)
        if name == "get_settings":
            return M.settings_view(request, db)
        if name == "update_settings":
            return M.put_settings_api(M.SettingsIn(**a), request, db)
        if name == "diagnose":
            return M.diag(request, 1 if a.get("front") else 0, db)
        raise KeyError(name)

    def handle(msg, request):
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:               # notification: nothing to answer
            return None

        def res(r):
            return {"jsonrpc": "2.0", "id": mid, "result": r}

        def err(code, text):
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

        if method == "initialize":
            return res({"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "panel", "version": "1.0.0"}})
        if method == "ping":
            return res({})
        if method == "tools/list":
            return res({"tools": [{"name": n, "description": d, "inputSchema": s} for n, d, s in TOOLS]})
        if method == "tools/call":
            p = msg.get("params") or {}
            name, args = p.get("name"), dict(p.get("arguments") or {})
            if name not in {t[0] for t in TOOLS}:
                return err(-32602, f"unknown tool {name}")
            db = M.m.SessionLocal()
            try:
                out = call(name, args, request, db)
                return res({"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, default=str)}]})
            except HTTPException as e:
                return res({"isError": True, "content": [{"type": "text", "text": f"{e.status_code}: {e.detail}"}]})
            except Exception as e:
                return res({"isError": True, "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}]})
            finally:
                db.close()
        return err(-32601, "method not found")

    async def endpoint(request: Request, path_token: str | None = None):
        if not ok_token(request, path_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if request.method == "GET":     # no server-initiated stream
            return Response(status_code=405, headers={"Allow": "POST"})
        if request.method == "DELETE":
            return Response(status_code=200)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, status_code=400)
        from starlette.concurrency import run_in_threadpool
        if isinstance(body, list):
            outs = [o for o in [await run_in_threadpool(handle, x, request) for x in body] if o]
            return JSONResponse(outs) if outs else Response(status_code=202)
        out = await run_in_threadpool(handle, body, request)
        return JSONResponse(out) if out else Response(status_code=202)

    async def ep_header(request: Request):
        return await endpoint(request, None)

    async def ep_path(request: Request, path_token: str):
        return await endpoint(request, path_token)

    app.add_api_route(base, ep_header, methods=["GET", "POST", "DELETE"], include_in_schema=False)
    app.add_api_route(base + "/{path_token}", ep_path, methods=["GET", "POST", "DELETE"], include_in_schema=False)
    print(f"MCP: enabled at {base}", flush=True)
