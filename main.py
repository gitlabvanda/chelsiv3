import base64, os, re, secrets, time, uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

import models as m
import engine as eng

ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASS = os.environ["ADMIN_PASS"]
SESSION_SECRET = os.environ["SESSION_SECRET"]
ADMIN_PATH = os.environ["ADMIN_PATH"].strip("/")
if not re.fullmatch(r"[A-Za-z0-9_-]{8,}", ADMIN_PATH):
    raise SystemExit("ADMIN_PATH must be 8+ chars: letters, digits, - or _")
BASE = "/" + ADMIN_PATH
_fails = {}
PANEL_DOMAIN = (os.getenv("PANEL_DOMAIN") or os.getenv("RAILWAY_PUBLIC_DOMAIN") or "") \
    .replace("https://", "").replace("http://", "").strip("/")
FRONT_HOST = os.getenv("FRONT_HOST", "www.cloudflare.com:443")
TCP_DOMAIN = os.getenv("TCP_PROXY_DOMAIN", "")   # Railway TCP Proxy domain (for edge mode)
TCP_PORT = os.getenv("TCP_PROXY_PORT", "")       # Railway TCP Proxy public port
# --- client-side link options (xhttp behind Cloudflare) ---
CLIENT_FP = os.getenv("CLIENT_FP", "chrome")      # chrome | firefox | safari | ios | android | edge | randomized
CLIENT_ALPN = os.getenv("CLIENT_ALPN", "h2")      # xhttp: h2 is safest in Iran (QUIC/UDP is often throttled)
CLIENT_ALPN_WS = os.getenv("CLIENT_ALPN_WS", "http/1.1")  # WebSocket needs HTTP/1.1 through Cloudflare
# Comma-separated Cloudflare IPs/domains to connect to. SNI and Host stay = your domain.
CLIENT_ADDRESS = [a.strip() for a in os.getenv("CLIENT_ADDRESS", "").split(",") if a.strip()]
# Optional raw JSON for the xhttp "extra" link parameter (xmux, xPaddingBytes, ...)
XHTTP_EXTRA = os.getenv("XHTTP_EXTRA", "").strip()


@asynccontextmanager
async def lifespan(app):
    m.Base.metadata.create_all(m.engine)
    for col in ("up_bytes", "down_bytes"):  # add new columns to an existing database
        try:
            with m.engine.begin() as cx:
                cx.execute(text(f"ALTER TABLE clients ADD COLUMN {col} BIGINT DEFAULT 0"))
        except Exception:
            pass
    with m.SessionLocal() as db:
        eng.restart(db)
    eng.start_poller(m.SessionLocal)
    yield
    eng.stop()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax",
                   https_only=os.getenv("RAILWAY_ENVIRONMENT") is not None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def get_db():
    db = m.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def auth(request: Request):
    if not request.session.get("ok"):
        raise HTTPException(401, "unauthorized")


def host_of(request: Request):
    return PANEL_DOMAIN or request.headers.get("host", "").split(":")[0]


def build_link(c, host):
    ib = c.endpoint
    name = quote(f"{ib.remark}-{c.name}")
    path = quote(ib.path, safe="")
    if ib.kind == "web-http":
        q = (f"encryption=none&security=tls&sni={host}&fp={CLIENT_FP}&alpn={quote(CLIENT_ALPN, safe='')}"
             f"&type=xhttp&host={host}&path={path}&mode={ib.mode}")
        if XHTTP_EXTRA:
            q += "&extra=" + quote(XHTTP_EXTRA, safe="")
        # one link per address (clean Cloudflare IPs); falls back to the domain itself
        return "\n".join(f"vless://{c.uuid}@{a}:443?{q}#{name}" for a in (CLIENT_ADDRESS or [host]))
    if ib.kind == "web-ws":
        q = (f"encryption=none&security=tls&sni={host}&fp={CLIENT_FP}&alpn={quote(CLIENT_ALPN_WS, safe='')}"
             f"&type=ws&host={host}&path={path}")
        return "\n".join(f"vless://{c.uuid}@{a}:443?{q}#{name}" for a in (CLIENT_ADDRESS or [host]))
    sni = FRONT_HOST.split(":")[0]
    addr = TCP_DOMAIN or host
    port = TCP_PORT or eng.EDGE_PORT
    q = f"encryption=none&security=reality&sni={sni}&fp={CLIENT_FP}&pbk={ib.key_b}&sid={ib.tag_id}"
    if ib.kind == "edge-tcp":
        q += "&type=tcp&flow=xtls-rprx-vision"
    else:
        q += f"&type=xhttp&path={path}&mode={ib.mode}"
    return f"vless://{c.uuid}@{addr}:{port}?{q}#{name}"


# ---------- pages ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    # unknown pages look like the public site, not like a JSON API
    if exc.status_code == 404 and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(request, "landing.html", {}, status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/")
def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html", {})


@app.get(BASE)
def admin_page(request: Request):
    if not request.session.get("ok"):
        return templates.TemplateResponse(request, "login.html",
                                          {"err": request.query_params.get("err"), "base": BASE})
    return templates.TemplateResponse(request, "dashboard.html", {"base": BASE})


@app.post(BASE + "/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    n, t = _fails.get(ip, (0, 0.0))
    if n >= 5 and time.time() - t < 600:
        raise HTTPException(429, "try later")
    ok = secrets.compare_digest(username, ADMIN_USER) & secrets.compare_digest(password, ADMIN_PASS)
    if not ok:
        _fails[ip] = (n + 1, time.time())
        return RedirectResponse(BASE + "?err=1", status_code=303)
    _fails.pop(ip, None)
    request.session["ok"] = True
    return RedirectResponse(BASE, status_code=303)


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# ---------- endpoints ----------
class EndpointIn(BaseModel):
    remark: str
    kind: str
    mode: str = "packet-up"


@app.get("/api/endpoints", dependencies=[Depends(auth)])
def list_endpoints(db=Depends(get_db)):
    return [{"id": i.id, "remark": i.remark, "kind": i.kind, "mode": i.mode,
             "accounts": len(i.clients)} for i in db.query(m.Endpoint).all()]


@app.post("/api/endpoints", dependencies=[Depends(auth)])
def add_endpoint(data: EndpointIn, db=Depends(get_db)):
    if data.kind not in ("web-http", "web-ws", "edge-tcp", "edge-http"):
        raise HTTPException(400, "invalid kind")
    if data.mode not in ("packet-up", "stream-up", "stream-one"):
        raise HTTPException(400, "invalid mode")
    is_edge = data.kind.startswith("edge")
    for i in db.query(m.Endpoint).all():
        # edge kinds share one port (one of them); each web kind has its own internal port
        if (is_edge and i.kind.startswith("edge")) or i.kind == data.kind:
            raise HTTPException(400, "only one endpoint of this kind is supported (one port each)")
    if data.kind == "web-ws":
        ib = m.Endpoint(remark=data.remark.strip() or "endpoint", kind=data.kind, mode="ws",
                        path="/w/" + secrets.token_hex(6))   # exact path, no trailing slash
    else:
        ib = m.Endpoint(remark=data.remark.strip() or "endpoint", kind=data.kind, mode=data.mode,
                        path="/s/" + secrets.token_hex(6) + "/")
    if is_edge:
        ib.key_a, ib.key_b = eng.gen_keys()
        ib.tag_id = secrets.token_hex(8)
    db.add(ib)
    db.commit()
    eng.restart(db)
    return {"id": ib.id}


@app.delete("/api/endpoints/{iid}", dependencies=[Depends(auth)])
def del_endpoint(iid: int, db=Depends(get_db)):
    ib = db.get(m.Endpoint, iid)
    if not ib:
        raise HTTPException(404, "not found")
    db.delete(ib)
    db.commit()
    eng.restart(db)
    return {"ok": True}


# ---------- clients ----------
class AccountIn(BaseModel):
    endpoint_id: int
    name: str
    gb: float = 0      # 0 = unlimited
    days: int = 0      # 0 = never expires


@app.get("/api/accounts", dependencies=[Depends(auth)])
def list_clients(db=Depends(get_db)):
    return [{"id": c.id, "name": c.name, "endpoint": c.endpoint.remark, "used": c.used_bytes or 0, "up": c.up_bytes or 0, "down": c.down_bytes or 0,
             "total": c.total_bytes or 0, "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
             "enable": c.enable, "active": eng.is_active(c), "token": c.sub_token}
            for c in db.query(m.Account).all()]


@app.post("/api/accounts", dependencies=[Depends(auth)])
def add_client(data: AccountIn, db=Depends(get_db)):
    if not db.get(m.Endpoint, data.endpoint_id):
        raise HTTPException(400, "endpoint not found")
    c = m.Account(endpoint_id=data.endpoint_id, name=data.name.strip() or "user",
                 uuid=str(uuidlib.uuid4()), sub_token=secrets.token_urlsafe(16),
                 total_bytes=int(data.gb * 1024 ** 3),
                 expiry=datetime.utcnow() + timedelta(days=data.days) if data.days else None)
    db.add(c)
    db.commit()
    eng.restart(db)
    return {"id": c.id}


@app.post("/api/accounts/{cid}/toggle", dependencies=[Depends(auth)])
def toggle_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.enable = not c.enable
    db.commit()
    eng.restart(db)
    return {"enable": c.enable}


@app.post("/api/accounts/{cid}/reset", dependencies=[Depends(auth)])
def reset_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.used_bytes = c.up_bytes = c.down_bytes = 0
    db.commit()
    eng.restart(db)
    return {"ok": True}


@app.delete("/api/accounts/{cid}", dependencies=[Depends(auth)])
def del_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    db.delete(c)
    db.commit()
    eng.restart(db)
    return {"ok": True}


class RenewIn(BaseModel):
    gb: float = 0
    days: int = 0


@app.post("/api/accounts/{cid}/renew", dependencies=[Depends(auth)])
def renew_account(cid: int, data: RenewIn, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.total_bytes = int(data.gb * 1024 ** 3)
    c.used_bytes = c.up_bytes = c.down_bytes = 0
    c.expiry = datetime.utcnow() + timedelta(days=data.days) if data.days else None
    c.enable = True
    db.commit()
    eng.restart(db)
    return {"ok": True}


@app.get("/api/stats", dependencies=[Depends(auth)])
def stats(db=Depends(get_db)):
    cl = db.query(m.Account).all()
    days = db.query(m.DailyStat).order_by(m.DailyStat.day.desc()).limit(14).all()[::-1]
    return {"accounts": len(cl), "active": sum(1 for c in cl if eng.is_active(c)),
            "up": sum(c.up_bytes or 0 for c in cl), "down": sum(c.down_bytes or 0 for c in cl),
            "days": [{"day": d.day, "up": d.up or 0, "down": d.down or 0} for d in days]}


# ---------- subscription ----------
@app.get("/sub/{token}")
def sub(token: str, request: Request, db=Depends(get_db)):
    c = db.query(m.Account).filter_by(sub_token=token).first()
    if not c:
        raise HTTPException(404, "not found")
    link = build_link(c, host_of(request))
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(request, "sub.html", {
            "c": c, "link": link, "active": eng.is_active(c),
            "used": round((c.used_bytes or 0) / 1024 ** 3, 2),
            "total": round((c.total_bytes or 0) / 1024 ** 3, 2),
            "pct": min(100, int((c.used_bytes or 0) * 100 / c.total_bytes)) if c.total_bytes else 0,
            "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
        })
    # subscription apps get base64 + usage header
    exp = int(c.expiry.timestamp()) if c.expiry else 0
    hdr = f"upload=0; download={c.used_bytes or 0}; total={c.total_bytes or 0}; expire={exp}"
    body = base64.b64encode(link.encode()).decode()
    return PlainTextResponse(body, headers={"subscription-userinfo": hdr})
