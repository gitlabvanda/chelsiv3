import base64, ipaddress, json, os, re, secrets, socket, ssl, time, uuid as uuidlib
from concurrent.futures import ThreadPoolExecutor
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
_gfails = []   # timestamps of recent failed logins from all addresses
POOL = ThreadPoolExecutor(max_workers=4)
FRONT_HOST = os.getenv("FRONT_HOST", "www.cloudflare.com:443")
TCP_DOMAIN = os.getenv("TCP_PROXY_DOMAIN", "")   # Railway TCP Proxy domain (for edge mode)
TCP_PORT = os.getenv("TCP_PROXY_PORT", "")       # Railway TCP Proxy public port
# Optional raw JSON merged into the xhttp "extra" link parameter (advanced)
XHTTP_EXTRA = os.getenv("XHTTP_EXTRA", "").strip()
FRAG_MAX_SPLIT = os.getenv("FRAG_MAX_SPLIT", "3-6").strip()
FP_OK = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
ALPN_OK = ("h2", "http/1.1", "h2,http/1.1")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def parse_list(raw):
    out = []
    for it in re.split(r"[\s,;]+", raw or ""):
        it = re.sub(r"^https?://", "", it.strip().lower()).split("/")[0]
        if it and it not in out:
            out.append(it)
    return out


def valid_host(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(HOST_RE.fullmatch(h))


def fmt_addr(a):
    return f"[{a}]" if ":" in a else a


@asynccontextmanager
async def lifespan(app):
    m.Base.metadata.create_all(m.engine)
    for col in ("up_bytes", "down_bytes", "limit_down_kbps", "limit_up_kbps"):  # add new columns to an existing database
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
        raise HTTPException(404, "unauthorized")   # looks like any other missing page to outsiders


def plain_host(h):
    """A usable public host name from a Host header, or ''."""
    h = (h or "").split(",")[0].split(":")[0].strip().lower()
    if not h or h == "localhost" or h.endswith((".internal", ".local")) or ipaddress_ok(h) or not HOST_RE.fullmatch(h):
        return ""
    return h


def hosts_of(request: Request, st):
    """Domains used in links: dashboard setting (or PANEL_DOMAIN) > the host this request came in on > Railway domain."""
    lst = [h for h in parse_list(st["domains"]) if valid_host(h)]
    if lst:
        return lst
    h = plain_host(request.headers.get("x-forwarded-host")) or plain_host(request.headers.get("host"))
    if h:
        return [h]
    rd = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
    return [rd] if rd else ["localhost"]


def link_targets(st, hosts):
    """(address, host) for every link, in the same order build_links uses."""
    addrs = parse_list(st["addresses"])
    return [(a, h) for h in hosts for a in (addrs or [h])]


def build_links(c, st, hosts):
    ib = c.endpoint
    name = f"{ib.remark}-{c.name}"
    path = quote(ib.path, safe="")
    if ib.kind.startswith("edge"):
        sni = FRONT_HOST.split(":")[0]
        addr = TCP_DOMAIN or hosts[0]
        port = TCP_PORT or eng.EDGE_PORT
        q = f"encryption=none&security=reality&sni={sni}&fp={st['fp']}&pbk={ib.key_b}&sid={ib.tag_id}"
        if ib.kind == "edge-tcp":
            q += "&type=tcp&flow=xtls-rprx-vision"
        else:
            q += f"&type=xhttp&path={path}&mode={ib.mode}"
        return [f"vless://{c.uuid}@{addr}:{port}?{q}#{quote(name)}"]
    enc = quote(st["venc_enc"], safe="") if (st["vlessenc"] == "1" and st["venc_enc"]) else "none"
    addrs = parse_list(st["addresses"])
    extra = {}
    if ib.kind == "web-http":
        if st["padding"] != "100-1000" or st["xhttp_obfs"] == "1":
            extra["xPaddingBytes"] = st["padding"]
        if st["xhttp_obfs"] == "1":
            extra["xPaddingObfsMode"] = True
        if XHTTP_EXTRA:
            try:
                extra.update(json.loads(XHTTP_EXTRA))
            except ValueError:
                pass
    links = []
    for h in hosts:
        base = f"encryption={enc}&security=tls&sni={h}&fp={st['fp']}"
        if ib.kind == "web-http":
            q = f"{base}&alpn={quote(st['alpn'], safe='')}&type=xhttp&host={h}&path={path}&mode={ib.mode}"
            if extra:
                q += "&extra=" + quote(json.dumps(extra, separators=(",", ":")), safe="")
        else:  # web-ws
            q = f"{base}&alpn={quote(st['alpn_ws'], safe='')}&type=ws&host={h}&path={path}"
        for a in (addrs or [h]):
            links.append((f"vless://{c.uuid}@{fmt_addr(a)}:443?{q}", name))
    if len(links) == 1:
        return [f"{links[0][0]}#{quote(links[0][1])}"]
    return [f"{l}#{quote(f'{n}-{i}')}" for i, (l, n) in enumerate(links, 1)]


def qr_svg(text):
    try:
        import segno
        return segno.make(text, error="m").svg_inline(scale=4, border=2, omitsize=True, dark="#0b1220", light="#ffffff")
    except Exception:
        return ""


# ---------- pages ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    # The dashboard sends X-Panel: 1 and gets JSON. Everybody else sees an ordinary "page not found".
    if exc.status_code in (404, 405) and request.headers.get("x-panel") != "1":
        return templates.TemplateResponse(request, "notfound.html", {}, status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.middleware("http")
async def hardening_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    p = request.url.path
    if p.startswith(BASE) or p.startswith("/sub/") or p.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.api_route("/", methods=["GET", "HEAD"])
def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html", {})


@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nAllow: /\n")


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
    now = time.time()
    _gfails[:] = [t for t in _gfails if now - t < 600][-500:]
    if len(_gfails) >= 10:   # many failures from anywhere: slow every attempt down (limits guessing, never locks you out)
        time.sleep(min(4.0, 0.25 * (len(_gfails) - 9)))
    ok = secrets.compare_digest(username, ADMIN_USER) & secrets.compare_digest(password, ADMIN_PASS)
    if not ok:
        _gfails.append(time.time())
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


@app.post("/api/endpoints/{iid}/rotate", dependencies=[Depends(auth)])
def rotate_endpoint(iid: int, db=Depends(get_db)):
    """New secret path (and Reality short id): use it if a path or key ever leaks or gets blocked."""
    ib = db.get(m.Endpoint, iid)
    if not ib:
        raise HTTPException(404, "not found")
    if ib.kind == "web-ws":
        ib.path = "/w/" + secrets.token_hex(6)
    elif ib.kind != "edge-tcp":
        ib.path = "/s/" + secrets.token_hex(6) + "/"
    if ib.kind.startswith("edge"):
        ib.tag_id = secrets.token_hex(8)
    db.commit()
    eng.restart(db)
    return {"ok": True}


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
    down_mbps: float = 0   # speed limit, megabit/s, 0 = unlimited
    up_mbps: float = 0


def to_kbps(mbps):
    if mbps < 0 or mbps > 10000:
        raise HTTPException(400, "speed must be between 0 and 10000 Mbps")
    return max(1, int(round(mbps * 1000))) if mbps > 0 else 0


@app.get("/api/accounts", dependencies=[Depends(auth)])
def list_clients(db=Depends(get_db)):
    return [{"id": c.id, "name": c.name, "endpoint": c.endpoint.remark, "used": c.used_bytes or 0, "up": c.up_bytes or 0, "down": c.down_bytes or 0,
             "total": c.total_bytes or 0, "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
             "enable": c.enable, "active": eng.is_active(c), "token": c.sub_token,
             "limit_down": c.limit_down_kbps or 0, "limit_up": c.limit_up_kbps or 0}
            for c in db.query(m.Account).all()]


@app.post("/api/accounts", dependencies=[Depends(auth)])
def add_client(data: AccountIn, db=Depends(get_db)):
    if not db.get(m.Endpoint, data.endpoint_id):
        raise HTTPException(400, "endpoint not found")
    c = m.Account(endpoint_id=data.endpoint_id, name=data.name.strip() or "user",
                 uuid=str(uuidlib.uuid4()), sub_token=secrets.token_urlsafe(16),
                 total_bytes=int(data.gb * 1024 ** 3),
                 limit_down_kbps=to_kbps(data.down_mbps), limit_up_kbps=to_kbps(data.up_mbps),
                 expiry=datetime.utcnow() + timedelta(days=data.days) if data.days else None)
    db.add(c)
    db.commit()
    eng.restart(db)
    return {"id": c.id}


class LimitIn(BaseModel):
    down_mbps: float = 0
    up_mbps: float = 0


@app.post("/api/accounts/{cid}/limit", dependencies=[Depends(auth)])
def set_limit(cid: int, data: LimitIn, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.limit_down_kbps, c.limit_up_kbps = to_kbps(data.down_mbps), to_kbps(data.up_mbps)
    db.commit()
    eng.restart(db)
    return {"down": c.limit_down_kbps, "up": c.limit_up_kbps}


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


# ---------- settings ----------
class SettingsIn(BaseModel):
    domains: str | None = None
    addresses: str | None = None
    fp: str | None = None
    alpn: str | None = None
    alpn_ws: str | None = None
    padding: str | None = None
    xhttp_obfs: bool | None = None
    frag: bool | None = None
    frag_len: str | None = None
    frag_int: str | None = None
    vlessenc: bool | None = None
    regen_keys: bool = False


def settings_view(request, db):
    st = m.get_settings(db)
    return {"domains": st["domains"], "addresses": st["addresses"], "fp": st["fp"], "alpn": st["alpn"],
            "alpn_ws": st["alpn_ws"], "padding": st["padding"], "xhttp_obfs": st["xhttp_obfs"] == "1",
            "frag": st["frag"] == "1", "frag_len": st["frag_len"], "frag_int": st["frag_int"],
            "vlessenc": st["vlessenc"] == "1", "has_keys": bool(st["venc_dec"]),
            "effective": hosts_of(request, st), "fps": list(FP_OK), "alpns": list(ALPN_OK)}


@app.get("/api/settings", dependencies=[Depends(auth)])
def get_settings_api(request: Request, db=Depends(get_db)):
    return settings_view(request, db)


@app.put("/api/settings", dependencies=[Depends(auth)])
def put_settings_api(data: SettingsIn, request: Request, db=Depends(get_db)):
    old = m.get_settings(db)
    new = {}
    if data.domains is not None:
        lst = parse_list(data.domains)
        if any(not valid_host(h) or ipaddress_ok(h) for h in lst):
            raise HTTPException(400, "domains must be host names (no IP addresses)")
        new["domains"] = ",".join(lst)
    if data.addresses is not None:
        lst = parse_list(data.addresses)
        if any(not valid_host(h) for h in lst):
            raise HTTPException(400, "invalid address in the list")
        new["addresses"] = ",".join(lst)
    if data.fp is not None:
        if data.fp not in FP_OK:
            raise HTTPException(400, "invalid fingerprint")
        new["fp"] = data.fp
    for key, val in (("alpn", data.alpn), ("alpn_ws", data.alpn_ws)):
        if val is not None:
            if val not in ALPN_OK:
                raise HTTPException(400, "invalid alpn")
            new[key] = val
    if data.padding is not None:
        mt = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", data.padding.strip())
        if not mt or (mt.group(2) and int(mt.group(1)) > int(mt.group(2))):
            raise HTTPException(400, "padding must look like 100-1000")
        new["padding"] = data.padding.strip()
    if data.frag is not None:
        new["frag"] = "1" if data.frag else "0"
    for key, val in (("frag_len", data.frag_len), ("frag_int", data.frag_int)):
        if val is not None:
            mt = re.fullmatch(r"(\d{1,4})(?:-(\d{1,4}))?", val.strip())
            if not mt or (mt.group(2) and int(mt.group(1)) > int(mt.group(2))) or int(mt.group(1)) < 1:
                raise HTTPException(400, "fragment values must look like 100-200")
            new[key] = val.strip()
    if data.xhttp_obfs is not None:
        new["xhttp_obfs"] = "1" if data.xhttp_obfs else "0"
    if data.vlessenc is not None:
        new["vlessenc"] = "1" if data.vlessenc else "0"
    want_enc = new.get("vlessenc", old["vlessenc"]) == "1"
    if (want_enc and not old["venc_dec"]) or (data.regen_keys and want_enc):
        try:
            new["venc_dec"], new["venc_enc"] = eng.gen_vlessenc()
        except Exception:
            raise HTTPException(500, "could not generate encryption keys")
    m.put_settings(db, new)
    after = m.get_settings(db)
    if any(old[k] != after[k] for k in ("padding", "xhttp_obfs", "vlessenc", "venc_dec")):
        eng.restart(db)   # server side changed; clients must refresh their subscription
    return settings_view(request, db)


def resolve(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    except OSError:
        return []


def check_front(hostport):
    """Does the Reality target look like a good one? (TLS 1.3 and HTTP/2, as Reality needs)"""
    host, _, port = hostport.partition(":")
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, int(port or 443)), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as t:
            return {"host": host, "tls": t.version(), "tls13": t.version() == "TLSv1.3",
                    "h2": t.selected_alpn_protocol() == "h2"}


@app.get("/api/diag", dependencies=[Depends(auth)])
def diag(request: Request, front: int = 0, db=Depends(get_db)):
    st = m.get_settings(db)
    names = list(hosts_of(request, st)) + [h for h in parse_list(st["addresses"]) if not ipaddress_ok(h)]
    futs = {h: POOL.submit(resolve, h) for h in dict.fromkeys(names)}
    domains = []
    for h, f in futs.items():
        try:
            ips = f.result(timeout=4)
        except Exception:
            ips = []
        domains.append({"host": h, "ok": bool(ips), "ips": ips[:3]})
    out = {"domains": domains}
    if front:
        try:
            out["front"] = check_front(FRONT_HOST)
        except Exception as e:
            out["front"] = {"host": FRONT_HOST.split(":")[0], "error": type(e).__name__}
    return out


def ipaddress_ok(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


# ---------- full client config with TLS fragment ----------
def client_json(c, st, hosts, idx):
    """A complete client config. The fragment mask splits the TLS ClientHello (and with it the SNI)
    into small pieces, which defeats DPI that only matches the server name in a single packet."""
    ib = c.endpoint
    if not ib.kind.startswith("web"):
        raise HTTPException(400, "json config is only available for the web modes")
    targets = link_targets(st, hosts)
    addr, host = targets[min(max(idx, 0), len(targets) - 1)]
    enc = st["venc_enc"] if (st["vlessenc"] == "1" and st["venc_enc"]) else "none"
    if ib.kind == "web-http":
        xs = {"host": host, "path": ib.path, "mode": ib.mode}
        if st["padding"] != "100-1000" or st["xhttp_obfs"] == "1":
            xs["xPaddingBytes"] = st["padding"]
        if st["xhttp_obfs"] == "1":
            xs["xPaddingObfsMode"] = True
        if XHTTP_EXTRA:
            try:
                xs.update(json.loads(XHTTP_EXTRA))
            except ValueError:
                pass
        ss = {"network": "xhttp", "xhttpSettings": xs}
        alpn = st["alpn"]
    else:
        ss = {"network": "ws", "wsSettings": {"path": ib.path, "host": host}}
        alpn = st["alpn_ws"]
    ss.update(security="tls", tlsSettings={"serverName": host, "fingerprint": st["fp"], "alpn": alpn.split(",")})
    outbounds = [{
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": addr, "port": 443, "users": [{"id": c.uuid, "encryption": enc}]}]},
        "streamSettings": ss,
    }]
    if st["frag"] == "1":
        # split the TLS hello into small pieces right on the outbound socket (no extra chained outbound)
        ss["sockopt"] = {"dialerProxy": "", "finalmask": {"tcp": [{
            "type": "fragment",
            "settings": {"packets": "tlshello", "lengths": [st["frag_len"]],
                         "delays": [st["frag_int"]], "maxSplit": FRAG_MAX_SPLIT},
        }]}}
    outbounds += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
             "outboundTag": "direct"}]},
    }


@app.get("/sub/{token}/json")
def sub_json(token: str, request: Request, i: int = 0, db=Depends(get_db)):
    c = db.query(m.Account).filter_by(sub_token=token).first()
    if not c:
        raise HTTPException(404, "not found")
    st = m.get_settings(db)
    return JSONResponse(client_json(c, st, hosts_of(request, st), i))


# ---------- subscription ----------
@app.get("/sub/{token}")
def sub(token: str, request: Request, db=Depends(get_db)):
    c = db.query(m.Account).filter_by(sub_token=token).first()
    if not c:
        raise HTTPException(404, "not found")
    st = m.get_settings(db)
    hosts = hosts_of(request, st)
    links = build_links(c, st, hosts)
    if "text/html" in request.headers.get("accept", ""):
        sub_url = f"https://{hosts[0]}/sub/{token}"
        return templates.TemplateResponse(request, "sub.html", {
            "c": c, "links": links, "active": eng.is_active(c),
            "used": round((c.used_bytes or 0) / 1024 ** 3, 2),
            "total": round((c.total_bytes or 0) / 1024 ** 3, 2),
            "pct": min(100, int((c.used_bytes or 0) * 100 / c.total_bytes)) if c.total_bytes else 0,
            "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
            "sub_url": sub_url, "qr": qr_svg(sub_url),
            "json_urls": ([(a, f"https://{hosts[0]}/sub/{token}/json?i={n}")
                           for n, (a, h) in enumerate(link_targets(st, hosts))]
                          if c.endpoint.kind.startswith("web") else []),
            "down": c.limit_down_kbps or 0, "up": c.limit_up_kbps or 0,
        })
    # subscription apps get base64 + usage header
    exp = int(c.expiry.timestamp()) if c.expiry else 0
    hdr = f"upload={c.up_bytes or 0}; download={c.down_bytes or 0}; total={c.total_bytes or 0}; expire={exp}"
    body = base64.b64encode("\n".join(links).encode()).decode()
    return PlainTextResponse(body, headers={"subscription-userinfo": hdr})
