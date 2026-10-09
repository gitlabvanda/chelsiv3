import json, os, subprocess, sys, threading
from datetime import datetime
import re
from models import Endpoint, Account, DailyStat, get_settings

CORE_BIN = os.getenv("CORE_BIN", "/usr/local/bin/appcore")
CONF = "/tmp/core.json"
WEB_PORT = 10000        # internal xhttp, reached through Caddy at /s/*
WS_PORT = 10001         # internal WebSocket, reached through Caddy at /w/*
API_PORT = 10085        # internal stats API
EDGE_PORT = int(os.getenv("EDGE_PORT", "4433"))  # expose via Railway TCP Proxy
FRONT_HOST = os.getenv("FRONT_HOST", "www.cloudflare.com:443")
LIMITS = "/tmp/limits.json"
LIM_BASE = int(os.getenv("LIMIT_PORT_BASE", "20000"))   # local relay ports for speed-limited users
THROTTLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "throttle.py")

_proc = None
_tproc = None
_lock = threading.Lock()
_stop = threading.Event()
_active_ids = set()


def gen_keys():
    """Return (private_key, public_key) from the core binary (old and new output formats)."""
    out = subprocess.check_output([CORE_BIN, "x25519"], text=True)
    vals = [l.split(":", 1)[1].strip() for l in out.splitlines() if ":" in l]
    return vals[0], vals[1]


def gen_vlessenc():
    """Return (decryption, encryption) strings for VLESS Encryption (X25519 variant: short enough for share links)."""
    out = subprocess.check_output([CORE_BIN, "vlessenc"], text=True)
    dec = re.findall(r'"decryption": "([^"]+)"', out)
    enc = re.findall(r'"encryption": "([^"]+)"', out)
    if not dec or not enc:
        raise RuntimeError("core did not return VLESS encryption keys")
    return dec[0], enc[0]


def is_active(c):
    if not c.enable:
        return False
    if c.expiry and c.expiry < datetime.utcnow():
        return False
    if c.total_bytes and c.used_bytes >= c.total_bytes:
        return False
    return True


def build_config(db):
    """Return (core config, speed-limit relays)."""
    st = get_settings(db)
    limited = []  # active users that have a speed limit
    inbounds = [{
        "tag": "api", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }]
    for ib in db.query(Endpoint).filter_by(enable=True).all():
        flow = "xtls-rprx-vision" if ib.kind == "edge-tcp" else ""
        clients = []
        for c in ib.clients:
            if is_active(c):
                cl = {"id": c.uuid, "email": f"u{c.id}", "level": 0}
                if flow:
                    cl["flow"] = flow
                clients.append(cl)
                if (c.limit_down_kbps or 0) or (c.limit_up_kbps or 0):
                    limited.append(c)
        if not clients:
            continue
        stream = {}
        if ib.kind == "web-http":
            xs = {"path": ib.path, "mode": ib.mode, "xPaddingBytes": st["padding"]}
            if st["xhttp_obfs"] == "1":
                xs["xPaddingObfsMode"] = True      # clients must use the same setting (share links carry it)
            stream = {"network": "xhttp", "security": "none", "xhttpSettings": xs}
            listen, port = "127.0.0.1", WEB_PORT
        elif ib.kind == "web-ws":
            stream = {"network": "ws", "security": "none", "wsSettings": {"path": ib.path}}
            listen, port = "127.0.0.1", WS_PORT
        else:
            host = FRONT_HOST.split(":")[0]
            stream = {
                "network": "tcp" if ib.kind == "edge-tcp" else "xhttp",
                "security": "reality",
                "realitySettings": {
                    "show": False, "dest": FRONT_HOST, "serverNames": [host],
                    "privateKey": ib.key_a, "shortIds": [ib.tag_id],
                },
            }
            if ib.kind == "edge-http":
                stream["xhttpSettings"] = {"path": ib.path, "mode": ib.mode}
            listen, port = "0.0.0.0", EDGE_PORT
        dec = st["venc_dec"] if (st["vlessenc"] == "1" and st["venc_dec"] and ib.kind.startswith("web")) else "none"
        inbounds.append({
            "tag": f"in{ib.id}", "listen": listen, "port": port, "protocol": "vless",
            "settings": {"clients": clients, "decryption": dec},
            "streamSettings": stream,
        })
    outbounds = [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]
    rules = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        # users must not reach the panel, the stats API or Railway's private network through the proxy
        {"type": "field", "outboundTag": "block", "ip": [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
            "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"]},
    ]
    relays = []
    for i, c in enumerate(limited):
        port = LIM_BASE + i
        relays.append({"port": port, "down_kbps": int(c.limit_down_kbps or 0), "up_kbps": int(c.limit_up_kbps or 0)})
        outbounds.append({"protocol": "socks", "tag": f"lim{c.id}",
                          "settings": {"servers": [{"address": "127.0.0.1", "port": port}]}})
        u = f"u{c.id}"
        rules += [
            {"type": "field", "user": [u], "network": "udp", "port": "53", "outboundTag": "direct"},
            # other UDP (QUIC, ...) cannot be throttled by the relay: block it so apps fall back to TCP
            {"type": "field", "user": [u], "network": "udp", "outboundTag": "block"},
            {"type": "field", "user": [u], "network": "tcp", "outboundTag": f"lim{c.id}"},
        ]
    cfg = {
        # no per-connection access log by default: it would record every user's destinations
        "log": {"loglevel": os.getenv("CORE_LOG", "warning"),
                "access": "" if os.getenv("CORE_ACCESS_LOG") == "1" else "none"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }
    return cfg, relays


def _kill(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def restart(db):
    global _proc, _tproc, _active_ids
    with _lock:
        cfg, relays = build_config(db)
        _active_ids = {c.id for c in db.query(Account).all() if is_active(c)}
        with open(CONF, "w") as f:
            json.dump(cfg, f)
        _kill(_proc)
        _kill(_tproc)
        _tproc = None
        if relays:  # speed-limit relays must be listening before the core starts using them
            with open(LIMITS, "w") as f:
                json.dump(relays, f)
            _tproc = subprocess.Popen([sys.executable, THROTTLE, LIMITS])
        _proc = subprocess.Popen([CORE_BIN, "run", "-c", CONF])


def _poll(SessionLocal):
    while not _stop.is_set():
        _stop.wait(30)
        try:
            out = subprocess.run(
                [CORE_BIN, "api", "statsquery", f"--server=127.0.0.1:{API_PORT}", "-reset"],
                capture_output=True, text=True, timeout=15).stdout
            stats = json.loads(out).get("stat", []) if out.strip() else []
            with SessionLocal() as db:
                for s in stats:
                    p = s["name"].split(">>>")
                    if len(p) >= 4 and p[0] == "user":
                        c = db.get(Account, int(p[1][1:]))
                        v = int(s.get("value", 0))
                        if c and v:
                            up = p[-1] == "uplink"
                            c.used_bytes = (c.used_bytes or 0) + v
                            if up:
                                c.up_bytes = (c.up_bytes or 0) + v
                            else:
                                c.down_bytes = (c.down_bytes or 0) + v
                            day = datetime.utcnow().strftime("%Y-%m-%d")
                            d = db.get(DailyStat, day)
                            if not d:
                                d = DailyStat(day=day, up=0, down=0)
                                db.add(d)
                                db.flush()
                            if up:
                                d.up += v
                            else:
                                d.down += v
                db.commit()
                cur = {c.id for c in db.query(Account).all() if is_active(c)}
                if cur != _active_ids:
                    restart(db)
        except Exception as e:  # keep the poller alive
            print("poll error:", e, flush=True)


def start_poller(SessionLocal):
    threading.Thread(target=_poll, args=(SessionLocal,), daemon=True).start()


def stop():
    _stop.set()
    if _tproc and _tproc.poll() is None:
        _tproc.terminate()
    if _proc and _proc.poll() is None:
        _proc.terminate()
