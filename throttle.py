"""Per-user speed limiter.

Railway gives no access to `tc`, and the core has no built-in limiter, so limited users are routed
(by the core's routing rules) through tiny local SOCKS5 relays. There is one relay port per limited
user, bound to 127.0.0.1 only. The relay forwards the TCP stream and delays it with a token bucket
that is shared by all connections of that user. TCP back-pressure then slows the real transfer.

Usage: python throttle.py /tmp/limits.json
limits.json: [{"port": 20000, "down_kbps": 2000, "up_kbps": 1000}, ...]   (kilobit/s, 0 = unlimited)
"""
import asyncio, ipaddress, json, socket, struct, sys, time

CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 300


def blocked(ip_str):
    """Never let a relay reach private / loopback / link-local / CGNAT / multicast addresses."""
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (not ip.is_global) or ip.is_multicast


class Bucket:
    """Shared by every connection of one user in one direction."""
    BURST = 0.25  # seconds of unused capacity that may be spent at once

    def __init__(self, kbps):
        self.rate = kbps * 125  # kilobit/s -> bytes/s (0 = unlimited)
        self.t = time.monotonic()

    async def take(self, n):
        if not self.rate:
            return
        now = time.monotonic()
        self.t = max(self.t, now - self.BURST) + n / self.rate
        delay = self.t - now
        if delay > 0:
            await asyncio.sleep(delay)


async def pipe(r, w, bucket):
    size = 16384 if not bucket.rate else max(2048, min(16384, bucket.rate // 8))
    try:
        while True:
            data = await asyncio.wait_for(r.read(size), IDLE_TIMEOUT)
            if not data:
                break
            await bucket.take(len(data))
            w.write(data)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except Exception:
        w.close()


def reply(code):
    return b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"


async def connect_any(host, port):
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    tried = 0
    refused = True
    for _fam, _t, _p, _c, addr in infos:
        if blocked(addr[0]):
            continue
        refused = False
        tried += 1
        if tried > 3:
            break
        try:
            return await asyncio.wait_for(asyncio.open_connection(addr[0], port), CONNECT_TIMEOUT), 0
        except Exception:
            continue
    return None, (2 if refused else 4)  # 2 = not allowed, 4 = host unreachable


async def handle(r, w, down, up):
    rw = None
    try:
        ver, n = await r.readexactly(2)
        if ver != 5:
            return
        await r.readexactly(n)
        w.write(b"\x05\x00")
        ver, cmd, _, atyp = await r.readexactly(4)
        if cmd != 1:                       # only CONNECT (TCP); no BIND / UDP
            w.write(reply(7)); return
        if atyp == 1:
            host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 3:
            host = (await r.readexactly((await r.readexactly(1))[0])).decode("ascii", "ignore")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        else:
            w.write(reply(8)); return
        port = struct.unpack("!H", await r.readexactly(2))[0]
        res, err = await connect_any(host, port)
        if not res:
            w.write(reply(err)); return
        rr, rw = res
        w.write(reply(0))
        await w.drain()
        # xray -> internet = the user's upload ; internet -> xray = the user's download
        await asyncio.gather(pipe(r, rw, up), pipe(rr, w, down))
    except Exception:
        pass
    finally:
        for x in (w, rw):
            if x:
                try:
                    x.close()
                except Exception:
                    pass


async def main(path):
    items = json.load(open(path))
    servers = []
    for it in items:
        down, up = Bucket(int(it.get("down_kbps", 0))), Bucket(int(it.get("up_kbps", 0)))
        servers.append(await asyncio.start_server(
            lambda r, w, d=down, u=up: handle(r, w, d, u), "127.0.0.1", int(it["port"]), backlog=256))
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv[1]))
    except KeyboardInterrupt:
        pass
