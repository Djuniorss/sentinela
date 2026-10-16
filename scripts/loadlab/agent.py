"""Worker independente: servidor de controle HTTP/JSON mínimo + motor de carga.

  python loadlab.py worker --port 9101 --token SEGREDO --region gru

Exige token. Só aceita bind fora de loopback com token explícito.
Um worker = 1 processo asyncio = ~1 núcleo. Para usar uma máquina inteira, suba N workers.
"""
import asyncio
import json
import os
import platform
import socket
import sys
import time
from urllib.parse import urlsplit, parse_qs

from . import health, __version__
from .engine import Engine


class Agent:
    def __init__(self, wid, region, token):
        self.wid, self.region, self.token = wid, region, token
        self.engine = None
        self.task = None
        self.calib = None

    # ---- rotas ---------------------------------------------------------------
    async def route(self, method, path, q, body):
        if path == "/hello":
            return {"id": self.wid, "region": self.region, "version": __version__,
                    "host": socket.gethostname(), "os": platform.platform(),
                    "facts": health.static_facts(), "t": time.time()}
        if path == "/time":
            return {"t": time.time()}
        if path == "/probe":
            return await self.probe(body)
        if path == "/calibrate":
            from .calibrate import calibrate
            self.calib = await calibrate(body or {})
            return self.calib
        if path == "/start":
            if self.engine and self.engine.state in ("waiting", "running"):
                return {"error": "já existe execução ativa"}, 409
            self.engine = Engine(body["config"], float(body["start_at"]))
            self.task = asyncio.ensure_future(self.engine.run())
            return {"ok": True, "state": self.engine.state}
        if path == "/status":
            e = self.engine
            if not e:
                return {"state": "idle"}
            last = e.healthlog.get(max(e.healthlog)) if e.healthlog else None
            return {"state": e.state, "rel": round(e.rel(), 2) if e.t0 else None,
                    "totals": e.totals, "health": last, "inflight": e.inflight}
        if path == "/data":
            if not self.engine:
                return {"buckets": {}, "health": {}}
            d = self.engine.snapshot(int(q.get("from", ["0"])[0]))
            d["state"] = self.engine.state
            d["totals"] = self.engine.totals
            if self.engine.state in ("finished", "stopped"):
                d["tenants"] = self.engine.tenant_snapshot()
            return d
        if path == "/stop":
            if self.engine:
                self.engine.stop()
            return {"ok": True}
        return {"error": "rota desconhecida"}, 404

    async def probe(self, body):
        """RTT TCP de base até o alvo, medido ANTES da carga (linha de base de rede)."""
        u = urlsplit(body["base_url"])
        port = u.port or (443 if u.scheme == "https" else 80)
        out = []
        for _ in range(int(body.get("n", 10))):
            t = time.perf_counter()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(u.hostname, port), 5)
                out.append((time.perf_counter() - t) * 1000)
                w.close()
            except Exception as e:
                return {"ok": False, "error": repr(e)}
            await asyncio.sleep(0.05)
        out.sort()
        return {"ok": True, "rtt_min_ms": round(out[0], 2), "rtt_p50_ms": round(out[len(out) // 2], 2),
                "rtt_max_ms": round(out[-1], 2)}

    # ---- HTTP mínimo ----------------------------------------------------------
    async def handle(self, r, w):
        try:
            head = await r.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            hd = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
            n = int(hd.get("content-length", 0))
            body = json.loads(await r.readexactly(n)) if n else None
            u = urlsplit(target)
            if hd.get("x-loadlab-token") != self.token:
                res, code = {"error": "token inválido"}, 401
            else:
                res = await self.route(method, u.path, parse_qs(u.query), body)
                res, code = res if isinstance(res, tuple) else (res, 200)
        except Exception as e:  # noqa
            res, code = {"error": repr(e)}, 500
        data = json.dumps(res).encode()
        w.write(f"HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
                f"Connection: close\r\n\r\n".encode() + data)
        try:
            await w.drain()
        except Exception:
            pass
        w.close()


def serve(host, port, token, wid, region):
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        sys.exit("recusado: bind fora de loopback exige --token")
    token = token or os.environ.get("LOADLAB_TOKEN", "")
    if not token:
        sys.exit("informe --token ou LOADLAB_TOKEN")
    ag = Agent(wid, region, token)

    async def main():
        srv = await asyncio.start_server(ag.handle, host, port, limit=1 << 22)
        print(f"[worker {wid}/{region}] ouvindo em {host}:{port}", flush=True)
        async with srv:
            await srv.serve_forever()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
