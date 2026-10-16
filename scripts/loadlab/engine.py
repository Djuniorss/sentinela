"""Motor de carga nativo (HTTP/1.1, asyncio, só stdlib).

Dois modelos SEPARADOS — nunca equivalentes:
  open   -> taxa de chegada (req-iterações/s planejadas; o alvo lento NÃO reduz a carga;
            o que o gerador não consegue emitir vira 'drop', nunca some em silêncio)
  closed -> concorrência (N usuários virtuais em loop com think time; carga cai se o alvo fica lento)
Latência de resposta ('resp') é medida do envio real; o atraso do gerador antes do envio ('late')
é medido à parte — a diferença entre as duas é o que o gerador "introduziu".
"""
import asyncio
import errno
import math
import random
import ssl
import time
from urllib.parse import urlsplit

from .hist import Hist
from . import health

MAX_ARRIVALS_PER_TICK = 4000
PORT_EXHAUST = {errno.EADDRNOTAVAIL, 10048, 10055, 99}


def new_bucket():
    return {"arr": 0, "sent": 0, "ok": 0, "err": 0, "drop_cap": 0, "drop_sched": 0,
            "tx": 0, "rx": 0, "plan": 0.0,
            "resp": Hist(), "ttfb": Hist(), "conn": Hist(), "late": Hist(), "lag": Hist(),
            "errs": {}, "status": {}, "ep": {}}


def bucket_to_dict(b):
    d = {k: v for k, v in b.items() if k not in ("resp", "ttfb", "conn", "late", "lag", "ep")}
    for k in ("resp", "ttfb", "conn", "late", "lag"):
        d[k] = b[k].to_dict()
    d["ep"] = {n: {"n": e["n"], "err": e["err"], "resp": e["resp"].to_dict(), "errs": e["errs"]}
               for n, e in b["ep"].items()}
    return d


class Engine:
    def __init__(self, cfg, start_at):
        self.cfg = cfg
        self.start_at = start_at
        self.model = cfg["model"]
        self.stages = cfg["stages"]
        self.start_value = cfg.get("start_value", 0)
        self.total = sum(s["duration"] for s in self.stages)
        self.timeout = float(cfg.get("timeout", 10))
        self.keepalive = cfg.get("keepalive", True)
        self.max_inflight = int(cfg.get("max_inflight", 2000))
        self.rng = random.Random(cfg.get("seed", 1))
        u = urlsplit(cfg["target"]["base_url"])
        self.scheme, self.host = u.scheme, u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.base_path = u.path.rstrip("/")
        self.ssl = None
        if self.scheme == "https":
            self.ssl = ssl.create_default_context()
            if not cfg["target"].get("verify_tls", True):
                self.ssl.check_hostname = False
                self.ssl.verify_mode = ssl.CERT_NONE
        self.eps = {e["name"]: e for e in cfg["endpoints"]}
        flows = cfg.get("flows") or [{"name": e["name"], "weight": e.get("weight", 1),
                                      "steps": [e["name"]]} for e in cfg["endpoints"]]
        self.flows = flows
        self.flow_cdf = _cdf([f.get("weight", 1) for f in flows])
        tn = cfg.get("tenants") or {}
        self.tn_count = int(tn.get("count", 0))
        self.tn = tn
        self.tn_cdf = _tenant_cdf(tn) if self.tn_count else None
        self.tenant_stats = {}
        self.stride = int(cfg.get("stride", 1))
        self.widx = int(cfg.get("worker_index", 0))
        self.buckets = {}
        self.healthlog = {}
        self.cnt = {"conns": 0, "tx": 0, "rx": 0}
        self.pool = []
        self.inflight = 0
        self.tasks = set()
        self.state = "pending"
        self.t0 = None
        self.stop_flag = False
        self.seq = 0
        self.totals = {"arr": 0, "sent": 0, "ok": 0, "err": 0, "drop_cap": 0, "drop_sched": 0}
        self.sampler = None

    # ---- utilidades ---------------------------------------------------------
    def rel(self):
        return time.perf_counter() - self.t0

    def bucket(self, sec=None):
        if sec is None:
            sec = int(self.rel())
        b = self.buckets.get(sec)
        if b is None:
            b = self.buckets[sec] = new_bucket()
        return b

    def level(self, t):
        prev, acc = self.start_value, 0.0
        for st in self.stages:
            d = st["duration"]
            if t < acc + d:
                return prev + (st["target"] - prev) * ((t - acc) / d if d else 1)
            prev, acc = st["target"], acc + d
        return None

    def fill(self, s, ctx):
        return (s.replace("{tenant}", str(ctx["tenant"])).replace("{user}", str(ctx["user"]))
                 .replace("{seq}", str(ctx["seq"])).replace("{rand}", str(random.randint(0, 10**9))))

    def make_ctx(self, gid, user_fixed=False):
        if self.tn_count:
            r = random.Random(gid * 7919 + self.cfg.get("seed", 1)) if user_fixed else self.rng
            t = _pick(self.tn_cdf, r.random())
            user = f"{t}-u{gid}" if user_fixed else f"{t}-u{self.rng.randrange(max(1, int(self.tn.get('users_per_tenant', 10))))}"
            return {"tenant": f"t{t:04d}", "user": user, "seq": gid}
        return {"tenant": "", "user": f"u{gid}", "seq": gid}

    # ---- E/S HTTP -----------------------------------------------------------
    def _close(self, w):
        try:
            w.close()
        except Exception:
            pass
        self.cnt["conns"] -= 1

    async def _exchange(self, ep, ctx, phase):
        reused = False
        conn = self.pool.pop() if (self.pool and self.keepalive) else None
        conn_ms = None
        if conn is None:
            phase[0] = "connect"
            tc = time.perf_counter()
            r, w = await asyncio.open_connection(self.host, self.port, ssl=self.ssl)
            conn_ms = (time.perf_counter() - tc) * 1000
            self.cnt["conns"] += 1
        else:
            r, w = conn
            reused = True
        phase[0] = "io"
        path = self.base_path + self.fill(ep["path"], ctx)
        body = self.fill(ep["body"], ctx).encode() if ep.get("body") else b""
        h = {"Host": self.host, "User-Agent": "sentinela/1", "Accept": "*/*"}
        if self.tn_count:
            h[self.tn.get("tenant_header", "X-Tenant-Id")] = ctx["tenant"]
            h[self.tn.get("user_header", "X-User-Id")] = ctx["user"]
        for k, v in (ep.get("headers") or {}).items():
            h[k] = self.fill(str(v), ctx)
        if body:
            h["Content-Length"] = str(len(body))
        if not self.keepalive:
            h["Connection"] = "close"
        req = (f"{ep.get('method', 'GET')} {path} HTTP/1.1\r\n" +
               "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body
        try:
            w.write(req)
            await w.drain()
            self.cnt["tx"] += len(req)
            ts = time.perf_counter()
            first = await r.readexactly(1)
            ttfb = (time.perf_counter() - ts) * 1000
            head = first + await r.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            status = int(lines[0].split()[1])
            hd = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hd[k.strip().lower()] = v.strip().lower()
            nb = len(head)
            close_after = hd.get("connection") == "close" or lines[0].startswith("HTTP/1.0")
            if "chunked" in hd.get("transfer-encoding", ""):
                while True:
                    ln = await r.readline()
                    size = int(ln.split(b";")[0], 16)
                    nb += len(ln)
                    if size == 0:
                        nb += len(await r.readline())
                        break
                    await r.readexactly(size + 2)
                    nb += size + 2
            elif "content-length" in hd:
                n = int(hd["content-length"])
                if n:
                    await r.readexactly(n)
                nb += n
            elif status not in (204, 304):
                nb += len(await r.read())
                close_after = True
            self.cnt["rx"] += nb
        except BaseException:
            self._close(w)
            raise
        if close_after or not self.keepalive:
            self._close(w)
        else:
            self.pool.append((r, w))
        return status, ttfb, conn_ms, reused

    async def request(self, ep, ctx, intended=None):
        ts = time.perf_counter()
        late = (ts - intended) * 1000 if intended is not None else None
        phase = ["connect"]
        kind = status = ttfb = conn_ms = None
        self.inflight += 1
        try:
            for attempt in (0, 1):
                try:
                    status, ttfb, conn_ms, _ = await asyncio.wait_for(
                        self._exchange(ep, ctx, phase), self.timeout)
                    kind = None
                    break
                except asyncio.TimeoutError:
                    kind = "connect_timeout" if phase[0] == "connect" else "read_timeout"
                    break
                except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
                    if attempt == 0 and phase[0] == "io" and self.keepalive and \
                            time.perf_counter() - ts < 0.5:
                        continue  # conexão idle reciclada pelo servidor: 1 retry, como um navegador
                    kind = "reset"
                    break
                except ConnectionRefusedError:
                    kind = "connect_refused"
                    break
                except ssl.SSLError:
                    kind = "tls"
                    break
                except OSError as e:
                    kind = "port_exhaustion" if e.errno in PORT_EXHAUST else (
                        "dns" if "getaddrinfo" in str(e) else "connect_error" if phase[0] == "connect" else "io_error")
                    break
                except (ValueError, IndexError, asyncio.LimitOverrunError):
                    kind = "protocol"
                    break
        finally:
            self.inflight -= 1
        total = (time.perf_counter() - ts) * 1000
        if kind is None:
            exp = ep.get("expect")
            bad = (status not in exp) if exp else status >= 400
            if bad:
                kind = f"http_{status}" if status in (429, 502, 503, 504) else \
                    ("http_5xx" if status >= 500 else "http_4xx")
        self.record(ep["name"], ctx, total, ttfb, conn_ms, late, kind, status)

    def record(self, name, ctx, total, ttfb, conn_ms, late, kind, status):
        b = self.bucket()
        b["sent"] += 1
        self.totals["sent"] += 1
        e = b["ep"].get(name)
        if e is None:
            e = b["ep"][name] = {"n": 0, "err": 0, "resp": Hist(), "errs": {}}
        e["n"] += 1
        ts_ = None
        if self.tn_count:
            ts_ = self.tenant_stats.get(ctx["tenant"])
            if ts_ is None:
                ts_ = self.tenant_stats[ctx["tenant"]] = [0, 0, Hist()]
            ts_[0] += 1
        if kind is None:
            b["ok"] += 1
            self.totals["ok"] += 1
        else:
            b["err"] += 1
            self.totals["err"] += 1
            e["err"] += 1
            b["errs"][kind] = b["errs"].get(kind, 0) + 1
            e["errs"][kind] = e["errs"].get(kind, 0) + 1
            if ts_:
                ts_[1] += 1
        if status is not None:
            k = str(status)
            b["status"][k] = b["status"].get(k, 0) + 1
        if status is not None:  # só respostas reais entram nos histogramas de latência
            b["resp"].add(total)
            e["resp"].add(total)
            if ts_:
                ts_[2].add(total)
            if ttfb is not None:
                b["ttfb"].add(ttfb)
        elif kind in ("read_timeout", "connect_timeout"):
            b["resp"].add(total)   # timeout é latência >= limite: não pode sumir da cauda
            e["resp"].add(total)
        if conn_ms is not None:
            b["conn"].add(conn_ms)
        if late is not None:
            b["late"].add(max(late, 0.0))

    # ---- fluxos --------------------------------------------------------------
    async def run_flow(self, flow, ctx, intended=None):
        for i, step in enumerate(flow["steps"]):
            await self.request(self.eps[step], ctx, intended if i == 0 else None)
            if i + 1 < len(flow["steps"]) and flow.get("step_think"):
                await asyncio.sleep(self.rng.uniform(*flow["step_think"]))

    def pick_flow(self):
        return self.flows[_pick(self.flow_cdf, self.rng.random())]

    # ---- modelo aberto --------------------------------------------------------
    async def open_loop(self):
        nxt = 0.0
        while not self.stop_flag:
            now = self.rel()
            if now >= self.total:
                break
            lv = self.level(max(nxt, 0.0))
            if lv is None:
                break
            if lv < 1e-6:
                nxt = now + 0.05
                await asyncio.sleep(0.05)
                continue
            n = 0
            while nxt <= now and not self.stop_flag:
                lv = self.level(nxt)
                if lv is None:
                    break
                sec = int(nxt)
                n += 1
                b = self.bucket(sec)
                b["arr"] += 1
                self.totals["arr"] += 1
                if n > MAX_ARRIVALS_PER_TICK:
                    b["drop_sched"] += 1
                    self.totals["drop_sched"] += 1
                elif self.inflight >= self.max_inflight:
                    b["drop_cap"] += 1
                    self.totals["drop_cap"] += 1
                else:
                    self.seq += 1
                    ctx = self.make_ctx(self.seq * self.stride + self.widx)
                    t = asyncio.ensure_future(self.run_flow(self.pick_flow(), ctx, self.t0 + nxt))
                    self.tasks.add(t)
                    t.add_done_callback(self.tasks.discard)
                nxt += 1.0 / max(lv, 1e-6)
            await asyncio.sleep(0.002)

    # ---- modelo fechado -------------------------------------------------------
    async def vu(self, local_idx, stop_evt):
        gid = local_idx * self.stride + self.widx
        ctx = self.make_ctx(gid, user_fixed=True)
        th = self.cfg.get("think") or {"min": 0, "max": 0}
        while not stop_evt.is_set() and not self.stop_flag and self.rel() < self.total:
            ctx["seq"] += self.stride * 100000
            await self.run_flow(self.pick_flow(), ctx)
            d = self.rng.uniform(th.get("min", 0), th.get("max", 0))
            if d > 0:
                try:
                    await asyncio.wait_for(stop_evt.wait(), d)
                except asyncio.TimeoutError:
                    pass

    async def closed_loop(self):
        vus = []  # (evt, task)
        nxt_id = 0
        while not self.stop_flag:
            t = self.rel()
            lv = self.level(t)
            if lv is None:
                break
            want = int(round(lv))
            while len(vus) < want:
                evt = asyncio.Event()
                vus.append((evt, asyncio.ensure_future(self.vu(nxt_id, evt))))
                nxt_id += 1
            while len(vus) > want:
                evt, _ = vus.pop()
                evt.set()
            await asyncio.sleep(0.1)
        for evt, _ in vus:
            evt.set()
        await asyncio.gather(*[t for _, t in vus], return_exceptions=True)

    # ---- sondas de saúde ------------------------------------------------------
    async def lag_probe(self):
        while not self.stop_flag:
            t = time.perf_counter()
            await asyncio.sleep(0.05)
            lag = (time.perf_counter() - t - 0.05) * 1000
            self.bucket()["lag"].add(max(lag, 0.0))

    async def sampler_loop(self):
        self.sampler = health.Sampler()
        sec = 0
        while True:
            await asyncio.sleep(max(0.0, (sec + 1) - self.rel()))
            b = self.bucket(sec)
            lv = self.level(sec + 0.5)
            b["plan"] = float(lv or 0.0)
            lag = b["lag"]
            h = self.sampler.sample(self.cnt, lag.mx if lag.n else 0.0, lag.q(99) or 0.0)
            late99 = b["late"].q(99) if b["late"].n else 0.0
            plan = b["plan"]
            arr_ratio = ((b["arr"] - b["drop_sched"]) / plan) if (self.model == "open" and plan > 0) else None
            drop_ratio = (b["drop_sched"] / b["arr"]) if b["arr"] else 0.0
            # sec 0 = aquecimento (imports, 1ºs handshakes); depois de stop o achieved_ratio é artefato
            viol = [] if (sec == 0 or self.stop_flag) else health.judge_second(h, late99, drop_ratio, arr_ratio)
            h["violations"] = [{"k": k, "v": round(v, 3), "lim": lim} for k, v, lim in viol]
            h["compromised"] = bool(viol)
            self.healthlog[sec] = h
            sec += 1
            if self.stop_flag or sec > self.total + self.timeout + 2:
                break

    # ---- ciclo de vida --------------------------------------------------------
    async def run(self):
        self.state = "waiting"
        while time.time() < self.start_at and not self.stop_flag:
            await asyncio.sleep(min(0.05, max(0.0, self.start_at - time.time())))
        if self.stop_flag:
            self.state = "stopped"
            return
        health.improve_timer()
        self.t0 = time.perf_counter()
        self.state = "running"
        side = [asyncio.ensure_future(self.lag_probe()), asyncio.ensure_future(self.sampler_loop())]
        main = self.open_loop() if self.model == "open" else self.closed_loop()
        try:
            await main
        except asyncio.CancelledError:
            pass
        # drena o que ainda está em voo (até o timeout)
        end = time.perf_counter() + self.timeout + 0.5
        while self.tasks and time.perf_counter() < end and not self.stop_flag:
            await asyncio.sleep(0.05)
        for t in list(self.tasks):
            t.cancel()
        self.state = "stopped" if self.stop_flag else "finished"
        # fecha o último segundo de saúde
        await asyncio.sleep(1.2)
        self.stop_flag = True
        for t in side:
            t.cancel()
        for r, w in self.pool:
            self._close(w)
        self.pool.clear()

    def stop(self):
        self.stop_flag = True

    def snapshot(self, from_sec=0):
        cur = int(self.rel()) if self.t0 is not None and self.state == "running" else 10**9
        bks = {str(s): bucket_to_dict(b) for s, b in self.buckets.items() if from_sec <= s < cur}
        hl = {str(s): h for s, h in self.healthlog.items() if from_sec <= s}
        return {"buckets": bks, "health": hl}

    def tenant_snapshot(self):
        return {t: {"n": v[0], "err": v[1], "resp": v[2].to_dict()} for t, v in self.tenant_stats.items()}


# ---- helpers ------------------------------------------------------------------
def _cdf(weights):
    tot = float(sum(weights)) or 1.0
    acc, out = 0.0, []
    for w in weights:
        acc += w / tot
        out.append(acc)
    out[-1] = 1.0
    return out


def _pick(cdf, x):
    lo, hi = 0, len(cdf) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if cdf[mid] >= x:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _tenant_cdf(tn):
    n = int(tn["count"])
    dist = tn.get("distribution", "uniform")
    if dist == "zipf":
        w = [1.0 / (i + 1) ** float(tn.get("zipf_s", 1.1)) for i in range(n)]
    elif dist == "hot":
        hs = float(tn.get("hot_share", 0.5))
        w = [hs] + [(1 - hs) / max(n - 1, 1)] * (n - 1)
    else:
        w = [1.0] * n
    return _cdf(w)
