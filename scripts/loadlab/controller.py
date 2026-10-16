"""Controlador central: distribui carga, sincroniza, agrega, tolera falhas, entrega a perícia.

Distribuição sem duplicação acidental:
  - open  : cada worker recebe share_i × taxa (frações somam 1.0 exatamente).
  - closed: VUs por estágio repartidos por maior-resto (soma inteira exata).
  - IDs de usuário/iteração intercalados (id = local*N + índice_do_worker): nunca colidem.
Sincronização: offset de relógio medido por handshake (ponto médio do RTT) e start_at comum.
"""
import asyncio
import hashlib
import json
import os
import random
import secrets
import subprocess
import sys
import time
import urllib.parse

from . import analysis, report, safety
from .hist import Hist, merged

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- config -------------------------------------------------------------------
def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    return normalize(cfg)


def normalize(cfg):
    cfg.setdefault("name", "sentinela")
    cfg.setdefault("model", "open")
    if cfg["model"] not in ("open", "closed"):
        raise ValueError("model deve ser 'open' (taxa de chegada) ou 'closed' (VUs)")
    pf = cfg.get("profile")
    if pf and "stages" not in cfg:
        t = pf["target"]
        st = []
        if pf.get("ramp_up"):
            st.append({"name": "ramp-up", "duration": pf["ramp_up"], "target": t})
        st.append({"name": "steady-state", "duration": pf.get("steady", 60), "target": t})
        if pf.get("ramp_down"):
            st.append({"name": "ramp-down", "duration": pf["ramp_down"], "target": 0})
        cfg["stages"] = st
        cfg.setdefault("start_value", 0)
    if not cfg.get("stages"):
        raise ValueError("defina 'stages' ou 'profile'")
    for s in cfg["stages"]:
        if s["duration"] <= 0 or s["target"] < 0:
            raise ValueError("estágio inválido")
    if not cfg.get("endpoints"):
        raise ValueError("defina 'endpoints'")
    names = [e["name"] for e in cfg["endpoints"]]
    if len(set(names)) != len(names):
        raise ValueError("nomes de endpoint duplicados")
    for fl in cfg.get("flows", []):
        for st in fl["steps"]:
            if st not in names:
                raise ValueError(f"flow '{fl['name']}' referencia endpoint inexistente '{st}'")
    cfg.setdefault("timeout", 10)
    cfg.setdefault("workers", [{"local": 1, "region": "local"}])
    cfg.setdefault("criteria", {})
    cfg["_planned_peak"] = safety.peak(cfg)
    return cfg


def config_hash(cfg):
    c = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()[:12]


def _largest_remainder(total, shares):
    base = [int(total * s) for s in shares]
    rem = int(round(total)) - sum(base)
    order = sorted(range(len(shares)), key=lambda i: -(total * shares[i] - base[i]))
    for i in order[:max(rem, 0)]:
        base[i] += 1
    return base


def split_load(cfg, workers):
    """Gera a fatia de config de cada worker. Soma dos alvos == alvo total (exata)."""
    n = len(workers)
    tot_share = sum(w["share"] for w in workers)
    for w in workers:
        w["share"] = w["share"] / tot_share
    sh = [w["share"] for w in workers]
    out = []
    closed = cfg["model"] == "closed"
    start_vals = _largest_remainder(cfg.get("start_value", 0), sh) if closed else [cfg.get("start_value", 0) * s for s in sh]
    stage_vals = [(_largest_remainder(s["target"], sh) if closed else [s["target"] * x for x in sh]) for s in cfg["stages"]]
    for i, w in enumerate(workers):
        sl = {k: v for k, v in cfg.items() if k in ("model", "target", "endpoints", "flows", "think", "timeout",
                                                    "tenants", "keepalive", "max_inflight")}
        sl["stages"] = [{"duration": s["duration"], "target": stage_vals[j][i]} for j, s in enumerate(cfg["stages"])]
        sl["start_value"] = start_vals[i]
        sl["stride"], sl["worker_index"] = n, i
        sl["seed"] = int(cfg.get("seed", 1)) * 1000 + i
        # concorrência máxima por worker (modelo aberto): 'max_vus' total dividido
        if "max_vus" in cfg:
            sl["max_inflight"] = max(1, int(round(cfg["max_vus"] * w["share"])))
        w["slice"] = sl
        w["planned_peak"] = max([s["target"] for s in sl["stages"]] + [sl["start_value"]])
    # checagem de duplicação/omissão
    for j in range(len(cfg["stages"])):
        s = sum(w["slice"]["stages"][j]["target"] for w in workers)
        if abs(s - cfg["stages"][j]["target"]) > 1e-6 * max(1, cfg["stages"][j]["target"]):
            raise AssertionError(f"distribuição inconsistente no estágio {j}: {s} != {cfg['stages'][j]['target']}")
    return workers


# ---- RPC minimalista --------------------------------------------------------------
async def rpc(w, method, path, body=None, timeout=5.0):
    u = urllib.parse.urlsplit(w["url"])
    data = json.dumps(body).encode() if body is not None else b""
    req = (f"{method} {path} HTTP/1.1\r\nHost: {u.hostname}\r\nX-LoadLab-Token: {w['token']}\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data

    async def go():
        r, wr = await asyncio.open_connection(u.hostname, u.port)
        wr.write(req)
        await wr.drain()
        raw = await r.read()
        wr.close()
        head, _, b = raw.partition(b"\r\n\r\n")
        code = int(head.split()[1])
        if code != 200:
            raise RuntimeError(f"{path} -> HTTP {code}: {b[:200]!r}")
        return json.loads(b)
    return await asyncio.wait_for(go(), timeout)


# ---- resolver workers -----------------------------------------------------------------
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def resolve_workers(cfg, procs):
    out = []
    for spec in cfg["workers"]:
        if "local" in spec:
            n = int(spec["local"])
            for i in range(n):
                port = _free_port()
                tok = secrets.token_hex(8)
                wid = spec.get("id", "local") + (f"-{i+1}" if n > 1 or True else "")
                p = subprocess.Popen([sys.executable, os.path.join(HERE, "loadlab.py"), "worker", "--port", str(port),
                                      "--token", tok, "--id", wid, "--region", spec.get("region", "local")],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                procs.append(p)
                out.append({"id": wid, "region": spec.get("region", "local"), "url": f"http://127.0.0.1:{port}",
                            "token": tok, "share": spec.get("share", 1.0) / n, "local": True})
        else:
            tok = spec.get("token") or os.environ.get(spec.get("token_env", "LOADLAB_TOKEN"), "")
            out.append({"id": spec["id"], "region": spec.get("region", "?"), "url": spec["url"], "token": tok,
                        "share": spec.get("share", 1.0), "local": False})
    return out


# ---- execução ---------------------------------------------------------------------------
class Run:
    def __init__(self, cfg, outdir, confirm=None, calibrate=False, log=print):
        self.cfg, self.outdir, self.confirm = cfg, outdir, confirm
        self.do_cal, self.log = calibrate, log
        self.events = []
        self.procs = []
        self.W = {}
        self.canary = []
        self.stop_reason = None
        self.t_wall0 = None

    def ev(self, level, msg):
        t = round(time.time() - self.t_wall0, 1) if self.t_wall0 else 0
        self.events.append({"t": t, "level": level, "msg": msg})
        self.log(f"  [{level}] {msg}")

    async def execute(self):
        cfg = self.cfg
        ok, msgs = safety.check(cfg, self.confirm)
        for m in msgs:
            self.log(("  ✓ " if ok else "  ✗ ") + m)
        if not ok:
            raise SystemExit("RECUSADO pelo portão de autorização (nada foi enviado ao alvo).")
        self.t_wall0 = time.time()
        started_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        workers = resolve_workers(cfg, self.procs)
        try:
            await self._boot(workers)
            alive = [w for w in workers if w["status"] == "ok"]
            policy = cfg.get("on_worker_unavailable", "abort")
            dead = [w for w in workers if w["status"] != "ok"]
            if dead:
                self.ev("error", f"workers indisponíveis no início: {', '.join(w['id'] for w in dead)}")
                if policy == "abort" or not alive:
                    for w in dead:
                        self.W[w["id"]] = _wrec(w)
                    return await self._finish(started_iso, workers, status="failed",
                                              reason="worker(s) indisponível(is) no pré-voo (política: abort)")
                self.ev("warn", "redistribuindo explicitamente a parcela dos indisponíveis (política: redistribute)")
                for w in dead:
                    self.W[w["id"]] = _wrec(w)
            for w in alive:
                self.W[w["id"]] = _wrec(w)
            split_load(cfg, alive)
            if self.do_cal or cfg.get("preflight", {}).get("calibrate"):
                await self._calibrate(alive)
            # --- início sincronizado
            lead = 4.0
            start = time.time() + lead
            self.start_at = start
            for w in alive:
                await rpc(w, "POST", "/start", {"config": w["slice"], "start_at": start + w["offset"]}, timeout=10)
            self.log(f"  ▶ {len(alive)} worker(s) iniciam juntos em {lead:.0f}s "
                     f"(offsets de relógio: {', '.join(f'{w['id']}={w['offset']*1000:+.0f}ms' for w in alive)})")
            planned = sum(s["duration"] for s in cfg["stages"])
            await self._monitor(alive, start, planned)
            return await self._finish(started_iso, workers, status=("aborted" if self.stop_reason else "completed"),
                                      reason=self.stop_reason)
        finally:
            for p in self.procs:
                try:
                    p.terminate()
                except Exception:
                    pass

    async def _boot(self, workers):
        # espera workers locais subirem
        for w in workers:
            w["status"], w["offset"], w["facts"], w["rtt"] = "down", 0.0, {}, None
            for _ in range(60):
                try:
                    h = await rpc(w, "GET", "/hello", timeout=2)
                    w["facts"], w["host"], w["os"] = h["facts"], h["host"], h["os"]
                    w["status"] = "ok"
                    break
                except Exception as e:
                    w["err"] = repr(e)
                    await asyncio.sleep(0.25 if w["local"] else 0.5) if w["local"] else None
                    if not w["local"]:
                        break
            if w["status"] != "ok":
                continue
            # offset de relógio: melhor de 7 (menor RTT)
            best = None
            for _ in range(7):
                t0 = time.time()
                r = await rpc(w, "GET", "/time", timeout=3)
                t1 = time.time()
                rtt = t1 - t0
                if best is None or rtt < best[0]:
                    best = (rtt, r["t"] - (t0 + t1) / 2)
            w["offset"], w["clock_rtt_ms"] = best[1], best[0] * 1000
            try:
                w["rtt"] = await rpc(w, "POST", "/probe", {"base_url": self.cfg["target"]["base_url"], "n": 8}, timeout=20)
                if not w["rtt"].get("ok"):
                    self.ev("warn", f"{w['id']}: sem rota TCP até o alvo ({w['rtt'].get('error')})")
            except Exception as e:
                self.ev("warn", f"{w['id']}: probe de RTT falhou ({e!r})")
            self.log(f"  ✓ {w['id']} [{w['region']}] {w['host']} · {w['facts'].get('cpus')} CPUs · "
                     f"RTT base {w['rtt'] and w['rtt'].get('rtt_p50_ms')} ms · relógio {w['offset']*1000:+.1f} ms")

    async def _calibrate(self, alive):
        self.log("  ⚙ Régua: calibrando os geradores contra um alvo nulo…")
        peak = max(w["planned_peak"] for w in alive) if self.cfg["model"] == "open" else 0
        res = await asyncio.gather(*[rpc(w, "POST", "/calibrate", {"max_rate": max(peak * 3, 1000)}, timeout=300) for w in alive],
                                   return_exceptions=True)
        self.calibration = {}
        for w, r in zip(alive, res):
            if isinstance(r, Exception):
                self.ev("warn", f"{w['id']}: calibração falhou ({r!r})")
                continue
            w["calibration"] = r
            self.calibration[w["id"]] = r
            self.log(f"    {w['id']}: teto ≈ {r['ceiling_rps']:g} rps (seguro ≤ {r['safe_rps']:g}) — {r['stopped_because']}")
            if self.cfg["model"] == "open" and w["planned_peak"] > r["safe_rps"]:
                msg = (f"{w['id']}: carga planejada {w['planned_peak']:.0f} rps > teto seguro calibrado {r['safe_rps']:g} rps "
                       "— o gerador tende a mentir")
                if self.cfg.get("calibration_policy", "warn") == "refuse":
                    raise SystemExit("RECUSADO: " + msg)
                self.ev("warn", msg)

    async def _canary_loop(self, stop):
        url = self.cfg.get("canary_url")
        if not url:
            return
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        import ssl
        while not stop.is_set():
            t0 = time.perf_counter()
            ok, ms, st = False, None, None
            try:
                async def go():
                    r, w = await asyncio.open_connection(u.hostname, port, ssl=ssl.create_default_context() if u.scheme == "https" else None)
                    w.write(f"GET {u.path or '/'}{'?' + u.query if u.query else ''} HTTP/1.1\r\nHost: {u.hostname}\r\nConnection: close\r\n\r\n".encode())
                    await w.drain()
                    raw = await r.read()
                    w.close()
                    return int(raw.split(b" ", 2)[1])
                st = await asyncio.wait_for(go(), 8)
                ms = (time.perf_counter() - t0) * 1000
                ok = st < 500
            except Exception:
                pass
            self.canary.append({"t": round(time.time() - self.start_at, 1), "ms": None if ms is None else round(ms, 1),
                                "ok": ok, "status": st})
            try:
                await asyncio.wait_for(stop.wait(), 2)
            except asyncio.TimeoutError:
                pass

    async def _poll(self, w):
        rec = self.W[w["id"]]
        try:
            d = await rpc(w, "GET", f"/data?from={max(rec['cursor'] - 2, 0)}", timeout=6)
        except Exception as e:
            rec["fails"] += 1
            if rec["fails"] == 3 and not rec["lost_at"]:
                rec["lost_at"] = round(time.time() - self.start_at, 1)
                rec["meta"]["status"] = "indisponível durante o teste"
                self.ev("error", f"worker {w['id']} INDISPONÍVEL (3 falhas seguidas) — resultados parciais; "
                                 f"parcela de carga dele não é redistribuída")
            return None
        if rec["fails"] >= 3:
            self.ev("warn", f"worker {w['id']} voltou")
            rec["meta"]["status"] = "ok"
            rec["lost_at"] = None
        rec["fails"] = 0
        for s, b in d["buckets"].items():
            rec["buckets"][int(s)] = _hydrate(b)
        for s, h in d["health"].items():
            rec["health"][int(s)] = h
        if rec["buckets"]:
            rec["cursor"] = max(rec["cursor"], max(rec["buckets"]))
        rec["totals_reported"] = d.get("totals")
        rec["state"] = d.get("state")
        if "tenants" in d:
            rec["tenants"] = {t: {"n": v["n"], "err": v["err"], "resp": Hist.from_dict(v["resp"])} for t, v in d["tenants"].items()}
        return d

    def _abort_check(self, alive):
        ab = (self.cfg.get("criteria", {}) or {}).get("abort") or {}
        if not ab:
            return None
        win = int(ab.get("window_s", 10))
        horizon = min((max(self.W[w["id"]]["buckets"], default=0) for w in alive), default=0)
        secs = range(max(0, horizon - win), horizon)
        sent = err = 0
        h = Hist()
        comp = 0
        total_w = 0
        for w in alive:
            rec = self.W[w["id"]]
            wc = False
            for s in secs:
                b = rec["buckets"].get(s)
                if b:
                    sent += b["sent"]
                    err += b["err"]
                    h.merge(b["resp"])
                hh = rec["health"].get(s)
                if hh and hh.get("compromised"):
                    wc = True
            total_w += 1
            comp += 1 if wc else 0
        if sent >= ab.get("min_requests", 200):
            if ab.get("error_rate") is not None and err / sent > ab["error_rate"]:
                return f"critério de interrupção: erros {100*err/sent:.1f}% > {100*ab['error_rate']:.1f}% nos últimos {win}s"
            if ab.get("p95_ms") and h.n and h.q(95) > ab["p95_ms"]:
                return f"critério de interrupção: P95 {h.q(95):.0f} ms > {ab['p95_ms']} ms nos últimos {win}s"
        if ab.get("generator_compromised_frac") is not None and total_w and comp / total_w >= ab["generator_compromised_frac"] \
                and horizon > win:
            return f"critério de interrupção: {comp}/{total_w} geradores comprometidos — resultado inválido, parando"
        cf = ab.get("canary_failures", 3)
        tail = self.canary[-cf:]
        if self.cfg.get("canary_url") and len(tail) >= cf and all(not c["ok"] for c in tail):
            return f"critério de interrupção: canário independente falhou {cf}× seguidas (alvo possivelmente fora do ar)"
        return None

    async def _monitor(self, alive, start, planned):
        stop = asyncio.Event()
        can = asyncio.ensure_future(self._canary_loop(stop))
        end_by = start + planned + float(self.cfg.get("timeout", 10)) + 25
        last_print = 0
        try:
            while True:
                await asyncio.sleep(1.0)
                now = time.time()
                if now < start:
                    continue
                res = await asyncio.gather(*[self._poll(w) for w in alive])
                states = [self.W[w["id"]].get("state") for w in alive]
                if now - last_print >= 5:
                    last_print = now
                    self._progress(alive, now - start, planned)
                if not self.stop_reason:
                    r = self._abort_check(alive)
                    if r:
                        self.stop_reason = r
                        self.ev("error", r)
                        for w in alive:
                            try:
                                await rpc(w, "POST", "/stop", timeout=3)
                            except Exception:
                                pass
                done = all((st in ("finished", "stopped")) or self.W[w["id"]]["lost_at"] for st, w in zip(states, alive))
                if done or now > end_by:
                    if now > end_by:
                        self.ev("warn", "tempo limite de espera excedido; encerrando com o que foi coletado")
                    break
        except KeyboardInterrupt:
            self.stop_reason = "interrompido pelo operador (Ctrl-C)"
            self.ev("warn", self.stop_reason)
            for w in alive:
                try:
                    await rpc(w, "POST", "/stop", timeout=3)
                except Exception:
                    pass
            await asyncio.sleep(2)
        finally:
            stop.set()
            await can
        for _ in range(3):  # coleta final
            await asyncio.sleep(1.5)
            await asyncio.gather(*[self._poll(w) for w in alive])

    def _progress(self, alive, rel, planned):
        sent = err = 0
        for w in alive:
            rec = self.W[w["id"]]
            if rec["totals_reported"]:
                sent += rec["totals_reported"]["sent"]
                err += rec["totals_reported"]["err"]
        comp = [w["id"] for w in alive if (self.W[w["id"]]["health"] and
                                          self.W[w["id"]]["health"][max(self.W[w["id"]]["health"])].get("compromised"))]
        self.log(f"  t={rel:5.0f}/{planned}s  req={sent}  erros={err} ({(100*err/sent if sent else 0):.1f}%)"
                 + (f"  ⚠ gerador comprometido: {', '.join(comp)}" if comp else ""))

    async def _finish(self, started_iso, workers, status, reason):
        cfg = self.cfg
        for w in workers:
            rec = self.W.setdefault(w["id"], _wrec(w))
            rec["meta"].update({"share": w.get("share"), "rtt": w.get("rtt"), "region": w["region"],
                                "host": w.get("host"), "os": w.get("os"), "facts": w.get("facts"),
                                "clock_offset_ms": round(w.get("offset", 0) * 1000, 2),
                                "planned_peak": w.get("planned_peak")})
            if w["status"] != "ok":
                rec["meta"]["status"] = "indisponível no pré-voo"
        lost = [w for w, r in self.W.items() if r["lost_at"] or r["meta"].get("status") not in (None, "ok")]
        if status == "completed" and lost:
            status = "partial"
        ended = time.time()
        pv_gen, prev = 0.0, cfg.get("start_value", 0)  # área planejada (trapézios)
        for s_ in cfg["stages"]:
            pv_gen += (prev + s_["target"]) / 2 * s_["duration"]
            prev = s_["target"]
        col = {
            "cfg": cfg, "provenance": "measured", "workers": self.W, "canary": self.canary,
            "calibration": _pick_cal(getattr(self, "calibration", None)),
            "clock": {"method": "handshake de ponto médio; melhor de 7 amostras",
                      "offsets_ms": {w["id"]: round(w.get("offset", 0) * 1000, 2) for w in workers}},
            "network": {w["id"]: w.get("rtt") for w in workers},
            "run": {"id": f"{time.strftime('%Y%m%d-%H%M%S')}-{config_hash(cfg)}", "name": cfg["name"],
                    "started_at": started_iso, "ended_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "duration_planned_s": sum(s["duration"] for s in cfg["stages"]),
                    "duration_actual_s": round(ended - self.t_wall0, 1),
                    "status": status, "abort_reason": reason, "events": self.events,
                    "config_hash": config_hash(cfg),
                    "app_version": cfg["target"].get("app_version"), "script_version": cfg.get("script_version"),
                    "environment": (cfg.get("authorization") or {}).get("environment") or ("local" if safety.is_local(urllib.parse.urlsplit(cfg['target']['base_url']).hostname or '') else None),
                    "target": cfg["target"]["base_url"], "tool": "sentinela 1.0.0",
                    "planned_total": None, "planned_vs_generated": None},
            "infra": {"num_workers_planned": len(workers),
                      "num_workers_effective": sum(1 for w in workers if w["status"] == "ok" and not self.W[w["id"]]["lost_at"]),
                      "workers": [{"id": w["id"], "region": w["region"], "host": w.get("host"), "os": w.get("os"),
                                   "facts": w.get("facts"), "share": w.get("share"), "rtt": w.get("rtt"),
                                   "clock_offset_ms": round(w.get("offset", 0) * 1000, 2),
                                   "planned_peak": w.get("planned_peak"),
                                   "status": self.W[w["id"]]["meta"].get("status") or "ok",
                                   "lost_at": self.W[w["id"]]["lost_at"], "local": w["local"]} for w in workers],
                      "target": cfg["target"], "infra_notes": cfg.get("infra_notes", "")},
        }
        # planejado vs. gerado
        if cfg["model"] == "open":
            plan_total = pv_gen
            made = sum(sum(b["arr"] for b in r["buckets"].values()) for r in self.W.values())
            sent = sum(sum(b["sent"] for b in r["buckets"].values()) for r in self.W.values())
            col["run"]["planned_total"] = round(plan_total)
            col["run"]["planned_vs_generated"] = {"planned_iterations": round(plan_total), "arrivals_generated": made,
                                                  "requests_completed": sent,
                                                  "generated_pct": round(100 * made / plan_total, 2) if plan_total else None}
        else:
            col["run"]["planned_vs_generated"] = {"planned_vu_seconds": round(pv_gen),
                                                  "requests_completed": sum(sum(b["sent"] for b in r["buckets"].values()) for r in self.W.values())}
        m = analysis.analyze(col)
        paths = report.write_all(m, self.outdir, cfg=cfg)
        return m, paths


def _hydrate(b):
    for k in ("resp", "ttfb", "conn", "late", "lag"):
        b[k] = Hist.from_dict(b[k])
    for e in b["ep"].values():
        e["resp"] = Hist.from_dict(e["resp"])
    return b


def _wrec(w):
    return {"meta": {"id": w["id"], "region": w["region"], "status": None}, "buckets": {}, "health": {}, "cursor": 0,
            "fails": 0, "lost_at": None, "totals_reported": None, "state": None, "tenants": {}}


def _pick_cal(c):
    if not c:
        return None
    best = min(c.values(), key=lambda x: x["ceiling_rps"])
    return dict(best, per_worker={k: {"ceiling_rps": v["ceiling_rps"], "safe_rps": v["safe_rps"]} for k, v in c.items()})
