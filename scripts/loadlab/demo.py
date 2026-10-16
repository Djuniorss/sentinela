"""Demonstração SINTÉTICA — passa pelo mesmo pipeline de análise, mas é rotulada DEMO em todo lugar.

Cenários: db | generator | network | healthy. Servem para ver o dashboard e a lógica da perícia.
Nada aqui representa um sistema real.
"""
import math
import random
import time

from . import health
from .engine import new_bucket
from .hist import Hist

REGIONS = [("gru-1", "sa-east", 0.4), ("iad-1", "us-east", 0.4), ("fra-1", "eu-central", 0.2)]
EPS = [("health", "edge", 0.2, 4.0), ("catalog", "app", 0.3, 12.0), ("search", "cache", 0.15, 8.0), ("orders", "db", 0.35, 28.0)]
T, PEAK = 140, 1400.0


def _plan(t):
    if t < 80:
        return PEAK * t / 80
    if t < 125:
        return PEAK
    return PEAK * max(0, (T - t)) / 15


def build(scenario="db", seed=7):
    rnd = random.Random(seed)
    W = {}
    for wid, rg, share in REGIONS:
        W[wid] = {"meta": {"id": wid, "region": rg, "share": share, "status": "ok",
                           "rtt": {"ok": True, "rtt_p50_ms": {"sa-east": 18.0, "us-east": 120.0, "eu-central": 210.0}[rg]},
                           "facts": {"cpus": 4, "platform": "demo", "python": "demo"}, "planned_peak": PEAK * share},
                  "buckets": {}, "health": {}, "totals_reported": None, "tenants": {}}
    db_cap = 380.0   # req/s que o "banco" aguenta (cenário db)
    canary = []
    for t in range(T):
        plan = _plan(t)
        db_load = plan * 0.35
        for wid, rg, share in REGIONS:
            rate = plan * share
            b = new_bucket()
            n = int(round(rate * rnd.uniform(.97, 1.03)))
            b["plan"], b["arr"] = rate, n
            gen_sat = scenario == "generator" and wid == "gru-1" and t >= 62
            net_bad = scenario == "network" and wid == "iad-1" and t >= 66
            late_h = Hist()
            drops = 0
            if gen_sat:
                drops = int(n * min(0.35, 0.02 + (t - 62) * 0.01))
                n -= drops
                b["drop_sched"] = drops
            for _ in range(n):
                name, layer, wt, base = _pick(rnd)
                f = 1.0
                err = False
                if scenario == "db" and layer == "db" and db_load > db_cap:
                    over = db_load / db_cap
                    f = 1 + (over - 1) * 14
                    err = rnd.random() < min(0.6, (over - 1) * 0.9)
                elif scenario == "db" and layer in ("app", "cache", "edge") and db_load > db_cap:
                    f = 1.05
                if net_bad:
                    f *= 3.5
                lat = base * f * math.exp(rnd.gauss(0, 0.28))
                if gen_sat:
                    lat *= 2.4  # artefato: o gerador mede o próprio atraso
                    late_h.add(rnd.uniform(60, 400))
                rtt = {"sa-east": 18, "us-east": 120, "eu-central": 210}[rg]
                lat += rtt * (5 if net_bad else 1)
                cn = rtt * (4.5 if net_bad else 1.0) * math.exp(rnd.gauss(0, .15))
                if not err and lat > 4000:
                    err = True
                b["sent"] += 1
                e = b["ep"].setdefault(name, {"n": 0, "err": 0, "resp": Hist(), "errs": {}})
                e["n"] += 1
                b["resp"].add(lat)
                e["resp"].add(lat)
                b["ttfb"].add(max(lat - cn * 0.3, 1))
                if rnd.random() < 0.04:
                    b["conn"].add(cn)
                if err:
                    k = "http_503" if rnd.random() < 0.7 else "read_timeout"
                    b["err"] += 1
                    e["err"] += 1
                    b["errs"][k] = b["errs"].get(k, 0) + 1
                    b["status"]["503" if k == "http_503" else "200"] = b["status"].get("503" if k == "http_503" else "200", 0) + 1
                else:
                    b["ok"] += 1
                    b["status"]["200"] = b["status"].get("200", 0) + 1
            b["late"] = late_h
            W[wid]["buckets"][t] = b
            cpu = min(1.0, 0.1 + rate / 3000 + rnd.uniform(-.02, .02))
            lag = rnd.uniform(0.5, 4)
            if gen_sat:
                cpu, lag = 1.0, rnd.uniform(35, 140)
            hl = {"t": t, "cpu_proc_cores": round(cpu, 3), "cpu_sys_pct": round(18 + 60 * cpu * 0.8 + rnd.uniform(-2, 2), 1), "mem_pct": round(34 + rate / 80, 1),
                  "rx_bps": int(rate * 1800), "tx_bps": int(rate * 420), "net_prov": "demo", "conns_own": int(rate * 0.06 + 5),
                  "tcp_established": None, "tcp_time_wait": None, "ports_pct": round(rate / 220 + (30 if gen_sat else 0), 1), "ports_prov": "demo",
                  "fd_used": None, "fd_pct": None, "loop_lag_max_ms": round(lag * 1.4, 2), "loop_lag_p99_ms": round(lag, 2)}
            viol = health.judge_second(hl, late_h.q(99) if late_h.n else 0, drops / max(b["arr"], 1), None)
            hl["violations"] = [{"k": k, "v": round(v, 3), "lim": lim} for k, v, lim in viol]
            hl["compromised"] = bool(viol)
            W[wid]["health"][t] = hl
        base_c = 40 + rnd.uniform(-3, 3)
        bad_c = scenario == "db" and db_load > db_cap * 1.1 and rnd.random() < 0.0
        if t % 2 == 0:
            canary.append({"t": t, "ms": round(base_c * (1.0 if scenario != "db" or db_load <= db_cap else 1.15), 1), "ok": True, "status": 200})
    for w in W.values():
        w["totals_reported"] = None
    cfg = {"name": f"DEMO · cenário {scenario}", "model": "open",
           "target": {"base_url": "https://demo.invalid", "app_version": "demo-1.0", "verify_tls": True},
           "script_version": "demo", "endpoints": [{"name": n, "path": "/" + n, "layer": l, "weight": w_} for n, l, w_, _ in EPS],
           "stages": [{"duration": 80, "target": PEAK}, {"duration": 45, "target": PEAK}, {"duration": 15, "target": 0}],
           "workers": [{"id": w, "region": r, "share": s, "url": "demo"} for w, r, s in REGIONS],
           "criteria": {"pass": {"p95_ms": 900, "error_rate": 0.01}}, "start_value": 0, "timeout": 10,
           "tenants": {"count": 40, "distribution": "zipf"}}
    from .controller import normalize, config_hash
    cfg = normalize(cfg)
    inf = {"num_workers_planned": 3, "num_workers_effective": 3,
           "workers": [{"id": w, "region": r, "share": s, "status": "ok", "local": False, "planned_peak": PEAK * s,
                        "rtt": W[w]["meta"]["rtt"]} for w, r, s in REGIONS],
           "target": cfg["target"], "infra_notes": "DEMO sintética: 3 geradores simulados"}
    pv = sum(sum(b["arr"] for b in W[w]["buckets"].values()) for w in W)
    ten = {}
    for t_ in range(40):
        n = int(40000 / (t_ + 1) ** 1.1 / 3)
        h = Hist()
        for _ in range(min(n, 300)):
            h.add(30 * math.exp(rnd.gauss(0, .5)) * (4 if t_ == 7 else 1))
        ten[f"t{t_:04d}"] = {"n": n, "err": int(n * 0.01), "resp": h}
    W["gru-1"]["tenants"] = ten
    return {"cfg": cfg, "provenance": "demo", "workers": W, "canary": canary, "calibration": None,
            "run": {"id": f"DEMO-{scenario}-{time.strftime('%H%M%S')}", "name": cfg["name"], "started_at": "—", "ended_at": "—",
                    "duration_planned_s": T, "duration_actual_s": T, "status": "completed", "abort_reason": None,
                    "events": [{"t": 0, "level": "info", "msg": "dados sintéticos de demonstração"}],
                    "config_hash": config_hash(cfg), "tool": "sentinela demo", "target": cfg["target"]["base_url"],
                    "app_version": "demo-1.0", "script_version": "demo", "environment": "demo", "planned_total": None,
                    "planned_vs_generated": {"planned_iterations": round(sum(_plan(t) for t in range(T))), "arrivals_generated": pv}},
            "infra": inf, "clock": {"offsets_ms": {}}, "network": {}}


def _pick(rnd):
    r, acc = rnd.random(), 0.0
    for e in EPS:
        acc += e[2]
        if r <= acc:
            return e
    return EPS[-1]
