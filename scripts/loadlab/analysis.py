"""Consolida dados dos workers e emite a PERÍCIA: de quem é a limitação?

Princípios (invioláveis):
  1. Percentil global = merge de histogramas. Nunca média de percentis.
  2. Saturação do alvo só é afirmada com o gerador provadamente saudável nas janelas usadas.
  3. Camada culpada (borda/app/banco/rede/gerador) vem de EVIDÊNCIA diferencial; sem
     evidência -> "não determinado", dizendo o que falta medir.
  4. Todo número carrega procedência: measured | estimated | demo | ingested.
"""
import math
import statistics

from .hist import Hist, merged

WIN = 5  # segundos por janela de análise
CONSEQ_KEYS = {"ports_pct", "fd_pct", "drop_ratio", "achieved_ratio"}  # efeitos possíveis de alvo lento


def _H(d):
    return Hist.from_dict(d) if isinstance(d, dict) else (d or Hist())


def _r(x, n=2):
    return None if x is None else round(x, n)


def _q(h, p):
    return _r(h.q(p), 2) if h.n else None


# =============================================================================
def analyze(col):
    cfg, W = col["cfg"], col["workers"]
    prov = col.get("provenance", "measured")
    model = cfg["model"]
    unit = "req/s" if model == "open" else "VUs"
    health_known = col.get("health_measured", True)

    # ---- pré-processa baldes --------------------------------------------------
    wids = list(W)
    shares = {w: W[w]["meta"].get("share", 1.0 / max(len(wids), 1)) for w in wids}
    secs = sorted({s for w in wids for s in W[w]["buckets"]})
    if not secs:
        return _empty(col, "Nenhuma amostra recebida de nenhum worker.")
    last = max(secs)
    peak_plan = 0.0

    # por worker-segundo
    wsec = {w: {} for w in wids}
    for w in wids:
        for s, b in W[w]["buckets"].items():
            h = W[w]["health"].get(s)
            comp = None if (h is None and health_known) else bool(h and h.get("compromised"))
            wsec[w][s] = {"b": b, "h": h, "comp": comp}

    G = {}      # segundo -> agregado global (bruto)
    GC = {}     # segundo -> agregado limpo (só worker-segundos sem violação)
    EPS = {}    # endpoint -> {sec: {"raw":Hist,"clean":Hist,"n":,"err":}}
    ep_layer = {e["name"]: e.get("layer", "unknown") for e in cfg["endpoints"]}
    for s in range(0, last + 1):
        g = {"plan": 0.0, "arr": 0, "sent": 0, "ok": 0, "err": 0, "drop_cap": 0, "drop_sched": 0,
             "tx": 0, "rx": 0, "resp": Hist(), "ttfb": Hist(), "conn": Hist(), "late": Hist(),
             "nw": 0, "ncomp": 0, "comp_share": 0.0, "errs": {}, "status": {}}
        c = {"sent": 0, "ok": 0, "err": 0, "resp": Hist(), "ttfb": Hist(), "conn": Hist(), "errs": {}, "status": {}}
        for w in wids:
            x = wsec[w].get(s)
            if not x:
                continue
            b = x["b"]
            g["nw"] += 1
            for k in ("plan", "arr", "sent", "ok", "err", "drop_cap", "drop_sched", "tx", "rx"):
                g[k] += b.get(k, 0)
            for k in ("resp", "ttfb", "conn", "late"):
                g[k].merge(b.get(k))
            for k in ("errs", "status"):
                for kk, v in b.get(k, {}).items():
                    g[k][kk] = g[k].get(kk, 0) + v
            bad = x["comp"] is not False  # True ou None(sem saúde) => não confiável
            if bad:
                g["ncomp"] += 1
                g["comp_share"] += shares[w]
            else:
                for k in ("sent", "ok", "err"):
                    c[k] += b.get(k, 0)
                for k in ("resp", "ttfb", "conn"):
                    c[k].merge(b.get(k))
                for k in ("errs", "status"):
                    for kk, v in b.get(k, {}).items():
                        c[k][kk] = c[k].get(kk, 0) + v
            for en, e in b.get("ep", {}).items():
                rec = EPS.setdefault(en, {}).setdefault(s, {"raw": Hist(), "clean": Hist(), "n": 0, "err": 0, "cn": 0, "cerr": 0})
                he = _H(e["resp"])
                rec["raw"].merge(he)
                rec["n"] += e["n"]
                rec["err"] += e["err"]
                if not bad:
                    rec["clean"].merge(he)
                    rec["cn"] += e["n"]
                    rec["cerr"] += e["err"]
        G[s], GC[s] = g, c
        peak_plan = max(peak_plan, g["plan"])
    planned_total = float(cfg.get("_planned_peak", peak_plan)) or peak_plan

    # ---- séries ----------------------------------------------------------------
    series = []
    for s in range(0, last + 1):
        g = G[s]
        series.append({
            "t": s, "plan": _r(g["plan"], 2), "arr": g["arr"], "sent": g["sent"], "ok": g["ok"], "err": g["err"],
            "drop_cap": g["drop_cap"], "drop_sched": g["drop_sched"],
            "p50": _q(g["resp"], 50), "p90": _q(g["resp"], 90), "p95": _q(g["resp"], 95), "p99": _q(g["resp"], 99),
            "cp95": _q(GC[s]["resp"], 95),
            "ttfb_p95": _q(g["ttfb"], 95), "conn_p50": _q(g["conn"], 50), "conn_p95": _q(g["conn"], 95),
            "late_p99": _q(g["late"], 99), "tx": g["tx"], "rx": g["rx"],
            "nw": g["nw"], "ncomp": g["ncomp"], "comp_share": _r(g["comp_share"], 3),
            "errs": g["errs"], "status": g["status"]})

    wseries = {}
    for w in wids:
        arr = []
        for s in range(0, last + 1):
            x = wsec[w].get(s)
            if not x:
                continue
            b, h = x["b"], x["h"] or {}
            r = _H(b["resp"])
            arr.append({"t": s, "plan": _r(b.get("plan", 0), 2), "sent": b["sent"], "err": b["err"],
                        "drop_sched": b.get("drop_sched", 0), "drop_cap": b.get("drop_cap", 0),
                        "p50": _q(r, 50), "p95": _q(r, 95), "p99": _q(r, 99),
                        "late_p99": _q(_H(b["late"]), 99), "ttfb_p95": _q(_H(b["ttfb"]), 95),
                        "conn_p95": _q(_H(b["conn"]), 95),
                        "cpu_proc": h.get("cpu_proc_cores"), "cpu_sys": h.get("cpu_sys_pct"),
                        "mem": h.get("mem_pct"), "rx_bps": h.get("rx_bps"), "tx_bps": h.get("tx_bps"),
                        "conns": h.get("conns_own"), "tw": h.get("tcp_time_wait"),
                        "ports": h.get("ports_pct"), "fd": h.get("fd_pct"),
                        "lag99": h.get("loop_lag_p99_ms"),
                        "comp": x["comp"], "viol": [v["k"] for v in h.get("violations", [])]})
        wseries[w] = arr

    # ---- janelas ---------------------------------------------------------------
    wins = []
    for k in range(0, last // WIN + 1):
        r = [s for s in range(k * WIN, min((k + 1) * WIN, last + 1))]
        if not r:
            continue
        cl = merged(GC[s]["resp"] for s in r)
        raw = merged(G[s]["resp"] for s in r)
        n_all = sum(G[s]["sent"] for s in r)
        n_cl = sum(GC[s]["sent"] for s in r)
        errs = sum(G[s]["err"] for s in r)
        cerr = sum(GC[s]["err"] for s in r)
        ncomp = sum(G[s]["ncomp"] for s in r)
        nw = sum(G[s]["nw"] for s in r)
        wins.append({
            "k": k, "t0": r[0], "t1": r[-1] + 1, "plan": sum(G[s]["plan"] for s in r) / len(r),
            "rps": sum(G[s]["ok"] for s in r) / len(r), "sent": n_all,
            "err_rate": errs / n_all if n_all else 0.0, "cerr_rate": cerr / n_cl if n_cl else None,
            "n_clean": n_cl, "p95": _q(raw, 95), "cp95": _q(cl, 95), "cp50": _q(cl, 50), "cp99": _q(cl, 99),
            "ttfb95": _q(merged(GC[s]["ttfb"] for s in r), 95),
            "conn95": _q(merged(GC[s]["conn"] for s in r), 95),
            "trusted": (1 - ncomp / nw) if nw else 0.0,
            "comp_viol": sorted({x["k"] for w in wids for s in r
                                 for x in ((wsec[w].get(s) or {}).get("h") or {}).get("violations", [])}),
            "drops": sum(G[s]["drop_sched"] for s in r), "dropcap": sum(G[s]["drop_cap"] for s in r),
            "errs": _sum_dict(G[s]["errs"] for s in r), "status": _sum_dict(G[s]["status"] for s in r)})

    peak_win_plan = max((w["plan"] for w in wins), default=0.0)

    # ---- regiões ---------------------------------------------------------------
    regions = {}
    for w in wids:
        rg = W[w]["meta"].get("region") or "?"
        R = regions.setdefault(rg, {"region": rg, "workers": [], "resp": Hist(), "conn": Hist(), "ttfb": Hist(),
                                    "n": 0, "err": 0, "series": {}, "cseries": {}, "rtt": []})
        R["workers"].append(w)
        if W[w]["meta"].get("rtt"):
            R["rtt"].append(W[w]["meta"]["rtt"].get("rtt_p50_ms"))
        for s, x in wsec[w].items():
            b = x["b"]
            R["resp"].merge(b["resp"])
            R["conn"].merge(b["conn"])
            R["ttfb"].merge(b["ttfb"])
            R["n"] += b["sent"]
            R["err"] += b["err"]
            ss = R["series"].setdefault(s, Hist())
            ss.merge(b["resp"])
            if x["comp"] is False:
                R["cseries"].setdefault(s, Hist()).merge(b["resp"])
    # ---- linha de base e joelho ----------------------------------------------
    first_half = next((w["k"] for w in wins if w["plan"] >= 0.5 * peak_win_plan), len(wins))  # baseline só na SUBIDA (ramp-down tardio não conta)
    base_wins = [w for w in wins if 1 <= w["k"] < first_half and w["plan"] > 0 and w["plan"] <= 0.25 * peak_win_plan and w["n_clean"] >= 30]
    base_quality = "baixa carga (≤25% do pico)"
    if not base_wins and len(wins) >= 3:
        base_wins = [w for w in wins[1:3] if w["n_clean"] >= 30]
        base_quality = "primeiros segundos (sem rampa de baixa carga) — referência fraca"
    bsecs = {s for w in base_wins for s in range(w["t0"], w["t1"])}
    base_h = merged(GC[s]["resp"] for s in bsecs)
    base_p95 = base_h.q(95) if base_h.n else None
    bn = sum(GC[s]["sent"] for s in bsecs)
    base_err = (sum(GC[s]["err"] for s in bsecs) / bn) if bn else 0.0
    crit = cfg.get("criteria", {}).get("pass", {}) or {}
    lat_thr = None
    if base_p95:
        lat_thr = max(3 * base_p95, base_p95 + 50)
    if lat_thr is None and crit.get("p95_ms"):
        lat_thr = crit["p95_ms"]  # sem baseline: só o SLO declarado serve de régua (referência fraca)
    err_thr = max(0.02, base_err + 0.01, crit.get("error_rate", 0) or 0)

    def degraded(w):
        if w["trusted"] < 0.9 or w["n_clean"] < 30:
            return None  # indeterminado
        d = (lat_thr is not None and w["cp95"] is not None and w["cp95"] > lat_thr) or \
            ((w["cerr_rate"] or 0) > err_thr)
        return bool(d)

    for w in wins:
        w["degraded"] = degraded(w)
        w["raw_degraded"] = bool((lat_thr is not None and w["p95"] is not None and w["p95"] > lat_thr) or w["err_rate"] > err_thr)

    knee = None
    elig = [w for w in wins if w["plan"] >= 0.2 * peak_win_plan]
    for i, w in enumerate(elig):
        nxt = elig[i + 1] if i + 1 < len(elig) else None
        if w["degraded"] and (nxt is None or nxt["degraded"] is not False):
            knee = w
            break
    # joelho "sujo": parece degradação, mas gerador estava comprometido
    tainted = [w for w in elig if w["raw_degraded"] and w["trusted"] < 0.9]
    first_taint = tainted[0] if tainted else None

    # joelho REGIONAL: só uma minoria de regiões degrada (rota/PoP). Se TODAS degradam, é causa comum.
    reg_knee = None
    if len(regions) >= 2:
        hits = {}
        for rg, R in regions.items():
            bh = merged(R["cseries"][s] for s in bsecs if s in R["cseries"])
            if bh.n < 30 or not bh.q(95):
                continue
            thr = max(3 * bh.q(95), bh.q(95) + 50)
            hit, dmax = [], 0.0
            for w in elig:
                hh = merged(R["cseries"][s] for s in range(w["t0"], w["t1"]) if s in R["cseries"])
                if hh.n >= 30:
                    dmax = max(dmax, hh.q(95) - bh.q(95))
                    if hh.q(95) > thr:
                        hit.append(w)
            hits[rg] = (hit, bh.q(95), thr, dmax)
        # Causa comum (app/banco) soma o MESMO atraso em ms em todas as regiões; rota regional soma só numa.
        deg = {}
        for rg, v in hits.items():
            others = [x[3] for r2, x in hits.items() if r2 != rg]
            if len(v[0]) >= 2 and v[3] >= 3 * max(others + [15.0]):
                deg[rg] = v
        if deg:
            rg = min(deg, key=lambda r: deg[r][0][0]["k"])
            reg_knee = (rg, deg[rg][0], deg[rg][1], deg[rg][2])
            if knee is None:
                for w in reg_knee[1]:
                    w["degraded"] = True
                knee = reg_knee[1][0]

    # ---- saúde por worker -----------------------------------------------------
    integrity = []
    for w in wids:
        arr = wseries[w]
        n = len(arr)
        bad = [a for a in arr if a["comp"] is not False]
        keys = {}
        for a in arr:
            for k in a["viol"]:
                keys[k] = keys.get(k, 0) + 1
        mx = lambda f: max([a[f] for a in arr if a.get(f) is not None], default=None)
        integrity.append({
            "id": w, "region": W[w]["meta"].get("region"), "seconds": n, "compromised_s": len(bad),
            "integrity_pct": _r(100 * (1 - len(bad) / n), 1) if n else None,
            "violations": keys, "cpu_proc_max": mx("cpu_proc"), "cpu_sys_max": mx("cpu_sys"),
            "mem_max": mx("mem"), "ports_max": mx("ports"), "fd_max": mx("fd"),
            "lag99_max": mx("lag99"), "late99_max": mx("late_p99"), "conns_max": mx("conns"),
            "first_compromised_t": next((a["t"] for a in arr if a["comp"] is not False), None),
            "health_measured": health_known})

    # ---- endpoints ------------------------------------------------------------
    knee_secs = set()
    if knee:
        knee_secs = {s for w in wins if w["k"] >= knee["k"] and w["degraded"] for s in range(w["t0"], w["t1"])}
    endpoints = []
    for en, per in EPS.items():
        allh = merged(v["raw"] for v in per.values())
        n = sum(v["n"] for v in per.values())
        er = sum(v["err"] for v in per.values())
        bh = merged(per[s]["clean"] for s in per if s in bsecs)
        dh = merged(per[s]["clean"] for s in per if s in knee_secs)
        dn = sum(per[s]["cn"] for s in per if s in knee_secs)
        de = sum(per[s]["cerr"] for s in per if s in knee_secs)
        ratio = None
        if bh.n >= 20 and dh.n >= 20 and bh.q(95):
            ratio = dh.q(95) / bh.q(95)
        endpoints.append({
            "name": en, "layer": ep_layer.get(en, "unknown"), "n": n, "err": er,
            "err_rate": _r(er / n, 4) if n else None,
            "p50": _q(allh, 50), "p90": _q(allh, 90), "p95": _q(allh, 95), "p99": _q(allh, 99),
            "base_p95": _q(bh, 95), "degraded_p95": _q(dh, 95), "ratio": _r(ratio, 2),
            "degraded_err_rate": _r(de / dn, 4) if dn else None,
            "series": [{"t": s, "n": per[s]["n"], "err": per[s]["err"], "p95": _q(per[s]["raw"], 95)}
                       for s in sorted(per)]})
    for e in endpoints:
        e["errs"] = _sum_dict((W[w]["buckets"][s].get("ep", {}).get(e["name"], {}).get("errs", {})
                               for w in wids for s in W[w]["buckets"]))
    endpoints.sort(key=lambda e: -e["n"])

    reg_out = []
    for rg, R in regions.items():
        reg_out.append({"region": rg, "workers": R["workers"], "n": R["n"],
                        "err_rate": _r(R["err"] / R["n"], 4) if R["n"] else None,
                        "p50": _q(R["resp"], 50), "p90": _q(R["resp"], 90), "p95": _q(R["resp"], 95),
                        "p99": _q(R["resp"], 99), "conn_p95": _q(R["conn"], 95), "ttfb_p95": _q(R["ttfb"], 95),
                        "rtt_baseline_ms": _r(statistics.median([x for x in R["rtt"] if x is not None]), 2) if any(x is not None for x in R["rtt"]) else None,
                        "series": [{"t": s, "p95": _q(h, 95)} for s, h in sorted(R["series"].items())]})

    # ---- tenants ---------------------------------------------------------------
    tenants = _tenants(W, wids)

    # ---- canário independente ---------------------------------------------------
    canary = col.get("canary", [])

    # ---- veredito --------------------------------------------------------------
    V = _verdict(col, cfg, model, unit, wins, elig, knee, first_taint, integrity, endpoints, reg_out,
                 canary, base_p95, lat_thr, err_thr, base_quality, peak_win_plan, health_known,
                 G, W, wids, shares, tenants, series, prov, reg_knee)

    # ---- totais / confiabilidade -------------------------------------------------
    tot = {k: sum(G[s][k] for s in G) for k in ("arr", "sent", "ok", "err", "drop_cap", "drop_sched", "tx", "rx")}
    allresp = merged(G[s]["resp"] for s in G)
    totals = dict(tot, **{f"p{p}": _q(allresp, p) for p in (50, 90, 95, 99)},
                  err_rate=_r(tot["err"] / tot["sent"], 4) if tot["sent"] else None,
                  mean=_r(allresp.mean(), 2))
    rel = _reliability(col, W, wids, G, tot, secs, last, integrity, canary, health_known, prov, cfg, unit)
    crit_res = _criteria(cfg, endpoints, wins, V, totals)

    run = dict(col["run"])
    return {
        "schema": 1, "provenance": prov, "unit": unit, "model": model,
        "run": run, "infra": col.get("infra", {}), "series": series, "workers_series": wseries,
        "windows": [{k: (_r(v, 3) if isinstance(v, float) else v) for k, v in w.items()} for w in wins],
        "endpoints": endpoints, "regions": reg_out, "tenants": tenants, "integrity": integrity,
        "totals": totals, "canary": canary, "calibration": col.get("calibration"),
        "criteria": crit_res, "verdict": V["verdict"], "recommendations": V["recs"],
        "reliability": rel, "baseline": {"p95_ms": _r(base_p95), "err_rate": _r(base_err, 4),
                                          "quality": base_quality, "lat_threshold_ms": _r(lat_thr),
                                          "err_threshold": _r(err_thr, 4)},
        "config": cfg,
    }


def _sum_dict(it):
    out = {}
    for d in it:
        for k, v in d.items():
            out[k] = out.get(k, 0) + v
    return out


def _empty(col, why):
    return {"schema": 1, "provenance": col.get("provenance", "measured"), "run": col["run"], "empty": True,
            "series": [], "endpoints": [], "regions": [], "workers_series": {}, "windows": [], "integrity": [],
            "infra": col.get("infra", {}), "canary": [], "calibration": col.get("calibration"), "tenants": None,
            "totals": {}, "criteria": {"items": [], "passed": None}, "config": col["cfg"], "unit": "", "model": col["cfg"]["model"],
            "baseline": {}, "reliability": {"limitations": [why], "lost_pct": None, "planned_vs_generated": None},
            "verdict": {"state": "INCONCLUSIVO", "headline": "Sem dados: " + why, "location": "indeterminado",
                        "confidence": "n/a", "suspects": [], "evidence": [], "generator_ok": None,
                        "trusted_pct": 0, "capacity": None, "knee": None, "how_to_read": why},
            "recommendations": [{"priority": 1, "impact": 100, "title": "Descobrir por que nenhum worker entregou dados",
                                 "why": why, "action": "Veja run.events e o log do worker.", "layer": "gerador"}]}


# =============================================================================
def _tenants(W, wids):
    agg = {}
    for w in wids:
        for t, v in (W[w].get("tenants") or {}).items():
            a = agg.setdefault(t, {"n": 0, "err": 0, "h": Hist()})
            a["n"] += v["n"]
            a["err"] += v["err"]
            a["h"].merge(v["resp"])
    if not agg:
        return None
    rows = [{"tenant": t, "n": a["n"], "err_rate": _r(a["err"] / a["n"], 4) if a["n"] else None,
             "p50": _q(a["h"], 50), "p95": _q(a["h"], 95), "p99": _q(a["h"], 99)} for t, a in agg.items() if a["n"] >= 20]
    if not rows:
        return None
    p95s = sorted(r["p95"] for r in rows if r["p95"] is not None)
    med = statistics.median(p95s) if p95s else None
    worst = sorted(rows, key=lambda r: -(r["p95"] or 0))[:8]
    busiest = sorted(rows, key=lambda r: -r["n"])[:8]
    return {"count": len(agg), "median_p95": _r(med), "worst_p95": worst, "busiest": busiest,
            "spread": _r(max(p95s) / med, 2) if med and p95s else None,
            "top_share": _r(max(r["n"] for r in rows) / sum(r["n"] for r in rows), 3)}


def _reliability(col, W, wids, G, tot, secs, last, integrity, canary, health_known, prov, cfg, unit):
    planned = col["run"].get("planned_total")
    lost = 0
    expected = 0
    for w in wids:
        t = W[w].get("totals_reported")
        if t:
            expected += t["sent"]
            lost += max(0, t["sent"] - sum(b["sent"] for b in W[w]["buckets"].values()))
    lost_pct = _r(100 * lost / expected, 2) if expected else (0.0 if prov == "measured" else None)
    lim = []
    ev = col["run"].get("events", [])
    for w in wids:
        m = W[w]["meta"]
        if m.get("status") not in (None, "ok", "finished"):
            lim.append(f"worker {w}: {m.get('status')}")
    if not health_known:
        lim.append("Saúde do gerador NÃO foi medida nesta fonte (dados importados) — "
                   "o veredito sobre o alvo fica rebaixado: não dá para excluir o gerador.")
    for it in integrity:
        if it["compromised_s"]:
            lim.append(f"gerador {it['id']}: {it['compromised_s']}s com limites operacionais violados "
                       f"({', '.join(sorted(it['violations']))}) — amostras desses segundos foram excluídas do agregado limpo.")
    fa = col.get("platform_notes", [])
    lim.extend(fa)
    lim.append("Latência é medida do envio real da requisição; atraso do gerador antes do envio é medido à parte (late).")
    lim.append("Amostras são atribuídas ao segundo em que a resposta termina.")
    if col.get("calibration") is None and prov == "measured":
        lim.append("Sem calibração do gerador (Régua): teto honesto da máquina de carga desconhecido.")
    return {"lost_pct": lost_pct, "planned_vs_generated": col["run"].get("planned_vs_generated"),
            "planned_total": planned, "events": ev, "limitations": lim,
            "clock": col.get("clock", {}), "network": col.get("network", {}),
            "interference": [e for e in ev if e.get("level") in ("warn", "error")]}


def _criteria(cfg, endpoints, wins, V, totals):
    c = cfg.get("criteria", {}) or {}
    p = c.get("pass", {}) or {}
    items = []
    steady = [w for w in wins if w["plan"] > 0 and w["plan"] >= 0.95 * max((x["plan"] for x in wins), default=0)]
    sn = sum(w["sent"] for w in steady)
    se = sum(w["err_rate"] * w["sent"] for w in steady)
    errr = se / sn if sn else None
    p95 = max((w["cp95"] for w in steady if w["cp95"] is not None), default=None)
    p99 = max((w["cp99"] for w in steady if w["cp99"] is not None), default=None)
    trusted = V["verdict"].get("generator_ok") is not False and all(w["trusted"] >= 0.9 for w in steady) if steady else False
    for key, label, val, op in (("p95_ms", "P95 (pior janela de 5s no patamar)", p95, "<="),
                                ("p99_ms", "P99 (pior janela de 5s no patamar)", p99, "<="),
                                ("error_rate", "Taxa de erro no patamar", errr, "<=")):
        if p.get(key) is not None:
            ok = (val is not None) and val <= p[key]
            items.append({"key": key, "label": label, "limit": p[key], "value": _r(val, 4), "ok": ok,
                          "trusted": trusted})
    for en, lim in (p.get("per_endpoint") or {}).items():
        e = next((x for x in endpoints if x["name"] == en), None)
        if e and lim.get("p95_ms") is not None:
            items.append({"key": f"{en}.p95_ms", "label": f"{en} P95 (run inteiro)", "limit": lim["p95_ms"],
                          "value": e["p95"], "ok": e["p95"] is not None and e["p95"] <= lim["p95_ms"], "trusted": trusted})
    passed = None
    if items:
        passed = all(i["ok"] for i in items)
        if passed and not trusted:
            passed = None  # "passou" sem gerador íntegro não vale
    return {"items": items, "passed": passed, "trusted": trusted,
            "note": None if trusted or not items else "Resultado não confiável: gerador comprometido no patamar."}


# =============================================================================
def _verdict(col, cfg, model, unit, wins, elig, knee, first_taint, integrity, endpoints, regs, canary,
             base_p95, lat_thr, err_thr, base_quality, peak_win_plan, health_known, G, W, wids, shares,
             tenants, series, prov, reg_knee=None):
    ev = []      # evidências globais
    sus = []     # suspeitos
    recs = []
    comp_wins = [w for w in wins if w["trusted"] < 0.9]
    comp_frac = len(comp_wins) / len(wins) if wins else 0
    trusted_pct = _r(100 * (1 - comp_frac), 1)
    gen_viol = {}
    for it in integrity:
        for k, n in it["violations"].items():
            gen_viol[k] = gen_viol.get(k, 0) + n
    cal = col.get("calibration")

    def E(txt, kind="measured", pro=None):
        ev.append({"txt": txt, "kind": kind if prov == "measured" else prov, "supports": pro})

    # -- gerador: primário ou consequência?
    gen_primary = False
    gen_conseq = False
    gen_first = None
    if first_taint is not None or comp_wins:
        fw = (first_taint or comp_wins[0])
        gen_first = fw["t0"]
        keys = set(fw["comp_viol"]) or set(gen_viol)
        after_knee = knee is not None and fw["k"] >= knee["k"]
        if after_knee and keys and keys <= CONSEQ_KEYS:
            gen_conseq = True
        elif comp_frac > 0.10 or (first_taint is not None):
            gen_primary = True
    if not health_known:
        gen_primary = False

    # -- calibração vs carga planejada (estimativa)
    over_cal = []
    if cal and model == "open":
        for it in col["infra"].get("workers", []):
            if it.get("planned_peak") and cal["safe_rps"] and it["planned_peak"] > cal["ceiling_rps"]:
                over_cal.append(it["id"])
    # -- camadas (diferencial)
    layers = {}
    for e in endpoints:
        if e["ratio"] is not None or e["degraded_err_rate"] is not None:
            L = layers.setdefault(e["layer"], {"eps": [], "max_ratio": 0.0, "err": 0.0})
            L["eps"].append(e["name"])
            L["max_ratio"] = max(L["max_ratio"], e["ratio"] or 0)
            L["err"] = max(L["err"], e["degraded_err_rate"] or 0)
    deg_layers = {k for k, L in layers.items() if (L["max_ratio"] >= 2.5 or L["err"] >= 0.02)}
    flat_layers = {k for k in layers if k not in deg_layers}

    # -- fase de erro/ttfb/conn
    conn_ratio = ttfb_ratio = None
    if knee:
        fh = next((w["k"] for w in wins if w["plan"] >= 0.5 * peak_win_plan), len(wins))
        base_w = [w for w in wins if w["plan"] > 0 and w["plan"] <= 0.25 * peak_win_plan and 1 <= w["k"] < fh]
        bc = [w["conn95"] for w in base_w if w["conn95"]]
        bt = [w["ttfb95"] for w in base_w if w["ttfb95"]]
        dw = [w for w in wins if w["k"] >= knee["k"] and w["degraded"]]
        dc = [w["conn95"] for w in dw if w["conn95"]]
        dt = [w["ttfb95"] for w in dw if w["ttfb95"]]
        if bc and dc:
            conn_ratio = statistics.median(dc) / max(statistics.median(bc), 0.05)
        if bt and dt:
            ttfb_ratio = statistics.median(dt) / max(statistics.median(bt), 0.05)
    dstat, derrs = {}, {}
    if knee:
        for w in wins:
            if w["k"] >= knee["k"] and w["degraded"]:
                for k, v in w["status"].items():
                    dstat[k] = dstat.get(k, 0) + v
                for k, v in w["errs"].items():
                    derrs[k] = derrs.get(k, 0) + v
    nerr = sum(derrs.values()) or 0
    share = lambda keys: sum(derrs.get(k, 0) for k in keys) / nerr if nerr else 0
    overload_share = share(("http_429", "http_503", "http_502", "http_504", "http_5xx"))
    timeout_share = share(("read_timeout",))
    conn_err_share = share(("connect_timeout", "connect_refused", "reset", "connect_error"))
    port_share = share(("port_exhaustion",))

    # -- canário
    can_ratio = None
    if canary and knee:
        bef = [c["ms"] for c in canary if c["ok"] and c["t"] < knee["t0"] and c["ms"] is not None]
        aft = [c for c in canary if c["t"] >= knee["t0"] and c["t"] < knee["t1"] + 15]
        aftok = [c["ms"] for c in aft if c["ms"] is not None]
        fail_aft = sum(1 for c in aft if not c["ok"])
        if bef and (aftok or fail_aft):
            m0 = statistics.median(bef)
            m1 = statistics.median(aftok) if aftok else float("inf")
            can_ratio = (m1 / max(m0, 0.5)) if aftok else float("inf")
            if fail_aft and not aftok:
                can_ratio = float("inf")

    # -- regional
    reg_diff = None
    if len(regs) >= 2:
        p95s = {r["region"]: r["p95"] for r in regs if r["p95"] is not None}
        if len(p95s) >= 2:
            lo, hi = min(p95s.values()), max(p95s.values())
            if lo > 0 and hi / lo >= 2.5 and knee:
                worst = max(p95s, key=p95s.get)
                reg_diff = (worst, hi / lo)

    # ===== decisão ===========================================================
    capacity = _capacity(wins, knee, crit=cfg.get("criteria", {}).get("pass", {}), unit=unit)
    state, location, headline, conf, how = "INCONCLUSIVO", "indeterminado", "", "baixa", ""
    aborted = col["run"].get("status") in ("aborted",)
    n_samples = sum(w["sent"] for w in wins)

    sus_gen = {"layer": "gerador de carga", "score": 0, "evidence": [], "against": [],
               "confirm": "Rode `loadlab.py calibrate` nas máquinas e use mais workers / menos carga por worker."}
    sus_net = {"layer": "conectividade / rede", "score": 0, "evidence": [], "against": [],
               "confirm": "Meça RTT/perda (mtr, iperf3) entre gerador e alvo; compare regiões; cheque LB/NAT/conntrack."}
    sus_app = {"layer": "aplicação SaaS", "score": 0, "evidence": [], "against": [],
               "confirm": "Correlacione com CPU/threads/GC/pool do app e logs no mesmo horário do joelho."}
    sus_db = {"layer": "banco de dados", "score": 0, "evidence": [], "against": [],
              "confirm": "Veja conexões ativas, locks, slow queries (pg_stat_statements/slow log) e CPU/IO do banco no joelho."}
    sus_inf = {"layer": "infraestrutura (borda/LB/orquestração)", "score": 0, "evidence": [], "against": [],
               "confirm": "Cheque limites do LB/ingress, autoscaling, CPU/limits de pods, filas de accept."}

    # gerador
    if gen_primary:
        sus_gen["score"] += 60
        sus_gen["evidence"].append(f"{len(comp_wins)} de {len(wins)} janelas com limite operacional violado ({', '.join(sorted(gen_viol)) or '—'})")
        if first_taint is not None:
            sus_gen["evidence"].append(f"janela(s) com 'degradação' aparente coincidem com gerador comprometido (a partir de t={first_taint['t0']}s)")
            sus_gen["score"] += 25
    if over_cal:
        sus_gen["score"] += 15
        sus_gen["evidence"].append(f"carga por worker acima do teto calibrado ({cal['ceiling_rps']:g} rps): {', '.join(over_cal)}")
    if not gen_primary and health_known:
        sus_gen["against"].append(f"{trusted_pct}% das janelas com todos os geradores dentro dos limites")
    if gen_conseq:
        sus_gen["against"].append("o gerador só degradou DEPOIS do joelho e por efeito (conexões/portas/drops) — consequência, não causa")

    # alvo/camadas
    if knee and not gen_primary:
        base_score = 40
        sus_app["evidence"].append(f"joelho em t={knee['t0']}s: P95 limpo {knee['cp95']} ms vs. base {_r(base_p95)} ms (limiar {_r(lat_thr)} ms)" if knee["cp95"] else f"joelho em t={knee['t0']}s por erros ({_r((knee['cerr_rate'] or 0)*100,1)}%)")
        if ttfb_ratio and ttfb_ratio >= 2.5:
            E(f"TTFB P95 ×{ttfb_ratio:.1f} após o joelho: tempo ESPERANDO o servidor, não conectando", pro="alvo")
            sus_app["score"] += 15
        if overload_share >= 0.5:
            E(f"{overload_share*100:.0f}% dos erros pós-joelho são 429/5xx explícitos — o alvo recusa/sobrecarrega", pro="alvo")
            sus_app["score"] += 15
            sus_inf["score"] += 5
        if timeout_share >= 0.5:
            E(f"{timeout_share*100:.0f}% dos erros pós-joelho são timeouts de leitura — fila no servidor (ou rota lenta)", pro="alvo")
            sus_app["score"] += 10
        if conn_ratio and conn_ratio >= 3:
            E(f"tempo de conexão P95 ×{conn_ratio:.1f} — fila de accept/SYN, LB ou rota", pro="rede/infra")
            sus_net["score"] += 20
            sus_inf["score"] += 25
            sus_net["evidence"].append(f"connect P95 ×{conn_ratio:.1f} vs. base")
        if conn_err_share >= 0.3:
            sus_inf["score"] += 20
            sus_net["score"] += 15
            sus_inf["evidence"].append(f"{conn_err_share*100:.0f}% dos erros são falhas de conexão (refused/reset/timeout de connect)")
        if port_share > 0:
            sus_gen["score"] += 30
            sus_gen["evidence"].append("erros de esgotamento de portas efêmeras (EADDRNOTAVAIL) — limite do GERADOR/SO")
        if reg_knee:
            sus_net["score"] += 50
            sus_inf["score"] -= 20
            sus_db["score"] -= 20
            base_score -= 25
            sus_net["evidence"].append(f"só a região '{reg_knee[0]}' degradou (P95 +{reg_knee[3]:.0f} ms sobre a própria base de {reg_knee[2]:.0f} ms) enquanto nas outras o acréscimo foi mínimo — causa comum (app/banco) somaria o mesmo atraso em todas")
            sus_app["against"].append("se fosse o app/banco, todas as regiões degradariam juntas")
            sus_app["score"] -= 30
            E(f"degradação isolada na região '{reg_knee[0]}' — padrão de rota/PoP regional", pro="rede")
        elif reg_diff:
            sus_net["score"] += 30
            sus_net["evidence"].append(f"região '{reg_diff[0]}' ×{reg_diff[1]:.1f} pior que a melhor — padrão de rota regional")
            sus_app["against"].append("se fosse o app, todas as regiões degradariam juntas")
        elif len(regs) >= 2:
            sus_net["against"].append("regiões degradam juntas — não parece problema de rota regional")
        if can_ratio is not None:
            if can_ratio >= 2.0:
                E(f"canário independente (fora dos geradores) também piorou ×{'∞' if can_ratio == float('inf') else f'{can_ratio:.1f}'} — degradação é REAL no alvo", pro="alvo")
                base_score += 20
            else:
                E(f"canário independente estável (×{can_ratio:.1f}): consistente com degradação restrita a camadas internas (a sonda toca só a borda/health)", pro="exclusão")
                if "edge" in deg_layers:
                    sus_net["score"] += 25
                    sus_app["score"] -= 15
                    base_score -= 15
        # diferencial por camada
        if layers:
            for k, L in layers.items():
                E(f"camada '{k}': pior P95 ×{L['max_ratio']:.1f}, erro {L['err']*100:.1f}% ({', '.join(L['eps'][:3])})", pro=k)
            if "db" in deg_layers and not (deg_layers & {"app", "edge", "cache"}):
                sus_db["score"] += 55
                sus_db["evidence"].append("endpoints que tocam o banco degradaram enquanto os sentinelas sem banco ficaram planos")
                sus_app["against"].append("endpoints de app sem banco permaneceram estáveis")
                base_score -= 35  # o sentinela sem banco ficou plano: a degradação genérica "do alvo" é do banco
            elif "db" in deg_layers and (deg_layers & {"app"}):
                sus_app["score"] += 30
                sus_db["score"] += 15
                sus_app["evidence"].append("camadas app E db degradaram: gargalo comum (CPU/threads/pool) é mais provável que só o banco")
                sus_db["evidence"].append("db degradou, mas o sentinela de app também — o banco é suspeito, não condenado")
            elif "edge" in deg_layers:
                sus_inf["score"] += 40
                sus_net["score"] += 20
                sus_inf["evidence"].append("até o endpoint de borda/estático degradou: limite antes da aplicação (LB, banda, conexões)")
            elif "cache" in deg_layers and "db" not in deg_layers:
                sus_app["score"] += 25
                sus_app["evidence"].append("camada de cache degradou isoladamente")
            elif "app" in deg_layers:
                sus_app["score"] += 40
                sus_app["evidence"].append("endpoints de app degradaram")
            if flat_layers:
                E(f"camadas estáveis no joelho: {', '.join(sorted(flat_layers))} (sentinelas de controle)", pro="exclusão")
        else:
            sus_app["score"] += 20
            sus_app["evidence"].append("sem endpoints marcados por 'layer': não é possível separar app/banco/borda")
            how = "Marque cada endpoint com layer: edge|app|db|cache|queue|external e inclua 1 sentinela sem banco."
        sus_app["score"] += base_score
    # decisão do estado
    healthy_in_knee = bool(knee) and (knee["trusted"] >= 0.9)
    have_corr = (can_ratio is not None and can_ratio >= 2.0)
    n_indep = sum([bool(ttfb_ratio and ttfb_ratio >= 2.5), overload_share >= 0.5, have_corr,
                   bool(layers), (conn_ratio or 0) >= 3])
    if aborted and not knee:
        state = "ABORTADO"
    if n_samples < 200 or len(wins) < 2:
        state, headline = "INCONCLUSIVO", "Amostras insuficientes para concluir qualquer coisa."
        location, conf = "indeterminado", "n/a"
    elif gen_primary:
        state, location, conf = "GERADOR_COMPROMETIDO", "gerador de carga", "alta" if comp_frac > 0.3 or first_taint else "média"
        top = max(gen_viol, key=gen_viol.get) if gen_viol else "limites"
        headline = (f"Este resultado NÃO prova limite do seu SaaS: o gerador passou do limite operacional "
                    f"({_viol_pt(top)}) em {100*comp_frac:.0f}% das janelas. Nada foi atribuído ao alvo.")
        how = how or "Divida a carga entre mais workers (ou mais máquinas) e reexecute; veja a Régua (calibrate)."
    elif not health_known:
        state, location, conf = "INCONCLUSIVO", "indeterminado (gerador não medido)", "baixa"
        headline = ("Dados sem telemetria do gerador: há " + ("degradação" if knee else "ausência de degradação") +
                    " nas respostas, mas não dá para separar alvo de gerador. Rebaixado a inconclusivo.")
    elif knee and healthy_in_knee:
        if n_indep >= 3 and (have_corr or not canary):
            state, conf = "ALVO_SATURADO_CONFIRMADO" if have_corr else "ALVO_SATURADO_PROVAVEL", ("alta" if have_corr else "média")
        else:
            state, conf = "ALVO_SATURADO_PROVAVEL", "média" if n_indep >= 2 else "baixa"
        sus_sorted = sorted([sus_app, sus_db, sus_inf, sus_net], key=lambda s: -s["score"])
        location = sus_sorted[0]["layer"] if sus_sorted[0]["score"] >= 40 else "alvo (camada não determinada)"
        cap = capacity.get("validated")
        headline = (f"Degradação real a partir de ~{_r(knee['plan'], 0):g} {unit} (t={knee['t0']}s) com geradores íntegros — "
                    f"suspeito principal: {location}." + (f" Capacidade validada: ~{cap:g} req/s." if cap else ""))
        if location.startswith("conect"):
            state = "CONECTIVIDADE_PROVAVEL"
            headline = headline.replace("Degradação real", "Degradação REAL, mas no CAMINHO (rota/rede), não no sistema em si:", 1)
        if not layers:
            headline += " (camada exata não separável sem sentinelas.)"
        if gen_conseq:
            how += " Atenção: o gerador degradou depois do joelho, por efeito da lentidão do alvo."
    elif knee and not healthy_in_knee:
        state, location, conf = "INCONCLUSIVO", "indeterminado", "baixa"
        headline = "Houve degradação, mas o gerador estava sob estresse nas janelas do joelho — não dá para acusar o alvo."
    else:
        state, location, conf = "SEM_SATURACAO", "nenhuma limitação observada", "média" if trusted_pct >= 90 else "baixa"
        headline = (f"Nenhuma saturação até o pico testado (~{_r(peak_win_plan, 0):g} {unit}) com geradores íntegros. "
                    "A capacidade real é MAIOR que isso — o teste não achou o limite.")
        if peak_win_plan and base_quality.startswith("primeiros"):
            how += " Sem rampa de baixa carga, a comparação com baseline é fraca."

    for s in (sus_gen, sus_net, sus_app, sus_db, sus_inf):
        s["score"] = max(0, min(100, int(s["score"])))
        sus.append(s)
    sus.sort(key=lambda s: -s["score"])
    if state in ("SEM_SATURACAO", "INCONCLUSIVO") and not gen_primary:
        for s in sus:
            if s["layer"] != "gerador de carga":
                s["score"] = min(s["score"], 20)
    # ---- recomendações -------------------------------------------------------------
    recs.extend(_recs(state, gen_primary, gen_viol, comp_frac, cal, sus, layers, deg_layers, endpoints,
                      overload_share, timeout_share, conn_ratio, tenants, health_known, canary, knee, regs, reg_diff,
                      model, col, wins))
    recs.sort(key=lambda r: -r["impact"])
    for i, r in enumerate(recs, 1):
        r["priority"] = i
    return {"verdict": {
        "state": state, "location": location, "headline": headline, "confidence": conf,
        "suspects": sus, "evidence": ev, "generator_ok": (not gen_primary) if health_known else None,
        "generator_consequence": gen_conseq, "trusted_pct": trusted_pct,
        "capacity": capacity,
        "knee": ({"t": knee["t0"], "plan": _r(knee["plan"], 1), "rps": _r(knee["rps"], 1), "p95": knee["cp95"],
                  "err_rate": _r(knee["cerr_rate"], 4)} if knee else None),
        "tainted_from_t": first_taint["t0"] if first_taint else None,
        "how_to_read": how.strip(),
        "layers": {k: {"max_ratio": _r(v["max_ratio"], 2), "err": _r(v["err"], 4), "degraded": k in deg_layers, "eps": v["eps"]}
                   for k, v in layers.items()},
        "signals": {"ttfb_ratio": _r(ttfb_ratio, 2), "conn_ratio": _r(conn_ratio, 2),
                    "canary_ratio": None if can_ratio is None else (None if can_ratio == float("inf") else _r(can_ratio, 2)),
                    "canary_failed": can_ratio == float("inf"),
                    "overload_err_share": _r(overload_share, 3), "timeout_err_share": _r(timeout_share, 3),
                    "conn_err_share": _r(conn_err_share, 3)},
    }, "recs": recs}


def _viol_pt(k):
    return {"loop_lag_p99_ms": "event loop atrasado", "late_p99_ms": "envio atrasado vs. planejado",
            "cpu_proc_cores": "CPU do processo no teto", "cpu_sys_pct": "CPU do sistema", "mem_pct": "memória",
            "ports_pct": "portas efêmeras", "fd_pct": "descritores de arquivo",
            "drop_ratio": "iterações descartadas", "achieved_ratio": "taxa de chegada abaixo do planejado"}.get(k, k)


def _capacity(wins, knee, crit, unit):
    """Capacidade validada = maior vazão sustentada (>=2 janelas = 10s) em janelas íntegras e não degradadas."""
    best, bestw = 0.0, None
    run = []
    for w in wins:
        good = (w["degraded"] is False) and w["trusted"] >= 0.9 and w["plan"] > 0
        if good:
            run.append(w)
            if len(run) >= 2:
                v = min(x["rps"] for x in run[-2:])
                if v > best:
                    best, bestw = v, run[-1]
        else:
            run = []
    out = {"validated": _r(best, 1) if best else None, "at_t": bestw["t1"] if bestw else None,
           "prov": "measured", "unit": "req/s (respostas ok/s)"}
    if knee:
        out["note"] = ("Última vazão sustentada íntegra antes do joelho. O limite exato está entre esse valor e "
                       f"~{_r(knee['rps'], 0):g} req/s (onde degradou); não é extrapolação.")
    else:
        out["note"] = "Limite superior NÃO encontrado: capacidade real ≥ valor validado."
    return out


def _recs(state, gen_primary, gen_viol, comp_frac, cal, sus, layers, deg_layers, endpoints, overload_share,
          timeout_share, conn_ratio, tenants, health_known, canary, knee, regs, reg_diff, model, col, wins):
    R = []

    def add(impact, layer, title, why, action):
        R.append({"impact": impact, "layer": layer, "title": title, "why": why, "action": action})
    if gen_primary:
        add(100, "gerador", "Refazer o teste com mais geradores / menos carga por worker",
            f"Limites violados: {', '.join(_viol_pt(k) for k in sorted(gen_viol))}.",
            "Rode `loadlab.py calibrate` em cada máquina; mantenha cada worker ≤ 70% do teto calibrado; "
            "1 worker ≈ 1 núcleo — suba N workers por host.")
        if "ports_pct" in gen_viol:
            add(70, "gerador", "Esgotamento de portas efêmeras no gerador",
                "Muitas conexões novas/TIME_WAIT para o mesmo destino.",
                "Mantenha keepalive, aumente o range de portas (Linux: net.ipv4.ip_local_port_range), distribua em mais IPs/workers.")
        if "fd_pct" in gen_viol:
            add(65, "gerador", "Limite de descritores de arquivo", "ulimit -n baixo.", "Suba `ulimit -n` (≥ 65535) antes de iniciar o worker.")
    if not health_known:
        add(90, "confiabilidade", "Rode pelo motor nativo (ou exporte telemetria do gerador)",
            "Resultados importados não trazem saúde do gerador.", "Use `loadlab.py run`, ou colete CPU/rede dos geradores e reimporte.")
    if state.startswith("ALVO_SATURADO") or state == "CONECTIVIDADE_PROVAVEL":
        top = sus[0]
        if top["layer"] == "banco de dados":
            names = [n for k in deg_layers if k == "db" for n in layers[k]["eps"]]
            add(95, "banco", f"Investigar o banco no ponto de joelho ({', '.join(names[:3])})",
                "Endpoints com banco degradaram, sentinelas sem banco não.",
                "pg_stat_activity/pg_locks, pg_stat_statements (top por tempo), saturação do pool de conexões, índices faltantes.")
        elif top["layer"].startswith("aplicação"):
            add(90, "app", "Procurar gargalo de CPU/threads/pool na aplicação",
                "Degradação sem sinal de rede ou banco isolado.", "Profile sob carga, tamanho do pool de workers/threads, GC, pool de conexões do banco; escale horizontalmente e re-teste.")
        elif top["layer"].startswith("infra"):
            add(90, "infra", "Revisar limites de borda/LB/orquestração",
                "A degradação aparece até em endpoints de borda ou na conexão.", "Limites de conexão do LB/ingress, worker_connections, autoscaling, requests/limits dos pods.")
        elif top["layer"].startswith("conect"):
            add(88, "rede", "Verificar rota/rede entre gerador e alvo", "Padrão regional ou connect lento.",
                "mtr/iperf3, perda, NAT/conntrack, peering; repita com gerador na mesma região do alvo.")
        if overload_share >= 0.5:
            add(70, "app", "Alvo devolvendo 429/5xx sob carga", f"{overload_share*100:.0f}% dos erros pós-joelho.",
                "Confirme se é rate-limit (esperado) ou esgotamento (bug); revise backpressure e autoscaling.")
        if timeout_share >= 0.5:
            add(65, "app", "Timeouts de leitura dominando", "Requisições ficam na fila do servidor.",
                "Reduza trabalho síncrono por request, limite concorrência por rota, defina timeouts coerentes em toda a cadeia.")
    if state == "SEM_SATURACAO":
        add(60, "teste", "Subir o patamar para achar o limite", "Nenhuma degradação até o pico testado.",
            "Aumente o pico em passos (ex.: 1.5×) mantendo a Régua do gerador; o teste atual só prova capacidade ≥ pico.")
    if tenants and tenants.get("spread") and tenants["spread"] >= 3:
        add(55, "multi-tenant", "Possível vizinho barulhento entre tenants",
            f"P95 do pior tenant é ×{tenants['spread']} a mediana.", "Cheque limites por tenant, índices por tenant_id e partição de dados dos tenants lentos.")
    if not canary:
        add(35, "confiabilidade", "Ative o canário independente (canary_url)",
            "Sem sonda fora dos geradores não há corroboração externa da degradação.", "Defina `canary_url` (endpoint leve) no config.")
    if not layers:
        add(40, "confiabilidade", "Marque endpoints com `layer` e inclua sentinelas",
            "Sem camadas não dá para separar app/banco/borda.", "layer: edge (estático/health do LB), app (sem banco), db, cache, queue, external.")
    if cal is None:
        add(30, "confiabilidade", "Rode a Régua (calibrate) antes", "Teto do gerador desconhecido.", "`loadlab.py calibrate` em cada máquina de carga.")
    return R
