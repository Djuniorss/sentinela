"""Importa resultados do JMeter (JTL/CSV) e do k6 (--out json) para o MESMO relatório.

Limite honesto: essas ferramentas não entregam a saúde do gerador. O relatório marca
`health_measured=False` e rebaixa qualquer veredito sobre o alvo a INCONCLUSIVO.
"""
import csv
import datetime
import json
import time

from .engine import new_bucket
from .hist import Hist
from .controller import normalize, config_hash


def _col(cfg, tool, workers, labels, t0, t1, note):
    if not cfg:
        cfg = {"name": f"import-{tool}", "model": "open", "target": {"base_url": "imported://"},
               "endpoints": [{"name": l, "path": "/", "layer": "unknown"} for l in sorted(labels)],
               "stages": [{"duration": max(1, int(t1 - t0)), "target": 1}]}
    cfg = normalize(dict(cfg))
    W = {}
    for wid, buckets in workers.items():
        for s, b in buckets.items():  # carga observada como proxy do plano (declarado nas limitações)
            b["plan"] = float(b["sent"])
        W[wid] = {"meta": {"id": wid, "region": "?", "share": 1.0 / len(workers), "status": "ok"},
                  "buckets": buckets, "health": {}, "totals_reported": None, "tenants": {}}
    return {"cfg": cfg, "provenance": "ingested", "health_measured": False, "workers": W, "canary": [],
            "platform_notes": [note, "Carga planejada indisponível: usando a carga OBSERVADA por segundo como referência."],
            "calibration": None,
            "run": {"id": f"{time.strftime('%Y%m%d-%H%M%S')}-import-{tool}", "name": cfg["name"],
                    "started_at": datetime.datetime.fromtimestamp(t0).isoformat(timespec="seconds"),
                    "ended_at": datetime.datetime.fromtimestamp(t1).isoformat(timespec="seconds"),
                    "duration_planned_s": None, "duration_actual_s": round(t1 - t0, 1), "status": "completed",
                    "abort_reason": None, "events": [], "config_hash": config_hash(cfg), "tool": f"sentinela (import {tool})",
                    "target": cfg["target"]["base_url"], "app_version": cfg["target"].get("app_version"),
                    "script_version": cfg.get("script_version"), "environment": None,
                    "planned_total": None, "planned_vs_generated": None},
            "infra": {"num_workers_planned": len(W), "num_workers_effective": len(W),
                      "workers": [{"id": w, "region": "?", "status": "ok", "share": 1.0 / len(W), "local": False} for w in W],
                      "target": cfg["target"], "infra_notes": "importado"}}


def _rec(b, label, ms, err, status=None, ttfb=None, conn=None, tx=0, rx=0, kind="http"):
    b["sent"] += 1
    b["arr"] += 1
    e = b["ep"].setdefault(label, {"n": 0, "err": 0, "resp": Hist(), "errs": {}})
    e["n"] += 1
    if err:
        b["err"] += 1
        e["err"] += 1
        k = f"http_{status}" if status in ("429", "502", "503", "504") else ("http_5xx" if (status or "").startswith("5") else "http_4xx" if (status or "").startswith("4") else "error")
        b["errs"][k] = b["errs"].get(k, 0) + 1
        e["errs"][k] = e["errs"].get(k, 0) + 1
    else:
        b["ok"] += 1
    if status:
        b["status"][status] = b["status"].get(status, 0) + 1
    if ms is not None:
        b["resp"].add(ms)
        e["resp"].add(ms)
    if ttfb is not None:
        b["ttfb"].add(ttfb)
    if conn:
        b["conn"].add(conn)
    b["tx"] += tx
    b["rx"] += rx


def ingest_jtl(path, cfg=None):
    workers, labels = {}, set()
    t_min = t_max = None
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                ts = int(r["timeStamp"]) / 1000.0
                el = float(r["elapsed"])
            except (KeyError, ValueError):
                continue
            t_min = ts if t_min is None else min(t_min, ts)
            t_max = ts if t_max is None else max(t_max, ts)
            workers.setdefault(r.get("Hostname") or "jmeter", {})
            labels.add(r["label"])
    if t_min is None:
        raise SystemExit("JTL sem linhas válidas (precisa de CSV com cabeçalho: timeStamp,elapsed,label,responseCode,success,...)")
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                ts, el = int(r["timeStamp"]) / 1000.0, float(r["elapsed"])
            except (KeyError, ValueError):
                continue
            sec = int(ts + el / 1000.0 - t_min)  # fim da resposta
            wb = workers[r.get("Hostname") or "jmeter"]
            b = wb.setdefault(sec, new_bucket())
            ok = str(r.get("success", "true")).lower() == "true"
            _rec(b, r["label"], el, not ok, r.get("responseCode"), _f(r.get("Latency")), _f(r.get("Connect")),
                 int(r.get("sentBytes") or 0), int(r.get("bytes") or 0))
    note = ("Importado de JTL do JMeter: Latency=TTFB, Connect=connect; o JMeter mede coordinated omission de forma diferente "
            "do motor nativo e não informa saúde do gerador.")
    return _col(cfg, "jmeter", workers, labels, t_min, t_max, note)


def ingest_k6(path, cfg=None):
    workers, labels = {}, set()
    pts = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            try:
                j = json.loads(ln)
            except ValueError:
                continue
            if j.get("type") != "Point" or j.get("metric") not in ("http_req_duration", "http_req_waiting", "http_req_connecting"):
                continue
            d = j["data"]
            t = datetime.datetime.fromisoformat(d["time"].replace("Z", "+00:00")).timestamp()
            pts.append((t, j["metric"], d["value"], d.get("tags", {})))
    if not pts:
        raise SystemExit("k6 JSON sem pontos http_req_* (use: k6 run --out json=out.json script.js)")
    t_min, t_max = min(p[0] for p in pts), max(p[0] for p in pts)
    for t, m, v, tags in pts:
        wid = tags.get("instance_id") or tags.get("instance") or "k6"
        label = tags.get("endpoint") or tags.get("name") or tags.get("url", "?")
        labels.add(label)
        b = workers.setdefault(wid, {}).setdefault(int(t - t_min), new_bucket())
        if m == "http_req_duration":
            st = str(tags.get("status", ""))
            bad = st.startswith(("4", "5")) or st in ("0", "") or tags.get("expected_response") == "false"
            _rec(b, label, v, bad, st or None)
        elif m == "http_req_waiting":
            b["ttfb"].add(v)
        else:
            b["conn"].add(v)
    note = "Importado de k6 --out json: tempos de TTFB/connect entram como histogramas independentes; sem saúde do gerador."
    return _col(cfg, "k6", workers, labels, t_min, t_max, note)


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None
