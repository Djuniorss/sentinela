"""Entrega SEMPRE: dashboard.html autocontido + métricas + config reproduzível + relatório técnico.
Mesmo em falha/abort/parcial/crash, gera a página explicando o que ocorreu e o que ainda é confiável."""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(os.path.dirname(HERE), "assets", "dashboard.html")

STATE_PT = {
    "GERADOR_COMPROMETIDO": "GERADOR COMPROMETIDO — nada provado sobre o alvo",
    "ALVO_SATURADO_CONFIRMADO": "ALVO SATURADO — confirmado",
    "ALVO_SATURADO_PROVAVEL": "ALVO SATURADO — provável",
    "CONECTIVIDADE_PROVAVEL": "LIMITAÇÃO DE CONECTIVIDADE — provável",
    "SEM_SATURACAO": "SEM SATURAÇÃO até o pico testado",
    "INCONCLUSIVO": "INCONCLUSIVO",
    "ABORTADO": "TESTE ABORTADO",
}


def _json_for_html(obj):
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    return s.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def write_all(m, outdir, cfg=None):
    rid = m["run"]["id"]
    d = os.path.join(outdir, rid)
    os.makedirs(d, exist_ok=True)
    paths = {}

    def w(name, text, mode="w"):
        p = os.path.join(d, name)
        with open(p, mode, encoding="utf-8", newline="") as f:
            f.write(text)
        paths[name] = p
        return p

    cfg = cfg or m.get("config", {})
    m_lite = dict(m)
    m_lite["config"] = _public_cfg(cfg)
    w("metrics.json", json.dumps(m_lite, ensure_ascii=False, indent=1, default=str))
    w("config.resolved.json", json.dumps(_public_cfg(cfg), ensure_ascii=False, indent=2, default=str))
    w("reproduce.txt", _repro(m, cfg))
    _csvs(m, d, paths)
    w("report.md", technical_report(m))
    try:
        from . import exporters
        ex = os.path.join(d, "exports")
        os.makedirs(ex, exist_ok=True)
        for fn, txt in exporters.build_all(cfg).items():
            with open(os.path.join(ex, fn), "w", encoding="utf-8", newline="\n") as f:
                f.write(txt)
        paths["exports/"] = ex
    except Exception as e:  # exportação nunca derruba o relatório
        paths["exports_error"] = repr(e)
    w("dashboard.html", render_dashboard(m))
    return paths


def _public_cfg(cfg):
    c = json.loads(json.dumps(cfg, default=str))
    for wk in c.get("workers", []):
        if "token" in wk:
            wk["token"] = "***"
    return {k: v for k, v in c.items() if not k.startswith("_")}


def render_dashboard(m):
    with open(TEMPLATE, encoding="utf-8") as f:
        t = f.read()
    return t.replace("/*__DATA__*/null", _json_for_html(m), 1)


def _repro(m, cfg):
    r = m["run"]
    return (f"# Reprodução — run {r['id']}\n"
            f"# config hash: {r.get('config_hash')}  ·  ferramenta: {r.get('tool')}\n"
            f"# Os workers remotos precisam estar de pé:  python loadlab.py worker --host 0.0.0.0 --port 9101 --token $LOADLAB_TOKEN --region <regiao>\n"
            f"python loadlab.py run config.resolved.json --out ./results "
            f"--confirm \"<I-AUTHORIZE host [PRODUCTION]>\"\n"
            f"# tokens de worker não são gravados: informe via token_env / LOADLAB_TOKEN\n")


def _csvs(m, d, paths):
    p = os.path.join(d, "timeseries.csv")
    cols = ["t", "plan", "arr", "sent", "ok", "err", "drop_cap", "drop_sched", "p50", "p90", "p95", "p99", "cp95",
            "ttfb_p95", "conn_p95", "late_p99", "tx", "rx", "nw", "ncomp"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(cols)
        for s in m["series"]:
            wr.writerow([s.get(c) for c in cols])
    paths["timeseries.csv"] = p
    p = os.path.join(d, "workers.csv")
    cols = ["worker", "t", "plan", "sent", "err", "drop_sched", "drop_cap", "p50", "p95", "p99", "late_p99", "ttfb_p95",
            "conn_p95", "cpu_proc", "cpu_sys", "mem", "rx_bps", "tx_bps", "conns", "tw", "ports", "fd", "lag99", "comp", "viol"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(cols)
        for wid, arr in m["workers_series"].items():
            for a in arr:
                wr.writerow([wid] + [(";".join(a[c]) if c == "viol" else a.get(c)) for c in cols[1:]])
    paths["workers.csv"] = p
    p = os.path.join(d, "endpoints.csv")
    cols = ["name", "layer", "n", "err", "err_rate", "p50", "p90", "p95", "p99", "base_p95", "degraded_p95", "ratio"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(cols)
        for e in m["endpoints"]:
            wr.writerow([e.get(c) for c in cols])
    paths["endpoints.csv"] = p


def technical_report(m):
    r, v, t = m["run"], m["verdict"], m.get("totals", {})
    prov = {"measured": "MEDIDO", "demo": "DEMONSTRAÇÃO (dados sintéticos)", "ingested": "IMPORTADO"}.get(m["provenance"], m["provenance"])
    L = [f"# Relatório técnico — {r['name']}", "",
         f"> Procedência dos dados: **{prov}** · Execução `{r['id']}` · Estado: **{r['status']}**" +
         (f" — {r['abort_reason']}" if r.get("abort_reason") else ""), "",
         "## Veredito", "", f"**{STATE_PT.get(v['state'], v['state'])}** (confiança {v['confidence']})", "", v["headline"], ""]
    if v.get("how_to_read"):
        L += [f"_{v['how_to_read']}_", ""]
    L += ["### Suspeitos (perícia diferencial)", "", "| Camada | Pontos | Evidências a favor | Contra | Como confirmar |", "|---|---|---|---|---|"]
    for s in v["suspects"]:
        L.append(f"| {s['layer']} | {s['score']} | {'; '.join(s['evidence']) or '—'} | {'; '.join(s['against']) or '—'} | {s['confirm']} |")
    L += ["", "### Evidências", ""]
    L += [f"- ({e['kind']}) {e['txt']}" for e in v["evidence"]] or ["- (nenhuma)"]
    c = v.get("capacity") or {}
    L += ["", "## Capacidade", "",
          f"- Validada (medida): **{c.get('validated')}** {c.get('unit', '')}" if c.get("validated") else "- Validada: não determinada",
          f"- {c.get('note', '')}"]
    if v.get("knee"):
        k = v["knee"]
        L.append(f"- Joelho: t={k['t']}s, carga ≈ {k['plan']} {m['unit']}, P95 limpo {k['p95']} ms, erros {k['err_rate']}")
    L += ["", "## Totais", "", f"- Requisições concluídas: {t.get('sent')} · erros: {t.get('err')} ({t.get('err_rate')})",
          f"- Latência global (merge de histogramas): P50 {t.get('p50')} · P90 {t.get('p90')} · P95 {t.get('p95')} · P99 {t.get('p99')} ms",
          f"- Iterações descartadas: {t.get('drop_sched')} (gerador) + {t.get('drop_cap')} (teto de VUs)", ""]
    L += ["## Integridade dos geradores", "", "| Worker | Região | Íntegro % | Violações | CPU proc máx | Lag P99 máx (ms) | Portas % máx |", "|---|---|---|---|---|---|---|"]
    for i in m["integrity"]:
        L.append(f"| {i['id']} | {i['region']} | {i['integrity_pct']} | {', '.join(i['violations']) or '—'} | {i['cpu_proc_max']} | {i['lag99_max']} | {i['ports_max']} |")
    L += ["", "## Critérios", ""]
    for it in m["criteria"]["items"]:
        L.append(f"- {'✅' if it['ok'] else '❌'} {it['label']}: {it['value']} (limite {it['limit']})" + ("" if it["trusted"] else " — NÃO confiável (gerador)"))
    if not m["criteria"]["items"]:
        L.append("- (nenhum critério configurado)")
    L += ["", "## Recomendações (por impacto)", ""]
    for x in m["recommendations"]:
        L.append(f"{x['priority']}. **{x['title']}** [{x['layer']}, impacto {x['impact']}] — {x['why']} → {x['action']}")
    rel = m["reliability"]
    L += ["", "## Confiabilidade", "", f"- Amostras perdidas: {rel.get('lost_pct')}%",
          f"- Planejado vs. gerado: {json.dumps(rel.get('planned_vs_generated'), ensure_ascii=False)}",
          f"- Geradores: planejados {m['infra'].get('num_workers_planned')} / efetivos {m['infra'].get('num_workers_effective')}",
          f"- Versão do app: {r.get('app_version')} · versão dos scripts: {r.get('script_version')} · ferramenta {r.get('tool')}",
          f"- Início {r['started_at']} · fim {r['ended_at']} · duração {r.get('duration_actual_s')}s (planejada {r.get('duration_planned_s')}s)",
          "", "### Limitações e interferências", ""]
    L += [f"- {x}" for x in rel["limitations"]] or ["- (nenhuma registrada)"]
    L += ["", "### Eventos", ""] + [f"- t={e['t']}s [{e['level']}] {e['msg']}" for e in r.get("events", [])]
    L += ["", "## Classificação dos dados", "",
          "- **Medido**: contadores/histogramas coletados pelos workers e a vazão/latência/erros derivadas.",
          "- **Estimado**: portas efêmeras quando o SO não expõe estados TCP; capacidade segura (70% do teto calibrado); camada culpada (inferência diferencial).",
          "- **Demonstração**: qualquer página com banner DEMO — dados sintéticos, só para mostrar a interface.", ""]
    return "\n".join(L)


def write_crash(cfg, outdir, err_text, events=None, name="sentinela"):
    """Página de falha: a ferramenta nunca devolve só um traceback."""
    import time
    from . import analysis
    rid = time.strftime("%Y%m%d-%H%M%S") + "-falha"
    col = {"cfg": cfg or {"model": "open", "endpoints": [], "stages": []}, "provenance": "measured", "workers": {},
           "run": {"id": rid, "name": (cfg or {}).get("name", name), "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "ended_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "status": "failed", "abort_reason": err_text,
                   "events": events or [{"t": 0, "level": "error", "msg": err_text}], "duration_planned_s": None,
                   "duration_actual_s": 0, "tool": "sentinela 1.0.0"}}
    m = analysis._empty(col, err_text)
    m["run"] = col["run"]
    m["verdict"]["headline"] = ("A execução falhou antes de gerar dados confiáveis. Nenhuma conclusão sobre o alvo ou "
                                "sobre capacidade pode ser tirada. Motivo: " + err_text)
    m["reliability"]["limitations"] = ["Nenhum resultado desta execução é confiável.", err_text]
    return write_all(m, outdir, cfg=cfg or {})
