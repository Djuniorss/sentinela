#!/usr/bin/env python3
"""sentinela — teste de carga distribuído com perícia de gargalo. Só stdlib (Python 3.9+).

  loadlab.py calibrate                       Régua: teto honesto DESTE gerador (alvo nulo local)
  loadlab.py plan   cfg.json                 mostra a divisão de carga e o portão de autorização (não envia nada)
  loadlab.py run    cfg.json [--confirm ..]  executa; SEMPRE gera dashboard.html + métricas + relatório
  loadlab.py worker --port 9101 --token T    sobe um worker remoto
  loadlab.py demo   [--scenario db|generator|network|healthy]   dashboard sintético (rotulado DEMO)
  loadlab.py sandbox                         SaaS de brinquedo local (banco = gargalo) p/ treinar a perícia
  loadlab.py ingest jtl|k6 arquivo [--config cfg.json]          importa resultados de JMeter/k6
  loadlab.py export cfg.json --out dir       gera k6 / k6-operator / JMeter equivalentes
"""
import argparse
import asyncio
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(prog="loadlab", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("worker")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9101)
    s.add_argument("--token", default="")
    s.add_argument("--id", default="worker")
    s.add_argument("--region", default="local")

    sp.add_parser("nullserver").add_argument("--port", type=int, default=0)
    s = sp.add_parser("sandbox")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--db-pool", type=int, default=8)
    s.add_argument("--db-ms", type=float, default=20.0)

    s = sp.add_parser("calibrate")
    s.add_argument("--max-rate", type=float, default=100000)
    s.add_argument("--out", default="./results")

    for n in ("plan", "run"):
        s = sp.add_parser(n)
        s.add_argument("config")
        s.add_argument("--out", default="./results")
        s.add_argument("--confirm", default=None, help='ex.: "I-AUTHORIZE host" (+ " PRODUCTION")')
        s.add_argument("--calibrate", action="store_true", help="roda a Régua em cada worker antes do teste")

    s = sp.add_parser("demo")
    s.add_argument("--scenario", default="db", choices=["db", "generator", "network", "healthy"])
    s.add_argument("--out", default="./results")

    s = sp.add_parser("ingest")
    s.add_argument("kind", choices=["jtl", "k6"])
    s.add_argument("file")
    s.add_argument("--config", default=None)
    s.add_argument("--out", default="./results")

    s = sp.add_parser("export")
    s.add_argument("config")
    s.add_argument("--out", default="./exports")

    a = ap.parse_args()

    if a.cmd == "worker":
        from loadlab import agent
        agent.serve(a.host, a.port, a.token, a.id, a.region)
    elif a.cmd == "nullserver":
        from loadlab import calibrate
        calibrate.nullserver(a.port)
    elif a.cmd == "sandbox":
        from loadlab import sandbox
        sandbox.run(a.port, db_pool=a.db_pool, db_ms=a.db_ms)
    elif a.cmd == "calibrate":
        from loadlab import calibrate
        res = asyncio.run(calibrate.calibrate({"max_rate": a.max_rate}))
        os.makedirs(a.out, exist_ok=True)
        p = os.path.join(a.out, "calibration.json")
        json.dump(res, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"Régua: teto ≈ {res['ceiling_rps']:g} rps · seguro (70%) ≤ {res['safe_rps']:g} rps")
        print(f"  parou porque: {res['stopped_because']}\n  {res['caveat']}\n  salvo em {p}")
        for st in res["steps"]:
            print(f"   {st['rate']:>8.0f} rps -> {st['achieved_rps']:>8.1f} | cpu {st['cpu_proc_cores_max']:.2f} | lag {st['loop_lag_p99_ms_max']:.1f}ms | {'ok' if st['ok'] else 'VIOLOU ' + ','.join(st['violations'])}")
    elif a.cmd in ("plan", "run"):
        _plan_or_run(a)
    elif a.cmd == "demo":
        from loadlab import demo, analysis, report
        m = analysis.analyze(demo.build(a.scenario))
        paths = report.write_all(m, a.out, cfg=m["config"])
        print(f"DEMO ({a.scenario}) · veredito: {m['verdict']['state']}\n  {m['verdict']['headline']}\n  abra: {paths['dashboard.html']}")
    elif a.cmd == "ingest":
        from loadlab import ingest, analysis, report
        cfg = json.load(open(a.config, encoding="utf-8")) if a.config else None
        col = (ingest.ingest_jtl if a.kind == "jtl" else ingest.ingest_k6)(a.file, cfg)
        m = analysis.analyze(col)
        paths = report.write_all(m, a.out, cfg=col["cfg"])
        print(f"veredito: {m['verdict']['state']}\n  {m['verdict']['headline']}\n  abra: {paths['dashboard.html']}")
    elif a.cmd == "export":
        from loadlab import exporters, controller
        cfg = controller.load_config(a.config)
        os.makedirs(a.out, exist_ok=True)
        for fn, txt in exporters.build_all(cfg).items():
            open(os.path.join(a.out, fn), "w", encoding="utf-8", newline="\n").write(txt)
            print("  +", os.path.join(a.out, fn))


def _plan_or_run(a):
    from loadlab import controller, safety, report
    try:
        cfg = controller.load_config(a.config)
    except Exception as e:
        sys.exit(f"config inválido: {e}")
    if a.cmd == "plan":
        ok, msgs = safety.check(cfg, a.confirm)
        print(f"Modelo: {cfg['model'].upper()} ({'taxa de chegada — alvo lento NÃO reduz a carga' if cfg['model']=='open' else 'VUs — alvo lento reduz a carga'})")
        print(f"Pico planejado: {safety.peak(cfg):g} {'req/s' if cfg['model']=='open' else 'VUs'} · duração {sum(s['duration'] for s in cfg['stages'])}s")
        ws = []
        for spec in cfg["workers"]:
            n = int(spec.get("local", 1)) if "local" in spec else 1
            for i in range(n):
                ws.append({"id": spec.get("id", "local") + (f"-{i+1}" if "local" in spec else ""), "region": spec.get("region", "?"),
                           "share": spec.get("share", 1.0) / n})
        controller.split_load(cfg, ws)
        for w in ws:
            print(f"  {w['id']:<12} [{w['region']}] {w['share']*100:5.1f}%  pico {w['planned_peak']:.1f}")
        print("Autorização:", "OK" if ok else "RECUSADA")
        for m in msgs:
            print("  -", m)
        return
    log = print
    print(f"== sentinela · {cfg['name']} ==")
    run = controller.Run(cfg, a.out, confirm=a.confirm, calibrate=a.calibrate, log=log)
    try:
        m, paths = asyncio.run(run.execute())
    except SystemExit as e:
        msg = str(e)
        print(msg)
        if "RECUSADO" in msg:
            sys.exit(2)
        report.write_crash(cfg, a.out, msg, run.events)
        sys.exit(1)
    except KeyboardInterrupt:
        report.write_crash(cfg, a.out, "interrompido pelo operador antes de coletar dados", run.events)
        sys.exit(130)
    except Exception as e:
        tb = traceback.format_exc()
        print(tb)
        p = report.write_crash(cfg, a.out, f"erro interno do controlador: {e!r}", run.events)
        print("Página de falha gerada:", p["dashboard.html"])
        sys.exit(1)
    v = m["verdict"]
    print(f"\nVeredito: {v['state']} (confiança {v['confidence']}) — {v['location']}\n  {v['headline']}")
    cap = v.get("capacity") or {}
    if cap.get("validated"):
        print(f"  capacidade validada: {cap['validated']} req/s")
    print(f"\nDashboard : {paths['dashboard.html']}\nRelatório : {paths['report.md']}\nMétricas  : {paths['metrics.json']}")


if __name__ == "__main__":
    main()
