"""Exporta o MESMO cenário para k6 (local, segmentos, k6 Operator) e Apache JMeter (-R).

Armadilhas que o README gerado deixa explícitas:
  k6 Operator  : o script leva a carga TOTAL; o operador fatia por execution segment (parallelism=N).
  k6 manual    : cada máquina roda o mesmo script com --execution-segment (frações que somam 1).
  JMeter -R    : CADA worker executa o plano INTEIRO. Threads do plano = por worker, não total
                 (senão a carga multiplica por N — duplicação acidental clássica).
"""
import json
import urllib.parse
from fractions import Fraction


def _shares(cfg):
    ws = []
    for w in cfg.get("workers", [{"local": 1}]):
        n = int(w.get("local", 1)) if "local" in w else 1
        ws += [w.get("share", 1.0) / n] * n
    t = sum(ws)
    return [x / t for x in ws]


def _dur(s):
    return f"{int(s)}s"


def k6_script(cfg):
    open_m = cfg["model"] == "open"
    peak = max(s["target"] for s in cfg["stages"])
    stages = [{"duration": _dur(s["duration"]), "target": s["target"]} for s in cfg["stages"]]
    if open_m:
        mv = int(cfg.get("max_vus") or max(50, peak * float(cfg.get("timeout", 10)) / 4))
        ex = {"executor": "ramping-arrival-rate", "startRate": cfg.get("start_value", 0), "timeUnit": "1s",
              "preAllocatedVUs": max(10, mv // 4), "maxVUs": mv, "stages": stages}
    else:
        ex = {"executor": "ramping-vus", "startVUs": cfg.get("start_value", 0), "stages": stages,
              "gracefulRampDown": "10s"}
    p = (cfg.get("criteria") or {}).get("pass") or {}
    th = {}
    if p.get("p95_ms") or p.get("p99_ms"):
        t = []
        if p.get("p95_ms"):
            t.append(f"p(95)<{p['p95_ms']}")
        if p.get("p99_ms"):
            t.append(f"p(99)<{p['p99_ms']}")
        th["http_req_duration"] = t
    if p.get("error_rate") is not None:
        th["http_req_failed"] = [f"rate<{p['error_rate']}"]
    base = cfg["target"]["base_url"].rstrip("/")
    eps = [{"name": e["name"], "layer": e.get("layer", "unknown"), "method": e.get("method", "GET"), "path": e["path"],
            "weight": e.get("weight", 1), "headers": e.get("headers", {}), "body": e.get("body")} for e in cfg["endpoints"]]
    tn = cfg.get("tenants") or {}
    return f"""// Gerado por sentinela — modelo {'ABERTO (taxa de chegada)' if open_m else 'FECHADO (VUs)'}
// Carga TOTAL aqui. k6 Operator / --execution-segment dividem entre os workers; NÃO divida à mão.
import http from 'k6/http';

export const options = {{
  scenarios: {{ main: {json.dumps(ex)} }},
  thresholds: {json.dumps(th)},
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
}};

const BASE = __ENV.BASE_URL || {json.dumps(base)};
const EPS = {json.dumps(eps, ensure_ascii=False)};
const TOTAL = EPS.reduce((a, e) => a + e.weight, 0);
const TENANTS = {int(tn.get('count', 0))};
const ZIPF = {json.dumps(tn.get('distribution') == 'zipf')};
const TH = {json.dumps(tn.get('tenant_header', 'X-Tenant-Id'))};
const UH = {json.dumps(tn.get('user_header', 'X-User-Id'))};

function pickEp() {{
  let r = Math.random() * TOTAL;
  for (const e of EPS) {{ if ((r -= e.weight) <= 0) return e; }}
  return EPS[EPS.length - 1];
}}
function pickTenant() {{
  if (!TENANTS) return '';
  const i = ZIPF ? Math.floor(Math.pow(Math.random(), 3) * TENANTS) : Math.floor(Math.random() * TENANTS);
  return 't' + String(i).padStart(4, '0');
}}

export default function () {{
  const e = pickEp();
  const tenant = pickTenant();
  const user = `${{tenant}}-u${{__VU}}`;
  const headers = Object.assign({{}}, e.headers);
  if (TENANTS) {{ headers[TH] = tenant; headers[UH] = user; }}
  const path = e.path.replace('{{tenant}}', tenant).replace('{{user}}', user).replace('{{seq}}', String(__ITER));
  http.request(e.method, BASE + path, e.body, {{ headers, tags: {{ endpoint: e.name, layer: e.layer }} }});
}}
"""


def k6_segments_sh(cfg):
    sh = _shares(cfg)
    n = len(sh)
    fr, acc = [Fraction(0)], Fraction(0)
    for s in sh[:-1]:
        acc += Fraction(s).limit_denominator(1000)
        fr.append(acc)
    fr.append(Fraction(1))
    seq = ",".join(str(f) for f in fr)
    L = ["#!/usr/bin/env bash", "# k6 em várias máquinas SEM operador: cada máquina i roda com seu segmento.",
         "# As frações somam 1 => nenhuma carga duplicada/omitida. Inicie todas ao mesmo tempo (ex.: ssh paralelo / at).",
         "set -euo pipefail", f"SEQ={seq}"]
    for i in range(n):
        L.append(f'# máquina {i+1}: k6 run --execution-segment "{fr[i]}:{fr[i+1]}" --execution-segment-sequence "$SEQ" '
                 f'--out json=k6-w{i+1}.json k6-script.js')
    return "\n".join(L) + "\n"


def k6_operator(cfg):
    n = len(_shares(cfg))
    name = "".join(c if c.isalnum() else "-" for c in cfg.get("name", "loadlab").lower()).strip("-")[:40] or "loadlab"
    return f"""# Requer k6-operator instalado no cluster (https://github.com/grafana/k6-operator).
# 1) kubectl create configmap {name}-script --from-file=k6-script.js
# 2) kubectl apply -f k6-testrun.yaml
# O operador cria {n} runners e fatia a carga por execution segment automaticamente.
apiVersion: k6.io/v1alpha1
kind: TestRun
metadata:
  name: {name}
spec:
  parallelism: {n}
  script:
    configMap:
      name: {name}-script
      file: k6-script.js
  separate: true          # 1 runner por nó/pod isolado: evita gerador disputando CPU com outro pod
  runner:
    env:
      - name: BASE_URL
        value: "{cfg['target']['base_url']}"
    resources:
      requests: {{ cpu: "1", memory: 512Mi }}
      limits:   {{ cpu: "2", memory: 1Gi }}
    # Dica: use nodeSelector/affinity para espalhar por regiões e antiAffinity para não empilhar runners.
"""


def jmeter_plan(cfg):
    sh = _shares(cfg)
    n = len(sh)
    peak = max(s["target"] for s in cfg["stages"])
    dur = int(sum(s["duration"] for s in cfg["stages"]))
    ramp = int(cfg["stages"][0]["duration"]) if len(cfg["stages"]) > 1 else 0
    open_m = cfg["model"] == "open"
    threads = max(1, round((peak if not open_m else int(cfg.get("max_vus") or max(50, peak * 2))) / n))
    u = urllib.parse.urlsplit(cfg["target"]["base_url"])
    port = u.port or (443 if u.scheme == "https" else 80)
    tot = sum(e.get("weight", 1) for e in cfg["endpoints"])
    from xml.sax.saxutils import quoteattr, escape
    smp = []
    for e in cfg["endpoints"]:
        pct = 100.0 * e.get("weight", 1) / tot
        smp.append(f"""        <ThroughputController guiclass="ThroughputControllerGui" testclass="ThroughputController" testname="{escape(e['name'])} ({pct:.1f}%)">
          <intProp name="ThroughputController.style">1</intProp>
          <boolProp name="ThroughputController.perThread">false</boolProp>
          <FloatProperty><name>ThroughputController.percentThroughput</name><value>{pct:.2f}</value><savedValue>0.0</savedValue></FloatProperty>
        </ThroughputController>
        <hashTree>
          <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname={quoteattr(e['name'])}>
            <stringProp name="HTTPSampler.domain">{escape(u.hostname)}</stringProp>
            <stringProp name="HTTPSampler.port">{port}</stringProp>
            <stringProp name="HTTPSampler.protocol">{u.scheme}</stringProp>
            <stringProp name="HTTPSampler.path">{escape(u.path.rstrip('/') + e['path'])}</stringProp>
            <stringProp name="HTTPSampler.method">{e.get('method', 'GET')}</stringProp>
            <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
          </HTTPSamplerProxy>
          <hashTree/>
        </hashTree>""")
    ctt = ""
    if open_m:
        per_min = peak * 60.0 / n
        ctt = f"""        <ConstantThroughputTimer guiclass="TestBeanGUI" testclass="ConstantThroughputTimer" testname="vazão alvo por worker (APROXIMA taxa de chegada)">
          <intProp name="calcMode">0</intProp>
          <stringProp name="throughput">${{__P(rpm,{per_min:.0f})}}</stringProp>
        </ConstantThroughputTimer>
        <hashTree/>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Gerado por sentinela. NÃO validado contra um JMeter real nesta máquina: abra no GUI uma vez e salve. -->
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="{escape(cfg.get('name','loadlab'))}"/>
    <hashTree>
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="usuários (POR WORKER)">
        <stringProp name="ThreadGroup.num_threads">${{__P(threads,{threads})}}</stringProp>
        <stringProp name="ThreadGroup.ramp_time">{ramp}</stringProp>
        <boolProp name="ThreadGroup.scheduler">true</boolProp>
        <stringProp name="ThreadGroup.duration">{dur}</stringProp>
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController" guiclass="LoopControlPanel" testclass="LoopController">
          <intProp name="LoopController.loops">-1</intProp>
          <boolProp name="LoopController.continue_forever">false</boolProp>
        </elementProp>
      </ThreadGroup>
      <hashTree>
{ctt}{chr(10).join(smp)}
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>
"""


def jmeter_sh(cfg):
    n = len(_shares(cfg))
    peak = max(s["target"] for s in cfg["stages"])
    open_m = cfg["model"] == "open"
    thr = max(1, round((peak if not open_m else int(cfg.get("max_vus") or max(50, peak * 2))) / n))
    return f"""#!/usr/bin/env bash
# JMeter distribuído (https://jmeter.apache.org/usermanual/remote-test.html)
# ATENÇÃO: com -R, CADA worker roda o plano inteiro. Por isso threads={thr} é POR WORKER (total ≈ {thr*n}).
# Pré-requisitos: mesma versão do JMeter em todos, jmeter-server rodando nos workers (RMI),
# portas 1099/50000 liberadas entre controlador e workers, e (Java 8+) keystore RMI ou server.rmi.ssl.disable=true em rede privada.
set -euo pipefail
WORKERS="${{WORKERS:?ex: WORKERS=10.0.0.11,10.0.0.12}}"
jmeter -n -t jmeter-plan.jmx -R "$WORKERS" \\
  -Gthreads={thr} {'-Grpm=' + str(int(peak*60/n)) + ' ' if open_m else ''}\\
  -Jjmeter.save.saveservice.hostname=true -Jjmeter.save.saveservice.output_format=csv \\
  -l results.jtl
# Depois, gere a perícia:  python loadlab.py ingest jtl results.jtl --config config.resolved.json
# (JTL não traz saúde do gerador: o veredito sobre o alvo será rebaixado — monitore os workers à parte.)
"""


def readme(cfg):
    return """# Exportações — leia antes de rodar

| Alvo | Como a carga é dividida | Armadilha |
|---|---|---|
| k6 local | 1 máquina | confirme a Régua do gerador antes (`loadlab.py calibrate`) |
| k6 segmentos (`k6-segments.sh`) | frações que somam 1 | rode todas as máquinas ao mesmo tempo |
| k6 Operator (`k6-testrun.yaml`) | `parallelism` = nº de runners | o script leva a carga TOTAL; não divida à mão |
| JMeter `-R` (`jmeter-plan.jmx`) | cada worker roda o plano inteiro | threads = POR worker; JMeter é modelo fechado — Constant Throughput Timer só APROXIMA taxa de chegada |

Modelo aberto (taxa de chegada) ≠ modelo fechado (VUs): não troque um pelo outro sem decidir qual pergunta você está respondendo.
O JMX foi gerado por template e não foi validado em um JMeter real aqui.
"""


def build_all(cfg):
    if not cfg or not cfg.get("endpoints"):
        return {}
    return {"k6-script.js": k6_script(cfg), "k6-segments.sh": k6_segments_sh(cfg), "k6-testrun.yaml": k6_operator(cfg),
            "jmeter-plan.jmx": jmeter_plan(cfg), "jmeter-remote.sh": jmeter_sh(cfg), "README-exports.md": readme(cfg)}
