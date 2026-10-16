# Plataformas

Referências oficiais: JMeter remote-test e distributed step-by-step (jmeter.apache.org/usermanual), k6 running-distributed-tests / set-up-distributed-k6 (grafana.com/docs/k6), github.com/grafana/k6-operator.

## Motor nativo (padrão)
Só stdlib, HTTP/1.1, keepalive. 1 worker = 1 núcleo. Remoto: `worker --host 0.0.0.0 --token T` (recusa bind externo sem token); controlador fala JSON/HTTP com header `X-LoadLab-Token`. Use rede privada/VPN/túnel — o canal não é TLS.
Config remoto: `{"id":"gru-1","region":"sa-east","url":"http://10.0.0.5:9101","token_env":"TOKEN_GRU","share":0.5}`.

## k6
`export` gera `k6-script.js` (carga total, `ramping-arrival-rate` ou `ramping-vus`, tags endpoint/layer), `k6-segments.sh` (multi-máquina com `--execution-segment`) e `k6-testrun.yaml` (Operator: `parallelism`, `separate: true`). Resultados: `k6 run --out json=x.json` → `ingest k6 x.json`.

## JMeter
Gera `jmeter-plan.jmx` (não validado em JMeter real — abra e salve no GUI) e `jmeter-remote.sh`. Cada worker roda o plano inteiro: threads = por worker. JMeter é modelo fechado; Constant Throughput Timer só aproxima taxa de chegada. Habilite `saveservice.hostname=true` para o JTL identificar workers. `ingest jtl results.jtl`.

## Kubernetes
Prefira k6 Operator para escala; 1 runner por nó (`separate: true`, antiAffinity), requests=limits de CPU para não competir com vizinhos (gerador comprometido por throttling do cgroup aparece como loop lag).

## Limites de observabilidade
Linux: CPU/RAM/rede/TCP/FD/portas medidos. Windows: CPU/RAM medidos; rede = payload do gerador; TCP/FD/portas estimados. Calibração em loopback mede CPU/event loop, não NIC nem rota.
