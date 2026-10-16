---
name: sentinela
description: Teste de carga distribuído que acusa o culpado CERTO. Orquestra workers (nativos, k6, k6 Operator, JMeter) em várias máquinas/regiões, vigia a saúde de cada gerador e entrega um dashboard HTML autocontido com a perícia - gerador, rede, borda, app ou banco. Use ao testar carga/capacidade/stress de SaaS ou API, quando alguém diz "testar de uma máquina só não adianta", "o teste de carga deu ruim, é a app ou é o gerador?", "load test distribuído", "k6/JMeter em várias máquinas", "capacidade máxima", "gargalo", "VUs vs RPS".
---

# Sentinela — primeiro prove o gerador, depois acuse o alvo

Quase todo teste de carga falha na mesma pergunta: **a lentidão é do sistema testado ou da máquina que gera a carga?**
A Sentinela só responde isso com evidência — e quando não dá, diz "inconclusivo" e o que falta medir.

## O que a torna diferente (o tempero)

1. **Régua** (`calibrate`): antes de testar, mede o teto honesto do gerador contra um alvo nulo local. Carga acima de 70% do teto = gerador mente.
2. **Selo de integridade por segundo**: cada worker se vigia (event loop atrasado, envio atrasado, CPU no teto, portas efêmeras, FDs, descartes). Segundo violado é **excluído do agregado limpo**. Veredito sobre o alvo só usa janelas limpas.
3. **Sentinelas por camada**: cada endpoint recebe `layer` (edge|app|db|cache|queue|external). Se `/health` e `/app` ficam planos e `/db` degrada → banco. Se tudo degrada junto → app/infra. Se só uma região degrada com **acréscimo em ms diferente** das demais → rota. É diagnóstico diferencial, não palpite.
4. **Canário independente**: sonda fora dos geradores confirma se a degradação é real.
5. **Causa vs. consequência**: gerador que piora *depois* do alvo, por conexões/portas, é consequência — não invalida o joelho.
6. **Rótulo de procedência** em todo número: MEDIDO · ESTIMADO · DEMO · IMPORTADO.
7. **Sempre entrega página**: mesmo com falha, abort ou crash, gera dashboard explicando o que ocorreu e o que ainda é confiável.

## Regras invioláveis

- **Nunca** acuse o alvo se o gerador estava comprometido nas janelas do joelho. Estados: `GERADOR_COMPROMETIDO`, `ALVO_SATURADO_CONFIRMADO|PROVAVEL`, `CONECTIVIDADE_PROVAVEL`, `SEM_SATURACAO`, `INCONCLUSIVO`, `ABORTADO`.
- **VUs ≠ RPS.** `model: "open"` = taxa de chegada (alvo lento NÃO reduz carga). `model: "closed"` = VUs com think time (alvo lento reduz carga). Pergunte qual pergunta o usuário quer responder; nunca converta um no outro.
- **Percentil global = merge de histogramas.** Nunca média de percentis.
- **Sem autorização, não dispara.** Alvo não-loopback exige bloco `authorization` (host, responsável, ambiente, validade, teto). Alta intensidade exige `--confirm "I-AUTHORIZE <host>"`; produção exige também `allow_production` e `... PRODUCTION`. **Nunca** preencha autorização nem `--confirm` por conta própria: peça ao usuário.
- Banco só é "culpado" por inferência diferencial — rotule como estimado e peça telemetria do banco para confirmar.

## Fluxo

1. Entender: alvo, ambiente, pergunta (concorrência ou taxa?), SLO, quem autoriza. Use `assets/examples/sandbox.json` como molde.
2. Escrever o config (endpoints com `layer` + ao menos 1 sentinela sem banco, `canary_url`, rampa de baixa carga antes do pico, `criteria.pass/abort`).
3. `python scripts/loadlab.py plan cfg.json` — mostra divisão de carga e portão de autorização, sem enviar nada.
4. Em cada máquina de carga: `python scripts/loadlab.py calibrate`; workers remotos: `worker --host 0.0.0.0 --port 9101 --token $LOADLAB_TOKEN --region gru` (1 worker ≈ 1 núcleo: suba N por host).
5. `python scripts/loadlab.py run cfg.json --calibrate [--confirm "..."]`.
6. Abrir `results/<run>/dashboard.html`; ler o veredito, ressalvas e recomendações ao usuário com fidelidade (inclusive "inconclusivo").

Saídas por execução: `dashboard.html` (autocontido), `metrics.json`, `timeseries.csv`, `workers.csv`, `endpoints.csv`, `config.resolved.json`, `reproduce.txt`, `report.md`, `exports/` (k6, segmentos, k6 Operator, JMeter).

## Outros comandos

| Comando | Uso |
|---|---|
| `demo --scenario db\|generator\|network\|healthy` | dashboard SINTÉTICO (banner DEMO) para mostrar a interface |
| `sandbox` | SaaS de brinquedo local (banco = gargalo) para treinar/validar a perícia |
| `ingest jtl\|k6 arquivo --config cfg.json` | importa JMeter/k6; sem saúde do gerador → veredito rebaixado |
| `export cfg.json --out dir` | k6 / `k6-testrun.yaml` (Operator) / JMeter `-R` |

## Armadilhas de plataforma (resumo; detalhes em `references/plataformas.md`)

- k6 Operator: script leva carga **total**, o operador fatia. JMeter `-R`: cada worker roda o plano **inteiro** → threads são por worker.
- Windows/macOS: algumas métricas do SO ficam `n/a` (nunca inventadas); portas efêmeras viram estimativa.
- Calibração em loopback não valida NIC nem rota até o alvo.

Metodologia e limiares: `references/metodologia.md`.
