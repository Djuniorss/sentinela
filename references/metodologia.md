# Metodologia da Sentinela

## Integridade do gerador (por worker, por segundo)
Violado se qualquer: loop lag P99 > 25 ms · envio atrasado P99 > 50 ms · CPU do processo > 0,90 núcleo (asyncio é 1 thread) · CPU sistema > 90% · RAM > 92% · portas efêmeras > 70% · FD > 80% · descartes do gerador > 1% · chegadas < 95% do planejado.
Segundo 0 (aquecimento) e segundos após stop não são julgados. Limiares em `loadlab/health.py` (`LIMITS`).
Descartes por teto de VUs (`drop_cap`) são contados à parte: com gerador saudável, indicam alvo lento (ou `max_vus` pequeno), não gerador.

## Latências
`resp` = do envio real até o fim da resposta (timeouts entram como latência ≥ limite). `late` = atraso do gerador antes de enviar. `ttfb`, `conn` separados. Tudo em histogramas log-lineares (erro ≤ ~1%) somados entre workers.

## Joelho e capacidade
Janelas de 5 s. Linha de base = janelas de baixa carga (≤25% do pico) **na subida**. Degradada se P95 limpo > max(3×base, base+50 ms) ou erro > max(2%, base+1pp), com ≥90% de confiança do gerador. Joelho = 1ª janela degradada seguida de outra (ou do fim). Capacidade validada = maior vazão sustentada ≥ 10 s em janelas íntegras e não degradadas — **medida, não extrapolada**.

## Perícia diferencial
- Camadas: razão do P95 pós-joelho / base por `layer`; degradada se ≥ 2,5× ou erro ≥ 2%.
- Região isolada: só conta se o acréscimo em ms for ≥ 3× o das outras (causa comum soma o mesmo atraso em todas).
- Sinais: TTFB×, connect×, % 429/5xx, % timeouts, % falhas de conexão, EADDRNOTAVAIL (→ gerador), canário.
- Pontuação 0–100 por suspeito = **estimativa**, não probabilidade.

## Critérios
`criteria.pass` (p95_ms, p99_ms, error_rate, per_endpoint) avaliado no patamar; "APROVADO" sem gerador íntegro vira "não conclusivo". `criteria.abort` (error_rate, p95_ms, window_s, generator_compromised_frac, canary_failures) interrompe e ainda gera relatório.

## Distribuição sem duplicação
Open: share×taxa (frações somam 1). Closed: maior-resto nos alvos de estágio. IDs intercalados (`local*N+idx`). Soma verificada por asserção. Início sincronizado por offset de relógio (handshake, melhor de 7). Worker indisponível: política `abort` (padrão) ou `redistribute` no pré-voo; durante o teste a parcela dele **não** é redistribuída (registrada como carga não gerada).
