"""RÉGUA — calibração do gerador contra um alvo NULO.

Antes de acusar o alvo, descubra o teto honesto deste gerador: sobe um servidor nulo
(resposta fixa, sem lógica) em OUTRO processo e sobe a taxa de chegada até o gerador
começar a mentir (loop atrasado, envio atrasado, CPU no teto, iterações descartadas).

Limites do método (declarados no relatório): mede CPU/event-loop/SO em loopback.
NÃO mede a placa de rede nem a rota até o alvo real — use iperf3/probe para isso.
O teto é um PISO conservador: o servidor nulo compete pela mesma máquina.
"""
import asyncio
import os
import subprocess
import sys
import time

from .engine import Engine

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Null(asyncio.Protocol):
    RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"

    def connection_made(self, t):
        self.t = t

    def data_received(self, d):
        for _ in range(d.count(b"\r\n\r\n")):
            self.t.write(self.RESP)


def nullserver(port=0):
    async def main():
        loop = asyncio.get_running_loop()
        srv = await loop.create_server(_Null, "127.0.0.1", port, backlog=4096)
        print("PORT", srv.sockets[0].getsockname()[1], flush=True)
        await srv.serve_forever()
    asyncio.run(main())


def _stage_cfg(port, rate, secs):
    return {"model": "open", "target": {"base_url": f"http://127.0.0.1:{port}"},
            "endpoints": [{"name": "nulo", "path": "/", "weight": 1}],
            "stages": [{"duration": secs, "target": rate}], "start_value": rate,
            "timeout": 3, "max_inflight": 4000, "seed": 7}


async def calibrate(opts):
    secs = int(opts.get("step_seconds", 3))
    start = float(opts.get("start_rate", 200))
    max_rate = float(opts.get("max_rate", 100000))
    p = subprocess.Popen([sys.executable, os.path.join(_HERE, "loadlab.py"), "nullserver"],
                         stdout=subprocess.PIPE, text=True)
    port = int(p.stdout.readline().split()[1])
    steps, ceiling, why = [], 0.0, "limite máximo configurado atingido sem violação"
    try:
        rate = start
        while rate <= max_rate:
            eng = Engine(_stage_cfg(port, rate, secs), time.time() + 0.2)
            await eng.run()
            hs = [h for s, h in eng.healthlog.items() if s >= 1] or list(eng.healthlog.values())
            bad = [h for h in hs if h["compromised"]]
            tot = eng.totals
            achieved = tot["sent"] / (secs + 0.0) if secs else 0
            st = {"rate": rate, "achieved_rps": round(achieved, 1),
                  "cpu_proc_cores_max": max((h["cpu_proc_cores"] for h in hs), default=0),
                  "loop_lag_p99_ms_max": max((h["loop_lag_p99_ms"] for h in hs), default=0),
                  "drop_sched": tot["drop_sched"], "errors": tot["err"],
                  "violations": sorted({v["k"] for h in bad for v in h["violations"]}),
                  "ok": not bad and tot["err"] == 0 and achieved >= 0.95 * rate}
            steps.append(st)
            if not st["ok"]:
                why = "primeira violação: " + (", ".join(st["violations"]) or
                                                ("erros" if tot["err"] else "taxa abaixo de 95% do planejado"))
                break
            ceiling = rate
            rate *= 1.6
    finally:
        p.terminate()
    return {"kind": "calibration", "prov": "measured", "method": "loopback vs. servidor nulo (processo separado)",
            "ceiling_rps": round(ceiling, 1), "safe_rps": round(ceiling * 0.7, 1),
            "stopped_because": why, "steps": steps,
            "caveat": "Piso conservador em loopback; não valida NIC nem rota de rede até o alvo.",
            "when": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
