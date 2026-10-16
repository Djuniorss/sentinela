"""SaaS de brinquedo para treinar a perícia com medições REAIS (não sintéticas).

Camadas conhecidas: /health (edge) · /api/app (app, sem banco) · /api/db (banco com pool pequeno).
O banco é o gargalo por construção: pool × (1/db_ms) req/s. A skill deve apontar o banco —
e NÃO acusar o alvo se o gerador estiver saturado. Serve para validar a ferramenta.
"""
import asyncio
import json
import random


async def serve(port=0, db_pool=8, db_ms=20.0, app_ms=3.0, queue_limit=300):
    db = asyncio.Semaphore(db_pool)
    waiting = {"n": 0}

    async def handle(r, w):
        try:
            while True:
                head = await r.readuntil(b"\r\n\r\n")
                path = head.split(b" ", 2)[1].decode()
                if path.startswith("/health"):
                    code, body = 200, b'{"ok":true}'
                elif path.startswith("/api/app"):
                    await asyncio.sleep(app_ms / 1000 * random.uniform(.7, 1.4))
                    code, body = 200, b'{"app":"ok"}'
                elif path.startswith("/api/db"):
                    if waiting["n"] >= queue_limit:
                        code, body = 503, b'{"error":"db pool exhausted"}'
                    else:
                        waiting["n"] += 1
                        try:
                            async with db:
                                await asyncio.sleep(db_ms / 1000 * random.uniform(.7, 1.4))
                        finally:
                            waiting["n"] -= 1
                        code, body = 200, b'{"db":"ok"}'
                else:
                    code, body = 404, b"{}"
                w.write(f"HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                await w.drain()
                if b"connection: close" in head.lower():
                    break
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            w.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", port, backlog=4096)
    print("PORT", srv.sockets[0].getsockname()[1], flush=True)
    async with srv:
        await srv.serve_forever()


def run(port=0, **kw):
    try:
        asyncio.run(serve(port, **kw))
    except KeyboardInterrupt:
        pass
