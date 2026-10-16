"""Portão de autorização: nenhum teste de alta intensidade sai sem autorização explícita.

Regras:
  - alvo em loopback (127.x/localhost/::1): livre.
  - qualquer outro alvo: bloco `authorization` no config com host, responsável, ambiente, validade.
  - alta intensidade (pico >= limiar) além disso exige --confirm "I-AUTHORIZE <host>".
  - ambiente 'production' exige allow_production=true E o texto "... PRODUCTION" no --confirm.
  - teto de rps/vus declarado na autorização é obrigatório e vale mesmo com --confirm.
"""
import datetime
import fnmatch
from urllib.parse import urlsplit

LOCAL = ("127.", "localhost", "::1")
HIGH_RPS, HIGH_VUS = 200.0, 100.0


def is_local(host):
    return host == "localhost" or host == "::1" or host.startswith("127.")


def peak(cfg):
    return max([s["target"] for s in cfg["stages"]] + [cfg.get("start_value", 0)])


def check(cfg, confirm=None):
    """Retorna (ok, [mensagens]). Não lança."""
    msgs = []
    host = urlsplit(cfg["target"]["base_url"]).hostname or ""
    pk = peak(cfg)
    open_model = cfg["model"] == "open"
    thr = cfg.get("intensity_threshold", {})
    high = pk >= (thr.get("rps", HIGH_RPS) if open_model else thr.get("vus", HIGH_VUS))
    if is_local(host):
        return True, [f"alvo local ({host}): sem exigência de autorização"]
    a = cfg.get("authorization")
    if not a:
        return False, [f"alvo remoto '{host}' sem bloco 'authorization' no config. "
                       "Declare host, authorized_by, environment e expires."]
    ok = True
    pats = a.get("target_hosts") or [a.get("target_host", "")]
    if not any(fnmatch.fnmatch(host, p) for p in pats if p):
        ok = False
        msgs.append(f"host '{host}' não consta na autorização ({pats})")
    if not a.get("authorized_by"):
        ok = False
        msgs.append("authorization.authorized_by vazio (quem autoriza?)")
    env = a.get("environment")
    if env not in ("dev", "test", "staging", "sandbox", "production"):
        ok = False
        msgs.append("authorization.environment deve ser dev|test|staging|sandbox|production")
    try:
        exp = datetime.date.fromisoformat(str(a.get("expires", ""))[:10])
        if exp < datetime.date.today():
            ok = False
            msgs.append(f"autorização expirou em {exp}")
    except ValueError:
        ok = False
        msgs.append("authorization.expires ausente/ inválido (AAAA-MM-DD)")
    cap = a.get("max_rps" if open_model else "max_vus")
    if cap is None:
        ok = False
        msgs.append(f"authorization.{'max_rps' if open_model else 'max_vus'} é obrigatório (teto autorizado)")
    elif pk > cap:
        ok = False
        msgs.append(f"pico planejado {pk:g} excede o teto autorizado {cap:g}")
    prod = env == "production"
    if prod and not a.get("allow_production"):
        ok = False
        msgs.append("ambiente production exige authorization.allow_production=true")
    if high or prod:
        want = f"I-AUTHORIZE {host}" + (" PRODUCTION" if prod else "")
        if (confirm or "").strip() != want:
            ok = False
            msgs.append(f"alta intensidade/produção: passe --confirm \"{want}\"")
    if ok:
        msgs.append(f"autorizado por {a['authorized_by']} para {host} ({env}), teto {cap:g}")
    return ok, msgs
