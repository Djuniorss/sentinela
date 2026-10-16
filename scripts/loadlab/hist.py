"""Histograma log-linear mergeável (erro relativo <= ~1%).

Percentil global SÓ pode sair de histogramas somados — nunca da média de percentis.
Valores em milissegundos.
"""
import math

_BASE = 1.02
_LOGB = math.log(_BASE)
_FLOOR = 0.01  # ms


def _idx(ms):
    if ms <= _FLOOR:
        return 0
    return int(math.log(ms / _FLOOR) / _LOGB) + 1


def _val(i):
    if i <= 0:
        return _FLOOR
    return _FLOOR * _BASE ** (i - 0.5)


class Hist:
    __slots__ = ("c", "n", "s", "mx")

    def __init__(self):
        self.c = {}
        self.n = 0
        self.s = 0.0
        self.mx = 0.0

    def add(self, ms):
        i = _idx(ms)
        self.c[i] = self.c.get(i, 0) + 1
        self.n += 1
        self.s += ms
        if ms > self.mx:
            self.mx = ms

    def merge(self, other):
        if other is None:
            return self
        if isinstance(other, dict):
            other = Hist.from_dict(other)
        for i, k in other.c.items():
            self.c[i] = self.c.get(i, 0) + k
        self.n += other.n
        self.s += other.s
        if other.mx > self.mx:
            self.mx = other.mx
        return self

    def q(self, p):
        """Percentil p (0-100). None se vazio."""
        if self.n == 0:
            return None
        target = max(1, math.ceil(self.n * p / 100.0))
        acc = 0
        for i in sorted(self.c):
            acc += self.c[i]
            if acc >= target:
                return min(_val(i), self.mx) if p < 100 else self.mx
        return self.mx

    def mean(self):
        return self.s / self.n if self.n else None

    def summary(self):
        if self.n == 0:
            return {"n": 0}
        return {"n": self.n, "mean": round(self.mean(), 3), "p50": round(self.q(50), 3),
                "p90": round(self.q(90), 3), "p95": round(self.q(95), 3),
                "p99": round(self.q(99), 3), "max": round(self.mx, 3)}

    def to_dict(self):
        return {"c": {str(k): v for k, v in self.c.items()}, "n": self.n,
                "s": round(self.s, 3), "mx": round(self.mx, 3)}

    @staticmethod
    def from_dict(d):
        h = Hist()
        if not d:
            return h
        h.c = {int(k): v for k, v in d.get("c", {}).items()}
        h.n = d.get("n", 0)
        h.s = d.get("s", 0.0)
        h.mx = d.get("mx", 0.0)
        return h


def merged(hists):
    out = Hist()
    for h in hists:
        out.merge(h)
    return out
