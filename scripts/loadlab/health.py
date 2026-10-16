"""Saúde do gerador: o que a máquina de carga mede sobre SI MESMA.

Cada campo que a plataforma não permite medir fica None (nunca inventado).
`prov` diz de onde veio cada número: measured | estimated | n/a.
"""
import os
import sys
import time

IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
NCPU = os.cpu_count() or 1


# ---- leitores de plataforma ------------------------------------------------
def _sys_cpu_times():
    """(idle, total) acumulados do sistema, ou None."""
    try:
        if IS_LINUX:
            with open("/proc/stat") as f:
                p = [float(x) for x in f.readline().split()[1:]]
            return p[3] + (p[4] if len(p) > 4 else 0), sum(p)
        if IS_WIN:
            import ctypes
            from ctypes import wintypes
            i, k, u = (wintypes.FILETIME() for _ in range(3))
            ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
            v = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
            idle, kern, user = v(i), v(k), v(u)
            return idle, kern + user  # kernel já inclui idle
    except Exception:
        pass
    return None


def _mem_pct():
    try:
        if IS_LINUX:
            m = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":")
                    m[k] = float(v.split()[0])
            return round(100 * (1 - m["MemAvailable"] / m["MemTotal"]), 1)
        if IS_WIN:
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong)] + \
                           [(n, ctypes.c_ulonglong) for n in
                            ("tp", "ap", "tpf", "apf", "tv", "av", "ae")]
            ms = MS()
            ms.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return float(ms.load)
    except Exception:
        pass
    return None


def _net_bytes():
    """(rx, tx) bytes do SISTEMA (só Linux). Windows usa os contadores próprios."""
    if IS_LINUX:
        try:
            rx = tx = 0
            with open("/proc/net/dev") as f:
                for line in list(f)[2:]:
                    name, data = line.split(":")
                    if name.strip() == "lo":
                        continue
                    c = data.split()
                    rx += int(c[0])
                    tx += int(c[8])
            return rx, tx
        except Exception:
            pass
    return None


def _tcp_states():
    """{'established':n,'time_wait':n} do sistema (só Linux)."""
    if not IS_LINUX:
        return None
    out = {"established": 0, "time_wait": 0}
    try:
        for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
            if not os.path.exists(fn):
                continue
            with open(fn) as f:
                next(f)
                for line in f:
                    st = line.split()[3]
                    if st == "01":
                        out["established"] += 1
                    elif st == "06":
                        out["time_wait"] += 1
        return out
    except Exception:
        return None


def _fd_info():
    if IS_LINUX:
        try:
            import resource
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            return len(os.listdir("/proc/self/fd")), soft
        except Exception:
            pass
    return None


def _port_range():
    if IS_LINUX:
        try:
            with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
                a, b = f.read().split()
            return int(b) - int(a) + 1, "measured"
        except Exception:
            pass
    return (16384 if IS_WIN else 28232), "estimated"  # defaults do SO


def static_facts():
    pr, prov = _port_range()
    fd = _fd_info()
    return {"cpus": NCPU, "platform": sys.platform, "python": sys.version.split()[0],
            "ephemeral_port_range": pr, "ephemeral_port_range_prov": prov,
            "fd_limit": fd[1] if fd else None}


# ---- amostrador -------------------------------------------------------------
class Sampler:
    """Chame sample(counters) 1x/s. counters: dict com conns, tx, rx (acumulados)."""

    def __init__(self):
        self.t0 = time.time()
        self.cpu0 = time.process_time()
        self.sys0 = _sys_cpu_times()
        self.net0 = _net_bytes()
        self.tx0 = self.rx0 = 0
        self.port_range, self.port_prov = _port_range()

    def sample(self, c, lag_ms_max, lag_ms_p99):
        now = time.time()
        dt = max(now - self.t0, 1e-6)
        cpu = time.process_time()
        proc_cores = (cpu - self.cpu0) / dt  # 1.0 = um núcleo inteiro (teto do asyncio)
        s = _sys_cpu_times()
        sys_pct = None
        if s and self.sys0 and s[1] > self.sys0[1]:
            sys_pct = round(100 * (1 - (s[0] - self.sys0[0]) / (s[1] - self.sys0[1])), 1)
        n = _net_bytes()
        rx_bps = tx_bps = None
        net_prov = "n/a"
        if n and self.net0:
            rx_bps, tx_bps = (n[0] - self.net0[0]) / dt, (n[1] - self.net0[1]) / dt
            net_prov = "measured"
        else:  # contadores do próprio gerador: payload HTTP apenas (sem headers de TCP)
            rx_bps, tx_bps = (c["rx"] - self.rx0) / dt, (c["tx"] - self.tx0) / dt
            net_prov = "measured(payload do gerador)"
        tcp = _tcp_states()
        tw = tcp["time_wait"] if tcp else 0
        ports_used = c["conns"] + tw
        fd = _fd_info()
        out = {
            "t": round(now, 3),
            "cpu_proc_cores": round(proc_cores, 3),
            "cpu_sys_pct": sys_pct,
            "mem_pct": _mem_pct(),
            "rx_bps": round(rx_bps), "tx_bps": round(tx_bps), "net_prov": net_prov,
            "conns_own": c["conns"],
            "tcp_established": tcp["established"] if tcp else None,
            "tcp_time_wait": tcp["time_wait"] if tcp else None,
            "ports_pct": round(100 * ports_used / self.port_range, 1),
            "ports_prov": "measured" if tcp else "estimated(só conexões próprias)",
            "fd_used": fd[0] if fd else None,
            "fd_pct": round(100 * fd[0] / fd[1], 1) if fd and fd[1] else None,
            "loop_lag_max_ms": round(lag_ms_max, 2),
            "loop_lag_p99_ms": round(lag_ms_p99, 2),
        }
        self.t0, self.cpu0, self.sys0, self.net0 = now, cpu, s, n
        self.tx0, self.rx0 = c["tx"], c["rx"]
        return out


# ---- veredito de integridade do gerador ------------------------------------
LIMITS = {
    "loop_lag_p99_ms": 25.0,     # event loop atrasado => timestamps mentem
    "late_p99_ms": 50.0,         # envio atrasado vs. instante planejado
    "cpu_proc_cores": 0.90,      # asyncio é single-thread: 1.0 = teto
    "cpu_sys_pct": 90.0,
    "mem_pct": 92.0,
    "ports_pct": 70.0,
    "fd_pct": 80.0,
    "drop_ratio": 0.01,
    "achieved_ratio": 0.95,
}


def judge_second(h, late_p99, drop_ratio, achieved_ratio):
    """Devolve lista de violações [(chave, valor, limite)] para um segundo."""
    v = []

    def chk(key, val, lim, hi=True):
        if val is None:
            return
        if (val > lim) if hi else (val < lim):
            v.append((key, val, lim))
    chk("loop_lag_p99_ms", h.get("loop_lag_p99_ms"), LIMITS["loop_lag_p99_ms"])
    chk("late_p99_ms", late_p99, LIMITS["late_p99_ms"])
    chk("cpu_proc_cores", h.get("cpu_proc_cores"), LIMITS["cpu_proc_cores"])
    chk("cpu_sys_pct", h.get("cpu_sys_pct"), LIMITS["cpu_sys_pct"])
    chk("mem_pct", h.get("mem_pct"), LIMITS["mem_pct"])
    chk("ports_pct", h.get("ports_pct"), LIMITS["ports_pct"])
    chk("fd_pct", h.get("fd_pct"), LIMITS["fd_pct"])
    chk("drop_ratio", drop_ratio, LIMITS["drop_ratio"])
    chk("achieved_ratio", achieved_ratio, LIMITS["achieved_ratio"], hi=False)
    return v


def improve_timer():
    """Windows: timer padrão tem ~15,6 ms de granularidade — pedir 1 ms evita falso 'event loop atrasado'."""
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.winmm.timeBeginPeriod(1)
        except Exception:
            pass
