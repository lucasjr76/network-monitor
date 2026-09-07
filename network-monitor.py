#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
network-monitor.py — monitor de conexões de rede em tempo real (via ss).

Teclas
  ↑ ↓ / k j     rola uma linha          g   agrupa: nenhum/processo/peer/serviço
  PgUp PgDn     rola uma página         s   filtro: todos/ESTAB/LISTEN
  Home End      início / fim            o   ordena: padrão/tráfego/fila/processo
                                        i   liga/desliga a medição de velocidade
  [ ]           fonte do terminal       d   densidade: normal/compacta/mínima
  + -           intervalo               p   pausa      r  recoleta     q  sai

Uso
  ./network-monitor.py [--interval 1.0] [--iface eth0] [--no-proc]
                       [--no-rates] [--density N]

Notas
  - sem root o ss só identifica o processo dos SEUS sockets; use sudo.
  - --iface limita o contador de tráfego a uma interface. Em host com bridge
    (Proxmox, pfSense virtualizado) somar tudo conta o mesmo pacote 2-3 vezes.
  - TX/s e RX/s vêm da derivada de bytes_sent/bytes_received do tcp_info
    (ss -i), não de captura de pacotes: só TCP, só payload, sem cabeçalhos.
    Por isso os números não batem exatamente com iftop. Em servidor com muitos
    sockets o -i encarece a coleta; use i ou --no-rates para desligar.
  - [ e ] usam OSC 50, suportado por xterm/urxvt. Em gnome-terminal, kitty,
    alacritty e afins nada acontece: use o zoom do próprio terminal. Para ganhar
    linhas de forma portável use d (densidade).
"""

import argparse
import curses
import os
import re
import signal
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

POLL_MS = 60
MIN_COLS, MIN_ROWS = 52, 7
PANEL_MIN_COLS = 112
PANEL_MIN_WIDTH = 26
PANEL_MAX_WIDTH = 34
PANEL_BAR_WIDTH = 8
SCROLLBAR_MIN_TABLE_W = 76
SCROLLBAR_MIN_PAGE = 4
MAX_KEYSTROKES_PER_CYCLE = 64
SPARK_LEN = 24
SS_TIMEOUT_S = 10.0
ESSENTIAL_COL_PRIO = 700

DEBUG = bool(os.environ.get("NETMON_DEBUG"))
RE_PROC = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
RE_SENT = re.compile(r'\bbytes_sent:(\d+)')
RE_ACKED = re.compile(r'\bbytes_acked:(\d+)')
RE_RECV = re.compile(r'\bbytes_received:(\d+)')
BLOCKS = " ▁▂▃▄▅▆▇█"

PENDING = object()
ESTAB = ("ESTAB", "ESTABLISHED")
WILDCARD_PEERS = {"*", "0.0.0.0", "::"}


# ══════════════════════════════════════════════════════════ log (opcional)

def _log_path():
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
    except OSError:
        return None
    return os.path.join(base, "network-monitor.log")


_LOGF = _log_path() if DEBUG else None


def log(*a):
    if not _LOGF:
        return
    try:
        fd = os.open(_LOGF, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {' '.join(map(str, a))}\n")
    except OSError:
        pass


# ══════════════════════════════════════════════════════════ formatação

def human_bytes(b):
    b = float(b)
    for unit, div in (("B", 1.0), ("K", 1024.0), ("M", 1048576.0),
                      ("G", 1073741824.0), ("T", 1099511627776.0)):
        if abs(b) < div * 1024 or unit == "T":
            return f"{b:,.0f} B" if unit == "B" else f"{b / div:,.1f} {unit}"
    return f"{b:,.0f} B"


def human_rate(r):
    if r <= 0:
        return "0 B/s"
    if r >= 1000 * 1048576:
        g = r / 1073741824
        return f"{g:.1f} G/s" if g >= 100 else f"{g:.2f} G/s"
    if r >= 1000 * 1024:
        return f"{r / 1048576:.2f} M/s"
    if r >= 1024:
        return f"{r / 1024:.1f} K/s"
    return f"{r:.0f} B/s"


def compact_int(n):
    if n < 1000:
        return str(n)
    if n < 1000000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1000000:.1f}M"


def pad(s, w, align="<"):
    s = "" if s is None else str(s)
    if w <= 0:
        return ""
    if len(s) > w:
        s = (s[:w - 1] + "…") if w > 1 else s[:1]
    return f"{s:{align}{w}}"


def pad_addr(host, port, w):
    if w <= 0:
        return ""
    full = f"{host}:{port}" if port else str(host)
    if len(full) <= w:
        return f"{full:<{w}}"
    tail = f":{port}" if port else ""
    keep = w - len(tail) - 1
    if keep < 1:
        return pad(full, w)
    return f"{host[:keep]}…{tail}"


def spark(values, w):
    vals = list(values)[-w:]
    if not vals:
        return ""
    top = max(vals)
    if top <= 0:
        return BLOCKS[1] * len(vals)
    return "".join(BLOCKS[max(1, min(8, round(v / top * 8)))] for v in vals)


def _int(x, default=0):
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def normalize_state(state):
    st = str(state).upper()
    return "ESTAB" if st in ESTAB else st


def split_hostport(addr):
    if not addr:
        return "", ""
    if addr.startswith("["):
        host, _, rest = addr.partition("]")
        return host[1:], rest.lstrip(":")
    if addr == ":::*":
        return "::", "*"
    if addr.count(":") > 1:
        host, sep, port = addr.rpartition(":")
        if sep:
            return host or ":", port
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep else (addr, "")


# ══════════════════════════════════════════════════════════ coleta

class SSMissing(Exception):
    pass


def _apply_rate_counters(row, text):
    m = RE_SENT.search(text) or RE_ACKED.search(text)
    if m:
        row["_bs"] = int(m.group(1))
    m = RE_RECV.search(text)
    if m:
        row["_br"] = int(m.group(1))


def parse_ss(out):
    """Converte a saída do ss em dicts."""
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if rows:
                _apply_rate_counters(rows[-1], line)
            continue

        fields = line.split()
        if len(fields) < 6 or fields[0] in ("Netid", "State"):
            continue

        lip, lport = split_hostport(fields[4])
        pip, pport = split_hostport(fields[5])
        tail = " ".join(fields[6:]) if len(fields) > 6 else ""
        proc = pid = ""
        if tail:
            m = RE_PROC.search(tail)
            if m:
                proc, pid = m.group(1), m.group(2)

        row = {
            "netid": fields[0],
            "state": normalize_state(fields[1]),
            "rq": _int(fields[2]),
            "sq": _int(fields[3]),
            "lip": lip,
            "lport": lport,
            "pip": pip,
            "pport": pport,
            "proc": proc,
            "pid": pid,
            "n": 1,
            "rtx": None,
            "rrx": None,
        }
        if tail:
            _apply_rate_counters(row, tail)
        rows.append(row)
    return rows


class InterfaceCounters:
    def __init__(self, iface=None):
        self.iface = iface
        self.iface_error = ""

    def read(self):
        tx = rx = 0
        found_iface = not self.iface
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    name, _, rest = line.partition(":")
                    name = name.strip()
                    if self.iface:
                        if name != self.iface:
                            continue
                        found_iface = True
                    elif name == "lo":
                        continue
                    p = rest.split()
                    if len(p) >= 9:
                        rx += _int(p[0])
                        tx += _int(p[8])
        except OSError:
            return tx, rx, ""
        if self.iface and not found_iface:
            self.iface_error = f"iface '{self.iface}' não encontrada"
        else:
            self.iface_error = ""
        return tx, rx, self.iface_error


class RateTracker:
    def __init__(self):
        self.sock_prev = {}
        self.sock_t = None
        self.no_counters = False

    def reset(self):
        self.sock_prev = {}
        self.sock_t = None
        self.no_counters = False

    def apply(self, rows):
        now = time.monotonic()
        dt = (now - self.sock_t) if self.sock_t else 0.0
        cur, found, tcp_estab = {}, False, 0
        for r in rows:
            if r["netid"] == "tcp" and normalize_state(r["state"]) == "ESTAB":
                tcp_estab += 1
            bs, br = r.pop("_bs", None), r.pop("_br", None)
            if bs is None and br is None:
                continue
            found = True
            bs, br = bs or 0, br or 0
            key = (r["netid"], r["lip"], r["lport"], r["pip"], r["pport"])
            cur[key] = (bs, br)
            prev = self.sock_prev.get(key)
            if prev and dt > 0 and bs >= prev[0] and br >= prev[1]:
                r["rtx"] = (bs - prev[0]) / dt
                r["rrx"] = (br - prev[1]) / dt
        self.sock_prev = cur
        self.sock_t = now
        self.no_counters = bool(tcp_estab) and not found


class Collector:
    _executor = ThreadPoolExecutor(max_workers=1)

    def __init__(self, want_proc=True, iface=None, want_rates=True):
        self.want_proc = want_proc
        self.want_rates = want_rates
        self.ss_ms = 0.0
        self.prev = None
        self.tx = self.rx = 0
        self.rate_tx = self.rate_rx = 0.0
        self.hist_tx = deque(maxlen=SPARK_LEN)
        self.hist_rx = deque(maxlen=SPARK_LEN)
        self.error = ""
        self.ss_error = ""
        self.iface_reader = InterfaceCounters(iface=iface)
        self.rate_tracker = RateTracker()
        self._future = None

    @property
    def iface(self):
        return self.iface_reader.iface

    @property
    def no_counters(self):
        return self.rate_tracker.no_counters

    def _update_error(self):
        self.error = self.ss_error or self.iface_reader.iface_error

    def _ss_args(self, want_proc=None):
        args = ["ss", "-t", "-u", "-a", "-n"]
        if self.want_proc if want_proc is None else want_proc:
            args.append("-p")
        if self.want_rates:
            args.append("-i")
        return args

    def _permission_denied(self, stderr_text):
        text = stderr_text.lower()
        return any(token in text for token in (
            "permission denied",
            "operation not permitted",
            "not permitted",
        ))

    def _finalize_rows(self, rows, elapsed_s):
        self.ss_ms = elapsed_s * 1000
        if self.want_rates:
            self.rate_tracker.apply(rows)
        self.ss_error = ""
        self._update_error()
        return rows

    def _run_ss_once(self, want_proc):
        args = self._ss_args(want_proc=want_proc)
        cp = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SS_TIMEOUT_S,
        )
        return {
            "args": args,
            "returncode": cp.returncode,
            "stdout": cp.stdout,
            "stderr": cp.stderr,
        }

    def _run_ss_blocking(self, want_proc=None):
        want_proc = self.want_proc if want_proc is None else want_proc
        t0 = time.monotonic()
        try:
            result = self._run_ss_once(want_proc)
        except FileNotFoundError:
            raise SSMissing("comando 'ss' não encontrado (pacote iproute2)")
        except subprocess.TimeoutExpired:
            self.ss_error = "ss demorou demais; mantendo dados anteriores"
            self._update_error()
            return None
        stderr_text = result["stderr"].decode(errors="replace").strip()
        if result["returncode"] != 0:
            if want_proc and self._permission_denied(stderr_text):
                self.want_proc = False
                return self._run_ss_blocking(want_proc=False)
            self.ss_error = stderr_text or f"ss retornou {result['returncode']}"
            self._update_error()
            return None
        rows = parse_ss(result["stdout"].decode(errors="replace"))
        return self._finalize_rows(rows, time.monotonic() - t0)

    def ss(self):
        return self._run_ss_blocking()

    def start_fetch(self):
        if self._future is not None:
            return
        self._future = self._executor.submit(self._run_ss_blocking)

    def _clear_fetch(self):
        self._future = None

    def poll_fetch(self):
        if self._future is None:
            return None
        future = self._future
        if not future.done():
            return PENDING
        self._clear_fetch()
        return future.result()

    def counters(self):
        tx, rx, iface_error = self.iface_reader.read()
        self._update_error()
        return tx, rx

    def tick(self):
        now = time.monotonic()
        tx, rx = self.counters()
        if self.prev:
            dt = now - self.prev[0]
            if dt > 0:
                self.rate_tx = max(0.0, (tx - self.prev[1]) / dt)
                self.rate_rx = max(0.0, (rx - self.prev[2]) / dt)
                self.hist_tx.append(self.rate_tx)
                self.hist_rx.append(self.rate_rx)
        self.prev = (now, tx, rx)
        self.tx, self.rx = tx, rx

    def set_rates_enabled(self, enabled):
        self.want_rates = enabled
        self.rate_tracker.reset()


# ══════════════════════════════════════════════════════════ modos

def _k_proc(c):
    return c["proc"] or f"({c['netid']} sem processo)"


def _k_peer(c):
    return c["pip"] or "—"


def _k_serv(c):
    return f"{c['netid']}/{c['lport'] or '—'}"


GROUPS = [("nenhum", None, "LOCAL"),
          ("processo", _k_proc, "PROCESSO"),
          ("peer", _k_peer, "PEER IP"),
          ("serviço", _k_serv, "SERVIÇO")]

FILTERS = [("todos", lambda c: True),
           ("estab", lambda c: normalize_state(c["state"]) == "ESTAB"),
           ("listen", lambda c: normalize_state(c["state"]) == "LISTEN")]

SORTS = ["padrão", "tráfego", "fila", "processo"]


def group_rows(conns, keyfn, by_peer=False):
    buckets = {}
    for conn in conns:
        buckets.setdefault(keyfn(conn), []).append(conn)

    out = []
    for key, items in buckets.items():
        states = {normalize_state(item["state"]) for item in items}
        procs = {item["proc"] for item in items if item["proc"]}
        peers = {
            item["pip"] for item in items
            if item["pip"] and item["pip"] not in WILDCARD_PEERS
        }
        if by_peer:
            ports = {item["lport"] for item in items if item["lport"]}
            detail = f"porta {ports.pop()}" if len(ports) == 1 else f"{len(ports)} portas locais"
        elif len(peers) == 1:
            detail = peers.pop()
        elif peers:
            detail = f"{len(peers)} peers"
        else:
            detail = "—"

        rated = [item for item in items if item["rtx"] is not None]
        out.append({
            "rtx": sum(item["rtx"] for item in rated) if rated else None,
            "rrx": sum(item["rrx"] for item in rated) if rated else None,
            "netid": items[0]["netid"] if len({item["netid"] for item in items}) == 1 else "*",
            "state": states.pop() if len(states) == 1 else "vários",
            "rq": sum(item["rq"] for item in items),
            "sq": sum(item["sq"] for item in items),
            "lip": key,
            "lport": "",
            "pip": detail,
            "pport": "",
            "proc": procs.pop() if len(procs) == 1 else ("vários" if procs else "—"),
            "pid": "",
            "n": len(items),
        })
    return out


def _speed(r):
    return (r["rtx"] or 0) + (r["rrx"] or 0)


def sort_rows(rows, mode, grouped):
    name = SORTS[mode]
    if name == "tráfego":
        return sorted(rows, key=lambda r: (-_speed(r), r["lip"]))
    if grouped:
        return sorted(rows, key=lambda r: (-r["n"], r["lip"]))
    if name == "fila":
        return sorted(rows, key=lambda c: (-(c["rq"] + c["sq"]), c["lip"]))
    if name == "processo":
        return sorted(rows, key=lambda c: (c["proc"] or "\uffff", -(c["rq"] + c["sq"])))
    return sorted(rows, key=lambda c: (c["proc"] or "\uffff", c["netid"], c["lip"],
                                       _int(c["lport"]), c["pip"], _int(c["pport"])))


# ══════════════════════════════════════════════════════════ cores

C_GREEN, C_CYAN, C_YELLOW, C_MAGENTA, C_RED, C_BLUE = 1, 2, 3, 4, 5, 6
DIM = curses.A_DIM


def init_colors():
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        return
    for n, fg in ((C_GREEN, curses.COLOR_GREEN), (C_CYAN, curses.COLOR_CYAN),
                  (C_YELLOW, curses.COLOR_YELLOW), (C_MAGENTA, curses.COLOR_MAGENTA),
                  (C_RED, curses.COLOR_RED), (C_BLUE, curses.COLOR_BLUE)):
        try:
            curses.init_pair(n, fg, -1)
        except curses.error:
            pass


def state_attr(state):
    st = normalize_state(state)
    if st == "ESTAB":
        return curses.color_pair(C_GREEN) | curses.A_BOLD
    if st == "LISTEN":
        return curses.color_pair(C_CYAN)
    if st.startswith("SYN") or st in ("CLOSE-WAIT", "LAST-ACK"):
        return curses.color_pair(C_RED)
    if st in ("TIME-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSING"):
        return curses.color_pair(C_BLUE) | DIM
    if st == "UNCONN":
        return curses.color_pair(C_YELLOW)
    if st == "VÁRIOS":
        return curses.color_pair(C_MAGENTA)
    return 0


# ══════════════════════════════════════════════════════════ motor de colunas

class Col:
    __slots__ = ("key", "titles", "min", "max", "weight", "prio", "align", "fmt", "attr")

    def __init__(self, key, titles, min_w, max_w=None, weight=0, prio=50,
                 align="<", fmt=None, attr=None):
        self.key = key
        self.titles = [titles] if isinstance(titles, str) else list(titles)
        self.min, self.max = min_w, (max_w if max_w is not None else min_w)
        self.weight, self.prio, self.align = weight, prio, align
        self.fmt = fmt or (lambda r, w: pad(r.get(key, ""), w, align))
        self.attr = attr or (lambda r: 0)

    def title_for(self, w, override=None):
        for t in ([override] if override else []) + self.titles:
            if len(t) <= w:
                return t
        return (override or self.titles[-1])[:w]


def _q(key):
    def f(r, w):
        v = r.get(key, 0)
        return pad(compact_int(v) if v else "", w, ">")
    return f


def _q_attr(key):
    return lambda r: (curses.color_pair(C_YELLOW) if r.get(key, 0) else DIM)


def _rate_fmt(key):
    def f(r, w):
        v = r.get(key)
        return pad("" if not v else human_rate(v), w, ">")
    return f


def proc_attr(row):
    return curses.color_pair(C_CYAN) | curses.A_BOLD if row["proc"] else DIM


def pid_attr(row):
    return curses.color_pair(C_YELLOW) | curses.A_BOLD if row["pid"] else DIM


def active_rate_attr(row):
    return curses.A_BOLD if _speed(row) > 0 else 0


def _rate_attr(key, color):
    return lambda r: (curses.color_pair(color) | active_rate_attr(r) if r.get(key) else DIM)


ALL_COLS = [
    Col("n", ("CONN", "N"), 4, 7, 0, 300, ">", fmt=lambda r, w: pad(compact_int(r["n"]), w, ">"), attr=lambda r: curses.A_BOLD),
    Col("netid", ("PROTO", "PRO", "P"), 3, 5, 0, 40, "<", fmt=lambda r, w: pad(r["netid"], w), attr=lambda r: DIM),
    Col("local", "LOCAL", 14, 80, 3, 900, "<", fmt=lambda r, w: pad_addr(r["lip"], r["lport"], w)),
    Col("peer", "PEER", 12, 80, 3, 800, "<", fmt=lambda r, w: pad_addr(r["pip"], r["pport"], w)),
    Col("state", ("STATE", "ST"), 7, 10, 1, 700, "<", fmt=lambda r, w: pad(r["state"], w), attr=lambda r: state_attr(r["state"])),
    Col("rq", ("RECV-Q", "RCVQ", "RQ"), 5, 8, 0, 55, ">", fmt=_q("rq"), attr=_q_attr("rq")),
    Col("sq", ("SEND-Q", "SNDQ", "SQ"), 5, 8, 0, 50, ">", fmt=_q("sq"), attr=_q_attr("sq")),
    Col("proc", ("PROCESSO", "PROC"), 8, 20, 1, 655, "<", fmt=lambda r, w: pad(r["proc"] or "—", w), attr=proc_attr),
    Col("tx", ("TX/s", "TX"), 9, 10, 0, 645, ">", fmt=_rate_fmt("rtx"), attr=_rate_attr("rtx", C_MAGENTA)),
    Col("rx", ("RX/s", "RX"), 9, 10, 0, 640, ">", fmt=_rate_fmt("rrx"), attr=_rate_attr("rrx", C_GREEN)),
    Col("pid", "PID", 7, 7, 0, 660, ">", fmt=lambda r, w: pad(r["pid"], w, ">"), attr=pid_attr),
]
COLS = {c.key: c for c in ALL_COLS}


def solve_layout(keys, width, gap=1):
    active = [COLS[k] for k in keys if k in COLS]

    def need(cs):
        return sum(c.min for c in cs) + gap * max(0, len(cs) - 1)

    while len(active) > 1 and need(active) > width:
        victim = min(active, key=lambda c: c.prio)
        if victim.prio >= ESSENTIAL_COL_PRIO:
            break
        active.remove(victim)

    w = {c.key: c.min for c in active}
    extra = width - need(active)
    if extra < 0:
        for c in sorted(active, key=lambda c: c.prio):
            if extra >= 0:
                break
            take = min(w[c.key] - 1, -extra)
            w[c.key] -= take
            extra += take
        return [(c, w[c.key]) for c in active if w[c.key] > 0]
    for _ in range(8):
        pool = [c for c in active if c.weight > 0 and w[c.key] < c.max]
        if extra <= 0 or not pool:
            break
        total_w = sum(c.weight for c in pool)
        given = 0
        for c in pool:
            add = min(extra * c.weight // total_w, c.max - w[c.key])
            w[c.key] += add
            given += add
        if given == 0:
            for c in pool:
                if given >= extra:
                    break
                w[c.key] += 1
                given += 1
        extra -= given
    if extra > 0 and active:
        widest = max(active, key=lambda c: c.weight)
        if widest.weight:
            w[widest.key] += extra
    return [(c, w[c.key]) for c in active]


def visible_keys(grouped, group_label, rates=True):
    keys = ["netid", "local", "peer", "state", "tx", "rx", "rq", "sq", "proc", "pid"]
    if not rates:
        keys.remove("tx")
        keys.remove("rx")
    if grouped:
        keys.insert(0, "n")
        keys.remove("pid")
        if group_label == "PROCESSO":
            keys.remove("proc")
    return keys


# ══════════════════════════════════════════════════════════ desenho

def put(stdscr, y, x, text, attr=0):
    rows, cols = stdscr.getmaxyx()
    if y < 0 or x < 0 or y >= rows or x >= cols or not text:
        return
    avail = cols - x - (1 if y == rows - 1 else 0)
    if avail <= 0:
        return
    try:
        stdscr.addstr(y, x, text[:avail], attr)
    except curses.error:
        pass


def term_font(step):
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(f"\033]50;#{'+' if step > 0 else '-'}1\007")
            tty.flush()
    except OSError:
        pass


def panel_tables(conns):
    counts, peers = {}, {}
    for row in conns:
        counts[row["proc"] or "—"] = counts.get(row["proc"] or "—", 0) + 1
        ip = row["pip"]
        if ip and ip not in WILDCARD_PEERS:
            peers[ip] = peers.get(ip, 0) + 1
    return counts, peers


def footer_text(cols, pos):
    full = "q sair | ↑↓ rolar | PgUp página | Home/End | g grupo | s filtro | o ordem | i taxas | d densidade | p pausa"
    mid = "q sair | ↑↓ rolar | PgUp | g grupo | s filtro | o ordem | i taxas | d densidade"
    short = "q sair | ↑↓ | g s o i d p"
    label = short
    for candidate in (full, mid, short):
        if len(candidate) + len(pos) + 4 <= cols:
            label = candidate
            break
    return label


class Ui:
    def __init__(self, args):
        self.col = Collector(want_proc=not args.no_proc, iface=args.iface,
                             want_rates=not args.no_rates)
        self.interval = max(0.2, args.interval)
        self.density = min(2, max(0, args.density))
        self.conns = []
        self.scroll = 0
        self.group = self.filt = self.sort = 0
        self.paused = False
        self.running = True
        self.last_fetch = 0.0
        self.fatal = ""
        self._rows_cache = None
        self._panel_cache = None

    def stop(self):
        self.running = False

    def fetch(self):
        try:
            self.col.start_fetch()
            rows = self.col.poll_fetch()
        except SSMissing as e:
            self.fatal = str(e)
            return False
        if rows is PENDING:
            return False
        if rows is not None:
            self.conns = rows
            self.invalidate()
        self.col.tick()
        self.last_fetch = time.monotonic()
        return True

    def rows(self):
        if self._rows_cache is not None:
            return self._rows_cache
        keyfn = GROUPS[self.group][1]
        data = [c for c in self.conns if FILTERS[self.filt][1](c)]
        if keyfn:
            data = group_rows(data, keyfn, by_peer=(keyfn is _k_peer))
        self._rows_cache = sort_rows(data, self.sort, bool(keyfn))
        return self._rows_cache

    def panel_data(self):
        if self._panel_cache is None:
            self._panel_cache = panel_tables(self.conns)
        return self._panel_cache

    def invalidate(self):
        self._rows_cache = None
        self._panel_cache = None

    def geometry(self, rows, cols):
        show_title = self.density < 2 and rows >= 8
        show_sum = self.density < 1 and rows >= 12
        panel = 0
        if cols >= PANEL_MIN_COLS and self.density < 2 and rows >= 12:
            panel = min(PANEL_MAX_WIDTH, max(PANEL_MIN_WIDTH, cols // 4))
        table_w = cols - (panel + 3 if panel else 0)
        y_head = (1 if show_title else 0) + (1 if show_sum else 0)
        y_data = y_head + 1
        page = max(1, rows - y_data - 1)
        bar = 2 if (table_w >= SCROLLBAR_MIN_TABLE_W and page >= SCROLLBAR_MIN_PAGE) else 0
        return {"title": show_title, "sum": show_sum, "panel": panel,
                "table_w": table_w - bar, "bar": bar, "px": cols - panel,
                "y_head": y_head, "y_data": y_data, "page": page}

    def draw(self, stdscr):
        rows, cols = stdscr.getmaxyx()
        stdscr.erase()
        if cols < MIN_COLS or rows < MIN_ROWS:
            put(stdscr, 0, 0, f"Preciso de {MIN_COLS}x{MIN_ROWS}.")
            stdscr.refresh()
            return
        g = self.geometry(rows, cols)
        data = self.rows()
        total = len(data)
        self.scroll = max(0, min(self.scroll, max(0, total - g["page"])))
        grouped = GROUPS[self.group][1] is not None
        label = GROUPS[self.group][2]
        layout = solve_layout(visible_keys(grouped, label, self.col.want_rates), g["table_w"])
        if g["title"]:
            self.draw_title(stdscr, cols)
        if g["sum"]:
            self.draw_summary(stdscr, (1 if g["title"] else 0), g["table_w"])
        self.draw_head(stdscr, g["y_head"], layout, label, grouped)
        self.draw_body(stdscr, g, layout, data)
        if g["bar"]:
            self.draw_scrollbar(stdscr, g, total)
        if g["panel"]:
            self.draw_panel(stdscr, g, rows)
        self.draw_footer(stdscr, rows, cols, g, total)
        stdscr.refresh()

    def draw_title(self, stdscr, cols):
        modes = (f"grupo:{GROUPS[self.group][0]}  filtro:{FILTERS[self.filt][0]}"
                 f"  ordem:{SORTS[self.sort]}  {self.interval:.1f}s"
                 f"{'' if self.col.want_rates else '  taxas:off'}")
        clock = time.strftime("%H:%M:%S") + ("  PAUSADO" if self.paused else "")
        left = " ss-monitor  " + modes
        if len(left) + len(clock) + 2 > cols:
            left = " ss-monitor  " + f"g:{GROUPS[self.group][0]} f:{FILTERS[self.filt][0]}"
        if len(left) + len(clock) + 2 > cols:
            left = " ss-monitor"
        gapw = max(1, cols - 1 - len(left) - len(clock) - 1)
        put(stdscr, 0, 0, (left + " " * gapw + clock + " ")[:cols - 1], curses.A_REVERSE | curses.A_BOLD)

    def draw_summary(self, stdscr, y, w):
        c = self.col
        estab = sum(1 for x in self.conns if normalize_state(x["state"]) == "ESTAB")
        listen = sum(1 for x in self.conns if normalize_state(x["state"]) == "LISTEN")
        x = 0
        for text, attr in (
            (f"{len(self.conns)} sockets", curses.A_BOLD),
            (f"  {estab} estab", curses.color_pair(C_GREEN)),
            (f"  {listen} listen", curses.color_pair(C_CYAN)),
            (f"   ↑ {human_rate(c.rate_tx):>8}", curses.color_pair(C_MAGENTA)),
            (f"  {human_bytes(c.tx):>8}", DIM),
            (f"   ↓ {human_rate(c.rate_rx):>8}", curses.color_pair(C_GREEN)),
            (f"  {human_bytes(c.rx):>8}", DIM),
            (f"   ss {c.ss_ms:.0f}ms", DIM if c.ss_ms < 250 else curses.color_pair(C_YELLOW)),
        ):
            if x + len(text) > w:
                break
            put(stdscr, y, x, text, attr)
            x += len(text)
        if c.no_counters and not c.error and x + 4 < w:
            put(stdscr, y, x + 2, "sem contadores por socket (kernel < 4.6?)"[:w - x - 2], curses.color_pair(C_YELLOW))
        elif c.error and x + 4 < w:
            put(stdscr, y, x + 2, ("! " + c.error)[:w - x - 2], curses.color_pair(C_RED))

    def draw_head(self, stdscr, y, layout, label, grouped):
        x = 0
        for col, w in layout:
            override = None
            if col.key == "local":
                override = label
            elif col.key == "peer" and grouped:
                override = "DETALHE"
            put(stdscr, y, x, pad(col.title_for(w, override), w, col.align), curses.A_UNDERLINE | curses.A_BOLD)
            x += w + 1

    def draw_body(self, stdscr, g, layout, data):
        for i in range(g["page"]):
            idx = self.scroll + i
            if idx >= len(data):
                break
            row = data[idx]
            x = 0
            for col, w in layout:
                put(stdscr, g["y_data"] + i, x, col.fmt(row, w), col.attr(row))
                x += w + 1

    def draw_scrollbar(self, stdscr, g, total):
        x = g["table_w"] + 1
        page, top = g["page"], self.scroll
        if total <= page:
            return
        size = max(1, page * page // total)
        pos = (top * (page - size)) // max(1, total - page)
        for i in range(page):
            on = pos <= i < pos + size
            put(stdscr, g["y_data"] + i, x, "█" if on else "│", curses.color_pair(C_CYAN) if on else DIM)

    def draw_panel(self, stdscr, g, rows):
        px, pw = g["px"], g["panel"]
        for y in range(g["y_head"], rows - 1):
            put(stdscr, y, px - 2, "│", DIM)
        c, y = self.col, g["y_head"]
        put(stdscr, y, px, pad("TRÁFEGO", pw), curses.A_UNDERLINE | curses.A_BOLD)
        y += 1
        sw = min(SPARK_LEN, max(0, pw - 8))
        for arrow, rate, hist, color in (("↑", c.rate_tx, c.hist_tx, C_MAGENTA), ("↓", c.rate_rx, c.hist_rx, C_GREEN)):
            put(stdscr, y, px, f"{arrow} {human_rate(rate)}", curses.color_pair(color))
            y += 1
            put(stdscr, y, px, spark(hist, sw), curses.color_pair(color) | DIM)
            y += 1
        y += 1
        counts, peers = self.panel_data()
        for title, table in (("PROCESSOS", counts), ("PEERS", peers)):
            if y >= rows - 3:
                break
            put(stdscr, y, px, pad(title, pw), curses.A_UNDERLINE | curses.A_BOLD)
            y += 1
            top = sorted(table.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
            big = top[0][1] if top else 1
            cw = max(len(compact_int(n)) for _, n in top) if top else 1
            barw = PANEL_BAR_WIDTH if pw >= PANEL_MIN_WIDTH else 0
            nw = pw - cw - barw - (2 if barw else 1)
            for name, n in top:
                if y >= rows - 1:
                    break
                put(stdscr, y, px, pad(name, nw))
                if barw:
                    fill = max(1, round(n / big * barw)) if big else 0
                    put(stdscr, y, px + nw + 1, "█" * fill, curses.color_pair(C_BLUE))
                    put(stdscr, y, px + nw + 1 + fill, "·" * (barw - fill), DIM)
                put(stdscr, y, px + pw - cw, pad(compact_int(n), cw, ">"), curses.A_BOLD)
                y += 1
            y += 1

    def draw_footer(self, stdscr, rows, cols, g, total):
        pos = f"{self.scroll + 1}-{min(self.scroll + g['page'], total)}/{total}" if total > g["page"] else str(total)
        help_ = footer_text(cols, pos)
        gapw = max(1, cols - 1 - len(help_) - len(pos) - 2)
        put(stdscr, rows - 1, 0, (" " + help_ + " " * gapw + pos + " ")[:cols - 1], curses.A_REVERSE)

    def key(self, k, page, total):
        if k in (ord("q"), ord("Q")):
            return False
        if k in (curses.KEY_UP, ord("k")):
            self.scroll -= 1
        elif k in (curses.KEY_DOWN, ord("j")):
            self.scroll += 1
        elif k == curses.KEY_PPAGE:
            self.scroll -= page
        elif k == curses.KEY_NPAGE:
            self.scroll += page
        elif k in (curses.KEY_HOME, ord("<")):
            self.scroll = 0
        elif k in (curses.KEY_END, ord(">")):
            self.scroll = max(0, total - page)
        elif k in (ord("g"), ord("G")):
            self.group = (self.group + 1) % len(GROUPS)
            self.scroll = 0
            self.invalidate()
        elif k in (ord("s"), ord("S")):
            self.filt = (self.filt + 1) % len(FILTERS)
            self.scroll = 0
            self.invalidate()
        elif k in (ord("o"), ord("O")):
            self.sort = (self.sort + 1) % len(SORTS)
            self.scroll = 0
            self.invalidate()
        elif k in (ord("i"), ord("I")):
            self.col.set_rates_enabled(not self.col.want_rates)
            self.last_fetch = 0
            self.invalidate()
        elif k in (ord("d"), ord("D")):
            self.density = (self.density + 1) % 3
        elif k == ord("["):
            term_font(-1)
        elif k == ord("]"):
            term_font(+1)
        elif k in (ord("p"), ord("P")):
            self.paused = not self.paused
        elif k in (ord("+"), ord("=")):
            self.interval = min(30.0, self.interval + 0.5)
        elif k == ord("-"):
            self.interval = max(0.2, self.interval - 0.5)
        elif k in (ord("r"), ord("R")):
            self.last_fetch = 0
        self.scroll = max(0, min(self.scroll, max(0, total - page)))
        return True


def main_loop(stdscr, ui):
    curses.noecho()
    curses.cbreak()
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.keypad(True)
    stdscr.timeout(POLL_MS)
    init_colors()

    dirty = True
    while ui.running:
        if not ui.paused and time.monotonic() - ui.last_fetch >= ui.interval:
            dirty = ui.fetch() or dirty
        if ui.fatal:
            return ui.fatal
        if dirty:
            ui.draw(stdscr)
            dirty = False
        rows, cols = stdscr.getmaxyx()
        page = ui.geometry(rows, cols)["page"]
        total = len(ui.rows())
        for _ in range(MAX_KEYSTROKES_PER_CYCLE):
            k = stdscr.getch()
            if k == -1:
                break
            dirty = True
            if k == curses.KEY_RESIZE:
                stdscr.clear()
                continue
            if not ui.key(k, page, total):
                ui.stop()
                break
    return ""


def parse_args(argv):
    p = argparse.ArgumentParser(description="Monitor de conexões de rede (ss).")
    p.add_argument("--interval", type=float, default=1.0, help="segundos entre coletas (padrão: 1.0)")
    p.add_argument("--iface", default=None, help="conta tráfego só desta interface (ex.: eth0)")
    p.add_argument("--no-proc", action="store_true", help="não tenta 'ss -p' (mais rápido, sem nome de processo)")
    p.add_argument("--no-rates", action="store_true", help="não usa 'ss -i'; some com TX/s e RX/s e a coleta fica leve")
    p.add_argument("--density", type=int, default=0, choices=(0, 1, 2), help="0 normal, 1 compacta, 2 mínima")
    return p.parse_args(argv)


def install_signal_handlers(ui):
    prev = {}

    def handler(_signum, _frame):
        ui.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        prev[sig] = signal.getsignal(sig)
        signal.signal(sig, handler)
    return prev


def restore_signal_handlers(prev):
    for sig, handler in prev.items():
        signal.signal(sig, handler)


def main():
    args = parse_args(sys.argv[1:])
    ui = Ui(args)
    prev_handlers = install_signal_handlers(ui)
    try:
        err = curses.wrapper(main_loop, ui)
    except KeyboardInterrupt:
        return 0
    finally:
        restore_signal_handlers(prev_handlers)
    if err:
        print(f"erro: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
