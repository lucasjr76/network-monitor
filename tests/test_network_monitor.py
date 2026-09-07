from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "network-monitor.py"
spec = importlib.util.spec_from_file_location("network_monitor_under_test", SCRIPT_PATH)
nm = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = nm
spec.loader.exec_module(nm)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ss"


def read_fixture(name):
    return (FIXTURE_DIR / name).read_text()


def parse_fixture(name):
    return nm.parse_ss(read_fixture(name))


def make_row(**overrides):
    row = {
        "netid": "tcp",
        "state": "ESTAB",
        "rq": 0,
        "sq": 0,
        "lip": "127.0.0.1",
        "lport": "8080",
        "pip": "1.1.1.1",
        "pport": "443",
        "proc": "curl",
        "pid": "123",
        "n": 1,
        "rtx": None,
        "rrx": None,
    }
    row.update(overrides)
    return row


def test_group_rows_normalizes_estab_state():
    rows = [
        make_row(state="ESTAB"),
        make_row(state="ESTABLISHED"),
    ]

    grouped = nm.group_rows(rows, lambda _: "srv")

    assert grouped[0]["state"] == "ESTAB"


@pytest.mark.parametrize(
    ("addr", "expected"),
    [
        ("127.0.0.1:22", ("127.0.0.1", "22")),
        ("[2001:db8::1]:443", ("2001:db8::1", "443")),
        ("*:80", ("*", "80")),
        (":::*", ("::", "*")),
        ("", ("", "")),
    ],
)
def test_split_hostport_handles_common_ss_formats(addr, expected):
    assert nm.split_hostport(addr) == expected


def test_counters_invalid_iface_sets_error_once(monkeypatch):
    collector = nm.Collector(iface="naoexiste0")

    @contextmanager
    def fake_open(*_a, **_k):
        yield iter([
            "Inter-|   Receive                                                |  Transmit\n",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
            "  eth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n",
        ])

    monkeypatch.setattr(nm, "open", fake_open, raising=False)

    tx, rx = collector.counters()

    assert (tx, rx) == (0, 0)
    assert "iface" in collector.error.lower()
    assert "naoexiste0" in collector.error


def test_ss_fallback_only_on_permission_error(monkeypatch):
    collector = nm.Collector(want_proc=True, want_rates=False)
    calls = []

    def fake_run(args, stdout, stderr, timeout):
        calls.append(list(args))
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"ss: some other failure")

    monkeypatch.setattr(nm.subprocess, "run", fake_run)

    rows = collector.ss()

    assert rows is None
    assert collector.want_proc is True
    assert calls == [["ss", "-t", "-u", "-a", "-n", "-p"]]
    assert "some other failure" in collector.error


def test_ss_fallback_retries_without_proc_on_permission_error(monkeypatch):
    collector = nm.Collector(want_proc=True, want_rates=False)
    calls = []

    def fake_run(args, stdout, stderr, timeout):
        calls.append(list(args))
        if "-p" in args:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"Permission denied")
        return SimpleNamespace(
            returncode=0,
            stdout=(
                b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                b"tcp ESTAB 0 0 127.0.0.1:8080 1.2.3.4:443\n"
            ),
            stderr=b"",
        )

    monkeypatch.setattr(nm.subprocess, "run", fake_run)

    rows = collector.ss()

    assert collector.want_proc is False
    assert len(rows) == 1
    assert calls == [
        ["ss", "-t", "-u", "-a", "-n", "-p"],
        ["ss", "-t", "-u", "-a", "-n"],
    ]


def test_start_fetch_reuses_single_inflight_job(monkeypatch):
    collector = nm.Collector(want_proc=False, want_rates=False)
    submissions = []

    class FakeFuture:
        def done(self):
            return False

    class FakeExecutor:
        def submit(self, fn):
            submissions.append(fn)
            return FakeFuture()

    monkeypatch.setattr(collector, "_executor", FakeExecutor())

    collector.start_fetch()
    collector.start_fetch()

    assert len(submissions) == 1
    assert collector.poll_fetch() is nm.PENDING


def test_fetch_uses_completed_background_result(monkeypatch):
    ui = nm.Ui(nm.parse_args([]))
    ui.col = SimpleNamespace(
        ss_ms=0.0,
        no_counters=False,
        error="",
        want_rates=True,
        rate_tx=0.0,
        rate_rx=0.0,
        hist_tx=[],
        hist_rx=[],
        tx=0,
        rx=0,
        start_fetch=lambda: None,
        poll_fetch=lambda: [make_row()],
        tick=lambda: None,
    )

    ui.fetch()

    assert len(ui.conns) == 1
    assert ui.last_fetch > 0


def test_fetch_handles_timeout_without_blocking_result(monkeypatch):
    ui = nm.Ui(nm.parse_args([]))
    ui.col = SimpleNamespace(
        ss_ms=0.0,
        no_counters=False,
        error="mantendo dados anteriores",
        want_rates=True,
        rate_tx=0.0,
        rate_rx=0.0,
        hist_tx=[],
        hist_rx=[],
        tx=0,
        rx=0,
        start_fetch=lambda: None,
        poll_fetch=lambda: None,
        tick=lambda: None,
    )
    ui.conns = [make_row(proc="old")]

    ui.fetch()

    assert ui.conns[0]["proc"] == "old"


def test_parse_ss_reads_inline_and_indented_tcp_info():
    out = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process

tcp ESTAB 0 0 127.0.0.1:8080 1.2.3.4:443 users:((\"curl\",pid=123,fd=5)) bytes_sent:100 bytes_received:50
    cubic wscale:7,7 rto:204 bytes_sent:120 bytes_received:70
"""
    rows = nm.parse_ss(out)

    assert len(rows) == 1
    assert rows[0]["_bs"] == 120
    assert rows[0]["_br"] == 70


@pytest.mark.parametrize(
    "fixture_name",
    [
        "ss-tu-an.txt",
        "ss-tu-an-p.txt",
        "ss-tu-an-i.txt",
        "ss-tu-an-p-i.txt",
    ],
)
def test_parse_ss_real_fixtures_return_rows(fixture_name):
    rows = parse_fixture(fixture_name)

    assert rows
    assert all("netid" in row and "lip" in row and "pip" in row for row in rows)


def test_parse_ss_proc_fixture_extracts_process_names():
    rows = parse_fixture("ss-tu-an-p.txt")

    assert any(row["proc"] for row in rows)
    assert any(row["pid"] for row in rows)


def test_parse_ss_rate_fixture_extracts_socket_counters():
    rows = parse_fixture("ss-tu-an-p-i.txt")

    assert any("_bs" in row or "_br" in row for row in rows)


def test_parse_ss_fixture_preserves_ipv6_scope_and_wildcards():
    rows = parse_fixture("ss-tu-an-p-i.txt")

    assert any("%" in row["lip"] for row in rows)
    assert any(row["pport"] == "*" for row in rows)


def test_pid_column_fits_linux_pid_max_without_ellipsis():
    pid_col = nm.COLS["pid"]
    rendered = pid_col.fmt(make_row(pid="4194304"), pid_col.min)

    assert pid_col.min >= 7
    assert rendered.strip() == "4194304"
    assert "…" not in rendered


def test_pid_column_is_more_important_than_rates():
    assert nm.COLS["pid"].prio > nm.COLS["tx"].prio
    assert nm.COLS["pid"].prio > nm.COLS["rx"].prio


def test_pid_attr_is_not_dim_when_pid_exists(monkeypatch):
    monkeypatch.setattr(nm.curses, "color_pair", lambda n: n * 100)

    assert nm.pid_attr(make_row(pid="123")) & nm.curses.A_BOLD
    assert nm.pid_attr(make_row(pid="")) == nm.DIM


def test_active_rate_attr_is_bold(monkeypatch):
    monkeypatch.setattr(nm.curses, "color_pair", lambda n: n * 100)
    attr = nm.active_rate_attr(make_row(rtx=2048, rrx=0))

    assert attr & nm.curses.A_BOLD


def test_footer_text_prefers_clean_labels():
    text = nm.footer_text(cols=120, pos="25/900")

    assert "q sair" in text
    assert "↑↓ rolar" in text
    assert "PgUp/PgDn" not in text
