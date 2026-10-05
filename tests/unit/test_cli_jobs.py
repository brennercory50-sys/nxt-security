"""CLI: scan / jobs / logs --assessment / scope --resolve / plugins show."""

import json
import socket
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nxtsec.cli.main import cli

EXAMPLE_SCOPE = Path(__file__).resolve().parents[2] / "config" / "scope.example.yaml"


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(EXAMPLE_SCOPE))


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    yield s.getsockname()[1]
    s.close()


def run(*args, log_file=False):
    flags = [] if log_file else ["--no-log-file"]
    return CliRunner().invoke(cli, [*flags, *args], obj={})


def scan_json(*args):
    r = run("scan", "run", *args, "--json")
    return r, (json.loads(r.output) if r.output.strip().startswith("{") else None)


def test_scan_foreground(listener):
    r, d = scan_json("127.0.0.1", "-m", "network.tcp_connect", "-o", f"ports={listener}")
    assert r.exit_code == 0, r.output
    assert d["assessment"]["status"] == "completed"
    [run_] = d["module_runs"]
    assert run_["observations"][0]["state"] == "open"
    assert d["evidence"][0]["verified"] is True


def test_scan_human_output(listener):
    r = run("scan", "run", "127.0.0.1", "-m", "network.tcp_connect", "-o", f"ports={listener}")
    assert r.exit_code == 0
    assert "completed" in r.output and f"127.0.0.1:{listener}" in r.output


def test_scan_refusals():
    r = run("scan", "run", "8.8.8.8", "-m", "network.tcp_connect")
    assert r.exit_code == 3 and "REFUSED" in r.output
    r = run("scan", "run", "127.0.0.1", "-m", "no.such.module")
    assert r.exit_code == 1 and "unknown plugin" in r.output
    r = run("scan", "run", "127.0.0.1", "-m", "network.tcp_connect", "-o", "ports=abc")
    assert r.exit_code == 1 and "invalid port" in r.output
    r = run("scan", "run", "127.0.0.1", "-m", "network.tcp_connect", "-o", "noequals")
    assert r.exit_code == 2
    r = run("scan", "run", "127.0.0.1", "-m", "network.tcp_connect", "--lab")
    assert r.exit_code == 1 and "LAB mode only accepts lab" in r.output
    r = run("scan", "run", "file:/tmp", "-m", "network.tcp_connect")
    assert r.exit_code == 1 and "does not accept file" in r.output


def test_scan_requires_attestation(tmp_path, monkeypatch):
    sc = tmp_path / "scope.yaml"
    sc.write_text("name: noatt\nallow: [127.0.0.0/8]\n")
    monkeypatch.setenv("NXTSEC_PATHS__SCOPE_FILE", str(sc))
    r = run("scan", "run", "127.0.0.1", "-m", "network.tcp_connect")
    assert r.exit_code == 3 and "operator_attestation" in r.output


def test_queue_show_run_cancel(listener):
    r = run(
        "scan",
        "run",
        "127.0.0.1",
        "-m",
        "network.tcp_connect",
        "-o",
        f"ports={listener}",
        "--queue",
        "--json",
    )
    aid = json.loads(r.output)["assessment_id"]
    queued = json.loads(run("jobs", "list", "--status", "queued", "--json").output)
    assert [a["id"] for a in queued] == [aid]

    r = run("jobs", "run", aid, "--json")
    assert r.exit_code == 0 and json.loads(r.output)["assessment"]["status"] == "completed"
    assert run("jobs", "run", aid).exit_code == 1  # not queued any more

    shown = run("jobs", "show", aid)
    assert shown.exit_code == 0 and "verified intact" in shown.output
    assert run("jobs", "show", "asm_nope").exit_code == 1

    r2 = json.loads(
        run("scan", "run", "127.0.0.1", "-m", "dns.resolve", "--queue", "--json").output
    )["assessment_id"]
    c = run("jobs", "cancel", r2)
    assert c.exit_code == 0 and "cancelled" in c.output
    assert run("jobs", "cancel", r2).exit_code == 1


def test_worker_once():
    ids = [
        json.loads(
            run("scan", "run", "127.0.0.1", "-m", "dns.resolve", "--queue", "--json").output
        )["assessment_id"]
        for _ in range(2)
    ]
    r = run("jobs", "worker", "--once")
    assert r.exit_code == 0 and "2 assessment(s) processed" in r.output
    statuses = {a["id"]: a["status"] for a in json.loads(run("jobs", "list", "--json").output)}
    assert all(statuses[i] == "completed" for i in ids)


def test_logs_filtered_by_assessment(listener):
    r = run(
        "scan",
        "run",
        "127.0.0.1",
        "-m",
        "network.tcp_connect",
        "-o",
        f"ports={listener}",
        "--json",
        log_file=True,
    )
    aid = json.loads(r.output)["assessment"]["id"]
    out = run("logs", "--assessment", aid, "-n", "50", log_file=True).output
    assert "assessment started" in out and "[network.tcp_connect]" in out
    assert "assessment completed" in out


def test_background_worker_really_runs(listener):
    r = run(
        "scan",
        "run",
        "127.0.0.1",
        "-m",
        "network.tcp_connect",
        "-o",
        f"ports={listener}",
        "--background",
    )
    assert r.exit_code == 0 and "background (pid" in r.output, r.output
    aid = r.output.split()[0]
    deadline = time.monotonic() + 60
    status = None
    while time.monotonic() < deadline:
        status = json.loads(run("jobs", "show", aid, "--json").output)["assessment"]["status"]
        if status in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.5)
    assert status == "completed"


def test_scope_show_and_resolve():
    d = json.loads(run("scope", "show", "--json").output)
    assert d["fingerprint"] and d["attestation"] and d["expired"] is False
    r = run("scope", "check", "localhost", "--resolve", "--json")
    [res] = json.loads(r.output)
    assert r.exit_code == 0 and res["allowed"] and res["addresses"]


def test_plugins_list_and_show():
    names = {p["name"] for p in json.loads(run("plugins", "list", "--json").output)["plugins"]}
    assert {"dns.resolve", "network.tcp_connect", "forensics.hash"} <= names
    shown = json.loads(run("plugins", "show", "forensics.hash").output)
    assert shown["risk_level"] == "passive" and "read-only" in shown["documentation"].lower()
    assert run("plugins", "show", "nope").exit_code == 1
