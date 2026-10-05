import sys

import pytest

from nxtsec.core.errors import CommandError, CommandTimeout
from nxtsec.safety.execution import run_command

PY = sys.executable


def test_runs_argv():
    r = run_command([PY, "-c", "print('hi')"], timeout=20)
    assert r.ok and r.stdout.strip() == "hi"


def test_shell_metacharacters_are_literal(tmp_path):
    marker = tmp_path / "pwned"
    r = run_command([PY, "-c", "import sys; print(sys.argv[1])", f"; touch {marker}"], timeout=20)
    assert r.stdout.strip() == f"; touch {marker}"
    assert not marker.exists()


@pytest.mark.parametrize("bad", ["echo hi", b"echo", [], [PY, 1], [PY, "a\x00b"]])
def test_rejects_bad_argv(bad):
    with pytest.raises(CommandError):
        run_command(bad)


def test_missing_binary():
    with pytest.raises(CommandError, match="not found"):
        run_command(["definitely-not-a-real-tool-xyz"])


def test_timeout_kills():
    with pytest.raises(CommandTimeout):
        run_command([PY, "-c", "import time; time.sleep(10)"], timeout=0.5)


@pytest.mark.parametrize("t", [0, -1, 10**9])
def test_invalid_timeout(t):
    with pytest.raises(CommandError):
        run_command([PY, "-c", "pass"], timeout=t)


def test_output_cap():
    r = run_command([PY, "-c", "print('x'*5000)"], timeout=20, max_output=100)
    assert r.truncated and len(r.stdout) == 100


def test_nonzero_exit_is_reported_not_raised():
    r = run_command([PY, "-c", "import sys; sys.exit(4)"], timeout=20)
    assert r.returncode == 4 and not r.ok
