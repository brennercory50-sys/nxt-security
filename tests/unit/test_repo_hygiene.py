"""Repository hygiene: source must be committable; secrets and runtime data must not be."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout"
)


def _ignored(paths: list[str]) -> set[str]:
    r = subprocess.run(  # noqa: S603 - fixed argv
        ["git", "check-ignore", "--stdin"],  # noqa: S607
        input="\n".join(paths),
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    return {line.strip().replace("\\", "/") for line in r.stdout.splitlines() if line.strip()}


def test_no_source_file_is_ignored():
    sources = [
        p.relative_to(ROOT).as_posix()
        for d in ("nxtsec", "tests")
        for p in (ROOT / d).rglob("*")
        if p.suffix in (".py", ".yaml", ".md") and "__pycache__" not in p.parts
    ]
    assert sources and _ignored(sources) == set()


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.production",
        "config/scope.yaml",
        "config/local.yaml",
        "evidence/a.json",
        "logs/nxtsec.jsonl",
        "data/x",
        "capture.pcap",
        "nxtsec.db",
        "server.key",
        "id_rsa",
    ],
)
def test_sensitive_paths_are_ignored(path):
    assert path in _ignored([path])


def test_env_example_is_not_ignored():
    assert _ignored([".env.example"]) == set()
