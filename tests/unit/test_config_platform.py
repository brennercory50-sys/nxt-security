from pathlib import Path

import pytest

from nxtsec.config.settings import load_settings
from nxtsec.core.errors import ConfigError
from nxtsec.platform.detect import PlatformInfo, default_home, detect_platform


def _root(tmp_path: Path, text: str = "") -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yaml").write_text(text)
    return tmp_path


def test_defaults_and_file(tmp_path):
    root = _root(tmp_path, "logging:\n  level: DEBUG\n")
    s = load_settings(env={}, project_root=root)
    assert s.get("logging.level") == "DEBUG"
    assert s.get("execution.default_timeout") == 60
    assert s.scope_file == root / "config" / "scope.yaml"


def test_env_override(tmp_path):
    root = _root(tmp_path)
    s = load_settings(
        env={"NXTSEC_LOGGING__LEVEL": "ERROR", "NXTSEC_LOGGING__JSON": "true"}, project_root=root
    )
    assert s.get("logging.level") == "ERROR" and s.get("logging.json") is True
    assert "environment" in s.sources


@pytest.mark.parametrize(
    "text",
    [
        "logging:\n  level: LOUD\n",
        "- list\n",
        "execution:\n  default_timeout: -1\n",
        "key: [unclosed\n",
        "tools: 5\n",
    ],
)
def test_invalid_config(tmp_path, text):
    with pytest.raises(ConfigError):
        load_settings(env={}, project_root=_root(tmp_path, text))


def test_missing_explicit_config(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(config_path=tmp_path / "missing.yaml", env={}, project_root=tmp_path)


def test_sqlite_default_url(tmp_path):
    s = load_settings(env={"NXTSEC_HOME": str(tmp_path / "h")}, project_root=_root(tmp_path))
    assert s.database_url.startswith("sqlite:///")


def test_termux_detection():
    p = detect_platform({"PREFIX": "/data/data/com.termux/files/usr"})
    if p.system in ("termux", "linux"):
        assert p.is_termux == (p.system == "termux")


@pytest.mark.parametrize(
    ("system", "env", "expect"),
    [
        ("windows", {"LOCALAPPDATA": "C:/Users/x/AppData/Local"}, "NXT-Security"),
        ("linux", {"XDG_DATA_HOME": "/xdg"}, "nxt-security"),
        ("termux", {}, "nxt-security"),
        ("macos", {}, "NXT-Security"),
    ],
)
def test_default_home_per_platform(system, env, expect):
    info = PlatformInfo(system, "", "", "", system == "termux", False)
    assert default_home(info, env).name == expect


def test_nxtsec_home_override(tmp_path):
    assert default_home(env={"NXTSEC_HOME": str(tmp_path)}) == tmp_path
