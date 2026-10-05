from pathlib import Path

from nxtsec.config.settings import load_settings
from nxtsec.core.doctor import Doctor, Level
from nxtsec.integrations.tools import ToolRegistry, ToolSpec
from nxtsec.platform.detect import PlatformInfo
from nxtsec.plugins.registry import PluginRegistry

PLAT = PlatformInfo("linux", "6", "x86_64", "3.11", False, False)


def _settings(tmp_path: Path, extra: str = "", scope: str | None = "allow: [127.0.0.1]\n"):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "config.yaml").write_text(extra)
    if scope is not None:
        (tmp_path / "config" / "scope.yaml").write_text(scope)
    return load_settings(env={"NXTSEC_HOME": str(tmp_path / "home")}, project_root=tmp_path)


def _tools(required=False):
    spec = ToolSpec(
        "ghosttool",
        "d",
        "test",
        "ghost-tool-xyz",
        ("-v",),
        r"(\d+)",
        "",
        {"linux": "n/a"},
        required=required,
    )
    return ToolRegistry((spec,), system="linux")


def _run(settings, tools=None, plat=PLAT, env=None):
    return Doctor(settings, plat, tools or _tools(), PluginRegistry, env=env or {}).run()


def _get(report, name):
    return next(c for c in report.checks if c.name == name)


def test_degraded_when_optional_missing(tmp_path):
    r = _run(_settings(tmp_path))
    assert _get(r, "ghosttool").level == Level.MISSING
    assert _get(r, "Database").level == Level.OK
    assert _get(r, "Scope").level == Level.OK
    assert r.overall == "DEGRADED"


def test_not_ready_when_required_missing(tmp_path):
    r = _run(_settings(tmp_path), tools=_tools(required=True))
    assert _get(r, "ghosttool").level == Level.ERROR and r.overall == "NOT READY"


def test_missing_and_malformed_scope(tmp_path):
    assert _get(_run(_settings(tmp_path, scope=None)), "Scope").level == Level.WARN
    assert _get(_run(_settings(tmp_path, scope="allow: [nope/99]\n")), "Scope").level == Level.ERROR


def test_credentials_in_config_flagged(tmp_path):
    r = _run(_settings(tmp_path, "ai:\n  providers:\n    openai:\n      api_key: sk-abc\n"))
    c = _get(r, "Credentials in config")
    assert c.level == Level.ERROR and "ai.providers.openai.api_key" in c.detail
    assert "sk-abc" not in c.detail


def test_termux_and_root_warnings(tmp_path):
    plat = PlatformInfo("termux", "", "aarch64", "3.11", True, True)
    r = _run(_settings(tmp_path), plat=plat)
    assert _get(r, "Termux").level == Level.WARN
    assert _get(r, "Privileges").level == Level.WARN


def test_unwritable_home_is_error(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yaml").write_text("")
    s = load_settings(env={}, project_root=tmp_path)
    s.data["paths"]["home"] = str(f / "sub")  # parent is a file -> cannot mkdir
    r = _run(s)
    assert _get(r, "Data directory").level == Level.ERROR


def test_json_shape(tmp_path):
    d = _run(_settings(tmp_path)).to_dict()
    assert set(d) == {"overall", "counts", "checks"}
    assert all({"section", "name", "level", "detail"} <= set(c) for c in d["checks"])


def test_check_crash_is_contained(tmp_path):
    def boom():
        raise RuntimeError("kaboom")

    r = Doctor(_settings(tmp_path), PLAT, _tools(), boom, env={}).run()
    assert any(c.section == "internal" and "kaboom" in c.detail for c in r.checks)
