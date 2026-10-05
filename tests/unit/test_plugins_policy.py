import logging

import pytest

from nxtsec.core.errors import PluginError, ScopeViolation
from nxtsec.core.models import Mode, TargetType
from nxtsec.events import EventBus
from nxtsec.plugins import (
    ModuleContext,
    ModuleResult,
    Permission,
    Plugin,
    PluginManifest,
    PluginRegistry,
    RiskLevel,
)
from nxtsec.plugins.policy import Policy
from nxtsec.targets import parse_target


def _manifest(**kw):
    base = dict(
        name="demo",
        version="1.0.0",
        description="d",
        category="recon",
        permissions=frozenset({Permission.NETWORK_ACCESS}),
        risk_level=RiskLevel.LOW,
        target_types=frozenset({TargetType.IPV4, TargetType.DOMAIN}),
    )
    base.update(kw)
    return PluginManifest(**base)


class Demo(Plugin):
    manifest = _manifest()

    def run(self, target, ctx):
        ctx.require(Permission.NETWORK_ACCESS)
        return ModuleResult(observations=[{"target": target.value}])


@pytest.mark.parametrize(
    "kw",
    [{"name": "Bad Name"}, {"version": "1"}, {"risk_level": RiskLevel.HIGH}],
)
def test_invalid_manifest(kw):
    with pytest.raises(PluginError):
        _manifest(**kw)


def test_manifest_roundtrip():
    m = _manifest()
    assert PluginManifest.from_dict(m.to_dict()) == m
    with pytest.raises(PluginError):
        PluginManifest.from_dict({"name": "x1", "version": "1.0.0", "permissions": ["GOD_MODE"]})


def test_registry():
    reg = PluginRegistry()
    reg.register(Demo)
    assert reg.get("demo") is Demo and len(reg) == 1
    with pytest.raises(PluginError):
        reg.get("nope")

    class Clash(Demo):
        pass

    with pytest.raises(PluginError):
        reg.register(Clash)
    with pytest.raises(PluginError):
        reg.register(object)  # type: ignore[arg-type]


def test_policy_scope_enforced(scope):
    p = Policy()
    assert Permission.NETWORK_ACCESS in p.authorize(
        Demo.manifest, parse_target("192.168.1.5"), Mode.REAL, scope
    )
    with pytest.raises(ScopeViolation):
        p.authorize(Demo.manifest, parse_target("8.8.8.8"), Mode.REAL, scope)


def test_policy_target_type(scope):
    with pytest.raises(PluginError):
        Policy().authorize(Demo.manifest, parse_target("file:/x"), Mode.REAL, scope)
    with pytest.raises(PluginError):
        Policy().authorize(Demo.manifest, None, Mode.REAL, scope)


def test_high_risk_lab_only(scope):
    m = _manifest(
        name="exploitcheck",
        risk_level=RiskLevel.HIGH,
        permissions=frozenset({Permission.LAB_ONLY_VALIDATION}),
        target_types=frozenset({TargetType.LAB}),
    )
    with pytest.raises(PluginError):
        Policy().authorize(m, parse_target("lab:dvwa"), Mode.REAL, scope)
    assert Policy().authorize(m, parse_target("lab:dvwa"), Mode.LAB, scope)


def test_raw_socket_not_granted_in_real_mode(scope):
    m = _manifest(name="rawscan", permissions=frozenset({Permission.RAW_SOCKET}))
    with pytest.raises(PluginError, match="RAW_SOCKET"):
        Policy().authorize(m, parse_target("192.168.1.5"), Mode.REAL, scope)


def test_context_require(scope):
    ctx = ModuleContext(
        "asm_1",
        Mode.REAL,
        scope,
        frozenset({Permission.READ_ONLY}),
        logging.getLogger("t"),
        EventBus(),
    )
    with pytest.raises(PluginError):
        Demo().run(parse_target("192.168.1.5"), ctx)


def test_event_bus_isolates_failures():
    bus, seen = EventBus(), []
    bus.subscribe("x", lambda e: 1 / 0)
    unsub = bus.subscribe("*", lambda e: seen.append(e.name))
    bus.publish("x", a=1)
    unsub()
    bus.publish("x")
    assert seen == ["x"]


# --- Phase 6 policy rules ----------------------------------------------------
from nxtsec.safety.scope import Scope  # noqa: E402


def test_lab_and_real_are_separate(scope):
    lab_ok = _manifest(name="labprobe", target_types=frozenset({TargetType.LAB, TargetType.IPV4}))
    with pytest.raises(PluginError, match="LAB mode only accepts lab"):
        Policy().authorize(lab_ok, parse_target("192.168.1.5"), Mode.LAB, scope)
    with pytest.raises(PluginError, match="require LAB mode"):
        Policy().authorize(lab_ok, parse_target("lab:dvwa"), Mode.REAL, scope)
    assert Policy().authorize(lab_ok, parse_target("lab:dvwa"), Mode.LAB, scope)


def test_attestation_required_for_real_network():
    unattested = Scope(["192.168.1.0/24"])
    with pytest.raises(ScopeViolation, match="operator_attestation"):
        Policy().authorize(Demo.manifest, parse_target("192.168.1.5"), Mode.REAL, unattested)
    relaxed = Policy(require_attestation=False)
    assert relaxed.authorize(Demo.manifest, parse_target("192.168.1.5"), Mode.REAL, unattested)


def test_attestation_not_needed_for_local_files():
    files = _manifest(
        name="filecheck",
        permissions=frozenset({Permission.LOCAL_FILES}),
        target_types=frozenset({TargetType.FILE}),
    )
    assert Policy().authorize(files, parse_target("file:/x"), Mode.REAL, Scope([]))


def test_cidr_size_cap(scope):
    m = _manifest(name="sweep", target_types=frozenset({TargetType.CIDR}))
    assert Policy().authorize(m, parse_target("10.10.10.0/24"), Mode.REAL, scope)
    with pytest.raises(PluginError, match="limit is 16"):
        Policy(max_cidr_hosts=16).authorize(m, parse_target("10.10.10.0/24"), Mode.REAL, scope)


def test_policy_from_settings(tmp_path):
    from nxtsec.config.settings import load_settings

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yaml").write_text(
        "safety:\n  max_cidr_hosts: 8\n  require_attestation: false\n  max_risk_real: low\n"
    )
    p = Policy.from_settings(load_settings(env={}, project_root=tmp_path))
    assert p.max_cidr_hosts == 8 and not p.require_attestation
    assert p.max_risk_real == RiskLevel.LOW
