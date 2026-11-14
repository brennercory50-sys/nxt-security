"""secrets.scan module: directory walking, skips, masking, findings."""

import logging

import pytest

from nxtsec.core.errors import PluginError
from nxtsec.core.models import Mode, Severity
from nxtsec.events import EventBus
from nxtsec.modules.secrets.scan import SecretsScan, looks_binary
from nxtsec.plugins import ModuleContext, Permission
from nxtsec.safety.scope import Scope
from nxtsec.targets import parse_target

GH_TOKEN = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIAIOSFODNN7EXAMPLE"


def ctx(options=None, perms=None):
    return ModuleContext(
        "asm_t",
        Mode.REAL,
        Scope.empty(),
        frozenset(perms or {Permission.READ_ONLY, Permission.LOCAL_FILES}),
        logging.getLogger("t"),
        EventBus(),
        options=options or {},
        module_name="secrets.scan",
    )


def run(path):
    return SecretsScan().run(parse_target(f"file:{path}"), ctx())


def test_scan_single_file(tmp_path):
    f = tmp_path / "config.py"
    f.write_text(f'TOKEN = "{GH_TOKEN}"\nDEBUG = True\n')
    res = run(f)
    assert len(res.findings) == 1
    fnd = res.findings[0]
    assert fnd.severity == Severity.CRITICAL and "github_token" in fnd.component
    # never leaks the raw token anywhere on the finding
    blob = f"{fnd.title}{fnd.component}{fnd.description}"
    assert GH_TOKEN not in blob and GH_TOKEN[:4] in fnd.component


def test_scan_directory_with_skips(tmp_path):
    (tmp_path / "app.py").write_text(f'aws = "{AWS}"\n')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(f'token = "{GH_TOKEN}"\n')  # must be skipped
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(f'k="{GH_TOKEN}"\n')  # skipped
    (tmp_path / "clean.py").write_text("x = 1\n")
    res = run(tmp_path)
    paths = {f.title.split(" in ")[1].split(":")[0] for f in res.findings}
    assert paths == {"app.py"}  # only the real source file


def test_binary_files_skipped(tmp_path):
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02" + GH_TOKEN.encode() + b"\x00")
    (tmp_path / "ok.py").write_text(f'k = "{GH_TOKEN}"\n')
    res = run(tmp_path)
    assert len(res.findings) == 1 and "ok.py" in res.findings[0].title


def test_skip_suffixes(tmp_path):
    (tmp_path / "bundle.min.js").write_text(f'var k="{GH_TOKEN}"\n')
    (tmp_path / "logo.png").write_text(f"{GH_TOKEN}")
    res = run(tmp_path)
    assert res.findings == []


def test_max_files_limit(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text(f'k = "{GH_TOKEN}"\n')
    res = SecretsScan().run(parse_target(f"file:{tmp_path}"), ctx({"max_files": "2"}))
    assert any("max_files=2" in e for e in res.errors)
    assert len(res.findings) <= 2


def test_clean_tree_no_findings(tmp_path):
    (tmp_path / "a.py").write_text("def f():\n    return 42\n")
    (tmp_path / "b.md").write_text("# docs\nnothing secret here\n")
    assert run(tmp_path).findings == []


def test_env_example_placeholders_ignored(tmp_path):
    (tmp_path / ".env.example").write_text(
        "API_KEY=your_api_key_here\nSECRET=changeme\nTOKEN=<token>\n"
    )
    assert run(tmp_path).findings == []


def test_missing_path(tmp_path):
    with pytest.raises(PluginError, match="cannot access"):
        run(tmp_path / "nope")


def test_requires_local_files_permission(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    with pytest.raises(PluginError):
        SecretsScan().run(parse_target(f"file:{tmp_path}"), ctx(perms={Permission.READ_ONLY}))


@pytest.mark.parametrize(
    ("data", "binary"),
    [
        (b"plain text here", False),
        (b"\x00\x01binary", True),
        (b"", False),
        (bytes(range(0, 32)) * 5, True),
    ],
)
def test_looks_binary(data, binary):
    assert looks_binary(data) is binary
