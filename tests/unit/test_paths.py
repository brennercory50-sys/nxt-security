import os

import pytest

from nxtsec.core.errors import PathViolation
from nxtsec.safety.paths import safe_component, safe_join


def test_safe_join_inside(tmp_path):
    assert safe_join(tmp_path, "a", "b.txt") == (tmp_path / "a" / "b.txt").resolve()


@pytest.mark.parametrize("parts", [("..",), ("a", "..", ".."), ("/etc/passwd",), ("a\x00",)])
def test_safe_join_escape(tmp_path, parts):
    with pytest.raises(PathViolation):
        safe_join(tmp_path, *parts)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_symlink_escape(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    try:
        (base / "link").symlink_to(tmp_path)
    except OSError:
        pytest.skip("symlink not permitted")
    with pytest.raises(PathViolation):
        safe_join(base, "link", "x")


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b", "c:x"])
def test_safe_component(bad):
    with pytest.raises(PathViolation):
        safe_component(bad)
