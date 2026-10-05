import pytest

from nxtsec.safety.scope import Scope


@pytest.fixture
def scope() -> Scope:
    return Scope(
        [
            "localhost",
            "192.168.1.0/24",
            "10.10.10.0/24",
            "authorized.example.com",
            "*.lab.example.com",
            "fd00::/8",
        ],
        ["192.168.1.1", "secret.lab.example.com"],
        name="test",
    )


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("NXTSEC_HOME", str(tmp_path / "home"))
