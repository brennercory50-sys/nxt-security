import logging

import pytest

from nxtsec.logging.setup import configure_logging
from nxtsec.safety.redaction import mask, redact, redact_obj

SECRETS = [
    "sk_live_abcdefghijklmnop1234",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "sk-ant-api03-" + "b" * 40,
    "xoxb-1234567890-abcdefghij",
    "AIza" + "c" * 35,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_secret_not_present_after_redaction(secret):
    out = redact(f"found {secret} in config")
    assert secret not in out
    assert "****" in out


def test_mask_keeps_edges():
    assert mask("sk_live_abcdefghijklmnop1234") == "sk_l" + "*" * 20 + "1234"
    assert "*" in mask("short")


def test_private_key_block():
    pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in redact(pk)


@pytest.mark.parametrize(
    "line",
    [
        "password=hunter2hunter2",
        "DB_PASSWORD: 'Sup3rSecretValue'",
        "api_key = abcd1234efgh",
        "postgres://admin:Sup3rSecret@db.local/app",
        "Authorization: Bearer abcdefghijklmnopqrstuv",
    ],
)
def test_assignments_and_urls(line):
    secret = {
        "password=hunter2hunter2": "hunter2hunter2",
        "DB_PASSWORD: 'Sup3rSecretValue'": "Sup3rSecretValue",
        "api_key = abcd1234efgh": "abcd1234efgh",
        "postgres://admin:Sup3rSecret@db.local/app": "Sup3rSecret",
        "Authorization: Bearer abcdefghijklmnopqrstuv": "abcdefghijklmnopqrstuv",
    }[line]
    assert secret not in redact(line)


def test_plain_text_untouched():
    s = "Scanning 192.168.1.10 port 443 https://example.com/path"
    assert redact(s) == s


def test_redact_obj_nested():
    data = {"user": "bob", "api_key": "plainvalue123", "nested": [{"note": "token=abcdefgh1234"}]}
    out = redact_obj(data)
    assert out["user"] == "bob"
    assert "plainvalue123" not in str(out)
    assert "abcdefgh1234" not in str(out)


def test_logs_are_redacted(tmp_path):
    logger = configure_logging("DEBUG", console=False, log_dir=tmp_path)
    secret = "sk_live_abcdefghijklmnop1234"
    logging.getLogger("nxtsec.test").info("leak %s", secret, extra={"target": f"key={secret}"})
    for h in logger.handlers:
        h.flush()
    text = (tmp_path / "nxtsec.jsonl").read_text()
    assert secret not in text
    assert "sk_l" in text
