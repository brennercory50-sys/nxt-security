"""Secret detection engine: coverage, masking (never leak), placeholder filtering."""

import pytest

from nxtsec.scanners.secrets import (
    is_placeholder,
    mask_secret,
    scan_text,
    shannon_entropy,
)

# Realistic-but-fake secrets. The scanner must detect each and never echo it raw.
AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"
GH_TOKEN = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
ANTHROPIC = "sk-" + "ant-api03-" + "x" * 40 + "AA"
GOOGLE = "AI" + "za" + "Sy" + "A" * 33
SLACK = "xox" + "b-" + "123456789012-abcdefABCDEF1234"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (f'aws_secret_access_key = "{AWS_SECRET}"', "aws_secret_key"),
        (f"AWS_ACCESS_KEY_ID={AWS_ACCESS}", "aws_access_key"),
        (f'token = "{GH_TOKEN}"', "github_token"),
        (f'STRIPE="{STRIPE}"', "stripe_secret"),
        (f'key: "{ANTHROPIC}"', "anthropic_key"),
        (f'google = "{GOOGLE}"', "google_api_key"),
        (f'slack_token = "{SLACK}"', "slack_token"),
        (f'jwt = "{JWT}"', "jwt"),
        ('db = "postgres://admin:S3cr3tP@ss@db.local:5432/app"', "db_url_password"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ('password = "hunter2hunter2"', "generic_secret"),
    ],
)
def test_detects_rule(text, rule):
    rules = {m.rule for m in scan_text(text)}
    assert rule in rules, f"{rule} not in {rules}"


SECRETS_ALL = [AWS_ACCESS, AWS_SECRET, GH_TOKEN, STRIPE, ANTHROPIC, GOOGLE, SLACK, JWT]


@pytest.mark.parametrize("secret", SECRETS_ALL)
def test_never_leaks_raw_value(secret):
    text = f'credential = "{secret}"'
    matches = scan_text(text)
    assert matches, f"no match for {secret[:6]}..."
    blob = repr([(m.masked, m.context, m.description) for m in matches])
    assert secret not in blob, "raw secret leaked into match output!"
    # but a prefix should survive so the operator can identify it
    assert any(m.masked.startswith(secret[:4]) for m in matches)


def test_mask_secret_shape():
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA" + "*" * 12 + "MPLE"
    assert "*" in mask_secret("short")
    assert mask_secret("abcdefghijkl").count("*") >= 4


@pytest.mark.parametrize(
    "placeholder",
    [
        "your_api_key_here",
        "xxxxxxxxxx",
        "changeme",
        "<your-token>",
        "${API_KEY}",
        "example_secret",
        "TODO",
        "AAAAAAAA",
        "....",
        "replace_with_key",
        "test_value_123",
    ],
)
def test_placeholders_filtered(placeholder):
    assert is_placeholder(placeholder)
    assert scan_text(f'api_key = "{placeholder}"') == []


def test_real_secret_not_placeholder():
    assert not is_placeholder(AWS_SECRET)
    assert not is_placeholder(GH_TOKEN)


def test_entropy():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy(GH_TOKEN) > 3.5
    assert shannon_entropy("") == 0.0


def test_high_entropy_catches_unlabeled_token():
    # a bare high-entropy string with no sensitive key name, in quotes
    token = "Zx9Kq2Lm7Pw4Rt6Yn1Bv8Cd3Fg5Hj0"
    matches = scan_text(f'value = "{token}"')
    assert any(m.rule == "high_entropy" for m in matches)
    assert token not in repr([m.masked for m in matches])


def test_low_entropy_string_ignored():
    # long but low-entropy (repeated), not flagged as high_entropy
    assert not any(m.rule == "high_entropy" for m in scan_text('x = "abcabcabcabcabcabcabcabc"'))


def test_line_and_column_reported():
    text = 'ok = 1\npassword = "realLongSecret99"\n'
    [m] = [m for m in scan_text(text) if m.rule == "generic_secret"]
    assert m.line == 2 and m.column > 0


def test_overlap_prefers_stronger_rule():
    # a GitHub token also looks high-entropy; only the typed rule should win on that span
    matches = scan_text(f'token = "{GH_TOKEN}"')
    gh = [m for m in matches if m.rule == "github_token"]
    he = [m for m in matches if m.rule == "high_entropy"]
    assert gh and not he


def test_empty_and_plain_text():
    assert scan_text("") == []
    assert scan_text("# just a comment\nx = 1\nreturn total\n") == []
