"""AI layer: providers, factory, and the analyst's redaction + advisory guarantees."""

import sys
import types

import pytest

from nxtsec.ai.analyst import ADVISORY_BANNER, AIAnalyst, finding_prompt, summary_prompt
from nxtsec.ai.base import AIError, AIProvider, AIRequest, AIResponse
from nxtsec.ai.factory import available_providers, build_provider
from nxtsec.ai.offline import OfflineProvider
from nxtsec.config.settings import load_settings
from nxtsec.core.models import Confidence, Finding, FindingStatus, Severity
from nxtsec.database.store import SQLiteDatabase
from nxtsec.findings.service import FindingService

GH_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _settings(tmp_path, cfg=""):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "config.yaml").write_text(cfg)
    return load_settings(env={}, project_root=tmp_path)


# -- offline provider ----------------------------------------------------------
def test_offline_always_available_and_deterministic():
    p = OfflineProvider()
    ready, _ = p.available()
    assert ready and p.model == "heuristic-v1"
    r1 = p.complete(AIRequest(prompt="Line one. Line two. Line three."))
    r2 = p.complete(AIRequest(prompt="Line one. Line two. Line three."))
    assert r1.text == r2.text
    assert "heuristic" in r1.text.lower() and "advisory" in r1.text.lower()
    assert r1.provider == "offline"


# -- factory -------------------------------------------------------------------
def test_available_providers():
    assert set(available_providers()) == {"offline", "claude", "openai", "local"}


def test_factory_defaults_to_offline(tmp_path):
    assert isinstance(build_provider(_settings(tmp_path)), OfflineProvider)


def test_factory_unknown_falls_back_offline(tmp_path):
    p = build_provider(_settings(tmp_path, "ai:\n  provider: bogus\n"))
    assert isinstance(p, OfflineProvider)


def test_factory_builds_claude(tmp_path):
    from nxtsec.ai.claude import ClaudeProvider

    p = build_provider(_settings(tmp_path, "ai:\n  provider: claude\n"))
    assert isinstance(p, ClaudeProvider) and p.model == "claude-opus-5-5"


def test_factory_builds_claude_custom_model(tmp_path):
    p = build_provider(_settings(tmp_path, "ai:\n  provider: claude\n  model: claude-haiku-5-5\n"))
    assert p.model == "claude-haiku-5-5"


def test_factory_local_defaults_base_url(tmp_path):
    from nxtsec.ai.openai_compat import OpenAICompatProvider

    p = build_provider(_settings(tmp_path, "ai:\n  provider: local\n"))
    assert isinstance(p, OpenAICompatProvider) and p._base_url and "11434" in p._base_url


# -- claude adapter (mocked SDK, no network) -----------------------------------
def _install_fake_anthropic(monkeypatch, *, captured, text="risk explained", stop="end_turn"):
    mod = types.ModuleType("anthropic")

    class APIError(Exception):
        pass

    class _Block:
        type = "text"

        def __init__(self, t):
            self.text = t

    class _Resp:
        def __init__(self):
            self.content = [_Block(text)]
            self.stop_reason = stop
            self.usage = types.SimpleNamespace(input_tokens=11, output_tokens=22)

    class _Messages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Resp()

    class Anthropic:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    mod.Anthropic = Anthropic
    mod.APIError = APIError
    monkeypatch.setitem(sys.modules, "anthropic", mod)


def test_claude_available_requires_key(monkeypatch):
    from nxtsec.ai.claude import ClaudeProvider

    _install_fake_anthropic(monkeypatch, captured={})
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ready, detail = ClaudeProvider().available()
    assert not ready and "ANTHROPIC_API_KEY" in detail
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    assert ClaudeProvider().available()[0]


def test_claude_complete_uses_messages_api(monkeypatch):
    from nxtsec.ai.claude import ClaudeProvider

    captured: dict = {}
    _install_fake_anthropic(monkeypatch, captured=captured, text="OpenSSH risk", stop="end_turn")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    resp = ClaudeProvider().complete(AIRequest(prompt="analyze", system="be precise"))
    assert resp.text == "OpenSSH risk" and resp.model == "claude-opus-5-5"
    assert captured["model"] == "claude-opus-5-5" and captured["messages"][0]["role"] == "user"
    assert resp.usage == {"input_tokens": 11, "output_tokens": 22}


def test_claude_truncation_flag(monkeypatch):
    from nxtsec.ai.claude import ClaudeProvider

    _install_fake_anthropic(monkeypatch, captured={}, stop="max_tokens")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    assert ClaudeProvider().complete(AIRequest(prompt="x")).truncated is True


def test_claude_missing_package(monkeypatch):
    from nxtsec.ai.claude import ClaudeProvider

    monkeypatch.setitem(sys.modules, "anthropic", None)  # force ImportError
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    with pytest.raises(AIError):
        ClaudeProvider().complete(AIRequest(prompt="x"))


# -- analyst: redaction + advisory-only ----------------------------------------
class RecordingProvider(AIProvider):
    name = "recording"

    def __init__(self):
        self.seen = []

    @property
    def model(self):
        return "rec-1"

    def available(self):
        return True, "ok"

    def complete(self, request):
        self.seen.append(request)
        return AIResponse(text="Advisory text", provider="recording", model="rec-1")


@pytest.fixture
def svc(tmp_path):
    db = SQLiteDatabase(":memory:")
    db.migrate()
    yield FindingService(db, "tester")
    db.close()


def _add_secret_finding(svc):
    f = Finding(
        "Hardcoded token in app.py:3",
        Severity.CRITICAL,
        "/repo/app.py",
        "secrets.scan",
        confidence=Confidence.FIRM,
        component=f"github_token {GH_TOKEN}",
        description=f"A secret was found: {GH_TOKEN}",
    )
    svc.db.upsert_finding(f)
    return f.id


def test_finding_prompt_is_redacted(svc):
    fid = _add_secret_finding(svc)
    prompt = finding_prompt(svc.get(fid))
    assert GH_TOKEN not in prompt and GH_TOKEN[:4] in prompt


def test_analyst_never_sends_raw_secret(svc):
    fid = _add_secret_finding(svc)
    prov = RecordingProvider()
    AIAnalyst(prov, svc, "tester").analyze_finding(fid)
    assert prov.seen and GH_TOKEN not in prov.seen[0].prompt


def test_analyst_annotate_adds_advisory_note_without_changing_finding(svc):
    fid = _add_secret_finding(svc)
    before = svc.get(fid)
    AIAnalyst(OfflineProvider(), svc, "tester").analyze_finding(fid, annotate=True)
    after = svc.get(fid)
    # advisory note attached, but severity and status untouched
    assert after["severity"] == before["severity"] == "CRITICAL"
    assert after["status"] == before["status"] == FindingStatus.OPEN.value
    assert after["notes"] and ADVISORY_BANNER in after["notes"][-1]["text"]
    assert GH_TOKEN not in after["notes"][-1]["text"]
    assert any(a["action"] == "ai.analyze" for a in svc.db.list_audit())


def test_analyst_no_annotate_leaves_no_note(svc):
    fid = _add_secret_finding(svc)
    AIAnalyst(OfflineProvider(), svc, "tester").analyze_finding(fid, annotate=False)
    assert not svc.get(fid).get("notes")


def test_summary_prompt_redacted(svc):
    _add_secret_finding(svc)
    prompt = summary_prompt(svc.search())
    assert GH_TOKEN not in prompt


def test_summarize_audited(svc):
    _add_secret_finding(svc)
    AIAnalyst(OfflineProvider(), svc, "tester").summarize(svc.search())
    assert any(a["action"] == "ai.summarize" for a in svc.db.list_audit())
