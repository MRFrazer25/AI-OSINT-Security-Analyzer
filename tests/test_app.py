"""Smoke tests for the Streamlit UI (no network or API keys needed)."""

from pathlib import Path

import pytest

import osint_tools as t

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("COHERE_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
                "NVD_API_KEY", "SHARE_SERVER_KEYS", "SERVER_KEY_RUNS_PER_HOUR", "SERVER_KEY_RUNS_PER_CLIENT_PER_HOUR"):
        monkeypatch.delenv(var, raising=False)
    t.server_key_quota().reset()


def _session():
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception
    return at


@pytest.fixture
def app():
    return _session()


def _target_box(at):
    return next(t for t in at.text_input if t.label == "Target")


def _run_button(at):
    return next(b for b in at.button if b.label == "Run Analysis")


def test_app_loads_with_model_choices(app):
    model_box = next(s for s in app.selectbox if s.label == "Cohere model")
    assert "command-a-plus-05-2026" in model_box.options[0]
    assert any(t.label == "Target" for t in app.text_input)
    assert any(b.label == "Run Analysis" for b in app.button)
    assert not app.error


def test_mocked_analysis_shows_the_report_page(fake_agent):
    at = _session()
    at.session_state["user_keys"] = {"cohere": "session-key"}
    _analyse(at, "8.8.8.8")
    assert len(fake_agent) == 1 and fake_agent[0].cohere == "session-key"
    assert any("Security Report" in h.value for h in at.header)
    assert any("ok" in m.value for m in at.markdown)


def test_private_ip_is_rejected(app):
    _target_box(app).input("10.0.0.1")
    _run_button(app).click()
    app.run()
    assert not app.exception
    assert any("not a public" in e.value for e in app.error)


def test_missing_cohere_key_is_explained(app):
    _target_box(app).input("8.8.8.8")
    _run_button(app).click()
    app.run()
    assert any("Cohere API key is required" in e.value for e in app.error)


def _analyse(at, target="CVE-2021-44228"):
    _target_box(at).input(target)
    _run_button(at).click()
    at.run()
    assert not at.exception


@pytest.fixture
def fake_agent(monkeypatch):
    import ai

    runs = []

    def fake_run(target, keys, complexity, on_event=None, model=None):
        runs.append(keys)
        return ai.AgentResult(target=ai.classify_target(target), report="## Executive Summary\nok",
                              complexity=complexity, model="m")

    monkeypatch.setattr(ai, "run_osint_agent", fake_run)
    return runs


def test_server_keys_are_not_shared_unless_enabled(monkeypatch, fake_agent):
    monkeypatch.setenv("COHERE_API_KEY", "server-key")
    at = _session()
    _analyse(at)
    assert any("Cohere API key is required" in e.value for e in at.error)
    assert fake_agent == []


def test_server_key_runs_are_limited_across_sessions(monkeypatch, fake_agent):
    monkeypatch.setenv("COHERE_API_KEY", "server-key")
    monkeypatch.setenv("SHARE_SERVER_KEYS", "true")
    monkeypatch.setenv("SERVER_KEY_RUNS_PER_HOUR", "1")
    monkeypatch.setenv("SERVER_KEY_RUNS_PER_CLIENT_PER_HOUR", "1")
    first, second = _session(), _session()  # separate browser sessions, so the per-session cooldown doesn't apply
    _analyse(first)
    assert len(fake_agent) == 1 and fake_agent[0].cohere == "server-key"
    assert any("Security Report" in h.value for h in first.header)
    _analyse(second)
    assert len(fake_agent) == 1
    assert any("hourly limit" in w.value for w in second.warning)


def test_own_keys_bypass_the_server_key_limit(monkeypatch, fake_agent):
    monkeypatch.setenv("SERVER_KEY_RUNS_PER_HOUR", "0")
    at = _session()
    at.session_state["user_keys"] = {"cohere": "my-own-key"}
    _analyse(at)
    assert len(fake_agent) == 1 and fake_agent[0].cohere == "my-own-key"
