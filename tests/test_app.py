"""Smoke tests for the Streamlit UI (no network or API keys needed)."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("COHERE_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
                "NVD_API_KEY", "GREYNOISE_API_KEY"):
        monkeypatch.delenv(var, raising=False)


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

    monkeypatch.setattr(ai, "run_agent", fake_run)
    return runs


def test_keys_on_the_server_are_never_used(monkeypatch, fake_agent):
    # Keys in the environment, .env or Streamlit secrets must never run a visitor's analysis,
    # even with the old sharing switch set.
    for var in ("COHERE_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "NVD_API_KEY"):
        monkeypatch.setenv(var, "server-key")
    monkeypatch.setenv("SHARE_SERVER_KEYS", "true")
    at = _session()
    _analyse(at)
    assert any("Cohere API key is required" in e.value for e in at.error)
    assert fake_agent == []


def test_keys_typed_into_the_session_are_used(monkeypatch, fake_agent):
    monkeypatch.setenv("SHODAN_API_KEY", "server-key")
    at = _session()
    at.session_state["user_keys"] = {"cohere": "my-own-key"}
    _analyse(at)
    assert len(fake_agent) == 1 and fake_agent[0].cohere == "my-own-key"
    assert fake_agent[0].shodan == ""  # the server's key isn't filled in either


def test_optional_keys_are_not_shown_as_missing(app):
    statuses = [m.value for m in app.markdown if "Configured" in m.value or "(required)" in m.value
                or "(optional)" in m.value]
    assert any("Cohere" in s and "Missing (required)" in s for s in statuses)
    assert any("NVD" in s and "Not set (optional)" in s for s in statuses)



def test_report_shows_the_confirmed_cve_table_and_chart(monkeypatch):
    import ai

    check = {"tool": "version_check", "success": True, "software": "nginx", "version": "1.20.1",
             "affected_count": 1, "affected_by_severity": {"HIGH": 1},
             "affected_cves": [{"cve_id": "CVE-2021-23017", "severity": "HIGH", "cvss_score": 7.7,
                                "epss": {"epss": 0.9}, "fixed_in": "1.21.0"}]}

    def fake_run(target, keys, complexity, on_event=None, model=None):
        return ai.AgentResult(target=ai.classify_target(target), report="ok", complexity=complexity, model="m",
                              tool_calls=[ai.ToolCallRecord("version_specific_vulnerability_check", {}, 1, "t", 1,
                                                            check)])

    monkeypatch.setattr(ai, "run_agent", fake_run)
    at = _session()
    at.session_state["user_keys"] = {"cohere": "session-key"}
    _analyse(at, "nginx 1.20.1")
    assert any("Confirmed vulnerabilities" in m.value for m in at.markdown)
    assert at.dataframe and list(at.dataframe[0].value["CVE"]) == ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
