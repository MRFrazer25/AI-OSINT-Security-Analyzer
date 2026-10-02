"""Smoke tests for the Streamlit UI (no network or API keys needed)."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture
def app(monkeypatch):
    for var in ("COHERE_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY",
                "NVD_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception
    return at


def _target_box(at):
    return next(t for t in at.text_input if t.label == "Target")


def _run_button(at):
    return next(b for b in at.button if b.label == "Run Analysis")


def test_app_loads_with_model_choices(app):
    model_box = next(s for s in app.selectbox if s.label == "Cohere model")
    assert "command-a-plus-05-2026" in model_box.options[0]


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
