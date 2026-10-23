import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import osint_tools as t  # noqa: E402


@pytest.fixture(autouse=True)
def no_exploitdb_download(monkeypatch):
    """Exploit-DB's index is a 10 MB download; tests that need it replace this again."""
    monkeypatch.setattr(t, "exploit_lookup_many", lambda cve_ids: {})
