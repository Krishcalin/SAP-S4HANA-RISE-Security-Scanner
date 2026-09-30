"""
The SAP LogServ batch puller (collect/logserv.py) — the offline-testable parts:
the write shape, the window computation, the event count, and the credential
discipline (env only, fails loudly when unset). The network fetch needs a live
LogServ endpoint and is not exercised here.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import logserv  # noqa: E402


def test_write_produces_the_source_file_a_scan_reads(tmp_path):
    payload = {"events": [{"class_uid": 3002}, {"class_uid": 3002}]}
    count = logserv.write(tmp_path, payload)
    out = tmp_path / "logserv_events.json"
    assert out.exists() and count == 2
    assert json.loads(out.read_text(encoding="utf-8")) == payload


def test_event_count_handles_both_shapes(tmp_path):
    assert logserv.write(tmp_path, [{"a": 1}, {"b": 2}, {"c": 3}]) == 3
    assert logserv.write(tmp_path, {"data": [{"a": 1}]}) == 1
    assert logserv.write(tmp_path, {"not_events": 1}) == 0


def test_window_since_is_iso_utc():
    since = logserv.window_since(24)
    assert since.endswith("Z") and "T" in since and len(since) == 20


def test_credentials_come_from_env_not_argv(monkeypatch):
    monkeypatch.delenv("LOGSERV_URL", raising=False)
    monkeypatch.delenv("LOGSERV_TOKEN", raising=False)
    with pytest.raises(logserv.LogServError):
        logserv.fetch("2026-01-15T00:00:00Z")
    monkeypatch.setenv("LOGSERV_URL", "https://logserv.example/api/events")
    with pytest.raises(logserv.LogServError):  # URL set, token still missing
        logserv.fetch("2026-01-15T00:00:00Z")
