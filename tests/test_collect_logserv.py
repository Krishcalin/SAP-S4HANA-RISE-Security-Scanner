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


# ── hardening: high-water-mark, manifest, pagination, retry ────────────────────
BASE_S = 1768471200   # 2026-01-15T10:00:00Z in epoch seconds


def _creds(monkeypatch):
    monkeypatch.setenv("LOGSERV_URL", "https://logserv.example/api/events")
    monkeypatch.setenv("LOGSERV_TOKEN", "t0ken")


def test_high_water_mark_round_trip(tmp_path):
    # Newest event at BASE_S+120; resume is one second later, read back as ISO.
    payload = {"events": [{"_time": BASE_S}, {"_time": BASE_S + 120},
                          {"time": (BASE_S + 60) * 1000}]}  # mixed sec / ms
    mark = logserv.write_state(tmp_path, payload)
    assert mark == "2026-01-15T10:02:01Z"
    assert logserv.read_since(tmp_path) == "2026-01-15T10:02:01Z"


def test_write_state_is_none_without_times(tmp_path):
    assert logserv.write_state(tmp_path, {"events": [{"message": "x"}]}) is None
    assert logserv.read_since(tmp_path) is None


def test_read_since_absent_is_none(tmp_path):
    assert logserv.read_since(tmp_path) is None


def test_manifest_records_the_window(tmp_path):
    logserv.write_manifest(tmp_path, "2026-01-15T00:00:00Z", None, 7, 2)
    m = json.loads((tmp_path / "logserv_manifest.json").read_text(encoding="utf-8"))
    assert m["since"] == "2026-01-15T00:00:00Z" and m["events"] == 7 and m["pages"] == 2


def test_fetch_all_follows_the_next_cursor(monkeypatch):
    _creds(monkeypatch)
    pages = [
        {"events": [{"id": 1}, {"id": 2}], "next": "https://logserv.example/api?cursor=p2"},
        {"events": [{"id": 3}], "next_cursor": "p3"},
        {"events": [{"id": 4}]},
    ]
    calls = []
    def fake_get(url, token, **kw):
        calls.append(url)
        return pages[len(calls) - 1]
    monkeypatch.setattr(logserv, "_get", fake_get)
    result = logserv.fetch_all("2026-01-15T00:00:00Z")
    assert result["pages"] == 3
    assert [e["id"] for e in result["events"]] == [1, 2, 3, 4]


def test_fetch_all_single_page_when_no_cursor(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setattr(logserv, "_get", lambda url, token, **kw: {"events": [{"id": 1}]})
    result = logserv.fetch_all("2026-01-15T00:00:00Z")
    assert result["pages"] == 1 and len(result["events"]) == 1


def test_get_retries_a_transient_failure_then_succeeds(monkeypatch):
    _creds(monkeypatch)
    import urllib.error

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"events": []}'
    attempts = {"n": 0}
    def flaky(req, timeout=None, context=None):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.URLError("connection reset")
        return _Resp()
    monkeypatch.setattr(logserv._time, "sleep", lambda *_a: None)   # no real backoff
    monkeypatch.setattr("urllib.request.urlopen", flaky)
    assert logserv.fetch("2026-01-15T00:00:00Z") == {"events": []}
    assert attempts["n"] == 3


def test_a_4xx_is_not_retried(monkeypatch):
    _creds(monkeypatch)
    import urllib.error
    attempts = {"n": 0}
    def forbidden(req, timeout=None, context=None):
        attempts["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    with pytest.raises(logserv.LogServError):
        logserv.fetch("2026-01-15T00:00:00Z")
    assert attempts["n"] == 1      # a 403 will not fix itself; do not retry
