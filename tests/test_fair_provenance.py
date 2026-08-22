"""What produced the figure: the catalogue, the engine, and the model version.

The load-bearing test here edits a copy of the real catalogue and asserts the
fingerprint moves. Everything else is a property; that one is the actual claim.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_adapter as fa         # noqa: E402
from modules import fair_provenance as fp      # noqa: E402

CATALOGUE = ROOT / "data" / "fair_scenarios.json"


# ── digests ──────────────────────────────────────────────────────────────────

def test_a_digest_is_stable_and_content_addressed(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text('{"x": 1}', encoding="utf-8")
    b.write_text('{"x": 1}', encoding="utf-8")
    assert fp.file_digest(a) == fp.file_digest(b)
    b.write_text('{"x": 2}', encoding="utf-8")
    assert fp.file_digest(a) != fp.file_digest(b)


def test_a_missing_file_digests_to_none_not_to_a_lie():
    """None renders as 'unknown'. An empty string or a digest of b'' would both
    claim we know something we do not."""
    assert fp.file_digest(ROOT / "does-not-exist.json") is None


def test_taking_a_digest_never_raises(tmp_path):
    """Provenance sits ALONGSIDE the figure. A scan must not fail because a
    digest could not be taken."""
    assert fp.file_digest(tmp_path) is None          # a directory
    assert fp.file_digest(None) is None


# ── the catalogue ────────────────────────────────────────────────────────────

def test_the_shipped_catalogue_reports_its_own_version_and_bytes():
    prov = fp.catalogue_provenance(CATALOGUE)
    assert prov["version"], "the shipped catalogue declares no _meta.version"
    assert prov["sha256"] and len(prov["sha256"]) == 64
    assert prov["scenario_count"] == 5
    assert prov["currency"] == "USD"


def test_the_declared_version_and_the_bytes_are_recorded_separately():
    """They answer different questions, and they disagree exactly when somebody
    edits the catalogue without bumping the version — which the version alone
    cannot catch and is the likeliest way this happens."""
    prov = fp.catalogue_provenance(CATALOGUE)
    assert "version" in prov and "sha256" in prov
    assert prov["version"] != prov["sha256"]


def test_a_catalogue_edit_changes_the_digest_even_at_the_same_version(tmp_path):
    """THE CLAIM THIS FEATURE MAKES.

    Edit a loss band, leave _meta.version alone, and the digest must still move.
    Otherwise a catalogue change moves every customer's figure on unchanged
    findings and the trend redraws its own past in silence.
    """
    copy = tmp_path / "fair_scenarios.json"
    shutil.copy(CATALOGUE, copy)
    before = fp.catalogue_provenance(copy)

    data = json.loads(copy.read_text(encoding="utf-8"))
    # a plausible edit: widen one scenario's productivity loss
    data["scenarios"][0]["primary_loss"]["productivity"]["likely"] *= 2
    copy.write_text(json.dumps(data, indent=2), encoding="utf-8")

    after = fp.catalogue_provenance(copy)
    assert after["version"] == before["version"], "the version was left alone"
    assert after["sha256"] != before["sha256"], "the bytes changed and the digest did not"


# ── the engine ───────────────────────────────────────────────────────────────

def test_the_engine_records_where_it_came_from():
    module, origin = fa.locate_engine_with_origin()
    assert module is not None
    assert origin["kind"] in ("bundled", "env", "explicit", "sibling")
    assert origin["sha256"] and len(origin["sha256"]) == 64
    assert origin["path"] and origin["path"].endswith("crq_engine.py")


def test_a_broken_engine_is_recorded_rather_than_swallowed(tmp_path):
    """THE BARE `except Exception: continue` IS WHAT THIS REPLACES.

    A file that fails to import used to be passed over in silence, and a
    DIFFERENT engine then produced the number with nothing anywhere saying so.
    """
    broken = tmp_path / "broken_engine.py"
    broken.write_text("raise RuntimeError('this engine is broken')\n", encoding="utf-8")
    module, origin = fa.locate_engine_with_origin(str(broken))
    # the bundled engine still wins, which is right — but the failure is on record
    assert module is not None
    assert origin["kind"] == "bundled"
    assert any("broken_engine" in s["path"] for s in origin["skipped"])
    assert any(s["reason"] == "RuntimeError" for s in origin["skipped"])


def test_a_file_without_a_fair_engine_is_recorded_with_its_reason(tmp_path):
    notengine = tmp_path / "notengine.py"
    notengine.write_text("VALUE = 1\n", encoding="utf-8")
    _module, origin = fa.locate_engine_with_origin(str(notengine))
    assert any(s["reason"] == "no FAIREngine in module" for s in origin["skipped"])


def test_the_compatibility_wrapper_still_returns_a_module():
    """locate_engine has external callers and docs; it must keep its shape."""
    assert fa.locate_engine() is not None


# ── the run carries it ───────────────────────────────────────────────────────

def test_a_run_records_what_produced_it():
    result = fa.run([], [], simulations=500)
    prov = result["provenance"]
    assert prov["catalogue"]["sha256"]
    assert prov["engine"]["kind"] == "bundled"
    assert prov["model_version"] == fp.MODEL_VERSION
    assert prov["simulations"] == 500
    assert prov["seed"] == 42
    # and it reaches the summary, which is what gets stored
    assert result["summary"]["provenance"] == prov


def test_the_two_model_versions_agree():
    """server.crq.MODEL_VERSION and fair_provenance.MODEL_VERSION are the same
    number in two places. Two version numbers that can disagree are worse than
    one, so this fails the moment they drift."""
    psycopg = pytest.importorskip("psycopg")           # noqa: F841
    from server import crq
    assert crq.MODEL_VERSION == fp.MODEL_VERSION


# ── the fingerprint ──────────────────────────────────────────────────────────

def test_the_fingerprint_is_stable_for_identical_material():
    material = {"a": 1, "b": "two", "c": None}
    assert fp.fingerprint(material) == fp.fingerprint(dict(material))
    # key order must not matter
    assert fp.fingerprint({"b": "two", "a": 1, "c": None}) == fp.fingerprint(material)


def test_the_fingerprint_survives_types_json_cannot_encode():
    """psycopg returns Decimal for a numeric column. Raising here would take a
    scan down over a provenance record, which is the wrong trade."""
    from decimal import Decimal
    assert fp.fingerprint({"ale": Decimal("1.5")})


def test_the_fingerprint_moves_on_a_catalogue_change():
    a = {"catalogue_sha256": "aaa", "engine_sha256": "zzz"}
    b = {"catalogue_sha256": "bbb", "engine_sha256": "zzz"}
    assert fp.fingerprint(a) != fp.fingerprint(b)


def test_the_fingerprint_moves_on_an_engine_change():
    a = {"catalogue_sha256": "aaa", "engine_sha256": "zzz"}
    b = {"catalogue_sha256": "aaa", "engine_sha256": "yyy"}
    assert fp.fingerprint(a) != fp.fingerprint(b)
