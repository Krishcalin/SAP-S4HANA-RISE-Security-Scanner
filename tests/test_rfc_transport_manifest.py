"""What the RFC collector's connection actually was, recorded rather than assumed.

WHAT WAS WRONG, AND WHY IT WAS WORSE THAN A MISSING FIELD. Three of the four
collectors thread `tls_verified` into the manifest and treat an unverified
connection as a caveat on the evidence. `cmd_rfc` never passed it — and the
parameter DEFAULTS to True, so the manifest positively asserted that the RFC
collection was TLS-verified. RFC is not TLS at all, so the file whose entire
purpose is to say what a collection could and could not establish was making a
statement about it that could not be true.

THE ASYMMETRY THIS REMOVES. `modules/snc_posture.py` is a 103-reference module
whose job is auditing whether a CUSTOMER's RFC connections use SNC. This product
asked that question of every estate it scanned and never asked it of its own
collector, which authenticates with a username and password and pulls sixteen
sources including users, roles, profiles and auth_objects.

WHAT IT DOES NOT CLAIM. That the connection was unencrypted. The collector sets
no snc_mode/snc_partnername/snc_qop/snc_lib, so it neither requests nor
negotiates SNC — whether the conversation was protected depends on what the
server enforces, which cannot be observed from this side. "Not requested" is a
fact about us; "unencrypted" would be a claim about them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import extract                                    # noqa: E402

RFC_TRANSPORT = {
    "protocol": "SAP RFC",
    "encryption_requested": False,
    "mechanism": "SNC (Secure Network Communications)",
    "note": "does not set snc_mode/snc_partnername/snc_qop/snc_lib",
    "sources_affected": "every file this collection wrote",
}


def _manifest(tmp_path: Path, **over):
    kwargs = dict(source="rfc", endpoint="sapdev:3300",
                  collected_at="2026-08-20T09:00:00+00:00",
                  wrote={"users.csv": 412},
                  attempts=[{"source": "users", "ok": True, "rows": 412}],
                  cannot_reach=("gw_secinfo",))
    kwargs.update(over)
    path = extract.write_manifest(tmp_path, **kwargs)
    return json.loads(path.read_text(encoding="utf-8")), path


# ═════════════════════════════════════════════════════════════════════════════
#  Not-applicable is a third answer, not a missing one
# ═════════════════════════════════════════════════════════════════════════════

def test_a_non_tls_transport_records_none_rather_than_inheriting_true(tmp_path):
    """THE FALSE ASSERTION. The default is True, so a collector that says nothing
    publishes a claim that its connection was TLS-verified."""
    m, _ = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    assert m["collections"][0]["tls_verified"] is None


def test_the_transport_is_named_so_a_reader_knows_which_protocol(tmp_path):
    m, _ = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    assert m["collections"][0]["transport"]["protocol"] == "SAP RFC"


def test_it_records_that_encryption_was_not_requested_not_that_it_was_absent(tmp_path):
    """The distinction the whole record turns on. The collector can know what it
    asked for; it cannot know what the server enforced."""
    m, _ = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    t = m["collections"][0]["transport"]
    assert t["encryption_requested"] is False
    assert "unencrypted" not in json.dumps(t).lower()


def test_the_mechanism_is_named_so_the_remedy_is_findable(tmp_path):
    """"No encryption" tells an operator nothing to act on. SNC does."""
    m, _ = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    assert "SNC" in m["collections"][0]["transport"]["mechanism"]


# ═════════════════════════════════════════════════════════════════════════════
#  The operator has to see it
# ═════════════════════════════════════════════════════════════════════════════

def test_the_summary_raises_it_as_an_attention_line(tmp_path):
    """A field in a JSON file nobody opens is not a disclosure."""
    _, path = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    text = extract.summarise(path)
    assert "ATTENTION" in text
    assert "NO transport encryption was requested" in text


def test_the_summary_says_what_crossed_the_network(tmp_path):
    """The credentials and the authorisation model, not an abstraction."""
    _, path = _manifest(tmp_path, tls_verified=None, transport=RFC_TRANSPORT)
    assert "credentials and every source below" in extract.summarise(path)


def test_a_non_tls_transport_that_did_request_encryption_is_not_alarming(tmp_path):
    """If SNC is ever requested, the same None must read as a note rather than a
    warning — or the warning stops meaning anything."""
    _, path = _manifest(tmp_path, tls_verified=None,
                        transport={"protocol": "SAP RFC",
                                   "encryption_requested": True})
    text = extract.summarise(path)
    assert "ATTENTION" not in text
    assert "is not TLS" in text


def test_disabled_tls_verification_still_reads_as_disabled(tmp_path):
    """The pre-existing warning must survive the new branch. Three collectors
    depend on it."""
    _, path = _manifest(tmp_path, tls_verified=False)
    assert "verification was DISABLED" in extract.summarise(path)


def test_a_verified_tls_collection_says_nothing(tmp_path):
    """A warning on the healthy case is how the real one gets skipped."""
    _, path = _manifest(tmp_path, tls_verified=True)
    text = extract.summarise(path)
    assert "ATTENTION" not in text and "is not TLS" not in text


# ═════════════════════════════════════════════════════════════════════════════
#  The collector actually passes it
# ═════════════════════════════════════════════════════════════════════════════

def _cmd_rfc_source() -> str:
    src = (ROOT / "collect" / "__main__.py").read_text(encoding="utf-8")
    return src.split("def cmd_rfc", 1)[1].split("\ndef ", 1)[0]


def test_the_rfc_collector_states_its_transport():
    """A manifest field nothing populates is the state this change was made to
    leave behind."""
    body = _cmd_rfc_source()
    assert "tls_verified=None" in body, "cmd_rfc still inherits the True default"
    assert '"encryption_requested": False' in body


def test_the_other_collectors_still_record_their_tls_state():
    """Three of four already did this correctly and must keep doing it."""
    src = (ROOT / "collect" / "__main__.py").read_text(encoding="utf-8")
    assert src.count("tls_verified=") >= 4


def test_the_collector_does_not_claim_the_connection_was_unencrypted():
    """It sets no SNC parameters, so it knows what it asked for and not what the
    server did. Overclaiming here would be the same defect in the other
    direction."""
    body = _cmd_rfc_source()
    assert "cannot observe" in body
    assert "claim about them" in body


def test_the_note_points_at_the_parameters_a_reader_would_search_for():
    body = _cmd_rfc_source()
    for param in ("snc_mode", "snc_partnername", "snc_qop", "snc_lib"):
        assert param in body, param


def test_the_asymmetry_with_snc_posture_is_recorded():
    """This product audits exactly this question on customer estates. Saying so
    in the code is what stops the next reader assuming it was an oversight."""
    assert "snc_posture" in _cmd_rfc_source()
