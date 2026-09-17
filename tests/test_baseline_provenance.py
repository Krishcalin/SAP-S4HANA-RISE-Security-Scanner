"""
The provenance of a legacy (non-ECS) parameter finding.

WHAT THIS FILE IS DEFENDING
---------------------------
`SecurityParamAuditor.BASELINE` is the pre-3250501 rule set. Its entries cite two
populations of reference: values transcribed verbatim from SAP's Apache-2.0 CSA
policy XML / Security Baseline (VERIFIED), and legacy SAP Note numbers plus CIS
clauses that predate this work and were never checked against the note's own
reference list (UNVERIFIED — enumerated in the module and in monitorrisk-accuracy).

Two things went wrong at once, and both reached the customer:

  1. `_details()` stamped `baseline_source` only for the ECS rules, so every one
     of the 33 BASELINE rules sent an EMPTY `source` into `server/remediation.py`
     and `server/servicerequest.py`.
  2. The full `refs` list — unverified notes included — rode onto the finding.
     `servicerequest._basis()` returns the first ref containing "Note" as the
     document SAP checks the request against, so an unverified note number was
     published into a customer→SAP request. CLAUDE.md forbids citing an
     unverified SAP identifier anywhere customer-facing.

The fix cleans the refs and stamps a verified source at the single emit point in
`modules/security_params.py`; this file is the guard that it stays fixed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_params import (                                # noqa: E402
    _UNVERIFIED_BASELINE_NOTES,
    _ref_is_verified,
    SecurityParamAuditor,
)

BASELINE = SecurityParamAuditor.BASELINE


def _looks_unverified(ref: str) -> bool:
    """The property no published reference may have: a legacy note number or a
    CIS clause. Independent of `_ref_is_verified` on purpose — this is the
    outcome the guard asserts, not the function under test asking itself."""
    text = str(ref)
    if "CIS SAP Benchmark" in text:
        return True
    return any(("Note" in text) and (num in text)
               for num in _UNVERIFIED_BASELINE_NOTES)


# --------------------------------------------------------------------------- #
#  The classifier                                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ref", [
    "SAP policy 2AUSRCTR check USRCTR-A_a.1 — NAME = 'dynp/checkskip1screen' and VALUE = 'ALL'",
    "SAP Security Baseline USRCTR-A",
    "SAP Security Baseline v2.6 PWDPOL-A c)",
    "SAP Note 3250501",                       # the ECS note, transcribed wholesale
    "SAP Note 1956086 (cited by SAP's own baseline)",
    "SAP 'Securing RFC' section 6 — gw/sim_mode not left active",
])
def test_verified_references_are_kept(ref):
    assert _ref_is_verified(ref)


@pytest.mark.parametrize("ref", [
    "SAP Note 68048",
    "SAP Note 2416093",
    "SAP Note 1408081",
    "SAP Note 510007",
    "SAP Note 2191612",
    "CIS SAP Benchmark 1.1.1",
    "CIS SAP Benchmark 7.1",
])
def test_unverified_references_are_rejected(ref):
    assert not _ref_is_verified(ref)


# --------------------------------------------------------------------------- #
#  Every rule, at the source                                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", sorted(BASELINE))
def test_published_refs_for_every_rule_are_verified_and_non_empty(name):
    rule = BASELINE[name]
    published = SecurityParamAuditor._public_refs(rule)
    assert published, name
    leaked = [r for r in published if _looks_unverified(r)]
    assert not leaked, (name, leaked)


@pytest.mark.parametrize("name", sorted(BASELINE))
def test_every_rule_carries_a_verified_source_label(name):
    rule = BASELINE[name]
    source = SecurityParamAuditor._source_label(rule)
    assert source, name                       # never the empty string it was
    assert not _looks_unverified(source), (name, source)
    # And `_details` — the actual carrier read by the server — agrees.
    details = SecurityParamAuditor._details(name, rule, "whatever")
    assert details["baseline_source"] == source


def test_a_rule_with_only_unverified_refs_falls_back_to_the_generic_baseline():
    """`login/no_automatic_user_sapstar` cites only note 68048 and a CIS clause;
    with both withheld, the finding must still carry a reference — the generic
    one CLAUDE.md prescribes, not a blank."""
    published = SecurityParamAuditor._public_refs(
        BASELINE["login/no_automatic_user_sapstar"])
    assert published == ["SAP Security Baseline"]


def test_a_verified_note_survives_while_its_cis_neighbour_is_dropped():
    """`login/min_password_lng` cites note 3250501 (verified) AND CIS 1.1.1. The
    note is kept — losing it would weaken a real citation — and the CIS clause
    goes."""
    published = SecurityParamAuditor._public_refs(BASELINE["login/min_password_lng"])
    assert published == ["SAP Note 3250501"]


# --------------------------------------------------------------------------- #
#  End to end — the emit path, not just the helpers                           #
# --------------------------------------------------------------------------- #

#: Parameters note 3250501 does NOT mandate, so `effective_rules()` leaves them
#: on the BASELINE rule and the finding travels the legacy emit path this fix is
#: about — an ECS-mandated parameter would resolve to the ECS rule and never
#: exercise it. Each: (parameter, a value that FAILS its rule).
_LEGACY_ONLY_FAILING = [
    ("rfc/reject_insecure_logon", "0"),        # 2416093 + CIS  -> generic
    ("rfc/allowoldticket4tt", "1"),            # 2416093        -> generic
    ("login/disable_multi_gui_login", "0"),    # CIS 1.2.6      -> generic
    ("rdisp/wpdbug_max_no", "5"),              # CIS 7.1        -> generic
    ("abap/path_normalization", "off"),        # verified refs, both KEPT
]


def _finding_for(param: str, value: str) -> dict:
    auditor = SecurityParamAuditor(
        {"security_params": [{"NAME": param, "VALUE": value}]}, {})
    findings = [f for f in auditor.run_all_checks()
                if f["check_id"] == f"PARAM-{param}"]
    assert len(findings) == 1, (param, value, [f["check_id"] for f in findings])
    return findings[0]


@pytest.mark.parametrize("param,value", _LEGACY_ONLY_FAILING)
def test_emitted_legacy_finding_is_clean_and_sourced(param, value):
    finding = _finding_for(param, value)

    # 1. No unverified citation reached the finding the customer sees.
    leaked = [r for r in finding["references"] if _looks_unverified(r)]
    assert not leaked, (param, leaked)

    # 2. It carries a non-empty, verified source (what the service request reads).
    source = finding["details"].get("baseline_source")
    assert source and not _looks_unverified(source), (param, source)

    # 3. A reference is always present — never a blank cell.
    assert finding["references"], param


def test_verified_refs_survive_the_legacy_emit_path():
    """`abap/path_normalization` is legacy-only AND fully verified (a baseline
    requirement name plus a policy predicate quote). The fix must PROPAGATE those
    verbatim, not treat 'not ECS' as 'withhold'."""
    finding = _finding_for("abap/path_normalization", "off")
    assert finding["references"] == [
        "SAP Security Baseline FILE-A", "SAP policy 2AFILE check FILE-A_a2"]
    assert finding["details"]["baseline_source"] == "SAP Security Baseline FILE-A"


def test_a_legacy_only_finding_that_had_only_unverified_refs_now_has_a_source():
    """`rfc/reject_insecure_logon` cited note 2416093 and a CIS clause — both
    withheld — and used to send `source: ''` to the service request. It now
    carries the generic baseline."""
    finding = _finding_for("rfc/reject_insecure_logon", "0")
    assert finding["references"] == ["SAP Security Baseline"]
    assert finding["details"]["baseline_source"] == "SAP Security Baseline"
