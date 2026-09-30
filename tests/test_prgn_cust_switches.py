"""
PRGN_CUST customizing-switch checks (SAP Baseline v2.6: AUTHASSIGN-A, USRTYP-A,
USRCHAR-A).

Each check gets a positive test (a non-compliant switch fires it) and negative
controls (compliant value, and no export at all, stay silent). The absence of a
switch from a SUPPLIED export is itself non-compliant — a switch left unset runs
on its permissive default — so that case is asserted too.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.prgn_cust_switches import PrgnCustSwitchAuditor  # noqa: E402


def _run(rows):
    """rows is a list of (switch, value); None rows means no export supplied."""
    data = {} if rows is None else {"prgn_cust": [{"ID": s, "PATH": v} for s, v in rows]}
    return {f["check_id"]: f for f in PrgnCustSwitchAuditor(data, {}).run_all_checks()}


COMPLIANT = [
    ("US_ASGM_TRANSPORT", "NO"),
    ("USER_REL_IMPORT", "no"),      # case-insensitive
    ("REF_USER_CHECK", "E"),
    ("BNAME_RESTRICT", "ALL"),
]


def test_a_fully_compliant_prgn_cust_is_silent():
    assert _run(COMPLIANT) == {}


def test_no_export_is_silent():
    assert _run(None) == {}


# ── AUTHASSIGN-A ──────────────────────────────────────────────────────────────
def test_a_transport_switch_not_no_fires_authassign():
    f = _run([("US_ASGM_TRANSPORT", "YES"), ("USER_REL_IMPORT", "NO"),
              ("REF_USER_CHECK", "E"), ("BNAME_RESTRICT", "ALL")])
    assert "AUTHASSIGN-001" in f
    assert f["AUTHASSIGN-001"]["severity"] == "MEDIUM"
    assert {o["name"] for o in f["AUTHASSIGN-001"]["affected_objects"]} == {"US_ASGM_TRANSPORT"}


def test_an_unset_transport_switch_fires_authassign():
    # REF_USER_CHECK/BNAME_RESTRICT present-and-compliant; both transport switches absent
    f = _run([("REF_USER_CHECK", "E"), ("BNAME_RESTRICT", "ALL")])
    assert "AUTHASSIGN-001" in f
    names = {o["name"] for o in f["AUTHASSIGN-001"]["affected_objects"]}
    assert names == {"US_ASGM_TRANSPORT", "USER_REL_IMPORT"}


# ── USRTYP-A ──────────────────────────────────────────────────────────────────
def test_ref_user_check_not_e_fires_usrtyp():
    f = _run([("REF_USER_CHECK", "X")] + COMPLIANT[:2] + [("BNAME_RESTRICT", "ALL")])
    assert "USRTYP-001" in f
    assert f["USRTYP-001"]["affected_objects"][0]["name"] == "REF_USER_CHECK"


def test_ref_user_check_e_is_silent():
    assert "USRTYP-001" not in _run(COMPLIANT)


# ── USRCHAR-A ─────────────────────────────────────────────────────────────────
def test_bname_restrict_not_set_fires_usrchar():
    f = _run(COMPLIANT[:3])  # BNAME_RESTRICT absent
    assert "USRCHAR-001" in f


def test_bname_restrict_xxx_or_all_is_silent():
    assert "USRCHAR-001" not in _run(COMPLIANT[:3] + [("BNAME_RESTRICT", "XXX")])
    assert "USRCHAR-001" not in _run(COMPLIANT[:3] + [("BNAME_RESTRICT", "all")])


def test_every_finding_carries_a_verified_baseline_reference():
    # Provenance: each finding cites SAP's own requirement and policy predicate,
    # never an unverified note number as the source.
    for f in _run([("US_ASGM_TRANSPORT", "YES")]).values():
        assert any(r.startswith("SAP Security Baseline") for r in f["references"])
        assert any("SAP policy check" in r for r in f["references"])
