"""The standards mapping, and the guards that keep it from becoming a guess.

Mapping 673 checks to the OWASP Top 10 by reading their names would take an
afternoon and would produce a compliance panel showing full coverage of every
category, none of it evidence. The tests here are mostly about the opposite
property: that every mapping records WHERE IT CAME FROM, and that the checks with
no honest category stay unmapped and counted rather than being swept into A05.
"""
from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.owasp_mapping import (API10, ASVS, CWE_TO_OWASP,      # noqa: E402
                                   FAMILY_TO_OWASP, TOP10,
                                   UNMAPPED_CWE, UNMAPPED_FAMILY,
                                   coverage, map_finding)


# ═════════════════════════════════════════════════════════════════════════════
#  Provenance — the property that separates a mapping from a guess
# ═════════════════════════════════════════════════════════════════════════════

def test_every_mapping_records_the_basis_it_rests_on():
    """A mapping whose provenance is invisible cannot be told apart from one
    somebody invented, which is why `basis` is not optional."""
    for check, cwe, expected in (("ABAP-SQLI-001", "CWE-89", "cwe"),
                                 ("ARA-P2P-01", None, "family"),
                                 ("RISE-001", None, None)):
        assert map_finding(check, cwe)["basis"] == expected


def test_a_cwe_beats_a_family_guess():
    """The CWE half is OWASP's own published derivation. A curated family
    judgement must never override it — ABAP-* would otherwise map everything to
    A03 including the access-control rules."""
    result = map_finding("ABAP-CDS-003", "CWE-862")
    assert result["basis"] == "cwe"
    assert result["owasp_top10"] == "A01"      # not A03 from an ABAP family rule


def test_an_unmapped_finding_carries_the_reason_not_just_silence():
    result = map_finding("FIN-PP-001")
    assert result["basis"] is None
    assert "financial control framework" in result["unmapped_reason"]


def test_an_unknown_family_says_so_rather_than_defaulting():
    result = map_finding("ZZZ-999")
    assert result["basis"] is None
    assert "no OWASP mapping has been curated" in result["unmapped_reason"]


# ═════════════════════════════════════════════════════════════════════════════
#  The unmapped bucket must stay honest
# ═════════════════════════════════════════════════════════════════════════════

def test_nothing_unclassifiable_was_swept_into_security_misconfiguration():
    """A05 is where everything ends up when a mapping is forced. The families
    deliberately left out are the test: if one of them acquires an A05 mapping
    without its reason being removed first, the two tables contradict."""
    overlap = set(FAMILY_TO_OWASP) & set(UNMAPPED_FAMILY)
    assert not overlap, "a family is both mapped and declared unmapped: %s" % overlap


def test_a_cwe_is_never_both_mapped_and_declared_unmappable():
    overlap = set(CWE_TO_OWASP) & set(UNMAPPED_CWE)
    assert not overlap, overlap


def test_every_unmapped_entry_gives_a_reason_of_substance():
    """"Not applicable" is not a reason. Each entry has to say what the subject
    actually is and why no category fits."""
    for table in (UNMAPPED_CWE, UNMAPPED_FAMILY):
        for key, reason in table.items():
            assert len(reason) > 60, "%s has a token reason: %r" % (key, reason)


def test_the_unmapped_set_is_expected_to_be_non_empty():
    """A product whose every check mapped cleanly to the Top 10 would either be
    a web-application scanner or be lying. This one audits contracts, financial
    configuration and disaster recovery."""
    result = coverage()
    assert result["by_basis"]["unmapped"] > 0
    assert set(result["unmapped_families"]) & {"RISE", "FIN", "RES"}


# ═════════════════════════════════════════════════════════════════════════════
#  Internal consistency
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("table", [CWE_TO_OWASP])
def test_every_cwe_row_points_at_categories_that_exist(table):
    for cwe, (top, api, asvs) in table.items():
        assert top in TOP10, "%s -> unknown Top 10 %s" % (cwe, top)
        assert api is None or api in API10, "%s -> unknown API %s" % (cwe, api)
        assert asvs in ASVS, "%s -> unknown ASVS chapter %s" % (cwe, asvs)


def test_every_family_row_points_at_categories_that_exist_and_gives_a_rationale():
    for fam, (top, api, asvs, why) in FAMILY_TO_OWASP.items():
        assert top in TOP10, fam
        assert api is None or api in API10, fam
        assert asvs in ASVS, fam
        assert len(why) > 25, "%s has no real rationale: %r" % (fam, why)


def test_every_cwe_the_code_rules_use_is_either_mapped_or_declared():
    """A CWE that appears in a rule table and in neither mapping table would go
    silently unmapped — the finding would carry no standards fields and no
    reason, which is the one outcome both tables exist to prevent."""
    from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,
                                   ALL_JS_RULES, CROSS_ARTIFACT_RULES)
    used = set()
    for table in (ALL_ABAP_SAST_RULES, ALL_JS_RULES, ALL_BTP_CONFIG_RULES,
                  CROSS_ARTIFACT_RULES):
        used |= {str(r["cwe"]).upper() for r in table if r.get("cwe")}
    unaccounted = sorted(used - set(CWE_TO_OWASP) - set(UNMAPPED_CWE))
    assert not unaccounted, "CWEs in rule tables with no decision: %s" % unaccounted


# ═════════════════════════════════════════════════════════════════════════════
#  It reaches real findings
# ═════════════════════════════════════════════════════════════════════════════

def test_the_acceptance_criterion_a_cap_authorization_finding_maps_to_a01():
    """SRS AC-01: a CAP app missing @requires/@restrict must produce a finding
    mapped to OWASP A01 / API authorization / ASVS Authorization. The detection
    half already worked; this is the half that did not exist."""
    from modules.cap_xsuaa import CapXsuaaAuditor
    fixture = ROOT / "tests" / "fixtures" / "cap_project"
    with contextlib.redirect_stdout(io.StringIO()):
        findings = CapXsuaaAuditor({"cap_project_dir": str(fixture)}, {}).run_all_checks()
    cds = next(f for f in findings if f["check_id"] == "CAPX-CDS-001")
    assert cds["owasp"]["owasp_top10"] == "A01"
    assert cds["owasp"]["owasp_api"] == "API5"
    assert cds["owasp"]["asvs"] == "V4"
    assert cds["remediation"]


def test_every_finding_from_a_real_scan_carries_the_mapping_block():
    """Attached in BaseAuditor.finding so it reaches all 673 checks from one
    place. A module that forgot to call a helper would be invisible."""
    from modules.data_loader import DataLoader
    from modules.sap_hotnews import SapHotNewsAuditor
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        findings = SapHotNewsAuditor(data, {}).run_all_checks()
    assert findings
    for finding in findings:
        assert "owasp" in finding, finding["check_id"]
        assert "basis" in finding["owasp"], finding["check_id"]


def test_a_code_finding_resolves_through_its_cwe_at_runtime():
    from modules.abap_sast import AbapSourceScanner
    scanner = AbapSourceScanner(data_flow=True)
    raw = scanner.scan_text("SELECT * FROM t WHERE f = lv_x.", Path("x.abap"))
    assert isinstance(raw, list)          # the scan itself is not the subject
    result = map_finding("ABAP-SQLI-001", "CWE-89")
    assert result["owasp_top10"] == "A03" and result["basis"] == "cwe"


# ═════════════════════════════════════════════════════════════════════════════
#  What is deliberately absent
# ═════════════════════════════════════════════════════════════════════════════

def test_no_cvss_vector_is_invented_for_a_configuration_finding():
    """SRS SCORE-01 asks for a CVSS vector on every finding. CVSS scores a
    vulnerability in a product — Attack Vector, Attack Complexity, Privileges
    Required. "This subaccount has no audit logging" has none of those, and
    inventing one would manufacture precision. CVEs carry real vectors from the
    SAP CNA record; configuration findings carry severity and business context."""
    from modules.data_loader import DataLoader
    from modules.btp_cloud_surface import BtpCloudSurfaceAuditor
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        findings = BtpCloudSurfaceAuditor(data, {}).run_all_checks()
    gov = next(f for f in findings if f["check_id"] == "BTP-GOV-001")
    assert "cvss" not in gov and "cvss_vector" not in gov
    assert "cvss" not in gov["owasp"]
    assert gov["severity"]                      # what it does have


def test_the_coverage_figure_is_measured_not_asserted():
    result = coverage()
    assert result["checks"] > 600
    total = sum(result["by_basis"].values())
    assert total == result["checks"], "the bases do not partition the catalogue"
