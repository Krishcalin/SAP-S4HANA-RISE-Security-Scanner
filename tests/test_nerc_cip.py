"""NERC CIP, for the utility running SAP.

WHY THIS FRAMEWORK. This product already carries OT and plant-floor content, and
a utility running SAP is the buyer for whom CIP-007 and CIP-010 land directly on
the parameter, patch and account checks the scanner already runs. It is one of
the two frameworks `docs/COMPETITOR_ONAPSIS.md` §2.3 names as theirs and not
ours.

THE RULE THE WHOLE MAPPING IS HELD TO, from the module's own docstring: "the
control is listed only if it is one this scanner's findings are genuinely
evidence against". Breadth is worth nothing here — a control id an auditor pulls
on and we cannot defend costs more than the gap it papered over.

CITED AT STANDARD + REQUIREMENT, NEVER PART LEVEL, and with no version suffix.
"CIP-007 R2" is defensible; "CIP-007-6 R2 Part 2.3" asserts what a sub-part says,
and the version moves. This is the decision DORA already got in the same file,
for the same reason, and these tests hold it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.compliance_mapping import ComplianceMapper                # noqa: E402

CIP = next(f for f in ComplianceMapper.FRAMEWORKS if f["id"] == "nerccip")
CONTROLS = {cid for lst in CIP["themes"].values() for cid, _ in lst}


def _assess(*categories, severity="HIGH"):
    findings = [{"severity": severity, "category": c} for c in categories]
    return {f["id"]: f for f in ComplianceMapper(findings).assess()}


# ── how it is cited ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_every_citation_is_a_standard_and_a_requirement(control):
    """`CIP-007 R2` — nothing narrower, nothing vaguer."""
    assert re.fullmatch(r"CIP-0\d{2} R\d+", control), control


@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_no_version_suffix_is_pinned(control):
    """CIP-007-6 becomes CIP-007-7. A version pinned here goes stale silently
    and is still quoted as current."""
    assert not re.search(r"CIP-\d{3}-\d", control), control


@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_no_part_level_citation(control):
    """"Part 2.3" asserts what a specific sub-part says. Unverified, that is the
    coverage that collapses on the first auditor question."""
    assert not re.search(r"\bR\d+\.\d", control), control


def test_only_standards_that_exist_are_cited():
    """A fabricated standard number is the credibility failure this project has
    already suffered once."""
    real = {"CIP-002", "CIP-003", "CIP-004", "CIP-005", "CIP-006", "CIP-007",
            "CIP-008", "CIP-009", "CIP-010", "CIP-011", "CIP-012", "CIP-013",
            "CIP-014"}
    cited = {c.split()[0] for c in CONTROLS}
    assert cited <= real, "unknown CIP standard(s): %s" % sorted(cited - real)


# ── what is deliberately not claimed ─────────────────────────────────────────

def test_the_programme_and_physical_standards_are_not_claimed():
    """An SAP export is not evidence about which systems are BES Cyber Systems,
    about a designated CIP Senior Manager, or about a door."""
    cited = {c.split()[0] for c in CONTROLS}
    for standard, why in (("CIP-002", "categorisation is the customer's"),
                          ("CIP-003", "policy and programme artefacts"),
                          ("CIP-006", "physical security"),
                          ("CIP-012", "control-centre communications"),
                          ("CIP-014", "physical security of transmission")):
        assert standard not in cited, "%s claimed — %s" % (standard, why)


def test_segregation_of_duties_is_not_mapped_here():
    """NERC CIP has no SoD requirement. It is mapped for ISO, SOX and the
    others, and inventing a CIP home for it would be breadth for its own sake."""
    assert "sod" not in CIP["themes"]


def test_secure_development_is_not_mapped_here():
    """CIP's software provisions are about vendor supply chain (CIP-013), not a
    customer's own ABAP."""
    assert "secure-development" not in CIP["themes"]


def test_the_scope_caveat_is_written_down_where_it_will_be_read():
    """An SAP ERP system is very often NOT a BES Cyber System. Where it falls
    outside CIP scope these requirements do not reach it at all, and a mapping
    that does not say so invites being read as a compliance claim."""
    source = (ROOT / "modules" / "compliance_mapping.py").read_text(encoding="utf-8")
    block = source[source.index('"id": "nerccip"') - 4000:
                   source.index('"id": "nerccip"')]
    assert "NOT a BES Cyber System" in block
    assert "CIP-002" in block


# ── that it actually maps ────────────────────────────────────────────────────

def test_a_patch_finding_reaches_patch_management_and_vulnerability_assessment():
    got = _assess("SAP Security Notes (HotNews)")
    assert "nerccip" in got, "a missing-note finding reached no CIP requirement"
    ids = {c["id"] for c in got["nerccip"]["controls"]}
    assert {"CIP-007 R2", "CIP-010 R3"} <= ids


def test_a_password_finding_reaches_system_access_control():
    got = _assess("Password Policy")
    ids = {c["id"] for c in got["nerccip"]["controls"]}
    assert "CIP-007 R5" in ids


def test_an_audit_log_finding_reaches_security_event_monitoring():
    got = _assess("Audit Logging")
    ids = {c["id"] for c in got["nerccip"]["controls"]}
    assert "CIP-007 R4" in ids


def test_a_password_finding_does_not_reach_unrelated_requirements():
    """NEGATIVE CONTROL. Over-mapping is the failure mode of every compliance
    matrix: a password parameter is not evidence about recovery plans or
    incident response."""
    got = _assess("Password Policy")
    ids = {c["id"] for c in got["nerccip"]["controls"]}
    assert "CIP-009 R1" not in ids
    assert "CIP-008 R1" not in ids


def test_an_unmapped_category_flags_no_requirement():
    """`assess()` returns every framework whatever happens, so the honest
    signal is the CONTENT: a finding in a category nothing maps reaches no CIP
    requirement, rather than being spread thinly across all fifteen."""
    got = _assess("A Category That Does Not Exist")
    assert got["nerccip"]["mapped_findings"] == 0
    assert got["nerccip"]["controls"] == []
