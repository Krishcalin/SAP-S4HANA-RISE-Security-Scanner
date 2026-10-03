"""MITRE ATT&CK mapping of the observed-behaviour (LogServ) detections.

modules/mitre_mapping.py maps the retrospective log-threat checks to ATT&CK
techniques (with a confidence + source), falls back to a TACTIC-ONLY tag where a
SAP threat has no clean technique, and maps nothing for configuration / code /
vulnerability findings — ATT&CK describes adversary actions, not weaknesses. What
must hold: every mapping is internally consistent and uses a real technique/tactic,
every mapped check id is a REAL check in the catalogue (no fabricated id), the
debug case is tactic-only, and non-behaviour findings carry the reason they're
unmapped rather than a silent blank.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import mitre_mapping as mm  # noqa: E402

_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_THREAT_PREFIXES = ("LREV-PAT", "LVIO-", "GWLOG", "HANALOG", "ICMLOG", "NETLOG", "CORR-")


def test_representative_mappings():
    cases = {
        "LREV-PAT-002": ("T1110", "Credential Access"),
        "LREV-PAT-003": ("T1078.001", "Initial Access"),
        "LREV-PAT-006": ("T1562.001", "Defense Evasion"),
        "LREV-PAT-008": ("T1059", "Execution"),
        "LREV-PAT-010": ("T1110.003", "Credential Access"),
        "HANALOG-001": ("T1562.001", "Defense Evasion"),
        "HANALOG-003": ("T1110", "Credential Access"),
        "ICMLOG-002": ("T1595.002", "Reconnaissance"),
        "ICMLOG-003": ("T1190", "Initial Access"),
        "NETLOG-003": ("T1133", "Initial Access"),
        "CORR-GW-001": ("T1190", "Initial Access"),
    }
    for cid, (tech, tactic) in cases.items():
        m = mm.map_mitre(cid)
        assert m["basis"] == "check", cid
        assert m["technique"] == tech, cid
        assert m["tactic"] == tactic, cid
        assert m["technique_name"] == mm.TECHNIQUES[tech], cid
        assert m["confidence"] in ("high", "medium", "low"), cid
        assert m["source"], cid


def test_debug_is_tactic_only_not_a_forced_technique():
    m = mm.map_mitre("LREV-PAT-004")
    assert m["basis"] == "check"          # we DID consider it
    assert m["technique"] is None         # but assigned no technique
    assert m["technique_name"] is None
    assert m["tactic"] in mm.TACTICS
    assert m["confidence"] == "low"


def test_non_behaviour_findings_are_unmapped_with_a_reason():
    for cid in ("PARAM-0001", "ABAP-SQLI-001", "HOTNEWS-001", "AUTH-015",
                "CRYPTO-001", "ARA-DIDDO-001", ""):
        m = mm.map_mitre(cid)
        assert m["basis"] is None, cid
        assert m["unmapped_reason"], cid
        assert "technique" not in m, cid


def test_every_mapping_is_internally_consistent():
    for cid in mm.mapped_check_ids():
        m = mm.map_mitre(cid)
        tech = m["technique"]
        if tech is not None:
            assert _TID.match(tech), f"{cid}: bad technique id {tech}"
            assert tech in mm.TECHNIQUES, f"{cid}: {tech} missing from TECHNIQUES"
        assert m["tactic"] in mm.TACTICS, f"{cid}: unknown tactic {m['tactic']}"
        assert m["confidence"] in ("high", "medium", "low"), cid


def test_only_logserv_threat_families_are_mapped():
    for cid in mm.mapped_check_ids():
        assert cid.startswith(_THREAT_PREFIXES), \
            f"{cid} is mapped but is not a LogServ observed-threat family"


def test_the_core_logserv_detections_are_all_mapped():
    """A LogServ threat detection with no ATT&CK tag would read, on the Perceived
    Threats screen, as if it were deliberately un-classifiable. Pin the known set
    so a new one that is forgotten is caught here."""
    expected = (
        [f"LREV-PAT-{n:03d}" for n in range(1, 11)]
        + ["LVIO-FF-001", "LVIO-OFH-001"]
        + ["GWLOG-001", "GWLOG-002", "GWLOG-003"]
        + ["HANALOG-001", "HANALOG-002", "HANALOG-003"]
        + ["ICMLOG-001", "ICMLOG-002", "ICMLOG-003"]
        + ["NETLOG-001", "NETLOG-002", "NETLOG-003"]
        + ["CORR-GW-001", "CORR-HANA-001", "CORR-ICM-001", "CORR-NET-001"]
    )
    for cid in expected:
        assert mm.map_mitre(cid)["basis"] == "check", f"{cid} lost its ATT&CK mapping"


def test_every_mapped_check_id_is_a_real_catalogue_check():
    """Accuracy guard: a mapping keyed on a check id that the product cannot
    actually raise is a fabricated mapping. Every key must be a real check."""
    from modules.coverage import check_catalogue
    catalogue = set(check_catalogue())
    unknown = [cid for cid in mm.mapped_check_ids() if cid not in catalogue]
    assert not unknown, f"mapped check ids not in the catalogue: {unknown}"


def test_coverage_counts_split_technique_tactic_unmapped():
    cov = mm.coverage(["LREV-PAT-002", "LREV-PAT-004", "PARAM-1"])
    assert cov == {"total": 3, "technique": 1, "tactic_only": 1, "unmapped": 1}
