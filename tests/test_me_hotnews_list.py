"""HOTNEWS-015 — the customer's own SAP-for-Me HotNews list, security notes only.

SAP for Me publishes, per customer, the HotNews that reach the products that
customer runs. Ingesting that list gives MonitorRisk SAP's own product scoping —
a stronger applicability signal than anything it infers — and these tests pin the
two directions that matter: the finding fires on a listed security note that is
not applied, and stays silent on one that is. They also pin the scope decision
(security notes only; functional/data-loss HotNews are excluded) and that the
.xlsx export SAP for Me offers is read end-to-end with no third-party dependency.
"""
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor   # noqa: E402
from modules.data_loader import DataLoader          # noqa: E402


def _fired(**data):
    out = {}
    for f in SapHotNewsAuditor(data).run_all_checks() or []:
        out.setdefault(f["check_id"], []).append(f)
    return out


def _row(number="3798315", title="[CVE-2026-76969] Credential disclosure in CAP",
         component="BC-XS-CDX-SEC", link="", version="15"):
    """A row shaped as the loader produces it (headers upper-cased, spaces->_)."""
    return {"SAP_COMPONENT": component, "NUMBER": number, "VERSION": version,
            "TITLE": title, "RELEASED_ON": "9-8-26",
            "LINK": link or ("https://me.sap.com/notes/%s" % number)}


#: An applied-notes export that makes has_applied True without covering the note
#: under test — so the list-minus-applied diff still surfaces it.
APPLIED_OTHER = [{"NOTE": "1", "STATUS": "Completely implemented"}]


# ═════════════════════════════════════════════════════════════════════════════
#  Fires / stays silent
# ═════════════════════════════════════════════════════════════════════════════

def test_listed_security_note_not_applied_is_reported():
    fired = _fired(me_hotnews=[_row()], applied_notes=APPLIED_OTHER)
    assert "HOTNEWS-015" in fired
    f = fired["HOTNEWS-015"][0]
    items = " ".join(f["affected_items"])
    assert "3798315" in items
    # the reference URL the user asked for, straight from the customer's export
    assert "me.sap.com/notes/3798315" in items
    assert {"type": "sap_note", "name": "3798315"} in f["affected_objects"]
    assert f["details"]["customer_authoritative"] is True


def test_listed_note_that_is_applied_is_not_reported():
    applied = [{"NOTE": "3798315", "STATUS": "Completely implemented"}]
    assert "HOTNEWS-015" not in _fired(me_hotnews=[_row()], applied_notes=applied)


def test_no_list_supplied_is_silent():
    assert "HOTNEWS-015" not in _fired(applied_notes=APPLIED_OTHER)


# ═════════════════════════════════════════════════════════════════════════════
#  Scope — security notes only (the user's decision)
# ═════════════════════════════════════════════════════════════════════════════

def test_functional_hotnews_row_is_excluded_by_scope():
    """A data-loss HotNews with no CVE in its title is not this scanner's to raise."""
    func = _row(number="3794443", component="HAN-DB",
                title="Standard Table Partitioning can Introduce Duplicate "
                      "Records or Table Inconsistencies")
    assert "HOTNEWS-015" not in _fired(me_hotnews=[func], applied_notes=APPLIED_OTHER)


def test_multiple_vulnerabilities_row_is_treated_as_security():
    """A 'Multiple vulnerabilities' HotNews is a security note even with no CVE id."""
    r = _row(number="3341460", component="BC-SYB-PD",
             title="Multiple Vulnerabilities in SAP PowerDesigner")
    assert "HOTNEWS-015" in _fired(me_hotnews=[r], applied_notes=APPLIED_OTHER)


def test_a_security_and_a_functional_row_report_only_the_security_one():
    rows = [_row(),  # security (CVE)
            _row(number="3731697", component="BC-UPG-DTM-TLA",
                 title="SUM 2.0 SP25: Potential data loss in table NRIV")]
    fired = _fired(me_hotnews=rows, applied_notes=APPLIED_OTHER)
    assert fired["HOTNEWS-015"][0]["details"]["count"] == 1


# ═════════════════════════════════════════════════════════════════════════════
#  Note number provenance — never invented
# ═════════════════════════════════════════════════════════════════════════════

def test_note_number_is_read_from_the_link_when_number_is_blank():
    r = _row(number="", link="https://me.sap.com/notes/3759472", component="BC-CST-MS",
             title="[CVE-2026-58240] Missing Authentication check in Message Server")
    fired = _fired(me_hotnews=[r], applied_notes=APPLIED_OTHER)
    assert "HOTNEWS-015" in fired
    assert "3759472" in " ".join(fired["HOTNEWS-015"][0]["affected_items"])


def test_a_row_with_no_resolvable_note_number_is_dropped_not_guessed():
    r = {"SAP_COMPONENT": "BC", "NUMBER": "", "LINK": "",
         "TITLE": "[CVE-2026-0001] something"}
    assert "HOTNEWS-015" not in _fired(me_hotnews=[r], applied_notes=APPLIED_OTHER)


# ═════════════════════════════════════════════════════════════════════════════
#  Severity + worklist framing
# ═════════════════════════════════════════════════════════════════════════════

def test_a_known_exploited_note_on_the_list_is_critical():
    # 3594142 / CVE-2025-31324 is exploited-in-the-wild in the curated catalogue.
    r = _row(number="3594142", component="BC-VCM",
             title="[CVE-2025-31324] Unauthenticated file upload to Visual Composer")
    f = _fired(me_hotnews=[r], applied_notes=APPLIED_OTHER)["HOTNEWS-015"][0]
    assert f["severity"] == "CRITICAL"
    assert "exploited in the wild" in " ".join(f["affected_items"])
    assert f["details"]["exploited"] >= 1


def test_without_applied_notes_the_list_is_a_worklist():
    fired = _fired(me_hotnews=[_row()])
    assert "HOTNEWS-015" in fired
    assert fired["HOTNEWS-015"][0]["details"]["applied_notes_supplied"] is False


# ═════════════════════════════════════════════════════════════════════════════
#  XLSX ingest — SAP for Me's spreadsheet download, read with the stdlib
# ═════════════════════════════════════════════════════════════════════════════

_SHARED = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    ' count="5" uniqueCount="5">'
    '<si><t>SAP Component</t></si><si><t>Number</t></si><si><t>Title</t></si>'
    '<si><t>BC-XS-CDX-SEC</t></si>'
    '<si><t>[CVE-2026-76969] Credential disclosure in CAP</t></si></sst>')

_SHEET = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<sheetData>'
    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c>'
    '<c r="C1" t="s"><v>2</v></c></row>'
    '<row r="2"><c r="A2" t="s"><v>3</v></c><c r="B2"><v>3798315</v></c>'
    '<c r="C2" t="s"><v>4</v></c></row>'
    '</sheetData></worksheet>')


def _write_xlsx(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/sharedStrings.xml", _SHARED)
        z.writestr("xl/worksheets/sheet1.xml", _SHEET)


def test_load_xlsx_parses_shared_strings_and_numeric_cells(tmp_path):
    path = tmp_path / "me_hotnews.xlsx"
    _write_xlsx(path)
    rows = DataLoader(tmp_path)._load_xlsx(path)
    assert rows == [{"SAP_COMPONENT": "BC-XS-CDX-SEC", "NUMBER": "3798315",
                     "TITLE": "[CVE-2026-76969] Credential disclosure in CAP"}]


def test_xlsx_export_flows_through_load_all_into_the_check(tmp_path):
    _write_xlsx(tmp_path / "me_hotnews.xlsx")
    data = DataLoader(tmp_path).load_all()
    rows = data.get("me_hotnews")
    assert rows and rows[0]["NUMBER"] == "3798315"

    fired = {}
    for f in SapHotNewsAuditor({"me_hotnews": rows,
                                "applied_notes": APPLIED_OTHER}).run_all_checks():
        fired.setdefault(f["check_id"], []).append(f)
    assert "HOTNEWS-015" in fired


def test_unreadable_xlsx_is_the_third_state_not_empty(tmp_path):
    """A file the customer supplied that will not open is None, not [], so
    'was this supplied?' stays honest — the same contract _load_csv uses."""
    bad = tmp_path / "me_hotnews.xlsx"
    bad.write_bytes(b"this is not a zip")
    loader = DataLoader(tmp_path)
    assert loader._load_xlsx(bad) is None
    assert "me_hotnews.xlsx" in loader.unreadable_sources
