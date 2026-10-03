"""Transport Content Auditor — what each transport CARRIES (E070/E071).

modules/transport_content.py reads the transport object directory and flags the
security-relevant payload a route/approval check cannot see: authorization-check
deactivation (TOBJ_OFF), user/role table content, security object types, table
content, and transports of copies imported to production. What must hold: each
check FIRES on the real SAP identifier it targets at the right severity; the
auth tables are raised at HIGH and excluded from the MEDIUM table-content check;
the transport-of-copies check requires a production import (correlated with
history); a missing object directory discloses "not assessed" only when there IS
transport history; and nothing is invented from an empty row.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.transport_content import TransportContentAuditor  # noqa: E402


def _obj(trkorr, pgmid, object_type, obj_name, trfunction="K"):
    return {"TRKORR": trkorr, "TRFUNCTION": trfunction, "PGMID": pgmid,
            "OBJECT": object_type, "OBJ_NAME": obj_name}


def _run(objects: Optional[List[Dict[str, Any]]] = None,
         history: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    data: Dict[str, Any] = {}
    if objects is not None:
        data["transport_objects"] = objects
    if history is not None:
        data["transport_history"] = history
    return TransportContentAuditor(data).run_all_checks()


def _by_id(objects=None, history=None) -> Dict[str, Dict[str, Any]]:
    return {f["check_id"]: f for f in _run(objects, history)}


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-006 — authorization-check deactivation (TOBJ_OFF)
# ═════════════════════════════════════════════════════════════════════════════

def test_tobj_off_content_is_critical_auth_deactivation():
    f = _by_id([_obj("T1", "R3TR", "TABU", "TOBJ_OFF")])
    assert "CODE-TMS-006" in f
    assert f["CODE-TMS-006"]["severity"] == "CRITICAL"


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-007 — authorization / user table content
# ═════════════════════════════════════════════════════════════════════════════

def test_auth_buffer_and_role_table_content_is_high():
    f = _by_id([_obj("T1", "R3TR", "TABU", "USRBF2"),
                _obj("T2", "R3TR", "TABU", "AGR_1251/ZROLE")])
    assert "CODE-TMS-007" in f and f["CODE-TMS-007"]["severity"] == "HIGH"
    # the table key after the slash does not defeat the table-name match
    items = " ".join(f["CODE-TMS-007"]["affected_items"])
    assert "USRBF2" in items and "AGR_1251" in items


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-008 — transport of copies imported to production
# ═════════════════════════════════════════════════════════════════════════════

def test_transport_of_copies_to_prod_fires_only_with_a_prod_import():
    objects = [_obj("TOC1", "R3TR", "PROG", "ZHOTFIX", trfunction="T")]
    to_prod = [{"TRKORR": "TOC1", "TARGET": "PRD"}]
    f = _by_id(objects, to_prod)
    assert "CODE-TMS-008" in f and f["CODE-TMS-008"]["severity"] == "HIGH"


def test_transport_of_copies_to_non_prod_does_not_fire():
    objects = [_obj("TOC1", "R3TR", "PROG", "ZHOTFIX", trfunction="T")]
    to_qas = [{"TRKORR": "TOC1", "TARGET": "QAS"}]
    assert "CODE-TMS-008" not in _by_id(objects, to_qas)


def test_transport_of_copies_to_a_p_convention_prod_sid_fires():
    # SAP production SIDs commonly follow the P<nn> convention (P01, PP1, PRP) and
    # contain no "PRD"/"PROD" substring — these must still be recognised as prod.
    objects = [_obj("TOC1", "R3TR", "PROG", "ZHOTFIX", trfunction="T")]
    for sid in ("P01", "PP1", "PRP"):
        assert "CODE-TMS-008" in _by_id(objects, [{"TRKORR": "TOC1", "TARGET": sid}]), sid
    # a dev/QA/sandbox target still does not fire
    assert "CODE-TMS-008" not in _by_id(objects, [{"TRKORR": "TOC1", "TARGET": "D01"}])


def test_a_normal_request_type_is_not_a_transport_of_copies():
    objects = [_obj("WB1", "R3TR", "PROG", "ZREPORT", trfunction="K")]
    to_prod = [{"TRKORR": "WB1", "TARGET": "PRD"}]
    assert "CODE-TMS-008" not in _by_id(objects, to_prod)


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-009 — security object types
# ═════════════════════════════════════════════════════════════════════════════

def test_auth_objects_and_roles_as_repository_objects_fire_009():
    f = _by_id([_obj("T1", "R3TR", "SUSO", "Z_AUTHOBJ"),
                _obj("T2", "R3TR", "ACGR", "Z_ROLE_ADMIN")])
    assert "CODE-TMS-009" in f and f["CODE-TMS-009"]["severity"] == "MEDIUM"


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-010 — table content (and the auth tables are NOT double-counted)
# ═════════════════════════════════════════════════════════════════════════════

def test_ordinary_table_content_is_a_medium_review_item():
    f = _by_id([_obj("T1", "R3TR", "TABU", "TVARVC")])
    assert "CODE-TMS-010" in f and f["CODE-TMS-010"]["severity"] == "MEDIUM"


def test_auth_tables_are_raised_as_007_not_as_010():
    f = _by_id([_obj("T1", "R3TR", "TABU", "USRBF2")])
    assert "CODE-TMS-007" in f
    assert "CODE-TMS-010" not in f     # not double-counted at the lower severity


# ═════════════════════════════════════════════════════════════════════════════
#  CODE-TMS-011 — not-assessed disclosure, scoped to "history but no objects"
# ═════════════════════════════════════════════════════════════════════════════

def test_disclosure_fires_when_history_supplied_but_no_object_directory():
    f = _by_id(objects=None, history=[{"TRKORR": "X", "TARGET": "PRD"}])
    assert "CODE-TMS-011" in f and f["CODE-TMS-011"]["severity"] == "INFO"


def test_no_disclosure_when_no_transport_data_at_all():
    assert _run(objects=None, history=None) == []


def test_no_disclosure_when_the_object_directory_is_present():
    f = _by_id([_obj("T1", "R3TR", "PROG", "ZREPORT")],
               history=[{"TRKORR": "T1", "TARGET": "QAS"}])
    assert "CODE-TMS-011" not in f


# ═════════════════════════════════════════════════════════════════════════════
#  Never fabricates; benign content stays quiet
# ═════════════════════════════════════════════════════════════════════════════

def test_a_benign_program_transport_raises_nothing():
    assert _run([_obj("T1", "R3TR", "PROG", "ZREPORT"),
                 _obj("T1", "LIMU", "REPS", "ZREPORT")]) == []


def test_an_empty_object_name_contributes_no_graph_object():
    f = _by_id([_obj("T1", "R3TR", "TABU", "")])
    # no TABU table name -> not matched by any check, nothing fabricated
    assert f == {}
