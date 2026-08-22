"""Three defects an adversarial sweep found, each pinned through the REAL path.

WHY "THROUGH THE REAL PATH" IS THE POINT OF THIS FILE. The first of the three had
already been fixed once, with tests, and the tests passed — because they built a
`csv.DictReader` themselves and handed rows straight to the auditor. The loader
sits between those two things in production and was throwing the data away. A test
that skips the layer where the bug lives cannot see the bug.

So every test here drives the loader, or the auditor's real entry point, or the
route, rather than a convenient inner function. Each was confirmed to FAIL when its
fix is reverted; a regression test nobody has watched fail is a comment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.code_transport import CodeTransportAuditor        # noqa: E402
from modules.data_loader import DataLoader                     # noqa: E402
from modules.webdisp_security import WebDispatcherAuditor      # noqa: E402


def _load(tmp_path: Path, name: str, text: str) -> dict:
    import contextlib
    import io
    (tmp_path / name).write_text(text, encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return DataLoader(tmp_path).load_all()


# ═════════════════════════════════════════════════════════════════════════════
#  1. The loader discarded csv.DictReader's overflow key
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unquoted_delimiter_inside_a_value_survives_the_loader(tmp_path):
    """SAP profile values routinely contain commas. `if k` in the loader's key
    normalisation dropped the None key — where DictReader puts the overflow — so
    everything after the first comma was gone before any module saw it."""
    data = _load(tmp_path, "webdisp_params.csv",
                 "NAME,VALUE\n"
                 "icm/HTTP/admin_0,PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443\n")
    assert data["webdisp_params"][0]["VALUE"] == \
        "PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443"


def test_a_restricted_admin_handler_is_not_reported_as_unrestricted(tmp_path):
    """THE FALSE POSITIVE THIS SHIPPED. The file says CLIENTHOST and PORT are set;
    the customer is told at HIGH that they are not, and sent to fix a correct
    configuration on the strength of how their spreadsheet saved the file."""
    data = _load(tmp_path, "webdisp_params.csv",
                 "NAME,VALUE\n"
                 "icm/HTTP/admin_0,PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443\n")
    raised = {f["check_id"] for f in WebDispatcherAuditor(data, {}, {}).run_all_checks()}
    assert "WDISP-011" not in raised, "CLIENTHOST is present in the file"
    assert "WDISP-012" not in raised, "PORT is present in the file"


def test_a_genuinely_unrestricted_handler_is_still_reported(tmp_path):
    """The rejoin must not swallow the real finding along with the false one."""
    data = _load(tmp_path, "webdisp_params.csv",
                 "NAME,VALUE\nicm/HTTP/admin_0,PREFIX=/sap/admin\n")
    raised = {f["check_id"] for f in WebDispatcherAuditor(data, {}, {}).run_all_checks()}
    assert "WDISP-011" in raised


def test_a_well_formed_quoted_file_is_unchanged(tmp_path):
    """The rejoin only fires on overflow. A correct CSV must round-trip exactly."""
    data = _load(tmp_path, "webdisp_params.csv",
                 'NAME,VALUE\nicm/HTTP/admin_0,"PREFIX=/x,CLIENTHOST=1.2.3.4"\n')
    assert data["webdisp_params"][0]["VALUE"] == "PREFIX=/x,CLIENTHOST=1.2.3.4"


def test_a_short_row_still_reads_as_an_empty_cell(tmp_path):
    """The loader's other documented behaviour, next door to the change: a MISSING
    trailing field is an empty cell, not a broken file."""
    data = _load(tmp_path, "webdisp_params.csv", "NAME,VALUE\nicm/max_conn\n")
    assert data["webdisp_params"][0]["VALUE"] == ""


# ═════════════════════════════════════════════════════════════════════════════
#  2. CODE-CLIENT-001 misread SAP's own raw T000 codes
# ═════════════════════════════════════════════════════════════════════════════

def _clients(rows):
    return [f for f in CodeTransportAuditor({"client_settings": rows}, {}, {})
            .run_all_checks() if "CLIENT" in f["check_id"]]


#: SAP policy 1ACHANGE, check item CHANGE-A_b, verbatim:
#:   (CCCATEGORY='P' and CCCORACTIV='2' and CCNOCLIIND='3'
#:    and (CCCOPYLOCK='X' or CCCOPYLOCK='L')) OR CCCATEGORY != 'P'
SAP_COMPLIANT_PROD = {"MANDT": "100", "CCCATEGORY": "P", "CCCORACTIV": "2",
                      "CCNOCLIIND": "3", "CCCOPYLOCK": "X"}


def test_saps_own_compliant_production_client_raises_nothing():
    """THE DEFECT. A scanner that flags SAP's own mandated configuration is
    confidently wrong on every correctly locked estate — the failure this
    codebase's ECS baseline module was written to prevent, recurring on a
    different export route."""
    assert _clients([SAP_COMPLIANT_PROD]) == []


@pytest.mark.parametrize("lock", ["X", "L"])
def test_both_copy_lock_values_sap_accepts_are_accepted(lock):
    """SAP's predicate permits X or L. Recognising only one would report half the
    compliant estates."""
    assert _clients([dict(SAP_COMPLIANT_PROD, CCCOPYLOCK=lock)]) == []


@pytest.mark.parametrize("field,value", [
    ("CCCORACTIV", " "), ("CCCORACTIV", "1"),
    ("CCNOCLIIND", "1"), ("CCCOPYLOCK", ""),
])
def test_a_production_client_missing_any_required_value_is_reported(field, value):
    """The other direction. `CCCORACTIV='1'` is NOT compliant by SAP's rule — a
    detail worth pinning, because assuming it meant "locked" is what made the
    first verification of this bug right by accident."""
    raised = _clients([dict(SAP_COMPLIANT_PROD, **{field: value})])
    assert [f["check_id"] for f in raised] == ["CODE-CLIENT-001"]


def test_a_non_production_client_is_compliant_under_this_check():
    """SAP's predicate ends `OR CCCATEGORY != 'P'`. Other checks judge those
    clients on other grounds; this one does not."""
    assert _clients([dict(SAP_COMPLIANT_PROD, CCCATEGORY="C", CCCORACTIV=" ")]) == []


def test_the_descriptive_scc4_route_still_works():
    """Both export routes are documented. Fixing one must not break the other."""
    assert _clients([{"CLIENT": "100", "ROLE": "PRODUCTION",
                      "CHANGES_ALLOWED": "NO_CHANGES",
                      "CROSS_CLIENT_CHANGES": "NO",
                      "REPOSITORY_CHANGES": "NO"}]) == []
    assert _clients([{"CLIENT": "100", "ROLE": "PRODUCTION",
                      "CHANGES_ALLOWED": "MODIFIABLE",
                      "CROSS_CLIENT_CHANGES": "YES",
                      "REPOSITORY_CHANGES": "YES"}])


def test_the_sap_values_are_transcribed_and_not_widened():
    """Guessing that '1' also means locked is exactly how this check came to
    report SAP's standard as CRITICAL. The accepted set is the note's."""
    assert CodeTransportAuditor._T000_PROD_COMPLIANT == {
        "CCCORACTIV": ("2",), "CCNOCLIIND": ("3",), "CCCOPYLOCK": ("X", "L")}


# ═════════════════════════════════════════════════════════════════════════════
#  3. /api/upload took a landscape and a system with no scope check
# ═════════════════════════════════════════════════════════════════════════════

def _upload_handler() -> str:
    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    return src.split("async def api_upload", 1)[1].split("\n@app.", 1)[0]


def test_the_upload_route_scopes_the_write():
    """Every READ path runs through auth.scope_for; this WRITE did not, so an
    analyst restricted to one landscape could upload a scan into another and
    attach findings to systems they cannot read. A write is the worse half: they
    never see the result, and the landscape's owner gets findings from a bundle
    nobody authorised.

    Structural, because the handler needs a database and a multipart body — but
    the assertions are specific enough that removing the check fails them."""
    handler = _upload_handler()
    assert "auth.scope_for(user)" in handler, "the upload does not consult the scope"
    assert "not in your scope" in handler
    assert "not in that landscape" in handler


def test_a_restricted_account_must_name_its_system():
    """Without a system id there is nothing to check the scope against, so the
    upload is refused rather than allowed through unscoped."""
    assert "must name the system it belongs to" in _upload_handler()


def test_an_unrestricted_account_is_not_forced_to_name_one():
    """`scope_for` returns None for an admin, and the check is skipped entirely.
    Note the guard is `is not None` rather than truthiness: `if scope:` would also
    skip for an EMPTY scope, which means nothing rather than everything."""
    assert "if scope is not None:" in _upload_handler()
