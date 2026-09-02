"""The last four checks nothing had ever been seen to fire.

`docs/CHECK_FIRING.md` counted 803 of 807 proven. These are the four, and they
resisted the earlier sweep for the same reason: none can be reached from a
single file.

  ABAP-CDS-003   an exposed CDS view that no DCL role in the TREE grants on
  ABAP-RAP-005   a behaviour definition stating no authorization at all
  ABAP-RAP-006   a behaviour authorising the operation but never the instance
  ATC-RFC        a runtime family id, one per ATC finding category

The first three are cross-artefact: the defect is the file that was never
written, so proving them needs a source tree with the right absence in it.
ABAP-CDS-003 additionally needs at least one DCL artefact present, because a
tree carrying none is reported as ABAP-COV-005 ("read this as the check not
having been performed") rather than reporting every view as unprotected on
evidence it does not have.

Proving them found a fifth thing, which is why this file exists at all: that
DCL guard used to suppress the RAP pair as well, and those two need no DCL to be
readable. See test_the_dcl_guard_does_not_suppress_the_rap_checks.

One trap worth recording, since it cost a probe run: the DCL suffix is
`.asdcls`. A file named `.dcls.asddls` is not recognised, the tree looks like it
has no access control at all, and ABAP-CDS-003 stays silent behind the coverage
finding.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSastAuditor                           # noqa: E402
from modules.atc_import import AtcImportAuditor                         # noqa: E402

GRANTED_VIEW = ("@OData.publish: true\n"
                "define view Z_I_Granted as select from t000 { client }\n")
ORPHAN_VIEW = ("@OData.publish: true\n"
               "define view Z_I_Orphan as select from bkpf { belnr }\n")
#: Grants on Z_I_Granted and nothing else, so the tree HAS access control and
#: Z_I_Orphan is genuinely roleless rather than merely unexported.
ROLE = ("@EndUserText.label: 'role'\n"
        "define role Z_I_GRANTED_ROLE {\n"
        "  grant select on Z_I_Granted where ( bukrs ) = aspect pfcg_auth "
        "( F_BKPF_BUK, BUKRS, ACTVT = '03' );\n}\n")
NO_AUTH_BEHAVIOR = ("managed implementation in class zbp_i_noauth unique;\n"
                    "define behavior for Z_I_NoAuth alias NoAuth\n"
                    "persistent table znoauth\nlock master\n"
                    "{\n  create;\n  update;\n}\n")
GLOBAL_ONLY_BEHAVIOR = ("managed implementation in class zbp_i_globalonly unique;\n"
                        "define behavior for Z_I_GlobalOnly alias GlobalOnly\n"
                        "persistent table zglobal\nlock master\n"
                        "authorization master ( global )\n"
                        "{\n  create;\n  update;\n}\n")


def scan(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    found = AbapSastAuditor({"abap_source_dir": str(tmp_path)}, {}).run_all_checks()
    return {f["check_id"] for f in (found or [])}


# ── ABAP-CDS-003 — the file that was never written ─────────────────────────

def test_an_exposed_view_no_role_grants_on_is_reported(tmp_path):
    got = scan(tmp_path, {"z_granted.ddls.asddls": GRANTED_VIEW,
                          "z_orphan.ddls.asddls": ORPHAN_VIEW,
                          "z_roles.asdcls": ROLE})
    assert "ABAP-CDS-003" in got
    assert "ABAP-COV-005" not in got, (
        "the tree carries a DCL artefact, so the check ran rather than standing "
        "down")


def test_a_view_a_role_does_grant_on_is_not_reported(tmp_path):
    got = scan(tmp_path, {"z_granted.ddls.asddls": GRANTED_VIEW,
                          "z_roles.asdcls": ROLE})
    assert "ABAP-CDS-003" not in got


def test_a_tree_with_no_access_control_stands_down_instead(tmp_path):
    """THE MOST DAMAGING FALSE POSITIVE THIS SCANNER COULD PRODUCE would be
    reporting every view as unprotected on a checkout that simply did not
    include the DCL. That case is a coverage finding, not a defect."""
    got = scan(tmp_path, {"z_orphan.ddls.asddls": ORPHAN_VIEW})
    assert "ABAP-CDS-003" not in got
    assert "ABAP-COV-005" in got


def test_the_dcl_suffix_is_asdcls(tmp_path):
    """A file named `.dcls.asddls` is not recognised — the tree then looks like
    it has no access control at all and the check disappears behind the
    coverage finding. This cost a probe run; it is written down so it costs
    nobody else one."""
    got = scan(tmp_path, {"z_granted.ddls.asddls": GRANTED_VIEW,
                          "z_orphan.ddls.asddls": ORPHAN_VIEW,
                          "z_roles.dcls.asddls": ROLE})
    assert "ABAP-COV-005" in got and "ABAP-CDS-003" not in got


# ── ABAP-RAP-005 / -006 — what the behaviour definition does not say ───────

def test_a_behaviour_with_no_authorization_is_reported(tmp_path):
    got = scan(tmp_path, {"z_noauth.asbdef": NO_AUTH_BEHAVIOR})
    assert "ABAP-RAP-005" in got


def test_a_behaviour_authorising_only_globally_is_reported(tmp_path):
    """Global authorization answers "may this user perform this operation at
    all" and never "may they perform it on THIS record". Correct for an entity
    whose rules do not depend on the record; the whole vulnerability for one
    whose rules do."""
    got = scan(tmp_path, {"z_globalonly.asbdef": GLOBAL_ONLY_BEHAVIOR})
    assert "ABAP-RAP-006" in got
    assert "ABAP-RAP-005" not in got, (
        "it does state an authorization; the defect is which KIND")


def test_a_behaviour_with_instance_authorization_is_not_reported(tmp_path):
    both = GLOBAL_ONLY_BEHAVIOR.replace("authorization master ( global )",
                                        "authorization master ( global, instance )")
    got = scan(tmp_path, {"z_both.asbdef": both})
    assert "ABAP-RAP-005" not in got
    assert "ABAP-RAP-006" not in got


def test_all_three_cross_artefact_checks_reachable_from_one_tree(tmp_path):
    """The realistic shape: a package with some protection, one view that was
    forgotten, and two behaviours written at different times."""
    got = scan(tmp_path, {"z_granted.ddls.asddls": GRANTED_VIEW,
                          "z_orphan.ddls.asddls": ORPHAN_VIEW,
                          "z_roles.asdcls": ROLE,
                          "z_noauth.asbdef": NO_AUTH_BEHAVIOR,
                          "z_globalonly.asbdef": GLOBAL_ONLY_BEHAVIOR})
    assert {"ABAP-CDS-003", "ABAP-RAP-005", "ABAP-RAP-006"} <= got


# ── ATC-RFC — a runtime family id ──────────────────────────────────────────

def atc(rows):
    found = AtcImportAuditor({"custom_code_scan": rows}).run_all_checks()
    return {f["check_id"] for f in (found or [])}


def test_an_unsafe_rfc_atc_finding_produces_its_family_id():
    assert "ATC-RFC" in atc([
        {"OBJECT_NAME": "Z_RFC_CALLER", "OBJECT_TYPE": "PROG",
         "CHECK_ID": "CL_CI_TEST_RFC", "LINE": "42",
         "DESCRIPTION": "Unsafe RFC destination used in CALL FUNCTION DESTINATION"}])


@pytest.mark.parametrize("description", [
    "RFC_INJECTION detected in dynamic destination",
    "RFC CALLBACK not restricted",
])
def test_each_rfc_token_classifies_to_the_same_family(description):
    assert "ATC-RFC" in atc([{"OBJECT_NAME": "Z_X", "OBJECT_TYPE": "PROG",
                              "CHECK_ID": "CL_CI_TEST_RFC",
                              "DESCRIPTION": description}])


def test_a_non_security_atc_finding_produces_no_family_id():
    """Performance and naming checks are counted and disclosed, never dropped
    silently — but they are not security families."""
    got = atc([{"OBJECT_NAME": "Z_SLOW", "OBJECT_TYPE": "PROG",
                "CHECK_ID": "CL_CI_TEST_PERF",
                "DESCRIPTION": "SELECT inside LOOP, performance"}])
    assert "ATC-RFC" not in got

def test_the_dcl_guard_does_not_suppress_the_rap_checks(tmp_path):
    """A GUARD PROTECTING ONE CHECK WAS SILENTLY SUPPRESSING TWO OTHERS.

    cross_artifact_findings used to return an empty list for the whole
    function when no DCL artefact was found. That is right about ABAP-CDS-003
    and wrong about the RAP pair: a behaviour definition states its own
    authorization inside itself and needs no DCL file to be readable.

    The cost was a package of behaviour definitions with no CDS access controls
    — an ordinary shape — reporting no RAP findings at all, and a coverage
    notice about VIEW protection instead, which is not what was missing.
    Adding one unrelated .asdcls file made ABAP-RAP-005 appear; that is how it
    was found.
    """
    got = scan(tmp_path, {'z_noauth.asbdef': NO_AUTH_BEHAVIOR})
    assert 'ABAP-RAP-005' in got, (
        'the RAP check is gated behind DCL presence again')
    assert 'ABAP-COV-005' in got, (
        'the coverage notice about views is still correct and still stands')
