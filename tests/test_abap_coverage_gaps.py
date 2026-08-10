# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The six coverage gaps, and the discipline that keeps them honest.

EVERY FAMILY HERE SHIPS WITH A NEGATIVE FIXTURE, AND THAT IS THE POINT
A rule that fires is easy. A rule that fires only where it should is the whole
difficulty of SAST, and the negative fixtures earned their keep immediately —
they caught two real defects the positive tests could never have seen:

  * `@AccessControl.authorizationCheck` was being chopped in half, because the
    ABAP splitter ends a statement at a period and CDS does not. No CDS annotation
    rule could ever have matched. Coverage was zero while appearing to work.
  * ABAP's dynamic-WHERE rule fired on a DCL grant's
    `where ( lifnr ) = aspect pfcg_auth (...)` — reporting SQL injection in a
    correctly written access-control role, because CDS was being scanned with ABAP
    rules.

Both were one root cause: CDS is not ABAP and must not be parsed or matched as
ABAP.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSourceScanner, split_cds_statements  # noqa: E402
from modules.abap_sast_extra import EXTRA_ABAP_RULES                   # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "abap"


def scan(name):
    path = FIXTURES / name
    return AbapSourceScanner(data_flow=False).scan_text(
        path.read_text(encoding="utf-8"), path)


def ids(name):
    return sorted({h["rule_id"] for h in scan(name)})


# --------------------------------------------------------------------------- #
#  The negative half — checked FIRST, because it is the half that matters      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fixture", sorted(
    p.name for p in FIXTURES.iterdir() if "secure" in p.name))
def test_secure_code_produces_nothing(fixture):
    """The exit criterion for this phase. A rule that also fires on correct code
    is worse than no rule: it costs the reviewer time and it costs the product
    their trust."""
    found = scan(fixture)
    assert not found, (
        f"{fixture} is correctly written and produced "
        f"{[(f['rule_id'], f['statement'][:60]) for f in found]}")


# --------------------------------------------------------------------------- #
#  The positive half                                                          #
# --------------------------------------------------------------------------- #

def test_amdp_injection_is_detected():
    """Built first on purpose: SAP's own keyword documentation states no test tool
    exists for AMDP, so this is where the module can be ahead rather than behind."""
    found = ids("amdp_vulnerable.clas.abap")
    assert "ABAP-AMDP-001" in found, "EXECUTE IMMEDIATE inside an AMDP method"
    assert "ABAP-AMDP-002" in found, "APPLY_FILTER from a variable"
    assert "ABAP-AMDP-003" in found, "database procedure with no ABAP-side check"


def test_native_sql_is_detected():
    found = ids("native_sql_vulnerable.prog.abap")
    assert "ABAP-NSQL-001" in found, "EXEC SQL block"
    assert "ABAP-NSQL-002" in found, "ADBC statement from a variable"


def test_a_cds_view_without_access_control_is_detected():
    assert "ABAP-CDS-001" in ids("cds_vulnerable.asddls")


def test_a_dcl_role_that_grants_unconditionally_is_detected():
    """Worse than no role at all: a review sees that access control is defined."""
    assert "ABAP-CDS-002" in ids("dcl_vulnerable.asdcls")


def test_xxe_ssrf_and_test_seam_are_detected():
    found = ids("misc_vulnerable.prog.abap")
    assert "ABAP-XXE-001" in found, "XML parsed from input"
    assert "ABAP-SSRF-001" in found, "HTTP client from a non-literal URL"
    assert "ABAP-BKDR-008" in found, "TEST-SEAM in transportable code"


# --------------------------------------------------------------------------- #
#  CDS is a different language                                                #
# --------------------------------------------------------------------------- #

def test_a_cds_annotation_survives_its_own_dots():
    """`@AccessControl.authorizationCheck` contains a period. Under the ABAP
    splitter it became `@AccessControl` and `authorizationCheck: #NOT_REQUIRED`,
    and no annotation rule could match across the break."""
    stmts = split_cds_statements(
        "@AccessControl.authorizationCheck: #NOT_REQUIRED\n"
        "define view entity ZI_X as select from lfa1 { key lifnr }\n")
    assert any("@AccessControl.authorizationCheck: #NOT_REQUIRED" in s.text
               for s in stmts), [s.text for s in stmts]


def test_cds_files_are_not_matched_with_abap_rules():
    """A DCL grant's `where ( lifnr ) = aspect pfcg_auth (...)` looks exactly like
    ABAP's dynamic-WHERE injection pattern, and is the correct way to write one."""
    rules = AbapSourceScanner._rules_for(Path("z_role.asdcls"))
    rule_ids = {r["id"] for r in rules}
    # The guarantee is that no ABAP rule reaches a CDS artefact — NOT that every
    # rule is spelled ABAP-CDS-*. RAP behaviour definitions route here too and
    # carry their own family, which is why the prefix alone is the wrong test.
    assert rule_ids and all(r.startswith(("ABAP-CDS-", "ABAP-RAP-"))
                            for r in rule_ids), \
        f"CDS artefacts are being scanned with {sorted(rule_ids)[:5]}"
    assert "ABAP-SQLI-001" not in rule_ids, \
        "the dynamic-WHERE rule is back on DCL, where a pfcg_auth grant looks " \
        "exactly like an injection"


def test_scan_text_picks_the_rules_for_the_file_it_was_given():
    """It used to default to the ABAP corpus whatever the path said, so only
    scan_tree routed correctly and the default was a trap for every other caller."""
    path = FIXTURES / "dcl_secure.asdcls"
    direct = AbapSourceScanner(data_flow=False).scan_text(
        path.read_text(encoding="utf-8"), path)
    assert not direct


def test_cds_comments_are_not_code():
    stmts = split_cds_statements("// @AccessControl.authorizationCheck: #NOT_REQUIRED\n")
    assert not [s for s in stmts if "NOT_REQUIRED" in s.text]


# --------------------------------------------------------------------------- #
#  House rules                                                                #
# --------------------------------------------------------------------------- #

def test_the_new_rules_do_not_collide_with_the_vendored_corpus():
    from modules.abap_sast_rules import ALL_ABAP_SAST_RULES as vendored
    from modules.abap_sast_rules import ALL_BTP_CONFIG_RULES, ALL_JS_RULES
    existing = {r["id"] for r in vendored + ALL_BTP_CONFIG_RULES + ALL_JS_RULES}
    new = {r["id"] for r in EXTRA_ABAP_RULES}
    assert not (existing & new), f"id reused: {sorted(existing & new)}"


def test_the_new_rules_live_outside_the_vendored_file():
    """`tools/build_abap_rules.py` regenerates the vendored corpus verbatim from
    the upstream repository. A rule added there is destroyed on the next refresh,
    silently, with no test failing."""
    vendored = (ROOT / "modules" / "abap_sast_rules.py").read_text(encoding="utf-8")
    for rule in EXTRA_ABAP_RULES:
        assert rule["id"] not in vendored, \
            f"{rule['id']} is in the regenerated file and will be lost"


def test_every_new_rule_is_complete_and_routes_to_a_team():
    from server.enrich import team_for
    for rule in EXTRA_ABAP_RULES:
        for field in ("id", "name", "pattern", "severity", "category",
                      "cwe", "description", "recommendation"):
            assert rule.get(field), f"{rule.get('id')} is missing {field}"
        assert rule["cwe"].startswith("CWE-")
        assert team_for(rule["id"]) != "unassigned", \
            f"{rule['id']} routes to no team"


def test_every_new_rule_compiles():
    import re
    for rule in EXTRA_ABAP_RULES:
        re.compile(rule["pattern"], re.IGNORECASE)


def test_rap_readiness_was_declined_rather_than_half_built():
    """RAP READINESS is measured against SAP's continuously-updated released-object
    catalogue, which IS the check — shipping a snapshot would be a content-currency
    treadmill. Declining it explicitly is the honest option, and this test exists so
    a future reader finds the decision instead of the gap.

    WHAT THIS TEST NO LONGER ASSERTS. It used to require that no rule id contained
    "RAP" at all, which was a proxy, and the wrong one: ABAP-RAP-001..004 read a
    behaviour definition's OWN source for authorization off-switches. They carry no
    catalogue and go stale at no rate, so they are not the declined check. Before
    they existed, a BDEF that disabled authorization produced zero findings.
    """
    extra = (ROOT / "modules" / "abap_sast_extra.py").read_text(encoding="utf-8")
    assert "WHAT IS DELIBERATELY NOT HERE" in extra
    assert "RAP" in extra
    # The thing that must not appear is a SNAPSHOT of released objects.
    snapshotted = [r for r in EXTRA_ABAP_RULES
                   if "released" in (r.get("description", "") + r["pattern"]).lower()]
    assert not snapshotted, \
        f"{[r['id'] for r in snapshotted]} looks like a released-object snapshot"
