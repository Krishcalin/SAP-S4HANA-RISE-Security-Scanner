# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The CVA engine's open questions, as they get settled against SAP's own docs.

`docs/CVA_ENGINE_IMPROVEMENT_PLAN.md` section 7 lists twelve things the engine
BETS on — constructs it matches, additions it ignores, identifiers it was going
to add — each with the SAP source that would settle it. They are open because
this repo does not let a rule ship on a guess, and closing one means finding the
documentation, not deciding it is probably fine.

Two are closed here, and both were defects rather than research questions.

U5 — `ABAP-CDS-002` matched `GRANT SELECT ON <entity> WHERE TRUE`. DCL has no
such form. SAP's keyword documentation gives the full access rule as
`GRANT SELECT ON cds_entity [ REDEFINITION ] ;` and states it in words: "A full
access rule GRANT SELECT ON without the addition WHERE provides access to a CDS
entity cds_entity without conditions." The rule could never fire. A HIGH rule
that cannot fire is worse than an absent one, because its silence reads as
evidence.

U6 — the AUTHORITY-CHECK guard credited a check carrying `FOR USER`. SAP: "If the
addition FOR USER is specified, the authorization of the user is checked whose
user name is specified in user." That answers a question about somebody else, so
crediting it suppressed findings about the caller — a false negative in the most
security-critical rule family in the engine.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSourceScanner       # noqa: E402


def _ids(source: str, name: str):
    scanner = AbapSourceScanner(data_flow=True)
    return sorted({f["rule_id"] for f in scanner.scan_text(source, Path(name))})


# ═════════════════════════════════════════════════════════════════════════════
#  U5 — the DCL full access rule
# ═════════════════════════════════════════════════════════════════════════════

_FULL = "define role z_role {\n  grant select on z_entity;\n}\n"
_CONDITIONAL = ("define role z_role {\n  grant select on z_entity\n"
                "    where (ctry) = aspect pfcg_auth(zobj, zctry, ACTVT = '03');\n}\n")


def test_the_documented_full_access_rule_is_detected():
    """`grant select on <entity>;` with no WHERE. SAP's own example of the form
    is `grant select on demo_cds_auth_fullaccess;`."""
    assert "ABAP-CDS-002" in _ids(_FULL, "z.asdcls")


def test_the_redefinition_addition_does_not_hide_it():
    """`[ REDEFINITION ]` is in SAP's syntax and adds no condition, so a grant
    carrying it is still unrestricted."""
    assert "ABAP-CDS-002" in _ids(
        "define role z { grant select on z_ent REDEFINITION; }", "z.asdcls")


def test_a_conditional_rule_is_not_reported():
    """The whole point of the correction. A `where ... aspect pfcg_auth(...)`
    rule is authorization working as designed, and reporting it would make the
    check worthless in exactly the estates that model access properly."""
    assert "ABAP-CDS-002" not in _ids(_CONDITIONAL, "z.asdcls")


def test_the_two_forms_are_told_apart_in_one_file():
    """Real DCL mixes them. The finding must land on the unrestricted grant and
    not on its conditional neighbour."""
    source = ("define role z {\n"
              "  grant select on a where (x) = aspect pfcg_auth(o, f);\n"
              "  grant select on b;\n}\n")
    scanner = AbapSourceScanner(data_flow=True)
    hits = [f for f in scanner.scan_text(source, Path("z.asdcls"))
            if f["rule_id"] == "ABAP-CDS-002"]
    assert len(hits) == 1
    assert hits[0]["line"] == 3


def test_the_rule_no_longer_looks_for_a_construct_dcl_does_not_have():
    """Pinning the defect itself. `WHERE TRUE` was never DCL syntax; if it comes
    back, the rule has silently stopped firing again."""
    from modules.abap_sast import PATTERN_FIXES, _RULES_BY_ID
    effective = PATTERN_FIXES.get("ABAP-CDS-002",
                                  _RULES_BY_ID["ABAP-CDS-002"]["pattern"])
    assert "TRUE" not in effective.upper()


def test_the_description_tells_the_reader_what_sap_says_about_full_access():
    """SAP: it "does not as a rule supply any CDS roles with full access rules.
    Partners and customers can use full access rules to override roles supplied
    by SAP." That reframes the finding from a gap to a possible override, which
    is what the reader needs to judge it."""
    from modules.abap_sast import DESCRIPTION_FIXES
    text = DESCRIPTION_FIXES["ABAP-CDS-002"]
    assert "no WHERE addition" in text
    assert "override" in text


# ═════════════════════════════════════════════════════════════════════════════
#  U6 — AUTHORITY-CHECK FOR USER
# ═════════════════════════════════════════════════════════════════════════════

_FORM = ("FORM f.\n  %s\n  IF sy-subrc = 0.\n"
         "    DELETE FROM zcust WHERE id = lv_id.\n  ENDIF.\nENDFORM.\n")
_SELF = "AUTHORITY-CHECK OBJECT 'ZOBJ' ID 'ACTVT' FIELD '06'."
_OTHER = "AUTHORITY-CHECK OBJECT 'ZOBJ' FOR USER lv_other ID 'ACTVT' FIELD '06'."


def test_a_check_on_the_current_user_still_guards():
    """The control. This must keep working, or the fix has traded a false
    negative for a page of false positives."""
    assert "ABAP-AUTH-005" not in _ids(_FORM % _SELF, "z.abap")


def test_a_check_for_another_user_does_not_guard():
    """SAP: "If the addition FOR USER is specified, the authorization of the
    user is checked whose user name is specified in user." The rules in
    AUTHORITY_GUARDED report an operation performed without checking whether
    THIS user may perform it, and a check aimed elsewhere answers nothing
    about the caller."""
    assert "ABAP-AUTH-005" in _ids(_FORM % _OTHER, "z.abap")


def test_the_addition_is_recognised_however_it_is_spaced():
    """ABAP is whitespace-tolerant and this is a security guard, so the check
    cannot depend on the author's formatting."""
    for spelling in ("FOR  USER lv_o", "for user lv_o", "FOR\tUSER lv_o"):
        statement = ("AUTHORITY-CHECK OBJECT 'ZOBJ' %s ID 'ACTVT' FIELD '06'."
                     % spelling)
        assert "ABAP-AUTH-005" in _ids(_FORM % statement, "z.abap"), spelling


def test_for_user_inside_a_literal_does_not_disarm_a_real_guard():
    """The mirror of the T1.3 defect. A comment or message mentioning the
    addition must not turn a genuine current-user check into a non-guard —
    that would be this fix creating the opposite false positive."""
    source = _FORM % (
        "AUTHORITY-CHECK OBJECT 'ZOBJ' ID 'ACTVT' FIELD '06'.\n"
        "  MESSAGE 'checked FOR USER context' TYPE 'I'.")
    assert "ABAP-AUTH-005" not in _ids(source, "z.abap")


@pytest.mark.parametrize("code,meaning", [
    (0, "authorization successful or no check was carried out"),
    (4, "authorization check not successful"),
    (12, "no authorization found for the object"),
    (40, "an invalid user ID was specified in user"),
])
def test_the_documented_subrc_codes_are_recorded_where_somebody_will_find_them(
        code, meaning):
    """U6's second half. The plan recorded only 0, 4 and 12 as documented; the
    keyword documentation also gives 40 for an invalid user id — which only
    arises WITH the FOR USER addition, so the two halves of this question were
    always the same question. 24 is documented as no longer set.

    Code 0 is the one worth reading twice: it means success OR that no check was
    carried out, so `sy-subrc = 0` is not by itself proof that a check happened.
    """
    from modules.abap_sast import (AUTHORITY_CHECK_SUBRC,
                                   AUTHORITY_CHECK_SUBRC_OBSOLETE)
    assert code in AUTHORITY_CHECK_SUBRC
    assert meaning.split()[0].lower() in AUTHORITY_CHECK_SUBRC[code].lower()
    assert 24 in AUTHORITY_CHECK_SUBRC_OBSOLETE
    assert 24 not in AUTHORITY_CHECK_SUBRC


def test_the_subrc_table_does_not_invent_codes_sap_does_not_document():
    """The table is a record of SAP's documentation, not a guess at a system's
    behaviour. An extra key would be a fabricated fact of exactly the kind the
    open-questions list exists to prevent."""
    from modules.abap_sast import AUTHORITY_CHECK_SUBRC
    assert set(AUTHORITY_CHECK_SUBRC) == {0, 4, 12, 40}


def test_zero_is_recorded_as_ambiguous_because_it_is():
    """"Authorization successful OR no check was carried out." Anything reading
    `sy-subrc = 0` as proof that a check happened is reading it wrong, and the
    table has to say so where the next person will see it."""
    from modules.abap_sast import AUTHORITY_CHECK_SUBRC
    assert "no check was carried out" in AUTHORITY_CHECK_SUBRC[0]


# ═════════════════════════════════════════════════════════════════════════════
#  U3 — the released spelling, and what a set of examples cannot prove
# ═════════════════════════════════════════════════════════════════════════════

def test_the_released_allowlist_spelling_is_the_one_that_ships():
    """SAP's released-classes listing shows `CL_ABAP_DYN_PRG` with
    `check_allowlist` and `check_table_name_tab`."""
    from modules.abap_sast_extra import _ALLOWLIST
    assert "check_allowlist" in _ALLOWLIST


def test_the_unconfirmed_alias_is_kept_and_the_reasoning_is_written_down():
    """`check_whitelist` appears nowhere in that listing. That confirms the
    released spelling and does NOT settle the original question — whether the old
    name is a legacy alias — because the listing gives worked examples rather
    than class signatures, and absence from examples is not absence from a class.

    So it stays, and the asymmetry is the argument: keeping a name that does not
    exist costs a false negative only in a contrived case, while removing one
    that does exist reports correct code as unsanitised.
    """
    from modules.abap_sast_extra import _ALLOWLIST
    source = (ROOT / "modules" / "abap_sast_extra.py").read_text(encoding="utf-8")
    assert "check_whitelist" in _ALLOWLIST
    assert "PARTIALLY SETTLED" in source
    assert "absence from a set of examples" in source


# ═════════════════════════════════════════════════════════════════════════════
#  U4 — a rule aimed at the wrong idea, not merely an imprecise one
# ═════════════════════════════════════════════════════════════════════════════

def test_the_http_utility_rule_stays_retired_with_the_reason_upgraded():
    """SAP describes `CL_WEB_HTTP_UTILITY` as "Encoding strings/xstrings in
    Base64 and decoding Base64-encoded strings/xstrings" and it exposes no
    HTML-escaping method, so "used this class without escaping" says nothing
    either way. The rule was aimed at the wrong idea, which no amount of
    narrowing would have fixed."""
    from modules.abap_sast import RETIRED_RULES
    source = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "ABAP-XSS-006" in RETIRED_RULES
    assert "U4 IS NOW SETTLED" in source


def test_the_limit_of_that_evidence_is_stated_too():
    """The listing covers RELEASED ABAP Cloud APIs. `CL_HTTP_UTILITY`'s absence
    from it proves the class is unreleased, NOT that the classic class lacks
    `escape_html` — and anyone deciding whether to revive the rule needs that
    distinction rather than an overstated conclusion."""
    source = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "NOT establish" in source and "unreleased" in source


# ═════════════════════════════════════════════════════════════════════════════
#  U10 — identifiers may ship, but only with a citation
# ═════════════════════════════════════════════════════════════════════════════

def test_every_confirmed_identifier_names_the_file_it_was_read_from():
    """The bar U10 set: not "this looks like a real class" but "here is where
    SAP writes it"."""
    from modules.abap_sast import RiseTaintAnalyzer
    for name, source in RiseTaintAnalyzer.CONFIRMED_SOURCE_IDENTIFIERS.items():
        assert "abap-cheat-sheets" in source, (name, source)
        assert source.endswith(".md"), (name, source)


def test_json_deserialisation_taints_what_it_produces():
    src = ("FORM f.\n"
           "  /ui2/cl_json=>deserialize( EXPORTING json = lv_body"
           " CHANGING data = ls_out ).\n"
           "  SELECT * FROM (ls_out-tab) INTO TABLE @DATA(t).\n"
           "ENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    hits = [f for f in scanner.scan_text(src, Path("z.abap"))
            if f["rule_id"].startswith("ABAP-SQLI")]
    assert hits, "the dynamic FROM was not reported at all"
    assert any(h["confidence"] == "confirmed" for h in hits)


def test_a_reader_built_over_input_carries_the_inputs_provenance():
    """`cl_sxml_string_reader=>create( xml )` produces a reader over input, so
    everything pulled through it is attacker-influenced."""
    src = ("FORM f.\n"
           "  DATA(reader) = cl_sxml_string_reader=>create( lv_xml ).\n"
           "  SELECT * FROM (reader) INTO TABLE @DATA(t).\n"
           "ENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    assert any(f["confidence"] == "confirmed"
               for f in scanner.scan_text(src, Path("z.abap"))
               if f["rule_id"].startswith("ABAP-SQLI"))


def test_screen_field_values_are_a_source():
    """`DYNP_VALUES_READ` reads the user's own screen entries back into the
    program. It reaches the finding through the output-parameter binding rather
    than an assignment, so it lifts the evidence class without reaching
    `confirmed` — which is the honest grade for it."""
    src = ("FORM f.\n"
           "  CALL FUNCTION 'DYNP_VALUES_READ' TABLES dynpfields = lt_f.\n"
           "  SELECT * FROM (lt_f) INTO TABLE @DATA(t).\n"
           "ENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    hits = [f for f in scanner.scan_text(src, Path("z.abap"))
            if f["rule_id"].startswith("ABAP-SQLI")]
    assert hits
    assert all(h["confidence"] != "pattern-only" for h in hits)


def test_an_identifier_with_no_provenance_would_fail_the_guard():
    """The guard's teeth, exercised rather than asserted. A name added to the
    pattern without an entry in the table must break the tier-3 check — that is
    what stops the next unverified identifier."""
    from modules.abap_sast import RiseTaintAnalyzer
    confirmed = dict(RiseTaintAnalyzer.CONFIRMED_SOURCE_IDENTIFIERS)
    invented = "cl_made_up_class=>get_input"
    assert invented not in confirmed
    alternatives = [a.replace("\\", "").strip()
                    for a in (RiseTaintAnalyzer._SOURCE_RE.pattern + "|"
                              + invented).split("|")]
    unrecorded = [a for a in alternatives if "=>" in a and a not in confirmed]
    assert unrecorded == [invented]
