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


# ═════════════════════════════════════════════════════════════════════════════
#  U9 — all six data-cluster media
# ═════════════════════════════════════════════════════════════════════════════

_IMPORT = ("FORM f.\n  IMPORT p = lv_v FROM %s.\n"
           "  SELECT * FROM (lv_v) INTO TABLE @DATA(t).\nENDFORM.\n")


@pytest.mark.parametrize("medium", [
    "MEMORY ID lv_id",
    "DATA BUFFER lv_x",
    "INTERNAL TABLE lt_c",
    "DATABASE indx(zz) ID lv_id",
    "SHARED MEMORY indx(zz) ID lv_id",
    "SHARED BUFFER indx(zz) ID lv_id",
])
def test_every_documented_cluster_medium_is_a_source(medium):
    """SAP's IMPORT syntax gives exactly six media. Three were already covered;
    the other three had been proposed on structural symmetry alone and were
    correctly left out until a fetched file named them. It does."""
    scanner = AbapSourceScanner(data_flow=True)
    hits = [f for f in scanner.scan_text(_IMPORT % medium, Path("z.abap"))
            if f["rule_id"].startswith("ABAP-SQLI")]
    assert hits, medium
    assert any(h["confidence"] == "confirmed" for h in hits), medium


def test_the_cross_program_media_are_the_strongest_case_not_the_weakest():
    """A cluster in ABAP Memory was at least written by the same session. SAP
    calls SHARED MEMORY and SHARED BUFFER "a cross-program memory area" — data
    some other program wrote, possibly on another day — so if any medium
    belonged in the source list, these did."""
    source = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "cross-program memory area" in source


def test_the_runtime_name_table_form_is_still_left_alone():
    """`IMPORT (param_table) FROM ...` binds by a name table computed at
    runtime. U9 widened the MEDIA, not the binding forms, and widening one is
    not licence to widen the other."""
    scanner = AbapSourceScanner(data_flow=True)
    src = ("FORM f.\n  IMPORT (lt_names) FROM MEMORY ID lv_id.\n"
           "  SELECT * FROM (lv_v) INTO TABLE @DATA(t).\nENDFORM.\n")
    hits = [f for f in scanner.scan_text(src, Path("z.abap"))
            if f["rule_id"].startswith("ABAP-SQLI")]
    assert all(h["confidence"] != "confirmed" for h in hits)


# ═════════════════════════════════════════════════════════════════════════════
#  U11 — FOR is in, FILTER is out, and SAP said which
# ═════════════════════════════════════════════════════════════════════════════

def test_a_dynamic_where_on_a_for_loop_is_reported():
    """SAP lists FOR loops among the constructs supporting "Dynamic WHERE
    conditions: any character-like data object ... within a pair of
    parentheses"."""
    src = ("FORM f.\n  DATA(r) = VALUE ty( FOR wa IN it WHERE (lv_dyn) ( wa ) ).\n"
           "ENDFORM.\n")
    assert "ABAP-DYNT-001" in _ids(src, "z.abap")


@pytest.mark.parametrize("condition", [
    "( comp2 = 1 )",                      # SAP's own example, verbatim
    "( table_line CA `ACXYGZD` )",        # SAP's second example
])
def test_a_static_for_condition_in_parentheses_is_not_reported(condition):
    """THE TRAP THAT KEPT U11 OPEN. A FOR loop's static condition is written in
    parentheses as ordinary syntax, so `WHERE (` after a FOR is evidence of
    nothing. Both fixtures here are SAP's own example lines — if this check ever
    fires on them it is reporting correct, idiomatic modern ABAP."""
    src = ("FORM f.\n  DATA(r) = VALUE ty( FOR wa IN it WHERE %s ( wa ) ).\n"
           "ENDFORM.\n" % condition)
    assert "ABAP-DYNT-001" not in _ids(src, "z.abap")


def test_filter_is_refused_because_no_dynamic_form_is_documented():
    """FILTER was named alongside the covered constructs, which is why it was a
    question. SAP gives it restricted options — "Only table key columns can be
    compared with single values in the WHERE condition" — and documents no
    dynamic form, so including it would be a guess."""
    src = "FORM f.\n  DATA(r) = FILTER #( it WHERE key = lv_k ).\nENDFORM.\n"
    assert "ABAP-DYNT-001" not in _ids(src, "z.abap")


def test_for_all_entries_is_not_swept_up_by_the_new_alternation():
    """`SELECT ... FOR ALL ENTRIES IN itab WHERE (dyn)` is ABAP SQL and belongs
    to ABAP-SQLI-001. The anchor is `FOR <name> IN`, and "ALL ENTRIES" is two
    words, so the internal-table rule cannot reach it — otherwise one statement
    would carry both a CWE-89 and a CWE-913 finding."""
    src = ("FORM f.\n  SELECT * FROM t FOR ALL ENTRIES IN it WHERE (lv_dyn)"
           " INTO TABLE @DATA(x).\nENDFORM.\n")
    found = _ids(src, "z.abap")
    assert "ABAP-SQLI-001" in found
    assert "ABAP-DYNT-001" not in found


def test_the_reason_filter_was_excluded_is_recorded_not_just_the_exclusion():
    """An absent construct with no note reads as an oversight, and the next
    person re-opens the question. The refusal has to carry SAP's wording."""
    source = (ROOT / "modules" / "abap_sast_extra.py").read_text(encoding="utf-8")
    assert "FILTER DOES NOT" in source
    assert "Only table key columns" in source


# ═════════════════════════════════════════════════════════════════════════════
#  U12 — whose list is it
# ═════════════════════════════════════════════════════════════════════════════

def test_every_allowlisted_host_declares_which_table_it_belongs_to():
    """U12 was never "is this list right" but "whose list is it". A host in the
    compiled tuple and in neither table is one nobody has taken responsibility
    for, which is the state the question was raised about."""
    from modules.abap_sast import (_NAMESPACE_HOSTS, _NAMESPACE_HOSTS_OURS,
                                   _NAMESPACE_HOSTS_VERIFIED)
    declared = set(_NAMESPACE_HOSTS_VERIFIED) | set(_NAMESPACE_HOSTS_OURS)
    assert set(_NAMESPACE_HOSTS) == declared
    assert not (set(_NAMESPACE_HOSTS_VERIFIED) & set(_NAMESPACE_HOSTS_OURS))


def test_a_verified_host_names_the_file_it_was_read_from():
    """The stronger claim carries the heavier burden. Checking this one turned up
    that `w3.org` and `xml.sap.com` had been carrying a "verified" marker they
    had not earned — only `http://www.sap.com/abapxml` appears in an SAP file."""
    from modules.abap_sast import _NAMESPACE_HOSTS_VERIFIED
    for host, evidence in _NAMESPACE_HOSTS_VERIFIED.items():
        assert ".md" in evidence, (host, evidence)
        assert "http://" in evidence, "cite the namespace URI, not just the file"


def test_our_own_entries_give_a_reason_rather_than_an_assertion():
    """These are judgements. A judgement with no reason cannot be reviewed, and
    the next person either trusts it blindly or deletes it blindly."""
    from modules.abap_sast import _NAMESPACE_HOSTS_OURS
    for host, reason in _NAMESPACE_HOSTS_OURS.items():
        assert len(reason) > 40, (host, reason)


def test_the_list_is_not_presented_as_sap_s():
    """The whole point of U12. If this file ever says the allowlist is SAP's,
    the product is making a claim on SAP's behalf that SAP has not made."""
    source = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "not a claim about SAP" in source
    assert "this project's error to correct" in source


@pytest.mark.parametrize("uri", [
    "http://www.sap.com/abapxml",              # SAP's asXML namespace
    "http://www.w3.org/2001/XMLSchema",        # XML Schema
    "http://schemas.xmlsoap.org/soap/envelope/",   # SOAP 1.1 envelope
])
def test_a_namespace_uri_is_not_reported_as_insecure_transport(uri):
    """The false positives F5 removed. Relabelling must not change behaviour —
    an honesty fix that quietly resurrects a page of findings is not one."""
    src = "FORM f.\n  DATA(x) = '%s'.\nENDFORM.\n" % uri
    assert "ABAP-CONF-002" not in _ids(src, "z.abap")


def test_a_real_http_endpoint_is_still_reported():
    """The control. An allowlist that swallowed everything would be a silent
    retirement of the rule rather than a narrowing of it."""
    src = "FORM f.\n  DATA(x) = 'http://evil.example.com/api'.\nENDFORM.\n"
    assert "ABAP-CONF-002" in _ids(src, "z.abap")


# ═════════════════════════════════════════════════════════════════════════════
#  U2 — the FIELDS clause, and a question whose answer is "no change"
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("statement", [
    # SAP's own dynamic-SELECT-list example, verbatim in shape.
    "SELECT (select_list) FROM zdemo_abap_fli"
    " INTO CORRESPONDING FIELDS OF TABLE @fli_tab.",
    # SAP's second spelling, with the list as a string literal.
    "SELECT (`CARRID, CONNID, FLDATE`) FROM zdemo_abap_fli INTO TABLE @lt.",
])
def test_the_documented_dynamic_column_list_is_matched(statement):
    """U2 asked whether A1 needed extending. It did not, and this is why: SAP
    documents the dynamic column list exactly once, as a parenthesis directly
    after SELECT, and both of its spellings already match. Pinned so the answer
    stays true rather than being re-derived."""
    assert "ABAP-SQLI-013" in _ids("FORM f.\n  %s\nENDFORM.\n" % statement,
                                   "z.abap")


@pytest.mark.parametrize("statement", [
    "SELECT carrid, connid FROM zdemo_abap_fli INTO TABLE @lt.",
    "SELECT FROM zdemo_abap_fli FIELDS carrid, connid INTO TABLE @lt.",
    "SELECT FROM zdemo_abap_fli FIELDS zdemo_abap_fli~* INTO TABLE @lt.",
    "SELECT FROM zdemo_abap_fli FIELDS carrid AS al1 INTO TABLE @lt.",
])
def test_the_static_field_list_forms_stay_silent(statement):
    """The four `FIELDS` variants SAP tabulates are static column lists. A rule
    firing on them would report a CRITICAL CWE-89 on the modern arrangement of
    ordinary SQL."""
    assert "ABAP-SQLI-013" not in _ids("FORM f.\n  %s\nENDFORM.\n" % statement,
                                       "z.abap")


def test_the_undocumented_parenthesised_fields_form_is_not_matched():
    """The decision U2 actually settles. `FIELDS (lv_list)` appears in no SAP
    material — not in the FIELDS variant table, not in the dynamic-programming
    cheat sheet — so matching it would be inventing syntax. That is exactly how
    ABAP-CDS-002 spent its life matching a `WHERE TRUE` that DCL has never had
    (U5), and this test exists so nobody adds it on symmetry.
    """
    src = "FORM f.\n  SELECT FROM zdemo FIELDS (lv_list) INTO TABLE @lt.\nENDFORM.\n"
    assert "ABAP-SQLI-013" not in _ids(src, "z.abap")


def test_the_reason_for_leaving_it_alone_is_recorded_beside_the_rule():
    """A rule that does not match something looks identical to a rule nobody
    thought about. The distinction has to be written down, or U2 gets re-opened
    by the next person who notices FIELDS is missing."""
    source = (ROOT / "modules" / "abap_sast_extra.py").read_text(encoding="utf-8")
    assert "U2, settled" in source
    assert "NONE of them is" in source


# ═════════════════════════════════════════════════════════════════════════════
#  U1 — the two grammar questions the lexer had been betting on
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unclosed_literal_does_not_mask_the_following_statement():
    """"Character literals that span multiple lines are not allowed." While the
    mode stack carried `lit` across the newline, everything after a stray
    apostrophe was masked as literal content and every rule went blind on real
    code — bounded only by the fifty-line runaway guard."""
    from modules.abap_sast import split_statements
    stmts = split_statements(
        "x = 'unclosed\nDELETE FROM zcust WHERE id = lv_id.\n")
    assert any("DELETE FROM zcust" in s.text for s in stmts), [s.text for s in stmts]


def test_an_unclosed_template_does_not_mask_the_following_statement():
    """"A string template that starts with | must be closed with | within the
    same line of source code.\""""
    from modules.abap_sast import split_statements
    stmts = split_statements(
        "x = |unclosed\nDELETE FROM zcust WHERE id = lv_id.\n")
    assert any("DELETE FROM zcust" in s.text for s in stmts), [s.text for s in stmts]


def test_the_documented_exception_still_spans_lines():
    """"The only exceptions to this rule are line breaks in embedded
    expressions." Closing the template at the newline here would break the one
    multi-line form ABAP actually allows."""
    from modules.abap_sast import split_statements
    stmts = split_statements("x = |a{ lv_b\n  + lv_c }d|. WRITE x.\n")
    assert any("WRITE x" in s.text for s in stmts), [s.text for s in stmts]


def test_a_forced_close_is_reported_as_degraded_rather_than_recovered_silently():
    """A recovery nobody is told about is indistinguishable from a clean lex.
    The following lines are now scanned — which is the fix — but the line that
    was malformed still has to reach the coverage signal."""
    from modules.abap_sast import AbapSourceScanner
    scanner = AbapSourceScanner(data_flow=False)
    scanner.scan_text("REPORT z.\nx = 'never closed\nWRITE lv_a.\n", Path("z.abap"))
    assert scanner.lex_degraded >= 1


# ═════════════════════════════════════════════════════════════════════════════
#  U7 — the application-server dataset
# ═════════════════════════════════════════════════════════════════════════════

def test_a_dataset_read_is_a_taint_source():
    """SAP: "This statement exports data from the file specified in dset to the
    data object dobj." A file on the application server was written by an
    interface, an upload, another system or an operator — never by the program
    reading it."""
    src = ("FORM f.\n  READ DATASET lv_file INTO lv_line.\n"
           "  SELECT * FROM (lv_line) INTO TABLE @DATA(t).\nENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    assert any(f["confidence"] == "confirmed"
               for f in scanner.scan_text(src, Path("z.abap"))
               if f["rule_id"].startswith("ABAP-SQLI"))


def test_the_length_additions_do_not_hide_the_target():
    """`MAXIMUM LENGTH` and `[ACTUAL] LENGTH` are in SAP's syntax and sit after
    the INTO target, so a pattern anchored too tightly would miss the common
    form."""
    src = ("FORM f.\n  READ DATASET lv_file INTO lv_line MAXIMUM LENGTH 200.\n"
           "  SELECT * FROM (lv_line) INTO TABLE @DATA(t).\nENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    assert any(f["confidence"] == "confirmed"
               for f in scanner.scan_text(src, Path("z.abap"))
               if f["rule_id"].startswith("ABAP-SQLI"))


def test_it_taints_the_target_and_not_every_variable_in_scope():
    """The control. A source that tainted the whole scope would confirm every
    dynamic statement in the FORM and make the evidence class meaningless."""
    src = ("FORM f.\n  READ DATASET lv_file INTO lv_line.\n"
           "  SELECT * FROM (lv_other) INTO TABLE @DATA(t).\nENDFORM.\n")
    scanner = AbapSourceScanner(data_flow=True)
    assert all(f["confidence"] != "confirmed"
               for f in scanner.scan_text(src, Path("z.abap"))
               if f["rule_id"].startswith("ABAP-SQLI"))


def test_a_keyword_source_needs_no_provenance_entry():
    """`READ DATASET` is an ABAP keyword — a language construct anyone can
    verify. `CONFIRMED_SOURCE_IDENTIFIERS` exists for library names, which are
    claims about SAP's shipped code, and padding it with keywords would blur the
    distinction it was created to keep."""
    from modules.abap_sast import RiseTaintAnalyzer
    assert not any("DATASET" in name.upper()
                   for name in RiseTaintAnalyzer.CONFIRMED_SOURCE_IDENTIFIERS)


# ═════════════════════════════════════════════════════════════════════════════
#  U8 — declined, and the decision recorded
# ═════════════════════════════════════════════════════════════════════════════

def test_the_http_handler_seeding_is_declined_with_its_reason():
    """U8 is the one question in section 7 that no fetchable SAP source answers.
    Seeding a handler's request parameter is ordinary B2-shaped work needing no
    new machinery — what it needs is the interface and method name, and neither
    appears in the released-classes listing, the cloud cheat sheet, or the
    keyword documentation pages tried. Writing it from memory is exactly the
    failure U10 exists to prevent, and remembering it correctly would not make
    it verified. The DECISION is settled even though the question is not, and it
    has to be recorded or the next person re-opens it."""
    source = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "U8 (the ABAP-Cloud HTTP handler interface) is DECLINED" in source
    assert "What would settle it" in source
