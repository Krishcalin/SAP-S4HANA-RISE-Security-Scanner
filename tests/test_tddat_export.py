"""
The table -> authorization group extract, from the file on disk to the finding.

WHY THIS FILE EXISTS
--------------------
Two checks in `modules/ecs_config_items.py` — AUTH-ECS-001 (the password-hash
tables behind authorization group SPWD) and CRYPTO-ECS-001 (SSF_PSE_D behind SPSE)
— were written, reviewed, correct and unit-tested, and had never once run against
data. They read `table_auth_groups`, `modules/data_loader.py` had no key for it, so
`self.data.get(...)` returned None and both self-skipped on every scan anybody has
ever run. `tests/test_ecs_config_items.py` hands the auditor a dict directly and
could not have caught that: the missing link was the LOADER.

So every test here goes from a file in a directory, through `DataLoader`, to the
findings. The load-bearing ones are:

  * the two checks FIRE on an extract that is on disk — the path that had never
    executed;
  * a correctly grouped extract on disk produces ZERO findings. A rule that also
    fires on correct config is worse than no rule, and this one would tell a
    compliant customer every password hash in their system is exposed;
  * every column alias the module documents survives the loader's header
    normalisation. The loader deliberately keeps NO vocabulary of its own, so a
    header only one side knows reads as an empty cell — and an empty cell here
    means "no authorization group assigned". A silent disagreement between these
    two files IS the false positive above.

THE OTHER HALF: THE EXTRACT IS READ AS COMPLETE
-----------------------------------------------
A table absent from a complete extract has no authorization group, and that is the
finding. A namespace-filtered extract would therefore over-report, so the tests
below pin both directions: where a filter can be PROVEN the absent objects are
disclosed as a coverage gap rather than reported as unprotected, and where it
cannot be proven the finding says so in its own text.
"""
from __future__ import annotations

import contextlib
import csv
import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import cloudalm_import, ecs_config_items                  # noqa: E402
from modules.compliance_mapping import ComplianceMapper                # noqa: E402
from modules.data_loader import DataLoader                             # noqa: E402
from modules.ecs_config_items import (                                 # noqa: E402
    EcsConfigAuditor,
    PASSWORD_HASH_AUTH_GROUP,
    PASSWORD_HASH_TABLES,
    PSE_AUTH_GROUP,
    PSE_TABLE,
    TABLE_AUTH_GROUPS,
    _GROUP_KEYS,
    _TABLE_KEYS,
)
from server.coverage import all_logical_sources, build_manifest        # noqa: E402
from server.enrich import team_for                                     # noqa: E402

ALIASES = DataLoader.FILE_MAP.get(TABLE_AUTH_GROUPS, [])


# --------------------------------------------------------------------------- #
#  Helpers — everything goes through the loader, never straight into the dict  #
# --------------------------------------------------------------------------- #

def write_extract(directory, rows, *, filename="table_auth_groups.csv",
                  table_header="TABNAME", group_header="CCLASS",
                  delimiter=",", encoding="utf-8"):
    """Write a table -> authorization group extract as a customer would send it."""
    path = Path(directory) / filename
    with open(path, "w", encoding=encoding, newline="") as fh:
        writer = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
        writer.writerow([table_header, group_header])
        writer.writerows(rows)
    return path


def load(directory):
    """The DataLoader output for a directory, with its console chatter suppressed."""
    with contextlib.redirect_stdout(io.StringIO()):
        return DataLoader(Path(directory)).load_all()


def scan(directory):
    return EcsConfigAuditor(load(directory)).run_all_checks()


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def by_id(findings, check_id):
    return next(f for f in findings if f["check_id"] == check_id)


def assert_extract_reaches_the_checks(tmp_path, **write_kwargs):
    """The same file shape, both directions: compliant is silent, defective fires.

    WHY BOTH HALVES ARE NEEDED, AND WHY `== []` ALONE IS NOT A TEST OF THE LOADER.
    A file the loader never managed to read produces exactly the same answer as a
    compliant one: `_table_auth_index` returns None and nothing is reported. So a
    test that writes an extract in some shape and asserts `scan(...) == []` cannot
    fail for the reason it claims — it passes just as happily when the shape defeated
    the loader and the whole extract was dropped. Two mutations proved it: removing
    the delimiter detection and the BOM handling, and then removing header
    normalisation entirely, each left every test in this file green.

    The second half is what pins the loader down. The finding names the table it read
    out of that file, and no non-load can satisfy it.
    """
    write_extract(tmp_path, compliant_rows(), **write_kwargs)
    assert scan(tmp_path) == []

    rows = compliant_rows()
    rows[0] = [PASSWORD_HASH_TABLES[0], "SS"]
    write_extract(tmp_path, rows, **write_kwargs)
    finding = by_id(scan(tmp_path), "AUTH-ECS-001")
    assert finding["details"]["wrong_group"] == {PASSWORD_HASH_TABLES[0]: "SS"}
    assert finding["details"]["extract_rows"] == len(rows)


def compliant_rows():
    """An extract in which every object the note names is correctly grouped."""
    return ([[t, PASSWORD_HASH_AUTH_GROUP] for t in PASSWORD_HASH_TABLES]
            + [[PSE_TABLE, PSE_AUTH_GROUP],
               # Two ordinary rows: a complete extract is not a list of our seven
               # objects, and the checks must ignore everything else in it.
               ["T000", "SS"],
               ["ZCUSTOM_TABLE", ""]])


# --------------------------------------------------------------------------- #
#  The wiring that was missing                                                 #
# --------------------------------------------------------------------------- #

def test_the_loader_has_a_key_for_the_extract():
    """The whole defect in one line: no key meant both checks self-skipped on every
    scan, and a self-skipped check contributes nothing and looks like a pass."""
    assert TABLE_AUTH_GROUPS in DataLoader.FILE_MAP
    assert ALIASES, "a key with no filenames can never be satisfied"


@pytest.mark.parametrize("fname", ALIASES)
def test_every_alias_follows_the_house_filename_convention(fname):
    assert fname == fname.lower()
    assert fname.endswith(".csv")


@pytest.mark.parametrize("fname", ALIASES)
def test_no_alias_collides_with_a_cloud_alm_store_name(fname):
    """`tddat.csv` is the alias this source obviously wants and deliberately does
    not have.

    TDDAT is also a Cloud ALM CSA store name, and `DataLoader._resolve` withholds a
    differently-cased match only for stores the importer TRANSLATES. TDDAT is in
    `UNMAPPED_STORES`, so the alias would let the filename pass swallow a CSA
    `TDDAT.csv` raw — losing the "recognised, not translated" line that is currently
    the only thing said about that store, and claiming a store whose completeness
    nobody has established, for a source where an object the extract omits is
    reported as unprotected.

    If a later change adds an alias that names a known store, this fails and the
    decision gets made deliberately instead of by filename.
    """
    assert cloudalm_import.store_for_filename(fname) is None, (
        f"{fname} names CSA store {cloudalm_import.store_for_filename(fname)}; the "
        "filename pass would eat that store export untranslated")


@pytest.mark.parametrize("fname", ALIASES)
def test_each_alias_is_loaded_and_reaches_the_checks(tmp_path, fname):
    """The alias list is only real if each name actually resolves on disk."""
    write_extract(tmp_path, [[t, "SS"] for t in PASSWORD_HASH_TABLES]
                  + [[PSE_TABLE, PSE_AUTH_GROUP]], filename=fname)
    data = load(tmp_path)
    assert data[TABLE_AUTH_GROUPS], f"{fname} was not loaded"
    assert ids(EcsConfigAuditor(data).run_all_checks()) == ["AUTH-ECS-001"]


def test_the_module_docstring_names_the_filenames_the_loader_accepts():
    """The module's docstring tells a reader what to ask the customer for. If the
    loader's alias list moves and the docstring does not, the instruction is wrong
    and the export arrives under a name nothing reads."""
    doc = ecs_config_items.__doc__ or ""
    for fname in ALIASES:
        assert fname in doc, f"{fname} is accepted by the loader but undocumented"


def test_the_source_is_visible_in_the_upload_coverage_manifest(tmp_path):
    """A customer who did not send this extract must be told so somewhere. The
    checks stay silent by design, so the manifest is the only thing that says the
    question was never asked."""
    assert TABLE_AUTH_GROUPS in all_logical_sources()

    absent = build_manifest(load(tmp_path))
    assert TABLE_AUTH_GROUPS in absent["missing"]

    write_extract(tmp_path, compliant_rows())
    supplied = build_manifest(load(tmp_path))
    assert TABLE_AUTH_GROUPS in supplied["supplied"]


# --------------------------------------------------------------------------- #
#  THE NEGATIVE CONTROL                                                        #
# --------------------------------------------------------------------------- #

def test_a_correctly_grouped_extract_on_disk_produces_zero_findings(tmp_path):
    """The exit criterion. A compliant system reading this file from disk must be
    told nothing at all — and until this test existed, nothing had ever read one.

    The row count is asserted first because silence is ambiguous: an extract the
    loader dropped is silent too, and a negative control that cannot tell the two
    apart is proving nothing about a compliant system.
    """
    rows = compliant_rows()
    write_extract(tmp_path, rows)
    assert len(load(tmp_path)[TABLE_AUTH_GROUPS]) == len(rows)
    assert scan(tmp_path) == []


def test_an_extract_full_of_other_tables_is_not_our_business(tmp_path):
    """A real extract is thousands of rows about tables the note never mentions."""
    rows = compliant_rows() + [[f"ZTAB{n:03d}", ""] for n in range(50)] \
        + [["BKPF", "FC31"], ["USR40", ""]]
    write_extract(tmp_path, rows)
    assert len(load(tmp_path)[TABLE_AUTH_GROUPS]) == len(rows)
    assert scan(tmp_path) == []


# --------------------------------------------------------------------------- #
#  The two checks, firing against data for the first time                      #
# --------------------------------------------------------------------------- #

def test_a_password_hash_table_in_the_wrong_group_fires_from_a_file(tmp_path):
    rows = compliant_rows()
    rows[0] = [PASSWORD_HASH_TABLES[0], "SS"]
    write_extract(tmp_path, rows)
    findings = scan(tmp_path)
    assert ids(findings) == ["AUTH-ECS-001"]
    detail = by_id(findings, "AUTH-ECS-001")["details"]
    assert detail["wrong_group"] == {PASSWORD_HASH_TABLES[0]: "SS"}
    assert detail["extract_rows"] == len(rows)


def test_a_password_hash_table_with_no_group_fires_from_a_file(tmp_path):
    rows = compliant_rows()
    rows[1] = [PASSWORD_HASH_TABLES[1], ""]
    write_extract(tmp_path, rows)
    findings = scan(tmp_path)
    assert ids(findings) == ["AUTH-ECS-001"]
    assert by_id(findings, "AUTH-ECS-001")["details"]["no_group"] == \
        [PASSWORD_HASH_TABLES[1]]


def test_the_pse_table_in_the_wrong_group_fires_from_a_file(tmp_path):
    rows = [r for r in compliant_rows() if r[0] != PSE_TABLE] + [[PSE_TABLE, "SS"]]
    write_extract(tmp_path, rows)
    findings = scan(tmp_path)
    assert ids(findings) == ["CRYPTO-ECS-001"]
    assert by_id(findings, "CRYPTO-ECS-001")["details"]["observed_group"] == "SS"


def test_both_checks_fire_from_one_file(tmp_path):
    """They are independent defects with independent owners; one file can carry
    both and neither may mask the other."""
    write_extract(tmp_path, [[t, "SS"] for t in PASSWORD_HASH_TABLES]
                  + [[PSE_TABLE, ""], ["T000", "SS"]])
    assert ids(scan(tmp_path)) == ["AUTH-ECS-001", "CRYPTO-ECS-001"]


# --------------------------------------------------------------------------- #
#  Loader <-> module column vocabulary                                         #
# --------------------------------------------------------------------------- #

def test_the_docstring_and_the_code_document_the_same_column_vocabulary():
    """One vocabulary, written down once. If the docstring drifts from the tuples
    the module actually matches on, the export guide built from that docstring tells
    customers to send a header nothing reads."""
    doc = ecs_config_items.__doc__ or ""
    block = doc.split("table name", 1)[1].split("THIS LIST IS THE ONLY ONE", 1)[0]
    documented = set(re.findall(r"[A-Z][A-Z0-9_]{2,}", block))
    assert documented == set(_TABLE_KEYS) | set(_GROUP_KEYS)


@pytest.mark.parametrize("header", _TABLE_KEYS)
def test_every_table_header_alias_survives_the_loader(tmp_path, header):
    """If the loader's normalisation broke an alias, the table name would read as
    empty, the row would be dropped and a wrongly grouped table would pass."""
    write_extract(tmp_path, [[t, "SS"] for t in PASSWORD_HASH_TABLES]
                  + [[PSE_TABLE, PSE_AUTH_GROUP]], table_header=header)
    assert ids(scan(tmp_path)) == ["AUTH-ECS-001"]


@pytest.mark.parametrize("header", _GROUP_KEYS)
def test_every_group_header_alias_survives_the_loader(tmp_path, header):
    """The dangerous direction, and the reason the loader keeps no second list: an
    alias it mangles reads as an empty group, which is 'no authorization group
    assigned' — a HIGH finding against a system that is correctly configured.

    The defective half is asserted too: an alias could equally be mangled into
    silence, and silence about a wrongly grouped table is the false NEGATIVE."""
    assert_extract_reaches_the_checks(tmp_path, group_header=header)


def test_a_header_outside_the_shared_vocabulary_is_the_false_positive_itself(tmp_path):
    """The stake, demonstrated rather than asserted — not an outcome we accept.

    This system is COMPLIANT: every object the note names sits behind its group. The
    only thing wrong is a column header neither file knows, so the group reads as an
    empty cell, an empty cell means "no authorization group assigned", and the
    customer is told every password hash they hold is readable — twice, at HIGH.

    That is what a disagreement between the loader and the module costs, which is
    why the vocabulary lives in exactly one place. If a header like this turns up in
    the field the fix is to add it to `_GROUP_KEYS` in the module, where the loader
    inherits it for free; adding it to the loader instead re-creates the split.
    """
    assert "BERECHTIGUNGSGRUPPE" not in set(_GROUP_KEYS)
    write_extract(tmp_path, compliant_rows(), group_header="BERECHTIGUNGSGRUPPE")
    assert ids(scan(tmp_path)) == ["AUTH-ECS-001", "CRYPTO-ECS-001"]


@pytest.mark.parametrize("table_header,group_header", [
    ("Table Name", "Auth Group"),
    ("table_name", "authorization_group"),
    ("  TABNAME  ", "  CCLASS  "),
])
def test_headers_as_a_download_actually_spells_them_still_read(
        tmp_path, table_header, group_header):
    """`_load_csv` strips, upper-cases and turns spaces into underscores; the module
    matches case-insensitively. An ALV or Excel round-trip must not change the
    verdict — and 'no verdict at all' is a changed verdict, so the defective half is
    asserted as well."""
    assert_extract_reaches_the_checks(
        tmp_path, table_header=table_header, group_header=group_header)


def test_the_values_are_matched_case_insensitively_end_to_end(tmp_path):
    """An SE16 download may lower-case the contents; 'spwd' is SPWD."""
    rows = [[t.lower(), PASSWORD_HASH_AUTH_GROUP.lower()] for t in PASSWORD_HASH_TABLES]
    rows.append([PSE_TABLE.lower(), PSE_AUTH_GROUP.lower()])
    write_extract(tmp_path, rows)
    assert len(load(tmp_path)[TABLE_AUTH_GROUPS]) == len(rows)
    assert scan(tmp_path) == []

    # And the other direction from the same lower-cased file: a wrong group has to be
    # read as a wrong group, not lost with the rest of the row.
    rows[0] = [PASSWORD_HASH_TABLES[0].lower(), "ss"]
    write_extract(tmp_path, rows)
    assert by_id(scan(tmp_path), "AUTH-ECS-001")["details"]["wrong_group"] == \
        {PASSWORD_HASH_TABLES[0]: "SS"}


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_the_delimiters_the_loader_detects_all_reach_the_checks(tmp_path, delimiter):
    """A German Excel writes semicolons and an SE16 clipboard paste writes tabs. The
    loader detects the delimiter; getting it wrong would collapse every row into one
    column and silently drop the whole extract — which is why this asserts the
    defective direction too. 'Dropped the whole extract' also produces no findings."""
    assert_extract_reaches_the_checks(tmp_path, delimiter=delimiter)


def test_a_byte_order_mark_does_not_hide_the_first_column(tmp_path):
    """Excel writes UTF-8 with a BOM. A BOM glued to the first header would make
    TABNAME unrecognisable and every table read as unnamed — and 'unnamed' rows are
    dropped, which is silent, so silence alone cannot be the assertion."""
    assert_extract_reaches_the_checks(tmp_path, encoding="utf-8-sig")


# --------------------------------------------------------------------------- #
#  Absent, empty and unreadable input — silence, never a verdict, never a raise #
# --------------------------------------------------------------------------- #

def test_a_directory_without_the_extract_leaves_the_checks_silent(tmp_path):
    """Requirement of the wiring: adding the key must not change what happens to a
    customer who never sent this export."""
    data = load(tmp_path)
    assert data[TABLE_AUTH_GROUPS] is None
    assert EcsConfigAuditor(data).run_all_checks() == []


def test_a_header_only_file_is_not_read_as_a_system_with_no_groups(tmp_path):
    """An export that ran and returned nothing is a broken export, not a system
    whose password hash tables are all unprotected."""
    write_extract(tmp_path, [])
    data = load(tmp_path)
    assert data[TABLE_AUTH_GROUPS] == []
    assert EcsConfigAuditor(data).run_all_checks() == []


def test_an_extract_with_no_table_column_yields_nothing(tmp_path):
    """A file we cannot interpret decides nothing in either direction. Reading a
    missing TABNAME column as 'every required table is absent' would report the
    estate's password hashes as unprotected on a system that is fine."""
    path = Path(tmp_path) / "table_auth_groups.csv"
    path.write_text("CCLASS,DESCRIPTION\nSPWD,user master\nSPSE,PSE\n",
                    encoding="utf-8")
    assert scan(tmp_path) == []


def test_one_short_row_does_not_truncate_the_extract(tmp_path):
    """A dropped trailing cell must not turn a compliant system into two HIGH findings.

    `csv.DictReader` fills an absent trailing field with None, and `_load_csv` raised
    on `None.strip()` — out of the row loop, into an `except` that returned the rows
    read SO FAR. So an extract whose FIRST row lost its empty trailing cell (which is
    what a spreadsheet round-trip does) arrived one row long, and every table after it
    read as absent. Absent, in this one source, means "no authorization group".

    The system below is correctly configured. The row order is the whole point: the
    ragged row is FIRST, so a truncating loader keeps only `T000` — an SAP-delivered
    name, so the namespace-filter guard does not catch it either — and reports every
    password hash table and the database PSE table as unprotected.
    """
    rows = compliant_rows()
    path = Path(tmp_path) / "table_auth_groups.csv"
    path.write_text("TABNAME,CCLASS\nT000\n"
                    + "".join(f"{t},{g}\n" for t, g in rows), encoding="utf-8")
    assert len(load(tmp_path)[TABLE_AUTH_GROUPS]) == len(rows) + 1
    assert scan(tmp_path) == []


def test_blank_and_ragged_rows_do_not_raise(tmp_path):
    path = Path(tmp_path) / "table_auth_groups.csv"
    path.write_text(
        "TABNAME,CCLASS\n"
        + "\n".join(f"{t},{PASSWORD_HASH_AUTH_GROUP}" for t in PASSWORD_HASH_TABLES)
        + f"\n{PSE_TABLE},{PSE_AUTH_GROUP}\n"
        ",\n"          # a row with neither value
        "ORPHAN\n"     # a short row: DictReader fills the missing cell with None
        ",SPWD\n",     # a group with no table
        encoding="utf-8")
    assert scan(tmp_path) == []


# --------------------------------------------------------------------------- #
#  "Complete" is an assumption, and it is disclosed either way                 #
# --------------------------------------------------------------------------- #

def filtered_rows():
    """A Z*-only extract: the shape a customer produces when they filter TDDAT to
    their own namespace, which is a natural thing to do and completely wrong here."""
    return [[f"ZTAB{n:03d}", "" if n % 2 else "ZCLS"] for n in range(8)]


def test_a_namespace_filtered_extract_does_not_report_the_hashes_as_unprotected(tmp_path):
    """THE FALSE POSITIVE THE COMPLETENESS RULE CREATES IF NOBODY LOOKS FOR IT.

    Absence means "no authorization group" only in a COMPLETE extract. This one
    names nothing SAP delivers, so it cannot be complete, and reading its silence
    about USR02 as a verdict would hand a compliant customer a HIGH finding that
    says every password hash in their system is readable.
    """
    write_extract(tmp_path, filtered_rows())
    fired = ids(scan(tmp_path))
    assert "AUTH-ECS-001" not in fired and "CRYPTO-ECS-001" not in fired


def test_a_namespace_filtered_extract_discloses_the_gap_instead(tmp_path):
    """And the other half, which matters more: staying silent would leave a report
    that says nothing about the password-hash tables, and that reads exactly like a
    report that found them correctly protected."""
    write_extract(tmp_path, filtered_rows())
    findings = scan(tmp_path)
    assert ids(findings) == ["AUTH-ECS-000"]
    finding = findings[0]
    assert finding["severity"] == "INFO"
    assert set(finding["details"]["objects_not_assessable"]) == \
        set(PASSWORD_HASH_TABLES) | {PSE_TABLE}
    assert finding["details"]["checks_affected"] == ["AUTH-ECS-001", "CRYPTO-ECS-001"]
    assert "cannot tell" in finding["description"]


def test_the_disclosure_names_no_defective_object(tmp_path):
    """A coverage gap is not a defect. Putting the objects we could NOT judge into
    identity would add attack-path nodes no evidence supports."""
    write_extract(tmp_path, filtered_rows())
    finding = scan(tmp_path)[0]
    assert "affected_objects" not in finding
    assert finding["scope"] == "aggregate"


def test_the_disclosure_carries_the_finding_contract(tmp_path):
    write_extract(tmp_path, filtered_rows())
    finding = scan(tmp_path)[0]
    assert team_for(finding["check_id"]) != "unassigned"
    assert finding["category"] in ComplianceMapper.CATEGORY_THEMES
    assert re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", finding["check_id"])
    assert finding["remediation"].strip() and finding["description"].strip()
    assert any("3250501" in r for r in finding["references"])


def test_one_sap_delivered_row_is_enough_to_stop_the_filter_claim(tmp_path):
    """The detection SUPPRESSES evidence, so it is deliberately the strict rule: a
    single SAP-delivered name means the extract could be complete, and a real defect
    must not be silenced by a heuristic."""
    write_extract(tmp_path, filtered_rows() + [["T000", "SS"]])
    findings = scan(tmp_path)
    assert ids(findings) == ["AUTH-ECS-001", "CRYPTO-ECS-001"]


def test_the_disclosure_is_about_the_gap_not_about_the_filter(monkeypatch, tmp_path):
    """A filtered extract that still carries every object the note names answered
    the question in full, and an INFO finding would then be noise on a system we
    did assess. Unreachable with the real note — every object it names is an
    SAP-standard name — so the guard is pinned here rather than left to rot."""
    monkeypatch.setattr(ecs_config_items, "PASSWORD_HASH_TABLES", ("ZUSR02",))
    monkeypatch.setattr(ecs_config_items, "PSE_TABLE", "ZPSE")
    write_extract(tmp_path, [["ZUSR02", PASSWORD_HASH_AUTH_GROUP],
                             ["ZPSE", PSE_AUTH_GROUP]])
    assert scan(tmp_path) == []


def test_the_disclosure_does_not_inflate_the_loss_figure(tmp_path):
    """AUTH-ECS-000 routes to the privilege-escalation FAIR scenario on its prefix,
    which is where its two checks belong — and it must cost nothing there.

    `data/fair_scenarios.json` routes by check-id prefix, and the module docstring
    already records what that can do silently: STDUSR-ECS-001 is not TRUST-ECS-001
    precisely because the prefix alone would have priced a leftover client as remote
    code execution. A finding that says "we could not look" is not a control
    weakness, and pricing it as one would put a number on our own missing evidence.

    It costs nothing today because the resistance-strength band follows the WORST
    severity in the bucket and INFO falls back to `hardened` — the same band the
    target state uses. This pins that, so a later change of severity or prefix has
    to be deliberate.
    """
    from modules import fair_adapter
    from modules.risk_prioritizer import RiskPrioritizer

    write_extract(tmp_path, filtered_rows())
    findings = scan(tmp_path)
    assert ids(findings) == ["AUTH-ECS-000"]

    catalog = fair_adapter.load_catalog()
    built = fair_adapter.build_inputs(RiskPrioritizer().prioritize(findings),
                                      catalog, catalog["organization_default"])
    for asis in built["asis"]["scenarios"]:
        target = next(s for s in built["target"]["scenarios"] if s["id"] == asis["id"])
        assert asis["resistance_strength"] == target["resistance_strength"], asis["id"]
        assert asis["primary_loss"] == target["primary_loss"], asis["id"]


@pytest.mark.parametrize("check_id,missing", [
    ("AUTH-ECS-001", PASSWORD_HASH_TABLES[3]),
    ("CRYPTO-ECS-001", PSE_TABLE),
])
def test_a_finding_that_rests_on_absence_says_the_extract_may_be_filtered(
        tmp_path, check_id, missing):
    """The case we CANNOT detect: an extract naming SAP tables may still have been
    filtered by object name, and nothing in the rows can settle it. The note's
    reading is applied — absence means no group — and the finding carries the
    assumption in its own text, because a reviewer holding a filtered extract will
    read the finding and not this module.
    """
    write_extract(tmp_path, [r for r in compliant_rows() if r[0] != missing])
    finding = by_id(scan(tmp_path), check_id)
    assert "does not list at all" in finding["description"]
    assert "unfiltered" in finding["description"]
    assert finding["details"]["extract_completeness"].startswith("read as complete")


def test_the_caveat_is_absent_when_no_verdict_rests_on_absence(tmp_path):
    """The control for the test above. Every offender here is present in the extract
    with the wrong group — positive evidence — so a paragraph about filtered exports
    would be noise attached to a finding it does not qualify."""
    rows = compliant_rows()
    rows[0] = [PASSWORD_HASH_TABLES[0], "SS"]
    write_extract(tmp_path, rows)
    finding = by_id(scan(tmp_path), "AUTH-ECS-001")
    assert "does not list at all" not in finding["description"]
    assert finding["details"]["not_in_extract"] == []


def test_the_absent_objects_stay_separated_from_the_misassigned_ones(tmp_path):
    """One defect and one fix, so one finding — but a reviewer has to be able to see
    at a glance which objects the extract simply never mentioned."""
    rows = [r for r in compliant_rows() if r[0] != PASSWORD_HASH_TABLES[2]]
    rows[0] = [PASSWORD_HASH_TABLES[0], "SS"]
    rows[1] = [PASSWORD_HASH_TABLES[1], ""]
    write_extract(tmp_path, rows)
    detail = by_id(scan(tmp_path), "AUTH-ECS-001")["details"]
    assert detail["wrong_group"] == {PASSWORD_HASH_TABLES[0]: "SS"}
    assert detail["no_group"] == [PASSWORD_HASH_TABLES[1]]
    assert detail["not_in_extract"] == [PASSWORD_HASH_TABLES[2]]
