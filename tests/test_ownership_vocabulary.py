"""The owning-team mapping has to speak the vocabulary the schema enforces.

WHAT HAPPENED. `modules/rise_ownership.py` mapped the `CSA-` prefix to
`"configuration"`, which is not one of the seven teams
`check_definition_owning_team_check` allows. Every scan that produced a CSA
finding was rejected by PostgreSQL at insert — but no scan ever produced one,
because `cloudalm_verdicts` was one of the five modules that fired on nothing.
An invalid value in a prefix table costs exactly nothing until the prefix is
used, and then it costs the whole run.

WHY THE TEST SUITE MISSED IT. The check constraint lives in PostgreSQL, so only
the `server (PostgreSQL 16)` job could see it, and that job is skipped without a
DB_DSN — which is the ordinary local state. The mapping and the constraint are
two files that have to agree, in two languages, verified by a job most runs skip.

THIS TEST NEEDS NO DATABASE. It reads the allowed values out of `schema.sql` and
compares them against the mapping, so the disagreement is caught by any run of
the suite rather than only by the job that would have hit it in production.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = ROOT / "server" / "schema.sql"


def _allowed_teams() -> set:
    """The vocabulary, read from the schema rather than restated here.

    Restating it would create a third copy to keep in step, and the bug this file
    exists for was two copies disagreeing.
    """
    text = SCHEMA.read_text(encoding="utf-8")
    match = re.search(r"owning_team\s+text CHECK \(owning_team IN\s*\((.*?)\)\)",
                      text, re.S)
    assert match, "the owning_team constraint has moved; this test cannot verify it"
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


def test_every_mapped_team_is_one_the_schema_accepts():
    from modules.rise_ownership import TEAM_BY_PREFIX

    allowed = _allowed_teams()
    invalid = sorted({team for _, team in TEAM_BY_PREFIX} - allowed)
    assert not invalid, (
        "these owning teams are not in check_definition_owning_team_check and "
        "will be rejected by PostgreSQL the first time a finding with that "
        "prefix reaches the database: %s. Allowed: %s"
        % (invalid, sorted(allowed)))


def test_the_default_team_is_one_the_schema_accepts():
    """A default that the schema rejects fails on the first UNMAPPED prefix
    rather than on a named one, which is harder to trace back to this file."""
    import modules.rise_ownership as ownership

    allowed = _allowed_teams()
    for name in dir(ownership):
        if "DEFAULT" not in name.upper():
            continue
        value = getattr(ownership, name)
        if isinstance(value, str) and value.islower() and "_" in value or \
                (isinstance(value, str) and value in allowed):
            assert value in allowed, (
                "%s = %r is not a team the schema accepts" % (name, value))


def test_every_check_prefix_resolves_to_a_valid_team():
    """End to end through the function the ingest path actually calls, over every
    check id the product publishes — so a prefix that falls through to a default,
    or one the table orders wrongly, is caught with its id named."""
    from modules.coverage import all_check_ids
    from modules.rise_ownership import team_for

    allowed = _allowed_teams()
    bad = {}
    for check_id in sorted({c for ids in all_check_ids().values() for c in ids}):
        team = team_for(check_id)
        if team is not None and team not in allowed:
            bad[check_id] = team
    assert not bad, (
        "these published checks resolve to a team the schema rejects, so a scan "
        "producing any of them fails at insert: %s"
        % sorted(bad.items())[:8])


# ── the same question, asked of every vocabulary the database enforces ────────

def _enum_constraints() -> dict:
    """`{column: allowed values}` for every enum-style CHECK in the schema.

    Derived rather than listed for the same reason as `_allowed_teams`: a hand-
    written copy is a third thing to keep in step.
    """
    text = SCHEMA.read_text(encoding="utf-8")
    pattern = re.compile(r"(\w+)\s+text\s+CHECK\s*\(\s*\1\s+IN\s*\((.*?)\)\s*\)",
                         re.S)
    out = {}
    for match in pattern.finditer(text):
        values = set(re.findall(r"'([^']+)'", match.group(2)))
        # A one-or-two-letter capture is the regex meeting a CHECK that is not an
        # enum at all; a real column name here is always longer.
        if len(match.group(1)) > 2:
            out[match.group(1)] = values
    return out


def test_the_corpus_produces_no_value_the_database_would_reject():
    """The general form of the CSA- bug, asked of the data rather than the table.

    `owning_team` was wrong in a mapping; the next one could be wrong in a module
    that computes its value instead. This walks every finding the bundled corpus
    produces and checks each field the schema constrains — so a module whose
    vocabulary drifts fails here rather than at insert, in a CI job most local
    runs skip.
    """
    import contextlib
    import importlib
    import io

    sample = ROOT / "sample_data"
    if not sample.is_dir():
        import pytest
        pytest.skip("sample_data absent")

    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT

    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(sample).load_all()
        findings = []
        for module_name, class_name in AUDITORS:
            auditor = getattr(importlib.import_module(f"modules.{module_name}"),
                              class_name)
            findings += auditor(data, None, RUN_CONTEXT).run_all_checks() or []

    constraints = _enum_constraints()
    assert constraints, "no enum constraints found; the schema has moved"

    offenders = {}
    for finding in findings:
        details = finding.get("details") or {}
        for column, allowed in constraints.items():
            for source in (finding, details if isinstance(details, dict) else {}):
                value = source.get(column)
                if value is not None and str(value) not in allowed:
                    offenders.setdefault(column, set()).add(
                        (finding.get("check_id"), str(value)))
    assert not offenders, (
        "the corpus produces values PostgreSQL would reject: %s"
        % {k: sorted(v)[:4] for k, v in offenders.items()})
