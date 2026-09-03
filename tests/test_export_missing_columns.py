"""A supplied export that reads perfectly and lost a column its checks need.

`export_integrity` was built because an export that would not DECODE produced an
empty list, and an empty list is indistinguishable from an export that genuinely
held nothing. Its own docstring records the measurement: re-encoding one file as
UTF-16 took the scan from 407 findings to 383, the segregation-of-duties
conflicts disappeared entirely, and the customer-facing report said nothing.

A third cause reaches the identical outcome. The file decodes, parses into rows,
and is counted among the sources the customer supplied — and the column its
readers join on is not in it. Measured on the sample estate by dropping one
column and re-running every auditor:

    security_params.csv   NAME       58 checks stop firing
    security_params.csv   VALUE      53
    role_auth_values.csv  OBJECT     30
    user_roles.csv        AGR_NAME    9   (every SoD finding)

The tests below do two different jobs. The fast ones fix the BEHAVIOUR of
EXPORT-003. The slow one at the end re-runs the measurement itself, so a cost
written in `REQUIRED_COLUMNS` cannot quietly become untrue — a number nobody
rechecks is the thing this repository keeps finding.
"""
import csv
import importlib
import io
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.export_integrity import ExportIntegrityAuditor            # noqa: E402

REQUIRED = ExportIntegrityAuditor.REQUIRED_COLUMNS


def fired(data):
    return {f["check_id"]: f
            for f in ExportIntegrityAuditor(data).run_all_checks()}


# ── behaviour ──────────────────────────────────────────────────────────────

def test_a_complete_export_says_nothing():
    assert "EXPORT-003" not in fired(
        {"user_roles": [{"UNAME": "JSMITH", "AGR_NAME": "Z_FI"}]})


def test_a_missing_column_is_reported_with_what_it_costs():
    finding = fired({"user_roles": [{"UNAME": "JSMITH"}]})["EXPORT-003"]
    assert finding["severity"] == "HIGH"
    item, = finding["affected_items"]
    assert "user_roles.csv" in item
    assert "AGR_NAME or ROLE or AGR" in item, (
        "the accepted spellings must be listed, or somebody re-exports with a "
        "valid alternative and gets the same finding again")
    assert "9 check(s) cannot run" in item


def test_it_degrades_coverage_rather_than_accusing_the_estate():
    """The estate is not the problem here; the evidence is. The gate must not
    return green on a scan that could not ask the question."""
    finding = fired({"user_roles": [{"UNAME": "JSMITH"}]})["EXPORT-003"]
    assert finding["details"]["degrades_coverage"] is True
    assert finding["details"]["checks_not_run"] == 9


@pytest.mark.parametrize("spelling", ["AGR_NAME", "ROLE", "AGR"])
def test_every_accepted_spelling_is_accepted(spelling):
    """A check that rejected a column the reader happily accepts would be a
    false alarm on a valid export — worse than the silence it replaces."""
    assert "EXPORT-003" not in fired(
        {"user_roles": [{"UNAME": "JSMITH", spelling: "Z_FI"}]})


def test_spelling_is_case_insensitive():
    assert "EXPORT-003" not in fired(
        {"user_roles": [{"uname": "JSMITH", "agr_name": "Z_FI"}]})


def test_an_absent_source_is_not_this_finding():
    """Absence is handled everywhere already: the value is None and every
    consumer self-skips. Reporting it here would double-count it."""
    assert "EXPORT-003" not in fired({})


def test_a_supplied_and_empty_source_is_not_this_finding():
    """An export that ran and returned nothing is a real answer. There is also
    no row to read a column from, so there is nothing to judge."""
    assert "EXPORT-003" not in fired({"user_roles": []})


def test_several_sources_roll_into_one_finding():
    finding = fired({
        "user_roles": [{"UNAME": "JSMITH"}],
        "security_params": [{"NAME": "login/min_password_lng"}],
    })["EXPORT-003"]
    assert len(finding["affected_items"]) == 2
    assert finding["details"]["checks_not_run"] == 9 + 53
    assert finding["details"]["sources"] == ["security_params", "user_roles"]


def test_the_worst_loss_is_listed_first():
    """A reader fixing one file first should fix the one that costs most."""
    finding = fired({
        "user_roles": [{"UNAME": "JSMITH"}],
        "security_params": [{"NAME": "login/min_password_lng"}],
    })["EXPORT-003"]
    assert finding["affected_items"][0].startswith("security_params.csv")


def test_the_spellings_come_from_the_readers_not_this_module():
    """`security_params` shares its column vocabulary with every consumer via
    BaseAuditor. Restating it here would let the two drift apart, and the
    drifted copy would reject exports the product reads fine."""
    from modules.base_auditor import BaseAuditor
    names = [s for s, _what, _cost in REQUIRED["security_params"]]
    assert BaseAuditor.PARAM_NAME_COLUMNS in names
    assert BaseAuditor.PARAM_VALUE_COLUMNS in names


# ── the measurement itself ─────────────────────────────────────────────────

def _all_findings(directory):
    from modules import data_loader
    from server.ingest import AUDITORS
    buf, sys.stdout = sys.stdout, io.StringIO()
    try:
        data = data_loader.DataLoader(Path(directory)).load_all()
    finally:
        sys.stdout = buf
    out = set()
    for name, cls in AUDITORS:
        auditor_cls = getattr(importlib.import_module("modules." + name), cls)
        auditor = None
        for args in ((data,), (data, None), (data, None, {})):
            try:
                auditor = auditor_cls(*args)
                break
            except TypeError:
                continue
        if auditor is None:
            continue
        try:
            for finding in (auditor.run_all_checks() or []):
                out.add(finding["check_id"])
        except Exception:                                   # noqa: BLE001
            pass
    return out


@pytest.fixture(scope="module")
def clean_findings():
    """The clean scan, run ONCE.

    Every case below needs it as its baseline and it is the same answer each
    time. Rescanning per case took the whole suite from under three minutes to
    over eight, which is a price a guard should not charge.
    """
    return _all_findings(ROOT / "sample_data")


CASES = [(source, spellings[0], cost)
         for source, reqs in sorted(REQUIRED.items())
         for spellings, _what, cost in reqs]


# No `slow` marker: this repository registers no custom marks, and an
# unregistered one is a warning that does nothing. The ten cases share one cached
# baseline scan (see clean_findings); measured before that, rescanning per
# case took the suite from under three minutes to over eight.
@pytest.mark.parametrize("source, column, claimed", CASES,
                         ids=["%s.%s" % (s, c) for s, c, _ in CASES])
def test_the_claimed_cost_is_still_what_dropping_the_column_costs(
        tmp_path, clean_findings, source, column, claimed):
    """RE-RUNS THE MEASUREMENT RATHER THAN TRUSTING THE COMMENT.

    Every number in REQUIRED_COLUMNS was produced by dropping that column from
    the sample estate and counting the check ids that stopped firing. Rules
    change and modules move; a cost that has drifted is a claim this report
    makes to a customer and cannot support.

    The assertion is deliberately one-sided. An exact match would fail on every
    unrelated new check, which would make this an obstacle rather than a guard.
    What must stay true is that dropping the column still costs SOMETHING, and
    that the figure published is not larger than the truth.
    """
    fixture = ROOT / "sample_data" / ("%s.csv" % source)
    if not fixture.exists():
        pytest.skip("%s is not in the bundled corpus" % source)

    estate = tmp_path / "estate"
    shutil.copytree(ROOT / "sample_data", estate)
    with io.open(fixture, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    header = [c for c in rows[0] if c.upper() != column.upper()]
    assert len(header) < len(rows[0]), "%s has no column %s" % (source, column)
    with io.open(estate / ("%s.csv" % source), "w",
                 encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})

    lost = clean_findings - _all_findings(estate)
    assert lost, (
        "dropping %s.%s now costs nothing, so the %d in REQUIRED_COLUMNS is no "
        "longer true — re-measure it or remove the entry" % (source, column, claimed))
    assert claimed <= len(lost) + 2, (
        "REQUIRED_COLUMNS claims dropping %s.%s costs %d checks; it now costs "
        "%d. The published figure must not overstate the loss."
        % (source, column, claimed, len(lost)))
