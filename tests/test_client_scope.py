# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

""""Compliant in the clients we saw" must never render as "compliant".

WHAT WAS WRONG. `system_trust.check_default_passwords` read `standard_users`,
collected offenders and RETURNED IN SILENCE when it found none. The check is
cross-client by nature — SAP*/DDIC default passwords in every client, TMSADM only
in 000, client 066 removal — so an export covering only the productive client
produced no finding, and the reader concluded that no standard user anywhere has
a default password when the two clients most likely to (000, 001) were never read.

`data/rise_reachability.json` had already classified `standard_users` as `partial`
and said in as many words that "a check reading it must say so". Nothing did.

Section 3.1 of the RISE model states the cost: "Silently passing a cross-client
check on partial data is a defect an auditor can catch, and it is the kind that
ends an engagement."
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import client_scope                              # noqa: E402
from modules.system_trust import SystemTrustAuditor           # noqa: E402


def _su(*pairs):
    return [{"USER": u, "CLIENT": c, "DEFAULT_PASSWORD": d, "LOCKED": "X"}
            for u, c, d in pairs]


def _t000(*clients):
    return [{"CLIENT": c, "ROLE": "PRODUCTION"} for c in clients]


def _run(**data):
    return SystemTrustAuditor(data, {}, {}).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


def _one(findings, cid):
    hits = [f for f in findings if f["check_id"] == cid]
    assert hits, f"{cid} not raised; got {sorted(_ids(findings))}"
    return hits[0]


# ═════════════════════════════════════════════════════════════════════════════
#  The silent pass
# ═════════════════════════════════════════════════════════════════════════════

def test_a_clean_result_over_one_client_does_not_read_as_a_clean_system():
    """THE DEFECT. No offenders in client 100, and clients 000 and 001 never
    looked at. Before this, the scan said nothing at all."""
    findings = _run(standard_users=_su(("SAP*", "100", "")),
                    client_settings=_t000("000", "001", "100"))
    assert "STDUSR-002" not in _ids(findings)          # genuinely no offenders
    cov = _one(findings, "STDUSR-COV-001")             # but the gap is stated
    assert cov["details"]["clients_unexamined"] == ["000", "001"]
    assert cov["details"]["degrades_coverage"] is True


def test_a_finding_carries_the_clients_it_was_computed_over():
    """The mirror failure: offenders listed from one client while the finding
    reads as a statement about the system. It understates instead of overstating
    and the reader cannot tell which they hold."""
    f = _one(_run(standard_users=_su(("SAP*", "100", "X")),
                  client_settings=_t000("000", "100")), "STDUSR-002")
    assert "Assessed in client(s) 100 only" in f["description"]
    assert "000" in f["description"].split("Assessed in client(s)")[1]


def test_full_coverage_adds_no_caveat_and_no_finding():
    """A caveat on a complete scope is noise, and noise is how a real caveat gets
    skipped."""
    findings = _run(standard_users=_su(("SAP*", "000", ""), ("SAP*", "100", "")),
                    client_settings=_t000("000", "100"))
    assert "STDUSR-COV-001" not in _ids(findings)


def test_the_caveat_names_why_an_uncovered_standard_client_matters():
    """"Client 000 not covered" is a fact. Why it matters is what makes a reader
    go and get it."""
    cov = _one(_run(standard_users=_su(("SAP*", "100", "")),
                    client_settings=_t000("000", "100")), "STDUSR-COV-001")
    assert "TMSADM" in cov["description"]


def test_no_standard_user_export_raises_no_scope_finding():
    """The absent-source path belongs to the coverage manifest. Two findings for
    one absence is one too many."""
    assert "STDUSR-COV-001" not in _ids(_run(client_settings=_t000("000", "100")))


# ═════════════════════════════════════════════════════════════════════════════
#  Where the expected scope comes from
# ═════════════════════════════════════════════════════════════════════════════

def test_t000_is_the_measurement_and_the_basis_says_so():
    """A scope measured against the client list and one assumed from SAP's
    well-known clients are different strengths of claim."""
    scope = client_scope.scope_for(
        {"standard_users": _su(("SAP*", "100", "")),
         "client_settings": _t000("000", "100", "200")}, "standard_users")
    assert scope["unexamined"] == ["000", "200"]
    assert "T000" in scope["basis"]


def test_a_declared_scope_stands_in_where_t000_was_not_supplied():
    scope = client_scope.scope_for(
        {"standard_users": _su(("SAP*", "100", "")),
         "_client_scope": "000, 100, 200"}, "standard_users")
    assert scope["unexamined"] == ["000", "200"]
    assert "declared" in scope["basis"]


def test_t000_beats_a_declaration_when_both_are_present():
    """Measured beats asserted, always. A declaration that disagreed with the
    system's own client list would otherwise silently win."""
    scope = client_scope.scope_for(
        {"standard_users": _su(("SAP*", "100", "")),
         "client_settings": _t000("000", "100"),
         "_client_scope": "100"}, "standard_users")
    assert scope["unexamined"] == ["000"]
    assert "T000" in scope["basis"]


def test_with_neither_the_well_known_clients_are_the_floor_and_it_says_so():
    """A weaker claim than the T000 comparison, and the only one available.
    Making no claim would restore the silence this module exists to end."""
    scope = client_scope.scope_for(
        {"standard_users": _su(("SAP*", "100", ""))}, "standard_users")
    assert scope["unexamined"] == ["000", "001", "066"]
    assert "floor rather than a measurement" in scope["basis"]


def test_a_client_evidenced_but_absent_from_t000_is_not_a_gap():
    """T000 exports are sometimes filtered, and 001/066 legitimately appear in an
    RSUSR003 run that T000 did not list. The question is only what we did NOT
    look at — reporting the reverse would invent a finding out of an export
    filter."""
    scope = client_scope.scope_for(
        {"standard_users": _su(("SAP*", "000", ""), ("SAP*", "066", "")),
         "client_settings": _t000("000")}, "standard_users")
    assert scope["unexamined"] == []
    assert scope["complete"] is True


# ═════════════════════════════════════════════════════════════════════════════
#  Client numbers
# ═════════════════════════════════════════════════════════════════════════════

def test_leading_zeros_do_not_manufacture_an_uncovered_client():
    """T000 and an RSUSR003 export do not always agree about padding. A scope
    computed by set difference would report client 001 as unexamined because one
    file wrote `1`."""
    scope = client_scope.scope_for(
        {"standard_users": [{"CLIENT": "1"}], "client_settings": [{"CLIENT": "001"}]},
        "standard_users")
    assert scope["unexamined"] == []


@pytest.mark.parametrize("column", ["CLIENT", "MANDT", "CLNT", "CLIENT_ID"])
def test_the_client_column_is_matched_through_its_aliases(column):
    assert client_scope.clients_in([{column: "100"}]) == {"100"}


def test_a_declaration_accepts_commas_or_spaces():
    """An operator typing --clients 000,100 should not have to think about it."""
    for raw in ("000,100", "000 100", "000, 100", ["000", "100"]):
        assert client_scope.declared_clients({"_client_scope": raw}) == {"000", "100"}


def test_an_absent_client_list_is_none_rather_than_empty():
    """None means unknown; an empty set would mean T000 was read and named
    nobody, which is not something a running system can do."""
    assert client_scope.client_inventory({}) is None
    assert client_scope.client_inventory({"client_settings": []}) is None
    assert client_scope.declared_clients({}) is None


# ═════════════════════════════════════════════════════════════════════════════
#  One definition of a standard client
# ═════════════════════════════════════════════════════════════════════════════

def test_the_auditor_and_the_scope_checker_share_the_standard_client_set():
    """Two copies of "is this a standard client" is how they come to disagree
    about which clients a cross-client check must cover."""
    assert SystemTrustAuditor.STANDARD_CLIENTS == set(client_scope.WELL_KNOWN_CLIENTS)


def test_each_well_known_client_records_why_it_matters():
    for client, reason in client_scope.WELL_KNOWN_CLIENTS.items():
        assert len(reason) > 40, client


# ═════════════════════════════════════════════════════════════════════════════
#  The manifest records a partial source even where no check speaks
# ═════════════════════════════════════════════════════════════════════════════

def test_a_supplied_partial_source_is_named_in_the_manifest():
    """Supplied is not the same as complete, and the reachability table promised
    this: "obtainable but incomplete or mixed-ownership"."""
    from modules.coverage import build_manifest
    m = build_manifest({"standard_users": _su(("SAP*", "100", ""))},
                       modules_run=[], deployment_mode="rise_pce")
    assert "standard_users" in m["supplied_partial"]
    assert m["counts"]["sources_supplied_partial"] >= 1
    assert "partial in RISE" in m["summary"]


def test_outside_rise_no_source_is_partial():
    from modules.coverage import build_manifest
    m = build_manifest({"standard_users": _su(("SAP*", "100", ""))},
                       modules_run=[], deployment_mode="on_prem")
    assert m["supplied_partial"] == []


def test_the_sample_corpus_shows_the_production_client_was_never_examined():
    """End to end, and the sample is the awkward case by accident: its
    standard-user export covers 000/001/066 while T000 lists 000/100/200/300, so
    the PRODUCTION client is the one nobody looked at."""
    import contextlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    scope = client_scope.scope_for(data, "standard_users")
    assert "100" in scope["unexamined"]
    assert scope["examined"] == ["000", "001", "066"]
    cov = _one(SystemTrustAuditor(data, {}, {}).run_all_checks(), "STDUSR-COV-001")
    assert "100" in " ".join(cov["affected_items"])
