# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""SAP's own note record, and the two checks that rest on it.

WHY THIS FILE EXISTS. The standing risk in the roadmap was "a fabricated SAP
identifier ships", and the mitigation was a hand-curated catalogue of 43 notes
carrying "as cited by [source]". SAP publishes the same facts as machine-readable
policies under Apache-2.0, so the structural fix is to stop typing note numbers
at all: `data/sap_notes_catalogue.json` is generated from
`SAP-samples/frun-csa-policies-best-practices` and holds 1,732 notes across 154
patch days.

WHAT THESE TESTS ARE ACTUALLY FOR. Not that the parser works — the generator's
`--strict` mode covers that in CI, against the real files. These test the three
things a generated data file can still get wrong once it is committed: that the
provenance travels with it, that the checks reading it stay honest about what
they cannot determine, and that the one place where two sources genuinely
disagree is REPORTED rather than silently resolved in favour of whichever was
read last.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CATALOGUE = ROOT / "data" / "sap_notes_catalogue.json"


@pytest.fixture(scope="module")
def catalogue():
    assert CATALOGUE.exists(), "the SAP notes catalogue is missing"
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


def _run(data):
    from modules.sap_hotnews import SapHotNewsAuditor
    with contextlib.redirect_stdout(io.StringIO()):
        return {f["check_id"]: f for f in SapHotNewsAuditor(data, {}).run_all_checks()}


@pytest.fixture(scope="module")
def shop():
    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    return _run(data)


# ═════════════════════════════════════════════════════════════════════════════
#  Provenance — an Apache-2.0 derived work has to carry its notice
# ═════════════════════════════════════════════════════════════════════════════

def test_the_notice_travels_with_the_data_not_only_with_the_repo(catalogue):
    """Apache-2.0 §4(c). The file is extracted, mailed and vendored downstream;
    a notice that lives only in THIRD_PARTY_NOTICES.md does not travel with it."""
    meta = catalogue["_meta"]
    assert meta["source"] == "SAP-samples/frun-csa-policies-best-practices"
    assert "Apache-2.0" in meta["licence"]
    assert "SAP SE" in meta["licence"]


def test_it_says_what_was_not_taken(catalogue):
    """The distinction the whole adoption rests on. SAP's SQL runs against
    Focused Run's configuration database; reproducing it would claim a parity
    this product does not have."""
    text = catalogue["_meta"]["what_this_is_not"]
    assert "SQL" in text and "not" in text.lower()


def test_no_sql_predicate_was_copied_into_the_catalogue(catalogue):
    """The claim above, enforced rather than asserted. SAP's predicates are SQL
    fragments — if one had been carried across, it would be visible as SQL."""
    blob = json.dumps(catalogue)
    for fragment in ("noncompliant", "lpad(", " and NAME =", "joinstore"):
        assert fragment not in blob, "an SAP SQL predicate reached the catalogue"


def test_the_third_party_notice_names_this_file():
    notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "sap_notes_catalogue.json" in notice
    assert "tools/build_sap_notes_catalogue.py" in notice


# ═════════════════════════════════════════════════════════════════════════════
#  The data itself
# ═════════════════════════════════════════════════════════════════════════════

def test_it_holds_more_than_the_hand_curated_catalogue_by_two_orders(catalogue):
    from modules.sap_hotnews import SapHotNewsAuditor
    assert len(catalogue["notes"]) > 1500
    assert len(catalogue["notes"]) > 30 * len(SapHotNewsAuditor.HOTNEWS_CATALOG)


@pytest.mark.parametrize("note,cve", [
    ("3747367", "CVE-2026-44747"),   # the note that needed Launchpad confirmation
    ("3089831", "CVE-2021-38176"),
    ("3084487", "CVE-2021-38163"),   # CISA KEV
    ("2934135", "CVE-2020-6287"),    # RECON
])
def test_note_to_cve_bindings_match_what_was_derived_from_nvd(catalogue, note, cve):
    """Four bindings were established independently from NVD earlier in this
    project's history. SAP's published policies agree with all four, which is
    what makes the catalogue worth trusting for the other 1,728."""
    assert cve in catalogue["notes"][note]["cve"]


def test_every_note_number_looks_like_one(catalogue):
    """A parser that mis-read a header could invent a note number, which is the
    exact failure this whole source exists to prevent."""
    bad = [n for n in catalogue["notes"] if not (n.isdigit() and 6 <= len(n) <= 10)]
    assert not bad, bad[:10]


def test_the_config_store_mapping_points_at_sources_the_loader_accepts(catalogue):
    """`answerable_from` tells a reader which export answers a note. A source
    name the loader does not know would send them to produce a file nothing
    reads."""
    from modules.data_loader import DataLoader
    named = {s for rec in catalogue["notes"].values()
             for s in rec["answerable_from"]}
    assert named, "nothing is mapped; the config-store table has stopped working"
    assert not (named - set(DataLoader.FILE_MAP))


def test_an_unmapped_store_is_recorded_rather_than_dropped(catalogue):
    """SAP_KERNEL has no export behind it yet. A note needing only that must
    still say so — silently reporting it as unanswerable would hide what the
    missing export costs."""
    meta = catalogue["_meta"]
    assert "SAP_KERNEL" in meta["config_store_unmapped"]
    assert meta["counts"]["blocked_only_by_an_unmapped_store"] > 0


def test_the_kernel_export_is_worth_far_more_than_the_old_measurement(catalogue):
    """It was measured against the 43-note catalogue as unlocking one note and
    left unhooked on that basis. The number was right; the denominator was not."""
    blocked = [n for n, r in catalogue["notes"].items()
               if "SAP_KERNEL" in r["needs_unmapped_store"]]
    assert len(blocked) > 20, len(blocked)


# ═════════════════════════════════════════════════════════════════════════════
#  HOTNEWS-011 — two sources, and no adjudication
# ═════════════════════════════════════════════════════════════════════════════

def test_the_self_audit_reports_the_difference_without_picking_a_side(shop):
    """The instinct — treat SAP's policy as authoritative and 'correct' the
    curated score — was checked against NVD and found wrong. For CVE-2021-38176
    NVD publishes 8.8 (S:U) and SAP as CNA publishes 9.9 (S:C); for
    CVE-2022-41204 SAP's policy header even differs from SAP's own CNA record.
    Neither is corrected, and the finding has to say so."""
    finding = shop["HOTNEWS-011"]
    assert finding["details"]["self_audit"] is True
    text = finding["description"].lower()
    assert "provenance" in text
    assert "neither number is corrected" in text
    assert any("neither is corrected here" in i for i in finding["affected_items"])


def test_a_cvss_difference_is_labelled_as_provenance_and_a_cve_difference_is_not(shop):
    """The two are different kinds of disagreement and must not read alike. Two
    publishers scoring one CVE differently is method; two sources naming
    different CVEs for one note is an error on somebody's part."""
    items = shop["HOTNEWS-011"]["affected_items"]
    cvss = [i for i in items if "CVSS provenance differs" in i]
    cve = [i for i in items if "this catalogue says CVE-" in i]
    assert cvss and cve, items
    assert not any("provenance" in i for i in cve)


def test_the_self_audit_is_low_because_it_is_not_about_the_scanned_system(shop):
    """It concerns the scanner's own data. Ranking it beside a missing HotNews
    note would push a real finding down the queue."""
    assert shop["HOTNEWS-011"]["severity"] == "LOW"


def test_the_self_audit_runs_even_with_no_applied_notes_export():
    """It is a statement about the catalogue, not about the estate, so the
    export nobody supplied has no bearing on it."""
    assert "HOTNEWS-011" in _run({"system_component": []})


# ═════════════════════════════════════════════════════════════════════════════
#  HOTNEWS-012 — breadth, with the limit stated
# ═════════════════════════════════════════════════════════════════════════════

def test_it_says_plainly_that_applicability_was_not_determined(shop):
    """SAP decides applicability by evaluating support-package predicates in SQL.
    Those were deliberately not imported, so this is a worklist. A finding that
    implied otherwise would have people chasing notes for components they do not
    have, and stop trusting the ones that matter."""
    finding = shop["HOTNEWS-012"]
    assert finding["details"]["applicability_determined"] is False
    assert "WORKLIST, NOT A VERDICT" in finding["description"]


def test_its_scope_is_sap_s_own_tiering_not_ours(shop):
    """Priority 1 in SAP's tiering, carrying a CVE, inside the set SAP's own
    policies declare checkable. Choosing the scope ourselves would put us back
    to curating, which is the practice being retired."""
    assert shop["HOTNEWS-012"]["details"]["scope"] == (
        "sap_priority_1_with_cve_and_sap_checkable")


def test_curated_notes_are_not_reported_twice(shop, catalogue):
    """HOTNEWS-001 and -003 report those with exploitation context and
    applicability. Repeating them here would make the more precise finding look
    like a duplicate of the vaguer one."""
    from modules.sap_hotnews import SapHotNewsAuditor as H
    curated = {str(e["note"]).lstrip("0") for e in H.HOTNEWS_CATALOG}
    listed = {i.split(" ", 1)[0] for i in shop["HOTNEWS-012"]["affected_items"]}
    assert not (listed & curated)


def test_a_note_already_in_the_export_drops_out():
    """The check has to answer to the export, or it is a static list."""
    before = _run({"applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}]})
    listed = {i.split(" ", 1)[0] for i in before["HOTNEWS-012"]["affected_items"]}
    victim = sorted(listed)[0]
    after = _run({"applied_notes": [
        {"NOTE": victim, "STATUS": "Completely implemented"}]})
    still = {i.split(" ", 1)[0] for i in after["HOTNEWS-012"]["affected_items"]}
    assert victim not in still


def test_both_checks_go_quiet_if_the_catalogue_cannot_be_read(monkeypatch):
    """A missing data file must degrade breadth and nothing else. The curated
    catalogue is self-contained, so every other check still has to run."""
    from modules.sap_hotnews import SapHotNewsAuditor
    monkeypatch.setattr(SapHotNewsAuditor, "SAP_CATALOGUE_PATH",
                        ROOT / "data" / "does-not-exist.json")
    fired = _run({"applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}]})
    assert "HOTNEWS-011" not in fired and "HOTNEWS-012" not in fired
    assert "HOTNEWS-001" in fired, "the rest of the module stopped working too"
