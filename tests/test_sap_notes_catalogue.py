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
    """A store with no export behind it must still be named, or a note blocked
    only by it looks unanswerable in principle rather than for a reason somebody
    could fix.

    Two have graduated out of this table since it was written — SAP_KERNEL, then
    HDB_VERSION, each the largest remaining at the time — which is what the table
    is for: it names the next one worth building rather than leaving the gap
    implicit. The UI5, BusinessObjects, Unified Rendering and IGS stores remain,
    and each is worth a handful of notes rather than dozens.
    """
    meta = catalogue["_meta"]
    assert meta["config_store_unmapped"], "nothing is declared unmapped"
    assert "SAPUI5_VERSION" in meta["config_store_unmapped"]
    assert meta["counts"]["blocked_only_by_an_unmapped_store"] > 0
    for graduated in ("SAP_KERNEL", "HDB_VERSION"):
        assert graduated in meta["config_store_sources"]
        assert graduated not in meta["config_store_unmapped"]


def test_the_kernel_export_is_worth_far_more_than_the_old_measurement(catalogue):
    """It was measured against the 43-note catalogue as unlocking one note and
    left unbuilt on that basis. The number was right; the denominator was not.
    Now that it is mapped, the evidence of its worth is how many notes name it."""
    from modules.data_loader import DataLoader
    assert "sap_kernel" in DataLoader.FILE_MAP
    named = [n for n, r in catalogue["notes"].items()
             if "SAP_KERNEL" in r["config_stores"]]
    assert len(named) > 50, len(named)
    assert all("sap_kernel" in catalogue["notes"][n]["answerable_from"]
               for n in named)


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
    assert "APPLICABILITY COULD NOT SETTLE" in finding["description"]
    # And it has to say how many it DID settle, or a reader cannot tell whether
    # a short list means a healthy system or an absent component export.
    assert finding["details"]["settled_by_component_evidence"] > 0


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


# ═════════════════════════════════════════════════════════════════════════════
#  HOTNEWS-013 — the applicability engine, which is the point of all of it
# ═════════════════════════════════════════════════════════════════════════════

#: Note 3550708 (CVE-2025-0066) is fixed in SAP_BASIS 755 at SP 10, per SAP's
#: own policy. A system at SP 4 is below it; a system at SP 12 is not.
_NOTE = "3550708"


def _with_components(rows):
    return {"system_component": rows,
            "applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}]}


def test_a_component_below_the_fix_level_is_a_determination_not_a_worklist(shop):
    """The whole reason the predicates were read. Every other check reports that
    a note is absent from an export; this reports that the software is older
    than the fix, from SAP's published level and the customer's own export."""
    finding = shop["HOTNEWS-013"]
    assert finding["details"]["applicability_determined"] is True
    assert finding["details"]["basis"] == "component_release_and_support_package"
    assert finding["severity"] == "CRITICAL"


def test_the_evidence_names_the_component_the_installed_sp_and_the_required_sp(shop):
    """A finding a Basis team can act on without opening anything else."""
    hit = [i for i in shop["HOTNEWS-013"]["affected_items"] if i.startswith(_NOTE)]
    assert hit, "the sample landscape's SAP_BASIS 755 SP 0004 should be below"
    assert "SAP_BASIS 755 is at SP 0004" in hit[0]
    assert "the fix is in SP 0010" in hit[0]


def test_a_component_above_the_fix_level_is_not_reported():
    fired = _run(_with_components([
        {"COMPONENT": "SAP_BASIS", "RELEASE": "755", "SP_LEVEL": "0012"}]))
    listed = {i.split(" ", 1)[0] for i in
              fired.get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _NOTE not in listed


def test_a_release_sap_does_not_mention_is_not_a_verdict_either_way():
    """SAP's list names the releases it knows. An installed release outside it
    is unknown, not safe — and unknown belongs in HOTNEWS-012, not here."""
    fired = _run(_with_components([
        {"COMPONENT": "SAP_BASIS", "RELEASE": "999", "SP_LEVEL": "0001"}]))
    listed = {i.split(" ", 1)[0] for i in
              fired.get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _NOTE not in listed


def test_an_unreadable_support_package_is_dropped_rather_than_read_as_zero():
    """Defaulting an unparseable cell to 0 would put it below every fix level
    SAP publishes and turn a broken export into a page of critical findings."""
    fired = _run(_with_components([
        {"COMPONENT": "SAP_BASIS", "RELEASE": "755", "SP_LEVEL": "n/a"}]))
    assert "HOTNEWS-013" not in fired


def test_a_note_already_implemented_is_never_reported_below_its_fix_level():
    """A note whose correction was applied through SNOTE closes the finding even
    though the component version has not moved. Reporting a patched system as
    unpatched is the loudest false positive this check could produce."""
    rows = [{"COMPONENT": "SAP_BASIS", "RELEASE": "755", "SP_LEVEL": "0004"}]
    before = _run({"system_component": rows,
                   "applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}]})
    assert _NOTE in {i.split(" ", 1)[0] for i in before["HOTNEWS-013"]["affected_items"]}
    after = _run({"system_component": rows,
                  "applied_notes": [{"NOTE": _NOTE, "STATUS": "Completely implemented"}]})
    assert _NOTE not in {i.split(" ", 1)[0]
                         for i in after.get("HOTNEWS-013", {}).get("affected_items", [])}


def test_with_no_component_export_nothing_is_determined():
    """The engine needs the customer's half of the evidence. Without it the
    module falls back to the worklist and must not invent a verdict."""
    fired = _run({"applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}]})
    assert "HOTNEWS-013" not in fired
    assert "HOTNEWS-012" in fired
    assert fired["HOTNEWS-012"]["details"]["settled_by_component_evidence"] == 0


def test_the_two_checks_do_not_report_the_same_note(shop):
    """HOTNEWS-013 is strictly stronger where it applies. Repeating a note in
    the worklist would make the determination look like a duplicate."""
    thirteen = {i.split(" ", 1)[0] for i in shop["HOTNEWS-013"]["affected_items"]}
    twelve = {i.split(" ", 1)[0] for i in shop["HOTNEWS-012"]["affected_items"]}
    assert not (thirteen & twelve)


def test_the_fix_levels_are_sap_s_and_the_arithmetic_is_ours(catalogue):
    """The line that moved, pinned. What is stored is a component, a release and
    a support-package number — facts. No SQL, no operator, no expression."""
    record = catalogue["notes"][_NOTE]
    assert record["fix_levels"], "the fix levels went missing"
    for row in record["fix_levels"]:
        assert set(row) == {"component", "release", "min_sp"}
        assert isinstance(row["min_sp"], int)


def test_uninterpreted_ranges_are_counted_rather_than_silently_skipped(catalogue):
    """SAP expresses some affected sets as `between SP A and SP B`, which needs
    reasoning this product does not do. Skipping them is right; hiding how many
    were skipped is not."""
    assert catalogue["_meta"]["counts"][
        "check_items_using_an_uninterpreted_range"] > 0


# ═════════════════════════════════════════════════════════════════════════════
#  HDB_VERSION — the database half of the applicability engine
# ═════════════════════════════════════════════════════════════════════════════

#: Note 2424173 is fixed in HANA 1.00.122.07 and 2.00.001.0, per SAP's own policy.
_HANA_NOTE = "2424173"


def _hana(revision, applied="1"):
    data = {"applied_notes": [{"NOTE": applied, "STATUS": "Completely implemented"}]}
    if revision is not None:
        data["hana_version"] = [{"NAME": "VERSION", "VALUE": revision}]
    return _run(data)


def test_a_revision_below_the_fix_is_a_determination():
    """The point of mapping HDB_VERSION. A HANA note carries no component fix
    levels, so before this it could only ever be reported as unassessed."""
    fired = _hana("1.00.122.00")
    listed = {i.split(" ", 1)[0] for i in fired["HOTNEWS-013"]["affected_items"]}
    assert _HANA_NOTE in listed


def test_the_evidence_names_the_installed_revision_and_the_required_one():
    hit = [i for i in _hana("1.00.122.00")["HOTNEWS-013"]["affected_items"]
           if i.startswith(_HANA_NOTE)]
    assert hit
    assert "HANA is at revision 1.00.122.00" in hit[0]
    assert "the fix is in 1.00.122.07" in hit[0]


def test_a_revision_above_the_fix_is_not_reported():
    listed = {i.split(" ", 1)[0] for i in
              _hana("1.00.122.30").get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _HANA_NOTE not in listed


def test_the_comparison_is_numeric_not_lexicographic():
    """SAP's predicate compares a truncated version STRING, which works only
    because HANA zero-pads its segments. Borrowing that would make the answer
    depend on padding this product does not control: as strings, "1.00.122.9" is
    greater than "1.00.122.07" and also greater than "1.00.122.30"."""
    from modules.sap_hotnews import SapHotNewsAuditor as H
    assert H._revision_tuple("1.00.122.9") == (1, 0, 122, 9)
    assert H._revision_tuple("1.00.122.30") > H._revision_tuple("1.00.122.9")
    assert H._revision_tuple("2.00.073.00.1745") > H._revision_tuple("2.00.001.0")


def test_a_branch_sap_does_not_mention_is_unknown_not_safe():
    """SAP lists the branches it knows. An installed branch outside that list is
    undetermined, and undetermined belongs in HOTNEWS-012, never in silence."""
    listed = {i.split(" ", 1)[0] for i in
              _hana("9.99.999.00").get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _HANA_NOTE not in listed


def test_an_unreadable_revision_is_dropped_rather_than_ordered():
    """A revision this cannot parse must not be silently ordered against one it
    can — that is how an unreadable cell becomes a critical finding."""
    fired = _run({"applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}],
                  "hana_version": [{"NAME": "VERSION", "VALUE": "unknown"}]})
    listed = {i.split(" ", 1)[0] for i in
              fired.get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _HANA_NOTE not in listed


def test_a_note_already_implemented_is_not_reported_however_old_the_revision():
    listed = {i.split(" ", 1)[0] for i in
              _hana("1.00.122.00", applied=_HANA_NOTE)
              .get("HOTNEWS-013", {}).get("affected_items", [])}
    assert _HANA_NOTE not in listed


def test_the_bare_version_column_is_accepted_too():
    """`SELECT VERSION FROM M_DATABASE` gives a single column; SAP's own config
    store gives NAME/VALUE. Both are real exports and both must load."""
    fired = _run({"applied_notes": [{"NOTE": "1", "STATUS": "Completely implemented"}],
                  "hana_version": [{"VERSION": "1.00.122.00"}]})
    listed = {i.split(" ", 1)[0] for i in fired["HOTNEWS-013"]["affected_items"]}
    assert _HANA_NOTE in listed


def test_the_store_is_mapped_and_the_source_exists(catalogue):
    from modules.data_loader import DataLoader
    assert "hana_version" in DataLoader.FILE_MAP
    assert catalogue["_meta"]["config_store_sources"]["HDB_VERSION"] == "hana_version"
    assert "HDB_VERSION" not in catalogue["_meta"]["config_store_unmapped"]
    assert catalogue["_meta"]["counts"]["with_hana_fix_levels"] > 20


def test_a_malformed_check_item_id_is_counted_rather_than_repaired(catalogue):
    """SAP's own files carry `id="00022704878"` — note 2704878 with a stray zero
    — which names no note any header declared. Guessing which note was meant is
    the inference this catalogue exists to avoid, so it is counted and dropped:
    one note loses its fix levels and the number is visible."""
    assert catalogue["_meta"]["counts"]["check_items_with_an_unattributable_id"] > 0
    assert "22704878" not in catalogue["notes"]
    assert "2704878" in catalogue["notes"]
