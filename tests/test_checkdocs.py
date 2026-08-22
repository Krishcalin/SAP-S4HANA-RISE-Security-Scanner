"""Every check id and requirement id the console renders is now a LINK.

That is the point of the feature and it is also its whole risk. Before, an id
that resolved to nothing was grey text that resolved to nothing; now it is a
link, and a link that 404s is a worse experience than the dead text it replaced,
because it invites the click.

So the load-bearing tests here are the two that walk the ids the SCREENS
actually render and require every one of them to resolve. A test that checked a
handful of ids by hand would prove the endpoint works and say nothing about
whether the console can produce a link it cannot follow.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import checkdocs  # noqa: E402


# ── no dead links ────────────────────────────────────────────────────────────

def test_every_published_check_id_resolves():
    """The coverage screen and the path screens render ids straight from the
    catalogue. Every one of them must open a page."""
    index = checkdocs.catalogue_index()
    assert len(index) > 600, f"catalogue collapsed to {len(index)} ids"
    missing = [e["check_id"] for e in index if checkdocs.check(e["check_id"]) is None]
    assert not missing, f"catalogue ids that do not resolve: {missing[:10]}"


def test_every_check_a_risk_path_cites_resolves():
    """Path templates cite checks by id, and PathDetail now renders each hop's
    checks as links. A template citing an id the catalogue does not publish would
    put a dead link on the busiest screen in the product.

    NOTE this is deliberately weaker than `test_required_hops_cite_checks_the_
    scanner_can_actually_emit` in test_graph_paths.py, which asks whether a check
    FIRES on sample_data. This asks only whether it EXISTS, because an optional
    hop may legitimately cite a check no fixture triggers — and that check still
    needs a page.
    """
    import json
    paths = json.loads((ROOT / "data" / "attack_paths.json").read_text(encoding="utf-8"))
    cited = {c for p in paths["paths"] for h in p["hops"] for c in h.get("checks", [])}
    assert cited, "no template cites any check"
    unknown = sorted(c for c in cited if not checkdocs.known_check(c))
    assert not unknown, (
        f"risk-path templates cite check ids the catalogue does not publish, so "
        f"PathDetail would render a dead link for each: {unknown}")


def test_every_requirement_the_coverage_screen_shows_resolves():
    """Coverage renders both `covered` and `not_covered` requirement ids, and both
    are now links. The not-covered half is the easy one to forget: it is rendered
    from SAP's catalogue rather than from ours."""
    from modules.coverage import module_check_ids
    from server import sapcontent
    ids = sorted({c for v in module_check_ids().values() for c in v})
    cov = sapcontent.coverage(ids, sapcontent.load_catalogue())
    shown = [r["requirement"] for r in cov["covered"]] + \
            [r["requirement"] for r in cov["not_covered"]]
    assert shown, "the coverage screen shows no requirements at all"
    missing = [r for r in shown if checkdocs.requirement(r) is None]
    assert not missing, f"requirement ids on screen that do not resolve: {missing}"


def test_every_check_a_requirement_claims_resolves():
    """The requirement page lists `our_checks` as links, in both directions of the
    mapping. A one-way mapping would put dead links on the page that exists to
    show the mapping."""
    from modules.coverage import module_check_ids
    from server import sapcontent
    ids = sorted({c for v in module_check_ids().values() for c in v})
    cov = sapcontent.coverage(ids, sapcontent.load_catalogue())
    for row in cov["covered"]:
        doc = checkdocs.requirement(row["requirement"])
        assert doc is not None
        bad = [c for c in doc["our_checks"] if not checkdocs.known_check(c)]
        assert not bad, f"{row['requirement']} claims unknown checks: {bad}"


# ── the honest gap ───────────────────────────────────────────────────────────

def test_an_undocumented_check_still_resolves():
    """154 of the 714 ids have no narrative from any source. They are REAL checks
    that run like any other; only the prose is missing.

    404-ing them would be the wrong answer to "what is this?" — we know the
    category, the module, the exports it reads and the requirement it answers.
    `documented: False` lets the screen say which part is missing instead of
    implying the check is."""
    index = checkdocs.catalogue_index()
    undocumented = [e["check_id"] for e in index if not e["documented"]]
    assert undocumented, "expected some ids to have no narrative yet"
    doc = checkdocs.check(undocumented[0])
    assert doc is not None
    assert doc["documented"] is False
    assert doc["risk"] is None and doc["mitigation"] is None
    # Everything that is known is still there.
    assert doc["category"]


def test_documented_checks_carry_both_halves():
    """A risk narrative with no remediation is half an answer, and the screen
    renders two headings regardless."""
    index = checkdocs.catalogue_index()
    documented = [e["check_id"] for e in index if e["documented"]]
    assert len(documented) > 300
    thin = [c for c in documented
            if not (checkdocs.check(c)["risk"] and checkdocs.check(c)["mitigation"])]
    assert not thin, f"documented checks missing risk or mitigation: {thin[:10]}"


# ── unknown ids are refused, not answered ────────────────────────────────────

@pytest.mark.parametrize("bad", ["NOPE-999", "", "../etc/passwd", "LOG-AUD-9999"])
def test_an_unknown_check_is_none_rather_than_an_empty_shell(bad):
    assert checkdocs.check(bad) is None
    assert checkdocs.known_check(bad) is False


def test_an_unknown_requirement_is_none(bad="NOT-A-REQUIREMENT"):
    assert checkdocs.requirement(bad) is None


# ── the mapping agrees with the screen that counts it ────────────────────────

def test_the_check_page_names_the_same_requirement_the_coverage_page_counts():
    """Two mappings would eventually disagree, and the page would quietly
    contradict the number beside it."""
    from server import sapcontent
    for cid in ("LOG-AUD-001", "HANADB-AUDIT-001"):
        doc = checkdocs.check(cid)
        expected = sapcontent.requirement_for(cid)
        named = [r["requirement"] for r in doc["requirements"]]
        if expected:
            assert named == [expected], f"{cid}: {named} != {[expected]}"
        else:
            assert named == []


def test_a_cut_check_says_so():
    """The most actionable sentence the check page can produce. INTG-GW-001 is a
    cut on the gateway path; if it stops being one, the banner must stop too."""
    doc = checkdocs.check("INTG-GW-001")
    assert doc is not None
    cuts = [p for p in doc["paths"] if p["is_cut"]]
    assert cuts, "INTG-GW-001 is a cut on SAPPATH-04 and SAPPATH-13"
    assert {p["template_id"] for p in cuts} >= {"SAPPATH-04", "SAPPATH-13"}


# ── the choke-point worklist endpoint ────────────────────────────────────────

def test_the_chokepoint_limit_is_clamped_both_ways():
    """A caller-supplied limit reaches a SQL LIMIT. Zero returns an empty
    worklist that reads as "nothing to fix", and an unbounded one lets a query
    string decide how much of the graph to walk.

    Read off the source rather than exercised through HTTP: the clamp is two
    expressions and standing a database up to prove `max(1, min(n, 500))` would
    test psycopg.
    """
    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    body = src.split("def api_chokepoints")[1].split("\ndef ")[0]
    assert "max(1, min(limit, 500))" in body, \
        "the choke-point limit is no longer clamped"


def test_the_chokepoint_summary_is_counted_from_the_rows_returned():
    """Counts computed from anything other than the rows on screen can disagree
    with the table under them, and the reader has no way to tell which is right.

    `open_paths` is the deliberate exception and comes from the path summary:
    summing `paths_cut` would count every path with more than one cut repeatedly,
    and most paths have more than one.
    """
    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    body = src.split("def api_chokepoints")[1].split("\ndef ")[0]
    assert '"total": len(rows)' in body
    assert 'for r in rows if (r["paths_cut"] or 0) > 1' in body
    assert 'graph.path_summary(scope)' in body, \
        "open_paths must not be derived from the choke-point rows"
    assert 'sum(r["paths_cut"]' not in body, \
        "open_paths is being summed from paths_cut, which double-counts"


def test_the_worklist_says_when_it_was_capped():
    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    body = src.split("def api_chokepoints")[1].split("\ndef ")[0]
    assert '"truncated": len(rows) >= limit' in body, \
        "a capped list is indistinguishable from a complete one without this"


# ── prose the product already shipped, in corpora nothing was reading ────────
#
# 352 of the 714 published ids had no narrative, and `/checks/{id}` said so on
# every one. But 175 of those checks are GENERATED FROM RULE TABLES THAT ALREADY
# DESCRIBE THEM — a rule cannot match a pattern without saying what the pattern
# means. The prose existed; the only thing missing was a reader.
#
# The risk in reading it is overstatement, and that is what these tests are for:
# a rule's two sentences must not be presented as, or counted as, a written page.

def test_the_two_derived_tiers_close_most_of_the_gap():
    """Stated as a floor, not a number: adding a check should not fail this, and
    the count moving DOWN means a source stopped being read."""
    index = checkdocs.catalogue_index()
    derived = [e for e in index
               if e["doc_source"] in ("knowledge_base_family", "rule_definition")]
    assert len(derived) >= 190, (
        "only %d checks documented from the family entries and rule corpora; a "
        "source has stopped being read" % len(derived))
    undocumented = [e for e in index if not e["documented"]]
    assert len(undocumented) <= 160, (
        "%d checks undocumented; this went from 352 to 154 and should not "
        "climb back" % len(undocumented))


def test_a_derived_check_says_which_corpus_it_came_from():
    doc = checkdocs.check("WDISP-001")
    assert doc["documented"] is True
    assert doc["doc_source"] == "rule_definition"
    assert doc["doc_detail"], "a derived narrative with no stated origin"
    assert doc["risk"] and doc["mitigation"]


@pytest.mark.parametrize("check_id,corpus", [
    ("WDISP-001", "Web Dispatcher rule"),
    ("PARAM-abap/path_normalization", "profile-parameter rule"),
])
def test_each_corpus_is_actually_read(check_id, corpus):
    """One corpus silently failing to load would look like progress that had
    simply not happened — the checks would go back to undocumented and nothing
    would say why."""
    assert checkdocs.check(check_id)["doc_detail"] == corpus


def test_the_abap_corpus_is_read_even_though_a_family_narrative_outranks_it():
    """The ABAP rules no longer supply the narrative — the nineteen family
    entries are better prose and win. But the rule is still the only thing that
    can say which of a family's sixteen patterns this check matches, so it must
    still be loaded. If the corpus stopped loading, every ABAP check would keep
    its family narrative and quietly lose the specific line, which is a
    regression nothing else here would catch."""
    doc = checkdocs.check("ABAP-SQLI-001")
    assert doc["doc_source"] == "knowledge_base_family"
    assert "WHERE" in (doc["doc_specific"] or ""), doc["doc_specific"]


def test_a_profile_parameter_is_described_by_its_own_rule():
    doc = checkdocs.check("PARAM-abap/path_normalization")
    assert doc["doc_source"] == "rule_definition"
    assert "normalis" in (doc["risk"] or "").lower()


def test_the_knowledge_base_wins_where_both_exist():
    """A hand-written entry is longer, names the transactions and reports, and
    was written for a reader rather than for a matcher. A derived entry must
    never displace one."""
    doc = checkdocs.check("LOG-AUD-001")
    assert doc["doc_source"] == "knowledge_base"
    assert doc["doc_detail"] is None


def test_the_three_sources_are_counted_separately():
    """The load-bearing one. Reporting all three under a single `documented`
    flag would let a reader conclude the written knowledge base is 560 entries
    when the part written for a specific check is 362 — the overstatement this
    whole module exists to avoid."""
    index = checkdocs.catalogue_index()
    sources = {e["doc_source"] for e in index}
    assert sources == {"knowledge_base", "knowledge_base_family",
                       "rule_definition", None}
    written = {e["check_id"] for e in index
               if e["doc_source"] == "knowledge_base"}
    assert written <= set(checkdocs._details()), (
        "the index claims a knowledge-base entry the file does not have")


def test_a_family_narrative_is_read_and_labelled_as_one():
    """Nineteen family entries covering 128 checks had never been rendered:
    `_details().get()` is an exact lookup and `ABAP-SQLI` is not a published id.
    Reading them must not blur into claiming somebody wrote about this rule."""
    doc = checkdocs.check("ABAP-SQLI-001")
    assert doc["doc_source"] == "knowledge_base_family"
    assert doc["doc_detail"] == "ABAP-SQLI"
    assert doc["risk"] and doc["mitigation"]
    # And the rule's own line survives beside it — the family cannot say which
    # of its sixteen patterns fired, and that is what a reader arriving from a
    # finding actually wants.
    assert doc["doc_specific"]
    assert doc["doc_specific"] != doc["risk"]


def test_a_family_prefix_cannot_claim_an_unrelated_check():
    """`ABAP-CD` must never reach `ABAP-CDS-001`. The separator is required, so
    a family entry can only claim ids in its own family."""
    families = checkdocs._families()
    details = checkdocs._details()
    for cid, family in families.items():
        assert cid.startswith(family + "-"), (cid, family)
        assert family in details
        assert cid not in details, "an exact entry should have won"


def test_a_rule_narrative_does_not_repeat_itself():
    """Where the rule IS the narrative, printing its description again as the
    lead line would show the reader the same sentences twice."""
    for entry in checkdocs.catalogue_index():
        if entry["doc_source"] == "rule_definition":
            assert checkdocs.check(entry["check_id"])["doc_specific"] is None


def test_every_knowledge_base_entry_reaches_a_check():
    """A written narrative nothing can render is work that was done and lost —
    which is exactly what the nineteen family entries were until they were
    wired up. This is the guard that catches the next one.

    Four entries fail this today and are listed rather than silently allowed:
    they name ids the catalogue no longer publishes, so the checks were renamed
    or removed and the prose was left behind."""
    details = set(checkdocs._details())
    catalogue = set(checkdocs._catalogue())
    families = set(checkdocs._families().values())
    orphaned = sorted(details - catalogue - families)
    assert orphaned == ["CAPX-COV-001", "IAM-SOD-HEUR-001", "IAM-SOD-HEUR-002",
                        "IAM-SOD-HEUR-003"], (
        "the set of unreachable knowledge-base entries has changed: %s"
        % orphaned)


def test_the_remaining_gap_is_still_reported_as_a_gap():
    """Half the gap closing must not quietly close the other half."""
    index = checkdocs.catalogue_index()
    undocumented = [e for e in index if not e["documented"]]
    assert undocumented, "every check documented — implausible; check the sources"
    for entry in undocumented:
        doc = checkdocs.check(entry["check_id"])
        assert doc["risk"] is None and doc["mitigation"] is None
        assert doc["doc_source"] is None


# ── the prose that had to be written ─────────────────────────────────────────
#
# 198 of the 352 undocumented checks were recovered from material the product
# already shipped. The rest are genuine writing debt, and the order to write them
# in is not catalogue order. A check whose closure SEVERS a risk path is the most
# actionable thing this product says about it — the choke-point screen is built
# entirely on that idea — so a reader who follows a cut to its check and finds
# "no published description" has been let down at the one moment the product was
# being most useful.

def test_no_check_on_a_cut_is_undocumented():
    """The invariant the first batch of hand-written entries established.

    Deliberately phrased over the CUT hops rather than over a list of ids: adding
    a template, or marking an existing hop as a cut, should fail this test until
    the checks it cites are explained. That is the correct order of work — the
    path content and the prose that supports it move together."""
    import json
    from pathlib import Path

    paths = json.loads((ROOT / "data" / "attack_paths.json").read_text(
        encoding="utf-8"))["paths"]
    cited = {(p["id"], hop["name"], check)
             for p in paths for hop in p["hops"] if hop.get("cut")
             for check in (hop.get("checks") or [])}

    undocumented = sorted(
        {(template, hop, check) for template, hop, check in cited
         if checkdocs.known_check(check)
         and not checkdocs.check(check)["documented"]})
    assert not undocumented, (
        "checks on a cut with no published description: %s" % undocumented[:8])


def test_a_hand_written_entry_carries_both_halves_and_says_something():
    """A risk paragraph and a numbered remediation. The length floor is crude and
    it is there for one reason: the cheapest way to make this file's coverage
    number go up is to write two sentences, and two sentences about a control
    this specific is not an explanation."""
    written = [e["check_id"] for e in checkdocs.catalogue_index()
               if e["doc_source"] == "knowledge_base"]
    thin = []
    for check_id in written:
        doc = checkdocs.check(check_id)
        risk, fix = doc["risk"] or "", doc["mitigation"] or ""
        if len(risk) < 300 or len(fix) < 200 or "1." not in fix:
            thin.append(check_id)
    assert not thin, "knowledge-base entries too thin to be an answer: %s" % thin[:8]
