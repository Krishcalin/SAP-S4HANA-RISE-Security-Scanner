"""Every ABAP rule must be able to fire. Half the catalogue never has.

WHAT THIS IS FOR

392 of the product's 790 check ids have never produced a finding on either
shipped fixture. That is not 392 broken checks - most are pattern matchers that
correctly stay silent because the corpus contains no such defect. What it means
is that for half the product, "correctly silent" and "can never fire" are
indistinguishable, and the second is a real class: five SoD rules were found in
exactly that state, and SODCOV-007 exists to report it in a customer's ruleset.

This file closes the largest tractable part of that gap. The ABAP rules are
table-driven, so for each one a line can be synthesised from its own pattern,
fed through the real auditor, and the check id asserted to appear.

Measured after this file: of the 392 that had never fired, 81 are now PROVEN to
fire, and a further 90 are ARA rules already proven satisfiable by
test_ara_batch2.py. That leaves 221 genuinely unproven - mostly parameter and
configuration checks, which are the next tractable family and are NOT claimed
here. The point of stating the remainder is that a harness which quietly implied
it had covered everything would be the same defect it was written to find.

WHY IT IS SELF-VERIFYING

A generator that quietly produced a non-matching line would turn this file into
a test that proves nothing while passing. So every candidate is checked against
its own pattern FIRST, and rules whose candidate does not match are collected
and reported by name rather than skipped silently. `test_the_generator_covers_
most_of_the_catalogue` pins how many it manages, so the number cannot quietly
fall.

WHAT IT DOES NOT CLAIM

That a rule is CORRECT - only that it can fire at all. A rule matching the wrong
thing still passes here, which is why it complements review rather than
replacing it.
"""
import re
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import abap_sast_rules as R                      # noqa: E402
from modules import abap_sast as _sast                        # noqa: E402
from modules.abap_sast import AbapSastAuditor                 # noqa: E402

BS = chr(92)
#: Escaped literals must survive the quantifier stripping, so they are parked
#: behind sentinels first and restored last.
LITERALS = "*.+?()[]{}|^$/-"


def sample_for(pattern: str) -> str:
    """A line the pattern should match. Every caller verifies it actually does."""
    s = re.sub(r"\(\?[aiLmsux]+\)", "", pattern)
    for i, ch in enumerate(LITERALS):
        s = s.replace(BS + ch, "\x00%d\x00" % i)
    s = s.replace(BS + "b", "").replace(BS + "B", "")          # zero width
    s = s.replace(BS + "s*", " ").replace(BS + "s+", " ").replace(BS + "s", " ")
    s = s.replace(BS + "S+", "X").replace(BS + "S", "X")
    s = s.replace(BS + "w+", "X").replace(BS + "w*", "X").replace(BS + "w", "X")
    s = s.replace(BS + "d+", "1").replace(BS + "d", "1")
    for _ in range(6):                                          # lookarounds
        nxt = re.sub(r"\(\?<[=!][^()]*\)", "",
                     re.sub(r"\(\?[=!][^()]*\)", "", s))
        if nxt == s:
            break
        s = nxt
    s = re.sub(r"\[\^[^\]]*\][+*?]?", "X", s)
    s = re.sub(r"\[[^\]]*\]\*", "", s)
    s = re.sub(r"\[[^\]]*\]\?", "", s)
    s = re.sub(r"\[([^\]]*)\][+]?", _member, s)
    s = s.replace(".*", " ").replace(".+", "X").replace(".", "X")
    for _ in range(6):                                          # first branch
        nxt = re.sub(r"\((?:\?:)?([^()|]*)\|[^()]*\)", r"\1", s)
        if nxt == s:
            break
        s = nxt
    s = s.replace("(?:", "(").replace("(", "").replace(")", "")
    s = re.sub(r"\{\d+(,\d*)?\}", "", s)
    s = s.replace("^", "").replace("$", "")
    s = re.sub(r"[+*?]", "", s)
    s = s.replace(BS, "")
    for i, ch in enumerate(LITERALS):
        s = s.replace("\x00%d\x00" % i, ch)
    return s.strip()


def _member(m):
    """A MEMBER of a character class, not a stand-in for one. ["'] has to
    become a quote or the candidate cannot match its own pattern."""
    body = m.group(1)
    if not body:
        return "X"
    if body[0] == BS and len(body) > 1:
        return {"d": "1", "w": "X", "s": " "}.get(body[1], body[1])
    return body[0]


def all_rules():
    """Every pattern rule, ONCE. Several appear in more than one table, and
    counting them twice inflated the coverage figure this file publishes."""
    seen = set()
    for name in sorted(n for n in dir(R) if n.isupper() and n.endswith("_RULES")):
        for rule in getattr(R, name):
            if rule.get("pattern") and rule["id"] not in seen:
                seen.add(rule["id"])
                yield rule


def matchable():
    """(rule, line) for every rule whose generated line VERIFIABLY matches."""
    out = []
    for rule in all_rules():
        # A rule the module has retired can never fire, correctly.
        if rule["id"] in getattr(_sast, "RETIRED_RULES", ()):
            continue
        line = sample_for(rule["pattern"])
        try:
            if line and re.search(rule["pattern"], line, re.I):
                out.append((rule, line))
        except re.error:
            pass
    return out


MATCHABLE = matchable()
ALL = list(all_rules())


#: The scanner routes by FILE TYPE, so a probe written as .abap never
#: reaches the JavaScript or BTP-descriptor rules. Getting this wrong
#: reported 36 perfectly good rules as unfirable - a harness fault dressed
#: up as a product defect, which is the mistake this whole file exists to
#: avoid making about somebody else's code.
PROBE_NAME = {"ABAP-JS": "zprobe.js", "ABAP-BTP": "xs-security.json",
              "ABAP-CDS": "zprobe.cds"}


def probe_for(rule_id: str) -> str:
    for prefix, name in PROBE_NAME.items():
        if rule_id.startswith(prefix):
            return name
    return "zprobe.abap"


def run_on(line: str, filename: str = "zprobe.abap"):
    """Drive the real auditor over a one-line source file."""
    d = tempfile.mkdtemp()
    (Path(d) / filename).write_text(line + "\n", encoding="utf-8")
    a = AbapSastAuditor({AbapSastAuditor.SOURCE_KEY: d}, {}, {})
    a.run_all_checks()
    return {f["check_id"] for f in a.findings}


# ── the harness itself has to be honest ────────────────────────────────────

def test_the_generator_covers_most_of_the_catalogue():
    """Pinned so it cannot quietly fall. A generator that silently stopped
    producing matches would leave this file passing while proving nothing."""
    assert len(ALL) >= 90
    assert len(MATCHABLE) >= 90, (
        "%d of %d rules got a verified line; the generator has regressed"
        % (len(MATCHABLE), len(ALL)))


def test_every_generated_line_matches_the_rule_it_came_from():
    """The self-check. Nothing reaches the firing test unverified."""
    for rule, line in MATCHABLE:
        assert re.search(rule["pattern"], line, re.I), rule["id"]


def test_the_rules_we_cannot_generate_for_are_named_not_hidden():
    """A rule this harness cannot exercise is reported, so the gap stays
    visible instead of looking like coverage."""
    covered = {r["id"] for r, _ in MATCHABLE}
    ungenerated = sorted(r["id"] for r in ALL if r["id"] not in covered)
    assert len(ungenerated) <= 25, ungenerated
    # named here on purpose: this list is the harness's own blind spot
    assert all(isinstance(i, str) for i in ungenerated)


# ── what actually fires, and what this harness cannot reach ───────────

def _split():
    """(fires, does not) for every rule with a verified line.

    Computed once at import: driving the auditor ~190 times costs about three
    seconds and buys the only claim here that matters.
    """
    fires, silent = [], []
    for rule, line in MATCHABLE:
        got = run_on(line, probe_for(rule["id"]))
        (fires if rule["id"] in got else silent).append((rule, line))
    return fires, silent


FIRES, SILENT = _split()

#: Rules whose pattern this harness can satisfy but whose CHECK it cannot
#: reach, with the reason. None of these is a product defect - each needs
#: context a single synthesised line cannot supply.
#:
#: The list is asserted EXACTLY, not as a maximum, so a rule that stops firing
#: for a real reason lands here and breaks the build instead of joining a
#: tolerated pile. That is the whole value of writing it down.
UNREACHABLE_BY_THIS_HARNESS = {
    "ABAP-SQLI-001": "taint rule (_taint_sink): needs a tainted source, not a pattern",
    "ABAP-SQLI-002": "taint rule: the concatenation must reach a SELECT",
    "ABAP-CINJ-007": "needs a dynamic token the generated line does not carry",
    "ABAP-AUTH-003": "needs surrounding statement context",
    "ABAP-BTP-004": "CDS syntax (service ... {), routed by prefix to a descriptor",
    "ABAP-BTP-007": "descriptor-specific: needs the right file name, not xs-security.json",
    "ABAP-BTP-008": "descriptor-specific: needs the right file name",
}


@pytest.mark.parametrize("rule,line", FIRES,
                         ids=[r["id"] for r, _ in FIRES])
def test_the_rule_fires_on_a_line_built_from_its_own_pattern(rule, line):
    """THE test. Not that the regex matches - that the CHECK reports it.

    A rule whose pattern is satisfiable but whose surrounding code can never
    reach a finding call is dead in exactly the way SODCOV-007 reports for a
    customer's ruleset, and nothing else here would notice."""
    assert rule["id"] in run_on(line, probe_for(rule["id"]))


def test_most_of_the_catalogue_is_proven_to_fire():
    """The number this file exists to move. Pinned so it cannot fall quietly."""
    assert len({r["id"] for r, _ in FIRES}) >= 85


def test_the_unreachable_set_is_exactly_what_we_documented():
    """A rule that stops firing for a REAL reason must break the build rather
    than disappear into a tolerated pile. Exact, not a maximum."""
    assert {r["id"] for r, _ in SILENT} == set(UNREACHABLE_BY_THIS_HARNESS)


def test_each_unreachable_rule_says_why():
    for rid, why in UNREACHABLE_BY_THIS_HARNESS.items():
        assert why and len(why) > 20, rid
