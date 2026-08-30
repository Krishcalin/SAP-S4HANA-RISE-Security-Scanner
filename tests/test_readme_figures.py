"""The README states numbers. They have to be the ones the code produces.

WHY THIS FILE EXISTS

`docs/ARCHITECTURE.html` has had a test asserting its figures against the code
for a long time, and it has caught drift repeatedly. The README — the first
thing anyone reads, and the only document a stranger sees — had no such guard,
and every headline number in it was wrong:

    714 checks      against 793
    432 literals    against 448
     36 modules     against 38
    135 sources     against 136
     27 SoD risks   against 99

None of these were ever edited to be false. They were true when written and the
code moved, which is exactly the failure this product reports on in customers'
systems: a published figure nobody re-derives is a claim, not a measurement.

The numbers are asserted here rather than generated into the README, because the
README is prose a human writes and a generated file is not. What this guarantees
is narrower and sufficient: if the code moves, the build fails and somebody has
to look at the sentence.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import coverage                                    # noqa: E402
from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
CLAUDE = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")


def total_checks():
    return len(coverage.check_catalogue())


def module_count():
    return len(coverage.module_sources())


def states(text, number, label):
    """The number must appear as a standalone token, not inside a longer one."""
    assert re.search(r"\b%d\b" % number, text), (
        "%s: the document never states %d, the current figure. It has drifted "
        "from the code — find the stale sentence and update it." % (label, number))


# ── the README ─────────────────────────────────────────────────────────────

def test_the_readme_states_the_current_check_count():
    states(README, total_checks(), "README")


def test_the_readme_states_the_current_module_count():
    states(README, module_count(), "README")


def test_the_readme_states_the_current_source_count():
    states(README, len(coverage.all_logical_sources()), "README")


def test_the_readme_states_the_current_ruleset_size():
    states(README, len(ARA.RULESET), "README")


def test_the_readme_no_longer_states_the_figures_it_had_drifted_to():
    """The specific stale numbers, named so a copy-paste of an old sentence
    fails rather than passing because some other figure happens to match."""
    for stale, was in ((714, "checks"), (432, "literal ids"), (36, "modules")):
        assert not re.search(r"\b%d\b(?![%%\d])" % stale, README), (
            "README still states %d %s" % (stale, was))


# ── CLAUDE.md, which makes the same claims to a different reader ───────────

def test_claude_md_states_the_current_check_count():
    states(CLAUDE, total_checks(), "CLAUDE.md")


def test_claude_md_states_the_current_module_count():
    states(CLAUDE, module_count(), "CLAUDE.md")


def test_claude_md_no_longer_states_the_old_check_count():
    assert not re.search(r"\b714\b", CLAUDE)
