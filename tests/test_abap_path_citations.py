"""SAPPATH-15 cites a SUBSET of the ABAP scanner, by a rule that has to stay true.

WHY A SUBSET AT ALL. `ATC-*` represents each imported ATC family as one check id,
so `ATC-SQLI` is a citable thing. `abap_sast` represents each RULE as a check, so
the same concept is sixteen ids. Citing every rule in the injection families would
put fifty-nine ids on a single hop, which is not a template anybody can read.

WHY THIS FILE EXISTS. A hand-picked subset is exactly the kind of content that
rots: a rule added at CRITICAL next month would simply not be on the path, and
nothing would say so — which is the failure this whole exercise was started by.
The citation is therefore a STATED RULE, and this test derives the same set from
the rule table and requires the two to agree. Adding a CRITICAL injection rule now
fails the build until it is cited.

It is deliberately an equality, not a subset check, in both directions:

  * a rule that becomes CRITICAL and is not cited is a gap;
  * a rule cited here that is no longer CRITICAL — downgraded, or deleted — is a
    stale citation, and `test_every_check_a_risk_path_cites_resolves` only catches
    the deleted case.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: The stated rule, restated here independently of the content it governs.
INJECTION_FAMILIES = ("ABAP-SQLI", "ABAP-CINJ", "ABAP-CMDI", "ABAP-NSQL",
                      "ABAP-PATH", "ABAP-SSRF", "ABAP-XXE", "ABAP-AMDP")
AUTHORITY_FAMILIES = ("ABAP-AUTH", "ABAP-BKDR")


def _rules():
    from modules import abap_sast_rules

    out = {}
    for name in dir(abap_sast_rules):
        value = getattr(abap_sast_rules, name)
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], dict):
            for rule in value:
                if isinstance(rule, dict) and rule.get("id"):
                    out.setdefault(rule["id"], rule)
    return out


def _family(check_id):
    return check_id.rsplit("-", 1)[0]


def _hops():
    paths = json.loads((ROOT / "data" / "attack_paths.json").read_text(
        encoding="utf-8"))["paths"]
    p15 = next(p for p in paths if p["id"] == "SAPPATH-15")
    return (next(h for h in p15["hops"] if "injectable defect" in h["name"]),
            next(h for h in p15["hops"] if "caller's authority" in h["name"]))


def test_the_injection_hop_cites_exactly_the_critical_injection_rules():
    rules = _rules()
    expected = {i for i, r in rules.items()
                if _family(i) in INJECTION_FAMILIES
                and r.get("severity") == "CRITICAL"}
    assert expected, "no CRITICAL injection rules found — the rule table moved"
    cited = {c for c in _hops()[0]["checks"] if c.startswith("ABAP-")}
    assert cited == expected, (
        "SAPPATH-15's injectable-defect hop has drifted from the stated rule.\n"
        "  missing: %s\n  stale:   %s"
        % (sorted(expected - cited), sorted(cited - expected)))


def test_the_authority_hop_cites_exactly_the_critical_and_high_authority_rules():
    rules = _rules()
    expected = {i for i, r in rules.items()
                if _family(i) in AUTHORITY_FAMILIES
                and r.get("severity") in ("CRITICAL", "HIGH")}
    assert expected
    cited = {c for c in _hops()[1]["checks"] if c.startswith("ABAP-")}
    assert cited == expected, (
        "SAPPATH-15's authority hop has drifted from the stated rule.\n"
        "  missing: %s\n  stale:   %s"
        % (sorted(expected - cited), sorted(cited - expected)))


def test_the_imported_and_the_scanned_are_both_present_and_not_confused():
    """`ATC-*` is SAP's verdict, `ABAP-*` is ours. Both belong on the hop and the
    hop has to say which is which, because a reader who thinks they are duplicates
    will discount one of them."""
    hop = _hops()[0]
    assert any(c.startswith("ATC-") for c in hop["checks"])
    assert any(c.startswith("ABAP-") for c in hop["checks"])
    note = hop.get("note") or ""
    assert "ATC" in note and "authoritative" in note, (
        "the hop cites both sources and does not explain their relationship")


def test_the_backdoor_rules_are_not_on_the_injection_hop():
    """A hardcoded user comparison is an authority check written to pass, not an
    injectable defect. Putting it on the first hop would make the hop's name a
    lie about a third of what it cites."""
    injection, authority = _hops()
    assert not [c for c in injection["checks"] if c.startswith("ABAP-BKDR")]
    assert [c for c in authority["checks"] if c.startswith("ABAP-BKDR")]


@pytest.mark.skipif(not (ROOT / "sample_data").is_dir(), reason="sample_data absent")
def test_the_citation_actually_instantiates_on_the_bundled_corpus():
    """A citation that no finding can ever satisfy is decoration. At least one
    cited scanner rule has to fire on the corpus, or the hop is evidenced in
    theory only — which is what every ABAP citation was before the module could
    be reached at all."""
    import contextlib
    import importlib
    import io

    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT

    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        fired = set()
        for module_name, class_name in AUDITORS:
            auditor = getattr(importlib.import_module(f"modules.{module_name}"),
                              class_name)
            fired |= {f["check_id"] for f in
                      (auditor(data, None, RUN_CONTEXT).run_all_checks() or [])}

    for hop in _hops():
        cited = {c for c in hop["checks"] if c.startswith("ABAP-")}
        assert cited & fired, (
            "no ABAP rule cited on %r fires on sample_data" % hop["name"])
