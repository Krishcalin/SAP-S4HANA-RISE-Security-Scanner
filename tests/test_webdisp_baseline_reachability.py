"""Every Web Dispatcher baseline rule must be able to report a violation.

Like `data/sod_ruleset.json`, `data/webdisp_baseline.json` is declarative: each
rule names the parameter it reads, the operator, and the values that satisfy it.
So the rule states exactly what a compliant system looks like — and a violating
parameter set can be derived from it rather than written by hand.

Three of the fourteen (`WDISP-003`, `WDISP-006`, `WDISP-010`) had never been
observed to fire anywhere in this suite or against the bundled corpus, because
the corpus happens to be compliant on those three parameters. A rule that has
never reported anything is a rule whose parameter name could be misspelled
without anybody noticing: the check would stay silent on every estate, and
silence from a hardening check reads as "configured correctly".

Generated from the ruleset, so a rule added to the JSON is covered the moment
it is added.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.webdisp_security import WebDispatcherAuditor            # noqa: E402

BASELINE = json.loads((ROOT / "data" / "webdisp_baseline.json")
                      .read_text(encoding="utf-8"))
RULES = BASELINE["rules"]


def _violating_rows(rule):
    """Parameter rows that fail this rule, derived from the rule itself."""
    operator = rule["operator"]
    name = rule.get("name") or rule.get("name_prefix", "")

    if operator == "value_in":
        # Anything outside the compliant set. "TRUE" is the real-world
        # violation for every boolean rule in this file.
        return [{"NAME": name, "VALUE": "TRUE"}]
    if operator == "value_matches":
        return [{"NAME": name, "VALUE": "NONE"}]
    if operator == "value_not_blank":
        return [{"NAME": name, "VALUE": ""}]
    if operator == "value_not_equal":
        # Failing means being exactly the forbidden value — here, the delivered
        # default that leaves the handler open.
        return [{"NAME": name + "0", "VALUE": rule["value"]}]
    if operator == "value_contains":
        # The required substring is absent.
        return [{"NAME": name + "0", "VALUE": "PREFIX=/sap/admin"}]
    if operator == "value_not_contains_any":
        return [{"NAME": name + "0", "VALUE": rule["values"][0]}]
    if operator == "any_name_prefix_value_contains":
        # No port carries the required setting.
        return [{"NAME": name + "0", "VALUE": "PROT=HTTP,PORT=8000"}]
    raise AssertionError("unhandled operator %r on %s — this test must be "
                         "extended when a new operator is introduced"
                         % (operator, rule["check_id"]))


def _fired(rows):
    auditor = WebDispatcherAuditor({"webdisp_params": rows})
    return {f["check_id"] for f in (auditor.run_all_checks() or [])}


@pytest.mark.parametrize("rule", RULES, ids=[r["check_id"] for r in RULES])
def test_the_rule_reports_a_parameter_that_violates_it(rule):
    check_id = rule["check_id"]
    got = _fired(_violating_rows(rule))
    assert check_id in got, (
        "%s (%s on %s) reported nothing about a parameter set derived from its "
        "own definition to violate it. Either the parameter name no longer "
        "matches what the system exports, or the operator does not do what the "
        "rule says. Reported instead: %s"
        % (check_id, rule["operator"], rule.get("name") or rule.get("name_prefix"),
           sorted(got) or "nothing"))


def test_every_rule_names_a_parameter_to_read():
    nameless = [r["check_id"] for r in RULES
                if not (r.get("name") or r.get("name_prefix"))]
    assert not nameless, (
        "these rules read no parameter and can never fire: %s" % nameless)


def test_check_ids_are_unique():
    ids = [r["check_id"] for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate check ids in the baseline"
