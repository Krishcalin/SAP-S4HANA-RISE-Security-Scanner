"""Which line a fact sits on in the export must not change the answer.

An export is a set of facts about a system. The order of its rows is an accident
of whoever produced the file -- which table the extractor read first, whether a
spreadsheet was sorted before saving, which application server answered first.
Nothing about the system changes when that order changes, so nothing about the
scan may either.

THREE DEFECTS IN ONE DAY CAME FROM THAT ACCIDENT DECIDING AN ANSWER: SQL tie
order silently dropping 27 findings from the paginated list, and CSV row order
twice in the parameter checks, once deciding whether SAP*'s kernel emergency
user was reported at all. Each was found by hand, one at a time, and fixing each
one taught nothing about where the next one was.

This is the general form. It runs every auditor over an estate, then over the
same estate with every row list REVERSED, and requires the findings to be
identical. It found a fourth instance immediately -- `SystemTrustAuditor`, which
keeps its own copy of the parameter lookup and so still had the bug after both
fixes to `security_params`.

WHY REVERSED AND NOT SHUFFLED. The first version of this shuffled with a fixed
seed and reported nothing against code that was known to be broken. A shuffle is
one sample: with 43 parameter rows, whether the two duplicated rows actually
swap is a coin flip, and that seed did not swap them. Reversal is the one
permutation that flips the relative order of EVERY pair, so it cannot miss the
case a duplicate hides in. Shuffles are kept alongside it for the orderings
reversal happens to preserve.

COMPARED ON IDENTITY, NOT DISPLAY -- `check_id`, severity, and the fingerprint
the product itself uses to decide whether two findings are the same finding.
Two scans of one estate that disagree about that disagree about what to fix, and
about whether a finding is new. Display strings are deliberately out of scope:
a module that lists "the first fifty holders" may legitimately name a different
fifty, and that is a different argument from this one.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import random
import sys
from pathlib import Path
from typing import Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor  # noqa: E402
from server import identity                   # noqa: E402

RUN_CONTEXT = {"deployment_mode": "rise_pce", "modules": set()}


# --------------------------------------------------------------------------- #
#  Every auditor, found the way the scanner finds them                        #
# --------------------------------------------------------------------------- #

def auditor_classes() -> Dict[str, type]:
    """Every BaseAuditor subclass in `modules/`.

    Discovered rather than listed: a hand-written list is a list somebody
    forgets to add to, and the module this test caught would have been exactly
    the one left off it.
    """
    import modules
    found: Dict[str, type] = {}
    for info in pkgutil.iter_modules(modules.__path__):
        try:
            mod = importlib.import_module("modules.%s" % info.name)
        except Exception:                                     # noqa: BLE001
            continue                       # optional dependency; not this test's business
        for name, obj in vars(mod).items():
            if (inspect.isclass(obj) and issubclass(obj, BaseAuditor)
                    and obj is not BaseAuditor
                    and obj.__module__ == mod.__name__
                    and hasattr(obj, "run_all_checks")):
                found[name] = obj
    return dict(sorted(found.items()))


AUDITORS = auditor_classes()


def test_the_discovery_actually_finds_the_auditors():
    """If this ever returns a handful, every assertion below passes vacuously."""
    assert len(AUDITORS) >= 30, sorted(AUDITORS)


# --------------------------------------------------------------------------- #
#  Re-ordering                                                                #
# --------------------------------------------------------------------------- #

def reordered(data: dict, seed=None) -> dict:
    """Every row list re-ordered; `seed=None` reverses."""
    rng = random.Random(seed) if seed is not None else None
    out = {}
    for key, value in data.items():
        if isinstance(value, list) and len(value) > 1:
            copy = list(value)
            if rng is None:
                copy.reverse()
            else:
                rng.shuffle(copy)
            out[key] = copy
        else:
            out[key] = value
    return out


def identities(cls, data) -> set:
    """What this auditor concluded, as identities rather than prose."""
    findings = cls(data, {}, dict(RUN_CONTEXT)).run_all_checks() or []
    out = set()
    for f in findings:
        fingerprint, basis = identity.fingerprint_finding(f, system="PRD",
                                                          client="100")
        out.add((f.get("check_id"), f.get("severity"), basis, fingerprint))
    return out


def assert_stable(cls, data, label):
    original = identities(cls, data)
    for how, variant in (("reversed", reordered(data)),
                         ("shuffled seed 1", reordered(data, 1)),
                         ("shuffled seed 7", reordered(data, 7))):
        other = identities(cls, variant)
        if original == other:
            continue
        lost = sorted(original - other)
        gained = sorted(other - original)
        raise AssertionError(
            "%s on %s: the same estate %s produced different findings.\n"
            "  reported only in the original order: %s\n"
            "  reported only in the %s order:       %s\n"
            "Which line a fact sits on in the export decided the answer."
            % (cls.__name__, label, how,
               [k[:2] for k in lost] or "none",
               how, [k[:2] for k in gained] or "none"))


# --------------------------------------------------------------------------- #
#  The estate that carries the condition                                      #
# --------------------------------------------------------------------------- #

def param(name, value):
    return {"NAME": name, "VALUE": str(value)}


#: Parameters exported TWICE with values that read oppositely -- which is what a
#: multi-instance RSPARAM produces when the servers really do differ, and what a
#: merged DEFAULT.PFL produces when it carries an override beside its default.
#: One safe copy and one unsafe copy each, so whichever the code keeps decides
#: the verdict.
CONFLICTING = [
    param("login/no_automatic_user_sapstar", "0"),   # SAP* emergency user usable
    param("login/no_automatic_user_sapstar", "1"),
    param("rfc/selftrust", "1"),
    param("rfc/selftrust", "0"),
    param("ucon/rfc/active", "0"),
    param("ucon/rfc/active", "1"),
    param("rdisp/msserv_internal", "0"),
    param("rdisp/msserv_internal", "3299"),
    param("ms/monitor", "1"),
    param("ms/monitor", "0"),
    param("login/min_password_lng", "6"),
    param("login/min_password_lng", "15"),
    param("gw/prxy_info", ""),
    param("gw/prxy_info", "/usr/sap/PRD/prxyinfo"),
    param("gw/acl_mode_proxy", "0"),
    param("gw/acl_mode_proxy", "1"),
]

CONFLICTED_ESTATE = {"security_params": CONFLICTING}


@pytest.mark.parametrize("name", sorted(AUDITORS))
def test_no_auditor_depends_on_export_row_order(name):
    """THE INVARIANT. Reversing the export must not change any verdict."""
    assert_stable(AUDITORS[name], CONFLICTED_ESTATE, "a conflicted export")


@pytest.mark.parametrize("name", sorted(AUDITORS))
def test_no_auditor_depends_on_row_order_of_the_shipped_estate(name):
    """The same question of `sample_data`, which exercises far more checks --
    though not the duplicate case, since it has no duplicated parameters."""
    from modules.data_loader import DataLoader
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    assert_stable(AUDITORS[name], data, "sample_data")


# --------------------------------------------------------------------------- #
#  The instance it caught, stated on its own                                  #
# --------------------------------------------------------------------------- #

def trust_findings(rows: List[dict]) -> set:
    from modules.system_trust import SystemTrustAuditor
    return {f["check_id"]
            for f in SystemTrustAuditor({"security_params": rows}, {},
                                        dict(RUN_CONTEXT)).run_all_checks()}


@pytest.mark.parametrize("order", [("0", "1"), ("1", "0")])
def test_sap_star_auto_logon_survives_either_row_order(order):
    """`STDUSR-001` is SAP*'s kernel emergency user being usable -- CRITICAL, and
    for a while reported or not according to which duplicate row came last.

    `security_params` had this fixed twice today. This module keeps its OWN copy
    of the parameter lookup, so it kept the bug through both fixes, and only the
    invariant above found it.
    """
    rows = [param("login/no_automatic_user_sapstar", v) for v in order]
    assert "STDUSR-001" in trust_findings(rows)


def test_a_single_safe_value_still_reports_nothing():
    """Fail-closed must not become fail-always."""
    assert "STDUSR-001" not in trust_findings(
        [param("login/no_automatic_user_sapstar", "1")])


@pytest.mark.parametrize("order", [("1", "0"), ("0", "1")])
def test_rfc_self_trust_survives_either_row_order(order):
    rows = [param("rfc/selftrust", v) for v in order]
    assert "TRUST-002" in trust_findings(rows)


@pytest.mark.parametrize("order", [("0", "1"), ("1", "0")])
def test_ucon_allowlist_survives_either_row_order(order):
    rows = [param("ucon/rfc/active", v) for v in order]
    assert "TRUST-007" in trust_findings(rows)


def test_the_gateway_mitigation_must_hold_on_every_instance():
    """`gw/acl_mode_proxy = 1` auto-secures an empty `gw/prxy_info`, so it is the
    one value here read as a MITIGATION rather than an exposure -- and a
    mitigation only counts if every exported copy carries it. One instance still
    on the old default is one instance still open, and accepting the reassuring
    copy would reintroduce the fail-open this change removes."""
    rows = [param("gw/prxy_info", ""),
            param("gw/acl_mode_proxy", "1"),
            param("gw/acl_mode_proxy", "0")]
    assert "TRUST-008" in trust_findings(rows)
    # ...and where every copy agrees the mitigation is in place, it is accepted.
    assert "TRUST-008" not in trust_findings(
        [param("gw/prxy_info", ""), param("gw/acl_mode_proxy", "1")])
