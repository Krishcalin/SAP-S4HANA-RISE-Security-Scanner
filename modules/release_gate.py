# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Release Gate
============
The step that turns this from a tool that REPORTS into a tool that DECIDES.

A scanner tells you what is wrong. A gate refuses the change that would make it
worse — which is the only mechanism that stops a backlog growing, and it is the
difference between an audit artefact and a control an auditor will accept.

────────────────────────────────────────────────────────────────────────────────
THE FOUR RULES THAT DECIDE WHETHER A GATE SURVIVES CONTACT WITH A REAL PIPELINE
────────────────────────────────────────────────────────────────────────────────
Gates get switched off. Every rule below exists because of the specific way that
happens.

1. **Judge the DELTA, not the backlog.** A gate that fails on an estate's existing
   findings goes red on its first run, on a change that introduced none of them,
   and is disabled inside a week. So it compares against a BASELINE and blocks
   only on what is new. This is why `write_baseline()` exists and why establishing
   one is step one of adopting the gate, not an afterthought.

2. **Judge only what the change touches.** With `--gate-scope`, a transport is
   judged on the objects it actually contains. A developer cannot be asked to fix
   somebody else's object to ship their own.

3. **Never block on something the customer cannot fix.** In RISE, a real finding
   may be the provider's to remediate or may need an SAP ticket. Blocking a
   customer's transport on `provider_owned` or `ticket_to_sap` is a demand they
   cannot satisfy at any effort, and it is the fastest possible route to the gate
   being bypassed permanently. This is the four-state `remediation_owner` model
   earning its keep: the gate is strict precisely because it is fair.

4. **NEVER FAIL OPEN.** If coverage was degraded — the ABAP lexer lost its place,
   no findings were supplied, the policy is unreadable — the answer is "could not
   assess" (exit 2), never "pass". A mis-lexed file that yields a green pipeline is
   the single worst outcome this module can produce: it is indistinguishable from
   clean code and it is a lie told automatically, on every build, until someone
   notices. `ABAP-LEX-001` exists to be read here.

────────────────────────────────────────────────────────────────────────────────
WHAT BLOCKS, BY DEFAULT
────────────────────────────────────────────────────────────────────────────────
New, in-scope, customer-fixable CRITICAL or HIGH findings that carry data-flow
evidence (`confirmed`) or an inconclusive walk (`tentative`).

`pattern-only` deliberately does NOT block. That evidence class is exactly the
population Tier 2 of the CVA engine plan was about — rules that matched correct
code — and a finding with no data-flow evidence behind it is not a safe thing to
stop a release with. It is still reported, and it still counts in the report; it
just does not get to hold the build.

Exit codes follow CI convention: 0 pass, 1 policy violated, 2 could not assess.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

#: Severity order, worst first. Anything not listed never blocks.
SEVERITY_ORDER: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

EXIT_PASS = 0
EXIT_BLOCKED = 1
EXIT_CANNOT_ASSESS = 2

#: Deliberately strict on what it blocks and narrow about when. See the module
#: docstring: every default here is the conservative side of a rule that decides
#: whether the gate is still switched on in three months.
DEFAULT_POLICY: Dict[str, Any] = {
    # Maximum NEW findings permitted, per severity. A severity absent from this
    # map is not gated at all.
    "max_new": {"CRITICAL": 0, "HIGH": 0},
    # Evidence classes allowed to hold a build. `pattern-only` is excluded on
    # purpose — see the docstring.
    "blocking_confidence": ["confirmed", "tentative", None],
    # Ownership states that may block. A finding whose owner is unknown DOES
    # block: unknown is not a licence to ship.
    "blocking_owners": ["customer_fixable", None],
    # Check ids or id prefixes that never block, whatever else is true. For
    # accepted risks that have been through the dismissal workflow.
    "exempt_checks": [],
    # Rule 4. Turning this off means asking for a green build on a scan that
    # could not see the code.
    "block_on_degraded_coverage": True,
    # Rollout setting: evaluate and report exactly as normal, but always exit 0.
    # A hard gate cannot be dropped onto an existing estate on day one.
    "warn_only": False,
}


class GateResult:
    """The decision, and everything needed to argue with it."""

    __slots__ = ("decision", "exit_code", "reasons", "blocking", "counts",
                 "considered", "new_total", "policy")

    def __init__(self, decision: str, exit_code: int, reasons: List[str],
                 blocking: List[Dict[str, Any]], counts: Dict[str, int],
                 considered: int, new_total: int, policy: Dict[str, Any]):
        #: "pass" | "blocked" | "cannot_assess"
        self.decision = decision
        self.exit_code = exit_code
        #: Why, in the order a human should read them.
        self.reasons = reasons
        #: The findings that held the build — never a bare count, because a
        #: developer who cannot see what to fix will route around the gate.
        self.blocking = blocking
        self.counts = counts
        self.considered = considered
        self.new_total = new_total
        self.policy = policy

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "exit_code": self.exit_code,
            "reasons": self.reasons,
            "counts": self.counts,
            "considered": self.considered,
            "new_total": self.new_total,
            "blocking": [
                {"check_id": f.get("check_id"),
                 "severity": f.get("severity"),
                 "title": f.get("title"),
                 "confidence": (f.get("details") or {}).get("confidence"),
                 "remediation_owner": f.get("remediation_owner"),
                 "objects": _object_names(f),
                 "fingerprint": fingerprint(f)}
                for f in self.blocking
            ],
        }


# --------------------------------------------------------------------------- #
#  Identity                                                                   #
# --------------------------------------------------------------------------- #

def _object_names(finding: Dict[str, Any]) -> List[str]:
    """The SAP objects a finding is about, preferring structured over display."""
    names: List[str] = []
    for entry in (finding.get("subject") or []):
        if isinstance(entry, dict) and entry.get("name"):
            names.append(str(entry["name"]).upper())
    if names:
        return names
    for entry in (finding.get("affected_objects") or []):
        if isinstance(entry, dict) and entry.get("name"):
            names.append(str(entry["name"]).upper())
    return names


def fingerprint(finding: Dict[str, Any]) -> str:
    """A stable identity for baseline comparison.

    Mirrors `server/identity.py`'s contract rather than inventing a second one:
    the subject and its qualifier, NEVER the line number. A finding that moves
    down a file because four blank lines were added above it is the same finding,
    and a baseline that disagrees would re-block every unrelated edit.

    Falls back to the display strings when a module has no structured subject,
    which holds as long as that module's formatting holds — the same trade-off
    and the same caveat as the server's fingerprint.
    """
    parts: List[str] = [str(finding.get("check_id") or "")]
    subject = finding.get("subject") or finding.get("affected_objects") or []
    if subject:
        for entry in subject:
            if isinstance(entry, dict):
                parts.append(f"{entry.get('type', '')}:{entry.get('name', '')}"
                             f":{entry.get('qualifier', '')}")
            else:
                parts.append(str(entry))
    else:
        parts.extend(str(i) for i in (finding.get("affected_items") or []))
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


def write_baseline(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """The accepted state. Adopting the gate starts here, not with a red build."""
    prints = sorted({fingerprint(f) for f in findings})
    return {"version": 1, "count": len(prints), "fingerprints": prints}


def load_baseline(path: Path) -> Set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return set(data.get("fingerprints") or [])
    return set(data)                       # a bare list is accepted too


def load_policy(path: Optional[Path]) -> Dict[str, Any]:
    """Policy from JSON, merged over the defaults.

    Merged rather than replaced: a policy naming only `max_new` must not silently
    switch off `block_on_degraded_coverage` by omitting it. Fail-open by typo is
    still fail-open.
    """
    policy = json.loads(json.dumps(DEFAULT_POLICY))      # deep copy, stdlib only
    if path is None:
        return policy
    supplied = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(supplied, dict):
        raise ValueError("gate policy must be a JSON object")
    unknown = sorted(set(supplied) - set(DEFAULT_POLICY))
    if unknown:
        # A misspelled key that is silently ignored is a policy the operator
        # believes is in force and is not.
        raise ValueError(f"unknown gate policy key(s): {', '.join(unknown)}")
    policy.update(supplied)
    return policy


def load_scope(path: Path) -> Set[str]:
    """Object names a transport touches — one per line, `#` comments allowed."""
    out: Set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            out.add(name.upper())
    return out


# --------------------------------------------------------------------------- #
#  The decision                                                               #
# --------------------------------------------------------------------------- #

def _is_exempt(check_id: str, exempt: Sequence[str]) -> bool:
    return any(check_id == e or check_id.startswith(e) for e in exempt)


def evaluate(findings: Sequence[Dict[str, Any]],
             *,
             policy: Optional[Dict[str, Any]] = None,
             baseline: Optional[Set[str]] = None,
             scope: Optional[Set[str]] = None,
             degraded: bool = False,
             degraded_detail: str = "") -> GateResult:
    """Decide whether this change may ship.

    `degraded` is the fail-closed input: pass it True when anything made the scan
    less than complete. It is checked FIRST, before any finding is looked at,
    because "we found nothing" and "we could not look" must never produce the same
    exit code.
    """
    policy = policy or json.loads(json.dumps(DEFAULT_POLICY))
    reasons: List[str] = []

    max_new: Dict[str, int] = policy.get("max_new") or {}
    warn_only = bool(policy.get("warn_only"))

    # ---- Rule 4, checked before anything else -------------------------- #
    if degraded and policy.get("block_on_degraded_coverage", True):
        reasons.append(
            "Coverage was degraded, so this scan cannot support a pass. "
            + (degraded_detail or "Part of the source could not be analysed.")
            + " A gate that returns green on a scan that could not see the code "
              "is worse than no gate: the build goes through and the report looks "
              "clean.")
        return GateResult("cannot_assess",
                          EXIT_PASS if warn_only else EXIT_CANNOT_ASSESS,
                          reasons, [], {}, 0, 0, policy)

    # ---- Rule 2: only what the change touches --------------------------- #
    considered = list(findings)
    if scope is not None:
        considered = [f for f in considered
                      if scope.intersection(_object_names(f))]
        reasons.append(
            f"Scoped to {len(scope)} object(s) named by the transport: "
            f"{len(considered)} of {len(findings)} finding(s) are in scope.")

    # ---- Rule 1: only what is new --------------------------------------- #
    if baseline is not None:
        fresh = [f for f in considered if fingerprint(f) not in baseline]
        reasons.append(
            f"Compared against a baseline of {len(baseline)} accepted finding(s): "
            f"{len(fresh)} of {len(considered)} are new.")
    else:
        fresh = considered
        reasons.append(
            "No baseline supplied, so EVERY in-scope finding counts as new. This "
            "is correct for a first run and wrong for a pipeline — write one with "
            "--gate-write-baseline before enforcing.")

    # ---- Rule 3, plus evidence and exemptions --------------------------- #
    blocking_confidence = set(policy.get("blocking_confidence") or [])
    blocking_owners = set(policy.get("blocking_owners") or [])
    exempt = tuple(policy.get("exempt_checks") or [])

    blocking: List[Dict[str, Any]] = []
    for f in fresh:
        severity = (f.get("severity") or "").upper()
        if severity not in max_new:
            continue
        check_id = str(f.get("check_id") or "")
        if _is_exempt(check_id, exempt):
            continue
        confidence = (f.get("details") or {}).get("confidence")
        if blocking_confidence and confidence not in blocking_confidence:
            continue
        owner = f.get("remediation_owner")
        if blocking_owners and owner not in blocking_owners:
            continue
        blocking.append(f)

    counts: Dict[str, int] = {}
    for f in blocking:
        sev = (f.get("severity") or "").upper()
        counts[sev] = counts.get(sev, 0) + 1

    breached = [(sev, counts.get(sev, 0), limit)
                for sev, limit in max_new.items()
                if counts.get(sev, 0) > int(limit)]

    if breached:
        for sev, got, limit in sorted(
                breached, key=lambda b: SEVERITY_ORDER.index(b[0])
                if b[0] in SEVERITY_ORDER else 99):
            reasons.append(f"{got} new {sev} finding(s); the policy permits {limit}.")
        decision = "blocked"
        exit_code = EXIT_PASS if warn_only else EXIT_BLOCKED
    else:
        reasons.append("No new finding exceeds the policy.")
        decision, exit_code = "pass", EXIT_PASS

    if warn_only and decision != "pass":
        reasons.append(
            "warn_only is set, so this is reported and NOT enforced — exit 0. "
            "Remove it once the baseline is trusted, or the gate decides nothing.")

    # Only the ones that actually breached a limit are worth showing.
    breached_sevs = {sev for sev, _, _ in breached}
    shown = [f for f in blocking
             if (f.get("severity") or "").upper() in breached_sevs]

    return GateResult(decision, exit_code, reasons, shown, counts,
                      len(considered), len(fresh), policy)


# --------------------------------------------------------------------------- #
#  Output                                                                     #
# --------------------------------------------------------------------------- #

_BANNER = {
    "pass": "RELEASE GATE: PASS",
    "blocked": "RELEASE GATE: BLOCKED",
    "cannot_assess": "RELEASE GATE: CANNOT ASSESS",
}


def render(result: GateResult) -> str:
    """The CI log. A developer who cannot see what to fix routes around the gate,
    so this names the findings rather than counting them."""
    lines = ["", "=" * 72, _BANNER.get(result.decision, result.decision), "=" * 72]
    for reason in result.reasons:
        lines.append(f"  - {reason}")
    if result.blocking:
        lines.append("")
        lines.append("  Findings holding this release:")
        for f in result.blocking[:25]:
            objects = ", ".join(_object_names(f)[:3]) or "(no object named)"
            confidence = (f.get("details") or {}).get("confidence") or "n/a"
            lines.append(f"    [{f.get('severity')}] {f.get('check_id')} "
                         f"— {objects}  (evidence: {confidence})")
            lines.append(f"        {(f.get('title') or '').strip()[:100]}")
        if len(result.blocking) > 25:
            lines.append(f"    ... and {len(result.blocking) - 25} more")
    lines.append("=" * 72)
    lines.append(f"exit {result.exit_code}")
    lines.append("")
    return "\n".join(lines)
