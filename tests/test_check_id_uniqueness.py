"""
No two DIFFERENT checks may share a check_id.

A check_id is a foreign key into `check_definition`, into the 323-entry remediation
knowledge base, into the compliance mapping and into the attack-path templates. Two
different checks sharing one id share a title, a remediation and a control mapping,
and whichever fires last silently overwrites the catalogue row of the other.

WHY THIS IS AN ALLOWLIST RATHER THAN A CLEVER HEURISTIC
--------------------------------------------------------
"The id appears twice" is not the defect. One check is routinely emitted from
several branches — a main path and a fallback for a missing export, or two ways of
detecting the same defect — and modules reword the title per branch. `USR-002` says
"User X has critical profile Y" on the per-user path and "Users assigned critical
profiles" on the roll-up path. That is one check.

The defect is one id used for two genuinely different checks, which is what
`BASELINE-011` became when it was used for both the password-hash check and a new
RFC-callback check — two unrelated profile parameters under one id.

Telling those apart automatically means judging whether two English sentences
describe the same defect, which no regex does honestly. So the seven pre-existing
re-uses are listed below as REVIEWED, each with the reason it is acceptable, and
anything new fails. A reviewer adding a check id that already exists has to come
here and say why — which is exactly the conversation that should happen.

STATIC on purpose: the `BASELINE-011` collision never showed at runtime, because
the two checks fire on different conditions and `sample_data` only triggered one.
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES = ROOT / "modules"

#: check_id -> why more than one title for it is acceptable.
#:
#: Reviewed 2026-08-06. To add an entry, satisfy yourself that BOTH sites describe
#: the SAME defect and would take the SAME remediation — if they would not, the
#: second one needs its own id.
REVIEWED_MULTI_TITLE = {
    "CODE-DEV-001": "one defect, two detection paths: with and without an AGR_1251 export",
    "CRYPTO-SNC-001": "'SNC is disabled' worded twice; identical defect and remediation",
    "DPP-RAL-001": "three phrasings of 'Read Access Logging is not working'; one remediation",
    "LOG-AUD-001": "audit-log config absent vs present-but-inert; both mean 'no audit trail'",
    "LOG-SIEM-001": "SIEM config absent vs disabled; both mean 'nothing is forwarded'",
    "USR-002": "per-user branch and roll-up branch of the critical-profile check",
    # The weakest of the seven, kept because both take the same fix (upgrade the
    # connector) but worth splitting if either ever needs its own remediation text.
    "BTP-CC-008": "a named CVE and a general out-of-maintenance release; same remediation",
}

#: Two titles differing only by an interpolated value are the same title.
_NORM = re.compile(r"\{[^}]*\}|\s+")


def _literal(node):
    """Render a title argument: a plain string, or an f-string with its holes kept.

    An f-string becomes e.g. "User {} has profile {}", which `_NORM` collapses
    exactly as it collapses a real interpolation, so the per-user and roll-up
    branches of one check still read as one title.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else "{}"
            for part in node.values)
    return None


def _titles_by_id() -> dict:
    """Every (check_id, title) pair passed to a `finding(...)` call, found by AST.

    WHY THIS IS NO LONGER A REGEX
    -----------------------------
    It was two regexes, and the positional one matched ANY two adjacent
    uppercase-hyphenated string literals. That is exactly the shape of a rule
    table: `"tokens": ("AUTHORITY-CHECK", "AUTHORITY CHECK", ...)` was read as a
    check id `AUTHORITY-CHECK` carrying a title, and the guard failed on data that
    is not a check at all. With the ABAP engine's rule dicts arriving, those false
    positives were only going to multiply, and a guard that cries wolf gets
    deleted.

    An AST walk is still fully static — the point of this guard, since the
    `BASELINE-011` collision never showed at runtime — but it only ever looks at
    real calls to something named `finding`, so a table of strings cannot trip it.
    """
    found: dict = defaultdict(lambda: defaultdict(list))
    for path in sorted(MODULES.glob("*.py")):
        src = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Call):
                continue
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else getattr(node.func, "id", ""))
            if name != "finding":
                continue

            kw = {k.arg: k.value for k in node.keywords if k.arg}
            cid_node = kw.get("check_id") or (node.args[0] if node.args else None)
            title = (_literal(kw["title"]) if "title" in kw
                     else (_literal(node.args[1]) if len(node.args) > 1 else None))

            # A check_id built by an f-string (`f"ATC-{family}"`, and three
            # pre-existing ones in ara/iam/params) cannot be judged statically: at
            # runtime it is many distinct ids, and rendering it as "ATC-{}" would
            # collapse them into one and report a collision that does not exist.
            # Those are covered at RUNTIME instead, by the per-module tests that
            # assert every emitted id routes to a team. Skipping them here is a
            # real gap in this guard, and it is a smaller lie than a false alarm.
            cid = (cid_node.value
                   if isinstance(cid_node, ast.Constant) and isinstance(cid_node.value, str)
                   else None)
            if not cid or not title:
                continue

            key = _NORM.sub(" ", title).strip().lower()
            found[cid][key].append(f"{path.name}:{node.lineno}  {title[:64]}")
    return found


def test_no_new_check_id_is_reused_for_a_different_check():
    reused = {cid: t for cid, t in _titles_by_id().items() if len(t) > 1}
    unreviewed = {cid: t for cid, t in reused.items() if cid not in REVIEWED_MULTI_TITLE}
    assert not unreviewed, (
        "check id(s) used for what look like two different checks. Each id is a "
        "foreign key into the catalogue, the remediation KB and the attack-path "
        "templates, so one check silently overwrites the other.\n"
        "If both sites really are the SAME defect with the SAME remediation, add "
        "the id to REVIEWED_MULTI_TITLE with the reason. Otherwise give the second "
        "one its own id.\n"
        + "\n".join(
            f"  {cid}:\n" + "\n".join(f"      {s}" for sites in t.values() for s in sites)
            for cid, t in sorted(unreviewed.items())))


def test_the_reviewed_list_does_not_rot():
    """An entry that no longer collides has been fixed or renamed; leaving it here
    would let a future genuine collision on that id pass unnoticed."""
    reused = set(cid for cid, t in _titles_by_id().items() if len(t) > 1)
    stale = sorted(set(REVIEWED_MULTI_TITLE) - reused)
    assert not stale, (
        f"REVIEWED_MULTI_TITLE lists ids that no longer have multiple titles — "
        f"remove them so a future collision on the same id is caught: {stale}")


def test_check_ids_follow_the_house_format():
    """MODULE-SUBAREA-NNN. A stray format is a check nobody will find again."""
    bad = [cid for cid in _titles_by_id()
           if not re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", cid)]
    assert not bad, f"check ids not matching MODULE-SUBAREA-NNN: {sorted(bad)}"


# --------------------------------------------------------------------------- #
#  The stricter, orthogonal guard: one id, two FILES                          #
# --------------------------------------------------------------------------- #
#: Ids legitimately emitted from more than one module. Empty on purpose — add an
#: entry only with the reason, exactly as REVIEWED_MULTI_TITLE requires.
REVIEWED_MULTI_MODULE: dict = {}


def _ids_by_module() -> dict:
    """check_id -> {module names that emit it}, by literal, over every module."""
    out: dict = defaultdict(set)
    pattern = re.compile(r"""["']([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)["']""")
    for path in sorted(MODULES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and getattr(node.func, "attr", "") == "finding"):
                continue
            for kw in node.keywords:
                if kw.arg == "check_id" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    if pattern.fullmatch(f'"{kw.value.value}"'):
                        out[kw.value.value].add(path.name)
    return out


def test_no_check_id_is_emitted_by_two_different_modules():
    """A SEPARATE defect from id-reuse-with-a-different-title, and one that guard
    misses: two modules can pick the same id with similar enough wording to slip
    the title heuristic.

    That is what happened. `modules/resilience_posture.py` shipped LOG-RET-001 and
    LOG-IR-001, both of which already existed in `modules/log_monitoring.py` — two
    unrelated checks sharing a foreign key into the remediation knowledge base, the
    compliance mapping and the fingerprint. The title-based test passed throughout.

    Two modules reaching for one id is essentially always a mistake, so this asks
    no judgement about wording: it fails on the collision itself.
    """
    collisions = {cid: sorted(mods) for cid, mods in _ids_by_module().items()
                  if len(mods) > 1 and cid not in REVIEWED_MULTI_MODULE}
    assert not collisions, (
        "these check ids are emitted by more than one module, so they share a "
        f"remediation, a control mapping and an identity: {collisions}. Give one "
        "of them its own id, or add it to REVIEWED_MULTI_MODULE with the reason.")
