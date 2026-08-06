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

_KW = re.compile(
    r'check_id\s*=\s*"([A-Z0-9][A-Z0-9_\-]{2,})"\s*,\s*\n?\s*'
    r'title\s*=\s*f?"([^"]{6,})"')
_POS = re.compile(
    r'"([A-Z]{2,}[A-Z0-9_\-]*-[A-Z0-9]+)"\s*,\s*\n?\s*f?"([^"]{6,})"')

#: Two titles differing only by an interpolated value are the same title.
_NORM = re.compile(r"\{[^}]*\}|\s+")


def _titles_by_id() -> dict:
    found: dict = defaultdict(lambda: defaultdict(list))
    for path in sorted(MODULES.glob("*.py")):
        src = path.read_text(encoding="utf-8")
        for pattern in (_KW, _POS):
            for m in pattern.finditer(src):
                cid, title = m.group(1), m.group(2)
                key = _NORM.sub(" ", title).strip().lower()
                line = src[:m.start()].count("\n") + 1
                found[cid][key].append(f"{path.name}:{line}  {title[:64]}")
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
