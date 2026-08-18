# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Generate data/sap_notes_catalogue.json from SAP's own published CSA policies.

Run:  python -m tools.build_sap_notes_catalogue --source <extract-of-the-sap-repo>

WHY THIS EXISTS. `modules/sap_hotnews.py` carried a hand-curated catalogue of 43
notes with a `curated_through` date, and every entry in it was a place where this
product could have written down an SAP identifier that does not exist. The
standing risk in the roadmap was named exactly that: "a fabricated SAP identifier
ships". The structural fix is to stop typing them.

SAP publishes `SAP-samples/frun-csa-policies-best-practices` under Apache-2.0:
261 XML policies for Focused Run's Configuration & Security Analytics, of which
157 are security-note policies covering every ABAP and HANA patch day from
2016-01 onwards. Each one's header lists the notes it covers — number, component,
CVE, CVSS, priority tier, title, note version — AND, separately, the notes it
deliberately does not cover. Both halves are SAP's own words. This tool reads
them and writes a catalogue; nobody types a note number again.

WHAT IS TAKEN, AND WHAT IS NOT
Taken: note numbers, CVE ids, component keys, CVSS scores, priority tiers,
patch-day identifiers, titles, and which config stores SAP's own policy reads to
answer each note.

Also taken: the AFFECTED-VERSION FACTS the predicates encode — that note 3772411
is fixed in SAP_BASIS 750 at support package 37, 752 at 19, 753 at 17, and so on.

NOT taken: SAP's SQL as SQL. A CSA policy's `<compliant>` clause is a SQL
expression evaluated against Focused Run's own configuration database, which
this product does not have and does not emulate. Nothing here is executed, and
no claim of Focused Run parity is made or implied.

WHERE THAT LINE IS, AND WHY IT MOVED
This tool originally took none of the predicates at all, on the reasoning that
they were SAP's implementation. That was too broad. "Note 3772411 is fixed in
SAP_BASIS 750 at SP 37" is a FACT about a note, of exactly the same kind as
"note 3772411 is CVE-2026-58243" — it happens to be written in SQL because
Focused Run needed it executable. Refusing to read a fact because of the
notation it arrived in left this product unable to answer the only question that
matters about a note, which is whether it applies here.

So the fact is extracted and the comparison is this product's own Python,
against the customer's own `system_component.csv`. What is still refused: running
SAP's expressions, reproducing them verbatim, and saying we implement SAP's
policies. `between`-range predicates are deliberately NOT interpreted — an
"affected between SP 1 and SP 17" clause needs reasoning about whether a higher
level is also affected, and guessing there would put a wrong verdict in front of
somebody. Those are counted in the metadata as unextracted, not silently
skipped.

WHY THE CONFIG STORES ARE WORTH READING
`<configstore name="...">` names the data SAP consults for a note, and its
vocabulary is small: `COMP_LEVEL` (2448 uses) is component support-package
levels, `ABAP_NOTES` (1253) is note implementation status, `SAP_KERNEL` (99) is
kernel release and patch level. The first two are exports this product already
reads. So the catalogue can say, per note, whether the data needed to answer it
is something the customer already supplies — which turns "we have 1700 notes"
into "we can act on these, and these need one more export".

That measurement also corrected a decision. The kernel-version source was
measured against the OLD 43-note catalogue as unlocking exactly one note, and
left unhooked on that basis. Against SAP's own policies it is 99 check items.
The number was right and the denominator was wrong.

THE HEADERS ARE NOT UNIFORM, AND THAT IS THE HARD PART
Ten years of files written by different people in different tools:

  2016-2018  UTF-16LE, bare note numbers one per line, no metadata at all
  2017       half-year rollups listing note numbers many to a line
  2019-2020  `0002524203 - FI-CA - [CVE-2019-0304] Title`, sometimes with a
             space instead of the first dash, sometimes with no component
  2021+      `[p1-CVSS 9.9] 0003747367 BC-FES-ITS - [CVE-...] Title (Version 12)`
             with a comma decimal separator in the 2021 files

Every pattern below exists because a real file needed it. `--strict` fails the
build on any header line that looks like a note and did not parse, so a new
format in next month's patch day is a build failure rather than a silent gap.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "data" / "sap_notes_catalogue.json"

# ═════════════════════════════════════════════════════════════════════════════
#  Header grammar — one pattern per era, tried in order
# ═════════════════════════════════════════════════════════════════════════════

#: 2021+. `n/a` appears where SAP publishes no score; the comma decimal is the
#: 2021 files, which were evidently written on a German locale.
MODERN = re.compile(
    # The bracket is optional-plural and the separator before the score may be a
    # dash: SAP's own files carry `[p3-CVSS 6.3]]`, `[p3-CVSS 5.8` with no
    # closing bracket at all, and `[p2-CVSS-7.5]`. Each is a real note line, and
    # refusing them would drop notes over a typo in somebody else's file.
    r"^\[\s*p(?P<prio>\d)\s*-?\s*CVSS[\s-]+(?P<cvss>[\d.,]+|n/?a)\s*\]*\s+"
    r"(?P<note>\d{6,10})\s*-?\s*"
    r"(?P<component>[A-Z0-9][A-Z0-9\-]*)?\s*-?\s*"
    r"(?P<rest>.*)$", re.IGNORECASE)
#: 2019-2020, note and component separated by a dash OR a bare space.
MIDDLE = re.compile(
    r"^(?P<note>\d{6,10})\s*[-\s]\s*"
    r"(?P<component>[A-Z]{2}[A-Z0-9\-]*)\s*-\s*"
    r"(?P<rest>.*)$", re.IGNORECASE)
#: A note number followed by free text and no component at all. The separator
#: may be absent entirely — the 2019 HANA files write `2798243-[CVE-2019-0350]`.
#: The rest must not be another bare number, or a two-note line that RUN did not
#: match would be read as one note plus a title made of digits.
LOOSE = re.compile(r"^(?P<note>\d{6,10})\s*-?\s*(?!\d+\s*$)(?P<rest>\S.*)$")
#: 2016-2018, a note number alone on its line.
BARE = re.compile(r"^(?P<note>\d{6,10})$")
#: 2017 half-year rollups: many note numbers to a line.
RUN = re.compile(r"^\d{6,10}(?:\s+\d{6,10})+$")

CVE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
#: The line that divides "contains rules to check the following" from what SAP
#: deliberately leaves alone — almost always the non-ABAP stack (Commerce Cloud,
#: BusinessObjects, MII, Java). Everything after it is recorded as NOT checked.
NOT_CHECKED = re.compile(r"does not check", re.IGNORECASE)
TARGET = re.compile(r'<targetsystem[^>]*\bid="([^"]+)"', re.IGNORECASE)
CONFIGSTORE = re.compile(r'<configstore[^>]*\bname="([^"]+)"', re.IGNORECASE)
CHECKITEM = re.compile(r'<checkitem[^>]*\bid="([^"]+)"', re.IGNORECASE)
#: `<checkitem id="0003747367_k">` — note number, optionally suffixed.
CHECKITEM_NOTE = re.compile(r"^0*(\d{6,10})")

# ═════════════════════════════════════════════════════════════════════════════
#  Fix levels — the affected-version facts, however the predicate spells them
# ═════════════════════════════════════════════════════════════════════════════

#: `COMPONENT = 'SAP_BASIS' and VERSION = '750'` opens a clause about one
#: component at one release. Everything up to the next such pair belongs to it.
_COMP_HEAD = re.compile(
    r"COMPONENT\s*=\s*'([^']+)'\s*and\s*VERSION\s*=\s*'([^']+)'", re.IGNORECASE)
#: The support-package threshold inside that clause. SAP writes it four ways —
#: `not( lpad(SP,4,'0') < '0037' )` in a compliant clause, `to_integer(
#: COALESCE(NULLIF(SP,''),'0') ) < 22` in a noncompliant one, the same wrapped in
#: `not(...)`, and a REPLACE_REGEXPR variant — and the NUMBER MEANS THE SAME
#: THING in all of them: the first support package that carries the fix. That is
#: why one threshold pattern is enough and the surrounding SQL can be ignored.
_SP_THRESHOLD = re.compile(r"(?:&lt;|<)\s*'?(\d{1,5})'?")
#: An affected RANGE. Not interpreted — see the docstring.
_BETWEEN = re.compile(r"\bbetween\b", re.IGNORECASE)

#: `substring(VALUE,0,7) = '2.00.00' AND substring(VALUE,0,14) >= '2.00.001.0'`
#: — the HANA branch prefix and the first revision carrying the fix. SAP compares
#: a truncated version string; what is taken here is the PAIR, and the comparison
#: against an installed revision is this product's own, done on integer segments
#: rather than by string ordering.
_HANA_FIX = re.compile(
    r"substring\s*\(\s*VALUE\s*,\s*\d+\s*,\s*\d+\s*\)\s*=\s*'([^']+)'"
    r"\s*AND\s*substring\s*\(\s*VALUE\s*,\s*\d+\s*,\s*\d+\s*\)"
    r"\s*(?:&gt;=|>=)\s*'([^']+)'", re.IGNORECASE)

#: `NAME = 'KERN_PATCHLEVEL' and lpad(VALUE,4,'0') >= '1518'`
_KERN_PATCH = re.compile(
    r"NAME\s*=\s*'KERN_PATCHLEVEL'\s*and\s*lpad\s*\(\s*VALUE\s*,\s*\d+\s*,"
    r"\s*'0'\s*\)\s*(?:&gt;=|>=)\s*'(\d+)'", re.IGNORECASE)
#: The kernel release the patch level applies to, from the joined store.
_KERN_REL = re.compile(
    r"NAME\s*=\s*'KERN_REL'\s*and\s*VALUE\s*(?:like|=)\s*'([^']+)'", re.IGNORECASE)

_STORE_BLOCK = re.compile(
    r'<configstore[^>]*\bname="([^"]+)"[^>]*>(.*?)</configstore>', re.S | re.I)
_CHECKITEM_BLOCK = re.compile(
    r'<checkitem[^>]*\bid="([^"]+)"[^>]*>(.*?)</checkitem>', re.S | re.I)
_COMPLIANT = re.compile(r"<compliant>(.*?)</compliant>", re.S | re.I)
_NONCOMPLIANT = re.compile(r"<noncompliant>(.*?)</noncompliant>", re.S | re.I)


def _component_levels(blob: str):
    """(component, release, first-fixed-SP) triples from one predicate blob."""
    out, heads = [], [(m.start(), m.group(1).upper(), m.group(2))
                      for m in _COMP_HEAD.finditer(blob)]
    for index, (start, component, release) in enumerate(heads):
        end = heads[index + 1][0] if index + 1 < len(heads) else len(blob)
        window = blob[start:end]
        if _BETWEEN.search(window):
            continue
        threshold = _SP_THRESHOLD.search(window)
        if threshold:
            out.append((component, release, int(threshold.group(1))))
    return out


#: SAP's config-store names against the export this product reads to answer the
#: same question. Only the stores that appear in the notes policies are mapped;
#: a store with no entry here is recorded as unmapped rather than guessed at.
#: Source keys are asserted against the loader at build time, so renaming one
#: without updating this table fails the build instead of silently unmapping it.
CONFIGSTORE_SOURCES = {
    "COMP_LEVEL": "system_component",
    "ABAP_NOTES": "applied_notes",
    "ABAP_INSTANCE_PAHI": "security_params",
    "CRYPTOLIB": "crypto_library",
    "HDB_PARAMETER": "hana_parameters",
    "GW_REGINFO": "gw_reginfo",
    "GW_SECINFO": "gw_secinfo",
    "SAP_KERNEL": "sap_kernel",
    "HDB_VERSION": "hana_version",
}
#: Config stores with no export behind them yet, and what each would need. Kept
#: explicit so the catalogue can count what a missing export costs rather than
#: leaving the note looking unanswerable.
CONFIGSTORE_UNMAPPED = {
    "SAPUI5_VERSION": "SAPUI5 version",
    "BOBJ_VERSION": "BusinessObjects version",
    "ABAP_UR_VERSION": "Unified Rendering version",
    "igsmanifest.mf": "Internet Graphics Server build",
    "Parameters": "a generic parameter store; the policy does not say which",
}


def read(path: Path) -> str:
    """Decode a policy file. The 2016-2018 ones are UTF-16 with a BOM."""
    raw = path.read_bytes()
    for bom, enc in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"),
                     (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(enc, errors="replace")
    return raw.decode("utf-8", errors="replace")


def _stack(path: Path) -> str:
    parts = {p.upper() for p in path.parts}
    if "HANA" in parts:
        return "HANA"
    if "ABAP" in parts:
        return "ABAP"
    return "OTHER"


def _clean_title(rest: str) -> str:
    """The note title, with the CVE bracket and trailing version removed."""
    text = re.sub(r"\[(CVE-[^\]]*|Multiple CVEs)\]", "", rest, flags=re.I)
    text = re.sub(r"\(\s*Version\s+\d+\s*\)\s*$", "", text, flags=re.I)
    text = re.sub(r"\(\+\s*manual activity\s*\)", "", text, flags=re.I)
    return " ".join(text.split()).strip(" -–—")


def parse_policy(path: Path, strict_errors: list) -> dict:
    """One policy file: its notes, and the config stores it reads per note."""
    text = read(path)
    head = text.split("-->", 1)[0]
    target = TARGET.search(text)
    patchday = target.group(1) if target else path.stem

    entries, checking = [], True
    for raw in head.splitlines():
        line = raw.strip()
        if not line or line.startswith("<"):
            continue
        if NOT_CHECKED.search(line):
            checking = False
            continue
        if RUN.match(line):
            entries.extend({"note": n.lstrip("0"), "checked": checking}
                           for n in line.split())
            continue
        match = (MODERN.match(line) or MIDDLE.match(line)
                 or BARE.match(line) or LOOSE.match(line))
        if not match:
            if re.match(r"^\[?\s*p\d\s*-?\s*CVSS|^\d{6,10}\b", line):
                strict_errors.append("%s: %s" % (path.name, line[:120]))
            continue
        got = match.groupdict()
        rest = got.get("rest") or ""
        cve = CVE.search(rest)
        cvss = (got.get("cvss") or "").replace(",", ".")
        entries.append({
            "note": got["note"].lstrip("0"),
            "checked": checking,
            "component": (got.get("component") or "").upper() or None,
            "cve": cve.group(1).upper() if cve else None,
            "cvss": float(cvss) if re.match(r"^\d+(\.\d+)?$", cvss) else None,
            "priority": int(got["prio"]) if got.get("prio") else None,
            "title": _clean_title(rest) or None,
        })

    # Fix levels, per note, from whichever clause the item carries. 1,220 items
    # use a `between` range and are counted rather than guessed at.
    levels: dict = {}
    ranges = 0
    for store_name, block in _STORE_BLOCK.findall(text):
        for item_id, item in _CHECKITEM_BLOCK.findall(block):
            note_match = CHECKITEM_NOTE.match(item_id)
            if not note_match:
                continue
            note = note_match.group(1)
            blob = (" ".join(_COMPLIANT.findall(item))
                    or " ".join(_NONCOMPLIANT.findall(item)))
            if not blob:
                continue
            if store_name == "COMP_LEVEL":
                if _BETWEEN.search(blob):
                    ranges += 1
                for triple in _component_levels(blob):
                    levels.setdefault(note, {}).setdefault(
                        "components", set()).add(triple)
            elif store_name == "HDB_VERSION":
                for branch, minimum in _HANA_FIX.findall(blob):
                    levels.setdefault(note, {}).setdefault(
                        "hana", set()).add((branch, minimum))
            elif store_name == "SAP_KERNEL":
                patch = _KERN_PATCH.search(blob)
                if patch:
                    releases = _KERN_REL.findall(item) or ["*"]
                    for release in releases:
                        levels.setdefault(note, {}).setdefault(
                            "kernel", set()).add((release, int(patch.group(1))))

    # Config stores, attributed to the note whose check item names them. A
    # <configstore> element wraps its check items, so the nearest preceding
    # store name is the one that applies.
    stores: dict = {}
    current = None
    for match in re.finditer(r"<configstore[^>]*\bname=\"([^\"]+)\"|"
                             r"<checkitem[^>]*\bid=\"([^\"]+)\"", text, re.I):
        if match.group(1):
            current = match.group(1)
            continue
        note = CHECKITEM_NOTE.match(match.group(2) or "")
        if note and current:
            stores.setdefault(note.group(1), set()).add(current)

    return {"patchday": patchday, "stack": _stack(path), "file": path.name,
            "entries": entries, "stores": stores, "levels": levels,
            "ranges": ranges}


def build(source: Path, strict: bool = False) -> str:
    from modules.data_loader import DataLoader

    unknown = sorted(set(CONFIGSTORE_SOURCES.values()) - set(DataLoader.FILE_MAP))
    if unknown:
        raise SystemExit(
            "CONFIGSTORE_SOURCES names loader sources that do not exist: %s.\n"
            "A source was renamed; update the table rather than leaving the "
            "config store silently unmapped." % unknown)

    files = sorted(p for p in source.glob("NotesPolicies/**/*.xml"))
    if not files:
        raise SystemExit("no NotesPolicies/**/*.xml under %s — is this an "
                         "extract of SAP-samples/frun-csa-policies-best-practices?"
                         % source)

    strict_errors: list = []
    notes: dict = {}
    patchdays = set()
    range_items = 0
    unattributable = 0
    for path in files:
        policy = parse_policy(path, strict_errors)
        patchdays.add(policy["patchday"])
        range_items += policy["ranges"]
        for entry in policy["entries"]:
            rec = notes.setdefault(entry["note"], {
                "cve": [], "component": None, "cvss": None, "priority": None,
                "title": None, "patch_days": [], "stacks": [],
                "checked_by_sap_policy": False, "config_stores": [],
                "fix_levels": [], "kernel_fix": [], "hana_fix": [],
            })
            if entry.get("cve") and entry["cve"] not in rec["cve"]:
                rec["cve"].append(entry["cve"])
            for field in ("component", "cvss", "priority", "title"):
                if rec[field] is None and entry.get(field) is not None:
                    rec[field] = entry[field]
            if policy["patchday"] not in rec["patch_days"]:
                rec["patch_days"].append(policy["patchday"])
            if policy["stack"] not in rec["stacks"]:
                rec["stacks"].append(policy["stack"])
            rec["checked_by_sap_policy"] |= bool(entry["checked"])
        for note, found in policy["levels"].items():
            rec = notes.get(note)
            if rec is None:
                # SAP's own files carry at least one malformed check-item id —
                # `id="00022704878"`, which is note 2704878 with a stray zero —
                # and it names no note any header declared. Attaching it by
                # guessing which note was meant is exactly the kind of inference
                # this catalogue exists to avoid, so it is counted and dropped
                # rather than repaired. One note loses its fix levels and the
                # number is visible, which is the honest trade.
                unattributable += 1
                continue
            for component, release, sp in sorted(found.get("components", ())):
                row = {"component": component, "release": release, "min_sp": sp}
                if row not in rec["fix_levels"]:
                    rec["fix_levels"].append(row)
            for release, patch in sorted(found.get("kernel", ())):
                row = {"release": release, "min_patch": patch}
                if row not in rec["kernel_fix"]:
                    rec["kernel_fix"].append(row)
            for branch, minimum in sorted(found.get("hana", ())):
                row = {"branch": branch, "min_revision": minimum}
                if row not in rec["hana_fix"]:
                    rec["hana_fix"].append(row)
        for note, stores in policy["stores"].items():
            rec = notes.get(note)
            if rec is None:
                continue
            for store in sorted(stores):
                if store not in rec["config_stores"]:
                    rec["config_stores"].append(store)

    for rec in notes.values():
        rec["fix_levels"].sort(key=lambda r: (r["component"], r["release"]))
        rec["kernel_fix"].sort(key=lambda r: r["release"])
        rec["hana_fix"].sort(key=lambda r: r["branch"])
        rec["cve"].sort()
        rec["patch_days"].sort()
        rec["stacks"].sort()
        rec["config_stores"].sort()
        sources = sorted({CONFIGSTORE_SOURCES[s] for s in rec["config_stores"]
                          if s in CONFIGSTORE_SOURCES})
        missing = sorted({s for s in rec["config_stores"]
                          if s not in CONFIGSTORE_SOURCES})
        rec["answerable_from"] = sources
        rec["needs_unmapped_store"] = missing

    if strict and strict_errors:
        raise SystemExit(
            "%d header line(s) look like a note and did not parse. A new header "
            "format is a build failure, not a silent gap:\n  %s"
            % (len(strict_errors), "\n  ".join(strict_errors[:20])))

    store_counts = collections.Counter(
        s for rec in notes.values() for s in rec["config_stores"])
    meta = {
        "source": "SAP-samples/frun-csa-policies-best-practices",
        "source_path": "NotesPolicies/**/*.xml",
        "licence": ("Apache-2.0, Copyright (c) 2020 SAP SE or an SAP affiliate "
                    "company. Derived metadata only."),
        "what_this_is": (
            "SAP's own published list of security notes per patch day: note "
            "number, CVE, component, CVSS, priority tier, title, and which "
            "Focused Run config stores SAP reads to answer each one. Generated "
            "by tools/build_sap_notes_catalogue.py — no note number in this "
            "file was typed by hand."),
        "what_this_is_not": (
            "Not SAP's checks. The SQL predicates in the policies run against "
            "Focused Run's configuration database, which this product does not "
            "have and does not emulate; they are deliberately not reproduced. "
            "The checks in modules/ read exported files and are this product's "
            "own."),
        "checked_by_sap_policy": (
            "SAP's own declaration, taken from the 'The policy does not check "
            "the following' split in each header. False almost always means the "
            "note is for a non-ABAP stack (Commerce Cloud, BusinessObjects, "
            "MII, Java), not that the note is unimportant."),
        "counts": {
            "policy_files": len(files),
            "patch_days": len(patchdays),
            "notes": len(notes),
            "with_cve": sum(1 for r in notes.values() if r["cve"]),
            "with_cvss": sum(1 for r in notes.values() if r["cvss"] is not None),
            "checked_by_sap_policy": sum(
                1 for r in notes.values() if r["checked_by_sap_policy"]),
            "answerable_from_a_supplied_export": sum(
                1 for r in notes.values() if r["answerable_from"]),
            "blocked_only_by_an_unmapped_store": sum(
                1 for r in notes.values()
                if r["needs_unmapped_store"] and not r["answerable_from"]),
            "with_component_fix_levels": sum(
                1 for r in notes.values() if r["fix_levels"]),
            "component_release_sp_triples": sum(
                len(r["fix_levels"]) for r in notes.values()),
            "with_kernel_fix_levels": sum(
                1 for r in notes.values() if r["kernel_fix"]),
            "with_hana_fix_levels": sum(
                1 for r in notes.values() if r["hana_fix"]),
            "check_items_with_an_unattributable_id": unattributable,
            "check_items_using_an_uninterpreted_range": range_items,
        },
        "fix_levels": (
            "The first support package carrying the fix, per component and "
            "release, extracted from the affected-version facts SAP's predicates "
            "encode. SAP's SQL is neither executed nor reproduced; the "
            "comparison against system_component.csv is this product's own. "
            "`between`-range predicates are not interpreted and are counted "
            "above as check_items_using_an_uninterpreted_range."),
        "config_store_usage": dict(store_counts.most_common()),
        "config_store_sources": CONFIGSTORE_SOURCES,
        "config_store_unmapped": CONFIGSTORE_UNMAPPED,
        "unparsed_header_lines": len(strict_errors),
    }
    return json.dumps({"_meta": meta, "notes": notes},
                      indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True, type=Path,
                        help="extract of SAP-samples/frun-csa-policies-best-practices")
    parser.add_argument("--strict", action="store_true",
                        help="fail if any note-shaped header line did not parse")
    parser.add_argument("--check", action="store_true",
                        help="fail if the file on disk is not what this would write")
    args = parser.parse_args(argv)

    text = build(args.source, strict=args.strict)
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("data/sap_notes_catalogue.json is out of date", file=sys.stderr)
            return 1
        print("data/sap_notes_catalogue.json is current")
        return 0

    OUT.write_text(text, encoding="utf-8")
    meta = json.loads(text)["_meta"]["counts"]
    print("Wrote %s: %d notes from %d policy files over %d patch days "
          "(%d with a CVE, %d answerable from an export you already supply, "
          "%d with component fix levels over %d component/release/SP triples)"
          % (OUT.name, meta["notes"], meta["policy_files"], meta["patch_days"],
             meta["with_cve"], meta["answerable_from_a_supplied_export"],
             meta["with_component_fix_levels"],
             meta["component_release_sp_triples"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
