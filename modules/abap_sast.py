"""
ABAP / UI5 source scanning
==========================
Our own code scanner, for customers who do not have SAP's Code Vulnerability
Analyzer. Where they do, ``modules/atc_import.py`` ingests SAP's own results and
should be preferred — those findings cost nothing and carry no false positives of
our making.

Input is an **abapGit offline ZIP export** unpacked to a directory: the one route
by which ABAP source leaves a RISE PCE system with no OS access, no outbound
network and no SAP ticket.

────────────────────────────────────────────────────────────────────────────────
WHY THIS FILE EXISTS RATHER THAN THE UPSTREAM SCANNER
────────────────────────────────────────────────────────────────────────────────
The rule corpus came across intact (``modules/abap_sast_rules.py``). The scanning
core did not, because the upstream one analysed **one line of text at a time** and
ABAP statements are not lines — they end at a period and routinely span four or
five lines. Measured on the upstream engine, that single decision produced both
failure modes at once:

    " one line  ->  CRITICAL, data-flow confirmed
    SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).

    " the same statement, formatted the way real ABAP is written  ->  NOTHING
    SELECT *
      FROM mara
      WHERE (lv_where)
      INTO TABLE @DATA(lt).

and, in the other direction, 50 lines of secure idiomatic ABAP produced three
HIGH findings — two "DES encryption" hits caused by the letters ``des`` inside
``lv_modes`` and ``lt_codes``, in a file containing no cryptography at all.

So this module keeps the patterns and changes the unit they are matched against:

1. **Statements, not lines.** Comments are stripped, string literals are respected,
   and the text is split on statement-terminating periods. A rule now sees the
   whole statement regardless of how it was wrapped.
2. **Word boundaries.** ``PATTERN_FIXES`` repairs rules whose regex was anchored on
   only one side, which is what let ``des`` match inside an identifier.
3. **Block-scoped guards.** Five rules are named "... without AUTHORITY-CHECK" but
   only one carried the metadata to check for one. All five now look at the
   enclosing FORM / METHOD / FUNCTION before firing.

None of this makes the analysis interprocedural. It is statement-pattern matching
with optional intra-procedural taint refinement, and that is what it should be
called in front of a customer — the competitors ship global data-flow analysis and
this does not.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules.abap_sast_rules import (
    ALL_ABAP_SAST_RULES,
    ALL_BTP_CONFIG_RULES,
    ALL_JS_RULES,
    TaintAnalyzer,
)
from modules.base_auditor import BaseAuditor

# --------------------------------------------------------------------------- #
#  What an abapGit export actually contains                                   #
# --------------------------------------------------------------------------- #

#: Source we analyse. The upstream set stopped at `.ddls.abap`/`.dcls.abap`, which
#: abapGit does not produce — it writes `.asddls` and `.asdcls`, so CDS coverage
#: was silently zero on every real export.
ABAP_SUFFIXES: Tuple[str, ...] = (
    ".abap", ".abp",
    ".asddls",      # CDS data definition
    ".asdcls",      # CDS access control (DCL)
    ".asbdef",      # RAP behaviour definition
    ".aclrl",       # authorisation object / role content
    ".cds",
)
JS_SUFFIXES: Tuple[str, ...] = (".js", ".ts", ".xml.js")
DESCRIPTOR_NAMES: Tuple[str, ...] = (
    "xs-security.json", "xs-app.json", "mta.yaml", "mta.yml", "manifest.json",
)

#: abapGit writes one XML sidecar per object carrying its metadata. They are not
#: source and are deliberately not scanned — but they ARE counted, because
#: "skipped silently" and "nothing to scan" look identical in a report and only one
#: of them is true.
METADATA_SUFFIXES: Tuple[str, ...] = (".xml",)

#: Rules whose regex was anchored on one side only, so it matched inside an
#: identifier. Keyed by rule id; the value replaces `pattern`.
#:
#: Fixed here rather than in the vendored corpus so that re-deriving the corpus
#: from the upstream repository cannot silently undo the fix.
PATTERN_FIXES: Dict[str, str] = {
    # `(?:DES|3DES|TRIPLE.?DES)\b` has no LEADING boundary, so the `des` in
    # `lv_modes` and `lt_codes` matched and reported HIGH "DES encryption".
    "ABAP-CRYP-003": r"\b(?:3DES|TRIPLE.?DES|DES)\b",
}

#: Rules named "... without AUTHORITY-CHECK" whose pattern cannot express the
#: "without" half. Only ABAP-AUTH-001 shipped with the metadata to check; the other
#: four fired on every UPDATE/DELETE/INSERT/RFC call in the estate, guarded or not.
AUTHORITY_GUARDED: Tuple[str, ...] = (
    "ABAP-AUTH-001", "ABAP-AUTH-004", "ABAP-AUTH-005",
    "ABAP-AUTH-006", "ABAP-AUTH-007",
)

_AUTHORITY_CHECK = re.compile(r"\bAUTHORITY[-\s]?CHECK\b", re.IGNORECASE)

#: Statements that open and close a processing block. A guard inside one FORM does
#: not protect a sink in the next one.
_BLOCK_OPEN = re.compile(
    r"^\s*(?:FORM|METHOD|FUNCTION|MODULE)\b", re.IGNORECASE)
_BLOCK_CLOSE = re.compile(
    r"^\s*(?:ENDFORM|ENDMETHOD|ENDFUNCTION|ENDMODULE)\b", re.IGNORECASE)

_NOSEC = re.compile(r"#NOSEC(?P<ids>(?:\s+[A-Z0-9][A-Z0-9\-]*,?)*)", re.IGNORECASE)


class Statement:
    """One ABAP statement, with the source it came from."""

    __slots__ = ("text", "line", "raw", "block", "nosec")

    def __init__(self, text: str, line: int, raw: str, block: int,
                 nosec: Optional[List[str]]):
        #: Comments stripped, newlines collapsed — what the rules match against.
        self.text = text
        #: 1-based line where the statement STARTS. Display only; never identity.
        self.line = line
        #: The statement as written, for the report snippet.
        self.raw = raw
        #: Index of the enclosing processing block, for block-scoped guards.
        self.block = block
        #: Rule ids suppressed by a `#NOSEC` marker, or [] for "all rules".
        self.nosec = nosec


def split_statements(source: str) -> List[Statement]:
    """Split ABAP source into statements.

    ABAP terminates a statement with a period. The only things that make this
    non-trivial are the three places a period does not terminate anything:
    inside a string literal, inside a comment, and between two digits.

    Comments: a `*` in column 1 comments the whole line; a `"` outside a string
    literal comments the rest of it. Both are removed before splitting, so a
    commented-out `SELECT` cannot raise a finding — the upstream engine's habit of
    matching commented code was a quiet contributor to its noise.
    """
    statements: List[Statement] = []
    buf: List[str] = []
    raw: List[str] = []
    start_line = 1
    block = 0
    pending_nosec: List[str] = []
    have_nosec = False

    for lineno, line in enumerate(source.splitlines(), start=1):
        if not buf:
            start_line = lineno

        marker = _NOSEC.search(line)
        if marker:
            ids = [i.strip().rstrip(",").upper()
                   for i in marker.group("ids").split() if i.strip()]
            pending_nosec, have_nosec = ids, True

        code = _strip_comments(line)
        raw.append(line)

        if not code.strip():
            if not "".join(buf).strip():
                buf, raw = [], []
            continue

        buf.append(code)
        joined = " ".join(" ".join(buf).split())

        # Emit each complete statement in the buffer.
        while True:
            end = _terminator(joined)
            if end is None:
                break
            text, joined = joined[:end].strip(), joined[end + 1:].strip()
            if text:
                if _BLOCK_OPEN.match(text):
                    block += 1
                statements.append(Statement(
                    text, start_line, "\n".join(raw).strip(), block,
                    pending_nosec if have_nosec else None))
                if _BLOCK_CLOSE.match(text):
                    block += 1
            pending_nosec, have_nosec = [], False
            raw = []
            start_line = lineno
        buf = [joined] if joined else []

    trailing = " ".join(" ".join(buf).split()).strip()
    if trailing:
        statements.append(Statement(trailing, start_line, "\n".join(raw).strip(),
                                    block, pending_nosec if have_nosec else None))
    return statements


def _strip_comments(line: str) -> str:
    """Remove ABAP comments, respecting string literals."""
    if line[:1] == "*":
        return ""
    out: List[str] = []
    quote: Optional[str] = None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch == "'" or ch == "`":
            quote = ch
            out.append(ch)
            continue
        if ch == '"':
            break                      # comment to end of line
        out.append(ch)
    return "".join(out)


def _terminator(text: str) -> Optional[int]:
    """Index of the statement-terminating period, or None.

    Skips periods inside string literals and between two digits, so `'a.b'` and
    a decimal literal do not chop a statement in half.
    """
    quote: Optional[str] = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'`":
            quote = ch
        elif ch == ".":
            before = text[i - 1] if i else ""
            after = text[i + 1] if i + 1 < len(text) else ""
            if before.isdigit() and after.isdigit():
                continue               # decimal literal
            return i
    return None


class AbapSourceScanner:
    """Statement-level pattern matching with optional taint refinement."""

    def __init__(self, *, data_flow: bool = True):
        self.data_flow = data_flow
        self._compiled: Dict[str, Any] = {}
        self.files_scanned = 0
        self.metadata_skipped = 0
        self.unreadable: List[str] = []

    def _pattern(self, rule: Dict[str, Any]):
        rid = rule["id"]
        if rid not in self._compiled:
            src = PATTERN_FIXES.get(rid, rule["pattern"])
            self._compiled[rid] = re.compile(src, re.IGNORECASE)
        return self._compiled[rid]

    # ------------------------------------------------------------------ #

    def scan_tree(self, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            name = path.name.lower()
            if name.endswith(METADATA_SUFFIXES):
                self.metadata_skipped += 1
                continue
            if name.endswith(ABAP_SUFFIXES):
                rules = ALL_ABAP_SAST_RULES
            elif name.endswith(JS_SUFFIXES):
                rules = ALL_JS_RULES
            elif name in DESCRIPTOR_NAMES:
                rules = ALL_BTP_CONFIG_RULES
            else:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:                       # noqa: PERF203
                self.unreadable.append(f"{path}: {exc}")
                continue
            self.files_scanned += 1
            findings.extend(self.scan_text(text, path, rules))
        return findings

    def scan_text(self, source: str, path: Path,
                  rules: Iterable[Dict[str, Any]] = ALL_ABAP_SAST_RULES
                  ) -> List[Dict[str, Any]]:
        statements = split_statements(source)
        guarded_blocks = {
            st.block for st in statements if _AUTHORITY_CHECK.search(st.text)}

        out: List[Dict[str, Any]] = []
        for rule in rules:
            rid = rule["id"]
            pattern = self._pattern(rule)
            for st in statements:
                if not pattern.search(st.text):
                    continue
                # Named "... without AUTHORITY-CHECK": honour the "without".
                if rid in AUTHORITY_GUARDED and st.block in guarded_blocks:
                    continue
                suppressed = st.nosec is not None and (
                    not st.nosec or rid.upper() in st.nosec)
                out.append({
                    "rule_id": rid,
                    "name": rule["name"],
                    "category": rule.get("category", ""),
                    "severity": rule["severity"],
                    "cwe": rule.get("cwe"),
                    "file": str(path),
                    "object": _object_name(path),
                    "line": st.line,
                    "statement": st.text[:400],
                    "snippet": st.raw[:600],
                    "description": rule.get("description", ""),
                    "recommendation": rule.get("recommendation", ""),
                    # `pattern-only` until taint says otherwise. The evidence class
                    # is the single most decision-relevant field a SAST finding has.
                    "confidence": "pattern-only",
                    "flow": None,
                    "suppressed_by_nosec": suppressed,
                })

        if self.data_flow:
            self._refine(out, source)
        return out

    def _refine(self, findings: List[Dict[str, Any]], source: str) -> None:
        """Ask the taint analyzer about the 8 rules that carry a sink.

        A verdict is only ever ADDED — `confirmed` when tainted input reaches the
        sink, `tentative` when the walk found no evidence either way. Nothing is
        deleted on the strength of a sanitizer, because the walk is
        path-insensitive: upstream, a sanitizer inside an `IF` branch silently
        removed a genuine injection. A tool that hides findings it is not sure
        about is worse than one that grades them.
        """
        sinks = {r["id"] for r in ALL_ABAP_SAST_RULES if r.get("_taint_sink")}
        relevant = [f for f in findings if f["rule_id"] in sinks]
        if not relevant:
            return
        try:
            analyzer = TaintAnalyzer(source.splitlines())
        except Exception:                                # noqa: BLE001
            return
        for finding in relevant:
            try:
                verdict = analyzer.refine(finding["line"])   # type: ignore[attr-defined]
            except Exception:                            # noqa: BLE001
                continue
            if not verdict:
                continue
            state, flow = verdict if isinstance(verdict, tuple) else (verdict, None)
            if state:
                finding["confidence"] = state
                finding["flow"] = flow


def _object_name(path: Path) -> str:
    """The ABAP object an abapGit file belongs to.

    `zcl_thing.clas.abap` -> `ZCL_THING`. The object is a durable SAP name and is
    what a finding is ABOUT; the file name and line are display detail.
    """
    return path.name.split(".")[0].upper()


# --------------------------------------------------------------------------- #
#  Host contract                                                              #
# --------------------------------------------------------------------------- #

class AbapSastAuditor(BaseAuditor):
    """Emits host findings from an unpacked abapGit export.

    IDENTITY — WHY THE LINE NUMBER IS NOWHERE NEAR IT
    The subject is the ABAP OBJECT and the qualifier is the normalised offending
    statement. Line numbers move on every edit above them; the statement text does
    not. This is the upstream engine's own conclusion — its baseline fingerprint
    was already `rule|file|normalised-line` and explicitly line-number-independent
    — expressed through the host's existing subject/qualifier contract, so
    `server/identity.py` needed no change at all.

    SCOPE — WHY MOST FINDINGS ARE AGGREGATES
    Taint-*confirmed* findings are per-statement `scope="object"`: there is real
    evidence, and each one is worth tracking on its own. Everything else — which is
    all but the 8 rules carrying a sink — is `scope="aggregate"`, one finding per
    (rule × object), naming its occurrences as members. A 200k-line estate would
    otherwise produce thousands of individually-tracked pattern hits, and the FAIR
    figure is priced on the unfiltered set.
    """

    #: The directory holding an unpacked abapGit export, supplied via
    #: `--abap-src`. Absent means the module has nothing to do, which the coverage
    #: manifest states rather than passing over in silence.
    SOURCE_KEY = "abap_source_dir"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        root = self.data.get(self.SOURCE_KEY)
        if not root:
            return self.findings

        path = Path(root)
        if not path.is_dir():
            return self.findings

        scanner = AbapSourceScanner(data_flow=True)
        raw = scanner.scan_tree(path)
        self._emit(raw, scanner)
        return self.findings

    def _emit(self, raw: List[Dict[str, Any]], scanner: AbapSourceScanner) -> None:
        confirmed = [f for f in raw if f["confidence"] == "confirmed"]
        rest = [f for f in raw if f["confidence"] != "confirmed"]

        for f in confirmed:
            self._finding(f, [f], scope="object")

        grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for f in rest:
            grouped.setdefault((f["rule_id"], f["object"]), []).append(f)
        for (_rid, _obj), members in sorted(grouped.items()):
            self._finding(members[0], members, scope="aggregate")

        suppressed = [f for f in raw if f["suppressed_by_nosec"]]
        if suppressed:
            self.finding(
                check_id="ABAP-NOSEC-001",
                title="Findings suppressed by #NOSEC markers in source",
                severity=self.SEVERITY_INFO,
                category="Code & Transport Security",
                description=(
                    f"{len(suppressed)} finding(s) carry a #NOSEC marker in the "
                    "source. They are reported rather than removed: a suppression "
                    "that leaves no record is indistinguishable from a clean estate, "
                    "and the decision belongs in this product's dismissal workflow, "
                    "which has an audit trail and an expiry."
                ),
                affected_items=["#NOSEC markers present in the scanned source"],
                remediation=(
                    "1. Review each marked statement: a #NOSEC is a claim that the "
                    "code is safe, made by whoever wrote it, with no expiry.\n"
                    "2. Where the claim holds, dismiss the finding here instead so "
                    "the decision is recorded, attributed and re-reviewed.\n"
                    "3. Where it does not, fix the code and delete the marker."
                ),
                details={"suppressed_count": len(suppressed), "source": "abap_scan"},
                scope="aggregate",
            )

    def _finding(self, lead: Dict[str, Any], members: List[Dict[str, Any]],
                 *, scope: str) -> None:
        obj = lead["object"]
        lines = [m["line"] for m in members]
        confidence = lead["confidence"]

        evidence = {
            "confirmed": "tainted input provably reaches this statement",
            "tentative": "the data-flow walk found no evidence either way",
            "pattern-only": "matched by statement pattern; no data-flow evidence",
        }[confidence]

        self.finding(
            check_id=lead["rule_id"],
            title=f"{lead['name']} — {obj}",
            severity=lead["severity"],
            category="Code & Transport Security",
            description=(
                f"{lead['description']} Found in {obj} at line"
                f"{'s' if len(lines) > 1 else ''} "
                f"{', '.join(str(x) for x in lines[:20])}. Evidence: {evidence}."
            ),
            affected_items=[f"{obj} line {m['line']}: {m['statement'][:120]}"
                            for m in members[:50]],
            remediation=lead["recommendation"],
            references=[r for r in (lead.get("cwe"),) if r] +
                       ["SAP Security Baseline — secure custom code"],
            details={
                "source": "abap_scan",
                "cwe": lead.get("cwe"),
                "confidence": confidence,
                "occurrences": len(members),
                "file": lead["file"],
                "lines": lines[:200],
                "snippet": lead["snippet"],
                "taint_flow": lead.get("flow"),
                "suppressed_by_source_marker": lead["suppressed_by_nosec"],
            },
            affected_objects=[{"type": "program", "name": obj}],
            # Identity: the object, qualified by the offending statement. Never the
            # line number.
            subject=[{"type": "program", "name": obj,
                      "qualifier": lead["statement"][:200]}]
            if scope == "object" else [{"type": "program", "name": obj}],
            scope=scope,
        )
