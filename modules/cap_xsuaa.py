# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
CAP / XSUAA Application Security Auditor
========================================
Reads a SAP Cloud Application Programming Model project — its `xs-security.json`
application security descriptor and its CDS model — and follows the chain that
decides who can call what:

    scope  ←  role-template  ←  role-collection  ←  IdP group / user

Every other module in this product audits a system as it is CONFIGURED. This one
audits an application as it is WRITTEN, which is the only place several of these
facts exist at all: a wildcard redirect URI, a scope granted to another
application, a service with no access control. None of them appear in any
runtime export, and the first time they are visible anywhere else is after the
application is deployed and the mistake is live.

WHAT IT READS
  --cap-src DIR                  the project root (an MTA or a plain CAP project)
    <anywhere>/xs-security.json  the application security descriptor  [exact]
    <anywhere>/*.cds            the CDS model                        [lexical]
  btp_role_collection_mappings   who actually holds the collections   [exact]

TWO PARSERS, TWO CONFIDENCE LEVELS, AND THE REPORT SAYS WHICH
`xs-security.json` is JSON. Reading it is exact, and every descriptor finding is
a statement about a value that is literally in the file.

CDS is a language, and this product is stdlib-only, so there is no CDS compiler
here to ask. The model is read LEXICALLY — comments stripped, service and entity
declarations located, annotations associated with them by position and by
`annotate` target. That is good enough to find a service nobody protected, and
it is NOT good enough to be certain a service IS protected. So the CDS checks are
written in one direction only: they report what they positively found, never that
a service is safe, and `CAPX-COV-001` states every construct the parser could not
resolve. A model this parser could not read is reported as unread.

THE GRAPH IS THE POINT
Individually these checks are ordinary. The value is the join: a scope in the
descriptor is reachable only through a role-template, a role-template only
through a role-collection, and a role-collection only through the IdP groups and
users the subaccount maps to it. Break any link and the privilege is either
unreachable or held by everybody, and neither is visible from one end alone.
The descriptor cannot tell you who holds a collection; the subaccount export
cannot tell you what a collection grants. Read together they answer the question
an auditor actually asks, which is who can do this.

WHAT THIS MODULE DOES NOT CLAIM
  * That a CDS role missing from the descriptor is a defect. It may be granted by
    another application's role-template. `CAPX-CDS-003` reports the disagreement,
    not a verdict on which side is wrong.
  * That an unreferenced role-template is unreachable, unless the subaccount's
    role collections were also supplied — a collection assembled in the cockpit
    is invisible in the descriptor.
  * Anything at all about a project that was not supplied. Absent is absent; see
    the coverage manifest.

WHERE THE CHAIN STOPS, AND WHY IT STOPS THERE
The last link is the IdP GROUP and a holder count, not a list of named users.
That is a deliberate boundary, not a missing feature. Role-collection user
assignments are personal data, and this product's standing position on personal
data is the same everywhere it meets it: `btp_users` is not collected at all, and
audit-log records reach a report only as per-tenant counts. Naming individuals in
a finding would put a list of employees into every PDF, slide deck and ticket the
report generates, to answer a question the group already answers — "every
federated user" is a stronger and more actionable statement than four hundred
names, and it is the one that identifies the defect.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base_auditor import BaseAuditor


# ─────────────────────────────────────────────────────────────────────────────
#  Numbers SAP publishes, quoted rather than chosen
#
#  Source: "Application Security Descriptor Configuration Syntax", SAP BTP
#  documentation, section `oauth2-configuration` [verified]. The two defaults are
#  the same ones `btp_cloud_surface._ACCESS_TOKEN_DEFAULT` carries, and they have
#  to stay identical: BTP-TOK-* judges the subaccount value and CAPX-TOK-001
#  judges the application override of that same value, so two different
#  "defaults" would put the two checks in disagreement about one setting.
# ─────────────────────────────────────────────────────────────────────────────

#: "token-validity ... Default: 43200 seconds (12 hours)". Documented range:
#: "from 60 seconds to 86400 seconds, in other words, from 1 minute to 24 hours".
_TOKEN_DEFAULT = 43200
_TOKEN_MAX = 86400

#: "refresh-token-validity ... Default: 604800 seconds (7 days)". Documented
#: range: "from 60 seconds to 31536000 seconds, in other words, from 1 minute to
#: 1 year".
_REFRESH_DEFAULT = 604800
_REFRESH_MAX = 31536000

#: "Keep token validity ... as short as possible, but not less than 30 minutes."
_TOKEN_FLOOR = 1800

#: The pseudo-roles CAP defines. None of them is an XSUAA scope, so none of them
#: can be missing from a security descriptor, and comparing them against one
#: would report every correctly-written service as broken.
#: `any` is the dangerous one: "the `any` pseudo-role applies for all users and
#: is the default if no value is provided".
_PSEUDO_ROLES = frozenset((
    "any", "authenticated-user", "system-user", "internal-user",
    "privileged-user", "identified-user",
))

#: IdP group names that mean "everybody who logs in". Kept identical to
#: `s4_business_authz.check_birthright_role_collection` on purpose — if the two
#: disagreed, one module would call a collection birthright and the other would
#: not, about the same row of the same export.
_BIRTHRIGHT_GROUPS = frozenset(("default", "*", "all", "authenticated", "everyone"))

#: Directory names never worth walking. `node_modules` is the one that matters:
#: a CAP project routinely carries tens of thousands of files under it, including
#: other people's `xs-security.json` samples, and reading those would attribute a
#: dependency's test fixture to the customer's application.
_SKIP_DIRS = frozenset((
    "node_modules", ".git", ".svn", "dist", "build", "target", "gen",
    "__pycache__", ".vscode", ".idea", "coverage", ".cds_build",
))

_CDS_SUFFIXES = (".cds",)
_MAX_FILE_BYTES = 4 * 1024 * 1024


# ═════════════════════════════════════════════════════════════════════════════
#  Scope and role reference syntax
# ═════════════════════════════════════════════════════════════════════════════

_FOREIGN_REF = re.compile(r"^\$XSAPPNAME\s*\(([^)]*)\)\s*\.?\s*(.*)$")
_LOCAL_REF = re.compile(r"^\$XSAPPNAME\s*\.\s*(.+)$")


def _split_reference(ref: Any) -> Tuple[str, str]:
    """`(kind, name)` for one scope or role-template reference.

    SAP documents exactly three forms and they mean different things, so
    flattening them would make the graph wrong in both directions:

      `$XSAPPNAME.Display`                        -> ("local", "Display")
      `$XSAPPNAME(application,other-app).Create`  -> ("foreign", "other-app.Create")
      `uaa.user`                                  -> ("external", "uaa.user")

    Only LOCAL references can be resolved against this descriptor. A foreign
    reference names something in another application's descriptor, which is not
    in this project and must never be reported as a broken link — that would turn
    every correctly-integrated application into a finding.
    """
    text = str(ref or "").strip()
    if not text:
        return ("external", "")
    foreign = _FOREIGN_REF.match(text)
    if foreign:
        app = foreign.group(1).split(",")[-1].strip()
        local = foreign.group(2).strip()
        return ("foreign", "%s.%s" % (app, local) if local else app)
    local = _LOCAL_REF.match(text)
    if local:
        return ("local", local.group(1).strip())
    return ("external", text)


def _as_list(value: Any) -> List[Any]:
    """A JSON field that is documented as an array but is often written bare."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# ═════════════════════════════════════════════════════════════════════════════
#  The CDS model, read lexically
# ═════════════════════════════════════════════════════════════════════════════

_SERVICE_DECL = re.compile(r"\bservice\s+([A-Za-z_][\w.]*)", re.MULTILINE)
_ANNOTATE_DECL = re.compile(r"\bannotate\s+([A-Za-z_][\w.]*)\s+with\b", re.MULTILINE)
_QUOTED = re.compile(r"'([^']*)'|\"([^\"]*)\"")


def strip_cds_comments(source: str) -> str:
    """Comments out, LENGTH PRESERVED, strings respected.

    Two properties, and both are load-bearing.

    LENGTH PRESERVED. Every offset in this parser indexes into the returned text
    and the findings quote line numbers computed from it. Deleting comments
    rather than blanking them would shift every offset after the first one, so a
    finding about line 80 would point at line 62 — worse than no line number,
    because a reader trusts it.

    STRINGS RESPECTED, for `/* */` as well as `//`. This was two passes at first,
    and only the line-comment pass was string-aware. That asymmetry fails in the
    dangerous direction: a `/*` inside a CDS literal — a path, a URL, a regex in
    a `where` clause — would start a comment that ran to the next `*/` or to the
    end of the file, blanking real annotations along the way, and a service whose
    `@requires` had just been blanked is reported by CAPX-CDS-001 as having no
    access control at all. A parser that under-reads must never be able to
    manufacture a HIGH finding, so both comment forms are handled in one
    string-aware pass.
    """
    out = list(source)
    i, n = 0, len(source)
    quote = None
    while i < n:
        ch = source[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
        elif ch in ("'", '"'):
            # CDS strings are single-quoted; `"` is accepted because hand-written
            # and generated files both carry it in annotation values. A backtick
            # is NOT a delimiter in this language and is deliberately not treated
            # as one — modelling a delimiter the grammar does not have would let
            # one stray character silently disable comment stripping for the rest
            # of a file.
            quote = ch
            i += 1
        elif ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and source[i + 1] == "*":
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            while i < end:
                if source[i] != "\n":
                    out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _balanced(text: str, start: int, opener: str, closer: str) -> int:
    """Index just past the bracket group opening at `start`, or -1.

    String-aware, because a CDS `where` clause can hold a bracket inside a
    literal. Returning -1 on an unbalanced group is deliberate: the caller then
    records the construct as UNRESOLVED rather than guessing an end and reading
    an annotation that is not there.
    """
    if start >= len(text) or text[start] != opener:
        return -1
    depth, i, quote = 0, start, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _annotation_span_before(text: str, position: int) -> str:
    """The annotation block immediately preceding a declaration.

    CAP allows annotations either inline (`service S @(requires:'X') {`) or on
    the lines above the declaration. Both are ordinary and a parser that read
    only one of them would report half the protected services as unprotected.

    Walks backwards over whitespace and complete `@...` groups, stopping at the
    first character that is neither — a `;`, a `}` or the end of another
    definition. It never crosses a statement boundary, so an annotation on the
    PREVIOUS definition cannot be credited to this one.

    `}` IS A HARD STOP, and getting that wrong is not a cosmetic bug. The first
    version skipped backwards over `}` as a balanced group like `)` and `]`, so
    the walk sailed out of the preceding service's body, through its declaration,
    and picked up ITS annotations. In the fixture that made an unannotated
    `service AdminService` inherit `@protocol: 'none'` from the service above it
    and vanish from CAPX-CDS-001 — the check reported nothing, which is the
    failure mode this module is supposed to be immune to. A `}` at this level is
    always the end of a previous definition; a `{` that belongs to an annotation
    is always already inside the `(...)` or `[...]` group being skipped.
    """
    i = position - 1
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    end = i + 1
    # Walk back over balanced groups and identifiers until the '@' that starts
    # this annotation block; anything else ends it.
    while i >= 0:
        ch = text[i]
        if ch in ")]":
            opener = {")": "(", "]": "["}[ch]
            depth, j, found = 0, i, -1
            while j >= 0:
                if text[j] == ch:
                    depth += 1
                elif text[j] == opener:
                    depth -= 1
                    if depth == 0:
                        found = j
                        break
                j -= 1
            if found < 0:
                break
            i = found - 1
        elif ch in " \t\r\n:,._-" or ch.isalnum() or ch == "'" or ch == '"':
            i -= 1
        elif ch == "@":
            i -= 1
        else:
            break
    start = i + 1
    span = text[start:end]
    at = span.find("@")
    return span[at:] if at >= 0 else ""


def _inline_annotations(text: str, start: int) -> str:
    """Annotations between a declaration's name and its body or terminator."""
    i = start
    while i < len(text) and text[i] not in "{;":
        i += 1
    return text[start:i]


class CdsModel(object):
    """What the lexical pass found, and what it could not resolve.

    `unresolved` is not an error log. It is the evidence for `CAPX-COV-001`, and
    it is the reason the CDS findings can be trusted in the direction they are
    written: a service reported as unprotected was one where the parser found
    every annotation it could see and none of them protected it, in a file where
    nothing was left unread.
    """

    def __init__(self):
        self.services = {}          # name -> {"file", "line", "annotations"}
        self.annotate_targets = {}  # root name -> [annotation text, ...]
        self.roles = {}             # role name -> set of "file:line" sites
        self.open_privileges = []   # (service/target, file, line) with no `to`
        self.files = 0
        self.unresolved = []

    def annotations_for(self, service: str) -> str:
        parts = [self.services.get(service, {}).get("annotations", "")]
        parts.extend(self.annotate_targets.get(service, []))
        return "\n".join(p for p in parts if p)


def parse_cds_tree(root: Path, model: CdsModel) -> None:
    """Walk a project and read every `.cds` file into `model`."""
    for path in sorted(_walk(root, _CDS_SUFFIXES)):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                model.unresolved.append("%s (larger than %d bytes, not read)"
                                        % (_rel(root, path), _MAX_FILE_BYTES))
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            model.unresolved.append("%s (unreadable: %s)" % (_rel(root, path), exc))
            continue
        model.files += 1
        parse_cds_source(source, _rel(root, path), model)


def parse_cds_source(source: str, label: str, model: CdsModel) -> None:
    """Read one `.cds` file. Pure text in, `model` mutated."""
    text = strip_cds_comments(source)

    for match in _SERVICE_DECL.finditer(text):
        name = match.group(1)
        annotations = (_annotation_span_before(text, match.start())
                       + " " + _inline_annotations(text, match.end()))
        model.services[name] = {
            "file": label,
            "line": text.count("\n", 0, match.start()) + 1,
            "annotations": annotations,
        }

    for match in _ANNOTATE_DECL.finditer(text):
        target = match.group(1)
        root = target.split(".")[0]
        end = text.find(";", match.end())
        body = text[match.end():end if end > 0 else len(text)]
        model.annotate_targets.setdefault(root, []).append(body)
        if end < 0:
            model.unresolved.append(
                "%s: `annotate %s with` has no terminating ';'" % (label, target))

    _collect_roles(text, label, model)


def _collect_roles(text: str, label: str, model: CdsModel) -> None:
    """Every role named anywhere in this file, and every open privilege."""
    for match in re.finditer(r"\brequires\s*:", text):
        for role in _literal_values(text, match.end()):
            model.roles.setdefault(role, set()).add(
                "%s:%d" % (label, text.count("\n", 0, match.start()) + 1))

    for match in re.finditer(r"\brestrict\s*:", text):
        line = text.count("\n", 0, match.start()) + 1
        i = match.end()
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        end = _balanced(text, i, "[", "]") if i < len(text) and text[i] == "[" else -1
        if end < 0:
            model.unresolved.append(
                "%s:%d: `@restrict` list could not be read to its end" % (label, line))
            continue
        for privilege in _privileges(text[i:end]):
            named = list(_privilege_roles(privilege))
            for role in named:
                model.roles.setdefault(role, set()).add("%s:%d" % (label, line))
            if not named and re.search(r"\bgrant\s*:", privilege):
                # A privilege with `grant` and no `to`. SAP: "the `any` pseudo-role
                # applies for all users and is the default if no value is provided".
                model.open_privileges.append(
                    (label, line, " ".join(privilege.split())[:160]))


def _privileges(block: str) -> List[str]:
    """The `{...}` groups of a `@restrict` list, one privilege each."""
    out, i = [], 0
    while i < len(block):
        if block[i] == "{":
            end = _balanced(block, i, "{", "}")
            if end < 0:
                break
            out.append(block[i:end])
            i = end
        else:
            i += 1
    return out


def _privilege_roles(privilege: str):
    """The roles a single privilege's `to` names."""
    match = re.search(r"\bto\s*:", privilege)
    if not match:
        return []
    return _literal_values(privilege, match.end())


def _literal_values(text: str, start: int) -> List[str]:
    """The quoted string(s) a `key:` introduces — one value or an array."""
    i = start
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    if i >= len(text):
        return []
    if text[i] == "[":
        end = _balanced(text, i, "[", "]")
        if end < 0:
            return []
        span = text[i:end]
    else:
        stop = i
        while stop < len(text) and text[stop] not in ",}\n]":
            stop += 1
        span = text[i:stop]
    return [(m.group(1) if m.group(1) is not None else m.group(2))
            for m in _QUOTED.finditer(span)]


def _walk(root: Path, suffixes: Tuple[str, ...]):
    """Every file under `root` with one of `suffixes`, skipping build output."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name not in _SKIP_DIRS and not entry.is_symlink():
                        stack.append(entry)
                elif entry.suffix.lower() in suffixes:
                    yield entry
            except OSError:
                continue


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


# ═════════════════════════════════════════════════════════════════════════════
#  The auditor
# ═════════════════════════════════════════════════════════════════════════════

class CapXsuaaAuditor(BaseAuditor):

    #: The CAP / MTA project root, supplied via `--cap-src`. Absent means the
    #: module has nothing to do, which the coverage manifest states rather than
    #: passing over in silence.
    SOURCE_KEY = "cap_project_dir"

    #: Declared as a literal here, not aliased from a module global:
    #: `modules/coverage.py:check_catalogue` reads this by AST to pair each
    #: check id with its category, and it resolves a literal or
    #: `self.CATEGORY`. An indirection it cannot follow puts every check in
    #: this module into the catalogue with NO category, which silently
    #: shrinks the denominator its compliance percentage is measured against.
    CATEGORY = "CAP & XSUAA Application Security"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        root = self.data.get(self.SOURCE_KEY)
        if not root:
            # Nobody asked for a project scan. An absent optional input is not
            # degraded coverage — conflating the two would arm the gate on every
            # scan that omits any optional input, and the signal would be worth
            # nothing. `abap_sast` draws the same line for the same reason.
            return self.findings

        path = Path(root)
        if not path.is_dir():
            # ASKED TO LOOK, COULD NOT. Returning an empty list here would be
            # indistinguishable from a project with nothing wrong in it.
            self._coverage(
                "CAPX-COV-001",
                "CAP project scan was requested but the path is not readable",
                ("--cap-src named %r, which is not a directory, so no descriptor "
                 "and no CDS model were read. This is a finding rather than an "
                 "empty result because an empty result reads as a clean project: "
                 "the scan did not come back clean, it did not happen." % (root,)),
                ["%s (not a directory)" % root],
                ("1. Check the path given to --cap-src: it must be the project "
                 "root — the directory holding srv/, db/ and the mta.yaml or "
                 "package.json — not an archive and not a file inside it.\n"
                 "2. In a pipeline, confirm the checkout step ran and wrote to "
                 "the path the scan step reads.\n"
                 "3. Re-run. Until it reads a real project, treat its silence on "
                 "application security as unknown, not clean."),
                {"cap_project_dir": str(root), "reason": "not_a_directory"})
            return self.findings

        descriptors = self._load_descriptors(path)
        model = CdsModel()
        parse_cds_tree(path, model)

        if not descriptors and not model.files:
            self._coverage(
                "CAPX-COV-001",
                "CAP project scan found no descriptor and no CDS model",
                ("The directory was readable but holds neither an "
                 "`xs-security.json` nor any `.cds` file, so nothing was "
                 "examined. The usual causes are a path one level too high, a "
                 "checkout that only fetched build output, or a project whose "
                 "sources live in a subdirectory that was not included. Zero "
                 "findings here is not a clean result."),
                ["0 descriptors, 0 CDS files under %s" % root],
                ("1. Confirm --cap-src points at the project root.\n"
                 "2. Confirm the checkout included srv/ and db/ and was not "
                 "limited to gen/ or node_modules/.\n"
                 "3. Re-run once real sources are present."),
                {"descriptors": 0, "cds_files": 0, "reason": "nothing_to_read"})
            return self.findings

        for descriptor in descriptors:
            self.check_descriptor_graph(descriptor)
            self.check_scope_grants(descriptor)
            self.check_accepted_authorities(descriptor)
            self.check_unrestricted_attributes(descriptor)
            self.check_token_overrides(descriptor)
            self.check_redirect_uris(descriptor)
            self.check_credential_types(descriptor)
            self.check_tenant_mode(descriptor)

        self.check_model_access_control(model)
        self.check_open_privileges(model)
        self.check_model_descriptor_agreement(model, descriptors)
        self.check_who_holds_the_scopes(descriptors)
        self.check_undeliverable_role_templates(descriptors)
        self.report_coverage(path, descriptors, model)
        return self.findings

    # ── loading ─────────────────────────────────────────────────────────────

    def _load_descriptors(self, root: Path) -> List[Dict[str, Any]]:
        """Every `xs-security.json` in the project, parsed.

        More than one is normal: an MTA with two modules has two, and they define
        different applications. They are kept apart rather than merged, because a
        scope in one is not reachable from a role-template in the other.
        """
        out = []
        self._unreadable_descriptors = []
        for path in sorted(_walk(root, (".json",))):
            if path.name.lower() != "xs-security.json":
                continue
            label = _rel(root, path)
            try:
                raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError) as exc:
                # A descriptor that will not parse is the one most worth knowing
                # about, and dropping it silently would hide the application whose
                # security configuration is broken.
                self._unreadable_descriptors.append("%s (%s)" % (label, exc))
                continue
            if not isinstance(raw, dict):
                self._unreadable_descriptors.append(
                    "%s (top level is %s, not an object)" % (label, type(raw).__name__))
                continue
            out.append(self._parse_descriptor(raw, label))
        return out

    @staticmethod
    def _parse_descriptor(raw: Dict[str, Any], label: str) -> Dict[str, Any]:
        oauth = raw.get("oauth2-configuration")
        return {
            "file": label,
            "xsappname": str(raw.get("xsappname") or "").strip(),
            "tenant_mode": str(raw.get("tenant-mode") or "").strip(),
            "scopes": [s for s in _as_list(raw.get("scopes")) if isinstance(s, dict)],
            "attributes": [a for a in _as_list(raw.get("attributes"))
                           if isinstance(a, dict)],
            "role_templates": [t for t in _as_list(raw.get("role-templates"))
                               if isinstance(t, dict)],
            "role_collections": [c for c in _as_list(raw.get("role-collections"))
                                 if isinstance(c, dict)],
            "authorities": [str(a) for a in _as_list(raw.get("authorities"))],
            "oauth2": oauth if isinstance(oauth, dict) else {},
            "raw_keys": sorted(raw),
        }

    @staticmethod
    def _name(entry: Dict[str, Any]) -> str:
        return str(entry.get("name") or "").strip()

    def _app(self, descriptor: Dict[str, Any]) -> str:
        return descriptor["xsappname"] or descriptor["file"]

    # ── CAPX-GRAPH-001: the descriptor's own links ──────────────────────────

    def check_descriptor_graph(self, descriptor: Dict[str, Any]):
        """Follow every local reference in the descriptor and report the breaks.

        A role-collection references role-templates; a role-template references
        scopes. When a LOCAL reference names something the same descriptor does
        not define, the link is broken and the privilege behind it does not
        exist: the deployment either fails or, worse, succeeds and produces a
        role that grants nothing, which looks identical to a role that grants
        everything until somebody tests it.

        Only local references are followed. A `$XSAPPNAME(application,other)`
        reference names another application's descriptor, which is not in this
        project — reporting it as broken would make every correctly integrated
        application a finding.
        """
        scopes = set()
        for scope in descriptor["scopes"]:
            kind, name = _split_reference(self._name(scope))
            scopes.add(name if kind == "local" else self._name(scope))
        templates = set(self._name(t) for t in descriptor["role_templates"])

        broken, objects = [], []
        for template in descriptor["role_templates"]:
            tname = self._name(template)
            for ref in _as_list(template.get("scope-references")):
                kind, name = _split_reference(ref)
                if kind == "local" and name not in scopes:
                    broken.append("role-template '%s' references scope '%s', which "
                                  "this descriptor does not define (%s)"
                                  % (tname, ref, descriptor["file"]))
                    self._add(objects, "xsuaa_role_template", tname,
                              "missing scope %s" % ref)

        for collection in descriptor["role_collections"]:
            cname = self._name(collection)
            for ref in _as_list(collection.get("role-template-references")):
                kind, name = _split_reference(ref)
                if kind == "local" and name not in templates:
                    broken.append("role-collection '%s' references role-template "
                                  "'%s', which this descriptor does not define (%s)"
                                  % (cname, ref, descriptor["file"]))
                    self._add(objects, "xsuaa_role_collection", cname,
                              "missing role-template %s" % ref)

        if not broken:
            return
        self.finding(
            check_id="CAPX-GRAPH-001",
            title="Broken reference in the XSUAA authorization chain",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d reference(s) in the application security descriptor of '%s' "
                "name a scope or role-template the same descriptor does not "
                "define. The chain that grants a privilege runs scope <- "
                "role-template <- role-collection, and a break anywhere along it "
                "means the privilege at the end does not exist. The failure is "
                "quiet: `cf update-service` may reject the descriptor, or it may "
                "accept it and create a role that grants nothing, which is "
                "indistinguishable from a working role until somebody is denied "
                "access they were told they had. The usual cause is a rename on "
                "one side of the reference only, or a role-template copied "
                "between applications along with a scope name that did not come "
                "with it." % (len(broken), self._app(descriptor))),
            affected_items=broken,
            remediation=(
                "1. Open the descriptor named and locate each reference "
                "reported.\n"
                "2. For each one, decide which side is right: either the scope "
                "or role-template was renamed and the reference was not updated, "
                "or the reference is a leftover from a definition that was "
                "deleted.\n"
                "3. If the target genuinely lives in another application, write "
                "the reference in its foreign form, "
                "$XSAPPNAME(application,<xsappname>).<scope>, so it resolves at "
                "deployment.\n"
                "4. Re-run `cds compile --to xsuaa` if the descriptor is "
                "generated, rather than editing the generated file, or the fix "
                "is reverted by the next build.\n"
                "5. Redeploy and confirm the role appears with its scopes in the "
                "subaccount's role list.\n"
                "6. Re-run the scan to confirm every reference resolves."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"],
                     "xsappname": descriptor["xsappname"]},
            # One finding per descriptor rolling up its broken links; fixing one
            # must shrink it rather than retire and re-raise the whole set.
            scope="aggregate",
        )

    # ── CAPX-SCOPE-001: scopes handed to other applications ─────────────────

    def check_scope_grants(self, descriptor: Dict[str, Any]):
        """Report scopes this application grants to other applications.

        Two properties do this and they are not the same thing. `granted-apps`
        grants the scope for a USER scenario — the other application can act with
        it on behalf of a logged-in user. `grant-as-authority-to-apps` grants it
        for a CLIENT-CREDENTIALS scenario, which is the one worth looking at:
        SAP's own words are "if you want to grant a scope to other applications
        for a client credential scenario", and a client-credentials grant has no
        user in it at all.

        That matters because it leaves the role-collection graph entirely. A
        privilege granted this way is held by an application, not by anybody an
        administrator can see in the subaccount's user list, and no review of
        role collections will ever surface it.
        """
        granted, objects = [], []
        for scope in descriptor["scopes"]:
            sname = self._name(scope)
            for prop, kind in (("grant-as-authority-to-apps", "client credentials"),
                               ("granted-apps", "user scenario")):
                targets = [str(t) for t in _as_list(scope.get(prop)) if str(t).strip()]
                if not targets:
                    continue
                granted.append("%s -> %s (%s, %s)"
                               % (sname, ", ".join(targets), prop, kind))
                self._add(objects, "xsuaa_scope", sname,
                          "%s: %s" % (prop, ", ".join(sorted(targets))))

        if not granted:
            return
        self.finding(
            check_id="CAPX-SCOPE-001",
            title="Application scope granted directly to another application",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d scope(s) of '%s' are granted to other applications through "
                "`granted-apps` or `grant-as-authority-to-apps`. This is a "
                "supported and often necessary pattern, and it is reported "
                "because of where it does NOT appear: a scope granted this way "
                "is held by the receiving application, not by a role collection, "
                "so it is invisible to every review that works from the "
                "subaccount's role collections and user assignments. A "
                "`grant-as-authority-to-apps` grant is the stronger of the two — "
                "SAP documents it for the client-credentials scenario, meaning "
                "the receiving application can use the scope with no user "
                "involved and no user's authorizations limiting it. The risk is "
                "not the grant, it is that the receiving application's own "
                "security then bounds this application's data, and nothing in "
                "the subaccount will tell an auditor that."
                % (len(granted), self._app(descriptor))),
            affected_items=granted,
            remediation=(
                "1. For each grant, identify the receiving application and "
                "confirm the integration is still required.\n"
                "2. Confirm the receiving application's `authorities` names this "
                "scope explicitly rather than using "
                "$ACCEPT_GRANTED_AUTHORITIES, so the grant is bounded on both "
                "sides.\n"
                "3. Prefer `granted-apps` over `grant-as-authority-to-apps` "
                "where the call is made on behalf of a user, so the user's own "
                "authorizations still apply.\n"
                "4. Record these grants in your authorization design document — "
                "they will not appear in any role-collection review.\n"
                "5. Remove grants whose receiving application has been "
                "decommissioned.\n"
                "6. Re-run the scan to confirm the remaining grants are the ones "
                "you intended."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(Granting Scopes to Another Application)",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"]},
            scope="aggregate",
        )

    # ── CAPX-AUTH-001 ───────────────────────────────────────────────────────

    def check_accepted_authorities(self, descriptor: Dict[str, Any]):
        """`$ACCEPT_GRANTED_AUTHORITIES` accepts every grantable scope, unnamed."""
        if "$ACCEPT_GRANTED_AUTHORITIES" not in descriptor["authorities"]:
            return
        named = [a for a in descriptor["authorities"]
                 if a != "$ACCEPT_GRANTED_AUTHORITIES"]
        objects = []
        self._add(objects, "xsuaa_application", descriptor["xsappname"],
                  "$ACCEPT_GRANTED_AUTHORITIES")
        self.finding(
            check_id="CAPX-AUTH-001",
            title="Application accepts every authority granted to it, without naming them",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "'%s' declares `\"authorities\": [\"$ACCEPT_GRANTED_AUTHORITIES\"]`. "
                "SAP documents this as requesting and accepting ALL authorities "
                "flagged as grantable in the receiving applications, as opposed "
                "to naming the individual scope authorities it needs. The "
                "practical effect is that the set of privileges this application "
                "holds is decided elsewhere and changes without any edit here: "
                "another team adding `grant-as-authority-to-apps` to a new "
                "privileged scope widens this application silently, and nothing "
                "in this repository or this descriptor records that it "
                "happened. It is not a vulnerability on its own — it is a "
                "standing consent, and a standing consent cannot be reviewed."
                % self._app(descriptor)),
            affected_items=["%s in %s%s" % (descriptor["xsappname"] or "(unnamed app)",
                                            descriptor["file"],
                                            (" (also names %d specific authority(ies))"
                                             % len(named)) if named else "")],
            remediation=(
                "1. Determine which foreign authorities this application "
                "actually uses at runtime — the granting applications' "
                "descriptors list them under grant-as-authority-to-apps.\n"
                "2. Replace $ACCEPT_GRANTED_AUTHORITIES with the explicit list, "
                "in the form \"<ReceivingApp>.<Scope>\".\n"
                "3. Deploy to a non-production subaccount and exercise the "
                "integration paths, since an authority you missed will surface "
                "as a 403 rather than a deployment error.\n"
                "4. Where the wildcard must stay — a reuse service with many "
                "consumers is the legitimate case — record the decision and the "
                "reviewing owner, and re-confirm it whenever a granting "
                "application changes.\n"
                "5. Re-run the scan."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(authorities)",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"],
                     "named_authorities": named},
            scope="aggregate",
        )

    # ── CAPX-ATTR-001 ───────────────────────────────────────────────────────

    def check_unrestricted_attributes(self, descriptor: Dict[str, Any]):
        """`valueRequired: false` builds roles that are not restricted at all.

        This is the one descriptor setting whose plain reading is the opposite of
        its effect. `valueRequired: false` sounds like a relaxation of a form
        field; SAP's own words for what it produces are "A role that isn't
        restricted by attributes (unrestricted) is created". An attribute is
        normally what confines a role to one country, one company code or one
        cost centre, so an unrestricted attribute is the difference between a
        role that sees one plant and a role that sees all of them.
        """
        loose, objects = [], []
        by_name = {}
        for attribute in descriptor["attributes"]:
            aname = self._name(attribute)
            if not aname:
                continue
            by_name[aname] = attribute
            if attribute.get("valueRequired") is False:
                users = [self._name(t) for t in descriptor["role_templates"]
                         if aname in self._attribute_names(t)]
                loose.append("attribute '%s' has valueRequired=false%s"
                             % (aname,
                                (" — used by role-template(s): %s" % ", ".join(users))
                                if users else " (no role-template references it)"))
                self._add(objects, "xsuaa_attribute", aname, "valueRequired=false")

        if not loose:
            return
        self.finding(
            check_id="CAPX-ATTR-001",
            title="Attribute-based restriction declared but not enforced (valueRequired=false)",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d attribute(s) in '%s' are declared with "
                "`\"valueRequired\": false`. SAP documents the result plainly: "
                "\"A role that isn't restricted by attributes (unrestricted) is "
                "created\" — administrators do not have to supply a value, and a "
                "role built without one is not limited by that attribute at all. "
                "Attributes are the mechanism that confines a role to a country, "
                "a company code or a cost centre, so this is the difference "
                "between a role that sees one organisational unit and the same "
                "role seeing every one of them. It reads as a convenience "
                "setting and behaves as a scope decision, which is why it "
                "survives review: the role name, the scopes and the role "
                "collection all look correct."
                % (len(loose), self._app(descriptor))),
            affected_items=loose,
            remediation=(
                "1. For each attribute, decide whether an unrestricted role is "
                "genuinely intended — for a global administrator role it may "
                "be.\n"
                "2. Where it is not, set \"valueRequired\": true and give the "
                "role-template's attribute-references explicit default-values, "
                "so a default role is still generated at deployment.\n"
                "3. Note SAP's restriction before changing this: "
                "\"Do not change the 'valueRequired' property from false to "
                "true\" on a deployed descriptor — plan the change as a new "
                "role-template rather than an edit to the existing one.\n"
                "4. Review the users currently holding roles built from these "
                "templates; any of them created without attribute values are "
                "unrestricted today.\n"
                "5. Re-run the scan once the descriptor and the assigned roles "
                "agree."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(Relationship Between default-values of attribute-references "
                "and valueRequired)",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"]},
            scope="aggregate",
        )

    @staticmethod
    def _attribute_names(template: Dict[str, Any]) -> Set[str]:
        """The attribute names a role-template references.

        SAP documents `attribute-references` as either an array of strings or an
        array of objects, and real descriptors carry both. Handling only one form
        would silently drop half the references and make the finding above
        under-report which role-templates are affected.
        """
        out = set()
        for ref in _as_list(template.get("attribute-references")):
            if isinstance(ref, dict):
                name = str(ref.get("name") or "").strip()
            else:
                name = str(ref or "").strip()
            if name:
                out.add(name)
        return out

    # ── CAPX-TOK-001: the override BTP-TOK-* declared it could not see ──────

    def check_token_overrides(self, descriptor: Dict[str, Any]):
        """Application-level token lifetimes.

        `BTP-TOK-001` and `BTP-TOK-002` judge the subaccount's token policy and
        both say, in every finding they raise, that an application can override
        it in its own `xs-security.json` and that the scan cannot see those
        overrides. This is where that stops being true — SAP's own wording for
        the field is "These values override the values set for the subaccount".

        So a subaccount reported as tightened to 30 minutes can still be issuing
        12-hour tokens for one application, and that fact exists only here.
        """
        oauth = descriptor["oauth2"]
        if not oauth:
            return
        offenders, objects = [], []
        for key, default, ceiling, label in (
                ("token-validity", _TOKEN_DEFAULT, _TOKEN_MAX, "access token"),
                ("refresh-token-validity", _REFRESH_DEFAULT, _REFRESH_MAX,
                 "refresh token")):
            if key not in oauth:
                continue
            seconds = self._int(oauth.get(key))
            if seconds is None:
                offenders.append("%s: %s is %r, which is not a number of seconds"
                                 % (label, key, oauth.get(key)))
                self._add(objects, "xsuaa_application", descriptor["xsappname"],
                          "%s not numeric" % key)
                continue
            if seconds > ceiling:
                offenders.append(
                    "%s validity %s exceeds the documented maximum of %s — the "
                    "service will reject or clamp it"
                    % (label, self._duration(seconds), self._duration(ceiling)))
            elif seconds > default:
                offenders.append(
                    "%s validity %s, longer than the SAP default of %s"
                    % (label, self._duration(seconds), self._duration(default)))
            elif seconds < _TOKEN_FLOOR:
                offenders.append(
                    "%s validity %s, below the 30-minute floor SAP states"
                    % (label, self._duration(seconds)))
            else:
                continue
            self._add(objects, "xsuaa_application", descriptor["xsappname"],
                      "%s=%s" % (key, seconds))

        if not offenders:
            return
        self.finding(
            check_id="CAPX-TOK-001",
            title="Application overrides the subaccount token policy",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "'%s' sets its own OAuth token lifetimes in "
                "`oauth2-configuration`, and %d of them sit outside SAP's "
                "documented baseline. SAP's wording for this field is explicit: "
                "\"These values override the values set for the subaccount\". "
                "That is what makes this worth a separate finding — the "
                "subaccount-level checks in this report (BTP-TOK-001 / -002) "
                "state in every finding that they cannot see application "
                "overrides, so a subaccount tightened to 30 minutes can still be "
                "issuing 12-hour tokens for this one application and nothing at "
                "the subaccount level would show it. A stolen token from this "
                "application stays usable for as long as the value here says, "
                "whatever the subaccount policy is, and revoking the user's "
                "credentials does not shorten it."
                % (self._app(descriptor), len(offenders))),
            affected_items=offenders,
            remediation=(
                "1. Open the descriptor and review `oauth2-configuration` — "
                "record the current values before changing them.\n"
                "2. Establish why the application needed its own lifetime. A "
                "long one is usually a workaround for an integration that could "
                "not refresh; fix the refresh flow instead.\n"
                "3. Remove the override entirely if the subaccount policy is "
                "adequate, so the application inherits future tightening rather "
                "than pinning an old decision.\n"
                "4. Where an override is genuinely needed, keep token-validity "
                "within 1800 to 43200 seconds and refresh-token-validity within "
                "1800 to 604800 seconds; SAP states not less than 30 minutes.\n"
                "5. If the descriptor is generated by `cds compile --to xsuaa`, "
                "change the source and regenerate rather than editing the "
                "output.\n"
                "6. Redeploy and re-run the scan."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(oauth2-configuration)",
                "SAP BTP — Configure Token Policy for SAP Authorization and "
                "Trust Management Service",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"],
                     "subaccount_check": "BTP-TOK-001/002",
                     "token_validity": oauth.get("token-validity"),
                     "refresh_token_validity": oauth.get("refresh-token-validity")},
            scope="aggregate",
        )

    # ── CAPX-URI-001 ────────────────────────────────────────────────────────

    def check_redirect_uris(self, descriptor: Dict[str, Any]):
        """Wildcard redirect URIs, which is where an OAuth code goes to be stolen.

        SAP supports wildcards and cautions against them in the same paragraph:
        "If you use wildcards, we recommend that you make your URIs as specific
        as possible. By using wildcards, you open up the redirect for multiple
        web sites. Wildcards increase the risk of redirecting to malicious web
        sites."

        The attack is not theoretical and does not need the application to be
        vulnerable: the redirect URI is where the authorization server sends the
        code after a successful login, so an attacker who controls any host the
        pattern admits gets a code minted for the victim's real session.
        """
        uris = [str(u).strip() for u in _as_list(descriptor["oauth2"].get("redirect-uris"))
                if str(u or "").strip()]
        if not uris:
            return
        risky, objects = [], []
        for uri in uris:
            why = self._redirect_risk(uri)
            if why:
                risky.append("%s — %s" % (uri, why))
                self._add(objects, "xsuaa_application", descriptor["xsappname"], uri)

        if not risky:
            return
        self.finding(
            check_id="CAPX-URI-001",
            title="OAuth redirect URI is broader than a specific host",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d of the %d redirect URI(s) declared by '%s' are wildcards "
                "over a whole domain space, or are not HTTPS. The redirect URI "
                "is where the authorization server delivers the authorization "
                "code after a user has successfully logged in, so anyone who "
                "controls a host the pattern admits receives a code minted for "
                "that user's real session — the application itself does not have "
                "to be vulnerable for this to work. SAP supports wildcards and "
                "cautions against them in the same breath: \"By using wildcards, "
                "you open up the redirect for multiple web sites. Wildcards "
                "increase the risk of redirecting to malicious web sites.\" A "
                "pattern like https://*.cfapps.<region>.hana.ondemand.com admits "
                "every application in the region, including other tenants'."
                % (len(risky), len(uris), self._app(descriptor))),
            affected_items=risky,
            remediation=(
                "1. Replace each wildcard with the explicit hostnames the "
                "application actually redirects to — the landscape host and the "
                "custom domain host, with their paths.\n"
                "2. Never wildcard the domain segment that identifies the "
                "application; if you must wildcard, keep it to a path under a "
                "host you own, for example "
                "https://myapp.mydomain.com/callback/**.\n"
                "3. Remove http:// entries; an authorization code delivered over "
                "plain HTTP can be read in transit.\n"
                "4. Confirm the list still covers every environment the same "
                "descriptor is deployed to, since a missing URI fails login "
                "outright and is usually why the wildcard was added.\n"
                "5. Redeploy and test the login and logout flows in each "
                "environment.\n"
                "6. Re-run the scan."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(oauth2-configuration, redirect-uris)",
                "SAP BTP — Security Considerations for the SAP Authorization and "
                "Trust Management Service (Listing Allowed Redirect URIs)",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"], "redirect_uris": uris},
            scope="aggregate",
        )

    @staticmethod
    def _redirect_risk(uri: str) -> str:
        """Why this redirect URI is broader than a named HTTPS host, or ``""``.

        A wildcard in the PATH is not flagged. SAP's own example of an acceptable
        pattern is `https://*.mydomain.com/callback/**`, and the risk lives in the
        host segment: a path wildcard under a host you own redirects to you,
        while a host wildcard redirects to whoever registers the name.
        """
        text = uri.strip()
        lowered = text.lower()
        if lowered.startswith("http://"):
            return "plain HTTP; an authorization code sent here can be read in transit"
        host = lowered.split("://", 1)[-1].split("/", 1)[0]
        if not host or host.strip("*.") == "":
            return "any host may receive the authorization code"
        if host.startswith("*.") and host.count(".") <= 1:
            return "wildcard spans an entire top-level domain"
        if host.startswith("*.") and _is_shared_landscape(host):
            return ("wildcard spans a shared SAP landscape domain, which admits "
                    "applications that are not yours")
        return ""

    # ── CAPX-CRED-001 ───────────────────────────────────────────────────────

    def check_credential_types(self, descriptor: Dict[str, Any]):
        """Binding secrets that cannot be rotated."""
        types = [str(t).strip().lower()
                 for t in _as_list(descriptor["oauth2"].get("credential-types"))
                 if str(t or "").strip()]
        if not types or "instance-secret" not in types:
            return
        objects = []
        self._add(objects, "xsuaa_application", descriptor["xsappname"],
                  "credential-types=%s" % ",".join(types))
        self.finding(
            check_id="CAPX-CRED-001",
            title="Application requests an instance secret, which cannot be rotated",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "'%s' declares `credential-types` including `instance-secret`. "
                "SAP's guidance is to use `binding-secret` or `x509` "
                "specifically so that \"you can rotate the secret of a binding "
                "without affecting the other bindings of the service "
                "instance\"; instance secrets cannot be rotated, and SAP's "
                "security considerations tell customers to remove the ones that "
                "already exist. The consequence is operational and it is the "
                "reason leaked secrets stay live: when a binding secret is "
                "exposed — in a build log, a config repository, a support "
                "ticket — the remedy for an instance secret is to recreate the "
                "service instance and rebind every consumer, which is an outage, "
                "so in practice it does not happen and the secret stays valid."
                % self._app(descriptor)),
            affected_items=["%s: credential-types = %s"
                            % (descriptor["file"], ", ".join(types))],
            remediation=(
                "1. Change `credential-types` to [\"binding-secret\"] or "
                "[\"binding-secret\", \"x509\"], preferring x509 where the "
                "consumer supports it.\n"
                "2. Update the service instance and create new bindings; each "
                "binding then carries its own rotatable secret.\n"
                "3. Remove the old instance secrets once every consumer is on a "
                "binding secret — SAP asks explicitly that these be removed.\n"
                "4. Treat any instance secret that has ever been exposed as "
                "compromised until the instance is recreated.\n"
                "5. Add secret rotation for these bindings to your operational "
                "schedule.\n"
                "6. Re-run the scan."),
            references=[
                "SAP BTP — Security Considerations for the SAP Authorization and "
                "Trust Management Service (Rotating Secrets)",
                "SAP BTP Security Recommendations — BTP-UAA-0003",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"], "credential_types": types},
            scope="aggregate",
        )

    # ── CAPX-TEN-001 ────────────────────────────────────────────────────────

    def check_tenant_mode(self, descriptor: Dict[str, Any]):
        """`tenant-mode: shared` gives every subaccount the same client secret."""
        if descriptor["tenant_mode"].lower() != "shared":
            return
        objects = []
        self._add(objects, "xsuaa_application", descriptor["xsappname"],
                  "tenant-mode=shared")
        self.finding(
            check_id="CAPX-TEN-001",
            title="Application uses the shared tenant mode (one client secret everywhere)",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "'%s' declares `\"tenant-mode\": \"shared\"`. SAP documents what "
                "that means for the credential: \"An OAuth client always gets "
                "the same client secret. It's valid in all subaccounts.\" The "
                "default mode, `dedicated`, gives a separate secret per "
                "subaccount. Shared is the correct choice for a multitenant "
                "application using the application service plan, so this is a "
                "review item rather than a defect — but the blast radius of the "
                "secret changes completely. A secret recovered from a "
                "development or sandbox subaccount is the production secret too, "
                "so the weakest environment this application is deployed into "
                "sets the security of every other one, including subscriber "
                "tenants."
                % self._app(descriptor)),
            affected_items=["%s: tenant-mode = shared" % descriptor["file"]],
            remediation=(
                "1. Confirm this application is genuinely multitenant and needs "
                "the application service plan; if it is single-tenant, remove "
                "the property so it defaults to `dedicated`.\n"
                "2. Where shared is required, hold every subaccount this "
                "application is deployed into — including sandboxes — to the "
                "same standard as production for secret handling.\n"
                "3. Confirm the secret is not present in any source repository, "
                "CI variable or configuration file outside a secret store.\n"
                "4. Prefer x509 credential types so the credential can be "
                "rotated per binding.\n"
                "5. Re-run the scan once the mode and the environments agree."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(tenant-mode)",
            ],
            affected_objects=objects,
            details={"descriptor": descriptor["file"], "tenant_mode": "shared"},
            scope="aggregate",
        )

    # ── CAPX-CDS-001: services nobody protected ─────────────────────────────

    def check_model_access_control(self, model: CdsModel):
        """Services with no authorization annotation the parser could find.

        The default is documented and it is not "deny": "By default, CDS services
        have no access control, which means that without authorization modeling,
        authenticated users have access to all entities." CAP's own guide puts a
        warning box next to it — "Applications must implement proper
        authorization. CAP cannot enforce this automatically as it depends
        entirely on the specific domain model."

        `@protocol: 'none'` is excluded: a service that is not exposed through
        any protocol adapter cannot be called from outside, which is the
        documented way to declare a service internal.
        """
        if not model.services:
            return
        open_services, objects = [], []
        for name in sorted(model.services):
            info = model.services[name]
            annotations = model.annotations_for(name)
            if _has_protection(annotations):
                continue
            if re.search(r"protocol\s*:\s*['\"]none['\"]", annotations):
                continue
            open_services.append("%s (%s:%d)" % (name, info["file"], info["line"]))
            self._add(objects, "cap_service", name)

        if not open_services:
            return
        self.finding(
            check_id="CAPX-CDS-001",
            title="CAP service exposed with no access control",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d of %d CAP service(s) in this project carry no `@requires` "
                "and no `@restrict`, and are not marked `@protocol: 'none'`. "
                "CAP's behaviour here is documented and is not deny-by-default: "
                "\"By default, CDS services have no access control, which means "
                "that without authorization modeling, authenticated users have "
                "access to all entities.\" Any user who can authenticate to the "
                "subaccount — which, where the default SAP ID Service is still "
                "trusted, is a self-registered account — can read and write "
                "every entity the service exposes, including entities the "
                "compiler auto-exposed that were never listed in the service "
                "definition. CAP's own guide states the responsibility "
                "directly: \"Applications must implement proper authorization. "
                "CAP cannot enforce this automatically as it depends entirely on "
                "the specific domain model.\""
                % (len(open_services), len(model.services))),
            affected_items=open_services,
            remediation=(
                "1. For each service, decide the minimum role that should reach "
                "it and annotate it: `@(requires: 'Viewer')` on the service, or "
                "`@(restrict: [...])` for per-event control.\n"
                "2. Use `@requires: 'authenticated-user'` only where any "
                "authenticated user genuinely should have access, and never as a "
                "placeholder.\n"
                "3. Mark services that exist only for in-process handlers with "
                "`@protocol: 'none'` so no protocol adapter exposes them.\n"
                "4. Check the entities each service auto-exposes — compositions "
                "and @cds.autoexpose value lists are reachable through the "
                "service even though they are not written in it.\n"
                "5. Add the corresponding roles to xs-security.json by running "
                "`cds compile --to xsuaa`, and assign the resulting role "
                "collections.\n"
                "6. Re-run the scan and confirm each service now resolves to a "
                "role that exists in the descriptor."),
            references=[
                "SAP CAP — CAP-level Authorization (Declarative Access Control)",
                "SAP CAP — @requires and @restrict",
            ],
            affected_objects=objects,
            details={"services_total": len(model.services),
                     "services_unprotected": len(open_services),
                     "parser": "lexical"},
            scope="aggregate",
        )

    # ── CAPX-CDS-002: the `any` default ─────────────────────────────────────

    def check_open_privileges(self, model: CdsModel):
        """A `@restrict` privilege with no `to` applies to everyone.

        This is the sharpest edge in CAP's authorization model, because the
        annotation looks like a restriction and reads like one. SAP: "the `any`
        pseudo-role applies for all users and is the default if no value is
        provided". A privilege `{ grant: 'READ' }` restricts the EVENT and not
        the AUDIENCE, so it grants read to everybody — and it sits inside a
        `@restrict` block, next to privileges that do name roles, which is
        exactly where a reviewer stops looking.
        """
        if not model.open_privileges:
            return
        items, objects = [], []
        for label, line, text in model.open_privileges:
            items.append("%s:%d — %s" % (label, line, text))
            self._add(objects, "cds_source", label, "line %d" % line)
        self.finding(
            check_id="CAPX-CDS-002",
            title="@restrict privilege grants to every user (no `to` given)",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d `@restrict` privilege(s) name an event but no audience. "
                "SAP documents the default: \"the `any` pseudo-role applies for "
                "all users and is the default if no value is provided\". A "
                "privilege such as `{ grant: 'READ' }` therefore restricts WHAT "
                "may be done and not WHO may do it, granting that event to every "
                "caller. Because CAP combines the privileges of a `@restrict` "
                "block with logical OR — \"A request passes such a restriction "
                "if at least one of the privileges is met\" — one unbounded "
                "privilege defeats every other privilege in the same block, "
                "including the ones that carefully name a role. This is the "
                "hardest authorization defect to catch by reading, because the "
                "annotation is present, is syntactically correct, and sits "
                "beside privileges that look right."
                % len(model.open_privileges)),
            affected_items=items,
            remediation=(
                "1. Open each location listed and add an explicit `to:` to the "
                "privilege — a named role, or `'authenticated-user'` if any "
                "logged-in user genuinely qualifies.\n"
                "2. Where the privilege was meant to be open on purpose, write "
                "`to: 'any'` explicitly, so the next reader sees a decision "
                "rather than an omission.\n"
                "3. Re-read the whole `@restrict` block: because privileges "
                "combine with OR, the other privileges in it have been having no "
                "effect.\n"
                "4. Add a test that calls the entity as an unauthorized user and "
                "expects a rejection.\n"
                "5. Re-run the scan."),
            references=[
                "SAP CAP — @restrict annotation (grant / to / where)",
            ],
            affected_objects=objects,
            details={"parser": "lexical",
                     "privileges": len(model.open_privileges)},
            scope="aggregate",
        )

    # ── CAPX-CDS-003: the model and the descriptor disagree ─────────────────

    def check_model_descriptor_agreement(self, model: CdsModel,
                                         descriptors: List[Dict[str, Any]]):
        """Roles the model enforces that no descriptor in this project grants.

        `cds compile --to xsuaa` generates a role-template for every role named
        in the model, so in a project whose descriptor is generated the two sides
        agree by construction. They come apart when the descriptor is hand-kept,
        when a role is renamed on one side only, or when the descriptor is
        generated from a subset of the model.

        The consequence runs in the safe direction — a role nothing grants is a
        role nobody holds, so the service is unreachable rather than open — which
        is precisely why it survives: it presents as a support ticket about
        missing authorizations, and the usual field fix is to widen something
        else until the user gets in.

        THIS DOES NOT ASSERT WHICH SIDE IS WRONG. The role may legitimately come
        from another application's descriptor, which is not in this project.
        """
        if not descriptors or not model.roles:
            return
        granted = set()
        for descriptor in descriptors:
            for template in descriptor["role_templates"]:
                name = self._name(template)
                if name:
                    granted.add(name)
            for scope in descriptor["scopes"]:
                kind, name = _split_reference(self._name(scope))
                if kind == "local" and name:
                    granted.add(name)

        missing, objects = [], []
        for role in sorted(model.roles):
            if role in _PSEUDO_ROLES or role in granted:
                continue
            sites = sorted(model.roles[role])
            missing.append("%s — enforced at %s%s"
                           % (role, ", ".join(sites[:3]),
                              " and %d more" % (len(sites) - 3) if len(sites) > 3 else ""))
            self._add(objects, "cap_role", role)

        if not missing:
            return
        self.finding(
            check_id="CAPX-CDS-003",
            title="CDS model enforces a role no security descriptor grants",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d role(s) are enforced by `@requires` or `@restrict` in the "
                "CDS model but appear as neither a role-template nor a scope in "
                "any `xs-security.json` in this project. `cds compile --to "
                "xsuaa` generates a role-template for every role the model "
                "names, so a generated descriptor agrees with the model by "
                "construction; the two come apart when the descriptor is "
                "hand-maintained, when a role is renamed on one side only, or "
                "when the descriptor was generated from an earlier version of "
                "the model. The failure is quiet and runs in the safe direction "
                "— a role nothing grants is a role nobody can hold, so the "
                "resource is unreachable rather than open — which is exactly why "
                "it persists: it surfaces as a user reporting missing "
                "authorization, and the fastest field fix is to widen a "
                "different role until the user gets in. This finding does not "
                "assert which side is wrong: the role may be granted by another "
                "application's descriptor that is not part of this project."
                % len(missing)),
            affected_items=missing,
            remediation=(
                "1. For each role, establish which side is authoritative — is "
                "the role a typo in the model, or a role-template that was never "
                "added to the descriptor?\n"
                "2. If the descriptor is generated, run `cds compile --to "
                "xsuaa` and commit the result, rather than editing the generated "
                "file.\n"
                "3. If the role is granted by a different application, record "
                "that dependency; this project alone cannot show it.\n"
                "4. After redeploying, confirm the role appears in the "
                "subaccount's role list and is referenced by a role "
                "collection.\n"
                "5. Add an integration test that calls each restricted service "
                "as a user holding the role, so a future rename fails the build "
                "instead of reaching production.\n"
                "6. Re-run the scan."),
            references=[
                "SAP CAP — CAP-level Authorization",
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(role-templates)",
            ],
            affected_objects=objects,
            details={"parser": "lexical", "roles_in_model": len(model.roles),
                     "descriptors": [d["file"] for d in descriptors]},
            scope="aggregate",
        )

    # ── CAPX-GRAPH-002: the whole chain, end to end ─────────────────────────

    def check_who_holds_the_scopes(self, descriptors: List[Dict[str, Any]]):
        """Trace this application's scopes to the people who actually hold them.

        THIS IS THE JOIN THE MODULE EXISTS FOR. Neither side can answer the
        question alone. The descriptor knows that role-collection `X` carries
        role-template `Y` which carries scope `Z`, and knows nothing about who
        has `X`. The subaccount export knows that `X` is mapped to the IdP group
        `Default`, and knows nothing about what `X` grants. Put together they say
        that every federated user in the subaccount holds scope `Z`.

        Reported only for collections mapped to a birthright group, because that
        is the case where the answer is "everybody" and no assignment review will
        ever show it. `S4AUTHZ-008` reports the same mappings from the subaccount
        side without knowing what they grant; this adds the grant and says so, so
        a reader seeing both knows they are one situation and not two.
        """
        rows = self.data.get("btp_role_collection_mappings")
        if not rows or not descriptors:
            return

        # collection name -> the local scopes it delivers, via its role-templates
        delivers = {}
        for descriptor in descriptors:
            templates = {}
            for template in descriptor["role_templates"]:
                scopes = []
                for ref in _as_list(template.get("scope-references")):
                    kind, name = _split_reference(ref)
                    scopes.append(name if kind == "local" else str(ref))
                templates[self._name(template)] = scopes
            for collection in descriptor["role_collections"]:
                cname = self._name(collection)
                if not cname:
                    continue
                grants = delivers.setdefault(cname.lower(), {
                    "name": cname, "app": self._app(descriptor), "scopes": []})
                for ref in _as_list(collection.get("role-template-references")):
                    kind, name = _split_reference(ref)
                    for scope in templates.get(name, []):
                        if scope not in grants["scopes"]:
                            grants["scopes"].append(scope)

        if not delivers:
            return

        found, objects = [], []
        for row in self._rows(rows):
            name = self._cell(row, "ROLE_COLLECTION", "ROLECOLLECTION",
                              "COLLECTION", "NAME")
            group = self._cell(row, "IDP_GROUP", "GROUP", "MAPPED_GROUP",
                               "ATTRIBUTE_VALUE")
            if not name or not group:
                continue
            lowered = group.strip().lower()
            if lowered not in _BIRTHRIGHT_GROUPS and "default" not in lowered:
                continue
            grants = delivers.get(name.strip().lower())
            if not grants:
                continue
            # The direct user count, where the export carries it, is added as
            # context — a birthright collection that ALSO has named assignments
            # tells the reader somebody was assigning it by hand as well, which
            # is usually a sign nobody realised the group mapping existed.
            direct = self._cell(row, "USER_COUNT")
            extra = ""
            if direct.isdigit() and int(direct) > 0:
                extra = " (plus %s direct user assignment(s))" % direct
            found.append(
                "%s <- IdP group '%s' (every federated user)%s -> grants %d scope(s) "
                "of '%s': %s" % (name, group, extra, len(grants["scopes"]),
                                 grants["app"], ", ".join(grants["scopes"])
                                 or "(none resolved from this descriptor)"))
            self._add(objects, "role_collection", name,
                      "grants %s" % ", ".join(sorted(grants["scopes"])))

        if not found:
            return
        self.finding(
            check_id="CAPX-GRAPH-002",
            title="Application scopes are granted to every federated user by birthright",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d role collection(s) declared by this project's security "
                "descriptor are mapped in the subaccount to a Default or "
                "wildcard IdP group, so every user who authenticates through the "
                "corporate identity provider receives them automatically. The "
                "chain is complete and it is stated above for each one: scope <- "
                "role-template <- role-collection <- IdP group. That chain is "
                "why this is a separate finding from the mapping itself — the "
                "subaccount export shows a collection mapped to Default and "
                "cannot say what it grants, while the descriptor shows what it "
                "grants and cannot say who holds it. Read together they show "
                "named application privileges held by the entire user base, "
                "which no user-assignment review will surface, because there are "
                "no user assignments to review. `S4AUTHZ-008` reports the same "
                "mappings from the subaccount side without the grant; this and "
                "that finding are one situation."
                % len(found)),
            affected_items=found,
            remediation=(
                "1. For each collection, decide whether the scopes it delivers "
                "are genuinely universal — read-only launchpad access often is; "
                "anything that writes is not.\n"
                "2. Re-map the collection from the Default group to a specific "
                "IdP group that names the population that should hold it.\n"
                "3. Where a genuinely universal baseline is needed, split it: "
                "keep the read-only scopes in the birthright collection and move "
                "the rest to a requested collection.\n"
                "4. Review the CDS services these scopes reach, since the scope "
                "is only the key — what it opens is decided by @requires and "
                "@restrict in the model.\n"
                "5. Re-run the scan and confirm the chain no longer terminates "
                "at a Default group."),
            references=[
                "SAP BTP — Role Collections and Trust Configuration (default groups)",
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(role-collections)",
            ],
            affected_objects=objects,
            details={"also_reported_by": "S4AUTHZ-008",
                     "chain": "scope <- role-template <- role-collection <- IdP group"},
            scope="aggregate",
        )

    # ── CAPX-GRAPH-003 ──────────────────────────────────────────────────────

    def check_undeliverable_role_templates(self, descriptors: List[Dict[str, Any]]):
        """Role-templates no collection can deliver.

        A role-template is not assignable on its own — an administrator assigns a
        role COLLECTION. So a template referenced by no collection, in the
        descriptor or in the subaccount, produces a privilege that exists in the
        descriptor and cannot be given to anybody.

        Requires the subaccount's role collections. Without them a template
        missing from the descriptor's own `role-collections` proves nothing: the
        collection may have been assembled in the cockpit, which is the normal
        way it is done for anything shared between applications. The check stays
        silent rather than reporting a project that is configured correctly.
        """
        rows = self.data.get("btp_role_collection_mappings")
        if not descriptors or not rows:
            return

        deployed = set()
        for row in self._rows(rows):
            for column in ("ROLE_NAMES", "ROLES", "ROLE_REFERENCES"):
                value = self._cell(row, column)
                for part in re.split(r"[;,|]", value):
                    if part.strip():
                        deployed.add(part.strip().lower())
        if not deployed:
            # The export carried collections but not the role names inside them,
            # so "no collection references this template" cannot be established.
            return

        orphaned, objects = [], []
        for descriptor in descriptors:
            referenced = set()
            for collection in descriptor["role_collections"]:
                for ref in _as_list(collection.get("role-template-references")):
                    kind, name = _split_reference(ref)
                    referenced.add((name if kind == "local" else str(ref)).lower())
            for template in descriptor["role_templates"]:
                name = self._name(template)
                if not name:
                    continue
                if name.lower() in referenced or name.lower() in deployed:
                    continue
                orphaned.append("role-template '%s' of '%s' is referenced by no "
                                "role collection, in this descriptor or in the "
                                "subaccount" % (name, self._app(descriptor)))
                self._add(objects, "xsuaa_role_template", name)

        if not orphaned:
            return
        self.finding(
            check_id="CAPX-GRAPH-003",
            title="Role template that no role collection can deliver",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d role-template(s) are defined by this project but referenced "
                "by no role collection — not by the descriptor's own "
                "`role-collections`, and not by any collection in the "
                "subaccount's export. An administrator assigns role "
                "collections, never role templates directly, so the privilege "
                "these templates carry cannot be granted to anyone as things "
                "stand. Two situations produce this and they need opposite "
                "responses. Either the template is obsolete, in which case it is "
                "clutter that makes the authorization design harder to read and "
                "should be deleted; or it is required and its role collection "
                "was never created, in which case a service in this application "
                "is currently unreachable and somebody is about to be granted "
                "something broader to work around it."
                % len(orphaned)),
            affected_items=orphaned,
            remediation=(
                "1. For each template, establish whether the privilege is still "
                "needed — the CDS services referencing the matching role will "
                "tell you.\n"
                "2. Where it is needed, add a `role-collections` entry to the "
                "descriptor referencing it, or create the collection in the "
                "cockpit and map it to the appropriate IdP group.\n"
                "3. Where it is obsolete, remove the role-template and the "
                "scopes only it referenced.\n"
                "4. Confirm no user was granted a broader collection as a "
                "workaround for the missing one.\n"
                "5. Re-run the scan with a current role-collection export."),
            references=[
                "SAP BTP — Application Security Descriptor Configuration Syntax "
                "(role-collections)",
            ],
            affected_objects=objects,
            details={"requires": "btp_role_collections.json with roleReferences"},
            scope="aggregate",
        )

    # ── CAPX-COV-001 ────────────────────────────────────────────────────────

    def report_coverage(self, root: Path, descriptors: List[Dict[str, Any]],
                        model: CdsModel):
        """State what was read and, more importantly, what was not.

        Emitted whenever anything could not be read, and ALSO whenever the CDS
        model was read without a descriptor or the reverse — because half of this
        module's checks are joins, and a join with one side missing produces
        silence that looks exactly like agreement.
        """
        gaps = list(getattr(self, "_unreadable_descriptors", []))
        gaps.extend(model.unresolved)

        if descriptors and not model.files:
            gaps.append("no .cds file was found, so no service, role or "
                        "restriction in the model was examined")
        if model.files and not descriptors:
            gaps.append("no xs-security.json was found, so no role the model "
                        "enforces could be checked against a descriptor")
        if not gaps:
            return

        self._coverage(
            "CAPX-COV-001",
            "Parts of the CAP project could not be read",
            ("This scan read %d security descriptor(s) and %d CDS file(s) under "
             "%s, and %d thing(s) below it could not resolve. The CDS model is "
             "read lexically — this product is offline and stdlib-only, so there "
             "is no CDS compiler here to ask — which is enough to find a service "
             "nobody protected and is NOT enough to prove a service IS "
             "protected. Every construct this pass could not resolve is listed, "
             "because a check that skipped one and stayed silent would be "
             "indistinguishable from a check that ran and passed."
             % (len(descriptors), model.files, root, len(gaps))),
            gaps,
            ("1. Fix any descriptor reported as unparseable — a security "
             "descriptor that does not parse is the one most worth reading.\n"
             "2. For unresolved CDS constructs, confirm the file is complete and "
             "syntactically valid by running `cds compile` over the project.\n"
             "3. Where a side is missing entirely, supply it: --cap-src should "
             "point at a root holding both the descriptor and the model.\n"
             "4. Supply btp_role_collections.json as well, so the descriptor can "
             "be joined to who actually holds the collections.\n"
             "5. Re-run. Treat this module's silence on anything listed here as "
             "unknown, not clean."),
            {"descriptors": len(descriptors), "cds_files": model.files,
             "unresolved": len(gaps), "parser": "lexical"})

    # ── helpers ─────────────────────────────────────────────────────────────

    def _coverage(self, check_id: str, title: str, description: str,
                  affected_items: List[str], remediation: str,
                  details: Dict[str, Any]) -> None:
        """A finding that says the scan could not see something.

        `degrades_coverage` is what arms `--gate`'s fail-closed path. INFO is
        correct and is not a judgement about importance: nothing here says the
        project is bad, only that the rest of this module's silence is not
        evidence of absence.
        """
        details = dict(details)
        details["degrades_coverage"] = True
        self.finding(
            check_id=check_id,
            title=title,
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=description,
            affected_items=affected_items,
            remediation=remediation,
            details=details,
            scope="aggregate",
        )

    @staticmethod
    def _add(bucket: List[Dict[str, Any]], obj_type: str, name: Any,
             qualifier: Any = None) -> None:
        """One structured affected object, or nothing.

        An unnamed row contributes NO object. Emitted with a placeholder name it
        would merge every unnamed row across every run into one graph node and
        one finding identity — the same rule `btp_cloud_surface._add_object`
        follows, and for the same reason.
        """
        text = "" if name is None else str(name).strip()
        if not text or text.lower() in ("unknown", "none"):
            return
        obj = {"type": obj_type, "name": text}
        qual = "" if qualifier is None else str(qualifier).strip()
        if qual:
            obj["qualifier"] = qual
        bucket.append(obj)

    @staticmethod
    def _rows(rows: Any) -> List[Dict[str, Any]]:
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
        if isinstance(rows, dict):
            for key in ("rows", "items", "value"):
                found = rows.get(key)
                if isinstance(found, list):
                    return [r for r in found if isinstance(r, dict)]
        return []

    @staticmethod
    def _cell(row: Dict[str, Any], *names: str) -> str:
        for name in names:
            for key in (name, name.lower(), name.upper()):
                if key in row and row[key] is not None:
                    return str(row[key]).strip()
        return ""

    @staticmethod
    def _int(value: Any) -> Optional[int]:
        if isinstance(value, bool):
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _duration(seconds: int) -> str:
        """`43200 s (12 hours)` — identical wording to `btp_cloud_surface`, so
        the subaccount finding and the application override finding describe the
        same quantity the same way."""
        if seconds % 86400 == 0 and seconds >= 86400:
            unit, count = "day", seconds // 86400
        elif seconds % 3600 == 0 and seconds >= 3600:
            unit, count = "hour", seconds // 3600
        elif seconds % 60 == 0 and seconds >= 60:
            unit, count = "minute", seconds // 60
        else:
            return "%d s" % seconds
        return "%d s (%d %s%s)" % (seconds, count, unit, "" if count == 1 else "s")


# ═════════════════════════════════════════════════════════════════════════════
#  Module-level predicates
# ═════════════════════════════════════════════════════════════════════════════

_SHARED_LANDSCAPE = ("hana.ondemand.com", "cfapps.", "ondemand.com",
                     "hanacloud.ondemand.com")


def _is_shared_landscape(host: str) -> bool:
    """Is this a shared SAP landscape domain rather than a customer's own?

    A wildcard over `*.cfapps.eu10.hana.ondemand.com` admits every application
    deployed in that region — including other customers'. A wildcard over
    `*.acme.com` admits only hosts the customer controls, which is the case SAP
    documents as acceptable.
    """
    return any(marker in host for marker in _SHARED_LANDSCAPE)


def _has_protection(annotations: str) -> bool:
    """Does this annotation text restrict access at all?

    Deliberately generous: any `requires` or `restrict` counts, whatever it
    says. A generous reading here makes CAPX-CDS-001 UNDER-report, and that is
    the right direction to be wrong — the finding claims a service has no access
    control at all, which must not be raised against a service whose annotation
    this parser merely failed to interpret. Services that are annotated but
    annotated badly are the subject of CAPX-CDS-002 and CAPX-CDS-003.
    """
    if not annotations:
        return False
    return bool(re.search(r"\b(requires|restrict)\s*:", annotations))
