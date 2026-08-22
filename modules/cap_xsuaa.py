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

THE SECOND GRAPH: WHAT ONE REQUEST REACHES
`CAPX-CDS-004` walks a different graph — associations and compositions — for a
defect CAP documents against itself. "Currently, the security annotations are
only evaluated on the target entity of the request... Restrictions of
(recursively) expanded or inlined entities of a READ request aren't checked." So
an entity CAN carry a correct `@requires`, be reached by `$expand` from a service
that never demanded that role, and hand over its rows. The model looks right and
the runtime does not enforce it, which is why reading the annotations alone —
what every other CDS check here does — cannot find it.

Two things had to be modelled or the check would have done harm rather than good.
AUTO-REDIRECTION, because CAP's own remedy is to expose a reduced projection and
navigation redirects onto it; a walk that ignored redirection would report a
project that had applied the documented fix correctly. And THE RUNTIME SPLIT,
because CAP Java 4.0+ does check association hops while neither runtime checks
composition hops — so the finding names which kind it found and which runtime the
project builds on, rather than asserting one blanket severity over both.

WHAT THIS MODULE DOES NOT CLAIM
  * That a CDS role missing from the descriptor is a defect. It may be granted by
    another application's role-template. `CAPX-CDS-003` reports the disagreement,
    not a verdict on which side is wrong.
  * That a reachable entity is necessarily reachable by an unauthorized caller.
    `CAPX-CDS-004` fires only where the two role sets are DISJOINT — the target
    asks for something the root never made the caller prove. Roles are not
    ordered, so "weaker" is not a judgement this module makes.
  * That an element is sensitive because of what it is called. `CAPX-CDS-005`
    rests on the model's own `@PersonalData` annotations and nothing else.
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

#: How deep a navigation path is followed before the walk gives up. A CAP model
#: is a graph, not a tree, and `Teams -> members -> team -> members` is a legal
#: cycle; the walk is cycle-safe by construction, but depth still needs a bound
#: so that a wide model cannot turn one exposed entity into a combinatorial
#: report. Six hops is well past the two the documented example needs and past
#: anything a reviewer would follow by hand. Paths cut at the bound are counted
#: and named in the coverage manifest rather than dropped silently.
_MAX_NAV_DEPTH = 6

#: Element annotations that mark a field as personal or sensitive IN THE MODEL
#: ITSELF. These are the only basis CAPX-CDS-005 uses. Guessing sensitivity from
#: an element's NAME — salary, iban, password — would be a heuristic dressed as
#: a finding, and would be wrong in both directions: it would miss
#: `remuneration` and would flag a column called `password_policy_id`.
#: `@PersonalData.*` is SAP's own vocabulary from the CAP data-privacy guide,
#: applied by the developer, and it means what the finding says it means.
_SENSITIVE_ELEMENT_ANNOTATIONS = (
    "@PersonalData.IsPotentiallySensitive",
    "@PersonalData.IsPotentiallyPersonal",
)


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

_ENTITY_DECL = re.compile(r"\bentity\s+([A-Za-z_][\w.]*)", re.MULTILINE)
_NAMESPACE_DECL = re.compile(r"\bnamespace\s+([A-Za-z_][\w.]*)\s*;", re.MULTILINE)
_USING_DECL = re.compile(r"\busing\s+(\{[^}]*\}|[A-Za-z_][\w.]*(?:\s+as\s+[A-Za-z_]\w*)?)"
                         r"\s+from\b", re.MULTILINE)
_USING_ALIAS = re.compile(r"([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?")

#: `as projection on X`, `as select from X`, `as X` — the three ways a service
#: entity names the entity it is built from. All three are followed, because a
#: navigation reachable through a `select from` is exactly as reachable at
#: runtime as one reachable through a `projection on`.
_PROJECTION_SOURCE = re.compile(
    r"\bas\s+(?:projection\s+on|select\s+from)\s+([A-Za-z_][\w.]*)", re.IGNORECASE)

#: `excluding { a, b }` — CAP's own remedy for the exposure CAPX-CDS-004 and
#: CAPX-CDS-005 report, so the parser has to see it or the checks would keep
#: reporting a project that had already fixed itself.
_EXCLUDING = re.compile(r"\bexcluding\s*\{([^}]*)\}", re.IGNORECASE)

#: `Association to X`, `Association to many X`, `Composition of many X`. The
#: `to`/`of` pair is not interchangeable in CDL but both spellings appear for
#: both kinds in real models, so the parser accepts either and keeps the KIND
#: from the keyword — the kind is what decides whether CAP Java checks the
#: target, and the finding says which one it saw.
_NAVIGATION = re.compile(
    r"\b(Association|Composition)\s+(?:to|of)\s+(?:many\s+)?([A-Za-z_][\w.$]*)",
    re.IGNORECASE)


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
        #: Every `entity` declaration, keyed by its fully-qualified name where a
        #: namespace was declared and by its bare name otherwise. Entities inside
        #: a service body are keyed `Service.Entity`, which is how CAP addresses
        #: them and how `annotate CatalogService.Books with` names them.
        self.entities = {}
        #: Unqualified name -> set of qualified names carrying it. A model may
        #: legitimately hold two `Books`, and a navigation target written `Books`
        #: is then genuinely ambiguous; the resolver records that rather than
        #: picking one.
        self.by_short_name = {}
        #: Paths abandoned at `_MAX_NAV_DEPTH`, for the coverage manifest.
        self.truncated_paths = []

    def annotations_for(self, service: str) -> str:
        parts = [self.services.get(service, {}).get("annotations", "")]
        parts.extend(self.annotate_targets.get(service, []))
        return "\n".join(p for p in parts if p)

    def entity_annotations(self, name: str) -> str:
        """Everything annotating one entity, inline and from `annotate` blocks.

        The two are equal in CAP and the fixture uses both, so a check that read
        only the inline half would report a protected entity as unprotected.
        """
        parts = [self.entities.get(name, {}).get("annotations", "")]
        parts.extend(self.annotate_targets.get(name, []))
        return "\n".join(p for p in parts if p)

    def register_entity(self, name: str, info: Dict[str, Any]) -> None:
        self.entities[name] = info
        self.by_short_name.setdefault(name.rsplit(".", 1)[-1], set()).add(name)


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

    service_spans = []
    for match in _SERVICE_DECL.finditer(text):
        name = match.group(1)
        annotations = (_annotation_span_before(text, match.start())
                       + " " + _inline_annotations(text, match.end()))
        model.services[name] = {
            "file": label,
            "line": text.count("\n", 0, match.start()) + 1,
            "annotations": annotations,
        }
        body = text.find("{", match.end())
        if body >= 0:
            end = _balanced(text, body, "{", "}")
            if end < 0:
                model.unresolved.append(
                    "%s: body of `service %s` has no closing brace" % (label, name))
            else:
                service_spans.append((body, end, name))

    _parse_entities(text, label, model, service_spans)

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


def _parse_entities(text: str, label: str, model: CdsModel,
                    service_spans: List[Tuple[int, int, str]]) -> None:
    """Every `entity` in one file, with its elements and its projection source.

    The two kinds of entity are read the same way and kept apart by WHERE they
    were found. An entity inside a `service { ... }` body is a service entity —
    what OData exposes — and is keyed `Service.Entity`. An entity outside every
    service body is a domain entity, keyed with the file's namespace. The
    distinction matters because the exposure question is asked of one and the
    navigation question of the other.
    """
    namespace = ""
    ns = _NAMESPACE_DECL.search(text)
    if ns:
        namespace = ns.group(1)
    aliases = _using_aliases(text)

    for match in _ENTITY_DECL.finditer(text):
        short = match.group(1)
        start = match.start()
        owner = next((name for begin, end, name in service_spans
                      if begin < start < end), None)
        if owner:
            qualified = "%s.%s" % (owner, short)
        elif namespace and "." not in short:
            qualified = "%s.%s" % (namespace, short)
        else:
            qualified = short

        head_end = _declaration_head_end(text, match.end())
        head = text[match.end():head_end]
        source_match = _PROJECTION_SOURCE.search(head)
        excluding = set()
        for group in _EXCLUDING.finditer(head):
            excluding |= {n.strip() for n in group.group(1).split(",") if n.strip()}

        elements = []
        body = text.find("{", match.end())
        if body >= 0 and body < head_end:
            end = _balanced(text, body, "{", "}")
            if end < 0:
                model.unresolved.append(
                    "%s: body of `entity %s` has no closing brace, so its "
                    "elements and navigations were not read" % (label, short))
            else:
                elements = _parse_elements(text[body + 1:end - 1], namespace,
                                           aliases, body + 1, text)

        model.register_entity(qualified, {
            "file": label,
            "line": text.count("\n", 0, start) + 1,
            "name": qualified,
            "short": short,
            "service": owner,
            "annotations": (_annotation_span_before(text, start) + " "
                            + head[:source_match.start() if source_match else len(head)]),
            "source": (_qualify(source_match.group(1), namespace, aliases)
                       if source_match else None),
            "source_written": source_match.group(1) if source_match else None,
            "excluding": excluding,
            "elements": elements,
        })


def _declaration_head_end(text: str, start: int) -> int:
    """End of a declaration's head — its `{` body, its `;`, or end of file.

    Scanning to the first `{` alone would be wrong for
    `entity X as projection on db.Y;`, which has no body, and scanning to the
    first `;` alone would be wrong for an entity whose element list contains
    several. Whichever comes first wins, and the body case is then re-read from
    its own brace.
    """
    i, quote = start, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "{":
            end = _balanced(text, i, "{", "}")
            return len(text) if end < 0 else end
        elif ch == ";":
            return i
        i += 1
    return len(text)


def _parse_elements(block: str, namespace: str, aliases: Dict[str, str],
                    offset: int, whole: str) -> List[Dict[str, Any]]:
    """The elements of one entity body: name, navigation target, annotations.

    Elements are separated by `;` at depth zero. Nested `{ }` — an anonymous
    composition's inline type — is skipped as a unit rather than descended into:
    its own elements belong to a generated entity that no `@restrict` in the
    source can name, so there is nothing this analysis could say about them that
    would not be a guess.
    """
    out = []
    i, start, depth, quote = 0, 0, 0, None
    while i <= len(block):
        ch = block[i] if i < len(block) else ";"
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
        elif ch == ";" and depth <= 0:
            piece = block[start:i]
            element = _parse_one_element(piece, namespace, aliases)
            if element:
                # Anchored on the element NAME, not on the start of the
                # fragment. A fragment starts just after the previous `;`, so
                # its own offset is the end of the LINE BEFORE — and for an
                # annotated element it is two lines before the one a reader
                # needs. Findings quote this number; it has to land on the
                # element.
                element["line"] = whole.count(
                    "\n", 0, offset + start + element.pop("_at")) + 1
                out.append(element)
            start = i + 1
        i += 1
    return out


_ELEMENT_NAME = re.compile(
    r"(?:\b(?:key|virtual|masked|localized)\s+)*([A-Za-z_]\w*)\s*:", re.IGNORECASE)


def _parse_one_element(piece: str, namespace: str,
                       aliases: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """One `name : Type` element, or None if this fragment holds no element.

    A fragment with no `name :` is not an error — an entity body's first piece
    is often just the inherited-aspect list — so it returns None quietly rather
    than being recorded as unresolved.
    """
    match = _ELEMENT_NAME.search(piece)
    if not match:
        return None
    navigation = _NAVIGATION.search(piece)
    return {
        "name": match.group(1),
        "_at": match.start(1),
        # The whole fragment. Elements are split on `;` before this is called,
        # so every annotation in it belongs to this element and none can leak in
        # from the next — which is why no attempt is made to separate the
        # leading form `@X\n name : T` from the trailing form `name : T @X`.
        # Both are legal CDL and both appear in real models.
        "annotations": piece,
        "kind": navigation.group(1).lower() if navigation else None,
        "target": (_qualify(navigation.group(2), namespace, aliases)
                   if navigation else None),
        "target_written": navigation.group(2) if navigation else None,
    }


def _using_aliases(text: str) -> Dict[str, str]:
    """`using { acme.bookshop as db }` -> `{"db": "acme.bookshop"}`.

    Without this a navigation to `db.Contracts` never resolves to the entity
    `acme.bookshop.Contracts`, and CAPX-CDS-004 would go quiet on precisely the
    project layout SAP's own guide uses.
    """
    aliases = {}
    for match in _USING_DECL.finditer(text):
        clause = match.group(1)
        inner = clause[1:-1] if clause.startswith("{") else clause
        for part in inner.split(","):
            named = _USING_ALIAS.search(part.strip())
            if not named:
                continue
            full = named.group(1)
            aliases[named.group(2) or full.rsplit(".", 1)[-1]] = full
    return aliases


def _qualify(name: str, namespace: str, aliases: Dict[str, str]) -> str:
    """Expand a written reference to the name the model keys entities by."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    if head in aliases:
        return "%s.%s" % (aliases[head], rest) if rest else aliases[head]
    if "." not in name and namespace:
        return "%s.%s" % (namespace, name)
    return name


def declared_roles(annotations: str) -> Set[str]:
    """The application roles an annotation text demands.

    Pseudo-roles are stripped. `any` is not a role — it is the absence of one.
    `authenticated-user` is held by every caller that got as far as the service,
    so demanding it downstream adds nothing the caller has not already proved.
    Leaving either in would make CAPX-CDS-004 report a navigation as a privilege
    gap when no privilege was involved.
    """
    roles = set()
    for match in re.finditer(r"\brequires\s*:", annotations or ""):
        roles |= set(_literal_values(annotations, match.end()))
    for match in re.finditer(r"\brestrict\s*:", annotations or ""):
        i = match.end()
        while i < len(annotations) and annotations[i] in " \t\r\n":
            i += 1
        end = (_balanced(annotations, i, "[", "]")
               if i < len(annotations) and annotations[i] == "[" else -1)
        if end < 0:
            continue
        for privilege in _privileges(annotations[i:end]):
            roles |= set(_privilege_roles(privilege))
    return {r for r in roles if r not in _PSEUDO_ROLES}


def effective_roles(model: CdsModel, name: str) -> Set[str]:
    """The roles guarding one entity, own first and inherited otherwise.

    SAP: "Service entities inherit the restriction from the database entity, on
    which they define a projection. An explicit restriction defined on a service
    entity REPLACES inherited restrictions from the underlying entity." Replaces,
    not adds — so the chain stops at the first link that says anything, and a
    projection that restates its restriction is not credited with the database
    entity's as well.
    """
    seen, current = set(), name
    while current and current not in seen:
        seen.add(current)
        roles = declared_roles(model.entity_annotations(current))
        if roles:
            return roles
        current = (model.entities.get(current) or {}).get("source")
    return set()


def _resolve_entity(model: CdsModel, written: str) -> Optional[str]:
    """The model key for a written entity reference, or None.

    None covers three different situations — the target is in a package this
    scan never read, the name is ambiguous across namespaces, or it was never
    declared — and all three mean the same thing here: no claim can be made
    about that entity's restrictions. The caller records it as unresolved.
    """
    if not written:
        return None
    if written in model.entities:
        return written
    candidates = model.by_short_name.get(written.rsplit(".", 1)[-1], set())
    return next(iter(candidates)) if len(candidates) == 1 else None


def _elements_with_owner(model: CdsModel,
                         name: str) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """An entity's elements and the entity they are actually declared on.

    `entity Books as projection on db.Books;` declares no elements of its own
    and exposes every element of `db.Books` — including its associations. An
    analysis that read only the projection's own body would conclude that CAP
    services expose nothing navigable at all.

    The owner comes back with them because the elements' file and line belong to
    it, not to the projection. Quoting a line number from schema.cds against the
    name of catalog-service.cds sends a reader to the wrong file, and a wrong
    location is worse than none — they trust it and lose the trail.
    """
    seen, current = set(), name
    while current and current not in seen:
        seen.add(current)
        info = model.entities.get(current)
        if not info:
            return None, []
        if info["elements"]:
            return current, info["elements"]
        current = info.get("source")
    return None, []


def _elements_of(model: CdsModel, name: str) -> List[Dict[str, Any]]:
    return _elements_with_owner(model, name)[1]


def _excluded_along(model: CdsModel, name: str) -> Set[str]:
    """Element names removed by `excluding` anywhere down the projection chain."""
    out, seen, current = set(), set(), name
    while current and current not in seen:
        seen.add(current)
        info = model.entities.get(current)
        if not info:
            break
        out |= info.get("excluding") or set()
        current = info.get("source")
    return out


def _redirect(model: CdsModel, service: str, target: str) -> Optional[str]:
    """The service entity a navigation lands on, honouring auto-redirection.

    SAP: "When exposing related entities, associations are automatically
    redirected. This ensures that clients can navigate between projected
    entities as expected" — `AdminService.Authors.books` refers to
    `AdminService.Books`, not to `my.Books`.

    Skipping this is not a detail, it is the difference between a useful check
    and a harmful one. CAP's documented remedy for the very defect this module
    reports is to expose a reduced projection — `entity Employees as projection
    on db.Employees excluding { contract }` — and it works ONLY because
    navigation redirects to that projection. A walk that ignored redirection
    would follow the unreduced database entity, still find the restricted child,
    and report a project that had applied SAP's own fix correctly. Telling a
    developer their correct fix did not work is worse than saying nothing.

    Ambiguity returns None. Two projections on the same entity in one service is
    a compile error unless `@cds.redirection.target` picks one — "Auto-redirection
    fails if a target can't be resolved unambiguously" — so there is no real
    model behind that case to report on.
    """
    candidates = []
    for name, info in model.entities.items():
        if info.get("service") != service:
            continue
        chain, seen, current = [], set(), name
        while current and current not in seen:
            seen.add(current)
            chain.append(current)
            current = (model.entities.get(current) or {}).get("source")
        if target in chain[1:]:
            annotations = model.entity_annotations(name)
            if re.search(r"@cds\.redirection\.target\s*:\s*false", annotations,
                         re.IGNORECASE):
                continue
            preferred = bool(re.search(
                r"@cds\.redirection\.target(?!\s*:\s*false)", annotations,
                re.IGNORECASE))
            candidates.append((0 if preferred else 1, name))
    if not candidates:
        return None
    candidates.sort()
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        model.unresolved.append(
            "navigation to %s inside service %s has %d equally-ranked "
            "redirection targets, so the hop was not followed"
            % (target, service, len(candidates)))
        return None
    return candidates[0][1]


def navigation_reach(model: CdsModel, root: str) -> List[Dict[str, Any]]:
    """Every entity reachable from a service entity by association or composition.

    This is the `$expand` surface: what an OData client can ask for in one
    request having satisfied the authorization on `root` alone. SAP's own
    example is two hops — `/Teams?$expand=members($expand=contract)` — and the
    walk follows the same edges the runtime would, redirection included.

    Where a hop redirects to a projection inside the same service, the walk
    continues from the projection, so an `excluding` on it removes everything
    downstream of what it excluded. Where nothing in the service projects the
    target, the walk continues on the database entity, because that is what CAP
    auto-exposes and what the client reaches.

    Cycle-safe on the node, so `Teams -> members -> team` terminates.
    Depth-bounded, and anything cut at the bound is recorded on the model so the
    coverage manifest can say the reach was reported short rather than complete.
    """
    service = (model.entities.get(root) or {}).get("service")
    out, seen = [], {root}
    queue = [(root, [])]
    while queue:
        current, path = queue.pop(0)
        if len(path) >= _MAX_NAV_DEPTH:
            _note(model.truncated_paths,
                  "%s -> %s (stopped at depth %d)"
                  % (root, " -> ".join(step["via"] for step in path),
                     _MAX_NAV_DEPTH))
            continue
        excluded = _excluded_along(model, current)
        for element in _elements_of(model, current):
            if not element.get("kind") or element["name"] in excluded:
                continue
            target = _resolve_entity(model, element["target"])
            if target is None:
                _note(model.unresolved,
                      "navigation %s.%s -> %s could not be resolved to a "
                      "declared entity, so its restrictions were not examined"
                      % (current, element["name"], element.get("target_written")))
                continue
            landed = _redirect(model, service, target) or target
            step = {"via": element["name"], "kind": element["kind"],
                    "written": element.get("target_written"),
                    "resolved": landed, "redirected": landed != target,
                    "from": current}
            out.append({"entity": landed, "path": path + [step]})
            if landed not in seen:
                seen.add(landed)
                queue.append((landed, path + [step]))
    return out


def _note(bucket: List[str], message: str) -> None:
    """Record a note once. `navigation_reach` runs per exposed entity and the
    same unreadable target is reached from several of them; a coverage manifest
    that listed it eight times would read as eight gaps."""
    if message not in bucket:
        bucket.append(message)


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


def detect_runtime(root: Path) -> str:
    """`"java"`, `"node"`, `"both"` or `"unknown"` for a CAP project.

    This is not trivia. CAP's two runtimes enforce different amounts of the
    model, and the difference falls exactly across the finding below:

      * CAP Node — "Currently, the security annotations are only evaluated on
        the target entity of the request. Restrictions on associated entities
        touched by the operation are not regarded." Associations AND
        compositions are unchecked.
      * CAP Java 4.0+ — deep authorization is on by default and DOES check
        associated entities, but compositions are still exempt: "Restrictions on
        associated composition entities touched by the request are not regarded
        by the runtime", under a warning box that adds "If you model dedicated
        restriction rules on child entity level, you need to add custom
        authorization handlers accordingly."

    So a composition finding holds whatever the runtime is, and an association
    finding holds for Node and for Java below 4.0. Reporting both at the same
    confidence on a Java project would be wrong; staying silent on both because
    the runtime is unknown would be worse. The finding states which it found.
    """
    java = any((root / name).is_file() for name in ("pom.xml", "srv/pom.xml"))
    node = False
    package = root / "package.json"
    if package.is_file():
        try:
            raw = json.loads(package.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            raw = {}
        for section in ("dependencies", "devDependencies"):
            if any(str(k).startswith("@sap/cds")
                   for k in (raw.get(section) or {})):
                node = True
    if java and node:
        return "both"
    if java:
        return "java"
    if node:
        return "node"
    return "unknown"


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
        self.check_expand_reach(model, detect_runtime(path))
        self.check_property_exposure(model)
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

    # ── CAPX-CDS-004: $expand reaches past the authorization check ──────────

    def check_expand_reach(self, model: CdsModel, runtime: str):
        """Restricted entities reachable by navigation from a less-restricted one.

        This is the defect CAP documents against itself, and the reason it is
        worth a check of its own is that the model LOOKS correct: the sensitive
        entity carries a restriction, the developer wrote it deliberately, and
        the runtime does not apply it.

        SAP: "Currently, the security annotations are only evaluated on the
        target entity of the request. Restrictions on associated entities
        touched by the operation are not regarded... Restrictions of
        (recursively) expanded or inlined entities of a READ request aren't
        checked." Their own worked example ends: "only the target entity
        BrowseEmployeesService.Teams has to pass the authorization check in the
        generic handler, and not the associated entities."

        The comparison is deliberately timid. A navigation is reported only when
        the target demands at least one application role and the path root
        demands NONE of them — disjoint sets, not "weaker" ones. Roles are not
        ordered and pretending otherwise would manufacture findings out of
        naming; where the two overlap at all, the caller may well hold what the
        target asks for and this check says nothing.
        """
        service_entities = [name for name, info in sorted(model.entities.items())
                            if info.get("service")]
        if not service_entities:
            return

        items, objects, kinds = [], [], set()
        for name in service_entities:
            info = model.entities[name]
            service = info["service"]
            root_roles = (effective_roles(model, name)
                          or declared_roles(model.annotations_for(service)))

            for reached in navigation_reach(model, name):
                target_roles = effective_roles(model, reached["entity"])
                if not target_roles or (target_roles & root_roles):
                    continue
                steps = reached["path"]
                kinds |= {step["kind"] for step in steps}
                items.append(
                    "%s (requires %s) -> %s -> %s (requires %s) [%s]"
                    % (name, ", ".join(sorted(root_roles)) or "no role",
                       "?$expand=" + "($expand=".join(s["via"] for s in steps)
                       + ")" * (len(steps) - 1),
                       reached["entity"], ", ".join(sorted(target_roles)),
                       "/".join(sorted({s["kind"] for s in steps}))))
                self._add(objects, "cap_service_entity", name,
                          "reaches %s" % reached["entity"])

        if not items:
            return

        composition = "composition" in kinds
        association = "association" in kinds
        runtime_note = {
            "java": ("This project builds on CAP Java (a pom.xml is present). "
                     "Since CAP Java 4.0 deep authorization is on by default and "
                     "DOES check associated entities, so association hops here "
                     "are enforced unless "
                     "`cds.security.authorization.deep.enabled` was set to "
                     "false. Composition hops are not enforced on any version: "
                     "SAP's warning is explicit — \"Restrictions on compositions "
                     "are not checked by the runtime. If you model dedicated "
                     "restriction rules on child entity level, you need to add "
                     "custom authorization handlers accordingly.\""),
            "node": ("This project builds on CAP Node (package.json depends on "
                     "@sap/cds). Neither association nor composition hops are "
                     "checked: the Limitations section applies in full."),
            "both": ("Both a pom.xml and an @sap/cds dependency were found, so "
                     "which runtime serves these entities could not be settled "
                     "from the sources. Composition hops are unenforced either "
                     "way; association hops are unenforced on Node and on Java "
                     "below 4.0."),
            "unknown": ("Neither a pom.xml nor an @sap/cds dependency was found, "
                        "so the runtime could not be determined from the "
                        "sources. Composition hops are unenforced on both "
                        "runtimes; association hops are unenforced on Node and "
                        "on Java below 4.0."),
        }[runtime]

        self.finding(
            check_id="CAPX-CDS-004",
            title="Restricted entity reachable by $expand from a service that does "
                  "not require its role",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d navigation path(s) reach an entity carrying its own "
                "`@requires`/`@restrict` from a service entity whose caller was "
                "never required to hold any of those roles. CAP evaluates "
                "authorization on the request target only: \"Currently, the "
                "security annotations are only evaluated on the target entity "
                "of the request. Restrictions on associated entities touched by "
                "the operation are not regarded\", with the consequence stated "
                "outright — \"Restrictions of (recursively) expanded or inlined "
                "entities of a READ request aren't checked.\" So a single "
                "`$expand` returns the restricted entity's rows to a caller who "
                "proved only the root's authorization. SAP's own worked example "
                "of this is a payroll one, and it closes: \"only the target "
                "entity BrowseEmployeesService.Teams has to pass the "
                "authorization check in the generic handler, and not the "
                "associated entities.\" %s The paths are listed with the "
                "`$expand` that walks them. Each was reported only because the "
                "role sets are disjoint — the target asks for a role the root "
                "never made the caller prove."
                % (len(items), runtime_note)),
            affected_items=items,
            remediation=(
                "1. Take CAP's own remedy first: remove the navigation from the "
                "projection that should not carry it — `entity X as projection "
                "on db.X excluding { contract }` — so the association is not "
                "reachable from that service at all. SAP: \"Now, an Employee "
                "user cannot expand the contracts as the composition is not "
                "reachable anymore from the service.\"\n"
                "2. Where the navigation must stay, add a custom authorization "
                "handler on the child entity. The generic handler will not run "
                "for it, so the restriction on the child is documentation until "
                "code enforces it.\n"
                "3. Split the service rather than the entity where two audiences "
                "need different reach: one service exposing the full graph to "
                "the privileged role, one exposing the reduced projection.\n"
                "4. On CAP Java, confirm "
                "`cds.security.authorization.deep.enabled` has not been set to "
                "false, and note it still does not cover compositions.\n"
                "5. Test the actual request, not the model: call the root with a "
                "token holding only the root's role, add the `$expand` shown "
                "above, and confirm the response is rejected rather than "
                "filled.\n"
                "6. Re-run the scan."),
            references=[
                "SAP CAP — Authorization: Limitations (annotations evaluated on "
                "the target entity only)",
                "SAP CAP — Authorization: Deep Authorizations, Compositions",
                "SAP CAP — Authorization: Control Exposure of Associations and "
                "Compositions",
            ],
            affected_objects=objects,
            details={"paths": len(items), "runtime": runtime,
                     "composition_hops": composition,
                     "association_hops": association,
                     "cwe": "CWE-863", "parser": "lexical"},
            scope="aggregate",
        )

    # ── CAPX-CDS-005: no property-level authorization exists to reach for ───

    def check_property_exposure(self, model: CdsModel):
        """Model-marked personal data exposed by a projection that takes it all.

        CAP has no property-level authorization to offer here, and that is the
        finding rather than a caveat on it. The guide supports `@readonly` on a
        property "for the sake of input validation" and nothing else — no
        `@requires`, no `@restrict` at element level. So the only control over
        who sees a column is which projection carries it, and a projection
        written `as projection on db.X` carries every column including the ones
        the model itself marks as personal or sensitive.

        Only the model's own `@PersonalData.*` annotations count. Inferring
        sensitivity from element names would be a guess, and a guess in a report
        is worse than a gap in one.
        """
        items, objects = [], []
        for name in sorted(model.entities):
            info = model.entities[name]
            if not info.get("service"):
                continue
            excluded = _excluded_along(model, name)
            owner, elements = _elements_with_owner(model, name)
            owner_file = (model.entities.get(owner) or info)["file"]
            for element in elements:
                marked = [a for a in _SENSITIVE_ELEMENT_ANNOTATIONS
                          if a.lower() in (element.get("annotations") or "").lower()]
                if not marked or element["name"] in excluded:
                    continue
                items.append(
                    "%s.%s — %s, declared on %s (%s:%d) and carried into the "
                    "service by `as projection on %s` with no `excluding`"
                    % (name, element["name"], ", ".join(marked),
                       owner or name, owner_file,
                       element.get("line", info["line"]),
                       info.get("source_written") or info.get("source") or name))
                self._add(objects, "cap_service_entity", name,
                          "element %s" % element["name"])

        if not items:
            return
        self.finding(
            check_id="CAPX-CDS-005",
            title="Personal or sensitive element exposed by a projection that "
                  "excludes nothing",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d element(s) that the model itself annotates as personal or "
                "sensitive are exposed by a service projection that removes "
                "nothing. This matters because CAP has no property-level "
                "authorization to fall back on: the guide offers `@readonly` on "
                "a property \"for the sake of input validation\" and supports "
                "neither `@requires` nor `@restrict` at element level. Whoever "
                "may read the entity reads every column of it, so the projection "
                "IS the access control for these fields. The annotations quoted "
                "here are the project's own — this check does not infer "
                "sensitivity from element names, because a name is not evidence."
                % len(items)),
            affected_items=items,
            remediation=(
                "1. Decide, per element, whether every caller who may read this "
                "entity should read this column. Where the answer is no, the "
                "annotation cannot express that and the projection must: "
                "`as projection on db.X excluding { salary }`.\n"
                "2. Where two audiences need different columns, expose two "
                "service entities over the same database entity rather than one "
                "with a comment.\n"
                "3. Keep `@PersonalData` annotations current — they drive the "
                "audit-log and data-privacy behaviour as well as this check, and "
                "an unmarked personal column is invisible to all three.\n"
                "4. Confirm the exposed set against the OData $metadata document "
                "the service actually publishes, which is what a client reads.\n"
                "5. Re-run the scan."),
            references=[
                "SAP CAP — Authorization: restrictions are not supported at "
                "element level (@readonly only)",
                "SAP CAP — Data Privacy: @PersonalData annotations",
            ],
            affected_objects=objects,
            details={"elements": len(items), "basis": "model_annotation",
                     "cwe": "CWE-359", "parser": "lexical"},
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
        # A navigation walk cut at the depth bound reported a SHORTER reach than
        # the model has, so CAPX-CDS-004's silence about anything past that point
        # is ignorance and not a clean result. Saying so is the whole contract of
        # this manifest.
        gaps.extend("navigation walk truncated: %s" % path
                    for path in model.truncated_paths)

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
