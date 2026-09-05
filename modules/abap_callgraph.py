"""Who calls this procedure, and what do they pass it?

WHAT THIS IS FOR
----------------
`RiseTaintAnalyzer` seeds every inbound parameter of every FORM, METHOD and
FUNCTION as tainted. That is a defensible posture for a scanner and it has one
consequence nobody wanted: the confidence grade stops discriminating. Measured
across every ABAP fixture in this repository, **11 of 11 sink-carrying findings
came back `confirmed` and none came back `tentative`** — so a label that reads
"tainted input reaches this sink" was being printed against a subroutine whose
only caller passes a string literal.

A grade that is always the same value is decoration. This module is what lets it
carry information again, by answering the question the seeding assumes away:
*does anything actually pass this parameter something the caller controls?*

ONE ARTEFACT OR THE WHOLE TREE
------------------------------
`CallGraph(statements)` reads one file; `add_artefact` folds in more and
`tree_wide=True` says every file has been added. The distinction is not
bookkeeping — it changes what may be concluded.

One artefact answers nothing about class-based code. Measured on
`sample_data/abap_src`, every method parameter came back `NO_CALLER`, because a
class's callers live in other files by construction, and class-based ABAP is most
modern ABAP. It also changes what "nothing calls this" means: in one file that is
unremarkable, and over the customer's whole custom-code base it means nothing
they wrote reaches it.

THE THREE ANSWERS, AND WHY THE THIRD IS NOT A CLEAN BILL
--------------------------------------------------------
``CALLER_TAINTED``   a visible call passes an actual that is not a literal.
``LITERAL_ONLY``     every visible call passes a literal or a constant.
``NO_CALLER``        nothing visible calls it, or a call that might reach it
                     could not be resolved to it.

Only `LITERAL_ONLY` is evidence of anything safe, and only where ABAP itself
guarantees the visible callers are ALL the callers. That is `_clearable`, and it
is the language's rule rather than a heuristic:

    FORM        file-local in every codebase anyone writes
    PRIVATE     only from inside its class — one artefact holds every caller
    PROTECTED   its class and its subclasses, which need the whole tree
    PUBLIC      anything that imports the class, including code never exported
    FUNCTION    another system entirely, if it carries the RFC flag

`by_public_literal` and `priv_literal` in `tests/fixtures/abap_tree` are the pair
that makes this a rule: identical evidence, and only one of them may be
downgraded.

RESOLUTION IS BY CLASS, NOT BY NAME
-----------------------------------
`run`, `execute` and `get_data` are each defined dozens of times in a real
custom-code base. Resolving a call by bare name across a tree would make almost
every method ambiguous, and the tree graph would answer LESS than the
per-artefact one it replaced. Receivers are typed from `TYPE REF TO`, `NEW`,
`me->` and `zcl_x=>`; local types are per artefact and never carried between
files, because `lo_worker` in two files is two variables.

A receiver that cannot be typed leaves the call UNQUALIFIED. Such a call is
offered to every procedure of that short name, where it may add taint and may
never clear anything — it might reach any of them, which is a reason to be
careful about all of them and no reason to declare one safe.

A NON-LITERAL ACTUAL COUNTS AS TAINTED, WITHOUT ASKING WHETHER IT REALLY IS
---------------------------------------------------------------------------
`PERFORM inner USING iv_pass` inside another subroutine passes a variable. To
know whether `iv_pass` is tainted *at that line* is another taint question, and
answering it properly means a fixpoint over the call graph. This module does not
do that. It treats any non-literal actual as tainted, which:

  * cannot lose a finding — the only thing that clears a parameter is a literal,
    which is decidable by looking at it; and
  * keeps the chain working for the ordinary two-hop shape, where a caller passes
    its own parameter straight through to a helper.

The cost is that a parameter fed only from a hard-coded internal table still
reads as tainted. That is the direction to be wrong in.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple


class Evidence(NamedTuple):
    """What the callers say, and enough to point a reader at the call.

    A tuple rather than a bare `(verdict, line)` because a whole-tree graph puts
    the deciding call in ANOTHER FILE: a trace step carrying only "line 20" makes
    the reader look at line 20 of the file they are already in, which is a
    different statement about something else entirely."""
    verdict: str
    line: Optional[int] = None
    file: str = ""
    #: The argument the caller passed, which is the variable that is actually on
    #: that line. The callee's parameter name is not.
    actual: str = ""
    #: The calling statement, so the trace can show it without opening the file.
    code: str = ""

#: A visible call passes something the caller may control.
CALLER_TAINTED = "caller_tainted"
#: Every visible call passes a literal or a constant.
LITERAL_ONLY = "literal_only"
#: Nothing in this artefact calls it.
NO_CALLER = "no_caller"

#: Procedure kinds. A FORM's visible callers are authoritative; the other two are
#: reachable from outside the artefact and callers can only add evidence.
FORM = "form"
METHOD = "method"
FUNCTION = "function"

#: Class member visibility, which is what actually decides whether the callers we
#: can see are all the callers there are. This is ABAP's own rule and not a
#: heuristic: PRIVATE members are callable only from inside the class, so one
#: artefact holds every caller; PROTECTED adds subclasses, which a whole-tree
#: graph can see and a single-artefact one cannot; PUBLIC is callable by anything
#: that imports the class, including code that was never in the export.
PUBLIC = "public"
PROTECTED = "protected"
PRIVATE = "private"

_IDENT = r"[A-Za-z_][\w/]*"

_FORM_DEF = re.compile(r"^\s*FORM\s+(?P<name>%s)(?P<rest>.*)$" % _IDENT, re.IGNORECASE)
_METHOD_DEF = re.compile(r"^\s*METHOD\s+(?P<name>[\w/~]+)\s*$", re.IGNORECASE)
_FUNCTION_DEF = re.compile(r"^\s*FUNCTION\s+(?P<name>%s)\s*\.?\s*$" % _IDENT,
                           re.IGNORECASE)
#: The signature of a METHOD lives on its METHODS declaration, not on the
#: implementation header — the same lookup `_inbound_params` already does.
_METHODS_DECL = re.compile(
    r"^\s*(?:CLASS-)?METHODS\s*:?\s*(?P<name>[\w/~]+)(?P<rest>.*)$", re.IGNORECASE)

#: Inbound sections only. EXPORTING and RETURNING flow the other way, and binding
#: an outbound actual to an inbound formal would invent a data flow.
_IN_SECTION = re.compile(
    r"\b(?P<kw>IMPORTING|USING|CHANGING|TABLES)\b(?P<params>.*?)"
    r"(?=\bIMPORTING\b|\bEXPORTING\b|\bCHANGING\b|\bRETURNING\b|\bRAISING\b"
    r"|\bTABLES\b|\bUSING\b|$)", re.IGNORECASE)
#: `VALUE(iv_x)`, and the bare-token form. NOT a single alternation with a
#: `\b(IDENT)\b` fallback: that fallback also matched the TYPE, so
#: `FORM x USING p1 TYPE string p2 TYPE string` yielded
#: `[p1, string, p2, string]` and every positional bind after the first landed
#: on the wrong argument. The types have to be CONSUMED, which a walk does and
#: an alternation cannot.
_VALUE_FORMAL = re.compile(r"^VALUE\s*\(\s*(%s)\s*\)$" % _IDENT, re.IGNORECASE)
#: Introduces a type, so what follows is not a parameter.
_TYPE_INTRO = frozenset({"type", "like", "structure"})
#: Words that BUILD a type and are followed by more of it. Everything after these
#: that is an identifier is the type NAME, and exactly one of it is consumed.
#:
#: Guessing by keyword list alone does not work here: a list of "filler" words
#: leaves `TYPE REF TO cl_thing` yielding `cl_thing` as a parameter (it is not a
#: keyword) while `TYPE string` would swallow the NEXT parameter (it is). The
#: name has to be consumed positionally, which is what the state machine below
#: does.
_TYPE_CONSTRUCTOR = frozenset({"ref", "to", "standard", "sorted", "hashed",
                               "table", "of", "line", "range", "with", "unique",
                               "non-unique", "key", "empty", "initial", "size"})
#: Trailing clauses on a parameter, after its type.
_TAKES_ONE_VALUE = frozenset({"default"})
_TRAILING = frozenset({"optional", "preferred", "parameter", "resumable",
                       "read-only"})

_CLASS_BLOCK = re.compile(
    r"^\s*CLASS\s+(?P<name>%s)\s+(?P<what>DEFINITION|IMPLEMENTATION)\b" % _IDENT,
    re.IGNORECASE)
_ENDCLASS = re.compile(r"^\s*ENDCLASS\b", re.IGNORECASE)
_SECTION = re.compile(r"^\s*(?P<vis>PUBLIC|PROTECTED|PRIVATE)\s+SECTION\s*$",
                      re.IGNORECASE)

#: How a local variable acquires a class, so `lo_x->run( )` can be resolved to
#: one method rather than to every method named `run` in the estate. Without
#: this, a tree-wide graph is WORSE than a per-artefact one: `run`, `execute` and
#: `get_data` are defined dozens of times across a real custom-code base, and
#: resolving by bare name would make almost every method ambiguous and therefore
#: unanswerable.
_TYPE_REF = re.compile(
    r"^\s*(?:DATA|CLASS-DATA|STATICS)\s*:?\s*(?P<var>%s)\s+TYPE\s+REF\s+TO\s+"
    r"(?P<cls>%s)" % (_IDENT, _IDENT), re.IGNORECASE)
_NEW_ASSIGN = re.compile(
    r"^\s*(?:DATA\s*\(\s*)?(?P<var>%s)\s*\)?\s*=\s*NEW\s+(?P<cls>%s)\s*\("
    % (_IDENT, _IDENT), re.IGNORECASE)
_CREATE_OBJECT = re.compile(
    r"^\s*CREATE\s+OBJECT\s+(?P<var>%s)(?:\s+TYPE\s+(?P<cls>%s))?"
    % (_IDENT, _IDENT), re.IGNORECASE)

_PERFORM = re.compile(
    r"^\s*PERFORM\s+(?P<name>%s)(?!\s*\()(?P<rest>.*)$" % _IDENT, re.IGNORECASE)
_CALL_FUNCTION = re.compile(
    r"\bCALL\s+FUNCTION\s+(?P<q>['`])(?P<name>[^'`]+)(?P=q)(?P<rest>.*)$",
    re.IGNORECASE)
_CALL_METHOD = re.compile(
    r"\bCALL\s+METHOD\s+(?:%s\s*(?:->|=>)\s*)?(?P<name>%s)(?P<rest>.*)$"
    % (_IDENT, _IDENT), re.IGNORECASE)
#: `lo_x->run( iv_a = v )` and `zcl_x=>run( iv_a = v )`.
#:
#: THE RECEIVER IS KEPT. It used to be dropped and calls resolved by bare name,
#: which is defensible inside one artefact and wrong across a tree: `run`,
#: `execute` and `get_data` are defined dozens of times in a real custom-code
#: base, so bare-name resolution would make nearly every method ambiguous and the
#: whole-tree graph would answer less than the per-artefact one it replaced.
_METHOD_CALL = re.compile(
    r"(?P<recv>%s)\s*(?P<arrow>->|=>)\s*(?P<name>%s)\s*\((?P<args>[^()]*)\)"
    % (_IDENT, _IDENT))

#: `p = expr` inside a call's argument list.
_BIND = re.compile(r"(?P<formal>%s)\s*=(?!>)\s*(?P<actual>[^=]+?)(?=\s+%s\s*=(?!>)|$)"
                   % (_IDENT, _IDENT))

#: A text literal, a string template with nothing computed in it, or a number.
#: `|a{ x }b|` is NOT a literal — the braces carry an expression.
_LITERAL = re.compile(
    r"^\s*(?:'[^']*'|`[^`]*`|\|[^|{}]*\||[-+]?\d[\d.,]*|ABAP_TRUE|ABAP_FALSE|SPACE)\s*$",
    re.IGNORECASE)

#: Words that are ABAP syntax rather than an argument.
_NOT_A_FORMAL = frozenset({
    "using", "changing", "tables", "importing", "exporting", "returning",
    "raising", "type", "like", "structure", "value", "reference", "optional",
    "default", "ref", "to", "in", "of", "and", "or", "not",
})


def _formals_in(rest: str) -> Dict[str, List[str]]:
    """Inbound formal parameter names, per section keyword, in written order.

    Order is the whole point: `PERFORM x USING a b` binds positionally, so a list
    with a type name wrongly in it puts every later argument on the wrong
    parameter — silently, and in the direction that reads as a real data flow."""
    out: Dict[str, List[str]] = {}
    for section in _IN_SECTION.finditer(rest or ""):
        kw = section.group("kw").upper()
        names: List[str] = []
        in_type = False
        skip_next = False
        for tok in re.split(r"[\s,]+", section.group("params").strip()):
            tok = tok.strip().rstrip(".")
            if not tok:
                continue
            low = tok.lower()
            if skip_next:
                skip_next = False
                continue
            value = _VALUE_FORMAL.match(tok)
            if value:
                in_type = False
                name = value.group(1).lower()
                if name not in names:
                    names.append(name)
                continue
            if low in _TYPE_INTRO:
                in_type = True
                continue
            if in_type:
                if low in _TYPE_CONSTRUCTOR:
                    continue
                # The type NAME. One token, consumed, and type-mode ends — so
                # `TYPE REF TO cl_thing iv_n` reads cl_thing as the type and
                # iv_n as the next parameter, which a keyword list cannot do.
                in_type = False
                continue
            if low in _TAKES_ONE_VALUE:
                skip_next = True
                continue
            if low in _TRAILING or low in _NOT_A_FORMAL:
                continue
            if not re.match(r"^%s$" % _IDENT, tok):
                continue
            if low not in names:
                names.append(low)
        if names:
            out.setdefault(kw, []).extend(names)
    return out


def _actuals_in(rest: str) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """Positional actuals per section, and named `formal = actual` binds.

    Both are returned because ABAP writes calls both ways and a caller cannot
    know which it will meet: `PERFORM x USING a b` is positional, and
    `CALL FUNCTION 'X' EXPORTING p = a` is named."""
    positional: Dict[str, List[str]] = {}
    named: Dict[str, str] = {}
    for section in _IN_SECTION.finditer(rest or ""):
        kw = section.group("kw").upper()
        body = section.group("params")
        binds = list(_BIND.finditer(body))
        if binds:
            for b in binds:
                named[b.group("formal").lower()] = b.group("actual").strip()
            continue
        args = [a for a in re.split(r"\s+", body.strip()) if a]
        vals = [a for a in args if a.lower() not in _NOT_A_FORMAL]
        if vals:
            positional.setdefault(kw, []).extend(vals)
    return positional, named


def is_literal(actual: str) -> bool:
    """Is this actual argument fixed at compile time?

    The ONLY thing that clears a parameter, so it is deliberately narrow: an
    identifier is never a literal here, not even one named `lc_something`, and a
    string template containing `{ }` is an expression whatever the text around it
    says."""
    return bool(_LITERAL.match((actual or "").strip().rstrip(".")))


class CallSite:
    """One call, and what it hands over."""

    __slots__ = ("callee", "line", "positional", "named", "file",
                 "qualified", "code")

    def __init__(self, callee: str, line: int,
                 positional: Dict[str, List[str]], named: Dict[str, str],
                 file: str = "", qualified: bool = True, code: str = ""):
        #: `zcl_x~run` where the receiver's class was resolved, else the bare
        #: name. `qualified` says which, and it decides what the call may prove:
        #: an unresolved receiver can ADD taint to every method of that name, and
        #: can never contribute to clearing one, because we do not know which
        #: method it actually reaches.
        self.callee = callee
        self.line = line
        self.positional = positional
        self.named = named
        self.file = file
        self.qualified = qualified
        #: The calling statement as written, so a cross-file trace step can show
        #: it without the reader opening the other artefact.
        self.code = code


class CallGraph:
    """Procedures and their call sites within one artefact."""

    def __init__(self, statements: Optional[Sequence[object]] = None,
                 path: str = "", tree_wide: bool = False):
        #: key -> (kind, {section: [formal, ...]})
        self.procedures: Dict[str, Tuple[str, Dict[str, List[str]]]] = {}
        self.calls: List[CallSite] = []
        #: A key defined more than once. Resolving it is then a guess, so it is
        #: not resolved at all — see `evidence_for`.
        self.ambiguous: set = set()
        #: key -> PUBLIC / PROTECTED / PRIVATE, for class members only.
        self.visibility: Dict[str, str] = {}
        #: key -> the artefact that defines it, for the cross-file trace step.
        self.defined_in: Dict[str, str] = {}
        #: True when every artefact in the tree has been added. It is what makes
        #: a PROTECTED member answerable (its subclasses are in the tree) and
        #: what makes "nothing calls this" mean more than "nothing here does".
        self.tree_wide = tree_wide
        self._evidence_cache: Dict[Tuple[str, str], Evidence] = {}
        if statements is not None:
            self.add_artefact(statements, path)

    def add_artefact(self, statements: Sequence[object], path: str = "") -> None:
        """Fold one file into the graph.

        Local variable types are per artefact and are NOT kept between calls: a
        variable named `lo_worker` in two files is two variables, and carrying a
        type across would resolve one file's call against another file's
        declaration."""
        self._evidence_cache.clear()
        methods_decl: Dict[str, str] = {}
        var_class: Dict[str, str] = {}
        cls: Optional[str] = None
        section: Optional[str] = None

        for st in statements:
            text = getattr(st, "text", "") or ""
            block = _CLASS_BLOCK.match(text)
            if block:
                cls = block.group("name").lower()
                section = PUBLIC if block.group("what").upper() == "DEFINITION" else None
                continue
            if _ENDCLASS.match(text):
                cls, section = None, None
                continue
            vis = _SECTION.match(text)
            if vis:
                section = vis.group("vis").lower()
                continue
            decl = _METHODS_DECL.match(text)
            if decl:
                name = decl.group("name").lower()
                methods_decl[name] = decl.group("rest")
                if cls and section:
                    self.visibility[self._key(cls, name)] = section
                continue
            # Local type map, so `lo_x->run( )` resolves to one class.
            for pattern in (_TYPE_REF, _NEW_ASSIGN, _CREATE_OBJECT):
                m = pattern.match(text)
                if m and m.groupdict().get("cls"):
                    var_class[m.group("var").lower()] = m.group("cls").lower()
                    break

        self._scan(statements, methods_decl, var_class, path)

    @staticmethod
    def _key(cls: Optional[str], name: str) -> str:
        """`zcl_x~run`, or the bare name where no class is known."""
        name = name.lower()
        return "%s~%s" % (cls.lower(), name) if cls else name

    def _scan(self, statements: Sequence[object], methods_decl: Dict[str, str],
              var_class: Dict[str, str], path: str) -> None:
        cls: Optional[str] = None
        for st in statements:
            text = (getattr(st, "text", "") or "").strip()
            if not text:
                continue
            # STRUCTURE IS READ OFF THE MASKED TEXT, names off the raw.
            #
            # `_BIND` on raw text read a call whose literal argument itself
            # contains an equals sign as a bind of a formal named by a word
            # INSIDE that literal, and lost the real parameter entirely. The mask
            # blanks literal content to `#` and keeps the delimiters and every
            # offset, so the same expressions match in the same places and a
            # string can no longer invent an argument.
            #
            # The one thing the mask cannot give back is the callee of a
            # CALL FUNCTION, whose name IS a literal. That is taken from the raw
            # text at the masked match's own span.
            masked = (getattr(st, "text_masked", None) or text).strip()
            if len(masked) != len(text):
                masked = text
            line = getattr(st, "line", 0)
            block = _CLASS_BLOCK.match(text)
            if block:
                cls = block.group("name").lower()
                continue
            if _ENDCLASS.match(text):
                cls = None
                continue
            self._add_definition(text, methods_decl, cls, path)
            self._add_calls(text, masked, line, cls, var_class, path)

    # ---------------------------------------------------------------- #
    #  Building                                                         #
    # ---------------------------------------------------------------- #

    def _define(self, key: str, kind: str, rest: str, path: str) -> None:
        key = key.lower()
        if key in self.procedures:
            self.ambiguous.add(key)
        self.procedures[key] = (kind, _formals_in(rest))
        self.defined_in.setdefault(key, path)

    def _add_definition(self, text: str, methods_decl: Dict[str, str],
                        cls: Optional[str], path: str) -> None:
        m = _FORM_DEF.match(text)
        if m:
            self._define(m.group("name"), FORM, m.group("rest"), path)
            return
        m = _METHOD_DEF.match(text)
        if m:
            name = m.group("name").lower()
            # `if_x~run` implements an interface method; the declaration is on
            # the interface and is not in this artefact. The bare name is tried
            # too, because an implementing class usually declares it as well.
            rest = methods_decl.get(name) or methods_decl.get(name.split("~")[-1], "")
            self._define(self._key(cls, name), METHOD, rest, path)
            return
        m = _FUNCTION_DEF.match(text)
        if m:
            # A function module's signature is in its (generated) include, not
            # here. Its formals are therefore unknown and callers bind by name.
            self._define(m.group("name"), FUNCTION, "", path)

    def _add_calls(self, text: str, masked: str, line: int,
                   cls: Optional[str], var_class: Dict[str, str],
                   path: str) -> None:
        m = _PERFORM.match(masked)
        if m:
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(
                CallSite(m.group("name").lower(), line, pos, named, path,
                         code=text))
            return
        m = _CALL_FUNCTION.search(masked)
        if m:
            # The name is all `#` in the mask; read it off the raw text at the
            # span the mask matched, which is the same span by construction.
            name = text[m.start("name"):m.end("name")]
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(
                CallSite(name.lower(), line, pos, named, path, code=text))
            return
        m = _CALL_METHOD.search(masked)
        if m:
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(
                CallSite(m.group("name").lower(), line, pos, named, path,
                         qualified=False, code=text))
            return
        for call in _METHOD_CALL.finditer(masked):
            args = call.group("args")
            named = {b.group("formal").lower(): b.group("actual").strip()
                     for b in _BIND.finditer(args)}
            pos: Dict[str, List[str]] = {}
            if not named and args.strip():
                # `lo->run( lv_x )` — a single unnamed argument binds to the one
                # inbound parameter, which is the only case ABAP allows.
                pos["IMPORTING"] = [args.strip()]
            owner = self._receiver_class(call.group("recv"), call.group("arrow"),
                                         cls, var_class)
            name = call.group("name").lower()
            self.calls.append(
                CallSite(self._key(owner, name), line, pos, named, path,
                         qualified=owner is not None, code=text))

    @staticmethod
    def _receiver_class(recv: str, arrow: str, cls: Optional[str],
                        var_class: Dict[str, str]) -> Optional[str]:
        """The class a call goes to, or None when it cannot be told.

        `zcl_x=>m( )` names it outright. `lo->m( )` needs the local declaration,
        and `me->m( )` is the enclosing class. Anything else — a method call on a
        returned reference, a field symbol, an interface variable typed
        elsewhere — is left unresolved rather than guessed, and an unresolved
        call is never allowed to clear a parameter."""
        recv = (recv or "").lower()
        if arrow == "=>":
            return recv                       # zcl_x=>m( ) or if_x=>m( )
        if recv in ("me", "super"):
            return cls
        return var_class.get(recv)

    # ---------------------------------------------------------------- #
    #  Asking                                                           #
    # ---------------------------------------------------------------- #

    def callers_of(self, name: str) -> List[CallSite]:
        """Calls that reach this procedure, resolved plus unresolved.

        An UNRESOLVED call — one whose receiver could not be typed — is returned
        for every procedure of that short name, because it might reach any of
        them. It is marked `qualified=False`, and `evidence_for` uses that to let
        it add taint while refusing to let it clear anything: "some call named
        `run` passes a variable" is a reason to be careful about every `run`, and
        no reason at all to declare one of them safe."""
        key = (name or "").lower()
        short = key.split("~")[-1]
        out = []
        for c in self.calls:
            if c.callee == key:
                out.append(c)
            elif not c.qualified and c.callee.split("~")[-1] == short:
                out.append(c)
        return out

    def evidence_for(self, proc: str, param: str) -> Evidence:
        """What the visible callers say about one inbound parameter.

        Returns `(verdict, line)` where `line` is the call site that decided it,
        or None. An unknown or ambiguously-defined procedure answers `NO_CALLER`,
        which is the answer that changes nothing.

        MEMOISED because the analyzer re-walks a scope for every sink it grades,
        so the same procedure and parameter are asked about repeatedly and the
        answer cannot change — the graph is fixed once the artefact is parsed.
        Measured on a synthetic 4,000-line program with 2,000 findings, which is
        already past the size of real ABAP objects, the graph cost about 28% on
        top of the scan; `docs/CVA_MERGE_PLAN.md` records `--data-flow` scaling
        as a known concern, so the free saving is taken.
        """
        cache_key = ((proc or "").lower(), (param or "").lower())
        hit = self._evidence_cache.get(cache_key)
        if hit is not None:
            return hit
        out = self._evidence_uncached(proc, param)
        self._evidence_cache[cache_key] = out
        return out

    def _evidence_uncached(self, proc: str, param: str) -> Evidence:
        key = (proc or "").lower()
        if key in self.ambiguous or key not in self.procedures:
            return Evidence(NO_CALLER)

        _kind, formals = self.procedures[key]
        param = (param or "").lower()
        sites = self.callers_of(key)
        if not sites:
            return Evidence(NO_CALLER)

        saw_binding = False
        unresolved = False
        for site in sites:
            actual = site.named.get(param)
            if actual is None:
                # Positional: the formal's index within its own section.
                for kw, names in formals.items():
                    if param in names:
                        idx = names.index(param)
                        args = site.positional.get(kw) or []
                        if idx < len(args):
                            actual = args[idx]
                        break
            if actual is None:
                continue
            saw_binding = True
            if not site.qualified:
                # It may or may not reach this procedure. Enough to stop us
                # clearing it, never enough to conclude anything about it.
                unresolved = True
                continue
            if not is_literal(actual):
                return Evidence(CALLER_TAINTED, site.line, site.file,
                                actual.strip(), site.code)
        if unresolved:
            return Evidence(NO_CALLER)
        if not saw_binding:
            # Calls exist but none of them names or positions this parameter —
            # an optional argument left out, or a shape this module cannot read.
            # Not evidence of anything.
            return Evidence(NO_CALLER)
        first = sites[0]
        return Evidence(LITERAL_ONLY, first.line, first.file, code=first.code)

    def _clearable(self, key: str) -> bool:
        """May a parameter of this procedure ever start the walk untainted?

        Decided by who is ALLOWED to call it, which is a fact about ABAP and not
        a guess about this codebase:

          FORM       file-local in every codebase anyone writes.
          PRIVATE    callable only from inside its class, so one artefact holds
                     every caller there is.
          PROTECTED  its class and its subclasses. A subclass can live in another
                     artefact, so this is answerable from a whole-tree graph and
                     not from a single file.
          PUBLIC     anything that imports the class, including code that was
                     never in the export. Never clearable.
          FUNCTION   another system entirely, if it carries the RFC flag.
        """
        kind = self.procedures.get(key, (None, None))[0]
        if kind == FORM:
            return True
        if kind != METHOD:
            return False
        vis = self.visibility.get(key)
        if vis == PRIVATE:
            return True
        if vis == PROTECTED:
            return self.tree_wide
        return False

    def seeds_clean(self, proc: str, param: str) -> Tuple[bool, Evidence]:
        """Should this parameter start the walk UNtainted?

        Only where every visible caller passes a literal AND the procedure's own
        visibility means the visible callers are all the callers."""
        ev = self.evidence_for(proc, param)
        key = (proc or "").lower()
        return (ev.verdict == LITERAL_ONLY and self._clearable(key)), ev
