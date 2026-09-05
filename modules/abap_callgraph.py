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

WHAT IT IS NOT
--------------
It is not a whole-program call graph. It sees ONE artefact, because that is the
unit the scanner is handed and the unit `#NOSEC`, line numbers and every existing
verdict already work in. A caller in another include or another class is
invisible here, and the rules below are written so that invisibility can never
produce a false clean.

THE THREE ANSWERS, AND WHY THE THIRD IS NOT A CLEAN BILL
--------------------------------------------------------
``CALLER_TAINTED``   a visible call passes an actual that is not a literal.
``LITERAL_ONLY``     every visible call passes a literal or a constant.
``NO_CALLER``        no call to this procedure appears in this artefact.

Only `LITERAL_ONLY` is evidence of anything safe, and even then only for a FORM.
A FORM is file-local in every codebase anyone actually writes: `PERFORM` can name
an external program, but the form is deprecated, rare, and would show up in the
calling artefact rather than this one. So for a FORM the visible callers are the
callers.

A METHOD or a FUNCTION is the opposite. A public method is called by whatever
imports the class; a function module with the RFC flag is callable from another
system entirely. "No caller in this file" is the NORMAL state for both, and for a
remote-enabled function module it is precisely the dangerous one. So callers can
only ever ADD evidence for those two — `LITERAL_ONLY` and `NO_CALLER` leave the
conservative seed exactly where it was.

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
from typing import Dict, List, Optional, Sequence, Tuple

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

_PERFORM = re.compile(
    r"^\s*PERFORM\s+(?P<name>%s)(?!\s*\()(?P<rest>.*)$" % _IDENT, re.IGNORECASE)
_CALL_FUNCTION = re.compile(
    r"\bCALL\s+FUNCTION\s+(?P<q>['`])(?P<name>[^'`]+)(?P=q)(?P<rest>.*)$",
    re.IGNORECASE)
_CALL_METHOD = re.compile(
    r"\bCALL\s+METHOD\s+(?:%s\s*(?:->|=>)\s*)?(?P<name>%s)(?P<rest>.*)$"
    % (_IDENT, _IDENT), re.IGNORECASE)
#: `lo_x->run( iv_a = v )` and `zcl_x=>run( iv_a = v )`. The receiver is dropped:
#: this module resolves by NAME, because an artefact that defines `run` once is
#: the overwhelmingly common case and tracking object identity would be a type
#: analysis, not a call graph.
_METHOD_CALL = re.compile(
    r"(?:%s)\s*(?:->|=>)\s*(?P<name>%s)\s*\((?P<args>[^()]*)\)" % (_IDENT, _IDENT))

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

    __slots__ = ("callee", "line", "positional", "named")

    def __init__(self, callee: str, line: int,
                 positional: Dict[str, List[str]], named: Dict[str, str]):
        self.callee = callee
        self.line = line
        self.positional = positional
        self.named = named


class CallGraph:
    """Procedures and their call sites within one artefact."""

    def __init__(self, statements: Sequence[object]):
        #: name -> (kind, {section: [formal, ...]})
        self.procedures: Dict[str, Tuple[str, Dict[str, List[str]]]] = {}
        self.calls: List[CallSite] = []
        #: A name defined more than once. Resolving by name is then a guess, so
        #: it is not resolved at all — see `evidence_for`.
        self.ambiguous: set = set()
        #: (proc, param) -> verdict. Safe because nothing mutates the graph after
        #: construction, and the analyzer asks the same question many times.
        self._evidence_cache: Dict[Tuple[str, str], Tuple[str, Optional[int]]] = {}

        methods_decl: Dict[str, str] = {}
        for st in statements:
            text = getattr(st, "text", "") or ""
            decl = _METHODS_DECL.match(text)
            if decl:
                methods_decl[decl.group("name").lower()] = decl.group("rest")

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
            self._add_definition(text, methods_decl)
            self._add_calls(text, masked, line)

    # ---------------------------------------------------------------- #
    #  Building                                                         #
    # ---------------------------------------------------------------- #

    def _define(self, name: str, kind: str, rest: str) -> None:
        key = name.lower()
        if key in self.procedures:
            self.ambiguous.add(key)
        self.procedures[key] = (kind, _formals_in(rest))

    def _add_definition(self, text: str, methods_decl: Dict[str, str]) -> None:
        m = _FORM_DEF.match(text)
        if m:
            self._define(m.group("name"), FORM, m.group("rest"))
            return
        m = _METHOD_DEF.match(text)
        if m:
            name = m.group("name").lower()
            # `if_x~run` implements an interface method; the declaration is on
            # the interface and is not in this artefact. The bare name is tried
            # too, because an implementing class usually declares it as well.
            rest = methods_decl.get(name) or methods_decl.get(name.split("~")[-1], "")
            self._define(name, METHOD, rest)
            return
        m = _FUNCTION_DEF.match(text)
        if m:
            # A function module's signature is in its (generated) include, not
            # here. Its formals are therefore unknown and callers bind by name.
            self._define(m.group("name"), FUNCTION, "")

    def _add_calls(self, text: str, masked: str, line: int) -> None:
        m = _PERFORM.match(masked)
        if m:
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(CallSite(m.group("name").lower(), line, pos, named))
            return
        m = _CALL_FUNCTION.search(masked)
        if m:
            # The name is all `#` in the mask; read it off the raw text at the
            # span the mask matched, which is the same span by construction.
            name = text[m.start("name"):m.end("name")]
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(CallSite(name.lower(), line, pos, named))
            return
        m = _CALL_METHOD.search(masked)
        if m:
            pos, named = _actuals_in(m.group("rest"))
            self.calls.append(CallSite(m.group("name").lower(), line, pos, named))
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
            self.calls.append(CallSite(call.group("name").lower(), line, pos, named))

    # ---------------------------------------------------------------- #
    #  Asking                                                           #
    # ---------------------------------------------------------------- #

    def callers_of(self, name: str) -> List[CallSite]:
        key = (name or "").lower()
        short = key.split("~")[-1]
        return [c for c in self.calls if c.callee in (key, short)]

    def evidence_for(self, proc: str, param: str) -> Tuple[str, Optional[int]]:
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

    def _evidence_uncached(self, proc: str, param: str) -> Tuple[str, Optional[int]]:
        key = (proc or "").lower()
        if key in self.ambiguous or key not in self.procedures:
            return NO_CALLER, None

        _kind, formals = self.procedures[key]
        param = (param or "").lower()
        sites = self.callers_of(key)
        if not sites:
            return NO_CALLER, None

        saw_binding = False
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
            if not is_literal(actual):
                return CALLER_TAINTED, site.line
        if not saw_binding:
            # Calls exist but none of them names or positions this parameter —
            # an optional argument left out, or a shape this module cannot read.
            # Not evidence of anything.
            return NO_CALLER, None
        return LITERAL_ONLY, sites[0].line

    def seeds_clean(self, proc: str, param: str) -> Tuple[bool, str, Optional[int]]:
        """Should this parameter start the walk UNtainted?

        Only ever true for a FORM whose visible callers all pass literals. A
        METHOD or a FUNCTION keeps the conservative seed however clean its
        visible callers look, because the ones that matter are usually not in
        this artefact at all."""
        verdict, line = self.evidence_for(proc, param)
        kind = self.procedures.get((proc or "").lower(), (None, None))[0]
        return (verdict == LITERAL_ONLY and kind == FORM), verdict, line
