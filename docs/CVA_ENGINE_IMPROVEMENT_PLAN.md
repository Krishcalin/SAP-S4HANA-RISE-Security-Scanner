# CVA Engine Improvement Plan

Source: 7 parallel research agents mining SAP-authored, Apache-2.0 ABAP reference
material (`SAP-samples/abap-cheat-sheets`), followed by an adversarial verification
pass that re-ran the live scanner against every load-bearing claim.

WHY NOT THE HELP PORTAL. The URL originally supplied
(help.sap.com/doc/abapdocu_758_index_htm) is not machine-readable: the
`index.htm?file=` form returns a ~4 KB Vue SPA shell, and the direct `.html` form
returns an OAuth redirect to an SAP login. No agent read it. Every identifier that
lands in code from this plan must be grep-confirmable in a named, fetched,
SAP-authored file — see section 7 for what remains unverified.

Proposals: 72 across 7 angles. Verified: 9 survived, 6 rejected on measurement.
Claims marked **[re-run]** were reproduced against the shipped scanner.

---

## STATUS — TIER 1 SHIPPED

| Item | State | Where |
|---|---|---|
| T1.1 one mode-stack scanner incl. `{ }` | shipped | `_scan_line` in `modules/abap_sast.py` |
| T1.2 runaway flush + degraded counter | shipped | `_RUNAWAY_LINES`, `AbapSourceScanner.lex_degraded`, finding `ABAP-LEX-001` |
| T1.3 `text_masked` + `LITERAL_BLIND` | shipped | `Statement.text_masked`, `LITERAL_BLIND` |
| T1.4 rule-aware `_sink_argument` | shipped | `_SINK_ARG_BY_ID` |
| T1.5 anchored guard + `_subrc_evaluated` | shipped | `_guarded_blocks`; `ABAP-AUTH-008` added to `AUTHORITY_GUARDED` |
| T1.6 `ABAP-AUTH-003` moved into the engine | shipped | `RULE_HANDLED_IN_ENGINE` |
| T1.7 sanitizer inventory | shipped | `SINK_SANITIZERS` / `XSS_SANITIZERS` in `abap_sast_extra.py` |
| T1.8 sink-specific sanitizer mapping | shipped | `_analyzer_for` |
| T1.9 source before sanitizer, guard must wrap | shipped | `RiseTaintAnalyzer._classify` / `._combine` |
| T1.10 analyzer fed statements, not raw text | shipped | `_taint_source`, `RiseTaintAnalyzer` |
| **T1.11 positive safe/unsafe idioms** | **NOT SHIPPED** | see below |
| T1.12 AMDP / SQLScript lexing mode | shipped | `_M_AMDP*` modes in `_scan_line` |

Regression fixtures: `tests/test_abap_tier1.py`. One existing assertion in
`tests/test_abap_sast.py` was changed rather than preserved — the guarded fixture in
`test_an_authority_check_in_the_same_block_silences_the_guarded_rules` never read
`sy-subrc`, so it encoded the fail-open behaviour T1.5 removes. It now evaluates the
result, and `test_an_authority_check_whose_result_is_discarded_is_not_a_guard` covers
the case it used to assert backwards.

## STATUS — TIER 2 SHIPPED

All eleven, every one as a side-table entry so `tools/build_abap_rules.py` can keep
regenerating the vendored corpus. Each was reproduced against the shipped patterns
before being changed, and each ships with the control proving the true positive
survived.

| Item | Rule | Effect |
|---|---|---|
| F1 | `ABAP-SQLI-002` | fired on **every** `CONCATENATE` (INTO is mandatory) and on the English word "from"; now keyed on an SQL keyword inside the concatenated literal |
| F2 | `ABAP-SQLI-001` | parenthesised logical grouping read as a dynamic clause; parenthesis bounded to one name or literal |
| F3 | `ABAP-CINJ-007` | **was inverted** — CRITICAL on static `CALL TRANSFORMATION id`, silent on dynamic `(lv_dyn)` |
| F4 | 7 dynamic-token rules | literal operand → severity `LOW` + evidence text, finding kept as inventory |
| F5 | `ABAP-CONF-002` | XML/SOAP namespace URIs (incl. SAP's own asXML) reported as insecure transport |
| F6 | `ABAP-CINJ-005` | `SUBMIT rep LINE-SIZE 132` fired; anchored to the parenthesised form |
| F7 | `ABAP-AUTH-002` | partial DUMMY is not a disabled check; + `DESCRIPTION_FIXES`, severity → MEDIUM |
| F8 | `ABAP-CDS-002` | grant syntax marked **UNVERIFIED SYNTAX** rather than presented as coverage |
| F9 | `ABAP-XSS-006` | retired via `RETIRED_RULES` rather than narrowed by guessing method names |
| F10 | `ABAP-CONF-005` | false **negative**: silent on `ID 'ACTVT' FIELD '*'`, the form real code uses |
| F11 | CDS `/* */` | block comments emitted as statements; newlines preserved so line numbers hold |

Exit criterion: `test_a_correct_method_produces_nothing` — a 24-line correctly
authorised method that previously produced several findings, two CRITICAL, with no
dynamic SQL in it.

F4 does **not** introduce the proposed `confidence="literal-operand"`:
`finding.taint_confidence` is CHECK-constrained to confirmed / tentative /
pattern-only in `server/schema.sql:564`, and those classes are what
`modules/fair_adapter.py` prices. The demotion is carried by severity and evidence
text instead, which needs no schema change.

## STATUS — TIER 3 SHIPPED

Corpus 99 → 118 rules; taint sinks 9 → 12. Every Group A pattern was measured
against the SAFE form of its own construct before shipping, and that control lives
beside the positive case in `tests/test_abap_tier3.py`.

**Group A — all 15.** A1 `ABAP-SQLI-013` (dynamic column list) · A2
`ABAP-SQLI-014/-015/-016` (write-side: table name, SET clause, indicators) · A3
`ABAP-AUTH-010/-011` (cross-client — we were flagging the spelling SAP calls
obsolete and missing all three live ones) · A4 `ABAP-AMDP-004` (not read-only) ·
A5/A7/A12 widenings · A6 `ABAP-RAP-001/-002` (BDEF authorization off-switches —
`.asbdef` previously produced **zero** findings) · A8 `ABAP-CINJ-013` (qualified
dynamic method call) · A9 `ABAP-CINJ-014` · A10 `ABAP-DYNT-001/-002` + the engine
guard that stops `DELETE itab WHERE (c)` being reported CRITICAL CWE-89 · A11
`ABAP-CINJ-015` · A13 `ABAP-AMDP-005` · A14 `ABAP-RAP-003/-004` · A15
`ABAP-CINJ-016/-017`.

Two deviations, both taken from the plan's own warnings. Every parenthesised-name
pattern is bounded to `_NAME`, never `[^)]*`, or it re-introduces Tier 2's F2 defect
under a new id. And A15's **ASSIGN COMPONENT variant was dropped**, not narrowed:
index-driven component iteration is the dominant idiom in ALV and generic structure
walks, so it buys a MEDIUM on correct code in nearly every custom estate.

**Group B — 7 of 9.** B1 shipped in Tier 1. B2/B4 (procedure and handler inbound
parameters, seeded per scope and never into `_globals`) · B3 (output binding — this
is what finally lets `gui_upload` fire; it has been in the vendored source list
since day one and could never trigger) · B5 (`CALL TRANSFORMATION ... SOURCE XML`,
capturing the right-hand ABAP variable) · B6 (data cluster) · B7 (classic list) ·
B8 (selection-screen commands, plus `MODULE`/`ENDMODULE` as scopes so taint stops
leaking between dialog modules).

**B9 is declined.** HTTP response bodies need the released-classes listing to anchor
on client identity; anchoring on a bare accessor name instead would taint every
CATCH block in the estate, because that accessor is overwhelmingly the exception
message getter. Every source added is an ABAP **keyword or system field** — a
language construct anyone can verify — and `test_the_new_source_families_are_abap_keywords_not_library_names`
asserts no class-qualified identifier entered `_SOURCE_RE`. U9's shared-memory and
database cluster media are excluded for the same reason.

Two existing assertions in `tests/test_abap_coverage_gaps.py` were changed, both
because they tested a *proxy* rather than the intent:
`test_cds_files_are_not_matched_with_abap_rules` required every rule reaching a CDS
artefact to be spelled `ABAP-CDS-*`, which RAP behaviour definitions legitimately
are not — it now asserts the actual guarantee, that no ABAP rule reaches DCL.
`test_rap_readiness_was_declined_rather_than_half_built` required that no rule id
contained "RAP"; what was declined is the **released-object currency check**, and
`ABAP-RAP-001..004` read a BDEF's own source, carry no catalogue and go stale at no
rate. It now asserts no rule ships a released-object snapshot.

### Why T1.11 was declined

Both halves fail this repo's own evidence rule, in different ways.

**The `@`-bound downgrade.** The plan calls it "sound under path-insensitivity —
the `@` is in the string the sink actually receives". No concrete correct example
could be constructed: in the form where the host variable is named inside the
condition text, the whole clause is a literal and already classifies CLEAN without
any new machinery; in the built form what is spliced is the value, not the name, so
it is not host binding at all. Shipping a *suppression* whose motivating case cannot
be written down is the failure mode the no-fabrication rule exists to prevent — and
§7/U1 lists the related grammar questions as still unverified.

**The spliced-quote promotion.** Well-defined and detectable, but `confirmed` is
defined in `AbapSourceScanner._finding` as "tainted input provably reaches this
statement". A value spliced between bare quote characters is a structural signal,
not a taint proof, so promoting on it would make the evidence string the report
prints a false statement. Doing it honestly needs a fourth confidence class — a
`finding.taint_confidence` CHECK-constraint change in `server/schema.sql` that also
changes what `modules/fair_adapter.py` prices. That is a schema decision, not a
lexer fix.

---

## ABAP SAST ENGINE — ONE PRIORITISED PLAN

Everything below is grounded in the shipped files at `d:/KIZEN/SAP-Security-Tool/SAP-S4HANA-RISE-Security-Scanner/modules/`. I re-ran the live scanner to confirm the load-bearing claims before ranking them; measured results are marked **[re-run]**. Line numbers are from the current files (`abap_sast.py` 669 lines, `abap_sast_rules.py` 1451, `abap_sast_extra.py` 234).

---

# 1. THE HEADLINE

**Fix the lexer first: give `split_statements()` a single shared mode-stack scanner with a `{ }` embedded-expression mode, and add a runaway-buffer flush with a counter.**

Why this and nothing else, if only one thing ships:

A rule regex that misfires costs you one rule. A lexer that mis-splits costs you *every* rule on that file, silently, and it does so in the direction that looks clean. **[re-run]** On this input:

```abap
METHOD m1.
  DATA(msg) = |Result: { replace( val = txt pcre = `a|b` with = `#` ) }|.
  SELECT * FROM (lv_tab) INTO TABLE @DATA(lt).
ENDMETHOD.
METHOD m2.
  AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '03'.
  DELETE FROM zcust WHERE kunnr = lv_k.
ENDMETHOD.
```

`split_statements()` returns **2 statements, not 8**. The pipe inside the backquoted `` `a|b` `` closes the template early, the stray backquote opens a literal that never closes, `_terminator()` returns `None` for the remainder of the file, and everything from line 2 to EOF becomes one `Statement` with `block=1`. Both `ENDMETHOD`s and the second `METHOD` are swallowed, so `_BLOCK_OPEN`/`_BLOCK_CLOSE` (anchored `.match()`, `abap_sast.py:212,217`) never fire — and `guarded_blocks` (`:440`) then credits `m2`'s AUTHORITY-CHECK to `m1`'s SELECT. One literal pipe converts a whole object into a clean report. There is no counter for it, unlike `files_scanned` / `metadata_skipped` / `unreadable` (`:375-377`).

Everything in Tier 2 and Tier 3 is arithmetic on top of a number the lexer decides.

---

# 2. TIER 1 — CORRECTNESS

Ordered by blast radius. Items T1.1–T1.3 are prerequisites for anything else being trustworthy.

### T1.1 — One mode-stack scanner, replacing the two divergent lexers
**Files:** `abap_sast.py:281-329` (`_strip_comments`), `:332-366` (`_terminator`), threading at `:180/:194`.

Today there are two hand-written scanners over the same grammar. `_strip_comments` runs per raw line and threads only `in_template`; `quote` and `escaped` are locals reborn every line. `_terminator` re-derives all three from the joined buffer. They already disagree about whether literal state survives a newline. Neither has a `{ }` mode — the `_terminator` docstring at `:336` explicitly claims embedded `{ }` expressions are handled; they are not.

**Change:** one pass returning `(code, literal_spans, terminator_offset, carried_mode_stack)`, consumed by both call sites. Modes:

| Mode | Behaviour |
|---|---|
| `CODE` | `'` / `` ` `` push `LIT(delim)`; `\|` pushes `TPL`; `"` ends the line as comment; `.` is the terminator |
| `LIT(d)` | only `d` pops; doubled delimiter is the escape — pop-then-push already gives correct parity (`` str1 = `a backquote: ``.` `` splits correctly today); backslash is **not** an escape here |
| `TPL` | `\` consumes exactly one following char (`\\ \| \{ \}`); unescaped `\|` pops; unescaped `{` pushes `EMB`; `"` and `.` are data |
| `EMB` | lex as `CODE`, except `}` pops back to `TPL`. A literal inside `{ }` is a real literal (its pipes and periods inert); a `\|` inside `{ }` opens a nested `TPL` |

Thread the whole stack across lines exactly as `in_template` is threaded now.

**Do NOT delete the digit-digit exemption at `:363-364` in this change.** The verification pass demonstrated it is not inert: `tests/test_abap_sast.py:111` exercises it, and — more importantly — this scanner sees SQLScript inside `.abap` files (the repo ships `ABAP-AMDP-001/002/003` and `tests/fixtures/abap/amdp_vulnerable.clas.abap`), where bare decimals are normal. Removing it manufactured statements like `` `lt_f = SELECT * FROM orders WHERE margin > 0` `` / `` `75 AND rate < 12` ``. **Correct the comment** from "decimal literal" to what it actually protects: bare decimals in embedded SQLScript and native SQL reaching this splitter because they live in `.abap` files.

### T1.2 — Runaway-buffer flush + a degraded-coverage counter
**File:** `abap_sast.py:161-228`.

Even with T1.1, two grammar questions remain unsettled (multi-line templates, nested templates — see §7). Defence, not a bet:

- Track how many source lines the current `buf` spans. Past a bound (**50** — the module's own motivating example is a 4-line SELECT), flush `buf` as one `Statement`, reset the mode stack to `CODE`, increment a counter.
- Return/attach that counter next to `metadata_skipped` on `AbapSourceScanner` and surface it in the coverage manifest. A mis-lexed file must report as **degraded coverage**, never as a clean object.

### T1.3 — Mask literal/template *content* before rule matching
**Files:** `abap_sast.py:441-448` (`pattern.search(st.text)`), `:130`, `:440`.

Comments are stripped; literals are not. Both directions are live. **[re-run]**:

- **Invented HIGHs from prose** — `MESSAGE |Never use EXEC SQL in this program| TYPE 'I'.` → `ABAP-NSQL-001`. `` DATA(help) = `Use CALL TRANSACTION only with authority check`. `` → `ABAP-CINJ-004` + `ABAP-AUTH-008`.
- **Prose defeating the guard** — a FORM with `DELETE FROM zcust` + `UPDATE zvendor` yields `['ABAP-AUTH-005','ABAP-AUTH-006']`; adding only `MESSAGE |Remember to AUTHORITY-CHECK before delete| TYPE 'I'.` yields **`[]`**. A developer's TODO about missing authorization silences the finding about missing authorization.

**Change:** have the T1.1 scanner emit literal/template-text spans, and build `Statement.text_masked` — content of literals and of template *text* replaced character-for-character with `#`, preserving delimiters and offsets. Content of `{ }` embedded expressions is **code** and is not masked. Then:

- (a) Use `text_masked` **unconditionally** for the `_AUTHORITY_CHECK` scan at `:441`. A guard is a statement, never a message text.
- (b) Add `LITERAL_BLIND: frozenset[str]` in `abap_sast.py` beside `PATTERN_FIXES` (`:116`), naming rules matched against `text_masked`. Seed: `ABAP-NSQL-001`, `ABAP-CINJ-004`, `ABAP-AUTH-008`, the five in `AUTHORITY_GUARDED` (`:125-128`), and `ABAP-AMDP-001`.
- **Not global.** Rules that key on *values* — hardcoded-credential patterns, `ABAP-SSRF-001`'s `create_by_url`, `ABAP-CONF-002`'s URL literals — need literal content.

Side-table shape is deliberate: like `PATTERN_FIXES`, it survives `tools/build_abap_rules.py` regenerating the corpus.

### T1.4 — `_sink_argument()` must use each rule's own `_sink_arg`
**File:** `abap_sast.py:520-525`, consumed at `:502`.

Confirmed by inspection: **8 vendored rules ship a precise `_sink_arg`** and none of them is ever read.

```
ABAP-SQLI-001  WHERE\s*\(\s*([^)]*)\)          ABAP-SQLI-010  FROM\s*\(\s*([^)]*)\)
ABAP-SQLI-006  ORDER\s+BY\s*\(\s*([^)]*)\)     ABAP-SQLI-011  FROM\s*\(\s*([^)]*)\)
ABAP-SQLI-007  GROUP\s+BY\s*\(\s*([^)]*)\)     ABAP-CINJ-005  SUBMIT\s+\(?\s*([a-zA-Z_]\w*)
ABAP-SQLI-008  HAVING\s*\(\s*([^)]*)\)         ABAP-PATH-001  OPEN\s+DATASET\s+([a-zA-Z_]\w*)
```

`_refine` instead calls a generic `_SINK_ARG` that returns the *first* `( identifier )* anywhere in the statement. Three consequences, all reproduced across angles:

1. `SELECT * FROM (lv_tab) WHERE (lv_where)` grades the WHERE finding on `lv_tab`. Worse the other way: with `p_tab` a PARAMETERS and `lv_ord = 'MATNR'`, `ABAP-SQLI-006` is emitted `confidence=confirmed`, `scope=object`, with a `taint_flow` tracing a variable that is **not** the ORDER BY operand — a fabricated data-flow trace in a customer report.
2. The two sinks whose token is not parenthesised — `ABAP-PATH-001` (`OPEN DATASET lv_file`) and `ABAP-SSRF-001` (`create_by_url( ... url = lv_url )`) — return `None`, hit `if not arg: continue` at `:503`, and can **never** reach `confirmed`. Their taint pass is dead despite shipping a working regex.
3. Confidence routes scope at `:585-589`, so every misgrade also demotes a tracked object finding to a rule×object aggregate.

**Change:**
```python
_SINK_ARG_BY_ID = {r["id"]: re.compile(r["_sink_arg"], re.I)
                   for r in ALL_ABAP_SAST_RULES if r.get("_sink_arg")}

def _sink_argument(statement: str, rule_id: str | None = None) -> Optional[str]:
    pat = _SINK_ARG_BY_ID.get(rule_id) if rule_id else None
    m = (pat or _SINK_ARG).search(statement)
    return m.group(1).strip() if m else None
```
Call as `_sink_argument(finding["statement"], finding["rule_id"])` at `:502`. `abap_sast_rules.py:1192` already defines `_ABAP_RULES_BY_ID` and nothing consumes it — use it or delete it. Give `ABAP-SSRF-001` (`abap_sast_extra.py:209`) the `_sink_arg` it lacks:
`r"create_by_url\s*\([^)]*?\burl\s*=\s*([A-Za-z_]\w*)"`.

**Do not** ship the separately-proposed "skip `DATA(`/`FINAL(` targets, then prefer `FROM|WHERE|INTO|MODIFY`" tie-break. Verification measured 187 findings over ~525 KB of SAP-authored ABAP and `_sink_argument` never once returned a declaration target; and preferring `INTO` actively breaks the documented `... INTO ( dobj1, dob2 )` target-list form (03_ABAP_SQL.md:506). Rule-aware extraction makes an inline `@DATA(...)` target structurally unreachable whatever the clause order is. A bare `DATA|FINAL` skip in the *generic fallback* is cheap and harmless — keep that much, drop the keyword preference list.

### T1.5 — The AUTHORITY-CHECK guard is fail-open in four independent ways
**File:** `abap_sast.py:130`, `:440-441`, `:451`.

`_AUTHORITY_CHECK = r"\bAUTHORITY[-\s]?CHECK\b"` searched unanchored over `st.text` credits a whole block on keyword presence. Four documented no-ops all currently earn credit:

1. **Inside a string literal** — fixed by T1.3(a).
2. **All fields `DUMMY`** — an all-DUMMY check credits the block and suppresses `ABAP-AUTH-005`.
3. **`sy-subrc` never evaluated** — a real check whose result is discarded credits the block.
4. **`AUTHORITY CHECK` / `AUTHORITYCHECK`** admitted by `[-\s]?`; neither is the documented spelling.

**Change — one anchored pattern plus one shared predicate:**
```python
_AUTHORITY_CHECK_STMT = re.compile(
    r"^AUTHORITY-CHECK\s+OBJECT\b(?=.*\bFIELD\b)", re.IGNORECASE)
```
(`.match()`; statement text is whitespace-normalised at `:203`, so `^` and `.*` across the whole multi-line statement are both reliable.)

```python
def _subrc_evaluated(statements, i) -> bool:
    """Was the AUTHORITY-CHECK at index i actually acted on?"""
    for st in statements[i+1:i+4]:
        if st.block != statements[i].block:
            return False
        if re.search(r"\bSY-SUBRC\b", st.text, re.I):
            return True
        if re.match(r"^(?:IF|CASE|CHECK|ELSEIF|ASSERT)\b", st.text, re.I):
            return False
    return False
```
Three statements forward, not one: it absorbs residual mis-splitting and the `COND #( WHEN sy-subrc = 0 ... )` form.

```python
guarded_blocks = {st.block for i, st in enumerate(statements)
                  if _AUTHORITY_CHECK_STMT.match(st.text_masked)
                  and _subrc_evaluated(statements, i)}
```
One helper, two consumers — the guard, and T1.6.

Also **add `"ABAP-AUTH-008"` to `AUTHORITY_GUARDED`** (`:125-128`) and correct the docstring at `:42` from "Five rules" to "Six". `ABAP-AUTH-008` is literally named "…without S_TCODE check" and currently fires on correctly guarded code.

### T1.6 — `ABAP-AUTH-003` is dead code and must move into the engine
**File:** `abap_sast_rules.py:438`; splitter at `abap_sast.py:210`.

Pattern requires a literal `.` that `split_statements` strips, and a lookahead at the *next* statement that a single-statement regex can never see. It fires only when a period appears inside a literal (`FIELD 'A.B'`) — dead in general, guaranteed false positive in the one case it triggers.

**Change:** emit it from `scan_text` using `_subrc_evaluated()` from T1.5, and add `"ABAP-AUTH-003"` to a new `RULE_HANDLED_IN_ENGINE` set that the generic loop at `:444` skips. Look the rule dict up by id so severity/CWE/text stay vendored.

### T1.7 — Sanitizer inventory: three defects, one of them inverted
**File:** `abap_sast_rules.py:1232-1237`.

```
cl_abap_dyn_prg=>|file_validate_name|escape_quotes|cl_http_utility=>escape
|check_whitelist|check_char_literal|check_column_name|check_table_name
|check_int_value|check_variable_name
```

1. **The blanket `cl_abap_dyn_prg=>` prefix credits any method on the class** — including `escape_xss_javascript`, an XSS escaper, against a dynamic FROM clause. Reproduced: `lv_tab = cl_abap_dyn_prg=>escape_xss_javascript( gv_in ).` + `SELECT * FROM (lv_tab)` → `sanitized` → `tentative` → aggregate bucket.
2. **`escape_quotes` is listed; `quote` and `quote_str` are not.** The pair is backwards: escaping without delimiters is the half that does not make a value safe.
3. **No word boundaries, no call syntax.** `_SANITIZER_RE.search` matches the bare identifiers `lv_escape_quotes`, `gv_check_table_name_old`, `lt_check_int_values`. Since `classify_sink` (`:1391`) tests the regex against the *raw sink argument*, a PARAMETERS-tainted variable **named** `lv_escape_quotes` in `WHERE (lv_escape_quotes)` returns `sanitized` outright.
4. `check_allowlist` — the current released spelling — is absent, surviving only by accident via (1). Removing (1) without adding it turns every correct modern guard into a false positive.

**Change** (vendored file, so widen from `abap_sast.py` the way `PATTERN_FIXES` does, guarded by an idempotence flag so repeated scans do not keep appending):
```python
_SAN_METHODS = ("check_table_name_str", "check_table_name_tab", "check_allowlist",
                "check_column_name", "check_char_literal", "check_int_value",
                "check_variable_name", "quote", "quote_str")
# anchored + call syntax required
r"\b(?:cl_abap_dyn_prg\s*=>\s*)?(?:" + "|".join(_SAN_METHODS) + r")\s*\("
```
Plus the built-in escaping form, which is currently absent entirely and which SAP recommends: `\bescape\s*\(\s*val\s*=` together with `cl_abap_format\s*=>`. Keep `escape_xss_javascript` and `escape( ... format = cl_abap_format=>e_xss...)` in a **separate XSS-only set** no SQL/path/SUBMIT/SSRF sink may consult.

Regression test: `classify_sink` must return `tainted` for a tainted variable named `lv_escape_quotes`.

### T1.8 — Sink-specific sanitizer mapping
One flat `_SANITIZER_RE` is consulted identically by `_classify` (`:1357`), `_combine` (`:1366`) and `classify_sink` (`:1391`) for all 9 sinks, so a table-name check clears an `OPEN DATASET` path and a column check clears a `SUBMIT` program name. These guards are not interchangeable — SAP's own worked example calls the column check on all four passes while stating the pass-4 injection is prevented by the quoting function, not the column check.

**Change:** `SINK_SANITIZERS: dict[str, tuple[str, ...]]` in `abap_sast_extra.py` —

| Sink | Accepted guards |
|---|---|
| `ABAP-SQLI-010`, `-011` (table name) | `check_table_name_str`, `check_table_name_tab`, `check_allowlist` |
| `ABAP-SQLI-006`, `-007` (column/sort) | `check_column_name`, `check_allowlist` |
| `ABAP-SQLI-001`, `-008` (condition/value) | `quote`, `quote_str`, `check_allowlist` |
| `ABAP-CINJ-005` (SUBMIT), `ABAP-SSRF-001` | `check_allowlist` |
| `ABAP-PATH-001` (dataset path) | *(none — no verified guard)* |

`check_allowlist` appears in **every** entry: membership in a fixed set constrains the value in any position. Build one analyzer per rule id via a subclass overriding the class attribute, cached in a dict — `type('A',(TaintAnalyzer,),{'_SANITIZER_RE': sanitizer_re(rid)})(source)`. Vendored file untouched.

### T1.9 — Sanitizer credited before the source, and across the whole expression
**File:** `abap_sast_rules.py:1355-1369`.

`_classify` tests `_SANITIZER_RE` and returns `SANITIZED` *before* testing `_SOURCE_RE`, over the entire expression. Two reproduced consequences: `CONCATENATE cl_abap_dyn_prg=>quote( 'LH' ) p_in INTO lv_where` → `sanitized` (the guard wraps the safe literal; the tainted `p_in` is never examined); and a source and a wrong-sink guard on the same line → `sanitized`.

**Change**, both in the consumers, both regex-level and path-insensitive:
- Test `_SOURCE_RE` first; return `SANITIZED` only if no source token remains outside the guard's parentheses.
- Credit a guard only when it wraps *the* tainted identifier: `re.search(rf'{SAN}\s*\([^()]*\b{re.escape(ident)}\b', expr, re.I)`.

### T1.10 — Feed TaintAnalyzer our statements, not raw text
**File:** `abap_sast.py:499` passes raw `source`; `abap_sast_rules.py:1246-1252` re-lexes it per line with `line.split('"',1)[0]` — no literal awareness at all.

Measured downgrades of a *confirmed* injection to *tentative*, each isolated against a working control:

| Form | Cause |
|---|---|
| `DATA(lv_tab) = p_tab.` | assignment regex `^\s*([\w/]+)\s*=` (`:1343`) finds `(` |
| `lv_w &&= p_in.` | same |
| the same concatenation split over two lines | `_apply` never sees line 2 — **the exact failure this module's docstring (`:16-33`) exists to eliminate** |
| chained `PARAMETERS: p_a ..., p_tab ...` | `_PARAM_RE` (`:1240`) captures one name per *line*; `_globals` = `['p_a']` |
| `lv_where = p_in && ' say "hi" '.` | `split('"',1)` truncates — loses the source *and*, in the mirror case, the sanitizer |
| `CONSTANTS lc_where TYPE string VALUE 'MANDT = SY-MANDT'.` | no declaration case; a compile-time-fixed clause reports as `tentative` CRITICAL |

**Change:** add `_taint_source(statements, line_count)` in `abap_sast.py` producing a string with exactly the original line count, each `Statement`'s normalised text on its **start** line, consumed lines blanked. Alignment is free: findings carry `st.line` and `state_of` walks strictly before it. In the same pass, three rewrites local to the synthetic copy:
- `DATA(x) =` / `FINAL(x) =` / `@DATA(x) =` → `x =` (pad with `ljust` to preserve columns)
- `X &&= EXPR` → `X = X && EXPR`
- expand chained `PARAMETERS:` / `SELECT-OPTIONS:` / `TABLES:` so each member lands on one of the statement's own source lines

and substitute any `"` the lexer classifies as inside a literal/template with a harmless character. Taint only ever reads identifiers, so this is safe and column-preserving.

Then add, in a `RiseTaintAnalyzer(TaintAnalyzer)` subclass in `abap_sast.py`:
- a declaration case at the top of `_apply`: `r"^\s*(?:CONSTANTS|DATA|STATICS)\s*:?\s*([\w/]+)\b[^=]*?\bVALUE\s+(.+?)\s*$"` → `_assign`; `_LITERAL_RE` already returns `CLEAN` for a literal RHS. **This alone converts the largest single block of `tentative` CRITICALs into defensible CLEAN verdicts.**
- an `=(?!>)` guard on the assignment fallback. **[re-run]** `cl_gui_frontend_services=>gui_upload( CHANGING data_tab = lv_w ).` currently taints the *class name* and leaves `lv_w` unknown — a false negative on the real target and a false positive on every later mention of the class. `gui_upload` is already in `_SOURCE_RE` and can therefore never fire as intended.

### T1.11 — Positive safe/unsafe idioms (do these with T1.10, they share the plumbing)
- **SAFE, suppressible:** a host variable bound with `@` inside a dynamic clause. Record the last RHS per variable (`self._rhs[tgt] = rhs` in `_assign`). For condition-position sinks (`-001`, `-008`), return CLEAN when every occurrence of each tainted identifier in the builder RHS is `@`-bound and none is spliced. Sound under path-insensitivity — the `@` is in the string the sink actually receives.
- **UNSAFE, promotable:** a value spliced between bare quote characters adjacent to `&&`. New rule in `abap_sast_extra.py`, HIGH/CWE-89; and in `_refine`, promote a sink whose builder RHS matches it from `tentative` to `confirmed`. A positive structural signal, not an absence of evidence.

### T1.12 — AMDP bodies are lexed with ABAP comment rules
**File:** `abap_sast.py:281`.

`_strip_comments('  lt = APPLY_FILTER("ZDEMO_VIEW", :lv_filter);')` → `'  lt = APPLY_FILTER('`. In SQLScript `"` delimits an identifier. So `ABAP-AMDP-002` cannot fire on the quoted-identifier form, and `DELETE FROM "ZDEMO_VIEW" WHERE ...;` becomes the statement `DELETE FROM ENDMETHOD`. In the other direction `--` comments are never stripped, so `-- legacy: EXECUTE IMMEDIATE :lv_sql;` raises `ABAP-AMDP-001` CRITICAL — precisely the commented-code false positive the docstring at `:168-171` claims to have eliminated.

**Change:** thread an `in_amdp` flag as a mode in the T1.1 stack. Enter on an emitted statement matching `\bBY\s+DATABASE\s+(?:PROCEDURE|FUNCTION)\b`; leave on a **raw line** matching `^\s*ENDMETHOD\b` (a SQLScript body contains no period, so it emits no statement). While set: `"` toggles quoted-identifier state, `'` a string literal, `--` comments to end of line, `/* */` threads across lines, `*` in column 1 stays a comment; split on `;` instead of `.`; `_terminator` skips periods inside a quoted identifier so `"SCHEMA"."TABLE"` does not chop. Today the whole body plus `ENDMETHOD` collapses into one blob, which is why AMDP findings report the wrong line.

Sequence T1.12 after T1.1 — it is a mode in the same machine, not a separate patch.

---

# 3. TIER 2 — FALSE POSITIVES

Ranked by how often the safe form appears in real ABAP. All are `PATTERN_FIXES` entries in `abap_sast.py:116` unless noted — the vendored corpus must not be edited.

| # | Rule | How often the safe form appears | Fix |
|---|---|---|---|
| **F1** | `ABAP-SQLI-002` (`abap_sast_rules.py:62`) | **Every `CONCATENATE` statement in the estate.** `INTO` is mandatory syntax, so the pattern `(?:CONCATENATE\|&&).*(?:WHERE\|INTO\|FROM)\b` matches 100% of them at CRITICAL/CWE-89. **[re-run]** `CONCATENATE s4 s5 INTO s3.` → `ABAP-SQLI-002`. The `&&` arm matches the English word "from": **[re-run]** `` DATA(m) = `Deleted ` && lv_n && ` rows from the staging buffer`. `` → CRITICAL. No `_taint_sink`, so it can never be downgraded. | `"ABAP-SQLI-002": r"(?:\bCONCATENATE\b\|&&)[^.]*['\"`]\s*(?:WHERE\|AND\|OR\|ORDER\s+BY\|GROUP\s+BY\|HAVING\|FROM)\b"` — the danger is an SQL keyword inside a *literal* being concatenated. Longer term the rule is redundant: SQLI-001/010/011 + taint report the same thing with evidence. |
| **F2** | `ABAP-SQLI-001` (`:50`) | Parenthesised logical grouping is pervasive. **[re-run]** `SELECT * FROM dbtab WHERE ( comp1 = 'X' AND comp2 > 100 ) INTO TABLE @DATA(it).` → CRITICAL. Tuple form and `UPDATE ... WHERE ( k = @a AND f = @b )` too. `_sink_argument` finds no bare `( ident )`, returns `None`, `_refine` skips at `:503` — emitted CRITICAL `pattern-only`. | Bound the parenthesis to one name or one literal, as `ABAP-SQLI-011` already does for FROM: with `NAME = (?:` `` `[^`]*` `` `\|'[^']*'\|[A-Za-z_]\w*(?:->\w+\|-\w+)*)`, use `r"\b(?:SELECT\|UPDATE\|DELETE\|MODIFY)\b.*?\bWHERE\s*\(\s*" + NAME + r"\s*\)"`. Still matches both documented dynamic forms (both are written as one bare name); grouping, tuples and value lists drop out. |
| **F3** | `ABAP-CINJ-007` (`:226`) | **Inverted.** **[re-run]** `CALL TRANSFORMATION id SOURCE ... RESULT ...` → `ABAP-CINJ-007` CRITICAL; `CALL TRANSFORMATION (lv_dyn) ...` → **nothing**. It assumes "static means quoted", true for `CALL FUNCTION`/`CALL TRANSACTION`, false here. Any object doing XML/serialisation lights up. | `"ABAP-CINJ-007": r"\bCALL\s+TRANSFORMATION\s*\("` |
| **F4** | Dynamic-token rules on **literal** operands — `ABAP-CINJ-005/-006/-009/-012`, `ABAP-SQLI-010/-011/-012` | SAP writes literal operands as the *normal safe form*. Measured over ~525 KB of SAP-authored ABAP, the widened ASSIGN pattern fired 11 distinct times and **10 were hard-coded literals or integers**. `classify_sink` does return CLEAN for a quoted argument (`:1393`) but is never reached — `_SINK_ARG` requires a letter/underscore, returns `None`, `_refine` skips. | In `scan_text` before `out.append`: `_LITERAL_OPERAND = re.compile(r"\(\s*['\"`]")`; for ids in a new `DYNAMIC_TOKEN_RULES` set, when the parenthesised operand is a literal set `severity="LOW"`, `confidence="literal-operand"`, evidence "the dynamic name is a compile-time literal". **Keep the finding** — a literal class/report name is an inventory entry, just not a HIGH one. |
| **F5** | `ABAP-CONF-002` (`:684`) | Every object that serialises XML/SOAP carries several `http://` namespace URIs — all HIGH, all wrong, including SAP's own asXML namespace. | `"ABAP-CONF-002"` with a negative lookahead over a maintainable namespace-authority allowlist. **Only the SAP and W3C hosts are verified** (from 21_XML_JSON.md); treat the rest as an allowlist we maintain, not a claim about SAP. |
| **F6** | `ABAP-CINJ-005` (`:204`) | Unanchored, and the addition exclusion list is incomplete. `SUBMIT zdemo_report AND RETURN.` is clean but `SUBMIT zdemo_report LINE-SIZE 132 AND RETURN.` fires HIGH; and because it is unanchored, a report name *ending* in `submit` makes the statement match on its own identifier. | `"ABAP-CINJ-005": r"^\s*SUBMIT\s+\("` and rely on taint via the existing `_sink_arg` (now reachable after T1.4) for the bare-variable case. Anchoring alone kills the identifier-substring class. |
| **F7** | `ABAP-AUTH-002` (`:428`) | Fires on correct RAP authorization code; and the description asserts DUMMY "always passes… effectively disables the authorization check", which the source contradicts — a partial DUMMY still yields a non-zero `sy-subrc`. A reviewer is told a three-field check is disabled when two fields are enforced. | `"ABAP-AUTH-002": r"^AUTHORITY-CHECK\s+OBJECT\b(?!.*\bFIELD\b).*\bDUMMY\b"` (fires only when *no* field is checked). `PATTERN_FIXES` cannot reach `description`, so add a sibling `DESCRIPTION_FIXES: Dict[str,str]` applied at `:466`, and drop severity to MEDIUM. Note this is separable from T1.5(2), which is a *guard-credit* change. |
| **F8** | `ABAP-CDS-002` (`abap_sast_extra.py:153`) | Produces nothing against the only DCL grant syntax anyone verified — it may be matching a construct that does not exist. | Do not present it as covering anything until settled (§7). |
| **F9** | `ABAP-XSS-006` (`:400`) | Lookahead excludes exactly one method name, so every *other* use of a general HTTP utility class is reported MEDIUM as missing HTML escaping. | Add to a `RETIRED_RULES` set skipped at `:444` — XSS-001/002/003/005 cover the real output sinks. Do **not** write a narrowing regex naming methods until the released-class listing is read (§7). |
| **F10** | `ABAP-CONF-005` (`:714`) — *false **negative**, listed here because it is the same regex-shape defect* | Requires whitespace right after `ACTVT`, but the quoted form has a closing apostrophe there. **[re-run]** `AUTHORITY-CHECK OBJECT 'ZO' ID 'ACTVT' FIELD '*'.` → **no finding**. Silent on the form real code uses. | `"ABAP-CONF-005": r"AUTHORITY-CHECK\b[^.]*\bACTVT\b\W{0,3}FIELD\s+['\"`]\*['\"`]"` |
| **F11** | CDS block comments | `split_cds_statements` (`:248`) strips only `//`. A commented-out annotation inside `/* */` is emitted as a statement and fires `ABAP-CDS-001` HIGH; the stray `*/` leaks into the next statement's text. | `source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)` before the line loop. |

---

# 4. TIER 3 — NEW COVERAGE

**Group A — pure regex additions to `abap_sast_extra.py`.** No engine work. Ship after Tier 1.

| Rank | Rule | Why | Pattern |
|---|---|---|---|
| A1 | **`ABAP-SQLI-013` Dynamic SELECT column list** — HIGH, CWE-89, `_taint_sink` | **[re-run]** `SELECT (select_list) FROM zt INTO TABLE @DATA(it).` → **zero matches**. This is the exact construct SAP's own security example uses to motivate the allowlist check. | `r"\bSELECT\s+(?:SINGLE\s+\|DISTINCT\s+)*\(\s*" + NAME + r"\s*\)"` with the bounded `NAME` from F2. **Bounding is mandatory** — with `[^)]*` it fires on parenthesised SQL arithmetic in the select list (three HIGH CWE-89 on correct code, measured). **Drop `_sink_arg`** here: the generic extractor already returns `select_list` / `lv_cols` correctly. |
| A2 | **`ABAP-SQLI-014/-015/-016` write-side dynamics** — table name HIGH, SET clause **CRITICAL**, indicators MEDIUM | **[re-run]** `UPDATE (table) FROM @dref->*.` → **zero matches**. `ABAP-SQLI-010/-011` both require the literal `FROM` before the parenthesis; `ABAP-AUTH-006`'s `UPDATE\s+\w+\s+SET` cannot match `(table)`. A controlled SET clause rewrites arbitrary columns — it outranks a controlled WHERE. | `-014`: `r"\b(?:UPDATE\|MODIFY\|INSERT)\s+\(\s*[^)]*\)"`; `-015`: `r"\bUPDATE\b[^.]*\bSET\s*\(\s*[^)]*\)"`; `-016`: `r"\bINDICATORS\s*\(\s*[^)]*\)"`. `-014` cannot fire on `INSERT REPORT` or `INSERT dbtab FROM ( SELECT ... )` — the parenthesis must directly follow the keyword. |
| A3 | **`ABAP-AUTH-010/-011` cross-client** — `USING ALL CLIENTS` / `USING CLIENTS IN` **HIGH**; `USING CLIENT` MEDIUM | **[re-run]** `SELECT * FROM zt USING CLIENT @cl ...` → **zero matches**, while the spelling SAP calls **obsolete** (`CLIENT SPECIFIED`, `ABAP-AUTH-009`) is the only one we catch. We flag the dead form and miss all three live ones. | `-010`: `r"\bUSING\s+(?:ALL\s+CLIENTS\|CLIENTS\s+IN)\b"`; `-011`: `r"\bUSING\s+CLIENT\b"`. Both verified silent on `USING zdemo_view` and `USING client_dependent_view` — `\bCLIENT\b` cannot match inside `CLIENTS` or `client_dependent_view`. Split severity deliberately: reading all clients ≠ one redirect. |
| A4 | **`ABAP-AMDP-004` AMDP not read-only** — HIGH | An AMDP method that writes is invisible; today it produces the same single MEDIUM as a read-only one. | `r"\bBY\s+DATABASE\s+(?:PROCEDURE\|FUNCTION)\b(?!.*\bOPTIONS\s+READ-ONLY\b)"`. The negative lookahead is safe because the METHOD header is one complete statement. |
| A5 | **`ABAP-AMDP-003` widen** to `(?:PROCEDURE\|FUNCTION)` | `abap_sast_extra.py:76` matches only `PROCEDURE`, so every AMDP function is missed. A table function is consumable by any ABAP SQL SELECT, not only by a deliberate method call. | one-word change |
| A6 | **`ABAP-RAP-001/-002` BDEF authorization off-switches** — HIGH / MEDIUM, CWE-862 | `.asbdef` routes to `CDS_RULES`, which contains **only** `ABAP-CDS-001` and `ABAP-CDS-002` — two DDL/DCL shapes that cannot occur in a BDEF. A behaviour definition disabling authorization produces **zero findings**. Same silent-zero-coverage failure the docstring says was fixed for CDS. | `-001`: `r"\bauthorization\s+master\s*\(\s*none\s*\)"`; `-002`: `r"\bauthorization\s*:\s*none\b"`. **Must be added to `CDS_RULES`**, not `EXTRA_ABAP_RULES`. `split_cds_statements` already emits matchable units for both — no lexer change. |
| A7 | **`ABAP-CDS-001` widen** to `#(?:NOT_REQUIRED\|NOT_ALLOWED)` and **fix the recommendation** | `abap_sast_extra.py:136` misses the second full-exposure value. Worse, the recommendation at `:142-146` names the value whose missing role is only a *warning* — following our advice can leave a view unprotected and looking remediated. | widen pattern; change the recommendation to name the value that **forces** an access-control object to exist, keep the weaker one only as "warns", and state that the missed value additionally causes an existing role to be disregarded. |
| A8 | **`ABAP-CINJ-013` qualified dynamic method call** — HIGH, CWE-94 | `ABAP-CINJ-010` needs the parenthesis directly after `CALL METHOD`. Class- and object-qualified forms — the majority — match **no rule in the 99-rule corpus**. | `r"\bCALL\s+METHOD\s+[\w/]+\s*(?:=>\|->)\s*\(\s*[^)]*\)"`. Disjoint from CINJ-010, so no double-report. |
| A9 | **`ABAP-CINJ-014` compound dynamic type in `CREATE DATA`** — MEDIUM, CWE-913 | `ABAP-CINJ-012` sees only `TYPE (t)`; `TYPE TABLE OF (t)`, `TYPE REF TO (t)`, `TYPE LINE OF (t)`, `LIKE struc-(c)` and the dynamic key list all match nothing. | `r"\bCREATE\s+DATA\s+[\w<>/-]+\s+(?:TYPE\|LIKE)\b[^.]{0,200}?\(\s*[^)]*\)"` — bounded, so a mis-split statement cannot drag the match across unrelated text. |
| A10 | **`ABAP-DYNT-001/-002` internal-table dynamics** — MEDIUM, **CWE-913 not CWE-89** | 10 of 11 internal-table dynamic forms match nothing. The eleventh matches `ABAP-SQLI-001` and is reported **CRITICAL CWE-89 "Dynamic WHERE clause"** with a host-variable recommendation, on a statement that never touches the database. | `-001`: `r"\b(?:READ\s+TABLE\|LOOP\s+AT\|MODIFY\|DELETE)\s+[\w<>/-]+[^.]*\bWHERE\s*\(\s*" + NAME + r"\s*\)"` — **`DELETE` must be in the alternation** and the parenthesis **must** be bounded, or (a) you open a blind spot exactly where the guard below suppresses SQLI-001, and (b) you flag idiomatic parenthesised logical expressions in `LOOP AT`/`READ TABLE`, which SAP documents as correct. Both measured 4/4. `-002`: `r"\b(?:SORT\s+[\w<>/-]+\s+BY\|USING\s+KEY\|WITH\s+(?:TABLE\s+)?KEY\|COMPONENTS\|TRANSPORTING\|COMPARING)\s*\(\s*[^)]*\)"` — no constructible false positive; every static form puts a bare name where the dynamic form puts a parenthesis. Plus a guard in `abap_sast.py` skipping `ABAP-SQLI-001` when the statement matches `r"^\s*DELETE\s+(?!FROM\b)[\w<>/-]+\s"`. |
| A11 | **`ABAP-CINJ-015` dynamic `EXPORT`/`IMPORT` parameter list** — MEDIUM, CWE-913 | No rule anywhere mentions either as a dynamic construct. | `r"\b(?:EXPORT\|IMPORT)\s+\(\s*[^)]*\)\s+(?:TO\|FROM)\b"` — trailing `TO\|FROM` keeps it off unrelated parenthesised expressions. MEDIUM: it governs which names move in/out of a data cluster, not code execution. |
| A12 | **`ABAP-AMDP-001` widen** to `r"\b(?:EXEC(?:UTE)?\s+IMMEDIATE\|EXEC\s*\()"` | The bare call form is missed. `EXEC\s*\(` is restricted to the call shape so it cannot collide with `EXEC SQL` (already `ABAP-NSQL-001`) and double-report. |  |
| A13 | **`ABAP-AMDP-005` AMDP declaration not client-safe** — MEDIUM, CWE-284 | AMDP has no implicit client handling, and nothing matches either client-safety addition. | `r"\bAMDP\s+OPTIONS\b(?!.*\b(?:CDS\s+SESSION\s+CLIENT\s+DEPENDENT\|CLIENT\s+INDEPENDENT)\b)"`. Anchoring on `AMDP OPTIONS` keeps it to one statement. **Be honest in the rollout note**: a classic estate predating these additions lights up broadly — that is a real exposure, and aggregate scoping already collapses it to one finding per object. |
| A14 | **`ABAP-RAP-003/-004`** `IN LOCAL MODE` / `PRIVILEGED` in `.abap` behaviour pools — MEDIUM, CWE-862 | Grep finds no rule mentioning either. We report the *safe* construct two lines away and ignore the one that bypasses the check. | Simple keyword patterns. **MEDIUM, and the recommendation must say why**: both are legitimate inside behaviour pools and auxiliary classes, so the finding is "confirm the authorization decision was already taken upstream", not "this is a defect". Route to `scope="aggregate"`. |
| A15 | **ASSIGN family** — `ABAP-CINJ-009` covers only `ASSIGN (` ; **16 of 18** enumerated forms match no rule in the entire corpus | Real gap, but **do not ship the widened patterns as originally written** — measured, they fire almost entirely on hard-coded literals and integers. | Selector form: `r"\bASSIGN\b[^.]{0,200}?(?:->\|=>\|-)\(\s*(?!['\`0-9])[A-Za-z_]\w*\s*\)"` (collapses 11 distinct SAP-corpus hits to 1, and that survivor is the only genuinely dynamic one). `CASTING`: `r"\bCASTING\s+TYPE\s*\(\s*(?!['\`0-9])[A-Za-z_]"`. **`ASSIGN COMPONENT`: extend the lookahead to reject `sy-*` and bare integers, or drop the rule** — index-driven component iteration is the dominant idiom (ALV, generic structure walks) and flagging it buys a MEDIUM on correct code in nearly every custom estate. |

**Group B — needs engine work in `RiseTaintAnalyzer` (`abap_sast.py`), sequenced after T1.10.** Each is a new *source family*; today they all classify UNKNOWN, so every dynamic finding downstream of them is permanently `tentative` and permanently aggregated.

| Rank | Source | Shape |
|---|---|---|
| B1 | **Chained `PARAMETERS:` / `SELECT-OPTIONS:`** | Override `_collect_globals` to run over `split_statements(source)` (which already joins the chain) with a head regex + `(?:^\|,)\s*([A-Za-z_][\w/]*)`. The one source family the analyzer claims to own is currently 2/3 blind. `SELECTION-SCREEN INCLUDE PARAMETERS` correctly does not match. |
| B2 | **Procedure inbound parameters** (`IMPORTING`/`USING`/`CHANGING`/`TABLES`) | Seed **per-scope, never into `_globals`** — a shared name would leak taint into sibling procedures. Every injection reachable over RFC is currently UNKNOWN. Verified extraction correctly excludes `EXPORTING`/`RETURNING`. |
| B3 | **Output-parameter binding on a call** | `_OUT_BIND`/`_OUT_TGT` applied when `_SOURCE_RE` matches the statement. Fixes `gui_upload` — already in the source list, structurally unable to fire. Pairs with the `=(?!>)` guard from T1.10. |
| B4 | **RAP handler inbound parameter** | Keyed off the `METHODS ... FOR ...` declaration in the same class. The whole OData entry surface is invisible. Note `_IDENT_RE` (`:1242`) is `[A-Za-z_]\w*` and silently drops a leading `%`, so seed the bare name alongside the captured one or widen `_IDENT_RE` in the subclass. |
| B5 | **`CALL TRANSFORMATION ... SOURCE XML ... RESULT`** | Capture the **right-hand** ABAP variable in the result bindings, not the left-hand root name — that is the obvious wrong turn. Requires statement-level text (these are written across three lines). Without it our own `ABAP-XXE-001` can fire but nothing downstream of the parser can ever be confirmed. |
| B6 | **Data-cluster `IMPORT ... FROM MEMORY ID` / `DATA BUFFER` / `INTERNAL TABLE`** | New `_apply` branch; targets bind via `=` or `TO`. The `IMPORT (param_table) FROM DATA BUFFER` form binds by a runtime name table — leave it pattern-only, do not guess. |
| B7 | **Classic list interaction** — `sy-lisel` and `READ LINE ... INTO` | `_SOURCE_RE` addition works without touching `_IDENT_RE` because `_classify` searches the raw RHS text before identifier splitting. `READ CURRENT LINE.` correctly yields no INTO target. |
| B8 | **Selection-screen / dynpro function codes** | `sscrfields-*`, `sy-ucomm`; register `TABLES` work areas as tainted roots (reusing B1's chain regex). Also add `MODULE`/`ENDMODULE` to `_SCOPE_START_RE`/`_SCOPE_END_RE` — `abap_sast.py:134-137` already treats them as blocks, so today taint leaks between dialog modules. Deliberately broad; the current state is not zero-FP, it is zero-coverage. |
| B9 | **Outbound HTTP response bodies** | **Anchor on the client identity, not the accessor.** A bare `get_text` alternative would taint every CATCH block in the estate — the accessor is overwhelmingly the exception-message getter in the released-classes listing. Pairs with `ABAP-SSRF-001`: we can flag where the server is told to connect but not what comes back. Add base64-decoding helpers as **propagators only**, and keep them out of `_SANITIZER_RE` — decoding is not sanitising. |

---

# 5. WHAT THE SOURCE SETTLED THAT WE HAD GUESSED AT

**Contradicted — we were wrong:**

1. **`ABAP-AUTH-002`'s description.** We ship "DUMMY … always passes. This effectively disables the authorization check." The source's own worked examples show a partial DUMMY still yielding a non-zero `sy-subrc`. It exempts *one field*; the remaining pairs are enforced. Copy is wrong, regex is roughly right.
2. **`ABAP-CINJ-007`'s premise.** We inferred "static means quoted" from `CALL FUNCTION`/`CALL TRANSACTION`. For `CALL TRANSFORMATION` it is exactly backwards — static names are bare, dynamic ones are parenthesised. **[re-run]** confirmed both halves.
3. **`ABAP-AUTH-009` is the obsolete spelling.** We built cross-client detection on the form the source calls obsolete and have zero coverage of the three live ones.
4. **`check_whitelist` is not the released spelling** — `check_allowlist` is. Our entry survives only by accident via the blanket class prefix.
5. **`escape_quotes` vs the quoting function.** We credited the escaping half and never named the half that adds the delimiters. Backwards.
6. **The event-block split is net-negative.** We reasoned that a guard in one event block cannot protect a sink in another. The source states the execution **order**: these are sequential phases of one run, not independent entry points. Implementing the proposed regex turned two correctly-guarded programs into new `ABAP-AUTH-005/-006` findings and caught nothing new. Also: "all statements are implicitly assigned to `START-OF-SELECTION` unless explicitly assigned elsewhere" — so the current `blk=0` model is accidentally right.
7. **The digit-digit exemption is not inert.** We were about to delete it as encoding a wrong model of ABAP. It is covered by a passing test and protects bare decimals in embedded SQLScript, which reaches this splitter because AMDP lives in `.abap` files.

**Confirmed — inference held:**

8. **String templates needed lexing.** Confirmed by SAP code containing `MESSAGE |Hello.| TYPE 'I'.` — and the *embedded-expression* half is confirmed as still broken, since `{ }` embeds a full expression that carries its own literals, and literals routinely carry pipes.
9. **`PATTERN_FIXES` living outside the vendored file is the right shape.** Every fix in Tiers 1–2 uses it or a sibling side-table, and none requires editing a regenerated file.
10. **The dynamic-token inventory is genuinely narrow.** 40 of 49 SAP-authored dynamic statements matched **no rule at all**. The gap is not tuning.
11. **The built-in escaping function is the recommended form** and is absent from our sanitizer list — correctly escaped code currently reads as tainted.
12. **`ABAP-AMDP-002`'s argument order is right.** Only the quoted-identifier lexing defect (T1.12) defeats it.
13. **`ABAP-CDS-001`'s missing second value is real**, and our recommendation names the weaker of the two annotation values.
14. **Six event-block spellings we had flagged as possible fabrications are real** (`LOAD-OF-PROGRAM`, `AT LINE-SELECTION`, `TOP-OF-PAGE`, `END-OF-PAGE`, `AT USER-COMMAND` all appear in the list/report chapter; `END-OF-SELECTION` and `AT PF` do **not** appear there). Correcting the record only — see §6.

---

# 6. WHAT I WOULD NOT DO

1. **Do not split event blocks into separate `block` ids.** Rejected on measurement: 2 new false positives on correctly-guarded programs, 0 new true positives, and the proposal's own motivating example is a guarded program. If the underlying miss is worth chasing later, the correct shape is an **ordering-aware guard** — a report-level scope where a sink is unguarded only when no check occurs in a block that provably runs before it. That is a design task, not a patch.
2. **Do not delete the digit-digit exemption.** See §5.7. If it must go, it goes together with `tests/test_abap_sast.py:111` and a replacement guard suspending period-splitting between an AMDP/native-SQL opener and its matching close — much larger than "delete two lines".
3. **Do not add `INTO`/`MODIFY` to a `_sink_argument` clause-preference list.** Rule-aware extraction (T1.4) makes it unnecessary, and preferring `INTO` grades findings on the target for the documented parenthesised target-list form — reintroducing the exact defect, on a construct SAP documents.
4. **Do not ship any new dynamic-clause rule with `[^)]*` inside the parenthesis.** Measured false positives on SELECT-list arithmetic and on internal-table parenthesised logical expressions. Bound to one name or one literal. This applies to A1, A10 and F2 identically.
5. **Do not ship the widened ASSIGN patterns without the literal/integer exclusion.** 10 of 11 SAP-corpus hits were compile-time literals; the `ASSIGN COMPONENT` variant flagged the single most common generic-iteration idiom in real estates.
6. **Do not add `ABAP-AMDP-003` to `AUTHORITY_GUARDED`.** It would be inert: `guarded_blocks` is keyed on the enclosing block, and an AMDP method's block contains no ABAP statements, so a guarding check in the calling method is always in a different block. Instead **rename** the rule to what it detects (it executes outside the ABAP authorization layer) and drop or flag the unverified claim in its description.
7. **Do not build a parser or an AST.** Everything above is a mode-stack lexer, side tables, regex narrowing, and a subclass of the existing line-oriented analyzer. The taint pass stays intra-procedural and path-insensitive.
8. **Do not start deleting findings on the strength of a sanitizer.** The `_refine` docstring at `:484-487` is right, and T1.7–T1.9 tighten *who gets credit* without changing the downgrade-never-hide contract. The only two suppressions I would add are **positive** structural signals (T1.11), not absences of evidence.
9. **Do not write a narrowing regex for `ABAP-XSS-006` that names methods.** Retire it instead. Naming methods on a class nobody has read is exactly how fabricated identifiers enter this repo.
10. **Do not claim `ABAP-CDS-002` covers anything** until its grant syntax is confirmed (§7).
11. **Do not reconstruct the ABAP keyword documentation from memory.** It is a JS SPA behind OAuth and is not machine-readable to us. Every identifier that lands must be grep-confirmable in a named, fetched, SAP-authored file.

---

# 7. STILL UNVERIFIED — AND WHAT WOULD SETTLE IT

> **Ten closed, one of them partially.** U1, U2, U3 (partially), U4, U5, U6, U9, U10, U11 and U12 are settled against SAP's ABAP keyword documentation
> and struck through below; both turned out to be defects rather than research
> questions, which is the argument for working this list rather than leaving it.
> Regression fixtures live in `tests/test_abap_open_questions.py`.
>
> The route that worked, for whoever takes the next one: the keyword
> documentation is fetchable as static HTML at
> `help.sap.com/doc/abapdocu_<nnn>_index_htm/<n.nn>/en-US/<page>.htm` — the
> content page directly, NOT the `index.htm?file=` frameset, which returns only
> the frame shell. `SAP-samples/abap-cheat-sheets` is fetchable through the
> GitHub contents API and is a good way to find the page name, but it is a
> teaching resource and stops short of full syntax: for U6 it says only that "an
> addition is available with which you can specify other users" without naming
> it. The keyword documentation named it.

| # | Open question | Why it matters | Settles it |
|---|---|---|---|
| ~~U1~~ | **SETTLED — and the two halves have different answers, which is why threading one and resetting the other looked like an unexplained bet.** Character literals: "Character literals that span multiple lines are not allowed." String templates: "A string template that starts with | must be closed with | within the same line of source code. **The only exceptions to this rule are line breaks in embedded expressions.**" The T1.1 mode stack had made both consistent — consistently wrong, carrying `lit` AND `tpl` across every newline, so one stray delimiter masked the rest of the file as literal content and every rule went blind, bounded only by the fifty-line runaway guard. `_close_at_end_of_line` now drops both at the newline unless an `_M_EMB` frame is open, and the forced close marks the statement DEGRADED — a recovery nobody is told about is indistinguishable from a clean lex. | `abenstring_templates.htm`, `abenuntyped_character_literals.htm`, AS ABAP 7.55 | ✅ |
| ~~U2~~ | **SETTLED — the answer is NO, so A1 is unchanged and that is the result rather than an omission.** SAP documents the dynamic column list exactly once, and it is the form already matched: ``DATA(select_list) = `CARRID, CONNID, FLDATE`.`` then `SELECT (select_list) FROM ... INTO ...`. The `FIELDS` clause has its own variant table listing five forms — `FIELDS *`, a comma-separated list, `data_source~col`, `data_source~*`, `col AS alias` — and **none is parenthesised**; SAP calls the two spellings "basically the same but differently arranged", which is a statement about the STATIC list. No dynamic counterpart for `FIELDS` appears in the SQL or dynamic-programming material, so adding one would be inventing syntax — the way `ABAP-CDS-002` came to spend its life matching a `WHERE TRUE` DCL never had (U5). Both of SAP's spellings and all four static `FIELDS` forms are now regression fixtures. | `03_ABAP_SQL.md`, `06_Dynamic_Programming.md` | ✅ |
| ~~U3~~ | **PARTIALLY SETTLED.** SAP's released-classes listing shows `CL_ABAP_DYN_PRG` with `check_allowlist` and `check_table_name_tab`; `check_whitelist` appears nowhere in it, so **`check_allowlist` is confirmed as the released spelling**. What the source cannot settle is the original question, because the listing gives worked examples rather than class signatures and absence from examples is not absence from a class. The alias STAYS, and the asymmetry is the argument: keeping a name that does not exist costs a false negative only in a contrived case; removing one that does reports correct code as unsanitised. | `22_Released_ABAP_Classes.md` | ⚠️ |
| ~~U4~~ | **SETTLED — the rule was aimed at the wrong idea, so retirement is permanent rather than pending.** `CL_HTTP_UTILITY` is absent from the released listing entirely, and its ABAP Cloud counterpart `CL_WEB_HTTP_UTILITY` is described there as "Encoding strings/xstrings in Base64 and decoding Base64-encoded strings/xstrings", exposing only the four base64 methods — **no HTML escaping at all**. "Used this class without escaping" therefore says nothing either way, and no narrowing would have fixed that. Limit of the evidence, recorded in the code: the listing covers RELEASED APIs, so absence proves `CL_HTTP_UTILITY` is unreleased, not that the classic class lacks `escape_html`. | `22_Released_ABAP_Classes.md` | ✅ |
| ~~U5~~ | **SETTLED — and the rule was matching nothing.** SAP's keyword documentation gives the full access rule as `GRANT SELECT ON cds_entity [ REDEFINITION ] ;` and states it outright: "A full access rule GRANT SELECT ON **without the addition WHERE** provides access to a CDS entity `cds_entity` without conditions." There is no `WHERE TRUE` in DCL, so the shipped pattern could never fire — a HIGH/CWE-863 rule whose silence read as evidence. `PATTERN_FIXES` now matches the real construct (a grant that ends at its terminator, `REDEFINITION` permitted) and `DESCRIPTION_FIXES` carries SAP's own framing: it "does not as a rule supply any CDS roles with full access rules", so one in customer DCL is often an override of an SAP-delivered restriction. | `abencds_dcl_role_grant_rule.htm`, AS ABAP 7.55 | ✅ |
| ~~U6~~ | **SETTLED — the guard was fail-open.** The addition is `FOR USER`: "If the addition FOR USER is specified, the authorization of the user is checked whose user name is specified in `user`." A check aimed at somebody else answers nothing about the caller, and `_guarded_blocks` was crediting it — a false negative in the most security-critical rule family here. `_AUTHORITY_FOR_OTHER_USER` now excludes it. The full `sy-subrc` list is 0, 4, 12 and **40** (invalid user id, which arises only WITH `FOR USER` — so both halves of this question were one question); 24 is documented as no longer set. Recorded in `AUTHORITY_CHECK_SUBRC`, including that **0 means success OR that no check was carried out**, so `sy-subrc = 0` is not proof a check happened. | `abapauthority-check.htm`, AS ABAP 7.50 | ✅ |
| U7 | **Application-server dataset reads as a taint source** | Fits B7's existing `INTO`-target shape as a one-line addition if real. | `SAP/styleguides`, or a WebSearch restricted to SAP-published material. |
| U8 | **The ABAP-Cloud HTTP handler interface** | Would be a B2-shaped procedure-parameter seeding, no new machinery. Covered by no file in the cheat-sheet repo. | `SAP/styleguides` or SAP-published documentation other than the help portal SPA. |
| ~~U9~~ | **SETTLED — all six media are documented, so all six are in.** SAP's `IMPORT` medium syntax gives exactly `DATA BUFFER xstr`, `INTERNAL TABLE itab`, `MEMORY ID id`, `DATABASE dbtab(ar) [TO wa] [CLIENT cl] ID id`, `SHARED MEMORY ...` and `SHARED BUFFER ...`. The three excluded on structural symmetry are real, and they are the STRONGER case, not the weaker: a cluster in ABAP Memory was at least written by the same session, while SAP calls the last two "a cross-program memory area". The `IMPORT (param_table) FROM` runtime-name-table form is still left alone — U9 widened the media, not the binding forms. | `abapimport_medium.htm`, AS ABAP 7.55 | ✅ |
| ~~U10~~ | **SETTLED — four identifiers grep-confirmed and shipped with their provenance.** `/ui2/cl_json=>deserialize` and `cl_sxml_string_reader=>create` from `21_XML_JSON.md`; `DYNP_VALUES_READ` and `F4IF_INT_TABLE_VALUE_REQUEST` from `18_Dynpro.md`. They live in `RiseTaintAnalyzer.CONFIRMED_SOURCE_IDENTIFIERS`, each keyed to the file it was read from. The tier-3 guard changed shape rather than being relaxed: it used to refuse any `=>` outright, which was right while nothing was confirmed; it now requires an entry in that table, which still fails on a fabricated name **and additionally** fails on a real one added without a citation. | `21_XML_JSON.md`, `18_Dynpro.md` | ✅ |
| ~~U11~~ | **SETTLED, and it splits.** SAP lists the constructs taking a `WHERE` — `LOOP AT`, `READ TABLE`, `DELETE`, `FILTER`, `FOR` — then names which support the full option set: "`LOOP AT`, `READ TABLE` ..., `DELETE`, and `FOR` loops", including "Dynamic WHERE conditions ... within a pair of parentheses". **`FOR` is in.** **`FILTER` is out**, from the same page: its own bullet restricts it to "table key columns ... compared with single values", `=` only for hash keys, and documents no dynamic form. THE TRAP that kept this open: a `FOR` loop's STATIC condition is parenthesised as ordinary syntax (`FOR wa IN it WHERE ( comp2 = 1 )`), so `WHERE (` after a `FOR` proves nothing — the discriminator is the existing lone-operand restriction, since a bare identifier is not a valid static logical expression in ABAP. Anchored `FOR <name> IN` so `FOR ALL ENTRIES IN` cannot match. | `31_WHERE_Conditions.md` | ✅ |
| ~~U12~~ | **SETTLED — by relabelling, which is what it asked for, and the relabelling caught an overclaim.** The question was never "is this list right" but "whose list is it". The code said "the W3C and SAP entries are confirmed from SAP-authored material" and only ONE of them is: `http://www.sap.com/abapxml` appears in `21_XML_JSON.md`, while `w3.org` and `xml.sap.com` carried a *verified* marker they had not earned. Nothing was removed — the W3C and SOAP hosts genuinely are namespace authorities and dropping them would resurrect the F5 false positives. What changed is that the two classes are DATA (`_NAMESPACE_HOSTS_VERIFIED` / `_NAMESPACE_HOSTS_OURS`) rather than a comment, so a host added later must declare which it is, a verified entry must cite the file AND the namespace URI, and one of ours must give a reason. | n/a — ours, and now labelled so | ✅ |

---

## SUGGESTED SEQUENCING

**PR 1 (lexer)** — T1.1, T1.2, T1.3, T1.12. One mode-stack scanner, `text_masked`, `LITERAL_BLIND`, runaway counter, AMDP mode. Everything after this measures against a real statement stream.
**PR 2 (grading)** — T1.4, T1.7, T1.8, T1.9. Rule-aware sink extraction; anchored, call-syntax, sink-specific sanitizers.
**PR 3 (authorization)** — T1.5, T1.6, F7, plus `ABAP-AUTH-008` into `AUTHORITY_GUARDED`.
**PR 4 (taint input)** — T1.10, T1.11, then Group B in order B1→B9.
**PR 5 (narrowing)** — Tier 2 F1–F11 as `PATTERN_FIXES`/`DESCRIPTION_FIXES`/`RETIRED_RULES` entries. Cheap, high-yield, independent of PRs 1–4.
**PR 6+ (coverage)** — Group A in rank order.

Regression fixtures each PR must add: the pipe-in-`{ }` collapse (T1.1); the prose-defeats-guard pair (T1.3); `classify_sink` returning `tainted` for a variable *named* like a sanitizer (T1.7); the `_sink_argument` two-clause statement (T1.4); and the AMDP quoted-identifier body (T1.12).
