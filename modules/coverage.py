# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Upload coverage manifest.

WHY THIS IS A CORRECTNESS FIX, NOT A FEATURE
---------------------------------------------
In the offline scanner a missing export file loads as ``None`` and every check
that needs it self-skips silently. A customer who supplies 41 of the 117 logical
sources therefore gets a clean-looking report over a fraction of the estate, with
nothing anywhere saying so. That is not a gap in the feature set — it is a defect
a buyer catches in a proof of concept, and it is worse in our product than in a
connected competitor's, because they at least know which systems they reached.

The manifest answers three questions for every upload, in the customer's language:

    you supplied 41 of 117 sources
    12 modules ran degraded
    63 checks could not execute, and here is which

DERIVED, NOT DECLARED
---------------------
The module-to-source mapping is extracted from the module sources at import time
rather than kept in a hand-maintained table. A table would drift the first time
someone adds ``self.data.get("new_export")`` to a module and forgets to update it,
and a coverage manifest that silently under-reports what is missing is precisely
the failure this file exists to prevent.
"""
from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from modules.deployment_modes import is_rise

MODULES_DIR = Path(__file__).resolve().parents[1] / "modules"

_DATA_GET = re.compile(r'self\.data\.get\(\s*["\']([a-z0-9_]+)["\']')

_NOT_AN_AUDITOR = {
    "base_auditor", "data_loader", "__init__", "compliance_mapping", "fair_adapter",
    "finding_kb", "pdf_report", "pdf_writer", "pptx_report", "pptx_writer",
    "report_generator", "risk_prioritizer",
    # THIS FILE. It moved here from server/ so the offline reports could reach it,
    # and promptly discovered ITSELF as an auditor — 31 modules where there are
    # 30. A module that lists itself among the things it audits is the kind of
    # error that reads as a plausible number, which is why
    # tests/test_ecc_coverage.py now compares the list against the registry in
    # server/ingest.AUDITORS rather than against a count.
    "coverage",
    # The FAIR and framework tiers: libraries the auditors and reports call, not
    # auditors themselves. None declares a `self.data.get(...)` input, so none was
    # being listed, but naming them here means a future one that DOES read data
    # for its own purposes cannot quietly appear in a customer's coverage table.
    "crq_engine", "fair_cam", "fair_loss_model", "fair_provenance",
    "nist_csf", "deployment_modes", "platforms",
}

#: RISE scoping, from docs/RISE_SECURITY_MODEL.md section 4. In a RISE tenant the
#: customer holds the ABAP application layer and contractually loses everything
#: below it, so a module whose input is an OS artifact cannot be fed at all.
#:
#: Shipping the on-prem view into a RISE account produces a report full of
#: findings the customer cannot act on — the exact failure the research exists to
#: prevent — so the deployment mode changes what is even claimed to be assessed.
#:
#: "split" means the module has BOTH reachable and unreachable components and
#: must never blend them into one finding.
RISE_MODULE_SCOPE: Dict[str, str] = {
    "user_auth_audit": "in_scope",
    "atc_import": "in_scope",       # custom ABAP is contractually 100% customer
    "abap_sast": "in_scope",        # ditto; input is an abapGit export
    "security_params": "read_only",       # readable; fixable only by SAP
    "network_services": "split",
    "rise_btp_checks": "in_scope",
    "iam_advanced": "in_scope",
    "btp_cloud_surface": "in_scope",      # the only end-to-end automatable module
    "integration_layer": "split",         # gateway ACL *files* are OS artifacts
    "data_protection": "in_scope",
    "code_inventory_report": "in_scope",   # the custom code is the customer's own
    "resilience_posture": "in_scope",      # customer produces the backup/DR evidence
    "snc_posture": "split",           # SNC profile params are SAP-operated in PCE
    "ecs_config_items": "split",      # client/table settings split customer vs SAP
    "code_transport": "split",            # SE06/SCC4 are ticket-to-SAP
    "log_monitoring": "in_scope",
    # A retrospective review reads an export the customer produces themselves from
    # the ABAP application layer, which they keep in RISE.
    "log_review": "in_scope",
    "fiori_ui": "in_scope",
    "crypto_posture": "partial",
    "hana_db_security": "mostly_out",
    "sap_hotnews": "in_scope",            # identify; the fix is a ticket
    "abap_authorizations": "in_scope",
    "system_trust": "split",              # ms_acl + saprouttab are OS-level
    "grc_access_control": "conditional",  # only if the customer owns GRC
    "role_governance": "in_scope",
    "financial_controls": "in_scope",
    "baseline_params": "read_only",
    "s4_business_authz": "in_scope",
    "access_risk_analysis": "in_scope",
    "basis_job_command": "in_scope",
}

#: The CLI's `--modules` vocabulary, mapped to the module file names this file
#: keys on.
#:
#: THE BUG THIS CLOSES, WHICH RAN IN EVERY OFFLINE REPORT.
#: `sap_scanner.py` names its modules "users", "params", "authz"; the manifest
#: names them "user_auth_audit", "security_params", "abap_authorizations". It
#: passed the former into `modules_run=`, every name failed the `mod not in ran`
#: test, and ALL THIRTY modules were stamped `not_run` — in a report carrying 341
#: findings produced by those very modules. It hid because the four summary cards
#: count `modules_skipped` and not `modules_not_run`, so only the table underneath
#: said it, thirty times, in a column nobody reads when the cards look fine.
#:
#: A mismatch of vocabularies cannot be caught by reading either side. So
#: `build_manifest` REFUSES a `modules_run` list that names nothing it knows,
#: rather than reporting a total blackout it would produce identically if the run
#: really had done nothing — and tests/test_coverage_cli_names.py re-derives this
#: table from sap_scanner.py's own dispatch so it cannot go stale in silence.
CLI_MODULE_ALIASES: Dict[str, str] = {
    "users": "user_auth_audit",
    "params": "security_params",
    "network": "network_services",
    "rise": "rise_btp_checks",
    "iam": "iam_advanced",
    "btpcloud": "btp_cloud_surface",
    "intglayer": "integration_layer",
    "dataprot": "data_protection",
    "snc": "snc_posture",
    "ecsconfig": "ecs_config_items",
    "codeinv": "code_inventory_report",
    "resilience": "resilience_posture",
    "codetrans": "code_transport",
    "atc": "atc_import",
    "cva": "abap_sast",
    "logmon": "log_monitoring",
    "logreview": "log_review",
    "fiori": "fiori_ui",
    "crypto": "crypto_posture",
    "hanadb": "hana_db_security",
    "hotnews": "sap_hotnews",
    "authz": "abap_authorizations",
    "systrust": "system_trust",
    "baseline": "baseline_params",
    "s4authz": "s4_business_authz",
    "ara": "access_risk_analysis",
    "jobcmd": "basis_job_command",
    "grcac": "grc_access_control",
    "rolegov": "role_governance",
    "fincontrols": "financial_controls",
}

#: Logical sources a RISE customer cannot produce, because they are read from the
#: operating system and RISE customers contractually never get OS access. Listing
#: them as "missing" would be dishonest — the customer did not forget them, they
#: are structurally out of reach.
RISE_UNREACHABLE_SOURCES: Set[str] = {
    "ms_acl", "saprouttab", "gw_secinfo", "gw_reginfo", "ext_os_commands_sap",
}


def _sources_via_helper(src: str) -> Set[str]:
    """Logical sources reached through an accessor rather than read directly.

    WHY THIS EXISTS. The regex above only sees `self.data.get("literal")`. Four
    real auditors do not write it that way:

        user_auth_audit    self.data.get(key)          # a helper's parameter
        ecs_config_items   self.data.get(key)          # likewise
        code_inventory_report  (self.data or {}).get("code_inventory")
        abap_sast          self.data.get(self.SOURCE_KEY)   # a class constant

    All four therefore had NO entry in the manifest at all — not "unknown", not
    "skipped", simply absent — so a coverage report that exists to say what was
    and was not covered said nothing whatsoever about the module that audits
    users, profiles and roles. Found by the Phase 1 ECC measurement.

    The approach: find methods whose body reads `self.data.get(<own parameter>)`,
    then collect the string literals passed to those methods. That is precise —
    it will not absorb an unrelated literal that merely happens to match a source
    name, which would over-report requirements and make clean modules look
    degraded.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()

    accessors: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in node.args.args[1:]}
        if not params:
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "get"
                    and inner.args
                    and isinstance(inner.args[0], ast.Name)
                    and inner.args[0].id in params):
                accessors.add(node.name)
                break

    found: Set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in accessors
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            found.add(node.args[0].value)

    # `(self.data or {}).get("literal")` and `self.data.get(self.CONST)`.
    found |= set(re.findall(r'self\.data\s*or\s*\{\}\)\.get\(\s*["\']([a-z0-9_]+)["\']',
                            src))
    for const in re.findall(r'self\.data\.get\(\s*self\.([A-Z_][A-Z0-9_]*)\s*\)', src):
        m = re.search(rf'^\s*{const}\s*[:=][^=]*?["\']([a-z0-9_]+)["\']', src, re.M)
        if m:
            found.add(m.group(1))
    return found


@lru_cache(maxsize=1)
def module_sources() -> Dict[str, List[str]]:
    """Map auditor module name -> the logical data sources it reads.

    A module that reads NOTHING is reported with an empty list rather than being
    left out of the mapping. Omission and "reads nothing" are different facts,
    and `build_manifest` needs to be able to tell them apart in order to say so.
    """
    out: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "BaseAuditor" not in src:
            continue                      # a helper module, not an auditor
        tree = ast.parse(src, str(path))
        keys = set(_DATA_GET.findall(src)) | _sources_via_helper(src)
        # FILTERED AGAINST WHAT THE LOADER ACTUALLY KNOWS, and this is not
        # belt-and-braces. The accessor analysis collects literals passed to a
        # data-reading helper, and `user_auth_audit` passes "DDIC" — a standard
        # SAP user name — to one of them. Unfiltered, that became a required
        # "source" the customer could never supply, so the module would have read
        # as permanently degraded. Over-reporting requirements is the more
        # dangerous direction of error: it manufactures coverage gaps that are not
        # real, and a manifest that cries wolf gets ignored.
        keys &= set(all_logical_sources())
        # AND THE INPUTS THAT ARE NOT FILES. `abap_sast` reads an unpacked
        # abapGit DIRECTORY named by --abap-src, through a class attribute:
        #
        #     SOURCE_KEY = "abap_source_dir"
        #     root = self.data.get(self.SOURCE_KEY)
        #
        # The literal scan above cannot see `self.data.get(<variable>)`, and the
        # key is not one of DataLoader's file sources, so it was filtered out
        # twice over. The module therefore declared NO inputs at all, came back
        # `no_file_inputs` on every run, and counted as having looked — so
        # Custom Code Security could never report NOT_SUPPLIED and the resolution
        # guard could never withhold one of its findings. 133 rules' worth of
        # coverage was structurally invisible to the honesty machinery, while the
        # module's own docstring said "the coverage manifest states the absence".
        keys |= _source_key_attributes(tree)
        out[path.stem] = sorted(keys)
    return out


def _source_key_attributes(tree: ast.AST) -> Set[str]:
    """Logical inputs declared as `SOURCE_KEY = "..."` on the auditor class.

    Kept OUT of `all_logical_sources()` deliberately: that set is the denominator
    a customer is measured against ("106 of 123 sources supplied"), and a
    directory nobody was asked to supply does not belong in it. It is an input
    for the purpose of deciding whether a module looked, and not a file the
    customer forgot.
    """
    found: Set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and any(isinstance(x, ast.Name) and x.id == "SOURCE_KEY"
                        for x in node.targets)):
            found.add(node.value.value)
    return found


def all_logical_sources() -> List[str]:
    from modules.data_loader import DataLoader
    return sorted(DataLoader.FILE_MAP)


@lru_cache(maxsize=1)
def module_categories() -> Dict[str, List[str]]:
    """{module file name: the finding categories it can produce}, from the code.

    DERIVED FOR THE SAME REASON `module_sources` IS. The consumer is
    modules/domains.py, which has to answer "did anything that could have found
    something in this domain actually run?" — and the difference between "we
    looked and found nothing" and "the export never arrived" is the whole point
    of that question. A hand-written domain-to-module table would answer it
    confidently and wrongly the first time somebody moved a check.

    Two spellings, because the modules use two. Most pass a literal
    `category="Fiori & UI Layer"`; fifteen carry a class attribute `CATEGORY` and
    pass `category=self.CATEGORY`, which is invisible to a scan for literals —
    the first version of this function missed exactly those fifteen, including
    `log_review`, whose domain is the one most likely to be read as a monitoring
    result if it were wrongly marked clean.
    """
    out: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        src = path.read_text(encoding="utf-8")
        # The SAME guard `module_sources` uses, and it is load-bearing rather
        # than tidy: without it a rule table or a roll-up module joins the list
        # of things a customer is told did not run. modules/coverage.py once
        # listed ITSELF as an auditor for want of a filter.
        if "BaseAuditor" not in src:
            continue
        tree = ast.parse(src, str(path))
        found: Set[str] = set()
        found |= _declared_categories(tree)
        out[path.stem] = sorted(found)
    return out


def _declared_categories(tree: ast.AST) -> Set[str]:
    """Every finding category a module declares, in all THREE spellings it uses.

    THE THIRD ONE COST 7% OF A RUN. The first version read `category="..."`
    keyword arguments and the `CATEGORY = "..."` class attribute, and missed
    `modules/security_params.py` entirely — it carries category names as VALUES
    inside a parameter table:

        "gw/acl_mode": {"severity": "HIGH", "category": "Gateway Security", ...}

    Ten of its categories went unclaimed and six could be tied to no module at
    all, so `modules_for_categories()` returned an empty set for Password Policy,
    Login Security, RFC Security, Gateway Security, Transport Security and
    Development Controls. Every consumer reads an empty set as "assume it ran",
    which is the safe default for an unknown and a silent failure for a known:
    twenty-four findings could never be NOT_SUPPLIED and were resolved by runs
    that had not looked at them.

    A heuristic over source text can only see the spellings it anticipates, so
    tests/test_derivations_match_the_corpus.py holds this function to what the
    auditors actually emit rather than to what it thinks they might.
    """
    found: Set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.keyword) and node.arg == "category"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            found.add(node.value.value)
        elif (isinstance(node, ast.Assign)
              and isinstance(node.value, ast.Constant)
              and isinstance(node.value.value, str)
              and any(isinstance(t, ast.Name) and t.id == "CATEGORY"
                      for t in node.targets)):
            found.add(node.value.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "category"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)):
                    found.add(value.value)
    return found


@lru_cache(maxsize=1)
def check_catalogue() -> Dict[str, str]:
    """{check id: finding category}, for every check written as a literal.

    WHY A THIRD DERIVATION AND NOT A FOURTH TABLE. `module_categories` answers
    "what can this module produce" and `module_check_ids` answers "what ids does
    it write"; neither can say which of a module's categories a given id belongs
    to, and several modules emit more than one. A per-category DENOMINATOR needs
    exactly that pairing — how many checks exist in this category, including the
    ones that have never failed.

    Paired within a single call, which is what makes it precise: `check_id=` and
    `category=` are keyword arguments of the same `finding(...)` call, so they
    are read off the same AST node rather than correlated by position. A call
    passing `category=self.CATEGORY` is resolved through the class attribute, the
    spelling fifteen modules use.

    RUNTIME FAMILIES ARE HERE NOW, AND THE FLOOR IS GONE. They were excluded
    because their ids are composed rather than written, so the AST pairing above
    finds nothing — which left every consumer of this map computing a
    per-category denominator against 365 checks when 620 ran. That is the same
    defect modules/posture_score.py had: a denominator that only counts what it
    can see is not a denominator, and in a per-category pass rate it makes the
    thinly-covered categories look best.

    `runtime_check_families` now carries a category per id, derived from the
    emit site rather than declared here, so the two halves of this map are built
    the same way: pair the id with the category the same call passes.
    """
    out: Dict[str, str] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        src = path.read_text(encoding="utf-8")
        if "BaseAuditor" not in src:
            continue
        tree = ast.parse(src, str(path))
        class_category: Optional[str] = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and any(isinstance(x, ast.Name) and x.id == "CATEGORY"
                            for x in node.targets)):
                class_category = node.value.value
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kwargs = {k.arg: k.value for k in node.keywords if k.arg}
            cid_node, cat_node = kwargs.get("check_id"), kwargs.get("category")
            if not (isinstance(cid_node, ast.Constant)
                    and isinstance(cid_node.value, str)):
                continue
            if isinstance(cat_node, ast.Constant) and isinstance(cat_node.value, str):
                out[cid_node.value] = cat_node.value
            elif (isinstance(cat_node, ast.Attribute)
                  and cat_node.attr == "CATEGORY" and class_category):
                out[cid_node.value] = class_category
        # A dict literal carrying both keys is the third spelling — see
        # _declared_categories. Paired inside ONE dict for the same reason the
        # keyword form is paired inside one Call: correlating them any other way
        # would guess.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            pairs = {k.value: v for k, v in zip(node.keys, node.values)
                     if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            cid_node, cat_node = pairs.get("check_id"), pairs.get("category")
            if (isinstance(cid_node, ast.Constant) and isinstance(cid_node.value, str)
                    and isinstance(cat_node, ast.Constant)
                    and isinstance(cat_node.value, str)):
                out.setdefault(cid_node.value, cat_node.value)

    for family in runtime_check_families():
        for cid, category in family.get("categories", {}).items():
            out.setdefault(cid, category)

    # AND THE IDS PASSED POSITIONALLY, which neither reader above can pair.
    #
    # `_emit("AUTH-001", title, severity, …)` writes the id as an argument with
    # no keyword, so there is no `category=` beside it to pair with — the
    # category is applied inside the wrapper, one call further down. That left 31
    # ids uncategorised: the whole AUTH- and BASELINE- sets and three coverage
    # checks.
    #
    # Every one of those modules emits exactly ONE category, which is the
    # wrapper's own, so the attribution is not a guess. Where a module emits more
    # than one it is left out rather than assigned the more common of them: a
    # wrong category is worse than a missing one, because it moves a finding into
    # a denominator it does not belong to and nothing looks broken.
    emitted = runtime_emit_categories()
    for module, ids in all_check_ids().items():
        cats = emitted.get(module) or set()
        if len(cats) != 1:
            continue
        only = next(iter(cats))
        for cid in ids:
            out.setdefault(cid, only)
    return out


@lru_cache(maxsize=1)
def module_check_ids() -> Dict[str, List[str]]:
    """{module file name: the check ids written as literals in it}.

    A COARSER QUESTION THAN docs/CHECKS_REFERENCE.md ANSWERS, on purpose. That
    generator resolves wrapper signatures and positional arguments to enumerate
    every check for a reader; this only needs enough to tell which modules can
    produce a check id with a given PREFIX, because two of the twelve domains
    share a category with a sibling and are separated only by prefix.

    Ids built at runtime from rule tables are not literals and are not here. The
    consumer treats a module with no matching literal as "cannot feed this
    domain", so a missed id costs a NOT_SUPPLIED where CLEAR was right —
    over-caution about what we saw, which is the safe direction for this file.
    """
    out: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        src = path.read_text(encoding="utf-8")
        if "BaseAuditor" not in src:
            continue
        tree = ast.parse(src, str(path))
        found: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "check_id":
                value = _const_str(node.value)
                if value:
                    found.add(value)
        out[path.stem] = sorted(found)
    return out


def _const_str(node: Any) -> Optional[str]:
    """The string a node evaluates to, if that is knowable without running it.

    `ast.Constant` is the obvious case. The other is an f-string carrying no
    placeholders — `f"CODE-STMT-001"` — which is a plain string to every reader
    except a parser, where it is a `JoinedStr` and matches nothing. That one
    stray `f` hid a check id from the coverage derivation, the score denominator
    and the generated reference simultaneously, and nothing reported a problem
    because every consumer treats an id it cannot see as an id that does not
    exist.

    An f-string with real placeholders returns None: its value is not knowable
    here, and guessing would put a template where an id belongs.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values and all(
            isinstance(v, ast.Constant) and isinstance(v.value, str)
            for v in node.values):
        return "".join(v.value for v in node.values)
    return None


#: The methods that RAISE a finding. `finding(...)` is BaseAuditor's; the rest
#: are per-module wrappers that forward to it.
EMITTERS = {"finding", "_emit", "_flag", "_coverage_finding",
            "_finding_for_unset_parameter"}


@lru_cache(maxsize=1)
def wrapper_signatures() -> Dict[str, List[str]]:
    """Positional parameter names for each emitter, READ FROM ITS OWN `def`.

    The wrappers forward positionally — `_emit("AUTH-001", "title", SEVERITY, …)`
    — so a keyword-only reader finds nothing at all. That is how 28 check ids
    that a real scan emits every time, the whole `AUTH-` and `BASELINE-` sets,
    were invisible to `module_check_ids`.

    Derived rather than hardcoded because a hardcoded order is a second copy of
    the signature, and the day somebody inserts a parameter the reader silently
    starts collecting the title as the check id. Read the def, and it cannot
    drift.

    Shared with tools/build_checks_reference.py, which had this first and is now
    the consumer: two readers of the same signatures could disagree, and the one
    that documents the product disagreeing with the one that scores it is a
    particularly bad pair to let drift.
    """
    sigs: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in EMITTERS:
                continue
            names = [a.arg for a in node.args.args if a.arg != "self"]
            if names and node.name not in sigs:
                sigs[node.name] = names
    return sigs


@lru_cache(maxsize=1)
def positional_check_ids() -> Dict[str, List[str]]:
    """{module: check ids passed POSITIONALLY to an emitter}.

    The other half of `module_check_ids`, which reads `check_id=` keywords only.
    Neither is complete on its own; `all_check_ids` is the union.
    """
    sigs = wrapper_signatures()
    out: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        src = path.read_text(encoding="utf-8")
        if "BaseAuditor" not in src:
            continue
        found: Set[str] = set()
        for node in ast.walk(ast.parse(src, str(path))):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            fn = (node.func.attr if isinstance(node.func, ast.Attribute)
                  else getattr(node.func, "id", None))
            names = sigs.get(fn or "")
            if not names or names[0] != "check_id":
                continue
            value = _const_str(node.args[0])
            if value:
                found.add(value)
        if found:
            out[path.stem] = sorted(found)
    return out


@lru_cache(maxsize=1)
def runtime_emit_categories() -> Dict[str, Set[str]]:
    """{module: the categories it uses when the check id is COMPOSED}.

    `check_catalogue` pairs a check id with a category inside one call, and skips
    the call when the id is not a constant it can read. Every runtime family is
    exactly that call: `check_id=f"ARA-{rid}"`, `check_id=lead["rule_id"]`. The
    id cannot be read statically; the CATEGORY beside it usually can, and it is
    the same literal for every id the family produces.

    So the rule is the mirror of the one above it: a call whose check id is not
    resolvable and whose category is, is a runtime family's emit site, and that
    category belongs to every id in the family.

    DERIVED RATHER THAN DECLARED, because a per-family table here would be a
    second copy of a decision the emit site already makes, and it would go stale
    silently — a category is a string a person renames.
    """
    out: Dict[str, Set[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        src = path.read_text(encoding="utf-8")
        if "BaseAuditor" not in src:
            continue
        tree = ast.parse(src, str(path))
        class_category = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and any(isinstance(x, ast.Name) and x.id == "CATEGORY"
                            for x in node.targets)):
                class_category = node.value.value
        found: Set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kwargs = {k.arg: k.value for k in node.keywords if k.arg}
            if "check_id" not in kwargs or "category" not in kwargs:
                continue
            if _const_str(kwargs["check_id"]) is not None:
                continue                      # a literal id — the other reader has it
            cat = kwargs["category"]
            if isinstance(cat, ast.Constant) and isinstance(cat.value, str):
                found.add(cat.value)
            elif (isinstance(cat, ast.Attribute) and cat.attr == "CATEGORY"
                  and class_category):
                found.add(class_category)
        if found:
            out[path.stem] = found
    return out


def runtime_check_families() -> List[Dict[str, Any]]:
    """The check ids built at RUNTIME from shipped rule tables, per module.

    WHY THIS EXISTS AT ALL. Every other derivation in this file reads the source
    with `ast`, because the source is the authority and parsing it cannot be
    fooled by a stale table. These five families cannot be read that way: the ids
    do not appear as literals anywhere, they are composed from rows of a table
    (`PARAM-` + a parameter name, `ABAP-` + a rule id). AST parsing sees nothing,
    which is why `module_check_ids` has always been a floor about 255 ids short.

    RESOLVED BY IMPORTING THE TABLES, NOT BY PARSING THEM, for the same reason
    the reference generator does it that way: the table is the authority, and a
    second reading of it could disagree with the first.

    WHAT THE SHORTFALL COST. A denominator that cannot see a check until the
    check FAILS is not a denominator, it is a tally of failures. It made
    `posture_score` fall when a scan discovered more problems — 120 new LOW
    findings moved sample_data from 38 to 29 with nothing remediated — because an
    unseen id joined the denominator only on failure, diluting a mean it had not
    previously been part of. It also left `domains.py` unable to attribute a
    runtime finding to the module that raised it.

    NO try/except HERE, DELIBERATELY. This is the third time that rule is written
    down in this codebase and the reason has not changed: the reference
    generator's first version wrapped these imports, guessed two class names
    wrong, and silently shipped a catalogue missing 37 ids while printing a
    success line. A family that cannot be resolved must break the run. Silence
    here would restore precisely the undercount this function exists to end.
    """
    from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,
                                   ALL_JS_RULES)
    from modules.access_risk_analysis import AccessRiskAnalysisAuditor
    from modules.atc_import import AtcImportAuditor
    from modules.iam_advanced import AdvancedIamAuditor
    from modules.security_params import SecurityParamAuditor

    def _ids(table: Any, key: str, prefix: str = "") -> List[str]:
        """The ids as the AUDITOR EMITS THEM, prefix and all.

        The tables hold bare keys — `BASIS-01`, `AUTHCHK` — while the auditors
        raise `ARA-BASIS-01` and `ATC-AUTHCHK` (access_risk_analysis.py:846,
        atc_import.py:238, iam_advanced.py:490). Enumerating the bare keys would
        fill the denominator with ids no finding can ever match: the count would
        look right and every one of them would be a check that could never be
        observed to pass or fail. `abap_sast` is the exception whose table
        already carries the `ABAP-` prefix, so it takes no second one.
        """
        rows = table.values() if isinstance(table, dict) else table
        out = []
        for row in rows:
            value = row.get(key) if isinstance(row, dict) else row
            if value:
                out.append(prefix + str(value))
        return out

    params = SecurityParamAuditor({}, {}).effective_rules()
    families: List[Dict[str, Any]] = [
        {
            "module": "security_params",
            "pattern": "PARAM-<parameter name>",
            "ids": sorted("PARAM-" + name for name in params),
            "source": "modules/security_params.py — BASELINE + ECS_RULES",
            "note": "One id per judged profile parameter. `PARAM-000`, "
                    "`PARAM-MISSING` and `PARAM-MISSING-OTHER` are fixed ids and "
                    "appear in the literal table.",
        },
        {
            # THREE TABLES, NOT ONE. The JavaScript and BTP-descriptor rules emit
            # into the SAME `ABAP-` namespace as the ABAP/UI5 set. Reading only
            # the first undercounted the catalogue by 15, invisibly, because 118
            # is a plausible-looking number.
            "module": "abap_sast",
            "pattern": "ABAP-<rule id>",
            "ids": sorted(set(_ids(ALL_ABAP_SAST_RULES, "id")
                              + _ids(ALL_JS_RULES, "id")
                              + _ids(ALL_BTP_CONFIG_RULES, "id"))),
            "source": ("modules/abap_sast.py — ALL_ABAP_SAST_RULES (%d) + "
                       "ALL_JS_RULES (%d) + ALL_BTP_CONFIG_RULES (%d)"
                       % (len(ALL_ABAP_SAST_RULES), len(ALL_JS_RULES),
                          len(ALL_BTP_CONFIG_RULES))),
            "note": "Custom-code scan rules. All three tables emit into the same "
                    "`ABAP-` namespace: ABAP/UI5, JavaScript, and BTP descriptors.",
        },
        {
            "module": "access_risk_analysis",
            "pattern": "ARA-<risk id>",
            "ids": sorted(set(_ids(AccessRiskAnalysisAuditor.RULESET,
                                   "risk_id", "ARA-"))),
            "source": "modules/access_risk_analysis.py — RULESET",
            "note": "Segregation-of-duties and critical-access risks, extendable "
                    "by a customer's own `ara_ruleset.json`.",
        },
        {
            "module": "atc_import",
            "pattern": "ATC-<family>",
            "ids": sorted(set(_ids(AtcImportAuditor.FAMILIES,
                                   "family", "ATC-"))),
            "source": "modules/atc_import.py — FAMILIES",
            "note": "ABAP Test Cockpit finding families, imported from an ATC "
                    "export.",
        },
        {
            "module": "iam_advanced",
            "pattern": "IAM-<sod rule>",
            "ids": sorted(set(_ids(AdvancedIamAuditor.DEFAULT_SOD_RULES,
                                   "rule_id", "IAM-"))),
            "source": "modules/iam_advanced.py — DEFAULT_SOD_RULES",
            "note": "Conflicting-duty pairs.",
        },
    ]

    empty = [f["pattern"] for f in families if not f["ids"]]
    if empty:
        raise RuntimeError(
            "runtime check families resolved to zero entries: %s. A family with "
            "no members is a broken table reference, not an empty table — fix "
            "the source rather than carrying on without it." % (empty,))

    # A CATEGORY FOR EVERY ID, so check_catalogue can answer for these too.
    #
    # security_params is the one family whose category VARIES per id — it passes
    # `category=rule["category"]`, one per profile parameter — so it comes from
    # the same table the ids do. The other four pass a literal at the emit site,
    # which runtime_emit_categories reads.
    #
    # NOT FROM THE RULE ROW'S OWN `category` FIELD, for abap_sast. That table has
    # one, and it is a DIFFERENT TAXONOMY: "SQL Injection", "Cross-Site
    # Scripting", "Directory Traversal" — a classification of the weakness, not
    # of the finding. Taking it would have injected twelve categories that no
    # finding carries and no domain maps, and it looks exactly like the right
    # field to use. The emit site says "Code & Transport Security", and the emit
    # site is what the finding will actually carry.
    emitted = runtime_emit_categories()
    for family in families:
        module = family["module"]
        if module == "security_params":
            family["categories"] = {
                "PARAM-" + name: rule.get("category")
                for name, rule in params.items()
                if isinstance(rule, dict) and rule.get("category")}
        else:
            cats = emitted.get(module) or set()
            if len(cats) != 1:
                raise RuntimeError(
                    "cannot attribute a finding category to %s: its composed "
                    "check ids are emitted with %s. One family, one category — "
                    "name it at the emit site rather than leaving this to guess."
                    % (family["pattern"], sorted(cats) or "no readable category"))
            only = next(iter(cats))
            family["categories"] = {cid: only for cid in family["ids"]}
    return families


@lru_cache(maxsize=1)
def all_check_ids() -> Dict[str, List[str]]:
    """{module file name: every check id it can raise}, literals AND runtime.

    The complete answer, where `module_check_ids` is the cheap floor. Use this
    wherever the count is a DENOMINATOR — a denominator that grows only when a
    check fails is not measuring what it claims to. `module_check_ids` remains
    the right call for questions about the source text itself.

    Three sources, because a check id is written three different ways:
      * `check_id="X"` as a keyword          -> module_check_ids
      * `_emit("X", ...)` positionally       -> positional_check_ids
      * composed from a rule table at runtime -> runtime_check_families

    Missing any one of them produces the same failure in a different disguise: a
    check the denominator cannot see until it fails, which makes discovering a
    problem look like an improvement.
    """
    out = {name: set(ids) for name, ids in module_check_ids().items()}
    for name, ids in positional_check_ids().items():
        out.setdefault(name, set()).update(ids)
    for family in runtime_check_families():
        out.setdefault(family["module"], set()).update(family["ids"])
    return {name: sorted(ids) for name, ids in out.items()}


#: Module statuses that mean the module ACTUALLY RAN, best first.
#:
#: Ordered because `merge_manifests` has to pick one status per module across
#: several runs, and the order is the answer to "how much did we see". Anything
#: not listed here — `skipped`, `not_run` — means we did not look, and a domain
#: fed only by such modules must report NOT_SUPPLIED rather than CLEAR.
RAN_STATUSES = ("complete", "degraded", "no_file_inputs")

_STATUS_RANK = {name: i for i, name in enumerate(RAN_STATUSES)}


def ran_modules(manifest: Optional[Dict[str, Any]],
                require_complete: bool = False) -> Optional[Set[str]]:
    """The modules that actually executed, or None when we cannot tell.

    None is not an empty set and the difference is the whole point: an empty set
    means nothing ran, None means nobody checked. A caller that receives None must
    not report anything as unsupplied — claiming an export was missing without
    having looked is the same class of error as claiming it was clean.

    `require_complete` asks the STRICTER question: did this module see all of its
    input? A `degraded` module ran on part of what it needed, and whether that
    counts as "looked" depends entirely on what the caller does with the answer —
    see look_verdict, which is where the two readings are argued and where each
    caller chooses.
    """
    if not manifest or not isinstance(manifest.get("modules"), dict):
        return None
    return {
        name for name, info in manifest["modules"].items()
        if isinstance(info, dict) and info.get("status") in RAN_STATUSES
        and not (require_complete and info.get("sources_missing"))
    }


#: The three answers to "did anything that feeds this actually look?".
#:
#: LOOKED and NOT_SUPPLIED are proofs. UNKNOWN is the absence of one, and it is a
#: THIRD answer rather than a synonym for either — which is the whole reason this
#: function exists.
LOOKED = "looked"
UNSUPPLIED = "not_supplied"
UNKNOWN = "unknown"


def look_verdict(feeders: Set[str], manifest: Optional[Dict[str, Any]],
                 require_complete: bool = False) -> str:
    """Whether anything that can produce a thing actually ran, in one place.

    WHY THIS IS ONE FUNCTION AND NOT FIVE COPIES.

    `bool(feeders & ran)` was written out five times — modules/domains.py,
    modules/nist_csf.py, modules/fair_cam.py, server/ingest.py and
    server/analytics.py — and the five had already drifted apart on the case
    where `manifest` is None. One of them defaulted that to "assessed", divided a
    code-derived denominator by itself over an empty database, and published 28
    security categories at 100% compliant on a fresh install. The predicate is
    the product's central honesty rule; it should be one auditable site rather
    than a convention five files agree to follow.

    THE THREE ANSWERS ARE NOT TWO. A caller that collapses UNKNOWN into either
    proof is making a claim it cannot support:

      LOOKED       a module that feeds this ran. Report what was found.
      UNSUPPLIED   we know which modules feed this and NONE of them ran. This is
                   the only answer that authorises "the export never arrived".
      UNKNOWN      no manifest, or nothing ties this to a module. We cannot prove
                   a look and we cannot prove its absence.

    A `degraded` MODULE IS THE SECOND PLACE THE CALLERS DIVERGE, and it is the
    same shape of decision. Such a module ran on part of its input:

      * the CLAIM side — the domain tiles, the CSF Categories, the FAIR-CAM
        control functions — passes `require_complete=True`, because those three
        publish the sentence "we looked and found nothing". Drop
        security_audit_log.csv from an otherwise full upload and `log_review`
        comes back degraded; it is the sole feeder of Suspicious User Behaviour,
        and that domain rendered CLEAR about a log nobody supplied. A false
        reassurance is the one error a customer acts on.

      * the CONSEQUENCE side — the resolution guard and the release gate — does
        not, and deliberately. A complete sample_data run has ELEVEN degraded
        modules, so the strict rule there would freeze most of the backlog open
        and return cannot_assess on nearly every realistic upload. A gate that
        always blocks gets switched off wholesale, taking the real signal with
        it, and a resolution that never fires deletes the mitigation journey.

      * the PASS RATE keeps the loose rule too: it is a proportion that degrades
        gracefully rather than a binary reassurance, and marking most categories
        unassessed would empty the screen without making it more honest.

    Neither reading is the "correct" one. The costs are asymmetric in opposite
    directions, and the asymmetry is the argument.

    Callers differ on what UNKNOWN means for them, legitimately, and each states
    its choice at the call site:

      * the finding-facing roll-ups (domains, CSF, FAIR-CAM, the resolution
        guard) treat UNKNOWN as LOOKED, because claiming an export was missing
        without having checked tells a customer they forgot something they did
        send;
      * server/analytics.py's pass rate treats UNKNOWN as "no rate", because its
        denominator comes from the code and dividing it by itself asserts a
        perfect score over a system nobody scanned.

    Both are right for their screen. Neither may be inferred from the other,
    which is why this returns three values and not a bool.
    """
    ran = ran_modules(manifest, require_complete=require_complete)
    if ran is None:
        return UNKNOWN
    if not feeders:
        # Nothing ties this to a module. tests/test_derivations_match_the_corpus.py
        # makes that impossible for a category any auditor actually emits, so it
        # now means "genuinely outside the product" rather than "the derivation
        # has a hole" — but it is still not a proof of absence.
        return UNKNOWN
    return LOOKED if (feeders & ran) else UNSUPPLIED


def modules_for_categories(categories: Iterable[str]) -> Set[str]:
    """Which auditor modules can produce a finding in any of these categories.

    THE ONE DERIVATION, for every roll-up that needs it. nist_csf, fair_cam and
    domains each have to answer "did anything that could have found something
    here actually run?", and three copies of that question is three chances for
    one of them to keep saying CLEAR. Derived from the code (`module_categories`)
    rather than declared, for the reason that function already argues.

    modules/domains.py deliberately does NOT use this for its prefix-split
    domains: two of the twelve share a finding category with a sibling and are
    separated only by check-id prefix, so category alone over-attributes there.
    Everything else — the CSF Categories, the FAIR-CAM control functions — maps
    at category granularity and this is the right resolution for them.
    """
    wanted = set(categories)
    if not wanted:
        return set()
    return {mod for mod, cats in module_categories().items() if wanted & set(cats)}


def merge_manifests(manifests: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Fold several runs' manifests into one, taking the BEST status per module.

    WHY A UNION, AND WHY THAT IS THE CONSERVATIVE DIRECTION
    The console rolls findings up across every system a reader can see, not one
    run — so the question "was this domain's export supplied?" has to be answered
    over the same set. A module counts as having run if it ran for ANY system in
    scope, because a finding from any of those systems can land in the domain.

    The opposite rule (intersection) would report NOT_SUPPLIED for a domain that
    was assessed perfectly well on four systems out of five, which tells a
    customer they forgot an export they did send. Both directions of error are
    lies; this one is the smaller and the recoverable one, since the per-run
    coverage page still shows the gap system by system.

    Returns None for an empty sequence: with nothing to read we cannot say an
    export was missing, and claiming so unchecked is the same class of error as
    claiming it was clean.
    """
    modules: Dict[str, Dict[str, Any]] = {}
    merged = 0
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        entries = manifest.get("modules")
        if not isinstance(entries, dict):
            continue
        merged += 1
        for name, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            current = modules.get(name)
            if current is None or _rank(entry) < _rank(current):
                modules[name] = entry
    if not merged:
        return None
    # The run count travels with the merge because the result describes several
    # scans and no longer answers "which system was this?" — a reader (or a future
    # caller) must not mistake it for one run's manifest.
    return {"modules": modules, "merged_run_count": merged}


def _rank(entry: Dict[str, Any]) -> int:
    """Lower is better. Anything that did not run sorts behind everything that did."""
    return _STATUS_RANK.get(entry.get("status"), len(RAN_STATUSES))


def build_manifest(data: Dict[str, Any],
                   modules_run: Optional[Iterable[str]] = None,
                   deployment_mode: str = "on_prem",
                   unrecognised_files: Optional[Iterable[str]] = None
                   ) -> Dict[str, Any]:
    """Build the coverage manifest for one scan run.

    `data` is the DataLoader output — logical name -> rows, or None when the file
    was absent.

    `unrecognised_files` are files that were in the export directory and matched
    no name the loader knows. They belong here rather than only in the console
    output, because "you did not supply it" and "you supplied it under a name we
    do not read" lead to different actions and this manifest is the one record
    that reaches every artefact.
    """
    unrecognised_names = sorted(unrecognised_files or ())
    known = all_logical_sources()
    supplied = sorted(k for k in known if data.get(k))
    # A file that was present but parsed to zero rows is NOT the same as an absent
    # file, and conflating them hides a broken export behind "you didn't send it".
    empty = sorted(k for k in known if data.get(k) is not None and not data.get(k))
    absent = sorted(k for k in known if data.get(k) is None)

    rise = is_rise(deployment_mode)
    unreachable = sorted(RISE_UNREACHABLE_SOURCES & set(absent)) if rise else []
    missing = [k for k in absent if k not in set(unreachable)]

    supplied_set = set(supplied)
    # A non-file input counts as supplied when it is present in `data` at all —
    # sap_scanner.py puts --abap-src there under the module's own SOURCE_KEY.
    # These deliberately do NOT join `known`, so the "N of 123 sources" figure a
    # customer is measured against does not move.
    non_file = {s for keys in module_sources().values() for s in keys
                if s not in set(known)}
    supplied_set |= {s for s in non_file if data.get(s)}

    mods: Dict[str, Dict[str, Any]] = {}
    for mod, needs in module_sources().items():
        have = [s for s in needs if s in supplied_set]
        lack = [s for s in needs if s not in supplied_set]
        if not needs:
            # A module that reads nothing at all. It cannot fail to receive
            # anything, so it is neither skipped nor starved.
            status = "no_file_inputs"
        elif not have and all(n in non_file for n in needs):
            # NOT "skipped", AND NOT "no_file_inputs" EITHER. The module has an
            # OPTIONAL input that nobody asked for — `--abap-src` names a
            # directory, and omitting it is a choice rather than a forgotten
            # export.
            #
            # The distinction is the one modules/abap_sast.py argues for itself:
            # "if 'you did not ask me to look' armed the gate, every scan that
            # omits one optional input would come back cannot_assess and the
            # signal would be worth nothing. The coverage manifest states the
            # absence." So it is stated here and nowhere else — this status is
            # outside RAN_STATUSES, so the claim-side roll-ups report
            # NOT_SUPPLIED and the resolution guard withholds; and it is not one
            # of the statuses release_gate.coverage_reasons arms on, so a
            # pipeline that does not scan code is not blocked by not scanning
            # code.
            status = "not_requested"
        elif not have:
            status = "skipped"
        elif lack:
            status = "degraded"
        else:
            status = "complete"
        entry: Dict[str, Any] = {
            "status": status,
            "sources_required": needs,
            "sources_supplied": have,
            "sources_missing": lack,
        }
        if rise:
            entry["rise_scope"] = RISE_MODULE_SCOPE.get(mod, "unknown")
        mods[mod] = entry

    if modules_run is not None:
        # Accept either vocabulary — the CLI's short names or this file's module
        # names — and REFUSE a list that is neither. A name we do not recognise
        # produces `not_run`, which is a real and reportable state; a list where
        # NONE of them is recognised produces a total blackout indistinguishable
        # from a run that genuinely did nothing, and that is the one outcome a
        # coverage manifest must never invent. It ran that way for the whole life
        # of the offline report.
        ran = {CLI_MODULE_ALIASES.get(name, name) for name in modules_run}
        if ran and not (ran & set(mods)):
            raise ValueError(
                "modules_run names nothing this manifest knows: "
                + ", ".join(sorted(ran)[:5])
                + ". Pass module names (user_auth_audit) or the CLI's short names "
                  "(users); a list in a third vocabulary would report every module "
                  "as not_run.")
        for mod, entry in mods.items():
            if mod not in ran and entry["status"] != "skipped":
                # Ran-but-not-in-the-list means it was filtered out or it failed.
                # Either way it did not contribute, and the manifest must say so
                # rather than imply coverage the run did not deliver.
                entry["status"] = "not_run"

    counts = {
        "sources_known": len(known),
        "sources_supplied": len(supplied),
        "sources_empty": len(empty),
        "sources_missing": len(missing),
        "sources_unreachable_in_rise": len(unreachable),
        "modules_complete": sum(1 for m in mods.values() if m["status"] == "complete"),
        "modules_degraded": sum(1 for m in mods.values() if m["status"] == "degraded"),
        "modules_skipped": sum(1 for m in mods.values() if m["status"] == "skipped"),
        "modules_not_run": sum(1 for m in mods.values() if m["status"] == "not_run"),
        "modules_not_requested": sum(1 for m in mods.values()
                                     if m["status"] == "not_requested"),
        "files_unrecognised": len(unrecognised_names),
    }

    return {
        "deployment_mode": deployment_mode,
        "counts": counts,
        "unrecognised_files": unrecognised_names,
        "supplied": supplied,
        "empty": empty,
        "missing": missing,
        "unreachable_in_rise": unreachable,
        "modules": mods,
        "summary": summarize(counts, deployment_mode),
    }


def summarize(counts: Dict[str, int], deployment_mode: str = "on_prem") -> str:
    """One sentence an operator can read without a legend."""
    parts = [
        f"Supplied {counts['sources_supplied']} of {counts['sources_known']} "
        f"logical sources."
    ]
    if counts["sources_empty"]:
        parts.append(
            f"{counts['sources_empty']} file(s) were present but contained no rows — "
            "check the export, not the upload."
        )
    if counts["modules_degraded"]:
        parts.append(f"{counts['modules_degraded']} module(s) ran with incomplete input.")
    if counts["modules_skipped"]:
        parts.append(
            f"{counts['modules_skipped']} module(s) did not run at all because none of "
            "their input was supplied."
        )
    # SKIPPED AND NOT_RUN HAVE DIFFERENT OWNERS, so they get different sentences.
    # "You did not send the export" is the customer's to act on; "the scan did not
    # execute this module" is ours, or their scan configuration's. Folding the
    # second into the first tells a customer to go and find a file that would
    # have changed nothing.
    #
    # This clause was missing for the whole life of the manifest, and the four
    # summary cards below count `modules_skipped` — so `--modules users` produced
    # "Supplied 106 of 123 logical sources. 1 module(s) ran with incomplete
    # input." over a report in which twenty-nine modules never executed.
    if counts.get("modules_not_run"):
        parts.append(
            f"{counts['modules_not_run']} module(s) were not executed in this scan — "
            "they were filtered out by the module selection, or they failed. Their "
            "checks produced no findings, which is not the same as finding nothing."
        )
    if counts.get("sources_unreachable_in_rise"):
        parts.append(
            f"{counts['sources_unreachable_in_rise']} source(s) are not obtainable in "
            "RISE at all (they require OS access) and are excluded rather than counted "
            "as missing."
        )
    # GATED ON THE MODULES TOO, not on the sources alone. Every source can be
    # present while half the modules were never asked to look at them, and
    # "Coverage is complete." over a filtered run is the most reassuring sentence
    # this file can emit about the least complete thing it describes.
    if (counts["sources_supplied"] == counts["sources_known"]
            and not counts["modules_skipped"]
            and not counts.get("modules_not_run")):
        parts.append("Coverage is complete.")
    return " ".join(parts)
