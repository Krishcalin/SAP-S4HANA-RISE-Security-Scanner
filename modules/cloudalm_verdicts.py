# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""SAP Cloud ALM CSA compliance results, imported as SAP's findings.

THE QUESTION THIS EXISTS TO STOP GATING
---------------------------------------
`modules/cloudalm_import.py` translates Cloud ALM **configuration-store exports**
into the logical sources our own checks read, and it opens with a caveat that has
blocked this path since it was written: nobody could confirm whether Cloud ALM
returns RAW STORE VALUES or only SAP'S OWN POLICY VERDICTS. The roadmap turned
that into a precondition — "*Verify first:* whether its API returns raw store
values or only compliance verdicts. That determines whether it unlocks our 350
checks or only SAP's."

It could not be verified, and that is now a searched-for negative rather than an
untried one. SAP's `cloud-alm-setup-admin-guide` carries no CSA content at all;
`SAP-samples/cloud-alm-api-examples` publishes projects, tasks, process
authoring, requirements, test management and analytics, and nothing for
configuration and security analysis; the Business Accelerator Hub is a
JavaScript application this product cannot read. Settling it needs a live tenant.

So this module answers the question by making it stop mattering. The raw path was
already built. This is the verdict path. Whichever shape a tenant's export takes,
one of the two reads it, and the open question no longer decides whether the
customer can adopt CSA at all.

WHAT A VERDICT IS, AND WHAT IT IS NOT
-------------------------------------
A CSA result says SAP's policy `2AAUDIT` reported non-compliant on system `PRD`.
That is SAP's assessment, produced by SAP's rules against SAP's data collection.
It is NOT this product's finding, and every finding here says so — in the title,
in the description, and in `details["assessed_by"]`. Presenting somebody else's
verdict as our own would be the plainest possible form of the overclaim this
codebase spends most of its comments avoiding.

It also cannot be turned into one. A verdict carries no parameter value, no user
name, no table row — so nothing here can feed the checks in `modules/`, and the
importer's original caveat stands unchanged: "it cannot turn 'SAP's policy
1ASTDUSR reports non-compliant' into the parameter and user rows our checks
read".

WHAT MAKES THE VERDICT USEFUL ANYWAY
------------------------------------
`data/sap_baseline_requirements.json` is derived from the same published policies
Cloud ALM runs. So a bare policy id resolves to SAP's own requirement, family and
priority tier: `2AAUDIT` becomes "AUDIT-A, STANDARD, Audit Log activated". The
severity of every finding here is SAP'S TIER and not a judgement of ours — there
is no honest way for this product to rank a result it did not compute.

A policy id the vendored catalogue does not know is REPORTED, not dropped. SAP
adds policies on its own schedule, and a verdict naming one we cannot resolve
means the catalogue is behind — which is a fact about this product, and belongs
in the report rather than in silence.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base_auditor import BaseAuditor

#: Derived from SAP-samples/frun-csa-policies-best-practices by
#: `server/sapcontent.py`. The same policies Cloud ALM CSA evaluates, which is
#: what makes a bare policy id resolvable here at all.
BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "sap_baseline_requirements.json"

#: SAP's own priority tiers, mapped to this product's severity vocabulary. This
#: is a translation of SAP's ranking, NOT a ranking of ours: a verdict computed
#: by somebody else's rules against data we never saw cannot honestly be graded
#: on our scale, so the only defensible thing is to carry theirs across.
TIER_SEVERITY = {
    "CRITICAL": BaseAuditor.SEVERITY_CRITICAL,
    "STANDARD": BaseAuditor.SEVERITY_HIGH,
    "EXTENDED": BaseAuditor.SEVERITY_MEDIUM,
}

#: Column spellings a CSA export might use. Deliberately generous: this file is
#: produced by a tenant's own extraction, not by a documented API shape we could
#: pin, and refusing a reasonable spelling would send somebody to rename columns
#: rather than to read the finding.
_POLICY_KEYS = ("POLICY", "POLICY_ID", "POLICYID", "POLICY_NAME", "CHECK",
                "CHECK_ID", "RULE", "RULE_ID")
_SYSTEM_KEYS = ("SYSTEM", "SID", "SYSTEM_ID", "TARGET", "TARGET_SYSTEM",
                "MANAGED_OBJECT", "TECHNICAL_SYSTEM")
_STATUS_KEYS = ("STATUS", "RESULT", "COMPLIANCE", "COMPLIANCE_STATUS",
                "RATING", "VERDICT", "STATE")
_ITEM_KEYS = ("CHECK_ITEM", "ITEM", "CHECKITEM", "DESCRIPTION", "TITLE")
_DATE_KEYS = ("DATE", "TIMESTAMP", "COLLECTED", "COLLECTED_ON", "RUN_DATE",
              "LAST_RUN")

#: Values meaning "this policy did not pass". Everything else is treated as
#: compliant or unknown, which is the safe direction: inventing a failure from a
#: status word nobody recognised would put SAP's name on our mistake.
_FAILED = {"NON-COMPLIANT", "NONCOMPLIANT", "NOT COMPLIANT", "FAILED", "FAIL",
           "RED", "ERROR", "VIOLATION", "NOT OK", "NOTOK"}
#: Values meaning the policy could not be evaluated. Distinct from a failure on
#: purpose — "SAP could not check this" and "SAP checked it and it failed" are
#: different statements and a report that merges them is worth less than either.
_UNKNOWN = {"UNKNOWN", "NOT ASSESSED", "NOTASSESSED", "N/A", "NA", "GREY",
            "GRAY", "NO DATA", "NODATA", "PENDING"}


class CloudAlmVerdictAuditor(BaseAuditor):
    """SAP's own CSA results, reported as SAP's."""

    CATEGORY = "SAP Cloud ALM CSA Results"
    SOURCE_KEY = "csa_findings"

    # ── the vendored baseline, and what a policy id resolves to ─────────────

    def _baseline(self) -> Dict[str, Any]:
        cached = getattr(self, "_baseline_cache", None)
        if cached is not None:
            return cached
        try:
            data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        self._baseline_cache = data
        return data

    def _policy_index(self) -> Dict[str, Dict[str, Any]]:
        """`{policy_id: {title, requirement, family, tier}}`.

        The requirement side comes from the requirement whose `policies` list
        names this policy. Where several do — SAP groups a policy under more
        than one requirement — the HIGHEST tier wins, because a policy carrying a
        CRITICAL requirement is critical whatever else it also serves.
        """
        cached = getattr(self, "_policy_index_cache", None)
        if cached is not None:
            return cached
        baseline = self._baseline()
        rank = {"CRITICAL": 3, "STANDARD": 2, "EXTENDED": 1}
        index: Dict[str, Dict[str, Any]] = {}
        for policy in baseline.get("policies") or []:
            pid = str(policy.get("policy_id") or "").strip().upper()
            if pid:
                index[pid] = {"title": policy.get("title") or "",
                              "requirement": None, "family": None, "tier": None}
        for req in baseline.get("requirements") or []:
            tier = req.get("tier")
            for pid in req.get("policies") or []:
                entry = index.setdefault(
                    str(pid).strip().upper(),
                    {"title": "", "requirement": None, "family": None, "tier": None})
                if rank.get(str(tier).upper(), 0) > rank.get(
                        str(entry["tier"]).upper(), 0):
                    entry.update(requirement=req.get("requirement"),
                                 family=req.get("family"), tier=tier)
                elif entry["requirement"] is None:
                    entry.update(requirement=req.get("requirement"),
                                 family=req.get("family"))
        self._policy_index_cache = index
        return index

    # ── reading the export ──────────────────────────────────────────────────

    @staticmethod
    def _cell(row: Dict[str, Any], *names: str) -> str:
        if not isinstance(row, dict):
            return ""
        upper = {str(k).strip().upper(): v for k, v in row.items()}
        for name in names:
            value = upper.get(name)
            if value not in (None, ""):
                return str(value).strip()
        return ""

    def _verdicts(self) -> List[Dict[str, str]]:
        out = []
        for row in (self.data.get(self.SOURCE_KEY) or []):
            policy = self._cell(row, *_POLICY_KEYS).upper()
            if not policy:
                continue
            out.append({
                "policy": policy,
                "system": self._cell(row, *_SYSTEM_KEYS),
                "status": self._cell(row, *_STATUS_KEYS).upper(),
                "item": self._cell(row, *_ITEM_KEYS),
                "date": self._cell(row, *_DATE_KEYS),
            })
        return out

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        if self.data.get(self.SOURCE_KEY) is None:
            # Nobody supplied a CSA export. An absent optional input is not
            # degraded coverage — the same line `cap_xsuaa` and `abap_sast` draw.
            return self.findings

        verdicts = self._verdicts()
        if not verdicts:
            self._report_unreadable()
            return self.findings

        self.check_failed_policies(verdicts)
        self.check_unevaluated_policies(verdicts)
        self.check_unknown_policy_ids(verdicts)
        return self.findings

    # ── CSA-SAP-001: what SAP reports as non-compliant ──────────────────────

    def check_failed_policies(self, verdicts: List[Dict[str, str]]):
        """Policies SAP's own CSA reports as not passing.

        Severity is SAP's tier, translated. Nothing here re-judges the result,
        because nothing here saw the evidence: the verdict arrives without the
        parameter value, user or table row that produced it.
        """
        index = self._policy_index()
        failed = [v for v in verdicts if v["status"] in _FAILED]
        if not failed:
            return
        worst = BaseAuditor.SEVERITY_MEDIUM
        rank = {BaseAuditor.SEVERITY_CRITICAL: 3, BaseAuditor.SEVERITY_HIGH: 2,
                BaseAuditor.SEVERITY_MEDIUM: 1}
        items, objects, tiers = [], [], {}
        for v in sorted(failed, key=lambda r: (r["policy"], r["system"])):
            meta = index.get(v["policy"], {})
            tier = str(meta.get("tier") or "").upper()
            severity = TIER_SEVERITY.get(tier, BaseAuditor.SEVERITY_MEDIUM)
            if rank[severity] > rank[worst]:
                worst = severity
            tiers[tier or "unresolved"] = tiers.get(tier or "unresolved", 0) + 1
            items.append(
                "%s%s — %s%s%s"
                % (v["policy"],
                   " on %s" % v["system"] if v["system"] else "",
                   meta.get("title") or "policy not in the vendored catalogue",
                   " [%s, %s]" % (meta["requirement"], tier)
                   if meta.get("requirement") else "",
                   " — %s" % v["item"] if v["item"] else ""))
            self._add(objects, "sap_policy", v["policy"])
            if v["system"]:
                self._add(objects, "system", v["system"])

        self.finding(
            check_id="CSA-SAP-001",
            title="SAP Cloud ALM CSA reports these policies as not compliant",
            severity=worst,
            category=self.CATEGORY,
            description=(
                "%d SAP Cloud ALM Configuration & Security Analysis result(s) "
                "report a policy as not compliant.\n\n"
                "THESE ARE SAP'S FINDINGS, NOT THIS PRODUCT'S. They were "
                "produced by SAP's rules against SAP's own data collection, and "
                "nothing here re-judged them — a verdict arrives without the "
                "parameter value, user or table row that produced it, so there "
                "is nothing to re-judge. Severity is SAP's own priority tier "
                "translated across (CRITICAL / STANDARD / EXTENDED), because "
                "ranking a result this product did not compute would be "
                "inventing precision.\n\n"
                "Policy identifiers are resolved against the SAP Security "
                "Baseline catalogue this product vendors from SAP's published "
                "policies, so each line carries SAP's own requirement and tier "
                "where the catalogue knows the policy. Tiers seen: %s."
                % (len(failed),
                   ", ".join("%s %d" % (k, n) for k, n in sorted(tiers.items())))),
            affected_items=items[:60],
            affected_objects=objects,
            remediation=(
                "1. Work these in Cloud ALM itself, where the result was "
                "produced and where the evidence behind it can be opened. This "
                "report carries the verdict, not the value that failed.\n"
                "2. Where a policy also falls inside this product's own checks, "
                "expect two views of one problem rather than two problems — "
                "reconcile them before counting.\n"
                "3. Supply the raw configuration-store export as well if your "
                "tenant produces one: `modules/cloudalm_import.py` turns that "
                "into inputs this product's own checks read, which yields the "
                "value rather than the verdict.\n"
                "4. Re-run after the next CSA collection."),
            references=[
                "SAP Cloud ALM — Configuration & Security Analysis",
                "SAP Security Baseline Template (policy identifiers and tiers)",
            ],
            details={"count": len(failed), "assessed_by": "SAP Cloud ALM CSA",
                     "severity_basis": "sap_baseline_tier",
                     "reassessed_by_this_product": False,
                     "by_tier": tiers},
            scope="aggregate",
        )

    # ── CSA-SAP-002: what SAP could not evaluate ────────────────────────────

    def check_unevaluated_policies(self, verdicts: List[Dict[str, str]]):
        """Results SAP recorded as not assessed.

        Kept apart from the failures deliberately. "SAP could not check this"
        and "SAP checked it and it failed" are different statements, and a
        report that merges them is worth less than either — the first is a gap
        in the collection, the second is a gap in the system.
        """
        index = self._policy_index()
        unknown = [v for v in verdicts if v["status"] in _UNKNOWN]
        if not unknown:
            return
        items = ["%s%s — %s"
                 % (v["policy"], " on %s" % v["system"] if v["system"] else "",
                    index.get(v["policy"], {}).get("title")
                    or "policy not in the vendored catalogue")
                 for v in sorted(unknown, key=lambda r: (r["policy"], r["system"]))]
        self.finding(
            check_id="CSA-SAP-002",
            title="SAP Cloud ALM CSA could not evaluate these policies",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "%d CSA result(s) carry a status meaning the policy was not "
                "assessed rather than that it passed. A system reported as "
                "compliant on everything CSA could evaluate is not the same as "
                "a system reported as compliant, and the difference is only "
                "visible if the unevaluated results are listed. The usual cause "
                "is a store the collection did not gather on that system."
                % len(unknown)),
            affected_items=items[:60],
            affected_objects=[{"type": "sap_policy", "name": v["policy"]}
                              for v in unknown],
            remediation=(
                "1. In Cloud ALM, check whether the configuration collection "
                "covers the stores these policies read on this system.\n"
                "2. Where a policy is genuinely out of scope for the system, "
                "record that — an unevaluated result and an inapplicable one "
                "look identical in an export.\n"
                "3. Re-run after the next collection."),
            references=["SAP Cloud ALM — Configuration & Security Analysis"],
            details={"count": len(unknown), "assessed_by": "SAP Cloud ALM CSA",
                     "degrades_coverage": True},
            scope="aggregate",
        )

    # ── CSA-SAP-003: policies this product's catalogue does not know ────────

    def check_unknown_policy_ids(self, verdicts: List[Dict[str, str]]):
        """Verdicts naming a policy the vendored baseline cannot resolve.

        This is a finding about THIS PRODUCT. SAP adds and renames policies on
        its own schedule; a verdict we cannot resolve means the vendored
        catalogue is behind, and the honest place for that is the report rather
        than silence — the alternative is a line reading "policy not in the
        vendored catalogue" with nothing explaining why.
        """
        index = self._policy_index()
        unresolved = sorted({v["policy"] for v in verdicts
                             if v["policy"] not in index})
        if not unresolved:
            return
        self.finding(
            check_id="CSA-SAP-003",
            title="CSA results name policies the vendored baseline catalogue "
                  "does not know",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                "%d policy identifier(s) in this CSA export resolve to nothing "
                "in `data/sap_baseline_requirements.json`, so their results are "
                "reported without SAP's requirement or priority tier and are "
                "graded at the default rather than at SAP's ranking.\n\n"
                "This concerns THIS PRODUCT'S DATA and not the scanned system. "
                "SAP adds and renames CSA policies on its own schedule, and the "
                "vendored catalogue is a snapshot regenerated from SAP's "
                "published policy repository. An identifier it does not know "
                "most often means the snapshot is behind."
                % len(unresolved)),
            affected_items=unresolved[:60],
            remediation=(
                "1. Regenerate the baseline catalogue from SAP's published "
                "policies: `python -m server.cli rebuild-sap-catalogue "
                "<checkout>`.\n"
                "2. If the identifier is still unknown afterwards, it is a "
                "policy SAP has not published in that repository — report the "
                "result as it stands and record the id.\n"
                "3. The `sap-content` CI job re-derives the catalogue and fails "
                "on drift, so a stale snapshot should be caught before a "
                "customer sees it."),
            references=[
                "SAP-samples/frun-csa-policies-best-practices (Apache-2.0)",
            ],
            details={"count": len(unresolved), "self_audit": True,
                     "unresolved": unresolved[:60]},
            scope="aggregate",
        )

    # ── coverage ────────────────────────────────────────────────────────────

    def _report_unreadable(self):
        self.finding(
            check_id="CSA-COV-001",
            title="A CSA export was supplied but no result could be read from it",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "The CSA results file was loaded and no row in it names a "
                "policy, so nothing was assessed. Reporting nothing here would "
                "read exactly like a tenant with no failing policies. The usual "
                "cause is an export whose policy column is spelled in a way this "
                "module does not recognise, or a file that is a store export "
                "rather than a results export — those go to "
                "`modules/cloudalm_import.py` instead."),
            affected_items=["0 usable rows in the supplied CSA results export"],
            remediation=(
                "1. Confirm the file carries one row per policy result, with a "
                "column naming the policy (`POLICY`, `POLICY_ID`, `CHECK_ID` or "
                "`RULE_ID` are all accepted).\n"
                "2. If the file is a configuration-STORE export, it belongs to "
                "the store importer and needs no column renaming — see the "
                "Cloud ALM section of the export guide.\n"
                "3. Re-run."),
            references=["docs/EXPORT_GUIDE.md — SAP Cloud ALM CSA exports"],
            details={"degrades_coverage": True, "assessed_by": "SAP Cloud ALM CSA",
                     "reason": "no_policy_column"},
            scope="aggregate",
        )

    @staticmethod
    def _add(bucket: List[Dict[str, Any]], obj_type: str, name: Any) -> None:
        value = "" if name is None else str(name).strip()
        if not value:
            return
        obj = {"type": obj_type, "name": value}
        if obj not in bucket:
            bucket.append(obj)
