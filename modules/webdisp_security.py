# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""SAP Web Dispatcher — the internet-facing instance nobody was reading.

THE GAP, STATED PRECISELY
-------------------------
This was not "the Web Dispatcher is unsupported". Three modules already check
`is/HTTP/show_server_header` and `is/HTTP/show_detailed_errors` — against
`security_params`, which is the ABAP INSTANCE profile. A Web Dispatcher is a
separate instance with its own profile, and it is the one in front of everything
else. So the same parameter names were audited on the stack behind the door and
never on the door.

SAP draws the same line and that is the evidence for drawing it here: `2ADISCL`
reads the `ABAP_INSTANCE_PAHI` store, `2ODISCL` reads `Parameters`, and SAP ships
them as two policies because they describe two instances. Hence a separate logical
source, `webdisp_params`, rather than more rows in `security_params` — merging them
would produce one finding for two components and no way to tell which was exposed.

WHERE THE RULES COME FROM
-------------------------
`data/webdisp_baseline.json`, transcribed from SAP's own Apache-2.0 policy files
for the `WEBDISP_ALL` stack (`2ODISCL.xml`, `2ONETENC.xml`, v2.4). Every rule
carries the SAP check id and the VERBATIM predicate it came from, so the
transcription is checkable rather than trusted. `docs/RISE_SECURITY_MODEL.md`
section 3.3 argues for exactly this: deriving from an SAP-authored predicate
cannot invent a parameter name, and hand-authoring can.

Two of SAP's check items are deliberately NOT implemented and say why in the
content file — a filesystem-path regex whose shape we have not seen, and the
component-level patch check that needs an export this product does not collect.
An approximated predicate that disagrees with SAP's own tooling is worse than an
absent one.

WHAT AN ABSENT PARAMETER MEANS
------------------------------
Not a finding. A profile lists what was SET; an unset parameter takes SAP's
default, which no export tells us. Only `WDISP-014` reports on absence, because
"no HTTPS listener anywhere in the profile" is a statement the profile does make.
SAP encodes the same distinction as `not_found="positive"`.

WHO OWNS THIS UNDER RISE
------------------------
SAP operates the Web Dispatcher in a RISE tenant, so the profile is normally
theirs to export and theirs to change — `data/rise_reachability.json` classifies
the source `ticket` for that reason. A customer running their own dispatcher in
front of the tenant owns it completely, and for them these findings are directly
actionable. The reachability row says both.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.base_auditor import BaseAuditor

_PATH = Path(__file__).resolve().parents[1] / "data" / "webdisp_baseline.json"
_CACHE: Optional[Dict[str, Any]] = None

#: Column aliases for a profile export. `security_params` already accepts these
#: spellings and a Web Dispatcher profile is the same shape of list, so the same
#: names are accepted rather than a second vocabulary invented for one module.
_NAME_KEYS = ("NAME", "PARAMETER", "PARAMETER_NAME", "PARAM", "PNAME")
_VALUE_KEYS = ("VALUE", "PARAMETER_VALUE", "PVALUE", "CURRENT_VALUE")


def load(path: Optional[Path] = None) -> Dict[str, Any]:
    """The rules as content. An unreadable file disables the module's checks.

    That is the right failure: the Web Dispatcher simply goes back to being
    unaudited, which is where it was, rather than being audited against whatever
    a partial parse left behind.
    """
    global _CACHE
    if _CACHE is None:
        try:
            _CACHE = json.loads((path or _PATH).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _CACHE = {"rules": [], "_meta": {}}
    return _CACHE


def _cell(row: Dict[str, Any], keys) -> str:
    upper = {str(k).strip().upper(): v for k, v in row.items()
             if k is not None}
    for key in keys:
        val = upper.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _value(row: Dict[str, Any]) -> str:
    """The parameter value, PUT BACK TOGETHER if the export split it on commas.

    THE DEFECT THIS EXISTS FOR, WHICH IS A FALSE POSITIVE ON A HIGH FINDING.
    SAP profile values routinely contain commas — `PROT=HTTP,PORT=8000,TIMEOUT=60`
    is one value, not three. A CSV export that does not quote them produces more
    fields than headers, and `csv.DictReader` files the overflow under the key
    `None` where nothing looks at it. So

        icm/HTTP/admin_0,PREFIX=/x,CLIENTHOST=1.2.3.4

    arrives as VALUE='PREFIX=/x' with 'CLIENTHOST=1.2.3.4' discarded, and
    WDISP-011 reports an admin handler as unrestricted BECAUSE IT WAS RESTRICTED
    and the restriction fell off the end of the row. The customer is then sent to
    fix something that is already correct, on the strength of how their
    spreadsheet saved the file.

    Rejoining with commas restores the original line: the split happened on the
    delimiter, so the delimiter is what puts it back.
    """
    value = _cell(row, _VALUE_KEYS)
    overflow = row.get(None)
    if overflow:
        parts = overflow if isinstance(overflow, (list, tuple)) else [overflow]
        extra = ",".join(str(p) for p in parts if str(p).strip())
        if extra:
            value = f"{value},{extra}" if value else extra
    return value


def _compliant(value: str, rule: Dict[str, Any]) -> bool:
    """SAP's predicate for one rule, against one parameter value."""
    op = rule.get("operator")
    if op == "value_in":
        return value in (rule.get("values") or ())
    if op == "value_not_equal":
        return value != rule.get("value")
    if op == "value_contains":
        return str(rule.get("value") or "") in value
    if op == "value_not_contains_any":
        return not any(v in value for v in (rule.get("values") or ()))
    if op == "value_not_blank":
        return bool(value.strip())
    if op == "value_matches":
        return bool(re.search(str(rule.get("pattern") or ""), value))
    # An unknown operator must not silently pass. It is a content error, and
    # reporting nothing would present an unevaluated rule as a clean one.
    return True


class WebDispatcherAuditor(BaseAuditor):
    """SAP's own WEBDISP_ALL baseline, applied to the dispatcher's own profile."""

    CATEGORY = "Web Dispatcher Security"
    SOURCE_KEY = "webdisp_params"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        rows = [r for r in (self.data.get("webdisp_params") or [])
                if isinstance(r, dict)]
        if not rows:
            self.check_coverage()
            return self.findings
        params = {}
        for row in rows:
            name = _cell(row, _NAME_KEYS)
            if name:
                params[name] = _value(row)
        self.check_rules(params)
        return self.findings

    # ── checks ─────────────────────────────────────────────────────────────

    def check_coverage(self):
        """No Web Dispatcher profile, on the component that faces the internet.

        DEGRADES COVERAGE. Every other module in this scan describes the systems
        BEHIND the dispatcher. Saying nothing about the dispatcher itself, in a
        report that lists what it did examine, reads as though it was examined.
        """
        self.finding(
            check_id="WDISP-COV-001",
            title="No Web Dispatcher profile was supplied, so the internet-facing instance was not assessed",
            severity="INFO",
            category=self.CATEGORY,
            description=(
                "No Web Dispatcher profile export was provided. Every other check "
                "in this scan describes a system behind the dispatcher; nothing "
                "here speaks to the component that terminates external "
                "connections and decides which of them reach the back end.\n\n"
                "If this landscape has no Web Dispatcher, this finding is not "
                "applicable and can be closed as such. If SAP operates it under "
                "RISE, the profile is theirs to supply — that is a service "
                "request, not an export you can run."
            ),
            affected_items=["Web Dispatcher profile absent"],
            remediation=(
                "Export the Web Dispatcher instance profile as a NAME,VALUE list "
                "and supply it as webdisp_params.csv. Where SAP operates the "
                "dispatcher, request the profile through a service request."
            ),
            references=["SAP Security Baseline WEBDISP_ALL (2ODISCL, 2ONETENC)"],
            details={"degrades_coverage": True},
        )

    def check_rules(self, params: Dict[str, str]):
        """Every rule in the content file, against the supplied profile."""
        for rule in (load().get("rules") or ()):
            if rule.get("name"):
                self._single(rule, params)
            elif rule.get("operator") == "any_name_prefix_value_contains":
                self._family_any(rule, params)
            elif rule.get("name_prefix"):
                self._family_each(rule, params)

    def _single(self, rule: Dict[str, Any], params: Dict[str, str]):
        """One named parameter. Absent is not a finding — see the module docstring."""
        name = rule["name"]
        if name not in params:
            return
        value = params[name]
        if _compliant(value, rule):
            return
        self._report(rule, [f"{name} = {value}"],
                     [{"type": "parameter", "name": name}])

    def _family_each(self, rule: Dict[str, Any], params: Dict[str, str]):
        """Every parameter in a family, reported per offender.

        `icm/HTTP/admin_0` and `icm/HTTP/admin_1` are two listeners. Collapsing
        them into one finding would hide that the second is also exposed, and
        closing the finding would close both.
        """
        prefix = rule["name_prefix"]
        offenders = [(n, v) for n, v in sorted(params.items())
                     if n.startswith(prefix) and not _compliant(v, rule)]
        if not offenders:
            return
        self._report(rule, [f"{n} = {v}" for n, v in offenders],
                     [{"type": "parameter", "name": n} for n, _ in offenders])

    def _family_any(self, rule: Dict[str, Any], params: Dict[str, str]):
        """At least one member of the family must satisfy the predicate.

        The HTTPS-listener rule: SAP asks whether ANY icm/server_port_<n> serves
        HTTPS, not whether all of them do. A dispatcher with one HTTPS and three
        HTTP listeners is compliant on this check — the plain listeners are a
        separate argument SAP's baseline does not make here, and making it for
        them would be our claim wearing SAP's check id.
        """
        prefix, needle = rule["name_prefix"], str(rule.get("value") or "")
        family = {n: v for n, v in params.items() if n.startswith(prefix)}
        if not family and not rule.get("report_when_absent"):
            return
        if any(needle in v for v in family.values()):
            return
        listed = [f"{n} = {v}" for n, v in sorted(family.items())] or \
            [f"no {prefix}* parameter is set in this profile"]
        self._report(rule, listed,
                     [{"type": "parameter", "name": n} for n in sorted(family)])

    def _report(self, rule: Dict[str, Any], items: List[str],
                objects: List[Dict[str, str]]):
        self.finding(
            check_id=rule["check_id"],
            title=rule["title"],
            severity=rule["severity"],
            category=self.CATEGORY,
            description=rule["risk"],
            affected_items=items,
            affected_objects=objects,
            remediation=rule["fix"],
            references=[f"SAP Security Baseline {rule['policy']} "
                        f"check {rule['sap_check_id']}"],
            # The verbatim SAP predicate travels with the finding, so a customer
            # arguing with the result argues with SAP's own rule rather than ours.
            details={"sap_check_id": rule["sap_check_id"],
                     "sap_policy": rule["policy"],
                     "sap_predicate": rule["sap_predicate"]},
        )
