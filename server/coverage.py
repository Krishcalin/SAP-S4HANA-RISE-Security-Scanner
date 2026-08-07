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

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

MODULES_DIR = Path(__file__).resolve().parents[1] / "modules"

_DATA_GET = re.compile(r'self\.data\.get\(\s*["\']([a-z0-9_]+)["\']')

_NOT_AN_AUDITOR = {
    "base_auditor", "data_loader", "__init__", "compliance_mapping", "fair_adapter",
    "finding_kb", "pdf_report", "pdf_writer", "pptx_report", "pptx_writer",
    "report_generator", "risk_prioritizer",
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

#: Logical sources a RISE customer cannot produce, because they are read from the
#: operating system and RISE customers contractually never get OS access. Listing
#: them as "missing" would be dishonest — the customer did not forget them, they
#: are structurally out of reach.
RISE_UNREACHABLE_SOURCES: Set[str] = {
    "ms_acl", "saprouttab", "gw_secinfo", "gw_reginfo", "ext_os_commands_sap",
}


@lru_cache(maxsize=1)
def module_sources() -> Dict[str, List[str]]:
    """Map auditor module name -> the logical data sources it reads."""
    out: Dict[str, List[str]] = {}
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except OSError:
            continue
        keys = sorted(set(_DATA_GET.findall(src)))
        if keys:
            out[path.stem] = keys
    return out


def all_logical_sources() -> List[str]:
    from modules.data_loader import DataLoader
    return sorted(DataLoader.FILE_MAP)


def build_manifest(data: Dict[str, Any],
                   modules_run: Optional[Iterable[str]] = None,
                   deployment_mode: str = "on_prem") -> Dict[str, Any]:
    """Build the coverage manifest for one scan run.

    `data` is the DataLoader output — logical name -> rows, or None when the file
    was absent.
    """
    known = all_logical_sources()
    supplied = sorted(k for k in known if data.get(k))
    # A file that was present but parsed to zero rows is NOT the same as an absent
    # file, and conflating them hides a broken export behind "you didn't send it".
    empty = sorted(k for k in known if data.get(k) is not None and not data.get(k))
    absent = sorted(k for k in known if data.get(k) is None)

    rise = deployment_mode.startswith("rise")
    unreachable = sorted(RISE_UNREACHABLE_SOURCES & set(absent)) if rise else []
    missing = [k for k in absent if k not in set(unreachable)]

    supplied_set = set(supplied)
    mods: Dict[str, Dict[str, Any]] = {}
    for mod, needs in module_sources().items():
        have = [s for s in needs if s in supplied_set]
        lack = [s for s in needs if s not in supplied_set]
        if not have:
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
        ran = set(modules_run)
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
    }

    return {
        "deployment_mode": deployment_mode,
        "counts": counts,
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
    if counts.get("sources_unreachable_in_rise"):
        parts.append(
            f"{counts['sources_unreachable_in_rise']} source(s) are not obtainable in "
            "RISE at all (they require OS access) and are excluded rather than counted "
            "as missing."
        )
    if counts["sources_supplied"] == counts["sources_known"]:
        parts.append("Coverage is complete.")
    return " ".join(parts)
