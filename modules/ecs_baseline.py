# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The ECS hardening baseline, as one shared oracle.

`data/ecs_hardening_3250501.json` holds SAP Note 3250501 — the MANDATORY hardening
baseline for AS ABAP in SAP Enterprise Cloud Services — recorded as facts:
parameter names, SAP's standard value, and the exceptions SAP explicitly permits.

────────────────────────────────────────────────────────────────────────────────
WHY THIS IS A SHARED MODULE AND NOT A COPY IN EACH AUDITOR
────────────────────────────────────────────────────────────────────────────────
Several auditors form an opinion about the same profile parameter, and before this
existed they disagreed with SAP and with each other. Measured on an export set to
SAP's own mandated values, `BaselineParamAuditor` reported a HIGH finding:

    snc/accept_insecure_gui       = 1   <- the ECS STANDARD
    snc/accept_insecure_rfc       = 1   <- the ECS STANDARD
    snc/accept_insecure_r3int_rfc = 1   <- the ECS STANDARD

The check reasoned "insecure-sounding parameter set to 1 is a finding", which is
the correct instinct on classic on-premise ABAP and is wrong in ECS, where SAP
mandates those exact values. A RISE-specific product telling every RISE customer
they have a HIGH finding on SAP's own written mandate is worse than not checking
at all: it is confidently wrong, on every compliant system, in the one environment
we claim to specialise in.

`sapgui/user_scripting = TRUE` and `rfc/callback_security_method = 1` were the same
mistake against the note's `allowed` exceptions.

So the question "is this value acceptable here?" is answered in ONE place, from the
note, rather than re-derived per module from the parameter's name.

DEPLOYMENT MATTERS. These answers are about ECS/RISE. On classic on-premise ABAP
the stricter reading is right, which is why `is_compliant` takes the deployment
mode and only defers to the note when it applies.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

#: Deployment-mode PREFIX for which SAP Note 3250501 is the governing baseline.
#: `rise_pce` / `rise_tailored`, matched by prefix — the identical test
#: `user_auth_audit.is_ecs()` and `server/enrich.py` already use. A second
#: vocabulary for the same concept is how two modules end up disagreeing about
#: which estate they are auditing.
ECS_MODE_PREFIX: str = "rise"

_PATH = Path(__file__).resolve().parents[1] / "data" / "ecs_hardening_3250501.json"
_CACHE: Optional[Dict[str, Any]] = None


def load() -> Dict[str, Any]:
    """The note as data. An absent or unreadable file degrades to empty.

    Deliberately non-fatal: this file is a reference extract, not program logic.
    A scanner that refuses to run because a reference document is missing is worse
    than one that runs with the checks that do not need it — and `is_compliant`
    returns None ("no opinion") in that state, so nothing silently becomes
    compliant.
    """
    global _CACHE
    if _CACHE is None:
        try:
            _CACHE = json.loads(_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _CACHE = {"parameters": {}, "configuration_items": []}
    return _CACHE


def parameters() -> Dict[str, Dict[str, Any]]:
    return load().get("parameters", {})


def ecs_value(param: str) -> Optional[str]:
    entry = parameters().get(param)
    return entry.get("ecs") if entry else None


def is_mandated(param: str) -> bool:
    """Is this parameter governed by the note at all?

    Distinguishing "mandated and absent from the export" from "a check we happen to
    carry that the note does not mandate" is what stops a note-complete export
    being reported as an incomplete one.
    """
    return param in parameters()


def is_compliant(param: str, value: Any, deployment_mode: str = "") -> Optional[bool]:
    """Is `value` acceptable for `param` under the ECS baseline?

    Returns True (SAP's standard value or an explicitly permitted exception),
    False (a genuine deviation), or None — meaning THIS MODULE HAS NO OPINION,
    because the parameter is not in the note or the deployment is not ECS. None is
    never "compliant": callers must fall back to their own rule, not pass.
    """
    if deployment_mode and not deployment_mode.lower().startswith(ECS_MODE_PREFIX):
        return None
    entry = parameters().get(param)
    if entry is None or value is None:
        return None
    got = str(value).strip().lower()
    if got == str(entry.get("ecs", "")).strip().lower():
        return True
    for permitted in entry.get("allowed", []):
        allowed = str(permitted).strip().lower()
        # Range and bound expressions ("30 to 90", ">=15", "<=6 not 0") are carried
        # verbatim from the note and are not resolved here — a caller that needs
        # them owns the comparison, and guessing at them would be the fabrication
        # this whole extract exists to prevent.
        if any(tok in allowed for tok in ("to", ">=", "<=", "not")):
            return None
        if got == allowed:
            return True
    return False


def compliance(security_params: Any,
               deployment_mode: str = "") -> Dict[str, Any]:
    """How the estate stands against SAP's MANDATORY ECS hardening, as a roll-up.

    WHY THIS IS NOT A `compliance_mapping` FRAMEWORK. Every other framework in
    this product is a theme-to-control map: a finding about privileged access
    reaches ISO A.8.2 because both describe a kind of control. SAP Note 3250501 is
    not that shape. It is 92 named parameters with a mandated value each, and the
    question it answers is "is this parameter set to what SAP requires", one
    parameter at a time. Forcing it into a theme table would lose the parameter —
    which IS the control — and report a domain score where the note gives a list.

    So this is a roll-up beside the frameworks rather than one of them, and the
    distinction is worth keeping: a customer asking "am I ISO-aligned?" wants
    themes, and one asking "am I compliant with what SAP mandates for ECS?" wants
    the parameter that is wrong.

    FOUR OUTCOMES, NOT TWO. A parameter can be compliant, deviating, ABSENT FROM
    THE EXPORT — which is not a deviation, it is a thing we did not see — or one
    the note governs while this module holds no opinion. Collapsing "absent" into
    "deviating" would report an incomplete export as a non-compliant system, and
    collapsing it into "compliant" would do the reverse and worse.

    Returns `{}` outside ECS/RISE. The note governs SAP Enterprise Cloud Services,
    and scoring an on-premise estate against a contract it is not under would be
    the confidently-wrong reporting this module's docstring already warns about.
    """
    if deployment_mode and not deployment_mode.lower().startswith(ECS_MODE_PREFIX):
        return {}
    mandated = parameters()
    supplied: Dict[str, str] = {}
    for row in (security_params or ()):
        if not isinstance(row, dict):
            continue
        upper = {str(k).strip().upper(): v for k, v in row.items() if k is not None}
        name = ""
        for key in ("NAME", "PARAMETER", "PARAMETER_NAME", "PARAM", "PNAME"):
            if str(upper.get(key, "") or "").strip():
                name = str(upper[key]).strip()
                break
        if not name:
            continue
        for key in ("VALUE", "PARAMETER_VALUE", "PVALUE", "CURRENT_VALUE"):
            if upper.get(key) is not None:
                supplied[name] = str(upper[key]).strip()
                break

    compliant, deviating, no_opinion, absent = [], [], [], []
    for param in sorted(mandated):
        if param not in supplied:
            absent.append(param)
            continue
        verdict = is_compliant(param, supplied[param], deployment_mode or "rise_pce")
        if verdict is True:
            compliant.append(param)
        elif verdict is False:
            deviating.append({"parameter": param,
                              "found": supplied[param],
                              "sap_standard": ecs_value(param)})
        else:
            no_opinion.append(param)

    assessed = len(compliant) + len(deviating)
    return {
        "note": "SAP Note 3250501",
        "mandated": len(mandated),
        "assessed": assessed,
        "compliant": compliant,
        "deviating": deviating,
        "no_opinion": no_opinion,
        "absent_from_export": absent,
        # DENOMINATOR IS WHAT WAS ASSESSED, not what the note mandates. A rate over
        # all 92 when only 40 were exported reports the 52 nobody looked at as
        # failures, which is the same defect the coverage manifest exists to stop.
        "rate": (len(compliant) / assessed) if assessed else None,
        "summary": (
            "%d of %d mandated parameters assessed: %d compliant, %d deviating. "
            "%d were not in the export and are neither." % (
                assessed, len(mandated), len(compliant), len(deviating),
                len(absent))
            if assessed else
            "None of SAP's %d mandated parameters were present in the export, so "
            "this says nothing about compliance with them." % len(mandated)),
    }
