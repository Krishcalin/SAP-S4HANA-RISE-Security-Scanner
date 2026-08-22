"""
SAP's own security content, adopted rather than reinvented.

WHY
---
SAP publishes its Security Baseline as executable check logic:
`SAP-samples/frun-csa-policies-best-practices`, Apache-2.0, maintained by SAP SE.
Each policy is a `<targetsystem>` of `<configstore>` blocks whose `<checkitem>`
entries carry SQL compliant/noncompliant predicates over named configuration
stores.

Hand-authoring check content risks inventing parameter names, note numbers and
thresholds — the credibility failure this project has already suffered. Deriving
our control vocabulary from an SAP-authored source is the structural fix, and it
is free, versioned and licence-compatible.

WHAT WE TAKE, AND WHAT WE DO NOT
---------------------------------
We take the **requirement vocabulary**: family-technology IDs (`PWDPOL-A`,
`CRITAU-H`), their titles, their priority tier, and the configuration stores they
read. That lets our findings speak SAP's own control language, which is far more
defensible in front of an auditor than a house-brand control name.

We do **not** execute SAP's SQL predicates. They run against Focused Run's
Configuration and Change Database, which we do not have; our checks read exported
files. Claiming to run SAP's policies would be false.

A NUMBER TO BE CAREFUL WITH
----------------------------
A widely-quoted figure says the SAP Security Baseline has **214 in-scope control
points** (69 Critical / 92 Standard / 53 Extended). Parsing SAP's published v2.4
policies yields **351 check items** across **38 requirement families**
(97 / 175 / 79). Those are different units — a "control point" in the Baseline
document is not a `checkitem` in the CSA policies — and this module deliberately
reports only what it can count from the files. Do not publish a percentage against
214 using these numbers; they do not reconcile, and being caught doing so would
cost more than the claim is worth.
"""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

log = logging.getLogger(__name__)

CATALOGUE_PATH = (Path(__file__).resolve().parents[1] / "data"
                  / "sap_baseline_requirements.json")

#: `[p1-CRITICAL]` / `[p2-STANDARD]` / `[p3-EXTENDED]` prefix on a checkitem desc.
_PRIORITY = re.compile(r"\[(p\d)-([A-Z]+)\]\s*")

#: Requirement id: FAMILY-<technology>, technology being
#: A=ABAP AS, J=Java AS, H=HANA, O=Other (Web Dispatcher, SAPGUI), P=BTP Platform.
#:
#: SAP uses BOTH separators after the technology letter — `CRITAU-A_a.1` and
#: `NETENC-O.a.1` — so accepting only the underscore silently dropped NETENC-O,
#: OBSCNT-A and SECUPD-H. That is not a cosmetic loss: those requirements would
#: vanish from the published denominator and make our coverage look BETTER than it
#: is, which is the one direction an error here must never go.
_REQ = re.compile(r"^([A-Z]{3,10})-([AJHOP])(?:[_.]|$)")

TECHNOLOGY = {"A": "ABAP", "J": "Java", "H": "HANA", "O": "Other", "P": "BTP"}


def parse_policy(path: Path) -> Dict[str, Any]:
    """Parse one CSA policy file into its requirements.

    Tolerant by design: a policy this parser cannot read must not abort a catalogue
    build over 58 files, because SAP adds files on its own schedule and one new
    shape should degrade to "that policy contributed nothing", not to no catalogue.
    """
    root = ET.parse(path).getroot()
    policy = {
        "policy_id": root.get("id", ""),
        "title": root.get("desc", ""),
        "file": path.name,
        "stack": path.parent.name,
        "requirements": [],
    }
    for store in root.findall("configstore"):
        store_name = store.get("name", "")
        for item in store.findall("checkitem"):
            desc = item.get("desc", "") or ""
            check_id = item.get("id", "") or ""
            tier = None
            m = _PRIORITY.search(desc)
            if m:
                tier = m.group(2)
                desc = _PRIORITY.sub("", desc, count=1).strip()
            rm = _REQ.match(check_id)
            policy["requirements"].append({
                "check_id": check_id,
                "requirement": f"{rm.group(1)}-{rm.group(2)}" if rm else None,
                "family": rm.group(1) if rm else None,
                "technology": TECHNOLOGY.get(rm.group(2)) if rm else None,
                "title": desc,
                "tier": tier,
                "config_store": store_name,
            })
    return policy


def build_catalogue(root_dir: Path, version: str = "v2.4") -> Dict[str, Any]:
    """Build the requirement catalogue from a checkout of SAP's policy repository.

    `root_dir` is the repo root (the directory holding `BaselinePolicies/`).
    """
    base = root_dir / "BaselinePolicies" / "SOS" / version
    if not base.is_dir():
        raise FileNotFoundError(f"no SAP baseline policies at {base}")

    policies, requirements = [], {}
    tiers: Dict[str, int] = {}
    for path in sorted(base.rglob("*.xml")):
        try:
            policy = parse_policy(path)
        except ET.ParseError as exc:
            log.warning("skipping unparseable policy %s: %s", path.name, exc)
            continue
        policies.append({k: policy[k] for k in ("policy_id", "title", "file", "stack")})
        for req in policy["requirements"]:
            if req["tier"]:
                tiers[req["tier"]] = tiers.get(req["tier"], 0) + 1
            key = req["requirement"]
            if not key:
                continue
            entry = requirements.setdefault(key, {
                "requirement": key, "family": req["family"],
                "technology": req["technology"], "tier": req["tier"],
                "titles": [], "config_stores": set(), "check_items": 0,
                "policies": set(),
            })
            entry["check_items"] += 1
            entry["policies"].add(policy["policy_id"])
            if req["config_store"]:
                entry["config_stores"].add(req["config_store"])
            if req["title"] and req["title"] not in entry["titles"]:
                entry["titles"].append(req["title"])
            # A family's tier is the STRICTEST any of its items carries: a family
            # containing one CRITICAL item is a critical family, and averaging or
            # last-wins would quietly downgrade it.
            order = {"CRITICAL": 0, "STANDARD": 1, "EXTENDED": 2}
            if req["tier"] and order.get(req["tier"], 9) < order.get(entry["tier"], 9):
                entry["tier"] = req["tier"]

    for entry in requirements.values():
        entry["config_stores"] = sorted(entry["config_stores"])
        entry["policies"] = sorted(entry["policies"])
        entry["titles"] = entry["titles"][:4]

    return {
        "_meta": {
            "source": "SAP-samples/frun-csa-policies-best-practices",
            "licence": "Apache-2.0, Copyright (c) 2020 SAP SE or an SAP affiliate company",
            "baseline_version": version,
            "note": (
                "DERIVED from SAP's published policies: requirement ids, titles, "
                "priority tiers and config-store names only. SAP's SQL predicates "
                "are NOT reproduced and are NOT executed — they run against Focused "
                "Run's configuration database, which we do not have. Our checks read "
                "exported files and are our own."),
            "counts": {
                "policies": len(policies),
                "requirements": len(requirements),
                "check_items": sum(tiers.values()),
                "by_tier": tiers,
            },
            "unit_warning": (
                "These are CHECK ITEMS in the CSA policies, not the 'control points' "
                "counted in the Baseline document — the widely-quoted 214 (69/92/53) "
                "is that other unit. The two do not reconcile; do not publish a "
                "percentage of one against the other."),
        },
        "requirements": [requirements[k] for k in sorted(requirements)],
        "policies": policies,
    }


def load_catalogue(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or CATALOGUE_PATH
    if not p.is_file():
        return {"_meta": {}, "requirements": [], "policies": []}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def write_catalogue(catalogue: Dict[str, Any], path: Optional[Path] = None) -> None:
    with open(path or CATALOGUE_PATH, "w", encoding="utf-8") as fh:
        json.dump(catalogue, fh, indent=1, ensure_ascii=False, sort_keys=False)
        fh.write("\n")


# --------------------------------------------------------------------------- #
#  Mapping our checks onto SAP's vocabulary                                   #
# --------------------------------------------------------------------------- #

#: Our check-id prefix -> SAP Baseline requirement family.
#:
#: Deliberately conservative and NOT exhaustive. A wrong mapping is worse than a
#: missing one: it would tell an auditor we satisfy a control we do not test. Only
#: mappings where our check demonstrably reads the same configuration as SAP's
#: requirement are asserted; everything else stays unmapped and is reported as
#: such on the coverage page.
CHECK_TO_REQUIREMENT: Dict[str, str] = {
    # "PARAM-PWD": "PWDPOL-A" WAS HERE AND NEVER MATCHED ANYTHING. Every id in
    # that family is `PARAM-<parameter name>` — `PARAM-login/min_password_lng` —
    # so the prefix `PARAM-PWD` matched none of the 81. It was invisible because
    # nothing published the result: PWDPOL-A, a CRITICAL requirement whose
    # parameters this product has always checked, read as "not addressed" and no
    # reader ever saw the line. Publishing the catalogue is what found it.
    #
    # Replaced by `parameter_requirements()` below, which derives the mapping
    # from SAP's own requirement titles rather than guessing a prefix.
    "USR-00": "STDUSR-A",
    "STDUSR-": "STDUSR-A",
    "AUTH-": "CRITAU-A",
    "ARA-": "CRITAU-A",
    "TRUST-00": "RFCGW-A",
    "INTG-GW-": "RFCGW-A",
    "NET-00": "NETCF-A",
    "OBSCNT-": "OBSCNT-A",
    "LOG-AUD": "AUDIT-A",
    "CODE-SYSCHG": "CHANGE-A",
    "CODE-CLIENT": "CHANGE-A",
    "CODE-TMS": "CHANGE-A",
    "HOTNEWS-": "SECUPD-A",
    "HANADB-USER": "STDUSR-H",
    "HANADB-PRIV": "CRITAU-H",
    "HANADB-AUDIT": "AUDIT-H",
    "HANADB-PARAM": "PWDPOL-H",
    "CRYPTO-": "NETENC-A",
    "BTP-": "NETCF-P",
    # Verified by comparing SAP's requirement title against our check title:
    #   MSGSRV-A "File with access control list for message server" (store MS_SECINFO)
    #   SCRIPT-A "Scripting Protection profile parameter (sapgui/nwbc_scripting)"
    #   SSO-A    "Generate ticket only via https"
    #   NETENC-A "snc/enable (Profile Parameter, enable SNC-Module)"
    #   DISCL-A  "Disclosure of unnecessary information about versions or from errors"
    "TRUST-006": "MSGSRV-A",
    "TRUST-010": "MSGSRV-A",
    "BASELINE-004": "SCRIPT-A",
    "BASELINE-008": "SSO-A",
    "BASELINE-003": "NETENC-A",
    "BASELINE-009": "DISCL-A",
}


#: Path to the Web Dispatcher rule set, whose rows already name the SAP check
#: item each was transcribed from.
_WEBDISP_PATH = Path(__file__).resolve().parents[1] / "data" / "webdisp_baseline.json"
_EXACT_CACHE: Optional[Dict[str, str]] = None


#: Profile parameters SAP's own requirement titles do NOT name, mapped from the
#: policy predicate instead. PWDPOL-A's titles are prose — "Minimum password
#: length" — so a title-derived mapping cannot reach it, while the policy itself
#: is explicit.
#:
#: SOURCED, NOT GUESSED: docs/RISE_SECURITY_MODEL.md section 3.3 records the
#: `1APWDPOL.xml` predicates as `login/min_password_lng >= 0008`,
#: `login/password_max_idle_initial` and `login/password_downwards_compatibility`.
#: Kept deliberately short. A long hand-written list here would be exactly the
#: guessing the derivation replaced.
_PARAMETERS_FROM_PREDICATE: Dict[str, str] = {
    "login/min_password_lng": "PWDPOL-A",
    "login/password_max_idle_initial": "PWDPOL-A",
    "login/password_downwards_compatibility": "PWDPOL-A",
}

_PARAM_NAME = re.compile(r"\b([a-z][a-z0-9_]*(?:/[A-Za-z0-9_]+)+)")
_PARAM_CACHE: Optional[Dict[str, str]] = None


def parameter_requirements(catalogue: Optional[Dict[str, Any]] = None
                           ) -> Dict[str, str]:
    """`{profile parameter: SAP requirement}`, read out of SAP's own titles.

    WHY DERIVED. The prefix table cannot express this family: `PARAM-` ids carry
    the parameter name, and two parameters sharing that prefix belong to
    different requirements — `auth/check/calltransaction` to USRCTR-A,
    `snc/enable` to NETENC-A. A prefix guess produced `PARAM-PWD`, which matched
    none of the 81 ids for the whole life of the table.

    SAP's requirement titles name the parameter in most cases — "dynp/
    checkskip1screen (User Control Profile Parameter)" — so the mapping is read
    from the published content rather than assembled by hand. The handful whose
    titles are prose are listed above with the source that supplies them.
    """
    global _PARAM_CACHE
    if _PARAM_CACHE is None or catalogue is not None:
        cat = catalogue or load_catalogue()
        out: Dict[str, str] = dict(_PARAMETERS_FROM_PREDICATE)
        for req in cat.get("requirements", []):
            name = req.get("requirement")
            # ABAP requirements only. The Java and HANA technologies name the
            # same parameter (`ms/acl_info` is both RFCGW-A and RFCGW-J) and this
            # product's PARAM- family reads an ABAP profile.
            if not name or req.get("technology") != "ABAP":
                continue
            for title in req.get("titles") or ():
                for parameter in _PARAM_NAME.findall(title):
                    out.setdefault(parameter, name)
        if catalogue is not None:
            return out
        _PARAM_CACHE = out
    return _PARAM_CACHE


def requirement_exact() -> Dict[str, str]:
    """`{our check id: SAP requirement}` for checks that name their SAP check item.

    DERIVED, NOT TYPED. The prefix table below cannot express these: `WDISP-001`
    was transcribed from SAP check `DISCL-O_a.1` and `WDISP-014` from
    `NETENC-O.a1`, so two checks sharing a prefix belong to two different
    requirements. Reading the requirement out of the rule's own `sap_check_id` is
    both more precise and impossible to get wrong by hand — the rows already had
    to be right for the checks to fire.

    An unreadable rule file yields an empty map and the prefix table answers
    alone, which is where this started.
    """
    global _EXACT_CACHE
    if _EXACT_CACHE is None:
        out: Dict[str, str] = {}
        try:
            payload = json.loads(_WEBDISP_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        for rule in (payload.get("rules") or ()):
            ours, theirs = rule.get("check_id"), rule.get("sap_check_id") or ""
            # `DISCL-O_a.1` and `NETENC-O.a1` -> `DISCL-O`, `NETENC-O`.
            requirement = re.split(r"[._]", theirs)[0].strip().upper()
            if ours and requirement:
                out[str(ours).upper()] = requirement
        _EXACT_CACHE = out
    return _EXACT_CACHE


def requirement_for(check_id: str) -> Optional[str]:
    cid = (check_id or "").upper()
    # An exact match beats every prefix: it came from the check's own recorded
    # provenance, while a prefix is a generalisation about a family.
    exact = requirement_exact().get(cid)
    if exact:
        return exact
    # `PARAM-<parameter name>`: the parameter is the lookup key, and its case is
    # the profile's rather than upper.
    if cid.startswith("PARAM-"):
        parameter = (check_id or "")[len("PARAM-"):].strip()
        by_parameter = parameter_requirements()
        return (by_parameter.get(parameter)
                or by_parameter.get(parameter.lower()))
    best = ""
    req = None
    for prefix, requirement in CHECK_TO_REQUIREMENT.items():
        if cid.startswith(prefix) and len(prefix) > len(best):
            best, req = prefix, requirement
    return req


def coverage(check_ids: Iterable[str],
             catalogue: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """How our catalogue lines up against SAP's requirement vocabulary.

    Reports THREE numbers rather than one percentage, because a single percentage
    hides the interesting part:
      * requirements we map onto,
      * requirements SAP publishes that we do not address, and
      * our checks that map to no SAP requirement at all — which is not a failure.
        SoD, GRC, financial controls and the attack-path content have no Baseline
        equivalent, and that is precisely where the product goes beyond it.
    """
    cat = catalogue or load_catalogue()
    published = {r["requirement"]: r for r in cat.get("requirements", [])}

    mapped: Dict[str, List[str]] = {}
    unmapped: List[str] = []
    for cid in sorted(set(check_ids)):
        req = requirement_for(cid)
        if req and req in published:
            mapped.setdefault(req, []).append(cid)
        else:
            unmapped.append(cid)

    covered = sorted(mapped)
    not_covered = sorted(set(published) - set(covered))
    return {
        "baseline_version": cat.get("_meta", {}).get("baseline_version"),
        "requirements_published": len(published),
        "requirements_covered": len(covered),
        "covered": [{"requirement": r, "tier": published[r]["tier"],
                     "technology": published[r]["technology"],
                     "title": (published[r]["titles"] or [""])[0],
                     "our_checks": mapped[r]} for r in covered],
        "not_covered": [{"requirement": r, "tier": published[r]["tier"],
                         "technology": published[r]["technology"],
                         "title": (published[r]["titles"] or [""])[0]}
                        for r in not_covered],
        "beyond_baseline": unmapped,
        "note": cat.get("_meta", {}).get("unit_warning", ""),
    }
