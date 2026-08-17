# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""OWASP and ASVS mapping, by derivation where possible and by judgement where not.

WHY THIS IS NOT ONE BIG TABLE OF GUESSES

The obvious way to do this is to walk the 673 checks and assign each an OWASP
category by reading its name. That would produce a complete-looking mapping in an
afternoon and it would be a guess wearing a mapping's clothes — the compliance
panel would show 100% coverage of the Top 10 and none of it would be evidence.

So there are three routes, and every mapped finding records WHICH ONE put it
there, in `basis`:

  "cwe"        The check carries a CWE and OWASP publishes the CWE list for that
               category. This is derivation, not opinion: the mapping is OWASP's.
               135 code rules carry a CWE.
  "family"     A curated judgement about a check family whose security property
               is unambiguous — ARA-* is segregation of duties, so A01. Each one
               carries its reasoning in the table below and is a claim this
               product is making, not one it inherited.
  None         No honest mapping exists. Declared, counted, and reported.

THE UNMAPPED BUCKET IS NOT A GAP TO BE CLOSED

Several of this product's subject areas have no OWASP equivalent and never will.
RISE shared-responsibility findings are about a contract. ECS mandatory
configuration is about one vendor's baseline. FAIR loss scenarios are about
money. Forcing them into A05 "Security Misconfiguration" because everything
unclassifiable eventually lands there would make the category meaningless and the
coverage figure a lie. They stay unmapped and the report says so.

WHAT IS DELIBERATELY NOT DONE HERE: CVSS

The SRS asks for a CVSS vector on every finding. CVSS scores a vulnerability in a
product — it has Attack Vector, Attack Complexity, Privileges Required. "This
subaccount has no audit logging" has none of those; it is a control gap, not a
vulnerability, and inventing a vector for it would manufacture precision that
does not exist. CVEs in this product DO carry real vectors, taken from the SAP
CNA record (see data/cve_exposure.json). Configuration findings carry severity
and business context instead, which is what they actually have.

Sources: OWASP Top 10:2021 category CWE lists; OWASP API Security Top 10:2023;
OWASP ASVS 4.0 chapter structure.
"""

from typing import Any, Dict, List, Optional, Tuple

#: OWASP Top 10:2021.
TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

#: OWASP API Security Top 10:2023.
API10 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

#: ASVS 4.0 chapters, at chapter granularity. Requirement-level mapping would be
#: a much larger claim than this product can support: an ASVS requirement is a
#: verification activity, and asserting that one check verifies one requirement
#: needs the requirement text read against the check. Chapter level is what the
#: evidence supports.
ASVS = {
    "V1": "Architecture, Design and Threat Modeling",
    "V2": "Authentication",
    "V3": "Session Management",
    "V4": "Access Control",
    "V5": "Validation, Sanitization and Encoding",
    "V6": "Stored Cryptography",
    "V7": "Error Handling and Logging",
    "V8": "Data Protection",
    "V9": "Communication",
    "V10": "Malicious Code",
    "V12": "File and Resources",
    "V13": "API and Web Service",
    "V14": "Configuration",
}

#: CWE -> (Top 10, API Top 10, ASVS). Taken from the CWE lists OWASP publishes
#: WITH each Top 10:2021 category, so this half of the mapping is derivation
#: rather than opinion. A CWE this product uses that does not appear in any
#: published list is in UNMAPPED_CWE below rather than forced into the nearest
#: category.
CWE_TO_OWASP: Dict[str, Tuple[str, Optional[str], str]] = {
    # A01 Broken Access Control
    "CWE-22":  ("A01", "API1", "V12"),   # path traversal
    "CWE-200": ("A01", "API3", "V8"),    # information exposure
    "CWE-269": ("A01", "API5", "V4"),    # improper privilege management
    "CWE-284": ("A01", "API5", "V4"),    # improper access control
    # CWE-359 is the parent CWE-200's personal-data case, and MITRE's own entry
    # records its membership of "OWASP Top Ten 2021 Category A01:2021 - Broken
    # Access Control", so this is inherited and not inferred. It takes the same
    # API and ASVS columns as CWE-200 because it is the narrower form of it.
    "CWE-359": ("A01", "API3", "V8"),    # personal information exposure
    "CWE-601": ("A01", None,   "V5"),    # open redirect
    "CWE-862": ("A01", "API1", "V4"),    # missing authorization
    "CWE-863": ("A01", "API1", "V4"),    # incorrect authorization
    "CWE-913": ("A01", None,   "V10"),   # dynamically-managed code resources
    # A02 Cryptographic Failures
    "CWE-319": ("A02", None,   "V9"),    # cleartext transmission
    "CWE-327": ("A02", None,   "V6"),    # broken/risky algorithm
    "CWE-330": ("A02", None,   "V6"),    # insufficiently random values
    # A03 Injection
    "CWE-78":  ("A03", None,   "V5"),    # OS command injection
    "CWE-79":  ("A03", None,   "V5"),    # cross-site scripting
    "CWE-89":  ("A03", None,   "V5"),    # SQL injection
    "CWE-94":  ("A03", None,   "V5"),    # code injection
    "CWE-95":  ("A03", None,   "V5"),    # eval injection
    # A05 Security Misconfiguration
    "CWE-16":  ("A05", "API8", "V14"),   # configuration
    "CWE-547": ("A05", "API8", "V14"),   # hardcoded security-relevant constants
    "CWE-611": ("A05", "API8", "V5"),    # XML external entity
    # A07 Identification and Authentication Failures
    "CWE-287": ("A07", "API2", "V2"),    # improper authentication
    "CWE-798": ("A07", "API2", "V2"),    # hardcoded credentials
    # A10 SSRF
    "CWE-918": ("A10", "API7", "V13"),   # server-side request forgery
}

#: CWEs this product uses that OWASP does not list under any Top 10:2021
#: category. Recorded with the reason rather than assigned to the nearest
#: plausible one, because "everything unclassifiable becomes A05" is how a
#: category stops meaning anything.
UNMAPPED_CWE: Dict[str, str] = {
    "CWE-477": "Use of Obsolete Function — a maintainability and lifecycle "
               "property. A06 is about vulnerable DEPENDENCIES, not deprecated "
               "language constructs, and OWASP lists neither.",
    "CWE-489": "Active Debug Code — plausibly A05, but it appears in no "
               "published Top 10:2021 CWE list and the resemblance is not "
               "evidence.",
    "CWE-912": "Hidden Functionality — a backdoor. A08 concerns integrity of "
               "software and data in the supply chain; deliberately concealed "
               "behaviour in first-party code is a different thing and OWASP "
               "does not list it.",
    "CWE-1022": "Use of Web Link to Untrusted Target — listed under neither "
                "A01 nor A04 in 2021.",
}

#: Curated family mappings for the checks that carry no CWE — the configuration,
#: authorization and process checks. Each entry states WHY, because unlike the
#: CWE half this is a claim this product is making rather than one it inherited.
#: A family absent from this table is unmapped and counted as such.
FAMILY_TO_OWASP: Dict[str, Tuple[str, Optional[str], str, str]] = {
    "AUTH":      ("A01", "API5", "V4", "ABAP authorization objects decide who may perform which action"),
    "ARA":       ("A01", "API5", "V4", "segregation-of-duties conflicts are access control by definition"),
    "S4AUTHZ":   ("A01", "API5", "V4", "business roles, catalogs and CDS access control"),
    "RG":        ("A01", None,   "V4", "role design and derivation govern what access is delivered"),
    "GRC":       ("A01", None,   "V4", "emergency access and access-request approval are access control process"),
    "IAM":       ("A01", "API5", "V4", "identity and entitlement management"),
    "CAPX":      ("A01", "API5", "V4", "CAP/XSUAA authorization: scope to role to collection to user"),
    "USR":       ("A07", "API2", "V2", "user master, password policy and lock state are authentication"),
    "STDUSR":    ("A07", "API2", "V2", "standard users with default credentials"),
    "TRUST":     ("A07", "API2", "V2", "trusted-RFC relationships are an authentication mechanism"),
    "CRYPTO":    ("A02", None,   "V6", "TLS, SNC, certificates and key management"),
    "LOG":       ("A09", None,   "V7", "audit log configuration, retention and SIEM forwarding"),
    "LREV":      ("A09", None,   "V7", "retrospective review of what the audit log actually recorded"),
    "NET":       ("A05", "API8", "V14", "exposed services and network-level configuration"),
    "INTG":      ("A05", "API8", "V13", "integration surface: APIs, IDoc ports, web services"),
    "FIORI":     ("A01", "API1", "V4", "catalog, tile and OData authorization at the UI layer"),
    "HANADB":    ("A01", None,   "V4", "database privileges, roles and auditing"),
    "PARAM":     ("A05", "API8", "V14", "profile parameters are the system's security configuration"),
    "BASELINE":  ("A05", "API8", "V14", "SAP Security Baseline profile parameters"),
    "BTP":       ("A05", "API8", "V14", "BTP subaccount, destination and connectivity configuration"),
    "DPP":       ("A01", "API3", "V8", "read access logging, masking and data-subject controls"),
    "CODE":      ("A08", None,   "V1", "transport and change control are software integrity"),
    "ATC":       ("A03", None,   "V5", "imported ABAP Test Cockpit code findings"),
    "HOTNEWS":   ("A06", None,   "V14", "unpatched vendor components with known CVEs"),
}

#: Families deliberately left unmapped, with the reason. This is the list that
#: keeps the coverage figure honest, and it is expected to stay non-empty.
UNMAPPED_FAMILY: Dict[str, str] = {
    "RISE": "shared-responsibility findings are about which party a CONTRACT "
            "makes accountable. There is no application-security category for "
            "'SAP owns this one'.",
    "FIN":  "SOX financial-configuration controls — posting periods, tolerance "
            "groups, document-change rules. A financial control framework, not "
            "an application-security one.",
    "MDC":  "master-data change auditing: a fraud-detection and evidence "
            "control, adjacent to A09 but not a logging-configuration failure.",
    "VBM":  "vendor and bank master integrity — a payment-fraud signal, outside "
            "the web-application threat model the Top 10 describes.",
    "RES":  "backup, disaster recovery and ransomware readiness. Availability "
            "and continuity, which the Top 10 does not cover.",
    "JOBCMD": "background jobs and OS command definitions — closest to A01, but "
              "the finding is about what is SCHEDULED rather than who may act, "
              "and stretching A01 to cover it would blur the category.",
    "SNC":  "the SNC family is reported separately from CRYPTO and is an "
            "ECS-mandated configuration set; mapped through CRYPTO where the "
            "prefix resolves, otherwise left alone rather than double-counted.",
    "ECS":  "SAP's own mandatory cloud-services baseline. A vendor requirement, "
            "not an OWASP category.",
}


def _family(check_id: str) -> str:
    """The family prefix of a check id: `ABAP-SQLI-001` -> `ABAP`, `USR-003` -> `USR`."""
    return str(check_id or "").split("-", 1)[0].strip().upper()


def map_finding(check_id: str, cwe: Optional[str] = None) -> Dict[str, Any]:
    """OWASP / ASVS mapping for one finding, with the basis it rests on.

    CWE first, because that half is OWASP's own published derivation and a
    curated family guess must never override it. `basis` is always present so a
    reader — and the coverage statement — can tell the two apart.
    """
    key = str(cwe or "").strip().upper()
    if key and key in CWE_TO_OWASP:
        top, api, asvs = CWE_TO_OWASP[key]
        return {"owasp_top10": top, "owasp_top10_name": TOP10[top],
                "owasp_api": api, "owasp_api_name": API10.get(api or ""),
                "asvs": asvs, "asvs_name": ASVS[asvs],
                "basis": "cwe", "cwe": key}
    if key and key in UNMAPPED_CWE:
        return {"basis": None, "cwe": key, "unmapped_reason": UNMAPPED_CWE[key]}

    fam = _family(check_id)
    if fam in FAMILY_TO_OWASP:
        top, api, asvs, why = FAMILY_TO_OWASP[fam]
        return {"owasp_top10": top, "owasp_top10_name": TOP10[top],
                "owasp_api": api, "owasp_api_name": API10.get(api or ""),
                "asvs": asvs, "asvs_name": ASVS[asvs],
                "basis": "family", "family_rationale": why}
    if fam in UNMAPPED_FAMILY:
        return {"basis": None, "unmapped_reason": UNMAPPED_FAMILY[fam]}
    return {"basis": None,
            "unmapped_reason": "no OWASP mapping has been curated for the %s "
                               "family" % (fam or "unnamed")}


def _rule_cwes() -> Dict[str, str]:
    """check id -> CWE, for every code rule that declares one.

    The rule tables are static, so the CWE a code finding will carry is knowable
    without running a scan. Without this the coverage figure counted 143 ABAP
    checks as unmapped when every one of them resolves through its CWE the
    moment it fires — a floor so far below the truth that it would have made the
    mapping look far worse than it is, and understating coverage misleads a
    reader just as surely as overstating it, only in the other direction.
    """
    from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,
                                   ALL_JS_RULES, CROSS_ARTIFACT_RULES)
    out: Dict[str, str] = {}
    for table in (ALL_ABAP_SAST_RULES, ALL_JS_RULES, ALL_BTP_CONFIG_RULES,
                  CROSS_ARTIFACT_RULES):
        for rule in table:
            rid, cwe = rule.get("id"), rule.get("cwe")
            if rid and cwe:
                out[str(rid)] = str(cwe).strip().upper()
    return out


def coverage() -> Dict[str, Any]:
    """How much of the check catalogue carries an OWASP mapping, and on what basis.

    Imported lazily inside the function so this module stays a pure mapping
    library that `modules/coverage.py` can be measured against without a cycle.
    """
    from modules.coverage import all_check_ids

    ids = sorted({c for v in all_check_ids().values() for c in v})
    cwes = _rule_cwes()
    by_basis = {"cwe": 0, "family": 0, "unmapped": 0}
    unmapped_families: Dict[str, int] = {}
    for check in ids:
        result = map_finding(check, cwes.get(check))
        basis = result.get("basis")
        if basis:
            by_basis[basis] += 1
        else:
            by_basis["unmapped"] += 1
            fam = _family(check)
            unmapped_families[fam] = unmapped_families.get(fam, 0) + 1
    return {
        "checks": len(ids),
        "by_basis": by_basis,
        "unmapped_families": dict(sorted(unmapped_families.items(),
                                         key=lambda kv: (-kv[1], kv[0]))),
        "note": "every check id in the catalogue, with code rules resolved "
                "through the CWE their rule table declares",
    }
