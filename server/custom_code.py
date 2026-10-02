"""Custom Code: the ABAP/custom-code security posture, in one place.

MonitorRisk scans customer ABAP (an unpacked abapGit offline export) with a
statement-aware SAST engine, and — where the customer runs SAP's own Code
Vulnerability Analyzer / ATC — imports those verdicts too. Both land in the
generic Findings queue under one flat category ("Code & Transport Security"),
so the signal that makes a custom-code finding actionable (which weakness, which
Z-object, whether a taint walk *confirmed* it, whether it is reachable from the
internet, and whether it came from our scanner or SAP's) is invisible in
aggregate. This groups it into one "state of the custom code" view:

  * by WEAKNESS (CWE family), folding our native ABAP-* families and the imported
    ATC-* families of the same weakness together, each tagged with how many came
    from our scanner versus SAP's ATC;
  * the WORST OBJECTS — which custom programs/classes carry the most, worst-rated
    defects;
  * and a SCAN COVERAGE & TRUST section (the engine's own COV/LEX/NOSEC honesty
    checks plus whether ATC evidence was supplied), so an empty weakness reads as
    "not looked for" rather than "clean".

CONTENT, NOT CHECKS. This module emits no findings and defines no check ids; it
is a grouping of EXISTING check families by check-id prefix, for one screen. It
lives in server/ rather than modules/ deliberately, so it is not discovered as an
audit module and does not move the module / check counts.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: Severity buckets, worst first.
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Weakness groups. Each folds our native ABAP-* rule families and the imported
#: ATC-* families for the same weakness under one card, with the family's canonical
#: CWE (the same CWE already carried on those rules — not a new mapping). Prefixes
#: are matched with str.startswith; none is a prefix of another across groups, and
#: none collides with a TRUST prefix below.
GROUPS: List[Dict[str, Any]] = [
    {"id": "injection_sql", "label": "SQL & database injection", "cwe": "CWE-89",
     "prefixes": ("ABAP-SQLI", "ABAP-NSQL", "ABAP-AMDP", "ATC-SQLI"),
     "blurb": "Dynamic Open SQL (WHERE/FROM/ORDER BY), native SQL (EXEC SQL / "
              "ADBC) and AMDP SQLScript built from input that can reach the "
              "database verbatim."},
    {"id": "injection_code", "label": "Code injection & dynamic ABAP", "cwe": "CWE-94",
     "prefixes": ("ABAP-CINJ", "ABAP-DYNT", "ATC-CINJ"),
     "blurb": "Runtime-generated or dynamically dispatched ABAP — INSERT REPORT, "
              "GENERATE SUBROUTINE POOL, dynamic CALL FUNCTION/METHOD/TRANSACTION/"
              "TRANSFORMATION and dynamic internal-table operations."},
    {"id": "injection_os", "label": "OS command injection", "cwe": "CWE-78",
     "prefixes": ("ABAP-CMDI", "ATC-CMDI"),
     "blurb": "Operating-system commands from ABAP — CALL 'SYSTEM', SXPG_* "
              "function modules, OPEN DATASET/PIPE with FILTER, frontend execute."},
    {"id": "traversal", "label": "Directory traversal", "cwe": "CWE-22",
     "prefixes": ("ABAP-PATH", "ATC-PATH"),
     "blurb": "File paths built from input reaching OPEN/READ/DELETE DATASET, "
              "TRANSFER or frontend file services without validation."},
    {"id": "authorization", "label": "Missing & broken authorization", "cwe": "CWE-862",
     "prefixes": ("ABAP-AUTH", "ABAP-CDS", "ABAP-RAP", "ATC-AUTHCHK"),
     "blurb": "AUTHORITY-CHECK absent, stubbed with DUMMY or never tested against "
              "sy-subrc; CDS/RAP access control switched off or left open; DML with "
              "no authorization in front of it."},
    {"id": "web_output", "label": "Cross-site scripting & web output", "cwe": "CWE-79",
     "prefixes": ("ABAP-XSS", "ABAP-JS", "ATC-XSS"),
     "blurb": "Unescaped output to HTTP responses, HTML or UI5/JavaScript — "
              "set_cdata, response writers, innerHTML, document.write, eval."},
    {"id": "secrets", "label": "Hardcoded credentials & secrets", "cwe": "CWE-798",
     "prefixes": ("ABAP-CRED", "ATC-CRED"),
     "blurb": "Passwords, API keys, Basic-auth strings and RFC/BAPI logon "
              "credentials written into source."},
    {"id": "backdoor", "label": "Backdoor & malicious code", "cwe": "CWE-912",
     "prefixes": ("ABAP-BKDR",),
     "blurb": "Hardcoded SY-UNAME/SYSID/MANDT superuser checks, direct writes to "
              "user and authorization tables, SAP_ALL grants, programmatic user "
              "administration, debugging seams left in production."},
    {"id": "crypto", "label": "Weak cryptography", "cwe": "CWE-327",
     "prefixes": ("ABAP-CRYP", "ATC-CRYP"),
     "blurb": "MD5/SHA-1/DES, hardcoded keys or IVs, weak HMAC and non-cryptographic "
              "random number generation."},
    {"id": "interface", "label": "RFC & interface security", "cwe": "CWE-284",
     "prefixes": ("ABAP-RFC", "ATC-RFC"),
     "blurb": "Trusted-RFC calls, dynamic destinations, callbacks, registered "
              "server programs and asynchronous calls that cross a trust boundary."},
    {"id": "ssrf_xxe", "label": "SSRF & XML external entities", "cwe": "CWE-918",
     "prefixes": ("ABAP-SSRF", "ABAP-XXE"),
     "blurb": "HTTP clients built from a non-literal URL, and XML parsed without "
              "external entities disabled."},
    {"id": "config", "label": "Insecure configuration", "cwe": "CWE-16",
     "prefixes": ("ABAP-CONF", "ABAP-BTP"),
     "blurb": "Anonymous SSL, http:// endpoints, CSRF disabled, open redirects, "
              "obsolete statements, and BTP descriptors (xs-security/xs-app/mta, "
              "CDS @requires) that weaken authentication or authorization."},
    {"id": "info", "label": "Information disclosure", "cwe": "CWE-200",
     "prefixes": ("ABAP-INFO", "ATC-INFO"),
     "blurb": "Exceptions, break-points, system fields and sensitive-table reads "
              "that leak internal detail."},
]

#: Scan coverage & trust — not weaknesses, but they say whether the view above is
#: complete. Shown in their own section on the screen. ATC-GOV folds the importer's
#: governance findings (ATC not supplied; rows not classifiable as security).
HEALTH: List[Dict[str, Any]] = [
    {"id": "scan_coverage", "label": "Scan coverage",
     "prefixes": ("ABAP-COV", "ABAP-LEX"),
     "blurb": "Whether the scanner could read the source and parse it into whole "
              "ABAP statements. Unreadable paths, unscanned file types and a "
              "degraded lexer are blind spots, not clean results."},
    {"id": "suppression", "label": "Suppressed findings",
     "prefixes": ("ABAP-NOSEC",),
     "blurb": "Findings silenced by an in-source #NOSEC marker. The code can turn "
              "the scanner off from inside itself; this says how often it did."},
    {"id": "atc_evidence", "label": "SAP ATC / CVA evidence",
     "prefixes": ("ATC-GOV",),
     "blurb": "Whether SAP's own Code Vulnerability Analyzer / ATC results were "
              "supplied for the custom code, and whether every exported row could "
              "be classified."},
]

#: Catch-all so a custom-code finding is NEVER silently dropped: if a new ABAP-*/
#: ATC- family is added without being folded into a group above, its findings land
#: here (and tests/test_custom_code.py asserts this stays empty for known families).
_OTHER = {"id": "other", "label": "Other custom-code findings", "cwe": None,
          "prefixes": (), "blurb": "Custom-code findings not yet mapped to a "
          "weakness group above."}

_ALL = GROUPS + [_OTHER] + HEALTH
_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEV_RANK = {s: i for i, s in enumerate(_SEVERITIES)}


def provenance_for(check_id: Optional[str]) -> str:
    """"atc" for an imported SAP ATC/CVA finding, else "native" (our scanner)."""
    return "atc" if str(check_id or "").startswith("ATC-") else "native"


def group_for(check_id: Optional[str]):
    """(section, group_id) for a custom-code check id.

    section is "weakness" for a GROUPS family, "trust" for a HEALTH family, and
    "weakness"/"other" for an unmapped ABAP-*/ATC- id. GROUPS is checked before
    HEALTH so a weakness family is never caught by a trust prefix; the "other"
    fallback only applies to ids in the custom-code namespaces.
    """
    cid = str(check_id or "")
    for g in GROUPS:
        if cid.startswith(g["prefixes"]):
            return "weakness", g["id"]
    for h in HEALTH:
        if cid.startswith(h["prefixes"]):
            return "trust", h["id"]
    if cid.startswith(("ABAP-", "ATC-")):
        return "weakness", "other"
    return None, None


def _empty(g: Dict[str, Any]) -> Dict[str, Any]:
    out = {"id": g["id"], "label": g["label"], "blurb": g["blurb"],
           "counts": {s: 0 for s in _SEVERITIES}, "total": 0,
           "native": 0, "atc": 0, "findings": []}
    if "cwe" in g:
        out["cwe"] = g["cwe"]
    return out


def _rank(f: Dict[str, Any]):
    return (_TIER_RANK.get(str(f.get("priority_tier") or ""), 9),
            _SEV_RANK.get(str(f.get("severity") or "").upper(), 9),
            str(f.get("check_id") or ""))


def normalize(row: Dict[str, Any]) -> Dict[str, Any]:
    """Map a raw DB row (with jsonb affected_objects/details) to the flat shape
    roll_up consumes. Idempotent: a row that already carries the flat keys passes
    through, so tests can build normalized rows directly."""
    obj = row.get("object")
    # `subject` is what the query returns ([{type,name,...}]); affected_objects is
    # accepted as a fallback so a test can build a row either way.
    if obj is None:
        for key in ("subject", "affected_objects"):
            seq = row.get(key)
            if isinstance(seq, list) and seq and isinstance(seq[0], dict):
                obj = seq[0].get("name")
                if obj:
                    break
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    confidence = row.get("confidence", details.get("confidence"))
    exposed = row.get("internet_exposed", details.get("internet_exposed"))
    return {
        "id": row.get("id"), "check_id": row.get("check_id"),
        "severity": row.get("severity"), "priority_tier": row.get("priority_tier"),
        "title": row.get("title"), "category": row.get("category"),
        "sid": row.get("sid"), "state": row.get("state"),
        "object": obj, "confidence": confidence, "internet_exposed": exposed,
    }


def _worst_objects(rows: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    """Custom programs/classes ranked by how many, and how severe, their defects
    are. Weakness findings only — a coverage note is not an object's fault."""
    by: Dict[str, Dict[str, Any]] = {}
    for f in rows:
        name = f.get("object")
        if not name:
            continue
        o = by.setdefault(name, {"name": name, "total": 0,
                                 "counts": {s: 0 for s in _SEVERITIES},
                                 "native": 0, "atc": 0})
        o["total"] += 1
        sev = str(f.get("severity") or "").upper()
        if sev in o["counts"]:
            o["counts"][sev] += 1
        o[provenance_for(f.get("check_id"))] += 1
    ranked = sorted(
        by.values(),
        key=lambda o: tuple(-o["counts"][s] for s in _SEVERITIES) + (-o["total"],),
    )
    for o in ranked:
        o["worst"] = next((s for s in _SEVERITIES if o["counts"][s]), None)
    return ranked[:limit]


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Group custom-code findings into weakness groups and the trust section.

    `findings` is the projection queries.custom_code_findings returns (raw or
    already normalized — see `normalize`). Rows outside the ABAP-*/ATC- namespaces
    are ignored; an unmapped custom-code family lands in the "other" group so it is
    never lost. `coverage` supplies the `measured` timestamp, as on other screens.
    """
    rows = [normalize(f) for f in findings]
    buckets = {g["id"]: _empty(g) for g in _ALL}

    for f in rows:
        section, gid = group_for(f.get("check_id"))
        if gid is None:
            continue
        b = buckets[gid]
        b["findings"].append({
            "id": f.get("id"), "check_id": f.get("check_id"),
            "severity": f.get("severity"), "priority_tier": f.get("priority_tier"),
            "title": f.get("title"), "object": f.get("object"),
            "sid": f.get("sid"), "state": f.get("state"),
            "provenance": provenance_for(f.get("check_id")),
            "confidence": f.get("confidence"),
            "internet_exposed": f.get("internet_exposed"),
        })
        b["total"] += 1
        b[provenance_for(f.get("check_id"))] += 1
        sev = str(f.get("severity") or "").upper()
        if sev in b["counts"]:
            b["counts"][sev] += 1

    for b in buckets.values():
        b["findings"].sort(key=_rank)

    groups = [buckets[g["id"]] for g in GROUPS]
    # The catch-all is only surfaced when it actually caught something.
    if buckets["other"]["total"]:
        groups = groups + [buckets["other"]]
    health = [buckets[h["id"]] for h in HEALTH]

    weakness_rows = [f for f in rows
                     if group_for(f.get("check_id"))[0] == "weakness"]

    confidence = {"confirmed": 0, "tentative": 0, "unknown": 0}
    exposure = {"exposed": 0, "internal": 0, "unknown": 0}
    for f in weakness_rows:
        c = str(f.get("confidence") or "").lower()
        confidence[c if c in ("confirmed", "tentative") else "unknown"] += 1
        e = f.get("internet_exposed")
        exposure["exposed" if e is True else
                  "internal" if e is False else "unknown"] += 1

    return {
        "groups": groups,
        "health": health,
        "objects": _worst_objects(weakness_rows),
        "measured": (coverage or {}).get("measured"),
        "totals": {
            "findings": sum(g["total"] for g in groups),
            "trust": sum(h["total"] for h in health),
            "objects": len({f["object"] for f in weakness_rows if f.get("object")}),
            "counts": {s: sum(g["counts"][s] for g in groups) for s in _SEVERITIES},
            "provenance": {
                "native": sum(f["check_id"].startswith("ABAP-")
                              for f in weakness_rows if f.get("check_id")),
                "atc": sum(provenance_for(f.get("check_id")) == "atc"
                           for f in weakness_rows),
            },
            "confidence": confidence,
            "exposure": exposure,
        },
    }
