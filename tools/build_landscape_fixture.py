# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Generate a synthetic THREE-SYSTEM SAP landscape: D01 -> T01 -> P01.

    python -m tools.build_landscape_fixture
    python sap_scanner.py --data-dir sample_data_landscape/P01 --output p01.html

WHY A LANDSCAPE AND NOT A THIRD SINGLE SYSTEM
`sample_data/` is one S/4HANA system and `sample_data_ecc/` is one ECC system.
Neither can exercise the thing this product is actually for: a **trust edge from
a lower tier into production**. That is the single most load-bearing fact the
attack-path engine derives, and until now no fixture contained one, so the
feature could only be tested with hand-built rows rather than demonstrated.

So the three systems are not three copies with different names. They tell one
story, and every risky row below is there because it is a pattern that shows up
in real estates:

    D01 (development)  least hardened. Developers hold SAP_ALL, debugging is on,
                       the Security Audit Log is off, SAP* is unlocked.
                       Its RFC destination to P01 stores a privileged credential.
    T01 (test)         a PRODUCTION COPY with masking switched off, so real
                       personal and financial data sits in a system with weaker
                       controls and a wider user population.
    P01 (production)   hardened, but not perfect — a real estate never is.

The attack path the landscape exists to make visible:

    a developer on D01  ->  RFC destination with a stored privileged credential
                        ->  P01, production, where they have no account at all

EVERY SAP IDENTIFIER HERE IS REAL. Parameter names come from the shipped rule
tables, profile names, standard users, RFC types and logged tables from the
existing fixtures. Nothing about SAP is invented — only the values a customer's
own system would supply. That distinction is the difference between synthetic
data and fabricated facts, and this repository forbids the second.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "sample_data_landscape"

SYSTEMS = ("P01", "T01", "D01")


# --------------------------------------------------------------------------- #
#  Profile parameters — the hardening gradient                                #
# --------------------------------------------------------------------------- #
#  Parameter NAMES are taken from the shipped rule tables; only the VALUES are
#  synthetic. P01 is broadly compliant, T01 has drifted, D01 is a development
#  system that nobody hardened — which is normal, and is exactly why a trust edge
#  out of it matters.

PARAMS: Dict[str, Dict[str, str]] = {
    "P01": {
        "login/min_password_lng": "15",
        "login/password_expiration_time": "90",
        "login/password_history_size": "10",
        "login/fails_to_user_lock": "5",
        "login/no_automatic_user_sapstar": "1",
        "login/disable_multi_gui_login": "1",
        "rsau/enable": "1",
        "rsau/integrity": "1",
        "auth/rfc_authority_check": "6",
        "auth/no_check_in_some_cases": "Y",
        "auth/object_disabling_active": "N",
        "gw/reg_no_conn_info": "255",
        "gw/acl_mode": "1",
        "abap/ext_debugging_possible": "0",
        "rfc/reject_expired_passwd": "1",
        "service/protectedwebmethods": "SDEFAULT",
        "icf/set_HTTPonly_flag_on_cookies": "1",
        "login/ticket_only_by_https": "1",
    },
    "T01": {
        # Drifted from production: shorter passwords, no expiry, audit log on but
        # without integrity protection, debugging left on after an investigation.
        "login/min_password_lng": "8",
        "login/password_expiration_time": "0",
        "login/password_history_size": "5",
        "login/fails_to_user_lock": "5",
        "login/no_automatic_user_sapstar": "1",
        "login/disable_multi_gui_login": "0",
        "rsau/enable": "1",
        "rsau/integrity": "0",
        "auth/rfc_authority_check": "6",
        "auth/no_check_in_some_cases": "Y",
        "auth/object_disabling_active": "N",
        "gw/reg_no_conn_info": "255",
        "gw/acl_mode": "1",
        "abap/ext_debugging_possible": "1",
        "rfc/reject_expired_passwd": "1",
        "service/protectedwebmethods": "SDEFAULT",
        "icf/set_HTTPonly_flag_on_cookies": "1",
        "login/ticket_only_by_https": "0",
    },
    "D01": {
        # A development system nobody hardened. The audit log is OFF, which is
        # what makes the RFC hop out of here so hard to reconstruct afterwards.
        "login/min_password_lng": "6",
        "login/password_expiration_time": "0",
        "login/password_history_size": "0",
        "login/fails_to_user_lock": "0",
        "login/no_automatic_user_sapstar": "0",
        "login/disable_multi_gui_login": "0",
        "rsau/enable": "0",
        "auth/rfc_authority_check": "0",
        "auth/no_check_in_some_cases": "N",
        "auth/object_disabling_active": "Y",
        "gw/reg_no_conn_info": "0",
        "gw/acl_mode": "0",
        "abap/ext_debugging_possible": "1",
        "rfc/reject_expired_passwd": "0",
        "service/protectedwebmethods": "NONE",
        "icf/set_HTTPonly_flag_on_cookies": "0",
        "login/ticket_only_by_https": "0",
    },
}

COMPONENTS = [("SAP_BASIS", "755", "0004"), ("SAP_ABA", "755", "0004"),
              ("SAP_GWFND", "755", "0004"), ("S4CORE", "105", "0002")]

#: (user, type, lock flag, last logon, created, password changed, group)
#: USTYP A = dialog, B = system, C = communication, S = service.
#: UFLAG 0 = not locked, 64 = locked by administrator.
USERS: Dict[str, List[Sequence[str]]] = {
    "P01": [
        ("M.OKAFOR",    "A", "0",  "20260810", "20230114", "20260612", "FINANCE"),
        ("S.LINDQVIST", "A", "0",  "20260811", "20220908", "20260701", "BASIS"),
        ("R.NAKAMURA",  "A", "0",  "20260808", "20240221", "20260520", "FINANCE"),
        ("A.DUBOIS",    "A", "64", "20250903", "20211102", "20250301", "HR"),
        ("BATCH_FI",    "B", "0",  "20260811", "20200615", "20240101", "SYSTEM"),
        ("RFC_T01_IN",  "C", "0",  "20260811", "20210301", "20240101", "SYSTEM"),
        ("RFC_D01_IN",  "C", "0",  "20260811", "20210301", "20220118", "SYSTEM"),
        ("SOLMAN_RFC",  "C", "0",  "20260811", "20200211", "20230401", "SYSTEM"),
    ],
    "T01": [
        ("M.OKAFOR",    "A", "0",  "20260807", "20230114", "20260612", "FINANCE"),
        ("S.LINDQVIST", "A", "0",  "20260811", "20220908", "20260701", "BASIS"),
        ("T.ABIODUN",   "A", "0",  "20260811", "20250107", "20260405", "TEST"),
        ("J.WEBER",     "A", "0",  "20260806", "20240612", "20251120", "TEST"),
        ("EXT_TESTER1", "A", "0",  "20260805", "20260201", "20260201", "EXTERNAL"),
        ("BATCH_FI",    "B", "0",  "20260811", "20200615", "20240101", "SYSTEM"),
        ("RFC_D01_IN",  "C", "0",  "20260811", "20210301", "20220118", "SYSTEM"),
    ],
    "D01": [
        ("S.LINDQVIST", "A", "0",  "20260811", "20220908", "20260701", "BASIS"),
        ("K.PETROV",    "A", "0",  "20260811", "20230405", "20240102", "DEVELOP"),
        ("L.MENSAH",    "A", "0",  "20260811", "20231110", "20240102", "DEVELOP"),
        ("H.YILMAZ",    "A", "0",  "20260809", "20250320", "20250320", "DEVELOP"),
        ("EXT_DEV_01",  "A", "0",  "20260811", "20260115", "20260115", "EXTERNAL"),
        ("EXT_DEV_02",  "A", "0",  "20260604", "20260115", "20260115", "EXTERNAL"),
        ("BATCH_DEV",   "B", "0",  "20260811", "20210801", "20210801", "SYSTEM"),
    ],
}

#: Profile assignments. SAP_ALL on a development system held by four people is
#: the ordinary case, not the exotic one — and it is what makes the RFC hop
#: below a privilege escalation rather than a lateral move.
PROFILES: Dict[str, List[Sequence[str]]] = {
    "P01": [("S.LINDQVIST", "S_A.SYSTEM"), ("BATCH_FI", "Z_BATCH_PROC"),
            ("RFC_T01_IN", "Z_RFC_LIMITED"), ("RFC_D01_IN", "SAP_ALL"),
            ("SOLMAN_RFC", "S_A.SYSTEM"), ("M.OKAFOR", "Z_FI_ADMIN")],
    "T01": [("S.LINDQVIST", "S_A.SYSTEM"), ("T.ABIODUN", "SAP_ALL"),
            ("BATCH_FI", "Z_BATCH_PROC"), ("RFC_D01_IN", "SAP_ALL"),
            ("EXT_TESTER1", "Z_FI_ADMIN")],
    "D01": [("S.LINDQVIST", "SAP_ALL"), ("K.PETROV", "SAP_ALL"),
            ("L.MENSAH", "SAP_ALL"), ("H.YILMAZ", "SAP_NEW"),
            ("EXT_DEV_01", "SAP_ALL"), ("EXT_DEV_02", "SAP_NEW"),
            ("BATCH_DEV", "Z_BATCH_PROC")],
}

ROLES: Dict[str, List[Sequence[str]]] = {
    "P01": [("M.OKAFOR", "Z_FI_POSTING"), ("M.OKAFOR", "Z_FI_MASTERDATA"),
            ("R.NAKAMURA", "Z_FI_POSTING"), ("S.LINDQVIST", "Z_BASIS_ADMIN"),
            ("A.DUBOIS", "Z_HR_PAYROLL")],
    "T01": [("T.ABIODUN", "Z_BASIS_ADMIN"), ("J.WEBER", "Z_FI_POSTING"),
            ("EXT_TESTER1", "Z_FI_POSTING"), ("EXT_TESTER1", "Z_FI_MASTERDATA"),
            ("M.OKAFOR", "Z_FI_POSTING")],
    "D01": [("K.PETROV", "Z_DEVELOPER"), ("L.MENSAH", "Z_DEVELOPER"),
            ("H.YILMAZ", "Z_DEVELOPER"), ("EXT_DEV_01", "Z_DEVELOPER"),
            ("EXT_DEV_02", "Z_DEVELOPER"), ("S.LINDQVIST", "Z_BASIS_ADMIN")],
}

#: THE POINT OF THE WHOLE FIXTURE.
#: RFCTYPE 3 = ABAP connection. RFCAUTH STORED = the destination carries a saved
#: credential, so anyone who can open it inherits that user's authorisations in
#: the TARGET system without holding an account there.
RFC_DESTINATIONS: Dict[str, List[Sequence[str]]] = {
    "P01": [
        ("SOLMAN_MONITOR", "3", "solman.acme.internal", "SOLMAN_RFC", "Y", "TRUSTED"),
        ("PAYROLL_IFACE",  "T", "payroll-gw.acme.internal", "", "Y", "CERT"),
    ],
    "T01": [
        ("P01_READBACK",   "3", "p01.acme.internal", "RFC_T01_IN", "N", "STORED"),
        ("SOLMAN_MONITOR", "3", "solman.acme.internal", "SOLMAN_RFC", "Y", "TRUSTED"),
    ],
    "D01": [
        # Development -> production, storing a credential whose user holds SAP_ALL
        # in P01. This is the edge the attack-path engine exists to surface.
        ("P01_TRANSPORT",  "3", "p01.acme.internal", "RFC_D01_IN", "N", "STORED"),
        ("T01_TESTDATA",   "3", "t01.acme.internal", "RFC_D01_IN", "N", "STORED"),
        ("GITHUB_PROXY",   "T", "proxy.acme.internal", "", "N", "BASIC"),
    ],
}

RFC_TRUST: Dict[str, List[Sequence[str]]] = {
    "P01": [("D01", "P01_TRANSPORT", "TRUSTED"), ("T01", "P01_READBACK", "STORED")],
    "T01": [("D01", "T01_TESTDATA", "STORED")],
    "D01": [],
}

#: PROD_COPY / DATA_MASKING is the T01 story: real data, weaker controls.
LANDSCAPE = {
    "P01": ("PRODUCTION", "CONFIDENTIAL", "NO",  "",    "RESTRICTED"),
    "T01": ("QUALITY",    "CONFIDENTIAL", "YES", "NO",  "STANDARD"),
    "D01": ("DEVELOPMENT", "INTERNAL",    "NO",  "",    "OPEN"),
}

#: T000 client settings. A production client that permits changes is the classic
#: SCC4 finding; D01 is open by design, which is correct for a dev system.
CLIENTS = {
    "P01": [("100", "PRODUCTION", "NO", "NO", "NO"),
            ("000", "SAP_REFERENCE", "NO", "NO", "NO")],
    "T01": [("200", "TEST", "YES", "NO", "NO"),
            ("000", "SAP_REFERENCE", "NO", "NO", "NO")],
    "D01": [("300", "CUSTOMIZING", "YES", "YES", "YES"),
            ("000", "SAP_REFERENCE", "YES", "YES", "YES")],
}

STANDARD_USERS = {
    "P01": [("SAP*", "100", "NO", "YES", "DIALOG"), ("DDIC", "100", "NO", "YES", "DIALOG"),
            ("EARLYWATCH", "000", "NO", "YES", "DIALOG"), ("TMSADM", "000", "NO", "YES", "SYSTEM")],
    "T01": [("SAP*", "200", "NO", "YES", "DIALOG"), ("DDIC", "200", "NO", "NO", "DIALOG"),
            ("EARLYWATCH", "000", "YES", "NO", "DIALOG"), ("TMSADM", "000", "NO", "YES", "SYSTEM")],
    "D01": [("SAP*", "300", "YES", "NO", "DIALOG"), ("DDIC", "300", "YES", "NO", "DIALOG"),
            ("EARLYWATCH", "000", "YES", "NO", "DIALOG"), ("SAPCPIC", "000", "YES", "NO", "COMMUNICATION"),
            ("TMSADM", "000", "NO", "NO", "SYSTEM")],
}

ICF = {
    "P01": [("/sap/public/info", "X", "YES"), ("/sap/bc/ping", "X", "YES"),
            ("/sap/bc/soap/rfc", "", ""), ("/sap/bc/webrfc", "", ""),
            ("/sap/bc/gui/sap/its/webgui", "X", "YES")],
    "T01": [("/sap/public/info", "X", "NO"), ("/sap/bc/ping", "X", "YES"),
            ("/sap/bc/soap/rfc", "X", "YES"), ("/sap/bc/webrfc", "", ""),
            ("/sap/bc/gui/sap/its/webgui", "X", "YES")],
    "D01": [("/sap/public/info", "X", "NO"), ("/sap/bc/ping", "X", "NO"),
            ("/sap/bc/soap/rfc", "X", "NO"), ("/sap/bc/webrfc", "X", "NO"),
            ("/sap/bc/gui/sap/its/webgui", "X", "NO"),
            ("/sap/bc/bsp/sap/it00", "X", "NO")],
}

AUDIT = {
    "P01": [("FILTER_01", "YES", "ALL", "*"), ("FILTER_02", "YES", "ALL", "100")],
    "T01": [("FILTER_01", "YES", "ALL", "*")],
    "D01": [],           # audit log off entirely — see rsau/enable = 0
}

LOGGED_TABLES = ["USR02", "USR04", "USR21", "AGR_USERS", "AGR_DEFINE", "RFCDES",
                 "T000", "BKPF", "KNA1", "LFA1", "PA0001", "PA0002"]

TRANSPORT_ROUTES = [("D01", "T01", "CONSOLIDATION"), ("T01", "P01", "DELIVERY")]


def _write(path: Path, header: Sequence[str], rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        n = 0
        for row in rows:
            w.writerow(row)
            n += 1
    return n


def build(sid: str) -> Dict[str, int]:
    d = OUT / sid
    wrote: Dict[str, int] = {}

    wrote["security_params.csv"] = _write(
        d / "security_params.csv", ("NAME", "VALUE"), sorted(PARAMS[sid].items()))
    wrote["system_component.csv"] = _write(
        d / "system_component.csv", ("COMPONENT", "RELEASE", "SP_LEVEL"), COMPONENTS)
    wrote["users.csv"] = _write(
        d / "users.csv",
        ("BNAME", "USTYP", "UFLAG", "TRDAT", "ERDAT", "PWDCHGDATE", "CLASS"),
        USERS[sid])
    wrote["profiles.csv"] = _write(
        d / "profiles.csv", ("BNAME", "PROFILE"), PROFILES[sid])
    wrote["user_roles.csv"] = _write(
        d / "user_roles.csv", ("UNAME", "AGR_NAME"), ROLES[sid])
    wrote["rfc_destinations.csv"] = _write(
        d / "rfc_destinations.csv",
        ("RFCDEST", "RFCTYPE", "RFCHOST", "RFCUSER", "RFCSNC", "RFCAUTH"),
        RFC_DESTINATIONS[sid])
    wrote["rfc_trust.csv"] = _write(
        d / "rfc_trust.csv", ("RFCTRUSTSY", "RFCDEST", "TRUST_METHOD"),
        RFC_TRUST[sid])
    env, cls, copy, mask, policy = LANDSCAPE[sid]
    wrote["system_landscape.csv"] = _write(
        d / "system_landscape.csv",
        ("SID", "ENVIRONMENT", "DATA_CLASSIFICATION", "PROD_COPY", "DATA_MASKING",
         "ACCESS_POLICY"),
        [(sid, env, cls, copy, mask, policy)])
    wrote["client_settings.csv"] = _write(
        d / "client_settings.csv",
        ("CLIENT", "ROLE", "CHANGES_ALLOWED", "CROSS_CLIENT_CHANGES",
         "REPOSITORY_CHANGES"), CLIENTS[sid])
    wrote["standard_users.csv"] = _write(
        d / "standard_users.csv",
        ("USER", "CLIENT", "DEFAULT_PASSWORD", "LOCKED", "USER_TYPE"),
        STANDARD_USERS[sid])
    wrote["icf_services.csv"] = _write(
        d / "icf_services.csv", ("ICF_NAME", "ICF_ACTIVE", "AUTH_REQUIRED"),
        ICF[sid])
    wrote["audit_config.csv"] = _write(
        d / "audit_config.csv", ("FILTER_NAME", "ACTIVE", "EVENT_CLASS", "CLIENT"),
        AUDIT[sid])
    # Production logs the sensitive tables; the lower tiers log fewer, which is
    # how a change made in D01 and transported up becomes hard to attribute.
    logged = LOGGED_TABLES if sid == "P01" else (
        LOGGED_TABLES[:6] if sid == "T01" else LOGGED_TABLES[:2])
    wrote["table_logging.csv"] = _write(
        d / "table_logging.csv", ("TABLE_NAME", "LOGGING"),
        [(t, "X" if t in logged else "") for t in LOGGED_TABLES])
    wrote["transport_routes.csv"] = _write(
        d / "transport_routes.csv", ("SOURCE", "TARGET", "TYPE"), TRANSPORT_ROUTES)

    # A completeness declaration ONLY where it is honest: these parameter files
    # are generated in full, so they genuinely are the complete list for the
    # system they describe. Absent it, the scanner would disclose the missing
    # parameters as gaps rather than judging them — see docs/EXPORT_GUIDE.md.
    (d / "export_completeness.json").write_text(json.dumps({
        "complete_sources": ["security_params"],
        "declared_by": f"tools/build_landscape_fixture.py ({sid})",
        "declared_at": "2026-08-12",
        "method": "generated fixture — the parameter list is written in full",
    }, indent=2) + "\n", encoding="utf-8")
    wrote["export_completeness.json"] = 1
    return wrote


def main() -> int:
    print(f"Building a synthetic three-system landscape in {OUT.relative_to(ROOT)}/\n")
    print("  D01 (development) --transport--> T01 (test) --transport--> P01 (production)")
    print("  D01 --RFC, stored credential--> P01      <- the edge that matters\n")
    total = 0
    for sid in SYSTEMS:
        wrote = build(sid)
        rows = sum(wrote.values())
        total += rows
        print(f"  {sid}: {len(wrote)} files, {rows} rows")
    print(f"\n  {total} rows across {len(SYSTEMS)} systems.")
    print("\nScan one with:")
    for sid in SYSTEMS:
        print(f"  python sap_scanner.py --data-dir sample_data_landscape/{sid} "
              f"--output {sid.lower()}.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
