"""
Security Baseline Parameter Compliance Auditor
================================================
Checks the SAP profile parameters from the **SAP Security Baseline Template /
CIS / DSAG** that the other modules do not already cover — the authorization
engine, SNC insecure-fallback, SAP GUI scripting, weak legacy password hashes,
sapstartsrv/Host-Agent web methods, gateway ACL mode, SSO ticket/cookie
transport, and the ICM security log / error disclosure.

(Password length/complexity/expiry live in Security Parameters; snc/enable and
data-protection in Cryptographic Posture; message-server and gw/prxy_info in
System Trust; auth/object_disabling_active in ABAP Authorization — this module
deliberately avoids those.)

Data source:
  - security_params.csv → RSPARAM / RZ11 profile parameter export (NAME, VALUE)
"""

import re
from typing import Dict, List, Any, Optional
from modules.base_auditor import BaseAuditor


class BaselineParamAuditor(BaseAuditor):

    CATEGORY = "Security Baseline Parameters"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._params = self._param_index()
        if not self._params:
            return self.findings  # no profile-parameter export → self-skip
        self.check_rfc_authority_check()
        self.check_no_check_in_some_cases()
        self.check_snc_accept_insecure()
        self.check_gui_scripting()
        self.check_password_downwards_compat()
        self.check_protected_webmethods()
        self.check_gateway_acl_mode()
        self.check_sso_ticket_cookie()
        self.check_icm_security_log()
        self.check_password_compliance()
        return self.findings

    # ------------------------------------------------------------------ helpers
    def _param_index(self) -> Dict[str, str]:
        idx = {}
        for row in (self.data.get("security_params") or []):
            if not isinstance(row, dict):
                continue
            name = str(row.get("NAME", row.get("PARAMETER", row.get("PARAM", "")))).strip().lower()
            value = str(row.get("VALUE", row.get("PARAM_VALUE", row.get("VAL", "")))).strip()
            if name:
                idx[name] = value
        return idx

    def _p(self, name: str) -> Optional[str]:
        return self._params.get(name.lower())

    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "true", "yes", "on", "x")

    def _flag(self, check_id, title, severity, description, affected, remediation, references):
        self.finding(check_id=check_id, title=title, severity=severity, category=self.CATEGORY,
                     description=description, affected_items=affected, remediation=remediation,
                     references=references)

    # --------------------------------------------------------------------- checks
    def check_rfc_authority_check(self):
        v = self._p("auth/rfc_authority_check")
        if v is not None and v.strip() == "0":
            self._flag(
                "BASELINE-001", "RFC authorization check disabled (auth/rfc_authority_check)",
                self.SEVERITY_HIGH,
                "auth/rfc_authority_check = 0 disables the S_RFC authorization check on RFC "
                "function-module calls, so any authenticated user (or trusted-RFC caller) can "
                "invoke any RFC-enabled function module regardless of authorizations.",
                [f"auth/rfc_authority_check = {v}"],
                "Set auth/rfc_authority_check = 9 so the S_RFC authorization check is enforced "
                "for all called function modules on RFC calls.",
                ["SAP Security Baseline — auth/rfc_authority_check", "SAP Note 93254"])

    def check_no_check_in_some_cases(self):
        v = self._p("auth/no_check_in_some_cases")
        if v is not None and v.strip().upper() == "N":
            self._flag(
                "BASELINE-002", "Profile-generator authorization checks not active (auth/no_check_in_some_cases)",
                self.SEVERITY_HIGH,
                "auth/no_check_in_some_cases = N deactivates evaluation of the SU24 check "
                "indicators by the Profile Generator (PFCG), weakening how authorization "
                "defaults are derived for roles. The Baseline requires Y.",
                [f"auth/no_check_in_some_cases = {v}"],
                "Set auth/no_check_in_some_cases = Y so SU24 check indicators drive role "
                "authorization defaults (and transaction SU25 is maintained).",
                ["SAP Security Baseline — auth/no_check_in_some_cases"])

    def check_snc_accept_insecure(self):
        params = ["snc/accept_insecure_rfc", "snc/accept_insecure_gui",
                  "snc/accept_insecure_cpic", "snc/accept_insecure_r3int_rfc"]
        offenders = [f"{p} = {self._p(p)}" for p in params
                     if self._p(p) is not None and self._p(p).strip() in ("1", "u")]
        if offenders:
            self._flag(
                "BASELINE-003", "SNC accepts insecure (unencrypted) connections",
                self.SEVERITY_HIGH,
                f"{len(offenders)} snc/accept_insecure_* parameter(s) allow unencrypted "
                "RFC/GUI/CPIC connections even though SNC is enabled — defeating SNC, since a "
                "client can simply connect without encryption.",
                offenders,
                "Set the snc/accept_insecure_* parameters to 0 so only SNC-protected "
                "connections are accepted (after all clients/servers support SNC).",
                ["SAP Security Baseline — SNC insecure connections", "SAP Note 1690662"])

    def check_gui_scripting(self):
        v = self._p("sapgui/user_scripting")
        if v is not None and self._truthy(v):
            self._flag(
                "BASELINE-004", "SAP GUI Scripting enabled server-side (sapgui/user_scripting)",
                self.SEVERITY_HIGH,
                "sapgui/user_scripting = TRUE enables the SAP GUI Scripting API server-side, "
                "which lets automated scripts drive the GUI to extract data / credentials and "
                "replay user actions — a data-exfiltration and automation risk.",
                [f"sapgui/user_scripting = {v}"],
                "Set sapgui/user_scripting = FALSE unless a specific automation use case "
                "requires it; if enabled, restrict via sapgui/user_scripting_per_user and "
                "disable notification suppression.",
                ["SAP Security Baseline — SAP GUI Scripting",
                 "SAP Note 480149 (introduces sapgui/user_scripting)",
                 "SAP Note 692245 (server-side scripting security options)"])

    def check_password_downwards_compat(self):
        v = self._p("login/password_downwards_compatibility")
        if v is not None:
            try:
                if int(v.strip()) > 0:
                    self._flag(
                        "BASELINE-005", "Weak legacy password hashes retained (login/password_downwards_compatibility)",
                        self.SEVERITY_HIGH,
                        f"login/password_downwards_compatibility = {v} (> 0) keeps generating the "
                        "downward-compatible, weak password hash (CODVN B/D, MD5-based) in "
                        "USR02/BCODE alongside the strong hash. The weak hash is easily cracked "
                        "offline, so the strong hash provides no protection.",
                        [f"login/password_downwards_compatibility = {v}"],
                        "Once all connected systems support the current code version, set "
                        "login/password_downwards_compatibility = 0 and remove old BCODE/PASSCODE "
                        "hashes (report CLEANUP_PASSWORD_HASH_VALUES).",
                        ["SAP Security Baseline — Password hashes", "SAP Note 1023437"])
            except ValueError:
                pass

    def check_protected_webmethods(self):
        v = self._p("service/protectedwebmethods")
        val = (v or "").strip().lower()
        # SDEFAULT (recommended) and ALL (stricter) both protect the sensitive methods;
        # NONE / empty / a reduced custom list leave them exposed.
        if v is not None and "sdefault" not in val and val != "all":
            self._flag(
                "BASELINE-006", "sapstartsrv / Host Agent web methods not protected (service/protectedwebmethods)",
                self.SEVERITY_HIGH,
                f"service/protectedwebmethods = '{v}' — not the recommended SDEFAULT. The "
                "unprotected SOAP web methods of sapstartsrv / SAP Host Agent (Start/Stop, "
                "ReadLogFile, ABAPGetTraceFile, GetProcessList, …) are then callable at OS level, "
                "leaking logs/traces and allowing instance control.",
                [f"service/protectedwebmethods = {v}"],
                "Set service/protectedwebmethods = SDEFAULT (optionally extended) so the "
                "sensitive administrative web methods require authentication.",
                ["SAP Security Baseline — service/protectedwebmethods", "SAP Note 1439348"])

    def check_gateway_acl_mode(self):
        v = self._p("gw/acl_mode")
        if v is not None and v.strip() == "0":
            self._flag(
                "BASELINE-007", "RFC Gateway default ACL not enforced (gw/acl_mode)",
                self.SEVERITY_MEDIUM,
                "gw/acl_mode = 0 leaves the RFC Gateway permissive when no secinfo/reginfo ACL "
                "files exist, allowing rogue external programs to register with the gateway — the "
                "misconfiguration class behind the 10KBLAZE RFC-gateway RCE (CISA AA19-122A; no "
                "CVE — addressed by secinfo/reginfo ACLs).",
                [f"gw/acl_mode = {v}"],
                "Set gw/acl_mode = 1 to enforce the restrictive default gateway behaviour, and "
                "maintain explicit secinfo / reginfo ACL files.",
                ["SAP Security Baseline — gw/acl_mode", "SAP Note 1408081",
                 "CISA AA19-122A (10KBLAZE)"])

    def check_sso_ticket_cookie(self):
        offenders = []
        https = self._p("login/ticket_only_by_https")
        if https is not None and https.strip() == "0":
            offenders.append("login/ticket_only_by_https = 0 (SSO ticket sent over plain HTTP — sniffable)")
        httponly = self._p("icf/set_HTTPonly_flag_on_cookies")
        if httponly is not None and httponly.strip() not in ("0", ""):
            offenders.append(f"icf/set_HTTPonly_flag_on_cookies = {httponly} (HttpOnly not set on all ICF cookies)")
        to_host = self._p("login/ticket_only_to_host")
        if to_host is not None and to_host.strip() == "0":
            offenders.append("login/ticket_only_to_host = 0 (ticket accepted by other hosts)")
        if offenders:
            self._flag(
                "BASELINE-008", "SSO ticket / session-cookie transport not hardened",
                self.SEVERITY_MEDIUM,
                f"{len(offenders)} SSO/cookie transport parameter(s) are weak. Logon/assertion "
                "tickets (MYSAPSSO2) and ICF session cookies can then be intercepted or reused, "
                "enabling session hijacking.",
                offenders,
                "Set login/ticket_only_by_https = 1, icf/set_HTTPonly_flag_on_cookies = 0 "
                "(HttpOnly on all cookies), and login/ticket_only_to_host = 1.",
                ["SAP Security Baseline — SSO ticket / cookie hardening"])

    def check_icm_security_log(self):
        offenders = []
        seclog = self._p("icm/security_log")
        if seclog is not None:
            m = re.search(r"level\s*=\s*(\d+)", seclog, re.IGNORECASE)
            level = int(m.group(1)) if m else (None if seclog.strip() else 0)
            if seclog.strip() == "" or (level is not None and level < 3):
                offenders.append(f"icm/security_log = '{seclog or '(empty)'}' (log level < 3 / not configured)")
        errors = self._p("is/http/show_detailed_errors")
        if errors is not None and self._truthy(errors):
            offenders.append(f"is/HTTP/show_detailed_errors = {errors} (detailed errors leaked to clients)")
        if offenders:
            self._flag(
                "BASELINE-009", "Web-tier logging / error disclosure weak (ICM)",
                self.SEVERITY_MEDIUM,
                f"{len(offenders)} ICM web-tier setting(s) are weak: the ICM security log gives "
                "the web-tier forensic trail of HTTP(S) access and attacks, and detailed error "
                "pages disclose stack / server information useful to an attacker.",
                offenders,
                "Configure icm/security_log with LEVEL=3 (per SAP Security Baseline) and log "
                "rotation, and set is/HTTP/show_detailed_errors = FALSE in production.",
                ["SAP Security Baseline — ICM security log / error disclosure"])

    def check_password_compliance(self):
        v = self._p("login/password_compliance_to_current_policy")
        if v is not None and v.strip() == "0":
            self._flag(
                "BASELINE-010", "Existing passwords not forced to current policy (login/password_compliance_to_current_policy)",
                self.SEVERITY_MEDIUM,
                "login/password_compliance_to_current_policy = 0 lets users whose stored password "
                "predates a policy tightening keep using it indefinitely — legacy short/weak "
                "passwords remain valid despite a stronger current policy.",
                [f"login/password_compliance_to_current_policy = {v}"],
                "Set login/password_compliance_to_current_policy = 1 so non-compliant passwords "
                "must be changed at next logon.",
                ["SAP Security Baseline — password policy enforcement"])
