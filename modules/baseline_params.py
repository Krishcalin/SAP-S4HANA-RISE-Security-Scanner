# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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


from modules import ecs_baseline
from modules import snc_posture
from modules.deployment_modes import normalise


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
        self.check_password_hash_algorithm()
        self.check_rfc_callback_security()
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

    def _flag(self, check_id, title, severity, description, affected, remediation, references,
              affected_objects=None, scope=None):
        self.finding(check_id=check_id, title=title, severity=severity, category=self.CATEGORY,
                     description=description, affected_items=affected, remediation=remediation,
                     references=references, affected_objects=affected_objects, scope=scope)

    @staticmethod
    def _param_object(name: str, qualifier: Any = None) -> Dict[str, Any]:
        """A profile parameter as a structured object.

        `qualifier` carries the ACTUAL value, and it participates in identity — so pass
        it only where the check fires on exactly ONE value ("= 0"). Where the trigger is
        a range or "anything but X", the value must stay out: a 0 -> 2 change that fixes
        nothing would otherwise retire the finding and raise a fresh one with its age
        reset, and would split one parameter into several graph nodes.
        """
        obj: Dict[str, Any] = {"type": "parameter_name", "name": name}
        if qualifier:
            obj["qualifier"] = qualifier
        return obj

    # --------------------------------------------------------------------- checks
    def check_password_hash_algorithm(self):
        """MEDIUM/HIGH: login/password_hash_algorithm uses a weak hash or low work factor."""
        v = self._p("login/password_hash_algorithm")
        if v is None:
            return
        val = str(v)
        low = val.lower()
        issues = []
        # Algorithm strength: iSSHA-1/SHA-1/MD5 are obsolete; want iSSHA-256/384/512.
        weak_alg = any(t in low for t in ("issha-1", "issha1", "sha-1", "=sha1", " sha1",
                                          "md5"))
        strong_alg = any(t in low for t in ("issha-256", "issha-384", "issha-512",
                                            "issha256", "issha384", "issha512"))
        if weak_alg or (("algorithm" in low) and not strong_alg):
            issues.append(f"weak/obsolete hash algorithm in: {val}")
        # Iteration (work-factor) count.
        iters = None
        for part in low.replace(";", ",").split(","):
            if "iteration" in part:
                digits = "".join(ch for ch in part if ch.isdigit())
                if digits:
                    iters = int(digits)
        if iters is not None and iters < 10000:
            issues.append(f"iterations = {iters} (< 10000 work factor)")

        if issues:
            sev = self.SEVERITY_HIGH if weak_alg else self.SEVERITY_MEDIUM
            self._flag(
                "BASELINE-011",
                "Weak password hash algorithm (login/password_hash_algorithm)",
                sev,
                "login/password_hash_algorithm configures the one-way function used to store "
                f"the current (CODVN H) password hash in USR02: {val}. The exported value uses "
                "a weak or obsolete algorithm and/or a low iteration/work-factor. SAP password "
                "hashes are a routine offline-cracking target once an attacker reads USR02 (for "
                "example via broad S_TABU_DIS/S_TABU_NAM access, a table download, or a stolen "
                "backup): a SHA-1-based (iSSHA-1) or MD5-based hash and a low iteration count "
                "collapse the cost of recovering plaintext passwords, and any recovered password "
                "is then usable for lateral movement, especially where the same credentials are "
                "reused across the landscape. Because this parameter governs how EVERY dialog "
                "user's password is protected at rest, a weak setting is a systemic exposure that "
                "undermines the entire password policy no matter how strong the complexity rules "
                "are. This is independent of, and should be fixed alongside, "
                "login/password_downwards_compatibility (BASELINE-005).",
                issues,
                "Set login/password_hash_algorithm to a current, salted, iterated SHA-2 "
                "configuration, e.g. encoding=RFC2307, algorithm=iSSHA-512, iterations=15000, "
                "saltsize=256. After changing the parameter, force affected users to set a new "
                "password so the strong hash is generated, ensure "
                "login/password_downwards_compatibility = 0, and run CLEANUP_PASSWORD_HASH_VALUES "
                "to purge any residual weak BCODE/PASSCODE hashes. Validate against the SAP "
                "Security Baseline recommended value and re-export security_params to confirm.",
                ["SAP Security Baseline — Password hash algorithm",
                 "SAP Help Portal — Profile parameter login/password_hash_algorithm"],
                # One parameter is the entire defect; the two issues above are two ways
                # the SAME parameter is weak, not two objects. No qualifier: the trigger
                # accepts any weak algorithm and any iteration count below 10000, so the
                # value would churn identity (iterations 1024 -> 2048 fixes nothing).
                affected_objects=[self._param_object("login/password_hash_algorithm")],
                scope="object")

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
                ["SAP Security Baseline — auth/rfc_authority_check", "SAP Note 93254"],
                # The check fires on exactly one value ("0"), so the value cannot drift
                # while the finding is open and is safe in identity.
                affected_objects=[self._param_object("auth/rfc_authority_check", "0")],
                scope="object")

    def check_rfc_callback_security(self):
        """rfc/callback_security_method — the RFC callback allowlist.

        An outbound RFC call from production to a weaker system can be turned back
        on production: the callee invokes the predefined destination BACK, and the
        callback executes in the context of the production user who made the
        original call. No credentials are needed. This parameter is the control
        that constrains it, and the finding exists because it is the primary
        chokepoint of the callback-inversion attack path — a path whose other hops
        were all detected while its cut was unasserted, so the graph could show the
        path but never show it closed.
        """
        v = self._p("rfc/callback_security_method")
        if v is None:
            return                              # absent != insecure; self-skip
        val = v.strip()
        # 3 = reject callbacks not on the destination's allowlist. 0 disables the
        # mechanism; 1 and 2 only simulate/log it, so an attacker is still served.
        #
        # SAP Note 3250501 permits 1 on NetWeaver 7.40 to avoid breaking migrations,
        # with a planned move to 3. So in ECS a system on 1 is following SAP's own
        # written allowance, and reporting it HIGH is telling a compliant customer
        # they are not. The genuinely dangerous values (0 and 2) still fire.
        if (val in ("0", "1", "2")
                and ecs_baseline.is_compliant("rfc/callback_security_method", val,
                                              self._deployment_mode()) is not True):
            enforcing = {"0": "no callback protection at all",
                         "1": "simulation only — violations are logged, not blocked",
                         "2": "simulation with logging — still not blocked"}[val]
            self._flag(
                "BASELINE-012",
                "RFC callback protection not enforced (rfc/callback_security_method)",
                self.SEVERITY_HIGH,
                f"rfc/callback_security_method = {val} means {enforcing}. When this "
                "system makes an outbound RFC call to a less-protected system, an "
                "attacker controlling that system can call back into this one using "
                "the predefined destination BACK. The callback runs in the user "
                "context of whoever initiated the outbound call, so no credentials "
                "are required — the trust flows in the opposite direction to the "
                "data.",
                [f"rfc/callback_security_method = {val}"],
                "Set rfc/callback_security_method = 3 to reject callbacks that are "
                "not on the calling destination's allowlist, and maintain the "
                "per-destination callback allowlist in SM59 (called function module "
                "/ callback function module pairs). Activating UCON to restrict "
                "which function modules are remotely callable at all is the broader "
                "control.",
                ["SAP Security Baseline — RFC callback protection"],
                # Fires on exactly the value shown, so the value cannot drift while
                # the finding is open and is safe to carry in identity.
                affected_objects=[
                    self._param_object("rfc/callback_security_method", val)],
                scope="object")

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
                ["SAP Security Baseline — auth/no_check_in_some_cases"],
                # Pinned to one value. The comparison is case-folded, so the qualifier is
                # the folded form — otherwise an export spelling it "n" would be a second
                # identity for the same defect.
                affected_objects=[self._param_object("auth/no_check_in_some_cases", "N")],
                scope="object")

    def _deployment_mode(self) -> str:
        """Which estate we are auditing, using `user_auth_audit`'s vocabulary.

        Defaults to `on_prem` when the caller did not say. Guessing ECS would
        silently relax genuine on-premise findings, which is the wrong direction
        to be wrong in.
        """
        mode = (self.run_context or {}).get("deployment_mode") or ""
        return normalise(mode)

    def check_snc_accept_insecure(self):
        """The SNC insecure-fallback family — for the parameters nobody deeper owns.

        `modules/snc_posture.py` owns the SNC family: it reads all eighteen ``snc/*``
        parameters as one model against SAP Note 3250501 and, crucially, knows that
        with the master switch off every one of these settings is MOOT. On an export
        with ``snc/enable = 0`` this check was raising the fallback family as a second
        HIGH finding beside its own cause — measured, and the reason this deferral
        exists.

        The stand-down is PER PARAMETER and only where that module is genuinely in
        the run. WHILE SNC IS IN FORCE it never covers a parameter that module judged
        compliant, because that verdict is about ECS — where SAP mandates
        ``snc/accept_insecure_gui = 1`` — and on classic on-premise ABAP the stricter
        reading below is still the right one. Deleting it would be a worse defect than
        the duplicate.

        The one place a compliant verdict IS covered is when the master switch is off
        or unreadable. Every one of these settings is then moot on any deployment,
        on-premise included, so there is no on-premise reading left to lose — and the
        note below says which of the two reasons applied.
        """
        params = ["snc/accept_insecure_rfc", "snc/accept_insecure_gui",
                  "snc/accept_insecure_cpic", "snc/accept_insecure_r3int_rfc"]
        # `is_compliant` is consulted FIRST. In ECS, snc/accept_insecure_gui,
        # _rfc and _r3int_rfc are mandated at 1, so the plain "1 means insecure"
        # reading reported a HIGH finding on every compliant RISE system — against
        # SAP's own written baseline, in the environment this product specialises
        # in. `None` means the oracle has no opinion and the original rule stands.
        mode = self._deployment_mode()
        offending = [p for p in params
                     if self._p(p) is not None and self._p(p).strip() in ("1", "u")
                     and ecs_baseline.is_compliant(p, self._p(p), mode) is not True]

        owner = snc_posture.coverage_in_this_run(self)
        withheld = [p for p in offending
                    if owner is not None and owner.accounted_for(p)]
        offending = [p for p in offending if p not in withheld]
        if withheld:
            self._snc_deferred_to_the_family_model(withheld, owner.switch_state)

        offenders = [f"{p} = {self._p(p)}" for p in offending]
        # No qualifier: the trigger accepts "1" OR "u", so the value is not pinned and
        # would split one parameter into two graph nodes.
        objects = [self._param_object(p) for p in offending]
        if offenders:
            self._flag(
                "BASELINE-003", "SNC accepts insecure (unencrypted) connections",
                self.SEVERITY_HIGH,
                f"{len(offenders)} snc/accept_insecure_* parameter(s) allow unencrypted "
                "RFC/GUI/CPIC connections wherever SNC is in force — defeating it, since a "
                "client can simply connect without encryption. (This check reads the "
                "fallback parameters only. Whether SNC is switched on at all is "
                "snc/enable, which the SNC posture module reports on.)",
                offenders,
                "Set the snc/accept_insecure_* parameters to 0 so only SNC-protected "
                "connections are accepted (after all clients/servers support SNC).",
                ["SAP Security Baseline — SNC insecure connections", "SAP Note 1690662"],
                # Up to four independent parameters rolled into ONE finding. Hardening
                # snc/accept_insecure_gui while the CPIC one stays open must not retire
                # this finding and re-raise it with a reset age, so the members stay out
                # of identity and ride along as graph nodes only.
                affected_objects=objects,
                scope="aggregate")

    def _snc_deferred_to_the_family_model(self, withheld: List[str],
                                          switch_state: str):
        """Say which parameters were handed to the deeper module, and why.

        A silent stand-down is indistinguishable from a clean bill of health, which
        is the failure this codebase treats as the most damaging one available. So
        the note is emitted whenever anything was withheld — including the case where
        BASELINE-003 still fires for the remaining parameters, because a reader
        comparing the two runs otherwise cannot tell why a parameter left the list.
        """
        reason = (
            "the SNC master switch is not in force, so these fallback settings cannot "
            "take effect and are a consequence of that one defect rather than "
            "separate ones"
            if switch_state in ("off", "unreadable") else
            "the SNC posture module judged them against the mandatory ECS hardening "
            "baseline and is reporting them there")
        self._flag(
            "BASELINE-SNC-DEFERRED",
            "SNC insecure-fallback parameters deferred to the SNC family model",
            self.SEVERITY_INFO,
            f"{len(withheld)} snc/accept_insecure_* parameter(s) were not raised as "
            f"BASELINE-003 in this run because {reason}. The verdict on them is in "
            "the CRYPTO-SNCECS-* findings, which read all eighteen snc/* parameters "
            "as one family. This note exists so that their absence from BASELINE-003 "
            "is not read as those parameters being correct.",
            [f"{p} = {self._p(p)}" for p in withheld],
            "No action. To have this module judge these parameters itself, exclude "
            "the 'snc' module from the run.",
            ["SAP Security Baseline — SNC insecure connections"],
            # A note about a check that stood down asserts no defect, so it names no
            # object: the parameters are the readings withheld, and giving them graph
            # nodes here would attach a defect to them that this finding is not making.
            scope="aggregate")

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
                 "SAP Note 692245 (server-side scripting security options)"],
                # No qualifier: any truthy spelling (1 / TRUE / yes / on / X) trips this,
                # so pinning the exported spelling would create several identities and
                # several graph nodes for one parameter.
                affected_objects=[self._param_object("sapgui/user_scripting")],
                scope="object")

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
                        ["SAP Security Baseline — Password hashes", "SAP Note 1023437"],
                        # No qualifier: the trigger is a range (> 0), so a 3 -> 1 change
                        # that still keeps the weak hash would look like a new defect.
                        affected_objects=[self._param_object(
                            "login/password_downwards_compatibility")],
                        scope="object")
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
                ["SAP Security Baseline — service/protectedwebmethods", "SAP Note 1439348"],
                # No qualifier: anything that is neither SDEFAULT nor ALL trips this —
                # NONE, empty, or any reduced custom list — so the value is not pinned.
                affected_objects=[self._param_object("service/protectedwebmethods")],
                scope="object")

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
                 "CISA AA19-122A (10KBLAZE)"],
                # Pinned: the check fires on exactly one value ("0").
                affected_objects=[self._param_object("gw/acl_mode", "0")],
                scope="object")

    def check_sso_ticket_cookie(self):
        offenders = []
        objects = []
        https = self._p("login/ticket_only_by_https")
        if https is not None and https.strip() == "0":
            offenders.append("login/ticket_only_by_https = 0 (SSO ticket sent over plain HTTP — sniffable)")
            objects.append(self._param_object("login/ticket_only_by_https", "0"))
        httponly = self._p("icf/set_HTTPonly_flag_on_cookies")
        if httponly is not None and httponly.strip() not in ("0", ""):
            offenders.append(f"icf/set_HTTPonly_flag_on_cookies = {httponly} (HttpOnly not set on all ICF cookies)")
            # No qualifier: ANY value other than 0/empty trips this, so the value is not
            # pinned — a 1 -> 2 change would otherwise mint a second graph node.
            objects.append(self._param_object("icf/set_HTTPonly_flag_on_cookies"))
        to_host = self._p("login/ticket_only_to_host")
        if to_host is not None and to_host.strip() == "0":
            offenders.append("login/ticket_only_to_host = 0 (ticket accepted by other hosts)")
            objects.append(self._param_object("login/ticket_only_to_host", "0"))
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
                ["SAP Security Baseline — SSO ticket / cookie hardening"],
                # Three independent parameters rolled into ONE "transport not hardened"
                # finding. Fixing the HTTPS flag while the host binding stays open is
                # progress, not a different defect, so the member list must not enter
                # identity or the age would reset on every partial fix.
                affected_objects=objects,
                scope="aggregate")

    def check_icm_security_log(self):
        offenders = []
        objects = []
        seclog = self._p("icm/security_log")
        if seclog is not None:
            m = re.search(r"level\s*=\s*(\d+)", seclog, re.IGNORECASE)
            level = int(m.group(1)) if m else (None if seclog.strip() else 0)
            if seclog.strip() == "" or (level is not None and level < 3):
                offenders.append(f"icm/security_log = '{seclog or '(empty)'}' (log level < 3 / not configured)")
                # No qualifier: the trigger is a range (LEVEL < 3) over a free-form
                # value that also carries the log file name and size — raising LEVEL
                # from 0 to 1, or rotating the file name, would re-identify the node.
                objects.append(self._param_object("icm/security_log"))
        errors = self._p("is/http/show_detailed_errors")
        if errors is not None and self._truthy(errors):
            offenders.append(f"is/HTTP/show_detailed_errors = {errors} (detailed errors leaked to clients)")
            # No qualifier: any truthy spelling trips this.
            objects.append(self._param_object("is/http/show_detailed_errors"))
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
                ["SAP Security Baseline — ICM security log / error disclosure"],
                # Two independent web-tier settings summarised as one weakness: turning
                # off detailed errors while the security log stays at LEVEL=1 must keep
                # the same finding rather than restart its clock.
                affected_objects=objects,
                scope="aggregate")

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
                ["SAP Security Baseline — password policy enforcement"],
                # Pinned: the check fires on exactly one value ("0").
                affected_objects=[self._param_object(
                    "login/password_compliance_to_current_policy", "0")],
                scope="object")
