"""
System Trust & Standard Users Auditor
=======================================
Audits the SAP system-level trust / connectivity surface and the standard
(default) users — the landscape lateral-movement paths and the kernel/emergency
accounts that classic user-level checks miss.

Covers:
  - Trusted / trusting RFC relationships (RFCSYSACL / SMT1): inbound trust from a
    lower-security-tier system, self-trust, and trust not migrated to the 2020
    security method (SAP Notes 3089413 / 3157268)
  - Trusted RFC destinations that carry a fixed stored user instead of
    current-user propagation
  - SAProuter route-permission table (saprouttab) allow-all / wildcard rules
  - Message-server internal/external port separation and monitoring exposure
  - UCON (Unified Connectivity) RFC allowlist activation
  - RFC Gateway proxy ACL (gw/prxy_info)
  - Standard users: SAP* kernel emergency-user auto-logon
    (login/no_automatic_user_sapstar), default passwords still valid, and
    standard users left unlocked (SAP*, DDIC, SAPCPIC, EARLYWATCH, TMSADM,
    including clients 000/001/066)

Data sources:
  - security_params.csv → profile parameter export (NAME, VALUE)
  - rfc_trust.csv       → RFCSYSACL / SMT1 trusting-systems export
  - standard_users.csv  → RSUSR003 export (standard-user status per client)
  - saprouttab.csv      → SAProuter route-permission table
  - rfc_destinations.csv → SM59 / RFCDES export (for trusted destinations)
"""

from typing import Dict, List, Any, Optional
from modules.base_auditor import BaseAuditor


class SystemTrustAuditor(BaseAuditor):

    CATEGORY = "System Trust & Standard Users"

    STANDARD_USERS = {"SAP*", "DDIC", "SAPCPIC", "EARLYWATCH", "TMSADM", "SAP#*", "SAPSUPPORT"}
    # Clients that must never keep default-password standard users.
    STANDARD_CLIENTS = {"000", "001", "066"}
    # SID first letters that conventionally indicate a non-production tier.
    NONPROD_PREFIXES = ("D", "Q", "S", "T")

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._params = self._param_index()
        # standard users
        self.check_sapstar_autologon()
        self.check_default_passwords()
        self.check_standard_users_unlocked()
        # trust / connectivity
        self.check_inbound_trust_tier()
        self.check_self_trust()
        self.check_trust_migration()
        self.check_trusted_dest_fixed_user()
        self.check_saprouttab_wildcard()
        self.check_message_server_ports()
        self.check_ucon_allowlist()
        self.check_gateway_proxy_acl()
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

    def _param(self, name: str) -> Optional[str]:
        return self._params.get(name.lower())

    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "x", "yes", "true", "on", "y")

    @staticmethod
    def _get(row: dict, *names: str) -> str:
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    # =============================================================  STANDARD USERS
    def check_sapstar_autologon(self):
        """login/no_automatic_user_sapstar = 0 → SAP* kernel emergency user usable."""
        val = self._param("login/no_automatic_user_sapstar")
        if val is not None and val.strip() == "0":
            self.finding(
                check_id="STDUSR-001",
                title="SAP* kernel emergency-user auto-logon is enabled",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    "Profile parameter login/no_automatic_user_sapstar = 0. With this value, "
                    "if the SAP* user record is deleted from a client, the kernel-hardcoded "
                    "SAP* becomes usable with the default password 'PASS' and implicit full "
                    "privileges, in ANY client — a well-known full-compromise backdoor."
                ),
                affected_items=[f"login/no_automatic_user_sapstar = {val or '(empty)'}"],
                remediation=(
                    "Set login/no_automatic_user_sapstar = 1 in every instance profile and "
                    "DEFAULT.PFL, then restart. Ensure a real SAP* user exists, is locked, and "
                    "has a strong password in all clients."
                ),
                references=["SAP Note 2383 / SAP Security Baseline — SAP* protection",
                            "SAP Help — login/no_automatic_user_sapstar"],
            )

    def check_default_passwords(self):
        """RSUSR003: standard users with SAP default passwords still valid."""
        rows = self.data.get("standard_users")
        if not rows:
            return
        offenders = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            user = self._get(row, "USER", "BNAME", "USERNAME", "USER_NAME").upper()
            client = self._get(row, "CLIENT", "MANDT", "CLNT")
            defpw = self._get(row, "DEFAULT_PASSWORD", "DEFAULT_PWD", "PWD_STATUS",
                              "PASSWORD_STATUS", "HAS_DEFAULT_PW")
            if not user or (user not in self.STANDARD_USERS and not user.startswith("SAP")):
                continue
            dl = defpw.strip().lower()
            has_default = self._truthy(defpw) or ("default" in dl and not dl.startswith(("no", "not", "kein")))
            if has_default:
                offenders.append(f"{user} (client {client or '?'}) — default password still valid")
        if offenders:
            self.finding(
                check_id="STDUSR-002",
                title="Standard users still have SAP default passwords",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} standard/technical user(s) (SAP*, DDIC, SAPCPIC, "
                    "EARLYWATCH, TMSADM) still have their well-known SAP default password. "
                    "These are the first credentials an attacker tries and grant broad access."
                ),
                affected_items=offenders,
                remediation=(
                    "Change the passwords of all standard users in every client (including "
                    "000/001/066), then lock the ones not operationally required. Verify with "
                    "report RSUSR003."
                ),
                references=["SAP Note 2383 — Protecting standard users",
                            "SAP Security Baseline — Standard users / RSUSR003"],
            )

    def check_standard_users_unlocked(self):
        """RSUSR003: standard users left unlocked / dialog-capable (esp. clients 000/001/066)."""
        rows = self.data.get("standard_users")
        if not rows:
            return
        offenders = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            user = self._get(row, "USER", "BNAME", "USERNAME", "USER_NAME").upper()
            client = self._get(row, "CLIENT", "MANDT", "CLNT")
            locked = self._get(row, "LOCKED", "LOCK_STATUS", "IS_LOCKED", "USER_LOCK")
            utype = self._get(row, "USER_TYPE", "USTYP", "TYPE").upper()
            if user not in self.STANDARD_USERS and not user.startswith("SAP"):
                continue
            ll = locked.strip().lower()
            is_locked = self._truthy(locked) or ll.startswith("lock") or ll == "l"
            # SAP* / DDIC that are unlocked, or dialog-capable, are the risk
            dialog = utype in ("A", "DIALOG", "")  # A = dialog
            if not is_locked and (user in ("SAP*", "DDIC", "SAPCPIC") or client in self.STANDARD_CLIENTS):
                note = "unlocked"
                if user in ("SAP*", "DDIC") and dialog:
                    note += ", dialog-capable"
                offenders.append(f"{user} (client {client or '?'}) — {note}")
        if offenders:
            self.finding(
                check_id="STDUSR-003",
                title="Standard users not locked",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} standard user(s) are not locked. SAP*/DDIC/SAPCPIC and "
                    "any standard user in clients 000/001/066 should be locked (and SAP*/DDIC "
                    "never usable as dialog users) unless a specific task needs them."
                ),
                affected_items=offenders,
                remediation=(
                    "Lock standard users that are not required; keep DDIC/SAP* locked except "
                    "for controlled maintenance windows. Never delete SAP* (see STDUSR-001)."
                ),
                references=["SAP Note 2383", "SAP Security Baseline — Standard users"],
            )

    # =================================================================  RFC TRUST
    def _trust_rows(self):
        for row in (self.data.get("rfc_trust") or []):
            if isinstance(row, dict):
                yield row

    def check_inbound_trust_tier(self):
        """RFCSYSACL: inbound trust relationships, escalating non-production trusted SIDs."""
        local = str(self.get_config("local_system_sid", "")).strip().upper()
        items = []
        for row in self._trust_rows():
            trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "TRUSTED_SYSTEM",
                                "RFC_TRUSTSY", "SID").upper()
            if not trusted or trusted == local:
                continue
            nonprod = trusted[:1] in self.NONPROD_PREFIXES
            tag = " [likely NON-PRODUCTION tier]" if nonprod else ""
            items.append((nonprod, f"Trusted system {trusted}{tag}"))
        if not items:
            return
        nonprod_any = any(n for n, _ in items)
        self.finding(
            check_id="TRUST-001",
            title="Inbound trusted-RFC relationships (verify no trust from a lower tier)",
            severity=self.SEVERITY_HIGH if nonprod_any else self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(items)} system(s) are configured as TRUSTED to log on here via trusted "
                "RFC. Trust must only flow from equal-or-higher security tiers: a production "
                "system must never trust a development/QA system, or any dialog user in the "
                "lower system could pivot into production. Entries whose SID begins with "
                "D/Q/S/T are flagged as likely non-production."
            ),
            affected_items=[lbl for _, lbl in sorted(items, key=lambda x: (not x[0], x[1]))],
            remediation=(
                "Remove any trust FROM a lower-tier system. Keep trust one-directional from "
                "higher to lower security tiers and restrict S_RFCACL to specific users "
                "(see the ABAP authorization module, AUTH-002)."
            ),
            references=["SAP Note 128447 — Trusted/Trusting systems",
                        "SAP Security Baseline — RFC trust"],
        )

    def check_self_trust(self):
        """rfc/selftrust = 1, or a RFCSYSACL row trusting the local SID."""
        offenders = []
        val = self._param("rfc/selftrust")
        if val is not None and val.strip() == "1":
            offenders.append("rfc/selftrust = 1")
        local = str(self.get_config("local_system_sid", "")).strip().upper()
        if local:
            for row in self._trust_rows():
                trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "SID").upper()
                if trusted == local:
                    offenders.append(f"RFCSYSACL self-trust entry for {local}")
        if offenders:
            self.finding(
                check_id="TRUST-002",
                title="RFC self-trust enabled",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "The system trusts itself for trusted RFC (rfc/selftrust = 1 or a "
                    "self-referential RFCSYSACL entry). Self-trust lets a lower-privileged local "
                    "user pivot to a higher-privileged user in the same system via a trusted "
                    "destination — a local privilege-escalation path."
                ),
                affected_items=offenders,
                remediation=(
                    "Set rfc/selftrust = 0 and remove self-referential trust entries unless a "
                    "specific, reviewed scenario requires it."
                ),
                references=["SAP Note 128447", "SAP Security Baseline — rfc/selftrust"],
            )

    def check_trust_migration(self):
        """Legacy trust ticket method still allowed (not migrated to 2020 method)."""
        offenders = []
        val = self._param("rfc/allowoldticket4tt")
        if val is not None and str(val).strip().lower() in ("yes", "1", "true"):
            offenders.append("rfc/allowoldticket4tt = yes (legacy trust tickets accepted)")
        for row in self._trust_rows():
            trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "SID").upper()
            migrated = self._get(row, "MIGRATED", "TRUST_METHOD", "TRUSTMETH", "MIGRATION_CODE",
                                 "SECURITY_METHOD")
            if trusted and migrated and not (self._truthy(migrated) or migrated in ("3", "MIGRATED")):
                offenders.append(f"Trusted system {trusted} — trust method '{migrated}' (not migrated)")
        if offenders:
            self.finding(
                check_id="TRUST-003",
                title="Trusted-RFC relationships not migrated to the current security method",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} indicator(s) that trusted RFC still relies on the legacy "
                    "trust-ticket method rather than the 2020 security method (migration code / "
                    "method 3). The legacy method is forgeable and enables trusted-RFC "
                    "impersonation across the landscape."
                ),
                affected_items=offenders,
                remediation=(
                    "Migrate all trust relationships to the new method (transaction SMT1 → "
                    "migrate) and set rfc/allowoldticket4tt = no. See SAP Notes 3089413 / 3157268."
                ),
                references=["SAP Note 3089413 — Trusted-RFC security method (CVE-2021-27610)",
                            "SAP Note 3157268 — Trusted RFC migration how-to"],
            )

    def check_trusted_dest_fixed_user(self):
        """SM59 trusted destination with a fixed stored user instead of current-user."""
        rows = self.data.get("rfc_destinations")
        if not rows:
            return
        offenders = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = self._get(row, "RFCDEST", "DESTINATION", "NAME", "RFCDES")
            rtype = self._get(row, "RFCTYPE", "TYPE", "RFC_TYPE")
            rfcauth = self._get(row, "RFCAUTH", "AUTH_METHOD", "AUTH")
            trusted = self._get(row, "TRUSTED", "TRUST", "TRUSTED_SYSTEM", "Q_FLAG")
            is_trusted = self._truthy(trusted) or rfcauth.upper() == "TRUSTED"
            user = self._get(row, "RFCUSER", "USER", "LOGON_USER", "USERNAME")
            current = self._get(row, "CURRENT_USER", "CURRENTUSER", "USE_CURRENT_USER")
            if (is_trusted and user and not self._truthy(current)
                    and (rtype in ("3", "") or "3" in rtype)):
                offenders.append(f"{name} — trusted destination with fixed user '{user}'")
        if offenders:
            self.finding(
                check_id="TRUST-004",
                title="Trusted RFC destination configured with a fixed logon user",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} trusted RFC destination(s) carry a fixed technical logon "
                    "user instead of 'current user' propagation. This defeats the trusted-RFC "
                    "identity model and turns the destination into a stored-credential hop that "
                    "runs as the fixed (often highly privileged) user."
                ),
                affected_items=offenders,
                remediation=(
                    "For trusted destinations, use 'Current User' (no stored user). If a fixed "
                    "user is required it should be a low-privileged, dedicated technical user."
                ),
                references=["SAP Note 128447 — Trusted destinations",
                            "SAP Security Baseline — RFC destinations"],
            )

    # ============================================================  CONNECTIVITY
    def check_saprouttab_wildcard(self):
        """SAProuter route-permission table with allow-all / wildcard permit lines."""
        rows = self.data.get("saprouttab")
        if not rows:
            return
        offenders = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            action = self._get(row, "ACTION", "TYPE").upper()
            line = self._get(row, "LINE", "RULE", "ENTRY")
            src = self._get(row, "SOURCE", "SOURCE_HOST", "SRC", "FROM")
            dest = self._get(row, "DEST", "DEST_HOST", "TARGET", "TO")
            port = self._get(row, "PORT", "DEST_PORT", "SERVICE")
            if line and not action:
                parts = line.split()
                if parts:
                    action = parts[0].upper()
                    src = parts[1] if len(parts) > 1 else src
                    dest = parts[2] if len(parts) > 2 else dest
                    port = parts[3] if len(parts) > 3 else port
            if action in ("P", "S") and (dest in ("*", "", None) or port in ("*", "", None)):
                offenders.append(f"{action} {src or '*'} {dest or '*'} {port or '*'} — wildcard target host/port")
        if offenders:
            self.finding(
                check_id="TRUST-005",
                title="SAProuter route table allows wildcard target host/port",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} SAProuter permit rule(s) use a wildcard target host "
                    "and/or port. An allow-all saprouttab lets external clients route to any "
                    "internal host/port through the SAProuter, exposing the internal network."
                ),
                affected_items=offenders,
                remediation=(
                    "Replace wildcard P/S rules with explicit source, target host and target "
                    "port; deny by default. SAP explicitly forbids wildcards for target host/port."
                ),
                references=["SAP Help — SAProuter route permission table",
                            "SAP Security Baseline — SAProuter"],
            )

    def check_message_server_ports(self):
        """Message server internal/external port not separated, or monitoring exposed."""
        offenders = []
        internal = self._param("rdisp/msserv_internal")
        if internal is not None and internal.strip() == "0":
            offenders.append("rdisp/msserv_internal = 0 (no dedicated internal port — external "
                             "clients can reach the internal message-server channel)")
        monitor = self._param("ms/monitor")
        if monitor is not None and monitor.strip() not in ("0", ""):
            offenders.append(f"ms/monitor = {monitor} (external message-server administration allowed)")
        if offenders:
            self.finding(
                check_id="TRUST-006",
                title="Message-server internal/external separation weak",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "The message server does not fully separate its internal (application-server) "
                    "channel from external client access, or external administration is enabled. "
                    "Without a dedicated internal port and a restrictive ACL, an attacker who "
                    "reaches the message-server port can register as an application server or "
                    "administer the message server."
                ),
                affected_items=offenders,
                remediation=(
                    "Set rdisp/msserv_internal to a dedicated internal port (firewalled from "
                    "clients), set ms/monitor = 0, and maintain a restrictive ms_acl_info ACL."
                ),
                references=["SAP Note 1421005 — Message server security",
                            "SAP Security Baseline — Message server"],
            )

    def check_ucon_allowlist(self):
        """UCON RFC allowlist not active → external RFC surface unrestricted."""
        val = self._param("ucon/rfc/active")
        if val is not None and val.strip() != "1":
            self.finding(
                check_id="TRUST-007",
                title="UCON RFC allowlist is not active",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"Profile parameter ucon/rfc/active = {val or '(empty)'} (not 1). Unified "
                    "Connectivity is not enforcing the RFC basis allowlist (default Communication "
                    "Assembly), so every RFC-enabled function module remains externally callable "
                    "— the RFC attack surface is unrestricted."
                ),
                affected_items=[f"ucon/rfc/active = {val or '(empty)'}"],
                remediation=(
                    "Run the UCON phases (logging → evaluation → active) in UCONCOCKPIT and set "
                    "ucon/rfc/active = 1 to enforce the RFC allowlist, exposing only the RFMs "
                    "external callers actually need."
                ),
                references=["SAP Help — Unified Connectivity (UCON)",
                            "SAP Security Baseline — UCON RFC allowlist"],
            )

    def check_gateway_proxy_acl(self):
        """gw/prxy_info unset → gateway proxy ACL defaults to allow-all."""
        val = self._param("gw/prxy_info")
        acl_mode = self._param("gw/acl_mode_proxy")
        # modern kernels with gw/acl_mode_proxy=1 auto-secure an empty prxyinfo
        if (val is not None and val.strip() == ""
                and (acl_mode is None or acl_mode.strip() != "1")):
            self.finding(
                check_id="TRUST-008",
                title="RFC Gateway proxy ACL (gw/prxy_info) not configured",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "Profile parameter gw/prxy_info is empty, so no proxy ACL file is loaded and "
                    "the built-in default permits any source gateway to proxy RFC traffic to any "
                    "destination system. This enables cross-system RFC relaying through the "
                    "gateway."
                ),
                affected_items=["gw/prxy_info = (empty)"],
                remediation=(
                    "Create a prxyinfo ACL file with explicit source/destination rules, point "
                    "gw/prxy_info at it, and set gw/acl_mode_proxy = 1."
                ),
                references=["SAP Note 910918 — Parameter gw/prxy_info",
                            "SAP Note 3224889 — gw/acl_mode_proxy default settings",
                            "SAP Security Baseline — RFC Gateway ACLs"],
            )
