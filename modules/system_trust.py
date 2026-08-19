# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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
from modules import client_scope
from modules.base_auditor import BaseAuditor


class SystemTrustAuditor(BaseAuditor):

    CATEGORY = "System Trust & Standard Users"

    STANDARD_USERS = {"SAP*", "DDIC", "SAPCPIC", "EARLYWATCH", "TMSADM", "SAP#*", "SAPSUPPORT"}
    # Clients that must never keep default-password standard users.
    #: SAP's standard clients. Defined in `modules/client_scope.py` and
    #: imported rather than repeated: the scope checker and this auditor
    #: asking "is this a standard client" from two copies is how they come
    #: to disagree about which clients a cross-client check must cover.
    STANDARD_CLIENTS = set(client_scope.WELL_KNOWN_CLIENTS)
    # SID first letters that conventionally indicate a non-production tier.
    NONPROD_PREFIXES = ("D", "Q", "S", "T")

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._params = self._param_index()
        # standard users
        self.check_sapstar_autologon()
        self.check_default_passwords()
        self.check_standard_users_unlocked()
        # After the two it qualifies, so a reader meets the result and
        # the bound on it in that order.
        self.check_obsolete_clients()
        self.check_client_scope()
        # trust / connectivity
        self.check_inbound_trust_tier()
        self.check_self_trust()
        self.check_trust_migration()
        self.check_trusted_dest_fixed_user()
        self.check_saprouttab_wildcard()
        self.check_message_server_ports()
        self.check_message_server_acl()
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

    def _local_sid(self) -> str:
        """SID of THIS (trusting) system, when the caller's baseline names it.

        A trust finding belongs to the system that grants the trust, not to whichever
        export happened to reveal it. Empty when the baseline does not name it — in that
        case the finding falls back to the run-level system rather than inventing a SID.
        """
        return str(self.get_config("local_system_sid", "")).strip().upper()

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
                # One parameter, one defect: the subject is the parameter itself. The
                # qualifier is safe in identity because the check fires on exactly one
                # value ("0"), so it cannot drift while the finding is open.
                affected_objects=[{
                    "type": "parameter_name",
                    "name": "login/no_automatic_user_sapstar",
                    "qualifier": val.strip(),
                }],
                scope="object",
                remediation=(
                    "Set login/no_automatic_user_sapstar = 1 in every instance profile and "
                    "DEFAULT.PFL, then restart. Ensure a real SAP* user exists, is locked, and "
                    "has a strong password in all clients."
                ),
                references=["SAP Note 2383 / SAP Security Baseline — SAP* protection",
                            "SAP Help — login/no_automatic_user_sapstar"],
            )

    def _client_scope(self):
        """Which clients the standard-user export actually covered."""
        return client_scope.scope_for(self.data, "standard_users")

    def _scope_suffix(self) -> str:
        """The client bound, appended to a cross-client finding's own claim.

        A finding that lists offenders from one client while reading as a
        statement about the system is the same defect as the silent pass, in the
        other direction: it understates rather than overstates, and the reader
        cannot tell which they are holding.
        """
        note = client_scope.caveat(self._client_scope())
        return "\n\n" + note if note else ""

    def check_obsolete_clients(self):
        """SAP's OBSCNT-A: clients 066 and 001 should not still be there.

        THE OPERATOR CARRIES THE MEANING, AND READING ONLY THE PREDICATE WOULD
        INVERT THIS CHECK. SAP's policy `2AOBSCNT.xml` writes both clauses
        identically — `<compliant>MANDT = '066'</compliant>` and
        `<noncompliant>MANDT = '066'</noncompliant>` — and puts the semantics in
        `operator="NOT_EXIST"`: the system is compliant when NO such row exists.
        Transcribing the compliant clause at face value would have reported every
        estate that has removed client 066 as failing, and every estate that kept
        it as passing.

        WHY THE TWO ARE DIFFERENT SEVERITIES. SAP's own wording differs: 066
        "must not exist", while 001 "must be deleted IF NOT USED". A template
        client somebody genuinely uses is not a finding, so 001 is raised as a
        question rather than a defect.
        """
        rows = self.data.get("client_settings")
        if not rows:
            return                     # absence is the coverage manifest's to report
        present = {client_scope._normalise(client_scope._client_of(r))
                   for r in rows}
        present.discard("")

        if "066" in present:
            self.finding(
                check_id="OBSCNT-001",
                title="Obsolete client 066 still exists",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "Client 066 is the EarlyWatch client. SAP's own security "
                    "baseline requires that it not exist — it carries delivered "
                    "users, is almost never logged into, and therefore is almost "
                    "never noticed. Its standard-user passwords age in place."),
                affected_items=["client 066 present in T000"],
                affected_objects=[{"type": "client", "name": "066"}],
                remediation=(
                    "Delete client 066 (SCC5) once you have confirmed nothing "
                    "uses it. SAP has not shipped it for new installations for "
                    "many releases; an estate that still has it is usually one "
                    "that was upgraded rather than installed."),
                references=["SAP Security Baseline OBSCNT-A",
                            "SAP policy 2AOBSCNT check OBSCNT-A.1"],
                details={"sap_check_id": "OBSCNT-A.1",
                         "sap_operator": "NOT_EXIST"},
            )

        if "001" in present:
            self.finding(
                check_id="OBSCNT-002",
                title="Template client 001 still exists",
                severity=self.SEVERITY_LOW,
                category=self.CATEGORY,
                description=(
                    "Client 001 is the delivered template copy of client 000. "
                    "SAP's baseline asks for it to be deleted IF IT IS NOT USED "
                    "— and whether it is used is a question this export cannot "
                    "answer, which is why this is raised at LOW rather than as a "
                    "defect. Where it is unused it is a second copy of the "
                    "delivered credentials nobody watches."),
                affected_items=["client 001 present in T000"],
                affected_objects=[{"type": "client", "name": "001"}],
                remediation=(
                    "Confirm whether anything uses client 001. If nothing does, "
                    "delete it (SCC5). If something does, record that decision — "
                    "the baseline asks the question rather than forbidding the "
                    "client."),
                references=["SAP Security Baseline OBSCNT-A",
                            "SAP policy 2AOBSCNT check OBSCNT-A.2"],
                details={"sap_check_id": "OBSCNT-A.2",
                         "sap_operator": "NOT_EXIST"},
            )

    def check_client_scope(self):
        """WHAT THE STANDARD-USER CHECKS DID NOT LOOK AT.

        DEGRADES COVERAGE. STDUSR-002 and STDUSR-003 are cross-client by nature —
        SAP*/DDIC default passwords in EVERY client, TMSADM only in 000, client
        066 removal — and both returned in silence when they found no offenders.
        An export covering only the productive client therefore produced no
        finding at all, and the reader concluded that no standard user anywhere
        has a default password, when the two clients most likely to carry one
        (000 and 001) were never read.

        Section 3.1 of the RISE model is blunt about what that costs: "Silently
        passing a cross-client check on partial data is a defect an auditor can
        catch, and it is the kind that ends an engagement."
        """
        if not self.data.get("standard_users"):
            return                     # the no-data path belongs to the checks
        scope = self._client_scope()
        if scope["complete"]:
            return
        unexamined = scope["unexamined"]
        why = [c + " - " + client_scope.WELL_KNOWN_CLIENTS[c]
               for c in unexamined if c in client_scope.WELL_KNOWN_CLIENTS]
        detail = ""
        if why:
            detail = "\n\nWhy the uncovered clients matter:\n- " + "\n- ".join(why)
        self.finding(
            check_id="STDUSR-COV-001",
            title=("Standard-user checks covered %d client(s), not the whole system"
                   % len(scope["examined"])),
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "The standard-user export evidences client(s) %s. Client(s) %s "
                "were not covered, so nothing in this report speaks to SAP*, "
                "DDIC, SAPCPIC, EARLYWATCH or TMSADM in them.\n\n"
                "This matters more than an ordinary coverage gap because the "
                "standard-user checks are cross-client by nature: a clean "
                "STDUSR-002 means \"no default passwords in the clients we saw\", "
                "never \"no default passwords\".\n\n"
                "Scope established from: %s.%s"
                % (", ".join(scope["examined"]), ", ".join(unexamined),
                   scope["basis"], detail)
            ),
            affected_items=["client %s not covered" % c for c in unexamined],
            remediation=(
                "Run RSUSR003 in every client and supply the combined export. "
                "Where client 000 is restricted and on request - the usual case "
                "in RISE - ask SAP for its standard-user status rather than "
                "leaving the clients most likely to carry delivered credentials "
                "unassessed."
            ),
            references=["docs/RISE_SECURITY_MODEL.md section 3.1",
                        "SAP Security Baseline policy 1ASTDUSR"],
            details={"degrades_coverage": True,
                     "clients_examined": scope["examined"],
                     "clients_unexamined": unexamined,
                     "scope_basis": scope["basis"]},
        )

    def check_default_passwords(self):
        """RSUSR003: standard users with SAP default passwords still valid."""
        rows = self.data.get("standard_users")
        if not rows:
            return
        offenders = []
        objects = []
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
                # No per-member client: this is an aggregate spanning several clients, and
                # fingerprint_finding falls back to objs[0].client when the finding does
                # not declare one. Stamping the client on the members would therefore let
                # the member list leak into the aggregate's identity — fixing the first
                # offender would move objs[0] to another client and re-raise the finding.
                objects.append({"type": "user", "name": user})
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
                    + self._scope_suffix()
                ),
                affected_items=offenders,
                affected_objects=objects,
                scope="aggregate",
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
        objects = []
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
                # Client deliberately omitted on the members — see check_default_passwords.
                if user:
                    objects.append({"type": "user", "name": user})
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
                    + self._scope_suffix()
                ),
                affected_items=offenders,
                affected_objects=objects,
                scope="aggregate",
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
        objects = []
        for row in self._trust_rows():
            trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "TRUSTED_SYSTEM",
                                "RFC_TRUSTSY", "SID").upper()
            if not trusted or trusted == local:
                continue
            nonprod = trusted[:1] in self.NONPROD_PREFIXES
            tag = " [likely NON-PRODUCTION tier]" if nonprod else ""
            items.append((nonprod, f"Trusted system {trusted}{tag}"))
            # No qualifier: the non-production tag is inferred from the SID prefix, not
            # exported, and qualifying the node would split one trusted system into two
            # graph nodes across TRUST-001 and TRUST-003.
            objects.append({"type": "trusted_system", "name": trusted})
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
            # One inventory-style finding over the whole trust list: removing one trusted
            # system must not retire this finding and raise a fresh one with a reset age.
            affected_objects=objects,
            scope="aggregate",
            system=local or None,
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
        objects = []
        val = self._param("rfc/selftrust")
        if val is not None and val.strip() == "1":
            offenders.append("rfc/selftrust = 1")
            objects.append({"type": "parameter_name", "name": "rfc/selftrust",
                            "qualifier": val.strip()})
        local = str(self.get_config("local_system_sid", "")).strip().upper()
        if local:
            for row in self._trust_rows():
                trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "SID").upper()
                if trusted == local:
                    offenders.append(f"RFCSYSACL self-trust entry for {local}")
                    objects.append({"type": "trusted_system", "name": local})
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
                # Two independent indicators (the parameter and the RFCSYSACL row) for ONE
                # defect. Clearing the parameter while the self-referential entry remains
                # must keep the same finding, not restart its clock, so identity stays on
                # (system, client, TRUST-002) and the indicators ride along as members.
                affected_objects=objects,
                scope="aggregate",
                system=local or None,
                remediation=(
                    "Set rfc/selftrust = 0 and remove self-referential trust entries unless a "
                    "specific, reviewed scenario requires it."
                ),
                references=["SAP Note 128447", "SAP Security Baseline — rfc/selftrust"],
            )

    def check_trust_migration(self):
        """Legacy trust ticket method still allowed (not migrated to 2020 method)."""
        offenders = []
        objects = []
        val = self._param("rfc/allowoldticket4tt")
        if val is not None and str(val).strip().lower() in ("yes", "1", "true"):
            offenders.append("rfc/allowoldticket4tt = yes (legacy trust tickets accepted)")
            # No qualifier: the check accepts yes/1/true, so pinning the exported spelling
            # would split one parameter into three graph nodes.
            objects.append({"type": "parameter_name", "name": "rfc/allowoldticket4tt"})
        for row in self._trust_rows():
            trusted = self._get(row, "RFCTRUSTSY", "RFCSYSID", "TRUSTED_SID", "SID").upper()
            migrated = self._get(row, "MIGRATED", "TRUST_METHOD", "TRUSTMETH", "MIGRATION_CODE",
                                 "SECURITY_METHOD")
            if trusted and migrated and not (self._truthy(migrated) or migrated in ("3", "MIGRATED")):
                offenders.append(f"Trusted system {trusted} — trust method '{migrated}' (not migrated)")
                objects.append({"type": "trusted_system", "name": trusted})
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
                # Aggregate: migrating one relationship shrinks the list but does not fix
                # the defect, so the finding must keep its identity and its age.
                affected_objects=objects,
                scope="aggregate",
                system=self._local_sid() or None,
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
        objects = []
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
                # Both halves of the hop are real exported objects: the destination and
                # the stored user it runs as. The destination carries no qualifier so it
                # stays the same graph node the RFC-destination checks produce.
                if name:
                    objects.append({"type": "destination", "name": name})
                objects.append({"type": "user", "name": user})
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
                affected_objects=objects,
                scope="aggregate",
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
                # Aggregate, and deliberately with no affected_objects: an offending
                # saprouttab line is identified only by its source/target host and port,
                # and the offending lines are precisely the ones whose target is "*". A
                # wildcard is not an object, and inventing a name for it would fabricate a
                # graph node that does not exist in the export.
                scope="aggregate",
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
        objects = []
        internal = self._param("rdisp/msserv_internal")
        if internal is not None and internal.strip() == "0":
            offenders.append("rdisp/msserv_internal = 0 (no dedicated internal port — external "
                             "clients can reach the internal message-server channel)")
            objects.append({"type": "parameter_name", "name": "rdisp/msserv_internal",
                            "qualifier": internal.strip()})
        monitor = self._param("ms/monitor")
        if monitor is not None and monitor.strip() not in ("0", ""):
            offenders.append(f"ms/monitor = {monitor} (external message-server administration allowed)")
            # No qualifier: any non-zero value trips this, so the value must not enter the
            # node key or a 1 -> 2 change would look like a different object.
            objects.append({"type": "parameter_name", "name": "ms/monitor"})
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
                # Two parameters, one weakness. Setting ms/monitor = 0 while the internal
                # port is still shared must not retire this finding and re-raise it.
                # No message_server object: no export in this bundle names the message
                # server's host or instance, and a placeholder would be invented, not read.
                affected_objects=objects,
                scope="aggregate",
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
                # One parameter is the whole defect, so its identity is the parameter.
                # No qualifier: the check fires on ANY value other than 1, and putting the
                # value in identity would retire and re-raise the finding on a 0 -> 2
                # change that fixes nothing.
                affected_objects=[{"type": "parameter_name", "name": "ucon/rfc/active"}],
                scope="object",
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
                # The unset parameter IS the object. Its value is empty by definition of
                # the check, so there is nothing to qualify it with.
                affected_objects=[{"type": "parameter_name", "name": "gw/prxy_info"}],
                scope="object",
                remediation=(
                    "Create a prxyinfo ACL file with explicit source/destination rules, point "
                    "gw/prxy_info at it, and set gw/acl_mode_proxy = 1."
                ),
                references=["SAP Note 910918 — Parameter gw/prxy_info",
                            "SAP Note 3224889 — gw/acl_mode_proxy default settings",
                            "SAP Security Baseline — RFC Gateway ACLs"],
            )

    def check_message_server_acl(self):
        """Message-server ACL FILE CONTENT (ms/acl_info): a wildcard/permit-all or
        missing ACL lets ANY host register as an application server ('rogue app server'
        — the 10KBLAZE class). check_message_server_ports() only inspects the ms/*
        parameters; this parses the actual rule lines."""
        rows = self.data.get("ms_acl")
        if rows is None:
            return  # no ACL export -> params check (check_message_server_ports) still applies
        permit_all = []
        rule_count = 0
        for r in rows:
            if not isinstance(r, dict):
                continue
            host = self._get(r, "HOST", "HOSTNAME", "ADDR", "IP")
            line = self._get(r, "LINE", "RULE", "ACL", "ENTRY", "RAW")
            text = (host + " " + line).strip()
            if not text:
                continue
            rule_count += 1
            # HOST=* (any) / bare '*' / a permit-all line = unrestricted registration.
            if host in ("*", "0.0.0.0", "0.0.0.0/0") or "HOST=*" in line.upper().replace(" ", "") \
                    or line.strip() == "*":
                permit_all.append(text[:80])
        if permit_all or rule_count == 0:
            detail = (f"{len(permit_all)} permit-all/wildcard rule(s)" if permit_all
                      else "the ACL file is present but contains no rules")
            self.finding(
                check_id="TRUST-010",
                title="Message-server ACL permits any host to register (rogue app server)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "The message-server ACL (ms/acl_info file) " + detail + ". With a wildcard or empty "
                    "ACL, any host that can reach the internal message-server port can register as an "
                    "application server of the SAP system, join the work-process pool, and intercept or "
                    "inject traffic — the rogue-application-server attack (CISA AA19-122A / '10KBLAZE'). "
                    "The ms/* parameter checks cannot see this; it is in the ACL rule content."
                ),
                affected_items=(permit_all[:50] or ["ms/acl_info file present but empty"]),
                # Aggregate over the ACL rule set: tightening one wildcard rule while
                # another remains must not reset this finding's age. No affected_objects —
                # a rule is identified by its HOST, and the offending rules are exactly
                # those whose HOST is "*" (or which have no rules at all). There is no
                # object there to name without inventing one.
                scope="aggregate",
                remediation=(
                    "Populate ms/acl_info with explicit HOST rules listing ONLY the known application "
                    "servers of this system (no HOST=* / wildcard), and ensure ms/acl_info points at "
                    "the file. Combine with reginfo/secinfo gateway ACLs."
                ),
                references=["SAP Note 821875 — Security settings in the message server (ms/acl_info)",
                            "CISA AA19-122A / '10KBLAZE' — rogue SAP application server",
                            "SAP Security Baseline — Message Server ACL"],
                details={"count": len(permit_all)},
            )
