"""
OS & Infrastructure Hardening Auditor (`osec`)
==============================================
The operating-system layer of an SAP system: the accounts that run and
administer it, the permissions on its directories, and the host services around
it. This is the layer the NetWeaver Security Guide's "Operating System and
Database Security" section and the Security Baseline's `USRCTR-O` requirement
cover, and it is the largest surface that RISE excludes and on-premise /
self-managed-hyperscaler hosting exposes.

WHY THIS MODULE IS DEPLOYMENT-MODE-AWARE WITHOUT KNOWING THE MODE
----------------------------------------------------------------
It does not read the deployment mode and does not need to. In RISE the customer
has no OS access, so these exports never arrive and every check here self-skips;
`modules/rise_ownership.py` then marks the `OSEC-` family `not_assessable`,
which is the honest state — SAP ECS owns the host and the customer cannot even
see it, let alone fix it (the same treatment `TRUST-010`, the message-server
ACL, already gets). On-premise and on a self-managed hyperscaler VM the customer
owns OS root, so the exports can be supplied and `rise_ownership` returns
`customer_fixable` for the whole family with no code here. Decision D10.

THE DISCIPLINE: ABSENCE IS NOT INSECURE
---------------------------------------
Every check reads its own source and returns early when it is missing. A host
that supplied no OS export is not reported as failing — the coverage manifest
records the OS domain as UNSUPPLIED (not "clear"), which is the honest sentence.
An empty value that IS present stays a real answer, the same rule the profile
readers follow.

Data sources (any one absent -> that check self-skips):
  - os_users               → OS account inventory (name, uid, groups, shell, admin)
  - os_groups              → OS group membership (group -> members)
  - os_file_permissions    → filesystem permissions on SAP directories
  - os_services            → host network services and their state
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules import host_platforms
from modules.base_auditor import BaseAuditor
from modules.deployment_modes import is_rise


class OSSecurityAuditor(BaseAuditor):

    CATEGORY = "OS & Infrastructure Security"

    #: SAP service accounts that must NOT hold administrative OS privilege.
    #: `<sid>adm` is deliberately excluded: the NetWeaver guide says it IS a
    #: member of the local Administrators group on Windows and runs the system,
    #: so flagging its privilege would be a false positive against SAP's own
    #: design. The finding is the accounts that must stay unprivileged and are
    #: not: the service account and the Host Agent account.
    UNPRIV_SERVICE_ACCOUNTS = ("sapservice", "sapadm")

    #: The account whose UNIX login shell must remain a non-login shell.
    HOST_AGENT_ACCOUNT = "sapadm"
    NONLOGIN_SHELLS = frozenset({
        "/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin",
        "/bin/nologin",
    })

    #: Path fragments that mark a directory as SAP's. Matched case-insensitively
    #: and on both separators so a Windows or UNIX export is read the same way.
    SAP_PATH_MARKERS = ("/usr/sap", "\\usr\\sap", "/sapmnt", "\\sapmnt")

    #: Fragments of the paths that must be owner-only (the secure store and the
    #: security directory hold key material; the guide sets them to 700 / deny
    #: Administrators).
    OWNER_ONLY_MARKERS = ("/global/security", "\\global\\security",
                          "secstore", "/sec/", "\\sec\\", "/rsecssfs", "\\rsecssfs")

    #: Host services whose mere presence the guide says to remove. Cleartext or
    #: trust-based remote access first, then the directory services that expose
    #: password hashes across the network.
    CLEARTEXT_REMOTE = ("rlogin", "rsh", "rexec", "telnet", "rlogind", "rshd",
                        "in.rlogind", "in.telnetd", "in.rshd")
    DIRECTORY_SERVICES = ("ypbind", "ypserv", "nis", "rpc.yppasswdd")

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_cloud_infra_boundary()
        self.check_service_account_privilege()
        self.check_host_agent_shell()
        self.check_sap_directory_world_writable()
        self.check_secure_store_directory_exposure()
        self.check_dangerous_host_services()
        return self.findings

    # ── OSEC-CLOUD-001 ───────────────────────────────────────────────────────
    def check_cloud_infra_boundary(self):
        """Where MonitorRisk stops and the customer's CNAPP begins (D10).

        Reporting metadata, not a defect. On a customer-managed hyperscaler VM
        (host_platform aws/azure/gcp, and NOT a RISE tenant — where the whole
        stack is SAP's) the report names the boundary D10 draws: MonitorRisk
        audits the SAP application, the OS and HANA, and the cloud infrastructure
        BELOW the OS is the customer's CNAPP's job. Emitted from run_context, so it
        needs no OS export — the platform tag alone is the input.
        """
        platform = self.run_context.get("host_platform")
        if not host_platforms.is_hyperscaler(platform):
            return
        if is_rise(self.run_context.get("deployment_mode")):
            return  # in RISE SAP owns every layer; the CNAPP boundary is moot
        self.finding(
            check_id="OSEC-CLOUD-001",
            title="Cloud infrastructure below the OS is out of scope (self-managed hyperscaler)",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=host_platforms.cloud_infra_boundary_note(platform),
            affected_items=[f"host platform: {host_platforms.label(platform)}"],
            # No object: a scope statement about the whole scan, not a finding
            # about a named host artifact. Aggregate keeps it identified by
            # (system, check_id) alone, so it does not churn run to run.
            scope="aggregate",
            remediation=(
                "No action in MonitorRisk. Assess the cloud infrastructure below "
                "the OS — hypervisor, storage encryption, network security groups, "
                "cloud IAM — with your cloud security platform (CNAPP). This note "
                "marks the boundary so the two tools' scopes neither overlap "
                "silently nor leave a gap between them."
            ),
            references=["docs/DECISIONS.md D10 — all-inclusive hosting; hosting is a "
                        "responsibility axis, not a coverage axis"],
            # No degrades_coverage flag: this is a scope BOUNDARY, not a coverage
            # gap, so it must not arm the release gate's fail-closed path the way
            # the *-COV-* coverage findings do (docs/RELEASE_GATE.md).
            details={"host_platform": host_platforms.normalise(platform)},
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        low = {str(k).strip().lower(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.lower())
            if v is not None and str(v).strip():
                return str(v).strip()
        return ""

    @staticmethod
    def _rows(value: Any) -> List[dict]:
        return [r for r in (value or []) if isinstance(r, dict)]

    # ── OSEC-USR-001 ─────────────────────────────────────────────────────────
    def check_service_account_privilege(self):
        """SAP service accounts holding administrative OS privilege.

        Windows: `SAPService<SID>` and `sapadm` must not be in the local
        Administrators group. UNIX: `<sid>adm` and `sapadm` must not have root
        (uid 0 or the root group). A service account with admin rights turns any
        code-execution bug in the SAP runtime into host compromise.
        """
        users = self._rows(self.data.get("os_users"))
        if not users:
            return

        admin_group_members = self._admin_group_members()
        for row in users:
            name = self._get(row, "name", "user", "username", "login", "account")
            if not name:
                continue
            low = name.lower()
            is_service = low.startswith("sapservice") or low == "sapadm"
            is_sidadm = low.endswith("adm") and low != "sapadm" and len(low) == 6
            if not (is_service or is_sidadm):
                continue

            uid = self._get(row, "uid", "userid", "id")
            groups = self._groups_of(row)
            in_admin_grp = low in admin_group_members
            # Explicit admin flags some exports carry.
            admin_flag = self._get(row, "is_admin", "admin", "administrator").lower() \
                in ("1", "x", "yes", "true", "y")

            reason = None
            if is_service:
                # Service/Host-Agent accounts must never be privileged, on any OS.
                if uid == "0" or "root" in groups or in_admin_grp or admin_flag \
                        or "administrators" in groups:
                    where = ("uid 0 / root group" if (uid == "0" or "root" in groups)
                             else "local Administrators")
                    reason = f"{name} is privileged ({where}) — must be unprivileged"
            elif is_sidadm:
                # <sid>adm is an admin on Windows by design; the finding is UNIX root.
                if uid == "0" or "root" in groups:
                    reason = f"{name} has root (uid 0 / root group) — <sid>adm must not"
            if not reason:
                continue

            # ONE OFFENDING ACCOUNT IS ONE FINDING (object scope), the same shape
            # as the unlocked-default-user checks: closing one account's
            # over-privilege must not retire another's, and merging them would
            # collapse several defects into one and lose all but the first.
            self.finding(
                check_id="OSEC-USR-001",
                title="SAP OS service account holds administrative privilege",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "An SAP operating-system account that must be unprivileged holds "
                    "administrative rights. SAPService<SID> and sapadm must not be in "
                    "the local Administrators group on Windows, and <sid>adm / sapadm "
                    "must not have root on UNIX. A privileged service account makes any "
                    "flaw in the SAP runtime a full host compromise, and lets a break-in "
                    "on one SAP system reach the OS the whole landscape shares."
                ),
                affected_items=[reason],
                affected_objects=[{"type": "os_user", "name": name}],
                scope="object",
                remediation=(
                    "Remove SAPService<SID> and sapadm from the local Administrators "
                    "group (Windows) and ensure <sid>adm and sapadm have no root/uid-0 "
                    "membership (UNIX). Upgrading SAP Host Agent to the latest version "
                    "resets sapadm to compliant automatically."
                ),
                references=[
                    "SAP NetWeaver Security Guide 7.5 — USRCTR-O (OS user permissions)",
                    "SAP Security Baseline — USRCTR-O a)/b)",
                    "SAP System Security on Windows / under UNIX-LINUX",
                ],
                details={"account": name},
            )

    # ── OSEC-USR-002 ─────────────────────────────────────────────────────────
    def check_host_agent_shell(self):
        """sapadm login shell must remain a non-login shell (UNIX).

        The guide states the default `/bin/false` for `sapadm` in `/etc/passwd`
        must not be changed. A real login shell on the Host Agent account turns
        it into an interactive foothold on the host.
        """
        users = self._rows(self.data.get("os_users"))
        if not users:
            return
        for row in users:
            name = self._get(row, "name", "user", "username", "login", "account")
            if name.lower() != self.HOST_AGENT_ACCOUNT:
                continue
            shell = self._get(row, "shell", "login_shell", "loginshell")
            if not shell:
                continue  # this row can't tell us the shell; keep looking
            if shell.lower() in self.NONLOGIN_SHELLS:
                return  # compliant
            self.finding(
                check_id="OSEC-USR-002",
                title="SAP Host Agent account sapadm has an interactive login shell",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"The sapadm account (SAP Host Agent) has login shell {shell!r}. "
                    "The NetWeaver guide requires its default non-login shell "
                    "(/bin/false) to be kept: sapadm exists to run the Host Agent, not "
                    "to log in, and an interactive shell on it is a standing foothold."
                ),
                affected_items=[f"sapadm shell = {shell}"],
                affected_objects=[{"type": "os_user", "name": "sapadm"}],
                scope="object",
                remediation=(
                    "Restore sapadm's login shell to /bin/false in /etc/passwd. "
                    "Upgrading SAP Host Agent to the latest version corrects it "
                    "automatically."
                ),
                references=[
                    "SAP NetWeaver Security Guide 7.5 — USRCTR-O b)",
                    "SAP System Security Under UNIX/LINUX",
                ],
            )
            return

    # ── OSEC-FILE-001 ────────────────────────────────────────────────────────
    def check_sap_directory_world_writable(self):
        """SAP directories writable by everyone.

        `/usr/sap`, `/sapmnt` and their subtrees hold the kernel, profiles and
        transport data. A world-writable (UNIX "other" write bit, or Windows
        Everyone/Users write) entry there lets any local account replace a
        binary the SAP system will run as <sid>adm.
        """
        rows = self._rows(self.data.get("os_file_permissions"))
        if not rows:
            return
        offenders, objects = [], []
        for row in rows:
            path = self._get(row, "path", "file", "name", "directory", "dir")
            if not path or not self._is_sap_path(path):
                continue
            mode = self._get(row, "mode", "perms", "permissions", "octal", "rights")
            acl = self._get(row, "acl", "aces", "access")
            if self._others_writable(mode) or self._windows_open_write(acl):
                shown = mode or acl or "world-writable"
                offenders.append(f"{path} ({shown})")
                objects.append({"type": "path", "name": path})

        if offenders:
            self.finding(
                check_id="OSEC-FILE-001",
                title="SAP directory is writable by all OS users",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "One or more directories or files under the SAP installation are "
                    "writable by every local account (UNIX 'other' write bit, or Windows "
                    "Everyone/Users write). Anything under /usr/sap or /sapmnt is executed "
                    "or read by the SAP system as <sid>adm, so a world-writable entry there "
                    "is a local-privilege-escalation path into the SAP runtime."
                ),
                affected_items=offenders[:50],
                affected_objects=objects,
                # Aggregate over the offending paths: tightening one while another
                # stays open must shrink the finding, not retire and re-raise it.
                scope="aggregate",
                remediation=(
                    "Remove world/Everyone write from SAP directories. The NetWeaver "
                    "guide's baseline grants /usr/sap and /sapmnt to <sid>adm:sapsys "
                    "(UNIX) or SAP_<SID>_LocalAdmin (Windows) and no broader; align to it."
                ),
                references=[
                    "SAP NetWeaver Security Guide 7.5 — Setting Access Privileges for SAP "
                    "System Directories",
                    "SAP Security Baseline — USRCTR-O c)",
                ],
                details={"count": len(offenders)},
            )

    # ── OSEC-FILE-002 ────────────────────────────────────────────────────────
    def check_secure_store_directory_exposure(self):
        """The secure store / security directory must be owner-only.

        The guide sets `/usr/sap/<SID>/SYS/global/security` and the SecStore
        material to 700 (UNIX) / deny Administrators (Windows). Any group or
        other access there exposes the key that protects stored credentials.
        """
        rows = self._rows(self.data.get("os_file_permissions"))
        if not rows:
            return
        offenders, objects = [], []
        for row in rows:
            path = self._get(row, "path", "file", "name", "directory", "dir")
            if not path or not self._is_owner_only_path(path):
                continue
            mode = self._get(row, "mode", "perms", "permissions", "octal", "rights")
            if not mode:
                continue
            g, o = self._group_other_bits(mode)
            if g or o:
                offenders.append(f"{path} ({mode}) — accessible beyond owner")
                objects.append({"type": "path", "name": path})

        if offenders:
            self.finding(
                check_id="OSEC-FILE-002",
                title="SAP secure-store / security directory is accessible beyond its owner",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "The SAP security directory or secure store is readable or writable by "
                    "group or other. It holds the individual main key that protects the "
                    "secure store (RFC/DB credentials); the NetWeaver guide requires it to "
                    "be owner-only (700 on UNIX, deny-Administrators on Windows). Group or "
                    "other access there weakens the protection of every credential it guards."
                ),
                affected_items=offenders[:50],
                affected_objects=objects,
                scope="aggregate",
                remediation=(
                    "Set the security directory and secure-store files to 700 (owner "
                    "<sid>adm) on UNIX; on Windows grant only SAP_<SID>_LocalAdmin and "
                    "deny the Administrators group. See SECSTO-A for the store's own key."
                ),
                references=[
                    "SAP NetWeaver Security Guide 7.5 — SAP System Directory permissions "
                    "(/global/security 700)",
                    "SAP Security Baseline — SECSTO-A",
                ],
                details={"count": len(offenders)},
            )

    # ── OSEC-NET-001 ─────────────────────────────────────────────────────────
    def check_dangerous_host_services(self):
        """Cleartext-remote and directory services on the SAP host.

        The guide names rlogin/rsh/telnet (trust-based or cleartext remote
        access) and NIS (network-readable password hashes) as services to remove
        from an SAP server. Each widens the host's attack surface below the SAP
        layer the rest of this product audits.
        """
        rows = self._rows(self.data.get("os_services"))
        if not rows:
            return
        cleartext, directory, objects = [], [], []
        for row in rows:
            name = self._get(row, "name", "service", "daemon", "port_name").lower()
            if not name:
                continue
            state = self._get(row, "state", "status", "enabled", "running", "active").lower()
            # Present-and-enabled only. A service listed as disabled/stopped is a
            # real answer that it is off, and must not fire.
            if state in ("disabled", "stopped", "inactive", "off", "0", "no", "false"):
                continue
            if any(s in name for s in self.CLEARTEXT_REMOTE):
                cleartext.append(name)
                objects.append({"type": "os_service", "name": name})
            elif any(s in name for s in self.DIRECTORY_SERVICES):
                directory.append(name)
                objects.append({"type": "os_service", "name": name})

        if cleartext or directory:
            items = ([f"{s} (cleartext/trust-based remote access)" for s in cleartext]
                     + [f"{s} (network-exposed password directory)" for s in directory])
            self.finding(
                check_id="OSEC-NET-001",
                title="Dangerous OS network service enabled on the SAP host",
                # A cleartext remote-shell service is the sharper risk than NIS.
                severity=self.SEVERITY_HIGH if cleartext else self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "The SAP host runs an operating-system network service the NetWeaver "
                    "guide says to disable on a server: rlogin/rsh/telnet give trust-based "
                    "or cleartext remote access, and NIS serves password hashes across the "
                    "network. These sit below the SAP layer and give an attacker a route to "
                    "the host that SAP-level controls cannot see or stop."
                ),
                affected_items=items,
                affected_objects=objects,
                scope="aggregate",
                remediation=(
                    "Disable rlogin/rsh/rexec/telnet on the SAP host and use SSH instead; "
                    "replace NIS with a secured directory (LDAP over TLS or Kerberos). "
                    "Disable every host network service the SAP system does not require."
                ),
                references=[
                    "SAP NetWeaver Security Guide 7.5 — Protecting Specific Properties, "
                    "Files and Services (UNIX/LINUX)",
                    "SAP NetWeaver Security Guide 7.5 — Network Services",
                ],
                details={"cleartext": len(cleartext), "directory": len(directory)},
            )

    # ── permission / membership parsing ──────────────────────────────────────
    def _admin_group_members(self) -> set:
        """Lower-cased members of the Windows local Administrators group."""
        members = set()
        for row in self._rows(self.data.get("os_groups")):
            gname = self._get(row, "group", "name", "groupname").lower()
            if gname not in ("administrators", "administrator"):
                continue
            raw = self._get(row, "members", "users", "member", "memberof")
            for m in raw.replace(";", ",").split(","):
                m = m.strip().lower()
                if m:
                    # A member may be "DOMAIN\user" or "host\user"; key on the leaf.
                    members.add(m.split("\\")[-1])
        return members

    def _groups_of(self, row: dict) -> set:
        raw = self._get(row, "groups", "memberof", "local_groups", "group",
                        "primary_group", "gid")
        out = set()
        for g in raw.replace(";", ",").split(","):
            g = g.strip().lower()
            if g:
                out.add(g.split("\\")[-1])
        return out

    def _is_sap_path(self, path: str) -> bool:
        p = path.lower()
        return any(m in p for m in self.SAP_PATH_MARKERS)

    def _is_owner_only_path(self, path: str) -> bool:
        p = path.lower()
        return any(m in p for m in self.OWNER_ONLY_MARKERS)

    @staticmethod
    def _octal_triples(mode: str):
        """(owner, group, other) octal digits, or None if not a numeric mode."""
        digits = "".join(c for c in str(mode) if c.isdigit())
        if len(digits) < 3:
            return None
        last3 = digits[-3:]
        try:
            return int(last3[0]), int(last3[1]), int(last3[2])
        except ValueError:
            return None

    @staticmethod
    def _symbolic_writable_other(mode: str) -> Optional[bool]:
        """For an `ls -l` style string, is the 'other' triple writable?"""
        text = str(mode).strip()
        # rwxr-xr-x is 9 chars; a leading type char (d/-/l) makes 10.
        core = text[1:] if len(text) == 10 else text
        if len(core) == 9 and set(core) <= set("rwxsStT-"):
            return "w" in core[6:9].lower()
        return None

    def _others_writable(self, mode: str) -> bool:
        if not mode:
            return False
        sym = self._symbolic_writable_other(mode)
        if sym is not None:
            return sym
        triples = self._octal_triples(mode)
        if triples is None:
            return False
        return triples[2] in (2, 3, 6, 7)

    def _group_other_bits(self, mode: str):
        """(group_has_access, other_has_access) for an owner-only check."""
        triples = self._octal_triples(mode)
        if triples is not None:
            return triples[1] != 0, triples[2] != 0
        text = str(mode).strip()
        core = text[1:] if len(text) == 10 else text
        if len(core) == 9 and set(core) <= set("rwxsStT-"):
            group = core[3:6].replace("-", "") != ""
            other = core[6:9].replace("-", "") != ""
            return group, other
        return False, False

    @staticmethod
    def _windows_open_write(acl: str) -> bool:
        """Does a Windows ACL string grant write to Everyone / Users?"""
        if not acl:
            return False
        a = acl.lower()
        broad = ("everyone" in a or "\\users" in a or "authenticated users" in a
                 or "builtin\\users" in a)
        if not broad:
            return False
        # (F) full, (M) modify, (W) write, or the word write/modify/full.
        return any(tok in a for tok in ("(f)", "(m)", "(w)", "write", "modify",
                                        "fullcontrol", "full control"))
