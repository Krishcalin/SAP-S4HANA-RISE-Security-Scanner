"""
SAP LogServ gateway-log review (retrospective, over the exported window)
========================================================================
SAP LogServ forwards far more than the ABAP Security Audit Log: the RFC **gateway**
log records every external program a system registered or started and every
connection the secinfo / reginfo ACL allowed, denied or let through in simulation
mode. `modules/logserv_ocsf.to_system_events` pulls that gateway class out of the
OCSF stream (kept separate from the Security Audit Log rows `log_review` reviews),
and this module reviews it.

SAME DISCIPLINE AS log_review. This is a **retrospective review over the exported
window**, not monitoring and not live — it reports what the gateway log already
recorded. The findings here complement the CONFIGURATION checks that already exist
(`INTG-GW-*` secinfo/reginfo ACLs, `BASELINE-007` gw/acl_mode, `PARAM-gw/*`): the
config checks say the door is unlocked, these say something walked through it in
the window. The correlation of the two is `CorrelationAuditor` (`CORR-GW-*`).

WHY A SEPARATE MODULE, NOT log_review. A gateway event has no transaction code, a
different actor and an ACL verdict rather than an audit event class; it does not
fit the Security-Audit-Log row model `log_review` classifies. Its findings also
belong to the INTEGRATION team and the interface surface, not the audit-log owner.
The check-id prefix `GWLOG-` is fresh (`LOG-` is taken by log_monitoring).
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from modules import logserv_ocsf
from modules.base_auditor import BaseAuditor


class LogServReviewAuditor(BaseAuditor):
    """Retrospective review of the SAP LogServ gateway log over the exported window."""

    # One category per log class, so each routes to the domain that owns that
    # subject (see modules/domains.py) while the check-id prefix routes it to the
    # team that fixes it (see modules/rise_ownership.py). The gateway category is a
    # class attribute (self.CATEGORY) because several gateway checks share it; the
    # HANA / ICM / Network categories are passed as literal strings at each finding()
    # call, which is the only form the coverage catalogue scanner resolves for a
    # per-finding category (it reads `category=self.CATEGORY` or a literal, not other
    # class attributes).
    CATEGORY = "Gateway Log Review"           # gateway log review

    DATE_KEYS = ("DATE",)
    TIME_KEYS = ("TIME",)
    _DATE_FORMATS = ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y")
    _TIME_FORMATS = ("%H:%M:%S", "%H%M%S", "%H:%M")

    #: Registration / start actions — an external program attaching to the gateway.
    REGISTER_ACTIONS = frozenset({"register", "start"})
    #: HANA standard super-users whose activity in the log is always worth a look.
    HANA_PRIVILEGED_USERS = frozenset({"SYSTEM", "SYS", "_SYS_REPO", "_SYS_STATISTICS",
                                       "DBACOCKPIT", "SAPDBCTRL"})
    #: HANA actions that change a privilege grant.
    HANA_GRANT_ACTIONS = frozenset({"grant", "revoke"})
    #: ICF paths that serve an administrative console — a request here is high-value.
    ADMIN_PATH_MARKERS = ("/admin", "webadmin", "/wdisp/admin", "/sap/admin",
                          "/sap/bc/webdynpro/sap/wd_analyze", "/sap/bc/bsp/sap/system",
                          "/sap/bc/ping", "/sap/public/info", "/sap/bc/gui/sap/its/webadmin")
    #: ICF paths that expose remote execution over HTTP (SOAP/RFC, web service runtime).
    RFC_OVER_HTTP_MARKERS = ("/sap/bc/soap/rfc", "/sap/bc/srt", "/sap/bc/soap/wsdl",
                             "/sap/bc/webrfc", "/sap/bc/xmlrpc")
    #: TCP ports that front an SAP service and should never be internet-reachable.
    SENSITIVE_PORTS = frozenset({
        "3200", "3201", "3202", "3203", "3204", "3205",     # dispatcher 32NN
        "3300", "3301", "3302", "3303", "3304", "3305",     # gateway 33NN
        "3600", "3601", "3602",                              # message server 36NN
        "4800", "8000", "8001", "8080", "44300", "50000", "50001",  # ICM / Web
        "30013", "30015", "39013", "39015",                 # HANA SQL/index
    })
    #: The log classes a RISE tenant with LogServ would normally forward. Used only
    #: by the ingestion-health checks, to tell "that class was never forwarded" from
    #: "nothing happened in that class".
    EXPECTED_CLASSES = ("sal", "gateway", "hana", "icm", "network")
    _CLASS_LABEL = {"sal": "Security Audit Log", "gateway": "RFC gateway",
                    "hana": "HANA audit", "icm": "ICM / Web Dispatcher",
                    "network": "network / firewall"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._prepare()
        # Gateway
        self.check_external_program_registration()
        self.check_gateway_acl_denials()
        self.check_permissive_gateway_used()
        # HANA database audit log
        self.check_hana_audit_policy_changed()
        self.check_hana_privileged_activity()
        self.check_hana_failed_logons()
        # ICM / Web Dispatcher HTTP log
        self.check_icm_admin_path_access()
        self.check_icm_scanning()
        self.check_icm_remote_execution_endpoints()
        # Network / firewall log
        self.check_network_sensitive_port_access()
        self.check_network_blocked_attempts()
        self.check_network_public_source()
        # Ingestion health — is LogServ forwarding each class at all?
        self.check_logserv_class_coverage()
        self.check_logserv_window_usable()
        return self.findings

    # ================================================================= plumbing
    @staticmethod
    def _rows(value: Any) -> List[Dict[str, Any]]:
        return [r for r in (value or []) if isinstance(r, dict)]

    @staticmethod
    def _get(row: Dict[str, Any], keys: Tuple[str, ...]) -> str:
        for key in keys:
            val = row.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
        return ""

    def _prepare(self) -> None:
        """Bucket the LogServ system events by log class and bound the window."""
        events = logserv_ocsf.to_system_events(self.data.get("logserv_events"))
        self._gateway: List[Dict[str, str]] = [e for e in events if e.get("CLASS") == "gateway"]
        self._hana: List[Dict[str, str]] = [e for e in events if e.get("CLASS") == "hana"]
        self._icm: List[Dict[str, str]] = [e for e in events if e.get("CLASS") == "icm"]
        self._network: List[Dict[str, str]] = [e for e in events if e.get("CLASS") == "network"]
        moments = [dt for dt in (self._parse_dt(e) for e in events) if dt]
        self._window: Optional[Tuple[datetime, datetime]] = (
            (min(moments), max(moments)) if moments else None)

    @classmethod
    def _parse_dt(cls, row: Dict[str, Any]) -> Optional[datetime]:
        raw = cls._get(row, cls.DATE_KEYS)
        if not raw:
            return None
        date_val = None
        for fmt in cls._DATE_FORMATS:
            try:
                date_val = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        if date_val is None:
            return None
        time_part = cls._get(row, cls.TIME_KEYS).split(".")[0].split("+")[0]
        if time_part:
            for fmt in cls._TIME_FORMATS:
                try:
                    parsed = datetime.strptime(time_part, fmt)
                    return date_val.replace(hour=parsed.hour, minute=parsed.minute,
                                            second=parsed.second)
                except ValueError:
                    continue
        return date_val

    def _with_window(self, text: str) -> str:
        """Append the reviewed window, so a retrospective finding states its period."""
        if not self._window:
            return "%s The LogServ export carried no readable timestamps, so the " \
                   "reviewed period could not be bounded." % text.rstrip()
        start, end = self._window
        if start.date() == end.date():
            return "%s Reviewed window: %s." % (text.rstrip(), start.date().isoformat())
        return "%s Reviewed window: %s to %s." % (
            text.rstrip(), start.date().isoformat(), end.date().isoformat())

    @staticmethod
    def _gateway_object(host: str) -> Optional[Dict[str, str]]:
        return {"type": "gateway", "name": host} if host else None

    @staticmethod
    def _program_object(program: str) -> Optional[Dict[str, str]]:
        return {"type": "program", "name": program} if program else None

    def _objects(self, hosts, programs) -> List[Dict[str, str]]:
        """Graph nodes for the gateway hosts and external programs a finding names.

        These are the SAME node keys the gateway CONFIGURATION findings use, which is
        what lets CORR-GW-* join a log finding to the config finding that warned about
        the ACL — see server/identity.py and modules/correlation.py.
        """
        out: List[Dict[str, str]] = []
        for host in sorted({h for h in hosts if h}):
            out.append(self._gateway_object(host))
        for program in sorted({p for p in programs if p}):
            out.append(self._program_object(program))
        return out

    # ===================================================== gateway log patterns
    def check_external_program_registration(self):
        """GWLOG-001: an external program registered or started through the gateway.

        A registered server program is a process outside SAP that the gateway lets
        act as an RFC server. The set that should ever do so is small and known
        (rfcexec for a handful of tools); any registration in the window is worth
        reconciling, and an unknown program name is how gateway abuse first shows up
        in the log. Needs the gateway log; silent without it.
        """
        regs = [e for e in self._gateway
                if (e.get("ACTION") or "") in self.REGISTER_ACTIONS]
        if not regs:
            return
        by_program: Dict[str, set] = {}
        for e in regs:
            program = self._get(e, ("PROGRAM",)) or "(unnamed program)"
            by_program.setdefault(program, set()).add(self._get(e, ("GATEWAY_HOST",)))
        hosts = {h for hs in by_program.values() for h in hs}
        items = []
        for program in sorted(by_program):
            on = ", ".join(sorted(h for h in by_program[program] if h)) or "the gateway"
            items.append("%s registered/started on %s" % (program, on))
        self.finding(
            check_id="GWLOG-001",
            title="External program registered or started through the RFC gateway",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "%d external program(s) registered or started through the RFC gateway "
                "in the reviewed window. A registered server program runs outside SAP "
                "and acts as an RFC server; the set permitted to do so should be small, "
                "known and pinned by the reginfo ACL. Each registration should match an "
                "approved program, and an unrecognised program name is the first place "
                "gateway abuse shows up in the log." % len(by_program)),
            affected_items=items,
            affected_objects=self._objects(hosts, by_program.keys()),
            scope="aggregate",
            details={
                "programs": sorted(by_program),
                "gateway_hosts": sorted(h for h in hosts if h),
                "registrations": len(regs),
            },
            remediation=(
                "Reconcile every registered program against the approved set and the "
                "reginfo ACL. Pin the gateway with an explicit reginfo allowlist (TP, "
                "host) and reject registrations that do not match, so an external "
                "program cannot attach to the gateway without being listed."
            ),
            references=[
                "SAP Security Baseline — RFC gateway (reginfo / secinfo)",
                "SAP Note 1408081 — basic settings for reg_info / sec_info",
            ],
        )

    def check_gateway_acl_denials(self):
        """GWLOG-002: connections the gateway ACL blocked in the window.

        A denial is the ACL doing its job, but a run of them is a signal in its own
        right — something tried repeatedly to register or connect and was refused,
        which is either a misconfiguration to fix or probing to investigate.
        """
        denials = [e for e in self._gateway if (e.get("DECISION") or "") == "denied"]
        if not denials:
            return
        by_source: Dict[str, int] = {}
        hosts = set()
        for e in denials:
            src = self._get(e, ("SRC_HOST",)) or "(unknown source)"
            by_source[src] = by_source.get(src, 0) + 1
            hosts.add(self._get(e, ("GATEWAY_HOST",)))
        self.finding(
            check_id="GWLOG-002",
            title="Gateway connections blocked by the secinfo / reginfo ACL",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=self._with_window(
                "%d gateway connection or registration attempt(s) from %d source(s) "
                "were blocked by the secinfo / reginfo ACL in the reviewed window. A "
                "denial is the ACL working, but a run of them from one source is either "
                "a misconfiguration to reconcile or an attempt to reach the gateway "
                "that should be investigated." % (len(denials), len(by_source))),
            affected_items=[
                "%s: %d blocked attempt(s)" % (src, n)
                for src, n in sorted(by_source.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            affected_objects=self._objects(hosts, []),
            scope="aggregate",
            details={"sources": by_source, "blocked_attempts": len(denials)},
            remediation=(
                "Reconcile each blocked source against expected traffic. Where the "
                "source is legitimate, add it to the reginfo / secinfo ACL explicitly; "
                "where it is not, treat the run of denials as an attempt to reach the "
                "gateway and investigate it."
            ),
            references=[
                "SAP Security Baseline — RFC gateway (reginfo / secinfo)",
                "SAP Note 1408081 — basic settings for reg_info / sec_info",
            ],
        )

    def check_permissive_gateway_used(self):
        """GWLOG-003: the gateway let through a connection its ACL would have denied.

        In simulation / logging-only mode (gw/sim_mode, gw/reg_no_conn_info) the
        gateway evaluates the ACL but does NOT enforce it — a connection a rule would
        reject is allowed and merely logged. A log event that says a connection WOULD
        have been denied but was let through is the permissive gateway being used, and
        is the single strongest gateway signal in the window.
        """
        permissive = [e for e in self._gateway if (e.get("DECISION") or "") == "monitored"]
        if not permissive:
            return
        by_program: Dict[str, set] = {}
        hosts = set()
        for e in permissive:
            program = self._get(e, ("PROGRAM",)) or "(unnamed program)"
            by_program.setdefault(program, set()).add(self._get(e, ("SRC_HOST",)))
            hosts.add(self._get(e, ("GATEWAY_HOST",)))
        self.finding(
            check_id="GWLOG-003",
            title="Gateway allowed a connection its ACL would otherwise have denied",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "%d gateway connection(s) that the secinfo / reginfo ACL would have "
                "rejected were allowed through in the reviewed window because the "
                "gateway is running in simulation / logging-only mode (gw/sim_mode). "
                "The ACL is evaluated but not enforced, so the rule that should have "
                "stopped the connection only recorded it. This is a permissive gateway "
                "being used, not merely configured." % len(permissive)),
            affected_items=[
                "%s: %d connection(s) allowed despite a matching deny rule"
                % (program, len(srcs))
                for program, srcs in sorted(by_program.items(),
                                            key=lambda kv: (-len(kv[1]), kv[0]))
            ],
            affected_objects=self._objects(hosts, by_program.keys()),
            scope="aggregate",
            details={
                "programs": sorted(by_program),
                "gateway_hosts": sorted(h for h in hosts if h),
                "connections": len(permissive),
            },
            remediation=(
                "Move the gateway from simulation / logging-only mode to enforcing "
                "(gw/sim_mode = 0) once the reginfo / secinfo ACL is known to be "
                "complete, so a rule that matches a connection rejects it rather than "
                "logging it. Until then, treat every allowed-despite-deny connection as "
                "one the ACL was meant to stop."
            ),
            references=[
                "SAP Security Baseline — RFC gateway (reginfo / secinfo)",
                "SAP Note 1408081 — basic settings for reg_info / sec_info",
            ],
        )

    # ===================================================== shared object helpers
    @staticmethod
    def _nodes(otype: str, names) -> List[Dict[str, str]]:
        return [{"type": otype, "name": n} for n in sorted({n for n in names if n})]

    @staticmethod
    def _path_matches(path: str, markers: Tuple[str, ...]) -> bool:
        low = (path or "").lower()
        return any(m in low for m in markers)

    @staticmethod
    def _is_public_ip(host: str) -> bool:
        """True only for a dotted-quad that is NOT RFC1918 / loopback / link-local.

        A hostname (not an IP) returns False: we do not resolve, and guessing would
        manufacture findings. Over-reporting an internet source is the worst error
        here, so the uncertain case is treated as not-public."""
        parts = (host or "").split(".")
        if len(parts) != 4 or not all(p.isdigit() and p != "" for p in parts):
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        if a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) \
                or (a == 169 and b == 254) or a >= 224:
            return False
        return True

    SCAN_THRESHOLD = 5

    # ================================================= HANA database audit log
    def check_hana_audit_policy_changed(self):
        """HANALOG-001: the HANA audit configuration itself was changed.

        The audit policy is the record that a privileged database action was taken;
        altering, disabling or dropping a policy is how that record stops being
        written, and it is the first thing an attacker with system privileges does
        before acting. Each change should match an approved administrative task.
        """
        changes = [e for e in self._hana if e.get("ACTION") == "audit_change"]
        if not changes:
            return
        by_user: Dict[str, int] = {}
        policies = set()
        for e in changes:
            u = self._get(e, ("USER",)) or "(unknown)"
            by_user[u] = by_user.get(u, 0) + 1
            if self._get(e, ("AUDIT_POLICY",)):
                policies.add(self._get(e, ("AUDIT_POLICY",)))
        self.finding(
            check_id="HANALOG-001",
            title="HANA audit configuration changed in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category="HANA Log Review",
            description=self._with_window(
                "%d change(s) to the HANA audit configuration by %d account(s) were "
                "recorded in the reviewed window. The audit policy is the record that a "
                "privileged database action happened; changing, disabling or dropping a "
                "policy removes that record going forward, and is the move that precedes "
                "privileged misuse. Each change should match an approved administrative "
                "task." % (len(changes), len(by_user))),
            affected_items=["%s: %d audit change(s)" % (u, n)
                            for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("hana_user", by_user),
            scope="aggregate",
            details={"accounts": sorted(by_user), "policies": sorted(policies),
                     "changes": len(changes)},
            remediation=(
                "Reconcile each HANA audit-policy change with an approved change record. "
                "Confirm the policies that must stay active (logon, system privileges, "
                "structured privileges) are enabled, and restrict ALTER/DROP on audit "
                "policies to a named administrator role."),
            references=["SAP HANA Security Guide — auditing",
                        "SAP Security Baseline — database auditing"],
        )

    def check_hana_privileged_activity(self):
        """HANALOG-002: a HANA super-user acted, or a privilege was granted/revoked."""
        priv = [e for e in self._hana
                if e.get("ACTION") != "audit_change" and e.get("DECISION") != "denied"
                and (self._get(e, ("USER",)).upper() in self.HANA_PRIVILEGED_USERS
                     or e.get("ACTION") in self.HANA_GRANT_ACTIONS)]
        if not priv:
            return
        by_user: Dict[str, int] = {}
        privileges, objects = set(), set()
        for e in priv:
            u = self._get(e, ("USER",)) or "(unknown)"
            by_user[u] = by_user.get(u, 0) + 1
            if self._get(e, ("PRIVILEGE",)):
                privileges.add(self._get(e, ("PRIVILEGE",)))
            if self._get(e, ("OBJECT",)):
                objects.add(self._get(e, ("OBJECT",)))
        nodes = (self._nodes("hana_user", by_user)
                 + self._nodes("hana_privilege", privileges)
                 + self._nodes("schema", objects))
        self.finding(
            check_id="HANALOG-002",
            title="Privileged HANA database activity in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category="HANA Log Review",
            description=self._with_window(
                "%d privileged HANA database action(s) by %d account(s) were recorded "
                "in the reviewed window — activity by a standard HANA super-user "
                "(SYSTEM and the like) or a grant/revoke of a privilege. These change "
                "who can do what in the database, and the super-users should be dormant "
                "in normal operation, so each should match an approved task."
                % (len(priv), len(by_user))),
            affected_items=["%s: %d privileged action(s)" % (u, n)
                            for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=nodes,
            scope="aggregate",
            details={"accounts": sorted(by_user), "privileges": sorted(privileges),
                     "objects": sorted(objects), "actions": len(priv)},
            remediation=(
                "Reconcile each privileged database action with an approved task. "
                "Deactivate the SYSTEM user for day-to-day work and grant named "
                "administrators their own accounts, so super-user activity in the log "
                "is the rare, explained exception."),
            references=["SAP HANA Security Guide — the SYSTEM user and privileges",
                        "SAP Security Baseline — HANA privileged access"],
        )

    def check_hana_failed_logons(self):
        """HANALOG-003: failed HANA database logons in the window."""
        fails = [e for e in self._hana
                 if e.get("ACTION") == "connect" and e.get("DECISION") == "denied"]
        if not fails:
            return
        by_user: Dict[str, int] = {}
        for e in fails:
            u = self._get(e, ("USER",)) or "(unknown)"
            by_user[u] = by_user.get(u, 0) + 1
        self.finding(
            check_id="HANALOG-003",
            title="Failed HANA database logons in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category="HANA Log Review",
            description=self._with_window(
                "%d failed HANA database logon(s) across %d account(s) were recorded in "
                "the reviewed window. A run of failures against a database account is "
                "either an application wired with a stale credential or an attempt to "
                "guess one, and the two should be told apart rather than left in the log."
                % (len(fails), len(by_user))),
            affected_items=["%s: %d failed logon(s)" % (u, n)
                            for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("hana_user", by_user),
            scope="aggregate",
            details={"accounts": sorted(by_user), "failures": len(fails)},
            remediation=(
                "Reconcile each run of failed database logons. Fix the application that "
                "holds a stale credential; investigate failures against SYSTEM or an "
                "admin account as an attempt to guess it."),
            references=["SAP HANA Security Guide — authentication",
                        "SAP Security Baseline — brute-force protection"],
        )

    # ================================================= ICM / Web Dispatcher log
    def check_icm_admin_path_access(self):
        """ICMLOG-001: a successful request to an administrative web path."""
        hits = [e for e in self._icm if e.get("DECISION") == "allowed"
                and self._path_matches(self._get(e, ("PATH",)), self.ADMIN_PATH_MARKERS)]
        if not hits:
            return
        by_path: Dict[str, int] = {}
        sources = set()
        for e in hits:
            p = self._get(e, ("PATH",)) or "(unknown path)"
            by_path[p] = by_path.get(p, 0) + 1
            sources.add(self._get(e, ("SRC_HOST",)))
        self.finding(
            check_id="ICMLOG-001",
            title="Administrative web path accessed in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category="ICM Log Review",
            description=self._with_window(
                "%d successful request(s) to %d administrative web path(s) were recorded "
                "in the reviewed window. The ICF administration consoles and system "
                "services are the paths that, if reachable and reached, hand an attacker "
                "the application; a successful request to one should match an approved "
                "administrator and source." % (len(hits), len(by_path))),
            affected_items=["%s: %d request(s)" % (p, n)
                            for p, n in sorted(by_path.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("icf_path", by_path),
            scope="aggregate",
            details={"paths": sorted(by_path), "sources": sorted(s for s in sources if s),
                     "requests": len(hits)},
            remediation=(
                "Confirm each administrative path should be reachable at all, and "
                "deactivate in SICF the ones that need not be. For those that must stay, "
                "restrict them to an administrator network and reconcile the sources in "
                "the log against it."),
            references=["SAP Security Baseline — ICF service exposure (SICF)",
                        "SAP Note 1422273 — recommended ICF service settings"],
        )

    def check_icm_scanning(self):
        """ICMLOG-002: a source making many failed (4xx/5xx) HTTP requests."""
        by_src: Dict[str, int] = {}
        for e in self._icm:
            if e.get("DECISION") == "denied":
                s = self._get(e, ("SRC_HOST",)) or "(unknown source)"
                by_src[s] = by_src.get(s, 0) + 1
        scanners = {s: n for s, n in by_src.items() if n >= self.SCAN_THRESHOLD}
        if not scanners:
            return
        self.finding(
            check_id="ICMLOG-002",
            title="HTTP scanning pattern in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category="ICM Log Review",
            description=self._with_window(
                "%d source(s) each made at least %d failed HTTP request(s) in the "
                "reviewed window. A burst of refused requests from one source is the "
                "signature of a scan enumerating paths that exist, and it is worth "
                "knowing which source and whether any request later succeeded."
                % (len(scanners), self.SCAN_THRESHOLD)),
            affected_items=["%s: %d failed request(s)" % (s, n)
                            for s, n in sorted(scanners.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("endpoint", scanners),
            scope="aggregate",
            details={"sources": scanners, "threshold": self.SCAN_THRESHOLD},
            remediation=(
                "Investigate each scanning source and confirm whether any request "
                "succeeded. Rate-limit or block the source at the Web Dispatcher / "
                "reverse proxy, and confirm the paths it probed are deactivated in SICF."),
            references=["SAP Security Baseline — ICF service exposure (SICF)"],
        )

    def check_icm_remote_execution_endpoints(self):
        """ICMLOG-003: a successful request to a remote-execution HTTP endpoint."""
        hits = [e for e in self._icm if e.get("DECISION") == "allowed"
                and self._path_matches(self._get(e, ("PATH",)), self.RFC_OVER_HTTP_MARKERS)]
        if not hits:
            return
        by_path: Dict[str, int] = {}
        sources = set()
        for e in hits:
            p = self._get(e, ("PATH",)) or "(unknown path)"
            by_path[p] = by_path.get(p, 0) + 1
            sources.add(self._get(e, ("SRC_HOST",)))
        self.finding(
            check_id="ICMLOG-003",
            title="Remote-execution HTTP endpoint used in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category="ICM Log Review",
            description=self._with_window(
                "%d successful request(s) to %d remote-execution HTTP endpoint(s) "
                "(SOAP/RFC over HTTP, the web service runtime) were recorded in the "
                "reviewed window. These endpoints turn an HTTP request into a function "
                "call inside SAP; a successful request to one from an unexpected source "
                "is how an exposed service becomes remote code execution."
                % (len(hits), len(by_path))),
            affected_items=["%s: %d request(s)" % (p, n)
                            for p, n in sorted(by_path.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("icf_path", by_path),
            scope="aggregate",
            details={"paths": sorted(by_path), "sources": sorted(s for s in sources if s),
                     "requests": len(hits)},
            remediation=(
                "Confirm each remote-execution endpoint must be exposed over HTTP at all; "
                "deactivate those that need not be in SICF. For those that must stay, "
                "require authentication and restrict them to the systems that call them, "
                "and reconcile the sources in the log against that list."),
            references=["SAP Security Baseline — ICF service exposure (SICF)",
                        "SAP Note 1394100 — SOAP RFC service hardening"],
        )

    # ===================================================== network / firewall log
    def check_network_sensitive_port_access(self):
        """NETLOG-001: allowed connections to an SAP service port."""
        hits = [e for e in self._network if e.get("DECISION") == "allowed"
                and self._get(e, ("PORT",)) in self.SENSITIVE_PORTS]
        if not hits:
            return
        by_port: Dict[str, int] = {}
        dests = set()
        for e in hits:
            pt = self._get(e, ("PORT",))
            by_port[pt] = by_port.get(pt, 0) + 1
            dests.add(self._get(e, ("DEST_HOST",)))
        self.finding(
            check_id="NETLOG-001",
            title="Connections to SAP service ports in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category="Network Log Review",
            description=self._with_window(
                "%d allowed connection(s) to SAP service port(s) (%s) were recorded in "
                "the reviewed window. The dispatcher, gateway, message server and HANA "
                "SQL ports are meant to be reachable only from the application tier and "
                "administrators; a connection to one tells you the segment that reaches "
                "it, which is what an attacker would use to pivot."
                % (len(hits), ", ".join(sorted(by_port)))),
            affected_items=["port %s: %d connection(s)" % (p, n)
                            for p, n in sorted(by_port.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("endpoint", dests),
            scope="aggregate",
            details={"ports": sorted(by_port), "destinations": sorted(d for d in dests if d),
                     "connections": len(hits)},
            remediation=(
                "Confirm every segment that can reach an SAP service port should be able "
                "to. Restrict the dispatcher, gateway, message-server and HANA ports to "
                "the application tier and an administrator network with host or network "
                "firewall rules."),
            references=["SAP Security Baseline — network filtering / ports",
                        "SAP Note 821875 — security settings for the message server"],
        )

    def check_network_blocked_attempts(self):
        """NETLOG-002: blocked inbound connection attempts."""
        by_src: Dict[str, int] = {}
        for e in self._network:
            if e.get("DECISION") == "denied":
                s = self._get(e, ("SRC_HOST",)) or "(unknown source)"
                by_src[s] = by_src.get(s, 0) + 1
        if not by_src:
            return
        self.finding(
            check_id="NETLOG-002",
            title="Blocked network connection attempts in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category="Network Log Review",
            description=self._with_window(
                "%d blocked connection attempt(s) from %d source(s) were recorded in the "
                "reviewed window. A block is the firewall working, but a run of them from "
                "one source is either a rule that is filtering legitimate traffic or "
                "something probing the perimeter, and the two should be told apart."
                % (sum(by_src.values()), len(by_src))),
            affected_items=["%s: %d blocked attempt(s)" % (s, n)
                            for s, n in sorted(by_src.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("endpoint", by_src),
            scope="aggregate",
            details={"sources": by_src, "blocked": sum(by_src.values())},
            remediation=(
                "Reconcile each blocked source against expected traffic: allow a "
                "legitimate one explicitly, and treat a persistent unknown source as "
                "perimeter probing to investigate."),
            references=["SAP Security Baseline — network filtering / ports"],
        )

    def check_network_public_source(self):
        """NETLOG-003: an SAP service port reached from a public (internet) address."""
        hits = [e for e in self._network
                if self._get(e, ("PORT",)) in self.SENSITIVE_PORTS
                and self._is_public_ip(self._get(e, ("SRC_HOST",)))]
        if not hits:
            return
        by_src: Dict[str, int] = {}
        ports = set()
        for e in hits:
            s = self._get(e, ("SRC_HOST",))
            by_src[s] = by_src.get(s, 0) + 1
            ports.add(self._get(e, ("PORT",)))
        self.finding(
            check_id="NETLOG-003",
            title="SAP service port reached from a public source address",
            severity=self.SEVERITY_HIGH,
            category="Network Log Review",
            description=self._with_window(
                "%d connection(s) to SAP service port(s) (%s) came from %d public "
                "(non-private) source address(es) in the reviewed window. An SAP "
                "dispatcher, gateway, message-server or HANA port reachable from a public "
                "address is directly exposed to the internet, which is the exposure these "
                "ports must never have." % (len(hits), ", ".join(sorted(ports)), len(by_src))),
            affected_items=["%s: %d connection(s)" % (s, n)
                            for s, n in sorted(by_src.items(), key=lambda kv: (-kv[1], kv[0]))],
            affected_objects=self._nodes("endpoint", by_src),
            scope="aggregate",
            details={"sources": by_src, "ports": sorted(ports), "connections": len(hits)},
            remediation=(
                "Treat a public source on an SAP service port as a directly internet-"
                "exposed service: block it at the perimeter immediately, then confirm "
                "the port is reachable only from the application tier and an "
                "administrator network."),
            references=["SAP Security Baseline — network filtering / ports",
                        "SAP Note 821875 — security settings for the message server"],
        )

    # ===================================================== ingestion health (LSRV-)
    # The same question the Security-Audit-Log health checks ask (LREV-SRC/FLT/WIN),
    # one layer out: before reading a class's events, is LogServ forwarding that
    # class AT ALL? A clean review of a class LogServ never forwarded is not "nothing
    # happened" — it is "we could not have seen it". These checks make that the
    # difference the report states, so a quiet class is never read as a safe one.
    def _present_classes(self) -> set:
        """The log classes actually present in the LogServ export this run."""
        present = {e.get("CLASS") for e in (self._gateway + self._hana
                                            + self._icm + self._network)}
        if logserv_ocsf.to_audit_events(self.data.get("logserv_events")):
            present.add("sal")               # auth / SAL events forwarded via LogServ
        return {c for c in present if c}

    def check_logserv_class_coverage(self):
        """LSRV-COV-001: a log class the export does not carry at all.

        Needs a LogServ export (silent without one — absence of LogServ is a
        posture question for log_monitoring, not an ingestion-health one here).
        """
        if not self.data.get("logserv_events"):
            return
        present = self._present_classes()
        absent = [c for c in self.EXPECTED_CLASSES if c not in present]
        if not absent:
            return
        self.finding(
            check_id="LSRV-COV-001",
            title="A log class is not being forwarded by SAP LogServ",
            severity=self.SEVERITY_MEDIUM,
            category="LogServ Ingestion Health",
            description=self._with_window(
                "The SAP LogServ export carried %d of the %d log classes a RISE "
                "landscape normally forwards. Present: %s. NOT present: %s. Where "
                "LogServ is the source for a class that is not forwarded, the review "
                "of that class is blind for the window — a clean result there means "
                "'never forwarded', not 'nothing happened', and the two must not be "
                "confused." % (
                    len(present), len(self.EXPECTED_CLASSES),
                    ", ".join(sorted(self._CLASS_LABEL.get(c, c) for c in present)) or "none",
                    ", ".join(self._CLASS_LABEL.get(c, c) for c in absent))),
            affected_items=["%s: not forwarded in the reviewed window"
                            % self._CLASS_LABEL.get(c, c) for c in absent],
            scope="aggregate",
            details={"present": sorted(present), "absent": absent,
                     "expected": list(self.EXPECTED_CLASSES)},
            remediation=(
                "Confirm which log classes this estate should forward through SAP "
                "LogServ, and enable forwarding for each absent class that is in "
                "scope. Until then, record every absent class as a period the "
                "corresponding review could not see, so a clean class result is read "
                "as 'not forwarded' rather than 'no activity'."),
            references=[
                "SAP LogServ — log types and forwarding configuration",
                "SAP Security Baseline — logging and monitoring coverage",
            ],
        )

    def check_logserv_window_usable(self):
        """LSRV-WIN-001: LogServ events supplied but none carry a readable time.

        A retrospective review needs a bounded window; events with no timestamp
        cannot be ordered or placed in time, so the review degrades to a volume
        count and must say so rather than imply a time-bounded analysis.
        """
        raw = self.data.get("logserv_events")
        if not raw:
            return
        events = (self._gateway + self._hana + self._icm + self._network)
        if not events or self._window is not None:
            return                      # no system events, or at least one is dated
        self.finding(
            check_id="LSRV-WIN-001",
            title="SAP LogServ events carry no readable timestamps",
            severity=self.SEVERITY_MEDIUM,
            category="LogServ Ingestion Health",
            description=(
                "%d SAP LogServ system event(s) were supplied, but none carried a "
                "timestamp this review could read, so the reviewed window cannot be "
                "bounded and the events cannot be ordered. The class detectors still "
                "run over volume, but any finding that depends on timing is withheld, "
                "and the review cannot state the period it covers." % len(events)),
            affected_items=["%d event(s) with no readable time" % len(events)],
            scope="aggregate",
            details={"undated_events": len(events)},
            remediation=(
                "Confirm the LogServ export carries the event time — OCSF `time` "
                "(epoch milliseconds) or the raw `_time` (epoch seconds). Re-pull the "
                "window once the time field is present so the review can be bounded."),
            references=["SAP LogServ — log record format and the event time field"],
        )
