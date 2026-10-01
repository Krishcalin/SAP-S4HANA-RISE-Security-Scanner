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

    CATEGORY = "Gateway Log Review"

    DATE_KEYS = ("DATE",)
    TIME_KEYS = ("TIME",)
    _DATE_FORMATS = ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y")
    _TIME_FORMATS = ("%H:%M:%S", "%H%M%S", "%H:%M")

    #: Registration / start actions — an external program attaching to the gateway.
    REGISTER_ACTIONS = frozenset({"register", "start"})

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._prepare()
        self.check_external_program_registration()
        self.check_gateway_acl_denials()
        self.check_permissive_gateway_used()
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
        """Normalise the gateway class of the LogServ export into events."""
        events = logserv_ocsf.to_system_events(self.data.get("logserv_events"))
        self._gateway: List[Dict[str, str]] = [
            e for e in events if e.get("CLASS") == "gateway"]
        moments = [dt for dt in (self._parse_dt(e) for e in self._gateway) if dt]
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
            return "%s The gateway export carried no readable timestamps, so the " \
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
