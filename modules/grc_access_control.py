"""
GRC Access Control Auditor
==========================
Audits the SAP GRC **Access Control** system's OWN authoritative governance
records — the artifacts external SOX / ITGC auditors test directly, which the
technical modules never see. Where `access_risk_analysis` RE-DERIVES permission-
level SoD offline from AGR_1251, THIS module reads what GRC AC itself recorded:

  - Emergency Access Management (EAM / "Firefighter"): were privileged
    firefighter sessions used with a documented reason and actually reviewed, and
    is each firefighter ID owned + controlled by SEGREGATED people (the owner must
    not review their own usage)?
  - Access Request Management (ARM / MSMP workflow): was access provisioned only
    after approval and risk analysis, or self-requested / self-approved / pushed
    through without a workflow?
  - Risk analysis (ARA): users carrying an OPEN SoD violation with no active
    mitigating control (the residual-risk an auditor flags first).
  - Mitigating-control governance: controls that are expired, owner-less or have
    no assigned monitor — a mitigation that mitigates nothing.
  - SoD ruleset governance: disabled critical risks, risks with no owner, and a
    ruleset so small it was clearly never tailored from the delivered content.

All data is SE16-exportable from the GRC AC ABAP system (GRAC* tables), so the
audit stays fully offline. Each check self-skips when its export is absent.

Data sources (exported to CSV):
  - grac_firefighter_log     → GRACFFLOG (session usage: FF id, user, reason, review status)
  - grac_firefighter_owners  → GRACFFOWNER + GRACFFCTRL + GRACFFOBJECT (FF id owner/controller/log)
  - grac_access_requests     → GRACREQ (+ prov/appr): request, requestor, provisioned user, approver
  - grac_sod_violations      → GRACUSERPRMVL + GRACMITUSER: user, risk id, mitigation + validity
  - grac_mitigating_controls → GRACMITCNT: control id, owner, monitor, frequency, validity
  - grac_sod_risks           → GRACSODRISK + GRACRULESET: risk id, type, status, level, owner
"""

import datetime
from typing import Any, Dict, List, Optional

from modules.base_auditor import BaseAuditor


class GrcAccessControlAuditor(BaseAuditor):

    CATEGORY = "GRC Access Control"

    # Review/approval statuses that count as "properly closed".
    _REVIEWED = {"reviewed", "approved", "closed", "confirmed", "complete", "completed", "ok"}
    # Statuses that POSITIVELY indicate access was provisioned. Deliberately excludes
    # ambiguous terminal states like "closed"/"ok" (a rejected/withdrawn request is also
    # closed) so a non-provisioned request is never treated as a granted-access finding.
    _APPROVED = {"provisioned", "granted", "approved", "completed"}
    # A ruleset materially smaller than the delivered SAP default (~200+ risks)
    # signals it was never tailored / is incomplete.
    _MIN_RULESET_RISKS = 20
    # Risk CRITICALITY/LEVEL values (Critical/High/Medium/Low). NOT the GRACSODRISK
    # RISK TYPE codes (1=SoD, 2=Critical Action, 3=Critical Permission) — type is a
    # classification, not a severity, so it must never be matched here.
    _CRIT_LEVELS = {"critical", "high"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_firefighter_log_review()
        self.check_firefighter_ownership()
        self.check_access_request_governance()
        self.check_open_sod_without_mitigation()
        self.check_mitigating_control_governance()
        self.check_sod_ruleset_governance()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        if not isinstance(row, dict):
            return ""
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "x", "yes", "true", "on", "y", "enabled", "active")

    @staticmethod
    def _falsy(v: Any) -> bool:
        return str(v).strip().lower() in ("0", "no", "false", "off", "n", "disabled", "inactive", "")

    @staticmethod
    def _parse_date(s: Any) -> Optional[datetime.date]:
        """Parse an SAP date. Returns a date, or None if empty/unparseable.
        '99991231' / '9999-12-31' -> a far-future 'unlimited' sentinel date."""
        t = str(s or "").strip()
        if not t:
            return None
        t = t.replace("-", "").replace(".", "").replace("/", "")
        if t.startswith("9999"):
            return datetime.date(9999, 12, 31)
        if len(t) == 8 and t.isdigit():
            try:
                return datetime.date(int(t[:4]), int(t[4:6]), int(t[6:8]))
            except ValueError:
                return None
        return None

    def _today(self) -> datetime.date:
        return datetime.date.today()

    def _active_until(self, valid_to: Any) -> bool:
        """True only if a validity date is present AND not in the past. Fail-CLOSED:
        an empty/unparseable validity does NOT count as currently-active (so a real
        SoD violation is never hidden by an undated mitigation)."""
        d = self._parse_date(valid_to)
        return d is not None and d >= self._today()

    # =====================================================  EMERGENCY ACCESS (EAM)
    def check_firefighter_log_review(self):
        """GRACFFLOG: privileged firefighter sessions used without a documented
        reason code, or whose usage log was never reviewed/approved."""
        rows = self.data.get("grac_firefighter_log")
        if not rows:
            return
        no_reason, unreviewed = [], []
        for r in rows:
            ffid = self._get(r, "FFID", "FIREFIGHTER_ID", "FIREFIGHTER", "FF_ID")
            user = self._get(r, "FF_USER", "USER", "BNAME", "FIREFIGHTER_USER", "OWNER")
            when = self._get(r, "LOGON", "LOGON_TIME", "LOGON_DATE", "TIMESTAMP", "SESSION_DATE")
            reason = self._get(r, "REASON_CODE", "REASONCODE", "REASON", "JUSTIFICATION")
            status = self._get(r, "STATUS", "REVIEW_STATUS", "LOG_STATUS", "WORKFLOW_STATUS").lower()
            if not (ffid or user):
                continue
            label = f"{ffid or '?'} used by {user or '?'}" + (f" @ {when}" if when else "")
            if not reason:
                no_reason.append(label)
            if status and status not in self._REVIEWED:
                unreviewed.append(f"{label} (status={status})")
            elif not status:
                unreviewed.append(f"{label} (status=none)")
        if no_reason:
            self.finding(
                check_id="GRC-FF-001",
                title="Firefighter (emergency-access) sessions used without a documented reason",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(no_reason)} emergency-access (firefighter) session(s) were used with no "
                    "reason code / justification recorded. Firefighter IDs grant broad privileged "
                    "access; SOX ITGC and the SAP GRC EAM control model require that every use is "
                    "justified up-front and the log reviewed after the fact. Unjustified privileged "
                    "sessions are the classic gap auditors cite for emergency access."
                ),
                affected_items=no_reason[:50],
                remediation=(
                    "Maintain EAM Reason Codes and make reason-code entry mandatory in the "
                    "Superuser/EAM logon workflow so sessions cannot start without a justification. "
                    "Review the listed sessions with the firefighter owner and record the business "
                    "justification retroactively."
                ),
                references=["SOX ITGC — privileged/emergency access must be justified & monitored",
                            "SAP GRC Access Control — Emergency Access Management (EAM) config guide",
                            "DSAG Prüfleitfaden — Notfalluser (firefighter) governance"],
                details={"count": len(no_reason)},
            )
        if unreviewed:
            self.finding(
                check_id="GRC-FF-001B",
                title="Firefighter session logs not reviewed / approved",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(unreviewed)} firefighter session(s) have no completed log review "
                    "(review status missing or open). The compensating control for broad emergency "
                    "access is timely, independent review of what the firefighter actually did; an "
                    "unreviewed log means the privileged activity was never checked for abuse."
                ),
                affected_items=unreviewed[:50],
                remediation=(
                    "Ensure the firefighter controller reviews each session log (GRAC EAM log report "
                    "/ workflow) within the defined SLA and records an approval decision. Configure "
                    "log-review workflow notification so sessions cannot sit unreviewed."
                ),
                references=["SOX ITGC — emergency-access log review",
                            "SAP GRC Access Control — EAM log review workflow",
                            "DSAG Prüfleitfaden — Notfalluser-Protokollprüfung"],
                details={"count": len(unreviewed)},
            )

    def check_firefighter_ownership(self):
        """GRACFFOWNER/GRACFFCTRL/GRACFFOBJECT: firefighter IDs with no owner or
        controller, or where the owner also controls (self-monitoring SoD)."""
        rows = self.data.get("grac_firefighter_owners")
        if not rows:
            return
        no_governance, self_monitor, no_logreview = [], [], []
        for r in rows:
            ffid = self._get(r, "FFID", "FIREFIGHTER_ID", "FIREFIGHTER", "FF_ID")
            owner = self._get(r, "OWNER", "FF_OWNER", "OWNER_USER").upper()
            controller = self._get(r, "CONTROLLER", "FF_CONTROLLER", "CONTROLLER_USER").upper()
            logrev = self._get(r, "LOG_REVIEW", "LOG_DELIVERY", "NOTIFY_BY_EMAIL", "LOG_REVIEWED")
            if not ffid:
                continue
            if not owner or not controller:
                no_governance.append(f"{ffid} (owner={owner or 'NONE'}, controller={controller or 'NONE'})")
            elif owner == controller:
                self_monitor.append(f"{ffid} (owner==controller={owner})")
            if logrev and self._falsy(logrev):
                no_logreview.append(f"{ffid} (log review/delivery disabled)")
        if no_governance:
            self.finding(
                check_id="GRC-FF-002",
                title="Firefighter IDs without an assigned owner and controller",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(no_governance)} firefighter ID(s) lack an owner and/or controller. GRC EAM "
                    "requires every firefighter ID to have an owner (accountable for the ID) and a "
                    "controller (independent reviewer of its usage). Without them, privileged emergency "
                    "access is unaccountable and its logs are never independently reviewed."
                ),
                affected_items=no_governance[:50],
                remediation=(
                    "Assign a distinct owner and controller to every firefighter ID (GRAC EAM "
                    "Owners / Controllers). Decommission firefighter IDs that are no longer needed."
                ),
                references=["SAP GRC Access Control — EAM Owners & Controllers",
                            "SOX ITGC — accountability & independent review of privileged access",
                            "DSAG Prüfleitfaden — Notfalluser"],
                details={"count": len(no_governance)},
            )
        if self_monitor:
            self.finding(
                check_id="GRC-FF-002B",
                title="Firefighter owner also acts as controller (self-monitoring)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(self_monitor)} firefighter ID(s) have the SAME person as owner and "
                    "controller. This breaks segregation of duties over emergency access: the person "
                    "accountable for the privileged ID also signs off on its usage, so abuse can be "
                    "self-approved. Owner and controller must be different individuals."
                ),
                affected_items=self_monitor[:50],
                remediation=(
                    "Reassign the controller of each listed firefighter ID to an independent person "
                    "(not the owner), per the EAM segregation model."
                ),
                references=["SOX ITGC — SoD over privileged/emergency access",
                            "SAP GRC Access Control — EAM security guide"],
                details={"count": len(self_monitor)},
            )
        if no_logreview:
            self.finding(
                check_id="GRC-FF-002C",
                title="Firefighter log review / delivery disabled",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(no_logreview)} firefighter ID(s) have log review/delivery turned off, so the "
                    "controller does not receive the usage log for review — the after-the-fact "
                    "compensating control is effectively disabled."
                ),
                affected_items=no_logreview[:50],
                remediation="Enable log delivery / review workflow for every firefighter ID (GRAC EAM).",
                references=["SAP GRC Access Control — EAM log review", "SOX ITGC — emergency-access monitoring"],
                details={"count": len(no_logreview)},
            )

    # =====================================================  ACCESS REQUEST (ARM)
    def check_access_request_governance(self):
        """GRACREQ + provisioning: access provisioned self-service, self-approved,
        without an approver, or without a risk analysis."""
        rows = self.data.get("grac_access_requests")
        if not rows:
            return
        no_approval, self_approved, no_risk = [], [], []
        risk_col_present = False  # only judge "no risk analysis" if the export carries the indicator
        for r in rows:
            req = self._get(r, "REQ_ID", "REQUEST", "REQNO", "REQUEST_ID")
            requestor = self._get(r, "REQUESTOR", "REQUESTED_BY", "CREATED_BY", "REQUESTER").upper()
            prov_user = self._get(r, "PROVISIONED_USER", "PROV_USER", "USERID", "TARGET_USER", "USER").upper()
            approver = self._get(r, "APPROVER", "APPROVED_BY", "APPROVAL_BY").upper()
            provisioned = self._get(r, "PROVISIONED", "PROV_STATUS", "STATUS", "REQ_STATUS")
            risk = self._get(r, "RISK_ANALYSIS", "RISK_ANALYSIS_DONE", "RA_DONE", "RISK_CHECK")
            is_prov = self._truthy(provisioned) or provisioned.strip().lower() in self._APPROVED
            if not (req or prov_user):
                continue
            if risk:
                risk_col_present = True
            label = f"req {req or '?'}: {requestor or '?'} -> {prov_user or '?'}"
            if is_prov and not approver:
                no_approval.append(label + " (no approver)")
            elif is_prov and approver and (approver == requestor or approver == prov_user):
                self_approved.append(label + f" (self-approved by {approver})")
            # Flag both an explicit "not done" AND a blank indicator on a provisioned
            # request; emission is gated on the column actually being present so a
            # GRACREQ export without a risk-analysis column doesn't flag every request.
            if is_prov and self._falsy(risk):
                no_risk.append(label + (" (risk analysis not done)" if risk else " (no risk-analysis record)"))
        if no_approval:
            self.finding(
                check_id="GRC-ARM-001",
                title="Access provisioned without an approver (workflow bypass)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(no_approval)} access request(s) resulted in provisioned access with NO "
                    "recorded approver. SOX ITGC and GRC ARM (MSMP workflow) require documented "
                    "approval before access is granted; provisioning without an approval step is an "
                    "authorization-control failure and a common audit finding."
                ),
                affected_items=no_approval[:50],
                remediation=(
                    "Route all access provisioning through the GRAC ARM MSMP approval workflow; "
                    "disable direct/auto provisioning paths. Re-review the listed grants and obtain "
                    "retroactive approval or revoke."
                ),
                references=["SOX ITGC — access authorization/approval",
                            "SAP GRC Access Control — Access Request Management (MSMP workflow)",
                            "COBIT DSS05 — manage user access"],
                details={"count": len(no_approval)},
            )
        if self_approved:
            self.finding(
                check_id="GRC-ARM-001B",
                title="Access request self-approved / self-provisioned",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(self_approved)} access request(s) were approved by the requestor or by the "
                    "target user themselves. Self-approval defeats the four-eyes principle over access "
                    "granting — a user can grant themselves privileged access unchecked."
                ),
                affected_items=self_approved[:50],
                remediation=(
                    "Configure MSMP so the requestor/beneficiary can never be the approver; enforce "
                    "manager or role-owner approval. Investigate the listed self-approvals."
                ),
                references=["SOX ITGC — four-eyes over access granting",
                            "SAP GRC Access Control — MSMP approver determination"],
                details={"count": len(self_approved)},
            )
        if no_risk and risk_col_present:
            self.finding(
                check_id="GRC-ARM-002",
                title="Access provisioned without a risk (SoD) analysis",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(no_risk)} access request(s) were provisioned without a documented risk "
                    "analysis. GRC ARM should run ARA risk analysis at request time so SoD conflicts "
                    "are detected (and mitigated) BEFORE access is granted, not discovered later."
                ),
                affected_items=no_risk[:50],
                remediation="Enable mandatory risk analysis in the ARM workflow (ARA-ARM integration).",
                references=["SAP GRC Access Control — ARA/ARM integration (risk analysis at provisioning)",
                            "SOX ITGC — preventive SoD"],
                details={"count": len(no_risk)},
            )

    # =====================================================  RISK ANALYSIS (ARA)
    def check_open_sod_without_mitigation(self):
        """GRACUSERPRMVL + GRACMITUSER: users with an open SoD violation that has no
        currently-active mitigating control."""
        rows = self.data.get("grac_sod_violations")
        if not rows:
            return
        offenders = []
        for r in rows:
            user = self._get(r, "USERID", "USER", "BNAME", "USER_ID").upper()
            risk = self._get(r, "RISK_ID", "RISKID", "RISK", "SOD_RISK")
            mit = self._get(r, "MITIGATION_ID", "MIT_ID", "CONTROL_ID", "MITIGATED", "MITIGATION")
            valid_to = self._get(r, "VALID_TO", "MIT_VALID_TO", "VALIDTO", "TO_DATE", "EXPIRY")
            if not (user and risk):
                continue
            mitigated = bool(mit) and not self._falsy(mit)
            # Active mitigation = a mitigation is assigned AND (no validity given, i.e.
            # open-ended, OR the validity date has not passed). An EXPIRED validity means
            # not active (the violation stands); an undated control is caught separately
            # by GRC-MIT-001, so here we don't double-penalise it.
            if not mitigated:
                active = False
            elif valid_to:
                active = self._active_until(valid_to)
            else:
                active = True
            if not active:
                why = "no mitigation" if not mitigated else "mitigation expired/undated"
                offenders.append(f"{user} / {risk} ({why})")
        if offenders:
            self.finding(
                check_id="GRC-ARA-001",
                title="Users carry open SoD violations with no active mitigating control",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} user–risk combination(s) have an OPEN segregation-of-duties "
                    "violation (per GRC risk analysis) with no active mitigating control — either "
                    "unmitigated, or the mitigation assignment has expired. Unmitigated SoD is the "
                    "residual access risk external auditors examine first; each is a potential "
                    "fraud/error exposure (e.g. create vendor + pay vendor)."
                ),
                affected_items=offenders[:50],
                remediation=(
                    "For each: remove one side of the conflicting access (preferred), or assign a "
                    "valid, owner-monitored mitigating control with a current validity date in GRAC. "
                    "Re-run risk analysis to confirm the violation clears."
                ),
                references=["SOX ITGC — segregation of duties / residual risk",
                            "SAP GRC Access Control — ARA risk analysis & mitigation",
                            "DSAG Prüfleitfaden — SoD-Konflikte"],
                details={"count": len(offenders)},
            )

    def check_mitigating_control_governance(self):
        """GRACMITCNT: mitigating controls that are expired, owner-less or unmonitored."""
        rows = self.data.get("grac_mitigating_controls")
        if not rows:
            return
        offenders = []
        for r in rows:
            cid = self._get(r, "CONTROL_ID", "MITIGATION_ID", "MIT_ID", "MITIGATING_CONTROL", "CONTROL")
            owner = self._get(r, "OWNER", "CONTROL_OWNER", "OWNER_USER")
            monitor = self._get(r, "MONITOR", "MONITOR_USER", "MONITORED_BY", "MONITOR_ID")
            freq = self._get(r, "FREQUENCY", "MONITOR_FREQUENCY", "FREQ")
            valid_to = self._get(r, "VALID_TO", "VALIDTO", "TO_DATE", "EXPIRY")
            status = self._get(r, "STATUS", "STATE")
            if not cid:
                continue
            issues = []
            if not owner:
                issues.append("no owner")
            if not monitor:
                issues.append("no monitor")
            if not freq:
                issues.append("no monitoring frequency")
            if valid_to and not self._active_until(valid_to):
                issues.append(f"expired ({valid_to})")
            if status and self._falsy(status):
                issues.append("inactive")
            if issues:
                offenders.append(f"{cid}: " + ", ".join(issues))
        if offenders:
            self.finding(
                check_id="GRC-MIT-001",
                title="Mitigating controls are expired, owner-less or unmonitored",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} mitigating control(s) are not fit for purpose — missing an "
                    "owner, missing an assigned monitor, missing a monitoring frequency, expired, or "
                    "inactive. A mitigating control that no one owns or monitors provides no real "
                    "compensating assurance for the SoD risks it is claimed to cover, yet it still "
                    "suppresses those violations from the risk report — masking live exposure."
                ),
                affected_items=offenders[:50],
                remediation=(
                    "For each control (GRAC Mitigating Controls): assign an owner and an independent "
                    "monitor, set a monitoring frequency, renew or retire expired controls, and "
                    "confirm the control activity is actually performed and evidenced."
                ),
                references=["SOX ITGC — compensating/mitigating control operating effectiveness",
                            "SAP GRC Access Control — Mitigating Controls configuration",
                            "COBIT — control monitoring"],
                details={"count": len(offenders)},
            )

    # =====================================================  RULESET GOVERNANCE
    def check_sod_ruleset_governance(self):
        """GRACSODRISK + GRACRULESET: disabled critical risks, risks with no owner,
        and a ruleset too small to be a tailored, complete rule base."""
        rows = self.data.get("grac_sod_risks")
        if not rows:
            return
        total = 0
        disabled_crit, no_owner = [], []
        for r in rows:
            rid = self._get(r, "RISK_ID", "RISKID", "RISK", "SOD_RISK")
            if not rid:
                continue
            total += 1
            status = self._get(r, "STATUS", "STATE", "ENABLED").lower()
            # Criticality/level ONLY — never RISK_TYPE (that is a 1/2/3 classification).
            level = self._get(r, "RISK_LEVEL", "CRITICALITY", "LEVEL").lower()
            owner = self._get(r, "OWNER", "RISK_OWNER", "OWNER_USER")
            is_disabled = status in ("disabled", "inactive", "0", "n", "off", "false")
            if is_disabled and (level in self._CRIT_LEVELS):
                disabled_crit.append(f"{rid} (level={level or '?'}, status={status or 'disabled'})")
            if not owner:
                no_owner.append(rid)
        if disabled_crit:
            self.finding(
                check_id="GRC-RS-001",
                title="Critical SoD risks are disabled in the rule set",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(disabled_crit)} critical/high SoD risk(s) are disabled in the GRC rule set. "
                    "A disabled risk is never evaluated, so users can hold that conflicting-access "
                    "combination with no violation ever raised — silently blinding the SoD control. "
                    "Disabling a critical risk should be a rare, governed exception."
                ),
                affected_items=disabled_crit[:50],
                remediation=(
                    "Re-enable the listed critical risks (GRAC Access Rule Maintenance) unless there is "
                    "a documented, risk-owner-approved reason; record any exception with justification."
                ),
                references=["SAP GRC Access Control — Access Rule Set maintenance",
                            "SOX ITGC — completeness/effectiveness of SoD monitoring",
                            "DSAG Prüfleitfaden — SoD-Regelwerk"],
                details={"count": len(disabled_crit)},
            )
        if no_owner:
            self.finding(
                check_id="GRC-RS-002",
                title="SoD risks without an assigned risk owner",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(no_owner)} SoD risk(s) have no risk owner. Without an owner accountable for "
                    "deciding remediation vs mitigation, violations of that risk are never dispositioned."
                ),
                affected_items=no_owner[:50],
                remediation="Assign a business risk owner to every SoD risk in the rule set (GRAC).",
                references=["SAP GRC Access Control — risk ownership", "SOX ITGC — risk accountability"],
                details={"count": len(no_owner)},
            )
        if total and total < self._MIN_RULESET_RISKS:
            self.finding(
                check_id="GRC-RS-003",
                title="SoD rule set appears incomplete / never tailored",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"Only {total} SoD risk(s) are defined in the rule set. The SAP-delivered Access "
                    "Control rule set contains 200+ risks across process areas; a rule set this small "
                    "has likely not been activated/tailored from the delivered content, so most SoD "
                    "conflicts across P2P/O2C/R2R/H2R/Basis are simply not being detected."
                ),
                affected_items=[f"{total} risks defined (expected 200+ from delivered content)"],
                remediation=(
                    "Import and tailor the SAP-delivered rule set (or a maintained ruleset), covering "
                    "all in-scope process areas; validate with the business risk owners."
                ),
                references=["SAP GRC Access Control — default rule set import",
                            "DSAG Prüfleitfaden — Vollständigkeit des Regelwerks"],
                details={"count": total},
            )
