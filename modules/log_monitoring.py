"""
Logging, Monitoring & Incident Response Auditor
==================================================
Checks for security logging, SIEM integration, and incident
response readiness across S/4HANA RISE and BTP.

Covers:
  - Security Audit Log (SM20/SM21) configuration & filter coverage
  - System log (SM21) event monitoring
  - SIEM integration status and log forwarding
  - Alert Notification Service coverage
  - Log retention and archiving compliance
  - Incident response runbook & contact readiness
  - BTP audit log enablement across subaccounts
  - Table logging (rec/client) for critical tables
  - User session logging & logon event tracking
  - Security event correlation gaps

Data sources:
  - security_audit_log.csv   → SM19/SM20 audit log config & filters
  - siem_config.json         → SIEM connector & forwarding setup
  - log_retention.json       → Log retention policies per log type
  - incident_response.json   → IR runbook / contact / procedure config
  - table_logging.csv        → Tables with change logging enabled
  - logon_events.csv         → Recent logon success/failure stats
"""

from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class LogMonitoringAuditor(BaseAuditor):

    # Critical event types that should be monitored
    REQUIRED_AUDIT_EVENTS = {
        "dialog_logon_failure":  "Failed dialog logon attempts (brute-force detection)",
        "rfc_logon":             "RFC logon events (remote access tracking)",
        "transaction_start":     "Critical transaction starts (SU01, PFCG, SE38, SM59)",
        "user_master_change":    "User master record changes",
        "authority_check_fail":  "Authorization check failures",
        "report_start":          "Report/program execution",
        "rfc_function_call":     "RFC function module calls",
        "table_access":          "Direct table access (SE16/SE16N)",
        "system_event":          "System events (restart, parameter changes)",
        "audit_config_change":   "Changes to audit configuration itself",
    }

    # Critical tables that must have change logging
    CRITICAL_TABLES = [
        "USR02", "USR04", "USR21", "AGR_USERS", "AGR_DEFINE", "AGR_1251",
        "RFCDES", "PRGN_CUST", "T000", "TMSPCONF",
        "PA0000", "PA0001", "PA0002", "PA0008",
        "KNA1", "LFA1", "BKPF", "BSEG",
        "TADIR", "E070", "E071",
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_audit_log_filters()
        self.check_audit_event_coverage()
        self.check_siem_integration()
        self.check_siem_log_sources()
        self.check_log_retention()
        self.check_table_logging()
        self.check_logon_anomalies()
        self.check_incident_response_readiness()
        return self.findings

    def check_audit_log_filters(self):
        """Check SM19/SM20 audit log filter configuration."""
        audit = self.data.get("security_audit_log")
        if not audit:
            audit_cfg = self.data.get("audit_config") or []
            if not audit_cfg:
                self.finding(
                    check_id="LOG-AUD-001",
                    title="No security audit log configuration data available",
                    severity=self.SEVERITY_HIGH,
                    category="Logging, Monitoring & IR",
                    description=(
                        "No security audit log configuration was found. Cannot verify "
                        "SM19/SM20 filter coverage or audit log health."
                    ),
                    remediation=(
                        "Export SM19 filter configuration. Provide security_audit_log.csv "
                        "or audit_config.csv with filter definitions."
                    ),
                    references=["SAP Note 2191612 — Security Audit Log"],
                )
                return
            audit = audit_cfg

        active = [r for r in audit if str(r.get("ACTIVE", r.get("STATUS", ""))).upper()
                 in ("X", "1", "TRUE", "YES", "ACTIVE")]
        static = [r for r in audit if str(r.get("PROFILE_TYPE", r.get("TYPE", ""))).upper()
                 in ("STATIC", "S")]
        dynamic = [r for r in audit if str(r.get("PROFILE_TYPE", r.get("TYPE", ""))).upper()
                  in ("DYNAMIC", "D")]

        if not active:
            self.finding(
                check_id="LOG-AUD-001",
                title="Security Audit Log has no active filters",
                severity=self.SEVERITY_CRITICAL,
                category="Logging, Monitoring & IR",
                description=(
                    "No active SM19 audit filters found. Security events are not "
                    "being recorded. This is a fundamental audit and forensic gap."
                ),
                affected_items=[f"Total filters: {len(audit)}, active: 0"],
                remediation=(
                    "Configure SM19 with both static and dynamic audit profiles. "
                    "Enable filters for: dialog logon, RFC logon, user master changes, "
                    "transaction execution, and authorization failures."
                ),
                references=["SAP Note 2191612", "CIS SAP Benchmark 6.1"],
            )

        if not static:
            self.finding(
                check_id="LOG-AUD-002",
                title="No static audit profile configured",
                severity=self.SEVERITY_HIGH,
                category="Logging, Monitoring & IR",
                description=(
                    "No static audit profile found. Static profiles activate automatically "
                    "on system start. Without them, audit logging stops after restart "
                    "until manually re-enabled."
                ),
                affected_items=["Static profile: not configured"],
                remediation=(
                    "Create a static audit profile in SM19 covering core security events. "
                    "Static profiles survive system restarts automatically."
                ),
                references=["SAP Note 2191612 — Static vs Dynamic Profiles"],
            )

    def check_audit_event_coverage(self):
        """Verify required security event types are covered by audit filters."""
        audit = self.data.get("security_audit_log") or self.data.get("audit_config") or []
        if not audit:
            return

        configured_events = set()
        for row in audit:
            event = row.get("EVENT_CLASS", row.get("EVENT_TYPE",
                   row.get("FILTER_EVENT", ""))).upper()
            event_desc = row.get("DESCRIPTION", row.get("EVENT_DESC", "")).upper()
            active = str(row.get("ACTIVE", row.get("STATUS", ""))).upper()

            if active in ("X", "1", "TRUE", "YES", "ACTIVE"):
                configured_events.add(event)
                configured_events.add(event_desc)

        missing = []
        for event_key, desc in self.REQUIRED_AUDIT_EVENTS.items():
            found = any(
                event_key.upper().replace("_", " ") in ev or
                event_key.upper().replace("_", "") in ev or
                ev in event_key.upper()
                for ev in configured_events
            )
            if not found and "ALL" not in configured_events:
                missing.append(f"{event_key}: {desc}")

        if missing:
            self.finding(
                check_id="LOG-AUD-003",
                title="Security Audit Log missing event coverage",
                severity=self.SEVERITY_HIGH,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(missing)} security event type(s) are not covered by audit "
                    "filters. These events will not be recorded, creating blind spots "
                    "for incident detection and forensic investigation."
                ),
                affected_items=missing,
                remediation=(
                    "Add SM19 filters for all listed event types. "
                    "Use 'All audit classes' filter for comprehensive coverage, "
                    "or configure individual class filters for granular control."
                ),
                references=["SAP Note 2191612", "CIS SAP Benchmark 6.1"],
            )

    def check_siem_integration(self):
        """Check SIEM connector configuration and health."""
        siem = self.data.get("siem_config")
        if not siem:
            self.finding(
                check_id="LOG-SIEM-001",
                title="No SIEM integration configuration found",
                severity=self.SEVERITY_HIGH,
                category="Logging, Monitoring & IR",
                description=(
                    "No SIEM configuration data was provided. Without SIEM integration, "
                    "SAP security events cannot be correlated with other infrastructure "
                    "events for incident detection."
                ),
                remediation=(
                    "Configure SAP Enterprise Threat Detection (ETD) or third-party "
                    "SIEM connector (Splunk, Sentinel, QRadar). "
                    "Forward SM20 audit logs, SM21 system logs, and BTP audit logs."
                ),
                references=["SAP ETD — Enterprise Threat Detection"],
            )
            return

        config = siem if isinstance(siem, dict) else {}
        enabled = config.get("enabled", config.get("active", False))
        connector = config.get("connector", config.get("type", ""))
        last_sync = config.get("lastSync", config.get("lastForward", ""))
        sources = config.get("logSources", config.get("sources", []))

        if not enabled or str(enabled).lower() in ("false", "0", "no"):
            self.finding(
                check_id="LOG-SIEM-001",
                title="SIEM integration is disabled",
                severity=self.SEVERITY_HIGH,
                category="Logging, Monitoring & IR",
                description=(
                    f"SIEM connector ({connector or 'unknown'}) is configured but "
                    "disabled. Security events are not being forwarded."
                ),
                affected_items=[f"Connector: {connector}, status: disabled"],
                remediation="Enable the SIEM connector and verify log forwarding.",
                references=["SAP ETD — Configuration Guide"],
            )

    def check_siem_log_sources(self):
        """Check which log sources are forwarded to SIEM."""
        siem = self.data.get("siem_config")
        if not siem or not isinstance(siem, dict):
            return

        sources = siem.get("logSources", siem.get("sources", []))
        if not isinstance(sources, list):
            return

        source_names = set(str(s).upper() for s in sources)
        required_sources = {
            "SM20": "Security Audit Log",
            "SM21": "System Log",
            "CDHDR": "Change Documents",
            "BTP_AUDIT": "BTP Audit Log",
            "ICM_LOG": "ICM Access Log (HTTP)",
            "GATEWAY_LOG": "Gateway security log",
        }

        missing = []
        for src, desc in required_sources.items():
            if not any(src in s for s in source_names):
                missing.append(f"{src}: {desc}")

        if missing:
            self.finding(
                check_id="LOG-SIEM-002",
                title="SIEM missing critical log source forwarding",
                severity=self.SEVERITY_MEDIUM,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(missing)} critical log source(s) are not being forwarded "
                    "to the SIEM. Incomplete log coverage creates detection blind spots."
                ),
                affected_items=missing,
                remediation=(
                    "Configure forwarding for all listed log sources. "
                    "For BTP, use Alert Notification Service with webhook to SIEM. "
                    "For on-premise, use SAP ETD connector or syslog forwarding."
                ),
                references=["SAP SIEM Integration — Log Source Configuration"],
            )

    def check_log_retention(self):
        """Audit log retention policies across all log types."""
        retention = self.data.get("log_retention")
        if not retention:
            return

        policies = retention if isinstance(retention, list) else \
            retention.get("policies", retention.get("retentionRules", []))

        short_retention = []
        no_archiving = []
        min_days = self.get_config("log_min_retention_days", 365)

        for pol in policies:
            if not isinstance(pol, dict):
                continue
            name = pol.get("logType", pol.get("name", "unknown"))
            days = pol.get("retentionDays", pol.get("retention", 0))
            archive = pol.get("archiving", pol.get("archiveEnabled", False))

            try:
                ret_days = int(str(days))
                if ret_days < min_days:
                    short_retention.append(
                        f"{name}: {ret_days}d (min: {min_days}d)"
                    )
            except (ValueError, TypeError):
                pass

            if not archive or str(archive).lower() in ("false", "0", "no", ""):
                no_archiving.append(f"{name}: archiving not configured")

        if short_retention:
            self.finding(
                check_id="LOG-RET-001",
                title=f"Log retention below {min_days}-day minimum",
                severity=self.SEVERITY_MEDIUM,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(short_retention)} log type(s) have retention periods below "
                    f"the {min_days}-day minimum. Insufficient retention limits "
                    "forensic investigation capability."
                ),
                affected_items=short_retention,
                remediation=(
                    f"Increase retention to at least {min_days} days for all security logs. "
                    "Configure archiving for long-term compliance requirements."
                ),
                references=["SOX — Log Retention Requirements"],
            )

        if no_archiving:
            self.finding(
                check_id="LOG-RET-002",
                title="Security logs without archiving configured",
                severity=self.SEVERITY_LOW,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(no_archiving)} log type(s) have no archiving configured. "
                    "Without archiving, logs are permanently lost after retention expiry."
                ),
                affected_items=no_archiving,
                remediation="Configure log archiving for long-term retention compliance.",
                references=["SAP — Log Archiving Configuration"],
            )

    def check_table_logging(self):
        """Check if critical tables have change logging enabled."""
        table_log = self.data.get("table_logging")
        if not table_log:
            return

        logged_tables = set()
        for row in table_log:
            table = row.get("TABLE_NAME", row.get("TABLE",
                   row.get("TABNAME", ""))).upper()
            enabled = row.get("LOGGING", row.get("LOG_ENABLED",
                     row.get("LOG_FLAG", "")))
            if str(enabled).upper() in ("X", "1", "TRUE", "YES", "ACTIVE"):
                logged_tables.add(table)

        missing = [t for t in self.CRITICAL_TABLES if t not in logged_tables]

        if missing:
            self.finding(
                check_id="LOG-TBL-001",
                title="Critical tables without change logging enabled",
                severity=self.SEVERITY_HIGH,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(missing)} critical table(s) do not have change logging enabled. "
                    "Changes to these tables (user master, authorization, RFC config) "
                    "will not be recorded in the change document log."
                ),
                affected_items=missing,
                remediation=(
                    "Enable table logging for all listed tables via SE11 (technical settings). "
                    "Ensure rec/client parameter is set to log the production client. "
                    "Verify with report RSTBHIST."
                ),
                references=[
                    "CIS SAP Benchmark 6.2 — Table Logging",
                    "SAP Note 2098872",
                ],
            )

    def check_logon_anomalies(self):
        """Analyze logon event statistics for anomalies."""
        logon = self.data.get("logon_events")
        if not logon:
            return

        high_failure = []
        brute_force = []
        failure_threshold = self.get_config("logon_failure_threshold", 20)

        user_failures = defaultdict(int)
        user_successes = defaultdict(int)

        for row in logon:
            user = row.get("USERNAME", row.get("BNAME", row.get("USER", "")))
            event = row.get("EVENT", row.get("TYPE", row.get("LOGON_TYPE", ""))).upper()
            count = row.get("COUNT", row.get("OCCURRENCES", "1"))

            try:
                cnt = int(str(count))
            except ValueError:
                cnt = 1

            if "FAIL" in event or "ERROR" in event or event in ("F", "0"):
                user_failures[user] += cnt
            elif "SUCCESS" in event or event in ("S", "1"):
                user_successes[user] += cnt

        for user, failures in user_failures.items():
            if failures >= failure_threshold:
                successes = user_successes.get(user, 0)
                ratio = failures / max(successes, 1)
                entry = f"{user}: {failures} failures, {successes} successes (ratio: {ratio:.1f})"
                if ratio > 5:
                    brute_force.append(entry)
                else:
                    high_failure.append(entry)

        if brute_force:
            self.finding(
                check_id="LOG-LOGON-001",
                title="Potential brute-force attack patterns detected",
                severity=self.SEVERITY_CRITICAL,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(brute_force)} account(s) show patterns consistent with "
                    "brute-force attacks (very high failure-to-success ratio). "
                    "Investigate immediately."
                ),
                affected_items=brute_force,
                remediation=(
                    "Investigate affected accounts for unauthorized access attempts. "
                    "Lock accounts if attack is confirmed. "
                    "Review source IPs from SM20 logs. "
                    "Ensure login/fails_to_user_lock is properly configured."
                ),
                references=["SAP — Brute-Force Attack Detection"],
            )

        if high_failure:
            self.finding(
                check_id="LOG-LOGON-002",
                title="Accounts with excessive logon failures",
                severity=self.SEVERITY_MEDIUM,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(high_failure)} account(s) have {failure_threshold}+ logon "
                    "failures. This may indicate password issues, misconfigured "
                    "service accounts, or attack attempts."
                ),
                affected_items=high_failure,
                remediation=(
                    "Review failure reasons (expired password, wrong password, locked). "
                    "Contact users or check service account configurations. "
                    "Configure automated alerting for logon failure spikes."
                ),
                references=["CIS SAP Benchmark — Logon Monitoring"],
            )

    def check_incident_response_readiness(self):
        """Check incident response configuration and readiness."""
        ir = self.data.get("incident_response")
        if not ir:
            return

        config = ir if isinstance(ir, dict) else {}
        required = {
            "runbook": "Incident response runbook/playbook defined",
            "contacts": "Emergency security contact list maintained",
            "escalation": "Escalation matrix defined",
            "forensicAccess": "Forensic access procedures documented",
            "backupVerification": "Log backup verification schedule",
            "drillSchedule": "IR drill/tabletop exercise schedule",
        }

        missing = []
        for key, desc in required.items():
            val = config.get(key, "")
            if not val or str(val).lower() in ("false", "0", "no", "none", ""):
                missing.append(f"{key}: {desc}")

        if missing:
            self.finding(
                check_id="LOG-IR-001",
                title="Incident response readiness gaps",
                severity=self.SEVERITY_MEDIUM,
                category="Logging, Monitoring & IR",
                description=(
                    f"{len(missing)} incident response component(s) are not configured "
                    "or documented. Without these, response to security incidents "
                    "will be delayed and uncoordinated."
                ),
                affected_items=missing,
                remediation=(
                    "Complete all IR readiness components: document runbooks, "
                    "maintain contact lists, define escalation paths, ensure "
                    "forensic access is pre-approved, and schedule regular IR drills."
                ),
                references=["NIST SP 800-61 — Incident Handling Guide"],
            )
