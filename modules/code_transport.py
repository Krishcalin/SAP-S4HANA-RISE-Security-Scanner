"""
Code & Transport Security Auditor
====================================
Deep analysis of custom ABAP code security and transport/change
management controls in SAP S/4HANA RISE environments.

Covers:
  - SQL injection patterns in custom code (dynamic WHERE, EXEC SQL)
  - Missing authority checks in custom function modules / OData
  - Hardcoded credentials in ABAP source
  - Obsolete/insecure ABAP statements (CALL 'SYSTEM', GENERATE)
  - Transport workflow enforcement (approvals, cross-client)
  - Transport route integrity (dev→qa→prod path)
  - Direct production changes (SE38/SE80 in prod)
  - Cross-client customizing change restrictions
  - Change document audit trail completeness
  - Code inspector / ATC findings analysis
  - Custom code dependency on SAP modifications (Z* calling modified SAP)
  - Unreferenced / dead custom code

Data sources:
  - custom_code_scan.csv     → Code inspector / ATC scan results
  - transport_routes.csv     → TMS transport route configuration
  - transport_history.csv    → Transport import history (STMS log)
  - client_settings.csv      → SCC4 client configuration
  - change_documents.csv     → Change document headers (CDHDR)
  - code_inventory.csv       → Custom code inventory (Z*/Y* objects)
  - sap_modifications.csv    → SAP standard modifications (SMOD/SE95)
  - dev_access_prod.csv      → Users with SE38/SE80/S_DEVELOP in production
"""

from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class CodeTransportAuditor(BaseAuditor):

    # ── SQL injection patterns in ABAP ──
    SQL_INJECTION_PATTERNS = [
        "CONCATENATE.*INTO.*WHERE",
        "&&.*WHERE",
        "EXEC SQL",
        "ADBC_",           # ADBC (native SQL) classes
        "CL_SQL_STATEMENT",
        "NATIVE SQL",
        "|.*WHERE.*|",     # String templates in WHERE
    ]

    # ── Dangerous / obsolete ABAP statements ──
    DANGEROUS_STATEMENTS = {
        "CALL 'SYSTEM'":       "OS command execution via kernel call",
        "CALL 'C_SAPGPARAM'":  "Read system parameters — info disclosure",
        "GENERATE SUBROUTINE POOL": "Dynamic code generation — code injection risk",
        "GENERATE REPORT":     "Dynamic report generation — code injection risk",
        "INSERT REPORT":       "Modify ABAP source at runtime",
        "READ REPORT":         "Read ABAP source code at runtime",
        "EDITOR-CALL":         "Open ABAP editor — dev access in prod",
        "CALL TRANSACTION":    "Transaction call — verify auth check before",
        "SUBMIT.*VIA JOB":     "Background job submission — verify authorization",
        "DELETE REPORT":       "Delete ABAP source at runtime",
        "EXPORT.*MEMORY":      "Memory export — potential data leakage between sessions",
    }

    # ── Hardcoded credential patterns ──
    CREDENTIAL_PATTERNS = [
        "PASSWORD",
        "PASSWD",
        "PWD =",
        "SECRET =",
        "API_KEY",
        "APIKEY",
        "TOKEN =",
        "AUTH_TOKEN",
        "PRIVATE_KEY",
        "CLIENT_SECRET",
        "BEARER",
    ]

    # ── Tcodes that indicate development access ──
    DEV_TCODES = [
        "SE38", "SE80", "SE37", "SE24", "SE11", "SE16", "SE16N",
        "SM30", "SM31", "CMOD", "SMOD", "BADI_BUILDER",
        "SE09", "SE10",  # Transport organizer
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_sql_injection_patterns()
        self.check_missing_authority_checks()
        self.check_hardcoded_credentials()
        self.check_dangerous_statements()
        self.check_atc_critical_findings()
        self.check_transport_route_integrity()
        self.check_transport_workflow()
        self.check_direct_prod_imports()
        self.check_client_settings()
        self.check_change_document_gaps()
        self.check_dev_access_in_prod()
        self.check_sap_modifications()
        self.check_dead_custom_code()
        return self.findings

    # ════════════════════════════════════════════════════════════════
    #  CODE-INJ-*: Code Injection / SQL Injection Patterns
    # ════════════════════════════════════════════════════════════════

    def check_sql_injection_patterns(self):
        """
        Detect SQL injection patterns in custom ABAP code:
        - Dynamic WHERE clause construction via concatenation
        - EXEC SQL / native SQL usage
        - ADBC classes without parameterization
        """
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        sql_findings = []
        for row in scan:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM",
                      row.get("REPORT", "")))
            obj_type = row.get("OBJECT_TYPE", row.get("TYPE", ""))
            finding_type = row.get("FINDING_TYPE", row.get("CHECK",
                          row.get("MESSAGE_ID", "")))
            line = row.get("LINE", row.get("LINE_NUMBER", ""))
            description = row.get("DESCRIPTION", row.get("MESSAGE",
                         row.get("TEXT", "")))
            severity = row.get("SEVERITY", row.get("PRIORITY", ""))

            combined = f"{finding_type} {description}".upper()
            is_sql = any(
                p.upper().replace(".*", "") in combined
                for p in self.SQL_INJECTION_PATTERNS
            ) or any(
                kw in combined
                for kw in ["SQL INJECTION", "DYNAMIC WHERE", "DYNAMIC SQL",
                          "NATIVE SQL", "EXEC SQL", "OPEN SQL", "CONCATENAT"]
            )

            if is_sql:
                sql_findings.append(
                    f"{obj_name} ({obj_type}) line {line}: {description[:100]}"
                )

        if sql_findings:
            self.finding(
                check_id="CODE-INJ-001",
                title="SQL injection patterns detected in custom code",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(sql_findings)} custom code finding(s) indicate potential SQL "
                    "injection vulnerabilities. Dynamic WHERE clause construction via "
                    "string concatenation allows attackers to manipulate queries."
                ),
                affected_items=sql_findings[:50],
                remediation=(
                    "Replace dynamic WHERE concatenation with parameterized queries: "
                    "use ? placeholders with CL_SQL_STATEMENT=>BIND, or use "
                    "range tables / SELECT-OPTIONS for dynamic filtering. "
                    "Replace EXEC SQL with Open SQL where possible. "
                    "Run ABAP Test Cockpit (ATC) with security checks enabled."
                ),
                references=[
                    "SAP Note 1520356 — Secure ABAP Programming",
                    "OWASP — SQL Injection Prevention",
                    "SAP ATC Check — CALL_INJECTION_DYNAMIC_SQL",
                ],
                details={"total_count": len(sql_findings)},
            )

    def check_missing_authority_checks(self):
        """
        Detect custom function modules and OData implementations
        missing authority checks.
        """
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        missing_auth = []
        for row in scan:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM", ""))
            obj_type = row.get("OBJECT_TYPE", row.get("TYPE", ""))
            finding_type = row.get("FINDING_TYPE", row.get("CHECK", ""))
            description = row.get("DESCRIPTION", row.get("MESSAGE", ""))
            line = row.get("LINE", row.get("LINE_NUMBER", ""))

            combined = f"{finding_type} {description}".upper()
            is_auth_missing = any(
                kw in combined
                for kw in ["AUTHORITY-CHECK", "MISSING AUTH", "NO AUTHORIZATION",
                          "AUTH_CHECK_MISSING", "MISSING_AUTHORIZATION",
                          "NO AUTHORITY CHECK", "AUTHORIZATION MISSING"]
            )

            if is_auth_missing:
                missing_auth.append(
                    f"{obj_name} ({obj_type}) line {line}: {description[:100]}"
                )

        if missing_auth:
            self.finding(
                check_id="CODE-INJ-002",
                title="Custom code missing authority checks",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(missing_auth)} custom code object(s) lack proper "
                    "AUTHORITY-CHECK statements. Without authority checks, any "
                    "authenticated user can execute the function regardless of "
                    "their role assignments."
                ),
                affected_items=missing_auth[:50],
                remediation=(
                    "Add AUTHORITY-CHECK OBJECT statements for all relevant "
                    "authorization objects (e.g., S_TCODE, business-specific objects). "
                    "For OData implementations, check authorizations in the "
                    "GET_ENTITYSET / GET_ENTITY methods. "
                    "Use ATC check 'Missing Authorization Check' profile."
                ),
                references=[
                    "SAP Note 1520356 — Secure ABAP Programming",
                    "CIS SAP Benchmark — Custom Code Authorization Checks",
                ],
                details={"total_count": len(missing_auth)},
            )

    def check_hardcoded_credentials(self):
        """Detect hardcoded credentials in ABAP source code."""
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        hardcoded = []
        for row in scan:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM", ""))
            obj_type = row.get("OBJECT_TYPE", row.get("TYPE", ""))
            finding_type = row.get("FINDING_TYPE", row.get("CHECK", ""))
            description = row.get("DESCRIPTION", row.get("MESSAGE", ""))
            line = row.get("LINE", row.get("LINE_NUMBER", ""))

            combined = f"{finding_type} {description}".upper()
            is_cred = any(
                p in combined
                for p in self.CREDENTIAL_PATTERNS
            ) or any(
                kw in combined
                for kw in ["HARDCODED", "HARD-CODED", "EMBEDDED CREDENTIAL",
                          "LITERAL PASSWORD", "PLAIN TEXT SECRET"]
            )

            if is_cred:
                hardcoded.append(
                    f"{obj_name} ({obj_type}) line {line}: {description[:100]}"
                )

        if hardcoded:
            self.finding(
                check_id="CODE-INJ-003",
                title="Hardcoded credentials detected in custom code",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(hardcoded)} custom code finding(s) suggest hardcoded credentials "
                    "(passwords, API keys, tokens) in ABAP source. Hardcoded secrets "
                    "are visible in source code, transport logs, and version history."
                ),
                affected_items=hardcoded[:30],
                remediation=(
                    "Remove all hardcoded credentials from source code. "
                    "Use SAP Secure Store (SSF/STRUST) for certificates, "
                    "SM59 destinations for RFC credentials, or "
                    "CL_SEC_SXML_XSTRING for encrypted data storage. "
                    "For BTP, use the Credential Store service."
                ),
                references=[
                    "SAP Note 1520356",
                    "OWASP — Credential Management Cheat Sheet",
                ],
                details={"total_count": len(hardcoded)},
            )

    def check_dangerous_statements(self):
        """Detect dangerous/obsolete ABAP statements."""
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        dangerous = defaultdict(list)
        for row in scan:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM", ""))
            obj_type = row.get("OBJECT_TYPE", row.get("TYPE", ""))
            finding_type = row.get("FINDING_TYPE", row.get("CHECK", ""))
            description = row.get("DESCRIPTION", row.get("MESSAGE", ""))
            line = row.get("LINE", row.get("LINE_NUMBER", ""))

            combined = f"{finding_type} {description}".upper()
            for stmt, risk in self.DANGEROUS_STATEMENTS.items():
                stmt_upper = stmt.upper().replace(".*", "")
                if stmt_upper in combined:
                    dangerous[stmt].append(
                        f"{obj_name} ({obj_type}) line {line}"
                    )
                    break

        for stmt, items in dangerous.items():
            risk = self.DANGEROUS_STATEMENTS[stmt]
            self.finding(
                check_id=f"CODE-STMT-001",
                title=f"Dangerous ABAP statement: {stmt}",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(items)} custom code object(s) use '{stmt}'. "
                    f"Risk: {risk}. This statement should not be used in "
                    "production custom code."
                ),
                affected_items=items[:20],
                remediation=(
                    f"Replace '{stmt}' with safe alternatives. "
                    "For OS commands, use BAdI BADI_RUNTIME_EXEC with allowlisting. "
                    "For dynamic code, use predefined functions or BAdI frameworks. "
                    "Disable debugging statements via rdisp/wpdbug_max_no = 0."
                ),
                references=["SAP Note 1520356 — Secure ABAP Coding Guidelines"],
                details={"total_count": len(items)},
            )

    def check_atc_critical_findings(self):
        """Analyze ATC scan results for unresolved critical findings."""
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        critical_unresolved = []
        high_unresolved = []
        total_findings = 0

        for row in scan:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM", ""))
            severity = row.get("SEVERITY", row.get("PRIORITY", "")).upper()
            status = row.get("STATUS", row.get("RESOLUTION", "")).upper()
            finding_type = row.get("FINDING_TYPE", row.get("CHECK", ""))
            description = row.get("DESCRIPTION", row.get("MESSAGE", ""))

            total_findings += 1

            if status not in ("RESOLVED", "FIXED", "FALSE_POSITIVE",
                            "EXEMPTED", "CLOSED"):
                label = f"{obj_name}: {finding_type} — {description[:80]}"
                if severity in ("1", "CRITICAL", "ERROR", "E"):
                    critical_unresolved.append(label)
                elif severity in ("2", "HIGH", "WARNING", "W"):
                    high_unresolved.append(label)

        if critical_unresolved:
            self.finding(
                check_id="CODE-ATC-001",
                title=f"Unresolved critical ATC findings ({len(critical_unresolved)})",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(critical_unresolved)} critical ATC/code inspector finding(s) "
                    f"remain unresolved out of {total_findings} total. Critical findings "
                    "indicate exploitable security vulnerabilities in custom code."
                ),
                affected_items=critical_unresolved[:30],
                remediation=(
                    "Prioritize remediation of all critical ATC findings. "
                    "Integrate ATC into the transport workflow to block transports "
                    "with critical findings. Use ATC exemption process for false positives."
                ),
                references=[
                    "SAP ATC — Security Check Configuration",
                    "SAP Note 2364916 — ATC in Transport Workflow",
                ],
                details={"total_findings": total_findings,
                         "critical_count": len(critical_unresolved)},
            )

        if high_unresolved:
            self.finding(
                check_id="CODE-ATC-002",
                title=f"Unresolved high-severity ATC findings ({len(high_unresolved)})",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(high_unresolved)} high-severity ATC finding(s) remain unresolved. "
                    "These represent significant code quality and security risks."
                ),
                affected_items=high_unresolved[:30],
                remediation=(
                    "Schedule remediation sprints for high-severity findings. "
                    "Target: resolve within 90 days of detection."
                ),
                references=["SAP ATC — Finding Management"],
                details={"total_count": len(high_unresolved)},
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-TMS-*: Transport Management & Workflow
    # ════════════════════════════════════════════════════════════════

    def check_transport_route_integrity(self):
        """
        Verify transport routes follow proper dev→qa→prod sequence.
        """
        routes = self.data.get("transport_routes")
        if not routes:
            return

        # Build route graph
        direct_to_prod = []
        bypass_qa = []
        prod_indicators = ["PRD", "PROD", "P", "PRODUCTION"]
        qa_indicators = ["QAS", "QA", "Q", "QUALITY", "TST", "TEST"]
        dev_indicators = ["DEV", "D", "DEVELOPMENT", "SBX", "SANDBOX"]

        for row in routes:
            source = row.get("SOURCE", row.get("FROM_SYSTEM",
                    row.get("SOURCE_SID", ""))).upper()
            target = row.get("TARGET", row.get("TO_SYSTEM",
                    row.get("TARGET_SID", ""))).upper()
            route_type = row.get("TYPE", row.get("ROUTE_TYPE", ""))

            is_source_dev = any(d in source for d in dev_indicators)
            is_target_prod = any(p in target for p in prod_indicators)
            is_target_qa = any(q in target for q in qa_indicators)

            # Dev directly to prod (bypassing QA)
            if is_source_dev and is_target_prod:
                direct_to_prod.append(f"{source} → {target} (direct, no QA)")

        if direct_to_prod:
            self.finding(
                check_id="CODE-TMS-001",
                title="Transport routes allow direct dev-to-production delivery",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(direct_to_prod)} transport route(s) allow direct transport "
                    "from development to production, bypassing quality assurance. "
                    "This violates separation of environments and change management controls."
                ),
                affected_items=direct_to_prod,
                remediation=(
                    "Remove direct dev→prod transport routes. "
                    "Enforce dev→QA→prod route sequence in TMS (STMS). "
                    "Configure transport target groups for multi-tier delivery."
                ),
                references=[
                    "CIS SAP Benchmark — Transport Route Configuration",
                    "SAP Note 18898 — TMS Configuration",
                ],
            )

    def check_transport_workflow(self):
        """
        Analyze transport import history for workflow violations:
        - Imports without approval
        - Same user releasing and importing
        - Imports outside change windows
        """
        history = self.data.get("transport_history")
        if not history:
            return

        no_approval = []
        same_user = []
        weekend_imports = []

        for row in history:
            tr_id = row.get("TRKORR", row.get("TRANSPORT",
                   row.get("REQUEST", "")))
            released_by = row.get("RELEASED_BY", row.get("RELEASER",
                         row.get("AS4USER", "")))
            imported_by = row.get("IMPORTED_BY", row.get("IMPORTER",
                         row.get("IMPORT_USER", "")))
            approval = row.get("APPROVAL", row.get("APPROVED_BY",
                      row.get("APPROVER", "")))
            import_date = row.get("IMPORT_DATE", row.get("IMPORT_TIME",
                         row.get("TRDATE", "")))
            target = row.get("TARGET", row.get("TARGET_SYSTEM", ""))

            label = f"{tr_id} → {target}"

            # No approval
            if not approval or approval.strip() == "":
                target_upper = target.upper()
                is_prod = any(p in target_upper for p in ["PRD", "PROD", "P"])
                if is_prod:
                    no_approval.append(f"{label} (imported by: {imported_by})")

            # Same user released and imported
            if released_by and imported_by:
                if released_by.upper() == imported_by.upper():
                    same_user.append(
                        f"{label} — released and imported by: {released_by}"
                    )

            # Weekend/off-hours imports (basic check)
            if import_date:
                parsed = self._parse_date_flexible(import_date)
                if parsed and parsed.weekday() >= 5:  # Saturday=5, Sunday=6
                    weekend_imports.append(
                        f"{label} — imported: {import_date} (weekend)"
                    )

        if no_approval:
            self.finding(
                check_id="CODE-TMS-002",
                title="Production transport imports without approval",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(no_approval)} transport(s) were imported into production "
                    "without recorded approval. Change management requires explicit "
                    "approval before production deployment."
                ),
                affected_items=no_approval[:30],
                remediation=(
                    "Configure TMS workflow to require approval before production import. "
                    "Use SAP ChaRM (Change Request Management) or Solution Manager "
                    "for automated approval workflows. "
                    "Retroactively document approval for existing imports."
                ),
                references=[
                    "ITIL Change Management — Approval Process",
                    "CIS SAP Benchmark — Transport Approval Controls",
                ],
                details={"total_count": len(no_approval)},
            )

        if same_user:
            self.finding(
                check_id="CODE-TMS-003",
                title="Transports released and imported by the same user",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(same_user)} transport(s) were both released and imported "
                    "by the same person. This violates separation of duties in "
                    "the change management process (maker-checker principle)."
                ),
                affected_items=same_user[:30],
                remediation=(
                    "Enforce different users for release vs import. "
                    "Configure TMS to prevent self-import. "
                    "Separate developer (release) and basis admin (import) roles."
                ),
                references=["CIS SAP Benchmark — Transport SoD Controls"],
                details={"total_count": len(same_user)},
            )

        if weekend_imports:
            self.finding(
                check_id="CODE-TMS-004",
                title="Transport imports outside normal change windows (weekends)",
                severity=self.SEVERITY_MEDIUM,
                category="Code & Transport Security",
                description=(
                    f"{len(weekend_imports)} transport(s) were imported on weekends, "
                    "outside normal change windows. While not always prohibited, "
                    "off-hours changes warrant additional scrutiny."
                ),
                affected_items=weekend_imports[:20],
                remediation=(
                    "Review all off-hours imports for emergency justification. "
                    "Implement change freeze periods with exception workflows. "
                    "Log all emergency changes with post-implementation review."
                ),
                references=["ITIL — Change Window Management"],
                details={"total_count": len(weekend_imports)},
            )

    def check_direct_prod_imports(self):
        """Check for transports imported directly into production from non-standard sources."""
        history = self.data.get("transport_history")
        if not history:
            return

        direct_imports = []
        for row in history:
            tr_id = row.get("TRKORR", row.get("TRANSPORT", ""))
            source = row.get("SOURCE", row.get("SOURCE_SYSTEM",
                    row.get("ORIGIN", ""))).upper()
            target = row.get("TARGET", row.get("TARGET_SYSTEM", "")).upper()
            tr_type = row.get("TYPE", row.get("TRANSPORT_TYPE", ""))

            is_prod = any(p in target for p in ["PRD", "PROD", "PRODUCTION"])
            is_from_dev = any(d in source for d in ["DEV", "DEVELOPMENT", "SBX", "SANDBOX"])

            if is_prod and is_from_dev:
                direct_imports.append(
                    f"{tr_id}: {source} → {target} (type: {tr_type})"
                )

        if direct_imports:
            self.finding(
                check_id="CODE-TMS-005",
                title="Transports imported into production directly from development",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(direct_imports)} transport(s) were imported into production "
                    "directly from development systems, bypassing QA/staging. "
                    "This skips integration testing and quality gates."
                ),
                affected_items=direct_imports[:20],
                remediation=(
                    "Block direct dev→prod transports in TMS. "
                    "Enforce the consolidated delivery path through QA. "
                    "For emergencies, use a documented hotfix process that "
                    "still requires QA validation (post-deploy)."
                ),
                references=["CIS SAP Benchmark — Transport Route Enforcement"],
                details={"total_count": len(direct_imports)},
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-CLIENT-*: Client Configuration
    # ════════════════════════════════════════════════════════════════

    def check_client_settings(self):
        """
        Audit SCC4 client configuration for production client:
        - Cross-client changes allowed
        - Client-specific changes allowed
        - Changes to repository objects allowed
        """
        clients = self.data.get("client_settings")
        if not clients:
            return

        risky_clients = []
        for row in clients:
            client = row.get("CLIENT", row.get("MANDT", row.get("CLIENT_NUMBER", "")))
            role = row.get("ROLE", row.get("CLIENT_ROLE", row.get("CCCATEGORY", "")))
            changes = row.get("CHANGES_ALLOWED", row.get("CCCORACTIV",
                     row.get("CHANGE_OPTION", "")))
            cross_client = row.get("CROSS_CLIENT_CHANGES", row.get("CCNOCLIIND",
                          row.get("CROSS_CLIENT", "")))
            repo_changes = row.get("REPOSITORY_CHANGES", row.get("CCCOPYLOCK",
                          row.get("REPO_CHANGES", "")))

            is_prod = str(role).upper() in ("P", "PRODUCTION", "PROD")
            if not is_prod:
                # Also check by client number convention
                if client in ("000", "001"):
                    continue  # System clients, skip
                # Heuristic: high-number clients in range 100-999 may be prod
                # but we can't know for sure without the role flag

            issues = []

            # Changes allowed in production (should be locked)
            if changes and str(changes).upper() not in (
                "0", "NO_CHANGES", "LOCKED", "NO", "FALSE",
                "NO CHANGES ALLOWED", "LOCK"
            ):
                issues.append(f"changes_allowed={changes}")

            # Cross-client changes allowed
            if cross_client and str(cross_client).upper() in (
                "1", "YES", "ALLOWED", "TRUE", "X",
                "CHANGES TO REPOSITORY AND CROSS-CLIENT"
            ):
                issues.append(f"cross_client_changes=allowed")

            # Repository changes allowed
            if repo_changes and str(repo_changes).upper() in (
                "1", "YES", "ALLOWED", "TRUE", "X", "MODIFIABLE"
            ):
                issues.append(f"repository_changes=allowed")

            if issues and is_prod:
                risky_clients.append(
                    f"Client {client} (role: {role}) — {'; '.join(issues)}"
                )

        if risky_clients:
            self.finding(
                check_id="CODE-CLIENT-001",
                title="Production client allows changes (not locked)",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(risky_clients)} production client(s) are not properly locked. "
                    "Production clients should prohibit direct changes, cross-client "
                    "customizing, and repository modifications to enforce the "
                    "transport-based change management process."
                ),
                affected_items=risky_clients,
                remediation=(
                    "Lock production client via SCC4: "
                    "set 'Changes and Transports for Client-Specific Objects' = "
                    "'No Changes Allowed', disable cross-client changes, and "
                    "disable repository changes. Only allow changes via transport import."
                ),
                references=[
                    "SAP Note 135028 — Client Settings for Production",
                    "CIS SAP Benchmark — Client Configuration",
                ],
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-CHG-*: Change Document Audit Trail
    # ════════════════════════════════════════════════════════════════

    def check_change_document_gaps(self):
        """
        Analyze change document coverage:
        - Critical objects changed without change documents
        - Change documents disabled for sensitive tables
        """
        changes = self.data.get("change_documents")
        if not changes:
            return

        # Check for objects that should always have change docs
        critical_objects = {
            "USER": "User master changes (SU01)",
            "ROLE": "Role/authorization changes (PFCG)",
            "PFCG": "Role changes",
            "CDHDR": "Change document header manipulation",
            "T000": "Client configuration changes",
            "TADIR": "Repository object directory changes",
            "RFCDES": "RFC destination changes",
        }

        logged_objects = set()
        no_user_changes = []
        high_volume = []

        for row in changes:
            obj_class = row.get("OBJECTCLAS", row.get("OBJECT_CLASS",
                       row.get("OBJECT", ""))).upper()
            change_id = row.get("CHANGENR", row.get("CHANGE_NUMBER", ""))
            user = row.get("USERNAME", row.get("UNAME", row.get("USER", "")))
            change_date = row.get("UDATE", row.get("DATE", row.get("CHANGE_DATE", "")))
            tcode = row.get("TCODE", row.get("TRANSACTION", ""))

            logged_objects.add(obj_class)

            # Flag changes by system/batch users (may indicate automation without docs)
            if not user or user.strip() in ("", "BATCH", "SYSTEM", "DDIC"):
                no_user_changes.append(
                    f"{obj_class} #{change_id} — user: {user or 'empty'}, "
                    f"tcode: {tcode}, date: {change_date}"
                )

        # Check for critical objects without change documents
        missing_objects = []
        for obj, desc in critical_objects.items():
            if obj not in logged_objects:
                missing_objects.append(f"{obj}: {desc}")

        if missing_objects:
            self.finding(
                check_id="CODE-CHG-001",
                title="Critical object types without change documents",
                severity=self.SEVERITY_MEDIUM,
                category="Code & Transport Security",
                description=(
                    f"{len(missing_objects)} critical object type(s) have no change "
                    "documents recorded. This may indicate change logging is disabled "
                    "or the data export is incomplete."
                ),
                affected_items=missing_objects,
                remediation=(
                    "Ensure change document logging is enabled for all critical objects. "
                    "Verify rec/client parameter includes the production client. "
                    "Check table logging is active for sensitive tables."
                ),
                references=["CIS SAP Benchmark — Change Document Logging"],
            )

        if no_user_changes:
            self.finding(
                check_id="CODE-CHG-002",
                title="Change documents with empty or system user attribution",
                severity=self.SEVERITY_MEDIUM,
                category="Code & Transport Security",
                description=(
                    f"{len(no_user_changes)} change document(s) are attributed to empty, "
                    "BATCH, or SYSTEM users. Changes without proper user attribution "
                    "break the audit trail for forensic investigation."
                ),
                affected_items=no_user_changes[:20],
                remediation=(
                    "Investigate the source of unattributed changes. "
                    "Ensure batch jobs run under named service accounts, not generic users. "
                    "Configure system-to-system interactions to use traceable identities."
                ),
                references=["SOX Section 404 — Change Audit Trail"],
                details={"total_count": len(no_user_changes)},
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-DEV-*: Development Access in Production
    # ════════════════════════════════════════════════════════════════

    def check_dev_access_in_prod(self):
        """Check for users with development access (SE38/SE80/S_DEVELOP) in production."""
        dev_access = self.data.get("dev_access_prod")
        if not dev_access:
            # Fall back to auth_objects data
            auth = self.data.get("auth_objects")
            if not auth:
                return

            dev_users = []
            for row in auth:
                obj = row.get("OBJECT", row.get("AUTH_OBJECT", "")).upper()
                user = row.get("UNAME", row.get("BNAME", ""))
                value = row.get("VALUE", row.get("AUTH_VALUE", ""))
                field = row.get("FIELD", row.get("AUTH_FIELD", "")).upper()

                if obj == "S_DEVELOP":
                    activity = value if field == "ACTVT" else ""
                    # ACTVT = 02 (modify) or 01 (create) are especially dangerous
                    if activity in ("*", "01", "02"):
                        dev_users.append(
                            f"{user} → S_DEVELOP (ACTVT={activity})"
                        )

            if dev_users:
                self.finding(
                    check_id="CODE-DEV-001",
                    title="Users with S_DEVELOP modify/create access in production",
                    severity=self.SEVERITY_HIGH,
                    category="Code & Transport Security",
                    description=(
                        f"{len(dev_users)} user(s) have S_DEVELOP authorization with "
                        "create/modify activity in production. This allows direct "
                        "code changes and debugging with replace in the production system."
                    ),
                    affected_items=dev_users[:30],
                    remediation=(
                        "Remove S_DEVELOP with ACTVT 01/02/* from all production users. "
                        "Display-only (ACTVT=03) may be acceptable for support roles. "
                        "Use the firefighter process for emergency development access."
                    ),
                    references=[
                        "CIS SAP Benchmark Section 7.1 — Development in Production",
                        "SAP Note 2078087 — S_DEVELOP Authorization",
                    ],
                    details={"total_count": len(dev_users)},
                )
            return

        # Process dedicated dev_access_prod export
        dev_users = []
        for row in dev_access:
            user = row.get("USERNAME", row.get("BNAME", row.get("UNAME", "")))
            tcode = row.get("TCODE", row.get("TRANSACTION", ""))
            auth_obj = row.get("AUTH_OBJECT", row.get("OBJECT", ""))
            activity = row.get("ACTIVITY", row.get("ACTVT", ""))

            dev_users.append(
                f"{user} — tcode: {tcode}, auth: {auth_obj}, activity: {activity}"
            )

        if dev_users:
            self.finding(
                check_id="CODE-DEV-001",
                title="Users with development access in production",
                severity=self.SEVERITY_HIGH,
                category="Code & Transport Security",
                description=(
                    f"{len(dev_users)} user(s) have development transaction access "
                    "(SE38, SE80, etc.) or S_DEVELOP authorization in production."
                ),
                affected_items=dev_users[:30],
                remediation=(
                    "Remove all development tcodes and S_DEVELOP from production roles. "
                    "Use firefighter/emergency access for legitimate troubleshooting."
                ),
                references=["CIS SAP Benchmark — Development in Production"],
                details={"total_count": len(dev_users)},
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-MOD-*: SAP Standard Modifications
    # ════════════════════════════════════════════════════════════════

    def check_sap_modifications(self):
        """Audit SAP standard modifications for security and upgrade risk."""
        mods = self.data.get("sap_modifications")
        if not mods:
            return

        unregistered = []
        high_risk = []
        stale = []
        now = datetime.now()

        high_risk_namespaces = ["SAPLAUTH", "SAPLSU", "SAPLS38", "SAPLSECUR",
                                "SAPMSSY", "SAPLSMSY", "SAPLSTMS"]

        for row in mods:
            obj_name = row.get("OBJECT", row.get("OBJECT_NAME",
                      row.get("PROGRAM", "")))
            mod_type = row.get("TYPE", row.get("MOD_TYPE", ""))
            registered = row.get("REGISTERED", row.get("SAP_NOTE",
                        row.get("CORRECTION", "")))
            mod_date = row.get("MOD_DATE", row.get("DATE",
                      row.get("CHANGED_ON", "")))
            mod_by = row.get("MODIFIED_BY", row.get("CHANGED_BY",
                    row.get("USER", "")))
            reason = row.get("REASON", row.get("DESCRIPTION", ""))

            label = f"{obj_name} (type: {mod_type}, by: {mod_by})"

            # Unregistered modifications
            if not registered or registered.strip() == "":
                unregistered.append(f"{label} — no SAP Note / registration")

            # Modifications to security-sensitive objects
            for ns in high_risk_namespaces:
                if ns.upper() in obj_name.upper():
                    high_risk.append(f"{label} — modified security namespace: {ns}")
                    break

            # Stale modifications (very old, may cause upgrade issues)
            if mod_date:
                parsed = self._parse_date_flexible(mod_date)
                if parsed:
                    age_years = (now - parsed).days / 365
                    if age_years > 5:
                        stale.append(
                            f"{label} — modified: {mod_date} ({age_years:.0f} years ago)"
                        )

        if unregistered:
            self.finding(
                check_id="CODE-MOD-001",
                title="Unregistered SAP standard modifications",
                severity=self.SEVERITY_MEDIUM,
                category="Code & Transport Security",
                description=(
                    f"{len(unregistered)} modification(s) to SAP standard objects are "
                    "not registered with an SAP Note or correction number. "
                    "Unregistered modifications are lost during upgrades and "
                    "may introduce undocumented vulnerabilities."
                ),
                affected_items=unregistered[:30],
                remediation=(
                    "Register all modifications via transaction SE95 (Modification Browser). "
                    "Document the business reason and expected behavior change. "
                    "Plan to reverse modifications during upgrade projects."
                ),
                references=["SAP Note 7920 — Modification Assistant"],
                details={"total_count": len(unregistered)},
            )

        if high_risk:
            self.finding(
                check_id="CODE-MOD-002",
                title="Modifications to SAP security-critical standard programs",
                severity=self.SEVERITY_CRITICAL,
                category="Code & Transport Security",
                description=(
                    f"{len(high_risk)} modification(s) affect SAP security-related "
                    "standard programs (authorization, user management, transport system). "
                    "These modifications may weaken or bypass built-in security controls."
                ),
                affected_items=high_risk,
                remediation=(
                    "Review each security-related modification immediately. "
                    "Verify modifications do not weaken authorization checks. "
                    "Replace with BAdI/enhancement implementations where possible. "
                    "Request SAP security review for critical modifications."
                ),
                references=["SAP — Modification Guidelines for Security Objects"],
            )

        if stale:
            self.finding(
                check_id="CODE-MOD-003",
                title="Stale SAP modifications (5+ years old)",
                severity=self.SEVERITY_LOW,
                category="Code & Transport Security",
                description=(
                    f"{len(stale)} SAP modification(s) are more than 5 years old. "
                    "Very old modifications are likely outdated, may conflict with "
                    "current SAP patches, and should be reviewed for relevance."
                ),
                affected_items=stale[:20],
                remediation=(
                    "Review all stale modifications for continued necessity. "
                    "Reverse modifications that are no longer needed. "
                    "Update remaining modifications to align with current SAP version."
                ),
                references=["SAP Upgrade Guide — Modification Handling"],
                details={"total_count": len(stale)},
            )

    # ════════════════════════════════════════════════════════════════
    #  CODE-DEAD-*: Dead / Unreferenced Custom Code
    # ════════════════════════════════════════════════════════════════

    def check_dead_custom_code(self):
        """Check for unreferenced or unused custom code objects."""
        inventory = self.data.get("code_inventory")
        if not inventory:
            return

        unused = []
        no_owner = []

        for row in inventory:
            obj_name = row.get("OBJECT_NAME", row.get("PROGRAM",
                      row.get("REPORT", "")))
            obj_type = row.get("OBJECT_TYPE", row.get("TYPE", ""))
            last_used = row.get("LAST_USED", row.get("LAST_EXECUTION",
                       row.get("LAST_RUN", "")))
            owner = row.get("OWNER", row.get("RESPONSIBLE",
                   row.get("CREATED_BY", "")))
            referenced = row.get("REFERENCED", row.get("HAS_REFERENCES",
                        row.get("USED_BY", "")))
            created = row.get("CREATED", row.get("CREATED_DATE", ""))

            label = f"{obj_name} ({obj_type})"

            # Unreferenced code
            if referenced and str(referenced).upper() in (
                "NO", "FALSE", "0", "NONE"
            ):
                unused.append(f"{label} — unreferenced, created: {created or 'unknown'}")
            elif not last_used or last_used.strip() == "":
                # Never executed
                unused.append(f"{label} — never executed, created: {created or 'unknown'}")

            # No owner
            if not owner or owner.strip() == "":
                no_owner.append(label)

        if unused:
            max_dead_code = self.get_config("max_dead_code_alert", 50)
            if len(unused) > max_dead_code:
                self.finding(
                    check_id="CODE-DEAD-001",
                    title=f"Excessive unreferenced custom code ({len(unused)} objects)",
                    severity=self.SEVERITY_MEDIUM,
                    category="Code & Transport Security",
                    description=(
                        f"{len(unused)} custom code object(s) are unreferenced or never "
                        "executed. Dead code increases the maintenance surface, may "
                        "contain vulnerabilities, and complicates security reviews."
                    ),
                    affected_items=unused[:30],
                    remediation=(
                        "Conduct a custom code cleanup project. "
                        "Use SAP Custom Code Migration tools or ABAP Call Monitor "
                        "(SCMON) to identify truly unused code. "
                        "Archive and remove confirmed dead code."
                    ),
                    references=["SAP — Custom Code Lifecycle Management"],
                    details={"total_count": len(unused)},
                )

        if no_owner:
            self.finding(
                check_id="CODE-DEAD-002",
                title="Custom code objects without designated owner",
                severity=self.SEVERITY_LOW,
                category="Code & Transport Security",
                description=(
                    f"{len(no_owner)} custom code object(s) have no designated owner. "
                    "Ownerless code cannot be maintained, reviewed, or properly "
                    "included in security assessments."
                ),
                affected_items=no_owner[:30],
                remediation=(
                    "Assign owners to all custom code objects. "
                    "Owner should be the responsible development team or individual. "
                    "Include ownership in ATC/code inspector metadata."
                ),
                references=["SAP — Custom Code Governance"],
                details={"total_count": len(no_owner)},
            )

    # ════════════════════════════════════════════════════════════════
    #  Utility
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _parse_date_flexible(date_str: str):
        if not date_str or not str(date_str).strip():
            return None
        date_str = str(date_str).strip()
        for suffix in ("Z", "+00:00", "+0000"):
            if date_str.endswith(suffix):
                date_str = date_str[:-len(suffix)]
        if "T" in date_str:
            date_str = date_str.split("T")[0]
        for fmt in ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y", "%m/%d/%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(date_str[:10], fmt)
            except (ValueError, IndexError):
                continue
        return None
