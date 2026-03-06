"""
Security Parameters Auditor
============================
Validates SAP profile parameters (RZ10/RZ11 exports) against
CIS SAP S/4HANA benchmark and SAP security best practices.

Checks include:
  - Password policy parameters
  - Login security parameters
  - RFC security parameters
  - ICM/TLS configuration
  - Gateway security
  - Audit logging enablement
  - ABAP debugger restrictions
"""

from typing import Dict, List, Any
from modules.base_auditor import BaseAuditor


class SecurityParamAuditor(BaseAuditor):

    # Baseline: parameter → (expected_value, operator, severity, description, remediation)
    # Operators: "==", ">=", "<=", "!=", "in", "not_in", "contains"
    BASELINE = {
        # --- Password Policy ---
        "login/min_password_lng": {
            "expected": "8",
            "op": ">=",
            "severity": "HIGH",
            "category": "Password Policy",
            "desc": "Minimum password length should be at least 8 characters",
            "fix": "Set login/min_password_lng >= 8 in RZ10 (12+ recommended)",
            "refs": ["SAP Note 1731549", "CIS SAP Benchmark 1.1.1"],
        },
        "login/min_password_digits": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 digit",
            "fix": "Set login/min_password_digits >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.2"],
        },
        "login/min_password_letters": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 letter",
            "fix": "Set login/min_password_letters >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.3"],
        },
        "login/min_password_specials": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 special character",
            "fix": "Set login/min_password_specials >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.4"],
        },
        "login/password_expiration_time": {
            "expected": "90",
            "op": "<=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Password expiration should be 90 days or less",
            "fix": "Set login/password_expiration_time <= 90 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.6"],
        },
        "login/password_max_idle_initial": {
            "expected": "14",
            "op": "<=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Initial passwords should expire within 14 days if unused",
            "fix": "Set login/password_max_idle_initial <= 14",
            "refs": ["CIS SAP Benchmark 1.1.7"],
        },
        "login/password_history_size": {
            "expected": "5",
            "op": ">=",
            "severity": "LOW",
            "category": "Password Policy",
            "desc": "Password history should prevent reuse of last 5+ passwords",
            "fix": "Set login/password_history_size >= 5",
            "refs": ["CIS SAP Benchmark 1.1.8"],
        },

        # --- Login Security ---
        "login/fails_to_session_end": {
            "expected": "3",
            "op": "<=",
            "severity": "HIGH",
            "category": "Login Security",
            "desc": "Session should end after max 3 failed logon attempts",
            "fix": "Set login/fails_to_session_end <= 3",
            "refs": ["CIS SAP Benchmark 1.2.1"],
        },
        "login/fails_to_user_lock": {
            "expected": "5",
            "op": "<=",
            "severity": "HIGH",
            "category": "Login Security",
            "desc": "Account should lock after max 5 failed logon attempts",
            "fix": "Set login/fails_to_user_lock <= 5",
            "refs": ["CIS SAP Benchmark 1.2.2"],
        },
        "login/no_automatic_user_sapstar": {
            "expected": "1",
            "op": "==",
            "severity": "CRITICAL",
            "category": "Login Security",
            "desc": "Must disable automatic SAP* user logon (prevents default password attack)",
            "fix": "Set login/no_automatic_user_sapstar = 1",
            "refs": ["SAP Note 68048", "CIS SAP Benchmark 1.2.5"],
        },
        "login/disable_multi_gui_login": {
            "expected": "1",
            "op": "==",
            "severity": "LOW",
            "category": "Login Security",
            "desc": "Should disable multiple GUI sessions per user",
            "fix": "Set login/disable_multi_gui_login = 1",
            "refs": ["CIS SAP Benchmark 1.2.6"],
        },

        # --- RFC Security ---
        "rfc/reject_insecure_logon": {
            "expected": "1",
            "op": "==",
            "severity": "HIGH",
            "category": "RFC Security",
            "desc": "Must reject insecure RFC logons (plaintext password transmission)",
            "fix": "Set rfc/reject_insecure_logon = 1",
            "refs": ["SAP Note 2416093", "CIS SAP Benchmark 4.1"],
        },
        "rfc/reject_insecure_logon_data": {
            "expected": "1",
            "op": "==",
            "severity": "HIGH",
            "category": "RFC Security",
            "desc": "Must reject insecure RFC data transmission",
            "fix": "Set rfc/reject_insecure_logon_data = 1",
            "refs": ["SAP Note 2416093"],
        },
        "rfc/allowoldticket4tt": {
            "expected": "0",
            "op": "==",
            "severity": "MEDIUM",
            "category": "RFC Security",
            "desc": "Should disable old-format RFC tickets (weaker crypto)",
            "fix": "Set rfc/allowoldticket4tt = 0",
            "refs": ["SAP Note 2416093"],
        },

        # --- Gateway Security ---
        "gw/sec_info": {
            "expected": "",
            "op": "!=",
            "severity": "CRITICAL",
            "category": "Gateway Security",
            "desc": "Gateway security info file must be configured (secinfo)",
            "fix": "Configure gw/sec_info to point to a secinfo file with restrictive rules",
            "refs": ["SAP Note 1408081", "CIS SAP Benchmark 3.1"],
        },
        "gw/reg_info": {
            "expected": "",
            "op": "!=",
            "severity": "CRITICAL",
            "category": "Gateway Security",
            "desc": "Gateway registration info file must be configured (reginfo)",
            "fix": "Configure gw/reg_info to point to a reginfo file with restrictive rules",
            "refs": ["SAP Note 1408081", "CIS SAP Benchmark 3.2"],
        },
        "gw/reg_no_conn_info": {
            "expected": "255",
            "op": ">=",
            "severity": "HIGH",
            "category": "Gateway Security",
            "desc": "Should limit gateway connection logging level",
            "fix": "Set gw/reg_no_conn_info appropriately",
            "refs": ["SAP Note 1408081"],
        },

        # --- ICM / TLS ---
        "icm/HTTPS/verify_client": {
            "expected": "1",
            "op": ">=",
            "severity": "HIGH",
            "category": "Transport Security",
            "desc": "ICM should verify client certificates for HTTPS",
            "fix": "Set icm/HTTPS/verify_client = 1 (require) or 2 (optional verify)",
            "refs": ["SAP Note 510007"],
        },
        "ssl/ciphersuites": {
            "expected": "",
            "op": "!=",
            "severity": "HIGH",
            "category": "Transport Security",
            "desc": "TLS cipher suites must be explicitly configured (not defaults)",
            "fix": "Configure ssl/ciphersuites to allow only strong ciphers (TLS 1.2+, AES-256)",
            "refs": ["SAP Note 510007", "CIS SAP Benchmark 5.1"],
        },

        # --- Audit Logging ---
        "rsau/enable": {
            "expected": "1",
            "op": "==",
            "severity": "CRITICAL",
            "category": "Audit Logging",
            "desc": "Security Audit Log must be enabled",
            "fix": "Set rsau/enable = 1 and configure filters in SM19",
            "refs": ["SAP Note 2191612", "CIS SAP Benchmark 6.1"],
        },
        "rec/client": {
            "expected": "",
            "op": "!=",
            "severity": "HIGH",
            "category": "Audit Logging",
            "desc": "Table logging client must be configured",
            "fix": "Set rec/client to log critical client(s), e.g. rec/client = ALL",
            "refs": ["CIS SAP Benchmark 6.2"],
        },

        # --- Debug / Development in Production ---
        "rdisp/wpdbug_max_no": {
            "expected": "0",
            "op": "==",
            "severity": "HIGH",
            "category": "Development Controls",
            "desc": "Debugging in production should be disabled (zero debug work processes)",
            "fix": "Set rdisp/wpdbug_max_no = 0 in production systems",
            "refs": ["CIS SAP Benchmark 7.1"],
        },
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_params_against_baseline()
        self.check_missing_critical_params()
        return self.findings

    def check_params_against_baseline(self):
        """Compare each exported parameter against the security baseline."""
        params = self.data.get("security_params")
        if not params:
            self.finding(
                check_id="PARAM-000",
                title="No security parameters data available",
                severity=self.SEVERITY_HIGH,
                category="Security Parameters",
                description=(
                    "No profile parameter export was found. Cannot validate "
                    "security configuration baseline."
                ),
                remediation=(
                    "Export parameters using RZ11 (single) or RZ10 (profiles). "
                    "Alternatively, run report RSPARAM and export to CSV."
                ),
            )
            return

        # Build lookup: param_name → value
        param_lookup = {}
        for row in params:
            name = row.get("NAME", row.get("PARAMETER", row.get("PARAM_NAME", ""))).lower()
            value = row.get("VALUE", row.get("PARAM_VALUE", row.get("CURRENT_VALUE", "")))
            if name:
                param_lookup[name] = value

        # Check each baseline parameter
        for param_name, rule in self.BASELINE.items():
            # Allow baseline overrides
            override_key = f"param.{param_name}"
            if override_key in self.overrides:
                rule = {**rule, **self.overrides[override_key]}

            actual_value = param_lookup.get(param_name.lower())

            if actual_value is None:
                continue  # Will be caught by missing params check

            if not self._evaluate_rule(actual_value, rule["expected"], rule["op"]):
                self.finding(
                    check_id=f"PARAM-{param_name}",
                    title=f"Parameter {param_name} non-compliant",
                    severity=rule["severity"],
                    category=rule["category"],
                    description=(
                        f"{rule['desc']}. "
                        f"Current value: '{actual_value}', "
                        f"Expected: {rule['op']} '{rule['expected']}'"
                    ),
                    affected_items=[f"{param_name} = {actual_value}"],
                    remediation=rule["fix"],
                    references=rule.get("refs", []),
                    details={
                        "parameter": param_name,
                        "current_value": actual_value,
                        "expected_value": rule["expected"],
                        "operator": rule["op"],
                    },
                )

    def check_missing_critical_params(self):
        """Flag critical parameters that are missing from export entirely."""
        params = self.data.get("security_params")
        if not params:
            return

        param_lookup = set()
        for row in params:
            name = row.get("NAME", row.get("PARAMETER", row.get("PARAM_NAME", ""))).lower()
            if name:
                param_lookup.add(name)

        critical_missing = []
        for param_name, rule in self.BASELINE.items():
            if rule["severity"] in ("CRITICAL", "HIGH"):
                if param_name.lower() not in param_lookup:
                    critical_missing.append(f"{param_name} ({rule['category']})")

        if critical_missing:
            self.finding(
                check_id="PARAM-MISSING",
                title="Critical security parameters not found in export",
                severity=self.SEVERITY_HIGH,
                category="Security Parameters",
                description=(
                    f"{len(critical_missing)} critical/high-severity parameters "
                    "were not found in the exported data. They may be at default "
                    "values (often insecure) or not exported."
                ),
                affected_items=critical_missing,
                remediation=(
                    "Export all profile parameters using RSPARAM or RZ10. "
                    "Ensure the listed parameters are explicitly set to secure values."
                ),
            )

    @staticmethod
    def _evaluate_rule(actual: str, expected: str, op: str) -> bool:
        """Evaluate a parameter value against a rule."""
        try:
            if op == "==":
                return actual.strip() == expected.strip()
            elif op == "!=":
                return actual.strip() != expected.strip()
            elif op == ">=":
                return int(actual) >= int(expected)
            elif op == "<=":
                return int(actual) <= int(expected)
            elif op == "contains":
                return expected.lower() in actual.lower()
            elif op == "in":
                return actual.strip() in [v.strip() for v in expected.split(",")]
            elif op == "not_in":
                return actual.strip() not in [v.strip() for v in expected.split(",")]
        except (ValueError, TypeError):
            return False
        return False
