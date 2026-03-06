"""
Base Auditor Module
===================
Common base class for all audit modules with shared
finding creation and severity utilities.
"""

from typing import Dict, List, Any, Optional
import datetime


class BaseAuditor:
    """Base class for all SAP audit modules."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    def __init__(self, data: Dict[str, Any], baseline_overrides: Dict = None):
        self.data = data
        self.overrides = baseline_overrides or {}
        self.findings: List[Dict[str, Any]] = []

    def finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        affected_items: List[str] = None,
        remediation: str = "",
        references: List[str] = None,
        details: Dict = None,
    ) -> Dict[str, Any]:
        """Create a standardized finding dict."""
        f = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "affected_items": affected_items or [],
            "affected_count": len(affected_items) if affected_items else 0,
            "remediation": remediation,
            "references": references or [],
            "details": details or {},
            "timestamp": datetime.datetime.now().isoformat(),
        }
        self.findings.append(f)
        return f

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Override in subclass — run all checks and return findings."""
        raise NotImplementedError

    def get_config(self, key: str, default: Any) -> Any:
        """Get config value with baseline override support."""
        return self.overrides.get(key, default)
