"""
Findings Knowledge Base
=======================
Loads the bundled `data/finding_details.json` — a per-check library of detailed
security-risk narratives and step-by-step remediation procedures — and resolves
the best entry for a given finding.

Resolution order for a finding's `check_id`:
  1. exact match (e.g. "ARA-P2P-01")
  2. progressively shorter hyphen-delimited family prefixes ("BTP-CC-001" →
     "BTP-CC" → "BTP"), so dynamically-named checks still match a family entry
When nothing matches, the report falls back to the finding's own
`description` / `remediation`, so the report is always complete.
"""

import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Any


class FindingKB:
    def __init__(self, path: Optional[str] = None):
        self._kb: Dict[str, Dict[str, str]] = {}
        p = Path(path) if path else Path(__file__).resolve().parent.parent / "data" / "finding_details.json"
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    # accept either {check_id: {...}} or {"knowledge_base": {...}}
                    self._kb = data.get("knowledge_base", data)
            except Exception:
                self._kb = {}

    @property
    def loaded(self) -> bool:
        return bool(self._kb)

    def __len__(self) -> int:
        return len(self._kb)

    def lookup(self, check_id: str) -> Optional[Dict[str, str]]:
        if not self._kb or not check_id:
            return None
        if check_id in self._kb:
            return self._kb[check_id]
        parts = check_id.split("-")
        for i in range(len(parts) - 1, 0, -1):
            key = "-".join(parts[:i])
            if key in self._kb:
                return self._kb[key]
        return None

    def detail_for(self, finding: Dict[str, Any]) -> Tuple[str, str, bool]:
        """Return (risk_text, mitigation_text, is_detailed).

        `is_detailed` is True when a knowledge-base entry supplied the content,
        False when we fell back to the finding's own description/remediation."""
        kb = self.lookup(finding.get("check_id", ""))
        if kb and kb.get("risk") and kb.get("mitigation"):
            return kb["risk"].strip(), kb["mitigation"].strip(), True
        risk = (finding.get("description") or "No description provided.").strip()
        mit = (finding.get("remediation") or "No remediation guidance provided.").strip()
        return risk, mit, False
