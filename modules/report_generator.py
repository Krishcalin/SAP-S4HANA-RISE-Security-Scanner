"""
HTML Report Generator
======================
Generates a professional, interactive HTML security dashboard
with findings summary, severity breakdown, and detailed findings.
"""

import json
import html
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.finding_kb import FindingKB
from modules.compliance_mapping import ComplianceMapper


class ReportGenerator:

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 kb: Optional[FindingKB] = None, priorities: Optional[List[Any]] = None):
        self.findings = findings
        self.meta = meta
        self.kb = kb if kb is not None else FindingKB()
        # Risk-prioritization overlay (P1-P4). Supplied by the scanner; if absent,
        # compute here so a standalone report still shows tiers. Degrades to none.
        self._prio_by_id = {}
        self._tier_meta = {}
        if priorities is None:
            try:
                from modules.risk_prioritizer import RiskPrioritizer
                priorities = RiskPrioritizer().prioritize(findings)
            except Exception:
                priorities = []
        try:
            from modules.risk_prioritizer import TIER_META
            self._tier_meta = TIER_META
        except Exception:
            self._tier_meta = {}
        for p in (priorities or []):
            fnd = getattr(p, "finding", None)
            if fnd is not None:
                self._prio_by_id[id(fnd)] = p

    _TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

    def _tier_of(self, f):
        return self._prio_by_id.get(id(f))

    _ASSET_MIMES = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml", ".webp": "image/webp", ".gif": "image/gif",
    }

    @staticmethod
    def _asset_data_uri(*candidates: str) -> str:
        """Return the first existing assets/<name> file as a self-contained data
        URI (mime inferred from extension), or '' if none exist — so the report
        still renders offline when an optional brand asset is absent."""
        base = Path(__file__).resolve().parent.parent / "assets"
        for name in candidates:
            path = base / name
            try:
                data = path.read_bytes()
            except OSError:
                continue
            mime = ReportGenerator._ASSET_MIMES.get(path.suffix.lower(), "image/png")
            return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
        return ""

    @staticmethod
    def _logo_data_uri() -> str:
        """PhalanxCyber tool-vendor logo (top-right)."""
        return ReportGenerator._asset_data_uri("phalanxcyber-logo.png")

    def generate(self, output_path: str):
        """Generate complete HTML report."""
        # Compute stats
        total = len(self.findings)
        by_severity = {}
        by_category = {}
        for f in self.findings:
            sev = f["severity"]
            cat = f["category"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1

        crit = by_severity.get("CRITICAL", 0)
        high = by_severity.get("HIGH", 0)
        med = by_severity.get("MEDIUM", 0)
        low = by_severity.get("LOW", 0)
        info = by_severity.get("INFO", 0)

        # Proportion-bar widths for the severity cards (scaled to the largest
        # band so the counts read comparatively at a glance).
        _sev_max = max(crit, high, med, low, 1)
        crit_pct = round(crit / _sev_max * 100)
        high_pct = round(high / _sev_max * 100)
        med_pct = round(med / _sev_max * 100)
        low_pct = round(low / _sev_max * 100)

        # Priority tier counts (P1-P4) over the displayed findings.
        tier_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for f in self.findings:
            pr = self._tier_of(f)
            if pr is not None and getattr(pr, "tier", None) in tier_counts:
                tier_counts[pr.tier] += 1
        priority_html = self._render_priority_section(tier_counts)
        # Priority filter buttons — ONLY when tier data exists, so a report that
        # degraded to no tiers doesn't show dead buttons that hide every finding.
        prio_buttons_html = ""
        if self._prio_by_id and self._tier_meta:
            prio_buttons_html = (
                '<label style="margin-left:0.5rem">Priority:</label>'
                f'<button class="filter-btn" onclick="filterFindings(\'P1\')">P1 &middot; Fix Now ({tier_counts["P1"]})</button>'
                f'<button class="filter-btn" onclick="filterFindings(\'P2\')">P2 &middot; This Week ({tier_counts["P2"]})</button>'
                f'<button class="filter-btn" onclick="filterFindings(\'P3\')">P3 &middot; Planned ({tier_counts["P3"]})</button>'
                f'<button class="filter-btn" onclick="filterFindings(\'P4\')">P4 &middot; Backlog ({tier_counts["P4"]})</button>')

        # Risk score (weighted)
        risk_score = min(100, crit * 25 + high * 10 + med * 4 + low * 1)
        if risk_score >= 75:
            risk_label, risk_color = "Critical", "#dc2626"
        elif risk_score >= 50:
            risk_label, risk_color = "High", "#ea580c"
        elif risk_score >= 25:
            risk_label, risk_color = "Medium", "#d97706"
        else:
            risk_label, risk_color = "Low", "#16a34a"

        findings_html = self._render_findings()
        compliance_html = self._render_compliance()
        category_chart_data = json.dumps([
            {"name": k, "count": v} for k, v in sorted(by_category.items(), key=lambda x: -x[1])
        ])

        logo_uri = self._logo_data_uri()
        logo_html = (
            f'<img class="brand-logo" src="{logo_uri}" alt="PhalanxCyber" />'
            if logo_uri else ""
        )

        # Left-of-header "system under assessment" lockup. When the SAP logo asset
        # is present it supplies the "SAP" brand and a divider precedes the title;
        # otherwise the title carries the "SAP" text so the header is self-sufficient.
        sap_logo_uri = self._asset_data_uri(
            "sap-logo.png", "sap-logo.jpg", "sap-logo.jpeg", "sap-logo.svg", "sap.png"
        )
        if sap_logo_uri:
            left_brand_html = (
                f'<img class="sap-logo" src="{sap_logo_uri}" alt="SAP" />'
                '<div class="hl-divider"></div>'
            )
            title_text = "S/4HANA RISE"
        else:
            left_brand_html = ""
            title_text = "SAP S/4HANA RISE"

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP S/4HANA RISE — Security Assessment Report</title>
<style>
  /* Self-contained: no external font/CDN fetch, so the report renders identically
     offline / air-gapped. Preferred faces are used when installed locally. */

  :root {{
    /* Light theme — white page, dark text; severity hues darkened for
       readable contrast on white, tint backgrounds kept pale. */
    --bg-primary: #ffffff;
    --bg-secondary: #f1f5f9;
    --bg-card: #ffffff;
    --bg-card-hover: #f8fafc;
    --border: #e2e8f0;
    --text-primary: #0f172a;
    --text-secondary: #334155;
    --text-muted: #64748b;
    --accent: #0369a1;
    --accent-dim: rgba(3, 105, 161, 0.08);
    --critical: #dc2626;
    --critical-bg: rgba(220, 38, 38, 0.09);
    --high: #ea580c;
    --high-bg: rgba(234, 88, 12, 0.09);
    --medium: #b45309;
    --medium-bg: rgba(180, 83, 9, 0.10);
    --low: #15803d;
    --low-bg: rgba(21, 128, 61, 0.10);
    --info-c: #0369a1;
    --info-bg: rgba(3, 105, 161, 0.08);
    --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'SF Mono', Menlo, Consolas, 'Fira Code', 'Liberation Mono', monospace;
    --radius: 16px;
    --radius-sm: 10px;
    --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.04), 0 1px 3px rgba(15, 23, 42, 0.06);
    --shadow-md: 0 4px 6px -2px rgba(15, 23, 42, 0.05), 0 12px 24px -6px rgba(15, 23, 42, 0.10);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
    letter-spacing: -0.006em;
  }}

  .noise {{
    display: none;   /* dark texture overlay disabled for the white theme */
  }}

  .container {{
    max-width: 1280px;
    margin: 0 auto;
    padding: 2rem;
    position: relative;
    z-index: 1;
  }}

  /* Header */
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-bottom: 2rem;
    padding-bottom: 1.75rem;
    border-bottom: 1px solid var(--border);
  }}

  /* Left "system under assessment" lockup: SAP logo | title */
  .header-left {{
    display: flex;
    align-items: center;
    gap: 1.1rem;
    min-width: 0;
  }}

  .sap-logo {{
    height: 44px;
    width: auto;
    display: block;   /* transparent PNG — floats on the white header, no tile */
  }}

  .hl-divider {{
    width: 1px;
    height: 42px;
    background: var(--border);
    flex-shrink: 0;
  }}

  .header-titles {{
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }}

  .header-left h1 {{
    font-family: var(--font-mono);
    font-size: 1.35rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.02em;
    line-height: 1.1;
    white-space: nowrap;
  }}

  .header-left .subtitle {{
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
    letter-spacing: 0.02em;
    white-space: nowrap;
  }}

  .header-right {{
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0.75rem;
    text-align: right;
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  .header-right span {{
    display: block;
  }}

  /* PhalanxCyber brand logo — top right. The logo art has its own dark
     backdrop, shown as a rounded tile so it sits cleanly on the white page. */
  .brand-logo {{
    width: 210px;
    max-width: 45vw;
    height: auto;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.12);
  }}

  /* Copyright / usage notice, directly under the header. */
  .copyright-banner {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 0.85rem 1.1rem;
    margin-bottom: 2.5rem;
    font-size: 0.78rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }}

  .copyright-banner strong {{
    color: var(--text-primary);
    font-weight: 700;
  }}

  /* Summary Grid */
  .summary-grid {{
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
  }}

  /* Risk Score */
  .risk-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    padding: 2.25rem 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1.25rem;
    position: relative;
    overflow: hidden;
  }}

  .risk-score-ring {{
    width: 156px;
    height: 156px;
    position: relative;
  }}

  .risk-score-ring svg {{
    transform: rotate(-90deg);
    width: 156px;
    height: 156px;
    filter: drop-shadow(0 2px 6px {risk_color}33);
  }}

  .risk-score-ring .score-text {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
  }}

  .risk-score-ring .score-number {{
    font-family: var(--font-mono);
    font-size: 3rem;
    font-weight: 800;
    color: var(--text-primary);
    line-height: 1;
    letter-spacing: -0.04em;
    font-variant-numeric: tabular-nums;
  }}

  .risk-score-ring .score-label {{
    font-size: 0.66rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin-top: 0.35rem;
    font-weight: 600;
  }}

  .risk-level {{
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-weight: 700;
    color: {risk_color};
    background: {risk_color}14;
    border: 1px solid {risk_color}33;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    padding: 0.45rem 1rem;
    border-radius: 999px;
  }}

  /* Severity Cards */
  .severity-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    align-content: start;
  }}

  .sev-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow-sm);
    padding: 1.4rem 1.45rem 1.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    transition: transform 0.18s ease, box-shadow 0.18s ease;
  }}

  .sev-card:hover {{
    transform: translateY(-3px);
    box-shadow: var(--shadow-md);
  }}

  .sev-head {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}

  .sev-dot {{
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex-shrink: 0;
  }}

  .sev-card.critical .sev-dot {{ background: var(--critical); }}
  .sev-card.high .sev-dot {{ background: var(--high); }}
  .sev-card.medium .sev-dot {{ background: var(--medium); }}
  .sev-card.low .sev-dot {{ background: var(--low); }}

  .sev-card .sev-label {{
    font-size: 0.7rem;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }}

  .sev-card .sev-count {{
    font-family: var(--font-mono);
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.04em;
    font-variant-numeric: tabular-nums;
  }}

  .sev-card.critical .sev-count {{ color: var(--critical); }}
  .sev-card.high .sev-count {{ color: var(--high); }}
  .sev-card.medium .sev-count {{ color: var(--medium); }}
  .sev-card.low .sev-count {{ color: var(--low); }}

  .sev-bar {{
    height: 5px;
    background: var(--bg-secondary);
    border-radius: 999px;
    overflow: hidden;
  }}

  .sev-bar span {{
    display: block;
    height: 100%;
    border-radius: 999px;
  }}

  .sev-card.critical .sev-bar span {{ background: var(--critical); }}
  .sev-card.high .sev-bar span {{ background: var(--high); }}
  .sev-card.medium .sev-bar span {{ background: var(--medium); }}
  .sev-card.low .sev-bar span {{ background: var(--low); }}

  /* Category breakdown bar */
  .categories-section {{
    margin-bottom: 2.5rem;
  }}

  .categories-section h2 {{
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-family: var(--font-mono);
    font-size: 0.9rem;
    font-weight: 700;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1.1rem;
  }}

  .categories-section h2::before {{
    content: '';
    width: 3px;
    height: 15px;
    border-radius: 2px;
    background: var(--accent);
  }}

  .cat-bars {{
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }}

  .cat-bar-row {{
    display: grid;
    grid-template-columns: 220px 1fr 50px;
    align-items: center;
    gap: 1rem;
  }}

  .cat-bar-label {{
    font-size: 0.8rem;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    text-align: right;
  }}

  .cat-bar-track {{
    height: 20px;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
  }}

  .cat-bar-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--accent), #818cf8);
    border-radius: 4px;
    min-width: 2px;
    transition: width 0.8s ease-out;
  }}

  .cat-bar-count {{
    font-family: var(--font-mono);
    font-size: 0.8rem;
    color: var(--text-muted);
  }}

  /* Filter bar */
  .filter-bar {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    align-items: center;
  }}

  .filter-bar label {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-right: 0.5rem;
  }}

  .filter-btn {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    padding: 0.4rem 0.8rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.2s;
  }}

  .filter-btn:hover {{
    border-color: var(--accent);
    color: var(--accent);
  }}

  .filter-btn.active {{
    background: var(--accent-dim);
    border-color: var(--accent);
    color: var(--accent);
  }}

  /* Findings */
  .findings-section h2 {{
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-family: var(--font-mono);
    font-size: 0.9rem;
    font-weight: 700;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1.1rem;
  }}

  .findings-section h2::before {{
    content: '';
    width: 3px;
    height: 15px;
    border-radius: 2px;
    background: var(--accent);
  }}

  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-sm);
    margin-bottom: 0.8rem;
    overflow: hidden;
    transition: box-shadow 0.18s ease, border-color 0.18s ease;
  }}

  .finding-card:hover {{
    box-shadow: var(--shadow-md);
    border-color: #d7dee8;
  }}

  .finding-card.open {{
    box-shadow: var(--shadow-md);
  }}

  .finding-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem 1.25rem;
    cursor: pointer;
    user-select: none;
  }}

  .sev-badge {{
    font-family: var(--font-mono);
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    letter-spacing: 0.05em;
    min-width: 72px;
    text-align: center;
    flex-shrink: 0;
  }}

  .sev-badge.CRITICAL {{ background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.2); }}
  .sev-badge.HIGH {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(249,115,22,0.2); }}
  .sev-badge.MEDIUM {{ background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234,179,8,0.2); }}
  .sev-badge.LOW {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(34,197,94,0.2); }}
  .sev-badge.INFO {{ background: var(--info-bg); color: var(--info-c); border: 1px solid rgba(56,189,248,0.2); }}

  /* ── Priority tiers (P1–P4) ─────────────────────────────────────────────── */
  .prio-section {{ margin: 1.5rem 0; }}
  .prio-section h2 {{
    display: flex; align-items: center; gap: 0.6rem;
    font-family: var(--font-mono); font-size: 0.9rem; font-weight: 700;
    color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.08em;
    margin-bottom: 0.4rem;
  }}
  .prio-section h2::before {{
    content: ''; width: 3px; height: 15px; border-radius: 2px; background: var(--accent);
  }}
  .prio-sub {{ font-size: 0.8rem; color: var(--text-secondary); line-height: 1.6; margin: 0 0 1rem; }}
  .prio-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.9rem; }}
  .tier-card {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 1.1rem 1.2rem; border-top: 3px solid var(--text-muted);
    box-shadow: var(--shadow-sm);
    transition: transform 0.18s ease, box-shadow 0.18s ease;
  }}
  .tier-card:hover {{ transform: translateY(-3px); box-shadow: var(--shadow-md); }}
  .tier-card .tier-top {{ display: flex; align-items: baseline; gap: 0.5rem; }}
  .tier-card .tier-id {{ font-size: 1.7rem; font-weight: 800; letter-spacing: -0.02em; font-family: var(--font-mono); }}
  .tier-card .tier-n {{ font-size: 1.1rem; font-weight: 700; color: var(--text-primary); }}
  .tier-card .tier-lab {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); font-weight: 700; margin-top: 0.35rem; }}
  .tier-card .tier-win {{ font-size: 0.72rem; color: var(--text-muted); margin-top: 0.15rem; }}
  .tier-card.P1 {{ border-top-color: var(--critical); }} .tier-card.P1 .tier-id {{ color: var(--critical); }}
  .tier-card.P2 {{ border-top-color: var(--high); }} .tier-card.P2 .tier-id {{ color: var(--high); }}
  .tier-card.P3 {{ border-top-color: var(--medium); }} .tier-card.P3 .tier-id {{ color: var(--medium); }}
  .tier-card.P4 {{ border-top-color: var(--low); }} .tier-card.P4 .tier-id {{ color: var(--low); }}
  @media (max-width: 720px) {{ .prio-grid {{ grid-template-columns: repeat(2, 1fr); }} }}

  .p-badge {{ font-family: var(--font-mono); font-size: 0.68rem; font-weight: 700; padding: 0.25rem 0.5rem; border-radius: 4px; flex-shrink: 0; letter-spacing: 0.02em; }}
  .p-badge.P1 {{ background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }}
  .p-badge.P2 {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }}
  .p-badge.P3 {{ background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }}
  .p-badge.P4 {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(34,197,94,0.3); }}
  .p-tags {{ display: inline-flex; gap: 0.3rem; flex-wrap: wrap; }}
  .p-tag {{ font-family: var(--font-mono); font-size: 0.6rem; font-weight: 700; text-transform: uppercase; padding: 0.12rem 0.35rem; border-radius: 3px; letter-spacing: 0.03em; }}
  .p-tag.exploited {{ background: rgba(239,68,68,0.18); color: var(--critical); }}
  .p-tag.hotnews {{ background: rgba(249,115,22,0.15); color: var(--high); }}
  .p-tag.exposed {{ background: rgba(234,179,8,0.15); color: var(--medium); }}
  .p-tag.priv {{ background: rgba(79,70,229,0.12); color: #4f46e5; }}

  .tr-title {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-muted); font-weight: 700; margin: 1.2rem 0 0.6rem; }}
  .toprisks {{ display: flex; flex-direction: column; gap: 0.45rem; }}
  .tr-row {{ display: grid; grid-template-columns: auto auto 1fr auto; gap: 0.8rem; align-items: center; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 0.9rem; }}
  .tr-rank {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted); font-weight: 700; min-width: 1.1rem; text-align: center; }}
  .tr-name {{ font-size: 0.85rem; font-weight: 600; color: var(--text-primary); }}
  .tr-why {{ font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.2rem; line-height: 1.5; }}
  @media (max-width: 720px) {{ .tr-row {{ grid-template-columns: auto 1fr; }} .tr-score, .p-tags {{ grid-column: 2; }} }}

  .finding-title {{
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
  }}

  .finding-id {{
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-muted);
    flex-shrink: 0;
  }}

  .finding-chevron {{
    font-size: 0.75rem;
    color: var(--text-muted);
    transition: transform 0.2s;
  }}

  .finding-card.open .finding-chevron {{
    transform: rotate(90deg);
  }}

  .finding-body {{
    display: none;
    padding: 0 1.25rem 1.25rem;
    border-top: 1px solid var(--border);
  }}

  .finding-card.open .finding-body {{
    display: block;
  }}

  .finding-section {{
    margin-top: 1rem;
  }}

  .finding-section-title {{
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.5rem;
  }}

  .finding-section p {{
    font-size: 0.96rem;
    color: var(--text-secondary);
    line-height: 1.75;
    white-space: pre-line;
  }}

  .affected-list {{
    list-style: none;
    padding: 0;
    margin: 0;
    background: var(--bg-primary);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    max-height: 200px;
    overflow-y: auto;
  }}

  .affected-list li {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-secondary);
    padding: 0.2rem 0;
    border-bottom: 1px solid var(--border);
  }}

  .affected-list li:last-child {{ border: none; }}

  .ref-list {{
    list-style: none;
    padding: 0;
  }}

  .ref-list li {{
    font-size: 0.8rem;
    color: var(--accent);
    padding: 0.15rem 0;
  }}

  .ref-list li::before {{
    content: '→ ';
    color: var(--text-muted);
  }}

  .remediation-text {{
    background: var(--low-bg);
    border-left: 3px solid var(--low);
    padding: 0.9rem 1.1rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.96rem;
    line-height: 1.75;
    color: var(--text-secondary);
    white-space: pre-line;
  }}

  .risk-text {{
    background: var(--high-bg);
    border-left: 3px solid var(--high);
    padding: 0.9rem 1.1rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.96rem;
    color: var(--text-secondary);
    line-height: 1.75;
    white-space: pre-line;
  }}

  /* Compliance / control-framework mapping */
  .compliance-section {{ margin-bottom: 2.5rem; }}
  .compliance-section h2 {{
    display: flex; align-items: center; gap: 0.6rem;
    font-family: var(--font-mono); font-size: 0.9rem; font-weight: 700;
    color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.08em;
    margin-bottom: 0.6rem;
  }}
  .compliance-section h2::before {{
    content: ''; width: 3px; height: 15px; border-radius: 2px; background: var(--accent);
  }}
  .compliance-note {{
    font-size: 0.8rem; line-height: 1.65; color: var(--text-secondary);
    margin-bottom: 1.25rem; max-width: 62rem;
  }}

  .fw-panel {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-sm);
    margin-bottom: 0.8rem;
    overflow: hidden;
  }}
  .fw-head {{
    display: flex; align-items: center; gap: 1rem;
    padding: 1rem 1.25rem; cursor: pointer; user-select: none; list-style: none;
  }}
  .fw-head::-webkit-details-marker {{ display: none; }}
  .fw-chevron {{
    color: var(--text-muted); font-size: 0.7rem; flex-shrink: 0;
    transition: transform 0.18s ease;
  }}
  .fw-panel[open] .fw-chevron {{ transform: rotate(90deg); }}
  .fw-id {{ display: flex; flex-direction: column; gap: 0.1rem; min-width: 12rem; }}
  .fw-name {{ font-size: 0.95rem; font-weight: 700; color: var(--text-primary); }}
  .fw-sub {{ font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); }}
  .fw-metrics {{ display: flex; gap: 1.5rem; margin-left: auto; flex-wrap: wrap; }}
  .fw-metric {{ font-size: 0.78rem; color: var(--text-secondary); white-space: nowrap; }}
  .fw-metric strong {{ font-family: var(--font-mono); font-size: 0.95rem; color: var(--text-primary); }}

  .fw-body {{ border-top: 1px solid var(--border); overflow-x: auto; }}
  .fw-table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  .fw-table thead th {{
    text-align: left; font-family: var(--font-mono); font-size: 0.68rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted);
    padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); background: var(--bg-secondary);
    white-space: nowrap;
  }}
  .fw-table th.num, .fw-table td.num {{ text-align: center; width: 3.4rem; font-variant-numeric: tabular-nums; }}
  .fw-table tbody td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  .fw-table tbody tr:last-child td {{ border-bottom: none; }}
  .fw-table tbody tr:hover {{ background: var(--bg-secondary); }}
  .fw-cid {{ font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); white-space: nowrap; }}
  .fw-ctrl-name {{ display: block; color: var(--text-primary); font-weight: 600; }}
  .fw-themes {{ display: block; font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem; }}
  .fw-table td.num {{ font-family: var(--font-mono); font-weight: 700; }}
  .fw-table td.num.zero {{ color: var(--border); font-weight: 400; }}
  .fw-table td.c-crit {{ color: var(--critical); }}
  .fw-table td.c-high {{ color: var(--high); }}
  .fw-table td.c-med {{ color: var(--medium); }}
  .fw-table td.c-low {{ color: var(--low); }}
  .fw-table td.fw-tot {{ color: var(--text-secondary); }}

  /* Footer */
  .footer {{
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    text-align: center;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-muted);
  }}

  /* Responsive */
  @media (max-width: 900px) {{
    .summary-grid {{ grid-template-columns: 1fr; }}
    .severity-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .cat-bar-row {{ grid-template-columns: 140px 1fr 40px; }}
  }}

  /* Print */
  @media print {{
    body {{ background: white; color: #111; }}
    .finding-body {{ display: block !important; }}
    .noise {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="noise"></div>
<div class="container">

  <div class="header">
    <div class="header-left">
      {left_brand_html}
      <div class="header-titles">
        <h1>{title_text}</h1>
        <div class="subtitle">Security Assessment Report</div>
      </div>
    </div>
    <div class="header-right">
      {logo_html}
      <div class="header-meta">
        <span>Scan: {html.escape(self.meta.get('scan_time', 'N/A')[:19])}</span>
        <span>Source: {html.escape(self.meta.get('data_directory', 'N/A'))}</span>
        <span>Modules: {html.escape(', '.join(self.meta.get('modules_run', [])))}</span>
      </div>
    </div>
  </div>

  <div class="copyright-banner">
    <strong>&copy; 2026 PhalanxCyber &mdash; Open-source cybersecurity platform.</strong> Built for defenders.<br>
    All tools are provided for lawful, authorized security testing and educational use only.
    Offensive/red-team tooling is benign-by-default and intended for environments you own or are authorized to test.
  </div>

  <!-- Summary Grid -->
  <div class="summary-grid">
    <div class="risk-card">
      <div class="risk-score-ring">
        <svg viewBox="0 0 140 140">
          <defs>
            <linearGradient id="riskgrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="{risk_color}"/>
              <stop offset="100%" stop-color="{risk_color}" stop-opacity="0.5"/>
            </linearGradient>
          </defs>
          <circle cx="70" cy="70" r="60" fill="none" stroke="#eef2f6" stroke-width="9"/>
          <circle cx="70" cy="70" r="60" fill="none" stroke="url(#riskgrad)" stroke-width="9"
            stroke-dasharray="{risk_score * 3.77} {377 - risk_score * 3.77}"
            stroke-linecap="round"/>
        </svg>
        <div class="score-text">
          <div class="score-number">{risk_score}</div>
          <div class="score-label">Risk Score</div>
        </div>
      </div>
      <div class="risk-level">{risk_label} Risk</div>
    </div>

    <div class="severity-grid">
      <div class="sev-card critical">
        <div class="sev-head"><span class="sev-dot"></span><span class="sev-label">Critical</span></div>
        <div class="sev-count">{crit}</div>
        <div class="sev-bar"><span style="width: {crit_pct}%"></span></div>
      </div>
      <div class="sev-card high">
        <div class="sev-head"><span class="sev-dot"></span><span class="sev-label">High</span></div>
        <div class="sev-count">{high}</div>
        <div class="sev-bar"><span style="width: {high_pct}%"></span></div>
      </div>
      <div class="sev-card medium">
        <div class="sev-head"><span class="sev-dot"></span><span class="sev-label">Medium</span></div>
        <div class="sev-count">{med}</div>
        <div class="sev-bar"><span style="width: {med_pct}%"></span></div>
      </div>
      <div class="sev-card low">
        <div class="sev-head"><span class="sev-dot"></span><span class="sev-label">Low</span></div>
        <div class="sev-count">{low}</div>
        <div class="sev-bar"><span style="width: {low_pct}%"></span></div>
      </div>
    </div>
  </div>

  <!-- Priority Tiers (P1-P4) -->
  {priority_html}

  <!-- Category Breakdown -->
  <div class="categories-section">
    <h2>Findings by Category</h2>
    <div class="cat-bars">
      {self._render_category_bars(by_category, total)}
    </div>
  </div>

  <!-- Compliance / Control-Framework Mapping -->
  {compliance_html}

  <!-- Filter Bar -->
  <div class="filter-bar">
    <label>Filter:</label>
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
    {prio_buttons_html}
    <label style="margin-left:0.5rem">Severity:</label>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({crit})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({high})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({med})</button>
    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({low})</button>
  </div>

  <!-- Findings -->
  <div class="findings-section">
    <h2>Detailed Findings ({total})</h2>
    {findings_html}
  </div>

  <div class="footer">
    SAP S/4HANA RISE Security Scanner &middot; Generated {html.escape(self.meta.get('scan_time', '')[:19])} &middot;
    For authorized security assessments only
  </div>
</div>

<script>
// Toggle finding details
document.querySelectorAll('.finding-header').forEach(el => {{
  el.addEventListener('click', () => {{
    el.parentElement.classList.toggle('open');
  }});
}});

// Filter by priority tier (P1-P4) or severity — tiers and severities are distinct
// tokens, so one function matches either the card's data-tier or data-severity.
function filterFindings(key) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    const show = (key === 'ALL' || card.dataset.tier === key || card.dataset.severity === key);
    card.style.display = show ? '' : 'none';
  }});
}}

// Expand all for print
window.addEventListener('beforeprint', () => {{
  document.querySelectorAll('.finding-card').forEach(c => c.classList.add('open'));
  document.querySelectorAll('details').forEach(d => d.open = true);
}});
</script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    def _prio_tags(self, pr) -> str:
        """Exploitability / exposure micro-tags for a PriorityResult."""
        tags = []
        if getattr(pr, "exploited", False):
            cve = getattr(pr, "cve", None)
            tags.append(f'<span class="p-tag exploited">Exploited{(" " + html.escape(str(cve))) if cve else ""}</span>')
        elif getattr(pr, "hotnews", False):
            tags.append('<span class="p-tag hotnews">HotNews</span>')
        if getattr(pr, "privileged", False):
            tags.append('<span class="p-tag priv">Privileged path</span>')
        if getattr(pr, "exposed", False):
            tags.append('<span class="p-tag exposed">Exposed</span>')
        return "".join(tags)

    def _render_priority_section(self, tier_counts) -> str:
        """P1-P4 tier summary cards + a 'top to fix first' queue (P1/P2 by score)."""
        if not self._prio_by_id or not self._tier_meta:
            return ""
        sub = ("Findings ranked by severity &times; real-world exploitability (SAP HotNews / "
               "actively-exploited notes) &times; exposure. Work the queue top-down: P1 first.")
        cards = []
        for t in ("P1", "P2", "P3", "P4"):
            m = self._tier_meta.get(t, {})
            cards.append(
                f'<div class="tier-card {t}"><div class="tier-top">'
                f'<span class="tier-id">{t}</span><span class="tier-n">{tier_counts.get(t, 0)}</span></div>'
                f'<div class="tier-lab">{html.escape(m.get("label", ""))}</div>'
                f'<div class="tier-win">{html.escape(m.get("window", ""))}</div></div>')

        ranked = []
        for f in self.findings:
            pr = self._tier_of(f)
            if pr is not None:
                ranked.append((f, pr))
        ranked.sort(key=lambda x: (self._TIER_RANK.get(x[1].tier, 9), -getattr(x[1], "score", 0)))
        top = [(f, pr) for f, pr in ranked if pr.tier in ("P1", "P2")][:10]
        top_html = ""
        if top:
            rows = []
            for i, (f, pr) in enumerate(top, 1):
                rows.append(
                    f'<div class="tr-row"><div class="tr-rank">{i}</div>'
                    f'<div class="tr-score"><span class="p-badge {pr.tier}">{pr.tier} &middot; '
                    f'{getattr(pr, "score", 0)}</span></div>'
                    f'<div class="tr-main"><span class="tr-name">{html.escape(f.get("title", ""))}</span> '
                    f'<span class="finding-id">{html.escape(f.get("check_id", ""))}</span>'
                    f'<div class="tr-why">{html.escape(getattr(pr, "rationale", "") or "")}</div></div>'
                    f'<div class="p-tags">{self._prio_tags(pr)}</div></div>')
            top_html = (f'<div class="tr-title">Top {len(top)} to fix first</div>'
                        f'<div class="toprisks">{"".join(rows)}</div>')
        return (f'<div class="prio-section"><h2>Risk-Prioritized Remediation Queue</h2>'
                f'<div class="prio-sub">{sub}</div>'
                f'<div class="prio-grid">{"".join(cards)}</div>{top_html}</div>')

    def _render_findings(self) -> str:
        """Render all findings as HTML cards, in fix-first (P1->P4) order."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        def _sortkey(f):
            pr = self._tier_of(f)
            trank = self._TIER_RANK.get(getattr(pr, "tier", None), 9) if pr is not None else 9
            score = -getattr(pr, "score", 0) if pr is not None else 0
            return (trank, order.get(f.get("severity"), 4), score)
        sorted_findings = sorted(self.findings, key=_sortkey)

        parts = []
        for f in sorted_findings:
            affected_html = ""
            if f.get("affected_items"):
                items = "".join(
                    f"<li>{html.escape(str(item))}</li>"
                    for item in f["affected_items"][:50]  # Cap at 50 for readability
                )
                overflow = ""
                if len(f["affected_items"]) > 50:
                    overflow = f"<li>... and {len(f['affected_items']) - 50} more</li>"
                affected_html = f"""
                <div class="finding-section">
                  <div class="finding-section-title">Affected Items ({f['affected_count']})</div>
                  <ul class="affected-list">{items}{overflow}</ul>
                </div>"""

            refs_html = ""
            if f.get("references"):
                ref_items = "".join(
                    f"<li>{html.escape(str(r))}</li>" for r in f["references"]
                )
                refs_html = f"""
                <div class="finding-section">
                  <div class="finding-section-title">References</div>
                  <ul class="ref-list">{ref_items}</ul>
                </div>"""

            risk_text, mitigation_text, _detailed = self.kb.detail_for(f)
            remediation_html = f"""
                <div class="finding-section">
                  <div class="finding-section-title">Remediation — Step by Step</div>
                  <div class="remediation-text">{html.escape(mitigation_text)}</div>
                </div>"""

            pr = self._tier_of(f)
            p_badge, data_tier = "", ""
            if pr is not None and getattr(pr, "tier", None):
                p_badge = (f'<span class="p-badge {pr.tier}" title="{html.escape(getattr(pr, "rationale", "") or "")}">'
                           f'{pr.tier} &middot; {getattr(pr, "score", 0)}</span>')
                data_tier = f' data-tier="{html.escape(pr.tier)}"'

            parts.append(f"""
    <div class="finding-card" data-severity="{html.escape(f['severity'])}" data-category="{html.escape(f['category'])}"{data_tier}>
      <div class="finding-header">
        <span class="sev-badge {html.escape(f['severity'])}">{html.escape(f['severity'])}</span>
        {p_badge}
        <span class="finding-title">{html.escape(f['title'])}</span>
        <span class="finding-id">{html.escape(f['check_id'])}</span>
        <span class="finding-chevron">&#9654;</span>
      </div>
      <div class="finding-body">
        <div class="finding-section">
          <div class="finding-section-title">Security Risk</div>
          <div class="risk-text">{html.escape(risk_text)}</div>
        </div>
        {affected_html}
        {remediation_html}
        {refs_html}
      </div>
    </div>""")

        return "\n".join(parts) if parts else '<p style="color: var(--text-muted); text-align: center; padding: 2rem;">No findings to display.</p>'

    def _render_category_bars(self, by_category: Dict[str, int], total: int) -> str:
        """Render horizontal bar chart for categories."""
        if not by_category or total == 0:
            return ""

        max_count = max(by_category.values())
        rows = []
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            pct = (count / max_count) * 100 if max_count > 0 else 0
            rows.append(f"""
      <div class="cat-bar-row">
        <div class="cat-bar-label">{html.escape(cat)}</div>
        <div class="cat-bar-track"><div class="cat-bar-fill" style="width: {pct}%"></div></div>
        <div class="cat-bar-count">{count}</div>
      </div>""")
        return "\n".join(rows)

    def _render_compliance(self) -> str:
        """Map findings onto control frameworks (ISO 27001 / NIST CSF / CIS /
        TISAX / SOC 2 / GDPR) and render a collapsible gap-mapping section."""
        if not self.findings:
            return ""
        frameworks = ComplianceMapper(self.findings).assess()
        frameworks = [f for f in frameworks if f["controls"]]
        if not frameworks:
            return ""

        def sev_cell(n, cls):
            return (f'<td class="num {cls}">{n}</td>' if n
                    else '<td class="num zero">&middot;</td>')

        panels = []
        for i, fw in enumerate(frameworks):
            rows = []
            for c in fw["controls"]:
                themes = " &middot; ".join(html.escape(t) for t in c["themes"])
                rows.append(
                    "<tr>"
                    f'<td class="fw-cid">{html.escape(c["id"])}</td>'
                    f'<td class="fw-ctrl"><span class="fw-ctrl-name">{html.escape(c["name"])}</span>'
                    f'<span class="fw-themes">{themes}</span></td>'
                    + sev_cell(c["crit"], "c-crit") + sev_cell(c["high"], "c-high")
                    + sev_cell(c["med"], "c-med") + sev_cell(c["low"], "c-low")
                    + f'<td class="num fw-tot">{c["total"]}</td>'
                    "</tr>"
                )
            open_attr = " open" if i == 0 else ""
            panels.append(f"""
    <details class="fw-panel"{open_attr}>
      <summary class="fw-head">
        <span class="fw-chevron">&#9656;</span>
        <span class="fw-id"><span class="fw-name">{html.escape(fw['name'])}</span><span class="fw-sub">{html.escape(fw['subtitle'])}</span></span>
        <span class="fw-metrics">
          <span class="fw-metric"><strong>{fw['controls_flagged']}</strong>/{fw['total_controls']} control areas flagged</span>
          <span class="fw-metric"><strong>{fw['mapped_findings']}</strong> findings mapped</span>
        </span>
      </summary>
      <div class="fw-body">
        <table class="fw-table">
          <thead><tr>
            <th>Control</th><th>Area &amp; mapped themes</th>
            <th class="num">Crit</th><th class="num">High</th><th class="num">Med</th><th class="num">Low</th><th class="num">Total</th>
          </tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </details>""")

        return f"""<div class="compliance-section">
    <h2>Compliance &amp; Control-Framework Mapping</h2>
    <p class="compliance-note">Each detected finding is attributed to the control areas it is evidence
    against, so results can be navigated by standard. The counts below reflect controls with
    <em>open findings</em> in the assessed configuration &mdash; this is a gap-mapping for audit
    navigation and remediation scoping, <strong>not a certification, attestation, or statement of full
    compliance</strong>. Absence of findings for a control is not by itself evidence of conformance.</p>
    {''.join(panels)}
  </div>"""
