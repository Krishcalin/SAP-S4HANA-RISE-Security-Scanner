"""
HTML Report Generator
======================
Generates a professional, interactive HTML security dashboard
with findings summary, severity breakdown, and detailed findings.
"""

import json
import html
from typing import Dict, List, Any


class ReportGenerator:

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any]):
        self.findings = findings
        self.meta = meta

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
        category_chart_data = json.dumps([
            {"name": k, "count": v} for k, v in sorted(by_category.items(), key=lambda x: -x[1])
        ])

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP S/4HANA RISE — Security Assessment Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

  :root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --bg-card-hover: #1f2b3d;
    --border: #2a3548;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent: #38bdf8;
    --accent-dim: rgba(56, 189, 248, 0.1);
    --critical: #ef4444;
    --critical-bg: rgba(239, 68, 68, 0.08);
    --high: #f97316;
    --high-bg: rgba(249, 115, 22, 0.08);
    --medium: #eab308;
    --medium-bg: rgba(234, 179, 8, 0.08);
    --low: #22c55e;
    --low-bg: rgba(34, 197, 94, 0.08);
    --info-c: #38bdf8;
    --info-bg: rgba(56, 189, 248, 0.08);
    --font-sans: 'DM Sans', -apple-system, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
  }}

  .noise {{
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
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
    align-items: flex-start;
    margin-bottom: 2.5rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }}

  .header-left h1 {{
    font-family: var(--font-mono);
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
  }}

  .header-left .subtitle {{
    font-size: 0.875rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  .header-right {{
    text-align: right;
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  .header-right span {{
    display: block;
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
    border-radius: 12px;
    padding: 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
  }}

  .risk-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: {risk_color};
  }}

  .risk-score-ring {{
    width: 140px;
    height: 140px;
    position: relative;
    margin-bottom: 1rem;
  }}

  .risk-score-ring svg {{
    transform: rotate(-90deg);
    width: 140px;
    height: 140px;
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
    font-size: 2.5rem;
    font-weight: 700;
    color: {risk_color};
    line-height: 1;
  }}

  .risk-score-ring .score-label {{
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }}

  .risk-level {{
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: {risk_color};
    text-transform: uppercase;
    letter-spacing: 0.05em;
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
    border-radius: 10px;
    padding: 1.25rem;
    position: relative;
    overflow: hidden;
    transition: background 0.2s;
  }}

  .sev-card:hover {{
    background: var(--bg-card-hover);
  }}

  .sev-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }}

  .sev-card.critical::before {{ background: var(--critical); }}
  .sev-card.high::before {{ background: var(--high); }}
  .sev-card.medium::before {{ background: var(--medium); }}
  .sev-card.low::before {{ background: var(--low); }}

  .sev-card .sev-count {{
    font-family: var(--font-mono);
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
  }}

  .sev-card.critical .sev-count {{ color: var(--critical); }}
  .sev-card.high .sev-count {{ color: var(--high); }}
  .sev-card.medium .sev-count {{ color: var(--medium); }}
  .sev-card.low .sev-count {{ color: var(--low); }}

  .sev-card .sev-label {{
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.25rem;
  }}

  /* Category breakdown bar */
  .categories-section {{
    margin-bottom: 2.5rem;
  }}

  .categories-section h2 {{
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
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
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
  }}

  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 0.75rem;
    overflow: hidden;
    transition: background 0.2s;
  }}

  .finding-card:hover {{
    background: var(--bg-card-hover);
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
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.4rem;
  }}

  .finding-section p {{
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.7;
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
    border-bottom: 1px solid rgba(42, 53, 72, 0.5);
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
    background: rgba(34, 197, 94, 0.05);
    border-left: 3px solid var(--low);
    padding: 0.75rem 1rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.7;
  }}

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
      <h1>&#x1f6e1; SAP S/4HANA RISE</h1>
      <div class="subtitle">Security Assessment Report</div>
    </div>
    <div class="header-right">
      <span>Scan: {html.escape(self.meta.get('scan_time', 'N/A')[:19])}</span>
      <span>Source: {html.escape(self.meta.get('data_directory', 'N/A'))}</span>
      <span>Modules: {html.escape(', '.join(self.meta.get('modules_run', [])))}</span>
    </div>
  </div>

  <!-- Summary Grid -->
  <div class="summary-grid">
    <div class="risk-card">
      <div class="risk-score-ring">
        <svg viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="60" fill="none" stroke="#1e293b" stroke-width="10"/>
          <circle cx="70" cy="70" r="60" fill="none" stroke="{risk_color}" stroke-width="10"
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
        <div class="sev-count">{crit}</div>
        <div class="sev-label">Critical</div>
      </div>
      <div class="sev-card high">
        <div class="sev-count">{high}</div>
        <div class="sev-label">High</div>
      </div>
      <div class="sev-card medium">
        <div class="sev-count">{med}</div>
        <div class="sev-label">Medium</div>
      </div>
      <div class="sev-card low">
        <div class="sev-count">{low}</div>
        <div class="sev-label">Low</div>
      </div>
    </div>
  </div>

  <!-- Category Breakdown -->
  <div class="categories-section">
    <h2>Findings by Category</h2>
    <div class="cat-bars">
      {self._render_category_bars(by_category, total)}
    </div>
  </div>

  <!-- Filter Bar -->
  <div class="filter-bar">
    <label>Filter:</label>
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
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

// Severity filter
function filterFindings(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    if (sev === 'ALL' || card.dataset.severity === sev) {{
      card.style.display = '';
    }} else {{
      card.style.display = 'none';
    }}
  }});
}}

// Expand all for print
window.addEventListener('beforeprint', () => {{
  document.querySelectorAll('.finding-card').forEach(c => c.classList.add('open'));
}});
</script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    def _render_findings(self) -> str:
        """Render all findings as HTML cards."""
        # Sort by severity
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda f: order.get(f["severity"], 4))

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
                    f"<li>{html.escape(r)}</li>" for r in f["references"]
                )
                refs_html = f"""
                <div class="finding-section">
                  <div class="finding-section-title">References</div>
                  <ul class="ref-list">{ref_items}</ul>
                </div>"""

            remediation_html = ""
            if f.get("remediation"):
                remediation_html = f"""
                <div class="finding-section">
                  <div class="finding-section-title">Remediation</div>
                  <div class="remediation-text">{html.escape(f['remediation'])}</div>
                </div>"""

            parts.append(f"""
    <div class="finding-card" data-severity="{html.escape(f['severity'])}" data-category="{html.escape(f['category'])}">
      <div class="finding-header">
        <span class="sev-badge {html.escape(f['severity'])}">{html.escape(f['severity'])}</span>
        <span class="finding-title">{html.escape(f['title'])}</span>
        <span class="finding-id">{html.escape(f['check_id'])}</span>
        <span class="finding-chevron">&#9654;</span>
      </div>
      <div class="finding-body">
        <div class="finding-section">
          <div class="finding-section-title">Description</div>
          <p>{html.escape(f['description'])}</p>
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
