# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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
from modules import posture_score


#: Posture band -> colour. The bands themselves are derived in
#: modules/posture_score.py from the severity weights, so the three report
#: formats cannot disagree about what a number means.
_RISK_COLOUR = {"Critical": "#dc2626", "High": "#ea580c",
                "Medium": "#d97706", "Low": "#16a34a"}


class ReportGenerator:

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 kb: Optional[FindingKB] = None, priorities: Optional[List[Any]] = None,
                 fair: Optional[Dict[str, Any]] = None,
                 coverage: Optional[Dict[str, Any]] = None,
                 full_findings: Optional[List[Dict[str, Any]]] = None):
        self.findings = findings
        #: THE CORPUS AS SCANNED, before any display filter narrowed it.
        #:
        #: `--severity HIGH` is a DISPLAY option: it decides which findings are
        #: listed, not which were found. Anything that makes a claim ABOUT THE
        #: ESTATE — the framework roll-ups, the control-function map, the domain
        #: view — must read this instead of `findings`, or the filter silently
        #: converts "we found MEDIUM issues here" into the green "no findings"
        #: chip, and nothing on the page says a filter was applied.
        #:
        #: sap_scanner.py already snapshots the unfiltered set for exactly this
        #: reason, with the comment that the severity filter "must not silently
        #: change the dollar figure". The money was protected; the framework
        #: sections were not.
        #:
        #: Defaults to `findings` so an existing caller keeps working — and gets
        #: the filtered set, which is the status quo, not a silent new claim.
        self.full_findings = full_findings if full_findings is not None else findings
        self.meta = meta
        self.kb = kb if kb is not None else FindingKB()
        #: What the scan could NOT look at. None means the manifest could
        #: not be built, which the report says rather than passing over.
        self.coverage = coverage
        # Optional FAIR cyber-risk-quantification summary (from fair_adapter.run
        # -> summary). None unless --crq ran and the CRQ engine was located.
        self.fair = fair
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
        """MonitorRisk tool-vendor logo (top-right)."""
        return ReportGenerator._asset_data_uri("monitorrisk-logo.png")

    def _evidence_manifest_html(self) -> str:
        """The evidence manifest: which files, hashed, produced this report.

        Empty string when the meta carries no manifest (an older caller), so
        existing callers keep rendering unchanged."""
        manifest = self.meta.get("evidence_manifest") or []
        if not manifest:
            return ""
        body = "".join(
            "<tr>"
            f"<td><code>{html.escape(str(e.get('file', '')))}</code></td>"
            "<td style='font-family:monospace;font-size:11px;word-break:break-all'>"
            f"{html.escape(str(e.get('sha256', '')))}</td>"
            f"<td style='text-align:right'>{e.get('bytes', '')}</td>"
            f"<td style='text-align:right'>{'' if e.get('rows') is None else e.get('rows')}</td>"
            f"<td>{html.escape(str(e.get('modified', '')))}</td>"
            "</tr>"
            for e in manifest)
        return f"""
  <details class="evidence-manifest" style="margin:18px 0">
    <summary style="cursor:pointer;font-weight:600">Evidence manifest — {len(manifest)} supplied export(s), SHA-256 hashed at scan time</summary>
    <p style="font-size:13px;max-width:80ch">Every file this scan read. A challenged finding is re-checkable months
    later: the same files with the same hashes produce the same findings. A
    hash that no longer matches means the evidence changed after the scan —
    which is an answer, not a failure.</p>
    <div style="overflow-x:auto"><table>
      <tr><th>File</th><th>SHA-256</th><th>Bytes</th><th>Rows</th><th>Modified</th></tr>
      {body}
    </table></div>
  </details>"""

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

        # THE POSTURE SCORE DESCRIBES THE ESTATE, so it counts the estate.
        #
        # It sits under the words "Risk Score" and a one-word posture, which is a
        # claim about the systems and not about this page's selection. Computed
        # over the filtered list it moved from 100/100 Critical to 50/100 High on
        # `--severity CRITICAL` with no data change whatsoever — a display option
        # improving the customer's security posture — and it sat beside framework
        # sections that had just been corrected to describe all of it.
        #
        # The severity CARDS keep counting the filtered list. They are a
        # breakdown of what is listed below them, they are labelled as such, and
        # the notice above the grid reconciles the two.
        # AND IT IS A DENSITY, NOT A TOTAL. `min(100, crit*25 + high*10 + ...)`
        # reached 3693 on the reference estate, so it pinned at 100 and could not
        # move while a customer remediated; and it FELL when they supplied fewer
        # exports, because fewer modules ran and so found less. Both are fixed by
        # dividing by what was assessed — modules/posture_score.py, where the
        # bands are derived from the same severity weights, so the anchor printed
        # under the ring is arithmetic rather than an opinion.
        scored = posture_score.score_with_scope(self.full_findings, self.coverage)
        if scored is None:
            # No manifest, so nothing to divide by. A number here would be the
            # same error the rest of this report exists to avoid.
            risk_score, risk_caption = 0, "Not scored"
            risk_color, risk_num = "#64748b", "&mdash;"
            # TWO DIFFERENT ABSENCES, AND THEY ARE NOT THE SAME SENTENCE. A
            # missing manifest means we cannot say what ran; a manifest in which
            # no module ran means we can, and the answer is nothing. Printing
            # "no coverage manifest" over a report that contains a full coverage
            # section reads as a bug and teaches the reader to discount the page.
            risk_note = ("No coverage manifest, so how many checks ran is unknown "
                         "and there is nothing to score against. The severity "
                         "counts beside this are still exact."
                         if self.coverage is None else
                         "No module completed a check in this scan, so there is "
                         "nothing to score against. See the coverage section for "
                         "which modules ran and why. The severity counts beside "
                         "this are still exact.")
        else:
            risk_score, risk_label, assessed = scored
            risk_caption = html.escape(risk_label) + " Risk"
            risk_color = _RISK_COLOUR[risk_label]
            risk_num = str(risk_score)
            # The anchor AND the condition. The score describes the assessed
            # portion, and a conditional number printed without its condition is
            # how two reports over different coverage get compared as equals.
            risk_note = html.escape(
                posture_score.ANCHOR + " " + posture_score.scope_note(assessed))

        findings_html = self._render_findings()
        filter_html = self._render_filter_notice()
        coverage_html = self._render_coverage()
        compliance_html = self._render_compliance()
        fair_html = self._render_fair()
        csf_html = self._render_csf()
        fair_cam_html = self._render_fair_cam()
        category_chart_data = json.dumps([
            {"name": k, "count": v} for k, v in sorted(by_category.items(), key=lambda x: -x[1])
        ])

        logo_uri = self._logo_data_uri()
        logo_html = (
            f'<img class="brand-logo" src="{logo_uri}" alt="MonitorRisk" />'
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

  /* MonitorRisk brand logo — top right, on the white page.
     The artwork carries its OWN blue field again (the wordmark is half navy and
     half white, and white needs a ground), so the corner radius is back: it makes
     the rectangle read as a deliberate brand panel rather than an image that
     failed to key. No shadow — the field is flat and light, and a shadow under it
     on white reads as a UI control rather than a logo. */
  .brand-logo {{
    width: 230px;
    max-width: 45vw;
    height: auto;
    border-radius: 6px;
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

  .risk-note {{
    font-size: 0.66rem;
    line-height: 1.45;
    color: var(--text-muted);
    text-align: center;
    margin-top: 0.65rem;
    max-width: 15rem;
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
        <span>Severity filter: {html.escape(str(self.meta.get('severity_filter', 'ALL')))}</span>
      </div>
    </div>
  </div>

  <div class="copyright-banner">
    <strong>&copy; 2026 MonitorRisk &mdash; SAP threat, vulnerability &amp; GRC posture.</strong> Built for defenders.<br>
    All tools are provided for lawful, authorized security testing and educational use only.
    Offensive/red-team tooling is benign-by-default and intended for environments you own or are authorized to test.
  </div>

  <!-- WHAT THE SCAN COULD NOT SEE, BEFORE ANY NUMBER IT PRODUCED.
       Its own docstring has said "rendered FIRST, before the findings, because a
       reader who sees the finding count before the coverage will anchor on the
       wrong number" since it was written — and it sat below the risk ring, four
       severity cards, the P1-P4 queue and the category bars, which is every
       number a reader anchors on. -->
  {coverage_html}
  {self._evidence_manifest_html()}
  {filter_html}

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
          <div class="score-number">{risk_num}</div>
          <div class="score-label">Risk Score</div>
        </div>
      </div>
      <div class="risk-level">{risk_caption}</div>
      <div class="risk-note">{risk_note}</div>
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
    {csf_html}
    {fair_cam_html}
    {compliance_html}

  <!-- Financial Risk Exposure (FAIR cyber-risk quantification) -->
  {fair_html}

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
    <!-- THE REPORT IS THE ARTEFACT THAT LEAVES THE BUILDING. It is emailed to
         auditors, attached to tickets and forwarded to SAP, so it is the one
         place a tool-ownership notice reliably reaches somebody who has never
         seen the repository. Two distinct claims, kept distinct:
           1. the TOOL is proprietary — that is about this software;
           2. the CONTENTS describe the customer's estate — that is about their
              data, and it is their confidentiality, not mine, so it is worded as
              a caution rather than as a claim of ownership over their findings. -->
    MonitorRisk &mdash; SAP S/4HANA RISE Security Scanner &middot;
    Generated {html.escape(self.meta.get('scan_time', '')[:19])} &middot;
    For authorized security assessments only<br>
    <span style="opacity:.75">
      &copy; 2026 Krishnendu De. All rights reserved. MonitorRisk is proprietary
      software, licensed &mdash; not sold &mdash; and this report is generated
      output, not a grant of any licence to the tool.
      This report describes the security posture of the assessed system and
      should be handled accordingly.
    </span>
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

    # ── FAIR cyber-risk quantification ────────────────────────────────────
    @staticmethod
    def _fmt_money(v: float) -> str:
        v = float(v or 0)
        sign = "-" if v < 0 else ""
        a = abs(v)
        # Thresholds are rounding-aware: promote a tier when the mantissa would
        # round up to 1000 in that tier's format (else e.g. $999,999 -> "$1000K"
        # instead of "$1.0M", and $999.99M -> "$1000.0M" instead of "$1.00B").
        if a >= 999.95e6:            # .2f rounds to 1000.00 at >= 999.95e6
            return f"{sign}${a / 1e9:.2f}B"
        if a >= 999.5e3:             # .1f rounds to 1000.0 at >= 999.5e3
            return f"{sign}${a / 1e6:.1f}M"
        if a >= 999.5:               # .0f rounds to 1000 at >= 999.5
            return f"{sign}${a / 1e3:.0f}K"
        return f"{sign}${a:.0f}"

    def _svg_lec(self, points) -> str:
        """Render the loss-exceedance curve as an SVG.

        TWO SHAPES ARRIVE HERE, AND ASSUMING ONE OF THEM CRASHED THE REPORT.
        The engine emits `[{"probability": p, "loss": x}, ...]`
        (`crq_engine._calc_loss_exceedance`); this renderer was written against
        `[(loss, probability), ...]`. Unpacking `for t, p in points` over dicts
        iterates their KEYS, so the first point raised
        `ValueError: could not convert string to float: 'probability'` — after the
        scan, after the Monte-Carlo run, in the last step before the file is
        written. `--crq` therefore produced a `.crq.json` and NO HTML report at all.

        It stayed hidden because bundling `crq_engine.py` is what reached this
        branch: while the engine lived only in a sibling repo, `locate_engine()`
        usually failed, `fair` came back without a curve, and the renderer was
        never asked to draw one. Fixing the "no number at all" defect switched on
        the path that carried this one.

        Accepting both shapes rather than converting at the boundary is deliberate:
        the adapter passes the engine's payload through untouched, and a renderer
        that hard-fails the whole report over a container type is the wrong
        trade — a missing chart is a cosmetic loss, a missing report is total.
        """
        pts = []
        for point in (points or []):
            if isinstance(point, dict):
                t, p = point.get("loss"), point.get("probability")
            else:
                try:
                    t, p = point
                except (TypeError, ValueError):
                    continue
            if t is None or p is None:
                continue
            try:
                pts.append((float(t), float(p)))
            except (TypeError, ValueError):
                continue
        pts = [(t, p) for t, p in pts if t >= 0]
        if len(pts) < 2:
            return ""
        max_t = max(t for t, _ in pts) or 1.0
        x0, x1, y0, y1 = 56, 664, 210, 22
        def X(t):
            return x0 + (t / max_t) * (x1 - x0)
        def Y(p):
            return y0 - max(0.0, min(1.0, p)) * (y0 - y1)
        line = " ".join(f"{X(t):.1f},{Y(p):.1f}" for t, p in pts)
        area = f"{x0:.1f},{y0:.1f} " + line + f" {X(pts[-1][0]):.1f},{y0:.1f}"
        # y grid + labels (probability)
        grid = []
        for gp in (0.0, 0.25, 0.5, 0.75, 1.0):
            y = Y(gp)
            grid.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" class="lec-grid"/>')
            grid.append(f'<text x="{x0 - 8}" y="{y + 3:.1f}" class="lec-ytick">{int(gp * 100)}%</text>')
        # x labels (loss $)
        xlab = []
        for gx in (0.0, 0.5, 1.0):
            t = max_t * gx
            xlab.append(f'<text x="{X(t):.1f}" y="{y0 + 20}" class="lec-xtick">{self._fmt_money(t)}</text>')
        return f"""<svg viewBox="0 0 700 240" class="lec-svg" role="img" aria-label="Loss exceedance curve">
      {''.join(grid)}
      <polygon points="{area}" class="lec-area"/>
      <polyline points="{line}" class="lec-line"/>
      {''.join(xlab)}
      <text x="{(x0 + x1) / 2:.0f}" y="238" class="lec-axis">Annual loss ($)</text>
    </svg>"""

    def _render_fair(self) -> str:
        """Financial risk exposure (FAIR): annualized loss expectancy, loss
        exceedance curve, per-scenario breakdown, and remediation upside."""
        fair = self.fair
        if not fair or not fair.get("portfolio"):
            return ""

        # WITHOUT THE CUSTOMER'S FIGURES, NO CURRENCY TOTAL IS PRESENTED AS THEIRS.
        #
        # The scenario catalogue is calibrated, by its own _meta, to an illustrative
        # $1bn manufacturer. Before this, a report with no supplied figures printed
        # that company's losses under the customer's name, to the cent, with nothing
        # on the page saying so — and this report is the artefact that goes to an
        # auditor or a board.
        #
        # A caveat under the number was considered and rejected. Every caveat this
        # product has written has been outlived by the figure above it; a number in
        # a board pack is screenshotted without its footnote. So the headline is
        # ABSENT rather than annotated, and the section explains what would make it
        # appear. An absent number cannot be quoted.
        if not (fair.get("loss_model") or {}).get("applied"):
            return self._render_fair_unpriced(fair)

        pf = fair["portfolio"]
        org = fair.get("organization", {})
        sims = fair.get("simulations", 0)
        reducible = fair.get("reducible_ale_p90", 0)
        m = self._fmt_money
        rows = []
        for sc in sorted(fair.get("scenarios", []), key=lambda s: -(s.get("ale_p90") or 0)):
            sev = str(sc.get("severity", "LOW"))
            fc = sc.get("finding_count")
            fc_txt = f'{fc}' if fc is not None else "—"
            flags = []
            # FIRST IN THE LIST, because it qualifies every other number on the
            # row. A scenario nothing was routed to is priced at the hardened
            # band by default, so its figure is a floor rather than a
            # measurement — and it contributes nothing to the reducible total.
            if sc.get("unexamined"):
                flags.append("nothing routed - priced at the hardened band")
            if sc.get("exposed"):
                flags.append("exposed")
            if sc.get("exploited"):
                flags.append("exploited")
            flag_txt = (" · " + ", ".join(flags)) if flags else ""
            rows.append(f"""
        <tr>
          <td>{html.escape(str(sc.get('name', sc.get('id', ''))))}<span class="fair-scn-tc">{html.escape(str(sc.get('threat_community','')).replace('_',' '))}{flag_txt}</span></td>
          <td class="fair-num">{fc_txt}</td>
          <td class="fair-num">{m(sc.get('mean_ale'))}</td>
          <td class="fair-num">{m(sc.get('ale_p90'))}</td>
          <td><span class="fair-sev fair-sev-{sev.lower()}">{html.escape(sev)}</span></td>
        </tr>""")
        table_rows = "".join(rows)
        lec = self._svg_lec(pf.get("loss_exceedance"))
        rev = org.get("revenue")
        rev_txt = f" &middot; revenue {m(rev)}" if rev else ""
        ind = html.escape(str(org.get("industry", "")).replace("_", " "))
        # Disclose any findings that could not be attributed to a specific loss
        # scenario (conservatively folded into the privileged-access scenario).
        unrouted = int(fair.get("unrouted", 0) or 0)
        unrouted_html = (
            f"""<p class="fair-note" style="color:var(--high); font-style:normal;">&#9888;
      {unrouted} finding(s) could not be mapped to a specific SAP loss scenario and were conservatively folded into the
      privileged-access scenario (SAP-PRIV-03), which may overstate that scenario&rsquo;s exposure. Add explicit routing in
      <code>data/fair_scenarios.json</code> to attribute them correctly.</p>""" if unrouted else "")
        # Disclose findings held OUT of the calibration for want of evidence.
        # Calibration is band selection from the WORST finding routed to a
        # scenario, so a single unevidenced CRITICAL would move a figure a board
        # reads on the strength of a regex match. They are excluded from the
        # pricing and from nothing else.
        unevidenced = int(fair.get("unevidenced", 0) or 0)
        unevidenced_html = (
            f"""<p class="fair-note" style="font-style:normal;">&#9432;
      {unevidenced} code finding(s) rest on a statement pattern with no data-flow evidence, and did <strong>not</strong>
      calibrate these figures. They are still reported, ranked and tracked to closure &mdash; they are simply not allowed to
      set the price of a loss scenario on their own. Findings where the taint analysis ran, and everything imported from
      SAP&rsquo;s own ATC, are priced normally.</p>""" if unevidenced else "")
        return f"""<div class="fair-section">
    <style>
      .fair-section {{ margin: 2.5rem 0; }}
      .fair-section h2 {{ display:flex; align-items:baseline; gap:.6rem; }}
      .fair-eyebrow {{ font-size:.72rem; letter-spacing:.12em; text-transform:uppercase; color:var(--accent); font-weight:700; }}
      .fair-sub {{ color:var(--text-muted); font-size:.86rem; margin:.2rem 0 1.1rem; }}
      .fair-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1rem; margin-bottom:1.3rem; }}
      .fair-card {{ background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-sm); padding:1.1rem 1.2rem; box-shadow:var(--shadow-sm); }}
      .fair-card .lbl {{ font-size:.74rem; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); font-weight:600; }}
      .fair-card .big {{ font-size:1.85rem; font-weight:750; margin-top:.25rem; letter-spacing:-.02em; font-variant-numeric:tabular-nums; }}
      .fair-card .cap {{ font-size:.78rem; color:var(--text-muted); margin-top:.15rem; }}
      .fair-card.accent {{ border-color:var(--accent); background:var(--accent-dim); }}
      .fair-card.accent .big {{ color:var(--accent); }}
      .fair-grid {{ display:grid; grid-template-columns:1.3fr 1fr; gap:1.2rem; align-items:start; }}
      @media (max-width:760px) {{ .fair-grid {{ grid-template-columns:1fr; }} }}
      .lec-box, .fair-tbl-box {{ background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-sm); padding:1rem 1.1rem; box-shadow:var(--shadow-sm); }}
      .lec-box h3, .fair-tbl-box h3 {{ font-size:.9rem; margin:0 0 .5rem; }}
      .lec-svg {{ width:100%; height:auto; }}
      .lec-grid {{ stroke:var(--border); stroke-width:1; }}
      .lec-area {{ fill:var(--accent); opacity:.12; }}
      .lec-line {{ fill:none; stroke:var(--accent); stroke-width:2.5; stroke-linejoin:round; }}
      .lec-ytick, .lec-xtick {{ fill:var(--text-muted); font-size:11px; font-family:var(--font-mono); }}
      .lec-ytick {{ text-anchor:end; }} .lec-xtick {{ text-anchor:middle; }}
      .lec-axis {{ fill:var(--text-muted); font-size:11px; text-anchor:middle; }}
      .lec-cap {{ font-size:.78rem; color:var(--text-muted); margin-top:.4rem; }}
      table.fair-tbl {{ width:100%; border-collapse:collapse; font-size:.82rem; }}
      table.fair-tbl th {{ text-align:left; font-size:.68rem; text-transform:uppercase; letter-spacing:.05em; color:var(--text-muted); padding:.4rem .5rem; border-bottom:1px solid var(--border); }}
      table.fair-tbl td {{ padding:.5rem .5rem; border-bottom:1px solid var(--border); vertical-align:top; }}
      table.fair-tbl tr:last-child td {{ border-bottom:none; }}
      .fair-num {{ text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }}
      .fair-scn-tc {{ display:block; font-size:.72rem; color:var(--text-muted); }}
      .fair-sev {{ font-size:.68rem; font-weight:700; padding:.1rem .45rem; border-radius:5px; }}
      .fair-sev-critical {{ color:var(--critical); background:var(--critical-bg); }}
      .fair-sev-high {{ color:var(--high); background:var(--high-bg); }}
      .fair-sev-medium {{ color:var(--medium); background:var(--medium-bg); }}
      .fair-sev-low {{ color:var(--low); background:var(--low-bg); }}
      .fair-note {{ font-size:.76rem; color:var(--text-muted); margin-top:1rem; font-style:italic; line-height:1.5; }}
    </style>
    <h2><span class="fair-eyebrow">Cyber Risk Quantification</span> Financial Risk Exposure &middot; FAIR</h2>
    <div class="fair-sub">Annualized loss exposure from a FAIR Monte Carlo simulation ({sims:,} iterations/scenario) &mdash;
      {html.escape(str(org.get('name','')))}{rev_txt}{(' &middot; ' + ind) if ind else ''}. Modelled estimate, not a measurement.</div>
    <div class="fair-cards">
      <div class="fair-card">
        <div class="lbl">Expected annual loss (mean ALE)</div>
        <div class="big">{m(pf.get('mean_ale'))}</div>
        <div class="cap">across {len(fair.get('scenarios', []))} SAP loss scenarios</div>
      </div>
      <div class="fair-card">
        <div class="lbl">1-in-10 bad year (ALE P90)</div>
        <div class="big">{m(pf.get('ale_p90'))}</div>
        <div class="cap">median (P50) {m(pf.get('ale_p50'))}</div>
      </div>
      <div class="fair-card accent">
        <div class="lbl">Reducible by remediation</div>
        <div class="big">{m(reducible)}</div>
        <div class="cap">how far the 1-in-10 loss (P90) drops toward a fully-hardened posture</div>
      </div>
    </div>
    <div class="fair-grid">
      <div class="lec-box">
        <h3>Loss exceedance curve</h3>
        {lec if lec else '<p class="lec-cap">Curve unavailable.</p>'}
        <div class="lec-cap">Read as: the probability (y) that annual loss exceeds a given amount (x). The steeper it drops, the more contained the risk.</div>
      </div>
      <div class="fair-tbl-box">
        <h3>By loss scenario</h3>
        <table class="fair-tbl">
          <thead><tr><th>Scenario</th><th class="fair-num">Findings</th><th class="fair-num">Mean ALE</th><th class="fair-num">ALE P90</th><th>Sev</th></tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
    </div>
    <p class="fair-note">FAIR (Factor Analysis of Information Risk): a finding is not a risk &mdash; findings are evidence that shifts the frequency
      and magnitude factors of scoped SAP loss scenarios. Loss magnitudes are modelled estimates from public benchmarks (IBM, Verizon DBIR,
      ACFE, Sophos, GDPR enforcement) priced from the figures you supplied. The industry shown is a label and scales nothing. Validate against your own loss data before treating any figure as
      your organisation's actual risk. Scenario input exported alongside this report as <code>*.crq.json</code>.</p>
    {unrouted_html}
    {unevidenced_html}
  </div>"""

    def _render_fair_unpriced(self, fair) -> str:
        """The FAIR section when nobody has priced the business.

        Reports what the model DID establish — which scenarios apply and how many
        findings routed to each — and refuses to turn any of it into this
        organisation's money.
        """
        # THE EXCLUSION DISCLOSURES BELONG HERE TOO.
        #
        # They are statements about FINDINGS — how many were held out of
        # calibration for want of evidence, and how many had no scenario route —
        # not about money. Routing the unpriced case past them dropped a
        # disclosure the priced case makes, which a test caught: withholding a
        # currency figure must not withhold an admission about the analysis.
        unrouted = int(fair.get("unrouted") or 0)
        unevidenced = int(fair.get("unevidenced") or 0)
        disclosures = ""
        if unrouted:
            disclosures += (
                '<p class="fair-note" style="font-style:normal;">&#9432; '
                + str(unrouted) + " finding(s) had no explicit scenario route and were "
                "folded into the privileged-access scenario, which may overstate it.</p>")
        if unevidenced:
            disclosures += (
                '<p class="fair-note" style="font-style:normal;">&#9432; '
                + str(unevidenced) + " code finding(s) rest on a statement pattern with "
                "no data-flow evidence and did <strong>not</strong> calibrate this "
                "analysis. They are still reported, ranked and tracked to closure.</p>")

        scenarios = fair.get("scenarios", []) or []
        rows_html = "".join(
            "<tr><td>" + html.escape(str(sc.get("name", sc.get("id", "")))) + "</td>"
            "<td class='num'>"
            + (str(sc.get("finding_count")) if sc.get("finding_count") is not None else "&mdash;")
            + "</td><td>" + html.escape(str(sc.get("worst_severity", ""))) + "</td></tr>"
            for sc in scenarios)
        return f"""
    <h2><span class="fair-eyebrow">Cyber Risk Quantification</span> Financial Risk Exposure &middot; FAIR</h2>
    <div style="margin:.6rem 0 1rem;padding:.8rem 1rem;border-left:4px solid var(--medium);background:var(--medium-bg);border-radius:6px;">
      <strong>No currency figure is presented for this organisation.</strong>
      The FAIR model ran and the scenarios below were matched to your findings, but nobody has told it what an
      hour of SAP downtime costs you, how many personal records you hold, or what a payment run is worth. The
      shipped scenario catalogue is calibrated to an illustrative $1&nbsp;billion manufacturer, and printing that
      company&rsquo;s losses under your name would be a fabrication rather than an estimate.
      <br><br>
      Supply <code>crq_parameters.json</code> alongside your export, or pass <code>--crq-inputs</code>, and this
      section will price the scenarios from your own figures with the arithmetic shown.
    </div>
    <table class="fw-table">
      <thead><tr><th>Loss scenario</th><th class="num">Findings routed</th><th>Worst severity</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p class="fair-note">Scenario matching is real and independent of the money: it is driven by your findings.
      Only the loss magnitude is unpriced.</p>
    {disclosures}
"""
    def _render_filter_notice(self) -> str:
        """Say that a display filter is on, and which numbers it moved.

        WHY THIS IS NOT OPTIONAL NOW. The finding list obeys `--severity`; the
        framework roll-ups deliberately do not, because they describe the estate
        rather than the selection. That is the correct behaviour and it makes two
        numbers on one page disagree — so the page has to say why, or a reader
        reconciling "341 findings" against a CSF section counting more concludes
        one of them is broken.

        Silence was the worse failure and it is the one that shipped: the filter
        USED to narrow the roll-ups too, so a Category with real MEDIUM findings
        rendered the green "no findings" chip and nothing anywhere said a filter
        had been applied.
        """
        chosen = str(self.meta.get("severity_filter", "ALL") or "ALL").upper()
        if chosen == "ALL":
            return ""
        shown, scanned = len(self.findings), len(self.full_findings)
        hidden = max(0, scanned - shown)
        return f"""
    <div class="cov-lead" style="border-left:4px solid var(--accent);background:var(--accent-dim);padding:.7rem 1rem;border-radius:6px;margin:.6rem 0 1rem;">
      <strong>A severity filter is applied to this report.</strong>
      It lists the {shown} finding(s) at {html.escape(chosen)} or above and omits
      {hidden} below it. The framework sections &mdash; NIST CSF, FAIR-CAM and the
      compliance mapping &mdash; are computed over all {scanned} findings this scan
      produced, because they describe the estate rather than this selection. That is
      why their counts are larger, and it is deliberate: a display option must not be
      able to turn a finding into a clean control.
    </div>
"""

    def _render_coverage(self) -> str:
        """What the scan could not look at.

        THE MOST IMPORTANT SECTION IN THE REPORT, and it was absent for the whole
        life of the product. A missing export loads as None and every check that
        needs it self-skips SILENTLY, so a customer who supplied a fraction of the
        sources received a clean-looking report with nothing anywhere saying so.
        modules/coverage.py has said exactly that in its own docstring since it was
        written; the manifest was wired to the server's ingest path only, and the
        artefact that most needed it could not even import the code.

        It is rendered FIRST, before the findings, because a reader who sees the
        finding count before the coverage will anchor on the wrong number.
        """
        manifest = self.coverage
        if manifest is None:
            return f"""
    <h2>What this scan could not look at</h2>
    <div class="banner-warn" style="padding:.8rem 1rem;border-left:4px solid var(--medium);background:var(--medium-bg);border-radius:6px;">
      <strong>Coverage could not be determined for this scan.</strong> The manifest that
      records which exports were supplied and which modules ran on partial input could not be
      built, so this report cannot tell you how much of the estate it saw. Treat the findings
      below as a floor rather than a survey.
    </div>
"""
        counts = manifest.get("counts", {})
        supplied = counts.get("sources_supplied", 0)
        known = counts.get("sources_known", 0)
        degraded = counts.get("modules_degraded", 0)
        skipped = counts.get("modules_skipped", 0)
        # A FIFTH CARD RATHER THAN A BIGGER FOURTH. "You did not supply the input"
        # and "the scan did not run this module" have different owners and
        # different remedies, and adding them together produces a number nobody
        # can act on.
        not_run = counts.get("modules_not_run", 0)
        empty = counts.get("sources_empty", 0)
        lead = html.escape(manifest.get("summary", ""))

        empty_html = ""
        if manifest.get("empty"):
            names = ", ".join(html.escape(str(s)) for s in manifest["empty"])
            empty_html = (
                '<p class="fair-note" style="font-style:normal;">&#9432; '
                + str(empty) + " file(s) were present but contained no rows ("
                + names + "). That is a problem with the export rather than the "
                "upload, and it is reported separately because an empty file and "
                "an absent one mean different things.</p>")

        # `not_run` FIRST, and in both tables. Absent from `label` the raw enum
        # leaked into the customer's table as the string "not_run"; absent from
        # `order` it fell to the default 9 and sorted BELOW "complete", so the
        # one state meaning "this module never looked" sat at the bottom of a
        # table read top-down.
        order = {"not_run": 0, "skipped": 1, "not_requested": 2, "degraded": 3,
                 "no_file_inputs": 4, "complete": 5}
        label = {"complete": ("cov-complete", "complete"),
                 "not_requested": ("cov-skipped", "not requested"),
                 "degraded": ("cov-degraded", "partial input"),
                 "skipped": ("cov-skipped", "no input supplied"),
                 "not_run": ("cov-skipped", "not executed"),
                 "no_file_inputs": ("cov-complete", "needs no export")}
        rows = []
        for name, info in sorted(manifest.get("modules", {}).items(),
                                 key=lambda kv: (order.get(kv[1].get("status"), 9), kv[0])):
            cls, text = label.get(info.get("status"), ("cov-skipped", info.get("status", "")))
            missing = ", ".join(html.escape(str(s)) for s in info.get("sources_missing", []))
            rows.append(
                "<tr><td>" + html.escape(name) + '</td><td><span class="cov-state '
                + cls + '">' + text + "</span></td>"
                + '<td class="csf-why">' + (missing or "&mdash;") + "</td></tr>")
        rows_html = "".join(rows)
        return f"""
    <style>
      .cov-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:.7rem; margin:.8rem 0 1rem; }}
      .cov-card {{ border:1px solid var(--border); border-radius:8px; padding:.7rem .8rem; }}
      .cov-big {{ font-size:1.5rem; font-weight:700; }}
      .cov-cap {{ font-size:.68rem; color:var(--text-muted); margin-top:.15rem; }}
      .cov-state {{ font-size:.66rem; font-weight:700; padding:.1rem .4rem; border-radius:4px; white-space:nowrap; }}
      .cov-complete {{ color:#15803d; background:rgba(34,197,94,.13); }}
      .cov-degraded {{ color:var(--medium); background:var(--medium-bg); }}
      .cov-skipped {{ color:var(--text-muted); border:1px dashed var(--border); }}
    </style>
    <h2>What this scan could not look at</h2>
    <div class="cov-lead">{lead}</div>
    <div class="cov-cards">
      <div class="cov-card"><div class="cov-big">{supplied} <span style="font-size:.9rem;color:var(--text-muted)">/ {known}</span></div>
        <div class="cov-cap">logical sources supplied</div></div>
      <div class="cov-card"><div class="cov-big">{degraded}</div>
        <div class="cov-cap">modules ran on partial input</div></div>
      <div class="cov-card"><div class="cov-big">{skipped}</div>
        <div class="cov-cap">modules had no input supplied</div></div>
      <div class="cov-card"><div class="cov-big">{not_run}</div>
        <div class="cov-cap">modules were not executed</div></div>
      <div class="cov-card"><div class="cov-big">{empty}</div>
        <div class="cov-cap">files present but empty</div></div>
    </div>
    {empty_html}
    <table class="fw-table">
      <thead><tr><th>Module</th><th>State</th><th>Missing input</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p class="fair-note">A module that did not run produces no findings, and no findings is
      not a clean result &mdash; it is an unexamined one. Every check that needed an export you
      did not supply self-skipped silently, so the sections above describe the part of the
      estate this scan could see. Supply the missing sources and re-run to widen it.</p>
"""

    def _render_csf(self) -> str:
        """NIST CSF 2.0, at Function and Category level.

        FUNCTIONS AND CATEGORIES, NOT SUBCATEGORIES. Evidence is mapped at Category
        granularity (modules/nist_csf.py), so a per-Subcategory mark would be an
        invention at exactly the resolution a reader trusts most. CSWP 29 also says
        the Subcategories "are not a checklist of actions to perform", which is what
        a printed tick-list would turn them into.

        The three states survive into print: a Category this product cannot assess
        is drawn DASHED with its reason, never as a clean zero. Ten of the
        twenty-two are in that state, and a board reading a green CSF page for
        outcomes nobody examined is the failure this section exists to avoid.
        """
        if not self.full_findings:
            return ""
        try:
            from modules import nist_csf
        except Exception:                                # noqa: BLE001
            return ""
        rolled = nist_csf.roll_up(self.full_findings, coverage=self.coverage)
        tot = rolled["totals"]
        framework_txt = html.escape(rolled["framework"])
        reference_txt = html.escape(rolled["reference"])

        cards = []
        for fn in rolled["functions"]:
            na = fn["categories_total"] - fn["categories_assessed"]
            cards.append(
                '<div class="csf-card csf-' + fn["id"] + '">'
                '<div class="csf-mono">' + fn["id"] + '</div>'
                '<div class="csf-name">' + html.escape(fn["name"]) + '</div>'
                '<div class="csf-big">' + str(fn["total"]) + '</div>'
                '<div class="csf-cap">' + str(fn["categories_assessed"]) + " of "
                + str(fn["categories_total"]) + " categories assessed"
                + (" &middot; " + str(na) + " not assessed" if na else "") + "</div></div>")
        fn_cards_html = "".join(cards)

        rows = []
        for fn in rolled["functions"]:
            for cat in fn["categories"]:
                if cat["status"] == "not_assessed":
                    state = '<span class="csf-state csf-na">not assessed</span>'
                    count = "&mdash;"
                    why = html.escape(cat["reason"] or "")
                elif cat["status"] == "not_supplied":
                    # An em dash, never the 0 this Category actually computed. A
                    # zero drawn like a measurement is the sentence this whole
                    # section exists to avoid printing.
                    state = '<span class="csf-state csf-na">export not supplied</span>'
                    count = "&mdash;"
                    why = ("No module feeding this Category ran in this scan, so "
                           "the absence of findings is unexamined rather than clean.")
                else:
                    state = ('<span class="csf-state csf-clear">no findings</span>'
                             if cat["status"] == "clear"
                             else '<span class="csf-state csf-found">findings</span>')
                    count = str(cat["total"])
                    why = html.escape(" / ".join(cat["themes"])) if cat["themes"] else ""
                rows.append(
                    '<tr><td class="csf-id">' + cat["id"] + "</td><td>"
                    + html.escape(cat["name"]) + "</td><td>" + state
                    + '</td><td class="num">' + count + '</td><td class="csf-why">'
                    + why + "</td></tr>")
        rows_html = "".join(rows)
        return f"""
    <style>
      .csf-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.7rem; margin:.8rem 0 1.2rem; }}
      .csf-card {{ border:1px solid var(--border); border-left-width:4px; border-radius:8px; padding:.7rem .8rem; }}
      .csf-GV {{ border-left-color:#d4a017; }} .csf-ID {{ border-left-color:#0ea5e9; }}
      .csf-PR {{ border-left-color:#8b5cf6; }} .csf-DE {{ border-left-color:#f59e0b; }}
      .csf-RS {{ border-left-color:#ef4444; }} .csf-RC {{ border-left-color:#22c55e; }}
      .csf-mono {{ font-family:ui-monospace,monospace; font-weight:700; font-size:.7rem; color:var(--text-muted); }}
      .csf-name {{ font-weight:600; font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; }}
      .csf-big {{ font-size:1.5rem; font-weight:700; margin-top:.25rem; }}
      .csf-cap {{ font-size:.68rem; color:var(--text-muted); margin-top:.15rem; }}
      .csf-state {{ font-size:.66rem; font-weight:700; padding:.1rem .4rem; border-radius:4px; white-space:nowrap; }}
      .csf-found {{ color:var(--text-muted); border:1px solid var(--border); }}
      .csf-clear {{ color:#15803d; background:rgba(34,197,94,.13); }}
      .csf-na {{ color:var(--text-muted); border:1px dashed var(--border); }}
      .csf-id {{ font-family:ui-monospace,monospace; font-size:.72rem; white-space:nowrap; }}
      .csf-why {{ font-size:.7rem; color:var(--text-muted); }}
    </style>
    <h2>NIST Cybersecurity Framework 2.0</h2>
    <div class="fair-sub">Your open findings, arranged by the outcome each one is evidence against.
      {tot['categories_assessable']} of the {tot['categories']} CSF Categories are assessable from an SAP
      export; the other {tot['categories_not_assessed']} describe governance, training and incident-response
      outcomes this product produces no evidence about. They are listed below, dashed, with the reason for each.</div>
    <div class="csf-cards">{fn_cards_html}</div>
    <table class="fw-table">
      <thead><tr><th>Category</th><th>Name</th><th>State</th><th class="num">Findings</th><th>Basis / why not</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p class="fair-note">A finding is evidence against more than one outcome, so it can appear under several
      Categories; each counts it once. Nothing here is a statement that you comply with a Category &mdash; the
      absence of findings is not evidence of compliance, and no score or percentage is given because we see the
      findings, not your control environment. {framework_txt} &middot; {reference_txt}.</p>
"""
    def _render_fair_cam(self) -> str:
        """FAIR-CAM: which control function the findings actually weaken.

        The ambiguity flag is KEPT in print. Nine of the sixteen themes genuinely
        span more than one function, and a printed table that hides that reads as a
        precise attribution — which is worse on paper than on screen, because paper
        is what gets quoted back.
        """
        if not self.full_findings:
            return ""
        try:
            from modules import fair_cam
        except Exception:                                # noqa: BLE001
            return ""
        result = fair_cam.classify(self.full_findings, coverage=self.coverage)

        rows = []
        for fn in result["functions"]:
            if fn["status"] == "not_assessed":
                count = "&mdash;"
                note = html.escape(fn["reason"] or "")
                state = '<span class="csf-state csf-na">not assessed</span>'
            elif fn["status"] == "not_supplied":
                count = "&mdash;"
                note = ("No module feeding this control function ran in this "
                        "scan; its pressure is unmeasured, not zero.")
                state = '<span class="csf-state csf-na">export not supplied</span>'
            else:
                count = "%.1f" % fn["findings"]
                state = ('<span class="csf-state csf-clear">no findings</span>'
                         if fn["status"] == "clear"
                         else '<span class="csf-state csf-found">'
                              + html.escape(fn["confidence"]) + "</span>")
                note = html.escape(" / ".join(fn["themes"]))
            rows.append(
                "<tr><td>" + html.escape(fn["name"]) + "</td><td>" + fn["domain"]
                + '</td><td class="csf-id">' + fn["factor"].replace("_", " ")
                + "</td><td>" + state + '</td><td class="num">' + count
                + '</td><td class="csf-why">' + note + "</td></tr>")
        rows_html = "".join(rows)

        vm = result["variance_management"]
        extra_html = ""
        if vm["findings"]:
            extra_html = ('<p class="fair-note"><strong>%.1f findings are Variance '
                          "Management controls</strong> (%s). %s</p>"
                          % (vm["findings"], html.escape(", ".join(vm["themes"])),
                             html.escape(vm["note"])))
        return f"""
    <h2>Which control the findings weaken &middot; FAIR-CAM</h2>
    <div class="fair-sub">FAIR-CAM sorts controls into nine functions and each moves a different part of the
      risk model. Prevention changes how often a loss event happens; Detection and Response change how much it
      costs when it does.</div>
    <table class="fw-table">
      <thead><tr><th>Control function</th><th>Domain</th><th>Moves</th><th>Attribution</th><th class="num">Findings</th><th>Evidence from</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p class="fair-note">Findings are counted fractionally: one finding whose theme reaches three functions
      contributes a third to each, so the column sums to the corpus rather than triple-counting it. An
      <em>ambiguous</em> attribution means the theme genuinely spans more than one function &mdash; least
      privilege both resists an action and shrinks its blast radius &mdash; and the weighting is a stated
      modelling choice, not a measurement.</p>
    {extra_html}
"""
    def _render_compliance(self) -> str:
        """Map findings onto control frameworks (ISO 27001 / NIST CSF / CIS /
        TISAX / SOC 2 / GDPR) and render a collapsible gap-mapping section."""
        if not self.full_findings:
            return ""
        frameworks = ComplianceMapper(self.full_findings).assess()
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
