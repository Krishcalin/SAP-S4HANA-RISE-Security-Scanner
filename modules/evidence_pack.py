"""The per-control audit evidence, as a self-contained document an auditor keeps.

The console's ComplianceEvidence screen answers, per control, whether the estate
has a GAP, is CLEAR, was NOT TESTED or NOT MAPPED, and — where there is a gap —
shows the findings that prove it, plus how each control CHANGED since the previous
scan. This renders that same answer for ONE framework as a single HTML file a
customer can hand to an auditor, or attach to a control-owner ticket, offline.

WHY HTML AND NOT THE PDF/PPTX ENGINES. Those engines render a findings report —
their input is the finding corpus, not a per-control status map — and an auditor
opens an evidence pack, prints it if they want paper, and keeps it. A self-
contained HTML file (no external fetch, a print stylesheet) is the faithful,
stdlib medium for that, and it reads identically to the screen it mirrors.

THE DOCUMENT MAKES THE SAME PROMISES THE SCREEN DOES, IN THE SAME WORDS.
  * CLEAR is an observation that the feeding checks ran and found nothing — never
    an assertion that the control is met. NOT TESTED (the feeding checks did not
    run) is a different sentence and renders differently; the two must never look
    alike.
  * NO PERCENTAGE is computed. A control tally is counts, not a score.
  * Drift is recomputed at both scans with each scan's own coverage, so a control
    that changed only because an export stopped arriving reads as "stopped
    testing", and with no second scan every control reads "no baseline" — never a
    fabricated change. All of that is decided in modules/control_status.py; this
    only renders what it returns.

CONTENT, NOT CHECKS. Reads the assess_framework / drift output; emits no findings
and defines no check ids. stdlib-only (it lives in modules/).
"""
from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

# Status -> (label, colour) — the same four states control_status produces, in the
# same reading as the screen's STATUS map (gap=red, clear=green, not-tested=amber,
# not-mapped=grey). Kept here rather than imported so the document's palette is
# self-contained.
_STATUS = {
    "gap": ("Gap", "#dc2626"),
    "clear": ("Clear", "#15803d"),
    "not_tested": ("Not tested", "#b45309"),
    "not_mapped": ("Not mapped", "#64748b"),
}

# Change -> (label, colour). Only the changes worth a badge render; unchanged and
# no_baseline produce nothing, exactly as the screen's CHANGE map does.
_CHANGE = {
    "newly_failing": ("↑ newly failing", "#dc2626"),
    "remediated": ("↓ remediated", "#15803d"),
    "still_failing": ("still failing", "#dc2626"),
    "stopped_testing": ("⚠ stopped testing", "#b45309"),
    "started_testing": ("now tested", "#64748b"),
}

_SEV_COLOUR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#b45309",
    "LOW": "#15803d", "INFO": "#0369a1",
}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _e(value: Any) -> str:
    """Escape for HTML text; None becomes empty."""
    return html.escape("" if value is None else str(value))


def _counts_html(counts: Dict[str, int]) -> str:
    chips = []
    for sev in _SEVERITIES:
        n = counts.get(sev, 0)
        if n:
            chips.append(
                f'<span class="sev-chip" style="color:{_SEV_COLOUR[sev]};'
                f'border-color:{_SEV_COLOUR[sev]}55">{n}&nbsp;{sev}</span>')
    return "".join(chips)


def _findings_html(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return ""
    rows = []
    for f in findings:
        sev = str(f.get("severity") or "").upper()
        colour = _SEV_COLOUR.get(sev, "#64748b")
        sid = f.get("sid")
        meta = _e(f.get("check_id")) + (f" &middot; {_e(sid)}" if sid else "")
        items = f.get("affected_items") or []
        items_html = (
            f'<div class="ev-items">{_e(" · ".join(str(i) for i in items))}</div>'
            if items else "")
        rows.append(
            '<li class="ev-row">'
            f'<span class="sev-badge" style="background:{colour}14;color:{colour};'
            f'border-color:{colour}44">{_e(sev)}</span>'
            '<div class="ev-text">'
            f'<div class="ev-title">{_e(f.get("title") or f.get("check_id"))}</div>'
            f'<div class="ev-meta">{meta}</div>'
            f'{items_html}'
            '</div></li>')
    return f'<ul class="ev-list">{"".join(rows)}</ul>'


def _explanation_html(status: str) -> str:
    """The one honest sentence a non-gap status needs, in the screen's words."""
    if status == "clear":
        return ('<p class="ctrl-note">The checks that feed this control ran and '
                'produced no finding. This is an observation that we looked — '
                'not an assertion that the control is met.</p>')
    if status == "not_tested":
        return ('<p class="ctrl-note">The checks that feed this control did not run '
                '— the export they need was not supplied. This control was '
                '<strong>not tested</strong>.</p>')
    if status == "not_mapped":
        return ('<p class="ctrl-note">Nothing this product checks maps to this '
                'control.</p>')
    return ""


def _control_html(control: Dict[str, Any], change: Optional[str]) -> str:
    status = str(control.get("status") or "not_mapped")
    label, colour = _STATUS.get(status, _STATUS["not_mapped"])
    change_badge = ""
    if change and change in _CHANGE:
        clabel, ccolour = _CHANGE[change]
        change_badge = (f'<span class="change-badge" style="color:{ccolour}">'
                        f'{_e(clabel)}</span>')
    themes = control.get("themes") or []
    themes_html = (f'<p class="ctrl-themes">Tested via: {_e(", ".join(themes))}</p>'
                   if themes else "")
    counts_html = _counts_html(control.get("counts") or {}) if control.get("total") else ""
    return (
        '<section class="ctrl">'
        '<div class="ctrl-head">'
        f'<div class="ctrl-id"><span class="cid">{_e(control.get("id"))}</span>'
        f'<span class="cname">{_e(control.get("name"))}</span></div>'
        '<div class="ctrl-tags">'
        f'{change_badge}{counts_html}'
        f'<span class="status-pill" style="color:{colour};border-color:{colour}55">'
        f'{_e(label)}</span>'
        '</div></div>'
        f'{themes_html}'
        f'{_explanation_html(status)}'
        f'{_findings_html(control.get("findings") or [])}'
        '</section>')


def _drift_summary_html(drift: Optional[Dict[str, Any]]) -> str:
    if not drift:
        return ""
    if not drift.get("has_baseline"):
        return ('<p class="drift">No previous complete scan to compare against yet '
                '— control drift appears once a second scan has run.</p>')
    by = drift.get("totals", {}).get("by_change", {})
    parts: List[str] = []
    for key, word in (("newly_failing", "newly failing"),
                      ("remediated", "remediated"),
                      ("stopped_testing", "stopped testing"),
                      ("started_testing", "now tested")):
        if by.get(key):
            parts.append(f"{by[key]} {word}")
    tail = " · ".join(parts) if parts else "no control changed status"
    return (f'<p class="drift"><strong>Since the previous scan:</strong> '
            f'{_e(tail)}.</p>')


def _summary_line_html(totals: Dict[str, Any]) -> str:
    by = totals.get("by_status", {})
    n = totals.get("controls", 0)
    bits = [
        f'<span style="color:#dc2626;font-weight:600">{by.get("gap", 0)} gap</span>',
        f'<span style="color:#15803d;font-weight:600">{by.get("clear", 0)} clear</span>',
        f'<span style="color:#b45309;font-weight:600">{by.get("not_tested", 0)} '
        'not tested</span>',
    ]
    if by.get("not_mapped"):
        bits.append(f'{by["not_mapped"]} not mapped')
    return (f'Per-control audit evidence across the {n} control'
            f'{"" if n == 1 else "s"} this product maps: ' + " · ".join(bits) + ".")


_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#f1f5f9;color:#0f172a;line-height:1.6;
  font-family:'DM Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1040px;margin:0 auto;padding:2rem 1.25rem 3rem}
.doc-head{border-bottom:1px solid #e2e8f0;padding-bottom:1.25rem;margin-bottom:1.5rem}
.eyebrow{font-size:.72rem;text-transform:uppercase;letter-spacing:.14em;
  color:#64748b;font-weight:700}
h1{font-size:1.7rem;font-weight:800;letter-spacing:-.02em;margin:.35rem 0 .15rem}
.subtitle{color:#64748b;font-size:.9rem;margin:0}
.meta{color:#64748b;font-size:.78rem;margin-top:.75rem;display:flex;flex-wrap:wrap;
  gap:.35rem 1.25rem}
.summary{font-size:.95rem;margin:1.25rem 0;max-width:80ch}
.banner{background:#fffbeb;border:1px solid #fde68a;border-left:4px solid #b45309;
  border-radius:6px;padding:.85rem 1.1rem;margin:1rem 0;font-size:.85rem;max-width:80ch}
.banner strong{color:#92400e}
.drift{font-size:.88rem;margin:1rem 0;max-width:80ch;color:#334155}
.ctrl{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem 1.1rem;
  margin-bottom:.8rem}
.ctrl-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;
  flex-wrap:wrap}
.ctrl-id{display:flex;align-items:baseline;gap:.6rem;min-width:0}
.cid{font-family:'JetBrains Mono',Consolas,monospace;font-size:.76rem;color:#64748b;
  font-weight:700;flex-shrink:0}
.cname{font-size:.98rem;font-weight:700;color:#0f172a}
.ctrl-tags{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;flex-shrink:0}
.status-pill{font-size:.68rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;padding:.22rem .6rem;border-radius:999px;border:1px solid;
  background:#fff;white-space:nowrap}
.change-badge{font-size:.72rem;font-weight:700;white-space:nowrap}
.sev-chip{font-family:'JetBrains Mono',Consolas,monospace;font-size:.66rem;
  font-weight:700;border:1px solid;border-radius:4px;padding:.12rem .4rem;white-space:nowrap}
.ctrl-themes{font-size:.75rem;color:#64748b;margin:.4rem 0 0}
.ctrl-note{font-size:.85rem;color:#334155;margin:.5rem 0 0;max-width:80ch}
.ev-list{list-style:none;margin:.6rem 0 0;padding:0}
.ev-row{display:flex;gap:.65rem;align-items:flex-start;padding:.5rem 0;
  border-bottom:1px solid #f1f5f9}
.ev-row:last-child{border-bottom:none}
.sev-badge{font-family:'JetBrains Mono',Consolas,monospace;font-size:.62rem;
  font-weight:700;padding:.15rem .45rem;border-radius:4px;border:1px solid;
  min-width:62px;text-align:center;flex-shrink:0;margin-top:.1rem}
.ev-text{min-width:0}
.ev-title{font-size:.88rem;font-weight:600;color:#0f172a}
.ev-meta{font-family:'JetBrains Mono',Consolas,monospace;font-size:.7rem;color:#64748b}
.ev-items{font-size:.72rem;color:#64748b;margin-top:.15rem}
.footer{margin-top:2.5rem;padding-top:1.25rem;border-top:1px solid #e2e8f0;
  font-size:.72rem;color:#64748b;max-width:80ch}
@media print{body{background:#fff}.wrap{max-width:none}.ctrl{break-inside:avoid}}
"""


def render(assessed: Dict[str, Any], drift: Optional[Dict[str, Any]],
           meta: Dict[str, Any]) -> str:
    """One self-contained HTML document for a framework's per-control evidence.

    `assessed` is control_status.assess_framework output (required); `drift` is
    control_status.drift output or None; `meta` carries `generated`, `scope` and
    an optional `measured` label for the document to date itself.
    """
    change_by_id: Dict[str, str] = {}
    for c in (drift or {}).get("controls", []) or []:
        if c.get("change"):
            change_by_id[c["id"]] = c["change"]

    totals = assessed.get("totals", {})
    measured = totals.get("measured") or meta.get("measured")
    meta_bits = [f'<span>Generated {_e(meta.get("generated"))}</span>',
                 f'<span>Scope: {_e(meta.get("scope"))}</span>']
    if measured:
        meta_bits.append(f'<span>Status measured from the latest complete scan '
                         f'({_e(measured)})</span>')

    controls_html = "".join(
        _control_html(c, change_by_id.get(c.get("id")))
        for c in assessed.get("controls", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_e(assessed.get("name"))} — Control Evidence Pack</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="doc-head">
    <div class="eyebrow">Control evidence pack</div>
    <h1>{_e(assessed.get("name"))}</h1>
    <p class="subtitle">{_e(assessed.get("subtitle"))}</p>
    <div class="meta">{"".join(meta_bits)}</div>
  </div>

  <p class="summary">{_summary_line_html(totals)}</p>

  <div class="banner">
    <strong>Clear is not a certification.</strong> A control reads
    <em>clear</em> when the checks feeding it ran and found nothing — not that the
    control is met. <em>Not tested</em> means those checks did not run. No
    percentage is computed.
  </div>

  {_drift_summary_html(drift)}

  {controls_html}

  <div class="footer">
    Built from the finding store for the scope above, not from one scan, so each
    control's status reflects the open findings and the coverage of the latest
    complete scan per system. Affected objects are rendered from the stored typed
    objects. Resolved and false-positive findings are excluded. This document
    reports what was observed; it is evidence for an audit, not a statement of
    compliance. &copy; 2026 MonitorRisk.
  </div>
</div>
</body>
</html>"""
