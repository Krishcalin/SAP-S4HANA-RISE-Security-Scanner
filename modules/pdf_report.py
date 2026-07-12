"""
PDF Report Generator
====================
Renders the scan findings as a professional, multi-page PDF security-assessment
report suitable for handing to an SAP implementation / maintenance team — built
entirely on `pdf_writer.PDFWriter` (standard library only).

Layout:
  - Cover page (title, scope metadata, overall risk posture, severity summary)
  - Executive summary (posture narrative, severity table, category breakdown,
    top-priority critical findings)
  - Detailed findings — one styled block per finding with the full "Security
    Risk" narrative and the numbered "Remediation" procedure (from the findings
    knowledge base, falling back to the finding's own text), affected items and
    references — with automatic page breaks and running header/footer.
"""

from typing import Dict, List, Any, Optional, Tuple

from modules.pdf_writer import PDFWriter
from modules.finding_kb import FindingKB
from modules.compliance_mapping import ComplianceMapper


# ── palette (print-friendly) ──
NAVY = (0.055, 0.13, 0.24)
INK = (0.12, 0.16, 0.22)
MUTED = (0.42, 0.45, 0.50)
FAINT = (0.60, 0.63, 0.68)
RULE = (0.84, 0.86, 0.89)
LIGHT = (0.955, 0.965, 0.975)
ACCENT = (0.15, 0.39, 0.92)
WHITE = (1, 1, 1)

SEV_COLOR = {
    "CRITICAL": (0.72, 0.11, 0.11),
    "HIGH": (0.79, 0.29, 0.05),
    "MEDIUM": (0.71, 0.42, 0.04),
    "LOW": (0.09, 0.50, 0.20),
    "INFO": (0.02, 0.41, 0.63),
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class PDFReportGenerator:
    ML, MR, MT, MB = 45, 45, 56, 44

    _TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    TIER_COLOR = {"P1": SEV_COLOR["CRITICAL"], "P2": SEV_COLOR["HIGH"],
                  "P3": SEV_COLOR["MEDIUM"], "P4": SEV_COLOR["LOW"]}

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 kb: Optional[FindingKB] = None, priorities: Optional[List[Any]] = None):
        self.findings = findings
        self.meta = meta
        self.kb = kb or FindingKB()
        self.w = PDFWriter()
        self.pw, self.ph = self.w.pw, self.w.ph
        self.cw = self.pw - self.ML - self.MR
        self.y = 0.0
        self._content_pages = 0

        # Risk-prioritization overlay (P1-P4) — mirrors the HTML report so the PDF
        # presents findings in the same fix-first order. Compute here if not passed.
        if priorities is None:
            try:
                from modules.risk_prioritizer import RiskPrioritizer
                priorities = RiskPrioritizer().prioritize(findings)
            except Exception:
                priorities = []
        try:
            from modules.risk_prioritizer import TIER_META
            self.tier_meta = TIER_META
        except Exception:
            self.tier_meta = {}
        self._prio_by_id = {}
        for p in (priorities or []):
            fnd = getattr(p, "finding", None)
            if fnd is not None:
                self._prio_by_id[id(fnd)] = p
        self.tier_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for p in (priorities or []):
            t = getattr(p, "tier", None)
            if t in self.tier_counts:
                self.tier_counts[t] += 1

        # stats
        self.by_sev: Dict[str, int] = {}
        self.by_cat: Dict[str, int] = {}
        for f in findings:
            self.by_sev[f["severity"]] = self.by_sev.get(f["severity"], 0) + 1
            self.by_cat[f["category"]] = self.by_cat.get(f["category"], 0) + 1
        self.crit = self.by_sev.get("CRITICAL", 0)
        self.high = self.by_sev.get("HIGH", 0)
        self.med = self.by_sev.get("MEDIUM", 0)
        self.low = self.by_sev.get("LOW", 0)
        self.info = self.by_sev.get("INFO", 0)
        self.risk_score = min(100, self.crit * 25 + self.high * 10 + self.med * 4 + self.low * 1)
        self.risk_label, self.risk_col = self._risk_band(self.risk_score)

    @staticmethod
    def _risk_band(score: int):
        if score >= 75:
            return "Critical", SEV_COLOR["CRITICAL"]
        if score >= 50:
            return "High", SEV_COLOR["HIGH"]
        if score >= 25:
            return "Medium", SEV_COLOR["MEDIUM"]
        return "Low", SEV_COLOR["LOW"]

    def _tier_of(self, f):
        return self._prio_by_id.get(id(f))

    def _fix_first(self) -> List[Dict[str, Any]]:
        """Findings in the exact fix-first order the HTML uses: tier (P1->P4),
        then severity, then descending priority score."""
        def key(f):
            pr = self._tier_of(f)
            trank = self._TIER_RANK.get(getattr(pr, "tier", None), 9) if pr is not None else 9
            score = -getattr(pr, "score", 0) if pr is not None else 0
            return (trank, self._SEV_RANK.get(f.get("severity"), 4), score)
        return sorted(self.findings, key=key)

    # ── low-level cursor helpers (top-down) ──
    def _new_content_page(self):
        self.w.add_page()
        self._content_pages += 1
        # running header
        self.w.text(self.ML, self.ph - 30, "SAP S/4HANA RISE — Security Assessment Report",
                    font="HB", size=7.5, color=MUTED)
        self.w.text(self.pw - self.MR - self.w.string_width("CONFIDENTIAL", "HB", 7.5),
                    self.ph - 30, "CONFIDENTIAL", font="HB", size=7.5, color=SEV_COLOR["CRITICAL"])
        self.w.line(self.ML, self.ph - 38, self.pw - self.MR, self.ph - 38, color=RULE, width=0.6)
        self.y = self.ph - self.MT

    def _ensure(self, h: float):
        if self.y - h < self.MB:
            self._new_content_page()

    def _para(self, text: str, font="H", size=9.5, color=INK, leading=13.5,
              gap_after=0.0, indent=0.0, x0: Optional[float] = None):
        x0 = self.ML if x0 is None else x0
        lines = self.w.wrap(text, font, size, self.cw - indent - (x0 - self.ML))
        for ln in lines:
            self._ensure(leading)
            self.w.text(x0 + indent, self.y - size, ln, font=font, size=size, color=color)
            self.y -= leading
        self.y -= gap_after

    def _label(self, text: str, color=MUTED):
        self._ensure(14)
        self.w.text(self.ML, self.y - 8, text.upper(), font="HB", size=7.5, color=color)
        self.y -= 15

    # ── sections (same chronological order as the HTML report) ──
    def generate(self, output_path: str):
        self._cover_page()                 # header + risk posture + severity summary
        self._priority_section()           # Risk-Prioritized Remediation Queue (P1-P4 + top-10)
        self._categories_section()         # Findings by Category
        self._compliance_section()         # Compliance & Control-Framework Mapping
        self._detailed_findings()          # Detailed Findings (fix-first order)
        self._footers()
        self.w.save(output_path)

    def _cover_page(self):
        w = self.w
        w.add_page()
        # top band
        w.rect(0, self.ph - 150, self.pw, 150, fill=NAVY)
        w.rect(0, self.ph - 154, self.pw, 4, fill=ACCENT)
        w.text(self.ML, self.ph - 66, "SAP S/4HANA RISE", font="HB", size=13, color=(0.62, 0.78, 0.98))
        w.text(self.ML, self.ph - 104, "Security Assessment Report", font="HB", size=26, color=WHITE)
        w.text(self.ML, self.ph - 126, "Offline configuration review — S/4HANA · HANA · BTP / Cloud",
               font="H", size=10.5, color=(0.72, 0.79, 0.88))

        y = self.ph - 210
        # scope / metadata card — value column wraps; the card height grows to fit
        # (so long values like the full module list are printed in full).
        mods = ", ".join(self.meta.get("modules_run", [])) or "all"
        kv = [
            ("Assessment date", str(self.meta.get("scan_time", ""))[:19].replace("T", "  ")),
            ("Data source", str(self.meta.get("data_directory", "N/A"))),
            ("Severity filter", str(self.meta.get("severity_filter", "ALL"))),
            ("Modules in scope", mods),
        ]
        val_x = self.ML + 150
        val_w = self.cw - 150 - 16
        wrapped = [(k, w.wrap(v, "H", 9.5, val_w) or [""]) for k, v in kv]
        pad_top, line_h, row_gap, pad_bot = 20, 13, 6, 10
        content_h = sum(len(lines) * line_h + row_gap for _, lines in wrapped) - row_gap
        card_h = pad_top + content_h + pad_bot
        w.rect(self.ML, y - card_h, self.cw, card_h, fill=LIGHT, stroke=RULE, line_width=0.8)
        yy = y - pad_top
        for k, lines in wrapped:
            w.text(self.ML + 16, yy, k, font="HB", size=8.5, color=MUTED)
            for ln in lines:
                w.text(val_x, yy, ln, font="H", size=9.5, color=INK)
                yy -= line_h
            yy -= row_gap

        # risk posture + severity summary (positioned below the dynamic card)
        y2 = (y - card_h) - 18
        box_h = 118
        # left: risk posture
        lw = 170
        w.rect(self.ML, y2 - box_h, lw, box_h, fill=WHITE, stroke=RULE, line_width=0.8)
        w.rect(self.ML, y2 - 4, lw, 4, fill=self.risk_col)
        w.text(self.ML + 16, y2 - 26, "OVERALL RISK", font="HB", size=8, color=MUTED)
        score = str(self.risk_score)
        w.text(self.ML + 16, y2 - 74, score, font="HB", size=46, color=self.risk_col)
        w.text(self.ML + 20 + w.string_width(score, "HB", 46), y2 - 74, "/100",
               font="H", size=12, color=FAINT)
        w.text(self.ML + 16, y2 - 96, self.risk_label.upper() + " RISK POSTURE",
               font="HB", size=9, color=self.risk_col)

        # right: severity counts grid
        gx = self.ML + lw + 14
        gw = self.cw - lw - 14
        w.rect(gx, y2 - box_h, gw, box_h, fill=WHITE, stroke=RULE, line_width=0.8)
        w.text(gx + 16, y2 - 26, "FINDINGS BY SEVERITY   (total %d)" % len(self.findings),
               font="HB", size=8, color=MUTED)
        cells = [("CRITICAL", self.crit), ("HIGH", self.high), ("MEDIUM", self.med), ("LOW", self.low)]
        cw2 = (gw - 32) / 4
        for i, (name, n) in enumerate(cells):
            cx = gx + 16 + i * cw2
            col = SEV_COLOR[name]
            w.text(cx, y2 - 66, str(n), font="HB", size=28, color=col)
            w.text(cx, y2 - 84, name, font="HB", size=7.5, color=MUTED)
            w.rect(cx, y2 - 92, cw2 - 10, 3, fill=col)

        # confidentiality notice
        note = ("CONFIDENTIAL — This report contains sensitive security information about SAP "
                "systems and is intended solely for the named recipient's authorized security, "
                "Basis and audit personnel. Handle, store and distribute it according to your "
                "organization's information-classification policy. The scan is a point-in-time, "
                "offline analysis of exported configuration data and does not connect to or "
                "modify any SAP system.")
        self.y = y2 - box_h - 26
        self._para(note, font="H", size=8, color=MUTED, leading=11.5)
        w.text(self.ML, self.MB + 6,
               "Generated by SAP S/4HANA RISE Security Scanner", font="HB", size=8, color=FAINT)

    def _priority_section(self):
        self._new_content_page()
        self._section_title("Risk-Prioritized Remediation Queue")
        self._para(
            "Findings ranked by severity x real-world exploitability (SAP HotNews / actively-"
            "exploited notes) x exposure. Work the queue top-down: P1 first.",
            size=9, color=MUTED, gap_after=12)

        # tier cards (row of 4)
        if self.tier_meta:
            gap = 10
            cw4 = (self.cw - 3 * gap) / 4
            self._ensure(70)
            top = self.y
            for i, t in enumerate(("P1", "P2", "P3", "P4")):
                m = self.tier_meta.get(t, {})
                x = self.ML + i * (cw4 + gap)
                col = self.TIER_COLOR[t]
                self.w.rect(x, top - 60, cw4, 60, fill=WHITE, stroke=RULE, line_width=0.8)
                self.w.rect(x, top - 4, cw4, 4, fill=col)
                self.w.text(x + 10, top - 28, t, font="HB", size=18, color=col)
                cnt = str(self.tier_counts.get(t, 0))
                self.w.text(x + cw4 - 10 - self.w.string_width(cnt, "HB", 18), top - 28, cnt,
                            font="HB", size=18, color=INK)
                self.w.text(x + 10, top - 43, self._fit(m.get("label", ""), "HB", 7.5, cw4 - 20),
                            font="HB", size=7.5, color=MUTED)
                self.w.text(x + 10, top - 53, self._fit(m.get("window", ""), "H", 7, cw4 - 20),
                            font="H", size=7, color=FAINT)
            self.y = top - 60 - 16

        # top-10 to fix first (P1/P2 by score) — same selection/order as the HTML
        ranked = [(f, self._tier_of(f)) for f in self.findings if self._tier_of(f) is not None]
        ranked.sort(key=lambda x: (self._TIER_RANK.get(x[1].tier, 9), -getattr(x[1], "score", 0)))
        top = [(f, pr) for f, pr in ranked if pr.tier in ("P1", "P2")][:10]
        if top:
            self._label("Top %d to fix first" % len(top))
            tx = self.ML + 76
            for i, (f, pr) in enumerate(top, 1):
                # wrap title (right gutter reserved for the check-id) and rationale
                tlines = self.w.wrap(f.get("title", ""), "HB", 9, self.cw - 76 - 108) or [""]
                wlines = self.w.wrap(getattr(pr, "rationale", "") or "", "H", 7.5, self.cw - 84)
                self._ensure(13 + len(tlines) * 12 + len(wlines) * 11)
                col = self.TIER_COLOR.get(pr.tier, MUTED)
                self.w.text(self.ML, self.y - 10, str(i), font="HB", size=9, color=MUTED)
                badge = "%s  %d" % (pr.tier, getattr(pr, "score", 0))
                self.w.rect(self.ML + 15, self.y - 12, 52, 12, fill=col)
                self.w.text(self.ML + 19, self.y - 10, badge, font="HB", size=7.5, color=WHITE)
                cid = f.get("check_id", "")
                self.w.text(self.pw - self.MR - self.w.string_width(cid, "H", 8), self.y - 10,
                            cid, font="H", size=8, color=MUTED)
                for ln in tlines:
                    self.w.text(tx, self.y - 10, ln, font="HB", size=9, color=INK)
                    self.y -= 12
                for ln in wlines:
                    self.w.text(tx, self.y - 8, ln, font="H", size=7.5, color=MUTED)
                    self.y -= 11
                self.y -= 4

    def _categories_section(self):
        self.y -= 6
        self._ensure(150)
        self._section_title("Findings by Category")
        maxc = max(self.by_cat.values()) if self.by_cat else 1
        for cat, n in sorted(self.by_cat.items(), key=lambda x: -x[1]):
            self._ensure(16)
            self.w.text(self.ML, self.y - 8, self._fit(cat, "H", 8.5, 205), font="H", size=8.5, color=INK)
            bar_x = self.ML + 220
            bar_w = self.cw - 220 - 30
            self.w.rect(bar_x, self.y - 10, bar_w, 8, fill=LIGHT)
            self.w.rect(bar_x, self.y - 10, max(2, bar_w * n / maxc), 8, fill=ACCENT)
            self.w.text(self.ML + self.cw - 20, self.y - 8, str(n), font="HB", size=8.5, color=MUTED)
            self.y -= 15

    def _compliance_section(self):
        frameworks = ComplianceMapper(self.findings).assess()
        frameworks = [fw for fw in frameworks if fw["controls"]]
        if not frameworks:
            return
        self._new_content_page()
        self._section_title("Compliance & Control-Framework Mapping")
        self._para(
            "Each detected finding is attributed to the control areas it is evidence against, so "
            "results can be navigated by standard. Counts reflect controls with OPEN findings in "
            "the assessed configuration — this is a gap-mapping for audit navigation and "
            "remediation scoping, not a certification, attestation, or statement of full "
            "compliance.", size=8.5, color=MUTED, leading=12, gap_after=12)
        for fw in frameworks:
            self._compliance_framework(fw)

    def _compliance_framework(self, fw: Dict[str, Any]):
        self._ensure(64)
        self.y -= 2
        self.w.text(self.ML, self.y - 11, fw["name"], font="HB", size=11.5, color=NAVY)
        sub = ("%s   —   %d of %d control areas flagged   ·   %d findings mapped"
               % (fw["subtitle"], fw["controls_flagged"], fw["total_controls"], fw["mapped_findings"]))
        self.w.text(self.ML, self.y - 23, sub, font="H", size=8, color=MUTED)
        self.y -= 30

        # numeric columns anchored to the right
        num_w = 30
        xs = [self.pw - self.MR - num_w * k for k in (5, 4, 3, 2, 1)]  # C H M L Tot
        heads = ["Crit", "High", "Med", "Low", "Tot"]
        x_id = self.ML + 6
        x_area = self.ML + 74

        # header
        self._ensure(18)
        self.w.rect(self.ML, self.y - 15, self.cw, 15, fill=NAVY)
        self.w.text(x_id, self.y - 11, "Control", font="HB", size=7.5, color=WHITE)
        self.w.text(x_area, self.y - 11, "Area & mapped themes", font="HB", size=7.5, color=WHITE)
        for xh, h in zip(xs, heads):
            self.w.text(xh + num_w - 3 - self.w.string_width(h, "HB", 7.5), self.y - 11, h,
                        font="HB", size=7.5, color=WHITE)
        self.y -= 15

        def num_cell(x, val, color):
            s = str(val) if val else "-"
            c = color if val else RULE
            self.w.text(x + num_w - 3 - self.w.string_width(s, "HB", 8), self.y - 11, s,
                        font="HB", size=8, color=c)

        area_w = xs[0] - x_area - 8
        for ri, c in enumerate(fw["controls"]):
            # wrap the control name + themes so nothing is clipped; row grows to fit
            nlines = self.w.wrap(c["name"], "HB", 8, area_w) or [""]
            themes = " · ".join(c.get("themes", []))
            tlines = self.w.wrap(themes, "H", 7, area_w) if themes else []
            row_h = max(21, 6 + len(nlines) * 10 + len(tlines) * 9 + 4)
            self._ensure(row_h)
            if ri % 2 == 0:
                self.w.rect(self.ML, self.y - row_h, self.cw, row_h, fill=LIGHT)
            # control id + numeric cells align to the top line of the row
            self.w.text(x_id, self.y - 10, self._fit(c["id"], "HB", 8, 64), font="HB", size=8, color=INK)
            num_cell(xs[0], c["crit"], SEV_COLOR["CRITICAL"])
            num_cell(xs[1], c["high"], SEV_COLOR["HIGH"])
            num_cell(xs[2], c["med"], SEV_COLOR["MEDIUM"])
            num_cell(xs[3], c["low"], SEV_COLOR["LOW"])
            self.w.text(xs[4] + num_w - 3 - self.w.string_width(str(c["total"]), "HB", 8),
                        self.y - 11, str(c["total"]), font="HB", size=8, color=INK)
            # area name + themes, wrapped
            ay = self.y - 10
            for ln in nlines:
                self.w.text(x_area, ay, ln, font="HB", size=8, color=INK)
                ay -= 10
            for ln in tlines:
                self.w.text(x_area, ay, ln, font="H", size=7, color=MUTED)
                ay -= 9
            self.y -= row_h
        self.y -= 12

    def _detailed_findings(self):
        self._new_content_page()
        self._section_title("Detailed Findings")
        for f in self._fix_first():
            self._finding_block(f)

    def _finding_block(self, f: Dict[str, Any]):
        sev = f["severity"]
        col = SEV_COLOR.get(sev, MUTED)
        risk, mitigation, detailed = self.kb.detail_for(f)

        # Title wraps to as many lines as needed (never truncated); the header
        # bar grows to fit. A right gutter is reserved for the check-id so the
        # wrapped title never runs under it.
        title = f["title"]
        title_x = self.ML + 74
        title_w = self.cw - 74 - 120
        tlines = self.w.wrap(title, "HB", 10, title_w) or [""]
        bar_h = max(30, 12 + len(tlines) * 13)

        # keep the whole header bar + category line together on one page
        self._ensure(bar_h + 22)
        self.y -= 6
        top = self.y
        self.w.rect(self.ML, top - bar_h, self.cw, bar_h, fill=LIGHT, stroke=RULE, line_width=0.7)
        self.w.rect(self.ML, top - bar_h, 4, bar_h, fill=col)
        self.w.rect(self.ML + 12, top - 21, 54, 13, fill=col)
        self.w.text(self.ML + 16, top - 18.5, sev[:8], font="HB", size=7.5, color=WHITE)
        ty = top - 19
        for ln in tlines:
            self.w.text(title_x, ty, ln, font="HB", size=10, color=INK)
            ty -= 13
        cid = f["check_id"]
        self.w.text(self.pw - self.MR - 10 - self.w.string_width(cid, "H", 8.5), top - 19,
                    cid, font="H", size=8.5, color=MUTED)
        self.y = top - bar_h - 8
        self.w.text(self.ML, self.y, "Category: " + f.get("category", ""), font="H", size=8, color=MUTED)
        # priority tier chip (mirrors the HTML P-badge)
        pr = self._tier_of(f)
        if pr is not None:
            tcol = self.TIER_COLOR.get(pr.tier, MUTED)
            chip = "%s  %d" % (pr.tier, getattr(pr, "score", 0))
            cwid = self.w.string_width(chip, "HB", 7.5) + 14
            self.w.rect(self.pw - self.MR - cwid, self.y - 2, cwid, 12, fill=tcol)
            self.w.text(self.pw - self.MR - cwid + 7, self.y + 1, chip, font="HB", size=7.5, color=WHITE)
        self.y -= 14

        # affected items
        items = f.get("affected_items") or []
        if items:
            self._label("Affected items (%d)" % f.get("affected_count", len(items)))
            for it in items[:12]:
                ilines = self.w.wrap("· " + str(it), "C", 8, self.cw - 20) or [""]
                for j, ln in enumerate(ilines):
                    self._ensure(12)
                    self.w.text(self.ML + 8 + (0 if j == 0 else 10), self.y - 8, ln,
                                font="C", size=8, color=INK)
                    self.y -= 11.5
            if len(items) > 12:
                self._para("... and %d more affected item(s)." % (len(items) - 12),
                           font="HO", size=8, color=MUTED, x0=self.ML + 8)
            self.y -= 4

        # security risk
        self._label("Security risk", color=col)
        self._para(risk, gap_after=6)

        # remediation
        self._label("Remediation — step-by-step")
        self._para(mitigation, gap_after=6, x0=self.ML)

        # references (wrap fully — never truncated)
        refs = f.get("references") or []
        if refs:
            self._label("References")
            for r in refs:
                rlines = self.w.wrap("- " + str(r), "H", 8, self.cw - 16) or [""]
                for j, ln in enumerate(rlines):
                    self._ensure(12)
                    self.w.text(self.ML + 8 + (0 if j == 0 else 8), self.y - 8, ln,
                                font="H", size=8, color=ACCENT)
                    self.y -= 11.5

        if not detailed:
            self._para("(Detailed knowledge-base entry not available for this check; "
                       "the finding's own description and remediation are shown.)",
                       font="HO", size=7.5, color=FAINT, gap_after=2)

        # separator
        self._ensure(10)
        self.w.line(self.ML, self.y - 2, self.pw - self.MR, self.y - 2, color=RULE, width=0.5)
        self.y -= 10

    # ── small helpers ──
    def _section_title(self, text: str):
        self.w.rect(self.ML, self.y - 4, 30, 4, fill=ACCENT)
        self.y -= 12
        self.w.text(self.ML, self.y - 16, text, font="HB", size=16, color=NAVY)
        self.y -= 26

    def _sev_table(self, rows: List[Tuple[str, str, str]]):
        col_x = [self.ML + 8, self.ML + 180, self.ML + 280]
        # header
        self._ensure(20)
        self.w.rect(self.ML, self.y - 16, self.cw, 16, fill=NAVY)
        for i, h in enumerate(rows[0]):
            self.w.text(col_x[i], self.y - 12, h, font="HB", size=8, color=WHITE)
        self.y -= 16
        for ri, row in enumerate(rows[1:]):
            self._ensure(15)
            if ri % 2 == 0:
                self.w.rect(self.ML, self.y - 14, self.cw, 14, fill=LIGHT)
            sev_name = row[0].upper()
            dot = SEV_COLOR.get(sev_name)
            if dot:
                self.w.rect(self.ML + 8, self.y - 11, 8, 8, fill=dot)
            self.w.text(col_x[0] + (14 if dot else 0), self.y - 11, row[0], font="HB", size=8.5, color=INK)
            self.w.text(col_x[1], self.y - 11, row[1], font="H", size=8.5, color=INK)
            self.w.text(col_x[2], self.y - 11, row[2], font="H", size=8.5, color=MUTED)
            self.y -= 14

    def _fit(self, s: str, font: str, size: float, max_w: float) -> str:
        if self.w.string_width(s, font, size) <= max_w:
            return s
        ell = "..."
        while s and self.w.string_width(s + ell, font, size) > max_w:
            s = s[:-1]
        return s + ell

    def _footers(self):
        total = self.w.page_count
        gen = str(self.meta.get("scan_time", ""))[:19].replace("T", " ")
        for i in range(1, total):  # skip cover (index 0)
            page_ops = self.w._pages[i]
            saved = self.w._cur
            self.w._cur = page_ops
            self.w.line(self.ML, self.MB - 6, self.pw - self.MR, self.MB - 6, color=RULE, width=0.5)
            self.w.text(self.ML, self.MB - 18, "SAP S/4HANA RISE Security Scanner", font="H", size=7, color=FAINT)
            label = "Page %d of %d" % (i + 1, total)
            self.w.text(self.pw - self.MR - self.w.string_width(label, "H", 7), self.MB - 18,
                        label, font="H", size=7, color=FAINT)
            if gen:
                mid = "Generated " + gen
                self.w.text((self.pw - self.w.string_width(mid, "H", 7)) / 2, self.MB - 18,
                            mid, font="H", size=7, color=FAINT)
            self.w._cur = saved
