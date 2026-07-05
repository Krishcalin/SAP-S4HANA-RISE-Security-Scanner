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

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 kb: Optional[FindingKB] = None):
        self.findings = findings
        self.meta = meta
        self.kb = kb or FindingKB()
        self.w = PDFWriter()
        self.pw, self.ph = self.w.pw, self.w.ph
        self.cw = self.pw - self.ML - self.MR
        self.y = 0.0
        self._content_pages = 0

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

    # ── sections ──
    def generate(self, output_path: str):
        self._cover_page()
        self._exec_summary()
        self._detailed_findings()
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
        # scope / metadata card
        w.rect(self.ML, y - 96, self.cw, 96, fill=LIGHT, stroke=RULE, line_width=0.8)
        mods = ", ".join(self.meta.get("modules_run", [])) or "all"
        kv = [
            ("Assessment date", str(self.meta.get("scan_time", ""))[:19].replace("T", "  ")),
            ("Data source", str(self.meta.get("data_directory", "N/A"))),
            ("Severity filter", str(self.meta.get("severity_filter", "ALL"))),
            ("Modules in scope", mods if len(mods) < 92 else mods[:89] + "..."),
        ]
        yy = y - 20
        for k, v in kv:
            w.text(self.ML + 16, yy, k, font="HB", size=8.5, color=MUTED)
            w.text(self.ML + 150, yy, v, font="H", size=9.5, color=INK)
            yy -= 19

        # risk posture + severity summary
        y2 = y - 128
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

    def _exec_summary(self):
        self._new_content_page()
        self._section_title("Executive Summary")

        total = len(self.findings)
        posture = (
            f"This assessment reviewed the exported SAP configuration and produced {total} "
            f"finding(s): {self.crit} Critical, {self.high} High, {self.med} Medium and "
            f"{self.low} Low. The computed risk score is {self.risk_score}/100, an overall "
            f"'{self.risk_label}' risk posture. Critical and High findings represent issues that "
            "are directly exploitable or materially weaken the system's security or compliance "
            "posture and should be remediated first, in that order. Each finding in the detailed "
            "section below states the specific security risk, the affected objects, and a "
            "step-by-step remediation procedure the Basis / security team can execute."
        )
        self._para(posture, gap_after=8)

        # severity table
        self._label("Severity breakdown")
        rows = [("Severity", "Count", "Share")]
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = self.by_sev.get(name, 0)
            if n == 0 and name == "INFO":
                continue
            pct = (n / total * 100) if total else 0
            rows.append((name.title(), str(n), f"{pct:.0f}%"))
        self._sev_table(rows)
        self.y -= 8

        # category breakdown
        self._label("Findings by category")
        maxc = max(self.by_cat.values()) if self.by_cat else 1
        for cat, n in sorted(self.by_cat.items(), key=lambda x: -x[1]):
            self._ensure(16)
            self.w.text(self.ML, self.y - 8, cat[:46], font="H", size=8.5, color=INK)
            bar_x = self.ML + 210
            bar_w = self.cw - 210 - 30
            self.w.rect(bar_x, self.y - 10, bar_w, 8, fill=LIGHT)
            self.w.rect(bar_x, self.y - 10, max(2, bar_w * n / maxc), 8, fill=ACCENT)
            self.w.text(self.ML + self.cw - 20, self.y - 8, str(n), font="HB", size=8.5, color=MUTED)
            self.y -= 15
        self.y -= 8

        # top priority
        crits = [f for f in self.findings if f["severity"] in ("CRITICAL", "HIGH")]
        crits.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
        if crits:
            self._label("Top-priority findings (Critical & High)")
            for f in crits[:18]:
                self._ensure(15)
                col = SEV_COLOR[f["severity"]]
                self.w.rect(self.ML, self.y - 11, 46, 11, fill=col)
                self.w.text(self.ML + 4, self.y - 9, f["severity"][:4], font="HB", size=7, color=WHITE)
                self.w.text(self.ML + 54, self.y - 9,
                            (f["check_id"] + "  " + f["title"])[:82], font="H", size=8.5, color=INK)
                self.y -= 14.5
            if len(crits) > 18:
                self._para(f"... and {len(crits) - 18} more Critical/High finding(s) in the detailed section.",
                           font="HO", size=8, color=MUTED)

    def _detailed_findings(self):
        self._new_content_page()
        self._section_title("Detailed Findings")
        ordered = sorted(self.findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["check_id"]))
        for f in ordered:
            self._finding_block(f)

    def _finding_block(self, f: Dict[str, Any]):
        sev = f["severity"]
        col = SEV_COLOR.get(sev, MUTED)
        risk, mitigation, detailed = self.kb.detail_for(f)

        # keep the header + first lines together
        self._ensure(58)
        self.y -= 6
        # header bar
        top = self.y
        self.w.rect(self.ML, top - 30, self.cw, 30, fill=LIGHT, stroke=RULE, line_width=0.7)
        self.w.rect(self.ML, top - 30, 4, 30, fill=col)
        self.w.rect(self.ML + 12, top - 21, 54, 13, fill=col)
        self.w.text(self.ML + 16, top - 18.5, sev[:8], font="HB", size=7.5, color=WHITE)
        title = f["title"]
        # title (truncate to fit alongside id)
        self.w.text(self.ML + 74, top - 19, self._fit(title, "HB", 10, self.cw - 74 - 120),
                    font="HB", size=10, color=INK)
        cid = f["check_id"]
        self.w.text(self.pw - self.MR - 10 - self.w.string_width(cid, "H", 8.5), top - 19,
                    cid, font="H", size=8.5, color=MUTED)
        self.y = top - 38
        self.w.text(self.ML, self.y, "Category: " + f.get("category", ""), font="H", size=8, color=MUTED)
        self.y -= 14

        # affected items
        items = f.get("affected_items") or []
        if items:
            self._label("Affected items (%d)" % f.get("affected_count", len(items)))
            for it in items[:12]:
                self._ensure(12)
                self.w.text(self.ML + 8, self.y - 8, "· " + self._fit(str(it), "C", 8, self.cw - 20),
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

        # references
        refs = f.get("references") or []
        if refs:
            self._label("References")
            for r in refs:
                self._ensure(12)
                self.w.text(self.ML + 8, self.y - 8, self._fit("- " + r, "H", 8, self.cw - 16),
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
