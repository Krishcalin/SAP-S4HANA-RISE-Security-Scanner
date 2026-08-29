"""
PPTX Presentation Generator
===========================
Builds a concise, meeting-ready PowerPoint deck that SUMMARISES the scan — risk
posture, prioritized queue, top findings, category spread, compliance snapshot
and themed recommended actions. Deliberately high-level: the exhaustive per-
finding risk/remediation detail lives in the HTML/PDF reports, not here.

Standard library only, via `modules.pptx_writer`.
"""
import re
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.pptx_writer import PPTXWriter, Inches
from modules.compliance_mapping import ComplianceMapper
from modules.finding_kb import FindingKB
from modules import posture_score

# ── palette (matches the HTML/PDF report) ──
NAVY = "0B2138"
ACCENT = "0369A1"
INK = "1F2933"
SUB = "475569"
MUTED = "64748B"
LIGHT = "F5F7FA"
CARD = "FFFFFF"
BORDER = "E2E8F0"
WHITE = "FFFFFF"
LTBLUE = "9DC3E6"
SEV = {"CRITICAL": "DC2626", "HIGH": "EA580C", "MEDIUM": "B45309", "LOW": "15803D"}
#: Posture band -> colour, keyed by the band names modules/posture_score.py
#: derives from the severity weights.
_BAND_COLOR = {"Critical": SEV["CRITICAL"], "High": SEV["HIGH"],
               "Medium": SEV["MEDIUM"], "Low": SEV["LOW"]}
TIER = {"P1": "DC2626", "P2": "EA580C", "P3": "B45309", "P4": "15803D"}
_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# theme → one-line recommended action (for the summarised actions slide)
THEME_ACTION = {
    "privileged-access": "Remove standing privileged access; provision admin rights via reviewed roles and time-boxed firefighter (EAM).",
    "access-control": "Enforce least privilege — eliminate wildcard, generic and unrestricted access grants.",
    "authentication": "Strengthen password hashing/policy and enforce MFA / corporate-IdP single sign-on.",
    "sod": "Remediate Segregation-of-Duties conflicts and formalise monitored mitigating controls.",
    "cryptography": "Turn on encryption everywhere — HANA data/log/backup at rest, TLS and SNC in transit.",
    "data-protection": "Activate Read Access Logging, ILM retention and UI data masking (GDPR readiness).",
    "logging-monitoring": "Enable and tamper-protect the Security Audit Log; forward events to the SIEM.",
    "vuln-mgmt": "Apply the missing HotNews / actively-exploited SAP Security Notes without delay.",
    "secure-config": "Harden profile parameters to the SAP Security Baseline / CIS.",
    "network-security": "Lock down the RFC gateway, message server, ICF services and stored destinations.",
    "change-management": "Enforce dev/test/prod separation and a controlled transport process.",
    "backup-recovery": "Fix HANA log_mode/point-in-time recovery and verify encrypted, restorable backups.",
    "app-security": "Secure OData/Fiori exposure (S_SERVICE) and remediate custom-ABAP injection risks.",
    "incident-response": "Define and rehearse an SAP-specific incident-response and escalation runbook.",
    "supplier-cloud": "Harden BTP and the Cloud Connector; clarify the RISE shared-responsibility split.",
}
THEME_LABEL = {
    "privileged-access": "Privileged access", "access-control": "Access control",
    "authentication": "Authentication", "sod": "Segregation of duties",
    "cryptography": "Cryptography", "data-protection": "Data protection",
    "logging-monitoring": "Logging & monitoring", "vuln-mgmt": "Patch management",
    "secure-config": "Secure configuration", "network-security": "Network security",
    "change-management": "Change management", "backup-recovery": "Backup & recovery",
    "app-security": "Application security", "incident-response": "Incident response",
    "supplier-cloud": "Cloud / BTP",
}


def _p(text, sz, b=False, color=INK, align="l", bullet=False, spc=0, i=False, font="Calibri"):
    return {"runs": [{"t": text, "sz": sz, "b": b, "color": color, "i": i, "font": font}],
            "align": align, "bullet": bullet, "space_before": spc}


def _img_dims(path: str):
    """Return (w, h) of a PNG; (None, None) on failure."""
    try:
        d = open(path, "rb").read(33)
        if d[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", d[16:24])
            return w, h
    except Exception:
        pass
    return None, None


class PPTXReportGenerator:
    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 kb: Optional[FindingKB] = None, priorities: Optional[List[Any]] = None,
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
        self.coverage = coverage
        self.pageno = 0
        self.assets = Path(__file__).resolve().parent.parent / "assets"

        by = {}
        cat = {}
        for f in findings:
            by[f["severity"]] = by.get(f["severity"], 0) + 1
            cat[f["category"]] = cat.get(f["category"], 0) + 1
        self.by_sev, self.by_cat = by, cat
        self.crit = by.get("CRITICAL", 0)
        self.high = by.get("HIGH", 0)
        self.med = by.get("MEDIUM", 0)
        self.low = by.get("LOW", 0)
        self.total = len(findings)
        # THE POSTURE SCORE DESCRIBES THE ESTATE, so it counts the estate —
        # see the same note in modules/report_generator.py. The severity counts
        # above it stay on the listed findings, which is what they are labelled as.
        # DENSITY OVER WHAT WAS ASSESSED — see modules/posture_score.py. The old
        # total clamped at 100 on any real estate and fell when less was supplied.
        scored = posture_score.score_with_scope(self.full_findings, self.coverage)
        if scored is None:
            self.risk_score, self.risk_label = None, "Not scored"
            self.risk_color = "64748B"
            self.risk_note = (
                "No coverage manifest \u2014 how many checks ran is unknown, so "
                "there is nothing to score against."
                if coverage is None else
                "No module completed a check in this scan \u2014 see the "
                "coverage slide.")
        else:
            self.risk_score, self.risk_label, assessed = scored
            self.risk_color = _BAND_COLOR[self.risk_label]
            self.risk_note = (posture_score.ANCHOR + " "
                              + posture_score.scope_note(assessed))

        if priorities is None:
            try:
                from modules.risk_prioritizer import RiskPrioritizer
                priorities = RiskPrioritizer().prioritize(findings)
            except Exception:
                priorities = []
        self._prio = {id(getattr(p, "finding", None)): p for p in (priorities or [])
                      if getattr(p, "finding", None) is not None}
        self.tier_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for p in (priorities or []):
            if getattr(p, "tier", None) in self.tier_counts:
                self.tier_counts[p.tier] += 1
        try:
            from modules.risk_prioritizer import TIER_META
            self.tier_meta = TIER_META
        except Exception:
            self.tier_meta = {}
        self.compliance = ComplianceMapper(self.full_findings).assess()

    def _tier_of(self, f):
        return self._prio.get(id(f))

    def _new(self):
        self.pageno += 1
        return self.w.add_slide()

    @staticmethod
    def _summarize(text: str, max_sentences: int = 4, max_chars: int = 620) -> str:
        """Condense a long KB narrative to a slide-sized gist (whole sentences up
        to a budget) so each finding stays high-level and readable."""
        text = " ".join(str(text or "").split())
        if not text:
            return ""
        parts = re.split(r"(?<=[.!?])\s+", text)
        out, n = "", 0
        for p in parts:
            if n >= max_sentences:
                break
            if out and len(out) + len(p) + 1 > max_chars:
                break
            out = (out + " " + p).strip()
            n += 1
        if not out:
            out = text[:max_chars].rstrip()
        if len(out) < len(text):
            out = out.rstrip(".") + " …"
        return out

    def _fix_first(self):
        def key(f):
            pr = self._tier_of(f)
            trank = _TIER_RANK.get(getattr(pr, "tier", None), 9) if pr else 9
            score = -getattr(pr, "score", 0) if pr else 0
            return (trank, _SEV_RANK.get(f.get("severity"), 4), score)
        return sorted(self.findings, key=key)

    # ── chrome ──
    def _heading(self, s, kicker, title):
        W = self.w.W
        s.rect(Inches(0.6), Inches(0.55), Inches(0.09), Inches(0.34), fill=ACCENT)
        s.text(Inches(0.8), Inches(0.5), W - Inches(1.4), Inches(0.35),
               [_p(kicker.upper(), 12, b=True, color=ACCENT)])
        s.text(Inches(0.78), Inches(0.82), W - Inches(1.4), Inches(0.6),
               [_p(title, 27, b=True, color=INK)])
        s.rect(Inches(0.6), Inches(1.52), W - Inches(1.2), Inches(0.014), fill=BORDER)

    def _footer(self, s):
        W, H = self.w.W, self.w.H
        s.text(Inches(0.6), H - Inches(0.42), W - Inches(3.0), Inches(0.3),
               [_p("MonitorRisk  ·  SAP S/4HANA RISE Security Assessment  ·  CONFIDENTIAL", 8, color=MUTED)])
        s.text(W - Inches(1.4), H - Inches(0.42), Inches(0.8), Inches(0.3),
               [_p(str(self.pageno), 8, color=MUTED, align="r")])

    # ── slides ──
    def generate(self, output_path: str, full: bool = True):
        """full=True → executive front matter + per-framework compliance mapping +
        one slide per finding (300+ slides). full=False → the short exec deck."""
        self.w = PPTXWriter(title="SAP S/4HANA RISE — Security Assessment",
                            author="MonitorRisk")
        self.pageno = 0
        # executive front matter
        self._slide_title()
        self._slide_coverage()
        self._slide_exec()
        self._slide_priority()
        self._slide_categories()
        self._slide_domains()
        self._slide_actions()
        # compliance mapping
        self._slide_compliance()
        if not full:
            self._slide_top()
            self._slide_close()
            self.w.save(output_path)
            return
        for fw in [f for f in self.compliance if f["controls"]]:
            self._slide_compliance_framework(fw)
        # detailed findings — one per slide, fix-first order
        ordered = self._fix_first()
        total = len(ordered)
        self._slide_divider(
            "Detailed Findings",
            "%d findings, one per slide, in fix-first (P1→P4) order — each with the "
            "security risk and high-level mitigation. Full step-by-step remediation is in "
            "the HTML / PDF report." % total)
        for i, f in enumerate(ordered, 1):
            self._slide_finding(f, i, total)
        self._slide_close()
        self.w.save(output_path)

    def _logo(self, s, path, x, y, target_h_in, right_x=None):
        w, h = _img_dims(path)
        if not w:
            return
        h_emu = Inches(target_h_in)
        w_emu = int(h_emu * (w / h))
        if right_x is not None:
            x = right_x - w_emu
        s.image(x, y, w_emu, h_emu, path)

    def _slide_title(self):
        s = self._new()
        W, H = self.w.W, self.w.H
        # logos on white top strip
        sap = str(self.assets / "sap-logo.png")
        brand = str(self.assets / "monitorrisk-logo.png")
        if Path(sap).exists():
            self._logo(s, sap, Inches(0.6), Inches(0.5), 0.55)
        if Path(brand).exists():
            self._logo(s, brand, 0, Inches(0.42), 0.72, right_x=W - Inches(0.6))
        # navy title band
        s.rect(0, Inches(1.7), W, Inches(3.5), fill=NAVY)
        s.rect(0, Inches(1.7), W, Inches(0.06), fill=ACCENT)
        s.text(Inches(0.9), Inches(2.05), W - Inches(1.8), Inches(0.5),
               [_p("SAP S/4HANA RISE", 17, b=True, color=LTBLUE)])
        s.text(Inches(0.87), Inches(2.5), W - Inches(1.8), Inches(1.1),
               [_p("Security Assessment Report", 40, b=True, color=WHITE)])
        s.text(Inches(0.9), Inches(3.7), W - Inches(1.8), Inches(0.5),
               [_p("Offline configuration review  ·  S/4HANA · HANA · BTP / Cloud", 14, color="B9C6D6")])
        s.text(Inches(0.9), Inches(4.25), W - Inches(1.8), Inches(0.5),
               [_p("Executive summary for management review", 12, i=True, color="8FA3B8")])
        # metadata + confidentiality
        date = str(self.meta.get("scan_time", ""))[:19].replace("T", "  ")
        s.text(Inches(0.6), Inches(5.5), W - Inches(1.2), Inches(0.4),
               [_p("Assessment date: %s      Findings: %d      Risk posture: %s"
                   % (date, self.total, self.risk_label.upper()), 12, b=True, color=INK)])
        # A FILTERED DECK SAYS SO ON ITS FIRST SLIDE. "Findings: 84" is the
        # sentence a room remembers, and if a display filter produced it while
        # the framework slides describe all 341, the deck has to reconcile the
        # two itself — nobody in the room can open the CLI history.
        chosen = str(self.meta.get("severity_filter", "ALL") or "ALL").upper()
        if chosen != "ALL":
            hidden = max(0, len(self.full_findings) - self.total)
            s.text(Inches(0.6), Inches(5.9), W - Inches(1.2), Inches(0.5),
                   [_p("Severity filter: %s or above. %d finding(s) below it are not "
                       "listed; the framework slides cover all %d."
                       % (chosen, hidden, len(self.full_findings)), 10, color=SUB)])
        s.text(Inches(0.6), Inches(6.35), W - Inches(1.2), Inches(1.0),
               [_p("CONFIDENTIAL — contains sensitive SAP security information; distribute only to "
                   "authorized security, Basis and audit personnel. Point-in-time, offline analysis "
                   "of exported configuration; no SAP system was connected to or modified.", 9,
                   color=MUTED)])
        s.text(Inches(0.6), H - Inches(0.55), W - Inches(1.2), Inches(0.35),
               [_p("Prepared with MonitorRisk — SAP threat, vulnerability & GRC posture", 9,
                   b=True, color=ACCENT)])

    def _stat_card(self, s, x, y, w, h, top_color, big, big_color, label, sub=None):
        s.rect(x, y, w, h, fill=CARD, line=BORDER, line_w=1.0, round_=True)
        s.rect(x, y, w, Inches(0.07), fill=top_color)
        s.text(x, y + Inches(0.28), w, Inches(0.9),
               [_p(str(big), 40, b=True, color=big_color, align="ctr")])
        s.text(x, y + h - Inches(0.5), w, Inches(0.35),
               [_p(label, 11, b=True, color=MUTED, align="ctr")])
        if sub:
            s.text(x, y + h - Inches(0.3), w, Inches(0.3), [_p(sub, 8, color=MUTED, align="ctr")])

    def _slide_exec(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Executive summary", "Risk Posture at a Glance")
        # risk score card (left)
        rc_x, rc_y, rc_w, rc_h = Inches(0.6), Inches(1.95), Inches(3.5), Inches(2.7)
        s.rect(rc_x, rc_y, rc_w, rc_h, fill=NAVY, round_=True)
        s.rect(rc_x, rc_y, rc_w, Inches(0.08), fill=self.risk_color)
        s.text(rc_x, rc_y + Inches(0.3), rc_w, Inches(0.35),
               [_p("OVERALL RISK SCORE", 11, b=True, color="9DB2C6", align="ctr")])
        s.text(rc_x, rc_y + Inches(0.72), rc_w, Inches(1.2),
               [_p("n/a" if self.risk_score is None else "%d" % self.risk_score,
                   66, b=True, color=WHITE, align="ctr")])
        s.text(rc_x, rc_y + Inches(1.78), rc_w, Inches(0.35),
               [_p(self.risk_label.upper()
                   + ("  ·  out of 100" if self.risk_score is not None else ""),
                   13, b=True, color=self.risk_color, align="ctr")])
        # The anchor, so the number is interpretable. It is a density, not a
        # percentage of anything, and a slide is exactly where that gets assumed.
        s.text(rc_x + Inches(0.2), rc_y + Inches(2.12), rc_w - Inches(0.4), Inches(0.5),
               [_p(self.risk_note, 8, color="9DB2C6", align="ctr")])
        # severity cards (right, 2x2)
        gx = Inches(4.35)
        gw = W - gx - Inches(0.6)
        cw = (gw - Inches(0.45)) / 2
        ch = Inches(1.25)
        cells = [("CRITICAL", self.crit), ("HIGH", self.high), ("MEDIUM", self.med), ("LOW", self.low)]
        for i, (name, n) in enumerate(cells):
            cxx = gx + (i % 2) * (cw + Inches(0.45))
            cyy = Inches(1.95) + (i // 2) * (ch + Inches(0.2))
            self._stat_card(s, cxx, cyy, cw, ch, SEV[name], n, SEV[name], name)
        # takeaway
        s.rect(Inches(0.6), Inches(5.05), W - Inches(1.2), Inches(1.5), fill=LIGHT,
               line=BORDER, line_w=1.0, round_=True)
        mods = len(self.meta.get("modules_run", []) or [])
        s.text(Inches(0.85), Inches(5.2), W - Inches(1.7), Inches(0.4),
               [_p("KEY TAKEAWAY", 11, b=True, color=ACCENT)])
        s.text(Inches(0.85), Inches(5.55), W - Inches(1.7), Inches(1.0),
               [_p("%d findings were identified across %d audit modules. %d Critical and %d High "
                   "issues are directly exploitable or materially weaken security/compliance and need "
                   "prioritised remediation. Work the P1–P4 queue top-down; the detailed HTML/PDF "
                   "report gives per-finding risk and step-by-step remediation."
                   % (self.total, mods or 23, self.crit, self.high), 13, color=INK)])
        self._footer(s)

    def _slide_priority(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Prioritisation", "Risk-Prioritized Remediation Queue")
        s.text(Inches(0.6), Inches(1.7), W - Inches(1.2), Inches(0.5),
               [_p("Findings ranked by severity × real-world exploitability (SAP HotNews / "
                   "actively-exploited notes) × exposure. Fix top-down: P1 first.", 12, color=SUB)])
        cw = (W - Inches(1.2) - Inches(0.9)) / 4
        y = Inches(2.4)
        h = Inches(2.7)
        for i, t in enumerate(("P1", "P2", "P3", "P4")):
            x = Inches(0.6) + i * (cw + Inches(0.3))
            m = self.tier_meta.get(t, {})
            s.rect(x, y, cw, h, fill=CARD, line=BORDER, line_w=1.0, round_=True)
            s.rect(x, y, cw, Inches(0.09), fill=TIER[t])
            s.text(x, y + Inches(0.28), cw, Inches(0.7),
                   [_p(t, 40, b=True, color=TIER[t], align="ctr")])
            s.text(x, y + Inches(1.15), cw, Inches(0.6),
                   [_p(str(self.tier_counts.get(t, 0)), 30, b=True, color=INK, align="ctr")])
            s.text(x, y + Inches(1.75), cw, Inches(0.35),
                   [_p(m.get("label", ""), 12, b=True, color=SUB, align="ctr")])
            s.text(x, y + Inches(2.1), cw, Inches(0.5),
                   [_p(m.get("window", ""), 10, color=MUTED, align="ctr")])
        s.text(Inches(0.6), Inches(5.5), W - Inches(1.2), Inches(0.6),
               [_p("P1 = fix now · P2 = this week · P3 = planned (30 days) · P4 = backlog. "
                   "Tiers already fold in exploitability, so a 'High' that is actively exploited "
                   "outranks an unexploited 'Critical'.", 11, i=True, color=MUTED)])
        self._footer(s)

    def _slide_top(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Where to start", "Top Priorities to Fix First")
        ranked = [(f, self._tier_of(f)) for f in self.findings if self._tier_of(f)]
        ranked.sort(key=lambda x: (_TIER_RANK.get(x[1].tier, 9), -getattr(x[1], "score", 0)))
        top = [(f, pr) for f, pr in ranked if pr.tier in ("P1", "P2")][:6]
        y = Inches(1.8)
        rh = Inches(0.82)
        for f, pr in top:
            s.rect(Inches(0.6), y, W - Inches(1.2), rh - Inches(0.12), fill=LIGHT,
                   line=BORDER, line_w=0.8, round_=True)
            # tier badge
            s.rect(Inches(0.75), y + Inches(0.16), Inches(0.95), Inches(0.38),
                   fill=TIER[pr.tier], round_=True)
            s.text(Inches(0.75), y + Inches(0.2), Inches(0.95), Inches(0.32),
                   [_p("%s · %d" % (pr.tier, getattr(pr, "score", 0)), 12, b=True,
                       color=WHITE, align="ctr")])
            # title + why
            tx = Inches(1.9)
            tw = W - Inches(1.2) - Inches(1.5)
            s.text(tx, y + Inches(0.06), tw, Inches(0.34),
                   [_p(f.get("title", ""), 13, b=True, color=INK)])
            why = (getattr(pr, "rationale", "") or "").strip()
            s.text(tx, y + Inches(0.4), tw, Inches(0.34),
                   [_p((why or f.get("check_id", ""))[:150], 10, color=SUB)])
            # check id (right)
            s.text(W - Inches(2.4), y + Inches(0.06), Inches(1.7), Inches(0.3),
                   [_p(f.get("check_id", ""), 10, b=True, color=MUTED, align="r")])
            y += rh
        s.text(Inches(0.6), y + Inches(0.05), W - Inches(1.2), Inches(0.4),
               [_p("Full ranked queue and per-finding remediation steps are in the detailed report.",
                   10, i=True, color=MUTED)])
        self._footer(s)

    def _slide_categories(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Where the risk is", "Findings by Area")
        top = sorted(self.by_cat.items(), key=lambda x: -x[1])[:8]
        maxc = max((n for _, n in top), default=1)
        y = Inches(1.9)
        bar_x = Inches(4.6)
        bar_full = W - bar_x - Inches(1.1)
        rh = Inches(0.58)
        for cat, n in top:
            s.text(Inches(0.6), y, Inches(3.9), Inches(0.4),
                   [_p(cat, 12, b=True, color=INK)])
            s.rect(bar_x, y + Inches(0.03), bar_full, Inches(0.26), fill=LIGHT, round_=True)
            s.rect(bar_x, y + Inches(0.03), max(Inches(0.1), int(bar_full * n / maxc)),
                   Inches(0.26), fill=ACCENT, round_=True)
            s.text(W - Inches(1.0), y - Inches(0.02), Inches(0.6), Inches(0.35),
                   [_p(str(n), 12, b=True, color=SUB, align="r")])
            y += rh
        s.text(Inches(0.6), y + Inches(0.15), W - Inches(1.2), Inches(0.4),
               [_p("Top 8 of %d finding categories shown." % len(self.by_cat), 10, i=True, color=MUTED)])
        self._footer(s)

    def _slide_domains(self):
        """The twelve domains, in the vocabulary the audience arrived with.

        DIRECTLY AFTER "Findings by Area", because it answers the question that
        slide provokes: a reader looking at "Network & Integration Layer: 32"
        wants to know which of the twelve things on their checklist that is.

        WHAT THIS SLIDE MUST NOT BECOME. Twelve numbers on a projector assert
        twelve capabilities, and a deck is read further from its author than any
        other artefact we produce — nobody in the room can hover over a tile. So
        every line carries the reach word beside the count, the domain we do not
        do carries a dash instead of a zero, and the sentence at the foot says
        plainly that this is configuration rather than monitoring. A slide is
        exactly where that qualifier gets dropped for space, so it is the one
        thing here with a fixed position.
        """
        try:
            from modules import domains
        except Exception:                                # noqa: BLE001
            return
        rolled = domains.roll_up(self.full_findings, coverage=self.coverage)
        reach_word = {domains.FULL: "fully assessed",
                      domains.PARTIAL: "partly assessed",
                      domains.CONFIG_ONLY: "configuration only",
                      domains.NONE: "not covered"}

        s = self._new()
        W = self.w.W
        self._heading(s, "Coverage in your words", "The Twelve Security Domains")

        rows = rolled["domains"]
        half = (len(rows) + 1) // 2
        col_w = (W - Inches(1.2) - Inches(0.4)) / 2
        for col, group in enumerate((rows[:half], rows[half:])):
            x = Inches(0.6) + col * (col_w + Inches(0.4))
            y = Inches(1.8)
            for d in group:
                covered = d["reach"] != domains.NONE
                # THE STATE AXIS, WHICH THIS SLIDE USED TO COMPUTE AND DISCARD.
                # roll_up() is handed the manifest above and returns both axes;
                # only `reach` was ever read, so a domain whose export never
                # arrived printed "0" beside "fully assessed" — the reach word
                # reading as a verdict, which is the one thing the two-axis
                # design exists to prevent. Measured on a users-only export:
                # four tiles.
                unmeasured = (not covered
                              or d["state"] in (domains.NOT_SUPPLIED,
                                                domains.NOT_ASSESSED))
                s.text(x, y, col_w - Inches(0.9), Inches(0.3),
                       [_p(d["label"], 11, b=True, color=INK)])
                s.text(x + col_w - Inches(0.9), y - Inches(0.02), Inches(0.85),
                       Inches(0.3),
                       [_p("—" if unmeasured else str(d["total"]), 13, b=True,
                           color=MUTED if unmeasured else INK, align="r")])
                # The second line carries the reach word normally, and is
                # overridden by the run-specific state when there is one —
                # "configuration only" is not the useful sentence about a domain
                # whose export never arrived.
                if covered and d["state"] == domains.NOT_SUPPLIED:
                    caption = "export not supplied"
                elif covered and d["state"] == domains.CLEAR:
                    caption = reach_word[d["reach"]] + " · no findings"
                else:
                    caption = reach_word[d["reach"]]
                s.text(x, y + Inches(0.24), col_w - Inches(0.9), Inches(0.26),
                       [_p(caption, 8, color=MUTED)])
                y += Inches(0.52)

        note = ("Two facts per domain: the count is what this scan found, the "
                "line beneath it is what this product can ever see there. Where a "
                "domain names a continuous activity — event monitoring, interface "
                "traffic, user behaviour — what we contribute is an assessment of "
                "the configuration behind it. A dash is a boundary of this "
                "product, not a clean result about your estate.")
        if rolled["unplaced"]["total"]:
            note += (" %d findings sit outside this vocabulary and are reported "
                     "separately rather than dropped." % rolled["unplaced"]["total"])
        s.text(Inches(0.6), Inches(4.95), W - Inches(1.2), Inches(1.0),
               [_p(note, 9, color=SUB)])
        self._footer(s)

    def _slide_coverage(self):
        """What the scan could not look at.

        SECOND, RIGHT AFTER THE TITLE, and before the executive summary. This is
        the deck an executive reads, often only the first three slides, and a
        finding count met before the coverage anchors on the wrong number. The
        deck carried nothing of this until now: a customer who supplied a fraction
        of the exports got a clean-looking summary with no indication that most
        checks never ran.
        """
        manifest = self.coverage
        s = self._new()
        W = self.w.W
        self._heading(s, "Scope", "What This Scan Could Not Look At")

        if manifest is None:
            s.text(Inches(0.6), Inches(1.9), W - Inches(1.2), Inches(1.2),
                   [_p("Coverage could not be determined for this scan. This deck "
                       "cannot say how much of the estate it saw, so the findings "
                       "that follow are a floor rather than a survey.",
                       13, color=INK)])
            return

        counts = manifest.get("counts", {})
        s.text(Inches(0.6), Inches(1.68), W - Inches(1.2), Inches(0.6),
               [_p(manifest.get("summary", ""), 11, color=SUB)])

        # Five cards, not four. `modules_not_run` was computed on every run and
        # displayed nowhere, so a deck built from `--modules users` showed three
        # reassuring zeroes over a scan in which twenty-nine modules never ran.
        # Counted from the findings, not the manifest: the manifest counts
        # MODULES that ran degraded, this counts the conclusions a reader is
        # actually looking at.
        partial_findings = sum(
            1 for f in self.findings
            if not (f.get("evidence") or {}).get("complete", True))
        cards = [
            (str(counts.get("sources_supplied", 0)) + " / " + str(counts.get("sources_known", 0)),
             "logical sources supplied"),
            (str(counts.get("modules_degraded", 0)), "modules on partial input"),
            (str(counts.get("modules_skipped", 0)), "modules had no input"),
            (str(counts.get("modules_not_run", 0)), "modules not executed"),
            (str(counts.get("sources_empty", 0)), "files present but empty"),
            (str(partial_findings), "findings on partial data"),
        ]
        x = Inches(0.6)
        cw = (W - Inches(1.2) - Inches(1.2)) / len(cards)
        for value, caption in cards:
            s.text(x, Inches(2.5), cw, Inches(0.6), [_p(value, 26, b=True, color=INK)])
            s.text(x, Inches(3.1), cw, Inches(0.5), [_p(caption, 10, color=SUB)])
            x += cw + Inches(0.3)

        s.text(Inches(0.6), Inches(4.0), W - Inches(1.2), Inches(0.9),
               [_p("A module that did not run produces no findings, and no findings "
                   "is not a clean result — it is an unexamined one. The slides that "
                   "follow describe the part of the estate this scan could see.",
                   11, color=SUB)])

    def _slide_compliance(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Audit view", "Compliance & Control-Framework Snapshot")
        s.text(Inches(0.6), Inches(1.68), W - Inches(1.2), Inches(0.5),
               [_p("Findings mapped to the control areas of common frameworks — a gap view for audit "
                   "navigation, not a certification.", 11, color=SUB)])
        # No cap. This was `[:6]` back when there were exactly six frameworks, so
        # the truncation was invisible; adding NIST 800-53 and DORA silently
        # dropped two of them off this slide. In --pptx-mode summary this is the
        # ONLY compliance slide, so a framework missing here is missing from the
        # deck — and a compliance overview that quietly omits frameworks is worse
        # than one that admits it covers none.
        fws = [f for f in self.compliance if f["controls"]]
        y = Inches(2.35)
        rh = Inches(0.66)
        bar_x = Inches(6.6)
        bar_full = W - bar_x - Inches(1.4)
        for fw in fws:
            s.text(Inches(0.6), y, Inches(4.2), Inches(0.35),
                   [_p(fw["name"], 13, b=True, color=INK)])
            s.text(Inches(0.6), y + Inches(0.32), Inches(5.8), Inches(0.3),
                   [_p(fw["subtitle"], 9, color=MUTED)])
            # THE BAR IS GONE, AND IT IS NOT COMING BACK AS A CAPTION.
            #
            # It drew controls_flagged / total_controls in a risk colour. A bar
            # length IS a percentage and the colour gives it a direction, so this
            # was a compliance score in everything but name —
            # modules/compliance_mapping.py forbids one in as many words: "we see
            # the findings, not the control environment, so any percentage would
            # be a coverage claim about evidence we do not hold."
            #
            # The counts below say what is true without implying a denominator
            # means completeness.
            s.rect(bar_x, y + Inches(0.08), bar_full, Inches(0.24), fill=LIGHT, round_=True)
            s.text(W - Inches(0.75), y, Inches(0.15) + Inches(0.0), Inches(0.35), [_p("", 9)])
            s.text(bar_x, y + Inches(0.34), bar_full + Inches(0.7), Inches(0.3),
                   [_p("%d of %d control areas flagged  ·  %d findings mapped"
                       % (fw["controls_flagged"], fw["total_controls"], fw["mapped_findings"]),
                       9, color=SUB)])
            y += rh
        self._footer(s)

    def _slide_actions(self):
        s = self._new()
        W = self.w.W
        self._heading(s, "Recommendations", "Recommended Actions")
        # findings per theme
        theme_ct = {}
        for f in self.full_findings:
            for th in ComplianceMapper.CATEGORY_THEMES.get(f.get("category", ""), []):
                theme_ct[th] = theme_ct.get(th, 0) + 1
        top = sorted(theme_ct.items(), key=lambda x: -x[1])[:6]
        y = Inches(1.85)
        rh = Inches(0.82)
        for i, (th, n) in enumerate(top, 1):
            s.rect(Inches(0.6), y, Inches(0.45), Inches(0.45), fill=ACCENT, round_=True)
            s.text(Inches(0.6), y + Inches(0.06), Inches(0.45), Inches(0.34),
                   [_p(str(i), 16, b=True, color=WHITE, align="ctr")])
            s.text(Inches(1.25), y - Inches(0.02), W - Inches(2.6), Inches(0.36),
                   [_p("%s  (%d findings)" % (THEME_LABEL.get(th, th), n), 13, b=True, color=INK)])
            s.text(Inches(1.25), y + Inches(0.34), W - Inches(2.0), Inches(0.4),
                   [_p(THEME_ACTION.get(th, ""), 11, color=SUB)])
            y += rh
        self._footer(s)

    def _slide_close(self):
        s = self._new()
        W, H = self.w.W, self.w.H
        s.rect(0, 0, W, H, fill=NAVY)
        s.rect(0, Inches(2.6), W, Inches(0.06), fill=ACCENT)
        s.text(Inches(0.9), Inches(1.1), W - Inches(1.8), Inches(0.5),
               [_p("NEXT STEPS", 14, b=True, color=LTBLUE)])
        s.text(Inches(0.9), Inches(1.5), W - Inches(1.8), Inches(0.9),
               [_p("From assessment to remediation", 32, b=True, color=WHITE)])
        steps = [
            "Assign owners for the P1 findings and remediate within 24–72 hours.",
            "Schedule P2 for this week; track P3/P4 in the backlog with due dates.",
            "Apply the missing HotNews / actively-exploited SAP Notes first.",
            "Re-scan after remediation to confirm closure and update the posture.",
            "Use the detailed HTML/PDF report for per-finding risk and step-by-step fixes.",
        ]
        y = Inches(2.95)
        for st in steps:
            s.text(Inches(1.0), y, W - Inches(2.0), Inches(0.5),
                   [_p(st, 14, color="E5ECF4", bullet=True)])
            y += Inches(0.52)
        s.text(Inches(0.9), H - Inches(0.9), W - Inches(1.8), Inches(0.5),
               [_p("MonitorRisk — SAP threat, vulnerability & GRC posture", 11,
                   b=True, color=LTBLUE)])
        s.text(Inches(0.9), H - Inches(0.6), W - Inches(1.8), Inches(0.4),
               [_p("For lawful, authorized security testing and educational use only.", 9,
                   color="8FA3B8")])

    # ── full-deck slides ──
    def _slide_divider(self, title, subtitle):
        s = self._new()
        W, H = self.w.W, self.w.H
        s.rect(0, 0, W, H, fill=NAVY)
        s.rect(0, Inches(3.0), W, Inches(0.06), fill=ACCENT)
        s.text(Inches(0.9), Inches(2.15), W - Inches(1.8), Inches(0.9),
               [_p(title, 40, b=True, color=WHITE)])
        s.text(Inches(0.9), Inches(3.25), W - Inches(1.8), Inches(1.4),
               [_p(subtitle, 14, color="B9C6D6")])
        self._footer(s)

    def _slide_compliance_framework(self, fw):
        s = self._new()
        W = self.w.W
        self._heading(s, "Compliance mapping", fw["name"])
        s.text(Inches(0.6), Inches(1.66), W - Inches(1.2), Inches(0.4),
               [_p("%s   ·   %d of %d control areas flagged   ·   %d findings mapped"
                   % (fw["subtitle"], fw["controls_flagged"], fw["total_controls"],
                      fw["mapped_findings"]), 12, b=True, color=SUB)])
        xs = [W - Inches(0.6) - Inches(0.7) * k for k in (4, 3, 2, 1)]  # Crit High Med Low
        heads = ["Crit", "High", "Med", "Low"]
        y = Inches(2.2)
        s.rect(Inches(0.6), y, W - Inches(1.2), Inches(0.32), fill=NAVY)
        s.text(Inches(0.75), y + Inches(0.04), Inches(1.4), Inches(0.26),
               [_p("CONTROL", 9, b=True, color=WHITE)])
        s.text(Inches(2.25), y + Inches(0.04), Inches(4.0), Inches(0.26),
               [_p("AREA", 9, b=True, color=WHITE)])
        for xh, h in zip(xs, heads):
            s.text(xh, y + Inches(0.04), Inches(0.7), Inches(0.26),
                   [_p(h, 9, b=True, color=WHITE, align="ctr")])
        y += Inches(0.32)
        controls = fw["controls"][:12]
        rh = Inches(0.34)
        area_w = xs[0] - Inches(2.25) - Inches(0.1)
        for ri, c in enumerate(controls):
            if ri % 2 == 0:
                s.rect(Inches(0.6), y, W - Inches(1.2), rh, fill=LIGHT)
            s.text(Inches(0.75), y + Inches(0.05), Inches(1.4), Inches(0.26),
                   [_p(c["id"], 10, b=True, color=INK)])
            s.text(Inches(2.25), y + Inches(0.05), area_w, Inches(0.26),
                   [_p(c["name"], 10, color=INK)])
            vals = [(c["crit"], SEV["CRITICAL"]), (c["high"], SEV["HIGH"]),
                    (c["med"], SEV["MEDIUM"]), (c["low"], SEV["LOW"])]
            for xh, (v, cc) in zip(xs, vals):
                s.text(xh, y + Inches(0.05), Inches(0.7), Inches(0.26),
                       [_p(str(v) if v else "·", 10, b=bool(v),
                           color=cc if v else BORDER, align="ctr")])
            y += rh
        if len(fw["controls"]) > 12:
            s.text(Inches(0.6), y + Inches(0.06), W - Inches(1.2), Inches(0.3),
                   [_p("… and %d more control area(s) — full list in the HTML / PDF report."
                       % (len(fw["controls"]) - 12), 9, i=True, color=MUTED)])
        self._footer(s)

    def _slide_finding(self, f, idx, total):
        s = self._new()
        W, H = self.w.W, self.w.H
        pr = self._tier_of(f)
        sev = f.get("severity", "INFO")
        col = SEV.get(sev, MUTED)
        # kicker + title
        s.rect(Inches(0.6), Inches(0.5), Inches(0.09), Inches(0.3), fill=col)
        s.text(Inches(0.8), Inches(0.46), W - Inches(1.4), Inches(0.3),
               [_p("FINDING %d OF %d   ·   %s" % (idx, total, f.get("category", "").upper()),
                   10, b=True, color=ACCENT)])
        s.text(Inches(0.78), Inches(0.74), W - Inches(1.4), Inches(0.85),
               [_p(f.get("title", ""), 20, b=True, color=INK)])
        # chips row
        cy = Inches(1.66)
        s.rect(Inches(0.8), cy, Inches(1.15), Inches(0.32), fill=col, round_=True)
        s.text(Inches(0.8), cy + Inches(0.05), Inches(1.15), Inches(0.24),
               [_p(sev, 11, b=True, color=WHITE, align="ctr")])
        if pr:
            s.rect(Inches(2.1), cy, Inches(1.5), Inches(0.32), fill=TIER.get(pr.tier, MUTED), round_=True)
            s.text(Inches(2.1), cy + Inches(0.05), Inches(1.5), Inches(0.24),
                   [_p("%s · score %d" % (pr.tier, getattr(pr, "score", 0)), 10, b=True,
                       color=WHITE, align="ctr")])
        # exploit tags
        tags = []
        if getattr(pr, "exploited", False):
            tags.append("Actively exploited")
        elif getattr(pr, "hotnews", False):
            tags.append("HotNews")
        if getattr(pr, "privileged", False):
            tags.append("Privileged path")
        if getattr(pr, "exposed", False):
            tags.append("Exposed")
        if tags:
            s.text(Inches(3.75), cy + Inches(0.06), Inches(4.6), Inches(0.26),
                   [_p("  ".join(tags), 9, b=True, color=col)])
        # check id + affected count (right)
        aff = f.get("affected_count", len(f.get("affected_items") or []))
        s.text(W - Inches(4.2), cy + Inches(0.05), Inches(3.6), Inches(0.28),
               [_p("%s   ·   %d affected" % (f.get("check_id", ""), aff), 11, b=True,
                   color=MUTED, align="r")])
        # rule
        s.rect(Inches(0.6), Inches(2.12), W - Inches(1.2), Inches(0.014), fill=BORDER)
        # security risk + high-level mitigation (summarised from the KB)
        risk, mitigation, _ = self.kb.detail_for(f)
        s.text(Inches(0.6), Inches(2.25), Inches(4.0), Inches(0.3),
               [_p("SECURITY RISK", 11, b=True, color=col)])
        s.text(Inches(0.6), Inches(2.6), W - Inches(1.2), Inches(1.95),
               [_p(self._summarize(risk, 4, 640), 13, color=INK)])
        s.text(Inches(0.6), Inches(4.7), Inches(4.5), Inches(0.3),
               [_p("HIGH-LEVEL MITIGATION", 11, b=True, color="15803D")])
        s.text(Inches(0.6), Inches(5.05), W - Inches(1.2), Inches(1.75),
               [_p(self._summarize(mitigation, 4, 560), 13, color=INK)])
        self._footer(s)
