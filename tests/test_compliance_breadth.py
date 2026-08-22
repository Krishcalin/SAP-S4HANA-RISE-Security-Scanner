"""
Compliance breadth — the frameworks a buyer's procurement team asks about.

WHY THIS FILE EXISTS
ISO/IEC 27001:2022, NIST SP 800-53 Rev 5 and DORA were added to
`modules/compliance_mapping.py` because their absence is a buying blocker, not a
nice-to-have: DORA is in force for EU financial services and a scanner that
cannot produce a DORA view does not reach the shortlist.

Breadth added carelessly is worse than the gap it closed. Two failure modes are
what this file is actually guarding:

  1. A control id that is WRONG — an ISO 2013 clause number, a NIST control
     enhancement we cannot justify, a DORA article we never verified. The
     customer's auditor pulls on it, it does not say what we implied, and every
     other number in the report is now suspect.

  2. A finding that maps to NOTHING and says nothing about it. A category absent
     from `CATEGORY_THEMES` still reports its findings but vanishes from every
     compliance panel silently. Three categories were in exactly that state
     before this change ("Advanced IAM", "Change Management", "Security Audit Log
     Review"), so this is a measured failure mode, not a hypothetical one.

The negative controls are the point of the file: a clean system must produce an
EMPTY compliance panel, and a framework must not claim controls for evidence it
does not hold.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.compliance_mapping import ComplianceMapper          # noqa: E402


def fw(framework_id: str) -> dict:
    """The raw framework definition, by id."""
    return next(f for f in ComplianceMapper.FRAMEWORKS if f["id"] == framework_id)


def controls(framework_id: str) -> list:
    """Every (id, name) pair a framework declares, across all themes."""
    return [pair for lst in fw(framework_id)["themes"].values() for pair in lst]


def assess(*categories: str, severity: str = "HIGH") -> dict:
    """Run the mapper over one synthetic finding per category → {fw id: result}."""
    findings = [{"category": c, "severity": severity} for c in categories]
    return {r["id"]: r for r in ComplianceMapper(findings).assess()}


def flagged_ids(result: dict) -> set:
    return {c["id"] for c in result["controls"]}


# --------------------------------------------------------------------------- #
#  Regression — the frameworks that already shipped                           #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("framework_id, name", [
    ("iso27001", "ISO/IEC 27001:2022"),
    ("nistcsf", "NIST CSF 2.0"),
    ("cisv8", "CIS Controls v8"),
    ("tisax", "TISAX / VDA ISA"),
    ("soc2", "SOC 2"),
    ("gdpr", "EU GDPR"),
])
def test_the_frameworks_that_already_shipped_are_still_there(framework_id, name):
    """Customers have already received reports naming these. Dropping or renaming
    one makes this scan's output non-comparable with the previous one, and the
    remediation evidence a customer filed against "CIS 6" no longer resolves."""
    assert fw(framework_id)["name"] == name


@pytest.mark.parametrize("framework_id, expected", [
    ("cisv8", "CIS 6"),                 # Access Control Management
    ("nistcsf", "PR.AA"),               # Identity Management, Authn & Access Control
    ("soc2", "CC6"),                    # Logical and Physical Access Controls
    ("tisax", "ISA 4"),                 # Identity and Access Management
    ("iso27001", "A.5.17"),             # Authentication information
    ("iso27001", "A.8.5"),              # Secure authentication
])
def test_a_password_policy_finding_still_reaches_its_pre_existing_controls(framework_id, expected):
    """The pre-existing theme→control edges must survive the extension. If adding
    DORA quietly moved `authentication` off CIS 6, the CIS panel would go blank on
    a system whose only defect is a weak password policy — and blank reads as
    compliant."""
    assert expected in flagged_ids(assess("Password Policy")[framework_id])


def test_the_sox_financial_controls_category_still_maps():
    """`Financial Controls (SOX)` is the category the SOX-relevant checks emit.
    It carries segregation-of-duties and change-management evidence, and a SOX
    programme is the single most common reason a customer runs those checks —
    losing its mapping guts the audit view for the buyer who asked for it."""
    themes = ComplianceMapper.CATEGORY_THEMES["Financial Controls (SOX)"]
    assert {"sod", "change-management", "access-control"} <= set(themes)
    assert flagged_ids(assess("Financial Controls (SOX)")["iso27001"])


def test_gdpr_stays_scoped_to_privacy_relevant_evidence():
    """NEGATIVE CONTROL. GDPR is deliberately mapped for only three themes. A
    gateway-hardening finding is not evidence about processing personal data, and
    listing it under Art. 32 is how a report starts making legal claims it cannot
    support."""
    assert not flagged_ids(assess("Gateway Security")["gdpr"])


# --------------------------------------------------------------------------- #
#  ISO/IEC 27001:2022 — the 2022 layout, not the 2013 one                     #
# --------------------------------------------------------------------------- #

#: A.5 Organizational (37), A.6 People (8), A.7 Physical (14),
#: A.8 Technological (34) — 93 controls. The 2013 revision numbered its annex
#: A.5 through A.18, so any clause outside these four themes is 2013 numbering
#: that would send an auditor to a withdrawn standard.
ISO_2022_THEME_SIZES = {"5": 37, "6": 8, "7": 14, "8": 34}


@pytest.mark.parametrize("cid, _name", controls("iso27001"))
def test_every_iso_control_exists_in_the_2022_annex(cid, _name):
    """A 2013 clause (A.9 Access control, A.12 Operations security, …) in a report
    headed "ISO/IEC 27001:2022" is a citation to a withdrawn standard. The auditor
    who looks it up finds nothing at that number."""
    m = re.fullmatch(r"A\.(\d+)\.(\d+)", cid)
    assert m, f"{cid} is not an Annex A clause reference"
    theme, index = m.group(1), int(m.group(2))
    assert theme in ISO_2022_THEME_SIZES, \
        f"{cid} is 2013 numbering — the 2022 annex has only A.5–A.8"
    assert 1 <= index <= ISO_2022_THEME_SIZES[theme], \
        f"{cid} is outside A.{theme} (1–{ISO_2022_THEME_SIZES[theme]})"


def test_iso_people_and_physical_controls_are_not_claimed():
    """NEGATIVE CONTROL. Nothing this scanner reads out of an SAP export is
    evidence about background screening, awareness training or building access.
    Claiming A.6/A.7 would inflate the flagged-control count with controls we
    cannot produce a single finding for."""
    themes = {cid.split(".")[1] for cid, _ in controls("iso27001")}
    assert themes <= {"5", "8"}, f"unsupportable ISO themes claimed: {sorted(themes)}"


def test_the_iso_mapping_actually_grew():
    """The point of the change. If a later refactor collapses the annex mapping
    back to the original handful of clauses, the ISO panel loses the resolution an
    auditor navigates by and this test says so."""
    distinct = {cid for cid, _ in controls("iso27001")}
    assert len(distinct) >= 30, f"only {len(distinct)} Annex A controls mapped"


# --------------------------------------------------------------------------- #
#  NIST SP 800-53 Rev 5                                                        #
# --------------------------------------------------------------------------- #

#: The 20 Rev 5 families. PT (privacy) and SR (supply chain) are the two Rev 5
#: added over Rev 4, so a mapping that uses them is at least on the right
#: revision; a family outside this set is not 800-53 at all.
NIST_FAMILIES = {"AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP",
                 "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"}


def test_the_nist_80053_framework_is_present():
    """The procurement question is literally "do you map to 800-53". Its absence
    was the gap this work closed."""
    assert fw("nist80053")["name"] == "NIST SP 800-53 Rev 5"


@pytest.mark.parametrize("cid, _name", controls("nist80053"))
def test_every_nist_control_is_a_real_family_and_a_base_control(cid, _name):
    """Two ways to get this wrong, both audit-visible: a made-up family prefix,
    and a control ENHANCEMENT like AC-2(1). Which enhancements apply is decided by
    the system's categorisation and selected baseline — the customer's call, not
    something an SAP export reveals — so claiming one asserts a control selection
    we know nothing about."""
    m = re.fullmatch(r"([A-Z]{2})-(\d+)", cid)
    assert m, f"{cid} is not a base 800-53 control id (enhancements are not claimed)"
    assert m.group(1) in NIST_FAMILIES, f"{cid} uses a family that is not in 800-53"


def test_the_privacy_family_is_not_claimed():
    """NEGATIVE CONTROL. The PT controls are about processing authority, purpose
    and notice — programme artefacts we never see. Our data-protection findings
    are about read access, masking and deletion mechanics, which is SC/AC
    territory. Mapping them to PT would be coverage we could not evidence."""
    families = {cid.split("-")[0] for cid, _ in controls("nist80053")}
    assert "PT" not in families


def test_an_audit_logging_finding_reaches_the_audit_family():
    """The mapping has to be USEFUL, not merely well-formed: the most common
    800-53 question against an SAP system is whether audit logging is on and
    reviewed, and that must land in AU."""
    ids = flagged_ids(assess("Audit Logging")["nist80053"])
    assert {"AU-2", "AU-12"} <= ids, ids


def test_a_logging_finding_does_not_flag_unrelated_families():
    """NEGATIVE CONTROL. Precision is what makes the panel workable. A finding
    that SM20 is switched off is not evidence about backups (CP) or about
    developer testing (SA); flagging those turns the framework view into a list of
    everything and gives the remediation owner nothing to scope."""
    ids = flagged_ids(assess("Audit Logging")["nist80053"])
    assert not {c for c in ids if c.startswith(("CP-", "SA-", "IA-"))}, ids


# --------------------------------------------------------------------------- #
#  DORA — areas, deliberately not articles                                     #
# --------------------------------------------------------------------------- #

def test_the_dora_framework_is_present():
    """DORA applies to EU financial entities and their ICT providers and is an
    active procurement trigger. A RISE customer in scope cannot use a compliance
    report that does not have a DORA view in it."""
    assert fw("dora")["name"].startswith("DORA")


def test_dora_is_mapped_to_requirement_areas_and_claims_no_article_numbers():
    """THE CENTRAL REFUSAL IN THIS CHANGE.

    An auditor who reads "Art. 9(4)(c)" against a finding will open the regulation
    and expect the sub-paragraph to say what we implied. A theme→article table
    nobody verified clause by clause does not survive that, and it discredits the
    correctly-mapped frameworks alongside it. Areas describe DORA's subject matter
    accurately and are honest about their resolution.
    """
    for cid, name in controls("dora"):
        text = f"{cid} {name}"
        assert not re.search(r"\bArt(?:icle)?\.?\s*\d", text, re.I), \
            f"DORA entry {text!r} cites an article number"
        assert not re.search(r"\bChapter\b|\b[IVX]+\b", text), \
            f"DORA entry {text!r} cites a chapter"
        assert not re.fullmatch(r"[\d.]+", cid), \
            f"DORA id {cid!r} looks like a numbered citation"


def test_the_dora_caveat_travels_with_the_table():
    """The subtitle is rendered beside the framework name in the HTML, PDF and
    PPTX reports. Putting the caveat only in a source comment means the reader of
    the deliverable never sees it, which is the same as not making it."""
    assert "article-level mapping not claimed" in fw("dora")["subtitle"].lower()


def test_a_rise_shared_responsibility_finding_lands_in_third_party_risk():
    """RISE is an ICT third-party arrangement by definition. ICT third-party risk
    is the DORA area an in-scope financial entity is examined on hardest, and it
    is the one a RISE-hosted system produces the most evidence for."""
    ids = flagged_ids(assess("RISE / BTP Security")["dora"])
    assert "ICT third-party" in ids, ids


def test_a_password_policy_finding_is_not_third_party_risk():
    """NEGATIVE CONTROL. A weak password rule is the customer's own protection
    gap, not evidence about their provider arrangements. Mapping it to third-party
    risk would put findings in front of the vendor-management owner that they
    cannot act on."""
    assert "ICT third-party" not in flagged_ids(assess("Password Policy")["dora"])


def test_dora_governance_and_information_sharing_obligations_are_not_claimed():
    """NEGATIVE CONTROL. DORA also obliges a management-body governance role, a
    register of information on contractual arrangements, and threat-intelligence
    sharing. Those are real requirements and this scanner produces no evidence
    about any of them, so the DORA panel must not imply it covers them."""
    names = " ".join(name.lower() for _, name in controls("dora"))
    for absent in ("register of information", "management body",
                   "information sharing", "information-sharing"):
        assert absent not in names, f"DORA claims {absent!r} with nothing to evidence it"


# --------------------------------------------------------------------------- #
#  No category may fall out of the mapping silently                            #
# --------------------------------------------------------------------------- #

def _literal_categories_in(tree: ast.AST) -> set:
    """Every `"category": "..."` dict entry in one module.

    Used ONLY to resolve `category=rule["category"]`, where the categories live in
    a rule table in the same file. Scoped per-file on purpose: `abap_sast_extra`
    has its own unrelated rule-`category` vocabulary ("SQL Injection", …) that is
    never a finding category, and a repo-wide sweep would drag it in.
    """
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if (isinstance(k, ast.Constant) and k.value == "category"
                    and isinstance(v, ast.Constant) and isinstance(v.value, str)):
                out.add(v.value)
    return out


def emitted_categories() -> dict:
    """{category: module filename} for every category the shipped auditors emit.

    Read statically rather than by running the auditors: a check only fires when
    its data is present, so an execution-based sweep would report whichever
    categories `sample_data` happens to trigger and quietly miss the rest.
    """
    found: dict = {}
    for path in sorted((ROOT / "modules").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        # class-level CATEGORY constants, so `self.CATEGORY` resolves
        class_const = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant):
                        for tgt in stmt.targets:
                            if isinstance(tgt, ast.Name) and tgt.id == "CATEGORY":
                                class_const[node.name] = stmt.value.value
        file_literals = None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if (fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")) != "finding":
                continue
            expr = next((kw.value for kw in node.keywords if kw.arg == "category"), None)
            if expr is None and len(node.args) >= 4:
                expr = node.args[3]           # positional: check_id, title, severity, category
            if expr is None:
                continue
            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                found.setdefault(expr.value, path.name)
            elif isinstance(expr, ast.Attribute) and expr.attr == "CATEGORY":
                for value in class_const.values():
                    found.setdefault(value, path.name)
            else:
                # `rule["category"]` — resolve from this file's own rule table
                if file_literals is None:
                    file_literals = _literal_categories_in(tree)
                for value in file_literals:
                    found.setdefault(value, path.name)
    return found


def test_every_category_the_auditors_emit_maps_to_at_least_one_theme():
    """THE SILENT-DROP GUARD.

    An unmapped category does not raise, does not warn and does not appear
    anywhere: the findings are reported normally and are simply absent from every
    compliance panel. That is the worst shape a gap can take, because the panel
    still looks complete. Three categories were in this state before this change.

    If this fails, add the category to `ComplianceMapper.CATEGORY_THEMES`.
    """
    emitted = emitted_categories()
    assert emitted, "the static sweep found no categories at all — it is broken"
    unmapped = {c: m for c, m in emitted.items() if c not in ComplianceMapper.CATEGORY_THEMES}
    assert not unmapped, \
        "categories emitted but mapped to no control framework: " + \
        ", ".join(f"{c!r} ({m})" for c, m in sorted(unmapped.items()))


@pytest.mark.parametrize("category", [
    "Advanced IAM",                 # iam_advanced.py
    "Change Management",            # network_services.py
    "Security Audit Log Review",    # log_review.py
])
def test_the_three_previously_unmapped_categories_now_reach_controls(category):
    """These are the measured cases. Firefighter-access findings, open production
    transports and SM20 review findings were all invisible to every compliance
    panel — and those are among the first things an ISO or SOX auditor asks for."""
    results = assess(category)
    for framework_id in ("iso27001", "nist80053", "dora", "cisv8"):
        assert flagged_ids(results[framework_id]), \
            f"{category!r} still maps to nothing in {framework_id}"


# --------------------------------------------------------------------------- #
#  Structural invariants                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("framework", ComplianceMapper.FRAMEWORKS, ids=lambda f: f["id"])
def test_every_framework_theme_key_is_a_real_theme(framework):
    """A typo in a theme key does not raise — `fw["themes"].get(th, [])` returns
    an empty list — so the framework simply never flags anything for that theme
    and the panel understates the gap."""
    unknown = set(framework["themes"]) - set(ComplianceMapper.THEME_LABELS)
    assert not unknown, f"{framework['id']} declares unknown themes: {sorted(unknown)}"


def test_every_category_theme_is_a_real_theme():
    """Same silent failure from the other side: a mistyped theme in
    `CATEGORY_THEMES` maps the category to no control in any framework."""
    used = {th for lst in ComplianceMapper.CATEGORY_THEMES.values() for th in lst}
    assert used <= set(ComplianceMapper.THEME_LABELS), \
        sorted(used - set(ComplianceMapper.THEME_LABELS))


@pytest.mark.parametrize("framework", ComplianceMapper.FRAMEWORKS, ids=lambda f: f["id"])
def test_a_control_id_always_carries_the_same_name(framework):
    """The same control appears under several themes on purpose (AC-6 is both
    least privilege and privileged access). The mapper keys by id, so two spellings
    of one control's name mean whichever theme is walked last wins — the report
    would then show a different label run to run for no reason."""
    names: dict = {}
    for cid, cname in [p for lst in framework["themes"].values() for p in lst]:
        assert names.setdefault(cid, cname) == cname, \
            f"{framework['id']} gives {cid} two names: {names[cid]!r} vs {cname!r}"


@pytest.mark.parametrize("framework", ComplianceMapper.FRAMEWORKS, ids=lambda f: f["id"])
def test_a_control_id_fits_the_report_id_column(framework):
    """The PDF report renders the control id into a fixed 64pt column and clips
    what does not fit, so an over-long id reaches the customer truncated. Measured
    with the report's own font metrics rather than a character count, because that
    is what actually decides."""
    from modules.pdf_writer import PDFWriter
    writer = PDFWriter()
    for cid, _ in [p for lst in framework["themes"].values() for p in lst]:
        assert writer.string_width(cid, "HB", 8) <= 64, \
            f"{framework['id']} id {cid!r} will be clipped in the PDF report"


def test_the_result_contract_the_three_renderers_index_is_unchanged():
    """`report_generator`, `pdf_report` and `pptx_report` index these keys
    directly. A renamed or dropped key is a KeyError partway through generating a
    customer deliverable, after the scan has already run."""
    result = assess("Identity & Access Management")["iso27001"]
    assert set(result) == {"id", "name", "subtitle", "controls",
                           "controls_flagged", "total_controls", "mapped_findings"}
    assert set(result["controls"][0]) == {"id", "name", "themes",
                                          "crit", "high", "med", "low", "total"}


def test_no_framework_reports_a_coverage_percentage():
    """We see the findings, not the control environment. Any "% of the framework
    covered" would be a claim about evidence we do not hold, and it is the number
    a buyer would quote back at us first."""
    for result in ComplianceMapper([{"category": "Password Policy",
                                     "severity": "HIGH"}]).assess():
        assert not [k for k in result if "pct" in k or "percent" in k or "coverage" in k]


def test_total_controls_counts_each_control_once():
    """`total_controls` is the denominator of "N of M control areas flagged" in all
    three reports. Counting AC-6 twice because it is reachable from two themes
    makes the system look better than it is."""
    for framework in ComplianceMapper.FRAMEWORKS:
        distinct = {cid for lst in framework["themes"].values() for cid, _ in lst}
        result = next(r for r in ComplianceMapper([]).assess()
                      if r["id"] == framework["id"])
        assert result["total_controls"] == len(distinct)


def test_controls_are_ordered_worst_first():
    """The panel is read top-down. A CRITICAL buried under a LOW is a finding
    nobody schedules."""
    result = assess("Identity & Access Management", severity="CRITICAL")["iso27001"]
    also = ComplianceMapper(
        [{"category": "Identity & Access Management", "severity": "CRITICAL"},
         {"category": "Audit Logging", "severity": "LOW"}]).assess()
    iso = next(r for r in also if r["id"] == "iso27001")
    assert iso["controls"][0]["crit"] >= iso["controls"][-1]["crit"]
    assert result["controls"][0]["crit"] == 1


# --------------------------------------------------------------------------- #
#  Negative controls — a clean system, and inputs we do not understand         #
# --------------------------------------------------------------------------- #

def test_a_clean_system_flags_no_controls_in_any_framework():
    """THE EXIT CRITERION.

    Zero findings must mean zero flagged controls everywhere. All three renderers
    drop frameworks with an empty `controls` list, so this is what makes a clean
    scan produce no compliance panel at all rather than a page of controls with
    zero counts beside them — which reads as a list of failures.
    """
    for result in ComplianceMapper([]).assess():
        assert result["controls"] == []
        assert result["controls_flagged"] == 0
        assert result["mapped_findings"] == 0


def test_an_unknown_category_maps_to_nothing_rather_than_guessing():
    """NEGATIVE CONTROL. A category the table has never seen must contribute no
    controls. Falling back to "map it everywhere" would be worse than the silent
    drop it replaced: it would attribute findings to controls they are not
    evidence against."""
    for result in ComplianceMapper(
            [{"category": "Something Nobody Has Written Yet", "severity": "CRITICAL"}]).assess():
        assert result["controls"] == []


@pytest.mark.parametrize("findings", [
    None,
    [],
    [{"severity": "HIGH"}],                       # no category key at all
    [{"category": "", "severity": "HIGH"}],
    [{"category": None, "severity": "HIGH"}],
    # The shapes that reach a MAPPED category are the dangerous ones: an
    # unmapped category short-circuits before the severity is ever read, so the
    # three cases above never exercised the severity lookup at all. This one
    # does, and it used to raise KeyError.
    [{"category": "Password Policy"}],            # mapped, but no severity key
    [{"category": "Password Policy", "severity": None}],
    [{"category": "Password Policy", "severity": "MAJOR"}],   # not in SEV_ORDER
])
def test_the_mapper_never_raises_on_thin_input(findings):
    """The mapper runs at report time, after the scan has completed. Raising here
    destroys a finished scan's entire deliverable over a finding shape, which is
    the most expensive possible moment to fail."""
    results = ComplianceMapper(findings).assess()
    assert len(results) == len(ComplianceMapper.FRAMEWORKS)


def test_a_finding_with_no_severity_is_still_counted_not_dropped():
    """A finding whose severity we cannot read must still show up in the control's
    total. Silently dropping it is the worse failure: the control would show
    fewer open findings than it has, and the panel is read as a work list."""
    result = assess("Password Policy")["iso27001"]      # baseline: severity HIGH
    thin = next(r for r in ComplianceMapper([{"category": "Password Policy"}]).assess()
                if r["id"] == "iso27001")
    assert flagged_ids(thin) == flagged_ids(result)
    for control in thin["controls"]:
        assert control["total"] == 1
        assert control["crit"] == control["high"] == control["med"] == control["low"] == 0


def test_mapped_findings_counts_findings_not_control_edges():
    """`N findings mapped` is printed beside every framework name in all three
    reports. One finding reaching six controls is ONE finding mapped, not six —
    counting edges would let a framework claim more evidence than the scan holds,
    and it inflates worst for the frameworks with the densest mapping."""
    result = assess("Identity & Access Management")["nist80053"]
    assert result["mapped_findings"] == 1
    assert sum(c["total"] for c in result["controls"]) > 1, \
        "this category no longer reaches several controls — the test proves nothing"


def test_each_flagged_control_names_the_themes_it_was_flagged_through():
    """The themes are the second line of every control row in the HTML and PDF
    tables, and they are the only thing on the row that says WHY a finding landed
    on that control. Emptied, the panel becomes a list of control ids an auditor
    cannot trace back to a finding."""
    result = assess("HANA Database Security")["iso27001"]
    assert result["controls"]
    labels = set(ComplianceMapper.THEME_LABELS.values())
    for control in result["controls"]:
        assert control["themes"], f"{control['id']} names no theme"
        assert set(control["themes"]) <= labels, control["themes"]


def test_a_tls_setting_is_not_cited_as_a_change_management_control():
    """"Transport Security" is a FALSE FRIEND in an SAP context, and it mapped as
    one. Its only two checks are `icm/HTTP/redirect_0` and
    `icm/HTTPS/verify_client` — Internet Communication Manager settings, i.e. TLS
    — and they were mapped to change-management and secure-development themes.

    So a weak TLS setting reached an auditor under ISO A.8.28 "Secure coding",
    A.8.31 "Separation of development, test and production" and A.8.32 "Change
    management", and never reached A.8.24 "Use of cryptography" at all. A mapping
    that is confidently wrong is worse than one that is absent: the reader has no
    reason to check it.
    """
    from modules.compliance_mapping import ComplianceMapper

    themes = set(ComplianceMapper.CATEGORY_THEMES["Transport Security"])
    assert "cryptography" in themes
    assert "change-management" not in themes
    assert "secure-development" not in themes

    controls = set()
    for framework in ComplianceMapper.FRAMEWORKS:
        for theme, entries in (framework.get("themes") or {}).items():
            if theme in themes:
                controls |= {f"{framework['id']}:{c}" for c, _label in entries}
    assert "iso27001:A.8.24" in controls, "a TLS finding must reach 'Use of cryptography'"
    assert "iso27001:A.8.32" not in controls, "and must not reach 'Change management'"


def test_the_category_that_really_is_about_transports_still_maps_to_change():
    """The Change and Transport System has its own category, and this fix must
    not have moved it: SE06/SCC4/STMS evidence IS change-management evidence."""
    from modules.compliance_mapping import ComplianceMapper

    assert "change-management" in ComplianceMapper.CATEGORY_THEMES["Change Management"]
