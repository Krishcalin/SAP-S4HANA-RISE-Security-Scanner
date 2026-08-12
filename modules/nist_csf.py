# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
NIST Cybersecurity Framework (CSF) 2.0 — Core taxonomy and finding roll-up
==========================================================================
The complete CSF 2.0 Core: 6 Functions, 22 Categories, 106 Subcategories,
transcribed from NIST CSWP 29 (February 26, 2024),
https://doi.org/10.6028/NIST.CSWP.29 — a U.S. Government work, not subject to
copyright in the United States.

────────────────────────────────────────────────────────────────────────────────
THE ONE THING THIS MODULE EXISTS TO PREVENT
────────────────────────────────────────────────────────────────────────────────
A CSF dashboard that shows "GOVERN — 0 findings" next to a green tick is a LIE,
and it is the most dangerous kind because it is the reassuring kind. We never
looked at the organisation's risk appetite statement. We cannot: no SAP export
contains one. Reporting silence as compliance would tell a customer they are
covered on exactly the outcomes we know nothing about.

So every Category is one of THREE states, never two — the same three-state
discipline the release gate and the export-completeness signal already use:

  ASSESSED   this scanner produces evidence here, and this run produced findings
  CLEAR      this scanner produces evidence here, and this run produced none
  NOT_ASSESSED
             this scanner produces NO evidence here, in any run, by design.
             The outcome is a programme artefact (a policy, an exercise, a
             training record, a board review) that an SAP configuration export
             does not reveal. Nothing about the customer's posture is implied.

CLEAR and NOT_ASSESSED must never be rendered alike. CLEAR is an observation;
NOT_ASSESSED is the absence of one.

────────────────────────────────────────────────────────────────────────────────
WHERE SCOPE COMES FROM
────────────────────────────────────────────────────────────────────────────────
It is DERIVED, not declared. `assessable_categories()` reads the CSF entries out
of ComplianceMapper.FRAMEWORKS, so the set of Categories this product claims to
speak to is, by construction, exactly the set its findings are actually mapped
onto. A second hand-maintained list would drift the moment someone touched the
mapper, and the drift would be invisible — it would show up as a Category
silently reported NOT_ASSESSED while findings were landing in it.

`tests/test_nist_csf.py` pins the taxonomy against the published Core (6/22/106),
checks every Category id parses to a real Function, and fails if the mapper ever
references a Category that does not exist in the Core.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .compliance_mapping import ComplianceMapper


# ── Functions ────────────────────────────────────────────────────────────────
#: id -> (display name, the Function's outcome statement, verbatim from CSWP 29)
FUNCTIONS: Dict[str, Tuple[str, str]] = {
    "GV": ("Govern",
           "The organization's cybersecurity risk management strategy, "
           "expectations, and policy are established, communicated, and monitored"),
    "ID": ("Identify",
           "The organization's current cybersecurity risks are understood"),
    "PR": ("Protect",
           "Safeguards to manage the organization's cybersecurity risks are used"),
    "DE": ("Detect",
           "Possible cybersecurity attacks and compromises are found and analyzed"),
    "RS": ("Respond",
           "Actions regarding a detected cybersecurity incident are taken"),
    "RC": ("Recover",
           "Assets and operations affected by a cybersecurity incident are restored"),
}

#: The Core's own ordering, which is NOT alphabetical. CSWP 29 says the order
#: "is intended to resonate most with those charged with operationalizing risk
#: management" — GOVERN first because it informs the other five. Rendering these
#: alphabetically would discard a decision NIST made deliberately.
FUNCTION_ORDER: Tuple[str, ...] = ("GV", "ID", "PR", "DE", "RS", "RC")

# ── Categories ───────────────────────────────────────────────────────────────
#: id -> (display name, description verbatim from CSWP 29)
CATEGORIES: Dict[str, Tuple[str, str]] = {
    "GV.OC": ("Organizational Context",
              "The circumstances — mission, stakeholder expectations, dependencies, and "
              "legal, regulatory, and contractual requirements — surrounding the "
              "organization's cybersecurity risk management decisions are understood"),
    "GV.RM": ("Risk Management Strategy",
              "The organization's priorities, constraints, risk tolerance and appetite "
              "statements, and assumptions are established, communicated, and used to "
              "support operational risk decisions"),
    "GV.RR": ("Roles, Responsibilities, and Authorities",
              "Cybersecurity roles, responsibilities, and authorities to foster "
              "accountability, performance assessment, and continuous improvement are "
              "established and communicated"),
    "GV.PO": ("Policy",
              "Organizational cybersecurity policy is established, communicated, and enforced"),
    "GV.OV": ("Oversight",
              "Results of organization-wide cybersecurity risk management activities and "
              "performance are used to inform, improve, and adjust the risk management strategy"),
    "GV.SC": ("Cybersecurity Supply Chain Risk Management",
              "Cyber supply chain risk management processes are identified, established, "
              "managed, monitored, and improved by organizational stakeholders"),

    "ID.AM": ("Asset Management",
              "Assets (e.g., data, hardware, software, systems, facilities, services, people) "
              "that enable the organization to achieve business purposes are identified and "
              "managed consistent with their relative importance to organizational objectives "
              "and the organization's risk strategy"),
    "ID.RA": ("Risk Assessment",
              "The cybersecurity risk to the organization, assets, and individuals is "
              "understood by the organization"),
    "ID.IM": ("Improvement",
              "Improvements to organizational cybersecurity risk management processes, "
              "procedures and activities are identified across all CSF Functions"),

    "PR.AA": ("Identity Management, Authentication, and Access Control",
              "Access to physical and logical assets is limited to authorized users, services, "
              "and hardware and managed commensurate with the assessed risk of unauthorized access"),
    "PR.AT": ("Awareness and Training",
              "The organization's personnel are provided with cybersecurity awareness and "
              "training so that they can perform their cybersecurity-related tasks"),
    "PR.DS": ("Data Security",
              "Data are managed consistent with the organization's risk strategy to protect "
              "the confidentiality, integrity, and availability of information"),
    "PR.PS": ("Platform Security",
              "The hardware, software (e.g., firmware, operating systems, applications), and "
              "services of physical and virtual platforms are managed consistent with the "
              "organization's risk strategy to protect their confidentiality, integrity, and "
              "availability"),
    "PR.IR": ("Technology Infrastructure Resilience",
              "Security architectures are managed with the organization's risk strategy to "
              "protect asset confidentiality, integrity, and availability, and organizational "
              "resilience"),

    "DE.CM": ("Continuous Monitoring",
              "Assets are monitored to find anomalies, indicators of compromise, and other "
              "potentially adverse events"),
    "DE.AE": ("Adverse Event Analysis",
              "Anomalies, indicators of compromise, and other potentially adverse events are "
              "analyzed to characterize the events and detect cybersecurity incidents"),

    "RS.MA": ("Incident Management",
              "Responses to detected cybersecurity incidents are managed"),
    "RS.AN": ("Incident Analysis",
              "Investigations are conducted to ensure effective response and support forensics "
              "and recovery activities"),
    "RS.CO": ("Incident Response Reporting and Communication",
              "Response activities are coordinated with internal and external stakeholders as "
              "required by laws, regulations, or policies"),
    "RS.MI": ("Incident Mitigation",
              "Activities are performed to prevent expansion of an event and mitigate its effects"),

    "RC.RP": ("Incident Recovery Plan Execution",
              "Restoration activities are performed to ensure operational availability of "
              "systems and services affected by cybersecurity incidents"),
    "RC.CO": ("Incident Recovery Communication",
              "Restoration activities are coordinated with internal and external parties"),
}

# ── Subcategories ────────────────────────────────────────────────────────────
#: id -> outcome text, verbatim from CSWP 29 Appendix A.
#: The numbering is INTENTIONALLY not sequential — CSWP 29 states that gaps mark
#: CSF 1.1 Subcategories relocated in 2.0 (hence no ID.AM-06, no PR.DS-03..09,
#: no DE.CM-04/05/07/08, no RS.AN-01/02/04/05, no RC.CO-01/02). Do not "fix" them.
SUBCATEGORIES: Dict[str, str] = {
    # GOVERN
    "GV.OC-01": "The organizational mission is understood and informs cybersecurity risk management",
    "GV.OC-02": "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered",
    "GV.OC-03": "Legal, regulatory, and contractual requirements regarding cybersecurity — including privacy and civil liberties obligations — are understood and managed",
    "GV.OC-04": "Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated",
    "GV.OC-05": "Outcomes, capabilities, and services that the organization depends on are understood and communicated",
    "GV.RM-01": "Risk management objectives are established and agreed to by organizational stakeholders",
    "GV.RM-02": "Risk appetite and risk tolerance statements are established, communicated, and maintained",
    "GV.RM-03": "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes",
    "GV.RM-04": "Strategic direction that describes appropriate risk response options is established and communicated",
    "GV.RM-05": "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties",
    "GV.RM-06": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated",
    "GV.RM-07": "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions",
    "GV.RR-01": "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving",
    "GV.RR-02": "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced",
    "GV.RR-03": "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies",
    "GV.RR-04": "Cybersecurity is included in human resources practices",
    "GV.PO-01": "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced",
    "GV.PO-02": "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission",
    "GV.OV-01": "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction",
    "GV.OV-02": "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks",
    "GV.OV-03": "Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed",
    "GV.SC-01": "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders",
    "GV.SC-02": "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally",
    "GV.SC-03": "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes",
    "GV.SC-04": "Suppliers are known and prioritized by criticality",
    "GV.SC-05": "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties",
    "GV.SC-06": "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships",
    "GV.SC-07": "The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship",
    "GV.SC-08": "Relevant suppliers and other third parties are included in incident planning, response, and recovery activities",
    "GV.SC-09": "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle",
    "GV.SC-10": "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement",
    # IDENTIFY
    "ID.AM-01": "Inventories of hardware managed by the organization are maintained",
    "ID.AM-02": "Inventories of software, services, and systems managed by the organization are maintained",
    "ID.AM-03": "Representations of the organization's authorized network communication and internal and external network data flows are maintained",
    "ID.AM-04": "Inventories of services provided by suppliers are maintained",
    "ID.AM-05": "Assets are prioritized based on classification, criticality, resources, and impact on the mission",
    "ID.AM-07": "Inventories of data and corresponding metadata for designated data types are maintained",
    "ID.AM-08": "Systems, hardware, software, services, and data are managed throughout their life cycles",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
    "ID.RA-02": "Cyber threat intelligence is received from information sharing forums and sources",
    "ID.RA-03": "Internal and external threats to the organization are identified and recorded",
    "ID.RA-04": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded",
    "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization",
    "ID.RA-06": "Risk responses are chosen, prioritized, planned, tracked, and communicated",
    "ID.RA-07": "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked",
    "ID.RA-08": "Processes for receiving, analyzing, and responding to vulnerability disclosures are established",
    "ID.RA-09": "The authenticity and integrity of hardware and software are assessed prior to acquisition and use",
    "ID.RA-10": "Critical suppliers are assessed prior to acquisition",
    "ID.IM-01": "Improvements are identified from evaluations",
    "ID.IM-02": "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties",
    "ID.IM-03": "Improvements are identified from execution of operational processes, procedures, and activities",
    "ID.IM-04": "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved",
    # PROTECT
    "PR.AA-01": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
    "PR.AA-02": "Identities are proofed and bound to credentials based on the context of interactions",
    "PR.AA-03": "Users, services, and hardware are authenticated",
    "PR.AA-04": "Identity assertions are protected, conveyed, and verified",
    "PR.AA-05": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties",
    "PR.AA-06": "Physical access to assets is managed, monitored, and enforced commensurate with risk",
    "PR.AT-01": "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind",
    "PR.AT-02": "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind",
    "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected",
    "PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected",
    "PR.DS-10": "The confidentiality, integrity, and availability of data-in-use are protected",
    "PR.DS-11": "Backups of data are created, protected, maintained, and tested",
    "PR.PS-01": "Configuration management practices are established and applied",
    "PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
    "PR.PS-03": "Hardware is maintained, replaced, and removed commensurate with risk",
    "PR.PS-04": "Log records are generated and made available for continuous monitoring",
    "PR.PS-05": "Installation and execution of unauthorized software are prevented",
    "PR.PS-06": "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle",
    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
    "PR.IR-02": "The organization's technology assets are protected from environmental threats",
    "PR.IR-03": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
    "PR.IR-04": "Adequate resource capacity to ensure availability is maintained",
    # DETECT
    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
    "DE.CM-02": "The physical environment is monitored to find potentially adverse events",
    "DE.CM-03": "Personnel activity and technology usage are monitored to find potentially adverse events",
    "DE.CM-06": "External service provider activities and services are monitored to find potentially adverse events",
    "DE.CM-09": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events",
    "DE.AE-02": "Potentially adverse events are analyzed to better understand associated activities",
    "DE.AE-03": "Information is correlated from multiple sources",
    "DE.AE-04": "The estimated impact and scope of adverse events are understood",
    "DE.AE-06": "Information on adverse events is provided to authorized staff and tools",
    "DE.AE-07": "Cyber threat intelligence and other contextual information are integrated into the analysis",
    "DE.AE-08": "Incidents are declared when adverse events meet the defined incident criteria",
    # RESPOND
    "RS.MA-01": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
    "RS.MA-02": "Incident reports are triaged and validated",
    "RS.MA-03": "Incidents are categorized and prioritized",
    "RS.MA-04": "Incidents are escalated or elevated as needed",
    "RS.MA-05": "The criteria for initiating incident recovery are applied",
    "RS.AN-03": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident",
    "RS.AN-06": "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved",
    "RS.AN-07": "Incident data and metadata are collected, and their integrity and provenance are preserved",
    "RS.AN-08": "An incident's magnitude is estimated and validated",
    "RS.CO-02": "Internal and external stakeholders are notified of incidents",
    "RS.CO-03": "Information is shared with designated internal and external stakeholders",
    "RS.MI-01": "Incidents are contained",
    "RS.MI-02": "Incidents are eradicated",
    # RECOVER
    "RC.RP-01": "The recovery portion of the incident response plan is executed once initiated from the incident response process",
    "RC.RP-02": "Recovery actions are selected, scoped, prioritized, and performed",
    "RC.RP-03": "The integrity of backups and other restoration assets is verified before using them for restoration",
    "RC.RP-04": "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms",
    "RC.RP-05": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed",
    "RC.RP-06": "The end of incident recovery is declared based on criteria, and incident-related documentation is completed",
    "RC.CO-03": "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders",
    "RC.CO-04": "Public updates on incident recovery are shared using approved methods and messaging",
}

#: Why a Category carries no evidence from THIS product. Shown verbatim in the UI
#: so a NOT_ASSESSED tile explains itself instead of looking like a gap or a pass.
#: Every key here MUST be a Category absent from assessable_categories(); the test
#: fails if the two sets ever overlap or if a NOT_ASSESSED Category lacks a reason.
NOT_ASSESSED_REASON: Dict[str, str] = {
    "GV.OC": "Mission, stakeholder and regulatory context are organisational facts. No SAP export states them.",
    "GV.RM": "Risk appetite and tolerance are board-level statements, not system configuration.",
    "GV.PO": "The existence and review cadence of a written policy cannot be read from a system export.",
    "GV.OV": "Oversight is evidenced by review minutes and programme reporting, which we never see.",
    "ID.AM": "We read the components of the systems you export, but an ASSET INVENTORY is an organisational register — its completeness cannot be judged from the systems that were exported to us.",
    "ID.IM": "Improvement is evidenced by evaluations, exercises and lessons learned — programme artefacts, not configuration.",
    "PR.AT": "Awareness and training records live in an HR or LMS system, not in SAP configuration.",
    "RS.CO": "Whether stakeholders were notified during an incident is a record of what people did, not a system setting.",
    "RS.MI": "Containment and eradication are actions taken during a live incident; a configuration export is a snapshot, not a response log.",
    "RC.CO": "Recovery communications are an organisational activity with no configuration footprint.",
}

_SEVERITY_ORDER: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

ASSESSED = "assessed"
CLEAR = "clear"
NOT_ASSESSED = "not_assessed"


def function_of(category_id: str) -> str:
    """'PR.AA' -> 'PR'. Raises on anything that is not a real Category id."""
    prefix = category_id.split(".", 1)[0]
    if category_id not in CATEGORIES or prefix not in FUNCTIONS:
        raise KeyError(f"not a CSF 2.0 Category id: {category_id!r}")
    return prefix


def subcategories_of(category_id: str) -> List[Dict[str, str]]:
    """The Subcategories of a Category, in published order, WITH their text.

    The id alone ("PR.AA-05") tells a reader nothing; carrying the outcome makes
    the list worth rendering. This is NIST's wording, not a paraphrase — a
    summarised control outcome is a different control outcome.
    """
    return [{"id": s, "text": SUBCATEGORIES[s]}
            for s in SUBCATEGORIES if s.rsplit("-", 1)[0] == category_id]


def assessable_categories() -> Dict[str, List[str]]:
    """CSF Category id -> the security THEMES whose findings land in it.

    DERIVED from ComplianceMapper so scope cannot drift from the actual mapping.
    A Category is assessable precisely when some theme maps onto it; there is no
    second list to forget to update.
    """
    out: Dict[str, List[str]] = {}
    for framework in ComplianceMapper.FRAMEWORKS:
        if framework.get("id") != "nistcsf":
            continue
        for theme, controls in framework.get("themes", {}).items():
            for control_id, _label in controls:
                out.setdefault(control_id, []).append(theme)
    return {k: sorted(set(v)) for k, v in sorted(out.items())}


def _blank_counts() -> Dict[str, int]:
    return {s: 0 for s in _SEVERITY_ORDER}


def roll_up(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll findings up to the CSF Core.

    Returns the whole Core — every Function and every Category — never only the
    ones with findings, because a Category's ABSENCE from the answer is exactly
    the ambiguity this module exists to remove.
    """
    mapper = ComplianceMapper(list(findings))
    assessable = assessable_categories()

    per_category: Dict[str, Dict[str, Any]] = {}
    for cat_id, (name, description) in CATEGORIES.items():
        per_category[cat_id] = {
            "id": cat_id,
            "function": function_of(cat_id),
            "name": name,
            "description": description,
            "status": ASSESSED if cat_id in assessable else NOT_ASSESSED,
            "themes": assessable.get(cat_id, []),
            "reason": NOT_ASSESSED_REASON.get(cat_id),
            "counts": _blank_counts(),
            "total": 0,
            "subcategories": subcategories_of(cat_id),
        }

    # COUNT DISTINCT FINDINGS, NOT ATTRIBUTIONS.
    #
    # A finding is evidence against several themes, and a theme maps onto several
    # Categories, so the naive loop counts one finding many times. Per Category
    # that is defensible; rolled up to a Function it is not — the first run of
    # this code reported "Protect: 148" for a system with 92 findings in total.
    # A number larger than the corpus it summarises is indefensible in front of
    # the auditor this whole view exists to serve, and no footnote repairs it.
    # So each Category and each Function counts a finding AT MOST ONCE, tracked
    # by identity here and collapsed to counts below.
    seen_by_category: Dict[str, set] = {c: set() for c in per_category}
    mapped: set = set()
    unmapped_categories: Dict[str, int] = {}
    for index, finding in enumerate(findings):
        category = finding.get("category")
        severity = str(finding.get("severity", "")).upper()
        if severity not in _SEVERITY_ORDER:
            continue
        themes_for_finding = mapper.CATEGORY_THEMES.get(category, [])
        if not themes_for_finding:
            # A finding whose category maps to no theme reaches no control in any
            # framework AND SAYS NOTHING WHILE DOING IT — compliance_mapping.py
            # names this as its failure mode. Counted and reported here, because a
            # CSF page that quietly drops findings is worse than one that admits
            # it dropped them: the reader would take the roll-up for the corpus.
            unmapped_categories[category or "(no category)"] = (
                unmapped_categories.get(category or "(no category)", 0) + 1)
            continue
        for theme in themes_for_finding:
            for cat_id, themes in assessable.items():
                if theme in themes and cat_id in per_category:
                    seen_by_category[cat_id].add(index)
                    mapped.add(index)

    for cat_id, indices in seen_by_category.items():
        entry = per_category[cat_id]
        for index in indices:
            severity = str(findings[index].get("severity", "")).upper()
            entry["counts"][severity] += 1
        entry["total"] = len(indices)

    # An assessable Category with nothing in it is CLEAR — we looked. That is a
    # different statement from NOT_ASSESSED and is rendered differently.
    for entry in per_category.values():
        if entry["status"] == ASSESSED and entry["total"] == 0:
            entry["status"] = CLEAR

    functions: List[Dict[str, Any]] = []
    for fn_id in FUNCTION_ORDER:
        name, outcome = FUNCTIONS[fn_id]
        cats = [per_category[c] for c in CATEGORIES if function_of(c) == fn_id]
        # THE SAME DEDUPLICATION AGAIN, ONE LEVEL UP, AND IT IS NOT OPTIONAL.
        # Summing the Category counts here would double-count any finding that
        # lands in two Categories of the SAME Function — and several do, because
        # 'Identity & Access Management' is evidence for both PR.AA and PR.PS.
        # The per-Category fix alone still reported 4 findings for a 3-finding
        # corpus; only a union over the Function's Categories is correct.
        indices: set = set()
        for cat in cats:
            indices |= seen_by_category.get(cat["id"], set())
        counts = _blank_counts()
        for index in indices:
            counts[str(findings[index].get("severity", "")).upper()] += 1
        assessed = [c for c in cats if c["status"] == ASSESSED]
        clear = [c for c in cats if c["status"] == CLEAR]
        functions.append({
            "id": fn_id,
            "name": name,
            "outcome": outcome,
            "counts": counts,
            "total": len(indices),
            "categories": cats,
            "categories_total": len(cats),
            "categories_assessed": len(assessed) + len(clear),
            "categories_with_findings": len(assessed),
            "subcategories_total": sum(len(c["subcategories"]) for c in cats),
        })

    n_assessable = len(assessable)
    return {
        "framework": "NIST Cybersecurity Framework (CSF) 2.0",
        "reference": "NIST CSWP 29, February 26, 2024",
        "doi": "https://doi.org/10.6028/NIST.CSWP.29",
        "functions": functions,
        "totals": {
            "functions": len(FUNCTIONS),
            "categories": len(CATEGORIES),
            "subcategories": len(SUBCATEGORIES),
            "categories_assessable": n_assessable,
            "categories_not_assessed": len(CATEGORIES) - n_assessable,
            # `findings` is the corpus. `mapped` is how much of it this view can
            # account for. They are reported separately and never conflated: the
            # gap between them is the honest measure of what the CSF lens misses,
            # and collapsing it to one number is how that gap goes unnoticed.
            "findings": len(findings),
            "mapped": len(mapped),
            "unmapped": sum(unmapped_categories.values()),
            "unmapped_categories": dict(sorted(unmapped_categories.items(),
                                               key=lambda kv: (-kv[1], kv[0]))),
        },
    }


#: The readable URL form of each Function, and the reason this map exists.
#: A link reading /csf/govern says what it opens; /csf/GV does not, and the six
#: Function pages are the most-linked surface in the console. The ids stay
#: canonical everywhere else — this is a routing convenience, not a second
#: vocabulary, so `resolve_function` accepts BOTH and nothing else does.
SLUGS: Dict[str, str] = {
    "GV": "govern", "ID": "identify", "PR": "protect",
    "DE": "detect", "RS": "respond", "RC": "recover",
}
_BY_SLUG: Dict[str, str] = {slug: fn for fn, slug in SLUGS.items()}


def resolve_function(value: str) -> Optional[str]:
    """'PR', 'pr', 'protect' -> 'PR'. Anything else -> None.

    Both forms resolve because the console routes on the slug while the Core,
    the mapper and every id in the payload use the two-letter Function. An API
    that took only the id would 404 every link the UI generates — which is
    exactly what happened the first time this shipped, and what the unit test
    below failed to catch because it asserted the slug SHOULD be rejected.
    """
    if not value:
        return None
    upper = value.upper()
    if upper in FUNCTIONS:
        return upper
    return _BY_SLUG.get(value.lower())


def function_detail(findings: Sequence[Dict[str, Any]], function_id: str) -> Optional[Dict[str, Any]]:
    """One Function's roll-up, or None if `function_id` is not a CSF Function."""
    fn = resolve_function(function_id)
    if fn is None:
        return None
    rolled = roll_up(findings)
    for entry in rolled["functions"]:
        if entry["id"] == fn:
            entry["reference"] = rolled["reference"]
            entry["doi"] = rolled["doi"]
            return entry
    return None
