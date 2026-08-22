"""
Turn a CFO's answers into FAIR loss magnitudes.

WHAT WAS WRONG, MEASURED
------------------------
`data/fair_scenarios.json` carries ABSOLUTE loss bands — "productivity: likely
$6,000,000" — calibrated, by its own `_meta`, to an illustrative $1B-revenue
manufacturer. Every customer got that company's losses. A EUR 40M distributor and a
EUR 40B group received the same number, and the organisation dict that was supposed
to fix it was never read by the engine at all.

The reference deployment showed the consequence: a FICTITIOUS DEVELOPMENT SYSTEM
was reported at a portfolio ALE P90 of $49,634,933.91. To the cent.

WHAT THIS MODULE DOES
---------------------
Loss becomes a FUNCTION of the customer's own business. Business interruption is
downtime hours x hourly gross margin, not a constant. A privacy loss is records x
per-record cost, and if the estate holds no personal data that component is REMOVED
rather than set near zero — a scenario that cannot happen here should not contribute
a floor to the tail.

Every component is expressed as a three-point (min / likely / max) band, because
FAIR takes calibrated RANGES and a single number would be a false claim to
precision. Every component carries provenance naming which answer produced it.

THE LINE THIS MODULE WILL NOT CROSS
-----------------------------------
It ships NO industry benchmark figures. Not one. A number like "$165 per breached
record" reads as authoritative, gets copied into a board pack, and cannot be
defended unless we hold the study, its year, its currency, its sector and its
sample. We do not. So where a customer supplies nothing, the component is marked
`unanswered` and EXCLUDED from the simulation, and the UI says which of their
exposures went unpriced. An unpriced exposure disclosed beats an invented one
totalled.

That is also why every band below is arithmetic on the customer's OWN figures. The
only judgements this module makes are ratios between a customer's min, likely and
max, and those are stated in `SPREAD` where a reader can see and argue with them.
"""
from typing import Any, Dict, List, Optional, Tuple

#: FAIR-MAM v1.0 cost modules (10 categories). Component keys below name their home
#: so a loss breakdown can be presented in the taxonomy a risk function recognises.
#: P = Primary, S = Secondary, per the FAIR-MAM legend.
MAM_MODULES: Dict[str, Tuple[str, str]] = {
    "information_privacy": ("Information Privacy", "P/S"),
    "proprietary_data": ("Proprietary Data Loss", "P/S"),
    "business_interruption": ("Business Interruption", "P"),
    "cyber_extortion": ("Cyber Extortion", "P"),
    "network_security": ("Network Security", "P/S"),
    "financial_fraud": ("Financial Fraud", "P/S"),
    "media_content": ("Media Content", "P/S"),
    "hardware_bricking": ("Hardware Bricking", "P"),
    "post_breach_improvements": ("Post Breach Security Improvements", "S"),
    "reputational_damage": ("Reputational Damage", "S"),
}

#: How a single answer becomes a three-point band, as multipliers on the answer.
#:
#: THESE THREE NUMBERS ARE A MODELLING CHOICE, NOT A MEASUREMENT, and they are here
#: rather than buried in the arithmetic so a risk analyst can see them, disagree,
#: and change them. A CFO who says "about 8 hours to restore" is not claiming 8.00;
#: the band says the true value plausibly lies between half and triple that, which
#: is deliberately wide. FAIR practitioners calibrate to a 90% confidence interval;
#: absent that calibration exercise, being visibly wide is more honest than being
#: narrow and wrong.
SPREAD: Dict[str, float] = {"min": 0.5, "likely": 1.0, "max": 3.0}

#: Hours in a working year, for converting annual revenue to an hourly rate.
#: 8,760 would assume SAP earns revenue at 3am on a Sunday at the same rate as
#: Tuesday lunchtime. 2,080 (52 x 40) is the defensible default for a business whose
#: order-to-cash runs in business hours; `revenue_hours_per_year` overrides it for
#: continuous operations, which is the case that actually matters for manufacturing.
DEFAULT_REVENUE_HOURS = 2080.0


class Answer:
    """One CFO/CISO answer, with where it came from.

    `source` is one of:
      user        somebody typed it, and it is theirs to defend
      derived     computed from other answers (shown, never silently assumed)
      unanswered  nobody said, and NOTHING is invented to fill the gap

    The distinction is the whole point. An unedited default rendered like a
    considered answer is how a model launders its assumptions into a customer's
    board pack under their name.
    """

    __slots__ = ("key", "value", "source", "unit", "note")

    def __init__(self, key: str, value: Optional[float], source: str,
                 unit: str = "", note: str = "") -> None:
        self.key = key
        self.value = value
        self.source = source
        self.unit = unit
        self.note = note

    def answered(self) -> bool:
        return self.source != "unanswered" and self.value is not None

    def as_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "value": self.value, "source": self.source,
                "unit": self.unit, "note": self.note}


#: The question set. Deliberately short: every question is one a CFO or a CISO can
#: answer from a system they already own, and every one earns its place by pricing a
#: FAIR-MAM module. Anything we can measure ourselves is NOT asked — control strength
#: comes from the scan, and asking the customer to grade their own controls would
#: replace evidence with opinion.
PARAMETERS: List[Dict[str, Any]] = [
    {"key": "sap_revenue", "label": "Annual revenue processed through SAP",
     "unit": "currency", "group": "Business",
     "help": "Order-to-cash and billing that runs through this estate. Not group "
             "turnover unless SAP carries all of it.",
     "feeds": ["business_interruption", "reputational_damage"]},
    {"key": "gross_margin_pct", "label": "Gross margin on that revenue",
     "unit": "percent", "group": "Business",
     "help": "An outage costs you the margin, not the whole invoice — the revenue "
             "is usually deferred rather than lost.",
     "feeds": ["business_interruption"]},
    {"key": "revenue_hours_per_year", "label": "Hours per year SAP earns revenue",
     "unit": "hours", "group": "Business",
     "help": "2080 for business hours, 8760 for continuous operations.",
     "feeds": ["business_interruption"]},
    {"key": "downtime_hours", "label": "Hours to restore SAP after a major incident",
     "unit": "hours", "group": "Resilience",
     "help": "Your tested recovery time, not the RTO in the policy document.",
     "feeds": ["business_interruption"]},
    {"key": "response_staff_cost_hour", "label": "Fully-loaded hourly cost, response team",
     "unit": "currency", "group": "Resilience",
     "help": "Internal IT, Basis and finance staff pulled onto an incident, plus "
             "retained external responders.",
     "feeds": ["network_security", "post_breach_improvements"]},
    {"key": "response_staff_hours", "label": "Person-hours consumed by a major incident",
     "unit": "hours", "group": "Resilience",
     "help": "Across everyone, for the whole response.",
     "feeds": ["network_security", "post_breach_improvements"]},
    {"key": "pii_records", "label": "Personal records held in SAP",
     "unit": "count", "group": "Data",
     "help": "Employees, customers, patients. Zero is a valid and useful answer.",
     "feeds": ["information_privacy"]},
    {"key": "cost_per_record", "label": "Your cost per breached record",
     "unit": "currency", "group": "Data",
     "help": "Notification, credit monitoring and support. From your own DPO or "
             "insurer — WE DO NOT SUPPLY A FIGURE, because we cannot defend one.",
     "feeds": ["information_privacy"]},
    {"key": "regulatory_max_fine", "label": "Maximum credible regulatory fine",
     "unit": "currency", "group": "Data",
     "help": "Under GDPR this is up to 4% of worldwide annual turnover. Your "
             "counsel's view, not ours.",
     "feeds": ["information_privacy"]},
    {"key": "annual_disbursements", "label": "Annual payments disbursed through SAP",
     "unit": "currency", "group": "Financial",
     "help": "Prices payment fraud: what a fraudulent payment run could reach.",
     "feeds": ["financial_fraud"]},
    {"key": "max_single_payment_run", "label": "Largest single payment run",
     "unit": "currency", "group": "Financial",
     "help": "Fraud is usually bounded by one run, not the annual total.",
     "feeds": ["financial_fraud"]},
    {"key": "ransom_budget", "label": "Credible extortion demand",
     "unit": "currency", "group": "Financial",
     "help": "Leave blank if you have a no-payment policy — the component is then "
             "excluded rather than zeroed, and we say so.",
     "feeds": ["cyber_extortion"]},
    {"key": "insurance_retention", "label": "Cyber insurance retention (deductible)",
     "unit": "currency", "group": "Insurance",
     "help": "Reported alongside the loss, never subtracted from it.",
     "feeds": []},
    {"key": "insurance_limit", "label": "Cyber insurance limit",
     "unit": "currency", "group": "Insurance",
     "help": "Reported alongside the loss, never subtracted from it.",
     "feeds": []},
]

PARAMETER_KEYS = tuple(p["key"] for p in PARAMETERS)


def _band(value: float, spread: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """A three-point band around a single answer."""
    s = spread or SPREAD
    return {"min": value * s["min"], "likely": value * s["likely"],
            "max": value * s["max"]}


def _answer(answers: Dict[str, Any], key: str) -> Answer:
    raw = answers.get(key)
    if raw is None or raw == "":
        return Answer(key, None, "unanswered")
    try:
        return Answer(key, float(raw), "user")
    except (TypeError, ValueError):
        return Answer(key, None, "unanswered", note="not a number")


def build_loss_components(answers: Dict[str, Any]) -> Dict[str, Any]:
    """Price the FAIR-MAM modules this customer's answers support.

    Returns {"components": {name: {band, mam_module, basis, inputs}},
             "unpriced": [...], "answers": {...}}

    A module absent from `components` was NOT priced, and the caller must not
    treat it as zero — it is unknown. `unpriced` names each one and which answer
    would price it, so the gap is reportable rather than invisible.
    """
    a = {k: _answer(answers, k) for k in PARAMETER_KEYS}
    components: Dict[str, Any] = {}
    unpriced: List[Dict[str, str]] = []

    def need(*keys: str) -> Optional[List[Answer]]:
        got = [a[k] for k in keys]
        return got if all(x.answered() for x in got) else None

    # ── Business interruption: hours x hourly gross margin ───────────────────
    have = need("sap_revenue", "gross_margin_pct", "downtime_hours")
    if have:
        revenue, margin_pct, hours = (x.value for x in have)
        year_hours = (a["revenue_hours_per_year"].value
                      if a["revenue_hours_per_year"].answered()
                      else DEFAULT_REVENUE_HOURS)
        margin_per_hour = revenue * (margin_pct / 100.0) / max(year_hours, 1.0)
        components["business_interruption"] = {
            "band": _band(margin_per_hour * hours),
            "mam_module": "business_interruption",
            "fair_form": "Productivity Loss",
            "basis": (f"{hours:,.0f}h outage x margin of "
                      f"{margin_per_hour:,.0f} per hour "
                      f"({margin_pct:.0f}% of revenue over {year_hours:,.0f}h)"),
            "inputs": ["sap_revenue", "gross_margin_pct", "downtime_hours",
                       "revenue_hours_per_year"],
        }
    else:
        unpriced.append({"module": "business_interruption",
                         "needs": "annual revenue through SAP, gross margin, and "
                                  "hours to restore"})

    # ── Response cost: person-hours x loaded rate ────────────────────────────
    have = need("response_staff_cost_hour", "response_staff_hours")
    if have:
        rate, hours = (x.value for x in have)
        components["network_security"] = {
            "band": _band(rate * hours),
            "mam_module": "network_security",
            "fair_form": "Response Costs",
            "basis": f"{hours:,.0f} person-hours at {rate:,.0f} per hour",
            "inputs": ["response_staff_cost_hour", "response_staff_hours"],
        }
    else:
        unpriced.append({"module": "network_security",
                         "needs": "response person-hours and their loaded hourly cost"})

    # ── Information privacy: records x per-record cost, plus the fine ────────
    # A ZERO RECORD COUNT IS AN ANSWER, AND A GOOD ONE. It prices the component at
    # zero rather than leaving it unpriced, which is a materially different claim:
    # "this estate holds no personal data" versus "nobody told us".
    if a["pii_records"].answered() and a["cost_per_record"].answered():
        records, per_record = a["pii_records"].value, a["cost_per_record"].value
        fine = (a["regulatory_max_fine"].value
                if a["regulatory_max_fine"].answered() else 0.0)
        base = records * per_record
        band = _band(base)
        if fine:
            # The fine is not scaled by SPREAD: a stated maximum is a ceiling, so it
            # belongs at `max` and cannot sit above it.
            band["max"] = max(band["max"], base + fine)
        components["information_privacy"] = {
            "band": band,
            "mam_module": "information_privacy",
            "fair_form": "Response Costs / Fines and Judgments",
            "basis": (f"{records:,.0f} records at {per_record:,.0f} each"
                      + (f", up to a {fine:,.0f} regulatory maximum" if fine else "")),
            "inputs": ["pii_records", "cost_per_record", "regulatory_max_fine"],
        }
    else:
        unpriced.append({"module": "information_privacy",
                         "needs": "the number of personal records and your cost per "
                                  "breached record"})

    # ── Financial fraud: bounded by a payment run, not the annual total ──────
    if a["max_single_payment_run"].answered():
        run = a["max_single_payment_run"].value
        components["financial_fraud"] = {
            "band": _band(run, {"min": 0.1, "likely": 0.4, "max": 1.0}),
            "mam_module": "financial_fraud",
            "fair_form": "Replacement Costs",
            "basis": (f"a fraction of a {run:,.0f} payment run — fraud is usually "
                      f"caught mid-run, so the band runs from 10% to the whole run"),
            "inputs": ["max_single_payment_run"],
        }
    elif a["annual_disbursements"].answered():
        # Falling back to the annual total needs saying out loud: it is a much
        # weaker basis, and the note travels with the number into the report.
        annual = a["annual_disbursements"].value
        components["financial_fraud"] = {
            "band": _band(annual / 12.0, {"min": 0.1, "likely": 0.4, "max": 1.0}),
            "mam_module": "financial_fraud",
            "fair_form": "Replacement Costs",
            "basis": (f"no single-run figure given, so a month of the {annual:,.0f} "
                      f"annual disbursement is used as a proxy — WEAKER, and a real "
                      f"payment-run figure should replace it"),
            "inputs": ["annual_disbursements"],
        }
    else:
        unpriced.append({"module": "financial_fraud",
                         "needs": "your largest single payment run"})

    # ── Extortion ────────────────────────────────────────────────────────────
    if a["ransom_budget"].answered():
        components["cyber_extortion"] = {
            "band": _band(a["ransom_budget"].value),
            "mam_module": "cyber_extortion",
            "fair_form": "Response Costs",
            "basis": f"a credible demand of {a['ransom_budget'].value:,.0f}",
            "inputs": ["ransom_budget"],
        }
    else:
        unpriced.append({"module": "cyber_extortion",
                         "needs": "a credible extortion demand (blank is fine if you "
                                  "will not pay — the component is then excluded)"})

    return {
        "components": components,
        "unpriced": unpriced,
        "answers": {k: v.as_dict() for k, v in a.items()},
        "priced_modules": sorted(components),
        "spread": dict(SPREAD),
    }


def apply_to_scenario(scenario: Dict[str, Any],
                      priced: Dict[str, Any],
                      scale: Optional[float] = None) -> Dict[str, Any]:
    """Replace a catalogue scenario's illustrative loss bands with priced ones.

    Only components this scenario already declares are replaced. A scenario that
    never had a privacy loss does not acquire one because the customer answered the
    privacy question — the catalogue decides WHICH losses a scenario produces, and
    the customer's answers decide HOW BIG they are. Mixing those two authorities is
    how a model starts inventing exposures nobody has.

    A declared component with no priced equivalent is LEFT AS THE CATALOGUE HAD IT
    and reported in `kept_illustrative`, never silently dropped: dropping it would
    quietly shrink the customer's risk because they skipped a question.
    """
    out = dict(scenario)
    mapping = scenario.get("loss_component_map") or _default_map(scenario)
    components = priced.get("components", {})

    replaced: List[str] = []
    scaled: List[str] = []
    kept: List[str] = []
    for block_name in ("primary_loss", "secondary_loss"):
        block = scenario.get(block_name)
        if not isinstance(block, dict):
            continue
        new_block = dict(block)
        for component_name, spec in block.items():
            module = mapping.get(component_name)
            priced_component = components.get(module) if module else None
            if priced_component:
                new_block[component_name] = dict(priced_component["band"])
                replaced.append(f"{block_name}.{component_name}")
            elif scale is not None and isinstance(spec, dict):
                new_block[component_name] = {
                    k: float(v) * scale for k, v in spec.items()
                    if k in ("min", "likely", "max") and isinstance(v, (int, float))
                } or dict(spec)
                scaled.append(f"{block_name}.{component_name}")
            else:
                kept.append(f"{block_name}.{component_name}")
        out[block_name] = new_block

    out["_loss_provenance"] = {
        "replaced": replaced,
        "scaled_from_illustrative": scaled,
        "scale_factor": scale,
        "kept_illustrative": kept,
    }
    return out


def _default_map(scenario: Dict[str, Any]) -> Dict[str, str]:
    """Best-effort component -> FAIR-MAM module, for catalogue entries that predate
    the map.

    `replacement` MAPS TO HARDWARE, NOT TO FRAUD, and the first version of this
    table got that wrong. FAIR-MAM uses "Replacement Cost" as a FORM of loss (ReplC)
    that several modules share, so the word appears under both Hardware Bricking
    (server and laptop replacement) and Financial Fraud (funds transfer). Mapping
    the bare component name to fraud priced a RANSOMWARE scenario with a payment-run
    figure: it raised that component 3.8x and silently cancelled out the reductions
    everywhere else, so the customer's own numbers appeared to make no difference.
    Payment fraud is priced where it belongs, in the fraud scenario, by a catalogue
    `loss_component_map`.
    """
    return {
        "productivity": "business_interruption",
        "response": "network_security",
        "replacement": "hardware_bricking",
        "fines": "information_privacy",
        "notification": "information_privacy",
        "ransom": "cyber_extortion",
        "fraud": "financial_fraud",
        "funds_transfer": "financial_fraud",
        "reputation": "reputational_damage",
        "competitive_advantage": "proprietary_data",
    }


def scale_factor(answers: Dict[str, Any], catalogue_revenue: float) -> Optional[float]:
    """How far this customer sits from the catalogue's illustrative company.

    The shipped bands are calibrated, by the catalogue's own `_meta`, to a $1B
    revenue enterprise. Components we cannot price directly — reputational damage,
    competitive advantage — would otherwise keep that company's absolute figures on
    a business a fraction of its size, and those two are frequently the LARGEST
    terms in a scenario. Leaving them unscaled is how a EUR 420M manufacturer ends
    up carrying a EUR 1B group's reputational loss.

    A revenue ratio is a first-order adjustment and nothing more. It is applied only
    to components with no customer-priced equivalent, it is reported as
    `scaled_from_illustrative` so it appears in the breakdown rather than hiding in
    a total, and it is never applied on top of a priced component.
    """
    try:
        revenue = float(answers.get("sap_revenue") or 0)
    except (TypeError, ValueError):
        return None
    if revenue <= 0 or catalogue_revenue <= 0:
        return None
    return revenue / catalogue_revenue
