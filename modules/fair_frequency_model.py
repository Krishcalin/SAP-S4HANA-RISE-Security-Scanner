"""Turn a customer's own observations into FAIR contact frequency.

WHAT WAS WRONG, MEASURED
------------------------
`modules/fair_loss_model.py` exists because the shipped catalogue carried one
illustrative company's LOSSES and every customer received them. It fixed that
half: magnitudes are now priced from the customer's own answers, scaled by
revenue, and the product refuses to print a currency figure without them.

Nothing equivalent was ever done to the other half. `contact_frequency` and
`probability_of_action` come straight out of `data/fair_scenarios.json`,
switched only by two booleans derived from the findings. No customer answer
reaches them, so a two-hundred-person distributor and a fifty-thousand-person
bank are both told they are contacted five times a year.

Measured on `sample_data` at $1bn revenue, that produced:

    total expected loss events per year: 2.30
    -> a material SAP loss event every five months
    SAP-RCE-01 mean magnitude $25,080,419 per event
    mean ALE $34.4M = 3.4% of revenue, every year, from SAP alone

For scale, IBM's 2024 breach study puts the global AVERAGE TOTAL cost of a
breach near $4.9M. Annualised Loss Exposure is frequency times magnitude, so
calibrating the magnitude and leaving the frequency illustrative produces a
figure that is half measured and half borrowed — and presents it as neither.

THE ZERO TRAP, WHICH IS WHY THIS IS NOT JUST A RATIO
-----------------------------------------------------
The obvious calibration is "how many SAP security incidents have you had?" It
is also the one that would do the most damage. A customer with no audit log,
no SIEM feed and no monitoring answers **zero** — truthfully — and a naive model
hands them a frequency of nought and a risk of nothing. The organisations least
able to see an attack would be told they are the safest, by the tool whose own
findings say their logging is off.

So an incident count is accepted as a **cross-check and an upper bound on what
was DETECTED**, never as the frequency itself, and it is read together with the
detection posture the scan already measured. Observed CONTACT — probes, blocked
logons, rejected RFC calls — is a different quantity and is the one that can
calibrate, because it is a count of arrivals rather than a count of the
arrivals somebody noticed.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

#: The catalogue's illustrative contact rate, from `data/fair_scenarios.json`'s
#: own `_meta`. The denominator of the ratio, and the thing being replaced.
ILLUSTRATIVE_CONTACTS_PER_YEAR = 5.0

#: How far a single answer is allowed to move the catalogue. A customer
#: reporting four probes a year against an internet-facing SAP system is
#: describing their monitoring, not their threat environment; one reporting ten
#: million is describing background internet noise. Both are real answers and
#: neither should swing the model by three orders of magnitude.
MIN_SCALE = 0.1
MAX_SCALE = 10.0

#: 95% upper bound on a rate after observing nothing for three years — the rule
#: of three, 3/n. Used only to decide whether the model and the customer
#: genuinely disagree; it never moves a figure.
RULE_OF_THREE_BOUND = 3.0 / 3.0

#: Answers this model understands. Deliberately short: every question a customer
#: cannot answer is a question that gets guessed at, and a guess entered by the
#: customer is still a guess — it has just acquired their name.
ANSWERS = {
    "observed_contacts_per_year": (
        "Attempts against SAP seen in a year — blocked logons, rejected RFC "
        "calls, gateway denials, WAF blocks in front of Fiori. From the SIEM, "
        "the Security Audit Log or the reverse proxy. This is the one that "
        "calibrates: it counts arrivals, not the arrivals somebody noticed."),
    "sap_security_incidents_3y": (
        "Material SAP security incidents in three years. A CROSS-CHECK, never "
        "the frequency itself — see the zero trap in this module's docstring."),
}


class Calibration(dict):
    """Applied or not, and why. A dict so it stores and serialises unchanged."""

    @property
    def applied(self) -> bool:
        return bool(self.get("applied"))


def _positive(answers: Dict[str, Any], key: str) -> Optional[float]:
    raw = answers.get(key)
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0.0 else None


def calibrate(answers: Optional[Dict[str, Any]]) -> Calibration:
    """How far this customer's observed contact sits from the catalogue's.

    Returns a Calibration that is `applied` only when an answer that can
    honestly drive a frequency was supplied. Everything else — a missing file,
    an incident count on its own, an unparseable value — leaves it unapplied,
    and an unapplied calibration is what makes the product decline to state an
    event rate rather than state the catalogue's.
    """
    answers = answers or {}
    contacts = _positive(answers, "observed_contacts_per_year")
    incidents = _positive(answers, "sap_security_incidents_3y")

    if contacts is None:
        return Calibration({
            "applied": False,
            "reason": ("no observed contact rate supplied"
                       if incidents is None else
                       "only an incident count was supplied, which cannot "
                       "calibrate a contact frequency on its own"),
            "answers_understood": sorted(ANSWERS),
            "incidents_3y": incidents,
        })

    raw = contacts / ILLUSTRATIVE_CONTACTS_PER_YEAR if contacts else MIN_SCALE
    scale = min(MAX_SCALE, max(MIN_SCALE, raw))
    return Calibration({
        "applied": True,
        "basis": "observed_contacts_per_year",
        "observed_contacts_per_year": contacts,
        "illustrative_contacts_per_year": ILLUSTRATIVE_CONTACTS_PER_YEAR,
        "scale": scale,
        # Disclosed rather than applied silently. A customer whose answer was
        # clamped is being told something different from what they said, and
        # the first person to notice should not be them.
        "clamped": raw != scale,
        "raw_scale": raw,
        "incidents_3y": incidents,
    })


def apply_to_scenario(scenario: Dict[str, Any],
                      calibration: Calibration) -> Dict[str, Any]:
    """Scale a scenario's contact frequency bands. Magnitudes are untouched.

    Only CONTACT frequency moves. Probability of action is a property of the
    threat actor's motivation against this kind of target, not of how much
    traffic arrives, and scaling both would apply one observation twice.
    """
    if not calibration.applied:
        return scenario
    scale = float(calibration["scale"])
    out = dict(scenario)
    for band in ("baseline", "exposed"):
        bands = (scenario.get("contact_frequency") or {}).get(band)
        if not isinstance(bands, dict):
            continue
        out.setdefault("contact_frequency", dict(scenario["contact_frequency"]))
        out["contact_frequency"] = dict(out["contact_frequency"])
        out["contact_frequency"][band] = {
            k: (v * scale if isinstance(v, (int, float)) and not isinstance(v, bool)
                else v)
            for k, v in bands.items()
        }
    return out


def cross_check(calibration: Calibration, modelled_lef: float) -> Optional[str]:
    """Does the modelled event rate square with what the customer has seen?

    Returns a sentence when the two disagree materially, and None when they do
    not or when there is nothing to compare. Deliberately not a correction: an
    incident count is a count of what was DETECTED, so a model above it may be
    right and the monitoring wrong. Saying so is worth more than silently
    moving the number to agree with the weaker measurement.
    """
    incidents = calibration.get("incidents_3y")
    if incidents is None or modelled_lef <= 0:
        return None
    observed_per_year = float(incidents) / 3.0

    # THE RULE OF THREE, not an arbitrary threshold. Observing zero events in
    # three years puts a 95% upper confidence bound of 3/3 = 1.0 events a year
    # on the true rate. A model expecting more than that is not merely higher
    # than what was seen — it disagrees with what was seen, at a confidence
    # worth a sentence. Below it the two are compatible and silence is correct.
    if observed_per_year <= 0 and modelled_lef > RULE_OF_THREE_BOUND:
        return ("This model expects %.1f loss events a year; the organisation "
                "reports none in three years. Either the modelled frequency is "
                "too high for this estate, or events are occurring and not "
                "being detected — the logging findings in this report say which "
                "is more likely." % modelled_lef)
    if observed_per_year > 0 and modelled_lef > observed_per_year * 5:
        return ("This model expects %.1f loss events a year against %.1f "
                "observed. A gap that size is worth resolving before the figure "
                "is quoted." % (modelled_lef, observed_per_year))
    return None
