"""HOTNEWS-016 — a note recorded as implemented whose MANUAL step is undone.

SNOTE confirms a note's automatic corrections, not the manual post-implementation
activities the note text requires. HOTNEWS-016 verifies those manual steps — but
ONLY where a `manual_step` entry carries a named source, exactly as the workaround
check (HOTNEWS-009) does. The shipped `cve_exposure.json` seed is intentionally
empty (no manual step could be transcribed from note text to the charter's
standard without risking invention), so these tests drive the MECHANISM with
synthetic, source-bearing entries injected into the exposure cache. That proves
the verifier fires correctly the day a sourced entry is added, without shipping
one that was guessed.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor  # noqa: E402


def _assessable_note():
    """A real ABAP-assessable catalogue note, picked from the catalogue so the
    test does not pin a specific number that a catalogue edit could remove."""
    aud = SapHotNewsAuditor({})
    assessable, _ = aud._partition(aud._build_catalog())
    return aud._norm_note(assessable[0]["note"])


def _run(manual_step, *, applied=True, roles=None, params=None):
    note = _assessable_note()
    data = {
        "applied_notes": [{"NOTE": note,
                           "STATUS": "Completely implemented" if applied
                           else "Can be implemented"}],
    }
    if roles is not None:
        data["role_auth_values"] = roles
    if params is not None:
        data["security_params"] = params
    aud = SapHotNewsAuditor(data)
    # Inject the exposure record rather than shipping it: the production seed
    # stays empty, the mechanism is exercised.
    aud._exposure_cache = {note: {"manual_step": manual_step}}
    findings = aud.run_all_checks()
    return note, {f["check_id"]: f for f in findings}


# ── authorization_absent: the step is to withdraw an authorization ───────────

def test_fires_when_the_authorization_the_step_removes_is_still_granted():
    step = {"kind": "authorization_absent", "object": "S_DEVELOP",
            "field": "ACTVT", "value": "02",
            "statement": "withdraw S_DEVELOP activity 02 added by the pre-fix role",
            "source": "test fixture — synthetic, not a real note mapping"}
    roles = [{"AGR_NAME": "Z_LEGACY_DEV", "OBJECT": "S_DEVELOP",
              "FIELD": "ACTVT", "LOW": "02", "HIGH": "02"}]
    note, by_id = _run(step, roles=roles)
    assert "HOTNEWS-016" in by_id
    f = by_id["HOTNEWS-016"]
    assert f["severity"] == "HIGH"
    assert "Z_LEGACY_DEV" in " ".join(f["affected_items"])


def test_silent_when_the_authorization_is_already_gone():
    step = {"kind": "authorization_absent", "object": "S_DEVELOP",
            "field": "ACTVT", "value": "02", "statement": "withdraw it",
            "source": "test fixture"}
    # No role grants it — the manual step was done.
    _, by_id = _run(step, roles=[{"AGR_NAME": "Z_OTHER", "OBJECT": "S_TCODE",
                                  "FIELD": "TCD", "LOW": "SU01", "HIGH": "SU01"}])
    assert "HOTNEWS-016" not in by_id


# ── parameter_value: the step is to set a profile parameter ──────────────────

def test_fires_when_the_parameter_the_step_sets_holds_another_value():
    step = {"kind": "parameter_value", "parameter": "login/min_password_lng",
            "value": "8", "statement": "set login/min_password_lng to 8",
            "source": "test fixture"}
    _, by_id = _run(step, params=[{"NAME": "login/min_password_lng", "VALUE": "6"}])
    assert "HOTNEWS-016" in by_id
    assert "login/min_password_lng" in " ".join(by_id["HOTNEWS-016"]["affected_items"])


def test_fires_when_the_parameter_the_step_sets_is_absent():
    step = {"kind": "parameter_value", "parameter": "login/min_password_lng",
            "value": "8", "statement": "set it", "source": "test fixture"}
    _, by_id = _run(step, params=[{"NAME": "login/other", "VALUE": "1"}])
    assert "HOTNEWS-016" in by_id


def test_silent_when_the_parameter_already_holds_the_required_value():
    step = {"kind": "parameter_value", "parameter": "login/min_password_lng",
            "value": "8", "statement": "set it", "source": "test fixture"}
    _, by_id = _run(step, params=[{"NAME": "login/min_password_lng", "VALUE": "8"}])
    assert "HOTNEWS-016" not in by_id


# ── the source gate and the applied gate ─────────────────────────────────────

def test_an_unsourced_manual_step_is_never_checked():
    """No source, no check — an invented manual step is worse than none."""
    step = {"kind": "authorization_absent", "object": "S_DEVELOP",
            "field": "ACTVT", "value": "02", "statement": "withdraw it"}  # no source
    roles = [{"AGR_NAME": "Z_LEGACY_DEV", "OBJECT": "S_DEVELOP",
              "FIELD": "ACTVT", "LOW": "02", "HIGH": "02"}]
    _, by_id = _run(step, roles=roles)
    assert "HOTNEWS-016" not in by_id


def test_a_note_not_recorded_as_implemented_is_not_a_manual_step_gap():
    """HOTNEWS-016 is about notes the export says ARE applied. A note that was
    never implemented is the workaround check's business (HOTNEWS-009), not this."""
    step = {"kind": "authorization_absent", "object": "S_DEVELOP",
            "field": "ACTVT", "value": "02", "statement": "withdraw it",
            "source": "test fixture"}
    roles = [{"AGR_NAME": "Z_LEGACY_DEV", "OBJECT": "S_DEVELOP",
              "FIELD": "ACTVT", "LOW": "02", "HIGH": "02"}]
    _, by_id = _run(step, applied=False, roles=roles)
    assert "HOTNEWS-016" not in by_id


def test_the_production_seed_ships_no_manual_step_entries():
    """The data table is deliberately empty: nothing was transcribed without a
    sourced, verifiable mapping. If a real entry is added later, this test is
    updated alongside it — it exists so an un-sourced entry cannot slip in
    unremarked."""
    import json
    data = json.loads((ROOT / "data" / "cve_exposure.json").read_text(encoding="utf-8"))
    seeded = [n for n, e in data["entries"].items() if "manual_step" in e]
    assert seeded == [], (
        "cve_exposure.json ships manual_step entries %s — each must carry a named "
        "source transcribed from the note text, and this test updated to match"
        % seeded)
