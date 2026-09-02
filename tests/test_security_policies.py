"""Security policies override the profile parameters this product asserts.

SAP's own Security Baseline reads three configuration stores for requirement
PWDPOL-A: `ABAP_INSTANCE_PAHI`, `AUTH_SECURITY_POLICY` and
`USER_PASSWD_HASH_USAGE`. This product read the first and nothing else.

The second is SECPOL. A security policy assigned to a user overrides the
corresponding instance profile parameter FOR THAT USER, so
`login/min_password_lng = 12` and a policy setting six are both true at once and
only the second governs whoever holds the policy. Every `PARAM-login/*` finding
reads the profile — which means a system whose administrators sit on a weakened
policy reported a hardened password configuration.

The store had been recognised and declined, with a reason that was correct about
something else: "merging the two would score a policy attribute against a
parameter threshold". True, and an argument against MERGING them. It was read as
a reason to assess neither. These checks COMPARE without merging: policy value
against profile value, each in its own units, reporting only the relation.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_params import SecurityParamAuditor                # noqa: E402


def fired(data):
    return {f["check_id"]: f for f in SecurityParamAuditor(data).run_all_checks()}


def param(name, value):
    return {"PARAMETER": name, "VALUE": str(value)}


def attr(policy, attribute, value):
    return {"NAME": policy, "ATTRIBUTE": attribute, "VALUE": str(value)}


PROFILE = [param("login/min_password_lng", 12),
           param("login/fails_to_user_lock", 3),
           param("login/password_expiration_time", 90)]


# ── SECPOL-001 — the policy is weaker than the profile it overrides ────────

def test_a_policy_shorter_than_the_profile_is_reported():
    got = fired({"security_params": PROFILE,
                 "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 6)]})
    item, = got["SECPOL-001"]["affected_items"]
    assert "MIN_PASSWORD_LENGTH = 6" in item
    assert "login/min_password_lng = 12" in item, (
        "both values must be quoted — neither is scored against the other's "
        "baseline threshold, and the reader has to see the pair to judge it")


def test_a_policy_stronger_than_the_profile_is_not_a_finding():
    assert "SECPOL-001" not in fired({
        "security_params": PROFILE,
        "security_policies": [attr("Z_STRICT", "MIN_PASSWORD_LENGTH", 16)]})


def test_a_policy_equal_to_the_profile_is_not_a_finding():
    assert "SECPOL-001" not in fired({
        "security_params": PROFILE,
        "security_policies": [attr("Z_SAME", "MIN_PASSWORD_LENGTH", 12)]})


def test_the_direction_is_inverted_for_a_maximum():
    """More failed attempts before lockout is weaker, not stronger."""
    got = fired({"security_params": PROFILE,
                 "security_policies": [
                     attr("Z_SVC", "MAX_FAILED_PASSWORD_LOGON_ATTEMPTS", 50)]})
    assert "SECPOL-001" in got
    assert "SECPOL-001" not in fired({
        "security_params": PROFILE,
        "security_policies": [
            attr("Z_TIGHT", "MAX_FAILED_PASSWORD_LOGON_ATTEMPTS", 2)]})


def test_zero_on_a_maximum_means_no_limit_not_the_strictest_value():
    """PASSWORD_CHANGE_INTERVAL = 0 is "never expires", the weakest setting
    available. Compared literally it looked three months stricter than a
    90-day profile, and the corpus carries exactly that policy."""
    got = fired({"security_params": PROFILE,
                 "security_policies": [attr("Z_SVC", "PASSWORD_CHANGE_INTERVAL", 0)]})
    item, = got["SECPOL-001"]["affected_items"]
    assert "0 (no limit)" in item, (
        "the display must not print a bare 0 that reads as strict, nor the "
        "infinity the comparison uses internally")


def test_zero_on_a_minimum_keeps_its_ordinary_meaning():
    """On a minimum, 0 is already the weakest value and needs no special
    reading — and must not be turned into "no limit"."""
    got = fired({"security_params": PROFILE,
                 "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 0)]})
    item, = got["SECPOL-001"]["affected_items"]
    assert "MIN_PASSWORD_LENGTH = 0," in item
    assert "no limit" not in item


def test_the_holders_of_the_policy_are_named():
    """Which accounts a weakened policy governs is the whole question."""
    got = fired({
        "security_params": PROFILE,
        "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 4)],
        "users": [{"BNAME": "SVC_RFC_01", "SECURITY_POLICY": "Z_SVC"},
                  {"BNAME": "JSMITH", "SECURITY_POLICY": ""}],
    })
    item, = got["SECPOL-001"]["affected_items"]
    assert "1 user(s): SVC_RFC_01" in item
    assert "JSMITH" not in item


def test_unknown_holders_are_said_to_be_unknown():
    """A users export with no SECURITY_POLICY column cannot name them, and the
    finding must not imply the policy governs nobody."""
    item, = fired({
        "security_params": PROFILE,
        "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 4)],
    })["SECPOL-001"]["affected_items"]
    assert "holders not shown" in item


def test_a_policy_attribute_is_never_scored_against_a_baseline_threshold():
    """The reason the store was declined, honoured. With no profile parameter
    to compare against, the policy value is not judged on its own."""
    assert "SECPOL-001" not in fired({
        "security_params": [param("login/fails_to_user_lock", 3)],
        "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 1)]})


# ── SECPOL-002 — policies in use, and not exported ─────────────────────────

def test_policies_in_use_but_not_exported_degrades_coverage():
    """A hardened profile is not evidence for users it does not govern."""
    got = fired({"security_params": PROFILE,
                 "users": [{"BNAME": "SVC_RFC_01", "SECURITY_POLICY": "Z_SVC"}]})
    finding = got["SECPOL-002"]
    assert finding["severity"] == "INFO", (
        "this is a value that was not read, not a verdict about the system")
    assert finding["details"]["degrades_coverage"] is True


def test_no_policy_assignments_anywhere_stays_silent():
    """Most systems use none. Firing on all of them to catch the few that do
    is how a real finding gets skimmed past."""
    got = fired({"security_params": PROFILE,
                 "users": [{"BNAME": "JSMITH", "SECURITY_POLICY": ""}]})
    assert not [k for k in got if k.startswith("SECPOL")]


def test_the_export_being_present_replaces_the_coverage_statement():
    got = fired({"security_params": PROFILE,
                 "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 4)],
                 "users": [{"BNAME": "SVC_RFC_01", "SECURITY_POLICY": "Z_SVC"}]})
    assert "SECPOL-002" not in got
    assert "SECPOL-001" in got


# ── SECPOL-003 — attributes this product cannot yet judge ──────────────────

def test_an_unmapped_attribute_is_listed_rather_than_dropped():
    """A silently ignored attribute and a compliant one look identical."""
    got = fired({"security_params": PROFILE,
                 "security_policies": [attr("Z_SVC", "DISABLE_PASSWORD_LOGON", 0)]})
    assert got["SECPOL-003"]["affected_items"] == ["DISABLE_PASSWORD_LOGON"]
    assert got["SECPOL-003"]["details"]["degrades_coverage"] is True


def test_a_fully_mapped_policy_produces_no_coverage_statement():
    assert "SECPOL-003" not in fired({
        "security_params": PROFILE,
        "security_policies": [attr("Z_SVC", "MIN_PASSWORD_LENGTH", 16)]})


# ── the attribute map's own integrity ──────────────────────────────────────

@pytest.mark.parametrize(
    "attribute, pair", sorted(SecurityParamAuditor.POLICY_ATTRIBUTE_PARAMETERS.items()))
def test_every_mapped_attribute_names_a_parameter_this_module_knows(attribute, pair):
    """A map entry naming a parameter the baseline does not carry can never
    fire, and would look like a covered attribute."""
    param_name, direction = pair
    assert direction in ("min", "max")
    rules = SecurityParamAuditor({}).effective_rules()
    assert param_name in rules, (
        "%s maps to %s, which is in neither the ECS nor the legacy rule table — "
        "so nothing in this product ever reads that parameter and the "
        "comparison cannot happen" % (attribute, param_name))


def test_the_corpus_exercises_the_override():
    """The bundled estate carries a service-account policy that relaxes length,
    lockout and expiry — the shape this check exists for, and the shape a real
    estate most often has."""
    import csv
    rows = list(csv.DictReader(
        (ROOT / "sample_data" / "security_policies.csv").open(encoding="utf-8-sig")))
    assert rows, "the corpus no longer carries a security policy to assess"
    users = list(csv.DictReader(
        (ROOT / "sample_data" / "users.csv").open(encoding="utf-8-sig")))
    assert any(r.get("SECURITY_POLICY") for r in users), (
        "no user is assigned a policy, so the override cannot be exercised")
