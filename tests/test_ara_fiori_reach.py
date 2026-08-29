"""The action gate has two doors, and until recently it watched one.

An S/4HANA user reaches a capability through a transaction code OR through a
Fiori app, and only the first passes through S_TCODE. A conflict whose two
halves are Fiori apps was therefore reported clean — not "no conflict found",
but "the question was never asked", which reads identically on a report.

These tests pin both directions of the resolution:

  role -> tile -> app -> OData service      (fiori_tiles export)
  role -> S_SERVICE grant -> service        (AGR_1251, like any other object)

and, more importantly, they pin what must NOT happen. The first version of the
gate let S_TCODE '*' short-circuit everything, so every holder of a super-user
role became an offender on every Fiori rule — on the sample estate, two users
with zero tiles between them. A transaction wildcard confers no launchpad tile.
`test_a_transaction_wildcard_does_not_confer_a_tile` is the regression.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402

#: A conflict whose two halves are Fiori apps and nothing else.
APP_RISK = [{
    "risk_id": "ZF-01", "description": "manage users vs manage roles, via Fiori",
    "risk_type": "SOD", "severity": "HIGH", "process": "BASIS-SEC",
    "functions": [{"name": "Users", "actions": ["F0733"], "permissions": []},
                  {"name": "Roles", "actions": ["F0735"], "permissions": []}]}]

#: The same conflict named by the services behind those apps.
SERVICE_RISK = [dict(APP_RISK[0], risk_id="ZF-02", functions=[
    {"name": "Users", "actions": ["API_USER_MANAGEMENT"], "permissions": []},
    {"name": "Roles", "actions": ["API_BUSINESS_ROLE"], "permissions": []}])]


def tile(role, app, service):
    return {"TILE_ID": "T_%s" % app, "APP_ID": app, "CATALOG_ID": "Z_CAT",
            "ODATA_SERVICE": service, "ROLE": role, "TITLE": app}


BOTH_TILES = [tile("Z_ADMIN", "F0733", "API_USER_MANAGEMENT"),
              tile("Z_ADMIN", "F0735", "API_BUSINESS_ROLE")]


def offenders(data, ruleset=None):
    a = ARA(data)
    if ruleset is not None:
        a.RULESET = ruleset
    a.run_all_checks()
    # Role mode labels an offender "Role Z_X"; user mode "LWANG (n role(s))".
    return sorted(item[5:].split(" ")[0] if item.startswith("Role ")
                  else item.split(" ")[0]
                  for f in a.findings
                  for item in (f.get("affected_items") or []))


def auth(role, obj, field, low):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": "A1", "FIELD": field,
            "LOW": low, "HIGH": ""}


# ── the reach that was missing ─────────────────────────────────────────────

def test_a_conflict_held_entirely_through_fiori_apps_is_found():
    """THE test. Neither half of this conflict touches S_TCODE."""
    data = {"role_auth_values": [auth("Z_ADMIN", "S_USER_GRP", "ACTVT", "01")],
            "fiori_tiles": BOTH_TILES}
    assert offenders(data, APP_RISK) == ["Z_ADMIN"]


def test_the_same_conflict_is_found_when_the_rule_names_the_service():
    """An app carries no permissions of its own; they belong to the service
    behind it. A ruleset may reasonably name either."""
    data = {"role_auth_values": [auth("Z_ADMIN", "S_USER_GRP", "ACTVT", "01")],
            "fiori_tiles": BOTH_TILES}
    assert offenders(data, SERVICE_RISK) == ["Z_ADMIN"]


def test_an_explicit_s_service_grant_reaches_the_service():
    """The launchpad is not the only door to an OData service."""
    data = {"role_auth_values": [
        auth("Z_API", "S_SERVICE", "SRV_NAME", "API_USER_MANAGEMENT"),
        auth("Z_API", "S_SERVICE", "SRV_NAME", "API_BUSINESS_ROLE")]}
    assert offenders(data, SERVICE_RISK) == ["Z_API"]


def test_one_tile_alone_is_not_a_conflict():
    data = {"role_auth_values": [auth("Z_HALF", "S_USER_GRP", "ACTVT", "01")],
            "fiori_tiles": [BOTH_TILES[0]]}
    assert offenders(data, APP_RISK) == []


def test_a_role_that_exists_only_in_the_tile_export_is_still_analysed():
    """A business role granting Fiori apps and no S_TCODE is ordinary on
    S/4HANA. Dropping it would exclude its holders from every result."""
    data = {"role_auth_values": [auth("Z_OTHER", "S_TCODE", "TCD", "SU01")],
            "fiori_tiles": BOTH_TILES}
    assert offenders(data, APP_RISK) == ["Z_ADMIN"]


def test_the_user_is_named_when_the_two_halves_sit_in_different_roles():
    """The conflict a per-role view cannot see."""
    data = {"role_auth_values": [auth("Z_A", "S_USER_GRP", "ACTVT", "01"),
                                 auth("Z_B", "S_USER_GRP", "ACTVT", "01")],
            "fiori_tiles": [tile("Z_A", "F0733", "API_USER_MANAGEMENT"),
                            tile("Z_B", "F0735", "API_BUSINESS_ROLE")],
            "user_roles": [{"UNAME": "LWANG", "AGR_NAME": "Z_A"},
                           {"UNAME": "LWANG", "AGR_NAME": "Z_B"}]}
    assert offenders(data, APP_RISK) == ["LWANG"]


# ── what must NOT happen ───────────────────────────────────────────────────

def test_a_transaction_wildcard_does_not_confer_a_tile():
    """THE REGRESSION. S_TCODE '*' grants every transaction and not one Fiori
    app: the launchpad needs a tile assignment and the service needs S_SERVICE.
    The first version of the gate short-circuited on this flag and made every
    super-user an offender on every Fiori rule."""
    data = {"role_auth_values": [auth("Z_SUPER", "S_TCODE", "TCD", "*")],
            "fiori_tiles": BOTH_TILES}
    assert "Z_SUPER" not in offenders(data, APP_RISK)


def test_a_transaction_wildcard_still_reaches_every_transaction():
    """The fix must not have closed the door it was not aimed at."""
    tcode_risk = [dict(APP_RISK[0], risk_id="ZF-03", functions=[
        {"name": "A", "actions": ["FK02"], "permissions": []},
        {"name": "B", "actions": ["F110"], "permissions": []}])]
    data = {"role_auth_values": [auth("Z_SUPER", "S_TCODE", "TCD", "*")],
            "fiori_tiles": BOTH_TILES}
    assert offenders(data, tcode_risk) == ["Z_SUPER"]


def test_a_service_wildcard_does_not_confer_a_transaction():
    """And the leak must not run the other way either."""
    tcode_risk = [dict(APP_RISK[0], risk_id="ZF-04", functions=[
        {"name": "A", "actions": ["FK02"], "permissions": []},
        {"name": "B", "actions": ["F110"], "permissions": []}])]
    data = {"role_auth_values": [auth("Z_API", "S_SERVICE", "SRV_NAME", "*")],
            "fiori_tiles": BOTH_TILES}
    assert offenders(data, tcode_risk) == []


def test_a_service_wildcard_reaches_the_services_the_estate_publishes():
    """Bounded by the export rather than open: calling an OData endpoint
    directly needs no tile, but it does need the service to exist."""
    data = {"role_auth_values": [auth("Z_API", "S_SERVICE", "SRV_NAME", "*")],
            "fiori_tiles": BOTH_TILES}
    # Z_ADMIN also offends — it holds both tiles. The claim under test is that
    # the wildcard holder reaches the services without holding any tile.
    assert "Z_API" in offenders(data, SERVICE_RISK)


def test_an_app_is_not_mapped_to_an_equivalent_transaction():
    """No export here carries an app-to-transaction mapping, and inventing one
    would put users into conflicts on the strength of a guess. A role holding
    only the classic transactions must not offend a rule naming only apps."""
    data = {"role_auth_values": [auth("Z_CLASSIC", "S_TCODE", "TCD", "SU01"),
                                 auth("Z_CLASSIC", "S_TCODE", "TCD", "PFCG")],
            "fiori_tiles": BOTH_TILES}
    assert "Z_CLASSIC" not in offenders(data, APP_RISK)


def test_an_estate_with_no_fiori_export_behaves_exactly_as_before():
    """ECC has no launchpad to publish one, and must be unaffected."""
    tcode_risk = [dict(APP_RISK[0], risk_id="ZF-05", functions=[
        {"name": "A", "actions": ["FK02"], "permissions": []},
        {"name": "B", "actions": ["F110"], "permissions": []}])]
    data = {"role_auth_values": [auth("Z_R", "S_TCODE", "TCD", "FK02"),
                                 auth("Z_R", "S_TCODE", "TCD", "F110")]}
    assert offenders(data, tcode_risk) == ["Z_R"]
