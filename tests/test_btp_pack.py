"""The BTP-side change for a platform finding.

THE QUALIFIER IS THE DEFECT HERE, which is what makes this family writable and is
the exact opposite of `hana_pack`. There a qualifier meant the export had not
typed the object, so the statement had to be refused. Here it names the thing to
change: `path=/`, `TrustAll=true`, `allowedHosts=['*']`, `instanceStatus=DELETED`.

NO GRAPH IS READ, and that is the difference from the other three packs. A role
change needs a (role, object) pair and an assignment a (user, role) pair, so both
walk edges. A BTP finding carries the object and its defect in ONE subject entry,
so the finding is sufficient on its own.

THREE SHAPES, AND THEY ARE NOT THE SAME STRENGTH:

    exact target value   BTP-DST-002   TrustAll=true -> false
    pure removal         BTP-SB-003    an orphaned binding needs no replacement
    exact coordinate     BTP-CC-001    narrow path=/ — to WHAT is the customer's

BTP IS NOT ONE CONSOLE, which is why `where` is per prefix. A Cloud Connector
resource is narrowed in an on-premise admin UI on port 8443; a destination in the
cockpit; a queue in Event Mesh. One label reading "BTP" would send somebody to
the wrong screen.

WHAT IS REFUSED. Four checks are examined and declined rather than left silent,
because they share a shape: the finding is that an insecure mechanism is in use,
and the change is choosing which mechanism to move TO. That is a design decision
about an integration, and `parameter_pack` already refuses the same class when a
baseline states a rule rather than a value.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def finding(check_id="BTP-CC-001", subject=None, **over):
    row = {"check_id": check_id, "sid": "PRD",
           "remediation_owner": "customer_fixable",
           "subject": subject if subject is not None else
           [{"name": "S4H_Production", "type": "cc_backend", "qualifier": "path=/"}]}
    row.update(over)
    return row


# --------------------------------------------------------------------------- #
#  The three shapes                                                            #
# --------------------------------------------------------------------------- #

def test_a_wildcard_resource_becomes_a_step_to_narrow_it():
    pack = remediation.platform_pack(finding("BTP-CC-001"))
    assert pack["applicable"] is True
    step = pack["apply"][0]
    assert "S4H_Production" in step and "path=/" in step and "narrow" in step
    assert "restore path=/" in pack["rollback"][0]


def test_a_setting_with_a_known_safe_value_states_it():
    """The strongest of the three: TrustAll has exactly two settings and only one
    of them verifies the certificate, so the change names a value rather than an
    action."""
    pack = remediation.platform_pack(finding(
        "BTP-DST-002",
        [{"name": "Legacy_ECC_SOAP", "type": "btp_destination",
          "qualifier": "TrustAll=true"}]))
    assert "set TrustAll = false" in pack["apply"][0]
    assert "currently TrustAll=true" in pack["apply"][0]
    assert "set TrustAll = true" in pack["rollback"][0]


def test_an_orphaned_binding_is_a_removal_with_no_replacement_value():
    pack = remediation.platform_pack(finding(
        "BTP-SB-003",
        [{"name": "old-test-binding", "type": "service_binding",
          "qualifier": "instanceStatus=DELETED"}]))
    assert "delete the orphaned binding" in pack["apply"][0]
    assert "re-create the binding" in pack["rollback"][0]


def test_one_step_per_object_and_qualifier():
    """The same backend appears twice in one finding with two different paths, so
    the pairs must keep their order and their duplicates — which is why this reads
    subjects rather than reusing `_qualified_names`, whose set loses both."""
    pack = remediation.platform_pack(finding("BTP-CC-002", [
        {"name": "S4H_Production", "type": "cc_backend",
         "qualifier": "path=/sap/opu/odata/sap"},
        {"name": "S4H_Production", "type": "cc_backend",
         "qualifier": "path=/sap/bc/gui/sap/its/webgui"},
    ]))
    assert len(pack["apply"]) == 2
    assert "odata" in pack["apply"][0] and "webgui" in pack["apply"][1]


def test_it_is_not_executable():
    """Every one of these is a form in an admin console."""
    assert remediation.platform_pack(finding())["executable"] is False


# --------------------------------------------------------------------------- #
#  Which console                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id,expected", [
    ("BTP-CC-001", "Cloud Connector"),
    ("BTP-DST-002", "Destinations"),
    ("BTP-EM-001", "Event Mesh"),
    ("BTP-SB-003", "Service Bindings"),
])
def test_it_names_the_right_console(check_id, expected):
    """BTP is not one product. A single "BTP" label sends somebody to the wrong
    screen — the Cloud Connector one is not even in the cockpit."""
    subject = [{"name": "x", "type": "thing", "qualifier": "k=v"}]
    pack = remediation.platform_pack(finding(check_id, subject))
    assert expected in pack["where"], pack["where"]


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", ["BTP-DST-001", "BTP-CPI-002",
                                      "BTP-CPI-004", "BTP-MIG-001"])
def test_choosing_a_replacement_mechanism_is_declined_with_a_reason(check_id):
    """These four share a shape: the finding is that an insecure mechanism is in
    use, and the change is choosing what to move TO."""
    pack = remediation.platform_pack(finding(check_id))
    assert pack["applicable"] is False
    assert pack["apply"] == [] and pack["rollback"] == []
    assert len(pack["why"]) > 40, "a decline with no reason is just silence"


def test_a_writable_check_with_no_recorded_setting_is_declined():
    """Emitting "narrow  to the specific paths" is the blank-where-a-value-goes
    failure `parameter_pack` refuses, and worse here because it reads as an
    instruction."""
    pack = remediation.platform_pack(finding(
        "BTP-CC-001", [{"name": "S4H_Production", "type": "cc_backend"}]))
    assert pack["applicable"] is False
    assert "nothing precise to change" in pack["why"]


def test_a_finding_sap_owns_is_refused_with_the_other_route():
    pack = remediation.platform_pack(finding(remediation_owner="ticket_to_sap"))
    assert pack["applicable"] is False
    assert "service request" in pack["why"]


@pytest.mark.parametrize("check_id", ["AUTH-002", "IAM-EXP-001",
                                      "PARAM-LOGIN/MIN_PASSWORD_LNG"])
def test_it_answers_none_for_another_family(check_id):
    assert remediation.platform_pack(finding(check_id)) is None


def test_it_answers_none_for_a_btp_check_it_has_not_examined():
    """`BTP-GOV-001` is neither written nor declined — it is simply not covered,
    and the plan counts it under `not_covered` rather than showing an empty
    section."""
    assert remediation.platform_pack(finding("BTP-GOV-001")) is None


# --------------------------------------------------------------------------- #
#  Caveats                                                                     #
# --------------------------------------------------------------------------- #

def test_it_says_nothing_has_been_applied():
    caveats = " ".join(remediation.platform_pack(finding())["caveats"])
    assert "has changed nothing" in caveats


def test_a_cloud_connector_change_warns_about_established_connections():
    """The gotcha that makes this artefact credible, and the Cloud Connector
    equivalent of role_pack's profile-regeneration warning: narrowing a resource
    affects new requests and leaves established ones alone, so a working
    integration starts failing later with no obvious cause."""
    caveats = " ".join(remediation.platform_pack(finding("BTP-CC-001"))["caveats"])
    assert "established connections" in caveats
    assert "one backend at a time" in caveats


def test_a_destination_change_warns_when_it_is_actually_read():
    caveats = " ".join(remediation.platform_pack(finding(
        "BTP-DST-002",
        [{"name": "d", "type": "btp_destination", "qualifier": "TrustAll=true"}]
    ))["caveats"])
    assert "application start" in caveats


def test_a_very_wide_finding_is_capped_and_says_so():
    subject = [{"name": "backend%03d" % i, "type": "cc_backend",
                "qualifier": "path=/"} for i in range(80)]
    pack = remediation.platform_pack(finding("BTP-CC-001", subject))
    assert len(pack["apply"]) == remediation._MAX_STATEMENTS
    assert any("of 80 shown" in c for c in pack["caveats"])


# --------------------------------------------------------------------------- #
#  Wiring                                                                      #
# --------------------------------------------------------------------------- #

def test_the_dispatcher_reaches_it():
    assert remediation.pack(finding())["kind"] == "btp_setting"


def test_it_needs_no_graph():
    """The other three packs return None without a neighbourhood. This one must
    not, or every BTP finding would go unremediated wherever the graph is thin."""
    assert remediation.platform_pack(finding(), None)["applicable"] is True
    assert remediation.pack(finding(), None)["kind"] == "btp_setting"
