"""A platform that cannot disable encryption must not be told that it has.

`docs/EXPORT_GUIDE.md` documents the SAP HANA Cloud export shape and says of it,
in the same file, that "it is not possible to disable encryption... There is no
setting to export and no finding to raise". Fed exactly that shape,
`check_hana_encryption` used to raise three findings — two HIGH and one MEDIUM —
each asserting a control had been switched off on a platform that has no switch.

The cause is a shape every flag in that check shares:

    if not <flag> or str(<flag>).lower() in ("false", ...)

which cannot tell an ABSENT key from a disabled one. The HANA Cloud export
carries `deployment`, `data_at_rest` and `can_be_disabled`, and none of the
three keys the check looks for.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.crypto_posture import CryptoPostureAuditor              # noqa: E402

#: Copied verbatim from docs/EXPORT_GUIDE.md, so this test fails if the guide
#: and the code ever describe different exports.
HANA_CLOUD = {"deployment": "hana_cloud", "data_at_rest": "enforced_by_sap",
              "can_be_disabled": False}


def volume_findings(encryption):
    """Only the checks that judge HANA volume encryption."""
    got = CryptoPostureAuditor({"hana_encryption": encryption}).run_all_checks()
    return {f["check_id"]: f for f in got if f["check_id"].startswith("CRYPTO-HANA")}


def test_the_documented_cloud_export_raises_no_encryption_defect():
    got = volume_findings(HANA_CLOUD)
    assert list(got) == ["CRYPTO-HANA-006"], (
        "three HIGH/MEDIUM findings used to claim encryption was disabled on a "
        "platform whose own guide entry says it cannot be")
    assert got["CRYPTO-HANA-006"]["severity"] == "INFO"


def test_the_information_finding_quotes_what_it_read():
    """An auditor must be able to see WHY the volume checks did not run."""
    items = volume_findings(HANA_CLOUD)["CRYPTO-HANA-006"]["affected_items"]
    assert any("hana_cloud" in i for i in items)
    assert any("enforced_by_sap" in i for i in items)


@pytest.mark.parametrize("export, why", [
    ({"deployment": "hana_cloud"}, "the deployment names itself"),
    ({"deployment": "HANA-Cloud"}, "spelling and case must not decide it"),
    ({"can_be_disabled": "false"}, "the export states it directly"),
    ({"data_at_rest": "enforced_by_sap"}, "so does this"),
])
def test_a_platform_that_owns_encryption_is_recognised(export, why):
    assert "CRYPTO-HANA-006" in volume_findings(export), why


def test_a_genuine_on_premise_failure_is_still_reported_in_full():
    """THE POINT OF THE FIX IS NOT SILENCE. On-premise, encryption is the
    customer's to configure, it can be off, and the export carries the real
    state — every one of those findings must survive."""
    got = volume_findings({"deployment": "on_premise",
                           "data_volume_encryption": False,
                           "log_volume_encryption": False,
                           "backup_encryption": False})
    assert "CRYPTO-HANA-006" not in got
    assert {"CRYPTO-HANA-001", "CRYPTO-HANA-002", "CRYPTO-HANA-004"} <= set(got)


def test_an_export_that_says_encryption_can_be_disabled_is_not_sap_managed():
    """`can_be_disabled: true` is the opposite claim and must read as one."""
    got = volume_findings({"deployment": "on_premise", "can_be_disabled": True,
                           "data_volume_encryption": False})
    assert "CRYPTO-HANA-006" not in got
