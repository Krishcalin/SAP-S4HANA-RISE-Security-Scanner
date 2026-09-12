"""The host-platform vocabulary, declared once.

WHY THIS FILE EXISTS
--------------------
Decision D10 makes the product all-inclusive: it audits on-premise SAP and
self-managed SAP on a hyperscaler (AWS / Azure / GCP IaaS) as first-class, not
RISE-only. WHERE a customer-managed host runs is reporting metadata a report
should be able to state — and, for a hyperscaler, it marks the boundary where
MonitorRisk stops and the customer's cloud CNAPP begins: everything BELOW the OS
(hypervisor, block-storage encryption, security groups, cloud IAM) is the CNAPP's
job, not an SAP config scanner's. D10 records that naming this boundary, and NOT
duplicating the layer beneath it, is the whole point.

This is the same shape of change as the deployment-mode vocabulary (D7): a value
several tiers must agree on, declared ONCE here, with the tiers that cannot import
Python mirroring it under an agreement test (tests/test_host_platforms.py). It is
deliberately a module with no behaviour beyond a tuple, two predicates and a note.

WHAT IT IS NOT
--------------
It is NOT a coverage axis. D10 is explicit: hosting is a RESPONSIBILITY axis, not
a coverage axis. A self-managed hyperscaler host is `on_prem` for every SAP / OS /
HANA check — the customer owns OS root and the profile — so the platform tag
changes no verdict and gates no security check. Its only effects are (a) reporting
metadata and (b) the cloud-infrastructure boundary note, surfaced as OSEC-CLOUD-001
when the host is a customer-managed hyperscaler VM (never in RISE, where the whole
stack is SAP's).
"""
from __future__ import annotations

from typing import Tuple

#: Every host platform the product can tag a scan with. `bare_metal` and `vmware`
#: are on-premise fabrics; `aws`, `azure` and `gcp` are the hyperscaler IaaS
#: platforms D10 brings in as first-class self-managed hosts.
HOST_PLATFORMS: Tuple[str, ...] = (
    "bare_metal",
    "vmware",
    "aws",
    "azure",
    "gcp",
)

#: What an untagged scan means: the customer did not say where the host runs. Not
#: a platform — the ABSENCE of one — so is_hyperscaler is False for it and no
#: boundary note is emitted. A scan that never declared a platform is far more
#: common than any particular one, and inventing "bare_metal" for it would state a
#: fact the customer never gave.
DEFAULT_HOST_PLATFORM = "unspecified"

#: The hyperscaler IaaS platforms — the ones with a cloud-infrastructure layer
#: BELOW the OS that a customer's CNAPP owns, which is the boundary D10 names. An
#: on-premise fabric (bare metal, VMware) has no such layer in this sense, so it
#: gets no boundary note.
HYPERSCALERS: Tuple[str, ...] = ("aws", "azure", "gcp")

_LABELS = {
    "bare_metal": "bare metal",
    "vmware": "VMware",
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "unspecified": "unspecified",
}


def normalise(platform: object) -> str:
    """Coerce anything a caller holds into a known platform, or the default.

    An unrecognised value falls back to `unspecified` rather than raising: this
    runs inside a scan, and a typo in one config field must not take the run down
    — the same rule modules/deployment_modes.normalise follows.
    """
    text = str(platform or "").strip().lower()
    return text if text in HOST_PLATFORMS else DEFAULT_HOST_PLATFORM


def is_hyperscaler(platform: object) -> bool:
    """Is this a hyperscaler IaaS platform with a cloud layer below the OS?"""
    return normalise(platform) in HYPERSCALERS


def label(platform: object) -> str:
    """The display name for a platform tag."""
    return _LABELS.get(normalise(platform), "unspecified")


def cloud_infra_boundary_note(platform: object) -> str:
    """The sentence marking where MonitorRisk stops and the customer's CNAPP begins.

    Returned only for a hyperscaler; empty otherwise. It is the reader-facing form
    of D10's boundary: name it, defer it, do not duplicate it.
    """
    if not is_hyperscaler(platform):
        return ""
    name = label(platform)
    return (
        f"This SAP system is self-managed on {name}. MonitorRisk audits the SAP "
        f"application, the operating system and HANA — the layers a customer owns "
        f"and operates on a self-managed host. The cloud infrastructure BELOW the "
        f"operating system — the hypervisor, block-storage encryption, network "
        f"security groups and {name} IAM — is out of scope here and is the job of "
        f"the customer's cloud security platform (a CNAPP), not an SAP "
        f"configuration scanner. This is a boundary, not a gap (decision D10)."
    )
