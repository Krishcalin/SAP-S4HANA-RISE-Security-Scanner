"""The host-platform vocabulary, declared once, held to its callers.

Parallel to test_deployment_modes.py, for the D10 host-platform tag. The tag is
carried on the offline CLI today (`--platform`) and drives the
cloud-infrastructure boundary note (OSEC-CLOUD-001). When the client-server
product surfaces the tag in the console, `server/schema.sql` and
`frontend/src/api/types.ts` gain their mirrors and this file gains the same SQL/TS
agreement assertions test_deployment_modes carries. Declaring them before the
console stores or renders the value would be dead declarations — worse than an
honest absence — so until then this holds the CLI declaration and the Python
invariants, and no more.

WHY THE CLASSIFICATION IS WRITTEN OUT RATHER THAN DERIVED. The whole point of the
tag is which platforms have a cloud-infrastructure layer below the OS that a
customer's CNAPP owns. Deriving that from `is_hyperscaler` — the rule under test —
would agree with the implementation by construction, including when both are
wrong, exactly as EXPECTED_RISE explains in test_deployment_modes.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import host_platforms as hp                          # noqa: E402


#: Every platform, and whether it is a hyperscaler IaaS with a cloud layer below
#: the OS. `unspecified` is the ABSENCE of a tag and is not a platform.
EXPECTED_HYPERSCALER = {
    "bare_metal": False,
    "vmware": False,
    "aws": True,
    "azure": True,
    "gcp": True,
}


def test_every_platform_is_classified_as_hyperscaler_or_not():
    """A platform added to the tuple and left out of EXPECTED_HYPERSCALER fails
    here rather than shipping with whatever answer the membership test happens to
    give it — the same guard EXPECTED_RISE gives the deployment modes."""
    assert set(EXPECTED_HYPERSCALER) == set(hp.HOST_PLATFORMS), (
        "a host platform was added or removed without deciding whether it has a "
        "cloud-infrastructure layer below the OS; that decision drives the CNAPP "
        "boundary note and cannot be left to a membership test")
    for platform, expected in EXPECTED_HYPERSCALER.items():
        assert hp.is_hyperscaler(platform) is expected, platform


def test_unspecified_is_the_default_and_is_not_a_platform():
    """The absence of a tag, not a value in the tuple, so it triggers nothing."""
    assert hp.DEFAULT_HOST_PLATFORM == "unspecified"
    assert hp.DEFAULT_HOST_PLATFORM not in hp.HOST_PLATFORMS
    assert hp.is_hyperscaler("unspecified") is False


def test_an_unknown_or_empty_platform_falls_back_to_unspecified():
    """A typo in one config field must not take a scan down, and must never
    invent a platform the customer did not declare."""
    for junk in ("", None, "   ", "nonsense", "AWS_TYPO"):
        assert hp.normalise(junk) == "unspecified"
        assert hp.is_hyperscaler(junk) is False


def test_platforms_are_normalised_for_case_and_whitespace():
    assert hp.normalise("  AWS  ") == "aws"
    assert hp.is_hyperscaler("  Gcp ") is True


def test_the_boundary_note_is_returned_only_for_a_hyperscaler():
    """It is the reader-facing form of D10's boundary, so it must exist for the
    platforms that have a layer below the OS and be empty for the rest."""
    for platform in ("aws", "azure", "gcp"):
        note = hp.cloud_infra_boundary_note(platform)
        assert "CNAPP" in note and hp.label(platform) in note and "D10" in note
    for platform in ("bare_metal", "vmware", "unspecified", None):
        assert hp.cloud_infra_boundary_note(platform) == ""


def test_the_cli_reads_the_tuple_rather_than_repeating_it():
    """A hardcoded choices= list rejects a newly added platform with an argparse
    error that names every OTHER platform as valid — which reads as the feature
    not existing. The same guard test_deployment_modes puts on the mode CLIs."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert "HOST_PLATFORMS" in src, "sap_scanner.py no longer reads the tuple"
    body = src.replace("from modules.host_platforms", "")
    assert '"aws"' not in body and '"gcp"' not in body, \
        "sap_scanner.py has re-hardcoded the host-platform vocabulary"


def test_the_scanner_carries_the_platform_in_the_one_run_context():
    """The tag reaches the auditors the same way deployment_mode does: through the
    single run_ctx, not a second dict. Asserted on the AST so it cannot regress to
    a hand-rolled context that drops the key (the failure test_run_context_is_
    uniform exists for)."""
    tree = ast.parse((ROOT / "sap_scanner.py").read_text(encoding="utf-8"))
    built = [n for n in ast.walk(tree)
             if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "run_ctx" for t in n.targets)]
    assert len(built) == 1
    keys = {k.value for k in built[0].value.keys if isinstance(k, ast.Constant)}
    assert "host_platform" in keys, keys
