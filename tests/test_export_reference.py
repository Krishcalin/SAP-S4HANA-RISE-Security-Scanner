"""A source the customer is never told about is a check that can never fire.

THE DEFECT
docs/EXPORT_GUIDE.md is hand-written and covers the sources a first scan needs.
It names 36 of the 123 logical sources the loader accepts. The other 87 appeared
nowhere at all — not in the guide, not in the README, nowhere a customer would
look. So they were never supplied, the coverage manifest reported them "not
supplied" for ever, and the checks behind them could never run. Everything the
product said about that was accurate and none of it was actionable, because the
reader could not know the file existed.

WHAT IS FIXED, AND WHAT IS NOT
docs/EXPORT_SOURCES.md is generated from the loader's own table and lists all
123 with the filenames accepted, the modules each feeds, and whether a procedure
is written. What it does NOT do is invent the missing procedures: a fabricated
SAP transaction code in an export guide is worse than an absent one, and this
codebase does not guess at SAP identifiers.

WHAT THESE TESTS ENFORCE
That the catalogue is complete and current, so a source cannot be added to the
scanner and remain invisible to the person who has to produce it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REFERENCE = ROOT / "docs" / "EXPORT_SOURCES.md"
GUIDE = ROOT / "docs" / "EXPORT_GUIDE.md"


@pytest.fixture(scope="module")
def reference():
    assert REFERENCE.exists(), "the export source reference is missing"
    return REFERENCE.read_text(encoding="utf-8")


def test_every_logical_source_the_scanner_reads_is_listed(reference):
    """The whole point. A source the loader accepts and nobody documents is a
    check that cannot fire for a reason the customer cannot act on."""
    from modules.coverage import all_logical_sources

    listed = set(re.findall(r"^\| `([^`]+)` \|", reference, re.M))
    missing = sorted(set(all_logical_sources()) - listed)
    assert not missing, (
        "%d sources the scanner reads are in no document a customer would find: "
        "%s" % (len(missing), missing[:12]))


def test_the_reference_is_current(reference):
    """Generated, so it can drift the moment somebody adds a source and does not
    regenerate. The tool checks itself."""
    from tools.build_export_reference import build

    assert reference == build(), (
        "docs/EXPORT_SOURCES.md is out of date — regenerate it with "
        "`python -m tools.build_export_reference`")


def test_it_names_the_files_the_loader_will_actually_accept(reference):
    """The row is only useful if supplying the named file works. Every filename
    in the reference must be one the loader maps."""
    from modules.data_loader import DataLoader

    accepted = {n for names in DataLoader.FILE_MAP.values() for n in names}
    quoted = set(re.findall(r"`([\w./-]+\.(?:csv|json|zip))`", reference))
    invented = sorted(quoted - accepted)
    assert not invented, (
        "the reference names files the loader does not accept: %s" % invented[:8])


def test_the_undocumented_ones_are_marked_rather_than_quietly_listed(reference):
    """A row that looks like the others but has no procedure behind it would send
    a reader to a guide that says nothing. It says so instead.

    This test used to assert that SOME row was marked undocumented, which was true
    of the 87 that had no procedure. They now all do, so the assertion has been
    turned round: what must hold is that the two states are distinguishable and
    that every row carries one of them. A row with neither marker is the bug —
    it reads as documented to a skimming reader without claiming to be.
    """
    rows = re.findall(r"^\| `[^`]+` \|.*$", reference, re.M)
    assert len(rows) >= 100, "only %d rows — the table is not complete" % len(rows)
    unlabelled = [r for r in rows
                  if "| documented" not in r and "not yet written" not in r]
    assert not unlabelled, (
        "%d rows state neither documented nor not-yet-written: %s"
        % (len(unlabelled), unlabelled[:3]))


def test_every_source_has_a_procedure_a_customer_can_follow(reference):
    """The invariant this file was created to move towards, now that it holds.

    A source with no procedure is a check that cannot fire for a reason the
    customer cannot act on. Adding one to the loader without writing its
    extraction must fail here rather than sit in a table nobody re-reads.

    If you are adding a source and cannot verify its procedure, write the section
    anyway and mark the route *not verified for this guide* — that is an honest
    state the guide already carries for a dozen sources. What is not acceptable is
    a source the reader never hears about.
    """
    from modules.coverage import all_logical_sources
    from modules.data_loader import DataLoader

    guide = GUIDE.read_text(encoding="utf-8")
    missing = sorted(
        src for src in all_logical_sources()
        if src not in guide
        and not any(name in guide for name in DataLoader.FILE_MAP.get(src, ())))
    assert not missing, (
        "%d source(s) the scanner reads have no section in docs/EXPORT_GUIDE.md: "
        "%s" % (len(missing), missing[:12]))


#: Sections still carrying an unverified-route marker. The floor drops only when
#: a route is actually checked against a primary SAP source, and the drop is
#: recorded here with what was checked — otherwise "the caveats went away" and
#: "the routes got verified" are indistinguishable a month later.
#:
#:   12 → the count after the remaining 62 procedures were first written.
#:   12 → after verifying five BTP routes against SAP's own documentation
#:        repositories: `btp list accounts/entitlement` and
#:        `btp list services/binding` (SAP-docs/btp-cloud-platform), the IAS
#:        Application Configurations API (SAP-docs/btp-cloud-identity-services),
#:        and the Cloud Integration OData service root with its
#:        `IntegrationRuntimeArtifacts` and `DataStores` resources
#:        (SAP-docs/btp-integration-suite). Three sections lost the marker
#:        outright; `cpi_artifacts` keeps one for the credential-store half only.
#:        `sap_kernel` was added with a marker at the same time, so 12 held.
#:   10 → after closing three more: `system_change` (SAP's own Focused Run
#:        config store `GLOBAL` / `NAME='GLOBAL_SETTING'` /
#:        `VALUE='NOT MODIFIABLE'`, which makes the ABAP table irrelevant),
#:        `oauth_clients` (`btp list security/api-credential`, SAP-docs/
#:        btp-cloud-platform) and `apim_policies` (the `apiportal-apiaccess`
#:        service plan, SAP-docs/btp-integration-suite).
#:
#: The ten that remain are not remaining for want of trying. Six are S/4HANA and
#: Fiori application-layer routes, and SAP publishes no machine-readable
#: documentation repository for that layer the way it does for BTP and the
#: Integration Suite — confirming them needs a system or an S-user, not another
#: afternoon of searching. Their COLUMN NAMES are exact regardless, because those
#: come from the code.
UNVERIFIED_SECTION_FLOOR = 10


def test_an_unverified_route_says_so_where_the_reader_will_see_it(reference):
    """Not every procedure could be checked against a primary SAP source, and the
    ones that could not carry a marker. If those markers thin out, either somebody
    verified a dozen routes in an afternoon or the caveats were edited away — and
    the second is how a guide starts being trusted more than it has earned.

    Counted per SECTION rather than per phrase, because a section can carry a
    marker on one half of its route and a verified command on the other, which is
    exactly what `cpi_artifacts` does now: the OData resources are attested, the
    credential-store listing is not.
    """
    guide = GUIDE.read_text(encoding="utf-8")
    body = guide.split("# The remaining sources", 1)[-1]
    sections = re.split(r"^### ", body, flags=re.M)[1:]
    flagged = [s for s in sections
               if "not verified" in s.lower() or "no verified" in s.lower()]
    assert len(flagged) >= UNVERIFIED_SECTION_FLOOR, (
        "%d sections still declare an unverified route, down from the recorded "
        "floor of %d. If routes were genuinely verified, lower the floor and say "
        "in UNVERIFIED_SECTION_FLOOR which ones and against what."
        % (len(flagged), UNVERIFIED_SECTION_FLOOR))


def test_it_does_not_invent_sap_transaction_codes(reference):
    """The reason the missing procedures are missing rather than written.

    A transaction code is a claim a reader will act on. This file is generated
    from the loader's table and knows nothing about SAP's screens, so it must
    contain no procedure at all — anything that looked like one would have been
    guessed by the generator.
    """
    body = reference.split("## What", 1)[0]
    for verb in ("run transaction", "execute transaction", "go to transaction",
                 "in transaction "):
        assert verb not in body.lower(), (
            "the generated reference is describing a procedure it cannot know: %r"
            % verb)


def test_the_module_names_the_guide_quotes_are_ones_the_cli_accepts():
    """Five were wrong when the remaining 62 procedures were written.

    Each new section is headed "(the `xyz` module)" so a reader can run just that
    part of the scan. Five of those names were the module's PYTHON name rather
    than its `--modules` alias — `codetransport` for `codetrans`, `integration`
    for `intglayer`, and so on. Every one would have produced an unknown-module
    error at the exact moment a reader tried to act on the guide, which is the
    cheapest possible bug to prevent and one of the more expensive to be on the
    receiving end of.
    """
    from modules.coverage import CLI_MODULE_ALIASES

    guide = GUIDE.read_text(encoding="utf-8")
    valid = set(CLI_MODULE_ALIASES) | set(CLI_MODULE_ALIASES.values())
    quoted = set(re.findall(r"`([a-z0-9_]+)`(?=[^\n]{0,40}\bmodule)", guide))
    unknown = sorted(quoted - valid)
    assert not unknown, (
        "the guide names module(s) the CLI does not accept: %s" % unknown)


def test_the_guide_points_at_the_full_catalogue():
    """Otherwise the reference is another document nobody finds."""
    guide = GUIDE.read_text(encoding="utf-8")
    assert "EXPORT_SOURCES.md" in guide, \
        "the export guide does not link the full source catalogue"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "EXPORT_SOURCES.md" in readme, \
        "the README does not list the full source catalogue"
