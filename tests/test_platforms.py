# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The platform vocabulary, and the shape rules that hang off it.

THE SECOND GROWABLE VALUE LIST IN THIS SCHEMA, and it arrived immediately after
the first one nearly shipped wrong. `deployment_mode` was declared in six places
across three languages, which is how `rise_ecc` came close to being `ecc_rise`
(see tests/test_deployment_modes.py). `platform` is declared in four — Python,
two SQL statements and a TypeScript union — and this file is what stops them
drifting.

WHY DRIFT HERE IS WORSE THAN USUAL. `platform` does not merely label a row; it
selects which half of `sap_system_shape_check` applies, and therefore whether a
row is identified by SID and client or by an external key. A platform the
database accepts and Python does not is a tenant nobody can register; a platform
Python accepts and the database does not is a 500 on a form submission.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.platforms import (                                       # noqa: E402
    ABAP, PLATFORMS, TENANT_PLATFORMS, is_tenant)

SCHEMA = (ROOT / "server" / "schema.sql").read_text(encoding="utf-8")
TYPES = (ROOT / "frontend" / "src" / "api" / "types.ts").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
#  What a platform MEANS                                                      #
# --------------------------------------------------------------------------- #

#: Every platform, and whether it is identified by an external key rather than a
#: SID. Written out by hand rather than derived from TENANT_PLATFORMS, because a
#: table derived from the thing under test agrees with it by construction — it
#: would pass just as happily if `abap` were classified as a tenant.
EXPECTED_TENANT = {
    "abap": False,
    "ariba": True,
    "btp": True,
    "cloud_alm": True,
    "concur": True,
    "fieldglass": True,
    "ias": True,
    "successfactors": True,
}


def test_every_platform_is_deliberately_classified():
    assert set(EXPECTED_TENANT) == set(PLATFORMS), (
        "a platform was added or removed without deciding whether it is "
        "identified by an external key. That decision selects which half of "
        "sap_system_shape_check applies to the row.")
    for platform, expected in EXPECTED_TENANT.items():
        assert is_tenant(platform) is expected, platform


def test_abap_is_never_a_tenant():
    """The one that would break the schema's discriminator if it flipped. An ABAP
    row must carry a SID and client; treating it as a tenant would mean writing
    rows the CHECK refuses, on the most common path there is."""
    assert ABAP == "abap"
    assert is_tenant(ABAP) is False
    assert ABAP not in TENANT_PLATFORMS
    assert set(TENANT_PLATFORMS) == set(PLATFORMS) - {ABAP}


def test_an_unknown_platform_is_treated_as_abap_not_as_a_tenant():
    """Fail towards the constraint, not past it. An unknown value answering
    'tenant' would produce a row with no SID, no client and no external key —
    which has no identity at all and would collide with every other such row.
    Answering 'abap' produces a constraint violation at write time instead, which
    is a visible failure rather than a silent merge."""
    for junk in ("", None, "   ", "myspace", "ABAP-ish"):
        assert is_tenant(junk) is False


def test_platforms_are_normalised_for_case_and_whitespace():
    assert is_tenant("  SuccessFactors  ") is True
    assert is_tenant(" ABAP ") is False


# --------------------------------------------------------------------------- #
#  The three declarations that cannot import the source of truth              #
# --------------------------------------------------------------------------- #

def test_the_schema_create_and_migration_agree_with_python_and_each_other():
    """Three-way, for the reason the schema-upgrade CI job is three-way: the
    CREATE TABLE constraint governs fresh installs and the migration block governs
    upgrades, so widening one and not the other works on exactly half the world's
    databases and is invisible to any test that builds its schema from empty."""
    declarations = re.findall(r"platform IN \(([^)]*)\)", SCHEMA)
    assert len(declarations) >= 2, (
        f"expected the platform CHECK in BOTH the CREATE TABLE and the "
        f"constraint-migrations section, found {len(declarations)}. Editing the "
        f"CREATE alone changes nothing on any database that already exists.")

    parsed = [{v.strip().strip("'") for v in d.split(",")} for d in declarations]
    for i, values in enumerate(parsed):
        assert values == set(PLATFORMS), \
            f"schema.sql declaration #{i + 1}: {values ^ set(PLATFORMS)}"


def test_the_typescript_union_agrees_with_python():
    """The console offers these in a picker and types a system row by them. A
    platform the API returns and the union does not name fails the build; one the
    union names and the API rejects is a 400 the user cannot explain."""
    m = re.search(r"export type Platform\s*=\s*((?:\s*\|[^\n]*\n?)+)", TYPES)
    assert m, "the Platform union has moved or been renamed"
    declared = {v.strip().strip("'") for v in m.group(1).replace("\n", " ").split("|")
                if v.strip()}
    assert declared == set(PLATFORMS), \
        f"types.ts and platforms.py disagree: {declared ^ set(PLATFORMS)}"


def test_the_cli_reads_the_tuple_rather_than_repeating_it():
    """add-tenant's `choices=` must come from the tuple. A hardcoded list that
    drifts from the CHECK rejects a platform the database would accept while
    naming every other one as valid — which reads as the feature not existing."""
    src = (ROOT / "server" / "cli.py").read_text(encoding="utf-8")
    assert "TENANT_PLATFORMS" in src
    code = "\n".join(line.split("#")[0] for line in src.splitlines())
    assert "'successfactors'" not in code and '"successfactors"' not in code, \
        "server/cli.py has re-hardcoded the platform vocabulary"


# --------------------------------------------------------------------------- #
#  The shape rule, asserted against the schema text                           #
# --------------------------------------------------------------------------- #

def test_the_discriminator_demands_a_non_empty_sid_not_merely_a_present_one():
    """THE DISTINCTION THAT MAKES D8 WORK. `sid IS NOT NULL` is satisfied by an
    empty string, and an empty-string sid normalises to the same canonical
    fingerprint as every other empty sid — so a nullability-only discriminator
    leaves the exact collision this decision exists to remove, while looking like
    it fixed it. Such rows are insertable today: add-system takes sid positionally
    with no validation."""
    shapes = re.findall(r"CONSTRAINT sap_system_shape_check CHECK \((.*?)\)\);",
                        SCHEMA, re.S)
    assert len(shapes) >= 2, (
        f"expected sap_system_shape_check in BOTH the CREATE TABLE and the "
        f"constraint-migrations section, found {len(shapes)}")
    for i, body in enumerate(shapes):
        assert "sid <> ''" in body, \
            f"declaration #{i + 1} does not require a non-empty sid"
        assert "client <> ''" in body, \
            f"declaration #{i + 1} does not require a non-empty client"
        assert "external_key <> ''" in body, \
            f"declaration #{i + 1} does not require a non-empty external key"


def test_the_tenant_index_is_declared_where_upgrades_can_reach_it():
    """Statement ORDER is load-bearing exactly once in schema.sql, and this is it.

    The index predicate names `platform`. Declared beside the other sap_system
    indexes — the natural place — it is reached on an upgrade BEFORE the ADD COLUMN
    that creates that column, and the whole migration dies with
    `column "platform" does not exist`. It passes a fresh install, which is what
    makes the mistake shippable; it was made and caught during this work.
    """
    add_column = SCHEMA.index("ADD COLUMN IF NOT EXISTS platform")
    create_index = SCHEMA.index("CREATE UNIQUE INDEX sap_system_tenant_key")
    assert create_index > add_column, (
        "sap_system_tenant_key is declared before the ADD COLUMN that creates "
        "`platform`. Fresh installs will pass and every upgrade will fail.")

    # And it must not be the IF NOT EXISTS form, which is idempotent by NAME only:
    # PostgreSQL never compares the definition, so a changed predicate or column
    # list would be a silent no-op on every deployed database.
    assert "CREATE UNIQUE INDEX IF NOT EXISTS sap_system_tenant_key" not in SCHEMA
    assert "DROP INDEX IF EXISTS sap_system_tenant_key" in SCHEMA
    assert "NULLS NOT DISTINCT" in SCHEMA, (
        "the tenant index lost NULLS NOT DISTINCT; the default permits unlimited "
        "NULL-keyed duplicates, so a tenant could be created twice")
