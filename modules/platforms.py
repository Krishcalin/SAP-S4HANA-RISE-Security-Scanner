# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""What kind of thing a `sap_system` row is. Decision D8.

A row in `sap_system` used to be an ABAP system and nothing else. It is now
"a thing findings attach to", which is either an ABAP system — identified by SID
and client — or a SaaS tenant identified by its own external key.

WHY THIS IS A MODULE AND NOT A `choices=` LIST
The deployment-mode vocabulary was declared in six places across three languages,
and adding a fourth value to five of them was how `rise_ecc` nearly became
`ecc_rise` (see modules/deployment_modes.py). The platform vocabulary is the
second growable value list in this schema and would have repeated the mistake
immediately: a `choices=` list in the CLI that drifts from the database CHECK
rejects a platform the database would accept, while listing every OTHER platform
as valid — which reads to the user as the feature not existing, rather than as a
stale list.

SQL CANNOT IMPORT THIS. `server/schema.sql` declares the same list twice, in the
CREATE TABLE constraint and in the constraint-migrations block, and
`tests/test_platforms.py` asserts all three agree. The `schema-upgrade` CI job
additionally asserts the constraint that is LIVE in an upgraded database matches,
because a CHECK edited only inside `CREATE TABLE IF NOT EXISTS` is a no-op on
every database that already exists.
"""
from __future__ import annotations

from typing import Tuple

#: The ABAP platform, named once. Everything that is not this is a tenant, and
#: several places need to say so without spelling the literal.
ABAP = "abap"

#: Every platform a sap_system row may declare.
#:
#: ORDER: `abap` first because it is the default and the overwhelming majority;
#: the rest alphabetically, so an addition has an obvious place to go.
PLATFORMS: Tuple[str, ...] = (
    ABAP,
    "ariba",
    "btp",
    "cloud_alm",
    "concur",
    "fieldglass",
    "ias",
    "successfactors",
)

#: The platforms that are tenants — i.e. identified by an external key rather than
#: by a SID and client. Derived rather than written out, so it cannot drift from
#: PLATFORMS, and so `add-tenant` can never offer `abap` as a choice.
TENANT_PLATFORMS: Tuple[str, ...] = tuple(p for p in PLATFORMS if p != ABAP)


def is_tenant(platform: object) -> bool:
    """Is this row identified by an external key rather than a SID?

    Unknown values answer False — i.e. "treat it as ABAP". That is the safe
    direction: an ABAP row must carry a SID and client, so a mistake here produces
    a constraint violation at write time rather than a tenant that silently has no
    identity and collides with every other one.
    """
    return str(platform or "").strip().lower() in TENANT_PLATFORMS
