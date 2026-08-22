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

#: What this product actually DOES about each platform, and on whose authority.
#:
#: WHY THIS EXISTS. `PLATFORMS` says which platforms a `sap_system` row may
#: DECLARE. It says nothing about whether any check will ever look at one, and the
#: two had drifted apart in the direction that flatters the product: a customer
#: could `add-tenant ... ariba acme-prod` and receive a system row that no module
#: can produce a finding for, with nothing anywhere saying so. A registered tenant
#: that can never be assessed reads as coverage, which is the failure this codebase
#: exists to avoid in every other form.
#:
#: DECLARED, NOT DERIVED, AND THE REASON IS WORTH KNOWING. There is no link from a
#: module to a platform to read: `abap` has no source whose NAME contains "abap" —
#: its sources are `users`, `profiles`, `role_auth_values` — and `cloud_alm`'s is
#: `csa_findings`. A name-matching derivation would report both as unassessed,
#: which is the opposite of true. So this is a declaration with its evidence
#: attached, guarded by a test that every platform appears exactly once.
#:
#: `decision` cites where the call was made. A status with no decision behind it
#: is `undecided`, which is an honest state and a visible one — the point of
#: recording it is that the next person meets the open question instead of
#: assuming somebody already closed it.
PLATFORM_STATUS = {
    ABAP: {
        "status": "assessed",
        "why": "The core of the product. Most of the 36 modules read ABAP exports.",
        "decision": None,
        "evidence": "users, profiles, role_auth_values, security_params, and most "
                    "of the 135 logical sources",
    },
    "btp": {
        "status": "assessed",
        "why": "The one area with real APIs and no SAP involvement, and where "
               "SAP's own free baseline content is nearly empty — four BTP policy "
               "files against roughly 29 for ABAP.",
        "decision": None,
        "evidence": "btp_subaccounts, btp_trust, btp_destinations, "
                    "btp_audit_log_records, cloud_connector and six more; "
                    "modules/btp_cloud_surface.py, modules/cap_xsuaa.py",
    },
    "ias": {
        "status": "assessed",
        "why": "Identity Authentication is the trust anchor for the BTP surface "
               "already assessed, so leaving it out would break a chain mid-way.",
        "decision": None,
        "evidence": "ias_config",
    },
    "cloud_alm": {
        "status": "assessed",
        "why": "SAP's own CSA verdicts, imported and reported AS SAP's rather than "
               "re-judged.",
        "decision": None,
        "evidence": "csa_findings; modules/cloudalm_verdicts.py, "
                    "modules/cloudalm_import.py",
    },
    "successfactors": {
        "status": "in_scope_unbuilt",
        "why": "Decision D1 moved it OFF the non-goals list — offline-first, "
               "security surface only — on the grounds that the original reason "
               "('API-only and offline-hostile') was half about access, which "
               "connected mode answers: SuccessFactors exposes OData and SCIM over "
               "HTTPS. The other half, whether enough of its surface is SECURITY "
               "configuration rather than business configuration, remains inferred "
               "and untested. In scope, scheduled for nothing, and D1 says so: it "
               "'admits SuccessFactors to the roadmap; it does not schedule a "
               "connector for it.'",
        "decision": "D1",
        "evidence": "No logical source and no module today. The platform value "
                    "exists so a tenant can be registered against the decision.",
    },
    "ariba": {
        "status": "declined",
        "why": "A separate SaaS product rather than S/4HANA RISE, and chasing it "
               "dilutes the charter this product is built on. It reached the "
               "platform vocabulary without ever appearing in a decision or scope "
               "document — the gap this entry closes. The prompt to settle it was "
               "a competitor assessment listing Ariba as covered, whose own "
               "evidence rating for that claim was 'internal email only; I found "
               "no public product page confirming Ariba-specific telemetry "
               "mechanics'. Declining on thin third-party evidence is the right "
               "way round; if a real Ariba export shows a security surface worth "
               "checking, revisit this rather than quietly carrying it.",
        "decision": "D9",
        "evidence": "No logical source and no module. Retained in PLATFORMS so an "
                    "existing tenant row stays valid and so the refusal is visible "
                    "at the point somebody registers one.",
    },
    "concur": {
        "status": "undecided",
        "why": "In the platform vocabulary, assessed by nothing, and named in no "
               "decision or scope document. Recorded as undecided rather than "
               "quietly declined, because inventing a rationale nobody gave is how "
               "a decision comes to look settled without anyone making it.",
        "decision": None,
        "evidence": "No logical source and no module.",
    },
    "fieldglass": {
        "status": "undecided",
        "why": "Same position as concur: in the vocabulary, assessed by nothing, "
               "and named in no decision document.",
        "decision": None,
        "evidence": "No logical source and no module.",
    },
}

#: Statuses, and what each means to somebody registering a tenant.
PLATFORM_STATUSES = {
    "assessed": "Checks run against this platform today.",
    "in_scope_unbuilt": "Accepted into scope by a recorded decision; no check "
                        "reads it yet.",
    "declined": "Deliberately out of scope, with the reason recorded.",
    "undecided": "In the vocabulary, assessed by nothing, and nobody has ruled "
                 "either way.",
}


def status_of(platform: object) -> str:
    """The recorded status, or `undecided` for a platform nobody has ruled on."""
    entry = PLATFORM_STATUS.get(str(platform or "").strip().lower())
    return entry["status"] if entry else "undecided"


def is_assessed(platform: object) -> bool:
    return status_of(platform) == "assessed"


def status_note(platform: object) -> str:
    """One paragraph for somebody about to register a tenant of this platform.

    Empty for an assessed platform: a warning on the case that works is noise,
    and noise is how the warning that matters gets skipped.
    """
    key = str(platform or "").strip().lower()
    entry = PLATFORM_STATUS.get(key)
    if entry is None:
        return ("%s is not a platform this product records a position on." % key)
    if entry["status"] == "assessed":
        return ""
    return "%s: %s %s" % (key, PLATFORM_STATUSES[entry["status"]], entry["why"])


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
