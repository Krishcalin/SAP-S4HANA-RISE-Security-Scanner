# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The ECS "ABAP Security Configuration list" (SAP Note 3250501)
=============================================================
Note 3250501 has two halves. The 92 profile parameters are scored elsewhere; this
module covers the other half — the 18 CONFIGURATION items, the settings that are
not profile parameters and therefore cannot be scored by comparing a value against
a baseline row.

Most of those 18 were already checked by modules that predate the note arriving,
and re-checking them here would be worse than leaving them out: a duplicated
finding is counted twice in the FAIR loss figure and read twice by whoever works
the report. `CONFIG_ITEM_DISPOSITION` below records, for every one of the 18, who
owns it — and `tests/test_ecs_config_items.py` fails if the note gains or loses an
item that this table does not know about. That is the whole point of the table: a
v47 of the note that adds a nineteenth item must not slide in unnoticed.

────────────────────────────────────────────────────────────────────────────────
WHAT THIS MODULE READS
────────────────────────────────────────────────────────────────────────────────
`table_auth_groups`  — table/view -> authorization group, TDDAT-shaped. Loaded by
                       modules/data_loader.py from `table_auth_groups.csv`,
                       `table_authorization_groups.csv` or `se54.csv`. An absent key
                       still returns None, and every check that needs it returns []
                       cleanly — a customer who did not send this extract must not be
                       told anything about their authorization groups.

    Accepted headers (the extract may be produced by an SE16/SE11 download or by
    hand, and the header text differs between the two, so several aliases are
    accepted rather than one asserted as canonical):

        table name  : TABNAME | TABLE | TABLE_NAME | OBJECT | OBJECT_NAME | VIEWNAME
        auth group  : CCLASS | AUTH_GROUP | AUTHGROUP | AUTHORIZATION_GROUP
                      | AUTH_GRP | DICBERCLS | BRGRU

    THIS LIST IS THE ONLY ONE. The loader deliberately keeps no second copy of it:
    a header only one side knows reads as an empty cell, and an empty cell here
    means "no authorization group", so a disagreement between the two files would
    report a compliant system as exposing every password hash it holds. The
    agreement is enforced end-to-end by tests/test_tddat_export.py, which drives
    each alias through DataLoader rather than straight into the auditor.

    THE EXTRACT MUST BE UNFILTERED. A table that is absent from it is read as
    "no authorization group assigned", because that is what an absent row means
    in a complete extract — and reading it the other way would let the exact
    defect this module exists to catch pass silently.

    A namespace-filtered extract (Z* only, say) would therefore over-report, so the
    two directions are answered differently rather than assumed away:

      * PROVABLY filtered — the extract names nothing outside the customer and
        partner namespaces, so it cannot be a complete picture of the system's
        assignments whatever it says about SAP's own tables. Absence stops counting
        as evidence there: only the rows the extract actually carries are judged,
        and the objects it never mentions are disclosed as a coverage gap
        (AUTH-ECS-000) instead of reported as unprotected. Absence of evidence is
        not a finding.
      * NOT PROVABLE — an extract that does name SAP tables may still have been
        filtered by object name, and nothing in the rows can settle it. The finding
        is then raised on the note's own reading of absence and SAYS SO IN ITS OWN
        TEXT, with `details` carrying the row count and naming the absent objects
        separately from the mis-assigned ones so a reviewer holding a filtered
        extract sees it at a glance.

`client_settings`    — existing key. Only the client number is read (CLIENT | MANDT).

`security_audit_log` / `audit_config` — existing keys. Only the FILTER rows are
                       read, and only their user field. Reading event rows here
                       would fire on every system that ever supplied an event
                       extract, since every event names a user.

    A filter row is identified by POSITIVE evidence — it carries a column only a
    filter definition has (filter name, profile type, active flag) — and not
    merely by the absence of a date column. Absence was the first rule here and
    it was wrong: an event extract whose date column happens to be spelled
    anything other than the nine names we recognise (SLGDATE, AUDIT_TIME, …)
    read as a set of filter rows, and since every event names a user, a system
    whose filters are perfectly compliant was told its audit log was blind and
    handed a list of its own end users as if they were filter definitions. The
    verdict must not turn on the spelling of a column header.

    The fallback matches modules/log_review.py: an event-shaped
    `security_audit_log` means the filter configuration, if the customer sent
    one, is in `audit_config`. Falling back only when `security_audit_log` is
    entirely EMPTY (the first rule here) silently dropped the check on every
    system that supplied both.

────────────────────────────────────────────────────────────────────────────────
WHY THE CHECK IDS ARE SPREAD ACROSS FOUR FAMILIES
────────────────────────────────────────────────────────────────────────────────
A check id decides three things it has no business deciding by accident: the team
it routes to (`server/enrich.py`), the FAIR scenario it is priced under
(`data/fair_scenarios.json`, prefix match beats category match), and the SLA. The
four items below are genuinely four different kinds of defect with four different
owners, so they take the prefix of the family that owns the fix rather than one
tidy house prefix for this module:

    AUTH-ECS-001    table authorization groups -> authorizations team, priced as
                    privilege escalation
    CRYPTO-ECS-001  key material at rest       -> basis, priced as data loss
    STDUSR-ECS-001  leftover standard clients  -> basis, priced as privilege
                    escalation. NOT TRUST-, which is priced as remote code
                    execution — an undeleted client is not an RCE, and the prefix
                    would have silently set the loss magnitude.
    LREV-ECS-001    audit-log coverage         -> data protection. The LREV- family
                    is priced by no FAIR scenario today — all fifteen of
                    log_review's ids are in the same position — so this finding is
                    reported and worked but contributes nothing to the loss figure.
                    Deliberate: its sibling is LREV-FLT-002, the two are the user
                    and client halves of ONE note item, and pricing one half but
                    not the other would be worse than pricing neither. Whether the
                    LREV- family should route is a decision for whoever owns
                    data/fair_scenarios.json, not something to smuggle in by
                    choosing a different prefix here.

Every one of them carries a `category` that already exists in
`ComplianceMapper.CATEGORY_THEMES`; a category that does not is invisible to every
compliance panel without raising anything.

────────────────────────────────────────────────────────────────────────────────
NOTE NUMBERS AND OTHER SAP IDENTIFIERS
────────────────────────────────────────────────────────────────────────────────
3250501 is the only note cited anywhere in this file. It is the source document.

`PASSWORD_HASH_TABLES` is READ FROM the extract, not typed here. It was typed
here, from recollection, when the first extract recorded only the item slug — and
three of the six names could not be pointed at in any source while driving a HIGH
customer finding. The extract now enumerates them, and the fallback is empty, so
losing that data self-skips the check instead of asserting a member list nobody
can source. Every other identifier here is either derivable
from a note item name (SPWD, SSF_PSE_D, SPSE, clients 001 and 066) or already
established in this repository (USR02, USH02, USRPWDHISTORY, S_TABU_DIS, SE54,
SCC5).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from modules import ecs_baseline
from modules.base_auditor import BaseAuditor


# --------------------------------------------------------------------------- #
#  The note's configuration list, and who answers for each item                #
# --------------------------------------------------------------------------- #
#: Every key in `data/ecs_hardening_3250501.json` -> ("checked" | "covered" |
#: "not_evidenceable", explanation). The test asserts this is exactly the note's
#: item set, so the note gaining an item breaks the build rather than the report.
#:
#: "covered" entries are deliberate NON-implementations. Each names the check that
#: already fires, because a second finding for the same defect doubles it in the
#: FAIR figure and in the remediation queue.
CONFIG_ITEM_DISPOSITION: Dict[str, Tuple[str, str]] = {
    # ── implemented here ──────────────────────────────────────────────────── #
    "password_hash_tables_authgroup_SPWD": (
        "checked", "AUTH-ECS-001 — no prior coverage anywhere in the repository. "
                   "AUTH-ECS-000 is its coverage half: it discloses the objects "
                   "whose group could not be read because the extract proves it was "
                   "filtered, for this item and for the SPSE one, so a gap in the "
                   "evidence never reads as a clean result"),
    "ssf_pse_d_authgroup_SPSE": (
        "checked", "CRYPTO-ECS-001 — no prior coverage; CRYPTO-PSE-001 is about "
                   "PSE health (expiry/corruption), not about who may read the table"),
    "delete_unused_clients_001_066": (
        "checked", "STDUSR-ECS-001 — system_trust knows clients 000/001/066 as a "
                   "set but only ever asks whether the USERS in them are locked; "
                   "nothing asks whether the clients still exist"),
    "sal_filter_all_users_all_clients": (
        "checked", "LREV-ECS-001 covers the USER half only. The CLIENT half is "
                   "already LREV-FLT-002 in modules/log_review.py and is not "
                   "repeated here"),

    # ── already covered — deliberately not re-checked ─────────────────────── #
    "secure_sap_star": (
        "covered", "USR-001 (user_auth_audit) unlocked SAP*, STDUSR-001/002 "
                   "(system_trust) default password and login/no_automatic_user_sapstar"),
    "secure_ddic_ecs_exception": (
        "covered", "USR-001 + STDUSR-002 (system_trust) cover DDIC lock state and "
                   "default password"),
    "secure_sapcpic": (
        "covered", "USR-001 + STDUSR-002; login/disable_cpic is a profile parameter "
                   "and belongs to the parameter half of the note"),
    "secure_tmsadm": (
        "covered", "USR-001 + STDUSR-002 cover TMSADM lock state and default password"),
    "delete_earlywatch_all_clients": (
        "covered", "USR-001 + STDUSR-002 cover EARLYWATCH. The note asks for DELETION "
                   "rather than locking, which is a stricter bar than any existing "
                   "check applies — but a separate finding would fire alongside "
                   "USR-001 on every system where the account is also unlocked, and "
                   "double-counting the same account was judged the worse error. "
                   "Recorded here so the gap is visible rather than forgotten"),
    "deactivate_critical_icf_services": (
        "covered", "NET-004 (network_services) active high-risk ICF services, "
                   "NET-005 active services without authentication"),
    "gateway_reginfo_acl": (
        "covered", "INTG-GW-* (integration_layer) parses the reginfo rule lines"),
    "gateway_secinfo_acl": (
        "covered", "INTG-GW-* (integration_layer) parses the secinfo rule lines"),
    "gateway_prxyinfo_acl": (
        "covered", "TRUST-008 (system_trust) checks gw/prxy_info together with "
                   "gw/acl_mode_proxy, which is the pairing that decides whether an "
                   "empty proxy ACL is actually permissive"),
    "ms_acl_info_no_host_wildcard": (
        "covered", "TRUST-010 (system_trust) flags a wildcard or empty message-server ACL"),
    "se06_not_modifiable": (
        "covered", "CODE-SYSCHG-* (code_transport) global system change option"),
    "scc4_production_client_settings": (
        "covered", "CODE-CLIENT-001 (code_transport) SCC4 client changeability"),

    # ── cannot be evidenced from an offline export ────────────────────────── #
    "sal_storage_database_not_filesystem": (
        "not_evidenceable",
        "no export we take carries the audit log's storage medium. The filter "
        "extract describes WHAT is recorded, not WHERE it lands, and the profile "
        "parameter that selects the medium is not among the note's 92 parameters, "
        "so the parameter half will not see it either. Writing a check that reads "
        "a column no export produces would pass on every system forever, which "
        "reports compliance we never measured"),
    "icm_admin_port_204": (
        "not_evidenceable",
        "the ICM port table is not in any export we take, and the note's parameter "
        "list contains no icm/server_port entry to read it from. Guessing the "
        "intended state from the item's name is exactly the reasoning that produces "
        "a false positive on SAP's own baseline"),
}


# --------------------------------------------------------------------------- #
#  Objects named by the note                                                   #
# --------------------------------------------------------------------------- #
#: Logical data-source key for the table -> authorization group extract. A key in
#: modules/data_loader.py's FILE_MAP; see the module docstring for the filenames and
#: for why the extract has to be unfiltered.
TABLE_AUTH_GROUPS = "table_auth_groups"

#: The tables and views required to sit behind authorization group SPWD. They are
#: the ones that expose password hashes, directly or through a view or an archiving
#: copy — protecting USR02 alone leaves the same hashes readable through the others.
#:
#: PROVENANCE. Read from data/ecs_hardening_3250501.json, never hand-typed here.
#:
#: This list WAS hand-typed, and the first extract of the note recorded only the
#: item slug `password_hash_tables_authgroup_SPWD` with no member list — so three
#: of the six names were carried on recollection alone and drove a HIGH customer
#: finding. The extract now enumerates them, which is the only acceptable source:
#: a table name we cannot point at in the note is a fabricated identifier, and this
#: repository has shipped those before.
#:
#: The fallback is EMPTY, not a guess. If the extract loses the list, the checks
#: self-skip and say why, rather than asserting a member list nobody can source.
_DETAIL = ecs_baseline.load().get("configuration_detail", {})
_SPWD = _DETAIL.get("password_hash_tables_authgroup_SPWD", {})
PASSWORD_HASH_TABLES: Tuple[str, ...] = tuple(_SPWD.get("tables", ()))
PASSWORD_HASH_AUTH_GROUP = _SPWD.get("authorization_group", "SPWD")

#: Personal Security Environments held in the database. Reading it yields the
#: system's own key material, not merely a reference to it.
PSE_TABLE = "SSF_PSE_D"
PSE_AUTH_GROUP = "SPSE"

#: Clients the note requires to be gone when they are not in use. 000 is NOT in
#: this set: it is the SAP reference client and it stays.
OBSOLETE_CLIENTS: Tuple[str, ...] = ("001", "066")

# Column vocabularies. Several aliases per field on purpose — see the docstring.
_TABLE_KEYS = ("TABNAME", "TABLE", "TABLE_NAME", "OBJECT", "OBJECT_NAME", "VIEWNAME")
_GROUP_KEYS = ("CCLASS", "AUTH_GROUP", "AUTHGROUP", "AUTHORIZATION_GROUP",
               "AUTH_GRP", "DICBERCLS", "BRGRU")
_CLIENT_KEYS = ("CLIENT", "MANDT", "CLIENT_ID")
_USER_KEYS = ("USER", "USERNAME", "USER_NAME", "BNAME", "USERID", "ACCOUNT")
_ACTIVE_KEYS = ("ACTIVE", "STATUS", "ACTIVE_FLAG")
_DATE_KEYS = ("DATE", "EVENT_DATE", "AUDIT_DATE", "LOG_DATE", "DATUM",
              "TIMESTAMP", "EVENT_TIMESTAMP", "DATE_TIME", "DATETIME")

#: Columns only a FILTER DEFINITION carries. The date-column list above can only
#: ever recognise the spellings somebody thought of, so it is used to exclude
#: obvious event rows and never as the sole reason to believe a row is a filter.
#: EVENT_CLASS and CLIENT are deliberately absent: a logged event carries both, so
#: either would readmit exactly the rows this list exists to keep out.
_FILTER_SHAPE_KEYS = ("FILTER_NAME", "CONFIG_NAME", "PROFILE_NAME", "FILTER",
                      "FILTER_ID", "SLOT", "PROFILE_TYPE", "FILTER_TYPE",
                      "ACTIVE", "ACTIVE_FLAG", "STATUS")

_ACTIVE_VALUES = {"X", "1", "TRUE", "YES", "ACTIVE", "ON", "Y", "J"}

#: Values that mean "this row names no authorization group". `&NC&` is the marker
#: used for a table without a class; a dash or a blank is how an ALV download
#: renders the same emptiness.
_NO_GROUP = {"", "-", "&NC&", "N/A", "NONE"}

#: Values that mean "every user" / "every client" in a filter definition. A BLANK
#: user field is NOT in this set and is treated as no evidence rather than as a
#: wildcard: an ALV download renders an unset field and a '*' field identically
#: often enough that reading blank as "covers everyone" would suppress the finding
#: on exactly the systems that have it.
_WILDCARD = {"*", "ALL", "**", "*.*"}

_ECS_NOTE = ("SAP Note 3250501 — mandatory hardening of AS ABAP in SAP Enterprise "
             "Cloud Services (v46, 2026-05-15)")


def _cell(row: Dict[str, Any], *names: str) -> str:
    """First non-empty value among `names`, matched case-insensitively."""
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _has_column(row: Dict[str, Any], *names: str) -> bool:
    """Does the row carry any of these columns AT ALL, whatever its value?

    Separate from `_cell` because the two questions have different answers and the
    audit-filter check depends on the difference: an extract with no ACTIVE column
    says nothing about activity, while an ACTIVE column left blank says the filter
    is off. `_cell` collapses both to "" and cannot tell them apart.
    """
    lowered = {str(k).strip().lower() for k in row}
    return any(name.lower() in lowered for name in names)


def _normalise_client(raw: str) -> str:
    """'1' and '001' are the same client; an SE16 download gives either."""
    value = raw.strip()
    return value.zfill(3) if value.isdigit() and len(value) <= 3 else value.upper()


def _is_sap_standard_name(table: str) -> bool:
    """Is this the name of an object SAP itself delivers?

    Customer objects take a Z or Y prefix and partner objects sit in a /namespace/.
    Everything else is SAP's own basic namespace.

    Used for ONE question only — could this extract be complete? — and never to
    decide anything about an individual table: a table in a namespace is neither
    more nor less protected than one outside it, and none of the objects the note
    names is in a namespace anyway.
    """
    return bool(table) and not table.startswith(("Z", "Y", "/"))


class EcsConfigAuditor(BaseAuditor):
    """The configuration half of SAP Note 3250501."""

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_password_hash_tables_protected()
        self.check_pse_table_protected()
        # After the two checks it speaks for: it reports what they could not reach.
        self.check_table_extract_not_assessable()
        self.check_obsolete_clients_deleted()
        self.check_audit_filters_cover_all_users()
        return self.findings

    # ------------------------------------------------------------------ input
    def _rows(self, key: str) -> List[Dict[str, Any]]:
        """Dict rows under `key`, or [] for anything else.

        A key that is absent, empty, or holds something other than a list of rows
        is the same answer — we were not given this evidence — and the caller must
        stay silent rather than report either compliance or a defect.
        """
        raw = self.data.get(key)
        if not isinstance(raw, list):
            return []
        return [r for r in raw if isinstance(r, dict)]

    def _filter_rows(self, key: str) -> List[Dict[str, Any]]:
        """Rows under `key` that are audit FILTER DEFINITIONS, not logged events.

        A row qualifies only if it carries a column a filter definition has and no
        column a logged event has. Both halves are needed and neither alone is
        enough:

          * date column absent, filter column absent  — an event extract whose date
            header we do not recognise. Admitting it hands back a list of ordinary
            end users and reports a compliant filter set as blind. This is the
            defect that motivated the rule.
          * date column present, filter column present — an export that merged the
            two. Excluded, because a row we cannot classify is not evidence.

        The cost is that a hand-made extract of nothing but a USER column is read as
        no evidence and this check stays silent on it. That is the safe direction:
        silence understates coverage, a false verdict misstates the system.
        """
        return [r for r in self._rows(key)
                if _has_column(r, *_FILTER_SHAPE_KEYS) and not _cell(r, *_DATE_KEYS)]

    def _table_auth_index(self) -> Optional[Dict[str, str]]:
        """UPPER(table) -> UPPER(authorization group), or None when unusable.

        None and {} are different answers and the callers depend on the
        difference: None means the extract is absent or has no table column at
        all, so nothing can be concluded. It never returns {} for a supplied
        extract that we could read.
        """
        rows = self._rows(TABLE_AUTH_GROUPS)
        if not rows:
            return None
        index: Dict[str, str] = {}
        for row in rows:
            table = _cell(row, *_TABLE_KEYS).upper()
            if not table:
                continue
            group = _cell(row, *_GROUP_KEYS).upper()
            index[table] = "" if group in _NO_GROUP else group
        return index or None

    def _extract_is_namespace_filtered(self, index: Dict[str, str]) -> bool:
        """Can this extract be PROVEN to have been taken with a filter?

        A complete table -> authorization group extract names objects SAP itself
        delivers. One that names nothing but customer- and partner-namespace objects
        therefore cannot be complete, whatever it does or does not say about SAP's
        tables — and that is the only direction the rows can prove.

        The other direction is not claimed. An extract that DOES name SAP objects may
        still have been filtered by object name, and nothing here can settle it, so
        the findings that rest on absence carry the assumption in their own text
        rather than this method returning a verdict it has not measured.

        Returning True SUPPRESSES evidence, so the rule is deliberately the strict
        one: a single SAP-delivered name anywhere in the extract is enough to stop
        this claiming a filter and silencing a real defect.
        """
        return bool(index) and not any(_is_sap_standard_name(t) for t in index)

    def _required_objects(self) -> List[str]:
        """Every object the note requires to sit behind an authorization group.

        PASSWORD_HASH_TABLES is empty when the note extract has lost its member list
        (see the module docstring), and the list shrinks accordingly rather than the
        gap being filled with a guess.
        """
        return list(PASSWORD_HASH_TABLES) + [PSE_TABLE]

    @staticmethod
    def _completeness_note(absence_is_evidence: bool) -> str:
        """What was assumed about the extract, in one line, for `details`."""
        return ("read as complete — the rows carry no proof it was filtered"
                if absence_is_evidence else
                "namespace-filtered — objects it does not list are not judged here; "
                "see AUTH-ECS-000")

    #: Appended to a finding whose verdict rests on a table being ABSENT from the
    #: extract. The reading is the note's own and it is the right one for a complete
    #: extract, but "complete" is an assumption this scan cannot verify, and a
    #: reviewer holding a filtered extract has to be told that by the finding itself
    #: rather than by reading this module.
    _ABSENCE_CAVEAT = (
        " This verdict counts {0} object(s) that the extract does not list at all. "
        "In a COMPLETE table-to-authorization-group extract an absent row means no "
        "group is assigned, which is the reading applied here — but nothing in the "
        "extract proves it was taken without a namespace or object filter, and a "
        "filtered one would over-report exactly these objects. They are named "
        "separately under 'not_in_extract' in this finding's details; confirm the "
        "export was unfiltered before acting on them."
    )

    # -------------------------------------------------------------- the checks
    def check_password_hash_tables_protected(self):
        """Password-hash tables behind authorization group SPWD.

        The asset is not the table, it is every password hash in the system. A
        user who can display USR02 — or any of its views, its change history or
        its archiving copy — can take the hashes offline and attack them at
        leisure, including the administrators' own. `S_TABU_DIS` is checked
        against the table's authorization group, so a table with no group (or the
        wrong one) is reachable by anyone holding a broad table-display
        authorization, which in practice is most of Basis and most of support.

        AUTH-008 in modules/abap_authorizations.py approaches the same risk from
        the ROLE side ("who holds S_TABU_DIS for '*' or &NC&"). This is the object
        side, and the two do not substitute for each other: a tight role set still
        leaves the hashes exposed if the tables carry no group, and a correct SPWD
        assignment is worthless if roles grant '*'.
        """
        index = self._table_auth_index()
        if index is None:
            return

        # An extract that PROVES it was filtered cannot support the note's reading of
        # absence, so only the rows it actually carries are judged and the objects it
        # never mentions become AUTH-ECS-000's business. Written per table rather than
        # as an early return because the two are only equivalent today: every object
        # the note names is an SAP-standard name, so a provably-filtered extract
        # cannot currently carry one. A future detector that recognises another filter
        # shape must still report the mis-assignments it CAN see.
        absence_is_evidence = not self._extract_is_namespace_filtered(index)

        wrong: List[Tuple[str, str]] = []
        blank: List[str] = []
        absent: List[str] = []
        for table in PASSWORD_HASH_TABLES:
            if table not in index:
                if absence_is_evidence:
                    absent.append(table)
                continue
            group = index[table]
            if group == PASSWORD_HASH_AUTH_GROUP:
                continue
            (blank.append(table) if not group else wrong.append((table, group)))

        offenders = [t for t, _ in wrong] + blank + absent
        if not offenders:
            return

        items = ([f"{t}: authorization group {g} (expected {PASSWORD_HASH_AUTH_GROUP})"
                  for t, g in wrong]
                 + [f"{t}: no authorization group assigned" for t in blank]
                 + [f"{t}: not listed in the table authorization group extract"
                    for t in absent])

        self.finding(
            check_id="AUTH-ECS-001",
            title="Password-hash tables are not protected by authorization group SPWD",
            severity=self.SEVERITY_HIGH,
            category="ABAP Authorization & Critical Access",
            description=(
                "{0} of the {1} table(s) and view(s) that expose stored password "
                "hashes are not assigned to authorization group {2}: {3}. Table "
                "display is authorised through S_TABU_DIS against the table's "
                "authorization group, so a table carrying no group — or a group "
                "that broad support roles already hold — puts every password hash "
                "in the system, administrators included, within reach of anyone "
                "with generic table-display access. The hashes can then be "
                "attacked offline, with no failed-logon counter and nothing in the "
                "audit log to review. The ECS hardening baseline requires all {1} "
                "objects to sit behind {2}."
            ).format(len(offenders), len(PASSWORD_HASH_TABLES),
                     PASSWORD_HASH_AUTH_GROUP, ", ".join(offenders))
            + (self._ABSENCE_CAVEAT.format(len(absent)) if absent else ""),
            affected_items=items,
            # One defect with one fix: the hashes are not behind SPWD. Assigning
            # the group to one of the six must shrink the member list, not retire
            # this finding and raise a fresh one with a reset age. The tables are
            # real named objects and belong in the graph regardless.
            affected_objects=[{"type": "table", "name": t} for t in offenders],
            scope="aggregate",
            remediation=(
                "1. In SE54, assign authorization group {0} to each of the objects "
                "listed above.\n"
                "2. Confirm no role grants S_TABU_DIS for {0} beyond the accounts "
                "that genuinely administer user master data.\n"
                "3. Re-extract the table authorization group assignments and "
                "confirm all {1} objects report {0}."
            ).format(PASSWORD_HASH_AUTH_GROUP, len(PASSWORD_HASH_TABLES)),
            references=[_ECS_NOTE],
            details={
                "expected_group": PASSWORD_HASH_AUTH_GROUP,
                "wrong_group": {t: g for t, g in wrong},
                "no_group": blank,
                # Kept separate from `no_group` on purpose: "the extract says this
                # table has no group" and "the extract does not mention this table"
                # are different evidence, and a filtered extract shows up here.
                "not_in_extract": absent,
                "extract_rows": len(self._rows(TABLE_AUTH_GROUPS)),
                "extract_completeness": self._completeness_note(absence_is_evidence),
            },
        )

    def check_pse_table_protected(self):
        """SSF_PSE_D behind authorization group SPSE.

        SSF_PSE_D holds Personal Security Environments in the database — the
        system's own private key material for TLS, SNC and ticket signing. Read
        access to the table is read access to the keys themselves, not to a
        reference to them, which is what separates this from CRYPTO-PSE-001: that
        check asks whether the PSEs are healthy, this one asks who can read them.
        """
        index = self._table_auth_index()
        if index is None:
            return

        group = index.get(PSE_TABLE)
        if group == PSE_AUTH_GROUP:
            return

        absent = PSE_TABLE not in index
        absence_is_evidence = not self._extract_is_namespace_filtered(index)
        # Same rule as the SPWD check: an extract that proves it was filtered says
        # nothing about a table it does not list, and reporting the system's key
        # material as exposed on that basis would be a finding built out of absence.
        # AUTH-ECS-000 discloses the gap instead.
        if absent and not absence_is_evidence:
            return

        if absent:
            observed = "not listed in the table authorization group extract"
        elif not group:
            observed = "no authorization group assigned"
        else:
            observed = "authorization group {0}".format(group)

        self.finding(
            check_id="CRYPTO-ECS-001",
            # A literal, not a .format() — tests/test_check_id_uniqueness.py can only
            # read a title that is a constant or an f-string, and a computed title
            # silently drops this check out of the collision guard.
            title="Database PSE table SSF_PSE_D is not protected by authorization group SPSE",
            severity=self.SEVERITY_HIGH,
            category="Cryptographic Posture",
            description=(
                "Table {0}, which stores the system's Personal Security "
                "Environments, is {1} — the ECS hardening baseline requires {2}. "
                "The table holds private key material for TLS, SNC and logon-ticket "
                "signing, so anyone whose S_TABU_DIS authorization reaches this "
                "table can read the keys themselves rather than a reference to "
                "them. Extracted keys let an attacker impersonate the system to its "
                "peers and mint logon tickets, and no certificate on the system "
                "would need to change for that to keep working."
            ).format(PSE_TABLE, observed, PSE_AUTH_GROUP)
            + (self._ABSENCE_CAVEAT.format(1) if absent else ""),
            affected_items=["{0}: {1}".format(PSE_TABLE, observed)],
            # One named table IS the defect, so it belongs in identity.
            affected_objects=[{"type": "table", "name": PSE_TABLE}],
            scope="object",
            remediation=(
                "1. In SE54, assign authorization group {0} to table {1}.\n"
                "2. Restrict S_TABU_DIS for {0} to the accounts that administer "
                "certificates and PSEs.\n"
                "3. Re-extract the assignments and confirm {1} reports {0}."
            ).format(PSE_AUTH_GROUP, PSE_TABLE),
            references=[_ECS_NOTE],
            details={
                "table": PSE_TABLE,
                "expected_group": PSE_AUTH_GROUP,
                "observed_group": group if group else None,
                "in_extract": PSE_TABLE in index,
                "extract_rows": len(self._rows(TABLE_AUTH_GROUPS)),
                "extract_completeness": self._completeness_note(absence_is_evidence),
            },
        )

    def check_table_extract_not_assessable(self):
        """The objects whose authorization group this extract could not tell us.

        WHY THIS EXISTS
        Without it, a namespace-filtered extract makes the two checks above drop the
        objects it never mentioned — correctly, because absence in a filtered extract
        is not evidence — and the report then says nothing at all about the password
        hash tables or the database PSE table. A report that says nothing about them
        reads exactly like a report that found them correctly protected. "Nothing to
        find" and "could not look" must never look the same, and this is the second
        of those two, at INFO because it is a gap in the evidence and not a defect in
        the system.

        IT DOES NOT FIRE WHEN THE EXTRACT IS SIMPLY ABSENT. A customer who never sent
        this export is not told anything about their authorization groups: the source
        is reported as missing by the upload coverage manifest, which is where a
        source nobody supplied belongs. This finding is for the narrower and more
        misleading case — an extract WAS supplied, and it cannot answer the question
        it appears to answer.
        """
        index = self._table_auth_index()
        if index is None or not self._extract_is_namespace_filtered(index):
            return
        missing = [t for t in self._required_objects() if t not in index]
        if not missing:
            # A filtered extract that nonetheless carries every object the note names
            # answered the question in full. There is no gap to disclose, and an INFO
            # finding here would be noise on a system we did assess.
            return

        self.finding(
            check_id="AUTH-ECS-000",
            title="Table authorization group assignments could not be assessed from this export",
            severity=self.SEVERITY_INFO,
            category="ABAP Authorization & Critical Access",
            description=(
                "The table-to-authorization-group extract carries {0} row(s) and "
                "names no object outside the customer and partner namespaces, so it "
                "cannot be a complete picture of this system's assignments — it was "
                "taken with a filter. {1} of the objects SAP Note 3250501 requires to "
                "sit behind an authorization group are absent from it: {2}. Absence "
                "from a COMPLETE extract would mean no group is assigned, which is "
                "the defect AUTH-ECS-001 and CRYPTO-ECS-001 report; absence from a "
                "filtered one means only that the filter excluded them, so no verdict "
                "is claimed about these objects. This is a gap in the evidence, not a "
                "verdict on the system: the assignments may be correct, incorrect or "
                "missing and this scan cannot tell."
            ).format(len(self._rows(TABLE_AUTH_GROUPS)), len(missing),
                     ", ".join(missing)),
            remediation=(
                "Re-export the table authorization group assignments without a "
                "namespace or object filter — one row per table and view that carries "
                "an authorization group, from TDDAT — and re-run the scan. The "
                "extract is read as complete, so a filtered one cannot be interpreted: "
                "an object missing from it is indistinguishable from an object with no "
                "group assigned."
            ),
            references=[_ECS_NOTE],
            details={
                "objects_not_assessable": missing,
                "extract_rows": len(self._rows(TABLE_AUTH_GROUPS)),
                "tables_in_extract": sorted(index)[:50],
                "checks_affected": ["AUTH-ECS-001", "CRYPTO-ECS-001"],
                "why": ("no SAP-delivered object appears in the extract, so it cannot "
                        "be complete"),
            },
            # A coverage gap names no defective object. The objects listed above are
            # the ones we could NOT judge, and putting them in identity would add
            # nodes to the attack-path graph that no evidence supports — the same
            # reasoning as modules/snc_posture.py:check_family_not_assessable.
            scope="aggregate",
        )

    def check_obsolete_clients_deleted(self):
        """Clients 001 and 066 removed.

        Both ship with SAP-delivered accounts whose passwords are public, and
        neither is watched the way the production client is — nobody reviews logons
        to 066. They are a standing foothold: authenticate there, then move.

        WHAT THIS CANNOT SEE, AND WHY IT STILL FIRES
        The note asks for these clients to be deleted when UNUSED, and a
        configuration export carries no usage evidence at all — there is no column
        anywhere in what we take that says whether anybody logs on to client 001.
        Reporting the deviation and saying plainly that usage was not measured is
        more useful than staying silent, so the finding names the limit rather than
        implying we checked. Severity is set for that uncertainty, not against the
        worst case.
        """
        rows = self._rows("client_settings")
        if not rows:
            return

        present = set()
        for row in rows:
            client = _normalise_client(_cell(row, *_CLIENT_KEYS))
            if client:
                present.add(client)
        if not present:
            return

        offenders = [c for c in OBSOLETE_CLIENTS if c in present]
        if not offenders:
            return

        self.finding(
            check_id="STDUSR-ECS-001",
            title="Obsolete standard client(s) still present in the system",
            severity=self.SEVERITY_MEDIUM,
            category="System Trust & Standard Users",
            description=(
                "Client(s) {0} still exist in this system. The ECS hardening "
                "baseline requires them to be deleted once they are no longer in "
                "use. Each carries SAP-delivered accounts whose default passwords "
                "are public knowledge, and neither client attracts the logon "
                "monitoring the production client does, so an account there is a "
                "quiet place to authenticate before moving on. The configuration "
                "export carries no usage data, so whether these clients are "
                "actually unused has NOT been measured here — confirm that before "
                "deleting."
            ).format(", ".join(offenders)),
            affected_items=["Client {0}: present".format(c) for c in offenders],
            # Clients are real objects and belong in the graph, but this is one
            # baseline item with one decision; deleting 001 while 066 remains must
            # shrink the list rather than reset the finding's age.
            affected_objects=[{"type": "client", "name": c} for c in offenders],
            scope="aggregate",
            remediation=(
                "1. Confirm with the application and Basis owners that client(s) "
                "{0} carry no data and no logons that matter.\n"
                "2. Delete each confirmed-unused client with SCC5.\n"
                "3. Where a client must be kept, lock every SAP-delivered account "
                "in it, change the default passwords, and record the exception."
            ).format(", ".join(offenders)),
            references=[_ECS_NOTE],
            details={
                "obsolete_clients_present": offenders,
                "clients_in_export": sorted(present),
                # Named so a reader does not mistake the finding for a usage claim.
                "usage_evidence": "not available from a configuration export",
            },
        )

    def check_audit_filters_cover_all_users(self):
        """Security Audit Log filters recording every user.

        A filter bound to named users records those users and nobody else. The
        blind spot is the whole point: whoever is not on the list is not in the
        log, so a retrospective review of any window can say nothing about them.

        SCOPE, AND WHY IT IS HALF THE NOTE'S ITEM
        The note requires all users AND all clients. The client half is already
        LREV-FLT-002 in modules/log_review.py and is deliberately not repeated —
        two findings for one misconfiguration would be counted twice in the loss
        figure and worked twice.

        THE FALSE POSITIVE THIS AVOIDS
        A perfectly good configuration is one broad filter for everybody plus a
        narrow filter that records one account in more detail. Firing because SOME
        filter names a user would flag that configuration, so the check fires only
        when NO active filter covers all users while at least one names a specific
        one. A filter set that carries no user column at all is no evidence and
        produces nothing.
        """
        # Filter rows only, identified by POSITIVE evidence — see `_filter_rows`.
        # An event-shaped security_audit_log means the filter configuration, if we
        # were sent one, is in the fallback export; this is modules/log_review.py's
        # `_prepare` rule, and diverging from it dropped the check on every system
        # that supplied both an event log and a filter list.
        config_rows = (self._filter_rows("security_audit_log")
                       or self._filter_rows("audit_config"))
        if not config_rows:
            return

        named_users: List[str] = []
        for row in config_rows:
            # A row whose ACTIVE column is present but does not say "on" — including
            # a blank cell — is a switched-off filter: it records nothing and
            # restricts nothing, so it is no evidence here (it is LREV-FLT-001's
            # business). A row with no ACTIVE column at all is a different answer:
            # most hand-made filter extracts have no such column, and dropping those
            # rows would silently disable this check on every one of them.
            if (_has_column(row, *_ACTIVE_KEYS)
                    and _cell(row, *_ACTIVE_KEYS).upper() not in _ACTIVE_VALUES):
                continue
            user = _cell(row, *_USER_KEYS).upper()
            if not user:
                continue
            if user in _WILDCARD:
                return  # an active filter covers everyone — compliant, say nothing
            named_users.append(user)

        if not named_users:
            return  # no user field anywhere: no evidence either way

        offenders = sorted(set(named_users))
        self.finding(
            check_id="LREV-ECS-001",
            title="Security Audit Log filters are bound to named users rather than all users",
            severity=self.SEVERITY_HIGH,
            category="Security Audit Log Review",
            description=(
                "Every active audit filter is restricted to a specific user; none "
                "covers all users. The filters name {0} account(s): {1}. Actions by "
                "anyone else are not written to the Security Audit Log at all, so "
                "the log cannot answer a question about them after the fact — not "
                "an investigation, not an access review, not an auditor's sample. "
                "The ECS hardening baseline requires the audit filters to record "
                "all users."
            ).format(len(offenders), ", ".join(offenders[:20])),
            affected_items=["Audit filter restricted to user {0}".format(u)
                            for u in offenders[:50]],
            # The users named here are the filters' configured scope, not the
            # subject of the defect: the defect is that no filter is unrestricted,
            # and one fix (set the user field to '*') closes it whatever the list
            # says. Aggregate so editing one filter does not reset the age.
            scope="aggregate",
            remediation=(
                "1. In SM19 / RSAU_CONFIG, set the user field of the audit filter "
                "to '*' so every account is recorded.\n"
                "2. Keep any per-user filter only as an ADDITIONAL filter with a "
                "wider event selection, never as the only active one.\n"
                "3. Re-extract the filter configuration and confirm at least one "
                "active filter records all users."
            ),
            references=[_ECS_NOTE],
            details={
                "filters_restricted_to_users": offenders,
                "active_filter_rows": len(config_rows),
                # Named so nobody reads this finding as a statement about clients.
                "client_coverage": "checked separately by LREV-FLT-002",
            },
        )
