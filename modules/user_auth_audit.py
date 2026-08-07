"""
User & Authorization Auditor
=============================
Checks for:
  - SAP* and DDIC default user status
  - Users with SAP_ALL / SAP_NEW profiles
  - Dormant / never-logged-in accounts
  - Locked vs unlocked user ratios
  - Dialog users with critical authorizations
  - Service/system users with dialog logon type
  - Users with S_DEVELOP (debug/replace) in production
  - Excessive role assignments per user

WHY THE STANDARD-USER CHECK IS DEPLOYMENT-AWARE
------------------------------------------------
"Lock DDIC" is correct advice for AS ABAP in general and WRONG for the environment
this product exists to audit. SAP Note 3250501, the mandatory hardening baseline
for AS ABAP in SAP Enterprise Cloud Services, carries DDIC as an explicit exception
(configuration item ``secure_ddic_ecs_exception``): locking it is NOT required
there. SAP's stated reasoning is structural rather than lenient — DDIC ships as
user type System, which is a type that cannot open a normal SAP GUI dialog session;
it is moved to type Service only when a request is raised through SAP's CAM process
in ECS; and DDIC's activity is audit relevant either way.

UNVERIFIED: the three sentences above paraphrase the note's PROSE, which
``data/ecs_hardening_3250501.json`` deliberately does not carry (facts only — see
that file's ``source.note``). What the data supports is the configuration item NAME
``secure_ddic_ecs_exception``; "DDIC ships as user type System" and the process name
"CAM" are not in it. Both need checking against the note text before this reasoning
is quoted to a customer — and if DDIC is in fact delivered as type Dialog, USR-009
below fires on a compliant ECS tenant, which is the same false positive in a
different coat.

So on the exact estate we target we were telling every customer to perform work
their provider's own baseline says is unnecessary, with a remediation that can
collide with ECS operations. That is the same false-positive class the CVA engine's
Tier 2 was spent eliminating: reasoning from what a control SOUNDS like instead of
from what the governing baseline says.

The check is therefore split by deployment mode rather than deleted, because
non-ECS AS ABAP still wants DDIC locked and losing that would be a real regression:

  * on premise (``on_prem``, and any mode we were not told about) — unchanged.
  * ECS / RISE (``rise_*``) — the lock finding is not raised for DDIC. What IS
    verified is the premise SAP's exception rests on: that DDIC is type System or
    Service and not Dialog. A Dialog DDIC in ECS voids the protection SAP cites,
    and is a sharper finding than the one it replaces (``USR-009``).

EARLYWATCH gets the same treatment for the same reason in the other direction: the
note's configuration item is ``delete_earlywatch_all_clients``, so in ECS the
compliant state is that the account does not exist, not that it is locked, and our
generic "lock if unused" guidance under-states it (``USR-010``).

The mode arrives in ``run_context["deployment_mode"]`` and uses server/enrich.py's
existing vocabulary (``on_prem`` / ``rise_pce`` / ``rise_tailored``, tested with
``startswith("rise")``) rather than a second one invented here — two vocabularies
for one concept is how a finding ends up owned by nobody.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from modules.base_auditor import BaseAuditor


#: The bundled facts extracted from SAP Note 3250501. READ ONLY here — the file is
#: maintained elsewhere, and the values in it are the note's, never ours.
_ECS_NOTE_FILE = Path(__file__).resolve().parent.parent / "data" / "ecs_hardening_3250501.json"

#: ``None`` = not loaded yet; ``{}`` = loaded and unusable. Tests set this directly
#: to exercise the no-note path without touching the filesystem.
_ECS_NOTE_CACHE: Optional[Dict[str, Any]] = None


def _ecs_note() -> Dict[str, Any]:
    """The note's extracted facts, or ``{}``.

    Never raises: a missing or malformed data file must degrade the two ECS-aware
    checks, not take out the whole user audit.
    """
    global _ECS_NOTE_CACHE
    if _ECS_NOTE_CACHE is None:
        try:
            with open(_ECS_NOTE_FILE, encoding="utf-8") as fh:
                loaded = json.load(fh)
            _ECS_NOTE_CACHE = loaded if isinstance(loaded, dict) else {}
        except Exception:                                  # noqa: BLE001
            _ECS_NOTE_CACHE = {}
    return _ECS_NOTE_CACHE


def _ecs_configuration_items() -> frozenset:
    items = _ecs_note().get("configuration_items")
    return frozenset(str(i) for i in items) if isinstance(items, list) else frozenset()


def _ecs_parameter(name: str) -> str:
    """The ECS standard value for a profile parameter, or ``""`` if the note has none.

    Values are read, never transcribed. A hand-typed baseline value is how this
    product previously told customers a system was compliant when it was not.
    """
    params = _ecs_note().get("parameters")
    entry = params.get(name) if isinstance(params, dict) else None
    return str(entry.get("ecs", "")) if isinstance(entry, dict) else ""


def _ecs_note_citation() -> str:
    """"SAP Note 3250501 (v46, 2026-05-15)" — revision read from the file.

    The revision belongs in the finding: a reviewer holding v47 needs to see which
    revision we judged them against, and hard-coding it would let the citation drift
    away from the data it describes.
    """
    src = _ecs_note().get("source")
    src = src if isinstance(src, dict) else {}
    version, released = src.get("version"), src.get("released")
    if version and released:
        return f"SAP Note 3250501 (v{version}, {released})"
    return "SAP Note 3250501"


class UserAuthAuditor(BaseAuditor):

    # Well-known default SAP users that should be locked/secured.
    #
    # This is the GENERIC (non-ECS) rule set and stays exactly as it was — it is
    # correct for AS ABAP outside SAP Enterprise Cloud Services, which is precisely
    # why the ECS carve-outs live beside it instead of replacing it.
    DEFAULT_USERS = {
        "SAP*": "Default superuser — must be locked in all clients",
        "DDIC": "Data dictionary user — lock in production, restrict to admin",
        "SAPCPIC": "CPI-C communication user — lock if unused",
        "EARLYWATCH": "EarlyWatch monitoring — lock if not actively used",
        "TMSADM": "Transport management — verify authorization scope",
    }

    #: Standard users whose ECS rule differs from the generic one, mapped to the
    #: configuration item in SAP Note 3250501 that says so. Every entry here is a
    #: key looked up IN the note file, not a value copied out of it.
    #:
    #: SAP*, SAPCPIC and TMSADM are deliberately absent: the note's items for them
    #: call for the accounts to be secured, which is what the generic check already
    #: asserts. We only diverge where the note actually diverges.
    ECS_STANDARD_USER_ITEMS = {
        "DDIC": "secure_ddic_ecs_exception",
        "EARLYWATCH": "delete_earlywatch_all_clients",
    }

    #: Carve-outs that still stand when the note file cannot be read, and the reason
    #: they differ:
    #:
    #:   * DDIC — suppressing the lock finding costs nothing, because the sharper
    #:     `USR-009` type check runs in its place. Raising it would reinstate a known
    #:     false positive on every ECS tenant on the strength of a missing file.
    #:   * EARLYWATCH — its replacement `USR-010` asserts a rule we could not read,
    #:     so it must NOT run. Suppressing the generic check as well would leave the
    #:     account audited by nothing at all, which is worse than the generic text.
    ECS_ITEM_ASSUMED_WHEN_NOTE_UNREADABLE = frozenset({"DDIC"})

    #: SAP user types (USR02-USTYP). Only these two keep DDIC out of an ordinary
    #: dialog session, and they are the two states SAP's ECS exception describes:
    #: System as delivered, Service once access is requested through CAM.
    #: UNVERIFIED: "CAM" — see the module docstring.
    #:
    #: REVIEWER NOTE: this is reported to the reader in `details` but is NOT the
    #: decision. `check_ddic_type_ecs` fires on an explicit Dialog marker only, so a
    #: DDIC carrying any OTHER non-accepted type (C, L, a typo) is silent in ECS
    #: while the generic lock check stays suppressed. Widening the decision to
    #: "present and not in this set" is a behaviour change, so it is left to the
    #: owner rather than made during review.
    DDIC_ACCEPTED_TYPES_ECS = {"B": "System", "S": "Service"}

    #: Explicit markers for USTYP = Dialog. An EMPTY cell is not a Dialog user — it
    #: is an export that did not say, and turning silence into a HIGH finding
    #: against DDIC is the same reasoning error this module was sent to remove.
    _DIALOG_MARKERS = {"A", "DIALOG"}

    # Profiles considered critical / overprivileged
    CRITICAL_PROFILES = ["SAP_ALL", "SAP_NEW", "S_A.SYSTEM"]

    # Authorization objects indicating high-privilege access
    CRITICAL_AUTH_OBJECTS = {
        "S_DEVELOP":    "Debug and code replacement in production",
        "S_ADMI_FCD":   "Admin functions (PADM = all admin privileges)",
        "S_BTCH_ADM":   "Batch admin across all clients",
        "S_RZL_ADM":    "System administration",
        "S_USER_GRP":   "User group admin with ACTVT=* (full user management)",
        "S_TABU_DIS":   "Table maintenance with AUTH='&NC&' (bypasses auth groups)",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_default_users()
        self.check_ddic_type_ecs()
        self.check_earlywatch_removed_ecs()
        self.check_critical_profiles()
        self.check_dormant_accounts()
        self.check_user_type_mismatch()
        self.check_excessive_roles()
        self.check_critical_auth_objects()
        self.check_never_logged_in()
        self.check_password_not_changed()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _objects(pairs) -> List[Dict[str, Any]]:
        """Build de-duplicated affected-object dicts from (type, name) pairs.

        De-duplication keeps one graph node per real object: the SAP_ALL profile named
        in forty offending assignments is one node, not forty. A pair whose name is
        empty is dropped rather than given an invented placeholder — an export row with
        no BNAME names no user, and fabricating one would put a fictional node in the
        graph and, worse, let two nameless rows share an identity.
        """
        out: List[Dict[str, Any]] = []
        seen = set()
        for obj_type, name in pairs:
            n = "" if name is None else str(name).strip()
            if not n:
                continue
            key = (obj_type, n.upper())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": obj_type, "name": n})
        return out

    # ------------------------------------------------------- deployment context
    def deployment_mode(self) -> str:
        """Which estate we are auditing: ``on_prem`` / ``rise_pce`` / ``rise_tailored``.

        Defaults to ``on_prem`` for the same reason `BaseAuditor.run_context` says a
        module should: when the caller did not tell us, fall back to the historical
        behaviour rather than guess. Guessing ECS here would silently drop the DDIC
        lock check on genuine on-premise systems.
        """
        mode = self.run_context.get("deployment_mode") or ""
        return str(mode).strip().lower() or "on_prem"

    def is_ecs(self) -> bool:
        """RISE / SAP Enterprise Cloud Services, by server/enrich.py's own test."""
        return self.deployment_mode().startswith("rise")

    def _ecs_exception_applies(self, user: str) -> bool:
        """Does the ECS baseline carve this standard user out of the generic rule?

        Gated on the note file so the carve-out is REVISION-AWARE: if a future
        revision drops ``secure_ddic_ecs_exception``, DDIC falls straight back into
        the generic lock check without anyone editing this module. What happens when
        the file cannot be read is per-user and deliberate — see
        `ECS_ITEM_ASSUMED_WHEN_NOTE_UNREADABLE`.
        """
        if not self.is_ecs():
            return False
        item = self.ECS_STANDARD_USER_ITEMS.get(user)
        if not item:
            return False
        items = _ecs_configuration_items()
        if not items:
            return user in self.ECS_ITEM_ASSUMED_WHEN_NOTE_UNREADABLE
        return item in items

    # --------------------------------------------------------- row field access
    @staticmethod
    def _field(row: Dict[str, Any], *names: str, default: str = "") -> str:
        """A column's value as a stripped string, tolerating None and absent keys.

        ``row.get("BNAME", row.get("USERNAME", ""))`` returns None when BNAME is
        present but empty in the CSV, and the ``.upper()`` after it then takes the
        whole module down on one malformed row.
        """
        for name in names:
            value = row.get(name)
            if value not in (None, ""):
                return str(value).strip()
        return default

    def _rows(self, key: str) -> List[Dict[str, Any]]:
        """The dict rows of an export, or ``[]``.

        Every loop in this module goes through here so that one malformed row cannot
        take the audit down. That is not hypothetical tidiness: a raising module is
        caught and skipped by the runner (server/ingest.py), so a single junk row
        used to cost the customer EVERY user finding, and the report said only that
        the module failed.
        """
        rows = self.data.get(key)
        if not isinstance(rows, list):
            return []
        return [row for row in rows if isinstance(row, dict)]

    def _rows_for_user(self, user: str) -> List[Dict[str, Any]]:
        """Every row in the user export naming `user` (one per client, typically)."""
        return [row for row in self._rows("users")
                if self._field(row, "BNAME", "USERNAME").upper() == user]

    @classmethod
    def _is_unlocked(cls, row: Dict[str, Any]) -> bool:
        # UFLAG = 0 means unlocked; anything > 0 generally means locked.
        return cls._field(row, "UFLAG", "LOCK_STATUS", default="0") in ("0", "")

    @classmethod
    def _client_of(cls, row: Dict[str, Any]) -> str:
        return cls._field(row, "MANDT", "CLIENT")

    def check_default_users(self):
        """Check if default SAP users are properly secured."""
        for row in self._rows("users"):
            uname = self._field(row, "BNAME", "USERNAME").upper()

            if uname in self.DEFAULT_USERS:
                # DDIC and EARLYWATCH are judged by the ECS baseline's own rule in a
                # RISE tenant, not by this generic one. Skipping them here is the fix:
                # the replacement checks below are stricter, not absent.
                if self._ecs_exception_applies(uname):
                    continue
                if self._is_unlocked(row):
                    # Only claim what the note says when we have actually read it.
                    # On the unreadable-file path EARLYWATCH still reaches this
                    # branch, and "the baseline grants it no exception" would then
                    # be an assertion about a document we could not open.
                    ecs = self.is_ecs() and bool(_ecs_configuration_items())
                    self.finding(
                        check_id="USR-001",
                        title=f"Default user {uname} is unlocked",
                        severity=self.SEVERITY_CRITICAL if uname in ("SAP*", "DDIC") else self.SEVERITY_HIGH,
                        category="User & Authorization",
                        description=(
                            f"The default SAP user '{uname}' is unlocked. "
                            f"{self.DEFAULT_USERS[uname]}. "
                            "Attackers routinely target default users with well-known passwords."
                            + (
                                f" {_ecs_note_citation()} carries this account in its "
                                "mandatory hardening set for SAP Enterprise Cloud "
                                "Services and grants it no exception, so the "
                                "requirement is the provider's as well as ours."
                                if ecs else ""
                            )
                        ),
                        affected_items=[uname],
                        # One finding per unlocked default user, so the user IS the
                        # defect and must sit in identity — otherwise the four USR-001
                        # rows collapse into one and three defects vanish from the
                        # report (see server/identity.py, OBJECT findings).
                        affected_objects=[{"type": "user", "name": uname}],
                        scope="object",
                        remediation=(
                            f"Lock user {uname} via SU01 or set UFLAG > 0. "
                            "Change password to a strong random value."
                            + (self._sapstar_remediation() if uname == "SAP*" else "")
                        ),
                        references=(
                            # UNVERIFIED: 1414256 is not among the notes 3250501
                            # itself references, and it predates this work — kept
                            # rather than silently dropped, but do not rely on it
                            # without checking it in the SAP support portal.
                            ["SAP Note 1414256 — Secure default users",
                             "CIS SAP Benchmark Section 2.1"]
                            + ([_ecs_note_citation() + " — mandatory ECS hardening for AS ABAP"]
                               if ecs else [])
                        ),
                        details={"deployment_mode": self.deployment_mode()},
                    )

    def _sapstar_remediation(self) -> str:
        """The SAP* fallback-logon guidance, with any values read from the note.

        The parameter NAMES are ours to state and are stated unconditionally. The
        VALUES are only ever printed when the note file supplies them, and are
        labelled as the ECS standard rather than presented as a universal truth —
        a baseline value typed from memory is precisely the defect that told a
        customer they were compliant when they were not.
        """
        params = ("login/no_automatic_user_sapstar", "login/create_virtual_user_sapstar")
        stated = [f"{p} = {v}" for p in params if (v := _ecs_parameter(p))]
        if stated:
            # Attributed rather than asserted, because it is an ECS value and this
            # remediation is also read on premise.
            return (" Also close the SAP* fallback logon. SAP's ECS baseline sets "
                    + " and ".join(stated) + ".")
        return (" Also close the SAP* fallback logon via "
                + " and ".join(params) + ".")

    def check_ddic_type_ecs(self):
        """ECS only: DDIC must not be a Dialog user.

        This is the check that REPLACES "DDIC is unlocked" on a RISE tenant, and it
        is the sharper of the two. SAP's exception for DDIC in ECS does not say the
        account is harmless; it says the account's TYPE keeps it out of an ordinary
        SAP GUI session, that moving it to Service is a tracked request, and that
        what it does is audit relevant. Type Dialog satisfies none of that, so an
        ECS system whose DDIC is Dialog has lost the protection the exception is
        built on — while still, under the note, not being required to lock it.

        Only an EXPLICIT Dialog marker fires. A blank USTYP column is an export that
        did not say, and inferring Dialog from silence would rebuild the very false
        positive this method exists to remove.
        """
        if not self._ecs_exception_applies("DDIC"):
            return

        rows = self._rows_for_user("DDIC")
        if not rows:
            return

        dialog = [row for row in rows
                  if self._field(row, "USTYP", "USER_TYPE").upper() in self._DIALOG_MARKERS]
        if not dialog:
            return

        unlocked = [row for row in dialog if self._is_unlocked(row)]
        clients = sorted({self._client_of(row) for row in dialog if self._client_of(row)})
        where = f" in client(s) {', '.join(clients)}" if clients else ""

        # Same rule the generic check follows on this path: only describe the note
        # when we actually read it. `ECS_ITEM_ASSUMED_WHEN_NOTE_UNREADABLE` lets the
        # DDIC carve-out (and therefore this check) run on a missing file, so without
        # this branch the finding would quote 3250501 at a reader who could then not
        # be shown where the quote came from.
        note_read = bool(_ecs_configuration_items())
        if note_read:
            baseline = (
                f"{_ecs_note_citation()} does not require DDIC to be locked in SAP "
                "Enterprise Cloud Services (configuration item "
                f"'{self.ECS_STANDARD_USER_ITEMS['DDIC']}'), and this scanner "
                "therefore does not raise that finding here. That exception rests on "
                # UNVERIFIED: "CAM" is the ECS access-request process this reasoning
                # names; it is NOT stated in data/ecs_hardening_3250501.json, which
                # carries facts only. Confirm the process name against the note text
                # or the customer's ECS contract before relying on this wording.
                "DDIC being delivered as user type System — a type that cannot open "
                "an ordinary SAP GUI dialog session — and being moved to type Service "
                "only when access is requested through SAP's CAM process, with its "
                "activity treated as audit relevant. A Dialog DDIC removes the first "
                "of those protections and bypasses the request path that produces the "
                "second, so the account is interactively usable by anyone holding its "
                "password, outside the process SAP's exception assumes."
            )
        else:
            baseline = (
                "This scanner does not raise the generic 'default user unlocked' "
                "finding for DDIC on an ECS-managed system. Type Dialog lets the "
                "account open an ordinary SAP GUI session, so it is interactively "
                "usable by anyone holding its password."
            )

        self.finding(
            check_id="USR-009",
            title="DDIC is a dialog user on an ECS-managed system",
            # HIGH only where the account can actually be used: a locked Dialog DDIC
            # is a misconfiguration waiting for the next maintenance unlock, not a
            # live path. Severity is not part of a finding's identity, so this can
            # move between runs without orphaning its history.
            severity=self.SEVERITY_HIGH if unlocked else self.SEVERITY_MEDIUM,
            category="User & Authorization",
            description=(
                f"DDIC has user type Dialog{where}. "
                + baseline
                + ("" if unlocked else
                   " The account is currently locked, which limits exposure until the "
                   "next maintenance unlock — the type is still wrong.")
            ),
            affected_items=[
                f"DDIC (type=Dialog, "
                f"{'unlocked' if self._is_unlocked(row) else 'locked'}"
                + (f", client {self._client_of(row)}" if self._client_of(row) else "")
                + ")"
                for row in dialog
            ],
            # One account, one defect — even when the export carries a row per
            # client. The user is what the finding is ABOUT, so it carries identity
            # and the finding survives a client being added or removed.
            affected_objects=[{"type": "user", "name": "DDIC"}],
            scope="object",
            remediation=(
                "Set DDIC back to user type System (USR02-USTYP = B) in SU01, in "
                "every client where it is Dialog. Where DDIC access is genuinely "
                # UNVERIFIED: "CAM" — see the note above the description. The process
                # name is not in the extracted note facts; the rest of this sentence
                # stands without it.
                "needed, request it through the CAM process your ECS contract "
                "defines rather than converting the account locally — type Service "
                "is the state that process produces, and it keeps the access "
                "attributable. Confirm the account's activity is covered by the "
                "Security Audit Log before and after the change."
            ),
            # Cited only when the file backing the citation was actually read.
            references=(
                [_ecs_note_citation()
                 + " — mandatory hardening for AS ABAP in SAP Enterprise Cloud Services"]
                if note_read else []
            ),
            details={
                "deployment_mode": self.deployment_mode(),
                "ecs_configuration_item": self.ECS_STANDARD_USER_ITEMS["DDIC"],
                "accepted_types_ecs": self.DDIC_ACCEPTED_TYPES_ECS,
                "observed_clients": clients,
                "locked": not bool(unlocked),
            },
        )

    def check_earlywatch_removed_ecs(self):
        """ECS only: EARLYWATCH should not exist at all.

        Our generic guidance is "lock if not actively used". The ECS baseline's item
        for this account is ``delete_earlywatch_all_clients``, so on a RISE tenant a
        locked-but-present EARLYWATCH is still a deviation and a report that calls it
        compliant is wrong.

        Unlike the DDIC carve-out this check refuses to run when the note file cannot
        be read: this ASSERTS a requirement rather than withdrawing one, and asserting
        a requirement we could not read is how invented rules get shipped.
        """
        if not self.is_ecs():
            return
        item = self.ECS_STANDARD_USER_ITEMS["EARLYWATCH"]
        if item not in _ecs_configuration_items():
            return

        rows = self._rows_for_user("EARLYWATCH")
        if not rows:
            return                      # the compliant state: the account is gone

        unlocked = [row for row in rows if self._is_unlocked(row)]
        clients = sorted({self._client_of(row) for row in rows if self._client_of(row)})
        where = f" in client(s) {', '.join(clients)}" if clients else ""

        self.finding(
            check_id="USR-010",
            title="EARLYWATCH still exists on an ECS-managed system",
            # An unlocked EARLYWATCH keeps the HIGH the generic check gave it — this
            # replaces that finding and must not quietly downgrade a live account.
            # Locked-but-present is a baseline deviation with no logon path, so LOW.
            severity=self.SEVERITY_HIGH if unlocked else self.SEVERITY_LOW,
            category="User & Authorization",
            description=(
                f"The standard user EARLYWATCH is present{where} and is "
                f"{'unlocked' if unlocked else 'locked'}. "
                f"{_ecs_note_citation()} requires this account to be removed from "
                "every client of an AS ABAP system in SAP Enterprise Cloud Services "
                f"(configuration item '{item}') — locking it is not sufficient there, "
                "so this replaces the generic 'lock if unused' guidance we apply "
                "outside ECS."
                + (" While it is unlocked it is a logon target with a widely known "
                   "default password history." if unlocked else "")
            ),
            affected_items=[
                "EARLYWATCH ("
                + ("unlocked" if self._is_unlocked(row) else "locked")
                + (f", client {self._client_of(row)}" if self._client_of(row) else "")
                + ")"
                for row in rows
            ],
            affected_objects=[{"type": "user", "name": "EARLYWATCH"}],
            scope="object",
            remediation=(
                "Delete EARLYWATCH in every client via SU01 (SU10 for a mass "
                "action), after confirming with your SAP-managed-services contact "
                "that no EarlyWatch collection still authenticates as it. Lock it "
                "first and observe, if you need a rollback window — but the ECS "
                "target state is that the account does not exist."
            ),
            references=[
                _ecs_note_citation()
                + " — mandatory hardening for AS ABAP in SAP Enterprise Cloud Services",
            ],
            details={
                "deployment_mode": self.deployment_mode(),
                "ecs_configuration_item": item,
                "observed_clients": clients,
                "locked": not bool(unlocked),
            },
        )

    def check_critical_profiles(self):
        """Check for users assigned SAP_ALL, SAP_NEW, S_A.SYSTEM."""
        profiles = self._rows("profiles")
        if not profiles:
            # Fall back to checking in user_roles or users
            for row in self._rows("users"):
                prof = self._field(row, "PROFILE", "PROFILES").upper()
                for crit in self.CRITICAL_PROFILES:
                    if crit in prof:
                        uname = self._field(row, "BNAME", "USERNAME")
                        self.finding(
                            check_id="USR-002",
                            title=f"User {uname} has critical profile {crit}",
                            severity=self.SEVERITY_CRITICAL,
                            category="User & Authorization",
                            description=(
                                f"User '{uname}' is assigned the '{crit}' profile, "
                                "granting unrestricted system access. This violates "
                                "least-privilege and is a critical audit finding."
                            ),
                            affected_items=[f"{uname} → {crit}"],
                            # One finding per offending user-profile assignment, so
                            # both halves of the assignment belong to its identity:
                            # revoking SAP_ALL from one user must not touch another
                            # user's finding.
                            affected_objects=self._objects(
                                [("user", uname), ("profile", crit)]),
                            scope="object",
                            remediation=(
                                f"Remove {crit} from user {uname} via SU01/SU02. "
                                "Replace with role-based authorizations scoped to actual needs. "
                                "Document any temporary emergency assignments with expiry."
                            ),
                            references=[
                                "SAP Note 1698789 — Removal of SAP_ALL",
                                "CIS SAP Benchmark Section 2.3"
                            ],
                        )
            return

        affected = []
        object_pairs = []
        for row in profiles:
            profile = self._field(row, "PROFILE", "AGR_NAME").upper()
            uname = self._field(row, "BNAME", "USERNAME")
            for crit in self.CRITICAL_PROFILES:
                if crit == profile or crit in profile:
                    affected.append(f"{uname} → {profile}")
                    object_pairs.extend((("user", uname), ("profile", profile)))

        if affected:
            self.finding(
                check_id="USR-002",
                title=f"Users assigned critical profiles ({', '.join(self.CRITICAL_PROFILES)})",
                severity=self.SEVERITY_CRITICAL,
                category="User & Authorization",
                description=(
                    f"{len(affected)} user-profile assignment(s) found with critical profiles "
                    "that grant unrestricted system access."
                ),
                affected_items=affected,
                # This path rolls EVERY critical-profile assignment into one finding,
                # so its identity must exclude the membership: stripping SAP_ALL from
                # one of twelve users would otherwise retire this finding and raise a
                # brand-new one, resetting its age while eleven users stay exposed.
                # The users and profiles still ride along as graph nodes.
                affected_objects=self._objects(object_pairs),
                scope="aggregate",
                remediation=(
                    "Remove all SAP_ALL/SAP_NEW/S_A.SYSTEM assignments. "
                    "Implement proper role-based access control (RBAC). "
                    "Use emergency/firefighter procedures (e.g., SAP GRC) for break-glass scenarios."
                ),
                references=[
                    "SAP Note 1698789",
                    "CIS SAP Benchmark Section 2.3",
                ],
            )

    def check_dormant_accounts(self):
        """Flag accounts with no login in 90+ days."""
        dormant_days = self.get_config("dormant_threshold_days", 90)
        dormant = []
        dormant_objs = []

        for row in self._rows("users"):
            uname = self._field(row, "BNAME", "USERNAME")
            last_logon = self._field(row, "TRDAT", "LAST_LOGON")

            if not self._is_unlocked(row):
                continue  # already locked, skip

            if last_logon:
                try:
                    # Try common SAP date formats
                    for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"):
                        try:
                            logon_date = datetime.strptime(last_logon, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        continue

                    days_inactive = (datetime.now() - logon_date).days
                    if days_inactive > dormant_days:
                        dormant.append(f"{uname} (last logon: {last_logon}, {days_inactive}d ago)")
                        dormant_objs.append(("user", uname))
                except Exception:
                    continue

        if dormant:
            self.finding(
                check_id="USR-003",
                title=f"Dormant accounts ({dormant_days}+ days inactive)",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(dormant)} active (unlocked) user account(s) have not logged in "
                    f"for over {dormant_days} days. Dormant accounts increase attack surface."
                ),
                affected_items=dormant,
                # THE aggregate case from server/identity.py: "23 dormant accounts" is
                # about the check, not about any one account. Locking one dormant user
                # must shrink the list, not retire this finding and raise a fresh one
                # with its age reset to zero.
                affected_objects=self._objects(dormant_objs),
                scope="aggregate",
                remediation=(
                    "Review and lock dormant accounts. Implement automated dormant "
                    "account detection using SAP GRC or scheduled ABAP report RSUSR200. "
                    "Establish a policy for periodic user access reviews."
                ),
                references=["CIS SAP Benchmark Section 2.5"],
            )

    def check_user_type_mismatch(self):
        """Flag service/system accounts with dialog logon type."""
        mismatched = []
        mismatched_objs = []
        for row in self._rows("users"):
            uname = self._field(row, "BNAME", "USERNAME")
            user_type = self._field(row, "USTYP", "USER_TYPE")

            # In SAP: A=Dialog, B=System, C=Communication, L=Reference, S=Service
            # Service/system accounts should not have type A (dialog)
            # Check naming conventions suggesting service accounts
            is_service_name = any(
                prefix in uname.upper()
                for prefix in ("SVC_", "RFC_", "BATCH_", "BG_", "INT_", "API_", "TECH_")
            )
            if is_service_name and str(user_type).upper() in ("A", "DIALOG", ""):
                mismatched.append(f"{uname} (type={user_type or 'Dialog'})")
                mismatched_objs.append(("user", uname))

        if mismatched:
            self.finding(
                check_id="USR-004",
                title="Service/technical accounts with dialog logon type",
                severity=self.SEVERITY_HIGH,
                category="User & Authorization",
                description=(
                    f"{len(mismatched)} account(s) appear to be service/technical users "
                    "but have dialog (interactive) logon capability. This allows "
                    "interactive logon with service credentials."
                ),
                affected_items=mismatched,
                # One finding rolling up every mis-typed service account, so identity
                # excludes the membership — converting one account to type S must not
                # restart the clock on the ones still wrong.
                affected_objects=self._objects(mismatched_objs),
                scope="aggregate",
                remediation=(
                    "Change user type to B (System), C (Communication), or S (Service) "
                    "as appropriate via SU01. Service accounts should never allow "
                    "dialog logon in production."
                ),
                references=["SAP Note 2175909"],
            )

    def check_excessive_roles(self):
        """Flag users with an excessive number of role assignments."""
        max_roles = self.get_config("max_roles_per_user", 30)
        role_counts: Dict[str, int] = {}

        for row in self._rows("user_roles"):
            uname = self._field(row, "UNAME", "BNAME", "USERNAME")
            # A role assignment naming no user cannot be attributed to one, and
            # bucketing them all under "" would invent a user holding N roles.
            if not uname:
                continue
            role_counts[uname] = role_counts.get(uname, 0) + 1

        excessive = [
            f"{uname} ({count} roles)"
            for uname, count in role_counts.items()
            if count > max_roles
        ]

        if excessive:
            self.finding(
                check_id="USR-005",
                title=f"Users with excessive role assignments (>{max_roles})",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(excessive)} user(s) have more than {max_roles} roles assigned. "
                    "Excessive roles often indicate role explosion or inadequate RBAC design."
                ),
                affected_items=excessive,
                # One finding summarising every over-provisioned user. The role COUNT is
                # deliberately not a qualifier: it moves every time somebody gains or
                # loses a role, which would churn the graph node without the defect
                # changing.
                affected_objects=self._objects(
                    ("user", uname) for uname, count in role_counts.items()
                    if count > max_roles
                ),
                scope="aggregate",
                remediation=(
                    "Review role assignments for consolidation opportunities. "
                    "Use composite/derived roles to reduce direct assignments. "
                    "Conduct a role mining exercise."
                ),
                references=["CIS SAP Benchmark Section 2.4"],
            )

    def check_critical_auth_objects(self):
        """Check for users with dangerous authorization object values."""
        findings_map = {}
        users_map = {}
        for row in self._rows("auth_objects"):
            obj = self._field(row, "OBJECT", "AUTH_OBJECT").upper()
            uname = self._field(row, "UNAME", "BNAME", "USERNAME")
            field_val = self._field(row, "VALUE", "AUTH_VALUE")

            if obj in self.CRITICAL_AUTH_OBJECTS:
                # Flag wildcard or full-access values
                if field_val in ("*", "&NC&"):
                    key = obj
                    if key not in findings_map:
                        findings_map[key] = []
                        users_map[key] = []
                    findings_map[key].append(
                        f"{uname} → {obj} = {field_val}"
                    )
                    users_map[key].append(uname)

        for obj, affected in findings_map.items():
            self.finding(
                check_id="USR-006",
                title=f"Users with wildcard access on {obj}",
                severity=self.SEVERITY_HIGH,
                category="User & Authorization",
                description=(
                    f"{len(affected)} user(s) have unrestricted (wildcard) values for "
                    f"authorization object {obj}: {self.CRITICAL_AUTH_OBJECTS[obj]}."
                ),
                affected_items=affected,
                # One finding PER authorization object, naming every user that holds it
                # wide open: the defect is "S_DEVELOP is granted with a wildcard here",
                # and the user list is context that moves as people join and leave. So
                # the auth object is the SUBJECT and carries identity, while the users
                # ride along as members and as graph nodes. No qualifier on the subject:
                # this finding rolls up both offending values ("*" and "&NC&") for the
                # object, so pinning one of them would misdescribe it.
                subject=[{"type": "auth_object", "name": obj}],
                affected_objects=(
                    [{"type": "auth_object", "name": obj}]
                    + self._objects(("user", u) for u in users_map.get(obj, []))
                ),
                scope="object",
                remediation=(
                    f"Restrict {obj} field values to specific required entries. "
                    "Remove wildcard (*) authorizations and replace with "
                    "least-privilege values."
                ),
                references=["SAP Note 2077067", "CIS SAP Benchmark Section 3"],
            )

    def check_never_logged_in(self):
        """Flag active accounts that have never logged in."""
        never_logged = []
        never_logged_objs = []
        for row in self._rows("users"):
            uname = self._field(row, "BNAME", "USERNAME")
            last_logon = self._field(row, "TRDAT", "LAST_LOGON")
            created = self._field(row, "ERDAT", "CREATED_DATE")

            if self._is_unlocked(row) and not last_logon:
                never_logged.append(f"{uname} (created: {created or 'unknown'})")
                never_logged_objs.append(("user", uname))

        if never_logged:
            self.finding(
                check_id="USR-007",
                title="Active accounts that have never logged in",
                severity=self.SEVERITY_LOW,
                category="User & Authorization",
                description=(
                    f"{len(never_logged)} unlocked account(s) have no recorded logon. "
                    "These may be orphaned provisioning artifacts or pre-staged accounts."
                ),
                affected_items=never_logged,
                # Same shape as USR-003: N never-used accounts rolled into ONE finding,
                # so identity stays on the check and deleting one account does not
                # re-raise the finding for the rest.
                affected_objects=self._objects(never_logged_objs),
                scope="aggregate",
                remediation=(
                    "Verify account necessity with business owners. "
                    "Lock or delete unused accounts."
                ),
                references=["CIS SAP Benchmark Section 2.5"],
            )

    def check_password_not_changed(self):
        """Flag users who haven't changed password in 180+ days."""
        max_age = self.get_config("max_password_age_days", 180)
        stale = []
        stale_objs = []

        for row in self._rows("users"):
            uname = self._field(row, "BNAME", "USERNAME")
            pw_date = self._field(row, "PWDCHGDATE", "PASSWORD_CHANGE_DATE")
            user_type = self._field(row, "USTYP", "USER_TYPE", default="A")

            if not self._is_unlocked(row):
                continue
            # Only check dialog users
            if str(user_type).upper() not in ("A", "DIALOG", ""):
                continue

            if pw_date:
                for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"):
                    try:
                        pw_changed = datetime.strptime(pw_date, fmt)
                        days_old = (datetime.now() - pw_changed).days
                        if days_old > max_age:
                            stale.append(f"{uname} (password age: {days_old}d)")
                            stale_objs.append(("user", uname))
                        break
                    except ValueError:
                        continue

        if stale:
            self.finding(
                check_id="USR-008",
                title=f"Dialog users with stale passwords (>{max_age} days)",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(stale)} dialog user(s) have not changed their password in "
                    f"over {max_age} days."
                ),
                affected_items=stale,
                # One finding covering every dialog user with an over-age password. The
                # age in days is deliberately not a qualifier — it advances every single
                # run, so it would re-key the node daily.
                affected_objects=self._objects(stale_objs),
                scope="aggregate",
                remediation=(
                    "Enforce password rotation via profile parameter "
                    "login/password_max_idle_initial and login/password_expiration_time. "
                    "Consider SSO/certificate-based auth to reduce password dependency."
                ),
                references=["SAP Note 1731549", "CIS SAP Benchmark Section 2.8"],
            )
