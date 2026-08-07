"""
SNC posture against the ECS mandatory baseline
==============================================
The ``snc/*`` and ``igs/snc/*`` parameters SAP Note 3250501 governs — 18 of them in
revision 46 — read as ONE family rather than as eighteen independent comparisons.

WHY THE VALUES ARE NOT IN THIS FILE
-----------------------------------
Every compliant value is read at runtime from ``data/ecs_hardening_3250501.json``,
the extract of the note itself. Nothing here hand-types a value. A transcription
slip in a hardening baseline does not announce itself — it tells a customer their
system is compliant when it is not — and this repository has already shipped one
(``login/min_password_lng >= 8`` where the note mandates ``>= 15``). This module
therefore supplies only what the note cannot: our severity, our category, our
description and our remediation wording. The note supplies the facts, joined by
parameter name. ``tests/test_snc_posture.py`` fails if either side gains or loses a
parameter the other does not have.

SAP's own prose is copyright and is not reproduced. The descriptions below are ours.

THE FALSE POSITIVE THIS MODULE EXISTS TO AVOID
----------------------------------------------
Several values SAP MANDATES for ECS look insecure when read as English::

    snc/accept_insecure_gui  = 1     <- the ECS standard
    snc/accept_insecure_rfc  = 1     <- the ECS standard
    snc/only_encrypted_rfc   = 0     <- the ECS standard

A check that reasons "insecure-sounding name means finding" flags SAP's own baseline
on every ECS system in existence. THE COMPLIANT VALUE IS WHATEVER THE JSON SAYS, and
never what the parameter name suggests. The note also permits explicit exceptions
(``snc/only_encrypted_rfc`` may be 1, 2 or 3); a system sitting on one of those is
COMPLIANT and must produce no finding. The note records that enforcing SNC for RFC
is not generally available in ECS, so the hardened values are exceptions the note
permits — not the target we should be steering customers towards.

WHY THE FAMILY IS READ TOGETHER
-------------------------------
  * ``snc/enable = 0`` makes every ``accept_insecure_*`` and ``only_encrypted_*``
    setting moot. Reporting ten findings on a system with SNC switched off is ten
    findings where the truth is one, and the nine extra ones bury the one that is
    actionable.
  * ``min > max`` is incoherent whatever either value is on its own, so it is
    checked as a relation and not as two comparisons.
  * ``igs/snc/name`` has to agree with ``snc/identity/as``, and ``igs/snc/library``
    with ``snc/gssapi_lib``. A mismatch is a defect that neither parameter shows
    when it is looked at alone.
  * The ``accept_insecure_*`` and ``only_encrypted_*`` families describe the same
    posture from two directions and are reported as one verdict.

WHAT THIS MODULE CANNOT SEE, AND SAYS SO
----------------------------------------
``snc/identity/as`` has to match the subject of the SNC server certificate. A
profile-parameter export does not contain the certificate, so we can check the FORM
of the identity and its agreement with ``igs/snc/name``, and nothing more. Every
finding carries that caveat in ``details["unverifiable_from_export"]`` rather than
this module guessing at a certificate it has never seen.

The note's mandated values for the identity and the crypto library are TEMPLATES —
``p:<SID>_<CID>_SNCS.FQDN`` and ``$(DIR_LIBRARY)$(DIR_SEP)$(FT_DLL_PREFIX)sapcrypto
$(FT_DLL)``. A real system reports the substituted or macro-expanded form, so
comparing those four parameters literally would flag every system alive. They are
matched structurally instead, against the invariant part of the template as read
from the JSON.

OVERLAP TO RESOLVE WHEN THIS IS WIRED
-------------------------------------
``modules/crypto_posture.py`` already emits ``CRYPTO-SNC-001`` ("SNC is disabled")
and ``CRYPTO-SNC-002`` (QoP authentication-only) from the same export. Ours is the
ECS-baseline reading of the same switch and carries the moot-family reasoning, so
running both modules would report the same defect twice. Whoever wires this should
retire the ``check_snc_configuration`` branch in that module or gate one on the
other; this module deliberately does not silence itself, because dropping the ECS
verdict is the worse of the two failures.

Data source:
  - security_params.csv -> RSPARAM / RZ11 profile parameter export (NAME, VALUE)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.base_auditor import BaseAuditor

#: The extract of SAP Note 3250501. Facts only — SAP's descriptive prose is not in it.
BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "ecs_hardening_3250501.json"

#: The parameter families this module owns. Everything else in the note belongs to
#: another module, and the split is by prefix so a future revision of the note that
#: adds an snc parameter lands here automatically — the cross-check test then fails
#: until somebody writes our wording for it, which is the intended conversation.
SNC_PREFIXES = ("snc/", "igs/snc/")

# --------------------------------------------------------------------------- #
#  How each parameter is judged                                               #
# --------------------------------------------------------------------------- #
#: The switch. Its state decides whether the rest of the family means anything.
GROUP_SWITCH = "switch"
#: Which connections are accepted, and whether unprotected traffic is possible.
GROUP_ACCEPTANCE = "acceptance"
#: The protection level negotiated once a connection IS protected.
GROUP_PROTECTION_LEVEL = "protection_level"
#: Who this server says it is, on the ABAP stack and on the IGS.
GROUP_IDENTITY = "identity"
#: Which GSS-API library implements SNC.
GROUP_LIBRARY = "library"

GROUPS = (GROUP_SWITCH, GROUP_ACCEPTANCE, GROUP_PROTECTION_LEVEL,
          GROUP_IDENTITY, GROUP_LIBRARY)

#: parameter name -> our own words for what it governs, and which verdict it feeds.
#:
#: `role` is deliberately a description of the SETTING, never of what a particular
#: value means: the note's own values are the authority on that, and prose asserting
#: "1 means insecure" is how a mandated value ends up reported as a defect.
PARAM_META: Dict[str, Dict[str, str]] = {
    "snc/enable": {
        "group": GROUP_SWITCH,
        "role": "the master switch for Secure Network Communications on this server",
    },
    "snc/accept_insecure_gui": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether SAP GUI connections that carry no SNC protection are accepted",
    },
    "snc/accept_insecure_rfc": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether RFC connections that carry no SNC protection are accepted",
    },
    "snc/accept_insecure_cpic": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether CPIC connections that carry no SNC protection are accepted",
    },
    "snc/accept_insecure_r3int_rfc": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether internal RFC between the application servers of this system "
                "is accepted without SNC protection",
    },
    "snc/r3int_rfc_secure": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether internal RFC between the application servers of this system "
                "is opened with SNC",
    },
    "snc/only_encrypted_rfc": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether RFC connections are required to be encrypted",
    },
    "snc/only_encrypted_gui": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether SAP GUI connections are required to be encrypted",
    },
    "snc/permit_insecure_start": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether external programs may be started over a connection that is "
                "not SNC-protected",
    },
    "snc/force_login_screen": {
        "group": GROUP_ACCEPTANCE,
        "role": "whether a logon screen is presented even when an SNC identity is "
                "available for single sign-on",
    },
    "snc/data_protection/min": {
        "group": GROUP_PROTECTION_LEVEL,
        "role": "the lowest protection level this server will accept",
    },
    "snc/data_protection/max": {
        "group": GROUP_PROTECTION_LEVEL,
        "role": "the highest protection level this server will negotiate",
    },
    "snc/data_protection/use": {
        "group": GROUP_PROTECTION_LEVEL,
        "role": "the protection level this server applies by default",
    },
    "snc/r3int_rfc_qop": {
        "group": GROUP_PROTECTION_LEVEL,
        "role": "the protection level used for internal RFC between the application "
                "servers of this system",
    },
    "snc/identity/as": {
        "group": GROUP_IDENTITY,
        "role": "the SNC name this application server presents",
    },
    "igs/snc/name": {
        "group": GROUP_IDENTITY,
        "role": "the SNC name the Internet Graphics Service presents",
    },
    "snc/gssapi_lib": {
        "group": GROUP_LIBRARY,
        "role": "the GSS-API library that implements SNC for this server",
    },
    "igs/snc/library": {
        "group": GROUP_LIBRARY,
        "role": "the GSS-API library the Internet Graphics Service uses for SNC",
    },
}

# --------------------------------------------------------------------------- #
#  Per-parameter verdicts                                                     #
# --------------------------------------------------------------------------- #
STATUS_ECS = "ecs_standard"           # exactly the value the note mandates
STATUS_EXCEPTION = "permitted_exception"   # one of the alternatives the note permits
STATUS_DEVIATION = "deviation"        # neither of the above
STATUS_UNSET = "set_to_empty"         # present in the export with no value
STATUS_ABSENT = "not_in_export"       # we did not see it; that is not the same as wrong
STATUS_INDETERMINATE = "indeterminate"  # the permitted set is a range we cannot evaluate

#: A `security_params` export spells booleans several ways. Folding them here means
#: `snc/enable = TRUE` reads as the mandated `1` instead of as a deviation — a
#: reporting slip, not a misconfiguration. Only these exact spellings fold: "U" is a
#: real SNC value and must survive untouched.
_BOOLEAN_SPELLINGS = {"true": "1", "yes": "1", "on": "1", "x": "1",
                      "false": "0", "no": "0", "off": "0"}

#: An `allowed` entry that is a range rather than a value — ">=15", "<=7 not 0",
#: "30 to 90". None of the snc family uses one today, and if a future revision of the
#: note introduces one we must report "we cannot evaluate this" rather than treat a
#: perfectly permitted value as a deviation.
_RANGE_TOKENS = ("<", ">", " to ", "not ")


def load_ecs_baseline(path: Optional[str] = None) -> Dict[str, Any]:
    """The note extract, whole. ``{}`` when it cannot be read.

    A missing or unreadable baseline means we have nothing to judge against, and the
    auditor then reports nothing at all. Guessing the mandated values from memory is
    exactly the failure this module is built to prevent.
    """
    p = Path(path) if path else BASELINE_PATH
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def snc_family(baseline: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """``{parameter: {"ecs": ..., "allowed": [...]}}`` for the snc families only."""
    params = (baseline or {}).get("parameters")
    if not isinstance(params, dict):
        return {}
    return {name: spec for name, spec in params.items()
            if isinstance(name, str) and isinstance(spec, dict)
            and name.lower().startswith(SNC_PREFIXES)}


# --------------------------------------------------------------------------- #
#  Value handling                                                             #
# --------------------------------------------------------------------------- #

def _canon(value: Any) -> str:
    v = str(value if value is not None else "").strip()
    return _BOOLEAN_SPELLINGS.get(v.lower(), v)


def _as_int(value: str) -> Optional[int]:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def _same(a: Any, b: Any) -> bool:
    """Equal as a profile parameter value: numerically when both are numbers."""
    ca, cb = _canon(a), _canon(b)
    ia, ib = _as_int(ca), _as_int(cb)
    if ia is not None and ib is not None:
        return ia == ib
    return ca.casefold() == cb.casefold()


def _is_range_expression(allowed_entry: Any) -> bool:
    text = str(allowed_entry or "").lower()
    return any(token in text for token in _RANGE_TOKENS)


def _is_templated(mandated: Any) -> bool:
    """Does the note's value contain a placeholder or a profile macro?

    Read from the JSON rather than from a hand-kept list of parameter names, so a
    revision that replaces a template with a concrete value is compared literally
    from then on without anybody having to notice.
    """
    text = str(mandated or "")
    return "$(" in text or ("<" in text and ">" in text)


def _template_prefix(mandated: str) -> str:
    """The fixed head of a placeholder template: ``p:<SID>_...`` -> ``p:``."""
    return str(mandated or "").split("<", 1)[0].strip()


def _template_fragments(mandated: str) -> List[str]:
    """The literal pieces of a macro template — the part macro expansion cannot change.

    ``$(DIR_LIBRARY)$(DIR_SEP)$(FT_DLL_PREFIX)sapcrypto$(FT_DLL)`` -> ``["sapcrypto"]``.
    That fragment is what a resolved path still has to contain, and deriving it beats
    hand-typing the library name for the same reason every other value here is read
    from the JSON.
    """
    return [piece.strip() for piece in re.split(r"\$\([^)]*\)", str(mandated or ""))
            if piece.strip()]


class SncPostureAuditor(BaseAuditor):
    """One verdict on the SNC family, against SAP Note 3250501's ECS baseline."""

    CATEGORY = "Cryptographic Posture"

    #: Said in the details of every finding this module emits. A parameter export
    #: cannot show a certificate, and the honest move is to name the gap on every
    #: occasion we speak about SNC rather than to infer a subject we cannot see.
    UNVERIFIABLE = (
        "snc/identity/as has to match the subject of this server's SNC certificate. "
        "A profile-parameter export does not contain the certificate, so the form of "
        "the identity and its agreement with igs/snc/name are all that was checked "
        "here; compare it against the system PSE in STRUST."
    )

    def __init__(self, data: Dict[str, Any], baseline_overrides: Dict = None,
                 run_context: Dict[str, Any] = None):
        super().__init__(data, baseline_overrides, run_context)
        # The orchestrator may hand us an already-loaded extract; tests use the same
        # seam to feed a deliberately odd baseline without writing to data/.
        supplied = self.overrides.get("ecs_baseline")
        self._baseline: Dict[str, Any] = (supplied if isinstance(supplied, dict)
                                          else load_ecs_baseline())
        self._spec = snc_family(self._baseline)
        self._exported = self._param_lookup()
        self._verdicts: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    #  Input                                                             #
    # ------------------------------------------------------------------ #

    def _param_lookup(self) -> Dict[str, str]:
        """Lowercased parameter name -> value, from whatever the export calls them.

        Rows that are not dicts, or that carry no name, are skipped rather than
        raising: a hand-edited CSV is a normal input here, not an exceptional one.
        """
        rows = self.data.get("security_params")
        if not isinstance(rows, list):
            return {}
        out: Dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = ""
            for key in ("NAME", "PARAMETER", "PARAM_NAME", "name", "parameter"):
                candidate = row.get(key)
                if candidate:
                    name = str(candidate).strip().lower()
                    break
            if not name:
                continue
            value = ""
            for key in ("VALUE", "PARAM_VALUE", "CURRENT_VALUE", "value"):
                if key in row and row.get(key) is not None:
                    value = str(row.get(key))
                    break
            out[name] = value
        return out

    def _value(self, name: str) -> Optional[str]:
        return self._exported.get(name.lower())

    # ------------------------------------------------------------------ #
    #  Judging one parameter                                             #
    # ------------------------------------------------------------------ #

    def _evaluate(self, name: str) -> Dict[str, Any]:
        spec = self._spec.get(name) or {}
        mandated = spec.get("ecs", "")
        allowed = [a for a in (spec.get("allowed") or []) if a is not None]
        raw = self._value(name)
        verdict: Dict[str, Any] = {
            "name": name,
            "value": raw,
            "ecs": mandated,
            "allowed": [str(a) for a in allowed],
            "group": (PARAM_META.get(name) or {}).get("group", ""),
            "role": (PARAM_META.get(name) or {}).get("role", ""),
            "reason": "",
        }
        if raw is None:
            verdict["status"] = STATUS_ABSENT
            return verdict

        value = _canon(raw)
        if _is_templated(mandated):
            verdict.update(self._evaluate_templated(value, str(mandated)))
            return verdict

        if not value and str(mandated).strip():
            verdict["status"] = STATUS_UNSET
            verdict["reason"] = "the parameter is present in the export with no value"
            return verdict
        if _same(value, mandated):
            verdict["status"] = STATUS_ECS
            return verdict
        for entry in allowed:
            if _is_range_expression(entry):
                continue
            if _same(value, entry):
                verdict["status"] = STATUS_EXCEPTION
                return verdict
        if any(_is_range_expression(entry) for entry in allowed):
            # The note permits a RANGE here and we have no evaluator for it. Reporting
            # a deviation would be a guess against a value SAP may well permit, so we
            # decline to answer and record that we did.
            verdict["status"] = STATUS_INDETERMINATE
            verdict["reason"] = ("the exceptions the note permits are expressed as a "
                                 "range this module does not evaluate")
            return verdict
        verdict["status"] = STATUS_DEVIATION
        return verdict

    def _evaluate_templated(self, value: str, mandated: str) -> Dict[str, Any]:
        """Structural comparison for the values the note gives as a template.

        A literal comparison against a template would flag every system alive, so the
        only thing compared is the part of the template that substitution and macro
        expansion cannot change — and that part is derived from the JSON.
        """
        if not value:
            return {"status": STATUS_UNSET,
                    "reason": "the parameter is present in the export with no value"}

        if "<" in mandated and ">" in mandated:
            prefix = _template_prefix(mandated)
            if "<" in value and ">" in value:
                return {"status": STATUS_DEVIATION,
                        "reason": "the placeholder from the note's template is still "
                                  "in the value, so it was never substituted for "
                                  "this system"}
            if prefix and not value.lower().startswith(prefix.lower()):
                return {"status": STATUS_DEVIATION,
                        "reason": f"the mandated form begins with '{prefix}' and this "
                                  f"value does not"}
            return {"status": STATUS_ECS}

        # A macro template: the profile may still show the macros, or the export may
        # show the expanded path. Either is fine as long as it names the same library.
        if _same(value, mandated):
            return {"status": STATUS_ECS}
        fragments = _template_fragments(mandated)
        if fragments and all(f.lower() in value.lower() for f in fragments):
            return {"status": STATUS_ECS}
        reason = ("the value does not name " + ", ".join(fragments) if fragments
                  else "the value does not match the value the note mandates")
        return {"status": STATUS_DEVIATION, "reason": reason}

    # ------------------------------------------------------------------ #
    #  Family state                                                      #
    # ------------------------------------------------------------------ #

    def _snc_state(self) -> str:
        """``on`` / ``off`` / ``unreadable`` / ``not_exported``.

        ``unreadable`` and ``not_exported`` are kept apart on purpose. A value we do
        not recognise is something to report; a parameter that is simply not in the
        export is something we do not know, and reporting "SNC is disabled" from an
        incomplete export would be a fabrication.

        The 1/0 here is the kernel's meaning of the switch, not the baseline's
        opinion of it: whether that state is COMPLIANT is decided by `_evaluate`
        against the note, and the two questions are deliberately kept apart.
        """
        raw = self._value("snc/enable")
        if raw is None:
            return "not_exported"
        value = _canon(raw)
        if value == "1":
            return "on"
        if value == "0":
            return "off"
        return "unreadable"

    def _members(self, *groups: str) -> List[str]:
        return [name for name in self._spec
                if (PARAM_META.get(name) or {}).get("group") in groups]

    def _deviating(self, *groups: str) -> List[Dict[str, Any]]:
        return [v for name, v in self._verdicts.items()
                if v["group"] in groups
                and v["status"] in (STATUS_DEVIATION, STATUS_UNSET)]

    def _numeric(self, name: str) -> Optional[int]:
        raw = self._value(name)
        return None if raw is None else _as_int(_canon(raw))

    # ------------------------------------------------------------------ #
    #  Shared finding furniture                                          #
    # ------------------------------------------------------------------ #

    def _source(self) -> Dict[str, Any]:
        """The extract's provenance block, or ``{}``.

        A truthy non-dict — an extract whose ``source`` is a bare version string —
        used to reach ``.get`` and take the whole scan down with an AttributeError.
        The orchestrator may hand us the extract, so a malformed one has to degrade
        to "we do not know the revision", never to a crash.
        """
        source = self._baseline.get("source") if isinstance(self._baseline, dict) else None
        return source if isinstance(source, dict) else {}

    def _reference(self) -> str:
        version = self._source().get("version")
        tail = ("mandatory hardening baseline for AS ABAP in SAP Enterprise Cloud "
                "Services")
        return (f"SAP Note 3250501 v{version} — {tail}" if version
                else f"SAP Note 3250501 — {tail}")

    def _details(self, **extra: Any) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "baseline_note": "3250501",
            "baseline_version": self._source().get("version"),
            "snc_enable": self._value("snc/enable"),
            "unverifiable_from_export": self.UNVERIFIABLE,
        }
        details.update(extra)
        return details

    @staticmethod
    def _item(verdict: Dict[str, Any]) -> str:
        permitted = ("; also permitted: " + ", ".join(verdict["allowed"])
                     if verdict["allowed"] else "")
        tail = f" — {verdict['reason']}" if verdict.get("reason") else ""
        return (f"{verdict['name']} = {verdict['value']!r} "
                f"(ECS standard: {verdict['ecs']}{permitted}){tail}")

    @staticmethod
    def _hold(verdicts: List[Dict[str, Any]]) -> str:
        """Agreement, so a one-parameter finding does not read as broken English."""
        return ("holds a value that is" if len(verdicts) == 1
                else "hold values that are")

    @staticmethod
    def _objects(verdicts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        # No qualifier anywhere in this module: every check fires over a SET of
        # unacceptable values rather than one, so pinning the exported value into
        # identity would retire the finding and raise a fresh one — age reset — on a
        # change from one wrong value to another.
        return [{"type": "parameter_name", "name": v["name"]} for v in verdicts]

    @staticmethod
    def _switch_caveat(state: str) -> str:
        """Say when SNC being in force is an assumption rather than a reading.

        `not_exported` is not `off` and it is not `on` either. A finding that opens
        "SNC is enabled" on an export that never contained snc/enable asserts the one
        thing this module is careful never to assume, so the claim is dropped and the
        gap is stated instead.
        """
        return ("" if state == "on" else
                " snc/enable is not in this export, so whether SNC is in force could "
                "not be confirmed.")

    @staticmethod
    def _ecs_reminder() -> str:
        return ("Several values in this family are mandated by SAP in a form that "
                "reads as insecure — accepting unprotected SAP GUI and RFC "
                "connections is the ECS standard — so only values outside the set "
                "the note allows are reported here. A value outside that set is not "
                "automatically the weaker one either: enforcing SNC for RFC is not "
                "generally available in ECS, so a hardened value can break access "
                "that SAP operates. Confirm any value listed with SAP before "
                "changing or keeping it.")

    def _remediation(self, verdicts: List[Dict[str, Any]]) -> str:
        wanted = "; ".join(f"{v['name']} = {v['ecs']}" for v in verdicts)
        return (
            f"Restore the mandated values — {wanted} — or one of the exceptions the "
            "note permits for that parameter. Profile parameters in an ECS/RISE "
            "tenant are executed by SAP, so raise a ticket rather than editing the "
            "profile; confirm the running value in RZ11 afterwards, since a profile "
            "change only takes effect once the instance is restarted."
        )

    # ------------------------------------------------------------------ #
    #  Entry point                                                       #
    # ------------------------------------------------------------------ #

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self._spec:
            # No baseline extract, so no mandated values. Nothing can be judged and
            # nothing is claimed.
            return self.findings
        if not self._exported:
            return self.findings

        self._verdicts = {name: self._evaluate(name) for name in self._spec}
        if all(v["status"] == STATUS_ABSENT for v in self._verdicts.values()):
            self.check_family_not_assessable(
                "The profile-parameter export contains no snc/* or igs/snc/* "
                f"parameter, so none of the {len(self._spec)} SNC settings SAP Note "
                "3250501 mandates for ECS could be checked.")
            return self.findings

        state = self._snc_state()
        if state in ("off", "unreadable"):
            switch = self._verdicts.get("snc/enable") or {}
            if switch.get("status") in (STATUS_ECS, STATUS_EXCEPTION):
                # The switch holds a value the note itself mandates or permits. The
                # rest of the family is moot, and there is nothing to report: the
                # compliant value is whatever the note says, never what the parameter
                # name suggests. Today the note mandates 1, so this branch is
                # unreachable — it is here so a future revision cannot turn this
                # module into the thing it was written to prevent.
                return self.findings
            # ONE finding. Everything else in the family is a consequence of this.
            self.check_snc_switched_off(state)
            return self.findings

        self.check_acceptance_posture(state)
        # The protection-level triple is ONE subject: a value can be both outside the
        # mandate and in contradiction with its neighbours, and that is one defect
        # with one fix, not two findings. The contradiction is therefore folded into
        # the deviation finding when there is one, and stands alone only when every
        # value is individually permitted and they still disagree.
        contradictions, involved = self._level_contradictions()
        if not self.check_protection_level(state, contradictions):
            self.check_protection_level_coherence(contradictions, involved)
        self.check_identity_consistency(state)
        self.check_crypto_library(state)

        if not self.findings and state == "not_exported":
            # Silence would be read as "SNC is fine". It is not: without the switch
            # we do not know whether any of the settings we DID read are in force,
            # and saying so is the difference between a clean result and an
            # unexamined one.
            exported = sum(1 for v in self._verdicts.values()
                           if v["status"] != STATUS_ABSENT)
            self.check_family_not_assessable(
                "snc/enable is not in the profile-parameter export, so whether SNC "
                f"is in force could not be established. No deviation was found among "
                f"the {exported} snc/* parameter(s) that were exported, but none of "
                "them takes effect unless SNC is switched on.")
        return self.findings

    # ------------------------------------------------------------------ #
    #  The checks                                                        #
    # ------------------------------------------------------------------ #

    def check_family_not_assessable(self, reason: str):
        """The export did not carry enough of the family to reach a verdict.

        Two ways in — no snc parameter at all, or every one of them except the switch
        that decides whether any of them applies — and one check, because they are the
        same defect in the evidence and take the same fix: export the family.

        Reported at INFO because it is a gap in the evidence and not a defect in the
        system — and reported at all because "no SNC findings" otherwise reads as
        "SNC is fine", which is the misunderstanding that costs the customer.
        """
        self.finding(
            check_id="CRYPTO-SNCECS-000",
            title="SNC posture could not be assessed from this export",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                reason + " This is a gap in the evidence, not a verdict on the "
                "system: the SNC posture may be correct, incorrect or absent and "
                "this scan cannot tell."
            ),
            remediation=(
                "Re-export the profile parameters without a name filter — report "
                "RSPARAM lists every parameter with its running value — so the SNC "
                "family is included, then re-run the scan."
            ),
            references=[self._reference()],
            details=self._details(expected_parameters=sorted(self._spec)),
            # A coverage gap names no defective object: there is no parameter to
            # point at, and inventing one would put a node in the attack-path graph
            # that the data never contained.
            scope="aggregate",
        )

    def check_snc_switched_off(self, state: str):
        """The single truth on a system where SNC is not running.

        Every accept_insecure_*, only_encrypted_*, protection-level, identity and
        library setting depends on this switch. Reporting them alongside it would
        turn one actionable finding into ten, nine of which cannot be acted on until
        the first is fixed.
        """
        raw = self._value("snc/enable")
        mandated = self._spec.get("snc/enable", {}).get("ecs")
        moot = [self._item(v) for v in self._verdicts.values()
                if v["group"] != GROUP_SWITCH
                and v["status"] in (STATUS_DEVIATION, STATUS_UNSET)]
        if state == "off":
            opening = (f"snc/enable = {raw!r}. SAP Note 3250501 mandates "
                       f"{mandated} for AS ABAP in ECS.")
            consequence = ("With the switch off, SAP GUI, RFC and internal RFC "
                           "traffic reaches this system without SNC protection "
                           "whatever the rest of the family is set to.")
        else:
            opening = (f"snc/enable = {raw!r}, which is neither the mandated "
                       f"{mandated} nor a value this "
                       "module recognises as disabled.")
            consequence = ("SNC therefore cannot be assumed to be in force, and the "
                           "rest of the family cannot be assessed until the switch "
                           "reads a value that can be interpreted.")
        tail = (f" {len(moot)} other snc/* parameter(s) also deviate from the "
                "baseline; they are listed in this finding's details rather than "
                "raised separately, because none of them can take effect while the "
                "switch is in this state."
                if moot else
                " No other snc/* deviation was found, though none of those settings "
                "can take effect in this state either.")

        self.finding(
            check_id="CRYPTO-SNCECS-001",
            title="SNC is not enabled, so the mandated ECS SNC baseline is not in force",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=opening + " " + consequence + tail,
            affected_items=[f"snc/enable = {raw}"],
            affected_objects=[{"type": "parameter_name", "name": "snc/enable"}],
            # One parameter, one defect, and the moot family stays out of identity so
            # that fixing a dependent setting does not re-raise this finding.
            scope="object",
            remediation=(
                f"Set snc/enable = {mandated} and confirm the SNC identity "
                "and GSS-API library are in place before the instance restarts, so "
                "SNC actually initialises. Profile parameters in an ECS/RISE tenant "
                "are executed by SAP: raise a ticket rather than editing the profile."
            ),
            references=[self._reference()],
            details=self._details(snc_state=state,
                                  suppressed_because_snc_is_off=moot),
        )

    def check_acceptance_posture(self, state: str):
        """The accept_insecure_* / only_encrypted_* family, read as one posture."""
        deviations = self._deviating(GROUP_ACCEPTANCE)
        if not deviations:
            return
        members = self._members(GROUP_ACCEPTANCE)
        uncertainty = ("" if state == "on" else
                       " snc/enable is not in this export, so whether these settings "
                       "are currently in force could not be confirmed.")
        self.finding(
            check_id="CRYPTO-SNCECS-002",
            title="SNC connection-acceptance parameters deviate from the ECS baseline",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(deviations)} of the {len(members)} snc/* parameters that "
                "decide which connections are accepted, and whether unprotected "
                f"traffic remains possible, {self._hold(deviations)} neither the ECS "
                "standard nor an exception SAP Note 3250501 permits. Read together "
                "these parameters are one posture, so they are reported as one "
                f"finding. {self._ecs_reminder()}{uncertainty}"
            ),
            affected_items=[self._item(v) for v in deviations],
            affected_objects=self._objects(deviations),
            # Several independent parameters, one posture. Hardening one of them
            # while another stays outside the permitted set must not retire this
            # finding and re-raise it with its age reset.
            scope="aggregate",
            remediation=self._remediation(deviations),
            references=[self._reference()],
            details=self._details(
                deviations={v["name"]: {"value": v["value"], "ecs": v["ecs"],
                                        "allowed": v["allowed"], "role": v["role"]}
                            for v in deviations},
                family={name: self._verdicts[name]["status"] for name in members},
            ),
        )

    def check_protection_level(self, state: str,
                               contradictions: List[str] = None) -> bool:
        """The negotiated protection level, once a connection IS protected.

        Returns whether it reported, so the caller knows the contradictions have
        already been said and does not say them a second time.
        """
        deviations = self._deviating(GROUP_PROTECTION_LEVEL)
        if not deviations:
            return False
        members = self._members(GROUP_PROTECTION_LEVEL)
        contradictions = contradictions or []

        # SNC protection levels are ordered, and the level the note mandates is the
        # top of that order — the one that encrypts the payload. A level below it
        # still authenticates the peer, so the connection looks protected while the
        # data on it is not encrypted; that is a confidentiality exposure and is
        # severity-relevant. A level ABOVE the mandate, or a non-numeric value, is a
        # deviation we report without claiming it is weaker.
        below: List[str] = []
        for verdict in deviations:
            if verdict["name"] == "snc/r3int_rfc_qop":
                # A different scale from data_protection/*: the note mandates a
                # different value for it, and ordering the two together would be an
                # assumption about the kernel we have not verified.
                continue
            mandated = _as_int(str(verdict["ecs"]))
            actual = _as_int(_canon(verdict["value"]))
            if mandated is not None and actual is not None and actual < mandated:
                below.append(f"{verdict['name']} = {actual}")

        severity = (self.SEVERITY_HIGH if below and state == "on"
                    else self.SEVERITY_MEDIUM)
        exposure = (
            f" {', '.join(below)} sits below the level the note mandates, so "
            "connections that are SNC-protected are authenticated but their payload "
            "is not encrypted."
            if below else "")
        uncertainty = ("" if state == "on" else
                       " snc/enable is not in this export, so whether these levels "
                       "are currently in force could not be confirmed.")
        contradiction_text = (
            " The same values also contradict each other: " + "; ".join(contradictions)
            + ", so the effective protection level cannot be read off the profile at "
              "all." if contradictions else "")
        self.finding(
            check_id="CRYPTO-SNCECS-003",
            title="SNC protection level deviates from the ECS baseline",
            severity=severity,
            category=self.CATEGORY,
            description=(
                f"{len(deviations)} of the {len(members)} snc/* parameters that set "
                "the protection level for SNC-protected connections "
                f"{self._hold(deviations)} neither the ECS standard nor an exception "
                f"SAP Note 3250501 permits.{exposure}{contradiction_text}{uncertainty}"
            ),
            affected_items=[self._item(v) for v in deviations],
            affected_objects=self._objects(deviations),
            scope="aggregate",
            remediation=self._remediation(deviations),
            references=[self._reference()],
            details=self._details(
                below_mandated_level=below,
                contradictions=contradictions,
                family={name: self._verdicts[name]["status"] for name in members},
            ),
        )
        return True

    def _level_contradictions(self) -> Tuple[List[str], List[str]]:
        """min / max / use as a RELATION, which no single-value check can see.

        Both halves can be individually plausible and still contradict each other,
        and a contradiction means the effective level cannot be read off the profile
        at all — which is worse than a value that is simply wrong.

        Returns the problems in words and the parameters they involve. Reporting is
        the caller's decision, because the same values may already be reported as
        deviations and one wrong value must not become two findings.
        """
        low = self._numeric("snc/data_protection/min")
        high = self._numeric("snc/data_protection/max")
        use = self._numeric("snc/data_protection/use")

        problems: List[str] = []
        involved: List[str] = []
        if low is not None and high is not None and low > high:
            problems.append(
                f"snc/data_protection/min = {low} is above "
                f"snc/data_protection/max = {high}, so the lowest level the server "
                "accepts is higher than the highest level it will negotiate")
            involved += ["snc/data_protection/min", "snc/data_protection/max"]
        if use is not None and low is not None and high is not None and low <= high \
                and not (low <= use <= high):
            problems.append(
                f"snc/data_protection/use = {use} lies outside the "
                f"{low}..{high} window the same export declares in "
                "snc/data_protection/min and snc/data_protection/max")
            involved += ["snc/data_protection/use", "snc/data_protection/min",
                         "snc/data_protection/max"]
        ordered = [name for name in ("snc/data_protection/min",
                                     "snc/data_protection/max",
                                     "snc/data_protection/use")
                   if name in involved]
        return problems, ordered

    def check_protection_level_coherence(self, problems: List[str],
                                         ordered: List[str]):
        """The contradiction on its own, when every value is individually permitted.

        Today the note mandates the same level for all three with no exceptions, so a
        contradiction always implies a deviation and this finding does not fire — the
        contradiction is carried by CRYPTO-SNCECS-003 instead. It exists for the case
        where a revision permits a range and two individually-permitted values still
        disagree, which no per-parameter comparison could ever see.
        """
        if not problems:
            return
        low = self._numeric("snc/data_protection/min")
        high = self._numeric("snc/data_protection/max")
        use = self._numeric("snc/data_protection/use")
        self.finding(
            check_id="CRYPTO-SNCECS-004",
            title="SNC protection-level parameters contradict each other",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "; ".join(problems) + ". This is incoherent whatever the individual "
                "values are, so the effective protection level cannot be read off "
                "the profile. Restoring the values SAP Note 3250501 mandates "
                "removes the contradiction as a side effect."
            ),
            affected_items=[f"{name} = {self._value(name)}" for name in ordered],
            affected_objects=[{"type": "parameter_name", "name": name}
                              for name in ordered],
            # The defect is the relation between the parameters, not any one of them.
            scope="aggregate",
            remediation=self._remediation(
                [self._verdicts[name] for name in ordered if name in self._verdicts]),
            references=[self._reference()],
            details=self._details(min=low, max=high, use=use),
        )

    def check_identity_consistency(self, state: str = "on"):
        """snc/identity/as and igs/snc/name: form, and agreement with each other.

        The note gives the mandated identity as a template, so the check is
        structural. What we CANNOT do is confirm the identity against the SNC
        certificate — the export does not carry it — and that limit is stated in the
        finding rather than papered over.
        """
        reasons: List[str] = []
        involved: List[str] = []
        for name in ("snc/identity/as", "igs/snc/name"):
            verdict = self._verdicts.get(name)
            if not verdict or verdict["status"] not in (STATUS_DEVIATION, STATUS_UNSET):
                continue
            reasons.append(
                f"{name} = {verdict['value']!r} — "
                + (verdict["reason"] or "it does not follow the form the note gives"))
            involved.append(name)

        server = _canon(self._value("snc/identity/as") or "")
        igs = _canon(self._value("igs/snc/name") or "")
        # Only compare two concrete values. If either still carries the note's
        # placeholder we have already said so above, and adding "they differ" would
        # report the same defect twice.
        if server and igs and "<" not in server and "<" not in igs \
                and server.casefold() != igs.casefold():
            reasons.append(
                f"igs/snc/name ({igs!r}) is not the same SNC name as "
                f"snc/identity/as ({server!r}), which the note requires it to match")
            involved += ["snc/identity/as", "igs/snc/name"]
        if not reasons:
            return

        ordered = [name for name in ("snc/identity/as", "igs/snc/name")
                   if name in involved]
        self.finding(
            check_id="CRYPTO-SNCECS-005",
            title="SNC identity is not consistent with the ECS baseline",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                ("SNC is enabled, and the SNC name this system presents does not "
                 "hold up: " if state == "on" else
                 "The SNC name this system presents does not hold up: ")
                + "; ".join(reasons) + ". An identity that is unset, still "
                "carries the note's placeholder, or disagrees between the "
                "application server and the IGS will either stop SNC initialising or "
                "make peers fail to authenticate this system."
                + self._switch_caveat(state) + " " + self.UNVERIFIABLE
            ),
            affected_items=[f"{name} = {self._value(name)}" for name in ordered],
            affected_objects=[{"type": "parameter_name", "name": name}
                              for name in ordered],
            scope="aggregate",
            remediation=(
                "Set snc/identity/as to this server's own SNC name — the note's "
                "mandated form is "
                f"{self._spec.get('snc/identity/as', {}).get('ecs')}, with the "
                "system ID, client and fully qualified host substituted — and set "
                "igs/snc/name to the same value. Verify it against the subject of "
                "the SNC certificate in the system PSE (STRUST) before the instance "
                "is restarted. In an ECS/RISE tenant the profile is maintained by "
                "SAP, so raise a ticket."
            ),
            references=[self._reference()],
            details=self._details(
                snc_identity_as=self._value("snc/identity/as"),
                igs_snc_name=self._value("igs/snc/name"),
                mandated_form=self._spec.get("snc/identity/as", {}).get("ecs"),
                reasons=reasons,
            ),
        )

    def check_crypto_library(self, state: str = "on"):
        """snc/gssapi_lib and igs/snc/library: the same library, and the right one.

        The mandated value is a macro template, so a system reporting the expanded
        path is compliant and must not be flagged. Only the invariant fragment of the
        template — read from the JSON, not typed here — has to survive.
        """
        reasons: List[str] = []
        involved: List[str] = []
        for name in ("snc/gssapi_lib", "igs/snc/library"):
            verdict = self._verdicts.get(name)
            if not verdict or verdict["status"] not in (STATUS_DEVIATION, STATUS_UNSET):
                continue
            reasons.append(f"{name} = {verdict['value']!r} — "
                           + (verdict["reason"] or "it is not the mandated library"))
            involved.append(name)

        server = _canon(self._value("snc/gssapi_lib") or "")
        igs = _canon(self._value("igs/snc/library") or "")
        # An unexpanded macro on one side and a resolved path on the other are not
        # comparable as strings, and calling that a mismatch would be a false
        # positive on a perfectly consistent system.
        if server and igs and "$(" not in server and "$(" not in igs \
                and server.casefold() != igs.casefold():
            reasons.append(f"igs/snc/library ({igs!r}) is not the same library as "
                           f"snc/gssapi_lib ({server!r}), which the note requires it "
                           "to match")
            involved += ["snc/gssapi_lib", "igs/snc/library"]
        if not reasons:
            return

        ordered = [name for name in ("snc/gssapi_lib", "igs/snc/library")
                   if name in involved]
        self.finding(
            check_id="CRYPTO-SNCECS-006",
            title="SNC GSS-API library is not the one the ECS baseline mandates",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                ("SNC is enabled, and the library that implements it does not match "
                 "the baseline: " if state == "on" else
                 "The library that implements SNC does not match the baseline: ")
                + "; ".join(reasons) + ". SNC protection is only as "
                "good as the library providing it, and the ABAP stack and the IGS "
                "have to use the same one." + self._switch_caveat(state)
            ),
            affected_items=[f"{name} = {self._value(name)}" for name in ordered],
            affected_objects=[{"type": "parameter_name", "name": name}
                              for name in ordered],
            scope="aggregate",
            remediation=(
                "Point snc/gssapi_lib at the library the note mandates — "
                f"{self._spec.get('snc/gssapi_lib', {}).get('ecs')} — and set "
                "igs/snc/library to the same library. The macro form and the "
                "expanded path are both acceptable as long as they resolve to that "
                "library. In an ECS/RISE tenant the profile is maintained by SAP, so "
                "raise a ticket."
            ),
            references=[self._reference()],
            details=self._details(
                snc_gssapi_lib=self._value("snc/gssapi_lib"),
                igs_snc_library=self._value("igs/snc/library"),
                mandated_form=self._spec.get("snc/gssapi_lib", {}).get("ecs"),
                reasons=reasons,
            ),
        )
