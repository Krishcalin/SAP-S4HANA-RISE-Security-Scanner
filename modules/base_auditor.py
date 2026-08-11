# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Base Auditor Module
===================
Common base class for all audit modules with shared
finding creation and severity utilities.
"""

from typing import Dict, List, Any, Optional
import datetime


class BaseAuditor:
    """Base class for all SAP audit modules."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    def __init__(self, data: Dict[str, Any], baseline_overrides: Dict = None,
                 run_context: Dict[str, Any] = None):
        self.data = data
        self.overrides = baseline_overrides or {}
        #: What else is happening in this run. Currently carries
        #: ``{"modules": {<module keys>}}`` so a module can tell whether a DEEPER
        #: module is also running and defer to it.
        #:
        #: A module must never infer that a sibling ran just because that
        #: sibling's input data is present: `--modules iam` supplies the data
        #: without running `ara`, and deferring on data presence alone silently
        #: drops the capability with nothing anywhere saying so.
        #:
        #: When this is empty the caller did not tell us, and a module should
        #: fall back to its historical behaviour rather than guess.
        self.run_context = run_context or {}
        self.findings: List[Dict[str, Any]] = []

    # ---------------------------------------------------------------- #
    #  Reading a profile-parameter export                               #
    # ---------------------------------------------------------------- #
    #  ONE VOCABULARY, BECAUSE TWO PRODUCED A FALSE POSITIVE ON A COMPLIANT
    #  SYSTEM.
    #
    #  `security_params` read VALUE / PARAM_VALUE / CURRENT_VALUE; its sibling
    #  `baseline_params` read VALUE / PARAM_VALUE / VAL. An export spelling the
    #  column CURRENT_VALUE — which the first module documents as a supported
    #  spelling — was therefore fully readable by one and invisible to the other.
    #
    #  Worse, the second defaulted an unreadable value to "" instead of treating
    #  the row as absent, and `check_protected_webmethods` reads empty as
    #  non-compliant. Measured before the fix:
    #
    #      BaselineParamAuditor({'security_params':
    #          [{'NAME': 'service/protectedwebmethods',
    #            'CURRENT_VALUE': 'SDEFAULT'}]}).run_all_checks()
    #      -> BASELINE-006 HIGH  'service/protectedwebmethods = '
    #
    #  SDEFAULT is the hardened value. That is a HIGH finding raised against a
    #  correctly configured system, built entirely out of a column-spelling
    #  mismatch — and CLAUDE.md's criterion is that a compliant system must be
    #  silent.
    #
    #  The lesson was already learned once, in `security_params`, and written
    #  into its docstring. It simply never crossed the file boundary. So the
    #  implementation lives here now and both modules call it: a shared rule
    #  cannot drift from itself.

    #: Column spellings the various exports use for the parameter name.
    PARAM_NAME_COLUMNS = ("NAME", "PARAMETER", "PARAM_NAME", "PARAM")

    #: …and for its value. CURRENT_VALUE is RSPARAM's running-value spelling.
    PARAM_VALUE_COLUMNS = ("VALUE", "PARAM_VALUE", "CURRENT_VALUE", "VAL")

    #: …and for the SYSTEM DEFAULT, which RSPARAM prints beside the user value.
    #:
    #: THE BEST SOURCE OF A DEFAULT IS THE SYSTEM ITSELF, NOT A DOCUMENT. It was
    #: proposed that this repository carry SAP's documented defaults so that an
    #: unset parameter could be judged. That would have meant importing ~59 SAP
    #: facts, and would have been WRONG more often than it looked: a default
    #: varies by release and by kernel patch, so one recorded value cannot be
    #: right for every system. RSPARAM already prints the actual default for the
    #: system in front of you. Reading it invents nothing and is more accurate
    #: than any table could be.
    PARAM_DEFAULT_COLUMNS = ("DEFAULT_VALUE", "SYSTEM_DEFAULT", "SAP_DEFAULT",
                             "DEFAULT", "KERNEL_DEFAULT")

    #: How a parameter's effective value was arrived at.
    PARAM_SET = "set"                 # explicitly set in a profile
    PARAM_AT_DEFAULT = "kernel_default"   # left unset; the system's own default

    @staticmethod
    def param_lookup(params: Any) -> Dict[str, str]:
        """parameter name (lowercased) -> exported value.

        A ROW IS ONLY JUDGED WHEN IT ACTUALLY CARRIES A VALUE COLUMN. Defaulting a
        missing one to "" reads "this export does not tell us" as "this parameter
        is empty", and empty is a real finding for `gw/sec_info`, `ms/acl_info`
        and `service/admin_users` — so an export using an unrecognised
        value-column spelling would produce a page of confident accusations built
        from nothing. Skipping instead leaves the parameter unverified, which the
        coverage findings state honestly.

        An empty value that IS present stays a real answer: `gw/sec_info` with
        nothing after the comma is the unset ACL, and must keep firing.

        Tolerates a non-list (an int, say): iterating it raised TypeError and took
        the whole scan down with it.
        """
        lookup: Dict[str, str] = {}
        if not isinstance(params, (list, tuple)):
            return lookup
        for row in params:
            if not isinstance(row, dict):
                continue
            name = next((row[c] for c in BaseAuditor.PARAM_NAME_COLUMNS
                         if row.get(c) is not None), "")
            name = str(name or "").strip().lower()
            if not name:
                continue
            value = next((row[c] for c in BaseAuditor.PARAM_VALUE_COLUMNS
                          if row.get(c) is not None), None)
            default = next((row[c] for c in BaseAuditor.PARAM_DEFAULT_COLUMNS
                            if row.get(c) is not None), None)

            # RSPARAM LEAVES THE USER VALUE BLANK WHEN A PARAMETER IS AT ITS
            # KERNEL DEFAULT, and the default sits in its own column. Read as a
            # bare value that is the empty string, which is what happened before
            # this: `login/min_password_lng = ` — a finding whose evidence is
            # wrong, and a false positive outright wherever the default happens
            # to be compliant.
            #
            # The substitution is deliberately narrow: ONLY when a default column
            # is actually present and the user value is blank. With no default
            # column the old behaviour is untouched, which matters because an
            # empty value that is genuinely present IS a real answer — `gw/sec_info`
            # with nothing after the comma is the unset ACL and must keep firing.
            if default is not None and (value is None or not str(value).strip()):
                lookup[name] = str(default)
                continue
            if value is None:
                continue
            lookup[name] = str(value)
        return lookup

    @staticmethod
    def param_provenance(params: Any) -> Dict[str, str]:
        """parameter name -> how its effective value was arrived at.

        Separate from `param_lookup` so that adding this could not change what
        any existing caller receives. A finding that says "6" when the parameter
        is at the kernel default rather than set to 6 is not wrong about the
        value, but it is wrong about the SYSTEM — and the fix differs: one is
        "change it", the other is "set it".
        """
        out: Dict[str, str] = {}
        if not isinstance(params, (list, tuple)):
            return out
        for row in params:
            if not isinstance(row, dict):
                continue
            name = next((row[c] for c in BaseAuditor.PARAM_NAME_COLUMNS
                         if row.get(c) is not None), "")
            name = str(name or "").strip().lower()
            if not name:
                continue
            value = next((row[c] for c in BaseAuditor.PARAM_VALUE_COLUMNS
                          if row.get(c) is not None), None)
            default = next((row[c] for c in BaseAuditor.PARAM_DEFAULT_COLUMNS
                            if row.get(c) is not None), None)
            if default is not None and (value is None or not str(value).strip()):
                out[name] = BaseAuditor.PARAM_AT_DEFAULT
            elif value is not None:
                out[name] = BaseAuditor.PARAM_SET
        return out

    # ---------------------------------------------------------------- #
    #  Is this export the whole thing?                                  #
    # ---------------------------------------------------------------- #
    #  THE QUESTION THAT DECIDES WHETHER ABSENCE MEANS ANYTHING.
    #
    #  A parameter missing from `security_params.csv` has two possible causes and
    #  the file cannot tell them apart:
    #     the setting is not there  ->  a real observation, judgeable
    #     the export did not ask    ->  no information at all
    #  The export guide offers RZ11 — one parameter at a time — as an equal route
    #  to RSPARAM, so the second cause is not hypothetical; it is the documented
    #  workflow. That is why absent parameters are disclosed rather than judged.
    #
    #  `export_completeness.json` is where somebody states which sources are the
    #  COMPLETE list. Where a source is declared complete, absence within it
    #  becomes an observation.
    #
    #  IT IS A DECLARATION AND NOT A PROOF. Nothing verifies it. So this returns
    #  the DECLARATION rather than a bare boolean, callers put it in the finding,
    #  and a wrong declaration is diagnosable from the report instead of merely
    #  producing wrong findings.

    COMPLETENESS_KEY = "_export_completeness"

    def export_completeness(self, source: str) -> Optional[Dict[str, Any]]:
        """The declaration that `source` is complete, or None if none was made.

        None covers both "no declaration file" and "file present, this source not
        listed". They are the same fact for a caller: nobody has said this export
        is the whole thing, so absence within it still means nothing.
        """
        payload = self.data.get(self.COMPLETENESS_KEY)
        if not isinstance(payload, dict):
            return None
        declared = payload.get("complete_sources")
        if not isinstance(declared, list) or source not in declared:
            return None
        return {
            "source": source,
            "declared_by": payload.get("declared_by") or "unstated",
            "declared_at": payload.get("declared_at") or "unstated",
            "method": payload.get("method") or "unstated",
        }

    def absence_is_observable(self, source: str) -> bool:
        """May a caller treat a missing row in `source` as "it is not there"?

        Deliberately a separate, plainly-named predicate rather than a truthiness
        check on the dict above: `if self.export_completeness("x"):` reads as "is
        it complete", and the answer this actually gives is "has anybody said so",
        which is a weaker claim and needs to look like one at the call site.
        """
        return self.export_completeness(source) is not None

    # ---------------------------------------------------------------- #
    #  Release gating                                                   #
    # ---------------------------------------------------------------- #
    #  THREE ANSWERS, AND CONFLATING ANY TWO IS THE DEFECT.
    #
    #  A check that looks for something introduced in a particular release has
    #  three possible relationships to the system in front of it:
    #
    #    APPLIES         the system is new enough — run the check
    #    NOT_APPLICABLE  the system is too old — the thing cannot exist, and a
    #                    finding would be a false positive about a system that is
    #                    correctly configured for what it is
    #    UNKNOWN         no component export was supplied — we do not know
    #
    #  The tempting simplification is to fold UNKNOWN into one of the others.
    #  Both directions are wrong, and wrong silently:
    #
    #    unknown treated as APPLIES        -> a check for a 7.40 parameter fires
    #                                         on a 7.31 system that could never
    #                                         have had it. False findings erode
    #                                         trust in every other finding.
    #    unknown treated as NOT_APPLICABLE -> the check quietly does not run, and
    #                                         a report over a system nobody
    #                                         measured reads exactly like a report
    #                                         over a compliant one.
    #
    #  So UNKNOWN is its own answer, the caller is told which it got, and the
    #  helper below emits a coverage finding rather than returning silence.

    RELEASE_APPLIES = "applies"
    RELEASE_NOT_APPLICABLE = "not_applicable"
    RELEASE_UNKNOWN = "unknown"

    #: The component every ABAP system has. Callers naming nothing else get this.
    DEFAULT_COMPONENT = "SAP_BASIS"

    def _components(self) -> Dict[str, str]:
        """component name -> release, upper-cased, from the CVERS export."""
        rows = self.data.get("system_component")
        if not isinstance(rows, list):
            return {}
        out: Dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = (row.get("COMPONENT") or row.get("component")
                    or row.get("NAME") or "")
            rel = (row.get("RELEASE") or row.get("release")
                   or row.get("VERSION") or "")
            name, rel = str(name).strip().upper(), str(rel).strip()
            if name and rel:
                out[name] = rel
        return out

    @staticmethod
    def _release_key(release: str):
        """Comparable form of an SAP release string.

        SAP writes releases as `750`, `7.50` and occasionally `0750`, and they are
        the same release. Compared as strings, "750" < "8" and "7.31" > "7.4",
        both of which are wrong. Normalising to a tuple of integers is the only
        form in which they order correctly.
        """
        text = str(release).strip()
        if "." in text:
            # "7.50" -> (7, 50) and "7.4" -> (7, 40). The pad matters: without it
            # "7.4" reads as minor 4 and sorts BELOW "7.40" (minor 40), so a gate
            # with a 7.40 floor would decide a 7.4 system does not qualify — for
            # the same release, written the other way.
            major, _, minor = text.partition(".")
            mj = "".join(c for c in major if c.isdigit())
            mn = "".join(c for c in minor if c.isdigit())
            if not mj:
                return None
            return (int(mj), int((mn + "00")[:2]))

        digits = "".join(ch for ch in text if ch.isdigit()).lstrip("0")
        if not digits:
            return None
        # LSTRIP MATTERS. "0750" is how some exports write 750, and slicing the
        # raw string gave (0, 75) — a release that sorts below everything, so
        # every minimum was satisfied and every gated check ran. Caught by
        # test_the_same_release_written_three_ways_compares_equal.
        #
        # `digits[1:]` rather than `digits[1:3]`: S/4HANA year-style releases
        # (2020, 2021) collapse to the same key under a two-character slice.
        return (int(digits[0]), int(digits[1:] or 0))

    def release_gate(self, min_release: Optional[str] = None,
                     max_release: Optional[str] = None,
                     component: Optional[str] = None) -> str:
        """Does a release-dependent check apply here? Returns one of the three.

        `min_release` is inclusive, `max_release` exclusive — so a check for
        something introduced in 7.40 and removed in 7.54 is
        `release_gate("740", "754")`, which reads the way the SAP documentation
        does and avoids the off-by-one that an inclusive upper bound invites.
        """
        component = (component or self.DEFAULT_COMPONENT).upper()
        installed = self._components().get(component)
        if not installed:
            return self.RELEASE_UNKNOWN
        here = self._release_key(installed)
        if here is None:
            return self.RELEASE_UNKNOWN
        if min_release is not None:
            floor = self._release_key(min_release)
            if floor is not None and here < floor:
                return self.RELEASE_NOT_APPLICABLE
        if max_release is not None:
            ceiling = self._release_key(max_release)
            if ceiling is not None and here >= ceiling:
                return self.RELEASE_NOT_APPLICABLE
        return self.RELEASE_APPLIES

    def skip_for_release(self, check_id: str, what: str, category: str,
                         min_release: Optional[str] = None,
                         max_release: Optional[str] = None,
                         component: Optional[str] = None) -> bool:
        """True when the caller should NOT run the check — and says why.

        The whole point is the difference between the two skip reasons:

          * NOT_APPLICABLE is silent. The system genuinely cannot have the thing,
            so there is nothing to report and reporting it would be noise.
          * UNKNOWN emits an INFO finding carrying ``degrades_coverage``, which is
            the flag `--gate` reads to refuse a green build. A check that could
            not determine whether it applied did not examine this system, and the
            report must not imply that it did.

        `category` IS THE CALLER'S OWN CATEGORY, NOT "Coverage". The first draft
        invented a new one and `tests/test_compliance_breadth.py` rejected it —
        correctly, because an unmapped category is silently absent from every
        compliance panel while the panel still looks complete. Taking the calling
        check's category is also the better answer on its merits: an auditor
        reading the Cryptographic Posture panel should see that one crypto check
        could not be evaluated, in that panel, next to the ones that were.

        Usage:

            if self.skip_for_release("PARAM-XYZ", "the XYZ parameter",
                                     "Security Baseline Parameters", "740"):
                return
        """
        verdict = self.release_gate(min_release, max_release, component)
        if verdict == self.RELEASE_APPLIES:
            return False
        if verdict == self.RELEASE_NOT_APPLICABLE:
            return True

        comp = (component or self.DEFAULT_COMPONENT).upper()
        bounds = " and ".join(
            p for p in (f"at least {min_release}" if min_release else "",
                        f"below {max_release}" if max_release else "") if p)
        self.finding(
            check_id=f"{check_id}-COVERAGE",
            title=f"Release could not be determined for: {what}",
            severity=self.SEVERITY_INFO,
            category=category,
            description=(
                f"This check applies only where {comp} is {bounds}, and the export "
                f"contains no component version list, so it could not be decided "
                f"whether it applies here. The check did NOT run. Its silence is "
                f"therefore not evidence that {what} is correctly configured — it "
                f"is evidence that this system was not examined for it."),
            affected_items=[f"{comp} release unknown ({bounds})"],
            remediation=(
                "Export the installed component versions and re-run. The list is "
                "the CVERS table, shown as 'Component version' in SPAM/SAINT and "
                "in System > Status; save it as system_component.csv with "
                "COMPONENT and RELEASE columns."),
            details={"degrades_coverage": True, "component": comp,
                     "min_release": min_release, "max_release": max_release},
            scope="aggregate",
        )
        return True

    def module_is_running(self, module_key: str) -> Optional[bool]:
        """Is `module_key` part of this run? ``None`` when the caller did not say."""
        modules = self.run_context.get("modules")
        if modules is None:
            return None
        return module_key in modules

    def finding(
        self,
        check_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        affected_items: List[str] = None,
        remediation: str = "",
        references: List[str] = None,
        details: Dict = None,
        affected_objects: List[Dict[str, Any]] = None,
        subject: List[Dict[str, Any]] = None,
        scope: str = None,
        system: str = None,
        client: str = None,
    ) -> Dict[str, Any]:
        """Create a standardized finding dict.

        `affected_items` remains the human-readable display list every report renderer
        consumes and is unchanged.

        `affected_objects` is the structured parallel: a list of
        ``{"type", "name", "system"?, "client"?, "qualifier"?}`` dicts naming the
        concrete SAP objects the finding is about. It is what gives a finding a stable
        identity across runs and what supplies the attack-path graph its nodes — with
        display strings alone, every graph node would be a string and no finding could
        be matched against itself after a re-upload.

        It is optional so modules can be converted incrementally. A finding without it
        still gets a stable fingerprint, derived from the display strings instead, which
        holds as long as the module's formatting holds. See server/identity.py.

        `scope` declares what the finding is ABOUT, and getting it wrong breaks the
        mitigation journey in one of two directions:

          * ``"object"``    — this finding is about the object(s) named. Four unlocked
            default users are four findings, and must not collapse into one.
          * ``"aggregate"`` — this finding summarises a set ("23 dormant accounts").
            Its identity must exclude the member list, or dismissing one member would
            retire the finding and raise a new one, resetting its age every run.

        Left unset, a single named object is treated as ``object`` and several as
        ``aggregate``. Declare it explicitly whenever a check can legitimately name
        several objects that together constitute ONE defect.

        `subject` splits those two roles apart when a finding is ABOUT one thing but
        NAMES several. "Role Z_ADMIN grants SAP_ALL to 41 users" is about the role; the
        41 users are context that changes as people join and leave. Passing all 42 as
        ``affected_objects`` with ``scope="object"`` would put the users into identity
        and churn the finding every time somebody changed team; ``scope="aggregate"``
        would fix the churn but drop the role from identity too. `subject` gives the
        finding the role's identity while the users ride along as members and as graph
        nodes.

        Do NOT reach for `subject` merely to make `fingerprint_basis` read ``objects``.
        A genuine aggregate — one finding rolling up every offending role for a check —
        is correctly identified by check and system, and ``check_only`` is the honest
        label for it. Naming a constant as the subject would change the label without
        changing the guarantee, which is worse than the coarse label: the console
        presents ``objects`` as "structural, survives rewording", and that would then
        be a claim the data does not support.

        `system` / `client` let a finding override the run's defaults — a cross-system
        trust finding belongs to the system it is *about*, not to the one whose export
        happened to reveal it.
        """
        f = {
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "affected_items": affected_items or [],
            "affected_count": len(affected_items) if affected_items else 0,
            "remediation": remediation,
            "references": references or [],
            "details": details or {},
            "timestamp": datetime.datetime.now().isoformat(),
        }
        if affected_objects:
            f["affected_objects"] = affected_objects
        if subject:
            f["subject"] = subject
            # A finding with an explicit subject is by definition about that subject,
            # whatever else it names. Defaulting scope here stops a caller from
            # supplying a subject and then having it silently ignored because the
            # member count tripped the aggregate heuristic.
            f.setdefault("scope", "object")
        if scope:
            f["scope"] = scope
        if system:
            f["system"] = system
        if client:
            f["client"] = client
        self.findings.append(f)
        return f

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Override in subclass — run all checks and return findings."""
        raise NotImplementedError

    def get_config(self, key: str, default: Any) -> Any:
        """Get config value with baseline override support."""
        return self.overrides.get(key, default)
