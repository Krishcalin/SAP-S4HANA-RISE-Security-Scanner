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
