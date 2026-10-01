"""
Config-vs-log correlation (CORR-*)
==================================
Every other auditor reads the customer's export and reports a defect. This one
reads the OTHER auditors' FINDINGS — the full set, after they have all run — and
reports where a CONFIGURATION weakness and a matching LOG observation co-exist.
A weakness the configuration flagged is a theoretical gap; the same weakness with
a log event showing it being exercised is an active-exploitation indicator, and
that is a different, higher-severity statement.

HOW IT RUNS. It is NOT in `server/ingest.AUDITORS`, because it needs what the
auditors produce, not the raw export: it runs as a SECOND PASS after
`run_auditors`, reading the aggregated findings from `run_context["peer_findings"]`
(the pattern `ruleset_coverage` already uses) and emitting its own findings, which
the rest of the pipeline — dedup, ownership, journey, notifications, graph, CRQ,
attack paths — then picks up like any other. See server/ingest.py (server path)
and sap_scanner.py (offline path).

RETROSPECTIVE, LIKE ITS INPUTS. The log half is the retrospective review of an
exported window (GWLOG-*); the correlation adds no live capability. It says a
weakness was EXERCISED in the window the customer exported, not that anything is
being watched now.

SLICE 1 — GATEWAY. CORR-GW-001 pairs the gateway ACL configuration findings
(BASELINE-007 gw/acl_mode, INTG-GW-* secinfo/reginfo, PARAM-gw/*) with the gateway
log review (GWLOG-001 external program registered, GWLOG-003 permissive gateway
used). HANA / ICM / network correlations follow as those log detectors land.
"""
from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor


class CorrelationAuditor(BaseAuditor):
    """Emits CORR-* findings where a config weakness and a log observation coincide."""

    CATEGORY = "Gateway Log Review"

    #: Log observations that show the gateway being USED in a way the ACL should
    #: have stopped. A denial (GWLOG-002) is the ACL WORKING, so it is deliberately
    #: not a correlation signal — it is not evidence of a weakness being exercised.
    GATEWAY_LOG_SIGNALS = frozenset({"GWLOG-001", "GWLOG-003"})

    def run_all_checks(self) -> List[Dict[str, Any]]:
        peers = (self.run_context or {}).get("peer_findings") or []
        self.correlate_gateway_exposure_used(peers)
        return self.findings

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _is_gateway_config_weakness(finding: Dict[str, Any]) -> bool:
        """A configuration finding that the gateway ACL is weak or not enforced."""
        cid = str(finding.get("check_id") or "")
        return (cid == "BASELINE-007"
                or cid.startswith("INTG-GW-")
                or cid.lower().startswith("param-gw/"))

    @staticmethod
    def _system_of(finding: Dict[str, Any]) -> str:
        """The system a finding belongs to, '' when the run has not stamped one yet.

        Correlation runs before ownership/system defaulting, so in the common
        single-system scan every finding carries '' and falls into one bucket — which
        is correct: they are all the same system. A multi-system export stamps the
        system on the finding, and the bucket then separates them."""
        return str(finding.get("system") or "")

    # --------------------------------------------------------------- CORR-GW-001
    def correlate_gateway_exposure_used(self, peers: List[Dict[str, Any]]):
        """CORR-GW-001: a flagged gateway weakness AND a log event exercising it.

        The configuration findings say the secinfo / reginfo ACL is weak or not
        enforced; the gateway log shows a program registered or a connection allowed
        that the ACL should have stopped. Co-existing in one system, they are an
        active-exploitation indicator — the door the config flagged as unlocked had
        something walk through it in the reviewed window.
        """
        by_system: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for f in peers:
            if self._is_gateway_config_weakness(f):
                by_system.setdefault(self._system_of(f),
                                     {"config": [], "logs": []})["config"].append(f)
            elif str(f.get("check_id") or "") in self.GATEWAY_LOG_SIGNALS:
                by_system.setdefault(self._system_of(f),
                                     {"config": [], "logs": []})["logs"].append(f)

        for system, bucket in sorted(by_system.items()):
            if not bucket["config"] or not bucket["logs"]:
                continue
            config_ids = sorted({f["check_id"] for f in bucket["config"]})
            log_ids = sorted({f["check_id"] for f in bucket["logs"]})
            hosts, programs = set(), set()
            for f in bucket["logs"]:
                for obj in f.get("affected_objects") or []:
                    if obj.get("type") == "gateway":
                        hosts.add(obj.get("name"))
                    elif obj.get("type") == "program":
                        programs.add(obj.get("name"))
            objects = ([{"type": "gateway", "name": h} for h in sorted(hosts) if h]
                       + [{"type": "program", "name": p} for p in sorted(programs) if p])
            items = ["configuration flagged the gateway ACL: %s" % ", ".join(config_ids),
                     "the gateway log shows it being used: %s" % ", ".join(log_ids)]
            if hosts:
                items.append("gateway host(s): %s" % ", ".join(sorted(h for h in hosts if h)))
            self.finding(
                check_id="CORR-GW-001",
                title="RFC gateway exposure is being used, not just misconfigured",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    "The configuration review flagged the RFC gateway ACL as weak or "
                    "not enforced (%s), AND the gateway log over the reviewed window "
                    "shows that exposure being used (%s) — an external program "
                    "registered through the gateway, or a connection the ACL should "
                    "have rejected allowed through. A weakness the configuration "
                    "flagged and the log shows being exercised is an active-"
                    "exploitation indicator, not a theoretical gap, and should be "
                    "treated as an incident to confirm or rule out, not a hardening "
                    "backlog item." % (", ".join(config_ids), ", ".join(log_ids))),
                affected_items=items,
                affected_objects=objects,
                scope="aggregate",
                details={
                    "config_findings": config_ids,
                    "log_findings": log_ids,
                    "gateway_hosts": sorted(h for h in hosts if h),
                    "programs": sorted(p for p in programs if p),
                    "system": system or None,
                },
                remediation=(
                    "Treat this as active use of a known gateway weakness, not a "
                    "backlog item: investigate the registered programs and source "
                    "hosts named in the gateway-log findings, then close the exposure "
                    "— complete the reginfo / secinfo ACL and move the gateway to "
                    "enforcing (gw/sim_mode = 0, gw/acl_mode) so the rule that matched "
                    "rejects the connection rather than only recording it."
                ),
                references=[
                    "SAP Security Baseline — RFC gateway (reginfo / secinfo)",
                    "SAP Note 1408081 — basic settings for reg_info / sec_info",
                ],
            )
