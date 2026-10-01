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
exported window; the correlation adds no live capability. It says a weakness was
EXERCISED in the window the customer exported, not that anything is being watched.

ONE METHOD PER AREA, ON PURPOSE. The shared work — bucketing by system, pairing a
config predicate with a log-signal set, collecting the objects to join on — lives
in `_pairs`. But each area's `self.finding(check_id="CORR-…")` call is written out
in its own method with the id as a LITERAL, because the coverage scanner, the
reference generator and the catalogue all read the id at the `finding()` call site;
a factored-out emit with `check_id=<variable>` is invisible to them and silently
drops the check. The four areas:
  CORR-GW-001   gateway ACL weak/unenforced   + GWLOG-001/003
  CORR-HANA-001 HANA auditing/privileged weak + HANALOG-001/002
  CORR-ICM-001  web tier exposed              + ICMLOG-001/003
  CORR-NET-001  network service exposed       + NETLOG-001/003
"""
from typing import Any, Dict, Iterator, List, Tuple

from modules.base_auditor import BaseAuditor


def _prefix_pred(*prefixes):
    """A config-weakness predicate: check_id matches any of these prefixes/ids
    (case-insensitive on the lower-cased forms, so PARAM-gw/ matches too)."""
    lowers = tuple(p.lower() for p in prefixes)
    def pred(finding):
        cid = str(finding.get("check_id") or "").lower()
        return any(cid.startswith(p) for p in lowers)
    return pred


class CorrelationAuditor(BaseAuditor):
    """Emits CORR-* findings where a config weakness and a log observation coincide."""

    CATEGORY = "Gateway Log Review"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        peers = (self.run_context or {}).get("peer_findings") or []
        self.correlate_gateway(peers)
        self.correlate_hana(peers)
        self.correlate_icm(peers)
        self.correlate_network(peers)
        return self.findings

    # --------------------------------------------------------------- shared work
    @staticmethod
    def _system_of(finding: Dict[str, Any]) -> str:
        """The system a finding belongs to, '' when the run has not stamped one yet.

        Correlation runs before ownership/system defaulting, so in the common
        single-system scan every finding carries '' and falls into one bucket — which
        is correct: they are all the same system. A multi-system export stamps the
        system on the finding, and the bucket then separates them."""
        return str(finding.get("system") or "")

    def _pairs(self, peers, config_pred, log_ids, object_types
               ) -> Iterator[Tuple[str, List[str], List[str], List[Dict[str, str]]]]:
        """Per system where a config weakness and a matching log signal BOTH appear,
        yield (system, config_ids, log_ids_found, objects). A denial is the control
        working and is never in `log_ids`, so it is not a signal here."""
        by_system: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for f in peers:
            if config_pred(f):
                by_system.setdefault(self._system_of(f),
                                     {"config": [], "logs": []})["config"].append(f)
            elif str(f.get("check_id") or "") in log_ids:
                by_system.setdefault(self._system_of(f),
                                     {"config": [], "logs": []})["logs"].append(f)
        for system, bucket in sorted(by_system.items()):
            if not bucket["config"] or not bucket["logs"]:
                continue
            config_ids = sorted({f["check_id"] for f in bucket["config"]})
            log_ids_found = sorted({f["check_id"] for f in bucket["logs"]})
            collected = {t: set() for t in object_types}
            for f in bucket["logs"]:
                for obj in f.get("affected_objects") or []:
                    if obj.get("type") in collected and obj.get("name"):
                        collected[obj["type"]].add(obj["name"])
            objects = [{"type": t, "name": n}
                       for t in object_types for n in sorted(collected[t])]
            yield system, config_ids, log_ids_found, objects

    @staticmethod
    def _describe(subject: str, config_ids, log_ids_found, evidence: str) -> str:
        return (
            "The configuration review flagged %s (%s), AND the log over the reviewed "
            "window shows it being used (%s) — %s. A weakness the configuration flagged "
            "and the log shows being exercised is an active-exploitation indicator, not "
            "a theoretical gap, and should be treated as an incident to confirm or rule "
            "out rather than a hardening backlog item."
            % (subject, ", ".join(config_ids), ", ".join(log_ids_found), evidence))

    @staticmethod
    def _items(config_ids, log_ids_found) -> List[str]:
        return ["configuration flagged: %s" % ", ".join(config_ids),
                "the log shows it being used: %s" % ", ".join(log_ids_found)]

    @staticmethod
    def _detail(config_ids, log_ids_found, objects, system) -> Dict[str, Any]:
        return {"config_findings": config_ids, "log_findings": log_ids_found,
                "objects": ["%s:%s" % (o["type"], o["name"]) for o in objects],
                "system": system or None}

    _FIX_LEAD = "Treat this as active use of a known weakness, not a backlog item. "

    # --------------------------------------------------------------- CORR-GW-001
    def correlate_gateway(self, peers: List[Dict[str, Any]]):
        for system, config_ids, log_ids_found, objects in self._pairs(
                peers, _prefix_pred("BASELINE-007", "INTG-GW-", "PARAM-gw/"),
                frozenset({"GWLOG-001", "GWLOG-003"}), ("gateway", "program")):
            self.finding(
                check_id="CORR-GW-001",
                title="RFC gateway exposure is being used, not just misconfigured",
                severity=self.SEVERITY_CRITICAL, category="Gateway Log Review",
                description=self._describe(
                    "the RFC gateway ACL as weak or not enforced", config_ids,
                    log_ids_found,
                    "an external program registered through the gateway, or a connection "
                    "the ACL should have rejected allowed through"),
                affected_items=self._items(config_ids, log_ids_found),
                affected_objects=objects, scope="aggregate",
                details=self._detail(config_ids, log_ids_found, objects, system),
                remediation=self._FIX_LEAD + (
                    "Investigate the registered programs and source hosts in the "
                    "gateway-log findings, then complete the reginfo / secinfo ACL and "
                    "move the gateway to enforcing (gw/sim_mode = 0, gw/acl_mode)."),
                references=["SAP Security Baseline — RFC gateway (reginfo / secinfo)",
                            "SAP Note 1408081 — basic settings for reg_info / sec_info"])

    # --------------------------------------------------------------- CORR-HANA-001
    def correlate_hana(self, peers: List[Dict[str, Any]]):
        for system, config_ids, log_ids_found, objects in self._pairs(
                peers, _prefix_pred("HANADB-AUDIT-", "HANADB-USER-", "HANADB-PRIV-"),
                frozenset({"HANALOG-001", "HANALOG-002"}),
                ("hana_user", "hana_privilege", "schema")):
            self.finding(
                check_id="CORR-HANA-001",
                title="HANA privileged access is being used against weak auditing",
                severity=self.SEVERITY_CRITICAL, category="HANA Log Review",
                description=self._describe(
                    "HANA auditing or privileged access as weak", config_ids,
                    log_ids_found,
                    "a privileged database action, a privilege grant, or a change to the "
                    "audit configuration itself"),
                affected_items=self._items(config_ids, log_ids_found),
                affected_objects=objects, scope="aggregate",
                details=self._detail(config_ids, log_ids_found, objects, system),
                remediation=self._FIX_LEAD + (
                    "Investigate the accounts and privileges in the HANA-log findings, "
                    "deactivate the SYSTEM user for day-to-day work, and confirm the "
                    "audit policies that must stay active are enabled."),
                references=["SAP HANA Security Guide — auditing and the SYSTEM user",
                            "SAP Security Baseline — HANA privileged access"])

    # --------------------------------------------------------------- CORR-ICM-001
    def correlate_icm(self, peers: List[Dict[str, Any]]):
        for system, config_ids, log_ids_found, objects in self._pairs(
                peers, _prefix_pred("WDISP-", "BASELINE-009", "PARAM-icm/"),
                frozenset({"ICMLOG-001", "ICMLOG-003"}), ("icf_path", "endpoint")):
            self.finding(
                check_id="CORR-ICM-001",
                title="An exposed web service is being reached, not just exposed",
                severity=self.SEVERITY_CRITICAL, category="ICM Log Review",
                description=self._describe(
                    "the web tier (ICM / Web Dispatcher / ICF) as exposed or under-logged",
                    config_ids, log_ids_found,
                    "a successful request to an administrative or remote-execution HTTP path"),
                affected_items=self._items(config_ids, log_ids_found),
                affected_objects=objects, scope="aggregate",
                details=self._detail(config_ids, log_ids_found, objects, system),
                remediation=self._FIX_LEAD + (
                    "Investigate the paths and sources in the ICM-log findings, "
                    "deactivate the services that need not be reachable in SICF, and "
                    "restrict the rest to an administrator network."),
                references=["SAP Security Baseline — ICF service exposure (SICF)",
                            "SAP Note 1422273 — recommended ICF service settings"])

    # --------------------------------------------------------------- CORR-NET-001
    def correlate_network(self, peers: List[Dict[str, Any]]):
        for system, config_ids, log_ids_found, objects in self._pairs(
                peers, _prefix_pred("NET-0", "TRUST-006", "TRUST-010", "UCON-"),
                frozenset({"NETLOG-001", "NETLOG-003"}), ("endpoint",)):
            self.finding(
                check_id="CORR-NET-001",
                title="An exposed network service is being reached, not just exposed",
                severity=self.SEVERITY_CRITICAL, category="Network Log Review",
                description=self._describe(
                    "a network service as exposed", config_ids, log_ids_found,
                    "a connection to an SAP service port, in some cases from a public "
                    "source address"),
                affected_items=self._items(config_ids, log_ids_found),
                affected_objects=objects, scope="aggregate",
                details=self._detail(config_ids, log_ids_found, objects, system),
                remediation=self._FIX_LEAD + (
                    "Investigate the sources in the network-log findings, then restrict "
                    "the SAP service ports to the application tier and an administrator "
                    "network at the host or network firewall."),
                references=["SAP Security Baseline — network filtering / ports",
                            "SAP Note 821875 — security settings for the message server"])
