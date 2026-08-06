"""
Ingest: upload -> parse -> scan -> store -> diff.

THE RUN-OVER-RUN CONTRACT
-------------------------
`store_run` is where the mitigation journey is actually implemented, and it has
one rule that everything else follows from:

    A finding row is NEVER deleted, and "resolved" is the ABSENCE of an
    observation in the latest run, not a deletion.

That is what makes a regression re-open the SAME row with its history intact,
rather than raising a brand-new finding whose age starts at zero. It is also why
`finding` and `finding_observation` are separate tables: the durable defect and
the per-run sighting of it are different things, and collapsing them loses the
journey.

DEGRADE, NEVER DROP
-------------------
A module that raises is recorded as failed and the run continues. Losing 22
modules' findings because the 23rd hit a malformed row would be a far worse
outcome than an incomplete run that says it is incomplete — and the coverage
manifest makes the incompleteness visible rather than silent.
"""
from __future__ import annotations

import hashlib
import importlib
import logging
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psycopg
from psycopg.types.json import Jsonb

from server import db
from server.coverage import build_manifest
from server.identity import extract_nodes, fingerprint_finding

log = logging.getLogger(__name__)

#: module file stem -> auditor class name.
AUDITORS: List[Tuple[str, str]] = [
    ("user_auth_audit", "UserAuthAuditor"),
    ("security_params", "SecurityParamAuditor"),
    ("network_services", "NetworkServiceAuditor"),
    ("rise_btp_checks", "RiseBtpAuditor"),
    ("iam_advanced", "AdvancedIamAuditor"),
    ("btp_cloud_surface", "BtpCloudSurfaceAuditor"),
    ("integration_layer", "IntegrationLayerAuditor"),
    ("data_protection", "DataProtectionAuditor"),
    ("code_transport", "CodeTransportAuditor"),
    ("log_monitoring", "LogMonitoringAuditor"),
    ("fiori_ui", "FioriUiAuditor"),
    ("crypto_posture", "CryptoPostureAuditor"),
    ("hana_db_security", "HanaDbSecurityAuditor"),
    ("sap_hotnews", "SapHotNewsAuditor"),
    ("abap_authorizations", "AbapAuthorizationAuditor"),
    ("system_trust", "SystemTrustAuditor"),
    ("baseline_params", "BaselineParamAuditor"),
    ("s4_business_authz", "S4BusinessAuthzAuditor"),
    ("access_risk_analysis", "AccessRiskAnalysisAuditor"),
    ("basis_job_command", "BasisJobCommandAuditor"),
    ("grc_access_control", "GrcAccessControlAuditor"),
    ("role_governance", "RoleGovernanceAuditor"),
    ("financial_controls", "FinancialControlsAuditor"),
]


class ScanCancelled(Exception):
    """Raised when a user cancels a running scan. Not an error."""


@dataclass
class RunDiff:
    """What changed since the previous run for the same system."""
    new: List[int] = field(default_factory=list)
    persisting: List[int] = field(default_factory=list)
    resolved: List[int] = field(default_factory=list)
    regressed: List[int] = field(default_factory=list)

    def as_counts(self) -> Dict[str, int]:
        return {"new": len(self.new), "persisting": len(self.persisting),
                "resolved": len(self.resolved), "regressed": len(self.regressed)}


def bundle_sha(data_dir: Path) -> str:
    """Content hash of an upload, over sorted (relative name, bytes).

    Names participate so that renaming a file is a different bundle — the file
    name is what selects the parser, so two bundles with identical bytes under
    different names genuinely scan differently.
    """
    h = hashlib.sha256()
    for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
        h.update(path.relative_to(data_dir).as_posix().encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _should_cancel(conn: psycopg.Connection, run_id: int) -> bool:
    row = conn.execute("SELECT cancel_requested FROM scan_run WHERE id = %s",
                       (run_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def run_auditors(data: Dict[str, Any], conn: psycopg.Connection, run_id: int,
                 ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Run every auditor. Returns (findings, per-module status, modules that ran).

    A module that raises is recorded and skipped; the run continues.
    """
    findings: List[Dict[str, Any]] = []
    status: Dict[str, Any] = {}
    ran: List[str] = []

    conn.execute("UPDATE scan_run SET progress_total = %s, status = 'scanning' "
                 "WHERE id = %s", (len(AUDITORS), run_id))
    conn.commit()

    for index, (mod_name, cls_name) in enumerate(AUDITORS, start=1):
        if _should_cancel(conn, run_id):
            raise ScanCancelled(f"cancelled before {mod_name}")
        try:
            module = importlib.import_module(f"modules.{mod_name}")
            cls = getattr(module, cls_name)
            produced = cls(data).run_all_checks() or []
            findings.extend(produced)
            ran.append(mod_name)
            status[mod_name] = {"status": "ok", "findings": len(produced)}
        except Exception as exc:                      # noqa: BLE001 - degrade, never drop
            log.exception("auditor %s failed", mod_name)
            status[mod_name] = {
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                # Kept because reviewers punish exactly this: a failing component
                # that yields no detail in the console or the log.
                "traceback": traceback.format_exc(limit=6),
            }
        conn.execute("UPDATE scan_run SET progress_done = %s WHERE id = %s",
                     (index, run_id))
        conn.commit()

    return findings, status, ran


def _upsert_check_definitions(conn: psycopg.Connection,
                              findings: Iterable[Dict[str, Any]]) -> None:
    """Ensure a catalogue row exists for every check_id seen.

    Only the catalogue's *descriptive* columns are refreshed. Curated columns —
    owning_team, responsibility, baseline_req_id — are set once and left alone,
    because they are human judgements that a scan must not silently overwrite.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        cid = (f.get("check_id") or "").strip().upper()
        if cid and cid not in seen:
            seen[cid] = f
    for cid, f in seen.items():
        conn.execute(
            """
            INSERT INTO check_definition
                (check_id, title, category, default_severity, remediation,
                 risk_narrative, references_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (check_id) DO UPDATE SET
                title            = EXCLUDED.title,
                category         = EXCLUDED.category,
                default_severity = EXCLUDED.default_severity,
                remediation      = EXCLUDED.remediation,
                risk_narrative   = EXCLUDED.risk_narrative,
                references_json  = EXCLUDED.references_json,
                updated_at       = now()
            """,
            (cid, f.get("title", ""), f.get("category"), f.get("severity"),
             f.get("remediation", ""), f.get("description", ""),
             Jsonb(f.get("references") or [])),
        )


def _rebase(conn: psycopg.Connection,
            pool: Dict[Tuple[str, str], List[Dict[str, Any]]],
            check_id: str, new_basis: str, new_fp: str,
            previously_open: Dict[str, int]) -> Optional[Dict[str, Any]]:
    """Carry a finding's history across a change in how its identity is computed.

    THE PROBLEM THIS SOLVES, WHICH IS NOT HYPOTHETICAL
    ---------------------------------------------------
    Converting a module from display-string identity to structured-object identity
    changes every one of its findings' fingerprints. Without this, the next scan
    reports the whole check as newly broken and silently resolves the old rows —
    so a customer who has been tracking a defect for six months loses its age, its
    assignee, its risk acceptance and its entire history the day we ship an
    improvement. It was caught exactly this way: a module was converted between
    two scans of a byte-identical bundle and BTP-DST-001 churned new+resolved.

    THE RULE
    --------
    Rebase only when it is UNAMBIGUOUS: exactly one open finding for this check
    carries a different basis and has not already been matched by fingerprint in
    this run. If a check has several such rows we cannot tell which is which, and
    guessing would silently attach one defect's history to another — worse than
    losing it. In that case we do nothing and the finding is reported as new.
    """
    for basis in ("objects", "display", "check_only"):
        if basis == new_basis:
            continue
        candidates = [c for c in pool.get((check_id, basis), ())
                      if c["fingerprint"] in previously_open]
        if len(candidates) != 1:
            continue
        cand = candidates[0]
        conn.execute(
            "UPDATE finding SET fingerprint = %s, fingerprint_basis = %s WHERE id = %s",
            (new_fp, new_basis, cand["id"]))
        conn.execute(
            "INSERT INTO finding_transition (finding_id, from_state, to_state, actor, "
            "reason) VALUES (%s, NULL, 'open', 'scanner', %s)",
            (cand["id"], f"identity rebased from {basis} to {new_basis} "
                         f"(check definition changed; history preserved)"))
        # Re-key so the caller's "not seen this run" sweep does not resolve it.
        previously_open.pop(cand["fingerprint"], None)
        previously_open[new_fp] = cand["id"]
        pool[(check_id, basis)].remove(cand)
        log.info("rebased %s identity %s -> %s (finding %s)",
                 check_id, basis, new_basis, cand["id"])
        return dict(cand, state="open")
    return None


def store_run(conn: psycopg.Connection, run_id: int, landscape_id: int,
              system_id: Optional[int], findings: List[Dict[str, Any]],
              default_sid: Optional[str] = None,
              default_client: Optional[str] = None) -> RunDiff:
    """Persist a run's findings and compute the diff against what was open before.

    Runs inside the caller's transaction so that a failure leaves no half-stored
    run behind.
    """
    _upsert_check_definitions(conn, findings)

    # What was open for this system before this run. Compared by fingerprint, so
    # a finding matches itself regardless of how its wording or severity moved.
    previously_open = {
        r["fingerprint"]: r["id"]
        for r in conn.execute(
            "SELECT id, fingerprint FROM finding "
            "WHERE landscape_id = %s AND system_id IS NOT DISTINCT FROM %s "
            "AND state NOT IN ('resolved', 'false_positive')",
            (landscape_id, system_id)).fetchall()
    }

    # Candidates for identity rebasing, keyed by (check_id, basis). See _rebase.
    rebase_pool: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in conn.execute(
            "SELECT id, check_id, fingerprint, fingerprint_basis FROM finding "
            "WHERE landscape_id = %s AND system_id IS NOT DISTINCT FROM %s "
            "AND state NOT IN ('resolved', 'false_positive')",
            (landscape_id, system_id)).fetchall():
        rebase_pool.setdefault((r["check_id"], r["fingerprint_basis"]), []).append(r)

    diff = RunDiff()
    seen_now: Dict[str, int] = {}

    for f in findings:
        fp, basis = fingerprint_finding(f, default_sid, default_client)
        if fp in seen_now:
            # The same defect emitted twice in one run. Record the observation
            # once; do not double-count it in the diff.
            continue

        cid = (f.get("check_id") or "").strip().upper()
        scope = f.get("scope") or ("aggregate" if len(f.get("affected_objects") or ()) > 1
                                   else "object")
        subject = f.get("affected_objects") or []

        row = conn.execute(
            "SELECT id, state, regression_count FROM finding "
            "WHERE landscape_id = %s AND fingerprint = %s",
            (landscape_id, fp)).fetchone()

        if row is None:
            row = _rebase(conn, rebase_pool, cid, basis, fp, previously_open)

        if row is None:
            finding_id = conn.execute(
                """
                INSERT INTO finding
                    (landscape_id, system_id, fingerprint, check_id, client,
                     fingerprint_basis, scope, subject, severity,
                     first_seen_run, last_seen_run)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (landscape_id, system_id, fp, cid, default_client, basis, scope,
                 Jsonb(subject), f.get("severity"), run_id, run_id)).fetchone()["id"]
            diff.new.append(finding_id)
            conn.execute(
                "INSERT INTO finding_transition (finding_id, scan_run_id, from_state, "
                "to_state, actor, reason) VALUES (%s,%s,NULL,'open','scanner','first seen')",
                (finding_id, run_id))
        else:
            finding_id = row["id"]
            # A finding previously resolved that is seen again is a REGRESSION —
            # the same row re-opens, keeping its age and its history, and the
            # regression count makes a recurring process failure visible.
            if row["state"] == "resolved":
                conn.execute(
                    "UPDATE finding SET state = 'open', resolved_at = NULL, "
                    "regression_count = regression_count + 1, last_seen_run = %s, "
                    "last_detected_at = now(), severity = %s, subject = %s, "
                    "fingerprint_basis = %s WHERE id = %s",
                    (run_id, f.get("severity"), Jsonb(subject), basis, finding_id))
                conn.execute(
                    "INSERT INTO finding_transition (finding_id, scan_run_id, from_state,"
                    " to_state, actor, reason) VALUES (%s,%s,'resolved','open','scanner',"
                    "'regressed — seen again after being resolved')",
                    (finding_id, run_id))
                diff.regressed.append(finding_id)
            else:
                conn.execute(
                    "UPDATE finding SET last_seen_run = %s, last_detected_at = now(), "
                    "severity = %s, subject = %s, fingerprint_basis = %s WHERE id = %s",
                    (run_id, f.get("severity"), Jsonb(subject), basis, finding_id))
                diff.persisting.append(finding_id)

        conn.execute(
            """
            INSERT INTO finding_observation
                (finding_id, scan_run_id, severity, title, description,
                 affected_items, affected_objects, affected_count, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (finding_id, scan_run_id) DO NOTHING
            """,
            (finding_id, run_id, f.get("severity"), f.get("title", ""),
             f.get("description", ""), Jsonb(f.get("affected_items") or []),
             Jsonb(subject), f.get("affected_count") or 0,
             Jsonb(f.get("details") or {})))

        seen_now[fp] = finding_id

    # Anything open before and not observed now is resolved. Note this only
    # closes findings for the system this run covered — a partial upload must
    # never silently "resolve" a system it did not look at.
    for fp, finding_id in previously_open.items():
        if fp in seen_now:
            continue
        conn.execute(
            "UPDATE finding SET state = 'resolved', resolved_at = now(), "
            "last_transition_at = now(), transitioned_by = 'scanner' WHERE id = %s",
            (finding_id,))
        conn.execute(
            "INSERT INTO finding_transition (finding_id, scan_run_id, from_state, "
            "to_state, actor, reason) VALUES (%s,%s,NULL,'resolved','scanner',"
            "'not observed in this run')",
            (finding_id, run_id))
        diff.resolved.append(finding_id)

    return diff


def store_graph_nodes(conn: psycopg.Connection, run_id: int, landscape_id: int,
                      system_id: Optional[int], findings: List[Dict[str, Any]],
                      default_sid: Optional[str] = None) -> int:
    """Materialise the graph nodes named by this run's findings.

    Nodes are populated from day one even though path computation is a later
    phase, because a node's first_seen is only truthful if it was recorded when
    it was first seen. Backfilling it later would invent history.
    """
    nodes = extract_nodes(findings, default_system=default_sid)
    for node in nodes:
        conn.execute(
            """
            INSERT INTO graph_node
                (landscape_id, node_key, type, name, system_id, client, qualifier,
                 finding_count, first_seen_run, last_seen_run)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (landscape_id, node_key) DO UPDATE SET
                finding_count = EXCLUDED.finding_count,
                last_seen_run = EXCLUDED.last_seen_run
            """,
            (landscape_id, node["key"], node["type"], node["name"], system_id,
             node.get("client"), node.get("qualifier"), node["finding_count"],
             run_id, run_id))
    return len(nodes)


def scan_directory(data_dir: Path, landscape_id: int, system_id: Optional[int],
                   run_id: int, deployment_mode: str = "on_prem",
                   default_sid: Optional[str] = None,
                   default_client: Optional[str] = None) -> Dict[str, Any]:
    """The whole pipeline for one upload. Returns a result summary."""
    from modules.data_loader import DataLoader

    with db.connection() as conn:
        try:
            conn.execute("UPDATE scan_run SET status = 'parsing' WHERE id = %s", (run_id,))
            conn.commit()
            data = DataLoader(data_dir).load_all()

            findings, module_status, ran = run_auditors(data, conn, run_id)
            manifest = build_manifest(data, modules_run=ran,
                                      deployment_mode=deployment_mode)

            conn.execute("UPDATE scan_run SET status = 'deriving' WHERE id = %s", (run_id,))
            diff = store_run(conn, run_id, landscape_id, system_id, findings,
                             default_sid, default_client)
            node_count = store_graph_nodes(conn, run_id, landscape_id, system_id,
                                           findings, default_sid)

            conn.execute(
                "UPDATE scan_run SET status = 'complete', finished_at = now(), "
                "coverage = %s, module_status = %s WHERE id = %s",
                (Jsonb(manifest), Jsonb(module_status), run_id))
            db.audit(conn, "scanner", "scan.complete", "scan_run", str(run_id),
                     {"findings": len(findings), **diff.as_counts()})
            conn.commit()

            return {"run_id": run_id, "findings": len(findings), "nodes": node_count,
                    "diff": diff.as_counts(), "coverage": manifest,
                    "module_status": module_status}

        except ScanCancelled as exc:
            conn.rollback()
            conn.execute("UPDATE scan_run SET status = 'cancelled', finished_at = now(), "
                         "error = %s WHERE id = %s", (str(exc), run_id))
            conn.commit()
            return {"run_id": run_id, "status": "cancelled", "reason": str(exc)}

        except Exception as exc:                       # noqa: BLE001
            # Roll back the data, THEN mark the run failed, then re-raise. Marking
            # before rolling back would discard the error message with the data.
            conn.rollback()
            log.exception("scan run %s failed", run_id)
            conn.execute("UPDATE scan_run SET status = 'failed', finished_at = now(), "
                         "error = %s WHERE id = %s",
                         (f"{type(exc).__name__}: {exc}", run_id))
            conn.commit()
            raise
