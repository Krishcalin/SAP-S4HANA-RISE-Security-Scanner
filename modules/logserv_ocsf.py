"""
SAP LogServ (OCSF) → Security-Audit-Log event adapter
=====================================================
SAP LogServ is SAP's ECS log service for a RISE landscape: it collects logs from
across the estate (ABAP Security Audit Log, HANA, ICM, Web Dispatcher, Cloud
Connector, OS, Gateway, network) and forwards them in the **OCSF** schema (Open
Cybersecurity Schema Framework) — a normalised JSON event shape.

This module is the one place that understands OCSF. It converts a batch of OCSF
events into the SAME row shape `modules/log_review.py` already reads from a
`security_audit_log.csv` export, so every retrospective pattern there
(`LREV-PAT-*`) runs over LogServ events unchanged. LogServ is therefore just a
new, fresher SOURCE for the log review the product already ships — not a new
real-time capability. The analysis stays retrospective, over the exported window.

WHY A ROW, NOT A NEW EVENT MODEL. `log_review._prepare` turns each audit row into
`{when,user,client,terminal,tcode,tags}` via `_classify`, which reads an event
class, the free message text and the transaction code. Emitting a row with those
same columns lets that classifier — and its shared vocabulary with
`log_monitoring.REQUIRED_AUDIT_EVENTS` — do the work, rather than duplicating it.

TOLERANT BY DESIGN. A single malformed event must not abort the batch: an event
we cannot read contributes nothing and is skipped, exactly as the loader treats a
file it cannot decode. Only the standard library is used (OCSF is JSON).

TWO WIRE SHAPES, BOTH ACCEPTED — because SAP LogServ delivers logs raw and the
OCSF normalisation is a SEPARATE converter (SAP's own, or a forwarder such as the
Azure Sentinel / Google SecOps pipelines), so a customer may export either:

  * OCSF-converted events — `time` (epoch MILLISECONDS), `class_uid` / `class_name`,
    `activity_id`, `status_id` (1 = Success, 2 = Failure), `message`,
    `actor.user.name` / `user.name`, `src_endpoint.{hostname,ip}`, `dst_endpoint`,
    and an `unmapped` object for SAP vendor fields; or
  * RAW LogServ records (the S3 gzip-JSON shape) — `_raw` (the log line), `_time`
    (epoch SECONDS), `source` (the log file path), `host`. The log CLASS is then
    read from `source` (e.g. `.../work/gw_log` → gateway, `.../indexserver...` →
    HANA, `dev_icm` → ICM, `.../firewall/flowlog` → network, a `security_audit`
    path → SAL).

WHAT IS VERIFIED vs ASSUMED. The OCSF `class_uid`s used here are from the published
OCSF schema and are stable (Authentication 3002; Network Activity 4001 / DNS 4003 /
DHCP 4004 / RDP 4005; HTTP Activity 4002). SAP gateway and HANA audit have no
standard OCSF class, so they are recognised by signature, never by class_uid. The
raw field names (`_raw`/`_time`/`source`/`host`) are SAP LogServ's documented S3
shape. The exact LogServ *export API* query parameters remain assumed in
`collect/logserv.py` (see its note); the adapter does not depend on them.

WHY A ROW, NOT A NEW EVENT MODEL (for the SAL path). `log_review._prepare` turns
each audit row into `{when,user,client,terminal,tcode,tags}` via `_classify`, which
reads an event class, the free message text and the transaction code. Emitting a
row with those same columns lets that classifier do the work. The non-SAL classes
(gateway / HANA / ICM / network) go through `to_system_events` into a richer event
instead, and never become SAL rows.

TOLERANT BY DESIGN. A single malformed event must not abort the batch: an event we
cannot read contributes nothing and is skipped. Only the standard library is used.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

#: OCSF class_uid for the Authentication class (logon / logoff). The one class this
#: adapter maps to a specific audit event class; everything else flows through the
#: message and transaction code so log_review's own text/tcode heuristics classify it.
_AUTHENTICATION_CLASS_UID = 3002

#: OCSF status_id values.
_STATUS_FAILURE = 2

_USER_PATHS = (("actor", "user", "name"), ("user", "name"), ("actor", "user", "uid"))
_TERMINAL_PATHS = (("src_endpoint", "hostname"), ("src_endpoint", "ip"),
                   ("device", "hostname"), ("device", "ip"))
#: The destination side — the SAP server the connection reached (the gateway host
#: for a gateway event). Read defensively, same as the source side.
_DEST_PATHS = (("dst_endpoint", "hostname"), ("dst_endpoint", "ip"),
               ("dst_endpoint", "name"), ("host",), ("device", "hostname"))
#: SAP-specific fields land in `unmapped` (or occasionally at the top level); several
#: spellings are accepted rather than one asserted, as everywhere else in this repo.
_CLIENT_KEYS = ("client", "mandt", "sap_client", "MANDT", "CLIENT")
_TCODE_KEYS = ("tcode", "transaction", "transaction_code", "tcd", "TCODE")

# ── system-log (non-SAL) classes ────────────────────────────────────────────────
# SAP LogServ forwards far more than the ABAP Security Audit Log: gateway, HANA,
# ICM / Web Dispatcher and network logs all arrive in the same OCSF stream. Those
# do NOT fit the Security-Audit-Log row shape (no transaction code, a different
# actor, an ACL decision rather than an event class), so they are pulled out HERE
# into a richer "system event" and handed to modules/logserv_review.py, and are
# deliberately kept OUT of the SAL rows `to_audit_events` builds (see its guard),
# so a gateway event never inflates the audit-log window log_review reviews.
#
# Recognition is by SIGNATURE, not an asserted class_uid: LogServ's mapping of
# SAP-specific logs is partly vendor-defined, so several markers are accepted. An
# event that carries a SAP transaction code, or whose text/class is Security-Audit-
# Log vocabulary, is SAL and is never claimed here — that keeps the existing
# tcode/message heuristics (e.g. SM69 → LREV-PAT-008) working unchanged.
_GATEWAY_HINTS = ("gateway", "gwmon", "secinfo", "reginfo", "reg_info", "sec_info",
                  "registered program", "external program", "started program",
                  "rfcexec", "tp_name", "reg_program")
#: Program (external TP) and gateway-host field spellings, read from `unmapped`/top.
_PROGRAM_KEYS = ("program", "tp_name", "tpname", "tp", "reg_program",
                 "registered_program", "program_name")
_GATEWAY_HOST_KEYS = ("gateway_host", "gwhost", "gw_host", "server", "gateway")

#: HANA database audit log. Recognised by product/class/message naming HANA, or by
#: SAP HANA audit fields carried in `unmapped`.
_HANA_HINTS = ("hana", "hdb", "saphana", "indexserver", "nameserver", "hdbsql",
               "audit policy", "sql trace", "database audit")
_HANA_KEYS = ("audit_policy", "audit_policy_name", "db_user", "dbuser", "db_object",
              "schema", "privilege", "grantee", "sql_statement", "hana_user")
_AUDIT_POLICY_KEYS = ("audit_policy", "audit_policy_name", "policy", "policy_name")
_DB_OBJECT_KEYS = ("db_object", "object", "object_name", "schema_object", "view",
                   "table_name")
_PRIVILEGE_KEYS = ("privilege", "system_privilege", "granted_privilege", "object_privilege")

#: ICM / Web Dispatcher / ICF HTTP request log. Recognised by product/class naming
#: the web tier, or by an HTTP request path being present.
_ICM_HINTS = ("icm", "web dispatcher", "webdisp", "icf", "sicf", "http activity",
              "web resources", "http request", "message server http")
_PATH_PATHS = (("http_request", "url", "path"), ("http_request", "url", "text"),
               ("url", "path"), ("url", "text"), ("web_resources", "url", "path"))
_PATH_KEYS = ("url", "path", "http_path", "uri", "resource", "icf_path", "service_path")
_HTTP_METHOD_PATHS = (("http_request", "http_method"), ("http_request", "method"))
_HTTP_STATUS_PATHS = (("http_response", "code"), ("http_response", "status_code"),
                      ("status_code",))

#: Network / firewall / proxy / DNS log. Recognised by product/class, or by a
#: destination port with a connection/deny shape.
_NETWORK_HINTS = ("firewall", "network activity", "proxy", "dns activity", "netfilter",
                  "packet filter", "network traffic", "connection log")
_PORT_PATHS = (("dst_endpoint", "port"), ("dst_port",), ("dst_endpoint", "svc_name"))
_PROTOCOL_PATHS = (("connection_info", "protocol_name"), ("connection_info", "protocol"),
                   ("protocol",), ("network_protocol",))
_DISPOSITION_PATHS = (("disposition",), ("action",), ("network_endpoint", "disposition"))


def _dig_any(event: Dict[str, Any], paths) -> str:
    for path in paths:
        val = _dig(event, path)
        if val:
            return val
    return ""


def _http_path(event: Dict[str, Any]) -> str:
    """The requested HTTP/ICF path, from OCSF http_request or an unmapped field."""
    return _dig_any(event, _PATH_PATHS) or _unmapped_or_top(event, _PATH_KEYS)


def _has_network_shape(event: Dict[str, Any]) -> bool:
    """A destination port plus a protocol or a connect/deny disposition — enough to
    treat an event as a network-log line even when nothing names the product."""
    port = _dig_any(event, _PORT_PATHS)
    proto = _dig_any(event, _PROTOCOL_PATHS)
    return bool(port and (proto or _dig_any(event, _DISPOSITION_PATHS)))


def _product_blob(event: Dict[str, Any]) -> str:
    """Lower-cased product / feature / class / category names for signature tests."""
    parts = [str(event.get("class_name") or ""),
             str(event.get("category_name") or ""),
             str(event.get("activity_name") or "")]
    meta = event.get("metadata")
    if isinstance(meta, dict):
        prod = meta.get("product")
        if isinstance(prod, dict):
            parts.append(str(prod.get("name") or ""))
            parts.append(str(prod.get("vendor_name") or ""))
            feat = prod.get("feature")
            if isinstance(feat, dict):
                parts.append(str(feat.get("name") or ""))
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        parts.extend(str(k) for k in unmapped.keys())
    return " ".join(parts).lower()


#: Authoritative OCSF class_uid → system-log class, applied BEFORE the name /
#: signature heuristics. These class_uids are stable in the published OCSF schema
#: (category 4, Network Activity: 4001 Network / 4003 DNS / 4004 DHCP / 4005 RDP;
#: 4002 HTTP Activity). SAP gateway and HANA audit have no standard OCSF class, so
#: they are recognised by signature below and never by class_uid. Authentication
#: (3002) is deliberately absent: it is a Security Audit Log logon, handled by
#: to_audit_events, so it must fall through to "".
_OCSF_CLASS_UID = {4002: "icm", 4001: "network", 4003: "network",
                   4004: "network", 4005: "network"}

#: SAP LogServ also delivers RAW records (not OCSF-converted — the conversion is a
#: separate step): the log class is then identifiable only from `source`, the log
#: file path, or a `log_type` field. These substrings map that path to a class.
#: Gateway / HANA come first so a path naming both wins the more specific one.
_SOURCE_KEYS = ("source", "log_type", "logtype", "log_source", "_source")
_SOURCE_CLASS_PATTERNS = (
    ("gateway", ("gw_", "gwrd", "gateway", "/gw", "secinfo", "reginfo")),
    ("hana", ("hana", "hdb", "indexserver", "nameserver", "xsengine")),
    ("icm", ("icm", "web_disp", "webdisp", "/icf", "sicf", "httpaccess")),
    ("network", ("firewall", "flowlog", "flow_log", "/network", "dns_", "/dns",
                 "proxy", "packetfilter", "vpcflow")),
)
#: A `source` naming the security audit log is SAL, never a system class.
_SAL_SOURCE_MARKERS = ("audit", "/sal", "rsau", "sm20", "security_audit")


def _class_uid_of(event: Dict[str, Any]) -> Optional[int]:
    try:
        return int(event["class_uid"]) if event.get("class_uid") is not None else None
    except (TypeError, ValueError):
        return None


def _source_class(event: Dict[str, Any]) -> str:
    """gateway|hana|icm|network from a raw LogServ `source` / `log_type`, or ""."""
    src = _unmapped_or_top(event, _SOURCE_KEYS).lower()
    if not src or any(m in src for m in _SAL_SOURCE_MARKERS):
        return ""
    for cls, needles in _SOURCE_CLASS_PATTERNS:
        if any(n in src for n in needles):
            return cls
    return ""


def _logserv_class(event: Dict[str, Any]) -> str:
    """Which non-SAL system-log class this event belongs to, or "".

    One of {"gateway", "hana", "icm", "network"}. Recognition uses, in order of
    authority: a SAP transaction code or a security-audit-log `source` (both → "",
    i.e. SAL); the SAP-specific gateway / HANA signatures (no standard OCSF class);
    the documented OCSF class_uid; then the name / shape heuristics; and finally,
    for a RAW LogServ record carrying none of those, the `source` log-file path.
    Gateway and HANA are tested before the generic network class_uid so a gateway
    event — which also has a destination — is not swallowed as network.
    """
    if _unmapped_or_top(event, _TCODE_KEYS):
        return ""
    src = _unmapped_or_top(event, _SOURCE_KEYS).lower()
    if src and any(m in src for m in _SAL_SOURCE_MARKERS):
        return ""                                  # raw security-audit-log record
    blob = (_product_blob(event) + " " + str(event.get("message") or "")
            + " " + str(event.get("_raw") or "")).lower()
    if any(h in blob for h in _GATEWAY_HINTS) or _unmapped_or_top(event, _PROGRAM_KEYS):
        return "gateway"
    if any(h in blob for h in _HANA_HINTS) or _unmapped_or_top(event, _HANA_KEYS):
        return "hana"
    uid = _class_uid_of(event)
    if uid in _OCSF_CLASS_UID:
        return _OCSF_CLASS_UID[uid]
    if any(h in blob for h in _ICM_HINTS) or _http_path(event):
        return "icm"
    if any(h in blob for h in _NETWORK_HINTS) or _has_network_shape(event):
        return "network"
    return _source_class(event)


def _gateway_action(event: Dict[str, Any], decision: str) -> str:
    """register | start | deny | connect — from the activity name and message."""
    blob = (str(event.get("activity_name") or "") + " "
            + str(event.get("message") or "")).lower()
    if decision == "denied":
        return "deny"
    if "regist" in blob:
        return "register"
    if "start" in blob:
        return "start"
    if "connect" in blob or "connection" in blob:
        return "connect"
    return ""


def _gateway_decision(event: Dict[str, Any]) -> str:
    """allowed | denied | monitored — the secinfo/reginfo ACL verdict."""
    try:
        status_id = int(event.get("status_id")) if event.get("status_id") is not None else None
    except (TypeError, ValueError):
        status_id = None
    blob = (str(event.get("status") or "") + " "
            + str(event.get("message") or "") + " "
            + str(event.get("activity_name") or "")).lower()
    # Monitor / simulation mode is the dangerous one: a rule that WOULD deny the
    # connection is only logged, and the connection succeeds anyway. It is told
    # apart from a real denial by the outcome — monitor mode SUCCEEDS (not a
    # failure status) despite the deny rule — so it is tested first and gated on
    # the event not being a hard failure.
    if (status_id != _STATUS_FAILURE
            and any(w in blob for w in ("monitor", "simulation", "sim mode",
                                        "logging only", "would be denied", "permissive"))):
        return "monitored"
    if status_id == _STATUS_FAILURE or any(w in blob for w in
                                           ("deny", "denied", "blocked", "reject", "refused")):
        return "denied"
    return "allowed"


def _status_failed(event: Dict[str, Any]) -> bool:
    try:
        status_id = int(event.get("status_id")) if event.get("status_id") is not None else None
    except (TypeError, ValueError):
        status_id = None
    blob = (str(event.get("status") or "") + " " + str(event.get("message") or "")).lower()
    return status_id == _STATUS_FAILURE or any(
        w in blob for w in ("fail", "error", "denied", "unsuccessful", "reject", "refused"))


def _hana_action(event: Dict[str, Any]) -> str:
    """audit_change | grant | revoke | alter | connect | read | drop — the DB action."""
    blob = (str(event.get("activity_name") or "") + " "
            + str(event.get("message") or "")).lower()
    if "audit" in blob and any(w in blob for w in
                               ("chang", "alter", "disab", "drop", "polic", "creat")):
        return "audit_change"
    for needle, name in (("grant", "grant"), ("revoke", "revoke"), ("alter", "alter"),
                         ("logon", "connect"), ("connect", "connect"),
                         ("select", "read"), ("read", "read"), ("access", "read"),
                         ("drop", "drop"), ("delete", "drop")):
        if needle in blob:
            return name
    return ""


def _icm_decision(event: Dict[str, Any]) -> str:
    """allowed | denied, from the HTTP response code (>=400 is a refused/failed request)."""
    code = _dig_any(event, _HTTP_STATUS_PATHS)
    try:
        if code and int(code) >= 400:
            return "denied"
        if code:
            return "allowed"
    except (TypeError, ValueError):
        pass
    return "denied" if _status_failed(event) else "allowed"


def _network_decision(event: Dict[str, Any]) -> str:
    """allowed | denied, from the firewall disposition or the status."""
    disp = _dig_any(event, _DISPOSITION_PATHS).lower()
    if any(w in disp for w in ("deni", "deny", "drop", "block", "reject", "refus")):
        return "denied"
    if any(w in disp for w in ("allow", "accept", "permit", "pass")):
        return "allowed"
    return "denied" if _status_failed(event) else "allowed"


def _network_action(event: Dict[str, Any], decision: str) -> str:
    if decision == "denied":
        return "deny"
    blob = (str(event.get("activity_name") or "") + " "
            + str(event.get("message") or "")).lower()
    if "connect" in blob or "connection" in blob or "session" in blob:
        return "connect"
    return ""


def to_system_events(raw: Any) -> List[Dict[str, str]]:
    """Normalise the non-SAL part of a LogServ OCSF batch into system events.

    Each returned dict describes one gateway/HANA/ICM/network log event in a shape
    modules/logserv_review.py reads. Common keys: CLASS, ACTION, USER, SRC_HOST,
    DEST_HOST, DECISION, STATUS, TEXT (+ DATE/TIME when the event carried a time).
    Per-class keys: gateway adds PROGRAM/GATEWAY_HOST; HANA adds OBJECT/AUDIT_POLICY/
    PRIVILEGE; ICM adds PATH/HTTP_METHOD/HTTP_STATUS; network adds PORT/PROTOCOL.
    Only events a system-log class claims are returned; SAL events are left for
    `to_audit_events`. Tolerant and stdlib-only, exactly like the SAL path.
    """
    events: List[Dict[str, str]] = []
    for event in _events_of(raw):
        cls = _logserv_class(event)
        if not cls:
            continue
        dest = (_first(event, *_DEST_PATHS)
                or _unmapped_or_top(event, _GATEWAY_HOST_KEYS))
        row: Dict[str, str] = {
            "CLASS": cls,
            "ACTION": "",
            "USER": (_first(event, *_USER_PATHS)
                     or _unmapped_or_top(event, ("db_user", "dbuser", "hana_user"))),
            "SRC_HOST": _first(event, *_TERMINAL_PATHS),
            "DEST_HOST": dest,
            "DECISION": "",
            "STATUS": str(event.get("status") or "").strip(),
            "TEXT": str(event.get("message") or event.get("_raw") or "").strip(),
            # Per-class fields, present and empty unless this class fills them, so a
            # detector can read any of them without a KeyError.
            "PROGRAM": "", "GATEWAY_HOST": "", "OBJECT": "", "AUDIT_POLICY": "",
            "PRIVILEGE": "", "PATH": "", "HTTP_METHOD": "", "HTTP_STATUS": "",
            "PORT": "", "PROTOCOL": "",
        }
        if cls == "gateway":
            decision = _gateway_decision(event)
            row["DECISION"] = decision
            row["ACTION"] = _gateway_action(event, decision)
            row["PROGRAM"] = _unmapped_or_top(event, _PROGRAM_KEYS)
            row["GATEWAY_HOST"] = dest
        elif cls == "hana":
            row["DECISION"] = "denied" if _status_failed(event) else "allowed"
            row["ACTION"] = _hana_action(event)
            row["OBJECT"] = _unmapped_or_top(event, _DB_OBJECT_KEYS)
            row["AUDIT_POLICY"] = _unmapped_or_top(event, _AUDIT_POLICY_KEYS)
            row["PRIVILEGE"] = _unmapped_or_top(event, _PRIVILEGE_KEYS)
        elif cls == "icm":
            row["PATH"] = _http_path(event)
            row["HTTP_METHOD"] = _dig_any(event, _HTTP_METHOD_PATHS)
            row["HTTP_STATUS"] = _dig_any(event, _HTTP_STATUS_PATHS)
            row["DECISION"] = _icm_decision(event)
            row["ACTION"] = row["HTTP_METHOD"].lower() or "request"
        elif cls == "network":
            row["PORT"] = _dig_any(event, _PORT_PATHS)
            row["PROTOCOL"] = _dig_any(event, _PROTOCOL_PATHS)
            decision = _network_decision(event)
            row["DECISION"] = decision
            row["ACTION"] = _network_action(event, decision)
        when = _when(event)
        if when:
            row["DATE"], row["TIME"] = when
        events.append(row)
    return events


def _events_of(raw: Any) -> List[Dict[str, Any]]:
    """The list of OCSF events inside whatever the loader handed us.

    Accepts a bare list, or a wrapper object keyed `events` / `data` / `results` /
    `records` (LogServ exports vary), or nothing.
    """
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    if isinstance(raw, dict):
        for key in ("events", "data", "results", "records", "logs"):
            inner = raw.get(key)
            if isinstance(inner, list):
                return [e for e in inner if isinstance(e, dict)]
    return []


def _dig(obj: Any, path: tuple) -> str:
    """Follow a nested key path, returning "" for any miss or non-scalar leaf."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key)
    if cur in (None, "") or isinstance(cur, (dict, list)):
        return ""
    return str(cur).strip()


def _first(obj: Dict[str, Any], *paths: tuple) -> str:
    for path in paths:
        val = _dig(obj, path)
        if val:
            return val
    return ""


def _unmapped_or_top(event: Dict[str, Any], keys: tuple) -> str:
    """A SAP vendor field, read from `unmapped` first, then the top level."""
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        for k in keys:
            v = unmapped.get(k)
            if v not in (None, "") and not isinstance(v, (dict, list)):
                return str(v).strip()
    for k in keys:
        v = event.get(k)
        if v not in (None, "") and not isinstance(v, (dict, list)):
            return str(v).strip()
    return ""


def _when(event: Dict[str, Any]) -> Optional[tuple]:
    """(`YYYY-MM-DD`, `HH:MM:SS`) from the OCSF `time` (epoch ms), or None.

    Returned as strings so log_review._parse_dt — which reads SAP date/time
    strings — handles them unchanged; no epoch branch is needed there.
    """
    raw = event.get("time")
    if raw is None:
        raw = event.get("timestamp")
    if raw is None:
        raw = event.get("_time")           # the raw SAP LogServ epoch field
    try:
        ms = int(float(raw))
    except (TypeError, ValueError):
        return None
    # OCSF `time` is milliseconds since epoch; the raw LogServ `_time` is seconds.
    # Guard either: a value past ~2286 in seconds is really milliseconds.
    seconds = ms / 1000.0 if ms > 10_000_000_000 else float(ms)
    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")


def _event_class(event: Dict[str, Any]) -> str:
    """The normalised audit event-class string for an OCSF event.

    Only the Authentication class is mapped to a specific class here — to
    dialog/RFC logon success or failure, which the logon-based patterns
    (LREV-PAT-001/002/003/009/010) depend on. Every other class returns "" and is
    left to log_review's message/tcode classification, so a debug, table-access or
    external-command event carried by LogServ is still recognised.
    """
    try:
        class_uid = int(event.get("class_uid")) if event.get("class_uid") is not None else None
    except (TypeError, ValueError):
        class_uid = None
    class_name = str(event.get("class_name") or "").lower()
    is_auth = class_uid == _AUTHENTICATION_CLASS_UID or "authentication" in class_name
    if not is_auth:
        return ""
    try:
        status_id = int(event.get("status_id")) if event.get("status_id") is not None else None
    except (TypeError, ValueError):
        status_id = None
    status = str(event.get("status") or "").lower()
    failed = status_id == _STATUS_FAILURE or any(
        w in status for w in ("fail", "error", "denied", "reject"))
    if failed:
        return "dialog_logon_failure"
    protocol = (_dig(event, ("auth_protocol",)) + " "
                + _dig(event, ("logon_type",)) + " "
                + str(event.get("activity_name") or "")).lower()
    if "rfc" in protocol or "cpic" in protocol:
        return "rfc_logon"
    return "dialog_logon"


def to_audit_events(raw: Any) -> List[Dict[str, str]]:
    """Normalise a LogServ OCSF batch into Security-Audit-Log-shaped rows.

    Each returned dict uses the column names log_review already accepts
    (DATE/TIME/USER/TERMINAL/CLIENT/TCODE/EVENT_CLASS/TEXT/RESULT). An event with
    no usable timestamp is still returned (log_review keeps undated events for
    volume but excludes them from time-ordered analysis); an event that is not a
    dict, or carries nothing identifiable, is skipped.
    """
    rows: List[Dict[str, str]] = []
    for event in _events_of(raw):
        # A gateway/HANA/ICM/network event is a system log, not a Security Audit
        # Log row; it is handled by `to_system_events` and must not inflate the
        # audit-log window log_review reviews. An event carrying a SAP tcode or SAL
        # vocabulary is NOT claimed there, so the tcode/message heuristics still run.
        if _logserv_class(event):
            continue
        when = _when(event)
        row: Dict[str, str] = {
            "USER": _first(event, *_USER_PATHS),
            "TERMINAL": _first(event, *_TERMINAL_PATHS),
            "CLIENT": _unmapped_or_top(event, _CLIENT_KEYS),
            "TCODE": _unmapped_or_top(event, _TCODE_KEYS),
            "EVENT_CLASS": _event_class(event),
            "TEXT": str(event.get("message") or event.get("_raw") or "").strip(),
            "RESULT": str(event.get("status") or "").strip(),
        }
        if when:
            row["DATE"], row["TIME"] = when
        # Skip an event that carries nothing we could classify or attribute — it
        # would be an empty row that only inflates counts.
        if not any((row["USER"], row["EVENT_CLASS"], row["TEXT"], row["TCODE"])):
            continue
        rows.append(row)
    return rows
