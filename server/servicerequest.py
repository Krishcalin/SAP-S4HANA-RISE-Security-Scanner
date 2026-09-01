"""The text to send SAP for a setting the customer is not allowed to change.

WHAT WAS WRONG, ON SCREEN
-------------------------
The finding page told the customer, for every `ticket_to_sap` finding:

    This is SAP's to change. Raise a service request rather than attempting the
    change — the pre-drafted text is below.

There was no pre-drafted text. Nothing in the codebase produced one. What was
below was the check's generic remediation, which for a profile parameter opens

    Set login/min_password_lng to at least the mandated minimum.

— an instruction to perform the change the sentence above it has just said the
customer cannot perform, and precisely what `docs/RISE_SECURITY_MODEL.md` says
never to write: a parameter finding must say "raise with SAP ECS", never
"change this". Forty-seven findings on the reference estate, in the feature the
whole offline-RISE position rests on.

ONE REQUEST PER SYSTEM, NOT PER FINDING
---------------------------------------
Forty-seven tickets is not a remediation plan, it is a way to be ignored. SAP
ECS handles a change request per system and per change window, so the batch
draft groups every parameter on one system into one request with a table. The
single-finding draft still exists, because somebody chasing one setting should
not have to send a document about forty-six others.

WHAT IT REFUSES TO WRITE
------------------------
A value it does not have. A finding whose observation carries no current or
required value produces a request that says what is missing and asks SAP to
confirm the setting, rather than a template with a blank in the place where the
number goes — which is the version that gets sent, bounced, and blamed on the
tool.
"""
from __future__ import annotations

import textwrap
from typing import Any, Dict, List, Optional, Sequence

from server import db

#: The paragraph separator inside a drafted `ask`, named because a bare escape
#: inside a nested string is the kind of thing that survives a review.
NEWLINES = chr(10) * 2

#: What the customer is actually asking for, by deployment mode. RISE variants
#: differ in who operates what, and a request that cites the wrong contract is
#: one SAP rejects before reading the parameter name.
#: A value wider than this gets its own block rather than a table column.
WIDEST_VALUE = 28

#: Where the prose wraps. All of this is pasted into a ticket or an email, and
#: a paragraph arriving as one 160-character line is one somebody reformats
#: before sending — or worse, sends as it is.
WIDTH = 78


def _wrap(prose: str) -> List[str]:
    """Prose at WIDTH.

    Tables and long values are laid out by hand and never come through here:
    wrapping a column destroys it, which is the opposite of the problem this
    solves.
    """
    return textwrap.wrap(prose, WIDTH) or [""]

_CONTRACT = {
    "rise_pce": "RISE with SAP, Private Cloud Edition",
    "rise_tailored": "RISE with SAP, Tailored Option",
    "rise_ecc": "RISE with SAP (ECC in Enterprise Cloud Services)",
    "on_prem": "",
}


def _rows(finding_ids: Optional[Sequence[int]] = None,
          system_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """SAP-owned findings, with the observation that carries their values."""
    where = ["f.remediation_owner = 'ticket_to_sap'"]
    params: List[Any] = []
    if finding_ids:
        where.append("f.id = ANY(%s)")
        params.append(list(finding_ids))
    if system_id is not None:
        where.append("f.system_id = %s")
        params.append(system_id)
    return db.query(
        """
        SELECT f.id, f.check_id, f.severity, f.client, f.state,
               f.provider_ticket_ref, f.first_seen_at,
               cd.title, cd.references_json,
               s.sid, l.deployment_mode, l.name AS landscape,
               (SELECT o.details FROM finding_observation o
                 WHERE o.finding_id = f.id ORDER BY o.id DESC LIMIT 1) AS details
        FROM finding f
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        JOIN landscape l ON l.id = f.landscape_id
        WHERE %s
        ORDER BY f.check_id
        """ % " AND ".join(where), params)


def _setting(row: Dict[str, Any]) -> Dict[str, Any]:
    """Parameter, current and required, out of whatever the module recorded.

    Modules name these differently and some record none of them. Everything is
    optional here on purpose: an absent value becomes a question to SAP rather
    than an empty cell in a table somebody sends anyway.
    """
    detail = row.get("details") or {}

    # AN EMPTY VALUE IS A VALUE. `gw/sec_info` with "" means the parameter is
    # not set, which is the finding — rendering it as a blank cell in a table
    # sent to SAP is the "blank where the number goes" this module exists to
    # avoid, and it reads as a tool that failed rather than a system that is
    # unconfigured.
    current = detail.get("current_value")
    if isinstance(current, str) and not current.strip():
        current = "(not set)"

    return {
        "name": detail.get("parameter") or detail.get("setting")
                or (row["check_id"].split("PARAM-", 1)[-1].lower()
                    if row["check_id"].startswith("PARAM-") else ""),
        "current": current,
        "required": detail.get("ecs_standard") or detail.get("expected_value"),
        "allowed": detail.get("ecs_allowed") or [],
        "source": detail.get("baseline_source") or "",
    }


def _basis(row: Dict[str, Any], setting: Dict[str, Any]) -> str:
    """The document SAP will check the request against.

    The reference carries the note's VERSION and date where the catalogue has
    them, because ECS answers against the note as it stands and a request
    quoting a superseded revision is one that comes back.
    """
    refs = row.get("references_json") or []
    for ref in refs:
        if "Note" in str(ref):
            return str(ref)
    return setting["source"] or "SAP Security Baseline"


def draft(finding_id: int) -> Optional[Dict[str, Any]]:
    """One setting, as a request SAP can act on without a conversation first."""
    rows = _rows(finding_ids=[finding_id])
    if not rows:
        return None
    row = rows[0]
    setting = _setting(row)
    contract = _CONTRACT.get(row["deployment_mode"] or "", "")
    sid = row["sid"] or "the system"

    if setting["current"] is not None and setting["required"]:
        ask = ("Please set %s to %s on %s%s.\n\n"
               "We are not able to make this change ourselves: under %s the "
               "profile parameters of this system are operated by SAP. The "
               "current value is %s."
               % (setting["name"], setting["required"], sid,
                  " client %s" % row["client"] if row["client"] else "",
                  contract or "our contract", setting["current"]))
    else:
        # NO VALUES, SO NO INSTRUCTION. A request with a blank where the number
        # goes is worse than one that asks a question.
        ask = ("Please confirm the current value of %s on %s and advise whether "
               "it meets %s.\n\n"
               "Our review could not read the value from the export supplied, "
               "so this is a request to confirm rather than to change. We are "
               "not able to read or change it ourselves: under %s the profile "
               "parameters of this system are operated by SAP."
               % (setting["name"] or row["check_id"], sid,
                  _basis(row, setting), contract or "our contract"))

    body = "\n".join([
        "Subject: %s configuration request - %s on %s"
        % (contract or "SAP", setting["name"] or row["check_id"], sid),
        "",
        "System:      %s%s" % (sid, " client %s" % row["client"] if row["client"] else ""),
        "Setting:     %s" % (setting["name"] or row["check_id"]),
        "Current:     %s" % (setting["current"] if setting["current"] is not None
                             else "not readable from the export supplied"),
        "Required:    %s" % (setting["required"] or "per the basis below"),
        "Basis:       %s" % _basis(row, setting),
        "Severity:    %s" % row["severity"],
        "Our ref:     finding %d, first observed %s"
        % (row["id"], row["first_seen_at"].date()),
        "",
    ] + [line
         for para in ask.split(NEWLINES)
         for line in _wrap(para) + [""]])
    return {
        "finding_id": row["id"],
        "check_id": row["check_id"],
        "system": sid,
        "setting": setting["name"],
        "has_values": setting["current"] is not None and bool(setting["required"]),
        "provider_ticket_ref": row["provider_ticket_ref"],
        "text": body,
    }


def draft_for_system(system_id: int) -> Optional[Dict[str, Any]]:
    """Every SAP-owned setting on one system, as a single request.

    The unit SAP ECS actually works in. Raising one ticket per parameter is how
    forty-seven true findings become forty-seven ignored emails.
    """
    rows = _rows(system_id=system_id)
    if not rows:
        return None

    sid = rows[0]["sid"] or "the system"
    contract = _CONTRACT.get(rows[0]["deployment_mode"] or "", "") or "our contract"
    client = rows[0]["client"]

    table, unknown, bases = [], [], []
    for row in rows:
        setting = _setting(row)
        basis = _basis(row, setting)
        if basis not in bases:
            bases.append(basis)
        if setting["current"] is not None and setting["required"]:
            table.append((setting["name"], str(setting["current"]),
                          str(setting["required"])))
        else:
            unknown.append("  %s" % (setting["name"] or row["check_id"]))

    body = ["Subject: %s configuration request - %d setting(s) on %s"
            % (contract, len(rows), sid),
            "",
            "System: %s%s" % (sid, " client %s" % client if client else ""),
            "",
            ] + _wrap("Under %s the settings below are operated by SAP and we "
                      "are not able to change them ourselves. Please apply the "
                      "required values." % contract) + [""]
    if table:
        # Sized to the content rather than to a guess: `login/password_hash_
        # algorithm` and its value are both wider than any fixed column, and a
        # table that wraps in the customer's mail client is one SAP retypes.
        w_name = max(len("SETTING"), *(len(t[0]) for t in table))
        # Capped, because one long value should not widen every row. The hash
        # algorithm's value is sixty-four characters and would push the third
        # column past a hundred and ten, where it wraps in a mail client and
        # SAP retypes it. A row too wide for the table prints below it instead.
        wide = [t for t in table if len(t[1]) > WIDEST_VALUE or len(t[2]) > WIDEST_VALUE]
        narrow = [t for t in table if t not in wide]
        if narrow:
            w_cur = max(len("CURRENT"), *(len(t[1]) for t in narrow))
            row_fmt = "  %-{}s  %-{}s  %s".format(w_name, w_cur)
            body += [row_fmt % ("SETTING", "CURRENT", "REQUIRED"),
                     "  " + "-" * (w_name + w_cur + 20)]
            body += [row_fmt % t for t in narrow] + [""]
        for name, current, required in wide:
            body += ["  %s" % name,
                     "      current:  %s" % current,
                     "      required: %s" % required, ""]
    if unknown:
        body += _wrap("The following could not be read from the export "
                      "available to us. Please confirm their current values "
                      "and whether they meet the basis below:") + [""] \
                + unknown + [""]
    body += ["Basis:"] + ["  %s" % b for b in bases]
    body += [""] + _wrap("Raised from an offline configuration review. No "
                         "change has been attempted on our side.")

    return {
        "system_id": system_id, "system": sid,
        "settings": len(rows),
        "with_values": len(table), "to_confirm": len(unknown),
        "text": "\n".join(body),
    }
