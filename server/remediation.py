"""The change itself, for a finding the customer is able to make.

WHERE THIS SITS. The product finds a problem, ranks it, explains the ranking and
names the export that would find more. Then it hands over prose. For a profile
parameter it already knows the name, the current value, the required value and
the SAP Note that mandates it — everything an operator retypes by hand into
RZ10, from a screen that could have written it.

`server/servicerequest.py` covers the other half and is deliberately not
duplicated here: where the setting is SAP's to change under a RISE contract, the
artefact IS the service request, and an RZ10 line the customer cannot apply
would be worse than nothing. This module returns None for those and says why.

WHAT IT NEVER DOES. It does not connect to anything, apply anything, or claim
anything was applied — this product holds no connection to SAP and never will.
It emits text for a human to review and put through change control, and every
pack carries the rollback beside the change, because a proposal without one is
not a proposal an operator can accept.

WHY PARAMETERS FIRST. They are the case where the artefact is EXACT. `details`
carries parameter / current_value / expected_value, so the line to type is not
inferred from prose. A role change needs the authorisation object, field and
value to be safe, and a REVOKE needs the grantee-privilege pairing — which the
graph now holds as `holds_hana_privilege` edges. Both are the natural next kinds
and neither is guessed at here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

#: The owner `modules/rise_ownership.py` assigns to a change the CUSTOMER makes.
#: Read from that module rather than spelled here: the first draft of this file
#: guessed "customer" and every pack came back inapplicable, because the real
#: value is `customer_fixable` and nothing said so until real findings went
#: through it. A vocabulary invented in a second place is a vocabulary that
#: disagrees with the first one silently.
_CUSTOMER_FIXABLE = "customer_fixable"

PROFILE_PARAMETER = "profile_parameter"


def _is_a_value(text: Any) -> bool:
    """Is this something to type into a profile, or a sentence about it?

    A profile parameter's value is a token: a number, a flag, a path, a name.
    Anything carrying a comparison operator, a list, or ordinary English is a
    RULE the baseline states, and a rule pasted into a parameter file is not a
    setting — it is a sentence where a value goes.
    """
    s = str(text).strip()
    if not s or len(s) > 64:
        return False
    if any(ch in s for ch in "<>=") or "," in s:
        return False
    # Two or more words is prose. One token with a space in it is not a profile
    # value either — SAP does not accept "15 (SAP standard)".
    return len(s.split()) == 1


def _qualified_names(row: Dict[str, Any]) -> set:
    """Object names the finding recorded WITH a qualifier.

    `hana_db_security` attaches the debug target as a qualifier rather than as
    its own object, and says why: "the export gives a bare OBJECT_NAME that may
    be a procedure ('DEBUG ON ZFI_PAYMENT_RUN') or a user ('ATTACH DEBUGGER ON
    DBADMIN'), and there is no field that says which — typing it would be a
    guess." A REVOKE has to name the object's KIND, so a grant carrying one of
    these is not a statement this can write.
    """
    import json as _json

    subject = row.get("subject") or row.get("affected_objects")
    if isinstance(subject, str):
        try:
            subject = _json.loads(subject)
        except ValueError:
            return set()
    out = set()
    for obj in (subject or ()):
        if isinstance(obj, dict) and obj.get("qualifier") and obj.get("name"):
            out.add(str(obj["name"]))
    return out


def _detail(row: Dict[str, Any]) -> Dict[str, Any]:
    detail = row.get("details") or row.get("latest_details") or {}
    return detail if isinstance(detail, dict) else {}


def parameter_pack(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """An RZ10 change for one parameter finding, or None.

    None — never a half-filled template — whenever the required value is not
    known. "Set login/min_password_lng to " with a blank where the number goes
    is the failure `servicerequest` already names: it reads as a broken tool,
    and somebody sends it anyway.
    """
    check_id = str(row.get("check_id") or "")
    if not check_id.startswith("PARAM-"):
        return None

    owner = str(row.get("remediation_owner") or "").strip().lower()
    if owner and owner != _CUSTOMER_FIXABLE:
        # SAP's to change. Saying so is more useful than silence: the reader is
        # looking for a fix and there IS one, on the other route.
        return {"kind": PROFILE_PARAMETER, "applicable": False,
                "owner": owner,
                "why": "this parameter is operated by SAP under the contract; "
                       "raise the drafted service request instead",
                "apply": [], "rollback": []}

    detail = _detail(row)
    name = (detail.get("parameter") or detail.get("setting")
            or check_id.split("PARAM-", 1)[-1].lower())
    # `ecs_standard` FIRST, because `expected_value` is prose. On a real finding
    # they read "15" and "15 (SAP standard) or one of: >=15" respectively, and
    # the second one pasted into a profile is not a parameter line — it is a
    # sentence in a file that expects a value.
    required = detail.get("ecs_standard") or detail.get("expected_value")
    current = detail.get("current_value")
    if not name or required in (None, ""):
        return None
    if not _is_a_value(required):
        # A RULE, NOT A VALUE. ">= 15", "at least one of X or Y" and "not 0"
        # each describe an acceptable range; none of them is the thing to type.
        # Emitting one would put a sentence where a number goes, which is the
        # failure `servicerequest` already names — and worse here, because this
        # text is meant to be applied rather than read.
        return {"kind": PROFILE_PARAMETER, "applicable": False,
                "owner": owner or _CUSTOMER_FIXABLE,
                "why": "the baseline states a rule (%s) rather than a single "
                       "value, so the setting is a judgement this tool will not "
                       "make for you" % required,
                "apply": [], "rollback": []}

    # An empty string IS a value — `gw/sec_info` unset is the finding — and the
    # rollback has to be able to say so rather than render a blank.
    shown_current = current
    if isinstance(current, str) and not current.strip():
        shown_current = "(not set)"

    caveats: List[str] = [
        "Review and apply through your normal change control. This tool holds "
        "no connection to SAP and has changed nothing.",
        "A profile parameter takes effect on the next instance restart unless "
        "it is dynamic; confirm which before planning the change window.",
    ]
    allowed = detail.get("ecs_allowed") or []
    if allowed:
        caveats.append("SAP additionally permits: %s." % ", ".join(allowed))
    if detail.get("verification_caveat"):
        caveats.append(str(detail["verification_caveat"]))

    return {
        "kind": PROFILE_PARAMETER,
        "applicable": True,
        "owner": owner or "customer",
        "where": "RZ10 — instance profile of %s" % (row.get("sid") or "the system"),
        "apply": ["%s = %s" % (name, required)],
        # The rollback is the value the scan actually observed, not a guess at
        # a default: restoring "what SAP ships" would be a different change from
        # undoing this one.
        "rollback": ["%s = %s" % (name, shown_current)]
        if shown_current not in (None, "") else [],
        "verify": "Re-run the scan; %s closes when the parameter reports %s."
                  % (check_id, required),
        "source": detail.get("baseline_source") or "",
        "caveats": caveats,
    }


HANA_GRANT = "hana_grant"

#: How many statements to write out. A grant repeated across 60 accounts is a
#: script somebody runs, not a paragraph somebody reads, and the same [:50] cap
#: the modules put on their display lists applies for the same reason.
_MAX_STATEMENTS = 50

_EDGE_SQL = {"holds_hana_privilege": ("REVOKE %s FROM %s;", "GRANT %s TO %s;"),
             "holds_hana_role": ("REVOKE %s FROM %s;", "GRANT %s TO %s;")}


def hana_pack(row: Dict[str, Any],
              neighbourhood: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """`REVOKE` statements for a HANA grant finding, or None.

    THE PAIRS COME FROM THE GRAPH, which is the point. A finding names its
    grantees and its privileges as a flat list, and `REVOKE DATA ADMIN FROM
    <one of these four users>` is not a statement. The `holds_hana_privilege`
    edges record WHICH user holds WHICH privilege, so the statements are
    evidence rather than a cross product.
    """
    check_id = str(row.get("check_id") or "")
    if not check_id.startswith("HANADB-"):
        return None
    if not neighbourhood:
        return None

    pairs = [e for e in (neighbourhood.get("within") or [])
             if e.get("edge_type") in _EDGE_SQL]
    if not pairs:
        return None

    owner = str(row.get("remediation_owner") or "").strip().lower()
    if owner and owner != _CUSTOMER_FIXABLE:
        return {"kind": HANA_GRANT, "applicable": False, "owner": owner,
                "why": "these grants are not the customer's to change under "
                       "the contract; raise a service request instead",
                "apply": [], "rollback": []}

    # A QUALIFIED PRIVILEGE IS DECLINED, in the module's own words: the export
    # gives a bare OBJECT_NAME that may be a procedure ("DEBUG ON
    # ZFI_PAYMENT_RUN") or a user ("ATTACH DEBUGGER ON DBADMIN"), and no field
    # says which. `REVOKE DEBUG ON X FROM Y` has to name the object's KIND, so
    # writing one would be guessing at SQL somebody then runs against a
    # production database.
    # The qualifier is on the OBJECT, not in the edge's name: an edge to a
    # scoped DEBUG grant still reads `-> DEBUG`, so a first version of this
    # checked the edge text, found nothing, and would have written
    # `REVOKE DEBUG FROM CONTRACTOR1;` for a grant that was `DEBUG ON
    # ZFI_PAYMENT_RUN`. That statement revokes a DIFFERENT privilege — the
    # system one instead of the object one — against a production database.
    scoped = _qualified_names(row)
    qualified = [e for e in pairs if str(e.get("to") or "") in scoped]
    usable = [e for e in pairs if e not in qualified]
    if not usable:
        return {"kind": HANA_GRANT, "applicable": False,
                "owner": owner or _CUSTOMER_FIXABLE,
                "why": "every grant here names an object the export does not "
                       "type, so the REVOKE would have to guess whether it is a "
                       "schema, a procedure or a user",
                "apply": [], "rollback": []}

    apply_sql, rollback_sql = [], []
    for edge in usable[:_MAX_STATEMENTS]:
        fmt_apply, fmt_rollback = _EDGE_SQL[edge["edge_type"]]
        apply_sql.append(fmt_apply % (edge["to"], edge["from"]))
        rollback_sql.append(fmt_rollback % (edge["to"], edge["from"]))

    caveats = [
        "Review and apply through your normal change control. This tool holds "
        "no connection to SAP and has changed nothing.",
        "Run as a user holding the privilege WITH ADMIN OPTION; a REVOKE of a "
        "grantable privilege cascades to anything the grantee granted onward, "
        "so confirm the dependent grants before running it.",
    ]
    if qualified:
        caveats.append(
            "%d further grant(s) are not written here: they name an object the "
            "export does not type, and the statement would have to guess "
            "whether it is a schema, a procedure or a user."
            % len(qualified))
    if len(usable) > _MAX_STATEMENTS:
        caveats.append("%d of %d statements shown."
                       % (_MAX_STATEMENTS, len(usable)))

    return {
        "kind": HANA_GRANT,
        "applicable": True,
        "owner": owner or _CUSTOMER_FIXABLE,
        "where": "HANA SQL console — %s" % (row.get("sid") or "the database"),
        "executable": True,
        "apply": apply_sql,
        "rollback": rollback_sql,
        "verify": "Re-run the scan; %s closes when these grants are gone."
                  % check_id,
        "source": "",
        "caveats": caveats,
    }


def pack(row: Dict[str, Any],
         neighbourhood: Optional[Dict[str, Any]] = None
         ) -> Optional[Dict[str, Any]]:
    """The concrete change for one finding, or None if none can be generated.

    None is the honest answer for most of the catalogue today: a pack is only
    emitted where the exact change is KNOWN, and inventing an approximate one
    for the rest would put text into a change request that nobody verified.
    """
    return parameter_pack(row) or hana_pack(row, neighbourhood)
