"""Which clients an export actually covered, for the checks that span all of them.

THE DEFECT THIS CLOSES
----------------------
`docs/RISE_SECURITY_MODEL.md` section 3.1, in its own words:

    Standard-user hygiene is cross-client by nature: SAP*/DDIC/SAPCPIC default
    passwords in *all* clients, TMSADM existing only in 000, EARLYWATCH, client
    066 removal... In RISE a customer may only be able to evidence productive
    clients. The importer must accept a per-client scope declaration, and the
    report must distinguish "compliant in the clients we saw" from "compliant."
    Silently passing a cross-client check on partial data is a defect an auditor
    can catch, and it is the kind that ends an engagement.

`system_trust.check_default_passwords` did exactly that. It read `standard_users`,
collected offenders, and returned in silence when there were none. An export
covering only the productive client therefore produced no finding, and the reader
concluded that no standard user anywhere has a default password — when the two
clients most likely to (000 and 001) were never looked at.

`data/rise_reachability.json` already classifies `standard_users` as `partial` and
says in as many words that "a check reading it must say so". Until now nothing did.

WHY THIS DERIVES THE SCOPE INSTEAD OF ASKING FOR IT
---------------------------------------------------
Section 3.1 asks for "a per-client scope declaration". A declaration is a thing a
customer has to know to give, remember to update, and be trusted about — and the
answer is already in the export set. `client_settings` is the T000 client list,
it is a `yes`-reachable source, and every client in the system is in it. So the
scope is the difference between two things we already hold:

    clients T000 names          — the ones that EXIST
    clients the export evidences — the ones we LOOKED AT

A declaration is still accepted where T000 was not supplied, because then the
difference cannot be computed and something has to stand in for it. The basis is
reported either way, so a reader can tell a measured scope from an asserted one.

WHAT IT DOES WHEN IT KNOWS NOTHING
-----------------------------------
With no T000 and no declaration, the well-known SAP clients are the floor: 000,
001 and 066 exist in essentially every ABAP system, and an export naming none of
them has not covered them. That is a weaker claim than the T000 comparison and
`basis` says so — but it is the one claim available, and making no claim would
restore the silence this module exists to end.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

#: SAP's standard clients, and why each matters to a cross-client check. The set
#: lives here rather than in `system_trust` because two modules asking "is this a
#: standard client" from two copies is how they come to disagree; `system_trust`
#: imports it.
WELL_KNOWN_CLIENTS: Dict[str, str] = {
    "000": "SAP's reference client. TMSADM exists only here, and SAP*/DDIC "
           "default passwords survive here longest because nobody logs on.",
    "001": "The delivery copy of 000. Routinely forgotten, routinely still "
           "carrying the delivered credentials.",
    "066": "The EarlyWatch client. SAP's own baseline asks for its removal, and "
           "it cannot be assessed as removed without looking.",
}

#: Column aliases for a client number, matching what the auditors already accept.
CLIENT_KEYS: Sequence[str] = ("CLIENT", "MANDT", "CLNT", "CLIENT_ID",
                             "CLIENT_NUMBER")


def _client_of(row: Any) -> str:
    if not isinstance(row, dict):
        return ""
    upper = {str(k).strip().upper(): v for k, v in row.items() if k is not None}
    for key in CLIENT_KEYS:
        val = upper.get(key)
        if val is not None and str(val).strip():
            return _normalise(str(val))
    return ""


def _normalise(client: str) -> str:
    """`1` and `001` are the same client.

    T000 and an RSUSR003 export do not always agree about leading zeros, and a
    scope computed by set difference would report client 001 as unexamined
    because one file wrote `1`. Three digits is SAP's own width.
    """
    text = str(client).strip()
    return text.zfill(3) if text.isdigit() else text.upper()


def clients_in(rows: Optional[Iterable[Any]]) -> Set[str]:
    """The clients a set of exported rows actually evidences."""
    return {c for c in (_client_of(r) for r in (rows or ())) if c}


def client_inventory(data: Optional[Dict[str, Any]]) -> Optional[Set[str]]:
    """Every client the system has, from T000 — or None if T000 was not supplied.

    None and empty are different, as everywhere else in this codebase: None means
    the inventory is unknown, and an empty set would mean T000 was read and named
    nobody, which is not a thing a running system can do.
    """
    rows = (data or {}).get("client_settings")
    if rows is None:
        return None
    found = clients_in(rows)
    return found or None


def declared_clients(data: Optional[Dict[str, Any]]) -> Optional[Set[str]]:
    """A scope the operator declared, where T000 could not be supplied.

    Read from `run_context`-style keys the scanner already carries, so declaring
    a scope costs a flag rather than a new export. Accepts a list or a
    comma/space separated string, because an operator typing `--clients 000,100`
    should not have to think about which.
    """
    raw = (data or {}).get("_client_scope")
    if raw is None:
        return None
    if isinstance(raw, str):
        parts: List[str] = [p for p in raw.replace(",", " ").split() if p]
    else:
        parts = [str(p) for p in raw]
    found = {_normalise(p) for p in parts if str(p).strip()}
    return found or None


def scope_for(data: Optional[Dict[str, Any]], source_key: str) -> Dict[str, Any]:
    """What one cross-client source covered, and what it did not.

    Returns `examined`, `expected`, `unexamined`, `basis` and `complete`.
    `basis` names where `expected` came from, because a scope measured against
    T000 and one assumed from the well-known clients are different strengths of
    claim and a reader must be able to tell which they were given.
    """
    examined = clients_in((data or {}).get(source_key))

    expected = client_inventory(data)
    basis = "client_settings (T000)"
    if expected is None:
        expected = declared_clients(data)
        basis = "operator-declared client scope"
    if expected is None:
        expected = set(WELL_KNOWN_CLIENTS)
        basis = ("SAP's well-known clients, assumed — no T000 export and no "
                 "declared scope, so this is a floor rather than a measurement")

    # A client evidenced but absent from `expected` is not a gap: T000 exports
    # are sometimes filtered, and 001/066 legitimately appear in an RSUSR003 run
    # that T000 did not list. The question is only what we did NOT look at.
    unexamined = sorted(expected - examined)
    return {
        "examined": sorted(examined),
        "expected": sorted(expected),
        "unexamined": unexamined,
        "basis": basis,
        "complete": not unexamined and bool(examined),
    }


def caveat(scope: Dict[str, Any]) -> str:
    """One sentence a finding can carry, or empty when the scope is complete.

    Phrased as what was covered rather than what was missed, because it is
    appended to a finding whose own claim has to be read as bounded by it.
    """
    if scope["complete"] or not scope["examined"]:
        return ""
    return ("Assessed in client(s) %s only; %s %s not covered by this export, so "
            "this result describes the clients we saw rather than the system."
            % (", ".join(scope["examined"]), ", ".join(scope["unexamined"]),
               "was" if len(scope["unexamined"]) == 1 else "were"))
