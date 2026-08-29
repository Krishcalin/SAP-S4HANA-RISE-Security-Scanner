"""
Access Risk Analysis (Segregation of Duties) Auditor
=====================================================
Offline, GRC-style Access Risk Analysis. Resolves — per user, across ALL
assigned roles — the transaction codes and authorization object/field/value
combinations held (from AGR_1251 + AGR_USERS), then evaluates a built-in
Segregation-of-Duties ruleset at the PERMISSION level (not just the transaction
level) to cut false positives. It also flags critical single-function access,
honours documented mitigating controls, and produces a per-user risk profile.

This is deliberately deeper than, and distinct from:
  - iam (Advanced IAM): shallow transaction-code-only SoD with ~7 fixed rules,
    no permission-level precision, no mitigations, no user risk scoring.
  - authz (ABAP Authorization): flags critical auth objects per ROLE. This module
    aggregates to the USER, is SoD-pair oriented, and applies mitigations.

A FUNCTION = a set of Actions (transaction codes) plus the key Permissions
(auth object + field + activity/value) that make the action meaningful, e.g.
"maintain vendor" needs FK01/FK02/XK01/XK02 AND F_LFA1_BUK/F_LFA1_APP with
ACTVT in {01 create, 02 change}. Requiring the permission (not just the tcode)
is what suppresses display-only false positives.

A RISK is either two conflicting Functions (SOD) or a single high-risk Function
(CRITICAL_ACTION / CRITICAL_PERMISSION).

PROCESS COVERAGE, AND WHAT THE PLANT-FLOOR RULES ARE WORTH. The finance and
Basis rules (P2P, O2C, R2R, H2R, BASIS) were each researched and web-verified
object by object. A later block covers the operational processes an ERP
audit reaches next — Manufacturing, Inventory, Quality, Plant Maintenance,
Project System and Warehouse Management — and it is built from a different
kind of source: an operator-supplied S/4HANA design specification that lists
the authorization OBJECTS per module (Q_INSP_WRK, C_AFKO_AWK, C_STUE_BER,
I_AUART, C_PRPS_ART, L_LGNUM …) together with the conflict patterns SAP's own
starter library names. The objects come from that document; the FIELD
vocabulary is working knowledge and is NOT document-verified — which is why
the plant-floor entries carry a `provenance` key saying so, and why several
name more than one object per function.

That distinction is safe rather than merely disclosed, because the matcher is
FAIL-CLOSED: `_field_ok` returns False when a required field is absent from
the export, so a field name that turns out to be wrong makes its rule quieter,
never louder. A mis-guessed field costs coverage. It cannot manufacture a
conflict against a user who does not hold one — the failure direction that
would matter.

Several plant-floor functions are separated by TRANSACTION with a permission
floor (record results vs make the usage decision both sit on the inspection
lot, for instance). SAP's own model calls that a transaction-based rule and
notes it is coarser than an authorization-based one; each such rationale says
which kind it is rather than implying object-level precision it does not have.

A CAPABILITY HAS TWO DOORS AND THIS CHECK USED TO WATCH ONE
An S/4HANA user reaches a business capability through a transaction code OR
through a Fiori app, and only the first passes through S_TCODE. A Fiori app is
launched from a tile, resolved to an OData service, and gated by that service's
start authorization S_SERVICE. So an action gate built solely on S_TCODE cannot
see a conflict whose two halves are Fiori apps — and reports it clean.

The reach is therefore resolved along the chain the estate itself publishes:

    role → tile → app → OData service        (fiori_tiles export)
    role → S_SERVICE grant → OData service    (AGR_1251, same as any object)

and an action named in a rule is held if it matches a transaction the role can
start OR an app/service it can reach. The two are kept in SEPARATE sets with
SEPARATE wildcards on purpose: S_TCODE '*' does not confer Fiori reach and
S_SERVICE '*' does not confer transaction reach, and collapsing them would
fabricate access that the estate does not grant.

A TILE IS TREATED AS REACH, AND THAT ERRS ONE WAY ON PURPOSE
Tile visibility is not authorization: removing a tile leaves the OData endpoint
callable, and holding a tile without the matching S_SERVICE grant does not make
the service startable. So counting a tile as reach can over-report, on an estate
whose tile export and authorization export disagree.

That is the right direction to be wrong in, for two reasons. SAP's own guidance
on ruleset design is that it is better to over-report a conflict and clear it
than to under-report one and never see it. And requiring an explicit S_SERVICE
row would make every estate that does not export S_SERVICE show zero Fiori
reach — a confident silence over an unasked question, which is the failure this
whole module is built to avoid. An over-report is visible and can be cleared; an
under-report looks exactly like a clean result.

What is deliberately NOT done: no app is mapped to an "equivalent" transaction.
That mapping is not in any export here, and inventing it would put users into
conflicts on the strength of a guess. An app reaches only what its own service
reaches, and the permission half of every rule is still checked against
AGR_1251 — reaching a service is not holding the object behind it.

HOLDING A CONFLICT AND HAVING USED IT ARE DIFFERENT CLAIMS
Everything above answers "could this user do both halves". A separate and
stronger question is whether they DID, and change documents answer part of it:
CDHDR records which user changed which object under which transaction, on which
date. A conflict evidenced that way is not a theoretical exposure, it is a
realised one, and it deserves to be read first.

The evidence also cuts the other way, and that turned out to be the sharper
finding. A user can appear in the change log having performed both halves of a
conflict while the authorization export does not show them holding either. On
our own sample that is exactly what LWANG does: change documents record them
running SU01 and PFCG, and their roles carry no AGR_1251 rows at all. Whatever
the explanation - an export that omitted those roles, or access withdrawn after
it was used - every can-do answer about that user is unreliable, and a report
that stays silent presents an unreliable answer as a clean one. ARA-DIDDO-001
names those cases.

THE ASYMMETRY IS THE WHOLE DESIGN. Evidence of performance RAISES severity by
one level. Absence of evidence lowers NOTHING, ever, and the reason is that this
log cannot support the negative:

  - change documents exist only for objects with change logging switched on, so
    the record is partial by construction;
  - a display action leaves no change document at all, so any risk with a read
    half can never be fully evidenced here;
  - the log covers a window, and a conflict exercised before it began looks
    identical to one never exercised.

So "no evidence" is reported as no evidence, never as safety. That is the
opposite of the usage-based de-prioritisation the market sells, and it is
deliberate: SAP's own ruleset guidance is that it is better to over-report a
conflict and clear it than to under-report one and never see it. A tool that
quietly downgrades every unexercised conflict is optimising the axis SAP warns
against, and its clean results are indistinguishable from unasked questions.

Data sources:
  - role_auth_values.csv  → AGR_1251 (AGR_NAME, OBJECT, AUTH, FIELD, LOW, HIGH)
  - user_roles.csv        → AGR_USERS (UNAME, AGR_NAME)  [optional; falls back to
                            per-role analysis when absent]
  - mitigating_controls.csv (optional) → USER, RISK_ID, CONTROL_ID, VALID_TO
  - ara_ruleset.json (optional)        → custom risks to extend/override the built-in set
  - fiori_tiles.csv (optional)         → ROLE, APP_ID, ODATA_SERVICE — the app half
                                         of the action gate; absent on ECC, which
                                         has no launchpad to publish one
  - change_documents.csv (optional)    → CDHDR (USERNAME, TCODE, UDATE) — execution
                                         evidence; raises severity where a conflict
                                         was actually exercised, never lowers it
"""

#: Start authorization for an OData service. A Fiori app is gated by the
#: service behind it, never by S_TCODE, which is why it needs its own gate.
FIORI_START_OBJECT = "S_SERVICE"

from typing import Dict, List, Any, Optional
import json
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from modules.base_auditor import BaseAuditor



def _load_shipped_ruleset(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Read data/sod_ruleset.json, or refuse to run.

    THIS RAISES RATHER THAN RETURNING AN EMPTY LIST, and that is the whole
    point. An empty ruleset does not fail: it reports zero segregation
    conflicts, on every estate, for ever - and zero conflicts is precisely what
    a working control looks like on the page. A packaging mistake that dropped
    this file would therefore produce a clean report over an analysis that never
    happened, which is the failure this module and its coverage checks exist to
    prevent. Refusing to start is the only honest response.
    """
    path = path or (Path(__file__).resolve().parent.parent
                    / "data" / "sod_ruleset.json")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "the shipped SoD ruleset could not be read from %s (%s). Refusing "
            "to continue: an empty ruleset reports zero conflicts on every "
            "estate, which is indistinguishable from a clean one." % (path, exc))
    risks = payload.get("risks") if isinstance(payload, dict) else payload
    if not isinstance(risks, list) or not risks:
        raise RuntimeError(
            "%s contains no 'risks' list. Refusing to continue rather than "
            "reporting zero conflicts against an empty ruleset." % path)
    return risks


class AccessRiskAnalysisAuditor(BaseAuditor):

    CATEGORY = "Access Risk Analysis (SoD)"

    # The verified Segregation-of-Duties / critical-access ruleset is injected
    # below (research → consolidate → web-verify). Each entry:
    #   {risk_id, name, process, risk_type: SOD|CRITICAL_ACTION|CRITICAL_PERMISSION,
    #    severity: CRITICAL|HIGH|MEDIUM,
    #    functions: [{name, actions:[tcode...], permissions:[{object, field, values:[...]}]}],
    #    perm_match: "any"|"all" (optional; default any for SOD, all for CRITICAL_*),
    #    rationale, references:[...]}
    #: The shipped ruleset, loaded from data/sod_ruleset.json.
    #:
    #: It lived here as a 1534-line literal until the library reached 99 risks.
    #: The argument for moving it is the one that moved the finding guidance
    #: into data/finding_details.json: correcting a rule should be an edit to a
    #: content file that the person who knows SAP best can make, not a change
    #: to a Python module. That matters more here than it did there, because
    #: most of these rules were written from general SAP knowledge rather than
    #: object-by-object verification and each says so in `provenance` - the fix
    #: for that is review by somebody who knows the objects, and requiring them
    #: to edit Python is what stops it happening.
    #:
    #: Still a plain class attribute holding a list, so `ARA.RULESET` and the
    #: tests that replace it wholesale behave exactly as before.
    RULESET: List[Dict[str, Any]] = _load_shipped_ruleset()

    _SEV = {"CRITICAL": BaseAuditor.SEVERITY_CRITICAL, "HIGH": BaseAuditor.SEVERITY_HIGH,
            "MEDIUM": BaseAuditor.SEVERITY_MEDIUM, "LOW": BaseAuditor.SEVERITY_LOW}
    #: One level up, for a conflict with evidence it was actually exercised.
    #: There is deliberately no table in the other direction.
    _RAISE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL",
              "CRITICAL": "CRITICAL"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        role_index = self._build_role_index()
        if not role_index:
            return self.findings  # no AGR_1251 export → module self-skips
        self._role_index = role_index   # kept so a finding can name the role that carries a function
        self._units, self._mode = self._build_units(role_index)
        self._mit = self._load_mitigations()
        ruleset = self._effective_ruleset()

        user_risk: Dict[str, List[tuple]] = defaultdict(list)
        for risk in ruleset:
            self._evaluate_risk(risk, user_risk)

        self._emit_user_risk_profile(user_risk)
        self._emit_unexplained_execution()
        return self.findings

    # ------------------------------------------------------------------ parsing
    #: Lazily built by `_fiori_universe`; None until first use.
    _fiori_pub = None
    #: Lazily built by `_execution_index`; None until first use.
    _exec_idx = None

    def _build_role_index(self) -> Optional[Dict[str, Dict[str, Any]]]:
        rows = self.data.get("role_auth_values")
        if not rows:
            return None
        grouped: Dict[tuple, Dict[str, Any]] = {}
        # An authorization instance = one AGR_1251 authorization (the AUTH name). All of
        # an object's field requirements must be met WITHIN one instance, so we must not
        # pool fields from separate authorizations. When the AUTH column is blank (hand-made
        # / partial CSVs), we cannot key on it — collapsing every same-object row onto one
        # synthetic key would merge distinct authorizations and fabricate capabilities
        # (e.g. {INFTY 0008, AUTHC R} + {INFTY 2001, AUTHC W} -> a false "write Basic Pay").
        # Instead we infer authorization boundaries from field repetition: a repeated FIELD
        # within the same (role, object) starts a new instance.
        blank_auth = False
        _cur: Dict[tuple, list] = {}   # (role,obj) -> [synth_key, set(fields_seen)]
        _ctr: Dict[tuple, int] = {}    # (role,obj) -> running instance counter
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("DELETED", row.get("DELETED_FLAG", ""))).strip().upper() in ("X", "TRUE", "1"):
                continue
            role = str(row.get("AGR_NAME", row.get("ROLE", row.get("AGR", "")))).strip()
            obj = str(row.get("OBJECT", row.get("AUTH_OBJECT", ""))).strip().upper()
            auth = str(row.get("AUTH", row.get("AUTHORIZATION", row.get("VARIANT", "")))).strip()
            field = str(row.get("FIELD", row.get("FIELD_NAME", ""))).strip().upper()
            low = str(row.get("LOW", row.get("VALUE", row.get("VON", "")))).strip()
            high = str(row.get("HIGH", row.get("BIS", ""))).strip()
            if not role or not obj or not field:
                continue
            if auth:
                key = (role, obj, auth)
            else:
                blank_auth = True
                ck = (role, obj)
                st = _cur.get(ck)
                if st is None or field in st[1]:      # new authorization (or repeated field)
                    n = _ctr.get(ck, 0) + 1
                    _ctr[ck] = n
                    st = [f"{obj}#auto{n}", set()]
                    _cur[ck] = st
                st[1].add(field)
                key = (role, obj, st[0])
            inst = grouped.setdefault(key, {"role": role, "object": obj, "fields": {}})
            inst["fields"].setdefault(field, []).append((low, high))
        if blank_auth:
            print("    [ARA] Note: AGR_1251 export has blank AUTH names for some rows; "
                  "authorization boundaries were inferred from field repetition. Provide the "
                  "AUTH column for exact permission-level results.")

        roles: Dict[str, Dict[str, Any]] = {}
        for inst in grouped.values():
            r = roles.setdefault(inst["role"], {"tcodes": set(), "star_tcode": False,
                                                "auths": [], "fiori": set(),
                                                "star_service": False})
            r["auths"].append(inst)
            if inst["object"] == "S_TCODE":
                for low, _high in inst["fields"].get("TCD", []):
                    lv = str(low).strip().upper()
                    if lv == "*":
                        r["star_tcode"] = True
                    elif lv:
                        r["tcodes"].add(lv)
            elif inst["object"] == FIORI_START_OBJECT:
                # An OData service start grant. Kept apart from `tcodes` so that
                # its wildcard cannot widen transaction reach, and vice versa.
                for field in ("SRV_NAME", "SERVICE", "NAME"):
                    for low, _high in inst["fields"].get(field, []):
                        lv = str(low).strip().upper()
                        if lv == "*":
                            r["star_service"] = True
                        elif lv:
                            r["fiori"].add(lv)
        self._add_tile_reach(roles)
        return roles

    def _app_service_map(self) -> Dict[str, str]:
        """APP_ID -> OData service, read from the tile export.

        This is the resolution step that makes a Fiori rule expressible at all:
        an app carries no permissions of its own, they belong to the service
        behind it. An app whose tile names no service is left unmapped rather
        than guessed at — `ruleset_coverage` counts those separately.
        """
        mapping: Dict[str, str] = {}
        for row in (self.data.get("fiori_tiles") or []):
            if not isinstance(row, dict):
                continue
            app = str(row.get("APP_ID", row.get("APP", ""))).strip().upper()
            svc = str(row.get("ODATA_SERVICE", row.get("SERVICE", ""))).strip().upper()
            if app and svc:
                mapping[app] = svc
        return mapping

    def _add_tile_reach(self, roles: Dict[str, Dict[str, Any]]) -> None:
        """Add each role's launchpad reach: the apps assigned to it and the
        services behind them.

        A role that appears ONLY in the tile export still gets an entry — a role
        granting Fiori apps and no S_TCODE is an ordinary S/4HANA business role,
        and dropping it would silently exclude its holders from every result.
        """
        # A LIST, not a set: these are dicts and a set of them raises
        # TypeError. It only ever runs when some role holds S_SERVICE '*',
        # which the sample estate does not, so only a test could find it.
        star_services = [r for r in roles.values() if r["star_service"]]
        known_services = set()
        for row in (self.data.get("fiori_tiles") or []):
            if not isinstance(row, dict):
                continue
            role = str(row.get("ROLE", row.get("AGR_NAME", ""))).strip()
            app = str(row.get("APP_ID", row.get("APP", ""))).strip().upper()
            svc = str(row.get("ODATA_SERVICE", row.get("SERVICE", ""))).strip().upper()
            if svc:
                known_services.add(svc)
            if not role:
                continue
            r = roles.setdefault(role, {"tcodes": set(), "star_tcode": False,
                                        "auths": [], "fiori": set(),
                                        "star_service": False})
            if app:
                r["fiori"].add(app)
            if svc:
                r["fiori"].add(svc)
        for row in (self.data.get("odata_auth") or []):
            if isinstance(row, dict):
                name = str(row.get("SERVICE_NAME", row.get("SERVICE", ""))).strip().upper()
                if name:
                    known_services.add(name)
        # A wildcard S_SERVICE grant reaches every service the estate publishes,
        # and through each service the app in front of it — calling the endpoint
        # directly needs no tile. It reaches no service the estate does NOT
        # publish, so the widening is bounded by the export rather than open.
        if star_services and known_services:
            # A MULTIMAP: several apps can sit in front of one service, and
            # inverting the dict directly would keep only the last of them.
            by_service: Dict[str, set] = defaultdict(set)
            for app, svc in self._app_service_map().items():
                by_service[svc].add(app)
            reachable = set(known_services)
            for svc in known_services:
                reachable |= by_service.get(svc, set())
            for r in star_services:
                r["fiori"] |= reachable

    def _build_units(self, role_index: Dict[str, Dict[str, Any]]):
        """Return (units, mode). Aggregate to the USER when AGR_USERS is available,
        otherwise fall back to per-ROLE analysis (a single role holding both sides
        of a conflict is itself a finding)."""
        ur = self.data.get("user_roles")
        if ur:
            umap: Dict[str, List[str]] = defaultdict(list)
            for row in ur:
                if not isinstance(row, dict):
                    continue
                user = str(row.get("UNAME", row.get("USER", row.get("BNAME", "")))).strip()
                role = str(row.get("AGR_NAME", row.get("ROLE", row.get("AGR", "")))).strip()
                if user and role:
                    umap[user].append(role)
            units: Dict[str, Dict[str, Any]] = {}
            for user, roles in umap.items():
                u = {"tcodes": set(), "star_tcode": False, "auths": [],
                     "roles": [], "fiori": set(), "star_service": False}
                for role in roles:
                    ri = role_index.get(role)
                    if ri:
                        u["tcodes"] |= ri["tcodes"]
                        u["star_tcode"] = u["star_tcode"] or ri["star_tcode"]
                        u["fiori"] |= ri["fiori"]
                        u["star_service"] = u["star_service"] or ri["star_service"]
                        u["auths"].extend(ri["auths"])
                        u["roles"].append(role)
                if u["roles"]:
                    units[user] = u
            if units:
                return units, "user"
        # fallback: each role is a pseudo-unit
        return ({r: {**v, "roles": [r]} for r, v in role_index.items()}, "role")

    def _execution_index(self) -> Dict[str, Dict[str, List[str]]]:
        """user (upper) -> tcode (upper) -> the dates it was used on.

        Built from change documents, which are per-user, per-transaction and
        dated. Rows with no user or no transaction are skipped rather than
        bucketed under a blank key: an unattributed change is not evidence
        about anybody.
        """
        if self._exec_idx is None:
            idx: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
            for row in (self.data.get("change_documents") or []):
                if not isinstance(row, dict):
                    continue
                user = str(row.get("USERNAME", row.get("UNAME",
                                   row.get("USER", "")))).strip().upper()
                tcode = str(row.get("TCODE", "")).strip().upper()
                if not user or not tcode:
                    continue
                date = str(row.get("UDATE", row.get("DATE", ""))).strip()
                idx[user][tcode].append(date)
            self._exec_idx = idx
        return self._exec_idx

    def _evidence_window(self) -> str:
        """The span the evidence actually covers, so a reader can see what a
        silence is worth. A conflict exercised before this window began looks
        exactly like one never exercised."""
        dates = sorted(d for by_t in self._execution_index().values()
                       for dl in by_t.values() for d in dl if d)
        return "%s to %s" % (dates[0], dates[-1]) if dates else ""

    def _fiori_evidence_gap(self) -> str:
        """Execution evidence covers transactions only. On an estate that also
        publishes Fiori, saying so is the difference between a stated limit and
        a silent one — the launchpad usage export we take is aggregate and
        carries no user column, so it cannot evidence anybody."""
        if not self._fiori_universe():
            return ""
        return (" It also covers transaction executions only: this estate "
                "publishes a Fiori surface, and the launchpad usage export is "
                "aggregate with no user column, so a conflict exercised through "
                "Fiori would leave no trace here either.")

    def _exercised_functions(self, uid: str, risk: Dict[str, Any]) -> List[str]:
        """Which of a risk's functions this unit has evidence of performing.

        Role mode is excluded: change documents name a USER, and attributing a
        user's action to every role they hold would put the evidence on roles
        whose holders never did anything.
        """
        if self._mode != "user":
            return []
        used = self._execution_index().get(uid.upper())
        if not used:
            return []
        done = []
        for func in (risk.get("functions") or []):
            acts = {str(a).strip().upper() for a in (func.get("actions") or [])
                    if str(a).strip()}
            if acts & set(used):
                done.append(func.get("name", "?"))
        return done

    def _realised_by(self, risk: Dict[str, Any], offenders: List[str]) -> List[str]:
        """Offenders with evidence of performing EVERY function in the risk.

        Every, not any: performing one half of a segregation-of-duties pair is
        ordinary work. The conflict is realised only when the same identity has
        exercised both sides.
        """
        funcs = risk.get("functions") or []
        if not funcs:
            return []
        return sorted(uid for uid in offenders
                      if len(self._exercised_functions(uid, risk)) == len(funcs))

    def _load_mitigations(self) -> Dict[str, set]:
        """user (upper) -> set of mitigated risk_ids (upper); '*' mitigates all.
        Expired mitigations (VALID_TO in the past) are ignored so the risk re-surfaces."""
        mit: Dict[str, set] = defaultdict(set)
        today = datetime.now().date()
        for row in (self.data.get("mitigating_controls") or []):
            if not isinstance(row, dict):
                continue
            user = str(row.get("USER", row.get("USERNAME", row.get("BNAME", row.get("UNAME", ""))))).strip().upper()
            risk_id = str(row.get("RISK_ID", row.get("RISK", row.get("ACCESS_RISK", "*")))).strip().upper() or "*"
            valid_to = str(row.get("VALID_TO", row.get("VALIDTO", row.get("EXPIRY", row.get("TO_DATE", ""))))).strip()
            if not user:
                continue
            if valid_to:
                parsed = self._parse_date(valid_to)
                if parsed is None:
                    # unparseable expiry → fail CLOSED: no proof of validity, do not suppress
                    continue
                if parsed != "UNLIMITED" and parsed.date() < today:
                    continue  # expired (honoured through the whole VALID_TO date)
            mit[user].add(risk_id)
        return mit

    def _effective_ruleset(self) -> List[Dict[str, Any]]:
        ruleset = list(self.RULESET)
        custom = self.data.get("ara_ruleset")
        if isinstance(custom, list):
            by_id = {str(r.get("risk_id", "")).upper(): i for i, r in enumerate(ruleset)}
            for r in custom:
                if not isinstance(r, dict):
                    continue
                rid = str(r.get("risk_id", "")).upper()
                if rid and rid in by_id:
                    ruleset[by_id[rid]] = r      # override
                else:
                    ruleset.append(r)            # extend
        return ruleset

    # ------------------------------------------------------------------ matching
    @staticmethod
    def _covers(pairs: List[tuple], target: str) -> bool:
        """True if a (LOW,HIGH) value set covers `target` (exact / '*' / numeric range).
        Ranges are honoured only for numeric fields, so a lexical range on a symbolic
        field never brackets the target."""
        t = str(target).strip().upper()
        for low, high in pairs:
            lo, hi = str(low).strip().upper(), str(high).strip().upper()
            if lo == "*" or lo == t:
                return True
            # numeric range: compare as integers so unequal-width intervals ('5'..'100')
            # order correctly; a lexical range on a symbolic field never brackets the target
            if hi and lo.isdigit() and hi.isdigit() and t.isdigit() and int(lo) <= int(t) <= int(hi):
                return True
        return False

    def _field_ok(self, inst: Dict[str, Any], req: Dict[str, Any]) -> bool:
        field = str(req.get("field", "")).strip().upper()
        values = req.get("values") or []
        if not field:
            return True  # object presence alone is enough
        pairs = inst["fields"].get(field, [])
        if not pairs:
            return False
        if not values:
            return True
        return any(self._covers(pairs, v) for v in values)

    def _object_ok(self, auths: List[Dict[str, Any]], obj: str, reqs: List[Dict[str, Any]]) -> bool:
        """One authorization instance of `obj` must satisfy ALL its field requirements."""
        obj = obj.upper()
        for inst in auths:
            if inst["object"] != obj:
                continue
            if all(self._field_ok(inst, r) for r in reqs):
                return True
        return False

    def _function_held(self, unit: Dict[str, Any], func: Dict[str, Any], perm_match: str) -> bool:
        # A function is held only if the user holds one of its ACTION transaction codes
        # (or S_TCODE '*') AND satisfies its permission requirement. The action gate is
        # always conjunctive, so "has the payment tcode AND some maintain-level payment auth"
        # is a genuine capability. Across a function's distinct objects the default is
        # perm_match 'any' (holding maintain-level access via any listed object, each still
        # requiring the maintain activity — display is excluded); 'all' is used for the
        # conjunctive critical rules. Within a single object all field requirements must be
        # met by one authorization instance (handled in _object_ok).
        acts = {str(a).strip().upper() for a in (func.get("actions") or []) if str(a).strip()}
        if acts and not self._can_start(unit, acts):
            return False
        perms = func.get("permissions") or []
        if not perms:
            return True
        by_obj: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for p in perms:
            obj = str(p.get("object", "")).strip().upper()
            if obj:
                by_obj[obj].append(p)
        if not by_obj:
            return False  # permissions declared but all object-less → do not fall open to tcode-only
        results = [self._object_ok(unit["auths"], obj, reqs) for obj, reqs in by_obj.items()]
        return all(results) if perm_match == "all" else any(results)

    def _fiori_universe(self) -> set:
        """Every app and service this estate publishes.

        Used to tell a Fiori action apart from a transaction one, which is what
        keeps the two wildcards from leaking into each other.
        """
        if self._fiori_pub is None:
            pub = set()
            for row in (self.data.get("fiori_tiles") or []):
                if isinstance(row, dict):
                    for key in ("APP_ID", "APP", "ODATA_SERVICE", "SERVICE"):
                        v = str(row.get(key, "")).strip().upper()
                        if v:
                            pub.add(v)
            for row in (self.data.get("odata_auth") or []):
                if isinstance(row, dict):
                    v = str(row.get("SERVICE_NAME",
                                    row.get("SERVICE", ""))).strip().upper()
                    if v:
                        pub.add(v)
            self._fiori_pub = pub
        return self._fiori_pub

    def _can_start(self, unit: Dict[str, Any], acts: set) -> bool:
        """Can this unit start ANY of a function's actions, by either door?

        Actions within a function are alternatives — ME21N or the Manage
        Purchase Orders app both reach purchase-order creation — so one hit is
        enough.

        THE TWO WILDCARDS MUST NOT LEAK INTO EACH OTHER, and the first version
        of this method let one of them. S_TCODE '*' short-circuited the whole
        gate, so once Fiori apps became nameable actions it made every holder of
        a super-user role an offender on every Fiori rule — on the sample
        estate, two users with zero tiles between them. A transaction wildcard
        confers no launchpad tile and no S_SERVICE grant; treating it as though
        it did would have manufactured the conflicts this module exists to find
        honestly. A negative control caught it: apps the estate does not publish
        matched users who could not have reached them.

        So S_TCODE '*' satisfies only actions that are NOT published Fiori
        objects. An action the estate publishes as neither is treated as a
        transaction, which is the safe reading of an unknown token — a role
        holding every transaction really does hold it if it is one.
        """
        if unit["tcodes"] & acts:
            return True
        if unit.get("fiori", ()) & acts:
            return True
        return bool(unit["star_tcode"] and (acts - self._fiori_universe()))

    def _risk_offenders(self, risk: Dict[str, Any]) -> List[str]:
        funcs = risk.get("functions") or []
        rtype = str(risk.get("risk_type", "SOD")).upper()
        perm_match = risk.get("perm_match") or ("all" if rtype.startswith("CRITICAL") else "any")
        offenders = []
        for uid, unit in self._units.items():
            if rtype == "SOD":
                if len(funcs) >= 2 and all(self._function_held(unit, f, perm_match) for f in funcs):
                    offenders.append(uid)
            else:
                if funcs and self._function_held(unit, funcs[0], perm_match):
                    offenders.append(uid)
        return offenders

    # --------------------------------------------------------- structured naming
    # Everything below names what the check already decided. It never widens or narrows
    # a decision, and every name is read back out of the loaded export — a unit, role or
    # authorization object that is not in the data is omitted rather than invented.

    def _match_instance(self, auths: List[Dict[str, Any]], obj: str,
                        reqs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """The authorization instance of `obj` that satisfies ALL its field requirements,
        or None. Read-only twin of `_object_ok`: it decides nothing, it recovers WHICH
        instance the check accepted so the finding can name it and quote its values."""
        obj = obj.upper()
        for inst in auths:
            if inst["object"] != obj:
                continue
            if all(self._field_ok(inst, r) for r in reqs):
                return inst
        return None

    @staticmethod
    def _held_qualifier(inst: Dict[str, Any], reqs: List[Dict[str, Any]]) -> Optional[str]:
        """`FIELD=value,...` built from the values the unit ACTUALLY holds, not the values
        the rule asked for. This is what makes the object dangerous and so belongs in the
        qualifier: S_TABU_DIS with ACTVT=* is a different defect from a narrow one."""
        by_field: Dict[str, str] = {}
        for req in reqs:
            field = str(req.get("field", "")).strip().upper()
            if not field or field in by_field:
                continue
            vals = set()
            for low, high in inst["fields"].get(field, []):
                lo, hi = str(low).strip().upper(), str(high).strip().upper()
                if not lo:
                    continue
                vals.add(f"{lo}-{hi}" if hi and hi != lo else lo)
            if vals:
                by_field[field] = f"{field}={','.join(sorted(vals))}"
        return ";".join(by_field[f] for f in sorted(by_field)) or None

    def _risk_objects(self, risk: Dict[str, Any], units: List[str]) -> List[Dict[str, Any]]:
        """Structured affected objects for one access-risk finding.

        The offending user is named first — it is the subject an auditor remediates. In
        per-role fallback mode the unit IS a role, so the role is the subject instead. The
        roles that actually carry a conflicting function and the authorization objects
        that grant it ride along, so the attack-path graph gets
        user → role → auth_object nodes instead of one display string.
        """
        funcs = risk.get("functions") or []
        rtype = str(risk.get("risk_type", "SOD")).upper()
        perm_match = risk.get("perm_match") or ("all" if rtype.startswith("CRITICAL") else "any")
        objs: List[Dict[str, Any]] = []
        seen = set()

        def add(otype: str, name: Any, qualifier: Optional[str] = None) -> None:
            n = str(name or "").strip()
            if not n:
                return                    # a row without a name is omitted, never invented
            key = (otype, n.upper(), qualifier or "")
            if key in seen:
                return
            seen.add(key)
            o: Dict[str, Any] = {"type": otype, "name": n}
            if qualifier:
                o["qualifier"] = qualifier
            objs.append(o)

        unit_type = "user" if self._mode == "user" else "role"
        for uid in units:
            add(unit_type, uid)

        for uid in units:
            unit = self._units.get(uid) or {}
            if self._mode == "user":
                # Only roles that hold a whole conflicting function on their own are named.
                # A capability assembled ACROSS roles has no single guilty role, and naming
                # an arbitrary one of them would be a fabrication.
                for role in unit.get("roles", []):
                    ri = self._role_index.get(role)
                    if ri and any(self._function_held(ri, f, perm_match) for f in funcs):
                        add("role", role)
            auths = unit.get("auths") or []
            for func in funcs:
                by_obj: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
                for p in (func.get("permissions") or []):
                    o = str(p.get("object", "")).strip().upper()
                    if o:
                        by_obj[o].append(p)
                for obj, reqs in by_obj.items():
                    inst = self._match_instance(auths, obj, reqs)
                    if inst is not None:
                        add("auth_object", obj, self._held_qualifier(inst, reqs))
        return objs

    # ------------------------------------------------------------------ emission
    def _evaluate_risk(self, risk: Dict[str, Any], user_risk: Dict[str, List[tuple]]):
        offenders = self._risk_offenders(risk)
        if not offenders:
            return
        rid = str(risk.get("risk_id", "?"))
        residual, mitigated = [], 0
        for uid in offenders:
            if self._mode == "user" and self._is_mitigated(uid, rid):
                mitigated += 1
            else:
                residual.append(uid)
        if not residual:
            return  # every occurrence is covered by a documented mitigating control

        sev_str = str(risk.get("severity", "HIGH")).upper()
        severity = self._SEV.get(sev_str, self.SEVERITY_HIGH)
        realised = self._realised_by(risk, residual)
        if realised:
            # Evidence of performance raises by one level. Nothing lowers it.
            sev_str = self._RAISE.get(sev_str, sev_str)
            severity = self._SEV.get(sev_str, severity)
        rtype = str(risk.get("risk_type", "SOD")).upper()
        kind = "SoD conflict" if rtype == "SOD" else "Critical access"
        funcs = risk.get("functions") or []
        fnames = " ↔ ".join(f.get("name", "?") for f in funcs) if rtype == "SOD" \
            else (funcs[0].get("name", "?") if funcs else "?")

        for uid in residual:
            user_risk[uid].append((rid, sev_str))

        residual.sort()
        unit_word = "user" if self._mode == "user" else "role"
        affected = [self._unit_label(uid) for uid in residual[:100]]
        desc = (
            f"{len(residual)} {unit_word}(s) hold {'both sides of' if rtype == 'SOD' else ''} "
            f"this risk ({fnames}). {risk.get('rationale', '')}".strip()
        )
        if realised:
            desc += (
                f" {len(realised)} of them did not merely hold this conflict but "
                f"EXERCISED both sides: {', '.join(realised[:8])}"
                f"{' and others' if len(realised) > 8 else ''} — change documents "
                f"record them running the transactions, so this is a realised "
                f"exposure rather than a theoretical one, and the severity above "
                f"is raised one level accordingly.")
        elif self._execution_index():
            desc += (
                " The change-document log supplied covers "
                f"{self._evidence_window() or 'an unstated period'} and shows none "
                "of them exercising both sides. That is not evidence they did not: "
                "change documents exist only where change logging is on, display "
                "actions leave none at all, and anything before the window is "
                "invisible. The severity is therefore unchanged, not reduced."
                + self._fiori_evidence_gap())
        if mitigated:
            desc += f" ({mitigated} further {unit_word}(s) suppressed by a documented mitigating control.)"
        if self._mode == "role":
            desc += " (No AGR_USERS export was provided, so analysis is per role — a single role that already contains both functions.)"

        refs = risk.get("references") or [
            "SAP GRC Access Control — Access Risk Analysis (ARA)",
            "SoD ruleset (SAP GRC default / vendor rulesets)",
        ]
        self.finding(
            check_id=f"ARA-{rid}",
            title=f"{kind}: {risk.get('name', rid)}",
            severity=severity,
            category=self.CATEGORY,
            description=desc,
            affected_items=affected,
            remediation=(
                "Remove one side of the conflict for each affected user, or record a formal "
                "mitigating control (dual approval / independent review / monitoring) and add it "
                "to mitigating_controls.csv with a validity date." if rtype == "SOD" else
                "Restrict this critical access to the minimum number of users under least "
                "privilege; where it must remain, attach a documented mitigating control."
            ),
            references=refs,
            details={"total_affected": len(residual), "mitigated": mitigated,
                     "risk_type": rtype, "process": risk.get("process", ""),
                     "realised_by": realised,
                     "realised_count": len(realised),
                     # THREE states, not two: "nobody did it" and "we could not
                     # look" must never render as the same result.
                     "evidence_state": ("unmeasured" if not self._execution_index()
                                        else "realised" if realised
                                        else "no_evidence_in_window"),
                     "evidence_window": self._evidence_window(),
                     "evidence_source": "change_documents (CDHDR)"},
            affected_objects=self._risk_objects(risk, residual[:100]),
            # AGGREGATE: one finding per RISK summarising every user that holds it, so the
            # member list must stay out of its identity. Remediating one of five offenders
            # would otherwise retire this finding and raise a fresh one, resetting the
            # risk's age on every run. check_id already carries the risk id (ARA-<rid>),
            # which is the correct, stable subject here.
            scope="aggregate",
        )

    def _emit_unexplained_execution(self) -> None:
        """Conflicts the change log evidences and the authorization export cannot
        account for.

        This is a reliability finding before it is a risk finding. Two readings
        fit, and both matter:

          - the export is incomplete for those roles, in which case every SoD
            answer about that user is drawn from data that is missing the part
            which would have produced the conflict;
          - the access was genuinely withdrawn between the logged action and the
            snapshot, which is a good outcome and still worth seeing, because it
            is the only place a report shows access that USED to exist.

        Neither reading is asserted here. What is asserted is narrow and
        checkable: the log records this identity performing every function of
        this risk, and the authorization data supplied does not explain how.
        """
        if self._mode != "user" or not self._execution_index():
            return
        unexplained: Dict[str, Dict[str, Any]] = {}
        for risk in self.RULESET:
            funcs = risk.get("functions") or []
            if len(funcs) < 2 or str(risk.get("risk_type", "SOD")).upper() != "SOD":
                continue                      # a single-function rule is not a conflict
            for uid in self._execution_index():
                if uid in self._units and self._risk_held(self._units[uid], risk):
                    continue                  # explained: they hold it, already reported
                if len(self._exercised_functions(uid, risk)) != len(funcs):
                    continue
                rec = unexplained.setdefault(uid, {"risks": [], "tcodes": set()})
                rec["risks"].append(str(risk.get("risk_id", "?")))
                rec["tcodes"] |= set(self._execution_index()[uid])
        if not unexplained:
            return

        no_auth_rows = sorted(u for u in unexplained
                              if not (self._units.get(u) or {}).get("auths"))
        items = []
        for uid in sorted(unexplained):
            rec = unexplained[uid]
            items.append("%s — exercised %s using %s"
                         % (uid, "/".join(sorted(rec["risks"])),
                            ", ".join(sorted(rec["tcodes"])[:6])))
        self.finding(
            check_id="ARA-DIDDO-001",
            title=("%d user(s) exercised a conflict the authorization export "
                   "does not explain" % len(unexplained)),
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "Change documents record these users performing BOTH sides of a "
                "segregation-of-duties risk, and the authorization data supplied "
                "does not show them holding it. The conflict is evidenced; the "
                "access that allowed it is not visible. Two readings fit and this "
                "check does not choose between them: the role export may be "
                "incomplete for these users, or the access may have been "
                "withdrawn after it was used. %s"
                "Either way the segregation-of-duties result for these users is "
                "drawn from data that contradicts the execution record, so a "
                "clean SoD answer about them cannot be relied on — which is the "
                "reason this is reported rather than dropped as a mismatch."
                % ("%d of them %s no authorization rows at all in the export, "
                   "which points at the first reading. "
                   % (len(no_auth_rows), "has" if len(no_auth_rows) == 1 else "have")
                   if no_auth_rows else "")),
            affected_items=items[:100],
            remediation=(
                "1. Re-export AGR_1251 for the named users' roles and confirm "
                "whether the rows were simply missing; a partial role export is "
                "the most common cause and the cheapest to rule out.\n"
                "2. If the rows are genuinely absent, establish how the "
                "transactions were executed: a role deleted since, a firefighter "
                "or emergency-access session, a reference user, or a profile "
                "assigned directly rather than through a role.\n"
                "3. If the access was withdrawn after use, record that — it is "
                "the correct outcome and the change log is the only place the "
                "report can show it.\n"
                "4. Until one of the above explains every name here, treat SoD "
                "results for these users as unverified rather than clean."),
            references=[
                "CDHDR/CDPOS change documents — SAP change logging",
                "AGR_1251 — role authorization values",
                "docs/SOD_REFERENCE.md section 4.3 (technical identities) and 4.5",
            ],
            details={
                "users": sorted(unexplained),
                "users_with_no_authorization_rows": no_auth_rows,
                "evidence_window": self._evidence_window(),
                "evidence_source": "change_documents (CDHDR)",
                "coverage_state": "complete",
            },
            scope="aggregate",
        )

    def _risk_held(self, unit: Dict[str, Any], risk: Dict[str, Any]) -> bool:
        """Does this unit hold every function of the risk? (the can-do answer)"""
        funcs = risk.get("functions") or []
        perm_match = risk.get("perm_match") or (
            "all" if str(risk.get("risk_type", "SOD")).upper().startswith("CRITICAL")
            else "any")
        return bool(funcs) and all(self._function_held(unit, f, perm_match)
                                   for f in funcs)

    def _emit_user_risk_profile(self, user_risk: Dict[str, List[tuple]]):
        if not user_risk or self._mode != "user":
            return
        weight = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        ranked = []
        for uid, risks in user_risk.items():
            score = sum(weight.get(sev, 1) for _rid, sev in risks)
            crit = sum(1 for _r, s in risks if s == "CRITICAL")
            ranked.append((score, len(risks), crit, uid))
        ranked.sort(reverse=True)
        threshold = self.get_config("ara_user_risk_threshold", 2)
        top = [f"{uid} — {n} risk(s), {crit} critical, score {score}"
               for score, n, crit, uid in ranked if n >= threshold]
        top_uids = [uid for _score, n, _crit, uid in ranked if n >= threshold]
        if not top:
            return
        self.finding(
            check_id="ARA-SCORE-001",
            title="Users concentrating multiple access risks (SoD risk profile)",
            severity=self.SEVERITY_HIGH if any(c for _s, _n, c, _u in ranked if c) else self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(top)} user(s) each carry {threshold}+ unmitigated access risks. Users who "
                "concentrate many Segregation-of-Duties conflicts and critical accesses are the "
                "highest-priority remediation targets and the most likely single points of "
                "internal-control failure."
            ),
            affected_items=top[:100],
            remediation=(
                "Prioritise these users for role redesign / access removal. Drive each user's "
                "residual risk count to zero or to a fully-mitigated state, starting with the "
                "critical conflicts."
            ),
            references=["SAP GRC Access Control — Access Risk Analysis (user-level risk)"],
            details={"users_over_threshold": len(top), "threshold": threshold},
            affected_objects=[{"type": "user", "name": uid} for uid in top_uids[:100]],
            # AGGREGATE by construction: this finding IS the population statement ("N users
            # carry 2+ unmitigated risks"). Its members change every time any other ARA
            # risk moves, so binding them into its identity would churn it perpetually.
            scope="aggregate",
        )

    # ------------------------------------------------------------------ helpers
    def _is_mitigated(self, uid: str, risk_id: str) -> bool:
        s = self._mit.get(uid.upper())
        if not s:
            return False
        return risk_id.upper() in s or "*" in s

    def _unit_label(self, uid: str) -> str:
        unit = self._units.get(uid, {})
        if self._mode == "user":
            roles = unit.get("roles", [])
            return f"{uid} ({len(roles)} role(s))"
        return f"Role {uid}"

    @staticmethod
    def _parse_date(date_str: str):
        """Return the string 'UNLIMITED' for a no-expiry sentinel/blank, a datetime for a
        parseable date, or None for an unparseable value (caller fails closed on None).
        Only unambiguous SAP/ISO formats are accepted; slash dates are intentionally not
        parsed (m/d vs d/m is ambiguous) so a mis-typed expiry is not silently transposed."""
        if not date_str or not date_str.strip():
            return "UNLIMITED"
        s = date_str.strip()
        if s in ("99991231", "9999-12-31", "31.12.9999"):
            return "UNLIMITED"
        for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None  # unparseable
