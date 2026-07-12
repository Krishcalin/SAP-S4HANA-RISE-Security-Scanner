"""
Role Design & Governance Auditor
================================
Checks the QUALITY of the PFCG role concept (DSAG Berechtigungskonzept), which the
existing modules do not cover: `abap_authorizations` reads what risky access a role
grants, `access_risk_analysis` derives SoD from role content, and `iam_advanced`
covers role expiry / dangling assignments / single-vs-composite design and access
reviews. THIS module targets the build-quality gaps that let roles silently grant
the wrong access:

  - SU24 authorization-proposal hygiene: custom (Z*/Y*) transactions with no
    maintained SU24 proposal, so PFCG cannot propose authorizations and admins
    hand-add them (typically over-broad or S_TCODE-only) — the root cause of most
    over-authorized custom roles.
  - Un-generated authorization profiles: roles assigned to users whose PFCG profile
    was never (re)generated (AGR_1016 empty / red status), so the role's authorizations
    are missing or inconsistent with its menu — a change that "looks assigned" but is
    not actually in effect, or is stale.
  - Derived-role structural drift: derived roles whose authorization-object structure
    diverges from their parent/master role (someone edited the derived role directly
    instead of regenerating from the parent), which breaks the master-derived concept
    and hides authorization changes from the master role's owner.

All data is SE16-exportable (AGR_DEFINE, AGR_1251, AGR_1016, USOBT_C/USOBX_C,
AGR_USERS), so the audit stays fully offline. Each check self-skips when absent.

Data sources (exported to CSV):
  - su24_proposals → USOBT_C/USOBX_C: TCODE, OBJECT, CHECK_INDICATOR (CM/C/N/U)
  - role_profiles  → AGR_1016: AGR_NAME, PROFILE (generated profile name; blank = not generated)
  - role_details      → AGR_DEFINE: AGR_NAME, PARENT_AGR (derived-role parent)
  - role_auth_values  → AGR_1251: AGR_NAME, OBJECT, FIELD (auth-object structure)
  - user_roles        → AGR_USERS: assigned roles per user
"""

from typing import Any, Dict, List, Set

from modules.base_auditor import BaseAuditor


class RoleGovernanceAuditor(BaseAuditor):

    CATEGORY = "Role Design & Governance"

    # Organizational-level auth fields whose VALUES legitimately differ parent->derived.
    # They are excluded from the drift comparison because a derived role is SUPPOSED to
    # carry different org values. (MANDT/client is NOT an org level — excluded from this
    # list — and non-org field VALUES are compared, not just object/field presence.)
    _ORG_FIELDS = {"BUKRS", "WERKS", "VKORG", "EKORG", "KOKRS", "GSBER", "VTWEG",
                   "SPART", "LGORT", "PERSA", "PERSK", "BTRTL", "VKBUR", "VKGRP",
                   "$BUKRS", "$WERKS", "$KOKRS", "$CTRLAREA"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_su24_proposal_hygiene()
        self.check_ungenerated_profiles()
        self.check_derived_role_drift()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        if not isinstance(row, dict):
            return ""
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    @staticmethod
    def _is_custom_tcode(tcode: str) -> bool:
        return bool(tcode) and tcode[:1].upper() in ("Z", "Y")

    # =====================================================  SU24 PROPOSAL HYGIENE
    def check_su24_proposal_hygiene(self):
        rows = self.data.get("su24_proposals")
        if not rows:
            return
        # Reduce each tcode to its STRONGEST indicator by explicit precedence, so the
        # verdict is order-independent: maintained (CM/C) = 2 > N (deliberate no-check) = 1
        # > U/blank (unmaintained) = 0. A tcode is a gap only if its strongest rank is 0.
        best_rank: Dict[str, int] = {}
        for r in rows:
            tcode = self._get(r, "TCODE", "NAME", "TRANSACTION", "TCD").upper()
            ci = self._get(r, "CHECK_INDICATOR", "CHECK_IND", "OKFLAG", "MODE",
                           "PROPOSAL", "MAINTAINED").lower()
            if not tcode:
                continue
            if ci in ("cm", "c", "yes", "x", "1", "true", "maintained"):
                rank = 2
            elif ci == "n":
                rank = 1
            else:                       # 'u', blank, or anything unrecognised
                rank = 0
            best_rank[tcode] = max(best_rank.get(tcode, -1), rank)
        unmaintained = sorted(
            t for t, rk in best_rank.items() if self._is_custom_tcode(t) and rk == 0)
        if unmaintained:
            self.finding(
                check_id="RG-SU24-001",
                title="Custom transactions without maintained SU24 authorization proposals",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(unmaintained)} custom (Z*/Y*) transaction(s) have no maintained SU24 "
                    "authorization-default proposal (check indicator U/unmaintained). When such a "
                    "transaction is added to a PFCG role, the Profile Generator cannot propose the "
                    "authorization objects it needs, so administrators either add nothing (the role "
                    "silently under-authorizes) or hand-add broad objects (commonly just S_TCODE, or "
                    "an over-wide manual authorization). Unmaintained SU24 for custom code is the "
                    "single biggest root cause of over-authorized and inconsistent custom roles."
                ),
                affected_items=unmaintained[:50],
                remediation=(
                    "For each custom transaction, maintain SU24 (tcode SU24) so the authorization "
                    "objects checked by the program are proposed with check indicator 'Check/Maintain'. "
                    "Run SU25 step 2 after upgrades to reconcile SAP-delivered SU24 changes. Then "
                    "regenerate the affected roles so the maintained proposals take effect."
                ),
                references=["SAP Help — SU24/SU25 authorization default (proposal) maintenance",
                            "DSAG Prüfleitfaden — Qualität des Berechtigungskonzepts (SU24-Pflege)",
                            "ISO 27001 A.9.2 — access provisioning based on need"],
                details={"count": len(unmaintained)},
            )

    # =====================================================  UN-GENERATED PROFILES
    def check_ungenerated_profiles(self):
        role_profiles = self.data.get("role_profiles")
        if not role_profiles:
            return
        assigned = self._assigned_roles()
        offenders = []
        for r in role_profiles:
            agr = self._get(r, "AGR_NAME", "ROLE", "ROLE_NAME").upper()
            prof = self._get(r, "PROFILE", "PROFILE_NAME", "GENERATED_PROFILE", "PROFN")
            gen_status = self._get(r, "GENERATED", "STATUS", "GEN_STATUS").lower()
            if not agr:
                continue
            ungenerated = (not prof) or gen_status in ("no", "red", "false", "0", "not generated")
            if ungenerated and (not assigned or agr in assigned):
                who = "" if not assigned else " (assigned to users)"
                offenders.append(f"{agr}{who}")
        if offenders:
            verified = bool(assigned)   # was user_roles actually available to confirm assignment?
            assign_clause = ("yet are assigned to users" if verified
                             else "(assignment not verified — no user_roles/AGR_USERS export provided)")
            self.finding(
                check_id="RG-GEN-001",
                title=("Roles with no generated authorization profile are assigned to users" if verified
                       else "Roles with no generated authorization profile"),
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} role(s) have no generated authorization profile (AGR_1016 blank "
                    f"/ PFCG 'red' status) {assign_clause}. A role whose profile was never "
                    "(re)generated does not actually grant its maintained authorizations — the change "
                    "'looks assigned' in AGR_USERS but is not in effect, or the profile is stale versus "
                    "the current role menu/authorizations. This produces both access that silently does "
                    "not work and, after edits, authorizations that differ from what was reviewed."
                ),
                affected_items=offenders[:50],
                remediation=(
                    "Open each role in PFCG and generate the authorization profile (Authorizations tab "
                    "-> Generate) so it reaches 'green' status; use mass generation (SUPC / report "
                    "PFCG_TIME_DEPENDENCY) for many roles. Investigate why profiles were left ungenerated "
                    "in the transport/change process."
                ),
                references=["SAP Help — PFCG profile generation (AGR_1016)",
                            "DSAG Prüfleitfaden — Rollengenerierung / PFCG-Status",
                            "SOX ITGC — access changes are complete and effective"],
                details={"count": len(offenders)},
            )

    # =====================================================  DERIVED-ROLE DRIFT
    def check_derived_role_drift(self):
        role_details = self.data.get("role_details")
        role_auth = self.data.get("role_auth_values")   # AGR_1251: AGR_NAME/OBJECT/AUTH/FIELD/LOW/HIGH
        if not role_details or not role_auth:
            return
        # parent per derived role
        parent_of: Dict[str, str] = {}
        for r in role_details:
            agr = self._get(r, "AGR_NAME", "ROLE", "ROLE_NAME").upper()
            parent = self._get(r, "PARENT_AGR", "PARENT", "PARENT_ROLE", "MASTER_ROLE",
                               "MASTER", "IMH_ROLE").upper()
            if agr and parent and parent != agr:
                parent_of[agr] = parent
        if not parent_of:
            return
        # Per role, the set of non-org (object, field, low, high) tuples. Org-level
        # fields are excluded entirely (their values are meant to differ). For every
        # OTHER field we include the VALUES, so a derived role that broadens an activity
        # (ACTVT 03 -> 01-03) or hand-adds a transaction value is detected as drift — not
        # just added/removed objects.
        struct: Dict[str, Set] = {}
        for r in role_auth:
            agr = self._get(r, "AGR_NAME", "ROLE", "ROLE_NAME").upper()
            obj = self._get(r, "OBJECT", "AUTH_OBJECT", "OBJCT").upper()
            field = self._get(r, "FIELD", "AUTH_FIELD", "FIELDNAME").upper()
            if not agr or not obj:
                continue
            if field in self._ORG_FIELDS:
                continue
            low = self._get(r, "LOW", "VON", "VALUE", "FROM")
            high = self._get(r, "HIGH", "BIS", "TO")
            struct.setdefault(agr, set()).add((obj, field, low, high))
        drifted = []
        for child, parent in parent_of.items():
            if child not in struct or parent not in struct:
                continue
            c, p = struct[child], struct[parent]
            extra = c - p          # objects/fields the derived role has but the parent doesn't
            missing = p - c        # parent structure the derived role dropped
            if extra or missing:
                bits = []
                if extra:
                    bits.append(f"+{len(extra)} added " + ", ".join(sorted(f"{t[0]}:{t[1]}" for t in list(extra)[:3])))
                if missing:
                    bits.append(f"-{len(missing)} missing")
                drifted.append(f"{child} (parent {parent}): " + "; ".join(bits))
        if drifted:
            self.finding(
                check_id="RG-DRV-001",
                title="Derived roles have authorizations that drifted from their parent",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(drifted)} derived role(s) have authorizations that differ from their "
                    "parent/master role — extra or missing authorization objects, OR different "
                    "field VALUES on inherited (non-org) fields (e.g. a broadened activity or a "
                    "hand-added transaction), ignoring org-level field values that are meant to "
                    "differ. In the master-derived concept a derived "
                    "role must inherit the parent's authorizations and differ ONLY in organizational "
                    "field values; a structural difference means someone edited the derived role "
                    "directly instead of changing the parent and re-deriving. That hides the change "
                    "from the master-role owner and can silently grant access the master never had."
                ),
                affected_items=drifted[:50],
                remediation=(
                    "Restore the master-derived relationship: make authorization changes in the PARENT "
                    "role and re-derive/adjust-and-generate the child (PFCG 'Adjust Derived' / mass "
                    "generation). Remove authorizations added directly to derived roles. Audit how the "
                    "direct edits bypassed change control."
                ),
                references=["SAP Help — master (parent)-derived role concept",
                            "DSAG Prüfleitfaden — Ableitungskonzept (derived roles)",
                            "SOX ITGC — authorization changes follow change management"],
                details={"count": len(drifted)},
            )

    # ------------------------------------------------------------------ shared
    def _assigned_roles(self) -> Set[str]:
        """Set of roles assigned to at least one user (upper-cased). Empty set when no
        user_roles export (so the ungenerated-profile check does not gate on assignment)."""
        out: Set[str] = set()
        for r in (self.data.get("user_roles") or []):
            agr = self._get(r, "AGR_NAME", "ROLE", "ROLE_NAME", "ROLES").upper()
            if agr:
                out.add(agr)
        return out
