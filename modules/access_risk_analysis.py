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

Data sources:
  - role_auth_values.csv  → AGR_1251 (AGR_NAME, OBJECT, AUTH, FIELD, LOW, HIGH)
  - user_roles.csv        → AGR_USERS (UNAME, AGR_NAME)  [optional; falls back to
                            per-role analysis when absent]
  - mitigating_controls.csv (optional) → USER, RISK_ID, CONTROL_ID, VALID_TO
  - ara_ruleset.json (optional)        → custom risks to extend/override the built-in set
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime
from modules.base_auditor import BaseAuditor


class AccessRiskAnalysisAuditor(BaseAuditor):

    CATEGORY = "Access Risk Analysis (SoD)"

    # The verified Segregation-of-Duties / critical-access ruleset is injected
    # below (research → consolidate → web-verify). Each entry:
    #   {risk_id, name, process, risk_type: SOD|CRITICAL_ACTION|CRITICAL_PERMISSION,
    #    severity: CRITICAL|HIGH|MEDIUM,
    #    functions: [{name, actions:[tcode...], permissions:[{object, field, values:[...]}]}],
    #    perm_match: "any"|"all" (optional; default any for SOD, all for CRITICAL_*),
    #    rationale, references:[...]}
    RULESET = [
        {
            "risk_id": "P2P-01", "name": "Maintain Vendor Master and Process Vendor Payment",
            "process": "P2P", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A user who can create/change the vendor master AND execute outgoing payments can set up a ghost vendor and pay it, or redirect a real vendor's payment. Canonical AP fraud path. Maintain (ACTVT 01/02) on vendor combined with execute (not display) on payment must fire.",
            "functions": [
                {"name": "Maintain Vendor Master",
                 "actions": ["FK01", "FK02", "XK01", "XK02", "MK01", "MK02", "BP"],
                 "permissions": [{"object": "F_LFA1_APP", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_LFA1_BUK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Process / Execute Vendor Payment",
                 "actions": ["F110", "F-53", "F-58", "F-48"],
                 "permissions": [{"object": "F_REGU_BUK", "field": "FBTCH", "values": ["11", "21"]},
                                 {"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP GRC Access Control default ruleset (Maintain Vendor / Process Payment)", "tcodesearch F_REGU_BUK / F_BKPF_BUK", "authorizationexperts.com F_LFA1_APP"],
        },
        {
            "risk_id": "P2P-02", "name": "Maintain Vendor Bank Details and Run Automatic Payment Program",
            "process": "P2P", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "Highest-value refinement of P2P-01: the same user changes the vendor bank account (IBAN/bank key) and runs F110 that pays it, routing funds to an attacker account with no second pair of eyes. Bank-detail change governed by sensitive-field object F_LFA1_AEN.",
            "functions": [
                {"name": "Maintain Vendor Bank / Sensitive Fields",
                 "actions": ["FK02", "XK02", "BP"],
                 "permissions": [{"object": "F_LFA1_AEN", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Run Automatic Payment Program",
                 "actions": ["F110"],
                 "permissions": [{"object": "F_REGU_BUK", "field": "FBTCH", "values": ["11", "21"]}]},
            ],
            "references": ["SAP GRC / Pathlock P2P ruleset (Maintain Vendor Bank vs Run Payment)", "authorizationexperts.com F_LFA1_AEN", "tcodesearch F_REGU_BUK"],
        },
        {
            "risk_id": "P2P-03", "name": "Create/Change Purchase Order and Release Purchase Order",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who raises/changes a PO and releases (approves) it defeats the purchasing approval control, enabling self-authorized spend. Release authority = holding a release code in M_EINK_FRG (no ACTVT field).",
            "functions": [
                {"name": "Create / Change Purchase Order",
                 "actions": ["ME21N", "ME22N", "ME21", "ME22", "ME25"],
                 "permissions": [{"object": "M_BEST_BSA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_BEST_EKO", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_BEST_EKG", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Release / Approve Purchase Order",
                 "actions": ["ME28", "ME29N"],
                 "permissions": [{"object": "M_EINK_FRG", "field": "FRGCO", "values": []}]},
            ],
            "references": ["SAP GRC default ruleset (PO Create vs PO Release)", "tcodesearch M_EINK_FRG / M_BEST_EKO / M_BEST_BSA"],
        },
        {
            "risk_id": "P2P-04", "name": "Create Purchase Order and Post Goods Receipt",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who creates a PO and posts the goods receipt against it can confirm receipt of goods never delivered, driving the three-way match to auto-approve a fraudulent invoice.",
            "functions": [
                {"name": "Create Purchase Order",
                 "actions": ["ME21N", "ME21", "ME25"],
                 "permissions": [{"object": "M_BEST_BSA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_BEST_WRK", "field": "ACTVT", "values": ["01"]}]},
                {"name": "Post Goods Receipt",
                 "actions": ["MIGO", "MB01", "MIGO_GR", "MB0A"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WMB", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP GRC default ruleset (PO Create vs Goods Receipt)", "tcodesearch M_MSEG_BWA", "authorizationexperts.com m_mseg_bwa"],
        },
        {
            "risk_id": "P2P-05", "name": "Create Purchase Order and Post Vendor Invoice (MIRO)",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who creates a PO and posts the logistics invoice (MIRO) originates both the commitment and the payable, manipulating qty/price to overpay a colluding/fictitious vendor. Breaks the three-way match.",
            "functions": [
                {"name": "Create / Change Purchase Order",
                 "actions": ["ME21N", "ME22N", "ME21"],
                 "permissions": [{"object": "M_BEST_BSA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_BEST_EKO", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Post Vendor Invoice (Invoice Verification)",
                 "actions": ["MIRO", "MIR7", "MIRA", "MIR4"],
                 "permissions": [{"object": "M_RECH_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP GRC default ruleset (PO Create vs Invoice Processing)", "tcodesearch M_RECH_BUK", "SAP KBA 2197290"],
        },
        {
            "risk_id": "P2P-06", "name": "Maintain Vendor Master and Post AP (Non-PO) Vendor Invoice",
            "process": "P2P", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A user who creates/changes vendors and posts AP invoices can create a fictitious vendor and book a non-PO (FI) invoice against it, generating an open payable a later payment run settles. Covers the FB60/F-43 path MIRO risks do not.",
            "functions": [
                {"name": "Maintain Vendor Master",
                 "actions": ["FK01", "FK02", "XK01", "XK02", "BP"],
                 "permissions": [{"object": "F_LFA1_APP", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_LFA1_BUK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Post AP Vendor Invoice",
                 "actions": ["FB60", "FB65", "F-43", "MIRO"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_KOA", "field": "KOART", "values": ["K"]}]},
            ],
            "references": ["SAP GRC default ruleset (Maintain Vendor vs Post AP Invoice)", "authorizationexperts.com f_bkpf_buk / f_lfa1_app"],
        },
        {
            "risk_id": "O2C-01", "name": "Maintain Customer Master and Create Sales Order",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who creates/changes customer master AND creates sales orders can set up a fictitious/altered customer and immediately book sales/deliveries to it, enabling diverted goods or fraudulent revenue with no independent check on the counterparty.",
            "functions": [
                {"name": "Maintain Customer Master",
                 "actions": ["FD01", "FD02", "XD01", "XD02", "VD01", "VD02", "BP"],
                 "permissions": [{"object": "F_KNA1_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_KNA1_APP", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "B_BUPA_RLT", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create / Change Sales Order",
                 "actions": ["VA01", "VA02"],
                 "permissions": [{"object": "V_VBAK_AAT", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_VBAK_VKO", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help V_VBAK_AAT / V_VBAK_VKO", "SAP KBA 2814708 B_BUPA_RLT", "SAP GRC default ruleset O2C"],
        },
        {
            "risk_id": "O2C-02", "name": "Maintain Customer Credit Limit and Release Credit-Blocked Sales Order",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who maintains credit limits/risk category AND releases credit-blocked SD documents defeats credit control: raise a limit or release regardless, pushing through orders that should be blocked and concealing over-exposure.",
            "functions": [
                {"name": "Maintain Customer Credit Limit",
                 "actions": ["FD32", "UKM_BP"],
                 "permissions": [{"object": "F_KNKA_KKB", "field": "ACTVT", "values": ["02"]},
                                 {"object": "F_KNKA_MAN", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Release Credit-Blocked SD Document",
                 "actions": ["VKM1", "VKM3", "VKM4"],
                 "permissions": [{"object": "V_KNKK_FRE", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["Tricentis LiveCompare Audit Template B.07", "SAP Help F_KNKA_KKB", "SAP KBA V_KNKK_FRE (VKM3)"],
        },
        {
            "risk_id": "O2C-03", "name": "Post/Clear Incoming Customer Payments and Maintain Customer Master",
            "process": "O2C", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "Classic cash-misappropriation/lapping conflict: a user who applies/clears incoming customer payments AND maintains the customer master can divert a payment then cover the shortfall by altering the account, resetting cleared items (FBRA), or writing it off.",
            "functions": [
                {"name": "Post / Clear Incoming Customer Payments",
                 "actions": ["F-28", "FB05", "F-32", "FBRA"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_BKPF_KOA", "field": "KOART", "values": ["D"]}]},
                {"name": "Maintain Customer Master",
                 "actions": ["FD01", "FD02", "XD01", "XD02", "BP"],
                 "permissions": [{"object": "F_KNA1_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "B_BUPA_RLT", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help F_BKPF_BUK", "SAP GRC default ruleset (Process Customer Payments & Maintain Customer)", "SAP KBA 2814708"],
        },
        {
            "risk_id": "O2C-04", "name": "Maintain Pricing/Condition Records and Create Sales Order",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who maintains pricing/condition records AND creates sales orders can grant unauthorized prices/discounts and consume them on their own orders — kickbacks, under-billing of favored customers, margin erosion.",
            "functions": [
                {"name": "Maintain Pricing / Condition Records",
                 "actions": ["VK11", "VK12", "VK31", "VK32"],
                 "permissions": [{"object": "V_KOND_VEA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_KONH_VKS", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create / Change Sales Order",
                 "actions": ["VA01", "VA02"],
                 "permissions": [{"object": "V_VBAK_AAT", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_VBAK_VKO", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP KBA 3549883 V_KOND_VEA", "SAP Help V_KONH_VKS", "SAP GRC default ruleset O2C Pricing"],
        },
        {
            "risk_id": "O2C-05", "name": "Post Billing Document and Maintain Customer Master",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who posts billing documents AND maintains the customer master can invoice/credit-memo a customer whose terms, bank data, or existence they control — fabricated invoices/credit memos routed to an account they set up.",
            "functions": [
                {"name": "Post Billing Document",
                 "actions": ["VF01", "VF02", "VF04"],
                 "permissions": [{"object": "V_VBRK_VKO", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_VBRK_FKA", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Maintain Customer Master",
                 "actions": ["FD01", "FD02", "XD01", "XD02", "VD01", "VD02", "BP"],
                 "permissions": [{"object": "F_KNA1_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "B_BUPA_RLT", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help V_VBRK_VKO / V_VBRK_FKA", "SAP KBA 2838706", "SAP GRC default ruleset O2C Billing"],
        },
        {
            "risk_id": "O2C-06", "name": "Create Sales Order and Release Own Credit-Blocked Order",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A sales user who creates orders AND releases credit-blocked SD documents self-approves their own credit blocks: any order tripping the credit check can be released by the same person, nullifying the credit safeguard through delivery and billing.",
            "functions": [
                {"name": "Create / Change Sales Order",
                 "actions": ["VA01", "VA02"],
                 "permissions": [{"object": "V_VBAK_AAT", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_VBAK_VKO", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Release Credit-Blocked SD Document",
                 "actions": ["VKM1", "VKM3", "VKM4"],
                 "permissions": [{"object": "V_KNKK_FRE", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["Tricentis LiveCompare Audit Template B.07", "SAP KBA V_KNKK_FRE (VKM3)", "SAP GRC default ruleset O2C Create Order & Release"],
        },
        {
            "risk_id": "R2R-01", "name": "Maintain G/L Account Master Data and Post Journal Entries",
            "process": "R2R", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A user who creates/changes G/L account master AND posts accounting documents can set up a fictitious/suspense account and post fraudulent or concealing journals to it. Classic financial-statement-fraud and misappropriation-concealment SoD.",
            "functions": [
                {"name": "Maintain G/L Account Master Data",
                 "actions": ["FS00", "FS01", "FS02", "FSS0", "FSP0"],
                 "permissions": [{"object": "F_SKA1_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_SKA1_KTP", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_SKA1_AEN", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Post Journal Entry / Manual G/L Posting",
                 "actions": ["FB01", "FB50", "F-02", "FB01L", "FB50L"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_KOA", "field": "KOART", "values": ["S"]}]},
            ],
            "references": ["tcodesearch F_BKPF_BUK", "authorizationexperts.com f_ska1_buk / f_ska1_ktp / f_bkpf_koa"],
        },
        {
            "risk_id": "R2R-02", "name": "Maintain G/L Account Master Data and Open/Close Posting Periods",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who maintains G/L master AND opens/closes posting periods (OB52) can create/alter accounts and reopen a closed period to back-date entries into them, defeating period-end cutoff and master-data governance.",
            "functions": [
                {"name": "Maintain G/L Account Master Data",
                 "actions": ["FS00", "FSS0", "FSP0", "FS01", "FS02"],
                 "permissions": [{"object": "F_SKA1_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "F_SKA1_KTP", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Open / Close Posting Periods",
                 "actions": ["OB52"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]},
                                 {"object": "F_BKPF_BUP", "field": "BRGRU", "values": []}]},
            ],
            "references": ["blogs.sap.com auth group OB52", "SAP community OB52 auth check", "authorizationexperts.com f_ska1_buk"],
        },
        {
            "risk_id": "R2R-03", "name": "Enter/Park and Post Journal Entries (four-eyes bypass)",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "Parking splits preparation (park/enter) from approval (post). A user who can both park/enter and post/release parked documents defeats the four-eyes control on manual JE — a key SOX control. Park=ACTVT 77, post=ACTVT 01; distinguish park-only from post.",
            "functions": [
                {"name": "Enter / Park Journal Entry",
                 "actions": ["FV50", "FBV1", "FBV2", "F-65"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["77"]},
                                 {"object": "F_BKPF_KOA", "field": "ACTVT", "values": ["77"]}]},
                {"name": "Post Journal Entry / Post Parked Document",
                 "actions": ["FBV0", "FB01", "FB50", "F-02"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_KOA", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["blogs.sap.com separate park & post role", "SAP community F_BKPF_BUK parking/posting", "tcodesearch FV50"],
        },
        {
            "risk_id": "R2R-04", "name": "Maintain Exchange Rates and Post Journal Entries",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who maintains exchange rates (OB08/TCURR) AND posts accounting documents can manipulate the FX rate used on a foreign-currency posting/revaluation to book fictitious gains, understate liabilities, or shift value between entities, then post — with no independent rate control.",
            "functions": [
                {"name": "Maintain Exchange Rates",
                 "actions": ["OB08", "OB07", "OBBS"],
                 "permissions": [{"object": "S_EXCHRATE", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Post Journal Entry / Manual G/L Posting",
                 "actions": ["FB01", "FB50", "F-02", "FB01L", "FB50L"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_KOA", "field": "KOART", "values": ["S"]}]},
            ],
            "references": ["tcodesearch S_EXCHRATE", "authorizationexperts.com s_exchrate", "SAP community concurrent exchange-rate maintenance"],
        },
        {
            "risk_id": "R2R-05", "name": "Open/Close Posting Periods and Post Journal Entries",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who opens/closes posting periods (OB52) AND posts accounting documents can reopen a closed period to back-date, or push entries into a still-open period, then post unauthorized journals — defeating period-end cutoff and month-end close.",
            "functions": [
                {"name": "Open / Close Posting Periods",
                 "actions": ["OB52"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]},
                                 {"object": "F_BKPF_BUP", "field": "BRGRU", "values": []}]},
                {"name": "Post Journal Entry / Manual G/L Posting",
                 "actions": ["FB01", "FB50", "F-02", "FB01L", "FB50L"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_KOA", "field": "KOART", "values": ["S"]}]},
            ],
            "references": ["blogs.sap.com auth group OB52", "SAP community open/close posting periods", "tcodesearch F_BKPF_BUK"],
        },
        {
            "risk_id": "H2R-01", "name": "Maintain HR Master Data and Execute Payroll Run",
            "process": "H2R", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A user who changes pay-relevant master data (Basic Pay IT0008, Recurring Payments/Deductions IT0014, Additional Payments IT0015) AND executes the payroll driver can inflate their own or an accomplice's pay and process it into a live payroll result with no review. Flagship H2R SoD.",
            "functions": [
                {"name": "Maintain HR Master Data",
                 "actions": ["PA30", "PA40"],
                 "permissions": [{"object": "P_ORGIN", "field": "AUTHC", "values": ["W", "E", "S", "*"]},
                                 {"object": "P_ORGIN", "field": "INFTY", "values": ["0008", "0014", "0015", "*"]}]},
                {"name": "Execute Payroll Run",
                 "actions": ["PC00_M99_CALC", "PC00_M10_CALC"],
                 "permissions": [{"object": "P_PCLX", "field": "AUTHC", "values": ["U"]},
                                 {"object": "P_ABAP", "field": "COARS", "values": ["1", "2"]}]},
            ],
            "references": ["SAP Help P_ORGIN (INFTY/AUTHC)", "SAP Help AUTHC values R/M/W/E/D/S", "sap-tcodes PC00_M99_CALC", "sapsecuritypages P_ABAP"],
        },
        {
            "risk_id": "H2R-02", "name": "Maintain Employee Bank Details and Run Payroll / Generate Payments",
            "process": "H2R", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A user who changes Bank Details (IT0009) AND runs payroll or creates the payment medium/DME file can redirect net pay to an attacker account and push the payment out in the same period. Classic payroll-diversion fraud.",
            "functions": [
                {"name": "Maintain Employee Bank Details",
                 "actions": ["PA30", "PA40"],
                 "permissions": [{"object": "P_ORGIN", "field": "INFTY", "values": ["0009"]},
                                 {"object": "P_ORGIN", "field": "AUTHC", "values": ["W", "E", "S", "*"]}]},
                {"name": "Run Payroll and Generate Payments",
                 "actions": ["PC00_M99_CALC", "PC00_M99_CIPE", "PC00_M99_CDTA", "PC00_M99_FPAYM"],
                 "permissions": [{"object": "P_PYEVRUN", "field": "ACTVT", "values": ["01", "10"]},
                                 {"object": "P_PCLX", "field": "AUTHC", "values": ["U"]}]},
            ],
            "references": ["sap-tcodes PC00_M99_CIPE", "dan852 PC00_M99_CDTA/FPAYM", "authorizationexperts.com p_pyevrun", "SAP Help P_ORGIN"],
        },
        {
            "risk_id": "H2R-03", "name": "Maintain Personnel Actions (Hire/Terminate) and Maintain Time Data",
            "process": "H2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who runs personnel actions (hire/rehire/terminate via PA40, creating IT0000/0001/0002/0008) AND enters time data (IT2xxx via PA61/PA62) can create a ghost employee and book the hours that generate pay for it.",
            "functions": [
                {"name": "Maintain Personnel Actions (Hire/Terminate)",
                 "actions": ["PA40", "PA30"],
                 "permissions": [{"object": "P_ORGIN", "field": "INFTY", "values": ["0000", "0001", "0002", "0008", "*"]},
                                 {"object": "P_ORGIN", "field": "AUTHC", "values": ["W", "E", "S", "*"]}]},
                {"name": "Maintain Time Data",
                 "actions": ["PA61", "PA62"],
                 "permissions": [{"object": "P_ORGIN", "field": "INFTY", "values": ["2001", "2002", "2010", "2*"]},
                                 {"object": "P_ORGIN", "field": "AUTHC", "values": ["W", "E", "S", "*"]}]},
            ],
            "references": ["saptcodelist PA62", "sap-tcodes PA51 (display)", "SAP Help P_ORGIN INFTY/AUTHC"],
        },
        {
            "risk_id": "H2R-04", "name": "Execute Payroll Run and Post Payroll Results to Accounting",
            "process": "H2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "Separating who runs/simulates payroll from who creates and posts the posting run to FI is a standard payroll control. A user holding both can push fraudulent or unreviewed payroll results straight into the GL with no four-eyes check between calculation and posting.",
            "functions": [
                {"name": "Execute / Simulate Payroll Run",
                 "actions": ["PC00_M99_CALC", "PC00_M99_CALC_SIMU", "PC00_M10_CALC"],
                 "permissions": [{"object": "P_PCLX", "field": "AUTHC", "values": ["U"]},
                                 {"object": "P_ABAP", "field": "REPID", "values": []}]},
                {"name": "Post Payroll Results to Accounting",
                 "actions": ["PC00_M99_CIPE"],
                 "permissions": [{"object": "P_PYEVRUN", "field": "ACTVT", "values": ["01", "10"]}]},
            ],
            "references": ["sap-tcodes PC00_M99_CIPE", "sapdatasheet PC00_M99_CALC_SIMU", "authorizationexperts.com p_pyevrun"],
        },
        {
            "risk_id": "BASIS-01", "name": "User Administration vs Authorization/Profile Administration",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A single user who administers user master records (create users, reset passwords, assign roles/profiles) AND defines what roles/profiles grant (build authorizations) can grant themselves unlimited access with no four-eyes control. Foundational Basis privilege-escalation SoD.",
            "functions": [
                {"name": "User Administration (create/change users, assign roles & profiles)",
                 "actions": ["SU01", "SU10", "SU12"],
                 "permissions": [{"object": "S_USER_GRP", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_USER_AGR", "field": "ACTVT", "values": ["22"]},
                                 {"object": "S_USER_PRO", "field": "ACTVT", "values": ["22"]}]},
                {"name": "Authorization & Profile Administration (define role/profile content)",
                 "actions": ["PFCG", "SU02", "SU03", "SU24"],
                 "permissions": [{"object": "S_USER_AGR", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_USER_AUT", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_USER_PRO", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help S_USER_GRP (CLASS/ACTVT)", "SAP KBA 2658656", "SAP Help S_USER_AGR (ACTVT 01/02/22)", "authorizationexperts.com s_user_agr"],
        },
        {
            "risk_id": "BASIS-02", "name": "Maintain Role vs Assign Role to User",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "The person who BUILDS a role (its transactions and authorization values) must not be the person who ASSIGNS it to users. Combined, a user could insert powerful access into a role and assign it to their own account, bypassing role-owner approval. Build-vs-assign split at role granularity.",
            "functions": [
                {"name": "Maintain Role Content (build role menu & authorizations)",
                 "actions": ["PFCG"],
                 "permissions": [{"object": "S_USER_AGR", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_USER_TCD", "field": "TCD", "values": ["*"]}]},
                {"name": "Assign Role to User",
                 "actions": ["SU01", "SU10", "PFCG", "PFUD"],
                 "permissions": [{"object": "S_USER_AGR", "field": "ACTVT", "values": ["22"]},
                                 {"object": "S_USER_GRP", "field": "ACTVT", "values": ["22"]}]},
            ],
            "references": ["SAP Help / authorizationexperts.com S_USER_AGR (01/02 vs 22)", "SAP Help S_USER_TCD (TCD)", "SAP Help S_USER_SAS"],
        },
        {
            "risk_id": "BASIS-03", "name": "ABAP Development vs Transport Release/Import to Production",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A developer who writes/changes ABAP AND releases their own transports and imports them into production defeats change-management four-eyes control, moving untested or malicious code (backdoors) into PRD unreviewed.",
            "functions": [
                {"name": "Develop / Maintain ABAP Repository Objects",
                 "actions": ["SE38", "SE80", "SE24", "SE37", "SE11"],
                 "permissions": [{"object": "S_DEVELOP", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Release & Import Transport Requests to Production",
                 "actions": ["SE09", "SE10", "SE01", "STMS"],
                 "permissions": [{"object": "S_TRANSPRT", "field": "ACTVT", "values": ["43"]},
                                 {"object": "S_CTS_ADMI", "field": "CTS_ADMFCT", "values": ["IMPA", "IMPS"]}]},
            ],
            "references": ["SAP Help S_DEVELOP; SAP Note 65968", "authorizationexperts.com s_transprt (ACTVT 43)", "SAP Help S_CTS_ADMI (IMPA/IMPS)"],
        },
        {
            "risk_id": "BASIS-04", "name": "Maintain Table Data vs Administer Security Audit Log",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A user who directly changes sensitive table contents AND configures/deactivates the logging that records those changes (Security Audit Log via SM19/RSAU_CONFIG) can make and then conceal fraudulent changes. Separating data maintenance from audit administration preserves an untampered trail.",
            "functions": [
                {"name": "Maintain Table Contents Directly",
                 "actions": ["SM30", "SM31", "SM34", "SE16N"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]},
                                 {"object": "S_TABU_NAM", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Administer Security Audit Log / Change Logging",
                 "actions": ["SM19", "RSAU_CONFIG"],
                 "permissions": [{"object": "S_ADMI_FCD", "field": "S_ADMI_FCD", "values": ["AUDA"]}]},
            ],
            "references": ["SAP Help S_TABU_DIS / S_TABU_NAM", "SAP Help Configuring the Security Audit Log (SM19/RSAU_CONFIG)", "SAP community S_ADMI_FCD AUDA/AUDD"],
        },
        # ── Batch B: procure-to-pay depth. SAP's own delivered rulebook is
        # roughly one third P2P, and six risks did not reflect that.
        {
            "risk_id": "P2P-07", "name": "Maintain Purchasing Info Record and Create Purchase Order",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "The info record carries the price the purchase order defaults to. A user who can set the price and then raise the order against it fixes what the company pays without a second pair of eyes, and the order looks entirely ordinary because the price it used is the one on file.",
            "functions": [
                {"name": "Maintain Purchasing Info Record",
                 "actions": ["ME11", "ME12", "ME15"],
                 "permissions": [{"object": "M_EINF_EKG", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_EINF_EKO", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create / Change Purchase Order",
                 "actions": ["ME21N", "ME22N", "ME21", "ME22"],
                 "permissions": [{"object": "M_BEST_BSA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_BEST_EKO", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help MM Purchasing: M_EINF_EKG / M_EINF_EKO (purchasing info record)",
                           "SAP Help MM Purchasing: M_BEST_BSA / M_BEST_EKO"],
        },
        {
            "risk_id": "P2P-08", "name": "Create Purchase Requisition and Release It",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "The requisition release strategy is the first approval in the procurement chain. Raising the demand and approving it are the same person's actions here, so the release step records an approval that never happened independently and every downstream control inherits an unapproved requirement.",
            "functions": [
                {"name": "Create / Change Purchase Requisition",
                 "actions": ["ME51N", "ME52N", "ME51", "ME52"],
                 "permissions": [{"object": "M_BANF_BSA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_BANF_EKG", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Release Purchase Requisition",
                 "actions": ["ME54N", "ME55", "ME54"],
                 "permissions": [{"object": "M_EINK_FRG", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["SAP Help MM Purchasing: M_BANF_BSA / M_BANF_EKG (requisition)",
                           "SAP Help MM Purchasing: M_EINK_FRG (release code)"],
        },
        {
            "risk_id": "P2P-09", "name": "Post Goods Receipt and Post Vendor Invoice",
            "process": "P2P", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "Three-way match is the control: someone orders, someone confirms receipt, someone verifies the invoice. A user holding the receipt and the invoice confirms goods that never arrived and then pays for them, and the match succeeds because both sides of it were entered by the same person.",
            "functions": [
                {"name": "Post Goods Receipt",
                 "actions": ["MIGO", "MB01", "MB0A"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WWE", "field": "ACTVT", "values": ["01"]}]},
                {"name": "Post Vendor Invoice (Logistics Invoice Verification)",
                 "actions": ["MIRO", "MIR7", "MRHR"],
                 "permissions": [{"object": "M_RECH_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_RECH_WRK", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP Help MM: M_MSEG_BWA / M_MSEG_WWE (goods movement)",
                           "SAP Help MM: M_RECH_BUK / M_RECH_WRK (invoice verification)"],
        },
        {
            "risk_id": "P2P-10", "name": "Release Blocked Invoice and Execute Vendor Payment",
            "process": "P2P", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "An invoice is blocked because something failed the match - price, quantity or date. Releasing that block and then running the payment removes the only control standing between a disputed invoice and the money leaving, and the release leaves a record showing the discrepancy was reviewed.",
            "functions": [
                {"name": "Release Blocked Invoice",
                 "actions": ["MRBR"],
                 "permissions": [{"object": "M_RECH_AKZ", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Execute Vendor Payment",
                 "actions": ["F110", "F-53", "F-58"],
                 "permissions": [{"object": "F_REGU_BUK", "field": "FBTCH", "values": ["11", "21"]}]},
            ],
            "references": ["SAP Help MM: M_RECH_AKZ (invoice release)",
                           "SAP Help FI: F_REGU_BUK (automatic payment, FBTCH)"],
        },
        {
            "risk_id": "P2P-11", "name": "Maintain Material Master Valuation and Post Goods Movement",
            "process": "P2P", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "The material master's accounting view carries the valuation price against which every goods movement posts. Changing the price and then moving the stock writes an inventory value the person choosing it also decided, which is how inventory shrinkage is concealed as a revaluation.",
            "functions": [
                {"name": "Maintain Material Master (Accounting / Valuation)",
                 "actions": ["MM01", "MM02", "MR21"],
                 "permissions": [{"object": "M_MATE_BUK", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_MATE_MAT", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Post Goods Movement",
                 "actions": ["MIGO", "MB1A", "MB1B", "MB1C"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP Help MM: M_MATE_BUK / M_MATE_MAT (material master)",
                           "SAP Help MM: M_MSEG_BWA (movement type)"],
        },
        # ── Batch C: order-to-cash depth.
        {
            "risk_id": "O2C-07", "name": "Create Sales Order and Post Goods Issue",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "Raising the order and issuing the goods against it moves inventory out of the business on one person's authority. Where the customer is fictitious or the order is later cancelled, the stock has already gone and the only record of why is the document its creator wrote.",
            "functions": [
                {"name": "Create / Change Sales Order",
                 "actions": ["VA01", "VA02"],
                 "permissions": [{"object": "V_VBAK_AAT", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "V_VBAK_VKO", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create Delivery / Post Goods Issue",
                 "actions": ["VL01N", "VL02N", "VL06O"],
                 "permissions": [{"object": "V_LIKP_VST", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help SD: V_VBAK_AAT / V_VBAK_VKO (sales document)",
                           "SAP Help SD: V_LIKP_VST (delivery, shipping point)"],
        },
        {
            "risk_id": "O2C-08", "name": "Create Credit Memo Request and Bill It",
            "process": "O2C", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "A credit memo returns money or cancels a receivable. Raising the request and converting it to a billing document is the sales-side equivalent of writing a cheque to oneself, and it is the standard route by which a receivable owed by a colluding customer quietly disappears.",
            "functions": [
                {"name": "Create Credit Memo Request",
                 "actions": ["VA01", "VA02"],
                 "permissions": [{"object": "V_VBAK_AAT", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create Billing Document / Credit Memo",
                 "actions": ["VF01", "VF02", "VF04"],
                 "permissions": [{"object": "V_VBRK_FKA", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help SD: V_VBAK_AAT (sales document type)",
                           "SAP Help SD: V_VBRK_FKA (billing type)"],
        },
        {
            "risk_id": "O2C-09", "name": "Maintain Customer Master and Execute Dunning",
            "process": "O2C", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "Dunning is the control that surfaces overdue receivables. A user who can set a customer's dunning block or level and then run the dunning programme decides which debts are chased, so a receivable from a related party can be kept permanently invisible without any write-off appearing.",
            "functions": [
                {"name": "Maintain Customer Master (Dunning Data)",
                 "actions": ["XD02", "FD02", "BP"],
                 "permissions": [{"object": "F_KNA1_BUK", "field": "ACTVT", "values": ["02"]},
                                 {"object": "F_KNA1_APP", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Execute Dunning Run",
                 "actions": ["F150"],
                 "permissions": [{"object": "F_MAHN_BUK", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help FI: F_KNA1_BUK / F_KNA1_APP (customer master)",
                           "SAP Help FI: F_MAHN_BUK (dunning, company code)"],
        },
        # ── Batch D: record-to-report depth.
        {
            "risk_id": "R2R-06", "name": "Maintain Asset Master and Post Asset Acquisition or Retirement",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "Creating the asset and posting its acquisition or retirement puts the whole fixed-asset lifecycle in one pair of hands. A retirement posted against an asset the same person created removes a book value with no independent confirmation the asset ever existed or has genuinely gone.",
            "functions": [
                {"name": "Maintain Asset Master",
                 "actions": ["AS01", "AS02", "AS05", "AS06"],
                 "permissions": [{"object": "A_S_ANLKL", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Post Asset Acquisition / Retirement",
                 "actions": ["ABZON", "F-90", "ABAVN", "F-92"],
                 "permissions": [{"object": "A_B_ANLKL", "field": "ACTVT", "values": ["01"]},
                                 {"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP Help FI-AA: A_S_ANLKL (asset master, company code / asset class)",
                           "SAP Help FI-AA: A_B_ANLKL (asset posting)",
                           "SAP Help FI: F_BKPF_BUK (accounting document, company code)"],
        },
        {
            "risk_id": "R2R-07", "name": "Maintain House Bank / Bank Master and Execute Payment Run",
            "process": "R2R", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "The house bank and bank master decide which account money leaves from and which it arrives at. Changing them and then running the payment programme is the treasury equivalent of P2P-02: the destination and the disbursement are chosen by one person, and the payment file itself looks correct.",
            "functions": [
                {"name": "Maintain Bank Master / House Bank",
                 "actions": ["FI01", "FI02", "FI12", "FBZP"],
                 "permissions": [{"object": "F_BNKA_MAN", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Execute Payment Run",
                 "actions": ["F110", "F111"],
                 "permissions": [{"object": "F_REGU_BUK", "field": "FBTCH", "values": ["11", "21"]}]},
            ],
            "references": ["SAP Help FI: F_BNKA_MAN (bank master data)",
                           "SAP Help FI: F_REGU_BUK (automatic payment transactions)"],
        },
        {
            "risk_id": "R2R-08", "name": "Maintain Recurring Entry and Execute the Recurring Run",
            "process": "R2R", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "A recurring entry posts on a schedule with no further human step. Defining the template and running it means a journal posts every period on the authority of the person who wrote it, and because the postings are routine they attract none of the scrutiny a one-off entry of the same value would.",
            "functions": [
                {"name": "Maintain Recurring Entry Document",
                 "actions": ["FBD1", "FBD2", "FBD5"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Execute Recurring Entry Run",
                 "actions": ["F.14", "SM35"],
                 "permissions": [{"object": "F_BKPF_BUK", "field": "ACTVT", "values": ["01"]},
                                 {"object": "S_BDC_MONI", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["SAP Help FI: F_BKPF_BUK (accounting document, company code)",
                           "SAP Help: S_BDC_MONI (batch input session monitoring)"],
        },
        # ── Batch E: Basis depth.
        {
            "risk_id": "BASIS-05", "name": "Open the Client and Import a Transport",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "CRITICAL",
            "rationale": "Transport-only change is the control the whole ITGC framework rests on. A user who can both open the production client and import transports can introduce a change by either route and close the door behind them, so the system's own settings will later assert that only transports arrived.",
            "functions": [
                {"name": "Change Client Settings",
                 "actions": ["SCC4", "SE06"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Import Transport to Production",
                 "actions": ["STMS", "SE01", "SE09"],
                 "permissions": [{"object": "S_CTS_ADMI", "field": "CTS_ADMFCT", "values": ["IMPA", "IMPS"]},
                                 {"object": "S_TRANSPRT", "field": "ACTVT", "values": ["43"]}]},
            ],
            "references": ["SAP Help: S_CTS_ADMI (CTS administration functions)",
                           "SAP Help: S_TRANSPRT (transport organizer)"],
        },
        {
            "risk_id": "BASIS-06", "name": "Maintain Authorization Check Indicators and Build Roles",
            "process": "BASIS-SEC", "risk_type": "SOD", "severity": "HIGH",
            "rationale": "SU24 decides which authorization objects PFCG proposes for a transaction, and a check indicator set to 'no check' removes an object from every role built afterwards while the transaction still works. A user who can edit SU24 and build roles can therefore create a role that passes permission-level review because the object the review looks for is no longer proposed.",
            "functions": [
                {"name": "Maintain Check Indicators / Proposals",
                 "actions": ["SU24", "SU25", "SU22"],
                 "permissions": [{"object": "S_USER_VAL", "field": "ACTVT", "values": ["02"]}]},
                {"name": "Build / Change Roles",
                 "actions": ["PFCG"],
                 "permissions": [{"object": "S_USER_AGR", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_USER_AUT", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["SAP Help: SU24 maintains USOBT_C / USOBX_C; only customer defaults are applied by PFCG",
                           "SAP Help: S_USER_AGR / S_USER_AUT / S_USER_VAL",
                           "docs/SOD_REFERENCE.md section 4.7"],
        },
        # ── Critical access: capabilities that are one half of nothing,
        # because they are both halves of everything. Added 2026-08-29; each
        # object/field/value is verified in docs/SOD_REFERENCE.md against an SAP
        # primary source rather than inferred.
        {
            "risk_id": "CA-01", "name": "Generic Table Maintenance (SE16/SM30 write access)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_ACTION", "severity": "CRITICAL",
            "rationale": "A user who can change table contents directly through the Data Browser or table maintenance performs the DATA half of every business conflict without holding any business transaction. Changing LFA1/LFBK is 'maintain vendor' with no FK02; changing BSEG is 'post document' with no FB01. SAP's own EarlyWatch Alert lists users who can change all tables as a critical finding, and Note 1541577 exists precisely because S_TABU_NAM breaks rulesets keyed on S_TABU_DIS. This is the single most common way a transaction-level SoD report reads clean over a compromised estate.",
            "functions": [
                {"name": "Change Table Contents Generically",
                 "actions": ["SE16", "SE16N", "SE17", "SM30", "SM31", "SE14"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]},
                                 {"object": "S_TABU_NAM", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["SAP EarlyWatch Alert - Security (ABAP): Users Authorized to Change or Display all Tables",
                           "SAP Help: S_TABU_DIS (DICBERCLS, ACTVT); S_TABU_NAM (TABLE, ACTVT)",
                           "SAP Note 1541577 - Impact of S_TABU_NAM in Risk Analysis and Remediation",
                           "docs/SOD_REFERENCE.md section 4.2"],
        },
        {
            "risk_id": "CA-02", "name": "Debug and Replace in Production (S_DEVELOP DEBUG ACTVT 02)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "CRITICAL",
            "rationale": "Debug-replace edits variable values in a running program, which means it alters the result of an AUTHORITY-CHECK AFTER the check has executed. No authorization object, organisational level or SoD rule can constrain a user who holds it: the canonical /h + change sy-subrc technique defeats every control this ruleset expresses. SAP's Security Optimization Guide names S_DEVELOP in production as critical on its own.",
            "functions": [
                {"name": "Change Variables in the ABAP Debugger",
                 "actions": ["SE38", "SE24", "SE80", "SE16N"],
                 "permissions": [{"object": "S_DEVELOP", "field": "OBJTYPE", "values": ["DEBUG"]},
                                 {"object": "S_DEVELOP", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["SAP Help: Rights for Debugging - S_DEVELOP OBJTYPE DEBUG, ACTVT 02 allows editing values of variables in the ABAP debugger",
                           "SAP Security Optimization Guide: Protecting ABAP Development Environment",
                           "SAP EarlyWatch Alert - Security: Users Authorized to Debug / Replace",
                           "SAP Note 65968"],
        },
        {
            "risk_id": "CA-03", "name": "Execute Any ABAP Report (SA38/SE38 with unrestricted S_PROGRAM)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_ACTION", "severity": "HIGH",
            "rationale": "Running an arbitrary report bypasses the transaction code the ruleset keys on. The program behind a transaction can be submitted directly, so a user with SA38 reaches the capability without ever holding the transaction - the false-negative direction, and the more dangerous of the two. SAP's EarlyWatch Alert reports users authorized to start all reports as a distinct critical finding.",
            "functions": [
                {"name": "Start Any Report",
                 "actions": ["SA38", "SE38", "SE80"],
                 "permissions": [{"object": "S_PROGRAM", "field": "P_ACTION", "values": ["SUBMIT"]}]},
            ],
            "references": ["SAP EarlyWatch Alert - Security (ABAP): Users Authorized to Start all Reports",
                           "SAP Help: S_PROGRAM (P_GROUP, P_ACTION)",
                           "docs/SOD_REFERENCE.md section 2.1"],
        },
        {
            "risk_id": "CA-05", "name": "Schedule a Background Job Step Under Another User",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "CRITICAL",
            "rationale": "By default a job runs under the authorizations of the user who scheduled it. S_BTCH_NAM lifts that: the step runs as a named other user, so a clerk holding only FB60 can schedule a step that executes F110 as a batch account. The two halves of a real conflict then sit in two identities and USER-LEVEL SoD analysis reports nothing, while one human executed both. SAP restricts this authorization to the batch administrator for exactly this reason.",
            "functions": [
                {"name": "Run a Job Step as Another User",
                 "actions": ["SM36", "SM37", "SM64"],
                 "permissions": [{"object": "S_BTCH_NAM", "field": "BTCUNAME", "values": ["*"]},
                                 {"object": "S_BTCH_JOB", "field": "JOBACTION", "values": ["RELE"]}]},
            ],
            "references": ["SAP Help: Defining Users for Background Processing - 'You should give this authorization to the batch administrator only'",
                           "SAP Help: Authorizations for Background Processing - a job runs under the authorizations of the user who scheduled it",
                           "SAP Note 101146",
                           "docs/SOD_REFERENCE.md section 4.3"],
        },
        {
            "risk_id": "CA-06", "name": "Administer RFC Destinations (SM59)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_ACTION", "severity": "HIGH",
            "rationale": "An RFC destination holding stored credentials is a privilege capsule: the caller needs only S_RFC for the function group and then executes in the target system as the stored user, frequently a wide-authorization service account. Whoever can create or edit destinations can therefore manufacture a path into any connected system, and none of it appears in their own role portfolio. SAP's EarlyWatch Alert lists RFC administrators as a critical group.",
            "functions": [
                {"name": "Create or Change RFC Destinations",
                 "actions": ["SM59"],
                 "permissions": [{"object": "S_RFC_ADM", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "S_ADMI_FCD", "field": "S_ADMI_FCD", "values": ["NADM"]}]},
            ],
            "references": ["SAP EarlyWatch Alert - Security (ABAP): Users Authorized to Administer RFC Connections",
                           "SAP RFC/ICF Security Guide: S_RFC_ADM",
                           "docs/SOD_REFERENCE.md section 4.3"],
        },
        {
            "risk_id": "CP-01", "name": "Trusted-RFC Logon Without a Password (S_RFCACL)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "CRITICAL",
            "rationale": "S_RFCACL lets a caller assume an identity in the target system with no password, the calling system asserting who they are. SAP deliberately excludes it from SAP_ALL - one of very few objects it withholds - and warns that individual users might be misused as anonymous users to perform actions in the target system. A holder inherits whatever the asserted identity can do, in a system where no SoD analysis of the source estate can see it.",
            "functions": [
                {"name": "Log On via Trusted RFC",
                 "actions": ["SMT1", "SMT2"],
                 "permissions": [{"object": "S_RFCACL", "field": "RFC_EQUSER", "values": ["Y", "*"]}]},
            ],
            "references": ["SAP RFC/ICF Security Guide: 'The object S_RFCACL is not included in the authorization profile SAP_ALL'; 'individual users might be misused as anonymous users to perform actions in the target system'",
                           "SAP Help: as of Release 40B SAP_ALL does not contain an authorization for S_RFCACL",
                           "docs/SOD_REFERENCE.md section 4.3"],
        },
        {
            "risk_id": "CP-02", "name": "Cross-Client Table Maintenance (S_TABU_CLI)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "HIGH",
            "rationale": "Cross-client tables are shared by every client on the system, so a change made from a sandbox or training client takes effect in production on the same instance. Client separation is the control most estates rely on to make a non-production client harmless; this authorization removes it, and it does so without appearing in any business transaction.",
            "functions": [
                {"name": "Maintain Cross-Client Tables",
                 "actions": ["SM30", "SM31", "SE16", "SE16N"],
                 "permissions": [{"object": "S_TABU_CLI", "field": "CLIIDMAINT", "values": ["X"]},
                                 {"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["SAP Help: S_TABU_CLI (CLIIDMAINT) - cross-client table maintenance",
                           "docs/SOD_REFERENCE.md section 4.2"],
        },
        {
            "risk_id": "CP-03", "name": "Execute External Operating-System Commands (SM49/SM69)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "CRITICAL",
            "rationale": "An external command runs on the application server under the SAP system's operating-system account. Whoever can define or execute one steps outside the ABAP authorization concept entirely - reading or replacing files, invoking database utilities, or launching a shell - so no SoD rule, org level or table protection constrains what follows. Defining the command and executing it are separately protected for that reason.",
            "functions": [
                {"name": "Define or Execute External OS Commands",
                 "actions": ["SM49", "SM69"],
                 "permissions": [{"object": "S_LOG_COM", "field": "COMMAND", "values": ["*"]},
                                 {"object": "S_RZL_ADM", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["SAP Help: S_LOG_COM (COMMAND, OPSYSTEM, HOST) - external operating system commands",
                           "SAP Help: S_RZL_ADM - CCMS system administration"],
        },
        {
            "risk_id": "CP-04", "name": "Application-Server File Access from ABAP (S_DATASET)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_PERMISSION", "severity": "HIGH",
            "rationale": "S_DATASET governs OPEN DATASET, so a holder reads and writes files on the application server: payment files awaiting transmission to the bank, interface drops, and transport data. A payment file altered after approval and before transmission changes the payee with no document, no change record and no transaction anywhere in an SoD ruleset.",
            "functions": [
                {"name": "Read or Write Server Files from ABAP",
                 "actions": ["AL11", "CG3Y", "CG3Z"],
                 "permissions": [{"object": "S_DATASET", "field": "ACTVT", "values": ["34", "A6"]}]},
            ],
            "references": ["SAP Help: S_DATASET (PROGRAM, ACTVT, FILENAME) - authorization for file access",
                           "docs/SOD_REFERENCE.md section 2.1"],
        },
        {
            "risk_id": "CA-07", "name": "Open the Production Client for Changes (SCC4)",
            "process": "BASIS-SEC", "risk_type": "CRITICAL_ACTION", "severity": "CRITICAL",
            "rationale": "Client settings decide whether production accepts direct configuration change and cross-client customizing. A user who can open the client removes the control that makes 'changes only arrive by transport' true, and can then make a change directly, close the client again, and leave a system whose settings say it was never open. Every downstream control that assumes transport-only change inherits the failure.",
            "functions": [
                {"name": "Change Client Settings",
                 "actions": ["SCC4", "SE06", "SCC5"],
                 "permissions": [{"object": "S_TABU_DIS", "field": "ACTVT", "values": ["02"]},
                                 {"object": "S_TABU_CLI", "field": "CLIIDMAINT", "values": ["X"]}]},
            ],
            "references": ["SAP Help: client maintenance (SCC4), table T000",
                           "SAP Help: S_TABU_CLI for cross-client maintenance"],
        },
        {
            "risk_id": "CA-04", "name": "Change Payroll Status / Delete Payroll Results",
            "process": "H2R", "risk_type": "CRITICAL_ACTION", "severity": "HIGH",
            "rationale": "PU03 edits the Payroll Status infotype (IT0003) — unlock a personnel number, reset accounted-to/earliest-retro date and correction flags — while PU01 deletes the current payroll result. Together they re-open a closed/locked period, wipe a result and recalculate, defeating payroll locking and enabling undetected manipulation.",
            "functions": [
                {"name": "Manipulate Payroll Status / Results",
                 "actions": ["PU03", "PU01"],
                 "permissions": [{"object": "P_ORGIN", "field": "INFTY", "values": ["0003"]},
                                 {"object": "P_PCLX", "field": "AUTHC", "values": ["U"]}]},
            ],
            "references": ["SAP community IT0003 payroll status (PU03)", "dan852 PU01 delete current result", "authorizationexperts.com p_pclx (RELID/AUTHC=U)"],
        },
        {
            "risk_id": "CP-05", "name": "Maintain Own HR Master Data (P_PERNR PSIGN=I)",
            "process": "H2R", "risk_type": "CRITICAL_PERMISSION", "severity": "HIGH",
            "rationale": "P_PERNR (Personnel Number Check) with PSIGN='I' (own personnel number) at write level lets a user maintain their OWN pay-relevant infotypes (Basic Pay 0008, Bank Details 0009) — self-service pay manipulation. When the PERNR main switch is active (OOAC, AUTSW/PERNR), P_PERNR overrides P_ORGIN; PSIGN='I' with write AUTHC is the exact self-maintenance grant. Best practice PSIGN='E' (exclude own record) for pay-relevant infotypes.",
            "functions": [
                {"name": "Maintain Own Personnel Master Data",
                 "actions": ["PA30", "PA40"],
                 "permissions": [{"object": "P_PERNR", "field": "PSIGN", "values": ["I"]},
                                 {"object": "P_PERNR", "field": "AUTHC", "values": ["W", "E", "S", "*"]}]},
            ],
            "references": ["SAP Help P_PERNR", "SAP Help P_PERNR PSIGN I/E, main switch OOAC (AUTSW/PERNR)"],
        },
        # ══════════════════════════════════════════════════════════════════
        #  PLANT-FLOOR PROCESSES (MFG / INV / QM / PM / PS / WM)
        #  Objects from the operator design specification; field vocabulary is
        #  working knowledge — see the module docstring's provenance note. The
        #  matcher is fail-closed, so an inaccurate field silences a rule
        #  rather than inventing a conflict.
        # ══════════════════════════════════════════════════════════════════
        {
            "risk_id": "MFG-01", "name": "Maintain BOM / Routing and Release Production Order",
            "process": "MFG", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (C_STUE_BER, C_ROUT, C_AFKO_AWK); fields unverified",
            "rationale": "A user who changes what a product is made of (BOM) or how it is made (routing) AND releases the production order that consumes it can quietly alter component quantities, then run the order that draws the extra material — the consumption becomes 'planned' and reconciles cleanly. Costing is distorted in the same motion. Authorization-based on both sides.",
            "functions": [
                {"name": "Maintain BOM / Routing",
                 "actions": ["CS01", "CS02", "CA01", "CA02", "CEWB"],
                 "permissions": [{"object": "C_STUE_BER", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "C_ROUT", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Create / Release Production Order",
                 "actions": ["CO01", "CO02", "CO40", "CO41", "COHV"],
                 "permissions": [{"object": "C_AFKO_AWK", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — PP authorization objects",
                           "SAP GRC starter ruleset — Manufacturing (BOM/routing vs order release)"],
        },
        {
            "risk_id": "MFG-02", "name": "Confirm Production Order and Post Component Goods Movement",
            "process": "MFG", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (C_AFKO_AWK, M_MSEG_BWA/WMB); fields unverified",
            "rationale": "Confirmation declares the yield and scrap a production order achieved; the goods movement books the components it consumed and the finished stock it produced. One user holding both can confirm output that was never made, or write off good material as scrap and remove it — the classic false-production-confirmation loss, invisible because the paperwork agrees with itself.",
            "functions": [
                {"name": "Confirm Production Order",
                 "actions": ["CO11N", "CO15", "CO1F", "CO11", "MFBF"],
                 "permissions": [{"object": "C_AFKO_AWK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Post Goods Movement",
                 "actions": ["MIGO", "MB31", "MB1A", "MB1B", "MB11"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WMB", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["S/4HANA security design specification — PP / Inventory objects",
                           "SAP GRC starter ruleset — Manufacturing (confirm vs component GI/GR)"],
        },
        {
            "risk_id": "INV-01", "name": "Post Goods Movement and Post Physical Inventory Difference",
            "process": "INV", "risk_type": "SOD", "severity": "CRITICAL",
            "provenance": "objects from design spec (M_MSEG_BWA/WMB); fields unverified",
            "rationale": "The count is the control that catches the theft. A user who moves stock AND posts the physical-inventory difference writes off exactly what they removed — the book balance is corrected to match the shelf, the variance is 'explained', and no reconciliation ever surfaces it. Posting an inventory difference is itself a material movement (types 701/702), so the movement-type authorization governs both sides.",
            "functions": [
                {"name": "Post Goods Movement",
                 "actions": ["MIGO", "MB1A", "MB1B", "MB1C", "MB11", "MBST"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WMB", "field": "ACTVT", "values": ["01"]}]},
                {"name": "Post Physical Inventory Difference",
                 "actions": ["MI07", "MI08", "MI10", "MI37"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WMB", "field": "ACTVT", "values": ["01"]}]},
            ],
            "references": ["S/4HANA security design specification — Inventory objects and MI07 flow",
                           "SAP GRC starter ruleset — Inventory (goods movement vs inventory difference)"],
        },
        {
            "risk_id": "INV-02", "name": "Post Goods Movement and Maintain Material Valuation / Status",
            "process": "INV", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (M_MSEG_BWA, M_MATE_MAR/STA); fields unverified",
            "rationale": "A user who moves stock AND maintains the material master can change the valuation class, price control or material status that governs how the movement is valued and whether it is blocked — writing stock off at a price they chose, or unblocking a material to move it and re-blocking it afterwards. The master data decides what the movement means.",
            "functions": [
                {"name": "Post Goods Movement",
                 "actions": ["MIGO", "MB1A", "MB1B", "MB1C", "MB11"],
                 "permissions": [{"object": "M_MSEG_BWA", "field": "ACTVT", "values": ["01"]},
                                 {"object": "M_MSEG_WMB", "field": "ACTVT", "values": ["01"]}]},
                {"name": "Maintain Material Master (valuation / status)",
                 "actions": ["MM01", "MM02", "MM17", "MASS", "MR21"],
                 "permissions": [{"object": "M_MATE_MAR", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_MATE_STA", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_MATE_BUK", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — Material master objects",
                           "SAP GRC starter ruleset — Inventory / material master"],
        },
        {
            "risk_id": "QM-01", "name": "Record Inspection Results and Make the Usage Decision",
            "process": "QM", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (Q_INSP_WRK); TRANSACTION-separated with a permission floor",
            "rationale": "Quality assurance is two people by design: one records what the inspection measured, another decides whether the lot is acceptable. One user doing both can enter passing results and accept their own lot, releasing defective material to customers or production with no independent gate. Separated by transaction with an inspection-lot permission floor rather than by object — coarser than an authorization-based rule, and stated as such.",
            "functions": [
                {"name": "Record Inspection Results",
                 "actions": ["QE51N", "QE01", "QE02", "QE11", "QE23"],
                 "permissions": [{"object": "Q_INSP_WRK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Make Usage Decision",
                 "actions": ["QA11", "QA12", "QA14", "QA32"],
                 "permissions": [{"object": "Q_INSP_WRK", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — QM authorization objects",
                           "SAP GRC starter ruleset — Quality (results recording vs usage decision)"],
        },
        {
            "risk_id": "QM-02", "name": "Make Usage Decision and Maintain Material QM Inspection Setup",
            "process": "QM", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (Q_INSP_WRK, M_MATE_MAR/QM material); fields unverified",
            "rationale": "Accepting a failing lot is a single event somebody may notice. Changing the material's QM inspection setup so future lots are not inspected at all is the same fraud made permanent, and it stops generating evidence. A user holding both can accept today's defective batch and switch off tomorrow's inspection.",
            "functions": [
                {"name": "Make Usage Decision",
                 "actions": ["QA11", "QA12", "QA14"],
                 "permissions": [{"object": "Q_INSP_WRK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Maintain Material QM / Inspection Setup",
                 "actions": ["MM01", "MM02", "QS21", "QS22", "QDR1"],
                 "permissions": [{"object": "Q_MATERIAL", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "M_MATE_MAR", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — QM objects (Q_MATERIAL, Q_INSP_WRK)",
                           "SAP GRC starter ruleset — Quality (usage decision vs inspection setup)"],
        },
        {
            "risk_id": "PM-01", "name": "Create Maintenance Order and Confirm the Work",
            "process": "PM", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (I_AUART, I_IWERK); I_* field vocabulary UNVERIFIED",
            "rationale": "A maintenance order authorises spend — labour, parts, external services — and the confirmation says the work happened. One user raising the order and confirming it can book maintenance that was never performed, consuming spare parts that leave the storeroom to somewhere else, or route an external service to a colluding contractor with the confirmation as the only evidence.",
            "functions": [
                {"name": "Create / Change Maintenance Order",
                 "actions": ["IW31", "IW32", "IW34", "IW36"],
                 "permissions": [{"object": "I_AUART", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "I_IWERK", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Confirm Maintenance Work",
                 "actions": ["IW41", "IW42", "IW44", "IW48"],
                 "permissions": [{"object": "I_AUART", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "I_IWERK", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — PM/EAM authorization objects",
                           "SAP GRC starter ruleset — Plant Maintenance (order vs confirmation)"],
        },
        {
            "risk_id": "PS-01", "name": "Maintain Project Budget and Settle Project Costs",
            "process": "PS", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (C_PRPS_ART, C_PROJ_TCD, K_ORDER); fields unverified",
            "rationale": "Project budget is the control that stops a project absorbing cost without approval, and settlement is what moves that cost onto an asset or a P&L account. A user who sets the budget AND settles can raise the budget to cover an overrun they then settle away — the overrun never surfaces as a variance, and capital projects are where the largest single-approval amounts in an ERP live.",
            "functions": [
                {"name": "Maintain Project / WBS Budget",
                 "actions": ["CJ30", "CJ32", "CJ37", "CJ36", "CJ20N"],
                 "permissions": [{"object": "C_PRPS_ART", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "C_PROJ_TCD", "field": "ACTVT", "values": ["01", "02"]}]},
                {"name": "Settle / Post Project Costs",
                 "actions": ["CJ88", "CJ8G", "CJ44", "CJ45"],
                 "permissions": [{"object": "K_ORDER", "field": "ACTVT", "values": ["01", "02"]},
                                 {"object": "K_CCA", "field": "ACTVT", "values": ["01", "02"]}]},
            ],
            "references": ["S/4HANA security design specification — PS authorization objects",
                           "SAP GRC starter ruleset — Project System (budget vs settlement)"],
        },
        {
            "risk_id": "WM-01", "name": "Create Warehouse Transfer Order and Confirm It",
            "process": "WM", "risk_type": "SOD", "severity": "HIGH",
            "provenance": "objects from design spec (L_LGNUM); fields unverified",
            "rationale": "The transfer order says stock should move; the confirmation says it did. A user holding both can confirm a movement that never physically happened — the bin balance in the system matches the paperwork while the goods are gone, and the discrepancy only appears at the next physical count, by which time the trail is a system record the same user created.",
            "functions": [
                {"name": "Create Warehouse Transfer Order / Task",
                 "actions": ["LT01", "LT03", "LT06", "LT10", "/SCWM/TO_CREATE"],
                 "permissions": [{"object": "L_LGNUM", "field": "ACTVT", "values": ["01"]}]},
                {"name": "Confirm Warehouse Transfer Order / Task",
                 "actions": ["LT11", "LT12", "LT13", "LT22", "/SCWM/TO_CONF"],
                 "permissions": [{"object": "L_LGNUM", "field": "ACTVT", "values": ["02"]}]},
            ],
            "references": ["S/4HANA security design specification — WM/EWM objects (L_LGNUM)",
                           "SAP GRC starter ruleset — Warehouse (task creation vs confirmation)"],
        },
    ]

    _SEV = {"CRITICAL": BaseAuditor.SEVERITY_CRITICAL, "HIGH": BaseAuditor.SEVERITY_HIGH,
            "MEDIUM": BaseAuditor.SEVERITY_MEDIUM, "LOW": BaseAuditor.SEVERITY_LOW}

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
        return self.findings

    # ------------------------------------------------------------------ parsing
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
            r = roles.setdefault(inst["role"], {"tcodes": set(), "star_tcode": False, "auths": []})
            r["auths"].append(inst)
            if inst["object"] == "S_TCODE":
                for low, _high in inst["fields"].get("TCD", []):
                    lv = str(low).strip().upper()
                    if lv == "*":
                        r["star_tcode"] = True
                    elif lv:
                        r["tcodes"].add(lv)
        return roles

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
                u = {"tcodes": set(), "star_tcode": False, "auths": [], "roles": []}
                for role in roles:
                    ri = role_index.get(role)
                    if ri:
                        u["tcodes"] |= ri["tcodes"]
                        u["star_tcode"] = u["star_tcode"] or ri["star_tcode"]
                        u["auths"].extend(ri["auths"])
                        u["roles"].append(role)
                if u["roles"]:
                    units[user] = u
            if units:
                return units, "user"
        # fallback: each role is a pseudo-unit
        return ({r: {**v, "roles": [r]} for r, v in role_index.items()}, "role")

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
        acts = [str(a).strip().upper() for a in (func.get("actions") or []) if str(a).strip()]
        if acts and not (unit["star_tcode"] or (unit["tcodes"] & set(acts))):
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
                     "risk_type": rtype, "process": risk.get("process", "")},
            affected_objects=self._risk_objects(risk, residual[:100]),
            # AGGREGATE: one finding per RISK summarising every user that holds it, so the
            # member list must stay out of its identity. Remediating one of five offenders
            # would otherwise retire this finding and raise a fresh one, resetting the
            # risk's age on every run. check_id already carries the risk id (ARA-<rid>),
            # which is the correct, stable subject here.
            scope="aggregate",
        )

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
