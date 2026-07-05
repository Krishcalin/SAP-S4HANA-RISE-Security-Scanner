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
    ]

    _SEV = {"CRITICAL": BaseAuditor.SEVERITY_CRITICAL, "HIGH": BaseAuditor.SEVERITY_HIGH,
            "MEDIUM": BaseAuditor.SEVERITY_MEDIUM, "LOW": BaseAuditor.SEVERITY_LOW}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        role_index = self._build_role_index()
        if not role_index:
            return self.findings  # no AGR_1251 export → module self-skips
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
