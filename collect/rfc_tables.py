# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Which SAP tables answer which export file, and what each one honestly yields.

This is the whole of the RFC collector's SAP knowledge, in one table, so a Basis
administrator can read it and tell you whether it is right. Every table and field
name below is a standard SAP dictionary object; none is invented, and where a
source cannot be produced faithfully by `RFC_READ_TABLE` this file says so rather
than emitting a column filled with a guess.

TWO CONSTRAINTS SHAPE EVERY ENTRY
---------------------------------
1. RFC_READ_TABLE returns a 512-byte delimited row and nothing wider. That is why
   every extract names its columns instead of taking the table: SELECT * on USR02
   fails with DATA_BUFFER_EXCEEDED, which reads like a connection fault and is not
   one.

2. RFC_READ_TABLE returns TEXT, not typed columns. Dates arrive as YYYYMMDD
   strings and flags as single characters, which is what the offline CSVs already
   contain — so the export a customer makes by hand and the one this produces are
   the same shape, which is the property connected mode rests on.

WHERE THE MAPPING IS NOT CLEAN, IT SAYS SO
------------------------------------------
`rfc_destinations` is the sharpest case and the most valuable source in the list.
RFCDES stores a destination's target host, logon user and SNC setting inside a
single RFCOPTIONS blob rather than as columns, so those fields are PARSED out of
it — and a parse is a weaker claim than a column read. The entry says which fields
are read directly and which are derived, so a reader can weigh them differently.
"""
from typing import Any, Dict, List, Optional, Sequence

#: One extract: the SAP table, the fields to read, the CSV to write, and the
#: header to write it under.
#:
#: `columns` maps CSV header -> SAP field. A header whose SAP field is None is
#: NOT read from the table: it is derived (see `derive`) or left blank, and it is
#: listed rather than dropped so the gap is visible in this file.
EXTRACTS: List[Dict[str, Any]] = [
    {
        "source": "users",
        "file": "users.csv",
        "table": "USR02",
        "columns": {"BNAME": "BNAME", "USTYP": "USTYP", "UFLAG": "UFLAG",
                    "TRDAT": "TRDAT", "ERDAT": "ERDAT",
                    "PWDCHGDATE": "PWDCHGDATE", "CLASS": "CLASS"},
        "note": "User master. PWDCHGDATE exists from ECC 6.0; on an older release "
                "the field is absent and the extract drops that column rather "
                "than failing, which the manifest records.",
    },
    {
        "source": "profiles",
        "file": "profiles.csv",
        "table": "UST04",
        "columns": {"BNAME": "BNAME", "PROFILE": "PROFILE"},
        "note": "User-to-profile assignment. This is where SAP_ALL shows up.",
    },
    {
        "source": "user_roles",
        "file": "user_roles.csv",
        "table": "AGR_USERS",
        "columns": {"UNAME": "UNAME", "AGR_NAME": "AGR_NAME"},
        "note": "Role assignment. FROM_DAT/TO_DAT are deliberately not read: the "
                "auditors do not use them, and every column costs part of the "
                "512-byte row.",
    },
    {
        "source": "role_auth_values",
        "file": "role_auth_values.csv",
        "table": "AGR_1251",
        "columns": {"AGR_NAME": "AGR_NAME", "OBJECT": "OBJECT", "AUTH": "AUTH",
                    "FIELD": "FIELD", "LOW": "LOW", "HIGH": "HIGH"},
        "note": "Authorisation values per role. THE LARGEST TABLE HERE by a wide "
                "margin — millions of rows on a real estate — so it is the one "
                "that most needs --where or --row-limit.",
    },
    {
        "source": "background_jobs",
        "file": "background_jobs.csv",
        "table": "TBTCO",
        "columns": {"JOBNAME": "JOBNAME", "JOBCOUNT": "JOBCOUNT",
                    "STATUS": "STATUS", "SDLUNAME": "SDLUNAME",
                    "AUTHCKNAM": "AUTHCKNAM"},
        "note": "Job headers. AUTHCKNAM is the step user a job runs as, which is "
                "the field that matters for privilege review.",
    },
    {
        "source": "change_documents",
        "file": "change_documents.csv",
        "table": "CDHDR",
        "columns": {"OBJECTCLAS": "OBJECTCLAS", "CHANGENR": "CHANGENR",
                    "USERNAME": "USERNAME", "UDATE": "UDATE", "TCODE": "TCODE"},
        "note": "Change document headers. Unbounded on a production system; "
                "always pair with --where on UDATE.",
    },
    {
        "source": "client_settings",
        "file": "client_settings.csv",
        "table": "T000",
        "columns": {"CLIENT": "MANDT", "ROLE": "CCCATEGORY",
                    "CHANGES_ALLOWED": "CCCORACTIV",
                    "CROSS_CLIENT_CHANGES": "CCNOCLIIND",
                    "REPOSITORY_CHANGES": "CCNOCASCAD"},
        "note": "Client configuration (SCC4). The CSV's header names are the "
                "auditor's vocabulary and the SAP fields are the dictionary's; "
                "they are mapped here rather than renamed in either place.",
    },
    {
        "source": "rfc_destinations",
        "file": "rfc_destinations.csv",
        "table": "RFCDES",
        "columns": {"RFCDEST": "RFCDEST", "RFCTYPE": "RFCTYPE",
                    "RFCHOST": None, "RFCUSER": None,
                    "RFCSNC": None, "RFCAUTH": None},
        "derive": "rfcoptions",
        "extra_fields": ["RFCOPTIONS"],
        "note": "THE MOST VALUABLE SOURCE HERE AND THE LEAST CLEAN. RFCDES stores "
                "the target host, logon user and SNC flag inside one RFCOPTIONS "
                "blob rather than as columns, so those four are PARSED out of it "
                "— a weaker claim than a column read, and marked as derived in "
                "the manifest. Stored passwords are never returned by "
                "RFC_READ_TABLE and are not sought.",
    },
]

#: RFCOPTIONS is a comma-separated key=value string. Only the keys this collector
#: is confident of are mapped; anything else is ignored rather than guessed at.
#:
#: A key whose meaning is uncertain is worse than an absent column, because the
#: column would be populated and wrong — and RFC destination data feeds the
#: cross-system attack paths, where a wrong host silently redraws the graph.
_RFCOPTION_KEYS = {
    "H": "RFCHOST",     # target host
    "U": "RFCUSER",     # logon user
}


def parse_rfcoptions(blob: str) -> Dict[str, str]:
    """Pull what is safely knowable out of an RFCOPTIONS string.

    Returns only keys in _RFCOPTION_KEYS. RFCSNC and RFCAUTH are NOT derived
    here: the options string encodes them differently across releases and
    destination types, and a wrong value in either would mislabel a destination as
    secured. They are left blank, which the offline auditors already treat as
    unknown.
    """
    out: Dict[str, str] = {}
    for part in (blob or "").split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        name = _RFCOPTION_KEYS.get(key.strip().upper())
        if name:
            out[name] = value.strip()
    return out


def fields_for(extract: Dict[str, Any]) -> List[str]:
    """The SAP field list to request for one extract, in CSV column order."""
    fields = [sap for sap in extract["columns"].values() if sap]
    fields += list(extract.get("extra_fields") or [])
    return fields


def rows_to_csv(extract: Dict[str, Any],
                rows: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    """Turn raw table rows into the CSV shape the offline loader expects."""
    headers = list(extract["columns"])
    derive = extract.get("derive")
    out: List[Dict[str, str]] = []
    for row in rows:
        record = {h: row.get(sap, "") if sap else ""
                  for h, sap in extract["columns"].items()}
        if derive == "rfcoptions":
            record.update({k: v for k, v in
                           parse_rfcoptions(row.get("RFCOPTIONS", "")).items()
                           if k in record})
        out.append({h: record.get(h, "") for h in headers})
    return out


def by_source(name: str) -> Optional[Dict[str, Any]]:
    for extract in EXTRACTS:
        if extract["source"] == name:
            return extract
    return None


#: Sources this collector does NOT produce, and why. Named so the manifest can
#: report them the way SAPCONTROL_CANNOT_REACH and ICF_CANNOT_REACH already do —
#: an RFC connection is not a complete export either, and saying which gaps
#: remain is the difference between a connector and a claim.
RFC_CANNOT_REACH: Dict[str, str] = {
    "gateway_acl": "secinfo/reginfo are files on the application server's file "
                   "system, not dictionary tables. Copy them from the gateway "
                   "directory as the export guide describes.",
    "audit_log_config": "SM19/RSAU configuration lives in kernel-side profile "
                        "parameters and filter definitions, not in a table this "
                        "collector reads. rsau/* parameters come from the "
                        "sapcontrol collector instead.",
    "transport_routes": "TMS routes are held in the domain controller's "
                        "configuration, not in a readable table on the member "
                        "system.",
    "auth_objects": "Object definitions are static SAP content rather than a "
                    "customer setting; the auditors use the role values in "
                    "AGR_1251, which this collector does produce.",
    "standard_users": "Derived by the scanner from users.csv and profiles.csv; "
                      "it is not a separate table.",
    "table_auth_groups": "TDDAT/TBRG are readable in principle but are not yet "
                         "mapped here, and an unmapped source is reported rather "
                         "than half-produced.",
}
