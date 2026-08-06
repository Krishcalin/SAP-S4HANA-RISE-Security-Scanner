# `sample_data_cloudalm/` — the same system, exported from SAP Cloud ALM

This directory holds SAP Cloud ALM **Configuration & Security Analysis (CSA)**
configuration-store exports. It is the CSA-shaped counterpart of the nine logical
sources `sample_data/` supplies natively, describing the *same* system with the
*same* defects — different file names, different column names, same facts.

That is what makes it a proof rather than a demo:
`tests/test_cloudalm_import.py` loads both directories, runs the audit modules over
each, and asserts the two sides produce the same check ids, the same severities and
the same **fingerprints**. Same fingerprints matter most — if re-uploading a system
as a Cloud ALM export minted new ones, every finding's age would reset and the
mitigation journey would be wrong for a whole scan.

```bash
python sap_scanner.py --data-dir ./sample_data_cloudalm --output report.html
```

## What each file demonstrates

| File | Native counterpart | The translation it exercises |
|---|---|---|
| `ABAP_INSTANCE_PAHI.csv` | `security_params.csv` | `PARAMETER`/`VALUE` → `NAME`/`VALUE`; an `INSTANCE` column riding along |
| `STANDARD_USERS.csv` | `standard_users.csv` | `USERNAME`, `PASSWORD_STATUS`, and **numeric `UFLAG`** → a lock flag. `64` and `32` are locks; untranslated they read as *unlocked* and a CRITICAL check silently passes |
| `AUTH_PROFILE_USER.csv` | `profiles.csv` | SAP's own `PROFILE`/`USERNAME`/`USER_TYPE`/`STATUS` → `USR04`'s `BNAME`/`PROFILE`. Note it does **not** become `users` |
| `SICF_SERVICES.csv` | `icf_services.csv` | a leaf `NAME` next to a full `PATH` — the path must win, or every high-risk-service match misses |
| `GW_SECINFO.csv` / `GW_REGINFO.csv` | `gw_secinfo.csv` / `gw_reginfo.csv` | structured `ACCESS`/`TP`/`HOST`/`USER` folded back into the ACL's own `P TP=… HOST=… USER=…` notation |
| `AUDIT_CONFIGURATION_SLOT.csv` | `audit_config.csv` | filter **slots** → filter rows |
| `CLIENTS.csv` | `client_settings.csv` | `MANDT`/`CCCATEGORY` → `CLIENT`/`ROLE`; the `P` role code is already what the production test reads |
| `MS_SECINFO.csv` | `ms_acl.csv` | `HOST` + `SERVICE` → a composed ACL line |

## Files that are here to prove a *refusal*

These are recognised, reported in the scan output with a reason, and **not**
translated. Each is a mistake the importer must not make:

| File | Why it must not be translated |
|---|---|
| `Parameters.csv` | The **Java** AS store is literally named `Parameters`. Translating it into `security_params` would score Java settings against ABAP profile-parameter thresholds — so the ABAP parameters in this directory come from `ABAP_INSTANCE_PAHI.csv` and nothing here reaches them |
| `AUDIT_CONFIGURATION.csv` | Global audit settings, not filter slots. Counting them as filters would turn "no audit filters configured" into a pass |
| `AUTH_COMB_USER.csv` | SAP's critical-authorisation combination content; we could not confirm whether it carries the rules or the matches, so mapping it would be a guess |

Note also what is **absent**: there is no `users` source here. No CSA store in SAP's
baseline policies carries a full `USR02` user master, and `AUTH_PROFILE_USER` holds
only users who hold a profile — a partial population that would make every
rate-based user check understate. `users.csv` still comes from `RSUSR002`.

See `docs/EXPORT_GUIDE.md` for how a customer obtains a real export, and for the
caveat about whether Cloud ALM returns raw store values at all.
