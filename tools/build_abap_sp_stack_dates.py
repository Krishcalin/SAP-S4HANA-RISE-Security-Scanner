"""Generate data/abap_sp_stack_dates.json from SAP's own published age policy.

Run:  python -m tools.build_abap_sp_stack_dates --source <extract-of-the-sap-repo>

WHY THIS EXISTS. MonitorRisk flags an out-of-maintenance HANA revision
(hana_db_security) and an old Cloud Connector (btp_cloud_surface), but nothing
said the ABAP application-server stack itself was years out of date. SAP publishes
exactly that judgement — `MiscPolicies/ABAPSPStackAge/age_of_sap_basis.xml` in
`SAP-samples/frun-csa-policies-best-practices` (Apache-2.0) — as a table of the
RELEASE DATE of each SAP_BASIS support package, rated non-compliant when that date
is more than 730 days (SAP's own threshold) before the scan date.

WHAT IS TAKEN, AND WHAT IS NOT. Taken: the (SAP_BASIS release, SP) -> release-date
facts and SAP's 730-day threshold. These are facts of exactly the same kind as the
note fix-levels build_sap_notes_catalogue.py already extracts. NOT taken: SAP's SQL
as SQL. The policy's `DAYS_BETWEEN(TO_DATE(...),CURRENT_DATE)` runs in Focused
Run; here the release date is extracted and the age is computed in this product's
own Python against system_component.csv and the scan date.

THE COVERAGE LIMIT, STATED HONESTLY. SAP's file is "Version 003, June 2020" and
tables only SAP_BASIS 700-754 with SP dates through mid-2020. It therefore cannot
age SAP_BASIS 755+ (S/4HANA 2020 and later). A stack outside the table is reported
as not-assessable-for-age, never as current — the same four-state honesty the rest
of the product follows. In 2026 every release the table DOES cover is well past
730 days, so the check is decisive for legacy/ECC estates and silent, by
construction, on the S/4HANA core.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "data" / "abap_sp_stack_dates.json"
POLICY = "MiscPolicies/ABAPSPStackAge/age_of_sap_basis.xml"

#: One row of SAP's CASE table:
#:   COMPONENT = 'SAP_BASIS' and VERSION = '754' and 1 = (CASE WHEN SP = '0002'
#:   THEN ( CASE WHEN DAYS_BETWEEN(TO_DATE('2020-05-05','YYYY-MM-DD'),...
#: The operator is `=` for an exact SP and `&gt;` (>) for the "everything above
#: the highest listed SP" fallback.
_ROW = re.compile(
    r"VERSION\s*=\s*'(?P<rel>\d+)'\s*and\s*1\s*=\s*\(\s*CASE\s+WHEN\s+SP\s*"
    r"(?P<op>=|&gt;|>)\s*'(?P<sp>\d+)'\s*THEN\s*\(\s*CASE\s+WHEN\s+DAYS_BETWEEN\("
    r"TO_DATE\('(?P<date>\d{4}-\d{2}-\d{2})'",
    re.IGNORECASE)

#: SAP's threshold, stated in the policy header: "within the last 730 days".
_THRESHOLD = re.compile(r"than\s+(\d{2,4})\s+days", re.IGNORECASE)
_VERSION = re.compile(r"Version:\s*(\d+)", re.IGNORECASE)


def parse(text: str) -> dict:
    releases: dict = {}
    for m in _ROW.finditer(text):
        rel, op, sp, date = m["rel"], m["op"], int(m["sp"]), m["date"]
        rec = releases.setdefault(rel, {"exact": {}, "above_sp": None,
                                        "above_date": None})
        if op == "=":
            # Keep the earliest date seen for a given (release, SP): compliant and
            # noncompliant clauses repeat the same fact, so dedup is a no-op, but a
            # malformed duplicate must not silently win.
            rec["exact"].setdefault(str(sp), date)
        else:  # SP > N  -> the fallback date for every SP above the highest listed
            if rec["above_sp"] is None or sp < rec["above_sp"]:
                rec["above_sp"], rec["above_date"] = sp, date
    threshold = _THRESHOLD.search(text)
    version = _VERSION.search(text)
    return {
        "releases": releases,
        "threshold_days": int(threshold.group(1)) if threshold else 730,
        "policy_version": version.group(1) if version else None,
    }


def build(source: Path) -> dict:
    path = source / POLICY
    if not path.is_file():
        raise SystemExit(
            "no %s under %s — is this an extract of "
            "SAP-samples/frun-csa-policies-best-practices?" % (POLICY, source))
    parsed = parse(path.read_text(encoding="utf-8", errors="replace"))
    releases = parsed["releases"]
    if not releases:
        raise SystemExit("parsed no SAP_BASIS release rows from %s — the policy "
                         "format has changed" % path)
    total_dates = sum(len(r["exact"]) + (1 if r["above_date"] else 0)
                      for r in releases.values())
    return {
        "_meta": {
            "source": "SAP-samples/frun-csa-policies-best-practices",
            "source_path": POLICY,
            "licence": ("Apache-2.0, Copyright (c) 2020 SAP SE or an SAP affiliate "
                        "company. Derived facts only — the (release, SP) -> "
                        "release-date table and SAP's 730-day threshold."),
            "policy_version": parsed["policy_version"],
            "threshold_days": parsed["threshold_days"],
            "what_this_is": (
                "SAP's own release dates for each SAP_BASIS support package, and "
                "the 730-day currency threshold. HOTNEWS-SPAGE-001 in "
                "modules/sap_hotnews.py compares these against system_component and "
                "the scan date; SAP's SQL is neither executed nor reproduced."),
            "coverage_limit": (
                "SAP's file is dated June 2020 and tables SAP_BASIS 700-754 only. "
                "SAP_BASIS 755+ (S/4HANA 2020 and later) cannot be aged from it and "
                "is reported as not-assessable-for-age rather than current."),
            "releases_covered": sorted(releases, key=int),
            "counts": {"releases": len(releases), "date_points": total_dates},
        },
        "threshold_days": parsed["threshold_days"],
        "releases": {rel: releases[rel] for rel in sorted(releases, key=int)},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True, type=Path,
                    help="root of a checkout of the SAP policy repository")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed file is out of date")
    args = ap.parse_args(argv)

    fresh = build(args.source)
    generated = json.dumps(fresh, indent=1, ensure_ascii=False) + "\n"
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != generated:
            print("data/abap_sp_stack_dates.json is out of date with SAP's "
                  "published age policy — regenerate it.")
            return 1
        print("data/abap_sp_stack_dates.json is up to date.")
        return 0
    OUT.write_text(generated, encoding="utf-8")
    print("Wrote %s: %d releases, %d date points."
          % (OUT.name, fresh["_meta"]["counts"]["releases"],
             fresh["_meta"]["counts"]["date_points"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
