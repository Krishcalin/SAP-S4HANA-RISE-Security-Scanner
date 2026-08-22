"""Add family-level knowledge-base entries for the code-scanning check families.

`FindingKB.lookup` falls back by prefix — ABAP-SQLI-007 -> ABAP-SQLI -> ABAP — so
14 family entries cover all 104 rules plus the ATC import, instead of writing 104
near-identical ones. A rule that needs its own text can still be added under its
full id later and will win.

House format, enforced by tests/test_prose.py:
  risk       one paragraph per line, single newline, never a blank line
  mitigation a numbered list 1..N, one step per line
No SAP Note numbers: only transactions that are certain, and otherwise the generic
SAP Security Baseline reference.
"""
import json
from pathlib import Path

KB = Path(r"d:/KIZEN/SAP-Security-Tool/SAP-S4HANA-RISE-Security-Scanner/data/finding_details.json")

REVIEW = ("1. Open the object in ADT or SE80 and read the reported statement in "
          "context — the line number came from a scan and moves as the code is edited.\n")
VERIFY = ("Re-run the scan or ATC over the changed object and confirm the finding "
          "shrinks or resolves; this product tracks it to closure, so partial "
          "progress is visible.\n")
GOVERN = ("Wire the check into the transport release path so the same defect class "
          "cannot be reintroduced by the next change.")

FAMILIES = {
    "SQLI": (
        "An attacker-controlled value is concatenated into an Open SQL statement — a dynamic WHERE, FROM, ORDER BY, GROUP BY or HAVING clause built from a variable.\n"
        "The database is asked to parse whatever arrives, so a crafted value changes which rows are read or written rather than merely which are selected.\n"
        "In SAP this rarely stops at data theft: the same clause frequently drives an update or a delete, so a read-only-looking report becomes a write path.\n"
        "The business impact is mass data exfiltration under any valid credential, and silent modification of records that the application's own authorization checks were meant to protect.",
        "Replace the concatenated clause with a parameterised query: bind values through the SQL statement API, or express the filter as a range table / SELECT-OPTIONS so the kernel builds the WHERE.\n"
        "Where a dynamic clause is genuinely required, validate the constructed string against an allowlist of column names before it reaches the statement — never against a denylist of characters.\n"
        "Escape any remaining dynamic fragment with the SAP-supplied dynamic-programming utility class rather than with hand-written quoting.\n"
        "Re-check the authorization: a statement that can now read arbitrary rows needs the AUTHORITY-CHECK that the narrowed query previously made unnecessary."),
    "CINJ": (
        "A value that an attacker can influence is turned into executable ABAP or into a dynamic call target — a generated subroutine pool, an INSERT REPORT, a dynamic method or a SUBMIT of a variable program name.\n"
        "This is remote code execution inside the application server, not a data problem: whatever the calling user could do, the injected code can do.\n"
        "Generated code also bypasses the transport system entirely, so what runs in production was never reviewed, never approved and does not appear in any change record.",
        "Remove the dynamic construction. A fixed CASE over an allowlist of known program, method or subroutine names is almost always what the code actually needed.\n"
        "Where dynamic dispatch is genuinely required, validate the target against an explicit allowlist held in customising, not against the input itself.\n"
        "Never build ABAP source from input at runtime; if code generation is required, generate at design time and transport the result so it is reviewable.\n"
        "Add an AUTHORITY-CHECK before the dispatch, because the check that guards the caller does not guard the target."),
    "CMDI": (
        "An operating-system command is built from a value the caller supplies and executed from ABAP.\n"
        "That crosses the boundary out of the SAP application into the host, where the code runs as the SAP system user and can reach the file system, the database and the network the application server sits on.\n"
        "This is the shortest route from an application vulnerability to full host compromise, and it is a documented hop in this product's attack paths for exactly that reason.",
        REVIEW +
        "2. Remove the interpolation: use a pre-registered external command whose arguments are fixed, so the caller chooses a command rather than composes one.\n"
        "3. Where an argument must vary, constrain it to an allowlist and reject anything containing shell metacharacters instead of trying to escape them.\n"
        "4. Restrict who may trigger the path with an AUTHORITY-CHECK, and confirm the authorization object is one the caller does not already hold for other reasons.\n"
        f"5. {VERIFY}"
        f"6. {GOVERN}"),
    "PATH": (
        "A file path opened by the application is built from input, so a caller supplying directory-traversal sequences reads or writes files the application never intended to expose.\n"
        "On an SAP application server the reachable files include trace and profile data, and in the worst case interfaces whose contents feed other systems.\n"
        "A write primitive is worse than a read one: dropping a file into a directory that another job consumes turns a file bug into code execution.",
        REVIEW +
        "2. Resolve the path against a fixed base directory and reject the result unless it still sits under that base after normalisation.\n"
        "3. Validate the file name against an allowlist pattern; strip nothing, reject instead — stripping traversal sequences is defeated by encoding them twice.\n"
        "4. Use the logical file name mechanism so the physical path comes from customising rather than from the caller.\n"
        f"5. {VERIFY}"),
    "XSS": (
        "Data is written into an HTML or JavaScript response without being encoded for the context it lands in, so a value supplied by one user executes as script in another user's browser.\n"
        "Inside SAP the victim is usually an authenticated business user, and the script runs with their session — so it can act as them against every service that session reaches.\n"
        "The Fiori launchpad makes this worse than a classic web application: one compromised tile has the user's whole catalogue behind it.",
        REVIEW +
        "2. Encode on output, for the exact context: HTML body, HTML attribute, URL and JavaScript each need a different encoding, and one encoder is not correct for all four.\n"
        "3. Prefer the framework's escaping mechanism over hand-rolled replacement of angle brackets.\n"
        "4. Set a Content-Security-Policy on the ICF node so an injected inline script does not execute even if one is missed.\n"
        f"5. {VERIFY}"),
    "AUTH": (
        "The statement performs a privileged action — reading, writing or deleting business data, calling out to another system, or starting a transaction — without an authorization check that governs it.\n"
        "Authorization in ABAP is not enforced by the database or the runtime; it happens only where a developer writes AUTHORITY-CHECK. A missing check is therefore not a weakened control but an absent one.\n"
        "Any user who can reach the code path can perform the action, regardless of their role, and the failure is invisible in role reviews because there is no role to review.",
        REVIEW +
        "2. Add an AUTHORITY-CHECK before the action, against the authorization object that actually governs it — for business data that is the object the standard transaction checks, not a convenient generic one.\n"
        "3. Check SY-SUBRC immediately after and stop processing when it is non-zero; an unchecked AUTHORITY-CHECK is the same as no check.\n"
        "4. Maintain the authorization proposal for the object so the check appears in role maintenance and can be reviewed.\n"
        "5. Verify by executing the path as a user who should be refused, and confirm the refusal.\n"
        f"6. {GOVERN}"),
    "CRED": (
        "A password, key or other secret is written into the source, where it is readable by anyone who can display the object and by everyone who has ever received a transport containing it.\n"
        "A hardcoded credential cannot be rotated without a code change and a transport, so in practice it is never rotated.\n"
        "It also leaves the system: source travels in transports, in support incidents and in backups, and the secret travels with it.",
        REVIEW +
        "2. Move the secret into the secure store the platform provides, and read it at runtime rather than embedding it.\n"
        "3. Rotate the exposed value — it must be assumed compromised, because it has been readable for as long as the code has existed.\n"
        "4. Where the secret authenticates to another SAP system, replace the stored password with trusted-system RFC or certificate-based authentication so there is no secret to hold.\n"
        "5. Search the transport history for the same value; a credential in one object is usually in several.\n"
        f"6. {VERIFY}"),
    "CRYP": (
        "The code uses a cryptographic algorithm or mode that is no longer considered sound — a broken hash, a short key, or an unauthenticated mode.\n"
        "Weak cryptography does not fail visibly: the data is still protected against a casual reader, and the weakness only matters when someone is actually attacking it.\n"
        "Where the algorithm protects a password or a token, the practical effect is that the protection can be undone offline, at leisure, with no further access to the system.",
        REVIEW +
        "2. Replace the algorithm with a current one — a SHA-2 family hash for integrity, and an authenticated mode for encryption.\n"
        "3. Use the platform's cryptographic library rather than a hand-written implementation; a correct algorithm used incorrectly is still broken.\n"
        "4. Re-protect any data that was written under the weak algorithm, since changing the code does not change what is already stored.\n"
        f"5. {VERIFY}"),
    "INFO": (
        "The code returns internal detail — a system message, a dump, a technical identifier or a stack trace — to a caller who should not see it.\n"
        "Individually these are not exploitable; collectively they are how an attacker maps the estate, learns which release and which custom objects are present, and chooses the next thing to try.\n"
        "Detailed error text is the most valuable of these, because it usually confirms whether an injection attempt reached the layer the attacker was aiming at.",
        REVIEW +
        "2. Return a generic message to the caller and write the detail to the application log, where it stays available for support without being disclosed.\n"
        "3. Ensure the failure path cannot dump: an unhandled exception reaching the caller usually discloses more than the message being fixed.\n"
        f"4. {VERIFY}"),
    "CONF": (
        "The code disables or weakens a protection the platform provides by default — a security check switched off, a validation skipped, or a permissive setting hardcoded.\n"
        "Because it is expressed in code rather than in configuration, it does not appear in any configuration review, and the parameter it undermines still reads as correctly set.\n"
        "That gap between what the configuration says and what the code does is what makes this class worth reporting separately.",
        REVIEW +
        "2. Remove the override and let the platform default apply; where the override was added to work around a failure, fix the failure instead.\n"
        "3. If the weakening is genuinely required, scope it to the narrowest block that needs it rather than to the whole program.\n"
        "4. Record the exception so a configuration review can see that the code contradicts the setting.\n"
        f"5. {VERIFY}"),
    "RFC": (
        "A remote call is made in a way that trusts the far side, the caller, or a stored credential more than it should — an unvalidated destination, a callback that the caller can steer, or a call made without checking who asked for it.\n"
        "RFC is how SAP systems reach each other, so a weakness here is a route between systems rather than within one, and it usually crosses a tier boundary.\n"
        "Where the destination carries a stored user, the calling code lends its identity to whoever can reach the code path.",
        REVIEW +
        "2. Validate the destination against an allowlist; never call a destination whose name came from input.\n"
        "3. Add an AUTHORITY-CHECK before the call — the authorization on the far side governs the destination's user, not the caller.\n"
        "4. Where the call crosses a tier boundary, confirm the trust relationship is intended in that direction; inbound trust from a lower tier is the more dangerous half.\n"
        "5. Restrict the callable function modules on the receiving side so a compromised caller cannot pivot to arbitrary remote functions.\n"
        f"6. {VERIFY}"),
    "BKDR": (
        "The statement matches a pattern associated with deliberately hidden functionality — a hardcoded user comparison, a debug hook, a hidden parameter that changes behaviour, or code that grants access on a value only its author would know.\n"
        "This class is different from the others in kind, not degree: the others are mistakes, and this one may not be.\n"
        "Treat a match as an investigation rather than a defect to schedule. A false positive here is cheap; a missed one is an insider with a permanent way in.",
        "1. Do not delete the code yet. Preserve the object, its version history and the transport that introduced it — the change record is the evidence.\n"
        "2. Identify who wrote it and when, from the object's version history and the transport it arrived in.\n"
        "3. Establish whether there is a legitimate explanation: support hooks and test scaffolding look identical to a backdoor and are far more common.\n"
        "4. If there is no legitimate explanation, treat it as a security incident and follow the incident process rather than the defect process.\n"
        "5. Once the investigation is closed, remove the code and rotate any credential or identifier it referenced.\n"
        f"6. {GOVERN}"),
    "JS": (
        "The finding is in UI5 / JavaScript delivered by the SAP front end, where it executes in the user's browser rather than on the application server.\n"
        "SAP's own Code Vulnerability Analyzer reads ABAP and does not cover this code at all, so a customer relying solely on ATC has no coverage here.\n"
        "The consequence is the same as any browser-side flaw — script executing with the victim's authenticated session — with the difference that the session is a business user's.",
        "1. Open the UI5 artefact and read the reported statement in context.\n"
        "2. Render data as text rather than as HTML; use the framework's own binding and formatting instead of writing markup from values.\n"
        "3. Where HTML genuinely must be produced, sanitise with the framework's sanitiser rather than by filtering characters.\n"
        "4. Remove any secret, endpoint or internal identifier embedded in front-end code — everything delivered to the browser is readable by the user.\n"
        f"5. {VERIFY}"),
    "BTP": (
        "The finding is in a deployment descriptor — the security descriptor, the application router configuration or the deployment manifest — rather than in program code.\n"
        "These files decide who may call the application and what the platform enforces before a request ever reaches it, so a permissive descriptor silently undoes the checks the code performs.\n"
        "They are also frequently copied between projects, so one weak template propagates across an estate.",
        "1. Open the descriptor and compare it against the platform's documented secure defaults.\n"
        "2. Remove wildcard scopes and wildcard route targets; name the scopes and the destinations explicitly.\n"
        "3. Require authentication on every route that is not deliberately public, and confirm the public ones really are.\n"
        "4. Check the same file in every other application that was created from the same template.\n"
        f"5. {VERIFY}"),
}

#: The ATC import raises the same defect classes from SAP's own engine.
ATC_ALIASES = {"ATC-SQLI": "SQLI", "ATC-CINJ": "CINJ", "ATC-CMDI": "CMDI",
               "ATC-AUTHCHK": "AUTH", "ATC-PATH": "PATH", "ATC-XSS": "XSS",
               "ATC-CRED": "CRED", "ATC-RFC": "RFC", "ATC-CRYP": "CRYP",
               "ATC-INFO": "INFO"}

kb = json.loads(KB.read_text(encoding="utf-8"))
before = len(kb)

for family, (risk, mitigation) in FAMILIES.items():
    kb[f"ABAP-{family}"] = {"risk": risk, "mitigation": mitigation, "detailed": ""}
for atc_key, family in ATC_ALIASES.items():
    risk, mitigation = FAMILIES[family]
    kb[atc_key] = {
        "risk": ("This was reported by SAP's own code analysis (ABAP Test Cockpit / "
                 "Code Vulnerability Analyzer) running inside the system, not by this "
                 "product's scanner.\n" + risk),
        "mitigation": mitigation, "detailed": ""}

KB.write_text(json.dumps(kb, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"knowledge base: {before} -> {len(kb)} entries "
      f"(+{len(FAMILIES)} ABAP families, +{len(ATC_ALIASES)} ATC families)")
