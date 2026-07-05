"""
Basis Jobs & External OS-Command Auditor
========================================
The realised host-command-execution and background-processing attack surface —
the layer where an SAP misconfiguration turns into operating-system code
execution or batch privilege escalation. It inspects the *definitions* and
*assignments*, not just the authorization objects:

  - External OS-command definitions (SM69 / table SXPGCOSTAB) that wrap a shell
    or interpreter, allow runtime argument injection (ADDPAR), or resolve to an
    unqualified / user-writable path.
  - Standing external commands that are destructive or exfiltration-capable.
  - Armed background jobs (TBTCO) and their steps (TBTCP) whose step user
    (AUTHCKNAM) is a standard/privileged account (DDIC, SAP*, SAP_ALL holder …),
    that shell out to an OS command/program, that run RSBDCOS0 (direct OS
    command, bypassing the SM69 allowlist) or unreviewed custom code, or whose
    step user differs from the scheduler (identity borrowing).

Complements — but does not duplicate — the ABAP Authorization module, which
covers who *can* run commands / set a foreign step user (S_LOG_COM, S_BTCH_NAM):
this module reports the *actual* command catalog and the *actual* armed jobs.

Data sources:
  - ext_os_commands.csv     → SXPGCOSTAB (customer external OS commands, SM69):
                              NAME, OPSYSTEM, OPCOMMAND, PARAMETERS, ADDPAR
  - ext_os_commands_sap.csv → SXPGCOTABE (SAP-delivered commands) — optional
  - background_jobs.csv      → TBTCO (job header): JOBNAME, JOBCOUNT, STATUS,
                              SDLUNAME, AUTHCKNAM
  - background_job_steps.csv → TBTCP (job steps): JOBNAME, JOBCOUNT, STEPCOUNT,
                              PROGNAME, XPGFLAG, EXTCMD, XPGPROG, AUTHCKNAM
  - reuses users.csv (USR02: BNAME/UFLAG/USTYP/GLTGB) and profiles.csv (USR04:
    BNAME/PROFILE) to resolve privileged (SAP_ALL/SAP_NEW) step users.
"""

import re
from typing import Dict, List, Any
from modules.base_auditor import BaseAuditor


class BasisJobCommandAuditor(BaseAuditor):

    CATEGORY = "Basis Jobs & OS Commands"

    # shells / interpreters that neutralise the SM69 allowlist into arbitrary execution
    # basenames are compared extension-insensitively (see _basename), so list the
    # bare interpreter names — 'python.exe', 'cmd.exe' etc. are normalised first.
    SHELLS = {
        "sh", "bash", "ksh", "zsh", "csh", "tcsh", "ash", "dash",
        "cmd", "command", "powershell", "pwsh",
        "python", "python2", "python3", "perl", "ruby", "php", "node",
        "cscript", "wscript", "sudo", "su",
        "at", "nohup", "eval", "xargs", "env", "sapevt",
    }
    # destructive / exfiltration verbs whose mere presence is a ready primitive
    DANGER_VERBS = {
        "rm", "del", "erase", "format", "dd", "mkfs", "shred", "rmdir",
        "curl", "wget", "tftp", "ftp", "nc", "ncat", "netcat", "scp", "rsync",
        "reg", "net", "sc", "certutil", "bitsadmin", "openssl", "base64",
        "chmod", "chown", "chgrp", "kill", "shutdown", "reboot",
    }
    # '&&' (chaining) not bare '&', so legitimate SM69 '&1 &2' parameter placeholders don't fire
    SHELL_METACHARS = ("|", ";", "&&", "`", "$(", ">", "<", "\n")
    # normalised to lowercase forward-slash; matched as an anchored path prefix (see check_command_path)
    WRITABLE_PATHS = ("/tmp", "/var/tmp", "/dev/shm", "/home",
                      "%temp%", "%tmp%", "c:/users", "c:/temp",
                      "c:/windows/temp", "c:/tmp")
    STANDARD_USERS = {"DDIC", "SAP*", "SAPCPIC", "EARLYWATCH", "TMSADM"}
    # job header STATUS codes that mean the job WILL run (armed): scheduled/released/ready/active
    ARMED_STATUS = {"P", "S", "Y", "R"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._priv_users = self._privileged_users()
        self._user_index = self._user_master_index()
        self.check_command_shell_wrap()
        self.check_command_addpar()
        self.check_command_path()
        self.check_command_danger_verbs()
        self.check_command_any_os()
        self.check_job_privileged_step_user()
        self.check_job_external_step()
        self.check_job_os_report()
        self.check_job_stale_step_user()
        self.check_job_identity_borrow()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _rows(data) -> list:
        return [r for r in (data or []) if isinstance(r, dict)]

    @staticmethod
    def _get(row: dict, *names: str) -> str:
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    def _privileged_users(self) -> set:
        """Users who effectively hold SAP_ALL / SAP_NEW (via profile assignment)."""
        priv = set()
        for row in self._rows(self.data.get("profiles")):
            prof = self._get(row, "PROFILE", "PROFN", "PROFILE_NAME").upper()
            user = self._get(row, "BNAME", "UNAME", "USER", "USERNAME").upper()
            if user and prof in ("SAP_ALL", "SAP_NEW", "S_A.SYSTEM"):
                priv.add(user)
        return priv

    def _user_master_index(self) -> Dict[str, Dict[str, str]]:
        idx = {}
        for row in self._rows(self.data.get("users")):
            bname = self._get(row, "BNAME", "USERNAME", "UNAME").upper()
            if bname:
                idx[bname] = {
                    "lock": self._get(row, "UFLAG", "LOCK_STATUS", "LOCK"),
                    "type": self._get(row, "USTYP", "USER_TYPE", "TYPE").upper(),
                    "valid_to": self._get(row, "GLTGB", "VALID_TO", "GLTB"),
                }
        return idx

    def _step_user_class(self, user: str) -> str:
        """Classify a batch step user: 'critical' (SAP*/DDIC/SAP_ALL), 'standard', or ''."""
        u = (user or "").strip().upper()
        if not u:
            return ""
        if u in ("SAP*", "DDIC") or u in self._priv_users:
            return "critical"
        if u in self.STANDARD_USERS:
            return "standard"
        return ""

    @staticmethod
    def _basename(cmd: str) -> str:
        c = (cmd or "").strip().strip('"').strip("'").replace("\\", "/")
        first = c.split(" ")[0] if c else ""
        base = first.rsplit("/", 1)[-1].lower()
        # strip a trailing executable extension so 'python.exe'/'curl.exe' match the sets
        return re.sub(r"\.(exe|com|bat|cmd|ps1|vbs|scr|msi)$", "", base)

    def _ext_commands(self) -> list:
        return self._rows(self.data.get("ext_os_commands")) + \
            self._rows(self.data.get("ext_os_commands_sap"))

    def _armed_steps(self):
        """Yield (job_label, step_dict, job_header) for steps of armed jobs."""
        headers = {}
        for h in self._rows(self.data.get("background_jobs")):
            key = (self._get(h, "JOBNAME", "NAME"), self._get(h, "JOBCOUNT", "COUNT"))
            headers[key] = h
        steps = self._rows(self.data.get("background_job_steps"))
        if steps:
            for s in steps:
                key = (self._get(s, "JOBNAME", "NAME"), self._get(s, "JOBCOUNT", "COUNT"))
                header = headers.get(key, {})
                status = self._get(header, "STATUS", "JOBSTATUS", "JOB_STATUS").upper() if header else ""
                # if we have a header, honour its status; if not, assume armed (can't prove otherwise)
                if header and status and status not in self.ARMED_STATUS:
                    continue
                jn = self._get(s, "JOBNAME", "NAME")
                yield (f"{jn}", s, header)
        else:
            # header-only export: use TBTCO's own AUTHCKNAM as a single pseudo-step
            for (jn, _jc), h in headers.items():
                status = self._get(h, "STATUS", "JOBSTATUS", "JOB_STATUS").upper()
                if status and status not in self.ARMED_STATUS:
                    continue
                yield (jn, h, h)

    # --------------------------------------------------------------- CMD checks
    def check_command_shell_wrap(self):
        offenders = []
        for c in self._ext_commands():
            name = self._get(c, "NAME", "SXPGLOGCMD", "COMMAND_NAME")
            opcmd = self._get(c, "OPCOMMAND", "BTCXPGPGM", "COMMAND", "PROGRAM")
            params = self._get(c, "PARAMETERS", "BTCXPGPAR", "PARAM")
            base = self._basename(opcmd)
            meta = any(mc in (opcmd + " " + params) for mc in self.SHELL_METACHARS)
            if base in self.SHELLS or meta:
                why = "wraps a shell/interpreter" if base in self.SHELLS else "contains shell metacharacters"
                offenders.append(f"{name or '?'} -> {opcmd} {params}".strip() + f"  ({why})")
        if offenders:
            self.finding(
                check_id="JOBCMD-CMD-001",
                title="External OS command wraps a shell / interpreter",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} external OS command definition(s) (SM69 / SXPGCOSTAB) "
                    "invoke a shell or interpreter, or embed shell metacharacters. The SM69 "
                    "allowlist is meant to constrain execution to a fixed program, but wrapping a "
                    "shell (or piping via metacharacters) turns any SXPG_COMMAND_EXECUTE / SM49 "
                    "caller into arbitrary operating-system command execution as the SAP service "
                    "user (<sid>adm)."
                ),
                affected_items=offenders,
                remediation=(
                    "Redefine each command to call the specific target executable directly with a "
                    "fixed argument list; never call sh/bash/cmd/powershell/python etc. or use "
                    "shell metacharacters. Remove commands that exist only to run a shell."
                ),
                references=["SAP Help — Maintaining External OS Commands (SM49/SM69)",
                            "SecurityBridge — SAP OS Command Injection (SAPXPG)"],
            )

    def check_command_addpar(self):
        offenders = []
        for c in self._ext_commands():
            name = self._get(c, "NAME", "SXPGLOGCMD")
            opcmd = self._get(c, "OPCOMMAND", "BTCXPGPGM", "COMMAND")
            addpar = self._get(c, "ADDPAR", "SXPGADDPAR", "ADD_PARAMETERS", "ALLOW_ADDPAR")
            if self._truthy(addpar):
                offenders.append(f"{name or '?'} -> {opcmd}  (additional parameters allowed)")
        if offenders:
            self.finding(
                check_id="JOBCMD-CMD-002",
                title="External OS command allows runtime additional parameters (ADDPAR)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} external OS command(s) are flagged 'additional parameters "
                    "allowed' (SXPGCOSTAB-ADDPAR = X). Callers of SXPG_COMMAND_EXECUTE / SM49 can "
                    "then append arbitrary arguments — and, on many targets, shell metacharacters — "
                    "at run time, turning an allowlisted command into an OS-command-injection "
                    "primitive even though the base program looks harmless."
                ),
                affected_items=offenders,
                remediation=(
                    "In SM69, edit each command and clear 'Additional Parameters Allowed' unless a "
                    "specific, reviewed use case requires it; where run-time input is unavoidable, "
                    "validate/escape it in the calling ABAP and restrict who holds S_LOG_COM."
                ),
                references=["SAP Help — External OS Commands: Additional Parameters (SM69)"],
            )

    def check_command_path(self):
        offenders = []
        for c in self._ext_commands():
            name = self._get(c, "NAME", "SXPGLOGCMD")
            opcmd = self._get(c, "OPCOMMAND", "BTCXPGPGM", "COMMAND")
            if not opcmd:
                continue
            prog = opcmd.strip().strip('"').split(" ")[0]
            low = prog.lower().replace("\\", "/")
            bare = ("/" not in prog and "\\" not in prog)
            relative = prog.startswith("./") or prog.startswith("../") or prog.startswith(".\\")
            writable = any(low == wp or low.startswith(wp + "/") for wp in self.WRITABLE_PATHS)
            if bare or relative or writable:
                why = ("unqualified name (PATH-search hijack)" if bare else
                       "relative path" if relative else "user-writable/temp location")
                offenders.append(f"{name or '?'} -> {prog}  ({why})")
        if offenders:
            self.finding(
                check_id="JOBCMD-CMD-003",
                title="External OS command resolves to an unqualified or writable path",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} external OS command(s) reference the target program by a "
                    "bare name (resolved via the PATH — a search-order hijack), a relative path, or "
                    "a user-writable / temp location. An attacker who can drop or replace a file in "
                    "that directory has the SAP host execute their binary as <sid>adm the next time "
                    "the command runs."
                ),
                affected_items=offenders,
                remediation=(
                    "Specify every external command with a fully-qualified, absolute path to a "
                    "root-owned, non-writable directory; never rely on PATH resolution or place "
                    "executables in world-writable/temp paths. Verify OS file permissions on each "
                    "referenced program."
                ),
                references=["SAP Help — External OS Commands (SM69) path definition",
                            "SAP Security Baseline — OS command hardening"],
            )

    def check_command_danger_verbs(self):
        offenders = []
        for c in self._ext_commands():
            name = self._get(c, "NAME", "SXPGLOGCMD")
            opcmd = self._get(c, "OPCOMMAND", "BTCXPGPGM", "COMMAND")
            base = self._basename(opcmd)
            if base in self.DANGER_VERBS:
                offenders.append(f"{name or '?'} -> {opcmd}  ({base})")
        if offenders:
            self.finding(
                check_id="JOBCMD-CMD-004",
                title="Destructive / exfiltration OS command defined as a standing command",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} external OS command(s) wrap a destructive or data-movement "
                    "utility (rm/del/dd/format, curl/wget/ftp/nc/scp, reg/net/certutil …). As a "
                    "standing, SM49-callable command these are ready-made primitives for data "
                    "destruction, lateral movement and exfiltration from the SAP host."
                ),
                affected_items=offenders,
                remediation=(
                    "Remove destructive/network utilities from the external-command catalog unless "
                    "there is a documented operational need; where genuinely required, scope tightly "
                    "and restrict S_LOG_COM to a small set of operators."
                ),
                references=["SAP Help — External OS Commands (SM69)",
                            "Onapsis / CISA — SAP OS command abuse"],
            )

    def check_command_any_os(self):
        offenders = []
        for c in self._ext_commands():
            name = self._get(c, "NAME", "SXPGLOGCMD")
            osys = self._get(c, "OPSYSTEM", "SYOPSYS", "TARGET_OS", "OS")
            if osys == "" or osys.upper() in ("ANYOS", "*", "ALL"):
                offenders.append(f"{name or '?'}  (OS: {osys or 'unspecified'})")
        if offenders:
            self.finding(
                check_id="JOBCMD-CMD-005",
                title="External OS command not bound to a specific operating system",
                severity=self.SEVERITY_LOW,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} external OS command(s) are defined for 'any' / unspecified "
                    "operating system. Binding each logical command to a concrete OS narrows where "
                    "and how it can be executed and is SAP best practice; an unbound command is more "
                    "portable for an attacker across heterogeneous application servers."
                ),
                affected_items=offenders,
                remediation=(
                    "In SM69, define each logical command for the specific target operating system "
                    "rather than 'Any Operating System'."
                ),
                references=["SAP Help — External OS Commands: operating-system binding (SM69)"],
            )

    # --------------------------------------------------------------- JOB checks
    def check_job_privileged_step_user(self):
        crit, high = [], []
        for label, step, _h in self._armed_steps():
            user = self._get(step, "AUTHCKNAM", "STEP_USER", "BTCUSER", "AUTH_USER")
            cls = self._step_user_class(user)
            if cls == "critical":
                crit.append(f"{label} — step user {user}")
            elif cls == "standard":
                high.append(f"{label} — step user {user}")
        if crit:
            self.finding(
                check_id="JOBCMD-JOB-001",
                title="Armed background job runs under SAP*/DDIC or a SAP_ALL step user",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(crit)} armed background job step(s) execute under a step user "
                    "(TBTCP/TBTCO-AUTHCKNAM) that is SAP*, DDIC, or a holder of SAP_ALL/SAP_NEW. "
                    "The step runs with that identity's full authorizations, so any report or "
                    "external command in the job effectively runs as an unrestricted superuser — a "
                    "direct privilege-escalation and control-bypass path, and against SAP's rule "
                    "that background users must not hold SAP_ALL."
                ),
                affected_items=crit,
                remediation=(
                    "Reassign these jobs to a dedicated, least-privilege background (type B / "
                    "system) user carrying only the authorizations the job needs; never run "
                    "productive jobs under SAP*/DDIC or a SAP_ALL account. Use SM37 to review job "
                    "step users and re-plan the jobs with a proper technical user."
                ),
                references=["SAP Security Baseline — background users must not hold SAP_ALL",
                            "SAP Help — Background job step authorization user (SM36/SM37)"],
            )
        if high:
            self.finding(
                check_id="JOBCMD-JOB-001B",
                title="Armed background job runs under a standard/technical step user",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(high)} armed background job step(s) run under a standard account "
                    "(SAPCPIC / EARLYWATCH / TMSADM). These accounts have known purposes and often "
                    "broad or default access; using them as a batch step user borrows their "
                    "privileges and obscures accountability."
                ),
                affected_items=high,
                remediation=(
                    "Move these jobs to a purpose-built least-privilege background user; lock the "
                    "standard accounts for interactive/batch use where they are not required."
                ),
                references=["SAP Help — Background processing users (SM36/SM37)"],
            )

    def check_job_external_step(self):
        offenders = []
        for label, step, _h in self._armed_steps():
            # PROGNAME (the ABAP report) is read separately; do NOT alias it here or every
            # ABAP step would look external. XPGFLAG is CHAR1 ('X' = external command/program).
            xpgflag = self._get(step, "XPGFLAG", "STEP_TYPE").upper()
            extcmd = self._get(step, "EXTCMD", "EXT_COMMAND")
            xpgprog = self._get(step, "XPGPROG", "EXT_PROGRAM")
            is_ext = bool(extcmd) or bool(xpgprog) or xpgflag == "X"
            if is_ext:
                user = self._get(step, "AUTHCKNAM", "STEP_USER", "BTCUSER")
                tag = extcmd or xpgprog or "external step"
                priv = "  [privileged step user]" if self._step_user_class(user) else ""
                offenders.append(f"{label} -> {tag} (user {user or '?'}){priv}")
        if offenders:
            self.finding(
                check_id="JOBCMD-JOB-002",
                title="Background job step executes an external OS command / program",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} armed background job step(s) run an external OS command or "
                    "external program (TBTCP XPGFLAG / EXTCMD / XPGPROG) rather than an ABAP report. "
                    "This is the realised OS-execution surface of the job scheduler; combined with a "
                    "shell-wrapping or ADDPAR-enabled command definition, or a privileged step user, "
                    "it is a direct route to host command execution."
                ),
                affected_items=offenders,
                remediation=(
                    "Review every job step that calls an external command/program: confirm the "
                    "business need, that the referenced SM69 command is safe (no shell wrap / "
                    "ADDPAR / writable path), and that the step user is least-privilege. Prefer "
                    "ABAP-native processing over shelling out where possible."
                ),
                references=["SAP Help — External command/program job steps (SM36)",
                            "SAP Datasheet — table TBTCP (XPGFLAG / EXTCMD / XPGPROG)"],
            )

    def check_job_os_report(self):
        offenders = []
        for label, step, _h in self._armed_steps():
            prog = self._get(step, "PROGNAME", "REPORT", "ABAP_PROGRAM").upper()
            user = self._get(step, "AUTHCKNAM", "STEP_USER", "BTCUSER")
            priv = self._step_user_class(user)
            if prog == "RSBDCOS0":
                offenders.append(f"{label} -> RSBDCOS0 (direct OS command, bypasses SM69) — user {user or '?'}")
            elif prog.startswith(("Z", "Y")) and priv:
                offenders.append(f"{label} -> custom report {prog} under privileged user {user}")
        if offenders:
            self.finding(
                check_id="JOBCMD-JOB-003",
                title="Job runs RSBDCOS0 or unreviewed custom code under a privileged user",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} armed job step(s) either run RSBDCOS0 — the standard report "
                    "that executes an operating-system command directly, bypassing the SM69 "
                    "allowlist — or run a custom Z/Y program under a privileged step user. Either "
                    "way, code that can reach the OS or do anything the powerful batch user can is "
                    "executing on a schedule with little oversight."
                ),
                affected_items=offenders,
                remediation=(
                    "Remove RSBDCOS0 from scheduled jobs and restrict authorization to run it; "
                    "review custom Z/Y batch programs for OS access and reassign them to a "
                    "least-privilege step user. Investigate any RSBDCOS0 schedule as a potential "
                    "backdoor."
                ),
                references=["SAP KBA 2443193 — Report RSBDCOS0: execute OS command from SAP GUI (SM69-allowlist bypass)",
                            "SAP Help — Background processing security"],
            )

    def check_job_stale_step_user(self):
        offenders = []
        for label, step, _h in self._armed_steps():
            user = self._get(step, "AUTHCKNAM", "STEP_USER", "BTCUSER").upper()
            if not user:
                continue
            info = self._user_index.get(user)
            reason = ""
            if info is None and self._user_index:
                reason = "deleted / not in user master (can be re-created to hijack the job)"
            elif info:
                if str(info["lock"]).strip() not in ("0", ""):
                    reason = "locked"
                elif info["type"] in ("A", "DIALOG"):
                    reason = "dialog user used for batch"
                elif self._expired(info["valid_to"]):
                    reason = f"expired (valid to {info['valid_to']})"
            if reason:
                offenders.append(f"{label} — step user {user} ({reason})")
        if offenders:
            self.finding(
                check_id="JOBCMD-JOB-004",
                title="Armed job step user is deleted, locked, expired, or a dialog user",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} armed job step(s) run under a step user that is absent from "
                    "the user master (a deleted account whose name could be re-created to hijack the "
                    "job's authorizations), locked, past its validity date, or a dialog user (batch "
                    "should use a dedicated system/background user). Each is a job-hygiene and "
                    "potential-hijack issue."
                ),
                affected_items=offenders,
                remediation=(
                    "Re-plan affected jobs onto a valid, unlocked, least-privilege system (type B) "
                    "background user; never leave a job pointing at a deleted or dialog account. "
                    "Review whether locked/expired step users indicate an abandoned job."
                ),
                references=["SAP Help — Background job step user (SM37) / user types (SU01)"],
            )

    def check_job_identity_borrow(self):
        offenders = []
        for label, step, header in self._armed_steps():
            user = self._get(step, "AUTHCKNAM", "STEP_USER", "BTCUSER").upper()
            sched = self._get(step, "SDLUNAME", "SCHEDULER", "CREATOR").upper() or \
                self._get(header, "SDLUNAME", "SCHEDULER", "CREATOR").upper()
            if user and sched and user != sched and self._step_user_class(user):
                offenders.append(f"{label} — scheduled by {sched}, runs as {user}")
        if offenders:
            self.finding(
                check_id="JOBCMD-JOB-005",
                title="Background job step user differs from scheduler (identity borrowing)",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} armed job(s) are scheduled by one user but run under a "
                    "different, more-privileged step user. A lower-privileged scheduler thereby "
                    "gets code executed with a stronger identity's authorizations — a subtle "
                    "privilege-escalation and accountability gap."
                ),
                affected_items=offenders,
                remediation=(
                    "Ensure the step user reflects the least privilege actually required and that "
                    "the scheduler is authorized (S_BTCH_NAM) to use it; investigate cases where a "
                    "non-administrator schedules jobs running as a powerful technical user."
                ),
                references=["SAP Help — S_BTCH_NAM / background step user",
                            "SAP Security Baseline — background processing"],
            )

    # ------------------------------------------------------------------ util
    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "true", "yes", "on", "x")

    @staticmethod
    def _expired(valid_to: str) -> bool:
        s = (valid_to or "").strip()
        if not s or s in ("99991231", "9999-12-31", "31.12.9999"):
            return False
        from datetime import datetime
        for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y"):
            try:
                return datetime.strptime(s, fmt).date() < datetime.now().date()
            except ValueError:
                continue
        return False
