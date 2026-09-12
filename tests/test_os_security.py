"""OS & infrastructure hardening (`os_security`).

These tests prove the five OSEC checks fire on a misconfigured host, stay silent
on a compliant one, and self-skip when the OS export is absent — the "absence is
not insecure" discipline the whole product follows. They also pin the wiring that
makes the module deployment-mode-aware without reading the mode: the ownership
flip (customer_fixable on-prem, not_assessable in RISE when the host is out of
reach) lives entirely in modules/rise_ownership.py, and this file holds it there.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.os_security import OSSecurityAuditor            # noqa: E402


def _run(data):
    return OSSecurityAuditor(data, {}, {"deployment_mode": "on_prem",
                                        "modules": set()}).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


def _by_id(findings, cid):
    return next(f for f in findings if f["check_id"] == cid)


# ── absence is not insecure ──────────────────────────────────────────────────

def test_a_host_with_no_os_export_produces_nothing():
    """The whole family self-skips when its sources are absent. A RISE estate
    that cannot produce an OS export must not be reported as failing."""
    assert _run({}) == []
    assert _run({"os_users": None, "os_file_permissions": None,
                 "os_services": None}) == []


def test_each_check_reads_only_its_own_source():
    """Supplying one source must not make another check fire on missing data."""
    only_services = _run({"os_services": [{"name": "telnet", "state": "enabled"}]})
    assert _ids(only_services) == {"OSEC-NET-001"}


# ── OSEC-USR-001: service-account privilege ──────────────────────────────────

def test_windows_service_account_in_administrators_fires():
    findings = _run({"os_users": [
        {"name": "SAPServicePRD", "groups": "Administrators"}]})
    f = _by_id(findings, "OSEC-USR-001")
    assert f["severity"] == "HIGH"
    assert f["scope"] == "object"
    assert f["affected_objects"] == [{"type": "os_user", "name": "SAPServicePRD"}]


def test_windows_admin_membership_seen_from_the_group_export():
    """The Administrators membership can arrive on the group row rather than the
    user row, and must be read either way."""
    findings = _run({
        "os_users": [{"name": "sapadm"}],
        "os_groups": [{"group": "Administrators", "members": "Domain Admins,sapadm"}],
    })
    assert "OSEC-USR-001" in _ids(findings)


def test_sapadm_with_root_fires():
    findings = _run({"os_users": [{"name": "sapadm", "uid": "0"}]})
    assert "OSEC-USR-001" in _ids(findings)


def test_sidadm_with_root_fires():
    findings = _run({"os_users": [{"name": "prdadm", "uid": "0", "groups": "root"}]})
    assert "OSEC-USR-001" in _ids(findings)


def test_a_compliant_sidadm_is_silent():
    """<sid>adm is an admin on Windows BY DESIGN and a normal uid on UNIX. A
    non-root <sid>adm must not fire — flagging SAP's own design is a false
    positive."""
    findings = _run({"os_users": [
        {"name": "prdadm", "uid": "1001", "groups": "sapsys"},
        {"name": "sapadm", "uid": "1002", "groups": "sapsys"}]})
    assert "OSEC-USR-001" not in _ids(findings)


def test_each_privileged_account_is_its_own_finding():
    """Object scope: two offending accounts are two findings, so closing one does
    not retire the other."""
    findings = _run({"os_users": [
        {"name": "sapadm", "uid": "0"},
        {"name": "SAPServicePRD", "groups": "Administrators"}]})
    usr = [f for f in findings if f["check_id"] == "OSEC-USR-001"]
    assert len(usr) == 2


# ── OSEC-USR-002: host-agent login shell ─────────────────────────────────────

def test_sapadm_with_interactive_shell_fires():
    findings = _run({"os_users": [{"name": "sapadm", "shell": "/bin/bash"}]})
    f = _by_id(findings, "OSEC-USR-002")
    assert f["severity"] == "MEDIUM"
    assert f["affected_objects"] == [{"type": "os_user", "name": "sapadm"}]


def test_sapadm_with_nologin_shell_is_silent():
    for shell in ("/bin/false", "/sbin/nologin", "/usr/sbin/nologin"):
        findings = _run({"os_users": [{"name": "sapadm", "shell": shell}]})
        assert "OSEC-USR-002" not in _ids(findings), shell


def test_a_users_export_without_a_shell_column_cannot_judge_the_shell():
    """No shell column is 'we cannot tell', not 'compliant' and not 'insecure'."""
    findings = _run({"os_users": [{"name": "sapadm", "uid": "1002"}]})
    assert "OSEC-USR-002" not in _ids(findings)


# ── OSEC-FILE-001: world-writable SAP directory ──────────────────────────────

@pytest.mark.parametrize("mode", ["777", "-rwxrwxrwx", "0757", "drwxr-xrwx"])
def test_world_writable_sap_directory_fires(mode):
    findings = _run({"os_file_permissions": [
        {"path": "/usr/sap/PRD/SYS/exe/run/disp+work", "mode": mode}]})
    f = _by_id(findings, "OSEC-FILE-001")
    assert f["severity"] == "HIGH"
    assert f["scope"] == "aggregate"
    assert f["affected_objects"][0]["type"] == "path"


def test_windows_everyone_write_fires():
    findings = _run({"os_file_permissions": [
        {"path": "E:\\usr\\sap\\PRD\\SYS", "acl": "Everyone:(F)"}]})
    assert "OSEC-FILE-001" in _ids(findings)


@pytest.mark.parametrize("mode", ["750", "755", "-rwxr-x---", "0700"])
def test_a_correctly_permissioned_sap_directory_is_silent(mode):
    findings = _run({"os_file_permissions": [
        {"path": "/usr/sap/PRD/SYS/exe", "mode": mode}]})
    assert "OSEC-FILE-001" not in _ids(findings)


def test_a_world_writable_path_outside_sap_is_ignored():
    """This module owns the SAP install, not the whole filesystem."""
    findings = _run({"os_file_permissions": [{"path": "/tmp/scratch", "mode": "777"}]})
    assert "OSEC-FILE-001" not in _ids(findings)


# ── OSEC-FILE-002: secure store / security directory ─────────────────────────

@pytest.mark.parametrize("mode", ["750", "755", "710", "-rwxr-x---"])
def test_secure_store_accessible_beyond_owner_fires(mode):
    findings = _run({"os_file_permissions": [
        {"path": "/usr/sap/PRD/SYS/global/security/rsecssfs/data", "mode": mode}]})
    f = _by_id(findings, "OSEC-FILE-002")
    assert f["severity"] == "MEDIUM"
    assert f["affected_objects"][0]["type"] == "path"


@pytest.mark.parametrize("mode", ["700", "-rwx------", "0700"])
def test_an_owner_only_secure_store_is_silent(mode):
    findings = _run({"os_file_permissions": [
        {"path": "/usr/sap/PRD/SYS/global/security", "mode": mode}]})
    assert "OSEC-FILE-002" not in _ids(findings)


# ── OSEC-NET-001: dangerous host services ────────────────────────────────────

@pytest.mark.parametrize("svc", ["telnet", "rlogin", "in.rshd", "rexec"])
def test_a_cleartext_remote_service_fires_high(svc):
    findings = _run({"os_services": [{"name": svc, "state": "enabled"}]})
    f = _by_id(findings, "OSEC-NET-001")
    assert f["severity"] == "HIGH"
    assert f["affected_objects"][0]["type"] == "os_service"


def test_nis_alone_fires_medium():
    findings = _run({"os_services": [{"name": "ypbind", "state": "running"}]})
    f = _by_id(findings, "OSEC-NET-001")
    assert f["severity"] == "MEDIUM"


def test_a_disabled_dangerous_service_is_a_real_answer_not_a_finding():
    """A service listed as disabled is present-and-off, which is compliant — the
    finding is present-and-on."""
    for state in ("disabled", "stopped", "inactive"):
        findings = _run({"os_services": [{"name": "telnet", "state": state}]})
        assert "OSEC-NET-001" not in _ids(findings), state


def test_ordinary_services_are_ignored():
    findings = _run({"os_services": [
        {"name": "sshd", "state": "enabled"},
        {"name": "saphostexec", "state": "running"}]})
    assert "OSEC-NET-001" not in _ids(findings)


# ── wiring: identity, ownership, coverage ────────────────────────────────────

def test_every_emitted_object_type_is_registered_for_identity():
    """os_user / path / os_service must all give a stable fingerprint, or a
    finding drops out of the console."""
    from server.identity import fingerprint_finding
    findings = _run({
        "os_users": [{"name": "sapadm", "uid": "0", "shell": "/bin/bash"}],
        "os_file_permissions": [
            {"path": "/usr/sap/PRD/SYS/exe", "mode": "777"},
            {"path": "/usr/sap/PRD/SYS/global/security", "mode": "750"}],
        "os_services": [{"name": "telnet", "state": "enabled"}],
    })
    assert len(findings) >= 5
    for f in findings:
        fp, basis = fingerprint_finding(f, system="PRD", client="100")
        assert len(fp) == 64
        assert basis in ("objects", "display", "check_only")


def test_the_family_is_customer_fixable_on_prem():
    from modules.rise_ownership import remediation_owner_for, team_for
    for cid in ("OSEC-USR-001", "OSEC-FILE-001", "OSEC-NET-001"):
        assert remediation_owner_for(cid, "on_prem") == "customer_fixable"
        assert team_for(cid) == "basis"


def test_the_family_is_not_assessable_in_rise_when_the_host_is_out_of_reach():
    """The honest RISE state: the customer can neither see nor change the host,
    exactly like TRUST-010. Not 'provider_owned', which would imply we assessed
    something we cannot see."""
    from modules.rise_ownership import remediation_owner_for
    assert remediation_owner_for("OSEC-USR-001", "rise_pce",
                                 data_was_supplied=False) == "not_assessable"


def test_an_os_export_supplied_in_rise_is_the_customers_to_fix():
    """If the customer got OS access some other way and uploaded it, the finding
    is real and theirs — the presence of the evidence flips it back."""
    from modules.rise_ownership import owner_for_finding
    finding = {"check_id": "OSEC-USR-001",
               "affected_objects": [{"type": "os_user", "name": "sapadm"}]}
    owner, _note = owner_for_finding(finding, "rise_pce",
                                     supplied_sources={"os_users"})
    assert owner == "customer_fixable"


def test_the_module_is_wired_into_every_registry():
    from modules.coverage import (CLI_MODULE_ALIASES, module_categories,
                                   module_sources)
    from server.ingest import AUDITORS

    assert CLI_MODULE_ALIASES["osec"] == "os_security"
    assert ("os_security", "OSSecurityAuditor") in AUDITORS
    assert set(module_sources()["os_security"]) == {
        "os_users", "os_groups", "os_file_permissions", "os_services"}
    assert module_categories()["os_security"] == ["OS & Infrastructure Security"]


# ── OSEC-CLOUD-001: the cloud-infra boundary note (host-platform tag, D10) ─────

def _run_ctx(host_platform=None, deployment_mode="on_prem"):
    """No OS data — only the run-context-driven boundary check can fire."""
    ctx = {"deployment_mode": deployment_mode, "modules": set()}
    if host_platform is not None:
        ctx["host_platform"] = host_platform
    return OSSecurityAuditor({}, {}, ctx).run_all_checks()


@pytest.mark.parametrize("platform", ["aws", "azure", "gcp"])
def test_self_managed_hyperscaler_gets_the_boundary_note(platform):
    f = _by_id(_run_ctx(host_platform=platform, deployment_mode="on_prem"),
               "OSEC-CLOUD-001")
    assert f["severity"] == "INFO"
    assert f["scope"] == "aggregate"
    assert "CNAPP" in f["description"]


@pytest.mark.parametrize("platform", ["bare_metal", "vmware", "unspecified", "typo", None])
def test_a_non_hyperscaler_platform_gets_no_boundary_note(platform):
    assert "OSEC-CLOUD-001" not in _ids(
        _run_ctx(host_platform=platform, deployment_mode="on_prem"))


def test_the_boundary_note_is_moot_in_rise():
    """In RISE SAP owns every layer including the cloud infrastructure, so the
    CNAPP boundary does not apply even on a hyperscaler."""
    assert "OSEC-CLOUD-001" not in _ids(
        _run_ctx(host_platform="aws", deployment_mode="rise_pce"))


def test_the_boundary_note_needs_no_os_export():
    """It is reporting metadata driven by the platform tag, so it fires on a scan
    with no OS data at all — unlike every other OSEC check."""
    findings = _run_ctx(host_platform="aws", deployment_mode="on_prem")
    assert _ids(findings) == {"OSEC-CLOUD-001"}
