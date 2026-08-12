# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The container hardening, asserted rather than trusted.

Every line these tests pin was verified against a running container before it was
written — read_only refusing a write to /app, /tmp refusing to execute, initdb
succeeding on a FRESH volume under the reduced capability set. The tests exist
because the next person to debug a permissions error will be tempted to delete the
line that caused it, and a hardening measure removed in a hurry is one nobody
notices is gone.

They parse the YAML rather than grep it: a commented-out `read_only: true` matches
a grep and hardens nothing.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

COMPOSE = ROOT / "docker-compose.yml"
DOCKERFILE = ROOT / "Dockerfile"


@pytest.fixture(scope="module")
def compose():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def app(compose):
    return compose["services"]["app"]


@pytest.fixture(scope="module")
def db(compose):
    return compose["services"]["db"]


# ── the app container ────────────────────────────────────────────────────────

def test_the_app_filesystem_is_read_only(app):
    """Verified: `touch /app/PROOF` returns "Read-only file system".

    It is safe because scan working directories are created inside the uploads
    VOLUME — server/app.py uses tempfile.mkdtemp(dir=upload_dir), not /tmp — and
    bytecode is compiled at build time.
    """
    assert app.get("read_only") is True


def test_tmp_is_provided_but_cannot_execute(app):
    """The stdlib reaches for /tmp in places nobody enumerates, so it is given —
    as memory, small, and noexec, because nothing should ever run from a scratch
    directory."""
    tmpfs = app.get("tmpfs") or []
    entry = next((t for t in tmpfs if t.startswith("/tmp")), None)
    assert entry, "the app has no /tmp; the first stdlib call that wants one fails"
    assert "noexec" in entry
    assert "nosuid" in entry


def test_the_app_holds_no_linux_capabilities(app):
    """It binds :8000 as uid 10001. Port 8000 is above 1024, so not even
    CAP_NET_BIND_SERVICE is needed."""
    assert app.get("cap_drop") == ["ALL"]
    assert not app.get("cap_add"), "the app should need no capability at all"


def test_privilege_escalation_is_blocked(app):
    assert "no-new-privileges:true" in (app.get("security_opt") or [])


def test_the_app_is_bounded(app):
    """The Monte Carlo is pure Python and CPU-bound. `simulations` is clamped in
    the route; these are the backstop that does not depend on remembering to."""
    assert app.get("pids_limit")
    assert app.get("mem_limit")
    assert app.get("cpus")


def test_the_port_is_not_published_to_every_interface(app):
    """0.0.0.0:8000 would put a customer's entire SAP security posture on their
    office LAN."""
    for mapping in app.get("ports") or []:
        assert str(mapping).startswith("127.0.0.1:"), mapping


# ── the database container ───────────────────────────────────────────────────

def test_the_database_is_not_published_at_all(db):
    """It holds the whole posture; only the app needs to reach it."""
    assert not db.get("ports"), "the database must not be reachable from the host"


def test_the_database_drops_all_and_re_adds_only_what_initdb_needs(db):
    """VERIFIED AGAINST A FRESH VOLUME, which is the case that actually breaks.

    An existing volume skips initdb entirely, so a capability list that is too
    tight passes every test on a developer's machine and fails on the customer's
    first deployment. This set was checked by starting an isolated project with an
    empty volume: initdb ran, chowned the data directory, dropped to the postgres
    user, and reported "database system is ready to accept connections".
    """
    assert db.get("cap_drop") == ["ALL"]
    added = set(db.get("cap_add") or [])
    assert {"CHOWN", "SETUID", "SETGID"} <= added, (
        "the official entrypoint starts as root and drops privileges; without "
        "these initdb fails on a fresh volume")


def test_the_database_is_not_read_only(db):
    """Deliberately. Postgres writes its data directory, a socket and temp files;
    forcing it read-only means mounting three tmpfs to work around a database
    doing database things, and buys nothing the capability drop has not."""
    assert db.get("read_only") is not True


def test_neither_service_runs_privileged(app, db):
    for service in (app, db):
        assert service.get("privileged") is not True


# ── the image ────────────────────────────────────────────────────────────────

def test_the_image_runs_as_a_non_root_user():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "USER sapsec" in text
    assert text.index("USER sapsec") < text.index("EXPOSE"), (
        "USER must precede the runtime stage, or the process starts as root")


def test_bytecode_is_compiled_at_build_time():
    """This is what makes read_only viable. Without it CPython silently
    recompiles on every import and the only symptom is a slow start."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "compileall" in text
    assert "PYTHONDONTWRITEBYTECODE=1" in text


def test_the_image_declares_a_healthcheck_without_installing_a_tool():
    """Compose waited on the database and had nothing to wait on for the app, so
    `up` reported success while the console was still 503. urllib rather than
    curl: the slim base has none, and adding one to check a health endpoint grows
    the attack surface faster than it describes it."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "HEALTHCHECK" in text
    assert "urllib.request" in text
    assert "curl" not in text.split("HEALTHCHECK")[1]


def test_the_deployment_is_still_two_services(compose):
    """The one-container-plus-Postgres shape is the product's clearest structural
    advantage over the alternatives, and the compose file says so at the top.
    Hardening must not have quietly added a sidecar."""
    assert set(compose["services"]) == {"app", "db"}
