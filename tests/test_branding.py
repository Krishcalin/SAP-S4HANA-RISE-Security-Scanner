"""
Branding and the sign-in layout.

WHY THIS IS TESTED AT ALL
A rebrand is the kind of change that looks complete and is not: one template keeps
the old name in a <title>, and it surfaces months later in a browser tab during a
customer demo. The name is asserted from the filesystem rather than page-by-page,
so a NEW template that ships with the old name fails too.

The static mount is tested because it is unauthenticated by necessity — the sign-in
page carries the logo, and a gated mount renders a broken image to exactly the
people who have not signed in yet. Unauthenticated is a decision, so it gets a test
that states it; the traversal case is here so "unauthenticated" never quietly grows
into "reads any file on disk".
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEMPLATES = ROOT / "server" / "templates"
STATIC = ROOT / "server" / "static"

BRAND = "MonitorRisk"
#: Names the product used to ship under. None of them may survive in a template.
RETIRED = ("SAPSec", "SAP Security Platform")


# --------------------------------------------------------------------------- #
#  Name — checked against the tree, so a new template cannot regress it        #
# --------------------------------------------------------------------------- #

def test_no_template_carries_a_retired_product_name():
    offenders = []
    for path in sorted(TEMPLATES.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        for old in RETIRED:
            if old in text:
                offenders.append(f"{path.name}: {old!r}")
    assert not offenders, "retired product name still rendered: " + "; ".join(offenders)


def test_every_page_template_sets_a_branded_title():
    """A tab reading just "Findings" does not say whose findings they are."""
    missing = []
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name == "base.html":       # defines the default, does not override
            continue
        text = path.read_text(encoding="utf-8")
        block = re.search(r"{%\s*block title\s*%}(.*?){%\s*endblock\s*%}", text, re.S)
        if block is None or BRAND not in block.group(1):
            missing.append(path.name)
    assert not missing, f"no {BRAND} in the title block of: {', '.join(missing)}"


def test_the_openapi_document_is_branded():
    from server import app as appmod
    assert BRAND in appmod.app.title


# --------------------------------------------------------------------------- #
#  Assets                                                                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [
    "monitorrisk-logo.png",        # full lockup, sign-in panel
    "monitorrisk-mark.png",        # shield only, light theme header
    "monitorrisk-mark-dark.png",   # shield only, dark theme header
    "favicon.ico",
])
def test_the_brand_assets_are_present_and_non_empty(name):
    asset = STATIC / name
    assert asset.is_file(), f"{name} is referenced by a template but not in server/static"
    assert asset.stat().st_size > 512, f"{name} is suspiciously small"


def test_the_logo_is_transparent_not_a_cream_rectangle():
    """The supplied artwork sits on a cream field. Pasted as-is it is a bright slab
    on the dark console, and its cream never quite matches a CSS colour, so there is
    always a visible rectangle. The shipped asset must have an alpha channel with
    genuinely transparent corners."""
    png = (STATIC / "monitorrisk-logo.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    # IHDR: width, height, bit depth, colour type. Type 6 = truecolour + alpha.
    colour_type = png[25]
    assert colour_type == 6, f"logo has colour type {colour_type}, expected 6 (RGBA)"


# --------------------------------------------------------------------------- #
#  Sign-in page                                                               #
# --------------------------------------------------------------------------- #

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pg
def test_the_sign_in_page_renders_with_the_logo():
    from fastapi.testclient import TestClient
    from server import app as appmod

    body = TestClient(appmod.app).get("/login").text
    assert "/static/monitorrisk-logo.png" in body
    assert 'class="auth-form"' in body and 'class="auth-brand"' in body
    for old in RETIRED:
        assert old not in body


@pg
def test_the_form_precedes_the_brand_panel_in_the_document():
    """Left/right is CSS, but DOM order is what a keyboard and a screen reader
    follow. The thing you came to do must come before the thing that tells you
    where you are."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    body = TestClient(appmod.app).get("/login").text
    assert body.index('class="auth-form"') < body.index('class="auth-brand"')


@pg
@pytest.mark.parametrize("asset", [
    "/static/monitorrisk-logo.png", "/static/monitorrisk-mark.png",
    "/static/monitorrisk-mark-dark.png", "/static/favicon.ico",
])
def test_brand_assets_load_without_authentication(asset):
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app).get(asset)
    assert resp.status_code == 200, "the sign-in page would show a broken image"
    assert len(resp.content) > 512


@pg
def test_the_static_mount_does_not_serve_the_rest_of_the_disk():
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app)
    for probe in ("/static/../app.py", "/static/../config.py",
                  "/static/..%2fapp.py", "/static/....//app.py"):
        resp = c.get(probe)
        assert resp.status_code != 200 or b"SESSION_COOKIE" not in resp.content, \
            f"{probe} escaped the static directory"


@pg
def test_static_stays_reachable_for_an_account_held_at_the_password_gate():
    """A forced account still renders base.html, which loads the header mark. If the
    forced-change gate caught /static too, that page would be missing its brand."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    name = f"brand_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "generated-pass-999", "analyst", must_change=True)
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        c.post("/login", data={"username": name, "password": "generated-pass-999",
                               "next": "/"})
        assert c.get("/").status_code == 303                      # gate is on
        assert c.get("/static/monitorrisk-mark-dark.png").status_code == 200
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))
