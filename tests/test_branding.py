# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Branding and the sign-in layout.

WHY THIS IS TESTED AT ALL
A rebrand is the kind of change that looks complete and is not: one screen keeps
the old name in a <title>, and it surfaces months later in a browser tab during a
customer demo. The name is asserted from the filesystem rather than screen by
screen, so a NEW screen that ships with the old name fails too.

The static mount is tested because it is unauthenticated by necessity — the
sign-in screen carries the logo, and a gated mount renders a broken image to
exactly the people who have not signed in yet. Unauthenticated is a decision, so
it gets a test that states it; the traversal case is here so "unauthenticated"
never quietly grows into "reads any file on disk".

WHAT MOVED WHEN THE SERVER-RENDERED CONSOLE WAS RETIRED
This file used to read server/templates/*.html: the product name in thirteen
files, a `{% block title %}` in each, and the rendered /login page's markup. Those
templates are deleted and the console is compiled TypeScript, so every one of
those assertions was rewritten against the thing that now produces the markup —
frontend/src — rather than dropped. Two of them got stronger on the way:

  * The title check was per-template and could only see that a block existed.
    A SPA has ONE index.html and therefore one <title>, so the brand now lives in
    lib/title.ts and every screen must CALL it. That is what is asserted, plus the
    branding inside the helper — which is one place instead of thirteen, and a
    screen that forgets it is now visible rather than merely unbranded.

  * The sign-in DOM-order check needed a database, because the page only rendered
    for a request. It is a source-level fact now, so it runs on a bare checkout —
    which is where a layout regression is cheapest to catch.

The brand ASSETS did not move at all. server/static is still mounted, still
unauthenticated, and the compiled index.html names /static/favicon.ico by
absolute path — which is why that mount survived a cutover that deleted
everything around it.
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

FRONTEND = ROOT / "frontend"
SRC = FRONTEND / "src"
STATIC = ROOT / "server" / "static"

BRAND = "MonitorRisk"
#: Names the product used to ship under. None of them may survive in the console.
RETIRED = ("SAPSec", "SAP Security Platform")


def _console_sources():
    """Every file that can put text on a screen, plus the shell's index.html."""
    return sorted(SRC.rglob("*.ts*")) + [FRONTEND / "index.html"]


# --------------------------------------------------------------------------- #
#  Name — checked against the tree, so a new screen cannot regress it          #
# --------------------------------------------------------------------------- #

def test_no_console_source_carries_a_retired_product_name():
    offenders = []
    for path in _console_sources():
        text = path.read_text(encoding="utf-8")
        for old in RETIRED:
            if old in text:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {old!r}")
    assert not offenders, "retired product name still rendered: " + "; ".join(offenders)


def test_the_tab_title_is_branded_in_one_place():
    """A tab reading just "Findings" does not say whose findings they are.

    Thirteen templates each declared their own `{% block title %}`. There is one
    document now, so the brand is appended by lib/title.ts and this asserts it
    there — one definition that cannot be half-applied, where before a new
    template could ship unbranded and nothing but this test would notice.
    """
    title_ts = (SRC / "lib" / "title.ts").read_text(encoding="utf-8")
    assert re.search(rf"document\.title\s*=.*{BRAND}", title_ts), \
        f"lib/title.ts no longer brands the tab with {BRAND}"

    index = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert f"<title>{BRAND}</title>" in index, \
        "index.html's fallback title — what shows before React runs — is not branded"


def test_every_screen_sets_a_tab_title():
    """The half a single <title> makes possible to get wrong.

    A server-rendered page could not forget its title; it was in the template. A
    SPA screen that never calls useTitle leaves the PREVIOUS screen's name in the
    tab, so an analyst who opens a finding from the queue still reads "Findings —
    MonitorRisk" — and the tab strip, the history menu and any bookmark they take
    are all keyed on that string. It looks right in a screenshot, which is exactly
    the kind of loss a migration makes invisibly.
    """
    missing = []
    for path in sorted((SRC / "routes").glob("*.tsx")) + [SRC / "components" / "Login.tsx"]:
        if "useTitle(" not in path.read_text(encoding="utf-8"):
            missing.append(path.relative_to(ROOT).as_posix())
    assert not missing, f"no useTitle() call in: {', '.join(missing)}"


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
    assert asset.is_file(), f"{name} is referenced by the console but not in server/static"
    assert asset.stat().st_size > 512, f"{name} is suspiciously small"


def _png_pixels(path):
    """Decode a PNG without Pillow — the suite installs pytest and nothing else.

    Returns (width, height, rows) with rows as lists of (r, g, b, a).
    """
    import struct
    import zlib

    raw = path.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is not a PNG"
    pos, idat, width = 8, b"", None
    while pos < len(raw):
        length, kind = struct.unpack(">I4s", raw[pos:pos + 8])
        body = raw[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack(">IIBB", body[:10])
            assert (depth, colour) == (8, 6), \
                f"{path.name} is depth {depth} colour type {colour}, expected 8/6 (RGBA)"
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length

    data = zlib.decompress(idat)
    stride, rows, prev = width * 4, [], bytearray(width * 4)
    at = 0
    for _ in range(height):
        filt, line = data[at], bytearray(data[at + 1:at + 1 + stride])
        at += 1 + stride
        for i in range(stride):                       # PNG per-scanline filters
            a = line[i - 4] if i >= 4 else 0
            b = prev[i]
            c = prev[i - 4] if i >= 4 else 0
            if filt == 1:
                line[i] = (line[i] + a) & 0xFF
            elif filt == 2:
                line[i] = (line[i] + b) & 0xFF
            elif filt == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif filt == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc
                                      else b if pb <= pc else c)) & 0xFF
        rows.append([tuple(line[i:i + 4]) for i in range(0, stride, 4)])
        prev = line
    return width, height, rows


def test_the_word_risk_survived_the_asset_pipeline():
    """The regression the obvious assertion cannot see.

    `key_out` un-mixes each pixel against the ink colours to key the background
    away. Every target ink is DARKER than the master's blue field, so a WHITE pixel
    projects to a negative coefficient, clamps to zero and is written fully
    transparent. "Risk" is white. Run the old cream-era treatment over the current
    master and the console renders the product as "Monitor" — with a valid RGBA
    PNG, correct dimensions, a passing colour-type check and a green suite.

    So the test is for the ink, not the container: the shipped lockup must contain
    a real run of white pixels. Nothing else here would notice half the wordmark
    going missing.
    """
    width, _, rows = _png_pixels(STATIC / "monitorrisk-logo.png")
    white = sum(1 for row in rows for r, g, b, a in row
                if a > 250 and r > 245 and g > 245 and b > 245)
    assert white > 2000, (
        f"only {white} white pixels in the lockup — the white half of the wordmark "
        f'("Risk") has been keyed away; see tools/build_brand_assets.py')

    # And the navy half, so a change that loses the OTHER ink fails just as loudly.
    navy = sum(1 for row in rows for r, g, b, a in row
               if a > 250 and r < 60 and g < 80 and b < 140)
    assert navy > 2000, f"only {navy} navy pixels in the lockup"


def test_the_lockup_field_matches_the_css_panel_behind_it():
    """A cross-file contract that only fails when someone edits one side.

    The lockup ships WITH its field because there is no page colour on which a
    keyed version reads — navy falls to 1.30:1 on the dark console, white to
    1.12:1 on a light panel. The panels it sits in are therefore painted the same
    colour, and the master's compression noise is flattened to exactly that value
    so the edge disappears instead of nearly disappearing.

    Two files have to agree for that to hold, and they are edited by different
    people for different reasons.
    """
    width, height, rows = _png_pixels(STATIC / "monitorrisk-logo.png")
    corners = [rows[1][1], rows[1][width - 2],
               rows[height - 2][1], rows[height - 2][width - 2]]
    assert len({c[:3] for c in corners}) == 1, \
        f"the lockup's field is not uniform at the corners: {corners}"
    assert all(c[3] == 255 for c in corners), \
        "the lockup is transparent at the corners — it is meant to carry its field"

    field = "#%02x%02x%02x" % corners[0][:3]
    css = (SRC / "index.css").read_text(encoding="utf-8")
    declared = re.search(r"--brand-field\s*:\s*(#[0-9a-fA-F]{6})", css)
    assert declared, "--brand-field is no longer declared in index.css"
    assert declared.group(1).lower() == field, (
        f"the artwork's field is {field} but index.css paints the panel behind it "
        f"{declared.group(1).lower()} — the seam is back")


def test_the_header_mark_is_transparent_because_it_sits_on_the_page():
    """The mark is the half that IS keyed, and must stay keyed.

    Unlike the lockup it has no white in it — navy shield, blue pulse — so it can
    composite onto whatever colour the header is. It is used at 22px directly on
    the page background; shipped with a field it would be a small opaque tile.
    """
    for name in ("monitorrisk-mark.png", "monitorrisk-mark-dark.png"):
        width, height, rows = _png_pixels(STATIC / name)
        corners = [rows[0][0], rows[0][width - 1],
                   rows[height - 1][0], rows[height - 1][width - 1]]
        assert all(c[3] == 0 for c in corners), \
            f"{name} has an opaque corner {corners} — it would tile on the header"


def test_the_console_and_the_reports_carry_the_same_lockup():
    """One brand everywhere.

    server/static/ is what the console serves; assets/ is what the CLI's HTML, PDF
    and PPTX reports embed. They were the same bytes by hand, with nothing
    enforcing it — and a different brand in the deliverable the customer KEEPS is
    the exact defect that was fixed on 2026-08-07. Both are derived by
    tools/build_brand_assets.py now, so this asserts the property that fix wanted.
    """
    served = (STATIC / "monitorrisk-logo.png").read_bytes()
    embedded = (ROOT / "assets" / "monitorrisk-logo.png").read_bytes()
    assert served == embedded, (
        "server/static and assets/ hold different lockups — the console and the "
        "customer's report would carry different brands; run "
        "python tools/build_brand_assets.py")


def test_the_console_asks_for_the_brand_assets_by_absolute_path():
    """Why /static outlived the templates.

    The shell's <link rel="icon"> and the sign-in lockup are written as
    /static/… rather than relative to the bundle's base. That is what let the
    console move from /ui to the root without touching either reference — and it
    is also why deleting the mount that reads like part of the retired page
    server would replace the brand with two broken images on the first screen
    every user sees.
    """
    index = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert 'href="/static/favicon.ico"' in index, \
        "the favicon is no longer requested from the unauthenticated brand mount"

    login = (SRC / "components" / "Login.tsx").read_text(encoding="utf-8")
    assert 'src="/static/monitorrisk-logo.png"' in login, \
        "the sign-in lockup is no longer requested from /static"


# --------------------------------------------------------------------------- #
#  Sign-in screen                                                             #
# --------------------------------------------------------------------------- #
#  Source-level, and deliberately not behind a database marker any more. The
#  screen used to be a rendered template and could only be inspected over HTTP;
#  it is a component now, so these run on a bare checkout — which is where a
#  layout regression is cheapest to catch.

def test_the_sign_in_screen_renders_with_the_logo():
    login = (SRC / "components" / "Login.tsx").read_text(encoding="utf-8")
    assert "/static/monitorrisk-logo.png" in login
    assert '"auth-form"' in login and '"auth-brand"' in login
    for old in RETIRED:
        assert old not in login


def test_the_form_precedes_the_brand_panel_in_the_document():
    """Left/right is CSS, but DOM order is what a keyboard and a screen reader
    follow. The thing you came to do must come before the thing that tells you
    where you are.

    Asserted on JSX source rather than on rendered HTML — the component IS the
    document order, and there is no server render left to read.
    """
    login = (SRC / "components" / "Login.tsx").read_text(encoding="utf-8")
    assert login.index('"auth-form"') < login.index('"auth-brand"')


def test_the_sign_in_styles_survived_the_port():
    """The class names above are only meaningful if the stylesheet still defines
    them. A component referencing `auth-brand` against a stylesheet that dropped
    it is an unstyled sign-in screen and every assertion above still passes."""
    css = (SRC / "index.css").read_text(encoding="utf-8")
    for cls in (".auth", ".auth-form", ".auth-brand"):
        assert cls in css, f"{cls} is referenced by Login.tsx but not defined in index.css"


# --------------------------------------------------------------------------- #
#  The mount itself — needs a running app                                     #
# --------------------------------------------------------------------------- #

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.mark.parametrize("asset", [
    "/static/monitorrisk-logo.png", "/static/monitorrisk-mark.png",
    "/static/monitorrisk-mark-dark.png", "/static/favicon.ico",
])
def test_brand_assets_load_without_authentication(asset):
    """No database needed: the static mount takes no session, which is the whole
    point of the test. It was behind the DB marker only because the assertions
    around it were."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app).get(asset)
    assert resp.status_code == 200, "the sign-in screen would show a broken image"
    assert len(resp.content) > 512


def test_the_static_mount_does_not_serve_the_rest_of_the_disk():
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app)
    for probe in ("/static/../app.py", "/static/../config.py",
                  "/static/..%2fapp.py", "/static/....//app.py"):
        resp = c.get(probe)
        assert resp.status_code != 200 or b"SESSION_COOKIE" not in resp.content, \
            f"{probe} escaped the static directory"


def test_the_brand_mount_is_declared_above_the_spa_mount():
    """Ordering, because the SPA now owns "/" and matches everything.

    Registered after it, /static would never run: the request would be answered by
    the console's own directory, which has no brand assets in it, and every logo
    would 404 while the mount that serves them sat in the file looking correct.
    """
    from starlette.routing import Mount
    from server import app as appmod

    positions = {r.name: i for i, r in enumerate(appmod.app.routes)
                 if isinstance(r, Mount)}
    assert "static" in positions and "spa" in positions
    assert positions["static"] < positions["spa"], \
        "the SPA mount was registered before /static and now swallows the brand assets"


@pg
def test_static_stays_reachable_for_an_account_held_at_the_password_gate():
    """A forced account still loads the console shell, which loads the header mark.
    If the forced-change gate caught /static too, that screen would be missing its
    brand at the moment the user is most likely to think something is wrong.

    The gate is asserted on the API, which is where it now lives: the screens are
    static files and answer everybody the same.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    name = f"brand_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "generated-pass-999", "analyst", must_change=True)
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        c.post("/api/auth/login", json={"username": name,
                                        "password": "generated-pass-999"})
        assert c.get("/api/dashboard").status_code == 403          # gate is on
        assert c.get("/static/monitorrisk-mark-dark.png").status_code == 200
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))
