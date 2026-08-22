"""Three small ways the product failed to say what it had not done.

Each is the same shape as the large ones this codebase has spent its effort on —
an absence of evidence presented as evidence of absence — at a scale small enough
that it survived a long time.

1. A MISNAMED EXPORT READ AS "NOT SUPPLIED". The loader matched filenames against
   its table and silently ignored everything else. A customer whose system writes
   `user_list_PRD.csv` put the account list in the directory, watched the manifest
   report `users` as not supplied, and had nothing to act on: the file was there.

2. A FAILED LANDSCAPE FETCH READ AS "YOU HAVE NO LANDSCAPES". The CRQ screen
   caught the error and set an empty list, so an endpoint that was down,
   forbidden or slow rendered identically to an account with nothing in it.

3. THE CLI SUBCOMMANDS DESCRIBED NOTHING. `--help` listed eleven verbs with no
   explanation of any of them, which is not a correctness bug and is the reason
   somebody runs the wrong one.
"""
from __future__ import annotations

import contextlib
import io
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import build_manifest                       # noqa: E402
from modules.data_loader import DataLoader                        # noqa: E402


def _load(directory, *disregard):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        loader = DataLoader(directory).disregard(*disregard)
        data = loader.load_all()
    return loader, data, out.getvalue()


@pytest.fixture()
def exports(tmp_path):
    """A copy of the sample export directory, safe to rename files in."""
    work = tmp_path / "exports"
    shutil.copytree(ROOT / "sample_data", work)
    return work


# ───────────────────────── 1. the unread export ─────────────────────────────

def test_a_misnamed_export_is_named_rather_than_silently_ignored(exports):
    """The whole point. "Not supplied" and "supplied under a name we do not
    read" lead to opposite actions, and only one of them is the customer's
    fault."""
    (exports / "users.csv").rename(exports / "user_list_PRD.csv")
    loader, data, printed = _load(exports)

    assert data.get("users") in (None, [], {}), \
        "the fixture did not actually take the account list away"
    assert "user_list_PRD.csv" in loader.unrecognised_files
    assert "not recognised" in printed, \
        "the operator was told nothing about a file sitting in the directory"


def test_the_manifest_carries_it_into_every_artefact(exports):
    """The console line reaches whoever ran the scan. The manifest reaches the
    report, the deck and the database — which is where somebody reading it later
    will be wondering why a source is missing."""
    (exports / "users.csv").rename(exports / "user_list_PRD.csv")
    loader, data, _ = _load(exports)
    manifest = build_manifest(data, unrecognised_files=loader.unrecognised_files)

    assert manifest["counts"]["files_unrecognised"] >= 1
    assert "user_list_PRD.csv" in manifest["unrecognised_files"]


def test_a_correctly_named_export_is_never_reported(exports):
    """A warning that fires on a healthy directory is one people learn to
    ignore, which would cost more than it saves."""
    loader, _, printed = _load(exports, "baseline.json")
    assert loader.unrecognised_files == [], \
        "a clean directory produced a warning: %s" % loader.unrecognised_files
    assert "not recognised" not in printed


def test_only_files_that_could_be_an_export_are_considered(exports):
    """A report, a note or a scenario export beside the data is expected. Only
    something that looks like an export the loader failed to match is worth a
    reader's attention."""
    (exports / "notes.txt").write_text("hand-over notes", encoding="utf-8")
    (exports / "report.html").write_text("<html></html>", encoding="utf-8")
    (exports / "scan.crq.json").write_text("{}", encoding="utf-8")
    (exports / "mystery_export.csv").write_text("A,B\n1,2\n", encoding="utf-8")

    loader, _, _ = _load(exports, "baseline.json")
    assert loader.unrecognised_files == ["mystery_export.csv"], \
        loader.unrecognised_files


def test_the_products_own_config_file_does_not_read_as_a_misnamed_export(exports):
    """THE WARNING ABOVE CRIED WOLF ON THE README'S FIRST COMMAND.

    `sample_data/baseline.json` ships with this product and only takes effect
    behind `--config`. Without the flag it is unread, so the first version of
    this warning reported "1 file(s) ... were not recognised" — about a file we
    wrote, on the first command a new reader runs. A warning whose first
    appearance is a false one is a warning people learn to scroll past, which
    costs more than the misnamed export it exists to catch.

    Present-but-not-applied is a third state, and its message is more useful than
    the one it replaced because it names the flag.
    """
    loader, _, printed = _load(exports)
    assert loader.unrecognised_files == [], loader.unrecognised_files
    assert ("baseline.json", "--config") in loader.unapplied_files
    assert "--config baseline.json" in printed, printed


def test_applying_it_says_nothing_at_all(exports):
    loader, _, printed = _load(exports, "baseline.json")
    assert loader.unapplied_files == []
    assert "was not applied" not in printed


def test_the_two_messages_do_not_mask_each_other(exports):
    """A directory can hold both. Reporting the known file must not suppress the
    unknown one — that would trade a false warning for a missing one."""
    (exports / "users.csv").rename(exports / "user_list_PRD.csv")
    loader, _, printed = _load(exports)
    assert loader.unrecognised_files == ["user_list_PRD.csv"]
    assert loader.unapplied_files == [("baseline.json", "--config")]
    assert "not recognised" in printed and "was not applied" in printed


def test_the_caller_can_declare_files_it_owns(exports):
    """The loader cannot know the operator passed `--gate-scope`; the composition
    root can, and says so. Any operator file may sit beside the exports — the
    README's own gate example puts a transport-objects list there."""
    (exports / "transport-objects.json").write_text('["ZCL_A"]', encoding="utf-8")

    undeclared, _, _ = _load(exports)
    assert "transport-objects.json" in undeclared.unrecognised_files
    declared, _, _ = _load(exports, "transport-objects.json")
    assert "transport-objects.json" not in declared.unrecognised_files


def test_the_scanner_declares_every_file_valued_flag_not_two_of_them():
    """A HAND-WRITTEN LIST WENT STALE BEFORE IT WAS A DAY OLD.

    The first version named `--config` and `--output` and missed the five gate
    flags and `--crq-inputs`, every one of which takes a path an operator may
    keep in the export directory. So the scanner reads the flags off its own
    parser: `metavar="FILE"` is what the author writes anyway, and a flag added
    tomorrow is covered on the day it is written rather than the day someone
    remembers this line.
    """
    import ast

    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert "loader.disregard(" in src, \
        "sap_scanner no longer tells the loader which files it owns"
    assert "unrecognised_files=" in src, \
        "the scanner builds a manifest without the unrecognised list"
    assert "action.metavar" in src, \
        "the disregard list is hand-written again; it must be read off the parser"

    # Every flag that takes a path declares itself as one, so the derivation sees
    # it. `--data-dir` and `--abap-src` are directories and are excluded on
    # purpose: they cannot be files sitting inside the export directory.
    tree = ast.parse(src)
    undeclared = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "attr", "") == "add_argument"):
            continue
        if not (node.args and isinstance(node.args[0], ast.Constant)):
            continue
        flag = node.args[0].value
        kw = {k.arg: k.value for k in node.keywords}
        metavar = kw.get("metavar")
        metavar = metavar.value if isinstance(metavar, ast.Constant) else None
        looks_like_a_path = any(
            word in flag for word in ("baseline", "policy", "scope", "json",
                                      "config", "output", "inputs"))
        if looks_like_a_path and metavar != "FILE":
            undeclared.append(flag)
    assert not undeclared, (
        "flag(s) take a file path without metavar=\"FILE\", so the loader will "
        "warn about the operator's own file: %s" % undeclared)


# ─────────────────── 2. the failed fetch on the CRQ screen ──────────────────

def test_the_crq_screen_does_not_render_a_failed_fetch_as_an_empty_estate():
    """Asserted against the source, as this codebase already does for the code
    card: the failure path is what matters and it is one line."""
    src = (ROOT / "frontend" / "src" / "routes" / "CrqInputs.tsx").read_text(
        encoding="utf-8")

    assert ".catch(() => { if (live) setScapes([]) })" not in src, \
        "the landscape fetch swallows its error again; a failure reads as 'none'"

    # The landscape effect must reach setFailure, so the banner explains itself.
    effect = src[src.index("landscapes()"):]
    effect = effect[:effect.index("useEffect", 1)] if "useEffect" in effect[1:] else effect
    assert "setFailure" in effect, \
        "a failed landscape fetch sets no failure message"
    assert "not that you have none" in src, \
        "the message no longer distinguishes 'could not load' from 'you have none'"


# ────────────────────────── 3. the CLI help text ────────────────────────────

def test_every_cli_subcommand_says_what_it_does():
    """Eleven verbs and no descriptions is how somebody runs the wrong one."""
    from server import cli

    parser = cli.build_parser() if hasattr(cli, "build_parser") else None
    if parser is None:
        src = (ROOT / "server" / "cli.py").read_text(encoding="utf-8")
        calls = re.findall(r"sub\.add_parser\((?:[^()]|\([^()]*\))*\)", src, re.S)
        assert len(calls) >= 10, "only %d subcommands found" % len(calls)
        missing = [" ".join(c.split())[:60] for c in calls if "help=" not in c]
        assert not missing, "subcommands with no help text: %s" % missing
        return

    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    assert actions, "no subparsers found"
    missing = [name for name, sp in actions[0].choices.items() if not sp.description
               and not getattr(sp, "help", None)]
    assert not missing, "subcommands with no help text: %s" % missing


def test_the_help_output_actually_renders_them():
    """The property a user sees, rather than the keyword argument behind it."""
    import subprocess

    out = subprocess.run([sys.executable, "-m", "server.cli", "--help"],
                         cwd=str(ROOT), capture_output=True, text=True,
                         timeout=120).stdout
    for verb in ("init-db", "create-user", "scan", "runs", "totp-status"):
        assert verb in out, verb
    assert "Create or migrate the database schema" in out
    assert "List stored scan runs" in out
