"""Every shipped module has to produce something on the bundled corpus.

WHY THIS IS A TEST AND NOT AN OBSERVATION. Five of the 36 modules produced
nothing on `sample_data`, and a module that never fires is a module never
exercised end to end — its checks are in the published catalogue, its object
types reach `server/identity.py`, its findings reach the graph and the FAIR
figure, and none of that had ever run. The roadmap recorded three of the five;
the other two had gone unnoticed entirely, which is the shape of the problem.

WHAT THE SILENCE WAS HIDING, in the two cases where the answer was not "a missing
fixture":

  * `abap_sast` and `cap_xsuaa` read DIRECTORIES — an unpacked abapGit export and
    a CAP project — supplied only through the CLI flags --abap-src and --cap-src.
    `server/ingest.py` calls `DataLoader(data_dir).load_all()` and set neither, so
    NO UPLOAD COULD REACH EITHER MODULE. 136 `ABAP-*` check ids and the CAP set
    were published in the catalogue and unreachable through the console, which is
    the product's main flow.

  * Giving `cap_xsuaa` something to scan immediately failed
    `test_every_emitted_object_type_is_registered`: `xsuaa_application` and
    `cap_service` were registered in neither case registry and in neither scope
    registry, so their identities took the unknown-type fallback undecided and
    would have borrowed the ABAP SID of whichever system the bundle was uploaded
    beside. That defect had existed for as long as the module was unreachable, and
    no amount of unit testing would have found it, because the unit tests construct
    the auditor directly and never go through ingest.

THE TEST IS DELIBERATELY WEAK IN WHAT IT ASSERTS. It requires a module to produce
at least one finding, not a particular finding, so tuning a threshold or rewording
a check does not break it. The thing being protected is that the code path RUNS.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLE = ROOT / "sample_data"
pytestmark = pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data absent")


@pytest.fixture(scope="module")
def scan():
    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT

    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()
        per_module = {}
        for module_name, class_name in AUDITORS:
            auditor = getattr(importlib.import_module(f"modules.{module_name}"),
                              class_name)
            per_module[module_name] = auditor(
                data, None, RUN_CONTEXT).run_all_checks() or []
    return data, per_module


def test_no_shipped_module_is_silent(scan):
    _, per_module = scan
    silent = sorted(m for m, findings in per_module.items() if not findings)
    assert not silent, (
        "these modules produce nothing on sample_data, so their checks are never "
        "exercised end to end: %s. Either the corpus is missing an input they "
        "need, or they cannot be reached at all — which is what was true of "
        "abap_sast and cap_xsuaa." % silent)


def test_the_corpus_reaches_the_two_directory_sources(scan):
    """The bug this file exists for, asserted at the source rather than at the
    symptom. A module can also fall silent because its fixture drifted; these two
    fell silent because nothing could hand them a path."""
    data, _ = scan
    for key in ("abap_source_dir", "cap_project_dir"):
        root = data.get(key)
        assert root, (
            "%s is unset, so an uploaded bundle cannot reach the module that "
            "reads it — the defect was that server/ingest.py never set it and "
            "only the CLI flags did" % key)
        assert Path(root).is_dir(), "%s = %r is not a directory" % (key, root)


def test_directory_discovery_never_returns_the_bundle_root(tmp_path):
    """Pointing a scanner at the bundle root would make it walk every CSV and
    count them in `unscanned_by_suffix`, turning a coverage figure into noise
    about files that were never source. A loose source file at the top level is
    not a project."""
    from modules.data_loader import DataLoader

    (tmp_path / "stray.abap").write_text("REPORT zstray.\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data.get("abap_source_dir") is None


def test_a_conventional_directory_is_only_believed_if_it_holds_sources(tmp_path):
    """An empty `src/` must not become "asked to look, could not" — that arms the
    release gate's fail-closed path on a bundle that simply has no ABAP in it."""
    from modules.data_loader import DataLoader

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "readme.txt").write_text("nothing here", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data.get("abap_source_dir") is None


def test_a_conventional_directory_holding_sources_is_found(tmp_path):
    from modules.data_loader import DataLoader

    src = tmp_path / "abap_src"
    src.mkdir()
    (src / "zfoo.prog.abap").write_text("REPORT zfoo.\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data.get("abap_source_dir") == str(src)


def test_an_unpacked_export_is_found_under_any_name(tmp_path):
    """Somebody who drops an abapGit repository into the bundle whole does not
    rename it first, so the content fallback has to answer."""
    from modules.data_loader import DataLoader

    src = tmp_path / "ZCUSTOMER_REPO" / "src"
    src.mkdir(parents=True)
    (src / "zbar.clas.abap").write_text("CLASS zbar DEFINITION.\nENDCLASS.\n",
                                        encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data.get("abap_source_dir") == str(src)


def test_a_cap_project_is_found_by_its_descriptor(tmp_path):
    from modules.data_loader import DataLoader

    project = tmp_path / "cap_project"
    project.mkdir()
    (project / "xs-security.json").write_text('{"xsappname": "t"}',
                                              encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data.get("cap_project_dir") == str(project)
