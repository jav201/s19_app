"""Batch-100 increment 8a — the active change document is recorded and
reopened (HLR-170).

Covers:

  - TC-B100-28 — LLR-170.1: the ``active_document`` key. One form predicate
    at both ends (``is_active_document_form``); the writer emits the key
    only when set and refuses a value out of form (no text, one finding);
    the reader accepts it only in form (otherwise one issue and ``None``,
    the rest read); the key is known, so an in-project rewrite carries it.
    The A-15 arm of LLR-169.2 (``project_file_records`` records the
    document) runs here, as the requirement says.
  - TC-B100-29 — LLR-170.2: Save project writes a pasted document as
    ``changes.json`` in its kind's home (M-1: reuse / ``_1``), binds it,
    records the landing; a file-backed document is copied (outside) or
    recorded as on disk (in its home), never rewritten (E3 R1); a document
    inside the project but outside its home, or whose source is gone or
    behind a link, is not placed (E3 R11, R18); a failed write saves the
    project without it; a failure after the write removes it.
  - TC-B100-30 — LLR-170.3: Load reopens the recorded document after the
    A2L through one classifier (``recorded_document_state``, E3 R10): caps
    (1 MiB, 1 000 entries, E3 R4), a guarded decode (``RecursionError``,
    ``ValueError`` — E3 R19), file-level codes only (E3 R17), a link and a
    locked file; the entries are listed, never re-applied (Q6).

Symbols NEW at Inc 8a (``is_active_document_form``, ``ACTIVE_DOCUMENT_HOMES``,
``recorded_document_state``, ``classify_active_document``) are imported
inside their nodes, so every behavioural node of this module still runs —
and fails on its own assertion — at the base.

Oracles: ``project.json`` and document files are read with the stdlib;
digests with ``hashlib``; images with ``tests/support/independent_reader``.
Status oracles read the full ``set_status`` message (``StatusLog``), never a
clipped painted strip.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

import pytest

import s19_app.tui.app as app_module
import s19_app.tui.changes.io as changes_io
from s19_app.tui.models import ProjectVariantSet
from s19_app.tui.screens_directionb import LoadGuardScreen
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services import manifest_writer
from s19_app.tui.services.manifest_writer import serialize_manifest
from s19_app.tui.services.manifest_writer import write_project_manifest
from s19_app.tui.services.project_gather_service import document_home_for_kind
from s19_app.tui.services.variant_execution_service import MANIFEST_BAD_STRUCTURE
from s19_app.tui.services.variant_execution_service import MANIFEST_PATH_ESCAPE
from s19_app.tui.services.variant_execution_service import manifest_keep_reason
from s19_app.tui.services.variant_execution_service import manifest_rewrite_refusal
from s19_app.tui.services.variant_execution_service import read_project_manifest
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR
from s19_app.tui.workspace import build_variant_set

from tests.support import b100_links
from tests.support import b100_manifests as documents
from tests.support import b100_projects as projects
from tests.support.independent_reader import read_s19
from tests.support.timing import timing_bound

PATCH_ADDRESS = 0x8000007C
PATCH_BYTES = (0xDE, 0xAD, 0xBE, 0xEF)
SECOND_ADDRESS = 0x80000060
INTERNAL_CODE = re.compile(r"\b(MF|CHG|MANIFEST|GATHER)-[A-Z0-9-]+")
EXCEPTION_NAME = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _source(tmp_path: Path, name: str = "firmware.s19") -> Path:
    return projects.copy_sources(tmp_path / "sources", projects.CASE01_DIR, name) / name


def _write_manifest(project_dir: Path, payload: dict) -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "project.json").write_text(json.dumps(payload), encoding="utf-8")


def _active_document(manifest) -> object:
    """``ProjectManifest.active_document``, or a marker when the field does
    not exist (the base), so the assertion — not an AttributeError — fails."""
    return getattr(manifest, "active_document", "<no active_document field>")


def _document_entries(path: Path) -> list:
    return json.loads(path.read_text(encoding="utf-8"))["entries"]


def _panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def _add(app, address: int, run) -> None:
    app._change_service.add_entry(
        f"0x{address:08X}", "", " ".join(f"{byte:02X}" for byte in run)
    )


async def _add_through_the_panel(pilot, app, address: str, run: str, entries_after: int) -> None:
    """Add one entry through the Patch Editor's own inputs (sets the
    panel's dirty flag the way the user does)."""
    await pilot.press("6")
    await projects.wait_for(
        pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor panel"
    )
    from textual.widgets import Input

    # Clear both inputs first: a second add keeps the first add's text and
    # ctrl+a does not always select it (the inputs are the panel's own).
    app.query_one("#patch_entry_address_input", Input).value = ""
    app.query_one("#patch_entry_bytes_input", Input).value = ""
    assert await pilot.click("#patch_entry_address_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*address)
    assert await pilot.click("#patch_entry_bytes_input")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*run)
    assert await pilot.click("#patch_entry_add_button")
    await projects.wait_for(
        pilot,
        lambda: len(app._change_service.document.entries) == entries_after,
        f"the entry added through the panel ({entries_after} entries)",
    )


def _capture_plans(monkeypatch: pytest.MonkeyPatch) -> list:
    """Every SavePlan the app computes (the shipped planner, spied)."""
    plans: list = []
    original = app_module.plan_project_save

    def _spy(*args, **kwargs):
        plan = original(*args, **kwargs)
        plans.append(plan)
        return plan

    monkeypatch.setattr(app_module, "plan_project_save", _spy)
    return plans


def _document_rows(plan) -> list:
    return [(row.landing.name, row.action) for row in plan.rows if row.role == "document"]


def _painted_clean(messages) -> None:
    """E3 R6: no internal code and no exception class name painted."""
    text = "\n".join(messages)
    assert INTERNAL_CODE.search(text) is None, text
    assert EXCEPTION_NAME.search(text) is None, text


# ---------------------------------------------------------------------------
# TC-B100-28 — LLR-170.1: the ``active_document`` key
# ---------------------------------------------------------------------------

#: 32 767 characters (MANIFEST_ENTRY_MAX_CHARS) and one more.
AT_THE_LENGTH_BOUND = "patches/" + "a" * (32767 - len("patches/") - len(".json")) + ".json"
OVER_THE_LENGTH_BOUND = "patches/" + "a" * (32768 - len("patches/") - len(".json")) + ".json"
ESCAPES_AND_BELL = "patches/" + "\x1b]0;x\x07" + "a.json"

FORM_ACCEPTED = (
    "patches/boost.json",
    "checks/c.json",
    "patches/changes.json",
    "patches/changes_1.json",
    "patches/boost.JSON",
    "patches/boost.Json",
    AT_THE_LENGTH_BOUND,
)

FORM_REFUSED = (
    "firmware.s19",
    "../x.json",
    "project.json",
    "patches/x.txt",
    "/abs/x.json",
    "patches\\boost.json",
    "boost.json",
    "patches/sub/x.json",
    "patches/../x.json",
    "./patches/x.json",
    "templates/t.json",
    "flows/f.json",
    "C:patches/x.json",
    "C:/patches/x.json",
    "patches/.json",
    " patches/boost.json",
    "patches/boost.json ",
    "Patches/boost.json",
    OVER_THE_LENGTH_BOUND,
    ESCAPES_AND_BELL,
    "patches/a\x85.json",
    "patches/a\x7f.json",
    "patches/a\x00.json",
    "",
)

FORM_NON_TEXT = (7, True, None, ["patches/boost.json"], Path("patches/boost.json"))


@pytest.mark.parametrize("text", FORM_ACCEPTED, ids=lambda t: repr(t)[:40])
def test_tc_b100_28_form_predicate_accepts(text: str) -> None:
    """Two components, a document home compared exactly, a ``.json``
    suffix compared case-insensitively, at most 32 767 characters."""
    from s19_app.tui.services.variant_execution_service import is_active_document_form

    assert is_active_document_form(text) is True


@pytest.mark.parametrize("text", FORM_REFUSED, ids=lambda t: repr(t)[:40])
def test_tc_b100_28_form_predicate_refuses(text: str) -> None:
    """Every refused form, including C0/C1 control characters (E3 R6) — the
    no-control-character mutant accepts ``ESCAPES_AND_BELL`` → RED."""
    from s19_app.tui.services.variant_execution_service import is_active_document_form

    assert is_active_document_form(text) is False


@pytest.mark.parametrize("value", FORM_NON_TEXT, ids=repr)
def test_tc_b100_28_form_predicate_is_total(value) -> None:
    """Pre-ruling 1 / P3: a value that is not ``str`` → False, never a raise."""
    from s19_app.tui.services.variant_execution_service import is_active_document_form

    assert is_active_document_form(value) is False


def test_tc_b100_28_document_homes_equal_the_gather_homes() -> None:
    """Pre-ruling 1: the predicate's homes are its own constant (no import
    cycle); this pins them equal to the gather's homes, so the two cannot
    drift."""
    from s19_app.tui.services.variant_execution_service import ACTIVE_DOCUMENT_HOMES

    assert set(ACTIVE_DOCUMENT_HOMES) == {
        document_home_for_kind("change"),
        document_home_for_kind("check"),
    }


def _variant_set(project_dir: Path) -> ProjectVariantSet:
    vs = build_variant_set("P", [project_dir / "firmware.s19"])
    vs.active_id = "firmware"
    return vs


@pytest.mark.parametrize("text", ["patches/boost.json", "checks/c.json"])
def test_tc_b100_28_writer_and_reader_round_trip(tmp_path: Path, text: str) -> None:
    """2 of 2 round-trips: serialized, written, read back equal; 0 issues,
    0 unknown keys, ``active_variant`` read."""
    project_dir = tmp_path / "P"
    (project_dir / text).parent.mkdir(parents=True)
    (project_dir / text).write_bytes(projects.change_document_bytes())
    serialized, issues = serialize_manifest(
        _variant_set(project_dir), project_dir, active_document=text
    )
    assert issues == [] and serialized is not None, issues
    assert json.loads(serialized)["active_document"] == text
    (project_dir / "project.json").write_text(serialized, encoding="utf-8")
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == ()
    assert manifest.issues == []
    assert _active_document(manifest) == text
    assert manifest.active_variant == "firmware"


def test_tc_b100_28_absent_key_is_byte_identical(tmp_path: Path) -> None:
    """``active_document=None`` → no key, byte-identical to the call
    without the keyword (TC-B100-21's byte identity holds)."""
    vs = _variant_set(tmp_path / "P")
    without, _ = serialize_manifest(vs, tmp_path / "P", batch=["patches/a.json"])
    with_none, issues = serialize_manifest(
        vs, tmp_path / "P", batch=["patches/a.json"], active_document=None
    )
    assert issues == []
    assert with_none == without
    assert "active_document" not in json.loads(with_none)


#: LLR-170.1's six reader arms, each with its issue code (pre-ruling 6).
READER_REFUSALS = (
    ("../x.json", MANIFEST_PATH_ESCAPE),
    ("/abs/x.json", MANIFEST_PATH_ESCAPE),
    (7, MANIFEST_BAD_STRUCTURE),
    ("firmware.s19", MANIFEST_BAD_STRUCTURE),
    ("project.json", MANIFEST_BAD_STRUCTURE),
    ("patches/x.txt", MANIFEST_BAD_STRUCTURE),
)

#: The further reader arms of the prototype (form → BAD-STRUCTURE; text
#: rules of the manifest-keys mode → PATH-ESCAPE).
READER_MORE_REFUSALS = (
    ("patches\\boost.json", MANIFEST_BAD_STRUCTURE),
    ("boost.json", MANIFEST_BAD_STRUCTURE),
    ("patches/sub/x.json", MANIFEST_BAD_STRUCTURE),
    ("templates/t.json", MANIFEST_BAD_STRUCTURE),
    ("Patches/boost.json", MANIFEST_BAD_STRUCTURE),
    (ESCAPES_AND_BELL, MANIFEST_BAD_STRUCTURE),
    (True, MANIFEST_BAD_STRUCTURE),
    ("", MANIFEST_BAD_STRUCTURE),
    (["patches/boost.json"], MANIFEST_BAD_STRUCTURE),
    ("C:patches/x.json", MANIFEST_PATH_ESCAPE),
    ("patches/NUL.json", MANIFEST_PATH_ESCAPE),
    ("patches/x.json.", MANIFEST_PATH_ESCAPE),
)


@pytest.mark.parametrize(
    "value, code", READER_REFUSALS + READER_MORE_REFUSALS, ids=lambda v: repr(v)[:30]
)
def test_tc_b100_28_reader_refuses_a_value_out_of_form(tmp_path: Path, value, code: str) -> None:
    """One issue of the expected code, ``active_document`` ``None``, the
    key known (0 unknown keys), ``active_variant`` still read. The
    no-prefix-rule mutant accepts ``firmware.s19`` → RED."""
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": "firmware", "active_document": value},
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == (), manifest.unknown_keys
    assert [issue.code for issue in manifest.issues] == [code], manifest.issues
    assert manifest.issues[0].details.get("key") == "active_document", manifest.issues[0]
    assert _active_document(manifest) is None
    assert manifest.active_variant == "firmware"


def test_tc_b100_28_document_finding_is_kept_first_beside_a_full_batch(tmp_path: Path) -> None:
    """SEC6-5 + parse order (D-E4-2): 1 000 escaping ``batch`` entries (at
    the cap) and a refused ``active_document`` → 1 001 skipped entries; the
    document's finding is the first issue and kept one by one (its key
    mark), the rest folded; read under 1 s."""
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {
            "schema_version": 1,
            "active_variant": "firmware",
            "active_document": "patches/x.txt",
            "batch": [f"../b{i}.json" for i in range(1000)],
        },
    )
    start = time.perf_counter()
    manifest = read_project_manifest(project_dir)
    elapsed = time.perf_counter() - start
    assert manifest.issues, "no finding at all"
    assert manifest.issues[0].details.get("key") == "active_document", manifest.issues[0]
    assert manifest.issues[0].code == MANIFEST_BAD_STRUCTURE
    assert len(manifest.issues) < 1001, len(manifest.issues)
    assert elapsed < timing_bound(1.0), elapsed


def test_tc_b100_28_reader_null_and_absent_are_none(tmp_path: Path) -> None:
    """P5: ``"active_document": null`` reads as absent — ``None``, 0 issues;
    an absent key → ``None``, 0 issues."""
    for name, payload in (
        ("null", {"schema_version": 1, "active_variant": "firmware", "active_document": None}),
        ("absent", {"schema_version": 1, "active_variant": "firmware"}),
    ):
        _write_manifest(tmp_path / name, payload)
        manifest = read_project_manifest(tmp_path / name)
        assert manifest.unknown_keys == (), (name, manifest.unknown_keys)
        assert manifest.issues == [], (name, manifest.issues)
        assert _active_document(manifest) is None, name


def test_tc_b100_28_reader_accepts_a_document_absent_from_disk(tmp_path: Path) -> None:
    """A recorded document whose file is gone is still accepted by the
    reader (``check_project_files`` owns ``missing``, LLR-169.5)."""
    project_dir = tmp_path / "P"
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": "firmware", "active_document": "patches/boost.json"},
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.issues == []
    assert _active_document(manifest) == "patches/boost.json"


WRITER_REFUSALS = (
    "firmware.s19",
    "../x.json",
    "patches\\boost.json",
    "patches/sub/boost.json",
    "patches/boost.txt",
    "templates/t.json",
    "C:patches/boost.json",
    "C:/x.json",
    "patches/NUL.json",
    "Patches/boost.json",
    ESCAPES_AND_BELL,
    "patches/" + "a" * 32763 + ".json",
)


@pytest.mark.parametrize("text", WRITER_REFUSALS, ids=lambda t: repr(t)[:30])
def test_tc_b100_28_writer_refuses_a_value_out_of_form(tmp_path: Path, text: str) -> None:
    """``(None, findings)`` with exactly one finding naming
    ``active_document``; 0 text. The no-form-check mutant serializes
    ``firmware.s19`` → RED."""
    serialized, findings = serialize_manifest(
        _variant_set(tmp_path / "P"), tmp_path / "P", active_document=text
    )
    assert serialized is None
    assert len(findings) == 1, findings
    assert "active_document" in (
        findings[0].message + " " + json.dumps(getattr(findings[0], "details", {}) or {}, default=str)
    ), findings[0]


def test_tc_b100_28_writer_refusal_writes_no_bytes(tmp_path: Path) -> None:
    """A refused value with a ``project.json`` already there → path
    ``None``, 1 finding, the file's bytes unchanged."""
    base = tmp_path / "app"
    project_dir = projects.copy_sources(_workarea(base) / "P", projects.CASE01_DIR, "firmware.s19")
    vs = _variant_set(project_dir)
    written, issues = write_project_manifest(vs, project_dir, base)
    assert written is not None and issues == []
    before = (project_dir / "project.json").read_bytes()
    written, findings = write_project_manifest(
        vs, project_dir, base, active_document="firmware.s19"
    )
    assert written is None
    assert len(findings) == 1, findings
    assert (project_dir / "project.json").read_bytes() == before


def test_tc_b100_28_writer_refuses_a_sub_folder_files_key_unless_it_is_the_document(
    tmp_path: Path,
) -> None:
    """Pre-ruling 4: the writer cannot write what the reader refuses — a
    ``files`` key ``patches/other.json`` beside ``active_document``
    ``patches/boost.json`` → ``(None, 1 finding)``; the document's own key
    → serialized, and the reader accepts it with 0 issues."""
    project_dir = tmp_path / "P"
    for name in ("boost.json", "other.json"):
        (project_dir / "patches").mkdir(parents=True, exist_ok=True)
        (project_dir / "patches" / name).write_bytes(projects.change_document_bytes())
    (project_dir / "firmware.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    record = manifest_writer.file_record(project_dir / "patches" / "boost.json")
    vs = _variant_set(project_dir)
    refused, findings = serialize_manifest(
        vs, project_dir, files={"patches/other.json": record}, active_document="patches/boost.json"
    )
    assert refused is None and len(findings) == 1, findings
    accepted, issues = serialize_manifest(
        vs, project_dir, files={"patches/boost.json": record}, active_document="patches/boost.json"
    )
    assert issues == [] and accepted is not None
    (project_dir / "project.json").write_text(accepted, encoding="utf-8")
    manifest = read_project_manifest(project_dir)
    assert manifest.issues == []
    assert _active_document(manifest) == "patches/boost.json"


def test_tc_b100_28_writer_refuses_a_junction_home(tmp_path: Path) -> None:
    """Inc 7 cp1 "link on the way": ``P/patches`` is a junction to a folder
    outside P → the serialize refuses the key (``None``, 1 finding)."""
    b100_links.require_junctions()
    project_dir = tmp_path / "P"
    project_dir.mkdir()
    projects.junction_home(project_dir, "patches", tmp_path / "private")
    serialized, findings = serialize_manifest(
        _variant_set(project_dir), project_dir, active_document="patches/boost.json"
    )
    assert serialized is None
    assert len(findings) == 1, findings


def _a15_project(tmp_path: Path) -> Path:
    project_dir = projects.copy_sources(
        tmp_path / "P", projects.CASE01_DIR, "firmware.s19", "firmware.mac", "firmware.a2l"
    )
    shutil.copyfile(projects.CASE00_DIR / "prg.s19", project_dir / "prg.srec")
    for relative in ("flows/f1.json", "reports/r.md"):
        (project_dir / relative).parent.mkdir(exist_ok=True)
        (project_dir / relative).write_text("{}", encoding="utf-8")
    (project_dir / "patches").mkdir()
    (project_dir / "patches" / "boost.json").write_bytes(projects.change_document_bytes())
    (project_dir / "patches" / "other.json").write_bytes(
        projects.change_document_bytes([projects.address_entry(SECOND_ADDRESS, (1,))])
    )
    return project_dir


def test_tc_b100_28_a15_files_records_the_active_document(tmp_path: Path) -> None:
    """LLR-169.2 A-15 arm (run in TC-B100-28): the 4 top-level files plus
    ``patches/boost.json`` (5), ``patches/other.json`` absent, each record
    equal to hashlib's. The leave-the-document-out mutant → 4 keys → RED."""
    project_dir = _a15_project(tmp_path)
    records = manifest_writer.project_file_records(
        project_dir, active_document="patches/boost.json"
    )
    assert set(records) == {
        "firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec", "patches/boost.json"
    }, sorted(records)
    record = records["patches/boost.json"]
    expected = projects.file_record_of(project_dir / "patches" / "boost.json")
    assert (record.size, record.sha256) == (expected["size"], expected["sha256"])


def test_tc_b100_28_a15_absent_document_has_no_record(tmp_path: Path) -> None:
    """A recorded document absent from disk → no record for it, 0 raises."""
    project_dir = _a15_project(tmp_path)
    records = manifest_writer.project_file_records(
        project_dir, active_document="patches/gone.json"
    )
    assert set(records) == {"firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec"}


def test_tc_b100_28_a15_junction_home_is_never_followed(tmp_path: Path) -> None:
    """S3-8: ``P/patches`` is a junction to a private folder holding
    ``boost.json`` → no record for it, 0 raises."""
    b100_links.require_junctions()
    project_dir = projects.copy_sources(tmp_path / "P", projects.CASE01_DIR, "firmware.s19")
    projects.junction_home(project_dir, "patches", tmp_path / "private")
    records = manifest_writer.project_file_records(
        project_dir, active_document="patches/boost.json"
    )
    assert set(records) == {"firmware.s19"}, sorted(records)


def test_tc_b100_28_valid_key_is_carried_not_kept_aside(tmp_path: Path) -> None:
    """SEC6-2: a manifest holding a valid ``active_document`` has 0 unknown
    keys, so no in-project rewrite refuses it and Save project keeps no
    ``.previous`` copy for it. The left-out-of-KNOWN_MANIFEST_KEYS mutant →
    "holds keys this version does not know" → RED."""
    project_dir = projects.seed_document_project(tmp_path)
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == ()
    assert manifest_rewrite_refusal(manifest) is None
    assert manifest_keep_reason(manifest) is None


#: The keep / rewrite-refusal phrase for a refused document (E3 R5 with
#: R6 user terms; orchestrator note to E4, D-E4-1).
REFUSED_DOCUMENT_REASON = "holds a change document path this version cannot use"


def test_tc_b100_28_refused_value_is_a_keep_reason(tmp_path: Path) -> None:
    """E3 R5: a refused ``active_document`` (``templates/x.json``) is a
    skipped entry the reader names as a known key (0 unknown keys), and
    ``manifest_keep_reason`` fires for it. The ignore-the-refused-value
    mutant → reason ``None`` → RED."""
    project_dir = projects.seed_document_project(
        tmp_path, active_document="templates/x.json"
    )
    manifest = read_project_manifest(project_dir)
    assert manifest.unknown_keys == ()
    assert _active_document(manifest) is None
    reason = manifest_keep_reason(manifest)
    assert reason == REFUSED_DOCUMENT_REASON, reason
    # SEC6-2: the in-project rewrite is still refused, never carried
    # verbatim (D-E4-1: it now gives the R5 phrase first).
    refusal = manifest_rewrite_refusal(manifest)
    assert refusal == REFUSED_DOCUMENT_REASON, refusal
    # E3 R6: the phrase is painted, so it never names the key.
    assert "active_document" not in reason


def test_tc_b100_28_variant_append_keeps_the_key(tmp_path: Path) -> None:
    """LLR-170.1 threshold: a variant append into a project recording a
    valid ``active_document`` rewrites ``project.json`` (1 rewrite) and
    keeps the key equal."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base))
    before = (project_dir / "project.json").read_bytes()
    source = projects.copy_sources(tmp_path / "src", projects.CASE02_DIR, "firmware.s19")
    projects.append_variant(base, source / "firmware.s19")
    assert (project_dir / "project.json").read_bytes() != before
    written = projects.read_manifest(project_dir)
    assert written.get("active_document") == "patches/boost.json", written


# ---------------------------------------------------------------------------
# TC-B100-29 — LLR-170.2: the app writes a pasted document; the gather places
# ---------------------------------------------------------------------------


def _pasted_save(tmp_path: Path, *, entries=((PATCH_ADDRESS, PATCH_BYTES),), document_text=None,
                 prepare=None, name: str = "P"):
    """Load case_01's S19, put a pasted document in the editor (``entries``
    added through the service, or ``document_text`` parsed), run
    ``prepare(app)`` and Save project ``name``. Returns (status messages,
    project folder, the editor document's source_path, panel flag)."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        if document_text is not None:
            assert app._change_service.load_text(document_text).ok
        for address, run in entries:
            _add(app, address, run)
        if prepare is not None:
            prepare(app)
        messages = await projects.save_project(pilot, app, log, name)
        return messages, app.workarea / name, app._change_service.document.source_path

    return projects.run_app(tmp_path / "app", scenario)


def test_tc_b100_29_pasted_document_lands_and_is_recorded(tmp_path: Path) -> None:
    """AT-B100-08 seed / HLR-170 ``p01``: one entry pasted at
    ``0x8000007C``, Save project ``P`` → ``P/patches/changes.json`` holds 1
    entry, ``active_document`` "patches/changes.json", its ``files`` record
    equal to hashlib's, the document bound to the landing (Q1)."""
    messages, project_dir, source_path = _pasted_save(tmp_path)
    assert any(m.startswith("Saved project to") for m in messages), messages
    landed = project_dir / "patches" / "changes.json"
    assert landed.is_file(), projects.tree_files(project_dir).keys()
    entries = _document_entries(landed)
    assert [entry["address"].upper() for entry in entries] == ["0X8000007C"], entries
    written = projects.read_manifest(project_dir)
    assert written.get("active_document") == "patches/changes.json", written
    assert written["files"]["patches/changes.json"] == projects.file_record_of(landed)
    assert source_path is not None and Path(source_path).as_posix().endswith(
        "patches/changes.json"
    ), source_path


def test_tc_b100_29_pasted_check_document_lands_in_checks(tmp_path: Path) -> None:
    """A pasted check document with 1 entry → ``P/checks/changes.json``,
    ``active_document`` "checks/changes.json"."""
    check_text = projects.change_document_bytes(kind="check").decode("utf-8")
    messages, project_dir, _ = _pasted_save(tmp_path, entries=(), document_text=check_text)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert (project_dir / "checks" / "changes.json").is_file()
    assert not (project_dir / "patches" / "changes.json").exists()
    assert projects.read_manifest(project_dir).get("active_document") == "checks/changes.json"


def test_tc_b100_29_zero_entries_writes_no_document(tmp_path: Path) -> None:
    """A pasted document with 0 entries → 0 files written by the app, no
    ``active_document`` (holds at the base; the ≥1-entry rule)."""
    messages, project_dir, _ = _pasted_save(tmp_path, entries=())
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert not (project_dir / "patches").exists()
    assert "active_document" not in projects.read_manifest(project_dir)


def _existing_project_with_changes_json(tmp_path: Path, body: bytes) -> Path:
    project_dir = projects.save_case01_project(tmp_path / "app", files=("firmware.s19",))
    (project_dir / "patches").mkdir(exist_ok=True)
    (project_dir / "patches" / "changes.json").write_bytes(body)
    return project_dir


def test_tc_b100_29_different_changes_json_lands_as_changes_1(tmp_path: Path) -> None:
    """M-1: a different ``changes.json`` already in ``P/patches/`` → the
    pasted document lands as ``changes_1.json`` and is recorded; the old
    file's bytes are unchanged."""
    other = projects.change_document_bytes([projects.address_entry(SECOND_ADDRESS, (0xAA,))])
    project_dir = _existing_project_with_changes_json(tmp_path, other)
    messages, _, _ = _pasted_save(tmp_path, name="P")
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert (project_dir / "patches" / "changes.json").read_bytes() == other
    assert (project_dir / "patches" / "changes_1.json").is_file()
    assert projects.read_manifest(project_dir).get("active_document") == "patches/changes_1.json"


def test_tc_b100_29_identical_changes_json_is_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M-1: an identical ``changes.json`` → reused, 0 new files under
    ``patches/``, recorded as "patches/changes.json"; the plan's document
    row says ``keep`` (TC-B100-59: the always-``new`` mutant → RED)."""
    project_dir = projects.save_case01_project(tmp_path / "app", files=("firmware.s19",))
    plans = _capture_plans(monkeypatch)

    def _place_identical(app) -> None:
        (project_dir / "patches").mkdir(exist_ok=True)
        (project_dir / "patches" / "changes.json").write_bytes(
            changes_io.serialize_change_document(app._change_service.document)
        )

    messages, _, _ = _pasted_save(tmp_path, prepare=_place_identical)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert sorted(p.name for p in (project_dir / "patches").iterdir()) == ["changes.json"]
    assert projects.read_manifest(project_dir).get("active_document") == "patches/changes.json"
    assert _document_rows(plans[-1]) == [("changes.json", "keep")], plans[-1].rows


def _file_backed_save(tmp_path: Path, body: bytes, *, delete_after_load: bool = False):
    """A document file in the COMMON patches folder, loaded through the
    Patch Editor's load seam, then Save project ``P``."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        common = app.workarea / "patches"
        common.mkdir(parents=True, exist_ok=True)
        document = common / "boost.json"
        document.write_bytes(body)
        result = app._change_service.load(str(document), app.base_dir)
        assert result.ok, result
        if delete_after_load:
            document.unlink()
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    return projects.run_app(tmp_path / "app", scenario)


def test_tc_b100_29_file_backed_document_is_copied_and_recorded(tmp_path: Path) -> None:
    """A file-backed ``boost.json`` from the common folder → 1 file
    ``P/patches/boost.json`` byte-equal to the source, recorded."""
    body = projects.change_document_bytes()
    messages, project_dir = _file_backed_save(tmp_path, body)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert (project_dir / "patches" / "boost.json").read_bytes() == body
    assert projects.read_manifest(project_dir).get("active_document") == "patches/boost.json"


def test_tc_b100_29_file_backed_zero_entries_is_recorded(tmp_path: Path) -> None:
    """E3 R9 / pre-ruling 8: a file-backed document with 0 entries is
    copied and recorded (the ≥1-entry rule is for a pasted one only)."""
    body = projects.change_document_bytes(entries=[])
    messages, project_dir = _file_backed_save(tmp_path, body)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert (project_dir / "patches" / "boost.json").read_bytes() == body
    assert projects.read_manifest(project_dir).get("active_document") == "patches/boost.json"


def test_tc_b100_29_deleted_file_backed_document_is_not_placed(tmp_path: Path) -> None:
    """E3 R11 class ``missing``: the source deleted after its load → the
    project is saved (never "Project NOT saved"), 0 document rows, no
    ``active_document``, 1 status line naming the document, no internal
    code painted."""
    messages, project_dir = _file_backed_save(
        tmp_path, projects.change_document_bytes(), delete_after_load=True
    )
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert not any("NOT saved" in m for m in messages), messages
    assert "active_document" not in projects.read_manifest(project_dir)
    assert len([m for m in messages if "boost.json" in m]) == 1, messages
    _painted_clean(messages)


def _forced_write_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """The document write returns ``(None, [one containment finding])`` —
    the writer's own refusal shape — wherever the app reaches it."""
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    def _refuse(*args, **kwargs):
        return None, [
            ValidationIssue(
                code=changes_io.MF_WRITE_CONTAINMENT,
                severity=ValidationSeverity.ERROR,
                message="forced by the test",
                artifact="change",
            )
        ]

    monkeypatch.setattr(changes_io, "write_change_document", _refuse)
    monkeypatch.setattr(app_module, "write_change_document", _refuse, raising=False)


def test_tc_b100_29_forced_write_failure_saves_without_the_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-170 error arm: a forced document-write failure into a fresh
    ``P`` → the project is saved, no ``active_document``, 1 status line
    holding "not saved" and "changes.json", the panel flag still set, no
    internal code or class name painted."""
    _forced_write_failure(monkeypatch)
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        await _add_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF", entries_after=1)
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P", _panel(app)._dirty

    messages, project_dir, dirty = projects.run_app(tmp_path / "app", scenario, size=(220, 60))
    assert any(m.startswith("Saved project to") for m in messages), messages
    notes = [m for m in messages if "not saved" in m.lower() and "changes.json" in m]
    assert len(notes) == 1, messages
    assert "active_document" not in projects.read_manifest(project_dir)
    assert not (project_dir / "patches" / "changes.json").exists()
    assert dirty is True
    _painted_clean(messages)


def test_tc_b100_29_failure_after_the_write_removes_the_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced manifest-write failure after the document landed in a
    fresh target → the target is rolled back (``P`` absent). Vacuity
    guard: the document was on disk when the manifest write ran. The
    leave-the-document-off-placed-files mutant keeps ``changes.json`` →
    RED."""
    landed_before_manifest: list = []

    def _fail_after_landing(self, project_dir, *args, **kwargs) -> bool:
        landed_before_manifest.append(
            (Path(project_dir) / "patches" / "changes.json").is_file()
        )
        return False

    monkeypatch.setattr(app_module.S19TuiApp, "_write_and_verify_manifest", _fail_after_landing)
    messages, project_dir, _ = _pasted_save(tmp_path)
    assert landed_before_manifest == [True], (landed_before_manifest, messages)
    assert not (project_dir / "patches" / "changes.json").exists()
    assert not project_dir.exists(), list(projects.tree_files(project_dir))


def test_tc_b100_29_second_save_of_the_bound_document_writes_nothing(tmp_path: Path) -> None:
    """E3 R1 / LED .72 Q1: after the first save binds the document to
    ``P/patches/changes.json``, 1 entry added and Save project into ``P``
    again → 0 writes for the document (1 file under ``patches/``, no
    ``changes_1.json``, bytes unchanged), still recorded, the panel flag
    set, 1 status line naming the unsaved edits and the Patch Editor save.
    The rewrite-in-place mutant changes a byte → RED."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        await _add_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF", entries_after=1)
        await projects.save_project(pilot, app, log, "P")
        landed = app.workarea / "P" / "patches" / "changes.json"
        first = landed.read_bytes() if landed.is_file() else None
        if first is None:
            return None, [], app.workarea / "P", _panel(app)._dirty
        await _add_through_the_panel(pilot, app, "0x80000060", "AA", entries_after=2)
        messages = await projects.save_project(pilot, app, log, "P")
        return first, messages, app.workarea / "P", _panel(app)._dirty

    first, messages, project_dir, dirty = projects.run_app(tmp_path / "app", scenario, size=(220, 60))
    assert first is not None, "the first Save project wrote no document"
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert sorted(p.name for p in (project_dir / "patches").iterdir()) == ["changes.json"]
    assert (project_dir / "patches" / "changes.json").read_bytes() == first
    assert projects.read_manifest(project_dir).get("active_document") == "patches/changes.json"
    assert dirty is True
    notes = [m for m in messages if "unsaved" in m.lower() and "Patch Editor" in m]
    assert len(notes) == 1, messages


def test_tc_b100_29_document_inside_the_project_outside_its_home_is_not_placed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E3 R11 class ``inside_elsewhere``: a document loaded from
    ``P/notes/x.json``, Save project into the open ``P`` → saved, 0 bytes
    copied into ``P/patches``, no ``active_document``, 1 status line naming
    "x.json"; the plan has 0 document rows (the no-``inside_elsewhere``
    mutant plans a row with no file in the tree → RED)."""
    project_dir = projects.save_case01_project(tmp_path / "app", files=("firmware.s19",))
    (project_dir / "notes").mkdir()
    (project_dir / "notes" / "x.json").write_bytes(projects.change_document_bytes())

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        result = app._change_service.load(str(project_dir / "notes" / "x.json"), app.base_dir)
        assert result.ok, result
        return await projects.save_project(pilot, app, log, "P")

    plans = _capture_plans(monkeypatch)
    messages = projects.run_app(tmp_path / "app", scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert not (project_dir / "patches" / "x.json").exists()
    assert "active_document" not in projects.read_manifest(project_dir)
    assert len([m for m in messages if "x.json" in m]) == 1, messages
    # TC-B100-59 (A3R2-1): 0 document rows, so the plan equals the tree.
    assert _document_rows(plans[-1]) == [], plans[-1].rows
    assert "active_document" not in plans[-1].manifest_keys


def test_tc_b100_29_r18_document_behind_a_junctioned_home_is_never_copied(
    tmp_path: Path,
) -> None:
    """E3 R18 / S3R3-1: ``P/patches`` swapped for a junction to a private
    folder; the editor document is bound to ``P/patches/boost.json`` (the
    unresolved spelling); Save project into a new ``Q`` copies 0 bytes and
    records nothing. The mutant that ``lstat``-s only the file (not its
    parent) copies the private file into ``Q/patches`` → RED."""
    b100_links.require_junctions()
    p_dir = projects.save_case01_project(tmp_path / "app", files=("firmware.s19",))
    secret = projects.junction_home(p_dir, "patches", tmp_path / "private")
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        assert app._change_service.load_text(secret.read_text(encoding="utf-8")).ok
        app._change_service.document.source_path = p_dir / "patches" / "boost.json"
        return await projects.save_project(pilot, app, log, "Q")

    messages = projects.run_app(tmp_path / "app", scenario)
    q_dir = _workarea(tmp_path / "app") / "Q"
    assert any(m.startswith("Saved project to") for m in messages), messages
    copied = [p for p in q_dir.rglob("*.json") if p.name != "project.json"]
    assert copied == [], copied
    assert "active_document" not in projects.read_manifest(q_dir)


# ---------------------------------------------------------------------------
# TC-B100-30 — LLR-170.3: the one classifier and the reopen
# ---------------------------------------------------------------------------

#: body -> (outcome, entry count for "ok")
CLASSIFIER_BODIES = {
    "one-entry": (projects.change_document_bytes(), "ok", 1),
    "empty-entries": (documents.EMPTY_ENTRIES, "ok", 0),
    "exactly-1000-entries": (documents.document_with_entries(1000), "ok", 1000),
    "1001-entries": (documents.document_with_entries(1001), "too_large", None),
    "one-byte-over-1MiB": (documents.document_over_byte_cap(), "too_large", None),
    "20000-entries": (documents.document_with_entries(20000), "too_large", None),
    "truncated": (documents.TRUNCATED, "unreadable", None),
    "v1-document": (documents.V1_DOCUMENT, "unreadable", None),
    "not-utf8": (documents.NOT_UTF8, "unreadable", None),
    "brackets-1MiB": (documents.OPEN_BRACKETS_ONE_MIB, "unreadable", None),
    "brackets-under-entries": (documents.OPEN_BRACKETS_UNDER_ENTRIES, "unreadable", None),
    "entries-is-5": (documents.ENTRIES_IS_FIVE, "unreadable", None),
    "bare-entries-is-5": (documents.BARE_ENTRIES_IS_FIVE, "unreadable", None),
    "5000-digit-integer": (documents.FIVE_THOUSAND_DIGITS, "unreadable", None),
    "entries-long-string": (documents.ENTRIES_LONG_STRING, "unreadable", None),
    "entries-wide-object": (documents.ENTRIES_WIDE_OBJECT, "unreadable", None),
}


def _recorded(tmp_path: Path, body) -> Path:
    project_dir = tmp_path / "P"
    if body is not None:
        (project_dir / "patches").mkdir(parents=True, exist_ok=True)
        (project_dir / "patches" / "boost.json").write_bytes(body)
    else:
        project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


@pytest.mark.parametrize("case", sorted(CLASSIFIER_BODIES))
def test_tc_b100_30_classifier_outcome(tmp_path: Path, case: str) -> None:
    """E3 R4 / R10 / R19: each body → its one outcome, 0 raises, under
    1 s. Over either cap → ``too_large`` (never parsed); a decode or parse
    failure (``RecursionError``, ``ValueError`` of a 5 000-digit integer,
    ``UnicodeDecodeError``) or ``entries`` not a list → ``unreadable``.
    Mutants: caps removed (the 20 000-entry file over 1 s), ``RecursionError``
    or ``ValueError`` left out of the catch set (a raise) → RED."""
    from s19_app.tui.app import recorded_document_state

    body, outcome, count = CLASSIFIER_BODIES[case]
    project_dir = _recorded(tmp_path, body)
    start = time.perf_counter()
    state = recorded_document_state(project_dir, "patches/boost.json")
    elapsed = time.perf_counter() - start
    assert state.outcome == outcome, (case, state.outcome)
    assert elapsed < timing_bound(1.0), f"{case}: {elapsed:.3f} s"
    if outcome == "ok":
        assert len(state.document.entries) == count
    else:
        assert state.document is None


def test_tc_b100_30_classifier_missing_file_and_missing_home(tmp_path: Path) -> None:
    """The file deleted → ``missing``; the home absent → ``missing``."""
    from s19_app.tui.app import recorded_document_state

    project_dir = _recorded(tmp_path, projects.change_document_bytes())
    (project_dir / "patches" / "boost.json").unlink()
    assert recorded_document_state(project_dir, "patches/boost.json").outcome == "missing"
    shutil.rmtree(project_dir / "patches")
    assert recorded_document_state(project_dir, "patches/boost.json").outcome == "missing"


def test_tc_b100_30_classifier_a_folder_is_unreadable(tmp_path: Path) -> None:
    from s19_app.tui.app import recorded_document_state

    project_dir = tmp_path / "P"
    (project_dir / "patches" / "boost.json").mkdir(parents=True)
    assert recorded_document_state(project_dir, "patches/boost.json").outcome == "unreadable"


def test_tc_b100_30_classifier_linked_file_is_a_link(tmp_path: Path) -> None:
    """S3-9: the recorded file is a symbolic link → ``link``."""
    from s19_app.tui.app import recorded_document_state

    project_dir = tmp_path / "P"
    (project_dir / "patches").mkdir(parents=True)
    target = tmp_path / "private.json"
    target.write_bytes(projects.change_document_bytes())
    try:
        os.symlink(target, project_dir / "patches" / "boost.json")
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks need privilege on this platform (PDR C-QA-6)")
    assert recorded_document_state(project_dir, "patches/boost.json").outcome == "link"


def test_tc_b100_30_classifier_junction_home_is_a_link(tmp_path: Path) -> None:
    """S3-9: ``P/patches`` is a junction → ``link``, 0 bytes read outside."""
    b100_links.require_junctions()
    from s19_app.tui.app import recorded_document_state

    project_dir = tmp_path / "P"
    project_dir.mkdir()
    projects.junction_home(project_dir, "patches", tmp_path / "private")
    state = recorded_document_state(project_dir, "patches/boost.json")
    assert state.outcome == "link"
    assert state.document is None


def test_tc_b100_30_classifier_held_file_is_io_error(tmp_path: Path) -> None:
    """S3R2-2: the file held open by another program (sharing violation on
    open) → ``io_error``, 0 raises."""
    if os.name != "nt":
        pytest.skip("share-mode locks are a Windows-only test arm (PDR C-QA-6)")
    from s19_app.tui.app import recorded_document_state

    project_dir = _recorded(tmp_path, projects.change_document_bytes())
    with projects.held_exclusively(project_dir / "patches" / "boost.json"):
        state = recorded_document_state(project_dir, "patches/boost.json")
    assert state.outcome == "io_error"


def _a2l_context() -> dict:
    from s19_app.tui.a2l_parse import parse_a2l_file

    return parse_a2l_file(projects.CASE01_DIR / "firmware.a2l")


SYMBOL_DOCUMENT = projects.change_document_bytes(
    [projects.symbol_entry("CAL_BLOCK_A", 0x80000010, (0x5A,))]
)


def test_tc_b100_30_classifier_symbol_entry_is_ok_with_or_without_context(
    tmp_path: Path,
) -> None:
    """E3 R17: an entry-level finding never makes the document unreadable —
    a symbol entry with no A2L context → ``ok`` (1 ``CHG-SYMBOL-UNRESOLVED``
    finding); with the project's A2L payload → ``ok``, 1 entry, 0 such
    findings. The any-ERROR-is-unreadable mutant → RED."""
    from s19_app.tui.app import recorded_document_state

    project_dir = _recorded(tmp_path, SYMBOL_DOCUMENT)
    bare = recorded_document_state(project_dir, "patches/boost.json")
    assert bare.outcome == "ok"
    assert [i.code for i in bare.document.issues].count("CHG-SYMBOL-UNRESOLVED") == 1
    resolved = recorded_document_state(project_dir, "patches/boost.json", _a2l_context())
    assert resolved.outcome == "ok"
    assert len(resolved.document.entries) == 1
    assert "CHG-SYMBOL-UNRESOLVED" not in [i.code for i in resolved.document.issues]


def _reopen(tmp_path: Path, project_dir_builder, *, hold: bool = False):
    """Build ``P`` with ``project_dir_builder(workarea)``, open it in a
    fresh app (optionally while the document is held by another program)
    and return (problems as (label, file, detail), document entry count,
    document source_path, panel flag, image map, Load seconds, issues)."""
    base = tmp_path / "app"
    project_dir = project_dir_builder(_workarea(base))

    async def scenario(app, pilot, log):
        if hold:
            with projects.held_exclusively(project_dir / "patches" / "boost.json"):
                elapsed = await projects.load_project(pilot, app, "P")
        else:
            elapsed = await projects.load_project(pilot, app, "P")
        document = app._change_service.document
        return (
            [(p.label, p.file, p.detail) for p in app._last_load_announcement.problems],
            len(document.entries),
            document.source_path,
            _panel(app)._dirty,
            dict(app.current_file.mem_map) if app.current_file is not None else None,
            elapsed,
            [i.code for i in document.issues],
            log.messages,
        )

    return project_dir, projects.run_app(base, scenario)


def test_tc_b100_30_reopen_lists_the_recorded_document(tmp_path: Path) -> None:
    """HLR-170 ``p06`` A: Load ``P`` → the Patch Editor holds
    ``patches/boost.json`` with 1 entry, its source path absolute, the
    panel flag clear, 0 problems."""
    project_dir, result = _reopen(tmp_path, projects.seed_document_project)
    problems, count, source_path, dirty, _image, _t, _codes, _log = result
    assert problems == [], problems
    assert count == 1
    assert source_path is not None and Path(source_path).is_absolute()
    assert Path(source_path).as_posix().endswith("patches/boost.json"), source_path
    assert dirty is False


def test_tc_b100_30_reopen_resolves_a_symbol_against_the_project_a2l(tmp_path: Path) -> None:
    """LLR-170.3 / Q5: a symbol entry is parsed with the project's A2L
    context → 1 entry, 0 unresolved. The no-``a2l_context`` mutant → 1
    ``CHG-SYMBOL-UNRESOLVED`` → RED."""

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(
            workarea, body=SYMBOL_DOCUMENT, data_files=("firmware.s19", "firmware.a2l")
        )

    _p, (problems, count, _s, _d, _i, _t, codes, _log) = _reopen(tmp_path, _build)
    assert count == 1, (count, codes)
    assert "CHG-SYMBOL-UNRESOLVED" not in codes, codes


def test_tc_b100_30_reopen_never_applies_the_entries(tmp_path: Path) -> None:
    """Q6: a document whose entry differs from the saved image → after Load
    the image bytes equal the image file's bytes (independent reader); the
    entry is listed, 0 applied. The apply-on-reopen mutant → bytes differ →
    RED."""
    entry = projects.change_document_bytes(
        [projects.address_entry(0x80000010, (0x5A, 0x5A))]
    )

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(workarea, body=entry)

    project_dir, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    assert count == 1, "the reopen listed no entry (vacuity guard)"
    expected = read_s19(project_dir / "firmware.s19").data
    assert {a: image[a] for a in (0x80000010, 0x80000011)} == {
        a: expected[a] for a in (0x80000010, 0x80000011)
    }


def test_tc_b100_30_missing_document_is_one_missing_problem(tmp_path: Path) -> None:
    """The recorded file deleted → exactly 1 problem, ``missing``,
    labelled "change document patches/boost.json" (E3 R20; from
    ``check_project_files``), 0 editor entries, the image opens. The
    also-report-it-from-the-reopen mutant → 2 → RED. Re-pinned in Inc 8a
    cp1 from the bare text "patches/boost.json" (R20)."""

    def _build(workarea: Path) -> Path:
        project_dir = projects.seed_document_project(workarea)
        (project_dir / "patches" / "boost.json").unlink()
        return project_dir

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    assert [(label, file) for label, file, _ in problems] == [
        ("missing", "change document patches/boost.json")
    ]
    assert count == 0
    assert image


def test_tc_b100_30_truncated_document_is_one_not_readable(tmp_path: Path) -> None:
    """The file holds ``{`` (with a ``files`` record) → exactly 1 problem,
    ``not readable``, labelled "change document patches/boost.json" (E3
    R20, re-pinned in Inc 8a cp1); 0 entries; the image opens; the painted
    reason holds no internal code or class name."""

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(workarea, body=documents.TRUNCATED)

    _p, (problems, count, source_path, _d, image, _t, _c, log) = _reopen(tmp_path, _build)
    assert [(label, file) for label, file, _ in problems] == [
        ("not readable", "change document patches/boost.json")
    ], problems
    assert count == 0
    assert source_path is None
    assert image
    _painted_clean([detail for _, _, detail in problems] + log)


HOSTILE_REOPEN = {
    "20000-entries": (documents.document_with_entries(20000), "too large to reopen"),
    "brackets-1MiB": (documents.OPEN_BRACKETS_ONE_MIB, None),
    "5000-digit-integer": (documents.FIVE_THOUSAND_DIGITS, None),
}


@pytest.mark.parametrize("case", sorted(HOSTILE_REOPEN))
def test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second(
    tmp_path: Path, case: str
) -> None:
    """E3 R4 / R10 / R19: over the caps, a 1 MiB bracket flood, a
    5 000-digit integer → exactly 1 ``not readable`` (the over-cap one says
    "too large to reopen"), 0 entries, the image opens, Load under 1 s,
    0 raises."""
    body, reason = HOSTILE_REOPEN[case]

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(workarea, body=body)

    _p, (problems, count, _s, _d, image, elapsed, _c, _log) = _reopen(tmp_path, _build)
    # E3 R20 (Inc 8a cp1 re-pin): the row is labelled as the change document.
    assert [(label, file) for label, file, _ in problems] == [
        ("not readable", "change document patches/boost.json")
    ], problems
    if reason is not None:
        assert reason in problems[0][2], problems
    assert count == 0
    assert image
    assert elapsed < timing_bound(1.0), f"{case}: Load took {elapsed:.3f} s"


def test_tc_b100_30_held_document_is_not_readable_and_stays_recorded(tmp_path: Path) -> None:
    """E3 R8 refined / R16: the file held by another program at Load → 1
    ``not readable`` with the reason "could not be read", 0 entries, the
    record still in ``project.json``."""
    if os.name != "nt":
        pytest.skip("share-mode locks are a Windows-only test arm (PDR C-QA-6)")
    project_dir, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(
        tmp_path, projects.seed_document_project, hold=True
    )
    # E3 R20 (Inc 8a cp1 re-pin): one row, labelled as the change document.
    assert [(label, file) for label, file, _ in problems] == [
        ("not readable", "change document patches/boost.json")
    ], problems
    assert "could not be read" in problems[0][2], problems
    assert count == 0
    assert projects.read_manifest(project_dir).get("active_document") == "patches/boost.json"


def test_tc_b100_30_refused_record_is_one_not_readable_row_and_no_reopen(
    tmp_path: Path,
) -> None:
    """HLR-170 invalid arm, as ruled at E4 integration (ruling 3) and E3
    R20: ``active_document`` "firmware.s19" → exactly 1 problem, ``not
    readable``, labelled "change document firmware.s19" with the reason
    "the recorded change document path is not one the app can use", 0
    problems on the image file "firmware.s19" itself (it opened), 0
    ``manifest damaged`` rows; the image opens, 0 editor entries.
    Re-pinned from ``..._is_one_manifest_damaged_row_and_no_reopen`` (E4)
    and from the bare label "firmware.s19" (Inc 8a cp1, R20): a document
    row must never read as a fault of the image that opened."""

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(
            workarea, active_document="firmware.s19", record_document=False
        )

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    assert problems == [
        (
            "not readable",
            "change document firmware.s19",
            "the recorded change document path is not one the app can use"
            " - replace the file, or Save project to drop it",
        )
    ], problems
    assert [p for p in problems if p[1] == "firmware.s19"] == []
    assert count == 0
    assert image


@pytest.mark.parametrize("record_document", [True, False], ids=["recorded", "unrecorded"])
def test_tc_b100_30_linked_document_is_one_not_readable_row(
    tmp_path: Path, record_document: bool
) -> None:
    """E4 integration ruling 3 (the tester's open question): the recorded
    ``patches/boost.json`` is a symbolic link → exactly 1 problem, ``not
    readable``, naming "patches/boost.json" with "the file is a link and is
    not opened", 0 ``manifest damaged`` rows — whether or not ``files``
    records it (its key would otherwise add a second row for the same
    file) — 0 editor entries, the image opens. The reader-code wording
    ("a file path goes through a link or junction") is not painted."""
    private = tmp_path / "private.json"
    private.write_bytes(projects.change_document_bytes())

    def _build(workarea: Path) -> Path:
        project_dir = projects.seed_document_project(workarea, record_document=record_document)
        target = project_dir / "patches" / "boost.json"
        target.unlink()
        try:
            os.symlink(private, target)
        except (OSError, NotImplementedError):
            pytest.skip("file symlinks need privilege on this platform (PDR C-QA-6)")
        return project_dir

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    # E3 R20 (Inc 8a cp1 re-pin): the label is the change document's.
    assert problems == [
        (
            "not readable",
            "change document patches/boost.json",
            "the file is a link and is not opened - replace the file, or Save project to drop it",
        )
    ], problems
    assert count == 0
    assert image


def test_tc_b100_30_reopened_document_loads_without_a_question(tmp_path: Path) -> None:
    """After the reopen the panel flag is clear, so a following Patch
    Editor Load raises 0 ``LoadGuardScreen`` (the reopen is a load, writer
    w4)."""
    base = tmp_path / "app"
    projects.seed_document_project(_workarea(base))
    other = tmp_path / "other.json"
    other.write_bytes(projects.change_document_bytes([projects.address_entry(SECOND_ADDRESS, (1,))]))

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        assert len(app._change_service.document.entries) == 1, "no reopen (vacuity guard)"
        app.action_show_screen("patch")
        await projects.wait_for(pilot, lambda: len(app.query("#patch_doc_load_button")) > 0,
                                "the Patch Editor")
        from textual.widgets import Button, Input

        panel = _panel(app)
        panel.query_one("#patch_doc_path_input", Input).value = str(other)
        panel.query_one("#patch_doc_load_button", Button).press()
        for _ in range(12):
            await pilot.pause()
            assert not isinstance(app.screen, LoadGuardScreen), "the Load asked a question"
        return True

    assert projects.run_app(base, scenario) is True


# ---------------------------------------------------------------------------
# E4 integration — the tester's named gaps (R-32, gather classifier)
# ---------------------------------------------------------------------------


def _classifier_project(tmp_path: Path) -> Path:
    project_dir = _workarea(tmp_path / "app") / "P"
    (project_dir / "patches").mkdir(parents=True)
    (project_dir / "notes").mkdir()
    for path in (
        project_dir / "patches" / "boost.json",
        project_dir / "notes" / "x.json",
        tmp_path / "sources" / "y.json",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(projects.change_document_bytes())
    return project_dir


def test_tc_b100_29_gather_classifier_names_each_of_its_four_classes(tmp_path: Path) -> None:
    """E3 R11, direct: the one gather classifier decides the plan row and
    the copy, so each class must come out for its own source — ``in_home``
    (recorded as on disk, never rewritten, R1), ``outside`` (copied under
    its own name), ``inside_elsewhere`` and ``missing`` (0 rows, nothing
    copied). A classifier that folds ``inside_elsewhere`` into ``in_home``
    would record a file outside its home; one that folds ``missing`` into
    ``outside`` would plan a copy of a file that is not there."""
    from s19_app.tui.services.project_gather_service import classify_active_document

    project_dir = _classifier_project(tmp_path)
    in_home = project_dir / "patches" / "boost.json"
    assert classify_active_document(project_dir, in_home, "patches") == ("in_home", "boost.json")
    assert classify_active_document(
        project_dir, tmp_path / "sources" / "y.json", "patches"
    ) == ("outside", "y.json")
    assert classify_active_document(
        project_dir, project_dir / "notes" / "x.json", "patches"
    ) == ("inside_elsewhere", None)
    assert classify_active_document(
        project_dir, tmp_path / "sources" / "gone.json", "patches"
    ) == ("missing", None)
    # The home is the kind's: a patch file under P/patches is not in the
    # checks home, so a check document there is not recorded as in place.
    assert classify_active_document(project_dir, in_home, "checks") == ("inside_elsewhere", None)


def test_tc_b100_29_gather_classifier_never_copies_a_linked_source(tmp_path: Path) -> None:
    """S3R2-5: a file-backed source that is a symbolic link is ``missing``
    — never ``outside`` — so the gather never copies the bytes the link
    points at (a private file outside the work area)."""
    from s19_app.tui.services.project_gather_service import classify_active_document

    project_dir = _classifier_project(tmp_path)
    private = tmp_path / "private.json"
    private.write_bytes(projects.change_document_bytes())
    linked = tmp_path / "sources" / "linked.json"
    try:
        os.symlink(private, linked)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks need privilege on this platform (PDR C-QA-6)")
    assert classify_active_document(project_dir, linked, "patches") == ("missing", None)


def test_tc_b100_29_gather_classifier_home_spelled_in_another_case(tmp_path: Path) -> None:
    """A3R2-7: the home folder is compared case-sensitively, so a source
    spelled ``P/Patches/boost.json`` is not ``in_home`` even where the
    filesystem folds case — the recorded text would otherwise be one the
    reader refuses (``Patches/...`` fails the form)."""
    if os.name != "nt":
        pytest.skip("a case-folding filesystem is the Windows arm of this case")
    from s19_app.tui.services.project_gather_service import classify_active_document

    project_dir = _classifier_project(tmp_path)
    spelled = project_dir / "Patches" / "boost.json"
    assert spelled.is_file(), "vacuity guard: the filesystem must fold case here"
    assert classify_active_document(project_dir, spelled, "patches") == ("inside_elsewhere", None)


def test_tc_b100_29_r12_bind_keeps_the_unresolved_spelling(tmp_path: Path) -> None:
    """E3 R12 (S3R2-6): the pasted document is bound to
    ``project_dir / home / name`` as the app spells the work area, never
    to the placement's resolved path — so a work area reached through a
    junction above its anchor stays visible to every later placement guard
    (the source path the next Save sees is the one the user's project
    holds). The bind-to-``PlacementResult.path`` mutant names the resolved
    folder → RED."""
    b100_links.require_junctions()
    real = tmp_path / "real"
    real.mkdir()
    b100_links.create_junction(tmp_path / "via", real)
    base = tmp_path / "via" / "app"
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea, app._change_service.document.source_path

    messages, workarea, source_path = projects.run_app(base, scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    expected = workarea / "P" / "patches" / "changes.json"
    assert expected.is_file(), messages
    assert os.path.normcase(str(expected)) != os.path.normcase(str(expected.resolve())), (
        "vacuity guard: the app's spelling of the work area must differ from the resolved one"
    )
    assert source_path is not None
    assert os.path.normcase(str(Path(source_path))) == os.path.normcase(str(expected)), source_path


@pytest.mark.parametrize(
    ("reason", "step", "next_step"),
    [
        (
            "too large to reopen",
            "open_from_editor",
            "open it from the Patch Editor (it can take a while)",
        ),
        (
            "could not be read",
            "check_then_load",
            "check that the file can be opened, then Load again",
        ),
        (
            "the file is a link and is not opened",
            None,
            "replace the file, or Save project to drop it",
        ),
        (
            "not a change or check document the app can read",
            None,
            "replace the file, or Save project to drop it",
        ),
    ],
    ids=["too_large", "io_error", "link", "unreadable"],
)
def test_tc_b100_30_not_readable_document_paints_the_next_step_of_its_reason(
    reason: str, step, next_step: str
) -> None:
    """E4 integration ruling 1 (G-1, D-B5; §3 rows for Inc 8a, E3 R16):
    Save project KEEPS a too-large or locked document (R8 refined), so
    "Save project to drop it" would send the user to a step that does not
    drop it; those two reasons paint their own next step, while a link or
    an unreadable file — which Save project does drop — keep the kind's
    token. A composer that always paints the kind's token → RED on the
    first two ids. Re-pinned in Inc 8a cp1 (review F5): the producers
    carry the step as a mark on the problem (``step``) and the composer
    reads the mark, never the reason's text."""
    from s19_app.tui.services.variant_execution_service import ProjectFileProblem
    from s19_app.tui.services.variant_execution_service import ProjectManifest
    from s19_app.tui.services.variant_execution_service import compose_load_announcement

    variant_set = build_variant_set("P", [Path("firmware.s19")])
    variant_set.active_id = "firmware"
    announcement = compose_load_announcement(
        "P",
        variant_set,
        ProjectManifest(schema_version=1, active_variant="firmware"),
        problems=[
            ProjectFileProblem("not readable", "patches/boost.json", reason, step=step)
        ],
    )
    assert [(p.label, p.file, p.detail) for p in announcement.problems] == [
        ("not readable", "patches/boost.json", f"{reason} - {next_step}")
    ]


# ---------------------------------------------------------------------------
# Inc 8a corrective pass 1 — review F1–F6, SEC8a-1 / SEC8a-3 / SEC8a-4
# ---------------------------------------------------------------------------

#: Device stems with any case and suffix spelling (F1) and Unicode format
#: characters — bidi controls, zero-width, BOM (SEC8a-4).
DEVICE_STEM_TEXTS = [
    "patches/aux.json",
    "checks/CON.json",
    "patches/nul.JSON",
    "patches/com1.json",
    "patches/lpt9.json",
]
FORMAT_CHARACTER_TEXTS = [
    "patches/‮osj.exe.json",
    "patches/a​b.json",
    "checks/⁦x.json",
    "patches/﻿x.json",
]


@pytest.mark.parametrize("text", DEVICE_STEM_TEXTS + FORMAT_CHARACTER_TEXTS)
def test_tc_b100_28_cp1_form_refuses_device_stems_and_format_characters(
    tmp_path: Path, text: str
) -> None:
    """F1 / SEC8a-4 (LLR-170.1): the one form predicate refuses what the
    manifest-keys mode refuses on the text (a device stem) and any Unicode
    format character, so the app never records a landing the writer or the
    reader refuses; the writer refuses it (``None``, 1 finding) and the
    reader refuses it (no document, 1 finding). Control: ``auxiliary.json``
    is a plain name and passes. Mutants: drop the key-mode clause → RED on
    the device stems; drop the format-character test → RED on the others."""
    from s19_app.tui.services.variant_execution_service import is_active_document_form

    assert is_active_document_form("patches/auxiliary.json") is True
    assert is_active_document_form(text) is False
    project_dir = tmp_path / "P"
    project_dir.mkdir()
    serialized, findings = serialize_manifest(
        _variant_set(project_dir), project_dir, active_document=text
    )
    assert serialized is None
    assert len(findings) == 1, findings
    _write_manifest(
        project_dir,
        {"schema_version": 1, "active_variant": "firmware", "active_document": text},
    )
    manifest = read_project_manifest(project_dir)
    assert _active_document(manifest) is None
    assert len(manifest.issues) == 1, manifest.issues


def _file_backed(app, folder: Path, name: str, body: bytes = b"") -> Path:
    """Write a change document ``name`` into ``folder`` and open it in the
    Patch Editor (file-backed)."""
    folder.mkdir(parents=True, exist_ok=True)
    document = folder / name
    document.write_bytes(body or projects.change_document_bytes())
    result = app._change_service.load(str(document), app.base_dir)
    assert result.ok, result
    return document


@pytest.mark.parametrize("doc_name", ["aux.json", "con.json"])
def test_tc_b100_29_cp1_device_stem_document_never_refuses_the_save(
    tmp_path: Path, doc_name: str
) -> None:
    """F1 / pre-ruling 2 / R11 (reviewer probe Q6): a file-backed change
    document whose stem is a Windows device name → Save project completes
    ("Saved project to"), ``active_document`` absent, the copy not listed
    in ``gathered`` (project.json could not hold it), exactly one line
    naming the document, which says it is not recorded and never "could not
    be placed", 0 internal codes painted. The drop-the-key-mode-clause
    mutant → "Project NOT saved" → RED."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        common = app.workarea / "patches"
        common.mkdir(parents=True, exist_ok=True)
        if doc_name not in os.listdir(common):
            (common / doc_name).write_bytes(projects.change_document_bytes())
        if doc_name not in os.listdir(common):
            pytest.skip(f"{doc_name} cannot be created as a file on this host")
        _file_backed(app, common, doc_name)
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    manifest = projects.read_manifest(project_dir)
    assert "active_document" not in manifest, manifest
    assert doc_name not in json.dumps(manifest.get("gathered", {})), manifest
    about = [m for m in messages if doc_name in m]
    assert len(about) == 1, messages
    assert "not recorded" in about[0] and "could not be placed" not in about[0], about
    _painted_clean(messages)


def test_tc_b100_29_cp1_copied_document_outside_the_form_says_so(tmp_path: Path) -> None:
    """F3 (reviewer probe Q2): a file-backed ``boost.txt`` from the common
    patches folder → copied to ``P/patches/boost.txt``, not recorded, and
    the one line says it was copied but is not recorded because of its
    name — never "could not be placed"."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        _file_backed(app, app.workarea / "patches", "boost.txt")
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    assert (project_dir / "patches" / "boost.txt").is_file()
    assert "active_document" not in projects.read_manifest(project_dir)
    about = [m for m in messages if "boost.txt" in m]
    assert len(about) == 1, messages
    assert "was copied into the project's patches folder" in about[0], about
    assert "could not be placed" not in about[0], about


def test_tc_b100_29_cp1_in_home_document_outside_the_form_names_its_name(
    tmp_path: Path,
) -> None:
    """F3: ``P/patches/boost.txt`` (already in its home, a name outside the
    form) → not recorded, and the one line says the name is the reason —
    never "not in its patches folder"."""
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        _file_backed(app, app.workarea / "P" / "patches", "boost.txt")
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert "active_document" not in projects.read_manifest(project_dir)
    about = [m for m in messages if "boost.txt" in m]
    assert len(about) == 1, messages
    assert "in the project's patches folder, but its name" in about[0], about
    assert "not in its patches folder" not in about[0], about


def test_tc_b100_29_cp1_held_reopened_document_paints_one_true_line(tmp_path: Path) -> None:
    """F2 (reviewer probe Q1) and the M-15 arm: Load P (reopens
    ``patches/boost.json``), the file held by another program, Save project
    into P → the record stays (R8 refined, ``io_error``), exactly one line
    names the document and none says "not recorded". The plan's digest
    raises here: the propagate-the-OSError mutant (M-15) refuses the save →
    RED."""
    if os.name != "nt":
        pytest.skip("share-mode locks are a Windows-only test arm (PDR C-QA-6)")
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base))

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        assert len(app._change_service.document.entries) == 1
        with projects.held_exclusively(project_dir / "patches" / "boost.json"):
            return await projects.save_project(pilot, app, log, "P")

    messages = projects.run_app(base, scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert projects.read_manifest(project_dir).get("active_document") == "patches/boost.json"
    about = [m for m in messages if "boost.json" in m]
    assert len(about) == 1, messages
    assert "not recorded" not in about[0] and "stays recorded" in about[0], about


def test_tc_b100_29_cp1_document_recorded_elsewhere_paints_one_true_line(
    tmp_path: Path,
) -> None:
    """F2 (reviewer probe Q3): P records ``checks/boost.json`` holding a
    change document; Load P, Save project into P → the carried record is
    written, and exactly one line names it, saying it stays recorded as it
    was — none says "not recorded"."""
    base = tmp_path / "app"
    project_dir = projects.seed_document_project(_workarea(base), document="checks/boost.json")

    async def scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        assert len(app._change_service.document.entries) == 1
        return await projects.save_project(pilot, app, log, "P")

    messages = projects.run_app(base, scenario)
    assert projects.read_manifest(project_dir).get("active_document") == "checks/boost.json"
    about = [m for m in messages if "boost.json" in m]
    assert len(about) == 1, messages
    assert "not recorded" not in about[0] and "stays recorded" in about[0], about


def test_tc_b100_29_cp1_unreadable_outside_document_is_not_placed(tmp_path: Path) -> None:
    """F6 / M-15 (LLR-167.6 / A3R2-1): a file-backed document outside the
    project that exists but cannot be read (held with share mode 0) →
    the plan gives it no row, Save project completes, nothing copied, no
    ``active_document``, one line naming it. The propagate-the-OSError
    mutant → "Project NOT saved" → RED."""
    if os.name != "nt":
        pytest.skip("share-mode locks are a Windows-only test arm (PDR C-QA-6)")
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        document = _file_backed(app, app.workarea / "patches", "boost.json")
        with projects.held_exclusively(document):
            messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert not (project_dir / "patches" / "boost.json").exists()
    assert "active_document" not in projects.read_manifest(project_dir)
    assert len([m for m in messages if "boost.json" in m]) == 1, messages


def test_tc_b100_29_cp1_failed_document_write_drops_the_key_from_the_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F4 / LLR-167.6 on the failure path (reviewer probe Q4): a forced
    pasted-document write failure → the plan the save ends with lists the
    keys ``project.json`` is written with (no ``active_document``). The
    plan predicted before the write lists it (vacuity guard). The
    keep-the-predicted-plan mutant → RED."""
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    def _refuse(*args, **kwargs):
        return None, [
            ValidationIssue(
                code=changes_io.MF_WRITE_CONTAINMENT,
                severity=ValidationSeverity.ERROR,
                message="forced",
                artifact="change",
            )
        ]

    monkeypatch.setattr(app_module, "write_change_document", _refuse)
    plans = _capture_plans(monkeypatch)
    settle = app_module._plan_without_document_key

    def _settled(plan):
        settled = settle(plan)
        plans.append(settled)
        return settled

    monkeypatch.setattr(app_module, "_plan_without_document_key", _settled)
    src = _source(tmp_path)

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        messages = await projects.save_project(pilot, app, log, "P")
        return messages, app.workarea / "P"

    messages, project_dir = projects.run_app(tmp_path / "app", scenario)
    written = tuple(json.loads((project_dir / "project.json").read_text(encoding="utf-8")))
    assert "active_document" in plans[0].manifest_keys, plans[0].manifest_keys
    assert "active_document" not in written
    assert tuple(plans[-1].manifest_keys) == written, (plans[-1].manifest_keys, written)


def test_tc_b100_29_cp1_case_sensitive_work_area_keeps_two_projects_apart(
    tmp_path: Path,
) -> None:
    """SEC8a-1: in a case-sensitive folder holding projects ``P`` and
    ``p``, a document in ``p/patches`` is ``outside`` for ``P`` (copied,
    never recorded as ``P``'s own file), with ``P/patches/x.json`` absent
    and present; control: ``in_home`` for ``p``. The case-folding mutant
    → ``in_home`` for ``P`` → RED."""
    from s19_app.tui.services.project_gather_service import classify_active_document
    from s19_app.tui.services.project_gather_service import document_in_home

    workarea = tmp_path / "cs"
    workarea.mkdir()
    b100_links.enable_case_sensitive(workarea)
    (workarea / "P" / "patches").mkdir(parents=True)
    (workarea / "p" / "patches").mkdir(parents=True)
    if sorted(os.listdir(workarea)) != ["P", "p"]:
        pytest.skip("the folder did not hold P and p apart (not case-sensitive)")
    source = workarea / "p" / "patches" / "x.json"
    source.write_bytes(projects.change_document_bytes())
    assert classify_active_document(workarea / "P", source, "patches") == ("outside", "x.json")
    assert document_in_home(workarea / "P", source, "patches") is False
    (workarea / "P" / "patches" / "x.json").write_bytes(b"{}")
    assert classify_active_document(workarea / "P", source, "patches") == ("outside", "x.json")
    assert classify_active_document(workarea / "p", source, "patches") == ("in_home", "x.json")


def test_tc_b100_29_cp1_junctioned_home_gives_no_document_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC8a-3: P exists and ``P/patches`` is a junction to another
    project's ``Q/patches`` (holding its own ``changes.json``); a pasted
    document, Save project into P → the plan has 0 document rows (the
    planner runs the guarded write's containment check), Save project
    completes, ``Q`` is unchanged, no ``active_document``, and the one line
    names ``changes.json`` (never a name derived from Q's file). The
    skip-the-check mutant → a predicted row → RED."""
    b100_links.require_junctions()
    plans = _capture_plans(monkeypatch)
    src = _source(tmp_path)
    base = tmp_path / "app"
    workarea = _workarea(base)
    q_patches = workarea / "Q" / "patches"
    q_patches.mkdir(parents=True)
    (q_patches / "changes.json").write_bytes(b'{"q": "own file"}')
    project_dir = workarea / "P"
    project_dir.mkdir(parents=True)
    shutil.copy2(src, project_dir / "firmware.s19")
    b100_links.create_junction(project_dir / "patches", q_patches)
    before = sorted((item.name, item.read_bytes()) for item in q_patches.iterdir())

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        _add(app, PATCH_ADDRESS, PATCH_BYTES)
        return await projects.save_project(pilot, app, log, "P")

    messages = projects.run_app(base, scenario)
    assert _document_rows(plans[-1]) == [], plans[-1].rows
    assert any(m.startswith("Saved project to") for m in messages), messages
    assert sorted((item.name, item.read_bytes()) for item in q_patches.iterdir()) == before
    assert "active_document" not in projects.read_manifest(project_dir)
    about = [m for m in messages if "changes" in m]
    assert len(about) == 1 and "changes.json was not saved" in about[0], about
    assert "changes_1" not in about[0], about


def test_tc_b100_30_cp1_held_unrecorded_document_paints_the_reopen_reason(
    tmp_path: Path,
) -> None:
    """F6 / R-17 (E3 R16): the recorded document has no ``files`` record and
    is held by another program at Load, so the project check emits no row
    and the reopen's own row is the one painted → exactly 1 problem: ``not
    readable``, "change document patches/boost.json", "could not be read -
    check that the file can be opened, then Load again". The R-17 mutant
    (``io_error`` worded as unreadable) and a dropped step mark → RED."""
    if os.name != "nt":
        pytest.skip("share-mode locks are a Windows-only test arm (PDR C-QA-6)")

    def _build(workarea: Path) -> Path:
        return projects.seed_document_project(workarea, record_document=False)

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build, hold=True)
    assert problems == [
        (
            "not readable",
            "change document patches/boost.json",
            "could not be read - check that the file can be opened, then Load again",
        )
    ], problems
    assert count == 0
    assert image


def test_tc_b100_30_cp1_next_step_follows_the_mark_not_the_reason_text() -> None:
    """F5: the composer picks the next step by the problem's mark. A
    problem worded "too large to reopen" without a mark paints the kind's
    token; the reasons the producers paint are the reader module's
    constants (one spelling, shared by object identity)."""
    from s19_app.tui.services import variant_execution_service as ves

    variant_set = build_variant_set("P", [Path("firmware.s19")])
    variant_set.active_id = "firmware"
    announcement = ves.compose_load_announcement(
        "P",
        variant_set,
        ves.ProjectManifest(schema_version=1, active_variant="firmware"),
        problems=[ves.ProjectFileProblem("not readable", "x.json", "too large to reopen")],
    )
    assert [p.detail for p in announcement.problems] == [
        "too large to reopen - replace the file, or Save project to drop it"
    ]
    assert app_module._DOCUMENT_REASON[app_module.DOCUMENT_IO_ERROR] is ves.DOCUMENT_REASON_IO_ERROR
    assert app_module._DOCUMENT_REASON[app_module.DOCUMENT_TOO_LARGE] is ves.DOCUMENT_REASON_TOO_LARGE
    assert app_module._DOCUMENT_REASON[app_module.DOCUMENT_LINK] is ves.DOCUMENT_REASON_LINK


def test_tc_b100_30_cp1_changed_document_row_is_labelled_as_the_change_document(
    tmp_path: Path,
) -> None:
    """E3 R20 at the project check: the recorded document's bytes differ
    from its ``files`` record (a valid two-entry document now) → exactly 1
    problem, ``changed on disk``, labelled "change document
    patches/boost.json" (the check's own row; the reopen succeeds and adds
    none). The check-labels-with-the-bare-text mutant → RED."""

    def _build(workarea: Path) -> Path:
        project_dir = projects.seed_document_project(workarea)
        (project_dir / "patches" / "boost.json").write_bytes(
            projects.change_document_bytes(
                [
                    projects.address_entry(PATCH_ADDRESS, PATCH_BYTES),
                    projects.address_entry(SECOND_ADDRESS, (1,)),
                ]
            )
        )
        return project_dir

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    assert [(label, file) for label, file, _ in problems] == [
        ("changed on disk", "change document patches/boost.json")
    ], problems
    assert count == 2
    assert image


def test_tc_b100_30_cp1_missing_unrecorded_document_is_one_change_document_row(
    tmp_path: Path,
) -> None:
    """E3 R20 at ``_active_document_missing``: the recorded document has no
    ``files`` record and is deleted → exactly 1 problem, ``missing``,
    labelled "change document patches/boost.json"; 0 entries; the image
    opens. The bare-text mutant → RED."""

    def _build(workarea: Path) -> Path:
        project_dir = projects.seed_document_project(workarea, record_document=False)
        (project_dir / "patches" / "boost.json").unlink()
        return project_dir

    _p, (problems, count, _s, _d, image, _t, _c, _log) = _reopen(tmp_path, _build)
    assert [(label, file) for label, file, _ in problems] == [
        ("missing", "change document patches/boost.json")
    ], problems
    assert count == 0
    assert image


# ---------------------------------------------------------------------------
# AT-B100-08 — HLR-170 / US-160 black-box: Save project → active_document →
# Load, by keys, clicks and a bracketed paste
# ---------------------------------------------------------------------------

AT_SIZES = [(118, 54), (220, 60)]


def _at_status(app) -> str:
    from textual.widgets import Label

    return str(app.query_one("#status_text", Label).render())


def _at_ledger(app) -> str:
    """The Patch Editor ledger as painted (its rendered strips)."""
    return "\n".join(projects.painted_lines(app.query_one("#patch_doc_entries_table")))


def _at_script_border(app) -> str:
    """The SCRIPT window's bottom border row as the screen paints it (the
    composited strip; a widget's own ``render_line`` excludes its border):
    it carries ``N entries`` and the unsaved marker (LLR-005.1)."""
    region = app.query_one("#patch_win_script").region
    strips = app.screen._compositor.render_strips()
    return strips[region.y + region.height - 1].text[region.x : region.x + region.width]


async def _at_load_file_through_dialog(pilot, app, src: Path) -> None:
    from s19_app.tui.screens import LoadFileScreen

    await pilot.press("l")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, LoadFileScreen), "the Load file dialog"
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await projects.wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadFileScreen)
        and _at_status(app).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


async def _at_paste_and_parse(pilot, app, text: str) -> None:
    """Open the Patch Editor (``6``), pick its JSON tab by its chip, select
    the paste buffer's text (``f7``) and paste ``text`` over it the way a terminal
    delivers a paste (bracketed paste: ``events.Paste`` to the app, which
    forwards it to the focused buffer), then click Parse pasted."""
    from textual import events
    from textual.widgets import TextArea

    await pilot.press("6")
    await projects.wait_for(
        pilot, lambda: len(app.query("#patch_paste_parse_button")) > 0, "the Patch Editor"
    )
    assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
    await projects.wait_for(
        pilot,
        lambda: app.query_one("#patch_paste_text").region.area > 0,
        "the painted paste buffer",
    )
    assert await pilot.click("#patch_paste_text"), "click missed #patch_paste_text"
    # ``f7`` is the paste buffer's select-all key (``ctrl+a`` moves to the
    # line start there); the paste then replaces the selection.
    await pilot.press("f7")
    app.post_message(events.Paste(text))
    buffer = app.query_one("#patch_paste_text", TextArea)
    await projects.wait_for(pilot, lambda: buffer.text == text, "the pasted text in the buffer")
    assert await pilot.click("#patch_paste_parse_button"), "click missed Parse pasted"
    await projects.wait_for(
        pilot,
        lambda: f"{PATCH_ADDRESS:08X}" in _at_ledger(app).upper(),
        "the pasted entry painted in the ledger",
    )


async def _at_save_project_through_dialog(pilot, app, log, name: str) -> list:
    from s19_app.tui.screens import SaveProjectScreen

    mark = len(log.messages)
    await pilot.press("ctrl+s")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, SaveProjectScreen), "the Save project dialog"
    )
    assert await pilot.click("#project_name"), "click missed #project_name"
    await pilot.press(*name)
    assert await pilot.click("#save_ok"), "click missed #save_ok"
    await projects.wait_for(
        pilot,
        lambda: any(
            outcome in message
            for message in log.since(mark)
            for outcome in projects.SAVE_OUTCOMES
        ),
        "the Save project outcome",
    )
    return log.since(mark)


async def _at_open_project_through_dialog(pilot, app, name: str) -> str:
    """``1`` (home), ``p`` (Load project dialog), click the project's row,
    click OK; read the Load-result panel it opens, close it with ``esc``."""
    from textual.widgets import Label

    from s19_app.tui.screens import LoadProjectScreen

    await pilot.press("1")
    for _ in range(4):
        await pilot.pause()
    await pilot.press("p")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, LoadProjectScreen), "the Load project dialog"
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await projects.wait_for(
        pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel"
    )
    text = await projects.read_load_result_panel(pilot, app)
    await projects.dismiss_load_result_panel(pilot, app)
    return text


@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_08_saved_document_reopens_with_the_project(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-170's acceptance scene by keys, clicks and a paste: Load file
    ``case_01`` ``firmware.s19`` (``l``); in the Patch Editor (``6``) paste
    a change document holding one entry ``0x8000007C DE AD BE EF`` and
    click Parse pasted (the entry is NOT applied); Save project P
    (``ctrl+s``) → ``P/patches/changes.json`` holds that entry and
    ``project.json`` records ``active_document`` "patches/changes.json".
    Then a FRESH app opens P through the Load project dialog (``p``): the
    Load-result panel lists no problem, the Patch Editor ledger paints
    ``8000007C``, the SCRIPT window paints ``1 entr...`` with no unsaved
    marker, the image bytes at the entry's 4 addresses equal the saved
    ``P/firmware.s19`` (independent reader) and the reopen's full
    ``set_status`` log holds the ``0 problems`` summary and no apply
    outcome — the reopen lists the entry, it never re-applies it. Both
    reference sizes.

    RED (base dc3b314, P-8): the save writes no ``patches/changes.json``
    and records no ``active_document``; a reopen lists 0 entries."""
    import asyncio

    src = _source(tmp_path)
    base = tmp_path / "app"
    project_dir = _workarea(base) / "P"
    pasted = projects.change_document_bytes(
        [projects.address_entry(PATCH_ADDRESS, PATCH_BYTES)]
    ).decode("utf-8")
    addresses = [PATCH_ADDRESS + offset for offset in range(len(PATCH_BYTES))]
    dirty_marker = "●"

    async def _save_scene() -> tuple:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_load_file_through_dialog(pilot, app, src)
            await _at_paste_and_parse(pilot, app, pasted)
            border = _at_script_border(app)
            messages = await _at_save_project_through_dialog(pilot, app, log, "P")
            return border, messages

    async def _reopen_scene() -> tuple:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            panel = await _at_open_project_through_dialog(pilot, app, "P")
            await pilot.press("6")
            await projects.wait_for(
                pilot,
                lambda: len(app.query("#patch_doc_entries_table")) > 0
                and f"{PATCH_ADDRESS:08X}" in _at_ledger(app).upper(),
                "the reopened entry painted in the ledger",
            )
            image = {a: app.current_file.mem_map.get(a) for a in addresses}
            return panel, _at_ledger(app), _at_script_border(app), image, log.messages

    border_before, messages = asyncio.run(_save_scene())
    # Vacuity guard: before the save the pasted draft is unsaved work.
    assert dirty_marker in border_before, border_before
    assert any(m.startswith("Saved project to") for m in messages), messages
    landed = project_dir / "patches" / "changes.json"
    assert landed.is_file(), sorted(projects.tree_files(project_dir))
    assert [e["address"].upper() for e in _document_entries(landed)] == ["0X8000007C"]
    written = projects.read_manifest(project_dir)
    assert written.get("active_document") == "patches/changes.json", written
    saved_image = read_s19(project_dir / "firmware.s19").data
    # Save project folds the unapplied entry into the saved image (HLR-167,
    # "1 applied by this save"), so the byte leg below cannot by itself
    # tell a re-apply from none; the status-log leg (no apply outcome
    # painted by the reopen) is the one that bites. TC-B100-30
    # ``reopen_never_applies_the_entries`` holds the byte-differing case.
    assert [saved_image[a] for a in addresses] == list(PATCH_BYTES), messages

    panel, ledger, border, image, reopen_log = asyncio.run(_reopen_scene())
    flat = projects.flat(panel)
    assert "Opened    firmware.s19" in panel, panel
    for problem in ("missing", "not readable", "changed on disk", "not recorded"):
        assert problem not in flat, panel
    assert f"{PATCH_ADDRESS:08X}" in ledger.upper(), ledger
    assert re.search(r"\b1 entr", border), border
    assert dirty_marker not in border, border
    assert image == {a: saved_image[a] for a in addresses}, (image, reopen_log)
    assert any(
        m.startswith("Loaded project 'P' -> firmware.s19") and "0 problems" in m
        for m in reopen_log
    ), reopen_log
    assert not [m for m in reopen_log if "Apply:" in m or "applied" in m], reopen_log
