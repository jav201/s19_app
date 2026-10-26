"""Workarea content dedup on re-load (batch-96 bug B8, TC-1800).

``copy_into_workarea`` used to dedup collisions by NAME only: loading the
same file twice left ``fw.s19`` + ``fw_1.s19`` byte-identical copies under
the workarea. The fix ports the project gather's byte-compare idiom
(``project_gather_service._gather_copy``): a colliding target whose bytes
match the source is returned as-is — no extra copy; a colliding target
with divergent bytes keeps the ``_<N>`` name-dedup suffix.

Coverage map (test -> TC):

- TC-1800 (B8) — ``test_tc1800_reload_same_content_reuses_existing_target``:
  loading the same file twice returns the same path and leaves exactly one
  file on disk (bytes identical, no ``_1``).
- TC-1800 (B8, name-dedup regression) —
  ``test_tc1800_same_name_divergent_content_suffixes``: two same-named
  files with different content still land as ``fw.s19`` + ``fw_1.s19``.

Harness: pure service calls — ``copy_into_workarea`` is a workspace helper
with no TUI surface (same containment destination idiom as
``tests/test_tui_helpers.py::test_copy_into_workarea_creates_unique_names``).
"""
from __future__ import annotations

from pathlib import Path

from s19_app.tui.workspace import copy_into_workarea


def _workarea(tmp_path: Path) -> Path:
    # Destination must resolve under <base>/.s19tool/workarea/ per LLR-005.3.
    return tmp_path / ".s19tool" / "workarea" / "temp"


def test_tc1800_reload_same_content_reuses_existing_target(tmp_path: Path) -> None:
    workarea = _workarea(tmp_path)
    source = tmp_path / "fw.s19"
    source.write_bytes(b"S113000048656C6C6F0A")

    first = copy_into_workarea(source, workarea)
    second = copy_into_workarea(source, workarea)

    assert second == first, "a byte-identical re-load must reuse the existing target"
    assert first.name == "fw.s19"
    on_disk = sorted(p.name for p in workarea.iterdir())
    assert on_disk == [".staging", "fw.s19"], (
        f"re-loading identical content must not duplicate: {on_disk}"
    )
    # HLR-155 (LLR-155.1): the private-staging HOME under temp/ persists;
    # every per-write mkdtemp directory below it is removed.
    assert list((workarea / ".staging").iterdir()) == []
    assert first.read_bytes() == source.read_bytes()


def test_tc1800_same_name_divergent_content_suffixes(tmp_path: Path) -> None:
    workarea = _workarea(tmp_path)
    first_source = tmp_path / "fw.s19"
    first_source.write_bytes(b"S1130000414141410A")
    second_source = tmp_path / "incoming" / "fw.s19"
    second_source.parent.mkdir(parents=True)
    second_source.write_bytes(b"S1130000424242420A")

    first = copy_into_workarea(first_source, workarea)
    second = copy_into_workarea(second_source, workarea)

    assert first.name == "fw.s19"
    assert second.name == "fw_1.s19", "divergent content keeps the _<N> name-dedup suffix"
    assert first.read_bytes() == first_source.read_bytes()
    assert second.read_bytes() == second_source.read_bytes()
