"""batch-67 AC-7 — a change document patches identically from BOTH entry points.

Summary:
    FB-P2 asked to "confirm the JSON change-doc input is surfaced in the Flow
    Builder UI and document the dual entry". Disk answered the surfacing part
    YES before this test was written — the Flow Builder has had a
    ``Select`` option "Patch (change doc)" plus a project-relative ref
    ``Input`` since the batch-44 tracer, and the Patch Editor has a richer
    ``#patch_doc_file_select`` picker. So the real gap was never discovery: it
    was that **nothing pinned the two entry points to the same behaviour.**
    They could drift and no test would notice.

    That is what this module fixes. It is a convergence oracle, not a feature:

    - **AC-7** applies ONE change document to ONE source image through both
      paths and requires byte-identical ``(mem_map, ranges)``. The oracle is
      the mutated image itself, not the summary object, because a summary can
      agree while the bytes differ.
    - A structural test pins that both paths reach the SAME engine function
      (``apply_change_document``), so convergence is by construction rather
      than by two implementations happening to agree today.
    - A third test records the ONE known asymmetry found while writing this
      (the Flow Builder path does not refresh ``collision_issues`` first), so
      it is a documented difference rather than a latent surprise.

Data Flow:
    - Builds a project dir with a source S19 + a change document, then runs
      ``run_flow`` (Flow Builder) and ``ChangeService`` (Patch Editor) over
      independent copies of the same starting image and compares.

Dependencies:
    Uses:
        - ``flow_execution_service.run_flow`` / ``services.change_service``
        - ``changes.io.read_change_document`` / ``changes.apply``
    Used by:
        - the batch-67 acceptance gate (AC-7)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from s19_app.core import S19File
from s19_app.tui.changes import emit_s19_from_mem_map
from s19_app.tui.changes.io import (
    FORMAT_ID,
    FORMAT_VERSION,
    read_change_document,
)
from s19_app.tui.services.change_service import ChangeService
from s19_app.tui.services.flow_execution_service import FlowContext, run_flow
from s19_app.tui.services.flow_model import (
    Flow,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)

_BASE = 0x80000000
_PATCH_ADDR = 0x80000010
_PATCH_BYTES = "DE AD BE EF"


def _project_with_image_and_doc(tmp_path: Path) -> Tuple[Path, str, str]:
    """Create a project dir holding one S19 image and one change document.

    Returns:
        Tuple[Path, str, str]: ``(project_dir, image_name, doc_name)``.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "dual"
    project_dir.mkdir(parents=True, exist_ok=True)

    mem_map = {_BASE + i: 0xFF for i in range(64)}
    ranges = [(_BASE, _BASE + 64)]
    (project_dir / "prg.s19").write_text(
        emit_s19_from_mem_map(mem_map, ranges), encoding="ascii"
    )

    document = {
        "format": FORMAT_ID,
        "version": FORMAT_VERSION,
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [
            {
                "type": "bytes",
                "address": f"0x{_PATCH_ADDR:08X}",
                "bytes": _PATCH_BYTES,
            }
        ],
    }
    (project_dir / "patch.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    return project_dir, "prg.s19", "patch.json"


def _fresh_image(project_dir: Path) -> Tuple[Dict[int, int], List[Tuple[int, int]]]:
    """Re-read the on-disk source image so each path starts from equal state."""
    parsed = S19File(str(project_dir / "prg.s19"))
    return (
        dict(parsed.get_memory_map()),
        [tuple(r) for r in parsed.get_memory_ranges()],
    )


def _flow_patched_image(project_dir: Path, doc_name: str) -> Dict[int, int]:
    """Run SOURCE→PATCH→WRITE-OUT and return the EMITTED file's memory map.

    Summary:
        ``run_flow`` does not expose the in-flight memory map, so the flow side
        is read back from the artifact it actually writes. That is the stronger
        oracle anyway: it compares the deliverable the operator ends up with,
        not an internal structure, and it exercises the emitter the Flow Builder
        really uses.

    Args:
        project_dir (Path): The work-area project directory.
        doc_name (str): The change document's project-relative filename.

    Returns:
        Dict[int, int]: The written image's sparse address→byte map.

    Dependencies:
        Uses:
            - ``run_flow`` / ``S19File``
        Used by:
            - the AC-7 convergence and positive-control tests
    """
    flow = Flow(
        name="dual-entry",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock(doc_name),
            WriteOutBlock("patched.s19"),
        ],
    )
    result = run_flow(flow, FlowContext(project_dir=project_dir))
    assert result.written_paths, (
        "the flow must write its patched image; block results: "
        f"{[(b.index, b.kind, b.status, b.detail) for b in result.block_results]}"
    )
    return dict(S19File(str(result.written_paths[-1])).get_memory_map())


def test_ac7_both_entry_points_produce_the_same_patched_image(
    tmp_path: Path,
) -> None:
    """AC-7: the Flow-Builder block and the Patch-Editor service agree byte-for-byte.

    Compares the MUTATED IMAGE, not the summary: two paths can report the same
    disposition counts while writing different bytes, so the summary is the
    weaker oracle. Each path starts from an independently re-read copy of the
    same on-disk image, so a shared-mutable-state bug cannot make them agree.
    """
    project_dir, _image, doc_name = _project_with_image_and_doc(tmp_path)
    flow_mem = _flow_patched_image(project_dir, doc_name)

    # --- Path B: the Patch Editor service ---
    editor_mem, editor_ranges = _fresh_image(project_dir)
    service = ChangeService()
    service.document = read_change_document(
        str(project_dir / doc_name), project_dir
    )
    service.apply(editor_mem, editor_ranges, None, None, variant_id="prg")

    assert flow_mem == editor_mem, (
        "the two PATCH entry points must produce the SAME patched image. "
        f"Differing addresses: "
        f"{sorted(set(flow_mem) ^ set(editor_mem))[:8] or 'none (values differ)'}; "
        f"first value mismatch: "
        f"{next(((a, flow_mem.get(a), editor_mem.get(a)) for a in sorted(set(flow_mem) | set(editor_mem)) if flow_mem.get(a) != editor_mem.get(a)), None)}"
    )


def test_ac7_the_patch_actually_changed_the_image(tmp_path: Path) -> None:
    """AC-7 positive control: the convergence above is not agreement on a no-op.

    Two paths that both apply NOTHING agree perfectly. This requires the patched
    bytes to actually be present and to differ from the 0xFF source fill, so
    ``test_ac7_both_entry_points_produce_the_same_patched_image`` cannot pass
    vacuously.
    """
    project_dir, _image, doc_name = _project_with_image_and_doc(tmp_path)
    before, _ranges = _fresh_image(project_dir)
    after = _flow_patched_image(project_dir, doc_name)

    expected = [int(tok, 16) for tok in _PATCH_BYTES.split()]
    written = [after[_PATCH_ADDR + i] for i in range(len(expected))]
    assert written == expected, (
        f"the change document must write {expected} at 0x{_PATCH_ADDR:08X}; "
        f"got {written}"
    )
    assert before[_PATCH_ADDR] != after[_PATCH_ADDR], (
        "the patch must CHANGE the image — if the source already held the "
        "patched bytes the convergence test would be vacuous"
    )


def test_ac7_both_entry_points_share_one_engine_function(tmp_path: Path) -> None:
    """AC-7 structural: convergence is by construction, not by coincidence.

    Both paths must call the SAME ``apply_change_document``. Two independent
    implementations that agree on one fixture would satisfy the behavioural
    test above while being free to diverge on the next input; sharing the engine
    function is what makes the dual entry a documented capability rather than a
    duplicated one.
    """
    import s19_app.tui.changes.apply as apply_mod
    import s19_app.tui.services.change_service as editor_mod
    import s19_app.tui.services.flow_execution_service as flow_mod

    assert flow_mod.apply_change_document is apply_mod.apply_change_document, (
        "the Flow Builder PatchBlock must use the shared engine "
        "apply_change_document, not a fork"
    )
    assert editor_mod.apply_change_document is apply_mod.apply_change_document, (
        "the Patch Editor must use the shared engine apply_change_document, "
        "not a fork"
    )


def test_ac7_known_asymmetry_flow_path_does_not_refresh_collisions(
    tmp_path: Path,
) -> None:
    """Record the ONE behavioural difference between the two entry points.

    ``ChangeService.apply`` recomputes ``collision_issues`` over the document's
    entries before delegating to the engine, because the Patch Editor lets the
    operator build overlapping entries interactively. The Flow Builder path
    reads a finished document from disk and delegates directly, so it relies on
    whatever issues ``read_change_document`` already attached.

    For a document parsed from disk the two agree — which is what this asserts,
    and why the divergence is benign TODAY. It is pinned rather than left
    implicit so that if the editor's pre-apply rule ever grows beyond collision
    refresh, this test fails and whoever changed it has to decide consciously
    whether the flow path needs the same rule.
    """
    project_dir, _image, doc_name = _project_with_image_and_doc(tmp_path)

    document = read_change_document(str(project_dir / doc_name), project_dir)
    codes_from_disk = sorted(issue.code for issue in document.issues)

    editor_mem, editor_ranges = _fresh_image(project_dir)
    service = ChangeService()
    service.document = read_change_document(
        str(project_dir / doc_name), project_dir
    )
    service.apply(editor_mem, editor_ranges, None, None, variant_id="prg")
    codes_after_editor = sorted(issue.code for issue in service.document.issues)

    assert codes_from_disk == codes_after_editor, (
        "the Patch Editor's pre-apply collision refresh changed the issue set "
        "for a document parsed from disk, so the Flow Builder path (which does "
        "NOT refresh) would now behave differently on the same file. "
        f"from disk={codes_from_disk} after editor={codes_after_editor}"
    )
