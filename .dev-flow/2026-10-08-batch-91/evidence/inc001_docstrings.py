"""batch-91 inc-001 — insert the adoption docstring tokens into the 41 modules.

Discipline: docstring/comment lines ONLY. Every edit is verified before write:
  * the new text still ast.parses and the module docstring carries the TC token;
  * difflib shows additions only (the single allowed exception is
    test_a2l_enriched.py, whose one-line docstring is expanded to multi-line —
    exactly one modified line, still inside the docstring);
  * the only AT/TC token the block introduces is the module's own TC id
    (checked with tools/id_registry.py's TOKEN_RE via iter_tokens).
"""
import ast
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.id_registry import iter_tokens

ROOT = Path(__file__).resolve().parents[3]

# module -> (TC id, one-line mapping). From 01-requirements.md LLR-122.1..122.5.
BLOCKS = {
    "test_core_srecord_validation": ("TC-617", "this module pins the S-record parser's per-record checksum validation with overlap and out-of-order detection (LLR-122.1)."),
    "test_hexfile": ("TC-618", "this module pins the Intel HEX parser: record types 00-05 with checksums and the memory map (LLR-122.1)."),
    "test_hex_emit": ("TC-619", "this module pins the emitters round-tripping a parsed image back to records (LLR-122.1)."),
    "test_range_index": ("TC-620", "this module pins the range index answering membership in sorted ranges (LLR-122.1)."),
    "test_address_census": ("TC-621", "this module pins the contiguous-range/gap computation over parsed addresses (LLR-122.1)."),
    "test_address_origin": ("TC-621", "this module pins the contiguous-range/gap computation over parsed addresses (LLR-122.1)."),
    "test_a2l_enriched": ("TC-622", "this module pins the A2L engine's enrichment of raw and physical values via datatype/COMPU_METHOD (LLR-122.2)."),
    "test_a2l_missing_length_fix": ("TC-623", "this module pins the A2L engine's ASAP2 parse with missing-length records handled (LLR-122.2)."),
    "test_a2l_record_layout_length": ("TC-624", "this module pins the A2L engine's record-layout length handling (LLR-122.2)."),
    "test_tui_a2l": ("TC-625", "this module pins the A2L engine's tag extraction behind the TUI viewer (LLR-122.2)."),
    "test_validation_a2l": ("TC-626", "this module pins the A2L engine's internal structure validation (LLR-122.2)."),
    "test_tui_mac": ("TC-627", "this module pins the MAC parser's TAG=hexaddr reading behind the MAC View (LLR-122.3)."),
    "test_validation_mac": ("TC-628", "this module pins the MAC parser's collect-don't-abort diagnostics: malformed lines kept and flagged (LLR-122.3)."),
    "test_crc_kernel": ("TC-629", "this module pins the parameterized Rocksoft CRC kernel, width 8-64, with its catalogue presets (LLR-122.4)."),
    "test_crc_designer_model": ("TC-630", "this module pins the CRC designer model behind the catalogue presets (LLR-122.4)."),
    "test_crc_template_loader": ("TC-630", "this module pins the collect-don't-abort loader for *.crc.json templates (LLR-122.4)."),
    "test_crc_word_codec": ("TC-630", "this module pins the check-word encode/decode per its store width and endianness (LLR-122.4)."),
    "test_unload_feature": ("TC-631", "this module pins the unload (U) host-surface behavior (LLR-122.5)."),
    "test_undo_redo_ux": ("TC-632", "this module pins the undo/redo UX (LLR-122.5)."),
    "test_universal_paste": ("TC-633", "this module pins the universal paste behavior (LLR-122.5)."),
    "test_capped_text_area": ("TC-634", "this module pins the capped text area (LLR-122.5)."),
    "test_discoverability": ("TC-635", "this module pins the host-surface discoverability arms (LLR-122.5)."),
    "test_filename_markup_safety": ("TC-636", "this module pins filename markup safety (LLR-122.5)."),
    "test_tui_hostile_map": ("TC-637", "this module pins the hostile map arms (LLR-122.5)."),
    "test_tui_helpers": ("TC-638", "this module pins the tui helpers/services seams (LLR-122.5)."),
    "test_tui_services": ("TC-638", "this module pins the tui helpers/services seams (LLR-122.5)."),
    "test_map_click_chain": ("TC-639", "this module pins the map click chain (LLR-122.5)."),
    "test_memmap_entropy_merge": ("TC-640", "this module pins the memory-map entropy merge (LLR-122.5)."),
    "test_patch_dual_entry": ("TC-641", "this module pins the patch dual entry (LLR-122.5)."),
    "test_flow_execution": ("TC-642", "this module pins the flow execution and multi-image UI arms (LLR-122.5)."),
    "test_flow_multi_image_ui": ("TC-642", "this module pins the flow execution and multi-image UI arms (LLR-122.5)."),
    "test_legend_n8": ("TC-643", "this module pins the N8 legend and logwidth scope (LLR-122.5)."),
    "test_legend_scope_and_logwidth": ("TC-643", "this module pins the N8 legend and logwidth scope (LLR-122.5)."),
    "test_report_logging": ("TC-644", "this module pins the report logging/progress/off-thread behaviors (LLR-122.5)."),
    "test_report_progress": ("TC-644", "this module pins the report logging/progress/off-thread behaviors (LLR-122.5)."),
    "test_report_off_ui_thread": ("TC-644", "this module pins the report logging/progress/off-thread behaviors (LLR-122.5)."),
    "test_workspace_variants": ("TC-645", "this module pins the workspace variants (LLR-122.5)."),
    "test_tui_evidence_packs": ("TC-646", "this module pins the evidence packs and the pilot GIFs example (LLR-122.5)."),
    "test_examples_pilot_gifs": ("TC-646", "this module pins the evidence packs and the pilot GIFs example (LLR-122.5)."),
    "test_sync_evidence": ("TC-647", "this module pins the sync-evidence tooling (LLR-122.5)."),
    "test_cli": ("TC-648", "this module pins the command-line entry behavior (LLR-122.5)."),
}

#: Purpose lines for the ten modules that ship no module docstring — one is
#: prepended so the token lives in a docstring there too.
PURPOSE = {
    "test_core_srecord_validation": "Tests for the S-record parser's validation arms.",
    "test_hexfile": "Tests for the Intel HEX parser.",
    "test_range_index": "Tests for the sorted-range membership index.",
    "test_tui_a2l": "Tests for the TUI A2L viewer surface over the engine.",
    "test_validation_a2l": "Tests for the A2L structure validator.",
    "test_tui_mac": "Tests for the TUI MAC view over the MAC parser.",
    "test_validation_mac": "Tests for the MAC validation diagnostics.",
    "test_tui_helpers": "Tests for the TUI helpers seam.",
    "test_tui_services": "Tests for the TUI services seam.",
    "test_cli": "Tests for the command-line entry.",
}


def block_lines(tc: str, mapping: str) -> list:
    return ["", "Batch-91 contract adoption (HLR-122):", f"# {tc} \u2014 {mapping}"]


def main() -> None:
    for mod, (tc, mapping) in sorted(BLOCKS.items()):
        path = ROOT / "tests" / f"{mod}.py"
        original = path.read_text(encoding="utf-8")
        if tc in original:
            print(f"SKIP {mod}: {tc} already present")
            continue
        lines = original.splitlines()
        tree = ast.parse(original)
        first = tree.body[0]
        is_doc = (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        )
        block = block_lines(tc, mapping)
        if not is_doc:
            new_lines = [f'"""{PURPOSE[mod]}', "" , "Batch-91 contract adoption (HLR-122):",
                         f"# {tc} \u2014 {mapping}", '"""', ""] + lines
        elif first.lineno == first.end_lineno:
            # Single-line docstring: expand it (the one allowed line edit).
            single = lines[0]
            assert single.startswith('"""') and single.endswith('"""') and len(single) > 6, single
            new_lines = [single[:-3]] + block + ['"""'] + lines[1:]
        else:
            closing = first.end_lineno - 1  # 0-based index of the closing quotes line
            assert lines[closing].strip() == '"""', (mod, lines[closing])
            new_lines = lines[:closing] + block + lines[closing:]
        new_text = "\n".join(new_lines) + ("\n" if original.endswith("\n") else "")

        # Verify: parses, docstring carries the token, only the intended token added.
        new_tree = ast.parse(new_text)
        doc = ast.get_docstring(new_tree)
        assert doc and tc in doc, f"{mod}: token not in docstring"
        old_tokens = {t.raw for t, _ in iter_tokens(original)}
        new_tokens = {t.raw for t, _ in iter_tokens(new_text)}
        assert new_tokens - old_tokens == {tc}, (mod, new_tokens - old_tokens)

        # Verify: additions only (except the single-line docstring expansion).
        diff = list(difflib.unified_diff(lines, new_text.splitlines(), lineterm=""))
        removed = [d for d in diff if d.startswith("-") and not d.startswith("---")]
        if is_doc and first.lineno == first.end_lineno:
            assert len(removed) == 1 and removed[0] == "-" + lines[0], (mod, removed)
        else:
            assert not removed, (mod, removed[:3])

        path.write_text(new_text, encoding="utf-8")
        print(f"OK {mod}: {tc}")


if __name__ == "__main__":
    main()
