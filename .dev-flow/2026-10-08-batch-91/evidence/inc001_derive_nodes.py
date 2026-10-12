"""batch-91 inc-001 — derive the registry `nodes` for TC-617..TC-648.

Derives with the shared library's machinery, never by hand: same ast.walk over
FunctionDef/AsyncFunctionDef/ClassDef as tools/id_registry.py's
derive_named_nodes, same repo-relative posix `file::name` rendering. A node
that does not exist on disk is a lie, so every emitted name is checked against
defined_names() — the guard's own existence oracle.
"""
import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.id_registry import defined_names, read_text, repo_root

ROOT = repo_root(Path(__file__))

# TC -> adopting modules (from 01-requirements.md LLR-122.1..122.5).
ADOPTION = {
    "TC-617": ["test_core_srecord_validation"],
    "TC-618": ["test_hexfile"],
    "TC-619": ["test_hex_emit"],
    "TC-620": ["test_range_index"],
    "TC-621": ["test_address_census", "test_address_origin"],
    "TC-622": ["test_a2l_enriched"],
    "TC-623": ["test_a2l_missing_length_fix"],
    "TC-624": ["test_a2l_record_layout_length"],
    "TC-625": ["test_tui_a2l"],
    "TC-626": ["test_validation_a2l"],
    "TC-627": ["test_tui_mac"],
    "TC-628": ["test_validation_mac"],
    "TC-629": ["test_crc_kernel"],
    "TC-630": ["test_crc_designer_model", "test_crc_template_loader", "test_crc_word_codec"],
    "TC-631": ["test_unload_feature"],
    "TC-632": ["test_undo_redo_ux"],
    "TC-633": ["test_universal_paste"],
    "TC-634": ["test_capped_text_area"],
    "TC-635": ["test_discoverability"],
    "TC-636": ["test_filename_markup_safety"],
    "TC-637": ["test_tui_hostile_map"],
    "TC-638": ["test_tui_helpers", "test_tui_services"],
    "TC-639": ["test_map_click_chain"],
    "TC-640": ["test_memmap_entropy_merge"],
    "TC-641": ["test_patch_dual_entry"],
    "TC-642": ["test_flow_execution", "test_flow_multi_image_ui"],
    "TC-643": ["test_legend_n8", "test_legend_scope_and_logwidth"],
    "TC-644": ["test_report_logging", "test_report_progress", "test_report_off_ui_thread"],
    "TC-645": ["test_workspace_variants"],
    "TC-646": ["test_tui_evidence_packs", "test_examples_pilot_gifs"],
    "TC-647": ["test_sync_evidence"],
    "TC-648": ["test_cli"],
}

out = {}
for tc, modules in sorted(ADOPTION.items()):
    nodes = set()
    for mod in modules:
        path = ROOT / "tests" / f"{mod}.py"
        assert path.is_file(), f"{path} missing"
        source = read_text(path)
        tree = ast.parse(source)
        rel = path.relative_to(ROOT).as_posix()
        module_nodes = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                module_nodes.add(f"{rel}::{node.name}")
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                module_nodes.add(f"{rel}::{node.name}")
        # Truth check against the guard's own oracle, per module.
        defined = defined_names(source)
        for ref in module_nodes:
            name = ref.split("::", 1)[1]
            assert name in defined, f"{ref} not defined on disk"
        nodes |= module_nodes
    assert nodes, f"{tc}: no test nodes derived"
    out[tc] = sorted(nodes)

dest = Path(__file__).with_name("inc001_nodes.json")
dest.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
for tc, nodes in sorted(out.items()):
    print(f"{tc}: {len(nodes)} node(s) across {len(ADOPTION[tc])} module(s)")
print("total nodes:", sum(len(v) for v in out.values()))
