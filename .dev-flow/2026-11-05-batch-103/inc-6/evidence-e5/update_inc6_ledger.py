from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "02-test-cases.md"
GREEN = ROOT.parent / "evidence" / "inc-6" / "final-functional-green.txt"
assert "77 passed" in GREEN.read_text(encoding="utf-8"), "final 77-case GREEN is required"

MODEL = "tests/test_b103_picker_model.py"
EDITOR = "tests/test_b103_picker_editor.py"
NODES = {
    "001": (MODEL, "test_r001_declared_length_is_the_only_size_source"),
    "002": (MODEL, "test_r002_real_a2l_shapes_report_whole_object_length"),
    "003": (MODEL, "test_r003_element_datatype_and_unit_paint_exactly"),
    "004": (MODEL, "test_r004_reader_refusals_keep_length_missing"),
    "005": (MODEL, "test_r005_use_parameter_refuses_missing_length_without_reads"),
    "006": (EDITOR, "test_r006_use_transfers_whole_object"),
    "007": (EDITOR, "test_r007_unavailable_bytes_are_all_or_nothing"),
    "008": (EDITOR, "test_r008_declared_length_observes_decode_cap"),
    "009": (EDITOR, "test_r009_check_spec_matches_address_and_full_length"),
    "010": (EDITOR, "test_r010_new_generation_keeps_or_demotes_full_spec"),
    "011": (EDITOR, "test_r011_patch_pick_controls_and_id_isolation"),
    "012": (EDITOR, "test_r012_patch_add_list_opens_shared_modal"),
    "013": (EDITOR, "test_r013_r014_patch_bulk_counts_and_exact_summaries"),
    "014": (EDITOR, "test_r013_r014_patch_bulk_counts_and_exact_summaries"),
    "015": (EDITOR, "test_r015_patch_bulk_close_preserves_ledger_and_document"),
    "016": (EDITOR, "test_r016_use_after_bulk_transfers_only_highlight"),
    "018": (MODEL, None),
    "019": (MODEL, None),
    "020": (EDITOR, "test_r020_patch_surfaces_fit_real_terminal_regions"),
    "021": (EDITOR, "test_r021_check_validate_write_refuses_missing_length"),
}

lines = LEDGER.read_text(encoding="utf-8").splitlines()
out = []
seen = []
for line in lines:
    match = re.match(r"\| (R-PICKER-CORRECT\.(\d{3})/(\d+)) \|", line)
    if not match:
        out.append(line)
        continue
    case, requirement, number = match.groups()
    if requirement == "017":
        node = f"{MODEL}::test_r017_{number}_" + {
            "1": "hostile_parameter_name_is_replaced_literally",
            "2": "hostile_unit_is_replaced_literally",
            "3": "long_hostile_unit_clips_on_both_surfaces_at_80_and_118",
        }[number]
    elif requirement == "018":
        node = f"{MODEL}::test_r018_{number}_" + {
            "1": "equal_signature_is_a_zero_describe_noop",
            "2": "changed_generation_batches_once_per_picker",
            "3": "none_always_repopulates_with_real_a2l_data",
            "4": "live_reload_refreshes_both_without_reentry",
        }[number]
    elif requirement == "019":
        node = f"{MODEL}::test_r019_{number}_" + {
            "1": "13990_object_population_has_one_timed_batch_per_generation",
            "2": "twenty_filter_page_rebuilds_never_describe",
        }[number]
    else:
        module, function = NODES[requirement]
        node = f"{module}::{function}"
    cells = [cell.strip() for cell in line.strip("|").split("|")]
    assert len(cells) == 9, (case, len(cells))
    cells[6] = f"`{node}` ({'partial' if requirement == '021' else 'full'})"
    cells[7] = "partial" if requirement == "021" else "covered"
    cells[8] = "verified — ../evidence/inc-6/final-functional-green.txt"
    out.append("| " + " | ".join(cells) + " |")
    seen.append(case)
assert len(seen) == 77 and len(set(seen)) == 77, len(seen)
text = "\n".join(out) + "\n"
text = text.replace(
    "Tests entries are unassigned, coverage `gap`, results `not_run`.",
    "75 `full`, 2 `partial`; coverage **75 `covered`, 2 `partial`, 0 `conflict`**, 0 `gap`, 0 `not-testable`; results **77 `verified`**, 0 `not_run`.",
)
text = text.replace(
    "77 Tests entries, all `full`; coverage **77 `covered`, 0 `partial`, 0 `conflict`**, 0 `gap`, 0 `not-testable`; results **77 `verified`**, 0 `not_run`.",
    "75 `full`, 2 `partial`; coverage **75 `covered`, 2 `partial`, 0 `conflict`**, 0 `gap`, 0 `not-testable`; results **77 `verified`**, 0 `not_run`.",
)
if ".021 is `partial`" not in text:
    text += "- .021 is `partial`: the real Check button handler, exact status, zero actions/reads/writes and preservation of the other included field are verified synchronously; repeated mounted `run_test` attempts stalled before completion, so the mounted acceptance route is not claimed.\n"
LEDGER.write_text(text, encoding="utf-8", newline="\n")
print(f"cases_verified={len(seen)}")
