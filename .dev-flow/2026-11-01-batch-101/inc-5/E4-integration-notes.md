# Inc 5 — E4 integration notes

Batch 2026-11-01-batch-101, increment 5, design-first flow (`dev-flow-v3-beta`, E4 integration step). Integrator: Opus. Base `c2cba35`; branch `b101-inc5`; integrated head = this commit. Inputs: implementation `fa9c24f` (DeepSeek v4 Pro, units A and B), independent tests `2b11db5` (Sonnet ×2). Runs: LAN Linux host 2 only (operator rule), detached worktree `<HOME>/work/s19_i5int` at `c2cba35` with the increment diff applied and staged; the index tree printed at the top of every transcript equals the local tree of the integrated change. Nothing that imports `s19_app` ran on the Windows PC.

## 1. Verdict

**GREEN for the right reasons.** Every node of the two new test files (10 designer, 26 Check Editor) and the re-pinned `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` pass on the integrated tree on the first run (int-01: 58 passed), and the same nodes were RED on base for behavioural reasons (`red-01-tester1-base.txt`: 8 failed, 2 standing guards; `red-01-tester2-base.txt`: 21 failed, 6 declared standing guards). The QC-BC set, every other importer of `screens_directionb` or `crc_designer_view`, the law guards and the `serial_timing` nodes pass, except 4 nodes that fail identically on base `c2cba35` (the batch's known failures, §4). All 34 test cases are `covered` and `verified (linux, int-01)` in `02-test-cases.md`.

## 2. Review of the implementation against the graph

Each slice node was read against its `func:` (was / now) in `codewire/graph-inc5.md`; no deviation:

- G1 `app.py`: `_note_image_bytes_written` queries the panel inside the `try` only and delegates outside it; the apply hook sits after the `try`/`except`, keyed on `event.action == "apply_doc"`, not gated on `applied > 0`; the save-back hook runs right after `save_patched` returns, before `_report_change_result`, whatever `result.ok`; the project-save hook sits inside `if request.image is not None:` after `adopt_rederived`; the spec-pick items carry `expected` and `symbol` (I-3); `_check_items_to_document` takes a tuple of exactly `size` bytes without reading the image and otherwise keeps the base path.
- G2 `crc_designer_view.py`: `note_image_bytes_written` is the one-statement public delegate to `_on_image_changed` (I-1).
- G3 `screens_directionb.py`: the ten nodes match, including `kept` captured before the no-op check, the demotion at the spec entry's own address, size and bytes in `kept` order, the prune keyed on the current picks and the range, `_named_parameter` returning `None` with no address fallback when a listed symbol's range differs (E3 A-6), and the `(address, size)` range test in `_collected_items`.
- Guide `ch10-check-editor.md` §10.6–§10.8: states `E1-rulings.md` §1 (5)–(7). The F-01 sentence at the end of §10.8 ("A spec with `symbol` entries … is refused") is stale since Inc 4 and contradicts R-CHKED-041.2/2; it stays because Inc 14's ruling D-8 routes it (with ch08 §8.2, ch17 and the DOSSIER F-01 row) to the batch-end doc pass.

Observation, not a finding: if `ChangeService.save_patched` raised after it adopted the re-derived bytes, the save-back hook would not run. The graph places the hook "after `save_patched` returns" and no case covers a raise there; left to E5's reviewers.

## 3. Decisions taken at integration

- **I-D1 — no product change.** The code implements the approved graph and every test agrees with it on the first run; there was no code bug to fix.
- **I-D2 — no test change.** No test disagreed with the code or with a requirement. The testers' strengthenings (positive controls in 041.3/3, /4, /6; the included pair in 041.3/2; an inside-image control row in 027/1; limbs (a) and (b) of 002.1/6) only add assertions.
- **I-D3 — 002.5/8 drive accepted; wording finding recorded, not a requirement defect.** The case says "the entry's address edited to `0x9000`"; the product's entry editor finds an entry by its address and rebuilds only its content, and a file-backed document disables JSON edit, so the only product route is Remove of `0x8003` and Add of `0x9000` = `AA` in the same document. The state the response depends on (the document holds one entry outside the image; the earlier apply is in the journal) and every expected result are the requirement's. The shall-statement of R-CRC-PREVIEW-002.5 is unchanged; only the threshold's precondition wording should read "the `0x8003` entry removed and a `0x9000` entry added" at the canon fold. Not edited here.
- **I-D4 — `EXPECTED_SCANNED_TEST_FILES` 262 → 264**, measured by the guard itself (int-06: `test_id_registry.py` passes at 264; two new modules, no support module).
- **I-D5 — R-CHKED-041.3/5 marked `partial`** in `02-test-cases.md` (E3 Round-2 NOTE: a pick cannot reach two entries naming one parameter; the items go through `CheckEditorPanel.load_spec`). R-CHKED-041.3/6 and R-CRC-PREVIEW-002.5/6 were already `partial`.
- **I-D6 — QC-BC set.** Grep of `tests/` for the observables this increment changed: the Check Editor (`CheckEditorPanel`, `load_spec`, `check_mem_table`, written `.chk.json`, `Checks:` status, Fields head lines, `memory row`), the in-place write sites (`apply_doc`, `save_patched`, `SaveBackDecision`, `ctrl+s`, `_on_project_saved`), the CRC Designer (`CrcDesignerPanel`, `CRC_RECOMPUTE_S`) and readers of the user guide (`ch10`, `user-guide`): 68 files; kept the 51 that build the app or import the changed modules. The 17 left out exercise service code this increment does not change (`test_change_service`, `test_changes_apply`, `test_flow_execution*`, the `test_report_*` modules, `test_synth_release_case`, `test_changes_file_notation_help`, `test_flow_a2b_b94`) or are the new files and the registry (run in int-01 and int-06). The importer run (int-04) is the 24 importers not already in int-01 or int-02.
- **I-D7 — records.** `02-test-cases.md`: the header names the two files the orchestrator split **N** into, the 002.1/6 tests cell names both limbs, Coverage and Result set from int-01.

## 4. Runs (LAN Linux host 2, Python 3.11.18, `-n 8 -m "not serial_timing"` unless stated)

Every transcript starts with the base commit, the index tree with the increment staged (`10e1b162…` = the local tree of the code and tests committed here; the records written after the runs are the only difference) and `s19_app.__file__` = the detached worktree.

| Run | Scope | Result | Evidence |
|---|---|---|---|
| int-01 | `test_b101_designer_writes.py`, `test_b101_check_spec_keep.py`, `test_b101_symbol_reads.py` | **58 passed** (5:54) | `../evidence/inc-5/int-01.txt` |
| int-02 | QC-BC set, 51 files (I-D6) | 2 failed, **2428 passed**, 107 skipped, 1 xfailed (40:35); the 2 failures are known (int-03) | `../evidence/inc-5/int-02.txt` |
| int-03 | the 2 int-02 failures on base `c2cba35` (separate detached worktree, nothing applied; removed after) | 2 failed, same assertions (`test_at_b78_03…` palette freeze: unexpected `a2l_describe_tag`, `confirm_attention`; `test_at_056e…`: baseline wrote `[]`) | `../evidence/inc-5/int-03.txt` |
| int-04 | the 24 other importers of `screens_directionb` / `crc_designer_view` | 2 failed, **488 passed** (3:35); the 2 failures are known (int-05) | `../evidence/inc-5/int-04.txt` |
| int-05 | the 2 int-04 failures on base `c2cba35` | 2 failed, same (`test_tc016s_density_layout_snapshot[patch-comfortable-80x24]`, `[…-120x30]`) | `../evidence/inc-5/int-05.txt` |
| int-06 | law guards: `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_requirements_canon`, `test_docs_canon`, `test_filename_markup_safety`, `test_import_census` (`test_tui_directionb` with its `test_tc031_*` engine-freeze nodes ran in int-02) | **117 passed** | `../evidence/inc-5/int-06.txt` |
| int-07 | `-m serial_timing`, serial, over all 85 files of int-01, int-02, int-04, int-06 | **58 passed**, 2 skipped, 3201 deselected; `QC-TM: 84 bounds, 0 under 20 % margin` | `../evidence/inc-5/int-07.txt` |
| int-08 | `-rs` on the slice's closest modules (the 3 of int-01, `test_tui_check_editor`, `test_b97_check_editor`, `test_b102_parameter_picker`, `test_b102_bulk_add`, `test_b102_patch_picker`, `test_crc_designer_view`, `test_b101_designer_recompute`, `test_tui_patch_editor_v2`, `test_b97_patch_editor`, `test_b100_save_image`) | **399 passed**, 4 skipped, all Windows-only arms (`msvcrt` byte-range lock; directory junctions) | `../evidence/inc-5/int-08.txt` |
| int-09 | `-m serial_timing -rs`, serial, the 9 files whose timing nodes carry a skip condition | **52 passed**, 2 skipped: the Windows-only junction arm — the 2 skips of int-07 | `../evidence/inc-5/int-09.txt` |

Known failures (4, identical on base, all on the batch's known list in `HANDOFF-2026-11-06.md`): `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`, `test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` and `[patch-comfortable-120x30]`.

Not run: the full suite (batch end); Windows (operator rule: nothing importing `s19_app` on the Windows PC); the mutant table (E5). The remote worktree `<HOME>/work/s19_i5int` and the `i5int-*` helpers were removed after the runs.

## 5. Changes made at integration, per file

| File | Change |
|---|---|
| `tests/test_id_registry.py` | `EXPECTED_SCANNED_TEST_FILES` 262 → 264, with its history comment (I-D4) |
| `.dev-flow/2026-11-01-batch-101/inc-5/02-test-cases.md` | header note on the file split; 002.1/6 tests cell; 041.3/5 `partial`; Coverage `covered`, Result `verified (linux, int-01)` on all 34 cases (I-D5, I-D7) |
| `.dev-flow/2026-11-01-batch-101/inc-5/E4-integration-notes.md` | this record |
| `.dev-flow/2026-11-01-batch-101/inc-5/steps.log` | E4 integration line |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-01.txt` … `int-09.txt` | transcripts; home paths and account names redacted |

No source file and no test body changed. Source files of the increment: 3 of the cap of 4 (`app.py`, `crc_designer_view.py`, `screens_directionb.py`).

## Mutant table for E5

Run in a copy of the tree (never this worktree), one mutant at a time, over `tests/test_b101_designer_writes.py` (**D**), `tests/test_b101_check_spec_keep.py` (**C**) and `tests/test_b101_symbol_reads.py` (**S**). Expected = the nodes that must turn RED; a mutant that stays GREEN is a finding. Sources: the Negative-control column of `01-requirements.md` (E1, E3), `02-test-cases.md` footer, and the E4 addenda of `E1-rulings.md` §6 and `E3-rulings.md` Round 2.

| # | Source | Mutation (file · function) | Expected RED |
|---|---|---|---|
| M1 | 002.5 hook absent (apply site) | `app.py` `on_patch_editor_panel_action_requested`: delete the `if event.action == "apply_doc": self._note_image_bytes_written()` block | D 002_5_3, 002_5_6, 002_5_8 |
| M2 | 002.5 hook absent (save-back site) | `app.py` `on_patch_editor_panel_save_back_decision`: delete `self._note_image_bytes_written()` | D 002_5_4, 002_5_7 |
| M3 | 002.1/6, 002.5 hook absent (project-save site) | `app.py` `_on_project_saved`: delete `self._note_image_bytes_written()` | D 002_5_5, 002_1_6 (both limbs) |
| M4 | 002.5 hook recomputing while hidden | `crc_designer_view.py` `note_image_bytes_written`: `self._schedule_recompute()` instead of `self._on_image_changed()` | D 002_5_3 … 002_5_8 ("a hidden CRC Designer recomputed": 1 recompute before key `0`) |
| M5 | 002.5/6 hook in the success branch only | `app.py`: move the apply hook inside the `apply_doc` arm, after `set_status(f"Apply: …")` (inside the `try`) | D 002_5_6 |
| M6 | **addendum 2a**, E3 SEC5-2: save-back hook under `result.ok` | `app.py` `on_patch_editor_panel_save_back_decision`: move the call into `if result.ok:` | D 002_5_7 |
| M7 | **addendum 2b**, E3 A-2: apply hook under `applied > 0` | `app.py`: move the apply hook into the arm's `if counts["applied"] > 0 and loaded is not None:` (or wrap it in `if counts["applied"] > 0:`) | D 002_5_8 |
| M8 | R-CHKED-010 picks cleared on a repopulation (base) | `screens_directionb.py` `set_a2l_parameters`: delete `self._picker.include_names(kept)` | C 010_2, 010_3, 026_4; also 055_1, 025_3 setups (picks `[]`) |
| M9 | R-CHKED-055 every earlier name kept without the new ledger | `set_a2l_parameters`: replace `self._picker.include_names(kept)` by `self._picker._picked_params.extend(n for n in kept if n not in self._picker._picked_params)` | C 055_1 (`unresolved` line, head `3 fields: 2 params · 1 memory row`) |
| M10 | R-CHKED-054 post-Write refresh clears the picks | `app.py` Write arm (`self._prefill_check_editor()` after a write, `:7416`): call `panel._picker.clear_picks()` first. Note: E1's literal form (the refresh repopulating with no signature) is **equivalent after Inc 5** — a repopulation now re-includes the picks (R-CHKED-010) — expected to survive; M10 is the effective control | C 054_1 |
| M11 | R-CHKED-041.1 earlier fields kept | `load_spec`: delete `self._picker.clear_picks()` and `self._memory_rows = []` | C 041_1 |
| M12 | R-CHKED-041.1 an entry dropped | `load_spec`: skip the last item (`items = list(items)[:-1]`) | C 041_1, 041_2_1 |
| M13 | R-CHKED-041.2 resolution removed (base) | `load_spec`: `name = None` | C 041_2_1, 041_2_3, 026_4, 056_*; S `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` |
| M14 | R-CHKED-041.2 symbol ignored | `_named_parameter`: delete the symbol branch | C 041_2_3 (twin → memory row) |
| M15 | R-CHKED-041.2/.3 size ignored (address only) | `load_spec`: key `by_key` and the lookup by address only | C 041_3_3 |
| M16 | R-CHKED-041.3/4 first match on an ambiguity | `_named_parameter`: `if names and names[0] not in taken: return names[0]` | C 041_3_4 |
| M17 | R-CHKED-041.3/5 duplicate included twice / dropped | `_named_parameter`: drop the `not in taken` test (address branch) | C 041_3_5 |
| M18 | R-CHKED-041.3/6 symbol range mismatch falls back to the address rule (E3 A-6) | `_named_parameter`: replace `return None` after the symbol range test by falling through to the address rule | C 041_3_6 |
| M19 | R-CHKED-025/2 spec bytes never pruned on a toggle | `_on_a2l_parameter_picker_selection_changed`: delete `self._prune_spec_bytes()` | C 025_2 |
| M20 | R-CHKED-026 expected bytes re-read from the image (base) | `app.py` `_check_items_to_document`: delete the `spec_expected` branch | C 026_1, 026_2, 026_3, 026_4, 027_2 |
| M21 | R-CHKED-026/4 spec bytes dropped on every repopulation | `set_a2l_parameters`: `self._spec_bytes = {}` right after `set_parameters` | C 026_4 |
| M22 | R-CHKED-056/2 R-CHKED-055's drop applied to a spec field | `_demote_moved_spec_params`: delete the `self._memory_rows.append(…)` | C 056_1, 056_2, 056_3 |
| M23 | R-CHKED-056/3 byte count left out of the key | `_demote_moved_spec_params`, `_prune_spec_bytes`, `_collected_items`: compare `[:1]` (address) instead of `[:2]` | C 056_3 |
| M24 | **addendum 2c**, E3 SEC5-1 + Round-2 NOTE: name-only spec-bytes key (the E1 design) | `_demote_moved_spec_params`: return `kept` unchanged (no demotion); `_prune_spec_bytes`: keep by name only (drop the range test); `_collected_items`: `expected = spec[2]` whenever `spec is not None` | C 056_1, 056_2, 056_3, 025_3 |

Not mutated (structure, not behaviour): `_rebuild_memory_table`'s 4-tuple unpack and `_add_memory_row`'s `None` (a wrong arity raises at once in every Check Editor node).
