# E4 fix FX9e — classify Inc 9's colour literals in the hue census (F-X9r-2)

Test-side only: `tests/test_tui_patch_json.py` (commit `8a1ca00f`, on tip `4f1149ec`). No product change.

## Entries added
| Literal | Where | Entry | Role / reason |
|---|---|---|---|
| `#f5c26b` | `definition_bench_view.py:54` (`EDIT = "bold #f5c26b"`, C9 D-6) | `_CLAIMED_HUES` "definition_bench_view.EDIT (edited-cell foreground)" | Foreground cue: claimed. |
| `#1c2438` | `definition_bench.py:469` (ramp step-0 background) | `_EXCLUDED_LITERALS` | Background fill, value 21.9%; same law as the DEPTH stack. |
| `#101828` | `definition_bench.py:477` (dark text on light ramp cells) | `_EXCLUDED_LITERALS` | Near-black contrast colour (value 15.7%) on pale fills; not a chromatic cue. |

## RED / GREEN (rtx, HT-02 env, `s19_app.__file__` printed first, load ~0.4-1)
- RED on `4f1149ec`: `-k tc079` = 1 failed, 6 passed; `test_tc079_5c_hue_census_is_complete` names exactly `#1c2438`, `#101828`, `#f5c26b` as unaccounted.
- GREEN with the entries: `-k tc079` = 7 passed. Whole `tests/test_tui_patch_json.py` = 3 failed, 14 passed; the 3 are `test_ac1_editor_fills_json_window_when_room_exists`, `test_ac3_fill_does_not_leak_to_sibling_windows`, `test_ac5_gauge_stays_above_editor`, identical to the 3 on base `6c4fd21f` (X9r `f-test_tui_patch_json-c6c4fd21f.txt`).

## Hue rules for `#f5c26b` (hue 37.83 deg)
Nearest claimants: orange3 `#d78700` 0.15 deg, WAITING_HUMAN `#e8ad3d` 1.47, mac_out_of_range `#d9a35b` 3.54, CRC_FAMILY `#c9562b` 21.5, YELLOW 27.0. Distance to MAGENTA (`#f586da`, 314.59 deg) is about 83 deg, so no claimant-to-gauge collision. MAGENTA's nearest claimant is unchanged (`#e06c75`, 40.75 deg) and the admissible optimum is unchanged (314.57 deg, 40.77). Every `tc079_*` rule passes; no colour or rule changed. Note for the operator, not a rule failure: the edit amber sits within 1.5 deg of two existing amber cues (orange3 and WAITING_HUMAN) and 3.5 of a third; the census does not test claimant-to-claimant distance.

## Laws (exact clone of `8a1ca00f`, real `.git`, no `main` ref as in X9r)
`test_id_registry`, `test_suite_hygiene`, `test_deps_seam_law`, `test_no_private_tokens`, `test_engine_unchanged` (1 skipped), `test_requirements_canon`, `test_address_census`: only the 2 known base failures (`test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`). A first run with a local `main` I had created showed `test_tc027_engine_modules_unchanged_vs_main` failing (it fails with `origin/main` too); it is skipped without a `main` ref, as in X9r; that failure came from my scratch ref, not from this change. An earlier run on a `git archive` copy (no repository) errored in `test_id_registry`; discarded.

## Open
None from this fix. Diff has 0 CR.
