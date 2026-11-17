# RESULT — b103-g3-ui-b

Base integration: `21ec06b2e668b76ec62e76b9c3c6eb7cf971f2b1`.
Test correction commit: `980983158ee9a517ca8612eb2633842e2edecd26`.
Scope: eight authorized test files; no product, support, requirement, push or other-lane changes.

## Correction

Migrated Patch Editor drivers to the current tabs with `show_tab` / `click_visible`, recognized `patch_export_dock`, waited for `settle_workers`, re-showed post-Apply export prompts with `show_prompt_again`, and measured B94/JSON controls on their live tabs. Preserved byte/state oracles, negative controls and geometry thresholds. Replaced fixed pauses in the affected v2 Load/Validate/Apply/Save/Checks/paste flows with bounded observable or worker waits.

The follow-up evidence commit changes only two diagnostic texts: JSON messages now name the actual 118x54 terminal plus the 60-row test region, and B94 no longer claims simultaneous table/editor visibility across sequential tabs. No assertion changed and the full files were not repeated for this diagnostic-only edit.

## Known residual RED after the fix

**19/19 passed**: geometry 7/7 (`fix3-geometry*`) and CRC/CHKED/inplace 12/12 (`red-writes-fix*`).

Nodeids, also recorded in `known-red-nodeids.txt`:

1. `tests/test_tui_patch_card.py::test_at080d_reachable_with_card[size0]`
2. `tests/test_tui_patch_card.py::test_at080d_reachable_with_card[size1]`
3. `tests/test_tui_patch_editor_b94.py::test_at_b94_03_expanded_editor_primary_surface`
4. `tests/test_tui_patch_json.py::test_ac1_editor_fills_json_window_when_room_exists`
5. `tests/test_tui_patch_json.py::test_ac3_fill_does_not_leak_to_sibling_windows`
6. `tests/test_tui_patch_json.py::test_ac5_gauge_stays_above_editor`
7. `tests/test_tui_patch_chips.py::test_at076a_docked_buttons_are_grouped_chips`
8. `tests/test_b101_inplace_views.py::test_r_a2l_048_3_save_back_shows_in_the_tag_table`
9. `tests/test_b101_inplace_views.py::test_r_tui_004_7_2_save_back_shows_in_the_a2l_hex_view`
10. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_5_4_save_back_then_display`
11. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_5_5_save_project_then_display`
12. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_5_7_blocked_save_back_still_refreshes`
13. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_5_8_zero_applied_restore_still_refreshes`
14. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_1_6_save_project_commit_while_displayed_schedules_a_recompute`
15. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_1_6_save_project_commit_while_displayed_recomputes_after_the_quiet_time`
16. `tests/test_b101_designer_writes.py::test_control_other_patch_actions_do_not_mark_the_coverage_stale`
17. `tests/test_b101_designer_writes.py::test_r_chked_057_2_save_back_clears_the_validation_results`
18. `tests/test_b101_designer_writes.py::test_r_chked_057_3_save_project_commit_clears_the_validation_results`
19. `tests/test_b101_designer_writes.py::test_r_crc_preview_002_5_9_save_back_raising_after_the_adopt_ends_the_app`

## Complete touched files — exact consolidated count

**264 collected = 249 passed + 15 residual failures.**

| File | Passed | Residual failed | Total |
|---|---:|---:|---:|
| `test_b101_designer_writes.py` | 14 | 0 | 14 |
| `test_b101_inplace_views.py` | 21 | 1 | 22 |
| `test_b103_inc12_tag_table.py` | 102 | 13 | 115 |
| `test_tui_patch_editor_v2.py` | 52 | 0 | 52 |
| `test_tui_patch_card.py` | 24 | 1 | 25 |
| `test_tui_patch_editor_b94.py` | 17 | 0 | 17 |
| `test_tui_patch_json.py` | 15 | 0 | 15 |
| `test_tui_patch_chips.py` | 4 | 0 | 4 |
| **Total** | **249** | **15** | **264** |

Evidence map:

- `full-geometry-tag*`: 176 collected, 161 passed, 15 failed in that run. Its `test_tc_b94_09_widget_census[size1]` failure was subsequently corrected; `full-b94-final*` supersedes B94 with 17/17 passed. The consolidated count uses that final B94 result, leaving 14 residual failures from this run.
- `full-v2-final4*`: 52/52 passed.
- `full-writes*`: 36 collected, 35 passed, one inherited performance failure.
- `full-b94-final*`: 17/17 passed.

## Residual nodeids and base evidence

`residual-base.tsv` is the machine-readable join between the final failing nodeids and the supplied residual `comparison.tsv`. Every row has `base_status=failure` and `head_status=failure`; `category` and both assertion signatures are preserved. This covers exactly 13 tag-table nodes plus purity and performance.

| Nodeid | Residual category | Base | Head |
|---|---|---|---|
| `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_3_4_card_keeps_the_full_name` | inherited, same signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_1_name_without_display_identifier` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_2_display_identifier` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_3_description` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_4_unit` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_5_conversion` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_6_limits` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_1_7_name_on_the_name_line` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_2_1_description_break_run` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_7_2_2_unit_break_run` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_8_1_name_line_with_a_display_identifier` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_r_tui_042a_8_2_no_name_line_without_a_display_identifier` | inherited, different signature | failure | failure |
| `tests/test_b103_inc12_tag_table.py::test_at_b103_i12_1_no_glued_or_cut_values` | inherited, different signature | failure | failure |
| `tests/test_b101_inplace_views.py::test_qc_tm_10b_1_a2l_refresh_cost_on_the_largest_a2l` | inherited, same signature | failure | failure |

The final performance observation was 220040 tags at 2.192 s against the unchanged 1.0 s bound; the supplied base/head comparison already recorded the same assertion at 1.986 s / 1.633 s.

## Integrity and redaction

- `SHA256SUMS.tsv` records source and redacted SHA-256 for every final log/JUnit and the generated nodeid/base-evidence files.
- Source `comparison.tsv` SHA-256: `ee957749aec12b811dc209933bd7464abee28395e385d9f16e9d56826c65d6c6`.
- Combined source JUnit SHA-256 for the 19-node selection: `340118367474eeb29b3697a406d2083eb03f76fe33c0cf0175a48b01a200fb94`.
- Copies are UTF-8; local paths, account/host identity and network addresses are redacted. Test names, statuses, counts, timings and assertion content remain intact.
- `git diff --check` passed for the test correction. Ruff reported only the pre-existing unused `Rail` import in B94; this lane did not alter that import.
