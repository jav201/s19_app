# WCI run 2 triage — 38 failed / 39 passed / 37 skipped

Evidence: `.dev-flow/2026-11-05-batch-103/evidence/inc-1a/wci-run-42508713028-failed.txt`
Products read: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`
Tests read: `tests/test_b103_clipboard_windows.py`, `tests/support/b103_clipboard.py`

## Result summary

- **8 distinct causes.**
- **0 product faults** — every failure is a test fault (driver / fixture / timing harness). No deviation of `os_clipboard_input.py` or `capped_text_area.py` from the inc-1a rows/graph was found; the core Win32 read/write, cap, strip, no-log-leak and bounded-read behaviours all pass their green tests.

---

## Cause table (38 rows, grouped)

| test id(s) | cause | class | file:line | fix |
|---|---|---|---|---|
| `test_r_tui_043_4_1_single_line_inserts_first_line_at_cursor` | `Input._on_focus` selects-all and clobbers the partial selection set before `focus()`; paste replaces "ab" instead of inserting at cursor | test (driver) | test_b103_clipboard_windows.py:432 | set `widget.selection` AFTER `widget.focus()` + `await pilot.pause()` |
| `test_r_tui_043_5_1_2_ctrl_v_replaces_selection[single]` | same select-all-on-focus clobber (selection (0,4) → (0,9)) | test (driver) | :475 | set selection after focus |
| `test_r_paste_5_win_no_selection_keeps_os_clipboard` | same; empty selection (4,4) → select-all, so Ctrl+C copies "KEEP" | test (driver) | :809 | set selection after focus |
| `test_r_paste_25_26_win_right_click_copy_app_clipboard[single]` | same; selection (0,4) → select-all, right-click copies "AAAA-BBBB" | test (driver) | :1166 | set selection after focus |
| `test_r_paste_29_30_win_right_click_paste_placement[single]` | same; select-all makes `selected_text` truthy → right-click COPIES instead of pastes | test (driver) | :1267 | set selection after focus (or clear `selected_text`) |
| `test_r_paste_35_4_win_right_click_strips_multi_line` | right-click on `#patch_paste_text` never lands: Patch JSON tab not active → box unmounted (region 0×0) | test (driver) | :731 | call `show_patch_paste(app, pilot)` (press `#patch_tab_json`) before the right-click |
| `test_r_paste_24_1_2_five_right_click_copies[multi]` | same unmounted-box cause; `other_program_read()` returns stale "RC-5 Ñ€" because the copy never wrote | test (driver) | :1118 | activate `#patch_tab_json` before right-click |
| `test_r_paste_25_26_win_right_click_copy_app_clipboard[multi]` | same; `app.clipboard` stays "BEFORE" (copy never ran) | test (driver) | :1166 | activate `#patch_tab_json` |
| `test_r_paste_27_1_2_right_click_copy_ends_within_typed_key_time[multi]` | same; clipboard sequence number never changes → 10 s timeout | test (driver) | :1201 | activate `#patch_tab_json` |
| `test_r_paste_28_1_2_held_right_click_copy_ends_within_2_5[multi]` | same unmounted-box cause (copy never runs → no warning → 999) | test (driver) | :1238 | activate `#patch_tab_json` |
| `test_r_paste_31_1_2_right_click_paste_ends_within_typed_key_time[multi]` | same; `_wait_for_box` never sees P1000 | test (driver) | :121 (`_wait_for_box`) | activate `#patch_tab_json` |
| `test_r_paste_31_5_6_right_click_no_text_no_powershell[multi]` | same; right-click never pastes → box keeps pre-seeded JSON | test (driver) | :1330 | activate `#patch_tab_json` |
| `test_r_paste_32_1_2_held_right_click_paste_ends_within_2_5[multi]` | same; right-click never pastes "APP-TEXT" | test (driver) | :121 | activate `#patch_tab_json` |
| `test_r_tui_043_6_5_win_right_click_pastes_app_clipboard[multi]` | same unmounted-box cause | test (driver) | :1398 | activate `#patch_tab_json` |
| `test_r_tui_043_11_2_right_click_keeps_code_page[multi]` | same; box stays empty after right-click | test (driver) | :1414 | activate `#patch_tab_json` |
| `test_r_tui_044_2_6_win_right_click_paste_capped[multi]` | same; right-click paste of P70k inserts nothing (0) | test (driver) | :1493 | activate `#patch_tab_json` |
| `test_r_tui_043_10_1_5_6_no_text_no_powershell[multi]` | inline `_drive` never clears the pre-seeded `#patch_paste_text` changeset JSON → "APP-TEXT" prepends, len 285 ≠ 8 | test (driver) | :208 | clear the box (`widget.text = ""`) like `_box_m` before pasting |
| `test_r_tui_043_6_2_held_clipboard_pastes_app_clipboard[multi]` | same not-cleared box → "APP-TEXT{json}" ≠ "APP-TEXT" | test (driver) | :339 | clear the box before pasting |
| `test_r_tui_043_6_3_empty_unicode_text_pastes_app_clipboard_no_powershell[multi]` | same not-cleared box | test (driver) | :375 | clear the box before pasting |
| `test_r_tui_043_12_2_held_clipboard_logs_warning` | `_hold_clipboard` holds via a same-process thread; Win32 `OpenClipboard(NULL)` re-enters, so the ctypes read succeeds (reads leftover text) and no WARNING fires | test (fixture) | :524 | hold the clipboard from a **separate process**, not a thread of the test process |
| `test_r_paste_9_2_held_clipboard_write_warning[single]` | same broken hold fixture → ctypes write succeeds, no write-fail warning | test (fixture) | :857 | hold from a separate process |
| `test_r_paste_9_2_held_clipboard_write_warning[multi]` | same | test (fixture) | :857 | hold from a separate process |
| `test_r_paste_13_1_2_held_clipboard_copy_ends_within_2_5[single]` | same → write succeeds, no notice → 999 | test (fixture) | :944 | hold from a separate process |
| `test_r_paste_13_1_2_held_clipboard_copy_ends_within_2_5[multi]` | same | test (fixture) | :944 | hold from a separate process |
| `test_r_paste_28_1_2_held_right_click_copy_ends_within_2_5[single]` | same → write succeeds, no notice → 999 | test (fixture) | :1238 | hold from a separate process |
| `test_r_paste_10_2_win_right_click_copy_logs_warning` | same broken hold fixture → write succeeds, no WARNING | test (fixture) | :1537 | hold from a separate process |
| `test_r_tui_043_9_1_held_read_ctrl_v_stays_responsive` | same → read returns instantly, 0 ticks before `ended` | test (fixture) | :1028 (`_assert_ticks_on_time`) | hold from a separate process |
| `test_r_paste_14_1_held_write_ctrl_c_stays_responsive` | same → 1 tick | test (fixture) | :1028 | hold from a separate process |
| `test_r_paste_14_2_held_write_right_click_stays_responsive` | same → 0 ticks | test (fixture) | :1028 | hold from a separate process |
| `test_r_tui_043_9_2_held_read_right_click_stays_responsive` | same → 0 ticks | test (fixture) | :1028 | hold from a separate process |
| `test_r_tui_043_6_5_win_right_click_pastes_app_clipboard[single]` | paste into `#a2l_tags_filter_input` schedules the app's self-re-arming `_apply_filter` debounce; it fires during teardown (a2l screen popped) → `NoMatches #a2l_tags_list` on `Screen('_default')` | test (timing harness) | app.py:21347/20930 (surfaces at :1398) | don't paste into the filter input, or await/cancel the `_apply_filter` timer before `run_test` exits |
| `test_r_paste_31_5_6_right_click_no_text_no_powershell[single]` | same debounce-teardown crash | test (timing harness) | :1329 | await/cancel `_apply_filter` before teardown |
| `test_r_tui_043_12_3_win_right_click_held_logs_warning` | same debounce-teardown crash | test (timing harness) | :1442 | await/cancel `_apply_filter` before teardown |
| `test_r_tui_043_11_1_code_page_characters_arrive_unchanged[single]` | `other_program_write` (PowerShell `$input \| Set-Clipboard`) decodes UTF-8 stdin as the OEM/CP437 console page → P1 stored mojibake'd; product's UTF-16 read is faithful | test (fixture) | :493 | make `other_program_write` write UTF-16 (use `_own_write`, or UTF-16LE stdin + matching InputEncoding) |
| `test_r_tui_043_11_1_code_page_characters_arrive_unchanged[multi]` | same mojibake fixture | test (fixture) | :493 | fix `other_program_write` encoding |
| `test_r_tui_043_11_2_right_click_keeps_code_page[single]` | same mojibake fixture (right-click does paste, but content is already corrupted) | test (fixture) | :1414 | fix `other_program_write` encoding |
| `test_r_paste_16_1_read_rescue_starts_system_powershell` | test expects the read rescue to fire but never forces the ctypes read to fail; ctypes reads "PS-READ" so no PowerShell starts (`started == []`) | test (precondition) | :1564 | mock `_read_via_ctypes` → `None` (or otherwise force a ctypes failure) before asserting the rescue path |
| `test_r_paste_17_no_powershell_starts_nothing[read]` | test doesn't clear the OS clipboard; leftover "PS-READ" from prior tests is read via ctypes instead of the internal "APP-TEXT" fallback | test (fixture) | :1643 | clear the OS clipboard first, or assert against the actual OS clipboard content |

---

## Cause legend (8 distinct)

1. **C1 — `Input._on_focus` select-all clobber** (5 tests): Textual's stock `Input._on_focus` selects the whole text, so any `.selection` set before `widget.focus()` is lost.
2. **C2 — right-click on unmounted `#patch_paste_text`** (11 tests): the Patch JSON tab must be active (`show_patch_paste`) or the box's region is 0×0 and the App-route right-click never hits it.
3. **C3 — `#patch_paste_text` not cleared** (3 tests): inline `_drive` pastes into the pre-seeded changeset JSON instead of an empty box (the `_box_m` helper clears it; the inline drivers don't).
4. **C4 — `_hold_clipboard` fixture ineffective** (11 tests): holding from a same-process thread does not block the product's ctypes `OpenClipboard(NULL)` (re-entrant within a process), so reads/writes succeed and no failure warning fires.
5. **C5 — a2l-filter debounce teardown crash** (3 tests): pasting into `#a2l_tags_filter_input` arms the self-re-arming `_apply_filter` timer, which raises `NoMatches #a2l_tags_list` when it fires after the a2l screen is popped.
6. **C6 — `other_program_write` non-ASCII corruption** (3 tests): PowerShell 5.1 decodes the UTF-8 stdin as the OEM code page, mojibake'ing P1 before the product reads it.
7. **C7 — read-rescue precondition missing** (1 test): `016_1` never forces the ctypes read to fail, so the PowerShell rescue (and its `started` spy) never triggers.
8. **C8 — OS clipboard not cleared** (1 test): `017[read]` reads leftover "PS-READ" instead of the intended internal fallback.

## Notes for the next increment

- All fixes are in `tests/` (or the `_hold_clipboard` / `other_program_write` helpers in `tests/support/b103_clipboard.py`), not in `s19_app/`.
- C5 also exposes a latent `app.py::_apply_filter` robustness bug (self-re-arming timer with no teardown/`NoMatches` guard). That is pre-existing, outside the inc-1a product files, and out of scope here — file it separately if desired.
