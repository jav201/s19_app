# WCI run 3 triage — 35 failed / 42 passed / 37 skipped

Evidence: `.dev-flow/2026-11-05-batch-103/evidence/inc-1a/wci-run-42512707465-failed.txt`
Compare: run 2 `.dev-flow/2026-11-05-batch-103/evidence/inc-1a/wci-run-42508713028-failed.txt`
Products read: `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py`
Tests read: `tests/test_b103_clipboard_windows.py`, `tests/support/b103_clipboard.py`
Fix commit under review: `c4599d72` (run-2 test fixes)

## Verdict up front

- **35 distinct causes collapse to 3.**
- **0 product faults.** Every run-3 failure is a test fault. The run-2 triage's
  "0 product faults" conclusion **holds**, but the run-2 *fix* for C6 was wrong
  and the run-2 *attribution* for `12_3` was wrong.
- The run-3 delta (38→35) is not real progress: ~14 tests got fixed, but the
  C6 "fix" broke ~21 tests that were previously failing for other reasons (or
  passing). Net −3.

## The three causes

### C6-regression — `other_program_write` UTF-16LE "fix" corrupts every payload to its first character (21 tests)

Run-2 fix changed `other_program_write` (tests/support/b103_clipboard.py) from
UTF-8 stdin to UTF-16LE stdin + `[Console]::InputEncoding=Unicode`. Windows
PowerShell 5.1 does **not** decode *piped* `$input` by `[Console]::InputEncoding`;
it decodes the UTF-16LE bytes as single-byte, producing a string with an
embedded `\x00` after every character (`"P\x001\x00 \x00…"`). `Set-Clipboard`
stores that string; the `CF_UNICODETEXT` reader (both the product's
`_read_via_ctypes` and PowerShell `Get-Clipboard`) stops at the first NUL and
returns **one character**.

Signature (unambiguous, seen across all 21):
- `"P1 line\nsecond"` → `aPb` (expected `aP1 lineb`)
- `"ZZ"` → `Z-BBBB` (expected `ZZ-BBBB`)
- `P1 = "COPY-1 Ñoño Ж 漢字 😀"` → `C`
- `P1000` (digits) → `0`
- `P70K` → box length `1` (expected `65536`)
- `"OS-BEFORE"` → `O` (via `other_program_read`)
- `"PS-READ"` → `P`

This is a **test-fixture fault**, not a product fault: the product reads back
exactly what the fixture wrote. The clean fix is to make `other_program_write`
call the already-correct `_own_write` (ctypes `CF_UNICODETEXT` UTF-16LE, no
PowerShell encoding trick) — this fixes both the run-2 mojibake AND the run-3
truncation.

### C4-unsolved — `_hold_clipboard` still does not hold the clipboard (13 tests)

Run-2 fix moved the hold from a same-process thread to a separate Python child
that `OpenClipboard(None)`s and sleeps. But the run-3 evidence shows the
clipboard is **still not held** against the test process:

- `9_2` (held write warning): `warnings == []` — the write **succeeds**, no failure.
- `12_2` / `12_3` / `10_2` (held read/write must log ≥1 WARNING): `n == 0` — no failure.
- `13_1_2` / `28_1_2` (held copy ends ≤2.5 s): `999.0` — the failure warning never fires.
- `043_9_1/2`, `14_1/2` (responsive while held): `only 2/0/1/0 ticks` — the
  read/write returns in ~0–100 ms instead of the 1–2.1 s the requirement
  assumes (R-TUI-043.9, R-PASTE.14).

All of it is the *same* failure mode as run 2 (write succeeds, no warning,
operation ends instantly): the hold never takes effect. The run-2 diagnosis
"hold fixture ineffective" was **correct**; the separate-process rewrite did
**not** make it effective. Mechanism not yet proven (likely `OpenClipboard(NULL)`
from a windowless, message-pump-less child does not hold the lock cross-process
on the CI runner) — this is the one place a diagnostic is required (below).

### C5 — `_apply_filter` debounce fires after the a2l screen is popped (1 test)

`043_10_2_1_2[single]` pastes into `#a2l_tags_filter_input`; the self-re-arming
`_apply_filter` timer (app.py:21347) fires during `run_test` teardown and raises
`NoMatches #a2l_tags_list` on `Screen('_default')`. Same as run-2 C5, now newly
exposed on this test by the changed hold timing. Test-harness fault + a
pre-existing, out-of-scope app.py robustness gap (documented in run-2 triage).

## Run-2 diagnosis audit (was it wrong?)

| cause | run-2 diagnosis | verdict after run 3 |
|---|---|---|
| C1 select-all clobber | correct | **confirmed** — selection-after-focus works; residual failures are C6 |
| C2 unmounted `#patch_paste_text` | correct | **confirmed** — `show_patch_paste` works |
| C3 box not cleared | correct | **confirmed** — `widget.text = ""` works |
| C4 hold ineffective | correct | **confirmed** — but the separate-process fix is **insufficient** |
| C5 debounce teardown | correct | **confirmed** (still; one test) |
| C6 mojibake | correct | diagnosis right, **fix wrong** (UTF-16LE regressed to 1-char) |
| C7 read-rescue precondition | correct | **confirmed** — mock works; test now fails only via C6 |
| C8 clipboard not cleared | correct | **confirmed** — `17[read]` now passes |

**Two corrections to run-2 triage:**
1. `test_r_tui_043_12_3_win_right_click_held_logs_warning` was attributed to C5
   (debounce). Run 3 shows it cleanly failing `n == 0` — the true cause is C4
   (hold ineffective → read succeeds → no warning). Run-2 C5 attribution wrong.
2. `test_r_paste_31_1_2[single]` / `[multi]` and `29_30[multi]` were attributed
   to C5/C2/C1; run 3 shows their *content* path now fails on C6 (and the box
   mounting / selection fixes did land).

## Product-fault hypothesis — tested and rejected

For each surface named in the brief, against the inc-1a rows:

- **Read cascade timing** (R-TUI-043.10.1, R-PASTE.31): non-held timing tests
  pass (r_paste_11/27 margins 43–58%); the only timing failures are C6 payload
  corruption, not cascade latency. `os_clipboard_input._read_via_ctypes` reads
  faithfully (bounded `wstring_at` + NUL split) — the "1 char" is the fixture's
  embedded NUL, not a product truncation.
- **PowerShell fallback cost** (R-PASTE.16, R-TUI-043.10.2): 2.0 s budget
  matches the spec; no test shows the cascade exceeding it. `16_2` (write
  rescue) passes; `16_1`/`16_3` fail only on C6 payload.
- **Held-clipboard handling** (R-TUI-043.9/10.2/12, R-PASTE.9/10/13/14/28/32):
  the product's fail→fallback→warn path is implemented and its non-held tests
  pass; the held tests cannot exercise it because the fixture never holds. No
  product deviation shown.
- **Focus/selection handling** (R-TUI-043.4/5, R-PASTE.5/29/30): C1 fixes worked;
  residual failures are C6 content, not selection placement.

## Table (35 rows)

| test | run-2 cause | run-3 evidence | verdict | fix / diagnostic |
|---|---|---|---|---|
| `043_10_1_1_2_ctrl_v_ends_within_typed_key_time[single]` | PASSED | `_wait_for_box` got `'0'` | test (C6) | `other_program_write` → `_own_write` |
| `043_10_1_1_2_ctrl_v_ends_within_typed_key_time[multi]` | PASSED | got `'0'` | test (C6) | same |
| `043_10_2_1_2_held_clipboard_paste_ends_within_2_5[single]` | PASSED | `NoMatches #a2l_tags_list` (C5) | test (C5 timing) | cancel `_apply_filter` before teardown |
| `043_4_1_single_line_inserts_first_line_at_cursor` | C1 | `aPb` (C6) | test (C6) | `other_program_write` → `_own_write` |
| `044_3_1_multi_line_inserts_all_at_cursor` | PASSED | `aPb` (C6) | test (C6) | same |
| `043_5_1_2_ctrl_v_replaces_selection[single]` | C1 | `Z-BBBB` (C6) | test (C6) | same |
| `043_5_1_2_ctrl_v_replaces_selection[multi]` | PASSED | `Z-BBBB` (C6) | test (C6) | same |
| `043_11_1_code_page_characters_arrive_unchanged[single]` | C6 | `C` (C6-worse) | test (C6) | same |
| `043_11_1_code_page_characters_arrive_unchanged[multi]` | C6 | `C` | test (C6) | same |
| `043_12_2_held_clipboard_logs_warning` | C4 | `n==0` | test (C4 unsolved) | parent-verify hold (diag 1) |
| `044_2_4_ctrl_v_of_os_text_capped[single]` | PASSED | `1 == 65536` (C6) | test (C6) | `other_program_write` → `_own_write` |
| `044_2_4_ctrl_v_of_os_text_capped[multi]` | PASSED | `1 == 65536` (C6) | test (C6) | same |
| `r_paste_5_win_no_selection_keeps_os_clipboard` | C1 | `'O'` (C6) | test (C6) | same |
| `r_paste_9_2_held_clipboard_write_warning[single]` | C4 | `[]` (write succeeded) | test (C4 unsolved) | parent-verify hold |
| `r_paste_9_2_held_clipboard_write_warning[multi]` | C4 | `[]` | test (C4 unsolved) | parent-verify hold |
| `r_paste_13_1_2_held_clipboard_copy_ends_within_2_5[single]` | C4 | `999.0` | test (C4 unsolved) | parent-verify hold + layer log |
| `r_paste_13_1_2_held_clipboard_copy_ends_within_2_5[multi]` | C4 | `999.0` | test (C4 unsolved) | same |
| `043_9_1_held_read_ctrl_v_stays_responsive` | C4 | `only 2 ticks` | test (C4 unsolved) | parent-verify hold + elapsed log |
| `r_paste_14_1_held_write_ctrl_c_stays_responsive` | C4 | `only 1 tick` | test (C4 unsolved) | same |
| `r_paste_14_2_held_write_right_click_stays_responsive` | C4 | `only 0 ticks` | test (C4 unsolved) | same |
| `043_9_2_held_read_right_click_stays_responsive` | C4 | `only 0 ticks` | test (C4 unsolved) | same |
| `r_paste_28_1_2_held_right_click_copy_ends_within_2_5[single]` | C4 | `999.0` | test (C4 unsolved) | parent-verify hold + layer log |
| `r_paste_28_1_2_held_right_click_copy_ends_within_2_5[multi]` | C4 | `999.0` | test (C4 unsolved) | same |
| `r_paste_29_30_win_right_click_paste_placement[single]` | C1 | `aPb` (C6) | test (C6) | `other_program_write` → `_own_write` |
| `r_paste_29_30_win_right_click_paste_placement[multi]` | PASSED | `aPb` (C6) | test (C6) | same |
| `r_paste_31_1_2_right_click_paste_ends_within_typed_key_time[single]` | PASSED | got `'0'` (C6) | test (C6) | same |
| `r_paste_31_1_2_right_click_paste_ends_within_typed_key_time[multi]` | C2 | got `'0'` (C6) | test (C6) | same |
| `043_11_2_right_click_keeps_code_page[single]` | C6 | `C` | test (C6) | same |
| `043_11_2_right_click_keeps_code_page[multi]` | C2+C6 | `C` | test (C6) | same |
| `043_12_3_win_right_click_held_logs_warning` | C5 (wrong) | `n==0` | test (C4 unsolved) | parent-verify hold; re-attribute |
| `044_2_6_win_right_click_paste_capped[single]` | PASSED | `1 == 65536` (C6) | test (C6) | `other_program_write` → `_own_write` |
| `044_2_6_win_right_click_paste_capped[multi]` | C2 | `1 == 65536` (C6) | test (C6) | same |
| `r_paste_10_2_win_right_click_copy_logs_warning` | C4 | `n==0` | test (C4 unsolved) | parent-verify hold |
| `r_paste_16_1_read_rescue_starts_system_powershell` | C7 | `'P'` (C6; rescue now runs) | test (C6) | `other_program_write` → `_own_write` |
| `r_paste_16_3_decoy_powershell_never_runs` | PASSED | `'P'` (C6) | test (C6) | same |

## Minimal diagnostics for run 4

1. **Prove the hold (C4).** In `_hold_clipboard`, after the child prints
   `HOLDING`, have the **parent** call `user32.OpenClipboard(None)` via ctypes and
   record the BOOL. If it returns TRUE the hold is still ineffective (rewrite the
   holder: give the child a real window + message pump, or use a holder that
   pumps `GetMessage`/`PeekMessage` while holding). This one check decides the
   fate of all 13 C4 tests and is the only open question.
2. **Layer/elapsed log for the held read/write.** In `_held_clipboard_tick_lateness`
   (and the 999 tests), wrap each cascade layer to record `(name, result, elapsed)`
   and log the wall-clock of `read_os_clipboard`/`write_os_clipboard`. With a real
   hold this must read `ctypes ~0.1s + powershell ≤2.0s`; the run-3 `0–2 ticks`
   says it did not.
3. **`other_program_write` self-check.** After `other_program_write(P1)`, assert
   `other_program_read() == P1` (or `len == len(P1)`). This catches any future
   encoding regression at the fixture itself instead of in 21 downstream tests.

## Notes for the next increment

- One-line product fix candidate (out of inc-1a scope, pre-existing): guard
  `_apply_filter`/`update_a2l_tags_view` against the popped screen (try/except
  `NoMatches` or cancel the timer on screen deactivate). This is the C5 root and
  is in `app.py`, not an inc-1a file.
- All 35 fixes are in `tests/` or `tests/support/b103_clipboard.py`. Do not
  touch `os_clipboard_input.py` or `capped_text_area.py`.
