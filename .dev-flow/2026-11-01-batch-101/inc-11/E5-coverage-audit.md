# Inc 11 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 11, stage E5. Worktree head `688ca2b`. Role: coverage auditor (did not write the cases or the tests). Mode: **validation** of the coverage records. This file is the only file written.

Inputs read: `02-test-cases.md` (77 cases), `01-requirements.md` (28 active rows), `E4-tester-notes.md`, `E4-integration-notes.md` (SR-1, SR-2, OR-3 … OR-8), `E1-rulings.md` (OR-2), the transcripts under `evidence/inc-11/`, `git diff main...HEAD -- tests` (8 files), the existing tests the `covered` rows name (`test_a2l_enriched.py` TC-682, `test_a2l_curve_description.py` TC-1820, `test_tui_issues_triage_b94.py` TC-B94-18), and `s19w/test-cases/TC-PROFILE.md` (TCP-MAP-1, -3, -4, -5, -6, -7; TCP-TRC-4; TCP-EVD-3). `PLAN.md` does not name TCP-MAP; the rules were read from the profile, as at Inc 8.

Evidence: **inspection** of the three new test files, the re-pinned tests and the product call sites, plus two **executed** steps by this auditor: (1) `pytest --collect-only` (s19env, `PYTHONPATH=.`, isolated `LOCALAPPDATA`) over the cited files: 393 nodes; the int-07 file set with `-m "not serial_timing"` collects 328 (1 deselected), matching int-07's 326 passed + 2 failed; (2) an independent line-token scan of the A2L corpus (§3). No test was run by this auditor. Every pass/fail below is from the orchestrator's E4 runs on the LAN Linux host (Python 3.11.18, Textual 8.2.8), read from `int-07`, `int-08`, `int-09` and `red-01`. Nothing was run on Windows; inspection cannot show Windows behaviour.

Rule applied: a test verifies a case only if it asserts the case's expected result; it is `full` only when the product itself produces what it asserts. A stand-in, a pre-shown fixture, an entry no product route calls, a CSS class in place of the painted style, an unasserted clause, or a pinned value that differs from the case make it `partial` (TCP-MAP-1, -5, -6, -7).

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 77 (71 requirement cases, 6 ATs). OR-2 was approved at E1 (`E1-rulings.md` §4), so the 4 `[OR-2]` cases and AT-I11-2's ordering arm stand |
| Coverage as recorded | `full` 67 · `covered` 7 · `partial` 3 · `gap` 0 |
| Coverage after this audit | covered 71 · partial 6 · conflict 0 · gap 0 |
| Marks changed | **3** (3.9%): R-TUI-042b.4/1, AT-I11-4 and R-SEG-SRC.6/1 (which is AT-I11-4) full → partial |
| Expected result / preconditions / inputs to correct | **7** (9.1%): AT-I11-1, AT-I11-4, AT-I11-5, R-A2L-036.7/1, R-TUI-042b.4/1, R-TUI-042b.5/2, R-SEG-SRC.6/2 |
| Tests column wrong (node missing, failed or not collectable) | **13** (16.9%): R-A2L-120/1, R-VAL-032.3/3, plus 11 references that are not collectable node ids (§6) |
| Requirement clauses with no case | 3 (§4) |
| Black-box ATs owed | 3 (§5) |
| Cases with no executed negative control | 21 (§8) |
| **Cases changed, substantive (any column but Result, vocabulary excluded)** | **20 of 77 = 26.0%** |
| Cases changed, any column but Result (vocabulary included) | 75 of 77 = 97.4% (only R-A2L-036.1/1 and R-A2L-036.6/2 unchanged) |

Top issues:
1. **R-TUI-042b.4/1 asserts a CSS class, not a colour.** `has_class("sev-warning")` is TCP-MAP-5(b) evidence; the row says "the colour of its severity" (`#f6ff8f`). `test_tc024_issues_severity_color_round_trips` maps severity → class, not class → painted colour. Partial.
2. **AT-I11-4 does not pair names with bases.** It asserts the four bases and the four names as substrings of the whole table body (`"app" in text`, `"cal" in text`). A table that put `boot` at 0x00040000 would pass. Partial until each row line is asserted to hold its name and its base.
3. **R-VAL-032.3/3 cites a node that failed.** `test_tc_b94_18_curated_set_and_engine_freeze` is one node holding both the engine arm and the OR-3 freeze arm. It FAILED in int-07, and on CI (no `main` ref) it SKIPS, so the node is never `verified` before the merge (TCP-MAP-2, TCP-EVD-3). The engine arm runs first, so its assertions did pass. Fix: drop it from this row; the G1 nodes back the case in full.
4. **Record vocabulary.** `full` is an `asserts` value, not a coverage value (TCP-TRC-4: covered / partial / gap / conflict); `pass (int-07)` is not a verification value (TCP-EVD-3: `verified`, with the platform). The preamble ("Result is `not_run` everywhere", "Coverage is `gap`") and the Count paragraph ("6 `partial`, 64 `gap`") are E1 text and contradict the table (67 / 7 / 3).
5. **The requirement negative controls were never executed for 21 cases.** Their tests pass on base too (red-01), and E4 ran no mutants (E4 item 6). Among them are all 11 R-A2L-036.4 cases: all 22 `no_base` nodes pass on base, so red-01 does not reproduce the base value `01-requirements.md` states for S1 ("base 0x1000"), and nothing shows these tests can fail.

## 2. Change table

"Who" = which artifact changes: **case** (`02-test-cases.md`), **test** (G1/G2/G3 file), **row** (`01-requirements.md`).

| Case | Column | Old → new | Reason (one line) | Who |
|---|---|---|---|---|
| R-TUI-042b.4/1 | Coverage; Expected | full → **partial**; add "painted in `#f6ff8f`" | class asserted in place of the painted style (TCP-MAP-5(b)); the row's threshold names the colour | case; test (read the row's rendered style colour) |
| AT-I11-4 | Coverage; Inputs | full → **partial**; "palette `Split / Join / Export`, `t` twice" → "`ctrl+k`, type `join`, Enter; `t`, Tab, `t`" | names and bases are matched as loose substrings of the body; row pairing and sizes not asserted (TCP-MAP-1); route per SR-1 / OR-8 | case; test (assert per row line) |
| AT-I11-1 | Preconditions | "load dialog (`l`)" → "Load dialog opened with `p`, project row under *Projects*, `#load_ok`" | `l` is `load_file`; the test uses `p` (`load_project`, `app.py:2703`), as do AT-I11-2 … 6 by inheritance | case |
| AT-I11-5 | Inputs | "`2`, cursor on the first CURVE row, `d`" → "`2`, PgDn until a page holds a CURVE row, cursor set with `DataTable.move_cursor`, `d`" | states the real route; stays partial (cursor not moved by keys, TCP-MAP-7) | case |
| R-A2L-036.7/1 | Expected | add "and the Split / Join a2l source lists no row for it" | the partial mark's reason is a threshold clause the case never stated; stays partial until a test asserts it | case; test |
| R-TUI-042b.5/2 | Expected | add "with filter `error`: `E_b`, `E_d`; with filter `warning`: `W_a`, `W_c`" | threshold clause ("with the filter `error` the order is the list order"), already asserted by the test, stated in no case | case |
| R-SEG-SRC.6/2 | Preconditions; reason | "an image loaded, `software_a.a2l` loaded" → "`prg.s19` + `software_a.a2l` assigned to `app.current_file` (no load route); window opened by `action_open_split_join_export()`; tabs cycled by `action_cycle_tab()`" | stays partial, with more reasons than recorded: state injected and window driven by methods (TCP-MAP-7), names and sizes read white-box from `_a2l_rows()`, only bases read from the painted body | case |
| R-A2L-120/1 | Tests | TC-1820 alone → add G1 `test_r_a2l_122_rows_carry_no_note` | TC-1820 asserts x = 0, 1, 2 but not that the lines start `  0`, `  1`, `  2`; the G1 node pins the exact lines. With it: covered | case |
| R-VAL-032.3/3 | Tests; Result | drop TC-B94-18; `pass (int-07)` → `verified (linux, int-07)` on the G1 nodes | the cited node FAILED in int-07 (OR-3) and skips on CI; a failing node fails every case it backs (TCP-MAP-2) | case |
| R-A2L-036.1/4 | Tests | "that test" → `tests/test_a2l_enriched.py::test_tc682_quoted_names_and_the_offset_field` | not a node id (TCP-MAP-3) | case |
| R-A2L-036.2/1, 036.3/1 | Tests | "the two TC-682 fixture tests" → `…::test_tc682_quoted_demo_a2l_segments_parse_to_full_rows`, `…::test_tc682_unquoted_fixture_rows_parse_byte_identically` | not node ids (TCP-MAP-3) | case |
| R-A2L-036.6/1 | Tests | "TC-682 quoted demo test" → `…::test_tc682_quoted_demo_a2l_segments_parse_to_full_rows[ASAP2_Demo_V161.a2l]` | not a node id | case |
| R-A2L-036.8/1, 036.9/1 | Tests | "TC-682" → the named TC-682 nodes (V161; V171 and `memorysegment.a2l`) | not node ids | case |
| R-VAL-032.2/1 | Tests | `…[<N>]` → bare function `test_r_val_032_2_asam_block_names_raise_nothing` (62 ids collect) | a placeholder id does not collect | case |
| R-VAL-032.2/3 | Tests | `…[<file>]` → bare function (37 ids collect) | a placeholder id does not collect | case |
| R-TUI-025.6/2, R-TUI-042b.5/3, R-SEG-SRC.6/1 | Tests | "G3 AT-I11-3 / -2 / -4" → `test_at_i11_3_…`, `test_at_i11_2_…`, `test_at_i11_4_…` (R-SEG-SRC.6/1 inherits AT-I11-4's **partial**) | a case reference is not a node (TCP-MAP-3) | case |
| all 67 `full` rows | Coverage | `full` → `covered` (`partial` for the 3 above) | vocabulary (TCP-TRC-4) | case |
| all 77 rows | Result | `pass (int-0n)` → `verified (linux py3.11, int-0n)` | vocabulary and platform (TCP-EVD-3); no Windows result exists | case |
| preamble, Count paragraph | text | E1 text → E4 state: covered 71 · partial 6 | contradicts the table | case |

Unchanged in substance (57 cases): every other R-VAL-032, R-TUI-042b, R-TUI-025, R-A2L-036, R-A2L-034 and R-A2L-121 … 123 case, and AT-I11-2, -3 and -6. Each asserts its case's exact pinned values on product output. AT-I11-1 … -3 match the OR-7 numbers (`262`, `285`, `rows 1-40/277`). AT-I11-3 uses a real pointer click; AT-I11-6 reads DataTable cell data. No expected value differs from what a test pins, apart from the routes above.

## 3. Corpus walker oracle (R-VAL-032.2/3)

**The recognised set is independent; the tree it walks is not.**
- The set the walker accepts (`ASAM_BLOCK_NAMES`) is typed in the test from `01-requirements.md`, never imported, and pinned at 62 distinct names. A shrunken or grown engine list fails it. Independent.
- The walker `_walk_names_outside_if_data` walks the product's own `parse_a2l_file(...)["sections"]` tree. Its IF_DATA rule (upper-case name, any ancestor) is a line-for-line copy of the engine's `_iter_sections` (`rules.py:449-458`). It shares the parser's nesting, including O-5: a one-line `/begin IF_DATA … /end IF_DATA` stays open. In `ASAP2_Demo_V171.a2l` the first such line is line 3181, and **348 of 411** `/begin` sections come after it. Both walker and engine therefore treat those 348 as inside IF_DATA and never check them. The definition of "inside" adopts that nesting on purpose, so the case is consistent with the row, but the subset clause cannot detect a parser nesting defect.
- **Independent cross-check (executed by this auditor, a scratch script with no product import):** a line-token scan of the 34 `examples/**/*.a2l` files and `synth_a2l.a2l` (comments stripped, every `/begin` and `/end` token on a line counted, so a one-line IF_DATA closes) finds **no** non-ASAM name outside a real IF_DATA in 35 of 35 files. The oracle's conclusion holds on those files. The two demo A2Ls (generated at test time) were not scanned.
- Verdict: `covered` stands. The 0-issue clause is product output; the subset clause is a valid but parser-dependent oracle. Recommended (test): replace the tree walk with a token scan like the one above, so the oracle no longer depends on the parser.

## 4. Requirement clauses with no case

| Row | Clause | Note |
|---|---|---|
| R-A2L-036.7 | "Split / Join lists no row for it" | Owed in R-A2L-036.7/1 (§2); no test asserts it. It is also R-SEG-SRC.6's "has a base" exclusion, which no case covers either |
| R-TUI-042b.4 | "pale yellow `#f6ff8f`" | No case or test reads the painted colour (§2) |
| R-TUI-042b.5 | "with the filter `error` the order is the list order" | Asserted by the test; stated in no case until R-TUI-042b.5/2 is corrected |

Not counted (statements in the threshold, not observable clauses): R-A2L-036.2's "E3 model 17/17"; R-A2L-036.6 writes "is a number" in lower case where the defined term is **Number** (row wording, requirements session).

## 5. Owed black-box ATs

1. **R-SEG-SRC.6, `software_a.a2l` arm.** The row's threshold says "2/2 (AT)". Today only the white-box G2 test (injected state, method-driven tabs) backs it. Owed: load an image and `software_a.a2l` through the Load dialog, open Split / Join via the palette, keys to the a2l tab, then assert `a2l(3)` and the three painted rows.
2. **AT-I11-5 cursor route.** Reach the first CURVE row with keys (PgDn, Down) instead of `move_cursor`; this would make AT-I11-5 `covered`.
3. **AT-I11-4 row pairing.** Not a new AT: strengthen the existing node to assert each painted row holds its name and its base (and size), as §2 says.

R-A2L-034, R-A2L-121 / 122, R-TUI-025.2 / .6, R-TUI-042b.1 / .5 / .6 and R-VAL-032.2 have their black-box ATs (AT-I11-1, -2, -3, -6 `covered`).

## 6. Node collection (TCP-MAP-3)

Every function the Tests column names collects. New files: G1 152 nodes (62 ASAM ids, 37 corpus ids, 22 `no_base` ids), G2 11, G3 6; all bracketed ids the table names (`[top]`, `[single-begin-line]`, `[over]` …) collect exactly. The 11 Tests references that are **not** node ids are listed in §2: 6 prose references to TC-682 / "that test", 2 placeholder ids (`[<N>]`, `[<file>]`) and 3 "G3 AT-I11-n" case references.

## 7. Transcripts cited

- Every Result cites int-07, int-08 or int-09; **none cites int-03 or int-05** (the invalid runs). int-07 … int-09 print the same tree fingerprint `f2c0ee954a895b80` at start and end.
- int-07 (`-n 6`, `-m "not serial_timing"`): 2 failed (TC-027, TC-B94-18), 326 passed. The 169 new nodes are in it and none failed. No new node carries `serial_timing`.
- int-08: TC-682, TC-1820 and `test_validation_a2l.py` are in its 28-file set and passed. Its one failure (`tc_b100_52[case_06]`) backs no case of this table.
- int-09: the `test_tui_directionb.py` partial nodes of R-TUI-042b.1/1 and R-TUI-025.6/1 passed; its two failures are TC-031 (OR-3).
- `-q` output prints no per-node PASSED lines. Per-node pass is inferred as "collected, not in the FAILED list". The inference is sound because the collected count matches (§ Evidence).

## 8. Negative controls (TCP-MAP-4)

These cases' tests **pass on base** (red-01: G1 102 failed / 50 passed; G2 R-TUI-042b.1/1 passed), and no mutant was run (E4 item 6), so `negative_control` is `none-recorded`:
- R-VAL-032.1/1 … /4 (row's control: a top-level-only walker);
- R-TUI-042b.1/1 (re-introduce the INFO remap);
- R-A2L-036.2/4;
- R-A2L-036.4/1 … /11 (all 22 nodes; the controls "scan on for the next pair" and "accept a single Number" were never run);
- R-A2L-036.12/1, R-A2L-036.13/1;
- R-A2L-121/2, R-A2L-123/1.

That is 21 cases. In addition, R-VAL-032.2/1 is RED on base for 47 of 62 names only. AT-I11-3 and AT-I11-4 were RED on base with their earlier routes (`Button.press()`, `t t`) for the right value reasons (`rows 1-40/379`, `a2l(0)`); their current routes were not run on base. Owed at E5: run the row negative controls as mutants on the branch tree and record each RED.

## 9. OR-3 freeze guards — state

| Guard | Branch state | Transcript | Owed |
|---|---|---|---|
| TC-027 `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` | **failed** by design | int-07 | GREEN on the merged tree before the push |
| TC-B94-18 `test_tui_issues_triage_b94.py::test_tc_b94_18_curated_set_and_engine_freeze` (freeze arm; the node fails as a whole) | **failed** by design; **skips** on CI (no `main` ref) | int-07 | GREEN on the merged tree; and drop it from R-VAL-032.3/3 (§2) |
| TC-031 ×2 `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main`, `…_no_name_only_diff_vs_main` | **failed** by design (added to OR-3's scope at E4) | int-09 | GREEN on the merged tree |

No transcript shows any of the four GREEN. None is a case of this table, but TC-B94-18 is cited as evidence by one case. Also still open from E4, outside the table: the six `a2l-*` snapshot baselines (29 snapshot nodes skipped, plugin absent), and `tc_b100_52[case_06]` under the full battery.
