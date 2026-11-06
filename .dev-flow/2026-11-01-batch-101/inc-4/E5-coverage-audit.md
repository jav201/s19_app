# Inc 4 -- E5 coverage audit

Batch 2026-11-01-batch-101, increment 4. Mode: **validation**. This audit checks the case records against the tests and the runs. Auditor: qa-reviewer. I did not write the cases, the tests or the integration. Tree: worktree head `149e3bf`. Rules: TCP-MAP-1, TCP-MAP-5, TCP-MAP-6 and TCP-MAP-7, plus TCP-ROW-2, TCP-TRC-2/4 and TCP-EVD-3/4 where a finding needs them (`s19w/test-cases/TC-PROFILE.md`; `PLAN.md` cites the profile but does not restate the rules). Inputs: `02-test-cases.md` (22 cases), `01-requirements.md` (6 rows), `E4-tester-notes.md`, `E4-integration-notes.md` (F-1 … F-4, OR-1 … OR-4, §5 timings), `evidence/inc-4/int-*.txt` and `red-01-tester-base.txt`, and `git diff main...HEAD -- tests`.

Rule applied: a test verifies a case only if it asserts the case's expected result. It is `full` only when the product itself produces what the test asserts. Any of the following makes it `partial`: a stand-in echo, a fixture that already shows the result, an entry point no product route calls, an unasserted clause, a different pinned value, or an observation that another behaviour could also produce. OR-4 says the tester saw the implementer's in-progress edits, so I read every test against its case and its requirement row, not against the code. Code was read only to settle questions of the form "does the product produce this observable" (§6).

Execution: **I ran no test.** The only command I ran is `pytest --collect-only` over the 24 cited node ids (§7). Every pass, fail or time below was executed by the E4 integrator (Opus, `int-*`) or the E4 tester (`red-01-tester-base.txt`). I read each one from that run's own transcript.

## 1. Verdict

**22/22 cases have a test that executes. 0 are `gap`. 18 are covered by a `full` node, and 4 drop to `partial`. 11 of the 22 rows need a substantive change (50 %).** A vocabulary fix also touches all 22 rows (100 % of rows touched in all), and one row is missing (R-CHG-SYM.13/3).

- **Rating changes, full → partial (4 = 18 %):**
  - R-CHG-SYM.9/4: a confirm that does nothing passes, and the row's "document is replaced" clause is not observed.
  - R-CHG-SYM.11/2: the black-box drive uses stand-ins, and "lines end" is asserted only as membership.
  - R-CHG-SYM.11/3: "0 `blocked`" is not asserted, the applied count is pinned at `>= 2` rather than 7, and the drive uses stand-ins.
  - R-CHG-SYM.13/1: the symbol spelling is checked on 2 of 1 000 entries.
- **Expected-result or Tests-column changes with no change in rating (7):**
  - R-CHG-SYM.9/1, R-CHG-SYM.9/5 and R-CHG-SYM.12/2: the drive is partial, so these need the same label as 11/2.
  - R-CHG-SYM.10/3, R-CHG-SYM.10/4 and R-TUI-058.9/3: the Expected omits lines that the product paints and the test pins.
  - R-TUI-058.9/1: the requirement says "document unchanged", but the case says only "entry 2 unchanged".
- **Record-wide defect:** the Coverage column says `full` on all 22 rows. `full` is an `asserts` value (TCP-ROW-2), not a coverage value. The coverage values are `covered`, `partial`, `gap`, `conflict` and `not-testable`.
- **Missing row:** the record body (line 97) and the integration notes cite **R-CHG-SYM.13/3**, but no such row exists. Its node, the A-7/OR-2 measurement, sits in 13/1's Tests column. That node does not assert 13/1's expected result (TCP-MAP-1).
- **Black-box ATs owed: 8.** None of the six session reads is driven only by keys and dialogs, and neither are Execute scope or the report run (§4).
- **Timing:** 13/1 has the run count its threshold needs. The 13/3 measurement does not, and int-26 measured it under the old 2.0 s bound (§5).
- **Collection:** all 24 cited node ids collect (§7). The test names in `E4-tester-notes.md` §2 are stale (`_at_1000_`, pre-F-1) and do not collect.

## 2. Changes to `02-test-cases.md` (for the record's owner; I did not edit it)

| # | Case | Column | Old → new | Reason |
|---|---|---|---|---|
| C-1 | R-CHG-SYM.9/4 | Tests, Coverage, Expected | full → **partial**; coverage full → **partial**. Expected: add a positive observable, for example "confirm the entry with bytes changed within `<tag 2>`'s length: entry 2 then holds the new bytes and keeps symbol `<tag 2>`; 7 entries" | TCP-MAP-6. Every clause asserted is an absence or an unchanged state: no rejection line, no finding line, `after == before`, 7 entries. A confirm that returns without reading or replacing anything gives the same observation. Only the base's rejection is excluded. R-CHG-SYM.9's threshold says "per-entry Edit JSON of a symbol entry: **the document is replaced** with no finding line". No case asserts that clause (§3). D10-29 excludes the success text, so the replacement has to be shown through the document. |
| C-2 | R-CHG-SYM.11/2 | Tests, Coverage | "full (output); drive partial" → **partial** (output full; drive and the end clause partial); coverage full → **partial** | (a) Drive: scope cycling and Execute use `Button.press()`, and arm b's unload calls `app.on_loaded_artifacts_panel_unload_requested(...)` directly, not the panel's control. (b) The case says "lines **end** `Execute: scope 'all' finished - 1 variant(s), 0 error(s)`". The test asserts `in lines`, so a line painted after it (an error) still passes (TCP-MAP-1, different pin). Fix (b): `lines[-1] == …` after the flush. The output clause (patched bytes read with the independent reader, both arms) is full. |
| C-3 | R-CHG-SYM.11/3 | Tests, Coverage | full → **partial**; coverage full → **partial** | (a) "**0 entries `blocked`**" is in the case and in R-CHG-SYM.11's report-surface threshold, but it is not asserted. (b) "Both symbol entries applied" is pinned as overview applied `>= 2`, while the tester notes say 7 expected. With 2 applied and 5 blocked it still passes. The Modifications rows and the patched bytes do prove that the two symbol entries were applied. (c) The Reports screen opens through `app.action_view_reports()` (a direct action call), and Generate uses `Button.press()`. Fix: pin applied `== 7` and 0 blocked from the report text. |
| C-4 | R-CHG-SYM.13/1 | Tests, Coverage, Inputs | full → **partial**; coverage full → **partial**. Tests: move `test_r_chg_sym_13_whole_document_edit_json_confirm_of_1000_entries_by_220040_tags` out to the new row C-12. Inputs: "entry i at tag i's address" → "entry k at tag 220·k's address" | (a) Expected: "every entry's symbol the tag's spelling". The test checks only `entries[0]` and `entries[-1]`. A read that dropped symbols from the middle 998 entries, with 0 issues, passes (TCP-MAP-1). Fix: compare all 1 000. (b) The A-7 node asserts the added cost of the whole-document confirm, not this read's counter or its clock, so it does not verify 13/1. (c) The input deviation does not change the verdict: the symbols are still distinct and spread out. The counter (exactly 1 per run, 5 runs) and the 1.0 s ceiling are full. |
| C-5 | R-CHG-SYM.9/1 | Tests | full → **full (output); drive partial**: the File dropdown pick assigns `Select.value` | The case is labelled black-box ("keys, clicks and dialogs only"). Use the same label as 11/2. The output clauses are full. The JSON-view clause discriminates: the view shows `serialize_change_document(document)` (`app.py:7148`), so on base the skipped entries are absent. |
| C-6 | R-CHG-SYM.9/5 | Tests, Expected | full → **full (output); drive partial** (`Select.value`). Expected: add "the loaded spec's entry 2 carries `<check tag>`" | The case is labelled black-box and the pick is a stand-in, as in C-5. R-CHG-SYM.9's clause "every symbol entry … with its tag's spelling as its symbol" has no assertion for alternative 5: the test checks lines and 3 collector rows only (§3). |
| C-7 | R-CHG-SYM.12/2 | Tests, Expected (advisory) | full → **full (output); drive partial** (`Button.press()` for scope and Execute). Advisory: pin `… 1 variant(s), 0 error(s)` | The OR-1 premise deletes the A2L file after the attach. With the error count left open, "no patched file" could also come from a run that errors on a missing A2L path. The base's blocked document ends with `0 error(s)` (tester notes §2), so pinning it costs nothing. The product reads the folder at run time (`variant_execution_service.py:2746`), so no rating change is needed today. |
| C-8 | R-CHG-SYM.10/3 | Expected | add "then 2 R-CHG-SYM.2 finding lines (entries 2 and 3)" | The test pins them (`two_findings`). The record should state every value the test pins (TCP-DER-3). |
| C-9 | R-CHG-SYM.10/4 | Expected | "…then 1 R-CHG-SYM.2 finding line for `<tag 2>`" → "…then 1 R-CHG-SYM.2 finding line for `<tag 2>`, then the R-TUI-058.9 line (R-TUI-058.9/1)" | After Inc 4 the product paints three lines. The test accepts `lines[2:] in ([], [PLAIN])`, so the Expected no longer matches what the product paints. |
| C-10 | R-TUI-058.9/1 | Expected, Tests | "entry 2 unchanged" → "the document unchanged (7 entries equal)"; Tests: add `test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[entry-json]` (full for that clause) | R-TUI-058.9's threshold says "document unchanged". The 058.9/1 node compares row 2 only. The `[entry-json]` node runs the same scenario and compares all 7 entries (TCP-MAP-2). |
| C-11 | R-TUI-058.9/3 | Expected | arms a and b: add the first line `Patch Editor: entry edit rejected - see findings.` | The test pins `[REJECTED, finding]` exactly. The Expected names only the finding line. |
| C-12 | **R-CHG-SYM.13/3 (new row)** | all | add the row: objective "the symbol resolution adds ≤ min(2 × measured, 1.0 s) to the whole-document Edit JSON confirm of 1 000 entries × 220 040 tags (A-7, OR-2)"; class normal; Expected `Loaded change: 1000 entries, 0 error(s)` on both arms and added < 1.0 s, **5/5 samples**; node the A-7 test, `serial_timing`; Result not_run until 5 samples run (§5) | The id is cited (record line 97; integration notes §2 F-4, §5, OR-2) but does not exist. Count becomes 23. `_apply_changeset_json_edit` is the `ChangeSetJsonScreen` callback (`app.py:5355`), so TCP-MAP-7 is satisfied. The session A2L is planted (`app.current_a2l_data = context`), a precondition stand-in that is acceptable for a measurement. |
| C-13 | all 22 | Coverage | `full` → `covered` (18) or `partial` (4: C-1 … C-4) | TCP-ROW-2 vocabulary (TCP-TRC-4: `covered` requires at least one `asserts: full` node). Also label every node in the Tests column `(full)` or `(partial: …)`, as the column header promises. Today only 11/2 carries a label. |

Unchanged after re-check (TCP-MAP-1/5/6/7):
- **R-CHG-SYM.9/2:** exact `Loaded change` ×1, 0 finding lines, 7 entries, symbols equal through the Parse paste handler.
- **R-CHG-SYM.9/3:** 0 refused lines, `Loaded change` ×1. The draft comes in through `install_draft` with an explicit context, a precondition the trigger does not produce. The confirm replaces the document, so the 7-entries clause is not pre-shown.
- **R-CHG-SYM.9/6:** exact panel status, 3 entries, entry 2's symbol from the stashed spec the product built.
- **R-CHG-SYM.10/1, /2, /5, /6:** exact lines or prefixes, exactly 2 or 1 findings. /6 opens the project through the dialog with the project's A2L file present, then unloads. That excludes both mutants, "project A2L" and "last loaded A2L".
- **R-CHG-SYM.11/1:** service-level, status `ok`, 0 unresolved, 0 blocked, applied at both addresses, exact aggregates, no `doc-fault`. `execute_project_variants` has product callers (Execute scope and the report worker).
- **R-CHG-SYM.12/1:** exactly 2 findings, all entries blocked, `doc-fault` ×2.
- **R-CHG-SYM.13/2:** counter 0 and 1, exact.
- **R-TUI-058.9/2:** exact two lines, 0 plain lines.

## 3. Requirement clauses with no case (or no asserting node)

| Row | Clause | State | Fix |
|---|---|---|---|
| R-CHG-SYM.9 | alternative 4: "the document is replaced" | no assertion (C-1) | the C-1 Expected |
| R-CHG-SYM.9 | "every symbol entry … with its tag's spelling as its symbol", alternative 5 (Check Editor) | no assertion (C-6) | assert the loaded spec's entry 2 symbol |
| R-CHG-SYM.10 | "1 for each check document" | only `demo_check` is read. `demo_check_fails` never goes through a session read in any case | low risk (same reader); add a `[check-editor-fails]` arm or narrow the threshold |
| R-CHG-SYM.11 | report surface: "0 `blocked`" | in the case, not asserted (C-3) | pin it |
| R-CHG-SYM.11 | black-box: "the run ends `… 0 error(s)`" | asserted as membership (C-2) | `lines[-1]` |
| R-TUI-058.9 | "document unchanged" | case says entry 2 only (C-10) | the C-10 Expected |
| A-7 / OR-2 | the confirm's added cost | the id is cited, no row (C-12) | the new row |
| graph node `_parse_entries` (E3 A-2, "once per read") | the integrator's `index_built` fix (no declared A2L: at most 1 builder call, where the implementer's code made one call per symbol entry) | **no test fails without the fix**. 13/1 and 13/2 always pass a context. Integration notes §8 say M-10 and M-15 "now also cover the no-context path", but no node exercises that path | add an arm to 13/2: `parse_change_document(demo_patch, a2l_context=None)` → counter ≤ 1. This is not a requirement clause (the row bounds a read with a declared A2L), so it is not counted as a case change |

## 4. Owed black-box ATs (8)

The case header defines black-box as "keys, clicks and dialogs only". The Load dialog (`l`, typed path, `#load_ok` click), the project dialog and the screen keys `6`, `7` and `=` are real. The record says "`ctrl+l` … `enter`", while the tests press `l` and click Load. That is a small drive deviation, and the dialog itself is real. The stand-ins are listed below.

| # | Surface | Today | Owed |
|---|---|---|---|
| BB-1 | Patch Editor file load (9/1, 10/1) | `Select.value = PATCH` | the pick through the dropdown by keys or click |
| BB-2 | Parse paste (9/2, 10/2) | `TextArea.text = …`, then `Button.press()` | typed or pasted text, then a click on Parse paste |
| BB-3 | whole-document Edit JSON (9/3, 10/3) | the draft comes from `service.load_text(…, a2l_context=…)`, not from a paste; Edit JSON and Confirm use `Button.press()` | the draft from a real paste, then clicks |
| BB-4 | per-entry Edit JSON (9/4, 10/4, 058.9/1–/3) | as BB-3, plus `DataTable.move_cursor`; unload by a direct handler call | row choice by keys, clicks, unload from the panel's control |
| BB-5 | Check Editor Spec pick (9/5, 10/5) | `Select.value` | the dropdown by keys or click |
| BB-6 | A2B Diff check-spec pick (9/6, 10/6) | `Select.value` | the dropdown by keys or click |
| BB-7 | Execute scope (11/2 arms a and b, 12/2) | scope and Execute by `Button.press()`; arm b's unload by a direct handler call | `pilot.click` on scope and Execute, unload from the panel |
| BB-8 | project report run (11/3) | `app.action_view_reports()`, Generate by `Button.press()` | the Reports key, then a click on Generate |

The product outputs these tests assert are produced by the product. Only the drive is a stand-in, so the gap is the gesture-to-handler wiring.

## 5. Timing rows: run counts and bounds

| Row | Threshold needs | Runs on record | State |
|---|---|---|---|
| R-CHG-SYM.13/1 | < 1.0 s, **5/5**, LAN host, `serial_timing`, `report_margin`; stop if measured > 0.5 s | int-26 (load 1.28): 5 runs, 0.183–0.186 s; int-27 (load 0.78): 5 runs, 0.174–0.186 s; counter 1 per run; bounds print `1.000 s`, so `CI` was unset and `timing_bound` did not loosen | **enough**. Measured 0.186 s, under the 0.5 s stop rule. 1.0 s ≥ 5 × measured. Executed by the integrator. |
| R-CHG-SYM.13/3 (C-12) | OR-2: added < min(2 × measured addition, 1.0 s); the run count is not stated | **1 sample per invocation**: one plain run and one symbolic run after a discarded warm-up. int-26: 0.622 s, asserted against **2.000 s** (transcript line 57, the pre-F-4 file). Integration notes §5 list int-26 against "1.0 s", which the transcript contradicts. int-27: 0.395 s against 1.000 s, the only run of the final file. | **not enough**. The bound is "2 × measured", but two single samples differ by 57 %, and int-25 (load 12) gave 2.439 s. Owed: 5 samples on the final file under the 1.0 s ceiling, with the max recorded. Until then: `verified` for 1 sample only, or not_run against a 5/5 threshold. |
| int-25 | none | load 12 | invalid as a measurement, as the integration notes say. I cite no value from it. |

No Windows timing was run (operator rule; R-CHG-SYM.13).

## 6. Results and traceability

- **Who ran it:** every `verified (linux, …)` Result was executed by the E4 integrator on the LAN Linux host. int-28 (`-n 8 -m "not serial_timing"`, the new file plus 6 guard files) ends `179 passed`, 0 skipped, 0 failed. It runs at file granularity (`-q`), so the 22 non-timing nodes pass as part of that count. No transcript lists them by name. The 2 timing nodes pass in int-27 (`2 passed`).
- **Revision (TCP-EVD-4):** the runs used `origin/main 7add3d63` with the local Inc 4 diff applied. That tree is not a commit. The notes say the md5 sums of the source files and the new test file were checked against the local worktree, but no checksum is printed in int-27 or int-28. `149e3bf` changes exactly the files the integrator lists (io.py, change_service.py and three test files). I accept the equivalence on the integrator's statement and record that the transcripts do not show it. A diff hash of `git diff b7b77c4` printed in the transcript would close this.
- **Vocabulary:** `verified` is a valid TCP-EVD-3 verification value, and I keep it. Coverage `full` is not valid (C-13).
- **Rated on the cases, not on the code (OR-4):** each test asserts its case's stated values. No assertion depends on an implementation detail the design does not name. `_symbol_name_index` is a graph node, and the counter is the row's primary oracle. Code was read only for C-5 (what the JSON view shows), C-7 (where the variant run gets its A2L) and C-12 (who calls `_apply_changeset_json_edit`).

## 7. Collection (TCP-TRC-2)

`python -m pytest --collect-only -q` (s19env, Windows PC, collection only), over the 24 node ids the Tests column cites. The parametrized ids were expanded from the column's `[file-load]` … `[ab-diff-project-a2l-not-implicit]` and `[session-a2l-loaded|unloaded]`. Result: **24 tests collected**, 0 errors. The column cites 22 functions or parameters plus the A-7 node, and every one collects. Stale names that do not collect are in `E4-tester-notes.md` §2: `…_symbol_read_at_1000_entries_…` and `…_edit_json_confirm_at_1000_entries_…` (renamed by F-1). They are not in `02-test-cases.md`.

## 8. Summary counts

| Measure | Count |
|---|---|
| Cases | 22 (+1 owed row, R-CHG-SYM.13/3) |
| Covered by a full node after this audit | 18 |
| Partial | 4 (9/4, 11/2, 11/3, 13/1) |
| Gap | 0 |
| Rating changes | 4 / 22 = 18 % (all full → partial) |
| Rows with a substantive change (C-1 … C-11) | 11 / 22 = **50 %** |
| Rows touched including the C-13 vocabulary fix | 22 / 22 = 100 % |
| Requirement clauses with no asserting node | 6, plus 1 unguarded design fix (§3) |
| Black-box ATs owed | 8 (§4) |
| Cited nodes that collect | 24 / 24 |
| Timing rows with enough runs | 1 / 2 (13/1 yes, 13/3 no) |

## Evidence checklist

- ✓ Mode declared: validation (header).
- ✓ Every case carries a rating and a state. Results stay `verified`, executor the E4 integrator. 13/3's state is not_run against a 5/5 threshold (§5).
- ✓ Each executed result names its executor (§6). The auditor ran collection only.
- ✓ Expected results are checked against the pinned values (C-2, C-3, C-4, C-8 … C-11).
- ✓ Edge and negative arms are reviewed (R-CHG-SYM.10 ×6, R-CHG-SYM.12 ×2, R-TUI-058.9 /2 and /3).
- ✗ Layer B (black-box): 8 surfaces are owed (§4). The outputs are product-produced, the drives are not.
- ✓ Bidirectional reachability: every input surface of R-CHG-SYM.9, .10 and .11 reaches the handler. The stand-in gestures are listed in §4.
- ✓ No unfilled placeholders in this file. No PII, names, hosts or paths: transcripts are quoted as `<HOME>`.

## Re-audit (2026-11-06)

Mode: **validation**. Scope: only the cases the E5 corrective pass changed or added, against §2–§5 above. Tree: worktree head `200cc69`. Inputs: `E5-rulings.md` (C-1 … C-8), `E5-corrective-notes.md`, `git diff 149e3bf..200cc69 -- 02-test-cases.md 01-requirements.md tests/` (`01-requirements.md` is unchanged), `evidence/inc-4/e5c-*.txt`. Execution: **I ran no test.** I ran `pytest --collect-only` only. Every pass, fail and time below was executed by the E5 corrective agent (Opus) on the LAN Linux host. I read each one from its own transcript. Every final transcript prints fingerprint `7f5b5b48049d1725` at start and end, and `e5c-01` lists all 22 non-timing nodes by name. This closes the §6 revision and naming gap.

### R.1 Earlier issues: closed

| Earlier | Now | Evidence | Rating |
|---|---|---|---|
| C-1 9/4 "document replaced" | A second confirm of row 2 changes every byte (XOR 0x5A, length kept). `replaced == (type, address, new bytes, <tag 2>)`, with 7 entries | M-17 (`if edited is None or True`, `app.py:5529`) is RED at `(164,) != (254,)` (`e5c-mut17`, `RESTORE_OK`) | **full** |
| C-2 11/2 | Scope and Execute go through `pilot.click`. Arm b unloads with key `1` and a click on the Loaded panel's `Button.loaded-unload[name=a2l]`. `lines[-1] ==` the finished line, read after the `lines_after` flush | `e5c-01` | **full** |
| C-3 11/3 | Overview applied `== 7`. Modifications has 7 rows and none has Before `-`. `report_service.py` renders `before_bytes=None` (every non-applied disposition) as `-`, so this does show 0 blocked. Key `t`, then a Generate click | `e5c-01` | **full** |
| C-4 13/1 | All 1 000 spellings compared, on every one of the 5 runs | `e5c-05` | **full** |
| §3 unguarded fix → 13/2 | Third arm: no-A2L read, builder called exactly 1 time, 2 R-CHG-SYM.2 findings | M-16 (`symbol_index is None`, `io.py:904`) is RED with "2 time(s)" (`e5c-mut16`, `RESTORE_OK`) | **full** |
| C-12 13/3 | New row. 5 samples, each asserted against `timing_bound(1.0)`. Additions 0.422 / 0.290 / 0.021 / 0.008 / 0.351 s (max 0.422 s). Quiet host (load 1.34), QC-TM 0 under 20 % | `e5c-05` | **full** for the measurement (stand-in trigger accepted, C-12) |
| C-5…C-11 Expected/labels | 10/3 (refused ×1 + 2 findings + all 7 unchanged), 10/4 (`lines[2:] == [PLAIN]`, C-8), 058.9/1 (adds the `[entry-json]` node plus a 7-entry compare in its own node), 058.9/3 (`[REJECTED, finding]` in both arms), 9/1, 9/5 and 12/2 (gesture drives; 12/2 pins `0 error(s)` last) | each matches its test | unchanged, full |
| C-13 Coverage column | `covered` ×23, and every node carries `(full)` with any precondition stand-in named | record | — |
| §3 10 "each check document" | The Check Editor arm also picks `demo_check_fails`, and the exact 2 lines are pinned | `e5c-01` | full |
| §4 BB-1…BB-8 | Dropdowns: a click on the face (hit checked by ancestry), arrow keys and `enter`, with no `Select.value` write. Pastes: a click, `f7`, then `events.Paste` posted to the app; the app forwards it to the focused widget (`textual/app.py:4142`, the terminal route). Buttons, tab chips, Confirms and Generate are clicked with an asserted hit. Ledger: a click, then arrow keys. Unload: the Loaded panel `[u]`. Reports: key `t` | test diff | 0 owed |

### R.2 The Check Editor "spelling not visible" ruling (9/5)

**I accept it on risk, but the wording is wrong.** `on_check_editor_panel_spec_file_selected` (`app.py:7436`) reads through `read_change_document(..., a2l_context=self.current_a2l_data)`. It keeps `{address, size}` only and then drops the document, so no product surface shows the spelling. Alternatives 1, 2, 3, 4 and 6 assert the spelling through the same `io` reader, and 9/5's 0 findings needs the session A2L to resolve the tag. Calling the clause "not-testable" overstates it, though. A spy on `read_change_document` would test it, and that is the same technique 13/1's call counter uses and this audit rates full. The new address assertion comes from the document's own `address` field, so it proves the symbol entry was kept, not which tag it resolved to. Fix: reword the clause to "not observable on this surface; the shared reader is asserted in alternatives 1–4 and 6", or add the spy. This does not change the rating.

### R.3 Remaining issues (none change a rating)

| # | Case | Issue | Fix |
|---|---|---|---|
| RA-1 | 9/5 | "not-testable" wording (R.2) | reword, or add a spy |
| RA-2 | 13/3 | The Expected says each confirm "**ends** `Loaded change: 1000 entries, 0 error(s)`". The test asserts `in lines`, the same membership-versus-ending gap that 11/2 had | `lines[-1] ==`, or Expected "paints" |
| RA-3 | 13/2 arm 3 | It pins exactly 1 builder call on a no-A2L read. That is an implementation detail: a correct read that skips the builder with no context (0 calls) would go RED. A-2 is "at most once" | `<= 1`. M-16 (2 calls) stays killed (advisory) |
| RA-4 | record hygiene | Line 67 of `E5-corrective-notes.md` names a home-relative remote path (`~/work/…`). The transcripts already redact it as `<HOME>` | redact it in the notes |

### R.4 Collection

`python -m pytest --collect-only -q` (s19env, Windows PC, `PYTHONPATH=.`, `LOCALAPPDATA` set to an isolated temp folder), over the 24 node ids the Tests column now cites: **24 tests collected**, 0 errors. `git status` stayed clean.

### R.5 Totals

| Measure | Count |
|---|---|
| Cases | 23 |
| Re-checked (test or Expected changed, or added) | 21 (all except 11/1 and 12/1, which changed only the Coverage label; I checked that label as well) |
| Covered, full node | 23 / 23 |
| Partial / gap | 0 / 0 |
| Re-checked cases I would still change | **3 / 21 = 14 %** (RA-1 to RA-3: wording or advisory; 0 rating changes) |
| Requirement clauses with no asserting node | 0. One clause (spelling, alternative 5) is not observable on one surface and is asserted on the other five |
| Black-box ATs owed | 0 / 8 |
| Mutants | 17 / 17 killed (M-16 and M-17 read from their own transcripts) |
| Timing rows with enough runs | 2 / 2 |
| Cited nodes that collect | 24 / 24 |

Evidence checklist for this re-audit: ✓ mode declared; ✓ every executed result names its executor (the E5 corrective agent) and I claim only the collection; ✓ Layer B: 5 cases are black-box end to end, and the rest use gesture drives with named precondition stand-ins; ✓ the Expected values were checked against the pinned values; ✓ no PII, names, hosts or paths in this section.
