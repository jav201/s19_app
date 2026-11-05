# Inc 7 — E5 coverage audit (independent; did not write the test cases)

Batch 2026-11-01-batch-101, increment 7. Tree: head `90ea8ae` (worktree `b101-inc7`). Mode: **validation** (an audit of the mapping, not a run). Inputs: `01-requirements.md`, `02-test-cases.md` (52 cases), `E4-tester-notes.md`, `E4-integration-notes.md` (SR-1, SR-2), `git diff main...HEAD -- tests`, and the mapping rules TCP-MAP-1 … 8 (`s19w/test-cases/TC-PROFILE.md`; PLAN.md and inc-7 do not restate them).

Rule applied: a node verifies a case only if it **asserts the case's expected result**. `full` only when the product writes what is asserted. A stand-in echo, a fixture that already shows the result, an entry no product route calls, or a pinned value that differs from the case's Expected each make it `partial` (TCP-MAP-1, -5, -6, -7). Cases and nodes are many-to-many (TCP-MAP-2). A case is `covered` when its nodes together assert every clause of its Expected, each through a product route.

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 52 / 52 |
| Cited node ids | 57 distinct. **57/57 collect** (`--collect-only`, s19env interpreter, `s19_app.__file__` = the worktree package, isolated `LOCALAPPDATA`) |
| Nodes passed on the integrated tree | 57/57 `PASSED` in `evidence/inc-7/int-04-final-case-nodes.txt` (**executed by the E4 integrator**, tree `9508239` + integration edits; `9508239..90ea8ae` changes only a docstring, the SR-1 allow-list and the SR-2 rename). I ran no test. |
| Coverage before audit | 50 covered, 2 partial, 0 gap |
| **Coverage after audit** | **51 covered, 1 partial, 0 gap** |
| Cases changed (any change: coverage, node label, node set or Expected text) | **8 / 52 = 15.4 %** |
| Cases whose coverage state changed | 3 / 52 = 5.8 % (two up, one down) |
| `gap` rows with passing full tests | 0 (no row is `gap`) |
| Cases whose Expected no longer matches what the test pins | 3 (§3) |
| Requirement clauses with no case | 5 (§4) |
| Owed black-box ATs | 3, plus 1 strengthening and 1 case row (§5) |

## 2. Change table

| # | Case | Old → new | Reason |
|---|---|---|---|
| C-1 | R-BEFORE-AFTER-REPORT-001.24/4 | node `partial` → `full`; coverage `partial` → `covered` | `test_tc311_no_filter_generator_kwargs_shape_is_todays` asserts `set(kwargs) == todays_keys` (the 7 keys) on both generator calls with no artifact input. That is the case's whole Expected, and the composer itself produces the kwargs. The spies only stand in for the return value, which is not asserted, so TCP-MAP-5(a) does not apply. The "no-artifact arm only" qualifier describes the case itself; the case has no other arm. |
| C-2 | R-CMP-004.14/6 | node `partial` → `full`; coverage `partial` → `covered` | `test_default_kwargs_output_byte_identical_pre_change_golden` asserts the whole `.md` and `.html` bytes equal `_PRE_CHANGE_*_TEMPLATE`. The diff touches only the two label lines of the MD template; every hex line and the whole HTML template are unchanged. So it asserts "hex lines unchanged" exactly, and more besides. |
| C-3 | R-CMP-004.14/2 | node `full` → `partial`; coverage `covered` → `partial` | The Expected says each pane is "equal to the Markdown A and B blocks", but the test pins only the row count and `row[:10]` (the address). Full equality cannot hold: in the HTML pane, an unmapped byte's ASCII cell is a space (F-E3-5, Definitions), and rows `0x0FC0 … 0x0FF0` are unmapped. The requirement threshold asks only for equal counts, which is met. **Fix (either one):** reword the Expected to "644 rows each, same addresses as the Markdown A and B blocks", or tighten the test to `row[:58]` (address + 16 byte cells, equal in both files). Either fix returns the case to `covered`. |
| C-4 | R-CMP-005.16/2 | node set: `test_r_cmp_005_16_3_stale_part_file_is_not_touched` removed from this row | That node pins the opposite of this case: one stale `.part` stays and `FileExistsError` propagates (N-1 / A-2). This case expects 0 `.part`. Coverage stays `covered`: `…_16_2_…` (generator HTML arm) and `test_before_after_report.py::…_16_4_…` (composer arm) are each full for their arm. The `_16_3` node backs no case row (§4, §5 R-5). |
| C-5 | R-CMP-004.9.1/9 | node labels: `test_tc_b94_24_…` `full` → `partial (flow arm only)`; `test_at_b94_18_…` "unchanged guard" → `partial (external arm, Flow Builder)`; coverage stays `covered` | `tc_b94_24`'s external input is `base`, so it holds no `[red]`. It pins only `patch\.out` (one escape), and it pins it through `run_flow`, not the Flow Builder. `at_b94_18` drives the Flow Builder Run button and asserts `\[red\]` in the external label and no raw `[red]`. A double escape (`\\\[red\\\]`) holds no `\[red\]` substring, so that positive also excludes `\\[`. Together the two nodes cover every clause, and AT-B94-18 shows the Run button reaches `run_flow` (TCP-MAP-7 satisfied). The flow arm of this "(AT)" case is still not observed through keys (§5 R-4). |
| C-6 | R-CMP-004.9.1/6 | `test_tc318_hostile_filter_name_sanitized_md_html` "(re-pinned)" → `partial` | It pins a different input and line: U+0001 and CR make it `a\|b\`c\<b\>� d\.json`. That is not this case's Expected `a\|b\`c\<b\>d\.json`. The case remains `covered` by `…_9_1_6_…` (full, exact line). |
| C-7 | R-CMP-004.15/2 | `test_r_cmp_004_15_3_strip_ctl_is_the_shared_visible_text` "(coupling pin)" → `supporting, not verifying` | It asserts private `_strip_ctl == _normalise`, not text in either report file (TCP-MAP-1). It keeps the E3 round 2 coupling, but it verifies no case. The case remains `covered` by `…_15_2_…` (full). |
| C-8 | R-CMP-004.9.1/11 | unlabelled census nodes → `full` (AST-guard clause) | `test_mode_b_in_a_table_cell_is_still_forbidden_at_every_call_site` (now reads `diff_report_service.py`, flags `_md_path`) and `test_mode_b_cell_guard_flags_a_planted_cell` (its counterfactual) assert exactly the case's third clause. The reader test is full for the token and column clauses. Its payload holds every listed element (U+2028 confirmed in the source). Note: the case's Inputs name the composer, but no node drives it. The generator gets the provenance and linkage directly, and the composer calls the same generator. |

**The three composer tests that were RED on base only by `TypeError`** (.35/1, .24/1, .24/2). Their coverage stays `full`: each asserts the exact text the product writes. But an interface RED proves only that the keyword was missing. It does not show the oracle fails on wrong output. Proof status at audit time comes from the E5 mutant runner's uncommitted transcripts, which I read without changing anything:
- .35/1: the **A2L half is proven** (`mut-M6.txt`: M6 drops `a2l_data`, the node fails on the artifact line). The **MAC half (`mac=used (1/1)`) is not proven**, because no mutant drops the MAC from `compare_images`.
- .24/1: **proven** (`mut-M8.txt`: M8 drops `a2l_records`, `.24/1` and `.24/3` fail). M9 is pending.
- .24/2: **not proven**. No mutant targets it, and M8 was not run on this node. Owed mutant: the composer drops `mac_records` from the generator kwargs, which should leave `CAL\_A` alone in the cell → RED.

## 3. Cases whose Expected no longer matches what the test pins

| Case | Expected says | Test pins | Action |
|---|---|---|---|
| R-CMP-004.14/2 | panes "equal to the Markdown A and B blocks" | count 644 + address prefix | C-3: reword or tighten |
| R-CMP-005.16/2 | 0 `.part` | (`_16_3`) 1 stale `.part` kept, `FileExistsError` | C-4: node removed from the row |
| R-CMP-004.9.1/6 | `a\|b\`c\<b\>d\.json` | (`tc318`) `a\|b\`c\<b\>� d\.json` | C-6: labelled partial |

Input deviations that change no verdict: in R-CMP-004.15/1 each field carries one of U+0085 / U+202E rather than both (each character still appears in at least two fields), and the generators get provenance and linkage directly instead of through the composer. The key-`b` cases (.35/2, .24/3, R-CMP-003.2/1) seed `app.current_a2l_data` with a hand-built 2-tag payload instead of loading an A2L file. That is a precondition the trigger cannot produce, so TCP-MAP-5(c) does not apply. The product's `_compute_a2l_enriched_tags` runs on it.

## 4. Requirement clauses with no case

| Requirement / clause | Why it matters |
|---|---|
| R-BEFORE-AFTER-REPORT-001.35 and .24, the **loaded MAC** on the shipped route (key `b` with a MAC file loaded → `mac=used (k/n)`; Symbols names the MAC record) | The only key-`b` MAC case is the absent arm (R-CMP-003.2/1). The app branch that forwards `loaded.mac_records` when `mac_path is not None` (`app.py`, `action_before_after_report`) is asserted by no node. A mutant that "never forwards the MAC" survives all 52 cases. |
| R-CMP-005.16 threshold: "the status is still R-CMP-005.10's / R-BEFORE-AFTER-REPORT-001.17's text" after a failed write | .16/1, /2 and the `_16_4` node are service- or composer-level and read no status. |
| R-CMP-005.17 threshold, before/after arm: status `Before/after report failed: <error type>: <message>` unchanged | .17/2 is composer-level. Only the A↔B arm (.17/1) reads the status through the UI. |
| R-CMP-004.9.2 threshold "4/4 fields (2 image paths, …)" | Image B's path is never planted. .9.2/1 plants A only. Low risk, because both lines go through one `_image_line`. |
| E3 addendum A-2 / N-1 (stale `.part` untouched, `FileExistsError` propagates) and the CTX-DIFFREPORT `file write` term | The node `test_r_cmp_005_16_3_stale_part_file_is_not_touched` exists and passed, but no case row cites it. |

## 5. Owed list

| Id | Kind | What | Requirement |
|---|---|---|---|
| R-1 | black-box AT (key `b`) | Load an image **with a MAC file**, apply, confirm save-back, press `b`. Expect both artifact lines `mac=used (k/n)` and the run's Symbols cell naming the MAC record (escaped). | .35, .24 |
| R-2 | black-box AT (Diff screen Report control / key `7`) | Write fails mid-way (`OSError`). Expect the status `Diff report failed: OSError: …` and 0 report and 0 `.part` files in `reports/`. | R-CMP-005.16 (status clause), R-CMP-005.10 |
| R-3 | black-box AT (key `b`) | The HTML generator raises, and in a second arm refuses. Expect the status `Before/after report failed: <type>: <msg>` (refused arm: its refusal text) and 0 `.md` / `.html` left. | R-CMP-005.17, R-BEFORE-AFTER-REPORT-001.17 |
| R-4 | AT strengthening | In `test_at_b94_18_…`'s report arm, also pin the flow-input Image A label (one escape, no `\\`). That makes .9.1/9 observed wholly through the Flow Builder. | R-CMP-004.9.1/9 |
| R-5 | case row | Add `R-CMP-005.16/3` (N-1: a stale `.part` keeps its bytes, `FileExistsError` propagates) and cite `…_16_3_…` there (C-4). | R-CMP-005.16 / A-2 |
| R-6 | negative control (mutant) | Composer drops `mac_records` from the generator kwargs → .24/2 RED. Composer drops the MAC from `compare_images` → .35/1 RED. | .24/2, .35/1 |

Naming note, no action needed: node `…_16_4_…` backs case /2, `…_15_3_…` backs no /3, and `…_16_3_…` has no case row (R-5).

## 6. Per-case verdict (after audit)

`=` means unchanged from `02-test-cases.md`.

| Case | Coverage | Note |
|---|---|---|
| .32/1, .33/1, .34/1 | covered = | exact title / `<title>` / first `<h1>`; negatives on `Diff report` |
| .32/2 | covered = | AT-054b golden, byte-identical (canonical form); golden line 1 re-pinned |
| .32/3, .34/2 | covered = | AT-053b: line 0, line 2, heading once; `<h1>` index + 1 is the `<h2>` |
| R-CMP-004.1/1, /2 | covered = | full nodes assert all three titles / MD + HTML |
| .35/1 | covered = | full; proof: A2L half by M6, MAC half unproven (§2) |
| .35/2 | covered = | key `b`; `a2l=used (k/2)`, k ≥ 1 on both lines |
| R-CMP-003.2/1 | covered = | key `b`; `mac=absent`, no `mac=unused`, A2L used |
| R-CMP-003.2/2 | covered = | composer; exact `summary=none; a2l=absent; mac=absent` lines |
| .24/1 | covered = | exact MD row + HTML cell; proven by M8 |
| .24/2 | covered = | exact cells; proof owed (R-6) |
| .24/3 | covered = | key `b`; exact escaped row; M8 kills it |
| .24/4 | **covered (C-1)** | was partial |
| R-CMP-004.5/1 | covered = | `-` for WIDE, `HERE` named |
| .11/1, .11/2 | covered = | exact diagnostics; status via a `set_status` wrapper that records the product's own message; 0 files |
| R-CMP-004.14/1, /3, /4, /5 | covered = | independent `_oracle_rows`; counts, first and last rows, 0 cap lines |
| R-CMP-004.14/2 | **partial (C-3)** | Expected vs pinned |
| R-CMP-004.14/6 | **covered (C-2)** | was partial |
| R-CMP-004.14/7 | covered = | equals `render_hex_view` row for row + oracle + spelled rows |
| R-CMP-005.16/1 | covered = | half-write injection asserted reached (`hit`); 0 files |
| R-CMP-005.16/2 | covered = **(C-4)** | `_16_3` removed from the row |
| R-CMP-005.17/1 | covered = | Diff screen Report control (compare stubbed, MD generator real); status + 0 files |
| R-CMP-005.17/2 | covered = | raise and refuse arms; 0 `.md` |
| R-CMP-004.9.1/1, /2, /3, /4, /5, /7, /8, /10, /12 | covered = | exact escaped text; /5's census predicate has no product caller (used by tests only, TCP-MAP-7 note); its rendered rows are asserted exactly |
| R-CMP-004.9.1/6 | covered = **(C-6)** | tc318 labelled partial |
| R-CMP-004.9.1/9 | covered = **(C-5)** | two partial arms, union full |
| R-CMP-004.9.1/11 | covered = **(C-8)** | AST nodes labelled; composer arm not driven |
| R-CMP-004.9.2/1, /2, /3, /4 | covered = | 2 backticks per line; golden; identity path |
| R-CMP-004.8/1 | covered = | no `\_` / `\.` in HTML |
| R-CMP-004.15/1 | covered = | input deviation (§3) |
| R-CMP-004.15/2 | covered = **(C-7)** | `_15_3` supporting only |
| .21/1, .21/2, .22/1 | covered = | `CTL�SYM` both files, no `CTLSYM`; path `�`; 10 structural pipes |

## Re-audit (2026-11-05)

Scope: only the cases the E5 corrective pass changed or added (`E5-rulings.md` C-1 … C-8, `E5-corrective-notes.md`), at head `f24d71e`. Mode: **validation** (an audit of the mapping, not a run). Inputs: `git diff 90ea8ae..HEAD -- I/01-requirements.md I/02-test-cases.md tests/ s19_app/`, the `e5c-*` transcripts. Every pass/kill below was **executed by the E5 corrective agent** (Linux LAN host; the C-1 arm on Windows) and read from its transcripts. I ran no test: `--collect-only` only.

### R.1 Earlier issues: closed

| Earlier issue | Status | Evidence |
|---|---|---|
| §4/R-1 loaded MAC through key `b` | closed | `…_001_35_3_bkey_loaded_mac_is_used`: key `b` pressed by the pilot; MAC loaded through the app's own `_load_mac_file` + `_merge_mac_with_existing_primary` (the same two calls as the load branch, `app.py` ~14165), not seeded; exact artifact lines (both files, both images), exact Symbols row/cell. M26 (never forward) and M24/M25 kill it on output text (`e5c-mut-M24/25/26.txt`). |
| §4/R-2 R-CMP-005.16 status text | closed | `…_16_3_report_control_failed_write_status[md/html]`: key `7`, Compare and Report by `enter`; `#diff_status` render `==` `Diff report failed: OSError: disk full`, the same line is an element of the painted `#log_line_1…4`; `hit` proves the injection was reached; `reports/` exists and is empty. Key-`b` arm `…_16_3_bkey_failed_write_status`: painted line exact; `listing == []` also proves the folder exists. |
| §4/R-3 R-CMP-005.17 before/after status | closed | `…_17_3_bkey_html_failure_status[raise/refuse]`: painted line exact for both texts; `listing == []`, `found == []`. |
| §4 image B path | closed | `…_9_2_5_image_b_path_text`: whole line equality, 2 backticks, image A line unchanged. |
| §4/R-5 N-1 node with no row | closed | row R-CMP-005.16/4 cites `…_16_3_stale_part_file_is_not_touched`; `_16_3` removed from /2. |
| R-4 AT-B94-18 assertion | closed | whole flow Image A line pinned (`source\.out [flow] …`) and no `\`; .9.1/9 is now observed wholly through the Flow Builder. |
| R-6 .35/1 MAC half, .24/2 | closed | M24 fails .35/1 at the `mac=used (1/1)` line; M25 fails .24/2 at the `CAL\_A, CAL\_M` row. Both are output-text assertion failures, not `TypeError`. |
| C-3 R-CMP-004.14/2 | closed | compares `row[:58]` (address + 16 byte cells) and the whole hex part before `  |`, row for row; Expected not reworded, now matches what is pinned. |
| C-7 `…_17_1` vacuity | closed | `reports/` asserted to be a directory before the emptiness check. |
| §2 label changes C-1, C-2, C-4 … C-8 | applied | `02-test-cases.md` rows .24/4, .14/6, .16/2, .9.1/6, .9.1/9, .15/2, .9.1/11 carry the audit labels. |

**C-2 (M22) RED proof.** Acceptable. The case pins a guarantee head already keeps (`_md_cell` escapes the pipe), so no RED on head can exist; the mutant kill is the correct proof that the oracle fails on wrong output. `e5c-mut-M22.txt` fails at the exact linkage-row assertion with raw `by|tes`, while the neighbouring pre-existing test passes under the same mutant, which is why M22 survived run 1. Limit: the kill shows only the first assertion failing; the flow-row, refusal and Applied assertions are exact-text equalities and need no separate proof.

**C-1 case text.** The CTX-DIFFREPORT `file write` term, graph I-6 and node `_write_report`, and the E3 N-1 note now say `<name>.<16 random hex digits>.part`, and that a `.part` this write did not create is never touched. That matches the source (`secrets.token_hex(8)`). M27 (back to the fixed name) kills /4 and /5 (`FileExistsError` on Linux).

**Full / partial.** All 8 new rows and every changed row are `full` under the rule: the product writes the report text and paints the status that is asserted. The stubs only inject failure (half write, a raising or refusing HTML generator) and are not asserted. Black-box notes (no verdict change): the R-2 arm sets the two path `Input` values and button focus programmatically, then presses `7` and `enter`; the written-pair status of .35/3 is compared cut to the 120-column log line, and its whole text is asserted through the `set_status` capture.

### R.2 Remaining issues

| # | Severity | Case / clause | Issue | Owed |
|---|---|---|---|---|
| RA-1 | MEDIUM (coverage of the security fix) | CTX-DIFFREPORT `file write`: "`<name>.<16 random hex digits>.part`"; R-CMP-005.16/5 | No case pins that the staging name is **unpredictable**. /4 and /5 plant only the old `<name>.part`, and M27 reverts only to that exact name. A mutant staging under any other fixed name (for example `<name>.tmp.part`) survives all 60 cases, and so would a link planted at that name. | New case R-CMP-005.16/6: spy the mode-`"x"` open in `_write_report`; the staging name matches `^<name>\.[0-9a-f]{16}\.part$` and differs between two writes. Mutant: a fixed `<name>.tmp.part` → RED. |
| RA-2 | LOW | R-CMP-005.16/4 | The Inputs still name `<ts>-diff-report.md.part` without saying it is the pre-C-1 guessable name, which can no longer collide. The case also exercises "never touched" only on the success path. A failure-path cleanup that unlinks every `*.part` in the folder survives (/1 and /2 plant no stale file). | Reword the Inputs ("a stale file at the pre-C-1 name `<name>.part`"). Add a failure arm: stale `.part` + half-write failure → the stale file keeps its bytes. |

### R.3 Totals after re-audit

| Count | Value |
|---|---|
| Cases re-checked | 19: 8 new (R-CMP-005.16/3, /4, /5, R-CMP-005.17/3, .35/3, .24/5, .22/2, R-CMP-004.9.2/5) + 11 changed (.35/1, .24/2, .24/4, R-CMP-004.14/2, /6, R-CMP-005.16/2, R-CMP-005.17/1, R-CMP-004.9.1/6, /9, /11, R-CMP-004.15/2) |
| Re-checked cases I would still change | **1 / 19 = 5.3 %** (R-CMP-005.16/4, RA-2). RA-1 adds a row; it changes no existing one. |
| Coverage | **60 covered, 0 partial, 0 gap** (the RA-1 clause has no row, so it is not counted as a gap) |
| Cited node ids | **66 distinct; 66/66 collect** (`--collect-only`, s19env, `s19_app.__file__` = the worktree package, isolated `LOCALAPPDATA`). The 66 equal the 66 `PASSED` in `e5c-final-case-nodes.txt` (executed by the E5 corrective agent; Linux). |
| Mutants | 28/28 killed as recorded in `E5-mutants.md`. I read M22 and M24 … M27: each fails on an output-text assertion or the intended `FileExistsError`. |
| Requirement clauses with no case | 1 (RA-1) |
