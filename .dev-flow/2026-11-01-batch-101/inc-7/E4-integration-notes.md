# Inc 7 — E4 integration notes (batch-101, before/after report hardening)

Integration of the E4 implementation (`E4-impl-notes.md`, 4 source files) and the independent tests (`E4-tester-notes.md`) against the approved design (`01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `codewire/graph-inc7.md`, `E3-rulings.md` rounds 1 and 2 and the E4 addenda). Branch `b101-inc7`, rebased on main `9f9f6af`. E4 work committed as found in `9508239`. Every run used the worktree package (`s19_app.__file__` printed at the top of each transcript), an isolated `LOCALAPPDATA`, and its own `--basetemp`. No run wrote the OS clipboard. Model: Opus.

## 1. Verdict

**GREEN.** The final run of every file that carries a case node, plus the guards, is **547 passed, 1 skipped, 1 failed** (`int-04`). The one failure is `test_at_056e_a2b_diff_report_byte_identical_despite_selection`, which fails the same way on base `9f9f6af` (`int-03`). All 52 case rows of `02-test-cases.md` pass (50 covered, 2 partial).

Two failures surfaced when the integrated tree met tests outside the slice. Both were seams between the design and canon, and each got the smallest fix (§3). No source behaviour changed at integration. The only source edit is a docstring sentence that the E3 round 2 condition A-1 asks for. No assertion was weakened.

## 2. Failures met

| # | Failure | Who disagreed | Cause | Fix |
|---|---|---|---|---|
| F-1 | `tests/test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement`: 4 primitives outside the LLR-155.3 allow-list (`_write_report` `os.replace` and `unlink`, `_remove_orphan_markdown` `unlink`, `_drop_orphan_md` `unlink`) | **design vs canon** (seam SR-1) | S-3 (R-CMP-005.16/.17) adds atomic writes and orphan removal in new functions. The batch-99 census pins every `unlink` / `os.replace` to named functions per file. The slice did not list this guard. | The allow-list in `tests/test_b99_staging.py` gains the 3 functions, each with its reason, following the file's own pattern (one comment per batch). |
| F-2 | `tests/test_id_registry.py` G1, AT-280, AT-281: `AT-512 carried by test_r_cmp_004_9_1_7_symbol_cut_at_512 is not in the registry` | **design vs canon** (seam SR-2) | The E1 case table proposed the name `..._cut_at_512`, and `tools/id_registry.py` `_FUNC_ID_RE` reads `at_512` as the id AT-512. | Renamed to `test_r_cmp_004_9_1_7_symbol_cut_to_512_characters` in the test file and in `02-test-cases.md`. The body is unchanged. |
| — | `tests/test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` (unexpected `a2l_describe_tag`, `confirm_attention`) | none (pre-existing) | Fails the same way on base `9f9f6af` (`int-03`). Inc 7 touches no binding. | Not fixed (out of scope). Reported for the batch backlog. |
| — | `test_at_056e_a2b_diff_report_byte_identical_despite_selection` | none (pre-existing, known) | Fails the same way on base (`int-03`: `baseline wrote []`) | Not fixed, as instructed. |
| — | 1–2 `F` marks in the `test_tui_diff_screen.py` region of the two runs that hit the 1,800 s timeout (`int-02`, `int-02c`) | unknown | Each run was killed before its summary, so the node is not known. The host was shared with other agents' pytest runs at the time. The per-file rerun gave **53/53** (`int-02d`). | Not reproduced. **E5 reruns `tests/test_tui_diff_screen.py` in its battery.** |

Source edit at integration: the `_strip_ctl` docstring (`diff_report_service.py`) now says why no public alias of `_normalise` exists (a fifth source file, over the increment cap). This is E3 round 2 condition A-1/1. Behaviour is unchanged.

## 3. Seam rulings

- **SR-1 (F-1): extend the LLR-155.3 allow-list. Do not restructure the code.** LLR-155.3 forbids replacing or deleting an *existing final name* outside a placement function. The three new functions keep that invariant:
  - `_write_report` creates `<name>.part` exclusively, so it never overwrites. It moves the file onto the report's own fresh name, which `_diff_report_filename` chooses, and it unlinks only the `.part` it created (N-1, pinned by R-CMP-005.16/3).
  - The two orphan removals unlink only the Markdown file the same report has just written.

  Moving the primitives into the already-allowed generators would duplicate `_write_report` into two functions, and the census would still need `_drop_orphan_md`. The same-second concurrent writer that `os.replace` would overwrite is the case `write_text` already had on base. N-1 records it; it is not a regression. Records to update at E5: list `tests/test_b99_staging.py` among the touched nodes in `E1-slice.md` §4.
- **SR-2 (F-2): a test-name rule.** A node name must not hold `at_<n>` or `tc_<n>` unless it carries a registered id (`tools/id_registry.py:95`). The case's id and body stay the same.

## 4. Tester ambiguities, resolved against the records

1. **Base `e266395` vs `9f9f6af`.** `e266395` is the E1 design base, and the records' line numbers refer to it. The branch was rebased on main `9f9f6af` after Inc 2 merged, as ruled in E1-rulings "Orchestrator rulings". RED (tester) and the base checks here (`int-03`) correctly use `9f9f6af`.
2. **R-CMP-004.14/2 "equal per window".** The threshold says Markdown and HTML **row counts** are equal per window. F-E3-5 and the Definitions put the HTML side-by-side pane outside the row text format (an unmapped ASCII cell shows as a space). Comparing counts and addresses is therefore exactly what the row requires.
3. **R-CMP-004.9.1/11 leading `1) ` / `- `.** Every sink writes a literal prefix, so the payload is interior. Keeping the payload as written is correct. The test proves it can fail: it parses the same payload, unescaped, with the same reader and asserts that live tokens appear.
4. **Symbols order (A2L, then MAC).** `_run_symbol_names` keeps the `symbol_addresses` order. The pairs are built A2L first, as on base, which matches case .24/2's text `CAL\_A, CAL\_M`.
5. **Waits.** `wait_for_complete` and `wait_until` are existing idioms. No bare pause is counted. Accepted.

Implementer deviations, accepted:
- `_remove_orphan_markdown` is one private helper for the two removal arms. It behaves as the G2 node does and is now in the SR-1 allow-list.
- The composer catches `BaseException` and re-raises after the removal. This matches "re-raises" in slice #20.
- The `report_*` local names in `action_before_after_report` are only names.

## 5. E4 addenda closed

| Addendum | State | Evidence |
|---|---|---|
| A-1 + round 2 condition 1 (docstring) | `executed` | `_strip_ctl` docstring |
| Round 2 condition 2 (coupling pin) | `executed` | `test_r_cmp_004_15_3_strip_ctl_is_the_shared_visible_text` passed (`int-04`) |
| Round 2 condition 3 (backlog row: public `visible_text` alias) | `planned` | for E5 / backlog (§8) |
| A-2 / N-1 (stale `.part` untouched, `FileExistsError` propagates) | `executed` | `test_r_cmp_005_16_3_stale_part_file_is_not_touched` passed |
| A-3 (`missing_ok=True`, set after `md.written`) | `executed` | code read; `test_tc_b100_51_*` passed (`int-04`, `test_b100_busy.py`) |
| A-4 (both spellings on negatives) | `executed` | 5 sites re-pinned (diff read). New negatives on raw names are paired with positives on the escaped spelling. |
| A-5 (TC-717/718 unaffected by message escaping) | `executed` | `test_changes_symbol_entries.py` passed (`int-04`). TC-717 was re-pinned only for `c2\.json`. |
| A-6 (~4 MiB worst case) | `executed` | `int-05`, below |
| A-7 (no home folder in goldens, evidence or tests) | `executed` | grep of the goldens, the test diff and `evidence/inc-7/` is clean. Transcripts are redacted to `<HOME>`/`<USER>`/`<SCRATCH>`. The tester's `red-01` line 8 was normalised to `<HOME>`. |
| A-8 (no in-place mutation) | `executed` | `int-06`: 0 mutating calls on `mac_records`, `_a2l_enriched_tags`, `current_a2l_data`, `a2l_records` or `a2l_data` in `s19_app/`. The 36 assignments are rebindings. The Inc 7 consumers do not mutate them. |
| S-7(a) differential hex test (M19) | `executed` | `test_r_cmp_004_14_7_rows_match_render_hex_view_for_all_byte_values` passed: A block = `render_hex_view` row for row, plus spelled-out rows at 0x20, 0x7E and 0x7F |
| S-6 reader census + extended Mode-B AST guard | `executed` | `test_r_cmp_004_9_1_11_*`, `test_mode_b_cell_guard_flags_a_planted_cell` passed |

**A-6 numbers** (`int-05`). Two 4 MiB images differ at every byte (one changed run). Each report ran in its own process. Wall times are upper bounds, because other agents' test runs shared the host.

| Report | Wall | Peak working set | `.md` | `.html` |
|---|---|---|---|---|
| manual A↔B (compare + both generators, as the worker calls them) | 32.6 s (compare 7.9, maps 6.8, md 4.9, html 13.1) | 5,157 MiB | 85,459,849 B (81.5 MiB) | 1,183,319,853 B (1.13 GiB) |
| before/after (composer) | 32.2 s | 5,157 MiB | 85,460,393 B | 1,183,320,572 B |

This agrees with OBS-7-4's extrapolation (about 0.3 GB of HTML per MiB). Both reports run on `@work(thread=True)` workers, and the callers return without a wait or join (`int-06`). The UI thread is not blocked. OBS-7-5 (flow A2B on the UI thread) is unchanged and remains an admitted limit. **New fact for the orchestrator:** about 5 GB peak memory at 4 MiB. A larger fully changed image can hit `MemoryError`. That error surfaces as `Diff report failed: MemoryError`, and with R-CMP-005.16 it leaves no partial file. The OBS-7-4 backlog row (HTML pane size: a shared CSS class instead of inline style per byte) is the lever.

## 6. Counts per transcript (`evidence/inc-7/`)

| Transcript | Scope | Result |
|---|---|---|
| `int-01-touched-files.txt` | the 6 touched test files, tree `9508239` | 204 passed, 1 failed (056e) |
| `int-02-green-set-single-run-timeout.txt` | whole GREEN set (32 files), one process | killed at 1,800 s at 70% (exit 124); 7 `F` marks, no summary |
| `int-02a-green-chunk-a.txt` | 11 files (b100_busy … id_registry) | 336 passed, 1 skipped, 4 failed (F-1, F-2 ×3) |
| `int-02b-green-chunk-b.txt` | 13 files (render_hexview, report_*, requirements_canon, suite_hygiene, check_*) | 439 passed |
| `int-02c-green-chunk-c-timeout.txt` | 8 TUI files, one process | killed at 1,800 s at 79% (exit 124) |
| `int-02d-green-per-file-rerun.txt` | chunk C file by file, plus the 3 files fixed for F-1/F-2 | 561 passed, 2 failed (b78_03 and 056e, both pre-existing): commandbar 44+1F, diff_screen 53, directionb 184 (incl. the TC-031 engine guards), flow_builder_b94 5, map_big 107, patch_json 17, report_filter_surface 13+1F, report_seam 28, b99_staging 31, id_registry 12, diff_report_service 67 |
| `int-03-base-preexisting.txt` | base `9f9f6af`, temporary worktree (removed) | 056e failed; commandbar b78_03 failed |
| `int-04-final-case-nodes.txt` | final tree: the 6 case files, flow_builder_b94, b100_busy, b99_staging, id_registry, engine_unchanged, requirements_canon, render_hexview, report_markup_safety | **547 passed, 1 skipped, 1 failed (056e)** |
| `int-05-a6-worst-case.txt` | A-6 | §5 |
| `int-06-a8-no-mutation-grep.txt` | A-8 and the worker-join check | 0 matches |

`EXPECTED_SCANNED_TEST_FILES` is unchanged (248) **by measurement**: `test_id_registry.py` passes 12/12 with no edit, and Inc 7 adds no test module (D-8). The `serial_timing` arms were deselected (1 node) and were not run.

## 7. Files changed at integration

`tests/test_b99_staging.py` (SR-1 allow-list), `tests/test_diff_report_service.py` (SR-2 rename), `s19_app/tui/services/diff_report_service.py` (docstring only), `02-test-cases.md` (Coverage, Result, one header note, the rename), `evidence/inc-7/int-*.txt`, the `red-01` redaction form, this file and `steps.log`. The source file count stays 4.

## 8. Left for E5

- Mutants M1–M19 (`02-test-cases.md`), run in a copy of the tree.
- The Linux run and the full battery. Rerun `tests/test_tui_diff_screen.py`, because of the unattributed timeout-run `F` (§2).
- Canon at integration: the new and changed rows, the R-CMP-004.9 split, and the CTX-DIFFREPORT / CTX-BEFOREAFTER terms (`01-requirements.md` "Requirement-level changes"). Record SR-1's touched node and the `test_at_056a` re-pin in `E1-slice.md` §4.
- Backlog rows: a public `visible_text` alias in `markdown_safety` (round 2 condition 3); OBS-7-1, -2, -4 (HTML pane size, now with the ~5 GB / 4 MiB measurement), -5 (D16-15) and -6; the pre-existing `test_at_b78_03` palette freeze failure.
- Optional L-2 (log "orphan not removed" in the before/after worker): not done. The record says it is acceptable as is.
- Observation: the tester's new tests embed a raw U+202E in the source at `tests/test_diff_report_service.py`, 7 lines near 2208–2360. The repo already does this (`tests/test_b100_busy.py:1065`). A reviewer may prefer the `‮` escape.
