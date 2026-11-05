# Inc 14 — E4 integration notes

Batch 2026-11-01-batch-101, increment 14, stage E4 (integration step). Model: Opus.
Inputs: the DeepSeek v4 Pro implementation (3 units: code, top-level documents, user guide) and the Sonnet independent tests, committed as found (`817dd2b`). Base `b7b77c4`; the LAN Linux host ran on `origin/main` `7add3d6`, which is code-identical to `b7b77c4` (the two commits above it touch only `.dev-flow/`).
Records read: `01-requirements.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md` (rounds 1 and 2, addenda N-1 … N-3), `codewire/graph-inc14.md`, `02-test-cases.md`, `E4-impl-notes-{code,top,guide}.md`, `E4-tester-notes.md`.

## 1. Verdict

**GREEN on the LAN Linux host.** The implementation follows the approved graph: **no source file and no document changed at integration.** All 6 first-run failures were in the tests (5) or in a stale registry bound (1). Every fix is in a test file; no assertion was weakened — each now pins the graph's binding text exactly. The two later failures outside the slice were a known load flake and a harness artifact of my own `--basetemp`; both passed on re-run.

## 2. Failures met

### First run, focused set (`int-01-first-run.txt`): 6 failed, 227 passed, 3 skipped

| # | Test (case) | Cause | Who was wrong | Fix |
|---|---|---|---|---|
| 1–4 | `test_r_doc_guide_1_passages_describe_1_0_0[passage-1/4/7/8]` (R-DOC-GUIDE.1/1, /4, /7, /8) | the test pinned `(capture taken before 1.0.0)` with a closing parenthesis; graph interface I-5 (binding) defines the note as the opening text `(capture taken before 1.0.0` followed by `:` and what the capture shows, and every graph passage /1, /4, /7, /8 is written that way; the guide copies the graph exactly | test (the case rows and the R-DOC-GUIDE.1 measure carry the same slip) | SR-1: `_BEFORE = "(capture taken before 1.0.0"` (`tests/test_b101_help_legend_docs.py:1442`) |
| 5 | `test_r_doc_security_1_1_policy_names_private_path` (R-DOC-SECURITY.1/1) | (a) the graph's text sets the UI name in bold (`**Security** tab`), so the literal `Security tab` is absent from the raw Markdown; (b) the test's regex required `do not / don't / never … public issue`, but the graph's text and its example 1/1 say `not in a public issue` | test | match the rendered words (`**` removed) and pin the graph example's exact substring `not in a public issue` (`tests/test_b101_help_legend_docs.py:1224-1230`) — stricter than the regex it replaces |
| 6 | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` | the guard scans `tests/**/*.py`, support modules included (precedent: `tests/support/b100_links.py`); the tester counted +1, the corpus grew by 2 | stale bound | TC-607 `EXPECTED_SCANNED_TEST_FILES` 250 → **252**, measured by the guard and by an independent `find tests -name '*.py'` minus the four excluded directories (both 252) (`tests/test_id_registry.py:173-175`) |

### Wider set (after the fixes)

| Test | Transcript | Cause | Outcome |
|---|---|---|---|
| `tests/test_b97_flow_execution.py::test_tc_b97_55_input_queued_during_a_run_starts_no_second_run` | `int-03` (4 calls for one Run) | load flake: host load average 15–19 on 8 cores from another agent's run sharing the host; already recorded as a load flake in batch-97 Inc-6 (`increment-006.md:100`). Inc 14 changes no flow-execution code | passed 3 of 3 isolated (`int-04`) |
| `tests/test_tui_snapshot.py::test_tc016s_snapshot_setup_loads_only_public_fixtures` | `int-05` | harness: the test requires `pytest` or `snapshot_public` in the temp path; my `--basetemp=/tmp/s19_i14_bt` had neither | passed with `--basetemp=/tmp/pytest-s19_i14_bt` (`int-06`) |

## 3. Orchestrator rulings on the tester's ambiguities

- **OR-1** — case R-WHELP.19/2's expected value is `12587007` (`0x00C00FFF`). The case row is fixed (`02-test-cases.md`, the Expected result cell); the test already pinned 12587007 and passes.
- **OR-2** — pinning the row mark + bytes pattern (`✓ 256 B`) for the unlabelled ranges coverage column (R-WHELP.12/2): accepted; the test passes.
- **OR-3** — document checks pin the exact substrings the cases quote: accepted (the graph's texts are binding, so a paraphrase is a defect). Applied in reverse too: where a test pinned text that the graph does not say (SR-1, the SECURITY regex), the test was brought to the graph's exact text.
- **OR-4** — AT-285 reads single-key cells; paired cells are guarded by R-DOC-README.3/1: accepted; both pass.
- **OR-5** — the N-2 hold-out group stays identifiable: `test_r_doc_security_1_1_policy_names_private_path`, `test_r_doc_security_2_1_supported_versions`, `test_r_doc_security_1_3_readme_links_the_policy` (all in `tests/test_b101_help_legend_docs.py`, under the `SECURITY.md group (hold-out unit, ruling N-2)` banner). `SECURITY.md` stays in the branch; the hold-out decision is the orchestrator's at merge time.
- **OR-6** — R-WHELP.26/2 reuses Inc 8's `tests/test_b101_flow_ext_copy.py::test_r_flow_crc_4_designer_template_is_named_in_the_flow` (passed in `int-02`); R-DOC-SECURITY.1/2 is E5 `gh api` evidence: accepted.

## 4. Seam rulings

- **SR-1** — The capture note is the graph's I-5 text: `(capture taken before 1.0.0` opening a parenthesis that continues with `: <what the capture shows>`. The `)`-closed spelling in the R-DOC-GUIDE.1 measure, in E1 ruling D-5 and in case rows R-DOC-GUIDE.1/1, /4, /7, /8 is a records slip; the graph's passages (binding) and the shipped guide agree. Smallest fix: the test pins the I-5 text. The records correction goes to E5 (§6).

## 5. Runs and counts

All runs: LAN Linux host, conda env `s19ci` (Python 3.11.18), detached worktree at `origin/main` `7add3d6` plus the branch diff applied with `git apply`, `s19_app.__file__` printed first (the worktree's), `env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.`, `pytest -q -p no:cacheprovider -n 8`, `timeout 2400`. Transcripts (redacted) in `.dev-flow/2026-11-01-batch-101/evidence/inc-14/`.

| Run | Set | Result | Transcript |
|---|---|---|---|
| int-01 | as delivered: new file, the 3 re-bodied files, `test_docs_canon.py`, `test_id_registry.py`, `test_suite_hygiene.py`, `test_b101_flow_ext_copy.py` | 6 failed, 227 passed, 3 skipped | `int-01-first-run.txt` |
| int-02x | the whole GREEN set in one run | stopped by me at ~31 of 40 min (host load from another agent's run); no summary; superseded by int-02/03/05 | `int-02x-combined-killed-at-timeout.txt` |
| int-02 | group A, corrected: new file, `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_docs_canon.py`, `test_id_registry.py`, `test_suite_hygiene.py`, `test_engine_unchanged.py`, `test_requirements_canon.py`, `test_b101_flow_ext_copy.py`, `test_tui_legend.py`, `test_legend_{map_sheet,n8,two_pane,scope_and_logwidth}.py`, `test_tui_directionb.py` | **505 passed, 3 skipped, 0 failed** | `int-02-group-a-inc14-and-guards.txt` |
| int-03 | group B (importers of `window_help` / `legend`): `test_b97_{check_editor,chips_help,flow_builder,flow_execution,key_bar,patch_editor,width}.py`, `test_b99_bytes_field.py`, `test_b100_{focus,load_dialog}.py` | 1 failed (load flake, §2), 669 passed, 10 skipped | `int-03-group-b-b97-b99-b100.txt` |
| int-04 | the two TC-B97-55 nodes, isolated, 3 times | 2 passed × 3 | `int-04-tc-b97-55-isolated-reruns.txt` |
| int-05 | group C: `test_report_service.py`, `test_segment_split_window.py`, `test_tui_diff_screen.py`, `test_tui_report_seam.py`, `test_tui_theme.py`, `test_tui_snapshot.py`, `test_help_toggle_and_a2l_panel.py` | 1 failed (harness basetemp, §2), 203 passed, 29 skipped | `int-05-group-c-report-split-diff-snapshot.txt` |
| int-06 | `test_tui_snapshot.py`, `--basetemp` under `pytest-…`, `-rs` | 4 passed, 29 skipped | `int-06-snapshot-rerun-pytest-basetemp.txt` |

- New file `tests/test_b101_help_legend_docs.py`: all collected nodes pass in int-02 (65 per the tester's count; not re-counted per file because the runs are batched).
- **Skips.** int-06 itemises 29: `pytest-textual-snapshot not installed (dev-only optional extra)` — the SVG snapshot tests did not run (§6). The 3 skips of int-02 and the 10 of int-03 were not itemised (`-rs` was off for those runs); the files hold Windows-only `skipif` arms (3 in `test_b101_flow_ext_copy.py`, several in `test_b100_load_dialog.py`) and git-history arms, none in an Inc 14 file. `not-run` itemisation, stated as such.
- **Law guards** (repo `CLAUDE.md`; no `AGENTS.md` exists): `test_engine_unchanged.py`, `test_tui_directionb.py` (incl. `test_tc031_*`), `test_requirements_canon.py`, `test_id_registry.py`, plus `test_suite_hygiene.py` — all in int-02, 0 failed.
- `02-test-cases.md`: Result cell of 68 cases set to `verified (linux, int-02)`; R-DOC-SECURITY.1/2 stays `not_run` (E5 evidence). OR-1 fixed the R-WHELP.19/2 expected value. No other column touched.
- Changed at integration: `tests/test_b101_help_legend_docs.py` (SR-1, the SECURITY check), `tests/test_id_registry.py` (TC-607 bound and its comment), `02-test-cases.md`, this file, `steps.log`, the evidence transcripts. **No source or document file changed.**
- Remote worktree `~/work/s19_i14` and my scratch files on the host were removed at the end; no other worktree was touched.

## 6. Left for E5

**Merge precondition and hold-out (N-2, A-6, S-1):**
1. Run `gh api repos/jav201/s19_app/private-vulnerability-reporting` and save the dated transcript as `evidence/inc14/gh-pvr.txt` (case R-DOC-SECURITY.1/2). At E1 it read `{"enabled":false}`. If still `false` at merge, hold out `SECURITY.md` **and** the three `test_r_doc_security_*` tests (the README `SECURITY.md` link test is one of them). **Correction to the tester's note:** `test_r_doc_readme_4_2_linked_documents_exist` names only `CHANGELOG.md` but also asserts that *every* README link target exists (`tests/test_b101_help_legend_docs.py:1195-1199`), so holding out `SECURITY.md` alone turns it RED. The README `## Documentation` row linking `SECURITY.md` has to be held out with the file — the orchestrator decides how at merge.

**Records corrections** (the integration changed only Result cells and OR-1):
2. SR-1: R-DOC-GUIDE.1 measure, E1 ruling D-5 and case rows R-DOC-GUIDE.1/1, /4, /7, /8 → the note is `(capture taken before 1.0.0` (graph I-5), not `(capture taken before 1.0.0)`.
3. Coverage column of `02-test-cases.md` still reads `gap` for the rows E4 now covers; the tester's `full` / `partial` marks are in the Tests column — the E5 coverage audit sets the column.
4. Tester note "EXPECTED_SCANNED_TEST_FILES grows by 1 (the support module is not a test file)" is wrong: the glob scans `tests/support/`; measured 252.

**Not run here / for the reviewers:**
5. SVG snapshot tests (29) did not run: `pytest-textual-snapshot` is not installed in `s19ci`. A text scan of `tests/__snapshots__/` finds neither the old nor the new legend lines (`double-click`, `glyph`), so no baseline is expected to move, but this is a scan, not a run.
6. The full suite (batch end), the mutant table, `trace_check.py`, and real guide captures (D-5: re-take at the batch-end doc pass).
7. Implementer deviations to review (all in non-rendered or layout-only text, none changes a pinned string): docstring paragraph about `split_join_export` dropped and an extra legend comment (`E4-impl-notes-code.md`); SECURITY "Include:" as a bullet list (`E4-impl-notes-top.md`); the inline `[A-1]` tag omitted from guide passage /11 (`E4-impl-notes-guide.md`).
8. TC-B97-55 remains a load flake under a shared host (batch-97 Inc-6 precedent); no Inc 14 change touches it.
