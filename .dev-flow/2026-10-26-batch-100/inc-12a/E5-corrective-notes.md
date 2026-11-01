# Inc 12a — E5 corrective notes

One corrective pass on `b100-inc12a` (base `71376a3`), implementing the rows `E5-rulings.md` marks **corrective**: SE5-12a-1, SE5-12a-2, SE5-12a-3, CR12a-3. Not done here: SE5-12a-4 and CR12a-1 (routed to Inc 12b integration); CR12a-2 (only if a Save abort-exit mutant survives; no survivor was sent to this pass).

Source edits: `s19_app/tui/app.py` only (3 hunks). `styles.tcss` unchanged. Test edits: `tests/test_b100_busy.py`, `tests/test_b100_recents.py`, `tests/test_report_progress.py`, `tests/test_b100_save_dialog.py` (MERGE-12a-1). Registry: `AT-TC-REGISTRY.jsonl` (TC-644 re-bound to the 2 renamed nodes). Backlog: `.dev-flow/BACKLOG-CODE.md` (1 row, SE5-12a-2 file-state line). CRLF kept in every CRLF file; the registry stays LF.

## Per id

### SE5-12a-1 (MAJOR): the status log is the control-byte choke point

- **Change:** `app.py:19862`–`:19864`, `_append_log_line`: `trimmed = safe_text(message).plain.strip()` (was `message.strip()`). So every log line, including the direct `_append_log_line(status_message)` in `_apply_prepared_load`, drops C0/C1 before it is stored or painted. Idempotent for text that was already scrubbed.
- **Arms:**
  - New `tests/test_b100_busy.py::test_tc_b100_50_control_bytes_never_reach_the_status_log` (`:1121`). It runs on Windows: `_format_coexistence_status` is patched to return `Loaded a\x1b]0;x\x07.s19 (S19 only)` (as `rev12a-security/probe_esc_log.py` arm B does), a real `load_from_path` follows, and the test asserts that the scrubbed line arrives (`Loaded a]0;x.s19 (S19 only)`) and that there are 0 C0/C1 code points in `app.log_lines`, `#log_line_1..4` and `#status_text`. A direct `_append_log_line("direct \x9b2J\x00 line")` comes out as `direct 2J line`.
  - Changed: the `ESC and BEL` arm of `test_tc_b100_50_names_paint_literally_through_load_from_path` (`:1113`–`:1118`) now asserts on `app.log_lines` plus the 4 painted `#log_line_*` rows, not on `StatusLog`. That arm stays skipped on Windows (S12a-R2-3), so it was **not-run** on this host, either RED or GREEN.
- **RED (71376a3):** the new arm FAILED: `['Loaded a\x1b]0;x\x07.s19 (S19 only)', …, 'Loaded a\x1b]0;x.s19 (S19 only)', …]`, i.e. ESC+BEL stored and ESC painted (Textual drops BEL). **GREEN:** passed.

### SE5-12a-2 (MINOR, = O-12a-1): the outcome line is scrubbed like the A2L one

- **Change:** `app.py:17702`, `_start_load_worker`: outcome `f"Loaded {painted_names([path.name])}"` (was `path.name`).
- **Arm:** the `bidi override` arm of `test_tc_b100_50_names_paint_literally_through_load_from_path` (`:1103`–`:1107`) re-adds the outcome assertion: the outcome lines `== ["Loaded fwgpj.s19"]`. The O-12a-1 comment is replaced, and the docstring is updated.
- **RED (71376a3):** FAILED `['Loaded fw‮gpj.s19'] == ['Loaded fwgpj.s19']`. **GREEN:** passed.
- **Backlog:** the file-state line (`_format_coexistence_status`, base text) is a new row in `.dev-flow/BACKLOG-CODE.md:1612` (after the S10-04 row in the batch-100 section).

### SE5-12a-3 (NIT): the exact listed name wins

- **Change:** `app.py:13682`–`:13687`, `_listed_project_name`: `listed = self.list_projects(); if name in listed: return name`, then the first `normcase` match. The docstring says why. It is still the one function that calls both `list_projects` and `normcase`: `test_tc_b100_38_one_project_match` is green.
- **Arms (`tests/test_b100_recents.py`):**
  - New `test_tc_b100_38_one_project_match_prefers_the_exact_listed_name` (`:3537`). The listing is injected as `["Proj", "proj"]`, so the arm runs on any volume. Expected: `proj`→`proj`, `Proj`→`Proj`, `PROJ`→`Proj` on Windows (`None` elsewhere).
  - New `test_tc_b100_38_picking_proj_loads_proj_when_proj_differs_by_case` (`:3559`). On disk, the folders `Proj` and `proj` each hold a data file; `_handle_load_project("proj")` must give `current_project == "proj"`. The arm skips when the volume cannot hold both folders (the NTFS default).
- **RED (71376a3):** the unit arm FAILED with `{'proj': 'Proj', …}`. The on-disk arm was skipped on the default basetemp. It was then run with `--basetemp` under a scratch folder set case-sensitive (`fsutil file setCaseSensitiveInfo …/corr12a/bt/csparent enable`; new subfolders inherit the flag). There it FAILED: `('Proj', ["Loaded project 'Proj' -> firmware.s19 - …"])`. This is the reviewer's scenario, executed. **GREEN:** the unit arm passed; the on-disk arm passed on the case-sensitive folder and skips on the default one.

### CR12a-3 (NIT): the two re-pinned report tests are renamed

- **Change (tests only):** in `tests/test_report_progress.py`, `test_report_generation_drives_progress_bar_to_100` → `test_report_generation_drives_progress_bar_then_clears_it` (`:49`), and `test_finish_generate_report_completes_bar` → `test_finish_generate_report_clears_bar` (`:157`). Each docstring keeps a `History:` line with the old name. `AT-TC-REGISTRY.jsonl` TC-644 `nodes` is re-bound to the new names (spec: a renamed verifier stays LIVE, re-bound to the current node). Without that, G2 would fail. `test_id_registry.py` is green.
- **RED:** none owed for a rename (brief). **GREEN:** both renamed nodes passed (`green-03-corrective.txt`).

### MERGE-12a-1 (coordinator row): the Inc 11 arm takes the 12a generation

- **Defect:** `green-03-merged.txt` shows 2 failed, 254 passed. Both failures are `tests/test_b100_save_dialog.py::test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session[same_ranges|other_ranges]` (Inc 11 corrective arm, SE5-11-1). The arm called `_start_load_worker(loaded)` without the keyword-only `gen` that Inc 12a added. The worker raised `TypeError`, and the wait timed out.
- **Re-pin (test only):** `tests/test_b100_save_dialog.py:3792`–`:3797`: `gen = app._busy_begin_action("file_load", loaded.name)`, then `app._start_load_worker(loaded, gen=gen)`. That is the hand-off `load_from_path` makes (`app.py:14857`–`:14858`). The arm still skips the copy step, which it never ran, and the open Save dialog does not trigger the Inc 10 question. What it proves is unchanged: a load landing under the dialog rebuilds the session; with the same ranges the image is derived from the new file, and with other ranges the app stays up.
- **RED:** none owed for a re-pin. The pre-re-pin failure is the `TypeError` in `green-03-merged.txt`. **GREEN:** `green-06-merge-repin.txt` has 2 passed, both layouts, in 21 s.

## Evidence (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/`; each transcript prints `s19_app.__file__`)

| File | Tree | Result |
|---|---|---|
| `red-03-corrective.txt` | `base12ac` (71376a3, test files copied in, then restored) | run 1: **3 failed, 2 skipped** (bidi outcome, control-bytes arm, exact-match unit arm FAIL; ESC arm skipped on Windows; on-disk case arm skipped). run 2 (case-sensitive folder): on-disk case arm **1 failed** |
| `green-03-corrective.txt` | worktree | run 1: **9 passed, 2 skipped** (same 2 skips); run 2 (case-sensitive folder): **1 passed** |
| `green-04-new-and-guards.txt` | worktree | **130 passed, 2 skipped**: 23 `test_b100_busy.py` nodes on the changed code, 18 `test_b100_recents.py` project-match and pick nodes, plus `test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`. The skips are the Windows ESC arm and the 130-character picked-row arm (the host refuses the long temp path; pre-existing) |
| `green-06-merge-repin.txt` | worktree | MERGE-12a-1: **2 passed** (`same_ranges`, `other_ranges`) |
| `green-05-busy-file.txt` | worktree | the whole `tests/test_b100_busy.py` once: **81 passed, 1 skipped** (the ESC arm) in 338 s |

Env for every run: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, `LOCALAPPDATA` and `--basetemp` under the scratchpad `corr12a/`, s19env Python. No timing arm failed, so no re-run was needed. Whole touched modules and the full suite were not run (operator override).

## Source sha256[:16]

| File | Before (71376a3, CRLF working copy) | After |
|---|---|---|
| `s19_app/tui/app.py` | `2d1908b14236004f` | `15ffc7bdbb599615` |
| `s19_app/tui/styles.tcss` | `f7b4f75911b296a4` | `f7b4f75911b296a4` (unchanged) |

## Not done / open

- The `ESC and BEL` arm (Linux CI only) is changed but **not-run** here; it first runs in CI.
- CR12a-2: no mutant survivor reached this pass, so no AST rule was added.
- The case-sensitive scratch folder `…/scratchpad/corr12a/bt/csparent` is scratch only. Nothing in the repo depends on it.
