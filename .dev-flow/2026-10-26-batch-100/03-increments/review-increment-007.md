# Code Review — Increment 007 (batch-100, "`files` digests, every problem listed, caps, private staging, `derived_from`", HLR-169 / LLR-168.4)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: `software-dev` implemented it, not me. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc7`, branch `b100-inc7`, base `80052cb`, uncommitted. Source sha256 (16): `manifest_writer.py` `b3a8da7ae550bda5`, `variant_execution_service.py` `bd33c8be189d2c87`, `app.py` `0e29d80841fa3f38`, `screens.py` `e23ea8f72bc93153`. These equal the packet §4 "final source hashes". New test files: `test_b100_project_check.py` `bdb5f34c0fcb65a9`, `tests/support/b100_manifests.py` `af1603c710d4e5c4`, `tests/support/b100_projects.py` `8bbec2880e36e8e3`. I did not edit source or tests. The files I created in the worktree are this report and `evidence/inc-7/review/` (copies of my probe, scripts and transcripts). |
| Contract | `01-requirements.md`: HLR-169 (LLR-169.1 … 169.9), LLR-168.4, LLR-167.6 (the plan's manifest keys), LLR-178.1 (relation line). `design/design-proposal-b100.md` §5.7. Briefs `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-7.md`. Packet `03-increments/increment-007.md` §6 rulings, treated as decided: OQ-7a, OQ-7b, SEC6-2 (refuse the rewrite), the SEC6-5 bound, CI-6-1. I checked that the code implements each ruling. Precedent: `review-increment-006.md`. |
| Interpreter proof | s19env Python 3.11.15. Probes ran on the worktree itself (cwd = worktree, `python -m pytest -c pyproject.toml`). Each transcript prints `s19_app.__file__` = `C:\Users\jjgh8\Github\s19_app-b100-inc7\s19_app\__init__.py` and the 4 source hashes. Reviewer mutants ran in one tree per mutant under `…\scratchpad\r7\mut\<id>\`: `s19_app`, `tests`, `examples`, `tools` and `pyproject.toml` copied from the worktree, with one single-occurrence edit and CRLF kept. Each transcript prints that tree's import path and the mutated file's hash before and after. Environment: `NO_COLOR` unset (`env -u`), `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `-p no:cacheprovider`. I deleted the mutant trees after the runs. |
| **Verdict** | **FAIL (reject until fixed).** Recorded token: **`BLOCK — BLOCK-UNTIL: F1, F2, F3`** (0 HIGH, 3 MAJOR that block on correctness, 2 MINOR, 3 LOW). This verdict authorises nothing. The increment advances only after I re-read each fix on the diff and re-run probes PA, PB and P1. F4 and F5 are test gaps and should land in the same corrective pass. |

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`. The probe source and every transcript are copied to `.dev-flow/2026-10-26-batch-100/evidence/inc-7/review/`.

## BLUF

The writer, the reader and the problem list do what HLR-169 asks on the paths the packet tests, and the packet's 23 mutation kills are behavioural. I found 3 correctness gaps on paths that no test exercises. Each one is reproduced by an executed probe:

- **F1:** an A2L that cannot be read makes Load call a valid image "not an S19 or HEX file". The image is not opened, and the panel tells the user to drop it.
- **F2:** the SEC6-5 bound in packet §6 is not what the code does. A manifest at the `files` cap gives 999 panel rows, and the panel takes 2.45 s to paint.
- **F3:** Save project's plan lists fewer `project.json` keys than the save writes when a `derived_from` record is carried. LLR-167.6 requires the plan to list the keys the app writes.

What works (checked on the diff, and executed where noted):

- **`files` / `derived_from` writer.**
  - Both keys are omitted when empty, so the output stays byte-identical (golden test).
  - Every key and every `base` goes through `_reject_unsafe_entry`, which now runs in the manifest-keys mode.
  - The seam computes `files` after the copies, and the verify domain covers both keys.
  - `derived_from` is computed from the re-derived map: `save_patched` mutates `mem_map` in place, so the count is taken against what was written.
- **Private staging.** `_private_stage_dir` is used and removed in `finally`. The containment check now runs before staging.
- **SEC6-3.** `_guarded_destination(destination.parent, this work area)` runs on the unresolved folder. The packet's junction arm and its mutant are KILLED.
- **Reader.**
  - The read is bounded at 1 MiB + 1 byte.
  - The caps are counted before any entry resolves (`assignments` and `gathered` are counted in total and by key).
  - A cap breach voids the whole manifest. It is marked as manifest scope, so `manifest_is_damaged` and the rewrite refusal both see it.
  - The type checks refuse a `bool` size.
  - The manifest-keys mode is used only by the reader (`batch`, `assignments`, `gathered`, `files`, `derived_from`, `base`) and by `_reject_unsafe_entry`. The flow callers keep the default mode (P-41 mutant KILLED).
- **CI-6-1.** The length rule runs on the text before any filesystem call, in every mode, as ruled.
- **One problem per file.** `merge_load_problems` keeps the lowest rank, and on a tie the first one seen. The packet's both-orders arms and two mutants pin it.
- **OQ-7a.** Only "no data" or "does not parse" counts as `not readable`. The case_04 arm keeps a checksum-error image open.
- **`choose_install_set`.** It is pure. It starts at the recorded variant when that variant is in the set and wraps once. The load loop terminates, because every pass adds one id to `unreadable`. Probe PN covers every image unreadable with no MAC: no exception, one summary line, `not readable: aaa.s19`.
- **SEC2-10.** `_abort_save` → `_restore_manifest` retries, then claims `project.json.previous-<UTC>` with `O_CREAT|O_EXCL`, and the status names the copy and its folder. Probe PR shows the retry works on the tree.
- **The panel.** The relation line is painted in the warning colour, and `not readable` in `RED`. Disk names go through `safe_text`. `screens.py` imports no service module.

## Scope reviewed

- `git diff 80052cb` for all four sources, read in full:
  - `manifest_writer.py` (serialize, `_check_destination_contained`, `write_project_manifest`, verify, `file_record`, `_top_level_project_files`, `project_file_records`, `count_differing_bytes`, `derive_record`, `_disk_problem`, `check_project_files`);
  - `variant_execution_service.py` (constants, `FileRecord`, `DerivedFrom`, `_manifest_key_refusal`, `_climbs_above_root`, `_resolve_manifest_entry`, `_over_cap_issues`, `_recorded_file`, the two record parsers, `_bound_entry_findings`, `read_project_manifest`, the problem kinds, `merge_load_problems`, `manifest_problems`, `manifest_rewrite_refusal`, `_relation_line`, `_missing_recorded`, `compose_load_announcement`);
  - `app.py` (`_save_manifest_keys`, `_image_map`, `InstallSet`, `choose_install_set`, the save-back, `_abort_save`, `_restore_manifest`, `_keep_previous_manifest`, Save project's carry and emit, the seam, `_handle_load_project`, `_install_project_image`, `_manifest_carry`, `_rewrite_project_manifest`, `_derived_record`);
  - `screens.py`.
- Read for context, unchanged: `workspace._guarded_destination` / `_private_stage_dir` / `contained_in_workarea`, `ChangeService.save_patched`, `load_selected_file` / `_parse_loaded_file`, `_load_a2l_data_with_cache` → `parse_a2l_file` (re-raises `OSError`), `project_gather_service.plan_project_save`.
- Tests:
  - all of `test_b100_project_check.py` and `tests/support/b100_manifests.py`;
  - the diffs of `test_b100_active_variant.py`, `test_b100_announce.py`, `test_b100_save_guards.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`, `test_b99_staging.py`, `test_tui_variants.py`, `test_variant_execution.py`, `test_id_registry.py`.
- Records: the packet, `HANDOFF.md`, and 10 of the 23 `mut-*.txt`. I read `169.5`, `SEC6-3`, `178.1-first-by-name`, `169.9-code`, `168.4`, `SEC2-10`, `SEC6-5`, `169.8-P41`, `169.6` and `SEC6-2`. Each names its mutant (old → new), fails on a behavioural assertion (not an `ImportError` or `NameError`), and ends with `reverted: sha256 restored = True`.

## What I executed (evidence state: `executed`)

| Run (`evidence/inc-7/review/<file>`) | Result |
|---|---|
| **P1** (`probes-tree.txt`). Open project P1 holds `firmware.s19`, `firmware.mac` and a `project.json` with `files` and one `derived_from` record. Save project into P1 with no pending change (a copy, `image_step.emit == False`). | **FAILED (finding F3).** `plan.manifest_keys = (schema_version, active_variant, batch, assignments, files)`. Keys written: the same five plus `derived_from`. The record is carried (`app.py:9344`), but the plan's keys come from `_save_manifest_keys(..., derived=image_step.emit)` (`:9860-9861`). |
| **PA** (`probes-tree-2.txt`). P holds `firmware.s19` (valid, recorded active, with `files`) and `firmware.a2l`. `parse_a2l_file` raises `PermissionError(13)`, which is the shipped parser's behaviour for a read error. P is opened with `_handle_load_project`. | **FAILED (finding F1).** `problems = (LoadProblem('not readable', 'firmware.s19', 'not an S19 or HEX file - replace the file, or Save project to drop it'),)`, `current_file: None`, summary `Loaded project 'P' -> (no image) - 1 variants, 1 problem - details: p`. No painted line names the A2L. |
| **PB** (`probes-tree-2.txt`). P holds `firmware.s19`. Its `files` holds that record plus 999 well-formed records for files that are not on disk: 1 000 entries, at the cap, so the manifest is not damaged. P is opened through the Load dialog with the shipped SEC6-5 harness. | **FAILED (finding F2).** `load 0.42 s; panel painted 2.45 s; problem rows 999`. The packet names a bound of `≤ 100 + 1 + 1 + 1 per top-level file` (here 103) and says the panel paints under 1 s. |
| **PN** (`probes-tree.txt`). Every image is unreadable (`aaa.s19` is a terminator only) and there is no MAC. | Passed. No exception; `unreadable == ('aaa.s19',)`; 1 summary line. (`1 variants` is pre-existing wording.) |
| **PR** (`probes-tree.txt`). The SEC2-9 merge scene. The verify raises while another handle holds the new `project.json`, and a timer releases the handle after 0.15 s, inside the retry window. | Passed on the tree: the restore lands, no `.previous-*` copy exists, and no "could not be restored" line is painted. |
| **MR** (`mut-MR.txt`). `app.py:8953`: `attempts >= 5` → `attempts >= 1`, so `_restore_manifest` does not retry. Run: the 2 shipped SEC2-10 arms plus probe PR. | **SURVIVES the shipped arms** (2 passed). Killed only by PR (1 failed: `project.json could not be restored (PermissionError); its previous content is kept as …`). → F4 |
| **MF** (`mut-MF.txt`). `_bound_entry_findings`: `return` before the fold row is appended, so entries past the 100th are dropped unreported. Run: all of `test_b100_project_check.py` plus probe PF. | **SURVIVES 72 of 72 shipped nodes**, including the SEC6-5 arm. Killed only by PF (`issues: 100 last: ../escape_099.json`; expected 101 issues with the last one being `50 more recorded entries`). → F5 |
| **PF** (`probes-tree.txt`). 150 escaping `batch` entries. | Passed on the tree: 101 issues, the last one `50 more recorded entries`. |

Note on the transcripts: `probes-tree.txt` was produced before PA and PB were appended to the probe file. `test_r7_probes.py` in `review/` is the final version and holds all 7 probes.

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **MAJOR** (blocks: a wrong reason and wrong advice on a reachable error path; LLR-169.9 user terms) | `app.py:10499-10549` `_install_project_image`, the call `:10533` `self._parse_loaded_file(variant.path, list(a2l_files))` | **An A2L read failure is reported as the image being "not an S19 or HEX file".** `_parse_loaded_file` parses the image and then the project's A2L (`_load_a2l_data_with_cache` → `parse_a2l_file`, which re-raises `OSError`). `_install_project_image` turns any exception into `not readable` for the variant. Every variant fails the same way, so no image opens. The MAC load, if a MAC exists, then hits the same A2L and paints `Load failed: …`. The panel tells the user to "replace the file, or Save project to drop it" for a valid firmware image. Base `80052cb` also did not open the image (by code reading, not executed), but its status `Load failed: [Errno 13] … firmware.a2l` named the real cause. Trigger: an A2L the OS refuses to read, or one that vanished between the listing and the parse. | PA: `not readable: firmware.s19 - not an S19 or HEX file …`, `current_file None`. | Separate the image from the A2L. Before the variant loop, read the A2L once inside `try/except OSError`. On failure, add `ProjectFileProblem(PROBLEM_NOT_READABLE, a2l.name, "the file cannot be read")` and install the variants (and the MAC) with `a2l_files=[]`. Keep `_install_project_image`'s `not readable` for failures of the image itself. Arm: PA as a TC-B100-61 node, asserting `not readable: firmware.a2l`, that `firmware.s19` opens, and that 0 problems name `firmware.s19`. Mutant: drop the A2L `try` → RED. **Discharge:** I re-read the fix and re-run PA. |
| **F2** | **MAJOR** (blocks: the accepted SEC6-5 bound in packet §6 is false; executed) | `variant_execution_service.py:908` `_bound_entry_findings` (folds reader issues only); `manifest_writer.py:1020` `check_project_files` (one `missing` / `changed on disk` / `not readable` per `files` record, up to the 1 000 cap); `variant_execution_service.py:1702` (merged, never bounded) | **The panel is not bounded by `100 + 1 + 1 + 1 per top-level file`.** The fold covers only the reader's skipped-entry findings. Disk problems come one per recorded file, and `files` may hold 1 000 records without being damaged. A hand-edited or stale manifest at the cap therefore gives about 1 000 rows, and the panel paints in 2.45 s, against the packet's "under 1 s" claim. The shipped SEC6-5 arm uses only escaping entries, which the text check refuses before they reach `files` records that resolve, so it cannot see this. Inc 6 froze for 10.2 s at 6 000 rows. This is smaller, but it is not the bound the ruling accepted. | PB: `problem rows 999`, `panel painted 2.45 s`. | Bound the composed list, not only the reader: in `compose_load_announcement`, after `merge_load_problems`, keep the first `MANIFEST_ENTRY_ROWS` rows (they are in precedence order) and fold the rest into one counting row (`<N> more files - …`). Then restate the bound in packet §6 as one formula that covers both sources. Arm: PB as a TC-B100-61 SEC6-5 node (rows ≤ the bound, panel under 1 s). Mutant: drop the composer fold → RED. Hand this to `security-reviewer` too, since SEC6-5 is their item. **Discharge:** re-read and re-run PB. |
| **F3** | **MAJOR** (blocks: the LLR-167.6 contract, "the app passes the keys it writes"; TC-B100-59 pins key equality) | `app.py:9860-9861` (`_save_manifest_keys(self._declared_regions, derived=image_step.emit)`) vs `:9341-9346` (the target's `derived_from` carried) and `:9404-9410` (an emit records nothing when `_derived_record` returns `None`) | **The Save plan's `project.json` keys differ from what the save writes.** The plan includes `derived_from` exactly when the save emits. The save writes it when any record is carried from the target (a copy-save into a project that has a save-back variant) or emitted, and it omits it on an emit whose base can no longer be read. Users see the plan before they confirm, so it shows one key fewer (or one more) than the save writes. `test_tc_b100_59_files_row` asserts `tuple(written) == plan.manifest_keys`, but only for a fresh folder. | P1: plan `(…, 'files')`; written `(…, 'files', 'derived_from')`. | Decide the `derived_from` key from data the planner already has: `derived = image_step.emit or bool(<the target's readable derived_from>)`, with the target read once and shared with the carry at `:9341`. For an emit whose base cannot be re-read, either check the base when planning (it is on disk) or accept the key with an empty map, documented. Arm: P1 as a TC-B100-59 open-project node. Mutant: `derived=image_step.emit` restored → RED. **Discharge:** re-read and re-run P1. |
| F4 | MINOR (a stated behaviour without a test) | `app.py:8945-8957` (the retry loop); `tests/test_b100_save_guards.py` `test_tc_b100_07_failed_restore_keeps_the_previous_manifest` | **SEC2-10's retry is untested.** Brief item 6 and packet §1 state "retries `os.replace` on `PermissionError` (5 tries within 1 s)". Both shipped arms block for the whole window, so they pass whether or not the code retries. | MR SURVIVES both arms; PR kills it. | Add PR as an arm: the holder lets go after 0.15 s → restored, no copy, no "could not be restored" line. Add MR to the packet's mutation table. |
| F5 | MINOR (a weak test for "nothing dropped unreported") | `variant_execution_service.py:908-942`; `test_b100_project_check.py:743-787` | **No test asserts the fold row.** The SEC6-5 arm checks only `rows <= bound` and the timings. A fold that silently drops entries past the 100th, or one that reports nothing at all, passes it. HLR-169 says "every malformed or unsafe manifest record shall be reported". | MF SURVIVES all 72 nodes; PF kills it. | Add PF (101 issues, the last one `50 more recorded entries`). In the SEC6-5 arm, also assert that the fold row is painted, which gives a lower bound. |
| F6 | LOW (duplication) | `variant_execution_service.py:1684` and `:1702`; `manifest_writer.py` `check_project_files` | **Manifest problems are computed twice per load.** `check_project_files` already returns `manifest_problems(manifest)`, and `compose_load_announcement` adds them again. `merge_load_problems` hides the duplicates, so the output is right, but the data flow says one thing twice. | code read | Let the composer add manifest problems only when no `problems` are passed (its pure-call use), or document that the merge de-duplicates them. |
| F7 | LOW (re-pin oracle coupled to wording) | `tests/test_variant_execution.py:238` | The re-pinned `test_load_project_unknown_active_variant_falls_back` checks `"problems" in line`. That holds only because the seed has no `files`, so a second problem (`no digests saved`) makes the word plural. With exactly 1 problem the oracle fails although the behaviour is right. | code read | Match `r"\b\d+ problems?\b"` or the count token. |
| F8 | LOW (wording) | `variant_execution_service.py:1551-1552` | `manifest_rewrite_refusal` says "was written by a newer version" for any `schema_version` other than 1, including `0` and the string `"1"`. | code read | Use "has schema_version <v>, not 1", or split the newer and the invalid cases. |

## Re-pins (each checked against a requirement)

| Node | Justified? |
|---|---|
| TC-55 labels → kind tokens; the `missing` file name; 3 rows → 2 | Yes, LLR-169.9. The 2-row arm still pins precedence (manifest damaged before missing). Its two findings carry no entry mark, which is consistent: real skipped entries always carry one. |
| TC-56 / TC-67 seeds gain `files` | Yes, LLR-169.5: without them the seed reports `no digests saved`. |
| TC-56 control-byte arm (the "activating the first variant" line gone) | Yes, LLR-169.6. The no-control-character oracle still covers the panel. |
| TC-67 overlong 3 rows → 1 | Yes, LLR-169.9: one recorded entry is one file. The SEC6-7 no-crash intent is kept. |
| TC-20 overlong and junction-loop arms → "not rewritten" | Yes, the SEC6-2 ruling. The no-crash intent is kept, and `project.json` is checked byte-identical. |
| TC-20 read-only arm → Windows only, plus the any-platform sibling | Yes, CI-6-1. The sibling forces the same failure on every platform. |
| `test_load_project_unknown_active_variant_falls_back` | Yes, LLR-169.6 (see F7 for its oracle). |
| TC-B100-08 install marker → `_apply_loaded_file`; TC-B99-13 allow-list gains `_restore_manifest`, `_keep_previous_manifest`; the `_parse_loaded_file` call-site list gains `_install_project_image` | Yes. Each names its requirement (LLR-169.6, SEC2-10, LLR-169.6) in a comment. `_keep_previous_manifest` claims only a new name and unlinks only its own partial claim, so the allow-list's rule ("never a pre-existing file") holds. |
| AT-05 / -19 / -20 extensions, AT-06 `derived_from` line, TC-59 `files` row | Planned Inc 7 arms (AT index), not re-pins. They are RED at base (`red-03`). |

Notes (no finding):

- **The rulings are implemented as decided.**
  - OQ-7a: the `elif loaded.errors` branch is gone. An empty map is reported as "not an S19 or HEX file" when it has errors and as "0 data bytes" when it has none.
  - OQ-7b: the TC-22 fixture adds `checks/inner.s19`.
  - SEC6-2: the rewrite is refused for damaged, schema ≠ 1, unknown keys or skipped entries, with a separate arm for each of the three new conditions.
  - CI-6-1: `len(raw_entry) > 32 767` is checked on the text, before any filesystem call, in both modes.
  - The SEC6-5 bound is the exception: the code does not match its stated formula (F2).
- **`_derived_record` re-reads the base from disk** at the write. If the base changed on disk since the load, the record describes the current file, which is internally consistent. If the base was removed, no record is written, the log says so, and nothing is painted. Acceptable as declared. The plan-key consequence is part of F3.
- **POSIX-only edge, not executed:** a top-level data file whose name has a `:`, a trailing dot or space, or a device name (possible on Linux) makes `serialize_manifest` refuse the whole manifest, because the `files` key fails the manifest-keys predicate. On Windows such names cannot exist. Worth one line in the backlog.
- `InstallSet.a2l` has no caller yet. It is declared for the Inc 9b preview (LLR-174.x), which is acceptable.
- **The `files` hashing runs before the write's containment guard** (`project_file_records` is called before `write_project_manifest`). For a project folder swapped for a junction, the files on the other side are read and hashed, then the write is refused. Nothing is written. Read-only, so I note it for `security-reviewer`.
- **Out-of-scope change seen in the worktree while I reviewed:** `tools/e13/capture_all.ps1` and `tools/e13/run.py` were modified at 05:50–05:51 local (a `pe-patched` capture scenario). They were not in `git status` when I started, and I did not make them. They are not in the packet's §2 and I did not review them. The orchestrator should decide whether they belong to this increment.

## Evidence checklist

- [x] Diff read in full: the four sources (`git diff 80052cb`; app.py hunks `:1453-1600`, `:3864-3873`, `:8879-9020`, `:9336-9410`, `:9857-9862`, `:9970-10010`, `:10394-10600`, `:10607-10760`), the 2 new test files, and the 10 test diffs.
- [x] Correctness pass: the A2L error path (F1, executed), the panel bound (F2, executed), plan vs written keys (F3, executed), every image unreadable (PN, passed), the restore retry (PR, passed on the tree).
- [x] Simplicity pass: no premature abstraction. One duplicated computation (F6).
- [x] Reuse checked: `_guarded_destination`, `_private_stage_dir`, `_resolve_manifest_entry` (modes, not a second predicate), `is_windows_device_name`, `_parse_loaded_file` / `_apply_loaded_file`.
- [x] Tests reviewed for intent: 10 mutation transcripts read (behavioural kills). 2 reviewer mutants survive the shipped tests (F4, F5). The re-pins are justified.
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1, F2, F3`, with executed evidence (PA, PB, P1).

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1, F2, F3** (0 HIGH, 3 MAJOR blocking, 2 MINOR, 3 LOW) · F1, F2 and F3 are open.

- **F1:** an A2L the OS cannot read makes Load report the valid image as `not readable: not an S19 or HEX file … Save project to drop it`, and no image opens (probe PA). Fix: read the A2L separately and report it against `firmware.a2l`.
- **F2:** the SEC6-5 bound in packet §6 is false. 1 000 `files` records give 999 panel rows, and the panel paints in 2.45 s (probe PB). Fix: bound the composed list as well.
- **F3:** Save project's plan omits `derived_from` when a record is carried, so the plan and the written keys differ (probe P1, against the LLR-167.6 contract).

F4 (the restore retry is untested: reviewer mutant MR survives) and F5 (the fold row is unasserted: reviewer mutant MF survives 72 of 72 nodes) should land in the same pass. Each blocking finding is discharged only when I re-read the fix on the diff and re-run its probe. Everything else is sound: the writer and verify, private staging, the SEC6-3 guard, the caps and type checks, the mode limited to the reader and the predicate, one problem per file, OQ-7a, CI-6-1, SEC6-2, and the packet's 23 behavioural kills.

---

# Round 2 — corrective pass 1 (re-review)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, round 2. This is a separate instance from round 1. I am independent of the corrective pass: `software-dev` wrote the fixes, not me. I did not edit source or tests and committed nothing. The files I added in the worktree are this section and the `r2-*` files in `evidence/inc-7/review/`. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc7`, base `80052cb`, uncommitted. Source sha256[:16]: `manifest_writer.py` `ab36c9a2a6216de5`, `variant_execution_service.py` `aae7d7fdde4d735e`, `app.py` `3b46619711652f9c`, `screens.py` `49d6efdc73e26b28`. These equal the packet's cp1 hashes, and every r2 transcript prints them. Pre-fix tree: `…\scratchpad\cp7-1\pre\`, with hashes `b3a8da7ae550bda5` / `bd33c8be189d2c87` / `0e29d80841fa3f38` / `e23ea8f72bc93153`, equal to the round-1 tree. |
| Diff read | `diff -u` pre → worktree for the 4 sources, read in full (1 193 lines, `…\scratchpad\r7b\cp1.diff`):<br>• `manifest_writer.py`: the SEC7-2 post-replace check.<br>• `variant_execution_service.py`: `_lstat_state`, `_EntryWalk`, `_entry_text`, `_walk_manifest_entry`, `_resolve_manifest_entry`, `_recorded_file`, the parsers, `_bound_entry_findings`, `read_project_manifest`, `LoadAnnouncement.hidden` / `problem_count`, `manifest_keep_reason` / `manifest_rewrite_refusal`, `compose_load_announcement`.<br>• `app.py`: the `_restore_manifest` status, `_keep_previous_manifest`, the F3 plan block, the SEC7-3 keep and refusal, `_plan_project_save(derived=)`, the F1 A2L pre-read.<br>• `screens.py`: the title count.<br>Read for context, unchanged: `_abort_save`, `_write_and_verify_manifest`, `_manifest_carry`, `_derived_record`, `_load_a2l_data_with_cache`, `_parse_loaded_file`, `check_project_files`, `_top_level_project_files`, `serialize_manifest` / `_reject_unsafe_entry`, `workspace._is_reparse_point` / `_path_traverses_reparse_point`.<br>Records: packet §1 (cp1), §4 "Corrective pass 1 — results", §6 (cp1 dispositions), and the cp1 section of `HANDOFF.md`. |
| Interpreter / env | s19env Python 3.11. `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<tree>`, `-p no:cacheprovider`, cwd = the tree. Each transcript prints the `s19_app` import path. |
| **Verdict** | **PASS-WITH-NOTES.** Recorded token: **`OK to advance`** (with notes).<br>• F1, F2 and F3 are CLOSED: I re-read each fix on the diff and re-ran its probe on the cp1 tree, and all three are GREEN.<br>• F4–F8 are closed.<br>• Open: 0 HIGH, 0 MAJOR.<br>• New: 2 MINOR (R2-1, a test gap; R2-2, the call ceiling inside the caps) and 2 LOW (R2-3, R2-4). None blocks. |

## Round-1 findings — status

| id | Status | Evidence (re-read on the diff + executed) |
|---|---|---|
| **F1** | **CLOSED** | **Code** (`app.py:10491-10507`):<br>• The project's A2L is read once, through `_load_a2l_data_with_cache`, inside its own `try`, before `choose_install_set`.<br>• If that read fails, there is one `not readable: <a2l> - the file cannot be read` problem and `a2l_files = []`.<br>• `_reset_project_session()` runs earlier, so the image cannot pick up a stale `current_a2l_path`. The image parse then hits the A2L cache.<br>**Probe PA re-run** (`r2-round1-probes-cp1.txt`): problems `(('not readable', 'firmware.a2l'),)`, `current_file …\P\firmware.s19`, summary `variant 1 of 1, 1 problem`.<br>**Shipped arm** `test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens` asserts the A2L row, `unreadable == ()`, that the image is open, and `a2l is None`. Mutant `mut-cp1-F1.txt` is KILLED on the row assertion. |
| **F2** | **CLOSED** | **Code** (`variant_execution_service.py` `compose_load_announcement`):<br>• The composer lists `merged[:LOAD_PROBLEM_ROWS]` (102 rows), then one `more problems: <N> more files` row, ranked above every kind.<br>• `LoadAnnouncement.hidden` / `problem_count` keep the true count for the summary line and the panel title (`screens.py:1090`).<br>• Rows are ordered by `merge_load_problems` (precedence, stable sort), so the manifest-level rows and the reader rows (rank 0) always fit.<br>**Probe PB re-run:** `load 0.21 s; problem rows 103`. Round 1 measured 999 rows and 2.45 s.<br>**Shipped arm** asserts:<br>• rows == 103;<br>• the counting row `897 more files`;<br>• 102 `missing` rows;<br>• `problem_count == 999`;<br>• `999 problems` in the title and the summary.<br>Mutant `mut-cp1-F2.txt` is KILLED: the timing assertion fails first, and the row assertions come after it.<br>Packet §6 now states one bound for every source: ≤ 103 rows. |
| **F3** | **CLOSED** | **Code** (`app.py:9243-9264`):<br>• The target manifest is read once, before the plan.<br>• `carried_derived` and `emitted_record` are decided there. `emitted_record` comes from `_derived_record` and is `None` when the base cannot be read.<br>• The plan gets `_plan_project_save(..., derived=bool(carried_derived) or emitted_record is not None)`.<br>• The write path (`:9384`, `:9444-9445`) uses the same two values, so the plan keys and the written keys come from one decision.<br>• `emitted_record` is now computed before the emit, from the same inputs as before (`current_file.path`, `image_step.derived`). It reads the base before any file is placed, which can only be as good as reading it after, or better.<br>**Probe P1 re-run:** plan keys == written keys `(…, 'files', 'derived_from')`.<br>**Shipped arm** `test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from[carried|emit|emit-base-unreadable]`. Mutant `mut-cp1-F3.txt` is KILLED 2, in both directions. |
| F4 | CLOSED | Arm `test_tc_b100_07_restore_retry_lands_when_the_holder_lets_go`. Reviewer mutant MR is KILLED (`mut-cp1-F4-MR.txt`: a `.previous-*` copy appears). Probe PR re-run: passed. |
| F5 | CLOSED | Arm `test_tc_b100_61_skipped_entries_beyond_the_bound_are_counted` asserts 101 entries and `50 more recorded entries`. Reviewer mutant MF is KILLED (`mut-cp1-F5-MF.txt`). Probe PF re-run: passed. |
| F6 | CLOSED | `compose_load_announcement` no longer adds `manifest_problems` or `no project.json`; `check_project_files` is the one source. Arm `test_tc_b100_55_composer_adds_no_second_copy_of_the_check`, mutant KILLED. The 3 TC-55 re-pins now pass `problems=_checked(manifest)`, as the load does (LLR-169.9). The re-pins are justified. |
| F7 | CLOSED | `test_load_project_unknown_active_variant_falls_back` asserts the exact count. Mutant `F7` (count + 1) is KILLED. |
| F8 | CLOSED | `manifest_keep_reason` treats as this version only `type(v) is int and v == 1`, or an absent key. An int above 1 is "newer"; any other value is "unknown". Arms cover 9 values. Mutants: `F8-type` KILLED 4, `F8-wording` KILLED 5. |

I re-ran the round-1 probe file verbatim on the cp1 tree: **7 passed** (`r2-round1-probes-cp1.txt`).

## Corrective-pass diff — what I checked and found sound

- **`_EntryWalk` (SEC7-1).**
  - **Cost.** The walk makes one `os.lstat` per distinct (parent node, `normcase(component)`) per read. It stops at the first component that is not present: a missing folder costs one call, and every later entry under it costs none. A junction loop is refused at its first link.
  - **`..` handling.** `..` is applied to the text only after `_climbs_above_root` has refused any climb, so `parts.pop()` never runs on an empty list.
  - **Lexical path.** The walk returns the lexical path, and every later use (the carry, `_disk_problem`) uses that same path, so a `sub/../x` entry never opens `sub`.
  - **Reparse predicate.** `S_ISLNK` or `FILE_ATTRIBUTE_REPARSE_POINT` matches `workspace._is_reparse_point`, so files that were refused before (any reparse tag) are still refused. Refusing a link as the final file is the accepted behaviour change.
  - **Writer.** `_reject_unsafe_entry` gets a fresh walk for each entry (≤ 33 calls), so the ceiling never applies there.
- **The 32-component rule.** It counts separators on the raw text (`>= 32` separators → refused). It applies in the manifest-keys mode only, before any filesystem call. It can over-refuse an entry with redundant separators (`a//b`), which is harmless.
- **`_recorded_file`.** It decides the one-name / suffix scope on the text before the walk. Mutant `scope-after-fs` is KILLED by the call count.
- **`LOAD_PROBLEM_ROWS`.** See F2. The counting row's `rank` is above every kind. `screens.py` paints labels generically, so the new label needs no lookup.
- **Separate A2L read.** See F1. The broad `except Exception` is right for an untrusted file, and only the class name is logged.
- **F3 plan keys.** See F3.
- **SEC7-2.**
  - The re-check runs after the `finally` that removes the staging folder, and it reuses `_check_destination_contained`.
  - `written is None` means `on_written` is not called, so no restore is armed for bytes that did not land in the project.
  - Mutant KILLED.
- **SEC7-3 copy + rollback.**
  - **Decision.** The keep decision uses the manifest read before the plan.
  - **Rollback.** The copy joins `placed_files`, so a later failure removes it. `_abort_save` restores the original first: the restore runs before the unlink loop. If the restore itself fails, `_restore_manifest` claims the next name (`…-1`), and the status line names that copy.
  - **Status lines.** The success line is followed by the kept-copy line, and the R2-5 mismatch repaint stays last.
  - **Refusal branch, executed** (probe Q1, below):
    - status: "Project NOT saved: project.json holds keys this version does not know and its content could not be kept beside it in …";
    - `project.json` is byte-identical;
    - the copied image is rolled back, so P holds only `project.json`.

    On the pre-fix tree the same probe overwrote the manifest (RED).
- **`_keep_previous_manifest`.**
  - `os.open` without `O_BINARY` does not translate bytes on this interpreter. I checked that `b'a\nb\x1ac\r\n'` round-trips unchanged.
  - The guard and the `except OSError: continue` are as ruled (SEC7-6).
- **Re-pinned tests.** Each traces to a requirement:
  - the 3 TC-55 nodes → LLR-169.9 / F6 (oracles unchanged, input made explicit);
  - `test_load_project_unknown_active_variant_falls_back` → LLR-169.6 / F7 (exact count).

  No test was removed.
- **New tests can fail.** I read 12 of the `mut-cp1-*.txt` transcripts: `F1`, `F2`, `F3`, `F4-MR`, `F5-MF`, `F6`, `F7`, `F8-wording`, `SEC7-1-no-cache`, `SEC7-1-no-ceiling`, `SEC7-2`, `SEC7-3`. Each one:
  - names its edit (old → new);
  - fails on a behavioural assertion (rows, keys, call counts, statuses, file presence);
  - ends `# reverted: sha256 restored = True`.

## What I executed in round 2 (evidence state: `executed`)

| Run (`evidence/inc-7/review/<file>`) | Result |
|---|---|
| Round-1 probes, verbatim, on the cp1 tree (`r2-round1-probes-cp1.txt`) | **7 passed.**<br>• P1: the keys are equal.<br>• PA: `not readable: firmware.a2l`, and the image is open.<br>• PB: 103 rows, load 0.21 s.<br>• PF, PN and PR pass. |
| **Q1.** The SEC7-3 refusal branch. P holds a `project.json` with an unknown key, and `_keep_previous_manifest` returns `None` (`r2-probes-cp1.txt`, `r2-probes-pre.txt`). | **cp1: passed.** The save is refused, the manifest is unchanged and the image is rolled back.<br>**Pre-fix tree: failed.** The manifest is overwritten and `firmware.s19` is left in P. |
| **Q1-mutant.** One edit at `app.py:9553`, in a copy tree: `if kept is None:` → `if kept is None and False:` (`r2-mut-SEC7-3-refusal.txt`). | Shipped `test_b100_save_guards.py` + `test_b100_save_image.py`: **107 passed — SURVIVES (no shipped node reaches the branch)**.<br>Probe Q1: **1 failed — KILLED (`AttributeError: 'NoneType' object has no attribute 'unlink'` in the rollback; the first run of this step used a POSIX path pytest could not find and is kept in the transcript, followed by the re-run)**. → R2-1 |
| **Q2.** A `files` key that differs from the disk name only by case, with the correct digest (`r2-probes-*.txt`). | **Pre-fix:** 0 problems.<br>**cp1:** `not recorded: firmware.s19 - in the project, not in project.json`. → R2-3 |
| **Q3.** A well-formed manifest inside every cap (`r2-probes-*.txt`):<br>• `batch`: 1 000 existing files under `p/`;<br>• `assignments[firmware]`: 1 000 existing files under `q/`;<br>• `files`: the image's record. | **Pre-fix:** all 2 000 entries and the record are accepted, 0 issues (read 0.55 s).<br>**cp1:**<br>• read 0.13 s;<br>• `assignments` 998, `files` **0**;<br>• one fold row: `3 more recorded entries - skipped - more entries than one load checks`;<br>• the check adds `no digests saved`;<br>• `manifest_rewrite_refusal` = "holds entries that were skipped".<br>→ R2-2 |

## New findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **R2-1** | MINOR (a ruled behaviour without a test) | `app.py:9548-9575` (the SEC7-3 keep); the refusal `if kept is None:` is at `:9553` | **The SEC7-3 refusal-and-rollback branch has no test.**<br>• The orchestrator ruling says Save project refuses and rolls back when it cannot keep `project.json.previous-<UTC>`.<br>• All five cases of `test_tc_b100_07_save_project_keeps_a_manifest_it_cannot_carry` keep a copy. No test makes the claim fail, so the branch can be removed or broken without any test going RED.<br>• The code is right on the tree: Q1 is GREEN there and RED on the pre-fix tree. | Q1. The Q1 mutant survives the shipped modules and is killed by Q1. | Add Q1 as a TC-B100-07 node: make `_keep_previous_manifest` return `None`, then assert "Project NOT saved", `project.json` byte-identical, the placed image removed, and no "Saved project to" line. Add the mutant to the cp1 table. |
| **R2-2** | MINOR (valid input inside the documented caps loses entries; the loss is reported, not silent) | `variant_execution_service.py:111` (`MANIFEST_FS_CALL_CAP = 2 * MANIFEST_ENTRY_CAP`) and `:475`; parse order `:1335` (batch) … `:1415` (files) | **The 2 000-call ceiling is below what the caps allow, and `files` is walked last, so it is cut first.**<br>• **The gap.** Each array may hold 1 000 entries (`batch`, `assignments`, `gathered`, `files`, `derived_from` and its bases). A well-formed manifest can therefore need more than 2 000 distinct names.<br>• **What happens.** Past the ceiling, entries that are safe and exist are skipped as "unchecked". In Q3 this drops 2 assignments and the image's `files` record.<br>• **Effects.** Load then also reports `no digests saved`, and every in-project rewrite is refused ("holds entries that were skipped") until Save project runs.<br>• **What the packet says.** Packet §1 declares "skipped unchecked and counted". It does not say that a cap-legal manifest can reach the ceiling, or that `files` is cut first.<br>• **Impact.** No user-visible harm at realistic sizes (tens of entries). | Q3: cp1 `files 0`, `assignments 998`; on the pre-fix tree every entry is accepted. | Pick one:<br>(a) Walk `files` / `derived_from` before `batch` / `assignments` / `gathered`, or exempt them from the ceiling. Each is one top-level name (≤ 1 call), so their cost is already bounded by their cap.<br>(b) Size the ceiling to the caps, for example one call per entry of every capped array plus their folders, and keep the depth rule as the per-entry bound.<br>(c) Declare the trade-off and its consequences in §6 as accepted.<br>Arm: Q3, asserting the chosen outcome. |
| R2-3 | LOW (a false problem row; only for hand-edited or renamed files) | `variant_execution_service.py:661` (`return walk.project_root.joinpath(*parts)`) with `manifest_writer.py:1087` (`recorded = {path.name for path in manifest.files}`) | **On Windows, the reader no longer returns the on-disk case of a name.**<br>• `resolve()` used to return the on-disk spelling. The lexical walk keeps the recorded spelling.<br>• `check_project_files` compares names as case-sensitive strings. A `files` key that differs only in case therefore now gives `not recorded: firmware.s19` although the record matches. Triggers: a hand edit, or a file renamed by case in Explorer after the save.<br>• Path comparisons elsewhere are case-insensitive on Windows, so nothing else changed in the probe. | Q2: pre-fix 0 problems, cp1 1 problem. | Compare with `os.path.normcase` in `check_project_files` (both `recorded` and the disk name), or record the walk's on-disk name. A backlog item is enough. |
| R2-4 | LOW (consistency; for `security-reviewer`) | `manifest_writer.py:592-602` (the new SEC7-2 message), painted by `app.py:10056-10063` (`notify(detail, title="Manifest write failed - project.json not written")`) | **The new SEC7-2 message puts `{type(exc).__name__}: {exc}` into a toast.**<br>• In this same pass, SEC7-5 moved exception class names out of the restore status line.<br>• The first containment message, which already existed, also shows the class. So the new message matches that line, not SEC7-5. | code read | Keep the class in the log only, as SEC7-5 does, or record that toasts are out of SEC7-5's scope. |

Notes (no finding):

- After a SEC7-2 detection, the manifest bytes stay wherever the swapped folder pointed, and the packet says so. No restore runs, because the project folder is no longer the one the save started in. That is reasonable. This is `security-reviewer`'s item.
- `_derived_record` now runs before `plan.refusal` is checked, so a refused save still parses the base image once. This costs time only.
- An lstat error other than "not found" (for example, access denied on a folder) now refuses the entry as "not a usable path". Before, `resolve()` accepted such an entry and the later check reported the file. The new rule is stricter. I found no real-world case that triggers it.

## Evidence checklist (round 2)

- [x] **Diff read in full:** pre → worktree for the 4 sources (1 193 diff lines), plus the context functions listed above.
- [x] **Correctness pass:**
  - F1/F2/F3 paths re-run (PA, PB, P1);
  - the SEC7-3 refusal executed (Q1);
  - case handling of names (Q2);
  - ceiling vs caps (Q3);
  - checked by reading: `..` and `pop` safety, cache keys, the writer's walk, restore ordering.
- [x] **Simplicity pass:**
  - The `_entry_text` / `_walk_manifest_entry` / `_EntryWalk` split is proportionate.
  - `manifest_keep_reason` + `manifest_rewrite_refusal` is one rule plus one extension.
  - Nothing is speculative.
- [x] **Reuse:** the pass reuses existing code rather than rewriting it: `_check_destination_contained`, `_guarded_destination`, `_load_a2l_data_with_cache` (its cache is shared with the image parse) and the reparse predicate.
- [x] **Tests reviewed for intent:** I read 12 cp1 mutation transcripts, and every kill is behavioural. The re-pins are justified. One ruled branch has no test (R2-1).
- [x] **Verdict explicit:** `OK to advance` with notes. No HIGH. Every round-1 blocking finding was re-read on the diff and re-run GREEN.

## §4b `Independent review` cell (round 2, for the orchestrator to write)

`code-reviewer` (round 2) · **OK to advance — PASS-WITH-NOTES** (0 HIGH, 0 MAJOR; 2 MINOR and 2 LOW open, none blocking).

- **F1, F2, F3 — closed.** Each was re-read on the cp1 diff and its probe re-ran GREEN:
  - PA: `not readable: firmware.a2l`, and the image opens;
  - PB: 103 rows, load 0.21 s;
  - P1: plan keys == written keys.

  All 7 round-1 probes pass.
- **F4–F8 — closed** by arms whose mutants are killed.
- **Open notes:**
  - **R2-1:** the SEC7-3 branch "no copy → refuse and roll back" has no test. The code works (probe Q1).
  - **R2-2:** the 2 000-call ceiling can skip valid entries, `files` first, in a manifest that is inside every cap (probe Q3).
  - **R2-3:** on Windows, a name that differs only by case now reports `not recorded` (probe Q2).
  - **R2-4:** the SEC7-2 toast shows the exception class.
