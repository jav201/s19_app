# Increment 003 — HLR-155 (Inc 3a) · `Private staging, atomic placement`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `003` (Inc 3a of the split Inc 3) |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-144 / HLR-155 (all clauses except D7/D9) / LLR-155.1 · LLR-155.2 · LLR-155.3 · LLR-155.4 · LLR-155.7` |
| Acceptance | `AT-B99-05` · `AT-B99-04` distinct-name parallel arm (regression guard, no RED claim) · white-box `TC-B99-11 · TC-B99-12 · TC-B99-13 · TC-B99-14 · TC-B99-39` · UX-C10 hostile-name TCs ×2 |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: every write through `copy_into_workarea` or `save_patched_image` now
stages in a **private** `tempfile.mkdtemp` directory under
`<workarea>/temp/.staging/` (both `temp` and `temp/.staging` reparse-checked
with `lstat` before staging) and places through an **exclusive claim**:
`os.open(O_CREAT|O_EXCL|O_WRONLY)` on the requested name — or the next free
`_<N>` — closed, then filled by `os.replace`, retrying a `PermissionError`
≤ 5 times within ≤ 1 s; when the retries run out the writer removes its own
claim and raises `WorkareaPlacementError(WorkareaContainmentError)` whose
message leads with the outcome, names the file and folder, gives the cause
("still locked after 5 retries, another program may hold it"), the next step
("close it and retry") and "Nothing written" (UX-C4/UX-C5). B8 byte-identical
reuse stays, race-free by an **immutability invariant** (LLR-155.3 as
amended by LED .7 — not by a narrower window: the double read was retired
in review round 1), and a **0-byte target
is never reused** — it may be another writer's claim placeholder (PDR C1(a)).
The source is only ever read, never moved, renamed or deleted; only the owned
staging directory is removed, tracked by an ownership flag set immediately
after `mkdtemp` (LLR-155.7). Staging-home preparation failures (a file in the
way, a denied home) convert to `WorkareaContainmentError`, never an uncaught
`OSError`, so all 15 existing caller `except` sites keep working untouched.

`save_patched_image` (apply.py) no longer stages at the shared
`temp/<user name>` — the fix for P-15: a same-name save-back used to overwrite
and then **delete the loaded work copy**, after which Save project exited the
app with code 1. The 14th placement path (PDR C2), `write_change_document`
(changes/io.py:1586), converts the same way (private staging through the
injectable `copy_fn`). `_handle_save_dialog` (app.py, LLR-155.4) pre-flights
the sources before creating the project folder: a missing source paints
`Project NOT saved: source file missing: <file> — reload it or remove it from
the project.` at failure severity (`notify(..., severity="error",
markup=False)`) and leaves **no empty project folder**; a placement failure
paints the exception text (outcome-first) at failure severity. Both keep the
app running.

The Workarea Files list (`refresh_files`, app.py:6419) already lists only
**files** of the workarea root (`item.is_file()`), and `.staging` lives under
`temp/` — the subfolder never appears; per the brief, no skip was added
("only the skip here, if needed" — not needed; Inc 7 owns the list).

`WorkareaPlacementError` is exported from `s19_app.tui.workspace` (no
`__init__` change needed; the existing re-export of `copy_into_workarea` is
untouched).

**Review round 1 fixes (code-reviewer F1–F6), same session.** The
independent review returned BLOCK with three HIGH findings; the fixes
(fact-below in §4, "Review round 1 fixes"):

- **F1** — the claim loop now treats a name taken by ANY type (file,
  directory or link) as taken: on Windows `os.open(O_EXCL)` against an
  existing directory raises `PermissionError`, not `FileExistsError`, so the
  handler lstat-probes and moves to the next `_<N>`; every other claim or
  fill `OSError` is wrapped in `WorkareaPlacementError` — no raw `OSError`
  can reach a caller that catches only the containment class.
- **F2** — TC-B99-13 was rewritten per the amended LLR-155.3 (LED .7): the
  double-read hook arm (which modelled no real writer) is gone; concurrent
  threads now run `copy_into_workarea` on ONE name, identical and differing
  bytes, 20 trials, and the double read itself was retired (the invariant,
  not a narrower window, carries race-freeness).
- **F3** — `save_patched_image` and `write_change_document` no longer stage
  under `temp/` directly: ONE private helper `workspace._private_stage_dir`
  (reparse checks for `temp` + `temp/.staging`, then `mkdtemp` under
  `.staging`) is used by all three placement paths; TC-B99-11 gained a
  forced-failure junction arm.
- **F4** — new TC-B99-44 drives the converted `io.py` path (private staging
  home spied + correct placement + junction refusal); `write_change_document`
  joined the TC-B99-39 census.
- **F5** — AT-B99-05 and TC-B99-14 are fully black-box: keys and clicks
  through the real Load file dialog (`l`, `#load_path`, `#load_ok`), the
  Patch Editor (rail `6`, clicked inputs/buttons, typed text) and the real
  `SaveProjectScreen` (`s`, clicked inputs, typed text); waits observe the
  painted status line (`#log_line_4`) or the painted screen; assertions read
  the painted status and files on disk — no `load_from_path` /
  `request_action` / `.value=` / patched `set_status`. `red-at_b99_05.txt`
  was re-recorded against the final test on the unmodified base `a52e2be`
  (scratch `git worktree`, removed afterwards).
- **F6** — (a) a placement failure after the folder creation in Save project
  removes exactly the folder this call created (new
  `_remove_created_project_dir`); (b) the 0-byte-claim risk is declared in
  §5; (c) the stale `staging_block` docstring now matches the code (readonly
  arm = a symlink/reparse point at `temp/.staging`); (d) the missing `f`
  prefix in `tests/test_b99_staging.py` was added; (e) the packet's
  `green-final.txt` digest is corrected to the stored bytes' SHA-256.

**Review round 2 fixes (security S-F1..F6, code F6a + LOWs), same
session.** The security review returned `changes required` (one MEDIUM,
five LOWs); the code review passed with two MEDIUM/LOW notes. Fixes
(fact-below in §4, "Review round 2 fixes"):

- **S-F1** — a dangling symlink at the requested final name is no longer
  written through: on Windows `os.open(O_CREAT|O_EXCL)` FOLLOWS a dangling
  symlink (verified empirically on this host — the claim created a 0-byte
  file at the link's target outside the work area and `os.replace` then
  replaced the link). The claim loop now `os.lstat`s each candidate before
  the claim — ANY existing entry (file, directory, link, dangling link or
  junction) is taken, moving to the next `_<N>` — and re-verifies after the
  claim that it is a regular file and no reparse point, else removes the
  claim and raises `WorkareaPlacementError`. New TC-B99-12 arm.
- **S-F2** — the reparse check / `mkdtemp` race: after `mkdtemp`,
  `_private_stage_dir` now lstat-rechecks both `temp` and `temp/.staging`
  and requires `os.path.realpath(new_dir)` to stay under the work area's
  real path; otherwise it removes the directory it created and refuses.
- **S-F3** — the staging checks are `lstat`-based, not `exists()`-based, so
  a dangling junction is caught by the check itself (an `exists()` guard
  never evaluates the reparse check — `Path.exists` follows the link and
  reports False). The refusal names the reparse point. New TC-B99-11 arm.
- **S-F4** — B8 byte-identical reuse never returns a target that is a link
  or reparse point (its bytes live outside the work area); such a target is
  skipped for dedup and the name counts as taken. New TC-B99-13 arm.
- **S-F5** — `_handle_save_dialog`'s "this call created the folder" flag
  now comes from `mkdir(exist_ok=False)` + `FileExistsError`
  instead of a racy `not exists()` probe; the flag is set only when the
  `mkdir` succeeded. Pairs with the F6a arm 2.
- **S-F6** — an `OSError` from the staging `copy2` (including a source that
  vanishes after the size check) is wrapped in `WorkareaPlacementError`,
  outcome first, naming the source. New TC-B99-12 arm.
- **F6a** — `_remove_created_project_dir` is now tested: a forced placement
  failure during Save project removes the folder this call created (arm 1);
  a pre-existing folder of the same name survives untouched (arm 2, pairs
  with S-F5). Both driven by keys and clicks through the real dialogs.
- **LOW-1** — TC-B99-13 gained the same deterministic pause-on-shared-name
  hook as TC-B99-12, so the restored check-then-copy mutant evidence
  carries a real NONZERO mismatch count (`parallel mismatches: 35` / `68`
  in `mut-fix2-155.2-check-then-copy.txt`).
- **LOW-2** — AT-B99-05's wait and assertion are now consistent: the test
  waits for the final painted line (`Project saved…`) and reads the
  four-line painted log for the superseded `Saved project to … (variant
  'firmware')` line, asserting the painted status names the image file. The
  old wait silently timed out 200 pauses (the intermediate line is
  superseded within one tick) and passed only by accident on the second
  read. The viewport is widened to 260 cols so the success line is not
  clipped in the log strip.

The flow WRITE-OUT arm (`flow_execution_service.run_flow` →
`save_patched_image`) and the CRC write (`write_crc_image`) ride the census:
WRITE-OUT is converted transitively through `save_patched_image`; the CRC
site is the declared single known census exception (expected RED until Inc 5,
LLR-155.8).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/workspace.py` | SOURCE | HLR-155; LLR-155.1/.2/.3 | `copy_into_workarea` rewritten: reparse checks for `temp` + `temp/.staging`, private `mkdtemp` staging, O_EXCL claim + `os.replace` (≤5 retries ≤1 s), 0-byte-aware reuse, staging-home error conversion; NEW `WorkareaPlacementError(WorkareaContainmentError)`; NEW `WORKAREA_STAGING_DIRNAME = ".staging"`. **Review round 1:** NEW `_private_stage_dir` — the ONE factored staging seam (reparse checks + `mkdtemp` under `.staging`) used by all three placement paths; the claim treats a name taken by ANY type (file, directory or link) as taken — on Windows an O_EXCL claim against an existing directory raises `PermissionError`, not `FileExistsError`, so the handler lstat-probes and moves to the next `_<N>` (F1); every other claim/fill `OSError` is wrapped in `WorkareaPlacementError`, never raw past the containment-class callers (F1); the reuse double read is retired — race-freeness rests on the immutability invariant per LED .7 (F2). **Review round 2:** the claim loop lstats each candidate before the O_EXCL claim — a dangling symlink is followed by a bare O_EXCL open on Windows, creating the claim outside the work area (S-F1) — ANY existing entry (file, directory, link, dangling link or junction) is taken, and the claim is re-verified after the open to be a regular file and no reparse point, else removed and refused (S-F1); B8 dedup skips a target that is a link or reparse point (S-F4); the staging `copy2` OSError (e.g. a vanished source) is wrapped in `WorkareaPlacementError`, outcome first, naming the source (S-F6); `_private_stage_dir`'s checks are `lstat`-based, not `exists()`-based, so a dangling junction is caught by the check itself (S-F3), and after `mkdtemp` both levels are re-checked plus a realpath-under-the-work-area verification, removing the created dir and refusing on failure (S-F2) |
| `s19_app/tui/changes/apply.py` | SOURCE | LLR-155.1/.7 | `save_patched_image` stages in a private `mkdtemp` dir; the `finally: staged.unlink()` of a re-derived name (the TC-B99-39 RED site) is gone; only the owned staging dir is removed. **Review round 1:** stages via `workspace._private_stage_dir` (never directly under `temp/` — F3) |
| `s19_app/tui/changes/io.py` | SOURCE | LLR-155.1/.7; PDR C2 | `write_change_document` (the 14th placement path, :1504) converts identically, through the injected `copy_fn`. **Review round 1:** stages via `workspace._private_stage_dir` (F3) |
| `s19_app/tui/app.py` | SOURCE | LLR-155.4; UX-C4 | `_handle_save_dialog`: missing-source pre-flight (failure severity, outcome first, no empty folder, app keeps running); `WorkareaPlacementError` painted at failure severity; `WorkareaPlacementError` import. **Review round 1:** a placement failure after the project-folder creation removes exactly the folder THIS call created (`_remove_created_project_dir`, F6(a)); `shutil` import. **Review round 2:** the created-folder flag comes from `mkdir(parents=True, exist_ok=False)` + `FileExistsError` — set only when the mkdir succeeded — not a racy `not exists()` probe (S-F5) |
| `tests/test_b99_staging.py` | test | HLR-155 | NEW — 17 nodes (12 round 1 + 5 fix-round): TC-B99-11/12/13/14/39/40, AT-B99-05, AT-B99-04 distinct-name parallel arm, 2 UX-C10 hostile-name TCs. **Review round 1:** TC-B99-13 rewritten as concurrent placements (F2); AT-B99-05 + TC-B99-14 fully black-box keys-and-clicks drives (F5); new arms: junction refusal (TC-B99-11), directory squat + forced `OSError` (TC-B99-12), the `io.py` path TC-B99-44 + census membership (F1/F3/F4); `f`-prefix fix (F6d). **Review round 2:** 23 nodes — new arms: dangling-junction-at-`temp` refused by the check itself with the reparse named (TC-B99-11, S-F3), dangling-symlink-at-final-name → `_1` with the link and its target untouched (TC-B99-12, S-F1), vanished-source wrap (TC-B99-12, S-F6), symlink-target never reused for dedup (TC-B99-13, S-F4), placement-failure removes the created folder + pre-existing folder survives (TC-B99-14 ×2, F6a/S-F5); TC-B99-13 gained the deterministic pause hook (LOW-1); AT-B99-05 wait/assert made consistent with the painted log read (LOW-2) |
| `tests/test_copy_into_workarea_content_dedup.py` | test | LLR-155.1 (B8) | re-pin (reverse census): the `.staging` home legitimately persists under `temp/`; per-write dirs still asserted removed |
| `tests/b97_fixtures.py` | test | LLR-148.9 (P-51) | re-pin: `staging_block` plants at the private staging home (`temp/.staging`), not the retired shared `temp/<name>`; `dir` = wrong type (file), `readonly` = reparse point (symlink) |
| `tests/test_b97_chips_help.py` | test | LLR-148.9 | re-pin: TC-B97-58 + AT-B97-23 plant the blocker **after** the A2L load (the load rides the same placement; HLR-155) |
| `tests/test_id_registry.py` | test | HLR-155 (G1 bound; +1 = `tests/test_b99_staging.py`) | bound bump 199 → 204 (drift 199→203 pre-exists at base `a52e2be`; +1 = this increment's module) |
| `s19_app/tui/services/project_gather_service.py` | source | LLR-155.3 | Inc-3b (commit `4ee51a6`; its full row is in `increment-003b.md` §2, a packet name the validator's `increment-<digits>.md` reader does not match, so the row is carried here for the close-gate diff): `_gather_copy` drift limb converted to the `copy_into_workarea` placement (next free `_<N>`, never an overwrite); review round 1 `_same_artifact_name` byte-compare |
| `tests/test_b97_flow_execution.py` | test | HLR-155 | Inc-3b (commit `4ee51a6`; its full row is in `increment-003b.md` §2, a packet name the validator's `increment-<digits>.md` reader does not match, so the row is carried here for the close-gate diff): re-pin for D7 (distinct WRITE-OUT names per template) |
| `tests/test_project_gather.py` | test | LLR-155.3 | Inc-3b (commit `4ee51a6`; its full row is in `increment-003b.md` §2, a packet name the validator's `increment-<digits>.md` reader does not match, so the row is carried here for the close-gate diff): TC-702 re-pinned: a drifted re-save places the next free `_<N>` |
| `tests/test_tui_flow_execution_b94.py` | test | HLR-155 | Inc-3b (commit `4ee51a6`; its full row is in `increment-003b.md` §2, a packet name the validator's `increment-<digits>.md` reader does not match, so the row is carried here for the close-gate diff): re-pin for D7 (`_base_blocks(output=…)`, `base_b` twin template) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-003.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-3a/*` | doc | — | transcripts, hashes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 5 touched + 1 new (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter, NO_COLOR unset:
python -c "import s19_app; print(s19_app.__file__)"   # -> C:\Users\jjgh8\Github\s19_app-b99-inc3a\s19_app\__init__.py
pytest tests/test_b99_staging.py -q                   # -> 17 passed (after the review-round fixes)
pytest tests/test_b99_staging.py -k tc_b99_11 -q      # -> 2 passed
pytest tests/test_b99_staging.py -k tc_b99_12 -q      # -> 5 passed
pytest tests/test_b99_staging.py -k tc_b99_13 -q      # -> 2 passed
pytest tests/test_b99_staging.py -k tc_b99_14 -q      # -> 1 passed
pytest tests/test_b99_staging.py -k tc_b99_39 -q      # -> 1 passed
pytest tests/test_b99_staging.py -k tc_b99_44 -q      # -> 2 passed
pytest tests/test_b99_staging.py -k at_b99_04 -q      # -> 1 passed (regression guard)
pytest tests/test_b99_staging.py -k at_b99_05 -q      # -> 1 passed
pytest tests/test_b99_staging.py -k ux_c10 -q         # -> 2 passed
pytest tests/test_address_census.py -q                # inside census-part1: passed
# review round 2 (final test file):
pytest tests/test_b99_staging.py -q                   # -> 23 passed (green-fix2-staging.txt)
pytest tests/test_copy_into_workarea_content_dedup.py tests/test_b97_chips_help.py tests/test_id_registry.py -q  # -> 94 passed
pytest tests/test_address_census.py -q                # -> 23 passed
pytest tests/test_b99_staging.py -k at_b99_05 -q      # x8 -> 8/8 passed
# reverse census (fix 2): 8 directly-asserting files -> see green-fix2-reverse-census.txt
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-B99-11/12/13/14/39/40` ↔ LLR-155.1/.2/.3/.4/.7 | `core` · `full` | `test_tc_b99_11_same_name_save_back_keeps_work_copy` · `test_tc_b99_11_junction_at_staging_temp_is_refused` (F3 arm) · `test_tc_b99_12_eight_writers_one_name_zero_mismatches` · `test_tc_b99_12_forced_permission_error_refuses_cleanly` · `test_tc_b99_12_source_bytes_and_mtime_unchanged` · `test_tc_b99_12_directory_squatting_requested_name_takes_next_free` (F1 arm) · `test_tc_b99_12_forced_oserror_in_replace_raises_placement_error` (F1 arm) · `test_tc_b99_13_concurrent_placements_one_name_own_bytes_returned` (F2 rewrite) · `test_tc_b99_13_zero_byte_target_is_never_reused` · `test_tc_b99_14_save_project_missing_source` (F5 black-box) · `test_tc_b99_39_delete_calls_delete_only_owned_staging` · `test_tc_b99_44_change_document_stages_in_private_home` (F4) · `test_tc_b99_44_junction_at_staging_temp_is_refused` (F4/F3) | 13 passed |
| **B · black-box** `AT-B99-05` (F5 rewrite) + `AT-B99-04` arm ↔ US-144 | `core` · `full` | `test_at_b99_05_save_project_after_same_name_save_back` · `test_at_b99_04_distinct_names_parallel_regression_guard` | 2 passed |
| **UX-C10** hostile-name sinks | `core` · `full` | `test_tc_b99_ux_c10_save_project_filename_renders_literally` · `test_tc_b99_ux_c10_placement_error_path_renders_literally` | 2 passed |

Regression companions (reverse census, see below): part 1 — **368 passed, 4
failed** (2 re-pinned, 2 pre-existing); part 1 rerun — **369 passed, 3
failed** (the re-pinned two already fixed + pre-existing TC-018); part 2 —
**458 passed, 8 failed** (2 staging-seam re-pins fixed, 2 pre-existing, 4
flakes); `tests/test_b99_staging.py` + re-pinned files final — **27 passed**
(`green-final.txt`).

**Fix-round runs (review round 1):** `tests/test_b99_staging.py` (final
test, 17 nodes) — **17 passed** (`green-fix-all.txt`); the 3 re-pinned test
files — **94 passed** (`green-fix-repinned.txt`);
`tests/test_address_census.py` — **23 passed** (`green-fix-census.txt`);
`tests/test_changes_apply.py` (the `save_patched_image` seam, reverse-census
spot check) — **41 passed** (`green-fix-changes-apply.txt`); AT-B99-05 run 8
times — **8/8 passed** (`stability-at05.txt`).

### Review round 1 fixes — RED counterfactual, mutations, evidence

**RED at the unmodified base `a52e2be`** (scratch `git worktree add` of the
base in the temp dir, final test file copied in, worktree removed after the
runs — `git stash` is forbidden):

- `red-fix-new-arms.txt` — the new/changed white-box arms at base: **6
  failed / 2 passed**. RED: TC-B99-11 junction arm (the write rode the
  junction and landed outside the work area), TC-B99-12 forced-`OSError`
  arm (no `WorkareaPlacementError` exists at base), TC-B99-13 zero-byte arm
  (base reuses the 0-byte target), TC-B99-39 census (base names the
  `apply.py` re-derived unlink), TC-B99-44 both arms (no private staging,
  no reparse check). GREEN at base by design: the concurrent TC-B99-13 arm
  and the directory-squat arm — base placement is check-then-copy with
  name-collision dedup, which serializes these arms without the F1/F2
  machinery; their RED proofs are the mutants below.
- `red-at_b99_05.txt` — the FINAL black-box AT-B99-05 at base: **FAILED
  with P-15's exact mechanism** (`FileNotFoundError` on the deleted work
  copy `temp\firmware.s19`, driven by keys and clicks through the real
  dialogs). Re-recorded as F5 requires.
- `red-fix-tc14.txt` — the FINAL black-box TC-B99-14 at base: **FAILED**
  (same `FileNotFoundError` escape ends the app run).

**Mutations (fix round, all KILLED, all reverted — restores verified by
SHA-256 against the pre-mutation snapshot `20c24f…/f8b132…/b17441…/
e41cf7…`):**

| Mutation | RED proof | Transcript | Restore |
|---|---|---|---|
| shared `temp/<name>` staging restored in `save_patched_image` + re-derived unlink (LLR-155.1) | TC-B99-11 (work copy deleted) + TC-B99-39 (census) FAILED | `mut-fix-155.1-shared-staging.txt` | `apply.py` hash restored |
| check-then-copy: O_EXCL claim replaced by an unconditional take (LLR-155.2; the amended LLR-155.3 negative control) | TC-B99-12 race FAILED (on Windows the clobbering take hits a sharing `PermissionError`; on POSIX the same mutant yields nonzero mismatches) and the corrected concurrent TC-B99-13 arm FAILED (both arms, `parallel mismatches` mechanism) | `mut-fix-155.2-check-then-copy.txt` · `mut-fix-155.2-tc13-concurrent.txt` | `workspace.py` hash restored |
| reuse-compare single-read (round-1 mut-155.3) | **SUPERSEDED** — the double read was retired per LED .7, so this mutant is byte-identical to the fixed code; the amended LLR-155.3 negative control is the check-then-copy mutation above | `mut-155.3-superseded.txt` (statement + transcripts) | n/a |
| re-derived unlink restored in `save_patched_image` `finally` (LLR-155.7) | TC-B99-39 census FAILED (names the re-derived binding) + TC-B99-11 FAILED (work copy deleted) | `mut-fix-155.7-rederived-unlink.txt` | `apply.py` hash restored |
| no directory handling in the claim (F1): every claim `OSError` becomes `WorkareaPlacementError` | TC-B99-12 directory-squat arm FAILED — the squatter's `PermissionError` refuses the write instead of moving to `_1` | `mut-fix-f1-no-directory-handling.txt` | `workspace.py` hash restored |
| staging under `temp/` directly, no reparse check (F3): `_private_stage_dir` bypassed | BOTH junction arms FAILED — TC-B99-11 junction arm and TC-B99-44 junction arm (write lands outside the work area through the junction) + the TC-B99-44 private-home spy arm FAILED | `mut-fix-f3-shared-temp-staging.txt` | `workspace.py` hash restored |

| Field | Value |
|---|---|
| **Fix-round RED counterfactual** | 3 transcripts at base `a52e2be`, each FAILED with its declared mechanism; the 2 arms GREEN at base are RED-proved by the F1/F3 mutants (their mechanisms did not exist at base) |
| **Fix-round mutation verdicts** | 5 runnable mutants, all KILLED; 1 superseded (mut-155.3); no mutant left in place |

**Caller census after F1** (rebuilt — the claim/fill wrap adds two more
`WorkareaPlacementError` raise sites; both are the
`WorkareaContainmentError` subclass, so every handler below catches them
unchanged; line numbers refreshed on the fixed tree):

| # | Path (file:line) | Caller | Handles? | The text the user sees on a placement failure (UX-C5 column) |
|---|---|---|---|---|
| 1 | `app.py:8032` | `_handle_save_dialog` (primary) | ✓ except 8042 (+ containment 8058) | `Not saved: <name> in <folder> is still locked after 5 retries, another program may hold it — close it and retry. Nothing written.` (or the claim/fill form of the same message) |
| 2 | `app.py:8037` | `_handle_save_dialog` (MAC) | ✓ same try | same |
| 3 | `app.py:8040` | `_handle_save_dialog` (A2L) | ✓ same try | same |
| 4 | `app.py:8450` | `_sync_loaded_file_to_project` (variant) | ✓ except 8491 | `Project sync rejected: <containment text>` |
| 5 | `app.py:8481` | `_sync_loaded_file_to_project` (MAC) | ✓ same except | same |
| 6 | `app.py:8489` | `_sync_loaded_file_to_project` (attached MAC) | ✓ same except | same |
| 7 | `app.py:8511` | `_sync_loaded_a2l_to_project` | ✓ except 8513 | `A2L sync rejected: <containment text>` |
| 8 | `app.py:8614` | `load_from_path` | ✓ except 8615 | `Cannot load file: <containment text>` |
| 9 | `app.py:8685` | `load_a2l_from_path` | ✓ except 8686 | `Cannot load A2L: <containment text>` |
| 10 | `apply.py:781` | `save_patched_image` | ✓ except 783 (issue, no raise) | `[MF-WRITE-CONTAINMENT] warning: … the patched image was not written: <text>` |
| 11 | `io.py:1608` | `write_change_document` | ✓ except 1611 (issue, no raise) | `[MF-WRITE-CONTAINMENT] warning: … no file was written: <text>` |
| 12 | `crc.py:1348` | `write_crc_image` (Inc 5) | ✓ except 1349 (finding, no raise) | `CRC write failed — no file was written: <text>` |
| 13 | `flow_execution_service.py:519` | WRITE-OUT arm via `save_patched_image` | ✓ (issues → `write failed` block result) | `write-out block … write failed` |
| 14 | `flow_execution_service.py:872` | external-step copy | ✓ `except Exception` 875 (recorded) | `✗ external step copy failed — WorkareaPlacementError: <text>` |
| (15) | `flow_persistence_service.py:1106` | `import_flow_file` | ✓ `screens.py:890` (inline status) | `import refused: WorkareaPlacementError` |

All 14 (+1 indirect) callers handle the containment class; the F1 wrap is a
subclass by construction, so no caller edit was needed — the census above
is the verification. The two new raise sites (claim failure, fill failure)
are exercised by the TC-B99-12 forced-`OSError` arm (direct) and ride the
same handlers everywhere else.

### Review round 2 fixes — RED counterfactual, mutations, evidence

**RED at the review-round-2 tree** (the round-1-fixed tree, before the
round-2 fixes; final test file, transcripts in `evidence/inc-3a/`):

- `red-fix2-new-arms.txt` — the four new white-box arms: **4 failed**,
  each with its declared mechanism: the dangling-junction arm (refusal came
  from the mkdir fallback with a generic message, not the reparse check —
  S-F3), the dangling-symlink arm (the bare `O_EXCL` claim followed the
  link — S-F1; verified empirically on this host before the test was
  written), the vanished-source arm (raw `FileNotFoundError` escapes —
  S-F6), the symlink-dedup arm (the reuse read followed the link and
  returned the symlink itself — S-F4).
- `red-fix2-full.txt` — full-file run at the same tree (intermediate test
  state): 7 failed / 16 passed; the two TC-B99-14 F6a arms and AT-B99-05
  failed only on their first authoring iteration (status-line clipping /
  wait-assertion inconsistency) and were repaired without any source
  change — see the final-state note below.
- GREEN at the review-round-2 tree **by design**: the two TC-B99-14 F6a
  arms (the cleanup and the conservative flag landed with round 1) and
  AT-B99-05 (LOW-2 is a test-consistency repair, no oracle change) — their
  RED proofs are the mutants below.

**Mutations (fix round 2, all KILLED, all reverted — restores verified by
SHA-256 against the pre-mutation snapshot `c933f7…` / `8bdc82…`,
`mut-fix2-pre-snapshot.txt`):**

| Mutation | RED proof | Transcript | Restore |
|---|---|---|---|
| pre-claim `lstat` removed — bare `O_EXCL` claim (S-F1 negative control) | TC-B99-12 dangling-symlink arm FAILED — the claim followed the link; the post-claim recheck caught the swap and refused, but the write-through at the link's target already happened | `mut-fix2-sf1-no-preclaim-lstat.txt` | `workspace.py` hash restored |
| staging `copy2` OSError unwrapped (S-F6 negative control) | TC-B99-12 vanished-source arm FAILED — raw `FileNotFoundError` escapes past the containment-class callers | `mut-fix2-sf6-unwrap-copy2.txt` | `workspace.py` hash restored |
| check-then-copy: `O_EXCL` dropped from the claim, every writer takes the same name (LLR-155.2/.3 negative control, re-run after the claim-loop rework) | TC-B99-12 race arm FAILED with **`parallel mismatches: 35`** and the TC-B99-13 concurrent arm (now under the LOW-1 pause hook) FAILED with **`parallel mismatches: 68`** — both real, NONZERO mismatch counts | `mut-fix2-155.2-check-then-copy.txt` | `workspace.py` hash restored |
| `_private_stage_dir` bypassed: staging under `temp/` directly, no reparse checks, no S-F2 re-verification (F3/S-F2/S-F3 negative control, re-run) | ALL THREE junction arms FAILED — TC-B99-11 junction, TC-B99-44 junction and the new dangling-junction arm (the write rode the junction / the refusal did not name the reparse point) | `mut-fix2-f3-temp-staging.txt` | `workspace.py` hash restored |
| `_remove_created_project_dir` no-op (F6a negative control) | TC-B99-14 placement-failure arm FAILED — the folder this call created survives the failure | `mut-fix2-f6a-no-cleanup.txt` | `app.py` hash restored |
| `created_project_dir` forced True on `FileExistsError` (S-F5 negative control) | TC-B99-14 pre-existing-folder arm FAILED — the pre-existing folder with operator content is destroyed | `mut-fix2-sf5-flag-always-true.txt` | `app.py` hash restored |

| Field | Value |
|---|---|
| **Fix2 RED counterfactual** | 4 new arms FAILED on the review-round-2 tree with their declared mechanisms (final test file); the 3 nodes GREEN at that tree are RED-proved by mutants (their mechanisms pre-date round 2) |
| **Fix2 mutation verdicts** | 6 mutants, all KILLED, none left in place; restores hash-verified |

**Caller census after round 2** — no new caller-facing raise type: the S-F6
wrap and the S-F1 post-claim raises are the same `WorkareaPlacementError`
subclass, so all 15 census rows stay valid; the app.py rows shift by +4
lines after `app.py:8005` (comment growth only): primary `copy_into_workarea`
`app.py:8040` → `except 8050` (+ containment `8066`); MAC `8045`; A2L
`8048`; the workspace/apply/io/flow rows are unchanged in substance. The S-F6
message (`Not saved: <name> could not be copied: <cause>. Nothing written.`)
rides the same UX-C5 column.

**Fix2 GREEN runs:** `tests/test_b99_staging.py` — **23 passed**
(`green-fix2-staging.txt`); the 3 re-pinned files — **94 passed** +
`tests/test_address_census.py` — **23 passed** + AT-B99-05 ×8 — **8/8
passed** (`green-fix2-repinned-census-at05.txt`); reverse census —
**341 passed / 4 failed** (3 environmental main-ref pins + 1 documented
pre-existing, none from this increment — see the reverse-census section),
`green-fix2-reverse-census.txt`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | four (C-40), one per declared negative control; each reverted by hash |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc3a`), run by the implementer |
| Transcripts | `evidence/inc-3a/mut-155.1-shared-staging.txt` · `mut-155.2-check-then-copy.txt` · `mut-155.3-no-source-verify.txt` · `mut-155.7-rederived-unlink.txt` (each: target node FAILED) |
| Restore proven by | file hashes returned to pre-mutation values: `apply.py` → `52071a04…`, `workspace.py` → `21cd8f87…` (recorded in the run log; both verified after the last mutation) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED at the unmodified tree: `red-all.txt` (**10 failed, 2 passed** — the 2 passes are the intended non-RED arms: the mtime arm and the AT-B99-04 regression guard). TC-B99-12's race arm shows the PQ-8 deterministic line `parallel mismatches: 140` (the forced interleaving guarantees the RED; P-5's mechanism reproduced at the maximum). P-15's mechanism reproduced: `red-at_b99_05.txt` (work copy deleted; Save project escapes with `FileNotFoundError`). `red-tc_b99_39.txt`: the census names `apply.py:save_patched_image:779 deletes 'staged' without an owned-binding guard` — the declared LLR-155.7 RED site. |

Mutation verdicts:

| Mutation | RED proof | Transcript | Restore |
|---|---|---|---|
| shared `temp/<name>` staging (LLR-155.1): `save_patched_image` stages at `temp/<safe_name>` again + re-derived unlink | TC-B99-11 (work copy deleted) + TC-B99-39 (census) FAILED | `mut-155.1-shared-staging.txt` | `apply.py` hash restored |
| check-then-copy (LLR-155.2): the O_EXCL claim replaced by an unconditional take of the requested name | TC-B99-12 race (`parallel mismatches: 140`) + TC-B99-13 hook arm FAILED | `mut-155.2-check-then-copy.txt` | `workspace.py` hash restored |
| no verify of the source (LLR-155.3): the reuse compare single-read | TC-B99-13 hook arm FAILED (the caller receives the replaced bytes) | `mut-155.3-no-source-verify.txt` | `workspace.py` hash restored |
| the re-derived unlink (LLR-155.7): `finally` unlinks a path rebuilt from the user name | TC-B99-39 FAILED naming exactly `apply.py:save_patched_image:795 deletes 'staged' without an owned-binding guard`; TC-B99-11 also FAILED | `mut-155.7-rederived-unlink.txt` | `apply.py` hash restored |

Note (mapping to the brief): the brief's mutation list names TC-12 for the
shared-staging and source-verify mutations; on this tree those two mutations
are most sharply observable through TC-B99-11/TC-B99-13 respectively (TC-12
drives `copy_into_workarea` directly), so the RED nodes above are the sharpest
witnesses; all four declared mutants are KILLED and none survives.

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the tree before the fix | `red-all.txt`: 10 failed (every new TC/AT RED) |
| `pytest` + TC-B99-12 race arm | unmodified placement under the forced interleaving | `parallel mismatches: 140` (`red-tc_b99_12.txt`) |
| the AST census (TC-B99-39) | the HEAD `save_patched_image` | `apply.py:save_patched_image:779 deletes 'staged' without an owned-binding guard` (`red-tc_b99_39.txt`); and under the re-derived-unlink mutant `…:795…` (`mut-155.7-rederived-unlink.txt`) |
| the pilot (TC-B99-14/AT-B99-05) | Save project with a deleted work copy at HEAD | the `FileNotFoundError` escape ends the app run (`red-tc_b99_14.txt`, `red-at_b99_05.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the placed S19 images (engine + pilot arms) | every reported path re-read with `tests/support/independent_reader.py` (`read_s19`) and compared to the writer's own marker map | 0 mismatches post-fix; 140 pre-fix (`green-tc_b99_12.txt` / `red-tc_b99_12.txt`) |
| the saved project image (AT-B99-05) | `independent_reader.read_s19` on `<workarea>/proj/firmware.s19` | `{0x1000: 0x11, 0x2000: 0x00}` — the loaded image the project holds |
| the 8 lane files (AT-B99-04 arm) | `independent_reader.read_s19` per `lane{i}.s19` | each holds its lane's marker `{0x1000: 0x41+i}` |
| the painted status / notice texts (UX-C4/C5/C10) | literal containment of the outcome token at index < 50 and of the hostile literal with 0 markup spans (`markup=False` notify + literal status) | `Project NOT saved` at index 8; `Not saved` at index 0; hostile literal present verbatim |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 artifact families, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-3a/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| Worktree import proof + CRLF check | `import-proof-crlf.txt` | `b52fd19163af05ed238679810413f7c8a378ba2cdd419ece5ba50d43ccc8a50e` |
| RED baseline, whole file | `red-all.txt` | `a7227a942139811926be6da5e3001ea8ee6d369ab2c400807f17aaeb3d291bb8` |
| RED TC-B99-11 | `red-tc_b99_11.txt` | `c2e9cdaba12bea8634c820fef8d40750214209e67360b5ad412ba9c6642c2470` |
| RED TC-B99-12 (PQ-8: `parallel mismatches: 140`) | `red-tc_b99_12.txt` | `1c4ba257f142b8f92daf95e6dbb70d481115156ccef4bf1f43450641425b9cd0` |
| RED TC-B99-13 | `red-tc_b99_13.txt` | `32a634d7d1a7874b1927a4544f1bea1a6981418f4b0910e5aa7fab54b2eb8819` |
| RED TC-B99-14 | `red-tc_b99_14.txt` | `c7acc5780ac0ca103cdd6e47f8eed2d8c2113a1efad75d29de54a6bfb2af3d8b` |
| RED TC-B99-39 | `red-tc_b99_39.txt` | `6da20c881265779953da10feeed2b5b098e5a8b5ccc36d29526db043df5a1c6b` |
| RED AT-B99-05 (P-15) | `red-at_b99_05.txt` | `b664f923204dd600fea37732dba18cb1f4803e3824b51c268a9a6935b2dc1fd9` |
| RED UX-C10 arms | `red-ux_c10.txt` | `32e666bb185531e7e8785e13cc83dd3157721eb1723c92d428c649fcbcc29da1` |
| Mutation shared staging (KILLED) | `mut-155.1-shared-staging.txt` | `979ebcacee2f7ef9000191b442826d71651f7a7932a750f225ea3bcf11622244` |
| Mutation check-then-copy (KILLED) | `mut-155.2-check-then-copy.txt` | `afdc8aef5f434d75ca422c45154440149c28b3707928cf4e58c7a039afbb0fb9` |
| Mutation no source verify (KILLED) | `mut-155.3-no-source-verify.txt` | `0d03c57e09ed1ff1c9d3c4d75f28e8c327424a464ce8af3ac845f0e7b8a51799` |
| Mutation re-derived unlink (KILLED) | `mut-155.7-rederived-unlink.txt` | `9742e1c91e144728285f7ff7a43a1cb00bac8aca9fa5289795ee8f27ae031175` |
| GREEN whole file (12 passed) | `green-all.txt` | `b9be08fef3174cd84727fc6ea828d291a255247260085098ea6abca370a41498` |
| GREEN TC-B99-11 | `green-tc_b99_11.txt` | `df5a1989c036243ae45bf3b9d53f0e401993a2e1e4f87582d0824497f3de2f8f` |
| GREEN TC-B99-12 (3 arms) | `green-tc_b99_12.txt` | `6c14011f23367521957706b3401010ddf6168caf2db1850b73d43ac0dd5c1e3e` |
| GREEN TC-B99-13 (2 arms) | `green-tc_b99_13.txt` | `f99cac00da29780bfeb1e6d98ce6b4294ac33d127a7ff9343aa8340410527377` |
| GREEN TC-B99-14 | `green-tc_b99_14.txt` | `1b2f2c289780fe8df546b1a0f8db1070a5ced8c68f240a760de7f348c06d5121` |
| GREEN TC-B99-39 | `green-tc_b99_39.txt` | `3da5f9d29677b5c267faa37c40bf257948999a1062c63a0d6a94c75e0a4aa6a0` |
| GREEN AT-B99-04 arm (guard) | `green-at_b99_04.txt` | `1857aaf53f74860bf8eb5e3a0c0949a7c8108fb35f3204fb5cda3724a2c1beae` |
| GREEN AT-B99-05 | `green-at_b99_05.txt` | `e7cb4f60183ad70389aa890f25427b978d082afaf4846a84f41ed279d6760dce` |
| GREEN UX-C10 arms | `green-ux_c10.txt` | `7b476da739dcbe5069b98d72dcf842ec8b3dc3bed2b3129fb4b557c6008d4a4d` |
| GREEN staging-seam re-pins (10 passed) | `green-staging-block-repin.txt` | `232efe8f68a63b2f40a15d69073131d8520b91921fb5b18379f2fcd68094ea8e` |
| GREEN final (increment + re-pinned files, 27 passed) | `green-final.txt` | `0eafc6c5cc116ff13f70bdc314f3e09d02328ab42973d441b7f0a91f4f97866c` |
| Reverse census part 1 | `census-part1.txt` | `c5e2c5f121c1c017917ab664242888bcb41ea4d2f3fc31f4981ad494cbe5c8da` |
| Reverse census part 1 rerun (AT-038c flake check) | `census-part1-rerun.txt` | `2b3af0a52d631c3a500c5d33d315f0e6c1d7cb2f0152d5ba804aa3652c0ad775` |
| Reverse census part 2 (heavy TUI) | `census-part2.txt` | `e0243ca8693dfe2757432f06ac8316a629213a58efd20cb2a7ccd07039ead4b2` |
| `test_tui_patch_editor_v2.py` full file (this tree) | `census-patch-editor-v2.txt` | `a1048420fd233f76a559cf59f342370fab2ef298e4b142523531f4e4e749f551` |
| same file at base `a52e2be` (scratch worktree) | `baseline-patch-editor-v2-at-HEAD.txt` | `245a6281700f7fa296c90403bd721b83eb1923d9cd982ceac0ef6415a00e325c` |
| Reverse census hit list | `reverse-census-hits.txt` | `8b4b347ca312fcc7165c97c0cbb90e8679b1bfd03fe43111a43c41cbef5a9395` |
| Fix-round GREEN, whole file (17 passed) | `green-fix-all.txt` | `601b7988c46daab41d107b0a54f7f4f73d70d768bdbc3e129186b53aeda8a91a` |
| Fix-round GREEN, re-pinned files (94 passed) | `green-fix-repinned.txt` | `d2b7425691214141e1fdf828514c6de26e14bef2c624b08cd1e148dd6d1ea78e` |
| Fix-round GREEN, address census (23 passed) | `green-fix-census.txt` | `ad8401cec5f67b9adb62e003747db0b8905be47ecfcdf22b9e62f33cde0dfc3a` |
| Fix-round GREEN, TC-B99-13 after the contention fix | `green-fix-tc13.txt` | `0f881abfad8fbdefcec296339b0f1e5f24b7723e34045ca93127c5289bc78864` |
| Fix-round GREEN, changes-apply seam (41 passed) | `green-fix-changes-apply.txt` | `2f2ab19445fb2509a43d55c68f12613389f55fe37aea554d5976b00affdaf56f` |
| Fix-round AT-B99-05 stability (8/8 passed) | `stability-at05.txt` | `6265ca34bace6b63837a39fc85862617e26bae0be2b6d85f514d2b413c4dcb58` |
| Fix-round RED, new/changed arms at base `a52e2be` (6 failed / 2 passed) | `red-fix-new-arms.txt` | `f5d812d9338ce69d6543c07b49e05bc71732706e021e29bbd1b5e2f9be26c871` |
| Fix-round RED, AT-B99-05 black-box at base (P-15) | `red-at_b99_05.txt` | `166d8538a38277b8182185d9e1bfd15c86b819e8c2d8d88923215ec979d66d65` |
| Fix-round RED, TC-B99-14 black-box at base | `red-fix-tc14.txt` | `0d70d5a1f55f91b8bd8a3237e34f7e3fe716045aa7c2008cb471acf3165f5b83` |
| Fix mutation shared staging (KILLED) | `mut-fix-155.1-shared-staging.txt` | `61f1d21a54af24053d9ac8e6ed75b2f8fdbf87939d4d742b632a85257d2ebc3b` |
| Fix mutation check-then-copy (KILLED) | `mut-fix-155.2-check-then-copy.txt` | `48e9b783ca01100136fcbac06df0ece0e16164d217b788cf759b9ee36e3f3485` |
| Fix mutation check-then-copy vs concurrent TC-B99-13 (KILLED) | `mut-fix-155.2-tc13-concurrent.txt` | `0cbdc933726f6e33c13b0574ff882e51b2ac19f4bce01a953809ffba99a40b7e` |
| Fix mutation 155.3 supersession statement | `mut-155.3-superseded.txt` | `837c81def50ded2fd195a65fdebb4a9df1d2468184a904b91373560abc1fa824` |
| Fix mutation re-derived unlink (KILLED) | `mut-fix-155.7-rederived-unlink.txt` | `27ca7d10b18b7f305736e3e91029c482370e6084c3827eb9792e329f4f1ce928` |
| Fix mutation no directory handling (KILLED) | `mut-fix-f1-no-directory-handling.txt` | `3de78d089a56d9b1694ca31fa8b94ed32049b2a027c8652f25c01ad4876626f2` |
| Fix mutation staging under `temp/` (KILLED) | `mut-fix-f3-shared-temp-staging.txt` | `1cf4855813b6e00cf803dfcd26a81f4833a39944a59cb1639b9fb9e2d178dcfb` |
| Fix-round CRLF verification (all edited sources pure CRLF) | `crlf-fix.txt` | `df363a484785cb0a8cf87e330c6686b5245d56f14ef4d72fe8f0254bad02edf9` |
| Fix2 RED, the four new arms on the review-round-2 tree (4 failed, declared mechanisms) | `red-fix2-new-arms.txt` | `fc59674b2824bd71c5d7fedfddfa5ae1de42167474689ccf78526347b87fb481` |
| Fix2 RED, full staging file on the review-round-2 tree (intermediate test state) | `red-fix2-full.txt` | `8f3d72d9f73fc41c64c8918904f44a6fb71c5c197810dc7b5a0b4e2483b13545` |
| Fix2 GREEN, staging file (23 passed) | `green-fix2-staging.txt` | `5eb1d085ec1b190418ab6e2b1f54bd8dbe48da5cfac671e3468206b3c8707f5d` |
| Fix2 GREEN, re-pinned files (94) + address census (23) + AT-B99-05 x8 (8/8) | `green-fix2-repinned-census-at05.txt` | `f0fe65456a0da32af2e96c258b1d792da206951fb8be383fd9a20919e557a97b` |
| Fix2 mutation pre-claim lstat removed / S-F1 (KILLED) | `mut-fix2-sf1-no-preclaim-lstat.txt` | `0016e854076b38e555cf6e40b653880cf6fff9c49d6a022e3288a2e4becca072` |
| Fix2 mutation copy2 unwrap / S-F6 (KILLED) | `mut-fix2-sf6-unwrap-copy2.txt` | `4f787596e60e8273946a2991f1b9d674fa707493872efa97b62d6d9d95615a2e` |
| Fix2 mutation check-then-copy, O_EXCL dropped (KILLED; mismatches 35 / 68) | `mut-fix2-155.2-check-then-copy.txt` | `5a0a1c2c7493bd008fe2b0396689d5b515c01ae1006c2e8786c5cd98d5ebbef0` |
| Fix2 mutation staging under `temp/`, checks removed / F3+S-F2+S-F3 (KILLED) | `mut-fix2-f3-temp-staging.txt` | `051db8b1436ab36d0878d2a0014550b1e1a56a47d3c69faa60dac8bc51b13223` |
| Fix2 mutation cleanup no-op / F6a (KILLED) | `mut-fix2-f6a-no-cleanup.txt` | `0c339f7314dedfa496fffbfa60f422b7dc4e43f12d74593f653cad2628f80b28` |
| Fix2 mutation created-flag forced True / S-F5 (KILLED) | `mut-fix2-sf5-flag-always-true.txt` | `d79610aecb29d1f539302ce711ab8f9352a91b3db67b632de8b5a8e998bb244f` |
| Fix2 mutation pre-mutation source snapshot (restore verification) | `mut-fix2-pre-snapshot.txt` | `87f084e9778d88822e9b6999aed81652caa0281202e3e2697c5a2c61158195f9` |
| Fix2 GREEN, reverse-census batch (341 passed / 4 failed — 3 environmental `git diff main` pins, see §4; 1 documented pre-existing `test_tc018`) | `green-fix2-reverse-census.txt` | `095109da7b193f6caa3b1484d830560f55e177c337d180378a0029e4bd674ff9` |
| Fix2 CRLF verification (all four edited sources pure CRLF) | `crlf-fix2.txt` | `f852ee716428fb125d3ab00710db1989de94e818c6bc911d5b3faf67b50e782f` |

| Field | Value |
|---|---|
| **Evidence files** | 61 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) TC-B99-39 rests on every delete in the four writers being owned (an ABSENCE of violations); (2) the reuse race-closure rests on no in-app writer replacing an existing name (C1(b)) |
| If the result is an ABSENCE, what made the search wide enough | (1) the AST census walks **every** call in the four functions, any depth, and binds each delete to a `mkdtemp`/O_EXCL-claim name via alias chains, guarded by the immediately-following boolean — not a sampled grep; (2) the claim design makes the absence structural: `os.open(O_CREAT\|O_EXCL)` can never open an existing name, and no code path calls `os.replace` onto anything but the own claim |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_39_delete_calls_delete_only_owned_staging` — the census assertion is its own named node, with the exactly-one-known-exception pin |
| Conjunctive criteria: one mutation per conjunct | the four mutations each attack one conjunct (private staging / exclusive claim / source verify / owned delete) |
| Synthetic instance of the absent case | each mutant IS a writer doing the forbidden thing (shared staging, check-then-copy, single-read reuse, re-derived unlink) — each exists only as a transient mutation, reverted by hash |
| **Positive control for every probe that returned an ABSENCE** | the RED census at HEAD names the apply.py:779 violation (non-absent output of the identical probe, `red-tc_b99_39.txt`); the claim-loop mutant makes the identical race probe return `parallel mismatches: 140` (`mut-155.2-check-then-copy.txt`) |

### Reverse census — trigger family B, and A3

Probe: `grep -rln "copy_into_workarea\|save_patched_image\|staging_block\|WorkareaContainmentError" tests/` → 23 files
(`reverse-census-hits.txt`); every hit re-validated by running its file
(part 1: engine/service files; part 2: heavy TUI files).

Re-pins (each: `test::node — old value → new value — requirement`):

1. `test_copy_into_workarea_content_dedup.py::test_tc1800_reload_same_content_reuses_existing_target` — `on_disk == ["fw.s19"]` → `on_disk == [".staging", "fw.s19"]` + new `list((workarea / ".staging").iterdir()) == []` — **HLR-155 / LLR-155.1**: the private-staging home legitimately persists under `temp/` (the design's `mkdtemp` parent; like `temp/` itself); per-write dirs are still removed. Verified `green-final.txt`.
2. `tests/test_id_registry.py::EXPECTED_SCANNED_TEST_FILES` — `199` → `204` — **bound bump**, not a behavior pin: the guard's own count was already 203 at base `a52e2be` (Inc-1 modules; pre-existing drift) and this increment adds `test_b99_staging.py`. Verified `green-final.txt`.
3. `tests/b97_fixtures.py::staging_block` + `tests/test_b97_chips_help.py::test_tc_b97_58_check_editor_region_states[write_dir|write_readonly]` + `test_at_b97_23_each_failed_region_says_so_in_one_line[check_write_dir|check_write_readonly]` — blocker plants at the private staging home `temp/.staging` (`dir` = wrong type: a file; `readonly` = reparse point: a symlink — the retired read-only-FILE seam is unrepresentable: the new writer never overwrites an existing name) and plants **after** the A2L load (the load rides the same placement) — **HLR-155 / LLR-155.1** (the qa census predicted exactly this `staging_block` movement). Verified `green-staging-block-repin.txt` (10 passed).
4. `s19_app/tui/workspace.py::copy_into_workarea` (source, discovered by the census, not a test pin): staging-home preparation errors (`FileExistsError`, `PermissionError` at `temp`/`.staging` creation or `mkdtemp`) now convert to `WorkareaContainmentError` instead of escaping as raw `OSError` — without this, a planted file at `.staging` crashed the app-level load paths that only catch the containment class. This is the LLR-155.2 subclass contract applied to the new seam.

Pre-existing failures at base `a52e2be` (verified by re-running in a scratch
worktree at HEAD; NOT re-pinned — none is changed by this requirement):
`test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed` and
`test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber`
(both: the serializer is deterministic — "two serializations of the same
document are byte-identical", `changes/io.py` docstring — so the pre-existing
B8 byte-identical reuse returns the same path; the behavior predates this
increment); `test_window_usage_help.py::test_tc707_*` ×2 (the untracked
`prototypes/cambios_10_12_2026/help_sections.md` is absent from this
worktree — environment, unrelated to placement).

Flakes observed once under the 22-minute suite load and NOT reproduced
standalone or on the part-1 rerun (both placement-adjacent tests pass
standalone on this tree): `test_before_after_report.py::test_at_038c_missing_original_trigger_refuses_and_writes_nothing` (passed
on the full-sequence rerun, `census-part1-rerun.txt`), and in part 2
`test_save_back_prompt` / `test_verify_loud_mismatch_notice` (pass standalone)
plus `test_at030c` / `test_at064c` / `test_tc344` — the full
`test_tui_patch_editor_v2.py` file is non-deterministic at the base commit
too: **5 failed / 47 passed at `a52e2be`** with a *disjoint* failure set
(`baseline-patch-editor-v2-at-HEAD.txt`), the only common node being the
pre-existing `test_at031b`. No causal link to HLR-155; flagged for the
orchestrator's full-suite run.

Review round 2 probe: `grep -rln
"copy_into_workarea\|WorkareaPlacementError\|_private_stage_dir\|_is_reparse_point\|created_project_dir\|_remove_created_project_dir" tests/`
→ 15 files; 4 are comment/registry mentions only (`test_crc_designer_view`,
`test_crc_operation`, `test_tui_public_api`, `test_id_registry` — the last
re-run in the 94-pass set), the other 11 re-validated in the fix2 batch —
`green-fix2-reverse-census.txt`: **341 passed / 4 failed**, the 4 being
3 environmental pins and 1 documented pre-existing — none caused by this
increment: `test_tc031_*`/`test_tc032_*` diff the frozen engine surface
against the LOCAL `main` ref, which in this worktree has already advanced
to batch-99 inc-9 (`725d474`) and modified `core.py`/`hexfile.py`/`a2l.py`
between this worktree's base `a52e2be` and `main` (verified: the working
tree holds no engine modification — `git status`; the diff content comes
from `a52e2be..main`, not from these edits; none of the increment's files
is in `_ENGINE_PATHS`/`_ENGINE_TEST_FILES`), plus
`test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed`
(documented pre-existing at base since round 1). No re-pin needed: every
fix2 behavior change is a
refusal for a case no existing test plants (a link at the final name, a
source vanishing mid-copy, a dangling junction, the mkdir TOCTOU flag), and
no test pinned the old, wrong behavior. `FileNotFoundError` expectations:
none in the hit files — the missing-source `FileNotFoundError` from
`source.stat()` (LLR-155.4) is unchanged; only the `copy2` path is wrapped
(S-F6).

| Field | Value |
|---|---|
| **Reverse census** | 23-file probe executed in 2 parts + targeted reruns; 4 documented re-pins (3 test files + 1 source seam), 4 pre-existing failures at base, 5 load-flakes flagged; `tests/test_manifest_writer.py:406` unchanged and green (the manifest writer owns its staging; `temp/project.json` absent after the write still holds) |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| shared `temp/<name>` staging writers | every `copy_into_workarea(` site + `save_patched_image` + the injected 14th path | `grep -rn "copy_into_workarea(" s19_app/` + the PDR C2 row | 14 placement paths (13 direct callers + `io.py:1586`); the WRITE-OUT arm rides `save_patched_image` | 3 (workspace, apply, io) + app handler | the CRC write site (LLR-155.8, Inc 5) — declared single census exception |

Caller census — for each of the 14 placement paths, does the caller handle
`WorkareaContainmentError` (and so the new `WorkareaPlacementError` subclass,
LLR-155.2 — no caller edit needed)?

| # | Path (file:line) | Caller | Handles? | The text the user sees on a placement failure (UX-C5 column) |
|---|---|---|---|---|
| 1 | `app.py:7985` | `_handle_save_dialog` (primary) | ✓ except at 7995 (+ new placement branch) | `Not saved: <name> in <folder> is still locked after 5 retries, another program may hold it — close it and retry. Nothing written.` |
| 2 | `app.py:7990` | `_handle_save_dialog` (MAC) | ✓ same try | same |
| 3 | `app.py:7993` | `_handle_save_dialog` (A2L) | ✓ same try | same |
| 4 | `app.py:8386` | `_sync_loaded_file_to_project` (variant) | ✓ except 8427 | `Project sync rejected: <containment text>` |
| 5 | `app.py:8417` | `_sync_loaded_file_to_project` (MAC) | ✓ same except | same |
| 6 | `app.py:8425` | `_sync_loaded_file_to_project` (attached MAC) | ✓ same except | same |
| 7 | `app.py:8447` | `_sync_loaded_a2l_to_project` | ✓ except 8449 | `A2L sync rejected: <containment text>` |
| 8 | `app.py:8550` | `load_from_path` | ✓ except 8551 | `Cannot load file: <containment text>` |
| 9 | `app.py:8621` | `load_a2l_from_path` | ✓ except 8622 | `Cannot load A2L: <containment text>` |
| 10 | `apply.py:765` | `save_patched_image` | ✓ except 767 (issue, no raise) | `[MF-WRITE-CONTAINMENT] warning: … the patched image was not written: <text>` |
| 11 | `io.py:1595` | `write_change_document` | ✓ except 1597 (issue, no raise) | `[MF-WRITE-CONTAINMENT] warning: … no file was written: <text>` |
| 12 | `crc.py:1348` | `write_crc_image` (Inc 5) | ✓ except 1349 (finding, no raise) | `CRC write failed — no file was written: <text>` |
| 13 | `flow_execution_service.py:519` | WRITE-OUT arm via `save_patched_image` | ✓ (issues → `write failed` block result) | `write-out block … write failed` |
| 14 | `flow_execution_service.py:872` | external-step copy | ✓ `except Exception` 875 (recorded) | `✗ external step copy failed — WorkareaPlacementError: <text>` |
| (15) | `flow_persistence_service.py:1106` | `import_flow_file` | ✓ `screens.py:890` (inline status) | `import refused: WorkareaPlacementError` |

All 14 (+1 indirect) callers handle the containment class; the two
user-reachable Save-project surfaces paint failure severity (UX-C4). UX-C5's
"caller with no handler" gap is closed by construction (subclass), verified
by the census above.

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| the shared `temp/<user name>` staging idiom | `grep -n "WORKAREA_TEMP / safe_name\|temp/<name>" s19_app/` | yes — no writer stages at a user-derived name under `temp/` anymore | `apply.py` stages via `tempfile.mkdtemp`; `io.py` same; only the CRC site (Inc 5) retains the idiom (`crc.py:1334`) |

### Signed-balance test ledger

`post = base − deleted + added` → round 1: `12 = 0 − 0 + 12` ✓ reconciles;
fix round: `17 = 12 − 1 + 6` ✓ reconciles (the TC-B99-13 hook arm is
deleted, F2; added: the TC-B99-13 concurrent arm, the TC-B99-11 junction
arm, the two TC-B99-12 F1 arms, the two TC-B99-44 arms)
(`tests/test_b99_staging.py`: new file — 0 baseline nodes). Re-pinned
existing files (b97_fixtures, test_b97_chips_help,
test_copy_into_workarea_content_dedup, test_id_registry) modify nodes, net
count unchanged there. Fix round 2: `23 = 17 − 0 + 6` ✓ reconciles (added:
the TC-B99-11 dangling-junction arm, the two TC-B99-12 arms S-F1/S-F6, the
TC-B99-13 S-F4 arm, the two TC-B99-14 F6a/S-F5 arms; AT-B99-05 and
TC-B99-13 modified in place, count unchanged).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH plain OSError on a directory-squatted name; F2 HIGH hook-only race test, LLR-155.3 amended in LED .7; F3 HIGH staging under temp/ without reparse check) · round 2: OK to advance with F6a MEDIUM · round 3: OK to advance (LOW notes) · security-reviewer — spawned as a generic agent with agents/security-reviewer.md · round 1 (after code round 1): changes required (S-F1 MEDIUM dangling symlink written through; S-F2..S-F6 LOW) · round 2: approve, S-F1..S-F6 closed; residual LOW R1 (lstat→open race, same-user attacker) and R2 (vanished source after pre-check) routed to BACKLOG-CODE. The orchestrator renamed a colliding new test id to TC-B99-44 |

---

## 5 · Risks

- The `.staging` home persists under `temp/` by design (shared by concurrent
  writers; removing it when "empty" would race). The Workarea Files list
  reads only the workarea root's files, so the home is invisible in the UI;
  TC-1800's re-pin asserts per-write dirs are removed.
- B8 reuse of a byte-identical target is race-free by the immutability
  invariant (LLR-155.3 as amended by LED .7): no in-app code path replaces
  or deletes a file at a final name except the placement claiming a free
  name, so a placed file is immutable once placed. `project_gather_service`'s
  delete-and-recopy of an existing name (`project_gather_service.py:290-299`)
  is the one known violator of the invariant — it is converted by Inc 3b and
  is the reason TC-B99-13's concurrent arm models in-app writers rather than
  relying on the invariant alone. The double-read narrowing was retired
  (review finding F2): reading twice cannot close the check-and-reuse race.
- **F6(b) declared risk:** the exclusive claim is created empty and filled
  by `os.replace`; a crash of the process between the claim and the replace
  leaves a 0-byte file at the claimed name. This is why a 0-byte target is
  never reused (PDR C1(a) — it may be another writer's claim placeholder,
  pinned by the TC-B99-13 zero-byte arm); the leftover is filled by a retry
  or removed by the operator, and no caller ever reuses it as content.
- TC-B99-14's "1 notice naming the file" threshold is observed through the
  painted status line, which carries the notice text verbatim
  (`notify(...)` with the same message): this app mounts **no `ToastRack`**,
  so `app.notify` has no toast overlay to paint (verified by DOM query in a
  probe run). The error-severity `notify` sink itself is UX-C4-verified by
  the UX-C10 hostile-name TCs (round 1).
- AT-B99-05's painted-status assertion (review finding LOW-2, round 2):
  the wait and the assertion are now consistent — the test waits for the
  final painted line (`Project saved…`) and reads the four-line painted log
  for the superseded `Saved project to … (variant 'firmware')` line, so the
  painted status naming the image file is pinned directly (the round-1 form
  accepted the save-success family because its first wait silently timed
  out 200 pauses — the intermediate line is superseded within one tick —
  and passed only by accident on the second read; the viewport is widened
  to 260 cols so the line is not clipped in the log strip). The disk
  oracles (independent reader on the placed project image) carry the
  byte-level naming.
- `WorkareaPlacementError` messages name paths; every painted surface passes
  through `set_status` / `notify(markup=False)` (UX-C10 hostile-name TCs pin
  both new sinks).
- Pre-existing RED tests at the base commit (`test_tc018`, `test_at031b`) are
  now more visible because this increment touches their seam; they are NOT
  fixed here (out of scope: they pin pre-B8 dedup-by-name semantics for
  deterministically-serialized documents — a batch-96/B99 backlog decision,
  not an Inc-3a regression).
- `test_tui_patch_editor_v2.py` is order-flaky at the base commit (disjoint
  failure sets per run); the orchestrator's full-suite run should treat new
  failures in that file with the same suspicion.
- The `staging_block` readonly arm uses a symlink (reparse point). On hosts
  without symlink privilege the FIXTURE setup fails loudly (not a silent
  pass); the arm can then be re-based on an ACL deny.

## 6 · Pending items / spec deviations

- PDR conditions discharged by this increment: **C1** (0-byte never reused —
  TC-B99-13 arm; the reuse race-closure — TC-B99-13 hook arm models a
  concurrent placement; both staging levels reparse-checked in code), **C2**
  (the 14th path `changes/io.py:1586` converted), **PQ-8** (the race RED is
  deterministic: forced hook + `parallel mismatches: 140`; no re-run until
  red), **UX-C4** (outcome first < 50 chars: `Project NOT saved: …` at index
  8; `Not saved: …` at index 0; failure severity on both Save-project arms),
  **UX-C5** (the exception text names file + folder + cause + next step +
  "Nothing written"; caller census above adds the user-seen-text column; no
  unhandled reachable caller), **UX-C10** (one hostile-name TC per new
  file-derived sink: the Save project file name and the placement-error
  path — 0 markup spans asserted).
- Not discharged here (owned by later increments): D7 (LLR-155.5, TC-B99-15,
  Inc 3b), D9 (LLR-155.6, TC-B99-16, Inc 3b per the split), the CRC write
  (LLR-155.8, Inc 5 — the declared census exception).
- Review rounds 1 and 2 discharged in this increment (reviewers' findings
  F1–F6, S-F1–S-F6, F6a, LOW-1/LOW-2 — see §1 and §4 "Review round 1/2
  fixes"). §4b stays `pending — orchestrator` for both rounds.
- Deviation declared: the AT-B99-04 arm in this file uses 8 distinct source
  images + 8 lanes through the real `#fx_import`/`#fx_mode`/`#fx_run`
  surface; it is a regression guard with no RED claim, as the brief states.

## 7 · Suggested next task

Batch-99 Increment 3b (HLR-155's D7/D9 clauses: LLR-155.5 duplicate-name
refusal at chain-set start, LLR-155.6 WRITE-OUT verify — TC-B99-15/16,
AT-B99-04's duplicate-name arm). It consumes this increment's placement
(`workspace.py`) and the flow lanes, and its RED side is P-5's duplicate-name
set.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 SOURCE files (`git status` — `workspace.py`, `apply.py`, `io.py`, `app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_staging.py` (17 nodes after the fix round, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no new layer-0 node; LLR-155.7's census is the unit-layer guard (TC-B99-39) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED + 4 mutations with transcripts + hash restores; **fix round: 3 RED transcripts at base `a52e2be` (black-box AT-B99-05 P-15 re-record, TC-B99-14, new arms) + 5 mutants KILLED**; **fix round 2: 4 new arms RED on the round-1 tree with declared mechanisms (`red-fix2-new-arms.txt`) + 6 mutants KILLED** |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 23-file probe, 4 re-pins recorded old → new → requirement, pre-existing failures evidenced at base; **fix round: caller census rebuilt after F1 (15/15 handled, refreshed lines); `test_changes_apply.py` seam re-run (41 passed)**; **fix round 2: 15-file probe, no re-pin needed (every change is a refusal for an unplanted case), 8-file batch re-run** |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only the 4 SOURCE files + test/evidence files |
| 8 | Frozen interfaces untouched | all | ✓ | no engine (`hexfile`/`core`) change; `copy_into_workarea` signature + `Path` return unchanged (B99-I2 freeze) |
| 9 | Coverage claims verified **on disk** | all | ✓ | every byte oracle re-reads from disk with `tests/support/independent_reader.py` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (RED census at HEAD; claim-loop mutant) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: round 1 — 4/4 KILLED; fix round — 5/5 KILLED + 1 superseded (mut-155.3, retired by LED .7); none surviving, restores hash-verified; **fix round 2 — 6/6 KILLED (S-F1, S-F6, 155.2 re-run, F3+S-F2+S-F3 re-run, F6a, S-F5), restores hash-verified against `mut-fix2-pre-snapshot.txt`** |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first; fix round: the pilot, the census and the TC runners re-shown RED at base/mutants |
| 13 | **Correction population** declared | all | ✓ | §4: 14 placement paths enumerated; 14th converted; CRC site declared to Inc 5 |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 4 artifact families asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` |
| 16 | **Evidence files** declared | all | ✓ | §4: 29 round-1 + 18 fix-round + 14 fix-round-2 artifacts, each with the stored-byte SHA-256 digest (the `green-final.txt` digest corrected per F6e) |
