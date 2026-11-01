# Batch-100 — batch-end fix round 1: the Linux-runner failures

- **Branch / worktree:** `b100-fix1` from `main` 760f885, `C:/Users/jjgh8/Github/s19_app-b100-fix1`. Nothing committed.
- **Scope:** rows CI9b-3, CI9b-4, CI11-1, CI11-2, CI11-3, CI11-4 of the CI fix list (CI runs 41284211218 and 41290452101).
- **Host:** Windows only. No Linux host, no WSL. Posix behaviour comes from reading the code, from pure-function probes with `posixpath` and drive-rooted texts, and from the posix test arm forced on Windows where that works. Where only the Linux CI can show the posix arm, the row says so.
- **Evidence folder:** `evidence/fix-1/`.

## Summary

| Row | Cause | Requirement | Change | Linux-only? |
|---|---|---|---|---|
| CI9b-3 | test | LLR-173.4j (with LLR-172.2e) | posix recents are drive-rooted texts | yes |
| CI9b-4 | test | LLR-173.5a | trailing-dot arm Windows-only (ruling) | yes |
| CI11-1 | **product** | LLR-171.1m | `app.py:12116-12125` guard on the row rebind | **no — RED on Windows too** |
| CI11-2 | test (wait race) | LLR-175.1 | already fixed at 001bb84; slow-debounce arm added | no — a timing race on any host |
| CI11-3 | test | ruling Q10 / MUT11-M-96 (fold follows the host) | expectation by `os.path.normcase` | yes |
| CI11-4 | test (not re-pinned after Inc 11) | LLR-167.6 (refused → 0 files), LLR-175.5 | re-pinned to the session refusal | **no — RED on Windows too** |

Two rows do not match the brief's premise ("pass on Windows"). CI11-1 and CI11-4 fail on Windows at 760f885 and at 4dfb5a1 (12a). Increment runs skip the touched modules under the b100 override, so these tests were never run on Windows after Inc 11.

## CI9b-3 — `test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load`

- **Cause: test.** LLR-172.2e: "If the path of a store entry is not a drive letter followed by a root, then the system shall drop that entry". `_recent_entry_ok` (`workspace.py`) enforces this with the same regex on every host. The test seeded two `/tmp/...` paths and `Q:\nowhere\fw.s19`. On posix the store drops the two `/tmp` paths, so `Recent` lists 1 row (`fw.s19`), as the CI output shows. The product is correct and host-neutral.
- **Requirement:** LLR-173.4j. Its subject is 0 filesystem calls on a recent before load. The present / missing / unassigned-drive mix is how the threshold builds it.
- **Change:** `tests/test_b100_load_dialog.py:2392`. On Windows the recents are unchanged. On posix the 3 recents are `C:\src\here.s19`, `C:\missing\gone.s19` and `Q:\nowhere\fw.s19`. These are drive-rooted texts that name no file on posix, and the counting spy still catches any call that names them. The present-file arm needs a drive-rooted file, so it runs on Windows only. The docstring says why.
- **Arm:** the Windows arm is unchanged. The posix arm now has 3 rows to highlight.
- **Evidence:**
  - `posix-probes.txt`: the `/tmp` entries give `kept=False`; `Q:\nowhere\fw.s19`, `C:\src\here.s19` and `C:\missing\gone.s19` give `kept=True`.
  - `ci9b-3-posix-arm-driven-on-windows.txt` (`executed`): the posix arm with the module's `WIN` forced to False → `1 passed`.
  - `green-load-dialog-tc43-tc63.txt` (`executed`): 47 passed.
  - The real posix run is `not-run` until the Linux CI runs it.

## CI9b-4 — `test_tc_b100_63_typed_unsupported_file_is_explained[trailing dot]`

- **Cause: test** (ruling already made). Windows strips a trailing dot from a file name, so `fw.s19.` opens `fw.s19` and the product says `not a supported file`. On posix `fw.s19.` is a separate name that does not exist, so `not found — check the path` is the correct answer there.
- **Requirement:** LLR-173.5a.
- **Change:** `tests/test_b100_load_dialog.py:2569`. A new `TRAILING_DOT_ARM = skipif(not WIN, reason=...)` marks only that arm. The reason names the Windows trailing-dot stripping.
- **Arm:** the Windows arm is unchanged, and the other 2 arms still run on every host.
- **Evidence:** `green-load-dialog-tc43-tc63.txt` (`executed`, Windows; the arm ran there). On Linux the arm is `n/a — Windows file-name semantics`.

## CI11-1 — `test_e4_llr_171_1m_rebind_only_to_a_plan_entry[dot-dot]`

- **Cause: product, on both hosts.** The save-as tail (`_save_project_files`, `app.py`) has a document-row branch, added in Inc 11 (53d08d5, Q10 (d)). It rebinds the Patch Editor document to the row's landing whenever `normcase(abspath(row.source)) == normcase(abspath(document))`. `abspath` collapses `..`, so the match also fires in 2 cases:
  - a document spelled `P/../elsewhere/x.json`;
  - a document outside P, which gets an `outside` document row that copies it into `Q/patches/`.

  In both cases `document_relative` is replaced by `patches/x.json`, which then passes the `..` / plan-entry check. Instrumented run on Windows: `document_relative='../elsewhere/x.json'`, `row_relative='patches/x.json'`, so the document was rebound to `Q/patches/x.json`.
- **Requirement:** LLR-171.1m: "never to a path whose part relative to P holds `..` … a document from outside P (the common folder) → its binding unchanged".
- **Change:** `s19_app/tui/app.py:12116-12125`. The row branch now also requires `document_relative is not None and ".." not in PurePosixPath(document_relative).parts`. A document inside P still follows its row (Q10 (d)). `document_relative` is computed lexically (`Path.absolute().relative_to`) on both hosts, so the fix is host-neutral (`posix-probes.txt`, CI11-1 section).
- **Test:** `tests/test_b100_project_homes.py:2080`. A new arm `outside P`: a document in the work area's common `patches/x.json` keeps its binding. The docstring records the cause.
- **Evidence:**
  - `ci11-1-red-base.txt` (`executed`, base code with the new test): `[dot-dot]` and `[outside P]` FAILED, `[skipped junction]` passed.
  - `ci11-1-green.txt` (`executed`): 3 passed.
  - Neighbours, `green-project-homes-171-1m-tc31.txt` (`executed`): 38 passed. The 2 failures there are `test_tc_b100_31_depth_ceiling[32]` and `[33]`, which fail in fixture setup with `WinError 206` because the scratchpad basetemp is long (the path reaches 248 characters). Re-run alone with a shorter basetemp under the scratchpad → 2 passed (`rerun-depth-ceiling-short-basetemp.txt`).
  - `green-document-tc29-tc30.txt` (`executed`): 70 passed.
  - The same test was also RED on Windows at 4dfb5a1 (`executed` in a temporary detached worktree, since removed; output `1 failed, 1 passed`, transcript not kept).

## CI11-2 — `test_tc_b100_47_target_line_merge_and_existing_folder_kinds`

- **Cause: test (wait race), not posix semantics.** The first read guessed a case or prefix match. In fact, after `ef` the kind text is already painted, so a wait on the kind alone returns before the 150 ms debounce repaints for `nt`. Inc 12b already fixed the wait (001bb84: wait for `f"{name} — new project in an existing folder"`). The 12a CI ran the old wait.
- **Requirement:** LLR-175.1.
- **Change:** `tests/test_b100_save_dialog.py:540`. A new parameter `debounce` (`shipped`, `slow 0.6 s`) monkeypatches `screens.SAVE_RECOMPUTE_S` to 0.6, so the race is reproduced on any host.
- **Evidence:**
  - `ci11-2-red-old-wait-slow-debounce.txt` (`executed`, the old kind-only wait restored for the probe): both arms FAILED on Windows with the exact CI message `'nt': 'ef — new project in an existing folder'`.
  - `green-save-dialog-tc47-tc65.txt` (`executed`, the named-folder wait): both arms passed.

## CI11-3 — `test_tc_b100_65_document_free_name_walk_folds_case`

- **Cause: test** (ruling already made: the fold follows the host file system, `normcase`). The planner folds with `os.path.normcase` (`project_gather_service.py:1707-1712`), and the commit claims the first name that `os.lstat` does not find (`workspace.py` `place_into_workarea`). Both follow the host, so on posix the plan, the painted row and the written file all agree on `patches/changes.json`.
- **Requirement:** ruling Q10 / MUT11-M-96 (TC-B100-65).
- **Change:** `tests/test_b100_save_dialog.py:4044`. `folds = normcase("Changes.json") == normcase("changes.json")`.
  - Windows arm (unchanged): `changes_1.json`.
  - Posix arm: row `document patches/changes.json — new`, plan `("changes.json", "new")`, tree `{"Changes.json", "changes.json"}`.
- **Evidence:**
  - `posix-probes.txt`: the walk gives `changes_1.json` with `ntpath`, `changes.json` with `posixpath`.
  - The posix row text is the one the Linux runner painted (CI log 41290452101).
  - `green-save-dialog-tc47-tc65.txt` (`executed`, Windows arm).
  - The posix arm cannot run on Windows, because NTFS sees `changes.json` as taken. `not-run` until the Linux CI runs it.

## CI11-4 — `test_tc_b100_59_refused_plan_writes_nothing`

- **Cause: test, not re-pinned after Inc 11; not posix.** Since 53d08d5, `_save_session_inputs` carries the blocked-entry refusal as the session refusal (LLR-175.5). `_prepare_project_save` then returns `_refused(session.refusal)` before any plan (`app.py`, `if session.refusal is not None`). So `plan_project_save` is never called, and `plans[-1]` raises IndexError on every host.
- **Requirement:** LLR-167.6, threshold "the refused scenario → 0 files". LLR-175.5 decides the image once per open.
- **Change:** `tests/test_b100_save_image.py:1404-1424`. The test now asserts:
  - the status line `Project NOT saved: 1 blocked entry (0x8000007C)`;
  - `plans == []`;
  - no project folder is created;
  - the work-area tree is unchanged.
- **Ruling taken here (to confirm):** I re-pinned the test rather than routing the session refusal through `plan_project_save`. Routing it there would undo the Inc 11 ordering, and the requirement's observable threshold (0 files, the refusal named) holds as shipped. Inc 8b's Code-Wire note says "a passed refusal wins over the MAC clash". It now holds because the session refusal comes first.
- **Evidence:**
  - Base RED on Windows at 760f885 and at 4dfb5a1 (`executed`; output `1 failed`, IndexError; transcripts not kept).
  - `ci11-4-negative-control-mutant.txt` (`executed`): with the session early return removed, a plan is computed carrying the refusal and `plans == []` is RED.
  - `green-save-image-tc59-tc17.txt` (`executed`): 38 passed.

## Runs (Windows, s19env, `s19_app.__file__` = this worktree in every transcript)

| Transcript | Selection | Result |
|---|---|---|
| `green-load-dialog-tc43-tc63.txt` | `test_b100_load_dialog.py -k "tc_b100_43 or tc_b100_63"` | 47 passed |
| `ci9b-3-posix-arm-driven-on-windows.txt` | tc_b100_43 no-fs node, `WIN=False` | 1 passed |
| `green-project-homes-171-1m-tc31.txt` | `test_b100_project_homes.py -k "171_1m or tc_b100_31"` | 38 passed, 2 failed (MAX_PATH in setup) |
| `rerun-depth-ceiling-short-basetemp.txt` | `-k depth_ceiling`, shorter basetemp | 2 passed |
| `green-document-tc29-tc30.txt` | `test_b100_document.py -k "tc_b100_29 or tc_b100_30"` | 70 passed |
| `green-save-dialog-tc47-tc65.txt` | `test_b100_save_dialog.py -k "tc_b100_47_target_line or free_name or tc_b100_65_document"` | 9 passed |
| `green-save-image-tc59-tc17.txt` | `test_b100_save_image.py -k "tc_b100_59 or tc_b100_17"` | 38 passed |
| `ci11-1-red-base.txt` | rebind test on base code | 2 failed, 1 passed (RED as owed) |
| `ci11-2-red-old-wait-slow-debounce.txt` | tc_b100_47 with the old wait | 2 failed (RED as owed) |
| `ci11-4-negative-control-mutant.txt` | tc_b100_59 with the session refusal removed | 1 failed (RED as owed) |

The full suite and the Linux CI are `not-run` (operator override: no full suite).

## Pending

- The posix arms of CI9b-3, CI11-3 and the CI11-1 fix are proven on Linux only by the next CI run. Compare its FAILED set with run 41290452101.
- CI11-4 ruling to confirm: test re-pin vs routing the session refusal through the plan.
- Risk noted, not fixed: on a case-insensitive posix volume (macOS APFS), `normcase` is the identity while `lstat` folds. The plan would then say `changes.json` and the save would write `changes_1.json`. That host is not a target today.

## Source files changed (sha256[:16])

| File | Working copy (CRLF) | LF-normalised |
|---|---|---|
| `s19_app/tui/app.py` | `ab9bc201022b3ee8` | `42ce2e89285fae22` |

## Orchestrator rulings (Opus, 2026-11-01)
- CI11-1 product fix accepted (read on the diff): the text-level `..` / outside-P gate keeps LLR-171.1m host-neutral; `abspath` alone collapsed `..`.
- CI11-4: the test re-pin is accepted. The Inc 11 ordering (the session refuses a blocked entry before any plan, LLR-175.5) is the design; routing the refusal through `plan_project_save` would undo it.
- CI11-2: accepted as a wait race already fixed at 12b; the debounce parametrization stays as the regression arm.
- CI9b-3, CI9b-4, CI11-3: accepted as host-following test arms (CI9b-4 and CI11-3 per the earlier rulings).
- macOS case-insensitive volume risk (normcase vs lstat): BACKLOG-CODE, not a target host.
- Posix arms are confirmed only by the Linux CI after the merge.
