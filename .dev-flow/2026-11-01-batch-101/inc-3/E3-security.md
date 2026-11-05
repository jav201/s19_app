# Inc 3 — E3 security review (code-free design review)

Batch 2026-11-01-batch-101, increment 3. Reviewer: security-reviewer. Tree: `b101-inc3` at `99696fa` (base `e266395`, product code unchanged). Read: `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings of 2026-11-02), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc3.md`; code `project_gather_service.py` (`gather_project_artifacts`, `_schedule`, `_gather_copy`, `_check_home_contained`), `app.py` (`_save_project_files` 11826-11870 and 11980-12010, `_sync_loaded_file_to_project`, `_sync_loaded_a2l_to_project`, `_manifest_carry`), `workspace.py` (`place_into_workarea`, `validate_project_files`), `manifest_writer.py` (`_reject_unsafe_entry`, `serialize_manifest`), `variant_execution_service.py` (`_entry_text`); canon rows R-PROJ-CONTAIN.1, R-PROJ-GATHER.1-.11, R-PROJ-002.12/.13, R-PROJ-ASSIGN-001.7, R-MAN-VERIFY-001.4, the LLR-171 absorption rows (incl. the S15 D15-18 note).

Probes (Python 3.12.7, Windows 11, run against the base tree from a scratch folder; nothing written in the worktree): `probe_loop.py`, `probe_records.py`, `probe_symsrc.py` under the session scratchpad `e3sec/`.

## Verdict

**FAIL** — `BLOCK-UNTIL: S-1`. S-1 is a record fix (threshold, case, graph example, test name); no code change is owed. Every other finding is non-blocking. On the subject named in the brief (path containment once `resolve()` goes), the design holds: see §Confirmations.

## Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| S-1 | HIGH | R-PROJ-GATHER.13 (threshold), R-PROJ-GATHER.13/1, graph `gather_project_artifacts` example /1 context, slice §2 node `test_r_proj_gather_13_save_goes_on_past_a_link_loop_at_a_composition_name` | The save-level expected result is unreachable without a containment regression. With a junction loop `x.json` at the project top level and `batch=("x.json",)`, the head gather returns (no raise). But `batch` is passed unchanged to the manifest writer (`app.py:11980`), and `_reject_unsafe_entry` refuses the entry. Probe, executed: `refusing to serialize manifest batch entry that is absolute or escapes the project directory: 'x.json'`. The save then ends `Project NOT saved: could not save — project.json was not written. check the folder.` (`app.py:11992-11996`, by code reading) and never reaches `Project saved + manifest verified`. Nothing before the writer raises on the loop: `project_file_records` and `validate_project_files` both return normally (probe executed). An E4 author working to the threshold as written can only turn it green by weakening the writer's link and escape predicate (LLR-001.5, SEC7 walk), which is the batch-100 containment rule. | Restate the R-PROJ-GATHER.13 threshold and case /1. Gather level: returns without raising, and the common `x.json` is scheduled into `patches/`. Save level: the outcome lines hold `Project NOT saved: could not save — project.json was not written. check the folder.`, 0 lines hold `an unexpected error stopped the save`, and after the rollback `patches/x.json` does not exist. The negative control (`resolve()` restored → the unexpected-error line) stays RED, because the line differs. Rename the save-level test to match. Add to the E4 brief: `_reject_unsafe_entry`, `_EntryWalk` and `_entry_text` are outside the slice and must not change. |
| S-2 | MINOR | R-PROJ-002.14; `_sync_loaded_file_to_project`, `_sync_loaded_a2l_to_project` | A race window remains. If the folder vanishes after `validate_project_files` succeeds and before the write, it is still re-created: `place_into_workarea` runs `resolved_destination.mkdir(parents=True, exist_ok=True)` (`workspace.py:1183`), and the project.json write runs `destination.parent.mkdir(parents=True, exist_ok=True)` (`manifest_writer.py:648`). The re-created folder stays inside the work area (the destination guard runs first; R-PROJ-CONTAIN.1 holds), so this is not an escape. The R-PROJ-002.14 tests delete the folder before the trigger, so they pass. | Record the window as an observation in `E1-rulings.md` §5 (accepted residual: inside the work area, needs a concurrent delete). No code change in Inc 3. |
| S-3 | MINOR | R-PROJ-GATHER.13; graph `gather_project_artifacts` | `Path.is_file()` swallows only ENOENT, ENOTDIR, EBADF and ELOOP, and Windows errors 21, 123 and 1921. The junction loop gives 1921 (probe executed: `is_file` False, `os.stat` WinError 1921), so the row's case is covered. Any other `OSError` at a composition name still escapes the gather and stops the save with the unexpected-error line. Examples: EACCES on a parent folder, or a damaged or offline reparse point (WinError 1920, 4392). This contradicts the docstring's `Raises: None` (collect-don't-abort, C-5). The base behaves the same, so it is not a regression. | Either catch `OSError` around the check (treat the name as not home; it falls to the common lookup or to `GATHER-SOURCE-MISSING`), with the orchestrator's approval because it widens the row; or log it as a backlog row. Default: backlog. |
| S-4 | MAJOR (pre-existing, outside the slice, non-blocking) | composition limb → `_schedule` → `_gather_copy` → `place_into_workarea` | For a composition source, `_schedule` hands the placement the **resolved** common candidate (`unresolved=False`). The placement's source-side link refusal therefore never sees the link: a symlink in the common patches library that points outside the work area is followed. Probe, executed on the base tree: `common/boost.json` → `outside/secret.json` gives `gathered {'patches': ['patches/secret.json']}`, 0 issues, and the outside bytes copied into the project under the target's name, not the batch name. No byte is written outside (R-PROJ-CONTAIN.1 holds), but the save reads outside the work area. The active-document limb refuses the same shape (`GATHER-CONTAINMENT`). Inc 3 neither creates nor widens this: any missing name already reaches the fallback, and the loop name now joins them. | Backlog security row, not Inc 3. Decide whether a composition source that is a link is refused like the active document (`GATHER-CONTAINMENT`, not copied). If so, pass the unresolved candidate to the placement. Owner: the gather's next increment. |
| S-5 | MINOR (pre-existing, non-blocking) | composition limb | The limb runs no lexical filter before touching the filesystem. Absolute, drive-relative (`D:x`), UNC and `..` names are probed with `is_file()`, which acts as an existence oracle. A UNC name makes Windows attempt SMB authentication to that host. Removing `resolve()` changes none of this (probe executed: `(project/'../../../outside/secret.json').is_file()` True, the same answer as through `resolve()`; base `resolve()` touched the same paths). The writer refuses such names afterwards. Names reach the gather only from the dialog payload, or from a carried manifest already filtered by the reader (`_manifest_carry` → `read_project_manifest`). | Backlog: run the reader's lexical predicate (`_entry_text`, manifest-keys mode) on each composition name before any filesystem call. This also saves time. Not Inc 3. |

## Confirmations (the subjects named in the brief)

- **Containment once `resolve()` is removed: unchanged.** The check produces one boolean, "already home → skip". The in-project path is never read, copied or written. Every copy goes through `_gather_copy(source, home, workarea_root)`, which runs the destination guard on the unresolved home with the app's own root (B100-I14, SEC-1). R-PROJ-CONTAIN.1 is untouched, and interface I-1 (unchanged signature and outcome) holds for these security cases:
  - `..` and absolute names give the same answer as through `resolve()`. Windows applies `..` lexically in both; POSIX applies it physically in both.
  - A junction at a name that points outside gives `is_file` True → skipped, nothing read (probe executed), and the writer then refuses the entry (probe executed).
- **Link loop: nothing escapes.** The loop name falls to the common lookup by bare name (`Path(name).name`, which stays inside `common_patches_dir`). The only artifact is the common copy into `patches/`, which the S-1 refusal rolls back (`_abort_save` with `written` / `created_homes`). A loop names no file, so it cannot be used to make the save read outside. What gets written for it is S-1, not a leak.
- **TOCTOU between `is_file()` and the copy: not applicable to the checked path.** The checked path is never copied. The common candidate's `is_file()` → copy race is pre-existing and handled by `place_into_workarea` (size check, private staging, S-F6 → `WorkareaPlacementError`).
- **Sync refusal: no new write path.** With `mkdir` removed:
  - A deleted folder raises `FileNotFoundError` at `iterdir` and gets the canon refusal.
  - A file in the folder's place raises `NotADirectoryError`, the same as today.
  - A dangling junction in the folder's place raises `FileNotFoundError` and gets the refusal. On the base it was `FileExistsError` from `mkdir`, also a refusal.
  - A junction to outside in the folder's place: `validate_project_files` lists names through it (pre-existing), then the placement's reparse walk refuses (`Project sync rejected: …`).
  
  No folder is created on the refusal path. The residual race is S-2.
- **D15-18 / LLR-171.4i/.4j:** these are flow and chain-set saves (S15). Inc 3 touches neither; no interaction.
- **Tests:** the junction-loop helper's rule holds (remove with `os.rmdir`, never a recursive delete through a link). E4 must keep it for the new R-PROJ-GATHER.13 nodes. The R-PROJ-002 tests' `shutil.rmtree` targets plain test folders with no links.

## Evidence states

| Item | State |
|---|---|
| S-1 writer refusal of a loop entry | `executed` (probe `probe_loop.py`); save-level line `planned` (code reading, `app.py:11980-12010`); fix `planned` |
| S-1 nothing earlier raises on the loop | `executed` (`probe_records.py`) |
| S-2 re-create race | `executed` by code reading (`workspace.py:1183`, `manifest_writer.py:648`); not run live |
| S-3 `is_file` on the loop → False | `executed` (`probe_loop.py`); other OSError kinds `not-run` (code reading of pathlib) |
| S-4 symlinked common source copied | `executed` (`probe_symsrc.py`, Windows with symlink privilege) |
| S-5 `..` existence probe | `executed` (`probe_loop.py`) |
| Mitigations for S-1 | `planned`: not applied, not verified; re-verify after the record fix |

## Evidence checklist

- [x] Each finding has what, where, why and a fix: table above.
- [x] Each finding has a severity: column 2.
- [x] No secret values in this report: none handled.
- [x] The verdict is explicit: FAIL / `BLOCK-UNTIL: S-1`; no mitigation is applied yet.
- [x] No new tool or integration: n/a, no external tool in this increment.
