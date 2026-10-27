# Security check: batch-100 Inc 2 (Save project name guards)

| Field | Value |
|---|---|
| **Reviewer** | `security-reviewer`, independent of the author |
| **Subject** | Uncommitted Inc 2 in the worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2`, detached at main `2edfee2`. The changes are in `s19_app/tui/app.py`, `s19_app/tui/workspace.py` and the new `tests/test_b100_save_guards.py`; the packet is `increment-002.md`. It covers LLR-164.1 to LLR-164.4 and closes S-04, S-05, R2-04 and R2-05 in code. |
| **Execution** | One probe ran against the worktree, which was put first on `sys.path` (`python -I -B`). It printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc2\s19_app\__init__.py` on Python 3.12.7. It loads `firmware.s19` in a Textual `run_test`, then calls the real `_handle_save_dialog` with each name and records the new folders and the status line. Script and output: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\sec_inc2_probe.py` / `.out`. The probe made one scratch folder, `scratchpad\inc2work`; its junctions were removed with `rmdir` and the ACL deny was lifted. The app's open log file stopped the probe's own removal, so I removed the folder by its literal path afterwards, and none remains. I did not edit the worktree. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH). One MAJOR, SEC2-1, is a crash path that Inc 2 introduces in its own handler. It should land in the same corrective pass. This verdict authorises nothing beyond the increment gate and is not the operator's authorization. |

## What the probe showed (each point executed)

- **Device names.** Each of these was refused with `is a device name — choose another name` and left 0 new folders: `CON`, `NUL`, `AUX`, `COM1`, `LPT9`, `COM¹`, `con.txt` and `nul.json` (raw), `C O N` (sanitised to `CON`), and `x\CON` (as a path component).
- **Reserved homes, compared case-folded.** `Splits`, `REPORTS` and `crc` were refused with `is a reserved name`, and 0 folders were created.
- **Name length.** 64 characters saved (`Project saved + manifest verified`). 65 characters were refused with `name too long (at most 64 characters)`.
- **Full-path limit.** With a work-area path of 150 characters, a 55-character name (total 259) saved, and a 56-character name (total 260) was refused with `path too long`.
- **Disguised clash.** Project `ab` existed and was not open. `a b`, `AB` and `Ab` were each refused, naming both names, and `ab` kept the same digest. Typing `ab` exactly merged into the project, as the contract says.
- **Link or junction at the target name.** `evil` was a junction into another work area. `evil`, `EVIL` and `e v i l` (which sanitises to `evil`), and a dangling junction `dang`, were each refused with `is a link or junction`, before `resolve()` and before `mkdir`. The other work area was unchanged.
- **`OSError` after the folder is created.** I forced the error at four stages: `validate_project_files`, `copy_into_workarea`, `gather_project_artifacts` and the manifest write. Each gave `could not save … check the folder`, with no exception raised and no folder left.
- **No regression from Inc 1.** The `app.py` diff adds no `.resolve()`. The three Save placement calls pass `workarea_root=self.workarea`, and so does `gather_project_artifacts`. `project_dir` is `parent / cleaned` with no resolution, and `current_project_dir = project_dir` is stored as built.

## Findings

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC2-1 | **MAJOR** | `app.py` `_handle_save_dialog`, the new disguised-clash scan (`for item in sorted(self.workarea.iterdir())` … `any(… for child in item.iterdir())`), which runs **before** the `try` block | The clash scan lists every folder in the work area, and lists inside each one. An `OSError` from any folder escapes the handler. One unreadable folder anywhere in the work area is enough: for example a folder created by another account, an elevated process, or an antivirus-locked folder. The exception comes from a dialog callback, so Textual ends the app, and **every** Save project fails while that folder exists, whatever name is typed. Inc 2 introduces this path: before this increment, the handler touched only its own target. S-05's intent is that the app keeps running when a save fails. | `executed` (P7). `icacls <workarea>\locked /deny <user>:(RD)`, then saving the fresh name `fresh1`, gave `RAISED PermissionError: [WinError 5] Access is denied: …\workarea\locked`. The exception left `_handle_save_dialog`; in the real app it would leave a dialog callback. The ACL was lifted afterwards. | Wrap the scan in `try/except OSError`. A folder that cannot be read is either skipped (not counted as a project, matching `list_projects`) or the save is refused with the `could not save` tokens; it is never raised. Add a TC arm in `test_b100_save_guards.py`: a deny-read folder in the work area, and saving a fresh name gives 0 raises, with the app still running and the save either done or refused with tokens. |
| SEC2-2 | MINOR | `workspace.py` `is_windows_device_name` | The predicate splits on the **last** dot (`rpartition(".")`) and does not ignore trailing spaces. Windows treats the part before the **first** dot, with trailing spaces ignored, as the device name. So `nul.tar.gz` and `CON .txt` read as not device names. This has no effect in Inc 2: the folder name is always the sanitised name, which has no dots or spaces, and those inputs sanitise to safe names (`nultargz`, `CONtxt`). It matters once the same predicate checks **path components**, where dots and spaces survive: manifest keys (LLR-169.8, Inc 7) and recent paths (LLR-172.2, Inc 9a). It also refuses `COM⁴`, which is not a device name; that is harmless. | `executed` (P1): `'nul.tar.gz' raw=False`, `'CON .txt' raw=False`, `'COM\u2074' raw=True`. | Take the stem up to the **first** dot and strip trailing spaces before comparing. Limit the digit to `0`–`9` plus `¹²³`. Add the arms `nul.tar.gz`, `CON .txt` and `CON.` (refused) and `COM⁴` (accepted) before Inc 7 reuses the predicate. |
| SEC2-3 | MINOR (declared in the packet) | `_handle_save_dialog`, exact-name merge into a project that is not open | When a merge fails partway (`created_project_dir` is False), the files it already placed stay in the target project. The packet assigns the merge carry and the mid-merge `OSError` arm to Inc 8a (R2-07, LLR-164.2 (b)). Nothing is overwritten, because placement claims files with `O_EXCL`. | `not-run` for the failure. The merge itself ran (P4: `ab` was saved and its digest changed). | Inc 8a, as declared. Keep the arm in Inc 8a's test plan. |

## Evidence checklist

- [x] Every probe the brief asked for ran against the worktree, with `s19_app.__file__` printed: device names (raw, sanitised, component), reserved homes, the 64/65 cap, the 259/260 full-path limit, the disguised clash (including case-only), the junction target, `OSError` after creation, and the Inc 1 regression.
- [x] Each finding has what, where, why, a recommendation and a severity: 0 HIGH, 1 MAJOR, 2 MINOR.
- [x] No secret values or real names appear in the output. The probe reads the account name from `USERNAME` only to apply and lift the ACL, and the account name is not printed.
- [x] The worktree was not edited. The scratch folder, its junctions and the ACL deny were all removed.
- [ ] Not tested: Python 3.11, and Windows 10 device semantics.

---

## Round 2: re-check after Kimi's fix pass 1 (LED .52)

| Field | Value |
|---|---|
| **Subject** | The same worktree, still uncommitted: fix pass 1 per `HANDOFF.md` §"Fix pass 1". It adds the `_abort_save` rollback, the first-dot device predicate and the clash scan that skips unreadable folders. |
| **Execution** | One probe ran against the worktree (`python -I -B`, worktree first on `sys.path`). It printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc2\s19_app\__init__.py` on Python 3.12.7 and drove the real `_handle_save_dialog` inside Textual `run_test`. Script and output: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\sec_inc2_r2_probe.py` / `.out`. The probe ended with `ACL lifted: 2 \| junctions removed: 1`. The scratch folder `scratchpad\inc2r2work` was held back only by the app's open log file. I confirmed it held no junction or deny ACL, then removed it by its literal path. I did not edit the worktree. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH, 0 MAJOR). SEC2-1 and SEC2-2 are closed. SEC2-3 is closed for the top-level placements and app state, but not for files the gather places (SEC2-4, MINOR). This verdict authorises nothing beyond the increment gate and is not the operator's authorization. |

### Closure

| id | state | executed evidence |
|---|---|---|
| SEC2-1 (MAJOR) | **closed** | I denied read access to the folder `locked`. Saving `fresh1` then **succeeded**, with no exception. I also denied read access to `Clashme`, a folder holding project data. Typing `clashme` or `Clashme` gave `could not save — [WinError 5] Access is denied` from inside the save body. Nothing was raised and no folder was created. The scan now compares the name first and lists inside only the folder that matches. |
| SEC2-2 (MINOR) | **closed** | These are now refused as device names: `nul.tar.gz`, `CON .txt`, `com1.a.b`, `CON.`, `CON `, `LPT¹.s19`, `conin$.x`, `Aux.` and `prn.txt.bak`. These are no longer refused, so there is no false refusal: `console`, `contents.s19`, `auxdata`, `nullable`, `com10`, `lpt` and `COM⁴`. |
| SEC2-3 / LED .52 (b) (MINOR) | **partly closed** | The test was a merge into the existing project `ab`, which was not open and already held `firmware.mac` and `patches/keep.json`, with a forced failure. When the manifest write raised, the image copy placed by this save was removed, and every piece of app state was restored: `current_project`, `current_project_dir`, `variant_id` and the variant set (`restored: True`). When the gather raised after the image copy, the image was again removed. A pre-existing identical `patches/boost.json` **survived** a rollback, so there was no data loss. But the file the **gather** placed, `patches/boost.json` from the common library, was **left behind** after the failed manifest write (`ab after: [… 'patches\\boost.json' …] \| unchanged: False`). See SEC2-4. |

### New findings, round 2

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC2-4 | MINOR | `app.py` `_handle_save_dialog`: `placed_paths` collects only the image, MAC and A2L copies; the `_abort_save` skip test is `placed.name in preexisting_names`, a top-level name set | (a) Files placed by `gather_project_artifacts` in `patches/`, `checks/` and `templates/` are not tracked. A save that fails after the gather leaves them in a folder that already existed, against LED .52 (b). A later Load would see them as unrecorded files. Nothing is overwritten (`O_EXCL`), and everything stays inside the work area. (b) **A hazard for the fix:** the skip test compares bare names against the **top-level** listing. If gather placements were simply appended to `placed_paths`, a pre-existing identical file in a sub-folder would be reused by the gather (same path), would not appear in the top-level name set, and would be **deleted** on rollback. That would destroy a pre-existing user file. | `executed`: `[merge 'ab', batch=boost.json, manifest raises]` gave `ab after: ['firmware.mac', 'patches\\boost.json', 'patches\\keep.json'] \| unchanged: False`. Part (b) is reasoned from the code; I did not run it as a mutation. | Track what the gather writes through `GatherOutcome` (written versus reused) and add only the **written** paths to the rollback list. Take the pre-save snapshot as a set of full relative paths (including sub-folders), not top-level names, and skip any path in it. TC arms: (1) a merge with a failure after the gather leaves the target's digest unchanged; (2) a pre-existing identical `patches/x.json` survives the rollback. |

### Regression set (re-run)

- **Device and reserved names:** `CON`, `NUL`, `COM¹`, `con.txt`, `nul.json`, `C O N`, `x\CON`, `Splits`, `REPORTS` and `crc` were all refused, with 0 folders created.
- **Name length:** 64 characters saved; 65 were refused.
- **Clash:** `a b` and `AB` were refused against `ab`.
- **Junctions:** `evil` and `EVIL` were refused as a link or junction, and the other work area was unchanged.
- **Forced `OSError`:** at `validate_project_files` and at `copy_into_workarea`, each gave `could not save` and left no folder.
- **Inc 1:** the stored `current_project_dir` is the built path. I did not re-test the 259/260 path limit: it ran in round 1, and fix pass 1 does not touch that check.

---

## Round 3: fix pass 3, the rollback walker (bounded, operator decision at the iteration cap)

| Field | Value |
|---|---|
| **Subject** | `walk_tree_no_links` in `workspace.py`, the one tree walk that never follows a link. The pre-save snapshot (`_project_tree_snapshot`) and the rollback (`_abort_save`) both use it. It replaces the `rglob` walk that code-reviewer R3-1 (HIGH) showed descending into junctions on Python 3.11. The worktree is uncommitted. |
| **Execution** | The probe ran on **Python 3.11.15** (`C:\Users\jjgh8\anaconda3\envs\s19env\python.exe`, `os.path.isjunction present: False`, Textual 8.2.8) against the worktree, which was first on `sys.path`. It printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc2\s19_app\__init__.py`. It drives the real `_handle_save_dialog` inside `run_test`. The forced failure sits at the manifest write, which comes after the snapshot and the image placement. Just before that failure, a hook plants links and files to simulate changes made during the save. Script and output: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\sec_inc2_r3_probe.py` / `.out`. At the end the probe removed its junctions (`rmdir`) and symlinks and lifted the ACL deny. The scratch folder `scratchpad\inc2r3work` was held back only by the app's open log file. I confirmed it held no link, then removed it by its literal path. I did not edit the worktree. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH). R3-1's class is closed on 3.11: in every probe the rollback neither entered a reparse point nor touched its target. **One MAJOR (SEC2-5)** remains in the rollback's design. It is not a reparse-point problem: the rollback can delete pre-existing user files **inside** the project. It goes to the operator for a decision under the bounded round. This verdict authorises nothing beyond the increment gate and is not the operator's authorization. |

### The five probes asked for (Python 3.11, executed)

| case | result |
|---|---|
| **Walker unit test** (loop, outbound junction, dangling junction, file symlink, directory symlink) | The walk gave `['a', 'a/b', 'a/b/f.txt', 'dang', 'dlink', 'ext', 'flink.s19', 'loop']`. Each link is yielded as a leaf and never entered (`entered a link target: False`). The walk ends on the loop. |
| **1. Junction out of the project; a file appears outside during the save** | The pre-existing `ab/ext` junction to `outside` was **kept**, still as a junction. The junction `newj`, also to `outside` and created during the save, was **removed as a link only**. `outside` kept `victim.txt` and `appeared.txt`. |
| **2. Symlink to a file outside** | The pre-existing `pre_link.s19` was kept. The file symlink `new_link.s19` and the directory symlink `new_dlink`, both created during the save, were removed. The target `victim_file.s19` was intact. |
| **3. Junction loop** | The pre-existing `ab/loop → ab` was kept. The loop `patches/loop2 → ab`, created during the save, was removed. The rollback finished, and `patches` still held `keep.json`. |
| **4. Dangling junction** | The pre-existing `dang_pre` was kept. `dang_new`, created during the save, was removed. |
| **5. Deep tree** | A pre-existing 20-level tree kept its file. A 20-level tree created during the save was removed bottom-up. A 70-level tree was cut off at MAX_PATH (264 characters, `LongPathsEnabled = 0`). The walker listed the 61 entries that exist and skips anything it cannot list, the same way in the snapshot and in the rollback. |
| **Created-folder rollback** (the `rmtree` path) | A junction to `outside`, planted inside the new folder `fresh` during the save, did not stop `fresh` being removed, and `outside` was intact. Python 3.11's `rmtree` unlinks a directory junction without entering it. |

**Can the rollback delete *through* a reparse point, or delete its target?** No. A new reparse point is removed with `rmdir()` (directory or junction, through `is_dir()`) or with `unlink()` (a file symlink, or a dangling junction). On Windows both remove only the link. Reparse points are never pushed onto the walk stack, so nothing under a link target is ever a removal candidate. One edge was not probed: a pre-existing real directory swapped for a junction during the save. Its path is in the snapshot, so it is skipped and not removed; only new entries under it could be candidates, and the walker does not enter it.

### Findings, round 3

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC2-5 | **MAJOR** | `workspace.walk_tree_no_links` (`except OSError: continue` on `os.scandir`), used by `_project_tree_snapshot` and by the rollback in `_abort_save` | **If the snapshot cannot list a folder, the rollback can delete the pre-existing files in it.** The snapshot silently skips any folder it cannot list. The rollback then treats *everything* it can list but the snapshot did not record as written by this save, and deletes it. If a folder in an existing project could not be listed when the snapshot ran but can be listed by rollback time, every pre-existing file in it is deleted. Examples: an ACL change, a transient antivirus or sync lock, a cloud-placeholder folder. Those are the user's own patches, checks and reports, deleted with no confirmation and no trace. | `executed` (R7): `deny on ab/patches: True`, the deny was lifted in the hook before the failure, and the result was `ab/patches/keep.json after rollback: False`. | Delete only what **this save wrote**: the paths the placements and the gather actually **wrote** (`PlacementResult.reused` false, `GatherOutcome` written), each skipped if it appears in a full-path snapshot. Never treat the difference between the snapshot and the current tree as "written by this save". If the diff design stays, the snapshot must fail closed: `walk_tree_no_links` reports listing errors, and the save refuses with the `could not save` tokens **before** placing anything when the snapshot is incomplete. TC arm: R7 (a read-denied `patches/` at snapshot time, then lifted) leaves `keep.json` present. |
| SEC2-6 | MINOR | the same diff-based rollback | A file that another writer creates inside the project during the save is deleted by the rollback. Examples: a second app instance, the user copying a file in, a flow run. The window is short, and the file is inside the work area. | `executed` (R8): `user_added.json after rollback: False`. | The same change closes it: delete only the paths this save wrote. |
| SEC2-4 (round 2) | **closed** | — | The rollback now covers gather placements and keeps pre-existing identical files by full relative path. R1–R5 show pre-existing entries in sub-folders kept and new ones removed. The full-path snapshot is how it is done; SEC2-5 is the caveat on how that snapshot is taken. | R5 (pre-existing deep file kept, new deep tree removed). | — |

### Evidence checklist (round 3)

- [x] Executed on Python 3.11.15, where `is_junction` is missing, against the worktree, with `s19_app.__file__` printed.
- [x] All five requested cases, plus the created-folder `rmtree` path, the read-denied snapshot (R7) and a concurrent writer (R8).
- [x] No file outside the project was deleted in any probe (`outside final: ['appeared.txt', 'appeared2.txt', 'victim.txt', 'victim_file.s19']`).
- [x] Each finding has what, where, why, a recommendation and a severity: 0 HIGH, 1 MAJOR, 1 MINOR.
- [x] The worktree was not edited. Junctions, symlinks and the ACL deny were removed or lifted, and the scratch folder was removed.

---

## Round 4: the exact-list rollback (LED .53)

| Field | Value |
|---|---|
| **Subject** | The redesign in the worktree, uncommitted, per `HANDOFF.md` §"Redesign (LED .53)". `_abort_save` restores the app state. It then unlinks exactly `placed_files`: the image, MAC and A2L placements with `reused == False`, plus `GatherOutcome.written`. Finally it removes `created_dirs` (the gather's `created_homes`, plus the project folder if this save created it), deepest first and only while empty. There is no folder walk and no snapshot. |
| **Execution** | The probe ran on **Python 3.11.15** (`C:\Users\jjgh8\anaconda3\envs\s19env\python.exe`) against the worktree, which was first on `sys.path`. It printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc2\s19_app\__init__.py`. It drives the real `_handle_save_dialog` in `run_test`, forcing a failure at the manifest write or at the verify. The batch named `boost.json` from the common `workarea/patches/` library so that the gather runs. Script and output: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\sec_inc2_r4_probe.py` / `.out`. Afterwards the ACL deny was lifted and the junctions removed. The scratch folder `scratchpad\inc2r4work` was held back only by the app's open log file. I confirmed it held no link, then removed it by its literal path. I did not edit the worktree. |
| **VERDICT** | **`BLOCK — BLOCK-UNTIL: SEC2-7`** (1 HIGH). The exact-list rollback still deletes a **pre-existing** user file when the gather's reuse check and the placement's reuse check disagree about letter case. The verdict authorises nothing, and it is not the operator's authorization. |

### Requested checks (Python 3.11, executed)

| check | result |
|---|---|
| **R7: pre-existing file in a folder unreadable at save start** | `keep.json survives: True`. SEC2-5 is **closed**. |
| **R8: a file another writer adds during the save** | `user_added.json survives: True`. SEC2-6 is **closed**. |
| **Junctions: out of the project, a loop, and a new junction created during the save** | `outside: ['victim.txt']`, untouched. `ext`, `loop` and `newj` were all left in place: under the exact-list rule nothing that this save did not create is removed. No link was entered and no target was touched. |
| **Q3: the gather reused an identical file of the same name** | `ab/patches/boost.json survives: True`. |
| **Q4: a "created" entry this save did not create** | **Found** (SEC2-7). Also found: two gaps around `project.json` (SEC2-8, SEC2-9). |

**Race between check and claim (Q4).** The top-level placements report `reused` from `place_into_workarea` itself. A path with `reused == False` was claimed with `O_CREAT|O_EXCL` (after an `lstat`), so this call created it, even when another writer races the claim (the claim then takes the next `_<N>`). One residual window remains: another writer could replace *our* placed file between the placement and the rollback, and the unlink would then remove their bytes. That needs a second writer aiming at a name we just claimed, so I record it as a note, not a finding.

### Findings, round 4

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC2-7 | **HIGH** | `services/project_gather_service.py` `_gather_copy` (`copied` is set to True whenever it calls `copy_into_workarea`) and `_same_artifact_name` (case-sensitive `stem` and `suffix` compare); `workspace.find_identical` (case-insensitive on Windows) | **A pre-existing user file is deleted by a failed save.** `_gather_copy` first runs its own reuse check, which compares names case-sensitively, then calls `copy_into_workarea`. `copy_into_workarea` reuses a byte-identical file under a **case-variant** name (`BOOST.json`, `boost.JSON`), because `find_identical` compares case-insensitively on Windows. It returns that existing path. But `copy_into_workarea` hides the `reused` flag, so `_gather_copy` reports `copied=True`, the existing file goes into `GatherOutcome.written`, and `_abort_save` unlinks it. The trigger is a fixed project state (a case-variant identical file in `patches/`, `checks/` or `templates/`) plus **any** failure after the gather, such as a manifest write error, a full disk or a lock. The deletion is silent and cannot be undone: exactly the class LED .53 exists to remove. | `executed` (Q4a): pre-existing `ab/patches/BOOST.json`, batch `boost.json`, manifest write raises, result `ab/patches after: ['keep.json', 'user_added.json'] \| pre-existing BOOST.json survives: False`. (Q4b) `boost.JSON`: `survives: False`. | Make the placement the only judge. `_gather_copy` calls `place_into_workarea(source, home, workarea_root=…)` and records `written` only when `PlacementResult.reused` is False. Its own name-based pre-check is removed or made advisory, never the decision. Keep the LLR-155.3 census happy by listing the call. TC arms: a pre-existing case-variant identical file (`BOOST.json`, and `boost.JSON`) survives a failure after the gather. A census arm asserts that no `GatherOutcome.written` path came from a `reused == True` placement. |
| SEC2-8 | **MAJOR** | `app.py` `_handle_save_dialog`; `_write_and_verify_manifest` writes `project.json` before the verify, and `project.json` is in neither `placed_files` nor `created_dirs` | **The project folder this save created is left behind when the failure comes after the manifest was written.** If the verify raises (an `OSError` while re-reading), the rollback unlinks the image and then calls `rmdir` on the project folder. That fails, because `project.json` is still inside, and the error is swallowed. A half project, holding only a manifest, stays in the work area and is listed by Load. That breaks HLR-164's "every refused or failed save shall leave no folder that the save created" (S-05). | `executed` (Q4c): `freshv left on disk: True \| contents: ['project.json']`. | When this save created `project.json` (it did not exist before the write), add it to `placed_files` as soon as the write returns. TC arm: the verify raises, and no folder is left. |
| SEC2-9 | **MAJOR** | the same path, in a merge into an existing project | **A merge that fails after the manifest write leaves the existing project's `project.json` replaced.** The rollback does not restore the previous manifest. The bytes from before the save are lost, and with them any keys the failed save's manifest did not carry. The full carry of those keys lands only in Inc 8a. | `executed` (Q4d): `ab/project.json restored to its pre-save content: False`. | Before the write, keep the previous `project.json` (bytes in memory, or a private staged copy). If the save then fails, `os.replace` it back. If there was no previous manifest, treat the file as SEC2-8 does. TC arm: a merge whose verify raises leaves `project.json` byte-equal to its pre-save content. |

### Closure summary

- **SEC2-5 (MAJOR): closed** (R7).
- **SEC2-6 (MINOR): closed** (R8).
- **Junction safety: holds.** Nothing outside was touched, and no link was entered or removed.
- **New this round:** **SEC2-7 (HIGH)**, which blocks; SEC2-8 and SEC2-9 (MAJOR), which belong in the same corrective pass.

### Evidence checklist (round 4)

- [x] Executed on Python 3.11.15 against the worktree, with `s19_app.__file__` printed.
- [x] R7, R8, the junction cases (out of the project, a loop, a new junction during the save), same-name gather reuse, and the Q4 search, including the check-and-claim race, the case-variant reuse, and the manifest-written failure in a new folder and in a merge.
- [x] `outside final: ['victim.txt']`: no file outside the project was touched.
- [x] Each finding has what, where, why, a recommendation and a severity: 1 HIGH, 2 MAJOR.
- [x] The worktree was not edited. The ACL deny was lifted, the junctions removed, and the scratch folder removed.
