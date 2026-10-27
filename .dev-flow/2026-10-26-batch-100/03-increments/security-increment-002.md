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
