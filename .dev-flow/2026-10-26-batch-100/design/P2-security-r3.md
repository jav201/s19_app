# P2 security review, round 3 (bounded verification): batch-100 (Load + projects)

- **Reviewer:** `security-reviewer`. This is a bounded round-3 verification, the operator's decision after the P2 iteration cap. **Scope:** only the closure of my open findings R2-01..R2-09 and the carried S-02, S-08 and S-16. This is not a new full review. Anything new I noticed is a PDR condition and does not block, because none of it is HIGH.
- **Sources:** the contract at `4e9c8f1` (`01-requirements.md`, ledger LED .14 to .23, and the `02-review.md` "Round 2" section) and `docs/ARCHITECTURE.md` B100-I13 to B100-I22.
- **Execution:** the probe ran on the `git archive 1d677ba` snapshot from earlier rounds. `s19_app.__file__` printed `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\snap\s19_app\__init__.py`.
  - Probe script and output: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\p2sec_r3_probe.py` / `.out`.
  - The probe made one scratch folder (`scratchpad\r3work`) and removed it at the end; the output records `scratch folder removed: True`.
  - I also read the code paths: `changes/apply.py:776-781` and `services/manifest_writer.py:13-15`, `:366`, `:431`.

## Closure table

| id | round-2 severity | state | closed by | verification |
|---|---|---|---|---|
| R2-01 (carries S-02) | MAJOR | **closed** | LLR-171.4; LLR-163.1; LLR-164.2 (link or junction target refused before `resolve()`, for new and merge targets); B100-I13, B100-I14; LED .20 | The this-work-area check now lives inside `place_into_workarea`. The emit places through `copy_into_workarea`: I read `changes/apply.py:781`, `target = copy_into_workarea(staged, dest_dir)`, so the emit is covered by construction. The Inc 8b arm covers 7 writers, including Save project new name, merge and emit, the variant append, and the MAC and A2L syncs. The Inc 1 arm covers `place_into_workarea` into two kinds of junction. My round-2 junction probe (R4) showed that the resolve-then-check rule refuses the junction. Residual wording: PDR-C1. |
| R2-02 | MAJOR | **closed** | LLR-163.1 (every guard in `place_into_workarea`; `copy_into_workarea` is `return place_into_workarea(...).path`; an AST check expects 1 claim loop); B100-I13; LED .20 | There are direct-call arms for a destination outside every work area, a destination through a junction, and a source over the cap: 3 refusals, 0 bytes written. The export uses `PlacementResult.reused` (LLR-163.6). |
| R2-03 (carries S-08) | MAJOR | **closed** | LLR-169.4 (1 MiB, plus 1 000 entries in each of `batch`, `assignments`, `declared_regions`, `gathered`, `files`, `derived_from`); LLR-173.4 (a highlight with a 1 MiB manifest answers a key within 200 ms; a main-thread preview read fails the arm); LLR-177.1 (load on a worker); LED .18, LED .20 | The freeze is gone: the load and the preview both read on workers, and the preview is cancelled when the highlight moves. Executed: a 1 MiB manifest holding 75 `assignments` keys × 1 000 entries each gave `read=14.80s`. A per-list cap allows that, and it now costs a slow load behind a spinner rather than a frozen UI. PDR-C2. |
| R2-04 | MINOR | **closed** | LLR-164.1 (`is_windows_device_name` on both the typed and the sanitised name; arms `con.txt` raw, `CONIN$` raw, `C O N` sanitised); LED .20 | The arms now match the rule. Round 2's R1 showed that `C O N` sanitises to `CON`. |
| R2-05 | MINOR | **closed** | LLR-169.8 (every path component, with or without an extension; 14 arms including `patches/NUL.json`, `nul.s19`, `sub./x.s19`, `patches/x.json `); LLR-172.2 (no device-name component; `C:\x\NUL.s19` arm); B100-I21; LED .20, LED .21 | — |
| R2-06 | MINOR | **closed** | LLR-171.1 (one pruned walk gives both the total and the copy; the junction arm adds 0 bytes to the total); LED .20 | — |
| R2-07 | MINOR | **closed** | LLR-164.2 (b) (the merge carries every key it does not own and removes what it placed if it fails; a forced `OSError` mid-merge leaves the file set and `project.json` unchanged); LED .20 | — |
| R2-08 | MINOR | **closed** | LLR-172.2 (drive letter and root required; mapped drives named as a gap guarded by "never touched before Enter"; the `a.s19:ads` and `a.s19.` arms); §6.3; LED .21 | — |
| R2-09 | MINOR | **closed** | LLR-164.4 (the handler and the AST census cover the Save worker body; removal happens in the failing path; 5 forced stages on the worker); LLR-177.2; LED .19 | — |
| S-16 | MINOR | **closed** (operator decision) | LLR-172.1 (`recent_store_path()` = `%APPDATA%\s19_app\recent_sources.json`, disabled when `APPDATA` is unset, 0 store files under the base folder); LLR-172.3 (no copy into any file under the base folder); LED .21 | The store no longer travels with a shared `.s19tool`, which also removes the planting route behind S-07. PDR-C3. |

**Result:** 12 of 12 closed, and 0 open.

## PDR conditions (new observations, non-blocking, none HIGH)

- **PDR-C1, the manifest seam is not "covered by construction".** LLR-171.4 lists the manifest seam among the writers that `place_into_workarea` covers by construction. That is not true. `write_project_manifest` must *replace* `project.json`, so it stages and calls `os.replace` after `_check_destination_contained` (`manifest_writer.py:13-15`, `:366`, `:431`), and that function accepts *any* `.s19tool/workarea`. B100-I14 already lists the manifest seam separately as "also require it", so the architecture is right and only the LLR wording is off. In practice the gap is unreachable. `current_project_dir` can only be set through a load or a save, and LLR-171.4 now refuses a link or junction folder on both. **Condition:** at PDR, `_check_destination_contained` calls `contained_in_workarea(destination, workarea)` with this app's work area, LLR-171.4's "by construction" sentence drops the manifest seam, and the Inc 8b arm adds the seam as an eighth writer (0 bytes written outside `self.workarea`).
- **PDR-C2, the cap on `assignments`.** "1 000 entries in each of … `assignments`" can be read per variant list. Under that reading, 75 keys × 1 000 entries fit inside 1 MiB, and the executed read took 14.80 s. The worker and the preview cancellation keep the UI responsive, so this is a slow load, not a freeze. **Condition:** state that the cap counts the total entries across all `assignments` lists, plus the number of keys, and add the arm: 75 × 1 000 gives 1 issue and a read under 1 s.
- **PDR-C3, roaming profile.** `%APPDATA%` is the *roaming* profile. On a domain with roaming profiles, absolute local paths (which can include account names) are copied to the profile server. `%LOCALAPPDATA%` is per user and per machine. **Condition:** the operator confirms `APPDATA` with that consequence known, or the store moves to `LOCALAPPDATA`. Either way, nothing else in LLR-172.1 changes.

## Verdict

- **Risk verdict:** no HIGH finding, so this is neither `Block` nor `BLOCK-UNTIL:`. All 12 of my findings in scope are closed in the contract. Their mitigations are written in the contract, so their state is `approved` as requirements; none is `executed` in code yet, and the increment gates check that.
- **Recommended P2 gate token, for the security lens:** `approve`. The three PDR conditions above go to PDR and do not block. This review is not operator authorization.
- **Open count:** 0 findings open, and 3 PDR conditions carried.

## Evidence checklist

- [x] Each closure cites its LLR, ledger and interface ids (closure table, *closed by* column).
- [x] Severity is kept for each finding. New observations are classed as non-blocking PDR conditions, and none is HIGH.
- [x] No secret values or real names appear in the output.
- [x] The verdict is explicit: 0 HIGH, gate token `approve` for the security lens.
- [x] I executed where it was cheap, on a `git archive 1d677ba` snapshot, with `s19_app.__file__` printed. This round's scratch folder was removed (`scratch folder removed: True`).
