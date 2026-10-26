# Code Review — Increment 001 (batch-100, "one placement function, reuse, containment")

| Field | Value |
|---|---|
| Reviewer | `code-reviewer` (independent; did not write this code; implementer Kimi K2.8) |
| Tree reviewed | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc1`, detached at `e044112` plus uncommitted changes |
| Contract | main checkout `f3c867e`: `01-requirements.md` HLR-163, LLR-163.1..163.7, LLR-171.4; `design/design-proposal-b100.md` §5.1; `kimi/BRIEF-inc-1.md` + `BRIEF-COMMON.md`; `docs/architecture.md` §11 B100-I6/I13/I14/I22 |
| Interpreter proof | `C:\Users\jjgh8\Github\s19_app-b100-inc1\s19_app\__init__.py` (PYTHONPATH = worktree, NO_COLOR unset, s19env 3.11) |
| **Verdict** | **approve-with-fixes**. Recorded token: **`BLOCK — BLOCK-UNTIL: F1`** (1 HIGH). This verdict authorises nothing. The increment does not advance until F1 is fixed and this reviewer has re-read the fix on the diff. F2–F5 (MAJOR) should land in the same corrective pass. |

## Scope reviewed

- `s19_app/tui/workspace.py`: the whole diff, plus the unchanged `place_group_into_workarea` (`:1128-1458`) and the helpers it relies on (`:195-422`).
- `s19_app/tui/segment_split_view.py`: the diff, and the export body `:815-964`.
- `s19_app/tui/app.py`: the diff at `:195-199` and `:8540-8640`.
- `tests/test_b100_reuse.py` (whole file), `tests/support/b100_links.py` (whole file), and the re-pins in `tests/test_unified_write.py`, `tests/test_tui_patch_editor_v2.py`, `tests/test_b99_export.py`, `tests/test_b99_staging.py` and `tests/test_id_registry.py`.
- The packet `increment-001.md`, `HANDOFF.md` and all 21 evidence transcripts.
- A caller read of `project_gather_service._check_home_contained` / `_gather_copy`. That file is not changed here. It was read to test the "covered by construction" claim.

## What I executed (evidence state: `executed`)

| Run | Result |
|---|---|
| `tests/test_b100_reuse.py` + the 3 re-pins + `test_tc_b99_31_bin_pair…` | 18 passed |
| S-02 probe, export through a junction (`scratchpad/probe/s02_export.py`): `<this wa>/P/exports` was made a junction to `<other>/.s19tool/workarea/victim` | `fmt=s19`: export **WROTE** `other\…\victim\t_isle.s19`; `fmt=bin`: **WROTE** `t_isle.bin` + `t_isle.addr` into the victim; direct `place_into_workarea(junction)`: REFUSED; direct `place_group_into_workarea(junction)`: **WROTE** into the victim |
| S-02 probe, gather (`s02_gather.py`): `_gather_copy(src, <this wa>/P/patches → junction to victim)` | **WROTE** `other\…\victim\hotfix.json` |
| Prediction vs placement path form (`predict_form.py`), relative destination | predicted `b\.s19tool\workarea\P\f.s19`, placed `C:\…\b\.s19tool\workarea\P\f.s19`, equal: **False** |
| Reviewer mutants on a scratch copy (pristine hash `305e197c…` matched `pre-mutation-hashes.txt`). Each was run against `test_b100_reuse.py` (non-AT), `test_copy_into_workarea_content_dedup.py`, `test_b99_staging.py` and `test_tui_workspace.py` | `cap` (size check removed from `place_into_workarea`, the contract's second LLR-163.1 mutation, which the packet never ran) → **KILLED** by `test_tc_b100_01_direct_calls…`; `seam` (the `.s19tool` reparse check removed) → **KILLED** by `tc_b100_62_junction…`; `zero` (0-byte skip removed) → **KILLED** by `test_b99_staging::test_tc_b99_13_zero_byte_target_is_never_reused`; `fold` (case-folding → identity) → **SURVIVED** (79 passed); `contained` (the `contained_in_workarea` refusal removed) → **SURVIVED** (79 passed) |
| Reverse-census files the packet did not run: `test_segment_split_window.py` (it calls the changed export), the whole of `test_tui_patch_editor_v2.py`, `test_tui_variants.py` and `test_copy_into_workarea_content_dedup.py` | head: 2–4 failures in `test_tui_patch_editor_v2.py`, a different set on each run. **At base `e044112`, the same command also gives 4 failures** (again a different set), and each failing node passes in isolation (4 passed). This is a pre-existing order/timing flake, not a regression. `test_segment_split_window.py` passes. |
| Evidence SHA-256s | all 21 transcript digests in the packet match the bytes on disk |
| CRLF | the 8 edited files are uniformly CRLF in the working copy (0 bare LF); the index stays LF via `core.autocrlf=true` |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** | `segment_split_view.py:829`, `:927`, `:939`; `workspace.py:1218-1229`; (caller outside this increment) `services/project_gather_service.py:240-252`, `:342`, `:364` | **S-02 is still open for every caller that resolves the destination before placing.** `place_into_workarea` takes "this work area" from the destination's own textual path. When a caller passes an already-resolved path, the junction is gone before the guard can see it: the resolved path sits in the other work area, and `contained_in_workarea` is then checked against that other work area. The export does exactly this: `home = _check_home_contained(dest_dir)` returns `home.resolve()`, and that home is passed to both placements. The gather does the same with `resolved_home`. `place_group_into_workarea` still runs the pre-batch resolve-first walk directly. So the export's single-file and BIN/`.addr` paths, and Save project's sub-folder copies (named in LLR-171.4's own writer list), all still write into another work area. The packet's claims are false: §1 and LLR-171.4 say "every placing writer … covered by construction", and §5 says the group "places at the same destination the single-file arm already guards". **This is the S-02 class.** It is not a regression; base behaves the same. The export and the group belong in **this** increment: the export is an Inc-1 file, the false claim is made in this packet, and R30 froze the group's *reuse* rule, not its containment. | Probes above: 3 export files, 2 group files and 1 gather file landed in `other\.s19tool\workarea\victim`. | (1) Factor the destination guard (textual walk → `.s19tool` seam → `resolve` → `contained_in_workarea`) into one `workspace.py` helper and call it from both `place_into_workarea` and `place_group_into_workarea`. (2) In the export, pre-check through that helper and pass the **unresolved** `dest_dir` to both placements, never a resolved `home`. (3) Gather: either convert `_check_home_contained` the same way (it would be source file 4/4), or have the orchestrator schedule it by ledger with its own TC-B100-62 arm. Do not leave it implied. (4) Add TC-B100-62 sub-arms: the export through a junction (s19 and bin) and `place_group_into_workarea` through a junction, each with 0 bytes in the victim. Route to `security-reviewer` to confirm severity. |
| F2 | MAJOR | `workspace.py:865-870` | The `contained_in_workarea` refusal inside `place_into_workarea` has no test that kills it. With the check deleted, all 79 nodes stay green. Because the root is derived from the destination itself, the walk plus the seam check already decide every Windows case, so the LLR-171.4 named guard is unverified and close to tautological. "This work area" here means the destination's textual root, not the app's `self.workarea` that B100-I14 describes. | Mutant `contained` SURVIVED. | Either add an arm that only this check can refuse, or record it in the packet as a declared backstop with the reason. Surface to the orchestrator that "this app's work area" (B100-I14) is not what the placement can check without a `workarea` parameter. |
| F3 | MAJOR | `workspace.py:170` (fold), `:246-263`; `tests/test_b100_reuse.py` (missing arms) | The LLR-163.1 boundary catalog is not tested. Missing: an upper-case `_2` name on Windows (reused); `_1` deleted beside an identical `_2` (reused); a link candidate at a `_<N>` name (not reused); a 0-byte `_<N>` candidate (not reused). The Windows case-fold branch is entirely unverified. | Mutant `fold` SURVIVED (79 passed). | Add sub-arms `test_tc_b100_01_<arm>` for the 4 catalog cases. The case arm must fail with `fold` set to identity. |
| F4 | MAJOR | `workspace.py:1089-1104` vs `:865`, `:1026` | `predict_placement` returns `destination / name` unresolved, while `place_into_workarea` returns `resolved_destination / name`. The frozen B100-I22 says the prediction answers "where the placement would put a file", and the B100-I17 handler (Inc 5) compares the landed path with the planned row and raises a mismatch error. A relative or non-canonical destination therefore produces a false mismatch. `self.workarea` comes from an unresolved `base_dir` (`app.py:1543-1545`). | Probe: relative destination, equal False. | Normalise the destination in `predict_placement` the same way the placement does (resolve it, since a prediction writes nothing), and add a TC-B100-68 arm with a relative destination asserting `placed.path == predicted.path`. Fix it now, before Inc 5 consumes the frozen interface. |
| F5 | MAJOR | `tests/test_b100_reuse.py:368-395`; `segment_split_view.py:938-942` | The TC-B100-57 census gives false confidence. Its docstring says "exactly one byte-identity rule exists in the package", but it only counts functions **named** `find_identical`. The package still holds 2 more rules: the group rule (`workspace.py:1290-1296`) and `_gather_copy`'s sibling scan (`project_gather_service.py:354-361`). Any new rule under another name would pass. Also, the group's status word is computed from a pre-listing (`names_before`), outside any `PlacementResult`. That contradicts LLR-163.6's threshold "0 status words computed outside a `PlacementResult`" and is not declared as a deviation. | Code read; the census passes on a tree with 3 rules. | Census by pattern (`read_bytes() ==` / `_hash_file` comparisons) with a declared allow-list (the group rule, R30; `_gather_copy`, naming the increment that converts it). Record the group-word derivation in packet §6 as a deviation for the orchestrator to accept or reject. |
| F6 | MINOR | `tests/test_b100_reuse.py:528-529` | Tautological assertion: the test builds `mismatch = f"{a} != {b}"` and then asserts that `a` and `b` are in it. The test cannot fail on these lines. | Read. | Delete the 2 lines and record the "mismatch error naming both paths" arm as deferred to Inc 5 (B100-I17) in packet §6. |
| F7 | MINOR | `tests/test_b100_reuse.py:172-200` | LLR-163.1's threshold "AST check → 1 claim loop in `workspace.py`" was replaced by a wrapper-shape check without saying so. As written, the threshold is false: `place_group_into_workarea` has a second claim loop. | Read. | Declare the substitution in the packet; the orchestrator fixes the contract wording (e.g. "0 claim loops in `copy_into_workarea`"). |
| F8 | MINOR | `workspace.py:840-846` | The textual anchor refuses legitimate non-canonical forms that the old resolve-first code accepted: an 8.3 `S19TOO~1` component (executed: refused), and on Windows a differently cased `.S19TOOL\WORKAREA`. Exposure is low, because the app builds these paths by joining names. | Probe refusal. | Optionally compare the two anchor parts with case-folding on Windows; note the short-name limit in the docstring. |
| F9 | MINOR | `workspace.py:1108-1125`, `:506`, `:1033-1034`, `:985-989`; `app.py:8636` | Convention and simplicity: the public `copy_into_workarea` lost its `Summary:/Args:/Returns:` sections; `-> list` and an untyped `digest_or_bytes`; an unreachable `if claim_path is None` block after the unbounded walk; the reuse branch still logs "Appended variant". | Read. | Restore the sectioned docstring; type `list[str]` and `str \| bytes`; drop the dead block; log "reused" on the reuse branch. |
| F10 | MINOR | `tests/test_b99_staging.py:2025-2036` | The unplanned re-pin **is justified** by LLR-163.1/B100-I13: the write primitives moved into the new `place_into_workarea`. Its RED side is executed (`mut-llr-155-3-allowlist.txt`), and the census still catches any write outside the list. It does not hide a regression. However, `copy_into_workarea` stays on the allow-list though it no longer writes, which leaves the census looser than it needs to be. | Read + transcript. | Drop `copy_into_workarea` from the set (the TC-B100-01 AST arm pins the wrapper anyway). |
| F11 | MINOR | `increment-001.md` §4, §2; `HANDOFF.md` | Packet accuracy. "19 artifacts", but there are 21 rows (all 21 digests match the files). The signed ledger `217 = 213 − 0 + 4` reconciles with nothing: 213 is the scanned-file count and the module adds 14 nodes. The reverse census skipped `test_segment_split_window.py` and the full `test_tui_patch_editor_v2.py`, although HANDOFF says "all 15 hit files"; I ran them (see above: flake present at base too). The chunk transcripts elide their file list in the `cmd:` line, so they cannot prove which files ran. The LLR-163.1 second mutation was not run (I ran it: KILLED). `HANDOFF.md` is untracked and has no §2 row, so it must not be committed. The two new test files are LF in a CRLF working tree (cosmetic; the index is LF). | Transcripts, my reruns. | Correct the counts and the ledger; add the missing census transcripts with explicit file lists; record the LLR-163.1 cap mutation; keep `HANDOFF.md` out of the commit. |

`tc_b99_31_bin_pair_placed_under_one_suffix` is **unchanged** (no diff) and passes.

## Checks the brief named

| Check | State |
|---|---|
| Correctness against each LLR | 163.1 ✓ apart from F3/F7 · 163.2 ✓ (counting oracle, mutation killed) · 163.3 ✓ · 163.4 ✓ · 163.5 ✓ (order oracle) · 163.6 ✓ for single files; group word F5 · 163.7 ✗ F4 · 171.4 guard ✗ F1/F2 |
| `place_into_workarea` holds every guard, in order | ✓ inside the function: source reparse → textual walk + `.s19tool` seam → resolve + `contained_in_workarea` → 256 MiB cap before staging → private staging → reuse or `O_EXCL` claim → `os.replace` with retry. ✗ against callers that pre-resolve (F1). |
| `copy_into_workarea` is exactly `place_into_workarea(...).path`, with no second claim loop | ✓ (`workspace.py:1125`; AST arm) |
| `predict_placement` shares the walk | ✓ shares `_match_identical` + `_placed_name_candidates`; ✗ path form (F4) |
| The export takes its word from `PlacementResult` | ✓ single file; the group derives it from a listing (F5) |
| 3 SOURCE files, CRLF preserved | ✓ 3/4; ✓ CRLF |
| Tests black-box where they are ATs | ✓ AT-B100-01 drives rail keys and clicks, reads `#log_line_4` / `#status_text` and the files on disk, at 118×54 and 220×60 with notifications on. TC-B100-03 is white-box (`_handle_load_project`, `load_from_path`, a patched `set_status`), which is allowed for a TC. |
| Declared mutations kill | ✓ for the 8 in the packet; mine: cap/seam/zero KILLED, fold/contained SURVIVED (F2, F3) |
| `test_b99_staging.py` re-pin | justified (F10) |
| `place_group_into_workarea` containment | S-02 class, executed escape; belongs in this increment (F1) |

## Evidence checklist

- [x] Diff read in full: `workspace.py` (diff, plus `:195-422` and `:1128-1458`), `segment_split_view.py:670-964`, `app.py:8540-8640`, all test diffs, and both new test files.
- [x] Correctness pass: F1, F2, F4, F8.
- [x] Simplicity pass: one shared walk (good); a dead block (F9); one duplicated destination guard between the two placements (folded into the F1 fix).
- [x] Reuse/duplication checked against existing utilities: the group rule and the gather rule remain (F5).
- [x] Tests reviewed for intent: F3, F5, F6, F7; the LLR-163.5 order oracle is a good catch by the implementer.
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1`; the one HIGH is open, with executed evidence.

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1** (1 HIGH, 4 MAJOR, 6 MINOR) · F1 open: the S-02 escape is still live through the export (single file + BIN/`.addr` group) and through Save project's gather, because those callers place into a pre-resolved destination and `place_group_into_workarea` keeps the resolve-first walk (executed probes, `review-increment-001.md`). It is discharged only when a re-read of the applied fix shows the shared destination guard plus the new TC-B100-62 export and group arms.

## Hand-offs

- `security-reviewer`: F1 (the S-02 class, executed escapes) and the gather path's scheduling.
- Orchestrator: F2's "this app's work area" interface question (B100-I14 vs no `workarea` parameter); F7's contract wording; F5's group-word deviation.
- `qa-reviewer`: the `test_tui_patch_editor_v2.py` order/timing flake, present at base and head.

---

# Round 2 — re-read of corrective pass 1

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as round 1. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc1` at `e044112` with Inc 1 and fix pass 1 uncommitted; `workspace.py` sha256 `c10a9d82…` |
| Contract | main `5f0ef66`: amended LLR-163.1 and LED .49 (the root is read off the unresolved destination; the group is a second placement kind; 4 source files) |
| Inputs | `HANDOFF.md` §"Fix pass 1", `BRIEF-inc-1-fix1.md`, packet `increment-001.md` (§2, §4, §5, §6) |
| **Verdict** | **approve — PASS-WITH-NOTES.** 0 HIGH open. **F1 is discharged**, because I re-read the applied fix on the diff and re-ran the escape probes myself. One new MAJOR (N1) stays open as a recorded note. It does not block, because no shipped writer can build the path it needs. It must be closed in this increment or scheduled in the ledger before Inc 8b. |

## What I executed in round 2 (evidence state: `executed`)

| Run | Result |
|---|---|
| F1 probe, export (`probe/s02_export.py`): `<this wa>/P/exports` as a junction to `<other>/.s19tool/workarea/victim` | `fmt=s19` **REFUSED**, `fmt=bin` **REFUSED**, `place_group_into_workarea(junction)` **REFUSED**, direct `place_into_workarea` REFUSED. Victim folder: `[]` |
| F1 probe, gather (`probe/s02_gather.py`) | `_gather_copy` **REFUSED**. Victim folder: `[]` |
| F4 probe (`probe/predict_form.py`) | relative destination: predicted == placed (**True**). 8.3 short-name destination: **accepted**, and predicted == placed (True) |
| New-code probes (`probe/r2_guard.py`) | (a) short-name form through a `.s19tool` junction → REFUSED · (b1) explicit root, destination in another work area → REFUSED · (b2) explicit root, junction inside this work area → REFUSED · (c1) legitimate `.S19TOOL\WORKAREA` → accepted · (c2) upper-case form through a junction → REFUSED · **(d) nested anchor: junction `<this wa>/nest` → `<other>`, destination `<this wa>/nest/.s19tool/workarea/x`, no explicit root → WROTE `other\.s19tool\workarea\x\f.s19`** (N1) · (d′) the same destination with `workarea_root=<this wa>` → REFUSED |
| Reviewer mutants on scratch copy `mutwt2` (pristine `c10a9d82…`), run against `test_b100_reuse.py` (non-AT), `test_copy_into_workarea_content_dedup.py`, `test_b99_staging.py`, `test_tui_workspace.py` and `test_project_gather.py` | `fold` → **KILLED** (`…upper_case_suffix_name_is_reused_on_windows`) · `contained` → **KILLED** (`…62_explicit_root_refuses_another_workarea`) · `seam` → **KILLED** (`…62_junction_destination…`) · `shortreparse` (reparse refusal removed from the short-name fallback) → **SURVIVED** (104 passed) · `anchorcase` (case-folded anchor match → exact) → **SURVIVED** (104 passed) |
| Affected files on the fixed tree: `test_b100_reuse.py`, `test_project_gather.py`, `test_segment_split_window.py`, `test_b99_export.py`, `test_b99_staging.py`, the tc018 and at031b nodes, `test_id_registry.py` | **164 passed**, 0 failed |
| CRLF | the 4 sources and all edited or new test files: 0 bare LF |
| Evidence digests | 36 of 37 packet rows match the bytes on disk. **`guards.txt` does not**: the packet shows `…5290d9e85f8762a2b5ff0818e0e7f8`, the disk has `…5290d9e85f876a2b5ff0818e0e7f8a`. This is a hand-copy error (N2). |

## Closure table — round 1 findings

| id | Round-1 severity | Status | Evidence of closure (re-read on the diff) |
|---|---|---|---|
| **F1** | HIGH | **CLOSED** | `_guarded_destination` (`workspace.py:553-655`) reads the root off the unresolved path, walks it for reparse points, checks the `.s19tool` seam, and only then resolves both sides and compares them. Both placement kinds call it (`:1041`, `:1434`). The export guards and places with the unresolved `dest_dir` (`segment_split_view.py:833`, `:939-941`). The gather routes `_check_home_contained` through the guard and passes the unresolved `home` (`project_gather_service.py:242`, `:357`). My probes: export s19/bin, group and gather are all refused, with 0 bytes in the victim. Three caller arms (`test_tc_b100_62_{export,group,gather}_junction…`), each with a caller-revert RED (`red-04/05/06`). |
| F2 | MAJOR | **CLOSED, with a note** | My `contained` mutant is now killed, through the explicit-root arm. Note: **no production caller passes `workarea_root`**. On every shipped path the root is still derived from the destination, so there the resolved-pair check remains a backstop, and that is why N1 exists. LED .49 explicitly allows the derived root; I accept the §6 ruling as written. |
| F3 | MAJOR | **CLOSED** | Four boundary arms (`test_b100_reuse.py:238-316`). The packet's mutants (fold, barename, link, zero) are all killed, and my `fold` mutant is killed too. The link and upper-case arms skip off Windows or without symlink privilege, with the reason given. |
| F4 | MAJOR | **CLOSED** | `predict_placement` resolves its destination (`workspace.py:1262`); arm `test_tc_b100_68_relative_destination_matches_placed_path`; my probe agrees. |
| F5 | MAJOR | **CLOSED (census); §6 deviation ACCEPTED with one condition** | The census now works by behaviour, with an exact-set assertion against two declared other rules (`:484-554`). A new rule under any name, or a deleted declared rule, fails it. **§6 group word: accepted.** It is correct because the group's claim loop checks with lstat before claiming and never claims an existing name, so "every returned name was present before" means reused. Condition: the comparison `f.name in names_before` is case-exact. On Windows, a reused group whose existing file differs only in case from the requested name (the group returns the requested spelling) would be reported as `wrote`. Compare case-folded on Windows (N5). |
| F6 | MINOR | **CLOSED** | The self-confirming lines are deleted (`:803-824`); the mismatch-report arm is deferred to Inc 5 in §6. |
| F7 | MINOR | **CLOSED; §6 substitution ACCEPTED** | `test_tc_b100_01_one_claim_loop_per_placement_kind` pins exactly 1 `O_EXCL` per kind (2 in total), matching amended LLR-163.1 and LED .49. |
| F8 | MINOR | **CLOSED, with notes** | Case-insensitive anchor on Windows (`:311-328`) and the 8.3 fallback (`:339-403`). Both forms are accepted, and the escape forms are still refused (probes a, c1, c2). Two notes are in N4. |
| F9 | MINOR | **CLOSED** (one nit) | The sectioned docstring is restored; the dead block is gone (only the `# pragma: no cover` raise at `:1278` remains, which is fine); the reuse branch logs "Reused variant" (`app.py`); `digest_or_bytes` is typed. Nit: `_reuse_candidate_names` still returns a bare `-> list` (`:696`). |
| F10 | MINOR | **CLOSED** | `copy_into_workarea` is off `_FINAL_NAME_ALLOWLIST` (`test_b99_staging.py:2031-2037`); the staging tests pass. |
| F11 | MINOR | **MOSTLY CLOSED; one residual (N2)** | Count and ledger reconcile (37 rows; files `215 = 213 − 0 + 2`; nodes `24 = 14 + 10`, 23 functions with the AT parametrised ×2). The chunk transcripts name their files on line 1; the cap mutation is recorded; `HANDOFF.md` is declared out of the commit. Residual: the `guards.txt` digest is wrong (N2). |

## New findings — round 2

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **N1** | **MAJOR** (does not block: no shipped writer builds this path) | `workspace.py:621-646` (`_guarded_destination`, derived-root branch) | **Nested-anchor bypass.** With no explicit root, the guard picks the **nearest** `.s19tool/workarea` ancestor. The reparse walk then stops at that inner anchor's `.s19tool`, so a junction **between the app's work area and a nested anchor** is never checked. The resolved pair (other work area vs other work area) then passes. This falsifies amended LLR-163.1's own sentence "a junction or link anywhere in the destination is caught". Same S-02 class. Today no shipped writer composes `<wa>/<x>/.s19tool/workarea/…`: project names are sanitised and the sub-folders are fixed names. But it is one typed or loaded path away (the Inc 8b/9a surfaces). | Probe (d): WROTE into `other\.s19tool\workarea\x`. Probe (d′) with an explicit root: REFUSED. | Either (a) when deriving the root, continue the textual reparse walk up to the **outermost** anchor's `.s19tool` (the parts between two anchors lie inside the outer work area, so checking them is correct and cheap), or (b) record a ledger entry so that every app-level writer passes `workarea_root=self.workarea` by Inc 8b, with a TC-B100-62 nested-anchor arm. (a) is a ~5-line change inside Inc 1's own guard; I recommend it. Route to `security-reviewer`. |
| N2 | MINOR | `increment-001.md`, §4 evidence row `guards.txt` | The recorded SHA-256 does not match the file. Two characters are swapped near the end and the digest is shifted by one; it looks hand-copied. `devflow-evidence.py --check` would fail on it. | `sha256sum` on disk vs the packet row. | Regenerate the row with `devflow-evidence.py --write <packet> --rederive`; never hand-copy a digest. |
| N3 | MINOR | `tests/test_b100_reuse.py:520-522`, `:493` | The census says `_gather_copy`'s sibling scan is "converted by Inc 3b". Batch-100 has no Inc 3b (that was batch-99's conversion of the delete-and-recopy). The declared rule therefore has no owner. | `design-proposal-b100.md` lists Inc 3 = "a project load starts clean". | Name it as backlog (or the real increment, if the orchestrator schedules one), not "Inc 3b". |
| N4 | MINOR | `workspace.py:381-391`, `:311-322` | Two F8 branches have no test that kills them: my `shortreparse` and `anchorcase` mutants both SURVIVE. `anchorcase` is close to equivalent, because the 8.3 fallback resolves an upper-case form anyway. `shortreparse` is equivalent for escapes, because the main walk and the seam check still cover `.s19tool` and below. But the fallback's own check also refuses reparse ancestors **above** the anchor (for example a junctioned user or TEMP folder). That refuses a short-name form the base accepted, against the F8 decision "don't refuse forms the base accepted unless they escape". | Mutants SURVIVED. | Limit the fallback's reparse refusal to the anchor and below (the main walk already covers that, so the fallback can simply return the prefix), or keep the stricter rule and declare it in §6. An upper-case arm needs no new test if you declare it equivalent. |
| N5 | MINOR | `segment_split_view.py:938-942` | This is the F5 acceptance condition: the case-exact group-word comparison can report a reused group as `wrote` on Windows (see F5 above). | Code read. | `fold = str.casefold` on win32 for both sides of the membership test. |

## Verdict

**approve — PASS-WITH-NOTES** (0 HIGH; open: 1 MAJOR, N1; 4 MINOR, N2–N5; plus the F9 nit).
- **F1 is discharged by this re-read.** The fix is applied on the diff, my own probes refuse all three writers, and the arms carry RED proofs.
- N2 is a record defect. The orchestrator corrects it before the commit, since a failing evidence check would block.
- N1 should be fixed in this increment (option a). If it is not, it must have a ledger entry with an owner before Inc 8b. It must not be left implicit.

## §4b `Independent review` cell (final, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; round 2 open: N1 MAJOR, N2–N5 MINOR) · F1 (HIGH, round 1) RESOLVED: one destination guard, `_guarded_destination`, is used by both placement kinds. It reads the root off the unresolved destination, and the export, group and gather now pass unresolved destinations. Re-read on the diff, my escape probes refused all three writers (0 bytes in the victim), and arms `test_tc_b100_62_{export,group,gather}_junction…` each carry a caller-revert RED (`red-04/05/06`). F2–F11 are closed; the §6 F5 and F7 declarations are accepted, F5 on condition N5. Round-2 note N1: a nested-anchor junction escapes the derived-root guard (probe d); fix it in Inc 1 or ledger it before Inc 8b (`review-increment-001.md` §Round 2).

## Hand-offs (round 2)

- `security-reviewer`: N1 (the nested-anchor S-02 variant, executed escape).
- Orchestrator: N2 (correct the evidence row before the commit); N3 (who owns `_gather_copy`'s rule); the decision on N1, fix now or ledger.
