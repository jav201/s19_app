# Code Review — Increment 002 (batch-100, "Save project name guards")

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. Independent: I did not write this code. The implementer was Kimi K2.8. |
| Tree reviewed | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2`, detached at `2edfee2`, with uncommitted changes. `app.py` sha256 `935726ca3b6c…` and `workspace.py` `6c7db1448758…` both equal `pre-mutation-hashes.txt`. |
| Contract | `01-requirements.md`: HLR-164, LLR-164.1..164.4, the refusal-token table, LED .49 and .50. `design/design-proposal-b100.md` §5.2. `kimi/BRIEF-inc-2.md` and `BRIEF-COMMON.md`. Precedent: `review-increment-001.md`. |
| Interpreter proof | `…\scratchpad\fixed\s19_app\__init__.py` and `…\scratchpad\base\s19_app\__init__.py`. Both used `PYTHONPATH` = that tree, `NO_COLOR` unset and s19env 3.11. The worktree was never edited. |
| **Verdict** | **approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: F1, F2`** (2 HIGH). This verdict authorises nothing. The increment does not advance until F1 and F2 are fixed and I have re-read both fixes on the diff. F3–F7 (MAJOR) should land in the same corrective pass. |

## Scope reviewed

- `s19_app/tui/app.py`: the whole diff (`:179-205`, `:1404-1415`, `:8112-8463`, `:8465-8571`, `:8722-8728`). I also read the consumers of `_variant_set` (`:4337`, `:4781`, `:5927`, `:6657`, `:6737`, `:6789`, `:7234-7243`, `:11259`, `:13511`) to judge F1's impact.
- `s19_app/tui/workspace.py`: the whole diff (`:54-65`, `:1744-1770`), plus `_is_reparse_point` (`:207`), `sanitize_project_name` (`:1773`) and the existing device list in `segment_split_view.py:518-623`.
- `tests/test_b100_save_guards.py` (all of it) and `tests/test_id_registry.py` (the diff).
- The packet `increment-002.md`, `HANDOFF.md` and all 17 transcripts in `evidence/inc-2/`.

## What I executed (evidence state: `executed`)

| Run | Result |
|---|---|
| **Behavioural RED at base.** `git archive 2edfee2` into scratch, with the new test file copied in. Its one import of `PROJECT_NAME_MAX_CHARS` was replaced by the literal `64`. Transcript: `scratchpad\base-red.txt`. | **16 failed, 2 passed.** Every failure is behavioural, not an import error. Reserved: `'temp': … got 'Manifest verify MISMATCH'`. Device: `FileNotFoundError … workarea\nul`. Listing: `['realproject', …, 'Splits']`. Clash and case-only: `Project saved + manifest verified`. Junction: token missing, because the Inc 1 guard refused untokenised. Cap: `FileNotFoundError` on 300 characters. Path: the 56-character name saved. Census: `return at line 8167 leaves without removing`. All 5 forced stages: `OSError` escaped. AT: `did not settle: the reserved-name refusal tokens`. The 2 that pass are the must-stay-green guards (`exact_name_adds_a_variant` and `open_project_unsanitised_name_saves_into_it`). They cannot be RED at base by design. |
| GREEN on a scratch copy of the fixed tree (same hashes): `test_b100_save_guards.py` + the A-09 node + `test_tui_report_seam.py` + `test_tui_manifest_save.py` | **61 passed** (370 s) |
| Kimi's mutants, re-run: M1 (device check on the sanitised name only) | **KILLED**: `'con.txt': expected the device-name refusal, got 'Project saved + manifest verified'` |
| Kimi's M4 (the `except OSError` removal call deleted) | **KILLED**, and by more than the packet claims: the census and **all 5** forced stages fail (6 failed). Kimi's transcript ran 2 selected nodes only. |
| Reviewer M5 (the open-project exemption `continue` deleted) | **KILLED** by `test_tc_b100_05_open_project_unsanitised_name_saves_into_it` |
| Reviewer M6+M7 (both empty-name statuses reverted to `"Invalid project name."`) | **SURVIVED.** TC-04/05/06: 10 passed. The full module also stayed green under M6, 18 passed. → F6 |
| Restore after each mutant | sha256 back to `935726ca3b6c…` after every mutant |
| Probes (`scratchpad\fixed\tests\test_zz_review_probes.py`) | See F1, F3, F4, F5 and F7. Their output is quoted in each finding. |
| Evidence SHA-256s, checked with `devflow-evidence.py --root . --check <all 17>` | The 15 digests in the packet match the bytes on disk. `green-01` and `green-03` are on disk but are not in the packet. The index `MISMATCH` lines are only "not staged", which is expected for an uncommitted tree. |
| LED .50 sweep: `git diff -U0 -- s19_app/` searched for added `resolve(` or placement calls | 0 added `.resolve()`; 0 new placement calls. The 3 existing `copy_into_workarea` calls and the gather keep `workarea_root=self.workarea`. ✓ |
| CRLF | The 4 edited files are uniformly CRLF in the working copy (`app.py` 13864/13864, `workspace.py` 1941/1941). The blobs stay LF via `core.autocrlf=true`. ✓ |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** | `app.py:8353-8373` (in-memory state committed), `:8414-8422`, `:8427-8463` (failure exits) | **A failed save leaves the app holding the variant set of the folder it just deleted.** Kimi moved `current_project` / `current_project_dir` to the end of the body. But `self._variant_set = build_variant_set(cleaned, …)`, `current_file.variant_id` and `_report_filter_path = None` are still written mid-body, before the gather and the manifest. Every later exit removes the folder and restores none of them. So after a manifest refusal, or an `OSError` in the gather or the manifest, the app is in a mixed state. `current_project` still names the old project, while `_variant_set` lists the new project's files, which are gone from disk. Consequences: `v` offers a variant that does not exist; Execute (`:4337-4340`) and Report (`:4780-4783`) pair the OLD project dir with the deleted project's variants; and the open project's real variant set is lost until it is reloaded. This is a **regression of this diff**. At base, a manifest refusal kept the folder and installed the new project consistently; base crashed on a gather `OSError`. The 5 forced-`OSError` arms assert only folders and tokens. They therefore give false confidence on "the app keeps running": it runs, in a wrong state. Smaller: the status log already shows `Saved project to …` (`:8379-8384`) before the save can still fail. | Probe `stale_variant_set_after_manifest_refusal`. Project `ab` open, variant ids before `['a']` → `ab\a.s19`. Save as `newp` with the writer returning `(None, issues)`. Status `could not save … check the folder`; `current_project: ab`; **variant ids after `['firmware']` → `…\workarea\newp\firmware.s19`, exists `False`**; `current_file.variant_id: firmware`. The gather-`OSError` probe gives the same result. | Snapshot `_variant_set`, `current_file.variant_id` and `_report_filter_path` before the `try`. Restore them at every failure exit: fold the restore and `_remove_created_project_dir` into one `_abort_save(...)` helper that every exit calls, so the census still counts one call per exit. Move the `Saved project to …` status after `manifest_ok`. Add assertions to each forced stage of TC-B100-07: with a project open beforehand, `_variant_set` ids and paths and `current_file.variant_id` are unchanged after the failure. Add one arm where `write_project_manifest` returns `(None, issues)`. Packet §5 claims that path is armed; no test exercises it. |
| **F2** | **HIGH** (record; `V59` blocks) | `increment-002.md` §2, row `tests/test_id_registry.py` | `Kind` = `config` with `Traces to` = `registry hygiene`. That is not a requirement id. `V59` says a `config` row owes an existing US/HLR/LLR id and that a missing id **blocks at every gate**. This is the defect corrected on Inc 1 after its gate (main `cdd2ea5`: "V59 kinds and traces corrected"). | Packet line 68 | Write `HLR-164 (registry hygiene for the new Inc 2 test file)`, the shape `cdd2ea5` used. |
| F3 | MAJOR | `workspace.py:1764-1770` | **`is_windows_device_name` splits on the LAST dot.** Windows matches the part before the FIRST dot: Microsoft's naming rules say `NUL.tar.gz` is equivalent to `NUL`. So `con.tar.gz`, `NUL.tar.gz` and `com1.a.b` are all reported as not device names. In this increment the raw name `con.tar.gz` is saved as `contargz` while `con.txt` is refused, which is inconsistent with LLR-164.1's "with or without an extension". The larger cost: this is the ONE shared predicate, frozen here (B100-I11), and LLR-169.8 (manifest-key path components) and LLR-172.2 (recents) consume it. A manifest entry `nul.tar.gz` would pass there. | Probe: `PREDICATE 'con.tar.gz' -> False`, `'NUL.tar.gz' -> False`, `'com1.a.b' -> False` | `stem = folded.partition(".")[0]`, replacing the `rpartition` branch, before it freezes. Add the raw arms `con.tar.gz` and `NUL.tar.gz` to TC-B100-04. Route to `security-reviewer`: decide whether trailing spaces in the stem (`"nul "`, `"CON .txt"`) belong in the predicate or stay with LLR-169.8's separate rule. |
| F4 | MAJOR | `app.py:8208`, `:8225-8226`, `:8423` | **The open-project exemption is case-folded, which is wider than LLR-164.2(c).** (c) exempts the open project's name "typed exactly or as its unsanitised form". `AB` is neither: `sanitize_project_name` does not fold case, and for a project that is not open the same `AB` is refused as a case-only clash. With `ab` open, `AB` is saved and the app installs `current_project='AB'` and `current_project_dir=<wa>\AB`, while the folder on disk is `ab`. The project's identity now differs from its folder. | Probe `open_project_case_variant`: `STATUS: Project saved + manifest verified`; `current_project after: AB …\workarea\AB`; folders `['ab', 'patches', 'temp']` | Exempt only when `cleaned == item.name` and `item.name` is the open project (an exact match after sanitising). `AB` then falls into the clash refusal. If the orchestrator prefers to accept case variants for the open project, then install `item.name` (the on-disk spelling), not `cleaned`. Either way, add the arm. |
| F5 | MAJOR | `app.py:8427-8463`; packet §5 bullet 1 | **A failed save into an existing folder (an exact-name merge, or the open project) leaves the files it placed.** `_remove_created_project_dir` runs only when `created` is true, and nothing removes the variants already copied. HLR-164 ("remove … the files the merge placed") and the thresholds of both HLR-164 and LLR-164.2 ("a forced `OSError` mid-merge → the target's file set and `project.json` unchanged") require it. Packet §5 defers this arm to Inc 8a "per the proposal's table". But the contract's split table (`01-requirements.md:1930`) gives Inc 8a only "the merge carry of `gathered` and `active_document`", and the brief excludes only "the merge-carry arm". The deferral is not in the contract. | Probe `merge_oserror_leaves_placed_file`: `ab` exists and is not open, `ab` is typed, and the gather raises. Status `could not save`; **`ab` files after: `['a.s19', 'firmware.s19']`** | Either implement it now: place through `place_into_workarea` so `PlacementResult.reused` is known, and unlink the non-reused placed paths in the shared abort helper of F1. Or get an orchestrator ledger entry that moves this arm to 8a, and correct the §5 citation. |
| F6 | MAJOR | `app.py:8130-8146`; `tests/test_b100_save_guards.py` (missing arm); packet §4 "Supersession" row 2 | **The empty-name refusal has no test, and the packet claims one.** The supersession row cites "`test_tc_b100_04` + the AT empty boundary in `green-04`". Neither tests an empty name. Reverting both empty-name statuses to the old `"Invalid project name."` leaves the module green. | M6+M7 SURVIVED (10 passed, TC-04/05/06). The full module stayed green under M6 (18 passed). | Add `test_tc_b100_04_empty_names_refused` (`""`, `"   "`, `"!!!"`) → `name is empty` + `type a project name`, 0 folders. Correct the packet row. |
| F7 | MAJOR | `tests/test_b100_save_guards.py:703-769`; packet §6 bullet 2 | **The §6 reading of "P2 open" is not right.** Enabler E4 (design §5) defines P2 as a project builder (`prg.s19`), next to P1. So "With project `ab` saved and P2 open" means another project is open and `ab` is not. Kimi read P2 as "a loaded file, no project open" and says it is "the only reading consistent with LLR-164.2". It is not: the literal reading is fully consistent, and the shipped code already passes it. The substitution drops the one precondition this AT states, a different project being open. That is the case where an exemption keyed to "some project is open" would misfire. `ab` is also built by hand rather than saved. | Probe `other_project_open_then_disguised_clash`: `open: P2` → `STATUS: Project NOT saved: 'a b' is already a project as 'ab' — choose another name.`; `ab` files `['a.s19']` | In the AT: build `ab` and P2. Ideally `ab` comes from a real Save project, which is cheap, since the AT already loads a file. Open P2 through the Load project dialog by keys, then type `a b`. Rewrite §6 to state the literal reading. |
| F8 | MINOR | `app.py:8210-8222` | The Q-2 scan calls `iterdir()` on **every** work-area folder before comparing names. That costs a full child listing per save. Worse, any `OSError` from an unrelated folder (for example access denied) is raised before the folder exists and outside the handler, so `_handle_save_dialog` raises, against HLR-164's "keep running". | code read | Compare `item.name.casefold() != cleaned.casefold()` first, then inspect only the matching folder. Wrap that one probe in `except OSError`, refusing with `could not save` / `check the folder`. |
| F9 | MINOR | `tests/test_b100_save_guards.py:179-201`, `:256-263` | The reserved-name oracle is a FILE digest (`_digest_manifest` ignores folders), so a refusal placed after `mkdir` would pass. LLR-164.1 says "0 folders". `_make_project(app, "sPlItS")` is the same folder as `Splits` on NTFS, although the docstring says three folders exist. | code read | Also assert that the work area's folder list is unchanged. Drop or explain the `sPlItS` line. |
| F10 | MINOR | packet §4, §5; `evidence/inc-2/` | Record hygiene. (a) The evidence field says 16 artifacts but the table lists 15. `green-01` and `green-03` (intermediate failing runs) are unhashed: list them as superseded or remove them. (b) "Arms that stayed GREEN: named per mutation" is not evidenced, because each mutation transcript runs only the killed node(s). (c) The `cmd:` lines of `green-02`, `guards`, `guards-census`, `reverse-census-*` and `mut-*` omit `PYTHONPATH` and `NO_COLOR`. `import-proof.txt` does not show the env either. (d) The RED row is a collection error. Cite a behavioural base run like mine (16 failed / 2 passed, with the 2 named as must-stay-green). (e) `HANDOFF.md` sits at the worktree root and is not in §2. Move it to `kimi/inc-2-HANDOFF.md` as Inc 1 did. | transcripts | Fix the record in the corrective pass. Every `N passed` figure that the packet quotes does appear in a cited transcript: 18, 1, 152, 132+1x, 116, 75+29 snapshots, 85. ✓ |
| F11 | MINOR | `app.py:8120-8124`, `:8190-8193`, `:8210` | The path-limit check and the Q-2 scan use `self.workarea`, but the save target is `parent_resolved / cleaned`. The `#project_parent_path` field still exists until Inc 11 (D7). Choosing another parent therefore skips the clash check, and the length check measures the wrong base. `resolve_input_path` can also lengthen an 8.3 base. The contract names `self.workarea`, so this is a note for Inc 11, not a fix here. | code read | Record it as an Inc 11 dependency: removing the field closes it. |

## Checks the brief named

| Check | State |
|---|---|
| Name check before ANY `mkdir`, in order | ✓ The order is: empty (`:8130`, plus "no usable characters" `:8137`) → device on raw + components + sanitised (`:8151-8167`) → reserved case-folded (`:8168-8179`) → cap 64 (`:8180`) → path limit 259 (`:8190`) → disguised clash naming both, `choose another name`, no merge wording (UX-35) (`:8208-8240`) → link/junction before any resolve (`:8277`). The pre-existing missing-source check (LLR-155.4) sits between the clash and the link check; it is not a name check. ✗ The predicate is wrong for multi-dot names (F3), and the exemption is too wide (F4). |
| One `OSError` handler from creation, with cleanup | ✓ The whole post-`mkdir` body is under one `try`; the 7 exits each remove. ✗ In-memory state is not rolled back (F1). Files placed into an existing folder are not removed (F5). |
| `list_projects` case-folded | ✓ `:8723-8726`; `Splits` is no longer listed (RED at base, GREEN now) |
| Exact-name save adds a variant (LLR-005.1) | ✓ `test_tc_b100_05_exact_name_adds_a_variant`; the A-09 node passes unchanged (my run: part of the 61) |
| No regression of Inc 1 (LED .50) | ✓ no new `.resolve()`; every placement keeps `workarea_root=self.workarea` |
| RED quality | ✓ Behavioural RED shown by me at base: 16 of 16 behavioural nodes fail for the right reason. The 2 must-stay-green guards are non-vacuous by mutation (M5 kills the open-project guard; the exact-name guard is the A-09 behaviour). ✗ The empty-name branch is vacuous (F6). |
| Kimi's §6 reading | ✗ F7 |
| Hygiene | ✓ 2 SOURCE files, CRLF preserved, digests match. ✗ The V59 trace (F2), and record items (F10) |

## Evidence checklist

- [x] Diff read in full: `app.py` `:179-205`, `:1404-1415`, `:8112-8571`, `:8722-8728`; `workspace.py` `:54-65`, `:1744-1770`; the whole new test file; the `test_id_registry.py` diff.
- [x] Correctness pass: F1 (state on failure), F3 (predicate), F4 (exemption), F5 (merge failure), F8 (the scan raising).
- [x] Simplicity pass: the guards are plain sequential checks, with no premature abstraction. The one inefficiency is F8. The F1 fix should add ONE abort helper, not a second removal pattern.
- [x] Reuse checked: `_is_reparse_point` is reused rather than re-implemented, and cross-module private use has precedent in Inc 1 (`_guarded_destination`). The new device predicate duplicates `segment_split_view._EXPORT_RESERVED_DEVICES`, which the contract records as backlog.
- [x] Tests reviewed for intent: F1 (state not asserted), F6 (empty-name branch vacuous), F7 (AT precondition dropped), F9 (folder oracle).
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1, F2`. Both HIGHs are open, with executed evidence (F1) and a rule citation (F2).

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1, F2** (2 HIGH, 5 MAJOR, 4 MINOR) · F1 is open: after a failed save (manifest refused, or an `OSError` in the gather or the manifest), the app keeps a `_variant_set` and `current_file.variant_id` that point into the folder it just removed, while `current_project` still names the previous project (executed probe, `review-increment-002.md`). F2 is open: the §2 row `tests/test_id_registry.py` traces to no requirement id (`V59`). Each is discharged only when a re-read of the applied fix shows the rollback with its state assertions in the TC-B100-07 arms, plus a `(None, issues)` manifest arm (F1), and the corrected trace (F2).

## Hand-offs

- `security-reviewer`: F3. The shared device predicate freezes here and LLR-169.8 and LLR-172.2 consume it. Also decide the trailing-space question.
- Orchestrator: F5 (is the mid-merge `OSError` arm Inc 2 or Inc 8a? There is no ledger entry either way). F4 (refuse a case variant of the open project, or accept it under the on-disk spelling). F7 (the literal "P2 open" reading). F11 (an Inc 11 dependency).
- `qa-reviewer`: F6 and F9 (oracle gaps), and the F1 state assertions in the forced-failure arms.

---

# Round 2: re-read of corrective pass 1

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as round 1. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2` at `2edfee2`, with Inc 2 and fix pass 1 uncommitted. `app.py` sha256 `b2dcf23c1f9a…` and `workspace.py` `d2137e1d5b5d…` both equal `pre-mutation-hashes-fix1.txt`. |
| Contract | main `3bafa06`: LED .52 (a) the open project's name ignores case and the save uses the on-disk name; (b) a failed save removes every file it placed and restores the app state; (c) "P2 open" means another project is open. Plus `kimi/BRIEF-inc-2-fix1.md` and `security-increment-002.md` SEC2-1..3. |
| Inputs | `HANDOFF.md` §"Fix pass 1"; packet `increment-002.md` §1, §2, §4, §5, §6; 36 transcripts in `evidence/inc-2/`. |
| Interpreter proof | `…\scratchpad\fix1\s19_app\__init__.py`. That scratch copy holds `git archive 2edfee2` plus the 5 changed files, with hashes equal to the worktree. `NO_COLOR` was unset. The worktree was never edited. |
| **Verdict** | **approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: R2-1, R2-2`** (2 HIGH). **F1 and F2 are discharged**: I re-read both fixes on the diff, and for F1 I re-ran the probe myself. R2-1 is the same class as F1 and F5, but it hits the gather's copies. A save into an existing project that fails still leaves those copies behind, which contradicts LED .52(b). R2-2 is the same record class as F2. |

## What I executed in round 2 (evidence state: `executed`)

| Run | Result |
|---|---|
| GREEN on the scratch copy of the fix-pass tree: `test_b100_save_guards.py` (27 nodes, both ATs included) + the A-09 node + the 2 re-pinned `test_b99_staging.py` nodes | **30 passed** (196 s) |
| Round-1 probes re-run (`scratchpad\fix1\tests\test_zz_review_r2.py`) | **F1:** open `ab`, save `newp`, writer refuses. Variant paths, current variant and `current_project` are equal before and after (`['…\ab\a.s19'], None, 'ab'` both times); the log tail is `Manifest write failed` → `could not save`, with no `Saved` line. **F3:** `con.tar.gz`, `NUL.tar.gz`, `com1.a.b`, `CON .txt`, `CON.`, `nul ` and `conin$.x` → True; `COM⁴`, `console` and `con\xa0.txt` → False. **F4:** open `ab`, type `A B` → saved into `ab`; `current_project` and the folder name are both `ab`; no new folder. |
| **New probe: gather copies after a failed merge.** `ab` exists and is not open. `<wa>\patches\hotfix.json` exists, the payload has `batch=("hotfix.json",)`, `ab` is typed exactly, and the manifest writer refuses. | Status `could not save … check the folder`. **`ab` before: `['a.s19']`; `ab` after: `['a.s19', 'patches', 'patches\hotfix.json']`.** Control, the same save with no forced failure: `['a.s19', 'firmware.s19', 'patches', 'patches\hotfix.json', 'project.json']`. → R2-1 |
| Mutants on the scratch copy, each run against the module's 25 non-AT nodes, with both source hashes restored after each | **M6** (empty-name status, first branch) → **KILLED** by `test_tc_b100_04_empty_names_refused`. **M7** (second branch, no usable characters) → **KILLED**, same node. **MF1** (the state-restore lines removed from `_abort_save`) → **KILLED**, 6 failed: the census, forced `gather`, `manifest` and `manifest-refused`, and merge `exact-ab-gather` and `exact-ab-manifest-refused`. **MF3** (`rpartition` restored) → **KILLED**, 2 failed: the device node and the predicate unit. **MF4** (`cleaned = item.name` removed) → **KILLED** by the case-variant node. **MF5** (`placed.unlink()` removed) → **KILLED**, 3 failed: the census and both `exact` merge arms. |
| LED .50 sweep: `git diff -U0 -- s19_app/` searched for added `resolve(` or placement calls | 0 added `.resolve()`; 0 new placement calls. The 3 copies and the gather still pass `workarea_root=self.workarea`. ✓ |
| Evidence: `devflow-evidence.py --root . --check` on all 36 transcripts | The 32 digests in the packet match disk. The 4 files without a digest (`green-01`, `green-03`, `green-fix1-save-guards-iter1` and `-iter2`) are declared in the packet as superseded and kept unhashed. ✓ |
| V56: claimed figures read against the cited bytes | 27 ✓ · 1 ✓ · 150 + 2 failed ✓ (the 2 failures in `reverse-census-fix1-1.txt` are the two pre-re-pin nodes; `repin-b99-staging.txt` shows them passing, 2 passed) · 132 + 1 xfailed ✓ · 116 ✓ · 75 ✓ · 85 ✓ · RED 14 failed / 13 passed ✓ · each `mut-fix1-*` transcript fails ✓ |
| Transcript headers | Every `*-fix1*` header carries `PYTHONPATH=<worktree> (NO_COLOR unset)` and the tree. ✓ |
| CRLF | `app.py` 13987/13987, `workspace.py` 1945/1945, `test_b99_staging.py` 2277/2277. ✓ |

## Closure table: round-1 findings

| id | State | How it was resolved (re-read on the diff) |
|---|---|---|
| **F1** (HIGH) | **CLOSED** | `_abort_save` (`app.py:8112-8151`) restores `_variant_set`, `_report_filter_path`, `current_file.variant_id`, `current_project` and `current_project_dir` from the snapshot taken right after `mkdir` (`:8359-8365`). Every post-creation exit calls it (`:8382`, `:8401`, `:8412`, `:8510`, `:8545`, `:8556`, `:8579`). The `Saved project to …` line moved after `manifest_ok` (`:8518-8526`). The forced-failure arms now assert the app state, and the `manifest-refused` stage is new. Verified by my probe and by MF1 (6 nodes go RED). |
| **F2** (HIGH, record) | **CLOSED** | The §2 row now reads `HLR-164 (registry hygiene for the Inc 2 test file)`, and the 4 rows that §2 lists all carry a Kind from the closed set and a real id. **But** §2 omits a touched file → R2-2. |
| F3 | CLOSED | `workspace.py:1766-1774`: `folded.partition(".")[0].rstrip(" .")`; the digit is limited to `0`–`9` after the `¹²³` fold. Raw arms added for the multi-dot and trailing-space names, plus a predicate unit arm. MF3 kills both. |
| F4 | CLOSED per LED .52(a) | `app.py:8278-8284`: when a case variant matches the open project, the save adopts `item.name`. A case-only match against ANOTHER project is still refused (new arm). MF4 kills the case-variant node. |
| F5 | **PARTLY CLOSED** | Placed data, MAC and A2L files are unlinked unless their name existed before the save (`app.py:8144-8150`, `:8377`); MF5 kills that. The files the gather places are not covered → R2-1. |
| F6 | CLOSED | `test_tc_b100_04_empty_names_refused`; M6 and M7 both killed. The supersession claim is corrected. |
| F7 | CLOSED per LED .52(c) | The AT builds `prg` and `ab` by real saves. It opens P2 with rail key `1`, then clicks `#ws_load_project_button`, the row and `#project_ok`; that is the documented drive from `test_b99_load_project`. It waits for `Loaded project 'prg'`, then refuses `a b` naming `ab`, and `ab`'s digest is unchanged. §6 is rewritten. |
| F8 | CLOSED | The name comparison now comes first (`app.py:8259`). Only the matching folder is listed inside, under `except OSError` (`:8265-8275`). The `icacls` deny-read arm passes (in my 30). Residue: the outer `self.workarea.iterdir()` is still unguarded, but a work area the app cannot list breaks everything else too, so this is not a finding. |
| F9 | CLOSED | Folder-list oracle added; the phantom `sPlItS` folder dropped. |
| F10 | CLOSED | 32 hashed, 4 declared superseded; environment lines in the headers; behavioural RED `red-fix1` (14 failed / 13 passed); `HANDOFF.md` is still at the root, for the orchestrator to move. |
| F11 | CLOSED (note) | Recorded in §5 as an Inc 11 dependency. |

**The two NEW re-pins in `tests/test_b99_staging.py` are justified. Neither hides a regression.**
- `test_at_b99_05…`: the newest painted line changes from `Project saved + manifest verified` to `Saved project to …`. This is the direct effect of the status move that F1 asked for. The re-pin is stronger, not weaker: it now also asserts that the manifest-verify line is painted.
- `test_tc_b99_13…`: `_abort_save` joins the LLR-155.3 unlink allow-list. LED .52(b) requires the removal. Each unlink is limited to a path this call placed whose name did not exist before the save, and the same file's census pins the allow-list, so a new unlink site elsewhere still fails.
- A side effect worth a look: see R2-5.

## New findings: round 2

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **R2-1** | **HIGH** | `app.py:8484-8493` (the gather), `:8144-8150` (`_abort_save` unlinks only `placed_paths`), `:8366`, `:8377`; packet §5 bullet 2; the docstring of `test_tc_b100_07_failed_merge_removes_placed_files` | **A failed save into an existing project still leaves the gather's copies behind.** `placed_paths` records only the 3 `copy_into_workarea` results. `gather_project_artifacts` copies change and check documents into `<project>\patches\`, `checks\` and `templates\` before the manifest write. When the manifest is refused, or an `OSError` hits the manifest, the labels or the file refresh, those copies survive, including the home folders the gather created. LED .52(b) is explicit: "removes every file it placed during that save, including in a folder that already existed"; only the merge **carry** of the `gathered` key stays at 8a. Packet §5 and the merge-arm docstring both claim the target's file set is "exactly as before". Their arms pass only because the gather has nothing to copy in them, so they give false confidence here. The leftover copy is not recorded in `project.json`, so the next load can raise it as a `not recorded` problem. | Probe `gather_copy_left_after_failed_merge`: **`ab` after = `['a.s19', 'patches', 'patches\hotfix.json']`**, against `['a.s19']` before. | Take the pre-save snapshot as the RECURSIVE set of files and folders under `project_dir`, relative to it, not just its top-level names. On abort, unlink every file absent from that snapshot, then remove every folder absent from it, deepest first, when empty. That covers the copies, the MAC and A2L files and the gather alike, and `placed_paths` can go. Keep the byte-identical reuse rule: a reused file has a pre-existing path, so it is kept. Add a merge arm with a gathered composition document (`batch=("hotfix.json",)`) at the `manifest-refused` stage, asserting the tree is unchanged by both files and folders. It must be RED first with the current `_abort_save`. |
| **R2-2** | **HIGH** (record; same class as F2) | `increment-002.md` §2 | **`tests/test_b99_staging.py` is touched but has no row in §2.** It carries 2 re-pins, and the count table still says "Test files 2". The reverse trace for that file is therefore missing; it is recorded only in §4's re-pin list. This is the defect class Inc 1 corrected after its gate (`cdd2ea5`). | `git status`: ` M tests/test_b99_staging.py`; §2 has 4 rows. | Add the row `tests/test_b99_staging.py · test · LLR-164.4 · LLR-155.3 · (LED .52(b)) · 2 re-pins: AT-B99-05 status order, the LLR-155.3 allow-list gains _abort_save`, and set the test-file count to 3. |
| R2-3 | MINOR | `app.py:8518-8530` | The steps after the commit (the success status, `current_project`, `update_project_labels()`, `refresh_files()`) are inside the rollback `try`. If any of them raised `OSError` after `project.json` was written, `_abort_save` would unlink the new variant while the new `project.json` still lists it, leaving a manifest that names a missing file. I did not find a raising path; this is from reading the code. | code read | Move those 4 statements into a `try … else:` block, or after the `try`, so that an error once the save is committed is never rolled back. |
| R2-4 | MINOR | `tests/test_b100_save_guards.py:718` | The census accepts `_remove_created_project_dir` as a rollback (`_ABORT_HELPERS`, "for a transitional exit"). A future exit that only removes the folder, restoring no state and leaving placed files, would pass the census. Today the behavioural arms still catch it. | code read | Accept only `_abort_save` for post-creation exits in `_handle_save_dialog`. |
| R2-5 | MINOR (UX) | `app.py:8496-8526` | Because the success line now paints after the verify result, a manifest **verify MISMATCH** (LLR-004.2, reported but not a failure) is no longer the newest status line. `Saved project to …` follows it. The mismatch still raises a notification (`_surface_manifest_verify_result`) and stays in the 4-line log. | code read | Route to `ux-reviewer`: is the toast enough, or should the success line carry `(manifest MISMATCH)` when the verify fails? |

## Verdict

**approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: R2-1, R2-2`** (2 HIGH open: R2-1 in the code, R2-2 in the record). F1 and F2 are discharged by re-read. F3–F11 are closed, apart from F5's gather remainder, which is carried as R2-1. R2-3, R2-4 and R2-5 are MINOR notes.

## §4b `Independent review` cell (round 2, for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: R2-1, R2-2** (2 HIGH, 0 MAJOR, 3 MINOR open) · How the round-1 HIGHs were resolved:
- **F1:** the one `_abort_save` rollback restores the variant set, the current variant, the report filter and the current project, and the success line now paints after the manifest. Re-read on the diff, my probe re-run (state equal before and after), MF1 kills 6 nodes.
- **F2:** the trace is now `HLR-164`.

Still open:
- **R2-1:** a failed save into an existing project leaves the gather's copies (probe: `ab\patches\hotfix.json` survives a refused manifest), against LED .52(b).
- **R2-2:** §2 has no row for the touched `tests/test_b99_staging.py`.

Each is discharged only when a re-read of the applied fix shows a recursive pre-save snapshot rollback, with a gathered-document merge arm that is RED first (R2-1), and the added §2 row (R2-2).

## Hand-offs (round 2)

- `security-reviewer`: none new. F3 and SEC2-2 were verified by probe and by MF3.
- `ux-reviewer`: R2-5.
- Orchestrator: move `HANDOFF.md` from the worktree root into `kimi/` (as Inc 1 did).

---

# Round 3: re-read of corrective pass 2

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1 and 2. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2` at `2edfee2`, with Inc 2 and fix passes 1 and 2 uncommitted. `app.py` sha256 `52b5f9495107…` and `workspace.py` `d2137e1d5b5d…` both equal `pre-mutation-hashes-fix2.txt`. |
| Inputs | `kimi/BRIEF-inc-2-fix2.md`; `HANDOFF.md` §"Fix pass 2"; packet §1, §2, §4, §6; `evidence/inc-2/` (54 files, 50 hashed). |
| Interpreter proof | `…\scratchpad\fix2\s19_app\__init__.py`. That scratch copy holds `git archive 2edfee2` plus the 5 changed files, with hashes equal to the worktree. `NO_COLOR` was unset. The worktree was never edited. |
| **Verdict** | **approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: R3-1`** (1 HIGH). **R2-1 and R2-2 are discharged by re-read.** R2-3, R2-4 and R2-5 are closed. The new HIGH, R3-1, is in the same rollback: it walks INTO junctions that already exist in the project, and it deleted a file outside the work area (executed probe). |

## What I executed in round 3 (evidence state: `executed`)

| Run | Result |
|---|---|
| GREEN on the scratch copy of the fix-pass-2 tree: `test_b100_save_guards.py` (31, ATs included) + the A-09 node + the 2 re-pinned `test_b99_staging.py` nodes + `test_tui_report_seam.py` | **62 passed** (371 s) |
| The R2-1 probe re-run (`scratchpad\fix2\tests\test_zz_review_r3.py`). `ab` exists and is not open, the payload has `batch=("hotfix.json",)`, `ab` is typed exactly, and the manifest is refused. | `could not save`. Tree before `['a.s19']`, after `['a.s19']`, **equal**. ✓ |
| The security trap: a pre-existing **byte-identical** `ab\patches\hotfix.json` | before = after = `['a.s19', 'patches', 'patches/hotfix.json']`. **The file survives.** ✓ |
| The trap with **different** pre-existing content (`{"v": 0}`) | Tree unchanged (the gather's `hotfix_1.json` was removed); the original content `{"v": 0}` is kept. ✓ |
| **A junction that already exists inside the project**: `ab\ext` → `<tmp>\victim` (outside the work area), which holds `keep.txt`. The gather is patched to stand in for another program that writes `victim\user-work.txt` during the save, and then fails with `OSError`. | Status `could not save`. **Victim after: `['keep.txt']`. `user-work.txt` was DELETED by the rollback**, outside the work area. → R3-1 |
| A junction cycle inside the project: `ab\loop` → `ab` | Every save into `ab` fails. The snapshot's `rglob` recurses `loop\loop\…` until `FileNotFoundError [WinError 3]`. The status shows the `could not save` tokens followed by a path of about 260 characters. Nothing is deleted, because a failed snapshot skips the removal; the project simply can no longer be saved into. → R3-1 (same cause) |
| Rollback mutants on the scratch copy, run against the 15 TC-B100-07 nodes, with the hash restored to `52b5f949…` after each | **MR1** (the snapshot reduced to the top level, `iterdir`) → **KILLED** (`merge-gathered-reused`). **MR2** (the `if rel in preexisting_paths: continue` guard removed) → **KILLED**, 5 failed. **MR3** (sorted shallowest first, not deepest first) → **KILLED** (`merge-gathered`: `patches/` stays). **MR4** (the R2-5 re-paint removed) → **KILLED** (the mismatch node). **MR6** (the `_variant_set` restore removed) → **KILLED**, 6 failed, the census included. |
| LED .50 sweep of the fix-pass-2 diff | 0 added `.resolve()`; no placement call added or changed; `workarea_root=self.workarea` kept on every placement and on the gather. ✓ No Inc 1 regression. |
| Evidence: `devflow-evidence.py --check` on all 54 files | The 50 digests in the packet match disk. The 4 files without a digest are the ones already declared superseded. ✓ |
| CRLF | `app.py` 14038/14038. ✓ |

## Closure table: round-2 findings

| id | State | How it was resolved (re-read on the diff) |
|---|---|---|
| **R2-1** (HIGH) | **CLOSED** | `_project_tree_snapshot` (`app.py:8112-8123`) records every file and folder as a relative POSIX path before any placement (`:8415`). `_abort_save` (`:8125-8183`) removes only paths absent from that set, deepest first, and removes a folder only when it is empty. `placed_paths` and the bare-name set are gone. New arms: `merge-gathered`, `merge-gathered-reused` and `fresh-gathered`. Verified by my probe and by MR1, MR2 and MR3. Note: the walk itself causes R3-1. |
| **R2-2** (HIGH, record) | **CLOSED** | §2 now has the row `tests/test_b99_staging.py · test · LLR-164.4 · LLR-155.3`, with both re-pins named, and the test-file count is 3. |
| R2-3 | CLOSED | The committed block (the success line, the MISMATCH re-paint, `current_project` / `_dir`, labels, refresh) now runs after the `try`/`except` chain (`:8603-8627`), outside the rollback. |
| R2-4 | CLOSED | `_ABORT_HELPERS = {"_abort_save"}` (test `:761`). The census still requires `_abort_save` to restore `_variant_set`. MR6 turns the census RED. |
| R2-5 | CLOSED | `_write_and_verify_manifest` records `_last_manifest_verify_result`. The handler re-paints `Manifest verify MISMATCH` after `Saved project to …` (`:8612-8621`). The new arm asserts `messages[-1]`; MR4 kills it. |

## New findings: round 3

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **R3-1** | **HIGH** | `app.py:8120-8123` (`project_dir.rglob("*")` in the snapshot) and `:8166-8181` (`project_dir.rglob("*")` in the removal) | **The rollback follows junctions inside an existing project, so it can delete files outside the work area.** On Python 3.11, `Path.rglob` skips symlinks but descends into NTFS junctions: `os.DirEntry.is_symlink()` is False for a junction, and `is_junction` only arrives in 3.12. Both walks therefore enumerate the junction's TARGET. During a failed save, any file that appears in that target between the snapshot and the abort is unlinked, along with any folder that is new and empty. That breaks the rule the whole batch keeps since Inc 1 and LED .50: never follow a reparse point, and never write or delete outside this work area. The same cause has two smaller effects. A junction cycle inside a project (`ab\loop` → `ab`) makes the snapshot fail, so every save into that project is refused with a path of about 260 characters in the status. A junction to a large tree is walked in full on every save into that project. | Probe `rollback_deletes_through_junction`: `victim\user-work.txt`, written by "another program" during the save, is **deleted**; the victim goes from `['keep.txt', 'user-work.txt']` to `['keep.txt']`. Probe `junction_cycle_inside_project`: `could not save — [WinError 3] … ab\loop\loop\…`. | Use ONE non-following walker for both the snapshot and the removal. It descends only into real directories (`child.is_dir() and not _is_reparse_point(child)`), records a reparse point as a leaf path, and never descends into one. In the removal, never unlink or `rmdir` a path the snapshot recorded (already true), and never descend into a reparse point. Add a Windows-only arm with `b100_links`: a junction inside `ab` to an outside folder, a forced failure that writes a file into the target first, and the target file surviving. It must be RED first with the current `rglob`. Add a cycle arm: `ab\loop` → `ab` and an exact-name merge saves. Route to `security-reviewer`. |
| R3-2 | MINOR | `app.py:8712`, `:8743`, `:8616` | `_last_manifest_verify_result` is first assigned inside `_write_and_verify_manifest`, not in `__init__`. It works, because the handler always calls the writer before it reads the attribute, but it breaks the class's convention that instance state is declared up front. | code read | Initialise `self._last_manifest_verify_result = None` in `__init__`, next to `_variant_set`. |

## Verdict

**approve-with-fixes.** Recorded token: **`BLOCK — BLOCK-UNTIL: R3-1`** (1 HIGH open). R2-1 and R2-2 are discharged by re-read; R2-3, R2-4 and R2-5 are closed; R3-2 is MINOR. Earlier MINOR notes still stand as recorded (`HANDOFF.md` location).

## §4b `Independent review` cell (round 3, for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: R3-1** (1 HIGH, 0 MAJOR, 1 MINOR open) · How every earlier HIGH was resolved:
- **F1:** the one `_abort_save` rollback restores the app state, and the success line paints after the manifest. Re-read; probe; MF1 and MR6 kill it.
- **F2:** the trace is `HLR-164`.
- **R2-1:** a recursive relative-path snapshot drives the rollback, which removes only new paths, deepest first, and keeps pre-existing ones. Re-read; the R2-1 probe and both trap probes are clean; MR1, MR2 and MR3 kill it.
- **R2-2:** §2 now has the `tests/test_b99_staging.py` row.

Still open:
- **R3-1:** the snapshot and removal walks use `rglob`, which on Python 3.11 descends into NTFS junctions. The rollback deleted a file outside the work area (`victim\user-work.txt`, executed probe), and a junction cycle blocks every save into that project.

It is discharged only when a re-read of the applied fix shows one non-following walker, plus a RED-first junction arm and a cycle arm.

## Hand-offs (round 3)

- `security-reviewer`: R3-1. It is a deletion through a reparse point, the reverse of the S-02 class, and it reaches outside the work area.
- Orchestrator: `HANDOFF.md` is still at the worktree root.

---

# Round 4: bounded re-read of fix pass 3 (R3-1, R3-2 only)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1–3. I did not write the fix. |
| Scope | BOUNDED by the operator at the iteration cap: the fixes for R3-1 and R3-2, plus a check that R2-1 has not regressed. Anything new beyond those would stop the increment for a redesign. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2`, fix pass 3 uncommitted. `app.py` sha256 `fee2d17a6876…` and `workspace.py` `2f6dbdb4cf04…` both equal `pre-mutation-hashes-fix3.txt`. |
| Interpreter proof | `…\scratchpad\fix3\s19_app\__init__.py`. That scratch copy holds `git archive 2edfee2` plus the 5 changed files, with identical hashes. `NO_COLOR` was unset. The worktree was never edited. |
| **Verdict** | **PASS-WITH-NOTES.** 0 HIGH, 0 MAJOR open. **R3-1 is discharged by re-read and by probe.** R3-2 is closed. R2-1 has not regressed. No new finding. |

## What I executed in round 4 (evidence state: `executed`)

| Run | Result |
|---|---|
| R3-1 probe `rollback_deletes_through_junction`. A junction `ab\ext` → `<tmp>\victim` sits outside the work area. A concurrent writer drops `victim\user-work.txt`, then the save fails. | **Victim after: `['keep.txt', 'user-work.txt']`. The outside file SURVIVES.** (Round 3: it was deleted.) |
| A junction-loop project: `ab\loop` → `ab`, exact-name merge, nothing forced | **`Saved project to …\ab`**. Tree `['a.s19', 'firmware.s19', 'loop@', 'project.json']`. The loop is kept, there is no `[WinError 3]`, and the save is no longer blocked. |
| The same junction loop with a refused manifest | Tree before = after `['a.s19', 'loop@']`. |
| R2-1 regression check (my R2-1 probe and both trap probes) | R2-1: before = after `['a.s19']`. Identical pre-existing `patches/hotfix.json`: it survives. Different pre-existing content (`{"v": 0}`): kept, and the gather's `hotfix_1.json` is removed. ✓ |
| Walker mutants on the scratch copy, run against the 18 TC-B100-07 nodes, with both hashes restored after each | **W1** (the `_is_reparse_point` re-check dropped, so junctions are followed) → **KILLED**: `rollback_never_touches_junction_target` + `walk_tree_no_links_yields_reparse_point_as_leaf`. **W3** (the removal walk reverted to `rglob` while the snapshot keeps the walker) → **KILLED**: `rollback_never_touches_junction_target`. **W4** (no descent into sub-folders) → **KILLED**: `failed_save_removes_every_placed_path[merge-gathered]` + the walker unit arm. |
| GREEN on the fix-pass-3 tree: `test_b100_save_guards.py` (34, ATs included) + the A-09 node + the 2 re-pinned `test_b99_staging.py` nodes | **37 passed** (284 s). The merge-gathered arms are in that count. |
| LED .50 sweep | 0 added `.resolve()`. `workspace.py` adds only `walk_tree_no_links` and the `Iterator` import beyond the earlier Inc 2 changes. Placements are unchanged. ✓ |
| Evidence and CRLF | The 69 digests in the packet match disk; the 4 files without a digest are the ones already declared superseded. `app.py` 14050/14050 and `workspace.py` 2002/2002 CRLF. ✓ |

## Closure table: round-3 findings

| id | State | How it was resolved (re-read on the diff) |
|---|---|---|
| **R3-1** (HIGH) | **CLOSED** | `walk_tree_no_links` (`workspace.py:255-309`) walks with an explicit stack and `os.scandir`. It pushes a child only when `entry.is_dir(follow_symlinks=False) and not _is_reparse_point(child)`, so a symlink or junction is yielded as a leaf and never entered. A folder that cannot be listed is skipped. Both `_project_tree_snapshot` (`app.py:8130`) and the removal walk in `_abort_save` (`:8180`) use it; `rglob` is gone from the rollback. A pre-existing junction is in the snapshot, so it is never removed, and its target is never walked. My through-junction probe and the loop probe are clean, and W1, W3 and W4 are killed. One note: W1 alone does not turn the loop arm RED, because the walker swallows the over-long-path `OSError`. The unit arm catches it, so this is not a finding. |
| R3-2 (MINOR) | **CLOSED** | `self._last_manifest_verify_result: Optional[ManifestVerifyResult] = None` is now set in `__init__` (`app.py:1641`). |

## Verdict

**PASS-WITH-NOTES.** 0 HIGH, 0 MAJOR open in my lane. Every HIGH of rounds 1–3 has been applied and re-read on the diff. The one remaining note is housekeeping for the orchestrator: move `HANDOFF.md` from the worktree root into `kimi/`.

## §4b `Independent review` cell (final, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR open; note: move `HANDOFF.md` into `kimi/`) · Every HIGH was resolved and re-read on the diff:
- **F1** (round 1; the app state pointed at the deleted folder after a failed save): the one `_abort_save` rollback restores the state, and the success line paints after the manifest. Probe re-run; MF1 and MR6 killed.
- **F2** (round 1, record): the trace is now `HLR-164`.
- **R2-1** (round 2; the gather's copies survived a failed merge): a recursive relative-path snapshot drives the rollback, which removes only new paths, deepest first. The probe and both trap probes are clean; MR1, MR2 and MR3 killed.
- **R2-2** (round 2, record): §2 now has the `tests/test_b99_staging.py` row.
- **R3-1** (round 3; the rollback deleted through a junction outside the work area): the one non-following `walk_tree_no_links` is used by both the snapshot and the removal. The outside file survives, a junction-loop project saves, and W1, W3 and W4 are killed.

37 passed on the fix-pass-3 tree (`review-increment-002.md` §Round 4).

---

# Round 5: re-read of the rollback redesign (LED .53, "Lista exacta")

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1–4. I did not write the redesign. |
| Why this round | Security found SEC2-5 (MAJOR): an incomplete snapshot made the rollback delete pre-existing user files. SEC2-6 is a concurrent writer's file deleted the same way. The operator stopped the increment and ruled "Lista exacta" (LED .53, main `4a4533b`): a failed save removes exactly what it created. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2`, uncommitted. `app.py` sha256 `fcb1bf400645…`, `workspace.py` `8ef1763e180c…` and `services/project_gather_service.py` `c2d8cc2864a1…`, all equal to `restore-fix4.txt`. |
| Inputs | `kimi/BRIEF-inc-2-fix4.md`; `HANDOFF.md` §"Redesign (LED .53)"; packet §1, §2, §4, §5, §6; `evidence/inc-2/` (82 files, 78 hashed). |
| Interpreter proof | `…\scratchpad\fix4\s19_app\__init__.py`. That scratch copy holds `git archive 2edfee2` plus the 6 changed files, with identical hashes. `NO_COLOR` was unset. The worktree was never edited. |
| **Verdict** | **PASS-WITH-NOTES.** 0 HIGH. **1 MAJOR open (R5-1)**: a recorded note that does not block, the same way N1 was handled in Inc 1 round 2. It must be fixed in this increment (a one-line fix in the gather) or scheduled in the ledger. 1 MINOR (R5-2). Every earlier probe still passes on the redesign. |

## The design, as I re-read it

- **Placements** (`app.py:8445-8471`): the image, the MAC and the A2L now go through `place_into_workarea(..., workarea_root=self.workarea)`. Only results with `reused == False` enter `placed_files`.
- **Gather** (`project_gather_service.py:588-612`): `GatherOutcome.written` gets `destination` only when `_gather_copy` returns `copied=True`. A reused byte-identical sibling returns `(False, sibling)` and never appears. `created_homes` gets the home only when it did not exist before the copy and the copy wrote. The app extends its two lists with these (`app.py:8528-8529`).
- **Rollback** (`_abort_save`, `app.py:8104-8167`):
  - restores the app state, unchanged from LED .52(b);
  - unlinks exactly `placed_files`;
  - `rmdir`s `created_dirs`, plus the project folder when this call created it, deepest first and only while empty;
  - walks no folder and keeps no snapshot. `_project_tree_snapshot` and `_remove_created_project_dir` (with its `rmtree`) are gone.
- **The walker** stays only for Inc 8b's save-as.

This is simpler than rounds 3–4, and it is correct by construction for SEC2-5 and SEC2-6: a path that was never recorded can never be deleted. The manifest write that would leave a committed `project.json` behind cannot raise after it has written. `write_project_manifest` stages the file, moves it in place with an atomic `os.replace`, and returns findings instead of raising. `verify_written_manifest` is collect-don't-abort. So no failure exit exists after `project.json` is on disk.

## What I executed in round 5 (evidence state: `executed`)

| Run | Result |
|---|---|
| GREEN on the redesign tree: `test_b100_save_guards.py` (36, ATs included) + the A-09 node + all of `test_b99_staging.py` + all of `test_project_gather.py` (the reverse census of `GatherOutcome` / `gather_project_artifacts`, along with `test_b100_reuse.py`, which is in Kimi's census chunk) | **83 passed** (379 s) |
| Earlier probes re-run on the redesign (`scratchpad\fix4\tests\test_zz_review_r3.py`, `test_zz_review_r2.py`) | **R2-1 merge-gathered:** tree before = after `['a.s19']`. **Trap, identical pre-existing `patches/hotfix.json`:** survives. **Trap, different content:** `{"v": 0}` kept and the tree unchanged. **Junction `ab\ext` → outside:** tree unchanged, victim untouched. **Through-junction with a concurrent writer:** `user-work.txt` **survives**. **Junction loop, refused manifest:** tree unchanged. **Junction loop, normal save:** `Saved project to …`. **F1 state:** before = after `(['…\ab\a.s19'], None, 'ab')`. **F4:** `A B` saves into `ab` under its on-disk name. All pass. |
| **New probe: the gather home is created, then its copy fails, then the save fails** (the disk-full shape). The gather's `copy_into_workarea` is patched to `mkdir` the home and then raise `OSError(28, "No space left on device")`, which is what happens when the staging copy runs out of disk after the placement's `mkdir` (`workspace.py:1150` then `:1170`). The manifest is then refused. Target: a fresh folder `freshp`. | Status `could not save`. **`freshp` is LEFT on disk, holding an empty `patches\`.** → R5-1 |
| Mutants on the created-list logic, run on the scratch copy against the 20 TC-B100-07 nodes, with both hashes restored after each | **Ma** (reused placements recorded too) → **KILLED** (`open-case-AB-gather`). **Mc** (`written` includes reused files) → **KILLED** (`merge-gathered-reused`). **Md** (`created_homes` not consumed) → **KILLED** (`merge-gathered`, `fresh-gathered`). **Me** (the created project folder not listed for removal) → **KILLED**, 7 failed: all 6 forced stages + `fresh-gathered`. **Mg** (`written` not consumed) → **KILLED**, 2 failed. **Mf** (the `home_preexisted` guard dropped, so pre-existing homes are listed as created) → **SURVIVED**, 20 passed. → R5-2 |
| Kimi's mutants (a), (b) and (c), read from the cited transcripts | (a) 1 failed, (b) 2 failed (R7 + R8), (c) 1 failed. Each is consistent with my Ma and Mc. |
| Census | Still requires every post-creation exit to go through `_abort_save` only (`_ABORT_HELPERS = {"_abort_save"}`). `_abort_save` must restore `_variant_set`, `unlink`, and now `rmdir` (re-pinned from `_remove_created_project_dir`, which no longer exists). Me kills the 6 behavioural arms; the census rule is unchanged. ✓ |
| The two re-pins in `test_b100_save_guards.py` | (1) The `copies` stage now patches `app_module.place_into_workarea`. **Justified**: the save body no longer calls `copy_into_workarea`, so patching the old seam would make the stage a silent no-op. (2) The census's folder-removal pin becomes "`_abort_save` contains `rmdir`". **Justified**: the `rmtree` helper is gone by design. "Remove only while empty" is LED .53's rule, and Me shows the behavioural arms still pin that the created folder disappears. |
| LED .50 sweep | 0 added `.resolve()`. The three new `place_into_workarea` calls keep `workarea_root=self.workarea`, and the gather keeps its root. ✓ |
| Packet | §2: 3/4 SOURCE files. `project_gather_service.py` row: `source · LLR-164.4 (LED .53) · LLR-138.4` ✓ (V59). The 6 rows all use closed-set Kinds with real ids. V56: 36 ✓, 2 failed (RED, cited) ✓, 369 + 1 xfailed ✓, 31 ✓, 75 ✓, 85 ✓, and 436 = 369 + 31 + 36 ✓. Evidence: the 78 digests match disk; the 4 without a digest are the ones already declared superseded. CRLF ✓ (per the handoff counts; `app.py` checked). |

## Closure

| id | State |
|---|---|
| R3-1, R3-2 (round 4) | Still closed. The walker is no longer in the rollback at all, which is stronger: there is nothing to follow. The junction probes still pass. |
| SEC2-5 / SEC2-6 (security, LED .53) | Closed by construction in my lane: no recorded path means no deletion. R7 and R8 are RED first (`red-fix4-r7-r8.txt`) and GREEN now. The security verdict itself is `security-reviewer`'s. |
| F1, R2-1, F4 | Not regressed (probes above). |

## New findings: round 5

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| R5-1 | **MAJOR** | `project_gather_service.py:588-612` (`created_homes` appended only `if copied`); `workspace.py:1150` (the placement `mkdir`s the home before staging) | **A home the gather created stays unrecorded when its copy then fails, so a failed fresh save leaves its folder behind.** `place_into_workarea` creates the home, then the staging copy can fail (disk full, the source vanishing): the gather collects an issue and continues. When the save then fails too, which is likely under the same disk-full condition, the empty `patches\` is not in `created_homes`. The project folder is therefore not empty and its `rmdir` fails. The result is a leftover `freshp\patches\`, which goes against HLR-164's "every refused or failed save shall leave the work area as it was" and TC-B100-07's "0 folders left". It is only empty folders, with no data loss, which is why it is MAJOR rather than HIGH. It is new with the redesign: the round-4 `rmtree` of a created project folder covered it. | Probe `r5_gather_home_created_then_copy_fails`: `freshp tree: ['patches']` after `could not save`. | Record the home from whether it now exists, not from whether the copy wrote: after the `try`/`except`, on both paths, `if not home_preexisted and home_dir.is_dir() and home_dir not in outcome.created_homes: outcome.created_homes.append(home_dir)`. This is safe because the rollback removes a folder only while it is empty. Add an arm: the gather copy fails after the `mkdir` on a fresh save, then the save fails, and the folder must be gone. |
| R5-2 | MINOR | `project_gather_service.py:610`; tests | No arm discriminates the `home_preexisted` guard: mutant Mf survives. If the guard regressed, a pre-existing EMPTY `patches\` in an existing project would be removed by a failed save. That alters the work area, but only by deleting an empty folder. | Mf: 20 passed | Add an arm: `ab\patches\` exists and is empty, a gathered document is written there, the save fails, and `ab\patches\` must still exist. |

## Verdict

**PASS-WITH-NOTES.** 0 HIGH open. R5-1 (MAJOR) is a recorded note that does not block, the same way N1 was handled in Inc 1 round 2; it must be fixed in this increment or scheduled in the ledger before the gate. R5-2 is MINOR. Every HIGH from rounds 1–4 stays resolved under the redesign. The orchestrator note stands: move `HANDOFF.md` into `kimi/`.

## §4b `Independent review` cell (round 5, final, for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; open: **R5-1 MAJOR**, a gather home created before a failed copy stays unrecorded and leaves a fresh folder behind (fix it here or schedule it by ledger), and R5-2 MINOR; note: `HANDOFF.md` into `kimi/`) · Every HIGH was resolved and re-read on the diff:
- **F1:** the one `_abort_save` restores the app state.
- **F2:** the trace is `HLR-164`.
- **R2-1, now under the LED .53 redesign:** the exact created list (non-reused placements, `GatherOutcome.written`, created homes) is removed, and empty created folders go deepest first. The merge-gathered probe is clean.
- **R2-2:** the §2 `test_b99_staging.py` row.
- **R3-1:** no folder walk is left in the rollback; the outside file survives a concurrent write and a junction-loop project saves.

SEC2-5 and SEC2-6 are closed by construction (R7 and R8 RED first, then GREEN). Mutants Ma, Mc, Md, Me and Mg are killed; Mf survives (R5-2). 83 passed on the redesign tree (`review-increment-002.md` §Round 5).

---

# Round 6: re-read of the redesign fix pass (SEC2-7/8/9, R5-1, R5-2)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, the same reviewer as rounds 1–5. I did not write the fix. |
| Tree re-read | worktree `C:\Users\jjgh8\Github\s19_app-b100-inc2`, uncommitted. `app.py` sha256 `e30805c44126…`, `workspace.py` `2ab2ba749fb5…`, `services/project_gather_service.py` `bc8b6eeacac4…`. |
| Inputs | `kimi/BRIEF-inc-2-fix5.md`; `HANDOFF.md` §"Redesign fix pass"; `security-increment-002.md` Round 4 (SEC2-7 HIGH, SEC2-8, SEC2-9); packet §1, §2, §4, §6; `evidence/inc-2/` (105 files, 101 hashed). |
| Interpreter proof | `…\scratchpad\fix5\s19_app\__init__.py`. That scratch copy holds `git archive 2edfee2` plus the 7 changed files, with identical hashes. `NO_COLOR` was unset. The worktree was never edited. |
| **Verdict** | **PASS.** 0 HIGH, 0 MAJOR open. **R5-1 and R5-2 are closed, and Mf now dies.** Two MINOR notes on the record (R6-1, R6-2). |

## What I executed in round 6 (evidence state: `executed`)

| Run | Result |
|---|---|
| GREEN on the fix5 tree: `test_b100_save_guards.py` (43, ATs included) + the A-09 node + all of `test_b99_staging.py` + `test_project_gather.py` + `test_b100_reuse.py` (TC-B100-57 re-pinned) + `test_copy_into_workarea_content_dedup.py` | **130 passed** (549 s). The gather-reuse behaviour (LLR-138.4, TC-B99-13's reuse and drift arms), the `_gather_copy` containment and root-threading arms, and the census all stay green. |
| Every earlier probe re-run (`scratchpad\fix5\tests\test_zz_review_r3.py`, `test_zz_review_r2.py`) | R2-1 merge-gathered: tree unchanged. Identical pre-existing `patches/hotfix.json`: survives. Different content: kept. Junction `ab\ext`: tree unchanged, victim untouched. Through-junction with a concurrent writer: `user-work.txt` survives. Junction loop, refused manifest: tree unchanged. Junction loop, normal save: saved. F1 state: before = after. F4: saves under the on-disk name. All pass. |
| **R5-1 probe** (the gather home `mkdir`ed, then the copy fails with disk full, then the manifest is refused, on a fresh `freshp`) | `freshp` tree: **None**, so no folder is left behind. (Round 5: `['patches']`.) |
| **SEC2-7 probe, two cases**: a pre-existing byte-identical `ab\patches\HOTFIX.json` or `hotfix.JSON`, a gathered `hotfix.json`, then a failed save | Both trees are unchanged, and **the case-variant file survives**. |
| **SEC2-8 probe**: a fresh `freshv` where `verify_written_manifest` raises `OSError` after the write | `freshv exists: False`. |
| **SEC2-9 probe**: a merge into `ab`, whose existing `project.json` carries `custom_key`, where verify raises | `project.json` is **restored byte-identical**; tree `['a.s19', 'project.json']`. |
| Mutants on the scratch copy, run against the 27 TC-B100-07 nodes, with both hashes restored after each | **Mf** (both `home_preexisted` guards → `True`) → **KILLED** (`empty_preexisting_home_survives_failed_save` + `gather_reuse_never_ends_in_written`). **Mf1** (no home recorded on the copy-failure path) → **KILLED** (`gather_home_created_then_copy_fails_no_folder_left`). **M7** (`_gather_copy` returns `copied=True` always, so reused files land in `written`) → **KILLED**, 4 failed: both case-variant arms, `merge-gathered-reused` and the census/unit arm. **M8** (the created `project.json` not added to `placed_files`) → **KILLED** (`failed_verify_leaves_no_folder_fresh`). **M9** (the `os.replace` of the kept manifest removed) → **KILLED** (`failed_verify_restores_previous_manifest`). |
| LED .50 sweep | 0 added `.resolve()`. `_gather_copy` passes the UNRESOLVED home plus the explicit `workarea_root` to `place_into_workarea`, after `_check_home_contained`. ✓ |
| Packet | §2: 3/4 SOURCE files; 7 rows, each with a closed-set Kind and a real id (V59 ✓), including the new `tests/test_b100_reuse.py · test · LLR-163.1` row; test-file count 4. V56: 43 ✓ · 75 ✓ · 85 ✓ · census 38 + 48 + 29 ✓ · each RED and mutant transcript fails ✓. Digests: the 101 recorded in the packet match disk, and the 4 without a digest are the ones declared superseded. CRLF: `app.py` 14116/14116, `workspace.py` 2004/2004, gather service 682/682, `test_b100_reuse.py` 1358/1358 ✓. |

## Design checks the coordinator named

- **"The placement is the sole reuse judge"** (`project_gather_service.py` `_gather_copy`): `_check_home_contained(home, workarea_root)`, then `place_into_workarea(source, home, workarea_root=…)`, then `return not placed.reused, placed.path`. `_same_artifact_name` and the gather's own byte scan are deleted (`grep` finds 0 references in `s19_app/` and `tests/`).
  - **Simple and correct**: there is one rule, `find_identical` (case-folded on Windows, LLR-163.1), so no second rule can disagree with it. That disagreement was SEC2-7.
  - **Behaviour change versus the retired scan**: a case-variant identical file is now reused, which is wanted. A 0-byte or linked sibling is never reused, the placement's own rule; a 0-byte JSON document is not a valid change document anyway.
  - **LLR-138.4** ("skip when an identical destination exists, otherwise the next free name") is preserved, and `test_project_gather.py` and TC-B99-13 are green.
- **TC-B100-57 re-pin** (`test_b100_reuse.py`): the declared byte-identity rules shrink from {the group's R30, `_gather_copy`} to {R30}. The census is **stronger**: any new rule, including one re-added in the gather, fails it. Kimi's `red-fix5-census57.txt` shows the census RED on the old tree ("gather rule unexpected"). This pulls Inc 5's planned conversion of the gather rule into Inc 2 → R6-2.
- **The `on_written` hook** (`app.py` `_write_and_verify_manifest`): it is called once, right after `write_project_manifest` returns a path and before the verify. The closure in the handler appends to `placed_files` (no previous manifest, so SEC2-8) or to `manifest_restores` (a previous manifest, so SEC2-9). That is the minimal shape for this need: the window it covers comes after the write but before the method returns, so a return value could not carry it. Both branches are killed by M8 and M9.
- **The manifest keep and restore** in `_abort_save`: the previous bytes are read before the write, inside the rollback `try`. The restore runs FIRST in `_abort_save`: it writes a staged copy into `_private_stage_dir(self.workarea)`, which is on the same volume, then calls `os.replace`, then removes the stage folder in `finally`, and never raises. ✓ As security noted, `verify_written_manifest` cannot raise today, because it collects problems instead of aborting. So SEC2-8 and SEC2-9 are defence in depth, pinned by monkeypatched arms.

## Closure

| id | State |
|---|---|
| R5-1 (MAJOR) | **CLOSED.** The home is recorded from `not home_preexisted and home_dir.is_dir()` on both the success path and the copy-failure path. Probe clean; Mf1 killed. |
| R5-2 (MINOR) | **CLOSED.** The arm `empty_preexisting_home_survives_failed_save` kills Mf. |
| SEC2-7 / SEC2-8 / SEC2-9 | Closed in my lane (probes and M7, M8, M9). The security verdict is `security-reviewer`'s. |
| F1, R2-1, R3-1, F4 and the junction arms | Not regressed. |

## New findings: round 6

| id | Severity | file:line | Finding | Fix |
|---|---|---|---|---|
| R6-1 | MINOR (record) | `evidence/inc-2/*-fix5*.txt` headers | The fix-pass-5 transcripts' `cmd:` lines dropped the `PYTHONPATH=<worktree> (NO_COLOR unset)` environment line that F10 restored at fix pass 1. `import-proof-fix5.txt` does show `s19_app.__file__` resolving into the worktree, so the runs are attributable. | Restore the environment line in later transcript headers. No re-run is needed. |
| R6-2 | MINOR (plan) | `test_b100_reuse.py` TC-B100-57 docstring; design §5 (Inc 5) | Converting the gather's reuse rule was planned for Inc 5 (review finding N3, recorded in the census's own comment). It has now landed in Inc 2, so Inc 5's plan still lists work that is done. | The orchestrator drops that item from Inc 5's plan or records the move in the ledger. |

## Verdict

**PASS.** 0 HIGH, 0 MAJOR open in my lane. R6-1 and R6-2 are MINOR record and plan notes. The housekeeping note stands: move `HANDOFF.md` into `kimi/`.

## §4b `Independent review` cell (round 6, final, for the orchestrator to write)

`code-reviewer` · **PASS** (0 HIGH, 0 MAJOR open; MINOR notes R6-1, the fix-pass-5 transcript headers lack the environment line, and R6-2, Inc 5's gather-rule item is now done in Inc 2; housekeeping: `HANDOFF.md` into `kimi/`) · Every HIGH and MAJOR was resolved and re-read on the diff:
- **F1:** the one `_abort_save` restores the app state.
- **F2:** the trace is `HLR-164`.
- **R2-1:** under LED .53, the exact created list is removed. Probe clean.
- **R2-2:** the §2 row.
- **R3-1:** no folder walk is left in the rollback. The junction probes are clean.
- **R5-1:** the gather home is recorded on both the success and the failure path. The disk-full probe leaves no folder; Mf1 killed.

R5-2 is closed and Mf is killed. SEC2-7, SEC2-8 and SEC2-9 are pinned by the case-variant, fresh-verify and merge-restore arms, with M7, M8 and M9 killed. 130 passed on the fix5 tree (`review-increment-002.md` §Round 6).
