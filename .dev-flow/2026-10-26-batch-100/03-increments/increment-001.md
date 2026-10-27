# Increment 001 — HLR-163 / LLR-163.1–163.7, LLR-171.4 (guard) · `One placement function, reuse, containment`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `001` |
| Lane (if the batch forked) | `main` · `s19_app/tui/workspace.py · s19_app/tui/segment_split_view.py · s19_app/tui/app.py · s19_app/tui/services/project_gather_service.py` (4 SOURCE files, ⚠ at cap — LED .49) |
| Requirement(s) | `HLR-163 / LLR-163.1–163.7 · LLR-171.4 (guard clause)` |
| Acceptance | `AT-B100-01` · white-box `TC-B100-01 · TC-B100-02 · TC-B100-03 · TC-B100-57 · TC-B100-62 · TC-B100-68` · re-pinned `TC-018 · AT-031b · TC-B99-31` |
| Agent | `software-dev` |
| Date | `2026-10-26` |

---

## 1 · What changed

BLUF: there is now ONE placement function. `place_into_workarea(source, destination, …) ->
PlacementResult(path, reused)` in `s19_app/tui/workspace.py` owns every guard — the source and
destination reparse checks, this-work-area containment (`contained_in_workarea`, LLR-171.4: the
destination must land inside the work area it textually names, with links and junctions refused
BEFORE resolving — the executed S-02 shape), the 256 MiB cap, private staging — then either reuses
the byte-identical candidate `find_identical` finds among `<name>` and every
`<stem>_<digits><suffix>` (one directory listing, size checked before any candidate bytes are
read, links/reparse points/0-byte files never reused, case-folded on Windows) or claims the
lowest free `_<N>` with `O_EXCL` and fills it with `os.replace`. `copy_into_workarea` is now
exactly `return place_into_workarea(...).path`, so all 15 call sites keep their `Path` return and
every guard covers them by construction. `predict_placement(digest_or_bytes, size, destination,
name)` answers where the placement would land — same candidate walk, same free-name walk, no
staging, no claim, nothing written. The Split/Join export takes its `reused`/`wrote` word only
from the `PlacementResult` of the placement it performed (`_export_reuse_target` is gone; the
BIN/`.addr` group keeps requested-names-only placement and derives its word from the placement
outcome). `_sync_loaded_file_to_project` places through `place_into_workarea` and, when
`reused` is true, names the existing variant (`Variant '<id>' already in project '<name>'`)
instead of emitting the added-variant status. The user-visible outcome: repeated loads of an
identical file no longer accumulate `firmware_1`, `firmware_2`, … copies — the work area and the
project keep one file per distinct image, and the status says so.

**Fix pass 1 (code-review corrective pass; discharges review-increment-001 F1–F11 under LED .49).**
The destination guard is now ONE shared helper — `workspace._guarded_destination(destination,
workarea_root=None) -> (resolved_destination, resolved_root)` — used by BOTH placement kinds
(`place_into_workarea` and `place_group_into_workarea`). It takes the work-area root from the
destination **as given, before any resolution**: the nearest `.s19tool/workarea` ancestor of the
unresolved path (compared case-insensitively on Windows, with an 8.3 short-name fallback that
reparse-checks each component before resolving it), or an explicit root an app-level caller passes
— and only then resolves both sides and compares them (`contained_in_workarea`), which is what
refuses a destination that resolves into ANOTHER work area (F2). Every caller passes its
destination UNRESOLVED: the Split/Join export runs `dest_dir` through the guard and hands the same
unresolved `dest_dir` to both placements; Save project's gather (`project_gather_service`, the 4th
SOURCE file, ⚠ at cap per LED .49) routes `_check_home_contained` through the same guard and passes
the unresolved home to `copy_into_workarea`. `predict_placement` now answers in the same resolved
path FORM the placement returns (F4). `place_into_workarea` gained an optional `workarea_root`
parameter (the B100-I14 explicit-root surface; default None preserves the frozen B100-I13 shape for
all 15 wrapper call sites). The LLR-163.1 boundary catalog (upper-case `_2` on Windows, `_1`
deleted beside an identical `_2`, a link candidate, a 0-byte candidate) is now armed, each arm with
a mutant that kills it (F3).

**Fix pass 2 (security-review + code-review round 2; discharges SEC-1 (HIGH) and SEC-2, review
N1–N5 and the F9 nit, under LED .50).**
**App paths stay unresolved.** `current_project_dir` is stored as the path under
`self.workarea`, not `project_dir.resolve()` (`app.py`), and Save project builds its target with no
`.resolve()` — every destination the app hands on still shows any junction under the work area.
**App callers pass the root.** All 9 placement calls in `app.py` (the variant append, the 3 Save
copies, the 2 MAC syncs, the A2L sync, the 2 temp-load copies) pass `workarea_root=self.workarea`,
and the gather (`gather_project_artifacts`) and the Split/Join export (`write_split_join_export`)
thread that root from their app callers through to the guard and every placement;
`copy_into_workarea` and `place_group_into_workarea` gained the keyword (the wrapper's one-line
AST shape is unchanged, and the 15 frozen call sites keep working via the None default). A new AST
census arm pins that every `app.py` placement call names the root. **The derived-root walk reaches
the OUTERMOST anchor** (N1): with no root, `_find_workarea_root` now returns the outermost
`.s19tool/workarea` ancestor (mirrored by the 8.3 short-name fallback), so a junction between this
work area and a NESTED anchor is reparse-checked instead of skipped. **No bare `OSError`** (SEC-2):
an invalid path spelling (WinError 123) raises `WorkareaContainmentError` — the guard wraps both
`resolve()` calls, and both placement kinds (plus the export's home mkdir) wrap the destination
creation, because on Python 3.11 non-strict `resolve()` normalizes textually and the first
filesystem touch is the mkdir. **N5:** the export's group word compares the pre-listing case-folded
on Windows. **F9 nit:** `_reuse_candidate_names` returns `list[str]`. **N4 arms:** the F8
case-insensitive anchor match and the 8.3 short-name fallback are now tested.

**Fix pass 3 (code-review round 3, BOUNDED at the operator's iteration cap; discharges R3-1
(HIGH, the round-3 BLOCK), R3-2 and R3-3 under LED .50; R3-4 routed to the backlog untouched).**
**R3-1 — the junctioned-base export regression is fixed.** `write_split_join_export` no longer
rebinds `workarea_root` to the guard's RESOLVED root (`segment_split_view.py`): the guard's
return is held in a distinct `resolved_root` used only for the staging paths (`stage_worst` and
`_private_stage_dir`), while both placements re-run the guard on the UNRESOLVED `dest_dir` with
the CALLER'S root — so an app whose base folder is reached through a junction (a redirected or
junctioned user folder; `Path.cwd()` keeps that spelling) exports into its work area again, the
behaviour at base and after fix pass 1. New arm: the junctioned-base export with the app root
writes exactly `t_isle.s19` into the real work area (RED side `red-14-r3-1-junctioned-base.txt`
— refused with "traverses a symbolic link", the reviewer's probe shape). **R3-2:** the
`_active_project_dir` fallback returns `self.workarea / self.current_project` with no
`.resolve()` — the last place app code handed out a resolved project path; app paths stay
unresolved end to end (LED .50). **R3-3:** `gather_project_artifacts` takes `workarea_root`
keyword-only with NO default — the default-unsafe API whose `None` derived the root from a
junctioned project's own textual path (probe `r3_gather_projjunction.py` wrote into the victim
work area) is closed at the only boundary the app can reach: omitting the root is a `TypeError`
(new arm `test_tc_b100_62_gather_requires_workarea_root`). The four test callers re-pin to pass
their work area (`test_b99_staging.py` ×2, `test_project_gather.py` ×2). The private seams
`_check_home_contained` / `_gather_copy` keep their `None` derivation — their one no-root
production caller is `scoped_home`, whose own callers (`folder_open_service.py`,
`crc_designer_view.py`) sit outside the LED .50 4-file cap; that threading is the R3-4/backlog
family, recorded in §6.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/workspace.py` | source | LLR-163.1 · LLR-163.2 · LLR-163.7 · LLR-171.4 (guard) · B100-I6 (amended) · B100-I13 · B100-I14 · B100-I22 | `PlacementResult`, `contained_in_workarea`, `_hash_file`, `_reuse_candidate_names`, `_match_identical`, `find_identical`, `_placed_name_candidates`, `place_into_workarea` (optional explicit `workarea_root`, B100-I14), `predict_placement` (resolved path form, F4); `copy_into_workarea` is the one-line wrapper; **`_guarded_destination` — the ONE shared destination guard both placement kinds run** (textual anchor case-folded on Windows + 8.3 short-name fallback, F8; reparse walk before resolving; resolved-pair comparison, F1/F2). **Fix pass 2:** `_find_workarea_root` (and the short-name fallback) return the OUTERMOST anchor so the reparse walk covers a junction before a NESTED anchor (N1, LED .50); SEC-2 wraps both `resolve()` calls and both placements wrap the destination mkdir — an invalid spelling is a containment refusal, never a bare `OSError`; `copy_into_workarea` and `place_group_into_workarea` gain the `workarea_root` keyword (wrapper AST shape unchanged); `_reuse_candidate_names` returns `list[str]` (F9 nit) |
| `s19_app/tui/segment_split_view.py` | source | LLR-163.6 · LLR-160.2 · LLR-171.4 (guard) · B100-I6 (amended) | `_export_reuse_target` deleted; the export pre-checks `dest_dir` through `_guarded_destination` UNRESOLVED and passes the same unresolved `dest_dir` to both placements (F1); the single-file word comes from `PlacementResult.reused`; the group word derives from the placement outcome (`place_group_into_workarea` unchanged, R30). **Fix pass 2:** `write_split_join_export` takes `workarea_root` and threads it to the guard and both placements (SEC-1, LED .50); the group word compares the pre-listing case-folded on Windows (N5); the home mkdir wraps `OSError` into the containment class (SEC-2). **Fix pass 3 (R3-1):** the guard's return is bound to a distinct `resolved_root` (staging paths only); both placements keep the CALLER'S `workarea_root`, so the export writes again when the base folder is reached through a junction |
| `s19_app/tui/app.py` | source | LLR-163.5 · LLR-171.4 (guard) | `_sync_loaded_file_to_project` places through `place_into_workarea`; a reused file names the existing variant, never the added-variant status; the reuse branch logs "Reused variant …", the append branch keeps "Appended variant …" (F9). **Fix pass 2 (LED .50 / SEC-1):** `current_project_dir` is stored UNRESOLVED (the path under `self.workarea`, not `project_dir.resolve()`) and Save project builds its target with no `.resolve()`; all 9 placement calls pass `workarea_root=self.workarea`; the Save gather passes `workarea_root=self.workarea` too; every reader of `current_project_dir` re-validated — no equality relied on the resolved form (comparisons resolve both sides at the comparison point, never at storage). **Fix pass 3 (R3-2):** the `_active_project_dir` fallback drops `.resolve()` — app paths stay unresolved end to end (LED .50) |
| `s19_app/tui/services/project_gather_service.py` | source | LLR-171.4 (guard) · LLR-163.1 (LED .49) | 4/4 ⚠ (LED .49): `_check_home_contained` routes through `_guarded_destination` on the UNRESOLVED home; `_gather_copy` passes the unresolved home to `copy_into_workarea` (F1). Fourth SOURCE file, at cap — LED .49: the gather is a writer that resolved its destination before the guard, and the guard must see that destination unresolved. **Fix pass 2 (LED .50 / SEC-1):** `_check_home_contained`, `_gather_copy` and `gather_project_artifacts` take and thread `workarea_root` to the guard and the placement. **Fix pass 3 (R3-3):** `gather_project_artifacts` takes `workarea_root` keyword-only with NO default — the unsafe `None` derivation is closed at the public boundary (omission → `TypeError`); the private seams keep the `None` derivation for `scoped_home`, whose callers sit outside the 4-file cap (R3-4/backlog family, §6) |
| `tests/test_b100_reuse.py` | test | HLR-163 · LLR-163.1–163.7 · LLR-171.4 | TC-B100-01/02/03/57/62/68 and AT-B100-01 — fix pass 1 adds 10 nodes (24 total); fix pass 2 adds 12 nodes (36 total): the app-placement root census arm (TC-B100-01), the five explicit-root route arms — variant append, Save copies, MAC/A2L syncs, gather, export (TC-B100-62), the nested-anchor arm and its explicit-root half (N1), the SEC-2 invalid-spelling arm, the two F8 arms — upper-case anchor + 8.3 short-name (N4), the N5 group-word case-fold arm (TC-B100-57). **Fix pass 3 adds 2 nodes (38 total):** the junctioned-base export arm (R3-1) and the gather-root `TypeError` arm (R3-3) |
| `tests/support/b100_links.py` | fixture | LLR-171.4 · LLR-163.1 (TC-B100-62 enabler E1) | junction helpers on `_winapi.CreateJunction` (no privilege); non-Windows arms skip with the named reason (PDR C-QA-6). **Fix pass 2:** `short_path_name` wraps `GetShortPathNameW` for the 8.3 short-name arm (N4), skipping with a named reason where the volume carries no 8.3 names |
| `tests/b97_fixtures.py` | test | LLR-171.4 (guard) | comment only: `make_project` documents that `load_project` returns the directory the app holds — stored unresolved per LED .50 (on these tmp bases the spelling is identical either way) |
| `tests/test_unified_write.py` | test | LLR-163.3 | `test_tc018_existing_name_is_dedup_suffixed` re-pinned (two arms: identical reuse; different document dedup-suffixed) |
| `tests/test_tui_patch_editor_v2.py` | test | LLR-163.3 | `test_at031b_two_saves_are_distinct_no_clobber` re-pinned (unchanged-document saves reuse one file; added entry adds a second distinct name) |
| `tests/test_b99_export.py` | test | LLR-163.4 | `test_tc_b99_31_changed_bytes_take_the_next_free_name` re-pinned (third identical export reuses `t_isle_1.s19`, reports `reused`, 2 files) |
| `tests/test_b99_staging.py` | test | LLR-163.1 · LLR-138.1/138.4 | `_FINAL_NAME_ALLOWLIST` re-pinned: `place_into_workarea` added to the workspace.py pin set (B100-I13); fix pass 1 drops `copy_into_workarea` from the set — the wrapper no longer writes (F10), and the TC-B100-01 AST arm pins its shape. **Fix pass 3 re-pin (LED .50, R3-3):** the two `gather_project_artifacts` callers (`test_tc_b99_13_gather_drift_places_next_free_name`, `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`) pass `workarea_root=root` — old (no root, the removed unsafe default) → new (their own work area) |
| `tests/test_project_gather.py` | test | LLR-138.1 · LLR-171.4 (guard) | **Fix pass 3 re-pin (LED .50, R3-3):** the two `gather_project_artifacts` callers (`test_tc699_assignments_referenced_documents_are_gathered`, `test_gather_containment_escape_refuses_without_writing`) pass `workarea_root` — old (no root, the removed unsafe default) → new (their own work area); the containment arm's expectation is unchanged (the outside project refuses against the passed root) |
| `tests/test_id_registry.py` | config | HLR-163 (registry hygiene for the new Inc 1 test files) | `EXPECTED_SCANNED_TEST_FILES` 213 → 215 (measured; two new scanned files) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4 ⚠ at cap** (LED .49: the gather is a writer that resolves before the guard; the guard must see its destination unresolved — the increment cannot be smaller; LED .50 keeps the same 4) |
| Test files | 9 (uncapped; 6 from rounds 1–fix 1 + `tests/b97_fixtures.py` comment + `tests/test_project_gather.py` re-pins + this packet) |
| Doc files | 0 (outside the count) |

---

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>
unset NO_COLOR
python -m pytest -q -p no:cacheprovider tests/test_b100_reuse.py
python -m pytest -q -p no:cacheprovider \
  tests/test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed \
  tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber \
  tests/test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name \
  tests/test_b99_export.py::test_tc_b99_31_bin_pair_placed_under_one_suffix
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | `test_tc_b100_01_wrapper_is_the_one_line_path_return` (AST) · `test_tc_b100_01_one_claim_loop_per_placement_kind` (AST, F7) · `test_tc_b100_57_export_holds_no_byte_identity_rule` (behavioural census, F5) · `test_tc_b100_62_containment_predicate` | 4 passed |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `TC-B100-01` (9 nodes: S7 sequence, direct refusals, wrapper AST, per-kind claim-loop AST, root-census AST, 4 boundary-catalog arms) · `TC-B100-02` · `TC-B100-03` · `TC-B100-57` (3 nodes) · `TC-B100-62` (15 nodes: predicate, 2 direct junction arms, export/group/gather junction arms, explicit-root arm, 5 explicit-root route arms, 2 nested-anchor arms, SEC-2 arm, 2 F8 anchor arms, junctioned-base arm (R3-1), gather-root TypeError arm (R3-3)) · `TC-B100-68` (4 nodes) · re-pinned `TC-018` · `AT-031b` · `TC-B99-31` | 35 nodes in `tests/test_b100_reuse.py` + 3 re-pinned nodes in their home files |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | `AT-B100-01` at (118×54) and (220×60), notifications on | 2 passed |

All 36 nodes of `tests/test_b100_reuse.py` pass in 73 s (`green-09-fix2-arms.txt`, fix pass 2 —
the file grew from 24 to 36 nodes); fix pass 1's 24-node run is `green-03-fix1-arms.txt`; round 1's
14-node run is `green-01-test-b100-reuse.txt`. The three re-pinned nodes and the four unchanged
siblings of LLR-163.4 pass (`green-02-repins.txt`, 7 passed; `green-05-gather-repins.txt` re-runs
them in fix pass 1 together with the gather service: 55 passed). Whole-tree guards re-run in fix
pass 2 (`guards.txt`, §4 fix-pass-2 table); the census sweep passes (`guards-census.txt`).

### Fix pass 1 (review F1–F11, LED .49) — RED / GREEN / mutation rows

| Kind | Transcript | Command (first line of the transcript names it) | Result |
|---|---|---|---|
| RED (fix-pinning arms vs the unfixed Inc 1 tree) | `red-03-fix1-arms.txt` | `pytest tests/test_b100_reuse.py` before the fix | 5 failed / 19 passed — exactly the three junction caller arms (export, group, gather: DID NOT RAISE, bytes in the victim), the explicit-root arm (TypeError: no `workarea_root` parameter) and the relative-destination arm (predicted relative vs placed resolved) |
| RED (revert proof — export caller only) | `red-04-revert-export.txt` | the export arm, with the export caller change reverted (pre-resolved home through the guard and the placements) | 1 failed — the S-02 escape reappears through the export |
| RED (revert proof — group caller only) | `red-05-revert-group.txt` | the group arm, with `place_group_into_workarea`'s guard change reverted (destination resolved before the guard) | 1 failed |
| RED (revert proof — gather caller only) | `red-06-revert-gather.txt` | the gather arm, with `_gather_copy`'s change reverted (pre-resolved home end to end) | 1 failed |
| GREEN (full module, fixed tree) | `green-03-fix1-arms.txt` | `pytest tests/test_b100_reuse.py` | 24 passed, 0 failed |
| mutation F2 (KILLED) | `mut-F2.txt` | the `contained` mutant — the `contained_in_workarea` refusal removed from `_guarded_destination` | the explicit-root arm writes into the other work area → 1 failed |
| mutation F3 case arm (KILLED) | `mut-llr-163-1-fold.txt` | `fold` — case-folding replaced by identity in `_reuse_candidate_names` | the upper-case `_2` arm → 1 failed |
| mutation F3 `_1`-deleted arm (KILLED) | `mut-llr-163-1-barename.txt` | bare-name — `_REUSE_NUMBERED_RE` never matches (comparison restricted to the requested name) | the `_1`-deleted arm → 1 failed |
| mutation F3 link arm (KILLED) | `mut-llr-163-1-link.txt` | link — the reparse skip removed in `_match_identical` and the candidate followed with `os.stat` instead of `os.lstat` | the link-candidate arm → 1 failed |
| mutation F3 0-byte arm (KILLED) | `mut-llr-163-1-zero.txt` | zero — the 0-byte candidate skip removed from `_match_identical` | the 0-byte arm → 1 failed |
| mutation LLR-163.1 cap (KILLED — F11) | `mut-llr-163-1-cap.txt` | the contract's second LLR-163.1 mutation: the size-cap refusal disabled in `place_into_workarea` | the direct over-cap arm writes → 1 failed |

All six fix-pass-1 mutants were reverted; the restore is proven by SHA-256 — the three touched
sources hash-equal the fixed-state snapshot (`workspace.py` c10a9d8247b1…, `segment_split_view.py`
ea30405e41fd…, `project_gather_service.py` 88ffdb6abc1a…) after every restore.

### Fix pass 2 (SEC-1/SEC-2, review N1–N5 + F9 nit, LED .50) — RED / GREEN / mutation rows

| Kind | Transcript | Command (first line of the transcript names it) | Result |
|---|---|---|---|
| RED (route revert — variant append) | `red-07-routes.txt` | the variant-append route arm, with `place_into_workarea` reverted to ignore `workarea_root` | 1 failed — DID NOT RAISE: the destination textually inside the other work area is accepted |
| RED (route revert — Save copies + syncs) | `red-08-save-copies.txt` | the Save-copies and MAC/A2L-syncs arms, with `copy_into_workarea` reverted to drop the root | 2 failed — both routes accept the other work area |
| RED (route revert — gather) | `red-09-gather.txt` | the gather route arm, with `_gather_copy` reverted to drop the root | 1 failed |
| RED (route revert — export) | `red-10-export.txt` | the export route arm, with `write_split_join_export` reverted to drop the root at the guard and both placements | 1 failed |
| RED (SEC-2 revert) | `red-11-sec2.txt` | the invalid-spelling arm, with the SEC-2 mkdir wrap removed from `place_into_workarea` | 1 failed — the bare `OSError` `[WinError 123]` escapes past the containment class |
| RED (F8 fallback revert) | `red-12-shortname.txt` | the 8.3 short-name arm, with `_find_workarea_root_shortname` removed from the guard | 1 failed — the non-canonical anchor spelling is refused |
| RED (N5 revert) | `red-13-n5.txt` | the group-word arm, with the case-folded pre-listing reverted to case-exact | 1 failed — the reused group reports `wrote` |
| GREEN (full module, fixed tree) | `green-09-fix2-arms.txt` | `pytest tests/test_b100_reuse.py` | 36 passed, 0 failed |
| GREEN (affected files, reverse census) | `green-10-affected.txt` | `test_project_gather · test_segment_split_window · test_b99_export · test_b99_staging · test_copy_into_workarea_content_dedup · test_tui_workspace` | 161 passed, 0 failed |
| GREEN (remaining reverse-census files) | `green-11-tui-files.txt` | `test_unified_write · test_tui_patch_editor_v2 · test_tui_variants · test_manifest_writer · test_open_folder_chips · test_crc_designer_view` | 147 passed, 4 failed — all 4 in `test_tui_patch_editor_v2` (`test_save_back_prompt`, `test_at032b_clarity_added_action_wiring_unchanged`, `test_at_batch41_escape_cancels_changeset_json_popup`, `test_at068b_per_entry_json_popup_edits_only_selected_entry`): the documented pre-existing order/timing flake, present at base `e044112` (review-increment-001 round 1); the same 4 nodes pass in isolation — `green-12-flake-isolation.txt`, 4 passed |
| mutation N1 (KILLED) | `mut-n1-outermost.txt` | the declared N1 mutant — `_find_workarea_root` reverted to the NEAREST anchor | the nested-anchor arm → 1 failed (DID NOT RAISE — the escape reappears); the explicit-root half stays GREEN, named in the transcript |
| mutation census (KILLED) | `mut-census-root.txt` | the declared census mutant — `workarea_root=self.workarea` dropped from ONE `app.py` call (the A2L sync) | the root-census arm → 1 failed, naming the call site and line |
| mutation SEC-2 (KILLED) | `red-11-sec2.txt` | the SEC-2 wrap removed — recorded as both the arm's RED side and the mutation verdict | the invalid-spelling arm → 1 failed with the bare `OSError` |

All fix-pass-2 mutants were reverted; the restore is proven by SHA-256 — the four sources and the
two test files hash-equal the fixed-state snapshot `pre-mutation-hashes-fix2.txt`
(`workspace.py` a92556e46428…, `segment_split_view.py` 75b605252940…, `app.py` bde62a5695ac…,
`project_gather_service.py` ecb826507cc3…, `test_b100_reuse.py` 1d791b9f878a…,
`b100_links.py` 881f95fd8216…) after every restore; the one transcript produced during a
failed (no-op) mutation attempt was re-recorded (`red-11-sec2.txt`) and the no-op run discarded.

### Fix pass 3 (review round 3 R3-1/R3-2/R3-3, LED .50 — BOUNDED pass) — RED / GREEN / mutation rows

| Kind | Transcript | Command (first line of the transcript names it) | Result |
|---|---|---|---|
| RED (junctioned-base arm + gather-root arm vs the fix-pass-2 tree) | `red-14-r3-1-junctioned-base.txt` | the two new arms before the fixes | 2 failed — the export refuses "destination traverses a symbolic link or reparse point" (the R3-1 regression, the reviewer's probe shape; base and fix pass 1 WROTE) and the gather does not raise `TypeError` without the root (R3-3) |
| GREEN (full module, fixed tree) | `green-13-reuse-module.txt` | `pytest tests/test_b100_reuse.py` | 38 passed, 0 failed (36 + the 2 fix-pass-3 arms: the junctioned-base export writes exactly `t_isle.s19` into the real work area; the gather without a root is a `TypeError`) |
| GREEN (affected files, reverse census) | `green-14-affected.txt` | `test_project_gather · test_segment_split_window · test_b99_export · test_b99_staging · test_copy_into_workarea_content_dedup · test_tui_workspace` | 161 passed, 0 failed — every export and junction arm still refuses an escape; the four R3-3 re-pins green |
| GREEN (`_active_project_dir` census files, R3-2) | `green-15-active-dir-census.txt` | `test_tui_report_seam · test_tui_report_view · test_tui_app` | 98 passed, 1 xfailed — the unresolved fallback breaks no reader |
| GREEN (whole-tree guards) | `guards.txt` | the six guard files | 75 passed, 29 snapshot cells unchanged |
| GREEN (census sweep, PDR C-QA-3) | `guards-census.txt` | `pytest -k census tests` | 84 passed |
| mutation N1 re-run (KILLED) | `mut-n1-outermost-fix3.txt` | `_find_workarea_root` reverted to the NEAREST anchor | the nested-anchor arm → 1 failed (DID NOT RAISE — the escape reappears); the explicit-root half stays GREEN, named |
| mutation census re-run (KILLED) | `mut-census-root-fix3.txt` | `workarea_root=self.workarea` dropped from ONE `app.py` call (the A2L sync) | the root-census arm → 1 failed, naming the call site and line |
| restore proof | `pre-mutation-hashes-fix3.txt` | SHA-256 of the four sources before mutation | both restores hash-equal the snapshot (`RESTORE OK` in the run output; no mutant left in place) |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | LLR-163.5 oracle hardening: the swapped-branch mutation (`if placement.reused:` → `if not placement.reused:`) SURVIVED the first TC-B100-03 because that version counted the two status messages without pinning which load produced which — `mut-llr-163-5.txt` (1 passed) is the vacuous-oracle catch. The order oracle (`statuses.index(added[0]) < statuses.index(named[0])`) was added; the same mutation then goes RED — `mut-llr-163-5b.txt` (1 failed). Restore proven by hash in every transcript. |
| Instrument | project code, own hand via a one-off patch script (position + operation, never pasted requirement text); restore from a byte-copy, verified by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b100-inc1`), implementer agent |
| Transcript | `evidence/inc-1/mut-llr-163-5.txt` (survived — oracle strengthened) and `evidence/inc-1/mut-llr-163-5b.txt` (KILLED) |
| Restore proven by | `restore: <sha256>` + `RESTORE OK` line in each `mut-*.txt`; final tree hashes equal `pre-mutation-hashes.txt` |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` in every run (C-46) |
| Arms resolved at baseline | 14 nodes in `tests/test_b100_reuse.py` (2 of them parametrized AT arms) + 3 re-pinned nodes + 4 unchanged siblings — counts asserted per transcript |
| Verdict granularity | per node id, per transcript |
| Arms that stayed GREEN | named per mutation verdict below |

| Field | Value |
|---|---|
| **RED counterfactual** | The re-pinned nodes' RED side is their pre-change failure, executed at base: `tc_b99_31` third export saw `t_isle_2.s19` (`red-02-repins.txt`, 1 failed / 3 passed); `TC-018`/`AT-031b` failed at base as `FF` (contract P-7, `g005-tests.txt`); the whole new module failed at base on import (`red-01-new-module.txt`). Live mutation REDs: 8 applied, 8 reverted, per LLR below. |

| Field | Value |
|---|---|
| **Mutation verdicts** | per resolved node: `LLR-163.1` — `_reuse_candidate_names` restricted to the bare name → `test_tc_b100_01_s7_sequence_reuses_identical_files` KILLED (the direct-refusal and AST arms stayed GREEN, named) · `evidence/inc-1/mut-llr-163-1.txt` · restore 305e197c…43d1 ✓. `LLR-163.2` — the size-first skip removed in `_match_identical` → `test_tc_b100_02_size_check_runs_before_any_candidate_read` KILLED (5 reads) · `mut-llr-163-2.txt` · restore ✓. `LLR-163.3`+`LLR-163.4` — reuse disabled (`identical = None`) → `test_tc018_existing_name_is_dedup_suffixed`, `test_at031b_two_saves_are_distinct_no_clobber`, `test_tc_b99_31_changed_bytes_take_the_next_free_name` all KILLED · `mut-llr-163-3.txt` (3 failed) · restore ✓. `LLR-163.5` — branches swapped in `_sync_loaded_file_to_project` → `test_tc_b100_03_reused_variant_is_named_not_added` KILLED (order oracle) · `mut-llr-163-5b.txt` · restore 0dedd784…623e ✓. `LLR-163.6` — export word restricted to the requested name → `test_tc_b100_57_identical_reexport_to_existing_suffix_is_reused` KILLED (the `_1` arm reports `wrote`; the census arm stayed GREEN, named) · `mut-llr-163-6.txt` · restore 6dacb71d…324b ✓. `LLR-163.7` — prediction given an `is_file()` walk that skips directories → `test_tc_b100_68_prediction_walks_the_same_names_as_the_placement` KILLED (predicts `firmware_1.s19`; the two sibling arms stayed GREEN, named) · `mut-llr-163-7.txt` · restore ✓. `LLR-171.4` — the pre-resolve reparse walk removed from `place_into_workarea` → `test_tc_b100_62_junction_destination_is_refused_nothing_written` KILLED (bytes escape into the other work area; the containment-predicate arm stayed GREEN, named) · `mut-llr-171-4.txt` · restore ✓. `LLR-155.3` (the 4th re-pin's pin) — `place_into_workarea` removed from the final-name allow-list → `test_tc_b99_13_no_final_name_replace_outside_placement` KILLED · `mut-llr-155-3-allowlist.txt` · restore 46eafb00…dee33 ✓ |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest tests/test_b100_reuse.py` (new module) | run at base (pre-change tree): the new symbols do not exist | collection ImportError, exit 2 — `red-01-new-module.txt` |
| `pytest <re-pinned nodes>` at base | `tc_b99_31` third export at base | `AssertionError: assert ['t_isle_2.s19'] == ['t_isle_1.s19']`, exit 1 — `red-02-repins.txt` |
| the counting oracle of TC-B100-02 | mutation removing the size check | `candidate_reads == [sized]` saw 5 reads — `mut-llr-163-2.txt` |
| the order oracle of TC-B100-03 (after hardening) | swapped status branches | `statuses.index(added[0]) < statuses.index(named[0])` fails — `mut-llr-163-5b.txt` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the placed files on disk | `read_s19(destination / "firmware.s19").data == read_s19(CASE01).data` and the `firmware_1` ↔ case_02 pair (independent reader) | both equalities held — `green-01-test-b100-reuse.txt` |
| the export's `PlacedExport` words | `all(p.action == "reused" for p in rechanged)` with `home.iterdir()` holding exactly `t_isle.s19`, `t_isle_1.s19` | `reused`, 2 files — `green-01` |
| the painted status line | `"Variant 'firmware' already in project 'P'" in #log_line_4` after a repeated load, at both sizes | found at (118, 54) and (220, 60) — `green-01` |
| the durable file-state line | `#status_text` starts with `"Loaded "` after each dialog load | observed after every load — `green-01` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/import-proof.txt | 935124e09ad399b77998ab018c514337ad00dea7cc1318f92383e076b5b44702 |
| red-01-new-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-01-new-module.txt | 8607ee2f6ece28dd55a9558e9cc1320b5767852f670995b1d6e52c4547128f54 |
| red-02-repins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-02-repins.txt | 8e23b49ed362ea67eb7adaef295ac15df96893db6bc09b5f737d2820154b802e |
| green-01-test-b100-reuse.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-01-test-b100-reuse.txt | 72b3c430b42df0afd544251286941e2f08bdcee9fde32336b5284ab1f61cde11 |
| green-02-repins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-02-repins.txt | 22e28dcfa3254258f80d625c457d6f2f9dcda48e685be660e9f0275084c69bf4 |
| mut-llr-163-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1.txt | b76876f4a41648df06fb11c501bfda1fdf32067d16b20ec69fb223f782368a38 |
| mut-llr-163-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-2.txt | 37213be6460733faffb337affcd1fb41caedd935032c77a615a6c35bd7b87058 |
| mut-llr-163-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-3.txt | 74cadde5cd7800d3681edb33845ea992efbfea70eaa326125213f6e6b74ca7ab |
| mut-llr-163-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-5.txt | f726e71710fb3f7891c3839f2e0c4b430bb912f3b7fe1b06f9d440f22a751c66 |
| mut-llr-163-5b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-5b.txt | 3600aacae0b5ab9671a491ca8826578bfda4dbeb8330be8642d4c42e4255b261 |
| mut-llr-163-6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-6.txt | 57cfbc8c59feb89559aaea5d6afbd36d737e00139aa1e7114240f182ce59bf9b |
| mut-llr-163-7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-7.txt | 8063f19b0653ea86c74fea7b078fd441c4e01794432de6f435ee2a957326ebae |
| mut-llr-171-4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-171-4.txt | 66c3b311faca1be58ce80a49cdcbea8171904d2627154649032430e432717bba |
| pre-mutation-hashes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/pre-mutation-hashes.txt | 920b9d54961767e91c3770affcef7f1416fff4bd520e0d57f30ee918ab9b15eb |
| mut-llr-155-3-allowlist.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-155-3-allowlist.txt | 22d9f16d2bd8d21f67772493d7c2426e887668be156d767af1f0ae4d64dd0baf |
| reverse-census-tests.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/reverse-census-tests.txt | 4bce1ec27490c65675fae65c35b0fbafb07760554a5071eaa89ce65eb453063a |
| reverse-census-tests-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/reverse-census-tests-2.txt | c2877e13b01475a716cf3be99622cdd1d90ab43e8402dceb7e0f346923de3b12 |
| reverse-census-tests-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/reverse-census-tests-3.txt | edf7497ba4259f054fc818c4222296fa0f1ddc52037bffba1c615fc947b4d6c9 |
| reverse-census-tests-4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/reverse-census-tests-4.txt | 905281b7a7418643b0f8ef8ba51da551aa402894497bb23cb5f6e5dbcab185c4 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/guards.txt | 110ea2e3d4e7e7059574bae9b3c7b828bdbe8a409403ab8eeb93cd0775f5dc3c |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/guards-census.txt | 3095d5eaf3c6876e308afe74f7dcf587cb963225cb2e69d84e3486f85befebac |
| red-03-fix1-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-03-fix1-arms.txt | 338f60f49b7cc49ffa06e835b8b5f998af5da600f35927d749feb48788e02c9d |
| red-04-revert-export.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-04-revert-export.txt | 9cdec8ece8039d6c982aebd09fcb9569ffc764ce7d4fde693c9f521e7b4151b5 |
| red-05-revert-group.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-05-revert-group.txt | a181aa878b4545c9a800dd60a584aa58fd0ca2b9132a5c3ffc58939f747ef9d7 |
| red-06-revert-gather.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-06-revert-gather.txt | f3dfe0ec0ebca33b297f0c53b3ce96eff23001c2f48f4e0a040b5bc977f1b818 |
| green-03-fix1-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-03-fix1-arms.txt | 6829ce16c0e5f4e0e6011c39ff59a1786dfdc712064f86d39fbc943fb62c1ffa |
| green-04-staging.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-04-staging.txt | a2fab1c83ef15af423993c1a2efcfed673458d0b9dab2ac37a28b18e8b731516 |
| green-05-gather-repins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-05-gather-repins.txt | 4132cccf6d4d4956da15aabf0d06b8f0acc0e71cd17fc1cf4ab8fa1c1155a5a9 |
| green-06-census-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-06-census-files.txt | eddf9b504b2d9c3224c14f70e17f16480a74c9ad39a9fac0d51d083479408028 |
| green-07-tui-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-07-tui-files.txt | c9a256aac5d1bdb0bf499676e21d248bce2feb5d38ef0b9d39a9e883cce4e102 |
| green-08-remaining-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-08-remaining-census.txt | f857a76911d0c37708bab8eb0522023b55003f1beb2999bf6df9d0317204a1cb |
| mut-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-F2.txt | de4a614d4b29a36c3362019eac68691c64349f02ef8ca916508921042ebee61b |
| mut-llr-163-1-fold.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1-fold.txt | bc815eab582e76f7bf7fb17533b7ae8eba50648e86c646a3d9f205206eefe86b |
| mut-llr-163-1-barename.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1-barename.txt | e115656d5fa1b4bea7cfa7dc890a51732fb6324b596599c347551b3456bad43c |
| mut-llr-163-1-link.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1-link.txt | 74d472560268574012a8bdb281a0ab2fd34517a0ad3400d5ec5ddac54546757b |
| mut-llr-163-1-zero.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1-zero.txt | 39b2e47fe62e665fddecb25c6cc6500eb4a849719c842d21c19bfd44dc79fb93 |
| mut-llr-163-1-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-llr-163-1-cap.txt | a24fc7fe0c3a2fbf7844fd9f5a0ad8f74d676868d6bccc0f296247d2d6e59f8a |
| pre-mutation-hashes-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/pre-mutation-hashes-fix2.txt | 8094a4b831c257bdb05533f48dd7c2010f683b8a1b61ff81dc40726d298076a9 |
| red-07-routes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-07-routes.txt | a8e95c4baac98face4a07af7021f1e15fbabe0300734aad43927cecd3b89e545 |
| red-08-save-copies.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-08-save-copies.txt | 597c23fab370c3b791d99378adf1c9d4bec01a281224e98833bdaf3b4ce04105 |
| red-09-gather.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-09-gather.txt | 716f779f4284a5a45dc629a7a3217932c1ce81738309ea571c830cd077a041ba |
| red-10-export.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-10-export.txt | 8a6e06a7dc393a1bd51e6be8f0cdf61cf30579d7e30affae4510ba060108e6d2 |
| red-11-sec2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-11-sec2.txt | 0d44491516af879b048d89824099943c44fd9529f2ec3a9ecb22e509482a1a19 |
| red-12-shortname.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-12-shortname.txt | 77e7bf3d89cb94ad8cb72e38a7b7c8083c0b2b82a3988c2bd77c3357c0fb0bc7 |
| red-13-n5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-13-n5.txt | f160f9b6e63cc3b62e3204cf90a38a5697c8c123a8ed0e410f1070e7387156e5 |
| green-09-fix2-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-09-fix2-arms.txt | f02b4bac04653cd5ee66711488d84d9f7b5d350cfb46573b17f192009567389e |
| green-10-affected.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-10-affected.txt | aeeee119aa73cbe2557f4fb8162eeef999ca0129c8da7fa3199e28b471c33237 |
| green-11-tui-files.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-11-tui-files.txt | 2dce0f2b849514c3f0a8d2ae30c03b4c99e45db94764f6b3f2ab238f9071e1b0 |
| green-12-flake-isolation.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-12-flake-isolation.txt | f64c8eea4b2c8d9a6de458d8883f313f354eed018c7810a4f39a87ae74dca6d0 |
| mut-n1-outermost.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-n1-outermost.txt | 2debd3fc24808c465a558cb58f5e1ee0f0c4d248d2c5734177294ef6e901be48 |
| mut-census-root.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-census-root.txt | 0bc1570db6f384a257d8a902c1011cb561b6d743338773299f6c2cbff431be26 |
| red-14-r3-1-junctioned-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/red-14-r3-1-junctioned-base.txt | 44bcbee95a60b5ea153d206a1728d9e0bcd8f9c160fb3ce014581b0cbf90b871 |
| green-13-reuse-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-13-reuse-module.txt | 31f7e0d7d4325f0142b06d99696f2f2dfdd1b570efd79c0f9c2241ade0e2b546 |
| green-14-affected.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-14-affected.txt | 2e9305cf5c206982c2aea4e367e303853bcbe4dcc11dd72f47368860b48824e5 |
| green-15-active-dir-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/green-15-active-dir-census.txt | 74ef27fd60ad389118add0fd106931f56cf6fdec4a06c873d3b433deb379144b |
| mut-n1-outermost-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-n1-outermost-fix3.txt | 2d7c42d9aed646537364940b7eb4567049e077f75696309950be0f6a62b2e76f |
| mut-census-root-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/mut-census-root-fix3.txt | 5bb9afd1b26db81e771e67ac02e07771d3ba3ad4d7f7f2e9f69a202c59e902da |
| pre-mutation-hashes-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/pre-mutation-hashes-fix3.txt | b86141392067c64474f5bac1607ca4cc0e1932a86d1a155202878785434eacdb |
| orchestrator-gate.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-1/orchestrator-gate.txt | f3a2f94f829a38eb549ec0985b037816f063486e79de7989c6281dedc92c5f3a |

| Field | Value |
|---|---|
| **Evidence files** | `59 artifact(s), each at the declared home, with the digest of its bytes on disk` |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | Yes — one: the TC-B100-57 census asserts the export module holds no `read_bytes` call at all. That is an ABSENCE claim. |
| If the result is an ABSENCE, what made the search wide enough | the probe parses every `s19_app/**/*.py` and greps the literal `read_bytes` — the over-broad property (any byte read in the export module) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b100_57_export_holds_no_byte_identity_rule` — its docstring says the census is the LLR-163.6 conclusion (one single-file identity rule, word from the placement), not a behaviour pin |
| Conjunctive criteria: one mutation per conjunct | LLR-163.6's mutation kills the `.<N>`-suffix arm while the census arm stays green — two conjuncts, two verdicts recorded; LLR-163.1's mutation kills the S7 arm while the refusal/AST arms stay green — same. **Fix pass 1 (F5):** the census now counts rules BY BEHAVIOUR (an AST `read_bytes() ==` comparison or a `_hash_file` digest compare inside any function), with a declared allow-list naming the two known others — the group's frozen rule (R30, `place_group_into_workarea`) and the gather's sibling scan (`_gather_copy`, converted by Inc 3b). Any new rule under another name, or a deleted declared one, fails the census |
| Synthetic instance of the absent case | the mutated export (requested-name-only word) is the synthetic re-introduction of the absent case, and the `_1` arm goes RED on it (`mut-llr-163-6.txt`); the four F3 boundary mutants are the synthetic instances for the boundary-catalog arms (`mut-llr-163-1-{fold,barename,link,zero}.txt`) |
| **Positive control for every probe that returned an ABSENCE** | the positive control is the pre-change tree itself: at base the same module DID contain the rule (`_export_reuse_target` with `read_bytes() ==`) and the same node failed differently (`red-01`/`red-02`); on the mutated tree the probe returns the NON-absent output (the `_1` arm reports `wrote`) — `mut-llr-163-6.txt` |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "copy_into_workarea\|_export_reuse_target\|_sync_loaded_file_to_project\|place_into_workarea\|find_identical\|predict_placement\|contained_in_workarea" tests/ --include=*.py` | 15 files (the contract's §5.4 population: `copy_into_workarea` ×15). Every hit re-validated in `reverse-census-tests.txt` |
| B1 "Added variant" | `grep -rln "Added variant" tests/ --include=*.py` | 2 files: the new module and `test_tui_variants.py` — the first-load arm stays green (`reverse-census-tests.txt`) |
| B2 file moved on disk | n/a — no file moved | no readers |
| B3 byte-identical golden captures this source | `grep -rn "workspace.py\|segment_split_view\|app.py" tests/goldens/ 2>/dev/null` | no hits |
| B4 artifact produced here is consumed elsewhere | `PlacedExport` action words consumed by the export panel status and `test_b99_export.py` | re-validated in the census run |
| A3 interface consumed by another module changed | `copy_into_workarea` return type frozen (B100-I6); new symbols consumed by `segment_split_view.py` and `app.py` only, both in this increment | 15 test files reference the wrapper; all re-validated |

| Field | Value |
|---|---|
| **Reverse census** | 6 probes run (B1 ×2, B2, B3, B4, A3): 15+2 test files found, every hit re-validated — 31 + 296 + 138 + 23 passed across `reverse-census-tests{,-2,-3,-4}.txt`, plus `test_b100_reuse.py` (`green-01`) and `test_id_registry.py` (`guards.txt`); 0 failures after the LLR-155.3 allow-list re-pin. **Fix pass 1 re-validates every hit again against the guarded tree:** `test_b99_staging.py` 31 passed (`green-04-staging.txt`); `test_project_gather.py + test_unified_write.py + test_b99_export.py` 55 passed (`green-05-gather-repins.txt`); `test_copy_into_workarea_content_dedup.py + test_segment_split_window.py + test_tui_workspace.py` 92 passed (`green-06-census-files.txt`); `test_tui_patch_editor_v2.py + test_tui_variants.py` 63 passed (`green-07-tui-files.txt`); the remaining round-1 chunk files re-validated in `green-08-remaining-census.txt`. Fix-pass-1 symbol probes: `grep -rln "place_group_into_workarea\|_check_home_contained\|_gather_copy\|predict_placement" tests/ --include=*.py` → 4 files, all in the re-run set; the `copy_into_workarea` population (15 files, contract §5.4) is covered by the same set plus the round-1 chunks. **Fix pass 2 re-validates every hit of the changed symbols again** (`grep -rln` over `copy_into_workarea · place_into_workarea · place_group_into_workarea · _guarded_destination · _find_workarea_root · _find_workarea_root_shortname · _reuse_candidate_names · write_split_join_export · gather_project_artifacts · _gather_copy · _check_home_contained · current_project_dir · contained_in_workarea` → 30 test files): `test_project_gather · test_segment_split_window · test_b99_export · test_b99_staging · test_copy_into_workarea_content_dedup · test_tui_workspace` 161 passed (`green-10-affected.txt`); `test_unified_write · test_tui_patch_editor_v2 · test_tui_variants · test_manifest_writer · test_open_folder_chips · test_crc_designer_view` 147 passed, 4 failed — all 4 in `test_tui_patch_editor_v2`, the documented pre-existing order/timing flake present at base `e044112` (review round 1); the same 4 nodes pass in isolation (`green-12-flake-isolation.txt`, 4 passed) — no assertion re-pin was required: every other hit passed unchanged |

**Re-pins recorded (old → new → requirement):**
- `tests/test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed` — second save asserted `first != second`, `second.name == "cs_1.json"` → two arms: identical document twice returns the SAME path with 1 file on disk; a different document lands at `cs_1.json` with both files surviving — LLR-163.3 (G-005).
- `tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber` — two saves after one added entry asserted 2 files → two saves of an unchanged document leave 1 file (reuse); a save after another added entry leaves 2 files with distinct names — LLR-163.3 (G-005).
- `tests/test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name` — third export of the changed bytes asserted `t_isle_2.s19`/`wrote`/3 files → asserts `t_isle_1.s19`/`reused`/2 files — LLR-163.4.
- `tests/test_b99_staging.py::_FINAL_NAME_ALLOWLIST` (the LLR-155.3 census arm `test_tc_b99_13_no_final_name_replace_outside_placement`) — the workspace.py allow-list pinned `{copy_into_workarea, _private_stage_dir, place_group_into_workarea}` → adds `place_into_workarea` (the placement invariant moved there; the wrapper has no primitives) — LLR-163.1 (B100-I13). RED side: with the entry removed the census fails (`mut-llr-155-3-allowlist.txt`, 1 failed, restore verified). **Fix pass 1 (F10):** the same set drops `copy_into_workarea` — the wrapper no longer writes (it is exactly `return place_into_workarea(...).path`), and the TC-B100-01 wrapper AST arm pins its shape — LLR-163.1 (B100-I13). Re-validated: `green-04-staging.txt`, 31 passed.
- Unchanged, per P-22/PDR C-QA-8 (run, not edited): `test_tc_b99_31_bin_pair_placed_under_one_suffix`, `test_tc_b94_04_template_save_reload_and_dedup`, `test_at_b94_17_template_save_listing_import_and_dedup`, `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`.

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the export must hold no byte-identity rule of its own | every function in `s19_app/` comparing file bytes for reuse | `grep -rn "read_bytes() ==" s19_app/ --include=*.py` before the edit | 2 (`segment_split_view.py` `_export_reuse_target`, `workspace.py` `place_group_into_workarea` internal group rule) | 1 (`_export_reuse_target` deleted) | 1 left — `place_group_into_workarea`'s requested-names-only group rule is frozen unchanged (R30); it decides placement, not a status word |
| the variant-append status must come from the placement outcome | every emitter of an "Added variant" status | `grep -n "Added variant" s19_app/tui/app.py` | 1 (`_sync_loaded_file_to_project`) | 1 | 0 |

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, each enumerated with its command before the first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| `_export_reuse_target` | 0 hits in `s19_app/` (deleted); 0 in `tests/` | yes | `segment_split_view.py` (function removed); census arm in `tests/test_b100_reuse.py` |
| requested-name-only reuse in the single-file export | 0 hits — the single-file branch rides `place_into_workarea` | yes | `segment_split_view.py` (export dispatch); `mut-llr-163-6.txt` proves a re-introduction is RED |

### Signed-balance test ledger

Scanned-file ledger (what `EXPECTED_SCANNED_TEST_FILES` pins):
`post = base − deleted + added` → `215 = 213 − 0 + 2` ✓ reconciles
(`tests/test_b100_reuse.py` and `tests/support/b100_links.py` are the two added scanned files;
`b100_links.py` is a helper module with no test nodes; `tests/test_id_registry.py` bumps the bound
by the measured count; nothing deleted.)

Node ledger (test functions collected in the new module):
`36 nodes = 24 (rounds 1 + fix pass 1) + 12 (fix pass 2)` — added in fix pass 2:
`test_tc_b100_01_app_placements_name_the_workarea_root` (the LED .50 root census),
`test_tc_b100_62_variant_append_root_refuses_another_workarea`,
`test_tc_b100_62_save_copies_root_refuses_another_workarea`,
`test_tc_b100_62_syncs_root_refuses_another_workarea`,
`test_tc_b100_62_gather_root_refuses_another_workarea`,
`test_tc_b100_62_export_root_refuses_another_workarea` (the five SEC-1 explicit-root route arms),
`test_tc_b100_62_nested_anchor_junction_refused_without_root` (N1),
`test_tc_b100_62_explicit_root_refuses_nested_anchor` (N1, explicit-root half),
`test_tc_b100_62_invalid_path_spelling_is_a_containment_refusal` (SEC-2),
`test_tc_b100_62_upper_case_anchor_is_accepted_on_windows` (F8/N4),
`test_tc_b100_62_short_name_anchor_is_accepted_on_windows` (F8/N4),
`test_tc_b100_57_group_word_compares_case_folded` (N5). Deleted: none. Windows-only arms: 8 of
the 12 (5 route arms use plain directories and run on every platform; the nested-anchor arms,
SEC-2, both F8 arms and N5 are Windows-only with the named PDR C-QA-6 skip reason).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES after 4 rounds (round 1 BLOCK-UNTIL F1 HIGH; round 2 PASS-WITH-NOTES; round 3 BLOCK-UNTIL R3-1 HIGH regression; round 4 PASS-WITH-NOTES, 0 HIGH / 0 MAJOR open) — `review-increment-001.md`. `security-reviewer` (routed F1) · round 1 BLOCK-UNTIL SEC-1 HIGH; round 2 PASS-WITH-NOTES, SEC-1 closed by driving the app routes — `security-increment-001.md`; SEC-4 → Inc 5, SEC-5 → Inc 8b, SEC-6 closed by R3-2. Orchestrator re-run on the final tree: 124 passed (Inc 1 files), guards 75 passed + 29 snapshots, census sweep 84 passed — `evidence/inc-1/orchestrator-gate.txt`. Operator decision at the P3 iteration cap: bounded fix pass 3. |

---

## 5 · Risks

- `place_group_into_workarea` **is now resolved** (fix pass 1, F1): it runs the same shared
  destination guard on the unresolved destination — no open containment gap remains for either
  placement kind. This closes the round-1 risk note; the group's frozen reuse rule (R30) is
  untouched.
- `predict_placement`'s forced-claim arm demonstrates divergence by comparing prediction and
  placement in the test; the handler-side mismatch REPORT is B100-I17 / LLR-163.7's second half
  and rides the save plan (Inc 5/11) — not buildable here (F6 defers the "mismatch error naming
  both paths" assertion there too).
- The reused-variant status wording (`Variant '<id>' already in project '<name>'`) is new surface
  text pinned by TC-B100-03 and AT-B100-01; any copy change must update both.
- 8.3 short-name destination forms (e.g. `S19TOO~1`) are accepted only through the per-component
  reparse-checked fallback (F8); a short-name seam that is a junction is still refused. Exposure
  is nil today — the app builds these paths by joining names — but a caller feeding exotic
  spellings relies on the fallback, not the textual walk.
- **SEC-3 (routed to backlog per LED .50):** the 8.3 fallback reparse-checks every component from
  the drive root, so a work area that itself sits under a reparse point (a redirected or synced
  folder, a junctioned user folder) is refused only on the 8.3 route — a false refusal, not a
  bypass (not run; reasoned from the code). LED .50 routes it to `BACKLOG-CODE.md` §Routed
  2026-10-26 batch-100, together with the explicit-root threading for the four placement callers
  outside this increment's 4-file cap (`changes/apply.py`, `operations/crc.py`,
  `services/flow_execution_service.py`, `services/flow_persistence_service.py`). Until then the
  fallback's stricter-than-the-textual-route check is declared in §6 (N4).

## 6 · Pending items / spec deviations

- TC-B100-62's Windows-only junction arms: on non-Windows platforms they `pytest.skip` with the
  named reason `directory junctions are a Windows-only test arm (PDR C-QA-6)` — counted per
  PDR C-QA-6 (this run executed them on Windows).
- `mut-llr-163-5.txt` records a mutation that SURVIVED the first oracle; the oracle was hardened
  in-increment (order pin) and the mutation re-run as `mut-llr-163-5b.txt` (KILLED). No contract
  deviation — a C-40 vacuous-oracle catch, recorded per the lessons catalog.
- **F5 (for the orchestrator to accept or reject):** the group's status word is computed from a
  pre-listing — `names_before = {p.name for p in home.iterdir()}` before
  `place_group_into_workarea`, then `group_reused = all(f.name in names_before for f in finals)`.
  It derives from the placement the export performed (a returned path whose name was already
  present is a reuse; the group never claims an existing name — its claim loop lstats first), but
  it is NOT read off a `PlacementResult` field, which sits one notch short of LLR-163.6's "0
  status words computed outside a `PlacementResult`". Recorded as a declared deviation; the single
  file word does come from `PlacementResult.reused`. **Fix pass 2 (N5):** the comparison is now
  case-folded on both sides on Windows (`test_tc_b100_57_group_word_compares_case_folded`, RED
  side `red-13-n5.txt`) — the F5 acceptance condition is met; the word still derives from the
  placement outcome, so the deviation stands only as to the `PlacementResult`-field wording.
- **F6:** the TC-B100-68 "mismatch error naming both paths" assertion was tautological (it built
  the string it searched); the two lines are deleted and the arm is deferred to Inc 5 (B100-I17),
  which owns the mismatch report.
- **F7 (declared substitution, orchestrator fixed the contract):** the AST arm now pins "exactly
  one `O_EXCL` claim loop per placement kind in `workspace.py` (2)" per LED .49 — one in
  `place_into_workarea`, one in `place_group_into_workarea` — replacing round 1's wrapper-shape-only check.
- **F8 (decisions):** (a) the `.s19tool\workarea` anchor compares case-insensitively on Windows
  (a differently-cased `.S19TOOL\WORKAREA` names the same seam); POSIX keeps the exact spelling.
  (b) 8.3 short-name forms are accepted via `_find_workarea_root_shortname`, which reparse-checks
  each component before resolving it, so a form the base accepted cannot escape; non-canonical
  forms that WOULD escape are still refused. Both decisions are documented in the function
  docstrings. **Fix pass 2 (N4):** both branches are now armed — the upper-case anchor and the 8.3
  short-name arms (`test_tc_b100_62_upper_case_anchor_is_accepted_on_windows`,
  `test_tc_b100_62_short_name_anchor_is_accepted_on_windows`; the fallback-removal mutant is
  `red-12-shortname.txt`, KILLED). Two declarations: the reviewer's `anchorcase` mutant (fold →
  identity in `_find_workarea_root`) stays equivalent — the 8.3 fallback resolves the upper-case
  form anyway, so the arm cannot kill it (the arm documents the accepted form instead); the
  `shortreparse` mutant (the fallback's per-component reparse refusal removed) also stays
  equivalent for escapes — the main walk and the seam check still cover `.s19tool` and below — and
  the fallback's STRICTER check (it also refuses a reparse ancestor above the anchor, e.g. a
  junctioned user or TEMP folder) refuses a short-name form the base accepted. That false refusal
  is the SEC-3 class, routed to the backlog by LED .50 (§5), not a silent widening — declared here.
- **F2 (orchestrator question, resolved by LED .49):** "this app's work area" (B100-I14) is now
  checkable without a `workarea` parameter — the guard takes the destination as given, and an
  app-level caller passes the explicit root via the new optional `workarea_root` parameter of
  `place_into_workarea` (default None; the frozen B100-I13 wrapper shape is unchanged).
  **Fix pass 2 (LED .50) completes the ruling:** every app-level placement call passes
  `workarea_root=self.workarea` (9 sites, pinned by the TC-B100-01 AST census arm,
  `mut-census-root.txt` its mutant), the wrapper and the group placement forward it, and the
  export and the gather thread it from their app callers. The remaining placement callers outside
  the 4-file cap (`changes/apply.py`, `operations/crc.py`, `services/flow_execution_service.py`,
  `services/flow_persistence_service.py`) receive destinations from the app that are now
  unresolved, so the derived-root guard — with the outermost-anchor walk (N1) — covers them;
  passing the root there is defence in depth routed to `BACKLOG-CODE.md` §Routed by LED .50.
- **N3 (fix pass 2):** the TC-B100-57 census's declared `_gather_copy` sibling-scan rule is owned
  by Inc 5, where `project_gather_service.py` is touched again — batch-100 has no "Inc 3b" (that
  was batch-99's delete-and-recopy conversion); the census comments and this packet now name Inc 5.
- **N1 (fix pass 2):** closed in-code, not ledged — `_find_workarea_root` returns the OUTERMOST
  anchor and the reparse walk runs up to the outermost `.s19tool` (mirrored by the short-name
  fallback); the nested-anchor junction arm
  (`test_tc_b100_62_nested_anchor_junction_refused_without_root`) carries the
  outermost→nearest revert as its RED side (`mut-n1-outermost.txt`, KILLED).
- **R3-1 (fix pass 3):** the round-3 BLOCK is discharged in-code — the export binds the guard's
  return to a distinct `resolved_root` (staging only) and hands the CALLER'S `workarea_root` to
  both placements; the junctioned-base arm
  (`test_tc_b100_62_export_junctioned_base_app_root_writes`, RED side
  `red-14-r3-1-junctioned-base.txt`) pins it. The reviewer's recommended hardening (in
  `_guarded_destination`, compare the explicit root's resolved and textual forms instead of
  walking past a textually-unmatched destination) is NOT applied — bounded pass; routed to the
  LED .50 backlog entry with SEC-3.
- **R3-2 (fix pass 3):** closed — `_active_project_dir`'s fallback returns the unresolved
  `self.workarea / self.current_project`; the round-2 sweep's conclusion (no equality relied on
  the resolved form) is re-validated by `green-15-active-dir-census.txt`
  (`test_tui_app · test_tui_report_seam · test_tui_report_view`: 98 passed, 1 xfailed).
- **R3-3 (fix pass 3, bounded-pass deviation — for the orchestrator to confirm):** the brief
  lists `_check_home_contained` / `_gather_copy` among the functions whose `workarea_root`
  becomes a keyword-only parameter with no default; applied to `gather_project_artifacts` ONLY.
  The two private seams keep `Optional[Path] = None` because their one no-root production caller
  is `scoped_home` (`project_gather_service.py:631`), whose callers `folder_open_service.py` and
  `crc_designer_view.py` lie outside the LED .50 4-file cap — making the seam parameter
  required would TypeError the CRC-Designer template save and the open-folder chip creation at
  runtime, and threading the root through them is exactly the R3-4 backlog item. The demonstrated
  escape (probe `r3_gather_projjunction.py`) entered through `gather_project_artifacts`'s
  default, which is now impossible (`TypeError`, armed); the remaining `None` derivation is
  reachable only from `scoped_home` (R3-4 family, routed) and direct private test probes.
  The four test callers re-pin as `old → new` under LED .50: `test_tc_b99_13_gather_drift_places_next_free_name`
  · `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate` (`test_b99_staging.py`) ·
  `test_tc699_assignments_referenced_documents_are_gathered` ·
  `test_gather_containment_escape_refuses_without_writing` (`test_project_gather.py`) — each
  old form omitted the root (the removed unsafe default), new form passes the test's own work
  area; no assertion semantics changed.
- **R3-4:** untouched per the brief — the orchestrator routes it to the LED .50 backlog entry
  (the four out-of-cap callers' root threading), where it closes with the `scoped_home` family.

## 7 · Suggested next task

Increment 2 (LLR-164.x — Save project name guards), per the proposal's hard order; it consumes
`contained_in_workarea` (B100-I14) shipped here.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ⚠ | 4 source files — AT CAP, with the LED .49 reason (§2): the gather is a writer that resolved its destination before the guard; the guard must see that destination unresolved, so the increment cannot be smaller |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b100_reuse.py` (38 nodes: 14 round 1 + 10 fix pass 1 + 12 fix pass 2 + 2 fix pass 3) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | 4 unit nodes (wrapper AST, per-kind claim-loop AST, behavioural census, containment predicate) — `green-03` |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 RED table + 8 round-1 mutation transcripts + 6 fix-pass-1 transcripts + 3 caller-revert REDs + 7 fix-pass-2 route/branch reverts and 2 declared mutants (`mut-n1-outermost.txt`, `mut-census-root.txt`) + fix pass 3's `red-14-r3-1-junctioned-base.txt` (2 failed) and the 2 re-run declared mutants (`mut-n1-outermost-fix3.txt`, `mut-census-root-fix3.txt`, both KILLED) |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 reverse census, 6 probes, re-validated in fix pass 1 (`green-04`…`green-08`) and again in fix passes 2 (`green-10`/`green-11`) and 3 (`green-14`, `green-15` — the `_active_project_dir` census files for R3-2) |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b: PASS-WITH-NOTES, round 4 |
| 7 | No file from another lane touched | all | ✓ | only the 4 named source files |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I6 (amended), I13, I14, I22 are FROZEN here, not changed; `place_group_into_workarea`'s reuse rule unchanged (R30) — fix pass 1 routes its GUARD through the shared one (LLR-163.1, LED .49), which the amended LLR names; `copy_into_workarea` keeps the exact one-line wrapper shape |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every `N passed` appears in a cited transcript |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 load-bearing emptiness |
| 11 | **Mutation verdicts** declared — **per arm** | all | ✓ | §4 mutation verdicts |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 instrument table (4 instruments) |
| 13 | **Correction population** declared | all | ✓ | §4 correction population (2 corrections) |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 emitted-form table (4 artifacts) |
| 15 | **Independent review** names somebody | all | ✓ | §4b: code-reviewer + security-reviewer |
| 16 | **Evidence files** declared | all | ✓ | §4 evidence table (paths + SHA-256) |
