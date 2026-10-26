# HANDOFF — batch-100 increment 1 (s19_app, worktree s19_app-b100-inc1)

## What was done
Increment 1 of `2026-10-26-batch-100` is implemented and verified: HLR-163 /
LLR-163.1–163.7 and the LLR-171.4 guard clause. `s19_app/tui/workspace.py` now holds
`PlacementResult`, `contained_in_workarea`, `find_identical` (the one byte-identity
rule: one listing, `<name>` + `<stem>_<digits><suffix>` case-folded on Windows, size
before bytes, never links/reparse points/0-byte files), `_placed_name_candidates`,
`place_into_workarea` (every guard in order: source reparse, destination reparse on the
textual path before resolving — the S-02 fix — plus `contained_in_workarea`, the 256 MiB
cap, private staging, reuse or the `O_EXCL` claim of the lowest free `_<N>`, then
`os.replace`) and `predict_placement` (same walks, no staging, no claim, writes
nothing). `copy_into_workarea` is exactly `return place_into_workarea(...).path`.
`s19_app/tui/segment_split_view.py` takes the export's `reused`/`wrote` word only from
the `PlacementResult` (`_export_reuse_target` deleted; the BIN/`.addr` group's word
derives from the placement outcome, `place_group_into_workarea` unchanged).
`s19_app/tui/app.py` `_sync_loaded_file_to_project` names the existing variant
(`Variant '<id>' already in project '<name>'`) when `reused` is true.

## Verified
- RED first: `red-01-new-module.txt` (import failure at base), `red-02-repins.txt`
  (`tc_b99_31` saw `t_isle_2.s19` at base; TC-018/AT-031b RED is the contract's P-7 FF).
- GREEN: `green-01-test-b100-reuse.txt` (14 passed), `green-02-repins.txt` (7 passed —
  3 re-pins + 4 unchanged siblings).
- Mutations (C-40): 9 applied, 9 reverted, restores hash-verified against
  `pre-mutation-hashes.txt` — all KILLED their targets; one (LLR-163.5 swapped
  branches) SURVIVED the first TC-B100-03 oracle, which was hardened in-increment with
  an order pin and re-run KILLED (`mut-llr-163-5.txt` vs `mut-llr-163-5b.txt`).
- Reverse census: all 15 hit files + `test_tui_variants.py` re-validated
  (31 + 296 + 138 + 23 + 14 + registry-in-guards passed, 0 failures) after a 4th
  required re-pin: `test_b99_staging.py`'s LLR-155.3 `_FINAL_NAME_ALLOWLIST` gains
  `place_into_workarea` (RED side: `mut-llr-155-3-allowlist.txt`).
- Whole-tree guards: 75 passed, 29 snapshot cells unchanged (`guards.txt`); census
  sweep 84 passed (`guards-census.txt`). `EXPECTED_SCANNED_TEST_FILES` 213 → 215.
- Packet `.dev-flow/2026-10-26-batch-100/03-increments/increment-001.md` filled §1–§7;
  §4b `pending — orchestrator`. No commits made; CRLF preserved in all edited sources.

## Left / open
- §4b independent review and the full-suite checkpoint run belong to the orchestrator.
- TC-B100-62's seam (Inc 7) and listing/load arms (Inc 8b) are contract-scheduled
  later increments — intentionally not written here.
- `place_group_into_workarea` still uses the pre-batch-100 containment walk (frozen,
  R30); flagged in the packet's §5 for the orchestrator — no contract row schedules it.

__KIMI_UNIT_DONE_ROUND1__
Files changed: s19_app/tui/workspace.py, s19_app/tui/segment_split_view.py, s19_app/tui/app.py (3 source); tests: test_b100_reuse.py (new), support/b100_links.py (new), re-pins in test_unified_write.py / test_tui_patch_editor_v2.py / test_b99_export.py / test_b99_staging.py, test_id_registry.py count bump; packet + 20 evidence transcripts under .dev-flow/2026-10-26-batch-100/.
Tests added: 14 nodes (TC-B100-01 ×3, -02, -03, -57 ×2, -62 ×2, -68 ×3, AT-B100-01 ×2 sizes) + 4 re-pinned nodes; RED 2 transcripts, GREEN 14+7 passed; guards 75 + census sweep 84 + reverse census 31/296/138/23 passed.
Mutations: 9 run (LLR-163.1/163.2/163.3+163.4/163.5/163.6/163.7/171.4/155.3-allow-list), all KILLED, all restores hash-verified; 1 vacuous oracle caught and hardened (TC-B100-03 order pin).
Open questions: none blocking — orchestrator owns §4b review, the checkpoint full suite, and the §5 note on place_group_into_workarea's containment walk.

---

# Fix pass 1 — batch-100 increment 1 (corrective pass for review-increment-001 F1–F11, LED .49)

## What changed
All eleven review findings are discharged. ONE shared destination guard now exists —
`workspace._guarded_destination(destination, workarea_root=None) -> (resolved_destination,
resolved_root)` — used by BOTH placement kinds (`place_into_workarea`,
`place_group_into_workarea`, F1). It takes the work-area root from the destination AS GIVEN,
before any resolution: the nearest `.s19tool/workarea` ancestor of the unresolved path
(case-folded on Windows, with an 8.3 short-name fallback that reparse-checks each component
before resolving it — F8), or an explicit root an app-level caller passes via the new optional
`workarea_root` parameter of `place_into_workarea` (the B100-I14 surface, F2). Both sides are
resolved and compared only afterwards (`contained_in_workarea`), which is what refuses a
destination resolving into ANOTHER work area. Callers: the export runs `dest_dir` through the
guard and passes the same UNRESOLVED `dest_dir` to both placements; Save project's gather (4th
SOURCE file, ⚠ at cap per LED .49) routes `_check_home_contained` through the same guard and
hands the unresolved home to `copy_into_workarea`; the group placement runs the same guard.
`predict_placement` now returns the same resolved path FORM as the placement (F4). Also: the
LLR-163.1 boundary catalog is armed (upper-case `_2` on Windows, `_1` deleted beside an
identical `_2`, link candidate, 0-byte candidate — F3); the TC-B100-57 census counts rules by
behaviour with the declared R30/gather allow-list, and the group's word derivation is declared
in the packet §6 (F5); the tautological TC-B100-68 lines are deleted, arm deferred to Inc 5
(F6); the AST arm pins 1 claim loop per placement kind (2) per LED .49 (F7); the wrapper
docstring is restored, the dead block dropped, the reuse branch logs "Reused variant" (F9);
`copy_into_workarea` is off the staging allow-list (F10); the packet counts, ledger, evidence
rows and transcript file lists are corrected (F11) and `HANDOFF.md` stays untracked, out of
any commit.

## Verified
- RED first: `red-03-fix1-arms.txt` — 5 failed / 19 passed (the three junction caller arms
  fail with DID NOT RAISE = bytes in the victim; explicit-root arm: no such parameter;
  relative-destination arm: relative vs resolved path forms).
- Caller-specific RED proofs: `red-04-revert-export.txt`, `red-05-revert-group.txt`,
  `red-06-revert-gather.txt` — each junction arm re-run with ONLY that caller's change
  reverted → 1 failed each.
- GREEN: `green-03-fix1-arms.txt` (24 passed) · `green-04-staging.txt` (31) ·
  `green-05-gather-repins.txt` (55) · `green-06-census-files.txt` (92) ·
  `green-07-tui-files.txt` (63) · `green-08-remaining-census.txt` (355 + 1 pre-existing
  xfailed) · guards 75 passed / 29 snapshots unchanged (`guards.txt`) · census sweep 84
  passed (`guards-census.txt`).
- Mutants: 6 run, 6 KILLED, 6 reverted, restores SHA-256-verified against the fixed-state
  snapshot — `mut-F2.txt` (contained refusal removed), `mut-llr-163-1-fold.txt`,
  `mut-llr-163-1-barename.txt`, `mut-llr-163-1-link.txt`, `mut-llr-163-1-zero.txt` (F3 arms),
  `mut-llr-163-1-cap.txt` (the contract's second LLR-163.1 mutation, recorded per F11).
- CRLF uniform in all edited sources (0 bare LF); the two new test files converted to CRLF.
- Packet `increment-001.md` updated: §1 (fix-pass-1 BLUF), §2 (4 files ⚠ with the LED .49
  reason, `Traces to` for every new row), §4 (fix-pass-1 RED/GREEN/mutation rows with
  SHA-256, evidence table now 37 rows, ledger reconciled as 215 = 213 − 0 + 2 files and
  24 = 14 + 10 nodes), §5 (`place_group_into_workarea` risk now RESOLVED), §6 (F5 deviation,
  F6 deferral, F7 substitution, F8 decisions, F2 interface ruling), §4b left
  `pending — orchestrator`.

## Left / open
- §4b independent re-read of the fix by the code-reviewer (BLOCK — BLOCK-UNTIL: F1
  discharge) and the security-review routing of F1 belong to the orchestrator.
- The F5 group-word deviation and the F7 wording are declared in packet §6 for the
  orchestrator to accept or reject.

__KIMI_UNIT_DONE_FIX1__
Files changed: s19_app/tui/workspace.py (shared `_guarded_destination` guard, case-fold + short-name fallback, explicit-root param, predict resolves destination, F9 cleanups), s19_app/tui/segment_split_view.py (unresolved dest_dir through guard + both placements), s19_app/tui/app.py (reuse-branch log line), s19_app/tui/services/project_gather_service.py (guard-routed _check_home_contained, unresolved _gather_copy) — 4 source, at cap per LED .49; tests: test_b100_reuse.py +10 nodes (24 total), test_b99_staging.py allow-list tightened; packet + 17 fix-pass-1 transcripts.
Tests added: 10 nodes — F1 export/group/gather junction arms, F2 explicit-root arm, F3 four boundary arms, F4 relative-destination arm, F5 behavioural census, F6 tautology removed, F7 per-kind claim-loop AST; RED 1 module run + 3 caller-revert proofs (5 fix-pinning arms), GREEN 24 + 31 + 55 + 92 + 63 + 355 passed, guards 75 + census 84.
Mutations: 6 run (contained, fold, barename, link, zero, cap), all KILLED, all restores hash-verified; plus 3 caller-revert RED proofs for the TC-B100-62 junction arms.
Open questions: none blocking — orchestrator owns §4b re-read, the F1 security routing, and the accept/reject decisions on the §6 F5/F7 declarations.

---

# Fix pass 2 — batch-100 increment 1 (corrective pass for SEC-1/SEC-2, review round 2 N1–N5 + F9 nit, LED .50)

## What changed
LED .50 is implemented in full, in the same 4 SOURCE files. **App paths stay unresolved:**
`current_project_dir` is stored as the path under `self.workarea` (not `project_dir.resolve()`),
Save project builds its target with no `.resolve()`, and every reader of `current_project_dir` was
re-validated — no equality relied on the resolved form (comparisons resolve both sides at the
comparison point, never at storage; `b97_fixtures.py`'s stale comment updated). **App callers pass
the root:** `copy_into_workarea` and `place_group_into_workarea` gained the `workarea_root`
keyword (the wrapper's one-line AST shape is unchanged, the 15 frozen call sites ride the None
default); all 9 `app.py` placement calls (variant append, 3 Save copies, 2 MAC syncs, A2L sync,
2 temp-load copies) pass `workarea_root=self.workarea`; the gather and the export thread the root
from their app callers through the guard and every placement; the TC-B100-01 AST census arm pins
the 9 calls. **The walk reaches the outermost anchor (N1):** `_find_workarea_root` (and the 8.3
short-name fallback, mirroring) return the OUTERMOST `.s19tool/workarea` ancestor, so a junction
between this work area and a NESTED anchor is reparse-checked; the nested-anchor arm carries the
outermost→nearest revert as its RED side. **SEC-2:** the guard wraps both `resolve()` calls, and
both placement kinds plus the export's home mkdir wrap the destination creation — on Python 3.11
non-strict `resolve()` normalizes textually and the mkdir is the first filesystem touch, so the
wraps are what turn WinError 123 into the containment refusal (verified: without them the bare
`OSError` escapes). **N5:** the export's group word compares the pre-listing case-folded on
Windows. **F9 nit:** `_reuse_candidate_names` returns `list[str]`. **N3:** the census's
`_gather_copy` rule is declared owned by Inc 5 (no "Inc 3b" in this batch) — census comments and
packet updated. **N4:** the F8 upper-case anchor and 8.3 short-name fallback are armed
(`b100_links.short_path_name` helper); the `anchorcase` mutant is declared equivalent (the
fallback resolves the form anyway) and the fallback's stricter-than-textual reparse check is
declared as the SEC-3 false-refusal class — both declarations in packet §6.

## Verified
- RED first: 7 revert transcripts, each RED then hash-restored — `red-07-routes` (placement
  ignores the root), `red-08-save-copies` (wrapper drops it; Save + syncs arms), `red-09-gather`,
  `red-10-export`, `red-11-sec2` (bare WinError 123 escapes), `red-12-shortname` (fallback
  removed), `red-13-n5` (case-exact word). One no-op mutation attempt (LF/CRLF mismatch in the
  patch script) was discarded and the transcript re-recorded.
- Mutants (the two LED .50 declarations): `mut-census-root.txt` (root dropped from ONE app.py
  call → census arm KILLED it, naming the line) and `mut-n1-outermost.txt` (outermost→nearest →
  the nested-anchor arm KILLED it; the explicit-root half stays GREEN, named). All restores
  SHA-256-verified against `pre-mutation-hashes-fix2.txt`.
- GREEN: `green-09` module 36 passed (24+12) · `green-10` affected files 161 passed ·
  `green-11` remaining reverse-census files 147 passed, 4 failed — all 4 in
  `test_tui_patch_editor_v2`, the documented pre-existing order/timing flake present at base
  `e044112`; the same 4 nodes pass in isolation (`green-12-flake-isolation.txt`, 4 passed) ·
  guards 75 passed / 29 snapshot cells unchanged (`guards.txt`) · census sweep 84 passed
  (`guards-census.txt`).
- CRLF uniform in every edited file (0 bare LF). No commits made.
- Packet updated: §1 (fix-pass-2 BLUF), §2 (file table + counts), §4 (layer/node counts, the
  fix-pass-2 RED/GREEN/mutation table, reverse-census re-validation, node ledger 36 = 24 + 12),
  §5 (SEC-3 routed to `BACKLOG-CODE.md` §Routed, with the four out-of-cap callers' root threading),
  §6 (N3 → Inc 5, N4 declarations, N5 closed, F2 completion note). §4b left
  `pending — orchestrator`. Evidence digests re-derived with
  `devflow-evidence.py --root . --write <packet> --rederive` (N2) — 51 artifacts, `--check` shows
  only "not staged" (no commits, per the rules), zero digest mismatches.

## Left / open
- §4b independent review of fix pass 2 and the SEC-1 discharge belong to the orchestrator.
- SEC-3 and the four out-of-cap callers' explicit-root threading are routed to the backlog by
  LED .50 — not implemented here (4-file cap).
- The `test_tui_patch_editor_v2.py` order/timing flake (present at base) remains for the
  qa-reviewer; fix pass 2 neither caused nor worsens it.

__KIMI_UNIT_DONE_FIX2__
Files changed: s19_app/tui/workspace.py (outermost-anchor walk N1, SEC-2 resolve+mkdir wraps, workarea_root on copy/group, F9 nit), s19_app/tui/segment_split_view.py (workarea_root threading, N5 case-folded group word, SEC-2 home-mkdir wrap), s19_app/tui/app.py (unresolved current_project_dir + Save target, 9 placement calls + gather pass workarea_root), s19_app/tui/services/project_gather_service.py (workarea_root threaded through _check_home_contained/_gather_copy/gather_project_artifacts) — 4 source, at cap per LED .50; tests: test_b100_reuse.py +12 nodes (36 total), b100_links.py short_path_name helper, b97_fixtures.py comment; packet + 16 fix-pass-2 transcripts.
Tests added: 12 nodes — the root census AST arm, 5 explicit-root route arms (variant append, Save copies, syncs, gather, export), 2 nested-anchor arms (N1), SEC-2 invalid-spelling arm, 2 F8 anchor arms (N4), N5 group-word arm.
RED/GREEN: RED 7 revert transcripts; GREEN 36 (module) + 161 + 147 + 4 (flake isolation) passed, guards 75 + census sweep 84.
Mutations: 2 declared (census root-drop, N1 outermost→nearest) both KILLED + 7 RED reverts, all restores SHA-256-verified; zero digest mismatches after the devflow-evidence --rederive.
Open questions: none blocking — orchestrator owns §4b, the SEC-1 security re-read, and the backlog routing confirmations (SEC-3, four out-of-cap callers, N4 equivalence declarations).

# Fix pass 3 — batch-100 increment 1 (corrective pass 3, BOUNDED; review round 3 R3-1/R3-2/R3-3, LED .50)

## What changed
R3-1 (HIGH, the round-3 BLOCK — regression of fix pass 2) is fixed in
`s19_app/tui/segment_split_view.py`: `write_split_join_export` no longer rebinds `workarea_root` to
the guard's RESOLVED root. The guard's return is held in a distinct `resolved_root` used only for
the staging paths (`stage_worst`, `_private_stage_dir`); both placements re-run the guard on the
UNRESOLVED `dest_dir` with the CALLER'S root, so an app whose base folder is reached through a
junction exports into its work area again (the base and fix-pass-1 behaviour). New arm
`test_tc_b100_62_export_junctioned_base_app_root_writes`: junctioned base + the app root writes
exactly `t_isle.s19` into the real work area, byte-oracle clean.
R3-2: `app.py` `_active_project_dir`'s fallback drops `.resolve()` — app paths stay unresolved end
to end (LED .50); the last resolved-handout is gone.
R3-3: `gather_project_artifacts` takes `workarea_root` keyword-only with NO default — the
default-unsafe API the reviewer's `r3_gather_projjunction.py` probe escaped through is closed at the
only boundary the app can reach (omission → `TypeError`, new arm
`test_tc_b100_62_gather_requires_workarea_root`). The four test callers re-pin to pass their work
area (`test_b99_staging.py` ×2, `test_project_gather.py` ×2), each recorded as `old → new` under
LED .50 in packet §6.
R3-4 untouched per the brief (orchestrator routes it to the backlog).

## Verified
- RED first: `red-14-r3-1-junctioned-base.txt` — 2 failed on the fix-pass-2 tree: the export arm
  refused with "traverses a symbolic link or reparse point" (the reviewer's probe shape; base and
  fix pass 1 WROTE) and the gather arm did not raise `TypeError`.
- GREEN: `green-13-reuse-module.txt` 38 passed (36+2) · `green-14-affected.txt` 161 passed — every
  export and junction arm still refuses an escape, the four re-pins green ·
  `green-15-active-dir-census.txt` 98 passed, 1 xfailed (`_active_project_dir` census files) ·
  guards 75 passed / 29 snapshot cells unchanged (`guards.txt`) · census sweep 84 passed
  (`guards-census.txt`).
- Mutants re-run (the brief's two): `mut-n1-outermost-fix3.txt` KILLED (nested-anchor arm DID NOT
  RAISE; the explicit-root half stays GREEN) and `mut-census-root-fix3.txt` KILLED (census arm names
  the call site and line) — both restores SHA-256-verified against
  `pre-mutation-hashes-fix3.txt` (`RESTORE OK`); no mutant left in place.
- CRLF uniform in every edited file (0 bare LF); source cap holds at exactly 4 files. No commits.
- Packet updated: §1 (fix-pass-3 BLUF), §2 (file rows + the new `test_project_gather.py` row + the
  two re-pin rows + test-file count 9), §4 (layer count 38, the fix-pass-3 RED/GREEN/mutation
  table, evidence rows with re-derived SHA-256), §6 (R3-1/R3-2 closed, the R3-3 bounded-pass
  deviation, R3-4 routing). §4b left `pending — orchestrator`. `devflow-evidence.py --rederive`
  written (58 artifacts); `--check` shows only "not staged" (no commits, per the rules), zero
  digest mismatches.

## Left / open
- The R3-3 bounded-pass deviation for the orchestrator to confirm: the no-default required root is
  applied to `gather_project_artifacts` only; the private seams `_check_home_contained` /
  `_gather_copy` keep the `None` derivation because their no-root production caller `scoped_home`
  reaches `folder_open_service.py` and `crc_designer_view.py`, outside the LED .50 4-file cap (the
  R3-4/backlog family). The demonstrated escape entered through the public default, now impossible.
- The reviewer's recommended `_guarded_destination` hardening (resolved-vs-textual root comparison
  instead of walking past a textually-unmatched destination) is NOT applied — bounded pass; belongs
  in the LED .50 backlog entry with SEC-3.
- §4b independent review of fix pass 3 belongs to the orchestrator; R3-4 and the `scoped_home`
  root-threading wait for the backlog routing.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/segment_split_view.py (R3-1: distinct resolved_root for staging, caller's root to both placements), s19_app/tui/app.py (R3-2: unresolved _active_project_dir fallback), s19_app/tui/services/project_gather_service.py (R3-3: required keyword-only workarea_root on gather_project_artifacts) — 3 of the 4 capped sources; tests: test_b100_reuse.py +2 nodes (38 total), test_b99_staging.py +2 re-pins, test_project_gather.py +2 re-pins; packet + 9 fix-pass-3 transcripts.
Tests added: 2 nodes — the junctioned-base export arm (R3-1) and the gather-root TypeError arm (R3-3); re-pins: 4 gather_project_artifacts callers pass their work area (old → new under LED .50).
RED/GREEN: RED 1 transcript (2 failed); GREEN 38 (module) + 161 (affected) + 98/1xf (active-dir census) passed, guards 75 + census sweep 84.
Mutations: N1 outermost→nearest and census root-drop re-run, both KILLED, restores SHA-256-verified; zero digest mismatches after the re-derive.
Open questions: orchestrator to confirm the R3-3 bounded deviation (private seams keep the None derivation) and to route R3-4 + the _guarded_destination hardening to the LED .50 backlog; §4b review of fix pass 3.
