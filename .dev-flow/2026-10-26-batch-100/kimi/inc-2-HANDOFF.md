# HANDOFF — batch-100 Increment 2 (Save project name guards)

Worktree: C:\Users\jjgh8\Github\s19_app-b100-inc2 (detached at 2edfee2, Inc 1 merged).
Nothing committed — all changes are in the working tree. Do not commit; the orchestrator does.

## What was done

Read `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-2.md`, design `design-proposal-b100.md` §5.2,
contract `01-requirements.md` HLR-164 / LLR-164.1–164.4 with the UX-07 refusal token table, LED
.19/.20/.22 (worker-census note is Inc 12's, not this increment's) and LED .49/.50 (app paths
stay unresolved; every app placement call passes `workarea_root=self.workarea` — preserved: the
Save target is built with no `.resolve()`).

Sources (2):
- `s19_app/tui/workspace.py` — `PROJECT_NAME_MAX_CHARS = 64` and `is_windows_device_name`
  (one shared predicate: case-folded, extension- and superscript-digit tolerant).
- `s19_app/tui/app.py` — `_handle_save_dialog`: ordered pre-`mkdir` guards (empty → device on
  raw/components/sanitised → reserved case-folded → 64-cap → full-path limit 53/259 → Q-2
  disguised clash naming both with the open-project exemption → link/junction before
  `resolve()`); ONE `OSError` handler over the whole post-creation body (`could not save` /
  `check the folder` + `_remove_created_project_dir`); every post-creation early return removes
  the folder; `current_project`/`current_project_dir` install on success only;
  `list_projects` case-folded reserved filter; `_write_and_verify_manifest -> bool`.

Tests: `tests/test_b100_save_guards.py` (TC-B100-04/05/06/07 + AT-B100-02, 18 nodes);
`tests/test_id_registry.py` bound 215 → 216 (measured).

## Verification (all transcripts under .dev-flow/2026-10-26-batch-100/evidence/inc-2/)

- RED at base: `red-01-save-guards.txt` (collection ImportError, exit 2 — same shape as Inc 1).
- GREEN: `green-04-save-guards.txt` (18 passed); A-09 unchanged `green-02-a09-variant.txt`.
- Mutations (all KILLED, restores hash-verified vs `pre-mutation-hashes.txt`):
  `mut-llr-164-1.txt` (sanitised-only device check), `mut-llr-164-2.txt` (clash bypass),
  `mut-llr-164-3.txt` (path limit disabled), `mut-llr-164-4.txt` (removal deleted).
- Reverse census: 16 files, 400 passed + 1 xfailed, 0 re-pins
  (`reverse-census-{1,2,3}.txt`); symbol census verbatim in `correction-population.txt`.
- Guards: `guards.txt` 75 passed + 29 snapshot cells unchanged (none changed, as required);
  `guards-census.txt` 85 passed.

## Deliverables

- Packet: `.dev-flow/2026-10-26-batch-100/03-increments/increment-002.md` (§4b
  `pending — orchestrator`).
- Evidence + digests: `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`.
- Working tree: `s19_app/tui/app.py`, `s19_app/tui/workspace.py`,
  `tests/test_b100_save_guards.py`, `tests/test_id_registry.py` (all CRLF preserved).

## Open questions

- §6 of the packet records one clarification for the orchestrator: HLR-164's black-box phrase
  "P2 open" was read as a loaded file with project `ab` NOT open (consistent with LLR-164.2's
  open-project exemption); the exemption itself is armed at TC level.

__KIMI_UNIT_DONE_ROUND1__
Files changed: s19_app/tui/app.py, s19_app/tui/workspace.py, tests/test_b100_save_guards.py (new), tests/test_id_registry.py, plus packet + 16 evidence transcripts.
Tests added: TC-B100-04/05/06/07 + AT-B100-02 — 18 nodes (1 Windows-only junction arm), registry bound 215→216 measured.
RED/GREEN: RED = base collection error (exit 2) for the new module; GREEN = 18 passed + A-09 guard + 400 census + 75 guards + 85 census-sweep.
Mutations: 4 applied (one per LLR-164.x), 4 KILLED, 4 reverted, restores proven by SHA-256.
Open questions: the "P2 open" reading of HLR-164's acceptance phrase (packet §6); §4b independent review pending the orchestrator.


## Fix pass 1 — review F1–F11, SEC2-1..3, LED .52 (a)/(b)/(c)

Read `kimi/BRIEF-inc-2-fix1.md`, `review-increment-002.md` (F1–F11),
`security-increment-002.md` (SEC2-1..3) and ledger LED .52. Sources stay at 2:
`s19_app/tui/app.py`, `s19_app/tui/workspace.py`.

**Code:**
- F1 + F5 + SEC2-3 + LED .52(b): one `_abort_save` helper in `app.py` — every
  post-creation failure exit (validation, MAC, A2L, manifest write, placement,
  containment, OSError) rolls back through it: restores `_variant_set`, the
  current variant, `_report_filter_path` and `current_project` from the
  pre-save snapshot; unlinks every placed file not in the pre-save folder
  snapshot (byte-identical reuse kept); removes the folder this call created.
  The `Saved project to …` line paints only after `project.json` is on disk.
- F3 + SEC2-2: `is_windows_device_name` takes the stem up to the FIRST dot,
  strips trailing spaces/dots; port digit 0–9 plus the ¹²³ fold; `COM⁴` is
  not a device name.
- F4 + LED .52(a): the open project's on-disk name typed in another case
  saves into it under the ON-DISK spelling (`current_project` keeps it); a
  case-only match against ANOTHER project stays a clash.
- F8 + SEC2-1: the clash scan compares the name first, lists inside only the
  matching folder, and skips an unreadable folder (`except OSError`), never
  raising.
- F2/F10/F11: packet-only (trace row fixed to HLR-164; 32 hashed artifacts;
  env lines in every transcript header; the workarea-vs-parent-field note
  recorded as an Inc 11 dependency).

**Tests** (`tests/test_b100_save_guards.py`, 18 → 27 nodes): F6 empty-name
arm; F3 multi-dot/trailing-space arms + a predicate unit arm; F4 case-variant
+ case-only-against-another arms; F1 state assertions in every forced-failure
arm + a `manifest-refused` stage; F5 three failed-merge arms; F8 `icacls`
deny-folder arm (Windows-only); F9 folder-list oracle + phantom `sPlItS`
dropped; F7 AT-B100-02 builds `prg` (P2) and `ab` by real saves and opens P2
through the shipped Load project surface by keys (rail `1` +
`#ws_load_project_button` — the Segment Split window binds `p`), refusing
`a b` naming `ab`.

**Verification** (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`):
RED first on the unfixed tree (`red-fix1-save-guards.txt`, 14 failed / 13
passed); GREEN module 27 passed (`green-fix1-save-guards.txt`); A-09 guard 1
passed; reverse census 398 passed + 1 xfailed + 2 re-pinned nodes green
(3 re-pins recorded: the TC-07 census, `test_at_b99_05…` status order,
`test_tc_b99_13…` LLR-155.3 allow-list gains `_abort_save`); guards 75
passed (no snapshot cell changed); census sweep 85 passed; 6 fix-pass-1
mutants (M6, M7, M-F1, F3, F4, F5) all KILLED, reverts hash-verified against
`pre-mutation-hashes-fix1.txt` (app.py b2dcf23c…, workspace.py d2137e1d…).
Packet §1/§2/§4/§5/§6 updated; §4b left `pending — orchestrator`.

__KIMI_UNIT_DONE_FIX1__
Files changed: s19_app/tui/app.py, s19_app/tui/workspace.py, tests/test_b100_save_guards.py (18→27 nodes), tests/test_b99_staging.py (2 re-pins), plus packet + 17 new evidence transcripts.
Tests added: empty-name, device predicate unit, case-variant + case-only-against-another, manifest-refused stage, 3 failed-merge arms, deny-folder arm, F1 state assertions in all forced arms; AT-B100-02 now drives P2-open-by-keys.
RED/GREEN: RED = 14 failed / 13 passed on the unfixed tree; GREEN = 27 + A-09 1 + census 398+1x + guards 75 + sweep 85.
Mutations: 6 applied (M6, M7, M-F1, M-F3, M-F4, M-F5), 6 KILLED, 6 reverted, restores proven by SHA-256.
Open questions: none — §4b independent review of the fix pass is with the orchestrator.

## Fix pass 2 — review round 2 R2-1..R2-5, SEC2-4

Read `kimi/BRIEF-inc-2-fix2.md`, `review-increment-002.md` §"Round 2" (R2-1..R2-5),
`security-increment-002.md` §"Round 2" (SEC2-4 and its trap). Sources stay at 2:
`s19_app/tui/app.py`, `s19_app/tui/workspace.py` (workspace untouched this pass).

**Code:**
- R2-1 + SEC2-4: the pre-save snapshot is now RECURSIVE — `_project_tree_snapshot`
  records every file AND folder under the project folder (POSIX relative paths)
  before ANY placement; `_abort_save` removes every path absent from it, DEEPEST
  FIRST (files before the folders that hold them; a folder only when empty), and
  never a path the snapshot recorded — so the gather's change/check copies in
  `patches/` / `checks/` / `templates/` with their home folders roll back too,
  and a byte-identical file reused at a pre-existing path survives. `placed_paths`
  is gone; `preexisting_names` (the bare top-level name set) is gone.
- R2-3: the committed block (the `Saved project to …` line, `current_project` /
  `current_project_dir` install, `update_project_labels()`, `refresh_files()`)
  moved OUT of the rollback `try` — once `project.json` is on disk an error there
  is never rolled back.
- R2-5: `_write_and_verify_manifest` publishes the verify outcome on
  `self._last_manifest_verify_result`; the handler re-paints
  `Manifest verify MISMATCH` as the NEWEST status line after
  `Saved project to …` (notice still fires once, inside the verify surfacing).
- R2-4: the AST census accepts ONLY `_abort_save` for post-creation exits.

**Tests** (`tests/test_b100_save_guards.py`, 27 → 31 nodes):
- `test_tc_b100_07_failed_save_removes_every_placed_path` (3 arms): a merge into
  `ab` with `batch=("hotfix.json",)` forced to fail at the manifest — the target
  tree (files AND folders) equals the pre-save snapshot exactly; the same with a
  pre-existing byte-identical `patches/hotfix.json` — it survives; a fresh-folder
  save that fails — no folder left behind.
- `test_tc_b100_07_manifest_mismatch_is_the_newest_status_line`: a forced verify
  MISMATCH — `Manifest verify MISMATCH` is the newest painted line, after
  `Saved project to …`.

**Verification** (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`):
RED first on the fix-pass-1 tree (`red-fix2-save-guards.txt`, 2 failed / 29
passed — the `merge-gathered` arm and the mismatch arm); the SEC2-4 trap is
demonstrated RED against the naive bare-name variant applied by hand and
reverted (`red-fix2-naive-trap.txt`, 2 failed — the rollback DELETES the reused
pre-existing `patches\hotfix.json`); GREEN module 31 passed
(`green-fix2-save-guards.txt`); A-09 guard + both b99 re-pinned nodes 3 passed
(`green-fix2-guards-nodes.txt`); 5 mutants all KILLED — M-R2-1 (top-level
snapshot, killed by the reuse arm), M-R2-4 (one exit reduced to a bare removal —
the CENSUS goes RED, 4 failed), M-R2-5 (re-paint skipped), M-F6a and M-S-F5
(the two mutants pre-named in `test_b99_staging.py`) — reverts hash-verified
against `pre-mutation-hashes-fix2.txt` (`restore-fix2.txt`, `RESTORE OK`).
Reverse census: 16 files, 431 passed + 1 xfailed, 0 new re-pins
(`reverse-census-fix2-{1,2,3}.txt` + `correction-population-fix2.txt`); guards
75 passed, no snapshot cell changed (`guards-fix2.txt`); census sweep 85 passed
(`guards-census-fix2.txt`). Packet §1/§2/§4/§6 updated — §2 now carries the
`tests/test_b99_staging.py` row (Kind `test`, Traces `LLR-164.4` · `LLR-155.3`,
the two re-pins named) and the test-file count is 3; the evidence table holds 50
hashed artifacts (digests re-derived with `devflow-evidence.py --write …
--rederive`); §4b left `pending — orchestrator`. CRLF preserved (app.py
14038/14038, test file 1380/1380). Nothing committed.

__KIMI_UNIT_DONE_FIX2__
Files changed: s19_app/tui/app.py (recursive-snapshot rollback, committed block outside the try, mismatch re-paint), tests/test_b100_save_guards.py (27→31 nodes), plus packet + 18 new evidence transcripts.
Tests added: the 3-arm recursive-tree rollback node (merge-gathered / merge-gathered-reused / fresh-gathered) and the manifest-MISMATCH newest-status node; the census re-pinned to _abort_save ONLY (R2-4).
RED/GREEN: RED = 2 failed / 29 passed on the fix1 tree + the 2-failed naive-trap demo; GREEN = 31 + A-09/b99 3 + census 431+1x + guards 75 + sweep 85.
Mutations: 5 applied (M-R2-1, M-R2-4, M-R2-5, M-F6a, M-S-F5), 5 KILLED, 5 reverted, restores proven by SHA-256.
Open questions: none — §4b independent review of fix pass 2 is with the orchestrator.

## Fix pass 3 — review round 3 R3-1, R3-2 (bounded pass)

Read `kimi/BRIEF-inc-2-fix3.md` and `review-increment-002.md` §"Round 3"
(R3-1 HIGH, R3-2 MINOR). Sources stay at 2: `s19_app/tui/app.py`,
`s19_app/tui/workspace.py`. The pass is BOUNDED — only the two findings
were touched.

**Code:**
- R3-1: the ONE reusable walker `walk_tree_no_links(root)` in
  `workspace.py` — `os.scandir` with `follow_symlinks=False`, each
  directory child re-checked with the lstat-based `_is_reparse_point`
  (on 3.11 a junction reads as a plain directory to `DirEntry.is_dir`),
  a symlink/junction yielded as a LEAF and never entered, explicit-stack
  depth-first so a `loop -> root` cycle cannot loop the walk. BOTH the
  pre-save snapshot (`_project_tree_snapshot`) and the rollback's removal
  walk (`_abort_save`) consume it — `rglob` is gone from the save
  rollback. The rollback never reaches a reparse point's target (nothing
  outside the work area is deletable through a junction) and removes a
  junction only if this save created it (it creates none). Written for
  reuse by save-as in Inc 8b (LLR-171.1) — named in the packet §5.
- R3-2: `self._last_manifest_verify_result` initialised in `__init__`,
  next to `_variant_set`.

**Tests** (`tests/test_b100_save_guards.py`, 31 → 34 nodes):
- `test_tc_b100_07_rollback_never_touches_junction_target`
  (Windows-only): a junction `ab\ext` → an outside victim folder; a
  concurrent writer (patched into the gather) drops `user-work.txt` into
  the victim and the save fails — the outside file SURVIVES and the
  project tree (a reparse-aware listing, test-side) equals its snapshot.
- `test_tc_b100_07_junction_cycle_does_not_block_save` (Windows-only):
  `ab\loop` → `ab`; the exact-name merge saves (`Saved project`, no
  `could not save`, no ~260-character path error) and every pre-existing
  path survives.
- `test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf`
  (Windows-only): the walker yields `ext`/`loop` as leaves, never
  `ext/inner/secret.txt`, terminates on the cycle.

**Verification** (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`):
RED first on the fix-pass-2 tree (`red-fix3-save-guards.txt`, 3 failed —
the outside file DELETED, the cycle refused with `[WinError 3] …
ab\loop\loop\…`, the walker ImportError); GREEN module 34 passed
(`green-fix3-save-guards.txt`, 205 s); A-09 guard + both b99 re-pinned
nodes 3 passed (`green-fix3-guards-nodes.txt`); reverse census 434 passed
+ 1 xfailed across `reverse-census-fix3-{1,2,3}.txt` (16 files, the grep
gains `walk_tree_no_links`, population unchanged — `correction-population-fix3.txt`),
no new re-pins; guards 75 passed, no snapshot cell changed
(`guards-fix3.txt`); census sweep 85 passed (`guards-census-fix3.txt`).
New mutant M-R3-1 (the walker follows reparse points) KILLED by the
junction-target arm (`mut-fix3-r31.txt`); the three fix-pass-2 rollback
mutants re-run on this tree all stay KILLED (`mut-fix3-mr1.txt` 1 failed,
`mut-fix3-mr2.txt` 6 failed, `mut-fix3-mr3.txt` 1 failed); all four
reverts hash-verified (`restore-fix3.txt`, `RESTORE OK` — snapshot
`pre-mutation-hashes-fix3.txt`: app.py fee2d17a…, workspace.py
2f6dbdb4…). LED .50 sweep: 0 added `.resolve()`, no new placement calls.
Packet §1/§2/§4/§5/§6 updated — 65 hashed evidence artifacts; §4b left
`pending — orchestrator`. CRLF preserved (app.py 14050/14050,
workspace.py 2002/2002, test file 1547/1547). Nothing committed.
Route to `security-reviewer` per the round-3 hand-off (a deletion
through a reparse point, now closed).

__KIMI_UNIT_DONE_FIX3__
Files changed: s19_app/tui/workspace.py (walk_tree_no_links — the one non-following walker), s19_app/tui/app.py (snapshot + removal walk use it; _last_manifest_verify_result init), tests/test_b100_save_guards.py (31→34 nodes), plus packet + 15 new evidence transcripts.
Tests added: Windows-only junction-target rollback arm, junction-cycle arm, walk_tree_no_links unit arm (RED first: 3 failed on the fix2 tree).
RED/GREEN: RED = 3 failed; GREEN = 34 + A-09/b99 3 + census 434+1x + guards 75 + sweep 85; new mutant M-R3-1 KILLED + 3 rollback mutants re-killed, reverts SHA-256-proven.
Mutations: 4 applied (M-R3-1 new, M-R2-1/M-R2-2/M-R2-3 re-runs), 4 KILLED, 4 reverted, restores proven by SHA-256.
Open questions: none — §4b independent review of fix pass 3 is with the orchestrator; the pass was bounded, so anything beyond R3-1/R3-2 stays with the orchestrator as recorded.

## Redesign (LED .53) — the rollback removes exactly what the save created

Read `kimi/BRIEF-inc-2-fix4.md`, ledger LED .53, `security-increment-002.md` Round 3
(SEC2-5 MAJOR / SEC2-6, probes R7/R8) and `review-increment-002.md` Round 4. Sources are
now 3: `s19_app/tui/app.py`, `s19_app/tui/workspace.py` and
`s19_app/tui/services/project_gather_service.py`. The previous `__KIMI_UNIT_DONE__`
marker was already renamed `__KIMI_UNIT_DONE_FIX3__` by fix pass 3.

**Code:**
- `project_gather_service.py`: `GatherOutcome` gains `written: list[Path]` (files the
  gather actually wrote — recorded only on `copied=True`, so a reused byte-identical
  sibling never appears) and `created_homes: list[Path]` (project homes created on
  demand — a home's existence is read BEFORE the copy decides). `_gather_copy` is
  untouched (still places through `copy_into_workarea`, the LLR-155.3 census holds).
- `app.py`: the snapshot-difference rollback is gone. `_project_tree_snapshot`,
  `_remove_created_project_dir` and the diff walk are removed; the save body places the
  image/MAC/A2L through `place_into_workarea` so `PlacementResult.reused` is known, and
  collects `placed_files` (non-reused placements + `gather_outcome.written`) and
  `created_dirs` (`gather_outcome.created_homes`). `_abort_save` restores the app state
  (unchanged, LED .52(b)), unlinks exactly `placed_files`, then rmdirs the created
  folders deepest first, each only while empty. It walks no folder and diffs against no
  snapshot. The manifest-MISMATCH re-paint and the committed block are unchanged.
- `workspace.py`: `walk_tree_no_links` stays, with its unit arm, for Inc 8b's save-as
  (LLR-171.1) — the Save rollback is no longer its consumer; docstrings updated.
- R7 (SEC2-5) and R8 (SEC2-6) close by construction: a pre-existing file the snapshot
  was blind to, and a concurrently written file, are never in the placed list.

**Tests** (`tests/test_b100_save_guards.py`, 34 → 36 nodes):
- `test_tc_b100_07_rollback_keeps_denied_folder_content_r7` (Windows-only): `ab/patches`
  read-denied (`icacls /deny …:(RD)`) at save start, `keep.json` pre-existing, the deny
  lifted inside the forced manifest writer, then the save refused — `keep.json` survives
  AND the placed `firmware.s19` is removed.
- `test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8`: another writer creates
  `ab/notes.txt` during the save, then the save is refused — `notes.txt` survives,
  the placed file is removed.
- Re-pins (recorded in the packet §4): the forced-failure `copies` stage now breaks
  `app_module.place_into_workarea` (the seam the save body calls since LED .53); the AST
  census's folder-removal pin is `_abort_save` containing `rmdir` (the
  `_remove_created_project_dir` helper is gone). The census's standing rules are
  unchanged: every post-creation exit rolls back through the ONE `_abort_save`, and
  `_abort_save` restores the pre-save app state.
- `tests/test_b99_staging.py`: the LLR-155.3 allow-list comment updated in place (the
  `_abort_save` entry unchanged — every unlink is one path of the placed-files list).

**Verification** (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`):
RED first on the fix-pass-3 tree (`red-fix4-r7-r8.txt`, 2 failed — the old rollback
DELETES `keep.json` and `notes.txt`, the exact deletions the round-3 probe executed);
GREEN module 36 passed (`green-fix4-save-guards.txt`, 240 s — the kept arms stay green:
merge-gathered ×3, fresh-folder, junction ×2, the F1 state assertions, the MISMATCH
re-paint). Mutants: (a) reused placements removed too → KILLED by the open-case arm
(`mut-fix4-a.txt`, 1 failed); (b) the snapshot difference back → KILLED by R7+R8
(`mut-fix4-b.txt`, 2 failed); (c) `written` including reused files → KILLED by
merge-gathered-reused (`mut-fix4-c.txt`, 1 failed) — all three reverts hash-verified
(`restore-fix4.txt`, `RESTORE OK` — app.py fcb1bf400645…, workspace.py 8ef1763e180c…,
project_gather_service.py c2d8cc2864a1…; the 6 discriminating arms re-run green on the
reverted tree). Reverse census: 16 files, 436 passed + 1 xfailed across the module run
+ `reverse-census-fix4-{1,2}.txt` (369 + 1 xfailed, 31 — `test_b99_staging.py` green
incl. the LLR-155.3 final-name census over the redesigned `_abort_save`); the A-09
guard and both b99 re-pins re-verified inside the census chunks. Guards 75 passed + 29
snapshot cells unchanged (`guards-fix4.txt`); census sweep 85 passed
(`guards-census-fix4.txt`). CRLF preserved (app.py 14046/14046, workspace.py 2003/2003,
gather service 719/719, test file 1676/1676, b99 staging 2278/2278). Packet §1/§2/§4/§5/§6
updated — 3 SOURCE files (`project_gather_service.py` traced to LLR-164.4), 78 hashed
evidence artifacts; §4b left `pending — orchestrator`. Nothing committed.

__KIMI_UNIT_DONE_REDESIGN__
Files changed: s19_app/tui/app.py (exact-list rollback; snapshot machinery removed), s19_app/tui/workspace.py (walker docstrings only), s19_app/tui/services/project_gather_service.py (GatherOutcome.written/created_homes), tests/test_b100_save_guards.py (34→36 nodes + 2 re-pins), tests/test_b99_staging.py (comment), plus packet + 13 new evidence transcripts.
Tests added: test_tc_b100_07_rollback_keeps_denied_folder_content_r7 (Windows-only) and test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8; RED first: 2 failed on the fix-pass-3 tree.
RED/GREEN: RED = 2 failed (fix3 tree); GREEN = 36 module + census 436+1x (16 files) + guards 75 (29 snapshot cells unchanged) + sweep 85.
Mutations: 3 applied ((a) reused placements removed, (b) snapshot difference back, (c) written includes reused), 3 KILLED, 3 reverted, restores proven by SHA-256.
Open questions: none — §4b independent review of the redesign is with the orchestrator; Inc 8b must consume walk_tree_no_links and the GatherOutcome exact-created lists as §5 records.

## Redesign fix pass — SEC2-7/8/9 (security round 4), R5-1/R5-2 (review round 5)

Read `kimi/BRIEF-inc-2-fix5.md`, `security-increment-002.md` Round 4 (SEC2-7 HIGH,
SEC2-8/9 MAJOR) and `review-increment-002.md` Round 5 (R5-1 MAJOR, R5-2 MINOR). Sources
stay at 3: `s19_app/tui/app.py`, `s19_app/tui/workspace.py`,
`s19_app/tui/services/project_gather_service.py`. The design stays — a failed save removes
exactly what it created; this pass fixes its implementation.

**Code:**
- SEC2-7: `_gather_copy` calls `place_into_workarea` and translates ONLY its
  `PlacementResult.reused` flag into the `copied` word — the placement (case-folded on
  Windows, LLR-163.1) is the sole byte-identity judge. The gather's own case-sensitive
  pre-check (`_same_artifact_name` + the sibling `read_bytes` scan) is RETIRED — the
  function is deleted. A byte-identical file under a case-variant name (`BOOST.json`,
  `boost.JSON`) is reused, never recorded in `written`, never deleted by a rollback.
  The TC-B100-57 census is re-pinned (re-pin 6): the declared-rules set drops the gather
  entry; `workspace.place_into_workarea`'s stale docstring passage updated.
- SEC2-8: `_write_and_verify_manifest` gains an `on_written` hook invoked the moment the
  manifest write returns, before the verify can raise. When no manifest pre-existed, the
  handler appends the written `project.json` to `placed_files` right there — a failure
  after that point (a forced verify re-read raise) leaves no folder behind.
- SEC2-9: a merge keeps the previous `project.json` bytes in memory before the write;
  the hook arms `(path, previous-bytes)` in `manifest_restores`; `_abort_save` consumes
  it FIRST — staged in the private staging home (`workspace._private_stage_dir`), put
  back with `os.replace` (atomic), never raising — then the unlinks and the folder
  removals. All 7 abort exits pass the list.
- R5-1: the gather records a home as created from whether it NOW exists on BOTH the
  copy-success and copy-failure paths (`not home_preexisted and home_dir.is_dir()`), so
  a home the placement mkdir'd before a dying copy (a full disk) is removed by the
  rollback.
- R5-2: new arm — an empty pre-existing `patches/` survives a failed save; kills Mf
  (round 5's survivor).

**Tests** (`tests/test_b100_save_guards.py`, 36 → 43 nodes): the headless census/unit arm
(`written` never holds a reused file + a fresh-write control limb), the two case-variant
save arms (Windows-only), the fresh-verify no-folder arm (SEC2-8), the merge-verify
manifest-restore arm (SEC2-9), the disk-full gather-home arm (R5-1), the
empty-pre-existing-home arm (R5-2). `tests/test_b100_reuse.py`: the TC-B100-57 census
re-pin (38 passed).

**Verification** (all under `.dev-flow/2026-10-26-batch-100/evidence/inc-2/`):
RED first against the reconstructed pre-pass tree — the three sources reversed
byte-exact (`pre-mutation-hashes-fix5.txt` re-derived for the reconstruction; gather +
workspace hashes equal the recorded pre-pass digests): 6 failed / 3 passed
(`red-fix5-new-arms.txt` — the reused-in-`written` arm, both case-variant arms deleting
the pre-existing file, `freshv` left behind, `project.json` not restored, the R5-1 arm's
first form superseded by the behavioral `red-fix5-r5-1.txt` showing `freshp` left
behind) + 1 failed (`red-fix5-census57.txt`). GREEN module 43 passed
(`green-fix5-save-guards.txt`, 241 s — every kept arm stays green). Reverse census on
this tree: 38 (`test_b100_reuse.py`) + 48 (`test_b99_staging.py` incl. the LLR-155.3
final-name census over the SEC2-9-extended `_abort_save`, `test_project_gather.py`,
`test_copy_into_workarea_content_dedup.py`) + 29 (`test_tui_report_seam.py` + the A-09
guard node) = 158 with the module (`reverse-census-fix5-{1,2,3}.txt`,
`correction-population-fix5.txt`). Guards 75 passed + 29 snapshot cells unchanged
(`guards-fix5.txt`); census sweep 85 (`guards-census-fix5.txt`). Mutants — 6/6 KILLED:
Mf now dies on the empty-home arm (`mut-fix5-mf.txt`), sec2-8 (`mut-fix5-sec2-8.txt`),
sec2-9 (`mut-fix5-sec2-9.txt`), r5-1 (`mut-fix5-r5-1.txt`), fix4-(a) and fix4-(c)
re-run on this tree (`mut-fix5-fix4-a.txt` 1 failed, `mut-fix5-fix4-c.txt` 3 failed) —
all reverts hash-verified against `pre-mutation-hashes-fix5-mutants.txt` (app.py
e30805c44126…, workspace.py 2ab2ba749fb5…, project_gather_service.py bc8b6eeacac4…;
`RESTORE OK`). CRLF preserved (app.py 14116/14116, workspace.py 2004/2004, gather service
682/682, test files 1998/1998 + 1358/1358). Packet §1/§2/§4/§6 updated — 101 hashed
evidence artifacts, 1 re-pin recorded (TC-B100-57); §4b left `pending — orchestrator`.
Nothing committed.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/app.py (SEC2-8/9: on_written hook, manifest keep/restore in _abort_save), s19_app/tui/workspace.py (docstring only), s19_app/tui/services/project_gather_service.py (SEC2-7: placement is the sole reuse judge, _same_artifact_name retired; R5-1: home recorded on both copy paths), tests/test_b100_save_guards.py (36→43 nodes), tests/test_b100_reuse.py (TC-B100-57 census re-pin), plus packet + 19 new evidence transcripts.
Tests added: 7 TC-B100-07 arms (gather-reuse census arm + fresh control, 2 case-variant arms (Windows-only), fresh-verify no-folder, merge-verify manifest-restore, disk-full gather-home, empty-pre-existing-home); RED first: 6 failed / 3 passed + census 1 failed on the byte-exact reconstructed pre-pass tree.
RED/GREEN: GREEN = 43 module + census 158 + guards 75 (29 snapshot cells unchanged) + sweep 85.
Mutations: 6 applied (Mf — round 5's survivor — now dies, sec2-8, sec2-9, r5-1, fix4-a, fix4-c), 6 KILLED, 6 reverted, restores proven by SHA-256 (RESTORE OK).
Open questions: none — §4b independent review of the corrective pass is with the orchestrator; the pre-pass reconstruction (1-line hash nuance vs the recorded redesign app.py, all hunks verified) is documented in the packet §4.
