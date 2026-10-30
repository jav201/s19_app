# HANDOFF — batch-100 Inc 7 (implementer checkpoint 3 — context limit, resume here)

State: Parts A, B, C code and tests DONE; GREEN on the tree for every touched module
(run during authoring). RED on base DONE. No commit. Ending at ~190k context per the
brief; resume with the steps below.

Scratch: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\inc7-impl\`
- `run_pytest.sh <tree> <out> <label> <pytest args>` — writes a transcript with the header
  (command, tree, PYTHONPATH, NO_COLOR, import proof, 4 source hashes).
- `mutate.py [ids…]` — 19 mutants (C-40); each writes `evidence/inc-7/mut-<id>.txt`,
  restores the source and appends `# reverted: sha256 restored = True`.
- `base/` — detached worktree at `80052cb` with the new/edited tests copied in
  (remove at the end: `git worktree remove --force <scratch>/base`).
- `crlf.py <files>` — normalise CRLF + print sha256[:16].

Source hashes (sha256[:16]) at checkpoint 3: manifest_writer `b3a8da7ae550bda5`,
variant_execution_service `85fbde0ca2ae9d78`, app `c01797f665287871`, screens `e23ea8f72bc93153`
(base: c88152e6975e6c1b / 76b276077ded9717 / 762d1a98c8a65903 / ea549ab4bd9d3ef4).

Evidence written (`.dev-flow/2026-10-26-batch-100/evidence/inc-7/`):
- `reverse-census-grep.txt` (3 greps + union: 41 test modules + b97_fixtures helper).
- `red-01-project-check-vs-base.txt` — 63 failed, 7 passed (7 = pins/boundaries/already-refused
  hostile entries; ImportError nodes are new pure symbols, behavioural RED by mutations).
- `red-02-other-modules-vs-base.txt` — 35 failed, 45 passed (all new + re-pinned nodes RED).
- `census-b100.txt`, `census-rest.txt` — RUNNING in background when this was written (task
  be26yl1n1). NOTE: red-01/red-02 ran concurrently with it, so a timing flake there must be
  re-run in isolation before it is dispositioned. `census-b100.txt` ran the PRE-fix TC-22
  fixture and the pre-literal bound: re-run `tests/test_b100_project_check.py` for green.

Remaining steps (in order; never run mutations while any other pytest runs on this tree):
1. Wait for census-b100/census-rest to finish; disposition every failure (base-vs-tree on
   `base/` for anything outside the known set: b78_03, b78_32, 056e_a2b + flakes list).
2. `green-01`: run_pytest.sh on the tree for tests/test_b100_project_check.py
   tests/test_b100_active_variant.py tests/test_b100_announce.py tests/test_b100_save_image.py
   tests/test_b100_save_guards.py tests/test_variant_execution.py tests/test_id_registry.py.
3. `python mutate.py` (all 19) → mut-*.txt; every one must show failed nodes + restored True.
4. Guards: `guards.txt` (6 files) and `guards-census.txt` (`-k census tests`).
5. Fill packet `03-increments/increment-007.md`: replace PENDING_RESULTS (§4: layers table,
   RED table, instrument RED-proof, mutation table, reverse census + re-pin list below, ledger,
   evidence table via devflow-evidence.py), PENDING_SECTION6, PENDING_CHECKLIST (16 rows, copy
   increment-006.md's shape). Then
   `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe C:/Users/jjgh8/.claude/docs/tools/devflow-evidence.py --root . <evidence files> --write .dev-flow/2026-10-26-batch-100/03-increments/increment-007.md`
6. Remove the base worktree; end this file with `__KIMI_UNIT_DONE__` + 5-line summary.

Re-pins (test::node — old → new — requirement):
- test_b100_announce.py::test_tc_b100_55_first_by_name_manifest_damaged — "Manifest damaged" → "manifest damaged" — LLR-169.9
- ::test_tc_b100_55_first_by_name_no_project_json — ("No manifest", …) → ("no project.json", …) — LLR-169.9
- ::test_tc_b100_55_next_valid_when_the_recorded_one_is_missing — "Missing variant" → "missing" — LLR-169.9
- ::test_tc_b100_55_three_problems_in_precedence_order — 3 rows → 2 (one manifest-level kept) — LLR-169.9
- ::test_tc_b100_56_one_summary_line… / ::test_tc_b100_67_* seeds — manifests gain `files` (else 1 `no digests saved`) — LLR-169.5
- ::test_tc_b100_56_recorded_variant_with_control_bytes_paints_none — the "activating the first variant" line → absent; 1 summary line — LLR-169.6
- ::test_tc_b100_67_thirty_problems… / damaged_manifest… / fallback colour / wrapped / digit-limit / junction-loop — "Manifest damaged"/"Manifest entry skipped" → "manifest damaged" — LLR-169.9
- ::test_tc_b100_67_overlong_entries… — 3 rows → 1 (same entry under 3 keys = one file) — LLR-169.9
- ::test_at_b100_19_… — "Missing variant: firmware-patched" → "missing: firmware-patched.s19" — LLR-169.9
- test_b100_active_variant.py::test_tc_b100_20_a2l_sync_with_an_overlong_entry_does_not_crash and
  ::test_tc_b100_20_variant_append_with_a_junction_loop_entry_does_not_crash — rewritten with the entry dropped
  → project.json byte-identical + "holds entries that were skipped and was not rewritten" — SEC6-2 / LLR-168.3
- test_variant_execution.py::test_load_project_unknown_active_variant_falls_back — status line → summary count +
  `missing: ghost` problem — LLR-169.6
- Planned arms (not re-pins): AT-B100-06 `derived_from` line; TC-B100-59 files row.

Decisions / open questions (packet §6):
- SEC6-2: refuse the rewrite (damaged / schema_version ≠ 1 / unknown keys / skipped entries).
- SEC6-5 bound: MANIFEST_ENTRY_ROWS = 100 entry rows + 1 counting row + 1 manifest-level +
  1 per top-level file; textual `..` escape (no fs call). Base: panel 10.38 s (red-01).
- OQ-7a: "load errors" ⇒ not readable even with data (LLR-169.9 literal) — orchestrator to rule.
- OQ-7b: TC-22 fixture adds `checks/inner.s19` so the walking mutant is observable
  (the contract's `flows/f1.json` has no data suffix).
- `derived_from` fields: base, sha256, differ.
- qa-reviewer F6 (Inc 3): no real-worker boundary arm at Inc 7 → Inc 12b.
- Not done: AT-B100-05 / AT-B100-19 / AT-B100-20 Inc 7 extensions beyond the AT-06 line
  (patched line on the panel at AT level; derived_from carried in AT-20).

## Checkpoint 4 (resumer, 2026-10-30)
- OQ-7a RULED (orchestrator): `not readable` only when the install yields NO data (empty
  `mem_map`) or the file does not parse; record-level errors keep the image open, shown as
  before. `app.py` `_install_project_image`: the `elif loaded.errors` branch removed.
  Arms: `test_tc_b100_61_checksum_errors_only_keep_the_image_open` (case_04),
  `test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on`. Mutants `OQ-7a-record-errors`,
  `OQ-7a-empty` added to mutate.py.
- AT-index extensions owed AT Inc 7 (01-requirements.md §5.3 lines 1910/1924/1925) DONE:
  AT-B100-05 ("patched from firmware.s19 (not in this project); 4 bytes differ from it"),
  AT-B100-19 ("patched, 4 bytes differ from firmware.s19", default name, no "identical"),
  AT-B100-20 (seeded `derived_from` kept equal after each of the 3 writers).
  RED on base: `red-03-at-extensions-and-oq7a-vs-base.txt` (8 failed).
- Next: green-01 → mutations → census (clean) → guards → packet → remove base worktree.
- green-01 (pre-CI-6-1) 267 passed; mutations 22/22 KILLED (keep-all mutant corrected — first form
  survived as "last wins"; reversed-order arm + `LLR-169.9-last-wins` mutant added).
- CI-6-1 (orchestrator, mid-run): Inc 6 CI on Linux, 3 failures. `variant_execution_service.py`
  `_resolve_manifest_entry`: `MANIFEST_ENTRY_MAX_CHARS = 32_767`, an entry longer than that is
  skipped on the TEXT in every mode before any filesystem call (OSError/ValueError/RuntimeError
  fallback kept). New arm `test_b100_announce.py::test_tc_b100_67_overlong_entry_is_decided_on_the_text`
  (resolve + reparse walk made non-raising = POSIX behaviour); RED on base `red-04-ci-6-1-vs-base.txt`
  (entry carried in `batch`), mutant `CI-6-1` KILLED.
  FINDING: `test_tc_b100_20_append_says_now_opens_only_after_the_write` has a DIFFERENT root
  cause (reasoned, not executed on Linux): a POSIX rename replaces a read-only file, so chmod
  S_IREAD forces no write failure there. Fix: that node skips off Windows with a named reason;
  new sibling `..._on_any_platform` forces `os.replace` onto project.json to raise PermissionError.
  The interrupted census run (pre-CI-6-1) was discarded; census restarts on the final tree.
- Final-tree runs: green-01 269 passed; census-tree 6 failed / 1043 passed; guards 1 failed
  (address census, my test file line 884 used an attribute selector) — NOT a snapshot cell
  (29 snapshots passed). Isolation (census-isolation-tree/-base): 4 Inc-7-caused failures, all
  passed on base → re-pinned (tests only): tc_b100_08 (install marker → `_apply_loaded_file`),
  tc_b99_13 (allow-list += `_restore_manifest`, `_keep_previous_manifest`), tui_variants
  parse-call-site list += `_install_project_image`, project_check line 884 literal "#result_ok".
  tc_035_4 passed in isolation on tree and base → flake. b78_03, 056e_a2b known.
- Running: green-02 (re-pinned modules), tc_035_4 repeats, guards, guards-census.
- Final: green-02 132 passed (re-pinned modules + project_check); tc_035_4 1 passed in isolation;
  guards 75 passed + 29 snapshots passed (no cell changed); guards-census 87 passed;
  known b78_03 / 056e_a2b FAILED on base (`census-known-vs-base.txt`). Packet §1–§7 filled,
  §4b `pending — orchestrator`, 37 evidence rows written by devflow-evidence.py.
  Base worktree removed (`git worktree remove --force`; long-path leftovers deleted from scratch).
- Final source sha256[:16]: manifest_writer b3a8da7ae550bda5, variant_execution_service
  bd33c8be189d2c87, app 0e29d80841fa3f38, screens e23ea8f72bc93153.

__KIMI_UNIT_DONE__
1. Files: 4 sources (manifest_writer, variant_execution_service, app, screens); tests: project_check (NEW, 72 nodes), b100_manifests (NEW), b100_projects, active_variant, announce, save_image, save_guards, variant_execution, session_reset, b99_staging, tui_variants, id_registry.
2. Tests added: 35 functions in test_b100_project_check.py + 13 across 4 modules; AT-B100-07 new; AT-05/-19/-20 Inc 7 extensions; OQ-7a and CI-6-1 arms.
3. RED on base: red-01 63F/7P, red-02 35F/45P, red-03 8F, red-04 1F/1P; GREEN: green-01 269 passed, green-02 132 passed; census 41 modules, 4 Inc-7-caused re-pins, 1 flake, 2 known.
4. Mutations: 23 run on the final tree, 23 KILLED, each restored and hash-verified.
5. Open: OQ-7a ledger amendment (orchestrator); CI-6-1 Linux confirmation on a CI run; third CI node had a different root cause (POSIX rename over a read-only file), fixed in tests.

## Corrective pass 1 (cp1, 2026-10-30) — resume here

Scratch: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\cp7-1\`
(`run.sh <tree> <out> <label> <pytest args>`; `mutate_cp1.py` = 19 cp1 mutants -> `mut-cp1-<id>.txt`;
`mutate_prior.py` = the 23 earlier mutants on the cp1 tree -> `mut-cp1-prior-<id>.txt`; `pre/` = copy of the
pre-fix sources (hashes b3a8da7ae550bda5 / bd33c8be189d2c87 / 0e29d80841fa3f38 / e23ea8f72bc93153) with the cp1
tests, used for RED; `sec/`, `rev/` = copies of the reviewers' probes; `cp1_nodes.txt` = the cp1 arm list).

Done (code + tests + RED + GREEN arms + mutants):
- F1 A2L read on its own in `_handle_load_project` (problem on the A2L, image opens).
- F2 composed bound `LOAD_PROBLEM_ROWS = MANIFEST_ENTRY_ROWS + 2` (=102) + 1 counting row; `LoadAnnouncement.hidden`
  / `problem_count`; panel title + summary count use `problem_count`.
- SEC7-1 manifest-keys mode: `_entry_text` (text checks, + `MANIFEST_ENTRY_MAX_PARTS = 32`), `_EntryWalk` (lstat walk
  from the project folder, one call per distinct name per read, `MANIFEST_FS_CALL_CAP = 2000`, unchecked counted in the
  fold row), `_recorded_file` scope before any fs call. Default mode unchanged (resolve).
- F3 `carried_derived` + `emitted_record` decided before the plan; plan `derived=` from them.
- F4/F5 arms; F6 composer no longer adds manifest problems / no-manifest (check_project_files is the one source;
  3 TC-55 re-pins pass `problems=`); F7 exact count; F8/SEC7-4(a) `manifest_keep_reason` strict int 1, newer/unknown.
- SEC7-2 post-replace containment re-check; SEC7-3 Save project keeps `.previous-<UTC>` when keep reason, refuses if no copy;
  SEC7-5 no class painted; SEC7-6 guard + any claim OSError -> next name (`_keep_previous_manifest` now an instance method).
- Evidence: `red-cp1-vs-pre-fix-tree.txt` (25 failed / 17 passed), `green-cp1-arms.txt` (42 passed),
  `mut-cp1-*.txt` 19/19 KILLED, `mut-cp1-prior-*.txt` 23/23 KILLED.
- cp1 source sha256[:16]: manifest_writer ab36c9a2a6216de5, variant_execution_service aae7d7fdde4d735e,
  app 3b46619711652f9c, screens 49d6efdc73e26b28.

Remaining (in order, serial, nothing else running): green-cp1-touched-modules.txt (running) -> reverse census
(`reverse-census-grep-cp1.txt`, `census-tree-cp1.txt`, ~72 min) -> base-vs-tree for any new failure -> guards
(`guards-cp1.txt`, `guards-census-cp1.txt`) -> packet §2/§4/§6 + evidence rows (devflow-evidence.py) -> report.
- cp1 close (2026-10-30): green-cp1-touched-modules 364 passed; census-tree-cp1 2 failed (known b78_03, 056e_a2b) / 987 passed;
  guards-cp1 75 passed + 29 snapshots (no cell changed); guards-census-cp1 87 passed; review-probes-cp1 7 passed;
  sec-probes-A-E-cp1 (A1 0.02 s, A3 0.06 s; E load 0.07 s, append 0.40 s). Packet §1/§2/§3/§4/§6/§7/checklist updated,
  88 evidence rows written; §4b stays `pending — orchestrator`. Nothing committed. Scratch `cp7-1/` kept for re-review.

## Corrective pass 2 (cp2, 2026-10-30) — resume here

Scratch: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\cp7-2\`
(`pre/` = full tree copy of the cp1 sources, hashes ab36c9a2a6216de5 / aae7d7fdde4d735e / 3b46619711652f9c / 49d6efdc73e26b28,
verified; `run.sh <tree> <out> <label> <pytest args>`; `nodes_cp2.txt` = the cp2 arm list; `patch_*.py` = the edits applied, CRLF-aware).

Code DONE (screens.py untouched):
- SEC7-R2-1: `_EntryWalk` keys a component by its exact text (per-node child dict), never `normcase`.
- SEC7-R2-2: `serialize_manifest` builds ONE `_EntryWalk` and passes it to `_reject_unsafe_entry(..., walk)` (now required).
  Writer-time cuts: `_component_refusal` lru_cache, per-node `Path` cache in the walk, POSIX absolute test as
  `startswith("/")`, `_resolve_intended_entries` lexical (`normpath`, no `resolve()` per entry).
- R2-2: `MANIFEST_FS_CALL_CAP` -> `MANIFEST_FOLDER_CHECK_CAP = 2000` distinct FOLDER checks; the final file of each entry
  is always checked (bounded by the entry caps). Fold text "over 2000 folder checks".
- R2-4 / SEC7-R2-3: SEC7-2 message has no class; class logged by `manifest_writer.logger`.
- SEC7-R2-4: kept copy goes to `kept_copies` (not `placed_files`); `_abort_save` unlinks it only when project.json reads
  back as the previous bytes, else paints "...is kept as <copy> in <folder> - rename it to project.json".
Tests DONE: 10 cp2 nodes (17 cases) GREEN (`try-arms3.txt`); re-pins in project_check (each_name (d)+(e); existing-folder
test renamed `..._are_all_checked`).
Remaining: RED on cp7-2/pre -> mutants (cp2 + prior 42) -> green touched modules -> reverse census -> guards -> packet -> report.
- cp2 progress: RED `red-cp2-vs-cp1-tree.txt` 15 failed / 2 passed (Q1 = test gap, `restored` = control); Q1 RED on pre-cp1
  tree `red-cp2-q1-vs-pre-cp1-tree.txt` 1 failed. Mutants `mutate_cp2.py`: cp2 8/8 KILLED (`mut-cp2-<id>`), cp1 19/19 on cp2 tree
  (`mut-cp2-cp1-<id>`, overrides SEC7-1-no-cache, SEC7-1-no-ceiling, SEC7-5), prior 23/23 (`mut-cp2-prior-<id>`); all restored.
  Source hashes cp2: manifest_writer d6c2decced648425, variant_execution_service 4f6d7022d008cd43, app be97fcdc55a02fdb, screens 49d6efdc73e26b28.
  Running `scratchpad/cp7-2/chain.sh` (log `chain.log`): green-cp2-arms -> green-cp2-touched-modules -> review-probes-cp2 ->
  sec-probes-cp2 -> census-tree-cp2 -> guards-cp2 -> guards-census-cp2. Then: packet §1/§2/§4/§6/§7/checklist + devflow-evidence.py.
- cp2 late changes (after the first mutant/green run): MANIFEST_FOLDER_CHECK_CAP 2000 -> 1000 (worst-case append 1.03 s once
  under the long module run); manifest_writer logger -> getLogger("s19tui") (a __name__ logger reached stderr via lastResort).
  FINAL cp2 hashes: manifest_writer 721f335bfed1cb89, variant_execution_service 425f610345f263c6, app be97fcdc55a02fdb,
  screens 49d6efdc73e26b28. chain.sh re-run from RED (red, mutants 50, green, probes, census, guards). Q2 probe fails = R2-3 backlog.
- Census on 721f335b/425f6103 found 2 cp2-caused failures (base-known pair b78_03 / 056e_a2b also failed):
  (1) tests/test_tui_manifest_save.py::test_manifest_writer_module_is_headless (LLR-004.3: no logging in manifest_writer) ->
  logger REMOVED from manifest_writer; the class now rides in the finding's details {"exception": ...}, and app.py's
  "Manifest write refused: <msg> (<class>: <text>)" log line carries it. (2) tests/test_b100_reuse.py::test_tc_b100_57_...
  byte-identity census flagged _abort_save's read_bytes()== (restore confirmation, not a reuse rule) -> census RE-PIN:
  ("s19_app/tui/app.py", "_abort_save") added to declared_other_rules with the reason.
  FINAL-FINAL hashes: manifest_writer 3711eba2c27f3691; variant_execution_service 425f610345f263c6; app bd4dca9461d381c5; screens 49d6efdc73e26b28; 
  RESUME: (1) bash scratchpad/cp7-2/chain.sh (re-runs red, 50 mutants, green, probes, census, guards; ~2 h, serial);
  (2) packet §4 "Corrective pass 2 — results" + §6 cp2 dispositions + checklist rows 2/4/5/11 + §7, then
  python C:/Users/jjgh8/.claude/docs/tools/devflow-evidence.py --root <worktree> <cp2 evidence files> --write <packet>;
  (3) report via SubagentHandback. Pieces drafted: §1/§2/§3 already in the packet.
- Chain on 3711eba2/425f6103/bd4dca94: 9 save_guards nodes failed (their stubs return SimpleNamespace findings without
  `.details`) -> app.py reads `getattr(issue, "details", {})`; mutant SEC7-R2-3-class target re-anchored (line now ends with ",").
  FINAL hashes now: manifest_writer 3711eba2c27f3691, variant_execution_service 425f610345f263c6, app 923de169c6c44bc8,
  screens 49d6efdc73e26b28. chain.sh re-launched on these bytes; resume steps unchanged (packet §4/§6/checklist/evidence, report).
