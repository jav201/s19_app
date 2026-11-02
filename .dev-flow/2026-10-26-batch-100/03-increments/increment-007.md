# Increment 007 — HLR-169 / LLR-168.4 · `files digests, every problem listed, caps, private staging, derived_from (PH-5, L-4, D3, O-2, O-11, UX-26)`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `007` |
| Lane | `main` · 4 SOURCE files (3 planned + `screens.py` as the declared 4th, ⚠ at cap) |
| Requirement(s) | `HLR-169 · LLR-169.1 … LLR-169.9` · `LLR-168.4` · `LLR-178.1` (TC-B100-55 Inc 7 arms) · `LLR-167.6` (TC-B100-59 `files` row) · `LLR-171.4` (TC-B100-62 seam arm, SEC6-3) · `LLR-164.4` (TC-B100-07, SEC2-10) · `LLR-168.3` (TC-B100-20, SEC6-2; CI-6-1 write-failure sibling) · CI-6-1 (orchestrator item: the textual length rule) · US-159 |
| Acceptance | `AT-B100-07` (new, 118×54 and 220×60) · `AT-B100-06` (Inc 7 arm: `derived_from` on disk) · `AT-B100-05` (Inc 7: the "patched" line against `derived_from`) · `AT-B100-19` (re-pin: the `missing` token; Inc 7: the `derived_from` line, default-name arm) · `AT-B100-20` (Inc 7: `derived_from` carried) · white-box `TC-B100-21 … -27 · -60 · -61 · -71` (new) · `-55` (Inc 7 arms) · `-59` (`files` row) · `-62` (seam arm) · `-20` (SEC6-2 arms) · `-07` (SEC2-10 arms) |
| Interfaces | freezes B100-I1 (`files`, `derived_from`), B100-I2 (`files`, `derived_from`, the caps), B100-I3, B100-I16, B100-I21; consumes B100-I13, the Inc 5 seam (`_write_and_verify_manifest`, `_save_manifest_keys()`), the Inc 6 helpers (`_rewrite_project_manifest`, `manifest_is_damaged`, `compose_load_announcement`, `LoadProblem`) |
| Agent | `software-dev` (Claude; briefs `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-7.md`) |
| Date | `2026-10-30` |
| Base | `main` `80052cb` (Inc 1–6 merged) |
| Import proof | `<HOME>\Github\s19_app-b100-inc7\s19_app\__init__.py` — printed in every transcript header (`# s19_app import:`) |

---

## 1 · What changed

**Part A — the writer.**
- `serialize_manifest` emits the B100-I1 additive keys `files` (`{<top-level name>: {"size", "sha256"}}`) and `derived_from` (`{<variant file>: {"base", "sha256", "differ"}}`), only when non-empty; every key (and each `base`) goes through `_reject_unsafe_entry`, now in the manifest-keys mode. With neither key the output is byte-identical to the base (golden captured on `80052cb`).
- **`derived_from` field names (LED .48, frozen with B100-I16):** `base` (the base image's file name, one path component), `sha256` (64 lowercase hex, the base file's digest), `differ` (int ≥ 0, addresses whose byte differs or that exist in only one of the two images, computed at the write).
- `_write_and_verify_manifest` computes `files` itself, after every copy, over the top-level regular files with a `PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS` suffix (`project_file_records`, streamed `file_record`); no sub-folder is walked; a file that cannot be read is left out (Load then reports `not recorded`).
- `verify_written_manifest` compares `files` and `derived_from` too (drift names `files`, `derived_from`).
- `write_project_manifest` stages in a private directory (`_private_stage_dir`) and `os.replace`s onto `project.json`; the shared `temp/project.json` is gone (O-11).
- **SEC6-3:** `_check_destination_contained(destination, workarea_root)` runs `_guarded_destination` on the UNRESOLVED project folder against this app's work area (SEC PDR-C1), so a project folder swapped for a junction after placement receives no manifest.
- The save-back into a project and Save project's emit record `derived_from` (`_derived_record`: the loaded image is the base; its data is re-read with the core parsers, the written data is the session map / the re-derived map); every rewrite carries it (`_manifest_carry`); Save project into an existing project carries the target's readable records.
- **SEC2-10 (LED .54 (a)):** `_abort_save` → `_restore_manifest`: the restore retries `os.replace` on `PermissionError` (5 tries within 1 s); if staging or the replace still fails, the previous bytes go to a claimed (`O_CREAT|O_EXCL`) `project.json.previous-<UTC timestamp>` beside the manifest and the status names that copy and its folder.

**Part B — the reader and the load.**
- `read_project_manifest`: a bounded read (1 MiB; the size probe stays as a seam), every array capped at 1 000 entries counted BEFORE any entry is resolved (`assignments` in total and by key count, `gathered` in total and by home count); an excess gives one `MANIFEST-BAD-STRUCTURE` per array, marked as voiding the whole manifest (read as damaged, defaults used, never rewritten). `files` and `derived_from` are parsed into `FileRecord` / `DerivedFrom` records (scope: one top-level data or A2L name; `size` an int ≥ 0 and never a `bool`; `sha256` 64 lowercase hex); `unknown_keys` records any other top-level key.
- **CI-6-1 (orchestrator item):** `_resolve_manifest_entry` skips an entry longer than `MANIFEST_ENTRY_MAX_CHARS = 32 767` characters on the text, in every mode, before any filesystem call — Linux's `resolve()` does not raise for it (Inc 6 CI). The `OSError` / `ValueError` / `RuntimeError` fallback stays.
- `_resolve_manifest_entry(..., mode=)` (B100-I21): the manifest-keys mode refuses a drive or a root, a `:`, a component ending in a dot or a space, or a device name (`is_windows_device_name`), and decides a `..` escape on the text alone; only the reader and `_reject_unsafe_entry` use it. Flow callers keep the default.
- Problem kinds = the §3 tokens (`manifest damaged`, `no project.json`, `missing`, `not readable`, `changed on disk`, `not recorded`, `no digests saved`), `PROBLEM_PRECEDENCE`, `PROBLEM_NEXT_STEP`, `ProjectFileProblem`, `merge_load_problems` (one per file; manifest-level problems all name `project.json`, so at most one is kept), `manifest_problems`.
- `check_project_files(project_dir, manifest)` (B100-I3, `manifest_writer.py`): never raises, parses no image; only `S_ISREG` non-link files are hashed.
- `choose_install_set` (pure, module-level in `app.py`, LED .34): the recorded variant when valid, else the next valid one in `build_variant_set` order (wrapping), then the MAC and A2L. `_handle_load_project` runs the check, installs through `_install_project_image` (parse first; an image whose parse raises or that holds no data is `not readable` and the next one is tried; record-level errors alone keep it open — OQ-7a ruling), opens the MAC when no variant can be opened, and no longer writes "activating the first variant". The internal codes go to the log (`Project P: <kind> <file> (<code>)`).
- **SEC6-2 decision (LED .68):** an in-project rewrite is **refused** (never carried verbatim) when the manifest is damaged, has a `schema_version` other than 1, unknown top-level keys, or skipped entries (`manifest_rewrite_refusal`); one status line: `project.json in project 'P' <why> and was not rewritten - <file> stays in the project; Save project rewrites it`. Save project stays the recovery.
- **SEC6-5 bound (as first shipped; superseded by corrective pass 1, F2 / SEC7-1 below):** the reader keeps at most `MANIFEST_ENTRY_ROWS = 100` skipped-entry findings one by one and folds the rest into one finding that counts them (`<N> more recorded entries`). Panel rows ≤ 100 + 1 + 1 manifest-level + one per top-level project file — under the 1 000-entry cap. Every array at the cap with every entry bad: load and panel each under 1 s (TC-B100-61 SEC6-5 arm).

**Part C — the panel and the AT.**
- `compose_load_announcement(..., problems=, unreadable=)`: problems painted as `<kind token>: <file>  <reason> - <next step>`; `relation` from `derived_from` — `patched, N bytes differ from <base>` when a project file has the recorded name and digest, `patched from <base> (not in this project); N bytes differ from it` otherwise — never the first variant by name.
- `LoadResultScreen` (`screens.py`): the relation line under the reason (warning colour), and `not readable` beside an unreadable variant in Others, in the error colour (`RED`, P-E verdict B). `screens.py` still imports no service module at run time.
- AT-B100-07 (black-box, both sizes).
- E4 (`tests/support/b100_projects.py`): `save_case01_project` (the shipped Save project handler, LED .42), `build_p04_case` (cases 2/5/6/7/9, legacy, hand-copied), `append_variant`, `flip_data_byte`, `file_records` (hashlib oracle). E8: `tests/support/b100_manifests.py`.

**Corrective pass 1 (2026-10-30; `review-increment-007.md` F1–F8, `security-increment-007.md` SEC7-1–SEC7-6; orchestrator rulings).**
- **F1 (`app.py` `_handle_load_project`):** the project's A2L is read on its own, before any image (`_load_a2l_data_with_cache` inside its own `try`). An A2L that cannot be read is one `not readable: <a2l name> - the file cannot be read` problem; the images and the MAC install without it. `_install_project_image`'s `not readable` stays for failures of the image itself.
- **F2 + SEC7-1, rows (`variant_execution_service.py` `compose_load_announcement`):** the COMPOSED list is bounded: at most `LOAD_PROBLEM_ROWS = MANIFEST_ENTRY_ROWS + 2 = 102` problems one by one, in precedence order, plus ONE row `more problems: <N> more files - not listed one by one - each has one of the problems above`. `LoadAnnouncement.hidden` / `problem_count` keep the true count for the summary line and the panel title (`screens.py`, one line).
- **SEC7-1, time (`variant_execution_service.py`):** the manifest-keys mode no longer calls `resolve()`. `_entry_text` makes every text decision first (length, more than `MANIFEST_ENTRY_MAX_PARTS = 32` components, the LLR-169.8 refusals, a `..` climb, NUL, absolute), and `_recorded_file` checks the `files` / `derived_from` one-name scope on the text BEFORE any filesystem call. `_EntryWalk` then walks the components from the project folder with one `os.lstat` per distinct folder or file per read (a cache keyed by parent node and component): it stops at the first missing component (the entry stays inside), refuses at the first link or junction (so a junction loop costs one call and every later entry through it none), and never makes more than `MANIFEST_FS_CALL_CAP = 2 × MANIFEST_ENTRY_CAP = 2 000` calls per read; an entry that would need a call past the ceiling is skipped unchecked and counted in the fold finding (`<N> more recorded entries`, reason `skipped - more entries than one load checks`). The default mode (flow references, P-41) is unchanged.
- **F3 (`app.py` `_handle_save_dialog`, `_plan_project_save(derived=)`):** the save's `derived_from` records — the target's readable records (carried) and the emitted image's own record (`_derived_record`, `None` when its base cannot be read again) — are decided once, before the plan; the plan's keys and the save use the same values.
- **F6:** `check_project_files` is the one source of the manifest's own problems and of `no project.json`; `compose_load_announcement` no longer adds them.
- **F8 + SEC7-4 (a):** `manifest_keep_reason` (new; `manifest_rewrite_refusal` = it, then skipped entries): only the integer `1` (`type(v) is int`) or an absent key is this version; an int above 1 is "was written by a newer version", any other value "was written by an unknown version". The reader keeps a float `schema_version` as found.
- **SEC7-2 (`manifest_writer.py` `write_project_manifest`):** after `os.replace` the destination is checked again with `_check_destination_contained`; a project folder swapped inside the window gives `(None, [MANIFEST-WRITE-CONTAINMENT naming where project.json landed])` — the app paints the write failure, never "manifest verified".
- **SEC7-3 (`app.py` Save project):** when the manifest it replaces has `manifest_keep_reason` (damaged, another `schema_version`, unknown top-level keys), Save project first keeps the old bytes through `_keep_previous_manifest` and paints `project.json <why>: its previous content is kept as project.json.previous-<UTC> in <folder>` after the success line; when no copy can be kept, the save is refused and rolled back (nothing overwritten). The copy joins the save's rollback list.
- **SEC7-5:** the SEC2-10 restore status paints no exception class; the class goes to the log.
- **SEC7-6:** `_keep_previous_manifest` (now an instance method) runs `_guarded_destination(project folder, this work area)` first and returns `None` when it refuses; a candidate name refused for any reason (a file, a folder or junction, any claim error) moves on to the next of `-1` … `-9`.

**Corrective pass 2 (2026-10-30; round 2 of `review-increment-007.md` R2-1–R2-4 and `security-increment-007.md` SEC7-R2-1–SEC7-R2-4; orchestrator rulings).**
- **SEC7-R2-1 (`variant_execution_service.py` `_EntryWalk`):** the per-read cache keys a component by its exact text, never `os.path.normcase`; a case-sensitive folder holds `sub` and `SUB` as two objects, so each spelling gets its own `os.lstat`. The cache is now one child dict per node (`_children`), with the node's `Path` cached beside it (`_paths`), so an entry no longer rebuilds its path.
- **R2-2 — the ceiling redesigned:** `MANIFEST_FS_CALL_CAP` (2 000 calls of any kind) is replaced by `MANIFEST_FOLDER_CHECK_CAP = MANIFEST_ENTRY_CAP = 1 000` distinct FOLDER checks per read (or per serialize). The file an entry ends on is always checked; those calls are bounded by the entry caps (at most 1 000 each in `batch`, `assignments`, `gathered`, `files`, and 1 000 `derived_from` keys + 1 000 bases: ≤ 6 000 per read). An entry becomes unchecked only when it needs a folder check past the ceiling. The fold text reads `(<N> unchecked: over 1000 folder checks)`. (Set first at 2 000; lowered to 1 000 in this pass because the worst case's variant append measured 1.03 s once under the 19-minute module run — §6.)
- **SEC7-R2-2 (`manifest_writer.py` `serialize_manifest`):** one `_EntryWalk` per serialize, passed to `_reject_unsafe_entry(..., walk)` (the parameter is now required, so no caller gets a fresh walk per entry). Each writer re-read already uses one walk (`read_project_manifest`). Per-entry cost cuts, same decisions: `_component_refusal` (the per-component rule of `_manifest_key_refusal`, `functools.lru_cache`, pure); the POSIX absolute test written as `text.startswith("/")` (exactly `PurePosixPath(text).is_absolute()`); `_resolve_intended_entries` (verify) joins the resolved root with each entry lexically (`os.path.normpath`), the form the reader's walk returns, instead of one `resolve()` filesystem call per intended entry.
- **R2-4 / SEC7-R2-3 (`manifest_writer.py`):** the SEC7-2 detection message names where `project.json` landed and carries no exception class; the class goes to the app's log file (`logging.getLogger("s19tui")`, as `screens.py`; `Manifest write landed outside the work area: <path> (<class>: <text>)`).
- **SEC7-R2-4 (`app.py` Save project + `_abort_save`):** the kept `project.json.previous-<UTC>` copy no longer joins `placed_files`; it is passed as `kept_copies` (copy, previous bytes) to the five rollbacks after the keep. `_abort_save` removes a copy only when `project.json` reads back as exactly those bytes; otherwise the copy stays and a status line names it (`project.json could not be restored; its previous content is kept as <copy> in <folder> - rename it to project.json`).
- **R2-1:** test only (the code was right): a TC-B100-07 node for the refusal branch.
- `screens.py` is untouched by this pass; `workspace.py`, `prototypes/`, `tools/e13/` untouched.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/variant_execution_service.py` | source | HLR-169 · LLR-169.4 · LLR-169.8 · LLR-169.9 · LLR-168.4 · LLR-178.1 | caps, bounded read, manifest-keys mode, the CI-6-1 length rule (`MANIFEST_ENTRY_MAX_CHARS`), `FileRecord`, `DerivedFrom`, `files` / `derived_from` / `unknown_keys` parse, problem kinds, `ProjectFileProblem`, `merge_load_problems`, `manifest_problems`, `manifest_rewrite_refusal`, `_bound_entry_findings`, composer `problems` / `unreadable` / `relation`. **cp1:** `_entry_text`, `_EntryWalk`, `_walk_manifest_entry`, `_lstat_state` (SEC7-1), `MANIFEST_FS_CALL_CAP`, `MANIFEST_ENTRY_MAX_PARTS`, `LOAD_PROBLEM_ROWS`, `LoadAnnouncement.hidden` / `problem_count` (F2), `manifest_keep_reason` (F8, SEC7-3/-4), composer one source (F6). **cp2:** `_EntryWalk` exact-text keys, per-node child dicts and `Path` cache (SEC7-R2-1); `MANIFEST_FS_CALL_CAP` → `MANIFEST_FOLDER_CHECK_CAP` (folder checks only, R2-2); `_component_refusal` (cached); POSIX absolute test as `startswith("/")`; `PurePosixPath` import dropped |
| `s19_app/tui/services/manifest_writer.py` | source | LLR-169.1 · LLR-169.2 · LLR-169.3 · LLR-169.5 · LLR-169.7 · LLR-168.4 · LLR-171.4 | `files` / `derived_from` serialize, private staging, `_guarded_destination` check, verify domain, `file_record`, `project_file_records`, `count_differing_bytes`, `derive_record`, `check_project_files`. **cp1:** containment re-check after the replace (SEC7-2). **cp2:** one `_EntryWalk` per `serialize_manifest`, `_reject_unsafe_entry(..., walk)` required (SEC7-R2-2); `_resolve_intended_entries` lexical (no `resolve()` per entry); the SEC7-2 message without the class, class to the `s19tui` log (SEC7-R2-3) |
| `s19_app/tui/app.py` | source | LLR-169.2 · LLR-169.6 · LLR-169.9 · LLR-168.4 · LLR-168.3 · LLR-164.4 · LLR-167.6 | seam computes `files`; `_save_manifest_keys(derived=)`; `_image_map`, `InstallSet`, `choose_install_set` (NEW, module-level); `_install_project_image`, `_derived_record`, `_restore_manifest`, `_keep_previous_manifest` (NEW); load rewrite; carry; rewrite refusal. **cp1:** the A2L read on its own (F1); `derived_from` decided before the plan, `_plan_project_save(derived=)` (F3); Save project keeps a manifest it cannot carry (SEC7-3); restore status without the class (SEC7-5); `_keep_previous_manifest` guarded, any taken name moves on (SEC7-6). **cp2:** the kept copy travels as `kept_copies` (not `placed_files`) to the five rollbacks after the keep; `_abort_save(kept_copies=)` removes it only when `project.json` reads back as the previous bytes, else names it (SEC7-R2-4) |
| `s19_app/tui/screens.py` | source | LLR-178.3 · LLR-169.9 | the relation line; the `not readable` mark in `RED` (declared 4th file: the Inc 6 fields cannot carry a colour or the new line). **cp1:** the panel title counts `problem_count` (F2). **cp2:** untouched |
| `tests/test_b100_project_check.py` | test | HLR-169 · LLR-169.1 … LLR-169.9 · LLR-171.4 | NEW. **cp1:** F1, F2, F5, SEC7-1 ×4, SEC7-2 arms; `LOAD_PANEL_ROW_BOUND` restated as 100 + 2 + 1. **cp2:** SEC7-R2-1 (2 cases), SEC7-R2-2 serialize count, R2-2 Q3 node, the folder ceiling's worst case, SEC7-R2-3 toast/status/log; re-pins: `…_each_name_is_checked_once_per_read` (d) + new (e), `…_entries_under_an_existing_folder_stop_at_the_ceiling` → `…_are_all_checked` |
| `tests/support/b100_manifests.py` | fixture | LLR-169.4 · LLR-169.8 | NEW (E8). **cp1:** `deep_missing_at_cap`, `existing_parent_at_cap`, `junction_loop_at_cap`, `files_at_cap_missing`. **cp2:** `distinct_folders_at_cap`, `distinct_folder_names` |
| `tests/support/b100_projects.py` | fixture | HLR-169 · LLR-169.5 | E4 slice for Inc 7. **cp2:** `CHAIN`, `real_files_under_a_chain` (the security probe T2's shape) |
| `tests/support/b100_links.py` | fixture | LLR-169.8 | **cp2:** `enable_case_sensitive` (`fsutil file setCaseSensitiveInfo`; skips with a named reason when unavailable) |
| `tests/test_b100_active_variant.py` | test | LLR-168.4 · LLR-168.3 · HLR-168 | TC-B100-71 (NEW), TC-B100-20 SEC6-2 arms (NEW), CI-6-1 any-platform write-failure sibling (NEW), AT-B100-06 `derived_from` line, AT-B100-20 Inc 7 extension, 3 re-pins. **cp1:** F8 / SEC7-4 (a) arms (3 writer cases, 9 values, the float reader). **cp2:** SEC7-R2-2 writer bound (5 writers on the 31-folder manifest) |
| `tests/test_b100_announce.py` | test | LLR-178.1 · LLR-178.2 · LLR-178.3 · LLR-169.9 · LLR-169.4 | TC-B100-55 Inc 7 arms (NEW), CI-6-1 length-rule arm (NEW), AT-B100-19 Inc 7 extension, re-pins. **cp1:** F6 arm; 3 TC-55 re-pins pass `problems=` |
| `tests/test_b100_save_image.py` | test | LLR-167.6 · LLR-168.4 | `test_tc_b100_59_files_row` (NEW), AT-B100-05 Inc 7 extension. **cp1:** F3 arm (3 cases) |
| `tests/test_b100_save_guards.py` | test | LLR-164.4 | `test_tc_b100_07_failed_restore_keeps_the_previous_manifest` (NEW, 2 arms). **cp1:** F4, SEC7-3 (5), SEC7-5 (2), SEC7-6 (2) arms. **cp2:** R2-1 (Q1) refusal node; SEC7-R2-4 rollback node (`held`, `no-space`, `restored`) |
| `tests/test_variant_execution.py` | test | LLR-169.6 | re-pin. **cp1:** F7 exact count |
| `tests/test_b100_session_reset.py` | test | LLR-169.6 | re-pin: TC-B100-08's install marker (census) |
| `tests/test_b99_staging.py` | test | LLR-164.4 | re-pin: the LLR-155.3 allow-list gains `_restore_manifest`, `_keep_previous_manifest` (census) |
| `tests/test_tui_variants.py` | test | LLR-169.6 | re-pin: the `_parse_loaded_file` call-site list gains `_install_project_image` (census) |
| `tests/test_id_registry.py` | config | HLR-169 | `EXPECTED_SCANNED_TEST_FILES` 222 → 224 |
| `.dev-flow/2026-10-26-batch-100/03-increments/increment-007.md` | doc | HLR-169 | this packet |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-7/*` | generated | HLR-169 | transcripts (§4 evidence table) |
| `tools/e13/run.py` | test | LLR-178.1 · UX-26 | orchestrator-owned (not the implementer's, not reviewed by the two reviewers): scenarios `pe-patched` (`firmware_1.s19` with a `derived_from` record and `files` records for every file: "patched, 4 bytes differ from firmware.s19", 0 problems) and `pe-unreadable` (the active variant `broken.s19` holds no S19 data: the red `not readable` mark, Load opens the next valid variant, 2 problems) |
| `tools/e13/capture_all.ps1` | test | LLR-178.1 · UX-26 | orchestrator-owned: `pe-patched` and `pe-unreadable` added to the capture plan (7 plans x 3 sizes) |
| `.dev-flow/2026-10-26-batch-100/kimi/inc-7-HANDOFF.md` | doc | HLR-169 | implementer checkpoints (moved here from the worktree root `HANDOFF.md` at the close, as `kimi/inc-6-HANDOFF.md`) |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_project_check.py tests/test_b100_active_variant.py \
  tests/test_b100_announce.py tests/test_b100_save_image.py tests/test_b100_save_guards.py tests/test_variant_execution.py
# guards (BRIEF-COMMON step 5), then the census sweep:
python -m pytest -q -p no:cacheprovider tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py \
  tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py
python -m pytest -q -p no:cacheprovider -k census tests
# mutations: scratchpad/inc7-impl/mutate.py (each transcript names its mutant and ends with the restore check)
# corrective pass 1: scratchpad/cp7-1/mutate_cp1.py (19 mutants), mutate_prior.py (the 23 on the cp1 tree);
# reviewers' probes: evidence/inc-7/review/test_r7_probes.py, evidence/inc-7/security/probe_a_dos.py, probe_e_load.py
# corrective pass 2: scratchpad/cp7-2/mutate_cp2.py cp2|cp1|prior (8 + 19 + 23 mutants on the cp2 tree);
#   scratchpad/cp7-2/chain.sh (green, both reviewers' round-2 probes, census, guards — serial)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-7/`. **Final source hashes** (sha256[:16], printed in every transcript header from `green-01` on): `manifest_writer.py` `b3a8da7ae550bda5` · `variant_execution_service.py` `bd33c8be189d2c87` · `app.py` `0e29d80841fa3f38` · `screens.py` `e23ea8f72bc93153` (base `80052cb`: `c88152e6975e6c1b` · `76b276077ded9717` · `762d1a98c8a65903` · `ea549ab4bd9d3ef4`). No source byte changed after the final `green-01` (checkpoint 3 had `app.py` `c01797f665287871` and `variant_execution_service.py` `85fbde0ca2ae9d78`; the OQ-7a edit (`app.py`) and the CI-6-1 edit (`variant_execution_service.py`) came after it, and every transcript in the table below was produced after both, except `red-01` / `red-02` / `red-03` (base runs, base hashes in their headers)). Import proof in every header: `<HOME>\Github\s19_app-b100-inc7\s19_app\__init__.py`; `PYTHONPATH` = the tree; `NO_COLOR` unset.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | TC-B100-21 … -27, -60, -61, -62 seam arm (`test_b100_project_check.py`, 72 nodes incl. the 2 OQ-7a arms) · TC-B100-71 (6 nodes; the byte-copy node is a boundary pin that passes at base) · TC-B100-20 SEC6-2 (3 + 2 re-pins) · TC-B100-55 Inc 7 arms (3) · TC-B100-59 `files` row (1) · TC-B100-07 SEC2-10 (2 arms) · CI-6-1 (`test_tc_b100_67_overlong_entry_is_decided_on_the_text`, `test_tc_b100_20_append_says_now_opens_only_after_the_write_on_any_platform`, and the 3 Inc 6 CI nodes) | `executed` — all passed: `green-01-touched-modules.txt` (**269 passed**, 0 skipped, 0 failed: the 7 touched modules incl. `test_id_registry.py`), run after the last source edit; `test_b100_project_check.py` was edited once more (one selector made literal for the address census) and re-run in full in `green-02-repinned-census-modules.txt` (**132 passed**) |
| **B · black-box** `AT-NNN` ↔ story | `core` · `full` | AT-B100-07 (new, 118×54 + 220×60) · AT-B100-05 / -19 / -20 Inc 7 extensions (2 sizes each) · AT-B100-06 Inc 7 arm (`derived_from` on disk, 4) | `executed` — all passed, inside `green-01` |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| `test_b100_project_check.py` (as of checkpoint 3, 70 nodes) vs base `80052cb` | `red-01-project-check-vs-base.txt` | **63 failed, 7 passed.** Behavioural: TC-21 (no `files` key), TC-24 caps (1 001 entries read, no issue), TC-25 / TC-61 (`p04` cases 2 / 6 / 7 → 0 problems, P-4), TC-26 (P-5), TC-27 (shared `temp/project.json`, the QA race shape), TC-60 (`C:x.s19` etc. resolve, S-09), TC-62 seam (manifest written through the junction, SEC6-3), AT-07 ×2. ImportError nodes = new pure symbols — behavioural RED by the mutants below. The 7 passes are pins / boundaries / entries the base already refuses (TC-60 accepted-entries, default mode, hostile entries base refuses for another reason). |
| Other touched modules vs base | `red-02-other-modules-vs-base.txt` | **35 failed, 45 passed.** Every new and re-pinned node RED: TC-71 ×5 (no `derived_from`), TC-20 SEC6-2 ×3 + 2 re-pins, AT-06 ×4 (`derived_from` line), TC-55 ×7, TC-56 / TC-67 re-pins, AT-19 ×2, `test_load_project_unknown_active_variant_falls_back`, TC-59 `files` row, TC-07 SEC2-10 `held` / `no-space` (no previous-bytes copy) |
| CI-6-1 arms vs base | `red-04-ci-6-1-vs-base.txt` | **1 failed, 1 passed.** The length-rule arm (resolve and the reparse walk made non-raising, the POSIX behaviour) is RED: the 40 000-character entry is carried in `batch` — the Linux CI failure reproduced on Windows. The any-platform write-failure sibling passes at base by design: it is the Inc 6 behaviour with a platform-neutral failure (Inc 6's own RED stands) |
| Inc 7 AT extensions + OQ-7a arms vs base | `red-03-at-extensions-and-oq7a-vs-base.txt` | **8 failed.** AT-19 ×2 and AT-05 ×2 fail on the new "patched" line (no relation line at base); AT-20 ×2 on `derived_from` dropped by the rewrite; OQ-7a empty-image arm `[] == [('not readable', 'aaa.s19')]` (behavioural); OQ-7a checksum arm on the missing `LoadAnnouncement.unreadable` field — not behavioural by design (the base already opens such an image; the ruling preserves it), behavioural RED by `mut-OQ-7a-record-errors` |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| `files` digests | `tests/support/b100_projects.py` `file_records` (stdlib `hashlib`, never the app); `mut-LLR-169.1`, `-169.2-*` RED on it |
| byte-identical serialization without the new keys | golden string captured on `80052cb`; `mut-LLR-169.1` (empty `files`) RED |
| one problem per file | `merge_load_problems` arms in both input orders; `mut-LLR-169.9-keep-all` (2 RED) and `-last-wins` (1 RED) |
| timing bounds (TC-24 P-40, SEC6-5) | `time.perf_counter` around the real handler; `mut-LLR-169.4-cap` RED (6), `mut-SEC6-5` RED ("the panel took 9.84 s to paint") |
| SEC6-3 junction swap | the manifest path under the second work area is asserted absent; `mut-SEC6-3` RED (the file appeared there) |
| SEC2-10 previous copy | `project.json.previous-*` globbed beside the manifest; `mut-SEC2-10` RED ×2 (`[]`) |
| OQ-7a | `mut-OQ-7a-record-errors` / `mut-OQ-7a-empty` RED |

### Mutation verdicts (C-40) — `scratchpad/inc7-impl/mutate.py`; each transcript names the mutant (old → new), the source hash before, and ends `# reverted: sha256 restored = True`

| Mutation | LLR | Transcript | Verdict |
|---|---|---|---|
| emit an empty `files` key | 169.1 | `mut-LLR-169.1.txt` | KILLED 1 |
| walk sub-folders | 169.2 | `mut-LLR-169.2-walk.txt` | KILLED 1 (`inner.s19` recorded) |
| key on `.s19` (+ MAC, A2L) only | 169.2 | `mut-LLR-169.2-s19only.txt` | KILLED 1 |
| leave `files` out of the verify drift domain | 169.3 | `mut-LLR-169.3.txt` | KILLED 1 (`'verified' == 'mismatch'`) |
| accept a `bool` size | 169.4 | `mut-LLR-169.4-bool.txt` | KILLED 1 |
| no entry cap (P-40 timing arm) | 169.4 | `mut-LLR-169.4-cap.txt` | KILLED 6 |
| drop the `not recorded` kind | 169.5 | `mut-LLR-169.5.txt` | KILLED 1 (hand-copied arm) |
| open no MAC when no variant opens | 169.6 | `mut-LLR-169.6.txt` | KILLED 1 |
| stage through the shared `temp/project.json` | 169.7 | `mut-LLR-169.7.txt` | KILLED 2 (race arm + source pin) |
| no manifest-keys refusal | 169.8 | `mut-LLR-169.8.txt` | KILLED 10 |
| the tightening applied to every caller (P-41) | 169.8 | `mut-LLR-169.8-P41.txt` | KILLED 2 (incl. `test_tc_b97_20_hostile_refs_render_literally`) |
| keep every kind per file | 169.9 | `mut-LLR-169.9-keep-all.txt` | KILLED 2 (case 6 gives 2 problems) |
| the last problem per file wins | 169.9 | `mut-LLR-169.9-last-wins.txt` | KILLED 1 |
| paint the issue code | 169.9 | `mut-LLR-169.9-code.txt` | KILLED 1 (`MANIFEST-BAD-STRUCTURE` on screen) |
| record errors make the image `not readable` (pre-ruling reading) | 169.9 / OQ-7a | `mut-OQ-7a-record-errors.txt` | KILLED 1 |
| an image with no data installs | 169.6 / OQ-7a | `mut-OQ-7a-empty.txt` | KILLED 1 |
| drop `derived_from` from the carry | 168.4 | `mut-LLR-168.4.txt` | KILLED 1 |
| compare with the first variant by name | 178.1 (TC-55) | `mut-LLR-178.1-first-by-name.txt` | KILLED 1 |
| judge the resolved destination only | 171.4 (SEC6-3) | `mut-SEC6-3.txt` | KILLED 1 |
| rewrite over unknown keys | 168.3 (SEC6-2) | `mut-SEC6-2.txt` | KILLED 1 (`unknown-key`) |
| no previous-bytes copy | 164.4 (SEC2-10) | `mut-SEC2-10.txt` | KILLED 2 |
| drop the textual length rule | CI-6-1 | `mut-CI-6-1.txt` | KILLED 1 (the entry is carried in `batch`) |
| no bound on skipped-entry findings | SEC6-5 | `mut-SEC6-5.txt` | KILLED 1 |

23 mutants, 23 KILLED, all re-run on the final tree (`variant_execution_service.py` `bd33c8be189d2c87` in each header). A first form of the keep-all mutant (`best.get(file + str(len(best)))`) survived: it made the last problem per file win, which matched both arms' input order. It was replaced by a true keep-all mutant, and a reversed-order arm plus the `last-wins` mutant were added (the survivor's transcript was overwritten by the corrected run).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| `project.json` | parsed with the stdlib `json` (`b100_projects.read_manifest`); `files` equal to `hashlib` records; `derived_from` = `{base, sha256, differ}`; golden bytes without the new keys |
| the saved images | `tests/support/independent_reader.py` |
| the status line / panel | painted `#log_line_4`, `#status_text`, `#result_body` renders (`read_load_result_panel`, `flat`) |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 greps (the brief's three) | `reverse-census-grep.txt` | 44 paths: 41 test modules + 3 helpers (`tests/b97_fixtures.py`, `tests/support/b100_manifests.py`, `tests/support/b100_projects.py`); the union was re-computed on the final tree — identical |
| the 7 touched modules | `green-01-touched-modules.txt` | **269 passed** |
| the other 34 modules, serial, final tree, nothing else running | `census-tree.txt`; re-pinned modules re-run in full: `green-02-repinned-census-modules.txt` (**132 passed**) | **6 failed, 1043 passed** (1:12:17) — every failure dispositioned in the table below |
| B3 snapshot cells | `guards.txt` | first run on the final tree: **1 failed, 74 passed, 29 snapshots passed** (`test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — this increment's test file, see below); after the fix `guards.txt`: **75 passed, 29 snapshots passed** — no snapshot cell changed |
| census sweep | `guards-census.txt` | after the fix: **87 passed, 4020 deselected** (`guards-census.txt`) |

| Node(s) | Disposition | Evidence (base vs tree) |
|---|---|---|
| `test_b100_session_reset.py::test_tc_b100_08_reset_runs_once_before_the_first_install` | **Re-pinned (instrument).** The test marked an install by wrapping `load_selected_file`; the project variant now installs through `_install_project_image` (parse first, then apply — LLR-169.6), so only the MAC was marked: `['reset', 'install', 'reset', 'install']`. Old → new: install marker `load_selected_file` ⇒ `_apply_loaded_file` (both install paths apply through it); the oracle `["reset", "install", "install"] * 2` is unchanged — LLR-169.6 | base PASSED (`census-isolation-base.txt`); tree FAILED (`census-tree.txt`, `census-isolation-tree.txt`); re-pinned PASSED (`green-02-repinned-census-modules.txt`) |
| `test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement` | **Re-pinned (allow-list).** The SEC2-10 restore moved out of the allow-listed `_abort_save` into `_restore_manifest` (stage privately, `os.replace` onto the manifest this save wrote) and `_keep_previous_manifest` (claims a NEW name with `O_CREAT\|O_EXCL`, unlinks only its own partial claim). Old → new: `app.py` allow-list `{_abort_save, action_dump_a2l_json}` ⇒ `+ _restore_manifest, _keep_previous_manifest`, with the reason as a comment — LLR-164.4 / SEC2-10 | base PASSED; tree FAILED; re-pinned PASSED (same three transcripts) |
| `test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` | **Re-pinned (census list).** LLR-169.6 / LLR-169.9 need a project variant parsed before it is applied (a rejected image never reaches the views). Old → new: allowed sites `[_start_load_worker, load_selected_file]` ⇒ `+ _install_project_image`, with the reason as a comment — LLR-169.6 | base PASSED; tree FAILED; re-pinned PASSED (same three transcripts) |
| `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` (guard) | **This increment's own test fixed** (not a re-pin): `test_b100_project_check.py` queried `projects.LOAD_RESULT_CLOSE` (an attribute selector); it now queries the literal `"#result_ok"` | FAILED on base too with the new test file copied in (`census-isolation-base.txt`) — the cause is the test file; `guards.txt` 75 passed after the fix |
| `test_tui_patch_variant.py::test_tc_035_4_routing_guards` | **Timing flake, not introduced here** (`the run button must route execute_scope exactly once …, got []` under the 72-minute serial load) | passed in isolation on the tree (`census-isolation-tree.txt`, `census-flake-tc035-4-tree.txt`) and on base (`census-isolation-base.txt`) |
| `test_tui_commandbar.py::test_at_b78_03_…`; `test_tui_report_filter_surface.py::test_at_056e_a2b_…` | **Pre-existing at base** (the known set) | base FAILED: `census-known-vs-base.txt` (2 failed) |

No other census failure. The earlier census runs (`census-b100.txt`, `census-rest.txt`, an interrupted pre-CI-6-1 run) overlapped other runs and were discarded, per the orchestrator.

Re-pins (test::node — old → new — requirement):
- `test_b100_announce.py::test_tc_b100_55_first_by_name_manifest_damaged` — "Manifest damaged" → "manifest damaged" — LLR-169.9
- `::test_tc_b100_55_first_by_name_no_project_json` — ("No manifest", …) → ("no project.json", …) — LLR-169.9
- `::test_tc_b100_55_next_valid_when_the_recorded_one_is_missing` — "Missing variant" → "missing" — LLR-169.9
- `::test_tc_b100_55_three_problems_in_precedence_order` — 3 rows → 2 (one manifest-level kept) — LLR-169.9
- `::test_tc_b100_56_one_summary_line…` / `::test_tc_b100_67_*` seeds — manifests gain `files` (else 1 `no digests saved`) — LLR-169.5
- `::test_tc_b100_56_recorded_variant_with_control_bytes_paints_none` — the "activating the first variant" line → absent; 1 summary line — LLR-169.6
- `::test_tc_b100_67_thirty_problems…` / `damaged_manifest…` / fallback colour / wrapped / digit-limit / junction-loop — "Manifest damaged" / "Manifest entry skipped" → "manifest damaged" — LLR-169.9
- `::test_tc_b100_67_overlong_entries…` — 3 rows → 1 (the same entry under 3 keys = one file) — LLR-169.9
- `::test_at_b100_19_…` — "Missing variant: firmware-patched" → "missing: firmware-patched.s19" — LLR-169.9 (plus the planned Inc 7 "patched" arm)
- `test_b100_active_variant.py::test_tc_b100_20_a2l_sync_with_an_overlong_entry_does_not_crash`, `::test_tc_b100_20_variant_append_with_a_junction_loop_entry_does_not_crash` — rewritten with the entry dropped → `project.json` byte-identical + "holds entries that were skipped and was not rewritten" — SEC6-2 / LLR-168.3
- `test_variant_execution.py::test_load_project_unknown_active_variant_falls_back` — status line → summary count + `missing: ghost` problem — LLR-169.6
- `test_b100_active_variant.py::test_tc_b100_20_append_says_now_opens_only_after_the_write` — runs on every platform → Windows only (named skip), with the new any-platform sibling — CI-6-1 / LLR-168.3
- `test_b100_session_reset.py::test_tc_b100_08_…`, `test_b99_staging.py::test_tc_b99_13_…`, `test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` — see the census table above
- Planned arms (not re-pins): AT-B100-06 `derived_from` line; AT-B100-05 / -19 / -20 Inc 7 extensions; TC-B100-59 `files` row.

### Signed-balance test ledger

Scanned files: `224 = 222 + 2` (`tests/test_b100_project_check.py`, `tests/support/b100_manifests.py`; `EXPECTED_SCANNED_TEST_FILES` bumped with a one-line comment; `test_id_registry.py` passed inside `green-01`). New test functions: 35 in `test_b100_project_check.py` + 7 (`test_b100_active_variant.py`) + 4 (`test_b100_announce.py`) + 1 (`test_b100_save_image.py`) + 1 (`test_b100_save_guards.py`). Re-pinned: the nodes listed above. Removed: 0.

### Corrective pass 1 — results (F1–F8, SEC7-1–SEC7-6)

**cp1 source hashes** (sha256[:16], in every cp1 transcript header): `manifest_writer.py` `ab36c9a2a6216de5` · `variant_execution_service.py` `aae7d7fdde4d735e` · `app.py` `3b46619711652f9c` · `screens.py` `49d6efdc73e26b28` (pre-fix = the checkpoint-4 hashes above). Still 4 SOURCE files; `workspace.py`, `prototypes/` and `tools/e13/` untouched by this pass. Helpers: `scratchpad/cp7-1/run.sh` (transcript header), `mutate_cp1.py`, `mutate_prior.py`.

| Run | Transcript | Result |
|---|---|---|
| RED — the cp1 arms on the pre-fix tree (the 4 checkpoint-4 sources + the cp1 tests, in `scratchpad/cp7-1/pre`, its own import line) | `red-cp1-vs-pre-fix-tree.txt` | **25 failed, 17 passed.** Every failure behavioural (§6 lists each). The 17 passes are by design: test-gap arms F4 (PR) and F5 (PF), the F7 oracle fix, the 3 F6 re-pins, and controls (`emit`, `clean`, `newer-schema`, `unknown-key`, `skipped-entry`, `string-schema`, `float-schema`, versions `1` / `None` / `2` / `7`) |
| GREEN — the same 42 nodes, cp1 tree | `green-cp1-arms.txt` | **42 passed** |
| GREEN — every touched / re-pinned module (project_check, announce, save_guards, save_image, active_variant, variant_execution, session_reset, b99_staging, tui_variants, id_registry) | `green-cp1-touched-modules.txt` | **364 passed**, 0 failed, 0 skipped (19:01) |
| The reviewers' probes on the cp1 tree | `review-probes-cp1.txt` (`test_r7_probes.py` verbatim); `sec-probes-A-E-cp1.txt` (`probe_a_dos.py`, `probe_e_load.py` verbatim) | **7 passed** (P1 keys equal, PA `not readable: firmware.a2l`, PB 103 rows, PF, PN, PR). Probe A: A1 0.02 s, A2 0.01 s, A3 0.06 s, A4 0.01 s. Probe E (the A1 manifest through the Load dialog): `_handle_load_project` 0.07 s, click → panel 0.83 s (dialog open included), 3 rows, 0 codes / class names; variant append 0.40 s (was 10.74 / 11.57 / 10.64 s) |

**SEC6-5 timings on the cp1 tree** (from `green-cp1-arms.txt`, seconds — read / load / panel after the click / append's re-read to its outcome line): deep 30-component entries 0.233 / 0.362 / 0.001 / 0.634 · existing folder chain 0.116 / 0.161 / 0.000 / 0.614 · junction loop 0.071 / 0.111 / 0.001 / 0.570 · `files` at the cap all missing: load 0.20, 103 rows. Pre-fix tree (`red-cp1-…`): 10.68 / 10.47 / 0.82 / 10.88 · 1.77 / 1.94 / 0.68 / 6.18 · 16.27 / 16.50 / 0.62 / 16.62 · 999 rows.

**cp1 mutation verdicts (C-40)** — `mutate_cp1.py`; each `mut-cp1-<id>.txt` names the mutant (old → new) and the source hash before, and ends `# reverted: sha256 restored = True`.

| Mutation | Finding | Transcript | Verdict |
|---|---|---|---|
| no separate A2L read | F1 | `mut-cp1-F1.txt` | KILLED 1 |
| the composer lists every problem | F2 | `mut-cp1-F2.txt` | KILLED 1 (panel 2.29 s) |
| manifest-keys entries resolved one by one (no walk) | SEC7-1 | `mut-cp1-SEC7-1-resolve.txt` | KILLED 2 (read 6.26 s / 9.77 s) |
| no per-read cache | SEC7-1 | `mut-cp1-SEC7-1-no-cache.txt` | KILLED 1 (2 000 calls, not 1) |
| no filesystem-call ceiling | SEC7-1 | `mut-cp1-SEC7-1-no-ceiling.txt` | KILLED 2 (3 008 calls; append 1.91 s) |
| `files` keys walked before their scope check | SEC7-1 | `mut-cp1-SEC7-1-scope-after-fs.txt` | KILLED 1 (1 000 calls, not 0) |
| no 32-component text rule | SEC7-1 | `mut-cp1-SEC7-1-depth.txt` | KILLED 1 |
| the plan's `derived_from` from `image_step.emit` | F3 | `mut-cp1-F3.txt` | KILLED 2 |
| reviewer MR: the restore does not retry | F4 | `mut-cp1-F4-MR.txt` | KILLED 1 |
| reviewer MF: the fold row dropped | F5 | `mut-cp1-F5-MF.txt` | KILLED 1 |
| the composer adds the manifest's problems again | F6 | `mut-cp1-F6.txt` | KILLED 1 |
| the summary counts one too many (plural unchanged) | F7 | `mut-cp1-F7.txt` | KILLED 1 |
| `True` / `1.0` count as version 1 | F8 / SEC7-4 (a) | `mut-cp1-F8-type.txt` | KILLED 4 |
| every other version called newer | F8 | `mut-cp1-F8-wording.txt` | KILLED 5 |
| no containment re-check after the replace | SEC7-2 | `mut-cp1-SEC7-2.txt` | KILLED 1 |
| Save project replaces what it cannot carry, no copy | SEC7-3 | `mut-cp1-SEC7-3.txt` | KILLED 4 |
| the exception class painted again | SEC7-5 | `mut-cp1-SEC7-5.txt` | KILLED 2 |
| no guard on the claimed copy | SEC7-6 | `mut-cp1-SEC7-6-guard.txt` | KILLED 1 |
| a name taken by a junction ends the search | SEC7-6 | `mut-cp1-SEC7-6-taken.txt` | KILLED 1 |

19 cp1 mutants, 19 KILLED. **The 23 earlier mutants re-run on the cp1 tree** (`mutate_prior.py` → `mut-cp1-prior-<id>.txt`): 23 KILLED. Two needed their old text updated to the cp1 source (no change of intent): `LLR-169.8-P41` (the resolver signature gained `walk`) and `SEC6-5` (`_bound_entry_findings(issues, walk.unchecked)`); `SEC6-5` now survives its original node (the composed bound caps the rows) and is KILLED by the F5 arm added to its node list.

**cp1 test ledger.** New test functions: 8 in `test_b100_project_check.py` (F1, F5, SEC7-1 ×4, F2, SEC7-2; plus the `_counted_read` and scene helpers), 5 in `test_b100_save_guards.py` (F4, SEC7-5, SEC7-6 ×2, SEC7-3), 1 in `test_b100_save_image.py` (F3, 3 cases), 2 in `test_b100_active_variant.py` (+3 SEC6-2 cases), 1 in `test_b100_announce.py` (F6); 4 builders in `tests/support/b100_manifests.py`. Re-pinned: the 3 TC-55 nodes (F6) and `test_load_project_unknown_active_variant_falls_back` (F7) — §6. Removed: 0. Scanned files unchanged (224): no new test file.

**cp1 snapshot cells:** `guards-cp1.txt` — **75 passed, 29 snapshots passed**; no snapshot cell changed. `guards-census-cp1.txt` — **87 passed**, 4 055 deselected.

**cp1 reverse census:** `reverse-census-grep-cp1.txt` — the brief's three greps on the cp1 tree: the same union as before (41 test modules + 3 helpers). The 10 modules of `green-cp1-touched-modules.txt` (364 passed) plus the other 31, serial with nothing else running: `census-tree-cp1.txt` — **2 failed, 987 passed** (1:07:49). The 2 failures are the known pre-existing pair, `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` and `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`, both FAILED on base `80052cb` (`census-known-vs-base.txt`). No new failure, no flake in this run, no census re-pin.

### Corrective pass 2 — results (R2-1–R2-4, SEC7-R2-1–SEC7-R2-4)

**Final source hashes** (sha256[:16], in the header of every cp2 transcript from `mut-cp2-*` on): `manifest_writer.py` `3711eba2c27f3691` · `variant_execution_service.py` `425f610345f263c6` · `app.py` `923de169c6c44bc8` · `screens.py` `49d6efdc73e26b28` (cp1: `ab36c9a2a6216de5` · `aae7d7fdde4d735e` · `3b46619711652f9c` · `49d6efdc73e26b28`). Still 4 SOURCE files; `screens.py` untouched by this pass. The operator cut the pass's verification chain before it finished: what ran is listed first, what did not run is listed after it and is **deferred to Inc 8a's validation** (§7).

**Ran on the final tree**

| Run | Transcript | Result |
|---|---|---|
| RED — the cp2 arms (10 functions, 17 cases) on the cp1 tree (`scratchpad/cp7-2/pre`, its own import line) | `red-cp2-vs-cp1-tree.txt` | **15 failed, 2 passed.** Behavioural RED (the timing arm prints its numbers: SEC6-5 read 0.115 s / load 0.273 s / painted 0.517 s / appended 0.69 s). The 2 passes are by design: the Q1 test gap (R2-1: the code was right, the test was missing) and a control (`restored`) |
| RED — Q1 on the pre-cp1 tree | `red-cp2-q1-vs-pre-cp1-tree.txt` | **1 failed** |
| GREEN — the same arms, final tree | `green-cp2-arms.txt` | **17 passed** |
| GREEN — every touched / re-pinned module | `green-cp2-touched-modules.txt` | **379 passed** (19:35) |
| The reviewers' round-2 probes (11 nodes) | `review-probes-cp2.txt` | **1 failed, 10 passed.** The failure is probe Q2 (`test_q2_files_key_case_differs_from_disk`) = **R2-3**, deferred to the backlog by ruling (§6) |

**cp2 mutation verdicts (C-40)** — `scratchpad/cp7-2/mutate_cp2.py cp2|cp1|prior`; each transcript names the mutant (old -> new) and the source hash before, and ends `# reverted: sha256 restored = True`. **8 cp2 mutants, 8 KILLED; the 19 cp1 mutants re-run on the cp2 tree, 19 KILLED; the 23 earlier mutants re-run on the cp2 tree, 23 KILLED** (50 of 50 restored, `chain.log`).

| Mutation | Finding | Transcript | Verdict |
|---|---|---|---|
| the walk cache keyed on `normcase(part)` again | SEC7-R2-1 | `mut-cp2-SEC7-R2-1-normcase.txt` | KILLED |
| a fresh walk per entry in `serialize_manifest` | SEC7-R2-2 | `mut-cp2-SEC7-R2-2-fresh-walk.txt` | KILLED |
| every call counts toward the ceiling (not folder checks only) | R2-2 | `mut-cp2-R2-2-every-call-counts.txt` | KILLED |
| no folder-check ceiling | R2-2 | `mut-cp2-R2-2-no-folder-ceiling.txt` | KILLED |
| the SEC7-2 message carries the exception class | R2-4 / SEC7-R2-3 | `mut-cp2-SEC7-R2-3-class.txt` | KILLED |
| the kept copy joins `placed_files` again | SEC7-R2-4 | `mut-cp2-SEC7-R2-4-placed.txt` | KILLED |
| `_abort_save` removes the copy without confirming the restore | SEC7-R2-4 | `mut-cp2-SEC7-R2-4-unconfirmed.txt` | KILLED |
| Save project's refusal when no copy can be kept, disabled | R2-1 | `mut-cp2-R2-1-refusal.txt` | KILLED 1 (`'NoneType' object has no attribute 'with_name'`) |
| the 19 cp1 mutants on the cp2 tree | F1–F8, SEC7-1/-2/-3/-5/-6 | `mut-cp2-cp1-<id>.txt` | KILLED 19 |
| the 23 earlier mutants on the cp2 tree | Inc 7 checkpoint | `mut-cp2-prior-<id>.txt` | KILLED 23 |

**Ran on the previous app bytes only** (`app.py` `bd4dca9461d381c5`, before the last `getattr(issue, "details", {})` fix; the guards were not re-run on the final bytes): `guards-cp2.txt` **75 passed, 29 snapshots passed**; `guards-census-cp2.txt` **87 passed**.

**Not run — deferred to Inc 8a by the operator** (the operator cut the remaining runs to move to Inc 8a; nothing below is claimed):

| Run | Transcript | State |
|---|---|---|
| security probes re-run on the final tree | `sec-probes-cp2.txt` | **not run** — the file is empty |
| reverse census, 31 modules, final tree | `census-tree-cp2.txt` | **not completed** — stopped at about 29 % with no failure so far; no pass count exists. The earlier cp2 census (chain B, on `manifest_writer.py` `721f335bfed1cb89`) found 2 cp2-caused failures, both fixed: the headless-module test `test_manifest_writer_module_is_headless` (the logger was removed from `manifest_writer.py`) and the `test_tc_b100_57` byte-identity census (re-pinned for `_abort_save`'s restore confirmation) — see `kimi/inc-7-HANDOFF.md` |
| guards on the final app bytes | `guards-cp2.txt` / `guards-census-cp2.txt` (above) are on `bd4dca94…` | **not re-run** on `923de169…` |
| round-3 code + security review of the cp2 diff | — | **not run** (pre-cp2 sources are in `scratchpad/cp7-2/pre/`) |

**E13 (C-UX-5) evidence.** Orchestrator-owned captures, real Windows Terminal, 7 plans (`pe-clean`, `pe-saveback`, `pe-saveback-closed`, `pe-problems`, `pe-damaged`, `pe-patched`, `pe-unreadable`) x 3 sizes (118x54, 220x60, 99x54) = 21 PNGs in `evidence/inc-7/e13/`, one row each in the table below. `pe-patched` shows the "patched, 4 bytes differ from firmware.s19" line; `pe-unreadable` shows the red `not readable` mark. See OBS-7-1 (§6) for a defect seen in the first `pe-patched` capture.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-7/` | SHA-256 |
|---|---|---|
| census-flake-tc035-4-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-flake-tc035-4-tree.txt | a154822f7bc608348164895bb433e847fd39de4b1dc13e4b342719bf5db6bb96 |
| census-isolation-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-isolation-base.txt | 59870f05ab03f09d2b44ea0f575e5f3f99a288e66ee07dd0958aac94c0d9407a |
| census-isolation-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-isolation-tree.txt | 9a2807c45ceaeabb6037f2ae8c57ab0bd654fdb17876b2291571f5e8c89f995c |
| census-known-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-known-vs-base.txt | ee78accc08afa43c2e8cc3a511ea977d62ca9ef0fc1a212f4c796c11f173c9a1 |
| census-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree.txt | 07602c2f5c1edf7ec44b604c97d0e225f88f61185cedf314e415fc001dde0d81 |
| green-01-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-01-touched-modules.txt | 1eb75e37830d7c0d7ded8efebd77b6f5a9c6481c58ab4f9438343308b9c65f47 |
| green-02-repinned-census-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-02-repinned-census-modules.txt | 7b8941a8fff3e7f910ca6deda78502387d93a722b1fc0961f081b41b0e9feca5 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census.txt | 85488d1cfdf41e08c95fad9eae6c74bce141763d9bdbcaacaf9dd632bef70803 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards.txt | ca8a80d0d1c702e3be67b0969460577bb353902d2fe8287304d988d5eda53b98 |
| mut-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-CI-6-1.txt | f283ca9556f61500d765fd2872beb79102168f57ba1b78b5cf6f42bef0bd7532 |
| mut-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-168.4.txt | 41045a1c1cb036acc515d41647169af63f33968a98b59477b9b103c25f8c2b3a |
| mut-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.1.txt | dcbddcd8c978969ea884a576f8867f78b79c7dc3421815a2f188f9c841c080e2 |
| mut-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.2-s19only.txt | d656b39398f140edbe329a632bc4a55a5ca5603bc5b4c936808792674d106316 |
| mut-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.2-walk.txt | 56bec4f0e47dfeef1b63501429a01505e20d089f52bcc55b588ac3be9ded3310 |
| mut-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.3.txt | 1af7c94e38e2051785c7951e4c1c55ddb8dc738c625d66ed319cdd4c5878711a |
| mut-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.4-bool.txt | 369a892a00522b1e1274ee1caa1e5b3eebc92393df9d8847f78a42b31b048cf3 |
| mut-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.4-cap.txt | ee392b1d10f5a8cdcc43cee7dcc8bf4557086080e4b2c77fee2ff0e8571752df |
| mut-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.5.txt | ee8547ea8d19d389ae8963f3bdcbf5fc513ae3c0c8c8e30beea71c21fc2c6015 |
| mut-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.6.txt | b9ec8cb18cac98ed0c7f6cb97843ce163b3aa8f371e998654a0fbab979fc04ee |
| mut-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.7.txt | 745a6377bb7b49211e54a1d9ba663c44aa00daf124a523648178b14931814ff7 |
| mut-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.8-P41.txt | a0b0cddb070f02613892633481e2bd37d66f24fa5e4e1b223db162c4f9cae48d |
| mut-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.8.txt | 7fcc83da752882504bc33f60a6e6eb6b7adb06e85cd8a33a65ebc98a77e2ecc1 |
| mut-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-code.txt | 9c37e79173246a2c47804d441538445408614255ed027355aaf1920cbb76a501 |
| mut-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-keep-all.txt | 6f8ccf625d2ef98686cdab34017ef70da3e2ae9680d806853345333714102385 |
| mut-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-last-wins.txt | 14211c29212787f0335ced6d15a58266fb11298b9e9040f3a1f45bc551051e2a |
| mut-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-178.1-first-by-name.txt | a96ef59f7624f672a429900849ef85435c2fa2d47229b0544fbb8ef6017cfe80 |
| mut-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-OQ-7a-empty.txt | 49c95982a8cd1cb1a04a26d33e47f85cd27f98a4ebb3b994646ea64e4a79f1db |
| mut-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-OQ-7a-record-errors.txt | 671df9b4806a568de04ef637d8759c0441f142d21ec54adaa85b0e1144651936 |
| mut-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC2-10.txt | e62c5156b6301d011862d65f398ca17e6b65c07f2fedd97745a9c759d027a7bd |
| mut-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-2.txt | 57e08bd01b810e73325a82a3b1d0cae3978b27b4120f64e4176d21b644ee39a5 |
| mut-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-3.txt | 2a80559f75c943aafd3c1d11d868bd3929e825261123ededee568b0f092bc3b9 |
| mut-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-5.txt | 3d7c3745ded9502ebfd2ae8c70dc08c73813200ca0009832d2bd38930e98d5e8 |
| red-01-project-check-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-01-project-check-vs-base.txt | b95944dc7f690ec25b00a0c104efbca63f85377fb2532c98c3094e1ed4ee7bdb |
| red-02-other-modules-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-02-other-modules-vs-base.txt | bc9ae5083099aba2229f1e0ee749c27cd65a75af2b8264a02e70ce384203b3ed |
| red-03-at-extensions-and-oq7a-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-03-at-extensions-and-oq7a-vs-base.txt | 2bc411dbb2eca0bc88c7d2cf217e4be0fb42ee38f2d2c896dfcbf230d56343bf |
| red-04-ci-6-1-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-04-ci-6-1-vs-base.txt | 8c26ba808a208a2c3a86b3f9edf5df2ee85ed0fa8a08c6628a1595ad6e6b73e7 |
| reverse-census-grep.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep.txt | 8c94de6871c92ac4e529556fc85c5197602e7ad08949ea92a5ae8f21b786641b |
| census-tree-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree-cp1.txt | ff13987280bf648f43ab84828a7932cfe44a4706cdd8fbc79c1482317dff91f4 |
| green-cp1-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp1-arms.txt | f417e11d7d6d1c9165847ac73232b86ca5a2c5fb0d1f856e127a10996405da1d |
| green-cp1-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp1-touched-modules.txt | ec403f7675a7dfb15721c9ce90ad12351dc1b37db922094722d72fdccad1e76b |
| guards-census-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census-cp1.txt | 0a52cbe3a85ba00bd9b19e359011a584019c73026f4315a181564606e2ac60b6 |
| guards-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-cp1.txt | 810a13cd73667b1e9fdd52e27cf9d416c445cce24dfd32964ed394be9427398b |
| mut-cp1-F1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F1.txt | 32d2e321a4c3f5ad58c04e37cdeea4c44bdba041cf73f957dbc0d14dc31d9b32 |
| mut-cp1-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F2.txt | e1ea1a39bb05e962fd521a272cabe5fbfdfeebd333777d13605ff9381bc2bbd5 |
| mut-cp1-F3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F3.txt | 55cce2a0cc44dd77da1d5303d9ec3ef8a2e5d44df50d87e97244be98a7d15ec1 |
| mut-cp1-F4-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F4-MR.txt | 05362f44e0b6c27bcb11bac5635280ceae8d02fdb059b2c2164efdc6f86e15b3 |
| mut-cp1-F5-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F5-MF.txt | 545ac9688f98b220f378a32d006cc4c746bdbd897fa3bf5a5b884e945c583a2f |
| mut-cp1-F6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F6.txt | 7587612c90fec32369bb0f3a9af3983dcfbec646d9f9955ddd7ad6bf21234210 |
| mut-cp1-F7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F7.txt | ca3b09ca1b9aa72e93b70567d1dde2a7d6a7f874b7dd876555c7ee9618498d0a |
| mut-cp1-F8-type.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F8-type.txt | b35cd85dd5b3f799d3f8e755a8f3ea440e6274785c6df8350685b218fdaa8d7e |
| mut-cp1-F8-wording.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F8-wording.txt | 6107a299ec97e855174d1449f284c0918180810a12b938435210a9f0e3480758 |
| mut-cp1-SEC7-1-depth.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-depth.txt | 44d7cfb1cf297486051fe1c7fdf1f81ff49bc0557d19ac604a450b59397a56b8 |
| mut-cp1-SEC7-1-no-cache.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-no-cache.txt | 9c433f5f99850d313397f686c8a812a454f6de3cbe4369e13f3b797016f7c497 |
| mut-cp1-SEC7-1-no-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-no-ceiling.txt | 6476f31ef4b0e284a639293344b6f9713df015bc3705cfcf0293689c398938cb |
| mut-cp1-SEC7-1-resolve.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-resolve.txt | 8526c0aa725fe777bfb1ebb97ac1d6eeb6917e719b40d636cd283096af4fc263 |
| mut-cp1-SEC7-1-scope-after-fs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-scope-after-fs.txt | 4b14660110edcc51ca98fb9b982d1c52c213025e49e04ccfcb9f55c489d3ccda |
| mut-cp1-SEC7-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-2.txt | c8420f803dc6fabc75dadf3de2bcec2ae0f77e8f559afd4134db5546f3a80a4a |
| mut-cp1-SEC7-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-3.txt | 3e05f32b18337b5afd248ea5fbfb5eac43304d404c8042926ad6c550618cafda |
| mut-cp1-SEC7-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-5.txt | 7428cf16ca1065f121e5318751325e99e59231d944e24b9225cbbf721f221c7c |
| mut-cp1-SEC7-6-guard.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-6-guard.txt | 8962a1bbb2c98e3e7e81bb666324fcd812063447ba482c29cce7c769a10c9d46 |
| mut-cp1-SEC7-6-taken.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-6-taken.txt | b285cb4d4ea0b2d02c9ea7646537ec908ff4f62459921ecafc5adfca764fa89b |
| mut-cp1-prior-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-CI-6-1.txt | 46844cb10c637284fa53dbbbb69276461b78b96d6bf03218418408b30ad4b69a |
| mut-cp1-prior-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-168.4.txt | 6264aae15c046b55d775883c47e0123f1fdf2a506aabbea4e19c10d1da747adf |
| mut-cp1-prior-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.1.txt | bfbad04e3bf6a1af5d12a2049ecad431823f43d5ed7a1b20322191e8290bdacf |
| mut-cp1-prior-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.2-s19only.txt | f385ddc9cd08093c27248a37ccb0127a0368c801e2ebd8745f1d6dcc20741f5f |
| mut-cp1-prior-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.2-walk.txt | d57ecb4defd453987586c9788e43710766ee84531c712f1e59657a952ed00996 |
| mut-cp1-prior-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.3.txt | 0dbef77c387995c2b50dbed5a0007a9f3a99042e9cead937e9247e1452d6c52c |
| mut-cp1-prior-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.4-bool.txt | ccd4c926bdb3a4b6437c5c0b73b730512c30bd917b5f0e1fc11a58cbaab4ca10 |
| mut-cp1-prior-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.4-cap.txt | bb2a4adac4010de37557f8bf2472c61ee33ac3515f7e89f047d3b49f008f1c23 |
| mut-cp1-prior-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.5.txt | 341b6c75e7ddebd9c3ff139e730c2be2a8fdb925de6064f40f18cfb77675e902 |
| mut-cp1-prior-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.6.txt | b6ae590337b1a3b7413888cc825049415241c1fa4c759c0721a8a75f99dcba59 |
| mut-cp1-prior-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.7.txt | 6eab45154a2f0595c7e628cc8dae9ead4c6abd5cdfbbcbf4ab396b8fcfb3f1c6 |
| mut-cp1-prior-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.8-P41.txt | 19352a6a2561fbf2c1b5c6919b6474d59d3c9ce80dfb6cb855f9201c956a654c |
| mut-cp1-prior-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.8.txt | 7477c75c45ec633f1cce996963b45dc039733178e4022dba9381d672e4bd876d |
| mut-cp1-prior-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-code.txt | a19e5cf602711b3f642ec89c7a8ff0c1b5b8efedff3c09c749957f559ba40cf2 |
| mut-cp1-prior-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-keep-all.txt | 6d65cef5b08f56d352beb65eae58ce0bfca2415d53a2dcce818157e272e5d242 |
| mut-cp1-prior-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-last-wins.txt | 430beac0eb6e1db20deeed83f638ce39932c42638a1bcc45a383c6252e7a14fe |
| mut-cp1-prior-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-178.1-first-by-name.txt | 9526c5dd9422689361bf0c839bbeb1578ff8173458cc3a0e3e923db89bb103ab |
| mut-cp1-prior-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-OQ-7a-empty.txt | 038c1c17be4cbcfb2f197f9ba830ad2f823bda1450e1cb92ad9ae53f1dda2dab |
| mut-cp1-prior-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-OQ-7a-record-errors.txt | 8f00056fc9f5c6a8e2c91def4df24346b67b555dbb08889bb4fc49fd7fb1af23 |
| mut-cp1-prior-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC2-10.txt | 23f9ee739f9657a43cc0cf66e74559a22e59d4f28a1ae01de0965066097e480c |
| mut-cp1-prior-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-2.txt | 4cfd626d3696c39c1c4f88d6134a90ef2e1c42191d800e85139a4bc592bfc5d3 |
| mut-cp1-prior-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-3.txt | bc3915d429e2c5cf72d2709fa0073999c0edbc22e036f89de35a4c7539a1e6da |
| mut-cp1-prior-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-5.txt | 1ce21d7d52d6e54f2a69abfdd51ebcf46e94eeffa4da93506018c0be2e80cb95 |
| red-cp1-vs-pre-fix-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp1-vs-pre-fix-tree.txt | f1a6529e51faf1c2cd7263be7e34238e9d900f968cdede6dcc4874e178139ff3 |
| reverse-census-grep-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep-cp1.txt | 90ca1571666b3148768ef647a7373fbcc3d715b423fe72a71ff07ec6aa2e6098 |
| review-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review-probes-cp1.txt | 4be149f97405d0ee8de623dc3e21c4ad431f5c687d9ac9b9c385298f6711abe0 |
| sec-probes-A-E-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/sec-probes-A-E-cp1.txt | f4cc477ed51abed0060bb96f5bbab9ba26a7add429d1a31b0e52465266f81972 |
| census-tree-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree-cp2.txt | 450943c95f39be8a987f166b85dee7d747494ee2a88cb4233b611d59468bc4d9 |
| green-cp2-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp2-arms.txt | f527ebd14ce595c62a14456e9faad3d79f25766b1622339b6d903c6ffcafe8eb |
| green-cp2-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp2-touched-modules.txt | b08bceca027fc84c8cdc8491e0994aca5d7204bb34206e57d63332e6564e3016 |
| guards-census-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census-cp2.txt | 9e15bf6bbeb4e8ebad05d6da59d786b42f1d672c0e5d43c221744aa1e4035839 |
| guards-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-cp2.txt | db98ea4d6f2d2df35f6ba1be72fc8c2d10c27d30e5131bcbbfe4e9425b95e8bf |
| mut-cp2-R2-1-refusal.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-1-refusal.txt | cc1e35769805034c147b5056eeab0a836f21c7132a183fe839f65054037bf27f |
| mut-cp2-R2-2-every-call-counts.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-2-every-call-counts.txt | 3f209c6558ffbdf1c63c4d4129983c733e5d1f96e206db5d8c2a2f62f148429b |
| mut-cp2-R2-2-no-folder-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-2-no-folder-ceiling.txt | 4751c876db9e3d0235d81f1307a309dcdea30a1c5a5765c4b3ed2ce63c79def7 |
| mut-cp2-SEC7-R2-1-normcase.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-1-normcase.txt | 8831e26afc31721a805cf2ad4bf7938df1c8f18c9d9d663e573a8ab9ad0a8f63 |
| mut-cp2-SEC7-R2-2-fresh-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-2-fresh-walk.txt | ffc790ad0527307e897d7ccf641b2a797910ec1d171c5a183a8a7a327b38fbdd |
| mut-cp2-SEC7-R2-3-class.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-3-class.txt | 2f23255e941aa9f53287bcec93a45ea7cf3d74c06bf6fda468da4a5eb9d54b03 |
| mut-cp2-SEC7-R2-4-placed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-4-placed.txt | 9fb607d19d337c9d4325ee000b112cecd3b31ef21b23114065a7fe16d7cf889a |
| mut-cp2-SEC7-R2-4-unconfirmed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-4-unconfirmed.txt | 07a1cf98386d0e1380779aa2b05da9fe5edf87a4dc1700e9d2b96233327cee76 |
| mut-cp2-cp1-F1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F1.txt | e180fc434a96ce2f1c505a8b84b473b8ecc9913baf8e404e7f58c92b76a8c6f8 |
| mut-cp2-cp1-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F2.txt | 44ffd6a9e161224f3c784302395c40969fd167a232a36cae5b8799b70488a580 |
| mut-cp2-cp1-F3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F3.txt | ccaa67693d7c97c81f7149133819f835b568daa2c304681701aab08977b042e8 |
| mut-cp2-cp1-F4-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F4-MR.txt | 236bb9fab7a491c5d52861255336d1e9680fae049db4eb38c7d5a58c5e82a550 |
| mut-cp2-cp1-F5-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F5-MF.txt | 38cfcacedb1ae1c701dac81f80b12aa467b8b9faee17080921c0c2ba9c1a32db |
| mut-cp2-cp1-F6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F6.txt | c063a0472bbec599074faee9b83bdb5d042e262b33f8efd2c0346690b65fd314 |
| mut-cp2-cp1-F7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F7.txt | 9abc1dbd18c9708693062c4c5c858fb81d9660b8e30bc367208e353f09cc4356 |
| mut-cp2-cp1-F8-type.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F8-type.txt | 56f9b23a90d3c804846f0818f2ac0cd9e81f514e8427aa09830fbeb3b81442d6 |
| mut-cp2-cp1-F8-wording.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F8-wording.txt | 47b1aa7d76a73331bb5bbc7f92d9681ae7fc44dfb082a42d20b976c798451aa9 |
| mut-cp2-cp1-SEC7-1-depth.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-depth.txt | 79524ed0a95ab69c4fb6689d0e233ca90a58a16c4e769a7e7b4115832dda24b4 |
| mut-cp2-cp1-SEC7-1-no-cache.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-no-cache.txt | 6da56073e93c1c801c20f8e5279cf11eb7cfc2971fae88abf8d49343ef0c0f43 |
| mut-cp2-cp1-SEC7-1-no-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-no-ceiling.txt | c74cf3ef3ae61852ffbd3de324850f6691196e291db02a129ef22c07838889a8 |
| mut-cp2-cp1-SEC7-1-resolve.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-resolve.txt | 0f5dce2390d95a91aa567897abf88924afaea65df824a04a5b7732f28fdd88be |
| mut-cp2-cp1-SEC7-1-scope-after-fs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-scope-after-fs.txt | dabb60bae36cc7e882aa509d9dc247df5481db911ce95738e083a917fb68e9f0 |
| mut-cp2-cp1-SEC7-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-2.txt | e4ad1a66e4303031cbc8c09992f8d96a3feff3bfe293245608f5a1f8008b6cc1 |
| mut-cp2-cp1-SEC7-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-3.txt | 68693f2609532b557997a080f05aedc95ddd82a73f6b9cf27504a226bec9a53c |
| mut-cp2-cp1-SEC7-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-5.txt | 72f86009cab17b221a7e204bea50b9f6be30e8a252520e657aa62ac6b52b51e8 |
| mut-cp2-cp1-SEC7-6-guard.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-6-guard.txt | 9e4f21649df52512a4bb6869da5c25abd2e3894fa48b89cfa232f6c07d165406 |
| mut-cp2-cp1-SEC7-6-taken.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-6-taken.txt | 661f956ab3dc5245cb38310692ffd4bd10c135611b4dfe22b2f80ba27a078020 |
| mut-cp2-prior-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-CI-6-1.txt | b9a69735bf757c4877a54d602e68a8cca4d26c7e13784e71a9a4ebe76df6df42 |
| mut-cp2-prior-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-168.4.txt | c42655e9651a93c51d1d48272a4128b8b048547d6e317d4ab1bde2bd1f29a50a |
| mut-cp2-prior-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.1.txt | 8103bc57977717b869f5e391adcee80022dec648c1fb490f504fd5c9b6020cbd |
| mut-cp2-prior-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.2-s19only.txt | ef45bd373cd9cdc76d2813cd4133b1ddf19ec2846d7afd2eb4edce0b792a9c8b |
| mut-cp2-prior-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.2-walk.txt | 3494414078fe6ce56af8f1438d976e064d9033e7dba3ea7345df19775d787065 |
| mut-cp2-prior-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.3.txt | 6f70baed2a82c762e0c6373524c21bbef38a1c405fefac036f94d90dde4783f9 |
| mut-cp2-prior-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.4-bool.txt | 5d6444f16f82956a913b919baed6789205c4d751926c7e29fae395e885324560 |
| mut-cp2-prior-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.4-cap.txt | a45fd9054255a7e07d1535910b8b1821fd7409c36e7884aebc14a85ce838f845 |
| mut-cp2-prior-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.5.txt | 0df1f9f36d8d26d55de9bf1d507f37d89637d261251de140810dab931c487956 |
| mut-cp2-prior-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.6.txt | a2591df0245a11ca5d7660748b792c2926899eb37ce49d3fe254a2fd0cfb6157 |
| mut-cp2-prior-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.7.txt | 2c5450471d61e2fcbed087b28b3ea5115daf8117fe800c5e0deb5753aa789c39 |
| mut-cp2-prior-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.8-P41.txt | 49c16d8c31666df723f73ad4314af1aa1cc2c7250c629c561a45a8282e42a124 |
| mut-cp2-prior-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.8.txt | b4cb44b16704fc0ab84b7506ad0b541b1fd6eaf2bfea96004afc067e8a2f665c |
| mut-cp2-prior-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-code.txt | 4615349c4fc9ac490062469d8def194ff29d61a0ef3f8c01e24fd92fb98a1a0a |
| mut-cp2-prior-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-keep-all.txt | 248da50b80f0ef526f187c4290c22587f553bfd89af885b22c793d0cee677e87 |
| mut-cp2-prior-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-last-wins.txt | e97c4281771f381f0db5bc43577116470ea83a319050e73ce67f73a8326239f1 |
| mut-cp2-prior-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-178.1-first-by-name.txt | 63ad4b794abaaaf21a91c009450de84f861ca53aa5084915f2be3144a0ce9323 |
| mut-cp2-prior-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-OQ-7a-empty.txt | 4b2dc6ea2211e90040742b541ec25aff1f71a1f69e42ecd8bf82e6dd12e634b1 |
| mut-cp2-prior-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-OQ-7a-record-errors.txt | 2b94850087f15cbd6084567a2c22b3dc9bfdec365648628565071047e9997d2c |
| mut-cp2-prior-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC2-10.txt | 80443d906f0d871b6de4a1ba8240021a963867e023dac26a90b7b0f178d86895 |
| mut-cp2-prior-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-2.txt | 88e64bb8c1b58b53faeac55fb00953f7195307f4b01eaea1d0568040774d04b6 |
| mut-cp2-prior-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-3.txt | 6a15d5d90705455a3d29ca55888ebc3d4dafca2a5bb28f57dbe36fb64c4f226f |
| mut-cp2-prior-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-5.txt | 965b5afe4ab9fdf5e54d71d98a6677a69ab8a9a40d2e0e999a92d474388497ce |
| red-cp2-q1-vs-pre-cp1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp2-q1-vs-pre-cp1-tree.txt | c0e5da48caf523d39ef8500a1045be344b39cce6f78e2a6475fc2c5cde349312 |
| red-cp2-vs-cp1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp2-vs-cp1-tree.txt | ded6f4568da899b632395800bc4764e9629e1f51491c8461f89987c36f94c155 |
| reverse-census-grep-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep-cp2.txt | 9c297261fa9e88c4696cb6778aba1fb12a3c2dea240d52f975732791a989a030 |
| review-probes-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review-probes-cp2.txt | 17879482a6e3e1ea9068201901638251434dbc47a561b7e471ed7cadbccda960 |
| mut-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mut-MF.txt | 6dacdf587c6cf422cfa3be5d461c88b1317e66fd98ea8304a2452ec3718ee5fe |
| mut-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mut-MR.txt | ec615ca96c5311363d6a8c905759a2a8940cb7359018c8c84d6ea26732c7ca27 |
| mutate_r7.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mutate_r7.py | a096396f27c268cafc242eb3ae84a892f3137ea29d2150880663113c0f7c31ea |
| probes-tree-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/probes-tree-2.txt | 69cbc90b383103baea5904c500fc9eb0630e179f54b5f7c71a35737474b3a710 |
| probes-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/probes-tree.txt | 365e48652d7e66e6901d07efc3608f61587dd9abf24ea19e8f72764d0076a7b3 |
| r2-mut-SEC7-3-refusal.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-mut-SEC7-3-refusal.txt | 8ba2aeb68d95d1851d35830191eba31f535711d4a65f09b29de3444ef72c5321 |
| r2-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-probes-cp1.txt | 92273ebadb43aadac05fe5f24e926381851a4a4b2a8b3c47e3e4a06719b0a850 |
| r2-probes-pre.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-probes-pre.txt | 6c9118d62427351258a61ca74482c92f7a7fd8430dc8d1ffbf0db46fbc6c25d5 |
| r2-round1-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-round1-probes-cp1.txt | eb8af1ac19f458f052423bb33a8be6fd5783eb040769a76185620d3a443f3324 |
| r2-test_r2_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-test_r2_probes.py | b5db902650c5971043c99f7ede8ae7d59d5a59934a8728ab94aac3de8a5a2ae2 |
| run_mut.sh | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/run_mut.sh | 6375791e239c9ac0a287de0cc13e33a86dae6e18b97649ff86d3bf054cacce55 |
| test_r7_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/test_r7_probes.py | 772d5b6270e0954520fe4894b6e765a641ccc8c2642ef6e46025653d3a6aeb95 |
| sec-probes-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/sec-probes-cp2.txt | 473162a3033b34217e4b92f3ca3500d0fe0b791320009292428bae55baaa9ced |
| common.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/common.py | aed0018f7ecd3c5f41afa1b51e39ee8c872380238b72f31a810225fb83640b73 |
| out_A.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A.txt | ee38bbf779da2d862c36c4e5b83c1054aafedb8dc788bcc6854d1babcd7d716b |
| out_A2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A2.txt | b6a95a92b412b824523bf0f88b1f33f23f2613ae53df61709261dca8b8d388c5 |
| out_A_base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A_base.txt | 52ff94934a6afabba6e9e373ed4a6dbb0a45424f86b660a071698c90f7fdb183 |
| out_B.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_B.txt | bb9b009b914dfe6c8179694758d511d56cb15b117dcf745a2ba60c8b29d14474 |
| out_B_base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_B_base.txt | d9a4da517eee51e1f36899d59c3e65ce4ab1c5743b06fc234e312c09fca3dc3c |
| out_C.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_C.txt | 6312522210eb3bf8fa2b128bf8a41aa574a14746443a7e9c2bee0a3086e91de8 |
| out_D1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_D1.txt | 0aa629bcefbee2059d64a65b24a7b539f0448bbc6a082a2ba8f30017aadbb52b |
| out_D23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_D23.txt | 6c5e44e8f16f6b13dcc65355dbcfba0ff73d2c3b49c4e2fe06a6e96bf9be479f |
| out_E.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_E.txt | 031fdcc94d659ff7ccaff6d2030cfcc3fc11b8e3a956a9404a9e750905b706de |
| out_F.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_F.txt | 48d00c607c611f20d15f107575bcb3c7c1aa81aee492596b0a7dc8ae1d67aaf8 |
| out_H.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_H.txt | 7f6e46524df29213272b9eb4dd4171f6e167b552da79a7b499784b3bdb32a66e |
| out_pytest.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_pytest.txt | 5cd25aeb8f04391bb75fcfb5c8ae3b5f140c51ee259b996ee2333090f7c0f597 |
| probe_a_dos.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_a_dos.py | 606298084df67542d77ab2fdec68396cf2b591f8ee31bed157053c7d6f546e40 |
| probe_a_dos_base.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_a_dos_base.py | 7b30e02c1c9fd4cc5e8effa0951d491f92f4b2be0ae8494597f72d40c54399cd |
| probe_b_sec63.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_b_sec63.py | 54c96534a1c8b4c438ccca883ccdaff3573252f383dc5209156271a78a563753 |
| probe_c_restore.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_c_restore.py | 7e3f836291d4fc2b890235bfa451eef7f21baf869083f2adad53916f6009999d |
| probe_d_writers.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_d_writers.py | 35d17413be2eb5bfd2e6415f6ccca0f2ca76a16a402dd251971fc43d61193401 |
| probe_e_load.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_e_load.py | 64f989be808b715906d4f6a8aabc0ca22170bb1edad43f899fee437b6b6bc6cd |
| probe_f_files.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_f_files.py | 602d4c4740a80723771f4527ebe6ca15d47948f88ca91a0188cf631aebc3a3c3 |
| probe_h_parse.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/probe_h_parse.py | d79366f0b185c3eaa320e6d49422093860cadfaa28b160f4c5deb3e2375efc50 |
| r2_normcase_pairs.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_normcase_pairs.py | 8b3f35046855e8745177d71fddf10c685e6c30906a67056bbc8a66911cc80011 |
| r2_out_A.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_A.txt | f2b2c056ca5ef82d057fe130381867b0b6e0f2ee748a346f7c5dfb120819bd9c |
| r2_out_B.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_B.txt | 70800a6d85e52fc54924d6bf52ad5816992decb3493f6c58396a0335205a1e63 |
| r2_out_C.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_C.txt | 724d9f66199b1693fdabf8b0842e696e14b7b2dac7b5cb9c00300f7723c708c0 |
| r2_out_D.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_D.txt | de8490a9d1f2500f8f9c3ad13aa78b4b7f1792c97dc450ff1dd729c141bcf6cf |
| r2_out_E.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_E.txt | 25be5cd66145475ad5f2a67526316e1fe510e9ae1f43df5c73d11728a8e2010c |
| r2_out_F.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_F.txt | 243cdd9a62ced5ae7041c6df3148336d6f203dba5afc975534be621325b5a61f |
| r2_out_H.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_H.txt | 52f9cbeccc88c0778c92af0e1b66b18d21d279398400cdf5454202924631815b |
| r2_out_S.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_S.txt | 7caa63cdbe3b3a961d38483af7b279350bd599b61126ca5a2be58c3828e11f27 |
| r2_out_S4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_S4.txt | f5a644cd82cb160be69105ef4c118562ae88849d1fb248ec9356f5b280c57bf6 |
| r2_out_T.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T.txt | 98c6bf214e32a663326667e175611f0b7551f389efb6a918c0b2cfc2e859b8c7 |
| r2_out_T3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T3.txt | 48f13e74e46693820e6deaf6b34501d85c3f54220a2b2d0ebb2c4b657298bc82 |
| r2_out_T_prefix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T_prefix.txt | 9e4ce3f6ff0e5777bd208eadca27fa58fe07d68a0e06529fc6eab4410c1eda55 |
| r2_out_T_prof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T_prof.txt | d4540106c7b947c813ba02d9096ed4c411f477845a67f15745e9f912d5602864 |
| r2_out_W.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W.txt | 62ea799e5a2a7277c4e89ff9cbaa37651d3d63eee78d1e2603173c9928ec09e4 |
| r2_out_W2x.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W2x.txt | fca25be159163cef0a25ff3318553c4e60db345f4c1c633bce667eac4f4359c1 |
| r2_out_W2x_prefix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W2x_prefix.txt | 1c565f8ab6e6f5a83795724a0d4cad95550c4532a4f7b7510aa377d9f0f67f61 |
| r2_out_normcase.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_normcase.txt | a0b7f2aede328378fd79397ff1108821881762cd1a1283507b8891a35376146d |
| r2_out_pytest.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_pytest.txt | d13340923155b34ac5709c2843c1bff6238bb8af4c424891886cff65fcde534a |
| r2_probe_s.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_s.py | de84de6ea71d4d8107a2e7766ba26dde90d346763c6a0221217d682777477946 |
| r2_probe_t.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t.py | 53681360e016df8028e23773ddc139e2fe6e053774f3ff859535ac3f0b2d387d |
| r2_probe_t3.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t3.py | 2099f8a4686747327e95b096594500289cf0a74a4e126e0b3597ba8d94f2ca92 |
| r2_probe_t_prof.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t_prof.py | e5a3c27b67601c2ad79f57cafc9e0080421fe17127ea42e516e2e4654655969c |
| r2_probe_w.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_w.py | da8b60616991ae2b320558219627bfc6644611c2ae9d5d576100346067972214 |
| r2_probe_w2x.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_w2x.py | 20b18297580474d267009f6e31eb6354915441d74ec92cbdd92c8c69d88a186d |
| r2_run.sh | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_run.sh | d8b6f53d5607983982129d24f3cddc23c478e1f582022fbb9c82d63e5742aa2b |
| pe-clean.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-clean.118x54.png | d77c06d4abf9e964f2272d49913c2f271e7c63e7606fbb9f80452aa489488101 |
| pe-clean.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-clean.220x60.png | ac464a1769d87afe86f83a420c9c5688fc2ab03e4bf751928d7790fde4ae2ad3 |
| pe-clean.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-clean.99x54.png | 7bc97c9452430c6f7077f5411d15dce7eaac2e523c67a1ef294504496d80f697 |
| pe-damaged.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-damaged.118x54.png | eed3e5ede7aab340f9336b9b1c895aa12acc74691c09ab48fb2b37c8d839e770 |
| pe-damaged.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-damaged.220x60.png | 31c4c05ab28eb846e05102b2db8abb40c13287557625dcb967756c6dea6bb99d |
| pe-damaged.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-damaged.99x54.png | cf41efb7c174bf813df128b94cfe3ac9b749d2a8299aa78472a5adcec9286b46 |
| pe-patched.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-patched.118x54.png | 9f1fd31a60d623fb1e08a5b7d610319c91d4d5c2671b61e93f0f51a21ee0d900 |
| pe-patched.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-patched.220x60.png | d4be1d15c6978d36f63226d845a2db4101b57bb35da8c785609a0f00f9b0a49b |
| pe-patched.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-patched.99x54.png | 372c9b80cf8a6eb1bb4b8d3d2b89317d9a1917735f3371870c24f0c279034282 |
| pe-problems.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-problems.118x54.png | bfe56f59368e513760c0620ac7421abfb1c3215dc166d1b13404677cb7e9ff3e |
| pe-problems.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-problems.220x60.png | f6decbedbb24a98504c2f20c0e79250f37b06affb5df845c4bfe34cf56f80bd2 |
| pe-problems.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-problems.99x54.png | f45d9d27a255c4e81b186f3603286c1d24330069be62ad8867e2f2f2003b2fff |
| pe-saveback-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback-closed.118x54.png | 56cd751c0758fec152f08633268b04f3b2aabb84132260a229dc9b6d3ea4fd84 |
| pe-saveback-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback-closed.220x60.png | adfa8cfc7c878856fb8f64ffc239c695a6e9747ea3d711a81bb6cb6e6aad7fde |
| pe-saveback-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback-closed.99x54.png | 4043924f3a88e47b3d5e93a5558f69011add0be7e0917588acaaf67a8de9a866 |
| pe-saveback.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback.118x54.png | cfc968f63a90cd87d4e22e67e62502e37709b2fdbd36d30a508576436d8b6ab4 |
| pe-saveback.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback.220x60.png | 9f67166473771cc42f2d9f7d21fdf2cfa35cd46c80d22ef35089ad9eedeb646a |
| pe-saveback.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-saveback.99x54.png | 92a3b03321a7230a5f1bc631bfdb803808c69fa968b43ee0da1ccbf819cbb3f8 |
| pe-unreadable.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-unreadable.118x54.png | cc30cb828da4453985e008f1c7317354c999b5c7110cc43a039d41eb676b0b84 |
| pe-unreadable.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-unreadable.220x60.png | fea5fdd5a20abf1305bb42a275c433ebc2bb43536bee1f6e991845695e5b3228 |
| pe-unreadable.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-7/e13/pe-unreadable.99x54.png | b466330decc9a43276d5ba182e70d7d0ff78c3f3ba7f1ba55e13f78dc4db0720 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES r2 (r1 FAIL `BLOCK — BLOCK-UNTIL: F1, F2, F3`) — r1: F1 MAJOR the project's A2L read inside the image's `try` blamed the image, F2 MAJOR the composed problem list was unbounded (999 rows), F3 MAJOR the save plan's `derived_from` keys differed from the written keys; F4, F5 MINOR test gaps; F6–F8 LOW. r2: F1, F2, F3 closed on the diff and the probes PA, PB, P1 re-run GREEN; F4–F8 closed; 0 HIGH, 0 MAJOR open; new: R2-1 MINOR (the SEC7-3 refusal branch had no test; code right), R2-2 MINOR (the 2 000-call ceiling skipped valid entries inside the caps), R2-3 LOW (a case-only `files` key mismatch reports `not recorded`), R2-4 LOW (the SEC7-2 toast showed the exception class) — `review-increment-007.md`, transcripts under `evidence/inc-7/review/`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · PASS-WITH-NOTES r2 (r1 PASS-WITH-NOTES, SEC7-1 MAJOR): r1 SEC7-1 MAJOR the manifest read cost 8–20 s on a 1 MiB manifest (per-entry `resolve()`), SEC7-2 to SEC7-6 MINOR/LOW; r2: SEC7-1 closed for the reader and Load, SEC7-2 closed as detection, SEC7-3, -5, -6 closed per ruling; new SEC7-R2-1 MAJOR (the walk cache folded case: a junction in a case-sensitive folder was accepted), SEC7-R2-2 MAJOR (the writers re-walked each entry: 6.4–7.1 s), SEC7-R2-3 LOW, SEC7-R2-4 LOW — all four fixed in corrective pass 2 and **not re-reviewed**; SEC7-4 (b) deferred to the backlog — `security-increment-007.md`, transcripts under `evidence/inc-7/security/`. **Orchestrator (2026-10-30).** Final source hashes: `manifest_writer.py` `3711eba2c27f3691`, `variant_execution_service.py` `425f610345f263c6`, `app.py` `923de169c6c44bc8`, `screens.py` `49d6efdc73e26b28`. Ran on the final tree: RED (15 failed / 2 passed, behavioural), cp2 arms 17 passed, touched modules 379 passed, the reviewers' probes 10 passed / 1 failed (Q2 = R2-3, backlog), 50 of 50 mutants KILLED and restored. Ran on the previous `app.py` bytes `bd4dca9461d381c5`: guards 75 passed + 29 snapshots, census sweep 87 passed. **Not run — deferred to Inc 8a's validation by the operator:** the 31-module reverse census on the final tree (stopped at about 29 %, no failure so far), the guards on the final `app.py` bytes, the security probes re-run (`sec-probes-cp2.txt` empty), and round-3 code + security review of the cp2 diff. Rulings applied: OQ-7a, OQ-7b, SEC6-2 refuse-rewrite, SEC6-5 bound, `derived_from` names, qa F6 -> Inc 12b, CI-6-1, the accepted cp1 behaviour changes, SEC7-3, the cp2 folder-check ceiling (§6). |

---

## 5 · Risks

- **OQ-7a reading of LLR-169.9** ("load errors" = fatal load errors): an image with data and record-level errors opens as before and is not reported as a problem on the panel; its errors show where they always did. The ledger amendment is the orchestrator's at close.
- **The CI-6-1 length rule applies in the default mode too** (flow references): on Windows nothing changes (such an entry already failed `resolve()`); on POSIX an entry over 32 767 characters is now skipped instead of carried. The Linux result is reasoned from the arm, not executed here.
- **A rewrite is now refused for any skipped entry, unknown key or newer `schema_version`** (SEC6-2). A project carrying a hand-edited bad entry keeps its old `project.json` after a save-back / append / sync until Save project; the session and disk can differ (the status says so — the Inc 6 OQ-1 (b) shape).
- **The reader's manifest-keys mode also applies to `batch` / `assignments` / `gathered`** (LLR-169.8 "used by `read_project_manifest`"): an entry such as `doc.json.` or `CON.json` that used to resolve is now skipped and reported.
- **`_install_project_image` parses before applying**: a rejected image never reaches the views; the parse cost of a rejected image is paid once per attempt.
- **Seeds without `files`** now report `no digests saved` (1 problem): Inc 6 tests that expected `0 problems` from hand-written manifests were given `files` records (§4 reverse census).
- **The `files` scope is the top level only** (O-2): a data file under a sub-folder is neither recorded nor reported.
- **Corrective pass 2 is not fully verified** (operator cut): the 31-module reverse census, the guards and the security probes were not run on the final tree and the cp2 diff has no round-3 review (§4, §7). The earlier cp2 census found 2 cp2-caused failures, both fixed; a third is not excluded until the census runs.
- **A manifest-keys read checks at most `MANIFEST_FOLDER_CHECK_CAP = 1000` distinct folders** (R2-2): an entry that would need a check past it is skipped unchecked and counted in the fold finding. Measured in the worst-case arm on Windows; not run on POSIX.
- **R2-3 (open, backlog):** on Windows a `files` key that differs from the on-disk name only by case reports `not recorded` for that file.

## 6 · Pending items / spec deviations

- **OQ-7a — ruled by the orchestrator (2026-10-30), implemented.** `not readable` applies only to an image whose install yields NO data: an empty `mem_map`, or a file that does not parse as S19/HEX. An image that installs with data but carries record-level load errors (bad checksums, `examples/case_04_bad_checksums`) stays open, is NOT a `not readable` problem, and its errors stay on the loaded file where the app showed them before this batch. Reason (orchestrator): viewing a file with checksum errors is a primary use of the tool; refusing to open it is a regression. **Reading of LLR-169.9:** its "load errors" is read as *fatal* load errors (the parse raises, or no data results). The ledger amendment is recorded by the orchestrator at close. Code: `app.py` `_install_project_image` lost its `elif loaded.errors` branch (reasons left: "not an S19 or HEX file", "0 data bytes"). Arms: `test_tc_b100_61_checksum_errors_only_keep_the_image_open` (a case_04 project with `files` records → 0 problems, 0 `not readable`, `firmware.s19` open with `mem_map` and `errors`), `test_tc_b100_61_empty_image_is_not_readable_and_load_moves_on` (the recorded `aaa.s19` holds a terminator only → 1 `not readable`, `firmware.s19` opens per LLR-169.6). Mutants `OQ-7a-record-errors` and `OQ-7a-empty`. TC-B100-61's numeric threshold is unchanged.
- **OQ-7b — accepted (orchestrator): fixture deviation.** The TC-B100-22 fixture adds `checks/inner.s19`, so the "walk sub-folders" mutant has a data-suffix file to find (the contract's `flows/f1.json` has no data suffix and cannot show the walk).
- **SEC6-2 — accepted (orchestrator): refuse the rewrite.** An in-project rewrite (save-back, variant append, MAC / A2L sync) is refused — never carried verbatim — when the manifest is damaged, has `schema_version` ≠ 1, has unknown top-level keys, or has skipped entries (`manifest_rewrite_refusal`). One status line names why and that `project.json` was not rewritten; Save project stays the recovery path. Arms: `test_tc_b100_20_rewrite_never_drops_what_it_cannot_carry` (the three conditions) and the two re-pinned TC-20 hostile-entry nodes.
- **SEC6-5 — accepted (orchestrator): the bound (as first shipped; found false by `code-reviewer` F2 and `security-reviewer` SEC7-1; the corrective-pass bound below replaces it).** The reader keeps at most `MANIFEST_ENTRY_ROWS = 100` skipped-entry findings one by one and folds the rest into 1 counting row (`<N> more recorded entries`). Panel rows ≤ 100 individual skipped-entry rows + 1 fold row + 1 manifest-level row + 1 per top-level project file. The `..` escape is decided on the text alone (no file-system call per entry). Executed arm: every capped array at 1 000 bad entries → load and panel each under 1 s (`test_tc_b100_61_every_array_at_the_cap_all_bad_opens_under_one_second`); at the reviewed Inc 6 tree, 6 000 bad entries took 10.2 s.
- **AT-index extensions owed at Inc 7 (01-requirements.md §5.3, lines 1910, 1924, 1925) — done.** AT-B100-05: the reopened P1 panel says "patched from firmware.s19 (not in this project); 4 bytes differ from it" (Save project's emit records the loaded source as base; the source is not a file of P1). AT-B100-19: the default save-back name opens with "patched, 4 bytes differ from firmware.s19", and the panel never says "identical". AT-B100-20: P also records a `derived_from` for `firmware.s19`; after each of the three writers it is JSON-equal to the seed. RED on base: `red-03-at-extensions-and-oq7a-vs-base.txt`. AT-B100-20 seeds its `derived_from` by hand, as it already seeds the four not-owned keys (the carry is the outcome under test; the shipped save-back writes the record in AT-B100-06 and TC-B100-71).
- **`derived_from` JSON field names (LED .48) — accepted (orchestrator), frozen with B100-I16:** `base` (one path component), `sha256` (64 lowercase hex), `differ` (int ≥ 0).
- **qa-reviewer F6 (Inc 3) — ruled:** Inc 7 owes no real-worker boundary arm; it goes to **Inc 12b**, where loads move onto workers.
- **The OQ-7a preservation arm is not RED at base by behaviour.** At base a case_04 project already opened its image; the base run fails only on the new `LoadAnnouncement.unreadable` field (`red-03`). Its behavioural RED is the mutant `OQ-7a-record-errors` (the pre-ruling reading).
- **New-symbol RED (not behavioural) in `red-01`:** the pure helpers (`file_record`, `project_file_records`, `derive_record`, `check_project_files`, `merge_load_problems`, …) fail at base with `ImportError`; each has its behavioural RED by a mutant (§4 mutation table).
- **Windows-only arms:** the junction arms (SEC6-3 seam arm, the junction-loop re-pin) skip off Windows with a named reason; all ran on Windows here (0 skipped in `green-01`).
- **Not covered:** POSIX symlink behaviour of the `files` scope and of the SEC6-3 guard (Windows only ran).
- **CI-6-1 (Linux): overlong entries decided on text — orchestrator item, implemented.** Inc 6 CI on Linux had 3 new failures. `_resolve_manifest_entry` skipped an entry only when `Path.resolve()` raised, which Windows does for a 40 000-character path and POSIX does not. Now an entry longer than `MANIFEST_ENTRY_MAX_CHARS = 32 767` characters (the Windows path maximum) is one skipped entry (`MANIFEST-PATH-ESCAPE`, reason "a file path is not a plain name in the project") on the text, in every mode and on every platform, before any filesystem call; the `OSError` / `ValueError` / `RuntimeError` handling stays as the fallback. Arm: `test_b100_announce.py::test_tc_b100_67_overlong_entry_is_decided_on_the_text` makes `Path.resolve` and the reparse walk non-raising (the POSIX behaviour) and asserts one skipped entry per key in the reader and in the default mode, and that an entry of exactly 32 767 characters is not refused by the length rule; RED on base (`red-04`: the entry is carried), mutant `CI-6-1` KILLED. Fixes `test_tc_b100_20_a2l_sync_with_an_overlong_entry_does_not_crash` and `test_tc_b100_67_overlong_entries_are_skipped_rows_not_a_crash` on Linux (reasoned from the arm; Linux itself was not run here).
- **CI-6-1, third node — a different root cause (finding).** `test_tc_b100_20_append_says_now_opens_only_after_the_write` makes `project.json` read-only to force a write failure. A POSIX `rename` replaces a read-only file when the folder is writable, so on Linux no failure happens and the manifest is rewritten — this is not the overlong-entry dependency (reasoned, not executed on Linux). Fix (tests only): that node now skips off Windows with a named reason (PDR C-QA-6), and a new sibling `test_tc_b100_20_append_says_now_opens_only_after_the_write_on_any_platform` forces every `os.replace` onto `project.json` to raise `PermissionError` (what Windows raises), so the same outcome is checked on every platform. Re-pin: `::test_tc_b100_20_append_says_now_opens_only_after_the_write` — runs everywhere → Windows only, with the any-platform sibling — CI-6-1 / LLR-168.3.

- **Corrective pass 1 — finding → disposition** (`review-increment-007.md`, `security-increment-007.md`; orchestrator rulings). Every arm is RED on the pre-fix tree (`red-cp1-vs-pre-fix-tree.txt`, the four checkpoint-4 sources with the cp1 tests) unless marked "test gap", GREEN on the cp1 tree (`green-cp1-arms.txt`), and each named mutant is KILLED (`mut-cp1-<id>.txt`).
  - **F1 (MAJOR) — fixed.** Arm `test_b100_project_check.py::test_tc_b100_61_unreadable_a2l_is_its_own_problem_and_the_image_opens` (reviewer probe PA): RED `[('not readable', 'firmware.s19')]`; mutant `F1` (no separate A2L read) KILLED.
  - **F2 (MAJOR) + SEC7-1 (MAJOR), rows — fixed. The bound, exactly:** a Load announcement lists at most `LOAD_PROBLEM_ROWS = MANIFEST_ENTRY_ROWS + 2 = 102` problems one by one (the reader's ≤ 100 skipped-entry rows, its 1 fold row and 1 manifest-level row always fit), plus at most ONE row counting the rest — **≤ 103 problem rows on the panel, whatever their source** (reader findings, disk problems, install problems). The reader's own bound is unchanged: ≤ 100 skipped-entry findings + 1 fold finding counting the rest (including entries skipped unchecked past the filesystem ceiling). Arm `test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` (probe PB): RED `999` rows; GREEN 103 rows (102 `missing` + `more problems: 897 more files`), title and summary say `999 problems`; mutant `F2` KILLED.
  - **SEC7-1 (MAJOR), time — fixed; SEC6-5 time bound discharged on Windows.** Measured on the cp1 tree (read / `_handle_load_project` / variant-append to its manifest outcome line, seconds): deep missing entries, 30 components, 5 × 1 000 — **0.233 / 0.362 / 0.634** (pre-fix tree: 10.68 / 10.47 / 10.88); 3 000 entries under an existing 8-level folder chain — **0.116 / 0.161 / 0.614** (pre-fix: 1.77 / 1.94 / 6.18); junction loop, 5 × 1 000 — **0.071 / 0.111 / 0.570** (pre-fix: 16.27 / 16.50 / 16.62); `files` at the cap all missing (PB) — load **0.20**, panel 103 rows. The security probes' own manifests (`probe_a_dos.py` re-run on the cp1 tree): A1 (37 components, 975 561 bytes) read **0.02 s** (now refused on the text by the 32-component rule; was 9.94 s), A2 (32 entries × 16 300 components) **0.01 s**, A3 (junction loop) **0.06 s** (was 19.57 s), A4 (through an in-project junction) **0.01 s** (was 8.09 s); app-level probe E (the A1 manifest through the Load dialog, then a variant append): `_handle_load_project` **0.07 s**, click → panel painted **0.83 s** (includes opening the dialog), append to its outcome line **0.40 s** (was 10.74 / 11.57 / 10.64 s) — `sec-probes-A-E-cp1.txt`. Arms: `test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent`, `…_entries_under_an_existing_folder_stop_at_the_ceiling`, `…_junction_loop_costs_one_failure` (non-`..` entries, assert read, load, panel and the writer's re-read each < 1 s and the row bound), `…_each_name_is_checked_once_per_read` (filesystem calls: 1 for 3 000 deep entries, 0 for 1 000 nested `files` keys, 0 for a 40-component entry, exactly 2 000 under the existing chain). Mutants `SEC7-1-resolve` (resolve per entry again: read 6.26 s / 9.77 s), `-no-cache` (2 000 calls), `-no-ceiling` (3 008 calls), `-scope-after-fs` (1 000 calls), `-depth` all KILLED. **New text rule (declared):** a manifest-keys entry with more than 32 path components is refused on the text (`MANIFEST-PATH-ESCAPE`, "a file path is not a plain name in the project") — the security reviewer's recommendation; without it a 1 MiB manifest of 16 300-component entries cost 0.58 s of per-component text work in one read.
  - **F3 (MAJOR) — fixed.** Arm `test_b100_save_image.py::test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from[carried|emit|emit-base-unreadable]` (LLR-167.6 plan == written keys): RED for `carried` (plan omits `derived_from`) and `emit-base-unreadable` (plan lists it, none written); `emit` is the control; mutant `F3` (`derived=image_step.emit`) KILLED 2.
  - **F4 (MINOR) — fixed (test gap).** Arm `test_b100_save_guards.py::test_tc_b100_07_restore_retry_lands_when_the_holder_lets_go` (probe PR; passes on the pre-fix tree by design); reviewer mutant MR (`attempts >= 1`) KILLED (`mut-cp1-F4-MR.txt`).
  - **F5 (MINOR) — fixed (test gap).** Arm `test_tc_b100_61_skipped_entries_beyond_the_bound_are_counted` (probe PF: 100 entries + `50 more recorded entries`, painted as a `manifest damaged` row); reviewer mutant MF (fold row dropped) KILLED. The earlier `SEC6-5` mutant (no reader fold) now survives its shipped node (the composed bound caps the rows) and is KILLED by this arm (`mut-cp1-prior-SEC6-5.txt`).
  - **F6 (LOW) — fixed.** One source: `check_project_files`. Arm `test_b100_announce.py::test_tc_b100_55_composer_adds_no_second_copy_of_the_check` (RED: the composer added the row); mutant `F6` KILLED. Re-pins (oracles unchanged, input made explicit): `test_tc_b100_55_first_by_name_manifest_damaged`, `…_no_project_json`, `…_three_problems_in_precedence_order` now pass the project check's problems (`problems=`), as the load does — F6 / LLR-169.9.
  - **F7 (LOW) — fixed.** `test_variant_execution.py::test_load_project_unknown_active_variant_falls_back` asserts the exact count (`, 2 problems - details: p`, and `count == 2`); mutant `F7` (the summary line counts one too many, plural unchanged) KILLED.
  - **F8 (LOW) + SEC7-4 (a) (LOW) — fixed.** Arms `test_b100_active_variant.py::test_tc_b100_20_schema_version_is_the_integer_one` (9 values), `…_reader_keeps_a_float_schema_version`, and the SEC6-2 writer matrix gains `bool-schema` (RED: rewritten as 1), `string-schema`, `float-schema`; mutants `F8-type` (KILLED 4) and `F8-wording` (KILLED 5).
  - **SEC7-2 (MINOR) — fixed (detection).** Arm `test_tc_b100_62_swap_after_the_check_is_reported_never_written` (the reviewer's injected swap in `_private_stage_dir`): RED `written = P/project.json`, no finding; GREEN `written None`, one `MANIFEST-WRITE-CONTAINMENT` naming `Q`. The bytes still land in Q (a handle-relative replace is not available on Windows); the write is reported as failed, never verified. Mutant `SEC7-2` KILLED.
  - **SEC7-3 (MINOR) — fixed per ruling.** Arm `test_tc_b100_07_save_project_keeps_a_manifest_it_cannot_carry[unknown-key|newer-schema|bool-schema|damaged|clean]`: RED ×4 (no copy); `clean` is the control (no copy, no line). Mutant `SEC7-3` KILLED 4.
  - **SEC7-5 (LOW) — fixed.** Arm `test_tc_b100_07_restore_status_paints_no_exception_class[held|no-space]` (the class is in the log line); RED `(PermissionError)` / `(OSError)`; mutant `SEC7-5` KILLED 2.
  - **SEC7-6 (LOW) — fixed.** Arms `test_tc_b100_07_previous_copy_never_lands_outside_the_work_area` (RED: the copy landed outside) and `test_tc_b100_07_taken_previous_names_move_to_the_next_candidate` (a junction then a folder hold the first two names → the copy lands on `-2`; RED `None`); mutants `SEC7-6-guard`, `SEC7-6-taken` KILLED.
  - **SEC7-4 (b) — deferred to the backlog (orchestrator):** unknown fields nested inside `derived_from` / `declared_regions` records are still dropped silently by an in-project rewrite (records are rebuilt from parsed fields). Not fixed here.
  - **Reviewer notes, not findings:** the `files` hashing runs before the write's containment guard (read-only; for `security-reviewer`); a POSIX-only top-level name with `:` / a trailing dot makes `serialize_manifest` refuse the whole manifest (backlog line); `InstallSet.a2l` has no caller yet (Inc 9b).
  - **`tools/e13/` changes** in the worktree are the orchestrator's (not this increment's, not reviewed here, not touched by this pass); §2 lists them, §4 names the E13 evidence.

- **Corrective pass 2 — finding -> disposition** (round 2 of `review-increment-007.md` and `security-increment-007.md`; orchestrator rulings). Arms RED on the cp1 tree (`red-cp2-vs-cp1-tree.txt`), GREEN on the final tree (`green-cp2-arms.txt`), each named mutant KILLED (`mut-cp2-<id>.txt`).
  - **SEC7-R2-1 (MAJOR, regression) — fixed.** `_EntryWalk` keys a component by its exact text (a child dict per node), never `normcase`; in a case-sensitive folder `sub` and `SUB` each get an `os.lstat`. Arm: 2 cases. Mutant `SEC7-R2-1-normcase` KILLED.
  - **SEC7-R2-2 (MAJOR) — fixed.** One `_EntryWalk` per `serialize_manifest` (`_reject_unsafe_entry(..., walk)` required), `_component_refusal` cached, the POSIX absolute test as `startswith("/")`, `_resolve_intended_entries` lexical. Arm: the 5 writers on the 31-folder manifest finish under 1 s (RED on the cp1 tree: the `save-project` case fails). Mutant `SEC7-R2-2-fresh-walk` KILLED.
  - **R2-2 (MINOR) — fixed; ceiling redesigned (orchestrator ruling).** `MANIFEST_FS_CALL_CAP` (2 000 calls of any kind) -> `MANIFEST_FOLDER_CHECK_CAP = 1000` distinct folder checks per read or serialize; the file an entry ends on is always checked. Set first at 2 000, lowered to 1 000 because the worst case's variant append measured 1.03 s once under the 19-minute module run. Arms: `test_q3_ceiling_inside_the_caps` (the entries inside the caps are all checked), the worst-case node, `…_entries_under_an_existing_folder_are_all_checked`. Mutants `R2-2-every-call-counts`, `R2-2-no-folder-ceiling` KILLED.
  - **R2-1 (MINOR, test gap) — fixed.** A TC-B100-07 node for the refusal branch (the code was right). Behavioural RED by the mutant `R2-1-refusal` (KILLED); `red-cp2-q1-vs-pre-cp1-tree.txt` is its run on the pre-cp1 tree.
  - **R2-4 / SEC7-R2-3 (LOW) — fixed.** The SEC7-2 detection message names where `project.json` landed and carries no exception class; the class goes to the finding's `details` and to the app's `Manifest write refused: <msg> (<class>: <text>)` log line (a first form, a logger in `manifest_writer.py`, was removed: LLR-004.3 keeps that module headless). Mutant `SEC7-R2-3-class` KILLED.
  - **SEC7-R2-4 (LOW) — fixed.** The kept `project.json.previous-<UTC>` copy is passed to the five rollbacks as `kept_copies`, not `placed_files`; `_abort_save` removes it only when `project.json` reads back as exactly those bytes, else the copy stays and a status line names it. Arm: `held`, `no-space`, `restored`. Mutants `SEC7-R2-4-placed`, `SEC7-R2-4-unconfirmed` KILLED.
  - **R2-3 (LOW) — deferred to the backlog (orchestrator ruling).** A `files` key that differs from the on-disk name only by case reports `not recorded`; probe Q2 stays failing (`review-probes-cp2.txt`, 1 failed). `BACKLOG-CODE` item.
  - **SEC7-4 (b) (LOW) — deferred to the backlog (orchestrator ruling, from cp1).** `BACKLOG-CODE` item.
  - **Census findings from the earlier cp2 census (chain B), both fixed:** `test_manifest_writer_module_is_headless` — fixed in the code (no logger in `manifest_writer.py`); `test_tc_b100_57_…` byte-identity census — re-pinned: `("s19_app/tui/app.py", "_abort_save")` added to `declared_other_rules`, because `_abort_save`'s `read_bytes() ==` is a restore confirmation, not a reuse rule (LLR-164.4 / SEC7-R2-4).
- **Orchestrator rulings in force at the close (2026-10-30):**
  - **OQ-7a:** `not readable` only for no data or an unparseable image; record-level errors keep the image open. This narrows LLR-169.9's "load errors" to fatal load errors (LED .69).
  - **OQ-7b:** the TC-B100-22 fixture adds `checks/inner.s19`.
  - **SEC6-2:** an in-project rewrite is refused, never carried verbatim, for a damaged manifest, another `schema_version`, unknown top-level keys or skipped entries.
  - **SEC6-3:** discharged by Inc 7 (`_check_destination_contained` runs `_guarded_destination` on the unresolved folder; SEC7-2 re-checks after the replace); `BACKLOG-CODE` marked.
  - **SEC6-5:** the bound (≤ 100 skipped-entry findings + 1 fold row; composed ≤ 103 problem rows; time, §4 cp1 and cp2).
  - **`derived_from`:** field names `base`, `sha256`, `differ` (LED .48).
  - **qa F6 (Inc 3):** no real-worker arm in Inc 7; it goes to Inc 12b.
  - **CI-6-1:** an overlong entry is decided on the text (`MANIFEST_ENTRY_MAX_CHARS = 32 767`) (LED .71).
  - **Accepted cp1 behaviour changes:** the 32-component depth cap; a link or junction as the final file is refused; Save project refuses and rolls back when no `.previous` copy can be kept; the title uses the full problem count.
  - **SEC7-3:** Save project keeps `project.json.previous-<UTC>` when it replaces a manifest it cannot carry.
  - **cp2 ceiling:** `MANIFEST_FOLDER_CHECK_CAP = 1000` distinct-folder checks.
  - **OBS-7-1 (LOW, observation, routed to Inc 8a review).** `_relation_line` (`variant_execution_service.py`, about line 1900) decides "in this project" from the `files` records only. A hand-made manifest with `derived_from` and no `files` therefore says "patched from firmware.s19 (not in this project)" while `firmware.s19` is on disk (seen in the first `pe-patched` capture). The app always writes `files` with `derived_from`, so it is not reachable through the app. Not fixed here.
  - **Close:** the operator cut the cp2 verification chain to move to Inc 8a; the deferred runs are routed to Inc 8a's validation (LED .70).

## 7 · Suggested next task

**Inc 8a (`active_document`, which joins `KNOWN_MANIFEST_KEYS`, the `files` scope and the carry).** Its validation owes, for Inc 7's corrective pass 2 (deferred by the operator, LED .70):
1. the full reverse census on the final tree: `census-tree-cp2.txt` was stopped at about 29 % (31 modules, no failure so far) — re-run it complete and disposition every failure against base;
2. the guards (`tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py`) and the census sweep (`-k census`) on the final `app.py` bytes (`923de169c6c44bc8`; the cp2 runs are on `bd4dca9461d381c5`);
3. the security probes re-run on the final tree (`sec-probes-cp2.txt` is empty): `probe_a_dos.py`, `probe_e_load.py` and the round-2 `r2_probe_*` set;
4. round-3 code + security review of the cp2 diff (pre-cp2 sources: `scratchpad/cp7-2/pre/`; final hashes in §4).

Also: review OBS-7-1 (`_relation_line` and a manifest with `derived_from` but no `files`, §6), and the orchestrator confirms CI-6-1 on a Linux CI run. Backlog (not Inc 8a): SEC7-4 (b) and R2-3 (`BACKLOG-CODE`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4: the 3 planned + `screens.py` as the declared 4th (the Inc 6 `LoadAnnouncement` fields cannot carry the error colour or the relation line) — §2; `workspace.py` untouched |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_project_check.py` (35 functions) + 13 new functions in 4 modules — §4 ledger; cp1: 17 new functions + 4 builders (§4 cp1 ledger); cp2: 10 functions (17 cases) + re-pins + fixture helpers (`b100_manifests.py`, `b100_projects.py`, `b100_links.py`) — §2 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `merge_load_problems`, `choose_install_set`, `serialize_manifest`, the reader caps, the manifest-keys mode (TC-60) |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01`, `red-02`, `red-03` (all executed on base `80052cb`); cp1: `red-cp1-vs-pre-fix-tree.txt` (25 failed, every failure behavioural; 17 passes by design); cp2: `red-cp2-vs-cp1-tree.txt` (15 failed / 2 passed; the 2 are the Q1 test gap and a control) |
| 5 | Reverse census declared | `core` · `full` | ✗ | checkpoint and cp1 done (41 modules: 7 in `green-01` + 34 in `census-tree.txt`; cp1: 10 in `green-cp1-touched-modules.txt` (364 passed) + 31 in `census-tree-cp1.txt`, 2 known failures only). **cp2: the 31-module census on the final tree is not run — `census-tree-cp2.txt` stopped at about 29 % (no failure so far). Not run — deferred to Inc 8a by the operator (§7).** The 10 touched modules ran: `green-cp2-touched-modules.txt`, 379 passed |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b — PASS-WITH-NOTES r2 (r1 FAIL `BLOCK — BLOCK-UNTIL: F1, F2, F3`); the cp2 diff (R2-1–R2-4 fixes) has no round 3 — deferred to Inc 8a |
| 7 | No file from another lane touched | all | ✓ | the 4 named sources + tests / fixtures / config / HANDOFF; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I1, -I2, -I3, -I16, -I21 frozen here as specified; B100-I13 and the Inc 5 / Inc 6 seams consumed unchanged |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript in the evidence table; the cp2 chain's cut runs are named as not run, not counted |
| 10 | Load-bearing emptiness declared | all | ✓ | the OQ-7a checksum arm asserts `mem_map` AND `errors` non-empty (an empty map would make it vacuous); the SEC6-3 arm asserts the containment issue code as well as "Q holds no `project.json`" (an absent file alone could be vacuous); the junction comes from `b100_links.create_junction`, which raises when it cannot create one |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 23 mutants, 23 KILLED, each restored and hash-verified — §4; cp1: 19 new mutants KILLED + the 23 re-run on the cp1 tree KILLED; cp2: 8 new KILLED + the 19 cp1 and the 23 earlier re-run on the cp2 tree KILLED (50 of 50 restored, final `app.py` `923de169c6c44bc8`) |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of `project.json`: Save project, save-back, variant append, MAC / A2L sync (all through `_write_and_verify_manifest` → private staging, `files`, carry incl. `derived_from`, SEC6-2 refusal); readers: `read_project_manifest` (caps, manifest-keys mode); the flow callers of `_resolve_manifest_entry` stay on the default mode (P-41) |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence table (written by `devflow-evidence.py`) covers the checkpoint, cp1 and cp2 transcripts and the reviewers' files; the 21 E13 PNG rows (`evidence/inc-7/e13/`) are included |
