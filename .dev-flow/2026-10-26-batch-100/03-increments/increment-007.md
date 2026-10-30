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
| Import proof | `C:\Users\jjgh8\Github\s19_app-b100-inc7\s19_app\__init__.py` — printed in every transcript header (`# s19_app import:`) |

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
# from the worktree root; interpreter C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
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

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-7/`. **Final source hashes** (sha256[:16], printed in every transcript header from `green-01` on): `manifest_writer.py` `b3a8da7ae550bda5` · `variant_execution_service.py` `bd33c8be189d2c87` · `app.py` `0e29d80841fa3f38` · `screens.py` `e23ea8f72bc93153` (base `80052cb`: `c88152e6975e6c1b` · `76b276077ded9717` · `762d1a98c8a65903` · `ea549ab4bd9d3ef4`). No source byte changed after the final `green-01` (checkpoint 3 had `app.py` `c01797f665287871` and `variant_execution_service.py` `85fbde0ca2ae9d78`; the OQ-7a edit (`app.py`) and the CI-6-1 edit (`variant_execution_service.py`) came after it, and every transcript in the table below was produced after both, except `red-01` / `red-02` / `red-03` (base runs, base hashes in their headers)). Import proof in every header: `C:\Users\jjgh8\Github\s19_app-b100-inc7\s19_app\__init__.py`; `PYTHONPATH` = the tree; `NO_COLOR` unset.

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
| census-flake-tc035-4-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-flake-tc035-4-tree.txt | 81e19b65caf571ebb09eda52f2ac4c45eab2a2a05c2df3577333673c1833b24a |
| census-isolation-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-isolation-base.txt | e5ad754a9b27d03bcf435e9988750edb1f61838efc39d07a32c70f09a776356d |
| census-isolation-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-isolation-tree.txt | bda1fb96c0e0ec4ab0b4753eb8b974d2788f862ebcb591eac63fd0d0b5221c79 |
| census-known-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-known-vs-base.txt | 021fd97e5d8a55e439b3f8f39a0f25e67a629ba7842decdb691c0a5fbde4e46d |
| census-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree.txt | 167037d5518bee7a9186f66c2b19e75bffae28d2d0b1c0bc65d4a712d418467b |
| green-01-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-01-touched-modules.txt | aab30fa4ff33515a74d386bcef15952a284db77d27cb5a2ff41bd461a8c3f8f1 |
| green-02-repinned-census-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-02-repinned-census-modules.txt | 0c30b4bf25b0fcc50f74f7e6d4b1b9ee9e70c91e0741ca7a7e36f8dd4eecd557 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census.txt | 059d5c4dd8f6a2fdafd54f70e5fcc58523a6e5422e52d9e9af270abc3a6136a1 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards.txt | beeca97a8c8febab04e430f0a90f6aa03ea39c76c7df69e011c50f60b29b4b17 |
| mut-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-CI-6-1.txt | 4ac872dd171a3a38025f52bb8e8ef2b00185d4915cb6bb692f14dfb748fd8628 |
| mut-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-168.4.txt | 9adb3805f75b8dbc8c905655dd08cf5b886b0b619a59f3d51d31c4b5c9ff07cb |
| mut-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.1.txt | 70866faeddf0b5022d7d78942f3382f898044fc2252527c23f4f3ccfcc7b06f8 |
| mut-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.2-s19only.txt | fd0f56cd63e468b34a681bf38944be89026ce521a6ed073a3dbbc7b2318fcf3d |
| mut-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.2-walk.txt | 34a2c2d7150cd8ac625c8238bdd6595f357a6c9c56d602b2f1de507d8cf8a55e |
| mut-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.3.txt | 573a0beafc9e6ea5cad7c515d5d98790f51dec29e7aad00d5dbea0651faf8bb2 |
| mut-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.4-bool.txt | 6e9a5435633f4c4274d92523fcc69179552a99388aea170a826faee81907e636 |
| mut-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.4-cap.txt | a308de2be6525a7dc71bfc8b609aad887a87d145c91519fe0c075e121e63aed4 |
| mut-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.5.txt | aa0dc40cdd347cb2dc10a8b4553b98540c7d998d1a3c154be91396e1785845c3 |
| mut-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.6.txt | df978463b1feffd8d672b7de6d126942ec86e0c554e610b79db84a462f17ac0e |
| mut-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.7.txt | 4f5d0fbb9ba719932fca0d9bb13e850dcf92b1489d1d7ec91189c2f255f40f81 |
| mut-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.8-P41.txt | 39bd67883e0fbe06b9898467badc38e9600ba4bb6085c139bc3589de9f136ea2 |
| mut-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.8.txt | a90c48d4c170bd20926879013eee6035495f33cf3d6ae3b98740af7be95aa1e8 |
| mut-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-code.txt | 34c9fae868a45c2fe3b8dfd6ee93b5f0a96f69c1ea86c6ddf2c028a15352fffa |
| mut-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-keep-all.txt | 4930c3c854bf6af8c18641856d92154cfc36e4e1933f1f93f1f1b3f70814784b |
| mut-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-169.9-last-wins.txt | c35ad8e73961dbb3bae509958f9187296dfbfc8cfadb4296441cbf85e452a5b8 |
| mut-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-LLR-178.1-first-by-name.txt | 135f92e8b611d0a459a00eb49674be4e0f2fc8c60923b0308cf1cb352380268b |
| mut-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-OQ-7a-empty.txt | 4859aa6403c8818b65432f0cd4291b5b005f9a6e32cda81a21959f88bf7d6a1d |
| mut-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-OQ-7a-record-errors.txt | 01c436cdaed8976bbbf998b1174f1144e5f7dfb0df83e79f80d1c4efde5850b6 |
| mut-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC2-10.txt | 021bd2e3245de0892f0864629c0080e4b635ffdf5579af2e04277550ec91d81b |
| mut-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-2.txt | ab3838c030ae877dec8bfdd31fcd81609a0c3d7f6180c275d9f5ff4924db9e5e |
| mut-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-3.txt | a891589b327652efd546223e6788ee0fd459b5ebbb0d7fe638632b59b003234b |
| mut-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-SEC6-5.txt | c200a38e52b217da60c49e76ed2aad556572ad02ee99d7b856da20a3a1dd6b51 |
| red-01-project-check-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-01-project-check-vs-base.txt | 1e2161a65e70fb7352364716f57d2ed81db73da3eb3f03a8f84a259aeda15543 |
| red-02-other-modules-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-02-other-modules-vs-base.txt | 081ce056163a83713a375a5e559b00adf9b6faeed294c45cabbeebb2bca7a8a1 |
| red-03-at-extensions-and-oq7a-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-03-at-extensions-and-oq7a-vs-base.txt | d39e2011a303ed7fd0927786e5f2abc0dbcfa8ab04968b38df2c9dabe1b1202a |
| red-04-ci-6-1-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-04-ci-6-1-vs-base.txt | cc30cdbbc069407d4406a3396a40437034a8b7a82b3ba68d8f69ee7aef7faf0c |
| reverse-census-grep.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep.txt | 8c94de6871c92ac4e529556fc85c5197602e7ad08949ea92a5ae8f21b786641b |
| census-tree-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree-cp1.txt | 89257589eb0641b44213cb317d5d95541c7887e8e210b99fea44910ceb85608c |
| green-cp1-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp1-arms.txt | 8532cece696d5d22a115ec6522f30f6dd41be1dbc6728bdcf3c7a924ef8df643 |
| green-cp1-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp1-touched-modules.txt | def7c0d36fe6bbf869f95b0360f50bbf2397fe009dcd74fa9301886cf5eec83c |
| guards-census-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census-cp1.txt | bead0f04906109bbad29fb3f88b902ef64b52d35a0e231f52a8ec4b811e709a8 |
| guards-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-cp1.txt | eeba2f3e864e8229ed31a7291a5103f6b6a1bbe9922300451ee21f19417be43b |
| mut-cp1-F1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F1.txt | 609b42c1c6b5936d2094cd7bc78c7c71df8f4279cbab1f9772a7c01d7c59cb8c |
| mut-cp1-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F2.txt | c4ed742b7b7ccc27e80ada60ab645571c21fac45f837de9ff3055a80023c997c |
| mut-cp1-F3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F3.txt | 9e4d4806cd3f406c88cec9e160f6a9ad181367de468fe25177fdfa79aa8f90b6 |
| mut-cp1-F4-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F4-MR.txt | 731e7749426d7d43e43de73532a70bd265ae8b5b0619a5144c75241c716174a0 |
| mut-cp1-F5-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F5-MF.txt | bd8ca02eb90985d2f73f92b646de50f83a5472a8a216fe21a34860da9c699f03 |
| mut-cp1-F6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F6.txt | ee1846535d344df8c8000bb1da3c0d461479719bd9b3192c9a08cedd10faa0b9 |
| mut-cp1-F7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F7.txt | d59bc4a490e385cb588ef6ecaf9ea0c496c928ae3a4f0c9ac8ea39d2d70c7b7e |
| mut-cp1-F8-type.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F8-type.txt | cd85f33cc801374b0b02848828bdcdb658f091062c57c4018a63e08243664d75 |
| mut-cp1-F8-wording.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-F8-wording.txt | dd9f7aaa7badb04b0010a79911307922d9f72664a50d46ea2ff0b0565d52c8db |
| mut-cp1-SEC7-1-depth.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-depth.txt | 8bf79e8eba03d63d49350423f0f1ef94c24934e82e4f78c7eb9a872bcaebade1 |
| mut-cp1-SEC7-1-no-cache.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-no-cache.txt | 5f0092f347ee018f35749f79720687558a98e2bb8c9d95b064fae44b5a92810d |
| mut-cp1-SEC7-1-no-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-no-ceiling.txt | 95824070d115de483e61c9cffe09d738a24c88ea4debdd49b29ea9db478e1a60 |
| mut-cp1-SEC7-1-resolve.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-resolve.txt | aeeeca90f142ec4274c0d748b438c44ac3f7100d775b373575f9e6602716aac7 |
| mut-cp1-SEC7-1-scope-after-fs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-1-scope-after-fs.txt | a2133cbf113d6db511b0f0a7ab2da78eac8e51a95eda0faf81cb3fd6dcfa45ab |
| mut-cp1-SEC7-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-2.txt | 55efa17ccddc3b8ca6429c94292a5e1114e90889e9b0d48f2c053b0dd641c724 |
| mut-cp1-SEC7-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-3.txt | e4ccf34006ed6ab389d4707256c6446ec4d7803a71f6b95aaf5f37d765b89f49 |
| mut-cp1-SEC7-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-5.txt | 09cf4af0cf18672025e9dc3396359ed9e2c3f17678b8492a2dac6c553d530e38 |
| mut-cp1-SEC7-6-guard.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-6-guard.txt | 9dd6dafa362ce0145655e48092925208aff15a733aab3ef06128f1bd7038ef58 |
| mut-cp1-SEC7-6-taken.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-SEC7-6-taken.txt | 8efddd987d29994035d55b83de63399978db160d8136d7525364db41dc70c688 |
| mut-cp1-prior-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-CI-6-1.txt | bb2edb1c2e6360a3925bd2ac86448f457978cea1e88de0c1bba0ca3b2f9b2cb0 |
| mut-cp1-prior-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-168.4.txt | 77dd854bfebd1e68981817847fffd5fbf62d58a7d4cfe2f79195fd00a2d115b0 |
| mut-cp1-prior-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.1.txt | 6a70c7161dba2bfc12f1369d7bc85d2f49c282c4ab8edba74f2d4a0e15596a67 |
| mut-cp1-prior-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.2-s19only.txt | abb51e8733a37e6aef8b7d86ca8896beef4540123e72acd3008122a191e33abd |
| mut-cp1-prior-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.2-walk.txt | 02c99b1ed81ab0e67e5bf070e62ab8dd678eda3c4228235544a5d542ce2597a0 |
| mut-cp1-prior-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.3.txt | 636fd6276eb1c2cf8ca7e707a963631da330237f51148e229e0b126c7020f7b1 |
| mut-cp1-prior-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.4-bool.txt | e7e1e59bd5d87e12d85347854499f4db646337baf95b59981164f8d2d5c42a52 |
| mut-cp1-prior-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.4-cap.txt | 8792608e622bbd69c25562417bbb07e26f55a14d7c9962788d73674c3493827e |
| mut-cp1-prior-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.5.txt | 15df5f23a4a640d0dfb25bd14bd7b0b99ec8c469c16fa01c2857e24e4bd44cf0 |
| mut-cp1-prior-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.6.txt | 4817df2f60d8d2a2971c78a4fb40e310b2fa506dbc6acfbfa761ebb49b601e9c |
| mut-cp1-prior-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.7.txt | fb4b887296da2f68640dca17f9a7aa4e201aff5bc46764a2859c54fe7176c933 |
| mut-cp1-prior-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.8-P41.txt | 850229eb9102330ba04b99be33e9544a6a661c46e82e96514e9226ec2289c7b9 |
| mut-cp1-prior-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.8.txt | 05eff0fe7ed5fb5291853dcd972878996f98eb030942f6064ae56107666c378b |
| mut-cp1-prior-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-code.txt | 6a9b20cd43ec029da31d7e38c176e57d8302d89c4b101b43342c0049e9c27024 |
| mut-cp1-prior-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-keep-all.txt | e49c983e0d5587b26e3758f214aa2bfce012630da28717937c3a9a2295b7dfff |
| mut-cp1-prior-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-169.9-last-wins.txt | 67b10b41fba407e11fdfd4bf4025b0b1ce81721892eeeecf22222750ec2a7dd7 |
| mut-cp1-prior-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-LLR-178.1-first-by-name.txt | 151a2df2e7468fdfb5b28574443ebc1ab2ae54454ecdb6e994e88b09c8db0b33 |
| mut-cp1-prior-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-OQ-7a-empty.txt | ebe32e2b2325609baa32d036c42cd73777b66f111a351bf1470d9b85124fe789 |
| mut-cp1-prior-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-OQ-7a-record-errors.txt | fd0117cccb57c0c5633c0de4440d2837e1d68b5489163aa5c87383fbd2273fd9 |
| mut-cp1-prior-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC2-10.txt | 423848cecf14bfeb6c23739f858671940b713c408c8f09f9f57a9e757f6fe6cc |
| mut-cp1-prior-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-2.txt | 61eed544ffca918769f32a09e6f853496802e7b08283e90e6cb615f4fef58734 |
| mut-cp1-prior-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-3.txt | b448fe032e831500c3851ad147f942bb01688b7aa9b360f7cd6a20d735bed08b |
| mut-cp1-prior-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp1-prior-SEC6-5.txt | 93e706f35ea90afed001068e884e3c33b3d574e699eff49329837063dc8b430c |
| red-cp1-vs-pre-fix-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp1-vs-pre-fix-tree.txt | 3ffbe82c7d570f0528b3521b7b3e87016d5c64d690b954853a7082d5bdcd7dab |
| reverse-census-grep-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep-cp1.txt | 90ca1571666b3148768ef647a7373fbcc3d715b423fe72a71ff07ec6aa2e6098 |
| review-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review-probes-cp1.txt | 75127ac530296aacc382c6f7f4b12f34f2495e9b2f0874d96bfb288299ab1536 |
| sec-probes-A-E-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/sec-probes-A-E-cp1.txt | a75ef7497da5631c2a5bdce91e3a48e269f4985ab581ca96522448002eb93472 |
| census-tree-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/census-tree-cp2.txt | 569512f486b8ac26cad931e9e5f795fd035c1beedfc447f3f1b0da88c1b457ed |
| green-cp2-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp2-arms.txt | 19b0c73ea9dde1eb62c0d37c07a971f3c05aa8da060f9afe965d20e513696555 |
| green-cp2-touched-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/green-cp2-touched-modules.txt | 1761db0905aeee005b9a8cb41721dbbb6bbd058f363b2973c0f5040ac8d44669 |
| guards-census-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-census-cp2.txt | 8b33c0eb5a93c6a7d1b1d2c70d538236cea6b89bac2b61cb156c4f8b2f364203 |
| guards-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/guards-cp2.txt | a601dfa8e6df64c1e75d5c7beff9a9fc673392c4eea62f749bf1f3559ff3413f |
| mut-cp2-R2-1-refusal.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-1-refusal.txt | 04d718cb146da18c5929887c1ff6b5197f9146b582145a20e24da92214605606 |
| mut-cp2-R2-2-every-call-counts.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-2-every-call-counts.txt | 41335708623ca6353839e4978b03877dbde3d51a42e051e814d956ef4ef1f636 |
| mut-cp2-R2-2-no-folder-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-R2-2-no-folder-ceiling.txt | 6c207f7b7abf845bbb885ba7f01434465d8ca0b1b8a42aa0b077fe9d954a2491 |
| mut-cp2-SEC7-R2-1-normcase.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-1-normcase.txt | befc84b1face24938150be3e35dfb10e8d619d300ebb4c47f5772c7bccfd7494 |
| mut-cp2-SEC7-R2-2-fresh-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-2-fresh-walk.txt | 28cfcfd6751447f18580fc7d872a259d24eec45b0511f16adbc8d526771c7caa |
| mut-cp2-SEC7-R2-3-class.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-3-class.txt | dd52e9d2309d866b7d5d39aaf03a1f942018a2eabe7d05a2e77aec2c5937bd1b |
| mut-cp2-SEC7-R2-4-placed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-4-placed.txt | 89b76e9007d8b54d1ae32577c75c434bab07fefceaae920d5768670a8693d7c5 |
| mut-cp2-SEC7-R2-4-unconfirmed.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-SEC7-R2-4-unconfirmed.txt | 97bd9d09194aaf18f051c6f4e2be0da57795514b15ad7c2dbdc8bbb487147e45 |
| mut-cp2-cp1-F1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F1.txt | fe6e649b329462fef1c23c50c3c1091f69074d1606db1d208db5cd5f992c7066 |
| mut-cp2-cp1-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F2.txt | 3f3a63babd940df70977bb2cea7369120a451f39f5f311e15b94e169a6cb2e2d |
| mut-cp2-cp1-F3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F3.txt | 19d211d859ac217acfd2c3a5e567e3d82335103f3b51ec2e716df85cfff371a9 |
| mut-cp2-cp1-F4-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F4-MR.txt | 7866c686b4b34a7db2d30ef55caa34042812d59b5d1943831df1bb693560a103 |
| mut-cp2-cp1-F5-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F5-MF.txt | ce17ff0c675029b8b0ec1cd10020dfcb2b35486c459c65e2172eccfc3291ce11 |
| mut-cp2-cp1-F6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F6.txt | afb6dc145be170d298dbe1d22ec8cda654f88985d29fd24fede660097e167e1e |
| mut-cp2-cp1-F7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F7.txt | 68241b6eaa6bb8d4650a1970c6ae345a7ef9f3589177de321a326efbd7f6ca62 |
| mut-cp2-cp1-F8-type.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F8-type.txt | 49695a0f04a91a2992c0b799f6e48c542f1ce30bdfd6c2b23f7510026d47875b |
| mut-cp2-cp1-F8-wording.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-F8-wording.txt | f6e9bdcace2a168e298df244bd23cfe236e69379d8ee580a615a1d454973b0bf |
| mut-cp2-cp1-SEC7-1-depth.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-depth.txt | 22d3b26d326fb37fb0c597ad764ef329142630b1a9d04716c6318ebb20aa771f |
| mut-cp2-cp1-SEC7-1-no-cache.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-no-cache.txt | 6e01a77c53d281af24af6efe7b933648b951e3e9205bc6fd8e27c2a85396c7bd |
| mut-cp2-cp1-SEC7-1-no-ceiling.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-no-ceiling.txt | f2bb0b178abaceabc95866b55efa8877f6ba47d704f42d4ff59fed842a8dcc8e |
| mut-cp2-cp1-SEC7-1-resolve.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-resolve.txt | 119981e6ae9d699b5e660232949c4d4a62e5e4e841bc4da4ef826c868a72e5a6 |
| mut-cp2-cp1-SEC7-1-scope-after-fs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-1-scope-after-fs.txt | 8f80a34fc370cedabee928f408d26aa392e43d8f6a53935121fa3f5ec14d3649 |
| mut-cp2-cp1-SEC7-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-2.txt | b7fb043501f484f32a72194dbe98ea846ed8f95b5be9728a7a679075e713a69c |
| mut-cp2-cp1-SEC7-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-3.txt | 10eea5455ed6f720fc759e8ce567ed811ac0e9bb3c59e9b23fcb336868b012df |
| mut-cp2-cp1-SEC7-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-5.txt | fdf457a3501c7891e897b57da2fe8869f31b89c3af5daa7f22d7446b54199a04 |
| mut-cp2-cp1-SEC7-6-guard.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-6-guard.txt | 1fb75f86712fb3cf54d1df9547b6e5ba4648c65dc69251fb000b47f31c75209a |
| mut-cp2-cp1-SEC7-6-taken.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-cp1-SEC7-6-taken.txt | 3734c3ad0afd8d6cb32cb33fb03d85edd179eb053d4f5facf1446974469f398d |
| mut-cp2-prior-CI-6-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-CI-6-1.txt | 8915971964ebc07731e0b8a8f0fc68d6a39cbea066affa7baff36f3287ad6abf |
| mut-cp2-prior-LLR-168.4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-168.4.txt | f01b510bd2f18bcf973841f163da988df5552526ea77e6784a609a3bfbca9b88 |
| mut-cp2-prior-LLR-169.1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.1.txt | c201dcb00a762ffc6717d37aec8366068a622cc83e96b1183881fecdd68f680e |
| mut-cp2-prior-LLR-169.2-s19only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.2-s19only.txt | 1fc38321816fc25effdae7b905f34f07777b7027b319656146b027388177e2b7 |
| mut-cp2-prior-LLR-169.2-walk.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.2-walk.txt | 5d32fe023095e83937ba9157b24dbebee560b181133b09d628306778d48648b1 |
| mut-cp2-prior-LLR-169.3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.3.txt | 0e8f3f888754f1f369c50d64f4e147a93433fdb06a6d7ce8341a2b24dbfedbd0 |
| mut-cp2-prior-LLR-169.4-bool.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.4-bool.txt | 61ae95e1f85e33bdd4d012111364fcba3dfc23bcbe4d8690347ea207c48d52fe |
| mut-cp2-prior-LLR-169.4-cap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.4-cap.txt | 44bc41752c38ce7e195c04b1644321d88fb7e016db5d4fa3025fbb1c3bf5cbcf |
| mut-cp2-prior-LLR-169.5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.5.txt | b9f58a7c0cf5229b23320d11190f68bcfc7959a521142a3ce72e52630543f7c7 |
| mut-cp2-prior-LLR-169.6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.6.txt | bb454f55187f6a77ec00fd84d6e73fa53e9c2568355d4f833c85b0a46a51ce9a |
| mut-cp2-prior-LLR-169.7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.7.txt | 1793a67440387ecad7ca5de1b83d5e8b44cde35d5b6ef5583e15b7a5bd0ef1b4 |
| mut-cp2-prior-LLR-169.8-P41.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.8-P41.txt | b4971ec3c8785564075ebbc899b84bed7c63fc477fdf8d70612219ed5d820514 |
| mut-cp2-prior-LLR-169.8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.8.txt | 29ba6d3471c6e12b00bec1e9f75496d3616255017d4e6d16cb462a865c43bdf9 |
| mut-cp2-prior-LLR-169.9-code.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-code.txt | c66324d4af15c41b65ebce587ee6062ced3cfe62fbf20d9d3760fbcad3f428f1 |
| mut-cp2-prior-LLR-169.9-keep-all.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-keep-all.txt | 6380fa93311c4c31f64367be832edc46b8df48c2fa40c118758569af49b8d3dc |
| mut-cp2-prior-LLR-169.9-last-wins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-169.9-last-wins.txt | 01d9c02a037c2a4296d777e5b537b26b3d3cf3cbbe7b2e473eeff867ed66fced |
| mut-cp2-prior-LLR-178.1-first-by-name.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-LLR-178.1-first-by-name.txt | 8fa37d70e7b38ad66c3cdcb4158035611c6b71f12a65c150e769dc0017fa31e6 |
| mut-cp2-prior-OQ-7a-empty.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-OQ-7a-empty.txt | 63db48d5e5be2d30af7d68f98c015553d7b4b097a4bcc725c95fef1cd7299370 |
| mut-cp2-prior-OQ-7a-record-errors.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-OQ-7a-record-errors.txt | fee3300daa0a6db8ba0cf4068729ec78427f55481859b267be350fe93da3278e |
| mut-cp2-prior-SEC2-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC2-10.txt | 1f50e15b2a21ca2090f3c658b33f47de813a67e33ed0887fd1ac286f4090f564 |
| mut-cp2-prior-SEC6-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-2.txt | 34cda3f1c6a2a5a20e687dbb61d1fe9e6e5166995176670d1932cb35c450580b |
| mut-cp2-prior-SEC6-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-3.txt | 4cdd31aaaf333fc16240103d9b0373127dbc8143f5268da61aadc652bd3dc944 |
| mut-cp2-prior-SEC6-5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/mut-cp2-prior-SEC6-5.txt | 35109bf56dceeb2f03a08d719fd14fdde68b65b2e7d07fda8a2deb8a8573208e |
| red-cp2-q1-vs-pre-cp1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp2-q1-vs-pre-cp1-tree.txt | 718eea800515919ffda364c5896a2082587db0389410a1f8a9c0675aa6a56c50 |
| red-cp2-vs-cp1-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/red-cp2-vs-cp1-tree.txt | 0a25a0fb290f9ae4a5e532095397b1aa2408d688c46c11d1921d67c48743fbd0 |
| reverse-census-grep-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/reverse-census-grep-cp2.txt | 9c297261fa9e88c4696cb6778aba1fb12a3c2dea240d52f975732791a989a030 |
| review-probes-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review-probes-cp2.txt | 84777ff187a6494bbc442dc7ec390545879a67b67b3443d060f76211377a7293 |
| mut-MF.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mut-MF.txt | 37991a731dff3eb33c23e390880800c3aeda521341c13b7776e7780ca7372309 |
| mut-MR.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mut-MR.txt | e6eea75ca04c81d2d404b4418c73c9cf3e173264978a18ea61046ac0635e0df6 |
| mutate_r7.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/mutate_r7.py | a096396f27c268cafc242eb3ae84a892f3137ea29d2150880663113c0f7c31ea |
| probes-tree-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/probes-tree-2.txt | 0c72b8eecadd17457854577d0b781b1200085d53e797885326acd3482936094a |
| probes-tree.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/probes-tree.txt | 3e0ba66c05216f492a42f1ef487d54e943087da5dc6b01d34cbd3e95b73ff66d |
| r2-mut-SEC7-3-refusal.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-mut-SEC7-3-refusal.txt | deb42634f3a80fee50386ea8b3b7fd0ac0445951d780c4f11ba70bc857880699 |
| r2-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-probes-cp1.txt | 2403228f6769ea2cc0996de4202c5e07cfb88b1897dc80439cdbf1981b49b754 |
| r2-probes-pre.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-probes-pre.txt | 91f7e32891473c3ff6acc7bf04f989fdb48e34a5ab2a1922f55e0ac5cb3eb1d1 |
| r2-round1-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-round1-probes-cp1.txt | 61e0d7552056f3a9b1e3b2a92cebeb2d28f475f6baa0841a245d3c74de49b68a |
| r2-test_r2_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/r2-test_r2_probes.py | b5db902650c5971043c99f7ede8ae7d59d5a59934a8728ab94aac3de8a5a2ae2 |
| run_mut.sh | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/run_mut.sh | 8d3a6db6aca5fe6c2c69af8c25c80453b16dacfa9b2286d8d3da0665c45df92c |
| test_r7_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/review/test_r7_probes.py | 772d5b6270e0954520fe4894b6e765a641ccc8c2642ef6e46025653d3a6aeb95 |
| sec-probes-cp2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/sec-probes-cp2.txt | d4bda984637bfdd00111d0ed5e42bd427338c359c61f76cf6a2e96900b94e8e7 |
| common.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/common.py | 032082e43b0de5068fef70b87feae589ace70f29239b672fbcdff15154f3e5d5 |
| out_A.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A.txt | 0ff8ada5b727f9dc2564c767265bf5276c5ecb283c715aae8a89f45a28616865 |
| out_A2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A2.txt | e92459d53f0c52616d195fa72c1b7c1a230390800b87011bb8253afc2a056958 |
| out_A_base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_A_base.txt | 0d141d522c3d48feee5212c7c0a2162662fe178175ff95930c918d960324a486 |
| out_B.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_B.txt | de976ef6c24072b35eeff94653b54f2558d2b94a96c4557be33114bd3f8939c8 |
| out_B_base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_B_base.txt | 2411350eee6f3d42c2cd8d5909a7eb9fe1344331981bba15b4bcff62bfd2e595 |
| out_C.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_C.txt | fe88c95368ec95f5535803de2fd5c01cb3c0daa623b81384b873bb3946aa5515 |
| out_D1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_D1.txt | 30cc1f41d1d68029022616e81f41b0c4043481d3f2d6053570bf35315e06b06e |
| out_D23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_D23.txt | 1e8e1eec53913ec80f0a2768eb210acd5c49f92120d32008422554db717b49cc |
| out_E.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_E.txt | 1d2d18d38027af91bc4267b10f1d64d9ecc6cdae04c574b44a5e715dfdfc732a |
| out_F.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_F.txt | 7822019a34bbc57649e7a002068d3f30857f42d52da240c8864c8bfc1f1a0a3f |
| out_H.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/out_H.txt | 6fc8843cef3f64c1953b603b97ff0f057e27ef56fb3c752c778438513f9a76df |
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
| r2_out_A.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_A.txt | 6a2523481e816d5cbc32c3c4927965586ce0d881358659199e87f79bf94f77be |
| r2_out_B.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_B.txt | 3b6efe2bfa35a1a1c7ed397e8f76d2cbd761398d6559e436bde37143ad49c2cd |
| r2_out_C.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_C.txt | a133cbd8bc838a3241d44eb51d6acc7d3f5c4dd294f92167fc44c5eab3fee532 |
| r2_out_D.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_D.txt | 1d69341063c7dd1f10c7505bb69f195fba83d8c7ee83b4a8247e81b0545e6e5c |
| r2_out_E.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_E.txt | a9ef1bb7dcd3d923adc71f2b6ff5da80aa4ccf839eaff4403f06de5c4a8c4f47 |
| r2_out_F.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_F.txt | 911ec4dffa95349d1e92d9458d6fe60273389faa42817d8807fdb7bc66105a0c |
| r2_out_H.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_H.txt | 2357d39003b6cd301601c623cfbae867f1fafd25d57a9fc0c55e44b0daa706df |
| r2_out_S.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_S.txt | 6955176b22a5dd70783fbfc089912968392dbd4cda49b9f0012024b585a602e6 |
| r2_out_S4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_S4.txt | 198ca876327f0765e615c381b1034f2e77608d8dfa4925202c031044958ee483 |
| r2_out_T.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T.txt | f1c3cd68c9b16e6315335e2d0fb590f5b22c5971463e34b2dc6e0f8e04ee8787 |
| r2_out_T3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T3.txt | 5c466871881ae3dbdd7e2ddc95602d2dc9410f90eda455a9554c11ca102569a8 |
| r2_out_T_prefix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T_prefix.txt | 840fca7470a873cb5bd90c0d26df45640e25627a678c3900b348229f8f36a02d |
| r2_out_T_prof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_T_prof.txt | fe67d3346d174220fc83fadbc91f580882ab17dac3e2b4ff36a673426098f462 |
| r2_out_W.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W.txt | 2c3993b28762d51a5a28921648f8cd6ee20f4af8f4c5fffc4be08075bca9ddd2 |
| r2_out_W2x.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W2x.txt | cfe5808afb3e1d49e552955bcaed2bf110f957298716c03f8c2978d0e925c117 |
| r2_out_W2x_prefix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_W2x_prefix.txt | 62310491537f9ac348f796e09ba301b6352313d5ec6ef011a183bfa804ba1bbb |
| r2_out_normcase.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_normcase.txt | a0b7f2aede328378fd79397ff1108821881762cd1a1283507b8891a35376146d |
| r2_out_pytest.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_out_pytest.txt | d13340923155b34ac5709c2843c1bff6238bb8af4c424891886cff65fcde534a |
| r2_probe_s.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_s.py | de84de6ea71d4d8107a2e7766ba26dde90d346763c6a0221217d682777477946 |
| r2_probe_t.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t.py | 53681360e016df8028e23773ddc139e2fe6e053774f3ff859535ac3f0b2d387d |
| r2_probe_t3.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t3.py | 2099f8a4686747327e95b096594500289cf0a74a4e126e0b3597ba8d94f2ca92 |
| r2_probe_t_prof.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_t_prof.py | e5a3c27b67601c2ad79f57cafc9e0080421fe17127ea42e516e2e4654655969c |
| r2_probe_w.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_w.py | da8b60616991ae2b320558219627bfc6644611c2ae9d5d576100346067972214 |
| r2_probe_w2x.py | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_probe_w2x.py | 20b18297580474d267009f6e31eb6354915441d74ec92cbdd92c8c69d88a186d |
| r2_run.sh | .dev-flow/2026-10-26-batch-100/evidence/inc-7/security/r2_run.sh | 4a709da4eff457db5ff748eb2a96d8325a35f34b938a4cf61973d9484e2b5c6e |
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
