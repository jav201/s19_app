# ARQ — batch 2026-10-26-batch-100 — Load + projects

Author role: `architect`. Station: ARQ (`p1-arq.md`). Base `1d677ba` (`git diff --stat 1d677ba HEAD -- s19_app tests docs` is empty and `git status --short s19_app tests docs` is clean, so every `file:line` below holds at `1d677ba`). Status: **for operator approval**; nothing landed.
The standing-map residue is in `docs/ARCHITECTURE.md` §10 *Batch-100 declarations* and §11 *Batch-100 interface amendments* (B100-I1..I12). This file holds what the map does not: the session-state inventory (§2), the `project.json` reader census (§3), the reuse rule (§5), the per-increment file sets and re-cuts (§8), the parallelisation matrix (§9) and the open decisions (§10).

> **P2 round 2 (2026-10-26).** This record has been amended for the P2 round-2 dispositions (`P2-dispositions-r2.md`, B-07):
> - §8 holds the re-derived per-increment file table, and §8.1 the test-arm moves.
> - The interface changes live in `docs/ARCHITECTURE.md` §11: B100-I2..I9, I11 and I12 are amended, and B100-I13..I22 are new (placement, containment, the `save_patched` split, `derived_from`, the save plan, the unsaved predicate, the session snapshot, the one load seam, the manifest-keys mode, `predict_placement`).
> - Rationale R25a, R26a, R31a and R34–R37 are added there. **PDR (`a1cad7e`):** ARCH C-1..C-3 are applied to B100-I15 / I16 / I22 in the contract's API form. `derived_from` is added to B100-I1, and `choose_install_set` (`app.py`) to B100-I8. The recent store's location is `%LOCALAPPDATA%` (B100-I9). The `assignments` total cap is in B100-I2, the seam's containment in B100-I14, and the plan's key-list input in B100-I17. §8 holds the decided file counts.
> - Sections §2–§7 and §10 keep their ARQ-gate text, and §11 of the map supersedes them where the two differ: R25 → B100-I19; R26 → B100-I15; R31 → `%APPDATA%`; the §3.3 problem kinds → B100-I3.

## 1. BLUF

- **Boundary:** no module created, no boundary moved. Every path is under `s19_app/**` (product) or `tests/**`. **A1 stays not fired:** the recent-sources store is two functions in `tui/workspace.py`, which already owns the `.s19tool/` layout (§6). No frozen-engine file (§7: `core.py`, `hexfile.py`, `tui/a2l.py`) is touched.
- **PH-2 seam:** one method, `S19TuiApp._reset_project_session()`, called by `_handle_load_project` after the project validates and before the first install. It **rebinds** `self._change_service = ChangeService()` instead of adding a `reset()` to the service, so the service's reset is complete by construction. Inc 3 therefore needs `app.py` only (§2).
- **`project.json`:** two additive keys, `files` (size + SHA-256 per file) and `active_document`. **No `schema_version` bump** (the `declared_regions` / `gathered` precedent, `manifest_writer.py:345-362`). The reader also starts to parse `gathered`. Of the seven modules the A3 probe named, **only three read the manifest's content** (§3).
- **Save project (D1):** the image comes from `current_file.mem_map` and goes through `ChangeService.save_patched` (`change_service.py:2009`). That reuses the emitter `save_patched_image` (`changes/apply.py:626`), the verify `verify_written_image` (`changes/verify.py:119`) and the frozen B99-I7 rule. The trigger is a new public predicate `ChangeService.image_differs_from_source(mem_map)`. A file whose image does not differ is still copied byte for byte (§4).
- **M-1:** `copy_into_workarea` reuses **any** existing `<name>` or `<stem>_<N><suffix>` with identical bytes, not only `<name>` (`workspace.py:560`). The return contract is unchanged (§5).
- **Re-cuts:** Inc 8 → 8a/8b (it reaches 5 files). Inc 9 → 9a/9b (keeps the dialog-free half outside the prototype gate). Inc 12 → 12a/12b, because project load, Save project and flow runs execute **on the main thread**, so no indicator can animate during them (§7). Inc 3 drops `change_service.py`. Inc 5 swaps `manifest_writer.py` for `change_service.py`.
- **Parallelisation:** sequential, one worktree per increment. `app.py` is in every increment except Inc 1 (§9).
- **Open:** 11 points that D1–D7 do not settle (§10). Three of them change scope: O-1 (other writers into an open project), O-7 (worker moves for Inc 12) and O-8 (two new visible surfaces outside P-A..P-D).

## 2. PH-2 — the session state a project load must reset, and the one seam

### 2.1 Method (executed)

```
grep -oE "self\.(_?[a-z][a-z_0-9]*)(: [^=]+)? = " s19_app/tui/app.py | sed … | sort | uniq -c
sed -n 1494,1500p s19_app/tui/app.py            # class-level reactive / plain attributes
grep -n "_change_service[,)]" s19_app/tui/app.py # is the service handed to any holder? -> 0 hits
grep -rn "_change_service" s19_app --include=*.py | grep -v tui/app.py   # -> 0 hits outside app.py
grep -n "else self.current_a2l_data" s19_app/tui/app.py
```

The census returns 67 distinct attribute names. `ChangeService()` is constructed once (`app.py:1600`). It has 33 uses, all through `self._change_service`, and it is never passed as an argument, so nothing else holds the object.

### 2.2 Inventory

| # | State | Where | Observed leak at `1d677ba` | Treatment in the seam |
|---|---|---|---|---|
| S1 | `current_file` (carries `mac_path` / `mac_records` / `a2l_*` / `mem_map`) | reactive `app.py:1496` | **yes:** `_merge_primary_with_existing_mac` copies the old MAC onto the new primary (`app.py:10067-10110`); `p03` `LEAK mac_records 0→2` | `None` before the first install, so the merge sees no existing file |
| S2 | `current_a2l_path` | `app.py:1498` | **yes:** the S19/HEX/MAC parses fall back to it when the project has no A2L (`app.py:10834`, `:10853`, `:9906`); `p03` `LEAK a2l_tags 0→3` | `None` |
| S3 | `current_a2l_data` | `app.py:1499` | **yes:** the second fallback, `… else self.current_a2l_data` (`app.py:9913`, `:10835`, `:10854`). Code-read: it is written at `:8844` and `:11112` and **cleared nowhere**, not even by `_apply_unload("all")` (`:10250-10251` clears only the path) | `None`. Recommend Inc 3 also clear it in `_apply_unload` for `"all"` / `"a2l"`: same root, same file. Repro `planned` at P1 |
| S4 | the change service (document, undo/redo, `last_summary`, journal, `_image_map`, `_applied_addresses`, `last_save_*`, check stamp) | `app.py:1600`; fields `change_service.py:867-913` | **yes:** `p03` `LEAK change_entries 0→1` | **rebind** `ChangeService()`, then re-push `set_image_generation(self._image_generation)` (`change_service.py:2494`) |
| S5 | `_variant_set`, `_pending_variant_id` | `app.py:1621` (property `:7209-7217`), `:1652` | no (the caller overwrites them, `:8506-8509`) | set by the caller after the reset; the reset sets `None` first |
| S6 | `_declared_regions` | `app.py:1672` | no (adopted at `:8472-8474`) | `()`; the caller adopts the manifest's value |
| S7 | `_last_template_path` | `app.py:1608`, written `:1958` | **latent:** the next Save project gathers project A's CRC template into project B's `templates/` (`app.py:8256`) | `None` |
| S8 | `_diff_last_result`, `_diff_check_spec`, `_diff_check_spec_name` | `app.py:1624`, `:1630-1631` | latent: the A2B report would cite project A's comparison and check spec | `None` / `""` |
| S9 | `_last_flow_run` | set `app.py:2625`, read `getattr` `:6132` | latent | `None` |
| S10 | `_last_execution` | `app.py:1663` | guarded: ignored when the project dir differs (`:4783-4790`) | `None` (cheap; removes the guard's burden) |
| S11 | `_report_filter_path` | `app.py:1682` | no (reset at every install, `:11097`) | `None` (harmless repeat) |
| S12 | A2L derived views: `_a2l_enriched_tags/_key`, `_a2l_filtered_tags`, `_a2l_summary_lines/_start`, find state | `app.py:1557-1566` | rebuilt at install when precomputed (`:11134-11138`) | cleared |
| S13 | MAC view caches, validation report and issues, window starts, goto addresses | `app.py:1567-1597` | no (reset at install, `:11102-11109`, `:11121-11133`) | not repeated; the install owns them |
| K1 | **kept on purpose:** `_image_generation`, `_diff_compare_generation` | `app.py:1616`, `:1646` | — | **must not reset:** they are monotonic counters that other code compares for equality (LLR-077.2) |
| K2 | kept: view preferences (filters, page sizes), `_active_screen_key`, `log_lines`, `_a2l_cache_key/_data` (a path-keyed parse cache, `:1555-1556`) | — | — | kept |
| U1 | **UI-held, not app state:** Flow Builder blocks and `_dirty` (`flow_screens.py:1175`, `is_dirty` `:1354`); Patch panel before/after prompt (`screens_directionb.py:6198`, `:6215`) and paste buffer (`#patch_paste_text`, `screens_directionb.py:5008`) | — | latent: unsaved flow edits from project A would be saved into B's `flows/` | open as **O-3**. Recommend: the before/after prompt is hidden by the seam's panel refresh; the Flow Builder is guarded by the P-B confirm when dirty, not cleared silently |

**Inc 3 as-built note (code-reviewer F10, 2026-10-27):** the reset clears **eight** `_mac_view_cache_*` names. The A-07 probe listed seven, so eight is a correct superset. The census also classifies two attributes introduced earlier in this batch: Inc 1's `_variant_set` path handling and Inc 2's `_last_manifest_verify_result`. `_last_manifest_verify_result` is rewritten before its only reader, so it is left as is. The seam also clears the Patch Editor paste buffer and calls `mark_loaded()` after the buffer's change message has been handled (LED .55, R2-1).

### 2.3 The seam

`S19TuiApp._reset_project_session()` (NEW, `app.py`). It is called from `_handle_load_project` (`app.py:8444`) after `validate_project_files` succeeds (`:8453-8461`) and before `load_selected_file` (`:8510`). It is also the place where the P-B confirm (Inc 10) has already been answered. It resets S1–S12 in one place, then repaints the Patch panel through the existing site (`refresh_entries`, as `_apply_prepared_load` does at `:11081-11087`). **One caller.** A loose Load file keeps composing with the session, which is intended (MAC + S19 + A2L).

**Why a rebind and not `ChangeService.reset()`:** a hand-written reset of ~14 fields is complete only until the next field is added. A new object is complete by construction, and nothing else holds the old one (§2.1). Cost: in-flight workers that captured `self._change_service` before the load (before/after report `:4123`, execute scope `:4334`) finish against the old object. That is the honest outcome for a run started on the previous project. **Rejected alternative:** a `reset()` method, which would also add `change_service.py` to Inc 3.

**AT discipline (C-31):** the leak AT's input set must be **derived**, not hand-listed. Compare `vars(app)` (plus `current_*` and the service's public state) between a cold load of P2 and a load of P2 over P1, with an explicit allow-list of the K1/K2 rows. A hand-listed set would miss the next S7.

## 3. `project.json` — schema change and backward compatibility

### 3.1 New keys (all additive, emitted only when non-empty)

```json
{
  "schema_version": 1,
  "active_variant": "firmware_1",
  "batch": [], "assignments": {},
  "declared_regions": [ … ],            // existing, optional
  "gathered": { "patches": [ … ] },      // existing, optional — now also PARSED by the reader
  "files": {                             // NEW (Inc 7, D3)
    "firmware.s19":       { "size": 358,   "sha256": "<64 lowercase hex>" },
    "firmware_1.s19":     { "size": 358,   "sha256": "…" },
    "firmware.mac":       { "size": 1210,  "sha256": "…" },
    "firmware.a2l":       { "size": 88213, "sha256": "…" },
    "patches/boost.json": { "size": 412,   "sha256": "…" }
  },
  "active_document": "patches/boost.json" // NEW (Inc 8a, D4)
}
```

- **`files` scope (recommended, O-2):** what Load opens, i.e. every top-level S19/HEX/MAC/A2L file plus the active document. **Not** `flows/`, `flowsets/`, `reports/`, `splits/`: other features write those after the save, so a digest would report drift by design.
- **Keys** are project-relative POSIX paths. Each key goes through the writer's `_reject_unsafe_entry` (`manifest_writer.py:179`) and the reader's `_resolve_manifest_entry` (`variant_execution_service.py:205`), the same single predicate, with no second path check. A malformed record (`size` not an int ≥ 0 or a bool; `sha256` not 64 hex) gives one `MANIFEST-BAD-STRUCTURE` and the file counts as "not checked".
- **Versioning:** `schema_version` stays `1`. Rationale: both previous extensions were additive with no bump, and a test pins that idiom (`tests/test_manifest_writer.py:481`). The reader accepts any `int | str` (`variant_execution_service.py:478-486`) and reads named keys only, so an older build opens a new project unchanged. The cost of no bump: a `files` key deleted by hand reads as a legacy project (the "no digests saved" notice) rather than as damage. **What would re-open it:** a change to the meaning of an existing key, or a requirement to tell a removed `files` key from a legacy project.
- **Write path:** `_write_and_verify_manifest` (`app.py:8272`) becomes the **one** manifest-writing seam. It computes `files` itself, from disk, after every copy has landed, so no caller can pass stale digests. `verify_written_manifest` (`manifest_writer.py:632`) adds `files` and `active_document` to its drift domain (today `active_variant` / `batch` / `assignments`, `:717-723`). Otherwise a writer bug on the new keys would still "verify".
- **Hashing:** stdlib `hashlib.sha256`, streamed. Cost estimate (**not measured**): a few hundred MB/s single-threaded, so a 10 MB S19 + 50 MB A2L project adds about 0.1–0.2 s to each Save and each Load, on the main thread. The 256 MB per-file copy cap (`workspace.py:55`) bounds the worst case at roughly 0.5–1 s per file.

### 3.2 Reader census (A3 probe re-run, every hit classified by reading it)

| Module named by the A3 probe | Site | Reads `project.json` content? | Effect of the new keys | Old project (no new keys) |
|---|---|---|---|---|
| `services/variant_execution_service.py` | `read_project_manifest` `:376-555`; `ProjectManifest` `:160-202` | **yes — the parser** | gains `gathered` (Inc 6), `files` (Inc 7), `active_document` (Inc 8a) | absent → empty, no issue |
| same | `plan_variant_executions` `:672-688`; `execute_project_variants` `:957` | `batch` / `assignments` | none | none |
| `services/manifest_writer.py` | `serialize_manifest` `:225-363`; `write_project_manifest` `:414`; `verify_written_manifest` `:632-735` | writer + verify re-read | + keys and + drift fields | output byte-identical when no new key is passed (the `:481` pin holds) |
| `tui/app.py` | `_handle_load_project` `:8468-8488` | `declared_regions`, `active_variant`; **ignores `issues`** (PH-5) | + issues, + file check, + document reopen, + variant announcement | legacy notice |
| same | `:4319`, `:4793`, `:4901` | **presence only** (`is not None`) | none | none |
| same | `_write_and_verify_manifest` `:8272-8372` | writer seam | computes `files`; carries composition for non-Save callers | — |
| `services/flow_persistence_service.py` | `:82-85` imports `_resolve_manifest_entry`, `MANIFEST_PATH_ESCAPE`; `:926` docstring | **no:** it reuses the path predicate for flow refs | none (the predicate is unchanged) | none |
| `services/report_service.py` | `:480-483` `REPORT_SOURCE_MANIFEST` label; `:639`, `:3194` declared regions from `ReportOptions` | **no** | none | none |
| `services/report_addendum.py` | `DeclaredRegion` type, docstring `:9` | **no:** a type provider | none | none |
| `tui/screens.py` | `SaveProjectPayload` `:144-176`; docstrings `:150`, `:507` | **no:** it feeds `batch` / `assignments` | D7 changes the parent rule (B100-I10) | none |
| (not in the probe) `services/flow_execution_service.py` | `:1419` → `plan_variant_executions` | indirect | none | none |
| older app builds | — | named keys only | a re-save **drops** `files` / `active_document`; the next Load shows the legacy notice | — |

Tests that touch the manifest API: 10 files (`grep -rlF --include=*.py` over `read_project_manifest|PROJECT_MANIFEST_NAME|write_project_manifest|verify_written_manifest|ProjectManifest|serialize_manifest`): `test_manifest_writer.py`, `test_manifest_verify.py`, `test_tui_manifest_save.py`, `test_variant_execution.py`, `test_project_gather.py`, `test_tui_report_seam.py`, `test_tui_evidence_packs.py`, `test_flow_multi_image_ui.py`, `test_b97_flow_builder.py`, `test_b99_staging.py`. The schema pins (`test_manifest_writer.py:99`, `:216`; `test_variant_execution.py:161`) stay valid because there is no bump.

### 3.3 Load-side check (D3) — B100-I3

`check_project_files(project_dir, manifest) -> list[ProjectFileProblem]` (NEW, `manifest_writer.py`, next to the verify that already re-reads the manifest). Problem kinds:

| Kind | Example text (P-E owns the final wording) |
|---|---|
| manifest unreadable (`MANIFEST-JSON-PARSE` / `-SIZE-CAP` / top-level `-BAD-STRUCTURE`) | `project.json is damaged — opened with defaults` |
| no `files` key | `No file digests saved (older project) — files not checked` |
| recorded file missing (L-4) | `firmware.s19 recorded in project.json is missing` |
| size or digest differs | `firmware.s19 changed on disk since the save` |
| image unreadable / 0 data bytes (`loaded.errors`, `mem_map` empty) | `firmware.s19 could not be read — 0 data records` |
| file present, not recorded (only if O-1 = no) | `firmware_2.s19 added after the last save — not checked` |

Load opens every valid file, falls back to the next valid variant when the active one is invalid, and lists every problem. The surface is a status line that leads with the count, plus one `notify(…, markup=False)` (C8).

### 3.4 The Load-project sequence after the batch

```mermaid
sequenceDiagram
    participant U as Load dialog (9b)
    participant A as _handle_load_project
    participant R as read_project_manifest
    participant C as check_project_files
    participant I as _apply_prepared_load
    participant S as ChangeService (new object)
    U->>A: LoadChoice(project, "P")
    A->>A: P-B confirm already answered (Inc 10)
    A->>A: _reset_project_session()  (S1–S12, rebind S4)
    A->>R: manifest (+issues, files, active_document, gathered)
    A->>C: problems = check(project_dir, manifest)
    A->>I: install active variant (or next valid), then MAC; A2L from the project only
    A->>S: load(active_document) after the A2L is attached (symbol context)
    A->>U: status + notify: variant opened (k of n), problems (P-E)
```

## 4. Save project (D1) — where the image comes from

- **Source of the image:** `current_file.mem_map`, the dict the Patch Editor's apply mutates in place (`app.py:3428-3442` passes it the same way for the save-back).
- **When to emit instead of copy:** `ChangeService.image_differs_from_source(mem_map) -> bool` (NEW, B100-I5). It is true iff the journal is bound to this dict (`_image_map is mem_map`, `change_service.py:895`) and some journaled address holds a byte different from its source byte (`_journal`, `:887`). Cost: O(patched addresses). Inc 10 (confirm) and Inc 11 (dialog preview) call it again on every dialog open, so it must be cheap. **Rejected:** `verify_written_image(current_file.path, mem_map, …)` as the predicate. It is exact and touches no service, but it re-parses the file on every call.
- **Emitter and verify reused:** `ChangeService.save_patched(mem_map, ranges, project_dir, current_file.path.name, source_kind=…, bytes_per_line=…, s0_header=…, source_image_path=current_file.path, mac_records=…, a2l_tags=…)` (`change_service.py:2009`). It reaches `save_patched_image` (`apply.py:626`, placement through B99-I2) and `verify_written_image` (`verify.py:119`). Its status suffix `save_back_status_suffix` names the entries the save applied that were not applied before. That suffix is the D1 status "how many entries it carries".
- **Why `save_patched` and not `save_patched_image` + verify called directly from the app:** B99-I7 is frozen as "the image saved equals the source plus the document's current entries". A direct emitter call saves the last-applied state, so the app would have two rules for one fact (the global rule 7 conflict). The cost is a side effect, decided in batch-99 and announced by the suffix: an entry added after the last apply is applied by the save.
- **Unpatched image:** stays the byte copy `copy_into_workarea(current_file.path, project_dir)` (`app.py:8173`). MAC and A2L stay byte copies (`:8177-8182`).
- **Naming:** the emitted file takes `current_file.path.name`. In an existing project whose same-name file holds other bytes, B99-I2 places it as `_<N>`. M-1 (§5) makes a re-save reuse an identical earlier `_<N>`. The saved file becomes the active variant through the existing filename match (`app.py:8214-8229`), which is consistent with D2.
- **Open details:** O-5 (record width and S0 for an emitted image when no prompt asks) and O-6 (a re-derive that blocks).

## 5. M-1 — how `copy_into_workarea` decides reuse vs `_<N>` (B100-I6, amends B99-I2)

At `1d677ba` the B8 reuse check runs only for `candidate == target` (`workspace.py:560-584`). A taken `_<N>` is skipped after `os.lstat` (`:591-597`) without a byte comparison, so identical copies accumulate (`ui_load_dialogs_probe.txt` S7: `firmware_1`, `_2`, `_3` all `a9e114d56077`).

**Rule after Inc 1:** reuse the first existing file among `<name>` and every `<stem>_<N><suffix>` in `destination` that is a regular file, not a link or reparse point, non-empty, of the staged size, and byte-identical to the staged bytes. Otherwise claim the lowest free `_<N>` exactly as today.
- Candidates are **enumerated from a directory listing** (`<stem>_<digits><suffix>`, compared case-insensitively on Windows), not walked until the first gap. Otherwise a deleted `_1` would hide an identical `_2`.
- A size precheck (`stat().st_size == len(staged_bytes)`) runs before `read_bytes`, so the comparison costs one read per same-size candidate.
- Safety rests on the same invariant as today (LLR-155.3, LED .7: no in-app writer replaces a placed file). The S-F4 (link) and PDR C1(a) (0-byte claim) exclusions apply to every candidate.
- The `Path` return contract and the 15 call sites (B99-I2 list) are unchanged. `place_group_into_workarea` keeps "requested names only" (B99 PDR C3(e)); the asymmetry is deliberate and stays out of scope.
- **G-005:** `test_tc018_existing_name_is_dedup_suffixed` and `test_at031b_two_saves_are_distinct_no_clobber` are **red at `1d677ba`** (`evidence/p0-premises/g005-tests.txt`: `FF`), because B8 already reuses identical bytes at the bare name. Inc 1 re-pins both as two pairs: identical bytes → one file, different bytes → `_1`.
- **Ripple census for P1:** 4 test files name a `_2+` file (`test_b99_export.py`, `test_b99_staging.py`, `test_flow_a2b_b94.py`, `test_tui_flow_builder_b94.py`). Each must be classified as identical or differing content before Inc 1.
- **Status honesty:** with wider reuse, the variant-append sync reports `Added variant 'firmware_1'` (`app.py:8615-8617`) for a file that was already there. This is pre-existing at the bare name and widened by M-1. **Condition C-1:** Inc 1 also takes `app.py` for this status (2 source files).

## 6. The Load dialog's data sources (P-A) and the recent store

| Source | Producer | Note |
|---|---|---|
| Projects | `list_projects()` (`app.py:8519-8524`), filtered by `RESERVED_WORKAREA_HOMES` (`workspace.py:40-50`) | Inc 2 makes the reserved match case-insensitive. `Splits` is listed today (`ui_load_dialogs_probe.txt` S6) |
| Work-area files | `workarea/temp/*` regular files, the folder `refresh_files` reads (`app.py:6543-6561`, B99-I9) | Inc 9a moves the enumeration into one function shared by the rail list and the dialog. A work-area pick loads **in place** through `load_selected_file` (as `_load_from_item`, `app.py:9021-9031`), with no second copy |
| Recent sources | **NEW** `read_recent_sources(base_dir)` / `record_recent_source(base_dir, path)` in `tui/workspace.py`, file `<base>/.s19tool/recent_sources.json` | written by `load_from_path` (`app.py:8710`) and `load_a2l_from_path` (`:8789`) after a successful copy, only for sources **outside** the work area |
| Typed path | `_load_path_from_user_input` (`app.py:8658-8672`) | Inc 9a: a project folder or a `project.json` inside the work area routes to the project load. Any other folder names the Projects list instead of `Unsupported file type: ` (L-2) |

**Recent store — no new module (A1 not fired), rationale R31.** `workspace.py` already owns the `.s19tool/` layout: `WORKAREA_DIRNAME`, `LOGS_SUBDIR`, `ensure_workarea` `:81`, `ensure_template_lib` `:92`, `setup_logging` `:120`. A bounded list is two functions and one constant. **Rejected:** `services/recent_sources_service.py` (fires A1 and needs a sub-module declaration, for about 60 lines). **Re-open:** recents gain behaviour (pin, clear, per-project) or a consumer outside `app.py`.

Contract (C6 / C8 / privacy):
- `{"schema_version": 1, "sources": [{"path": "<absolute>", "kind": "s19|hex|mac|a2l"}]}`, newest first, de-duplicated by resolved path, at most 20 entries.
- Read with a size cap (64 KiB) and a parse guard (the `read_project_manifest` idiom). An invalid entry is dropped, never raised.
- Written by staging next to the file and `os.replace`, after a reparse check on `.s19tool` (`_is_reparse_point`, `workspace.py:172`).
- Rendered with `markup=False`.
- **Privacy:** absolute local paths, the same data the log already holds (`app.py:10820-10825` logs every load path). The list never enters `project.json`, a report or a project folder.

**Dialog result contract (B100-I8):** the unified dialog dismisses with `LoadChoice(kind, value)`, where `kind ∈ {project, workarea, recent, path}`. The app routes it in one handler. Today's two contracts (`LoadFileScreen → Optional[Path]`, `screens.py:179`; `LoadProjectScreen → Optional[str]`, `:691`) are consumed by 4 + 7 test files, and `#load_path` / `#project_list` by 9 + 7. PDR decides whether those ids survive.

**Pre-existing C8 exposure, code-read (`planned` at P1):** `LoadProjectScreen` builds `Label(name)` (`screens.py:707`) and `refresh_files` builds `Label(item.name)` (`app.py:6558`). Textual 8.2.8 `Label` defaults to `markup=True` (constructor parameters checked). A file or folder name with `[…]` is parsed as markup: it is mis-rendered, or a malformed tag raises. Inc 9b must build both lists with `markup=False`.

## 7. Progress indicator for long actions (P-D) — the seam and its limit

- **Existing seam:** `set_progress(value, message)` (`app.py:13615-13619`) drives one `ProgressBar#progress_bar` (`app.py:2106`). Callers: the load worker (`:11455`), the before/after worker (`:4184-4211`), the report worker (`:4891-4962`, `:5035`), the diff-report worker (`:6203-6239`), `load_from_path` (`:8750-8769`), `load_a2l_from_path` (`:8823-8868`), load failure (`:11488`).
- **Workers today:** `@work(thread=True)` for load `:11380`, before/after `:4123`, execute scope `:4334`, generate report `:4816`, diff report `:6152`, and CRC `screens.py:2376`, `:2651`.
- **Main thread today:** `_handle_load_project → load_selected_file` (sync, `app.py:8510`, `:10731`), `_load_from_item` (`:9031`), `_handle_save_dialog` (copies and manifest write), `load_a2l_from_path` (parse at `:8844`), flow runs (`run_flow` `:2625`, `run_chain_set` `:2839`, `:2938`). An indicator **cannot tick** while the main thread is blocked. `app.py` has no `set_interval` today.
- **Recommended seam (B100-I12):** widen `set_progress` into `begin_busy(label)` / `step_busy(text, value=None)` / `end_busy(outcome)`. Elapsed time is driven by one `set_interval` on the main thread, and every worker call routes through `call_from_thread`, as now. For main-thread actions, `begin_busy` paints once before the work through the existing `call_after_refresh` idiom (`app.py:8708`): honest about "working", silent about elapsed time.
- **Re-cut:** 12a = the indicator over the actions that already run on workers. 12b = move project load, Save project and flow runs onto workers. 12b is conditional on O-7 and carries threading risk: the flow panels' Run/Confirm enable state is frozen by batch-97 D14 (I-7).

## 8. Per-increment source files vs the 4-file cap

`styles.tcss` is counted as a source file, as batch-97 counted it. **Round 2 (P2):** this table is the architect's round-2 re-derivation from the amended LLRs (`P2-architect-r2.md` §3), with the dispositions of `P2-dispositions-r2.md` applied. The ARQ-gate table is in git at `11763af`. A bracketed file is conditional; PDR decides it, and the increment packet records the decision.

| Inc | Story / finding | Source files (planned) | # | Cap |
|---|---|---|---|---|
| 1 | M-1, G-005 | `tui/workspace.py` (`find_identical`, `place_into_workarea`, `predict_placement`, containment inside the placement: B100-I13, I14, I22), `tui/segment_split_view.py` (the export's word from `PlacementResult`), `tui/app.py` (no "added" for a reused variant) | 3 | ok |
| 2 | M-4, M-7, reserved and device names, L-3 rest | `tui/app.py`, `tui/workspace.py` (one device-name predicate, `PROJECT_NAME_MAX_CHARS`) | 2 | ok |
| 3 | PH-2 | `tui/app.py` (`_reset_project_session`, `_session_snapshot`) | 1 | ok |
| 4 | CW-U-2 | `tui/app.py` (focus targets, the load tails) | 1 | ok |
| 5 | PH-1, D1, R-PC | `tui/app.py`, `tui/services/change_service.py` (the `save_patched` split B100-I15; `mark_saved` / `differs_from_last_saved` B100-I18), `tui/services/project_gather_service.py` (`plan_project_save` B100-I17) | 3 | ok |
| 6 | PH-4, D2, O-1, P-E | `tui/app.py`, `tui/services/variant_execution_service.py` (`gathered`, `compose_load_announcement`), `tui/screens.py` (the Load-result panel), `tui/styles.tcss` (its rules: modal rules live there by convention, `screens.py:131`) | **4** | ⚠ at cap (PDR) |
| 7 | PH-5, L-4, D3, O-2, O-11, UX-26 | `tui/services/manifest_writer.py`, `tui/services/variant_execution_service.py`, `tui/app.py` (`choose_install_set`, LED .34; the plan's `files` row from a key list the app passes, so `project_gather_service.py` is untouched) | 3 | ok; `derived_from` (B100-I16) lands here, not at 5 or 6, which would add `manifest_writer.py` to those increments |
| 8a | M-2, D4, Q-5 | `tui/app.py`, `tui/services/manifest_writer.py`, `tui/services/variant_execution_service.py`, `tui/services/project_gather_service.py` | **4** | **at cap, no slack**: any further file needs a re-cut |
| 8b | M-3 D5, M-6 D6, M-5 D7 (handler), S-02 | `tui/app.py`, `tui/services/project_gather_service.py`, `tui/workspace.py` (`contained_in_workarea` uses for listing and load) | 3 | ok |
| 9a | recents store (per-user, S-16), lister, L-2 routing | `tui/workspace.py`, `tui/app.py` | 2 | ok |
| 9b | P-A C dialog, D10, CW-U-12/13, C8 | `tui/screens.py`, `tui/app.py`, `tui/styles.tcss` (`choose_install_set` stays in `app.py`) | 3 | ok |
| 10 | CW-U-5, P-B A, B-02 | `tui/screens.py`, `tui/app.py` (the one load seam B100-I20), `tui/styles.tcss`, `tui/screens_directionb.py` (a public dirty-flag reader; the flag is private) | **4** | ⚠ at cap (PDR, ARCH C-5) |
| 11 | M-4 preview, D7 dialog half, P-C B | `tui/screens.py`, `tui/app.py`, `tui/styles.tcss` | 3 | ok |
| 12a + 12b (one unit, R-PD) | N5, P-D A, O-7 | `tui/app.py`, `tui/styles.tcss` (quit reuses the Inc 10 modal with its question text as a parameter) | 2 | ok; the `save_patched` split is already in Inc 5, so `change_service.py` is not needed here |

**No increment exceeds 4 source files.** PDR (`a1cad7e`) decided every conditional: Inc 6, 8a and 10 are at 4 (⚠, with their reasons in the design proposal), Inc 7 and 9b are 3, and Inc 12a+12b is 2. Inc 12's quit question depends on Inc 10's modal taking its text as a parameter (10 → 12).

Hard order: 1 → 6 (save-back naming relies on the reuse rule); 2 → 11 (the summary uses the name rules); 3 → 8a and 3 → 10 (reopen and confirm sit around the reset); 5 → 10 → 11 (the unsaved predicate and the save plan land at 5); 6 → 7 → 8a (the manifest seam, then `files` and `derived_from`, then `active_document`); 9a → 9b; 7 → 9b (`choose_install_set`); 10 → 12 (the parametrised confirm modal, ARCH-PDR-4); 12a and 12b as one unit. The prototype verdict is in, so no increment is prototype-gated any more.

### 8.1 Round-2 test-arm moves (B-06)

Each arm runs at the increment that makes it possible. An arm is written there; it is not left failing in an earlier increment.

| Arm | From | To | Why |
|---|---|---|---|
| LLR-164.2 (b): exact-name merge with the target's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` carried | Inc 2 | **Inc 8a** | the reader parses `gathered` from Inc 6 and `active_document` from Inc 8a, and the carry conversion is LLR-168.3 (Inc 6). Inc 2 keeps the refusal arms and an exact-name save that still adds a variant (LLR-005.1, `test_save_second_s19_into_project_appends_variant` green) |
| TC-B100-59 / AT-B100-21: plan rows | Inc 5 (all 5 scenarios) | Inc 5: fresh, pending patch, refused; **Inc 7**: the `files` row; **Inc 8a**: the document row and the merge scenario; **Inc 8b**: the save-as-with-sub-folders scenario | each row type exists only from its increment |
| TC-B100-12: modal closes | Inc 4 (all 4 closes) | Inc 4: the load tails (Load file, project load, Workarea Files pick) and TC-B100-13 (A2L); **Inc 6**: panel `enter` / `esc`; **Inc 9b**: dialog `esc`; **Inc 10**: question `n` | each modal is introduced by that increment |
| B100-I16: the panel's "patched, N bytes differ" against `derived_from` | Inc 6 | **Inc 7** | `derived_from` is written and read from Inc 7 |
| B100-I20: one arm per image-replacing route (dialog, rail pick, variant switch, project load) | — | **Inc 10** | the seam lands at Inc 10; the dialog arm needs Inc 9b, already landed |

## 9. Parallelisation verdict (mechanical rule, `p1-arq.md`)

All increments are in module **product**, so the rule is applied at file granularity, as in the batch-92/99 precedent. `app.py` is in every increment except Inc 1 (without C-1), so **every pair among 2…12b intersects on `app.py`**. Inc 1 is disjoint from all but 2 and 9a (`workspace.py`) and comes first anyway. Neither exit applies:
- a re-cut cannot remove `app.py`, because every finding's handler lives there;
- splitting `app.py` is a boundary move far out of proportion for this batch.

**Verdict: sequential, one Kimi worktree per increment, merged in order** (A4 not fired). This matches the batch-99 lesson that parallel lanes conflicted on the test-id registry. The `pip -e` trap applies to every worktree: probe `s19_app.__file__` before each run.

## 10. Decisions D1–D7 leave open

| # | Question | ARQ recommendation | Owner |
|---|---|---|---|
| O-1 | Do the **other** writers into an open project also rewrite `project.json`? These are the Load-file variant append (`app.py:8591`), MAC sync (`:8622`, `:8630`) and A2L sync (`:8652`). Without it, a variant added by Load file is active in memory but not on disk: the PH-4 class again | yes: every in-project write ends in `_write_and_verify_manifest` | operator at P1 |
| O-2 | `files` scope | top-level data/A2L + the active document (§3.1) | P1 |
| O-3 | Unsaved Flow Builder edits across a project load | P-B asks when dirty; never cleared silently | P-B |
| O-4 | D5 names `flows/ patches/ checks/ reports/`; the project also holds `flowsets/` (`app.py:3028`), `templates/` (gather home), `splits/` (`segment_split_view.py:168`) | copy every project home: a chain set in `flowsets/` names flows in `flows/` | operator |
| O-5 | Record width and S0 for an emitted Save-project image (no prompt asks) | the save-back defaults, 32 bytes/line with the S0 preserved (`app.py:3421-3427`), shown in the P-C preview | PDR / P-C |
| O-6 | Save project when the re-derive blocks (`change_service.py:2146-2158`) | refuse the whole save and name the blocked entries | P1 |
| O-7 | Which main-thread actions move to workers for Inc 12 (§7) | project load and flow runs; Save project only if measured slow | operator at P-D |
| O-8 | Two new visible surfaces outside P-A..P-D: the D2 "which variant opened / now active" announcement and the Load problem list (D3) | one prototype surface **P-E "Load / save result notice"** before Inc 6 | orchestrator |
| O-9 | M-4: a name equal to a **different** existing project | Inc 2 refuses with a notice; Inc 11's preview shows it before Save. The name of the open project updates in place without a warning | P1 |
| O-10 | After a D2 save-back, does `current_file.path` follow the new variant? | no. Keep the B-2 provenance (`source_image_path=loaded.path`, `app.py:3436`); update `_variant_set.active_id` and `current_file.variant_id` only | PDR |
| O-11 | `write_project_manifest` stages at the fixed `temp/project.json` (`manifest_writer.py:509`), the shared-staging pattern LLR-155.1 retired elsewhere | stage through `_private_stage_dir` in Inc 7, which already owns the file, or backlog it | P1 |

### 10.1 Orchestrator rulings on O-1..O-11 (ARQ gate, 2026-10-26)

These rulings were taken under the batch's standing authorization ("autonomous with exceptions"). None of them re-opens D1–D7, and each follows from them. They are recorded in `PLAN.md` and `decisions_log`.

| Id | Ruling | Why |
|---|---|---|
| O-1 | **Yes.** Every writer into an open project rewrites `project.json` through `_write_and_verify_manifest`: the Load-file variant append and the MAC/A2L syncs. | Otherwise PH-4 comes back through another door (D2's intent). |
| O-2 | **As recommended.** Digests cover the top-level data files, the A2L and the active document. `flows/`, `reports/`, `checks/` and other sub-folders are excluded. | Those folders change by design after a save, so a digest there would report false drift. |
| O-3 | **Yes.** The P-B confirm also asks when the Flow Builder has unsaved edits. Added to the P-B surface. | No unsaved work is dropped without a question (CW-U-5's intent). |
| O-4 | **Copy every project sub-folder.** That means `flows/`, `patches/`, `checks/`, `reports/`, plus `flowsets/`, `templates/` and `splits/`. | The operator chose "the new project is a full copy" (D5). A chain set in `flowsets/` refers to `flows/`. |
| O-5 | **Save-back defaults.** 32 bytes per line, S0 preserved, and no prompt in Save project. | This is the rule batch-99 froze for saved images. |
| O-6 | **Refuse the whole save and name the blocked entries.** | "Never lose or alter silently": a partial save would contradict D1's verified image. |
| O-7 | **Inc 12b moves project load, Save project and the A2L parse onto workers.** Flow runs already report per block. 12b stays conditional on the P-D verdict. | These are the long main-thread actions the operator meets; scope stays bounded. |
| O-8 | **Done:** surface **P-E** (Load project result: which variant opened and why, the D3 problem list) is already in the prototype round, from the operator's D2 note. Inc 6 and Inc 7's display wait for its verdict. | Operator note on D2. |
| O-9 | **Inc 2 refuses with a notice, and Inc 11's dialog shows the clash before Save.** | This is the warning promised in the plan (M-4), and it never merges silently. |
| O-10 | **Agreed.** `current_file.path` keeps the source path after a D2 save-back, and only the active variant changes. | It keeps the before/after report's source correct. |
| O-11 | **Fix it in Inc 7:** `write_project_manifest` stages privately, like batch-99's `.staging`. Inc 7 is at 3 files. | Same root as batch-99 H-3, and Inc 7 already touches the manifest writer. |

## 11. Risks

- **Save applies pending entries (Inc 5).** With D1 through `save_patched`, an entry added after the last apply is written by Save project. This is the batch-99 rule, announced by the suffix. An operator who reads "Save" as "save what I see" can still be surprised (O-5/O-6, and P-C shows it).
- **Manifest write amplification (Inc 6, O-1).** Every in-project write rewrites and re-verifies `project.json`. A failed rewrite after a successful file write leaves the folder ahead of the manifest. The verify mismatch notice already exists (`app.py:8416-8423`).
- **Hash cost on the main thread (Inc 7).** Estimated, not measured (§3.1). Large A2L projects add load and save latency that nothing displays until 12a/12b.
- **Reuse widening (Inc 1).** Callers receive an existing `_<N>` name where they used to receive a new one. Every status that says "added" or "saved as" must stay true (C-1). The flow WRITE-OUT and the save-back return an existing path whose bytes are identical (LLR-155.3 holds).
- **Reset completeness (Inc 3).** The app-side inventory is hand-made. The derived-set AT (§2.3) is the guard. The service side is complete by construction.
- **Older builds drop the new keys** on re-save (§3.2). A downgrade loses digests and the active document silently, apart from the next Load's legacy notice.
- **Threading (12b).** Moving flow runs off the main thread crosses the frozen I-7 surface (batch-97 D14 Run/Confirm enable rules). 12b must keep every "a painter re-enables" exit.
- **Markup injection (9b).** A pre-existing C8 exposure in the two list builders (§6), with file-derived names from disk.
- **Recent store privacy.** Absolute local paths in `.s19tool/recent_sources.json`, bounded to 20 and kept local (§6).
- **Index casing (carried from batch-99).** The index holds `docs/architecture.md`; the working tree file is `docs/ARCHITECTURE.md` (`git ls-files docs | grep -i arch` vs `ls docs`). Harmless on Windows.

## 12. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated | ✓ | 4 source files per increment `executed` (§8 table); sequential worktrees, A4 not fired `executed` (`state.json` triggers); frozen engine §7 untouched `executed` (no §7 path in §8); B99-I2 / B99-I7 / I-7 frozen surfaces respected `executed` (§4, §5, §7); public-repo wording `executed` (integrity is described as size + SHA-256 drift detection only); cost/latency `planned` (hash cost estimated, not measured, §3.1) |
| 2+ alternatives where a real decision exists | ✓ | reset by rebind vs `reset()` (§2.3); schema bump vs additive (§3.1); `save_patched` vs a direct emitter (§4); journal predicate vs verify re-parse (§4); recents in `workspace.py` vs a new module (§6); progress seam on workers vs moving actions (§7) |
| Constraints that do not apply marked `n/a` | ✓ | network/auth/secrets `n/a — no external surface` (C1–C5, C7 not fired); runtime $ cost `n/a — local TUI` |
| Recommendation tied to constraints | ✓ | file cap → re-cuts 8/9/12 (§8); frozen B99-I7 → `save_patched` (§4); completeness by construction → rebind (§2.3); the A1 cost → recents in `workspace.py` (§6) |
| Risks listed | ✓ | §11 |
| Every touched path under a declared module | ✓ | every §8 path exists under `s19_app/**` (`ls s19_app/tui/{app,screens,workspace}.py s19_app/tui/styles.tcss s19_app/tui/services/{change_service,manifest_writer,variant_execution_service,project_gather_service}.py`); no new file |
| Boundary verdict with evidence | ✓ | no new module; no new import edge: `app → changes.io.write_change_document` exists (`app.py:41-46`), `app → manifest_writer` (`:154-155`), `app → variant_execution_service` (`:175-179`), `project_gather_service → workspace` (`project_gather_service.py:70-75`), `manifest_writer → variant_execution_service` (`manifest_writer.py:59-64`); `hashlib` is stdlib |
| Interfaces + consumers measured | ✓ | §3.2 reader census; B100-I1..I12 in the map with consumer counts (`grep -rlF --include=*.py … tests`: `LoadFileScreen` 4, `LoadProjectScreen` 7, `SaveProjectPayload` 7, `_handle_load_project` 13, `_handle_save_dialog` 7, `copy_into_workarea` 15, `read_project_manifest` 8) |
| Session-state census executed | ✓ | §2.1 commands; 67 attribute names; 0 external holders of the change service |
| What would change the recommendation | ✓ | R24–R33 "re-open" column in the map; O-1..O-11 |
| Diagram when flow is non-trivial | ✓ | §3.4 (the Load-project sequence) |
| Two-layer requirements (US→AT→outcome + US→HLR→LLR→TC) | ✗ `planned` | owed at P1. ARQ precedes derivation (`p1-arq.md`) |
