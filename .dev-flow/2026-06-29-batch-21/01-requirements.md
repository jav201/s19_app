# 01 — Requirements — batch-21 (#8 Patch-editor overhaul)

> Status: **Phase 0 (scope-first decomposition / DoR)**. §2.6 below is the Phase-0 artifact. #8 decomposes into 6 candidate stories spanning ≥2 batches; the operator selects the batch-21 in-scope slice at the DoR gate.
> Language: English. Normative keyword: `shall`.

## 1. Purpose
Overhaul the patch editor (`PatchEditorPanel`, currently a single `ScrollableContainer` @`screens_directionb.py:335` hosting a 10-item flat stack). Six candidate sub-features (BACKLOG #8). High blast radius → decompose-before-code.

## 2. Context

### 2.4 Constraints
- Engine-frozen set OFF-LIMITS. `screens_directionb.py`, `app.py`, `workspace.py`, `styles.tcss`, `changes/io.py` are editable (TUI-side write logic → `changes/io.py`). ≤5 files/increment.
- **C-13 geometry-budget is the central risk** for any pane-layout story — measure the patch-editor host width at 80/120 cols at draft time; do NOT assume the full-width single-container budget transfers to a 4-pane split.

### 2.5 Assumptions (spike-verified, ec3a2a7)
- `PatchEditorPanel` = single `ScrollableContainer` (`screens_directionb.py:335`; `styles.tcss:556`), 10 stacked groups; hosted in `#screen_patch` (`app.py:1304`), key `6`. MODIFY compose() to host panes — refresh/show methods stay, targets move.
- Change docs = v2 JSON (`changes/io.py`), default name `changes.json` (`DEFAULT_CHANGE_FILE_NAME` :127); ONE in-memory `ChangeDocument`; final save lands in the **workarea ROOT** (`.s19tool/workarea/`) via `placement(staged, workarea)` (io.py:1352) — `temp/` is STAGING-only, cleaned after write (corrected Phase-2; the spike's "temp|<project>" was imprecise). **No change-file inventory/dropdown today** (operator types the path). Dropdown pattern exists: `AbDiffPanel.set_variants()` + `Select(...)` (`screens_directionb.py:1139`).
- Workarea: `.s19tool/workarea/` root (final saves) + `temp/` (staging) + `<project>/` (`workspace.py:16-48`); containment enforced on WRITE (`copy_into_workarea` :215) but NOT on READ (`resolve_input_path` :469, size-cap only). **No patch-dedicated folder.**
- Variants: `ProjectVariantSet.active_id` (`models.py:86`), persisted `project.json` `active_variant` (`variant_execution_service.py:198`). Inline variant dropdown is NET-NEW (modal `SelectVariantScreen` exists @`app.py:2783`, not inline).
- Checks: `#patch_checks_run_button` (`screens_directionb.py:591`) → `run_checks` action → `app.py:1311-1443` → `run_check_document`. **No bug/TODO/failing test found** — the "fix" is underspecified.
- Geometry: patch editor activates over the workspace body; estimated host content width ~58 cols @120-col, ~37 cols @80-col (UNVERIFIED — measure before the split story). No patch-editor snapshot test today (only an empty scaffold cell).

### 2.6 Source user stories (decomposition of #8)

| ID | Story | Tier | DoR status |
|----|-------|------|------------|
| US-026 | As an operator, I want a dropdown of available change files so I can pick one to load instead of typing its path. | 1 (low blast, NET-NEW) | READY *(folder source = couple w/ US-027)* |
| US-027 | As an operator, I want patch change-files kept in a dedicated workarea folder so they're organized and discoverable. | 2-critical-path (MODIFY workspace.py) | READY |
| US-028 | As an operator, I want an inline variant dropdown in the patch editor so I can switch the active variant without leaving the screen. | 1 (low blast, NET-NEW) | READY |
| US-029 | As an operator, I want the Checks button to clearly communicate what it does and which artifact it acts on, so I understand its purpose without guessing. | 1 (MODIFY, UI-clarity) | **READY** (operator-clarified: clarity/affordance, not a functional bug) |
| US-030 | As an operator, I want the patch editor laid out as a 4-pane split so the entries / change-file / checks / variant areas are visible together. | 2 (MEDIUM, geometry) | **SPIKE** — host width must be measured @80/120 before HLR (C-13); depends on US-026/027/028 pane decisions |
| US-031 | As an operator, I want the 4-pane layout to hold up at 80 and 120 cols (no clipping/underflow). | 2 (MEDIUM) | **OUT (this batch)** — depends on US-030 |

#### Refinement log

**US-026 — Change-file dropdown** · READY (pending folder source)
- INVEST: I ~ (couples to US-027 for the folder to scan) · N ✓ · V ✓ (no path-typing) · E ✓ · S ✓ (~2-3 files) · T ✓ (dropdown lists files; selecting loads).
- Path: new `Select` + file-discovery + `set_change_files()` on the panel (mirror `set_variants()`); `app.py` populates on screen activation. Source folder = US-027's dedicated folder (or default `temp/`).
- AT: "When ≥1 change file exists in the patch folder, the operator sees them in the dropdown and selecting one loads it."

**US-027 — Dedicated workarea folder** · READY
- INVEST: all ✓; MODIFY `workspace.py` (new `WORKAREA_PATCHES` const + `ensure_patch_folder()`); containment already enforced.
- Open sub-decision: global `.s19tool/workarea/patches/` vs per-project `<project>/patches/` — resolve in Phase 1.
- AT: "Saving a change file lands it in the dedicated patch folder; the folder is created if absent."

**US-028 — Inline variant dropdown** · READY
- INVEST: all ✓; NET-NEW inline `Select` + `VariantChanged` message → `app.py` updates `active_id` + persists manifest. Reuse `_variant_display_options()` (`app.py:2730`).
- AT: "Selecting a variant in the patch-editor dropdown updates the active variant and persists it to project.json."

**US-029 — Checks-button clarity** · **READY** (operator-clarified at DoR gate)
- **Observed defect (operator):** "the button is not clear enough … in the position it was laid out. the action … was not described nor pointed out clearly as to what it was doing in interaction with any other artifact." ⇒ NOT a functional bug (spike confirmed no crash/dead-wiring/TODO/failing test) — it is a **clarity/affordance defect**: the button's label + placement don't communicate WHAT it does or WHICH artifact it operates on (it runs the loaded change document's checks against the image — that relationship is invisible).
- INVEST: I ✓ (independent of US-026/027) · N ✓ · V ✓ (removes guesswork) · E ✓ · S ✓ (~1-2 files: label + inline description/help; possibly reposition) · T ✓ (rendered label/description text is observable through the screen).
- Path (Phase-1 to specify the exact treatment): a clearer button label and/or an inline one-line description/help stating what Checks does and on what artifact; optionally reposition near the change-file controls so the relationship reads. Small UI-clarity change in `screens_directionb.py` (+ `styles.tcss` if a description row is added).
- **C-13:** LOW — the panel is a vertical `ScrollableContainer`, so an added description row scrolls (no width-budget hit); a label-text change is in-place. Confirm at Phase 1 (no new always-on widget in a constrained row).
- AT: "When the patch editor is open, the operator observes a label/description on the Checks affordance that states what it checks and which artifact it acts on (not a bare 'Checks')."

**US-030 — 4-pane split** · **SPIKE**
- The headline refactor, but two gates before it's READY: (1) **measure** the patch-editor host content width at 80 and 120 cols (the ~37/~58 estimate is unverified) — a 4-pane horizontal split into ~37 cols at 80-col very likely underflows (C-13 prime case; C-13.1 fallback needed); (2) the pane allocation depends on US-026/027/028 being decided (which widgets occupy which pane). Recommend its own batch after the Tier-1 slice lands.

**US-031 — Geometry baseline/snapshots** · OUT (this batch) — follows US-030.

### Batch-21 scope (operator-decided at DoR gate)
- **IN: US-026 + US-027** ("change-file management": dropdown + dedicated folder) — operator's pick. Coupled (dropdown scans the folder), low-risk, no geometry refactor.
- **US-029 → READY** (operator clarified the defect = Checks-button clarity/affordance). Small, independent UI-clarity fix. **Inclusion in batch-21 pending operator confirm at the gate** (not in the original slice pick; recommend including — tiny + independent + same screen).
- **DEFERRED to a later batch:** US-028 (variant dropdown — operator excluded from this slice), US-030 (4-pane split — SPIKE, needs host-width measurement + C-13.1 ladder; its own geometry batch), US-031 (snapshots — OUT, follows US-030).
- **Per-story already-shipped check (RC-1) for the in-scope slice:** run at Phase-1 entry against `ec3a2a7` (US-026 dropdown / US-027 patch folder / US-029 Checks label — confirm net-new before deriving). **DONE:** `set_change_files`/dropdown ABSENT, `WORKAREA_PATCHES`/`ensure_patch_folder` ABSENT → both net-new. Seams confirmed (`DEFAULT_CHANGE_FILE_NAME` io.py:127, Checks button screens_directionb.py:591, `set_variants` :1139).

---

## 3. High-level requirements (HLR)

> Numbering continues from batch-20 (last HLR-029). **HLR-030 = US-026 dropdown, HLR-031 = US-027 folder, HLR-032 = US-029 clarity.** Implementation order differs (folder before dropdown — output-then-consume); see §4 increments.

### HLR-030 — Change-file dropdown · traces US-026
> When the Patch Editor is open AND ≥1 change file is present in the patches workarea folder, the Patch Editor **shall** present those change files as selectable options in a dropdown affordance; AND when the operator selects an option the Patch Editor **shall** load that change file as the active change document (same load path as the existing change-file Load action). When no change file is present, the dropdown **shall** present no change-file options. The dropdown **shall not** require typing a file path to load a change file that exists in the patches folder.
- **Observable deliverable:** the `#patch_doc_file_select` dropdown options reflect `workarea/patches/*.json`; selecting one makes that file's `ChangeDocument` active (entries table reflects it). **Oracle:** Pilot query of the Select options + the active document.
- **Acceptance:** AT-030a (C-12 gate) · AT-030b (empty-folder boundary) · AT-030c (consumer guard).

### HLR-031 — Dedicated patches folder · traces US-027
> When the Patch Editor saves a change document, the system **shall** write that change file into the dedicated patches folder `<base_dir>/.s19tool/workarea/patches/`, AND **shall** create that folder if absent. The system **shall not** place Patch-Editor change-document saves loose in the workarea root (`.s19tool/workarea/`), which is where the prior behavior placed them (`temp/` was and remains staging-only, untouched). The written file **shall** remain within the work-area containment root (`copy_into_workarea` placement preserved).
- **Observable deliverable:** a saved `*.json` under `…/workarea/patches/`, parseable as `s19app-changeset` v2; folder created on demand. **Oracle:** on-disk file path + parse.
- **Acceptance:** AT-031a (golden gate) · AT-031b (idempotent/no-clobber boundary).

### HLR-032 — Checks-button clarity · traces US-029
> When the Patch Editor is open, the Checks affordance **shall** display text stating (a) that it runs the loaded change document's checks and (b) that it acts against the loaded image — rather than the bare label "Run checks". The Checks affordance **shall** continue to post the existing `run_checks` action unchanged (label/description change only; behavior unchanged).
- **Observable deliverable:** a rendered description naming what is checked + the target artifact, near `#patch_checks_run_button`; `id` + action-map entry unchanged. **Oracle:** Pilot query of the rendered text + the unchanged action wiring.
- **Acceptance:** AT-032a (clarity-present gate) · AT-032b (bare-label-gone regression).

**`should`-misuse check: PASS** — every normative clause is `shall`/`shall not`. **Engine-frozen check: PASS** — touched files (`workspace.py`, `changes/io.py`, `screens_directionb.py`, `app.py`, `styles.tcss`) are the TUI-side editable set; 0 frozen-engine files.

### 3.x C-13 geometry finding
**PASS by structure — no horizontal-width budget hit.** `#patch_editor_panel` is `width:100%; height:1fr; overflow-y:auto` (VERIFIED `styles.tcss:556-561`) — a VERTICAL scroll container. Every added element is a new ROW that extends panel height and scrolls; none competes for horizontal width. The US-026 `Select` is full-width (mirrors the shipped diff Select `styles.tcss:568-574` — no min-width floor). The US-029 description is a `width:100%; height:auto` row. **No 4-pane split this batch** (US-030/031 deferred). **One flagged measurement (`assumed — measure Phase 3`):** ONLY if the dev implements US-029 as a verbose *button label* inside the 5-button controls `Horizontal` at 80 cols — mitigated and struck by choosing the standalone description-Label row (the §6 decision).

---

## 4. Low-level requirements (LLR) + increment plan

> Dependency order (output-then-consume): **Inc1 US-027 folder → Inc2 US-026 dropdown (consumes the folder) → Inc3 US-029 clarity (independent)**. Each ≤3 files; 0 engine-frozen.

### Increment 1 — HLR-031 (US-027 folder)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-031.1** | Add `WORKAREA_PATCHES = "patches"`; `ensure_workarea` creates `workarea/patches/` alongside `temp/`. | `workspace.py:18` (const) + `:45-46` (mkdir) | MODIFY | New module constant (export-safe); `ensure_workarea` return type unchanged (added mkdir is a side effect → `test_tui_workspace.py:33` stays green, EXTEND it to assert `patches/` exists = net-new fail-loud). |
| **LLR-031.2** | `write_change_document` routes the FINAL placement dir to `workarea/patches/` — corrected: today the final file lands in the **workarea ROOT** (`placement(staged, workarea)` io.py:1352), NOT `temp/` (`temp/` is staging-only). Change `placement(staged, workarea)` → `placement(staged, workarea / WORKAREA_PATCHES)`. | `changes/io.py:1348-1352` | MODIFY | **Internal default, no new param** → `ChangeService.save` (change_service.py:775) + all ~20 `write_change_document` callers untouched. `copy_into_workarea(staged, workarea/patches)` still contained (subdir inside workarea). **Inc1 must ADD a net-new positive placement TC** (`final path is_relative_to workarea/"patches"`) — else the move is silently unverified (existing tests assert containment under `workarea/` generically, which `patches/` satisfies). |

### Increment 2 — HLR-030 (US-026 dropdown), consumes Inc1
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-030.1** | Add `Select(id="patch_doc_file_select")`, full-width, in the change-file row; posts a message on `Select.Changed` carrying the chosen filename. | `screens_directionb.py:580-595` | MODIFY | `Select`/`ScrollableContainer` already imported (:48,55). New widget id = AT selector. |
| **LLR-030.2** | Panel method `set_change_files(names)` populating the Select (empty → no options). Mirror `set_variants` (:1139). | `screens_directionb.py` (new method) | NEW (method) | Pure view; no `changes` import (keeps the panel free of model imports). |
| **LLR-030.3** | App scans `workarea/patches/*.json` → `panel.set_change_files(sorted names)` on patch-screen activation AND after each save; on `Select.Changed`, route the chosen name through the EXISTING `service.load(path, base_dir)` (abs path = `workarea/patches/name`). Options built from `match.name` (bare component); scan results **sorted** deterministically. **Security F1 guard:** before `service.load`, re-resolve the constructed path and assert `resolved.is_relative_to(patches_dir)` (skip entries that aren't; optionally skip `match.is_symlink()`) — closes the write-guarded/read-unguarded asymmetry. | `app.py` (activation hook + save-result path; reuse `load_doc` logic :1386-1393) | MODIFY | Reuses `ChangeService.load` unchanged. Glob helper deterministic + **sorted** (AT-030a selects by known filename, not positional index). Re-scan-after-save satisfies the C-12 chain (R2). |

### Increment 3 — HLR-032 (US-029 clarity), independent
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-032.1** | Add a description `Label` (own row) reading **`"Checks: runs the loaded change document's checks against the loaded image."`** near `#patch_checks_run_button`; keep the button label short. | `screens_directionb.py:591` area | MODIFY | `id="patch_checks_run_button"` + action-map `"patch_checks_run_button":"run_checks"` (:779) **MUST NOT change** (AT-032b asserts wiring unchanged). |
| **LLR-032.2** | CSS for the description row: `width:100%; height:auto` (mirror `styles.tcss:568-574`). | `styles.tcss` (new rule) | NEW | No horizontal-budget impact (vertical). |

**File-count:** Inc1 = `workspace.py` + `io.py` (2). Inc2 = `screens_directionb.py` + `app.py` (2; +opt `workspace.py` glob helper → still ≤3). Inc3 = `screens_directionb.py` + `styles.tcss` (2). All ≤5.

---

## 5. Acceptance & traceability

### 5.2 Dual traceability
**Behavioral (black-box):**
- US-027 → **AT-031a** (golden, gate) → save via `request_action("save_doc")` (the change-document save — NOT the save-back image prompt) ⇒ `*.json` under `…/workarea/patches/` (folder created if absent), parseable v2 → *surface: on-disk file* · **AT-031b** (boundary) → save twice ⇒ no error, no clobber; assert **`len(patches.glob("*.json")) == 2` AND the two on-disk names DIFFER** (dedup-suffixed — the no-clobber contract is inherited from `copy_into_workarea`; pin it by distinct names, not just "no exception").
- US-026 → **AT-030a** (C-12 GATE) → produce TWO distinct files via the real save (`save_doc`, US-027 — name the producer explicitly, not the save-back image writer) → re-open Patch Editor → dropdown lists both → select the SECOND **by known filename** (options are sorted; do NOT index `[1]` on FS-order) → assert the editor holds file #2's distinguishing entry (C-10 non-default + content) → *surface: Select options + active document*. Sub-assertion (R2): a save performed WHILE the patch screen is open appears in the dropdown without re-activation. · **AT-030b** (boundary) → empty patches folder ⇒ empty/placeholder dropdown (`Select(allow_blank=True)` path), no crash · **AT-030c** (GUARD, in addition, NOT the gate) → file dropped DIRECTLY into `patches/` (bypassing save) ⇒ listed + loadable (pins the scan contract; stays green under a reverted save handler).
- US-029 → **AT-032a** (gate) → render Patch Editor ⇒ Checks affordance shows the actual substring naming what + which artifact (not bare "Run checks") → *surface: rendered label/description* · **AT-032b** (regression) → the bare-`Run checks`-only state is gone (enriched description present).

**Functional (white-box, TCs named; numbered Phase-3 per V-5):**
- HLR-031 → LLR-031.1/.2 → **TC** folder-creation (`ensure_workarea` makes `patches/`; extend `test_tui_workspace.py:33`) + **TC (NET-NEW, REQUIRED — architect):** positive placement assertion `final saved path is_relative_to(workarea / "patches")` — must be net-new, NOT a rename of an existing green containment test (existing tests assert `under workarea/` generically, which `patches/` satisfies, so without this the move is silently unverified and AT-031a's counterfactual can't go RED).
- HLR-030 → LLR-030.2/.3 → **TC** file-discovery (scan returns the `.json` set, ignores non-change files) + **TC** dropdown-population (one option per file; empty → placeholder).
- HLR-032 → LLR-032.1 → **TC** render (composed panel exposes the enriched Checks description naming the artifact; `id`/action unchanged).

### 5.3 Validation method
| Req | Method | Justification |
|---|---|---|
| AT-031a/b | test (pilot) + unit | On-disk artifact reached only through the save handler; observe the file in `patches/` via the shipped click path. Unit pins the resolver/`mkdir` contract. |
| AT-030a/b/c | test (pilot) + unit | Select→load wiring + the right doc loaded is a UI-event + state observation; only Pilot exercises it. Unit covers scan/population. |
| AT-032a/b | test (pilot) | Pure render assertion on the composed screen (label/description substring). |

### 5.4 Counterfactual table (QC-2)
| AT | One-line revert → RED |
|---|---|
| AT-031a | placement dir left `temp/` ⇒ file not under `patches/` → RED |
| AT-031b | drop the `exist_ok`/re-create guard ⇒ second save raises/clobbers → RED |
| AT-030a | Select not populated from the scan ⇒ no 2nd option / load returns dummy ⇒ file #2's entry never appears → RED |
| AT-030b | scan indexes `[0]` on empty ⇒ exception on open → RED |
| AT-030c | scanner filters to a save-stamped name only ⇒ directly-dropped file not listed → RED |
| AT-032a/b | leave bare `Button("Run checks")` no description ⇒ substring absent → RED |

---

## 6. Decisions, risks, assumptions

### 6.2 Key decisions
- **D1 (US-027 folder location) = GLOBAL `.s19tool/workarea/patches/`** (not per-project). The interactive save path is already global — final placement is the **workarea ROOT** (`placement(staged, workarea)` io.py:1352; `change_service.save` passes no project dir) — so the fix routes root→`patches/`, not temp→patches (architect MAJOR-1 correction). Per-project routing would be a larger, riskier change entangling project lifecycle and forcing the dropdown to branch. Dropdown then scans ONE folder. Containment preserved (subdir inside workarea). New const `WORKAREA_PATCHES="patches"`.
- **D2 (placement seam) = route INSIDE `write_change_document`** (internal default subdir), NOT a new param to `ChangeService.save` → zero call-site churn; the save-back patched-*image* writer (`app.py:1495`) is a different path, untouched.
- **D3 (US-029 treatment) = standalone description Label row**, NOT a verbose button label → removes the only horizontal-row width risk (5-button controls row @80). Exact AT anchor text: `"Checks: runs the loaded change document's checks against the loaded image."`
- **D4 (HLR vs increment numbering):** HLR numbers follow story ids (030/031/032 = dropdown/folder/clarity); increments follow dependency order (folder → dropdown → clarity).

### 6.3 Risks / watch-items
- **R1 (RESOLVED by architect census):** NO existing test asserts the change-file save lands in `temp/` OR pins the workarea root by exact path — the placement tests (`tests/test_unified_write.py::test_tc018_*`) assert containment under `workarea/` generically, which `patches/` satisfies. ⇒ **suite stays green, zero test edits**, BUT the move is silently unverified → Inc1 MUST add the net-new positive placement TC (see §5.2). The earlier R3 hypothesis (a `test_changes_schema.py` temp assertion breaks) was FALSE (that test asserts round-trip parse, not placement).
- **R2 (dropdown refresh):** scan must re-run after each save (not only on activation), else a save while the screen is open won't appear — also required by the AT-030a C-12 chain. Folded into LLR-030.3.
- **R3 (latent, state-don't-hide — directory corrected):** existing change files a user has already saved sit in the **workarea ROOT** (`.s19tool/workarea/<name>.json`, the default save target — NOT `temp/`; architect MAJOR-2). The new dropdown scans `patches/` only, so those root files won't appear. Acceptable for the slice — no data loss, still loadable by typed path. NOT a regression; stated. One-way-door: low (a future increment could also scan the root for back-compat — out of scope).
- **R4 (security) = GRANTED-after-fold (Phase-2 security-reviewer):** the WRITE path stays containment-safe (`_safe_name` + `copy_into_workarea` guards, both preserved under `patches/`). The READ path (`read_change_document`→`resolve_input_path`) has NO containment/symlink guard — only a size cap — so a symlinked `patches/` entry would be followed on load (F1, LOW; net-neutral vs the existing typed-path Load, read-only/parse-only/size-capped). **Fold (Inc2, LLR-030.3):** build Select from `match.name` + assert `resolved.is_relative_to(patches_dir)` (skip non-conforming; optionally skip symlinks) before `service.load`. F3 (Select renders raw filename, no markup injection) + F4 (no new external/network/secret surface) = PASS.

### 6.4 Reconciliation log

**Phase-2 cross-review (architect ∥ qa ∥ security) — 0 blockers; architect PROCEED, qa PROCEED, security GRANTED-after-fold. Folds APPLIED body-first:**
- **F-A1 (architect MAJOR-1, factual):** current final save = workarea ROOT, not `temp/` (`temp/` is staging-only). Corrected §2.5, HLR-031, LLR-031.2, D1, AT-031a. Semantically the fix is the same one-liner `placement(staged, workarea / WORKAREA_PATCHES)`.
- **F-A2 (architect MAJOR-2):** R3 rewritten — orphaned files are in the workarea ROOT (default save target), not `temp/`.
- **F-A3 (architect, R1 RESOLVED):** no existing test asserts `temp/` placement (census: `test_unified_write.py::test_tc018_*` assert containment under `workarea/` generically → `patches/` satisfies → suite stays GREEN). ⇒ Inc1 MUST add a NET-NEW positive placement TC (`is_relative_to(workarea/"patches")`) + extend `test_tui_workspace.py:33` to assert `patches/` created — else the move is silently unverified (AT-031a counterfactual can't go RED). Added to §4 LLR-031.1/.2 + §5.2.
- **F-Q1 (qa major-1):** AT-031b now asserts TWO DISTINCT on-disk names (`len==2` + names differ) — the no-clobber/dedup contract is inherited from `copy_into_workarea`; pin it, don't assume.
- **F-Q2 (qa major-2):** LLR-030.3 scan SORTED deterministically; AT-030a selects the second file BY KNOWN FILENAME, not positional `[1]` (glob order is FS-dependent).
- **F-Q3 (qa major-3):** AT-030a producer named explicitly as `save_doc` (change-document save), NOT the save-back image writer (`app.py:1495`) — a testability trap.
- **F-Q4 (qa minor-2):** AT-030a sub-assertion — a save WHILE the patch screen is open appears in the dropdown without re-activation (R2 flake guard).
- **F-S1 (security F1, LOW):** LLR-030.3 gains the read-path containment guard — build Select from `match.name` + assert `resolved.is_relative_to(patches_dir)` (skip non-conforming / symlinks) before `service.load`. Closes the write-guarded/read-unguarded asymmetry. §6.3 R4 updated to GRANTED-after-fold; F3/F4 PASS.

**Phase-3 watch-items (not spec defects):**
- **W1 (architect MINOR-1 + qa AT-030b):** confirm the empty-folder path uses `Select(allow_blank=True)` (or equivalent) so AT-030b's "no crash" holds on an empty option set.
- **W2 (architect MINOR-2):** LLR-030.1/.2 invariant — the Select composes with an empty/placeholder option set; `set_change_files` is the only populator; a never-scanned panel renders a valid empty dropdown (guards bare-construction test `test_tui_directionb.py:3324`).
- **W3 (qa minor-1):** AT-032a asserts a KEY TOKEN SPAN (e.g. `"runs the loaded change document's checks against the loaded image"`), not the whole string (brittle) nor "a Label exists" (vacuous).

**Supersession census (architect, change-first):** `write_change_document` placement move → NO caller/test breaks (containment asserted generically). New `Select`/`set_change_files` → bare `PatchEditorPanel()` construction stays valid (empty option set). `run_checks`/`patch_checks_run_button` consumer (`app.py:1421`) untouched (US-029 changes label/description only, id+action unchanged; AT-032b guards it). `WORKAREA_PATCHES`/`set_change_files`/`ensure_patch_folder` confirmed ABSENT (net-new). 0 engine-frozen edits.
