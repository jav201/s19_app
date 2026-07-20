# fast-dev-flow spec — Memory Map "No file loaded" when S19+MAC coexist

- **Date:** 2026-07-20
- **Batch:** fix-memmap-entropy-merge
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** to confirm at the Phase-A gate (default: operator merges). Surface any HIGH finding / scope creep.
- **Status:** CLOSED 2026-07-20.
- **Branch:** `claude/fix-memmap-entropy-merge` off `main` `1cc5683`.

---

## 1. Objective
Fix a real bug: the **Memory Map view shows "No file loaded" even though an S19/HEX is loaded**, whenever a **MAC coexists** with the primary image. Restore the map (and, defensively, stop the empty state from ever mislabelling a loaded image as "no file").

## 2. Root cause (diagnosed + reproduced)
- `LoadedFile.entropy_windows` (added batch-45, PR #81) is a **derived loader fact**, computed at load in `load_service` and consumed by the Memory Map: `MemoryMapPanel.render_ranges` (`s19_app/tui/screens_directionb.py:1452`) shows `_EMPTY_TEXT = "No file loaded - press Ctrl+L…"` when `not entropy_windows`.
- When an S19/HEX + MAC **coexist**, the app rebuilds `LoadedFile` via `_merge_primary_with_existing_mac` (`app.py:7652`) and `_merge_mac_with_existing_primary` (`app.py:7699`). Both explicitly carry `out_of_order_count` + `entry_point` forward as "derived loader facts" **but omit `entropy_windows`** → it resets to its empty default → the map falsely shows "No file loaded".
- **Not introduced by the recent A2L batches.** batch-45 added the field + the dependency without updating the two merge constructors (a missed writer-site).
- **Reproduced:** `examples/case_01_basic_valid/` (firmware.s19 + firmware.mac + firmware.a2l). A pure S19 (no MAC) works — it returns the `load_service`-built payload with `entropy_windows` intact.

## 3. User stories
- As an engineer, when I load an S19 alongside a MAC, I want the Memory Map to render the actual map (not "No file loaded"), so I can see coverage.
- As a maintainer, I want the empty-state message to distinguish "no file loaded" from "loaded but no entropy data", so a display gap never masquerades as an unloaded file.

## 4. Acceptance criteria (observable)
- **AC-1** — When an S19/HEX primary and a MAC are merged (either order), the resulting `LoadedFile.entropy_windows` **shall equal the surviving primary image's** `entropy_windows` (non-empty for a non-empty image), not the empty default. *(Verified against both `_merge_primary_with_existing_mac` and `_merge_mac_with_existing_primary`.)*
- **AC-2** — When an S19/HEX + MAC coexist, `MemoryMapPanel.render_ranges` fed the merged payload **shall render the band view** (header ≠ `_EMPTY_TEXT`), i.e. the map is drawn.
- **AC-3** — When `render_ranges` is given non-empty `ranges` but empty `entropy_windows`, its empty-state header **shall NOT read "No file loaded"** — it shall show a distinct "no entropy/coverage detail" message, reserving the "No file loaded" text for the genuinely-no-image case (`not ranges`).
- **AC-4 (regression)** — A pure S19 load (no MAC) **shall** still render the map unchanged (no behavior change on the non-coexistence path).

## 5. Out of scope
- The unload feature (separate design/batch). The A2L length work (batch-56). Any entropy recomputation change (`compute_entropy` is unchanged — the fix only carries the already-computed windows forward). No engine-frozen module is touched (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`).

## 6. Security flags
- Scanned objective + criteria + description for sensitive patterns (auth / secrets / external integrations / PII / destructive DB / input surface / network exposure).
- **No flags fire.** The change is an in-memory carry-forward of an already-computed field + a UI string; it adds no input surface, no external call, no secret/auth/PII/DB/network path. Parsing is untouched.
- **`security_required: false`.**

## 7. Plan (increments)
- **Inc-1 (1 file):** `app.py` — carry `entropy_windows` forward in both merge constructors (7652 → `primary_loaded.entropy_windows`; 7699 → `existing.entropy_windows`). *(Consider whether other derived fields are also missed — quick audit of the merge kwargs vs LoadedFile derived fields.)*
- **Inc-2 (1-2 files):** `screens_directionb.py` — split the `render_ranges` empty branch: `not ranges` → "No file loaded"; `ranges but not entropy_windows` → a distinct "no entropy detail" message (still draws the coverage stats strip). + a regression test in a NON-frozen test file (S19+MAC merge preserves `entropy_windows`; render draws the map; loaded-but-no-entropy ≠ "No file loaded").

## 10. Batch status
- CLOSED 2026-07-20. All 4 ACs covered + green; no regressions; no security flags.

## 11. Close

**What changed.** The S19+MAC merge constructors (`_merge_primary_with_existing_mac`, `_merge_mac_with_existing_primary` in `app.py`) now carry the primary image's derived loader facts `entropy_windows` **and** `source_s0_header` forward — they were previously dropped, resetting `entropy_windows` to `[]` and making the Memory Map falsely report "No file loaded" whenever an S19/HEX coexisted with a MAC. A quick audit found `source_s0_header` was dropped by the same omission (latent S0-header loss on coexistence) and is now carried too. Defensively, `MemoryMapPanel.render_ranges` splits its empty state: `not ranges` → "No file loaded"; ranges-present-but-no-entropy → a distinct `_NO_ENTROPY_TEXT` note with the real coverage stats — so a loaded image can never be mislabelled "No file loaded" again.

**How it was tested.** `tests/test_memmap_entropy_merge.py` (4 tests): `test_merge_primary_with_existing_mac_carries_entropy_and_s0` + `test_merge_mac_with_existing_primary_carries_entropy_and_s0` (AC-1, both merges), `test_memory_map_renders_when_s19_and_mac_coexist` (AC-2, through `update_memory_map`), `test_render_ranges_loaded_no_entropy_not_labelled_no_file` (AC-3). All 4 pass. Regression: `test_tui_app.py -k "merge or memory or mac"` 23 passed; `test_tui_directionb.py -k "memory or map or entropy or band"` 22 passed; engine-frozen dual-guard 11 passed (0 frozen files touched); ruff clean. Reproduced originally with `examples/case_01_basic_valid` (s19+mac+a2l).

**Open risks / pending.** None. Full suite runs in CI on the PR.

**Security flags.** None fired (`security_required: false`) — in-memory carry-forward + a UI string; no new input surface, external call, or secret/auth/PII/DB/network path.

**Suggested commit message.** `fix(tui): carry entropy_windows + source_s0_header through the S19+MAC merge`
