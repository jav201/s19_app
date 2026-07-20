# fast-dev-flow spec — Unload feature (Workspace "Loaded" panel, Variant B)

- **Date:** 2026-07-20
- **Batch:** unload-feature-workspace-panel
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** to confirm at the Phase-A gate.
- **Status:** CLOSED 2026-07-20.
- **Branch:** `claude/unload-feature-workspace-panel` off `main` `d756201` (post-#106).

---

## 1. Objective
Add the ability to **unload** a loaded artifact (S19/HEX, MAC, or A2L) — independently or all at once — via **Variant B**: a persistent **"Loaded" panel** on the Workspace rail screen that renders the three typed slots (present name+summary or dim "(none)") with a per-artifact `[u]` unload control and a `[U]` unload-all. The panel doubles as the load-status readout the app currently lacks (the gap that surfaced the Memory-Map bug). Design settled via `/prototype` (`prototypes/unload_state.NOTES.md`) + `/tui-design` (mockup, operator picked B).

## 2. State model (validated by the prototype)
`unload_primary` / `unload_mac` / `unload_a2l` each = the **inverse of the merges** (`_merge_primary_with_existing_mac` / `_merge_mac_with_existing_primary`): rebuild `current_file` clearing ONE artifact's fields and keeping the others, **carrying surviving derived loader facts forward** (`entropy_windows`, `source_s0_header`, `out_of_order_count`, `entry_point` — mirror the just-merged #106 fix). `unload_all` → `current_file = None`. `current_file` becomes `None` exactly when the last **spine** artifact is removed. **Artifact asymmetry (design clarification):** the S19/HEX image and the MAC are *spines* (they own `file_type`); the **A2L is a companion** — it is never loaded alone and has no `file_type` of its own. Rebuild rules: `unload_a2l` clears `a2l_path`/`a2l_data`, keeps the spine; `unload_mac` keeps the primary image if present (clearing `mac_*`), else (MAC-only) → `None`; `unload_primary` becomes a **MAC-only** state (`file_type="mac"`, `mac_*`+`a2l_*` kept, image fields + derived facts cleared) if a MAC is present, else → `None` (a companion A2L cannot outlive its spine, so it clears too). So MAC-only is a valid intermediate state; A2L-only is **not** (unloading the last spine clears everything). After any unload, set/clear `current_file` and re-run the post-load renderer sequence (`update_memory_map` / `update_hex_view` / `update_a2l_view` / `update_mac_view` / project labels) so every view refreshes — reaching each renderer's existing no-file empty-state branch when `current_file` is `None`.

## 3. User stories
- As an engineer, I want to remove a loaded S19/MAC/A2L without restarting, so I can swap or clear artifacts mid-session.
- As an engineer, I want to always see which of S19/MAC/A2L is loaded, so I'm never uncertain about load state.

## 4. Acceptance criteria (observable)
- **AC-1** — With S19+MAC+A2L loaded, when I unload the MAC, `current_file` **shall** retain the S19 image (`mem_map`/`ranges`) **and** `entropy_windows`, and the Memory Map **shall** still render (not "No file loaded"). MAC fields cleared.
- **AC-2** — With S19+MAC loaded, when I unload the S19/HEX, `current_file` **shall** become a MAC-only state (no image; `mem_map`/`ranges` empty; MAC fields kept) and the image views **shall** show their no-file branches while the MAC view still shows the MAC.
- **AC-3** — When I unload the last remaining artifact, `current_file` **shall** be `None` and every view **shall** show its empty state.
- **AC-4** — The Workspace "Loaded" panel **shall** render the correct present/absent slot for each of S19/MAC/A2L after every load and unload (present → name + summary; absent → dim "(none)").
- **AC-5** — Unload **shall** be reversible: after unloading an artifact, reloading the same file restores it (no residual state blocks the reload).

## 5. Out of scope
- The A2L length work (batch-56). The load flow itself (unchanged). A confirmation modal (unload is reversible — none). Variants A/C. **No engine-frozen module is touched** (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`).

## 6. Security flags
- Scanned objective + criteria + description. **No flags fire** — the feature is keybinding-driven in-memory state teardown + a status panel; no auth/secret/external/PII/DB/network path, no new file-input or form surface (it *removes* loaded state; it does not parse new input).
- **`security_required: false`.**

## 7. Plan (increments — target ≤3; promote to /dev-flow if it exceeds)
- **Inc-1 (`app.py`, ≤2 files):** the rebuild functions `unload_primary/mac/a2l/all` (pure, inverse of the merges, carrying derived facts) + the `action_unload_*` handlers/bindings (`U` unload-all; per-artifact driven by the panel) + the post-unload renderer refresh. Unit tests for the rebuild functions (mirror `test_memmap_entropy_merge.py` merge-test pattern).
- **Inc-2 (`screens_directionb.py` + `styles.tcss`):** the Workspace "Loaded" panel widget (three slots + `[u]`/`[U]` affordances, markup-safe, addr/size only — no file-derived markup sink), wired to the app's load-state; a message/handler from the panel `[u]` → the app unload action; empty-state row.
- **Inc-3 (tests):** pilot tests for AC-1..AC-5 through the shipped surface (load case_01, unload each, assert current_file state + the panel slots + the view empty-states + reload restores). New non-frozen test file `tests/test_unload_feature.py`.

## 10. Batch status
- CLOSED 2026-07-20. 3 increments; all 5 ACs green through the real loader; no security flags. Workspace snapshot drift → canonical-CI regen follow-up.

## 11. Close

**What changed.** Added an **unload** capability (Variant B). A persistent **`LoadedArtifactsPanel`** on the Workspace rail screen renders three typed slots — S19/HEX, MAC, A2L — each present (name + counts) or dim "(none)", with per-artifact `[u]` and an unload-all `[U]` (also the `U` key). It doubles as the load-status readout the app lacked. Unload is the inverse of the load merges: pure `_unload_primary/_unload_mac/_unload_a2l` rebuild `current_file` via `dataclasses.replace` (auto-carrying surviving derived facts — `entropy_windows`/`source_s0_header`/…), degrading a primary-unload to MAC-only and setting `current_file=None` when the last spine goes; A2L is a companion (can't outlive its spine). `_apply_unload(kind)` installs the rebuild and re-runs the load-path renderer set so every view refreshes (reaching its no-file branch when empty). Panel labels are `safe_text`-wrapped, counts/sizes only (no markup sink). Responsive at the 80×24 floor (caps to 2 visible slots; `U` + `[u]` stay reachable).

**How it was tested.** `tests/test_unload_feature.py` — 9 state-level unit tests (the `_unload_*` rebuild rules) + 5 pilot ACs driven through the **real** `load_selected_file` over `examples/case_01_basic_valid`: `test_ac1_unload_mac_keeps_image_and_map_through_surface`, `test_ac2_unload_primary_degrades_to_mac_only_no_image`, `test_ac3_unload_all_clears_snapshot_and_every_slot`, `test_ac4_slots_track_each_sequential_unload`, `test_ac5_reload_mac_after_unload_is_reversible`. Results: 14 passed; regression `-k "unload or loaded or memory or workspace or startup"` 39 passed; engine-frozen dual-guard 11 passed (0 frozen modules touched); ruff clean. AC-5 exercises a genuine reload through `_merge_mac_with_existing_primary`.

**Open risks / pending.** **Workspace snapshot drift** — the panel adds a persistent widget to `#screen_workspace`, drifting the `tc016s` workspace cells. The blocking `tui-ci` job skips snapshots (no `[dev]` extra); the `snapshot` job is `continue-on-error`. → a **canonical-CI snapshot-regen follow-up** (`snapshot-regen.yml`), never local. Cosmetic: a MAC-only state keeps the S19 `path` for the window title (panel labels correctly source `mac_path`).

**Security flags.** None (`security_required: false`) — in-memory state teardown + a status panel; no new input/form/external surface; file-derived names routed through `safe_text`.

**Suggested commit message.** `feat(tui): unload S19/MAC/A2L via a Workspace "Loaded" panel`
