# Functionality — Inline Variant Dropdown (US-028) — Batch 2026-07-01-batch-23

> **Audience:** technical stakeholder (engineer or reviewer familiar with the s19tui patch editor). **Purpose:** understand what shipped, how it works, and its deliberate limits.
>
> **BLUF: the patch editor's Variant pane now carries a dropdown (`Select#patch_variant_select`) that switches the project's active variant in place — no more leaving the editor for the `SelectVariantScreen` modal. The switch rides the existing activation pipeline unchanged, persists only on the next explicit project save, is inert (disabled + placeholder) when there is nothing to switch, and suppresses picks while a load is already in flight. This closes feature #8 (patch-editor overhaul).**

---

## 1. What it does

For a multi-variant project (N ≥ 2 variants), the bottom-right pane of the patch editor's 2×2 grid (`#patch_pane_variant`, created in batch-22) offers a dropdown listing every variant id in model order, preselected to the current active variant. Picking a different id:

- loads that variant's image on the worker thread (the same threaded pipeline the modal uses),
- updates the command-bar project label to `«project»:«chosen_id» (i/N)`,
- updates the rendered hex/workspace content to the chosen variant's bytes,
- re-syncs the dropdown's displayed value to the new active id.

The modal path (`SelectVariantScreen`) remains available and byte-untouched — the dropdown is an additional surface over the same mechanism, not a replacement.

## 2. How it works — pipeline reuse, in one pass

The design (Option B in 01-requirements.md §6.2) adds **zero new activation or persistence logic**. The flow, end to end: the operator's pick fires Textual's `Select.Changed`; the panel's dispatcher (`screens_directionb.py:1027`) filters the blank sentinel (`Select.NULL`) and posts a `PatchEditorPanel.VariantSelected` message (`screens_directionb.py:538`); the app handler (`on_patch_editor_panel_variant_selected`, `app.py:2366`) applies two cheap short-circuits — same-as-active (absorbs the repopulate echo pair that textual 8.2.5's `set_options` reset emits) and in-flight suppression (§5) — then routes the id **unchanged** into `_handle_select_variant` (`app.py:3134`), the pre-existing modal handler with all its guards (no variant set, unknown id, missing file). That handler stamps `_pending_variant_id`, kicks the threaded `load_from_path` pipeline, and `_apply_prepared_load` stamps the new `active_id` on completion. Finally, `update_project_labels` (`app.py:7769`) — the single funnel every variant-set mutation already passes through — refreshes both the label and the dropdown's options/value via `_refresh_patch_variant_select` (`app.py:2278`) → `PatchEditorPanel.set_variants` (`screens_directionb.py:614`). Sequence and state diagrams: `diagrams/batch-23-flows.md`.

**Key seams (current tree, re-verified at docs time):**

| Seam | Location |
|------|----------|
| Widget + row compose (always present, `disabled=True` at construction) | `s19_app/tui/screens_directionb.py:804` / `:809` |
| Message + dispatch | `screens_directionb.py:538` (VariantSelected), `:1027` (branch) |
| Options populate (`set_options` strictly before value assignment) | `screens_directionb.py:614` (`set_variants`) |
| App handler + short-circuits | `s19_app/tui/app.py:2366` |
| Reused activation pipeline (unchanged) | `app.py:3134` (`_handle_select_variant`) |
| Refresh triggers | `app.py:2278` (`_refresh_patch_variant_select`), hooked at patch-screen activation and at the `update_project_labels` tail (`app.py:7769`) |
| Race guard | `app.py:2329` (`_variant_load_in_flight`) |
| Persistence (pre-existing, sole write site) | `s19_app/tui/services/manifest_writer.py:319` |
| Layout rule | `s19_app/tui/styles.tcss:592` |

## 3. Empty / degenerate state (DoR Q1: disabled + placeholder)

The dropdown is **always present** — with no project loaded or fewer than 2 variants it is disabled with the placeholder prompt "Variants in project" and an empty option list (no single-id preselection). This was a deliberate DoR decision: no false affordance, and stable pane geometry across states (no layout jump when a project loads). The disabled invariant is co-located with population: `disabled = len(options) < 2` inside `set_variants`, and the construction default `disabled=True` holds it from first paint. Interaction in this state cannot crash or disturb loaded state (AT-035c, TC-035.5).

## 4. Persistence semantics (DoR Q2: persist-on-save)

A dropdown switch writes **nothing** to disk. It updates only the in-memory `variant_set.active_id` through the existing pipeline; `active_variant` reaches `project.json` exclusively through the pre-existing project-save serialization (`manifest_writer.py:319`, batch-16). Verified two ways: TC-035.6 asserts full byte-snapshot equality of the project directory across a switch, and the diff inspection confirms 0 new `manifest_writer` call sites vs `origin/main`. The positive chain — switch → shipped save → handler-written `project.json` carries the chosen id → an unmodified fresh load activates it — is the batch's C-12 gate (AT-035b). Consequence for the operator: a mis-click is never a persisted state change; only an explicit save records the switch.

## 5. Race guard (LLR-035.7: suppress-while-loading)

A pick that arrives while a prior variant (or plain) load is still in flight is **dropped with a status line** ("Variant switch ignored - a load is already in progress."), not queued. The guard (`_variant_load_in_flight`, `app.py:2329`) checks `_pending_variant_id` OR any unfinished `"load"`-group worker. This closes a Phase-2 security MAJOR (SEC-F2): without it, a rapid A→B pick could mislabel the rendered state and side-door a phantom variant copy into the project directory — which the next save would persist. Suppress-while-loading was chosen over generation-stamping because it leaves the shared load pipeline byte-untouched, so the modal path is demonstrably unaffected. The dropdown may briefly display the suppressed id; it self-heals when the in-flight activation's finalize re-syncs the value (tested in TC-035.7).

## 6. Geometry (C-13, measured — not estimated)

The Variant pane's content region measures **35×3 @80×24** and **46×6 @120×30** (Phase-0 Pilot probe). The variant group (Label "Active variant" + Select = 4 rows, measured at Phase 3) therefore composes **above** `#patch_execute_row`, keeping the switch affordance at the top of the pane with the Select's first row visible at scroll offset 0 at both sizes; the execute group scrolls below the fold @80×24 via batch-22's per-pane `overflow-y: auto`. One CSS rule was required (`styles.tcss:592`): `height: auto` on both groups, because a bare `Container` defaults to `height: 1fr` and would have split the 3-row pane between the two groups, clipping the Select.

## 7. What changed for the operator

1. Open the patch editor (rail item / patch screen).
2. In the **bottom-right (Variant) pane**, the "Active variant" dropdown shows all variants with the current one selected — or a disabled "Variants in project" placeholder if there is nothing to switch.
3. Pick a variant: the command-bar label flips to `«project»:«chosen» (i/N)` and the loaded image content updates. If a load is mid-flight, the pick is ignored with a status message — re-pick when it settles.
4. The switch is in-memory only. **Save the project** to record it: the next save writes `active_variant` into `project.json`, and future project loads open on that variant.

The old modal path (select-variant action) still works identically.

## 8. Assumptions, limitations, next steps

- **Assumptions:** behavior is pinned to installed textual **8.2.5** (blank sentinel `Select.NULL`; `set_options` resets selection and fires the watcher — both live-verified and version-pinned in 01-requirements §6.1 A-5).
- **Limitations (accepted by design):** in-flight picks are dropped, not queued; the pre-existing modal race window is unchanged (out of scope — the requirement was only that the modal not regress); a symlinked `.s19` in a project dir lists as a dead dropdown option that fails safely (SEC-F1, BACKLOG, pre-existing in the modal too).
- **Next steps:** regenerate the two batch-22 `patch-comfortable-*` SVG snapshot baselines in the canonical CI env (the pane tree changed; cells remain xfail-until-baseline); feature queue advances to #12 — feature #8 is closed.

**Evidence:** 11/11 new nodes green (validator re-run 2026-07-02); full non-slow suite 971 passed / 0 failed on base `f5f8111`; engine-frozen set 0-diff. Full chains: `traceability-matrix.md`.
