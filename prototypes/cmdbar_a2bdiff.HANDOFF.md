# HANDOFF — command-bar deletion · A2B diff master–detail · operations staged removal

**Date:** 2026-08-06 · **From:** design session (tui-design + runnable in-app prototype) ·
**To:** a fresh agent running the full `/dev-flow` V-model in `C:\Users\jjgh8\Github\s19_app`.
**Operator decisions (2026-08-06):** three verdicts, all resolved — see §2. Two independent lanes;
**suggested split: batch N = UI lane (S-1..S-9), batch N+1 = operations lane (S-10..S-13)** —
Phase 0 may re-split, but S-13 (deletion) MUST land after S-10..S-12 (migration) is merged and green.

This file is the batch charter INPUT. It is not a spec — Phase 1 owns the requirements, LLRs and
acceptances. Everything here is re-derivable; **re-derive it, don't copy it** (a carried number is
re-derived, not copied; an unstated grep pattern is an unstated definition).

---

## 1 · What was decided, and why

Full evidence, real Textual 8.2.8 captures (baseline + 3 variants × 2 areas), decision tables and
the operations premise check:

- `prototypes/cmdbar_a2bdiff.prototype.html` — the board (self-contained, captures embedded).
- `prototypes/cmdbar_a2bdiff.tui_prototype.py` — runnable in-app prototype (sub-shape A: patches
  `CommandBar` / `AbDiffPanel` on the real `S19TuiApp`; diff runs from the real `diff_mem_maps`,
  windows from the real `render_hex_view_text`). **Scratch quality; NOT implementation code.**
- `prototypes/cmdbar_a2bdiff.NOTES.md` — findings + verdicts.
- Captures: `cmdbar_{baseline,variant_A,variant_B,variant_C}.120w.svg`,
  `abdiff_{baseline,variant_A,variant_B,variant_C}.132w.svg`.

Repo state at handoff: `origin/main` @ `061a97e`. All handoff files are **untracked** — commit them
in the first batch's PR (the `legend_n8.*` / `memmap_variant_a.*` precedent).

Key code facts (verify at Phase 0, they are premises not axioms):

- The command bar's `#find_input` / `#cmdbar_goto_input` (`command_bar.py:139-149`) are **pure
  duplicates**: the workspace hex pane owns `#search_input`/`#goto_input` + buttons
  (`app.py:1992-1998` → `_handle_search`/`_handle_goto`, `app.py:11358/11448/11518`), A2L owns
  `alt_*` (`app.py:5151-5156`), MAC owns `mac_*` (`app.py:5229-5234`); the bar's find explicitly
  "calls `_handle_search` unchanged" (`app.py:6010-6023`). `/`·`g` focus the BAR inputs today
  (`action_focus_find/goto`, `app.py:5980/5984`). The bar also hosts the **Ctrl+K palette**
  (`#command_palette`) and the Project/A2L labels (`set_context_labels`, updated at `app.py:11351`).
- A2B diff (`screens_directionb.py:6716-7034`): `#diff_range_list` is a `Static`; only
  `_render_run_windows(0)` is ever called (runs 1..N unreachable — the docstring cites an
  `on_data_table_row_selected` handler that does not exist); `DISPLAY_CONTEXT_BYTES = 16`;
  `#diff_columns` = three rigid `1fr` columns that wrap hex rows unreadably.
- Operations modal (`x`, `screens.py:1845`): registry = `crc` + placeholders `extract` /
  `split_by_segment` (no I/O). The CRC op is `crc32_stream` (`operations/crc.py:41,82`): **CRC-32,
  poly `0x04C11DB7`, init `0xFFFFFFFF`, `reverse` (COUPLED refin+refout), final_xor `0xFFFFFFFF`**;
  config schema = `crc_config.py` (regions/groups, per-region `output_address`, `output_bytes`
  1/2/4/8 LE). The CRC Designer is preview-only (US-V6, `crc_designer_view.py:56`) and its kernel
  (`crc_kernel.py`) is the width-general Rocksoft model with INDEPENDENT refin/refout — the known
  algorithm is expressible as refin=refout=reverse. The modal's **Write CRC** is today the only
  interactive CRC-inject path (Flow Builder covers it only via flow + config file).

**Measured width ceiling** (this box, textual==8.2.8 — re-derive if challenged): a full hex+ASCII
row is 81 cells. With the 24-col rail: diff variant A (22-col list + full-width stacked windows) is
clean at ≥ ~130 cols and its ascii gutter wraps at 120; the shipped 3-column diff wraps below ~170.

## 2 · Scope (operator-approved)

### Lane 1 — command bar deletion (operator: "we don't need these, get rid of them")

| # | Item | Core of it |
|---|------|-----------|
| S-1 | Delete the bar row | `#command_bar_row` (prompt, Project/A2L labels, find/goto inputs) removed on every screen; ~3 rows reclaimed app-wide. The `CommandBar` widget may survive as a palette-only shell or the palette moves to its own overlay — Phase 1 decides the shape; **Ctrl+K must keep working on every screen**. |
| S-2 | Re-home `/`·`g` | They focus the ACTIVE screen's local inputs (workspace `#search_input`/`#goto_input`, A2L `alt_*`, MAC `mac_*`). On screens with no local find/goto: one status-line notice, no crash. `Esc` from a focused input returns focus to the pane (keyboard path stays closed-loop). |
| S-3 | Re-home context labels | Project/A2L names surface in the Loaded panel (`_refresh_loaded_panel`); all `set_context_labels` callers rerouted; the update path gets a discriminating test (not a vacuous "label exists"). |
| S-4 | Delete the dead surface | Bar CSS (`styles.tcss:55-102`), `CommandBar.Find/Goto` messages + `on_command_bar_find/goto` adapters + `focus_find/goto`, and any palette entries referencing them. Workspace/A2L/MAC search handlers are **untouched** (control: their behavior is byte-identical). |

### Lane 2 — A2B diff master–detail (operator: variant A; accessibility of information is first-class)

| # | Item | Core of it |
|---|------|-----------|
| S-5 | Selectable run list | `#diff_range_list` Static → `ListView`: EVERY run selectable by ↑↓ / `j`/`k` / mouse click / `n`/`p` next-prev; focus visibly highlighted; list scrolls past the viewport. Display caps (G-9, `DISPLAY_MAX_RUNS`/`DISPLAY_MAX_TOTAL_BYTES`) and the "showing N of M" notice preserved; the persisted report stays complete. |
| S-6 | Windows follow selection | Selection re-renders both windows (prototype proved this path live). Stacked full-width windows; context rows derived from pane height at render/resize time — NOT a constant (`DISPLAY_CONTEXT_BYTES` retires or becomes the floor). Run header carries index + range + kind; windows scrollable/pageable beyond the rendered rows. |
| S-7 | Width regimes | ≥ ~130 cols: 22-col list + full-width windows (the 132×44 capture). **120-col fallback required** — options measured: 12-col list (index+offset), list-as-overlay (`o`), or auto-stack list above windows; Phase 1 picks one, mirroring the `width-narrow` two-regime precedent (LLR-007.1). No wrapped hex row in either regime. |
| S-8 | Compact selection rows | The A/B selection + action rows condense to one line each (Input/Button/Select default to 3 rows and starve the results area — visible in the baseline capture). Compare/Report handlers unchanged. |
| S-9 | Discoverability | The keyboard path (j/k, n/p, click) surfaces in the Footer + `?` keymap (three-tier rule). Optional, Phase 1 decides in/out — do not silently absorb: Enter on a run posts an open-in-hex message (the memmap S-5 `OpenInHexRequested` precedent). |

### Lane 3 — operations staged removal (operator-refined 2026-08-06)

| # | Item | Core of it |
|---|------|-----------|
| S-10 | Known algorithm as a saved Designer config | The modal's CRC is a KNOWN algorithm. Encode it as a saved CRC Designer `.crc.json` in the template library: width 32, poly `0x04C11DB7`, init `0xFFFFFFFF`, refin=refout=true (maps the op's coupled `reverse`), xorout `0xFFFFFFFF`, plus the coverage/serialization carried over from the op-config model. **Open decision Phase 1 owns:** op configs allow MULTIPLE regions/groups with per-region output addresses; Designer serialization is single-output — per-region template files vs a model extension. Do not silently pick. |
| S-11 | Designer executes | The Designer gains an execute/apply-to-image path for a loaded config — this is the FIRST firmware write the Designer performs (amends US-V6 preview-only: **requirement amendment with explicit Before/After**, operator rule). It inherits the modal's verify-after-write + dispatch-token + bounded-write guards. |
| S-12 | Equivalence by test, not by UI | **NO dedicated check/KAT surface in the Designer for this** (operator ruling). The proof is the batch's test pass: on a fixture image, Designer execution of the saved config produces output **byte-identical** to the modal op's check+Write CRC path. Once fully tested, the leverage is known-correct. |
| S-13 | Delete (second increment, gated on S-10..S-12 merged) | `OperationsScreen`, the `x` binding, placeholder ops (`extract`, `split_by_segment`), their registry entries, palette entry, dead tests. CRC write remains reachable via Designer + Flow Builder. |

**Out of scope:** diff variants B/C (C additionally needs ~190 cols or an 8-byte row mode
`render_hex_view_text` doesn't have — register as backlog candidates, do not build). The deferred
`wire-kernel-into-crc.py` item (Designer kernel → `crc` op) intersects S-10..S-12 — Phase 1 states
its relationship explicitly (supersedes / defers / absorbs) rather than silently absorbing it.
CC-1 (per-arm counterfactual encoding) stays owed to the operator, unrelated.

## 3 · Invariants that must survive (verified against origin/main @ 061a97e)

- **C-17 markup safety:** any file/variant-derived text reaching a markup-enabled surface goes
  through `safe_text`; hex windows render `markup=False`.
- **Panel is presentational:** the diff panel classifies nothing — runs come from
  `compare_service`/`diff_mem_maps` only; report content from `diff_report_service` only.
- **Display caps bound the PANEL, never the report** (G-9).
- **Snapshot goldens regenerate only in canonical CI** (textual==8.2.8 pin; local regen drifts
  unrelated baselines). `tui-ci` runs `-m "not slow"` on PRs — run the FULL suite before merge and
  state which form produced any ledger figure.
- **Textual internal-name shadowing:** no `_nodes`/`_context` members on new widgets.
- **`styles.tcss` id selectors beat subclass `DEFAULT_CSS` on shared ids** (re-hit in this
  prototype) — new widget styling either owns new ids or edits `styles.tcss` directly.
- **Bounded writes:** S-11's file write is bounded and name-sanitized like the template-save path;
  no unbounded read of external images beyond the existing loaders.
- **AT/TC registry:** new ATs/TCs pass the G1–G7 guard (`AT-TC-REGISTRY.jsonl`).
- The `x` key becomes FREE after S-13 — do not rebind it in the same batch; register the free key
  in the backlog instead.

## 4 · Expected footprint

Lane 1: `command_bar.py`, `app.py` (compose, actions, adapters, `set_context_labels` call sites,
palette entries), `styles.tcss`, `test_tui_directionb.py`/command-bar tests, snapshots.
Lane 2: `screens_directionb.py` (`AbDiffPanel`), `styles.tcss`, diff tests, snapshots.
Lane 3: `crc_designer_view.py`, `operations/` (registry, crc glue; S-13 deletes `placeholders.py`),
`screens.py` (S-13 deletes `OperationsScreen`), template library dir, tests
(`test_operations.py`, designer tests), `AT-TC-REGISTRY.jsonl`.
Snapshot drift is expected in all lanes — CI-only regen.

## 5 · Draft acceptances (WHATs only — Phase 1 must re-derive and own these)

1. No screen shows the command-bar row; Ctrl+K opens the palette on every screen (control:
   palette command set unchanged).
2. `/` on the workspace focuses `#search_input`; `g` focuses `#goto_input`; A2L and MAC route to
   their locals; a screen with no local find/goto yields one status notice and no crash.
3. Project/A2L names appear in the Loaded panel after load/select; the test discriminates a real
   update (fails when the update call is removed — counterfactual on the ASSERTION, substituted
   VALUE recorded).
4. Workspace/A2L/MAC search + goto behavior is byte-identical to pre-change (the control).
5. Diff: with a multi-run comparison, EVERY run is reachable keyboard-only AND mouse-only; the
   selected run is visibly highlighted; runs beyond the viewport reachable by scrolling.
6. Selecting a run re-renders both windows to that run; at two different pane heights the window
   row count differs (proves height-derived context; kills the ±16 constant).
7. At 132×44 no hex row wraps; at 120 the fallback regime engages and no hex row wraps.
8. A comparison exceeding the display caps shows the cap notice; the persisted report is complete.
9. The template library contains the known-algorithm `.crc.json`; the Designer loads and EXECUTES
   it against a loaded fixture image; the written image is byte-identical to the Operations modal's
   check+Write CRC output on the same fixture (the equivalence oracle — this test exists BEFORE
   S-13 deletes the modal, then survives as the Designer-vs-`crc32_stream` oracle).
10. S-11's write path refuses cleanly (no partial file) on verify-mismatch, and a stale dispatch
    cannot repaint the surface (token guard inherited).
11. After S-13: `x` is unbound, `OperationsScreen` and placeholder ops are gone from code, registry
    and palette; the Designer execute path and Flow Builder CRC block still pass their suites.
12. No new AT is vacuous: every counterfactual fails on its ASSERTION with the substituted VALUE
    recorded (C-43 premise evaluation applies to the acceptances themselves).

## 6 · Process requirements for the executing session (operator-set, non-negotiable)

- **Ask the approval model at kickoff** — standing auth is per-batch, never carried.
- **Phase 0:** verify flow currency (`~/.claude/docs/FLOW-VERSION.md`, RC-1 hook); read the lane
  file `.dev-flow/BACKLOG-CODE.md` and register these items; **derive the next free batch number
  from disk + origin branches, not from memory** (two numbering collisions already happened);
  re-read `state.json` immediately before any edit — single-batch, last-writer-wins hazard.
- **Premise evaluation at every gate** (C-43) — including this handoff's §1 claims. The dominant
  defect class in this project is the **vacuous check, concentrated in specs/acceptances, not
  code** (batch-76: 14 defects, zero in shipped code). Consult `/dev-flow-lessons` before writing
  acceptances.
- The S-11 US-V6 amendment ships with an explicit Before/After block (operator rule).
- Decisions as option tables (✅❌⚠️), inline-paste evidence at gates, review packet per increment,
  backlog reconciliation at close, vault sync after merge (`/dev-flow-sync`).
- Commit the `prototypes/cmdbar_a2bdiff.*` set in the first batch's PR; delete it in the close-out
  of the LAST batch of this charter once verdicts are folded into requirements.

## 7 · Suggested skills for the executing session

`/dev-flow` (each batch) · `/dev-flow-lessons` (before acceptances) · `review-packet` (per
increment) · `tui-design` (only if a visual question reopens — the width-regime pick in S-7) ·
`/dev-flow-sync` (after each merge).
