# fast-dev-flow spec — JSON editor fills its window height

- **Status:** Phase C (implemented; gates green; AC-1 size RATIFIED)
- **⚠ AC-1 observation-size RATIFICATION (orchestrator, 2026-07-18, C-23/C-29 measurement correction):** the
  approved AC-1 said "at **120×30** → editor `region.height` > 8". PILOT-MEASURED, that is **unsatisfiable**:
  at a 30-row terminal the global `#workspace_shell` reserves the lower rows, so `#patch_editor_panel` maxes
  at ~13 rows and the JSON window body at ~9 — the editor is capped at 8 by *available room*, not by CSS
  (measured: 120×30 → 8, 120×50 → **26**, 80×24 → 8). The empty-space defect the operator reported manifests
  only at ≥~34 rows (the operator's screenshot was a tall terminal). **Ratified correction:** the growth arm
  observes at **120×50** (where free space exists and the mutation discriminates: flip to `height: 8` → RED);
  a **floor/no-regression arm stays at 120×30**. The shipped fix is unchanged and correct — it fills the
  window whenever room exists, which is exactly the operator's terminal. No scope change; a test-size
  correction the agent surfaced by measuring rather than assuming (this is why C-23 exists).
- **Date:** 2026-07-18
- **Branch:** `fix/patch-json-editor-fill-height` (off `main` `7440108`; RC-1 clean — branched from origin/main tip)
- **Route:** /fast-dev-flow (small, scoped UI/layout fix)
- **Language:** English
- **Run mode / merge:** TBD at Phase-A gate (per-batch authorization; batch-48's grant does NOT carry).
- **security_required:** FALSE (layout-only; see §6 — one C-17 preservation watch-item folded into AC-4).

## 1. Objective (BLUF)
The Patch Editor's JSON editor (`#patch_paste_text`, a `JsonHighlightTextArea`) is pinned to a
**fixed `height: 8`** (`styles.tcss:1239`), so it shows a scrollbar and leaves the rest of the
`#patch_win_json` window empty below it (operator screenshot). Make the editor **flex to fill the window's
available vertical space** at both terminal sizes, instead of the fixed 8-row cap.

## 2. Root cause (recon-verified)
`.patch-window-body { height: auto }` (`:891`, shared by all 3 windows) hugs its content at the top of a
taller window; `#patch_paste_row` has no height rule (auto); `#patch_paste_text { height: 8 }` is a fixed
cap. Chain: `#patch_win_json` (tall) → `#patch_win_json_body` (auto) → `#patch_paste_row` (auto) →
`#patch_paste_text` (8). Nothing in the chain claims the leftover space. `height: 1fr` is the established
idiom here (12 existing uses, incl. every other window body's main content).
**History:** the fixed `height: 8` was an intentional batch-36 (F-01) compromise; the full-screen
`#changeset_json_dialog` modal (`height: 90%`, opened by "Edit JSON") was created as the escape hatch for a
"readable multi-line editor the height-starved in-panel box cannot give." This batch makes the in-panel box
use its own space; the modal stays as-is.

## 3. Scope
**IN:** the JSON editor fills its window body's available height, scoped to the JSON window only. Expected
fix = a small set of `1fr` height rules on the JSON window's own body/row/editor in `styles.tcss`
(CSS-only if possible; pilot-measured), with a `min-height` floor so it stays usable at the 80×24 floor.
**OUT (do NOT touch):**
- The `#changeset_json_dialog` modal (batch-36/64b escape hatch) — unchanged.
- The other two windows (`#patch_win_script`, `#patch_win_checks`) and the shared `.patch-window-body`
  rule — the change must be JSON-window-scoped, not app-wide (C-30 sibling).
- Any behaviour/wiring: paste ingress, the cap gauge, the C-17 `_render_line` colouring path of
  `JsonHighlightTextArea` (`json_highlight.py`), the 64 KiB cap. **Layout-only.**
- The docked buttons (`#patch_paste_controls`) must stay reachable-under-scroll (no B2 regression).

## 4. Observable acceptance criteria
- **AC-1 (fills at 120×30):** When the Patch Editor is shown at 120×30, `#patch_paste_text`'s rendered
  `region.height` is **> 8** (grows past the old fixed cap to consume the JSON window's free space);
  MEASURED, not asserted against a CSS constant (C-32 assert-the-painted-result).
- **AC-2 (fills at 80×24, no overflow):** When shown at 80×24, `#patch_paste_text` fills the JSON window
  body's available height and does **not** push `#patch_paste_controls` below reachability — the docked
  buttons resolve reachable-under-scroll (reuse the batch-46 B2 contract). A HIGH if B2 recurs.
- **AC-3 (JSON-window-scoped):** `#patch_win_script` (entries table) and `#patch_win_checks` content
  heights are **unchanged** by this change (the fix does not touch the shared body rule) — measured at
  both sizes.
- **AC-4 (C-17 preserved):** After the resize, a hostile pasted payload (`[red]PWNED[/red]`, `[/nope]`)
  still renders literally via `_render_line` — no markup parse, no style leak (the batch-48 AT-079c
  contract holds; layout must not alter the paint path).
- **AC-5 (gauge intact):** The cap gauge (`#patch_paste_gauge`) still renders above the editor; the
  editor's growth does not displace or overlap it.

## 5. Test mapping (each AC → a named test; C-29 geometry via `App.run_test(size=…)`)
- AC-1/AC-2 → a new geometry test in `tests/test_tui_patch_json.py`, driving the panel at both sizes and
  asserting `#patch_paste_text.region.height` + docked-row reachability (C-32: measure the region).
- AC-3 → assert the other two windows' body heights unchanged (measured, both sizes).
- AC-4 → reuse/extend the existing AT-079c hostile-input assertion post-resize (do NOT weaken it).
- AC-5 → assert `#patch_paste_gauge` present + above the editor.
- Coverage-claim discipline: each named test confirmed on disk before Phase-C sign-off.

## 6. Security flags
Scanned: matches on **`user input` / `paste` / `escape`** — the JSON editor is a known **untrusted-input
sink** (C-17). BUT this change is **layout-only (CSS height)**: no new input surface, no new markup path,
no touch to `JsonHighlightTextArea._render_line`. → **`security_required: false`**, with one watch-item
folded into **AC-4**: the resize must preserve the existing C-17 painted-path contract (verified by
re-running the hostile-input assertion post-resize, not a full security review). **If Phase B finds it must
touch the render/paint path, STOP and re-flag.**

## 7. Snapshot impact (C-22, stack-specific)
The JSON window is in the 2 patch scaffold snapshot cells (`patch-comfortable-{80x24,120x30}`), **just
regenerated by PR #89**. Resizing the editor **will drift both cells again** → a **canonical-CI regen is
owed as a post-merge follow-up** (local regen FORBIDDEN; mark the 2 cells `xfail(strict=False)` for the
PR via a `_fdf_json_height_drift_marks`-style helper, retire on regen — the established pattern).

## 8. Increment plan (≤5 files; likely 1 increment)
1. **Inc-1 (AC-1..5):** `s19_app/tui/styles.tcss` (the JSON-window-scoped `1fr` rules + `min-height` floor)
   · `tests/test_tui_patch_json.py` (geometry + scope + gauge tests) · `tests/test_tui_snapshot.py` (the
   2-cell xfail drift marks) · possibly `s19_app/tui/screens_directionb.py` (only if a container needs an
   explicit height for `1fr` to cascade — pilot-measure first; prefer CSS-only). ≤4 files.

## 9. Batch status
| Field | Value |
|-------|-------|
| Current phase | A (awaiting gate) |
| Started | 2026-07-18 |
| Route | /fast-dev-flow |
| Promoted to /dev-flow | no |
