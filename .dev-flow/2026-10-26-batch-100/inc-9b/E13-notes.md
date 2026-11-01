# E13 capture notes — scenario `ld-dialog` (Load dialog, key `p`)

Inc 9b. Captures in `evidence/inc-9b/e13/`. Scenario opens the Load dialog via
`action_load_project` (not `_route_load_project`), with project P highlighted
by default and its `firmware` variant marked `●`. Seed: project P (clean
manifest, as `pe-clean`), project Q (copy of P), and work-area temp files
`fw.s19` (CASE01) and `cal.a2l` (CASE01 `firmware.a2l`), plus one recorded
recent source (CASE02) written through `record_recent_source`. `--close` does
not apply.

Selftest: `screen: LoadDialog`, `SELFTEST OK scenario=ld-dialog close=False`.
Capture: `DONE failures=0`, 3 PNGs (PrintWindow method, not nearly-black).

LOCALAPPDATA guard: `C:/Users/jjgh8/AppData/Local/s19_app` does NOT exist
before the run and does NOT exist after it. The runner points `LOCALAPPDATA`
at `<base>/lad` (capture.ps1 does not set it), so the real store is never
touched. No `E13-*` Windows Terminal window was left open after the run.

## What each size shows

### 118×54 (side by side)
- One centered modal: `Load` title, the path field (placeholder
  `C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder`), a list, and
  a preview pane.
- Panes sit **side by side** (width 118 ≥ 100): list on the left, preview on
  the right.
- List sections, in order: **Projects** (`P`, `Q`), **Work area** (`cal.a2l`,
  `fw.s19`), **Recent** (`firmware.s19 (s19)`). P is the highlighted row.
- Preview pane shows two lines: `● variant firmware.s19` and
  `project file: ok`. The `●` marks the active variant; the `project file`
  line is unmarked.
- Names paint literally (no markup interpretation, no mojibake).
- No list row wraps. The path-field placeholder is **clipped** (single-line
  input): only `…or a` is visible, `project folder` is cut off.
- **Load (alt+l)** and **Cancel (esc)** are both visible at the bottom right.

### 220×60 (side by side)
- Same dialog, panes **side by side** (width 220 ≥ 100). The dialog is
  max-width and centered, so the app's own chrome shows around it: left
  sidebar (Workspace, A2L Explorer, MAC View, Memory Map, Issues Report,
  Patch Editor, Check Editor, A2B Diff, Flow Builder, Flow Execution,
  Checks, CRC Designer) and the status line (`Ready.`, `(none) | (none)`,
  `unload all`).
- Path field shows the **full** placeholder on one line (the wider left pane
  fits it). List sections and preview identical to 118: Projects `P` `Q`,
  Work area `cal.a2l` `fw.s19`, Recent `firmware.s19 (s19)`; preview
  `● variant firmware.s19` / `project file: ok`.
- No row wraps. **Load (alt+l)** and **Cancel (esc)** visible.

### 99×54 (stacked)
- Same dialog, panes **stacked** (width 99 < 100): list on top, preview
  below, both full width.
- List sections in order: Projects `P` `Q`, Work area `cal.a2l` `fw.s19`,
  Recent `firmware.s19 (s19)`; the path field placeholder is **full** (fits
  the full-width input).
- Preview below shows `● variant firmware.s19` and `project file: ok`.
- No row wraps. **Load (alt+l)** and **Cancel (esc)** visible.

## Defects observed (not fixed)

- **OBS-9b-1** — At 118×54 (side-by-side) the Load path-field placeholder is
  clipped mid-hint: `…or a` shows but `project folder` is cut off. Cosmetic
  hint truncation only; the field itself is unaffected and the hint is fully
  visible at 99 and 220.
