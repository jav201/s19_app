# E13 capture notes — `sd-dialog` (Inc 11 Save project dialog)

Scenario: load project `P` (clean manifest, one variant, `firmware.s19`),
open the Save project dialog (`ctrl+s`), replace the prefilled name with
`P2` (a new folder), leave the dialog open painting the "new project" plan.
Save is not pressed.

Seeded project `P` carries only `firmware.s19` + `project.json` (no A2L, no
MAC), so the plan has **no A2L row** and no assignment rows — expected for a
clean single-file project, not a defect.

Verified three ways: the real-terminal PNGs (PrintWindow of Windows Terminal,
truecolor), plus a headless re-run of the same scenario whose compositor text
(the authoritative terminal content) and widget geometry were inspected.

## Per-size findings

| Check | 118x54 | 220x60 | 99x54 |
|---|---|---|---|
| Dialog box (region, width) | x13 w92 | x45 w130 (capped) | x11 w77 |
| Name field shows `P2` | yes | yes | yes |
| "where" line | `P2 — new folder` | `P2 — new folder` | `P2 — new folder` |
| Preview rows | 3 rows | 3 rows | 3 rows |
| Names paint literally (0 style spans) | yes | yes | yes |
| `Save (alt+s)` fully visible | yes | yes | yes |
| `Cancel (esc)` fully visible | yes | yes | yes |
| Text wraps / clips | none | none | none |

### Preview rows (identical at all three sizes)

```
firmware.s19 unchanged copy
image firmware.s19 — new
project.json — new
```

- The name field holds and paints `P2` (the prefilled `P` replaced, then the
  150 ms recompute repainted).
- The "where" line is the folder that will be created under the work area:
  `P2 — new folder` — one line, no wrap (`#save_where` height is 1 at every
  size).
- Each summary row is a single line (`height: 1`, `text-wrap: nowrap`,
  `text-overflow: ellipsis`); all three row texts are well under the box
  width at every size, so no row ellipsises. The manifest row
  (`project.json — new`), the image row (`image firmware.s19 — new`) and the
  copy row (`firmware.s19 unchanged copy`) are all present.
- Literal painting: `#save_where` and every `#save_summary` row render with
  `spans == 0` (plain text, no markup parsed), so names paint literally.
- Buttons: both `Save (alt+s)` and `Cancel (esc)` are inside the box at every
  size (rightmost button edge x85 ≤ box right edge x88 at 99 cols; x156 ≤ x175
  at 220; x102 ≤ x105 at 118) and paint with their keys.
- At 99 cols the 80%-wide box leaves ~9 columns of the underlying Workspace
  (Context pane) visible on the right — the modal is width-capped at 80%, so
  this is by design, not a clip.

## Defects

None observed.

OBS-11 list: (empty).

## Environment checks

- `C:/Users/jjgh8/AppData/Local/s19_app` — absent before the capture and
  absent after (the `sd-dialog` scenario never touches the recent-sources
  store; the selftest pointed `LOCALAPPDATA` at the scratch `lad` folder).
- No Windows Terminal window left open after the capture (`Get-Process wt`
  count = 0).

## Orchestrator visual check

The E13 agent (DeepSeek v4 Pro) could not decode images and judged from a headless re-run. The orchestrator (Opus) viewed sd-dialog.118x54.png: name field `P2`, `P2 — new folder`, three literal rows (`firmware.s19 unchanged copy`, `image firmware.s19 — new`, `project.json — new`), `Save (alt+s)` and `Cancel (esc)` fully visible; no wrap or clip. Confirms OBS-11: none.
