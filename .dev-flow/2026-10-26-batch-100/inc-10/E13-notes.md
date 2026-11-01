# E13-10 — `lq-question` capture notes (Inc 10)

Scenario `lq-question` (added to `tools/e13/run.py` and the `capture_all.ps1`
plan): seed project P as a clean manifest plus `workarea/temp/fw2.s19`
(a CASE02 copy), then drive, in order:

1. load CASE01 (`firmware.s19`) through `load_from_path` and wait for it;
2. apply one Patch Editor entry through the exact widget ids and values of
   the test helper `add_and_apply` (`#patch_entry_address_input` =
   `0x8000007C`, `#patch_entry_bytes_input` = `DE AD BE EF`,
   `#patch_entry_add_button`, `#patch_doc_apply_button`) — so the image is
   patched (D true) and the panel flag is set (W true);
3. start a project load of P through `_route_load_project("P")` (the Inc 10
   guarded route);
4. wait for `ConfirmQuestionScreen`, then 0.5 s more, and stop with the
   question open, unanswered.

Drive scheduling note: the drive runs as its own `asyncio.create_task`
(`on_mount`), not through `call_after_refresh`, so the Textual message loop
stays free to dispatch the Add/Apply button presses before the question is
composed. The recent-sources store is redirected to `<base>/lad` (like
`ld-dialog`) so the real `%LOCALAPPDATA%/s19_app` is never written.

## Selftest

```
s19_app: C:\Users\jjgh8\Github\s19_app-b100-inc10\s19_app\__init__.py
screen: ConfirmQuestionScreen
status: ['Patch Editor: entry added.', 'Apply: 1 applied, 0 skipped, 0 blocked']
SELFTEST OK scenario=lq-question close=False
```

## Capture

`powershell -NoProfile -File tools/e13/capture_all.ps1 -Root . -OutDir
.dev-flow/2026-10-26-batch-100/evidence/inc-10/e13 -Only lq-question`

Result: `DONE failures=0` — 3 PNGs, no terminal window left open.

- `.dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.118x54.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.220x60.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-10/e13/lq-question.99x54.png`

## Per-size findings

Painted text (all three sizes):

- title: `Replace firmware.s19?`
- body: `There are unsaved changes in firmware.s19 and Patch Editor entries. Load project P anyway?`
- buttons: `Replace (y)` (`#confirm_yes`) and `Cancel (n)` (`#confirm_no`)

### 118×54

- Title/body naming: yes. The title names the unsaved image
  (`firmware.s19`); the body names both unsaved items (`firmware.s19` and
  `Patch Editor entries`) and the target `project P`.
- Buttons: both fully visible with their keys (`Replace (y)`,
  `Cancel (n)`), side by side on the right; each region equals its clip and
  lies inside the screen.
- Focus: on `#confirm_no` (Cancel).
- Wrap/clip: no clip. The body soft-wraps to 2 lines —
  `…Patch Editor entries. Load` / `project P anyway?` — at a clean word
  break; the title stays on one line; the buttons do not wrap.

### 220×60

- Title/body naming: yes (same painted text as above).
- Buttons: both fully visible with their keys.
- Focus: on `#confirm_no` (Cancel).
- Wrap/clip: none. The body, title and buttons each fit on one line; the
  body is a single 1-row region.

### 99×54

- Title/body naming: yes (same painted text as above).
- Buttons: both fully visible with their keys (16 columns each, fully
  inside the screen).
- Focus: on `#confirm_no` (Cancel).
- Wrap/clip: no clip. The body soft-wraps to 2 lines —
  `…and Patch Editor` / `entries. Load project P anyway?` — at a clean word
  break; the title stays on one line; the buttons do not wrap.

## OBS list

None. No defect found: the title names the unsaved image, the body names
both unsaved items and the target `project P`, both buttons are fully
visible with their keys at every size, the focus starts on Cancel, and no
text clips. The two-line body at 118×54 and 99×54 is the designed soft-wrap
(the body stays fully visible; word breaks are clean).

## `%LOCALAPPDATA%/s19_app` check

`C:/Users/jjgh8/AppData/Local/s19_app` did not exist before the run and
does not exist after the selftest and the capture (the recent-sources store
is redirected to the scratch `<base>/lad` for this scenario).
