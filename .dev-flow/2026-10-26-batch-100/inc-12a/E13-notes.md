# E13 notes — bz-busy capture scenario (Inc 12a)

## Scope

Added one E13 capture scenario, `bz-busy`, that loads CASE01's firmware from
`workarea/temp/fw.s19` with the file-load worker's parse step slowed ~60 s
(patched in `tools/e13/run.py` only — `s19_app/` is never edited). The capture
stops on the `step 2/3 Parse` progress line while the load is still running,
so the spinner glyph and the elapsed time keep advancing.

## Selftest (118x54)

```
s19_app: C:\Users\jjgh8\Github\s19_app-b100-inc12a\s19_app\__init__.py
screen: Screen
status: []
status_text: ⠴ Loading fw.s19  ·  step 2/3 Parse  ·  00:02
SELFTEST OK scenario=bz-busy close=False
```

The selftest printed the screen name and the current `#status_text` value,
which contains `step `. Because the slowed worker was still sleeping (~60 s)
on its worker thread, the selftest ends the process explicitly after printing.

## Capture result

```
powershell -NoProfile -File tools/e13/capture_all.ps1 -Root . -OutDir .dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13 -Only bz-busy
```

```
CAPTURED ...\e13\bz-busy.118x54.png  1724x1608px  grid=118x54  method=PrintWindow  bytes=77564
CAPTURED ...\e13\bz-busy.220x60.png  3152x1776px  grid=220x60  method=PrintWindow  bytes=112551
CAPTURED ...\e13\bz-busy.99x54.png   1458x1608px  grid=99x54   method=PrintWindow  bytes=75562
DONE failures=0
```

PNG paths:

- `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.118x54.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.220x60.png`
- `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/e13/bz-busy.99x54.png`

## Headless re-runs per size

These values come from a headless re-run (`app.run_test`) at each size, read
off the compositor — not off the PNGs.

### 118x54

- `#status_text`: `⠴ Loading fw.s19  ·  step 2/3 Parse  ·  00:02`
- `#progress_bar`: `33 / 100`
- log lines: `[]` (no completed-action log line yet — the load is still running)
- key bar row 0: `^k Palette  ^d Density  ^l Load  ^s Save project  x Operations  ? Help  q Quit  ^p palette`
- key bar row 1: `Workspace  / Find  g Go-to  , Hex-  . Hex+  k Legend  p Projects  o Open workarea  r Refresh workarea  ? more`
- key bar says `Load` (in `^l Load`); no row says `Load file`.

### 220x60

- `#status_text`: `⠴ Loading fw.s19  ·  step 2/3 Parse  ·  00:02`
- `#progress_bar`: `33 / 100`
- log lines: `[]`
- key bar row 0: `^k Palette  ^d Density  ^l Load  ^s Save project  x Operations  ? Help  q Quit  ^p palette`
- key bar row 1: `Workspace  / Find  g Go-to  , Hex-  . Hex+  k Legend  p Projects  o Open workarea  r Refresh workarea  U Unload all`
- key bar says `Load` (in `^l Load`); no row says `Load file`.

### 99x54

- `#status_text`: `⠴ Loading fw.s19  ·  step 2/3 Parse  ·  00:02`
- `#progress_bar`: `33 / 100`
- log lines: `[]`
- key bar row 0: `^k Palette  ^d Density  ^l Load  ^s Save project  x Operations  ? Help  q Quit  ^p palette`
- key bar row 1: `Workspace  / Find  g Go-to  , Hex-  . Hex+  k Legend  p Projects  o Open workarea  ? more`
- key bar says `Load` (in `^l Load`); no row says `Load file`.

## PNG viewing

The three PNGs were not viewed by me (no image view available); the per-size
observations above are from headless re-runs at the same sizes.

## Defects

No defects observed. OBS list: none.

## Orchestrator visual check

The E13 agent (DeepSeek v4 Pro) could not decode images. The orchestrator (Opus) viewed bz-busy.118x54.png: `#status_text` paints `<glyph> Loading fw.s19  ·  step 2/3 Parse  ·  00:06`; the bar is at 33%; the key bar reads `^l Load` and `p Projects`. Labels and progress line match the design.

- **OBS-12a-1 (orchestrator):** the progress bar still shows Textual's built-in ETA readout (`33% 00:00:01`) beside the seam's elapsed time (`00:06`); during a 60 s parse the ETA claims 1 s remain. Two contradictory times on one row. Fix: `show_eta=False` on `#progress_bar` (or hide the ETA column). Route: Inc 12b integration (it owns the parse-progress half) or the batch-end fix round.
