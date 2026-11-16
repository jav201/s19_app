# Inc 9b E4 — pilots (P9b, E4 prep)

Batch `2026-11-05-batch-103`, increment 9b, E4 prep worker P9b, model Opus (claude-opus-5-5), orchestrator relevo-16. Card: SKILL.md § E2 (layered extraction) and § E4 (pilots first); `E1-slice.md` §4.

**Tree:** a fresh clone of the merged base `e4485817` (`b103-inc9b` = E2 `3daea03d` + Inc 8b `103a72df`), runner rtx under `~/work/zq-p9b/` (never `/tmp`), HT-02 env (HOME basename `<runner-home>`), `-n 0`, `timeout 300` per run, Textual 8.2.8. Every transcript starts with `uptime`, the head sha and `s19_app.__file__` (`~/work/zq-p9b/tree/s19_app/__init__.py`). 1-minute load 0.33–0.95 for every run (quiet, HT-08). Driver `evidence-e4/pilots/p9b-run.sh`; probe `evidence-e4/pilots/test_p9b_pilots.py` (copied into the scratch clone's `tests/` only, never into the repository's); reader `p9b_summary.py` → `out/summary.txt`. Transcripts `out/*.txt` (sanitized: `~`, `<user>`, `<runner-home>`, `<host>`).

## Decisions the pilots fix

| Pilot | Question | Result | Decision |
|---|---|---|---|
| §4.1 / P1 | Does a tick and a key run, and the screen paint, between two refresh steps? | `call_after_refresh`: gap 1→2 is 7–13 ms, **0 paints and no key in 6/6 runs** (`after_refresh` and `after_refresh_tick`, 3 each); the key sent 0.05 s into step 1 is handled after step 3 ends. `set_timer(0, …)`: **the chain stops after step 1** in 3/3 (Textual's `Timer._run` divides by the zero interval; `ZeroDivisionError` in `out/p1-run1.txt`). `set_timer(0.02, …)`: gap ~0.08 s, 1 tick, the key still waits for the chain's end (3/3). `set_timer(0.1, …)`: gap 0.19–0.33 s, the key handled between steps 1 and 2 (key at 0.799 / 0.799 / 0.823 s after steps ending at 0.704 / 0.705 / 0.728) and ≥ 1 paint with a new title in every gap (3/3). | **Chain the steps with `set_timer(STEP_GAP_S, …)`, STEP_GAP_S = 0.1 s** (F-9b-4). Never `call_after_refresh`, never `set_timer(0, …)`. |
| §4.2 / P2 | After the inline busy border, which clear returns the stylesheet's border and the `:focus-within` accent? | (A) `clear_rule("border")` → `False`, the four inline edge rules stay, amber stays (focus outside and within). (B) clear `border_top/right/bottom/left` → computed border back (rule `#1b233a`, or accent `#91abec` within) but the **painted** corner stays amber (no repaint). (C) set `("round", rule colour)` → rule colour painted, but the accent never returns when the focus enters (inline wins). (D) (B) + `win.refresh()` → painted `#1b233a` outside, `#91abec` within, and the accent appears when the focus enters afterwards. 0 `StagingSheet._paint` calls and no size change during every toggle (Inc 8b's `on_resize` not reached). `styles.border = ("round", EDIT)` raised `ColorParseError` (run 1): `EDIT = "bold #f5c26b"` is a style string. | **Idle look = clear the four edge rules, then `refresh()` the window** (F-9b-6). **Busy colour = `Style.parse(EDIT).color`** (#f5c26b; F-9b-5). |
| §4.3 / P3 | The title room B at 80, 118, 220 columns, read from the painted top border row | Window content width 70 / 110 / 194 (= Inc 8b's V); a title of width − 6 … width − 4 characters is shown whole, width − 3 is not; a 400-character title is cut by Textual to width − 5 characters + `…`, the title starting at column 3 (`╭─ `) and ending `… ─╮`. The pill's span style survives the window's `border-title-color`: painted bg `#f5c26b`, fg `#0a0e1b`, bold, at 80 / 118 / 220. | **B = window `size.width` − 4 = 66 / 106 / 190** at 80 / 118 / 220 columns; EX-BC13 room 76 → 66. |

## Graph examples that need no 9b code (same tree and host)

| Example | Result | Transcript |
|---|---|---|
| EX-BC12 | `name_echo("A\x1b[2J")` = `A�[2J`; `name_echo("B\x85C")` = `B�C` | `out/p-quick.txt`, `out/ex-small.txt` |
| EX-BC10 | DISPLAY_0001 selected → `sheet.states.get("DISPLAY_0001")` is `None` (a scalar row has no bench state → `busy_job` `None`) | `out/p-quick.txt` |
| EX-BC1 (ask) | LARGE selected with its decode held: `BenchState.job == "decode"` right after the key (and `_active_job` set, queue idle); still `"decode"` while running; after `down` to SMALL_BLK, LARGE keeps `job "decode"` (its worker runs on) and SMALL_BLK's state is `"decode"` (queued) → `busy_job` must read the **selected** row's state, as the node says | `out/ex-small.txt` |
| EX-BC6 / EX-BC14 (bytes, token) | VAL_BLK_DEF_0001 Set `10`, alt+s → one entry at `0x800090`, 12 bytes; the token `(id(document), history_depths(), id(current_file))` changes on the stage (depths back 0→1) and on the Undo (back 1→0, forward 0→1), and is stable with no change | `out/ex-small.txt` |
| EX-BC6 (step times, LARGE, 3 runs) | write 0.041 / 0.041 / 0.041 s; step 1 serialize 0.160 / 0.163 / 0.161; step 2 ledger + card + JSON 0.212 / 0.221 / 0.219; step 3 sheet `set_document` 0.256 / 0.258 / 0.256; step 4 0.004; whole block 0.673 / 0.687 / 0.682 s (FX9d 0.674 s: Inc 8b's paint did not move it). With the 0.1 s gaps the cue lasts about 1.0 s after the encode, the largest UI stall stays ≤ 0.26 s | `out/ex-bc6-t1..3.txt` |

## What this changes for E4

- Group S: `PatchMixin._run_refresh_steps` uses `self.set_timer(0.1, …)` per next step (graph node updated); the `on_done` exactly-once rule holds per timer callback.
- Group W: `ArrayBenchSheet._busy_tick` takes the busy colour from `Style.parse(EDIT).color`, clears the four edge rules plus `refresh()` for the idle look, and computes room B as `win.size.width − 4`.
- AT tester: R-PE-BENCH.105/1–/3 expect the cut at B = 66 / 106 / 190; R-PE-BENCH.99/1 can expect the key between the write step and step 1 (P1, `set_timer(0.1)`).
- Not run here: the key→job diagnosis K1–K6 (`E1-slice.md` §5) and the O-E measure (§6) — both are E4 work after GREEN; §6's base is this merge (E3-8b-08).
