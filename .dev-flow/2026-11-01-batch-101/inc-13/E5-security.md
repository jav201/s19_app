# Inc 13 — E5 security review (implemented code, probed)

Batch 2026-11-01-batch-101, increment 13, branch `b101-inc13`, head `a086fa5`, base `b7b77c4`. Reviewer: security-reviewer, independent of the author, the tester and the integrator. Scope: `git diff main...HEAD -- s19_app` (3 files: `crc_designer_view.py`, `operations/crc_kernel.py`, `segment_split_view.py`). Records read: `E3-security.md` (SEC-1 … SEC-10), `E3-rulings.md` (rounds 1 and 2, cap 16 MiB, N-1 … N-5), `E4-integration-notes.md`.

## Verdict

**OK to ship (security lens).** HIGH 0, MEDIUM 0, LOW 2, INFO 3. Every E3 mitigation that was ruled into this increment is `executed` (applied in the code) and `approved` (verified by a probe run below): SEC-1, SEC-2, A-6 (hidden Designer), SEC-4/SEC-8 (timers), SEC-5, SEC-6, SEC-9, and CRC bit-identity. SEC-3 (stale CRC after an in-place apply) stays routed to Inc 5 per the ruling; this review does not close it. This clearance is not the operator's authorization to merge.

## How it was probed

- LAN Linux host only (env `s19ci`, Python 3.11, Textual 8.2.8). Two detached worktrees of `origin/main` (`f9f3cb09`, contains `b7b77c4`, no `s19_app/` or `tests/` drift): one left as base, one with `git diff b7b77c4 a086fa5 -- s19_app tests` applied. `s19_app.__file__` printed into the right tree at each run. User-state paths (HOME, LOCALAPPDATA, XDG dirs) pointed at a throwaway directory; `NO_COLOR` unset. Both worktrees and the scratch directory were removed afterwards (`git worktree list` shows none). Nothing ran on the Windows PC.
- Probe 1 (pure functions, run in base and head, JSON outputs compared). Probe 2 (the real `S19TuiApp` through `run_test`, head only, with call counters on `gather_target`, `gap_conflict`, `evaluate_target`, `compute_target_crc`, `_compute_coverage`, `_recompute`). The probe scripts were scratch files (prefix `s13sec_`) and are not part of the tree.

## Checks asked for, with results

| # | Check | Result | Evidence |
|---|---|---|---|
| C-1 | SEC-1: reverse-typed and hostile Ranges draw a bounded line, no MemoryError or hang | `approved` | Reverse F-23 (`0x00C00000-0x00C00FFF, 0x00800000-0x00931FBF`): line 1 = 15 glyphs, recompute 0.38 s. Hostile `0x0-0x1, 0xFFFFFFF0-0xFFFFFFFF, 0x10-0x11`: line 1 = 51 glyphs, 0.35 s, refused by the cap (no gather). Code: `crc_designer_view.py:1260` (span from min start to max end). |
| C-2 | SEC-2: coverage above the cap shows the exact refusal and builds nothing large | `approved` | Three shapes (one range of cap+1 bytes; a 4 GiB forward gap; two overlapping ranges summing to cap+1), each under `join=concat` and `join=fill`: preview and window line 2 both read exactly `Cannot preview: coverage exceeds 16777216 bytes`; 0 calls of `gather_target`, `gap_conflict`, `evaluate_target`, `compute_target_crc`; 0.23–0.33 s. The cap's size sum (`:1124-1130`) uses the same declared-order forward-gap rule as `gather_target`, so it equals the window size `fill` would build (overlaps counted twice, as gather does). At-cap worst case (16 777 216 B, `intra_gap=fill`, `join=fill`, `warn`): 4.77 s, completes, bounded. |
| C-3 | A hidden Designer does no recompute on image load | `approved` | Panel hidden (key `1`), cap-sized coverage typed beforehand, 3 image loads: 0 `_compute_coverage`, 0 `_recompute`, dirty flag set, no pending timer (`is_on_screen` False). Key `0`: exactly 1 recompute, flag cleared. Code: `:679-707`. |
| C-4 | Timers after the screen closes or the app exits raise nothing | `approved` | Pending timer at `app.exit()` with Q = 0.15 s and Q = 2 s: no exception, return code 0. Timer firing under a pushed screen, then pop: 1 recompute, no exception. Pending timer then `panel.remove()`, then an image change: 0 recomputes (timer stopped, watcher dropped), no exception. `_recompute` clears `_pending_recompute` as its first statement (`:1340`), as SEC-8 asked. |
| C-5 | SEC-5: an int to `crc_lut` raises TypeError | `approved` | `crc_lut(5, …)` raises `TypeError` with `refin` True and False. Code: `crc_kernel.py:256`. |
| C-6 | SEC-6: all 256 pads give the reference marks; no regex backtracking | `approved` | `_conflict_marks` on a seeded image whose values include the regex metacharacters `]`, `\`, `^`, `-`: head output identical to base for all 256 pads (256 distinct results). Pad 256 and -1 raise `ValueError` (fail loud; base returned silently). Pattern is one negated class with `+` (`segment_split_view.py:374`): linear; 16 MiB worst case completes (see F-1). |
| C-7 | Markup and control characters in Ranges render literally | `approved` | Seven payloads (`[link=…]`, `[bold red]`, a lone `[`, `[/]`, ESC/OSC-8/BEL, CR, NUL): preview and window both read `Invalid coverage: …` with the token verbatim, no link span, no style; the rendered strips of both surfaces carry no raw ESC, BEL, CR or NUL (the echo paths use `repr`, `:1032-1034`). See F-3 for the Input widget itself. |
| C-8 | CRC results bit-identical to base for the designer presets | `approved` | All 7 `PRESETS` plus 4 extra parameter sets (refin-only, refout-only, width 12, width 24) over 6 inputs (empty, `123456789`, `bytes(range(256))`, reversed, 1 MiB random, 64 KiB of 0xFF), each as `bytes`, `bytearray` and `memoryview`: 198 of 198 identical. `compute_target_crc` over a seeded holed image, all `intra_gap` × `join` policies, ascending and reverse ranges: 88 of 88 identical. `_sweep` over 200 random mark sets: identical. |

## Findings

| Id | Tag | Severity | Where | Scenario | Recommendation |
|---|---|---|---|---|---|
| F-1 | impl | LOW | `segment_split_view.py:374-395` (`_conflict_marks`) | Adversarial image whose join-gap source alternates pad / non-pad byte by byte (16 MiB, 8 388 608 one-byte runs): head 3.59 s vs base 2.18 s (best of 3, serial, host idle). The per-match Python work (`finditer` + tuple per run) costs more than base's per-address loop when every run is one byte. Every other shape is faster (one 16 MiB run: 0.95 s vs 2.96 s). Linear, bounded by the source size, results identical; the band render after it is already unbounded for this input (SEC-7). | No change in this increment. Add this timing to the SEC-7 band-cell backlog item, which already holds the alternating-byte image as a test input. |
| F-2 | design-gap | LOW | `crc_designer_view.py:1260-1275` (line 1 of the coverage window) | With N-4 the per-run glyph cap was dropped, so line 1 is bounded per range (at most about 48 glyphs per range and per forward gap), not in total. 3000 full-space ranges drew 144 000 glyphs (0.47 s, refused by the cap). Growth is linear in the Ranges text the operator types; no MemoryError path exists. | None needed now. If a total bound is wanted later, cap line 1 at a fixed glyph count with a row; record as backlog only. |
| F-3 | impl (pre-existing, out of slice) | INFO | Textual `Input` (every Input in the app, e.g. `#crc_coverage_ranges`) | A bracketed paste of `ESC[31m…BEL` lands in `Input.value` unchanged, and the Input's own rendered strip carries the raw ESC character. Whether the terminal driver then emits it was not run. Self-inflicted (the operator pastes it); the Designer's result surfaces are safe (C-7). Same on base. | Backlog: a small `Input` subclass or paste filter that drops C0 control characters except TAB, applied to the app's Inputs. Not this increment. |
| F-4 | impl | INFO | `crc_designer_view.py:699` (`is_on_screen`) | `is_on_screen` is true while a modal screen covers the Designer, so an image load from a modal still schedules the recompute behind it (probed: fires, no exception). Cost is bounded by the cap (≤ about 5 s measured worst case). Correctness unaffected. | None. |
| F-5 | impl | INFO | `crc_kernel.py:256` | `bytes(memoryview(data))` rejects a `list[int]` when `refin` is set (base iterated it). No caller passes a list; `CrcAlgorithm.compute` is typed `bytes`. Fail-loud, the direction SEC-5 asked for. | None. |

## Items from E4 that touch security

- E4-F1 (`_state_text` shows GUARD before the conflict line): not a security defect of this slice; the export path still refuses on conflict (LLR-136.4), so no wrong export is written. Concur with routing it to the slice that owns the state line.
- E4 item 5 (a dropdown change stops a pending timer): by reading, `on_select_changed` calls `_recompute`, which stops and clears any pending timer first (`:1340`). Not probed separately (`not-run`).
- E4 item 3 (`test_tc_b97_69` one-off under `-n 12`): not investigated here; C-3 shows the new watcher does no work while the Designer is hidden, which makes a link through the Designer's compute unlikely but does not exclude a scheduling effect.

## Evidence states

- C-1 … C-8: `executed` and `approved` (probed on the LAN host, numbers above).
- F-1 … F-5: recommendations `planned` (backlog or none); none blocks.
- SEC-3: `n/a — routed to Inc 5 by the E3 ruling`; SEC-7: `n/a — backlog`.

## Evidence checklist

- [x] Each finding has what · where · why · recommendation — table above (F-1 … F-5).
- [x] Each finding has a severity — LOW 2, INFO 3; HIGH 0, MEDIUM 0.
- [x] No secret values in this report — none handled; the increment touches no credentials.
- [x] Verdict explicit — OK to ship (security lens); no HIGH open; every ruled-in mitigation applied and verified by probe.
- [x] New tool / integration — none (`re`, `itertools`, `dataclasses`, `typing` are stdlib; `textual.timer.Timer` is an existing dependency); n/a.
