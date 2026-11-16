# Inc 9 E4 FX9f - F-X9-2 closed by the operator's decision (relevo-14)

Worker FX9f, claude-sonnet-5-5. Tree `b103-inc9`, start `7c8bda05`, commit `f60f1dc5` (+ records). Runner rtx, HT-02 env,
fresh clone of a bundle, `s19_app.__file__` atop every transcript (`evidence-e5/fx9f/transcripts/`), scratch deleted (explicit list).

## Decision
Javier, 2026-11-14: "Relaja el límite pero deja en el backlog el item." (`s19-PENDING.md` P-125/P-126, review-page item F-X9-2).
Orchestrator ruling (provisional, P-059): 1.0 s for R-PE-BENCH.29/2 and .82/1 only.

## Changes (wording old -> new)
- `01-requirements.md` R-PE-BENCH.29, obligation: "shall handle the key within 0.5 s." -> "... within 0.5 s, except that while a preview or
  a record-stage encode of that object is running it shall handle the key within 1.0 s (relaxed by the operator decision F-X9-2 ...; O-A / O-E
  stay in the backlog)." The row carries the number, so the exception is written there, narrowly, with one `shall`.
- Same file, .29 case 2: "handled within 0.5 s" -> "handled within **1.0 s** (was 0.5 s; relaxed for this case only, ...)"; case 1 stays 0.5 s.
- Same file, R-PE-BENCH.82 case 1: "handled within 0.5 s while the encode runs" -> "within **1.0 s** (was 0.5 s; ...)".
- `02-test-cases.md` rows .29/2 and .82/1: 0.5 s -> 1.0 s with the decision cited; both test ids renamed `...within_half_a_second` ->
  `...within_one_second` (also in `02-test-cases-W.md`; historical transcripts keep the old names).
- `tests/test_b103_inc9_w_jobs.py`: new `RELAXED_KEY_LIMIT_S = timing_bound(1.0)` used by 29_2 and 82_1 only; `KEY_LIMIT_S` (29_1, 20_1),
  `keys_until`, `_typist`, `timed_press` untouched.

## Results (alone, `-n 0`, after a 1-min load < 2)
| Node | Result | Load before |
|---|---|---|
| 29_1 | GREEN 0.173 s / 0.5 s | 0.19 |
| 29_2 | GREEN 0.475 s / 1.0 s (52.5 %) | 0.76 |
| 82_1 | GREEN 0.916 s / 1.0 s, LOW margin 8.4 % | 0.94 |
| 20_1 | GREEN 0.145 s / 0.5 s | 0.98 |

Stall controls on the relaxed timers (copies only, HT-09; `evidence-e5/fx9f/scripts/mutate.py`). Does a 0.8 s stall still fail? **Yes**,
because the stall adds to the base latency: paint stall 0.8 s -> 29_2 RED 1.139 s, 82_1 RED 1.807 s. Re-aimed above the bound (1.3 s):
paint stall 29_2 RED 1.670 s, 82_1 RED 2.282 s; arrival stall 29_2 RED 1.441 s. The timer can still fail.

Fresh clone: Inc 9 (13 files, not timing) 327 passed; Inc 8 (14 files) 371 passed; laws 120 passed / 2 failed = the two known base failures.
`trace_check` 0 gaps. Diff 0 CR.

## Open
- 82_1's 8.4 % margin: can flake RED on a loaded host. O-A / O-E stay in the backlog (the operator's instruction).
- No push.
