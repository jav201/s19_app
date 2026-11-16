# Inc 1b E5 — ruling on TC-B97-69 (`did not settle: A2L loaded`)

Ruled 2026-11-12T22:53:17-06:00 by the orchestrator (claude-opus-5-5). Measurement: script `evidence-e5/b97-69/measure_b97_69.sh`, run on the batch-103 Linux runner (env s19ci, Textual 8.2.8), isolated HOME/XDG/TMPDIR, stdin closed, `PYTHONDONTWRITEBYTECODE=1`, pytest cache off, `s19_app.__file__` printed per run.

## Result (generated summaries: `evidence-e5/b97-69/{head,base}.summary`, per-run lines in `{head,base}.log`)

| Tree | Node alone | Whole `tests/test_b97_key_bar.py` |
|---|---|---|
| `287b9dc3` (head, Inc 1b E5) | 20/20 pass (~31–32 s each) | 5/5 runs, 38 passed |
| `e2e93548` (base before E4) | 20/20 pass | 5/5 runs, 38 passed |

## Ruling

- **Not an Inc 1b regression.** Head and base have the same pass rate in isolation (0 failures in 25 runs each), and Inc 1b's diff does not touch the A2L load path the wait polls.
- **Not labelled flaky either.** The single failure was seen once, inside the 27-min serial law battery (`evidence-e5/laws-final.txt:1207-1327`), and not reproduced in isolation or with its own file. Its class (order- or load-dependent inside a long serial battery) is unmeasured; measuring it means N≥10 law batteries (~27 min each).
- **Disposition:** the laws close for Inc 1b with B97-69 recorded as an open intermittent of the law battery, outside Inc 1b. Backlog item: rerun the law battery N≥10 on one base and record the rate; if it repeats, diagnose the shared state before the `A2L loaded` wait (`tests/test_b97_key_bar.py:715`).
