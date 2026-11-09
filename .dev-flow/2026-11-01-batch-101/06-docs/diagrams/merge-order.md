# Diagram — the increment dependency and merge order (flowchart)

> **Role:** `docs-writer`. Mermaid flowchart. It shows the 16 increments (18 packets with the 10 and 12 split into a/b), their dependency graph from `PLAN.md` §Roadmap, and the merge order recorded in `evidence/merge/`. The serial `app.py` chain is 3 → 4 → 5 → 6 → 9 → 10a → 10b → 12; Inc 1 ∥ Inc 2 open the batch, and Inc 3 ∥ 7 ∥ 8 ∥ 11 ∥ 13 ∥ 14 run in parallel after them. Inc 12b splits from Inc 12 and merges before the final full suite; Inc 15 ∥ Inc 16 merge together. Facts come from `PLAN.md` §Roadmap + §Order and `05-close.md` §3 (the merge SHAs).

```mermaid
flowchart TD
    S["Batch base (main) — release hardening for v1.0.0"]
    I1["Inc 1 — strict-EARS canon swap (6a4eadb)"]
    I2["Inc 2 — test hygiene, timing arms, CI (8e5127a, PR #212)"]
    P["Parallel lane (after Inc 1 + Inc 2): at most 3 E4 lanes in flight"]
    I3["Inc 3 — Save project margin, vanished folder (b7b77c4)"]
    I7["Inc 7 — reports: whole/inert/atomic (011fdd8)"]
    I8["Inc 8 — Flow CRC block, external steps (2a70774)"]
    I11["Inc 11 — A2L parsing (merged at its close)"]
    I13["Inc 13 — CRC/Split responsive at 10 MB (merged)"]
    I14["Inc 14 — help/legend/README/docs (merged)"]
    I4["Inc 4 — symbol resolution (990db24)"]
    I5["Inc 5 — CRC refresh + Check Editor (98d94d7)"]
    I6["Inc 6 — Patch Editor lifecycle (merged)"]
    I9["Inc 9 — flow saves (merged)"]
    I10a["Inc 10a — hex nav, unload, focus (6f1743c)"]
    I10b["Inc 10b — views after in-place writes (merged)"]
    I12b["Inc 12b — hidden Flow widgets removed (f481e8a)"]
    I12["Inc 12 — dead surfaces removed, Reports Escape (b982846)"]
    I15["Inc 15 — Windows-only test fixes (9bb0e3a)"]
    I16["Inc 16 — documentation hygiene (9bb0e3a)"]
    GATE["Batch-end battery on b982846 — full suite + snapshots + doc-pass + Inc 6 Windows arms"]

    S --> I1
    S --> I2
    I1 --> P
    I2 --> P
    P --> I3
    P --> I7
    P --> I8
    P --> I11
    P --> I13
    P --> I14
    I3 --> I4 --> I5 --> I6 --> I9
    I8 --> I9
    I13 --> I10a
    I9 --> I10a
    I10a --> I10b
    I10b --> I12
    I9 --> I12b
    I10a --> I12b
    I14 --> I16
    I14 --> I15
    I5 --> I12
    I6 --> I12
    I15 --> GATE
    I16 --> GATE
    I12 --> GATE
```

**Reading notes.**
- **Parallel first.** Inc 1 (canon swap, delivered by the requirements re-write session) and Inc 2 (test hygiene) open the batch and merge first.
- **Parallel middle.** Inc 3 ∥ 7 ∥ 8 ∥ 11 ∥ 13 ∥ 14 run after Inc 1 + Inc 2, at most three E4 lanes in flight.
- **Serial `app.py` chain.** 3 → 4 → 5 → 6 → 9 → 10a → 10b → 12, one writer at a time; Inc 9 also depends on Inc 8, and Inc 10a on Inc 13.
- **The two splits.** Inc 12b (the Flow half of F-35) split from Inc 12 at E3 and merged earlier (`f481e8a`); Inc 10b split from Inc 10 at E3 and merges between 10a and 12.
- **The tail (the brief's merge order).** After Inc 9, Inc 12b and Inc 10a merge, then Inc 10b, then Inc 12 — which is the final increment and the batch-end full suite on `b982846`.
- **Inc 15 ∥ Inc 16** merge together (`9bb0e3a`), both after Inc 14; Inc 16 is documentation-only plus comment-only source fixes.
- **Merge evidence.** `evidence/merge/lan-merge-inc3.txt` … `lan-merge-inc15-inc16.txt`; the full suite runs once at batch end (`evidence/close/full-suite-final.txt`).
