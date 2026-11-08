# Inc 4 — orchestrator rulings on the E2 graph (2026-11-06T18:37:50-06:00, Opus 5.5)

| Item | Ruling |
|---|---|
| Compact index (array trie, flat buffers): 18.1 MiB, build 1.80 s, rank ≤ 62.6 ms, 0 mismatches vs v3 | **accepted** |
| E2-2 (D-1 letter, PLAN I-3 row, stale S2.7 / 36-row text, 137 MiB RSS) | **fixed by the orchestrator** (E1-rulings D-1 → B, erratum; PLAN I-3 row; R-A2L-MATCH.37 cells) |
| E2-3 (three details E1 §5 left open) | **to E3** |
| E2-5 (code-point comparisons instead of `str.strip` / `isdigit` / `isalnum`) | **accepted** |
| +8 functions and 1 type over the E1 slice (the memory row removed the trie and bitmasks) | **accepted**; E3 checks the slice mapping |
