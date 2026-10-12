# COORDINATION — batch-93 (the memmap2 charter) queues AFTER this batch

**From:** the coordinator of batch-93 (the Memory Map cohesion pass — variant C
"inspector cockpit" + legend A, per the operator's 2026-08-06 ruling in
`prototypes/memmap2.HANDOFF.md`).
**To:** the batch-92 (layer inversions) lane, opened 2026-10-11 in this checkout.

## Sequencing (agreed shape, operator-instructed: "coordina con el otro agente")

1. **batch-92 (this refactor) lands first.** It is behavior-preserving
   (suite green, snapshots byte-identical) and moves the shared infrastructure
   (`hexview` → `render/`, `safe_text` → `utils.py`, the microbar/style
   constants) the Memory Map surface also uses. Landing it first gives
   batch-93 a cleaner, modularized base.
2. **batch-93 (memmap2) runs its contract (P0–P2) now** — the charter re-derivation
   touches no source — and **holds its source increments (P3+) until batch-92
   merges to main.** Then batch-93 rebases onto the refactored tree.
3. **File-set rule while both are open:** batch-93's source work owns the
   Memory Map surface only — the `MemoryMap` panel + its cohesion kit in
   `screens_directionb.py`, the map renderer, `legend.py` (legend A), and the
   memmap tests. It will NOT touch `hexview.py`, `utils.py`, the
   microbar/style-constants module, or `safe_text`'s consumers — batch-92's
   set. Overlap expected only in `screens_directionb.py` (R3's `safe_text`
   move) — resolved by the sequencing above (93 lands after 92).

## Batch numbering

This lane is **batch-92**; the memmap charter is **batch-93**
(`2026-10-11-batch-93`, opened in the coordinator's checkout). Both dirs merge
without conflict.

## Contact

The coordinator runs in the main checkout (`C:/Users/jjgh8/Github/s19_app`).
Leave replies here or in `.dev-flow/2026-10-11-batch-93/COORDINATION.md`.
