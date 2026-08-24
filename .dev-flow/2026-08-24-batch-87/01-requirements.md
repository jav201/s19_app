# 01 — Requirements · batch-87 · D-II re-author of the pilot IFC record + IFC surface #3 (`workspace_body`)

> **Status: P0 scaffold — §2.6 story intake only.** The full record (SPEC, HLR/LLR, IFC Part A/B,
> premise table, gates) is authored at P1 following the batch-86 exemplar
> (`.dev-flow/2026-08-24-batch-86/01-requirements.md`) under the execute-first discipline (C-39:
> probes run FIRST, thresholds derived from what they print).

## 2.6 · Story intake & refinement (Definition of Ready)

### US-87-1 — Re-author the batch-85 pilot IFC record (D-II discharge)

**As** the IFC retrofit programme, **the contract** for `loaded_panel` (the batch-85 pilot surface)
**is re-authored** to the batch-86 exemplar format — SIX outputs per the D-A analysis (split
`slot_rows` into `artifact_row_set`, `query(".loaded-slot")`, cardinality 4, and `unload_all_row`,
`query(".loaded-allrow")`, cardinality 1; `HANDOFF-atlas-ifc-2026-08-22.md` §8), pair-based
thresholds, scoped statements, no absorbed `owner` field — **so that** the UNPARSED census clears to
pure BATCHES entries and the D-86-E verbatim re-export duplication is resolved under
`screen_workspace`'s already-declared parent boundary.

- **D-II ruling (operator, 2026-08-24, this session):** re-author — chosen over patching the 15
  catalogued defects (`HANDOFF-batch85-ifc-pilot-2026-08-21.md` §5). The pilot's MEASUREMENTS
  (census, cost figures) stay valid history; re-authoring replaces the CONTRACT, not the record of
  what was measured.
- **Observable outcome (black-box, through the shipped validator):** the `[IFC]` UNPARSED entry at
  `2026-08-21-batch-85/01-requirements.md:372` (field `owner` absorbed 801 chars) is GONE from the
  regenerated `ATLAS-ORPHANS.md`; the BATCHES dir-name census entry remains (negative control);
  `loaded_panel` balancing stays CHECKED under V12; 0 new BLOCKs.
- **INVEST:** Independent of US-87-2 in authoring order (but shares the batch record — see D-87-A).
  Valuable: clears the last IFC parse debt + one contract, one declaration. Estimable: bounded by
  the exemplar + the D-A prescription. Small: one record section. Testable: the validator/Atlas
  observables above.
- **Open design question `D-87-A` (P1, decided by executed probe, not by reading):** where the
  re-authored contract LIVES — (a) corrected in place in the batch-85 record vs (b) declared fresh
  in batch-87's record. Deciding evidence owed: `_ifc_corpus`'s merge semantics when two batches
  declare the SAME `COMPONENT` id (named UNARMED by the pilot handoff §7.2 — the probe must be run,
  and D-86-E's rationale "correcting it elsewhere while the pilot stands forks the contract" weighs
  toward (a) for the contract body).
- **DoR: READY** — outcome observable through the shipped surface (validator + Atlas), acceptance
  criterion stated at behavior level, path known (exemplar + D-A), no unresolved dependency
  (D-87-A is a bounded in-batch decision with a named probe).

### US-87-2 — Declare IFC surface #3: `workspace_body` (the shell)

**As** the IFC retrofit programme, **the shell component** `workspace_body` (`#workspace_body`,
`app.py:1917` — the container above `screen_workspace`, the only undeclared `PARENT` V12 names)
**gets its IFC Part B contract declared** in the batch-87 record, **so that** the standing V12
NOTICE naming `screen_workspace/workspace_body` is replaced by a checked balancing verdict, and the
`.db-pane` / `.db-screen` couplings measured at batch-86 M-6 become contract-visible (D-86-A
discharge path).

- **Selection criterion:** the SAME V12-liveness criterion that chose surface #2 — it is the only
  undeclared PARENT the validator names (probe executed this session: the sole V12 finding names
  `screen_workspace/workspace_body`; validator run 2026-08-24, `0 block · 254 notice`).
- **Observable outcome (black-box):** post-state validator run shows 0 V12 findings naming
  `screen_workspace/workspace_body` as unchecked; `workspace_body`'s own PARENT question is answered
  honestly (SYSTEM if it is truly the root — to be MEASURED at P1, `app.py` compose tree — else one
  standing NOTICE one level up, the staged-retrofit pattern of pilot D-B / D-86-B).
- **Consumer-census input (measured this session, to be re-derived at P1):** `workspace_body`
  appears in 24 test files / 40 occurrences; `loaded_panel` in 12 test files.
- **INVEST:** Independent: declarable given screen_workspace's record (merged, on `main`).
  Valuable: retires the last named undeclared PARENT; per-surface cost point n=3 (dispersion series
  continues). Estimable/Small: one Part B contract; the shell is plausibly LARGE (composes three
  panes) — cost measured, not assumed (batch-86 non-extrapolation caveat honored). Testable: V12
  observable above.
- **DoR: READY** — same bar as US-87-1, all criteria evidenced by executed probes.

### Batch premise (both stories)

Spec-only batch: **0 source files** planned (pin verified at every gate, as batch-86). Canon mirror
edits in `REQUIREMENTS.md` only (R-TUI-113 refresh to re-authored status + new-id seeding per the
corpus rules; V22 debt must not grow — batch-86 closed at 276).
