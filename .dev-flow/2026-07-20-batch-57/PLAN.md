# batch-57 — CRC Algorithm Designer (headless integration) — living PLAN

**BLUF:** Adopt the already-built, already-tested parametric CRC keel (`crc_kernel.py` +
`crc_designer_model.py`, 34 tests) through the V-model, and complete its run-path integration with
two headless increments — **E7 LUT fast-path** (perf, result-identical) and **E8 `on_gap_conflict`
enforcement** (apply the gap-safety policy). The **Variant B TUI view is deferred to batch-58**
(keel-first, like the Flow Builder tracer). Requirements pre-exist and were adversarially refined
across the design phase (`docs/crc-algorithm-designer/01-requirements.md`).

## Where we are
- **Phase 0 — Story intake.** RC-1 done (ff-merged onto `origin/main` `f2109cf`; keel preserved +
  re-verified green: 119 CRC tests + frozen guard + ruff). Kickoff auth: **autonomous + self-merge**,
  English, full decision recording.

## Objective
Ship a mergeable, tested headless foundation for the CRC Designer: the reusable parametric engine
(width 8–64), the template/job/coverage model with the two-level gap policy, and the gap-safety
enforcement — so batch-58 can build the TUI view on a solid, verified base.

## Scope (autonomous decisions — recorded)
- **IN:** adopt keel (Inc-1); E7 LUT fast-path (Inc-2); E8 `on_gap_conflict` enforcement helper (Inc-3).
- **OUT → batch-58:** the Variant B TUI screen; E6 legacy-`crc_config` up-converter; wiring the
  width-general kernel into the shipped `crc.py` operation (only needed once the view/operation
  consumes a job).
- **Not touched:** the shipped `crc.py` engine stays as-is (32-bit path); the keel is additive.

## Stories (Phase 0)
- **US-CRC1** — *Reusable, verified CRC variant.* As an operator I author/select a parametric CRC
  variant (width/poly/init/refin/refout/xorout) and it is provably correct against the `"123456789"`
  known-answer, so I trust it before it touches firmware. Observable: `CrcAlgorithm.kat_ok()` tri-state;
  every seed preset reproduces its catalogue `check`. **READY** (built + tested).
- **US-CRC2** — *Multi-range coverage with two gap levels.* As an operator I cover one or more memory
  ranges with independent `intra_gap` (skip/fill) and `join` (concat/fill) policies. Observable:
  `gather_target` byte-window + oracle CRCs (concat `0x9C5BCBBD` / fill `0x2A8A3950`). **READY** (built + tested).
- **US-CRC3** — *Gap-safety: no silent divergence.* As an operator, if a gap I promised was erased
  actually holds real data, the tool refuses to emit a diverging CRC. Observable: `gap_conflict`
  returns the offending addresses; `on_gap_conflict` policy (`abort` default) governs the run path.
  **READY for enforcement** — detector built + tested; the run-path *enforcement helper* is Inc-3.
- **US-CRC4** — *Performance.* As an operator I run the CRC over MB-scale firmware without a slow
  bit-by-bit pass. Observable: a LUT fast-path whose output is byte-identical to the bitwise oracle
  over random vectors + all presets. **READY** — Inc-2 (new).

## Roadmap / increment plan (Phase 3)
1. **Inc-1 — adopt keel.** Formalize the already-on-disk `crc_kernel.py` + `crc_designer_model.py`
   + their 34 tests under the flow (validate, no new code). Counterfactual = move-aside RED (C-20).
2. **Inc-2 — E7 LUT fast-path.** `crc_kernel`: build a 256-entry table per algorithm at init
   (from `poly` + reflection), fast inner loop; keep bitwise as the KAT oracle. Differential test
   LUT vs bitwise over presets + random vectors. Result-identical (RK-6).
3. **Inc-3 — E8 enforcement.** `crc_designer_model`: an `evaluate_target`/`enforce_gap_policy`
   helper that runs `gap_conflict` and applies `on_gap_conflict` (`abort` → refuse + message,
   `warn` → proceed + diagnostic, `ignore` → silent). One AT per branch (C-10b).

## Key decisions (log)
- **D0 (kickoff):** autonomous + self-merge; English; full recording. RC-1 ff-merge onto `f2109cf`.
- **D1 (scope):** view + E6 → batch-58; batch-57 is headless keel + E7 + E8. Bounded, keel-first.

## Risks / watch-items
- Keel imports `..changes.io` (`READ_SIZE_CAP_BYTES`) + `..workspace` (`resolve_input_path`) — batch-55
  touched `a2l.py`, not these; re-verified green post-rebase. Watch at Phase 4 whole-suite.
- LUT correctness is the one real risk (Inc-2) — mitigated by the differential test + KAT table.
- Frozen set OFF-LIMITS (core/hexfile/range_index/validation/a2l/mac/color_policy); keel is additive → 0 frozen diff expected.

## Conventions honored
- ≤5 files/increment; black-box AT per behavioral change shown RED pre-fix; docstring §-order; type hints.
- Dual traceability (US→AT ; HLR/LLR→TC). Engine-frozen dual-guard (C-27).

## Out-of-scope carries (→ batch-58 / backlog)
- Variant B TUI view (CRC Designer screen) · E6 legacy up-converter · `emit_job` serializer ·
  wiring width-general kernel into shipped `crc.py` · `check==KAT` enforce-on-save in the view.

## Test ledger
- Base (keel, pre-batch-flow): 34 designer tests (test_crc_kernel 8 + test_crc_designer_model 26).
- Target after Inc-2/Inc-3: +LUT differential tests, +enforcement branch ATs. Reconcile at each gate.

## Decision log (autonomous, un-asked)
- 2026-07-20 — scope split (view→58) — recorded D1.
- 2026-07-20 — batch number 57 (collision avoidance) — recorded.
