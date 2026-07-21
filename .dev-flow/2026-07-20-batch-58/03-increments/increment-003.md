# Increment 003 — E6 flat up-converter + emit_job (LLR-E6.1/E6.2/E6.3)

**Gate: APPROVED (self, autonomous)** · code-reviewer: CHANGES-REQUIRED (1 HIGH F1) → **F1 FIXED + verified** → APPROVE · 2026-07-21

## 1. What changed
`crc_designer_model.py` (non-frozen): `parse_job` gained a flat-`crc_config` up-convert branch (`_is_flat_config`/`_upconvert_flat_algorithm`/`_upconvert_flat_targets`, routed through the existing `_build_target` so validation stays single-sourced) + new `emit_job(job)->str` (inline algorithm, round-tripping). LLR-E6.1/.2/.3, AT-058-01, AT-CRC-DSN-012.

## 2. Files modified (frozen census: 0 frozen diffs)
- `s19_app/tui/operations/crc_designer_model.py` (non-frozen — 0× in `_ENGINE_PATHS`)
- `tests/test_crc_job_upconvert.py` — NEW (13 tests)
- `git diff --name-only` = crc_designer_model.py only; new test untracked; `test_engine_unchanged.py` + 3× `tc031` guards green.

## 3. Up-convert mapping
`polynomial→poly`, `init→init`, `reverse→refin==refout`, `final_xor→xorout`, `width=32`, `check=None`, `name="custom"`; each `regions[]`→ single-range skip/concat target (== `compute_region_crc`); each `groups[]`→ multi-range declared-order skip/concat target (== `compute_group_crc`); `output_address`/store fields preserved. `emit_job` emits all 8 CrcTarget fields inline.

## 4. Test results
- RED (C-20): `ImportError: emit_job` (model stashed) + pre-state `parse_job(DUMMY_CONFIG_TEXT)`→1 error.
- GREEN: `test_crc_job_upconvert.py 13 passed`; regression `137 passed` + TUI-CRC `14 passed`; ruff clean.
- **code-reviewer independent run:** 125 passed + 3 tc031 guards; `examples/crc_config.example.json` → parse_job 0 errors/3 targets.

## 5. code-reviewer findings + resolution
- **F1 (HIGH) — FIXED:** the digest-equivalence test (the E6 back-compat guarantee) was vacuous — fixture mem at `0x8000/0x8010` didn't intersect the group spans `0x9000/0x9010`, so both sides digested `b''` → `0x0==0x0` (C-31 vacuous input set). Fixed: `_two_range_mem` now populates the group spans; assertion pins `== expected == 0x9C5BCBBD` (§3.2 concat oracle) so a dropped/reordered range goes RED. Verified: 1 passed with the pinned oracle.
- **F2 (MED, CARRY):** `parse_job` up-convert is intentionally stricter than legacy `parse_crc_config` on region bounds (routes through `_build_target`) and looser on group-width/stray-key. SAFE (parse_job is a new consumer; no shipped path regresses; example config parses clean). → BACKLOG: add a code comment / NOTES documenting the intentional loader asymmetry.
- **F3 (LOW, CARRY):** a flat config missing `polynomial` falls to the evolved branch → misleading "needs algorithm" error. Diagnostic nit. → BACKLOG.

## 6. Pending / carries
F2 + F3 → BACKLOG. E6 is engine-only; the view consuming emit_job/parse_job is Inc-4+.

## 7. Suggested next
Inc-4 — CRC Designer view scaffold + rail wiring (key `0`/glyph `⊕`/`R`) + form + preset population (LLR-V1.1/.2; AT-058-02). Triggers C-22/C-28 snapshot census + "nine→ten" rail docstring sweep.
