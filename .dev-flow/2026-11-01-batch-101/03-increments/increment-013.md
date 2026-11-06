# Increment 013 — Inc 13 · R-CRC-DESIGNER, R-CRC-PREVIEW, R-SEG-PREV · CRC Designer and Split/Join responsive at 10 MB; conflict-first state line

Flow: dev-flow-v3-beta. Records live in `.dev-flow/2026-11-01-batch-101/inc-13/`: `01-requirements.md` (24 active rows), `02-test-cases.md` (52 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md` + `E3-rulings.md` + `E3-security.md`, `E4-impl-notes-designer.md` / `-kernel.md` / `-split.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc13.md`, `evidence/inc-13/`. Branch `b101-inc13` from `main` (base `b7b77c4`), head `3e01603` plus the uncommitted re-review / re-audit sections and this packet.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1 (requirements + rulings), E2 (baseline graph), E3 (both design reviews, round 1 + round 2), the E4 integration step, the E5 code and security reviews and the coverage audit, and the E5 corrective pass; **DeepSeek v4 Pro** — the E4 implementers (3 units), the E5 mutant battery, and this record; **Sonnet** — the E4 independent tester.

## 1. What changed

The CRC Designer no longer freezes on the 10 MB demo image: text edits and image changes recompute once, 150 ms after the last of them (a quiet-time debounce), a toggle/dropdown/preset/template recomputes at once and exactly once (its fills run with change events suppressed), and one coverage computation is shared by the preview and the window — at most 2 window reads per recompute. A coverage larger than 16 MiB (16777216 bytes) is refused with an exact `Cannot preview: coverage exceeds … bytes` text before any read, and out-of-order Ranges draw a bounded line 1. The CRC engine reflects input bytes through a 256-entry table instead of per byte. The Split/Join preview's `_sweep` becomes a boundary sweep (O(m log m)) and `_conflict_marks` finds non-pad runs with one compiled regex, so the `g`/join-fill preview updates in well under its 2.5 s bound; and `_state_text` now paints the conflict clobber line before the GUARD chip (the E4-F1 fix ruled in by C-1). The painted texts, glyphs and layout otherwise stay as on base.

## 2. Files modified

Committed: `git diff --stat main...HEAD` (87 files, +9045 / −118). Uncommitted: the re-review / re-audit sections of `E5-code-review.md` and `E5-coverage-audit.md`, and this packet's two records (`04-validation.md`, this file). **SOURCE files: 3 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/crc_designer_view.py` | source | US-CRC-RESP-1 · US-CRC-FRESH-1 | Quiet-time debounce (`CRC_RECOMPUTE_S = 0.150`, `_schedule_recompute`); `_CoverageRun` shared once per recompute; `_compute_coverage` (≤ 2 reads, cap check first); the `current_file` watcher + stale flag + `on_show`; the 16 MiB cap and bounded line-1 scale; CR-3 (`crc_error` branch) and CR-5 (compute moved after the other surfaces) |
| `s19_app/tui/segment_split_view.py` | source | US-SEG-RESP-1 | `_sweep` one pass over sorted boundaries with a live per-class count; `_conflict_marks` regex non-pad runs + merge, fail-loud 0…255 precondition; `_state_text` tests `plan.conflicts` before `plan.guard` (C-1) |
| `s19_app/tui/operations/crc_kernel.py` | source | US-CRC-RESP-1 | `_REFLECT8` table; `crc_lut` translates input once via `bytes(memoryview(data)).translate(_REFLECT8)` when `refin` |
| `tests/support/b101_demo_image.py` | fixture | US-CRC-RESP-1 · US-SEG-RESP-1 | `demo_regions()` / `demo_loaded_file()` — the 10 MB demo scenes built from the generator (E1-D7) |
| `tests/support/b101_designer.py` | fixture | US-CRC-RESP-1 · US-CRC-FRESH-1 | The recompute-counter fixture and `wait_designer_recompute` helper (T6) |
| `tests/support/b101_inc13_reference.py` | fixture | US-SEG-RESP-1 | `reference_sweep` / `reference_conflict_marks` — the base functions copied verbatim from `b7b77c4:segment_split_view.py:288-351` (T4 oracle) |
| `tests/test_b101_designer_recompute.py` | test | US-CRC-RESP-1 · US-CRC-FRESH-1 | The recompute/cap/matrix/bounded-line nodes, the D-2 AST check, and the E5c black-box ATs (typing, dropdowns, template, load/unload/project-load, six surfaces, CR-3) |
| `tests/test_b101_inc13_perf.py` | test | US-CRC-RESP-1 · US-SEG-RESP-1 | The 4 `serial_timing` arms (002.2, 002.3, 002.4, 20/1) through `timing_bound` + `report_margin` |
| `tests/test_b101_split_join_band.py` | test | US-SEG-RESP-1 | Band invariance (classifier + verbatim reference), the hand-examples sweep skip, the clobber/priority state-line nodes, and the palette/keys ATs |
| `tests/test_crc_designer_view.py` | test | US-CRC-RESP-1 · US-CRC-FRESH-1 | The 15 D-2 wait sites (12 nodes + 3 helpers), the fixture import and `pytestmark`; no assertion changed (D-2, E3 A-1) |
| `tests/test_crc_kernel.py` | test | US-CRC-RESP-1 | New 001.1 node: 205 vectors × every preset + widths 9…63 (49) × refin/refout pairs (C-6) |
| `tests/test_id_registry.py` | test | US-CRC-RESP-1 · US-CRC-FRESH-1 · US-SEG-RESP-1 | `EXPECTED_SCANNED_TEST_FILES` 250 → 256 (measured, the 6 added scanned modules) |
| `.dev-flow/2026-11-01-batch-101/inc-13/01-requirements.md` | doc |  | EARS requirements: 24 active rows (13 new/changed + 11 canon verified, 1 withdrawn) + Definitions |
| `.dev-flow/2026-11-01-batch-101/inc-13/02-test-cases.md` | doc |  | 52 ISO 29119-3 cases; re-audited at E5 (49 covered / 3 partial / 0 gap) |
| `.dev-flow/2026-11-01-batch-101/inc-13/E1-rulings.md` | doc |  | E1 scope, canon changes, decisions D-1 … D-4, orchestrator rulings, E3 fold-in table |
| `.dev-flow/2026-11-01-batch-101/inc-13/E1-slice.md` | doc |  | Implementation slice: 19 items in 3 source files, the test files, the D-2 touched-node table |
| `.dev-flow/2026-11-01-batch-101/inc-13/E3-architect.md` | doc |  | E3 design review round 1 (FAIL, 2 MAJOR + 6 MINOR) → round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-13/E3-rulings.md` | doc |  | E3 round-1/2 rulings, the 16 MiB cap addendum, E4 addenda N-1 … N-5 |
| `.dev-flow/2026-11-01-batch-101/inc-13/E3-security.md` | doc |  | E3 design security review: PASS-WITH-NOTES, SEC-1 … SEC-10 |
| `.dev-flow/2026-11-01-batch-101/inc-13/E4-impl-notes-designer.md` | doc |  | E4 implementer notes, designer unit |
| `.dev-flow/2026-11-01-batch-101/inc-13/E4-impl-notes-kernel.md` | doc |  | E4 implementer notes, kernel unit |
| `.dev-flow/2026-11-01-batch-101/inc-13/E4-impl-notes-split.md` | doc |  | E4 implementer notes, split unit |
| `.dev-flow/2026-11-01-batch-101/inc-13/E4-tester-notes.md` | doc |  | Independent tester notes: RED on base, ambiguities 1–4 |
| `.dev-flow/2026-11-01-batch-101/inc-13/E4-integration-notes.md` | doc |  | E4 integration: GREEN on LAN host 2, SR-1, OR-1 / E4-F1, OR-2, items 1–5 |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-mutants.md` | doc |  | E5 mutant table: 24/25 KILLED, M-12 equivalent, corrective-pass addendum |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-code-review.md` | doc |  | E5 code review PASS-WITH-NOTES (CR-1 … CR-5) → re-review PASS at `3e01603` (uncommitted Re-review) |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, LOW 2 + INFO 3, probes C-1 … C-8 |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-coverage-audit.md` | doc |  | Coverage audit (17/39 changed) → re-audit at `3e01603` (uncommitted Re-audit) |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-rulings.md` | doc |  | E5 rulings C-1 … C-8 + the routed-to-backlog table |
| `.dev-flow/2026-11-01-batch-101/inc-13/E5-corrective-notes.md` | doc |  | E5 corrective pass: C-1 … C-8 done, counts, measured times, routed items |
| `.dev-flow/2026-11-01-batch-101/inc-13/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-13/steps.log` | doc |  | Stage log, models and UTC stamps |
| `.dev-flow/2026-11-01-batch-101/inc-13/codewire/graph-inc13.md` | doc |  | Code-wire graph G1/G2/G3 nodes, interfaces I-1 … I-9 |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | Three batch-101 rows: security F-1 (with SEC-7), security F-3, the `test_tc_b97_69` flake |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-013.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-ast.txt` | generated | US-CRC-RESP-1 | D-2 AST check, 3 PASSED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-b97-69-r1.txt` | generated | US-CRC-RESP-1 | `test_tc_b97_69` re-run alone 1/3 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-b97-69-r2.txt` | generated | US-CRC-RESP-1 | `test_tc_b97_69` re-run alone 2/3 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-b97-69-r3.txt` | generated | US-CRC-RESP-1 | `test_tc_b97_69` re-run alone 3/3 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-c1-green.txt` | generated | US-SEG-RESP-1 | C-1 GREEN: 108 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-c1-red.txt` | generated | US-SEG-RESP-1 | C-1 RED before the `_state_text` fix |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-cr3-green-and-ats.txt` | generated | US-CRC-RESP-1 | CR-3 GREEN + the black-box ATs, 4 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-cr3-red.txt` | generated | US-CRC-RESP-1 | CR-3 RED: `TypeError` on the `crc_error` path |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-lane1.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 final lane: 818 passed, 1 failed (flake), 16 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-AT-M2.txt` | generated | US-CRC-RESP-1 | Corrective control: `on_input_changed` at once — KILLED (typing AT, 13 recomputes) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-AT-M7.txt` | generated | US-CRC-RESP-1 | Corrective control: `current_file` watch dropped — KILLED (both load-route ATs) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-C2.txt` | generated | US-SEG-RESP-1 | Corrective control: `_sweep` without the empty/inverted skip — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-CR4.txt` | generated | US-CRC-RESP-1 | Corrective control: `_is_snapshot` without the name test — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-SEG-PREV-7.txt` | generated | US-SEG-RESP-1 | R-SEG-PREV.7 control (census from the merged blocks' count) — KILLED after C-1 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-mut-NC-SIX-SURFACES.txt` | generated | US-CRC-RESP-1 | Corrective control: `warnings.update` dropped — KILLED (six-surface node) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-serial-r1.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 serial lane run 1/5, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-serial-r2.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 serial lane run 2/5, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-serial-r3.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 serial lane run 3/5, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-serial-r4.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 serial lane run 4/5, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-serial-r5.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E5 serial lane run 5/5, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/e5c-split-join-ats.txt` | generated | US-SEG-RESP-1 | The Split/Join palette/keys ATs (20/2, 7/3, 7/4) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-ast-r1.txt` | generated | US-CRC-RESP-1 | E4 D-2 AST check + control, 2 PASSED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-lane1-r1.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 lane 1 before fixes: 3 failed, 801 passed, 16 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-lane1-r2.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 lane 1 after fixes: 804 passed, 16 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-probe-r1.txt` | generated | US-CRC-RESP-1 | E4 the three run-1 failures alone, after fixes: 14 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-serial-r1.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 serial lane run 1/3, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-serial-r2.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 serial lane run 2/3, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/int-serial-r3.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 serial lane run 3/3, 4/4 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-1.txt` | generated | US-CRC-RESP-1 | M-1 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-2.txt` | generated | US-CRC-RESP-1 | M-2 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-3.txt` | generated | US-CRC-RESP-1 | M-3 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-4.txt` | generated | US-CRC-RESP-1 | M-4 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-5.txt` | generated | US-CRC-RESP-1 | M-5 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-6.txt` | generated | US-CRC-RESP-1 | M-6 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-7.txt` | generated | US-CRC-RESP-1 | M-7 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-8.txt` | generated | US-CRC-RESP-1 | M-8 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-9.txt` | generated | US-CRC-RESP-1 | M-9 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-10.txt` | generated | US-CRC-RESP-1 | M-10 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-11.txt` | generated | US-CRC-RESP-1 | M-11 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-12.txt` | generated | US-SEG-RESP-1 | M-12 SURVIVED (equivalent) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-13.txt` | generated | US-SEG-RESP-1 | M-13 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-14.txt` | generated | US-SEG-RESP-1 | M-14 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-15.txt` | generated | US-SEG-RESP-1 | M-15 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-16.txt` | generated | US-CRC-FRESH-1 | M-16 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-17.txt` | generated | US-CRC-FRESH-1 | M-17 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-18.txt` | generated | US-CRC-FRESH-1 | M-18 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-19.txt` | generated | US-CRC-RESP-1 | M-19 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-20.txt` | generated | US-CRC-RESP-1 | M-20 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-21.txt` | generated | US-CRC-RESP-1 | M-21 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-22.txt` | generated | US-CRC-RESP-1 | M-22 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-23.txt` | generated | US-SEG-RESP-1 | M-23 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-24.txt` | generated | US-CRC-RESP-1 | M-24 KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/mut-M-25.txt` | generated | US-CRC-RESP-1 | M-25 KILLED (timing arm, −18.7 % margin) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-13/red-01-tester-base.txt` | generated | US-CRC-RESP-1 · US-SEG-RESP-1 | E4 tester RED on base (15 Designer nodes + 4 timing arms) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 9 committed (3 new test files, 3 support, 2 edited, 1 registry) |
| Doc files | 22 (`inc-13/` records + `BACKLOG-CODE.md` + this packet) |
| Generated files | 54 transcripts under `evidence/inc-13/` |

## 3. How to test

```bash
# the slice-covering lane (parallel; E4 ran -n 12, the E5 corrective pass -n 4)
python -m pytest -q -n 4 -m "not serial_timing" \
  tests/test_b101_designer_recompute.py tests/test_b101_split_join_band.py \
  tests/test_b101_inc13_perf.py tests/test_crc_designer_view.py tests/test_crc_kernel.py \
  tests/test_b101_crc_model_and_reasons.py tests/test_segment_split_window.py \
  tests/test_id_registry.py tests/test_suite_hygiene.py \
  tests/test_engine_unchanged.py tests/test_tui_directionb.py tests/test_requirements_canon.py
# the serial lane (the 4 timing arms, run alone, 5/5)
python -m pytest -q -m serial_timing -p no:randomly tests/test_b101_inc13_perf.py -v -rA
# the D-2 AST check
python -m pytest -q -rA \
  tests/test_b101_designer_recompute.py::test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits
```

## 4. Test results

Layer 0 / white-box: E5 final lane **818 passed, 1 failed, 16 skipped** (`e5c-lane1`); E4 lane 804 passed (`int-lane1-r2`); D-2 AST check 3 PASSED (`e5c-ast`), E4 2 PASSED (`int-ast-r1`). Serial lane: **4 arms × 5 runs, 20/20 pass, 0 margins under 20 %** (`e5c-serial-r1..r5`). Black-box ATs (the 13 E5c cases) all pass through keys/dialogs (`e5c-lane1`, `e5c-split-join-ats`, `e5c-cr3-green-and-ats`). Mutants 24/25, survivor equivalent (dropped). Case totals after the re-audit: 52 cases, 49 covered / 3 partial / 0 gap, result 52 pass. Details: `inc-13/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| **RED counterfactual** | The C-1 `_state_text` fix's own RED on the pre-fix tree: both new state-line nodes fail on the equality alone, the shipped GUARD chip in place of the canon clobber line — `e5c-c1-red.txt` (fingerprint start = end); the CR-3 fix's own RED is the `TypeError` on the `crc_error` path — `e5c-cr3-red.txt`; the tester's base RED (15 Designer nodes + 4 timing arms) is `red-01-tester-base.txt`; the base-source mutants the tester ran are in `red-01-tester-base.txt` |

### Mutation verdicts

| Field | Value |
|---|---|
| **Mutation verdicts** | 25 mutants on the implemented tree, per-node verdicts in `E5-mutants.md` and `mut-M-*.txt`: 24 KILLED, 1 SURVIVED (M-12, classified equivalent and dropped by C-5), 1 control N/A at the first pass (R-SEG-PREV.7-NC, blocked by E4-F1) then **KILLED** after C-1 (`e5c-mut-NC-SEG-PREV-7.txt`). The corrective pass's own controls (C-1 RED, C-2, CR-3 RED, CR-4, six surfaces, AT M-2 / M-7) are each KILLED — `e5c-mut-NC-*.txt` |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments shown RED before their PASS was believed: the `_state_text` fix (C-1 RED → GREEN, `e5c-c1-red` / `e5c-c1-green`); the CR-3 fix (RED `TypeError` → GREEN, `e5c-cr3-red` / `e5c-cr3-green-and-ats`); the tester's suite on base (`red-01-tester-base`) |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | none — this increment emits no artifact; the painted surfaces (coverage preview lines, window line 2, the store word, the clobber/GUARD state lines) are asserted in-place by the test nodes against the canon texts and independent oracles (`zlib.crc32`, the engine's `gap_conflict` count) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-13/`.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| e5c-ast.txt | evidence/inc-13/e5c-ast.txt | 5083c6bd49a4754fec4969c250678a9d2a4b8bf00b26a8d7bd156155f71ba23e |
| e5c-b97-69-r1.txt | evidence/inc-13/e5c-b97-69-r1.txt | 54b30f8ef62655179d3ec0a5154abedbf510f29e34a2c1f328de2955d26d31f2 |
| e5c-b97-69-r2.txt | evidence/inc-13/e5c-b97-69-r2.txt | fdb9a6c5e0ca4da25f1dec26a2d887f9a2a14c043c651fac0f27eabc699312fe |
| e5c-b97-69-r3.txt | evidence/inc-13/e5c-b97-69-r3.txt | 0dcb5e585eedbea9fc4ff9737ef953940280d4d9feb9f287035d38d0717d83a0 |
| e5c-c1-green.txt | evidence/inc-13/e5c-c1-green.txt | b0402542009d3e882dc4c3cc5e69309c169066c48b5c2f3316f365cf6539c8e2 |
| e5c-c1-red.txt | evidence/inc-13/e5c-c1-red.txt | 1b36871820cfb5bc4609b7d40f226d348af1ebc3f3c1f8bd5c9d47bab8ee3fd5 |
| e5c-cr3-green-and-ats.txt | evidence/inc-13/e5c-cr3-green-and-ats.txt | 7cf07bf9aa9b9762235c1055a66e0310b0df08a7a0bb74b97867fb0427e9dbb8 |
| e5c-cr3-red.txt | evidence/inc-13/e5c-cr3-red.txt | bd68044baebac3c9fc13f1ce4f9db693cebe50d0135e74a682ba4d782c13c341 |
| e5c-lane1.txt | evidence/inc-13/e5c-lane1.txt | 2c649b83e4ee2a97bde883fa0e6a57e8244d750e8db19c99c4b04e3d2870b0c4 |
| e5c-mut-NC-AT-M2.txt | evidence/inc-13/e5c-mut-NC-AT-M2.txt | a3d682bd67b72ac53c786c2542d27ff7de07bb5d8b0fdb97801c6237b8cf2beb |
| e5c-mut-NC-AT-M7.txt | evidence/inc-13/e5c-mut-NC-AT-M7.txt | f9f080868a02cd214bbd637f53e18a11f6f85e7977a99a1e36f72124da720028 |
| e5c-mut-NC-C2.txt | evidence/inc-13/e5c-mut-NC-C2.txt | fe3c9574f92833437559fdd1a155b5a30c78f211963b64e67321d5d3dc15dee3 |
| e5c-mut-NC-CR4.txt | evidence/inc-13/e5c-mut-NC-CR4.txt | 830f8452a5826ca4f9b36721ad0b975d14c9fc88ac0806023bb30bece17091cf |
| e5c-mut-NC-SEG-PREV-7.txt | evidence/inc-13/e5c-mut-NC-SEG-PREV-7.txt | ebbc8ff216687972cc5dd2b5dc570985608f0be4ace476842671e9745172ab34 |
| e5c-mut-NC-SIX-SURFACES.txt | evidence/inc-13/e5c-mut-NC-SIX-SURFACES.txt | 06e5f2e913854089da6124e645a8e85b50831f944042389711e1245b13c7d141 |
| e5c-serial-r1.txt | evidence/inc-13/e5c-serial-r1.txt | a8a39153a1c7faa1d2abece65143b2ed995301c003d16005b9eec668135316cd |
| e5c-serial-r2.txt | evidence/inc-13/e5c-serial-r2.txt | a003bd6d142c361f080c1e378f5fd48d9d5641aed391d6dcdba8eb2eaba4e6f1 |
| e5c-serial-r3.txt | evidence/inc-13/e5c-serial-r3.txt | 5084a7bb96c11f1b25eeab1db19b1078592fa9d66898bb9f9fc0710f90e3f449 |
| e5c-serial-r4.txt | evidence/inc-13/e5c-serial-r4.txt | c751f9370625ad90a5dd149ede882f6eff98d70c960c2587e2aa574b9f7e07f2 |
| e5c-serial-r5.txt | evidence/inc-13/e5c-serial-r5.txt | ecaecff3fc009c7e9320dae475b8209a34a762104186b2887b772a87683c479b |
| e5c-split-join-ats.txt | evidence/inc-13/e5c-split-join-ats.txt | 16a96a94dea75e3215e1b43c4651da2ec47098489d6543e2d2395157206dc144 |
| int-ast-r1.txt | evidence/inc-13/int-ast-r1.txt | de7aad5bb588d879969ddc44d96f99bad27feb2126a72a445040679fcae5c1bb |
| int-lane1-r1.txt | evidence/inc-13/int-lane1-r1.txt | b20b5afa90a88408e2639744f0334d23b505210b1ad089b2e8f0d575ab26e109 |
| int-lane1-r2.txt | evidence/inc-13/int-lane1-r2.txt | af6e23e9ebea8b30663bf4d69a4cf1d8762b01d883e09b5159c6653933eb6b68 |
| int-probe-r1.txt | evidence/inc-13/int-probe-r1.txt | efcc836fb1a8d118574ed33ceda41d0849c035c9c4fe7b9653ddd642b9c4df10 |
| int-serial-r1.txt | evidence/inc-13/int-serial-r1.txt | e0ef79627dbf1eaba8a4045d8e2c597ff29f7bf2e478580f29bba5c09642f5c2 |
| int-serial-r2.txt | evidence/inc-13/int-serial-r2.txt | 892a2f6f6d761e19bdf173c13c8f31851bc9e36319c84c5b1f091016cd64e856 |
| int-serial-r3.txt | evidence/inc-13/int-serial-r3.txt | c831d06d90b07dbbf21d975b8dc7e2f93a228120a006bc910d617416172ba4c1 |
| mut-M-1.txt | evidence/inc-13/mut-M-1.txt | e8c0feed6e8ce1dae3e5bc0cf6594824e05f7bccfe5d72ef15f7dc3834aaa374 |
| mut-M-2.txt | evidence/inc-13/mut-M-2.txt | 58a35019f0f56540e738964eb6b705aaf601ba523e628a09ff2c766c96fc3b39 |
| mut-M-3.txt | evidence/inc-13/mut-M-3.txt | 5905dc7cd2a8e0249e65e85f5e1d809b4954af2427840c5bc0ab87fb880a28d4 |
| mut-M-4.txt | evidence/inc-13/mut-M-4.txt | 23d801b452aec5798e6a98292a4bfcf8e0109aea49d55270d5c0ff1a094f44e1 |
| mut-M-5.txt | evidence/inc-13/mut-M-5.txt | 91b32a90d3b962876daf4b2547baf3e560d51e6b599dc2d112803c53c427a97b |
| mut-M-6.txt | evidence/inc-13/mut-M-6.txt | d29782fb203002b9390aad647f106ca8f3611325ff3104bc1b7c0505bae18b80 |
| mut-M-7.txt | evidence/inc-13/mut-M-7.txt | be04adde14a5f039097b5c413f6142b5e3f47f8d13c79ff44572c19cd3b85fe2 |
| mut-M-8.txt | evidence/inc-13/mut-M-8.txt | 3895630a9bc9ec3b3879d5bd45e4dc778d835fb872641a3da93053305b223833 |
| mut-M-9.txt | evidence/inc-13/mut-M-9.txt | 7a4e0a815bac2d454a0871c3b38b47fab2906513283efe444b7ced1312057fdd |
| mut-M-10.txt | evidence/inc-13/mut-M-10.txt | 3763b1eb17b92e2de4e5ccf903ee84ccbf7d4d4c0dd16bd54b361edc9165c2b9 |
| mut-M-11.txt | evidence/inc-13/mut-M-11.txt | 600f92ebf38da2c4c43e1d51821e282cdb5e1451d33228a4c3681744c9f28e77 |
| mut-M-12.txt | evidence/inc-13/mut-M-12.txt | 414e0e388b2b9ffe4e480753d454ec22cf72b1f5595088980efd879838c97dbd |
| mut-M-13.txt | evidence/inc-13/mut-M-13.txt | b9e8ef5430aeb34b4658f13ca293a112ae5ad29244940d8a2814e500561c15d4 |
| mut-M-14.txt | evidence/inc-13/mut-M-14.txt | d491213662e87da1aaea04646a91ba7c96d4b883d1b6aa6e49e7a274bf8c5d06 |
| mut-M-15.txt | evidence/inc-13/mut-M-15.txt | 86bd0ab8ed8ab09718379bee316c8b10c42d14e10750f42b429c6f5ae2a2efab |
| mut-M-16.txt | evidence/inc-13/mut-M-16.txt | 2878d434d20c62089961a54c8ede058ff8ae4b93cc08906a6ce034221a1b71d1 |
| mut-M-17.txt | evidence/inc-13/mut-M-17.txt | d7af1d55502364a10c48ed86f2c50d4ad97f65f2b1281cdbb4eb242c74662952 |
| mut-M-18.txt | evidence/inc-13/mut-M-18.txt | 32fd7dca2dd9f0508dbc75b4ffea40e20796349167e386d2fd22a20f6b76ca23 |
| mut-M-19.txt | evidence/inc-13/mut-M-19.txt | 4f72afbd74b50fa7cdef0b8af4f5f11979f483885ac35fc6cde4a3d04fecd35d |
| mut-M-20.txt | evidence/inc-13/mut-M-20.txt | 33ccf6653fb9eaa3c94869d5884f7e50e0dde37a5409bf52630c8bbc782c1b8e |
| mut-M-21.txt | evidence/inc-13/mut-M-21.txt | 7ba2c7a7c6abc12ee5e3d272612982e01b2d74da22fa42ea6e798248836c3c2e |
| mut-M-22.txt | evidence/inc-13/mut-M-22.txt | 802e5e0484dc9bb155c3101813d0e321c6a9b946521cfcbc930c9df59d15b924 |
| mut-M-23.txt | evidence/inc-13/mut-M-23.txt | 2d09a6046a9647da44ac7ed5ba071192b335c83f95f9dd0ed373b1585ca61a8d |
| mut-M-24.txt | evidence/inc-13/mut-M-24.txt | 4a54852a4d0bfa04c224b74cbdf49e99253d6d3b729e7b0472190d9816d31fbd |
| mut-M-25.txt | evidence/inc-13/mut-M-25.txt | 1a765fa15050c26b20dc8875fc019c05d6ac6a36577ef4982f4d3a15f9a94d37 |
| red-01-tester-base.txt | evidence/inc-13/red-01-tester-base.txt | ca8ec10993ec2d134aca80b0121774d3af5dd250db20687784f71fe2bc37f351 |

| Field | Value |
|---|---|
| **Evidence files** | 54 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names (`repo:.dev-flow/2026-11-01-batch-101/evidence/inc-13/`) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: the D-2 AST check asserts the 12 nodes and 3 helpers of `tests/test_crc_designer_view.py` differ from base only by the inserted waits; the reference-copy check asserts `tests/support/b101_inc13_reference.py` is verbatim `b7b77c4:288-351` |
| If the result is an ABSENCE, what made the search wide enough | the AST check compares `ast.dump` of every top-level function of the module against the base body after stripping the two inserted statement shapes; the reference diff is a full text diff against `git show b7b77c4:…` lines 288–351 |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits` (names any other drifted function); the verbatim-reference diff (the band invariance oracle) |
| Conjunctive criteria: one mutation per conjunct | M-24 (a D-2 site that also drops one oracle assertion) is a single mutation and is KILLED by the AST check |
| Synthetic instance of the absent case | M-24 plants a drifted node; the AST check's control node proves it can fail on synthetic sources (`int-ast-r1`, `e5c-ast`) |
| **Positive control for every probe that returned an ABSENCE** | the AST check's control node (RED on a planted drift, GREEN on the real module); M-24 KILLED (`mut-M-24.txt`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1: who asserts the new symbols | `grep -rn "CRC_RECOMPUTE_S\|_compute_coverage\|_CoverageRun\|_REFLECT8\|reference_sweep\|_conflict_marks" tests/` | asserted by the three new test files, the kernel differential tests and the verbatim reference; `_sweep`/`_conflict_marks` are called only by `build_plan` (checked in `E1-slice.md` §1) |
| B2: files moved | `git diff --name-status main...HEAD -- s19_app tests` | no file moved; all edits are in-place or new paths |
| B3: goldens | n/a | no golden is touched by this increment |
| A3: `s19_app/` interface | `E1-slice.md` §1 | no public signature changes; `build_plan`, `CrcAlgorithm.compute`, `compute_target_crc`, `evaluate_target` keep theirs |

| Field | Value |
|---|---|
| **Reverse census** | B1: the new product symbols are pinned by the three new test files and the kernel differential tests; the band functions have only `build_plan` as caller · B2: no file moved · B3: n/a (no golden) · A3: no `s19_app/` public signature changed (3 source files, in-place edits) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 8 corrections, each enumerated in `E5-rulings.md` before its first site was edited: C-1 (`_state_text` conflict-before-guard + its tests and the R-SEG-PREV.20/1 flip), C-2 (`_sweep` hand examples), C-3 (timing 5/5 + R-SEG-PREV.7/.20 results), C-4 (audit marks: 007.2/1, 007.3/1, 001.1/1, the substring-only nodes), C-5 (M-12 dropped), C-6 (cap 16777216 everywhere; the 001.1 test widened; the swapped base times), C-7 (the 5 uncovered clauses + the 7 black-box ATs), C-8 (CR-3, CR-4, CR-5, security F-2 accepted) |

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** → re-review **PASS** at `3e01603` — round 1 found E5-CR-1 (E4-F1 MAJOR design-gap, `_state_text` GUARD-before-conflict), CR-2 MINOR, CR-3 … CR-5 NIT; the re-review closed E5-CR-1 on the diff (order matches canon .7/.8, RED fails for the right reason in `e5c-c1-red`), CR-3/CR-4/CR-5, with two LOW notes (RR-1 pre-existing unreachable, RR-2 records for the requirements session) — `E5-code-review.md` §Re-review. `security-reviewer` (E5) · **PASS-WITH-NOTES** — 0 HIGH, 0 MEDIUM, LOW 2 (F-1, F-2), INFO 3 (F-3 … F-5); every ruled-in mitigation `executed` and `approved` by probe — `E5-security.md`. **Design reviews (E3, code-free):** `architect` round 1 **FAIL** (2 MAJOR A-1/A-2, 6 MINOR) → round 2 **PASS-WITH-NOTES** (the 16 MiB cap addendum) · `security-reviewer` **PASS-WITH-NOTES** (SEC-1 … SEC-10) — `E3-architect.md`, `E3-security.md`, `E3-rulings.md`. **Independent tester (E4):** wrote the Designer/band/perf tests from the design records only; its base RED is `red-01-tester-base.txt` — `E4-tester-notes.md`. **Coverage audit by `qa-reviewer` (E5):** first audit 17 of 39 cases changed (43.6 %); re-audit at `3e01603` closed every §1–§5 issue except 001.2.1/3 and 007.3/2 (partial) and two wording notes; final totals 49 covered / 3 partial / 0 gap over 52 cases — `E5-coverage-audit.md` §Re-audit. **There WAS a re-review (E3 round 2 and the E5 code re-review), because each round 1 blocked.** |

## 5. Risks

- The 5/5 serial runs were not on a quiet host (another session's `-n 4` lane ran throughout, load 3.7–4.6). A pass under load is conservative for an upper bound; every worst margin is ≥ 37.7 %.
- M-25 (base `crc_lut` restored) is killed only by its timing arm (3.561 s vs 3.0 s, −18.7 % margin) — the least robust of the four timing controls.
- 007.2/1 and 007.3/1 still decide on a fixed `pilot.pause(1.5)` (the §2 residual); a stalled loop could give a false pass under M-5/M-6.
- The security F-1 shape (alternating pad/non-pad 16 MiB image) is 3.6 s vs base 2.2 s; routed with the existing band-cell backlog item (SEC-7).
- The coverage audit re-audit marks 001.2.1/3 and 007.3/2 partial (their waits span the injected quiet time), not gap; they still pass.

## 6. Pending

- **The full suite at batch end.** The E5 lane ran the slice-covering set, not the whole battery.
- **`test_tc_b97_69_page_keys_do_nothing_where_disabled`** — the "A2L loaded did not settle" flake, failed once under load, passed 3/3 alone; cause not established; in `BACKLOG-CODE.md`.
- **Requirements-session records** — `docs/requirements/review/S17-ears-strict.md:279` and `CODE-CHANGES.md` D17-27 still describe the old state-line order; the notice half (R-SEG-EXP.3) stays open.
- **Security F-1 (LOW, with SEC-7) and F-3 (INFO, pre-existing)** — routed to `BACKLOG-CODE.md`.
- **D-4 (in-place-apply staleness)** — routed to Inc 5 (first in the `app.py` chain), recorded in PLAN.
- The uncommitted records (this packet, `04-validation.md`, the re-review / re-audit sections, the `02-test-cases.md` / `E1-rulings.md` re-audit edits) are to be committed by the orchestrator — nothing here is committed by this record.

## 7. Suggested next task

Commit the E5 records, then run the full suite at batch end to close the full-battery debt and re-check `test_tc_b97_69`; hand the requirements session the S13/S17 canon changes (the R-CRC-DESIGNER-001.2 split, the new rows, the CTX terms, and the D17-27 state-line record updates).
