## Inc 3a — Review Packet

### 1. What changed

The pure A2L definition model now describes and decodes VAL_BLK/MATRIX_DIM arrays, curves and maps, including STD/FIX/COM axes, exact FIX-point arithmetic, element/axis offsets, shared immutable read forms and bounded one-lookup conversion. The synthetic definitions case adds one AXIS_PTS record, two curves, one map and one VAL_BLK. No UI or write-side Inc 3b behavior is included.

### 2. Files modified

- `s19_app/tui/a2l_definition.py` — array/axis definitions and decoding, shared reduced forms, span and memory guards.
- `tools/synth/make_release_case.py` — deterministic array/axis fixture generation.
- `tests/support/b103_a2l_arrays.py` — synthetic INLINE3 builders.
- `tests/test_b103_a2l_definition_arrays.py` — kinds, shapes, layouts, axes and FIX cases.
- `tests/test_b103_a2l_definition_arrays_decode.py` — element/axis decoding, synth and acceptance arms.
- `tests/test_b103_a2l_definition_arrays_coverage.py` — read-once, immutability, echo and conversion controls.
- `tests/test_b103_a2l_definition_arrays_scale.py` — full serial scaling measures and clock regression.
- `tests/test_b103_a2l_definition_arrays_fix_cap.py` — the two FIX-at-cap cases.
- `tests/test_b103_a2l_definition.py`, `tests/test_b103_synth_definitions.py` — D-14 and array-aware synth contracts.
- `tests/test_id_registry.py` — scanned corpus bound 288 → 294.
- `.gitattributes` — byte preservation for increment transcripts and `steps.log`.
- `.dev-flow/2026-11-05-batch-103/inc-3/02-test-cases.md` — final case/evidence ledger.
- `.dev-flow/2026-11-05-batch-103/inc-3/04-validation.md` — E5 verdict and evidence index.
- `.dev-flow/2026-11-05-batch-103/HANDOFF-2026-11-09-KIMI-INC3A-E4.md`, `inc-3/steps.log`, `inc-3/evidence-*.txt` — handoff and run records.

### 3. How to test

From a committed Linux checkout with the `s19ci` interpreter and an explicit `sys.path.insert(0, checkout)`:

```bash
python -I -B -m pytest -q -m "not serial_timing and not slow" \
  tests/test_b103_a2l_definition.py \
  tests/test_b103_a2l_definition_arrays.py \
  tests/test_b103_a2l_definition_arrays_decode.py \
  tests/test_b103_a2l_definition_arrays_scale.py \
  tests/test_b103_a2l_definition_arrays_coverage.py \
  tests/test_b103_synth_definitions.py
python -I -B -m pytest -q -m serial_timing \
  tests/test_b103_a2l_definition_arrays_scale.py \
  tests/test_b103_a2l_definition_arrays_fix_cap.py
python -I -B -m pytest -q tests/test_b103_a2l_definition_perf.py
python -I -B -m pytest -q tests/test_b103_synth_definitions.py
```

Print `s19_app.__file__` before each transcript and isolate HOME/XDG/LOCALAPPDATA. The FIX cap cases have an external 60-second timeout per case. Mutants run only in isolated copies with their discriminating tests.

### 4. Test results

- Functional: **471 passed, 35 deselected** (`../evidence/inc-3/evidence-e5-green-final.txt`).
- Final RED on base: **269 failed, 6 passed, 34 deselected**, no fixture errors (`../evidence/inc-3/evidence-e5-red-final.txt`).
- Array timing: **33 passed, 1 deselected; 96 bounds, 0 under 20 % margin** (`../evidence/inc-3/evidence-e5-timing-final.txt`).
- FIX cap: **0.090 / 1.000 s, 1.2 MiB** and **0.514 / 5.000 s, 63.5 MiB** (`../evidence/inc-3/evidence-e5-fix-cap5-green.txt`, `../evidence/inc-3/evidence-e5-fix-cap6-green-fixed.txt`).
- Scalar performance: **22 passed; 52 bounds, 0 under 20 % margin** (`../evidence/inc-3/evidence-e5-scalar-perf.txt`).
- Synth: **3 passed** including slow/determinism; full file **9 passed** (`../evidence/inc-3/evidence-e5-synth-cited.txt`, `../evidence/inc-3/evidence-e5-synth-final.txt`).
- Law guards: **375 passed, 1 skipped**, then TC-027 **1 passed**; final ID/engine selection **13 passed** (`../evidence/inc-3/evidence-e5-lawguards-laptop-final.txt`, `../evidence/inc-3/evidence-e5-tc027-laptop.txt`, `../evidence/inc-3/evidence-e5-id-registry-final.txt`).
- Mutants: **103 KILLED, 0 open survivors** across A, B and supplemental runs (`../evidence/inc-3/evidence-e5-mutants-A-final.txt`, `../evidence/inc-3/evidence-e5-mutants-A-M141.txt`, `../evidence/inc-3/evidence-e5-mutants-B-run.txt`, `../evidence/inc-3/evidence-e5-mutants-extra-run.txt`, `../evidence/inc-3/evidence-e5-mutant-M148-reduce.txt`).
- Reviews: code/security/final re-review **PASS-WITH-NOTES**; final coverage has 275 full + 5 partial and no unrun 3a arm.

### 5. Risks

- Multiple FIX forms use PAR > PAR_DIST > PAR_LIST precedence; no corpus object declares more than one and there is no explicit multi-form case.
- A hostile MATRIX_DIM line with very many words can exceed the aggregate message bound of 1,024 characters, although each word is capped. This is a LOW design-gap.
- A truncated FIX form can use the no-points refusal rather than cannot-read wording; no crash and no pinned case.
- Timing and memory results are valid on `<runner>` / Python 3.11.18, not a Windows performance claim.
- Several controls are timing-only or non-discriminating and are listed in the mutant reports rather than counted as kills.

### 6. Pending items

- Inc 3b: 42 write-side cases and the five mixed edit arms.
- Integration into `batch-103`. Final committed-clone trace is accepted: 12 TEST gaps, all Inc 3b, and no Inc 3a/EVID gaps (`../evidence/inc-3/evidence-e5-trace-check-final.txt`).
- Full repository suite and requirements-canon fold at batch end.
- Inc 12 real Windows Terminal captures at 80, 118 and 220 columns with operator approval.
- `origin/main` remains unchanged until the whole batch is green.

### 7. Suggested next task

**Inc 12 — A2L tag table:** separate Address and Length, cap Tag without gluing or cutting values, and capture the real Windows Terminal at 80, 118 and 220 columns for operator review.
