# Inc 2b — Review Packet

## 1. What changed

The scalar A2L model now encodes numbers, enum texts and printable ASCII into whole-span bytes, preserves unedited bits under masks, applies limits, extended limits and precision checks, refuses parse errors and shared writes, and describes overlaps in cross-kind file order. The overlap index uses 16-byte pages, restores global order across pages, handles BLOB/INSTANCE fail-closed and never grants them a homonymous tag's mask exemption. Inc 2a read-side evidence is retained; the combined increment has 321 active cases = 216 + 105.

## 2. Files modified

- `s19_app/tui/a2l_definition.py` — scalar encode model and overlap guard; final product commit `e0f4553e`.
- `tests/test_b103_a2l_definition.py` — scalar-write, round-trip, hostile and overlap cases.
- `tests/test_b103_synth_definitions.py` — generated scalar write acceptance.
- `.dev-flow/2026-11-05-batch-103/inc-2/01-requirements.md` — final case thresholds and negative controls.
- `.dev-flow/2026-11-05-batch-103/inc-2/02-test-cases.md` — 321-case ledger with final RED/GREEN evidence.
- `.dev-flow/2026-11-05-batch-103/inc-2/codewire/graph-inc2.md` — final Code-Wire contracts.
- `.dev-flow/2026-11-05-batch-103/inc-2/04-validation.md` — combined validation record.
- `.dev-flow/2026-11-05-batch-103/inc-2/evidence-e4/` and `evidence-e5/` — test, performance, review and mutant evidence.
- `.dev-flow/2026-11-05-batch-103/evidence/inc-2/` — canonical final evidence and hashes.

## 3. How to test

Run on the Linux runner from the integrated tree, with isolated state and bytecode writing disabled:

```bash
python -I -B -m pytest -q -p no:cacheprovider \
  tests/test_b103_a2l_definition.py tests/test_b103_synth_definitions.py
python -I -B -m pytest -q -p no:cacheprovider tests/test_b103_a2l_definition_perf.py
python -I -B -m pytest -q -p no:cacheprovider \
  tests/test_requirements_canon.py tests/test_id_registry.py \
  tests/test_engine_unchanged.py tests/test_suite_hygiene.py \
  tests/test_report_markup_safety.py tests/test_filename_markup_safety.py \
  tests/test_tui_insight_style.py tests/test_entropy_style.py \
  tests/test_docs_canon.py tests/test_b101_doc_hygiene.py tests/test_tui_directionb.py
```

Run performance three times serially. Run the real stub and the 34 mutants only in copies, never in the worktree. The final driver is `evidence-e5/run_2b_mutants.py`; its output and per-mutant diffs are in `evidence-e5/mutants-2b/out/`.

## 4. Test results

- `322 passed in 15.50s` — model and synth, `int2b-run14-main.txt`.
- `125 failed, 197 passed in 29.24s` — real encode/shared-with stub; all 125 expected RED cases, `int2b-red-stub-final9-main.txt`.
- `1 failed, 309 deselected` — removal of only the homonymous-mask guard, `int2b-red-homonym-guard.txt`.
- `22 passed` in each of three performance runs; 52 bounds, 0 under 20% margin; `.136` 1.400–1.403 s / 2.000 s.
- `34 killed / 0 survived / 0 not realisable` — final mutant battery.
- `505 passed, 1 skipped in 702.97s` — canonical law guards, `int2b-lawguards-final4-57b.txt`.
- `1 US, 73 active requirements, 0 gaps` — trace check.
- Code review **PASS**; security and coverage **PASS-WITH-NOTES**, with no HIGH/MAJOR open.
- Windows was used only for `py_compile`, static review and trace checking. No Windows runtime, UI, clipboard or snapshot claim is made.

## 5. Risks

- Performance bounds are valid on <runner>, Python 3.11.18, only.
- Bidi and other Unicode format characters remain in model strings by contract; Inc 8/9 must isolate or filter them in the renderer.
- The specific homonymous RED stops at BLOB; INSTANCE is covered by GREEN and the shared guard, not by an independent RED arm.
- `_SCALAR_DEFC` is manually enumerated; a future scalar added to the generator must be added there or protected by a census assertion.
- Seventeen mixed ledger rows cite only their encode node, although their older describe/decode nodes also run in the suite.
- Masked writes perform a redundant image-byte check; this is overhead, not a correctness defect.

## 6. Pending items

- Full suite and requirements-canon fold: batch end.
- Inc 3b arrays/axes writes, then Inc 5 and 6, followed by 1b/10/7/8/9 according to the approved order.
- Final batch review and G3 precede any merge or push to `main`.

## 7. Suggested next task

**Inc 3b — re-review the approved array/axis write design against Inc 2b, then implement and validate `encode_values`, `_breaking_point` and AXIS_PTS overlap indexing.** The operator's standing instruction authorizes continuing the battery after this packet; no gate is waived.
