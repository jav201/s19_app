## Inc 6 — Review Packet

### 1. What changed
The shared Check/Patch A2L picker now uses declared whole-object length and element datatype format. Missing lengths stay missing and refuse Patch Use and Check Validate/Write instead of becoming one byte. Patch gains the same include/bulk selector as Check, with picker-local selection only. Names, datatypes and units render literally with control replacement and bounded layout; the narrow Patch layout preserves every control and full status text.

### 2. Files modified
- `s19_app/tui/a2l_parameter_picker.py` — declared length, one-batch I-2 definitions, literal rendering and compact controls.
- `s19_app/tui/screens_directionb.py` — panel handoff, Patch bulk host, missing-length guards and responsive layout.
- `tests/test_b103_picker_model.py` — 44 model/format cases.
- `tests/test_b103_picker_editor.py` — 33 editor/bulk/geometry cases, including Check’s new refusal.
- `tests/test_b102_patch_picker.py`, `test_b102_parameter_picker.py`, `test_b102_bulk_add.py`, `test_b101_check_spec_keep.py`, `test_tui_check_editor.py` — historical fixtures and spies updated for the new contract.
- `tests/test_b103_a2l_reader_coverage.py` and Inc 11’s ledger — the remaining historical format oracle now follows element datatype rather than the removed `or 1` fallback.
- `tests/test_id_registry.py` — declared test-module bound advanced to 299.
- `.dev-flow/2026-11-05-batch-103/inc-6/**` and `evidence/inc-6/**` — approved design, test ledger and proof.

### 3. How to test
Run on Linux with the `s19ci` interpreter, isolated state directories, closed stdin and bytecode disabled:

```bash
python -I -B run_inc6_green.py
python -I -B run_inc6_historical.py
python -I -B run_inc6_laws.py
S19CI_PYTHON=/home/<runner>/miniconda3/envs/s19ci/bin/python python -I -B run_21_mutants.py
```

Each runner inserts `.` into `sys.path` and prints `s19_app.__file__` before pytest. The mutant runner works only in copies.

### 4. Test results
- Base RED: model **33 failed / 11 passed**; editor **29 failed / 2 passed**.
- Final family: **77 passed in 396.51 s** (`evidence/inc-6/final-functional-green.txt`).
- Addendum: **4 passed**; focused geometry: **6 passed**.
- Mutants: **21 killed / 0 survived / 0 errors / 0 timeouts / 0 BAD** (`evidence/inc-6/mutant-summary-final.json`).
- Law guards: **550 passed, 3 skipped, 1 inherited redaction failure** (`evidence/inc-6/law-guards.txt`). Official Inc 6 redaction scan: **0 hits**; inherited Inc 12 and `inc-2/steps.log` were not changed.
- Historical first pass: **303 passed / 1 failed**; corrected fixture: **1 passed**; final historical family: **304 passed in 2900.05 s** (`evidence/inc-6/historical-green.txt`). The failure was the stale `u8` oracle, not a product defect.
- Independent reviews: code PASS, security PASS, coverage PASS-WITH-NOTES.
- Detached merge clone `c062293b`: **77 passed in 387.08 s** (`evidence/inc-6/merge-functional.txt`); Inc 6 and whole-batch traces both **0 gaps** (`evidence/inc-6/merge-trace.txt`).

### 5. Risks
- `.021/1-2` are only `partial`: direct handler behavior is proven, but mounted `run_test` acceptance is not. Mounted attempts stalled; no such acceptance is claimed.
- The complete repository suite is running in eight sequential chunks on the merge clone, launcher PID 596133. Its result is pending and must not be called full-suite PASS; G3 remains open. By operator amendment this does not block integration or main push.

### 6. Pending items
- Collect and redact the full-suite logs and summary, rule any findings into the next batch, then resume with Inc 1b. Do not start Inc 1b in this session.

### 7. Suggested next task
Inc 1b — Clipboard: copy from every view, using the approved PLAN row and existing clipboard/Windows conventions. Do not begin it in this session; resume from the handoff after Inc 6 closes.
