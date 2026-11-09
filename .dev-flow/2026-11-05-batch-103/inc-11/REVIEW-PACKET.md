## Inc 11 — Review Packet

### 1. What changed

The A2L reader now handles comments, quoted strings, mixed line endings, one-line sections, INSTANCE/BLOB spans and fail-closed length/address rules. E5 corrected full-span precedence (P16), exact TAB_VERB conversion (P17), standing DATA_SIZE/external spans (P18) and READ.52 performance without changing thresholds. Coverage is complete: 81 active requirements, 271 cases + 2 AT, 39 graph nodes, and trace_check reports 0 gaps.

### 2. Files modified

- `s19_app/tui/a2l.py` — lexer, section/tag extraction, conversions, full-span and length logic, bounded performance caches.
- `tests/support/b103_a2l_ref.py` — independent reference-oracle corrections.
- `tests/test_b103_a2l_reader.py` — READ.48 timing protocol hygiene and defect fixtures.
- `tests/test_b103_a2l_reader_e5.py` — P1–P18 discriminating corrective cases.
- `tests/test_b103_a2l_reader_coverage.py` — full supplemental coverage, real app routes and near-TAB_VERB negative exactness.
- `tests/test_b103_a2l_reader_perf.py` — fresh-process timing/memory protocol and one-body-line variant.
- `tests/test_id_registry.py` — scanned-test-file bound.
- `.dev-flow/2026-11-05-batch-103/inc-11/` — requirements, cases, graph, rulings, reviews, mutant tables and validation evidence.

### 3. How to test

On `<runner>`, with the final tree and `B103_BASE_ROOT` pointing to an `e07fb00` checkout:

```bash
cd /tmp/b103-e5-11-mutB-rtx/tree
/home/<user>/miniconda3/envs/s19ci/bin/python -I -B runner.py -q -n 8 \
  tests/test_b103_a2l_reader.py tests/test_b103_a2l_reader_e5.py \
  tests/test_b103_a2l_reader_coverage.py
/home/<user>/miniconda3/envs/s19ci/bin/python -I -B runner.py -q -s -m serial_timing \
  tests/test_b103_a2l_reader_perf.py
/home/<user>/miniconda3/envs/s19ci/bin/python -I -B runner.py -q \
  tests/test_b103_a2l_reader_perf.py::test_r_a2l_read_52_words_no_exception_and_one_error
```

Trace check on the committed clone:

```bash
cd /tmp/b103-e5-11-trace-14fdc3b9
/home/<user>/miniconda3/envs/s19ci/bin/python -I -B trace_check.py \
  --req .dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md \
  --base e07fb00 --src s19_app/tui/a2l.py s19_app/tui/a2l_extract.py \
  s19_app/tui/a2l_definition.py
```

### 4. Test results

- Final integration run 13: **A 332 passed; B 200 passed; C 389 passed + 1 skipped; D 215 passed + 4 skipped** (`int-green13.txt`).
- READ.52 on RTX: **7 passed, 1 deselected**; case_06 **8.411 / 8.843 s (4.9 % margin)**, software_a 11.6 %, all memory arms green.
- READ.65/6 separately: **1 passed**. Direct length-helper callers: **9 passed**.
- Mutant A: **19 KILLED, 1 NOT_REALISABLE, 0 SURVIVED, 0 CRASH**; restored baseline **332 passed**.
- Mutant B: **23 KILLED, 0 SURVIVED, 0 CRASH, 0 BAD**; restored baseline **522 passed + 1 deselected**.
- Coverage: **37 full, 0 partial, 0 gap**, all 37 dynamically verified.
- `trace_check`: **3 US, 81 active requirements, 2 withdrawn, 0 gaps**.
- Reviews: code **PASS**, security **PASS-WITH-NOTES**.

### 5. Risks

- M10 is unreachable through the public reader because universal newlines normalize CR/CRLF. A future raw-element or `newline=""` caller needs a direct test.
- REF still has three latent limitations outside the declared corpus: deposit/layout precedence, count-unit diagnostics and external-axis resolution.
- A quoted positional MEASUREMENT datatype is accepted by the product but not REF; this is a documented permissiveness divergence, bounded by the datatype table.
- Final case_06 margin is 4.9 %, not the earlier 0.2 % laptop margin. Performance evidence is platform-specific.
- Inc 12's UI captures and approval were not part of Inc 11.

### 6. Pending items

- Inc 3a and Inc 12, then the remaining increments in PLAN order.
- H3e remains routed to Inc 3a by CG-4.
- Full repository suite, batch canon fold, combined-tree trace check and final batch review.
- Integration of `b103-inc11-code` into `batch-103`, and only after the remaining batch gates, publication to `main`.

### 7. Suggested next task

**Inc 3a — A2L definition model II: arrays and axes**, including H3e, after integrating Inc 11 into `batch-103`.
