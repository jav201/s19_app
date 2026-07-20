# Validation — s19_app — Batch-50 (a2l.py F841 cleanup)

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the Phase-1 validation strategy (§4.9 registry, §5.2). Gate suite is orchestrator-owned (C-25); this artifact CONSUMES that run — not re-executed here.

## ✅ Verdict (read first)

- **Result:** **PASS**
- **Requirements:** `2`/`2` active-scope pass · `0` blocker fails. (PR-A active scope = {R-A2L-010 / F841}; R-A2L-009 / P-2 is post-merge PR-B — see §P-2 status. R-A2L-008 / P-1b DEFERRED, no Phase-4 obligation.)
- **Black-box acceptance (Layer B):** ✓ the one output-producing story (US-F841) has its deliverable — the enriched tag set — observed through the shipped surface `parse_a2l_file` with boundary + negative evidence (AT-094).
- **Surface-reachability (bidirectional):** ✓ input (raw demo A2L via `parse_a2l_file`) AND output (enriched tag fields: count + MEAS length/datatype + CHARACTERISTIC char_type/length) both reached/observed at the surface. No gaps.
- **Supersession inspection:** ✓ the deleted `header` local has zero surviving references in the walk closure; ruff F841=0 is the absence proof.
- **Test ledger:** ✓ reconciles (`1591 − 0 + 2 = 1593` passed).
- **Evidence checklist (qa-reviewer):** ✓ complete (see final section).

> Every line above is ✓. The Detail below is reference. Gate verdict: **APPROVE PR-A.**

---

## Detail (reference)

### Layer A — functional (white-box): per-requirement results

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-F841 / R-A2L-010 | test + inspection | `ruff check --select F841 s19_app/tui/a2l.py` | `0 errors` (pre: 1) | **pass** | `0` errors; pre-fix RED = 1 F841 at `a2l.py:942` captured at Phase-0 recon (orchestrator gate run). |
| LLR-F841.1 | test (TC-094) | `pytest … tests/test_a2l_f841_cleanup.py::test_tc094_no_f841_finding_in_a2l` | ruff F841=0 | **pass** | node passed (1 of 2 in the file); skips (not silent-pass) if ruff absent — reviewer-confirmed honest. |
| HLR-P2 / R-A2L-009 (LLR-P2.1/P2.2, TC-095/096) | test + inspection | *(post-merge PR-B)* | guards green + empty `git diff main` | **DEFERRED — post-merge PR-B** | Un-runnable in PR-A: a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard. NOT a Phase-4 blocker for PR-A. |

Supporting gate evidence (orchestrator-owned, C-25 — cited, not re-run):
- Full gate `pytest -q -m "not slow"`: **1593 passed, 2 skipped, 20 deselected, 3 xfailed, 0 failed** in 1127.26s (exit 0); **29 snapshots passed, no drift**.
- Frozen guards tc031/tc032/`test_tc027` → **10 passed** (a2l.py legitimately UNFROZEN this batch; the sanctioned edit does not trip — expected, P-2 re-freeze is PR-B).
- C-34 full guard-host `test_tui_directionb.py` → **174 passed** (exit 0); no markup-guard escape (contrast batch-49 Inc-1).
- Independent `code-reviewer` → **APPROVE, 0 findings**; re-derived all AT-094 pinned literals (75 / 25 / 50 / 24 / ASCII / 100).

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-F841 | `AT-094` → `tests/test_a2l_f841_cleanup.py::test_at094_demo_parse_stable_after_dead_store_removal` | `parse_a2l_file(ASAP2_Demo_V161.a2l)` (public parse surface — the shipped API a TUI load routes through) | Enriched tag set: **75** total tags · **25** MEAS · **50** CHARACTERISTIC · **24** MEAS-with-length (all carry datatype) · the parsing CHARACTERISTIC `ASAM.C.VIRTUAL.ASCII` → char_type **ASCII**, length **100** | ✓ repr (full demo tag set) · ✓ boundary (24 length-bearing MEAS + the 100-byte ASCII CHARACTERISTIC exercise the length/char_type edge) · ✓ negative (loud sentinel — a delete that had caught a live line diverges the tag set / `header_meas`/`header_char` propagation) | **pass** |

The deliverable is OBSERVED (the actual enriched field values are asserted), not merely the mechanism (the walk closure) exercised. AT-094 drives the shipped parse surface and pins the produced tag fields — a silent deliverable absence would fail it.

### Bidirectional surface-reachability matrix

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | raw demo A2L source | `parse_a2l_file(path)` (public parse entry) | yes — parsed from the on-disk `ASAP2_Demo_V161.a2l` fixture through the public API | `AT-094` | ✓ |
| output | enriched tag **count** (75 / 25 MEAS / 50 CHAR) | `extract_a2l_tags` walk (the closure whose dead store was removed) | yes — asserted on the returned tag collection | `AT-094` | ✓ |
| output | MEAS **length + datatype** (24 length-bearing, datatype present) | length-inference at former `a2l.py:1055/1058` consuming `header_meas` | yes — field values asserted | `AT-094` | ✓ |
| output | parsing CHARACTERISTIC **char_type + length** (`ASAM.C.VIRTUAL.ASCII` → ASCII / 100) | CHARACTERISTIC enrichment consuming `header_char` | yes — field values asserted | `AT-094` | ✓ |

Every named input AND every named output/deliverable is observed through the parse surface, not only via an internal service call. The removed `header` local sat between `header_meas`/`header_char` (inputs to the length calls) and these observed outputs — parity across all four output fields is the proof the store was dead.

### Supersession-completeness inspection

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `header = header_meas or header_char` (dead local, former `a2l.py:942`) | 0 hits of the bare-`header` local in the `extract_a2l_tags` walk closure | yes (absence) | `ruff check --select F841 s19_app/tui/a2l.py` → 0; reviewer grep confirmed only `header_meas`/`header_char` read at `:975`,`:981`,`:1055`,`:1058`; the `header` **kwarg** in `test_a2l_record_layout_length.py` / `_infer_length_characteristic` is an unrelated parameter (C-26 reverse-census clean). |

### Signed-balance test ledger

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| 1591 | 0 | 2 | 1593 | 1593 passed (+2 skipped, 20 deselected, 3 xfailed) | 1593 (full `-m "not slow"`) | **yes** |

`+A` = the 2 new nodes in `tests/test_a2l_f841_cleanup.py` (TC-094 + AT-094). `−D` = 0 (no test deleted; the source change removed one line, not a test). Post = 1593 passed, exit 0, 0 failed.

### Gaps detected

None. (No blocker, major, or minor gap in active PR-A scope.)

### Escaped-bug regression

Not an escaped-bug batch — this is a proactive dead-store cleanup, not a fix for a defect that slipped the suite. The counterfactual analysis for the new tests is below.

| Regression id | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|---------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| `TC-094` | `ruff --select F841 s19_app/tui/a2l.py` reported **exactly 1** F841 error at `a2l.py:942` (captured Phase-0) → RED on pre-fix state | value (a specific finding count 1→0, not a shape/import error) | n/a — TC-094 asserts an analyzer count (0), inherently value-discriminating (a spurious 0 pre-delete would have failed against the real 1) | pass (0 errors) | `test_a2l_f841_cleanup.py::test_tc094_no_f841_finding_in_a2l` |
| `AT-094` | Non-vacuous by construction: a delete that had caught a **live** line would diverge the demo tag set (loud sentinel on `header_meas`/`header_char` propagation) | value (pinned field literals 75/25/50/24/ASCII/100 discriminate the real produced values) | yes — literals independently re-derived by the reviewer; a wrong-but-well-typed tag set fails the assertions | pass (byte-identical parity) | `test_a2l_f841_cleanup.py::test_at094_demo_parse_stable_after_dead_store_removal` |

**Certainty note (V-5 reconciliation, C-18):** each provisional id maps to EXACTLY ONE on-disk collected node — AT-094 → `::test_at094_demo_parse_stable_after_dead_store_removal` (behavioral, black-box through `parse_a2l_file`); TC-094 → `::test_tc094_no_f841_finding_in_a2l` (functional/analysis). No "covered in parts"; both collected and passed (not skipped) in the gate run.

### P-2 / AT-095 status — DEFERRED to post-merge PR-B (NOT a PR-A blocker)

`R-A2L-009` / HLR-P2 (re-freeze `a2l.py` into the C-27 dual-guard set) and its acceptance `AT-095` / TC-095 / TC-096 are **un-runnable in PR-A** and are intentionally excluded from this Phase-4 gate:

- A same-PR re-freeze re-adds `a2l.py` to `_ENGINE_PATHS` while `a2l.py` still diffs vs `main` (it carries this batch's F841 edit) → `git diff main -- a2l.py` is non-empty → the frozen-guard self-trips RED. The requirement is only satisfiable **after** PR-A merges, when merged source == `main` source.
- Therefore P-2 executes as **follow-up PR-B (guard-files-only)**, gated on PR-A merge. AT-095 (guards green + empty `git diff main -- a2l.py`) and TC-096 (tc032 stays green; no batch-50 test in the frozen file) are validated there.
- This is a correct requirement/reality sequencing constraint recorded in Phase-1 (§4.9 "Sequencing flag", §6.4), not an unmet acceptance. **PR-A ships without it.**

### P-1b status — DEFERRED to a future batch (no Phase-4 obligation this batch)

`R-A2L-008` / US-P1b (CURVE/MAP/axis inline length derivation) was descoped at the Phase-2 gate (operator 2026-07-19): the length logic is sound but fires on nothing in real multi-line A2L until multi-line CHARACTERISTIC/AXIS_DESCR header parsing ships first (a core-parser prerequisite outside "tight cleanup" scope). AT-090..093 / TC-090..093 were retired with it. Verified future-batch seed retained in `01-requirements.md` §7. **No Phase-4 test obligation in batch-50.**

---

## Evidence checklist — qa-reviewer (full)

- [✓] **Acceptance criteria use Given/When/Then / observable-outcome form** — AT-094 states Given demo A2L, When parsed via `parse_a2l_file` after the dead-store delete, Then the enriched tag set is byte-identical (75/25/50/24/ASCII/100) and `ruff F841==0`.
- [✓] **Test cases have explicit Expected, not vague "works"** — TC-094 Expected = ruff F841 `0` errors; AT-094 Expected = the six pinned field literals. Cited: increment-001 §4.
- [✓] **Edge cases include empty, boundary, invalid, error** — proportionate to a 2-test dead-store batch: boundary = 24 length-bearing MEAS + 100-byte ASCII CHARACTERISTIC; negative/sentinel = tag-set divergence if a live line were caught. (Empty/malformed-input black-box ATs were tied to the DEFERRED P-1b parsing surface, §7 — not a PR-A surface, justified cut.)
- [✓] **Regression checklist exists** — a2l sibling suites (record-layout-length, missing-length-fix, enriched, tui-a2l) → 39 passed / 2 pre-existing skips; frozen guards tc031/tc032/tc027 → 10 passed; C-34 host `test_tui_directionb.py` → 174 passed; 29 snapshots no drift.
- [✓] **Exit criteria stated** — active-scope AT-094 + TC-094 both green, LLR-F841.1 covered, ruff F841=0, gate exit 0, 0 failed → APPROVE.
- [✓] **No real PII / secrets** — fixture-only (`ASAP2_Demo_V161.a2l`, a public demo A2L); no credentials or client data.
- [✓] **Test results left blank unless actually run** — all results here are transcribed from the orchestrator-owned gate run (C-25) and increment-001 §4; nothing fabricated, nothing re-run by qa.
- [✓] **Layer B (black-box)** — US-F841's deliverable (enriched tag set) observed through the SHIPPED surface `parse_a2l_file` with boundary + negative evidence (AT-094), not only white-box TCs on the walk mechanism.
- [✓] **Bidirectional surface-reachability** — input (raw demo A2L) AND all named outputs (count, MEAS length/datatype, CHARACTERISTIC char_type/length) exercised/observed through `parse_a2l_file`, per the matrix above.
- [✓] **No unfilled template** — no remaining `<...>`, `TC-NNN`, or empty required rows; every row carries batch-50 evidence.

**Gate verdict: PASS — APPROVE PR-A.** Active scope (R-A2L-010 / F841) fully validated through the shipped surface with a value-discriminating counterfactual and zero regressions. P-2 (R-A2L-009) correctly sequenced to post-merge PR-B; P-1b (R-A2L-008) deferred to a future batch — neither is a PR-A blocker.
