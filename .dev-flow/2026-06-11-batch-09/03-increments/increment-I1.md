# Increment I1 — Byte-run comparison engine (HLR-001)

Batch: 2026-06-11-batch-09 · Phase 3 · branch `claude/batch-09`
Scope: HLR-001 / LLR-001.1..001.5 (TC-001..TC-006)
Status: **IMPLEMENTED — engine + tests all green; BUT 2 pre-existing guard tests now fail (spec/code contradiction surfaced; orchestrator decision required before the gate). See §5 Risks / §6 Pending.**

---

## 1. What changed

Added the headless byte-run comparison engine `s19_app/compare.py` — the pure-data
core of the US-006 image comparison mode. It defines the §6.2 C-9 result
vocabulary (`ImageRef`, `DiffRun`, `DiffStats`, `ComparisonResult`) and the diff
function `diff_mem_maps(map_a, map_b)`, which classifies two sparse memory maps
into maximal contiguous difference runs (`changed` / `only_a` / `only_b`) in
ascending-start order with the LLR-001.2 adjacency rule (two adjacent addresses
share a run iff same classification; equal-byte addresses produce no run), plus
per-classification run/byte statistics. The engine is a single ascending walk
over the sorted key-union (the probe P-15 measured-fine approach). It imports
stdlib only — no Textual, no parser class (LLR-001.1). The engine produces only
`runs`/`stats`; the remaining `ComparisonResult` fields are dataclass-defined
here (this module is their home) but populated by the I2 service.

Added `tests/test_compare_engine.py` — 11 tests covering TC-001..TC-006, each
mapped to its TC/LLR in the module docstring.

No other file was touched.

## 2. Files modified

| File | Status | Purpose |
|---|---|---|
| `s19_app/compare.py` | NEW (~330 lines) | Headless diff engine: C-9 dataclasses + `diff_mem_maps` + per-address classifier. |
| `tests/test_compare_engine.py` | NEW (~270 lines) | TC-001..TC-006 engine tests. |

## 3. How to test

```
python -m pytest -q tests/test_compare_engine.py
python -m pytest -q tests/test_compare_engine.py -m "not slow"   # @slow deselects
python -m pytest tests/test_compare_engine.py -m slow            # perf test only
python -m pytest -q -m "not slow"                                # lean suite
python -m pytest -q --collect-only                               # collection ledger
rg -c "textual|S19File|IntelHexFile" s19_app/compare.py          # LLR-001.1 purity (expect 0)
```

## 4. Test results (exact)

1. `pytest -q tests/test_compare_engine.py` → **11 passed in 1.19s**. Exit 0.
2. `-m "not slow"` on the file → **10 passed, 1 deselected** (the `@slow` perf test
   correctly deselects).
3. `-m slow` on the file → **1 passed, 10 deselected in 1.25s**. The perf test's
   asserted budget is diff-compute `≤ 2.0 s`; the test wall (1.21s) includes the
   end-to-end parse of two `make_large_s19` files. Isolated diff-compute measured
   separately: **134.8 ms** (≈15× headroom under the 2.0 s budget; consistent with
   the spec's probe-P-15 ~201.7 ms walk on this regime: Win 11, Python 3.14.4,
   OneDrive worktree).
4. **Lean suite** `pytest -q -m "not slow"` → **2 failed, 689 passed, 29 skipped,
   21 deselected, 3 xfailed in 216.68s**. The 2 failures are NOT in my files — see §5.
5. **Collection ledger** `pytest -q --collect-only` last line → **744 tests
   collected** (pre-state 733 + 11 new engine tests; D=0, A=11).
6. **Purity probe** `rg -c "textual|S19File|IntelHexFile" s19_app/compare.py` →
   **0 hits** (exit 1 = no match). Orchestrator's import-form probe
   `rg -n "^\s*(from|import)\s+textual|S19File|IntelHexFile" s19_app/compare.py`
   → **0 hits**. (Docstring was reworded to drop the literal symbol names so the
   spec's `rg -c` form reaches 0, matching the `range_index.py` precedent.)

### Per-TC / per-LLR coverage (every named test confirmed present on disk)

| LLR | TC | Test function(s) | Result |
|---|---|---|---|
| LLR-001.1 | — (inspection) | rg purity probe | 0 hits ✓ |
| LLR-001.2 | TC-001 | `test_classification_set_equality`, `test_classification_set_equality_random` | pass |
| LLR-001.2 | TC-002 | `test_adjacency_merge_same_kind_merges`, `test_adjacency_change_forces_boundary` | pass |
| LLR-001.2 | TC-003 | `test_boundary_cases` | pass |
| LLR-001.3 | TC-004 | `test_identity_empty_and_equal`, `test_determinism_repeated_calls` | pass |
| LLR-001.4 | TC-005 | `test_stats_byte_count_equals_run_lengths`, `test_stats_run_counts_match` | pass |
| LLR-001.3/.4 | TC-005 | `test_symmetry_swap_only_a_only_b` (swap symmetry, spec extra) | pass |
| LLR-001.5 | TC-006 | `test_large_image_perf` (`@pytest.mark.slow`) | pass |

### A-3 reconciliation — actual pytest node ids created

```
tests/test_compare_engine.py::test_classification_set_equality
tests/test_compare_engine.py::test_classification_set_equality_random
tests/test_compare_engine.py::test_adjacency_merge_same_kind_merges
tests/test_compare_engine.py::test_adjacency_change_forces_boundary
tests/test_compare_engine.py::test_boundary_cases
tests/test_compare_engine.py::test_identity_empty_and_equal
tests/test_compare_engine.py::test_determinism_repeated_calls
tests/test_compare_engine.py::test_stats_byte_count_equals_run_lengths
tests/test_compare_engine.py::test_stats_run_counts_match
tests/test_compare_engine.py::test_symmetry_swap_only_a_only_b
tests/test_compare_engine.py::test_large_image_perf
```

Drift vs the spec's PROVISIONAL TC-001..TC-006 names: the spec named 6 TCs; I
implemented 11 node ids (the spec's `m-4` AC requires each of TC-001/002/003 to
own a distinct property, and several LLRs assert multiple properties). Mapping:
TC-001→2 nodes, TC-002→2 nodes, TC-003→1, TC-004→2, TC-005→3 (incl. the swap-
symmetry extra), TC-006→1. Element-style: all mandated elements present;
additional assertions permitted.

## 5. Risks

**BLOCKER (surfaced, not worked around) — spec/code contradiction at the I1
boundary:** creating the spec-mandated package-root engine module
`s19_app/compare.py` (D-7, LLR-001.1: "Module sits at package root beside
`range_index.py`") trips **two pre-existing batch-04 LLR-012.4 guard tests** that
pin the `s19_app/` package root to a fixed 7-module allowlist:

- `tests/test_tui_directionb.py::test_tc028_no_new_processing_module_added_outside_view_layer` (`:3174`)
- `tests/test_tui_directionb.py::test_tc028_no_new_processing_module_added_outside_view_layer_inc10` (`:3534`)

Both assert `{*.py at package root} - {__init__, cli, core, hexfile, range_index,
utils, version} == set()`. `compare.py` is the 8th root module → both fail.

Confirmed pre-state: with `compare.py` moved aside, both tests pass (2 passed in
0.39s); restored, both fail. Root cause is unambiguous.

**The batch-09 requirements did NOT enumerate these two guards for supersession.**
The R-8 census (probe P-16) catalogued only the TC-027 family and
`test_tc028_every_scaffold_screen_activates_without_error` inside
`test_tui_directionb.py`, all slated for the **I4** gate. These two package-root
guards were missed and break at **I1**, not I4. They are batch-04 artifacts whose
LLR-012.4 intent ("the batch adds no engine module outside the view layer") is
DIRECTLY OVERTURNED by batch-09's HLR-001/D-7 design (an engine module at the
package root is the whole point).

Per my hard boundary ("stop and report on any spec/code contradiction") and the
≤2-file I1 budget, I did **not** edit `test_tui_directionb.py` — that is a third
file, outside this increment, and the supersession was not authorized for I1.
**Orchestrator decision required** (see §6).

Other risks: none in the engine itself. The closure-based run-merging in
`diff_mem_maps` was validated by the brute-force oracle round-trip (TC-001) over
both planted and randomized fixtures, and by the at-scale stats check (TC-006).

## 6. Pending items

- **DECISION NEEDED (blocker):** how to dispose of the two batch-04 LLR-012.4
  package-root guards now overturned by HLR-001/D-7. Options:
  1. Add `compare.py` to the `engine_root_modules` allowlist in both tests
     (`:3186` and `:3545`) — minimal, keeps the guard's spirit (no UNEXPECTED
     module) while admitting the batch-09 engine. Recommended; ~2 line edits in
     1 file (`tests/test_tui_directionb.py`).
  2. Supersede/retire both guards as overturned (like the R-8 TC-027 family),
     recording the disposition in the suite-count reconciliation (`D`/`A`).
  3. Move the engine elsewhere — REJECTED: contradicts D-7/LLR-001.1, which
     mandate the package-root placement explicitly.
  Whichever is chosen, it is a `test_tui_directionb.py` edit (a 3rd file for this
  increment, or fold into I4's supersession pass). This must be reconciled before
  the I1 gate can declare a clean lean suite.
- I2..I5 remain unstarted (service, artifact notes, report, TUI, close) per the
  §6.2 increment plan.

## 7. Suggested next task

Resolve the blocker first: authorize Option 1 (add `compare.py` to the two
`engine_root_modules` allowlists in `tests/test_tui_directionb.py`, recorded as
a batch-04-guard supersession in the §5.3 signed balance), then proceed to **I2**
— `s19_app/tui/services/compare_service.py` + `tests/test_compare_service.py`
(LLR-002.x, LLR-003.x), consuming this engine's `diff_mem_maps` and filling the
remaining C-9 fields.
