# Increment 001 — US-035 headless entropy service (LLR-035.1..LLR-035.5)

> Batch 2026-07-06-batch-26 · Feature #12(b) · Phase 3, Increment 1
> Scope: **US-035 ONLY** (headless service). US-037 (report) and US-036 (modal) are later increments.

## 1. What changed

Added the headless, pure-arithmetic entropy/band-classification service — the shipped surface for US-035 and the prerequisite data source both later increments (US-036 modal, US-037 report) consume.

- **`compute_entropy(mem_map: Dict[int,int]) -> list[EntropyWindow]`** — derives contiguous half-open ranges from `sorted(mem_map)` (same `(start, prev+1)` algorithm as `core.py:503-514`, replicated in-service so no parser is imported), walks 256-byte windows *per range* (never across a gap), computes Shannon `H = -Σ p·log2(p)` bits/byte per window over a 256-bin histogram, classifies into a band, tags `low_confidence` when `sample_count < 64`, and returns one `EntropyWindow` per window in ascending address order. Empty map → `[]`.
- **`EntropyWindow`** frozen dataclass — `(start, end, sample_count, entropy, band, low_confidence)` (LLR-035.5).
- **Module constants** `ENTROPY_WINDOW_BYTES=256`, `ENTROPY_MIN_SAMPLES=64`, `ENTROPY_BANDS` ordered tuple with the `8.000001` headroom sentinel; **`classify_band(entropy)`** with half-open `[lo,hi)` semantics (value at a cutoff → higher band) (LLR-035.1).
- **Purity:** zero `textual` imports (LLR-035.5), mirroring `before_after_service.py`.
- **Export convention:** `services/__init__.py` is a bare docstring with no re-exports; `before_after_service`/`report_service` are imported by full path, so `entropy_service` follows suit — `__init__.py` was NOT touched (keeps the increment to 2 files).

## 2. Files modified

| File | Status | Notes |
|---|---|---|
| `s19_app/tui/services/entropy_service.py` | **NEW** | The service (constants, `classify_band`, `EntropyWindow`, `compute_entropy`, private `_derive_ranges`/`_window_entropy`). Outside the engine-frozen set. |
| `tests/test_entropy_service.py` | **NEW** | 14 tests — AT-035a..e + TC-035.1..7 + a frozen-shape guard + a `large_s19` stress guard. |

**2 files. No engine-frozen file touched** (verified `git diff --name-only main` over the frozen set → empty).

## 3. How to test

```bash
cd <this worktree root>   # ensures editable-install .pth resolves THIS worktree's entropy_service.py
python -m ruff check s19_app/tui/services/entropy_service.py tests/test_entropy_service.py
python -m pytest tests/test_entropy_service.py -v
```

Toolchain entry gate: `ruff 0.15.17`, `pytest 9.0.3` both present — no `pip install -e .[dev]` needed (the `[dev]` extra is snapshot-only: `pytest-textual-snapshot`, `textual==8.2.8`; no mypy/pyright declared anywhere). `s19_app` import confirmed resolving to this worktree.

## 4. Test results (real output)

`ruff check` → **All checks passed!**

`pytest tests/test_entropy_service.py -v` → **14 passed in 1.09s**:

```
test_at035a_constant_fill_band_and_zero_entropy PASSED
test_at035b_permutation_band_and_max_entropy PASSED
test_at035c_mixed_two_ranges_gap_not_straddled PASSED
test_at035d_partial_final_window_low_confidence PASSED
test_at035e_empty_map_returns_empty_list PASSED
test_tc035_1_multi_range_window_count_and_containment PASSED
test_tc035_2_band_cutoff_sides_direct_injection PASSED
test_tc035_3_low_sample_tag_boundary PASSED
test_tc035_4_degenerate_empty_and_single_byte PASSED
test_tc035_5_constants_pinned PASSED
test_tc035_6_estimator_reference_values PASSED
test_tc035_7_service_purity_no_textual_import PASSED
test_llr035_5_entropy_window_frozen_shape PASSED
test_stress_guard_large_s19_window_count PASSED
============================= 14 passed in 1.09s =============================
```

### Test → AT/TC → LLR map

| Test | AT/TC | LLR | Asserts |
|---|---|---|---|
| `test_at035a_...` | AT-035a | 035.3 | 256×0xFF → 1 window, `constant/padding`, `abs(H)<1e-9` |
| `test_at035b_...` | AT-035b | 035.3 | 0..255 perm → `high/random`, `abs(H-8.0)<1e-9` |
| `test_at035c_...` | AT-035c | 035.2/.3 | constant@0x3000 + gap + perm@0x4000 → exactly 2 windows, bands + H + start addrs |
| `test_at035d_...` | AT-035d | 035.2/.3/.4 | 296-B range → 2 windows; window2 = 40 B, `H==1.0`, `low_confidence True`; window1 False |
| `test_at035e_...` | AT-035e | 035.5 | `compute_entropy({})` → `[]`, no exception |
| `test_tc035_1_...` | TC-035.1 | 035.2 | 3 ranges → count = Σ ceil(len/256); each window ⊆ one range (gap non-straddle) |
| `test_tc035_2_...` | TC-035.2 | 035.1 | direct `classify_band` at literal `0.99/1.0/1.0001`, `4.99/5.0/5.0001`, `7.1999/7.2/7.2001` + endpoints |
| `test_tc035_3_...` | TC-035.3 | 035.4 | low-sample boundary 63(True)/64(False)/65(False) |
| `test_tc035_4_...` | TC-035.4 | 035.4/.5 | `{}`→[]; 1-byte range → 1 window, `H==0.0`, `low_confidence True` |
| `test_tc035_5_...` | TC-035.5 | 035.1 | constants + full bands tuple pinned exact |
| `test_tc035_6_...` | TC-035.6 | 035.3 | 128A+128B→H==1.0; 4×64→H==2.0; 32×8→H==5.0==log2(32) |
| `test_tc035_7_...` | TC-035.7 | 035.5 | source has no `import textual` / `from textual` (purity) |
| `test_llr035_5_...` | — | 035.5 | `EntropyWindow` is frozen, all six fields, ascending start order |
| `test_stress_guard_...` | — | 035.2 | `large_s19` → 3201 windows (= Σ ceil over the 201 parsed ranges), fast, exactly 1 low-conf window |

**Pre-fix counterfactual (QR-8):** every AT-035* would `ImportError` on the pre-fix tree (module absent) — satisfied by construction for this NEW module. No fabricated pre-fix run needed.

## 5. Risks

- **R-1 (H-precision, from §6.3):** float `log2` error vs `<1e-9`. Mitigated — exact endpoints (0.0, 8.0) and integer-log2 references (1.0, 2.0, 5.0) all land well within 1e-9; `TC-035.2` pins the cutoff *side* by direct float injection, decoupled from float-histogram construction (QR-2 resolved).
- **Stress-guard surprise (resolved, fail-loud caught it):** `S19File.get_memory_map()` maps the **S0 header record's data at address 0** — for `large_s19` that is the 6-byte ASCII string `"STRESS"`, producing a 201st tiny range → **3201** windows, not the 3200 I first asserted. The test now derives the expected count from the actual parsed ranges (Σ ceil(len/256)) AND pins the 201-range / 3201-window / 1-low-confidence structure, so it encodes the real substrate behavior rather than a guessed constant. This is correct service behavior (the header bytes are genuinely mapped), not a defect.
- **No new dependency, no new export surface.** `services/__init__.py` untouched.

## 6. Pending items

- **US-037** (per-variant entropy section in the report) — LLR-037.1..3, edits `report_service.py`. Consumes `compute_entropy(result.mem_map)`. Next increment candidate.
- **US-036** (entropy viewer modal) — LLR-036.1..6, edits `screens.py`/`app.py`/`styles.tcss` + snapshot cells. Consumes the same service.
- The `AT-035*` bodies live in this new test module; the qa `01b` §8 results table can be filled from the run above at Phase 4.

## 7. Suggested next task

Implement **US-037** (LLR-037.1..3): add `ReportOptions.include_entropy: bool = True` (+ `__post_init__` bool guard, `include_legend` precedent at `report_service.py:197`/`:231-235`), a `_entropy_lines(result)` Markdown builder calling `compute_entropy(result.mem_map)`, and wire it via the `emit()` helper (`report_service.py:1130-1132`) inside the per-variant loop immediately after `_hexdump_section` (`:1145-1147`). Gate with AT-037a (C-12: re-read the written report file) + AT-037b (`include_entropy=False` byte-identical). Still ≤5 files, all non-frozen.

---

### Evidence checklist

- [✓] Tests/type checks/lint pass — `ruff` clean; `14 passed in 1.09s`; no type-checker declared in `[project.optional-dependencies].dev` (snapshot-only), so none to run.
- [✓] No secrets in code or output — synthetic byte patterns (`0x00`/`0xFF`/permutations) only.
- [✓] No destructive commands run without approval — read/write/test only; `mkdir -p` for the increments dir.
- [✓] File count within cap — 2 new files (≤5).
- [✓] Review packet attached — this file.
- [✓] Engine-frozen set untouched — `git diff --name-only main` over the frozen set → empty.
- [✓] Purity confirmed — 0 `textual` references in `entropy_service.py`.
