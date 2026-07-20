# Traceability Matrix — batch-55 (P-1b inline-axis length summer)

> **Audience:** engineering / QA / reviewers. **Purpose:** prove that every user story, high-level requirement, and low-level requirement of batch-55 is realized by a named on-disk test node, with its C-26 touched symbol and validation status.
>
> **Source of truth:** `01-requirements.md` (§3 HLR, §4 LLR, §4.9 AT/TC registry, §5.2 dual traceability) reconciled against `04-validation.md` (Layer A / Layer B on-disk nodes). No gaps: every gate-blocking AT (104, 105, 106, 107, 107b, 108, 109, 110, 111) and every TC (133, 133b, 134–142) appears with its owning requirement and on-disk node.
>
> **Legend — Status:** ✅ green (verified on disk, passing) · ⏸ deferred (post-merge PR-B, correctly not a PR-A gate).
> **Legend — Test file:** all new white-box TCs and black-box ATs live in the NEW non-frozen `tests/test_a2l_inline_axis_length.py` unless noted. TC-140 amends `tests/test_a2l_multiline_headers.py`. TC-141/TC-142 are guard-file inspections.

---

## 1. Story → HLR → requirement id → validation → status

| US | Story (one line) | HLR | Req id | Validation method | Gate-blocking ATs | Status |
|----|------------------|-----|--------|-------------------|-------------------|--------|
| **US-P1b** | Inline STD_AXIS/FIX_AXIS CURVE/MAP shows a correct byte `length` (memory-checkable); external-axis stays grey | HLR-P1b | `R-A2L-008` | test + analysis | AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110 | ✅ |
| **US-DoS** | Byte-decode loop bounded by `MAX_A2L_DECODE_BYTES` (1 MiB) — no unbounded allocation on a hostile layout | HLR-DoS | `R-A2L-014` | test + analysis | AT-111 | ✅ |
| **US-P2b** | `a2l.py` re-frozen into both C-27 `_ENGINE_PATHS` sets after the summer merges | HLR-P2b | `R-A2L-015` | test + inspection | AT-112 (post-merge) | ⏸ PR-B |

---

## 2. Full LLR → TC matrix (with C-26 touched symbols)

| LLR | Statement (short) | C-26 touched symbol(s) | TC | On-disk test node | Method | Status |
|-----|-------------------|------------------------|----|-------------------|--------|--------|
| **LLR-P1b.1** | `_record_layout_full_span` sums `size × element_count` over components; datatype from token[2] (token[1] = position index); full-span-or-None on any unclassifiable line | NEW `_record_layout_full_span` (`a2l.py:1079`); reads `DATATYPE_SIZES` (`a2l.py:13`), `math.prod` | TC-133 | `test_tc133_record_layout_full_span_datatype_and_axis_order` · `test_tc133_full_span_or_none_on_unclassifiable` | unit | ✅ |
| **LLR-P1b.1** (A4 amendment) | ALIGNMENT_* / any unmodeled non-empty directive forces `None` (never under-report) | `_record_layout_full_span` else-branch (`a2l.py:1159-1165`) | TC-133b | `test_tc133b_alignment_directive_forces_none` | unit | ✅ |
| **LLR-P1b.2** | `_inline_axis_counts` returns ordered counts or `None`; base-10 cast in try/except; external gate | NEW `_inline_axis_counts` (`a2l.py:1017`); reads `axis_meta` (built `a2l.py:1440-1451`) | TC-134 | `test_tc134_inline_axis_counts_base10_and_external_gate` | unit | ✅ |
| **LLR-P1b.3** | Axis-kind census constants; disjoint subsets; union = `ALL_AXIS_KINDS`; census DERIVED from the parse (C-31, not hand-listed) | NEW `_DERIVABLE_AXIS_KINDS`, `_EXTERNAL_AXIS_KINDS`, `ALL_AXIS_KINDS` (`a2l.py:81-83`) | TC-135 | `test_tc135_axis_kind_census_completeness` | unit + inspection | ✅ |
| **LLR-P1b.4** | Post-axis-walk length pass gated on `name=="CHARACTERISTIC" ∧ char_type∈{CURVE,MAP} ∧ length is None`; runs AFTER `axis_meta` build (R2 ordering) | `extract_a2l_tags` walk closure NEW block (`a2l.py:1454-1465`); reads `record_layouts_by_name` | TC-136 | `test_tc136_post_axis_pass_ordering_and_precedence` | integration | ✅ |
| **LLR-P1b.5** | No-regression: MEASUREMENT / scalar VALUE / VAL_BLK / ASCII / no-kind / already-sized tags untouched | none new (negative surface of P1b.4 guard) | TC-137 | `test_tc137_scalar_value_unchanged` | unit + inspection | ✅ |
| **LLR-P1b.6** | Fail-closed: `DATATYPE_SIZES.get` (no subscript), len-guard token access, cast in try/except, never raise | `_record_layout_full_span`, `_inline_axis_counts` defensive branches | TC-139 | `test_tc139_fail_closed_no_raises` | unit + e2e | ✅ |
| **LLR-P1b.7** | UNFREEZE `a2l.py` in PR-A: remove from both `_ENGINE_PATHS`; new tests in NEW non-frozen sibling | `_ENGINE_PATHS` (`test_engine_unchanged.py:129`, `test_tui_directionb.py:5437`) + two NOTE blocks | TC-141 | inspection — `git diff main` on both guard files; tc031/tc032 green | inspection | ✅ |
| **LLR-DoS.1** | `MAX_A2L_DECODE_BYTES=1_048_576` clamp in `_extract_raw_bytes` before `range(byte_size)`; reused as summer cap | NEW `MAX_A2L_DECODE_BYTES` (`a2l.py:34`); `_extract_raw_bytes` guard (`a2l.py:1212`); `_record_layout_full_span` cap (`a2l.py:1173`) | TC-138 | `test_tc138_dos_clamp_pure_arithmetic` | unit + analysis | ✅ |
| **LLR-SUP.1** | Supersede batch-54 `test_at102_curve_map_length_stays_none`: None → 25/51; None-anchor role moves to AT-106 | `tests/test_a2l_multiline_headers.py::test_at102_curve_map_length_stays_none` (non-frozen) | TC-140 | `tests/test_a2l_multiline_headers.py::test_at102_curve_map_length_stays_none` (amended) | test + inspection | ✅ |
| **LLR-P2b.1** | RE-FREEZE `a2l.py` into both `_ENGINE_PATHS` (PR-B, post-merge); `git diff main -- a2l.py` empty | `_ENGINE_PATHS` (`test_engine_unchanged.py:120-131`, `test_tui_directionb.py:5428-5440`) + NOTE blocks | TC-142 | **post-merge PR-B** — guards green + empty diff | test + inspection | ⏸ PR-B |

---

## 3. Full AT matrix (black-box, observed through the shipped surface)

| AT | Story | Asserts THE VALUE (through the surface) | Shipped surface | On-disk test node | Gate-blocking? | Status |
|----|-------|-----------------------------------------|-----------------|-------------------|----------------|--------|
| **AT-104** | US-P1b | `ASAM.C.CURVE.STD_AXIS` → `length == 25` (1×UBYTE + 8×SBYTE + 8×SWORD) | `parse_a2l_file(demo).tags` | `test_at104_demo_curve_std_axis_length_25` | Yes | ✅ |
| **AT-105** | US-P1b | `ASAM.C.MAP.STD_AXIS.STD_AXIS` (axes 4 & 5) → `length == 51` (1+1+4+5 + 4·5·2) | `parse_a2l_file(demo).tags` | `test_at105_demo_map_std_axis_length_51` | Yes | ✅ |
| **AT-106** | US-P1b | `ASAM.C.CURVE.COM_AXIS` (external `AXIS_PTS_REF`) → `length is None` — **false-green anchor** | `parse_a2l_file(demo).tags` | `test_at106_demo_curve_com_axis_stays_none` | Yes | ✅ |
| **AT-107** | US-P1b (FIX_AXIS) | `ASAM.C.CURVE.FIX_AXIS.PAR_DIST` → `length == 12` (FNC-only layout, no on-disk AXIS_PTS line) | `parse_a2l_file(demo).tags` | `test_at107_demo_curve_fix_axis_length_12` | Yes | ✅ |
| **AT-107b** | US-P1b (demo-independent) | Synthetic single-line CURVE → `length == 13` (1×UBYTE + 4×SWORD + 4×UBYTE) | `parse_a2l_file(tmp)` | `test_at107b_synthetic_single_line_curve_length_13` | Yes | ✅ |
| **AT-108** | US-P1b (output-then-consume, C-12) | Derived `length==25` + covering `mem_map` → `_a2l_tag_row_severity` is `OK` (grey→green); reverted (length→None) → `memory_checked False` ∧ not OK | `parse_a2l_file` → `enrich_tags_and_render` → `_a2l_tag_row_severity` | `test_at108_derived_length_makes_row_memory_checkable` | Yes | ✅ |
| **AT-109** | US-P1b (no-regression) | (a) case_01 scalar VALUE length unchanged; (b) demo MEASUREMENT unchanged; (c) synthetic no-kind CHAR → `None`; (d) demo CUBOID stays `None` (char_type gate); (e) 0 snapshot drift beyond 8 inline rows | `parse_a2l_file(demo/case_01/tmp)` | `test_at109_no_regression_non_curve_map_untouched` | Yes | ✅ |
| **AT-110** | US-P1b (robustness) | Malformed CURVE, no exception: `'x'`→None; `'9'*5000`→None; bad datatype→None; **`'08'`→derives (25)** (base-10 proof) | `parse_a2l_file(tmp)` | `test_at110_malformed_curve_fail_closed` | Yes | ✅ |
| **AT-111** | US-DoS | Oversized synthetic axis (~10M / product over the bound) → `length is None` (clamped), completes < 2 s | `parse_a2l_file(tmp)` | `test_at111_oversized_axis_clamps_to_none` | Yes | ✅ |
| **AT-112** | US-P2b | After PR-B re-freeze: frozen-file guards green ∧ `git diff main -- a2l.py` empty | guard tests + `git diff` | **post-merge PR-B** | No — PR-B | ⏸ |

**Gate-blocking set (PR-A):** AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110, AT-111 — all ✅ green. AT-112 is the post-merge PR-B gate.

---

## 4. Dual-traceability cross-check (0 orphans)

- **Behavioral (US → AT):** US-P1b → {AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110}; US-DoS → AT-111; US-P2b → AT-112 (post-merge). Every US has ≥ 1 AT.
- **Functional (LLR → TC):** P1b.1 → 133 (+133b) · P1b.2 → 134 · P1b.3 → 135 · P1b.4 → 136 · P1b.5 → 137 · P1b.6 → 139 · P1b.7 → 141 · DoS.1 → 138 · SUP.1 → 140 · P2b.1 → 142. Every LLR has exactly one owning TC.
- **Bidirectional surface-reachability:** every input dimension (STD_AXIS / FIX_AXIS derivable, COM_AXIS/RES_AXIS/CURVE_AXIS external, malformed, oversized, scalar VALUE, no-kind, ALIGNMENT directive, unknown component) is exercised through `parse_a2l_file` (or the helper it drives); every output dimension (the byte `length` value 25/51/12/13, the `None`, the A2L row severity flip) is observed. See `04-validation.md` "Bidirectional surface-reachability matrix".
- **Check:** every gate-blocking AT (104–111 + 107b) observes THE VALUE / the `None` through `parse_a2l_file`; AT-108 additionally through `_a2l_tag_row_severity`. **0 orphans.**

---

## 5. §6.5 amendments — landed & green (see `01-requirements.md §6.5`, `04-validation.md §6.5`)

| Amd | What | Reflected in TC/AT | Status |
|-----|------|--------------------|--------|
| **A1** | `REQUIREMENTS.md:402-405` CURVE/MAP prose: "deferred, P-1b" → "summed via `_record_layout_full_span` × `_inline_axis_counts`, full-span-or-None; external stays None" | regression ref → `tests/test_a2l_inline_axis_length.py` | ✅ landed |
| **A2** | batch-54 AT-102 supersession: `is None` → `== 25` / `== 51` | TC-140 | ✅ landed + green |
| **A3** | `'08'` C-36 correction: base-10 valid decimal → 8 (NOT a `None` case) | AT-110 (`'08'→25`), TC-134/TC-139 (`'08'→[8]`) | ✅ reflected |
| **A4** | ALIGNMENT_* / unmodeled directive forces `None` (never under-report) | TC-133b | ✅ landed + green |

---

## 6. Verification evidence (from `04-validation.md`)

- Full suite: `pytest -q -m "not slow"` → **EXIT=0, 1670 passed / 2 skipped / 21 deselected / 3 xfailed, 29 snapshots passed / 0 drift**.
- Targeted white-box run: **19 passed in 0.40 s**; frozen guards **11 passed in 2.14 s**.
- C-27 dual-guard: `git diff --name-only main -- s19_app/` → `s19_app/tui/a2l.py` ONLY (the sanctioned unfreeze); no other engine-frozen module changed.
- Test delta: **+18** new tests (`tests/test_a2l_inline_axis_length.py`); 1652 base → 1670 total.

**Open items (non-blocking, carried forward):**
1. Commit hygiene — `git add tests/test_a2l_inline_axis_length.py` before the PR-A commit (was untracked during the green run).
2. AT-112 / TC-142 / LLR-P2b.1 — re-freeze `a2l.py` in the post-merge PR-B (guard-files-only; empty `git diff main -- a2l.py`).
3. batch-56 — alignment-aware padding sizing (A4 follow-up), to restore coverage the force-None guard currently degrades to grey.
