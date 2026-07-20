# 04 — Validation (Phase 4) · batch-55 (P-1b inline-axis length summer)

**Gate verdict: PASS (PR-A). Coverage / Certainty / Evidence all MET. 0 blockers.**
Every LLR maps to a green on-disk TC; every gate-blocking AT (104–111 + 107b) reconciles to EXACTLY ONE distinct on-disk test node observed through the shipped `parse_a2l_file` surface (AT-108 additionally through `enrich_tags_and_render` + `_a2l_tag_row_severity`). The C-27 dual-guard shows engine-frozen changes ONLY in the sanctioned `a2l.py` (unfrozen this batch) + the two guard files. All four §6.5 amendments (A1/A2/A3/A4) landed and are green. 0 snapshot drift (no regen PR). AT-112/TC-142 (re-freeze) are post-merge PR-B — correctly deferred, not a PR-A gate.

**One non-blocking item for the PR-level pass:** the new white-box test file `tests/test_a2l_inline_axis_length.py` is currently **untracked** (`git status` = `??`). It is on disk and in the green run, but must be `git add`-ed before the PR-A commit or it will not ship in the PR. Flag to `software-dev`/orchestrator. (Not a Phase-4 gate failure — the tests exist and pass; it is a commit-hygiene checkpoint.)

Consumed the orchestrator C-25 gate run (one complete `pytest -q -m "not slow"`, **EXIT=0, 1670 passed / 2 skipped / 21 deselected / 3 xfailed, 29 snapshots passed / 0 drift**). Targeted re-runs below are my own direct evidence (evidence-over-claim), not a re-run of the full suite.

---

## Layer A — Functional / white-box (LLR → TC, verified on disk + green)

Every TC function confirmed to EXIST on disk (`--co` collection + line-cited) and PASS (targeted run: **19 passed in 0.40s**; frozen guards **11 passed in 2.14s**).

| LLR | TC | On-disk node (`tests/test_a2l_inline_axis_length.py` unless noted) | Method | Status |
|-----|----|-----|--------|--------|
| P1b.1 `_record_layout_full_span` | TC-133 (+133b) | `test_tc133_record_layout_full_span_datatype_and_axis_order` · `test_tc133_full_span_or_none_on_unclassifiable` · `test_tc133b_alignment_directive_forces_none` | unit | ✅ green |
| P1b.2 `_inline_axis_counts` + external gate | TC-134 | `test_tc134_inline_axis_counts_base10_and_external_gate` | unit | ✅ green |
| P1b.3 census constants (C-31) | TC-135 | `test_tc135_axis_kind_census_completeness` | unit + inspection | ✅ green |
| P1b.4 post-axis-walk pass (R2) | TC-136 | `test_tc136_post_axis_pass_ordering_and_precedence` | integration | ✅ green |
| P1b.5 no-regression | TC-137 | `test_tc137_scalar_value_unchanged` | unit | ✅ green |
| P1b.6 fail-closed | TC-139 | `test_tc139_fail_closed_no_raises` | unit | ✅ green |
| P1b.7 UNFREEZE a2l.py (PR-A) | TC-141 | inspection — `git diff main` on both guard files (below) | inspection | ✅ verified |
| DoS.1 `MAX_A2L_DECODE_BYTES` clamp | TC-138 | `test_tc138_dos_clamp_pure_arithmetic` | unit + analysis | ✅ green |
| SUP.1 batch-54 AT-102 supersession | TC-140 | `tests/test_a2l_multiline_headers.py::test_at102_curve_map_length_stays_none` (amended) | test + inspection | ✅ green |
| P2b.1 re-freeze (PR-B) | TC-142 | **post-merge PR-B — deferred** | test + inspection | ⏸ deferred |

**Implementation cross-check (LLR wording, not the probe's looser branches — per Phase-2 carry):**
- `_inline_axis_counts` casts via base-10 `int(str(mp).strip())` inside `try/except (ValueError, TypeError)` (a2l.py diff L89–92) — NOT base-0, NOT an `isdigit()` pre-predicate (sec-F2/F3). ✓
- `_record_layout_full_span` uses `DATATYPE_SIZES.get(tokens[2])` (never subscript), reads datatype from `tokens[2]` (position index `tokens[1]` ignored), caps `total > MAX_A2L_DECODE_BYTES → None`, and forces `None` on any ALIGNMENT_*/unrecognized directive (diff L181–194, arch-MIN3 + A4). ✓
- `_extract_raw_bytes` clamp `if byte_size > MAX_A2L_DECODE_BYTES:` sits **before** the `range(byte_size)` loop (diff L207). ✓
- Post-axis-walk gate: `name == "CHARACTERISTIC" and char_type in ("CURVE","MAP") and length is None` → `_inline_axis_counts` → `record_layouts_by_name.get(...)` → `_record_layout_full_span` (diff L218–227). Placement after the `axis_meta` loop preserves R2 ordering; the `length is None` guard preserves explicit-LENGTH precedence. ✓ (`MAX_A2L_DECODE_BYTES == 1_048_576`.)

---

## Layer B — Behavioral / black-box (US → AT) + V-5 / C-18 realization gate

**C-18 gate: every §4.9 AT reconciles to EXACTLY ONE distinct on-disk node driving the whole named chain. No "satisfied-in-parts". Verified by grep of the test file.**

| AT | Story | On-disk node | Shipped surface | Asserts THE VALUE | Status |
|----|-------|--------------|-----------------|-------------------|--------|
| AT-104 | US-P1b | `test_at104_demo_curve_std_axis_length_25` | `parse_a2l_file(demo)` | `length == 25` | ✅ |
| AT-105 | US-P1b | `test_at105_demo_map_std_axis_length_51` | `parse_a2l_file(demo)` | `length == 51` | ✅ |
| AT-106 | US-P1b | `test_at106_demo_curve_com_axis_stays_none` | `parse_a2l_file(demo)` | `length is None` (false-green anchor) | ✅ |
| AT-107 | US-P1b (FIX_AXIS) | `test_at107_demo_curve_fix_axis_length_12` | `parse_a2l_file(demo)` | `length == 12` (FNC-only layout) | ✅ |
| AT-107b | US-P1b (demo-independent) | `test_at107b_synthetic_single_line_curve_length_13` | `parse_a2l_file(tmp)` | `length == 13` | ✅ |
| AT-108 | US-P1b (output-then-consume) | `test_at108_derived_length_makes_row_memory_checkable` | `parse_a2l_file` → `enrich_tags_and_render` → `_a2l_tag_row_severity` | `memory_checked True` ∧ row `OK` | ✅ |
| AT-109 | US-P1b (no-regression) | `test_at109_no_regression_non_curve_map_untouched` | `parse_a2l_file(demo/case_01/tmp)` | VALUE=1, MEAS=1, no-kind None, CUBOID None | ✅ |
| AT-110 | US-P1b (robustness) | `test_at110_malformed_curve_fail_closed` | `parse_a2l_file(tmp)` | `'x'`→None, `'08'`→25, `'9'*5000`→None, bad-dt→None, no raise | ✅ |
| AT-111 | US-DoS | `test_at111_oversized_axis_clamps_to_none` | `parse_a2l_file(tmp)` | 10M axis → `None`, <2s | ✅ |
| AT-112 | US-P2b | **post-merge PR-B** | guard tests + `git diff main -- a2l.py` empty | — | ⏸ deferred |

**C-18 verdict: PASS.** 9/9 gate-blocking ATs each realize to one distinct node, driving the full chain through the shipped surface — none is "satisfied in parts" by white-box TCs alone. AT-108 is genuinely output-then-consume (parses, builds a covering `mem_map`, re-enriches, applies `_a2l_tag_row_severity`). Every US has ≥1 black-box deliverable observation → **no story is a blocker for want of a black-box surface.**

---

## Bidirectional surface-reachability matrix

Every named INPUT dimension is exercised through `parse_a2l_file` (or the helper it drives), and every named OUTPUT/deliverable is observed. Each cell has a node.

| Input dimension | Exercised through | Node | Output observed |
|-----------------|-------------------|------|-----------------|
| STD_AXIS derivable (CURVE) | `parse_a2l_file(demo)` | AT-104 | `length == 25` |
| STD_AXIS derivable (MAP, 2 axes) | `parse_a2l_file(demo)` | AT-105 | `length == 51` |
| FIX_AXIS derivable (FNC-only) | `parse_a2l_file(demo)` | AT-107 | `length == 12` |
| STD_AXIS synthetic (demo-independent) | `parse_a2l_file(tmp)` | AT-107b / TC-136 | `length == 13` |
| COM_AXIS external (AXIS_PTS_REF) | `parse_a2l_file(demo)` | AT-106 | `length is None` |
| RES_AXIS / external flag | `_inline_axis_counts` | TC-134 | `None` |
| CUBOID (char_type-gate exclusion) | `parse_a2l_file(demo)` | AT-109(d) | `length is None` |
| Malformed MaxAxisPoints (`'x'`) | `parse_a2l_file(tmp)` | AT-110(i) / TC-139 | `None`, no raise |
| `'08'` base-10 (leading-zero) | `parse_a2l_file(tmp)` | AT-110(ii) / TC-134 | derives (25 / 8) |
| Huge-digit (`'9'*5000`) | `parse_a2l_file(tmp)` / `_inline_axis_counts` | AT-110(iii) / TC-138 | `None`, no exception |
| Unknown datatype token | `parse_a2l_file(tmp)` / `_record_layout_full_span` | AT-110(iv) / TC-139 | `None`, no KeyError |
| Unknown component (≥3-token) | `_record_layout_full_span` | TC-133 (`test_..._unclassifiable`) | `None` (not skip) |
| ALIGNMENT_* directive | `_record_layout_full_span` | TC-133b | `None` (not under-report) |
| Oversized DoS span | `parse_a2l_file(tmp)` / `_record_layout_full_span` | AT-111 / TC-138 | `None`, bounded time |
| ALIGNMENT / cap force-None | `_record_layout_full_span` | TC-133b / TC-138 | `None` |
| Scalar VALUE (no axis) | `parse_a2l_file(tmp)` | TC-137 / AT-109(a) | `length == 1` (unchanged) |
| No-kind CHARACTERISTIC | `parse_a2l_file(tmp)` | AT-109(c) | `char_type None`, `length None` |
| MEASUREMENT | `parse_a2l_file(demo)` | AT-109(b) | `length == 1` (unchanged) |

**Output-side coverage:** byte value 25/51/12/13 ✓ · the `None` ✓ · the A2L row severity flip (grey→OK) ✓ (AT-108). All output dimensions observed through the handler, not only the service API.

---

## Counterfactual / negative-control audit

Gate-blocking ATs have value-discriminating counterfactuals ACTUALLY ENCODED (not merely narrated):

- **AT-106 (external → None)** — the false-green anchor; a summer ignoring `_EXTERNAL_AXIS_KINDS`/`external` would produce a wrong non-None. Encoded as the demo COM_AXIS assertion. ✓
- **AT-108 (reverted → not-OK)** — counterfactual is CODE-EXECUTED (lines 467–474): force `length=None`, re-enrich over the SAME covering map → `memory_checked is False` ∧ severity `is not OK`. Discriminates that the derived length is what enabled the check. ✓ *(Fail-loud deviation, correctly documented in the test: the requirement's worded counterfactual said the reverted row is NEUTRAL, but the demo CURVE carries a formula `source` → it lands INFO, not NEUTRAL. The test pins the load-bearing fact (`memory_checked False` ∧ `not OK`) rather than the exact non-OK enum. Sound — the counterfactual still fails RED if the summer regresses.)*
- **TC-133 (X/Y-count swap)** — size-asymmetric MAP `[4,3]==25` vs `[3,4]==24`, asserted `!=` (arch-MAJ1). Position-as-count mutation would break the 25 oracle. ✓
- **TC-133b (alignment → None)** — counterfactual `summable==13` without alignment vs `None` with an ALIGNMENT_WORD/trailing ALIGNMENT_LONG. Discriminates under-report. ✓
- **TC-135 (derived census)** — `observed` DERIVED from the parse (`{am["header_tokens"][0] for tag in parse … for am in tag["axis_meta"]}`), asserted non-empty ∧ `⊆ ALL_AXIS_KINDS` — NOT a hand-listed literal (C-31 / qa-M2). A 6th kind absent from `ALL_AXIS_KINDS` fails RED. ✓
- **AT-110 base-10 proof** — `'08'` DERIVES (25), does NOT return None — proves base-10 (base-0 would raise). ✓

**On AT-104/105/107:** these assert an exact byte VALUE through the surface (a value-discriminating oracle in its own right — wrong wiring yields a different integer, not merely non-None); the mutation-level counterfactuals (position-as-count → 9, axis-swap) are delegated to white-box TC-133 per §4.9. No AT asserts only a default/non-None. ✓

---

## Frozen-diff check (C-27 dual-guard)

`git diff --name-only main -- s19_app/` → **`s19_app/tui/a2l.py` ONLY.** No other engine-frozen module changed (core.py / hexfile.py / range_index.py / validation/ / tui/mac.py / tui/color_policy.py all untouched). ✓

`git diff --stat main` (full): `a2l.py` (+192), `test_a2l_multiline_headers.py` (AT-102 supersession), `test_engine_unchanged.py` + `test_tui_directionb.py` (the two guard files — unfreeze). No unsanctioned engine edit.

Guard-file unfreeze verified: `"s19_app/tui/a2l.py"` REMOVED from BOTH `_ENGINE_PATHS`; the batch-54 "RE-FROZEN" NOTE replaced with the "temporarily UNFROZEN for batch-55 … RE-FREEZE … post-merge follow-up PR" wording in each file. **tc031 / tc032 / tc027 / engine guards: 11 passed** (direct run) — the unfreeze does not trip the guard, and tc032 confirms no batch-55 white-box test landed in the frozen `tests/test_tui_a2l.py`. ✓

**C-27 verdict: PASS.** Unfreeze REMOVES → same-PR OK (corollary honored). Re-freeze (adds back) is the separate post-merge PR-B.

---

## §6.5 amendments — landed & green

| Amd | What | Evidence | Status |
|-----|------|----------|--------|
| A1 | REQUIREMENTS.md CURVE/MAP prose (deferred→summed) | `git diff main -- REQUIREMENTS.md` shows the inline/external prose + `tests/test_a2l_inline_axis_length.py` regression ref | ✅ landed |
| A2 | batch-54 AT-102 None→25/51 supersession | `git diff` on `test_a2l_multiline_headers.py`: `is None`→`== 25`/`== 51`, intent comment updated; test green | ✅ landed + green |
| A3 | `'08'` C-36 base-10 correction | spec-only; reflected in TC-134/TC-139 (`'08'→[8]`) + AT-110 (`'08'→25`) — all green | ✅ reflected |
| A4 | ALIGNMENT force-None + TC-133b | `test_tc133b_alignment_directive_forces_none` present + green; a2l.py force-None guard (diff L181–194) | ✅ landed + green |

---

## Snapshot drift

**0 drift** (orchestrator run: 29 snapshots passed). The conservatively-predicted 8-row A2L-view drift did NOT materialize (same clean outcome as batch-54). **No canonical-CI regen PR needed.**

---

## Gate decision

| Axis | Verdict | Basis |
|------|---------|-------|
| **Coverage** | ✅ MET | 10/10 LLRs → a green TC (P2b.1/TC-142 correctly deferred to PR-B); 9/9 gate-blocking ATs → a distinct on-disk node; every input & output dimension reachable through the handler |
| **Certainty** | ✅ MET | Counterfactuals value-discriminating and code-encoded (AT-106/108, TC-133/133b/135); base-10 + fail-closed + cap-before-range implemented per LLR wording, not the probe; full suite EXIT=0 |
| **Evidence** | ✅ MET | Direct targeted runs (19 passed; 11 guard passed); diffs cited for unfreeze, supersession, prose, alignment; 0 frozen-diff outside sanctioned set; 0 snapshot drift |

**PR-A gate: PASS. 0 blockers.** No story lacks a black-box deliverable observation.

**Flags for the final PR-level pass:**
1. **Commit hygiene (non-blocking):** `tests/test_a2l_inline_axis_length.py` is untracked — `git add` it before the PR-A commit, else the 18 new tests won't ship.
2. **AT-108 enum deviation (documented, non-blocking):** reverted row lands INFO not NEUTRAL (formula `source`); test asserts the load-bearing `memory_checked False`/`not OK` — sound.
3. **PR-B (post-merge):** re-freeze `a2l.py` into both `_ENGINE_PATHS` (AT-112 / TC-142 / LLR-P2b.1); guard-files-only; `git diff main -- a2l.py` must be empty. batch-56 = alignment-aware padding sizing (A4 follow-up) to restore coverage the force-None guard currently degrades to grey.
