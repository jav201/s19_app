# Requirements Document — s19_app — Batch 56 (alignment-aware padding sizing)

> **Artifact language:** English (`state.json` default). Normative keyword: `shall` — used ONLY inside HLR/LLR statements. Any modal `should` inside a normative statement is a Phase-2 blocker.

**BLUF.** Two stories. **US-A56** (`R-A2L-016`) extends the batch-55 inline-axis length summer so a CURVE/MAP whose **RECORD_LAYOUT declares `ALIGNMENT_*` directives** sizes CORRECTLY — a cumulative-offset walk that pads each component's start up to its datatype's declared alignment — instead of the batch-55 force-`None`. Absent any record-layout-local `ALIGNMENT_*`, the layout stays **packed** (alignment 1, zero padding), preserving the batch-55 oracles (25 / 51 / 12 / None) byte-identically **by construction**. **US-P2b56** (`R-A2L-017`) re-freezes `a2l.py` into both C-27 guard sets as a post-merge PR-B (mirrors batch-54/55). The alignment math, the R-A/R-B/R-C decisions, and the batch-55-oracle invariance were **executed at draft time** over a synthetic ALIGNMENT fixture AND the real demo (§2.5 probe) — ALL MATCH; the demo's RECORD_LAYOUTs declare **zero** body-level `ALIGNMENT_*` (probe-confirmed `NONE (all packed)`), so the extension adds **zero** demo drift. `a2l.py` is currently FROZEN (batch-55 PR-B) → PR-A must UNFREEZE it in the same PR (C-27 corollary: unfreeze REMOVES → same-PR OK; re-freeze ADDS → post-merge PR-B).

> **§4.9 AT/TC registry** — the qa-reviewer authors the canonical AT/TC catalog in `01b-qa-catalog.md` (in parallel). §4.9 below is the orchestrator splice placeholder `<<QA-CATALOG>>`. This document authors the HLR/LLR statements, the R-A/R-B/R-C decisions, touched-symbols, and per-requirement validation methods. **AT/TC ids referenced in §3/§4 (`AT-113…`, `TC-143…`) are PROVISIONAL forward-continuations of batch-55 (which ended AT-112 / TC-142); the spliced qa catalog is authoritative and the orchestrator reconciles any id drift at §5.2.**

---

## 1. Introduction

### 1.1 Purpose
Specify alignment-aware on-disk sizing for the CURVE/MAP length summer: a RECORD_LAYOUT that DECLARES `ALIGNMENT_*` directives must derive a padded byte span (cumulative-offset walk with inter-component padding), instead of batch-55's blanket force-`None` on any `ALIGNMENT_*` line. Closes the batch-55 code-review **F1** hole (ALIGNMENT force-`None`) while preserving full-span-or-None for genuinely-unmodeled non-alignment directives.

### 1.2 Scope
- **In scope:** rewrite `_record_layout_full_span` as an alignment-aware cumulative-offset walk; a datatype→alignment-directive map (R-B); a first-pass collector of RECORD_LAYOUT-body-declared alignments; the R-C no-trailing-pad decision; supersede batch-55's `test_tc133b_alignment_directive_forces_none` (None→14/13); unfreeze (PR-A) + re-freeze (PR-B) `a2l.py`.
- **Out of scope:** **MOD_COMMON module-wide alignment defaults** (deliberately NOT honored — §6.2 R-A / §6.3 RISK-1; this is what preserves the batch-55 oracles and is a documented under-model of ASAM MCD-2, reversible as a follow-up); external-axis (COM_AXIS/RES_AXIS/CURVE_AXIS/AXIS_PTS_REF) length derivation (stays grey, batch-55); MEASUREMENT/scalar/VAL_BLK sizing (already handled); trailing pad-to-max-alignment / array-of-record stride (R-C reading (ii), rejected — §6.2 R-C); the DoS byte cap (already shipped batch-55 — reused, not re-added); any A2L-view restyle.
- **Reversible?** Yes — additive change inside a `length is None` guard behind a first-pass alignment detector; no new persisted state, no schema change. R-A (layout-local-only) and R-C (no trailing pad) are both reversible if a real ECU corpus later contradicts them. No one-way door.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| RECORD_LAYOUT | ASAM MCD-2 MC block describing a calibration object's on-disk byte layout, one component per body line. |
| Component | A RECORD_LAYOUT body line that contributes bytes: `NO_AXIS_PTS_*`, `NO_RESCALE_X`, `AXIS_PTS_*`, `FNC_VALUES`. Token[0]=name, **token[1]=POSITION INDEX (ordering, NOT a count)**, token[2]=datatype. |
| `ALIGNMENT_*` directive | A RECORD_LAYOUT body line `ALIGNMENT_<CLASS> N` (2 tokens) declaring that every component whose datatype falls in `<CLASS>` must START at an offset that is a multiple of `N`. Classes: `BYTE`, `WORD`, `LONG`, `INT64`, `FLOAT16_IEEE`, `FLOAT32_IEEE`, `FLOAT64_IEEE`. |
| Size class / alignment class | The mapping datatype → its governing `ALIGNMENT_*` directive (R-B): 1-byte→`BYTE`, 2-byte int→`WORD`, 4-byte int→`LONG`, 8-byte int→`INT64`, and the three IEEE float classes to their own directives. |
| Packed | A layout with NO body-level `ALIGNMENT_*`: every component has alignment 1, zero padding; the batch-55 behaviour. |
| Cumulative-offset walk | Track a running `offset`; per component, `offset = align_up(offset, component_alignment)` then `offset += size × element_count`. |
| `align_up(o, a)` | The smallest multiple of `a` that is ≥ `o` (`o` if `a ≤ 1` or `o % a == 0`). |
| Full-span-or-None | Safety contract (batch-55): the summer returns a byte total ONLY if every component, datatype, axis count, AND alignment value is classifiable; otherwise `None`. Never under-report (a short length would falsely pass the byte-range memory check → false-green). |
| MOD_COMMON alignment | Module-wide `ALIGNMENT_*` defaults in the `MOD_COMMON` block (demo `…:2173-2177`). **NOT** a RECORD_LAYOUT body line → **out of scope** (R-A). |

### 1.4 References
- Verified design seed: batch-55 `.dev-flow/2026-07-20-batch-55/01-requirements.md` §2.5 (taxonomy + oracle) + `02-review.md` **code-review F1** (the ALIGNMENT force-`None` hole this batch closes); batch-50 `.dev-flow/2026-07-19-batch-50/01-requirements.md §7`.
- Current impl (frozen oracle): `_record_layout_full_span` `s19_app/tui/a2l.py:1079-1177`; `_inline_axis_counts` `:1017-1076`; length-pass wiring `:1454-1465`; `axis_meta` build `:1444-1452`; `DATATYPE_SIZES` `:13-28`; `MAX_A2L_DECODE_BYTES` `:34`; axis-kind constants `:81-83`.
- ASAM MCD-2 MC (ASAP2) `ALIGNMENT_*` semantics (V1.6.1) — the demo file header block `examples/case_00_public/ASAP2_Demo_V161.a2l`.
- Supersession target: `tests/test_a2l_inline_axis_length.py:179-213` (`test_tc133b_alignment_directive_forces_none`).
- Locked A2L length prose (amended §6.5): `REQUIREMENTS.md:402-409`.
- qa-reviewer AT/TC catalog: `.dev-flow/2026-07-20-batch-56/01b-qa-catalog.md`.

### 1.5 Document overview
§2 stories + INVEST + the draft-time execution probe. §3 HLR. §4 LLR (with C-26 touched symbols + per-LLR validation). §4.9 AT/TC placeholder. §5.2 dual traceability. §6.2 the R-A/R-B/R-C decisions + rationale. §6.3 risks/security. §6.4 reconciliation. §6.5 amendments (the batch-55 TC-133b supersession + REQUIREMENTS.md prose).

---

## 2. Overall description

### 2.1 Product perspective
Additive change in the parsing layer (`s19_app/tui/a2l.py`, the frozen A2L oracle). Batch-55 introduced the summer as a post-axis-walk pass in `extract_a2l_tags`; batch-56 changes ONLY the body of `_record_layout_full_span` (and adds one private helper + one module constant map). The wiring, the `length is None` guard, `_inline_axis_counts`, the axis-kind census, and the DoS cap are unchanged. No new module, no service-layer change, no new persisted state.

### 2.2 Product functions
1. Detect the `ALIGNMENT_*` directives declared in a RECORD_LAYOUT body (first pass).
2. Sum a CURVE/MAP's on-disk byte span via a cumulative-offset walk, padding each component's start up to its datatype's declared alignment.
3. Size an alignment-free layout packed — byte-identical to batch-55.
4. Preserve full-span-or-None for unmodeled non-alignment components/directives, unknown datatypes, absent axis counts, malformed alignment values, and over-cap spans.
5. Return `a2l.py` to read-only-oracle status.

### 2.3 User characteristics
Firmware/calibration engineer reading the TUI A2L view. Today, a CURVE/MAP whose RECORD_LAYOUT declares `ALIGNMENT_*` renders grey (`length is None`, batch-55 force-`None`) even though its axes are inline and derivable; after this batch it shows a correct padded byte length and becomes memory-checkable. Packed CURVE/MAP behaviour (the demo corpus) is unchanged.

### 2.4 Constraints
- `a2l.py` is a C-27 engine-frozen oracle → PR-A must unfreeze in the same PR; re-freeze is a separate post-merge PR-B (a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard).
- Must NOT modify `tests/test_tui_a2l.py` (tc032-frozen); new white-box tests extend the NEW non-frozen `tests/test_a2l_inline_axis_length.py` (already exists, non-frozen, batch-55).
- Full-span-or-None: correctness-over-coverage. A wrong-but-non-`None` length is worse than grey (false-green memory check on a safety artifact).
- Textual SVG snapshots: **zero expected drift** — the demo has no body-level `ALIGNMENT_*`, so no demo A2L row changes value. Any snapshot drift is a regression signal (AT no-regression anchor). (Contrast batch-55, which had expected drift on 8 rows.)
- File budget ≤ 5 (increment): `a2l.py`, `tests/test_a2l_inline_axis_length.py`, the two guard files (PR-A unfreeze), `REQUIREMENTS.md`. PR-B (re-freeze) touches only the two guard files.

### 2.5 Assumptions and dependencies — **C-35 draft-time EXECUTION (decisive evidence)**

The alignment-aware candidate was **executed** over a synthetic ALIGNMENT fixture and the real demo (`examples/case_00_public/ASAP2_Demo_V161.a2l`) via `parse_a2l_file` (monkeypatched summer), not reasoned about. Probe: `scratchpad/b56_probe.py`. Output (verbatim, condensed):

```
== (A) synthetic ALIGNMENT_WORD fixture ==
   aligned span = 8   (hand-computed 8)   OK      # CURVE n_x=2: 1(UBYTE) + 2(SBYTE×2) + pad1 + 4(SWORD×2)
   packed  span = 7   (hand-computed 7)   OK      # same layout, ALIGNMENT_WORD line removed
== (C) R-C trailing-pad discrimination (CURVE n_x=3) ==
   reading(i) no-trailing-pad = 11   (expected 11)
   reading(ii) trailing-pad   = 12   (expected 12)   discriminates: True
== (B) real demo under monkeypatched alignment-aware summer ==
   ASAM.C.CURVE.STD_AXIS                  length=25   expected=25   OK
   ASAM.C.MAP.STD_AXIS.STD_AXIS           length=51   expected=51   OK
   ASAM.C.CURVE.FIX_AXIS.PAR_DIST         length=12   expected=12   OK
   ASAM.C.CURVE.COM_AXIS                  length=None expected=None OK
   CURVE/MAP total=12  derived(int)=8  None=4  (batch-55: 8 int / 4 None)  ← invariant
   RECORD_LAYOUTs declaring ALIGNMENT_* in body: NONE (all packed)
ALL MATCH
== superseded test's two layouts (axis_counts=[4]) ==
   summable   = 13   (unchanged, no alignment)
   with_align = 14   (was None; ALIGNMENT_WORD 2 → FNC_VALUES SWORD pads offset 5→6)
   trailing   = 13   (was None; ALIGNMENT_LONG 4 governs no present LONG datatype → zero effect)
```

**Hand-computed offset table — synthetic ALIGNMENT_WORD CURVE, `axis_counts=[2]`, layout declares `ALIGNMENT_WORD 2` only:**

| # | Component | datatype (tok[2]) | size | element count | align class → N | start = align_up(offset, N) | pad | end offset |
|---|-----------|-------------------|------|---------------|----------------|-----------------------------|-----|------------|
| 1 | `NO_AXIS_PTS_X` | UBYTE | 1 | 1 | BYTE → **undeclared=1** | align_up(0,1)=0 | 0 | 1 |
| 2 | `AXIS_PTS_X` | SBYTE | 1 | 2 (`n_x`) | BYTE → undeclared=1 | align_up(1,1)=1 | 0 | 3 |
| — | `ALIGNMENT_WORD 2` | — | — | — | (consumed in first pass; skipped in walk) | — | — | — |
| 3 | `FNC_VALUES` | SWORD | 2 | 2 (`prod`) | WORD → **declared=2** | align_up(3,2)=**4** | **1** | 8 |
| | | | | | | | **Σ span (reading i) = 8** (packed = 7) | |

**Full-corpus invariance:** all 12 demo CURVE/MAP tags size identically to batch-55 (8 int / 4 None); the ONLY body-level `ALIGNMENT_*` in the whole file lives in **`MOD_COMMON`** (`…:2173-2177`: `ALIGNMENT_BYTE 1`, `ALIGNMENT_WORD 2`, `ALIGNMENT_LONG 4`, `ALIGNMENT_FLOAT32_IEEE 4`, `ALIGNMENT_FLOAT64_IEEE 4`), which is **not** a RECORD_LAYOUT body and is therefore ignored by R-A. If MOD_COMMON WERE honored, `ASAM.C.CURVE.STD_AXIS` would size **26** (FNC_VALUES SWORD padded 9→10), NOT 25 — so the layout-local-only scope is not cosmetic; it is what keeps the batch-55 oracle correct. **AT (MOD_COMMON-not-honored, §3) anchors this** (demo CURVE stays 25 despite the module-wide `ALIGNMENT_WORD 2`).

**Secondary independent oracle:** UNAVAILABLE. `pip show a2lparser pya2l` → not installed (exit 1). The oracle is **hand-computed + ASAM-spec-cited + probe-executed only** (no third-party A2L reference sizer in this environment).

**Assumptions (invalidate the batch if false):** (a) batch-55's summer + wiring are on `main` and `layout["lines"]` carries the full RECORD_LAYOUT body INCLUDING any `ALIGNMENT_*` lines — **verified** (`extract_record_layouts`, `a2l.py:606-621`, `"lines": lines`; probe reads them); (b) `ALIGNMENT_*` directives, when present in a RECORD_LAYOUT, are 2-token lines `ALIGNMENT_<CLASS> N` — **verified** (demo MOD_COMMON block + ASAM grammar); (c) the demo record layouts declare no body-level `ALIGNMENT_*` — **verified** (probe: `NONE (all packed)`).

### 2.6 Source user stories — Definition of Ready (INVEST)

| ID | User story | Source | DoR |
|----|-----------|--------|-----|
| US-A56 | As a firmware engineer, I want a CURVE/MAP whose RECORD_LAYOUT declares `ALIGNMENT_*` directives to show a CORRECT padded byte `length` in the A2L view (inter-component padding accounted for), so that alignment-declaring calibration objects become memory-checkable instead of grey — WITHOUT changing any packed (alignment-free) layout's length. | Backlog TOP item (batch-56); code-review F1 (batch-55); operator 2026-07-20 | **READY** |
| US-P2b56 | As a maintainer, I want `a2l.py` re-added to both C-27 engine-frozen guard sets after the alignment-aware summer lands, so the module returns to read-only-oracle status and future accidental edits trip at the increment boundary. | Backlog P-2 pattern; C-27 | **READY** (post-merge PR-B) |

#### Refinement log

**US-A56 — alignment-aware padding sizing**
- **INVEST:** I ✓ · N ✓ · V ✓ (an alignment-declaring CURVE/MAP flips grey→checkable) · E ✓ (math executed, oracle hand-computed + probe-matched) · S ✓ (one function body + one helper + one map, parse-time, ≤5 files) · T ✓ (byte-value ATs over synthetic + demo).
- **Functionality:** user = calibration engineer · outcome = correct padded `length` on alignment-declaring inline CURVE/MAP; packed layouts unchanged; external stays `None` · why = enables the byte-range memory check on alignment-declaring objects without false-green, and closes batch-55 F1 (blanket force-`None` was a coverage gap, not a correctness bug — a valid derivable span was thrown away) · out of scope = MOD_COMMON defaults, trailing-pad stride, external-axis derivation.
- **Feasibility:** path = rewrite `_record_layout_full_span` as a cumulative-offset walk + `_collect_declared_alignments` first pass + `_DATATYPE_ALIGNMENT_DIRECTIVE` map; consumes batch-55's wiring/axis-resolver/DoS-cap unchanged. Unknowns = R-C (trailing pad?) — RESOLVED reading (i), §6.2. Fits one batch = yes.
- **Evaluability (black-box):** When `parse_a2l_file(tmp_with_alignment_curve)` runs, the user observes the CURVE's `length` == the hand-computed padded value (e.g. 8, not the packed 7); and `parse_a2l_file(demo)` still yields `ASAM.C.CURVE.STD_AXIS length==25` (MOD_COMMON's `ALIGNMENT_WORD 2` NOT honored) → the gate ATs.
- **Classification:** `READY`.

**US-P2b56 — re-freeze a2l.py (post-merge PR-B)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓ (guard-green + zero-diff).
- **Feasibility:** guard-files-only; gated on PR-A merge (same-PR re-freeze self-trips). Mirrors batch-50 LLR-P2.1, batch-54 PR-B, batch-55 LLR-P2b.1.
- **Evaluability:** with `a2l.py` back in both `_ENGINE_PATHS`, the frozen-file guards pass because merged source == `main` source; `git diff main -- a2l.py` empty.
- **Classification:** `READY` (post-merge).

---

## 3. High-level requirements (HLR)

### HLR-A56 — alignment-aware full-span sizing (`R-A2L-016`)
- **Traceability:** US-A56
- **Statement:** When `parse_a2l_file` sizes a CURVE/MAP whose resolved RECORD_LAYOUT declares one or more `ALIGNMENT_<CLASS> N` directives in its body, the system **shall** compute `length` by a cumulative-offset walk in which each summable component's start offset is aligned up to the declared alignment `N` for that component's datatype size-class (per the R-B datatype→directive map), a size-class with no declared directive taking alignment 1, and `ALIGNMENT_*` lines being consumed as directives rather than forcing `None`; and the system **shall**, when the RECORD_LAYOUT body declares NO `ALIGNMENT_*`, size the layout packed (every component alignment 1, zero inter-component padding) byte-identically to the batch-55 summer; and the system **shall** compute the span as the end offset of the last summable component with NO trailing pad-to-max-alignment (R-C reading (i)); and the system **shall** return `None` (full-span-or-None) for any unmodeled non-alignment component/directive, unknown datatype, absent axis count, malformed (`non-int`) alignment value, or a running offset exceeding `MAX_A2L_DECODE_BYTES`; and the system **shall NOT** honor `ALIGNMENT_*` defaults declared in `MOD_COMMON` (only RECORD_LAYOUT-body-local directives, R-A).
- **Rationale (informative):** batch-55 blanket-force-`None`'d any `ALIGNMENT_*` line (code-review F1) — correct-but-conservative (grey, never wrong), but it threw away a derivable span. `ALIGNMENT_*` induces deterministic inter-component padding; modeling it recovers coverage without risking under-report. Layout-local-only scope (R-A) preserves the batch-55 oracles by construction and is the operator-framed, oracle-preserving reading; MOD_COMMON module-wide honoring is a documented under-model (§6.3 RISK-1). No trailing pad (R-C) because a CURVE/MAP is a single object, not an array element.
- **Validation:** `test` + `analysis` · **Priority:** high
- **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py` (the alignment TCs + the amended TC-133b + regression) + the §2.5 offset-table derivation (aligned=8 vs packed=7; demo 25/51/12/None invariant; MOD_COMMON-honored counterfactual = 26).
- **Numeric pass threshold:** synthetic `ALIGNMENT_WORD 2` CURVE (`axis_counts=[2]`) → `length==8` (packed same layout → 7); demo `ASAM.C.CURVE.STD_AXIS==25` ∧ `ASAM.C.MAP.STD_AXIS.STD_AXIS==51` ∧ `ASAM.C.CURVE.FIX_AXIS.PAR_DIST==12` ∧ `ASAM.C.CURVE.COM_AXIS is None` (all unchanged); 8/12 demo CURVE/MAP derive, 4/12 `None`, 0 change vs batch-55; full suite 0 fail; 0 snapshot drift.
- **Acceptance (black-box):**
  - **Observable outcome:** a CURVE/MAP whose RECORD_LAYOUT declares `ALIGNMENT_*` shows a correct padded byte length and becomes memory-checkable; packed CURVE/MAP (the whole demo corpus) and external-axis rows are unchanged.
  - **Shipped surface:** `parse_a2l_file(Path)` tag `length` field (C-12 chain head); downstream `enrich_tags_and_render` → A2L view row severity (output-then-consume).
  - **Deliverable + observation:** the parsed tag dict at `path`; `tags[i]["length"]` == the exact padded byte value for an alignment-declaring inline CURVE/MAP; == the packed value (25/51/12) for the demo; `is None` for external / unmodeled / malformed.
  - **Acceptance test(s):** `AT-113` (synthetic aligned CURVE `length==8`, packed counterfactual `==7`), `AT-114` (demo 25/51/12/None ALL unchanged — packed no-regression + 0 snapshot drift), `AT-115` (**MOD_COMMON not honored** — demo CURVE stays 25 despite module-wide `ALIGNMENT_WORD 2`; the counterfactual 26 is RED), `AT-116` (full-span-or-None preserved: an alignment-declaring layout with an unmodeled non-alignment component still → `None`), `AT-117` (malformed alignment value `ALIGNMENT_WORD x` → `None`, no exception). Provisional-until-qa-catalog.
  - **Boundary catalog (QC-3):** ☑ empty (layout with only an `ALIGNMENT_*` line, no component → `None` via `contributed==False`) · ☑ boundary (declared alignment that produces zero pad because offset already aligned → == packed; alignment class matching no present datatype → zero effect, the `trailing_align`=13 case) · ☑ invalid (non-int alignment value → `None`; unknown datatype → `None`; unmodeled component → `None`) · ☑ error (external axis → `None`, unchanged from batch-55).

### HLR-P2b56 — re-freeze `a2l.py` into the C-27 dual-guard set (`R-A2L-017`)
- **Traceability:** US-P2b56
- **Statement:** After the PR-A source edits merge to `main`, the guard suite **shall** re-include `"s19_app/tui/a2l.py"` in BOTH `_ENGINE_PATHS` (`tests/test_engine_unchanged.py` and `tests/test_tui_directionb.py` tc031), the "UNFROZEN for batch-56" NOTE **shall** be restored to the re-frozen wording, and the guards **shall** pass with a zero source diff of `a2l.py` vs `main`.
- **Rationale (informative):** returns the A2L oracle to read-only. Only satisfiable post-merge — a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard (C-27 corollary: re-freeze ADDS → post-merge PR-B). Mirrors batch-50 `R-A2L-009`, batch-54 PR-B, batch-55 `R-A2L-015`.
- **Validation:** `test` + `inspection` · **Priority:** medium
- **Executed verification:** `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc027 or tc032"` + `git diff main -- s19_app/tui/a2l.py`.
- **Numeric pass threshold:** tc027/tc031/tc032 green with `a2l.py` in both frozen sets; `git diff main -- s19_app/tui/a2l.py` empty; PR-B touches ONLY the two guard test files.
- **Acceptance (black-box):**
  - **Observable outcome:** the frozen-file guards pass because merged source == `main` source.
  - **Shipped surface:** the guard tests.
  - **Deliverable + observation:** both `_ENGINE_PATHS` contain `a2l.py`; guards green; empty diff.
  - **Acceptance test(s):** `AT-118` (post-merge PR-B). **Sequencing flag:** un-runnable until PR-A merges.
  - **Boundary catalog:** ☑ error (a2l.py ≠ main → guard RED) · empty/boundary/invalid N/A (binary guard).

---

## 4. Low-level requirements (LLR)

> C-26: every LLR declares its touched symbols (verified `file:line`, or `NEW — created in Phase 3`). Reverse-greped at Phase 2/3.

### LLR-A56.1 — `_record_layout_full_span` alignment-aware cumulative-offset walk
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** `_record_layout_full_span` (`a2l.py:1079-1177` — REWRITTEN body; signature `(layout, axis_counts)` unchanged). Reads `DATATYPE_SIZES` (`a2l.py:13`), `MAX_A2L_DECODE_BYTES` (`a2l.py:34`), `math.prod`, and calls `_collect_declared_alignments` (LLR-A56.2) + a module-level `align_up` inlined or helper.
- **Statement:** `_record_layout_full_span` **shall** first collect the RECORD_LAYOUT's body-declared alignments (`_collect_declared_alignments(layout["lines"])`), then iterate `layout["lines"]` maintaining a running `offset` (init 0) and a `contributed` flag, and for each non-empty line: (a) if `token[0]` is an `ALIGNMENT_*` directive name, **shall** skip it (already consumed in the first pass); (b) else resolve the component element-count via the §2.5 taxonomy keyed on `axis_counts` (`token[0]`), returning `None` if unclassifiable or a needed axis count is absent; (c) **shall** require `len(tokens) >= 3`, read the datatype as `token[2]` (NOT `token[1]`, the position index), resolve `size = DATATYPE_SIZES.get(token[2])` (`None` → return `None`); (d) resolve the component's alignment via the R-B datatype→directive map and the collected declarations (undeclared class → 1); (e) **shall** set `offset = align_up(offset, alignment)` then `offset += size × element_count`, set `contributed = True`, and return `None` if `offset > MAX_A2L_DECODE_BYTES`; and after the walk **shall** return `None` if nothing contributed, else return `offset` (the last component's end — **no trailing pad**, R-C reading (i)).
- **Acceptance criteria (informative):** synthetic `ALIGNMENT_WORD 2` CURVE `axis_counts=[2]` → 8 (packed same layout → 7); a `token[1]`-as-count mutation still fails (MAJOR-1 guard, inherited); an alignment that leaves the offset already aligned → == packed; the trailing pad reading (ii) would give 12 for the §2.5(C) fixture but the impl returns 11.
- **Validation:** `test (unit)` — TC-143. **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py -k "alignment and full_span"`. **Numeric threshold:** in-test aligned layout → hand-computed padded total exact (8, 11, 14); the packed counterfactual differs by the pad byte(s); reading-(ii) value asserted-against (impl ≠ 12 for the (C) fixture).

### LLR-A56.2 — R-B datatype→alignment map + `_collect_declared_alignments` first pass
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** NEW module constant `_DATATYPE_ALIGNMENT_DIRECTIVE` (dict, near `DATATYPE_SIZES` `a2l.py:13-28` — NEW, Phase 3); NEW private `_collect_declared_alignments(lines) -> Optional[dict[str,int]]` (module-level, near `_record_layout_full_span` — NEW, Phase 3); NEW derived `_ALIGNMENT_DIRECTIVES = frozenset(_DATATYPE_ALIGNMENT_DIRECTIVE.values())` (NEW, Phase 3).
- **Statement:** The module **shall** define `_DATATYPE_ALIGNMENT_DIRECTIVE` mapping every `DATATYPE_SIZES` key to its governing directive name — `{UBYTE,SBYTE,BYTE}→ALIGNMENT_BYTE`, `{UWORD,SWORD,WORD}→ALIGNMENT_WORD`, `{ULONG,SLONG,LONG}→ALIGNMENT_LONG`, `{A_UINT64,A_INT64}→ALIGNMENT_INT64`, `FLOAT16_IEEE→ALIGNMENT_FLOAT16_IEEE`, `FLOAT32_IEEE→ALIGNMENT_FLOAT32_IEEE`, `FLOAT64_IEEE→ALIGNMENT_FLOAT64_IEEE` — such that its key-set equals `DATATYPE_SIZES`' key-set (every sizable datatype has a governing alignment class); and `_collect_declared_alignments` **shall** iterate the layout lines, and for each line whose `token[0]` is in `_ALIGNMENT_DIRECTIVES` and which has ≥2 tokens **shall** parse `int(token[1])` inside a `try/except (ValueError, TypeError)` returning `None` (fail-closed on a malformed alignment value), building `{directive_name: N}`; a directive appearing twice **shall** take the last declared value.
- **Rationale (informative):** the alignment is keyed on the DATATYPE, not the raw byte size, because `ALIGNMENT_WORD` (2-byte int) and `ALIGNMENT_FLOAT16_IEEE` (2-byte float) are distinct directives for the same byte width; a per-datatype map is the ASAM-correct discriminant. `_collect_declared_alignments` returning `None` (not `{}`) on a garbage value propagates full-span-or-None to `_record_layout_full_span`.
- **Validation:** `test (unit)` — TC-144. **Executed verification:** `pytest -q ... -k "alignment_map or declared_alignments"`. **Numeric threshold:** `set(_DATATYPE_ALIGNMENT_DIRECTIVE) == set(DATATYPE_SIZES)` True; `_collect_declared_alignments(["ALIGNMENT_WORD 2","ALIGNMENT_LONG 4"]) == {"ALIGNMENT_WORD":2,"ALIGNMENT_LONG":4}`; `["ALIGNMENT_WORD x"]` → `None`; a packed layout (no `ALIGNMENT_*`) → `{}`.

### LLR-A56.3 — packed no-regression (batch-55 oracles byte-identical)
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** none new — asserts the alignment-free branch of LLR-A56.1 (`_collect_declared_alignments` returns `{}` → every alignment resolves to 1 → `align_up` is a no-op → span == Σ size×count).
- **Statement:** For any RECORD_LAYOUT declaring no body-level `ALIGNMENT_*`, `_record_layout_full_span` **shall** return the identical byte total the batch-55 summer returned (packed), such that parsing the demo yields the identical 8 derived / 4 `None` CURVE/MAP split with the identical values (25/51/12/None) and NO Textual snapshot drift.
- **Rationale (informative):** `align_up(o, 1) == o`, so the packed path is arithmetically the batch-55 path; probe-verified over the full demo corpus (`RECORD_LAYOUTs declaring ALIGNMENT_* in body: NONE`).
- **Validation:** `test` + `inspection` — TC-145 / AT-114. **Executed verification:** `pytest -q ... -k "packed or no_regression"` + full-suite `pytest -q` + snapshot census. **Numeric threshold:** demo CURVE/MAP values identical to batch-55 (25/51/12/None); full suite 0 fail; 0 snapshot drift.

### LLR-A56.4 — MOD_COMMON exclusion + full-span-or-None preserved (R-A + safety)
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** `_record_layout_full_span`, `_collect_declared_alignments` (the scope of `layout["lines"]` — only the RECORD_LAYOUT body, never the module tree).
- **Statement:** The summer **shall** derive declared alignments ONLY from `layout["lines"]` (the RECORD_LAYOUT body), and **shall NOT** read `MOD_COMMON` or any module-wide alignment default; and it **shall** return `None` for any `≥3`-token line whose `token[0]` is neither an `ALIGNMENT_*` directive nor a taxonomy component (an unmodeled non-alignment directive/component — e.g. `AXIS_RESCALE_X`, `RESERVED`, `IDENTIFICATION`), never silently skipping it (that would under-report → false-green).
- **Rationale (informative):** R-A oracle-preservation (§6.2); honoring MOD_COMMON would flip demo CURVE 25→26 (§2.5). Distinguishing "consume as directive" (`ALIGNMENT_*`) from "force None" (any other non-component) is the precise line that closes batch-55 F1 without re-opening the under-report hole.
- **Validation:** `test (unit + e2e)` — TC-146 / AT-115 / AT-116. **Executed verification:** `pytest -q ... -k "mod_common or unmodeled"`. **Numeric threshold:** demo CURVE.STD_AXIS==25 through `parse_a2l_file` (NOT 26); an alignment-declaring layout carrying `RESERVED 4 UBYTE` → `None`.

### LLR-A56.5 — fail-closed on malformed layout / alignment / axis (robustness)
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** `_record_layout_full_span`, `_collect_declared_alignments` (defensive branches).
- **Statement:** The summer **shall** use `DATATYPE_SIZES.get(...)` (never subscript — subscript raises `KeyError`), **shall** length-guard token access (`len(tokens) >= 2` before `token[1]` in the alignment collector; `len(tokens) >= 3` before `token[2]` in the walk), **shall** parse each alignment value AND each `max_axis_points` inside a `try/except (ValueError, TypeError)` returning `None` (NEVER an `isdigit()`/regex pre-predicate — sec-F3 inherited), and **shall** return `None` (never raise) for a garbage datatype, a non-int alignment value, a truncated line, an absent axis count, or an over-cap offset, so that a malformed alignment-declaring CURVE/MAP parses to grey without aborting the load.
- **Rationale (informative):** the parsing layer's collect-don't-abort contract; a hostile A2L must not crash the TUI. Reuses batch-55's `MAX_A2L_DECODE_BYTES` cap (no new constant) — the padded offset is bounded by the same 1 MiB honesty ceiling.
- **Validation:** `test (unit + e2e)` — TC-147 / AT-117. **Executed verification:** `pytest -q ... -k "malformed or fail_closed"`. **Numeric threshold:** `ALIGNMENT_WORD x` layout through `parse_a2l_file` → `length is None`, 0 exceptions; over-cap padded span → `None`.

### LLR-A56.6 — UNFREEZE `a2l.py` in PR-A (enabling)
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:129`, entry `"s19_app/tui/a2l.py"`; `tests/test_tui_directionb.py:5437`, same entry) + the two NOTE blocks (`test_engine_unchanged.py:125-128`, `test_tui_directionb.py:5433-5436`).
- **Statement:** In PR-A (the source PR), `"s19_app/tui/a2l.py"` **shall** be removed from BOTH `_ENGINE_PATHS` tuples and the two "RE-FROZEN … any further edit needs an explicit unfreeze" NOTE blocks **shall** be replaced with an "UNFROZEN for batch-56 (operator-approved alignment-aware summer); RE-FREEZE in follow-up PR-B" note; and all new batch-56 white-box tests **shall** extend the EXISTING non-frozen `tests/test_a2l_inline_axis_length.py`, never the tc032-frozen `tests/test_tui_a2l.py`.
- **Rationale (informative):** C-27 corollary — an unfreeze REMOVES the path from the guard set, so the same PR may edit `a2l.py`; the re-freeze (LLR-P2b56.1) is the separate post-merge PR-B.
- **Validation:** `inspection` — TC-148. **Executed verification:** grep `"s19_app/tui/a2l.py"` absent from both `_ENGINE_PATHS` in PR-A; new tests in `test_a2l_inline_axis_length.py`, not `test_tui_a2l.py`; `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` green post-edit. **Numeric threshold:** 0 occurrences of `"s19_app/tui/a2l.py"` in either `_ENGINE_PATHS` in PR-A; tc031/tc032 green.

### LLR-SUP56.1 — supersede batch-55 `test_tc133b_alignment_directive_forces_none`
- **Traceability:** HLR-A56 · **Touched symbol (C-26):** `tests/test_a2l_inline_axis_length.py:179-213` (`test_tc133b_alignment_directive_forces_none`, NON-frozen, editable).
- **Statement:** The batch-55 assertions that the two alignment-declaring layouts return `None` **shall** be amended to assert the batch-56 derived padded values — `with_alignment` (`ALIGNMENT_WORD 2`, axis_counts=[4]) → `14` (FNC_VALUES SWORD start padded 5→6), `trailing_align` (`ALIGNMENT_LONG 4`, axis_counts=[4]) → `13` (the declared LONG alignment governs no present LONG datatype → zero effect) — the `summable` (no-alignment) case → `13` **shall** remain, the docstring/intent comment **shall** be updated from "force-None" to "alignment-aware padding (batch-56)", and the change **shall** be recorded as a §6.5 Before→After amendment. The false-green anchor role passes to AT-116 (unmodeled non-alignment component → `None`).
- **Rationale (informative):** batch-55 authored TC-133b to lock the force-`None` behavior batch-56 deliberately flips (code-review F1); leaving it unamended is a false regression signal at the Phase-4 gate. It lives in a non-frozen file, so editing it is sanctioned. The `trailing_align`→13 case is a load-bearing test: it proves a declared alignment affects ONLY components of its governed size-class.
- **Validation:** `test` + `inspection` — TC-149. **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py -k tc133b`. **Numeric threshold:** amended test asserts `14`/`13`/`13` and passes; 0 stale `is None` assertions on the two alignment layouts remain.

### LLR-P2b56.1 — re-freeze `a2l.py` into both `_ENGINE_PATHS` (PR-B, post-merge)
- **Traceability:** HLR-P2b56 · **Touched symbol (C-26):** `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-131`, `tests/test_tui_directionb.py:5428-5440`) + the two NOTE blocks.
- **Statement:** In PR-B (post-merge, guard-files-only), `"s19_app/tui/a2l.py"` **shall** be re-inserted into BOTH `_ENGINE_PATHS` tuples with a re-frozen NOTE, and the guards (tc027/tc031) **shall** pass with `git diff main -- s19_app/tui/a2l.py` empty; and the tc032 A2L-parser freeze (`_ENGINE_TEST_FILES`, `test_tui_directionb.py:5442+`) **shall** remain green, confirming batch-56 white-box tests landed in the non-frozen `tests/test_a2l_inline_axis_length.py`, not `tests/test_tui_a2l.py`.
- **Rationale (informative):** returns the oracle to read-only. Un-satisfiable pre-merge (same-PR re-freeze self-trips). Mirrors batch-50 LLR-P2.1/P2.2, batch-54 PR-B, batch-55 LLR-P2b.1.
- **Validation:** `test` + `inspection` — TC-150. **Executed verification:** `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc027 or tc032"` + `git diff main -- s19_app/tui/a2l.py`. **Numeric threshold:** tc027/tc031/tc032 green; empty diff; PR-B touches ONLY the two guard files. **Sequencing flag:** gated on PR-A merge.

---

## 4.9 Canonical AT / TC registry

`<<QA-CATALOG>>`

*(Orchestrator: splice `.dev-flow/2026-07-20-batch-56/01b-qa-catalog.md` Sections B/C/D — Black-box AT registry + White-box TC registry + dual traceability — here. The qa-reviewer authors this catalog in parallel. Provisional ids used in §3/§4 (AT-113..118, TC-143..150) continue batch-55's sequence (ended AT-112 / TC-142); the spliced catalog is authoritative and any id drift is reconciled at §5.2. C-12 chain head = `parse_a2l_file`; all new TCs extend the NON-frozen `tests/test_a2l_inline_axis_length.py`.)*

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A (white-box, `TC-*`):** `test (unit)` for the alignment-aware walk, the R-B map + collector, packed-regression, MOD_COMMON exclusion, and fail-closed; `inspection` for the guard-file toggles + snapshot census + the TC-133b supersession; `analysis` for the 8-vs-7 offset-table derivation and the MOD_COMMON-honored counterfactual (26).
- **Layer B (black-box, `AT-*`):** `parse_a2l_file(Path)` over synthetic single-line A2L strings whose RECORD_LAYOUT declares `ALIGNMENT_*` (padded byte value computable from the string) + the real demo (tags located BY NAME), asserting THE BYTE VALUE / the `None` — never "non-empty". AT-115 asserts the MOD_COMMON-not-honored invariant (demo CURVE==25 despite module-wide `ALIGNMENT_WORD 2`). AT (output-then-consume) drives `enrich_tags_and_render` over the parse-produced tags where a padded length flips a row's memory-checkability (C-12) — final id in the qa catalog.

### 5.2 Dual-traceability

> A requirement is complete only when BOTH chains exist. Ids below are provisional (author-side); the spliced §4.9 qa catalog is authoritative — the orchestrator reconciles.

**Behavioral (black-box) — per story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-A56 | alignment-declaring CURVE/MAP shows a correct padded byte length; packed/demo & external unchanged | `parse_a2l_file` `length`; `enrich_tags_and_render` row severity | AT-113 (aligned=8/packed=7), AT-114 (demo 25/51/12/None invariant + 0 drift), AT-115 (MOD_COMMON not honored: 25 not 26), AT-116 (unmodeled component → None), AT-117 (malformed alignment → None) | ⏳ Phase 4 |
| US-P2b56 | frozen-file guards pass; merged source == main | guard tests | AT-118 (post-merge PR-B) | ⏳ post-merge |

**Functional (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-A56 | test (e2e/pilot) | AT-113..117 (via `parse_a2l_file`) | black-box gate set |
| LLR-A56.1 | test (unit) | TC-143 | alignment-aware walk; offset-table exact; R-C reading (i) |
| LLR-A56.2 | test (unit) | TC-144 | R-B map key-set == DATATYPE_SIZES; collector fail-closed |
| LLR-A56.3 | test + inspection | TC-145 / AT-114 | packed == batch-55; 0 snapshot drift |
| LLR-A56.4 | test (unit + e2e) | TC-146 / AT-115 / AT-116 | MOD_COMMON excluded; unmodeled → None |
| LLR-A56.5 | test (unit + e2e) | TC-147 / AT-117 | malformed/over-cap → None, no raise |
| LLR-A56.6 | inspection | TC-148 | unfreeze PR-A; tc031/tc032 green |
| LLR-SUP56.1 | test + inspection | TC-149 | TC-133b amended None→14/13/13 |
| LLR-P2b56.1 | test + inspection | TC-150 | re-freeze PR-B; empty diff |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 passing TC.
- Every user story has ≥1 passing `AT-NNN` observing its outcome through `parse_a2l_file` (+ the render consumer) with boundary + negative evidence.
- Synthetic aligned CURVE `length==8` (packed counterfactual 7); demo 25/51/12/None ALL unchanged; MOD_COMMON-honored counterfactual (26) is RED for the impl.
- 0 blocker fails; full suite 0 fail; **0 Textual snapshot drift** (no demo A2L row changes value).
- `git diff main -- s19_app/tui/a2l.py` empty after PR-B; PR-B touches only the two guard files.

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. `align_up(o,a)` = `o if a<=1 or o%a==0 else o + (a - o%a)`.

### 6.2 Relevant design decisions (the pinned governing rules)

**R-A — alignment padding is RECORD_LAYOUT-body-local only (oracle-preserving).** Alignment padding applies **if and only if** an `ALIGNMENT_*` directive is DECLARED in the RECORD_LAYOUT body (`layout["lines"]`). Absent ANY body-level `ALIGNMENT_*`, the layout is **packed** (alignment 1 for every component, padding 0). `MOD_COMMON` module-wide alignment defaults are **NOT** honored.
- *ASAM reasoning:* ASAM MCD-2 MC lets `ALIGNMENT_*` be declared at MOD_COMMON (module default) OR inside a RECORD_LAYOUT (local override). Honoring MOD_COMMON is the fuller reading, but the demo's `MOD_COMMON` (`…:2173-2177`) declares `ALIGNMENT_WORD 2`/`ALIGNMENT_LONG 4`, which — if applied — would flip `ASAM.C.CURVE.STD_AXIS` from the batch-55 oracle **25** to **26** (probe-computed). The batch-55 oracles were hand-computed as PACKED spans; honoring MOD_COMMON would silently invalidate them.
- *Decision:* scope to layout-local directives. This (i) preserves every batch-55 oracle by construction (the demo's record layouts declare zero body-level `ALIGNMENT_*` — probe: `NONE (all packed)`), and (ii) is the operator-framed, oracle-preserving reading. **Stated as a `shall NOT` in HLR-A56 / LLR-A56.4.**
- *Code reads it as:* `_collect_declared_alignments(layout["lines"])` — the collector's ONLY input is the RECORD_LAYOUT body; the module tree / MOD_COMMON is never consulted.
- *Risk/reversibility:* documented under-model (§6.3 RISK-1); reversible as a follow-up if a real corpus ever needs MOD_COMMON semantics.

**R-B — datatype→alignment-directive map.** Each component's start offset is aligned up to the declared alignment for its DATATYPE's size class: `ALIGNMENT_BYTE`→{UBYTE,SBYTE,BYTE}(1B); `ALIGNMENT_WORD`→{UWORD,SWORD,WORD}(2B); `ALIGNMENT_LONG`→{ULONG,SLONG,LONG}(4B); `ALIGNMENT_INT64`→{A_UINT64,A_INT64}(8B); `ALIGNMENT_FLOAT16_IEEE`→FLOAT16_IEEE(2B); `ALIGNMENT_FLOAT32_IEEE`→FLOAT32_IEEE(4B); `ALIGNMENT_FLOAT64_IEEE`→FLOAT64_IEEE(8B). A size class with no declared directive → alignment 1 (packed) for that class.
- *ASAM reasoning:* alignment is per-datatype, not per-byte-width, because `ALIGNMENT_WORD` (2-byte int) and `ALIGNMENT_FLOAT16_IEEE` (2-byte float) are distinct directives sharing a byte width. A per-datatype map is the correct discriminant; keying on byte size alone would conflate them.
- *Code reads it as:* `_DATATYPE_ALIGNMENT_DIRECTIVE.get(token[2])` → directive name → `declared.get(directive, 1)`.

**R-C — NO trailing pad (reading (i)); span = last component's end offset.** The record's total is NOT padded up to the max declared alignment (struct-array-stride, reading (ii) — rejected).
- *Two readings:* (i) no trailing pad — span = the last summable component's end offset (single-object byte span); (ii) trailing pad — pad the total up to the max component alignment (array-of-record element stride).
- *Decision:* **reading (i).** Justification tied to the memory-coverage use: (1) a CURVE/MAP CHARACTERISTIC is a SINGLE calibration object, not an array element; the byte-range memory check verifies the object's DATA bytes are present in the S19 image, and the on-disk data footprint runs from the object's base address to the end of its last data component; trailing pad-to-max-alignment is the stride that aligns the NEXT object, not part of THIS object's data footprint. (2) The batch-55 "never under-report" contract is about DATA components (a short axis/function count → false-green on missing data); trailing PAD bytes are non-data filler, so omitting them cannot cause a data false-green. (3) Both readings coincide for packed layouts (max alignment 1 → 0 trailing pad), so reading (i) preserves the batch-55 oracles identically; they diverge only for alignment-declaring layouts, where (i) is the object's true data span. Probe §2.5(C) exhibits a fixture where (i)=11, (ii)=12.
- *Not flagged for a gate AskUserQuestion:* the memory-coverage semantics resolve it — reading (i) is the on-disk data footprint. Reversible if a real corpus of array-of-record CHARACTERISTICs (a CURVE with `MATRIX_DIM > 1`, absent here) later needs stride semantics.
- *Code reads it as:* `return offset` after the walk — the running end offset, no post-loop `align_up`.

### 6.3 Open risks

| ID | Risk | Severity | Mitigation |
|----|------|----------|-----------|
| RISK-1 | **MOD_COMMON under-model (R-A).** By ignoring module-wide `ALIGNMENT_*`, a real ECU whose objects ARE aligned per MOD_COMMON but whose RECORD_LAYOUTs don't re-declare it will size PACKED (too small) → a potential under-report false-green on that object. | Medium | Documented, operator-framed, oracle-preserving decision. The demo corpus is unaffected (all packed). If a real corpus surfaces MOD_COMMON-aligned objects, add a MOD_COMMON default pass as a follow-up batch — reversible, no schema change. Flagged here for the gate. |
| RISK-2 | R-C wrong for array-of-record CHARACTERISTICs (would need trailing pad). | Low | No such record in the demo corpus (`MATRIX_DIM>1` CURVE absent). Reading (i) is correct for single objects; reversible follow-up if needed. |
| RISK-3 | An `ALIGNMENT_*` value that is legal but absurd (e.g. `ALIGNMENT_WORD 1048577`) inflates the padded offset past the DoS cap. | Low | The offset is bounded by the existing `MAX_A2L_DECODE_BYTES` (1 MiB) check inside the walk → `None` (grey), no allocation. Reuses batch-55's cap; no new surface (§6.3-sec). |
| RISK-4 | The re-freeze (PR-B) is applied same-PR by mistake → self-trips the vs-main guard. | Low | Sequencing flag on LLR-P2b56.1 + HLR-P2b56; mirrors batch-50/54/55. |
| RISK-5 | A batch-55 test other than TC-133b silently depends on `ALIGNMENT_*`→`None`. | Low | Supersession census (§6.5) — greped: only `test_tc133b_alignment_directive_forces_none` asserts alignment→None (`tests/test_a2l_inline_axis_length.py:179-213`); no other test in the suite asserts alignment-layout sizing. Confirm at Phase-2 census. |

**Security (inherits batch-55):** the alignment walk adds no new external surface. `DATATYPE_SIZES.get(...)` (never subscript); alignment values parsed via `int()` in `try/except` (fail-closed, no `isdigit()` pre-predicate); the padded offset bounded by the existing `MAX_A2L_DECODE_BYTES` cap. No new file/network/exec surface. A hostile alignment-declaring A2L parses to grey or a bounded value, never a crash or unbounded allocation. **Security-reviewer loop-in recommended at sign-off** (parsing-layer change on a frozen oracle) though the surface delta is minimal.

### 6.4 Phase-1 reconciliation log
No LLR threshold or statement changed at draft (this is a fresh authoring, not an iterate-to-refine). One supersession is recorded as a §6.5 amendment (LLR-SUP56.1), body-first: the amended test values (14/13/13) are computed and probe-verified (§2.5) BEFORE the §6.5 row asserts them. No parent-HLR threshold contradicts its LLRs (HLR-A56 numeric thresholds = the union of LLR-A56.1..5 thresholds).

### 6.5 Requirement amendments (Before / After · Deleted / New)

**AMD-1 — supersede batch-55 `test_tc133b_alignment_directive_forces_none` (LLR-SUP56.1).**
- **Before (batch-55, `tests/test_a2l_inline_axis_length.py:179-213`):** `_record_layout_full_span(with_alignment, [4]) is None` (ALIGNMENT_WORD forces None); `_record_layout_full_span(trailing_align, [4]) is None` (trailing ALIGNMENT_LONG forces None). Intent comment: "An `ALIGNMENT_*` padding directive forces full-span-or-None (never under-report)."
- **After (batch-56):** `_record_layout_full_span(with_alignment, [4]) == 14` (FNC_VALUES SWORD start padded 5→6 by `ALIGNMENT_WORD 2`); `_record_layout_full_span(trailing_align, [4]) == 13` (`ALIGNMENT_LONG 4` governs no present LONG-class datatype → zero effect); `summable` (no alignment) stays `== 13`. Intent comment updated to "alignment-aware padding (batch-56): `ALIGNMENT_*` is now consumed as a directive and pads component starts; only unmodeled NON-alignment lines force None."
- **Deleted tokens:** the two `is None` assertions on the alignment layouts. **New tokens:** `== 14`, `== 13` (trailing), the batch-56 intent comment.
- **Parent-HLR re-read:** HLR-A56 (this batch's) — the amended values ARE the HLR's derived behavior; no contradiction (the batch-55 HLR-P1b that authored the None behavior is superseded by HLR-A56, which explicitly consumes `ALIGNMENT_*`). Body edit landed: LLR-SUP56.1 statement + LLR-A56.1 walk.
- **Re-derived AT/TC:** the false-green anchor role (formerly "alignment → None") passes to **AT-116** (an unmodeled NON-alignment component → `None`) + the malformed-alignment **AT-117**; TC-149 backs the supersession.

**AMD-2 — REQUIREMENTS.md CURVE/MAP length prose (`REQUIREMENTS.md:402-409`).**
- **Before:** "A CURVE/MAP CHARACTERISTIC with **inline STD_AXIS/FIX_AXIS** axes is sized by summing its resolved RECORD_LAYOUT on-disk span × inline axis point-counts (`_record_layout_full_span` × `_inline_axis_counts`, full-span-or-None) …"
- **After:** append a sentence — "When the RECORD_LAYOUT declares `ALIGNMENT_*` directives in its body, `_record_layout_full_span` accounts for inter-component padding (each component's start aligned up to its datatype's declared alignment; module-wide `MOD_COMMON` defaults are not honored; no trailing pad) — batch-56. Regression: `tests/test_a2l_inline_axis_length.py`."
- **Deleted tokens:** none (append only). **New tokens:** the alignment sentence + `ALIGNMENT_*`.
- **Parent-HLR re-read:** the REQUIREMENTS.md prose is the locked contract for `R-A2L`; the append reflects HLR-A56 without contradicting the existing full-span-or-None / external-stays-None statements. Body edit landed: HLR-A56 statement.
- **Re-derived AT/TC:** covered by AT-113/AT-114/AT-115 (behavioral) + TC-143/TC-145/TC-146 (functional).

---

*End of batch-56 requirements. §4.9 pending qa-catalog splice. C-35 probe: `scratchpad/b56_probe.py` (executed, ALL MATCH).*
