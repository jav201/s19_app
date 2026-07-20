# Requirements Document — s19_app — Batch 55 (P-1b inline-axis length summer)

> **Artifact language:** English (`state.json` default). Normative keyword: `shall` — used ONLY inside HLR/LLR statements. Any modal `should` inside a normative statement is a Phase-2 blocker.

**BLUF.** Three stories. **US-P1b** (`R-A2L-008`, the reserved P-1b id) makes CURVE/MAP CHARACTERISTICs with **inline STD_AXIS/FIX_AXIS** axes report a correct byte `length` — summing the RECORD_LAYOUT on-disk span × inline axis point-counts — while **external-axis** (COM_AXIS / RES_AXIS / CURVE_AXIS / any `AXIS_PTS_REF`) CHARACTERISTICs STAY `length=None` (honest grey, no false coverage). **US-DoS** (`R-A2L-014`) bounds the byte-decode loop with a `MAX_A2L_DECODE_BYTES` clamp (covers the new path AND the pre-existing scalar path). **US-P2b** (`R-A2L-015`) re-freezes `a2l.py` into both C-27 guard sets as a post-merge PR-B. The derivation, oracle values (25 / 51 / 12 / None), and taxonomy completeness were **executed at draft time** over the real demo (§2.5 probe) — ALL MATCH. `a2l.py` is currently FROZEN (batch-54 PR-B); PR-A must UNFREEZE it in the same PR (C-27 corollary: unfreeze REMOVES → same-PR OK).

> **§4.9 AT/TC registry** — the qa-reviewer authored the canonical AT/TC catalog (AT-104..112, TC-133..142) in `01b-qa-catalog.md`; it is spliced in full below (Black-box AT registry + White-box TC registry + dual traceability). This document authors the HLR/LLR statements, touched-symbols, and per-requirement validation methods, aligned to those ids.

---

## 1. Introduction

### 1.1 Purpose
Specify the CURVE/MAP inline-axis length derivation ("the summer"), its DoS byte-bound, and the `a2l.py` re-freeze — the top LIVE-BACKLOG item, unblocked 2026-07-20 by batch-54's multi-line header parsing (origin/main `a58d4e0`).

### 1.2 Scope
- **In scope:** derive `length` for CURVE/MAP with inline STD_AXIS/FIX_AXIS axes; keep external-axis CURVE/MAP at `length=None`; a shared byte-decode clamp; supersede batch-54's `test_at102_*` guard; unfreeze (PR-A) + re-freeze (PR-B) `a2l.py`.
- **Out of scope:** multi-line CHARACTERISTIC/AXIS_DESCR header PARSING (shipped batch-54 — this batch consumes it); COM_AXIS / AXIS_PTS_REF / RES_AXIS / CURVE_AXIS length derivation (deliberately grey — the on-disk axis storage lives in a separate AXIS_PTS record, not resolvable in-tag); MEASUREMENT length (already handled); array `MATRIX_DIM` VAL_BLK sizing (already handled); any A2L-view restyle.
- **Reversible?** Yes — additive parse-time enrichment behind a `length is None` guard + two guard-file toggles. No one-way door.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| RECORD_LAYOUT | ASAM MCD-2 MC block describing a calibration object's on-disk byte layout, one component per body line. |
| Component | One RECORD_LAYOUT body line, e.g. `AXIS_PTS_X 2 SBYTE ...`. Token[0]=component name, **token[1]=POSITION INDEX (ordering, NOT a count)**, token[2]=datatype. |
| Inline axis | An `AXIS_DESCR` whose attribute is STD_AXIS or FIX_AXIS — axis geometry is derivable from the record layout + `MaxAxisPoints` without an external AXIS_PTS reference. |
| External axis | COM_AXIS / RES_AXIS / CURVE_AXIS, or any AXIS_DESCR carrying `AXIS_PTS_REF` — storage lives in a separate record; length stays `None`. |
| Full-span-or-None | Safety contract: the summer returns a byte total ONLY if every component and every needed axis count is classifiable; otherwise `None`. Never under-report (a short length would falsely pass the byte-range memory check → false-green). |
| MaxAxisPoints | The AXIS_DESCR max axis-point count, `axis_meta[i]["max_axis_points"]` — **a STRING** (`axis_tokens[3]`), a spec-decimal `uint`. Cast **base-10** (`int(str(mp).strip())`) inside a `try/except` — NOT base-0 (base-0 widens the grammar to `0x`/`0o`/`0b` and *raises* on leading-zero decimals like `'08'`; sec-F2). |

### 1.4 References
- Verified design seed: `.dev-flow/2026-07-19-batch-50/01-requirements.md §7` + `02-review.md §0/§1/§2` (architect MAJOR-1 position-index-not-count; qa M1–M6; security F1–F3).
- Locked A2L length prose: `REQUIREMENTS.md:387-405` (amended by this batch — §6.5).
- qa-reviewer AT/TC catalog: `.dev-flow/2026-07-20-batch-55/01b-qa-catalog.md`.
- Prerequisite: batch-54 multi-line header parsing, PRs #102/#103, origin/main `a58d4e0`.

### 1.5 Document overview
§2 stories + INVEST + the draft-time execution probe. §3 HLR. §4 LLR (with C-26 touched symbols + per-LLR validation). §4.9 AT/TC placeholder. §5.2 dual traceability. §6.3 risks/security. §6.4 reconciliation. §6.5 amendments (incl. the mandatory batch-54 AT-102 supersession + REQUIREMENTS.md prose).

---

## 2. Overall description

### 2.1 Product perspective
Additive enrichment in the parsing layer (`s19_app/tui/a2l.py`, the frozen A2L oracle). The summer runs inside `extract_a2l_tags`' walk at parse time (upstream of `enrich_tags_and_render` / the A2L view), producing the `length` field every downstream consumer already reads. No new module; no service-layer change.

### 2.2 Product functions
1. Sum a CURVE/MAP's on-disk byte span from its resolved RECORD_LAYOUT × inline axis counts.
2. Gate derivation on axis kind — inline (STD_AXIS/FIX_AXIS) derives; external stays `None`.
3. Bound the byte-decode loop against a hostile/oversized layout.
4. Return `a2l.py` to read-only-oracle status.

### 2.3 User characteristics
Firmware/calibration engineer reading the TUI A2L view: a CURVE/MAP with a valid address that today renders grey ("not memory-checked") because `length is None` should become memory-checkable (green with an image hit / white without), while genuinely underivable (external-axis) records stay honestly grey.

### 2.4 Constraints
- `a2l.py` is a C-27 engine-frozen oracle → PR-A must unfreeze in the same PR; re-freeze is a separate post-merge PR-B (a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard).
- Must NOT modify `tests/test_tui_a2l.py` (tc032-frozen) — new white-box tests land in a NEW non-frozen sibling `tests/test_a2l_inline_axis_length.py`.
- Full-span-or-None: correctness-over-coverage. A wrong-but-non-None length is worse than grey (false-green memory check on a safety artifact).
- Textual SVG snapshots: the A2L view now shows a `length` on 8 previously-grey demo rows → snapshot drift is EXPECTED on those cells; regen via canonical CI only (per `reference_snapshot_regen_env`).

### 2.5 Assumptions and dependencies — **C-35 draft-time EXECUTION (decisive evidence)**

The candidate derivation was **executed over the real demo** (`examples/case_00_public/ASAP2_Demo_V161.a2l`) via `parse_a2l_file`, not reasoned about. Probe: `scratchpad/p1b_probe.py`. Output (verbatim, condensed):

```
== axis-kind census ==
  disjoint: True     ALL == D|E: True
  observed axis kinds in demo: ['COM_AXIS', 'CURVE_AXIS', 'FIX_AXIS', 'RES_AXIS', 'STD_AXIS']
  all observed in ALL_AXIS_KINDS: True

== ASAM.C.CURVE.STD_AXIS ==  char_type=CURVE  record_layout_name=RL.CURVE.SWORD.SBYTE.DECR
   axis_meta: [('STD_AXIS', '8', False)]   inline_axis_counts -> [8]
      NO_AXIS_PTS_X  dt=UBYTE size=1 el=1  -> 1 B
      AXIS_PTS_X     dt=SBYTE size=1 el=8  -> 8 B
      FNC_VALUES     dt=SWORD size=2 el=8  -> 16 B
   DERIVED length = 25   (expected 25)   OK
== ASAM.C.MAP.STD_AXIS.STD_AXIS ==  char_type=MAP  record_layout_name=RL.MAP.SWORD.SBYTE.SBYTE.INCR
   axis_meta: [('STD_AXIS','4',False), ('STD_AXIS','5',False)]   inline_axis_counts -> [4, 5]
      NO_AXIS_PTS_X 1B + NO_AXIS_PTS_Y 1B + AXIS_PTS_X 4B + AXIS_PTS_Y 5B + FNC_VALUES(4*5)*2=40B
   DERIVED length = 51   (expected 51)   OK
== ASAM.C.CURVE.FIX_AXIS.PAR_DIST ==  RL.FNC.SWORD.ROW_DIR  axis_meta:[('FIX_AXIS','6',False)]
      FNC_VALUES dt=SWORD size=2 el=6 -> 12 B      DERIVED length = 12   (expected 12)   OK
== ASAM.C.CURVE.COM_AXIS ==  axis_meta:[('COM_AXIS','8',True)]  inline_axis_counts -> None
   DERIVED length = None  (expected None)   OK
ALL MATCH
```

Full-corpus sweep (second probe): **12 CURVE/MAP tags total; ALL currently `length is None`** (⇒ the summer only fills residual `None`s — zero pre-existing value to override, no regression surface); **8 derive to an int** (inline STD_AXIS/FIX_AXIS), **4 stay grey** (external); **ZERO false-None** (no derivable inline case hit an unclassified component ⇒ the taxonomy is complete for the demo corpus). **Component census (arch-PP1, executed):** the only datatype-bearing components across all 12 (+1 CUBOID) demo layouts are `{AXIS_PTS_X/Y/Z, FNC_VALUES, NO_AXIS_PTS_X/Y/Z}` — all 7 in the taxonomy; zero unlisted/mis-dropped components (`RESERVED`/`AXIS_RESCALE_X`/`IDENTIFICATION`/`SRC_ADDR_*`/`RIP_ADDR_*`/`SHIFT_OP_*` absent). **13th in-family tag (arch-MIN2):** the demo also carries `ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS` (`char_type=CUBOID`, 3 axes) — the ONLY 3-axis record; **out of scope** by the `char_type ∈ {CURVE,MAP}` gate (and independently external via COM_AXIS), so it stays `length=None`. AT-109 anchors this (the char_type-gate exclusion).

**Component taxonomy (element-count rule per RECORD_LAYOUT component, keyed on ordered inline axis counts `[n_x, n_y, n_z]`):**

| Component name | Element count | Datatype (token[2]) × count |
|----------------|---------------|-----------------------------|
| `NO_AXIS_PTS_X` / `_Y` / `_Z`, `NO_RESCALE_X` | `1` (a scalar count byte) | `size × 1` |
| `AXIS_PTS_X` | `n_x` = `axis_counts[0]` | `size × n_x` |
| `AXIS_PTS_Y` | `n_y` = `axis_counts[1]` | `size × n_y` |
| `AXIS_PTS_Z` | `n_z` = `axis_counts[2]` | `size × n_z` |
| `FNC_VALUES` | `prod(axis_counts)` (CURVE→`n_x`; MAP→`n_x·n_y`) | `size × prod` |
| **any other component name** | **→ whole span returns `None`** (full-span-or-None) | — |
| unknown datatype on a real component | **→ whole span returns `None`** | — |
| `AXIS_PTS_Y`/`_Z` needed but axis count absent | **→ whole span returns `None`** | — |

**Assumptions (invalidate the batch if false):** (a) batch-54's parser populates `char_type`, `record_layout_name`, and `axis_meta[i].{max_axis_points(STR), external}` for these tags — **verified by the probe**; (b) `record_layouts_by_name[name]["lines"]` carries the full component body — **verified** (`extract_record_layouts`, `a2l.py:606-621`, `"lines": lines`); (c) FIX_AXIS axis points are NOT stored on-disk (only FNC_VALUES), so a FIX_AXIS layout omits `AXIS_PTS_*` — **verified** (`RL.FNC.SWORD.ROW_DIR` = `FNC_VALUES` only, `a2l.py`-consumed demo:2816-2818).

### 2.6 Source user stories — Definition of Ready (INVEST)

| ID | User story | Source | DoR |
|----|-----------|--------|-----|
| US-P1b | As a firmware engineer, I want a CURVE/MAP with an inline STD_AXIS/FIX_AXIS axis to show a correct byte `length` in the A2L view, so that its bytes become memory-checkable (green/white) instead of grey — WITHOUT external-axis CURVE/MAP falsely gaining a length. | Backlog TOP item; operator 2026-07-20 | **READY** |
| US-DoS | As a maintainer, I want the A2L byte-decode loop bounded by a `MAX_A2L_DECODE_BYTES` clamp, so that a hostile or malformed layout (huge MaxAxisPoints / datatype product) cannot drive an unbounded allocation/hang. | security F1/F2 (batch-50); operator | **READY** |
| US-P2b | As a maintainer, I want `a2l.py` re-added to both C-27 engine-frozen guard sets after the summer lands, so the module returns to read-only-oracle status and future accidental edits trip at the increment boundary. | Backlog P-2 pattern; C-27 | **READY** (post-merge PR-B) |

#### Refinement log

**US-P1b — inline-axis length summer**
- **INVEST:** I ✓ · N ✓ · V ✓ (grey→checkable row is user-visible) · E ✓ (derivation executed, oracle fixed) · S ✓ (parse-time, ≤5 files) · T ✓ (byte-value ATs).
- **Functionality:** user = calibration engineer · outcome = correct `length` on inline CURVE/MAP; external stays `None` · why = enables the byte-range memory check without false-green · out of scope = external-axis derivation, MEAS length, restyle.
- **Feasibility:** path = new `_record_layout_full_span` + `_inline_axis_counts` + census constants, wired as a post-axis-walk pass in `extract_a2l_tags`; consumes batch-54 fields. Unknowns = none material (probe closed them). Fits one batch = yes.
- **Evaluability (black-box):** When `parse_a2l_file(demo)` runs, the user observes tag `ASAM.C.CURVE.STD_AXIS` `length==25`, `ASAM.C.MAP.STD_AXIS.STD_AXIS` `length==51`, `ASAM.C.CURVE.COM_AXIS` `length is None` → AT-104/105/106.
- **Classification:** `READY`.

**US-DoS — byte-decode clamp**
- **INVEST:** I ✓ · N ✓ · V ✓ (robustness) · E ✓ · S ✓ · T ✓ (bounded/None observable).
- **Functionality:** user = maintainer/operator running untrusted A2L · outcome = oversized span → clamped, no runaway · out of scope = remote/exec surface (none exists).
- **Feasibility:** one module constant + one clamp at `_extract_raw_bytes:1033` (before `range(byte_size)` at `:1037`); reuses the constant as the summer's honesty upper bound.
- **Evaluability:** synthetic layout with an oversized MaxAxisPoints → `parse_a2l_file` returns `length is None` (or clamped) and decode does not allocate/hang → AT-111.
- **Classification:** `READY`.

**US-P2b — re-freeze a2l.py (post-merge PR-B)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓ (guard-green + zero-diff).
- **Feasibility:** guard-files-only; gated on PR-A merge (same-PR re-freeze self-trips). Mirrors batch-50 LLR-P2.1 and batch-54 PR-B.
- **Evaluability:** with `a2l.py` back in both `_ENGINE_PATHS`, the frozen-file guards pass because merged source == `main` source; `git diff main -- a2l.py` empty → AT-112.
- **Classification:** `READY` (post-merge).

---

## 3. High-level requirements (HLR)

### HLR-P1b — inline-axis length summer (`R-A2L-008`)
- **Traceability:** US-P1b
- **Statement:** When `parse_a2l_file` extracts a CHARACTERISTIC whose `char_type` is `CURVE` or `MAP` and whose `length` is still `None` after the existing inference, the system **shall** set `length` to the summed on-disk byte span of its resolved RECORD_LAYOUT (Σ over components of `datatype_size × element_count`, where each inline axis contributes its `MaxAxisPoints` count and `FNC_VALUES` contributes the product of the inline axis counts) **if and only if** every axis is inline (STD_AXIS or FIX_AXIS) and every component and axis count is classifiable; and the system **shall** leave `length` as `None` for any CHARACTERISTIC with an external axis (COM_AXIS / RES_AXIS / CURVE_AXIS or an `AXIS_PTS_REF`) or an unclassifiable component/datatype/axis count (full-span-or-None).
- **Rationale (informative):** a valid-but-underivable length is spec-valid grey, never a schema failure (`REQUIREMENTS.md:387`); a too-short length would falsely pass the byte-range memory check on a safety artifact, so under-reporting is prohibited.
- **Validation:** `test` + `analysis` · **Priority:** high
- **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py` (AT-104..109, TC-133..137) + the §2.5 oracle derivation (25 = 1+8+16; 51 = 1+1+4+5+40; None for COM_AXIS).
- **Numeric pass threshold:** demo `ASAM.C.CURVE.STD_AXIS` `length==25` ∧ `ASAM.C.MAP.STD_AXIS.STD_AXIS` `length==51` ∧ `ASAM.C.CURVE.COM_AXIS` `length is None`; 8/12 demo CURVE/MAP derive an int, 4/12 stay `None`, 0 false-None; full suite 0 fail.
- **Acceptance (black-box):**
  - **Observable outcome:** the previously-grey inline CURVE/MAP A2L rows show a correct byte length and become memory-checkable; external-axis rows stay grey.
  - **Shipped surface:** `parse_a2l_file(Path)` tag `length` field (C-12 chain head); downstream `enrich_tags_and_render` → A2L view row severity (output-then-consume, AT-108).
  - **Deliverable + observation:** the parsed tag dict at `path`, `tags[i]["length"]` == the exact byte value (25/51/12) for inline, `is None` for external; the A2L view row flips grey→`sev-info`/checked.
  - **Acceptance test(s):** `AT-104` (CURVE=25), `AT-105` (MAP=51), `AT-106` (COM_AXIS None — false-green anchor), `AT-107` (demo FIX_AXIS=12), `AT-107b` (synthetic CURVE=13, demo-independent), `AT-108` (view-row consumer flip via covering map + `_a2l_tag_row_severity`), `AT-109` (no-regression + CUBOID stays None), `AT-110` (malformed/`'08'`/huge-digit fail-closed). Provisional-until-Phase-3.
  - **Boundary catalog (QC-3):** ☑ empty (no AXIS_DESCR / `axis_meta==[]` → `None`, AT-110/TC-134) · ☑ boundary (single inline axis CURVE=25/12; two-axis MAP=51; product term) · ☑ invalid (non-numeric/`≤0` MaxAxisPoints; unknown datatype; unknown component → `None`, AT-110/TC-139) · ☑ error (external axis → `None`, AT-106).

### HLR-DoS — bounded byte-decode (`R-A2L-014`)
- **Traceability:** US-DoS
- **Statement:** If a CHARACTERISTIC's derived (or MATRIX_DIM/scalar-inferred) byte span exceeds `MAX_A2L_DECODE_BYTES`, then the system **shall** treat the raw bytes as unavailable (no per-byte allocation over the oversized span) rather than iterating an unbounded `range(byte_size)`, and the summer **shall** return `None` for any computed span exceeding that same bound.
- **Rationale (informative):** `_extract_raw_bytes` builds a `byte_size`-length list (`a2l.py:1037`, `for offset in range(byte_size)`), guarded today only by `byte_size <= 0` (`:1033`); an untrusted MaxAxisPoints/MATRIX_DIM makes `byte_size` unbounded (a local self-DoS, security F1). The clamp covers BOTH the new CURVE/MAP path and the pre-existing scalar `el × matrix` path. Distinct from batch-54's `R-A2L-013` (the linear-time `_strip_a2l_comments` bound) — a different surface.
- **Validation:** `test` + `analysis` · **Priority:** high
- **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py -k "dos or clamp"` (AT-111, TC-138) + the bound-selection analysis (below).
- **Numeric pass threshold:** oversized synthetic layout (MaxAxisPoints forcing span `> MAX_A2L_DECODE_BYTES`) → tag `length is None` (summer path) AND `_extract_raw_bytes` returns `raw_available=False` without allocating; runtime bounded (no hang); `MAX_A2L_DECODE_BYTES == 1_048_576` (1 MiB).
- **Acceptance (black-box):**
  - **Observable outcome:** a hostile oversized A2L parses without runaway allocation/hang; the oversized record is `None`/unavailable, not a giant number driving a giant loop.
  - **Shipped surface:** `parse_a2l_file` (summer cap) + `_extract_raw_bytes` (decode cap, reached via enrichment).
  - **Deliverable + observation:** parsed tag `length is None` for the oversized record; decode result `raw_available=False`; test completes under a wall-clock bound.
  - **Acceptance test(s):** `AT-111` (may be `@slow`). Provisional.
  - **Boundary catalog:** ☑ boundary (span exactly at the cap admitted; one over → `None`) · ☑ invalid (huge product) · ☑ empty N/A (empty handled by full-span-or-None) · ☑ error (no raise).

### HLR-P2b — re-freeze `a2l.py` into the C-27 dual-guard set (`R-A2L-015`)
- **Traceability:** US-P2b
- **Statement:** After the PR-A source edits merge to `main`, the guard suite **shall** re-include `"s19_app/tui/a2l.py"` in BOTH `_ENGINE_PATHS` (`tests/test_engine_unchanged.py` and `tests/test_tui_directionb.py` tc031), the "UNFROZEN for batch-55" NOTE **shall** be restored to the re-frozen wording, and the guards **shall** pass with a zero source diff of `a2l.py` vs `main`.
- **Rationale (informative):** returns the A2L oracle to read-only. Only satisfiable post-merge — a same-PR re-freeze makes `git diff main -- a2l.py` non-empty and self-trips the guard (C-27 corollary: re-freeze ADDS → post-merge PR-B). Mirrors batch-50 `R-A2L-009` and batch-54 PR-B.
- **Validation:** `test` + `inspection` · **Priority:** medium
- **Executed verification:** `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc027 or tc032"` + `git diff main -- s19_app/tui/a2l.py`.
- **Numeric pass threshold:** tc027/tc031/tc032 green with `a2l.py` in both frozen sets; `git diff main -- s19_app/tui/a2l.py` empty; PR-B touches ONLY the two guard test files.
- **Acceptance (black-box):**
  - **Observable outcome:** the frozen-file guards pass because merged source == `main` source.
  - **Shipped surface:** the guard tests.
  - **Deliverable + observation:** both `_ENGINE_PATHS` contain `a2l.py`; guards green; empty diff.
  - **Acceptance test(s):** `AT-112` (post-merge PR-B). **Sequencing flag:** un-runnable until PR-A merges.
  - **Boundary catalog:** ☑ error (a2l.py ≠ main → guard RED) · empty/boundary/invalid N/A (binary guard).

---

## 4. Low-level requirements (LLR)

> C-26: every LLR declares its touched symbols (verified `file:line`, or `NEW — created in Phase 3`). Reverse-greped at Phase 2/3.

### LLR-P1b.1 — `_record_layout_full_span(layout, axis_counts)` component summer
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** NEW `_record_layout_full_span` (private, module-level, near `_resolve_record_layout` `a2l.py:964` — NEW, created Phase 3). Reads `DATATYPE_SIZES` (`a2l.py:13`, via `.get()`).
- **Statement:** `_record_layout_full_span` **shall** iterate `layout["lines"]`, and for each line with ≥3 whitespace tokens **shall** read the component name as `token[0]` and the datatype as `token[2]` (NOT `token[1]`, which is the ASAM **position index**, not a count), resolve the datatype size via `DATATYPE_SIZES.get(token[2])`, resolve the component element-count via the §2.5 taxonomy keyed on `axis_counts`, and return the sum of `size × element_count`; and it **shall** return `None` (full-span-or-None) if any component recognised as a real data component has an unknown datatype, if a component name is unclassifiable, if a needed axis count is absent, if no component contributed, or if the computed total exceeds `MAX_A2L_DECODE_BYTES`.
- **Skip-vs-None (arch-MIN3):** a `≥3-token` line whose `token[0]` is NOT in the component taxonomy **shall** force the whole span to `None` — it **shall NOT** be silently skipped/`continue`d (the reference probe's skip-branch under-reports → a false-green; implement the LLR wording, not the probe). A line with `< 3` tokens (structural, e.g. a bare `/` continuation) is not a component and is ignored.
- **Acceptance criteria (informative):** synthetic `RL.CURVE.SWORD.SBYTE.DECR`-shaped layout + `axis_counts=[8]` → 25; `[4,5]` MAP layout → 51; a `token[1]`-as-count mutation yields 9 (MAJOR-1 guard); a **size-asymmetric MAP** where an X/Y count-swap changes the total (TC-133, arch-MAJ1) → discriminates axis-order wiring; an unknown ≥3-token component line → `None`.
- **Validation:** `test (unit)` — TC-133. **Executed verification:** `pytest -q tests/test_a2l_inline_axis_length.py -k full_span`. **Numeric threshold:** hand-computed span from an in-test layout string (25 & 51) exact; position-as-count mutation ⇒ ≠ expected.

### LLR-P1b.2 — `_inline_axis_counts(axis_meta)` axis resolver + external gate
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** NEW `_inline_axis_counts` (private, module-level — NEW, Phase 3). Reads the `axis_meta` list built at `a2l.py:1263-1273`.
- **Statement:** `_inline_axis_counts` **shall** return `None` if `axis_meta` is empty, or if any axis's kind (`header_tokens[0]`) is not in `_DERIVABLE_AXIS_KINDS`, or if any axis carries the `external` flag, or if any axis's `max_axis_points` is `None`, non-numeric, or `≤ 0`; otherwise it **shall** return the ordered list of integer axis counts, casting each `max_axis_points` (a STRING) via a **base-10** `int(str(mp).strip())` wrapped in a `try/except (ValueError, TypeError)` that returns `None` on failure (sec-F2 — NOT base-0: base-0 accepts `0x`/`0o`/`0b` and *raises* on `'08'`).
- **Guard shape (sec-F3, mandatory):** the numeric check **shall** be the `try/except` around the actual `int(...)` call — NEVER an `isdigit()`/regex pre-predicate (`'08'.isdigit()` is True but the cast could still raise; a predicate/cast mismatch aborts the load, violating collect-don't-abort).
- **Acceptance criteria (informative):** STD_AXIS `'8'` → `[8]`; two STD_AXIS `'4','5'` → `[4,5]`; COM_AXIS (external=True) → `None`; `max_axis_points='0'`/`'x'`/`None` → `None`; **`'08'` (leading-zero) → `8`** (base-10 accepts it; base-0 would raise); **`'9'*5000` (huge-digit) → `None`, no exception** (sec-F4: py3.11 `int()` raises `ValueError` past `set_int_max_str_digits`≈4300 — the try/except catches it); empty → `None`.
- **Validation:** `test (unit)` — TC-134. **Executed verification:** `pytest -q ... -k inline_axis_counts`. **Numeric threshold:** the five cases above exact; external-present ⇒ `None`.

### LLR-P1b.3 — axis-kind census constants + completeness invariant (C-31)
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** NEW module constants `_DERIVABLE_AXIS_KINDS`, `_EXTERNAL_AXIS_KINDS`, `ALL_AXIS_KINDS` (near `CHARACTERISTIC_KINDS` `a2l.py:59` — NEW, Phase 3).
- **Statement:** The module **shall** define `_DERIVABLE_AXIS_KINDS = frozenset({"STD_AXIS","FIX_AXIS"})`, `_EXTERNAL_AXIS_KINDS = frozenset({"COM_AXIS","RES_AXIS","CURVE_AXIS"})`, and `ALL_AXIS_KINDS = _DERIVABLE_AXIS_KINDS | _EXTERNAL_AXIS_KINDS` as live (code-derived) constants, such that the two subsets are disjoint and their union equals `ALL_AXIS_KINDS`; and `_inline_axis_counts` **shall** gate on `_DERIVABLE_AXIS_KINDS` (never a hand-listed literal at the call site).
- **Rationale (informative):** C-31 — the axis-kind census must be code-guarded, not hand-listed, so a new kind cannot be silently mis-bucketed. Probe confirms the demo's 5 observed kinds ⊆ `ALL_AXIS_KINDS`.
- **Validation:** `test (unit)` + `inspection` — TC-135. **Executed verification:** `pytest -q ... -k axis_kind_census`. The TC **shall** assert the code-derived set-algebra (disjointness, `ALL == _DERIVABLE | _EXTERNAL`, both subsets non-empty) AND **shall derive the demo-observed axis kinds FROM the parse** — `observed = {am["header_tokens"][0] for tag in parse_a2l_file(DEMO)["tags"] for am in tag.get("axis_meta", [])}` — asserting `observed` is non-empty and `observed <= ALL_AXIS_KINDS` (qa-M2 / C-31: the corpus census **shall NOT** be hand-listed — a literal `{STD_AXIS,FIX_AXIS,...}` is a vacuous input set that cannot notice a 6th kind). **Numeric threshold:** all set-assertions True; `len(_DERIVABLE_AXIS_KINDS) ≥ 1 ∧ len(_EXTERNAL_AXIS_KINDS) ≥ 1`; `observed` derived (not literal) and `⊆ ALL_AXIS_KINDS`.

### LLR-P1b.4 — post-axis-walk length pass (R2 ordering + wiring)
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** the `extract_a2l_tags` walk closure (`a2l.py:1131-1294`); the NEW length block inserted **after** the `axis_meta` append loop ends (`a2l.py:1273`) and **before** the `effective_byte_order` block (`a2l.py:1275`). Reads `record_layouts_by_name` (already in scope, param `a2l.py:1121`).
- **Statement:** After `tag["axis_meta"]` is fully built, the walk **shall**, only when `name == "CHARACTERISTIC"` and `tag["char_type"] in {"CURVE","MAP"}` and `tag["length"] is None`, compute `axis_counts = _inline_axis_counts(tag["axis_meta"])`, and if `axis_counts is not None` resolve `layout = record_layouts_by_name.get(str(tag.get("record_layout_name") or ""))` and set `tag["length"] = _record_layout_full_span(layout, axis_counts)` when `layout` is present; and the existing scalar/VALUE inference at `a2l.py:1258-1261` **shall** remain unchanged (it runs first, before `axis_meta` exists, and leaves CURVE/MAP `None`).
- **Rationale (informative):** R2 ordering — the summer needs `axis_meta`, which is built at `:1263-1273`, AFTER the `_infer_length_characteristic` call at `:1258-1261`; hence a distinct post-walk pass, not a change to `_infer_length_characteristic`. The `length is None` guard preserves explicit `LENGTH`/`MATRIX_DIM`/name-encoded-deposit precedence.
- **Validation:** `test (integration)` — TC-136. **Executed verification:** `pytest -q ... -k post_axis_pass` (asserts a CURVE with an explicit `LENGTH` keeps it; a bare inline CURVE gets the summed value; ordering: moving the pass before the axis loop would yield `None`). **Numeric threshold:** demo CURVE=25 via `parse_a2l_file`; explicit-LENGTH CURVE unchanged.

### LLR-P1b.5 — no-regression: scalar VALUE / single-line / no-kind untouched
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** none new — asserts the negative surface of LLR-P1b.4's guard.
- **Statement:** The summer **shall not** alter `length` for MEASUREMENT tags, scalar VALUE CHARACTERISTICs, VAL_BLK, ASCII, char_type-`None` records, or any CHARACTERISTIC whose `length` was already non-`None`; and parsing the demo **shall** leave all non-CURVE/MAP tag fields byte-identical to pre-batch output.
- **Rationale (informative):** probe evidence — only 8/12 CURVE/MAP change (grey→int), all currently `None`; nothing else is touched.
- **Validation:** `test` + `inspection` — TC-137 / AT-109. **Executed verification:** `pytest -q ... -k no_regression` + full-suite `pytest -q` + snapshot census. **Numeric threshold:** non-CURVE/MAP demo tag fields identical; full suite 0 fail; snapshot drift confined to the 8 inline CURVE/MAP A2L rows.

### LLR-P1b.6 — fail-closed on malformed layout / axis (robustness)
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** `_record_layout_full_span`, `_inline_axis_counts` (defensive branches, security F3).
- **Statement:** The summer **shall** use `DATATYPE_SIZES.get(...)` (never subscript — subscript raises `KeyError`, not fail-closed), **shall** length-guard token access (`len(tokens) >= 3` before `token[2]`; `header_tokens` before `[0]`), **shall** perform the `max_axis_points` numeric cast inside a `try/except (ValueError, TypeError)` returning `None` (NEVER an `isdigit()`/regex pre-predicate — sec-F3), and **shall** return `None` (never raise) for a garbage datatype, a non-numeric OR leading-zero OR huge-digit MaxAxisPoints, or a truncated component line, so that a malformed CURVE/MAP parses to grey without aborting the load.
- **Rationale (informative):** the parsing layer's collect-don't-abort contract; a hostile A2L must not crash the TUI.
- **Validation:** `test (unit + e2e)` — TC-139 / AT-110. **Executed verification:** `pytest -q ... -k malformed`. **Numeric threshold:** malformed CURVE through `parse_a2l_file` → `length is None`, no exception; 0 raises.

### LLR-P1b.7 — UNFREEZE `a2l.py` in PR-A (enabling)
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:129`, entry `"s19_app/tui/a2l.py"`; `tests/test_tui_directionb.py:5437`, same entry) + the two NOTE blocks (`test_engine_unchanged.py:125-128`, `test_tui_directionb.py:5433-5436`).
- **Statement:** In PR-A (the source PR), `"s19_app/tui/a2l.py"` **shall** be removed from BOTH `_ENGINE_PATHS` tuples and the two "RE-FROZEN … any further edit needs an explicit unfreeze" NOTE blocks **shall** be replaced with a "UNFROZEN for batch-55 (operator-approved P-1b summer); RE-FREEZE in follow-up PR-B" note; and all new batch-55 white-box tests **shall** land in a NEW non-frozen `tests/test_a2l_inline_axis_length.py`, never in the tc032-frozen `tests/test_tui_a2l.py`.
- **Rationale (informative):** C-27 corollary — an unfreeze REMOVES the path from the guard set, so the same PR may edit `a2l.py`; the re-freeze (LLR-P2b.1) is the separate post-merge PR-B.
- **Validation:** `inspection` — TC-141. **Executed verification:** grep `a2l.py` absent from both `_ENGINE_PATHS` in PR-A; new test file not equal to `test_tui_a2l.py`; `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` green post-edit. **Numeric threshold:** 0 occurrences of `"s19_app/tui/a2l.py"` in either `_ENGINE_PATHS` in PR-A; tc031/tc032 green.

### LLR-DoS.1 — `MAX_A2L_DECODE_BYTES` clamp
- **Traceability:** HLR-DoS · **Touched symbol (C-26):** NEW module constant `MAX_A2L_DECODE_BYTES` (near the size maps, `a2l.py:13-28` region — NEW, Phase 3); `_extract_raw_bytes` (`a2l.py:1030-1043`, add a guard before the `range(byte_size)` loop at `:1037`); reused as the upper bound in `_record_layout_full_span` (LLR-P1b.1).
- **Statement:** `_extract_raw_bytes` **shall**, when `byte_size > MAX_A2L_DECODE_BYTES`, return the unavailable result (`raw_bytes=None`, `raw_available=False`, `missing_ranges=[]`, `overlap_conflict=False`) without entering the per-byte `range(byte_size)` loop; and `MAX_A2L_DECODE_BYTES` **shall** be `1_048_576` (1 MiB).
- **Rationale (informative):** 1 MiB bounds the per-record decode list to ~1M entries (well below any legitimate single CHARACTERISTIC span on these ECU images — the largest realistic inline map is tens of KB) while making a hostile record cheaply refused. Placing the clamp in `_extract_raw_bytes` covers BOTH the new CURVE/MAP path and the pre-existing scalar `el × matrix` path (security F1/F2). The summer applies the same constant at derivation so an absurd span renders honest grey rather than a giant number.
- **Validation:** `test` + `analysis` — TC-138 / AT-111. **Executed verification:** `pytest -q ... -k "dos or clamp"`; the bound-selection analysis above. **Numeric threshold:** `byte_size = MAX_A2L_DECODE_BYTES` admitted; `+1` → unavailable, no list allocation; summer span `> cap` → `None`; test wall-clock bounded.

### LLR-SUP.1 — supersede batch-54 `test_at102_curve_map_length_stays_none`
- **Traceability:** HLR-P1b · **Touched symbol (C-26):** `tests/test_a2l_multiline_headers.py:329-341` (`test_at102_curve_map_length_stays_none`, NON-frozen, editable).
- **Statement:** The batch-54 assertion that `ASAM.C.CURVE.STD_AXIS` and `ASAM.C.MAP.STD_AXIS.STD_AXIS` keep `length is None` **shall** be amended to assert the new derived values (`25` and `51` respectively), the "a premature length summer would trip here" intent comment **shall** be updated to reference batch-55 ownership, and the None-anchor role **shall** be carried by AT-106 (external COM_AXIS) — recorded as a §6.5 Before→After amendment.
- **Rationale (informative):** the test was authored (batch-54) explicitly for batch-55 to flip; leaving it unamended is a false regression signal at the Phase-4 gate. It lives in a non-frozen file, so editing it is sanctioned.
- **Validation:** `test` + `inspection` — TC-140. **Executed verification:** `pytest -q tests/test_a2l_multiline_headers.py -k at102`. **Numeric threshold:** amended test asserts `25`/`51` and passes; 0 stale `is None` assertions on these two names remain.

### LLR-P2b.1 — re-freeze `a2l.py` into both `_ENGINE_PATHS` (PR-B, post-merge)
- **Traceability:** HLR-P2b · **Touched symbol (C-26):** `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-131`, `tests/test_tui_directionb.py:5428-5440`) + the two NOTE blocks.
- **Statement:** In PR-B (post-merge, guard-files-only), `"s19_app/tui/a2l.py"` **shall** be re-inserted into BOTH `_ENGINE_PATHS` tuples with a re-frozen NOTE, and the guards (tc027/tc031) **shall** pass with `git diff main -- s19_app/tui/a2l.py` empty; and the tc032 A2L-parser freeze (`_ENGINE_TEST_FILES`, `test_tui_directionb.py:5442+`) **shall** remain green, confirming batch-55 white-box tests landed in the NEW non-frozen sibling, not `tests/test_tui_a2l.py`.
- **Rationale (informative):** returns the oracle to read-only. Un-satisfiable pre-merge (same-PR re-freeze self-trips). Mirrors batch-50 LLR-P2.1/P2.2 and batch-54 PR-B.
- **Validation:** `test` + `inspection` — TC-142. **Executed verification:** `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or tc031 or tc027 or tc032"` + `git diff main -- s19_app/tui/a2l.py`. **Numeric threshold:** tc027/tc031/tc032 green; empty diff; PR-B touches ONLY the two guard files. **Sequencing flag:** gated on PR-A merge.

---

## 4.9 Canonical AT / TC registry

*(Spliced by orchestrator from `01b-qa-catalog.md` Sections B/C/D. Ids: black-box AT-104..112; white-box TC-133..142. C-12 chain head = `parse_a2l_file`; all new TCs land in the NEW non-frozen `tests/test_a2l_inline_axis_length.py`. `max_axis_points` is a STR → `int()`-cast.)*

### Black-box AT registry (observed through the shipped surface)

| AT | Story | Asserts THE VALUE (through the surface) | Counterfactual — mutation that turns it RED | Gate-blocking? |
|----|-------|-----------------------------------------|---------------------------------------------|----------------|
| **AT-104** | US-P1b | `parse_a2l_file(demo).tags` → `name=="ASAM.C.CURVE.STD_AXIS"` has **`length == 25`** (1×UBYTE + 8×SBYTE + 8×SWORD) | `tok[1]`-as-count → 9; drop axis term → 17; pre-fix → None | **Yes** |
| **AT-105** | US-P1b | `name=="ASAM.C.MAP.STD_AXIS.STD_AXIS"` (axes 4&5) has **`length == 51`** (1+1+4+5 + 4·5·2) | one axis only → 29; synthetic [8,8] → 146; pre-fix → None. *(Note arch-MAJ1: the demo MAP's axes are both SBYTE so 4+5 & 4·5 are order-invariant — 51 can't discriminate an X/Y-count swap; that discrimination is delegated to TC-133's size-asymmetric synthetic MAP.)* | **Yes** |
| **AT-106** | US-P1b | `name=="ASAM.C.CURVE.COM_AXIS"` (external `AXIS_PTS_REF`) has **`length is None`** — *false-green anchor: full-span-or-None* | summer ignores `external`/`_EXTERNAL_AXIS_KINDS` → a wrong non-None | **Yes** |
| **AT-107** | US-P1b (FIX_AXIS branch) | `parse_a2l_file(demo).tags` → `name=="ASAM.C.CURVE.FIX_AXIS.PAR_DIST"` has **`length == 12`** (`FNC_VALUES` = 6 × SWORD(2); **no on-disk `AXIS_PTS` line** — the distinct FIX_AXIS layout shape) | drop FIX_AXIS from `_DERIVABLE_AXIS_KINDS` → None; size the count into a non-existent `AXIS_PTS` line → ≠12; pre-fix → None | **Yes** |
| **AT-107b** | US-P1b (demo-independence) | A **synthetic single-line** CURVE (in-test string; span hand-computable, `1×UBYTE + 4×SWORD + 4×UBYTE = 13`) → `parse_a2l_file(tmp).length == 13` | position-as-count or wrong datatype token (token[1] vs token[2]) → ≠13; oracle independent of demo line numbers | **Yes** |
| **AT-108** | US-P1b | **Output-then-consume (C-12), corrected oracle (qa-M1):** `parse_a2l_file(demo)` → read the CURVE.STD_AXIS `address`; build a **covering** map `cover={addr+i:0 for i in range(25)}`; `merged,_ = enrich_tags_and_render(a2l_data, cover)`; assert `_a2l_tag_row_severity(curve_tag, {}) is ValidationSeverity.OK` (grey NEUTRAL → green OK) **because** `length==25` made the memory check applicable | **same `cover` map** with the summer reverted (length→None) → `applicable=False → memory_checked=False → _a2l_tag_row_severity is NEUTRAL` (stays grey). *(mem_map MUST be non-None & covering — with `mem_map=None`, `validate_a2l_tags` returns `memory_checked=False` for ANY length; and the `sev-*` class comes from `_a2l_tag_row_severity`, app.py:342, not from `enrich_tags_and_render`.)* | **Yes** |
| **AT-109** | US-P1b (no-regression) | (a) `case_01` scalar `VALUE` length unchanged; (b) demo MEASUREMENT lengths unchanged; (c) synthetic no-kind CHAR → `None`; (d) **the demo CUBOID `ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS` stays `length is None`** (char_type-gate exclusion, arch-MIN2); (e) **0 snapshot drift** beyond the 8 inline rows | summer over-reaches into scalar/MEAS/no-kind/CUBOID → a length appears where None, or a baseline shifts | **Yes** |
| **AT-110** | US-P1b (robustness) | Malformed CURVE via `parse_a2l_file`, **no exception** for each: (i) non-numeric MaxAxisPoints (`'x'`) → `length is None`; (ii) **huge-digit `'9'*5000`** → `None` *(py3.11 `int()` raises past `set_int_max_str_digits` — caught by try/except, sec-F4)*; (iii) a layout with an unknown datatype token → `None`. **PLUS the base-10 proof:** leading-zero `'08'` → **derives (count 8 → e.g. 25), NOT None** — proves base-10 (base-0 would *raise* on `'08'`; sec-F2/F3, §6.5 A3) | unguarded/base-0 `int()` → ValueError; `isdigit()` pre-predicate → uncaught raise; `DATATYPE_SIZES[dt]` subscript → KeyError; unguarded `[3]` → IndexError | **Yes** |
| **AT-111** | US-DoS | Oversized synthetic axis (MaxAxisPoints ≈ 10_000_000 / product over the bound) → `length is None` (clamped by `MAX_A2L_DECODE_BYTES`), completes fast (arithmetic cap, no allocation) | unbounded `range`/materialization → hang/OOM; clamp missing → absurd non-None | **Yes** (`@slow` only if it must allocate) |
| **AT-112** | US-P2b | After PR-B re-freeze, frozen-file guards green **and** `git diff main -- s19_app/tui/a2l.py` **empty** | a2l.py ≠ main → guard RED | **No — POST-MERGE PR-B** |

**Gate-blocking set (main PR):** **AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110, AT-111** (reconciled to the qa registry — no-regression, malformed, and DoS are main-PR gates, not deferrable). **AT-112 is post-merge (PR-B), not a PR-A gate.**

**Oracle provenance (verified §2.5):** CURVE.STD_AXIS = 25 B; real MAP.STD_AXIS.STD_AXIS = 51 B (**146 is the synthetic [8,8] — NOT the MAP oracle**); FIX_AXIS.PAR_DIST = 12 B; COM_AXIS = None.

### White-box TC registry (target: NEW `tests/test_a2l_inline_axis_length.py`)

| TC | Backs LLR | Asserts | Notes |
|----|-----------|---------|-------|
| **TC-133** | LLR-P1b.1 `_record_layout_full_span` | Synthetic `layout["lines"]`: datatype from **token[2]**, `1/2/3` = position indices not counts; hand-computed total exact; a position-as-count mutation (→9) asserted-against. **PLUS a size-asymmetric MAP oracle (arch-MAJ1):** `AXIS_PTS_X` SWORD n_x=4 (→8 B) + `AXIS_PTS_Y` SBYTE n_y=3 (→3 B) + FNC → the correct total is discriminable from an **X/Y-count-swap** (8+3 vs 6+4); a swapped `axis_counts[0]↔[1]` assignment → RED | MAJOR-1 guard + axis-order guard |
| **TC-134** | LLR-P1b.2 `_inline_axis_counts` | STD/FIX axis_meta → **base-10** `int(max_axis_points)` counts; COM_AXIS/`external=True` **excluded**; `'08'` → `8` (base-10, not a base-0 raise); `'x'`/`'9'*5000`/`'0'` → `None`, no exception | external gate + base-10 cast |
| **TC-135** | LLR-P1b.3 census (C-31) | code-derived set-algebra: `ALL_AXIS_KINDS == _DERIVABLE \| _EXTERNAL` ∧ disjoint ∧ both non-empty; **demo kinds DERIVED from the parse** (`{am["header_tokens"][0] for tag in parse_a2l_file(DEMO)["tags"] for am in tag["axis_meta"]}`), asserted non-empty ∧ `⊆ ALL_AXIS_KINDS` — **NOT hand-listed** (qa-M2); dropping a real kind from a subset → `observed ⊄ ALL` → RED | set-oracle, derived not literal |
| **TC-136** | LLR-P1b.4 ordering | Length derivable only from populated `axis_meta` → summer runs AFTER the axis loop (`:1273`); pre-axis placement → None | R2 |
| **TC-137** | LLR-P1b.5 no-regression | Scalar `VALUE` routes through `_resolve_record_layout` unchanged; summer not invoked for no-axis/VALUE | scalar path intact |
| **TC-138** | LLR-DoS.1 clamp | Huge count → `None` via a **pure-arithmetic** `MAX_A2L_DECODE_BYTES` compare (no `range`/list); <1s, no `@slow`. Includes a **huge-digit token `'9'*5000`** (sec-F4) → `None`, no exception | no allocation |
| **TC-139** | LLR-P1b.6 fail-closed | `DATATYPE_SIZES.get(dt)` → None not KeyError; `len()`-guard before `[2]`/`[3]`; the `max_axis_points` cast is a **`try/except` around the real `int()`** (NOT an `isdigit()`/regex pre-predicate — sec-F3); `'x'`/`'9'*5000` → None, no raise (`'08'` → 8 is the base-10 derive-case, TC-134) | white-box mirror of AT-110 |
| **TC-140** | LLR-SUP.1 | batch-54 `test_at102_curve_map_length_stays_none` amended None→25/51; positive assertion in the new file; no OTHER batch-54 test asserts these two None | supersession |
| **TC-141** | LLR-P1b.7 unfreeze | `a2l.py` removed from both `_ENGINE_PATHS` with `# UNFROZEN batch-55`; tc032 green (no batch-55 test in `test_tui_a2l.py`) | inspection |
| **TC-142** | LLR-P2b.1 re-freeze | **POST-MERGE PR-B:** `a2l.py` re-inserted into both `_ENGINE_PATHS`; guards green; `git diff main -- a2l.py` empty | post-merge |

### Dual traceability (0 orphans)
- **Behavioral (US → AT):** US-P1b → {AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110}; US-DoS → AT-111; US-P2b → AT-112 (post-merge).
- **Functional (LLR → TC):** P1b.1→133 · P1b.2→134 · P1b.3→135 · P1b.4→136 · P1b.5→137 · P1b.6→139 · P1b.7→141 · DoS.1→138 · SUP.1→140 · P2b.1→142.
- **Check:** every US ≥1 AT; every LLR exactly one TC; every gate-blocking AT (104–111 + 107b) observes THE VALUE / the None through `parse_a2l_file` (AT-108 additionally through the render consumer via `_a2l_tag_row_severity`). **0 orphans.**
- **Bidirectional surface-reachability:** inputs {STD_AXIS, FIX_AXIS derivable; COM_AXIS/CURVE_AXIS/RES_AXIS external; malformed; oversized; scalar VALUE; no-kind} each exercised through `parse_a2l_file`; outputs {byte `length` value; the None; the A2L row colour} observed through `parse_a2l_file` + `enrich_tags_and_render`.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A (white-box, `TC-*`):** `test (unit)` for the summer/resolver/census; `test (integration)` for the wired parse pass; `inspection` for the guard-file toggles + snapshot census; `analysis` for the DoS bound and the 25/51 oracle derivation.
- **Layer B (black-box, `AT-*`):** `parse_a2l_file(Path)` over synthetic single-line A2L strings (byte value computable from the string) + the real demo (tags located BY NAME, never by line), asserting THE BYTE VALUE / the `None` — never "non-empty". AT-108 additionally drives the downstream consumer over the parse-produced tags (output-then-consume, C-12).

### 5.2 Dual-traceability

**Behavioral (black-box) — per story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-P1b | inline CURVE=25 / MAP=51 / FIX_AXIS=12; external COM_AXIS `None`; CUBOID `None`; grey→checked row | `parse_a2l_file` `length`; A2L view row (`_a2l_tag_row_severity`) | AT-104, AT-105, AT-106, AT-107, AT-107b, AT-108, AT-109, AT-110 | Phase-4 |
| US-DoS | oversized layout → `None`/unavailable, no runaway | `parse_a2l_file` + `_extract_raw_bytes` | AT-111 | Phase-4 |
| US-P2b | frozen guards green + empty `git diff main -- a2l.py` | guard tests | AT-112 (post-merge) | Phase-4 (PR-B) |

**Functional (white-box) — per requirement:**

| Requirement | Method | Test Case | Notes |
|-------------|--------|-----------|-------|
| HLR-P1b | test (pilot) | AT-104/105/106/107/107b/108 | byte-value oracle |
| LLR-P1b.1 | test (unit) | TC-133 | position-index-not-count guard |
| LLR-P1b.2 | test (unit) | TC-134 | external gate |
| LLR-P1b.3 | test (unit) + inspection | TC-135 | C-31 census completeness |
| LLR-P1b.4 | test (integration) | TC-136 | R2 ordering |
| LLR-P1b.5 | test + inspection | TC-137 / AT-109 | no-regression + snapshot census |
| LLR-P1b.6 | test (unit + e2e) | TC-139 / AT-110 | fail-closed |
| LLR-P1b.7 | inspection | TC-141 | unfreeze PR-A + tc032 sibling |
| HLR-DoS / LLR-DoS.1 | test + analysis | TC-138 / AT-111 | 1 MiB cap |
| LLR-SUP.1 | test + inspection | TC-140 | AT-102 supersession |
| HLR-P2b / LLR-P2b.1 | test + inspection | TC-142 / AT-112 | re-freeze post-merge |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 passing TC; every US ≥1 passing AT with boundary + negative evidence.
- Gate-blocking AT-104/105/106/107/107b/108/109/110/111 green; 0 blocker fails.
- Full `pytest -q` 0 fail; snapshot drift confined to the 8 inline CURVE/MAP A2L rows (regen via canonical CI only).
- 0 engine-frozen diffs beyond the sanctioned `a2l.py` unfreeze in PR-A; `git diff main -- a2l.py` empty after PR-B.

---

## 6. Appendices

### 6.3 Open risks / security
- **R1 — false-green (HIGH, mitigated):** a too-short length would falsely pass the byte-range memory check. Mitigation = full-span-or-None (LLR-P1b.1) + the external gate (LLR-P1b.2); AT-106 (COM_AXIS stays `None`) is the false-green anchor. Probe: 0 false-None across 12 CURVE/MAP.
- **R2 — ordering (MED, mitigated):** the summer must run AFTER `axis_meta` is built (`:1263-1273`), else `_inline_axis_counts` sees `[]` → `None`. Mitigation = the post-walk pass placement (LLR-P1b.4); TC-136 asserts ordering.
- **R3 — DoS (MED, mitigated):** untrusted MaxAxisPoints/MATRIX_DIM → unbounded `range(byte_size)`. Mitigation = `MAX_A2L_DECODE_BYTES=1 MiB` clamp at `_extract_raw_bytes` + summer cap (LLR-DoS.1); covers the pre-existing scalar path. Distinct from batch-54 `R-A2L-013`. Local self-DoS only — no remote/exec/exfil surface (security F1).
- **R4 — taxonomy incompleteness (MED, mitigated by full-span-or-None):** an unlisted RECORD_LAYOUT component (e.g. `AXIS_RESCALE_X`, `IDENTIFICATION`, `SRC_ADDR_X`) OR a **span-affecting directive** (`ALIGNMENT_BYTE/WORD/LONG/INT64/FLOAT16/FLOAT32/FLOAT64`, which induce inter-component padding) in a future/other A2L → full-span returns `None` (honest grey), never a wrong number. **ALIGNMENT handling (code-review F1, operator decision 2026-07-20 — §6.5 A4):** because the summer does NOT model alignment padding, ANY summable CURVE/MAP layout carrying an ALIGNMENT_* (or any unrecognized non-empty directive line) is forced to `None` rather than under-reported — honoring "never under-report → never false-green" (§2.4). The demo corpus is fully covered (0 false-None; its inline CURVE/MAP layouts are alignment-free); alignment-bearing real A2Ls degrade safely to grey. **Follow-up: batch-56** = alignment-aware padding sizing to restore that coverage correctly.
- **R5 — snapshot false-regression (LOW):** 8 A2L rows flip grey→checked. Mitigation = expected-drift census (LLR-P1b.5) + canonical-CI regen; batch-54 AT-102 supersession (LLR-SUP.1) prevents a false RED.
- **Fail-closed hardening (security F3):** `.get()` not subscript on `DATATYPE_SIZES`; `len()`-guard token access (LLR-P1b.6).
- **C-27 sequencing:** unfreeze in PR-A (same-PR OK), re-freeze in PR-B (post-merge, else self-trip).

### 6.4 Phase-1 reconciliation log
- **New req ids:** `R-A2L-008` (P-1b summer — the id reserved-but-deferred by batch-50), `R-A2L-014` (DoS clamp — new; distinct from batch-54 `R-A2L-013`), `R-A2L-015` (re-freeze). Repo-max canonical in `REQUIREMENTS.md` = `R-A2L-007`; 008–013 are `.dev-flow`-assigned (008 batch-50 reserved, 011/012/013 batch-54). Next free = 014.
- **Draft-time execution (C-35):** the derivation was EXECUTED over the real demo (§2.5) before any LLR was locked — 25/51/12/None all reproduced; taxonomy proven complete (0 false-None over 12 tags). No LLR asserts an un-executed value.
- No LLR threshold/statement changed during reconciliation (first draft). No parent-HLR re-read table required.

### 6.5 Requirement amendments (Before / After)

**A1 — REQUIREMENTS.md:402-405 (locked CURVE/MAP prose):**
- **Before:** "CURVE/MAP deliberately stay unsized (element size would under-count an array span and falsely pass the byte-range check — a false-green); array sizing needs AXIS_DESCR/MATRIX_DIM resolution (deferred, P-1b)."
- **After:** "A CURVE/MAP CHARACTERISTIC with **inline STD_AXIS/FIX_AXIS** axes is sized by summing its resolved RECORD_LAYOUT on-disk span × inline axis point-counts (`_record_layout_full_span` × `_inline_axis_counts`, full-span-or-None), so such records become memory-checkable. CURVE/MAP with an **external axis** (COM_AXIS/RES_AXIS/CURVE_AXIS or AXIS_PTS_REF) deliberately stay `length=None` (the axis storage lives in a separate AXIS_PTS record). Regression: `tests/test_a2l_inline_axis_length.py`." (Phase-3 lands this edit in `REQUIREMENTS.md`; batch-50 flagged "amend when P-1b lands".)
- **New tokens:** `_record_layout_full_span`, `_inline_axis_counts`, `_DERIVABLE_AXIS_KINDS`, `_EXTERNAL_AXIS_KINDS`, `ALL_AXIS_KINDS`, `MAX_A2L_DECODE_BYTES`. **Deleted:** "deferred, P-1b".
- **Parent-HLR re-read:** N/A (documentation prose, not an HLR threshold). **Body edit landed?** §3 HLR-P1b Statement + §2.5 taxonomy.

**A4 — ALIGNMENT directives force `None` (Phase-3, code-review F1, operator decision 2026-07-20):**
- **Before:** `_record_layout_full_span` skipped all `<3`-token lines as "structural" (LLR-P1b.1) — so a 2-token `ALIGNMENT_*` directive was silently ignored, and an alignment-bearing summable layout would UNDER-REPORT its span (false-green — the exact failure full-span-or-None prevents; unregistered in R4 which only covered the *safe* `≥3`-token degradation).
- **After:** ANY non-empty line whose `token[0]` is NOT a recognized summable component and NOT a known-harmless structural token (ALIGNMENT_* being the concrete case) forces the whole span to `None`. LLR-P1b.1's "unclassifiable component → None" is extended from `≥3`-token components to span-affecting directives of any token count. Only genuinely-empty lines are skipped. New TC-133b asserts a synthetic alignment-bearing CURVE → `None` (not an under-reported number).
- **New/Deleted:** deleted the blanket `<3 → skip`; new ALIGNMENT/unrecognized-directive → None guard + TC-133b. **Operator ruling (AskUserQuestion 2026-07-20):** "Safe now + alignment-aware follow-up" — ship the force-None guard this batch; **batch-56** implements alignment-aware padding sizing to restore coverage. **Root cause:** the `<3`-token skip (a reasonable structural filter) created a hole in the safety contract for span-affecting 2-token directives; the demo's alignment-free inline layouts hid it; caught by the independent code review. **Parent-HLR re-read:** HLR-P1b — the full-span-or-None invariant is *strengthened*, no threshold change. **Body edit landed?** §4 LLR-P1b.1 (Phase-3 code) + §6.3 R4 + §4.9 TC-133b.

**A3 — AT-110/TC-139 `'08'` disposition (Phase-3, implementation-surfaced — C-36):**
- **Before (Phase-2 fold error):** AT-110(ii) + TC-139 listed leading-zero `'08'` as a `length is None` fail-closed case.
- **After:** `'08'` is a **valid base-10 decimal → 8 → derives** (e.g. 25 over a demo-shaped layout); it is NOT a None case. The `'08'→None` expectation was only true under the *rejected* base-0 cast (sec-F2). AT-110 now proves base-10 via `'08'→25`; the None-cases are non-numeric `'x'`, huge-digit `'9'*5000`, and unknown-datatype. `'08'→8` also lives in TC-134 (correct all along).
- **New/Deleted:** deleted the `'08'→None` assertion; new `'08'→derives` base-10 proof. **Root cause:** the Phase-2 sec-F2 fold adopted base-10 (correct) but the AT-110 wording still carried the base-0 `'08'→None` consequence — an acceptance value contradicting the model's own defined behavior (the C-36 phantom-value class). Caught at Inc-2 by the `software-dev` executing the real cast (fail-loud). **Parent-HLR re-read:** HLR-P1b — no threshold change. **Body edit landed?** §4.9 AT-110 + TC-139.

**A2 — batch-54 `test_at102_curve_map_length_stays_none` (LLR-SUP.1):**
- **Before:** `assert curve["length"] is None` ∧ `assert cmap["length"] is None` (`tests/test_a2l_multiline_headers.py:340-341`), intent "batch-55 owns the summer; a premature length summer would trip here."
- **After:** `assert curve["length"] == 25` ∧ `assert cmap["length"] == 51`; intent updated to "batch-55 summer landed"; the None-anchor role moves to AT-106 (external COM_AXIS).
- **New/Deleted tokens:** new `== 25`/`== 51`; deleted the two `is None` assertions on these names. **Parent-HLR re-read:** HLR-P1b — no threshold change (the test now confirms, not contradicts, the summer). **Body edit landed?** §4 LLR-SUP.1 + §4.9 TC-140.

---

## 7. Gate decision — symbol visibility (RESOLVED, autonomous 2026-07-20)
- **Decision: `_record_layout_full_span` + `_inline_axis_counts` are PRIVATE, no facade re-export.** The batch-50 seed named a public `record_layout_full_span`, but the exact in-module precedent — `_resolve_record_layout` and `_infer_length_characteristic` (both private, both tested directly via `tests/test_a2l_record_layout_length.py`, NEITHER re-exported from a facade) — governs. Private is the surgical, convention-conformant choice (C-3 surgical / C-11 match-the-codebase): the summer is an internal parse-time enrichment, not a public API. No `a2l_parse`/`a2l_extract`/`__all__` change; no `__all__` census TC needed. Recorded in the decision log; carried to the postmortem + vault.
- **Rationale for not asking:** the operator granted end-to-end autonomy; this is a design-default with a clear precedent-backed answer and no user-visible or interface consequence. Reversible (promoting a private symbol to public later is additive).
