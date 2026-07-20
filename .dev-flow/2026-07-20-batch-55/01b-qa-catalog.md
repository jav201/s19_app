# 01b — QA catalog · batch-55 (P-1b inline-axis length summer)

**BLUF.** This catalog pins (1) the per-requirement **validation method** and (2) the canonical **AT (black-box) + TC (white-box) registry** for the CURVE/MAP inline-axis length summer. Gate-blocking oracle values are fixed and independent of the demo: `ASAM.C.CURVE.STD_AXIS → length==25`, real inline `ASAM.C.MAP.STD_AXIS.STD_AXIS → length==51`, external `ASAM.C.CURVE.COM_AXIS → length is None` (the false-green anchor). Every value AT asserts **THE BYTE VALUE / the None**, never "non-empty". C-12 chain head = `parse_a2l_file`. All new TCs land in a NEW non-frozen file `tests/test_a2l_inline_axis_length.py` (NEVER `tests/test_tui_a2l.py`, tc032-frozen).

**Next-free ids (verified 2026-07-20 against tracked `tests/*.py` + `.dev-flow/`):**
- **AT family is clean:** repo-max tracked AT = `AT-103` (batch-54). Batch-55 uses **AT-104 … AT-112**.
- **TC low range is polluted:** `TC-100..102` (batch-54 `test_a2l_multiline_headers.py`), `TC-101..106` (`test_crc_engine.py`), `TC-111/112/121-126` (`test_crc_operation.py`), `TC-114` (`test_changes_schema.py`) are all merged and live. First clean contiguous block is **TC-133+**. Batch-55 uses **TC-133 … TC-142**. *(Do not "correct" these back to TC-104 — 104..126 collide with the merged CRC suite.)*

> **⚠ Cross-batch coordination (MANDATORY — for the architect's §6.5).** Batch-54 shipped a LIVE test `tests/test_a2l_multiline_headers.py::test_at102_curve_map_length_stays_none` (AT-102) that asserts `curve["length"] is None` **and** `cmap["length"] is None`, with the explicit counterfactual *"a premature length summer would trip here."* **Batch-55 IS that summer.** This test WILL go RED. It lives in a non-frozen file, so it is editable. This must be recorded as a §6.5 Before→After amendment (AT-102 flips from `None` to `25`/`51`) and the assertion superseded by **AT-104/AT-105** here. Tracked in this catalog as **LLR-SUP.1 / TC-140**. Failing to amend it = a false regression signal at the Phase-4 gate.

---

## Section A — Validation method per requirement

Method legend: **test** (automated AT/TC) · **demo** (observed through the shipped A2L view / pilot) · **inspection** (diff / census / guard-file read) · **analysis** (numeric bound / oracle derivation).

| Req (expected id — architect finalizes) | What it delivers | Method(s) | Evidence artifact |
|---|---|---|---|
| **US-P1b** — CURVE/MAP inline-axis length summer | grey→memory-checkable A2L row with a correct byte `length` | **test** (AT-104..108, TC-133..137) + **demo** (A2L view row flip, AT-108 / pilot gallery refresh) + **analysis** (25 & 51 oracle derivation) | AT-104/105/106/107/108; pilot A2L view screenshot |
| **LLR** `record_layout_full_span(layout, axis_counts)` reading `layout["lines"]` (1/2/3 = POSITION INDICES not counts; datatype = token[2]) | correct component byte span | **test** (TC-133) + **analysis** (hand-computed span from a synthetic layout) | TC-133 |
| **LLR** `_inline_axis_counts(axis_meta)` gated on `_DERIVABLE_AXIS_KINDS`, honoring the `external` flag | per-axis element counts, external → excluded | **test** (TC-134) | TC-134 |
| **LLR** axis-kind completeness invariant (`ALL_AXIS_KINDS == _DERIVABLE_AXIS_KINDS \| _EXTERNAL_AXIS_KINDS`; all non-empty; disjoint) | the axis-kind gate cannot silently drop a real kind | **test** (TC-135, C-31 set-oracle) + **inspection** (constants are derived/live, not hand-listed) | TC-135 |
| **LLR** post-axis-walk length pass (R2 ordering — summer runs AFTER `axis_meta` is built at `a2l.py:1263-1273`) | summer can see axis counts | **test** (TC-136) | TC-136 |
| **LLR** no-regression: scalar VALUE + single-line MEAS + no-kind chars untouched | summer engages ONLY for CURVE/MAP w/ derivable inline axes | **test** (AT-109, TC-137) + **inspection** (0 snapshot drift) | AT-109; TC-137; snapshot-diff |
| **US-P1b robustness** — malformed axis / record layout | fail-closed (`None`, no raise) | **test** (AT-110 black-box, TC-139 white-box: `.get()` not subscript; `len()`-guard `header_tokens`/`lines`) | AT-110; TC-139 |
| **US-DoS** — oversized axis count / datatype product | length clamped to `None` under a byte bound (`MAX_A2L_DECODE_BYTES`), no allocation/hang | **test** (AT-111, TC-138) + **analysis** (bound value chosen 1–16 MiB) | AT-111 (may `@slow`); TC-138 (pure-arithmetic cap) |
| **LLR-SUP.1** — supersede batch-54 AT-102 | old "stays None" test amended to the new value | **inspection** + **test** (TC-140) | TC-140 |
| **LLR** C-27 unfreeze `a2l.py` (enabling, this batch) | summer edit allowed in the same PR | **inspection** (TC-141: a2l.py removed from both `_ENGINE_PATHS`; new tests not in tc032-frozen file) | TC-141 |
| **US-P2b** — re-freeze `a2l.py` (post-merge PR-B, guard-files only) | module returns to read-only oracle | **test** + **inspection** (AT-112, TC-142: guards green + `git diff main -- a2l.py` empty) | AT-112 / TC-142 (**post-merge, non-gate for the main PR**) |

---

## Section B — AT registry (black-box, observed through the shipped surface)

C-12 chain head is `parse_a2l_file(Path)` for every value AT; AT-108 additionally drives the downstream consumer (`enrich_tags_and_render`) over the parse-produced tags (output-then-consume). Synthetic fixtures are SMALL single-line A2L strings whose byte length is hand-computable from the string, so the oracle is independent of the demo; demo ATs locate tags **by name**, never by line number.

| AT | Story | Asserts THE VALUE (through the surface) | Counterfactual — code mutation that turns it RED | Gate-blocking? |
|----|-------|-----------------------------------------|--------------------------------------------------|----------------|
| **AT-104** | US-P1b | `parse_a2l_file(demo).tags` → tag `name=="ASAM.C.CURVE.STD_AXIS"` has **`length == 25`** (1×UBYTE count + 8×SBYTE axis + 8×SWORD fnc) | reads `tok[1]` as count instead of position index → `9`; or drops the axis term → `17`; pre-fix → `None` | **Yes** |
| **AT-105** | US-P1b | tag `name=="ASAM.C.MAP.STD_AXIS.STD_AXIS"` (real inline, axes 4&5) has **`length == 51`** (1+1+4+5 + 4·5·2) | sums one axis only → `29`; uses synthetic `[8,8]` shape → `146`; pre-fix → `None` | **Yes** |
| **AT-106** | US-P1b | tag `name=="ASAM.C.CURVE.COM_AXIS"` (external `AXIS_PTS_REF`) has **`length is None`** — *the false-green anchor: full-span-or-None, we never fabricate coverage for an external axis* | summer ignores the `external` flag / `_EXTERNAL_AXIS_KINDS` and sums element sizes anyway → a wrong non-`None` (e.g. `17`) | **Yes** |
| **AT-107** | US-P1b | A **synthetic single-line** CURVE A2L (in-test string; span hand-computable, e.g. `1×UBYTE + 4×SWORD axis + 4×UBYTE fnc = 1+8+4 = 13`) → `parse_a2l_file(tmp).length == 13` | position-as-count or wrong datatype token (token[1] vs token[2]) → ≠13; independent of demo line numbers | **Yes** |
| **AT-108** | US-P1b | **User-surface / output-then-consume:** feed the AT-104 parse output into `enrich_tags_and_render`; the CURVE row severity flips **grey → memory-checkable** (`sev-neutral` → `sev-info` off-image, or `sev-ok` with a covering `mem_map`) *because* `length` is now `25` | `length` stays `None` → row stays grey (`sev-neutral`); proves the filled length actually reaches the row-colour policy | **Yes** |
| **AT-109** | US-P1b (no-regression) | (a) `case_01` 2/2 scalar `char_type=="VALUE"` `length` **unchanged**; (b) demo MEASUREMENT lengths **unchanged**; (c) synthetic no-kind CHARACTERISTIC → `length is None`; (d) **0 snapshot drift** on the A2L view baselines | summer over-reaches into the scalar/MEAS/no-kind path → a length appears where there was `None`, or a baseline shifts | **Yes** |
| **AT-110** | US-P1b (robustness) | Malformed CURVE via `parse_a2l_file(tmp)`: non-numeric `MaxAxisPoints` **and** a record layout missing any datatype token → tag `length is None`, **no exception raised** | `int(max_axis_points)` unguarded → `ValueError`; `DATATYPE_SIZES[dt]` subscript → `KeyError`; `header_tokens[3]`/`lines[i]` unguarded → `IndexError` | **Yes** |
| **AT-111** | US-DoS | Oversized synthetic axis (`MaxAxisPoints` = e.g. `10_000_000`, or a datatype-product over the byte bound) → tag `length is None` (clamped by `MAX_A2L_DECODE_BYTES`); the call **completes fast** (pure-arithmetic cap, no allocation) | unbounded `range`/materialization → hang/OOM; or clamp missing → an absurd non-`None` length | **Yes** (mark `@slow` only if it must allocate; prefer the arithmetic cap so it needn't) |
| **AT-112** | US-P2b | After the re-freeze PR-B, the frozen-file guards are green **and** `git diff main -- s19_app/tui/a2l.py` is **empty** | a2l.py ≠ `main` → guard RED | **No — POST-MERGE PR-B** (un-runnable until the main PR merges; a same-PR re-freeze self-trips the vs-`main` guard) |

**Gate-blocking set (main PR):** AT-104, AT-105, AT-106, AT-107, AT-108, AT-109, AT-110, AT-111. **AT-112 is post-merge (PR-B), not a main-PR gate.**

**Oracle provenance (analysis, verified this session):** CURVE `ASAM.C.CURVE.STD_AXIS` = 25 B (`1 count UBYTE + 8 axis SBYTE + 8 fnc SWORD`); real inline MAP `ASAM.C.MAP.STD_AXIS.STD_AXIS` (axes 4 & 5) = 51 B (`1+1+4+5 + 4·5·2`); **146 is the synthetic `[8,8]` — do NOT use it as the MAP oracle.** COM_AXIS → `None` (external). `axis_meta[i]["max_axis_points"]` is a **STR** → the summer MUST `int()`-cast it (through the DoS-guarded path).

---

## Section C — TC registry (white-box)

**Target file for ALL new TCs: `tests/test_a2l_inline_axis_length.py` (NEW, non-frozen).** Rationale (C-27): `tests/test_tui_a2l.py` is tc032-frozen; landing a batch-55 test there trips the freeze guard. TC-141/142 additionally touch only the guard-file lists.

| TC | Backs LLR (expected) | Asserts | Target test file |
|----|----------------------|---------|------------------|
| **TC-133** | `record_layout_full_span` | Over a synthetic `layout["lines"]`, the span reads the datatype from **token[2]** and treats `1/2/3` as **position indices, not counts**; hand-computed total matches; a **position-as-count mutation** (`1×UBYTE + 2×SBYTE + 3×SWORD = 9`) is asserted-against so it goes RED | `tests/test_a2l_inline_axis_length.py` |
| **TC-134** | `_inline_axis_counts` | STD_AXIS & FIX_AXIS axis_meta entries yield their `int(max_axis_points)` counts; a COM_AXIS / `external=True` entry is **excluded** (contributes no count) | `tests/test_a2l_inline_axis_length.py` |
| **TC-135** | axis-kind completeness invariant (C-31) | `ALL_AXIS_KINDS == _DERIVABLE_AXIS_KINDS \| _EXTERNAL_AXIS_KINDS` **and** `_DERIVABLE_AXIS_KINDS & _EXTERNAL_AXIS_KINDS == ∅` **and** all three sets non-empty. Vocabulary must cover the 5 demo kinds {STD_AXIS, FIX_AXIS, COM_AXIS, CURVE_AXIS, RES_AXIS}. **Dropping a real kind from either set → RED** (a hand-listed census would be vacuous; the invariant is the oracle) | `tests/test_a2l_inline_axis_length.py` |
| **TC-136** | post-axis-walk ordering pass | On a fixture whose length is only derivable from populated `axis_meta`, the summer runs **after** the axis_meta loop (`a2l.py:1263-1273`) → `length` is non-`None`; a fixture ordering probe fails if the length pass is placed before axis_meta is built | `tests/test_a2l_inline_axis_length.py` |
| **TC-137** | no-regression (scalar path) | Scalar `VALUE` still routes through `_resolve_record_layout` (unchanged byte_size); the CURVE/MAP summer is **not** invoked for a no-axis / VALUE char (assert the scalar length is identical to pre-batch) | `tests/test_a2l_inline_axis_length.py` |
| **TC-138** | US-DoS clamp | `record_layout_full_span` / the summer with a huge count returns `None` via a **pure-arithmetic** `MAX_A2L_DECODE_BYTES` comparison (no `range`/list materialization); runs in <1s without `@slow` | `tests/test_a2l_inline_axis_length.py` |
| **TC-139** | robustness (fail-closed) | `DATATYPE_SIZES.get(dt)` (not subscript) → `None`, not `KeyError`; `len()`-guard before `header_tokens[3]`/`lines[i]`; non-numeric `max_axis_points` → guarded `int()` → `None`. White-box mirror of AT-110 | `tests/test_a2l_inline_axis_length.py` |
| **TC-140** | LLR-SUP.1 (supersede batch-54 AT-102) | The batch-54 `test_at102_curve_map_length_stays_none` assertion (`None`/`None`) is **amended** to the batch-55 expectation (`25`/`51`); the new positive assertion lives in this file. Confirm no OTHER batch-54 multiline test asserts these two are `None` | `tests/test_a2l_inline_axis_length.py` + edit `tests/test_a2l_multiline_headers.py` |
| **TC-141** | C-27 unfreeze (this batch) | `s19_app/tui/a2l.py` is **removed** from both `_ENGINE_PATHS` (`test_engine_unchanged.py`, `test_tui_directionb.py` tc031) with an `# UNFROZEN batch-55` marker; tc032 (`test_tui_a2l.py` freeze) stays green because no batch-55 test landed there | inspection of guard files |
| **TC-142** | US-P2b re-freeze | **POST-MERGE PR-B (guard-files only):** `a2l.py` re-inserted into both `_ENGINE_PATHS`; guards green; `git diff main -- s19_app/tui/a2l.py` empty | `test_engine_unchanged.py` + `test_tui_directionb.py` (post-merge) |

---

## Section D — Dual traceability (0 orphans)

**Behavioral (US → AT):**
- **US-P1b** → {AT-104, AT-105, AT-106, AT-107, AT-108, AT-109 (no-regression), AT-110 (robustness)}
- **US-DoS** → AT-111
- **US-P2b** → AT-112 (post-merge)

**Functional (LLR → TC):**
- `record_layout_full_span` → TC-133 · `_inline_axis_counts` → TC-134 · axis-kind completeness → TC-135 · ordering pass → TC-136 · no-regression scalar → TC-137 · DoS clamp → TC-138 · robustness → TC-139 · LLR-SUP.1 → TC-140 · C-27 unfreeze → TC-141 · US-P2b re-freeze → TC-142

**Check:** every US has ≥1 AT (P1b: 7, DoS: 1, P2b: 1). Every expected LLR has exactly one TC. Every gate-blocking AT (104–111) observes THE VALUE / the None through `parse_a2l_file` (AT-108 additionally through the render consumer). **0 orphans.**

**Bidirectional surface-reachability:** input dimensions {STD_AXIS, FIX_AXIS derivable; COM_AXIS/CURVE_AXIS/RES_AXIS external; malformed; oversized; scalar VALUE; no-kind} are each exercised through `parse_a2l_file`. Output/deliverable {byte `length` value; the None; the A2L row colour} is observed through the shipped surfaces (`parse_a2l_file` + `enrich_tags_and_render`). Layer B (black-box) covered by AT-104..111; AT-108 observes the shipped A2L-view row, not only the mechanism.

---

## Section E — Evidence checklist (QA self-audit)

- [✓] Acceptance criteria use Given/When/Then form (implicit in AT "asserts THE VALUE … through parse_a2l_file"; expandable on request).
- [✓] Test cases have explicit Expected values — `25`, `51`, `None`, `13`, `9` (counterfactual) — not vague "works".
- [✓] Edge cases: empty/None (external → None), boundary (synthetic hand-computed span AT-107), invalid (malformed AT-110/TC-139), error/DoS (oversized AT-111/TC-138).
- [✓] Regression checklist: AT-109 (scalar VALUE + single-line MEAS + no-kind + 0 snapshot drift) and the batch-54 AT-102 supersede (TC-140).
- [✓] Exit criteria: gate-blocking set AT-104..111 green; AT-112/TC-142 post-merge; 0 snapshot drift; frozen guards green after re-freeze.
- [✓] No real PII / secrets — synthetic in-test A2L + the public `case_00_public` demo fixture only.
- [✓] Test results left **blank** — this is a plan authored pre-implementation; oracle values (25/51/None) were derived by executing `parse_a2l_file` over the demo this session, but no batch-55 test has been run (the summer does not exist yet). **I have NOT run AT-104..112.**
- [✓] Layer B: the output-producing story (US-P1b) is observed through the shipped `parse_a2l_file` surface AND the A2L-view render (AT-108), with boundary (AT-107) + negative (AT-106 external-None, AT-110 malformed) evidence.
- [✓] Bidirectional surface-reachability — see Section D.
- [✓] No unfilled template — every row is concrete; ids AT-104..112 / TC-133..142 are pinned; no `<...>` placeholders.

> **Not signed off as passing.** These are pre-implementation acceptance criteria. The summer, the axis-kind constants, `record_layout_full_span`, and the DoS clamp do not exist yet. The 25/51/None oracles are verified; the tests asserting them are not yet written or run.
