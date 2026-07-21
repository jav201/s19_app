# 01b — QA catalog · batch-56 (alignment-aware padding sizing)

**BLUF.** This catalog pins (1) the per-requirement **validation method** and (2) the canonical **AT (black-box) + TC (white-box) registry** for alignment-aware CURVE/MAP sizing. Every value AT asserts **THE BYTE VALUE / the None** through `parse_a2l_file`, never "non-empty". The **gate-blocking anchor** is the batch-55 regression AT (**AT-114**): the real demo must still report `CURVE.STD_AXIS==25`, `MAP.STD_AXIS.STD_AXIS==51`, `FIX_AXIS.PAR_DIST==12` UNCHANGED — a naive natural-alignment default would flip 25→26 and trip it. The value proof is **AT-113** (a synthetic ALIGNMENT-bearing CURVE → `length==16` where packed would be `13`) plus **AT-115** (same components parsed with vs without the ALIGNMENT lines → `16 > 13`, isolating R-A as the sole cause of the delta). All new TCs land in a NEW non-frozen file **`tests/test_a2l_alignment_sizing.py`** (NEVER `tests/test_tui_a2l.py`, tc032-frozen); the one supersede edit touches the non-frozen `tests/test_a2l_inline_axis_length.py`.

**Next-free ids (verified 2026-07-20 against tracked `tests/*.py` + `.dev-flow/`):**
- **AT:** repo-max tracked AT = `AT-112` (batch-55, post-merge re-freeze). Batch-56 uses **AT-113 … AT-121**. (`AT-113..125` confirmed unused.)
- **TC:** the inline-axis series ends at `TC-142` (batch-55); the next series `TC-143..152` is free (the `TC-3xx` block belongs to the report-service suite; `TC-101..126` to the CRC suite — do NOT reuse those). Batch-56 uses **TC-143 … TC-153**. (`TC-143..160` confirmed unused.)

> **⚠ Cross-batch coordination (MANDATORY — for the architect's §6.5).** Batch-55 shipped a LIVE test `tests/test_a2l_inline_axis_length.py::test_tc133b_alignment_directive_forces_none` (TC-133b) that asserts an `ALIGNMENT_WORD`/`ALIGNMENT_LONG` directive forces `length is None`, with the explicit intent *"an ALIGNMENT_* padding directive forces full-span-or-None (never under-report)."* **Batch-56 IS that model.** Its two force-None assertions WILL go RED:
> - `with_alignment` (`NO_AXIS_PTS_X UBYTE, ALIGNMENT_WORD 2, AXIS_PTS_X UBYTE, FNC_VALUES SWORD`, `axis=[4]`) flips `None → 14` (packed would be `13`; the `ALIGNMENT_WORD 2` inserts 1 pad byte before `FNC_VALUES`).
> - `trailing_align` (…`, ALIGNMENT_LONG 4` last) flips `None → 13` (no-trailing R-C) **or** `→ 16` (trailing-pad R-C) — value pinned by the R-C decision (see AT-119).
> - The FIRST assertion of TC-133b (`summable` with NO alignment → `13`) STAYS TRUE (R-A packed default) and must be RETAINED.
>
> This file is NON-frozen, so it is editable. Record it as a §6.5 Before→After amendment (TC-133b force-None → computed values) and supersede the flipped assertions via **LLR-SUP.2 / TC-151** here. Failing to amend it = a false regression signal at the Phase-4 gate. *(This is the direct batch-56 analog of batch-55's LLR-SUP.1 / AT-102 supersede.)*

> **Scope flag for the architect (MOD_COMMON).** The stress fixture `tests/conftest.py:205` declares `ALIGNMENT_BYTE 1` in **MOD_COMMON** (not the RECORD_LAYOUT). The batch-55 summer reads only `layout["lines"]`. **Decide in §2 whether batch-56 honors MOD_COMMON-scoped `ALIGNMENT_*`.** Either way `ALIGNMENT_BYTE 1` is a no-op (align=1 → 0 pad), so the `large_a2l` stress fixture must show **0 length drift** — asserted as a regression watch-item in AT-114(d).

---

## Section A — Validation method per requirement

Method legend: **test** (automated AT/TC) · **demo** (observed through the shipped A2L view / pilot) · **inspection** (diff / census / guard-file read) · **analysis** (numeric bound / hand-computed oracle).

| Req (expected id — architect finalizes) | What it delivers | Method(s) | Evidence artifact |
|---|---|---|---|
| **US-ALIGN** — ALIGNMENT-bearing CURVE/MAP size correctly (padded) | grey→memory-checkable A2L row with a correct **padded** byte `length` | **test** (AT-113, AT-115, AT-117, AT-118; TC-143..146) + **analysis** (cumulative-offset hand-computation, §oracle-provenance) | AT-113 (`16`); AT-115 (`16>13`) |
| **US-ALIGN (R-A)** — alignment-free layouts UNCHANGED from batch-55 (packed default) | 25 / 51 / 12 preserved; no perturbation of any alignment-free layout | **test** (AT-114 **gate anchor**, TC-147) + **demo** (real demo view values) + **inspection** (0 snapshot drift; 0 stress-fixture drift) | AT-114 (`25`,`51`,`12`); snapshot-diff |
| **LLR-ALIGN.1** — alignment-class census constant (`ALIGNMENT_<class> → size`, 7 classes, derived) | the alignment gate cannot silently drop a real class | **test** (TC-143, C-31 set-oracle) + **inspection** (derived from `DATATYPE_SIZES` classes, not hand-listed) | TC-143 |
| **LLR-ALIGN.2** — cumulative-offset walk with per-component `align_up` (R-B) | correct padded span from a synthetic layout | **test** (TC-144, TC-146) + **analysis** (hand-computed offsets) | TC-144 |
| **LLR-ALIGN.3** — alignment-map extraction from `layout["lines"]` (+MOD_COMMON scope decision) | declared `ALIGNMENT_*` → `{class: value}`; undeclared class → align 1 (R-A) | **test** (TC-145) | TC-145 |
| **LLR-ALIGN.4** — R-A packed default (no `ALIGNMENT_*` → padding 0) | byte-for-byte equal to the batch-55 running sum | **test** (TC-147, white-box mirror of AT-114) | TC-147 |
| **LLR-ALIGN.5** — R-B per-component align to the **declared** class value (over-align honored) | uses the declared value, not the datatype's natural size | **test** (AT-118, TC-144) | AT-118 (`16`, not `12`) |
| **LLR-ALIGN.6** — R-C trailing-record pad (**architect decision**) | total padded (or not) to max declared alignment | **test** (AT-119, TC-150) — **assert whatever §2 pins** | AT-119 (`17` no-trailing / `24` trailing) |
| **LLR-ALIGN.7** — full-span-or-None preserved for genuinely-unmodeled directives | an unmodeled non-alignment directive still → `None` (never a fabricated span) | **test** (AT-116 black-box, TC-148 white-box) | AT-116 (`None`) |
| **LLR-ALIGN.8** — DoS clamp holds WITH padding | padded total over `MAX_A2L_DECODE_BYTES` → `None`, no allocation/hang | **test** (AT-120, TC-149) + **analysis** (cap unchanged, padding bounded) | AT-120; TC-149 |
| **LLR-SUP.2** — supersede batch-55 TC-133b force-None | flipped assertions amended to the batch-56 computed values | **inspection** + **test** (TC-151) | TC-151 |
| **LLR-ALIGN.9** — C-27 unfreeze `a2l.py` (enabling, this batch) | alignment edit allowed in the same PR | **inspection** (TC-152: a2l.py removed from both `_ENGINE_PATHS`; new tests not in the tc032-frozen file) | TC-152 |
| **US-P2b** — re-freeze `a2l.py` (post-merge PR-B, guard-files only) | module returns to read-only oracle | **test** + **inspection** (AT-121, TC-153: guards green + `git diff main -- a2l.py` empty) | AT-121 / TC-153 (**post-merge, non-gate for the main PR**) |

---

## Section B — AT registry (black-box, observed through the shipped surface)

C-12 chain head is `parse_a2l_file(Path)` for every value AT; AT-113 additionally drives the downstream consumer (`enrich_tags_and_render` / `_a2l_tag_row_severity`) over the parse-produced tags (output-then-consume). Synthetic fixtures are SMALL A2L strings whose padded span is hand-computable from the string (built via the existing `_write_a2l` helper in `tests/test_a2l_inline_axis_length.py`, which drives `parse_a2l_file`), so the oracle is independent of the demo. Demo ATs locate tags **by name**, never by line number.

> **Recommended §2.5 primary fixture (adopt or adjust — architect owns §2.5).** A CURVE with a single `STD_AXIS` (`MaxAxisPoints=2`) and a RECORD_LAYOUT declaring two alignment classes:
> ```
> NO_AXIS_PTS_X 1 UBYTE     ← BYTE class, align 1
> ALIGNMENT_WORD 2
> ALIGNMENT_LONG 4
> AXIS_PTS_X   2 UWORD      ← WORD class → align 2, count = 2 (axis)
> FNC_VALUES   3 ULONG      ← LONG class → align 4, count = 2 (axis)
> ```
> **Packed (batch-55, executed today = 13):** `1×1 + 2×2 + 4×2 = 13`.
> **Aligned walk:** off 0 →(UBYTE)→ 1 →(UWORD, rup 1→2, +4)→ 6 →(ULONG, rup 6→8, +8)→ **16**. Ends LONG-aligned (16 mod 4 = 0) ⇒ **R-C-independent = 16**. 3 pad bytes across two classes.

| AT | Story | Asserts THE VALUE (through the surface) | Counterfactual — code mutation that turns it RED | Gate-blocking? |
|----|-------|-----------------------------------------|--------------------------------------------------|----------------|
| **AT-113** | US-ALIGN | Synthetic ALIGNMENT-bearing CURVE (above) via `parse_a2l_file` → tag `length == 16` (packed would be 13); **and (b) output-then-consume:** feeding that tag to `enrich_tags_and_render` / `_a2l_tag_row_severity` yields a memory-checkable (non-grey) row *because* `length` is filled | ignores the declared `ALIGNMENT_*` → `13`; skips the pad on one class → `14`/`15`; pre-fix (force-None on ALIGNMENT) → `None` → row stays grey | **Yes** |
| **AT-114** | US-ALIGN (R-A) — **the critical regression** | Real demo via `parse_a2l_file`: (a) `ASAM.C.CURVE.STD_AXIS.length == 25`; (b) `ASAM.C.MAP.STD_AXIS.STD_AXIS.length == 51`; (c) `ASAM.C.CURVE.FIX_AXIS.PAR_DIST.length == 12` — **ALL UNCHANGED**; (d) `large_a2l` stress-fixture characteristic lengths + A2L-view snapshots show **0 drift** | applies natural alignment **by default** (not gated on a declared `ALIGNMENT_*`) → the alignment-free STD_AXIS layout gains pad → `25→26`; or MOD_COMMON `ALIGNMENT_BYTE 1` mis-read as a wider align → drift | **Yes (gate anchor)** |
| **AT-115** | US-ALIGN (R-A isolation) | Parse the SAME components **with** the ALIGNMENT lines and **without** them (strip `ALIGNMENT_WORD`/`ALIGNMENT_LONG`) → `with.length (16) > without.length (13)` **and** `without.length == 13` (the batch-55 packed value survives in a synthetic) — proves the ALIGNMENT declaration is the SOLE cause of the delta | padding applied even when no `ALIGNMENT_*` is declared → `without` also `16` → the `>` holds but `without==13` fails (catches an ungated pad, the R-A violation AT-114 also guards) | **Yes** |
| **AT-116** | US-ALIGN (full-span-or-None preserved) | An ALIGNMENT-bearing CURVE whose RECORD_LAYOUT ALSO contains a genuinely-unmodeled non-alignment directive (`AXIS_RESCALE_X` / `RESERVED` / `SRC_ADDR_X`) → tag `length is None`, **no exception raised** | the alignment refactor treats any unknown 2-token line as 0-pad and sums past it → a fabricated non-`None` span (under-report false-green) | **Yes** |
| **AT-117** | US-ALIGN (boundary — already satisfied) | All-even WORD layout (`UWORD/UWORD/UWORD`, `STD_AXIS=2`) with `ALIGNMENT_WORD 2` declared → `length == 10` == the packed value (pad = 0; alignment declared but a no-op) | a mutation that pads unconditionally (adds a phantom byte even when the offset is already aligned) → `>10` | **Yes** |
| **AT-118** | US-ALIGN (boundary — over-align, R-B) | FIX_AXIS FNC-only layout (`UBYTE`, `ULONG`, `axis=2`) with `ALIGNMENT_LONG 8` **over-declared** (value > natural LONG size 4) → `length == 16` (`rup(1,8)=8; +8`) | uses the datatype's **natural** size (4) instead of the **declared** value (8) → `rup(1,4)=4; +8 = 12` ≠ 16 | **Yes** |
| **AT-119** | US-ALIGN (R-C decision) | Layout ending on a small component after a large-aligned one (`UBYTE`, `A_UINT64`, `UBYTE`, `ALIGNMENT_INT64 8`, `STD_AXIS=1`): no-trailing offset = 17, trailing-to-max = 24 → **assert the value §2 pins** (`17` if R-C = no trailing pad; `24` if R-C = pad to max declared alignment) | the impl adopts the OTHER R-C reading than the one pinned → the asserted value flips; a missing final-pad step → `17` when `24` was pinned | **Yes (pins R-C)** |
| **AT-120** | US-ALIGN (DoS) | Oversized synthetic axis with alignment declared (`MaxAxisPoints` huge, or a datatype-product + pad over the byte bound) → tag `length is None` (clamped by `MAX_A2L_DECODE_BYTES`); the call **completes fast** (arithmetic cap, padding is bounded, no allocation) | padding accounted AFTER the cap check, or clamp dropped → hang/OOM, or an absurd non-`None` length | **Yes** (mark `@slow` only if it must allocate; prefer the arithmetic cap so it needn't) |
| **AT-121** | US-P2b | After the re-freeze PR-B, the frozen-file guards are green **and** `git diff main -- s19_app/tui/a2l.py` is **empty** | a2l.py ≠ `main` → guard RED | **No — POST-MERGE PR-B** (un-runnable until the main PR merges; a same-PR re-freeze self-trips the vs-`main` guard) |

**Gate-blocking set (main PR):** AT-113, AT-114, AT-115, AT-116, AT-117, AT-118, AT-119, AT-120. **AT-121 is post-merge (PR-B), not a main-PR gate.**

**Oracle provenance (analysis + executed baselines, this session):** packed baselines EXECUTED through today's `_record_layout_full_span` (C-35): AT-113 packed `= 13`, AT-117 packed `= 10`, AT-118 packed `= 9`; TC-133b `with_alignment` currently `= None` (proving the batch-56 flip). Aligned oracles are hand-derived on top of those executed values via the cumulative-offset walk (R-A/R-B; R-C-independent for AT-113/117/118 by ending on a max-aligned offset). Batch-55 demo oracles 25 / 51 / 12 are the shipped values asserted by `test_at104/at105/at107` and are preserved by the R-A packed default. **AT-119 is the only oracle that moves with the R-C decision** — finalize its asserted value once §2 pins R-C.

---

## Section C — TC registry (white-box)

**Target file for ALL new TCs: `tests/test_a2l_alignment_sizing.py` (NEW, non-frozen).** Rationale (C-27): `tests/test_tui_a2l.py` is tc032-frozen; landing a batch-56 test there trips the freeze guard. TC-151 additionally edits the non-frozen `tests/test_a2l_inline_axis_length.py` (the TC-133b supersede). TC-152/153 touch only the guard-file lists.

| TC | Backs LLR (expected) | Asserts | Target test file |
|----|----------------------|---------|------------------|
| **TC-143** | LLR-ALIGN.1 census (C-31) | The `ALIGNMENT_<class> → size` map covers **all 7** ASAM classes {BYTE, WORD, LONG, INT64, FLOAT16_IEEE, FLOAT32_IEEE, FLOAT64_IEEE}; every distinct size in `DATATYPE_SIZES` (1/2/4/8) has a mapping; the map is **derived** from `DATATYPE_SIZES` size-classes (not hand-listed) and **disjoint** from the summable-component / unmodeled-directive vocabularies. **Dropping a class → RED** (a hand-listed census would be vacuous; the invariant is the oracle) | `tests/test_a2l_alignment_sizing.py` |
| **TC-144** | LLR-ALIGN.2 walk (R-B) | Over the §2.5 layout dict + `axis_counts=[2]`, the cumulative-offset walk returns **16**; position-index-not-count preserved (token[2] = datatype, token[1] = position); an **ignore-alignment** mutation is asserted-against so it goes RED at `13` | `tests/test_a2l_alignment_sizing.py` |
| **TC-145** | LLR-ALIGN.3 map extraction | An `ALIGNMENT_WORD 2` line in `layout["lines"]` parses into `{WORD: 2}`; a class NOT declared defaults to align **1** (R-A packed); the `ALIGNMENT_*` line itself contributes **0** span (consumed into the map, not summed as a component) | `tests/test_a2l_alignment_sizing.py` |
| **TC-146** | LLR-ALIGN.2 helper | `align_up(off, a)` correctness: `align_up(0,4)=0`, `align_up(1,4)=4`, `align_up(6,4)=8`, `align_up(x,1)==x` (identity when packed) — the padding primitive in isolation. *(Fold into TC-144 if the architect does not factor a named helper.)* | `tests/test_a2l_alignment_sizing.py` |
| **TC-147** | LLR-ALIGN.4 R-A default | With NO `ALIGNMENT_*` lines, the walk == the batch-55 running sum **byte-for-byte** on the demo layouts (STD_AXIS layout → 25; FIX_AXIS FNC → 12). White-box mirror of AT-114; guards the packed path did not change | `tests/test_a2l_alignment_sizing.py` |
| **TC-148** | LLR-ALIGN.7 full-span-or-None | With an alignment map present, a genuinely-unmodeled non-alignment directive (`AXIS_RESCALE_X`/`RESERVED`/`SRC_ADDR_X`) still → `None`, not a summed span. White-box mirror of AT-116 | `tests/test_a2l_alignment_sizing.py` |
| **TC-149** | LLR-ALIGN.8 DoS clamp | The walk with a huge count + declared alignment returns `None` via a **pure-arithmetic** `MAX_A2L_DECODE_BYTES` comparison that includes padding (no `range`/list materialization); runs <1s without `@slow`. Mirror of batch-55 TC-138 extended for padding | `tests/test_a2l_alignment_sizing.py` |
| **TC-150** | LLR-ALIGN.6 R-C | The trailing-record-pad rule at helper level: the AT-119 layout returns the **architect-pinned** R-C value (`17` no-trailing / `24` trailing). White-box mirror of AT-119 | `tests/test_a2l_alignment_sizing.py` |
| **TC-151** | LLR-SUP.2 (supersede batch-55 TC-133b) | The batch-55 `test_tc133b_alignment_directive_forces_none` force-None assertions are **amended**: `with_alignment` → **14**, `trailing_align` → the R-C value (`13` no-trailing / `16` trailing); the packed `summable` → **13** assertion is RETAINED. Confirm no OTHER batch-55 test asserts an ALIGNMENT-bearing layout is `None` (swept: only TC-133b + `conftest.py:205` MOD_COMMON no-op) | edit `tests/test_a2l_inline_axis_length.py` (+ positive assertions live in `tests/test_a2l_alignment_sizing.py`) |
| **TC-152** | LLR-ALIGN.9 C-27 unfreeze (this batch) | `s19_app/tui/a2l.py` is **removed** from both `_ENGINE_PATHS` (`test_engine_unchanged.py`, `test_tui_directionb.py` tc031) with an `# UNFROZEN batch-56` marker; tc032 (`test_tui_a2l.py` freeze) stays green because no batch-56 test landed there | inspection of guard files |
| **TC-153** | US-P2b re-freeze | **POST-MERGE PR-B (guard-files only):** `a2l.py` re-inserted into both `_ENGINE_PATHS`; guards green; `git diff main -- s19_app/tui/a2l.py` empty | `test_engine_unchanged.py` + `test_tui_directionb.py` (post-merge) |

---

## Section D — Dual traceability (0 orphans)

**Behavioral (US → AT):**
- **US-ALIGN** → {AT-113 (padded value + consumer), AT-114 (batch-55 preservation, gate anchor), AT-115 (R-A isolation), AT-116 (full-span-or-None), AT-117 (boundary: pad=0), AT-118 (boundary: over-align), AT-119 (R-C decision), AT-120 (DoS)}
- **US-P2b** → AT-121 (post-merge re-freeze)

**Functional (LLR → TC):**
- LLR-ALIGN.1 census → TC-143 · LLR-ALIGN.2 walk → TC-144, TC-146 · LLR-ALIGN.3 map extraction → TC-145 · LLR-ALIGN.4 R-A default → TC-147 · LLR-ALIGN.5 R-B declared-value → (AT-118 + TC-144) · LLR-ALIGN.6 R-C → TC-150 · LLR-ALIGN.7 full-span-or-None → TC-148 · LLR-ALIGN.8 DoS → TC-149 · LLR-SUP.2 supersede → TC-151 · LLR-ALIGN.9 unfreeze → TC-152 · US-P2b re-freeze → TC-153

**Check:** every US has ≥1 AT (ALIGN: 8, P2b: 1). Every expected LLR has ≥1 TC. Every gate-blocking AT (113–120) observes THE VALUE / the None through `parse_a2l_file` (AT-113 additionally through the render consumer; AT-114 through the shipped demo view). **0 orphans.**

**Bidirectional surface-reachability:** input dimensions {declared multi-class ALIGNMENT (AT-113); alignment-free / packed (AT-114/AT-115); already-satisfied pad=0 (AT-117); over-align declared>natural (AT-118); trailing-pad geometry (AT-119); unmodeled directive + alignment (AT-116); oversized+alignment (AT-120); MOD_COMMON no-op (AT-114d)} are each exercised through `parse_a2l_file`. Output/deliverable {the **padded** byte `length`; the packed `length` unchanged; the `None`; the A2L row colour} is observed through the shipped surfaces (`parse_a2l_file` + `enrich_tags_and_render`). Layer B (black-box) covered by AT-113..120, with boundary (AT-117/118/119) and negative (AT-116 None) evidence; AT-113(b)/AT-114 observe the shipped view/row, not only the mechanism.

---

## Section E — Evidence checklist (QA self-audit)

- [✓] Acceptance criteria use Given/When/Then form (implicit in each AT "given fixture → when parse_a2l_file → then length == VALUE"; expandable on request).
- [✓] Test cases have explicit Expected values — `16`, `25`, `51`, `12`, `13`, `10`, `None`, `17`/`24` (R-C), `14` (supersede) — not vague "works".
- [✓] Edge cases: empty/None (unmodeled directive → None, AT-116), boundary (already-satisfied pad=0 AT-117; over-align AT-118; trailing-pad AT-119), invalid/robustness (fail-closed inherited from batch-55 + AT-116 no-raise), error/DoS (oversized+padding AT-120/TC-149).
- [✓] Regression checklist: **AT-114 (the gate anchor — 25/51/12 + 0 snapshot drift + 0 stress-fixture drift)** and the batch-55 TC-133b supersede (TC-151). Sweep confirmed TC-133b + `conftest.py:205` are the ONLY ALIGNMENT references in the suite.
- [✓] Exit criteria: gate-blocking set AT-113..120 green; AT-121/TC-153 post-merge; 0 snapshot drift; frozen guards green after re-freeze.
- [✓] No real PII / secrets — synthetic in-test A2L (via `_write_a2l`) + the public `case_00_public` demo fixture only.
- [✓] Test results left **blank** — this is a plan authored pre-implementation. Packed baselines (13/10/9) and TC-133b's current `None` were EXECUTED this session (C-35) to ground the oracle; the padded oracles (16/…) are hand-derived on top and **not yet tested** (the alignment walk does not exist yet). **I have NOT run AT-113..121.**
- [✓] Layer B: the output-producing story (US-ALIGN) is observed through the shipped `parse_a2l_file` surface AND the A2L-view row consumer (AT-113b / AT-114), with boundary (AT-117/118/119) + negative (AT-116 None) evidence.
- [✓] Bidirectional surface-reachability — see Section D.
- [✓] No unfilled template — every row is concrete; ids AT-113..121 / TC-143..153 are pinned; the only deliberately-deferred value is AT-119/TC-150 (pinned once §2 fixes R-C) and the post-merge AT-121/TC-153. No `<...>` placeholders.

> **Not signed off as passing.** These are pre-implementation acceptance criteria. The alignment-class census, the cumulative-offset walk, the `align_up` primitive, the map extraction, and the R-C trailing-pad rule do not exist yet. The packed baselines (13/10/9) and the TC-133b `None` flip are verified; the padded oracles (16 etc.) are hand-derived and not yet written or run.
