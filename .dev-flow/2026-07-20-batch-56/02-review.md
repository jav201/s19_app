# 02 — Cross-agent review · batch-56 (alignment-aware padding sizing)

> Phase 2. Three independent reviewers (architect · qa-reviewer · security-reviewer) over `01-requirements.md` + `01b-qa-catalog.md`. **BLUF: no redesign needed — 0 HIGH, 0 design blockers.** All architect "blockers" are id/registry RECONCILIATION between the two Phase-1 docs (which §4.9/§5.2 always intended the orchestrator to fold); plus one REAL security bug (zero/negative-alignment division-by-zero) and two coverage gaps (malformed-value AT, over-align/DoS ATs missing from 01-req's HLR). This document folds all findings into a single canonical AT/TC registry and records the resolutions. Gate: **self-approved (autonomy grant), Certainty axis met after fold → Phase 3.**

---

## 1. Findings ledger (consolidated, deduped)

| # | Sev | Source | Finding | Resolution |
|---|-----|--------|---------|------------|
| B1 | blocker | architect, qa-M2, sec-min | `AT-113` has two oracles across the docs (single-class 8/7 vs multi-class 16/13) | **Canonical = multi-class 16/13** (stronger: 2 alignment classes, 3 pad bytes, ends max-aligned → R-C-independent; all 3 reviewers verified 16). 8/7 demoted to a secondary unit case in TC-144. §3 AT-113 rewritten. |
| B2 | blocker | architect | `AT-115`/`AT-117` mean different things in each doc | **Canonical id→meaning fixed** (table §2): AT-115 = R-A isolation; AT-117 = pad=0 boundary. |
| B3 | blocker | architect, qa-min | LLR id schemes disjoint (`LLR-A56.n` vs `LLR-ALIGN.n`) | **US/HLR/LLR ids = the requirements doc's `*-A56` scheme** (it owns statements per §4.9); the catalog's `LLR-ALIGN.x` TCs re-peg onto `LLR-A56.x` (§2 mapping). |
| M1 | major | architect | New test file → PR-A touches 6 files, busts §2.4 ≤5 | **Resolved by re-cutting into 3 increments** (§3), each ≤5 files. Keep the NEW `tests/test_a2l_alignment_sizing.py` (cohesive alignment suite). No waiver needed. |
| M2 | major | architect | 01-req HLR under-covers AT-118 (over-align R-B) + AT-120 (DoS) | **Adopt the full gate set AT-113..120 + AT-122.** §3 acceptance expanded. |
| **M3** | **major** | **security** | **`ALIGNMENT_WORD 0`/negative → `align_up(o,0)` → `o % 0` ZeroDivisionError, NOT caught by `(ValueError, TypeError)`** | **Real bug. Fold a `shall`:** LLR-A56.2 collector returns `None` if `int(token[1]) < 1` (fail-closed on non-positive); LLR-A56.5 `align_up` guards `a <= 1` before the modulo. New **AT-122** + TC-145/TC-146 assertions. |
| M4 | major | qa-M1 | No black-box AT for a malformed alignment VALUE (`ALIGNMENT_WORD x`→None); AT-116 is unmodeled-directive, not this branch | **New AT-122** (hostile alignment value: non-int `x`, zero, negative → `length is None`, no exception, via `parse_a2l_file`). Merges M3+M4 into one negative-alignment gate AT. |
| M5 | major | qa-M4 | NEW test file orphans `_write_a2l`/`_axis_meta` (they live in the batch-55 module) | **Import `_write_a2l`/`_axis_meta` from `tests/test_a2l_inline_axis_length.py`** (or promote to `conftest.py`); never silently duplicate. Pinned in TC target notes. |
| M6 | major | qa-M3 | AT-115 semantic collision loses the explicit MOD_COMMON=26 counterfactual | **Keep AT-115 = R-A isolation, AND pin `26` as AT-114's NAMED RED mutation** ("MOD_COMMON-honored → CURVE.STD_AXIS==26"). Makes R-A oracle-preservation non-vacuous. |
| m1 | minor | architect | Stale line anchors (`extract_record_layouts` at `:620-635` not `:606-621`; guard entries drifted to `:5452`/`:5448`) | **Phase-3 uses the corrected lines** (§4). Symbols all correct; only refs drifted. |
| m2 | minor | qa-C31 | TC-143 census catches a DROPPED key but not a MIS-mapping (FLOAT16→WORD keeps key-set equal) | **TC-143 also asserts** `set(_DATATYPE_ALIGNMENT_DIRECTIVE.values()) == {7 ALIGNMENT_* names}`, expectation derived by iterating `DATATYPE_SIZES` size-classes (not hand-listed). Drop OR mis-map → RED. |
| m3 | minor | qa | LLR-A56.5 (R-B declared-value) has no distinct TC node ("AT-118+TC-144") | **Accepted:** AT-118 (over-align 16≠12) is the load-bearing node; noted so it is NOT counted an orphan (C-18). |
| m4 | minor | qa | AT-113(b) C-12 chain must be ONE node over the parse-produced tag | **Pinned:** AT-113 drives `parse_a2l_file` → feeds THAT tag to the UNMODIFIED `enrich_tags_and_render`/`_a2l_tag_row_severity` in the same test fn; asserts grey(None)→non-grey(filled). |
| m5 | minor | sec | DoS AT-120 only in the catalog, not 01-req HLR | **Resolved by the §4.9 splice** (catalog authoritative); AT-120 is in the canonical gate set below. |

**Modal-keyword check (architect):** 0 `should` inside any normative statement. ✓
**C-35 core assumption (architect):** `layout["lines"]` carries the raw RECORD_LAYOUT body incl. `ALIGNMENT_*` — confirmed `a2l.py:631` (`"lines": lines`, unfiltered). ✓
**Upward traceability (architect):** every HLR→US, every LLR→HLR clean. ✓
**Supersede math (all 3):** `with_alignment`→14, `trailing_align`→13, `summable`→13 retained. ✓
**MOD_COMMON 25→26 (architect+qa):** arithmetically correct & load-bearing (R-A layout-local scope is what preserves 25). ✓
**conftest.py:205 `ALIGNMENT_BYTE 1` = no-op (qa):** align 1 → 0 pad; `large_a2l` 0 drift either way. ✓

---

## 2. CANONICAL AT / TC registry (the §4.9 splice — authoritative)

**US/HLR/LLR ids** = requirements doc (`US-A56`, `US-P2b56`, `HLR-A56`, `HLR-P2b56`, `LLR-A56.1..6`, `LLR-SUP56.1`, `LLR-P2b56.1`). **AT/TC ids** = catalog superset, reconciled below. C-12 chain head = `parse_a2l_file(Path)`.

### Black-box AT (US → AT) — 0 orphans
| AT | Story | Asserts THE VALUE through `parse_a2l_file` | Named RED counterfactual | Gate? |
|----|-------|--------------------------------------------|--------------------------|-------|
| **AT-113** | US-A56 | multi-class CURVE (`NO_AXIS_PTS_X UBYTE / ALIGNMENT_WORD 2 / ALIGNMENT_LONG 4 / AXIS_PTS_X UWORD / FNC_VALUES ULONG`, axis=[2]) → `length==16` (packed 13); **(b)** same parsed tag → `enrich_tags_and_render`/`_a2l_tag_row_severity` → row non-grey (memory-checkable) | ignore ALIGNMENT → 13; drop one class pad → 14/15; pre-fix force-None → None (grey) | ✅ |
| **AT-114** | US-A56 (R-A regression **anchor**) | demo: `CURVE.STD_AXIS==25` ∧ `MAP.STD_AXIS.STD_AXIS==51` ∧ `CURVE.FIX_AXIS.PAR_DIST==12` ALL unchanged; `large_a2l` + A2L snapshots **0 drift** | **MOD_COMMON-honored → CURVE.STD_AXIS==26** (named); or natural-align-by-default → 26 | ✅ anchor |
| **AT-115** | US-A56 (R-A isolation) | same components WITH vs WITHOUT the ALIGNMENT lines → `with==16 > without==13` ∧ `without==13` | ungated pad (padding without a declared `ALIGNMENT_*`) → without==16, `without==13` fails | ✅ |
| **AT-116** | US-A56 (full-span-or-None) | alignment-bearing CURVE + a genuinely-unmodeled non-alignment directive (`AXIS_RESCALE_X`/`RESERVED`/`SRC_ADDR_X`) → `length is None`, no exception | treat unknown 2-token line as 0-pad & sum past it → fabricated non-None span | ✅ |
| **AT-117** | US-A56 (boundary pad=0) | all-WORD layout (`UWORD×3`, axis=[2]) + `ALIGNMENT_WORD 2` declared but offsets already aligned → `length==10` (== packed) | pad unconditionally (phantom byte when already aligned) → >10 | ✅ |
| **AT-118** | US-A56 (boundary over-align, R-B) | FIX_AXIS FNC layout (`UBYTE`,`ULONG`,axis=2) + `ALIGNMENT_LONG 8` over-declared (>natural 4) → `length==16` (`rup(1,8)=8; +8`) | use natural size 4 not declared 8 → `rup(1,4)=4;+8=12`≠16 | ✅ |
| **AT-119** | US-A56 (R-C = no trailing pad) | `UBYTE`,`A_UINT64`,`UBYTE`,`ALIGNMENT_INT64 8`,axis=[1] → `length==17` (last component's end, NO trailing pad) | trailing pad-to-max → `align_up(17,8)=24` (the RED that signals the wrong R-C reading) | ✅ |
| **AT-120** | US-A56 (DoS) | oversized axis/alignment over `MAX_A2L_DECODE_BYTES` → `length is None`, completes fast (arithmetic cap, no alloc, no `@slow`) | cap dropped or padding after cap-check → hang/OOM or absurd non-None | ✅ |
| **AT-122** | US-A56 (hostile alignment value) | `ALIGNMENT_WORD x` (non-int), `ALIGNMENT_WORD 0`, `ALIGNMENT_WORD -4` → each `length is None`, **no exception** (esp. no `ZeroDivisionError`) | `int()` outside try/except, or non-positive alignment reaching `align_up` → crash on load | ✅ |
| **AT-121** | US-P2b56 | after PR-B, frozen-file guards green ∧ `git diff main -- a2l.py` empty | a2l.py ≠ main → guard RED | ❌ post-merge |

**Gate-blocking set (main PR):** AT-113, 114, 115, 116, 117, 118, 119, 120, 122. **Post-merge:** AT-121.

### White-box TC (LLR → TC) — 0 orphans
| TC | Backs LLR | Asserts | Target file |
|----|-----------|---------|-------------|
| TC-143 | LLR-A56.2 (map, C-31) | `set(map)==set(DATATYPE_SIZES)` AND `set(map.values())=={7 ALIGNMENT_* names}`, both DERIVED (not hand-listed); drop OR mis-map → RED | `tests/test_a2l_alignment_sizing.py` (NEW) |
| TC-144 | LLR-A56.1 (walk) | multi-class layout → 16; single-class `ALIGNMENT_WORD 2`,[2] → 8 (secondary); token[2]=datatype/token[1]=position preserved; ignore-alignment mutation → 13 | NEW |
| TC-145 | LLR-A56.2 (collector) | `ALIGNMENT_WORD 2`→`{WORD:2}`; undeclared class→align 1; the `ALIGNMENT_*` line contributes 0 span; **`x`/`0`/`-4` → None (fail-closed, non-positive guard, M3/M4)** | NEW |
| TC-146 | LLR-A56.1 (align_up) | `align_up(0,4)=0`,`(1,4)=4`,`(6,4)=8`,`(x,1)=x`; **`(o,0)` and `(o,-4)` never raise (guarded a<=1)** | NEW |
| TC-147 | LLR-A56.3 (packed) | no `ALIGNMENT_*` → byte-for-byte batch-55 sum (STD_AXIS layout→25; FIX_AXIS FNC→12) | NEW |
| TC-148 | LLR-A56.4 (MOD_COMMON excl + full-span-or-None) | alignment map present + unmodeled directive → None; collector reads only `layout["lines"]`, never MOD_COMMON | NEW |
| TC-149 | LLR-A56.5 (DoS) | huge count + alignment → None via pure-arithmetic cap incl. padding; <1s, no `@slow` | NEW |
| TC-150 | LLR-A56.1 (R-C) | AT-119 layout → 17 (no trailing pad); 24 is the counterfactual | NEW |
| TC-151 | LLR-SUP56.1 (supersede TC-133b) | amend `with_alignment`→14, `trailing_align`→13; retain `summable`→13; §6.5 Before→After | edit `tests/test_a2l_inline_axis_length.py` (non-frozen) |
| TC-152 | LLR-A56.6 (unfreeze) | a2l.py removed from BOTH `_ENGINE_PATHS`; tc032 (`test_tui_a2l.py`) still green (no batch-56 test landed there) | inspection of guard files |
| TC-153 | LLR-P2b56.1 (re-freeze) | POST-MERGE PR-B: a2l.py re-inserted both `_ENGINE_PATHS`; guards green; `git diff main -- a2l.py` empty | guard files (post-merge) |

**NEW-file helper reachability (M5):** `tests/test_a2l_alignment_sizing.py` imports `_write_a2l`, `_axis_meta` from `tests/test_a2l_inline_axis_length.py` (batch-55) — no duplication.

---

## 3. Re-cut increment plan (C-21 — the AT set changed: +AT-119/120/122)

PR-A, 3 increments, each ≤5 files:
- **Inc-1 — UNFREEZE (LLR-A56.6 / TC-152).** Remove `"s19_app/tui/a2l.py"` from both `_ENGINE_PATHS` + swap the two NOTE blocks to "UNFROZEN for batch-56". Files: `tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py` (2). Guards green (a2l.py still == main). RED counterfactual N/A (enabling).
- **Inc-2 — the alignment-aware walk (LLR-A56.1..5 / AT-113..120,122 / TC-143..150).** `s19_app/tui/a2l.py`: `_DATATYPE_ALIGNMENT_DIRECTIVE` map + `_collect_declared_alignments` (fail-closed on non-int AND non-positive) + `align_up` (guards a<=1) + rewrite `_record_layout_full_span` as the cumulative-offset walk (no trailing pad; MOD_COMMON never read; DoS cap inside walk). NEW `tests/test_a2l_alignment_sizing.py` (all positive + negative TCs, imports helpers from the batch-55 module). Files: 2. Counterfactuals: AT-113 ignore-alignment→13 (RED pre-fix = None); AT-119 no-trailing 17 vs 24.
- **Inc-3 — supersede + docs (LLR-SUP56.1 / TC-151 + AMD-2).** `tests/test_a2l_inline_axis_length.py` TC-133b amend (None→14/13/13, §6.5) + `REQUIREMENTS.md:402-409` prose append. Files: 2.
- **PR-B (post-merge, separate) — re-freeze (LLR-P2b56.1 / TC-153 / AT-121).** Re-insert a2l.py into both `_ENGINE_PATHS`; guard files only.

**Corrected line anchors for Phase 3 (m1):** `extract_record_layouts` `a2l.py:620-635` (`"lines": lines` at `:631`); guard entry-2 `tests/test_tui_directionb.py:5452` (NOTE `:5448`). Verify exact lines at edit time (do not trust the drifted 01-req cites).

---

## 4. Gate decision

**Self-approved (autonomy grant) → Phase 3.** Axis assessment:
- **Coverage:** every US→AT and LLR→TC chain exists, 0 orphans (§2). ✓
- **Certainty:** the fold closed every named gap — B1/B2/B3 (id reconciliation), M2 (missing gate ATs), M3 (the real zero-div bug → LLR `shall` + AT-122), M4/M5/M6. Every gate AT names a RED counterfactual through `parse_a2l_file`. ✓
- **Evidence:** each resolution cites the reviewer finding + file:line; the canonical registry is on disk here. ✓

No unmet axis remains after the fold → `approve`. Iteration count Phase 2 = 1 (single fold, no re-review needed — all blockers were reconciliation with unambiguous resolutions). Proceed to Phase 3.
