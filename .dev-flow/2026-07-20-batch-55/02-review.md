# 02 — Cross-agent review · batch-55 (P-1b inline-axis length summer)

**BLUF — PASS with folds, 0 blockers.** Three parallel reviewers (architect · qa · security) each independently executed probes against the real demo. **No blocker from any.** 5 MAJOR + 4 MINOR/positive findings, ALL fold-in refinements applied to `01-requirements.md` before Phase 3. The core design is sound: the derivation reproduces (25/51/12/None executed thrice independently), the taxonomy is complete for the corpus (full 13-tag component census), all wiring line-cites are accurate on the current `a2l.py`, and the DoS clamp location is provably sufficient (reverse-consumer sweep). Advancing to Phase 3.

## Two-layer review gate (blockers) — all clear
- (a) every story has a black-box AT ✓ · (b) every output-producing requirement names its observable deliverable + surface ✓ · (c) both traceability chains complete (0 orphans) ✓ · (d) ATs are genuinely black-box (drive `parse_a2l_file` / `enrich_tags_and_render`+`_a2l_tag_row_severity`, assert THE VALUE) ✓ (after the qa-M1 AT-108 correction).
- **Normative-keyword:** 0 modal `should`/`debería` inside any HLR/LLR **Statement** (all `shall`). Confirmed by architect + lint.

---

## Findings & dispositions

### architect (completeness / derivation / execution)
| id | sev | finding | disposition |
|----|-----|---------|-------------|
| PP1 | positive | **Component taxonomy COMPLETE** — full census over all 12 CURVE/MAP + 1 CUBOID demo layouts: only datatype-bearing components are `{AXIS_PTS_X/Y/Z, FNC_VALUES, NO_AXIS_PTS_X/Y/Z}`, all 7 in taxonomy; 0 unlisted/mis-dropped | recorded §2.5 census note |
| PP2-5 | positive | FNC=prod confirmed; ROW/COLUMN_DIR = ordering only (total invariant); `length is None` before summer (0 double-count); all wiring cites accurate (`:1263-1273`/`:1275`/`:1258-1261`/`:1121`/`:1030-1043`/`:13`/`:59`) | no change |
| **MAJ1** | **MAJOR** | **AT-105 (51) cannot discriminate an X/Y axis swap** — demo MAP's axes are both SBYTE(1), so 4+5 (addition) and 4·5 (commutative) are order-invariant; a swapped `axis_counts[0]↔[1]` stays green | **FOLDED** → TC-133 gains a size-asymmetric MAP oracle (AXIS_PTS_X SWORD n=4→8B, AXIS_PTS_Y SBYTE n=3→3B; swap → RED); AT-105 counterfactual note added |
| MIN2 | MINOR | demo CUBOID (13th in-family tag) unmentioned/unasserted (correctly excluded by char_type gate) | **FOLDED** → §2.5 note + AT-109(d) None-anchor |
| MIN3 | MINOR | LLR-P1b.1 "unclassifiable → None" is stricter than the probe's `continue`/skip (probe under-reports) | **FOLDED** → LLR-P1b.1 skip-vs-None clause made explicit (implement the LLR, not the probe) |

### qa (testability / acceptance discipline)
| id | sev | finding | disposition |
|----|-----|---------|-------------|
| **M-1** | **MAJOR** | **AT-108 oracle unfulfillable as worded** — a filled `length` does NOT flip row colour when `mem_map is None` (`validate_a2l_tags` → `memory_checked=False`); and `enrich_tags_and_render` doesn't emit `sev-*` (that's `_a2l_tag_row_severity`, app.py:342). Counterfactual couldn't fail | **FOLDED** → AT-108 rewritten: covering `mem_map` + apply `_a2l_tag_row_severity`; grey NEUTRAL→OK because length==25; reverted→NEUTRAL |
| **M-2** | **MAJOR** | **TC-135 "covers the 5 demo kinds {…}" is hand-listed** — the exact C-31 anti-pattern (vacuous input set; can't notice a 6th kind) | **FOLDED** → TC-135/LLR-P1b.3: derive `observed` from the parse, assert `observed ⊆ ALL_AXIS_KINDS`; keep code-derived set-algebra |
| **M-3** | **MAJOR** | **FIX_AXIS derivable branch has NO black-box VALUE AT** (distinct FNC-only layout shape); AT-107 mislabeled (§3 "FIX_AXIS=12" vs §4.9 "synthetic=13") | **FOLDED** → AT-107 retargeted to demo `ASAM.C.CURVE.FIX_AXIS.PAR_DIST`==12 (gate-blocking); synthetic=13 kept as AT-107b; labels reconciled |
| #1,#5,#7,#8 | positive | value-not-emptiness ✓; counterfactuals value-discriminating (9/29/146/non-None) ✓; DoS pure-arithmetic no-`@slow` ✓; **`_ENGINE_TEST_FILES` verified to exclude BOTH `test_a2l_multiline_headers.py` and `test_a2l_inline_axis_length.py`** (C-27 routing safe) | no change |

### security (untrusted-input / DoS / surface)
| id | sev | finding | disposition |
|----|-----|---------|-------------|
| **F1** | positive | **Single clamp SUFFICIENT** — reverse-swept every consumer of `tag["length"]`: the ONLY per-byte materialization is `_extract_raw_bytes:1037` `range(byte_size)`, and BOTH the summer length and the scalar `el×matrix` path funnel through it (`:1389`). All other consumers O(1)/O(log R): `validation/engine.py:123` (bisect), `range_index.py:96-104`, `report_filter.py:733`, `screens_directionb.py:895` — none iterate length bytes | **RECORDED** (this sweep). Keep clamp at `_extract_raw_bytes` before `:1037`; no other clamp site needed. A future length consumer that *allocates* must re-run this sweep |
| **F2** | **MAJOR** | **`int(str(mp),0)` base-0 is wrong** for an untrusted spec-decimal field — widens grammar (`0x`/`0o`/`0b`) AND raises on `'08'`/`'09'` (→ false-grey) | **FOLDED** → base-10 `int(str(mp).strip())` (LLR-P1b.2, TC-134, §1.3) |
| **F3** | **MAJOR** | **Guard must be `try/except` around the real `int()`, never `isdigit()`/regex** — `'08'.isdigit()`==True but `int('08',0)` raises; predicate/cast mismatch aborts the load (highest-likelihood realistic crash) | **FOLDED** → LLR-P1b.2/P1b.6, AT-110, TC-139 |
| **F4** | MINOR | huge-digit token (`'9'*5000`) raises `ValueError` on py3.11 (`set_int_max_str_digits`≈4300) — caught only if F3's try/except present; AT-111's 8-digit value doesn't exercise it | **FOLDED** → AT-110(iii) + TC-138 huge-digit vector |
| **F5** | positive | **No new external surface** — module constants + 2 private fns + 1 clamp + a wired block; no file-write/net/exec; length is an int (no markup sink fed file text) | no change |

---

## Increment plan (re-cut post-fold — C-21: AT set changed, re-reconciled)

The Phase-2 folds ADDED AT-107b and rewrote AT-108/TC-133/TC-135/TC-139 — the cut is re-reconciled so every AT (incl. the new/split ones) has an owning increment.

- **Inc-1 — UNFREEZE `a2l.py`** (LLR-P1b.7): remove `"s19_app/tui/a2l.py"` from BOTH `_ENGINE_PATHS` (`test_engine_unchanged.py:129`, `test_tui_directionb.py:5437`), replace the two NOTE blocks with an "UNFROZEN for batch-55" note. 2 files. Gate: tc031/tc032 green; a2l.py absent from both tuples. (Mirrors batch-54 Inc-1.)
- **Inc-2 — the summer** (LLR-P1b.1–6 + DoS.1 + SUP.1): in `a2l.py` — new constants (`_DERIVABLE_AXIS_KINDS`/`_EXTERNAL_AXIS_KINDS`/`ALL_AXIS_KINDS` near `:59`; `MAX_A2L_DECODE_BYTES` near `:13`), `_record_layout_full_span`, `_inline_axis_counts` (base-10 try/except), the `_extract_raw_bytes` clamp (before `:1037`), the post-axis-walk length block (after `:1273`); NEW `tests/test_a2l_inline_axis_length.py` (TC-133..139, AT-104..111 + 107b); amend `tests/test_a2l_multiline_headers.py` AT-102 (LLR-SUP.1/TC-140); REQUIREMENTS.md:402-405 prose (§6.5 A1). File budget: `a2l.py` + new test file + `test_a2l_multiline_headers.py` + `REQUIREMENTS.md` = **4 files** (facade untouched — private symbols, §7). Gate: all gate-blocking AT green; frozen dual-guard (C-27) both green; full A2L suite green.
- **PR-B (post-merge)** — RE-FREEZE `a2l.py` (LLR-P2b.1 / AT-112 / TC-142): guard-files-only.

## Carries into Phase 3
- Snapshot drift EXPECTED on the 8 inline CURVE/MAP A2L rows → canonical-CI regen only (local FORBIDDEN); predict per-cell (C-22).
- C-27 dual-guard (source + test-file) at every increment AND Phase-4.
- Phase-3 must implement the LLR wording (full-span-or-None, base-10 try/except, cap-before-range), NOT the reference probe's looser branches (arch-MIN3, sec-F3).
