# PLAN — 2026-07-20-batch-55 · P-1b inline-axis length summer

> Living compendium. Updated at every gate + significant checkpoint. BLUF-first.

## BLUF / where we are
- **Objective:** derive a correct byte `length` for CURVE/MAP CHARACTERISTICs (today `length=None`) by summing the RECORD_LAYOUT on-disk span × inline axis point-counts. Consumes batch-54's `axis_meta` (`max_axis_points` STR + `external` flag). Surface: `parse_a2l_file` → the A2L view (a filled length promotes a grey/not-checked row to memory-checkable).
- **Phase:** 0 (story intake / DoR) — **in progress**.
- **Route:** full /dev-flow (core-parser change on the frozen `a2l.py` under a sanctioned unfreeze; broad regression surface across all CHARACTERISTIC length output).
- **Branch:** `claude/p1b-inline-axis-length-e90fee` @ `a58d4e0` (= origin/main tip, RC-1 clean).

## Standing authorization (operator, 2026-07-20, per-batch — NOT carried)
- **Autonomy:** end-to-end autonomous; self-approve every gate with a named Coverage/Certainty/Evidence axis check.
- **Merge:** GRANTED, gated on green CI + a FINAL independent PR-level qa-reviewer pass over the whole diff vs `main` (dual traceability · 0 OTHER-engine-frozen diffs · no C-26 cross-increment regression · every carry discharged). HIGH finding → blocks + returns to operator. Then /dev-flow-sync.
- **a2l.py unfreeze:** APPROVED for this batch; RE-FREEZE as post-merge PR-B (same-PR re-freeze self-trips the vs-main guard).
- **Decision recording:** FULL — every un-asked decision → this log + state.json + 05-postmortem + vault.

## RC-1 (base currency) — PASS
- Base = origin/main tip `a58d4e0` (batch-54 re-freeze, PR #103). merge-base == HEAD == origin/main → no rebase.
- **Already-shipped check = NOT shipped:** executed `parse_a2l_file(ASAP2_Demo_V161.a2l)` → every CURVE/MAP `length=None`.
- **Prerequisite CONFIRMED LIVE (batch-54):** `axis_meta` populated —
  - `ASAM.C.CURVE.STD_AXIS` → `{max_axis_points:'8', external:False}` (oracle 25 B)
  - `ASAM.C.CURVE.COM_AXIS` → `external:True` (must stay grey → length None)
  - `FIX_AXIS.*` → `external:False` (derivable)

## Verified ground (executed 2026-07-20, this session)
- `parse_a2l_file` returns a dict: keys `tags`, `record_layouts_by_name`, `compu_methods_by_name`, ... (75 tags, 24 record layouts).
- Each tag dict carries: `record_layout_name`, `deposit`, `axis_meta` (list of `{max_axis_points:str, external:bool, header_tokens:[...]}`), `char_type`, `length` (currently None for arrays).
- `record_layouts_by_name[name]` is a dict `{name, tokens, lines, byte_order}`. **`lines`** = list of raw strings, one per on-disk component:
  - `NO_AXIS_PTS_X 1 UBYTE ...` · `AXIS_PTS_X 2 SBYTE ...` · `FNC_VALUES 3 SWORD ...`
  - Per line split on whitespace: `tokens[0]`=component, `tokens[1]`=**POSITION INDEX (discard for size)**, `tokens[2]`=**DATATYPE**.
- **CURVE.STD_AXIS (RL.CURVE.SWORD.SBYTE.DECR), max_axis_points=8:** `1×UBYTE + 8×SBYTE + 8×SWORD = 1 + 8 + 16 = 25 B` ✓ (batch-50 oracle).

## Design seed (batch-50 §7 + 02-review, VERIFIED — reuse verbatim where cited)
- `record_layout_full_span(layout, axis_counts)` reads `layout["lines"]` (NOT the scalar `_resolve_record_layout`). Datatype = `tokens[2]`; the `1/2/3` are position indices (naive reader → 9 not 25 — architect MAJOR-1).
- `_inline_axis_counts` gated on `_DERIVABLE_AXIS_KINDS={STD_AXIS,FIX_AXIS}`; live constants `ALL_AXIS_KINDS`/`_EXTERNAL_AXIS_KINDS` + completeness assert (`ALL == _DERIVABLE|_EXTERNAL`) + non-empty guard (qa M3, C-31 input-set-is-an-oracle).
- **Safety contract: full-span-or-None** — any unresolved component (unknown datatype, unknown axis count, external axis) → `length=None`; never under-report.
- Post-axis-walk length pass (R2 ordering); `axis_meta` build site is a touched symbol (C-26).
- **Oracle values:** STD_AXIS CURVE = 25 B; real inline MAP `ASAM.C.MAP.STD_AXIS.STD_AXIS` (axes 4&5) = 51 B (NOT 146 — 146 is synthetic `[8,8]`).
- **Security R2:** clamp the raw-decode path (`_extract_raw_bytes` `range(byte_size)`) with `MAX_A2L_DECODE_BYTES` (≈1–16 MiB); covers the pre-existing scalar path too. `.get()` not subscript for `DATATYPE_SIZES`; length-guard the split tokens.
- **C-35:** EXECUTE the summer over the real demo at draft time (Phase 1/2), not read code + fixture separately.
- **max_axis_points is a STR → cast to int.**

## Stories (Phase-0 DoR) — see §Intake below
| ID | Title | Class |
|----|-------|-------|
| US-P1b | CURVE/MAP inline-axis length shown correctly | READY |
| US-DoS | Decode-path byte cap (R2) so length derivation can't trigger unbounded work | READY |
| US-P2b | Re-freeze a2l.py post-merge (PR-B) | READY (post-merge) |
| (carry) | Direct multi-line surface-limit AT (batch-54 Phase-4 flag) | OUT — tangential to the summer |

## Roadmap (provisional; firmed at Phase 2 increment cut)
1. Inc-1 — UNFREEZE a2l.py (2 guard files) [mirror batch-54 Inc-1].
2. Inc-2 — the summer: `record_layout_full_span` + `_inline_axis_counts` + DATATYPE size map reuse + DoS clamp + the length pass wiring in `a2l.py`; facade re-export; NEW test file (synthetic-first + demo oracle + external-stays-None + DoS @slow + C-26 census).
3. PR-B (post-merge) — re-freeze a2l.py.

## Decisions log (human mirror of state.json)
- **2026-07-20 · kickoff:** autonomous + self-merge; a2l.py unfreeze YES (re-freeze PR-B); full recording. RC-1 clean @ a58d4e0; already-shipped=NOT shipped; prerequisite live. (Operator AskUserQuestion.)
- **2026-07-20 · Phase-0 gate:** DoR self-approved — 3 stories READY (US-P1b/US-DoS/US-P2b), carry OUT (multi-line surface-limit AT). Coverage/Certainty/Evidence met.
- **2026-07-20 · Phase-1 gate:** requirements self-approved. architect C-35 probe reproduced 25/51/12/None over the real demo; 3 HLR / 11 LLR; qa AT-104..112 / TC-133..142; 0 orphans; lint clean. Two autonomous decisions: **(D1)** gate-blocking set = AT-104..111 (qa registry; architect's 104-106 understated no-regression/malformed/DoS). **(D2)** summer symbols **PRIVATE** `_record_layout_full_span`/`_inline_axis_counts`, no facade — matches `_resolve_record_layout`/`_infer_length_characteristic` precedent (C-3/C-11). **Cross-batch catch:** batch-54 `test_at102_curve_map_length_stays_none` (non-frozen) flips RED under the summer → LLR-SUP.1/TC-140 §6.5 amendment (None→25/51). §6.5 A1 = REQUIREMENTS.md:402-405 prose.

- **2026-07-20 · Phase-2 gate:** triple review self-approved, 0 blockers. 5 MAJOR folded: **arch-MAJ1** (AT-105 can't discriminate X/Y swap → TC-133 size-asymmetric MAP oracle); **qa-M1** (AT-108 oracle unfulfillable → covering-map + `_a2l_tag_row_severity`); **qa-M2** (TC-135 hand-listed census → derive from parse); **qa-M3** (FIX_AXIS no VALUE-AT → AT-107 retargeted to demo==12 + AT-107b synthetic=13); **sec-F2** (base-0→base-10 cast) + **sec-F3** (try/except not isdigit). Positives recorded: **sec-F1** single-clamp-sufficient (reverse-consumer sweep); **arch-PP1** taxonomy complete (13-tag census); **sec-F5** no new surface. Gate-blocking = AT-104/105/106/107/107b/108/109/110/111. C-21 re-cut applied.

- **2026-07-20 · Phase-3 Inc-1 APPROVED:** a2l.py unfrozen (2 guard files), 11 guard tests pass exit0; inline review (diff = exactly the 2 tuple removals + NOTE swaps). 
- **2026-07-20 · Phase-3 Inc-2 (in gate):** summer implemented in a2l.py (180 insertions, additive; private symbols no facade) + new `tests/test_a2l_inline_axis_length.py` + AT-102 supersession + REQUIREMENTS.md prose. 5 verify runs green; C-35 probe reproduced 25/51/12/None/None, 0 false-None. **Two Phase-3 catches:** (1) dev fail-loud caught my Phase-2 fold error — AT-110/TC-139 `'08'→None` was a **C-36 phantom** (only true under rejected base-0; base-10 makes `'08'→8 valid`); corrected §4.9 + §6.5 A3. (2) code-review F1 (MEDIUM) — ALIGNMENT_* 2-token directives silently skipped → under-report/false-green on real A2Ls; **operator AskUserQuestion 2026-07-20 → "Safe now + alignment-aware follow-up"**: force-None guard this batch (§6.5 A4, R4) + **batch-56 backlog item** for alignment-aware sizing. Dev applying the guard + TC-133b now.

## Increment plan (Phase-3, C-21 re-reconciled)
- **Inc-1** — UNFREEZE `a2l.py` (LLR-P1b.7): remove from both `_ENGINE_PATHS` (`test_engine_unchanged.py:129`, `test_tui_directionb.py:5437`) + NOTE blocks. **2 files.** Gate: tc031/tc032 green.
- **Inc-2** — the summer (LLR-P1b.1–6 + DoS.1 + SUP.1): `a2l.py` (constants + `_record_layout_full_span` + `_inline_axis_counts` base-10 try/except + `_extract_raw_bytes` clamp + post-axis-walk block) + NEW `tests/test_a2l_inline_axis_length.py` + amend `tests/test_a2l_multiline_headers.py` (AT-102) + `REQUIREMENTS.md:402-405`. **4 files** (facade untouched — private symbols). Gate: gate-blocking AT green; C-27 dual-guard green; A2L suite green.
- **PR-B (post-merge)** — RE-FREEZE `a2l.py` (LLR-P2b.1/AT-112).

## Requirements summary (Phase 1 locked)
- **HLR:** HLR-P1b (`R-A2L-008`) · HLR-DoS (`R-A2L-014`) · HLR-P2b (`R-A2L-015`).
- **LLR (11):** P1b.1 `_record_layout_full_span` · P1b.2 `_inline_axis_counts`+external gate · P1b.3 census constants (C-31) · P1b.4 post-axis-walk wiring (R2, insert @ a2l.py:1273) · P1b.5 no-regression · P1b.6 fail-closed · P1b.7 unfreeze PR-A · DoS.1 `MAX_A2L_DECODE_BYTES`=1 MiB clamp @ `_extract_raw_bytes:1037` · SUP.1 supersede batch-54 AT-102 · P2b.1 re-freeze PR-B.
- **Wiring (verified):** new length pass after the `axis_meta` loop (`a2l.py:1273`), before `effective_byte_order` (`:1275`); guard `char_type∈{CURVE,MAP} ∧ length is None`; scalar/VALUE path at `:1258-1261` untouched.
- **Component taxonomy:** NO_AXIS_PTS_*/NO_RESCALE→1 · AXIS_PTS_X/Y/Z→n_x/n_y/n_z · FNC_VALUES→prod(axis_counts) · any other/unknown datatype/missing count→**None** (full-span-or-None). datatype=token[2] (token[1]=position index).

## Risks / watch-items
- **FNC_VALUES dimensionality** — CURVE scales by axis_x count; MAP by axis_x × axis_y. Component taxonomy (which line scales by which axis) is the core design question for Phase 1; get it from the real record layouts as oracle.
- **Full-span-or-None discipline** — the AT that proves it is the external-COM_AXIS-stays-None case (false-green proof, C-10 branch-AT).
- **Frozen dual-guard (C-27)** — a2l.py unfrozen this batch; run BOTH source + test guards; route new tests to a NON-frozen file.
- **Snapshot drift** — a filled length may change A2L-view render → predict per-cell (C-22); regen is canonical-CI-only.
- **Iteration cap** — soft 3/phase.

## Out of scope
- MEASUREMENT length (absent/deferred in batch-54). COM_AXIS/AXIS_PTS_REF external-axis length (stays None by contract). Scalar-VALUE length (P-1, already shipped #93). Multi-image / flow-builder carries.

## Test ledger
- Base (post batch-54): 1652 passed. Δ tracked at each increment.
