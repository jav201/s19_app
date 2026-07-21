# 03 — Phase-3 increments · batch-56 (alignment-aware padding sizing)

> PR-A implemented in 3 increments (each ≤5 files), independently code-reviewed (APPROVE, 0 HIGH/0 MED). RED→GREEN evidence per increment. Tree committed after review.

## Inc-1 — UNFREEZE (LLR-A56.6 / TC-152)
- **What:** removed `"s19_app/tui/a2l.py"` from BOTH `_ENGINE_PATHS`; swapped the two NOTE blocks to "UNFROZEN for batch-56 … RE-FREEZE in PR-B".
- **Files (2):** `tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py`.
- **Tests:** frozen dual-guard `-k "engine or tc031 or tc032"` → **7 passed** (a2l.py still == main → enabling-only). a2l.py in `_ENGINE_PATHS`: **0/0**.

## Inc-2 — alignment-aware walk (LLR-A56.1..5; AT-113..120,122; TC-143..150)
- **What (`s19_app/tui/a2l.py`):** `_DATATYPE_ALIGNMENT_DIRECTIVE` map (key-set==`DATATYPE_SIZES`) + `_ALIGNMENT_DIRECTIVES`; `align_up(o,a)` short-circuits `a<=1` before the modulo (no ZeroDivisionError); `_collect_declared_alignments` fail-closed on non-int AND non-positive (`<1`); `_record_layout_full_span` rewritten as a cumulative-offset walk (skip `ALIGNMENT_*`; `offset=align_up(offset, class-align)` then `+= size*count`; over-cap→None; no trailing pad; MOD_COMMON never read).
- **Files (2):** `s19_app/tui/a2l.py`, `tests/test_a2l_alignment_sizing.py` (NEW, imports `_write_a2l`/`_axis_meta`/`_demo_char` from the batch-55 module).
- **Tests:** new suite **17 passed**. **AT-113 pre-fix RED** (exec of `main`'s force-None impl) → `None`/grey; **post-fix** → 16 (packed 13). Oracles verified (none adjusted): AT-114 demo 25/51/12/None; AT-115 16>13 ∧ without==13; AT-116 unmodeled→None; AT-117→10; AT-118 over-align→16 (RED 12); AT-119→17 (RED 24); AT-120 DoS→None fast; AT-122 `x`/`0`/`-4`→None no-exc; TC-143 census derived (drop OR mis-map→RED).

## Inc-3 — supersede + docs (LLR-SUP56.1 / TC-151; AMD-2)
- **What:** amended `test_tc133b_alignment_directive_forces_none` (non-frozen) → `with_alignment`=14, `trailing_align`=13, `summable`=13 retained; intent docstring → "alignment-aware padding (batch-56)", false-green anchor → AT-116. Appended the batch-56 alignment sentence to `REQUIREMENTS.md` CURVE/MAP length prose.
- **Files (2):** `tests/test_a2l_inline_axis_length.py`, `REQUIREMENTS.md`.
- **Tests:** combined `test_a2l_alignment_sizing.py + test_a2l_inline_axis_length.py` → **35 passed**; a2l consumers (`test_tui_a2l.py` tc032 oracle, `test_a2l_record_layout_length.py`, `test_validation_a2l.py`) → **26 passed** (no regression).

## Independent code review (code-reviewer) — APPROVE
- **0 HIGH, 0 MED, 1 LOW** (F1: AT-114's MOD_COMMON→26 counterfactual is a comment not an executable mutation — accepted, the collector structurally cannot read MOD_COMMON so `==25` IS the discriminating guard; no change).
- Reviewer's own runs: 35 passed + 7 guards. Hand-traced every gate oracle; confirmed both security branches fail-closed; R-A (MOD_COMMON never read) holds; tests non-vacuous (TC-143 derived, named counterfactuals); tc032-frozen file untouched.

## Frozen dual-guard (C-27)
- `tests/test_tui_a2l.py` (tc032) NOT in the diff; new tests only in `test_a2l_alignment_sizing.py`; a2l.py out of both `_ENGINE_PATHS`. Guards 7/7.

## Test ledger
- New file: +17. Supersede: 0 net (rewrite-in-place, 2 assertions changed value). Base current-main: 1772 (b59 Phase-4). Post batch-56: 1772 + 17 = 1789 (gate suite confirms; the 19 pre-existing tc016s snapshot drifts are the b58/b59 canonical-CI carry, NOT batch-56).

## Gate (self-approved, autonomous)
- Coverage: every AT-113..122 (gate 113..120,122) + TC-143..152 realized to a distinct on-disk node (C-18); 0 orphans.
- Certainty: AT-113 counterfactual RED shown; both security branches have failing-input ATs; TC-143 derived-set oracle.
- Evidence: code-reviewer independent run + hand-traced oracles + this packet's cited counts.
- Axis met → advance to Phase 4 (orchestrator-owned gate suite in flight, C-25).
