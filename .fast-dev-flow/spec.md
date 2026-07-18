# fast-dev-flow spec — A2L missing-length no longer flagged as ERROR (engine-unfreeze)

- **Date:** 2026-07-18
- **Batch:** a2l-missing-length-fix
- **Flow:** /fast-dev-flow (engine-unfreeze increment included)
- **Language:** English
- **Run mode / merge:** Autonomous through self-merge (operator-authorized this batch; standing auth is per-batch and does NOT carry). Surface any HIGH finding or scope creep immediately.
- **Status:** Phase A — spec (autonomy granted; no external gate)

---

## 1. Objective

Stop the A2L view from painting a **spec-valid** record RED when its byte length cannot be
*derived* from the file. Under ASAM MCD-2 MC, a `MEASUREMENT`/`CHARACTERISTIC` size is **derived**
(MEASUREMENT ← Datatype; CHARACTERISTIC ← RECORD_LAYOUT / Deposit), not required inline. A record
with a valid address but no derivable length is therefore **valid, just not memory-checkable** — it
must render white/grey ("valid, not memory-checked"), never red.

## 2. Root cause (grounded)

`s19_app/tui/a2l.py:1283` `_tag_schema_and_applicability`:

```python
if address is None or length is None:
    return False, False, "missing address/length"   # conflates the two
```

`schema_ok=False` → `app.py:378` `_a2l_tag_row_severity` returns `ERROR` → red row. The conflation
means *missing length alone* (address present) is treated identically to *missing address*.

Verified sufficiency: `validation/rules.py` emits **no** length-keyed issue (only
`A2L_STRUCTURE_ERROR`/`A2L_INVALID_ADDRESS`/`A2L_DUPLICATE_SYMBOL`/warnings), so the red comes
*purely* from `schema_ok` — fixing the source flips the colour with no separate `ValidationIssue`
in the loop. (Confirms the backlog's "flows via schema_ok/valid, not a ValidationIssue" claim.)

Deeper root (NOT in scope this batch): `_infer_length_characteristic` (a2l.py:707) hunts a
non-standard `LENGTH` keyword instead of resolving the RECORD_LAYOUT, so `length` lands `None`
often. Resolving RECORD_LAYOUT is a larger parser feature — deferred, noted as pending.

## 3. The fix

Split the condition so the three cases are distinct:

```python
if virtual and address is None:
    return True, False, ""            # unchanged — virtual exempt
if address is None:
    return False, False, "missing address/length"   # missing ADDRESS stays a concern (RED)
if length is None:
    return True, False, ""            # NEW: valid address, underivable length -> valid, not checkable
return True, True, ""                 # both present -> memory-check applies
```

Result for a valid-address + missing-length tag: `schema_ok=True, memory_checked=False,
in_memory=None` → `_a2l_tag_row_severity` falls through to `NEUTRAL` (grey), never `ERROR`.

**Reason-string decision:** the missing-*address* branch keeps the existing `"missing
address/length"` string verbatim. This preserves the frozen test
`test_tui_a2l.py::test_validate_a2l_tags_marks_missing_address_or_length_invalid` (its only case is
`address=None`, still `schema_ok=False`) so **no frozen test file is touched**. Minor cosmetic debt
(the string still reads "/length" on an address-only failure) — refining it would require unfreezing
the tc032 test-file guard; deferred.

## 4. Engine-unfreeze (C-27 dual-guard sanction)

`a2l.py` is git-frozen by TWO guards that `git diff main` the file and assert empty:
- `tests/test_engine_unchanged.py::test_tc027_*` (`_ENGINE_PATHS`, line 125)
- `tests/test_tui_directionb.py::test_tc031_*` (`_ENGINE_PATHS`, line 5419)

Both will trip once `a2l.py` differs from `main`. Sanction: **remove `"s19_app/tui/a2l.py"` from
`_ENGINE_PATHS` in both files**, with a comment citing this operator-approved parsing-logic fix. The
other six engine modules (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `mac.py`,
`color_policy.py`) stay frozen.

> **⚠ Risk surfaced:** this **permanently unfreezes `a2l.py`** — future view-only batches editing it
> accidentally would no longer be caught by these two guards. Accepted for this batch per operator
> approval; a re-freeze-against-new-baseline follow-up is noted as pending (§8).

Neither guard file is itself in `_ENGINE_TEST_FILES`, so editing them is unconstrained.

## 5. Acceptance criteria (observable)

- **AC-1** — When `validate_a2l_tags` is given a tag with a valid int `address` and `length=None`
  (non-virtual) and a mem_map, the result shall have `schema_ok=True`, `valid=True`,
  `memory_checked=False`, `in_memory=None`, `reason=""`.
- **AC-2** — When `_a2l_tag_row_severity` is given that tag (schema_ok=True, memory_checked=False,
  not virtual), it shall return `NEUTRAL` (not `ERROR`).
- **AC-3** — When a tag has `address=None` (non-virtual), the verdict shall be unchanged:
  `schema_ok=False`, `reason="missing address/length"`, row severity `ERROR`.
- **AC-4** — When a virtual tag has `address=None, length=None`, it shall stay `schema_ok=True`
  (unchanged), not red.
- **AC-5** (end-to-end, via existing `NOLEN_CHAR` fixture) — In `test_at_036a`, the `NOLEN_CHAR`
  (missing length, valid address) row shall render **non-ERROR** styled AND produce **no**
  supplemental ERROR issue on the Issues surface, while `BROKEN_CHAR` (missing address) stays red
  with its issue.
- **AC-6** — The full engine guard suite (`test_tc027_*`, `test_tc031_*`, `test_tc032_*`) shall pass:
  a2l.py is sanctioned; all other engine modules and all frozen test files are byte-identical to
  `main`.

## 6. Security flags

Scanned objective + criteria + description. **No** auth/secrets/external-integration/PII/
destructive-DB/network patterns fired. `security_required: **false**`.

Residual note (not a flag): the change lives in a parser that already consumes untrusted A2L input.
It **narrows** what is flagged (fewer false ERRORs); it adds no input surface and no external action.
Reason strings still flow through the unchanged `validation/model.py` sanitiser/truncation. No
weakening of existing hardening.

## 7. Files (blast radius)

**Increment 1 — complete fix, suite-green (5 files):**
1. `s19_app/tui/a2l.py` — split the condition (the fix). *[engine-unfrozen this batch]*
2. `tests/test_engine_unchanged.py` — remove a2l.py from `_ENGINE_PATHS` (+comment).
3. `tests/test_tui_directionb.py` — remove a2l.py from `_ENGINE_PATHS` (+comment).
4. `tests/test_validation_service_supplemental.py` — flip `test_at_036a` NOLEN_CHAR assertions
   (row non-red + no supplemental issue) + refresh the a2l.py line-ref comments.
5. `tests/test_a2l_missing_length_fix.py` — **NEW** unit + severity proof tests (AC-1..AC-4).

**Increment 2 — docs/traceability (≤2 files):**
6. `REQUIREMENTS.md` — update the A2L colour requirement row + note the fix/unfreeze.
7. `CLAUDE.md` — correct the "Engine-frozen guard" paragraph (a2l.py no longer in the frozen set).

**Frozen, preserved unchanged:** `tests/test_tui_a2l.py`, `tests/test_validation_a2l.py`, all other
`_ENGINE_TEST_FILES`, and the six still-frozen engine modules.

## 8. Pending / deferred

- **P-1** RECORD_LAYOUT resolution in `_infer_length_characteristic` (the deeper root: many lengths
  land `None` because the parser never resolves the layout). Larger parser feature — separate batch.
- **P-2** Re-freeze `a2l.py` against a post-fix baseline so accidental future edits are caught again
  (the guards were removed, not re-baselined). Needs a small guard-mechanism design.
- **P-3** Reason-string precision on the missing-address branch ("/length" is now imprecise) —
  blocked by the tc032 frozen-test guard on `test_tui_a2l.py`; cosmetic.

## 9. Findings surfaced during implementation

- **F-1 (test-quality, MEDIUM) — `test_at_038c_a2l_error_row_keeps_severity_style` was a
  false-confidence test.** It seeded an A2L ERROR issue for `CAL_BLOCK_A` and asserted a red row,
  but (a) `update_a2l_view` recomputes `_validation_issues` from the file pair (LLR-037.3) so the
  seed was **silently discarded** before render, and (b) `CAL_BLOCK_A` is itself a missing-length
  tag (`VALUE 0x80000010 RL_U8` → address present, length underivable), so its "red" came *only*
  from the `schema_ok=False` bug this batch fixes — never from the issue-map path it claimed to
  test. The fix exposed it (row went white). **Resolved:** rewrote the test to inject a genuine
  duplicate `CAL_BLOCK_A`, so the real recomputed report emits `A2L_DUPLICATE_SYMBOL` ERROR and the
  row reds via the production issue-map path (verified end-to-end). This is the vacuous-check class
  the operator's C-31 (input-set-is-an-oracle) targets.

## 10. Batch status

| Current phase | Phase C — implemented; final full-gate re-run in flight |
