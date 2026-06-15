# Increment I3 — HEX save-back + verify wiring (HLR-002, LLR-002.1/.2/.3 + LLR-003.3 carrier)

Batch: 2026-06-13-batch-10 · Branch: claude/batch-10 · Worktree: competent-clarke-1e8940

## 1. What changed
Retired the blanket HEX-save refusal in the change-save engine and made HEX a
first-class persist format. `save_patched_image` now selects its emitter +
suffix by `source_kind` (`emit_s19_from_mem_map`/`.s19` for `"s19"`,
`emit_intel_hex_from_mem_map`/`.hex` for `"hex"`) and refuses only sources that
are neither (e.g. `"mac"`) with the still-defined `CHG-HEX-SAVE-UNSUPPORTED`
code. The filename sanitizer `_sanitize_s19_filename` gained a parametric
`suffix` argument (default `.s19`, passed `.hex` on the HEX branch) — the three
rejection rules (traversal, reserved device names, trailing dot/space) stay in
that one unforked function. Verify-on-save is wired into the service:
`ChangeService.save_patched` calls `verify_written_image` after a successful
write and stamps the `VerifyResult` onto `last_summary.verify_result` — the
§6.2 C-10 back-compatible carrier. `save_patched_image`'s 2-tuple return is
preserved unchanged (M-1). `verify_written_image`/`VerifyResult` are now
re-exported from the `changes` facade (deferred from I2).

## 2. Files modified (I3 footprint = 6 — one over the 5-cap, flagged §5)
- `s19_app/tui/changes/apply.py` (+108/−) — emitter+suffix selection table
  `_SAVE_BACK_EMITTERS`; refusal retired for `"hex"`, kept for other sources;
  `_sanitize_s19_filename(..., suffix=".s19")` parametric; docstrings updated.
- `s19_app/tui/services/change_service.py` (+26/−) — import `verify_written_image`;
  call it post-save and stamp `last_summary.verify_result`; docstrings updated.
- `s19_app/tui/changes/model.py` (+14/−) — `ChangeSummary.verify_result:
  Optional["VerifyResult"] = None` slotted field (TYPE_CHECKING-only import to
  keep model.py free of the runtime verify import); kept OFF `to_dict`
  (runtime-only carrier, preserves determinism tests).
- `s19_app/tui/changes/__init__.py` (+15/−) — re-export `verify_written_image`,
  `VerifyResult`, `STATUS_VERIFIED`, `STATUS_MISMATCH`.
- `tests/test_changes_apply.py` (+195/−) — HEX save-back + verify tests;
  retitled the obsolete refusal test to a `"mac"`-refused test.
- `tests/test_change_service.py` (+52/−) — carrier tests (verified stamp,
  refused→None).

`variant_execution_service.py` was NOT touched (M-1 / §1.2: its 2-tuple unpack
is unchanged; variant-execution HEX persist stays refused this batch).

## 3. How to test
```
python -m pytest -q tests/test_changes_apply.py
python -m pytest -q tests/test_change_service.py
python -m pytest -q tests/test_hex_emit.py tests/test_verify_on_save.py
python -m pytest -q tests/test_engine_unchanged.py
python -m pytest -q --collect-only        # last line
python -m pytest -q -m "not slow"
```

## 4. Test results (actual)
1. `test_changes_apply.py` → **25 passed** (incl. all original `test_save_back*`,
   2-tuple unpacks intact).
2. `test_change_service.py` → part of the 61-pass combined run (below); +2 new
   carrier tests green.
3. I1+I2 regression `test_hex_emit.py test_verify_on_save.py` → **18 passed**.
4. Combined four-file run → **61 passed**.
5. Engine-frozen `test_engine_unchanged.py` → **1 passed** (no frozen module touched).
6. `--collect-only` last line → **811 tests collected** (pre-state 800 → +11 new).
7. Lean suite `pytest -q -m "not slow"` → **758 passed, 29 skipped, 21
   deselected, 3 xfailed, 0 failures** (pre-state 747 passed → +11 = 758).

Signed-balance (§5.3): `collected_after == 800 − 0 + 11 == 811`. ✔ No node lost.

### Back-compat proof (M-1)
- Return annotation unchanged: `apply.py:581` →
  `Tuple[Optional[Path], List[ValidationIssue]]`.
- 2 production unpack sites intact: `change_service.py:851`,
  `variant_execution_service.py:711` (latter untouched).
- 3 original test unpack sites intact (shifted by import additions, still
  2-tuple): `tests/test_changes_apply.py:335,381,407`.
- 0 fields added to the tuple; `VerifyResult` rides `last_summary.verify_result`.

### A-3 / V-5 — actual node ids vs provisional spec names
| Spec provisional | Actual node id | File | LLR/TC |
|---|---|---|---|
| `-k hex_save` | `test_hex_save_writes_hex_file_that_reparses_to_post_apply_map` | test_changes_apply.py | LLR-002.1 / TC-005 |
| `-k hex_save` | `test_hex_save_forces_hex_suffix_when_name_lacks_it` | test_changes_apply.py | LLR-002.1 / TC-005 |
| (s19 suffix default) | `test_s19_save_still_forces_s19_suffix` | test_changes_apply.py | LLR-002.1 AC / TC-007 |
| `-k hex_save` | `test_hex_save_adversarial_filenames_contained_or_refused` (4 params) | test_changes_apply.py | LLR-002.1 AC / TC-005 |
| `-k unsupported_source` | `test_save_back_unsupported_source_refused_with_clear_issue` | test_changes_apply.py | LLR-002.2 / TC-006 |
| `-k verify_on_save` | `test_verify_written_hex_image_is_verified` | test_changes_apply.py | LLR-003.3 / TC-010 |
| `-k verify_on_save` | `test_verify_on_dropped_byte_is_mismatch_file_kept` | test_changes_apply.py | LLR-003.3 / TC-010 |
| `-k save_patched_hex` | `test_hex_save_stamps_verified_result_on_summary` | test_change_service.py | C-10 carrier |
| (refused→no verify) | `test_refused_save_leaves_verify_result_none` | test_change_service.py | C-10 carrier |

Per-TC status: TC-005 ✔ (3 tests + adversarial), TC-006 ✔, TC-007 ✔ (engine-half
suffix; full save-back-surface format selection LLR-002.3 lands in I4 at app.py),
TC-010 ✔ (verified + dropped-byte mismatch, collect-don't-abort). The DROP fault
asserts exactly one `only_a` run of length 1 (Rule 9 — kind matches planted fault).

## 5. Risks / deviations (LOUD)
- **DEVIATION — 6 files, one over the 5-cap.** The increment instructions
  enumerated 5 files but omitted `model.py`. `ChangeSummary` is `slots=True`, so
  the C-10 carrier `verify_result` cannot be a dynamic attribute — it MUST be a
  declared field, whose only home is `model.py`. The spec-pinned carrier
  (`last_summary`, a `ChangeSummary`) leaves no 5-file path that honors C-10.
  Alternative (carrier on `ChangeActionResult`, defined in change_service.py)
  would have stayed at 5 files but VIOLATED the pinned C-10 contract. Chose
  contract-fidelity over the cap; model.py is NOT engine-frozen so the edit is
  permitted. Flagging for orchestrator awareness.
- **DEVIATION (placement) — verify call lives in `change_service.save_patched`,
  NOT inside `save_patched_image`.** Increment item 1c said "after a successful
  write, call `verify_written_image` ... attach to the result." Attaching it to
  `save_patched_image`'s result would have forced widening its return (breaking
  M-1). The requirements (LLR-003.3, §6.2 C-10, increment-plan I3 line) are
  explicit that the SERVICE handler invokes verify and stamps `last_summary`.
  Followed the spec-authoritative placement; the 2-tuple stays untouched.
- `to_dict` intentionally does NOT serialize `verify_result` — keeps the
  determinism tests (two applies under a fixed clock compare equal) green and
  matches its runtime-only-carrier role.
- LLR-002.3 (format-aware default filename in the save-back SURFACE, `app.py`)
  is I4 scope — only the engine-half suffix forcing is proven here.

## 6. Pending items (deferred to I4)
- HLR-004 quiet/loud TUI surfacing (LLR-004.1/004.2) — read `last_summary.verify_result`.
- LLR-002.3 format-aware suggested filename at `app.py:1341`.
- HLR-005 folded hygiene (load_buttons ids + KeyError scope).
- REQUIREMENTS.md R-* traceability rows + status promotions (orchestrator/docs phase).

## 7. Suggested next task
I4 — TUI surfacing + folded hygiene: wire the quiet "saved + verified" status
line and the loud mismatch notice off `last_summary.verify_result`, make the
suggested save filename format-aware (LLR-002.3), and fold N-3 (unique modal
button ids) + the OperationsScreen KeyError scoping (LLR-005.1/005.2).
