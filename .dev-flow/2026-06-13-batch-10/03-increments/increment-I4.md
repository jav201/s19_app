# Increment I4 (FINAL) — TUI surfacing + folded hygiene (HLR-004 + HLR-005)

Batch: 2026-06-13-batch-10 · Branch: claude/batch-10 · Closes Phase 3.
Covers: HLR-004 (LLR-004.1/004.2 — hybrid verify surface), LLR-002.3
(format-aware save filename), HLR-005 (LLR-005.1 N-3 + LLR-005.2 M-3 hygiene).
TC status: TC-007, TC-011a, TC-011b, TC-012-N3, TC-013.

---

## 1. What changed

Wired the verify-on-save outcome (already computed in I2/I3 and carried on
`ChangeService.last_summary.verify_result`, the §6.2 C-10 back-compatible
carrier) into the TUI save-back surface as a **hybrid** (D-B option 3): on a
clean verify the app emits a single quiet `Saved + verified: <file>` status
line and raises no notice; on a `mismatch` it emits a `Verify MISMATCH: <file>`
status line **and** a prominent `severity="error"` Textual notification naming
the file plus the per-kind run/byte summary built from `DiffStats` over
`DIFF_KIND_DOMAIN`. The written file is left in place either way
(collect-don't-abort). app.py only **reads** the `VerifyResult` fields and
renders them — no diff/verify computation was added (orchestration-only
contract preserved; the diff was computed in the verify engine in I2).

The post-apply save-back filename suggestion, previously hard-coded
`"{variant_id}-patched.s19"`, is now **format-aware**: `.hex` for a `"hex"`
image, `.s19` for an `"s19"` image (LLR-002.3); the legacy
"HEX save-back not supported this batch" status arm is retired and the prompt
now opens for HEX sources.

Folded hygiene: **M-3 (LLR-005.2)** — `OperationsScreen._execute_selected`
now resolves the operation id through the `operation_service.operation_resolver`
seam **inside** a narrow `except KeyError` and calls the resolved operation's
`.execute(self.loaded, now_fn=None)` **outside** that `try`, so a `KeyError`
raised inside execution is no longer masked as "unknown operation".
**N-3 (LLR-005.1)** — the `load_buttons` widget id, previously shared across
six modal screens, is replaced with six screen-unique ids
(`loadfile_buttons`, `saveproject_buttons`, `loadproject_buttons`,
`selectvariant_buttons`, `reportviewer_buttons`, `operations_buttons`); the
now-dead `#load_buttons` CSS selector was removed (all rows already carry the
`.modal-buttons` class that supplies the styling).

## 2. Files modified (5 — within cap)

| File | Δ | Purpose |
|------|---|---------|
| `s19_app/tui/app.py` | +97/− | Format-aware save suggestion (LLR-002.3); `_surface_verify_result` + `_verify_mismatch_summary` (HLR-004); imports `DIFF_KIND_DOMAIN`, `STATUS_VERIFIED`, `VerifyResult`. |
| `s19_app/tui/screens.py` | +30/−20 | M-3 resolve/execute split in `_execute_selected`; N-3 six unique button-row ids; docstrings updated to the new route. |
| `s19_app/tui/styles.tcss` | +1/−2 | Drop the dead `#load_buttons` selector; keep `.modal-buttons`. |
| `tests/test_tui_operations_view.py` | +132 | TC-013 (M-3 execute-internal KeyError not masked + registry-miss still reported); TC-012-N3 (screen-unique id + `.modal-buttons` intact). |
| `tests/test_tui_patch_editor_v2.py` | +188 | TC-007 (format-aware `.hex` suggestion); TC-011a (quiet verified status, no error notice); TC-011b (loud mismatch notice names file + counts, file stays on disk). |

## 3. How to test

```
python -m pytest -q tests/test_tui_operations_view.py
python -m pytest -q tests/test_tui_patch_editor_v2.py
python -m pytest -q tests/test_changes_apply.py tests/test_change_service.py \
    tests/test_verify_on_save.py tests/test_hex_emit.py
python -m pytest -q tests/test_engine_unchanged.py \
    "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main"
python -m pytest -q "tests/test_checks_engine.py::test_no_textual_in_static_import_graph"
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only   # last line
git diff --stat s19_app/tui/rail.py  # empty
```

## 4. Test results (actual)

1. **New/changed TUI pilots:**
   - `tests/test_tui_operations_view.py` → **5 passed** (3 prior + TC-013 + TC-012-N3).
   - `tests/test_tui_patch_editor_v2.py` → **11 passed** (8 prior + TC-007 + TC-011a + TC-011b).
2. **I1–I3 regression** (`test_changes_apply` + `test_change_service` + `test_verify_on_save` + `test_hex_emit`) → **61 passed**.
3. **OperationsScreen batch-08 regression** (`test_tui_operations_view.py`) → **5 passed** (M-3/N-3 did not break the existing 3).
4. **Lean suite** (`-m "not slow"`) → **763 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failures** (228.48s). Pre-state 758 passed → +5 (the 5 new TC nodes).
5. **Collect-only** last line → **816 tests collected** (I3 ledger 811 → 811 + 5 = 816; `N_new(I4) = 5`).
6. **Engine-frozen + rail guards** → `test_engine_unchanged.py` + `test_tc031_engine_modules_have_no_diff_vs_main` = **2 passed**; `git diff --stat s19_app/tui/rail.py` = **empty** (rail untouched).
7. **app.py orchestration-only** → `grep "diff_mem_maps\|verify_written_image" s19_app/tui/app.py` = **0 hits**. app.py reads `VerifyResult` fields (`status`, `written_path`, `stats.run_counts/byte_counts`) only.
8. **Headless purity** → `test_no_textual_in_static_import_graph` = **1 passed** (new `.changes`/`..compare` imports in app.py do not pollute the headless graph).
9. **P-3 inspection** (LLR-005.1) → `rg 'id="load_buttons"' s19_app/tui/screens.py` = **0** (pre-state 6).

## 5. Risks

- The "loud" notice uses Textual `App.notify(severity="error")`. There is no
  prior `notify` usage in this app; the app already imports textual, so this is
  not a purity concern, and the toast is the natural Textual prominent-notice
  surface (`set_status` truncates to 50 chars and is the quiet channel). If a
  later batch standardizes a different notice surface, this is the one site to
  migrate.
- TC-011b injects the mismatch by substituting `verify_written_image` (the
  surfacing logic is the unit under test; the file is still faithfully written
  by the real save engine, so the on-disk-persistence assertion is genuine).
  A real emitter-fault end-to-end mismatch is exercised at the engine layer in
  I3 (`test_changes_apply.py -k verify_on_save`), so the two layers are covered
  by complementary fault models (Rule 9).
- Mismatch summary string is `"<kind> N run / M byte"` per `DIFF_KIND_DOMAIN`;
  it reports counts/addresses only, never raw image bytes (F-S-05 no-byte-leak).

## 6. Pending items

**None — Phase 3 closes.** All five HLRs (001–005) are implemented across
I1–I4; all LLRs covered by ≥1 passing TC; 0 blocker fails; 0 collection
regression (D=0, additive only).

## 7. Suggested next task

**Phase 4 (validation)** of batch-10: execute the §5.2 coverage table against
the implemented code, run the demo-validated HLR-004 TCs (TC-011a/b) as the
observed-behavior demos, and record the requirements-traceability promotions
in `REQUIREMENTS.md` (R-* rows for US-008/US-009). Deferred follow-ups for a
later batch: G-4 on-disk mismatch report via `diff_report_service`; the CRC
first-operation fill-in; the `project.json` manifest writer; variant-execution
HEX persist (`variant_execution_service.py:724-728`, still refused this batch).

---

## Hygiene disposition (N-3 / M-3)

### M-3 (LLR-005.2) — KeyError scope narrowed
`OperationsScreen._execute_selected` previously wrapped
`operation_service.run_operation(...)` — which does **both** resolve and
execute (`operation_service.py:90`) — in the `except KeyError`, so a `KeyError`
from inside the operation's own logic was misreported as "unknown operation".
Fixed by splitting the call: `operation_resolver(operation_id)` runs **inside**
the narrow `try` (it raises `KeyError` on a registry miss); the resolved
`operation.execute(self.loaded, now_fn=None)` runs **outside** the `try`. The
documented intent ("a registry `KeyError` becomes a status-line message",
`screens.py:601`) is preserved verbatim; only the catch scope tightened.
`now_fn=None` matches the default `run_operation` forwarded, so behavior on the
happy path is identical. TC-013 phase A (resolver raises → "unknown operation"
status) + phase B (stub `.execute` raises `KeyError` → propagates, NOT masked)
prove the split.

### N-3 (LLR-005.1) — per-screen unique button-row ids
The task brief scoped N-3 to renaming the OperationsScreen instance
(`screens.py:556`) to `operations_buttons`. **Deviation (loud, see below):**
LLR-005.1's pass threshold is *"0 widget ids shared across two screens"* (P-3:
the duplicate count must drop from 6-shared to 0-shared), which one rename
cannot satisfy — the other five screens would still share `load_buttons` among
themselves. To meet the LLR threshold I renamed **all six** occurrences to
screen-unique ids. This is zero-risk: every row already co-applies the
`.modal-buttons` class (`styles.tcss:697`) that supplies all the layout, so the
borrowed `#load_buttons` id carried no unique styling; the dead `#load_buttons`
CSS selector was removed. No test referenced `load_buttons` (grep `tests/` → 0).
The four-way `id="load_dialog"` collision (lines 85/135/194/260) is **out of
scope** — the spec targets only `load_buttons`, and each `ModalScreen` is a
separate DOM so within-screen uniqueness holds.

### CSS disposition (R-10-HYGIENE-CSS)
`#load_buttons` selector removed from `styles.tcss`; `.modal-buttons` rule kept
unchanged. No styling lost (verified by TC-012-N3 asserting the row still
carries `.modal-buttons`).

## Deviations (loud)

1. **N-3 broadened from the task brief's single-instance scope to all six
   screens** — required to satisfy LLR-005.1's P-3 threshold (0 cross-screen
   shared ids). Stayed within the same two files (screens.py + styles.tcss);
   zero behavior/styling change. Flagged here for the orchestrator.
2. **Test home for M-3/N-3:** the spec's §5.2 named `tests/test_operations.py`
   for TC-013, but the actual OperationsScreen pilot tests live in
   `tests/test_tui_operations_view.py` (batch-08 home). Tests landed there
   (V-5: spec-pinned paths were provisional-until-Phase-3). TC-013 +
   TC-012-N3 added there.
3. **HEX emitter import in tests:** `emit_intel_hex_from_mem_map` is exported
   from `s19_app.tui.changes.io` but **not** re-exported from the
   `s19_app.tui.changes` package `__init__` (only `emit_s19_from_mem_map` is).
   Test imports it directly from `.changes.io` rather than widening the package
   `__all__` (avoids touching a 6th file's export contract). Noted as a tidy
   follow-up: re-export the HEX emitter from the `changes` package for symmetry
   with the S19 emitter.

## A-3 / V-5 — actual node ids + test files vs spec provisional names

| Spec (provisional) | Actual landed |
|---|---|
| TC-007 — LLR-002.3 format-aware suffix | `tests/test_tui_patch_editor_v2.py::test_save_back_suggestion_is_format_aware` |
| TC-011a — LLR-004.1 verified status | `tests/test_tui_patch_editor_v2.py::test_verify_quiet_pass_on_faithful_hex_save` |
| TC-011b — LLR-004.2 mismatch notice | `tests/test_tui_patch_editor_v2.py::test_verify_loud_mismatch_notice` |
| TC-013 — LLR-005.2 KeyError scope (spec said `tests/test_operations.py`) | `tests/test_tui_operations_view.py::test_execute_internal_keyerror_not_masked_as_unknown_operation` |
| TC-012 — LLR-005.1 unique button ids (inspection; spec P-3 grep) | `tests/test_tui_operations_view.py::test_operations_button_row_has_screen_unique_id` (+ P-3 grep: 0 shared) |

Node ids (actual): button-row ids `loadfile_buttons` / `saveproject_buttons` /
`loadproject_buttons` / `selectvariant_buttons` / `reportviewer_buttons` /
`operations_buttons` (replacing the six `load_buttons`). New app.py symbols:
`S19TuiApp._surface_verify_result`, `S19TuiApp._verify_mismatch_summary`.

## Ledger

811 (after I3) → **816** collected. `N_new(I4) = 5` (TC-007, TC-011a, TC-011b,
TC-013, TC-012-N3). `D = 0` (additive only, no node removed/renamed away).
Lean suite 758 passed (pre) → **763 passed** (post), 0 failures.
