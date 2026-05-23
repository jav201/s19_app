# Increment 011 — Integration save/load + containment UI tests

> **Phase 3 · batch-03 · Increment 11 (final).** Drives the functional Patch
> Editor save / load and the work-area containment / dedup / reparse-point
> rejection **end-to-end through the running app** (`App.run_test()` + `pilot`).
> Spec: increment-plan §A.4 — Increment 11; requirements integration arms of
> LLR-007.3 / 007.4 / 007.7; TC-026 (save/load integration depth), TC-036
> (containment through the screen), TC-027a (Patch-Editor-load integration
> arm). Branch: `dev-flow/batch-02-direction-b-restyle`.
> **Tests only — no production behavior change.**

## 1. What changed

Two test files were touched — both **tests only**, no `s19_app/` production
file was modified. `tests/test_tui_patch_editor.py` gained an integration
section that deepens TC-026 and TC-027a from the increment-9 *service-seam*
arm (`CdfxService.save`/`.load` called directly) to the *screen* arm: a
change-list is built **through the Patch Editor widget controls**, and `"save"`
/ `"load"` are driven as `ActionRequested` messages so the whole screen →
`app.py` handler → `CdfxService` → `cdfx` package → `DataTable` path runs under
`App.run_test()`. The new `tests/test_tui_patch_containment.py` verdicts the
integration arm of TC-036 — a screen save resolves under `.s19tool/workarea/`,
a repeated save dedup-suffixes (`patchset.cdfx` → `patchset_1.cdfx`, no silent
clobber), and a save into a symlinked (reparse-point) work area is rejected
with a `W-WRITE-CONTAINMENT` `ValidationIssue` on the status path with no crash
and no file escaping the work area.

A small detail surfaced and was handled (not a defect): with no real A2L file
loaded, the Patch Editor handler resolves the change-list through
`_compute_a2l_enriched_tags`, which returns `[]` — every entry is then
`unresolved-no-a2l` and the writer excludes it (`W-INSTANCE-EXCLUDED`, the
exact "no-A2L empty-save sharp edge" recorded in increment-9 review packet §5).
A save→load round-trip driven through the screen with no A2L therefore
recovers zero entries. This is **correct writer behavior**, not a bug — so the
integration round-trip / save tests stub the app instance's
`_compute_a2l_enriched_tags` with synthetic `_A2L_TAGS` (the established
no-real-artifact pattern, constraint C-9) so the screen path resolves real
entries and the writer emits real `SW-INSTANCE`s. The malicious-load and
empty-save-issue tests deliberately keep the no-A2L state. **No real UI defect
was found** — the increment's optional production-file slot was not used, so
this is a 2-file increment.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `tests/test_tui_patch_editor.py` | **modified** | Added the increment-11 integration section: a `_patch_a2l_tags` helper (stubs the app's enriched-tag source with synthetic `_A2L_TAGS`); TC-026 integration depth — screen save writes a `.cdfx` under the work area, screen save→load round-trips through `pilot`, a screen load of a coalesced `VAL_BLK` `.cdfx` expands to the per-element rows, a screen save of an unresolved entry surfaces `W-INSTANCE-EXCLUDED` on `app.log_lines`; TC-027a integration arm — a billion-laughs `.cdfx` load through the screen keeps the screen usable (empty-state shown, follow-up add works) and surfaces `R-XML-PARSE` with no expanded-entity leak into any loaded entry. +6 tests (21 → 27). The increment-9 tests are unchanged. |
| `tests/test_tui_patch_containment.py` | **new** | TC-036 integration arm — 4 tests: a screen save resolves under `.s19tool/workarea/`; a repeated screen save of the default name dedup-suffixes (`patchset.cdfx` → `patchset_1.cdfx`, both survive); a screen save into a symlinked work area is rejected with a `W-WRITE-CONTAINMENT` issue on the status path, the screen stays usable, no `.cdfx` escapes (privilege-gated `skipif`, CV-03); a privilege-independent control arm forces the rejection by stubbing `copy_into_workarea` to raise `WorkareaContainmentError`. In-test `_can_create_symlink` probe (mirrors `test_cdfx_path_containment.py`), `_patch_a2l_tags` and `_save_one_entry_through_screen` helpers. |

**File count: 2 — under the ≤5 cap.** The increment-plan's optional third file
(`screens_directionb.py` / `app.py`, "only if a UI defect surfaces") was **not
needed** — no UI defect was found.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_tui_patch_editor.py tests/test_tui_patch_containment.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui"                         # app imports
python -m py_compile tests/test_tui_patch_editor.py tests/test_tui_patch_containment.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_tui_patch_editor.py`** → `27 passed in 6.14s`
  (21 increment-9 tests + 6 new increment-11 integration tests).
- **`pytest -q tests/test_tui_patch_containment.py`** → `4 passed in 2.07s`
  (the reparse-point arm **ran** — symlink creation is available on this
  Windows machine; on a privilege-less CI image it skips cleanly with the
  recorded CV-03 reason, it does not fail).
- **`pytest -q tests/test_tui_patch_editor.py tests/test_tui_patch_containment.py`**
  → `31 passed in 8.72s`.
- **`pytest -q` (full suite)** → `611 passed, 2 skipped, 3 xfailed in 175.55s`,
  `27 snapshots passed`, **0 failed**. Baseline was **601 passed / 2 skipped /
  3 xfailed / 0 failed**; 601 + 10 = 611 — exact, no regression. The skip and
  xfail counts are **unchanged** (2 / 3) and **27 snapshots passed** — no
  snapshot baseline went stale (this is a tests-only increment, no UI change).
- **`python -c "import s19_app.tui"`** → `IMPORT s19_app.tui OK`.
- **`python -m py_compile`** on both files → `PY_COMPILE OK`.

### New tests by TC

**`tests/test_tui_patch_editor.py` — 6 new (increment-11 integration section):**
- **TC-026 integration depth** — 4 tests:
  - `…screen_save_writes_cdfx_under_workarea` — a change-list built via the add
    control and saved via the `"save"` action produces a `.cdfx` whose resolved
    path is under `.s19tool/workarea/` (LLR-007.3 integration arm).
  - `…screen_save_then_load_round_trips_via_pilot` — build via the controls,
    `"save"`, `"remove"` to clear the table, `"load"` the written path → the
    change-list repopulates with the saved entry (LLR-007.3 / 007.4, the full
    cycle through one app instance, not a second `CdfxService`).
  - `…screen_load_expands_val_blk_to_element_rows` — a `.cdfx` carrying a
    coalesced `VAL_BLK` `SW-INSTANCE` loads through the screen as the
    per-element rows `(FUEL_TRIM, 0)` / `(FUEL_TRIM, 1)` — coalesce-on-write
    (LLR-004.9) → expand-on-read (LLR-005.6) verified through the UI.
  - `…screen_save_surfaces_issues_on_status_path` — a screen save of an
    unresolved entry routes `W-INSTANCE-EXCLUDED` to the status path
    (`app.log_lines`) via `_report_cdfx_result` — visible, never silent.
- **TC-027a integration arm** — 2 tests:
  - `…billion_laughs_load_keeps_screen_usable` — a billion-laughs `.cdfx` load
    through the `"load"` action leaves the change-list empty, shows the
    empty-state line, and a follow-up add control still works — no crash, no
    hang.
  - `…billion_laughs_load_surfaces_parse_issue` — the same load surfaces
    `R-XML-PARSE` on the status path; no expanded entity text (`LOLLOL`) leaks
    into any loaded change-list entry value.

**`tests/test_tui_patch_containment.py` — 4 new:**
- **TC-036 integration arm**:
  - `…screen_save_resolves_under_workarea` — a `"save"` driven through the
    running Patch Editor places the `.cdfx` under `.s19tool/workarea/`.
  - `…repeated_screen_save_dedup_suffixes` — two `"save"` actions produce
    `patchset.cdfx` + `patchset_1.cdfx`; both survive — no silent clobber.
  - `…reparse_point_save_rejected_not_crashed` — with `.s19tool/workarea` a
    symbolic link to an out-of-containment directory, a screen `"save"` is
    rejected with `W-WRITE-CONTAINMENT` on the status path, the screen stays
    usable (a follow-up `"edit"` still works), and no `.cdfx` escapes into the
    symlink target. **Privilege-gated** — a `_can_create_symlink` probe skips
    it with a recorded CV-03 reason when symlink privilege is absent.
  - `…reparse_point_save_is_visible_failure` — the privilege-independent
    control: `copy_into_workarea` is stubbed to raise
    `WorkareaContainmentError`; the screen save catches it and surfaces
    `W-WRITE-CONTAINMENT` — the rejection path is covered on every CI image
    regardless of symlink privilege.

No code defect was found during the run. One test-design correction was made
mid-increment: the first draft of the screen save→load round-trip ran with no
A2L and recovered zero entries (the writer correctly excludes unresolved
entries); the fix was to stub `_compute_a2l_enriched_tags` with synthetic A2L
tags so the integration arm exercises a *resolved* round-trip — see §1 and §5.

## 5. Risks

- **The no-A2L empty-save behavior is correct, and the integration tests now
  cover both sides of it.** With no A2L, a screen save excludes every entry
  (`W-INSTANCE-EXCLUDED`) and produces a backbone-only `.cdfx`; the round-trip
  and write-under-workarea tests therefore stub `_compute_a2l_enriched_tags`
  with synthetic `_A2L_TAGS` so the writer sees resolved entries, while the
  `…save_surfaces_issues_on_status_path` test deliberately keeps the no-A2L
  state to verify the exclusion warning is *visible*. This is the increment-9
  review packet §5 sharp edge, now test-pinned on both arms — not a new risk.
- **The `_compute_a2l_enriched_tags` stub couples the integration tests to a
  method name.** If `app.py`'s enriched-tag source is renamed, these tests
  break at the stub rather than at the behavior under test. *Mitigation:* the
  stub is a one-line helper (`_patch_a2l_tags`) in both files with a docstring
  explaining why; a rename is a loud, localized failure, and the production
  handler is unchanged this increment.
- **The reparse-point arm depends on OS symlink privilege.** It **ran** on this
  Windows machine; on a privilege-less CI image it skips cleanly with a
  recorded CV-03 reason — it does not fail and is not a silent pass (a visible
  `pytest.skip`). The `…reparse_point_save_is_visible_failure` control arm
  gives the containment-rejection path **unconditional**, privilege-independent
  coverage by stubbing `copy_into_workarea`.
- **`app.log_lines` is a `deque(maxlen=4)`** — `set_status` truncates each line
  to 50 characters and keeps only the last 4. The status assertions search the
  4 retained lines for a code substring (`W-INSTANCE-EXCLUDED` / `R-XML-PARSE`
  / `W-WRITE-CONTAINMENT`), all of which fall within the first 50 characters of
  their status line. The no-entity-leak assertion checks the parsed change-list
  entry values directly (not the truncated status line), so it is not weakened
  by the truncation. A future increase in the number of status lines emitted
  per action could push a target line out of the 4-deep deque — recorded so a
  later maintainer reads a failure here as a status-volume change, not a
  containment regression.
- **No snapshot baseline went stale.** This is a tests-only increment with no
  UI change — the 27 snapshot cells all passed, including
  `patch-comfortable-120x30`. (The increment-9 review packet flagged that cell
  as stale; it was evidently regenerated/accepted before the increment-11
  baseline of 601, since the full suite is now 0-failed.)
- **The increment-5 stale-test note** (writer-test scalars built with
  positional `array_index=0`) is unrelated to these files and was resolved in
  increment 6 — recorded only so Phase 4 does not re-flag it.

## 6. Pending items

- **None for this increment.** Increment 11's scope (the TC-026 / TC-036 /
  TC-027a integration arms through `App.run_test()`) is fully delivered, the
  full suite is green, and the file count is under cap.
- **Phase 3 (Implementation) is complete** — all 11 increments are shipped
  (increments 1-4 + the re-planned 5-11). The full CDFX feature is in place:
  the `Optional[int]` change-list model, A2L resolution, type-driven display,
  the coalescing writer + `W-*` validator, the `VAL_BLK`-expanding reader +
  `R-*` validator, the XML-safety + path-containment layer, the functional
  Patch Editor screen + `cdfx_service`, the round-trip / adversarial-float
  hardening, and now the end-to-end integration verdict.
- **Outstanding cross-functional hand-offs from earlier increments** (carried
  forward, not new): the increment-8 **security-reviewer** pass (DOCTYPE /
  `<!ENTITY>` rejection, the CV-04 `expat` hook ordering, the size/depth
  bounds, the `copy_into_workarea` write-path reuse) and the increment-9
  **qa-reviewer** acceptance-criteria / manual-test-plan hand-off for the
  functional screen. Phase 4 (validation) is the natural place these close.
- **CV-01** Phase-2 closure cosmetic item still has no natural touch-point
  (CV-02/CV-03 were applied in increments 5 / 8 / 11) — surfaced once more so
  it is not lost.

## 7. Suggested next task

**Phase 3 is complete — batch-03 advances to Phase 4 (validation).** All 11
increments have shipped; the full suite stands at **611 passed / 2 skipped /
3 xfailed / 0 failed**. The next step is the Phase-4 validation pass against
`01-requirements.md` §5: confirm every one of the 44 LLR / 47 TC has a passing
verdict, run the §5.9 acceptance gate (including the security gate — TC-027a /
TC-027b — and the C-2 no-new-dependency check), and execute the two carried-over
hand-offs as part of validation:

- **security-reviewer** — review the increment-8 XML-safety + write-path
  containment surface before the batch's validation gate closes.
- **qa-reviewer** — confirm the TC-025 / 026 / 028 acceptance criteria and the
  manual Patch-Editor test plan (the no-A2L empty-save sharp edge, the
  load-replaces-change-list destructive action, the `W-ARRAY-SPARSE` and
  `W-WRITE-CONTAINMENT` fail-loud behaviors).

---

**Stop boundary reached.** Increment 11 is complete: `tests/test_tui_patch_editor.py`
gained 6 integration tests deepening TC-026 / TC-027a to the screen arm, and
`tests/test_tui_patch_containment.py` (new) verdicts the TC-036 integration arm
— containment / dedup / reparse-point rejection driven through the running
Patch Editor under `App.run_test()`, the reparse-point arm privilege-gated with
a visible CV-03 `skipif` plus a privilege-independent stubbed control. Two
files, tests only, no production change, no UI defect found. The full suite is
611 passed / 2 skipped / 3 xfailed / 0 failed (601 baseline + 10), no snapshot
baseline stale, `s19_app.tui` imports unchanged, no new dependency. **Phase 3
(Implementation) is complete — all 11 increments shipped; batch-03 advances to
Phase 4 (validation).**
