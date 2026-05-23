# Increment 011 — No-regression + behavior verification

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" restyle)
**Phase:** 3 — Implementation
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Date:** 2026-05-20
**LLRs:** LLR-004.4, LLR-013.1, LLR-013.2, LLR-014.1, LLR-014.2
**TCs:** TC-011, TC-029, TC-030, TC-031, TC-032

---

## 1. What changed

This is the dedicated cross-cutting **no-regression / behavior verification** increment.
It adds **no production behavior** — it verdicts the batch. A 16-test increment-11
block was appended to `tests/test_tui_directionb.py`, implementing TC-011 (keyboard
reachability of every pre-batch action + the `1`/`2`/`3` rail supersession), TC-029
(every new Direction B control is keyboard-reachable + the input-focus single-key
suppression sub-case), TC-030 (the footer reflects the active screen's `show=True`
bindings, checked against increment-1's owner-approved keymap proposal), TC-031 (the
engine / data-processing modules are behaviorally unchanged vs the batch start —
verified by `git diff main`), and TC-032 (the engine/parser/validation test files are
unmodified vs the batch start and the suite stays green). The module docstring was
extended with the increment-11 LLR/TC list and a design note reconciling the keymap
proposal's per-screen `show=True` tables with the single-global-`BINDINGS`
implementation chosen in increments 2-7.

**No `app.py` edit was needed:** TC-029/TC-030 exposed no missing keyboard path and no
`show=False` binding that should be `show=True` — every new control was already
reachable and the footer already surfaces the keymap §2 global set on every screen.
**No `test_tui_app.py` edit was needed:** a repo-wide grep confirmed no pre-batch UI
test still references the retired `#main_layout` / `#alt_layout` / `#mac_layout` /
`#view_bar` structure — those tests were already re-pointed to the Direction B layout
in increments 2-7, and the 373-passing pre-increment baseline confirms they pass
unchanged. The increment therefore touched **2 files** (well within the 5-file cap).

## 2. Files modified

| File | Purpose |
|------|---------|
| `tests/test_tui_directionb.py` | Added the 16-test increment-11 block (TC-011/029/030/031/032); extended the module docstring with the increment-11 LLR/TC list and the keymap-vs-implementation design note for TC-030. |
| `.dev-flow/2026-05-20-batch-02/03-increments/increment-011.md` | This review packet (new). |

No production code was modified. No engine module, no `app.py`, no widget module
was touched.

### New tests (all carry a `TC-NNN` reference, matching conventions)

- `test_tc011_every_pre_batch_action_keeps_a_keyboard_path` — frozen pre-batch
  `BINDINGS` literal; every action reachable via a current binding or palette entry.
- `test_tc011_supersession_recorded_not_a_regression` — keys `1`/`2`/`3` remapped to
  `show_screen`, pressing them swaps to Workspace/A2L/MAC, `#view_bar` is gone.
- `test_tc029_rail_items_reachable_by_keyboard` — keys `1`-`8` activate each screen.
- `test_tc029_command_bar_inputs_reachable_by_keyboard` — `/`, `g`, `ctrl+k` reach
  find / go-to / palette.
- `test_tc029_density_toggle_reachable_by_keyboard` — `ctrl+d` flips the density class.
- `test_tc029_scaffold_inputs_reachable_by_keyboard` — Patch Editor inputs accept
  keyboard focus (inert but not mouse-only).
- `test_tc029_single_keys_suppressed_during_input_focus` — `g`/digit/`.` route into
  the focused find input as text; suppression ends when focus is released.
- `test_tc030_global_footer_set_present_on_every_screen` — keymap §2 global set in
  the footer on all 8 screens.
- `test_tc030_per_screen_paging_bindings_in_footer` — paging keys present on the 4
  screens the keymap §3 assigns paging to.
- `test_tc030_footer_updates_and_reflects_active_screen` — `Footer` mounted; footer
  set never drifts from `active_bindings`.
- `test_tc031_engine_modules_have_no_diff_vs_main` — `git diff --stat main` empty.
- `test_tc031_engine_modules_have_no_name_only_diff_vs_main` — `git diff --name-only
  main` empty (cross-check).
- `test_tc031_engine_imports_still_resolve` — every frozen engine module imports.
- `test_tc032_engine_test_files_unmodified_vs_main` — engine test files byte-identical.
- `test_tc032_no_engine_test_function_is_skipped` — no `skip`/`skipif` in engine tests.
- `test_tc032_directionb_tests_do_not_monkeypatch_engine_functions` — no view test
  monkeypatches an engine parse/validate function.

## 3. How to test

```bash
# The increment-11 block in isolation
python -m pytest tests/test_tui_directionb.py -q -k "tc011 or tc029 or tc030 or tc031 or tc032"

# Full suite (must hold 0 failed)
python -m pytest -q

# TC-031 engine-freeze evidence (must be empty)
git diff --stat main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
  s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py

# App still launchable
python -c "import s19_app.tui"

# ruff is NOT installed in this environment — substituted with py_compile:
python -m py_compile tests/test_tui_directionb.py
```

## 4. Test results — actual output

**Increment-11 tests (`-k "tc011 or tc029 or tc030 or tc031 or tc032"`):**

```
................                                                         [100%]
16 passed, 85 deselected in 7.66s
```

**Full suite (`pytest -q`):**

```
389 passed, 2 skipped, 3 xfailed in 134.41s (0:02:14)
```

- Pre-increment baseline: **373 passed / 2 skipped / 3 xfailed / 0 failed**.
- After increment 11: **389 passed / 2 skipped / 3 xfailed / 0 failed**.
- Delta: **+16 passed** = exactly the 16 new increment-11 tests. **0 failed, 0
  regressions.** The 2 skipped and 3 xfailed are the documented pre-existing
  baseline cases — unchanged.

**TC-031 engine-freeze evidence (`git diff --stat main` over the engine surface):**

```
[empty output]
EXIT:0 (empty output = zero diff = engine untouched)
---NAME-ONLY---
[empty output]   (empty = none changed)
```

`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`
and `tui/color_policy.py` are **byte-identical to `main`** (the batch start). Zero
changed lines → trivially cosmetic-only per the TC-031 Q-11 rubric (there is nothing
to classify; whitespace/comment/import-order = cosmetic, logic/constant/signature =
violation — none of either occurred). **LLR-014.1 verdict: PASS.**

**`import s19_app.tui`:** `import s19_app.tui OK`.

**`py_compile`:** `py_compile test_tui_directionb.py OK` (ruff not installed —
`py_compile` substituted per the brief).

### Verdict summary

| TC | LLR | Verdict | Evidence |
|----|-----|---------|----------|
| TC-011 | LLR-004.4 | PASS | Every pre-batch action keyboard-reachable; `1`/`2`/`3`→rail remap + `#view_bar` removal recorded as intended supersession. |
| TC-029 | LLR-013.1, LLR-004.5 | PASS | Rail items, command-bar inputs, density toggle, scaffold inputs all keyboard-reachable; single-key suppression during input focus verified both directions. |
| TC-030 | LLR-013.2 | PASS | Keymap §2 global footer set present on all 8 screens; keymap §3 paging keys present on Workspace/A2L/MAC/Issues; `Footer` never drifts from `active_bindings`. |
| TC-031 | LLR-014.1 | PASS | `git diff main` empty for all 7 engine modules; all engine modules import cleanly. |
| TC-032 | LLR-014.2 | PASS | 9 engine/parser/validation test files unmodified vs `main`; no `skip` markers; no engine monkeypatching; suite green. |

## 5. Risks

- **TC-030 keymap-vs-implementation reconciliation.** The increment-1
  `keymap-proposal.md` §3 lists *per-screen* `show=True` paging action ids
  (`a2l_tags_page_next`, `mac_records_page_next`, `validation_issues_page_next`).
  The implementation chosen in increments 2-7 realises those per-screen sets
  through a **single app-level `BINDINGS`** set: the paging keys
  `period`/`comma`/`plus`/`minus` are `show=True` globally and dispatch
  *context-sensitively* via `_active_view_name()` (`hex_page_next` on Workspace,
  `a2l_tags_page_*` on A2L Explorer, etc.). The footer therefore shows a **constant**
  chip set on every screen — the per-screen behavior is in the *action dispatch*, not
  in per-screen `Binding` objects. TC-030 verifies the honest, non-weakened reading
  of LLR-013.2: (a) the keymap §2 global footer set is present on every screen, and
  (b) the paging keys the keymap §3 assigns to a screen are present in that screen's
  footer. This is **not a regression** — the keymap proposal §3 itself defines a
  screen's footer as "global footer set + per-screen `show=True` set", and a single
  always-`show=True` dispatcher binding is a superset of every screen's expected set.
  This reconciliation is documented in the test module docstring and in each TC-030
  test docstring. **A reviewer who wants strict per-screen `Binding` objects would
  need a keymap-proposal or implementation change — out of scope for this increment.**
- **Scaffold-screen footer.** The keymap §3 assigns *no* per-screen bindings to the
  Memory Map / Patch Editor / A↔B Diff / Bookmarks scaffolds. With one global
  `BINDINGS`, the four paging-key chips still appear in those scaffolds' footers
  (the dispatchers are inert there — `_active_view_name()` returns `main` and the
  Workspace hex-paging guard / no-`row_bases` guard makes them no-ops). TC-030 does
  not assert the scaffolds *lack* paging chips — that would contradict the realised
  single-`BINDINGS` design. The scaffold footers show "global set + inert paging
  dispatchers", which is acceptable per the keymap proposal §3 open-point 3 ("their
  footers show only the global set" — interpreted against the realised dispatcher
  design).
- **`test_tui_app.py` / sibling UI tests not edited.** The increment-plan reserved a
  `test_tui_app.py` slot for re-pointing old-layout assertions. A repo-wide grep
  (`main_layout|alt_layout|mac_layout|view_bar|view_main|view_alt|view_mac|status_panel`)
  found **zero** matches in any pre-batch UI test file — they were already updated in
  increments 2-7, and the 373-passing baseline confirms they pass against the
  Direction B layout. No edit was made, so there is **no risk of weakening test
  intent** (GRNDIA rule 9): nothing was rewritten. If a hidden old-layout assertion
  exists in a path the grep missed, the full-suite green run would have caught it.
- **`git`-dependent tests (TC-031/TC-032).** Four tests shell out to `git diff main`.
  They require `main` to be present locally (it is — confirmed) and `git` on `PATH`.
  In a CI shallow-clone without `main`, `git diff main` would error; the tests would
  then fail loudly rather than pass silently — acceptable (a missing baseline is a
  real "cannot verify" condition, not a false green).

## 6. Pending items

- None for this increment. All 5 TCs (TC-011/029/030/031/032) are implemented and
  passing.
- **Deferred to increment 12 (next, not started):** TC-016 / TC-016-S — the
  27-baseline `pytest-textual-snapshot` matrix and the layout-drift guard; the
  119/120-column boundary check; the optional empty-state snapshot baseline.
- **Cross-functional note for `qa-reviewer`:** the TC-030 keymap-vs-implementation
  reconciliation (Risk 1) is a design judgement folded into this no-regression
  increment. If the qa-reviewer reads LLR-013.2 as requiring per-screen `Binding`
  objects, that is a keymap-proposal/implementation question for the `architect`, not
  a test fix.

## 7. Suggested next task

**Increment 12 — Snapshot test increment (`pytest-textual-snapshot`).** Build the
27-baseline snapshot matrix (4 restyled screens × {compact, comfortable} × {80×24,
120×30, 160×40} = 24, plus the 3 scaffolds at 120×30 = 3), register/use the
`snapshot` pytest marker, render baselines **only** against the public synthetic
fixtures (`examples/case_00_public/` + the `tests/conftest.py` generators — LLR-007.2,
S-2), and add the 119/120-column breakpoint check. Per the increment plan this is the
last increment of the batch; it must run only after this increment's green suite is
confirmed (it is). Flag the snapshot baselines for `security-reviewer` (S-2 — no
client data in any committed `.svg`).
