# Increment 01 — batch-48 · Patch Editor BIG · US-P1 EASY layer (R-TUI-075 / HLR-075)

> Branch `feat/batch-48-patch-big` @ base `6551aed`. Scope: **LLR-075.1 / 075.2 / 075.3 / 075.4 / 075.6**.
> **Carries the batch's HIGH security fix (BL-1 / LLR-075.6) — a live vulnerability in shipped code.**
> Out of scope, untouched: chips (Inc-2) · glyph (Inc-3) · card (Inc-7).

---

## 1. What changed

**BLUF: two live, proven-exploitable `Text.from_markup` sinks are now closed, and the Patch Editor's
three windows self-describe.** The spec named one sink (BL-1, the entries table). Phase 3 found a
**second** on the same gate-blocking path (`#patch_variant_select`) — see §5 R-NEW-1.

1. **LLR-075.6 ★★ (the HIGH fix).** `refresh_entries` now constructs **all five** entries cells as
   Rich `Text` via `safe_text` — `kind_text`, `address_text`, `value_text`, **`status_text`**, and
   **`linkage_text`** — regardless of role assignment. Previously every cell went to
   `DataTable.add_row()` as a bare `str`, and Textual's `default_cell_formatter`
   (`_data_table.py:220-221`) sets `possible_markup=True` → `Text.from_markup(content)`. `app.py` and
   `change_service.py` are **unchanged**: the fix lands at the panel's render boundary, the call site
   closest to the sink.
2. **LLR-075.2.** The three role cells carry their styles — `Kind` `PURPLE`, `Address` `CYAN`,
   `Value / bytes` `VALUE`. `Status`/`Linkage` carry **no role style but are still `Text`** — that
   separation is the point (see §5).
3. **LLR-075.1.** Border titles `¹PATCH SCRIPT` / `²CHECKS` / `³JSON EDIT` + **live** subtitles:
   SCRIPT = `N entries` (from `refresh_entries`), CHECKS = `no run yet` → `N checked` (from
   `refresh_check_results`), JSON = `v2 schema`. Follows batch-47's `app.py:1651-1656` precedent.
4. **LLR-075.3 / 075.4.** NEW `#patch_variant_scope_line` renders `Variant <id> · Scope <label>`.
   The scope was previously legible **only** from `#patch_execute_scope_button`'s own label. Built
   with `insight_style.label_value` (literal `append`), so the project-file-derived variant id is
   C-17-safe by construction.

**A5 re-confirmed:** `refresh_entries` applies no row-level style override → the accents ARE visible
on the live table. No §6.5 Amendment E-style relaxation needed.

**Placement refinement WITHIN LLR-075.3's stated container — NOT a deviation, and nothing was reparented.**
*(Corrected after Inc-1 code review F3; the original wording below was wrong on both counts and is retracted.)*
The line is nested inside `#patch_execute_row` — a **direct child of `#patch_pane_variant`** — adjacent to
the button whose scope it mirrors. LLR-075.3 says "**inside** `#patch_pane_variant`", which is a
**containment** claim, and containment is satisfied; the LLR never said "direct child". Nor is this a
reparent: `#patch_variant_scope_line` is a **widget created in this increment** (LLR-075.3 itself reads
"*NEW — created in Phase 3 … an ADDED id; no existing id moves*"). There is no prior placement to move
*from* — only a first choice that was wrong.

Direct-child placement was **rejected** because `test_tui_patch_variant.py:429` pins `#patch_pane_variant`'s
**direct-child list** to exactly `[patch_variant_row, patch_execute_row]` (R-PATCH-VARIANT-SELECT-001,
C-13-MEASURED). The census caught it as a real RED. The fix landed **in source, not in the oracle** — the
alternative was relaxing a pinned, measured, requirement-traced contract to accommodate a placement **no
requirement asked for**, i.e. trading a real contract for an arbitrary implementation detail.

⚠ **No §6.5 amendment needed.** Logging a non-deviation in the amendment ledger dilutes it — the ledger's
worth is that every entry is a real departure.

**Not done (spec says add border titles; it does not say remove the old ones):** each window still
carries its `Label(..., classes="patch-window-title")` — `test_tui_patch_layout.py:583` asserts that
class exists per window. Title text is now duplicated (border + in-body label). Flagged §6.

---

## 2. Files modified — **3** (cap 5, target 4 ✓)

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel`: the C-17 fix in `refresh_entries`; role styles; border titles + live subtitles (`compose`, `_set_window_subtitle`, `refresh_check_results`); the variant/scope line (`compose`, `_refresh_variant_scope_line`, `on_mount`, `set_variants`, scope-button handler); **the R-NEW-1 `Select` fix in `set_variants`** |
| `tests/test_tui_patch_big.py` | **NEW** — AT-075a/b/c/d★★/e★★ + the RED ledger |
| `tests/test_tui_snapshot.py` | `_batch48_patch_drift_marks` + wired into `_SCAFFOLD_CELLS` |

`change_service.py` **not needed** — the taint origin (`value_text = entry.value`) is left as-is; the
fix belongs at the render boundary. **Zero SVG baselines touched** (no local regen — forbidden).

---

## 3. How to test

```bash
pytest -q tests/test_tui_patch_big.py                       # the HLR-075 ATs
pytest -q tests/test_engine_unchanged.py                    # C-27 arm 1
pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032"   # C-27 arm 2
pytest -q tests/test_tui_patch_layout.py                    # C-26: the 48-id census
pytest -q tests/test_tui_patch_editor_v2.py                 # C-26: 32-hit file, MUST need no edit
pytest -q tests/test_tui_snapshot.py                        # C-22
python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_big.py tests/test_tui_snapshot.py
```

**Reproduce the RED** (the headline evidence): `git stash` the `screens_directionb.py` change and run
`pytest -q tests/test_tui_patch_big.py::test_at075e_c17_entries_table`.

---

## 4. Test results — **executed, pasted verbatim**

### 4.1 ★ THE RED — AT-075e against the vulnerable HEAD (`6551aed`, pre-fix)

```
E   rich.errors.MarkupError: closing tag '[/nope]' at position 0 doesn't match any open tag
C:\...\rich\markup.py:167: MarkupError
=========================== short test summary info ===========================
FAILED tests/test_tui_patch_big.py::test_at075e_c17_entries_table - rich.erro...
1 failed in 2.49s
```

The captured traceback locals prove the taint path end-to-end — **bare `str` cells reaching the sink**:

```
│ ordered_row = ['string', '0x120', '[/nope]', 'unvalidated-no-image / fault', '-']
│ textual\widgets\_data_table.py:221 in default_cell_formatter
│   ❱ 221     text = Text.from_markup(content, end="")
│   content = '[/nope]'   possible_markup = True
```

Direct probe of the sink at `textual==8.2.8` — **the spec's exploit table reproduces exactly**:

```
'[red]PWNED[/red]'              -> type= Text | plain= 'PWNED' | spans= [Span(0, 5, 'red')]
'[link=http://evil]click[/link]'-> type= Text | plain= 'click' | spans= [Span(0, 5, 'link http://evil')]
'[/nope]'                       -> RAISES MarkupError : closing tag '[/nope]' ... doesn't match any open tag
'\x1b[31mX\x1b[0m'              -> type= Text | plain= '\x1b[31mX\x1b[0m' | spans= []
'sensor[unclosed'               -> type= Text | plain= 'sensor[unclosed' | spans= []
```

⇒ style injection · **link injection from file data** · **file-triggered crash**. **MJ-6 independently
confirmed**: ANSI and `sensor[unclosed` render *identically* to the safe path — carried as regression
fixtures only, **not credited as counterfactuals**.

### 4.2 GREEN after the fix

```
$ python -m pytest -q tests/test_tui_patch_big.py
.........                                                                [100%]
9 passed in 7.37s
```

### 4.3 C-27 dual-guard — **0 frozen diff**

```
$ python -m pytest -q tests/test_engine_unchanged.py
1 passed in 0.06s
$ python -m pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032 or engine_unchanged"
7 passed, 168 deselected in 0.50s
$ git diff --name-only 6551aed -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
      s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

### 4.4 C-26 reverse census — every touched symbol

Touched: `refresh_entries` · `set_variants` · `refresh_check_results` · `compose` · `on_mount` ·
`on_button_pressed` (scope arm). New: `_set_window_subtitle` · `_refresh_variant_scope_line` ·
`#patch_variant_scope_line`.

| File | Result |
|---|---|
| `test_tui_patch_layout.py` (48 ids) | **9 passed** |
| `test_tui_patch_editor_v2.py` (32 hits) | **52 passed — NO edit** ✓ |
| `test_tui_variants.py` + `test_tui_patch_variant.py` + `test_undo_redo_ux.py` + `test_variant_execution.py` + `test_before_after_report.py` + `test_tui_patch_big.py` | **61 passed** |
| `test_tui_directionb.py` + `test_tui_patch_layout.py` + `test_tui_report_filter_surface.py` + `test_tui_memory_patch.py` + `test_loadfilescreen_input.py` + `test_capped_text_area.py` + `test_change_service.py` | **267 passed** |

**The census earned its keep:** `test_tui_patch_variant.py::test_tc_035_2_variant_group_above_execute_row`
went RED on the first placement (`#patch_pane_variant`'s pinned direct-child list). Fixed by **nesting the
new widget one level deeper — in source, not by editing the test.** The contract still discriminates: it
would go RED again if the compose order flipped. Nothing was weakened, and nothing was reparented (see §1).

### 4.5 C-22 snapshot — **per-cell prediction MEASURED, not reasoned**

Full tc016s run **before** adding the mark:

```
2 snapshots failed. 27 snapshots passed.
FAILED ...[patch-comfortable-80x24]
FAILED ...[patch-comfortable-120x30]
2 failed, 30 passed
```

**Exactly the 2 patch cells drift; no other cell moved** ⇒ containment patch-only, **C-28 shared-chrome
clean** (no footer/header/rail binding changed). After `_batch48_patch_drift_marks`:

```
$ python -m pytest -q tests/test_tui_snapshot.py
30 passed, 2 xfailed, 1 warning in 46.92s
```

**Per-cell WHY** — the scaffold loads **no change document**, so `refresh_entries([])` renders zero
rows: **the role styles and the `Text` cells are NOT visible in these cells.** What repaints is
(a) the three border titles, (b) the three subtitles (`0 entries` / `no run yet` / `v2 schema`),
(c) `#patch_variant_scope_line` (`Variant - · Scope active variant`).

**Regen = a batch-48 post-merge follow-up PR in canonical CI only** (`snapshot-regen.yml`,
`textual==8.2.8`). **Local regen NOT performed** (`reference_snapshot_regen_env`).

### 4.6 ruff

```
$ python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_big.py tests/test_tui_snapshot.py
All checks passed!
```

### 4.7 Full suite (`-m "not slow"`) — ONE run (C-19)

```
$ python -m pytest -q -m "not slow"
1456 passed, 2 skipped, 20 deselected, 5 xfailed, 1 warning in 879.51s (0:14:39)
```

**0 failed. 0 regressions.**

⚠ **PLAN.md's recorded baseline (`1416 passed / 0 failed / 3 xfailed`) is STALE** — it does not
reconcile, so I measured the real base rather than assert the delta:

```
$ (at base 6551aed, my 3 changes removed)  python -m pytest -q -m "not slow" --collect-only
1454/1474 tests collected (20 deselected)
$ (on branch)                              python -m pytest -q -m "not slow" --collect-only
1463/1483 tests collected (20 deselected)
$ python -m pytest -q tests/test_tui_patch_big.py --collect-only
9 tests collected
```

**Reconciliation — exact, every test accounted for:**

| | collected | passed | skipped | xfailed |
|---|---|---|---|---|
| base `6551aed` | 1454 | 1449 | 2 | 3 |
| branch (Inc-1) | **1463** | **1456** | 2 | **5** |
| delta | **+9** = my 9 new ATs | **+7** = +9 new − 2 patch cells now xfail | 0 | **+2** = the 2 patch cells |

⇒ collection delta is **exactly** the new AT file; the passed/xfail movement is **exactly** the
predicted snapshot drift. **Nothing else moved.** PLAN.md's baseline row needs correcting to
`1454 collected / 1449 passed / 2 skipped / 3 xfailed` (pending item 7).

---

## 5. Risks

| # | Risk | Sev | Disposition |
|---|---|---|---|
| **R-NEW-1** ⚠ | **A SECOND live sink, NOT in the spec: `#patch_variant_select`.** `app.py:3740-3742` maps each project `variant.variant_id` to **both** the option label and its value; Textual's `SelectCurrent.update(prompt)` (`_select.py:615`) hands the bare `str` label to a markup-enabled `Static` → `Content.from_markup` (`visual.py:103`). **Measured at 8.2.8: variant id `[red]PWNED[/red]` rendered `plain='PWNED'` + injected `Span(0,5,'red')`; `[/nope]` and `[link=…]` each raised `MarkupError` out of `set_variants`** (**F3 correction, Inc-1b** — this row previously claimed `[link=…]` *injected a link* at the Select. **That is false, and it was OUR claim**: measured, it **raises `MarkupError`** — Textual's `Content.from_markup` grammar requires a quoted value and rejects the bare URL. Link **injection** is real only on the **DataTable** path, whose engine is `rich.Text.from_markup` — a different grammar. See the Inc-1b note on the two engines.) | **HIGH** | **FIXED** in `set_variants` (literal `Text` labels; `app.py` unchanged). **In scope by AT-075d's own text** — the AT names `set_variants` as its ingress and asserts "no `MarkupError`", so this sink sat directly on the gate-blocking path. Dodging it would have meant weakening AT-075d — the exact partial-fix trap BL-1 names. **→ security-reviewer: answered — the class is 3 sites wide, 2 were still live in `main`; both closed in Inc-1b.** |
| R-1 | Snapshot RED — the 2 patch cells are strict oracles | med | Marked `xfail(strict=False)`, measured not assumed; regen follow-up budgeted |
| R-2 | The partial-fix trap (3 roles / 5 columns) | high | **Closed** — AT-075e clause (i) asserts `isinstance(Text)` on **all five**; `status`/`linkage` are `Text` with no style |
| R-3 | Tautology — `== payload` passes on the vulnerable code | high | **Closed** — clause (i) is load-bearing; clause (iv) (`[/nope]`) discriminates the crash class |
| R-4 | C-7 panel purity | low | **Held** — 0 `self.app`, 0 `mem_map`, 0 service imports added; `_SCOPE_LABELS` is the panel's own vocabulary |
| R-5 | `_nodes`/`_context` shadowing | low | **N/A** — no new Widget subclass; the line is a stock `Static` |
| R-6 | C-29 geometry (the line costs 1 row in a docked group) | med | `test_tui_patch_layout.py` **9 passed** — reachable-under-scroll holds at 80×24 + 120×30 with the line mounted. Not a full two-axis measure (that is LLR-075.5, and the card is the real consumer — Inc-7) |

---

## 6. Pending items

1. **R-NEW-1 → security-reviewer** (above). Recommend a follow-up sweep for file-derived
   `Select`/`OptionList` labels app-wide.
2. **Snapshot regen follow-up PR** (canonical CI) — 2 patch cells; retires `_batch48_patch_drift_marks`.
   Will accumulate more cells across Inc-2..7 → regen **once**, at batch end.
3. **Duplicate window titles** — border title `¹PATCH SCRIPT` + in-body `Label("PATCH SCRIPT")`.
   Removing the Label needs a `test_tui_patch_layout.py:583` edit → **operator call**, deferred.
4. **`REQUIREMENTS.md` R-TUI-075 row** — Phase 6.
5. **LLR-075.5** (C-29 two-axis, both regimes) — deferred to the card increment, per the spec's own
   "with the card mounted" instruction.
6. **Backlog carry (spec-noted, NOT touched):** the false `sensor[unclosed` counterfactual claim at its
   batch-47 origin, `tests/test_tui_a2l_detail.py:24-26,49` — my probe **independently confirms it is
   false**. Out of scope; would widen the census.
7. **PLAN.md test-ledger baseline is stale** (`1416 passed / 3 xfailed`); measured real base @ `6551aed`
   = `1454 collected / 1449 passed / 2 skipped / 3 xfailed`. Correct it so later increments reconcile
   against a true number. **Not edited from this increment** — PLAN.md is the orchestrator's artifact.

---

## 7. Suggested next task

**Inc-2 — HLR-076 chip-button CSS** (`styles.tcss` + `classes=` in `compose` + `tests/test_tui_patch_chips.py`):
the batch-47 carry, per the US-P1 → {P2,P3,P4,P6} → P5 dependency order. Its AT-076b (the C-30 leak
probe) is what makes the "C-30 = N/A" verdict falsifiable.

**Before Inc-2, please rule on:** R-NEW-1's disposition (§5) and pending item 3.

---

## Evidence checklist

- [x] **Tests/type checks/lint pass** — full suite `1456 passed, 2 skipped, 5 xfailed` / **0 failed** (§4.7, reconciled exactly); `test_tui_patch_big.py` 9 passed; C-26 census 52 + 61 + 267 + 9 passed; snapshots 30 passed / 2 xfailed; ruff `All checks passed!`
- [x] **RED captured FIRST on the vulnerable code** — §4.1, `MarkupError` + the bare-`str` `ordered_row` locals + the reproduced exploit table
- [x] **No secrets** in code or output — fixtures are synthetic (`0x100` + `AA BB`); no `.env`, key, or token read or printed
- [x] **No destructive commands** — read-only + `Edit`/`Write` in-worktree; no local snapshot regen (forbidden); no branch switch; no commit/push
- [x] **File count within cap** — **3** of 5 (target 4)
- [x] **Review packet attached** — this document
- [x] **C-27 dual-guard: 0 frozen diff** — §4.3
- [x] **C-26 census run and reported** — §4.4, incl. a real RED caught and fixed in **source**, not in the test
- [x] **C-22 per-cell drift predicted + measured** — §4.5
- [x] **Uncertainty surfaced, not hidden** — R-NEW-1 (a **HIGH finding outside the spec**) is reported in full with its measurement, not quietly folded in; the LLR-075.3 placement refinement is recorded (and, per code-review F3, **corrected** — it is neither a deviation nor a reparent, so no §6.5 amendment); PLAN.md's stale baseline is reported rather than restated, with its cause recorded as **UNKNOWN** rather than back-filled with a story that does not reconcile (the orchestrator's "29 retired xfails" explanation was checked and is false: 1416+29=1445≠1449)

> **Gate note (not a checklist failure):** every check above passes. **Two items need an operator/
> security ruling before this increment merges** — R-NEW-1's disposition + scope (§5) and pending
> item 3 (duplicate window titles). Stopping at the boundary.

---
---

# Increment 01b — close the rest of the C-17 `Select` class + two corrections

> Branch `feat/batch-48-patch-big` @ Inc-1 `faa65cb`. **Operator/orchestrator ruling on R-NEW-1's
> §6 pending item 1:** the security review probed **every** `Select` option-label site against the
> installed `textual==8.2.8` and measured the class at **3 sites — two still LIVE in `main`**.
> Both folded in: each is a one-line fix, one sits in the file Inc-1 already edits, and leaving a
> **measured, crashing HIGH in `main`** to preserve a scope boundary is the wrong trade.
> Scope unchanged otherwise: chips (Inc-2) · glyph (Inc-3) · card (Inc-7) untouched.

## 1b.1 What changed

**BLUF: the C-17 `Select`-label class is now CLOSED at all three of its sites, and the AT that
covers them no longer passes by accident.** Inc-1 fixed one of three; the review found the other two.

| # | Site | Payload origin | State before Inc-1b |
|---|---|---|---|
| 1 | `#patch_variant_select` (`PatchEditorPanel.set_variants`) | project-file `variant_id` (`app.py:3744`) | fixed in Inc-1 |
| 2 | **`#patch_doc_file_select`** (`set_change_files`, `:2614`) | **a FILENAME on disk** — `app.py:3693` → `_scan_patch_change_files()` over `workarea/patches/` | **LIVE** |
| 3 | **`#diff_select_a` / `#diff_select_b`** (`AbDiffPanel.set_variants`, `:3903`) | the SAME project-file `variant_id`s (`app.py:3511`) | **LIVE** |

1. **Fix 1 — `set_change_files`.** Literal `safe_text` labels, identical shape to the `set_variants`
   precedent. The option **value** stays a bare `str`: the `Changed` handler forwards it and never
   renders it. Site 2's payload is the sharpest of the three — **anyone who can drop a file into the
   work area names this label**.
2. **Fix 2 — `AbDiffPanel.set_variants`.** Same one-line fix; the trailing `(external path below)`
   sentinel is wrapped too, so the list is uniformly `Text` and a future edit cannot reintroduce a
   `str` by copying the neighbour.
3. **Fix 3 (F4, MEDIUM) — the guard was an ACCIDENT.** See §1b.2. NEW **AT-075f**, 3 tests × 5
   payloads, asserting the `SelectCurrent` `#label` **visual** at all three sites through each one's
   real ingress.
4. **Fix 4 (F3, LOW) — an overstated claim, corrected at both prose sites.** See §1b.3.

**`screens.py:1057` — probed, NOT live, NOT touched.** It already carries `escape_markup(name)` under
a C-15 probe comment dated 2026-07-10. It is the precedent, not a bug.

## 1b.2 F4 — why AT-075d guarded site 1 by accident

AT-075d reads only `#patch_variant_scope_line`; it never observes the Select's label. It caught the
Select sink **only via the crash path** — `[/nope]` / `[link=…]` raise, so the test errors out.
**`[red]PWNED[/red]` does not raise.** On a `str` label it silently mangles `plain` → `'PWNED'` and
injects `Span(0,5,'red')` — **and AT-075d still passes**. A regression to `str` labels would have
shipped the span-injection class with a green gate. AT-075f asserts `plain == payload` verbatim **and**
`spans == []` directly on the label, which is the clause that makes the crash-free payload visible.

## 1b.3 F4/F3 — TWO markup engines, different grammars

The Inc-1 §5 row and `test_tui_patch_big.py:41-42` both claimed `[link=…]` **"injected a link from
project-file data"** *at the Select*. **False — and it was our claim, so it is corrected, not carried.**

| Engine | Path | `[link=http://evil]click[/link]` | `[red]PWNED[/red]` |
|---|---|---|---|
| `rich.text.Text.from_markup` | DataTable cells (AT-075e) | **injects** `Span(0,5,'link http://evil')` | injects `Span(0,5,'red')` |
| `textual.content.Content.from_markup` | `Static` / Select labels (AT-075f) | **raises `MarkupError`** — the grammar requires a **quoted** value | injects `Span(0,5,'red')` |

Link **injection** is real only on the DataTable path (AT-075e's traceback confirms it). **Exposure is
identical on both engines; only the consequence differs.** Conflating them mis-scopes the next sweep —
a reviewer who expects "link injection" as the tell would clear a live `Static` sink that merely crashes.

## 1b.4 Files modified — **3** (cumulative Inc-1 + Inc-1b: **4** of cap 5)

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | Fix 1 (`set_change_files`) + Fix 2 (`AbDiffPanel.set_variants`) + the F3 docstring correction |
| `tests/test_tui_patch_big.py` | NEW AT-075f (3 sites × 5 payloads) + the F3 module-docstring correction |
| `.dev-flow/…/increment-01.md` | this section + the §5 R-NEW-1 correction |

**No test needed editing.** `tests/test_tui_snapshot.py` untouched this increment.

## 1b.5 ★ THE RED — captured BEFORE the fixes, on the live code

```
$ python -m pytest -q tests/test_tui_patch_big.py -k "at075f"
FAILED ...::test_at075f_c17_patch_doc_file_select_label[[red]PWNED[/red]]
FAILED ...::test_at075f_c17_patch_doc_file_select_label[[link=http://evil]click[/link]]
FAILED ...::test_at075f_c17_patch_doc_file_select_label[[/nope]]
FAILED ...::test_at075f_c17_ab_diff_select_labels[[red]PWNED[/red]]
FAILED ...::test_at075f_c17_ab_diff_select_labels[[link=http://evil]click[/link]]
FAILED ...::test_at075f_c17_ab_diff_select_labels[[/nope]]
6 failed, 9 passed, 9 deselected in 13.09s
E   textual.markup.MarkupError: closing tag '[/nope]' does not match any open tag
    textual\markup.py:320: MarkupError
```

**6 failed = exactly the 2 live sites × the 3 discriminators.** The 9 passed = site 1 (fixed in Inc-1,
all 5 payloads) + the 2 MJ-6 regression fixtures on each live site — which, per MJ-6, render
identically on both paths and are **not** credited as counterfactuals.

**The F4 evidence — the payload that does NOT crash:**

```
$ python -m pytest -q "tests/test_tui_patch_big.py::test_at075f_c17_patch_doc_file_select_label[[red]PWNED[/red]]"
line = Content('PWNED', spans=[Span(0, 5, style='red')])
E   AssertionError: #patch_doc_file_select: the hostile option label '[red]PWNED[/red]' must render
    VERBATIM; got 'PWNED'.
E   assert 'PWNED' == '[red]PWNED[/red]'
E     - [red]PWNED[/red]
E     + PWNED
1 failed in 1.24s
```

`Content('PWNED', spans=[Span(0, 5, style='red')])` — **no exception**. This is the injection AT-075d
is structurally blind to, and it is why F4 was worth fixing rather than noting.

**Direct probe of all three sites, `textual==8.2.8` — BEFORE (site 1 already fixed):**

```
=== #patch_variant_select ===
  '[red]PWNED[/red]'   -> plain='[red]PWNED[/red]' spans=[]        <- Inc-1 fix holding
  '[link=…]'           -> plain='[link=http://evil]click[/link]' spans=[]
  '[/nope]'            -> plain='[/nope]' spans=[]
=== #patch_doc_file_select ===   *** LIVE ***
  '[red]PWNED[/red]'   -> plain='PWNED' spans=[Span(0, 5, style='red')]
  '[link=…]'           -> RAISES MarkupError: Expected markup value (found '://evil]click[/link]').
  '[/nope]'            -> RAISES MarkupError: closing tag '[/nope]' does not match any open tag
=== #diff_select_a ===           *** LIVE ***
  '[red]PWNED[/red]'   -> plain='PWNED' spans=[Span(0, 5, style='red')]
  '[link=…]'           -> RAISES MarkupError: Expected markup value (found '://evil]click[/link]').
  '[/nope]'            -> RAISES MarkupError: closing tag '[/nope]' does not match any open tag
```

That `Expected markup value` is the F3 correction, measured: `Content.from_markup` **rejects** the
bare URL. It does not inject a link.

**AFTER — all three sites, all three discriminators, clean:**

```
=== #patch_variant_select ===  '[red]PWNED[/red]' -> plain='[red]PWNED[/red]' spans=[]
                               '[link=…]'         -> plain='[link=http://evil]click[/link]' spans=[]
                               '[/nope]'          -> plain='[/nope]' spans=[]
=== #patch_doc_file_select ===  (identical — verbatim, spans=[], 0 raises)
=== #diff_select_a ===          (identical — verbatim, spans=[], 0 raises)
```

## 1b.6 GREEN

```
$ python -m pytest -q tests/test_tui_patch_big.py
........................                                                 [100%]
24 passed in 20.98s
```

**24 = Inc-1's 9 + AT-075f's 15** (3 sites × 5 payloads). Collection delta is exactly the new AT.

## 1b.7 C-26 reverse census — **the AbDiffPanel fold cost ZERO**

Touched symbols: `set_change_files` · `AbDiffPanel.set_variants`. Reverse-grepped
`AbDiffPanel|set_variants|diff_select_a|diff_select_b|set_change_files|patch_doc_file_select|patch_variant_select`
across `tests/` → **8 files**, every one run in **ONE** invocation:

```
$ python -m pytest -q tests/test_tui_diff_compare_realpath.py tests/test_tui_diff_screen.py \
    tests/test_tui_directionb.py tests/test_tui_patch_big.py tests/test_tui_patch_editor_v2.py \
    tests/test_tui_patch_layout.py tests/test_tui_patch_variant.py tests/test_tui_variants.py
293 passed in 304.10s (0:05:04)
```

**The two diff-screen files — `test_tui_diff_screen.py` and `test_tui_diff_compare_realpath.py`, the
files the fold newly put at risk — pass UNEDITED**, as does `test_tui_patch_variant.py`.
**Answer to the standing question: taking `AbDiffPanel` cost us nothing.** The reason is structural,
not luck: the option **value** is unchanged (still the bare `str`), and `_selected_variant` compares
against the value, never the label. Only the label — the render side — moved.

## 1b.8 C-27 dual-guard — **0 frozen diff**

```
$ python -m pytest -q tests/test_engine_unchanged.py                       1 passed in 0.07s
$ python -m pytest -q tests/test_tui_directionb.py -k "test_tc031 or test_tc032 or engine_unchanged"
                                                                            6 passed, 168 deselected
$ git diff --name-only 6551aed -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
      s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
(empty)
```

## 1b.9 C-22 snapshot — **NO new drift**

```
$ python -m pytest -q tests/test_tui_snapshot.py
30 passed, 2 xfailed, 1 warning in 49.71s
```

**Identical to Inc-1** — still exactly the 2 patch cells marked, and **no diff or patch cell newly
drifts**. Measured, not reasoned. **WHY it does not repaint:** the scaffold loads no project, so
`set_variants([])` / `set_change_files([])` leave both dropdowns on the blank prompt — no option label
is painted at all. `(external path below)` is now a `Text` but renders byte-identical.
**No cells marked. No local regen** (`reference_snapshot_regen_env`).

## 1b.10 ruff

```
$ python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_big.py
All checks passed!
```

## 1b.11 Risks

| # | Risk | Sev | Disposition |
|---|---|---|---|
| R-1b-1 | Scope fold beyond the increment boundary | med | **Accepted, operator-ruled.** 2 one-line fixes; +1 file over Inc-1 (**4** of cap 5). The alternative was a measured, crashing HIGH left live in `main` |
| R-1b-2 | `AbDiffPanel` is a different screen → wider blast radius | med | **Closed by measurement** — §1b.7, 293 passed, both diff-screen files unedited; the value side is untouched by construction |
| R-1b-3 | A 4th `Select`/`OptionList` site exists that the probe missed | low | The review probed **every** `Select` option-label site. **`OptionList` was NOT swept** — see pending 1b-2 |
| R-1b-4 | AT-075f is tautological | high | **Closed** — it reads `SelectCurrent`'s `#label` **`.visual`** (the real render path), not the label the test passed in; and the RED is `Content('PWNED', spans=[Span(0,5,'red')])`, i.e. it demonstrably fails on the live code |

## 1b.12 Pending items (Inc-1 §6 items 2-7 all still stand)

1. **§6 item 1 is now CLOSED** — the `Select` sweep is done, 3/3 sites fixed, AT-075f covers them.
2. **`OptionList` option labels were NOT swept** (only `Select`). Same `Content.from_markup` sink
   shape. **Recommend a follow-up sweep** — out of scope here, and it would widen the census.
3. Inc-1 §6 items 2-7 carry unchanged (snapshot regen at batch end · duplicate window titles →
   **still needs the operator call** · REQUIREMENTS.md → Phase 6 · LLR-075.5 → Inc-7 · the
   batch-47 `sensor[unclosed` false-counterfactual carry · PLAN.md's stale baseline).

## 1b.13 Evidence checklist

- [x] **Tests/lint pass** — `test_tui_patch_big.py` **24 passed**; C-26 census **293 passed**; snapshots **30 passed / 2 xfailed**; ruff **All checks passed!**. Counts from ONE run each. **Full `-m "not slow"` suite NOT re-run this increment** — stated, not hidden; §4.7's 1456-pass run predates AT-075f (+15) and the 2 source fixes. The 8-file census + snapshots cover every touched symbol's reverse hits
- [x] **RED captured FIRST, on the live code** — §1b.5: 6 failed = 2 live sites × 3 discriminators, plus the non-crashing `Content('PWNED', spans=[Span(0,5,'red')])` that is the whole F4 point
- [x] **No secrets** — payloads are synthetic markup strings; no `.env`/key/token read or printed
- [x] **No destructive commands** — read-only + `Edit` in-worktree; no branch switch, no commit, no push, no local snapshot regen
- [x] **File count within cap** — 3 this increment; **4 cumulative** of 5
- [x] **C-27 dual-guard: 0 frozen diff** — §1b.8, all three arms
- [x] **C-26 census run and reported** — §1b.7, incl. the direct answer on `AbDiffPanel`'s cost
- [x] **C-22 drift measured** — §1b.9, no new cells, none marked
- [x] **Uncertainty surfaced** — the F3 correction (§1b.3) retracts **our own** overstated claim rather than carrying it; the un-swept `OptionList` surface is flagged (R-1b-3 / pending 1b-2); the un-re-run full suite is declared
