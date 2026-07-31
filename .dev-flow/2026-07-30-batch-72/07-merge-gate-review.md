# Merge-gate review — PR #166 — batch 2026-07-30-batch-72

> Final independent PR-level review of the **whole merged diff vs `main`**
> (`git diff origin/main...HEAD`, 9 commits, 30 files, `origin/main` = `31d87d0`, `HEAD` = `33edd1d`).
> Reviewer: `qa-reviewer`, invoked under the kickoff grant's merge condition.
> Subject is the diff, not any single increment. The full suite was **not** re-run (collected by the
> orchestrator: `2370 passed, 2 skipped, 21 deselected, 3 xfailed`, 29 snapshots, exit 0); every
> claim below rests on a targeted run, a `--collect-only`, a grep, a hash, or a `git diff` executed
> in this pass.

---

## BLUF

**No HIGH finding. Recommend MERGE.**

All four gate axes are intact and were verified by execution, not by reading the batch's own
verdicts:

- **Dual traceability is complete.** All 18 nodes (AT-213..219, TC-510..520) exist on disk at
  **exactly** the line `04-validation.md` claims — 18/18, zero drift, zero phantom ids. Every test
  node cited in `REQUIREMENTS.md`'s batch-72 additions resolves (27/27). Targeted run of both
  changed test files: **49 passed**.
- **Zero engine-frozen diffs.** Both guard arms green (7 passed); the diff's intersection with the
  frozen set is **empty** against `origin/main` *and* against the guards' own (stale-but-ancestral)
  `main` ref; `legend.py` is byte-identical by blob hash.
- **No cross-increment regression.** Inc-4 touched no `s19_app/` file. Inc-3's `styles.tcss` hunks
  are CRC-only. An AST-level function diff of `test_crc_designer_view.py` shows **exactly one**
  deletion, twelve additions, and **zero modified surviving functions** — AT-B59-03 and AT-B59-08
  are byte-untouched, and AT-B59-05 is a true deletion, not an edit-into-passing.
- **Gate carries are discharged with two exceptions**, both MEDIUM bookkeeping, neither affecting
  shipped behaviour: **G-001 (F5)** and **G-004** are neither closed on disk nor mirrored into
  `.dev-flow/BACKLOG-CODE.md`. They survive only inside batch-scoped artifacts that get archived.

The batch's own numbers hold under independent measurement. The ledger `2379 − 1 + 18 = 2396`
reconciles against my own `--collect-only` (**2396**) and against the gate run's
`2370 + 2 + 21 + 3 = 2396`. `04-validation.md`'s `styles.tcss` sha256 claim is byte-exact.

I looked specifically for a reason to block and did not find one. Stating that plainly rather than
promoting a LOW to justify the pass.

---

## Check 1 — Dual traceability across the whole diff ✓

### 1a. Every AT and TC maps to a real on-disk node at the claimed line

Executed: AST/regex resolution of every `(name, line)` pair asserted in `04-validation.md` §2 and
§4.1 against the working tree.

```
TC-510  OK  claimed:1665 actual:[1665] test_reflection_row_structure
TC-511  OK  claimed:1700 actual:[1700] test_orphaned_per_toggle_helper_is_deleted
TC-512  OK  claimed:1723 actual:[1723] test_hero_right_column_holds_warnings_only
TC-513  OK  claimed:1751 actual:[1751] test_retired_hero_selectors_absent_from_stylesheet
TC-514  OK  claimed:1858 actual:[1858] test_tc514_every_switch_construction_site_is_on_the_crc_designer
TC-515  OK  claimed: 259 actual:[259]  test_tc515_panes_hold_the_unmodified_render_output
TC-516  OK  claimed: 370 actual:[370]  test_tc516_legend_body_is_the_two_pane_wrapper
TC-517  OK  claimed: 563 actual:[563]  test_tc517_width_regime_flips_class_and_pane_order
TC-518  OK  claimed: 649 actual:[649]  test_tc518_key_pane_never_uses_height_auto
TC-519  OK  claimed: 700 actual:[700]  test_tc519_legend_module_unchanged_vs_main
TC-520  OK  claimed: 756 actual:[756]  test_tc520_legend_focus_traversal_is_pinned_in_both_regimes
AT-213  OK  claimed:1451 actual:[1451] test_reflection_pair_row_shares_one_band_and_drives_the_kernel
AT-214  OK  claimed:1802 actual:[1802] test_at214_no_two_switches_render_vertically_abutting
AT-215  OK  claimed:1527 actual:[1527] test_kat_verdict_demoted_to_self_test_row_under_check
AT-216  OK  claimed: 179 actual:[179]  test_at216_key_pane_shows_warning_row_without_scrolling
AT-217  OK  claimed: 489 actual:[489]  test_at217_floor_stacks_key_above_card_and_key_is_reachable
AT-218  OK  claimed: 419 actual:[419]  test_at218_pipeline_preserved_regression_pin
AT-219  OK  claimed:1593 actual:[1593] test_recompute_surface_ids_are_the_live_markup_census

mismatches: 0
```

Each name resolved to **exactly one** `def` — no duplicate definitions, so C-18's "one AT → one
node" is structurally true, not merely asserted.

### 1b. `01-requirements.md` §5.2 ↔ `04-validation.md` ↔ disk

Cross-read of §5.2's 8 rows (`01-requirements.md:365-373`) against §2/§4.1:

| §5.2 row | AT | TC | Present in §2/§4.1 | On disk |
|---|---|---|---|---|
| US-072-1 / HLR-072-1 | AT-213 | TC-510, TC-511 | ✓ | ✓ |
| US-072-1 / HLR-072-2 | AT-215 | TC-512, TC-513 | ✓ | ✓ |
| US-072-1 / HLR-072-3 | AT-214 | TC-514 | ✓ | ✓ |
| US-072-2 / HLR-072-6 (6.1) | *(covered by AT-217)* | **TC-520** | ✓ | ✓ |
| US-072-2 / HLR-072-5 | AT-216 | TC-515, TC-516 | ✓ | ✓ |
| US-072-2 / HLR-072-6 | AT-217 | TC-517, TC-518 | ✓ | ✓ |
| US-072-2 / HLR-072-7 | AT-218 *(pin)* | TC-519 | ✓ | ✓ |
| US-072-3 / HLR-072-8 | AT-219 | — | ✓ | ✓ |

**Orphan check — clean in both directions.** TC-520 was allocated outside the Phase-1 reservation
block (`TC-510..519`); it carries its own §5.2 row, folded at `d13bb1c`
(`01-requirements.md:369`). Seven HLRs in force, seven with a verifying AT node; the eighth
(HLR-072-4) is withdrawn, and its withdrawal is consistent — see Check 5. No test node in either
changed file carries an AT/TC id absent from §5.2.

### 1c. `REQUIREMENTS.md` citations resolve ✓

Every `::test_*` node named in the batch-72 additions to `R-TUI-100`, `R-LEGEND-MODAL-001` and
`R-LEGEND-GEOMETRY-001` was extracted from the diff and matched against a global index of `def
test_*` across `tests/`:

```
27 cited nodes → 27 resolved.   MISSING: []
```

Including the pre-existing batch-18 nodes those rows re-cite (`test_at023a..f`, `test_tc023_1/2`,
`test_tc_s2_report_and_modal_render_same_rows`). **No coverage is cited from intent.**

### 1d. The nodes actually pass

```
$ python -m pytest -q tests/test_legend_two_pane.py tests/test_crc_designer_view.py
49 passed in 117.11s
```

### 1e. Signed-balance ledger, re-derived

```
$ python -m pytest --collect-only -q | tail -1
2396 tests collected in 0.90s
```

`2379 (base) − 1 (D: AT-B59-05) + 18 (A) = 2396` = my collected count = the gate run's
`2370 + 2 + 21 + 3`. Reconciles exactly. Blocker **Q-9** (stale base of 2358) is closed on evidence,
not on assertion.

---

## Check 2 — Zero engine-frozen diffs ✓

### 2a. Both guard arms (C-27)

```
$ python -m pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py \
      -k "test_engine or tc031 or tc032"
7 passed, 168 deselected in 0.67s
```

Collected node ids, confirming both arms genuinely ran (not silently deselected):

```
test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main
test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main
test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main
test_tui_directionb.py::test_tc031_engine_imports_still_resolve
test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main
test_tui_directionb.py::test_tc032_no_engine_test_function_is_skipped
test_tui_directionb.py::test_tc032_directionb_tests_do_not_monkeypatch_engine_functions
```

Neither arm skipped (the `pytest.skip` path in `test_engine_unchanged.py:155` for a missing `main`
ref did not fire — 7 passed, 0 skipped).

### 2b. Independent intersection with the frozen set

```
$ git diff --name-only origin/main...HEAD | grep -E \
    "s19_app/(core|hexfile|range_index)\.py|s19_app/validation/|s19_app/tui/(a2l|mac|color_policy)\.py"
(no output — exit 1)
```

The whole diff's `s19_app/` footprint is exactly three files: `tui/crc_designer_view.py`,
`tui/screens.py`, `tui/styles.tcss`. **Empty intersection.**

### 2c. Guard-base currency — checked, because a stale base can make a guard vacuous

The guards diff against the local `main` ref, not `origin/main`. Those refs **differ**
(`main` = `e47b7da`, `origin/main` = `31d87d0`), so I verified the direction of the staleness:

```
$ git merge-base --is-ancestor main origin/main  → YES (local main is strictly OLDER)
$ git log --oneline origin/main..main            → (empty; no divergence)
$ git diff --name-only main HEAD -- <frozen set> → (empty)
```

Local `main` is an ancestor with zero divergent commits, so diffing against it can only *widen* the
reported change set, never mask one. The frozen intersection is empty against **both** bases. The
guard is not vacuous.

### 2d. `legend.py` byte-identical ✓

```
$ git rev-parse origin/main:s19_app/tui/legend.py HEAD:s19_app/tui/legend.py
1ca69ca19bbac6317dbaa1df18d9c6e77d012bc8
1ca69ca19bbac6317dbaa1df18d9c6e77d012bc8
```

Same blob hash — stronger than an empty textual diff. TC-519 asserts the same property from inside
the suite and passes.

> **Informational, pre-existing, not attributed to this batch.** `tests/test_engine_unchanged.py`'s
> `_ENGINE_PATHS` (`:120-130`) omits `s19_app/tui/color_policy.py`, which `CLAUDE.md` names in the
> frozen set. `tests/test_tui_directionb.py::_ENGINE_PATHS` (`:5479-5489`) **does** include it, so
> the union of the two arms covers the documented set and this batch's clean result is unaffected.
> Recorded only so a future reader does not assume the first arm alone is sufficient.

---

## Check 3 — No cross-increment regression ✓

### 3a. Inc-4 is test + docs only

```
$ git show --name-status --oneline 37474b5
A  .dev-flow/2026-07-30-batch-72/03-increments/increment-004.md
M  REQUIREMENTS.md
M  tests/test_crc_designer_view.py
M  tests/test_legend_two_pane.py
```

**No `s19_app/` file.** Confirmed. The two doc commits (`d13bb1c`, `33edd1d`) touch `.dev-flow/`
only.

### 3b. Inc-1/2 and Inc-3 did not disturb each other

| Commit | Increment | Non-doc files |
|---|---|---|
| `6854234` | Inc-1/Inc-2 (Legend) | `tui/screens.py`, `tui/styles.tcss`, `tests/test_legend_two_pane.py` |
| `a4f2d2e` | Inc-3 (CRC) | `tui/crc_designer_view.py`, `tui/styles.tcss`, `tests/test_crc_designer_view.py` |
| `0169108` | F1/F2 fold | `tests/test_legend_two_pane.py` |

`styles.tcss` is the only shared file. Inc-3's hunks in it are **CRC-only** — one addition
(`.crc-field-sublabel`, `@@ -1995,6 +1995,16 @@`) and one deletion (`.crc-hero`,
`@@ -2041,13 +2051,6 @@`). No legend selector appears in Inc-3's stylesheet diff, and no CRC
selector appears in Inc-1/2's. The legend blocks (`#legend_body`, `#legend_card_pane`,
`#legend_key_pane`, the three `#legend_dialog.legend-narrow` rules) come entirely from `6854234`.

### 3c. `AT-B59-03` / `AT-B59-08` survive unedited; `AT-B59-05` is a deletion ✓

AST-level per-function hash comparison of `tests/test_crc_designer_view.py`,
`origin/main` → `HEAD`:

```
deleted:                  ['test_verdict_hero_center_aligned_in_hero_row']   ← AT-B59-05
added (12):               [_custom_vector_result, _repo_root, _vertically_abutting,
                           test_at214_…, test_hero_right_column_holds_warnings_only,
                           test_kat_verdict_demoted_to_self_test_row_under_check,
                           test_orphaned_per_toggle_helper_is_deleted,
                           test_recompute_surface_ids_are_the_live_markup_census,
                           test_reflection_pair_row_shares_one_band_and_drives_the_kernel,
                           test_reflection_row_structure,
                           test_retired_hero_selectors_absent_from_stylesheet,
                           test_tc514_…]
modified surviving funcs: []          ← the decisive line
```

`modified surviving funcs: []` means **no** surviving function body changed by even one byte —
AT-B59-03 (`:896`, `:908`, `:929`) and AT-B59-08 (`:1276`) are untouched; their line numbers shifted
only by the offset of the deletion. This is a **deletion, not an edit-into-passing**: the function is
gone and `:1004` carries a tombstone comment naming what was removed and why. It is not reachable and
not weakened.

**No dangling reference to the deleted subjects.** Every remaining `crc_live_verify` / `crc-hero`
occurrence in `tests/` and `s19_app/` is either the tombstone or a *negative* assertion of absence
(`test_crc_designer_view.py:1589`, `:1763-1764`, and the discriminating negative at `:1568`).
`REQUIREMENTS.md`'s mentions are the §6.5 Before/After record of the retirement.

---

## Check 4 — Gate-carry discharge ⚠ (2 MEDIUM gaps)

Verified by re-reading each source artifact and then checking the disposition **on disk**, never by
trusting that a corrective pass ran.

### 4a. `02-review.md` — 9 blockers

| # | Finding | Disposition verified in this pass |
|---|---|---|
| **A-1** | HLR-072-2 deletes `#crc_live_verify`, which shipped `AT-B59-05` queries | ✓ **CLOSED.** AT-B59-05 deleted (AST, §3c); LLR-072-2.4 owns the deletion; ledger `D = 1` reconciles |
| **A-2** | HLR-072-6's floor mechanism cannot reach a modal | ✓ **CLOSED with a real mechanism.** `screens.py:1247` `_apply_width_regime`, `:1273` `narrow = width < _LEGEND_NARROW_WIDTH` (`:1036`), `:1280` `body.move_child`, `:1283`/`:1288` reading **`self.app.size.width`**. Pinned by TC-517 + CF-5 |
| **A-3 / Q-1** | G-1 unsatisfiable — 16 abutting pairs vs 1 fixed | ✓ **CLOSED by re-scope.** HLR-072-3 restated `Switch`-only; AT-214 derives its subject set from `screen.query(Switch)` filtered `region.area > 0`, asserts `>= 2` (anti-vacuity) and zero abutting pairs; CF-3 shows it RED on the whole-file revert with a control arm GREEN |
| **A-4** | G-2's acceptance proves wiring, not legibility | ✓ **CLOSED by retirement + carry.** `01-requirements.md:435` / §6.5 R-1; carried to `BACKLOG-CODE.md:172` with the dropped guarantee restated verbatim |
| **Q-4** | AT-216's `Pale yellow` matches a *card* caption | ✓ **CLOSED.** No bare literal survives: `test_legend_two_pane.py:116` derives the string via `LEGEND_TABLE["MAC"]["Pale yellow"][1]` and `:137` documents the Q-4 hazard explicitly |
| **Q-5** | "without scrolling" invisible to `render().plain` | ✓ **CLOSED.** AT-216 asserts painted regions + `max_scroll_y`, not `.plain` |
| **Q-8** | HLR-072-4 has no AT node (C-18 violation) | ✓ **CLOSED by withdrawal.** See Check 5 |
| **Q-9** | test-ledger base stale (2379, not 2358) | ✓ **CLOSED.** Re-derived independently above: 2396 |

### 4b. Re-gate files

`02-regate-qa.md` and `02-regate-architect.md` both record `iterate → APPROVED` on revision 2/3, and
`54c4b29`'s message ("the fold's own blocker caught") is borne out: the re-gate's N-1
(`move_child` ordering), N-3 (AT-216's containment arm), N-4 (`App.query` is screen-scoped) and N-5
(consume the tuple **by name**) are each present on disk — respectively `screens.py:1280`,
`test_legend_two_pane.py:211-220`, the TC-514 grep, and the named-lookup `_recompute`.

### 4c. `increment-001-002-review.md` — F1 (HIGH), F2 (MED), F3–F6 (LOW)

| # | Sev | Verified disposition |
|---|---|---|
| **F1** | HIGH | ✓ **FOLDED.** Clause 0 is on disk — measured at `test_legend_two_pane.py:170-174` (`key_right_of_card`, `panes_share_a_row`) and asserted at `:211-220`. Landed `0169108` |
| **F2** | MED | ✓ **FOLDED.** `test_legend_two_pane.py:666` is a **regex** (`height\s*:\s*auto`), not a substring; the live arm loops `((80,24), (120,30))` at `:681` |
| **F3** | LOW | ✓ **CARRIED** → `BACKLOG-CODE.md:173` |
| **F4** | LOW | ✓ **CARRIED** → `BACKLOG-CODE.md:173` |
| **F5** | LOW | ⚠ **NEITHER.** See MEDIUM-1 |
| **F6** | LOW | ✓ **CARRIED** — and I checked this one specifically because the post-mortem found it un-carried. It is now present and named as the near-escape: `BACKLOG-CODE.md:173`, *"**F6** is the one that nearly escaped — the post-mortem's C-44 sweep found it neither discharged nor carried"* |

### 4d. `04-validation.md` §10 / §10.1

| §10.1 item | Verified |
|---|---|
| 1. Correct `BACKLOG-CODE.md:153`'s false CRC-snapshot premise | ✓ `BACKLOG-CODE.md:155` carries the ⚠ correction with the executed probe |
| 2. Backlog **W-1**, **G-2**, **G-3** with measurements | ✓ `BACKLOG-CODE.md:170`, `:172`, `:171` — each with its number attached |
| 3. G-001..G-003 (unfolded LOW review findings) | ⚠ **G-002/G-003 yes** (`:173`); **G-001 no** — see MEDIUM-1 |
| 4. Escape-key dismissal is pre-existing | ✓ recorded as a note, correctly not raised as new |
| G-004 (CRC floor), action *"Backlog a floor measurement"* | ⚠ **not in `BACKLOG-CODE.md`** — see MEDIUM-1 |
| G-005 / G-006 / G-007 / G-008 | ✓ correctly informational; no backlog entry owed |

`state.json` is current (`current_phase: 6`), the branch is pushed
(`refs/heads/claude/batch-72-design-defect-634a67` = `33edd1d`), so the post-mortem's "entirely
unlanded" and "stale by four phases" carries are themselves discharged.

---

## Check 5 — The withdrawal and the retirements ✓

**HLR-072-4 (`Select` height cap) is withdrawn, and the withdrawal is total.**

```
$ git diff origin/main...HEAD -- s19_app/tui/styles.tcss | grep -E "^[+-].*Select"
(no output)
$ grep -rn "Select" tests/test_legend_two_pane.py tests/test_crc_designer_view.py | grep -i height
(no output)
```

No `Select` rule was touched at all — the pre-existing `#crc_designer_panel Select` block at
`styles.tcss:2009` is untouched — and no test asserts a `Select` height. `01-requirements.md:225`
marks HLR-072-4 struck; §6.5 W-1 (`:441`) records the basis (M-4: `CRC-32/ISO-HDLC` renders
`CRC-32/I`, 8 of 15 chars, no ellipsis); `AT-219` is reallocated to HLR-072-8 (`:455`). The density
finding itself is carried, not buried (`BACKLOG-CODE.md:170`), with the correct lever named (**width,
not height**) and an explicit *"do not re-attempt without re-reading M-4"*.

**G-2 retired / AT-B59-05 deleted.** The deletion is verified as a deletion in §3c above.
`01-requirements.md:435` and §6.5 R-1 (`:460`) record the retirement; `BACKLOG-CODE.md:172` carries
the dropped guarantee in recoverable form. The stylesheet counterpart (`.crc-hero`) is removed and
TC-513 asserts its absence at `test_crc_designer_view.py:1763-1764`.

---

## Check 6 — The D-1 sweep ⚠ (LOW residue)

`D-1` is the batch falsifying its own spec constant: *"`Switch(` has exactly one construction site"*
was true of `origin/main` (`:467`) and became false at HEAD (`:325`, `:327`) because LLR-072-1.2
deleted `_switch_row` and LLR-072-1.1 inlined both toggles. The correction re-derives the property to
**single-module confinement**, which is what TC-514 actually asserts.

Executed sweep across `01-requirements.md`, `00-measurements.md`, `06-docs/`, `04-validation.md`,
`05-postmortem.md`, `PLAN.md` and `REQUIREMENTS.md`:

| File | State |
|---|---|
| `00-measurements.md` | ✓ corrected at `d13bb1c` — M-1 (`:638`) and the §-body note (`:117-125`) both carry the ⚠ supersession |
| `01-requirements.md` | ✓ HLR-072-3 scope note rewritten (`:195-202`); §5.2 row rewritten (`:368`); §6.5 D-1 added — **but see LOW-1** |
| `04-validation.md` | ✓ clean — its "exactly one" instances (`:19`, `:100`, `:179`, `:189`) refer to the AT→node mapping, a different subject |
| `05-postmortem.md` | ✓ clean — §9.1 treats D-1 as its subject |
| `06-docs/` | ✓ clean — `crc-bench-layout.md:138` and `traceability-matrix.md:159` both narrate the correction |
| `REQUIREMENTS.md` | ✓ clean — all "exactly one" hits are unrelated pre-existing requirements |
| **`PLAN.md:104`** | ⚠ still reads *"the Switch completeness argument is now anchored to the single construction site"* |

The C-15(b) failure mode the sweep exists to catch — a correction applied to some files while
another still asserts the old fact — is **partially present but non-load-bearing**. Details under
LOW-1.

---

## Check 7 — Counterfactual ledger ⚠ (LOW)

Six entries in `04-validation.md` §3, traced to their claimed location:

| # | Claimed location | Transcript found |
|---|---|---|
| **CF-1** | Inc-1 §4 | ✓ `increment-001.md:123` — `AssertionError: the key pane Region(0,0,0,0) is not inside #legend_body Region(6,6,107,15)` |
| **CF-2** | *"Orchestrator-run at the F1 fold (`0169108`)"* | ⚠ **not in any increment packet** — see LOW-2 |
| **CF-3** | Inc-4 §4A | ✓ `increment-004.md:369` — `AssertionError: no two Switch widgets may render vertically abutting (G-1); abutting pairs: [('crc_field_refin','crc_field_refout')]` |
| **CF-3b** | Inc-4 §4A.5 | ✓ `increment-004.md` control arm, `2 passed` |
| **CF-4** | Inc-2 §4(a) | ✓ `increment-002.md:118` — `AssertionError: the card pane is starved (the degenerate 'height: auto' key regime)` |
| **CF-5** | Inc-2 §4(b) | ✓ `increment-002.md:131,134` — class still flips, order wrong: `['legend_card_pane','legend_key_pane'] != ['legend_key_pane','legend_card_pane']` |
| **CF-6** | Inc-3 §4 | ✓ `increment-003.md:153` — `AssertionError: with a bogus id in the module tuple _recompute must take its NoMatches early return` |

Every transcript fails on its **own assertion line** (`AssertionError`), not on an `ImportError` /
`NameError` — the `feedback_counterfactual_must_fail_on_its_assertion` bar is met in all six.

**CF-2's hash claim independently verified:**

```
$ python -c "hashlib.sha256(open('s19_app/tui/styles.tcss','rb').read()).hexdigest()"
c65ac445a4f17b861e4c7fdf142759f1cb30293a70d67488a282c925265d8e05
```

Byte-identical to §3's recorded *before* and *restored* hash — the mutation left nothing behind. And
CF-2's product is on disk and passing (clause 0, `:170-174` / `:211-220`), so the finding it
produced is real regardless of where its transcript lives.

---

## Check 8 — `ruff` ✓ (drift confirmed pre-existing)

```
$ python -m ruff check <the 4 changed .py files>
All checks passed!
```

`ruff format --check` reports all 4 would be reformatted. **Confirmed pre-existing and not
attributable to this batch**, by two independent measurements:

```
$ git show origin/main:<file> > /scratch/…   # the 3 files that exist at main
3 files would be reformatted        ← identical at main
$ python -m ruff format --check s19_app tests
171 files would be reformatted, 50 files already formatted   ← repo-wide condition
```

`tests/test_legend_two_pane.py` is new, so it has no `main` counterpart; its drift is three
line-wrap disagreements of the same character as the repo's existing 171 files
(`ruff format --diff` inspected). `ruff format` is not enforced by CI. Reported as found, as
instructed — **not** a batch defect.

---

## Findings

### HIGH — none

I state this plainly rather than promoting a LOW. Nothing in this diff changes shipped behaviour
incorrectly, weakens a test, breaks a frozen boundary, or makes a false claim about coverage.

### MEDIUM-1 — Two `04-validation.md` §10 carries reach no surviving queue

**G-001 (review finding F5)** and **G-004** are neither closed on disk nor present in
`.dev-flow/BACKLOG-CODE.md`.

- **G-001** — `04-validation.md:387` states AT-218's clause 4 is a gate-run property whose
  out-of-node status is unlabelled, proposed action *"one sentence in the test docstring at close."*
  Verified on disk: `tests/test_legend_two_pane.py:420-430` still enumerates **three** clauses and
  says nothing about clause 4. `04-validation.md:404` lists it among items *"owed at close"*; the
  backlog bullet that discharges that line (`BACKLOG-CODE.md:173`) names **F3 / F4 / F6** only.
- **G-004** — `04-validation.md:390`, proposed action *"Backlog a floor measurement"* for the
  unmeasured CRC screen at 80×24. Executed grep over `BACKLOG-CODE.md` for `80x24` / *"floor
  measurement"* / `crc.*floor` → **no hit**.

Both appear in `05-postmortem.md`'s "Open / deferred items → next batch" table (`:412`, `:418`) and
in `06-docs/traceability-matrix.md:134` (`G-072-04`). That is a genuine record — but those artifacts
are batch-scoped and get archived to the vault, while the next batch's Phase 0 reads
`BACKLOG-CODE.md`, which the project's own standing rule calls *the canonical open queue*. The
adjacent row in the same post-mortem table explicitly says *"mirror to `BACKLOG-CODE.md`"* for
W-1/R-1/G-3 and that mirror happened; G-001 and G-004 got no equivalent.

This is the F6 failure mode one level up: F6 escaped the increment gate and was caught by the C-44
sweep; these two escaped the C-44 sweep's own mirroring step.

**Why MEDIUM and not HIGH.** The substance is trivial (one docstring sentence; one measurement).
Neither affects shipped behaviour, and both are recorded in three artifacts, so nothing is
irrecoverable. **Recommended remedy:** append two bullets to the batch-72 carry block in
`BACKLOG-CODE.md`. This does not require re-work, re-testing, or re-gating and can be done as part
of the close-out/sync step.

### LOW-1 — D-1 sweep residue: two surviving instances of the falsified phrasing

- `01-requirements.md:206` — the italic N-4 re-gate quote ends *"…and the completeness claim is
  anchored to **the single construction site**."*
- `PLAN.md:104` — *"the Switch completeness argument is **now** anchored to the single construction
  site rather than to the query."*

Both are stale: HEAD has two sites. Rated LOW, not MEDIUM, for three reasons: (a) the
`01-requirements.md` instance sits **four lines below** the ⚠ correction that contradicts it
(`:195-202`), so a reader cannot reach it without first reading the correction; (b) the *argument*
survives the correction unchanged — confinement, not a count — so no conclusion drawn from either
sentence is wrong; (c) nothing cites them: TC-514 asserts confinement, the §5.2 row was rewritten,
M-1 was annotated.

`02-regate-architect.md:242` also contains the phrase but is a **historical gate record** stating a
reviewer's disposition at the time; retro-editing it would be worse practice than leaving it, and I
do not count it as residue.

### LOW-2 — CF-2's transcript is not in an increment packet

The ledger's other five entries point at a numbered section of a specific packet; CF-2 points at a
commit (*"Orchestrator-run at the F1 fold (`0169108`)"*), and its key lines exist only in
`04-validation.md` §3 itself plus `06-docs/traceability-matrix.md:111`. Executed grep for `clause 0`
/ `F1 fold` / `key_right_of_card` across `03-increments/` → no hit.

The attribution is honest (the ledger says who ran it and where), the hash claim verifies byte-exact,
and the fold's product is on disk and passing — so this is a provenance-locality nit, not a
credibility problem. Worth noting only because CF-2 is described as *"the most consequential run of
the batch"*, and the most consequential run should be the easiest one to re-find.

### Informational

- `ruff format --check` drift: pre-existing, repo-wide (171/221 files at `main`), not enforced by
  CI. Reported as found; correctly not swept by this batch (recorded as G-008).
- `tests/test_engine_unchanged.py::_ENGINE_PATHS` omits `color_policy.py`; the `test_tui_directionb`
  arm covers it. Pre-existing, out of scope for this batch, no effect on the clean result.

---

## Clean axes — stated explicitly

Recorded so they are not re-litigated, and because a clean result is the point of the check:

| Axis | Verdict | Evidence |
|---|---|---|
| Dual traceability, both directions | ✅ intact | 18/18 nodes at claimed lines; §5.2 ↔ §2/§4.1 ↔ disk consistent; zero orphans |
| `REQUIREMENTS.md` citations | ✅ all resolve | 27/27 cited nodes found on disk |
| Engine-frozen boundary | ✅ untouched | Both guard arms green; empty intersection vs two bases; `legend.py` blob-identical |
| Guard-base currency | ✅ not vacuous | local `main` is a strict ancestor with zero divergence |
| Inc-4 scope | ✅ test + docs only | no `s19_app/` file in `37474b5` |
| Inc-1/2 ↔ Inc-3 isolation | ✅ no interference | shared `styles.tcss` hunks are disjoint by selector |
| AT-B59-03 / AT-B59-08 | ✅ byte-untouched | AST: `modified surviving funcs: []` |
| AT-B59-05 | ✅ true deletion | one function removed, tombstoned at `:1004`, no dangling refs |
| HLR-072-4 withdrawal | ✅ total | no `Select` rule in the diff; no test asserts a `Select` height |
| G-2 retirement | ✅ consistent + carried | `01-requirements.md:435` / §6.5 R-1 / `BACKLOG-CODE.md:172` |
| Test ledger | ✅ reconciles exactly | independently re-derived 2396 three ways |
| Counterfactual quality | ✅ all six fail on their own assertion | no `ImportError`/`NameError` masquerading as evidence |
| Nine Phase-2 blockers | ✅ 9/9 closed on disk | §4a table, each verified at a file:line |
| F1 (HIGH) / F2 (MED) folds | ✅ both on disk | `:170-174`/`:211-220`; `:666` regex + `:681` both sizes |
| F6 (the near-escape) | ✅ carried and named as such | `BACKLOG-CODE.md:173` |
| `ruff check` | ✅ clean | `All checks passed!` |
| Secrets / PII | ✅ none introduced | diff is CSS, Textual widgets, tests and markdown; no credentials, no network, no new dependency |
| Snapshots | ✅ none drifted, none regenerated | `git diff --name-only origin/main -- '*__snapshots__*'` empty; 29 snapshots passed |

---

## Verdict

# **MERGE**

No HIGH finding. The merge condition in the kickoff grant is satisfied.

Two MEDIUM-and-below items to fold at close — neither blocks, and neither requires re-testing:

1. **MEDIUM-1** — append **G-001** (AT-218 clause-4 labelling) and **G-004** (CRC 80×24 floor
   measurement) to the batch-72 carry block in `.dev-flow/BACKLOG-CODE.md`, so they reach the queue
   the next batch actually reads.
2. **LOW-1** — strike the word *"single"* from `01-requirements.md:206` and `PLAN.md:104`, or mark
   both as superseded by §6.5 D-1.

Do these as part of the close-out/sync, not as a merge precondition.

---

### Evidence checklist — qa-reviewer

- [x] **Acceptance criteria use Given/When/Then** — n/a for a merge gate; the batch's ATs were
      reviewed against their own §5.2 contract instead, and each was reconciled to a collected node.
- [x] **Test cases have explicit Expected, not vague "works"** — every node checked carries a
      numeric or exact threshold (`mac (17,6)` / `map (20,7)`; `0xCBF43926 → 0x1898913F`;
      `max_scroll_y == 0`; `card_height >= 2`; `len(tuple) >= 6`).
- [x] **Edge cases include empty, boundary, invalid, error** — boundary: 80×24 floor + the 120
      breakpoint, both directions; invalid: `Invalid parameters` and `○ NO-EXPECTED` excluded by
      name in AT-215; error: the `NoMatches` early return is AT-219's gate arm.
- [x] **Regression checklist exists** — Check 3 (cross-increment isolation), plus the two labelled
      PINs (AT-218, AT-219 cl.1) and the frozen-boundary arms.
- [x] **Exit criteria stated** — the four gate axes plus the HIGH-blocks rule; verdict explicit.
- [x] **No real PII / secrets** — none in the diff; none reproduced here. Host paths in this
      artifact are the repo's existing convention (see `BACKLOG-PROCESS.md:42`).
- [x] **Results left blank unless actually run** — every result above is from a command executed in
      this pass. The full-suite figure is attributed to the orchestrator's run and **not** re-claimed
      as mine; I re-derived only the collection count (2396) and a targeted 49-node run.
- [x] **Layer B (black-box)** — verified as delivered: 7/7 ATs drive the shipped surface
      (`pilot.press("0")`, the `k` binding), never a `.focus()` proxy; each carries boundary +
      negative evidence per §4.1.
- [x] **Bidirectional surface-reachability** — `04-validation.md` §6 claims 13/13 inputs driven and
      21/21 outputs observed; spot-checked against §4.1's "Surface driven" / "Deliverable observed"
      columns and against the passing nodes.
- [x] **No unfilled template** — this artifact contains no placeholder; every `file:line` cited was
      opened or grepped.
