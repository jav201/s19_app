# Batch-35 — Increment 5 (Inc-5): patch-editor regroup — patch-script vs checks sections

> US-057 / HLR-057 / R-TUI-045 on `feat/batch-35-report-filter` @ `4495ad4`
> (Inc-0..4 committed). Implements LLR-057.1 (two labeled sections, 15-id
> census), LLR-057.2 (AT-032a token span moved by CONTAINER, text unchanged),
> LLR-057.3 (zero behavior change — compose + CSS only), LLR-057.4 (2-cell
> snapshot xfail plan) and realizes AT-057a, AT-057b, TC-319, TC-320.

## 1. What changed

- **`s19_app/tui/screens_directionb.py`** — `PatchEditorPanel.compose`,
  `#patch_doc_file_row` sub-tree only (compose-only; the
  `on_button_pressed` action dict at `:2095-2105` and every
  message/handler/binding are untouched):
  - NEW `Label("Patch script", id="patch_script_section_label",
    classes="patch-section-title")` above `#patch_doc_controls`.
  - `#patch_doc_controls` (same id, same `Horizontal`) now holds EXACTLY
    Load / Validate / Apply / Save.
  - NEW `Label("Checks", id="patch_checks_section_label",
    classes="patch-section-title")` above the NEW
    `Container(id="patch_checks_controls")`, which holds the moved
    `Button("Run checks", id="patch_checks_run_button")` +
    `Label(id="patch_checks_help")`. The help STRING is byte-identical —
    only its source-line wrapping moved with the deeper indent (verified:
    AT-032a/AT-052a green unmodified). Section-label texts reuse the
    existing `.patch-section-title` idiom ("Change document (v2 JSON)"
    precedent at `:1806-1809`).
- **`s19_app/tui/styles.tcss`**:
  - NEW `#patch_checks_controls { width: 100%; height: auto; }` —
    `height: auto` is required because a bare `Container` defaults to
    `1fr` and would grab the scrollable pane's viewport height (the
    `#patch_variant_row` precedent, styles.tcss batch-23 comment).
  - The stale LLR-033.3b comment ("five ... buttons") updated to the
    four-button reality + a pointer to `#patch_checks_controls`; the RULE
    body (`layout: grid; grid-size: 3; grid-gutter: 0 1`) is unchanged —
    the grid-3 pin passes unmodified with 4 buttons (3 + 1 across two
    rows).
  - **Geometry reasoning (cited per task):** the regroup only ADDS
    vertical rows (2 section titles + the container wrapper) inside
    `#patch_pane_changefile`, which scrolls independently
    (`overflow-y: auto`, styles.tcss:707-714, batch-22 C-13.1) — added
    rows scroll below the fold and cannot clip siblings. No
    horizontal-budget change: the widest row is still the 3-column button
    grid, now with FEWER buttons in it. AT-033a/b (80x24 floor + 120x30
    region oracle) green unmodified confirm the budget holds.
- **`tests/test_tui_patch_editor_v2.py`** (191 added lines, 0 deleted —
  pure append): `_PRESERVED_REGROUP_IDS` (the LLR-057.1 15-id census
  verbatim), **AT-057a** (pilot: both section labels by id + rendered
  text, 15/15 ids, `#patch_checks_run_button` AND `#patch_checks_help`
  parented under `#patch_checks_controls`, the locked `_CHECKS_HELP_TOKEN`
  span present, `#patch_doc_controls` holds exactly the 4 patch-script
  buttons in order), **AT-057b** (wiring regression via real
  `button.press()` — the AT-032b idiom: Load populates 2 table rows from
  the typed path, Validate posts `Validate:`, Apply posts `Apply:`, Save
  writes exactly one `changes*.json` under the work area, Run checks on a
  kind=change doc posts the batch-33 `Checks: not run` loud block; plus
  the app-level `b` binding still `before_after_report`).
- **`tests/test_tui_patch_layout.py`** (111 added lines, 0 deleted — pure
  append; the grid-3 pin at `:301-327` verified passing UNMODIFIED):
  **TC-319** white-box compose census — 15-id counts, both section
  labels, section ORDER inside `#patch_doc_file_row` (each label
  immediately precedes its container), `#patch_doc_controls` == exactly
  the 4 buttons, `#patch_checks_controls` children == exactly
  `[patch_checks_run_button, patch_checks_help]`.
- **`tests/test_tui_snapshot.py`** (62 added / 1 deleted — the 1 deletion
  is the `_SCAFFOLD_CELLS` marks-sum line gaining
  `+ _batch35_drift_marks(...)`, the standing batch-33 censused idiom;
  no existing test body touched): `_BATCH35_REGROUP_DRIFT` = the two
  patch cells, `_batch35_drift_marks()` returning
  `pytest.mark.xfail(strict=False, reason="batch-35 US-057 regroup —
  pending canonical-CI regen")`, and **TC-320** asserting the xfail set
  is EXACTLY the two patch cells against both the declared set and the
  marks actually attached to every parametrized cell (restyled +
  scaffold + entropy).

## 2. Files modified

1. `s19_app/tui/screens_directionb.py`
2. `s19_app/tui/styles.tcss`
3. `tests/test_tui_patch_editor_v2.py`
4. `tests/test_tui_patch_layout.py`
5. `tests/test_tui_snapshot.py`

File cap: 5/5 exactly as tasked (+ this mandated dev-flow record).
Engine-frozen set untouched (`tests/test_engine_unchanged.py` →
`1 passed in 0.07s`).

## 3. How to test

```bash
# the regroup nodes + both existing patch suites (0 edits to existing tests)
python -m pytest tests/test_tui_patch_editor_v2.py tests/test_tui_patch_layout.py -q
# snapshot plan (LLR-057.4)
python -m pytest tests/test_tui_snapshot.py -q
# engine-frozen guard
python -m pytest tests/test_engine_unchanged.py -q
# full fast suite
python -m pytest -q -m "not slow"
# lint
python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_editor_v2.py tests/test_tui_patch_layout.py tests/test_tui_snapshot.py
```

## 4. Test results (real output)

- **RED-first** (AT-057a written before any production edit; single
  foreground run, NO `git stash` at any point):

```
python -m pytest tests/test_tui_patch_editor_v2.py -k at057 -q
E           textual.css.query.NoMatches: No nodes match '#patch_script_section_label' on Screen(id='_default')
C:\...\site-packages\textual\dom.py:1505: NoMatches
FAILED tests/test_tui_patch_editor_v2.py::test_at057a_two_labeled_sections_ids_and_parentage
1 failed, 1 passed, 35 deselected in 1.84s
```

  (AT-057b passed pre-change as designed — it is a pure regression pin of
  PRE-batch behavior and must be green on both sides of the compose move.)

- **Pre-xfail snapshot drift evidence (mandated).** After the compose+CSS
  change, BEFORE adding any xfail:

```
python -m pytest tests/test_tui_snapshot.py -q
FAILED tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]
1 failed, 33 passed, 1 warning in 45.34s
```

  → drift set = **{patch-comfortable-120x30} only** — a strict SUBSET of
  the 2 declared patch cells; NO out-of-scope cell drifted (LLR-057.4
  containment holds). The 80x24 cell did NOT drift: the regroup rows
  render below the pane fold at the 80x24 floor — exactly the batch-33
  help-text precedent ("the 80x24 cell still matches — the longer text
  renders below the fold there"). Local `textual==8.2.8` EQUALS the
  canonical pin, so this local verdict is meaningful per the
  snapshot-regen-env convention. See §5 for the deviation record.

- **GREEN (scoped)**: `tests/test_tui_patch_editor_v2.py
  tests/test_tui_patch_layout.py` → `43 passed in 35.28s`, exit 0 —
  AT-057a/b + TC-319 green; ALL existing tests (grid-3 pin, AT-032a/b,
  AT-052a/b, AT-033a/b/c, TC-015/016/019/024/051/052) green with **0
  edits to any existing test** (LLR-057.3 threshold: 0 un-censused
  edits; the only census-recorded edit in the batch's test files is the
  snapshot marks-sum line, §1).
- **Snapshot plan (post-xfail)**: `tests/test_tui_snapshot.py` →
  `33 passed, 1 xfailed, 1 xpassed, 1 warning in 44.41s`, exit 0.
  31-cell oracle decomposition: **29 green + 1 xfailed
  (patch-comfortable-120x30, real drift) + 1 xpassed
  (patch-comfortable-80x24, no local drift, strict=False)**; the other
  passers are the fixture-provenance test, the 2 CV-04 boundary tests,
  and the new TC-320. 0 unexpected failures — TC-320's realized run
  outcome, with the xfailed/xpassed split recorded as the §5 deviation.
- **Engine-frozen**: `tests/test_engine_unchanged.py` → `1 passed in
  0.07s`, exit 0.
- **ruff** on all 4 touched Python files: `All checks passed!`, exit 0.
- **Full fast suite**: `python -m pytest -q -m "not slow"` (single
  invocation; the harness auto-backgrounded it — the tail below is that
  one run's output, no re-run):

```
1333 passed, 2 skipped, 21 deselected, 4 xfailed, 1 xpassed, 1 warning in 667.75s (0:11:07)
```

  exit 0. Arithmetic closes exactly: Inc-4 base 1331 passed / 3 xfailed
  under not-slow; +4 new nodes (AT-057a, AT-057b, TC-319, TC-320) −2
  patch cells leaving "passed" (120x30 → the 4th xfailed, 80x24 → the 1
  xpassed) = **1333 passed**; skips/deselected unchanged.

## 5. Risks

- **DEVIATION (recorded, not silent): the LLR-057.4 prediction "2 patch
  cells drift" realized as 1 drift + 1 no-drift** at the canonical
  textual pin. Both cells carry the mandated `xfail(strict=False)` mark
  per the locked LLR statement, so the 80x24 cell reports **xpassed**
  (non-gating, 0 unexpected) instead of xfailed until the canonical-CI
  regen. Consequence: the regen will find only the 120x30 baseline
  actually moved; retiring both marks afterwards is the standing
  procedure either way. If Phase-4 prefers the mark to track the OBSERVED
  drift set exactly (1 cell), that is a one-line §6.5 amendment to
  LLR-057.4 — flagged for the gate, not decided here.
- **80x24 visual**: at the floor, the new section titles sit below the
  change-file pane's fold at scroll 0 (why the 80x24 baseline holds).
  The sections are fully visible at 120x30 and on scroll — same
  progressive-disclosure behavior the batch-33 help text already has.
- **`#patch_doc_controls` grid keeps `grid-size: 3` with 4 buttons**
  (3 + 1 across two rows) — intentional per the LLR-057.1 acceptance
  criterion ("the id and grid survive with 4 buttons"); the pin stays
  the anti-clip guard. A later polish could re-balance to 2x2, which
  would require a censused pin supersede — out of scope.
- **Local snapshot regen NOT run** (forbidden; canonical-CI-only). The
  committed baselines are untouched; the 120x30 cell stays xfailed until
  the post-merge `snapshot-regen.yml` pass recommits it.

## 6. Pending items

- Canonical-CI snapshot regen for the patch cell(s) post-merge + mark
  retirement (the batch-25/27/28/31/33 follow-up pattern).
- Phase-4 call on the §5 deviation (keep both marks vs amend LLR-057.4
  to the observed 1-cell set).
- AT-053b + TC-318 (C-17 file-side pair) + operator format docs +
  REQUIREMENTS.md `R-RPT-FILTER-001`/`R-TUI-045` rows — ride the
  validation/docs increments per PLAN.

## 7. Suggested next task

Batch-35 Phase-4 validation: AT-053b/TC-318, the full §5.2 registry
sweep, REQUIREMENTS.md ledger rows, and the batch acceptance checklist
(§5.3) — all implementation increments (Inc-0..5) are now landed.

## Ledger delta

Base 1331 + 4 new = **1335 nodes** under `-m "not slow"` (AT-057a,
AT-057b, TC-319, TC-320), reporting as 1333 passed / 4 xfailed /
1 xpassed per the LLR-057.4 plan; **0 existing tests modified, 0
deletions** (the single snapshot-file deleted line is the marks-sum line
gaining the batch-35 term — censused in §1); engine-frozen set untouched.

## Evidence checklist

- [x] Tests/type checks/lint pass — full suite tail above (exit 0);
      `ruff` All checks passed.
- [x] No secrets in code or output — UI compose/CSS/tests only.
- [x] No destructive commands run — no stash, no reset, no regen.
- [x] File count within cap — 5/5 + the mandated increment record.
- [x] Review packet attached — this document (§1-§7).
