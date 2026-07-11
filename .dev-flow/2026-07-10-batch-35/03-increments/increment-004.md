# Batch-35 — Increment 4 (Inc-4): filter selector UX + b-key arm + surface ATs

> Test-heavy realization increment on `feat/batch-35-report-filter` @
> `49ec95b` (Inc-0..3 committed). Implements LLR-056.1 (filters/ scan),
> LLR-056.2 (selector row in `ReportViewerScreen` + reopen seeding + C-15
> escape), LLR-056.3 (sticky app-level selection + F-09 reset funnel),
> LLR-056.4 (typed-path fold), LLR-056.5 (geometry — ladder rung 3
> landed, see §5), LLR-053.5 b-key half + LLR-053.6 (markup-inert
> refusal/confirmation budget), LLR-054.1 app arm (b-key consumption of
> the Inc-2/3 machinery), and realizes the black-box AT registry nodes
> AT-053a (joined), AT-054a, AT-054c, AT-056a/a2/a3/b/c/d/e plus TC-316,
> TC-317, and the Inc-3-review TC-F1 consistency pin.

## C-15 probe result (FIRST action, mandated)

Runtime probe of textual **8.2.8** `Select` option-label markup behavior
(minimal `App.run_test`, option label `[red]x[/red].json`):

- **Population**: no exception raised.
- **Raw str label**: PARSED AS MARKUP — rendered
  `Content('x.json', spans=[Span(0, 1, style='red')])` — the brackets are
  CONSUMED and the name renders styled/corrupted (plain text `x.json`,
  literal brackets ABSENT). A silently-wrong display, and a malformed
  sequence is a `MarkupError` risk.
- **`rich.markup.escape(label)`**: renders the literal
  `[red]x[/red].json`. ✓
- **`Text(label)` prompt**: also renders the literal. ✓

**Decision**: `rich.markup.escape` on the label string at option
construction (`screens.py` compose, `(escape_markup(name), name)`) — the
str form keeps the option shape `(str, str)` and the VALUE stays the raw
bare name. AT-056b re-proves the literal render through the shipped
overlay + status funnel. (C-15 lineage: wrong assumptions here shipped
bugs in three prior batches.)

## F-09 reset-funnel citation (mandated)

Census of every path that swaps the active project/loaded file set:

- **Project load** (`_handle_load_project`, `app.py:5017`) and
  **loose-file load** / **variant activation** all terminate in
  `load_selected_file` → `_start_load_worker` / `_apply_loaded_file` →
  **`_apply_prepared_load`** — the single install point that mutates
  `self.current_file` (def `app.py:7084`, install at `:7136`). The reset
  `self._report_filter_path = None` lands there (**`app.py:7143`**).
- **Project create/save** (`_handle_save_dialog`, `app.py:4768`) swaps
  `current_project`/`current_project_dir` WITHOUT a file reload (no
  `_apply_prepared_load` pass) — second reset site at **`app.py:4832`**
  (right after the `current_project_dir` swap).
- **Project close**: NO close path exists in the app (grep
  `current_file = None` / close-project handlers → 0 production hits) —
  the "close" clause of LLR-056.3 is vacuously satisfied; recorded here
  as the funnel-completeness verification the spec flagged
  (`assumed — verify funnel completeness in Phase 3` → verified, two
  sites + one vacuous).

Save-back (`on_patch_editor_panel_save_back_decision`) was checked and
does NOT reload through the pipeline — the reset cannot fire between a
selection and the `b` press (verified by code read + AT-056a green).

## 1. What changed

- **`s19_app/tui/screens.py`** — `ReportViewerScreen`:
  - Constructor gains `filter_names: Tuple[str, ...] = ()`,
    `filter_select_value: Optional[str] = None`,
    `filter_path_text: str = ""` (defaults keep every existing 2/3-arg
    construction valid); class docstring Args extended.
  - `compose` gains `#report_filter_row` (a `Horizontal` above the
    buttons container): `Label#report_filter_label` +
    `Select#report_filter_select` (`allow_blank=True` — F-08 divergence
    from the A2B `allow_blank=False` sentinel precedent, justified: "none
    = full report" is a first-class default so a blank Select models it
    directly) + `OsClipboardInput#report_filter_path`. Option labels
    markup-escaped at construction (C-15 decision above); reopen seeding
    via the constructor `value=`/`value` kwargs (F-05(i)).
  - NEW messages `FilterSelected(name: Optional[str])` and
    `FilterPathTyped(raw: str)` posted straight to the app queue (the
    `GenerateRequested` idiom); `on_select_changed` handles the
    `Select.NULL` runtime sentinel per the batch-23 C-15 precedent
    (`screens_directionb.py:2148-2159` idiom), `on_input_submitted` is
    id-guarded to `#report_filter_path` and ignores empty submits.
- **`s19_app/tui/app.py`**:
  - Module constant `REPORT_FILTERS_DIR_NAME = "filters"` (`app.py:373`).
  - `_report_filters_dir()` (`app.py:2800`) + `_scan_report_filter_files()`
    (`app.py:2832`) mirroring `_scan_patch_change_files`: glob
    `*.json`, symlink entries SKIPPED, bare names SORTED, absent
    dir/project → `[]` (LLR-056.1).
  - `action_view_reports` scans the options and seeds the screen from the
    sticky `_report_filter_path` — filters/-resident selection seeds the
    Select value, a typed path seeds the path-input text (F-05(i)).
  - `on_report_viewer_screen_filter_selected` /
    `on_report_viewer_screen_filter_path_typed` +
    `_confirm_filter_selection`: dropdown pick → `filters_dir / name`
    stored (idempotent no-op on the reopen-seed echo); blank pick → reset
    + "Report filter: none (full report)"; typed path →
    `resolve_input_path` against `base_dir`, then the read-path security
    fold (missing → `Filter path not found: ...`, symlink →
    `Filter path is a symlink - refused: ...`, non-file →
    `Filter path is not a file: ...` — fault token leads within the
    50-char funnel, Q-7); out-of-project paths ALLOWED (S-F5).
    Confirmation carries the FILENAME: `Report filter: <name>`, falling
    back to the bare name when the framed form would exceed 50 chars.
    ALL through the markup-inert `set_status` funnel only (LLR-053.6).
  - **b-key arm** in `action_before_after_report` (LLR-053.5 /
    LLR-054.1): mirrors the Inc-3 `_trigger_generate_report` idiom —
    consult `_report_filter_path` at trigger time on the UI thread,
    `read_report_filter_text` → `parse_report_filter` → on ANY fault
    `set_status("Before/after report refused: " + "; ".join(errors))`,
    composer NOT invoked, `reports/` unchanged; on success
    `resolve_report_filter(parsed, _compute_a2l_enriched_tags() or None,
    loaded.mac_records, source_name=filter_path.name)` passed as the
    single `report_filter` kwarg into `compose_before_after_report`.
    Unfiltered = today's exact path (`report_filter=None` is the
    composer's default — AT-054b golden green unmodified).
  - **F-09 resets** (two sites, see the citation section above).
- **`s19_app/tui/styles.tcss`** — `#report_filter_row` + child rules.
  Geometry ladder record (LLR-056.5): see §5.
- **NEW `tests/test_tui_report_filter_surface.py`** — 13 nodes, one
  on-disk node per AT (C-18): AT-056a (both triggers byte-differ vs an
  unfiltered pinned baseline session + real-filename audit headers),
  AT-056a2 (row + Generate regions inside the dialog at 80x24 AND
  120x30), AT-056a3 (project switch → blank dropdown + unfiltered next
  report), AT-056b (hostile `[boom].json` — legal on Windows — populates,
  overlay renders literal, literal confirmation via the `markup=False`
  log labels, no `MarkupError`), AT-056c (fresh default: blank dropdown +
  canonical byte-equality vs the AT-055b golden), AT-056d (typed
  out-of-project valid path filters the next report; missing path
  refuses, nothing new written), AT-056e (filter selected → A2B diff
  report canonical-byte-identical to a no-filter run, both formats),
  AT-053a (JOINED node: invalid filter selected via the REAL dropdown on
  a run that would otherwise succeed on each surface → both kind-prefixed
  refusals carry the `'format'` fault, 0 files on both, worker never
  starts), AT-054a (b-key filtered pair: matching linkage row kept —
  `| 0x00001000 | 0x00001001 |` — unmatched `0x00001002` absent from MD
  AND HTML, audit header + real filename), AT-054c (b-key zero-match:
  pair written with `filter matched 0 of 1 items`, `refused` absent from
  report and status — Q-12 disjointness), TC-316 (scan unit + the
  `validate_project_files` filters/-subdir regression), TC-317 (relative
  resolve, missing/symlink typed refusals, and BOTH S-F2 swap classes:
  selected file DELETED → read-time refusal; selected file replaced by a
  SYMLINK → read-time symlink refusal; symlink arms auto-skip where the
  OS forbids symlink creation — they RAN here), TC-F1 (the Inc-3 review
  carry: `_zero_match_notice` (N=1,3), ctl-strip twins over
  `"a\x01b\r\nc"`, and `_filter_display_name` (named + unnamed matcher)
  pinned equal across `report_service` ↔ `diff_report_service` —
  LLR-054.3 cross-report wording contract; consolidation stays a later
  hygiene item).
- **`tests/conftest.py`** — `canonical_report_bytes` factored in on its
  THIRD use (the standing reviewer recommendation): shared canonicalizer
  for the new file's AT-056c/AT-056e byte-compares; the two existing
  per-file `_canonical_report_bytes` twins stay untouched (their
  increments' diffs stay closed). Plus a pre-existing `typing.Any` F401
  removed (ruff gate on a touched file; one token).

## 2. Files modified

1. `s19_app/tui/screens.py`
2. `s19_app/tui/app.py`
3. `s19_app/tui/styles.tcss`
4. `tests/test_tui_report_filter_surface.py` (NEW)
5. `tests/conftest.py`

File cap: 5/5 exactly as tasked (+ this mandated dev-flow record).
Engine-frozen set untouched (`tests/test_engine_unchanged.py` green).

## 3. How to test

```bash
# the new surface nodes
python -m pytest tests/test_tui_report_filter_surface.py -q
# goldens gate (mandated)
python -m pytest tests/test_before_after_report.py tests/test_tui_report_seam.py tests/test_report_filter.py tests/test_report_service.py tests/test_diff_report_service.py tests/test_tui_report_view.py -q
# snapshot watch (mandated — modal not in any scaffold cell)
python -m pytest tests/test_tui_snapshot.py -q
# engine-frozen guard
python -m pytest tests/test_engine_unchanged.py -q
# full suite
python -m pytest -q
# lint
python -m ruff check s19_app/tui/app.py s19_app/tui/screens.py tests/test_tui_report_filter_surface.py tests/conftest.py
```

## 4. Test results (real output)

- **RED-first** (all 13 nodes written before implementation; single
  foreground run): `12 failed, 1 passed in 38.05s` — TC-F1 alone passed
  (its pinned helpers landed in Inc-3; it is a consistency pin, not an
  AT). Recorded RED signatures (live, no import errors, NO `git stash`
  at any point):

```
textual.css.query.NoMatches: No nodes match '#report_filter_select' on ReportViewerScreen()
  (AT-056a, AT-056a3, AT-056b, AT-056c, AT-056e, AT-053a)
textual.css.query.NoMatches: No nodes match '#report_filter_row' on ReportViewerScreen()
  (AT-056a2)
textual.css.query.NoMatches: No nodes match '#report_filter_path' on ReportViewerScreen()
  (AT-056d, TC-317)
tests\test_tui_report_filter_surface.py:869: AssertionError: AT-054a: the md must carry the audit header
tests\test_tui_report_filter_surface.py:938: AssertionError: AT-054c: the loud zero-match notice must replace the filtered section bodies
tests\test_tui_report_filter_surface.py:985: AttributeError: 'S19TuiApp' object has no attribute '_scan_report_filter_files'
```

  (AT-054a/c are the live "no filtering on b-key" REDs: the b-key wrote
  an UNFILTERED pair despite the designated filter — the class this
  increment closes.)

- **GREEN (scoped)**: `tests/test_tui_report_filter_surface.py` →
  `13 passed in 73.90s`, exit 0. (First implementation pass was 12/1 —
  the geometry node correctly caught the rung-1 failure, §5.)
- **Goldens gate**: `tests/test_before_after_report.py
  tests/test_tui_report_seam.py tests/test_report_filter.py
  tests/test_report_service.py tests/test_diff_report_service.py
  tests/test_tui_report_view.py` → `181 passed in 104.57s`, exit 0 —
  AT-054b (MD+HTML) and AT-055b goldens green UNMODIFIED: the b-key
  wiring did not move an unfiltered byte.
- **Snapshot watch**: `tests/test_tui_snapshot.py` →
  `31 snapshots passed. 34 passed in 52.54s`, exit 0 — 0 drift; the
  LLR-057.4 `assumed — verify` flag is CONFIRMED: no scaffold cell
  renders the report-viewer modal.
- **Engine-frozen**: `tests/test_engine_unchanged.py` → `1 passed`,
  exit 0.
- **ruff** on all touched Python files: `All checks passed!`, exit 0
  (after removing the pre-existing `typing.Any` F401 in the touched
  `tests/conftest.py`).
- **S-F1 exit grep** over the new `app.py`/`screens.py` hunks:
  `git diff -U0 | grep '^+' | grep 'notify(\|set_file_status('` → one
  DOCSTRING mention only, 0 call sites — every filter-derived string
  flows through the markup-inert `set_status` funnel.
- **Full suite**: `python -m pytest -q` (single blocking invocation;
  the harness auto-backgrounded it — the summary below is that one
  run's output, no re-run):

```
31 snapshots passed.
1352 passed, 2 skipped, 3 xfailed in 1375.51s (0:22:55)
```

  exit 0. Arithmetic closes exactly: Inc-3's full fast suite was
  `1318 passed ... 21 deselected (slow)`; this FULL run (slow included) =
  1318 + 21 slow + 13 new = **1352**; skips/xfails unchanged.

## 5. Risks

- **Geometry ladder — rung 3 landed (specced fallback, not a
  deviation).** Measured at the 80x24 floor: the dialog's in-flow content
  ends EXACTLY at the dialog bottom pre-batch (the `1fr` scroll is
  already at its 2-row minimum, and `.modal-buttons` is `dock: bottom`,
  overlaying the declared-regions rows) — an in-flow selector row is a
  4-row deficit, so rung 1 (absorber) FAILED and rung 2 (−2 rows) cannot
  cover it. Rung 3 applied: the selector joins the DOCKED bottom control
  region (0 added flow rows). Realization detail: a literal fold into the
  single `#reportviewer_buttons` line is horizontally infeasible at 80
  cols (five widgets exceed the 48-cell interior), so the row is a SECOND
  docked line — `dock: bottom` + `margin-bottom: 4` (same-edge docks
  OVERLAY in textual 8.2.8, measured; the margin offsets by the buttons
  row's realized height). Measured result at 80x24: row y=11..14 stacked
  above buttons y=14..18, both inside the dialog; AT-056a2 green at both
  regimes. Cost: at the 80x24 floor the docked pair overlays the
  declared-regions rows — the SAME overlay class the buttons row already
  exhibits there pre-batch (measured y=14..18 over the textarea at
  y=15..20); no new failure mode at the floor, full layout intact at
  larger sizes.
- **Same-address confirmation echo**: the selection handlers are
  idempotent (same resolved path → silent no-op) to absorb the
  reopen-seed `Select.Changed` echo; a user RE-picking the already-active
  filter therefore gets no fresh confirmation line. Accepted (the audit
  header still names the applied filter on every filtered report).
- **TC-317/TC-316 symlink arms** auto-skip where `os.symlink` is
  forbidden (Windows without developer mode). They RAN on this machine
  (no skips in the recorded runs); CI (ubuntu) always runs them.
- **AT-056a baseline-vs-filtered construction** uses two sessions in two
  tmp roots under one pin; comparison is canonical-form (CRLF + run-root
  masking per LLR-054.4) — inherited, double-proven Inc-0 mechanism.
- **`filters/` subdir in saved projects**: `validate_project_files`
  skips non-files (verified + TC-316 regression), so a project carrying
  `filters/` loads/saves as before.

## 6. Pending items

- **US-057 patch-editor regroup (LLR-057.1-.4 + AT-057a/b, TC-319/320)**
  — NOT in this increment's 5-file task scope; the remaining Phase-3
  work item.
- AT-053b (valid hostile filter → proceed + every written file re-read)
  + TC-318 — the C-17 file-side pair rides the validation increment.
- Operator format documentation — rides the docs increment.
- LLR-053.4 perf smoke (4096-pattern worst case) — still deferred per
  PLAN.
- Hygiene (later batch): consolidate the `_zero_match_notice` /
  ctl-strip / `_filter_display_name` twins now pinned by TC-F1; collapse
  the two per-file `_canonical_report_bytes` twins onto the new conftest
  helper.

## 7. Suggested next task

Batch-35 Inc-5 per PLAN: the US-057 patch-editor regroup (compose + CSS
only, 15-id census, AT-032a token span, 2-cell snapshot xfail per
LLR-057.4 + TC-320) — the last implementation increment before Phase-4
validation (AT-053b/TC-318 + the full §5.2 registry sweep).

## Ledger delta

Base 1318 + 13 new = **1331** expected under `-m "not slow"` semantics
(AT-053a, AT-054a, AT-054c, AT-056a, AT-056a2, AT-056a3, AT-056b,
AT-056c, AT-056d, AT-056e, TC-316, TC-317, TC-F1); 0 existing tests
modified, 0 deletions; engine-frozen set untouched.
