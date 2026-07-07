# Increment 003 — US-036 entropy viewer modal CORE (LLR-036.1..036.6)

> Batch 2026-07-06-batch-26 · Phase 3 · Increment 3 · agent `software-dev`
> Scope: US-036 viewer modal CORE (NO SVG snapshot cells — those are Inc-3b).
> Behavioral proof = the Pilot ATs, not snapshots.

## 1. What changed

Added the entropy-viewer modal surface and wired it to a new `e` key binding,
consuming the Inc-1 headless `entropy_service` (untouched).

- **`EntropyViewerScreen(ModalScreen[Optional[int]])`** (`screens.py`) following
  the `LegendScreen` template: reuses the shared `.modal-dialog` box model, so
  the measured 48/76-col content-width budget (§2.6 C-13) holds **by
  construction** (verified: content width = 48 @80×24, 76 @120×30). It
  snapshots the loaded image's `mem_map` **once at construction**
  (`self._windows = compute_entropy(mem_map)`) — no live-tracking of later
  `mem_map` changes (LLR-036.2 snapshot-at-push). Composes:
  - a **band-coloured strip** (`#entropy_strip`, a `Static`): one `█` cell per
    window as inline Rich `Text` styling (the `hexview` per-cell precedent),
    coloured by the new `ENTROPY_BAND_COLOUR` map; low-confidence windows also
    dimmed via `ENTROPY_LOW_CONFIDENCE_STYLE`. The `Static` wraps cells into the
    content width — no horizontal overflow (LLR-036.3).
  - a **jump-to-address `ListView`** (`#entropy_jump_list`): one row per window
    reading `0xXXXXXXXX  <band>  H=<h>` (low-confidence flagged).
  - a **truncation indicator** (`#entropy_truncated`) shown when the window
    count exceeds a cap.
- **`ENTROPY_BAND_COLOUR`** (`screens.py`): the viewer's OWN band→Rich-colour
  map — `constant/padding`→`grey50` · `low`→`green` · `medium`→`yellow` ·
  `high/random`→`red` (§2.6 D-d). No `sev-*` reference in the band-cell path
  (`color_policy.py` stays read-only/frozen).
- **`ENTROPY_STRIP_MAX_CELLS = 512` / `ENTROPY_MAX_ROWS = 512`** (`screens.py`):
  cost caps mirroring `hexview.MAX_HEX_ROWS` magnitude (LLR-036.6). Beyond the
  cap the strip/jump list truncate and the indicator renders (never silent).
- **`action_show_entropy` + `_focus_entropy_target`** (`app.py`): the action
  reads `self.current_file`; with NO image loaded it is a safe no-op notify;
  with an image it `push_screen`s the modal with a callback. Jump-row activation
  dismisses the modal with the window's `start` address (LLR-036.5,
  dismiss-with-target), and the callback moves the main hex focus there through
  the existing `_apply_goto`/`update_hex_view` path (no new focus plumbing).
- **`Binding("e", "show_entropy", "Entropy", show=True)`** (`app.py`): the `e`
  key, verified unused before this increment (`git grep '"e"' app.py` → 0 hits).
- **CSS** (`styles.tcss`): `#entropy_dialog` height cap + `#entropy_body` scroll
  + `#entropy_strip`/`#entropy_jump_list` sizing, mirroring the legend rules.
  Band colours are inline Rich styles, so no per-band CSS rule is needed.

**Design deviation (recorded):** LLR-036.2 names `ModalScreen[None]`, but the
dismiss-with-target design (which LLR-036.5 explicitly authorises —
"dismissing with the target for the host to focus — implementer's choice")
requires an address payload, so the screen is typed
`ModalScreen[Optional[int]]`. Documented in the class docstring `Returns:`.

## 2. Files modified (4 — within the ≤5 cap)

| File | Change |
|---|---|
| `s19_app/tui/screens.py` | EDIT — `EntropyViewerScreen`, `ENTROPY_BAND_COLOUR`, `ENTROPY_LOW_CONFIDENCE_STYLE`, `ENTROPY_STRIP_MAX_CELLS`, `ENTROPY_MAX_ROWS`; imports `Dict`, `rich.text.Text`, `compute_entropy`/`EntropyWindow` |
| `s19_app/tui/app.py` | EDIT — `action_show_entropy` + `_focus_entropy_target`; `e` binding; `EntropyViewerScreen` import |
| `s19_app/tui/styles.tcss` | EDIT — entropy modal rules (`#entropy_dialog` / `#entropy_body` / `#entropy_strip` / `#entropy_jump_list`) |
| `tests/test_tui_entropy_viewer.py` | NEW — AT-036a/b/c + TC-036.1..5 + geometry @80/@120 |

(The `report_service.py` / `test_report_service.py` / `entropy_service.py` /
`test_entropy_service.py` / `.dev-flow/` entries in `git status` are Inc-1 &
Inc-2 work already on this branch — NOT part of this increment.)

## 3. How to test

```bash
# From this worktree root (cwd-first resolution; edits confirmed under test)
python -m pytest tests/test_tui_entropy_viewer.py -v

# Regression (frozen guards + Inc-1/2 suites + shared-file legend)
python -m pytest tests/test_entropy_service.py tests/test_report_service.py \
  tests/test_engine_unchanged.py tests/test_tui_legend.py \
  tests/test_tui_directionb.py -q

# Lint
python -m ruff check s19_app/tui/screens.py s19_app/tui/app.py \
  tests/test_tui_entropy_viewer.py
```

## 4. Test results (REAL output)

**New module — `tests/test_tui_entropy_viewer.py`: 12 passed in 9.21s.**

```
test_at036a_open_modal_strip_and_jump_list PASSED   # AT-036a GATE — LLR-036.1/.2/.3/.4
test_at036b_jump_second_row_moves_focus    PASSED   # AT-036b C-10 off-default — LLR-036.5
test_at036c_no_image_safe_noop             PASSED   # AT-036c edge (a) — LLR-036.4
test_at036c_no_image_empty_state_text      PASSED   # AT-036c edge (a') — HLR-036 empty
test_at036c_single_window_one_cell_one_row PASSED   # AT-036c edge (b) — LLR-036.2
test_tc036_1_band_colour_map_and_no_sev    PASSED   # TC-036.1 — LLR-036.1
test_tc036_2_strip_cell_per_window         PASSED   # TC-036.2 — LLR-036.2
test_tc036_3_jump_rows_documented_shape    PASSED   # TC-036.3 — LLR-036.2
test_tc036_4_e_binding_registered          PASSED   # TC-036.4 silent-unbind — LLR-036.4
test_tc036_5_cost_cap_and_truncation       PASSED   # TC-036.5 — LLR-036.6
test_geometry_fits_80                       PASSED   # geometry @80 — LLR-036.3
test_geometry_fits_120                      PASSED   # geometry @120 — LLR-036.3
```

**Test → AT/TC → LLR map:**

| Test | AT/TC | LLR | Asserts |
|---|---|---|---|
| `test_at036a_*` | AT-036a (GATE) | 036.1/.2/.3/.4 | `e` opens modal; strip band styles map to `ENTROPY_BAND_COLOUR` (semantic); jump rows for 0x3000 (constant/padding) + 0x4000 (high/random) with `H=` |
| `test_at036b_*` | AT-036b (C-10) | 036.5 | activate 2nd jump row → `_goto_focus_address` before≠after, ==0x4000 |
| `test_at036c_no_image_safe_noop` | AT-036c(a) | 036.4 | `e` with no image → no modal, no crash |
| `test_at036c_no_image_empty_state_text` | AT-036c(a') | HLR-036 | empty mem_map → positive empty-state text |
| `test_at036c_single_window_*` | AT-036c(b) | 036.2 | single-window → exactly 1 cell + 1 row |
| `test_tc036_1_*` | TC-036.1 | 036.1 | 4 documented bands, 4 distinct colours, no `sev-*`/`css_class_for_severity` in the code path |
| `test_tc036_2_*` | TC-036.2 | 036.2 | 3 windows → 3 styled strip cells, per-band styling |
| `test_tc036_3_*` | TC-036.3 | 036.2 | jump rows in `0xADDR  band  H=` shape, one per window |
| `test_tc036_4_*` | TC-036.4 | 036.4 | `"e" in BINDINGS` → `show_entropy`; `action_show_entropy` callable |
| `test_tc036_5_*` | TC-036.5 | 036.6 | large_s19 (>512 windows): strip ≤ cap, jump ≤ cap, truncation indicator present |
| `test_geometry_fits_80/120` | geometry | 036.3 | dialog + strip right edge within terminal width |

**Regression:** `test_entropy_service.py` + `test_report_service.py` +
`test_engine_unchanged.py` = **48 passed in 2.53s**. Combined
entropy+legend+engine-frozen+directionb = **125 passed in 90.15s** (includes
`test_tui_directionb.py::test_tc031_*` engine-frozen guards → **0 frozen-set
diff** confirmed).

**Ruff:** `All checks passed!` on the 3 changed source/test files.

**Geometry measurement (packet evidence):** entropy modal `content_region`
width = **48 @80×24** and **76 @120×30** — exactly the §2.6 C-13 budget, held by
`.modal-dialog` box-model reuse (no fallback rung needed).

## 5. Counterfactual (Certainty)

AT-036a's pre-fix RED state = key `e` unbound + `action_show_entropy` /
`EntropyViewerScreen` absent → the key press pushes nothing. Because this is
net-new code, the counterfactual is **satisfied by construction** (before this
increment `e` did nothing and neither symbol existed). It is positively pinned
two ways post-fix: `test_tc036_4` asserts the binding is now registered →
`show_entropy`, and `test_at036a` asserts the modal opens through the key. A
synthetic "strip the binding" run was attempted but hit an unrelated textual
CSS-source-introspection error on a dynamically-defined `App` subclass; not
pursued since the by-construction argument + the two positive pins cover it.

## 6. Risks

- **R-3 geometry regime drift** — MITIGATED by construction: `.modal-dialog`
  reuse gives the exact 48/76 content width (measured this increment); geometry
  tests lock the no-overflow invariant at both regimes.
- **R-4 band-cell cost @large image** — MITIGATED: `ENTROPY_STRIP_MAX_CELLS` /
  `ENTROPY_MAX_ROWS` caps + truncation indicator, verified on `large_s19`
  (>512 windows) by TC-036.5.
- **Type deviation** `ModalScreen[Optional[int]]` vs the LLR-036.2
  `ModalScreen[None]` note — LOW: authorised by LLR-036.5's implementer's-choice
  clause, documented in the docstring. Flag for the Phase-2/review reader.
- **`Static.renderable` absent in textual 8.2.8** — the strip's rendered Rich
  object is not introspectable via the widget; the ATs read band styling from
  the screen's own `_strip_text()` (push-time state, drive-level private access
  per the batch-23/24 ratified idiom). Widget *presence* is still asserted
  black-box (`#entropy_strip` query).

## 7. Pending items / Suggested next task

- **Inc-3b (separate):** add the two SVG snapshot cells @80×24 / @120×30 for the
  entropy modal, baselined per the batch-25 regen policy (explicitly out of
  scope here; behavioral proof already carried by AT-036a/b/c).
- **US-037 report section** (HLR-037) — confirm Inc-2 status / close.
- REQUIREMENTS.md §-entry + traceability update for US-036 (Phase 4/6).

## Evidence checklist

- [✓] Tests/type checks/lint pass — 12/12 new + 48 regression + 125 combined; `ruff` clean (`All checks passed!`).
- [✓] No secrets in code or output — synthetic byte patterns (`0x00`/`0xFF`/permutations) only.
- [✓] No destructive commands run without approval — read/test/ruff only.
- [✓] File count within cap — 4 files (screens.py, app.py, styles.tcss, new test); ≤5.
- [✓] Review packet attached — this document.
- [✓] Engine-frozen set untouched — `test_engine_unchanged.py` + `test_tc031_*` green (0 frozen diff); `color_policy.py` read-only, own band map used.

---

## Post-gate folds (code review)

Two approved review folds applied to Increment 3. Touched `s19_app/tui/screens.py` + `tests/test_tui_entropy_viewer.py` (2 files, ≤5).

### F1 (MEDIUM) — truncation indicator fires when EITHER cap is exceeded

`EntropyViewerScreen.compose`: the truncation-indicator guard was
`len(self._windows) > max(ENTROPY_STRIP_MAX_CELLS, ENTROPY_MAX_ROWS)`, which
only fired when **both** surfaces truncated. LLR-036.6 requires the indicator
"where the computed window count exceeds **either** cap." Changed `max(` →
`min(` so it fires as soon as either the strip or the jump list truncates, with
a comment noting the intent (either cap → indicator; use min so neither surface
truncates silently). Production cap VALUES unchanged (both still 512).

**TC-036.5 strengthened.** The existing `test_tc036_5_cost_cap_and_truncation`
uses equal caps (both 512) so it cannot distinguish `max` from `min`. Added a
new sibling test `test_tc036_5_truncation_fires_on_either_cap` that
`monkeypatch`es the two module-level cap constants UNEQUAL (strip cap =
`n_windows-1`, row cap = `n_windows+1`) — never editing their production values
— drives the shipped `e`-key surface, and asserts `#entropy_truncated` is still
present. Mutation-verified: with production reverted to `max()` the new test
FAILS; with `min()` it PASSES — so it genuinely pins the either-cap semantics.

### F3 (LOW) — type precision

`compose`: changed `body_children: List[object]` → `List[Widget]`, added
`from textual.widget import Widget`. `Widget` is the clean common supertype —
all members (`Static` strip, `ListView`, `Label` empty/truncated) are Textual
`Widget` subclasses.

### Real test result

`pytest tests/test_tui_entropy_viewer.py -v` → **13 passed in ~21s** (was 12;
+1 from the new either-cap test). `ruff check s19_app/tui/screens.py
tests/test_tui_entropy_viewer.py` → **All checks passed!**
