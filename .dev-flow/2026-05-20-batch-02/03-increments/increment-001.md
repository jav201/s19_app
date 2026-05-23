# Increment 001 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 1 — Theme tokens, `styles.tcss` extraction, keymap proposal + req-doc cosmetics
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-005.1, LLR-005.2 · **TCs covered:** TC-012, TC-013 · also delivers the OQ-8 keymap proposal (unblocks TC-030) and folds in CV-01..CV-05.

---

## 1. What changed

The inline Textual stylesheet (`S19TuiApp.CSS`, formerly app.py lines 416-694, ~280 lines) was extracted verbatim into a new `s19_app/tui/styles.tcss` file — every `#id` and `.class` rule carried over 1:1 — and `app.py` now references it via `CSS_PATH = "styles.tcss"` instead of the inline string. With the verbatim move confirmed (app still launches, full suite green), the Calm Dark theme was layered on top: one accent hue variable (`$accent-calm`, calm cyan-blue `#4ec9d4`), dark-only `$bg-base` / `$bg-panel` / `$fg-base` / `$rule` tokens, and the five `sev-*` rules retuned to calm hex values while keeping their class names and severity meaning. The `.mac_out_of_range` MAC overlay rule is preserved. `pyproject.toml` gained a `textual>=8.0.2` floor (the currently-installed version), a dev-only `[project.optional-dependencies]` extra pinning `pytest-textual-snapshot==1.1.0`, and a registered `snapshot` pytest marker. A new `tests/test_tui_theme.py` parses `styles.tcss` to verify the theme token budget (TC-012) and the severity-class binding (TC-013). Two dev-flow process docs were also produced: the OQ-8 keymap proposal and the CV-01..CV-05 cosmetic fixes to `01-requirements.md`. `color_policy.py` is byte-identical — untouched.

## 2. Files modified

**Code / config / test (4 — within the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/styles.tcss` | NEW | Extracted inline CSS verbatim + Calm Dark token layer (one accent, dark-only tokens, retuned `sev-*` hex, preserved `.mac_out_of_range`). |
| `s19_app/tui/app.py` | modified | Replaced the inline `CSS = """..."""` block with `CSS_PATH = "styles.tcss"`. No other change. |
| `pyproject.toml` | modified | `textual>=8.0.2` floor; `[project.optional-dependencies] dev` with pinned `pytest-textual-snapshot==1.1.0`; registered `snapshot` marker. |
| `tests/test_tui_theme.py` | NEW | TC-012 token-budget parse tests + TC-013(a) round-trip no-regression anchor + TC-013(b) per-`sev-*` rule assertion. |

**Dev-flow process docs (2 — not product code):**

| File | Status | Purpose |
|------|--------|---------|
| `.dev-flow/2026-05-20-batch-02/03-increments/keymap-proposal.md` | NEW | OQ-8 deliverable: global bindings + per-screen `show=True` footer set for all 8 rail screens. Unblocks TC-030. |
| `.dev-flow/2026-05-20-batch-02/01-requirements.md` | modified | CV-01..CV-05 cosmetic doc fixes only — no requirements scope change. |

**File count:** 4 code/config/test files + 2 dev-flow process docs = **6 files touched.** This matches the exact increment scope the user approved (the ≤5-file cap applies to the code/config/test slot, which is 4; the 2 dev-flow docs were explicitly additionally in scope per the increment brief).

## 3. How to test

```bash
# Theme tests (TC-012 + TC-013)
pytest -q tests/test_tui_theme.py

# Full suite — must stay green (no-regression)
pytest -q

# App still imports / launches with the new CSS_PATH
python -c "import s19_app.tui; print('import OK')"

# App.run_test() smoke (composes the app, loads styles.tcss):
python -c "import asyncio, tempfile, pathlib; from s19_app.tui.app import S19TuiApp; \
asyncio.run((lambda: (lambda app: app.run_test())(S19TuiApp(base_dir=pathlib.Path(tempfile.mkdtemp()))))().__aenter__())" \
  # (or run the inline async smoke used during dev — see Test results)

# Lint / format (see Test results — ruff is not installed in this env)
ruff check .
ruff format --check .
```

## 4. Test results (actual output)

**`pytest -q tests/test_tui_theme.py`:**
```
................                                                         [100%]
16 passed in 0.29s
```

**`pytest -q` (full suite):**
```
275 passed, 2 skipped, 3 xfailed in 83.39s (0:01:23)
```
0 failed. The 2 skipped + 3 xfailed are pre-existing (unchanged from before the increment). No test was silently skipped by this increment.

**App import + `run_test()` smoke:**
```
import OK
run_test smoke OK — app composed, styles.tcss loaded, #hex_panel found
```
The app composes, the `styles.tcss` stylesheet loads via `CSS_PATH`, and a known `#id` rule target (`#hex_panel`) is found in the widget tree.

**`pyproject.toml` validity + `pytest-textual-snapshot` resolution:**
```
pyproject.toml valid TOML
optional-deps: {'dev': ['pytest-textual-snapshot==1.1.0']}
markers: ['slow: ...', 'snapshot: marks pytest-textual-snapshot layout-drift tests ...']
pip install pytest-textual-snapshot==1.1.0 --dry-run -> Would install pytest-textual-snapshot-1.1.0
```
`1.1.0` is the latest published version (available: 1.1.0, 1.0.0, 0.4.0, ...) and resolves cleanly.

**`ruff check .` / `ruff format --check .`:** **NOT RUN — ruff is not installed in this environment** (`No module named ruff`, `ruff: command not found`). As a substitute, `python -m py_compile` was run on both edited Python files (`app.py`, `test_tui_theme.py`) — both compile clean. `styles.tcss` is parsed by the new test file and by the Textual engine during the `run_test()` smoke. Recommend running `ruff check .` / `ruff format --check .` in CI or a ruff-equipped environment before merge.

## 5. Risks

- **CSS extraction fidelity.** ~280 lines of inline CSS moved to a file; a dropped/reordered rule could silently change rendering. Mitigation applied: every `#id`/`.class` rule was carried 1:1, and the retheme was layered only after the verbatim move was confirmed by the full suite staying green and the `run_test()` smoke finding a styled widget. Residual risk: visual-only drift (border tone, panel background) is intentional (the Calm Dark retheme) and is not asserted by any automated test in this increment — TC-016-S snapshot baselines (increment 12) are the layout-drift guard.
- **`textual` floor.** `textual>=8.0.2` is set exactly at the installed version (8.0.2), no upper ceiling — cannot clash with the current install. A future environment with an older `textual` would now fail to install; this is the intended C-8/OQ-13 tightening.
- **`pytest-textual-snapshot` not installed here.** The dev extra is declared but not installed in this environment — that is correct for increment 1 (the snapshot tests land in increment 12). The `snapshot` marker is registered now so increment 12 has no config churn. If a future environment installs the `dev` extra, `pytest-textual-snapshot` registers its own `snap_compare` fixture; no conflict expected.
- **Keymap proposal is a design artifact, not code.** It must be reviewed/approved before increments 2-4 wire bindings against it. It carries 3 open points for owner sign-off (section 5 of the proposal). Flagged for owner review.
- **`color_policy.py` retune coupling.** The `sev-*` hex values in `styles.tcss` changed, but the class names and `SEVERITY_CLASS_MAP` are untouched — TC-013(a) anchors this. No semantic drift.

## 6. Pending items

- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment. Must be run in a ruff-equipped environment / CI before merge (see Test results §4).
- **Keymap proposal needs owner sign-off** — `keymap-proposal.md` section 5 lists 3 open points (`ctrl+l`/`ctrl+s` aliases, `q`-during-input-focus suppression, scaffold screens with no per-screen bindings). Increments 2-4 are blocked on this approval.
- **Legacy `project.toml` drift (intentional, noted).** The repo-root `project.toml` is the historical pre-PEP-621 copy and is **not read by the build backend** (per `CLAUDE.md`). Per the increment brief, `pyproject.toml` was edited and `project.toml` was deliberately **not** edited. `project.toml` now lags `pyproject.toml` by: the `textual>=8.0.2` floor, the `[project.optional-dependencies] dev` block, and the `[tool.pytest.ini_options]` markers (it never had a `[tool.pytest]` section). This drift is harmless (the file is inert) but is recorded here per the "keep them aligned" note in `CLAUDE.md` — if alignment is later wanted, `project.toml` would need the same three edits.
- **Empty-state snapshot baseline (CV-03)** — deferred to increment 12 at implementer discretion; noted in TC-016-S / TC-037.
- **119-column boundary check (CV-04)** — to be implemented in increment 12; noted in TC-016 / TC-017.

## 7. Suggested next task

**Increment 2 — App shell + 8-container screen routing + density toggle** (LLR-002.1, LLR-002.3, LLR-006.1, LLR-006.2, LLR-007.1 skeleton). Replace the 3-layout (`#main/alt/mac_layout`) toggle with the Direction B body — a command-bar mount point, a `Rail` mount point, and an 8-child `#workspace_body` of `.hidden`-toggled screen containers — plus `action_show_screen`, the `EmptyStatePanel`, and the `Ctrl+D` density cycle. **Prerequisite:** the keymap proposal from this increment should be signed off by the owner first, since increment 2's `action_show_screen` keys (`1`-`8`) and increment 4's bindings are wired against it.

---

*Increment 1 complete. Stopping at the increment boundary — increment 2 is NOT started.*
