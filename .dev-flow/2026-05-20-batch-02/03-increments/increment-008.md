# Increment 008 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 8 — Modal re-skin (Load / Save / Load-Project)
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-015.1 (the three Load / Save / Load-Project modals re-skinned to the Calm Dark token set), LLR-015.2 (modal behavior preserved — `validate_project_files`, `copy_into_workarea` containment, path resolution, `SaveProjectPayload`, `.s19tool/` workarea layout). · **TCs covered:** TC-033 (modal styling — Calm Dark adoption), TC-034 (modal behavior + path-traversal containment).

---

## 1. What changed

The three `screens.py` modal screens — `LoadFileScreen`, `SaveProjectScreen`, `LoadProjectScreen` — were re-skinned to the Calm Dark theme. This is a **visual-only re-skin**: no behavior, no path handling, no `validate_project_files` / `SaveProjectPayload` / `.s19tool/` workarea logic was touched (LLR-015.2 / C-1 / A-5).

**Key fact discovered while reading the code:** the modals carried **no inline CSS at all** — `screens.py` had no `DEFAULT_CSS`. Their styling was already entirely external in `styles.tcss` via the `#load_dialog` / `#load_buttons` ids and the global `Screen` rule. The pre-batch modals therefore had no hard-coded hex colors to swap; the re-skin work was to give the modals a complete, intentional Calm Dark surface (dimmed backdrop, accent title, accent confirm button, themed inputs) instead of inheriting only the bare `#load_dialog` rule.

The increment-plan's Approach line suggested keeping per-screen `DEFAULT_CSS` referencing `$accent-calm` etc. That path was attempted and **does not work**: a screen's `DEFAULT_CSS` is parsed in isolation and the Calm Dark `$bg-*` / `$fg-*` / `$rule` token variables (declared at the top of `styles.tcss`) are not in scope there — Textual raises `UnresolvedVariableError: reference to undefined variable '$bg-base'`. All modal styling therefore lives in `styles.tcss`, where the tokens resolve. This is recorded in a `screens.py` module comment and the `styles.tcss` block comment. `screens.py` declares **no `DEFAULT_CSS`** — confirmed safe because the three modal classes are the only `ModalScreen` subclasses in the app, so the `ModalScreen { ... }` rule in `styles.tcss` matches exactly them.

**`screens.py` changes (composition + classes only):**
- Each modal's dialog `Container` gained the shared `classes="modal-dialog"` and kept its legacy `id="load_dialog"`.
- Each modal's title `Label` gained `classes="modal-title"`.
- Each modal's button row `Container` gained `classes="modal-buttons"` (kept `id="load_buttons"`).
- Each modal's confirm button (`load_ok` / `save_ok` / `project_ok`) gained `classes="modal-confirm"` so it carries the single Calm Dark accent. A Textual `variant="primary"` was deliberately **not** used — `variant="primary"` would pull in Textual's built-in `$primary` hue, which is a *second* accent and would fail TC-033's single-accent rule.
- Docstrings updated to note the re-skin (PROJECT_RULES.md contract); a module comment explains why modal CSS lives in `styles.tcss`.

**`styles.tcss` changes (the modal token block):** the former 2-rule `#load_dialog` / `#load_buttons` block was extended into the full Calm Dark modal block — `ModalScreen` (dimmed `$bg-base 70%` backdrop, centered), `.modal-dialog` / `#load_dialog` (round `$accent-calm` border, `$bg-panel` surface, `$fg-base` text), `.modal-title` (`$accent-calm` bold), `.modal-buttons` / `#load_buttons` (right-aligned), `.modal-buttons Button` (left margin), `.modal-confirm` (`$accent-calm` background, `$bg-base` text), `.modal-dialog Input` (+ `:focus` accent border), `#project_list` (themed list surface). Every color resolves through one of the five Calm Dark tokens — no hard-coded hex, no second accent, no light variant.

No engine, service, `validation/`, `color_policy.py`, `workspace.py`, parser, hex-cap constant or new runtime dependency was touched. `validate_project_files`, `resolve_input_path`, `copy_into_workarea`, `sanitize_project_name` and `SaveProjectPayload` are byte-identical.

## 2. Files modified

**Code / test (3 — under the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/screens.py` | modified | Added the shared `.modal-dialog` / `.modal-title` / `.modal-buttons` / `.modal-confirm` CSS classes to the three modals' `compose` trees (composition + class attributes only — no logic, no id removal, no `DEFAULT_CSS`). Added a module comment explaining why modal CSS must live in `styles.tcss` (token scope). Updated the three class docstrings to the PROJECT_RULES.md contract noting the re-skin. |
| `s19_app/tui/styles.tcss` | modified | Replaced the 2-rule `#load_dialog` / `#load_buttons` block with the full Calm Dark modal block: `ModalScreen` dimmed backdrop, `.modal-dialog`, `.modal-title`, `.modal-buttons`, `.modal-confirm`, `.modal-dialog Input` (+ `:focus`), `#project_list`. All color via the five Calm Dark `$`-tokens. |
| `tests/test_tui_directionb.py` | modified | Added the increment-8 block (9 tests): TC-033 ×4 (no hard-coded color / no per-screen `DEFAULT_CSS`; single accent + no second/built-in accent + no light variant; runtime render of all 3 modals against the resolved token values incl. dimmed backdrop; no non-canonical `sev-*` class in the modal block) and TC-034 ×5 (`validate_project_files` cardinality unchanged; `copy_into_workarea` containment unchanged; `..\..\` path-traversal destination stays contained; `resolve_input_path` returns None for a traversal miss; modal cancel/confirm behavior + `SaveProjectPayload` intact). Added a `_modal_css_block` helper and the `_MODAL_SPECS` / `_CALM_DARK_TOKENS` / `_SEV_CLASSES` fixtures. Module docstring extended to increment 8. |

**Documentation:**
- `.dev-flow/2026-05-20-batch-02/03-increments/increment-008.md` — this review packet.

**File count:** 3 — under the ≤5 cap.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed in this environment — py_compile substituted)
python -m py_compile s19_app/tui/screens.py tests/test_tui_directionb.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. The new increment-8 tests only
python -m pytest -q tests/test_tui_directionb.py -k "tc033 or tc034"

# 4. The existing modal/project-file behavior suite — must stay green
python -m pytest -q tests/test_tui_workspace.py tests/test_tui_directionb.py

# 5. Full suite — must not regress from the 338/2/3/0 baseline
python -m pytest -q
```

An additional `App.run_test()` smoke (run ad-hoc, see §4) opens each of the three modals and reads back the computed dialog border / panel background / title color / confirm-button background / dimmed backdrop, and confirms `validate_project_files` still rejects an invalid (two-S19) project set.

## 4. Test results

**`python -m py_compile s19_app/tui/screens.py tests/test_tui_directionb.py`** — actual output:
```
PY_COMPILE OK
```
Note: `ruff` is **not installed** in this environment (`ModuleNotFoundError: No module named 'ruff'`). Per the increment instructions `python -m py_compile` was substituted as the static check and passes on both changed Python files. `styles.tcss` is parsed by the Textual engine on every `run_test()`-based case in the suite — a malformed rule or an unresolved token would surface as a `StylesheetError` / `UnresolvedVariableError` at mount (this is in fact how the per-screen `DEFAULT_CSS` dead-end was caught — see §1 / §5). Recommend `ruff check .` in CI / a ruff-equipped environment before merge.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT OK
```

**New increment-8 tests** — `python -m pytest -q tests/test_tui_directionb.py -k "tc033 or tc034"` — actual output:
```
.........                                                                [100%]
9 passed, 50 deselected in 1.95s
```
9 new increment-8 cases: TC-033 ×4, TC-034 ×5.

**Existing modal/project-file behavior suite** — `python -m pytest -q tests/test_tui_workspace.py tests/test_tui_directionb.py` — actual output:
```
92 passed in 36.38s
```
33 `test_tui_workspace.py` (the `validate_project_files` cardinality / symlink / case-collision, `copy_into_workarea` containment, `resolve_input_path`, `sanitize_project_name`, logging-surface tests — all green, the project-file engine is untouched) + 59 `test_tui_directionb.py` (50 prior increments 2-7 + 9 new increment-8).

**Full suite** — `python -m pytest -q` — actual output (tail):
```
347 passed, 2 skipped, 3 xfailed in 118.22s (0:01:58)
```
Baseline was **338 passed / 2 skipped / 3 xfailed / 0 failed**. The 9 new increment-8 tests bring the total to **347 passed** (338 + 9); the 2 skipped + 3 xfailed are unchanged (pre-existing). 0 failed — **no regression**. No test was silently skipped. The `test_tui_workspace.py` modal/project-file tests and the `test_tui_app.py` `_handle_load_dialog` / `_handle_save_dialog` tests are all green.

**`App.run_test()` modal-render smoke** (all 3 modals + `validate_project_files`) — actual output:
```
IMPORT OK
LoadFileScreen:    border=round dialog-bg=#171B23 title=#4EC9D4 confirm=#4EC9D4 backdrop=#11141A@a0.7
SaveProjectScreen: border=round dialog-bg=#171B23 title=#4EC9D4 confirm=#4EC9D4 backdrop=#11141A@a0.7
LoadProjectScreen: border=round dialog-bg=#171B23 title=#4EC9D4 confirm=#4EC9D4 backdrop=#11141A@a0.7
validate_project_files (invalid 2xS19): 'Project already has more than one S19/HEX file.'
SMOKE OK
```
All three modals open under `App.run_test()` and render with the Calm Dark theme: dialog = round `$accent-calm` (`#4EC9D4`) border on the `$bg-panel` (`#171B23`) surface; title and confirm button both = the single `$accent-calm` accent; the `ModalScreen` backdrop = `$bg-base` (`#11141A`) dimmed to 70% alpha so the modal reads as an overlay. The accent and backdrop are identical across all three modals (single shared accent / single shared backdrop tone — TC-033). `validate_project_files` still rejects an invalid (two-S19) project set with the correct message — behavior preserved.

> **Note on the first increment-8 test run during dev:** 3 of the 9 new tests failed on the first run — all 3 were test-assertion bugs, not re-skin bugs, and were corrected within the 3-file scope: (a) `getattr(cls, "DEFAULT_CSS")` returns Textual's *inherited* `Screen.DEFAULT_CSS`, so the "no per-screen CSS" check was switched to `cls.__dict__.get(...)` to inspect the class's own attribute; (b) the token-set scan matched `$bg-*` / `$fg-*` from the *prose of the block comment* — fixed by slicing the block from its `/*` opening and stripping `/* ... */` comments before scanning; (c) the rendered backdrop `.hex` carries an 8th alpha byte (`#11141AB2`) because the backdrop is dimmed — fixed by comparing the RGB triple and separately asserting `alpha < 1`. The final run is clean.

## 5. Risks

- **`UnresolvedVariableError` if a per-screen `DEFAULT_CSS` is reintroduced.** The Calm Dark tokens (`$bg-base`, `$fg-base`, `$rule`, etc.) are declared at the top of `styles.tcss` and are only in scope for the app-level stylesheet. A future edit that adds a `DEFAULT_CSS` to a modal and references a `$bg-*` token there will crash at modal mount. This is documented in the `screens.py` module comment and the `styles.tcss` block comment, and `test_tc033_modals_use_only_calm_dark_tokens_no_hardcoded_color` asserts the three modal classes declare no own `DEFAULT_CSS` — a reintroduction fails that test loudly.
- **`ModalScreen { ... }` is a broad selector.** The dimmed-backdrop rule keys on the `ModalScreen` type, not an id. It is correct **today** because the three `screens.py` classes are the only `ModalScreen` subclasses (verified by grep). If a future increment adds another `ModalScreen` it will inherit the Calm Dark backdrop — generally desirable, but worth knowing the rule is type-scoped.
- **Legacy shared `id="load_dialog"`.** All three modals still carry the literal `id="load_dialog"` (pre-batch state — `SaveProjectScreen` / `LoadProjectScreen` already reused it). Each modal is its own `ModalScreen`, so within a single mounted modal the id is unique and `query_one("#load_dialog")` is unambiguous; the duplication only exists *across* modals that are never mounted simultaneously. Not changed here to keep the re-skin behavior-neutral (no id rename) — the new `.modal-dialog` class is the canonical selector. Flagged for a possible later cleanup.
- **No visual / interactive verification.** All checks are headless (`App.run_test()` / `pytest` / computed-style read-back). The modals were not eyeballed in a real terminal — the dimmed backdrop, the accent border and the themed inputs render correctly per the computed-style assertions, but font/terminal rendering was not observed. A manual TUI pass is advisable before batch close.
- **Path containment is unchanged but security-adjacent.** TC-034 re-runs the `copy_into_workarea` containment guard and adds a `..\..\` path-traversal sub-case; `workspace.py` is byte-identical. This increment should still get a `security-reviewer` pass (path-containment-adjacent, S-4) to confirm the re-skin introduced no new path-handling surface — it did not (the modals only `dismiss(Path(value))` exactly as before).

## 6. Pending items

- **`security-reviewer` pass** — flagged by the increment-plan (S-4, path-containment-adjacent). The re-skin touched no path code (`workspace.py` byte-identical; modals' `dismiss` payloads unchanged); TC-034 re-runs the containment tests and adds the traversal sub-case. The reviewer should confirm no new path-handling surface was introduced before this increment's gate.
- **Manual TUI pass** — launch `s19tui`, press `Ctrl+L` (Load file), `Ctrl+S` (Save project), `Ctrl+P` (Load project); confirm each modal renders the dimmed backdrop, the accent border, the accent title and confirm button, and the themed inputs; confirm Cancel/confirm still work. Deferred to the Phase-4 validation gate.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **Legacy shared `id="load_dialog"`** — see §5; consider renaming the three dialog ids unique in a later cleanup increment.
- **Snapshot baselines (increment 12)** — the increment-12 snapshot matrix covers the 4 restyled screens + 3 scaffolds; the modals are not in the 27-baseline matrix. Modal layout-drift is therefore guarded only by TC-033's computed-style assertions, not a snapshot — acceptable per the increment-plan (modals are not a rail screen).
- **REQUIREMENTS.md traceability** — if `R-TUI-014` (project-file rule) or a modal-styling row is mapped, refresh it to cite `test_tui_directionb.py` TC-033/TC-034. Not done here (out of the 3-file scope; flagged for the docs increment).

## 7. Suggested next task

**Increment 9 — Memory Map + Bookmarks scaffolds** (LLR-012.1, LLR-002.2, LLR-012.4). New content in `screens_directionb.py`: a `MemoryMapScreen` content widget rendering ranges / gaps / coverage **only** from the existing `LoadedFile.ranges` / `range_validity` (no new coverage computation — C-4/C-5/LLR-012.4), and a `BookmarksPlaceholder` "coming soon" widget that invokes no persistence logic; wire them into `#screen_map` / `#screen_bookmarks` in `app.py`; add the Memory Map + Bookmarks rules to `styles.tcss`; extend `tests/test_tui_directionb.py` with TC-004, TC-025 and the scaffold side of TC-028 (no new processing module; `bincopy`/`pya2l`/`crcmod` absent from imports).

**Do not start increment 9 — this increment (8) is complete and stops here.**
