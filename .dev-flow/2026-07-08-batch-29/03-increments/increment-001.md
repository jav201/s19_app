# Increment 001 — US-042: bound the OS-clipboard read (R-TUI-044)

**BLUF.** `read_os_clipboard` now caps any clipboard value it returns to
`_CLIPBOARD_READ_CAP_CHARS = 65536` at a single funnel, so an oversized OS
clipboard can no longer flow unbounded into `splitlines`, the Load-dialog Input,
or the logs. 9 new tests (AT-042a–f + TC-042.1–.3) all green; production file
ruff-clean; engine-frozen diff 0. Ledger 1171 → 1180. **No commit.**

Batch: 2026-07-08-batch-29 · Branch: `claude/batch-29-clip-cap-datatable-retire`
Toolchain: Python 3.14.4 · pytest 8.4.2 · ruff 0.15.17 · `pip install -e .` OK.

---

## 1. What changed
- **LLR-044.1** — Added module constant `_CLIPBOARD_READ_CAP_CHARS = 65536`
  beside the budget constants (`os_clipboard_input.py`), with a one-line comment
  (64 Ki chars ≈ 2× the largest legal Windows extended path → a real path never
  truncates).
- **LLR-044.2 / .5** — Added a tiny module-private helper `_bound_clipboard_text`
  (passes `None`/short through, truncates longer to `[:CAP]`, never raises) and
  applied it at the single non-`None` funnel in `read_os_clipboard`
  (`text = _bound_clipboard_text(text)` **before** the success debug-log +
  return). The `len=%d` log therefore now reports the post-cap length
  automatically (LLR-044.5). Every layer (tk/ctypes/PS) and any injected
  `strategies` cascade is covered by this one funnel.
- **LLR-044.3 / .4** — Left `action_paste` unchanged: truncation returns the
  capped prefix (never `None`), so paste inserts the bounded first line via
  `splitlines()[0]` and does not fall through to the internal buffer or the
  failure notification. **No second cap added in `action_paste`** (spec: it must
  operate on already-bounded text).
- Docstring discipline: updated `read_os_clipboard`'s Returns / Data Flow /
  Dependencies (Uses) to name the bound + the helper; the new helper carries a
  full Summary/Args/Returns/Data Flow/Dependencies docstring.

No deviation from the approved spec. Helper route chosen (spec-permitted) for the
cleaner TC-042.2 unit.

## 2. Files modified
1. `s19_app/tui/os_clipboard_input.py` — constant + helper + one-line funnel edit
   + docstring updates.
2. `tests/test_loadfilescreen_input.py` — appended 9 tests (US-042 section).
3. `.dev-flow/2026-07-08-batch-29/03-increments/increment-001.md` — this packet.

Within the ≤5-file cap (2 code/test files). No frozen file touched.
(`.dev-flow/state.json` shows modified in `git status` — pre-existing, not edited
by this increment.)

## 3. How to test
```bash
python -m pytest tests/test_loadfilescreen_input.py -q          # 29 pass
python -m ruff check s19_app/tui/os_clipboard_input.py          # clean
python -m pytest tests/test_engine_unchanged.py -q              # 0 frozen diffs
python -m pytest --collect-only -q                             # 1180 collected
```

## 4. Test results (real output)
- `pytest tests/test_loadfilescreen_input.py -q` → **29 passed in 26.57s**
  (20 pre-existing + 9 new).
- `ruff check s19_app/tui/os_clipboard_input.py` → **All checks passed!**
- `pytest tests/test_engine_unchanged.py -q` → **1 passed** (engine-frozen diff 0;
  this increment touches no frozen file).
- `pytest --collect-only -q` → **1180 collected** (base 1171 + 9).

**Honest caveat (ruff on the test file):** `ruff check tests/test_loadfilescreen_input.py`
reports **1 error — F841 `before` unused at line 174**. This is
**pre-existing** (verified via `git stash`: the error is present on the
unmodified file, in `test_..._focus_stolen_by_button_reproduces_bug`, an untouched
function far above my appended code at line 627+). Per surgical-changes discipline
I did **not** touch it. My added test code is ruff-clean; the production file is
ruff-clean. Flagging for a separate cleanup, not fixing it in-scope here.

### TC/AT → LLR map
| Test (id) | LLR | Mechanism |
|-----------|-----|-----------|
| `test_at042a_...` (AT-042a) | LLR-044.2 | `read_os_clipboard(strategies=huge)` → len == CAP, == blob[:CAP] |
| `test_at042b_...` (AT-042b) | LLR-044.2/.3/.4 | **B-1 fix**: inject at `_STRATEGIES`, real `ctrl+v` → `input.value` len ≤ CAP, == blob[:CAP] |
| `test_at042c_...` (AT-042c) | LLR-044.2 | `"p"*CAP` → unchanged, len CAP |
| `test_at042d_...` (AT-042d) | LLR-044.2 | `"p"*CAP+"X"` → len CAP, last char `"p"` |
| `test_at042e_...` (AT-042e) | LLR-044.3 | real ~120-char path via `ctrl+v` → value == exact path |
| `test_at042f_...` (AT-042f) | LLR-044.4 | `"first\nsecond\nthird"` via `ctrl+v` → `"first"` |
| `test_tc042_1_...` (TC-042.1) | LLR-044.1 | constant exists, positive int (not bool), ≥ 4096 |
| `test_tc042_2_...` (TC-042.2) | LLR-044.2 | helper: ≤CAP unchanged; longer → `[:CAP]`; `""`/`None` no-raise |
| `test_tc042_3_...` (TC-042.3) | LLR-044.2/.3 | `read_os_clipboard` bounds the selected strategy result (caller-independent) |

**B-1 note in AT-042b (from `02-review.md`):** injection is at `_STRATEGIES`,
below the capped `read_os_clipboard`, so the real cap runs inside `action_paste`.
A wholesale `read_os_clipboard` monkeypatch would bypass the cap → false red /
forced second cap. The test carries this as an inline comment.

## 5. Risks
- **R-044-1 (low, disclosed in spec):** post-read cap is a *functional* bound, not
  a true source memory bound — each reader still transiently materializes the full
  string before the cap. Deferred LLR-044.6 (bounded Popen). Not this batch.
- **R-044-3 (low):** the internal-buffer fallback (`self.app.clipboard`) is not
  routed through `read_os_clipboard`, so it is not capped — but it is app-populated
  and short. Flagged in spec, not fixed (scope).
- Pre-existing F841 in the test file (above) — cosmetic, unrelated, left in place.

## 6. Pending items
- **Increment 2+ (US-043):** retire the hidden `#validation_issues_list` DataTable
  (LLR-043.R1–.R7) + restore the `.issue-related` node on `IssueRow` (LLR-043.R8),
  with the C-14 18-row test-migration census. Touches `app.py`, `issues_view.py`,
  `styles.tcss` + 5 test files.
- Not this increment: the pre-existing F841 lint (candidate for a trivial cleanup).

## 7. Suggested next task
Proceed to **Increment 2 — US-043 retirement (LLR-043.R1–.R5,.R7)**: remove the
DataTable compose/CSS/column-init/populate/row-select paths, keeping the grouped
panel + summary + paging, and migrate the C-14 census test files. Restoration
(LLR-043.R8 + AT-021 + TC-043-restore.1) can ride the same or a following
increment. Confirm scope/file-count before starting (US-043 spans >5 files → will
need explicit approval or sub-slicing).

---

### Evidence checklist
- [✓] Tests/type checks/lint pass — 29 pass; production file ruff-clean; engine
  guard 0-diff. (Test-file F841 pre-existing, disclosed §4.)
- [✓] No secrets in code or output — length-only logging preserved; no clipboard
  text logged.
- [✓] No destructive commands run without approval — only `git stash`/`stash pop`
  (non-destructive, round-tripped) to confirm the pre-existing lint.
- [✓] File count within cap — 2 code/test files (≤5). No frozen file touched.
- [✓] Review packet attached — this file.

### Ledger
- Base (collect-only): **1171**
- Post: **1180**  (Δ **+9** — AT-042a–f + TC-042.1–.3)
