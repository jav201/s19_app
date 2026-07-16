# Increment 01 — US-FND Foundation helpers (`insight_style.py`)

> Batch-47 (screen-upgrades Batch A) · Story US-FND · HLR-065 / LLR-065.1 / LLR-065.2
> Branch `claude/screen-upgrades-handoff-0874f9` · Artifact language: English

## 1. What changed

Added the NON-frozen foundation helper module `s19_app/tui/insight_style.py` (pattern:
`entropy_style.py`) plus its unit test suite. The module ships:

- **Palette constants (LLR-065.1)** — 14 module-level UPPER_SNAKE hex constants matching the
  operator-approved dolphie SVG palette: `LABEL`, `VALUE`, `GREEN`, `YELLOW`, `RED`, `HILITE`,
  `LBLUE`, `DGRAY`, `PURPLE`, `CYAN`, and the navy depth stack `DEPTH_BG` / `DEPTH_PANEL` /
  `DEPTH_ODD_ROW` / `DEPTH_BORDER`. LLR-065.1 lists values but leaves naming open → chose clear
  UPPER_SNAKE constants (noted). Also two internal glyph constants `MICROBAR_FILLED = "█"` /
  `MICROBAR_EMPTY = "░"`.
- **Four pure helpers (LLR-065.2)** — signatures as implemented:
  - `human_bytes(n: int) -> str` — decimal (SI, 1000-based) humanizer. `<1000` → integer + `B`;
    `>=1000` → one decimal + largest unit. **Divisor is decimal (1000)**, forced by the canonical
    TC-065.1 threshold `10**9 → "…GB"` (binary 1024 would put `10**9` in MB — see Risks).
  - `label_value(label: str, value: str, style: str = "") -> Text` — muted label + styled value,
    built via `Text()` + `append` (C-17-safe; never `from_markup`).
  - `microbar(frac: float, width: int, style: str = "") -> Text` — `round(clamp(frac)*width)` filled
    cells; `frac` clamped to `[0,1]`; `width=0` → empty `Text`; total glyph count always `width`.
  - `threshold_style(pct: float, warn: float, bad: float) -> str` — lower-inclusive bands
    (`pct<warn`→GREEN, `warn<=pct<bad`→YELLOW, `pct>=bad`→RED); boundary `pct==warn`→YELLOW,
    `pct==bad`→RED.

Full PROJECT_RULES.md docstrings (Summary→Args→Returns→Data Flow→Dependencies→Example) on the module
and each public helper. Type hints on all signatures. `Text` = `rich.text.Text` for the two
Text-returning helpers. No member named `_nodes`/`_context` (N/A — no widget/class, but honored).

## 2. Files modified (2 — within ≤5 cap)

- **NEW** `s19_app/tui/insight_style.py` — pure non-frozen helper module (palette + 4 helpers).
- **NEW** `tests/test_tui_insight_style.py` — 6 unit tests.

No frozen file, `styles.tcss`, `app.py`, or service touched.

## 3. How to test

```bash
python -m pytest -q tests/test_tui_insight_style.py
ruff check s19_app/tui/insight_style.py tests/test_tui_insight_style.py
# C-27 frozen dual-guard:
python -m pytest -q tests/test_engine_unchanged.py \
  "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" \
  "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main"
```

## 4. Test results (RED → GREEN evidence)

**RED counterfactual (C-20, net-new module).** Before `insight_style.py` existed, the test file
failed at import — natural RED, no stash:

```
tests\test_tui_insight_style.py:20: in <module>
    from s19_app.tui.insight_style import (
E   ModuleNotFoundError: No module named 's19_app.tui.insight_style'
1 error in 0.50s
```

**Intermediate RED (real defect caught).** First implementation used a binary (1024) divisor →
`human_bytes(10**9)` returned `"953.7 MB"`, failing the canonical `10**9 → "…GB"` threshold. Fixed
to decimal (1000) divisor + adjusted the B-cutoff to `<1000`; re-derived my own extra assertions.

**GREEN (after fix):**

```
tests/test_tui_insight_style.py ......   [100%]
6 passed in 0.21s
ruff: All checks passed!
```

**C-27 frozen dual-guard:**

```
tests/test_engine_unchanged.py + test_tc031 + test_tc032
3 passed in 0.61s
```

Counts from one run each (C-19): insight tests **6 passed / 0 failed**; frozen guards **3 passed /
0 failed**. `git status --porcelain` confirms only the 2 intended code files are added.

### TC ids realized (grep-confirmed test functions)

| TC (01b) | Test function | Facet |
|---|---|---|
| TC-065.1 | `test_human_bytes` | `0→"0 B"`, `1024→"1.0 KB"`, `10**9→"…GB"` (+ decimal boundaries) |
| TC-065.2 | `test_microbar`, `test_microbar_returns_text` | `frac=0.0`→0 filled, `1.0`→width, `0.5`→`round(width/2)`, clamp; returns `Text` |
| TC-065.3 | `test_threshold_style` | green/yellow/red band + `pct==warn`/`pct==bad` boundaries |
| TC-065.4 | `test_label_value_returns_text` | returns `rich.text.Text`, not `str`; hostile value literal |
| LLR-065.1 | `test_palette_constants_present_and_correct` | all 14 constants present + exact hex |

## 5. Risks

- **Divisor base decision (decimal vs binary).** The canonical TC-065.1 threshold `10**9 → GB`
  forces a **decimal (1000)** divisor; binary would render `10**9` as MB. Firmware sizes are often
  thought of in binary, so downstream consumers (Workspace section rows LLR-066.2, Memory-Map region
  rows) will show SI-style humanized sizes (`1.0 GB` for `10**9`). If the operator expects binary
  (KiB/MiB), flag at the Workspace/Map increment — the helper is the single source, so it is a
  one-line change + test-threshold update, but it is a **user-visible convention** worth confirming.
- **`round` uses banker's rounding.** `microbar(0.5, width)` == `round(width/2)`, matching the
  canonical threshold verbatim (both use Python `round`), so `width=5`→2 filled. Deterministic and
  intentional; documented in the docstring.
- **No styling/theme yet.** `styles.tcss` navy/pastel theme (LLR-065.3) is a LATER increment — this
  increment has **zero snapshot impact** by design (no widget/CSS touched).

## 6. Pending items (this story, later increments)

- LLR-065.3 — `styles.tcss` navy/pastel theme + chrome (separate increment; massive expected
  snapshot drift, canonical-CI regen).
- LLR-065.4 — `sev-*` name/semantics preservation + §6.5 amendment iff any sev hue changes.
- AT-065a / AT-065b — screen-level palette + sev-round-trip ATs (`test_tui_theme.py`), land with the
  theme increment.
- Consumers of these helpers wire in at US-WS / US-MAC / US-MAP increments.

## 7. Suggested next task

Increment 02 — **LLR-065.3/065.4 theme increment**: apply the navy/pastel palette to `styles.tcss`
`$`-vars + panel `border: tall` / `border-title-*` / zebra / chip styles; author
`tests/test_tui_theme.py` (TC-065.5 accent-hue==1 / 5 sev rules / no light variant + AT-065a/065b);
run `test_color_policy_round_trip` (frozen) + C-27 dual-guard; mark expected snapshot-drift cells
(C-22/C-28) for the canonical-CI regen follow-up. Confirm the decimal-vs-binary `human_bytes`
convention with the operator before the Workspace/Map size read-outs ship.

---

### Evidence checklist

- [x] Tests/type checks/lint pass — `6 passed`; `ruff: All checks passed!` (insight_style.py + test).
- [x] No secrets in code or output — pure palette hex + arithmetic; none present.
- [x] No destructive commands run without approval — only reads, pytest, ruff, git status.
- [x] File count within cap — 2 new files (≤5); `git status --porcelain` confirms.
- [x] Review packet attached — this document.

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review (code-reviewer):** APPROVE-WITH-NITS, 0 HIGH. RED→GREEN + C-27 0-diff independently reproduced (6 passed / 3 guard passed). One LOW nit F1 (banker's-rounding tie under-tested) — **APPLIED** (`test_microbar` now asserts `microbar(0.5, 5).count("█")==2`).
- **Operator units decision (AskUserQuestion 2026-07-15): BINARY (KiB/MiB, 1024).** `human_bytes` converted decimal→binary (1024 divisor, `KiB/MiB/GiB/TiB/PiB`); a `0x10000` region now reads `"64.0 KiB"`. Recorded as **§6.5 Amendment D** (01-requirements.md) + TC-065.1 threshold updated (01b). Re-verified: **6 passed, ruff clean.**
- **Gate axis check:** Coverage OK (TC-065.1..4 + LLR-065.1 realized, grep-confirmed); Certainty OK (return-type-is-Text asserts, clamp/boundary/tie cases, hostile-bracket literal); Evidence OK (RED→GREEN + C-27 from reproduced runs). **APPROVE.** → Inc-2 (US-WS data).
