# Increment 001 — US-059 (B-24) Workspace hex-view colour legend

Scope: **US-059 only** (HLR-059 / LLR-059.1 · LLR-059.2 · LLR-059.3). 4 source/test
files, within the ≤5 cap. `color_policy.py` (engine-frozen) READ-only, never edited.

## 1. What changed
Added a **`"Hex"` block** to the shared `LEGEND_TABLE` (`s19_app/tui/legend.py`) so both
legend surfaces — the in-app `LegendScreen` modal and the generated project report's
`## Legend` section — now document the two byte-cell overlay colours the hex view paints:

| Colour (derived) | Source constant (READ from frozen `color_policy`) | Meaning string |
|---|---|---|
| **Yellow** | `FOCUS_HIGHLIGHT_STYLE = "bold yellow"` | `search / goto-focus highlight: the byte span matched by the last in-memory search or goto-address jump in the hex view` |
| **Orange3** | `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"` | `MAC address overlay: a hex byte at an address referenced by a loaded MAC record` |

- Colour names are **derived** (not hardcoded) via a new deterministic helper
  `_colour_name_from_style(style)` — drops Rich modifier tokens, title-cases the remaining
  colour token AS-IS → `"Yellow"` / `"Orange3"`. The shade digit is **retained** on purpose:
  a digit-stripped `"Orange"` would collide with `COLOUR_SEVERITY["Orange"] → WARNING` and
  wrongly paint the row `sev-warning` (R-A04). Both derived names are absent from
  `COLOUR_SEVERITY`, so the modal renders `sev_class = ""` (no crash, empty severity column).
- New `HEX_LEGEND_STYLES` dict couples the Hex colour set to the two `color_policy` constants
  (anti-drift identity, LLR-059.3).
- Hex meaning strings are markup-free (no `[` / `]`), since the modal renders each row through
  a markup-enabled `Label` (S-01).
- `>`-glyph goto focus-row marker is deliberately **NOT** a legend colour row (it is a glyph,
  not a colour) — a recorded decision, not an omission (LLR-059.1 acceptance criteria).
- Anti-drift test updates (LLR-059.3): scoped the TC-S1 orphan-colour guard to the
  severity-driven artifacts (A2L/MAC/Issues) and admitted `"Hex"` to the artifact-set assertion.
- The batch-35 byte-identity golden `at055b-project-report.md` was rebaselined to include the
  new `### Hex` legend section (the only delta — see Risks / §5.1 census-gap finding).

## 2. Files modified
1. `s19_app/tui/legend.py` — `_RICH_MODIFIERS`, `_colour_name_from_style()`,
   `_HEX_STYLE_MEANINGS`, `HEX_LEGEND_STYLES`, `_HEX_ROWS`, `"Hex"` block in `LEGEND_TABLE`;
   imports the two overlay constants from `color_policy` (READ-only).
2. `tests/test_tui_legend.py` — modified 2 existing assertions (`:78` artifact-set → add
   `"Hex"` + Hex row-set; `:70` orphan-colour → scoped to `_SEVERITY_ARTIFACTS`); added
   `test_at059a_hex_legend_present_in_modal` (AT-059a) and
   `test_tc322_hex_block_coupled_to_overlay_styles` (TC-322).
3. `tests/test_tui_report_seam.py` — added `test_at059b_hex_legend_present_in_report`
   (AT-059b, C-12 output-then-consume).
4. `tests/goldens/batch35/at055b-project-report.md` — inserted the `### Hex` legend block
   after the Issues block (rebaseline; only delta).

## 3. How to test
```
pytest tests/test_tui_legend.py tests/test_tui_report_seam.py -q          # 41 passed
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "engine or unchanged or tc031" -q   # frozen guards, 10 passed
ruff check s19_app/tui/legend.py tests/test_tui_legend.py tests/test_tui_report_seam.py
pytest -k at059 -q          # both ATs
```

## 4. Test results (RED-then-GREEN, C-19 one complete run each)

### RED (pre-legend-block, tests already written)
`pytest tests/test_tui_legend.py::test_at059a_... ::test_tc322_... ::test_legend_table_has_documented_artifacts_and_rows tests/test_tui_report_seam.py::test_at059b_... -q`
→ **4 failed**. Evidence tail:
- `test_at059a...` — `AssertionError: the modal has no Hex artifact section` (`"Hex" not in headers`).
- `test_tc322...` — `ImportError`/`AttributeError`: `HEX_LEGEND_STYLES` / `_colour_name_from_style` absent from `legend`.
- `test_legend_table_has_documented_artifacts_and_rows` — `set(LEGEND_TABLE) == {"A2L","MAC","Issues","Hex"}` fails (Hex absent).
- `test_at059b...` — `AssertionError: the report legend must contain a Hex section` — reread `## Legend` region held A2L/MAC/Issues but **no `### Hex`** (proves the report legend mechanism reaches the file; only Hex missing — the exact counterfactual).

### GREEN (post-legend-block) — one complete run
`pytest tests/test_tui_legend.py tests/test_tui_report_seam.py -q`
→ **`41 passed in 103.54s`  EXIT=0**.
Engine-frozen guards: `10 passed, 154 deselected  EXIT=0`; `git diff --stat s19_app/tui/color_policy.py` empty (frozen intact). `test_legend_data_not_in_frozen_color_policy` green inside the 41.
Ruff: `All checks passed!  RUFF_EXIT=0`.

Note: an interim GREEN run (before the golden rebaseline) surfaced 1 failure —
`test_at_055b_no_filter_generate_report_byte_identical_to_golden` — because the added `### Hex`
legend legitimately drifts the full-report byte-identity golden. Rebaselining the golden (only
delta = the Hex block) cleared it; the final run above is clean.

### Per-LLR coverage
- **LLR-059.1** (Hex block sourced from overlay styles, markup-free) →
  `tests/test_tui_legend.py::test_tc322_hex_block_coupled_to_overlay_styles` +
  `test_legend_table_has_documented_artifacts_and_rows`.
- **LLR-059.2** (one block reaches BOTH surfaces, single-source) →
  `tests/test_tui_legend.py::test_at059a_hex_legend_present_in_modal` +
  `tests/test_tui_report_seam.py::test_at059b_hex_legend_present_in_report` +
  `test_tc_s2_report_and_modal_render_same_rows` (survives, reruns green).
- **LLR-059.3** (anti-drift decoupled from `COLOUR_SEVERITY`, coupled to overlay styles) →
  `test_tc322_hex_block_coupled_to_overlay_styles` + the scoped
  `test_legend_table_covers_all_severities`.

### C-18 (one on-disk node per AT)
- **AT-059a** = exactly one node: `tests/test_tui_legend.py::test_at059a_hex_legend_present_in_modal`.
- **AT-059b** = exactly one node: `tests/test_tui_report_seam.py::test_at059b_hex_legend_present_in_report`.

### Test-count ledger
`post = base − D + A` → **1365 = 1362 − 0 + 3** (A = AT-059a, AT-059b, TC-322; D = 0). Verified by `--collect-only`.

## 5. Risks
- **Golden rebaseline (census gap).** The spec's LLR-059.3 supersession census enumerated exactly
  two breaking assertions (`:70`, `:78`) and asserted the frozen tests stay green — but it **missed**
  the batch-35 byte-identity golden `at055b-project-report.md`, which captures the FULL unfiltered
  report bytes including the legend. Adding the Hex legend section legitimately drifts it. Resolved
  by inserting the `### Hex` block into the golden (surgical, only delta). Low residual risk: the
  em-dash / exact meaning strings are re-verified by the green AT-055b byte-identity run.
- **No snapshot impact.** LEGEND_TABLE is static in-repo text; no SVG snapshot cell renders the
  legend modal in this batch's snapshot set, and no new snapshot xfail is introduced (US-059 owns
  no snapshot LLR). C-17 (render-mode flip over file-derived text) is N/A — the Hex rows are static
  literals with no file-derived input (spec §3 note).
- **Import direction.** `legend.py` now imports two constants from `color_policy`; no cycle
  (`color_policy` imports only `..validation`).

## 6. Pending items
- None blocking. The `>`-glyph exclusion and the plain-byte (no row) exclusion are recorded
  decisions, not omissions.
- REQUIREMENTS.md `R-TUI-047` ledger row (proposed) is a Phase-6 docs deliverable, not part of
  this code increment.

## 7. Suggested next task
Increment 2 — **US-058** (patch-editor readable paste box + control regroup, HLR-058), the
compose/CSS-only reparent with the per-width measured N_w pins (LLR-058.1) and the TC-321 patch
snapshot xfail marks; OR **US-060** (fixture relocation + heavy-A2L prune, HLR-060) with the
I-060-1 verify-before-delete gate. US-060 touches `git mv` / `git rm` and is best sequenced with
the construct-equivalence census.

## Evidence checklist
- [x] Tests/type-checks/lint pass — GREEN `41 passed EXIT=0`; ruff `All checks passed!`; frozen guards `10 passed EXIT=0`.
- [x] No secrets in code or output — none introduced.
- [x] No destructive commands run without approval — none (golden edited via Edit; no `git rm`/`git mv`).
- [x] File count within cap — 4 source/test files (≤5).
- [x] Review packet attached — this document.
