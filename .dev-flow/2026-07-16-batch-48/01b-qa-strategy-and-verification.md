# 01b — QA Strategy & Verification — batch-48 (screen-upgrades Batch B: Patch Editor BIG)

> Companion to `01-requirements.md` (architect-owned — **not** edited here).
> **Phase-2 FOLD PASS (2026-07-16).** This document was originally authored **before `01-requirements.md` existed**
> and carried a provisional id space that `D-2` (US-P1 split → HLR-075 render / HLR-076 chips) invalidated. Per
> **BL-2**, `01-requirements.md` **§5.2 is CANONICAL**; every AT/TC id and node path below is re-numbered onto it.
> **AT/TC bodies (Given/When/Then, executed verification, numeric thresholds) are carried over unchanged except
> where a fold explicitly rewrites them.** The old→new map is §0.1; the fold ledger is §0.2.
> Recon anchored @ `6551aed`. Artifact language: English.

---

## 0. BLUF

- **Two-layer verification.** Layer A = white-box `TC-NNN` (unit/pilot/inspection/analysis over the mechanism,
  **1:1 with the LLR it validates** — the canonical §5.2 scheme). Layer B = **black-box `AT-NNN`** driving the
  SHIPPED Patch screen via `App.run_test(size=…)` and asserting the observed deliverable at **both 80×24 and
  120×30** (the batch-47 `_SIZES = ((80, 24), (120, 30))` both-regimes loop, reused verbatim).
- **45 executable TCs · 26 ATs** on the canonical id space — **the PINNED registry** (02-review POST-FOLD
  RECONCILIATION, 2026-07-16). 26 ATs × 2 pilot sizes = **52 AT executions**. The Phase-1 draft declared 23; the
  Phase-2 folds add exactly **3**: `AT-075e` ★★ (BL-1) · `AT-077e` ★ (BL-4 — **split from `AT-077c`**) · `AT-079d`
  (MJ-4, the fallback path). **This set is identical, id-for-id, to `01-requirements.md` §5.2.**
- **6 gate-blocking ATs** — three C-17 (`AT-075d` variant line · **`AT-075e` entries table, NEW** · `AT-079c`
  pasted JSON) and three wrong-answer-class (`AT-077c` document provenance · **`AT-077e` image generation, NEW** ·
  `AT-080d` C-29/B2 reachability). **`AT-080e` is NOT among them and is not an AT today** — it is
  conditional-on-grep (MJ-7): the LLR-080.7 mechanical gate fires ⇒ it is created that increment, gate-blocking.
- **The threat model is corrected (BL-1).** The paste buffer is **safe by construction**; the **entries table is the
  live `Text.from_markup` sink at HEAD**. `AT-075e` is the missing peer of `AT-079c` and is gate-blocking.
- **The glyph folds into the `Kind` cell (BL-3) — there is NO 6th column. T-1 is DISSOLVED** (§9.1). The 32-hit
  census file `tests/test_tui_patch_editor_v2.py` needs **zero** edits; if it ever does, the fold was implemented
  wrong — a free correctness signal, encoded as a threshold on TC-077.4.
- **JSON colouring is IN-PLACE** (operator decision, MJ-4): observe `TextArea.get_line(i).plain` + `.spans` on
  `#patch_paste_text`. **Asserting `ta.text` is TAUTOLOGICAL** and discharges nothing (MJ-5).
- **The mandated counterfactual was wrong (MJ-6).** `sensor[unclosed` does **not** discriminate. The real
  discriminators are the bracket-**pairs** + **`[/nope]`** (the only crash-class payload).
- **⚠ SNAPSHOT IS THE #1 CI RISK.** Both patch cells are STRICT GREEN oracles → any repaint is **CI RED, not
  xfail**. `_batch48_patch_drift_marks` (`strict=False`) lands in the same increment as the first visible change;
  regen in **canonical CI only**.

### 0.1 BL-2 — old→new id map (bodies carried; ids + traceability re-numbered)

**Requirement ids:**

| this doc (RETIRED) | canonical `01-requirements.md` |
|---|---|
| `R-TUI-075` (US-P1: titles + colour roles + chips + scope line) | **split** → `R-TUI-075` (render) **+** `R-TUI-076` (chip CSS) — the `D-2` split |
| `R-TUI-076` (glyph column) | `R-TUI-077` |
| `R-TUI-077` (pass/fail strip) | `R-TUI-078` |
| `R-TUI-078` (JSON colouring + gauge) | `R-TUI-079` |
| `R-TUI-079` (before/after card) | `R-TUI-080` |
| `R-TUI-080` (history strip) | `R-TUI-081` |
| `R-TUI-081` (standalone C-17 contract) | **DISSOLVED** — C-17 is per-sink: `LLR-075.4` (variant line) · **`LLR-075.6` NEW** (entries table, BL-1 fold) · `LLR-079.3` (pasted JSON) · N/A-with-reason at `LLR-077.6` / `078.5` / `080.7` |

**Acceptance-test ids:**

| this doc (RETIRED) | canonical | note |
|---|---|---|
| `AT-075a` titles/subtitles | `AT-075a` | unchanged |
| `AT-075b` chips grouped | `AT-076a` | moved to the chips HLR (D-2) |
| — | `AT-076b` ★ | **C-30 leak probe — canonical-only; this doc never had it.** Adopted. |
| — | `AT-076c` | **48-id preserve — canonical-only.** Adopted (was TC-CEN.1 here; now dual-listed). |
| `AT-075c` scope line | `AT-075c` | unchanged |
| — | `AT-075b` | **role-styled `Text` cells — canonical-only** (this doc had it only as TC-075.2). Adopted. |
| — | `AT-075d` ★ | **C-17 variant id — canonical-only.** Adopted. |
| `AT-076a` ✓/✗ branches | `AT-077a` | canonical **merges** ✓/◐/✗ into one node (see §3 note) |
| `AT-076b` ◐ uncheckable | `AT-077a` | merged into `AT-077a` |
| `AT-076c` `·` no-run | `AT-077b` | |
| `AT-076d` index alignment | `AT-077d` | body unchanged (the full ORDERED list) |
| — | `AT-077c` ★ | **document-provenance staleness — canonical-only.** Adopted, gate-blocking. |
| `AT-077a` strip counts | `AT-078a` | |
| `AT-077b` zero total | `AT-078b` | |
| — | `AT-078c` | **post-undo cleared strip — canonical-only.** Adopted. |
| `AT-078a` JSON colouring | `AT-079b` | **body REWRITTEN** (MJ-4/MJ-5: in-place, not a preview) |
| `AT-078b` cap gauge | `AT-079a` | |
| `AT-081a` ★ C-17 pasted JSON | `AT-079c` ★★ | **body REWRITTEN** (MJ-5 observation point; MJ-6 payload set) |
| `AT-081b` ★ C-17 new sinks | **DISSOLVED** | card/glyph/strip are N/A-with-reason (`LLR-077.6`/`078.5`/`080.7`); its live-sink half is **superseded by the NEW `AT-075e`**, and its re-open condition becomes a mechanical gate (TC-080.7, MJ-7) |
| `AT-079a` card, non-first row | `AT-080a` | |
| `AT-079b` read-only proof | `AT-080b` ★ | |
| `AT-079c` unmapped → `—` | `AT-080c` | |
| `AT-080a` history position | `AT-081a` | |
| `AT-080b` history empty | `AT-081b` | canonical widens to bounds (empty **+** `_HISTORY_MAX` saturation) |
| `AT-082` C-29 reachability | `AT-080d` ★ | **body REWRITTEN** (MJ-2: both pre- and post-amendment forms) |
| — | **`AT-075e` ★★** | **NEW (BL-1)** — entries-table C-17, gate-blocking |
| — | **`AT-077e` ★** | **NEW (BL-4)** — image-generation provenance, gate-blocking. **SPLIT from `AT-077c`, not merged into it** (registry ruling 2026-07-16): distinct trigger, distinct mechanism, and **the branch missed at Phase 1** ⇒ C-10 per-branch + C-18 one-node-per-AT |
| — | **`AT-079d`** | **NEW (MJ-4)** — the feature-detect fallback path. **Canonical-only until the 2026-07-16 reconciliation; ADOPTED here** (§3, US-P4) with an executed verification + threshold. CI is pinned at 8.2.8 and can **never** exercise degradation naturally ⇒ it must be an AT, not only `TC-079.1a` |
| — | ~~`AT-080e`~~ | **NOT AN AT — conditional-on-grep (MJ-7).** Created, gate-blocking, only in the increment where TC-080.7's mechanical grep fires. **Not counted in the 26** (an AT over a header that does not exist yet passes vacuously — the MJ-2 class) |

**Node paths:** this doc routed everything to `tests/test_tui_patch_big.py`; **canonical §5.2 spreads across 7
files** and is ADOPTED (§2, test-home table). Every home is verified **non-frozen** (5 are NEW files → non-frozen
by construction; `test_tui_patch_layout.py` and `test_tui_snapshot.py` are existing non-frozen).

**TC ids:** this doc's ad-hoc `TC-075.1…TC-080.3` are RETIRED. Canonical §5.2's functional chain is adopted:
**`TC-0XX.Y` ≡ `LLR-0XX.Y`, 1:1**, 36 LLR-level nodes. Fold-added sub-cases carry a letter suffix and trace to
their parent LLR (`TC-079.1a/b/c`, `TC-080.2a`). Cross-cutting TCs keep their names (`TC-FRZ.1/.2`, `TC-CEN.1`,
`TC-REG.1`, `TC-C29.1`).

### 0.2 Phase-2 fold ledger (what changed in this document, and why)

| Fold | Severity | Applied here |
|---|---|---|
| **BL-2** | BLOCKER | §0.1 full re-number onto canonical §5.2; AT count reconciled 19→**26** (23 draft + 3 fold-added); node paths adopted from canonical (7 files, all non-frozen). |
| **BL-3** | BLOCKER | §9.1 — **T-1 DISSOLVED and recorded**; glyph folds into cell 0 as its own span; `_ENTRIES_COLUMNS` stays a 5-tuple; TC-077.4 gains the **zero-diff-on-the-census-file** threshold; glyph ATs confirmed to survive unchanged (§3, US-P2 note). |
| **BL-1** | HIGH (security) | **NEW `AT-075e` ★★** (§3) over the entries table — the live `Text.from_markup` sink; **NEW `TC-075.6`** for the promoted C-17 LLR; §2.4/§5 threat-model text corrected. |
| **BL-4** | BLOCKER | **NEW `AT-077e` ★** (§3) — checks vs image A → load image B → glyphs go all-`·`, not stale `✓`; TC-077.2 widened to the `(document_signature, image_generation)` pair. |
| **MJ-1** | MAJOR | §8 census gains the **4th `refresh_entries` site** (`screens_directionb.py:2976`, the `on_mount` self-call) + **NEW `TC-080.2a`** for `mem_map` retain semantics. |
| **MJ-2** | MAJOR | `AT-080d` body rewritten — **both forms stated now**, so the pre-committed relaxation cannot void it. |
| **MJ-4/MJ-5** | MAJOR | `AT-079b` / `AT-079c` rewritten against the **in-place** `TextArea`; the `ta.text` tautology named; **NEW `TC-079.1a`** (fallback path forced) **+ `AT-079d` ADOPTED** (§3 — the black-box peer of TC-079.1a; canonical-only until the registry pin). |
| **POST-FOLD RECONCILIATION** (2026-07-16, **registry PINNED at 26**) | BLOCKER-class (process) | The parallel folds **re-created BL-2** — each agent minted ids independently (architect: 4-arm `AT-077c` + `AT-079d`; this doc: `AT-077e`). Ruling applied by **one agent owning both docs**: **`AT-077e` stays SPLIT** from `AT-077c` (§0.1, §3) · **`AT-079d` ADOPTED here** with an executed verification + threshold (§3) · **`AT-080e` stated identically in both as conditional-on-grep**, not a live AT, **not in the 26** (§3, §5) · **`AT-079b`'s `or` STRUCK** — the §12-1 residual, the same self-voiding shape MJ-2 blocked, missed by **both** Phase-2 reviewers (§3 note, §12-1). Totals: 25→**26**, 50→**52** executions. **Process rule: the orchestrator pins the registry BEFORE dispatching folds; agents never mint AT ids in parallel.** |
| **MJ-6** | MAJOR | Payload set corrected (§3, MD-1): **`[/nope]` ADDED**; `sensor[unclosed` demoted from counterfactual to regression fixture; the false claim removed everywhere. |
| **MJ-7** | MAJOR | `TC-080.7`'s re-open condition made **mechanical** (a grep threshold), not inspection-only. |
| **m-2 / m-3** | MINOR | **NEW `TC-079.1b`** (non-ASCII / byte-offset spans) and **`TC-079.1c`** (spans survive an edit). |

**Preserved unchanged from the pre-fold draft:** the C-29 structural-invariant discipline (no hard-coded row/col
thresholds anywhere) · the per-cell snapshot prediction + `strict=False` + canonical-CI-only regen · the
both-pilot-sizes rule on every AT · non-frozen homes only · the C-10 enforcement ledger.

### Verified facts backing the ATs (recon @ `6551aed`; Phase-2 additions marked **[P2]**)

| Fact | Evidence |
|---|---|
| Check result domain = `pass` / `fail` / `uncheckable` | `CHECK_RESULT_DOMAIN`, `changes/model.py:561` |
| Aggregate keys = `("passed","failed","uncheckable")`, **all three always present** | `CHECK_AGGREGATE_KEYS`, `changes/model.py:571` |
| `CheckRunEntry.actual_bytes` is `None` on **every** uncheckable outcome | `changes/model.py:641` docstring |
| `ChangeEntry.encoded_bytes: tuple[int,...]`, non-empty, 0-255 enforced at construction | `changes/model.py:80` + `__post_init__` |
| Entries table cols today = `("Kind","Address","Value / bytes","Status","Linkage")` — **stays 5 after BL-3** | `_ENTRIES_COLUMNS`, `screens_directionb.py:2264` |
| `refresh_entries(rows)` takes **already-shaped `ChangeEntryRow`** | `screens_directionb.py:3217`; `ChangeEntryRow` = `change_service.py:232` |
| `refresh_entries([])` **hides the table** and shows `#patch_doc_empty_state` | `screens_directionb.py:3217` docstring |
| **[P2] The entries table is a LIVE `Text.from_markup` sink** — `value_text = entry.value` (raw file JSON, unmodified) → `add_row()` as a bare `str` → `default_cell_formatter` sets `possible_markup=True` → `Text.from_markup(content)` | `change_service.py:1402-1425` · `screens_directionb.py:3244-3252` · `textual/widgets/_data_table.py:202-222` |
| **[P2] The paste buffer is SAFE BY CONSTRUCTION** — `TextArea.get_line` returns `Text(line_string, end="", no_wrap=True)` (literal ctor, **never** `from_markup`); styles resolve via `theme.syntax_styles.get(name)` and an **unknown token is skipped** → payload text cannot name a style | `textual/widgets/_text_area.py:1328` · `:1501-1503` |
| **[P2] `_highlights` offsets are BYTE offsets (UTF-8)** — tree-sitter convention; a missed lookup silently defaults to 0 | `textual/widgets/_text_area.py:1496-1508` (`_utf8_encode`) |
| **[P2] `_build_highlight_map()` CLEARS `_highlights` on rebuild** | `textual/widgets/_text_area.py:826-830` |
| **[P2] `[/nope]` raises `MarkupError` under `from_markup`; `sensor[unclosed` does NOT** (`plain='sensor[unclosed'`, `spans=[]` — identical to the safe path) | measured against installed `textual==8.2.8` (02-review MJ-6) |
| **[P2] `ChangeService()` is constructed ONCE at app init** and never rebuilt on file load; `last_check_result` resets only at `undo`/`redo` | `app.py:1171` · `change_service.py:474` / `:506` |
| **[P2] `run_checks` reads `actual_bytes` from `mem_map`**, not from the document | `change_service.py:1258-1259` |
| **[P2] A 4th `refresh_entries` call site exists** — an `on_mount` self-call | `screens_directionb.py:2976` (inside `on_mount` `:2962`) |
| `refresh_check_results(rows, status_line)` renders one `Static` per row + an aggregate status line | `screens_directionb.py:3434` |
| `_batch46_patch_drift_marks` = **retired no-op** (`return ()` at the top; body dead) | `tests/test_tui_snapshot.py:507-520` |
| Patch snapshot cells = exactly **2** | `_TWO_SIZE_SCAFFOLDS`, `tests/test_tui_snapshot.py:815` |
| **The snapshot scaffold loads NO change document** — only a synthetic `LoadedFile` triple | `_snapshot_run_before`, `tests/test_tui_snapshot.py:341-358` |
| Reachability primitives `_fully_visible` / `_scrollers` / `_reach` exist and are reusable | `tests/test_tui_patch_layout.py:144-200` |
| `_MUST_PRESERVE_IDS` = **48 ids** | `tests/test_tui_patch_layout.py:67-137` |
| Batch-46 measured panel viewport ≈ **5 rows @80×24**, 11 rows @120×30 | `tests/test_tui_patch_layout.py` module docstring (FOLD-8) |
| **[P2] Existing positional cell readers pin cols 1 and 2 only** — col 0 is **unasserted** | `tests/test_tui_patch_editor_v2.py:2578` (docstring pins order) · `:3208-3209` (`Coordinate(row,1)`=address, `(row,2)`=value) |
| **[P2] Batch-47 fold precedent — glyph into cell 0 as its own span, column count unchanged** | A2L `app.py:9548` ("the name cell (**index 0**) carries the leading in-image glyph") · MAC `app.py:9223-9226` ("**Fold** a leading status glyph … into the Tag cell **as its own span**") |

---

## 1. Requirement map (CANONICAL — mirrors `01-requirements.md` §5.2)

| Req id | HLR | Story | Deliverable (black-box observable) |
|---|---|---|---|
| `R-TUI-075` | HLR-075 | US-P1 | Window border titles + subtitles (entry count · run state · schema); entries-table role-coloured `Text` cells (kind purple / address cyan / bytes bright); variant+scope **line**. |
| `R-TUI-076` | HLR-076 | US-P1 | Chip-button CSS family, **patch-scoped**, three colour groups on the docked rows (the batch-47 carry). |
| `R-TUI-077` | HLR-077 | US-P2 | Check glyph — `✓` pass / `✗` fail / `◐` uncheckable / `·` no-current-result — **folded into the `Kind` cell as its own leading span** (BL-3), index-aligned by document order, provenance-guarded. |
| `R-TUI-078` | HLR-078 | US-P3 | CHECKS pass/fail strip: counts + unfloored microbar, values == `CheckRunResult.aggregates`. |
| `R-TUI-079` | HLR-079 | US-P4 | JSON window **in-place** syntax-ish colouring + paste-cap gauge (`N KB / 64KB`, cap = `_CLIPBOARD_READ_CAP_CHARS = 65536` **chars**). |
| `R-TUI-080` | HLR-080 | US-P5 | **LIVE before/after card** on entry-row select. Read-only. `mem_map` threaded as a method parameter (C-7). |
| `R-TUI-081` | HLR-081 | US-P6 | History strip: derived undo/redo depths + key hints. |

> The pre-fold `R-TUI-081` "standalone C-17 contract" is **retired**: C-17 binds per-sink at `LLR-075.4`,
> **`LLR-075.6` (NEW — BL-1 fold (a), architect-owned)**, and `LLR-079.3`; and is audited N/A-with-reason at
> `LLR-077.6` / `LLR-078.5` / `LLR-080.7`.

---

## 2. Validation method per requirement — Layer A white-box (`TC-NNN`)

Method ∈ {test(unit) · test(pilot) · inspection · analysis}. **`TC-0XX.Y` ≡ `LLR-0XX.Y`, 1:1.** Every
`test`/`analysis` row carries an **Executed verification** (provisional pytest node per V-5, reconciled at Phase 4)
+ a **numeric pass threshold**.

**Test-home routing — NEVER the 9 frozen test files** (`test_core_srecord_validation`, `test_hexfile`,
`test_range_index`, `test_validation_a2l`, `test_validation_engine`, `test_validation_mac`, `test_tui_a2l`,
`test_tui_mac`, `test_color_policy_round_trip`). **Canonical §5.2 routing ADOPTED.** Homes — all **non-frozen**:

| Home | Status | Use | Non-frozen because |
|---|---|---|---|
| `tests/test_tui_patch_big.py` | **NEW** | `AT-075a/b/c/d/e` + TC-075.* | new file |
| `tests/test_tui_patch_chips.py` | **NEW** | `AT-076a/b` + TC-076.1/.2/.4 | new file |
| `tests/test_tui_patch_glyphs.py` | **NEW** | `AT-077a/b/c/d/e` + TC-077.* | new file |
| `tests/test_tui_patch_checks_strip.py` | **NEW** | `AT-078a/b/c` + TC-078.* | new file |
| `tests/test_tui_patch_json.py` | **NEW** | `AT-079a/b/c/d` + TC-079.* | new file |
| `tests/test_tui_patch_card.py` | **NEW** | `AT-080a/b/c/d` + TC-080.* | new file |
| `tests/test_tui_patch_history_strip.py` | **NEW** | `AT-081a/b` + TC-081.* | new file |
| `tests/test_tui_patch_layout.py` | existing, **non-frozen** | `AT-076c` (existing node, re-run) · TC-076.3 · TC-CEN.1 · TC-C29.1 | not in the frozen 9 |
| `tests/test_tui_patch_editor_v2.py` | existing, **non-frozen** | **read-only re-run** (the 32-hit census). **Expected diff vs `main` = 0 lines** (BL-3) | not in the frozen 9 |
| `tests/test_tui_insight_style.py` | existing, **non-frozen** | microbar/label pure-helper TCs (TC-078.4) | not in the frozen 9 |
| `tests/test_tui_snapshot.py` | existing, **non-frozen** | `_batch48_patch_drift_marks` (§7) | not in the frozen 9 |

> **Routing note (open item for Phase 3 — see §12):** canonical routes `AT-080d` to `test_tui_patch_card.py`, but
> its primitives (`_fully_visible` / `_scrollers` / `_reach`, and `_MUST_PRESERVE_IDS`) are **module-private to
> `tests/test_tui_patch_layout.py:144-200`/`:67`**. Cross-test-module import is fragile. Two acceptable
> resolutions, decided in the increment that writes the node: **(i)** lift the primitives into `tests/conftest.py`
> first (the batch-41 `_canonical_report_bytes` consolidation precedent) and import from there, **or (ii)** keep
> `AT-080d`'s node in `test_tui_patch_layout.py`. Either satisfies C-18 (one on-disk node); **do not duplicate the
> primitives** into a second file.

### HLR-075 — R-TUI-075 (titles / role colours / variant+scope line / **entries-table C-17**)

| TC | LLR | Requirement facet | Method | Executed verification (provisional) | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-075.1 | LLR-075.1 | Each window's border title + subtitle renders; SCRIPT subtitle carries the live entry count, CHECKS the run state, JSON the schema token | test(pilot) + snapshot | `pytest tests/test_tui_patch_big.py::test_tc075_1_window_subtitles -q` | all 3 of `#patch_win_script/_checks/_json` have non-empty `border_title`; SCRIPT subtitle contains the literal count (`0` empty-doc → `3` after 3 adds — the **live** update, not a static string) |
| TC-075.2 | LLR-075.2 | Every cell added by `refresh_entries` is a Rich `Text` with its role style (kind `PURPLE` / address `CYAN` / value `VALUE`); **A5 no-row-override re-check** | test(unit) + test(pilot) | `pytest tests/test_tui_patch_big.py::test_tc075_2_role_colours -q` | for one row: **5/5** cells `isinstance(cell, rich.text.Text)` (**0** bare `str`); ≥3 **distinct** style tokens across cells 0/1/2; `add_row` call passes **0** `.style` row-override (inspection arm — A5) |
| TC-075.3 | LLR-075.3 | Scope line renders the active scope token from the panel's local vocabulary and **tracks the cycle** | test(pilot) | `pytest tests/test_tui_patch_big.py::test_tc075_3_scope_line -q` | line contains `active variant` at default; after 1 press of `#patch_execute_scope_button` contains `all variants` (== `_SCOPE_LABELS`, `screens_directionb.py:2552-2556`); **0** service imports in the line's build path |
| TC-075.4 | LLR-075.4 | C-17 on the variant/scope line: the project-derived variant id is `safe_text`/`Text`, never f-strung into markup | test(pilot, hostile) | `pytest tests/test_tui_patch_big.py::test_tc075_4_c17_variant -q` | for each MD-1 payload as a variant id: rendered `Text.plain` contains the payload **verbatim** (char-for-char); **0** spans whose style is payload-derived; **0** `MarkupError`; **0** `from_markup` in the line's build path (grep) |
| **TC-075.6** ★★ | **LLR-075.6 (NEW — BL-1)** | **The entries table is a live `Text.from_markup` sink.** *All five* cells — including `status_text` and `linkage_text`, which LLR-075.2's 3-role enumeration does not cover — are `Text`-constructed regardless of role assignment | test(unit) + inspection | `pytest tests/test_tui_patch_big.py::test_tc075_6_all_cells_text -q` | **5/5** cells `isinstance(..., rich.text.Text)` — **`status_text` and `linkage_text` included** (the partial-fix trap: converting only the 3 enumerated roles leaves 2 bare and the sink live); **0** bare-`str` arguments reach `add_row` (grep of `screens_directionb.py:3244-3252`); **0** `possible_markup=True` paths reachable from `entry.value` |

> **TC-075.5 (LLR-075.5 — C-29 width geometry)** is folded into **TC-C29.1** (cross-cutting) because BL-3 removed
> the 6th column: the width question is now "does a **5**-column table plus a **1-2 char glyph prefix inside cell
> 0** fit at 80×24", which is measured in the same both-axes pilot pass as everything else. No separate node; the
> measurement row records the `#patch_win_script_body` width and the rendered `Kind`-cell width per regime.

### HLR-076 — R-TUI-076 (chip CSS)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-076.1 | LLR-076.1 | Chip family exists and **every rule is `#patch_editor_panel`-rooted** (the C-30 containment) | inspection + test(pilot) | `pytest tests/test_tui_patch_chips.py::test_tc076_1_chip_css_scoped -q` | chip rule count ≥ 1 in `styles.tcss`; **every** new selector is prefixed by a `#patch_editor_panel` ancestor (or a class only reachable under it); **0** bare `Button` selectors added; **0** unscoped class rules |
| TC-076.2 | LLR-076.2 | Group assignment across the **9** docked containers | test(pilot) + inspection | `pytest tests/test_tui_patch_chips.py::test_tc076_2_chip_groups -q` | **9/9** docked containers carry a chip-group class (**0** `assumed`, **0** unmapped — the MJ-3 fold); ≥3 **distinct** group classes present; every group's members share exactly one group class |
| TC-076.3 | LLR-076.3 | Classes-only restyle: no id added-in-place-of, renamed, moved, or re-parented | test | `pytest tests/test_tui_patch_layout.py -q` | the layout suite passes **unmodified** (diff vs `main` == **0** lines); all **48** `_MUST_PRESERVE_IDS` → cardinality **1** at both sizes |
| TC-076.4 | LLR-076.4 | Chip height does not cost reachability at 80×24 | analysis (pilot measure) | recorded in TC-C29.1's measurement pass | measured docked-row rendered height per regime **recorded**; **no threshold asserted before the measurement lands** (C-29); verdicted jointly by `AT-080d` |

### HLR-077 — R-TUI-077 (check glyph, **folded into the `Kind` cell**)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-077.1 | LLR-077.1 | Glyph derived from `last_check_result.entries[i]` where `i` is the **document-order index**; never address-matched | test(unit) + inspection | `pytest tests/test_tui_patch_glyphs.py::test_tc077_1_index_alignment -q` | 3 entries, only index 1 `fail` → glyph list == `["✓","✗","✓"]` **exactly** (order-sensitive); **0** address comparisons in the derivation path (grep for `.address ==` / address-keyed dict lookups → 0) |
| TC-077.2 ★ | LLR-077.2 | **Provenance stamp = `(document_signature, image_generation)`** (BL-4). Signature over the ordered `(entry_type, address, encoded_bytes)` tuple; generation = a monotonic token bumped in `_apply_loaded_file` | test(unit) | `pytest tests/test_tui_patch_glyphs.py::test_tc077_2_provenance -q` | **4 invalidation cases, all → every glyph `·`**: (a) `add_entry` after a run; (b) `remove_entry`; (c) **in-place per-entry JSON edit with the count unchanged** (count-equality is insufficient); (d) **`image_generation` bump with the document untouched** (BL-4). **1 non-invalidation case**: no mutation → glyphs render. **0** uses of `id(mem_map)` as the token (id reuse after GC — grep == 0). `mac_records` / `a2l_tags` are **not** covered by the stamp (they drive `linkage`, not `result`) → assert the stamp's input set is exactly the 2 axes, so Phase 3 does not over-build |
| TC-077.3 | LLR-077.3 | Glyph vocabulary total over `CHECK_RESULT_DOMAIN` + the no-run case; unknown token → `◐` | test(unit) | `pytest tests/test_tui_patch_glyphs.py::test_tc077_3_glyph_map -q` | `pass→✓`, `fail→✗`, `uncheckable→◐`, no-result→`·`; **3/3** `CHECK_RESULT_DOMAIN` tokens mapped (**0** unmapped); an unknown token → `◐` (mirrors `_CHECK_RESULT_SEVERITY`'s default, `change_service.py:1324-1326`) — **0** crashes, **0** blanks; styles == `GREEN`/`RED`/`YELLOW`/`DGRAY` |
| TC-077.4 | LLR-077.4 | **BL-3 fold:** the glyph rides in the `Kind` cell **as its own leading span**; `_ENTRIES_COLUMNS` is unchanged | test(pilot) + inspection + snapshot | `pytest tests/test_tui_patch_glyphs.py::test_tc077_4_glyph_folded_into_kind -q` | `len(_ENTRIES_COLUMNS) == 5` (**unchanged**); cell 0 is a `Text` whose `.plain` **starts with** the glyph and whose `.spans` contains **≥1 span covering exactly the glyph's offsets** with the glyph's style (the batch-47 A2L/MAC idiom, `app.py:9548` / `:9223-9226`); `#patch_doc_entries_table`'s id, `zebra_stripes`, and `cursor_type="row"` unchanged; the empty-state toggle (`:3253-3258`) still fires; **`git diff main -- tests/test_tui_patch_editor_v2.py` == 0 lines** — *if this is non-zero the fold was implemented wrong (a leading COLUMN, not a leading SPAN); it is a free correctness signal, not a chore* |
| TC-077.5 | LLR-077.5 | The glyph rides on `ChangeEntryRow` → **no `refresh_entries` signature change for the glyph** at any call site | inspection | grep census, recorded in the increment's review packet | **4/4** `refresh_entries` sites unchanged **for the glyph** (`app.py:2049` · `:2255` · `:3884` · **`screens_directionb.py:2976`** — the MJ-1 4th site); **0** direct `ChangeEntryRow(` constructions in `tests/` (the defaulted field breaks no caller) |
| TC-077.6 | LLR-077.6 | C-17 disposition: the glyph carries only closed-vocabulary tokens | inspection | grep of the glyph derivation + its cell-0 span builder | **0** file-derived strings (`linkage_symbol` / `reason`) reach the glyph span; the glyph's value set is the 4-token vocabulary. **N/A for a hostile-input AT — reason:** closed vocabulary. **Re-open condition (mechanical):** if the glyph gains a tooltip, it MUST be a Rich `Text` via `safe_text` (batch-43 C-17: an `str` tooltip **is** markup-parsed by Textual 8.2.8) → grep the glyph path for `tooltip=` with a non-`Text` argument == **0** |

### HLR-078 — R-TUI-078 (pass/fail strip)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-078.1 | LLR-078.1 | Strip mounts inside `#patch_win_checks_body` above `#patch_checks_results`; `#patch_checks_status` retained | test(pilot) | `pytest tests/test_tui_patch_checks_strip.py::test_tc078_1_strip_mounted -q` | the strip node resolves **exactly once**; its DOM position precedes `#patch_checks_results`; `#patch_checks_status` still resolves and still carries the blocked-run message; **0** new member named `_nodes`/`_context` (`set(dir(Widget)) & {new private names}` == **0**) |
| TC-078.2 | LLR-078.2 | Aggregates threaded as a defaulted `Mapping[str,int]` parameter; **C-7 purity holds** | test(unit) + inspection | `pytest tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param -q` | `PatchEditorPanel` span `screens_directionb.py:2192-3468`: `self.app` count == **0**, service-import count == **0** (unchanged from HEAD); the parameter is defaulted → **0** callers break |
| TC-078.3 | LLR-078.3 | **Both** `refresh_check_results` sites push aggregates | test(pilot) | `pytest tests/test_tui_patch_checks_strip.py::test_tc078_3_both_sites -q` | post-run site (`app.py:2041-2043`) → strip counts == the run's aggregates; history site (`app.py:2261`) → strip **cleared** after `ctrl+z` (**0** stale counts — the batch-38 Inc-4 F1 defect) |
| TC-078.4 | LLR-078.4 | Microbar proportional (`floor=False`); zero-total boundary | test(unit) | `pytest tests/test_tui_insight_style.py::test_tc078_4_microbar_unfloored -q` | call site passes `floor=False` (or omits it); `frac=0.0` → **0** filled cells (a floored bar shows 1); total 0 → **0** `ZeroDivisionError`, bar frac == 0.0; all-passed → frac == 1.0 |
| TC-078.5 | LLR-078.5 | C-17 disposition: counts + glyphs + bar only | inspection | grep of the strip builder | **0** file-derived strings reach the strip; `run_blocked_reason` keeps its existing `#patch_checks_status` sink. **N/A for a hostile-input AT — reason:** integers + closed-vocabulary glyphs only |

### HLR-079 — R-TUI-079 (JSON colouring **in-place** + cap gauge)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-079.1 | LLR-079.1 | **Rung 1:** a pure tokenizer emits `(start, end, token_name)` spans into `TextArea._highlights` on `#patch_paste_text`, with a registered `TextAreaTheme` supplying the styles; feature-detected at construction | test(pilot) + analysis | `pytest tests/test_tui_patch_json.py::test_tc079_1_highlights_populated -q` | after pasting a valid change-set: ≥3 **distinct** styles across `ta.get_line(i).spans` summed over the buffer's lines; **the rung selection is RECORDED in `03-increments/` before Phase 4** (rung 1 or rung 2 — never "either") |
| **TC-079.1a** | LLR-079.1 (**MJ-4 fold**) | **The FALLBACK path is itself tested.** CI is pinned at 8.2.8 and can never exercise degradation naturally → force the feature-detect false | test(unit) | `pytest tests/test_tui_patch_json.py::test_tc079_1a_fallback_unstyled_no_raise -q` | with the feature-detect monkeypatched to `False`: **0** exceptions raised on paste + render; `ta.get_line(i).spans` == `[]` for every line (unstyled); `ta.get_line(i).plain` == the pasted line **verbatim** (the buffer text is untouched); the app boots and the JSON window mounts at both sizes |
| **TC-079.1b** | LLR-079.1 (**m-2 fold**) | **`_highlights` offsets are BYTE offsets (UTF-8), not codepoint offsets.** A Python tokenizer naturally emits codepoint offsets → non-ASCII pastes misstyle, and a missed lookup **silently defaults to 0** (styles from line start) | test(unit) | `pytest tests/test_tui_patch_json.py::test_tc079_1b_non_ascii_byte_offsets -q` | for a paste whose value contains a multi-byte character (e.g. `"sensor→α"`): every emitted span's `(start,end)` equals the **UTF-8 byte** offsets of the token (compare against `line.encode("utf-8")` slicing), **not** the codepoint offsets; **0** spans starting at offset 0 that should not (the silent-default tell); the rendered `.plain` is char-identical to the pasted line |
| **TC-079.1c** | LLR-079.1 (**m-3 fold**) | **Spans survive an edit.** `_build_highlight_map()` **clears** `_highlights` on rebuild (`_text_area.py:826-830`) → a once-populated map is erased on the next keystroke | test(pilot) | `pytest tests/test_tui_patch_json.py::test_tc079_1c_spans_survive_edit -q` | paste → assert ≥3 distinct styles; then type **1** character into the buffer → re-assert ≥3 distinct styles (**0** lines with an emptied span set where the token still exists); **0** exceptions |
| TC-079.2 | LLR-079.2 | Malformed / truncated JSON degrades to unstyled or best-effort spans, never raises, never alters the buffer | test(unit) | `pytest tests/test_tui_patch_json.py::test_tc079_2_malformed -q` | for {malformed, truncated mid-string, empty, non-JSON} inputs: **0** exceptions; `ta.text` byte-identical before/after tokenization |
| TC-079.3 ★★ | LLR-079.3 | **C-17 gate-blocking:** pasted content is never markup-parsed | test(pilot, hostile) | `pytest tests/test_tui_patch_json.py::test_tc079_3_c17_no_markup -q` | **0** occurrences of `from_markup` / `markup=True` / f-string-into-markup in the colouring path (grep); every MD-1 payload → `ta.get_line(i).plain` carries it **verbatim**, **0** payload-derived spans, **0** `MarkupError`. **Asserting `ta.text` does NOT discharge this TC** (see MJ-5 note under `AT-079c`) |
| TC-079.4 | LLR-079.4 | Gauge value == the **char** count of the buffer; denominator == the shared cap; at/over-cap boundary | test(pilot) | `pytest tests/test_tui_patch_json.py::test_tc079_4_gauge -q` | `_CLIPBOARD_READ_CAP_CHARS == 65536` asserted (sourced from `os_clipboard_input.py:72`, **not** a local literal — grep for a literal `65536` in the gauge path == **0**); 1024-char paste → the 1024-char-derived value; **at-cap** (65536) → frac == 1.0, **0** truncation marker; **over-cap** (65537) → rendered length == **65536** (`CappedTextArea` contract, `capped_text_area.py:69`); **empty** → `0` |
| TC-079.5 | LLR-079.5 | JSON window geometry (C-29) | analysis (pilot measure) | recorded in TC-C29.1's measurement pass | measured `#patch_win_json_body` (cols × rows) per regime **recorded**; buffer stays ≥ `_MIN_USABLE_W = 15` / `_MIN_USABLE_H = 5`; **no threshold asserted before the measurement lands** |

### HLR-080 — R-TUI-080 (live before/after card — HEADLINE)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-080.1 | LLR-080.1 | The card mounts; **0** `_nodes`/`_context` name collisions | inspection + test(pilot) | `pytest tests/test_tui_patch_card.py::test_tc080_1_mounts -q` | `set(dir(Widget)) & {new private member names}` == **0** (a collision is a silent mount crash / idle boot deadlock with **no traceback**); the app boots and the card node resolves exactly once at both sizes |
| TC-080.2 | LLR-080.2 | `mem_map` threaded as `mem_map: Optional[Mapping[int,int]] = None`; obtained **exclusively** from the parameter | test(unit) + inspection | `pytest tests/test_tui_patch_card.py::test_tc080_2_mem_map_param -q` | `PatchEditorPanel` span `2192-3468`: `self.app` == **0**, service imports == **0**, module-level singleton reads == **0**; the card renders from the parameter alone; the parameter is defaulted → **0** callers break |
| **TC-080.2a** | LLR-080.2 (**MJ-1 fold**) | **Retain semantics.** There are **FOUR** `refresh_entries` sites; the 4th is a self-call inside `on_mount` (`screens_directionb.py:2976`). If the retain is `self._mem_map = mem_map` **unconditional**, that self-call **nulls it** — benign today *only* by ordering, which is an unstated invariant | test(unit) + test(pilot) | `pytest tests/test_tui_patch_card.py::test_tc080_2a_retain_semantics -q` | after a `refresh_entries(rows, mem_map=M)` followed by a **parameterless** `refresh_entries(rows)` (the `on_mount` shape): the retained map is **still `M`** (sentinel-default ⇒ preserve) — **OR**, if the design chooses explicit clobber, this TC asserts the clobber is safe by driving the real `on_mount` → select a row → the card still shows byte VALUES (**0** "no image" states). **One of the two must be chosen and stated in LLR-080.2; "benign by ordering" is not a pass** |
| TC-080.3 | LLR-080.3 | Before-bytes == `mem_map` at `[address, address+len(encoded_bytes))`; after == `encoded_bytes`; unmapped → placeholder | test(unit) + test(pilot) | `pytest tests/test_tui_patch_card.py::test_tc080_3_before_after -q` | seeded `mem_map` + a 4-byte entry → returned tuple == the 4 seeded byte values **exactly**; **partial overlap** (4-byte entry, 2 mapped bytes) → 2 byte values + 2 absent tokens, **0** exceptions; **0** `KeyError`; the absent token is **distinguishable from a real `0x00`** (assert `token != rendering_of(0x00)`) |
| TC-080.4 | LLR-080.4 | No-image (`mem_map is None`) / no-selection → neutral state, no fabricated bytes | test(pilot) | `pytest tests/test_tui_patch_card.py::test_tc080_4_no_image -q` | `mem_map=None` → **0** byte values rendered, **0** `00` shown, **0** exceptions; empty document → **0** rows to select → card neutral, **0** exceptions |
| TC-080.5 ★ | LLR-080.5 | Read-only: **0** writes to `mem_map` / the document / the filesystem | test(pilot) | `pytest tests/test_tui_patch_card.py::test_tc080_5_read_only -q` | after N=3 selections: `mem_map` **deep-equal** to its pre-selection deep copy (and dict identity unchanged); document `entries` unchanged; **0** new files under `.s19tool/`; **0** `apply`/`save_patched` symbols reachable from the card path (grep) |
| TC-080.6 | LLR-080.6 | C-29 geometry **with the card mounted**, both axes, both regimes | analysis (pilot measure) | recorded in TC-C29.1's measurement pass | measured (cols × rows) for `#patch_win_script_body`, each sibling window, and each docked row, **with the card mounted and chips applied**, at 80×24 **and** 120×30 — **recorded**; **no AT threshold set before this lands** (C-29); verdicted by `AT-080d` |
| TC-080.7 | LLR-080.7 (**MJ-7 fold**) | C-17 disposition for the card — **re-open made MECHANICAL, not inspection-only** | inspection (**mechanical grep gate, every increment**) | `pytest tests/test_tui_patch_card.py::test_tc080_7_card_inputs_are_ints -q` | the card builder's input set is **100 % `int`** — assert every argument's annotation ∈ {`int`, `Mapping[int,int]`, `Sequence[int]`, `Optional[...]` thereof} and grep the builder for any **non-int** input == **0**. **Rationale for mechanising it:** LLR-080.7's re-open ("*if Phase 3 adds any file-derived label to the card…*") has no enforcing gate, and **a card header naming its entry is the natural design** — exactly the batch-47 MN-4 shape (a "conditional" C-17 LLR that was actually unconditional). If this TC's count goes non-zero, **`AT-080e` (hostile card header) is created in that same increment** and is gate-blocking |

### HLR-081 — R-TUI-081 (history strip)

| TC | LLR | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|---|
| TC-081.1 | LLR-081.1 | Depths are **derived** from `len(_undo_stack)`/`len(_redo_stack)` — no cursor exists | test(unit) | `pytest tests/test_tui_patch_history_strip.py::test_tc081_1_derived -q` | **0** new cursor/index attributes on `ChangeService`; after 2 mutations + 1 undo → `(1, 1)`; after **21** ops → `len(_undo_stack) == 20` and the reported total == **20** (not 21) — `_HISTORY_MAX = 20`, `change_service.py:92`, eviction `:441-442` |
| TC-081.2 | LLR-081.2 | Strip renders depths + `ctrl+z`/`ctrl+y` hints; C-7 purity holds; no `_nodes`/`_context` | test(pilot) + inspection | `pytest tests/test_tui_patch_history_strip.py::test_tc081_2_strip -q` | strip contains both key hints; purity probe == **0**/**0**; `dir(Widget)` collision == **0** |
| TC-081.3 | LLR-081.3 | All **three** `set_undo_redo_enabled` sites also push the depths; A-01 guard consistency | test(pilot) + inspection | `pytest tests/test_tui_patch_history_strip.py::test_tc081_3_sites -q` | **3/3** sites (`app.py:2059` · `:2263` · `:3891`) push depths; a **file-backed** document → strip shows the disabled/empty state **and** the buttons are disabled (**0** disagreement between strip and buttons) |
| TC-081.4 | LLR-081.4 | C-28 disposition: no App-level `Binding(show=True)` added | inspection | `git diff main -- s19_app/tui/app.py \| grep -c 'Binding('` | **0** App-level `Binding(` diffs vs `main` → the snapshot census stays bounded to the 2 patch cells. **If non-zero, C-28 fires and every shared-chrome cell is swept** (the batch-45 F-1 lesson: 18 unexpected cells) |

### Cross-cutting

| TC | Facet | Method | Executed verification | Threshold |
|---|---|---|---|---|
| TC-FRZ.1 | 0 frozen **src** diffs every increment (C-27 dual guard) | test | `pytest tests/test_engine_unchanged.py::test_tc027 tests/test_tui_directionb.py::test_tc031 -q` | 0 fail; **0** frozen src diff vs `main` |
| TC-FRZ.2 | 0 frozen **test-file** diffs every increment (C-27) | test | `pytest tests/test_tui_directionb.py::test_tc032 -q` | 0 fail; **0** diff on the 9 frozen test files |
| TC-CEN.1 | All **48** `_MUST_PRESERVE_IDS` resolve to exactly one widget each | test(pilot) | `pytest tests/test_tui_patch_layout.py::test_at063c_reparent_safety -q` | each of 48 ids → cardinality **1** at 80×24 **and** 120×30 (also the on-disk node for `AT-076c`) |
| TC-REG.1 | Full suite green — no new failures / hangs | test | `pytest -q -m "not slow"` | pass count ≥ **1416** baseline (@ `6551aed`); **0** new fail; xfail set == 3 + documented additions (§7) |
| TC-C29.1 | **Phase-3 pilot measurement** of the patch panel budget on **BOTH axes**, **with the card mounted and chips applied**, at 80×24 and 120×30 (C-29) | analysis (pilot measure) | `pytest tests/test_tui_patch_layout.py -q` + recorded `region` / `content_region` readings in `03-increments/` | measured (cols × rows) recorded **per size** for: the panel · each of the 3 windows · each docked row · the card · the rendered `Kind` cell. **No AT threshold is set before this lands.** Discharges TC-075.5 / TC-076.4 / TC-079.5 / TC-080.6 |

**TC totals:** 36 LLR-level (1:1 with the 36 LLRs, less TC-075.5 folded into TC-C29.1 ⇒ **35** distinct nodes) +
4 fold-added sub-cases (`TC-079.1a/b/c`, `TC-080.2a`) + 1 new C-17 (`TC-075.6`) + 5 cross-cutting =
**45 executable TC nodes.** Canonical §5.2's HLR-level rows `TC-075`…`TC-081` are **rollups**, discharged by
their child LLR TCs + the story's ATs — they are **not** separate nodes (see §12).

---

## 3. AT registry — Layer B black-box (`AT-NNN`) — CANONICAL IDS

Each AT drives the **shipped Patch screen** via `App.run_test(size=(W,H))` at **both 80×24 and 120×30** (the
batch-47 `_SIZES = ((80, 24), (120, 30))` loop) and asserts the **observed deliverable** in the rendered widget
content — never the service return value. C-18: every AT → **one** on-disk test node.
**★ = security/contract-critical · ★★ = gate-blocking C-17.**

### US-P1 — R-TUI-075 / R-TUI-076

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-075a | **Given** a change document with **3** entries loaded, **When** the Patch screen renders, **Then** `#patch_win_script`'s border title/subtitle contains the literal count `3` and the "no run yet" run-state token; `#patch_win_json`'s subtitle names the schema; **and When** a 4th entry is added **Then** the subtitle reads `4` | `test_tui_patch_big.py::test_at075a_titles` | asserts the CONTENT (the number, the schema string) **and its liveness** (3→4), not "a subtitle exists" | 80×24, 120×30 |
| AT-075b | **Given** a document containing **one `string`-kind and one `bytes`-kind** entry, **When** the table renders, **Then** every cell of both rows is a Rich `Text` (not a bare `str`) and the kind/address/value cells carry **≥3 distinct** style tokens | `test_tui_patch_big.py::test_at075b_role_colours` | structural invariant (≥3 distinct styles), never "K columns fit" — C-29-safe | 80×24, 120×30 |
| AT-075c | **Given** the Patch screen at the default scope, **When** `#patch_execute_scope_button` is pressed **once** (a real `pilot.click`), **Then** the scope line changes from `active variant` to `all variants` | `test_tui_patch_big.py::test_at075c_variant_scope_line` | **C-10(a)** — operator-selectable control driven to a NON-DEFAULT value; assert the observed line CHANGED | 80×24, 120×30 |
| **AT-075d ★★** | **Given** a project whose variant id carries each MD-1 payload, **When** `set_variants` feeds the variant/scope line and it renders, **Then** each payload appears **VERBATIM** in the line's `Text.plain`, **no payload-derived span** exists, and **no `MarkupError`** is raised | `test_tui_patch_big.py::test_at075d_c17_variant` | **GATE-BLOCKING C-17** — the variant id is project-file-derived | 80×24, 120×30 |
| **AT-075e ★★** **NEW (BL-1)** | **Given** a change document loaded from disk whose `ChangeEntry.value` carries each MD-1 payload (planted in the **document**, i.e. through the real file/paste ingress — not injected at the panel API), **When** the entries table renders, **Then** for each payload: **(i)** the stored cell is a **`rich.text.Text`, not a bare `str`**; **(ii)** its `.plain` carries the payload **char-for-char VERBATIM**; **(iii)** **no span in `.spans` is payload-derived** — specifically **0** spans with a `link` style and **0** spans whose range covers the payload's own bracket text; **(iv)** rendering the table raises **no `MarkupError`** and the app does not crash | `test_tui_patch_big.py::test_at075e_c17_entries_table` | **GATE-BLOCKING C-17 — the missing peer of `AT-079c`.** See the sink note below | 80×24, 120×30 |
| AT-076a | **Given** the Patch screen, **When** the docked rows render, **Then** buttons from three different docked groups resolve to **three distinct** chip-group styles, and **every** docked button carries a chip class | `test_tui_patch_chips.py::test_at076a_groups` | structural invariant (**≥3 distinct groups**, every button classed) — never "the 20 buttons render as chips" all-at-once (MJ-3 / §2.4-5) | 80×24, 120×30 |
| **AT-076b ★** | **Given** a **non-patch** screen with a `Button`, **When** it renders with the chip CSS present, **Then** its resolved style is **identical** to its pre-batch style | `test_tui_patch_chips.py::test_at076b_no_app_wide_leak` | **The C-30 leak probe — what makes the "N/A" verdict falsifiable rather than asserted** (C-30 N/A but *falsifiable*) | 80×24, 120×30 |
| AT-076c | **Given** the Patch screen, **When** it renders, **Then** all **48** `_MUST_PRESERVE_IDS` resolve to exactly one widget each | `tests/test_tui_patch_layout.py::test_at063c_reparent_safety` (**existing node, re-run unmodified**) | **Regression AT, not a new-deliverable AT** — an existing node cannot evidence a new deliverable, only the absence of damage. Recorded so the distinction is not lost at the gate | 80×24, 120×30 |

> **AT-075e sink note (why this AT exists and what it discriminates).** At HEAD, `change_service.py:1402-1425`
> sets `value_text = entry.value` — the **raw change-set JSON string, unmodified** — and `refresh_entries`
> (`screens_directionb.py:3244-3252`) passes it to `add_row()` as a **bare `str`**; Textual's
> `default_cell_formatter` (`_data_table.py:202-222`) sets `possible_markup=True` → **`Text.from_markup(content)`**.
> Measured: `[red]PWNED[/red]` → `plain='PWNED'` + `Span(0,5,'red')` (content mangled, style injected);
> `[link=http://evil]click[/link]` → `Span(0,5,'link http://evil')` (**link injected from file data** — the
> batch-43 class); **`[/nope]` → raises `MarkupError`** (crashes `refresh_entries`). This is **pre-existing**, but
> **this batch rewrites exactly these lines** (LLR-075.2 / LLR-075.6), so it is in scope and gate-blocking.
> **Tautology guard:** asserting `table.get_cell_at(Coordinate(row, 2)) == payload` is **TAUTOLOGICAL** — it
> round-trips the stored string and **passes on the live sink at HEAD**. Clause **(i)** (`isinstance(cell, Text)`)
> is the load-bearing one: `default_cell_formatter` calls `from_markup` **only** on `str`, so a `Text` cell is
> safe by construction and a `str` cell is not. Clause **(iv)** is what `[/nope]` discriminates.

### US-P2 — R-TUI-077 (glyph **folded into the `Kind` cell**)

> **BL-3 confirmation — these ATs survive the fold unchanged.** Every AT below asserts the glyph's **content** and
> its **ordered position**; **none asserts a column count or a column index**. The observation point moves from
> "column 0's cell" to "the leading span of the `Kind` cell's `Text`" — the batch-47 A2L (`app.py:9548`) / MAC
> (`app.py:9223-9226`) idiom, column count unchanged. The Given/When/Then bodies are carried over verbatim.

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-077a | **Given** a loaded image + a document with **three** entries — entry 0 matching the image, entry 1 not matching, entry 2 addressed **OUTSIDE** the image (`CHECK_REASON_OUTSIDE`) — **When** `run_checks` is driven **through the button**, **Then** the `Kind` cells' leading glyphs read **`✓` on row 0, `✗` on row 1, `◐` on row 2** | `test_tui_patch_glyphs.py::test_at077a_branches` | **C-10(b)** — canonical **merges** the three post-run branches into one node. The node still asserts **each branch by its exact glyph CONTENT**, in one fixture, so the obligation is discharged; the cost is coarser failure isolation (recorded in §12) | 80×24, 120×30 |
| AT-077b | **Given** a document loaded and **no check run performed**, **When** the table renders, **Then** every row's leading glyph is **`·`** | `test_tui_patch_glyphs.py::test_at077b_no_run` | **C-10(b)** fourth branch — the no-run default asserted **by content**, not by absence | 80×24, 120×30 |
| **AT-077c ★** | **PROVENANCE (document): Given** a completed check run whose glyphs read `✓`/`✗`, **When** the document is mutated — **(a)** `add_entry`, **(b)** `remove_entry`, **(c)** an **in-place per-entry JSON edit that leaves the count unchanged** (`#patch_entry_edit_json_button`) — **Then** in every case **every** row's glyph reverts to **`·`**, and **no row retains a stale `✓`/`✗`** | `test_tui_patch_glyphs.py::test_at077c_stale_provenance` | **GATE-BLOCKING** — the wrong-answer class. Case (c) is the counterfactual for a count-equality guard, which would pass (a)/(b) and silently mislabel (c) | 80×24, 120×30 |
| AT-077d | **INDEX ALIGNMENT: Given** a document with **exactly 3 entries where only the MIDDLE (index 1) fails**, **When** checks run and the table renders, **Then** the leading glyphs read top-to-bottom **exactly `["✓", "✗", "✓"]`** | `test_tui_patch_glyphs.py::test_at077d_index_alignment` | **The off-by-one killer.** "Some row shows `✗`" passes under a ±1 shift; the FULL ORDERED list fails `["✗","✓","✓"]` and `["✓","✓","✗"]`. Positional contract per `changes/model.py:660-661` | 80×24, 120×30 |
| **AT-077e ★** **NEW (BL-4)** | **PROVENANCE (image): Given** image **A** loaded and a check run whose glyphs read **all `✓`**, **When** image **B** (whose bytes differ at the entries' addresses) is loaded through the **real load surface** — the document **untouched** throughout — **Then** every row's glyph reads **`·`**, **NOT** a stale `✓` | `test_tui_patch_glyphs.py::test_at077e_image_generation_invalidates` | **GATE-BLOCKING.** Without this AT the batch ships glyphs **describing a previous image**. See the BL-4 note below | 80×24, 120×30 |

> **AT-077e note (why a document signature alone is insufficient).** `run_checks` reads `actual_bytes` **from
> `mem_map`** (`change_service.py:1258-1259`), and `ChangeService()` is constructed **once at app init**
> (`app.py:1171`) — never rebuilt on file load; resets remain only `undo:474` / `redo:506`. **⇒ run checks against
> image A (all `✓`) → load image B → the document is unchanged → a document-only signature **matches** → the
> glyphs still render, describing image A.** That is the exact wrong-answer class LLR-077.2 exists to prevent,
> reachable via **the most routine action in the app**. The stamp is therefore
> **`(document_signature, image_generation)`**, where `image_generation` is an `app.py`-owned **monotonic token**
> bumped in `_apply_loaded_file` and pushed alongside `mem_map` (those sites change anyway for LLR-080.2) — O(1),
> no hashing a large map. **`id(mem_map)` is unsafe** (id reuse after GC) → TC-077.2 asserts its absence.
> `mac_records` / `a2l_tags` need **no** covering (they drive `linkage`, not `result`) — stated so Phase 3 does
> not over-build.

### US-P3 — R-TUI-078

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-078a | **Given** a check run yielding 2 pass / 1 fail / 1 uncheckable, **When** the CHECKS strip renders, **Then** its three counts read **2 / 1 / 1** and equal `CheckRunResult.aggregates` **exactly**, and the bar is proportionally filled | `test_tui_patch_checks_strip.py::test_at078a_counts` | asserts the CONTENT == the `aggregates` dict, not "a strip exists" | 80×24, 120×30 |
| AT-078b | **Given** a check run with **0 total** entries, **When** the strip renders, **Then** it shows `0 · 0 · 0` with a **0-filled** bar and no crash | `test_tui_patch_checks_strip.py::test_at078b_zero_total` | empty-class boundary through the shipped surface; a **floored** bar would show 1 filled cell and fail | 80×24, 120×30 |
| AT-078c | **Given** a completed run whose strip shows non-zero counts, **When** `ctrl+z` is pressed (the real undo binding, which resets `last_check_result` `change_service.py:474`), **Then** the strip is **cleared** — **no stale counts** | `test_tui_patch_checks_strip.py::test_at078c_cleared` | **C-10(a)** — asserts the observed value CHANGED off its post-run state; the counterfactual is the batch-38 Inc-4 F1 stale-panel defect | 80×24, 120×30 |

### US-P4 — R-TUI-079 (JSON colouring **IN-PLACE** + gauge)

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-079a | **Given** a paste of a **known char count** (1024 chars), **When** the gauge renders, **Then** it reads the 1024-char-derived `N KB / 64KB`, the denominator sourced from `_CLIPBOARD_READ_CAP_CHARS = 65536` **chars**; **and Given** a paste **at** exactly 65536 chars **Then** the gauge is full with no truncation marker; **and Given** 65537 chars **Then** the buffer is truncated at 65536 | `test_tui_patch_json.py::test_at079a_gauge` | asserts the CONTENT against the real char count; the **char-vs-byte** confusion is the defect this catches | 80×24, 120×30 |
| AT-079b | **Given** a valid `s19app-changeset` pasted into `CappedTextArea#patch_paste_text`, **When** it renders, **Then** **≥3 distinct** token styles appear across `ta.get_line(i).spans` summed over the buffer's lines, and every `ta.get_line(i).plain` equals the pasted line **verbatim** — **a SINGLE pass condition; there is no `or`** | `test_tui_patch_json.py::test_at079b_colouring` | **REWRITTEN (MJ-4/MJ-5): IN-PLACE, not a preview widget.** Observe `get_line(i).plain` + `.spans` on `#patch_paste_text`. Structural invariant (≥3 distinct styles), never a column count. **The disjunction is STRUCK (registry reconciliation — the §12-1 residual): the rung is RECORDED (TC-079.1), and a probe failure routes to §6.5 Amendment B, which RE-WRITES this AT. See the note below** | 80×24, 120×30 |
| **AT-079c ★★** | **Given** a **hostile** change-set pasted into `CappedTextArea#patch_paste_text` whose string values carry the full MD-1 payload set, **When** the buffer renders, **Then** for every payload: it appears **VERBATIM** in `ta.get_line(i).plain`; **no style/link span originates from the payload** (`.spans` carries **0** payload-derived spans); **no `MarkupError`** is raised; and the app does not crash | `test_tui_patch_json.py::test_at079c_c17_hostile_paste` | **GATE-BLOCKING C-17.** **REWRITTEN (MJ-5)**: the observation point is the **render path**. **Asserting `ta.text` is TAUTOLOGICAL** — it returns the document string and **passes even if rendering is unsafe**; it does **NOT** discharge LLR-079.3. See the safety note below | 80×24, 120×30 |
| **AT-079d** **ADDED HERE (registry pin — it was canonical-only)** | **THE FALLBACK PATH ITSELF: Given** the JSON window with LLR-079.1's feature-detect **forced false** (monkeypatched at construction — the degradation CI **cannot** reach naturally at the `textual==8.2.8` pin), **When** a valid change-set is pasted into `CappedTextArea#patch_paste_text` and the screen renders, **Then** the buffer renders **UNSTYLED and RAISES NOTHING**: `ta.get_line(i).spans == []` for **every** line, every `ta.get_line(i).plain` equals the pasted line **VERBATIM**, **0** exceptions on paste + render, the JSON window still mounts and the app still boots at both sizes, **and `AT-079a`'s gauge still reads its value** (degradation is **cosmetic-only** — the recorded basis of the operator's MJ-4 in-place decision) | `test_tui_patch_json.py::test_at079d_feature_detect_fallback` | **Why an AT and not only a TC:** CI is **pinned at 8.2.8** (`pyproject.toml:38`), where the internals are present — **the fallback path is unreachable by any natural CI run**, so without a forced probe it ships **never having executed**, and "cosmetic-only failure mode" stays an assumption. **C-10** — the `False` branch of a policy the shipped code selects at runtime. Distinct from **TC-079.1a** (white-box unit, same forcing): this AT drives the **shipped screen** at both regimes and asserts the window still mounts and the gauge survives; the TC asserts the mechanism. **Both nodes exist — C-18 is per-AT, not per-behaviour** | 80×24, 120×30 |

> **AT-079b note — the `or` is STRUCK (registry reconciliation 2026-07-16; the §12-1 residual, now RESOLVED in both
> docs).** The pre-reconciliation pass condition read *"structure differentiated **or**, on the rung-2 fallback, the
> recorded amendment + a gauge-only assertion"* — the **same self-voiding shape MJ-2 caught on `AT-080d`**: an AT
> whose pass condition includes "…**or** the feature wasn't built" **can never fail**, because the second disjunct
> is satisfied by not delivering. It survived **both** Phase-2 reviews and was caught on qa's own re-read.
> **Canonical `01-requirements.md` §3 HLR-079 + §5.2 now state the single condition, and this row mirrors it:**
> - **Pass condition (one, not a menu):** ≥3 **distinct** token styles across `ta.get_line(i).spans` summed over the
>   buffer's lines · every `.plain` verbatim · byte offsets correct under non-ASCII (TC-079.1b) · spans survive an
>   edit (TC-079.1c) · **0** raises. The operator chose **in-place `_highlights`** (MJ-4), so this is *the* shipped
>   mechanism — **there is no second rung to fall to inside this AT**.
> - **The rung is a RECORDED DECISION (TC-079.1)** — written into `03-increments/` **before Phase 4**: "rung 1" or
>   "rung 2", **never "either"**. An unrecorded rung is a Phase-4 gate stop.
> - **A probe failure routes to §6.5 Amendment B — an amendment, not a disjunct.** The requirement is re-derived on
>   the record and **this AT is RE-WRITTEN** to: `ta.get_line(i).spans == []` for **every** line (**provably**
>   unstyled — asserted, not accidentally-unasserted) **AND** `.plain` verbatim **AND** 0 raises **AND** `AT-079a` +
>   `AT-079c` still pass unchanged. **Exactly one form runs.** The difference from the struck `or` is the entire
>   point: an amendment costs an operator-visible Before/After; a disjunct costs nothing.

> **AT-079c safety note (the threat model, corrected — BL-1).** The paste buffer is **SAFE BY CONSTRUCTION**
> (verified in installed `textual==8.2.8`): `TextArea.get_line` (`_text_area.py:1328`) returns
> `Text(line_string, end="", no_wrap=True)` — the **literal constructor, never `from_markup`** — and styles
> resolve via `theme.syntax_styles.get(name)` (`:1501-1503`), where an **unknown token is skipped** → payload text
> **cannot name a style**. `AT-079c` is therefore a **regression lock on a safe surface**, not the batch's primary
> defence. **The primary live sink is the entries table → `AT-075e`.** The pre-fold claim that "the pasted JSON is
> the batch's real security surface" had the threat model **backwards** and is retracted here and in §5.

**C-17 payload set (MD-1) — CORRECTED per MJ-6:**

| Payload | Under `Text.from_markup` | Discriminates? | Role |
|---|---|---|---|
| `[red]PWNED[/red]` | `plain='PWNED'` + `Span(0,5,'red')` — content mangled, style injected | ✅ **YES** | primary discriminator (bracket **pair**) |
| `[link=http://evil]click[/link]` | `Span(0,5,'link http://evil')` — **link injected from file data** | ✅ **YES** | primary discriminator (bracket **pair**, batch-43 class) |
| **`[/nope]`** **← ADDED** | **raises `MarkupError`** | ✅ **YES** | **the ONLY crash-class payload** — the unmatched closing tag |
| `\x1b[31mX\x1b[0m` (ANSI) | passes through | ❌ **no** | different threat class; kept as a regression fixture |
| `sensor[unclosed` | `plain='sensor[unclosed'`, `spans=[]` — **identical to the safe path** | ❌ **no** | **kept as a regression fixture only** |

> **MJ-6 correction — the false claim is retracted.** Both Phase-1 docs credited `sensor[unclosed` as *"the
> `from_markup` counterfactual … it raises `MarkupError` under `from_markup`"*. **Empirically false** (measured
> against installed `textual==8.2.8`): it yields `plain='sensor[unclosed'`, `spans=[]` — **indistinguishable from
> a correct implementation**. The designated discriminator was the **weakest** payload in the set. The real
> discriminators are the bracket **pairs** (`[red]…[/red]`, `[link=…]…[/link]`) plus **`[/nope]`**, which is the
> only payload that reaches the crash class. `sensor[unclosed` and the ANSI payload stay in the set as regression
> fixtures — **they are no longer credited as counterfactuals anywhere in this document**. All five payloads MUST
> render verbatim with **0** `MarkupError`. **BACKLOG CARRY:** the same false claim is live at its batch-47 origin,
> `tests/test_tui_a2l_detail.py:24-26,49` — fix it there in a separate change (do **not** edit it from this batch;
> it is out of scope and would widen the census).

### US-P5 — R-TUI-080 (HEADLINE)

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| **AT-080a** | **Given** a loaded image whose `mem_map` is seeded with known bytes AND a document with **≥3 entries**, **When** a **NON-FIRST** entry row (index ≥ 1) is selected via the real `DataTable` cursor, **Then** the card's **before**-bytes equal **`[mem_map[a] for a in range(addr, addr+len(encoded_bytes))]` for THAT entry's address** and the **after**-bytes equal **that entry's `encoded_bytes`** — asserted as the actual byte VALUES | `test_tui_patch_card.py::test_at080a_before_after` | **C-10(a) + the headline.** Non-default row (never index 0 — a card hard-wired to row 0 passes a first-row test). Asserts CONTENT (byte values), never "a card exists". Before/after seeded **distinct** so a card echoing after-as-before fails | 80×24, 120×30 |
| **AT-080b ★** | **READ-ONLY: Given** the same state, **When** a non-first row is selected **N=3** times, **Then** the loaded image's `mem_map` is **byte-identical** to its pre-selection deep copy AND the document's entries are unchanged AND **no file is written under `.s19tool/`** — nothing was applied | `test_tui_patch_card.py::test_at080b_read_only` | **The story's hard safety constraint.** Counterfactual = a card that renders **by applying**. `Mapping` (not `Dict`) at the panel boundary enforces it by type; this AT proves it at runtime | 80×24, 120×30 |
| AT-080c | **Given** an entry whose address is **NOT in `mem_map`** (unmapped), **When** that row is selected, **Then** the card's before-cell renders the absent placeholder, the after-cell still shows `encoded_bytes`, and the app does not crash; **and** the placeholder is **distinguishable from a real `0x00` byte** | `test_tui_patch_card.py::test_at080c_unmapped` | boundary/error class asserted **by content**. `mem_map` is sparse: an unmapped address is a **`KeyError`, not a zero** — the `—`-vs-`00` distinction is the branch discriminator | 80×24, 120×30 |
| **AT-080d ★** | **See both forms below — MJ-2 fold.** | `test_tui_patch_card.py::test_at080d_reachable_with_card` (see the §2 routing note) | **GATE-BLOCKING C-29 / field-audit B2** | 80×24, 120×30 |

**AT-080d — BOTH forms stated NOW (MJ-2: the relaxation must not be able to void the gate).**

LLR-080.6's pre-committed relaxation is *"the card is made regime-conditional (hidden/collapsed) under the existing
`width-narrow` regime"* — and **`width-narrow` is `<120`, so it fires at 80×24**. The pre-fold AT-080d asserted
*"at 80×24 **with the card mounted**, every docked button reachable"* → **if the amendment triggers, the card isn't
mounted at 80×24, the `Given` is unsatisfiable, and the gate passes vacuously** — the headline feature would cease
to exist at the floor while its gate stayed green. Both forms are therefore normative:

- **Form 1 — no relaxation (the card is mounted at both regimes):**
  **Given** the Patch screen with the before/after card **MOUNTED** (an entry selected, so the card occupies real
  rows) at **80×24** and at **120×30**, **When** each `_NAMED_BUTTONS` docked row is reached via
  `_reach(app, pilot, w)`, **Then** each button is `_fully_visible` after its window/panel scrolls to it, **and**
  each button's docked row is a **SIBLING of** (not a descendant of) its window's `VerticalScroll` body.
- **Form 2 — relaxation triggered (the card is regime-conditional under `width-narrow`):**
  **(a)** at **120×30** the card **IS mounted** *and* reachability holds (Form 1's assertions, unchanged — the
  headline still exists at the comfortable regime); **AND (b)** at **80×24** the card is **provably ABSENT**
  (its node resolves to **0** widgets — asserted, not assumed) **AND** reachability holds. Form 2 **may not** be
  selected merely because Form 1 is inconvenient: it activates **only** on the recorded TC-C29.1 measurement, via
  a §6.5 amendment, and the amendment record is part of this AT's pass evidence.

**AT-080d contract (batch-46 FOLD-8, reused verbatim — read this before writing a threshold):** the measured panel
viewport is **~5 rows @80×24** / ~11 @120×30 with **17+ named buttons**, so **"all buttons visible at scroll 0" is
PHYSICALLY IMPOSSIBLE** and `off == []` at scroll 0 is **deliberately NOT asserted**. The contract is
**reachable-under-scroll**: (a) the sibling-not-descendant structural invariant, and (b) `_fully_visible` **after**
`_reach`. **Never hard-code a row/col count** — the budget is pilot-measured in Phase 3 (TC-C29.1, C-29 both axes).

### US-P6 — R-TUI-081

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-081a | **Given** 2 entry-add operations then 1 `ctrl+z` (the batch-40 undo binding), **When** the history strip renders, **Then** it reports **1 step back and 1 step forward** — matching the **derived** `(len(_undo_stack), len(_redo_stack))` == `(1, 1)` — and shows the `ctrl+z` / `ctrl+y` hints | `test_tui_patch_history_strip.py::test_at081a_position` | **C-10(a)** — drives real bindings and asserts the strip moved **off its default**; asserts CONTENT against the derived depths (no cursor exists) | 80×24, 120×30 |
| AT-081b | **BOUNDS: Given** a fresh document with **no history**, **When** the strip renders, **Then** it shows the empty state with no crash and no divide-by-zero; **and Given** **21** operations, **Then** the reported depth reads **20** (`_HISTORY_MAX`), **not 21** — it saturates at the bound | `test_tui_patch_history_strip.py::test_at081b_bounds` | empty **and** full boundary classes through the shipped surface; the 21st-op eviction is the discriminator | 80×24, 120×30 |

**AT totals (CANONICAL — the PINNED registry):** US-P1 **9** (`AT-075a/b/c/d★★/e★★` + `AT-076a/b★/c`) · US-P2 **5**
(`AT-077a/b/c★/d/e★`) · US-P3 **3** · US-P4 **4** (`AT-079a/b/c★★/d`) · US-P5 **4** (incl. `AT-080b★`,
`AT-080d★`) · US-P6 **2** = **26 AT ids × 2 pilot sizes = 52 AT executions.**
Delta vs the Phase-1 draft's **23**: **+3** — `AT-075e` (BL-1) · `AT-077e` (BL-4, **split from `AT-077c`**, never
merged into it) · `AT-079d` (MJ-4, the fallback CI cannot reach naturally). **This set is identical to
`01-requirements.md` §5.2's 26** — verified id-for-id in the 2026-07-16 reconciliation pass.
**6 gate-blocking:** `AT-075d` ★★ (C-17 variant line) · `AT-075e` ★★ (C-17 entries table — **the live sink at
HEAD**) · `AT-079c` ★★ (C-17 pasted JSON) · `AT-077c` ★ (**document** staleness) · `AT-077e` ★ (**image**
staleness) · `AT-080d` ★ (C-29/B2 reachability, anti-vacuity form if the relaxation fires).

> **⚠ `AT-080e` is CONDITIONAL-ON-GREP and is NOT one of the 26 — stated identically in canonical §5.2 / LLR-080.7.**
> There is **no hostile-card-header AT today, and there must not be one**: the card header **does not exist yet**, so
> an AT over it would **pass vacuously** — the **MJ-2 defect class**, which is exactly what this batch spent a
> blocker learning. The chosen mechanism is LLR-080.7's **mechanical grep gate** (**TC-080.7**, run **every**
> increment that touches the card builder: any non-`int` input reaching a rendered string == **0**). **IF that grep
> fires, `AT-080e` (hostile card header, the MD-1 payload set through whatever new input reached the card) is
> created in that same increment and is gate-blocking**, and the registry moves to 27 with the increment recording
> it. Until then it is a **named contingency, not a node**: not counted, not scheduled, owed no evidence. *(The
> architect's grep-over-AT reasoning is adopted, not re-litigated: the grep has teeth today; the AT would not.)*

> **⚠ Registry provenance — why this list is pinned (02-review POST-FOLD RECONCILIATION, 2026-07-16).** The two
> Phase-2 fold agents ran **in parallel and each minted AT ids**, which **re-created the very divergence BL-2
> blocked on**: the architect folded BL-4 into a 4-arm `AT-077c` and added `AT-079d`; this document split BL-4 out
> as `AT-077e`. **Ruling: 26 = canonical's 25 + `AT-077e`; `AT-077c` and `AT-077e` stay SPLIT** (distinct triggers
> of one wrong-answer class; merging costs failure isolation — the cost this document itself booked against
> `AT-077a` in §12-4 — and **the image branch is the one MISSED at Phase 1**, so under C-10 per-branch + C-18
> one-node-per-AT it earns its own node). **Process rule: the orchestrator pins the id registry BEFORE dispatching
> folds; agents never mint AT ids in parallel.** Known **FALSE ALARMS** (recorded so a future grep does not
> "rediscover" them): **`AT-076d`** and **`AT-082`** appear **only in §0.1's old→new map table** as retired
> historical ids; **`AT-063a`/`AT-063b`** in §8 are **batch-46** cross-references in census prose. **None are
> batch-48 ATs and none are counted in the 26.**

---

## 4. C-10 AT discipline — enforcement ledger

**(a) Operator-selectable control driven to a NON-DEFAULT value, assert the observed value changed:**
- `AT-080a` — selects entry row **index ≥ 1** (never row 0) and asserts the card shows **THAT** entry's
  before/after byte values. A card hard-wired to row 0, or one rendering the first entry regardless of cursor,
  fails.
- `AT-075c` — presses the real `#patch_execute_scope_button` once; asserts the scope line moved
  `active variant` → `all variants` (the `EXECUTE_SCOPES` cycle, `screens_directionb.py:2551-2556`).
- `AT-081a` — drives 2 adds + 1 real `ctrl+z`; asserts the strip position moved off its default.
- `AT-078c` — drives a real `ctrl+z`; asserts the strip **cleared** off its post-run counts.
- `AT-075a` — adds a 4th entry; asserts the subtitle count moved `3` → `4` (liveness, not a static string).

**(b) A-or-B(-or-C…) policy branch → ONE AT PER BRANCH asserting CONTENT:**
- **Glyph four-way:** `AT-077a` (`✓` **and** `✗` **and** `◐` in one fixture — canonical merges the three post-run
  branches into one node) · `AT-077b` (`·` no-run). All four branches nodalized **by glyph content**.
- **Glyph ordering:** `AT-077d` — the full ORDERED glyph list for a middle-fails fixture. A **distinct** obligation
  from branch coverage: each branch can be right while the mapping is shifted.
- **Provenance two-axis:** `AT-077c` (document mutated → all `·`) / `AT-077e` (image swapped → all `·`). Two
  independent invalidation axes; a stamp covering only one passes the other's AT and ships a wrong answer.
- **Card mapped vs unmapped:** `AT-080a` (mapped → byte values) / `AT-080c` (unmapped → placeholder). The
  placeholder-vs-`0x00` distinction is the branch discriminator.
- **Read-only vs applied:** `AT-080b` asserts the negative — the state did **not** change.
- **C-17 literal vs parsed:** `AT-075d` (variant line) · `AT-075e` (**entries table — the live sink**) ·
  `AT-079c` (pasted buffer), each with the MD-1 bracket-**pairs** + **`[/nope]`**.
- **Chip scoped vs leaked:** `AT-076a` (three groups render) / `AT-076b` (a non-patch `Button` is **unchanged**).
- **Reachability with vs without the card:** `AT-080d` Form 1 / Form 2 — both stated, so neither branch is a void.

No AT asserts merely "output non-empty" where a branch or a selection exists — each names the expected glyph, byte
value, count, style-count, or string.

---

## 5. Boundary catalog per story

Classes: **empty · boundary · invalid · error**. Each gets an AT or TC, or is marked N/A with a reason.

### US-P1 (titles / role colours / scope line / chips)
| Class | Coverage |
|---|---|
| empty | No change-set loaded → subtitle entry count reads `0`; `#patch_doc_empty_state` shows and the table hides (`refresh_entries([])` contract) → AT-075a setup + TC-075.1. A docked row whose buttons are all disabled → chips still render (disabled variant) → TC-076.2. |
| boundary | ≥3 distinct chip groups + every button classed, asserted as a **structural invariant** (AT-076a), never "K chips fit" — C-29-safe at 80×24 where the docked row wraps/scrolls. Chip height vs reachability → TC-076.4 → verdicted by AT-080d. |
| invalid | A variant id with no label → the line renders a neutral placeholder, no crash → AT-075c/TC-075.3. Chip CSS classes are authored, not user-supplied → **N/A** for the CSS itself. |
| error | **Hostile file-derived text in the entries table** (`entry.value` — the **live `from_markup` sink**) → **AT-075e ★★**. **Hostile project-derived variant id** → **AT-075d ★★**. Chip CSS leaking app-wide (the C-30 hazard) → **AT-076b** + TC-076.1. |

### US-P2 (check glyph in the `Kind` cell)
| Class | Coverage |
|---|---|
| empty | **No `CheckRunResult`** (no run yet) → every glyph `·` → **AT-077b** + TC-077.3. 0-entry document → no rows, empty-state preserved, no glyph crash → TC-077.4. |
| boundary | A result with **fewer entries than the document** → surplus rows fall back to `·`, no `IndexError` → TC-077.1. A document whose entry count **equals** the result's but whose content changed (the in-place per-entry JSON edit) → **count-equality is insufficient**; the content signature covers it → **AT-077c** case (c). Single-entry document → subsumed by AT-077d's ordering assertion. |
| invalid | `uncheckable` outcomes (`outside` / `partial` / `no-image`) → `◐` → **AT-077a** + TC-077.3. An unrecognised result token → `◐`, mirroring `_CHECK_RESULT_SEVERITY`'s default → TC-077.3. |
| error | Index misalignment — the silent-mislabel class → **AT-077d** (full ordered list). **Stale-document glyphs** → **AT-077c ★**. **Stale-IMAGE glyphs** (the BL-4 class — checks ran against image A, image B is loaded, document untouched) → **AT-077e ★**. Untrusted `linkage_symbol`/`reason` do not reach the glyph (closed vocabulary) → TC-077.6 N/A-with-reason **+ a mechanical tooltip grep gate** (batch-43: an `str` tooltip **is** markup-parsed). |

### US-P3 (pass/fail strip)
| Class | Coverage |
|---|---|
| empty | `aggregates` all zero / 0 entries → `0 · 0 · 0`, no divide-by-zero → **AT-078b** + TC-078.4. No run / post-undo → cleared strip → **AT-078c**. |
| boundary | All-uncheckable run (no image loaded) → `0/0/N` → TC-078.1 fixture. `frac=0.0` → 0 filled cells (unfloored) → TC-078.4. All-passed → full bar → TC-078.4. |
| invalid | **N/A** — `CHECK_AGGREGATE_KEYS` guarantees all three keys always present (`changes/model.py:571`), so the strip never branches on a missing key. |
| error | A floored microbar misreporting 0 as "some" → TC-078.4 (`floor=False`, the batch-47 rule). A **BLOCKED** run → counts still render; the block reason keeps its existing `#patch_checks_status` sink → TC-078.5 (no untrusted text reaches the strip). |

### US-P4 (JSON colouring in-place + cap gauge)
| Class | Coverage |
|---|---|
| empty | **Empty paste** → gauge `0`, `.plain == ""`, `.spans == []`, no crash → TC-079.4 + TC-079.2. |
| boundary | Paste **AT** exactly `65536` chars → gauge full, no truncation; **over-cap** (65537) → truncated to 65536 → **AT-079a** + TC-079.4. **Non-ASCII** paste → spans are **UTF-8 byte** offsets, not codepoint offsets → **TC-079.1b** (m-2). |
| invalid | Malformed / truncated / non-JSON paste → the buffer still renders literally; the tokenizer degrades, never raises → TC-079.2. **The feature-detect false** (the degradation CI can never reach naturally at the 8.2.8 pin) → **AT-079d** (black-box, through the shipped window at both regimes) **+ TC-079.1a** (white-box, the mechanism) — MJ-4. **An edit after a paste** clears `_highlights` on rebuild → **TC-079.1c** (m-3). |
| error | **Hostile markup / link / `[/nope]` / ANSI** → **AT-079c ★★** (verbatim, no payload-derived span, no `MarkupError`) — a **regression lock on a surface that is safe by construction**, not the batch's primary defence (see the AT-079c safety note). |

### US-P5 (live before/after card)
| Class | Coverage |
|---|---|
| empty | **No file loaded** (`mem_map` is `None`) → neutral "no image" state, no crash, **no fabricated `00`** → TC-080.4. **Empty document** → no rows to select → card neutral → TC-080.4. |
| boundary | Entry **longer than the mapped span** (partial overlap) → mapped prefix + absent tail → TC-080.3. Entry at the exact last mapped byte → subsumed by TC-080.3. **The card's own row cost vs the 5-row @80×24 panel** → TC-080.6 → **AT-080d** (both forms). |
| invalid | Address **NOT in `mem_map`** (unmapped) → placeholder, **distinguishable from a real `0x00`** → **AT-080c** + TC-080.3. An entry index outside the row list → no card update, no crash → TC-080.4. |
| error | The card **applying** something (the safety class) → **AT-080b ★**. The `last_summary` trap (before-bytes always `None` pre-apply, `changes/model.py:336-338`) → TC-080.3 inspection arm. **A file-derived label sneaking onto the card** → **TC-080.7's mechanical grep gate** (MJ-7); non-zero ⇒ `AT-080e` is created that increment. |

### US-P6 (history strip)
| Class | Coverage |
|---|---|
| empty | **Empty history** → zero position, no crash, no divide-by-zero → **AT-081b**. **File-backed document** (history disabled by the batch-38 A-01 guard) → strip's disabled state agrees with the buttons → TC-081.3. |
| boundary | **Full stack** — `_HISTORY_MAX = 20`; the 21st op evicts, the reported total saturates at **20** → **AT-081b** + TC-081.1. |
| invalid | **N/A** — the strip reads only `len()` of two in-process lists; no external/untrusted input reaches it. |
| error | A stray cursor attribute drifting out of sync with the stacks → TC-081.1 (position must be **derived**, 0 new state). Strip and buttons disagreeing about whether a step exists → TC-081.3 (all 3 sites push depths). |

**Deferred (with reason):** concurrency (single-threaded UI thread; the worker/UI split is `LoadedFile`-only and
unchanged this batch) · auth states (**N/A** — no auth surface in this app) · a `.hex`-loaded card variant (the
card reads `mem_map`, which is file-format-agnostic — S19 coverage is sufficient; **noted, not silently cut**).

---

## 6. C-29 two-axis geometry note (carried into Phase 3) — **PRESERVED**

**Do NOT hard-code any rendered row/col count as a pass threshold.** Per C-29 (batch-46 origin — the exact control
this batch's headline re-triggers), Phase 3 MUST pilot-measure **BOTH** axes (width in columns AND height in rows)
of the **real boxed panel** — inside the command bar / status / footer / rail chrome — at **80×24 AND 120×30**,
**with the card mounted and the chips applied**:

- **The card is a structural addition to a panel already measured at ~5 content rows @80×24.** Adding rows to a
  5-row viewport is precisely the B2 defect's shape. Measure the panel budget **and every sibling window's** budget
  (`_MIN_USABLE_W = 15` / `_MIN_USABLE_H = 5`, `tests/test_tui_patch_layout.py:61-62`), not just the card — the
  C-23 whole-pane rule.
- **Do not inherit the prototype's budget.** `prototypes/screen_upgrades.prototype.py` renders the patch screen as
  the WHOLE screen; production boxes it inside chrome. The prototype's row count does not transfer (the C-16
  non-transfer trap on the vertical axis) — the literal batch-46 FOLD-8 origin.
- **Do not inherit batch-46's ~5-row figure as this batch's budget either.** It is cited as the **regime and the
  reason** for reachable-under-scroll; the card changes the container's content, so it must be **re-measured**.
- **If the measured budget cannot satisfy a threshold, relax the DESIGN or the acceptance at draft time**
  (collapsible card, card as a body row inside PATCH SCRIPT, reachable-under-scroll) rather than shipping a
  physically-impossible AT — **and state the post-relaxation AT form immediately** (the MJ-2 lesson: a relaxation
  that silently voids its own gate is worse than no gate). `AT-080d` Form 2 is that statement, pre-written.
- **BL-3 lowered the width risk but did not remove it.** The glyph now rides **inside** cell 0 as a span, so the
  table stays **5 columns** — but the `Kind` cell grows by the glyph + its separator. TC-C29.1 records the
  **rendered `Kind`-cell width** per regime alongside the panel measurement.
- ATs above assert **structural / relative invariants** only: ≥3 distinct chip groups; ≥3 distinct token styles;
  the exact ordered glyph list; the exact byte values; `_fully_visible` **after** `_reach` + the
  sibling-not-descendant tree invariant. **All hold at any geometry.**

---

## 7. ⚠ Snapshot census (C-22 per-cell) — **CRITICAL THIS BATCH** — **PRESERVED**

**The two patch cells are STRICT GREEN oracles at HEAD.** Verified: `_batch46_patch_drift_marks`
(`tests/test_tui_snapshot.py:507`) returns `()` **before** its dead body — batch-47's regen PR (#87, @ `6551aed`)
landed the refreshed baselines and retired the marks. **Any visible repaint of the patch panel therefore fails
`test_tc016s_density_layout_snapshot` as CI RED, not xfail.**

**Mandatory action:** add `_batch48_patch_drift_marks(screen, density, size_key)` to the `_SCAFFOLD_CELLS` mark
chain (`tests/test_tui_snapshot.py:818-830`) returning `pytest.mark.xfail(..., strict=False)` for
`screen == "patch"` — **in the same increment as the first visible change**, not at Phase 4. Then regen in
**canonical CI only** (`snapshot-regen.yml`, textual==8.2.8) as a **post-merge follow-up PR**. **Local regen is
FORBIDDEN** (`reference_snapshot_regen_env` — local textual drift corrupts unrelated baselines).

### Per-cell prediction (C-22 — reasoned, stated as an UPPER BOUND under `strict=False`)

**Scaffold constraint that shapes both predictions:** `_snapshot_run_before` (`tests/test_tui_snapshot.py:341-358`)
installs a synthetic `LoadedFile` triple but **loads NO change document**. So in both cells the patch panel renders
with an **empty document**: the entries table is **hidden** (`#patch_doc_empty_state` shows), no check result
exists, and no row is selected. **Therefore the glyph (US-P2), the card (US-P5), and a populated strip (US-P3) DO
NOT RENDER in either snapshot cell** — they cannot drift, and a snapshot could never serve as their oracle.

| Cell | Prediction | Why (per-cell reasoning) |
|---|---|---|
| `patch-comfortable-120x30` | **WILL drift — near-certain** | All three windows render 3-across at 11 rows each. Visible at scroll 0: window **border titles + subtitles** (US-P1), **chips** on the docked rows (US-P1), the **scope line** (US-P1), the **JSON cap gauge** rendering `0 KB / 64KB` (US-P4), the **zeroed CHECKS strip** (US-P3), and the **empty history strip** (US-P6). Multiple independent repaints. |
| `patch-comfortable-80x24` | **LIKELY drift — but narrower; NOT certain** | Stacked reflow with a **~5-row panel viewport at scroll 0**, so only the TOP of `#patch_win_script` is above the fold. Drift depends on **where the subtitle lands**: a **border_title / top-border** subtitle is above the fold → **drifts**; a **border_subtitle** (Textual renders it on the **bottom** border) or a scope line further down the pane is **below the fold** → **may NOT drift**. The chips, gauge, strip, and history strip are all below the fold at scroll 0 → do not contribute. |

**Upper bound: 2 cells.** `strict=False` absorbs the 80×24 case if it does not in fact drift (the batch-33 /
batch-35 over-count lesson). **No other screen renders the patch panel** (`_SCAFFOLD_SCREENS = ["map","patch","diff"]`,
`tests/test_tui_snapshot.py:110`), and **C-28 does not fire this batch** — no App-level `Binding(show=True)` is
added/removed/changed (render-only; TC-081.4 confirms it at **each increment's snapshot step**, not at the Phase-4
run — C-25). If an increment does touch a binding, sweep **every** shared-chrome cell per C-28 (batch-45 F-1: 18
unexpected cells).

**BL-3 lowers the 80×24 drift probability further:** with the glyph folded **into** cell 0 rather than added as a
6th column, the table's column layout does not change — and in the snapshot scaffold the table is **hidden anyway**
(empty document). The glyph contributes **0** predicted drift in **both** cells.

**Snapshot is NOT a primary AT oracle for any story here** — the scaffold renders an empty document, so the
headline deliverables are invisible to it. Every AT in §3 asserts on live rendered content via `run_test`.

**C-30:** this batch is patch-screen-scoped and adds **no** app-wide restyle → C-30 is **N/A**, *conditional on*
TC-076.1 holding (chip CSS must be `#patch_editor_panel`-scoped) and **falsified by AT-076b** if it does not. If
the chip CSS is authored as a bare `Button` rule, C-30 fires and the CSS increment must be sequenced **last**.

---

## 8. C-26 reverse-census plan (what must be re-validated per touched symbol)

For each symbol the batch touches, the census names the test files that reference it; **each must be re-run and
re-read BEFORE the edit** (C-26: the reverse census covers interaction-tests of MOVED/CHANGED **leaves**, not just
container ids). This table is a **cost-reduction heuristic, not a completeness proof** — the increment gate is the
guarantee.

| Touched symbol | Referencing tests (seed counts) | What must be re-validated |
|---|---|---|
| `PatchEditorPanel` | `patch_editor_v2`(32) · `directionb`(10) · `variants`(7) · `patch_variant`(5) · `before_after_report`(4) · `patch_layout`(4) · `undo_redo_ux`(3) · `loadfilescreen_input`(2) · `memory_patch`(2) · `report_filter_surface`(2) · `variant_execution`(2) | Compose-tree assumptions; every `query_one("#patch_*")`; **C-7 purity** (0 `self.app`, 0 service imports) after `mem_map` is threaded. |
| `_ENTRIES_COLUMNS` / entries table shape | `patch_editor_v2`: **positional cell reads at `:2578` (docstring pins the order as contract) and `:3208-3209` (`Coordinate(row,1)`=address, `(row,2)`=value)** | **BL-3: T-1 IS DISSOLVED.** The glyph folds into cell 0 as a span; `_ENTRIES_COLUMNS` stays a **5-tuple**; cols 1-2 do not move. **Col 0 is UNASSERTED by these readers** → **expected diff on this file = 0 lines**. Re-run it read-only; **a needed edit means the fold was implemented wrong** (TC-077.4's threshold). |
| `refresh_entries` / `ChangeEntryRow` | `patch_editor_v2` · `undo_redo_ux` · `change_service` | The shaped-row contract (`kind_text`/`address_text`/`value_text`/`status_text`/`linkage_text`). A defaulted `check_glyph` field must not break `rows()` consumers or `refresh_entries([])`'s hide-table branch. **Docstring (`:3229-3232`) enumerates the duck-typed attribute set → update it** (PROJECT_RULES contract). |
| **`refresh_entries` CALL SITES — FOUR, not three (MJ-1)** | `app.py:2049` · `app.py:2255` · `app.py:3884` · **`screens_directionb.py:2976`** (a **self-call** inside `on_mount` `:2962`) | **The 4th site is the MJ-1 defect shape.** The three `app.py` sites must pass `mem_map=`; the **panel's own `on_mount` self-call cannot** (the panel has no `mem_map` — C-7). If LLR-080.2's retain is `self._mem_map = mem_map` **unconditional**, that self-call **nulls it**. Benign today *only by ordering* — an unstated invariant. → **TC-080.2a** must pass, and LLR-080.2 must **state** the retain semantics (sentinel-default ⇒ preserve, **or** an explicit clobber-is-safe + this test). |
| `patch_win_*` | `patch_editor_v2` · `patch_layout` · `variants` | Window geometry (AT-063a/b); titles now non-empty; `_MIN_USABLE_W/H` floors still met **with the card mounted**. |
| `patch_pane_entries` | `directionb`(3) · `patch_layout`(1) | The FOLD-1 non-scroll sub-container invariant (batch-46) must survive the card's insertion. |
| `last_check_result` | `undo_redo_ux`(2) · `change_service`(1) · `patch_editor_v2`(1) | The **reset-on-undo/redo** contract (`change_service.py:474`/`:506`) now has a second consumer (the glyph) → TC-077.2. **And a NEW invalidation axis** (`image_generation`, BL-4) that these tests do not yet know about → re-read them for any assertion that a check result **survives** a file load. |
| **`_apply_loaded_file` / the load path** (**NEW seam — BL-4**) | `directionb` · `tui_app` · `patch_editor_v2` · any test that loads a second file into one app instance | The NEW `image_generation` token bumps here. Re-read every test that loads **two** files into one app for an assumption that patch-editor state survives the second load. → **AT-077e** + TC-077.2 case (d). |
| `CheckRunResult` | `checks_engine`(8) · `report_service`(5) · `variant_execution`(2) | Read-only consumption; assert **0 model changes** (the shape is engine contract). |
| `_HISTORY_MAX` | `change_service`(6) | The strip's derived total must agree with the eviction behaviour → TC-081.1. |
| `CappedTextArea` | `capped_text_area`(11) · `patch_editor_v2`(4) | The 64KiB cap contract is unchanged; the gauge is a **new reader**, not a new cap → TC-079.4. **`_highlights` is now written by us** → re-read for any assumption that the buffer is unstyled. |
| `_MUST_PRESERVE_IDS` (48) | `patch_layout` (the tuple itself) | **All 48 ids resolve exactly once** at both sizes → TC-CEN.1 / AT-076c. Any moved LEAF id (not just containers) trips this — the batch-46 C-26 census-miss lesson. This batch **moves no id** (classes-only + additive), so that failure mode is structurally absent. |
| `styles.tcss` patch block (≈`:824-1170`) | `patch_layout` (the `width-narrow` rule) · snapshot cells | The `width-narrow` reflow regime must still stack at <120 after the chip CSS lands — **and is the trigger surface for `AT-080d` Form 2**. |
| `test_tui_snapshot.py` marks | itself | `_batch48_patch_drift_marks` wired into `_SCAFFOLD_CELLS` (§7). |

**Frozen test set: CLEAN** — no census seed touches any of the 9 frozen test files. **C-27 dual guard
(TC-FRZ.1 + TC-FRZ.2) runs every increment.** All 7 new AT homes are **NEW files** → non-frozen by construction.

---

## 9. Testability risks — status after the Phase-2 folds

### 9.1 T-1 — **DISSOLVED by BL-3. Recorded explicitly.**

**Was (HIGH):** *"the entries table is read by hard-coded column index; a **prepended** glyph column silently
breaks `tests/test_tui_patch_editor_v2.py:2578` and `:3208-3209`"* — this document called it **"the batch's
sharpest regression risk"**.

**Now: not a risk at all.** The glyph **folds into the `Kind` cell as its own span**; `_ENTRIES_COLUMNS` stays a
**5-tuple**; **no column is added and no index shifts**. Precedent verified in source (not taken on framing):
batch-47 A2L `app.py:9548` — *"the name cell (**index 0**) carries the leading in-image glyph"*; MAC
`app.py:9223-9226` — *"**Fold** a leading status glyph … into the Tag cell **as its own span**"*. **Both keep the
column count unchanged.**

**Consequences, recorded:**
1. **The 32-hit census file needs ZERO edits.** Its readers pin `Coordinate(row,1)` (address) and `(row,2)`
   (value); **col 0 is unasserted by them**. Expected `git diff main -- tests/test_tui_patch_editor_v2.py` =
   **0 lines**.
2. **And if it ever does need an edit, the fold was implemented wrong** — a leading COLUMN was added instead of a
   leading SPAN. That is **a free correctness signal**, and it is encoded as a **threshold on TC-077.4**, not left
   as a hope.
3. **My glyph ATs survive unchanged — confirmed.** `AT-077a/b/c/d/e` assert the glyph's **content** and its
   **ordered position**; **none** asserts a column count or a column index. Only the observation point moves
   ("column 0's cell" → "the leading span of the `Kind` cell's `Text`"). The Given/When/Then bodies are carried
   over verbatim.
4. **Amendment C is unnecessary** (architect-owned) — the "6 columns don't fit at 80×24" deficit never exists. The
   width risk drops to "cell 0 grows by a glyph + separator", recorded in TC-C29.1.
5. `AT-076c` / TC-CEN.1 (the 48 ids) remain mandatory re-runs regardless — the card and the strips **add** ids.

### 9.2 Remaining risks (status)

- **T-2 (MEDIUM) — the glyph seam. ANSWERED** by LLR-077.1: a **defaulted `check_glyph` field on
  `ChangeEntryRow`**, computed in `rows()` (which already owns `last_check_result`). Constructor-census: **0**
  direct `ChangeEntryRow(` constructions in `tests/` → additive, breaks no caller. → TC-077.5. **Residual:** none.
- **T-3 (MEDIUM) — the card's row budget. ANSWERED** by LLR-080.6's pre-committed relaxation — **but MJ-2 showed
  the relaxation would have voided its own gate.** → `AT-080d` **both forms** (§3). **Residual:** the relaxation
  must be selected from the TC-C29.1 measurement and recorded as a §6.5 amendment; **"Form 2 because Form 1 was
  inconvenient" is not a pass.**
- **T-4 (MEDIUM) — the C-17 sink set. ANSWERED, and INVERTED (BL-1).** The enumerated sink set was wrong: the
  paste buffer is safe by construction; **the entries table is the live sink**. → `AT-075e` ★★ + `LLR-075.6`.
  **Residual:** LLR-080.7's card re-open → **mechanised** as TC-080.7's grep gate (MJ-7). The batch-43 tooltip
  precedent (an `str` tooltip **is** markup-parsed by Textual 8.2.8) is mechanised as TC-077.6's tooltip grep.
- **T-5 (LOW-MEDIUM) — partially-mapped before-bytes. ANSWERED** by LLR-080.3: **per-byte** — mapped bytes shown,
  unmapped shown as the absent token. → TC-080.3 has a stateable Expected. **Residual:** none.
- **T-6 (LOW) — the absent token vs `0x00`. ANSWERED** by LLR-080.3 + A4: `mem_map` is sparse; an unmapped address
  is a **`KeyError`, not a zero**; the placeholder must be **distinguishable**. → `AT-080c` asserts
  `token != rendering_of(0x00)`. **Residual:** none.
- **T-7 (LOW) — subtitle placement decides the 80×24 snapshot prediction. OPEN, non-blocking.** A Textual
  `border_subtitle` renders on the **bottom** border (below the 80×24 fold); a `border_title` renders on top. Not a
  correctness risk — but naming which one is used sharpens §7's prediction from "likely" to "certain/certain-not".
  **Residual:** resolve in the increment that writes LLR-075.1; record the answer in the increment's C-22 note.
- **T-8 (NEW, MEDIUM) — `AT-080d`'s primitives live in another test module.** See §2's routing note. **Residual:**
  decide (i) conftest-lift or (ii) keep the node in `test_tui_patch_layout.py`, in the increment that writes it.
  **Do not duplicate the primitives.**
- **T-9 (~~NEW, LOW-MEDIUM~~ — **CLOSED** 2026-07-16) — `AT-079b`'s canonical pass condition was an `or`.** Same
  self-voiding shape MJ-2 caught on `AT-080d`. **The disjunction is STRUCK in both documents** (§12-1): one pass
  condition, and §6.5 Amendment B **re-writes** the AT instead of satisfying it. **Residual:** the rung selection
  must still be **recorded** (TC-079.1) in `03-increments/` before Phase 4 — a Phase-3 obligation, not a spec gap.

---

## 10. Evidence checklist

- [x] Acceptance criteria use Given/When/Then — §3 AT registry (**26** ATs on the canonical, **pinned** id space; identical id-for-id to `01-requirements.md` §5.2).
- [x] Test cases have explicit Expected (numeric thresholds), not vague "works" — §2 (**45** executable TCs).
- [x] Edge cases include empty, boundary, invalid, error — §5, per story, with deferrals justified.
- [x] Regression checklist exists — TC-FRZ.1/.2, TC-CEN.1, TC-REG.1 (§2) + the §8 C-26 census + §7 snapshot.
- [x] Exit criteria stated — §11.
- [x] No real PII / secrets — public `examples/` fixtures + synthetic injection payloads only.
- [x] Test-results columns left **blank** — nothing in this file is marked as run; Phase 3 executes.
- [x] **Layer B (black-box):** every output-producing story's deliverable is observed through the SHIPPED Patch
      screen via `App.run_test(size=…)` at both regimes, with boundary + negative (C-17, read-only, provenance)
      evidence — §3. Snapshot is explicitly **not** an oracle (§7).
- [x] **Bidirectional surface-reachability:** every named INPUT (fixture load, **a second image load** [BL-4],
      paste into `#patch_paste_text`, `run_checks` button, row select, scope-button click, `ctrl+z`, **a
      file-derived hostile `entry.value` planted through the real document ingress** [BL-1]) AND every named
      OUTPUT (subtitles, chips, scope line, glyph span in cell 0, strip, coloured buffer, cap gauge, before/after
      card, history strip) is exercised/observed through the handler — not only the service API.
- [x] **No unfilled template:** no `<...>` placeholders, no `TC-NNN` stubs, no empty required rows.
- [x] **Id space reconciled to canonical** (BL-2) — §0.1; **no `→ 01b` pointer in `01-requirements.md` §3/§4 is
      left unresolved**; AT count 23 draft + 3 fold-added = **26**; node paths adopted from canonical §5.2.
- [x] **Registry PINNED and verified BIDIRECTIONALLY** (2026-07-16) — the AT id set in `01-requirements.md` §5.2
      **==** the set in this §3 **== 26**; **0** ids in one doc and not the other. Excluded by rule, not by
      oversight: §0.1's map-table historical ids (`AT-076d`, `AT-082`) and §8's batch-46 prose cross-references
      (`AT-063a/b`) are **not batch-48 ATs**; `AT-080e` is conditional-on-grep and deliberately uncounted.
- [x] **Every AT home is NON-FROZEN** — §2 (5 NEW files + 2 existing non-frozen); C-27 dual guard every increment.

---

## 11. Exit criteria (Phase-2 re-gate)

- Every TC row has an Executed-verification node + a numeric threshold. ✓ (§2, 45 TCs)
- Every story has ≥1 AT driving the shipped screen at **both** 80×24 and 120×30. ✓ (§3, **26** ATs / **52** executions)
- **All ids are on the canonical `01-requirements.md` §5.2 space; the old→new map is recorded.** ✓ (§0.1) — BL-2
- **The registry is PINNED at 26 and matches canonical §5.2 id-for-id in BOTH directions (0 orphans either way);
  `AT-080e` is conditional-on-grep and uncounted in both docs.** ✓ (§3) — POST-FOLD RECONCILIATION
- **US-P5's headline AT selects a NON-FIRST row and asserts byte VALUES; the read-only AT is present.** ✓
  (`AT-080a`, `AT-080b`)
- **US-P2 has all four glyph branches by content, PLUS the index-alignment AT, PLUS both provenance axes.** ✓
  (`AT-077a/b/d` + `AT-077c` document + `AT-077e` image) — BL-4
- **Three C-17 ATs present and gate-blocking — including the ENTRIES-TABLE AT over the live sink.** ✓
  (`AT-075d`, **`AT-075e`**, `AT-079c`) — BL-1
- **The payload set contains `[/nope]`; `sensor[unclosed` is credited as a regression fixture only.** ✓ (§3 MD-1)
  — MJ-6
- **The JSON ATs observe `get_line(i).plain` + `.spans` in place; the `ta.text` tautology is named; the fallback
  path has its own AT **and** TC; byte offsets and span-survival each have a TC.** ✓ (`AT-079b/c/d`,
  TC-079.1a/b/c) — MJ-4/MJ-5/m-2/m-3
- **`AT-079b` states a SINGLE pass condition — the `or` is struck and the rung is RECORDED (TC-079.1), mirrored in
  HLR-079's Acceptance.** ✓ (§3 note) — POST-FOLD RECONCILIATION (the §12-1 residual, closed)
- **`AT-080d` states both forms; the relaxation cannot void it.** ✓ (§3) — MJ-2
- **The 4th `refresh_entries` site is in the census and has a retain-semantics TC.** ✓ (§8, TC-080.2a) — MJ-1
- **T-1 is dissolved and recorded; the 32-hit census file's expected diff is 0 lines, enforced as a threshold.** ✓
  (§9.1, TC-077.4) — BL-3
- The C-29 reachability AT re-litigates B2 with the card mounted, using **structural invariants only**. ✓
  (`AT-080d`)
- Boundary catalog complete per story (empty/boundary/invalid/error) or deferral-justified. ✓ (§5)
- No hard-coded geometry threshold in any AT; C-29 two-axis measurement scheduled for Phase 3. ✓ (§6, TC-C29.1)
- Snapshot: per-cell prediction stated, `_batch48_patch_drift_marks` mandated in the first visible-change
  increment, regen deferred to a canonical-CI follow-up PR, **local regen FORBIDDEN**. ✓ (§7)
- C-26 census plan names every touched symbol and its re-validation, **including the two NEW seams** (the 4th
  `refresh_entries` site; `_apply_loaded_file`). ✓ (§8)
- All NEW tests routed to non-frozen homes; C-27 dual guard runs every increment. ✓ (§2, TC-FRZ.1/.2)
- **Open items handed back to the architect / Phase 3:** §12.

---

## 12. Open items — what QA believes the canonical space still gets wrong

Raised in the spirit of the fold, not to reopen it. None blocks the re-gate; each is bounded.

1. **~~`AT-079b`'s pass condition is an `or`~~ — RESOLVED 2026-07-16 (registry reconciliation pass).** The
   disjunction *"JSON structure differentiated (**or** rung-2 §6.5 amendment + gauge-only)"* was structurally
   identical to the AT-080d hazard MJ-2 blocked — **an AT that passes when the feature wasn't built** — and it
   survived **both** Phase-2 reviews. **Struck in both documents:** canonical `01-requirements.md` §3 HLR-079
   Acceptance + §5.2 now state a **single** pass condition (structure differentiated in `get_line().spans`), the
   rung is a **recorded decision** (TC-079.1, written to `03-increments/` before Phase 4), and the only route out
   is **§6.5 Amendment B, which RE-WRITES the AT** rather than satisfying it. This §3's AT-079b row + note mirror
   the canonical wording. **Residual: none** — the "Ask" is discharged, not deferred.
2. **`AT-080d`'s canonical node is in the wrong file for its primitives.** `test_tui_patch_card.py` cannot reach
   `_fully_visible` / `_scrollers` / `_reach` / `_MUST_PRESERVE_IDS` (module-private to
   `tests/test_tui_patch_layout.py`). Adopted canonical routing with a stated prerequisite (§2 routing note, T-8);
   **conftest-lift or re-home — but never duplicate.**
3. **The HLR-level TC rows `TC-075`…`TC-081` in canonical §5.2 are rollups, not nodes.** They carry a method and a
   name but no distinct facet — each is already discharged by its child LLR TCs + the story's ATs. Left them out of
   this document's node count (45 = executable only). **Ask:** mark them `rollup` in §5.2, or the "no unfilled
   template" check reads 7 unimplemented nodes.
4. **`AT-077a` merges three policy branches into one node.** C-10(b) wants one AT per branch. The node asserts all
   three glyphs **by content** in one fixture, so the obligation is discharged — but failure isolation is coarser
   (a `◐` regression and a `✗` regression report as the same red). Accepted as canonical; recorded so the
   trade-off is a decision, not an oversight.
5. **`AT-076c` is a regression AT, not a new-deliverable AT.** Canonical routes it to an **existing, unmodified**
   node (`test_tui_patch_layout.py::test_at063c_reparent_safety`). It resolves under C-18, and re-running it is
   right — but an existing node **cannot evidence a new deliverable**, only the absence of damage. Recorded so it
   is not counted as coverage for HLR-076's chips.
6. **7 new test files vs the ≤5-files-per-increment rule.** The canonical routing is good for census distribution,
   but the AT files must be **spread across increments matching the US dependency order**
   (US-P1 → {P2,P3,P4,P6} → P5), or an increment will breach the file cap on test files alone. Flagged for the
   Phase-3 increment plan, not a spec defect.
7. **`LLR-075.6` does not exist yet** (BL-1 fold (a) is architect-owned). `TC-075.6` and `AT-075e` are written
   against it. If the architect instead widens **LLR-075.2**'s generic clause and retires its 3-role enumeration,
   re-point `TC-075.6`'s traceability there — **the body and threshold are unaffected**. What must **not** happen
   is the enumeration surviving alongside the generic clause: **that contradiction is what BL-1 identified as the
   partial-fix trap** (3 roles enumerated, 5 columns to cover, `status_text` + `linkage_text` left bare, sink still
   live) — and TC-075.6's `5/5` threshold is what arbitrates it.
