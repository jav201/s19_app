# Traceability Matrix — s19_app — Batch 2026-10-11-batch-92

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label**. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`/`R-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block; what it must not do is order the translation of somebody else's.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row. ⚠ **This template is seeded by a BULLET under that table rather than by a row**, because `06-docs/` exists only in `full` — the same fact `V39`'s `_V39_OWED_IN["P6"]` carries.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

> **V-5 provisional→realized note (applies to every AT/TC id below).** AT-288..291 and TC-651..654 were reserved from the global id registry at P1, TC-655 by the P1 amendment pass — all provisional until Phase 3 minted their on-disk nodes (V-5) and Phase 4 reconciled each id to exactly one realized node (C-18). Realized state at close: **AT-288** minted as chartered; **AT-289** re-pointed at the DDR — its chartered node `test_at289_tui_namespace_drops_range_index_wrappers` never realized, the observation is realized by the TC-652 node (LED-…92.14); **AT-290** bound to one canonical node per the C-18 judgment, its sibling re-graded mention; **AT-291** realized by a 3-node charter with `test_at071_strip` as the whole-chain driver (the two companions recorded as same-chain mentions). TC-651..655 minted as chartered.
> **Id-registry state at merge:** the `AT-TC-REGISTRY.jsonl` rows for AT-288..291 / TC-651..655 still read `batch-92` / **`RESERVED`** (no LIVE flip, node bindings pending) — the flip is close bookkeeping carried to BACKLOG-CODE.md lane A (batch-92 close §6), a declared carry, not a gap. This matrix traces the realized nodes; the registry flip lands with that carry.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-92-1 | HLR-001 | LLR-001.1 | TC-651 (+TC-655 import-block pin) | `s19_app/render/hexview.py:1` (new — byte-preserving move; `s19_app/tui/hexview.py` deleted) | pass | Moved body hash `fe6921c7…` recomputed independently 3×; import block rewritten to `render/format`, zero `s19_app.tui.*` imports |
| US-92-1 | HLR-001 | LLR-001.2 | TC-651 | `s19_app/render/hexview.py` — fns ex-`tui/hexview.py:330,360,144,153,173,179,187` | pass | 7/7 symbols importable at the new address; 12 named behavior nodes repointed and green |
| US-92-1 | HLR-001 | LLR-001.3 | — (repointed suite: 5 × `test_tc_023_*` + public-api node) | `s19_app/render/hexview.py:20-24` (constants ex-`tui/hexview.py:20-24`) | pass | 5/5 layout constants hold base values; renderer surface stays in `tui.__all__` |
| US-92-1 | HLR-001 | LLR-001.4 | TC-651 | consumers `tui/app.py:37-42` · `tui/__init__.py:17-31` · `tui/screens.py:34` · `tui/screens_directionb.py:3336,7581` · `tui/services/load_service.py:8` · `report_service.py:58` · `diff_report_service.py:96` | pass | Live-tree AST import census, set-equality over the 8 measured consumers; drift fails the test |
| US-92-2 | HLR-002 | LLR-002.1 | TC-652 (+ repointed wrapper nodes, engine suite) | `s19_app/render/hexview.py` (wrappers deleted) · engine `s19_app/range_index.py:9-79` untouched | pass | 3/3 wrapper names absent from the moved module; engine 0 diff under the frozen dual-guard |
| US-92-2 | HLR-002 | LLR-002.2 | TC-652 | `s19_app/tui/__init__.py:28,87` (wrappers dropped from import block + `__all__`; renderer names kept) | pass | 3/3 names not importable from `s19_app.tui`; 12/12 renderer names present |
| US-92-2 | HLR-002 | LLR-002.3 | TC-652 | `s19_app/tui/app.py:37-42` (engine-direct sourcing) | pass | `app.py` edges: `s19_app.range_index` + `s19_app.render.hexview`, no `.hexview` edge |
| US-92-3 | HLR-003 | LLR-003.1 | TC-653 | `s19_app/utils.py` — `safe_text` + `_CONTROL_SCRUB` ex-`tui/screens_directionb.py:878,881-936` | pass | Transfer hash `103da220…2974` recomputed by the Inc-B reviewer; 1 definition site per symbol |
| US-92-3 | HLR-003 | LLR-003.2 | TC-653 (+ repointed hostile family) | `s19_app/utils.py::safe_text` | pass | C-17 contract intact: 65/65 control codepoints scrubbed, literal `Text`, never `from_markup` (mutation re-run RED at the new address) |
| US-92-3 | HLR-003 | LLR-003.3 | TC-653 | `tui/app.py:79` · `tui/checks_view.py:41` · `tui/issues_view.py:40` | pass | Live-tree AST census, set-equality over the 3 measured consumers |
| US-92-4 | HLR-004 | LLR-004.1 | TC-654 (+TC-655 value pin) | `s19_app/render/format.py` — microbar + glyphs + palette (ex-`tui/insight_style.py:43-61,117-118,216-277`); style strings value-equal to frozen `tui/color_policy.py:13-14` | pass | 8/8 symbols at base values; `CYAN`/`DGRAY` canonical ownership moved; `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE` pinned by TC-655 |
| US-92-4 | HLR-004 | LLR-004.2 | TC-654 (identity arm) | `s19_app/tui/insight_style.py` (8-symbol re-export shim) | pass | `is`-identity 8/8 against `render.format`; retained palette/helpers stay canonical in `insight_style` |
| US-92-4 | HLR-004 | LLR-004.3 | TC-654 | `s19_app/tui/services/validation_service.py:17` | pass | Service-layer grep for `insight_style` imports → 0; live-tree census set-equality |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| *(example)* US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| *(example)* US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| *(example)* US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |
```

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. A story with a complete functional chain but no behavioral row is INCOMPLETE.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-92-1 | AT-288 — `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` (exactly 1 node) | Report services end-to-end over the `large_s19` fixture → Direction-B hex view screen | Emitted report bytes byte-equal to the pinned pre-move capture, sha256 `061ee94c…4c39` (`evidence/at288-pre-move-report.bin` + `.sha256`, re-verified at P4 and at the PR-merge re-run) | pass |
| US-92-2 | AT-289 — `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` (V-5 re-point, LED-…92.14 — the chartered `test_at289_…` name never realized) | The `s19_app.tui` package namespace (`__init__` import surface + `__all__`) and `tui/app.py` | The 3 wrapper names not importable from `s19_app.tui`, absent from `__all__`, and the primitives live at the frozen engine address | pass |
| US-92-3 | AT-290 — canonical binding `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal`; `tests/test_tui_checks_view.py::test_c17_seed_hostile_linkage_and_reason_render_literal` re-graded mention (C-18 judgment, `review-p4-qa.md`) | The issues screen and checks screen through the shipped TUI app surface (`S19TuiApp.run_test` pilot) | Hostile bracket/ANSI/control payloads render literal — `.plain` verbatim, `spans == []`, no parse error, no style leak | pass |
| US-92-4 | AT-291 — `tests/test_tui_mac_coverage.py::test_at071_strip` (whole-chain driver; `test_build_mac_coverage_strip_counts`, `test_zero_total_no_divdivzero` companions as same-chain mentions) | The MAC coverage strip rendered through the shipped app surface via the service path | `mac_in_s19 of mac_total` strip identical to the pre-move capture; 14/14 strip family green | pass |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | AT-001 | `<handler/screen/CLI>` | `<outcome / file:path>` | pass |
```

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 6 (US-92-1…US-92-6) |
| Covered user stories | 4 of 4 in-scope READY (100%) · US-92-6 SATISFIED-EXTERNALLY at `b167828` (batch-91) · US-92-5 OUT (operator freeze ruling) → backlog lane A |
| Total HLR | 4 |
| Implemented HLR | 4 (100%) |
| Total LLR | 13 |
| Implemented LLR | 13 (100%) |
| Test cases | 5 minted (TC-651…TC-655) + 43 repointed existing nodes + the untouched engine family |
| TC pass | 5 / 5 (census TCs) · 43 / 43 (repointed suite) · engine suite green |
| TC fail | 0 |
| TC pending | 0 (the `AT-TC-REGISTRY.jsonl` RESERVED→LIVE flip is bookkeeping, tracked as a named carry — see the note atop §1) |

Test-ledger delta: 2765 − 0 + 5 = **2770** collected nodes post-batch (`05-postmortem.md` §Metrics).

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or TCs without code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| none — no gap | | Every in-scope LLR carries an executed TC or repointed suite; every READY story carries a reconciled AT (V-5/C-18) | |

Named carries (not coverage gaps — declared, routed at close per `05-postmortem.md`): the suite-flakiness sharpening (52-node known-unstable corpus), US-92-5 (`change_service → color_policy` residual edge), TC-027 `_ENGINE_PATHS` carry (C3), 4 stale `tui.hexview` prose mentions (C4), and the AT-290/AT-291 registry re-binding bookkeeping.

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| *(example)* G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |
```

---

## 4. Changes from previous batch

*(If applicable — what was added, modified, or closed since the previous batch.)*

| Type | Item | Detail |
|------|------|--------|
| new | HLR-001…HLR-004 · LLR-001.1…LLR-004.3 (13) · AT-288…AT-291 · TC-651…TC-655 | The batch's full requirement set, minted at P1 (iteration 1) and amended at the P1 return (iteration 2: render/format constants move + TC-655) |
| new | `s19_app/render/` package (`__init__.py`, `hexview.py`, `format.py`) | The architecture's product: a tui-free render layer |
| modified | 43 existing test nodes (repointed imports, ids kept) | `test_tui_hexview.py` / `test_tui_hexview_classed.py` / `test_tui_helpers.py` + the report-service source-census assertion; 0 nodes deleted |
| modified | `AT-TC-REGISTRY.jsonl` | AT-288..291 / TC-651..655 RESERVED rows written at P1; scanned-corpus bound 159 → 162 at the DDR (`tests/test_id_registry.py:70`, guard 13/13) |
| modified | pinned baseline reference | 44-node union extended to 52 known-unstable nodes after the third/base execution (LED-…92.15) — every added node carries executed evidence in both trees |
| closed | US-92-6 (suite runnable from a fresh checkout) | SATISFIED-EXTERNALLY at `b167828` (batch-91); worktree rebased onto `410cde5` |
| closed | US-92-5 | OUT — operator freeze ruling 2026-10-11 stands; residual edge declared and carried to backlog lane A |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* new | HLR-007 | Added in this batch |
| *(example)* modified | LLR-002.1 | Statement adjusted per review finding |
| *(example)* closed | G-003 (previous batch) | Resolved in TC-008 |
```

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-92-1** → HLR-001 → LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4 → TC-651, TC-655 (+ the repointed 43-node suite) · AT-288
- **US-92-2** → HLR-002 → LLR-002.1, LLR-002.2, LLR-002.3 → TC-652 · AT-289
- **US-92-3** → HLR-003 → LLR-003.1, LLR-003.2, LLR-003.3 → TC-653 · AT-290
- **US-92-4** → HLR-004 → LLR-004.1, LLR-004.2, LLR-004.3 → TC-654, TC-655 · AT-291
- **US-92-5** → OUT (deferred, declared residual `change_service → color_policy`)
- **US-92-6** → SATISFIED-EXTERNALLY at `b167828` (batch-91)

### 5.2 By code file
- `s19_app/render/hexview.py` (new — moved) → LLR-001.1, LLR-001.2, LLR-001.3, LLR-002.1 → TC-651, TC-652, TC-655
- `s19_app/render/format.py` (new) → LLR-004.1 → TC-654, TC-655
- `s19_app/render/__init__.py` (new — package marker) → LLR-001.1 → TC-651
- `s19_app/utils.py` (modified) → LLR-003.1, LLR-003.2 → TC-653
- `s19_app/tui/hexview.py` (deleted) → LLR-001.1 → TC-651 (old-path absence asserted)
- `s19_app/tui/__init__.py` → LLR-001.4, LLR-002.2 → TC-651, TC-652
- `s19_app/tui/app.py` → LLR-001.4, LLR-002.3, LLR-003.3 → TC-651, TC-652, TC-653
- `s19_app/tui/insight_style.py` → LLR-004.2 → TC-654
- `s19_app/tui/services/validation_service.py` → LLR-004.3 → TC-654
- `s19_app/tui/services/load_service.py` · `report_service.py` · `diff_report_service.py` → LLR-001.4 → TC-651
- `s19_app/tui/screens_directionb.py` · `screens.py` · `checks_view.py` · `issues_view.py` → LLR-001.4, LLR-003.1, LLR-003.3 → TC-651, TC-653
- `tests/test_render_hexview.py` · `tests/test_render_format.py` · `tests/test_import_census.py` (new) → TC-651, TC-652, TC-653, TC-654, TC-655 (5 nodes)

**Worked examples of both maps — text to read, never lines of your record:**

```text
- *(example)* **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003
- *(example)* `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- *(example)* `src/bar.ts` → LLR-002.1 → TC-003
```

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-11-batch-92` |
| Closing date | `2026-10-12` |
| Total iterations (sum of phases) | 12 station-passes (`P0:1, ARQ:1, P1:2, P2:2, PDR:1, P3:2, DDR:1, P4:1, P5:1`) |
| Validation passed | yes — P4 gate `approve`; PR #210 merged to main as `a67407c` after a CLEAN final qa pass |
| Synced to Obsidian | no — the closeout branch (`kimi/batch-92-closeout`) publishes the record; the vault view is generated by `/dev-flow-sync` step 6 |
