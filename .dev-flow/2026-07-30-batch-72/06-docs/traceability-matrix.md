# Traceability Matrix — s19_app — Batch 2026-07-30-batch-72

> **Artifact language:** English. Phase-6 artifact. Owner: `docs-writer`.
> Source of record: [`01-requirements.md`](../01-requirements.md) **revision 3** (+ §6.5 amendments
> D-1 / D-2 folded at `d13bb1c`), [`00-measurements.md`](../00-measurements.md),
> [`02-review.md`](../02-review.md), [`04-validation.md`](../04-validation.md), the four increment
> packets, and [`increment-001-002-review.md`](../03-increments/increment-001-002-review.md).
>
> Two chains — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> **Deviation from the template, stated up front:** the template's tables carry only *live* rows.
> This batch **withdrew one HLR** and **retired one design guard, one batch-59 requirement and one
> batch-59 acceptance test**. A matrix that silently omits them would misrepresent the batch, so
> §1c carries them as explicit rows with their disposition and evidence.

---

## 0. Read first — the state of both chains

| Question | Answer |
|---|---|
| Are both chains complete for all three stories? | **Yes.** 3/3 stories carry a functional chain to file:line and a behavioral chain to an observed outcome. |
| Any node RED at close? | **No.** Gate suite `2370 passed, 2 skipped, 21 deselected, 3 xfailed`, **29 snapshots passed**, `GATE_EXIT=0`. |
| Phase-4 verdict | **PASS**, no blocker — [`04-validation.md`](../04-validation.md) §11. 7 HLR in force / 7 pass; Layer A 11/11 TCs reconciled to a real on-disk collected node; Layer B 7/7 ATs each mapping to **exactly one distinct** node (C-18); 13/13 input dimensions driven through the handler and 21/21 named outputs observed. |
| Ledger | `2379 − 1 + 18 = 2396`, reconciled against `pytest --collect-only` (`2396 tests collected`) and against the gate run (`2370 + 2 + 21 + 3 = 2396`). |
| Snapshots regenerated | **0.** Premises P-2/P-3 held — neither screen is snapshot-captured; `git diff --name-only origin/main -- '*__snapshots__*'` is empty. |
| Anything not closable from source material | **One discrepancy, reported not blended:** `04-validation.md` §3 states *"Four mutations were executed in this batch"* and tables CF-1…CF-4 plus a control arm. Two further executed mutations are recorded in the increment packets and are **not** in that table. Enumerated in §2 and raised as gap **G-072-01**. |

---

## 1. Master table — functional chain (white-box)

Test-node file:line values are the `def` line of the node on the branch tip (`d13bb1c`).
Code file:line values are the shipped implementation the node observes.

| US | HLR | LLR | TC | Code file:line | Test node (file:line) | Status | Notes |
|----|-----|-----|----|----------------|------------------------|--------|-------|
| US-072-1 | HLR-072-1 | LLR-072-1.1 | TC-510 | `s19_app/tui/crc_designer_view.py:322-331` | `tests/test_crc_designer_view.py:1665` `test_reflection_row_structure` | pass | One `.crc-field-row` holding both switches; label inventory `["Reflection","in","out"]` |
| US-072-1 | HLR-072-1 | LLR-072-1.2 | TC-511 | `s19_app/tui/crc_designer_view.py` — per-toggle row helper **deleted** (was `origin/main:453-469`) | `tests/test_crc_designer_view.py:1700` `test_orphaned_per_toggle_helper_is_deleted` | pass | Threshold is a repo-wide grep → **0 hits**. The node assembles the token from fragments so it cannot falsify its own assertion |
| US-072-1 | HLR-072-2 | LLR-072-2.1 | **AT-215 clauses 1, 2, 4** *(no separate TC — declared, not omitted)* | `s19_app/tui/crc_designer_view.py:343-348` inside `#crc_algorithm_fields` (`:349`) | `tests/test_crc_designer_view.py:1527` `test_kat_verdict_demoted_to_self_test_row_under_check` | pass | The structural half of the re-parent (ancestor, on-screen vector name, `#crc_live_verify` empty) is carried by AT-215's non-behavioural clauses; §5.2 of the requirement allocates no TC here |
| US-072-1 | HLR-072-2 | LLR-072-2.2 | TC-512 | `s19_app/tui/crc_designer_view.py:445` (`#crc_top_right`) inside `:446` (`#crc_hero_row`) | `tests/test_crc_designer_view.py:1723` `test_hero_right_column_holds_warnings_only` | pass | Right column holds exactly one child group |
| US-072-1 | HLR-072-2 | LLR-072-2.3 | TC-513 | `s19_app/tui/styles.tcss` — `.crc-hero` block **removed** (was `:2051-2057`) | `tests/test_crc_designer_view.py:1751` `test_retired_hero_selectors_absent_from_stylesheet` | pass | `.crc-field-input` (`:1941-1948`) deliberately untouched — batch-59's R9 decision stands |
| US-072-1 | HLR-072-2 | LLR-072-2.4 | TC-513 *(companion)* + ledger `D = 1` | `tests/test_crc_designer_view.py:1003-1047` **deleted**; a retirement comment stands in its place (`~:1005-1011`) | deletion verified by `pytest --collect-only` (2387 → 2393 with `A=7, D=1`) | pass | **Deleted, never edited into passing** — §6.5 **A-1** |
| US-072-1 | HLR-072-3 | *(guard over LLR-072-1.1 — no LLR of its own, by design)* | TC-514 | `s19_app/tui/crc_designer_view.py` — `Switch` imported and constructed only in this module (`:325`, `:327`) | `tests/test_crc_designer_view.py:1858` `test_tc514_every_switch_construction_site_is_on_the_crc_designer` | pass | Asserts **single-module confinement**, not a site count — the spec constant this batch falsified itself (§6.5 **D-1**) |
| US-072-2 | HLR-072-5 | LLR-072-5.1 | TC-515 | `s19_app/tui/screens.py:1233-1237` | `tests/test_legend_two_pane.py:259` `test_tc515_panes_hold_the_unmodified_render_output` | pass | Per-pane widget counts match M-6: mac 17/6, map 20/7 |
| US-072-2 | HLR-072-5 | LLR-072-5.1 | TC-516 | `s19_app/tui/screens.py:1236` (`#legend_body` preserved as the wrapper) | `tests/test_legend_two_pane.py:370` `test_tc516_legend_body_is_the_two_pane_wrapper` | pass | All **9** shipped `#legend_body`-rooted query sites re-checked non-empty (C-38) |
| US-072-2 | HLR-072-5 | LLR-072-5.2 | TC-518 *(arm covering the wide rule)* + AT-216 clauses 0/3 | `s19_app/tui/styles.tcss:1544-1565` | `tests/test_legend_two_pane.py:649` `test_tc518_key_pane_never_uses_height_auto` | pass | Widened at the review fold: regex instead of a whitespace-exact substring, plus a 120x30 probe (finding **F2**) |
| US-072-2 | HLR-072-6 | LLR-072-6.1 | TC-517 | `s19_app/tui/screens.py:1036` (`_LEGEND_NARROW_WIDTH`), `:1247-1280` (`_apply_width_regime`), `:1282-1288` (`on_mount` / `on_resize`) | `tests/test_legend_two_pane.py:563` `test_tc517_width_regime_flips_class_and_pane_order` | pass | Asserts the class **and** the document order flip at the breakpoint; the TC quotes the constant, never the literal `120` |
| US-072-2 | HLR-072-6 | LLR-072-6.1 | TC-520 | `s19_app/tui/screens.py:1247-1288` (the reorder is what moves the tab cycle) | `tests/test_legend_two_pane.py:756` `test_tc520_legend_focus_traversal_is_pinned_in_both_regimes` | pass | Allocated **outside** the reserved `TC-510..519` block — §6.5 **D-2**. Pins three properties, not a literal chain |
| US-072-2 | HLR-072-6 | LLR-072-6.2 | TC-518 | `s19_app/tui/styles.tcss:1575-1588` (three `#legend_dialog.legend-narrow` rules) | `tests/test_legend_two_pane.py:649` | pass | Excludes the degenerate `height: auto` key regime that starves the card to 1 row |
| US-072-2 | HLR-072-7 | LLR-072-7.1 | TC-519 | `s19_app/tui/legend.py` — **unmodified**; `screens.py:1234-1235` calls `_render_card()` / `_render_key()` once each and re-parents | `tests/test_legend_two_pane.py:700` `test_tc519_legend_module_unchanged_vs_main` | pass | `git diff origin/main -- s19_app/tui/legend.py` empty; reviewer confirmed the node reddens on an appended byte |
| US-072-3 | HLR-072-8 | LLR-072-8.1 | *(AT-219 is itself the live-oracle census — no separate TC, per §5.2)* | `s19_app/tui/crc_designer_view.py:125-133` (tuple), `:1136` (`_recompute` consumes it **by name**) | `tests/test_crc_designer_view.py:1593` `test_recompute_surface_ids_are_the_live_markup_census` | pass | Named lookups, never a positional unpack — re-gate **N-5** |

---

## 1b. Behavioral chain (black-box)

Every AT drives the shipped surface through the real binding — `pilot.press("0")` for the CRC
Designer, `k` for the Legend — never a `.focus()` proxy (C-16).

| US | AT | Shipped surface | Observed outcome | Status |
|----|----|-----------------|------------------|--------|
| US-072-1 | **AT-213** `tests/test_crc_designer_view.py:1451` | CRC Designer view, 120x30 | `#crc_field_refin` and `#crc_field_refout` share one row band; the `out` `Label` renders strictly between their x-bands; driving `refin` `True → False` through the real `Switch` path moves `#crc_custom_vector_result` **`0xCBF43926` → `0x1898913F`** (the exact transition, not a `!=`; `0xCBF43926` is the externally published CRC-32 check value) | pass |
| US-072-1 | **AT-214** `tests/test_crc_designer_view.py:1802` | CRC Designer view, 120x30 | Derived subject set (`screen.query(Switch)` filtered `region.area > 0`) resolves **2** widgets and is asserted non-empty; **0** vertically-abutting `Switch` pairs. **C-40 counterfactual executed:** whole-file restore of `crc_designer_view.py` from `origin/main` on a private copy → RED on AT-214's own assertion line (`:1852`), reporting exactly `('crc_field_refin','crc_field_refout')` — M-1's predicted pair `c01`. Control arm on the same copy restored to HEAD → GREEN. Shared worktree byte-identical before/after (`2121d331…`) | pass |
| US-072-1 | **AT-215** `tests/test_crc_designer_view.py:1527` | CRC Designer view, 120x30 | `#crc_kat_verdict` resolves under `#crc_algorithm_fields`; `123456789` present on screen in that row; driving `#crc_field_check` to `0x00000000` through a real `Input.Changed` flips the verdict `✓ MATCH → ✗ MISMATCH`, with the two near-misses (`○ NO-EXPECTED` on a cleared field, `Invalid parameters: …` on non-hex) excluded explicitly; `query("#crc_live_verify")` **empty** — the discriminating negative | pass |
| US-072-2 | **AT-216** `tests/test_legend_two_pane.py:179` | Legend modal (mac view), 120x30 | Key row located by its `{legend-row, sev-warning}` classes inside `#legend_key_pane` (containment on the meaning string, not equality); pane `Region(70,6,43,15)` contained in `#legend_body` `Region(6,6,107,15)`; `scroll_offset == (0,0)` and `max_scroll_y == 0`. **Clause 0, added at the review fold (F1):** `key.region.x (70) >= card.region.right (70)` and both panes on `region.y == 6` — the side-by-side property. **Two oracle mutations executed:** `display: none` → RED (on clause 2b only, reported as such); removing the three `legend-narrow` prefixes → RED with the panes stacked at card `y=6` / key `y=13` | pass |
| US-072-2 | **AT-217** `tests/test_legend_two_pane.py:489` | Legend modal (mac view), 80x24 | Key `Region(6,6,68,4)` above card `Region(6,10,68,5)`; card height **5** satisfies the non-vacuity tooth `>= 2`; `key.max_scroll_y` **6** (mac) / **7** (map) and the last key row scrolls into a non-empty on-screen region. **Both declared teeth falsified independently:** `height: auto` on the narrow key → card collapses to `height=1`, clause 2 alone fails; `move_child` → no-op → clause 1 alone fails while the class still flips | pass |
| US-072-2 | **AT-218** `tests/test_legend_two_pane.py:419` — **labelled a REGRESSION PIN, not a gate** | Legend modal (mac + map), 120x30 | `#legend_mac_warning_sample` carries its inline `orange3` span read from `render().spans` (not `render_line(0)`, which reads the theme foreground — C-37); map band-key rows render in the **key** pane and still report `_render_markup is False`; all **9** `#legend_body`-rooted query sites resolve non-empty. Its subject is the *unchanged* pipeline, so it is invariant under this batch by construction — kept because it is the only thing that would catch an accidental data-layer edit | pass |
| US-072-3 | **AT-219** `tests/test_crc_designer_view.py:1593` | CRC Designer view, 120x30 | **Clause 1 (the PIN, labelled as such):** iterating the live module tuple, all **6** surfaces report `_render_markup is False`; `len(tuple) >= 6`. **Clause 2 (the GATE — the only clause FALSE before the hoist):** a bogus id monkeypatched into the tuple makes `_recompute` take its `NoMatches` early return and the live surfaces do not update. **Counterfactual executed:** with the pre-batch `_recompute` body re-bound onto the class, the bogus id changes nothing and the verdict moves `✓ MATCH → ✗ MISMATCH` — failing on the assertion line, proving the tuple would be declared but not consumed | pass |

---

## 1c. Withdrawn · retired · not-encoded nodes (explicit, not omitted)

> A node that disappears without a disposition is not a decision (C-40 limb 2). All six live here
> with their basis and where the residue went.

| Node | Kind | Disposition | Basis (executed) | Where the residue went |
|---|---|---|---|---|
| **HLR-072-4** — Select chrome cap (`#crc_designer_panel Select { height: 3 }`) | HLR | ❌ **WITHDRAWN at revision 2** — §6.5 **W-1**. No LLR, no TC, no AT. `AT-219` was **reallocated** to HLR-072-8 | **M-4:** at the bench's 12-col pane width, `height: 3` renders `CRC-32/ISO-HDLC` as **`CRC-32/I`** — 8 of 15 characters, **no ellipsis and no overflow marker** — and clips the bottom border on **4 of 6** Selects. Minimum legible height at that width is 5 (text) / 6 (text + intact box), i.e. exactly what `height: auto` already produces. The withdrawal rationale's own figure was also wrong: measured heights are `6/4/4/4/3/3`, so "5-6 rows" described one control, not the set | Verified absent from the shipped diff: the `styles.tcss` diff contains **no** line matching `select`. Carried to `BACKLOG-CODE.md` **with its measurement**; recorded in `REQUIREMENTS.md` `R-TUI-100` under "what this requirement deliberately does NOT claim" (a) |
| **G-2** — design guard: "a `Switch`'s state is legible as a glyph/word, not slider position alone" | design guard (`HANDOFF-PLAN.md:121`) | ❌ **RETIRED at revision 2** — §6.5 **R-1**. Never encoded; its proposed discharge (an AT-213 clause asserting the CRC vector text changes) was withdrawn with it | The rendered state word is **Variant A's** mechanism (`NOTES.md:66`); the operator chose **Variant B**, whose verdict row records "Steals from: —" (`:104`). Encoding A's guarantee against B's design is a category error. The proposed discharge also asserted a *different* proposition — that the CRC value moves when any algorithm parameter changes — which is handler **wiring**, already covered at `tests/test_crc_designer_view.py:414-415` | **Carried to backlog, not dropped.** The separability defect the operator actually reported is closed by HLR-072-1 + HLR-072-3. Recorded in `R-TUI-100` under "does NOT claim" (c) |
| **AT-B59-05** — `test_verdict_hero_center_aligned_in_hero_row` (`tests/test_crc_designer_view.py:1003-1047`) | acceptance test (batch-59) | ❌ **DELETED** by LLR-072-2.4. Ledger `D = 1` | All five of its assertions are falsified by Variant B **by design** — the hero tile it pins is the control the operator reported as not earning its placement | **Deleted, never edited into passing.** A retirement comment stands in its place. The surviving obligation (the verdict stays present, correctly parented, reachable) is **re-derived into AT-215** clauses 1/2/4 |
| **batch-59 US-L3 / HLR-L3 / LLR-L2.3+L3.1** — the verdict-hero requirement | requirement (batch-59) | ❌ **RETIRED**, §6.5 **A-1**, Before/After recorded | Parent-HLR re-read: batch-59's HLR-L3 exists to make the verdict *findable*. Demoting it to an annotation of the field it validates preserves findability and improves attribution | Superseded by HLR-072-2, now registered in `REQUIREMENTS.md` as part of **`R-TUI-100`** |
| **G-1** — control separability | design guard (`HANDOFF-PLAN.md:120`) | ✅ **ENCODED, re-scoped** → HLR-072-3 / AT-214 / TC-514 | The original scope (any two abutting focusables) is FALSE of **16** pairs and this change fixes **1**; a same-widget-class rule is **7 pre → 6 post** — RED before *and* after, which is not a gate. `Switch`-only is **1 pre → 0 post**, the only satisfiable rule of the three (M-1) | Scope stated openly in HLR-072-3 and in `R-TUI-100` so the narrow rule does not read as special-pleading |
| **G-3** — hero extent / the 6:1 law | design guard (`HANDOFF-PLAN.md:122`) | ⚪ **NOT ENCODED**, and the first reason given for that was itself wrong | **M-8:** `#crc_coverage_window` area **305** vs two identical `30x4` = **120** tiles. Retiring one tile and giving its space to the other changes the bounded quantity by **zero**. Worse, G-3 is **already FALSE on `main`** — the measured ratio is **2.54:1** against a 6:1 law | A **pre-existing, unrelated violation** this batch neither causes nor worsens; encoding it here would fail batch-72's gate on batch-59's geometry. Carried to backlog **with the 2.54:1**; recorded in `R-TUI-100` under "does NOT claim" (b) |
| **G-4** — colour key reachable in ≤1 interaction at both sizes | design guard (`HANDOFF-PLAN.md:123`) | ✅ **ENCODED, split by regime** | Measurement is why it splits: at 120x30 the key fits (0 interactions — AT-216 `max_scroll_y == 0`); at the floor the content budget is **9** rows against a **10 (mac) / 11 (map)**-row key, so 0 is unachievable under any non-degenerate CSS (AT-217 clause 3 — 1 interaction) | Both halves live and green. TC-520 additionally pins that the key stays *keyboard*-reachable at the floor |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | **3** |
| Covered user stories (both chains complete) | **3 (100%)** |
| Total HLR declared | **8** (HLR-072-1, 2, 3, 4, 5, 6, 7, 8) |
| HLR withdrawn | **1** (HLR-072-4 — §6.5 W-1) |
| HLR live | **7** |
| Implemented HLR | **7 of 7 (100%)** |
| Total LLR | **12** (1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 5.1, 5.2, 6.1, 6.2, 7.1, 8.1) |
| Implemented LLR | **12 (100%)** |
| Acceptance tests (`AT`) | **7** — AT-213, 214, 215, 216, 217, 218, 219 |
| Test cases (`TC`) | **11** — TC-510…TC-520 |
| Total nodes added (`A`) | **18** |
| Nodes deleted (`D`) | **1** (AT-B59-05) |
| Node pass / fail / pending | **18 / 0 / 0** |
| Counterfactuals / oracle mutations executed **within the batch** | **6**, enumerated below. `04-validation.md` §3 tables **4** of them plus one control arm — see gap **G-072-01** |
| ↳ 1 — AT-216 clause 2b | `display: none` on the key pane → RED (`Region(0,0,0,0)` not inside the body). Validation **CF-1** |
| ↳ 2 — AT-216 clause 0 | the three `legend-narrow` prefixes removed → wide regime stacks (`card y=6` / `key y=13`); pre-fold all 8 nodes GREEN, post-fold RED. Validation **CF-2** |
| ↳ 3 — AT-214 | whole-file revert of `crc_designer_view.py` from `origin/main` on a private copy → RED on its own assertion line at `:1852`. Validation **CF-3**, with control arm **CF-3b** |
| ↳ 4 — AT-217 clause 2 | narrow key pane `height: 1fr → auto` → card starved to `height=1`, clauses 1 and 3 stay GREEN. Validation **CF-4** |
| ↳ 5 — AT-217 clause 1 / TC-517 | `move_child` replaced by a no-op → the class still flips and the panes still stack; **only the order is wrong**. `increment-002.md` §4(b). **Not in `04-validation.md` §3** |
| ↳ 6 — AT-219 clause 2 | the pre-batch `_recompute` body re-bound onto the class → the bogus id is inert and the verdict moves `✓ MATCH → ✗ MISMATCH`; fails on its own assertion line. `increment-003.md` §4. **Not in `04-validation.md` §3** |
| Independent falsification runs by the increment-1/2 reviewer | **16** — 15 nodes/clauses redden on a named mutation; **1 axis did not**, which became finding **F1** |
| Test ledger | `2379 − 1 + 18 = **2396**` — reconciled two ways |
| Gate suite | **2370 passed, 2 skipped, 21 deselected, 3 xfailed, 29 snapshots passed, GATE_EXIT=0** — the orchestrator's own run (C-25), `1606.71s`. Distinct from `increment-004.md` §4.5's run (`1455.16s`), which reports identical counts |
| Snapshots regenerated | **0** |
| Frozen-engine diff vs `origin/main` | **empty**, both guard arms green (C-27) |

---

## 3. Detected gaps

> None of these is an unfilled chain row. They are known, measured, dispositioned residue —
> recorded so the next batch inherits facts rather than surprises.

| ID | ↔ `04-validation.md` | Type | Description | Proposed action |
|----|----|------|-------------|-----------------|
| **G-072-01** | *(new here)* | artifact discrepancy | `04-validation.md` §3 opens *"Four mutations were executed in this batch"* and tables CF-1…CF-4 (+ control arm CF-3b). **Two further mutations were executed and are absent from that table:** the `move_child` no-op (`increment-002.md` §4(b) — the run that proves CSS can stack but cannot order) and the pre-batch `_recompute` re-bind (`increment-003.md` §4 — AT-219's gate arm, the only clause FALSE before the hoist). Both carry pasted transcripts failing on their own assertion lines | Add both rows to `04-validation.md` §3 at close, or restate its opening count as "four **whole-file / stylesheet** mutations". The undercount does not change any verdict — it understates the evidence |
| **G-072-02** | **G-002** | no coverage (review **F4**, LOW, self-reported before it was reviewed) | `#legend_body { overflow: hidden }` (`styles.tcss:1549`) is pinned by nothing — reverting it to `overflow-y: auto` leaves all nodes GREEN. The consequence is the three-nested-scroll-context state LLR-072-5.2 exists to prevent; at current content sizes the symptom is invisible | One line in TC-518's stylesheet scan, **or** a backlog entry carrying this measurement. Author's call — it did not block the gate |
| **G-072-03** | **G-003** | partial coverage (review **F3**, LOW) | `on_mount`'s width argument is unpinned: mutating **only** `on_mount` to `self.size.width` leaves every node GREEN, because a `Resize` arrives immediately after mount and `on_resize` re-applies the correct regime. Mutating `on_resize`, or both, correctly reddens TC-516 **and** TC-517 | Optional TC hardening (sample before the first pause, or monkeypatch `on_resize` to a no-op). Explicitly marked "do not block on it" by the reviewer |
| **G-072-04** | **G-001** | documentation (review **F5**, LOW) | AT-218's clause 4 ("the three legend test files stay green") is a gate-run property — **discharged** at increment-001 §4 (239 passed), increment-002 §4 (242 passed), increment-004 §4.3 (108 passed) and the Phase-4 run. Only its labelling is missing: neither the module docstring nor the node's docstring (`:420-430`) says the clause is out-of-node | One sentence in the test docstring |
| **G-072-05** | *(not in validation)* | documentation (review **F6**, LOW) | `on_resize` discards `event` and reads `self.app.size.width`; the App-level sibling at `app.py:6212` *does* use `event.size.width`, so a future "cleanup" would look like a fix | Append the reason to the one-line docstring |
| **G-072-06** | *(not in validation)* | weak-but-redundant coverage (review table, ⚠️ rows) | AT-216 clause 1 (the anchor) and clause 3 (`max_scroll_y == 0`) were not independently falsified — clause 1 is redundant with TC-515, and clause 2a fires before clause 3 under every mutation tried | Accepted as-is. Recorded so nobody later reads the reviewer's ⚠️ as a ✅ |
| **G-072-07** | **G-004** | unmeasured axis | **The CRC screen at 80x24 was never measured**, by this batch or its predecessors. `R-TUI-100` states this explicitly and claims no floor behaviour. The Self-test row is tight at 120x30 (label 13 + `123456789` 10 + verdict; `○ NO-EXPECTED` is 13 chars and the fault string is long); a `Static` wraps rather than truncating, so the M-4 silent-truncation failure mode does not apply — but that is an argument, not a measurement | Measure the CRC bench at the floor in a future batch before any CRC floor claim is made |
| **G-072-08** | *(not in validation)* | no coverage, accepted | `.crc-field-sublabel` is a new CSS class pinned by no test **as a class name**. Its two effects *are* asserted — geometrically by AT-213 clause 2 (the label's x-band) and structurally by TC-510 (the label inventory) | None. Class names carry no test dependency in this codebase (C-26 census: 0 hits) |
| **G-072-09** | **§10.1** | backlog reconciliation owed | Four carries: **W-1** Select affordance density (with M-4), **G-3** the pre-existing 2.54:1 hero extent (with M-8), **G-2** the switch state-word guarantee, and the correction of `BACKLOG-CODE.md` line 153, whose claim that *"any change will drift the CRC snapshot cells"* was measured **FALSE** (P-2 — 0 CRC snapshots exist on disk) | Batch close step. All four are already traceable from `REQUIREMENTS.md` `R-TUI-100`, not only from this directory |
| **G-072-10** | **G-008** | pre-existing, not introduced | `ruff format --check` reports both touched test files would be reformatted — **and reports the same two files at `HEAD` with the changes stashed**. `ruff check` passes. Repo-wide `ruff check` shows 7 pre-existing findings in files this batch does not touch | None. `ruff format` is evidently not enforced in this repo; stated rather than passed over |
| **G-072-11** | **G-005** | guard/AT overlap, openly stated | AT-214 and TC-514 **coincide with AT-213 today**: only 2 `Switch` widgets exist and both are in the pair row, so the separability guard currently polices exactly the pair AT-213 already asserts | None. This is HLR-072-3's own admission. The subject set is *derived*, so a third `Switch` is policed with no test edit, and TC-514 reddens the moment one is constructed elsewhere |
| **G-072-12** | **G-006** | known tripwire | AT-216 has **one row of slack** — key content is 14 rows in a 15-row pane, both views | Already mitigated at the **cause** by clause 3 (`max_scroll_y == 0`), which fails before the symptom appears |
| **G-072-13** | **G-007** | scope note, informational | For **four** of the six `_recompute` sinks, AT-219 observes the **markup flag**, not the rendered value; their content oracles are pre-existing batch-58/59 nodes | None — correct for a markup-safety story. Recorded so a later reader does not over-read AT-219's coverage |
| **G-072-14** | **§10.1 item 4** | pre-existing, not a regression | The Escape key does not dismiss `LegendScreen` (`BINDINGS = ['tab','shift+tab','ctrl+c']`) — measured at `tabs=0` on the pre-batch tree too | None in this batch. Noted only so it is not mistaken for new |

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| **new** | `REQUIREMENTS.md` **`R-TUI-100`** | **Registers the CRC Designer view in `REQUIREMENTS.md` for the first time.** Batch-59's bench layout (merged #113) was never registered: executed greps at Phase 2 returned **0** hits for `crc_live_verify`, `verdict hero`, `crc_bench` and `Designer`. Revision 1 pointed at a row that does not exist — corrected as §6.5 **A-8**, changing the obligation from *amend* to *add*. Next free id measured (`R-TUI-099` was the max, from batch-70) |
| **modified** | `REQUIREMENTS.md` **`R-LEGEND-MODAL-001`** | `#legend_body` is now the **two-pane wrapper** holding `#legend_card_pane` + `#legend_key_pane`. Its `LegendScreen` code ref was also stale (`:474` no longer addresses the class) and is refreshed to `:1039` |
| **modified** | `REQUIREMENTS.md` **`R-LEGEND-GEOMETRY-001`** | Its Code line documented `#legend_body { height: 1fr; overflow-y: auto }`. The `overflow-y` has moved to the panes and the body is now `overflow: hidden`. Recorded as a **Before/After amendment block**, per the convention already used at `REQUIREMENTS.md:439`, `:464`, `:4244` — a named CSS declaration moving to a different element is recorded, not edited silently |
| **closed** | batch-59 US-L3 / HLR-L3 / LLR-L2.3+L3.1 | Retired by HLR-072-2 (§6.5 **A-1**), Before/After recorded |
| **closed** | `AT-B59-05` | Deleted (LLR-072-2.4). Ledger `D = 1` |
| **withdrawn** | HLR-072-4 | §6.5 **W-1**, on measurement (M-4) |
| **retired** | design guard **G-2** | §6.5 **R-1** |
| **modified** | HLR-072-3 scope note + `00-measurements.md` M-1 | §6.5 **D-1**: both stated *"exactly one `Switch(` construction site"* as present-tense fact. True of `origin/main`; **falsified by this batch's own success** (LLR-072-1.2 deleted the helper holding that one call, LLR-072-1.1 inlined both toggles → 2 sites at `:325`, `:327`). Corrected at `d13bb1c` to the invariant the number stood for: **single-module confinement** |
| **new** | `TC-520` | Allocated **outside** the reserved `TC-510..519` block (§6.5 **D-2**); §5.2 row added at the same fold |
| **survived unedited** | `AT-B59-03` / `AT-B59-08` | Variant B keeps `#crc_bench_c1/c2/c3` and the Algorithm group is still c1's only child, so both computed 3-column comparisons hold. No edit was needed, so the "STOP and report" branch was never taken |

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-072-1** (CRC Designer, Variant B) → HLR-072-1, HLR-072-2, HLR-072-3 → LLR-072-1.1, 1.2, 2.1, 2.2, 2.3, 2.4 → **AT-213, AT-214, AT-215** · TC-510, TC-511, TC-512, TC-513, TC-514
  *(also touched, and withdrawn: HLR-072-4)*
- **US-072-2** (Legend modal, Variant B) → HLR-072-5, HLR-072-6, HLR-072-7 → LLR-072-5.1, 5.2, 6.1, 6.2, 7.1 → **AT-216, AT-217, AT-218** · TC-515, TC-516, TC-517, TC-518, TC-519, TC-520
- **US-072-3** (markup-safety regression guard) → HLR-072-8 → LLR-072-8.1 → **AT-219**

### 5.2 By code file

- `s19_app/tui/crc_designer_view.py` → LLR-072-1.1, 1.2, 2.1, 2.2, 8.1 → AT-213, AT-214, AT-215, AT-219, TC-510, TC-511, TC-512, TC-514
- `s19_app/tui/screens.py` → LLR-072-5.1, 6.1, 7.1 → AT-216, AT-217, AT-218, TC-515, TC-516, TC-517, TC-520
- `s19_app/tui/styles.tcss` → LLR-072-1.1 (`.crc-field-sublabel`), 2.3 (`.crc-hero` retired), 5.2, 6.2 → TC-513, TC-518, AT-216, AT-217
- `s19_app/tui/legend.py` → LLR-072-7.1 → TC-519 *(the requirement is that this file does **not** change)*
- `REQUIREMENTS.md` → §5.3.5 → `R-TUI-100` (new), `R-LEGEND-MODAL-001`, `R-LEGEND-GEOMETRY-001`

### 5.3 By increment

| Increment | LLRs | Nodes added (`A`) | Ledger |
|---|---|---|---|
| **001** — Legend two-pane, wide regime | 5.1, 5.2, 7.1 | AT-216, AT-218, TC-515, TC-516, TC-519 (**5**) | — |
| **002** — Legend floor regime, key first | 6.1, 6.2 | AT-217, TC-517, TC-518 (**3**) | `2379 + 8 = 2387` |
| *(review fold `0169108`)* — closes **F1** HIGH + **F2** MEDIUM | — | AT-216 clause 0; TC-518 widened (**0** new nodes) | 2387 |
| **003** — CRC Designer Variant B | 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 8.1 | AT-213, AT-215, AT-219, TC-510…513 (**7**), **`D=1`** | `2387 − 1 + 7 = 2393` |
| **004** — G-1 guard, focus pin, `REQUIREMENTS.md` | *(guard over 1.1)* + 6.1 | AT-214, TC-514, TC-520 (**3**) | `2393 + 3 = 2396` |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-07-30-batch-72` |
| Branch | `claude/batch-72-design-defect-634a67` @ `d13bb1c` |
| Artifact language | English |
| Closing date | 2026-07-30 |
| Phase-1 iterations | **2** (revision 1 → revision 2 after 9 blockers / 12 majors / 7 minors; revision 3 after the Phase-2 re-gate) |
| Phase-3 increments | **4**, plus one independent code review that **BLOCKED** on a HIGH finding and one fold commit that closed it |
| Requirements withdrawn / retired during review | **2** (HLR-072-4; design guard G-2) — both on executed measurement, both carried to backlog |
| Validation passed | **yes — PASS, no blocker** ([`04-validation.md`](../04-validation.md) §11). 18/18 nodes green; gate suite `2370 passed, 2 skipped, 21 deselected, 3 xfailed`, 29 snapshots passed, `GATE_EXIT=0` |
| Frozen guards | both arms green; frozen-set diff vs `origin/main` empty |
| Snapshots regenerated | **0** |
| Synced to Obsidian | *(pending — batch close step)* |

### Evidence checklist — `docs-writer`

- [x] **Audience and purpose declared at the top** — §0 states the state of both chains before any table; the deviation from the template is declared in the header.
- [x] **Structure follows the template** — sections 1, 1b, 2, 3, 4, 5, 6 as in `~/.claude/templates/dev-flow/traceability-matrix.md`. **Justified deviation:** §1c added for withdrawn/retired nodes, and §5.3 added for the per-increment ledger.
- [x] **Code/CLI snippets actually run** — no new commands are introduced here; every quoted figure is copied from an executed transcript in `00-measurements.md`, the increment packets, or `increment-001-002-review.md`.
- [x] **Assumptions listed** — none load-bearing remain: `04-validation.md` landed during writing and its figures were reconciled against `increment-004.md` §4.5 (identical counts, different run). The one place the two artifacts disagree is raised as gap **G-072-01** rather than blended away.
- [x] **Risks / limitations called out** — §3, fourteen entries, each cross-referenced to `04-validation.md` §10's own gap id where one exists.
- [x] **Next steps stated** — §3 "Proposed action" column; §6 sign-off row for the Obsidian sync.
- [x] **Diagrams included where flow is non-trivial** — [`diagrams/`](diagrams/): Legend widget tree before/after, CRC bench before/after, and the two runtime mechanisms.
- [x] **No invented APIs / version numbers / metrics** — file:line values re-read from the branch tip; every count traced to its transcript. Where a number could not be verified from source material it is marked as a gap, not estimated.
