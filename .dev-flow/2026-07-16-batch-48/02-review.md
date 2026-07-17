# 02 — Phase-2 Cross-Agent Review — batch-48 (Patch Editor BIG)

> architect ∥ security-reviewer over `01-requirements.md` + `01b-qa-strategy-and-verification.md`.
> Consolidated by the orchestrator. **VERDICT: BLOCK → folds applied → re-gate.**
> **4 blockers (1 HIGH security) · 8 majors · 7 minors.** All bounded; one reconciliation pass fixes them.
> No re-architecture. Both reviewers independently hit the same two defects (id collision · JSON surface).

## BLUF
- **security-reviewer: BLOCK (1 HIGH).** *"The batch has its threat model backwards."* The paste buffer it set out to defend is **safe by construction**; the entries table it treats as a styling change is a **live, exploitable `Text.from_markup` sink at HEAD** that this batch rewrites without a gate test.
- **architect: BLOCK (3 blockers, 4 majors).** The two Phase-1 docs *are not describing the same batch* (id spaces collide → **no `→ 01b` pointer resolves**, C-18 unachievable); the glyph column is the wrong shape; the provenance stamp fingerprints the document while the check run depends on the **image**.
- Credit where due (both reviewers): `shall`/`should` is clean (**0** modal `should` in any statement); the A2/A5/A8 assumptions are grep-verified, not asserted; C-29's reachable-under-scroll is inherited **at draft** (a phase earlier than batch-46 managed); the `textual[syntax]` strike is correct.

---

## BLOCKERS

### BL-1 (security F1, **HIGH**) — Threat model inverted: the entries table is a live injection + crash sink; the batch rewrites it with no gate test
- **Paste buffer = SAFE BY CONSTRUCTION** (verified in installed `textual==8.2.8`): `TextArea.get_line` (`_text_area.py:1328`) returns `Text(line_string, end="", no_wrap=True)` — the literal constructor, **never `from_markup`**; styles resolve via `theme.syntax_styles.get(name)` (`:1501-1503`) and an unknown token is **skipped** → payload text *cannot name a style*.
- **Entries table = LIVE SINK**: `change_service.py:1402-1425` sets `value_text = entry.value` — the **raw change-set JSON string, unmodified** — and `refresh_entries` (`screens_directionb.py:3244-3252`) passes it to `add_row()` as a bare `str`; Textual's `default_cell_formatter` (`_data_table.py:202-222`) sets `possible_markup=True` → **`Text.from_markup(content)`**. Proven exploitable:

  | payload in `entry.value` | result |
  |---|---|
  | `[red]PWNED[/red]` | `plain='PWNED'` + `Span(0,5,'red')` — content mangled, style injected |
  | `[link=http://evil]click[/link]` | `Span(0,5,'link http://evil')` — **link injected from file data** (batch-43 class) |
  | `[/nope]` | **raises `MarkupError`** → crashes `refresh_entries` |

- **Why it blocks:** pre-existing, but **this batch rewrites exactly these lines**, and §2.4-4 ("the pasted JSON is the batch's real security surface") **actively steers Phase 3 away from it**. The partial-fix trap is concrete: LLR-075.2 enumerates **3 roles** (kind/address/value) for **5** columns → `status_text` + `linkage_text` get no role → the natural implementation converts 3 and leaves 2 bare → **sink still live**. LLR-075.2's generic clause ("*every* file-derived cell … as `Text`") **contradicts its own 3-role enumeration**, and no AT arbitrates.
- **FOLD:** (a) promote the safety clause to a first-class **gate-blocking C-17 LLR**: *all* cells `Text`-constructed regardless of role assignment; (b) **NEW gate-blocking AT** — hostile payload in `entry.value` → verbatim in the cell's `Text.plain`, no payload-derived span, **no `MarkupError`**; (c) correct §2.4-4 + HLR-079's rationale — the paste buffer is **not** the only untrusted surface and is in fact the safe one.

### BL-2 (architect B-1 = security F2) — The two docs use the SAME ids for DIFFERENT things
`D-2` split US-P1 into HLR-075 (render) + HLR-076 (chips); `01b` never got the split → everything from US-P2 on is **off by one**:

| | `01-requirements.md` | `01b` |
|---|---|---|
| `R-TUI-079` | JSON colouring | **the card (HEADLINE)** |
| `AT-079b` | JSON structure | **read-only card proof** |
| `AT-079c` | **gate-blocking C-17** | benign card-unmapped boundary |
| `AT-081a` | history-strip position | **gate-blocking C-17** |
| glyph column | `AT-077a-d` | `AT-076a-d` |
| C-29 reachability | `AT-080d` | `AT-082` |

Every `Executed verification` / `Numeric pass threshold` in §3/§4 is `→ 01b`; **not one resolves.** C-18 unachievable; §5.2's chain broken end-to-end. **This already misfired in the wild** — the orchestrator's own Phase-2 security brief used 01b's retired numbering.
- **FOLD:** `01-requirements.md` §5.2 is **canonical**; `01b` re-numbers onto it in the same pass; reconcile the AT **count** (23 vs 19) and node paths (01b: one file; §5.2: seven). Log in §6.4.

### BL-3 (architect B-2) — The glyph **column** is the wrong shape; **FOLD it into the `Kind` cell**
- Spec mandates a **leading column** (LLR-077.4) → shifts `Coordinate(row,1)`=address / `(row,2)`=value. The spec **never acknowledges qa T-1** (grep of 01-requirements for `T-1`/`Coordinate`/`prepend`/`append` → **0 hits**) while 01b calls it *"the batch's sharpest regression risk"*. Readers: `test_tui_patch_editor_v2.py:2578` (docstring pins the order as contract) + `:3208-3209`.
- **Batch-47 precedent verified in source** (not taken on framing): A2L `app.py:9548` — *"the name cell (**index 0**) carries the leading in-image glyph"*; MAC `app.py:9223-9226` — *"**Fold** a leading status glyph … into the Tag cell **as its own span**"*. **Both keep the column count unchanged.**
- **Folding wins on five axes:** T-1 dissolves (only cols 1-2 are index-read; col 0 unasserted → **zero** edits to the 32-hit census file) · **Amendment C becomes unnecessary** (the 6-column-at-80 deficit never exists) · C-11 idiom conformance · LLR-075.2 already does the work (glyph rides as its own span) · **no redundancy with `Status`** — `status_text` is the **containment** verdict (`MemoryStatus` INSIDE/PARTIAL/OUTSIDE/…), the glyph is the **check-run** verdict; different semantics + lifetimes, and folding puts visual distance between them.
- *The tell:* the spec had to **pre-commit Amendment C** for "6 columns don't fit at 80×24" — the design paying rent on a choice it shouldn't have made.
- **FOLD:** restate HLR-077 + LLR-077.4 (*"the `Kind` cell shall carry a leading glyph span; `_ENTRIES_COLUMNS` unchanged"*); **retire Amendment C**; §6.5's R-TUI-046 *verdict* holds but its **rationale** becomes the fold precedent. ATs unaffected (01b's assert glyph content + ordered position, never column count).

### BL-4 (architect B-3) — Provenance stamp under-scoped: it fingerprints the **document**, the check run depends on the **image** (an MJ-1-class defect)
- `change_service.py:1258-1259`: `result = self.check_runner(self.document, mem_map, ranges, mac_records, a2l_tags)` — `actual_bytes` is read **from `mem_map`**. And `app.py:1171` constructs `ChangeService()` **once at app init**; it is never rebuilt on file load; resets remain only `undo:474`/`redo:506`.
- **⇒ Run checks against image A (all `✓`) → load image B → document unchanged → signature matches → glyphs still render, describing image A.** The exact wrong-answer class LLR-077.2 exists to prevent, reachable via the most routine action in the app. §2.5 A1 ("runs over `self.document`") is true but **incomplete** — that's what let it through.
- **FOLD:** widen to `(document_signature, image_generation)`. Cheapest exact mechanism: an `app.py`-owned **monotonic token** bumped in `_apply_loaded_file`, pushed alongside `mem_map` (those sites change anyway for LLR-080.2) — O(1), no hashing a large map. **`id(mem_map)` is unsafe** (id reuse after GC). `mac_records`/`a2l_tags` need **no** covering (they drive `linkage`, not `result`) — state it so Phase 3 doesn't over-build.

---

## MAJORS

- **MJ-1 (arch M-1) — writer-census misses a 4th `refresh_entries` site.** Grep returns **four**: `app.py:2049 · 2255 · 3884` **+ `screens_directionb.py:2976`** (a self-call inside `on_mount:2962`). If LLR-080.2's retain is `self._mem_map = mem_map` unconditional, that self-call **nulls it**. Benign today *only* by ordering — an unstated invariant, and the MJ-1 shape. **FOLD:** add the row + disposition; make LLR-080.2 state retain semantics (sentinel default ⇒ preserve, or an explicit clobber-is-safe + test).
- **MJ-2 (arch M-2) — the pre-committed relaxation would silently VOID gate-blocking AT-080d.** LLR-080.6's relaxation = "regime-conditional under `width-narrow`" — which is **<120, so it fires at 80×24**. AT-080d asserts *"at 80×24 **with the card mounted**, every docked button reachable"* → if the amendment triggers, the card isn't mounted, the **B2 gate passes vacuously**, and the headline feature ceases to exist at the floor. **FOLD:** state AT-080d's post-amendment form NOW (120×30 card-mounted reachability holds; 80×24 card absent **AND** reachability holds).
- **MJ-3 (arch M-3) — HLR-076 over-claims vs LLR-076.2.** Parent: *"the **20** docked buttons render as chips"*; child maps **5 of 9** containers (4 left `assumed`). **FOLD:** map all 9, or narrow HLR-076 to the structural invariant (*every docked button carries a chip class AND ≥3 distinct groups present*) — also C-29-safe (m-1).
- **MJ-4 (arch M-4 = security F3) — the JSON-colouring SURFACE is unreconciled.** LLR-079.1 = in-place `TextArea._highlights`; 01b's ATs are written against a **separate preview widget** (AT-078a "the **preview**'s `Text.spans`"; AT-081a "the **preview**'s `Text.plain`"). Different widgets, geometry, and C-17 arguments — Phase 3 cannot implement both. **➜ OPERATOR DECISION (AskUserQuestion 2026-07-16): IN-PLACE via `TextArea._highlights`.** Rationale: only route that works at the ~5-content-row 80×24 floor; security **verified** it C-17-safe by construction; failure mode cosmetic-only behind a feature-detect. **FOLD:** align both docs to in-place; **the fallback path must itself be tested** (force feature-detect false → unstyled + no raise) since CI is pinned at 8.2.8 and can never exercise degradation naturally.
- **MJ-5 (security F3) — the C-17 AT's observation point is wrong for the chosen design.** Both docs presume a preview `Text.plain`; in-place colouring has none. `ta.text` is **tautological** (returns the document string; passes even if rendering is unsafe). **FOLD:** observe the **render path** — `TextArea.get_line(i).plain` (verbatim) + `.spans` (no payload-derived span); state that asserting `ta.text` does **not** discharge the C-17 LLR.
- **MJ-6 (security F4) — the mandated "counterfactual" does not discriminate, and the set omits the crash payload.** Both docs claim `sensor[unclosed` *"raises `MarkupError` under `from_markup`"* — **empirically false**: it yields `plain='sensor[unclosed'`, `spans=[]`, **identical to the safe path**. Measured: `[red]…[/red]` ✅ · `[link=…]` ✅ · ANSI ❌ (different threat class) · `sensor[unclosed` ❌ (**the designated discriminator is the weakest payload**) · **`[/nope]` ✅ — the only crash-class payload, and it is not in the set.** Not a hole (the bracket-*pairs* still fail a regression) but the rationale is wrong and **propagating 47→48** from `tests/test_tui_a2l_detail.py:24-26,49`. **FOLD:** add `[/nope]`; correct the claim in both docs; keep `sensor[unclosed` as a regression fixture but stop crediting it. **BACKLOG CARRY:** fix the claim at its batch-47 origin.
- **MJ-7 (security F5) — the new-sinks C-17 AT was dropped against 01b's explicit instruction; the re-open condition is inspection-only.** Card/glyph/strip C-17 rests on three no-test N/A dispositions (LLR-077.6/078.5/080.7). Each is well-reasoned *today*, but LLR-080.7's re-open (*"if Phase 3 adds any file-derived label to the card…"*) has **no enforcing gate** — and a card header naming its entry is the natural design. D-8 records this exact lesson (batch-47 MN-4: a "conditional" C-17 LLR that was actually unconditional). **FOLD:** restore a narrowed AT over the card header, **or** make the re-open a **mechanical** increment-gate check (grep the card builder for any non-int input).
- **MJ-8 (arch m-2/m-3, promoted) — the C-13.1 ladders aren't deficit-matched.** LLR-079.1's rung 2 (gauge-only) recovers **zero** of the colouring deficit — it's an acceptance relaxation, not a mechanism rung ("rung 1 or nothing" in C-13.1 clothes). LLR-080.6 names two relaxations (hidden/collapsed) untagged + unordered (collapse ≈2-3 rows; hide = full card height). **FOLD:** tag each rung with its recovery + pre-select from the measurement, or drop the C-13.1 framing.

## MINORS
- **m-1** HLR-076's "the 20 docked buttons render as chips" reads as a soft all-at-once claim (§2.4-5 forbids) → reword to the structural invariant. Rest of §3 is clean.
- **m-2 (security F6)** `_highlights` offsets are **BYTE** offsets (`_text_area.py:1496-1508`, `_utf8_encode`, tree-sitter convention); a Python tokenizer naturally emits **codepoint** offsets → non-ASCII pasted JSON misstyles, and a missed lookup **silently defaults to 0** (styles from line start). Ironically LLR-079.4 reasons carefully about chars≠bytes **for the gauge** and doesn't apply it to spans. **FOLD:** state the unit (byte, UTF-8) in LLR-079.1 + add a non-ASCII case.
- **m-3 (security F7)** `_build_highlight_map()` **clears** `_highlights` on rebuild (`_text_area.py:826-830`) → a once-populated map is erased on the next edit. **FOLD:** add "spans survive an edit" to LLR-079.1's Phase-3 probe pass-condition.
- **m-4** §6.5's "R-TUI-046: NO amendment" — **verdict survives** BL-3, but its stated reason ("additive column") does not → restate as the fold precedent.
- **m-5** Verified clean, recorded: `_MUST_PRESERVE_IDS` = **48** · `_batch46_patch_drift_marks` **is** retired (`test_tui_snapshot.py:507`, dead body after `return ()`) · `_TWO_SIZE_SCAFFOLDS = ("patch","map")` `:815`. §2.4-7 / R1 / §5.3's per-cell C-22 + `strict=False` + canonical-CI-only regen is **correctly and sufficiently specified — no finding.**

## PASS (affirmed, no finding)
- **C-7 purity + D-5 asymmetry** — *"the single best-argued decision in the document"* (architect). All three `app.py` sites can supply `mem_map`; `refresh_check_results` (2) + `set_undo_redo_enabled` (3) censuses **complete and correct** per grep.
- **US-P5 read-only is a first-class requirement with a gate AT** (LLR-080.5 ★): `mem_map` + document byte-identical after N selections, 0 new files under `.s19tool/`; `Mapping` (not `Dict`) at the panel boundary enforces it by type. *"This is well done."*
- **Frozen safety** — every C-17 fix site is non-frozen; the batch relies on **no frozen sanitizer**; BL-1's fix lands entirely in non-frozen code. No new fs/network/exec surface.
- **§6.5 Amendment A** re-measures rather than relaxes R-TUI-064's contract — correct.
- **C-28 does not fire** (no App-level `Binding(show=True)`). **C-30 N/A but falsifiable** (AT-076b is a leak probe) — the right way to state a verdict.
- **Provenance-stamp SHAPE is right** (architect answered its own escalation): the stamp catches add/remove/load; an in-place edit preserving `(entry_type,address,encoded_bytes)` is *correctly* vacuous (the outcome is identical by construction); "all `·` on mismatch" is the honest degradation. **The reset alternative is NOT simpler and NOT more correct** — it's a user-visible behaviour change in a render-only batch **and** would still need the image-load trigger (i.e. BL-4's work anyway). **Verdict: stamp, widened.**

## Operator decisions this gate
1. **JSON surface (MJ-4) → IN-PLACE `TextArea._highlights`** (AskUserQuestion 2026-07-16). Fallback path must be tested.

## Gate axis check
- **Coverage** — BROKEN by BL-2 (no AT resolves to a verification) → the fold restores it; BL-1 adds the missing entries-table C-17 node; MJ-7 closes the inspection-only C-17 gap.
- **Certainty** — BL-4 (stale-image glyphs) and MJ-2 (a gate voided by its own escape hatch) are non-vacuity defects; MJ-6 corrects a *false* counterfactual claim.
- **Evidence** — strong: both reviewers ran probes against installed source rather than reasoning from docs.

**VERDICT: BLOCK → apply the folds → re-gate before Phase 3 opens.**

---

## POST-FOLD RECONCILIATION (orchestrator, 2026-07-16) — BL-2 recurred; registry now PINNED

**Process failure, mine.** I dispatched the two fold agents **in parallel and let each mint new AT ids**, so the fold **re-created the divergence BL-2 blocked on**: the architect folded BL-4 into a widened 4-arm `AT-077c` and added `AT-079d`; qa split BL-4 out as `AT-077e`. In batch-47 I learned this exact lesson and pinned the canonical crosswalk **before** dispatching folds — I failed to repeat it here. **Rule for the remaining gates: the orchestrator pins the id registry; agents never mint AT ids in parallel.**

**Diagnosis (3 of 4 "divergences" were false alarms):**
| id | verdict |
|---|---|
| `AT-076d` | FALSE ALARM — appears only in 01b's old→new **map table** as a historical id |
| `AT-063a` | FALSE ALARM — a **batch-46** cross-reference in prose |
| `AT-080e` | COMPATIBLE — 01b's *conditional* hostile-card-header AT is precisely what the architect's **mechanical grep gate** (MJ-7) triggers; needs one consistent statement, not a decision |
| `AT-079d` / `AT-077e` | **REAL** — see the ruling |

### RULING — canonical registry = **26 ATs** (25 from `01` + `AT-077e`)
- **`AT-077c` and `AT-077e` stay SPLIT.** Document-mutation staleness (`AT-077c`) and **image-generation** staleness (`AT-077e`, BL-4) are **distinct triggers** of the same wrong-answer class, with distinct failure modes. Collapsing BL-4 into an arm of `AT-077c` gives coarser failure isolation (the cost qa itself flagged on `AT-077a`) — and **BL-4's image branch is the one that was MISSED at Phase 1**, so it earns its own node under C-10 (one AT per policy branch) + C-18 (one node per AT).
- **`AT-079d` (fallback path) is CANONICAL** — the feature-detect-forced-false path must be an AT, not only a TC, because CI is pinned at 8.2.8 and can never exercise degradation naturally.
- **`AT-080e` is conditional-on-grep** in both docs: the MJ-7 mechanical gate fires ⇒ `AT-080e` is created that increment, gate-blocking. (The architect's reasoning for grep-over-AT stands: an AT over a header that doesn't exist yet passes **vacuously** — the MJ-2 defect class.)

**Residual carries into the Phase-3 cut (from qa §12 — not blockers):**
1. **`AT-079b`'s pass condition is an `or`** ("structure differentiated **or** rung-2 + gauge-only") — **the same self-voiding shape MJ-2 blocked on `AT-080d`**, missed by both Phase-2 reviewers and caught by qa's own re-read. Now moot in mechanism (the operator picked in-place), but the **disjunction must be struck** and the rung *recorded* (TC-079.1), not left as an escape hatch.
2. **`AT-080d`'s node cannot reach its primitives** — they are module-private to `test_tui_patch_layout.py`. **conftest-lift or re-home; never duplicate.**
3. **7 new test files will break the ≤5-file cap on tests alone** → the increment cut must spread them.
4. HLR-level `TC-075…081` rows are **rollups** → mark them as such or they read as 7 unimplemented nodes.
5. `AT-076c` is a **regression** AT on an existing node → cannot evidence a new deliverable.
6. `AT-075e`'s node sits in `test_tui_patch_big.py` while its subject spans the service boundary (`change_service.py:1402-1425` → the table) — a C-18 node-path call.

**qa's tautology guard (recorded — it is load-bearing):** asserting `get_cell_at(...) == payload` **PASSES on the vulnerable code at HEAD** (it round-trips the stored string). `AT-075e` must assert the cell **IS a `rich.text.Text`, not a bare `str`** — `default_cell_formatter` calls `from_markup` only on `str`. Without that clause the gate-blocking AT is vacuous.
