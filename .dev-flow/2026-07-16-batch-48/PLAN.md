# PLAN — batch-48 · screen-upgrades Batch B: Patch Editor BIG (living compendium)

> Living plan; updated at every gate + checkpoint. Origin: `prototypes/screen_upgrades.HANDOFF-PLAN.md` §4.5
> (operator-approved 2026-07-15). Predecessor: batch-47 (Batch A) MERGED + synced.

## Where we are
- **Phase 0 — Story intake & DoR** — awaiting-gate (self-approve, autonomous).
- Branch `feat/batch-48-patch-big` @ `6551aed` (== origin/main tip). **RC-1 PASS.**

## Objective (BLUF)
Take batch-46's three-window Patch Editor to the **BIG** tier: colour roles + check glyphs + a pass/fail
strip + JSON colouring/cap gauge + a **live before/after card** (the headline) + a history strip — plus the
**chip-button CSS** batch-47 deferred (the patch docked rows are its consumer). **Render-only: no wiring or
behaviour change; every batch-46 widget id preserved.**

## Authorization (restated, not inherited — per feedback_standing_auth_per_batch)
Operator directives during batch-47: *"continue autonomously with the next one"* · *"continue autonomously
through both batches"* · *"take it up to PR merge"* · *"continue with the regen PR, then batch B … make sure
the backlog gets carried"*. → **AUTONOMOUS THROUGH SELF-MERGE**, gated: packets at every gate w/ named axis
check → PR + CI green → **final independent PR-level QA must be clean** → merge → sync. **A HIGH final-QA
finding blocks + returns** (this gate FIRED in batch-47 — not a formality). Operator may correct at any time.

## Stories (Phase 0 — DoR) — from handoff §4.5 items 1-6 + the chip carry
| ID | Story (analyst-observable) | Class | Notes |
|---|---|---|---|
| US-P1 | Window border titles + subtitles (entry count · run state · schema); entries colour roles (op purple / address cyan / bytes bright); **docked rows as colour-grouped chips**; variant+scope **line** | READY | Chip CSS = batch-47 carry. Scope line is **NEW** (today scope shows only on a button label) |
| US-P2 | Check-glyph column on entries (`✓`/`◐`/`✗`; no run → `·` grey) | READY | From the last `CheckRunResult`, **index-aligned** |
| US-P3 | CHECKS pass/fail strip (counts + microbar) | READY | `CheckRunResult.aggregates` = exactly `passed/failed/uncheckable` |
| US-P4 | JSON window syntax-ish colouring + paste-cap gauge (`N KB / 64KB`) | READY | ⚠ **C-17: pasted JSON is UNTRUSTED** — the batch's real security surface |
| US-P5 | **LIVE before/after card** on entry-row select (before = `mem_map` bytes at the entry address; after = the entry's patch bytes) | READY | **HEADLINE.** Read-only preview — applies nothing. C-29 geometry |
| US-P6 | History strip (position in the undo/redo stack + key hints) | READY | Position must be **derived** — no cursor exists |

Dependency order: **US-P1 (chips/CSS foundation) → {US-P2, US-P3, US-P4, US-P6} → US-P5** (the card is the
structural addition; measure geometry with it present).

## ⚠ LINE NUMBERS BELOW ARE STALE — measured @ `6551aed`, drifted ~160 lines by Inc-1/2/3
**Do NOT quote a line number from this section into a brief without re-measuring** (Inc-4 recon, 2026-07-16).
Known drift @ `9e3ac6d`: `last_check_result` reset **undo :538 / redo :570** (was :474/:506) · `#patch_win_checks_body`
**:3026** (was :2860) · `#patch_checks_results` **:3025** (was :2859) · `refresh_check_results` **:3819**
(was :3434). **Symbols and contracts below remain valid — only the coordinates rotted.** This is the same class
as the recon-count errors already corrected here (21 not 20 Buttons; 8 not 9 docked roots): *a draft-time
measurement is a snapshot, and every increment invalidates it.* Cite symbols, not coordinates.

## VERIFIED FACTS (recon @ 6551aed — draft-time verification for Phase 1)
**Panel** (`screens_directionb.py`): `PatchEditorPanel` :2192 (spans 2192-3468), `compose` :2644. Windows
`#patch_win_script` :2835 (body :2758) · `#patch_win_checks` :2890 (body :2860) · `#patch_win_json` :2958
(body :2911). Sub-containers `#patch_pane_entries` :2727 · `#patch_pane_changefile` :2756 ·
`#patch_pane_variant` :2832 · `#patch_doc_file_row` :2754. ⚠ **CORRECTED at Inc-2 (MEASURED against the
live tree; the draft-time figures below were mine and were wrong): 21 Buttons, not 20** · **8 `.patch-docked-*`
roots**, not 9 — "9" counted *button-bearing containers*, a different set. Harmless only because the ATs
enumerate the live tree rather than trusting this line; had an AT asserted `== 20`, it would have pinned my
error as the contract. **Treat every unmeasured recon count here as `assumed` until an increment measures it.**
All docked rows are SIBLINGS of the body (the HLR-064/B2 fix). Entries table `DataTable#patch_doc_entries_table`
:2696 (`zebra_stripes=True`, `cursor_type="row"`), columns `_ENTRIES_COLUMNS` :2264 = Kind/Address/Value·bytes/
Status/Linkage, rows built by `refresh_entries(rows)` :3217 from `ChangeEntryRow` (`change_service.py:1357`),
attrs `kind_text/address_text/value_text/status_text/linkage_text`. Empty state `#patch_doc_empty_state` :2701.
`safe_text` :640 (same file). `refresh_check_results` :3434.

**Data:** `CheckRunResult` `changes/model.py:684` — `aggregates` keys `CHECK_AGGREGATE_KEYS` :571 =
`("passed","failed","uncheckable")` (always all three) · `entries: list[CheckRunEntry]` :621 (fields:
`entry_type/address_start/address_end/expected_bytes/actual_bytes(None=uncheckable)/result/linkage/
linkage_symbol/reason_code/reason`). `ChangeEntry` `model.py:80` (`entry_type/address/encoded_bytes/value/
status`). `ChangeSummaryEntry` `model.py:321` (`before_bytes: Optional[...]`, `after_bytes`). `MemoryStatus`
:48. `last_check_result` on **`ChangeService`** `change_service.py:357` (set :1261; **reset on undo :474 /
redo :506** — batch-40 verified; render half `app.py:_refresh_patch_history_view` :2223 → :2261).
`_HISTORY_MAX = 20` `change_service.py:92`; stacks `_undo_stack` :362 / `_redo_stack` :366.
`CappedTextArea` `capped_text_area.py:69`; cap `_CLIPBOARD_READ_CAP_CHARS = 65536` **chars** (shared, from
`os_clipboard_input.py:72`); consumer `CappedTextArea#patch_paste_text` :2906 (the JSON window, only patch use).
`LoadedFile.mem_map` `models.py:57`.

**Reuse:** `insight_style.py` — palette + `human_bytes` :68 · `label_value` :119 · `microbar(frac,width,style,
floor=False)` :160 (⚠ batch-47: `floor=True` ONLY for bars meaning *"this exists"*; proportional bars stay
unfloored) · `threshold_style` :224. **Chip-button CSS does NOT exist** (only `.issue-code-chip` :1023, a
Label not a Button) → batch-47's deferral was correct; this batch creates it. Patch CSS block ≈ :824-1170
(`.patch-docked-row/.patch-docked-group` :902-903; the shared button-row block :913-918).

## 🔑 Four facts that SHAPE the design (recon)
1. **The card cannot use `last_summary`.** `ChangeSummaryEntry.before_bytes` is `None` for every
   **non-applied** disposition (`model.py:336-338`) — and a *live* card renders BEFORE an apply. **Before-bytes
   MUST come from `LoadedFile.mem_map`.**
2. **`PatchEditorPanel` is strictly presentational (C-7): ZERO `self.app`, ZERO `mem_map`, ZERO service
   imports** (grep-verified over 2192-3468). → thread `mem_map` in as a **method parameter**, following the
   batch-47 Inc-6 precedent `MemoryMapPanel.render_ranges(mem_map=…)` :1341. Reaching into `self.app` would be
   the panel's FIRST C-7 violation.
3. **Entry↔result correlation is POSITIONAL.** No ids on `ChangeEntry`/`CheckRunEntry`/`ChangeSummaryEntry`;
   the contract is document order (`model.py:660-661`). `cursor_type="row"` ⇒ the cursor row index IS the
   entry index. **Index-align; never address-match.**
4. ⚠ **Both patch snapshot cells are STRICT GREEN oracles at HEAD** — `_batch46_patch_drift_marks` was retired
   by batch-47's regen PR (#87). Any visible repaint now fails **CI RED**, not xfail. **Budget a canonical-CI
   regen from the start** (C-22 per-cell prediction; regen = follow-up PR, local FORBIDDEN).

## Guardrails
- **Engine-frozen OFF-LIMITS** (C-27 dual-guard each increment). Recon: the whole surface is non-frozen;
  frozen paths are touched read-only via existing imports only (`changes/model.py:35` → `validation.model`;
  `change_service.py:66` → `color_policy`). **No new frozen edits implied.**
- **C-17 (the batch's real surface):** the **pasted JSON** in `#patch_paste_text` is untrusted. Colour via a
  **tokenizer over a trusted-rendered `Text`** — NEVER markup-parse pasted content, never f-string it into
  markup. Gate-blocking hostile-input AT required (payload set incl. the unbalanced-bracket `from_markup`
  counterfactual). Also: check `linkage_symbol` / `reason` (file-derived) if they reach a new sink.
- **C-29 two-axis:** re-measure the window budget **with the card mounted**, at 80×24 AND 120×30. The card
  must NOT push the docked rows below reachability — that is field-audit **B2**, the exact defect batch-46
  fixed → **AT it explicitly** (reuse batch-46's reachable-under-scroll contract at the floor).
- **Preserve every batch-46 id:** `tests/test_tui_patch_layout.py:67 _MUST_PRESERVE_IDS` is a **48-id** tuple
  (14 wiring-critical leaves incl. `patch_doc_entries_table`/`patch_doc_issues`/`patch_checks_results`/2
  Selects + 22 census-pinned + 10 structural + 2 hidden rows). (The handoff's "14 leaf + 2 hidden" understates it.)
- **C-30 (new, batch-47):** sequence an app-wide restyle LAST. This batch is **patch-screen-scoped** → likely
  N/A; confirm at Phase 1 (the chip CSS must not leak app-wide).
- **C-26 reverse-census** each touched symbol (see the seed table below).

## C-26 census seeds (recon)
`PatchEditorPanel` → patch_editor_v2(32)/directionb(10)/variants(7)/patch_variant(5)/before_after_report(4)/
patch_layout(4)/undo_redo_ux(3)/loadfilescreen_input(2)/memory_patch(2)/report_filter_surface(2)/
variant_execution(2) · `patch_win_*` → patch_editor_v2/patch_layout/variants · `patch_pane_entries` →
directionb(3)/patch_layout(1) · `last_check_result` → undo_redo_ux(2)/change_service(1)/patch_editor_v2(1) ·
`CheckRunResult` → checks_engine(8)/report_service(5)/variant_execution(2) · `_HISTORY_MAX` →
change_service(6) · `CappedTextArea` → capped_text_area(11)/patch_editor_v2(4). **Frozen test set: CLEAN.**
⚠ **SEED GAP found at Inc-2 — `test_tui_theme.py` is a real C-26 hit these seeds MISSED.** The seeds keyed on
**code symbols** (`PatchEditorPanel`, `patch_win_*`, …) and therefore cannot see consumers of a **non-symbol
artifact** — `styles.tcss`. Any increment touching CSS/assets must census on the **artifact**, not just on the
symbols. (Generalizes: seed lists are a starting point, never the census.)
Patch snapshots: exactly 2 cells (`patch-comfortable-80x24` / `-120x30`; `_TWO_SIZE_SCAFFOLDS` :815).

## Risks / watch-items
- R1 **Snapshot RED (not xfail)** — the strict-oracle change above. Predict per-cell (C-22) + regen follow-up.
- R2 **C-17 pasted-JSON tokenizer** — the highest-risk sink of the batch.
- R3 **C-29 card-vs-docked-row reachability** — re-litigates the B2 defect; AT explicitly.
- R4 **C-7 purity** — do not let the card reach into `self.app`; parameter-thread `mem_map`.
- R5 **Positional index-alignment** — an off-by-one silently mislabels a row's check result.
- R6 **48-id preserve tuple** — a moved/renamed id trips the census.

## 🔴 INC-5 RULINGS (2026-07-16) — both blockers resolved

### RULING 1 (orchestrator, §6.5 amendment owed) — **AT-079b/c re-point to the PAINTED result**
`AT-079c` ★★ (the batch's **gate-blocking C-17 AT**) is **VACUOUS — constant-true.** MEASURED at the pin:
`_render_line` (`:1440`) stylizes a **local copy** — `line = self.get_line(i)` — and `get_line` (`:1328`) is
unconditionally `Text(line_string, ...)`. So `.spans` is **ALWAYS `[]`**, with `_highlights` fully populated:
```
get_line(0) : '{"a": 1}'  spans= []
_highlights : {0: [(1,4,'json.key'), (6,7,'json.number')]}
```
⇒ the AT passes on a safe implementation, an unsafe one, **and one never written**. It is the *exact* defect
01b itself names for `ta.text` (*"passes even if the rendering path is unsafe"*), **reproduced one accessor
over.** This is the **SEVENTH** vacuous check on this batch.
**Ruled: re-point AT-079b/c to the PAINTED result (`_render_line(y)` segments).** This is **not a judgment
call — a constant-true gate is forced to change**; the only question was who records it. **§6.5 Before/After
amendment REQUIRED** (never silently edit a locked requirement — [[feedback_requirement_amendment_before_after]]).
⚠ **Same correction F2 forces on Inc-4's strip. ONE ROOT, TWO INCREMENTS.** *"Assert the PAINTED result"* now
has **THREE sightings in one batch** (Inc-4 F2 · Inc-5 AT-079c · the `display=False` probe) → **Phase-5
control candidate in its own right.**

### RULING 2 (OPERATOR, 2026-07-16) — **gauge: Amendment F's SEMANTICS, but a NON-CONFUSABLE hue**
Operator: *"Do the amendment F as you recommend but try to choose different color that does not conflict or
can easily be confused for one or several of the current rules."*
⇒ **The gauge escalates as a WARNING (Amendment F is app-wide and stands, NOT narrowed) — but it must NOT
reuse GREEN/YELLOW/RED**, so nothing inside `#patch_editor_panel` can be misread as a verdict. Both of the
operator's prior rulings survive intact; neither is spent.
⚠ **This AUTHORIZES A NEW HUE** — the first time this batch has. Every prior brief said "introduce NO new
colour"; that constraint is **lifted for this one purpose only** because Inc-2b MEASURED the palette at
capacity (HILITE/PURPLE/CYAN are the only distinct non-verdict hues, and all three are now doubly claimed).
**Hue census (angles) — everything currently claimed:**
| Claimant | Hue |
|---|---|
| RED `#fd8383` — **verdict** | ~0° |
| **Orange** — MAC-specific cue (Amd F *preserved* it: `⚠` glyph · `MAC_ADDRESS_OVERLAY_STYLE` · `.mac_out_of_range`) | ~30° |
| YELLOW `#f6ff8f` — **verdict** + warning app-wide | ~66° |
| GREEN `#54efae` — **verdict** | ~158° |
| CYAN `#7dd3fc` — address role + checks chip + `.sev-info` | ~199° |
| HILITE/LBLUE `#91abec`/`#bbc8e8` — entry chip | ~223° |
| PURPLE `#b565f3` — kind role + apply chip | ~274° |
⛔ **ORANGE IS REJECTED and this is the trap to name:** it *looks* free inside the patch panel, but at **~30°
it sits BETWEEN RED (0°) and YELLOW (66°)** — the two hues most likely to be misread as a verdict, which is
precisely what the operator ruled out. It is also the MAC cue **Amendment F deliberately preserved** — taking
it here would spend a second operator decision to satisfy the first.
✅ **The free band is ~300-330° (magenta/pink):** **46° from PURPLE, 40° from RED.** Inc-2b measured
**HILITE↔CYAN at 24°** as "the closest pair, still distinct" ⇒ **40°+ is comfortable.**
**Constraint for the implementer: MEASURE, do not eyeball.** Compute the actual hue angle of any candidate and
assert **≥40° from EVERY claimant above**. Escalation may ride **intensity/boldness within the one new family**
rather than three new hues — prefer the smallest addition that reads as escalation. **If nothing clears 40°,
STOP and report** — that is a namespace decision, not an implementation choice.

## ⚠ INC-5 BINDING CORRECTIONS (Inc-4 code review F1/F2 — read BEFORE the geometry pass)
- **F1 — the C-29 risk was recorded INVERTED. The strip wraps at 120×30 and FITS at 80×24.** PILOT-MEASURED:
  `120×30` body interior **w=18** → strip **w=16 h=2 (WRAPS)** · `80×24` body interior **w=66** → strip
  **w=64 h=1 (fits)**. **22-23 is the WINDOW width** (`test_tui_patch_layout.py:56-58`), **not** the content
  budget — the real container is **16**. Inc-4 sized 8 cells against the inherited figure ⇒ **that IS the C-29
  error**, not an open gap. ⚠ **The orchestrator's brief compounded it by sending the reviewer to measure
  80×24 — the size that already works.** Aimed there, Inc-5 would have "closed" the gap while the wrap
  survived at the primary regime this batch exists to build. **Counts alone = 15 chars vs a 16-col body ⇒ the
  bar CANNOT share the line at 120×30 at any width worth drawing.** That is a DESIGN decision (tighter
  separators `✓2 ✗1 ◐3 ` = 9 + a 7-cell bar = 16 · responsive width · intentional two-line strip) — not a tweak.
- **F2 — no oracle in Inc-4 observes the PAINTED strip; both test layers are blind to visibility.** All ATs
  read `Static.render()` (**pre-layout `Content`**, geometry-independent). **MEASURED: mount the strip, update
  it, set `display = False` — all 6 tests still pass.** The snapshot layer is blind too (the 2 patch cells are
  `xfail(strict=False)`, so they *absorb* drift). **A strip that renders nothing at all ships green.** This is
  WHY F1 went unseen. → **Inc-5 owes ONE geometry arm at BOTH sizes** (e.g. `query_one("#patch_checks_strip")
  .region.height == 1`) — the assertion that would have caught F1. The data contract is well covered; the
  uncaught axis is **visibility**, exactly C-29's axis.
- **F3 [LOW] — the SIXTH vacuous check** (`tests/test_tui_patch_checks_strip.py:521-525`): both operands are
  **literals**, so it is **constant-true** — the reviewer evaluated it *without importing the panel* and it
  passed. Same root cause the dev fixed in its 3 grep oracles (*an oracle keyed to the AUTHOR'S DECLARATION,
  not derived from the code*), surviving in set form. Fix: `assert new_members <= set(vars(PatchEditorPanel))`
  first, binding the literal to the code.
- **F4 [LOW] — the floor rationale is applied at ONE END only.** *"Overstating passes is the harm"* — but
  `round()` overstates passes at the TOP end regardless of `floor`: **19-of-20 → 8/8 filled, identical to
  20/20.** No symmetric ceiling exists. The conclusion survives a THIRD time; the reasoning is still wrong.
  **The honest justification is REDUNDANCY, not asymmetry:** the authoritative counts sit beside the bar, so
  ±1 cell of rounding either way costs nothing.
- **F5 [LOW]** — TC-078.4 arms 1-4 duplicate `test_microbar_floor_opt_in` (~60 lines above, same file, width
  8). Optional trim; the AST + builder arms are the genuinely new ones.

## 🔑 PHASE-5 LESSON (Inc-4 review process note — the sharpest of the batch)
**The fact the dev "measured" was ALREADY RECORDED TWICE in the file it was editing.** `microbar`'s own
docstring says *"`frac <= 0` still renders an empty bar"* (`insight_style.py:176-177`), and
`test_microbar_floor_opt_in:137` — **~60 lines above where TC-078.4 was added, from batch-47 Inc-9, the very
HIGH-1 fix this reasoning invokes** — already asserts `microbar(0.0, width, floor=True).plain.count("█") == 0`.
So the orchestrator's false claim was refutable **by reading**, and the dev's first draft asserted the opposite
before measuring. **Same root cause the dev confessed for `Static.renderable`** (*"the house had already
recorded it and I had not read it"*) — **second instance, same increment.** Measurement saved it, but
measurement was the SECOND-cheapest way to learn it; **reading the file it was already in was the cheapest.**
⚠ This **rhymes exactly** with the LIVE BACKLOG's `Select`-label finding (*"the gap is not 'find the sink' —
it is 'when a sink is found, sweep every site of that class'"*). Both are **the house already knew, and nobody
read it.** → Candidate: **when a helper's semantics are in question, read the helper's own oracle before
measuring it.** Feeds the operator's code↔requirement traceability candidate — *an oracle nobody reads is an
untraversed edge.*

## 🔑 PHASE-5 CANDIDATE — **the input set is itself an oracle** (Inc-5b, HIGH-1's root)
**Proposed by the Inc-5b agent, NOT encoded — needs operator approval** ([[feedback_devflow_control_encode_approval]]):
> *"When a test certifies a UNIVERSAL, the input set is itself an oracle and must be **derived or guarded**,
> never hand-listed — **code mutation cannot test an input set.**"*
**Why this is a NEW class, and the ninth instance this batch.** The first eight were vacuous **assertions** —
checks that could not fail, all findable by mutating the code. HIGH-1 is a vacuous **INPUT SET**: the
assertion was real, the arithmetic **exact**, the measurement honest — and it was still wrong because the
**set it quantified over** was incomplete (`#e06c75`, 38.44°, omitted; live in the *same module*). **Mutate
the code and it still passes.** One level above everything the batch had been hunting.
**Evidence it generalises (same root, three sites, one batch):**
- Inc-5's **arc** was hardcoded while its rule ("don't sit between two verdicts") lived only in prose → the
  census could be hand-edited invisibly. Fix: `_admissible_optimum()` **computes** the arc every run.
- Inc-5's **F2** claimed a colour axis in four documents; the code checked `link`/`bold`/`italic` only.
- Inc-5b **committed the F2 defect WHILE FIXING F2** — its first census draft hardcoded `#d78700` under a
  comment claiming it was "resolved via `rich.color.Color.parse`". Caught by re-reading its own diff against
  its own claims; fixed by making the claim **true**, not by softening it.
⇒ All three are **one shape: a claim in prose with nothing binding it to code.** ⚠ **This is the operator's
own traceability call, arriving from a different direction** — a hand-listed census IS an untraversed
code↔assertion edge. **Assess whether ONE control subsumes both before encoding.**
**Corroborating proof the fix works:** M3 (drop `#e06c75` from the census) now fails **both** the guard **and**
the hue test, because optimality **recomputes from the census**. Under Inc-5 that mutation was **silently
green**. Census and arc can no longer drift apart — which was the actual bug.
⚠ **And the orchestrator's floor was UNSATISFIABLE, not merely arbitrary**: best achievable = **40.77°**; the
shipped claim was **≥43°** — a property **no colour can have**, "passing" only because the census omitted the
failing hues. **A constraint that barely admits its own answer measures nothing** (43 → empty set; 40 → a
1.53° arc). Replaced by an **anchored** floor (24°, beating the **23.5°** pair the app already ships and reads
fine) **plus optimality** — self-calibrating, can never go unsatisfiable. Lesson: **anchor a threshold to
something the system already demonstrates, never to an invented round number.**

## 🔎 Phase-5 CONTROL CANDIDATE (operator-requested 2026-07-16 — raise at the post-mortem)
**Gap: a SHARED-NAMESPACE collision between two individually-correct increments is invisible to every control
we have.** Origin: Inc-2 review **F1**. Inc-2 claimed GREEN/YELLOW as a chip *function* cue; Inc-3
concurrently claimed the same hues as a glyph *verdict* cue, same panel. **Neither increment was wrong alone;
every AT was green** (AT-076a: the 3 chip colours are mutually distinct — true; Inc-3: right glyph→right
colour — true). The defect exists **only in the overlap**, which no artifact owns.
**Why each control was blind — the AXIS is wrong, not the rigor:**
- **C-26 keys on touched SYMBOLS.** No shared symbol exists: Inc-2 wrote a **hex literal in CSS**, Inc-3 an
  `insight_style` **constant in Python**. Same *value*, no shared *name*. (Same root as Inc-2's seed-gap —
  symbol-keyed seeds were blind to `styles.tcss`, a non-symbol artifact.)
- **Dual traceability is per-chain.** HLR-076 and HLR-077 are separate `US→HLR→LLR→TC` chains. A **100%
  complete matrix is fully consistent with this bug** — completeness of each chain says nothing about two
  chains competing for one resource.
- **C-10(b)** buys one AT per *branch of one policy*; not across *two policies that never call each other*.
**General shape (ONE control, not four patches):** a **shared, finite semantic namespace scoped to a
container**, with multiple independent claimants, each locally valid. Hue is one instance; the shape also
covers **keybindings · widget ids · CSS specificity · markup sinks · glyph vocabulary**. ⚠ Same failure
family as **R-NEW-1's missed sweep** and **C-28** — three sightings, one root: *the census axis is keyed to
code symbols, but the defect lives in a shared namespace no symbol names.*
⚠ **What caught it is NOT reproducible** — a reviewer voluntarily read a **sibling agent's uncommitted WIP**.
No control required that. **Do not credit the process.**
🎯 **OPERATOR'S CALL (2026-07-16) — leading candidate; target = the GLOBAL `/dev-flow` + `/fast-dev-flow`
rules** (classified **project-agnostic** per the control-placement policy → global command, NOT
`docs/engineering-rules.md`): *"the code is not correctly traced — the code did not reference the requirements
even though it covers both requirements."* **This beats candidate (b):** a Phase-2 pass depends on someone
*noticing*; a **code↔requirement edge makes the overlap QUERYABLE** — structural, not diligence-dependent.
⚠ **Refinement — a back-reference ALONE does not catch it.** Two sites tagged `HLR-076` and `HLR-077` both
using `#54efae` still look fine individually. The tag is the **enabling edge**; the oracle is the **reverse
index `resource → {requirements claiming it}`**, flagging any resource with **≥2 claimants in one scope**.
✅ **Already half-built (MEASURED 2026-07-16):** `screens_directionb.py` = **25** `LLR-075`/`R-TUI-075` comment
back-refs · `styles.tcss` = **1** `HLR-076` · `REQUIREMENTS.md` already maps `R-*` → files + tests. **Both
directions exist.** Three gaps only: **convention, not contract** (unenforced) · **file-granular**, not
symbol/value-granular · **never traversed in reverse**. This is *closing* an edge, not inventing one.
⚠ **Cost to weigh honestly:** requirement tags in code **ROT** — a drifted tag is worse than no tag (it
asserts a trace that no longer holds). Any encoding owes a staleness answer (CI: every `R-*`/`LLR-*` tag names
a live requirement), else we buy a second false-confidence surface — the exact failure this batch keeps
hitting (Inc-2's vacuous `getattr` guard; the old class-based title oracle).
**Candidates (evaluate at P5; do NOT pre-adopt):** (a) per-container **semantic-namespace registry**
(hue→meaning, key→action, glyph→verdict) that a claiming increment must consult+extend, with a test asserting
no entry carries 2 meanings in one scope; (b) **Phase-2 cross-increment collision pass** over the *planned*
increment set; (c) extend C-26 to census **values/artifacts**, not only symbols; (d) accept + rely on review,
stated explicitly. ⚠ **(b) is cheapest and would have caught this BEFORE Inc-2 was cut — the collision was
predictable from HLR-076 + HLR-077 alone and did not need code to exist.** Precedent: batch-47 **MJ-1**
(writer-census at Phase 2, before code) proves this class is catchable pre-implementation.

## Phase-4 carries (post-merge regen PR)
- **The canonical-CI snapshot-regen follow-up must ALSO delete 2 ORPHAN baselines** (Phase-4 §7): `tests/__snapshots__/test_tui_snapshot/test_tc036s_entropy_modal_snapshot[entropy-comfortable-{80x24,120x30}].svg`. The test was retired in **batch-45** (entropy pop-up → Band-Bands); its baselines were never cleaned up and are **on main**. They are the sole cause of `pytest -q` (full, unfiltered) exiting **1** via syrupy's unused-snapshot session-fail (`selected_all_collected_items()` true only on a complete run). **NOT a batch-48 regression** — batch-48 touched 0 baselines vs base `6551aed`; the full suite exits 1 on the base tree too. The PR-blocking CI gate `-m "not slow"` exits 0. Deleting these 2 + regenerating the 2 patch drift cells makes `pytest -q` exit 0 again. Also fix the dangling comment ref at `test_tui_snapshot.py:440`.

## Out-of-scope carries (backlog — see MEMORY.md LIVE BACKLOG)
Issues Report tiers (PARKED — **but still owns P0 B1 Issues paging no-op; parked ≠ fixed**) · field-audit B3
A2L two-extra-chars (needs live repro) · discoverability gap · Issues filter/sort · universal paste · Flow
Builder (flow.json persistence · CHECK+CRC seam · multi-image) · report_service:1091 · frozen a2l.py:926 F841 ·
P-1 1-based index · **delete `prototypes/screen_upgrades.*` + `out/` AFTER this batch** (§10.4).

## Decision log
- **2026-07-16 P3 Inc-2b — OPERATOR DECISION: chip palette shifts to NON-VERDICT hues.** Raised by the Inc-2
  code review as F1 (MEDIUM). Inside `#patch_editor_panel` the Inc-2 chip family claimed GREEN `#54efae` +
  YELLOW `#f6ff8f` as a **function** cue, while Inc-3's `_GLYPH_STYLE = {"✓": GREEN, "✗": RED, "◐": YELLOW}`
  claims the same hues as a **verdict** cue — green = "apply-path button" *and* "check passed"; yellow =
  "checks-group button" *and* "check partial". The reviewer found this in Inc-3's *uncommitted WIP*, i.e. it
  was hypothetical for about one increment. **Ruling: chips → `$accent-calm`/CYAN/PURPLE/LBLUE (all already in
  `insight_style`; no new colours). GREEN/YELLOW/RED stay RESERVED for verdicts inside this panel.**
  **Why:** the verdict cue is the one that must never be ambiguous — it is what tells an analyst whether a
  patch passed. And §6.5 **Amendment F** (batch-47, operator-decided: *yellow ≡ warning app-wide*) was bought
  ONE BATCH AGO; spending it back here would leave the next reader an exception to memorise. Inc-2 is the
  increment that *claims* the hue → cheap to fix now, expensive after the Inc-4 pass/fail strip lands.
  ⚠ **Note the mechanism, not just the outcome:** Inc-2's rejection of `.sev-ok`/`.sev-warning` **was correct**
  (frozen `color_policy.py` stays severity's source of truth; reusing the class would let a severity retune
  silently retint buttons). The bug was never the *rejection* — it was reusing the **hue** after correctly
  rejecting the **class**. Right call, wrong palette.
- **2026-07-16 P0**: RC-1 PASS @ 6551aed. Authorization restated from the operator's explicit cross-batch
  grant. Already-shipped check: R-TUI-074 highest → new = **R-TUI-075+**; check-glyph 0 hits = NEW; the live
  before/after CARD is NOT shipped (the existing `#patch_before_after_button` → `action_before_after_report`
  **writes a report file**, US-061 — a distinct feature, `app.py:2158`/`:2639`). 6 stories READY.

## Test ledger
Baseline `pytest -q -m "not slow"` @ 6551aed — **MEASURED 2026-07-16, twice independently** (Inc-1 dev +
Inc-1 code review, agreeing): **1454 collected / 1449 passed / 2 skipped / 3 xfailed** (1449+2+3 = 1454 ✓).
⚠ **Supersedes the prior "1416 passed" figure, which does NOT reconcile. Cause UNKNOWN — do not infer one.**
The orchestrator's proffered explanation ("batch-47's regen retired 29 xfails → they became passes") was
**checked and is false**: 1416+29 = 1445 ≠ 1449, and this very line already claimed 1416 was *post*-regen
(its `3 xfailed` matches the measurement exactly). Only `passed` was stale, by 33. **A wrong story in the
ledger is worse than an acknowledged gap** — later increments would reconcile against a fiction.
Branch @ `faa65cb`: **1463 collected / 1456 passed / 2 skipped / 5 xfailed** — Δ **+9 collected** = exactly
the 9 new ATs in `test_tui_patch_big.py`; +2 xfail = the 2 patch snapshot cells (C-22).

### ⚠ VOCABULARY — fix this, it has been wrong in every increment so far (Inc-3 review F2)
**"Full suite" has been used for a `-m "not slow"` run in the Inc-1/2/3 commit messages + checklists.**
`CLAUDE.md` defines `pytest -q` as the FULL suite and `-m "not slow"` as the REDUCED variant. Per-increment
docs printed the exact command (honest); the **commit messages and checklists dropped the qualifier** — i.e.
the overstatement lived in the two most-read places. No hidden failure: the reviewer ran the TRUE full suite
@ `9e3ac6d` → **1507 passed / 2 skipped / 5 xfailed / 0 failed**; the 20 slow tests pass.
**Say "suite (`-m 'not slow'`)" or "full suite (unfiltered)" — never "full suite" for the reduced run.**
Also **relabel "collected" → "selected"**: 1494 is `1514 collected − 20 deselected`. The arithmetic is
self-consistent and applied identically across Inc-1/2/3, so the **deltas stay comparable** — only the noun
was wrong.

| @ `9e3ac6d` | unfiltered `pytest -q` | `-m "not slow"` |
|---|---|---|
| collected | **1514** | 1514 (20 deselected → **1494 selected**) |
| passed | **1507** | **1487** |
| skipped / xfailed / **failed** | 2 / 5 / **0** | 2 / 5 / **0** |

## ⚠ Ordering constraints (load-bearing — not housekeeping)
- **Inc-2's title de-dup MUST land BEFORE the batch-48 canonical-CI snapshot-regen PR.** The border title
  `¹PATCH SCRIPT` currently duplicates the in-body `Label("PATCH SCRIPT")` (`screens_directionb.py:2735` +
  `:3029`). The de-dup is correctly deferred out of Inc-1 (removing the Label means editing the **pinned**
  contract `test_tui_patch_layout.py:583`, which Inc-1's scope never covered) — but the 2 patch cells are
  **xfailed**, so the duplication is **invisible to CI**. If the de-dup slips past the regen, **the regen
  bakes the duplicate into the SVG baselines and it permanently stops reading as drift.** The deferral is
  safe; the *unpinned ordering* was not. (Inc-1 code review F5, MEDIUM.)
- **Inc-2 must DELETE-AND-RESTATE, not hide.** Replace `:583`'s `"patch-window-title" in c.classes` assertion
  with a `border_title` assertion — preserving the protected property (*each window self-describes*) in a
  **stronger** form. Do **NOT** hide the Label via CSS: a hidden element still satisfies the class check,
  converting `:583` into a **false-confidence test**. §6.5 amendment required for the removal.
