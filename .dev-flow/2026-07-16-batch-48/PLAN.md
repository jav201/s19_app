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

## VERIFIED FACTS (recon @ 6551aed — draft-time verification for Phase 1)
**Panel** (`screens_directionb.py`): `PatchEditorPanel` :2192 (spans 2192-3468), `compose` :2644. Windows
`#patch_win_script` :2835 (body :2758) · `#patch_win_checks` :2890 (body :2860) · `#patch_win_json` :2958
(body :2911). Sub-containers `#patch_pane_entries` :2727 · `#patch_pane_changefile` :2756 ·
`#patch_pane_variant` :2832 · `#patch_doc_file_row` :2754. **20 distinct Button ids** across 9 docked
containers (all SIBLINGS of the body — the HLR-064/B2 fix). Entries table `DataTable#patch_doc_entries_table`
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
Patch snapshots: exactly 2 cells (`patch-comfortable-80x24` / `-120x30`; `_TWO_SIZE_SCAFFOLDS` :815).

## Risks / watch-items
- R1 **Snapshot RED (not xfail)** — the strict-oracle change above. Predict per-cell (C-22) + regen follow-up.
- R2 **C-17 pasted-JSON tokenizer** — the highest-risk sink of the batch.
- R3 **C-29 card-vs-docked-row reachability** — re-litigates the B2 defect; AT explicitly.
- R4 **C-7 purity** — do not let the card reach into `self.app`; parameter-thread `mem_map`.
- R5 **Positional index-alignment** — an off-by-one silently mislabels a row's check result.
- R6 **48-id preserve tuple** — a moved/renamed id trips the census.

## Out-of-scope carries (backlog — see MEMORY.md LIVE BACKLOG)
Issues Report tiers (PARKED — **but still owns P0 B1 Issues paging no-op; parked ≠ fixed**) · field-audit B3
A2L two-extra-chars (needs live repro) · discoverability gap · Issues filter/sort · universal paste · Flow
Builder (flow.json persistence · CHECK+CRC seam · multi-image) · report_service:1091 · frozen a2l.py:926 F841 ·
P-1 1-based index · **delete `prototypes/screen_upgrades.*` + `out/` AFTER this batch** (§10.4).

## Decision log
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
