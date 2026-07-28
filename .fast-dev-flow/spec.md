# Quick Spec — s19_app · batch-66 feature slate (paste · map interaction · flow dual-entry)

- **Status:** open
- **Date:** 2026-07-28
- **Branch:** `claude/batch-66-feature-slate` (base `73e3fb9` = `origin/main` tip; RC-1 PASS, merge-base == tip)
- **Flow mode:** autonomous + self-merge (operator-granted THIS batch at kickoff; per-batch only, never carried)
- **Artifact language:** English (project default per `CLAUDE.md`; conversation stays Spanish)
- **security_required:** true (see §6)

> **Scope note — the flow's own escape hatch fired and was NOT taken.** `/fast-dev-flow` recommends promotion to `/dev-flow` at >3 increments; this batch has 5. Reported rather than silently ignored: the operator sized this slate explicitly at kickoff after seeing the per-increment breakdown, and every increment is independently revertible with its own AT. Staying in fast-flow is the operator's call, recorded here so it is auditable.

---

## 1. Objective (1 line)

Ship four user-facing features off the CODE-lane backlog — OS-clipboard paste in every remaining text box, the Memory-Map single/double-click split, clickable entropy bands, and a pinned dual-entry contract for PATCH change-documents.

---

## 2. User stories

- As an **operator**, I want Ctrl+V to work in every text box (search, goto, filter, save-name, CRC fields), so that I stop hand-typing addresses and paths that are already on my clipboard.
- As an **operator**, I want a single click on a memory-map region to *inspect* it without yanking me to the hex view, and a double click to make the jump, so that browsing regions is not a navigation trap.
- As an **operator**, I want the entropy **bands** at the top of the map to be clickable like the region rows, so that the visual overview is a navigation surface and not just decoration.
- As an **operator**, I want the change-document JSON to be a first-class PATCH input from **both** the Patch Editor and a Flow Builder block, so that the two entry points are a documented capability rather than an accident of implementation.

---

## 3. RC-1 verification — what disk says (premises corrected before deriving)

Three findings changed the plan. None was in the backlog text.

1. **N4a is a SPLIT, not an ADD.** `MemoryMapPanel.on_region_row_activated` (`screens_directionb.py:2327`) already populates the detail inspector (batch-47 R-TUI-074) **and** posts `OpenInHexRequested` (`:2370`) on one click. The backlog framed it as "add a details view". The work is moving the jump onto double-click. `event.chain` appears **nowhere** in `s19_app/tui/` — double-click support genuinely does not exist yet.
2. **N4b is small, because the addresses are already in hand.** `_build_band_widgets` (`:1964`) loops over `(band, run_bytes, start)` runs and mounts a plain `Static` per segment (`:1980`). `RegionRow(content, region_start, region_end, classes)` has **exactly** that constructor shape and no `DEFAULT_CSS`, so the band strip can reuse it verbatim and inherit whatever click semantics AC-2 lands. Gap-hatch segments (`:1972`) stay plain `Static` — an unmapped gap has no region to open.
3. **FB-P2's premise is half-wrong.** The change-doc input **is** surfaced in the Flow Builder (`Select` "Patch (change doc)" at `:2625` + a free-text ref `Input` at `:2705`), and the Patch Editor has a richer picker (`#patch_doc_file_select`, `:4012`, populated by `set_options`). So "confirm it is surfaced" is already answered YES. The real gap is that **nothing pins the two entries to the same behaviour** — they could diverge silently. The deliverable is therefore a convergence test + documentation, not new UI.

---

## 4. Acceptance criteria (observable)

**AC-1 — paste is universal.** When the TUI package is scanned, **zero** user-facing text-entry widgets shall be stock `Input`; all shall be `OsClipboardInput`. Baseline measured pre-fix: **16 stock sites across 5 files** (`app.py`×8, `command_bar.py`×3, `screens.py`×3, `crc_designer_view.py`×1, `screens_directionb.py`×1).

**AC-2 — paste actually pastes.** When `action_paste` runs on a representative converted widget with clipboard text `"DEADBEEF"`, the widget `value` shall contain `"DEADBEEF"`.

**AC-3 — single click inspects only.** When a `RegionRow` receives a click with `chain == 1`, the `#map_detail_body` shall be populated for that run **and no** `OpenInHexRequested` message shall be posted.

**AC-4 — double click navigates.** When a `RegionRow` receives a click with `chain == 2`, exactly one `OpenInHexRequested(region_start)` shall be posted.

**AC-5 — the OLD behaviour is gone (C-31/C-32 counterfactual).** An AT shall assert the pre-fix contract (single click posts `OpenInHexRequested`) and shall be shown **RED on the fixed tree** / GREEN on the unfixed tree, so the change of a shipped interaction is pinned in both directions.

**AC-6 — bands are clickable with the same semantics.** When a band-strip segment covering run `(start, start+run_bytes)` receives a single click, `#map_detail_body` shall show that window; on a double click exactly one `OpenInHexRequested(start)` shall be posted. When a **gap-hatch** segment is clicked, **no** message shall be posted.

**AC-7 — dual entry converges.** Given one change-document file, the Patch-Editor path and the Flow-Builder `PatchBlock` path shall produce the **same** `(mem_map, ranges)` mutation over the same source image.

**AC-8 — no regression.** Full non-slow suite green, and the 29 snapshot cells shall show **0 new** drift attributable to this batch.

---

## 5. Out of scope

- **N5 worker migration** (before/after + diff reports run on the UI thread; moving them to `@work` is a threading change, own batch).
- The three MAJOR `report_service` defects (D1 addendum memory, D2 schema-legal address denial, F4 unbounded tables) — defects, not features; operator chose features this batch.
- Issues Report v2 filter/sort (PARKED on an operator tier decision), PKI extraction (BLOCKED on operator definition), FB-P3 CRC sub-flow (deferred), A2L discoverability (needs a design pass).
- Any edit to the engine-frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) or the frozen test files.

---

## 6. Security flags

`security_required: **true**` — three patterns fired.

| Pattern | Where | Handling |
|---|---|---|
| **`user input` / paste** | AC-1/AC-2 widen an **untrusted external input** surface (OS clipboard) from 20 widgets to 36 | `OsClipboardInput` inserts only the **first line** of the payload and routes through `Input.replace`, identical to stock `Input._on_paste` policy. No new parsing path; the widening is of an already-audited widget (batch-31 B-03). Verify no converted site feeds a shell/eval sink. |
| **`form` / file-derived text into a widget** | AC-6 mounts band segments as clickable widgets carrying file-derived entropy runs | Segment content already passes `safe_text` (`:1980`) — C-17 markup safety preserved verbatim; the change adds an address window, not new text. |
| **`user input` (change doc)** | AC-7 exercises change-document resolution from two entry points | **Read-only test**; both paths already resolve through the reused `_resolve_manifest_entry` containment seam. The test must NOT fork that seam — asserting convergence is the point. |

---

## 7. Increments

| Inc | Content | Files (≤5) | AC |
|---|---|---|---|
| 1 | Universal paste A — `app.py` (8), `command_bar.py` (3) + census/behaviour tests | 3 | AC-1, AC-2 |
| 2 | Universal paste B — `screens.py` (3), `screens_directionb.py` (1), `crc_designer_view.py` (1) | 3-4 | AC-1 |
| 3 | N4a — click-chain split on `RegionRow` + counterfactual AT | 2 | AC-3, AC-4, AC-5 |
| 4 | N4b — band segments reuse `RegionRow`; gaps stay inert | 2 | AC-6 |
| 5 | FB-P2 — dual-entry convergence test + docs | 2-3 | AC-7 |

Close: full suite + snapshots (AC-8), backlog reconciliation, PR.
