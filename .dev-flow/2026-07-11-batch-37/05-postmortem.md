# 05 — Post-mortem (Phase 5) — 2026-07-11-batch-37

> **BLUF.** Batch-37 shipped the full P2 backlog (B-11..B-14 → 5 stories US-061/062/063/064a/064b)
> **clean, autonomous, self-merge**: 8/8 black-box ATs green, 10/10 white-box nodes, gate
> **1358 passed / 0 failed**, ledger **1369→1385 (+16)**, engine-frozen **0 diffs** across all
> increments. The V-model earned its keep twice — Phase 2 caught the **US-064b file-loaded
> data-loss footgun (A-01)** and converted a limited MVP into a *safe* one via a disable-guard;
> Phase 4's whole-suite gate caught the one escaped defect, a **cross-file census miss (TC-319)**,
> fixed test-only in-phase with zero shipped impact. Two friction root-causes, both process not
> product: (1) increment briefs scoped the "one complete run" to each story's HOME test file, so a
> sibling census pinning the same surface slipped every per-increment gate; (2) a draft-time
> spec-premise error (S-01) claimed `#patch_paste_text` routes through the clipboard funnel when it
> is a plain `TextArea`. Both were caught by the process (Phase 4 / the dev), neither shipped. **No
> scope drift.** One control candidate proposed (C-CAND-A, TC-319 census cross-file sweep — a C-14
> extension), plus one smaller candidate — proposed, **not encoded**.

Lenses: **architecture** (design integrity, seams, reversibility, lock-in) + **QA/testability**
(two-layer traceability, counterfactuals, census discipline). Run mode: **Autonomous + self-merge**
(operator grant, batch-37-only; per `feedback_standing_auth_per_batch` re-ask at B-38).

---

## 1. What worked

**Phase-2 review caught a DATA-LOSS footgun before a line of code (A-01).** The US-064b JSON popup
as originally specced would seed from `#patch_paste_text` — which still holds `DUMMY_CHANGESET_TEXT`
after a file load (a file load only refreshes the entries table, never the paste buffer) — and
Confirm would `load_text`-REPLACE the loaded document = **silent data loss**
(`02-review.md` A-01; `01-requirements.md:874-899` DF-2). This is exactly the class of design gap
the black-box review is meant to surface: the acceptance boundary "no-op re-parse" was *factually
false* in the file-loaded state. The fold turned a limited MVP into a **safe** one — a two-layer
disable-guard (`document.source_path is not None → Edit-JSON disabled`, plus a defense-in-depth
handler re-check before push) with a dedicated boundary AT (AT-064c) proving 0 mutation on a guarded
open (`increment-005.md §1`; `04-validation.md §3` AT-064c). Architecturally the right call: it
closes the footgun *at the trigger* rather than half-building a `document→JSON` serializer that
`ChangeService` doesn't have — the unsafe path is made unreachable, not patched downstream.

**The C-16 novel `pilot.click` mechanism landed clean — first in the suite.** US-063's clickable
entropy strip is the first real `await pilot.click(...)` end-to-end assertion in the whole test
suite (zero prior precedent). Phase 2 de-risked it by demoting the unproven rung-1 (`@click`-meta
offset arithmetic on a wrapped single `Static`) and promoting **rung-2 per-cell clickable widgets
to the BASELINE** (`02-review.md` Q-03/A-05; `01-requirements.md:586`). Inc-4 shipped it with the
remap proven under a **non-default sort** (`cell_0 → 0x1200` entropy-sorted, not raw `_windows[0]`)
and a shrunken page slice — a genuinely load-bearing test, not a happy-path click (`increment` gate
notes, Inc-4; `04-validation.md §3` AT-063b). Testability win: a deterministic per-cell widget id
(`#entropy_cell_k`) is a durable surface; offset math would have been a brittle one.

**The page-size-512 pin resolved a real AT/LLR contradiction (A-02/Q-01).** US-062's spec was
self-contradictory — the LLR said page size = a small pilot-measured body budget while the ATs
assumed 512/page; a ~15-row body would put window index ≥512 on page ~34, **unreachable by one
`next`** (`02-review.md` A-02; `01-requirements.md:995`). The fold **pinned page size = 512 FIXED**
(the pre-existing `MAX` cap becomes the per-page window budget; pilot-measure governs only
control/legend geometry). This removed the contradiction *and* kept computation untouched — paging
and sort are pure display transforms over the once-computed `self._windows` snapshot
(`01-requirements.md:854` P9). Clean separation of concern, no engine reach-through.

**The Phase-4 whole-suite gate caught the TC-319 cross-increment regression.** The one escaped
defect (a sibling census pinning the same `#patch_doc_controls`) slipped every per-increment gate
and was caught **only** by the C-25 orchestrator-owned whole-suite run — which is precisely the
safety net that gate exists to be (`04-validation.md §7`; state.json Phase-4 entry). It failed
loud, was fixed test-only, and re-ran clean.

**C-23 geometry was pilot-MEASURED throughout — no F-01 repeat.** Every geometry-bearing surface
(entropy controls/legend, the JSON popup) was measured via `App.run_test(size=...)`, never
fr-estimated. The popup measured **N_80 = 7 / N_120 = 13** editable lines (`increment-005.md`
C-23 block), discharging the batch-36 F-01 deferral (the height-starved in-panel box that could
show ~0-1 lines at 80 cols) with a full-screen modal that is readable even at 80. Zero geometry
surprises this batch — the batch-36 lesson held.

**C-25 (orchestrator-owned Phase-4 gate run) — encoded last batch — was applied and worked.** The
whole-suite gate was run by the orchestrator, not delegated into a backgrounded harness, and it is
what surfaced TC-319. The control encoded in response to batch-35/36's harness-backgrounding
recurrence did its job on first application.

---

## 2. What didn't / friction — root-caused

Two frictions. Both are **process defects caught by the process** — neither shipped a product
defect. Root-cause each:

### F-1 · TC-319 cross-file census miss (Phase-4-caught, orchestrator-fixed)
- **What:** Inc-1 added `#patch_doc_refresh_button` to `#patch_doc_controls` and dutifully updated
  its HOME-file census (`test_at057a_...` in `test_tui_patch_editor_v2.py`) — but NOT the **sibling**
  census `test_tc319_regroup_section_structure_census` in `test_tui_patch_layout.py`, which pins the
  SAME `#patch_doc_controls` child order in a *different file*. The additive button broke the sibling
  pin. It slipped Inc-1's gate and every subsequent per-increment gate, surfacing only on the
  Phase-4 whole-suite run (`04-validation.md §7`; `increment-001.md §5`).
- **Root cause:** the increment briefs scoped the increment's "one complete run" to the story's
  **home test file** (Inc-1's run was `pytest tests/test_tui_patch_editor_v2.py`), not to *every
  file that pins the touched surface*. This is an **orchestrator-owned brief defect** — the census
  discipline (C-14 family) was applied to the home file but the sweep was never widened to
  same-surface sibling pins. Nothing in the increment brief told the dev to grep the touched id
  across all of `tests/` before closing.
- **Cost / severity:** LOW. Test-only supersession (added `patch_doc_refresh_button` to TC-319's
  expected list, matching the SHIPPED Load/Refresh/… order — a behaviour-tracking update, not a
  weakened assertion); clean re-run; zero shipped defect; zero rework beyond the one test edit.
- **Drives:** C-CAND-A (§7).

### F-2 · S-01 spec-premise error (draft-time verification miss, dev-caught)
- **What:** LLR-064b.1 asserted `#patch_paste_text` "routes paste through the `os_clipboard_input`
  65 536-char funnel." It does not — `#patch_paste_text` is a plain `TextArea` using Textual's native
  bracketed-paste path, not an `OsClipboardInput`. The dev caught the false premise while
  implementing, mirrored the existing widget class faithfully (adding **no** new/second uncapped
  ingress — the true normative intent), and **flagged the deviation explicitly** rather than
  silently reconciling (`increment-005.md §5`; `04-validation.md §6.3`; state.json Inc-5 entry).
- **Root cause:** a **draft-time verification miss** — a spec claim about an *existing widget's
  class* was written without checking the class. The Phase-2 architect re-verified many seams
  (DF-2 no-serializer, C-16 real-click, all cited line numbers) but did not re-verify this
  particular widget-class claim; it survived to Inc-5.
- **Cost / severity:** LOW. The process worked — the dev's read-before-write (Engineering Rule 8)
  caught it, the discharge was faithful to intent, and it was surfaced not buried. It exposed a
  **real pre-existing backlog gap**, though: neither `#patch_paste_text` *nor* the new
  `#changeset_json_text` popup caps native bracketed paste at 64 KiB (the 65 KiB funnel guards a
  *different* ingress). US-064b added no new uncapped ingress, so this is a **separate pre-existing
  backlog item**, not a batch-37 regression (§6).

---

## 3. Scope drift

**None.** Two events could be mistaken for drift; both are recorded *decisions*, not creep:

1. **US-064 split into US-064a (refresh) + US-064b (popup)** — flagged as a possibility at Phase 0
   ("may split"), confirmed at Phase 1 (`01-requirements.md:107`, D-SPLIT `:916`). Independent,
   differently-shaped stories; splitting sharpened the increment cut, it didn't widen scope.
2. **US-064b scoped to the paste-buffer MVP** — an **autonomous DECISION recorded at Phase 1**
   ("US-064b JSON popup edits the PASTE BUFFER (MVP); `ChangeService` has no `document→JSON`
   serializer, so file-loaded round-trip is OUT unless operator wants a separate serializer story
   (DF-2)" — state.json Phase-1 entry; `01-requirements.md:874` DF-2). The A-01 guard makes the
   out-of-scope path *unreachable-and-safe* rather than half-built. This is a scope *narrowing*
   with an explicit operator-flaggable note, the opposite of drift.

The ≤5-files-per-increment cap held every increment (3/3/4/4/5). Out-of-scope carries (B-16..B-19,
Bookmarks, hygiene) stayed out.

---

## 4. Metrics

| Dimension | Value |
|-----------|-------|
| **Stories shipped** | 5 (US-061/062/063/064a/064b ← B-11/12/13/14; US-064 split a/b) |
| **Iterations per phase** | Phase 0: 1 · Phase 1: 1 · **Phase 2: 2** · **Phase 3: 5** · Phase 4: 1 · Phase 5: 1 |
| **Phase-2 findings** | **1 blocker (A-01) + 3 majors (A-02/Q-01, Q-02, Q-03/A-05) + 5 minors/lows (A-03, A-04/Q-06, Q-04, Q-05, Q-07) + 4 security LOW (S-01..S-04)** — **ALL folded** into `01-requirements.md §6.5`; 0 stories killed; security PASS (0 HIGH/MEDIUM) |
| **Increment reviews (5)** | **0 HIGH** across all five; ~9 LOW carried (Inc-1 F1; Inc-2 F1/F2; Inc-3 F1/F2; Inc-4 F1/F2; Inc-5 F1) |
| **Phase-4 findings** | **1 caught + fixed in-phase** (TC-319 cross-file census miss, test-only, 0 shipped defect) |
| **Black-box ATs** | **8/8 green** (AT-061a/062a/062b/063a/063b/064a/064b/064c), each → exactly ONE on-disk node (C-18), real counterfactual (C-20), deliverable observed through shipped surface (C-10/C-12) |
| **White-box nodes** | **10/10 green** (TC-324..331 + TC-319 + AT-036b regression guard) |
| **Test ledger** | **1369 → 1385 (+16, 0 deletions)** — per-increment: 1371/1373/1377/1381/1385 |
| **Gate run (C-25)** | `pytest -q -m "not slow"` → **1358 passed / 2 skipped / 20 deselected / 5 xfailed / 0 failed** (exit 0, 11:56); ledger reconciles (1365 run + 20 deselected = 1385) |
| **xfail set (5)** | 2 batch-37 entropy snapshot cells (canonical-CI regen post-merge) + 3 pre-existing unrelated — no regression |
| **Engine-frozen** | **0 diffs** across ALL 5 increments (all code landed in non-frozen `screens.py`/`screens_directionb.py`/`app.py`/`styles.tcss`) |
| **Run mode** | **Autonomous + self-merge** (operator grant, batch-37-only) |

---

## 5. Root causes where multiple iterations occurred

**Only Phase 2 took >1 iteration (2).** The sequence was `iterate-to-refine` → amendment fold →
`re-gate after fold`. Root cause: the **A-01 data-loss blocker** was the driver — a genuine design
gap (unsafe file-loaded seed) that demanded a guard + a new boundary AT (AT-064c) + LLR (064b.4),
which in turn forced the AT registry to reconcile from 7→8 ATs (`01-requirements.md:827`). The three
majors (page-size contradiction, two-truncation-nodes, unproven rung-1 click) rode the same fold.

**Was it avoidable?** No — and it *should not* be avoided. The V-model is designed so the review
gate catches design-level footguns *before* implementation; A-01 is the review doing exactly its
job. A single fold iteration to convert 1 blocker + 3 majors + 9 lower findings into a coherent,
re-verified spec is cheap insurance against shipping a data-loss bug. The process working as
intended, not a defect.

Phase 3's 5 iterations are the 5 planned increments (one story each), not rework loops — every
increment was APPROVE / 0 HIGH on first review. No increment was re-cut or re-done.

---

## 6. Items for next batch (B-38)

**Backlog (operator-owned pool):**
- **P3 set — B-16..B-19:** v2-path relabel (B-16), A2L >32-bit defensive warning (B-17), info
  buttons (B-18), patch undo/redo (B-19).
- **Bookmarks screen** — the dead "coming soon" rail-item-8 scaffold; the one clear TUI gap, owns
  its own batch.

**Hygiene carries (pre-existing, not batch-37):**
- **S-F7** — raw `linkage_symbol` in `report_service`.
- **`canonical_report_bytes` consolidation** (report byte-identity golden helper).
- **`__setattr__` retire.**
- **P-1 / P-2 / P-3** hygiene items.

**New / surfaced this batch:**
- **Native bracketed-paste 64 KiB cap gap (US-064-adjacent, PRE-EXISTING).** Neither
  `#patch_paste_text` nor the new `#changeset_json_text` popup caps Textual's native bracketed
  paste at 64 KiB; the 65 KiB `os_clipboard_input` funnel guards a *different* ingress
  (`04-validation.md §6.3`). Surfaced by the S-01 spec-premise correction (§2 F-2). A separate
  backlog item — batch-37 added no new uncapped ingress.
- **~9 LOW review carries** from this batch's increment reviews (Inc-1 TC-328 status-line proxy;
  Inc-2 `.press()`-not-`pilot.click` activation + distributed b-path asserts; Inc-3
  `ENTROPY_STRIP_MAX_CELLS` vestigial + drift-mark unused arg; Inc-4 page-2 click unit-only +
  deferred-mount race benign; Inc-5 `Escape` unbound on `ChangeSetJsonScreen`). All reviewer-accepted
  as non-blocking; groom if any recur.

**Owed to Phase 6 (docs):** REQUIREMENTS.md rows **R-TUI-049..053** (proposed, not yet added);
BACKLOG.md refresh (B-11..B-14 → done); docstrings/README as needed (`04-validation.md §6.4`).

**Snapshot:** 2 entropy cells (`entropy-comfortable-80x24` / `-120x30`) await **canonical-CI baseline
regen post-merge** (local regen forbidden per convention). A follow-up snapshot-baselines PR, as in
batches 35/36.

---

## 7. Candidate dev-flow controls — PROPOSED, NOT encoded

> Per `feedback_devflow_control_encode_approval`: these are **proposals**. The operator approves each
> via AskUserQuestion before it enters the C-lineage (currently C-1..C-25). Do **not** encode here.

### C-CAND-A · Census cross-file sweep (extends C-14)
- **Origin incident (this batch):** TC-319 cross-file census miss (§2 F-1; `04-validation.md §7`).
  Inc-1 added `#patch_doc_refresh_button` to `#patch_doc_controls`, updated the HOME-file census
  (`test_at057a`) but not the SIBLING census (`test_tc319_...` in `test_tui_patch_layout.py`) pinning
  the same container; it slipped every per-increment gate, caught only by the Phase-4 whole-suite run.
- **Exact rule:** *When an increment adds, moves, or removes a widget in a PINNED structure (an
  id-census or exact-child-list layout test), the increment's own test run AND the supersession
  census MUST include EVERY test file that pins the touched id, surface, or container — not only the
  story's home test file. Before closing the increment, grep the touched widget id and its parent
  container id across all of `tests/`; every file that references either must be in the increment's
  run scope and, if it asserts order/membership, superseded to the shipped state.*
- **Extends:** **C-14** (location-move census sweeps e2e observers). C-14 generalized the census to
  observers of a moved location; C-CAND-A generalizes it further to **same-surface pins in sibling
  files** — the census must be *file-complete over the surface*, not scoped to the story's home file.

### C-CAND-B · Verify existing-widget-class claims at draft time (extends C-8-family draft verification)
- **Origin incident (this batch):** S-01 spec-premise error (§2 F-2; `increment-005.md §5`). The spec
  claimed `#patch_paste_text` routes paste through the `os_clipboard_input` funnel; it is a plain
  `TextArea`. Caught by the dev at implementation, not at draft.
- **Exact rule:** *Any requirement/LLR statement that asserts a property of an EXISTING widget or
  seam (its class, the message it posts, the funnel it routes through) must be grep-verified against
  the source at draft time and the file:line cited inline — the same re-verification discipline
  already applied to cited seams — before the claim is used to justify a "no new ingress / reuses
  existing path" security or safety conclusion.*
- **Extends:** the **cited-seam re-verification** discipline the architect already runs in Phase 2
  (it re-verified DF-2, C-16, and all line numbers TRUE — this one widget-class claim slipped
  through). C-CAND-B makes existing-widget-*property* claims a mandatory line item of that same sweep,
  not just line-number existence.
- **Note:** lower-priority than C-CAND-A — the process already caught it (dev read-before-write);
  encoding is a *shift-left* to catch it at draft instead of at Inc-5. Operator may reasonably
  decline as already-covered by Engineering Rule 8.

---

## 8. Evidence checklist (architecture + QA lenses)

- [x] **Constraints stated** — run mode, ≤5 files/increment, engine-frozen off-limits, snapshot
  canonical-regen-only, C-23 pilot-measure (PLAN.md; `01-requirements.md §2.6`).
- [x] **Alternatives considered** — US-064b: paste-buffer MVP vs. `document→JSON` serializer
  (DF-2, serializer deferred as separate story); US-063 click: rung-1 offset vs. rung-2 per-cell
  widget (rung-2 chosen); US-062 page size: pilot-measured vs. fixed-512 (fixed chosen).
- [x] **Recommendations tied to constraints** — A-01 guard closes footgun at trigger without the
  absent serializer; fixed-512 removes the AT/LLR contradiction with no engine reach-through.
- [x] **Risks listed** — data-loss (A-01, closed); native-paste cap gap (pre-existing, backlogged);
  9 LOW carries; 2 snapshot cells pending canonical regen.
- [x] **Cost / latency** — N/A (TUI display transforms over a once-computed snapshot; no new API/token cost).
- [x] **Two-layer requirements** — every story has a first-class Acceptance block + `AT-NNN`; BOTH
  chains exist (behavioral US→AT→outcome §3 of `04-validation.md`; functional US→HLR→LLR→TC §2).
- [x] **Reversibility / lock-in** — all changes in non-frozen TUI modules; no new vendor/framework
  surface; test-only supersessions reversible.
- [x] **What would change the recommendation** — if an operator wants file-loaded JSON round-trip,
  the A-01 guard is lifted only *after* a `document→JSON` serializer story (DF-2) lands; the native
  64 KiB paste cap would move from backlog to in-scope if a large-paste incident occurs.

---

**Phase-5 disposition:** post-mortem complete. Metrics clean, no scope drift, 2 process frictions
both caught-not-shipped, 2 control candidates proposed (C-CAND-A primary / C-CAND-B secondary) for
operator approval, next-batch items enumerated. Recommend **proceed to Phase 6 (docs)**.
