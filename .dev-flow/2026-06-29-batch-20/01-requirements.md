# 01 — Requirements — batch-20 (D-1 + D-2 declared-region cleanup)

> Status: **Phase 0 (intake/DoR)**. §2.6 below is the Phase-0 artifact; §3/§4/§5 are derived in Phase 1 only from `READY` stories.
> Language: English. Normative keyword: `shall` (HLR/LLR only).

## 1. Purpose
Close batch-19's declared-region line: persist declared regions through the project save/load UI (D-1), and stop silently dropping mistyped region lines (D-2). The serialization layer (read/write `project.json` with `declared_regions`) shipped in batch-19; this batch wires it to the UI and adds skipped-line feedback.

## 2. Context

### 2.4 Constraints
- Engine-frozen set OFF-LIMITS: `core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py`. `validation/model.py` (incl. `_scrub_issue_message`) is read-only.
- Touchable surfaces (disk-verified, Phase-0 spike): `app.py`, `screens.py`, `styles.tcss` are open. `services/manifest_writer.py` + `services/variant_execution_service.py` ALREADY carry `declared_regions` (read-only reuse — no change needed). ≤5 files/increment.

### 2.5 Assumptions and dependencies (spike-verified)
- `write_project_manifest` / `serialize_manifest` (`manifest_writer.py:386 / :225`) already accept `declared_regions` and emit the key only when non-empty (back-compat) — **VERIFIED** `manifest_writer.py:330-334, 393`.
- `read_project_manifest` already returns `ProjectManifest.declared_regions` (re-scrubbed via `_parse_manifest_declared_regions`) — **VERIFIED** `variant_execution_service.py:201, 295-361, 539-541`.
- `DeclaredRegion.__post_init__` scrubs+caps `name` via `_scrub_issue_message` at construction — **VERIFIED** `report_addendum.py:72-90`. ⇒ data written to `project.json` and re-read is scrubbed at both ends; D-1 introduces NO new unscrubbed external-write surface.
- No app-level declared-region state exists today (`S19TuiApp` has none) — **VERIFIED** (Explore grep). D-1 must add one as the single source of truth.

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-024 | As an s19tool operator, I want the memory regions I declare in the Reports dialog to be saved with my project and restored when I reopen it, so that I don't have to retype them every session. | BACKLOG D-1 (batch-19 follow-on) | READY |
| US-025 | As an s19tool operator, I want to be told when region lines I typed were skipped as malformed/invalid, so that a mistyped region isn't silently dropped from my report. | BACKLOG D-2 (batch-19 Inc3 reviewer F1) | READY |

#### Refinement log

**US-024 — Declared regions survive project save/load through the UI**
- **INVEST:** I ✓ (independent of D-2) · N ✓ · V ✓ (removes per-session retyping) · E ✓ (surfaces mapped) · S ✓ (serialization already shipped; only UI wiring) · T ✓ (observable: pre-filled TextArea on load; `project.json` on disk after save).
- **Functionality:** user = operator using saved projects · outcome = regions declared in the Reports dialog persist to `project.json` on project-save and pre-fill the Reports dialog's region TextArea on project-load · why = no retyping across sessions · out of scope = adding regions anywhere other than the Reports dialog; auto-saving without an explicit project-save; merging/deduping regions.
- **Feasibility:** path = (save) thread a new `self._declared_regions` app attribute → `_write_and_verify_manifest` → existing `write_project_manifest(declared_regions=)`; (load) capture `manifest.declared_regions` into `self._declared_regions` in `_handle_load_project`, seed it into `ReportViewerScreen` at `action_view_reports` push + pre-fill the TextArea in `compose()`. Dependencies = serialization layer (shipped). Fits one batch ✓ (≈2 increments: save, load).
- **Evaluability (black-box):** AT — "When a project is loaded whose `project.json` carries `declared_regions`, the operator observes those regions pre-filled in the Reports dialog TextArea." AT — "When the operator declares regions in the Reports dialog, generates, then saves the project, the on-disk `project.json` carries those regions." (Round-trip: load→dialog→edit→generate→save→reload.)
- **Capture point (RESOLVED, operator @ DoR gate):** **Option A — capture into `self._declared_regions` when `GenerateRequested` fires.** Reuses the existing data flow; no new message. Known/accepted edge: regions typed but never used to generate are not saved (a region "counts" once generated with). This becomes a stated assumption + an AT boundary case (type-without-generate ⇒ not persisted).
- **Classification:** `READY`.

**US-025 — Operator sees a count of skipped region lines**
- **INVEST:** I ✓ · N ✓ · V ✓ (no silent data loss) · E ✓ · S ✓ (≈1 increment) · T ✓ (observable status/notify).
- **Functionality:** user = operator typing regions · outcome = when ≥1 region line is skipped as malformed (wrong field count) or invalid (bad number / failed `DeclaredRegion` validation), a status/notify message states how many were skipped · why = a mistyped region isn't silently dropped · out of scope = per-line error detail/location (D-2 is a count only; line-level detail stays a future item); blank lines (intentional spacing) do NOT count as skipped.
- **Feasibility:** path = `_parse_declared_regions` (`screens.py:543`) returns `(regions, skipped_count)` counting only malformed+invalid (not blank); `on_button_pressed` surfaces the count via the existing `set_status`/`notify` idiom before/at dismiss. Bounded callers: the one handler + one batch-19 direct test (`test_tui_report_seam.py:350`, TC-024.5) updated. Fits one increment ✓.
- **Evaluability (black-box):** AT — "When the operator enters a region TextArea containing a malformed line and presses Generate, the operator observes a status/notify message reporting the skipped-line count." Negative: all-valid input ⇒ no skip message.
- **Open questions:** surface choice — RESOLVED in Phase 1 = `self.notify(...)` from within `ReportViewerScreen` (modal frontmost, no extra app hop; reversible — confirm at Phase 3). Count = malformed+invalid only; blank lines excluded.
- **Classification:** `READY`.

---

## 3. High-level requirements (HLR)

> D-1 is split into two HLRs (SAVE-persist, LOAD-prefill): disjoint seam sets, separate ≤5-file increments, independent verification targets. D-2 is the third. **ID scheme:** HLR continues from batch-19's HLR-026 → HLR-027/028/029. AT/TC ids are batch-unique, tied to these HLRs (AT-027*/028*/029*, TC-027.*/028.*/029.*) to avoid colliding with batch-19's AT-024*/025*/026* + TC-024.*.

### HLR-027 — Declared regions persist to `project.json` on project SAVE  ·  traces US-024 (SAVE half)
- **HLR-027 (capture, Event-driven):** When a `GenerateRequested` message fires, the system **shall** store `tuple(message.declared_regions)` into `self._declared_regions`.
- **HLR-027 (persist, Event-driven):** When the operator triggers a project SAVE, the system **shall** write the regions held in `self._declared_regions` to the `declared_regions` key of the project's `project.json`.
- **HLR-027 (back-compat, Unwanted):** If `self._declared_regions` is empty at SAVE time, then the system **shall** emit a `project.json` byte-identical to the pre-batch-20 output (the `declared_regions` key is omitted — already the shipped serializer behavior, `manifest_writer.py:330-334`).
- **Observable deliverable:** on-disk `project.json` under the saved project dir contains `declared_regions: [{name,start,end},…]` equal to the generated regions; byte-identical (no key) when none generated. **Oracle:** `read_project_manifest(project_dir).declared_regions`.
- **Executed-verification:** `tests/test_tui_report_seam.py::test_save_persists_declared_regions` (AT-027a) + `::test_save_without_regions_byte_identical` (AT-027c) + white-box TC-027.1/.2/.3.

### HLR-028 — Declared regions pre-fill the Reports dialog on project LOAD  ·  traces US-024 (LOAD half)
- **HLR-028 (capture, Event-driven):** When the operator LOADs a project whose `project.json` carries `declared_regions`, the system **shall** set `self._declared_regions = tuple(manifest.declared_regions)`.
- **HLR-028 (seed, Event-driven):** When the operator subsequently opens the Reports dialog, the system **shall** seed the `#report_declared_regions` TextArea with one `name,start,end` line per held region, in stored order, in a form `_parse_declared_regions` re-accepts (round-trip idempotent).
- **Observable deliverable:** after LOAD + open Reports, `#report_declared_regions` `.text` equals the stored regions formatted `name,start,end\n…`, matching what was saved. **Oracle:** the TextArea `.text` under Pilot.
- **Executed-verification:** `tests/test_tui_report_seam.py::test_load_prefills_declared_regions` (AT-028a gate) + `::test_load_seed_guard` (AT-028b) + white-box TC-028.1/.2.

### HLR-029 — Operator sees a count of skipped region lines  ·  traces US-025
- **HLR-029 (surface, Event-driven):** When report generation is triggered and `_parse_declared_regions` skips ≥1 non-blank line (wrong field count OR failed `DeclaredRegion`/`int` parse), the system **shall** surface a `notify` message stating the number of skipped lines.
- **HLR-029 (blank exclusion, Unwanted):** If a skipped line is blank/whitespace-only, then the system **shall not** include it in the count.
- **HLR-029 (clean case, Unwanted):** If zero lines are skipped, then the system **shall not** surface a skip message.
- **Observable deliverable:** an on-screen `notify` message whose text reports the skipped-line count (assert the *number*, not exact prose); absent when count is 0. **Oracle:** the app notify/log channel under Pilot.
- **Executed-verification:** `tests/test_tui_report_seam.py::test_skipped_region_lines_counted` (AT-029a/b/c) + `::test_no_skip_no_message` (AT-029d) + white-box TC-029.1/.2.

**`should`-misuse check: PASS** — every normative statement above uses `shall`/`shall not`. **Engine-frozen check: PASS** — touched files (`app.py`, `screens.py`, `styles.tcss` n/a, `tests/test_tui_report_seam.py`) are outside `_ENGINE_PATHS`; `report_addendum.py`, `manifest_writer.py`, `variant_execution_service.py` reused read-only.

### 3.x C-13 geometry-budget / reuse-transfer finding
**Geometry N/A — no new persistent affordance.** D-1 LOAD seeds the **existing** `#report_declared_regions` TextArea (`screens.py:683`, `styles.tcss:828-833` height:5, already scrolls past 5 lines on typed input) — seeding `.text` adds content, not footprint. D-1 SAVE adds no widget (state + serialization only). D-2 reuses the **existing** `notify` surface — a transient toast, no layout cell. No 80/120-col budget computation required because no new always-on widget lands in a constrained row. Reuse-transfer: the height:5 box was validated in batch-19 for operator typing; seeding N loaded lines is the same container under the same constraint → proven geometry transfers, no re-measure.

---

## 4. Low-level requirements (LLR)

> Dependency order: **Increment A = HLR-027 (SAVE)** → **Increment B = HLR-028 (LOAD, depends on A's `self._declared_regions`)** → **Increment C = HLR-029 (D-2, independent, bundled last)**. Each ≤5 files.

### Increment A — HLR-027 (SAVE)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-027.1** | The system shall declare app state `self._declared_regions: Tuple[DeclaredRegion, ...] = ()`. | `app.py` (init, near other `self._…` snapshot state) | **NEW** | New attribute; no signature change. |
| **LLR-027.2** | When `on_report_viewer_screen_generate_requested` receives `GenerateRequested`, the system shall assign `self._declared_regions = tuple(message.declared_regions)` before dispatch. | `app.py:1862-1885` | **MODIFY** | One assignment in existing handler; no signature change. |
| **LLR-027.3** | When a project SAVE is handled, the system shall pass `declared_regions=self._declared_regions` from `_handle_save_dialog` into `_write_and_verify_manifest`. | `app.py:3770-3774` | **MODIFY** | Call-site arg add. |
| **LLR-027.4** | `_write_and_verify_manifest` shall accept `declared_regions: Sequence[DeclaredRegion] = ()` and forward to `write_project_manifest`. | `app.py:3778-3838` | **MODIFY** | **Signature change** — keyword-only defaulted; existing callers stay valid. `write_project_manifest` accepts it already (`manifest_writer.py:386`, read-only). |

**`SaveProjectPayload` does NOT change** — Option A captures from `self._declared_regions`, not the Save dialog payload (which never collects regions). Payload contract frozen.

### Increment B — HLR-028 (LOAD)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-028.1** | When `_handle_load_project` reads the manifest, the system shall set `self._declared_regions = tuple(manifest.declared_regions)`. | `app.py:3934` | **MODIFY** | One assignment beside existing `active_variant` use; `read_project_manifest` read-only. |
| **LLR-028.2** | When `action_view_reports` constructs the viewer, the system shall pass `declared_regions=self._declared_regions`. | `app.py:1860` | **MODIFY** | Call-site arg add (depends on LLR-028.3). |
| **LLR-028.3** | `ReportViewerScreen.__init__` shall accept `declared_regions: Tuple[DeclaredRegion, ...] = ()` and store it. | `screens.py:658` | **MODIFY** | **Signature change** — defaulted 3rd param; existing 2-arg constructions at `screens.py:620` (doctest) **and `tests/test_tui_report_seam.py:372`** stay valid via the default (architect MINOR-2 census addendum). |
| **LLR-028.4** | When `compose` builds the dialog, the system shall seed `TextArea(id="report_declared_regions")` with `"\n".join(f"{r.name},{r.start},{r.end}")` over held regions (decimal ints, re-parseable by `int(x,0)`). | `screens.py:683` | **MODIFY** | TextArea gets initial `text=`; CSS unchanged. Seed MUST be the inverse of `_parse_declared_regions` (round-trip idempotence). |

### Increment C — HLR-029 (D-2)
| LLR | Statement | Disk target | Flag | Contract-touch |
|---|---|---|---|---|
| **LLR-029.1** | `_parse_declared_regions` shall return both the parsed regions and a count of skipped non-blank lines. | `screens.py:551-578` | **MODIFY** | **Return-type change** `Tuple[DeclaredRegion,...]` → `Tuple[Tuple[DeclaredRegion,...], int]`. Blank `continue` (`:567-568`) stays uncounted; increment counter at the two skip sites (`:570-572`, `:574-577`). |
| **LLR-029.2** | The single internal caller `on_button_pressed` shall unpack the new return shape and post `GenerateRequested` with regions only. | `screens.py:781` | **MODIFY** | Caller update forced by LLR-029.1. `GenerateRequested.declared_regions` contract unchanged (carries regions only). |
| **LLR-029.3** | When skip-count ≥1, the system shall surface it via `self.notify(...)` with text stating the count; when 0, shall not surface. | `screens.py` `on_button_pressed` | **MODIFY** | In-screen `self.notify`; no new widget, no app handler. |
| **LLR-029.4** | The existing direct test of `_parse_declared_regions` shall be updated to the new return shape. | `tests/test_tui_report_seam.py:350` (batch-19 TC-024.5) | **MODIFY** | **Fail-loud:** the return-shape change breaks this batch-19 test; updating it (unpack `(regions, skipped)`) is the signal the contract moved. This is the ONE batch-19 test the bundle modifies. |

**Caller-count check (done at Phase-1):** `git grep _parse_declared_regions` = exactly 2 callers — `screens.py:781` + `tests/test_tui_report_seam.py:350`. No missed second caller; signature change is bounded.

**File-count:** Inc A = `app.py` (1). Inc B = `app.py` + `screens.py` (2). Inc C = `screens.py` + `tests/test_tui_report_seam.py` (2). All ≤5. New AT cases land in the existing `tests/test_tui_report_seam.py` — no new test file.

---

## 5. Acceptance & traceability

### 5.2 Dual traceability (behavioral AT + functional TC)

**US-024 (D-1) — behavioral (black-box):**
- US-024 → **AT-028a** (THE GATE, C-12) → real save→disk→fresh load→open dialog ⇒ TextArea shows exact regions → *surface: `#report_declared_regions` `.text` asserted against a **LITERAL** expected string (e.g. `"bootblk,4096,4351\ncal,32768,33023"`), hand-computed in the test — NOT derived by calling the production seed helper (qa minor-2: avoid the both-sides-move tautology)*
- US-024 → **AT-027a** → Generate+Save ⇒ `read_project_manifest().declared_regions` == exact tuple `(DeclaredRegion("bootblk",0x1000,0x10FF), DeclaredRegion("cal",0x8000,0x80FF))` (C-10 exact content, not `len>0`) → *surface: on-disk project.json*
- US-024 → **AT-028b** (GUARD, in addition, never the gate) → hand-written project.json `declared_regions` ⇒ load seeds TextArea → *surface: TextArea `.text`* (stays green under reverted save handler ⇒ cannot be the gate)
- US-024 → **AT-027b** (boundary) → typed-but-NOT-generated ⇒ `read_project_manifest().declared_regions` empty → *surface: on-disk project.json* (Option-A capture boundary)
- US-024 → **AT-027c** (negative/back-compat) → no regions ⇒ `declared_regions` key omitted + legacy no-key project loads + empty TextArea → *surface: manifest key absence + TextArea*

**US-024 — functional (white-box):**
- HLR-027 → LLR-027.2/.3/.4 → **TC-027.1** save threads `self._declared_regions` → `_write_and_verify_manifest` → `write_project_manifest` (regions reach the writer).
- HLR-027 → LLR-027.4 → **TC-027.2** `_write_and_verify_manifest` signature accepts defaulted `declared_regions=()` (existing callers valid).
- HLR-027 → LLR-027.1 → **TC-027.3** back-compat: empty `self._declared_regions` ⇒ project.json key omitted / byte-identical (0-byte delta vs baseline).
- HLR-028 → LLR-028.1/.4 → **TC-028.1** `_handle_load_project` sets `self._declared_regions`; seed maps regions → TextArea text.
- HLR-028 → LLR-028.4 → **TC-028.2** seed format is the inverse of `_parse_declared_regions` (seed text re-parses to the same tuple — idempotence).

**US-025 (D-2) — behavioral (black-box):**
- US-025 → **AT-029a** (malformed branch) → `good,…\nbad line` ⇒ notify message contains the standalone token `1` (regex `\b1\b`, qa minor-1 — guards against "Skipped 0 of 1 lines" passing spuriously) → *surface: notify channel*
- US-025 → **AT-029b** (invalid branch) → `good,…\nrev,0x20,0x10` (start>end ⇒ ValueError) ⇒ notify message contains the standalone token `1` (`\b1\b`) → *surface: notify channel*
- US-025 → **AT-029c** (boundary) → `valid + malformed + blank + invalid` ⇒ notify count == 2 (blank excluded) → *surface: notify channel*
- US-025 → **AT-029d** (negative) → all-valid AND empty input ⇒ NO skip message (assert absence, not "0") → *surface: notify channel*

**US-025 — functional (white-box):**
- HLR-029 → LLR-029.1 → **TC-029.1** `_parse_declared_regions` returns `(regions, skipped)` distinguishing malformed vs invalid vs blank-excluded.
- HLR-029 → LLR-029.3 → **TC-029.2** zero-suppression guard: count surfaced only when `skipped > 0`.

> All AT/TC ids are **provisional-until-Phase-3 (V-5)** — reconciled to the real collected nodes at Phase 4.

### 5.3 Validation method per requirement
| Req | Method | Justification |
|---|---|---|
| AT-028a / AT-028b | test (pilot) | Round-trip + load-seed observable only by driving save+load surfaces e2e via `App.run_test()`. |
| AT-027a / AT-027b / AT-027c | test (pilot) | On-disk effect = run real save handler then read project.json via oracle (produced-artifact assertion). |
| AT-029a–d | test (pilot) | Count is a UI side effect on the running app's notify channel through Generate. |
| TC-027.1/.2/.3, TC-028.1/.2, TC-029.1/.2 | test (unit/integration) | Signature threading, seed-format inverse, parser return shape, zero-suppression — pure-Python white-box. |

No `demo`/`inspection`/`analysis` rows: every requirement has a deterministic scriptable surface (TextArea text, on-disk project.json, notify message).

### 5.4 Counterfactual table (QC-2 — every AT must be able to FAIL)
| AT-id | One-line revert | Expected |
|---|---|---|
| AT-028a | save handler doesn't thread `self._declared_regions` **or** load doesn't seed TextArea | fresh-load TextArea empty → **RED** |
| AT-027a | `_write_and_verify_manifest` drops `declared_regions` | `read_project_manifest().declared_regions == ()` → **RED** |
| AT-028b | seed function returns `""` ignoring manifest | TextArea empty → **RED** |
| AT-027b | capture moved to save/keystroke (not Generate) | typed-not-generated region persists → manifest non-empty → **RED** |
| AT-027c | save writes `declared_regions: []` key when empty | key present where omission expected → **RED** |
| AT-029a | Generate handler never surfaces the count | no message → **RED** |
| AT-029b | invalid branch (`screens.py:577`) not counted | count 0 ≠ 1 → **RED** |
| AT-029c | blank line counted, or branches double-count | count 3 ≠ 2 → **RED** |
| AT-029d | message emitted at `skipped == 0` | spurious message → **RED** (absence assertion fails) |

---

## 6. Decisions, risks, assumptions

### 6.2 Key decisions
- **D1 (capture point) = Option A** (operator, DoR): capture on `GenerateRequested`. Accepted edge → AT-027b.
- **D2 (D-1 split):** HLR-027 (save) + HLR-028 (load) as separate increments to avoid hiding a half-done state behind one trace (architect).
- **D3 (D-2 surface) = `self.notify` in-screen** (architect; reversible — confirm at Phase-3 gate). AT asserts the *number*, not exact prose, to avoid brittle string-match.
- **D4 (back-compat shape) = key omitted when empty** — already the shipped serializer behavior (`manifest_writer.py:330-334`); not a new decision. TC-027.3 + AT-027c assert it.
- **D5 (SaveProjectPayload frozen):** regions come from `self._declared_regions`, payload unchanged.
- **D6 (id scheme):** batch-20 AT/TC tied to HLR-027/028/029 to avoid batch-19 collision (AT-024*/025*/026*, TC-024.*).

### 6.3 Risks / watch-items
- **Back-compat drift (fail-loud):** if any path sets `self._declared_regions` to a non-empty default/sentinel, the empty-key suppression breaks and existing projects' manifests drift on next save. Mitigation: AT-027c asserts 0-byte delta.
- **Return-type break is intentional + bounded:** LLR-029.1 breaks batch-19 TC-024.5 (`test_tui_report_seam.py:350`) + the one caller — both in the Inc-C modify set (LLR-029.2/.4). Caller count re-verified = 2.
- **Security (Phase-2 GRANTED):** D-1 round-trips region NAMES scrubbed at `DeclaredRegion.__post_init__` + re-scrubbed on read (`report_addendum.py`, `variant_execution_service.py`). Save writes already-scrubbed names to project.json; load re-scrubs hand-edited/malicious project.json through the `DeclaredRegion` constructor. The scrub strips `\n`/`\r`/control chars (`validation/model.py:20` `[\x00-\x1f\x7f]`) ⇒ a name **cannot** contain a newline ⇒ the `"\n".join(...)` seed cannot smuggle an extra line/region; Textual `TextArea.text` renders raw text (no Rich-markup interpretation). No NEW unscrubbed external-write surface. **Phase-3 carry (security F2):** D-2 notify stays **count-only** — do NOT interpolate the offending line text into the toast (it renders pre-scrub).
- **Comma-in-name round-trip (architect MINOR-1 / security F1 — LOW, no security impact):** commas survive the scrub (not control chars), so a region named `cal,x` is valid in app state + project.json but, when seeded `name,start,end` and re-parsed, splits to 4 parts ⇒ dropped from the seeded TextArea AND — now that D-2 ships — counted as a *visible* skipped line on the next Generate. Worst case = one fewer region (data loss, never injection/escalation). **Scoped OUT this batch:** no comma-escaping introduced; stated assumption — operators don't use commas in region names; D-2's skip-count surfaces it. Logged for BACKLOG if it recurs.

### 6.4 Reconciliation log

**Phase-2 cross-review (architect ∥ qa ∥ security) — 0 blockers; architect PROCEED, qa PROCEED, security GRANTED. Folds APPLIED body-first:**
- **F-A1 (architect MINOR-1 + security F1):** comma-in-name lossy round-trip — §6.3 updated: D-2 makes it a *visible* skip-count; scoped OUT (no escaping); stated assumption + BACKLOG-if-recurs. Security: LOW, no injection/escalation.
- **F-A2 (architect MINOR-2):** §4 LLR-028.3 contract-touch now enumerates the `tests/test_tui_report_seam.py:372` 2-arg construction (safe via default) alongside the `:620` doctest.
- **F-Q1 (qa minor-1):** §5.2 AT-029a/b assertion tightened to a standalone-token match (`\b1\b`) — guards against a count substring passing spuriously.
- **F-Q2 (qa minor-2):** §5.2 AT-028a now asserts `.text` against a hand-computed LITERAL string, not a reconstruction via the production seed helper (anti-tautology).
- **Supersession census (architect, change-first):** all 3 signature changes bounded — `ReportViewerScreen(` = 2 prod + 2 test (all safe via default), `_write_and_verify_manifest` = 1 caller, `_parse_declared_regions` = 2 usages (both in Inc-C modify-set). 0 frozen-file edits.
- **Security GRANTED (batch-19 catch defended):** Q1 save writes construction-scrubbed names; Q2 load re-scrubs malicious project.json via the `DeclaredRegion` ctor; Q3 newline impossible (scrub strips `\n`) + TextArea is raw-text (no markup); Q4 no new external-write surface beyond project.json; Q5 D-2 notify is count-only.

**Phase-3 carries (not spec defects — implementer notes):**
- **C-P3a (qa):** `tests/test_tui_report_seam.py` has NO notify-capture helper — Inc-C ATs must port `_notices()` from `tests/test_tui_manifest_save.py:64-78` (install BEFORE the Generate press). `Widget.notify`→`app.notify`, so the patch observes a Screen's `self.notify`.
- **C-P3b (security F2):** keep D-2 `self.notify` text count-only — do NOT interpolate the offending line (toast renders pre-scrub).
- **C-P3c (architect):** confirm at implement that `declared_regions` threads into `write_project_manifest` only (NOT also `verify_written_manifest`, which re-reads the file as oracle).

