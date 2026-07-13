# 02 — Phase-2 Independent QA Review — 2026-07-12-batch-38

> **Reviewer:** qa-reviewer (independent Phase-2 cross-review). Read fresh against the source at `5a6c45b`.
> **Inputs reviewed:** `01-requirements.md`, `01b-qa-strategy-and-verification.md`, `PLAN.md`.
> **Scope:** US-065, US-066, US-067, US-068a, US-068b · ATs 065a/066a/066b/067a/068a/068b.
> **Lane:** testability of each requirement · viability of each validation method · black-box AT quality · counterfactual soundness · C-10/C-16/C-17/C-18 compliance.

## BLUF

**1 blocker, 2 major, 4 minor.** The strategy is largely sound — every story has a black-box AT, C-16/C-17 are honored, the frozen set is respected, and the requirements-side producer path (`validation_service.build_validation_report`) is verified to actually reach the `GroupedIssuesPanel` sink. **One blocker** must be fixed before Phase 3: **AT-068b drives the wrong control** (`#patch_entry_edit_button`, the existing field-edit action), directly contradicting LLR-068b.1's mandate of a *new distinct* per-entry JSON control — as written the AT would stay RED even after a correct implementation (unsound counterfactual). Two majors are cross-document contradictions (AT-065a content target unpinned; TC-333/334/335 name the wrong producer unit vs the finalized LLR).

---

## Findings

### BLOCKER

#### F-B1 — AT-068b drives the existing field-edit button, contradicting LLR-068b.1 (unsound counterfactual)
- **Where:** `01b …verification.md` §3 AT-068b mechanism + RED-counterfactual; §4/§6 rows.
- **Evidence:**
  - 01b AT-068b mechanism: *"`await pilot.click("#patch_entry_edit_button")` (real pointer) to open the **per-entry** JSON popup"* and its RED line: *"the per-entry `Edit` button (`#patch_entry_edit_button`, screens_directionb.py:1886) exists but opens no JSON popup."*
  - Source: `screens_directionb.py:1886` is `Button("Edit", id="patch_entry_edit_button")` in the Add/Edit/Remove row, and `screens_directionb.py:2230` maps `"patch_entry_edit_button": "edit_entry"` — i.e. this button already performs the field-populate `edit_entry` action.
  - Requirements LLR-068b.1 explicitly mandates a **NEW distinct** control (`#patch_entry_edit_json_button`) and states the existing `#patch_entry_edit_button` is **unchanged** with *"no hijack of the existing per-entry Edit action `edit_entry` at `screens_directionb.py:2230`."*
- **Why it blocks:** The AT targets a selector that, per the finalized LLR, will *not* open the JSON popup (it is reserved for the field-edit action). So AT-068b either (a) tests the wrong mechanism, or (b) forces the implementer to hijack `edit_entry` — a direct LLR violation. Its RED counterfactual is **unsound**: clicking `#patch_entry_edit_button` yields no popup *before or after* a correct implementation, so the assertion never turns GREEN on the intended feature — a vacuous-fail, not a valid RED→GREEN gate.
- **Required correction:** Re-point AT-068b (and TC-341/342/343) to the new distinct control id (e.g. `#patch_entry_edit_json_button`, name to be finalized in the architect's LLR). Rewrite the RED counterfactual as: *"at `main`, no per-entry JSON control exists → the new selector is absent → click target not found → RED."* Assert the popup is seeded with a **single** entry (see F-m-scope note under compliance) to keep it distinct from batch-37's whole-set `ChangeSetJsonScreen`.

### MAJOR

#### F-M1 — AT-065a content assertion has no pinned target string (Phase-2 obligation not discharged)
- **Where:** `01-requirements.md` §3.1 / LLR-065.1 / LLR-065.2; `01b` §7 item 1.
- **Evidence:** §3.1 requires *"assert on the concrete new wording tokens, not merely non-empty (C-10 content assertion)"*, and LLR-065.1/.2 speak only of *"new wording tokens"* abstractly. 01b §7 item 1 defers the exact copy: *"architect must fix the exact replacement copy so the AT can assert it verbatim."* No concrete replacement string for the title (`"Change document (v2 JSON)"`, `:1854`) or placeholder (`"path to v2 change-set .json"`, `:1904`) is pinned anywhere in the Phase-1 artifacts.
- **Why major (not blocker):** the negative half ("no `v2`") is authorable today, but a pure-negative assertion passes on *any* rewrite including a wrong one (the exact defect C-10 exists to prevent). Since this **is** the Phase-2 gate, the deferred obligation must be discharged now, not carried further.
- **Required correction:** the architect pins the exact new section-title and placeholder strings in LLR-065.1/.2 during Phase 2; AT-065a then asserts the specific positive tokens (the "alternative to the `patches/` dropdown / same change-set" framing) **verbatim**, plus `v2` absent.

#### F-M2 — Producer-location contradiction: QA TCs name `a2l_service`, finalized LLR names `validation_service`
- **Where:** `01b` §1 (method table), §2 TC-332…343 (TC-333/334/335 target *"services/a2l_service producer (`enrich_tags_and_render` or its companion)"*), §7 item 3; vs `01-requirements.md` LLR-066.1/.2.
- **Evidence:** Requirements LLR-066.1 places the producer in `services/validation_service.py` as a sibling of `supplemental_a2l_row_issues` (`validation_service.py:20`), and LLR-066.2 merges it into `build_validation_report` (`:111`) in **both** the MAC-only branch (`~:166`) and the primary-backed branch (`~:191`). I verified both merge sites exist (`mac_only_issues + supplemental_a2l_row_issues(...)` and `merged_issues + supplemental_a2l_row_issues(...)`), and that `build_validation_report` feeds `ValidationReport.issues` → `GroupedIssuesPanel`. This path is the **correct, sink-reaching** one and resolves 01b's own §7-item-3 open question. But 01b's TC-333/334/335 and §1 still name `a2l_service.enrich_tags_and_render`, a *different* unit whose output is not guaranteed to reach the issues surface.
- **Why major:** the white-box TCs bind to the wrong mechanism; a Phase-3 implementer following 01b would build the producer in the wrong file and the AT-066a surface assertion could fail to observe it. It is also an internal contradiction between the two sibling Phase-1 docs that must be reconciled at the gate.
- **Required correction:** re-point TC-333/334/335 (and 01b §1/§6/§7-item-3) to `validation_service.supplemental_a2l_oversized_address_issues` + `build_validation_report` (both branches), matching LLR-066.1/.2. Delete the `a2l_service.enrich_tags_and_render` producer reference.

### MINOR

#### F-m1 — Issue-code string mismatch across the two docs (public contract)
- **Evidence:** Requirements pin `A2L_ADDRESS_EXCEEDS_32BIT` (§3.2, LLR-066.1). 01b §2 TC-333 uses `<new A2L-oversize code>` and §7 item 4 writes `A2L_ADDRESS_OVER_32BIT`. Issue codes are public contract (tests assert on them; CLAUDE.md engine section).
- **Correction:** adopt the requirements value `A2L_ADDRESS_EXCEEDS_32BIT` verbatim in 01b TC-333/AT-066a so the TC/AT bind to the minted code with no post-lock rename.

#### F-m2 — AT-066b over-specifies "ANSI escape appears verbatim" (path-dependent, can fail RED against a correct impl)
- **Evidence:** 01b AT-066b asserts *"the literal bracket/escape characters appear verbatim."* But `ValidationIssue.__post_init__` scrubs ANSI CSI sequences from **`message`** only (`model.py:71`, `_ANSI_CSI_RE.sub("", message)`) — it does **not** touch `symbol`, and it never strips brackets. So: brackets always survive and render literally via `safe_text` (correct); an ANSI escape routed through `message` is **stripped** (not "verbatim"), while one routed through `symbol` is neutralized as literal `Text` by `safe_text`. Asserting the ANSI byte "appears verbatim" is therefore routing-dependent and would fail against a correct implementation that carries the name in `message`.
- **Correction:** split the C-17 assertions by payload — for the **bracket/link** payload assert literal presence (`[red]` verbatim, no `MarkupError`); for the **ANSI** payload assert *no style leak / no crash / neutralized-or-stripped*, **not** "verbatim". The core C-17 guarantee (no markup parse, no style leak, no exception) is unaffected.

#### F-m3 — AT-067a: info-button render-vs-enable gate unspecified
- **Evidence:** LLR-067.1 says the info button is *"enabled whenever the variant selector is present"* — ambiguous whether the button is **conditionally rendered** (mirrors the ≥2-image visibility gate on `#patch_variant_select`, `screens_directionb.py:1988`) or **always present but disabled**. AT-067a's `pilot.click` target must exist; if conditionally rendered, the fixture must create ≥2 project images first (01b §3 notes this but LLR-067.1 does not pin it).
- **Correction:** architect specifies render-vs-enable in LLR-067.1; AT-067a pins the required fixture state (≥2 images so the selector + info button render) so the real click has a live target.

#### F-m4 — AT-065a may reword the wrong "section": title vs free-path field are different containers
- **Evidence:** the section-title `Label("Change document (v2 JSON)", …)` at `:1854` is the header of the entries pane (`id="patch_pane_entries"`), whereas the free-path field `#patch_doc_path_input` (`:1904`, the story's actual subject) lives in a *separate* `Container` with its own `Label("Change file", …)`. US-065's outcome ("free-path field reads as an alternative to the dropdown") is about the field's placeholder + its adjacent copy — not necessarily the entries-pane title.
- **Correction:** confirm at Phase 2 that the section copy being reworded is the one semantically bound to the free-path field (the "Change file"/dropdown region), so AT-065a observes the deliverable the story names. If the entries-pane title `:1854` is also in scope, state why.

---

## Per-AT control-compliance table

| AT | C-10 (non-default / content, per-branch) | C-16 (real interaction) | C-17 (markup safety) | C-18 (one distinct on-disk node) | Counterfactual sound? |
|----|------------------------------------------|-------------------------|----------------------|----------------------------------|-----------------------|
| **AT-065a** | ⚠ **F-M1** — target copy tokens not yet pinned; negative half OK, positive content unauthored | n/a (static render) | n/a | ✓ `tests/test_tui_directionb.py` (exists) | ✓ RED at main (`v2` present) — but positive assertion unbindable until copy pinned |
| **AT-066a** | ✓ names specific tag + code; in-range `0xFFFFFFFF` negative control | n/a (load event) | (delegated to AT-066b) | ✓ `tests/test_tui_a2l.py` (exists) | ✓ RED at main (no >32-bit handling) |
| **AT-066b** | ✓ asserts literal payload chars | n/a (load event) | ✓ owns bracket/ANSI/link payload in tag **name** — but ⚠ **F-m2** ANSI "verbatim" over-specified | ✓ `tests/test_tui_a2l_issue_recolor.py` (exists) | ✓ RED (markup consumed / MarkupError) for brackets |
| **AT-067a** | ✓ asserts modal body CONTENT tokens | ✓ real `pilot.click` (precedent `test_tui_entropy_viewer.py:797`, verified) | n/a | ✓ `tests/test_tui_variants.py` (exists) | ✓ RED (no info button at main); ⚠ **F-m3** target-existence gate |
| **AT-068a** | ✓ asserts specific restored entry content (undo AND redo branches) | ✓ real click/key on undo/redo affordance | n/a | ✓ `tests/test_tui_patch_editor_v2.py` (exists) | ✓ RED (no undo/redo at main) |
| **AT-068b** | ✓ asserts edited entry + sibling unchanged | ✗ **F-B1** — clicks existing `#patch_entry_edit_button` (field-edit `edit_entry`), not the new JSON control | (route rejects malformed, TC-343) | ✓ `tests/test_tui_patch_editor_v2.py` (distinct fn) | ✗ **F-B1** — stays RED even after correct impl (wrong target) |

**C-16 verdict:** AT-067a ✓ (real click, precedent verified). AT-068b uses a real click but on the **wrong widget** — the real-interaction *form* is right, the *target* is wrong (F-B1).
**C-17 verdict:** AT-066b correctly owns the hostile bracket/ANSI/link payload in the file-derived tag **name** and asserts literal render + no `MarkupError` + no style leak; only the ANSI "verbatim" wording needs tightening (F-m2).
**C-18 verdict:** all six ATs map to exactly one distinct on-disk node; all five target files verified present. AT-068a/068b share `test_tui_patch_editor_v2.py` but occupy distinct function nodes — compliant.
**C-10 verdict:** no AT relies on a default value or "output non-empty"; the only content-assertion gap is AT-065a's unpinned target copy (F-M1).

---

## Evidence checklist (completed)

- [✓] **(a) every story has a black-box AT** — US-065→065a, US-066→066a/b, US-067→067a, US-068a→068a, US-068b→068b (01b §3).
- [✓] **(b) every output-producing requirement names observable deliverable + observation method** — §3 blocks name rendered strings / issues-panel `ValidationIssue` / `app.screen` modal / `#patch_doc_entries_table` rows, each observed via Pilot.
- [⚠] **(c) both traceability chains complete** — behavioral US→AT ✓; functional LLR→TC present but **F-M2** points TC-333/334/335 at the wrong unit and **F-m1** code-string mismatch must reconcile.
- [⚠] **(d) each AT genuinely black-box (drives surface, asserts outcome, no internal symbol)** — 5/6 clean; **AT-068b drives the wrong surface control (F-B1)**.
- [⚠] **C-10** — pass except AT-065a positive-content target unpinned (F-M1).
- [⚠] **C-16** — AT-067a ✓; AT-068b real-click form ✓ but wrong target (F-B1).
- [✓/⚠] **C-17** — AT-066b feeds hostile bracket/ANSI/link payload in the tag NAME and asserts literal render; tighten ANSI "verbatim" (F-m2).
- [✓] **C-18** — each AT → exactly one distinct on-disk node; all five files verified on disk.
- [⚠] **Counterfactual soundness** — 5/6 sound; **AT-068b RED counterfactual unsound (F-B1)**; AT-065a positive assertion unbindable until copy pinned (F-M1).
- [✓] **No unfilled template placeholders** — TC/AT/LLR ids concrete (provisional-until-Phase-3 node ids acknowledged, allowed by V-5).
- [✓] **No real PII / secrets** — fixtures synthetic; hostile payloads inert markup strings.
- [✓] **Test-results columns left blank** — authoring artifact; nothing marked passed.
- [✓] **Layer B observed through shipped surface** — all six ATs use `App.run_test()` Pilot over the rendered surface (widget text / issues panel / `app.screen` / entries table), boundary + negative evidence present (AT-066a in-range control, AT-068a empty-history no-op, AT-068b sibling-unchanged).
- [✓] **Bidirectional surface-reachability** — 01b §6 ledger maps every input dim + deliverable through the handler; requirements-side producer path (`validation_service` → `GroupedIssuesPanel`) verified reachable.
- [✓] **Frozen-set respected** — no TC/AT edits `validation/` or other `_ENGINE_PATHS`; US-066 producer is TUI-side service (verified non-frozen).

---

## Verdict

**Not clean — 1 blocker.** F-B1 must be fixed (re-point AT-068b/TC-341..343 to the new distinct per-entry JSON control) before Phase 3. F-M1 and F-M2 should be discharged at this Phase-2 gate (pin US-065 copy; re-point the US-066 producer TCs). The four minors are precision/reconciliation fixes. All target test files exist; C-16/C-17/C-18 are otherwise honored and the requirements-side wiring is verified sink-reaching.
