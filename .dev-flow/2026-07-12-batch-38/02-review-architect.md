# 02 — Phase-2 Cross-Review (ARCHITECT, independent) — 2026-07-12-batch-38

> **Reviewer:** architect, independent Phase-2 pass. Read fresh against the working tree at `5a6c45b` (primary checkout `s19_app/…`). Lane: completeness · ambiguity · contradiction · US→HLR→LLR derivation · normative discipline · engine-freeze · reuse/duplication · supersession (C-26) census.
> **Verdict:** **1 blocker, 4 major, 3 minor.** The §4 HLR/LLR spine is sound and engine-freeze-clean; the defects are cross-artifact contradictions (producer location, per-entry click target, issue-code string, TC numbering) that will send an implementer to the wrong place if not reconciled before lock.

---

## BLUF
- The architect §4 requirement spine is **correct on the two things that matter most**: US-066's WARNING is produced in `validation_service.py` (the sink that actually reaches `GroupedIssuesPanel`), and US-068b mints a **new** control id without hijacking the existing per-entry Edit button. Both are verified against source.
- **But three sibling artifacts (intake §2.6, PLAN.md, 01b-qa) contradict §4** on the US-066 producer location, the US-068b click target, and the new issue-code string — each a place an implementer could follow into a failing AT.
- One **blocker**: the public issue code diverges (`A2L_ADDRESS_EXCEEDS_32BIT` vs `A2L_ADDRESS_OVER_32BIT`) across §4 and 01b. Public contract must be one string before Phase 3.
- Engine-freeze: **clean** — no LLR targets a frozen file.

---

## Adjudication of Phase-1 flags (F-a … F-d)

### F-a — US-066 WARNING reaches the correct surface? → **§4 is CORRECT; PLAN/intake/01b contradict it. MAJOR.**
Traced the sink end-to-end:
- `validation_service.build_validation_report` (`validation_service.py:111`) merges supplemental issues into `ValidationReport.issues` in **both** branches (`:166-169` MAC-only, `:190-194` primary-backed) before `dedupe_issues`.
- `S19TuiApp.update_validation_issues_view` (`app.py:6201`) reads those issues → `GroupedIssuesPanel.render_groups` (`app.py:6314,6336`), the `#validation_issues_groups` surface AT-066a observes.
- **Architect §4 (LLR-066.1 line 134, LLR-066.2 line 142) puts the producer in `validation_service.py` as a sibling of `supplemental_a2l_row_issues` — this is the right sink. CONFIRMED CORRECT.**

The problem is the **other artifacts point at the wrong sink**:
- Intake §2.6 (line 19), PLAN.md (lines 31, 42), and 01b-qa (§1, §2 TC-333, §6 ledger) place the producer in `services/a2l_service.enrich_tags_and_render`.
- That function returns `tuple[list[dict], list[str]]` — enriched tag rows + summary lines (`a2l_service.py:10-27`). It does **not** emit or route `ValidationIssue`s. A WARNING constructed there is **dropped** and never reaches `GroupedIssuesPanel`; AT-066a would fail.
- This is also an **internal contradiction inside the architect deliverable** (§2.6 line 19 says `a2l_service`; §4 LLR-066.1 says `validation_service`).

**Required correction:** make the producer location single-valued = `s19_app/tui/services/validation_service.py`. Correct intake §2.6 line 19, PLAN.md lines 31/42, and 01b-qa TC-333 (§2) + §1 + §6 to name `validation_service.py` (running over the same `tags_for_validation` list `build_validation_report` already resolves), not `enrich_tags_and_render`.

**LLR-066.3 render-path sub-claim — CONFIRMED CORRECT (no defect):** `IssueRow` composes `code`/`detail`/`related` through `safe_text` as literal `rich.text.Text` (`issues_view.py:183,187,189`; `safe_text` imported `:38`). The existing render already satisfies markup-safety, so LLR-066.3 is correctly a **producer constraint** ("do not pre-format the tag name into a markup-parsed string"), not new render code. Good.

### F-b — US-068b new control id, no hijack of `#patch_entry_edit_button`? → **§4 CORRECT; 01b AT-068b clicks the WRONG button. MAJOR.**
- Architect LLR-068b.1 (line 233) mandates a **new** `#patch_entry_edit_json_button`, keeps all three existing per-entry ids (`patch_entry_add_button`/`edit_button`/`remove_button`), and explicitly forbids hijacking the `edit_entry` action (`screens_directionb.py:2230`). Verified the existing ids/actions: `#patch_entry_edit_button` at `:1886` → `"edit_entry"` at `:2230`; whole-set `#patch_edit_json_button` at `:2033`; `#patch_doc_entries_table` `cursor_type="row"` at `:1857-1859`. **Architect side CONFIRMED CORRECT.**
- **But 01b-qa AT-068b mechanism (line 114) does `await pilot.click("#patch_entry_edit_button")`** — the existing field-based Edit button, directly contradicting the new-id mandate and the "no hijack" rule. As written, the AT drives the wrong control and cannot observe the new per-entry JSON popup.

**Required correction:** 01b AT-068b (line 114) and §6 ledger must click the **new** `#patch_entry_edit_json_button`, not `#patch_entry_edit_button`.

### F-c — new A2L issue code divergence → **BLOCKER (public contract, unreconciled).**
- Architect uses `A2L_ADDRESS_EXCEEDS_32BIT` consistently (§3.2 line 67, LLR-066.1 line 135, risk R-A line 312).
- 01b-qa uses a **different** example: `A2L_ADDRESS_OVER_32BIT` (§7 item 4) and an unbound `<new A2L-oversize code>` (TC-333, TC-334, TC-335). Issue codes are **public contract — tests assert on them** (per CLAUDE.md validation-engine section). Two candidate strings in two live batch artifacts is a lock hazard.
- Confirmed **no existing test** references either string (`tests/` grep clean), so R-A holds and there is no back-compat count assertion to break — but the forward divergence must still be collapsed.

**Required correction (blocker-clearing):** ratify **one** canonical code. `A2L_ADDRESS_EXCEEDS_32BIT` is already the normative §4 value — adopt it; rewrite 01b §7 item 4 and TC-333/334/335 to bind to it verbatim.

### F-d — TC-id numbering → **MAJOR (collision + count mismatch).**
- Architect §5.2 functional-chain table numbers **TC-001…TC-019** (19 rows, one per HLR+LLR).
- 01b-qa numbers **TC-332…TC-343** (12 TCs, LLR-level), correctly anchored above batch-37's TC-331 (01b §0/§2).
- Two defects: (1) architect's TC-001.. **collides** with the historical batch-01-era TC namespace and violates monotonic numbering — batch-38 TCs **shall** start at TC-332; (2) the two decompositions **disagree on count and mapping** (19 vs 12), so dual-traceability is currently double-booked.

**Required correction:** delete the TC-001..019 scheme; the qa-owned **TC-332…TC-343** set is authoritative (01b header assigns TC ownership to qa-reviewer). Rebuild architect §5.2's functional-chain column onto TC-332.. and reconcile to the single 12-TC (or explicitly-merged) mapping. This is a Phase-2 reconciliation obligation that must close before lock.

---

## Controls enforcement (findings)

### C-26 touched-symbol reverse census → **declared; one census gap (minor).**
Every LLR that touches a shared id/class/code declares it: LLR-065.1 (string@1854, `patch-section-title` class unchanged), LLR-065.2 (string@1904, `#patch_doc_path_input` unchanged), LLR-066.1 (new fn + **new public code**), LLR-066.2 (`build_validation_report` extended, return contract unchanged), LLR-067.1 (new `#patch_variant_info_button`, `#patch_variant_select` unchanged), LLR-068a.3 (new `#patch_undo_button`/`#patch_redo_button`, `refresh_entries` reused), LLR-068b.1 (new `#patch_entry_edit_json_button`, 3 existing ids survive). Good coverage.
- **Verified against `tests/`:** no test asserts the literal `"path to v2 change-set"` placeholder or `"Change document (v2 JSON)"` title (grep clean). So US-065 breaks **no** test — 01b §7 item 7's prediction that "existing tests asserting the old 'v2' copy will break" is **over-cautious (there are none)**. Not a defect, but the census note should be corrected to "0 breakages expected" so the increment gate isn't chasing a phantom.
- **Gap (minor):** `patch-section-title` is applied at **three** sites (`screens_directionb.py:1854,1918,1936`). LLR-065.1 changes only the 1854 `Label`'s string. The census must explicitly confirm the edit is scoped to the 1854 instance and does not perturb the class or the other two labels' copy.

### C-13/C-23 geometry → **CONFIRMED clean.**
US-067 (LLR-067.3 line 185) and US-068b (LLR-068b.2 line 242) both flag modal dimensions `assumed — pilot-measure in Phase 3` at 80×24/120×30; risk R-C records it. No fr-math size is asserted at Phase 1. Compliant.

### C-17 markup-safety → **CONFIRMED designed-in, not deferred.**
AT-066b exists (§3.2 line 70; 01b §3) with a bracket/ANSI/`[link=…]` payload in the file-derived tag **name**, asserting literal render + 0 `MarkupError`. Backed by LLR-066.3 producer constraint + existing `safe_text` render. US-067 modal text is `markup=False`/literal (LLR-067.3); US-068b confirm routes through the validated parse path (TC-343). Compliant.

### Normative-keyword discipline → **CONFIRMED clean.**
Every §4 HLR/LLR statement uses `shall`; rationale blocks are marked `(informative)`. No `should`/`deberá` used as a normative modal inside an HLR/LLR. No violation.

### Engine-freeze → **CONFIRMED clean (no blocker).**
LLR target files: `screens_directionb.py`, `services/validation_service.py`, `issues_view.py` (render, read-only), `screens.py`, `app.py`, `services/change_service.py`. **None** in the frozen set (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`). Note the correct distinction: `tui/services/validation_service.py` is **not** the frozen `validation/` package — routing US-066 here (Event R2) is the right freeze-respecting move. `css_class_for_severity` (frozen `color_policy.py`) is **read/imported**, not edited. Compliant.

---

## Additional findings

### A-1 (minor / Phase-3 watch) — US-066 positive branch depends on `address` being a parsed `int`.
LLR-066.1 guards on `isinstance(address, int) and address > 0xFFFFFFFF` (non-int/None → no issue) — correct and safe. **But** the WARNING only fires if `tags_for_validation` carries the address as an `int` at the point `build_validation_report` sees it, in **both** branches (raw `a2l_data["tags"]` in some MAC-only paths vs enriched tags). If a raw tag stores `address` as a hex **string**, AT-066a's positive branch silently never fires (vacuous pass risk). Phase 3 must confirm the tag `address` is an `int` in both branches (the existing `supplemental_a2l_row_issues` reads `address` at `validation_service.py:86-87` with the same `isinstance(int)` guard — reuse that precedent and add a fixture whose oversized tag's address is a genuine parsed int).

### A-2 (minor) — 01b test-node targeting for AT-066a/b is consistent with the §4 sink.
01b routes AT-066a through `test_tui_a2l.py` (load handler → issues panel) and AT-066b through `test_tui_a2l_issue_recolor.py`. Both observe `GroupedIssuesPanel`, which is compatible with the corrected (validation_service) producer. No change needed once F-a is reconciled; flagged only so the node choice isn't re-opened.

---

## Evidence checklist (architect lane)
- [✓] **Constraints stated** — engine-freeze set, C-16/17/18/21/22/23/26, `shall`-only regime, TC anchor ≥332, public-code contract. Evidence: PLAN §Conventions; 01-req §4 preamble; 01b §0.
- [✓] **≥2 alternatives considered** — US-066 producer routing (a2l_service vs validation_service) is exactly the axis in dispute; §6.4 Event R2 records the freeze-driven choice. Evidence: 01-req §6.4.
- [✓] **Recommendation tied to constraints** — producer=`validation_service.py` chosen because it is the only non-frozen sink reaching `GroupedIssuesPanel` (`app.py:6201,6336`). Evidence: this review F-a.
- [✓] **Risks listed** — cross-artifact contradiction (wrong sink/wrong button), public-code divergence, int-address vacuous-pass, TC collision. Evidence: findings above; 01-req §6.3 R-A..R-D.
- [✓] **Cost/latency** — n/a (copy/UI/robustness batch, no model calls or throughput surface); noted rather than hand-waved.
- [✓] **Diagram/flow** — flow traced inline (producer → `build_validation_report` → `update_validation_issues_view` → `GroupedIssuesPanel`); no separate diagram warranted for a 4-hop path.
- [✓] **What would change the recommendation** — if `enrich_tags_and_render` were refactored to return issues (it is not, `a2l_service.py:14`), the a2l_service placement would become viable; today it is not.
- [✓] **Two-layer requirements** — every story has a §3 Acceptance block + `AT-NNN` and both traceability chains (§5.2 behavioral US→AT + functional US→HLR→LLR→TC), pending the F-d TC renumber.

---

## Gate recommendation
**RETURN for reconciliation before Phase-3 lock.** One blocker (F-c public issue code) must be collapsed to a single string. Four majors are cross-artifact contradictions the implementer would trip on (F-a producer sink, F-b click target, F-d TC numbering, plus the §2.6 internal contradiction folded into F-a). The §4 HLR/LLR spine itself is engine-freeze-clean and correctly derived — the corrections are edits to intake §2.6, PLAN.md, and 01b-qa to match §4, plus the TC renumber. No re-derivation of requirements is needed.
