# PLAN.md — batch-24 (living compendium)

> **Feature #12: before/after report (a) + entropy/data-classification viewer (b) + A2L↔issues reconcile (c).** The design-heavy queue head. Phase 0 = decomposition + design proposal (batch-21 precedent). Full `/dev-flow`. Inline-paste at gates.

## Where we are
- **Phase 2 — Cross-review, post-fold.** `awaiting-gate` (re-presentation). The forced iterate-to-refine is DONE: all 18 findings folded body-first (18-row §6.4 table + 3 §6.5 amendments AM-1/2/3), C-15 sweep-back 0 stale, `should`-scan 0. **Now 3 HLR / 12 LLR / 9 AT / 14 TC.**
- Phase-2 headlines: **B-1** the no-MAC wipe (`update_mac_view` clears `_validation_issues`, `app.py:7160-7186` — the C-15 blind spot one function deeper than P-10 probed) → operator chose **fix-the-wipe** → NEW **LLR-037.4** (in I1; I1→I2 now STRICT). **B-2** stale/cross-project `last_summary` → `ChangeSummary.source_image_path` stamp (service-side, off `to_dict` for byte-stability) + preconditions 4-5 + refusal class 4 + **AT-038d**. qa: AT-038a takes the surfaced path + pins literal `img-patched_1.s19`. AT-037b's WARNING half → Layer-A GUARD (unbuildable through shipped chain).
- Phase 1 iteration 2 (the fold). Phase 1 `approved` (orig derivation, 13-probe ledger, P-10 finding). Phase 0 `approved` (slice US-032+033+034; entropy deferred).
- Key §6.2 decisions: D-1 composer = NEW `before_after_service.py` + default-off generator kwargs (byte-identical regression); D-2 WARNING never recolours; D-3 no-project refusal; D-4 dedup key casefolded-symbol×a2l×ERROR; D-5 map app-side.
- Fixture headline (qa): BOTH A2L defect fixtures must be authored (raw missing-address non-virtual + duplicate-symbol don't exist as files).
- Roadmap: 5 increments — I1 US-032 · I2 US-033 · I3 generator kwargs · I4 composer+trigger (I3→I4 strict) · I5 close.
- Phase 0 `approved` (2026-07-02): **slice = US-032+033+034**; entropy trio (US-035/036/037) deferred whole to its own spike batch. US-034: diff-report flavor + patch header/linkage table; **offer-after-save-back** trigger. Micro-spike resolved: save-back cannot clobber the original (`apply.py:574` dedup-suffix) → report "after" side = `last_summary.saved_path`.

## The batch in one line
Fix the live A2L-colour↔issues disagreement in BOTH directions (red⇒issue, ERROR-issue⇒red) + ship the one-action before/after report over the already-captured apply data.

## Key intake evidence (architect consult, cited)
- (c) divergence live TODAY: missing-address tag → red row ([app.py:223-232]) + zero issues ([rules.py:460-469] only fires on non-int-present); duplicate symbol → ERROR issue ([rules.py:470-480]) + normal row (severity fn never consults issues; REQUIREMENTS.md:364 anchor).
- (a) reuse: `ChangeSummaryEntry.before_bytes/after_bytes` already captured (model.py:365-372, apply.py:329-347); `compare_images` re-reads disk fresh; `diff_report_service` writes the complete artifact family.
- Fix locality: open merge point `validation_service.py:76-91` + `app.py` severity fn; frozen modules untouched.

## Risks / watch-items
- US-032 issue-code contract: NEW code ok, renames forbidden (tests pin codes).
- US-033 touches the 5k-line app.py render path (two functions); WARNING-row policy to be decided in §4.
- US-034 new write surface (report file) — inherits diff-report containment; security review will audit the offer-after-save-back trigger.
- AT-036a must demonstrably FAIL on today's tree (it IS the reported bug) — the strongest counterfactual this flow gets.

## RC-1 base-currency gate — PASS
- `git fetch` → `origin/main` = **9d2123c** (batch-23 PR #39 merged — #8 complete). Branch `claude/batch-24-feat12` cut at tip; merge-base == tip.
- Carried (uncommitted → ride batch-24 first commit): batch-23 close snapshot (`.dev-flow/2026-07-01-batch-23/state-snapshot-at-close.json`) + the `obsidian_synced=true` state flip.
- Already-shipped checks (all three sub-items OPEN): `entropy` → 0 code hits (one docstring phrase in change_service.py:825 — a LEAD, not a hit: the apply pipeline may already retain per-entry before/after records); `reconcile` → 0 hits; report_service.py has reusable machinery (hexdump windows, modified-files/applied-regions lines).

## Objective
Decompose #12 into INVEST stories, get operator design decisions at the DoR gate, lock the batch-24 slice.

## Risks / watch-items
- (b) entropy viewer is greenfield (model + surface + geometry) — C-13 measurement mandatory if it takes a pane; likely SPIKE for the windowing/classification algorithm.
- (a) may partially overlap the compare/diff seam (A↔B) — decomposition must say what a REPORT adds over compare.
- (c) may be an audit + reconcile-TC rather than a feature — classify honestly.
- Engine-frozen set OFF-LIMITS (entropy computation lives TUI-side).

## Test ledger
- Base (origin/main 9d2123c): batch-23 closed at 1004 collected non-slow (1002 + 2 merged-fix regressions); confirm at Phase-3 entry.

## Decision log
- 2026-07-02 P0: batch-24 init, #12 scope, RC-1 PASS (9d2123c), architect consult dispatched.
