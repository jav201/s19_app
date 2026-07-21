# Phase-2 Cross-Review — ARCHITECT dimension — batch-59

**Reviewer:** architect · **Date:** 2026-07-21 · **Artifact under review:** `.dev-flow/2026-07-21-batch-59/01-requirements.md` (5 US / 5 HLR / 10 LLR / 8 AT)

**Verdict: CHANGES-REQUESTED.** 1 blocker, 3 major, 3 minor.

**BLUF:** The requirements are internally sound, correctly derived, `shall`-clean, and the live-window / preservation / markup-safety spine is solid. But the document was authored BEFORE the operator's Phase-1 layout refinement and still encodes the pre-refinement layout throughout (verdict+warnings as a bench column). The operator moved verdict+warnings to a HERO ROW and gave JSON its own col3 (`state.json.confirmed_design_decisions.layout_refinement`). That fold is **not applied**, and it breaks the teeth AT (AT-B59-03): under the confirmed tree `#crc_kat_verdict` has **no `#crc_bench_c*` ancestor at all**, so "each resolves to a DIFFERENT bench-column ancestor" is unsatisfiable, not just imprecise. This is the blocker. The teeth SURVIVE a correct rewording (three pairwise-distinct ancestor containers; flat form still collapses to one), so this is a documented amendment, not a redesign.

---

## Blocker

### B1 — Layout fold not applied; AT-B59-03 (the teeth AT) is inconsistent with the operator-confirmed target
**Citations:** `01-requirements.md` §1.2:19, §2.2:62, HLR-L2:126, AT-B59-03:130, LLR-L2.1:210 vs `state.json:18` (`layout_refinement`) and the confirmed prototype `prototypes/crc_designer.b59.inapp_prototype.py:126-178`.

The operator confirmed (state.json:18): **hero ROW = coverage window (2fr) + a right column (1fr) holding the KAT verdict hero above Warnings**; **c3 = JSON(roomy) + template + load/save**. The requirements instead say, in five places, that **column 3 = verdict hero + JSON + Warnings + Template + Load/Save** (the pre-refinement layout):
- §1.2:19 "col3 = KAT verdict hero + Job JSON + Warnings + Template + Load/Save"
- §2.2:62 product function 3 + HLR-L2:126 "column 3 the verdict hero, Job JSON, Warnings, Template and Load/Save"
- LLR-L2.1:210 "`#crc_bench_c3` = `#crc_live_verify` + `#crc_json_preview_group` + `#crc_warnings_group` + `#crc_template_fields` + `#crc_loadsave_group`"

Consequence for the teeth AT. In the confirmed prototype the ancestry is:
- `#crc_kat_verdict` → `#crc_live_verify` → `#crc_top_right` → **`#crc_hero_row`** (NOT under `#crc_bench`)
- `#crc_coverage_ranges` → `#crc_coverage_group` → `#crc_bench_c2`
- `#crc_field_width` → `#crc_algorithm_fields` → `#crc_bench_c1`

AT-B59-03 (:130) asserts the three widgets "each resolve to a DIFFERENT **bench-column** ancestor." Under the confirmed tree `#crc_kat_verdict` has **no `#crc_bench_c*` ancestor**, so an implementation that walks for a bench-column ancestor of the verdict returns None / raises — the assertion is not merely imprecise, it is **unsatisfiable as written**. The operator's own note ("pairwise-distinct ancestors still hold") is only true under a reworded assertion.

**Required amendment (record as a §6.5 before/after so the locked AT is not silently edited):**
1. Reword AT-B59-03 from "different **bench-column** ancestor" → "**pairwise-distinct ancestor CONTAINER**": `#crc_kat_verdict`'s ancestor = the hero-row right column (`#crc_top_right`), `#crc_coverage_ranges`'s = `#crc_bench_c2`, `#crc_field_width`'s = `#crc_bench_c1`. Assert the three are pairwise distinct.
2. Amend HLR-L2:126, LLR-L2.1:210, §1.2:19, §2.2:62 to the confirmed layout: **c3 = JSON + Template + Load/Save**; verdict+warnings live in the hero row.
3. Update the §5.2 behavioral row for US-L2 accordingly.

**Teeth survive the rewording (verified):** in the shipped flat form all three widgets share the single `#crc_designer_panel` ancestor → pairwise-distinct is FALSE → the AT still fails a single-column revert. AT-B59-08's teeth claim (:172) remains valid after the rewrite.

---

## Major

### M1 — NEW hero-row container ids (`#crc_hero_row`, `#crc_top_right`) are specified nowhere in the LLR
**Citations:** prototype `:167-171` introduces `Horizontal(id="crc_hero_row")` and `Vertical(..., id="crc_top_right")`; no LLR (L2.1:210 lists only `#crc_bench`/`_c1`/`_c2`/`_c3`) names them.

The confirmed layout's signature structure — the wide window and the verdict/warnings tiles at the same top level — is carried entirely by two container ids that the requirements never enumerate. Completeness gap. Add to LLR-L2.1 (or a new LLR-L2.3): `compose` yields `Horizontal(id="crc_hero_row")` wrapping `#crc_coverage_window` (2fr) + `Vertical(id="crc_top_right")` (1fr) holding `#crc_live_verify` above `#crc_warnings_group`; enumerate these two NEW ids alongside the four bench ids.

### M2 — Reflow requirement covers only `#crc_bench`; the hero ROW has no width-narrow rule → the 2fr window crushes at the 80×24 floor (C-13/C-23/C-29)
**Citations:** LLR-L2.2:216-222, AT-B59-04:130, R-2:309; prototype shot at `size=(150,55)` (proto `:198`) — a wide budget.

LLR-L2.2 only specifies `#workspace_body.width-narrow #crc_bench { layout: vertical }`. The hero ROW (`#crc_coverage_window` 2fr + `#crc_top_right` 1fr) has no stacking rule, so at narrow widths the window keeps 2fr of a shrinking body. The prototype's 40-glyph window line (16+8+16 + labels ≈ 55+ chars, proto `:36-43`) was measured at 150 cols; at the 80-col floor the boxed 2fr window is a **different budget** — this is exactly the C-29 non-transfer trap (do not inherit a wide-prototype budget for a chrome-boxed panel) and C-23 (measure the WHOLE hero-row budget, both axes, at the tightest regime). Add: (a) an LLR/AT requiring `#crc_hero_row` to stack vertical under `#workspace_body.width-narrow`; (b) a Phase-3 pilot-measure obligation on the real boxed `#crc_coverage_window` width at 80×24 (not the prototype's 150-col line), feeding the OQ-3 glyph cap.

### M3 — Increment order (§5.3 Inc-1) is written for the old layout, weakening the R-1 guard
**Citations:** §5.3:288 "hero window as an empty placeholder Static first"; R-1:308 + LLR-L4.2:246 (full suite at Inc-1 is the ancestor-coupling guard).

Inc-1 as written re-arranges the bench but does not move verdict+warnings out to the hero row (that is folded into the window step, Inc-2). If a batch-58 test hard-codes the verdict's ancestor (the R-1 hazard), Inc-1's full-suite run passes against a tree where verdict is still bench-adjacent, and the break surfaces only at Inc-2 — one increment later than the guard is meant to fire. Fix: fold the hero-row extraction (verdict+warnings → `#crc_hero_row`/`#crc_top_right`) into Inc-1 so LLR-L4.2's full-suite run at the Inc-1 gate exercises the **final** ancestry. (This keeps §5.3's 3-file / 3-increment envelope intact.)

---

## Minor

### m1 — LLR-L1.1 empty-state should reuse the shipped string, not a new note
**Citations:** LLR-L1.1:186-189 ("graceful markup-safe note"); shipped `_coverage_preview_text` returns `"Load an image to preview coverage CRCs over real bytes."` at `crc_designer_view.py:850-851`.

OQ-1's degrade requirement is real and reusable (verified). The window and the existing preview now share the same no-image condition; specify that `_render_coverage_window` returns the **same** empty-state string (or a deliberate variant) so the two surfaces don't diverge. Currently generic.

### m2 — OQ-3 deferral is correct but must name C-29 explicitly
**Citations:** OQ-3:332, LLR-L1.1:190 ("glyph cap bounded … C-23"), state.json:20.

Deferring the glyph budget to a Phase-3 pilot is legitimate under C-23. Strengthen the note to cite C-29: the prototype's glyph line was measured full-screen; the boxed 2fr window is a non-transferable budget — re-measure, do not inherit. (Ties to M2.)

### m3 — OQ-4 / R-2 overstate col3 density under the confirmed layout (informative)
**Citations:** OQ-4:333, R-2:309 describe col3 as "5 groups (verdict/JSON/warnings/template/load-save)".

The confirmed fold moves verdict+warnings to the hero row, so col3 is **3 groups** (JSON-roomy + template + load/save), not 5 — the vertical-budget risk is lower than the doc states. Update OQ-4/R-2 to the 3-group reality (still worth a Phase-3 check because JSON is now "roomy").

---

## Items reviewed and PASSING (no change required)

- **OQ-1 live window (review item 2):** LLR-L1.1/L1.2/L1.3 correctly specify the window renders LIVE from `_build_coverage_target` (`:771`, method verified) + `compute_target_crc` (imported `:85`) with **zero new engine math**, and the empty/no-image state is handled and reuses a real shipped code path (`:850-851`). Consistent with `confirmed_design_decisions.OQ-1_live_window`. PASS.
- **R-1 guard (review item 5):** full-suite `tests/test_crc_designer_view.py` at Inc-1 is the **right** guard — id-based `query_one("#crc_*")` resolves descendants anywhere (re-nesting is transparent), and a test that hard-codes a structural ancestor goes RED; LLR-L4.2:246 correctly says "surface, do not silently patch." Correct **provided M3 is applied** so Inc-1 runs against the final tree.
- **`shall`/`should` (blocker axis):** clean — grep for `\bshould\b` in normative statements returns none; `should` appears only in informative "recommended" prose. PASS.
- **Markup-safety (C-17):** the single new sink `#crc_coverage_window` is specified `markup=False`, sourced from `mem_map` bytes + typed ints only (§2.4:71, LLR-L1.2:198). Sound.
- **US→HLR→LLR derivation:** sound for L1/L3/L4/L5; L2 needs the B1/M1/M2 amendments. Dual traceability (§5.2) present both chains.
- **Method/line citations:** spot-verified accurate — `_build_coverage_target:771`, `compute_target_crc` import `:85`, verdict-in-`#crc_live_verify` `:322-326`, `_recompute` NoMatches guard `:908-916`, `crc-*` CSS undefined (V-1), `width-narrow` on `#workspace_body` (`app.py:5692-5697`, reflow reachable).

---

## Evidence checklist

- [✓] Constraints stated explicitly — §2.4 (engine-frozen, C-16/17, geometry C-13/23, snapshot census).
- [✓] Requirements consistent with `confirmed_design_decisions` — **✗ for `layout_refinement`** (B1: verdict-in-c3 vs confirmed verdict-in-hero-row); ✓ for OQ-1/OQ-2.
- [✓] AT-B59-03 teeth valid under the confirmed tree — **✗ as written** (unsatisfiable: verdict has no bench-column ancestor); ✓ after the B1 rewording to pairwise-distinct ancestor container.
- [✓] OQ-1 live window + empty-state handled — ✓ (`crc_designer_view.py:850-851`, `_build_coverage_target:771`, 0 engine math).
- [✓] OQ-3 glyph budget @80×24 — ✗ under-specified for the hero row; deferral acceptable under C-23 but must add hero-row reflow (M2) + C-29 note (m2).
- [✓] OQ-4 col3 vertical budget @120×30 — ✓ deferred with C-13.1 fallback; density overstated (m3, informative).
- [✓] R-1 full-suite guard at Inc-1 — ✓ correct guard, conditioned on M3 (Inc-1 must include the hero-row move).
- [✓] `shall`/`should` misuse — ✓ none.
- [✓] NEW container ids specified — **✗** (`#crc_hero_row`/`#crc_top_right` absent from LLR, M1).
- [✓] What would change the recommendation stated — ✓ (OQ-1, R-1) in §6.5/§6.6.

## Required actions before Phase-3

1. **B1** — apply the layout fold: reword AT-B59-03 to pairwise-distinct ancestor CONTAINER; amend HLR-L2, LLR-L2.1, §1.2, §2.2 to c3 = JSON+Template+Load/Save with verdict+warnings in the hero row; record as a §6.5 before/after.
2. **M1** — enumerate `#crc_hero_row`/`#crc_top_right` (2fr/1fr split; verdict-hero above warnings) in the LLR.
3. **M2** — add a hero-row `width-narrow` stack requirement + a Phase-3 both-axes pilot at the boxed 2fr window width (C-23/C-29).
4. **M3** — fold the hero-row extraction into Inc-1 so the R-1 full-suite guard fires against the final ancestry.
5. **m1–m3** — reuse the shipped empty-state string; cite C-29 in OQ-3; correct col3 density in OQ-4/R-2.
