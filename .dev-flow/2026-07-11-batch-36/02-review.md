# 02 — Cross-agent review — 2026-07-11-batch-36

> BLUF: **BLOCKERS PRESENT → iterate-to-refine.** Three independent reviews (architect / qa /
> security). Security PASS (no HIGH/MEDIUM). Architect + qa each found blockers in the US-058
> acceptance predicate and the US-060 delete-gate — all **corrections/gates, not story-kills**.
> No story is rejected. Sub-reviews: `02-review-architect.md`, `02-review-qa.md`,
> `02-review-security.md`.

## Consolidated findings (severity-ordered)

| id | sev | story | summary | evidence | fold |
|----|-----|-------|---------|----------|------|
| **A-01** | **blocker** | US-058 | AT-058a "five regions pairwise-disjoint" is unsatisfiable: `#patch_doc_controls` + `#patch_checks_controls` are CHILDREN of `#patch_doc_file_row`, so parent⊃child always "overlaps"; also contradicts surviving TC-319. | `screens_directionb.py:1848-1923`; `test_tui_patch_layout.py:416-422` | Redefine acceptance to leaf-sibling disjointness + the paste group is NO LONGER a descendant of `#patch_doc_file_row`; give TC-319 explicit disposition |
| **Q-01** | **blocker** | US-058 | AT-058a paste metric `region.height >= N` is CSS-invariant (box already `height: 8`) → counterfactual can't fail pre-change (C-10 violated). | `styles.tcss:949-951`; DF-1 | Switch to content-region PLACEMENT idiom: paste region below the pane fold today (RED) → within viewport after (GREEN) |
| **Q-04 / A-08** | **blocker** | US-060 | The I-060-1 construct-equivalence gate is ABSENT from the requirements; LLR-060.2 authorizes the 54M delete on SIZE alone → coverage-preservation unproven before an irreversible delete. | `LLR-060.2` verification = sizes only | Add a hard Phase-3 verify-before-delete gate: construct-kind subset census over both `case_06/firmware.a2l`, evidence recorded BEFORE `git rm` |
| **Q-02 / A-05** | major | US-058 | N=6@80 assumes the current 3-row grid; rung-1 `grid-size: 2 4` gives ~5.5 rows/cell → may not clear 6. The 11-line `DUMMY_CHANGESET_TEXT` exceeds the 8-tall box (internal scroll). | `styles.tcss:702-704`; `changes/io.py` (11 lines) | Re-derive N from the CHOSEN rung's measured cell height; N is VISIBLE lines in-viewport, not seed line count |
| **Q-03** | major | US-058 | The 5-region non-overlap predicate carries weak counterfactual weight (mostly a vertical stack). | TC-319 | Folded with A-01 — the meaningful observable is "paste un-nested from the crowded pane" |
| **A-02 / Q-05** | major→minor | US-059 | Spec claim FALSE: adding `"Hex"` breaks only 2 `test_tui_legend.py` assertions (`:70` orphan, `:78` artifact-set), NOT 3 — `:322` renders dynamically and SURVIVES. | `screens.py:527`; `test_tui_legend.py:322` | Correct LLR-059.3 text (2 assertions, not 3) |
| **A-03** | major | US-058 | Supersession-census gap: TC-319 (`test_tui_patch_layout.py`) is missing from LLR-058.3's census; it pins the file_row parentage US-058 perturbs. | `test_tui_patch_layout.py:351-438` | Add TC-319 to the census with an explicit disposition (update, don't just note) |
| **A-04 / Q-07** | minor | US-059 | Hex↔`color_policy` coupling must DERIVE the colour name from the constant deterministically (`"bold orange3"`→`orange3` vs legend `"Orange"`), not hardcode. | `color_policy.py:13-14`; `legend.py:60,88` | Specify the canonicalization rule in LLR-059.3 |
| **A-06 / Q-08** | minor | US-059 | AT-registry drift: §5 folds both surfaces into AT-059a; 01b splits AT-059a (modal) + AT-059b (report reread). | req §5 vs 01b §2.3 | Reconcile to TWO ATs (059a modal, 059b report C-12) — apply C-21 (re-reconcile the registry before cutting increments) |
| **A-07 / Q-06** | minor | US-058 | Provisional snapshot id `patch-80x24` is wrong. | on-disk baselines | Adopt `patch-comfortable-80x24` / `patch-comfortable-120x30` |
| **S-02** | low | US-060 | Do the move/delete via `git mv` / `git rm` (index consistency, reversible). | — | Instruction to Phase 3 |
| **S-01** | low | US-059 | Keep new Hex meaning strings free of `[ ]` markup chars (modal renders markup-enabled; rows are static so no live vector). | `screens.py:538` | Authoring constraint |

## Security verdict
**PASS — no HIGH/MEDIUM.** US-060 deletion targets hold 0 secrets/PII, no license/attribution;
working-tree-only (no history rewrite sneak); US-058 zero new attack surface; US-059 C-17 = N/A
correct (static literals). Scope-change watch: if any Phase-3 amendment makes a legend row
derive from run data, C-17 re-triggers and re-routes here.

## Re-verification of Phase-1 claims (architect independent)
FALSE: (1) LLR-059.3's "3 assertions break" (only 2); (2) AT-058a's "five pairwise-disjoint"
(unachievable + contradicts TC-319). TRUE (re-verified): color_policy constant names+values,
two-styles-only hex render, unstyled `>` marker, C-13 budget arithmetic, US-060 observer census
+ exact byte sizes + tmp tracking, normative-keyword compliance.

## Gate disposition
BLOCKERS present (A-01, Q-01, Q-04) → **iterate-to-refine**: fold all findings into
`01-requirements.md` (§6.5 Before/After amendment records), re-reconcile the AT registry
(C-21), then re-gate Phase 2. No story is killed; all folds are corrections/gates.
