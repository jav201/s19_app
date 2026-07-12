# 02 — QA Cross-Review (Phase 2) · batch-36 (US-058 / US-059 / US-060)

> Independent, adversarial review of the requirements' TESTABILITY. Reviews
> `01-requirements.md` + `01b-qa-strategy-and-verification.md` against the actual
> test seams at tree `7df60dd`. Author: qa-reviewer. Verdict: **APPROVABLE WITH
> REQUIRED FOLDS** — 2 blockers (Q-01, Q-04), both fixable folds, not story-kills.

## BLUF

- **AT-058a's geometry assertion is reliably testable — but ONLY via the
  `content_region`-intersection idiom already in the tree
  (`test_tui_patch_variant.py::test_tc_035_2`, lines 413-448), NOT via the raw
  `region.height` the spec names.** Raw `region.height` == the CSS `height: 8`
  whether the box is visible or below the fold (confirmed: `styles.tcss:949-951`),
  so the spec's own counterfactual ("region.height >= N fails today") is FALSE →
  C-10 violation. **BLOCKER Q-01** — fixable, and the requirements' DF-1 already
  points the right way; the AT "Deliverable" bullet just contradicts it.
- **The I-060-1 duplication-equivalence gate the qa Phase-1 required is NOT
  encoded in the requirements.** `LLR-060.2` authorizes the 54 MB delete on SIZE
  alone; no construct-diff precondition. Coverage-preservation is therefore
  unproven at its leaf. **BLOCKER Q-04.**
- Confirmed patch snapshot cell ids (on disk): **`patch-comfortable-80x24`** and
  **`patch-comfortable-120x30`**. The requirements' provisional `patch-80x24`
  (LLR-058.4 / probe ledger) is WRONG; 01b §4 is correct. **Q-06.**
- US-059 anti-drift split is mostly right, but the requirements over-count the
  breakage (3 assertions vs the actual 2). **Q-05.**

---

## Findings

| ID | Sev | Story | Summary | Evidence | Suggested fold |
|----|-----|-------|---------|----------|----------------|
| **Q-01** | **blocker** | US-058 | AT-058a's paste-height metric `region.height >= N` is CSS-invariant (box is `height: 8` today and after) → the stated counterfactual cannot fail pre-change (C-10 violated). The valid metric is the **visible-viewport intersection**: assert the paste box's rows lie within `[pane.content_region.y, pane.content_region.bottom)` at scroll 0. | `styles.tcss:949-951` (`#patch_paste_text { height: 8 }`); DF-1 (req §6.2) itself says "never the `height` style property"; **precedent idiom** `tests/test_tui_patch_variant.py:434-438` asserts `content_y <= select_y < content_bottom`; 01b §1 counterfactual "region.height >= N fails" is factually false | Rewrite AT-058a "Deliverable + observation": measure visible paste rows = `min(paste.region.bottom, pane.content_region.bottom) - max(paste.region.y, pane.content_region.y)` (or the `content_y <= paste.region.y and paste.region.y + N <= content_bottom` form), assert `>= N` at scroll 0; delete the raw-`region.height` phrasing. Home: `test_tui_patch_layout.py`. |
| **Q-02** | major | US-058 | N=6@80x24 is **assumed, not measured**, and the vertical-budget math that says it "clears" is inconsistent with the chosen mechanism. LLR-058.1 claims "a dedicated 1fr paste region (~9 rows @24)" — but that 9-row figure comes from the CURRENT 3-row grid (`grid-rows: 1fr 1fr auto`); rung-1's `grid-size: 2 4` splits the height into ~5.5 rows/cell, which does NOT clear 6 visible paste rows once you subtract the paste label + parse button. | `styles.tcss:702-704` (`grid-size: 2 3`, `grid-rows: 1fr 1fr auto`); LLR-058.1 vertical-cause block ("~9 rows @24"); rung-1 text "`grid-size: 2 4`"; `DUMMY_CHANGESET_TEXT` = 11 lines but box caps at 8 | Make N a **Phase-3 measured pin** (not 6/8 asserted a priori). If the chosen rung yields <6 visible rows @80x24, the mechanism must give the paste cell an explicit taller row (e.g. weighted `grid-rows`) or N drops — either way, pin from the post-fix capture and record it at the gate. |
| **Q-03** | major | US-058 | The "five region rectangles pairwise non-overlapping" predicate carries **no counterfactual weight** and cannot co-anchor C-10. Four of the five groups (`#patch_doc_file_row`/`#patch_doc_controls`/`#patch_checks_controls`/`#patch_paste_row`) are a vertical STACK inside one pane → never overlap, before or after. The fifth, `#patch_pane_entries`, is a different 2×2 pane (left half) → cross-pane, trivially disjoint. So the only discriminating assertion is the paste-visible-rows one (mis-specified per Q-01). | Stack layout: `screens_directionb.py` TC-319 shows `#patch_doc_file_row` children stacked; `test_tui_patch_layout.py:161-176` overlap idiom is for the outer 2×2 panes; `#patch_pane_entries` is a top-level pane, the other four live in `#patch_pane_changefile` | Keep non-overlap only as a cheap guard; explicitly state in AT-058a that the **visible-row count is the sole C-10 discriminator**. Drop `#patch_pane_entries` from the "control groups" set (category error) or re-frame the five as the four inner groups + a note. |
| **Q-04** | **blocker** | US-060 | The I-060-1 construct-equivalence gate (qa Phase-1 required it; 01b §5/§9.1 makes it a hard precondition) is **absent from the requirements**. `LLR-060.2` "Executed verification" is size measurement only; nothing diffs the two `case_06` A2Ls' constructs. The whole coverage-preservation claim (§5.2 "identical code path") is thus unproven — if the 54 MB copy carries a construct the 36 MB lacks, the delete silently drops a parser/validator branch no golden catches. | `LLR-060.2` verification = sizes only (37,742,888 B / 56,046,631 B); probe P15 measured SIZE, not constructs; open question §2.6 "are the two copies genuinely duplicative" left unresolved; 01b §5 gate I-060-1 not mirrored into any LLR | Fold I-060-1 into `LLR-060.3` (or a new `LLR-060.5`) as a **hard Phase-3 precondition**: structural construct census (section kinds, nesting depth, symbol/record counts) of both A2Ls, evidence recorded BEFORE the delete; block the delete if constructs diverge. |
| **Q-05** | minor | US-059 | Requirements LLR-059.3 claims adding `"Hex"` breaks **THREE** assertions incl. the modal-header equality `headers == list(LEGEND_TABLE)` at `:322`. That one is fully dynamic — both sides derive from `LEGEND_TABLE` — so it **SURVIVES**. Only two break: the hardcoded `set(LEGEND_TABLE)=={"A2L","MAC","Issues"}` (`:78`) and the orphan-colour check (`:70`). | `test_tui_legend.py:322` `assert headers == list(LEGEND_TABLE)` (modal renders via `LEGEND_TABLE.items()`, `screens.py:527`); 01b census row #3 correctly marks it SURVIVES | Correct LLR-059.3 to "breaks TWO" (`:78`, `:70`); list `:322` as SURVIVES-regression, matching 01b census #3. |
| **Q-06** | minor | US-058 | Requirements' provisional snapshot cell id `patch-80x24` (LLR-058.4 + probe ledger last row, flagged `assumed`) is **wrong**. Confirmed on disk. | `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-80x24].svg` and `[patch-comfortable-120x30].svg`; id template `f"{screen}-comfortable-{size_key}"` `test_tui_snapshot.py:512` | Replace the two provisional ids in LLR-058.4/probe ledger with **`patch-comfortable-80x24`** + **`patch-comfortable-120x30`** (01b §4 already correct); retire the `assumed` flag. |
| **Q-07** | minor | US-059 | The new Hex↔`color_policy` coupling must derive the legend colour NAME from the style constant **deterministically** (strip `"bold "`, map `orange3`→`Orange`), not hardcode `"Yellow"`/`"Orange"` independently — else the "anti-drift" test does not actually couple to the shipped hex render. Constants are style strings (`"bold yellow"`), legend rows are colour names. | `color_policy.py:13-14` `FOCUS_HIGHLIGHT_STYLE="bold yellow"`, `MAC_ADDRESS_OVERLAY_STYLE="bold orange3"`; 01b §9.2 flags the fragile-substring risk | Require legend.py to expose a `hex-colour-name → style-constant` map, and TC-322 to assert the extraction from the constants (not a literal restatement). |
| **Q-08** | minor | US-059 | AT-registry drift (C-21): requirements §5.1/§5.2 list only **AT-059a** (one node, both surfaces); 01b splits **AT-059a (modal, `test_tui_legend.py`)** + **AT-059b (report reread, `test_tui_report_seam.py`)**. Both are C-18-legal, but bundling a `generate_project_report`→reread into the legend-modal node mixes homes; the C-12 report arm belongs in the report-seam home. | req §3 "AT-059a (both-surface, one node)"; 01b §1/§2.3 two nodes; C-12 reread idiom lives in `test_tui_report_seam.py:182-221` (`test_report_seam_writes_real_file_on_disk`) | Reconcile the registry at the gate: adopt 01b's split (AT-059a modal + AT-059b report reread) and amend requirements §5 to register AT-059b. |
| **Q-09** | minor | US-058 | 01b §3.1's N-derivation rule ("N ≥ `DUMMY_CHANGESET_TEXT` line count") = **11**, but the editor is `height: 8` and can never render 11 visible rows. The requirements' N=6/8 frame is feasible; 01b's rule is infeasible. | `DUMMY_CHANGESET_TEXT` = 11 lines; `styles.tcss:950` `height: 8` | Reconcile: N is bounded by the height:8 editor and measured against the **visible viewport** (Q-01); drop the "≥ 11 line count" rule. |

---

## Answers to the review's specific questions

**1. Testability of each requirement + validation method.** US-059 and US-060
are testable as specced (both legend consumers iterate `LEGEND_TABLE` dynamically
— `test_report_includes_legend_with_documented_rows` and `test_tc_s2` auto-extend
to Hex; confirmed the report reread idiom exists). US-058's method is testable but
the AT names the WRONG geometry primitive (Q-01) and an unmeasured threshold (Q-02).

**2. AT quality (C-10/C-12/C-18).**
- C-10: AT-059a/b assert exact meaning strings (good — mirrors `LEGEND_TABLE[...][1] in meanings`, `test_tui_legend.py:181`). AT-060a asserts named fixture + numeric size (good). **AT-058a fails C-10** as written (Q-01/Q-03).
- C-12: AT-059b/AT-060a genuinely output-then-consume — `test_report_seam_writes_real_file_on_disk` runs the REAL `generate_project_report` and rereads the file (`test_tui_report_seam.py:9,182-221`). AT-059a as bundled in requirements is awkward (Q-08) but the intent is C-12-correct.
- C-18: each AT maps to one node; 01b §2.3 flags AT-060a must not split (correct). The one registry mismatch is Q-08.

**3. Counterfactual soundness.** AT-059a/b/AT-060a counterfactuals are real (no Hex
block today; pv__ case + tmp/stress_smoke exist today). **AT-058a's is not** —
`region.height` is CSS-invariant and non-overlap is stack-trivial (Q-01/Q-03). Note
the app's Textual version reports a **NULL region (0,0)** for a *fully* scrolled-out
widget (documented at `test_tui_patch_variant.py:421,443`) but the FULL laid-out
region for a *partially*-visible one — and DF-1 says the paste box is partially
visible (~1-2 rows), so it reports height 8 today. The ≥6-line threshold IS
measurable and non-flaky **iff** measured via `content_region` intersection at
`scroll_y == 0` (the TC-035.2 pattern), with a null-region guard.

**4. Snapshot-drift prediction (C-22).** Correct that exactly 2 patch cells drift
and US-059/US-060 drift zero. Cell ids now pinned: `patch-comfortable-80x24`,
`patch-comfortable-120x30` (Q-06 corrects the requirements' `patch-80x24`).

**5. I-060-1 as a Phase-3 gate.** NOT reflected in the requirements → **Q-04 blocker**.

**6. US-059 anti-drift split.** Mostly correct (keeps the strict severity guard for
A2L/MAC/Issues, gives Hex its own coupling) but the breakage count is wrong
(Q-05: 2 assertions break, not 3) and the coupling must be deterministic (Q-07).

**7. Coverage-preservation map (US-060).** Structurally complete and node-by-node
correct (net delta 0; the relocated stress triple is a coverage GAIN). But its
central premise — the 36 MB case exercises the same constructs as the 54 MB — is
**unproven** without I-060-1 (Q-04). Map is correct AS A MAP; its leaf is ungated.

---

## Evidence checklist (qa-reviewer, Phase 2)

- [x] AT-058a reliability adjudicated against the actual pilot API — verdict: reliable ONLY via `content_region` intersection (`test_tui_patch_variant.py:434-438`), not raw `region.height`. Q-01.
- [x] Patch snapshot cell ids pinned from disk — `patch-comfortable-80x24`, `patch-comfortable-120x30` (`tests/__snapshots__/test_tui_snapshot/`). Q-06.
- [x] I-060-1 checked for hard-gate status in the spec — ABSENT (`LLR-060.2` size-only). Q-04.
- [x] US-059 anti-drift breakage re-grepped — `:78` + `:70` break, `:322` survives (dynamic). Q-05.
- [x] Coverage-preservation map completeness verified — complete; leaf premise ungated (Q-04).
- [x] C-12 report reread idiom confirmed to exist — `test_tui_report_seam.py:182-221`.
- [x] Every finding cites file:line — table above.
- [x] Test-results left blank — this is a review artifact; no execution claimed (only recon greps + `--collect-only`-class inspection).
- [x] No real PII / secrets surfaced.

## Verdict

**APPROVABLE WITH REQUIRED FOLDS.** Two blockers (Q-01, Q-04) and two majors
(Q-02, Q-03) must be folded into `01-requirements.md` before Phase-3 implementation;
all four are corrections/gates, not story-kills. Minors Q-05..Q-09 are accuracy
reconciliations. The QA strategy (01b) already anticipates most of these — the gap
is that the authoritative requirements file does not encode them.
