# Phase 5 — Post-mortem — batch-48 · screen-upgrades Batch B: Patch Editor BIG

> **Batch:** `2026-07-16-batch-48` · **Branch:** `feat/batch-48-patch-big` · **HEAD:** `8a00f51`
> **Base:** `6551aed` (== origin/main tip at kickoff) · **15 commits** (7 story + 8 fix/ruling/doc)
> **Author:** docs-writer (Phase 5). Read-only synthesis of PLAN.md, 01/01b/02/04, and increments 01–07.
> **Predecessor:** batch-47 (Batch A) MERGED + synced. **Language:** English (per kickoff). BLUF throughout.

---

## 1. Executive summary (BLUF)

**Batch B shipped all six stories of the Patch Editor BIG tier (HLR-075…081) — the live before/after card the headline — with the engine-frozen set byte-identical throughout and the ≤5-file cap held on every increment.** One HIGH was found and closed pre-merge (the vacuous hue census, Inc-5b), on top of two HIGH security findings closed in Inc-1/1b (a live `Text.from_markup` sink in the entries table, plus a `Select`-label class the spec never named). The dual-traceability matrix is COMPLETE and GREEN on all three axes; the single open item is documentation-only (Amendment D not folded into §6.5). **The batch's signature finding: 9 vacuous checks — assertions or fixtures that pass on broken code — most of them authored by the SPECS and the orchestrator's own briefs, and every one caught by an implementation or review agent.** That asymmetry (defects cluster in the artifacts with no edge binding them to code) is this post-mortem's thesis, and it converges on a single control candidate the operator already flagged.

---

## 2. What shipped

| Story | HLR / R-TUI | Widget delivered |
|---|---|---|
| US-P1 | HLR-075 | Window border titles + live subtitles (entry count · run state · schema); entries-table **role colours** (kind purple · address cyan · bytes bright) as `Text` cells; variant + scope **line**. Fixes a **pre-existing live injection/crash sink** in the entries table. |
| US-P1 | HLR-076 | Colour-grouped **chip-button CSS** family (entry / apply / checks), patch-scoped so C-30 stays N/A; the batch-47 CSS carry, with its first consumer. |
| US-P2 | HLR-077 | Check **glyph** (`✓`/`◐`/`✗`/`·`) **folded into the `Kind` cell** (no new column), index-aligned to document order, guarded by a two-part `(document_signature, image_generation)` provenance stamp. |
| US-P3 | HLR-078 | CHECKS **pass/fail strip** — `✓P ✗F ◐U` counts + a proportional (unfloored) microbar. |
| US-P4 | HLR-079 | JSON-window **syntax colouring** (in-place `TextArea._highlights`, no new dependency) + a **paste-cap gauge** (`N KB / 64KB`) in a new, hue-measured MAGENTA. |
| US-P5 | **HLR-080** | **The live before/after card** — on row select, image bytes at the entry's address vs the bytes the entry would write; read-only, applies nothing. **The headline.** |
| US-P6 | HLR-081 | History **strip** — undo/redo position (`↶ N back ↷ N fwd N/20`) + `ctrl+z`/`ctrl+y` hints. |

Plus R-NEW-1 (mid-batch, beyond spec): the C-17 `Select`-label class, closed at all three of its sites.

---

## 3. Metrics (for vault frontmatter)

```yaml
batch: 2026-07-16-batch-48
title: "Patch Editor BIG (screen-upgrades Batch B)"
head: 8a00f51
increments: 10            # Inc-1, 1b, 2, 2b, 3, 4, 5, 5b, 6, 7
commits: 15               # 7 story + 8 fix/ruling/doc
files_touched: 18         # 6 source + 11 test + REQUIREMENTS.md
  source: [screens_directionb.py, services/change_service.py, app.py, styles.tcss, insight_style.py, json_highlight.py(NEW)]
  new_test_files: 6       # patch_big, patch_chips, patch_glyphs, patch_checks_strip, patch_json, patch_history_strip, patch_card  (7 new — patch_card is the 7th)
us_total: 6
us_ready: 6
us_covered: 6
requirements: 8           # 7 HLR (R-TUI-075..081) + R-NEW-1
at_registry: 26 canonical + AT-075f (3 nodes / 15 param cases)   # all resolve to on-disk nodes, all green
llr_coverage: complete    # every HLR/LLR has >=1 green TC or declared inspection/analysis; zero orphan
findings_phase2: {blocker: 4, major: 8, minor: 7}   # 1 blocker = HIGH security
security_findings_HIGH: 2 # BL-1 entries-table sink; R-NEW-1 Select-label class (3 sites) — both closed pre-merge
high_found_mid_batch: 1   # HIGH-1 hue census (vacuous input set), Inc-5b — closed pre-merge
vacuous_checks: 9         # see taxonomy §4 — 0 caught P2, 9 caught P3, 0 caught P4
caught_p2: 0              # (of the 9 vacuous checks; Phase-2 review separately caught 19 review findings)
caught_p3gate: 9
caught_p4: 0
pct_vacuous_caught_p2: 0%
controls_stress_tested: 10  # C-7, C-10, C-15.1/MJ-1, C-17, C-18, C-22, C-26, C-27, C-29, C-30
cap_trips: 0              # <=5 files held every increment; Inc-5b/Inc-6/Inc-7 each DECLINED a 6th file
frozen_diff: 0            # C-27 dual-guard: byte-identical every increment
snapshot_drift_cells: 2  # patch-comfortable-80x24 / -120x30 (xfail strict=False, absorb; regen post-merge)
tests_base_reduced: 1449 # `-m "not slow"` @ 6551aed (measured, corrected from a stale 1416)
tests_post_reduced: 1540 # `-m "not slow"` @ ef7fe74 (Inc-7)
tests_post_full: 1560    # `pytest -q` unfiltered @ ef7fe74 → 1560 passed / 0 failed / 5 xfailed (EXIT=1 = pre-existing syrupy artifact, §7 below)
new_control: C-31, C-32   # operator-approved 2026-07-17: C-31 (input-set-is-an-oracle) → global dev-flow.md; C-32 (assert-the-painted-result) → project docs/engineering-rules.md. Unified A/C traceability control DEFERRED to a focused follow-up (needs its CI staleness guard). §8.
open_items_next: [phase6-docs, amendment-D-§6.5-reconcile, snapshot-regen-PR(+2 orphan tc036s), prototypes-delete, LLR-four/three-sites-errata, OptionList-sweep, control-encode-decision]
```

> ⚠ Two ledger caveats, stated not hidden. (a) `tests_base` was corrected mid-batch from a stale **1416** (which never reconciled) to a **measured 1449**; cause of the stale figure remains UNKNOWN and was not back-filled with a story. (b) Suite counts mix the reduced (`-m "not slow"`) and full (`pytest -q`) variants across increments; the figures above name which is which. Baseline for Inc-6 was *derived not measured* and declared as such.

---

## 4. ⭐ The vacuous-check taxonomy (this batch's central finding)

A **vacuous check** passes on code that is broken — it cannot fail, so it is non-evidence. This batch surfaced **9** of them (the Phase-4 reconciliation, `04-validation.md §2.2`, is the canonical count). The striking fact is **who wrote them**: most were authored by the requirement specs (`01b`) or the orchestrator's own increment briefs, and **every one was caught by an implementation or review agent** — usually by mutation-testing the oracle or measuring the pinned source, occasionally just by reading the file the answer was already in.

### The 9 canonical vacuous checks

| # | Vacuous check | Caught | Author | Class |
|---|---|---|---|---|
| 1 | **AT-077d palindrome fixture** `['✓','✗','✓']` — an ORDER test that passes a full reversal | Inc-3 (M-4b) | **SPEC (01b)** | vacuous assertion |
| 2 | **AT-078a degenerate 2/1/1** — `failed==uncheckable`, so a label swap is invisible | Inc-4 (M-2) | **SPEC (01b)** | vacuous assertion |
| 3 | **AT-078b zero-case oracle false** — no zero-pass test can discriminate the microbar floor (`floor` gates on `clamped>0`) | Inc-4 (M-1) | **SPEC (01b)** + brief | vacuous assertion |
| 4 | **`floor=False` justification false** — the "overstating passes is the harm / asymmetry" rationale, ordered verbatim; the top-end overstates identically | Inc-4 (M-1) | **orchestrator brief** | false reasoning (conclusion survived, reasoning did not) |
| 5 | **AT-079b `.spans` unsatisfiable** — `get_line(i).spans` is *always* `[]`; the pass condition is structurally impossible | Inc-5 (BLOCKER-1) | **SPEC (01b)** | vacuous assertion |
| 6 | **AT-079c span clause dead** — the gate-blocking C-17 AT's `.spans==[]` clause is constant-true on safe, unsafe, and unwritten code | Inc-5 (BLOCKER-1) | **SPEC (01b)** | vacuous assertion |
| 7 | **AT-079c cursor-line masking** — the render-path oracle passes on a *provably unsafe* buffer because the cursor line restyles over the injected span | Inc-5b (item 8) | agent's own new oracle | vacuous assertion (confounder) |
| 8 | **hue census vacuous INPUT SET (HIGH-1)** — "≥40° from EVERY hue", arithmetic exact, but the set OMITTED the hue (`#e06c75`, 38.44°) that fails it | Inc-5b (F1) | **orchestrator brief** | **vacuous INPUT SET (NEW class)** |
| 9 | **TC-080.1 `vars(card)&dir(Widget)` wrong oracle** — returns the identical 12 metaclass names for the shipped card; filtering to private names is vacuous (the card authors none) | Inc-7 (§4) | agent's own draft | vacuous assertion |

### The NEW class — "vacuous input set" (the ninth, HIGH-1)

The first eight were vacuous **assertions**: a check that cannot fail, findable by mutating the code under test. **HIGH-1 is a vacuous INPUT SET** — the assertion was real, the arithmetic exact, the measurement honest, and it was *still* wrong because the SET it quantified over was incomplete. **Mutate the code and it still passes**; the defect lives one level above everything the batch was hunting. The fix is structural: `test_tc079_5c` now **sweeps** every `#rrggbb` in `s19_app/` and requires each to be *claimed or excluded-with-reason*, and `_admissible_optimum()` **recomputes** the arc from the census every run — so census and arc can never silently drift apart. The orchestrator's floor was not merely arbitrary but **unsatisfiable**: best achievable = 40.77°, shipped claim ≥43° — a property no colour can have, "passing" only because the census omitted the failing hues.

### The meta-pattern — the thesis

**Defects clustered in the artifacts with no edge binding them to code.** Tallying authorship:

- **The SPEC (01b) authored the degenerate fixtures** — four prescribed fixtures were degenerate across the batch (AT-077d palindrome, AT-078a 2/1/1, AT-081a's `(1,1)` palindrome kept in Inc-6, and the `['✓','✗','✓']` shape twice). Each was a fixture the spec *named*, and each passed a mutation it existed to catch.
- **The orchestrator's briefs authored** an unsatisfiable threshold (≥43°), the false floor-justification ordered verbatim (the Inc-4 agent's first draft asserted the opposite before measuring, then refused), **two inverted geometry budgets** (the Inc-4 C-29 wrap regime recorded backwards — strip wraps at 120×30, fits at 80×24 — with the "16-cell" replacement figure itself one level too generous; the real budget was 14), and **two ID misfires** (Inc-3's brief named the wrong base commit; Inc-6's brief mislabelled the history strip HLR-080 when it is HLR-081 — against a requirements doc that *already recorded* this exact clash having misfired a Phase-2 security brief).
- **The implementation agents caught all of them.** Not one vacuous check shipped. Several agents additionally caught their *own* false oracles mid-increment (Inc-2's `getattr(l,"renderable","")` de-dup guard that silently returned `""`; Inc-2's false AT-076b RED ledger; Inc-4's three source-grep oracles that matched the author's own prose; Inc-5's YELLOW-keyword hue near-miss; Inc-5b committing the F2 defect *while fixing F2*), reinforcing the same shape.

**The general shape: a claim, fixture, census, or budget stated in a spec or brief, with nothing binding it to the code it describes — and the sweep/census axis keyed to code SYMBOLS while the defect lives where no symbol names it.** That is the thread connecting the vacuous input set, the shared-namespace hue collision, the missed writer-census sites, and the C-26 seed-table gaps (§8).

---

## 5. What went well

- **MJ-1's shape caught a real defect THREE times.** MJ-1 was batch-47's writer-census-at-Phase-2 precedent (catch a defect before code). This batch reproduced its *catch* three times: Inc-3's provenance stamp needed a **fifth `refresh_entries` site** at the load seam (the stamp is a model-side fix; the render also needs a trigger); Inc-6's history strip needed a **fourth `set_undo_redo_enabled` site** at mount (LLR-081.3 named three — a fresh screen painted `''`, not the empty state); Inc-7's card writer-census, **run before any card code**, found the load-triggered site the Phase-2 census omitted. Each was the *same* omission — a census keyed to "who calls this on an action" when the question is "who renders this state."
- **Mutation-testing every RED was the discipline that caught the agents' OWN false REDs.** The rule "if an AT exists to catch a mutation, apply that exact mutation and watch it fail" repeatedly falsified predictions the agents had written down: Inc-2 (its AT-076b RED ledger was false), Inc-3 (three ledger claims false — M-1/M-4b/M-6), Inc-4 (three of five predictions wrong), Inc-6 (four of seven wrong). In every case "the run won." A recorded RED that was never executed is worthless; this batch proved it, repeatedly.
- **The C-27 frozen guard was 0-diff throughout** — the entire batch surface is non-frozen; every C-17 fix landed at a non-frozen render boundary. Byte-identical every increment, both guard arms green.
- **The ≤5-file cap held every increment.** Inc-5b, Inc-6, and Inc-7 each *declined a 6th file* explicitly (the deferred `test_tui_insight_style.py` F4 docstring / F5 trim) rather than silently busting the cap.
- **Every gate was independently reviewed** — cross-agent Phase-2 (architect ∥ security), per-increment code review, and an independent Phase-4 dual-traceability reconciliation.
- **The HIGH was caught at increment-5, not final-QA.** Unlike batch-47 (whose HIGH-1 surfaced at final PR-QA), Inc-5's own review blocked on the vacuous C-17 gate and the hue census, closing HIGH-1 in Inc-5b — well inside the run.

---

## 6. What didn't — the orchestrator's error ledger (stated plainly)

This batch's honesty is the point: the errors were disclosed in the increment packets, not buried. The orchestrator's own ledger:

- **2 ID misfires** — Inc-3's brief named the wrong base commit (`b8d9ce3` when the real HEAD was `ac3ba35`/Inc-2b); Inc-6's brief mislabelled the history strip HLR-080. Both against a requirements doc that had *already recorded* the HLR-080↔081 clash misfiring a Phase-2 security brief (BL-2's recurrence — which the orchestrator also self-reported: dispatching two fold agents in parallel and letting each mint AT ids re-created the very divergence BL-2 blocked on).
- **2 inverted geometry budgets handed to agents** — the Inc-4 C-29 wrap regime recorded backwards, *and* the "16-cell" replacement budget still too generous (real: 14). The C-29 "measure the real container, not its parent" lesson then bit **four increments in a row** (Inc-4 → Inc-5 corrected it → Inc-6 inherited-14 trap → Inc-7 inherited-38-vs-36 trap), each caught by an agent re-measuring.
- **1 unsatisfiable threshold** — the ≥43° hue floor (best achievable 40.77°).
- **1 confidently-wrong floor justification ordered verbatim** — the microbar `floor=False` asymmetry rationale; the Inc-4 agent's first draft asserted the opposite before measuring, then refused to ship the reasoning (correcting it to "redundancy, not asymmetry"). The refutation was in the file the whole time — `microbar`'s own docstring and a batch-47 test ~60 lines above the edit.
- **The 57-min / 98%-CPU process-attribution error — made by BOTH an agent and the orchestrator.** A real measurement bound to the *wrong process*: Inc-7 misread `ps -W` columns and named an unrelated cygwin job's `runfixed.py` as its pytest; the orchestrator's own Phase-4 background full-run tracking chased the same phantom. "A PID's existence is not evidence; the command line is."

Plus the process hygiene failures, all disclosed:

- **Three agents edited files mid-test-run** — Inc-2 (a `styles.tcss` comment; run 1 discarded), Inc-3 (an `app.py` comment; run A killed), Inc-6 (an `app.py` docstring → 2 *phantom* failures via `linecache`/`getsource` line-shift, diagnosed not re-rolled). Lesson generalised: **never edit a source file while a suite that AST-inspects it is running.**
- **Two "slow ≠ hung" mis-calls** — Inc-7's 57-min confusion (waited it out correctly, in the end) and the Phase-4 full-run wait.
- **One destructive command / one near-miss** — Inc-4 ran `git checkout screens_directionb.py`, discarding its *own* uncommitted work (a real violation of the no-destructive-without-approval rule; self-inflicted, contained to one file, rebuilt and verified). Inc-7 **nearly killed** an unrelated process on the false 57-min alarm — the exact failure the monitoring rule warns about — and stopped after reading the actual command lines.

None of these reached `main`: every one was caught in-increment, disclosed, and corrected.

---

## 7. Controls stress-tested this batch

| Control | How exercised | Held / gap |
|---|---|---|
| **C-7** (panel purity) | Every new datum (`mem_map`, aggregates, history depths) threaded as a `refresh_*` **parameter**; AST-verified 0 `self.app` / 0 service imports in `PatchEditorPanel` each increment | **Held** — "the single best-argued decision in the document" (architect) |
| **C-10** (one AT per policy branch) | Strip branches (all-pass / has-fail / has-uncheckable / zero / cleared); glyph branches; history quadrants | **Held** — but is per-branch-of-*one*-policy; blind to two policies competing for one resource (the hue collision, §8-C) |
| **C-15.1 / MJ-1** (writer census before code) | Caught the 5th `refresh_entries` (Inc-3, Inc-7) and 4th `set_undo_redo_enabled` (Inc-6) sites | **Held where the census was DERIVED** (AST-walked); the *spec's* hand-listed census shipped the omission — this is the gap §8 targets |
| **C-17** (untrusted-text markup safety) | Fixed a live `Text.from_markup` sink in the entries table (BL-1, HIGH) + the `Select`-label class (R-NEW-1, HIGH, 3 sites); in-place JSON colouring verified safe-by-construction | **Held** — but its ATs were **twice vacuous** before the "assert the painted result" correction (§8-D) |
| **C-18** (one node per AT) | 01b's executed-verification commands run **verbatim**; Inc-3 found one node-id mismatch that would have made a command report "no tests ran" | **Held** — by execution, not by reading |
| **C-22** (per-cell snapshot prediction) | Predicted + MEASURED every increment; exactly the 2 patch cells drift, `xfail(strict=False)` absorbs, 0 new marks | **Held** — "their passing is NOT evidence" stated every time |
| **C-26** (touched-symbol reverse census) | Caught real regressions (Inc-1 placement RED; Inc-3's 2 broken tests; Inc-5's subclass false-alarm) | **Gap surfaced 3×** — the census is keyed to **symbols** and was blind to non-symbol artifacts (`styles.tcss`, a `"CappedTextArea"` string, an exhaustive Button-parent set) |
| **C-27** (frozen dual-guard) | Raw `git diff` over the frozen set = empty every increment; both guard-test arms green | **Held** — 0 diff throughout |
| **C-29** (two-axis geometry) | Re-measured with each new widget mounted, both regimes | **Held only because agents RE-MEASURED** — the class bit four increments running; "measure the real container, not its parent" |
| **C-30** (restyle-last sequencing) | Chip CSS patch-scoped; leak probe (AT-076b) measured 0 non-patch drift | **Held** — N/A verdict confirmed by measurement, not asserted |

---

## 8. Control candidates (RAISE, do not encode)

> Encoding any control requires an explicit operator AskUserQuestion (`ask` rule on `Edit(~/.claude/commands/**)`, per `feedback_devflow_control_encode_approval`). **This section raises; it does not encode.** Classify each before encoding: portable principle → global `/dev-flow`; stack-specific → the project's `docs/engineering-rules.md`.

Four candidates surfaced. **A, B, and C are arguably ONE control.**

### (A) code↔requirement traceability (the operator's call)
Code should reference the requirements it covers; the oracle is the **REVERSE index `resource → {requirements/claimants}`**, flagging any resource with ≥2 claimants in one scope. A back-reference *alone* does not catch the defect — two sites tagged `HLR-076` and `HLR-077` both using `#54efae` still look fine individually; the tag is the *enabling edge*, the reverse traversal is the oracle. **Half-built already:** `screens_directionb.py` carries 25 `LLR-*`/`R-TUI-*` back-refs; `REQUIREMENTS.md` maps `R-*` → files + tests. Three gaps: it is *convention not contract* (unenforced), *file-granular* not symbol/value-granular, and *never traversed in reverse*. **Cost to weigh:** requirement tags in code ROT — a drifted tag asserts a trace that no longer holds, buying a second false-confidence surface (the exact failure this batch kept hitting). Any encoding owes a CI staleness check.

### (B) "the input set is itself an oracle" (Inc-5b, HIGH-1's root)
*When a test certifies a UNIVERSAL, the input set is itself an oracle and must be **derived or guarded**, never hand-listed — code mutation cannot test an input set.* A distinct class from vacuous assertions (C-10) and belongs beside it. Instances: HIGH-1's hue census; batch-47 Inc-3 (deleted the micro-bar's only oracle); the `Select`-label missed sweep. The Inc-6/Inc-7 census tests already apply it (AST-derived, coverage-asserted, mutation-proven with M-7).

### (C) shared-namespace collision (Inc-2/3 hue)
A **shared, finite semantic namespace scoped to a container**, with multiple independent claimants each locally valid. Inc-2 claimed GREEN/YELLOW as a chip *function* cue while Inc-3 concurrently claimed the same hues as a glyph *verdict* cue in the same panel — **neither increment wrong alone, every AT green**, the defect living only in the overlap no artifact owns. Hue is one instance; the shape also covers **keybindings · widget ids · CSS specificity · markup sinks · glyph vocabulary**. Every existing control was blind because the axis is keyed to code *symbols* (Inc-2 wrote a hex literal in CSS, Inc-3 an `insight_style` constant in Python — same value, no shared name). ⚠ What caught it was **not reproducible** — a reviewer voluntarily read a sibling agent's uncommitted WIP; no control required that. Do not credit the process.

### ⚠ THE KEY SYNTHESIS (state this prominently)
**A, B, and C are arguably ONE control.** A `resource → claimants` reverse index IS a namespace registry; a value/artifact census IS the reverse traversal of a universal's input set. All three are the same shape: **a claim, census, or namespace with no edge binding it to the code it describes — the sweep/census axis keyed to code SYMBOLS while the defect lives where no symbol names it.** This is the SAME failure family as the C-26 seed-table gaps (blind to `styles.tcss`, to a `"CappedTextArea"` string, to an exhaustive Button-parent set — three value-keyed hits this batch), the R-NEW-1 missed sweep, and C-28's shared-chrome drift. **The operator asked whether ONE control subsumes all three; assess that before encoding.** The operator's leading candidate targets the **global `/dev-flow` + `/fast-dev-flow` rules** (classified project-agnostic): *"the code did not reference the requirements even though it covers both requirements"* — because a code↔requirement edge makes the overlap **queryable** (structural), not diligence-dependent.

### (D) "assert the PAINTED result" (stack-specific — Textual render path)
An oracle must observe the **rendered surface**, not a pre-layout proxy. THREE sightings in one batch: Inc-4 F2 (the strip's tests all read `Static.render()`, geometry-independent — a strip with `display:none` shipped green); Inc-5 AT-079c (the C-17 gate observed `.spans`, always `[]`); the `display=False` / `display:none` probe (Inc-7 M-6: 22 content oracles green, only the geometry arm caught the invisible card). ⚠ **And the painted result has its OWN confounders** — Inc-5b sharpened this: cursor-line masking and visual-vs-document line indexing mean moving the observation point closer to the pixels does not by itself make an oracle honest; *applying the mutation to your own new oracle and watching it fail* is what found traps 8/9/10. **D is stack-specific (Textual) → the project's `docs/engineering-rules.md`, not the global command.**

---

## 9. Open items → next (Phase 6)

1. **Phase-6 docs** — write the `REQUIREMENTS.md` `R-TUI-075…081` rows; reconcile **§6.5 Amendment D** (title de-dup) into `01-requirements.md` (still lists only A/B/retired-C; correct Amendment A's stale "Deleted — none"; re-word §5.2 `AT-076c` + §5.3 from "unmodified" to "passes, modified under Amendment D; 48-id tuple unchanged"). This is the **one named validation gap** — doc-only, iterate-to-refine, does not block the gate.
2. **Post-merge canonical-CI snapshot-regen PR** — bake the 2 patch cells' repaint into the SVG baselines and **retire `_batch48_patch_drift_marks`**; ALSO delete the **2 orphan `test_tc036s` entropy baselines** (retired in batch-45, still on `main`, the sole cause of `pytest -q` (full) `EXIT=1` via syrupy's unused-snapshot session-fail — **pre-existing, not a batch-48 regression**; the blocking gate `-m "not slow"` exits 0). Fix the dangling comment ref at `test_tui_snapshot.py:440`. **Local regen FORBIDDEN** (`snapshot-regen.yml`, textual==8.2.8 only).
3. **LLR errata** — LLR-077.5 "four sites", LLR-081.3 "three sites", LLR-080.2 "four call sites" are all now FALSE by one; the code + AST-derived census tests are authoritative (they fail loud if a further site appears). Orchestrator's call whether erratum or amendment.
4. **prototypes deletion** — delete `prototypes/screen_upgrades.*` + `prototypes/out/` now that Batch B is complete (handoff §10.4 absorb-then-delete).
5. **Carries** — the `OptionList` option-label sweep (only `Select` was swept); the named-colour census widen (values resolved, name SET still hand-enumerated); the batch-47 `sensor[unclosed` false-counterfactual carry at its origin (`test_tui_a2l_detail.py`).
6. **Control-encode decision** — the §8 synthesis, gated on an operator AskUserQuestion. Do not pre-adopt.

---

## Evidence checklist (Phase-5 completion)

- [x] **Audience/purpose declared** — engineering post-mortem for the operator + vault; top matter.
- [x] **Every claim traces to the record** — PLAN.md, 01/01b/02/04, increments 01–07, `git log 6551aed..8a00f51`.
- [x] **Metrics computed, not asserted** — §3; suite figures name reduced vs full; stale-1416 correction disclosed.
- [x] **The 9 vacuous checks enumerated with author + class** — §4, tracing `04-validation.md §2.2`.
- [x] **The orchestrator error ledger stated plainly** — §6; no failure omitted.
- [x] **Control candidates raised, NOT encoded** — §8; operator approval gate cited.
- [x] **Open items → next stated** — §9.
- [x] **No invented numbers** — every count cites its source; uncertainty flagged (baseline caveats, "nearly killed" vs "killed").
- [x] **No secrets / real client data** — synthetic C-17 payloads and byte fixtures only.
