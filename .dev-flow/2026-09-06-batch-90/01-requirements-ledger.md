# Requirements ledger — s19_app — 2026-09-06-batch-90

> **Append-only.** Entries are added in chronological order and never rewritten, never renumbered,
> never deleted. An entry that turns out wrong is superseded by a NEW entry that names it. The live
> contract is `01-requirements.md`; this file records how it came to say what it says. Every entry
> names the requirement it amends; every requirement names its entries. `V26` compares the two sets
> of pairs in both directions and BLOCKs on any pair present on one side only.
>
> This file lives under `.dev-flow/` deliberately: writing an id here DECLARES it to the corpus
> scanner, so traceability survives the split (C-56). For the same reason no mutation transcript in
> this file spells a mangled token — mutations are described by position and operation.

### LED-90.1 — the defect is a classification, not a missing rule, and that is why the requirement is about reporting

- **Requirement:** HLR-90.1, LLR-90.1.1, LLR-90.1.2
- **Date:** 2026-09-06
- **What changed:** `HLR-90.1` was written as an obligation to **report** an unregistered
  identifier, and the two decomposing LLRs were written against the classifier and the node
  derivation rather than against any guard rule.
- **Why:** the guard rules themselves are not wrong. `G1` asks the right question — *is every id
  derivable from a node name registered?* — and returns a correct answer over the set it is given.
  The set is where the defect lives: the tokenizer classifies a letter-initial body as ungoverned
  and the function-name pattern requires digits immediately after `at`/`tc`, so a batch-scoped id
  never enters the set and `G1`, `G3` and `G5` all decline to police it **without saying so**. This
  is the vacuous-input-set class (C-31) one layer up: an id form the pattern cannot parse is
  indistinguishable, to every rule downstream, from an id that does not exist. Writing the
  requirement against `G1` would have fixed the symptom in the rule that is already correct.
- **Evidence:** executed against the shipped tool —
  `iter_tokens("AT-B78-12")` → `IdToken(space='AT', body='B78-12', governed=False, conforming=False, key=None)`;
  `iter_tokens("TC-489")` → `governed=True, conforming=True, key='TC-489'`.
  The function-name pattern returns **NO MATCH** for `test_at_b78_09_loaded_panel_names_the_project`
  and `[('tc', '489', '')]` for `test_tc489_candidate_consumption_is_r_independent`.
  Population: **141** batch-scoped node definitions, **127** distinct ids, **0** registry rows,
  `1378` registry entries in total.

### LED-90.2 — the blast radius is a measured number, produced before the change

- **Requirement:** HLR-90.1, LLR-90.1.3, LLR-90.1.4
- **Date:** 2026-09-06
- **What changed:** `LLR-90.1.3` carries `678` as an executed count of today's derived identifiers,
  and `LLR-90.1.4` carries `127` as the number of rows the registry must gain. Neither number was
  predicted and neither was inherited from the backlog item.
- **Why:** the backlog item's own reason for demanding a dedicated batch is that widening the
  pattern *"reclassifies tokens repo-wide and could redden G1/G3/G5 across 678 existing ids"*. A
  threshold a gate is keyed on must be produced by an executed derivation over the current tree,
  never predicted (C-39) — and this one is computable before any implementation exists, so
  *"we'll find out in Phase 3"* would be a choice rather than a constraint. It was run.
  The `678` reproduces at this tree, which is worth saying because three of the five figures in the
  registry spec's own §1 did **not** reproduce when they were re-derived.
- **Evidence:** `derive_named_nodes` over **156** test files at this worktree → **678** distinct
  identifiers. `load_registry` → **1378** entries, of which **0** have a letter-initial body.
  Batch-scoped node definitions by tag: `b77:30 b78:74 b79:5 b83:18 b84:14`, summing to 141 over
  127 distinct ids.

### LED-90.3 — the residual requirement is about what the guard must distinguish, not about the canon

- **Requirement:** HLR-90.2, LLR-90.2.1, LLR-90.2.2
- **Date:** 2026-09-06
- **What changed:** `HLR-90.2` obliges the **guard**, and neither it nor its LLRs asks for an edit to
  `REQUIREMENTS.md`.
- **Why:** two measurements decided this. First, all **7 of 7** residual figures already occur
  inside the true `R-TUI-098` section, so binding the search to that section is achievable against
  the canon as it stands — a requirement that also demanded a canon edit would be asking for work
  that the measurement says is not needed, and a rule that false-fails a correct document costs as
  much as one that passes a wrong one (C-53). Second, the node's own docstring already concedes that
  its other half is a judgement flagged rather than automated; the executable half is the half a
  requirement can bind.
- **Evidence:** the anchor `**R-TUI-098**` occurs once. From it to the next `##` heading
  (`## Multi-image flow runs + report fusion — batch-70 (R-TUI-099)`) is **13,394** characters; the
  node currently slices **86,129**, anchor to end of file — a **6.4×** over-slice. In-section counts:
  `988 B/entry` 1 · `×1.68` 1 · `×1.81` 1 · `×1.94` 1 · `19200 → 300` 1 · `500 → 128000` 2 ·
  `+N more` 2. Whole-file count for `988 B/entry` is **2**, so **1** occurrence sits before the
  anchor and the whole-document search is satisfiable from outside the section today.

### LED-90.4 — the counterfactual was executed at P1 authoring time, not deferred to the increment

- **Requirement:** HLR-90.2, LLR-90.2.2, LLR-90.2.3
- **Date:** 2026-09-06
- **What changed:** `HLR-90.2`'s and `LLR-90.2.2`'s negative-control fields record an executed
  transcript rather than a described intention, and `LLR-90.2.3` was added to oblige one mutation
  per clause.
- **Why:** C-40 answers *"can this predicate go RED?"* at authoring time, by execution — and C-55
  limb 1 adds that a conjunctive criterion needs one mutation per conjunct, because mutating the
  section bound says nothing about the refutation clause and vice versa. The premise being tested
  here is the item's own claim that batch-74 rewrote a non-claim to say the figure was false and
  `TC-497` stayed green. That claim was reproduced rather than cited.
- **Evidence:** baseline `1 passed, 28 deselected`. A refutation was inserted into the `R-TUI-098`
  section, on the line following the one carrying the first residual figure, as one block-quoted
  sentence declaring that figure false and superseded; the figure token itself was left unchanged.
  `git diff --stat` reported `REQUIREMENTS.md | 3 +++`, which is the confirmation that the mutation
  applied — a typo'd mutation also produces a verdict, for the wrong reason. The node then reported
  `1 passed, 28 deselected`. The tree was restored with `git checkout --`, the file's `sha256`
  returned to `fc37480bfb6dad943d61b9921ab0888bad4ef3a1b34c211deb1f981a7f43b554`, and
  `git status --porcelain` was empty. The mutation is described here by position and operation and
  is nowhere spelled, because this file is corpus input to the scanners (C-56).
