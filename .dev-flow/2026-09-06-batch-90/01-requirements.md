# Requirements — s19_app — 2026-09-06-batch-90 · the lean contract

> **This file holds CURRENT STATE ONLY.** No strikethrough, no amendment bullets, no supersession
> narration, no measurement inside a normative sentence. The reason each requirement says what it
> says is in `01-requirements-ledger.md`, which is append-only and never edited. Every requirement
> declares a `**Ledger:**` field; every ledger entry declares a `**Requirement:**` field; `V26`
> compares the two sets of pairs in both directions.

---

## 1 · Scope

**Two defects, both of the same class: a green signal that is not evidence.** The project's id
authority reports nothing about a namespace the project itself mints, and the guard that protects
the `R-TUI-098` residual figures accepts a sentence denying a figure as though it were the figure.
Neither is a missing feature. Both are checks that pass while the property they name is false.

**Order.** `HLR-90.1` precedes `HLR-90.2` because batch-90's own id reservation is unsound until
the first lands.

**Not in scope, named rather than omitted:** `report_service` markdown escaping — dispositioned
`SATISFIED-EXTERNALLY` at P0 and dropped; widening the residual guard's figure list (a separate
backlog row); every other row of the code lane's prioritised index; the vault, the Atlas, and
anything under `~/.claude`.

**Held at P1.** The implementation stations are not opened in this wave. The reason is recorded in
`PLAN.md` §0 and is a sequencing decision, not an interruption.

---

## 2 · Source user stories

| ID | User Story | Source | DoR |
|----|------------|--------|-----|
| US-90.1 | As the **engineer allocating ids for a batch**, I want the id authority to cover every identifier namespace the project mints, so that a reservation actually prevents the collision it claims to prevent. | `.dev-flow/BACKLOG-CODE.md` §*Arrived 2026-07-31 by the router's Amendment A*; `AT-TC-REGISTRY-SPEC.md` §10 | READY |
| US-90.2 | As the **reviewer who will eventually rule on the `R-TUI-098` residuals**, I want the guard over those figures to fail when the canon refutes one, so that the figures I am asked to trust are the figures the document still asserts. | `.dev-flow/BACKLOG-CODE.md` §*New defects found in passing at batch-65* | READY |

### US-90.1 — the authority does not cover what the project mints

- **Ledger:** none
- **User:** the engineer opening a batch, following `CLAUDE.md`'s AT/TC id allocation rule.
- **Task:** reserving acceptance ids before writing them into a spec, then writing test nodes for them.
- **Environment:** a terminal in a worktree, alongside a concurrent session doing the same thing in another worktree, with no coordination between them beyond the registry file and git's merge conflicts.
- **Observable outcome:** the guard names an unregistered id whatever namespace it is minted in, so an unreserved id is caught by a red test rather than by a later collision.
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Out of scope:** `R-*`, `LLR-*`, `US-*` and `C-*` id spaces, which the registry has never governed.
- **Classification:** `READY`.

### US-90.2 — a refuted figure reads as an asserted one

- **Ledger:** none
- **User:** the reviewer or later batch that has to decide whether an `R-TUI-098` residual is still open.
- **Task:** taking the residual figures in the living canon as the basis for that decision.
- **Environment:** reading `REQUIREMENTS.md` and trusting that a green suite means the figures in it are current.
- **Observable outcome:** when the canon says a figure is false, the guard is red, so the reader is told rather than reassured.
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Out of scope:** which figures belong in the list; editing `REQUIREMENTS.md`.
- **Classification:** `READY`.

---

## 3 · Premise evaluation (C-43)

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | The registry holds no row for any batch-scoped id. | premise | ✅ TRUE | `git show origin/main:AT-TC-REGISTRY.jsonl \| grep -cE '"(AT\|TC)-B[0-9]+'` → `0`; and over the loaded registry, rows whose body is letter-initial → `0` of `1378` | — |
| P-2 | Batch-scoped ids are live on test nodes today. | premise | ✅ TRUE | `git grep -hE "^def test_(at\|tc)_b[0-9]+_" origin/main -- 'tests/*.py' \| wc -l` → `141`; distinct ids → `127`; tags `b77:30 b78:74 b79:5 b83:18 b84:14` | — |
| P-3 | The tokenizer classifies a batch-scoped token as ungoverned, with no key. | premise | ✅ TRUE | `iter_tokens("AT-B78-12")` → `IdToken(space='AT', body='B78-12', governed=False, conforming=False, key=None)`; `iter_tokens("TC-489")` → `governed=True, conforming=True, key='TC-489'` | — |
| P-4 | The registry's own metadata declares batch-scoped ids outside its authority. | premise | ✅ TRUE | `_meta.governed`: *"A token whose body starts with a digit. Letter-initial bodies … are batch-scoped / named-subspace ids, outside this authority by spec 2.3."* | — |
| P-5 | The population a grammar widening would reclassify is 678 ids. | premise | ✅ TRUE | `derive_named_nodes` over 156 test files at this tree → **678** distinct ids | — |
| P-6 | `TC-497` stays green when the canon refutes one of its residual figures. | hypothesis | ✅ TRUE | Executed at P0: baseline `1 passed`; refutation inserted into the `R-TUI-098` section (`git diff --stat` → `3 +++`); same node `1 passed`; restored, `sha256` returned to `fc37480b…`, `git status` empty | — |
| P-7 | Binding the figure search to the `R-TUI-098` section can be done without editing `REQUIREMENTS.md`. | premise | ✅ TRUE | All **7 of 7** residual figures occur inside the true section (anchor → next `##`, **13,394** chars). The node currently slices **86,129** chars, anchor to EOF | — |
| P-8 | The whole-document search is satisfiable today by an occurrence outside the section. | premise | ✅ TRUE | `988 B/entry` occurs **2×** in `REQUIREMENTS.md`, **1** of them before the `**R-TUI-098**` anchor | — |
| P-9 | Both guards are green on this branch before the work starts. | premise | ✅ TRUE | `pytest tests/test_id_registry.py -q` → `13 passed`; `pytest tests/test_report_addendum_bound.py -q -k tc497` → `1 passed, 28 deselected` | — |
| P-10 | `report_service` embeds file-derived text with no escaping. | premise | ❌ **FALSE** | `report_service.py` imports `md_safe`/`md_code` from `markdown_safety` and calls them **28** times; shipped at `fbc9f2a` (2026-07-26, PR #136), an ancestor of `origin/main` | **Closed at P0** — the item was dropped as `SATISFIED-EXTERNALLY` before any requirement was derived from it. Recorded here because the batch's scope was proposed on it |

---

## 4 · High-level requirements

### HLR-90.1 — the id authority covers every namespace the project mints

- **Traceability:** US-90.1
- **Ledger:** LED-90.1, LED-90.2
- **Statement:** If a test node carries an identifier in an `AT` or `TC` namespace that the project mints, then the id-registry guard shall report that identifier when the registry holds no entry for it.
- **Rationale (informative):** the registry exists so that a reservation prevents a collision. An id the guard cannot classify is indistinguishable, to every rule in the guard, from an id that does not exist — so the namespace that most needs the authority is the one it says nothing about.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_id_registry.py -q`
- **Numeric pass threshold:** 13 of 13 existing arms pass, plus the new arms; and the count of `AT`/`TC` identifiers carried by a test node that the guard neither registers nor reports is **0**, measured **127** today.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** an engineer who writes a test node in a batch-scoped namespace without registering the id sees a red guard naming that id, instead of a green suite.
  - **Shipped surface:** `pytest tests/test_id_registry.py`
  - **Acceptance test(s):** `AT-282` — **owed at Inc-1** *(reserved; provisional-until-Phase-3 per V-5)*
  - **Boundary catalog (QC-3):** ☑ empty — a registry with no batch-scoped row at all, which is today's tree · ☑ boundary — an id registered in one namespace form and cited in the other · ☑ invalid — a token that parses in neither form · ☑ error — a registry whose metadata omits the bound the new rule reads.
  - **Negative control:** the pre-state is the control and it is already executed. On this tree there are **127** batch-scoped ids on **141** node definitions and **0** registry rows for them, and `pytest tests/test_id_registry.py -q` reports `13 passed`. A guard satisfying this requirement is RED on exactly this input; the current one is green, which is the defect.

### HLR-90.2 — the residual guard distinguishes an assertion from its refutation

- **Traceability:** US-90.2
- **Ledger:** LED-90.3, LED-90.4
- **Statement:** If the living canon states that an `R-TUI-098` residual figure is false, superseded or corrected, then the residual guard shall report that figure as not carried.
- **Rationale (informative):** a presence search over a document pins a token, never a claim. Two sentences that say opposite things about the same number contain the same number, so the search cannot separate them — and the guard exists precisely to stop those figures decaying silently.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_report_addendum_bound.py -q -k tc497`
- **Numeric pass threshold:** the guard is GREEN on the unmodified canon and RED on each of the two refutation forms; **0** of the seven residual figures may be satisfied by an occurrence outside the `R-TUI-098` section.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a reader who refutes a residual figure in the canon sees the guard fail and is told which figure and why, instead of a green suite that still claims the figure is carried.
  - **Shipped surface:** `pytest tests/test_report_addendum_bound.py`
  - **Acceptance test(s):** `AT-283` — **owed at Inc-2** *(reserved; provisional-until-Phase-3 per V-5)*
  - **Boundary catalog (QC-3):** ☑ empty — the canon carries no `R-TUI-098` entry at all, which the existing precondition assertion already covers · ☑ boundary — the figure present inside the section and a refutation present in a *different* paragraph, which must stay GREEN · ☑ invalid — the figure present only outside the section · ☑ error — a figure written in a look-alike spelling, which the existing near-miss diagnostic already separates from omission.
  - **Negative control:** executed at P0 against the current node. Into the `R-TUI-098` section, on the line following the one carrying the first residual figure, one block-quoted sentence declaring that figure false and superseded was inserted, leaving the figure token unchanged; `git diff --stat` confirmed the edit applied; the node reported `1 passed`. The tree was restored and the file's `sha256` returned to its pre-mutation value. A guard satisfying this requirement is RED on that input.

---

## 5 · Low-level requirements

### LLR-90.1.1 — a batch-scoped token resolves to a comparable key

- **Traceability:** HLR-90.1
- **Ledger:** LED-90.1
- **Statement:** The token classifier shall resolve an `AT`/`TC` token whose body begins with a batch tag to a normalized key, rather than to no key.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_id_registry.py -q -k tc613`
- **Numeric pass threshold:** `iter_tokens` returns a token with a non-`None` key for every one of the **127** batch-scoped ids derived from the tree, and the key set contains no duplicate.
- **Negative control:** today the same call returns `key=None` — executed: `iter_tokens("AT-B78-12")` → `IdToken(space='AT', body='B78-12', governed=False, conforming=False, key=None)`. A classifier satisfying this LLR cannot produce that output.
- **Boundary catalog:** ☑ empty — a bare `AT-` with no body · ☑ boundary — a body that is a batch tag with no ordinal · ☑ invalid — a named-subspace body (`AT-CRC-DSN-010`), which must be classified deliberately rather than by accident · ☑ error — a token whose body mixes both shapes.
- **Symbols:** `tools/id_registry.py::iter_tokens`, `::IdToken`, `::CONFORMING_BODY_RE`, `::TOKEN_RE`, `::normalize` — all exist today. The batch-scoped branch is `NEW — created in Phase 3`.

### LLR-90.1.2 — the node derivation recognises the batch-scoped function-name form

- **Traceability:** HLR-90.1
- **Ledger:** LED-90.1
- **Statement:** The named-node derivation shall derive an id from a test function whose name carries a batch-scoped identifier.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_id_registry.py -q -k tc614`
- **Numeric pass threshold:** the derived id set grows from **678** to at least **805** (678 + 127), and every added id is one of the 127 measured batch-scoped ids.
- **Negative control:** executed today against the shipped pattern — `test_at_b78_09_loaded_panel_names_the_project` → **NO MATCH**, while `test_tc489_candidate_consumption_is_r_independent` → `[('tc', '489', '')]`. A derivation satisfying this LLR matches the first.
- **Boundary catalog:** ☑ empty — a test function with no id at all, which must still derive nothing · ☑ boundary — a class-carried batch-scoped id · ☑ invalid — a function name that contains the batch-tag letters but is not an id · ☑ error — a name carrying two ids.
- **Symbols:** `tools/id_registry.py::_FUNC_ID_RE`, `::_CLASS_ID_RE`, `::derive_named_nodes`, `::classify` — all exist today. `tools/seed_id_registry.py` reads the same symbols and is a consumer of this change.

### LLR-90.1.3 — the blast radius is measured before the change and does not become a regression

- **Traceability:** HLR-90.1
- **Ledger:** LED-90.2
- **Statement:** The widened classification shall leave every identifier that is governed today classified as it is today.
- **Validation:** `analysis`
- **Executed verification:** the derived-id set and the per-id classification are computed over the tree before and after the change, with `tools/id_registry.py::derive_named_nodes` and `::iter_tokens`, and the two are diffed.
- **Numeric pass threshold:** of the **678** ids derived today, **678** carry an unchanged `(governed, conforming, key)` triple after the change; the diff contains additions only.
- **Negative control:** substituting a classification that also alters one governed id must make the diff non-additive and the check RED; the substituted value is recorded in the increment packet, per C-40.
- **Boundary catalog:** ☑ empty — a tree with no batch-scoped id, where the diff must be empty · ☑ boundary — the highest governed stem, against `G7`'s high-water bound · ☑ invalid — a non-conforming legacy token, which must keep `conforming: false` · ☑ error — a registry whose `_meta` bound is absent.

### LLR-90.1.4 — the batch-scoped namespace is registered, and its monotonicity bound is its own

- **Traceability:** HLR-90.1
- **Ledger:** LED-90.2
- **Statement:** The registry shall hold an entry for every batch-scoped identifier carried by a test node, and the global high-water bound shall not be applied to a batch-scoped stem.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_id_registry.py -q`
- **Numeric pass threshold:** `G1` reports **0** unregistered named-node ids over the whole corpus, batch-scoped included; `G7` reports **0** problems; the registry holds at least **127** batch-scoped rows, against **0** today.
- **Negative control:** removing one seeded batch-scoped row must make `G1` name that id and go RED; the removed id is recorded by position in the increment packet, never pasted.
- **Boundary catalog:** ☑ empty — a batch tag with no ids · ☑ boundary — two batches minting the same ordinal under different tags, which must not collide · ☑ invalid — a batch-scoped row with a global stem · ☑ error — a batch-scoped row whose node does not exist, which `G2` must catch.
- **Symbols:** `tests/test_id_registry.py::g1_named_nodes_are_registered`, `::g2_live_entries_have_nodes`, `::g7_no_stem_exceeds_high_water` — all exist today. The batch-scoped bound is `NEW — created in Phase 3`.

### LLR-90.2.1 — the residual search is bound to the requirement's own section

- **Traceability:** HLR-90.2
- **Ledger:** LED-90.3
- **Statement:** The residual guard shall search for each residual figure within the `R-TUI-098` section alone, where the section ends at the next document heading.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_report_addendum_bound.py -q -k tc615`
- **Numeric pass threshold:** the searched extent is **13,394** characters against the **86,129** the node reads today, and all **7** figures resolve inside it.
- **Negative control:** an occurrence of a figure outside the section, with the in-section occurrence removed, must make the guard RED. This case is constructible today: `988 B/entry` already has **1** occurrence before the anchor and **1** inside, so removing the in-section one leaves the whole-document search satisfied and the bound search unsatisfied.
- **Boundary catalog:** ☑ empty — a canon with no `R-TUI-098` anchor, already covered by the node's precondition assertion · ☑ boundary — a figure on the section's last line · ☑ invalid — a second `**R-TUI-098**` anchor, which must be reported rather than silently resolved to the first · ☑ error — a canon with no heading after the anchor, where the section runs to end of file.
- **Symbols:** `tests/test_report_addendum_bound.py::_RESIDUAL_FIGURES`, `::_typographic_variants`, `::_LOOKALIKE_SPACES` — all exist today. The section bound is `NEW — created in Phase 3`.

### LLR-90.2.2 — a refutation in the figure's own paragraph is not an assertion of it

- **Traceability:** HLR-90.2
- **Ledger:** LED-90.3, LED-90.4
- **Statement:** The residual guard shall report a figure as not carried when a refutation marker occurs in the same paragraph as that figure.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_report_addendum_bound.py -q -k tc616`
- **Numeric pass threshold:** the guard is RED on each refutation marker in the declared marker set, and GREEN on the unmodified canon — where the unmodified canon contains **0** marker occurrences in any of the seven figures' paragraphs.
- **Negative control:** the P0 execution is the pre-state: the refutation was inserted, `git diff --stat` confirmed it applied, and the node reported `1 passed`. A guard satisfying this LLR is RED on that same input.
- **Boundary catalog:** ☑ empty — no marker anywhere, the current canon · ☑ boundary — a marker in the *adjacent* paragraph, which must stay GREEN, because a rule that reddens on a neighbouring paragraph false-fails a correct document · ☑ invalid — a marker word used in unrelated prose inside the paragraph · ☑ error — a figure whose paragraph cannot be delimited.

### LLR-90.2.3 — each clause owns its own mutation

- **Traceability:** HLR-90.2
- **Ledger:** LED-90.4
- **Statement:** The increment shall record one executed mutation per clause of `HLR-90.2`, and each mutation shall redden the clause it targets.
- **Validation:** `analysis`
- **Executed verification:** the two mutations are applied in this worktree, the affected node ids and their per-arm verdicts recorded, the tree restored, and the restore confirmed by the mutated file's hash returning to its pre-mutation value.
- **Numeric pass threshold:** **2** mutations, **2** distinct arms reddened, **0** arms reported green under the mutation that targets them; and the restored file's `sha256` equals its pre-mutation value in both cases.
- **Negative control:** a mutation that fails to apply also produces a red run for the wrong reason, so the `git diff --stat` confirmation of application is part of the record; without it the transcript cannot distinguish the two.
- **Boundary catalog:** ☑ empty — N/A: a mutation set of size zero is not a discharge · ☑ boundary — a mutation that reddens both clauses, which does not discharge either separately · ☑ invalid — a mutation applied to a file the guard does not read · ☑ error — a mutation left applied, which is why the hash confirmation is in the threshold.

---

## 6 · Information Flow Contract

### 6.1 Part A — Flow *(always owed)*

```
FLOW: id-authority
  SOURCE : test function and class names under tests/, and AT-TC-REGISTRY.jsonl
  NODES  :
    - fn    : tools/id_registry.py::iter_tokens
      owner : LLR-90.1.1
      in    : an AT/TC token as written
      out   : an IdToken carrying space, body, governed, conforming and a normalized key
    - fn    : tools/id_registry.py::derive_named_nodes
      owner : LLR-90.1.2
      in    : the test file set and the repository root
      out   : a map from identifier to the node references that carry it
    - fn    : tests/test_id_registry.py::g1_named_nodes_are_registered
      owner : LLR-90.1.4
      in    : the derived identifier map and the loaded registry
      out   : the list of identifiers carried by a node and held by no entry
    - fn    : tests/test_id_registry.py::g7_no_stem_exceeds_high_water
      owner : LLR-90.1.4
      in    : the loaded registry and its declared bound
      out   : the list of entries above the bound for their space
  SINK   : the pytest verdict of tests/test_id_registry.py
```

```
FLOW: residual-guard
  SOURCE : REQUIREMENTS.md, the living canon
  NODES  :
    - fn    : tests/test_report_addendum_bound.py::test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers
      owner : LLR-90.2.1
      in    : the canon text and the seven residual figures
      out   : the list of figures not carried inside the R-TUI-098 section
    - fn    : tests/test_report_addendum_bound.py::_typographic_variants
      owner : LLR-90.2.1
      in    : one residual figure
      out   : its near-miss spellings, which separate omission from mangling
  SINK   : the pytest verdict of tests/test_report_addendum_bound.py
```

**Nodes are owned and requirements are implemented:** every node above names an owner that exists in
§5, and every LLR in §5 that claims a transform names a node here. `LLR-90.1.3` and `LLR-90.2.3` are
`analysis` requirements over the change itself rather than transforms in the running system, so they
own no node — stated rather than left to be inferred from an absence.

### 6.2 Part B — boundary decomposition

**The trigger question — *does the system's boundary have components a consumer can address
independently?* — answers NO for this batch's deliverables, so Part B is not owed.** Both sinks are
a single pytest verdict, and the artifacts this batch changes are two source files with no
addressable sub-components. The project's TUI does have such a boundary and its decomposition is
being retrofitted surface by surface; batch-90 touches no screen, so it adds no `COMPONENT` block
and does not gate that retrofit.

---

## 7 · Validation strategy

**Layer A — white-box (`TC-NNN`):** `TC-613` and `TC-614` over the classifier and the node
derivation; `TC-615` and `TC-616` over the residual guard. Method `test` throughout, except
`LLR-90.1.3` and `LLR-90.2.3`, which are `analysis` over an executed diff and an executed mutation
set.

**Layer B — black-box (`AT-NNN`):** `AT-282` drives `pytest tests/test_id_registry.py` over a tree
carrying an unregistered batch-scoped id and asserts the guard names it. `AT-283` drives
`pytest tests/test_report_addendum_bound.py` over a canon that refutes a residual figure and asserts
the guard reports the figure as not carried. Both are `owed at` their increment and are reserved,
not written.

**`V2` did not check these two ids, and the reason is stated rather than left as a green
marker.** Its declared side strips code spans, so an acceptance id written inside backticks is
a mention and not a declaration; the rule therefore reports *no AT ids declared* over this
contract. Writing them bare instead would make `V2` resolve them against `tests/`, where
neither node exists yet, and BLOCK — which is the case the `owed at <increment>` empty exists
for. So the ids stay cited and the field carries the declared empty, and the consequence is
written here: **for this batch, `AT-282` and `AT-283` are governed by the registry reservation
and by this contract, not by `V2`.** They become `V2`'s subject when their nodes are written.

### Batch acceptance criteria

- Every LLR in §5 is covered by at least one passing arm.
- `pytest tests/test_id_registry.py` reports **0** unregistered named-node ids across the whole
  corpus, batch-scoped included — **127** today.
- Of the **678** identifiers derived today, **678** keep their classification unchanged.
- The residual guard is GREEN on the unmodified canon and RED on each of the two refutation forms.
- `devflow-validate.py` reports **0** BLOCK attributable to this batch.
- Every mutation executed in this batch is restored, and each restore is confirmed by the mutated
  file's hash returning to its pre-mutation value.

---

## 8 · Open findings carried out of P1

1. **The reservation is not merged.** `AT-TC-REGISTRY-SPEC.md` §4.2 step 2 requires it to reach
   `main` ahead of the batch's work; this lane cannot push. Until the operator merges it, a
   concurrent session can allocate `AT-282` or `TC-613`.
2. **The item's own scope name is narrower than the defect.** It is titled *batch-78/79*; the
   namespace spans five batch tags.
3. **`CLAUDE.md` recommends the namespace nothing polices.** Its AT/TC allocation rule prefers
   batch-scoped ids for new work. That recommendation and this batch's requirement 1 have to end up
   consistent; reconciling the text is a close-station obligation, not a P1 edit.
4. **A third `TC-497` defect is out of scope** — three disclosed residual figures sit outside the
   seven-string list. That is widening the list; this batch fixes what the list is compared against.
5. **The stale carry for `report_service` markdown escaping is still in `BACKLOG-CODE.md`.**
   Reconciling it against the `SATISFIED-EXTERNALLY` verdict belongs to the close.
