# Requirements — s19_app — 2026-08-24-batch-86

> **Station P0 state of this document.** Only §1 (context) and §2.6 (story intake) are
> authored at batch open; §2.7 (premises), §3 (acceptance), §4 (HLR/LLR) and §5 (IFC record)
> are Phase-1 work and are ABSENT, not pending-in-template. This early creation is deliberate:
> the active batch's own copy must win `_artifacts()` arbitration, or V1–V9 judge a frozen
> May-2026 document (measured at this batch's open: 17 V4 blocks from batch-01's LLRs).

## 1 · Context

First batch run under flow rev42–rev44 (derived Atlas + V20 · declared selector taxonomy ·
coherence rules V21–V23). Objective: the IFC record for a SECOND surface, clean-start,
applying the batch-85 format lessons — pair-based thresholds, split populations, scoped
statements — with the `SURFACE:` field, canon mirror seeding, and a per-surface cost record
at n=2. Zero product code planned.

## 2.6 · Story intake (Definition of Ready)

### US-86-1 — a second surface becomes contractually addressable

As the operator auditing s19_app's addressability, I want the IFC record (Part A + Part B)
of a second surface — selected by measured evidence — authored to the corrected format, so
that a second surface is contractually addressable, the pilot's `PARENT` can be balanced
(V12 verdict instead of "NOT checked"), and the per-surface retrofit cost gains a second
data point.

- **Who:** the operator (audit) and the flow's own validators (machine consumers).
- **Outcome (observable, black-box) — CORRECTED at the P1 fold per the qa-reviewer's D1–D4
  (`01b-qa-validation-plan.md` §4; the original wording is kept in that file's defect list):**
  (a) one `devflow-validate` run whose **counted messages** (never severities — passing rules
  also print `[-]`) equal the recorded pre-state plus exactly this record's frozen K/M/C
  figures, with final line `0 block` and no BLOCK located under `.dev-flow/2026-08-24-batch-86/`
  or `.dev-flow/_derived/`; (b) the regenerated Atlas renders the component one-row-per-
  declaration and V20 reads `atlas current (4 files, census ≤ 2)`; (c) **per-id canon greps**:
  every heading id this document declares appears ≥ 1 time in `REQUIREMENTS.md` at CLOSE
  (transient growth during authoring is declared in P-8); (d) the source-scope diff
  (`git diff --stat` over `s19_app/ tests/ tools/ pyproject.toml` vs merge-base) is empty —
  a PIN, labelled as such, not a gate.
- **Out of scope:** D-II (any amendment to the pilot's record) · the remaining surfaces ·
  the C3 seeding backlog beyond this batch's own ids · `docs/ARCHITECTURE.md` (D-IV carry).
- **INVEST:** Independent · Negotiable (record detail at Phase 1) · Valuable (audit + V12
  live + n=2 cost) · Estimable (LLR-85.7's measured pilot cost) · Small (record + canon
  mirror only) · Testable (validator + Atlas + suite-neutrality as oracles).
- **Classification: READY.** Surface-selection hypothesis and its confirming probes are
  recorded in `PLAN.md` (leading candidate: the workspace surface the pilot names as its
  undeclared `PARENT`); confirmation is Phase 1's first task, by execution.

## 2.7 · Premise evaluation (C-43)

> Every probe transcript lives in `.dev-flow/2026-08-24-batch-86/00-measurements.md` (M-1 …
> M-9), cited by id. A premise with no executed evidence is UNDECIDABLE, not TRUE.

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-1** | The pilot's undeclared `PARENT` (`screen_workspace`) is a real, independently addressable surface, and it is the mounter of `#loaded_panel` | HYPOTHESIS | ✅ TRUE | M-1: `Container(id="screen_workspace")` built by `S19TuiApp._compose_screen_workspace` (`s19_app/tui/app.py:1963-2071`); mounts `LoadedArtifactsPanel()` at `app.py:2066`; reached in code at `tests/test_tui_checks_screen.py:138` and `tests/test_tui_directionb.py:1958` | surface #2 = this workspace screen |
| **P-2** | The PLAN's candidate location — "the Direction-B workspace in `s19_app/tui/screens_directionb.py`" — is where the surface lives | PREMISE | ❌ FALSE | M-1: `grep -c screen_workspace screens_directionb.py` → **1** (docstring, `:211`). That file holds the PANELS; the screen container is composed in `app.py` | hypothesis holds with corrected location; recorded so the record cites the true provider file |
| **P-3** | For V12 to verdict the pilot, this record's `INPUTS` names must be a superset of `{loaded, project}` and its OUTPUT ids a superset of the pilot's five | PREMISE | ✅ TRUE | pilot `INPUTS` at `.dev-flow/2026-08-21-batch-85/01-requirements.md:337`; rule read at `devflow-validate.py:469-489` (`child_in - parent_in`, `child_out - parent_out`); M-9 executes both RED arms | drives LLR-86.6 / LLR-86.7 |
| **P-4** | The surface's compose body declares exactly 24 id literals + 2 class literals, plus one id-less child (`EmptyStatePanel`, type-queried) | PREMISE | ✅ TRUE | M-2: enumeration over `app.py:2010-2071`; `EmptyStatePanel` sets no id (`screens_directionb.py:144`), queried by type at `app.py:6049` | 24 + 1 outputs declared; the 2 class literals dispositioned by D-86-A |
| **P-5** | The class addresses `.db-pane` / `.db-screen` select populations this component owns | PREMISE | ❌ FALSE | M-6: `classes="db-pane"` has **7** instances app-wide, **4** outside this surface (`app.py:5196,5219,5279,5297`); `.db-screen` marks all rail-screen roots; `tests/test_tui_theme.py:266` queries `.db-pane` app-wide | **D-86-A**: shared-class addresses are NOT this component's outputs — declaring them would unite foreign populations under one component (the defect class of batch-85 #12) |
| **P-6** | The `#ws_stats` ⊂ `#ws_stats_title` prefix collision does not pollute the `#ws_stats` reacher population | PREMISE | ✅ TRUE | M-6: every file in the `#ws_stats` reacher set carries ≥1 bare (non-`_title`) hit — bare counts 8/1/5/1/8 | the pair populations are separable; no phantom consumer |
| **P-7** | The per-pair reacher census is executed for all 24 searchable literals, with mention-vs-dependant classified per PAIR, not per file | PREMISE | ✅ TRUE | M-3 (file census) + M-4 (pair classification) + M-5 (bare-name couplings: `on_button_pressed` `app.py:11833-11843`, `_EMPTY_STATE_SCREENS` `app.py:6009`) | consumer lists in §5.3; expected stray pair set in §5.6 |
| **P-8** | This station makes V22's unreflected-id aggregate grow (new `HLR-86.*`/`LLR-86.*` headings, canon untouched) until the Phase-3 canon-seeding increment lands | PREMISE | ✅ TRUE | M-8 baseline: `277 of 520 batch-declared ids are not reflected` — the sample already names `US-86-1`; this document adds 11 heading ids | declared transient; the story's "aggregate does not grow" is measured at CLOSE, after Phase-3 seeding — never at this station |
| **P-9** | The validator baseline at this station is 2 BLOCK, both pre-existing Atlas staleness, neither attributable to this document | PREMISE | ✅ TRUE | M-8 tail: `2 block · 233 notice · 14 n/a`; both `[x] V20` name `_derived/ATLAS-*` — stale since batch open | Atlas regenerated at this station's gate (`--atlas --write`); AT-B86-03 |

**Gate rule:** no ❌/❓ premise blocks this batch — P-2's FALSE corrects a location and P-5's
FALSE forces an exclusion decision; the corrected hypothesis (P-1) is what the record relies on.

## 3 · Acceptance (black-box) — the user-verified outcomes of US-86-1

> Layer B. The "user" here is the operator auditing addressability; the shipped surface is the
> validator + Atlas toolchain reading the authored record (trigger B4: the acceptance runs the
> REAL consumers over the handler-produced record, never a hand-fed copy). `AT-B86-*` ids are
> letter-initial ⇒ ungoverned by the registry (batch-85 P-13 precedent), provisional-until-
> Phase-3 per V-5. **No new pytest files** (`EXPECTED_SCANNED_TEST_FILES` stays pinned); these
> acceptances are operator-local validator runs, and saying so is the honest form (batch-85
> §6.2 correction precedent).

### AT-B86-01 — the validator reports counted verdicts naming `screen_workspace`
- **Observable outcome:** one `devflow-validate` run prints counted V10/V11/V13/V14/V19/V21
  messages whose figures include this record's component (thresholds in HLR-86.1).
- **Shipped surface:** `python ~/.claude/docs/tools/devflow-validate.py` at the worktree root,
  reading the merged IFC corpus.
- **Deliverable + observation:** §5.6 carries the verbatim pre-state (M-8) and post-state runs.
- **Counted MESSAGE, never severity** — V10/V11/V14/V21 report SKIP in both the empty and the
  passing case (pilot F-4, carried).
- **Boundary catalog:** ☑ empty — M-8 pre-state is the recorded RED arm · ☑ boundary — the
  INPUTS superset is exact: dropping `loaded` BLOCKs (M-9 RED arm 1) · ☑ invalid — an owner
  naming an undefined requirement BLOCKs (M-9 V21 arm) · ☑ error — a consumers entry naming an
  absent file is V14 BLOCK (pilot boundary, carried — not re-executed here).

### AT-B86-02 — the pilot's PARENT gains a real balancing verdict
- **Observable outcome:** V12's output no longer contains the pilot's `parent
  screen_workspace is not declared` notice (M-8); the only V12 finding names
  `screen_workspace`'s own undeclared parent `workspace_body`.
- **Shipped surface:** the same validator run.
- **Deliverable + observation:** §5.6 post-state; both directions demonstrated by M-9's
  executed GREEN + 2 RED arms.
- **Boundary catalog:** ☑ empty — pre-state notice recorded · ☑ boundary — a single-name INPUT
  drop flips to BLOCK · ☑ invalid — the omitted re-export flips to BLOCK (M-9 RED arm 2) ·
  ☐ error — N/A: V12 has no file-resolution failure mode (it is a set-containment rule).

### AT-B86-03 — the Atlas derives the new component, one row per declaration
- **Observable outcome:** after `--atlas --write`, V20 reports the Atlas current (0 V20
  BLOCK), `ATLAS-IFC.md` renders `screen_workspace` as its own declaration row (never a
  merged `{id: component}` collapse — handoff §5.4), and the UNPARSED census does not rise.
- **Shipped surface:** `python ~/.claude/docs/tools/devflow-validate.py --atlas --write` then
  a plain validator run.
- **Deliverable + observation:** `.dev-flow/_derived/ATLAS-IFC.md` (derived, banner-guarded);
  §5.6 records the post-regeneration tail line.
- **Boundary catalog:** ☑ empty — M-8's two stale-Atlas BLOCKs are the pre-state · ☑ boundary
  — the UNPARSED census count is compared against the committed Atlas by V20 itself ·
  ☐ invalid / ☐ error — N/A here: V20's own failure arms live in the upstream 152-arm
  `--selftest`, not re-armed per batch.

### AT-B86-04 — the batch is byte-neutral on product behavior
- **Observable outcome:** `git diff --stat main -- s19_app/ tests/ tools/` is empty at the
  gate; the whole-suite run matches the recorded base ledger.
- **Shipped surface:** git + the orchestrator's gate suite run (the orchestrator owns suite
  runs; this document does not execute pytest).
- **Deliverable + observation:** the increment gate record; PLAN.md test ledger
  (`post = base − 0 + 0`: the validator, not pytest, is this batch's oracle — A = 0).
- **Boundary catalog:** ☑ empty — trivially observable (empty diff) · ☑ boundary — the diff
  scope names the three product roots explicitly · ☐ invalid / ☐ error — N/A: a one-command
  structural check with no input space beyond the diff scope.

### Behavioral traceability (US → AT → outcome)

| US | Observable outcome | Shipped surface | AT | Observed? |
|----|--------------------|-----------------|----|-----------|
| US-86-1 | Counted V10–V21 verdicts include `screen_workspace` | `devflow-validate.py` | `AT-B86-01` | pre-state ✅ M-8 |
| US-86-1 | The pilot's V12 becomes a checked verdict | `devflow-validate.py` | `AT-B86-02` | pre-state ✅ M-8 · arms ✅ M-9 |
| US-86-1 | Atlas current, one row per declaration | `--atlas --write` + V20 | `AT-B86-03` | pre-state ✅ M-8 (2 stale BLOCKs) |
| US-86-1 | 0 product files touched, suite-neutral | git + gate suite | `AT-B86-04` | measured at gate |

### Batch acceptance criteria

- **3** HLRs and **8** LLRs covered by **8** inspection/analysis TCs (`TC-B86-01`…`08`); the
  single story by **4** ATs.
- **0 BLOCK attributable to this document** in the post-state run — stated WITH its scope:
  the two M-8 V20 BLOCKs predate this station and are discharged by the Atlas regeneration
  (AT-B86-03); a criterion without that scope would be the unfalsifiable batch-85 §6.3 shape.
- V12's finding count is **1** and its stray sets are empty (M-9 GREEN); every V13 figure is
  stated over the **(output_id, file) PAIR set** of §5.6 — never a finding count, never a
  file-set union.
- Ledger: `post = base − 0 + 0` (0 test files added or removed; the orchestrator's gate run
  confirms).
- V22's unreflected aggregate at CLOSE is ≤ its batch-open baseline (277) — the Phase-3
  seeding increment owes the shrink-back; P-8 records the transient growth at this station.

### Gate criterion set G-86 — instantiated at the P1 fold (qa plan `01b` §3 × the frozen figures)

| Gate | Criterion (pre-state → required post-state) | Status at P1 |
|---|---|---|
| **G1** (headline) | pilot's V12 `:334` "NOT checked" notice ABSENT; `loaded_panel` balancing CHECKED; only V12 finding names `screen_workspace/workspace_body` | **GREEN** (M-8/M-9, §5.6) |
| **G2** | V19 `1 → 2 COMPONENT id(s), each declared exactly once` | **GREEN** |
| **G3** | counted messages: V10 `9 → 20` · V11 `5 → 35` · V14 `15 → 97` · V21 `5 → 35`; final line `0 block`; no BLOCK under this batch's paths | **GREEN** (`0 block · 254 notice · 15 n/a`) |
| **G4** | V13 stray census = the enumerated §5.6 PAIR set (pilot's 4 ∪ this record's), sum exact; never a count alone | **GREEN** (38 pairs enumerated, 0 genuine undeclared dependants) |
| **G5** | Atlas renders `screen_workspace` ≥ 1 row (was 0) AND V20 `atlas current (4 files, census ≤ 2)` at every gate | **GREEN** (census 2; the mid-authoring rise to 3 was caught and fixed) |
| **G6** | per-id canon greps ≥ 1 for every batch-86 heading id — **measured at CLOSE** (P-8 declares the transient) | OPEN — owed by the Phase-3 seeding increment |
| **G7** (PIN) | source-scope diff empty + ledger `post = base − 0 + 0` — labelled a pin, not a gate | GREEN (pin) |

**Kill-mutation disposition (qa plan `01b` §2):** M2/M3/M6/M8 discharged by CITATION of the
rev44 `--selftest` arms (189 arms, exit 0) and the pilot's P-10. M-9 (this batch, executed in
memory at authoring) covers M1's class (V21 over THIS record's parse path) and M5 (V12
containment RED both directions). **Still OWED batch-local: M4** (remove one consumers entry
on a COPY → the V13 **pair** count moves +1 while the file-set union may not — defect #1's
demonstration) and **M7** (canon-mirror grep mutation) — both assigned to Phase 4 validation,
on a copy, never the live tree.

## 4 · Requirements (HLR / LLR)

> Scope-rule convention (batch-85 defect #7 closed): **every Statement names the population it
> quantifies over.** No repo-wide predicate appears anywhere in this section.

### HLR-86.1 — `screen_workspace` carries a declared, machine-checked information contract
- **Traceability:** US-86-1
- **Statement:** When the flow validator runs against this repository, the system shall report counted V10, V11, V13, V14, V19 and V21 verdicts whose figures include the `screen_workspace` component declared in §5.3 of this document — the quantified population being the merged IFC corpus (every `01-requirements.md` under `.dev-flow/`), with every reacher figure stated over `(output_id, file)` pairs.
- **Validation:** `inspection` (the validator lives outside the repository and is operator-local — batch-85 §6.2 correction precedent; a `test` label would assert a pytest node that cannot exist)
- **Executed verification:** `python ~/.claude/docs/tools/devflow-validate.py` at the worktree root; pre-state recorded 2026-08-24 (M-8), post-state in §5.6.
- **Numeric pass threshold:** V10 counts **20** FLOW nodes, every one owned (9 pilot + 11 this document); V11 counts **35** OUTPUT(s) (5 + 30); V14 resolves **97** consumers (15 + 82); V19 counts **2** COMPONENT ids, each declared exactly once; V21 counts **35** OUTPUT owners; V13's stray set for this component's searchable outputs is exactly the **38-pair** set enumerated in §5.6 plus **1** no-literal notice naming `screen_workspace/empty_state`.
- **Priority:** high
- **Acceptance (black-box):** `AT-B86-01` (§3).

### HLR-86.2 — the pilot's `PARENT` balances: a V12 verdict instead of "NOT checked"
- **Traceability:** US-86-1
- **Statement:** When V12 runs over the merged IFC corpus, the system shall report `loaded_panel`'s balancing as checked and shall confine the not-checked notice to `screen_workspace`'s own undeclared parent — the quantified population being the complete V12 finding set of one validator run.
- **Validation:** `inspection`
- **Executed verification:** the V12 line(s) of the same run; both mutation arms executed in memory against `_v12_outcome` (M-9), tree untouched (C-40).
- **Numeric pass threshold:** exactly **1** V12 finding; it names `screen_workspace` and `workspace_body`; **0** V12 findings name `loaded_panel`; both RED arms (M-9) flip to BLOCK on a one-field mutation.
- **Priority:** high
- **Acceptance (black-box):** `AT-B86-02` (§3).

### HLR-86.3 — the per-surface retrofit cost gains its second point, with dispersion
- **Traceability:** US-86-1
- **Statement:** When this batch closes, the close record shall report the six per-surface figures for surface #2 beside the pilot's six, together with a dispersion statement over the two measured surfaces and zero extrapolated retrofit totals — the quantified population being the figure table of `05-close.md` compared against §5.6 and batch-85 §7.4.
- **Validation:** `analysis`
- **Executed verification:** re-read of `05-close.md` against §5.6's figure table and `.dev-flow/2026-08-21-batch-85/01-requirements.md` §7.4; effort span from `git log --format='%h %ad' --date=iso` over this batch's commits.
- **Numeric pass threshold:** **6** of 6 figures non-null at n=**2**; **1** explicit dispersion statement (range form, no mean); **0** totals computed from the still-unmeasured surface count (batch-85 P-9 stands).
- **Priority:** medium
- **Acceptance (black-box):** `AT-B86-04` covers the neutrality half; the figure half is Layer-A analysis by design (partially unobservable, declared — pilot HLR-85.4 precedent: a green check never means "the cost is correct").

### LLR-86.1 — the workspace's two information flows are declared node-by-node, every node owned
- **Traceability:** HLR-86.1
- **Statement:** Section 5.2 of this document shall declare the `workspace_readout` and `workspace_find_goto` FLOW blocks in which every node names an owner defined as a heading in this document — the quantified population being the two fenced FLOW blocks of §5.2, nothing else.
- **Validation:** `inspection`
- **Executed verification:** the V10 line of the validator run (§5.6).
- **Numeric pass threshold:** V10 reports **20** FLOW node(s) corpus-wide, every one owned, **0** BLOCK; **11** of them from this document.
- **Symbol citations (all EXISTING, measured):** `_apply_loaded_file` `app.py:9494` · `refresh_files` `app.py:5419` · `update_sections` `app.py:10157` · `update_workspace_stats` `app.py:10275` · `update_memory_strip` `app.py:10346` · `update_hex_view` `app.py:10566` · `update_a2l_view` `app.py:11085` · `_apply_empty_state` `app.py:6015` · `_refresh_loaded_panel` `app.py:8868` · `_handle_search` `app.py:11927` · `_handle_goto` `app.py:11997`.
- **Acceptance criteria (informative):** no authoring pseudo-FLOW is declared — batch-85's `ifc_pilot_authoring` drew defect #11 (process verbs with no `def`); this batch's authoring transforms live as probe transcripts in `00-measurements.md` instead (D-86-C).

### LLR-86.2 — the structural outputs are declared with measured consumer sets
- **Traceability:** HLR-86.1
- **Statement:** The `screen_workspace` component record shall declare the seven structural outputs — `screen_root`, `memstrip_band`, `panes_container`, `left_pane`, `center_pane`, `right_pane`, `empty_state` — each with its address, cardinality 1, and the consumer set measured in M-3/M-4/M-5, the quantified population being those seven OUTPUT entries of §5.3.
- **Validation:** `inspection`
- **Executed verification:** the V11/V14/V13 lines (§5.6); census M-3, pair classification M-4, bare-name couplings M-5.
- **Numeric pass threshold:** V11 **0** BLOCK over these 7; V14 resolves their **21** consumer entries; V13's stray pairs for the six searchable ones are exactly the **15** pairs listed in §5.6 (`screen_root` 4 · `memstrip_band` 4 · `left_pane` 3 · `center_pane` 2 · `right_pane` 2 · `panes_container` 0); `empty_state` appears in exactly **1** no-literal notice.
- **Acceptance criteria (informative):** `empty_state`'s address is a type selector by measured necessity — the widget sets no id (`screens_directionb.py:144`) and is reached by type (`app.py:6049`); declaring a literal it does not have would be fiction.

### LLR-86.3 — the left-pane content outputs are declared with measured consumer sets
- **Traceability:** HLR-86.1
- **Statement:** The record shall declare `load_project_button`, `files_title`, `files_list`, `sections_title` and `sections_list`, each with address, cardinality 1 and the measured consumers — the quantified population being those five OUTPUT entries of §5.3.
- **Validation:** `inspection`
- **Executed verification:** V11/V14/V13 lines (§5.6); M-3/M-4/M-5.
- **Numeric pass threshold:** V14 resolves **12** entries; V13 stray pairs exactly **5** (`load_project_button` 1 · `files_list` 2 · `sections_list` 2 · both titles 0).
- **Symbol citations:** `refresh_files` `app.py:5419` (writes `#files_list` at `:5421`) · `update_sections` `app.py:10157` (reaches `#sections_list` at `:10198`) · `on_button_pressed` `app.py:11833` (routes `ws_load_project_button` at `:11839`). All EXISTING.

### LLR-86.4 — the center hex-pane outputs are declared with measured consumer sets
- **Traceability:** HLR-86.1
- **Statement:** The record shall declare `hex_title`, `hex_controls`, `search_input`, `search_button`, `goto_input`, `goto_button`, `hex_scroll` and `hex_view`, each with address, cardinality 1 and the measured consumers — the quantified population being those eight OUTPUT entries of §5.3.
- **Validation:** `inspection`
- **Executed verification:** V11/V14/V13 lines (§5.6); M-3/M-4/M-5.
- **Numeric pass threshold:** V14 resolves **23** entries; V13 stray pairs exactly **12** (`hex_controls` 1 · `search_input` 1 · `search_button` 2 · `goto_input` 2 · `goto_button` 1 · `hex_scroll` 3 · `hex_view` 2 · `hex_title` 0).
- **Symbol citations:** `_handle_search` `app.py:11927` (reads `#search_input` at `:11931`) · `_handle_goto` `app.py:11997` (reads `#goto_input` at `:12001`) · `update_hex_view` `app.py:10566` (writes `#hex_view` at `:10568`) · `on_button_pressed` `app.py:11833` (routes `search_button` / `goto_button` at `:11837` / `:11843`). All EXISTING.

### LLR-86.5 — the right context-pane outputs are declared with measured consumer sets
- **Traceability:** HLR-86.1
- **Statement:** The record shall declare `ws_stats_title`, `ws_stats`, `a2l_title`, `a2l_view` and `a2l_scroll`, each with address, cardinality 1 and the measured consumers — the quantified population being those five OUTPUT entries of §5.3.
- **Validation:** `inspection`
- **Executed verification:** V11/V14/V13 lines (§5.6); M-3/M-4 plus M-6 (the `#ws_stats` purity probe).
- **Numeric pass threshold:** V14 resolves **11** entries; V13 stray pairs exactly **2** (both on `ws_stats`); the `#ws_stats` population contains **0** files reaching it only through the `_title` superstring (M-6).
- **Symbol citations:** `update_workspace_stats` `app.py:10275` (writes `#ws_stats` at `:10314`) · `update_a2l_view` `app.py:11085` (the `#a2l_view` write site measured at `:11043`, in the helper block preceding the `def`; both cited from execution). All EXISTING.

### LLR-86.6 — the pilot's five outputs are re-exported verbatim at the parent boundary
- **Traceability:** HLR-86.2
- **Statement:** The `screen_workspace` record shall re-declare the pilot's five output ids — `panel_handle`, `slots_container`, `slot_rows`, `artifact_slots`, `project_row` — with address, cardinality and consumers identical to `.dev-flow/2026-08-21-batch-85/01-requirements.md` §5.3, the quantified population being those five OUTPUT entries of §5.3 of this document compared field-by-field against the pilot's five.
- **Validation:** `inspection`
- **Executed verification:** field-by-field comparison against the pilot block; the V12 emits-containment arm executed in memory (M-9 RED arm 2).
- **Numeric pass threshold:** **5** re-exported ids; **0** V12 emits-unbalanced BLOCKs; omitting the set flips V12 to BLOCK naming all five (M-9); V13 adds exactly **4** duplicate stray pairs at this document's lines (`panel_handle` 2 · `slots_container` 1 · `artifact_slots` 1).
- **Acceptance criteria (informative):** the re-export carries the pilot's `slot_rows` annotation VERBATIM, known-defective included — the D-A split into six outputs is D-II territory, and correcting it here while the pilot record stands would fork one contract into two disagreeing declarations. The defect is inherited, cited, and quarantined to one owner (D-II), never silently propagated.

### LLR-86.7 — the component's INPUTS and PARENT make the pilot balanceable, honestly
- **Traceability:** HLR-86.2
- **Statement:** The record shall declare `INPUTS` as the named list `loaded, project, workarea_files, search_query, goto_addr` (types in §5.3) and `PARENT : workspace_body`, the quantified population being the COMPONENT header fields of §5.3.
- **Validation:** `inspection`
- **Executed verification:** `_v12_outcome` GREEN + RED arms executed in memory over the planned declaration (M-9).
- **Numeric pass threshold:** the GREEN arm yields exactly **1** finding (the `workspace_body` notice); dropping `loaded` yields **1** BLOCK naming `loaded_panel`; **0** stray-input BLOCKs in the post-state run.
- **Acceptance criteria (informative):** `PARENT : workspace_body` is true and undeclared (D-86-B, mirroring pilot D-B): `SYSTEM` would be false — `#workspace_body` sits above this screen (`app.py:1917`) — so the honest cost is one standing V12 NOTICE until the shell's own record exists.

### LLR-86.8 — the surface-#2 cost figures are measured, and dispersion replaces extrapolation
- **Traceability:** HLR-86.3
- **Statement:** Section 5.6 of this document shall carry the six per-surface figures for surface #2, each derived from an executed measurement cited by M-id, and the close record shall restate them beside the pilot's with a range-form dispersion statement — the quantified population being §5.6's figure table and its six M-citations.
- **Validation:** `analysis`
- **Executed verification:** the figure table of §5.6 against M-2 … M-7 (each count re-derivable by re-running the cited command); close-time restatement per HLR-86.3.
- **Numeric pass threshold:** **6** figures non-null; **5** M-citations plus **1** declared close-time capture; dispersion stated as the measured range (outputs **5 → 30**, consumer entries **15 → 82**); **0** extrapolated totals.

### Functional traceability (US → HLR → LLR → TC)

| Requirement | Method | Test case | Notes |
|---|---|---|---|
| HLR-86.1 | inspection | `TC-B86-01` — the counted-verdict run | operator-local |
| HLR-86.2 | inspection | `TC-B86-02` — V12 finding-set check | + M-9 arms |
| HLR-86.3 | analysis | `TC-B86-03` — close-record figure audit | at Phase 5 |
| LLR-86.1 | inspection | `TC-B86-04` — V10 node/owner count | |
| LLR-86.2 | inspection | `TC-B86-05` — per-output pair census | M-3/M-4/M-5 |
| LLR-86.3 | inspection | `TC-B86-05` | same census, left-pane rows |
| LLR-86.4 | inspection | `TC-B86-05` | same census, center rows |
| LLR-86.5 | inspection | `TC-B86-05` + `TC-B86-06` — `#ws_stats` purity | M-6 |
| LLR-86.6 | inspection | `TC-B86-07` — re-export field comparison | + M-9 RED arm 2 |
| LLR-86.7 | inspection | `TC-B86-02` | shared with HLR-86.2 |
| LLR-86.8 | analysis | `TC-B86-08` — figure / M-citation audit | |

`TC-B86-*` are letter-initial ⇒ ungoverned by the registry (P-13 precedent); all are
operator-local inspection/analysis procedures, **not** pytest nodes — 0 test files added, and
saying so is the honest form.

## 5 · Information Flow Contract (C-54) — surface #2: `screen_workspace`

> Syntax per the rev44 template. One field per line; the validator anchors on the block
> keywords. **Format lessons applied (the batch's reason to exist):** (1) every reacher
> threshold in this document is stated over `(output_id, file)` PAIRS; (2) one address = one
> population — shared-class addresses are excluded by D-86-A rather than united; (3) every
> Statement in §4 carries an explicit scope rule.

### 5.1 The surface, confirmed by execution

`#screen_workspace` is the Workspace rail screen: an anonymous Textual `Container` composed by
`S19TuiApp._compose_screen_workspace` (`s19_app/tui/app.py:1963-2071`), child of
`#workspace_body` (`app.py:1917`), visible at startup, and the mounter of the pilot surface
`#loaded_panel` (`app.py:2066`). Probes: M-1 (identity), M-2 (address enumeration), M-3 … M-7
(reacher census and populations).

### 5.2 Part A — the workspace's information flows

```
FLOW: workspace_readout
  SOURCE : the LoadedFile snapshot built off-thread by _parse_loaded_file, plus the workarea
           directory listing, entering at S19TuiApp._apply_loaded_file and refresh_files
  NODES  :
    - fn    : _apply_loaded_file
      owner : LLR-86.1
      in    : LoadedFile + Path
      out   : dispatch to the per-pane renderers below
    - fn    : refresh_files
      owner : LLR-86.3
      in    : workarea file listing
      out   : the workarea rows of files_list
    - fn    : update_sections
      owner : LLR-86.3
      in    : LoadedFile contiguous ranges
      out   : the section rows of sections_list
    - fn    : update_memory_strip
      owner : LLR-86.2
      in    : LoadedFile memory map
      out   : the whole-image band in memstrip_band
    - fn    : update_workspace_stats
      owner : LLR-86.5
      in    : LoadedFile plus validation counts
      out   : the coverage text in ws_stats
    - fn    : update_hex_view
      owner : LLR-86.4
      in    : LoadedFile memory map plus focus address
      out   : the hex and ASCII text in hex_view
    - fn    : update_a2l_view
      owner : LLR-86.5
      in    : LoadedFile A2L summary
      out   : the context text in a2l_view
    - fn    : _apply_empty_state
      owner : LLR-86.2
      in    : loaded-presence flag
      out   : visibility swap between empty_state and panes_container
    - fn    : _refresh_loaded_panel
      owner : LLR-86.6
      in    : Optional[LoadedFile] plus composed project string
      out   : the loaded_panel child's render_slots call (the pilot contract's SOURCE)
  SINK   : the addressed widgets declared in 5.3, plus the loaded_panel component

FLOW: workspace_find_goto
  SOURCE : operator-typed text in the search and goto input widgets of 5.3
  NODES  :
    - fn    : _handle_search
      owner : LLR-86.4
      in    : ASCII query string
      out   : hex view refocused at the match
    - fn    : _handle_goto
      owner : LLR-86.4
      in    : hex address string
      out   : hex view refocused at the address
  SINK   : hex_view, refreshed through update_hex_view
```

### 5.3 Part B — boundary decomposition

**Trigger question: does the system's boundary have components a consumer can address
independently?** Yes — measured: 24 id literals in one compose body, each reached by named
consumers (M-3).

```
COMPONENT: screen_workspace
  PARENT : workspace_body
  SURFACE: Workspace rail screen — S19TuiApp._compose_screen_workspace (s19_app/tui/app.py:1963)
  INPUTS : loaded: Optional[LoadedFile] ; project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str
  OUTPUTS:
    - id          : screen_root
      value       : the workspace screen container itself, visibility-toggled by rail navigation and the empty state
      address     : query_one("#screen_workspace")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    tests/test_tui_checks_screen.py
                    tests/test_tui_directionb.py
      owner       : LLR-86.2
    - id          : memstrip_band
      value       : the whole-image memory-strip minimap band
      address     : query_one("#ws_memstrip")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_memory_strip
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_insight.py
      owner       : LLR-86.2
    - id          : panes_container
      value       : the three-pane Horizontal, hidden while no file is loaded
      address     : query_one("#workspace_panes")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-86.2
    - id          : left_pane
      value       : the fixed-width data and sections pane
      address     : query_one("#ws_left")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-86.2
    - id          : center_pane
      value       : the hex-view pane
      address     : query_one("#ws_center")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-86.2
    - id          : right_pane
      value       : the coverage and context pane
      address     : query_one("#ws_right")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-86.2
    - id          : empty_state
      value       : the no-file-loaded prompt panel, shown while panes_container is hidden
      address     : query_one(EmptyStatePanel) scoped to the workspace screen subtree — type selector, computed, carries no quoted literal by design (the widget sets no id)
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    tests/test_tui_directionb.py
      owner       : LLR-86.2
    - id          : load_project_button
      value       : the Load-project action button
      address     : query_one("#ws_load_project_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-86.3
    - id          : files_title
      value       : the Workarea Files caption label
      address     : query_one("#files_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.3
    - id          : files_list
      value       : the workarea file rows
      address     : query_one("#files_list")
      cardinality : 1
      consumers   : s19_app/tui/app.py::refresh_files
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-86.3
    - id          : sections_title
      value       : the Data Sections caption label
      address     : query_one("#sections_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.3
    - id          : sections_list
      value       : the contiguous-range rows of the loaded image
      address     : query_one("#sections_list")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_sections
                    s19_app/tui/styles.tcss
                    tests/test_tui_app.py
                    tests/test_tui_directionb.py
      owner       : LLR-86.3
    - id          : hex_title
      value       : the Hex View caption label
      address     : query_one("#hex_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.4
    - id          : hex_controls
      value       : the search and goto control strip container
      address     : query_one("#hex_controls")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.4
    - id          : search_input
      value       : the ASCII search text input
      address     : query_one("#search_input")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_search
                    s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
                    tests/test_tui_goto_marker.py
                    tests/test_tui_search_pagination.py
                    tests/test_universal_paste.py
      owner       : LLR-86.4
    - id          : search_button
      value       : the Find Next action button, routed by bare id in on_button_pressed
      address     : query_one("#search_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
      owner       : LLR-86.4
    - id          : goto_input
      value       : the goto-address text input
      address     : query_one("#goto_input")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_goto
                    s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_goto_marker.py
      owner       : LLR-86.4
    - id          : goto_button
      value       : the Goto action button, routed by bare id in on_button_pressed
      address     : query_one("#goto_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
      owner       : LLR-86.4
    - id          : hex_scroll
      value       : the scrollable container hosting the hex text
      address     : query_one("#hex_scroll")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-86.4
    - id          : hex_view
      value       : the rendered hex and ASCII text surface
      address     : query_one("#hex_view")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_hex_view
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_patch_variant.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-86.4
    - id          : ws_stats_title
      value       : the Coverage Stats caption label
      address     : query_one("#ws_stats_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.5
    - id          : ws_stats
      value       : the coverage, error and warning stat text
      address     : query_one("#ws_stats")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_workspace_stats
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_insight.py
      owner       : LLR-86.5
    - id          : a2l_title
      value       : the Context caption label
      address     : query_one("#a2l_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-86.5
    - id          : a2l_view
      value       : the A2L context summary text
      address     : query_one("#a2l_view")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_a2l_view
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-86.5
    - id          : a2l_scroll
      value       : the scrollable container hosting the A2L summary
      address     : query_one("#a2l_scroll")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-86.5
    - id          : panel_handle
      value       : re-export of loaded_panel's panel_handle at the parent boundary (balancing; the declaration of record is the pilot's)
      address     : query_one("#loaded_panel")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_refresh_loaded_panel
                    s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-86.6
    - id          : slots_container
      value       : re-export of loaded_panel's slots_container (balancing)
      address     : query_one("#loaded_slots")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_variants.py::_project_label
      owner       : LLR-86.6
    - id          : slot_rows
      value       : re-export of loaded_panel's slot_rows, VERBATIM including its D-A-defective cardinality union — the six-output split is D-II territory, inherited with citation, not fixed here
      address     : query("#loaded_slots > Horizontal"), cells within a row INDEXED POSITIONALLY as kind then detail then optional unload
      cardinality : 5
      consumers   : tests/test_tui_variants.py::_project_label
      owner       : LLR-86.6
    - id          : artifact_slots
      value       : re-export of loaded_panel's artifact_slots (balancing)
      address     : query(".loaded-detail"), INDEXED POSITIONALLY
      cardinality : 3
      consumers   : s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-86.6
    - id          : project_row
      value       : re-export of loaded_panel's project_row (balancing)
      address     : query(".loaded-project-detail")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
      owner       : LLR-86.6
```

**`consumers : none` appears nowhere in this record because it is nowhere true** — measured:
every declared address has at least one reacher (M-3; the minimum is the stylesheet). The
explicit-`none` obligation stands and simply has no instance on this surface. **No NEW output
carries `INDEXED POSITIONALLY`** — measured: every own address is a singleton id reached by
`query_one` (M-4); the only positional annotations are the pilot's, carried verbatim in the
re-export.

### 5.4 Design decisions inside the record, and what each costs

| # | Decision | Alternative rejected | Why | Cost |
|---|---|---|---|---|
| **D-86-A** | `.db-pane` and `.db-screen` are NOT outputs of this component | declare them with app-wide cardinality (7 and 10) | The populations are shared: 4 of 7 `.db-pane` instances and 9 of 10 `.db-screen` roots belong to OTHER screens (M-6). One address = one population — uniting foreign members under this component is batch-85 defect #12 re-enacted | The `styles.tcss` and `test_tui_theme.py` couplings to `.db-pane` stay contract-invisible until the shell (`workspace_body`) record exists; one stray-census row (M-7) documents the gap |
| **D-86-B** | `PARENT : workspace_body`, left undeclared | declare the shell now, or write `PARENT : SYSTEM` | Declaring the shell is out of one-surface scope; `SYSTEM` is false — `#workspace_body` sits above this screen (`app.py:1917`) | One standing V12 NOTICE — the honest state of a staged retrofit (pilot D-B, one level up) |
| **D-86-C** | No authoring pseudo-FLOW | mirror the pilot's `ifc_pilot_authoring` block | The pilot's authoring flow drew defect #11 — `fn` entries that are process verbs with no `def` anywhere. Probe transcripts (`00-measurements.md`) carry the authoring transforms instead | Part A holds 2 flows and 11 nodes, all real symbols; the batch's own work is auditable via M-ids rather than V10 |
| **D-86-D** | Mention-vs-dependant is classified per PAIR, and bare-name couplings count as dependants | classify per file; or declare only literal-hit files | A file can be a code consumer of one address and a docstring mention of another (`app.py` is both — M-4); and `app.py` couples to the three buttons by BARE id (`on_button_pressed`, M-5) — a real dependant whose grep hit is prose, the pilot's F-2 accident mirrored | 13 in-scope mention pairs stay undeclared (V13 NOTICEs); 5 bare-name couplings are declared on M-5 evidence rather than on grep membership |
| **D-86-E** | The pilot's five outputs are re-exported verbatim | omit them (V12 BLOCKs — M-9 RED arm 2); or re-declare them corrected per D-A | Balancing is a set-containment rule over ids — the parent must declare what the child emits. Correcting `slot_rows` here while the pilot stands would fork one contract into two disagreeing declarations | 15 duplicated consumer entries; 4 duplicate V13 stray pairs; the D-A defect inherited with a citation, owned by D-II |

### 5.5 Format-lesson compliance (why this batch exists)

| Batch-85 defect | Rule applied here | Where |
|---|---|---|
| #1 — thresholds projected over FILES erase the pair signal | every reacher threshold is a `(output_id, file)` PAIR set, enumerated | §4 LLR-86.2 … 86.6 thresholds; §5.6 census |
| #12 / D-A — one address uniting heterogeneous populations | one address = one population; shared classes excluded (D-86-A); every own output a singleton | §5.3; P-5 |
| #7 — repo-wide Statements with no scope rule | every §4 Statement names its quantified population | §4, all Statements |
| rev42 `SURFACE:` field | declared on the COMPONENT | §5.3 header |
| V21 owner law (rev44) | every OUTPUT owner is a single-line LLR id defined in this document | §5.3; M-9 V21 RED arm |

### 5.6 Measured validator verdicts and the stray-pair census

**Pre-state** (2026-08-24, before this record existed — M-8): V10 `9 FLOW node(s)` · V11
`5 OUTPUT(s)` · V12 NOTICE `loaded_panel: parent screen_workspace is not declared … NOT
checked` · V13 3 findings and 4 pairs (all the pilot's) · V14 `15 declared consumer(s)` · V19
`1 COMPONENT id(s)` · V21 `5 OUTPUT owner(s)` · tail `2 block · 233 notice · 14 not
applicable` (both BLOCKs = stale Atlas, pre-existing).

**Post-state** — recorded at this station's gate by running the real validator over the merged
corpus after this section landed, then regenerating the Atlas:

V10 **20** nodes owned · V11 **35** outputs · V14 **97** consumers resolved · V19 **2** ids,
each once · V21 **35** owners · V12 exactly **1** finding (`screen_workspace` /
`workspace_body`). V13's stray PAIR set attributable to `screen_workspace` — **38 pairs**,
classified below; every class is mention or citation, **0** are undeclared dependants:

| Output | Stray pairs | Files (class) |
|---|---|---|
| screen_root | 4 | unload-feature spec (archived spec) · REQUIREMENTS.md (canon citation) · docs/architecture.md (doc) · legend_n8.INVENTORY.md (prototype note) |
| memstrip_band | 4 | test_tui_snapshot.py (comment) · REQUIREMENTS.md · legend_n8 · screen_upgrades.HANDOFF-PLAN.md |
| left_pane | 3 | app.py:677 (comment) · sections-label spec · screen_upgrades |
| center_pane | 2 | REQUIREMENTS.md · screen_upgrades |
| right_pane | 2 | app.py:10278 (docstring) · screen_upgrades |
| hex_controls | 1 | app.py:1981 (compose docstring; the provider) |
| load_project_button | 1 | test_tui_patch_chips.py:40 (docstring) |
| files_list | 2 | test_tui_snapshot.py:391 (comment) · batch-31 spec |
| sections_list | 2 | sections-label spec · batch-31 spec |
| search_input | 1 | cmdbar_a2bdiff.HANDOFF.md (prototype note) |
| search_button | 2 | test_tui_commandbar.py:224 (docstring) · test_tui_patch_chips.py:41 (docstring) |
| goto_input | 2 | test_tui_directionb.py:6345 (docstring) · cmdbar prototype |
| goto_button | 1 | test_tui_patch_chips.py:41 (docstring) |
| hex_scroll | 3 | app.py:1982 (docstring) · test_tui_mac_layout.py:12 (docstring) · REQUIREMENTS.md |
| hex_view | 2 | batch-31 spec · REQUIREMENTS.md |
| ws_stats | 2 | test_tui_snapshot.py:537 (comment) · REQUIREMENTS.md |
| panel_handle (re-export) | 2 | the pilot's 2 mention files, reported once more at this document's lines |
| slots_container (re-export) | 1 | the provider (pilot F-2), duplicated |
| artifact_slots (re-export) | 1 | the pilot's archived promoted spec, duplicated |
| **Σ** | **38** | plus **1** no-literal notice (`empty_state`, type-addressed by measured necessity) |

**Per-surface cost figures (surface #2, measured now; effort captured at close):**

| # | Figure | Surface #2 (this record) | Pilot (batch-85 §7.4) | M-cite |
|---|---|---|---|---|
| 1 | Declared OUTPUTS | **30** (25 own + 5 re-export) | 5 | M-2 |
| 2 | Consumer entries · distinct dependant files | **82** · **15** | 15 · 6 | M-3/M-4/M-5 |
| 3 | Addresses literal-greppable | **29 of 30** (`empty_state` type-only) | 5 of 5 | M-2 |
| 4 | V13 stray pairs, classified | **38 pairs · 0 undeclared dependants** | 3 findings / 4 files | M-7 + the gate run |
| 5 | Stale in-repo claims found | **not surveyed** — no HLR-85.2 analogue in scope; declared rather than zero-filled | 5 sites / 4 files | — |
| 6 | Authoring effort | captured at close | captured at close | — |

**Dispersion (n = 2, range form — no mean, no total):** outputs 5 → 30; consumer entries
15 → 82; the spread is a factor of about 6 between the two surfaces measured so far, which is
exactly why no per-surface average may be multiplied by the still-undefined surface count
(batch-85 P-9 stands unmeasured).
