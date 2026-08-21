# Requirements Document — s19_app — Batch 85 · IFC pilot on `LoadedArtifactsPanel`

> **Read this first.** Batch **85** executes the charter that every existing citation calls
> **"batch-82"** (`.dev-flow/design/C-54-information-flow-contract.md`, and
> `.dev-flow/design/BATCH-82-LANE-A-SCOPING.md`). The charter keeps its name; the executing batch
> is 85. A reader who greps `batch-82` finds the charter here.

| | |
|---|---|
| **Batch** | `2026-08-21-batch-85` · mode `core` · artifact language English |
| **Base** | `origin/main` `a112eeb` (merge-base equal — RC-1 ✓) |
| **Flow** | `2026.08.21-rev38` · `flow_hash 004ec303f6ca9dbb` · V7 / V15 / V16 / V17 green |
| **Control under pilot** | **C-54** — the Information Flow Contract (IFC) |
| **Surface under pilot** | `LoadedArtifactsPanel` — `s19_app/tui/screens_directionb.py` |
| **Predecessor spec** | `.fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md` (CLOSED — promoted) |
| **Authored by** | `architect` + `qa-reviewer` lenses in parallel, folded by the orchestrator |

---

## 1. Introduction

### 1.1 Purpose

Author the first real **C-54 Information Flow Contract** record in this repository — Part A (flow)
and Part B (boundary decomposition) — for exactly one surface, and **measure what it cost**. The
retrofit's remaining surfaces are sized by three disagreeing counts (27 / 31 / ~40, §2.7 P-9); this
batch replaces one unknown factor of that product with a measurement.

Per the design's D-2 ruling, **the deliverable is the findings, not the file.** Authoring an
`address` and a `consumers` list for a surface that never declared one forces the question *"who
depends on this, and how do they reach it?"* — and this repository already carries stale answers to
that question, written when they were true.

### 1.2 Scope

**In scope.** One surface: its Part A flow, its Part B component record, correction of every in-repo
consumer note that contradicts the measured set, one membership assertion over the address census
with its RED counterfactual, and the cost record.

**Out of scope.** The other surfaces. The D-6 consumer-declares inversion. The public-repo question
(D1). Changing any address — this batch *declares* how consumers reach the surface; it moves nothing.
Escalating `V13` from `NOTICE` to `BLOCK` (§7.3 R-7).

### 1.3 Definitions

| Term | Meaning here |
|---|---|
| **IFC** | Information Flow Contract — control C-54. Part A = flow; Part B = boundary decomposition |
| **address** | *how a consumer reaches a value* — a Textual selector passed to `query`/`query_one`, or a CSS selector in `styles.tcss` |
| **consumer / dependant** | anything that **would break if the address moved**, including a stylesheet rule |
| **balancing** | the `⊆` containment rule between a component and its parent (DFD / Structured Analysis) |
| **surface** | a widget/screen with an addressable boundary. **The definition is not settled** — §2.7 P-9 |
| **misaddressed observable** | a threshold measuring a real property that is *true in the failing case*, because the failure lives in the address rather than the value |
| **modelled form** | one of `literal` / `name` / `fstring` — what `tools/address_census.py::_argument_form` produces today |

### 1.4 References

| Ref | Artifact |
|---|---|
| R1 | `.dev-flow/design/C-54-information-flow-contract.md` — the approved design |
| R2 | `~/.claude/templates/dev-flow/ifc-template.md` — block syntax; **its §3 worked example is this exact surface** |
| R4 | `.dev-flow/design/BATCH-82-LANE-A-SCOPING.md` — Lane A scoping (PR #199); two claims corrected in §2.7 |
| R5 | `.fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md` — premise table **carried forward** |
| R6 | `.dev-flow/2026-08-21-batch-85/PLAN.md` — stories, decisions D-1…D-7, triggers |
| R7 | `~/.claude/docs/tools/devflow-validate.py` — `V10`–`V14` implementation |
| R8 | `.dev-flow/2026-08-06-batch-78/01-requirements.md:425` — `LLR-120.2`, the origin defect |

---

## 2. Overall description

### 2.1 Product perspective

`LoadedArtifactsPanel` is a presentational Textual `Container` on the Workspace rail. It holds no
state: `S19TuiApp._refresh_loaded_panel` hands it a `LoadedFile` snapshot plus a composed project
string and it re-mounts a row set. Every consumer reaches its cells through **selector addresses**,
and until this batch **none of those addresses was declared anywhere**.

That is the gap `LLR-120.2` fell into: its threshold measured the three slot rows' *text* (set
equality), the implementation moved the *address*, and six shipped tests broke while the threshold
held.

### 2.4 Constraints

| Constraint | Value | Evidence |
|---|---|---|
| Source-file budget | ≤4 SOURCE per increment; 3 increments planned | R6 §6 |
| Engine-frozen set | untouched | `CLAUDE.md` |
| No new test file | `tests/test_id_registry.py:73` pins `EXPECTED_SCANNED_TEST_FILES = 155` | R6 D-6 |
| Id allocation | `AT-B85-*` / `TC-B85-*` are letter-initial ⇒ **ungoverned**; no reservation owed, `_meta.next_free` untouched | `AT-TC-REGISTRY.jsonl:1`; `tests/test_id_registry.py:493` |
| `V13` runtime cost | **0.058 s, 344 files, 8.0 MB** per run; paid only when a component declares a literal address | measured 2026-08-21 |
| IFC corpus cost | **0.09 s, 61 files** merged per rule invocation | measured 2026-08-21 |

### 2.6 Source user stories

| ID | User Story | DoR |
|----|------------|-----|
| **US-85-1** | As the flow's validator, I want a declared contract for `LoadedArtifactsPanel`, so that a change to *how consumers reach* its cells is a contract change rather than an accident. | READY |
| **US-85-2** | As a maintainer reading any in-repo "two shipped readers" note, I want the measured consumer set, so that I am not reading a count that was accurate when written. | READY |
| **US-85-3** | As the address census, I want to fail loudly the day an address form outside `{literal, name, fstring}` appears, so that I am never silently incomplete. | READY |
| **US-85-4** | As the operator sizing the remaining retrofit, I want a measured per-surface cost, so that I am not multiplying an unknown by a disputed surface count. | READY |

### 2.7 Premise evaluation (C-43)

> **P-1 … P-8 are CARRIED FORWARD** from R5 per the promotion ruling and are **not re-derived**.
> P-9 … P-13 are executed 2026-08-21 against this worktree.

| # | Premise | Tier | Verdict | Executed evidence |
|---|---|---|---|---|
| **P-1** | Lane B is encoded; the control exists to be applied | AXIOM | ✅ TRUE | *(carried)* `BACKLOG-PROCESS.md:9` |
| **P-2** | The flow is current | PREMISE | ✅ TRUE | *(carried, refreshed)* `rev38`, `004ec303f6ca9dbb`; V7/V15/V16/V17 green |
| **P-3** | Authoring an IFC record moves `V10`–`V14` off the pre-state verdict | HYPOTHESIS | ❌ FALSE at rev37 → ✅ **TRUE at rev38** | `_ifc_corpus` merges **61** files |
| **P-4** | `V14` blocks a consumer with no `::symbol` | PREMISE | ❌ **FALSE** | `devflow-validate.py:512` — `elif symbol and not contains(...)`, conditional |
| **P-5** | Whether a stylesheet counts as a consumer is open | PREMISE | ❌ **FALSE — already settled** | `_V13_EXT` includes `.tcss`/`.css`; R2 §3 lists `styles.tcss` |
| **P-6** | `.loaded-detail` has 4 dependants, not 2 | PREMISE | ✅ **TRUE — re-verified** | `styles.tcss:258`, `test_help_toggle_and_a2l_panel.py:72`, `test_tui_commandbar.py:1285`, `test_unload_feature.py:270` |
| **P-7** | A third stale copy exists, unregistered | PREMISE | ⚠️ **TRUE BUT UNDERSTATED — five sites in four files** | see P-12 |
| **P-8** | The census's `other:*` form is empty today | PREMISE | ✅ TRUE | 1574 sites, forms `{fstring, literal, name}`, unmodelled `set()` |
| **P-9** | The retrofit's surface count is known | PREMISE | ❌ **FALSE — three live figures, none reconciled** | **27** by `compose()`, **31** by widget-base, **~40** by R1 D-2. "Surface" has no evaluable definition |
| **P-10** | `LLR-120.*` can be cited as `owner` | HYPOTHESIS | ❌ **FALSE — and this is a finding** | `_declared_ids` matches `^#{2,5}\s+…`. Batch-78 wrote `**LLR-120.2 — …**` as **bold**, `R8`. Corpus declares 508 ids; `LLR-120.2` is not among them. Citing it → `V10` **BLOCK** |
| **P-11** | With this record present, `V10`–`V14` report a verdict | HYPOTHESIS | ✅ **TRUE — executed** | §5.5 |
| **P-12** | The stale claim is confined to prose comments | PREMISE | ❌ **FALSE — one lives inside a shipped assertion message, split across two f-string fragments** | `tests/test_tui_commandbar.py:1301-1303`: `"…Two shipped "` / `"readers index this query positionally…"`. **`grep -c "two shipped readers"` → 0.** The search that maintained the list was narrower than the thing it searched for |
| **P-13** | `AT-B85-*` need a registry reservation | PREMISE | ❌ **FALSE** | `_meta.governed`: letter-initial bodies are outside the authority |

---

## 3. High-level requirements (HLR)

### HLR-85.1 — `LoadedArtifactsPanel` has a declared, machine-checked information contract
- **Traceability:** US-85-1
- **Statement:** When the flow validator runs against this repository, the system shall report a counted `V10`–`V14` verdict naming the `loaded_panel` component, in place of the pre-state verdict that no `FLOW` or `COMPONENT` blocks are declared.
- **Validation:** `test (integration)`
- **Executed verification:** `python ~/.claude/docs/tools/devflow-validate.py` at the repo root, filtering `V10`–`V14`; pre-state captured 2026-08-21 (§5.5).
- **Numeric pass threshold:** all **5** rules change verdict from the recorded pre-state; `V11` names **≥5** `OUTPUT(s)`; `V14` names **≥15** resolved consumers; `V10` names **≥9** owned `FLOW` nodes; `V12` emits exactly **1** finding; `V13` emits exactly **3**, each naming `loaded_panel/…`.
- **Acceptance (black-box):** `AT-B85-01`
  - **Observable outcome:** the operator runs the validator and sees five lines counting this surface's flow nodes, outputs and consumers.
  - **⚠ The threshold is stated over a COUNTED QUANTITY IN THE MESSAGE, never over severity** — `V10`/`V11`/`V14` report `SKIP` **both before and after** (§5.5). An acceptance keyed on severity is green over an empty document. *Both review lenses found this independently.*
  - **Boundary catalog:** ☑ empty — the pre-state is the recorded RED arm · ☑ boundary — `cardinality: 3` is the arity the origin defect crossed · ☑ invalid — an `owner` naming an undefined requirement is `V10`-BLOCK (demonstrated by P-10) · ☑ error — a `consumers` entry naming an absent file is `V14`-BLOCK.

### HLR-85.2 — no in-repo consumer note contradicts the measured dependant set
- **Traceability:** US-85-2
- **Statement:** The repository shall carry no note asserting that two readers depend on `.loaded-detail`, and each surviving note shall enumerate the four measured dependants.
- **Validation:** `inspection`
- **Executed verification:** `grep -rniF "two shipped" --exclude-dir=.git .` **plus** a multi-line probe for the split fragment; pre-state 2026-08-21 = **5 sites in 4 files**.
- **Numeric pass threshold:** **0** surviving two-reader claims; **4** corrected sites enumerate all **4** dependants; **1** errata block on the design record.
- **⚠ Two-sided by construction:** *"the stale phrase is gone"* alone is satisfiable by **deleting** the comment. Criterion 2 is mandatory — a single-sided check cannot distinguish *corrected* from *removed*.
- **Acceptance:** `AT-B85-02`

### HLR-85.3 — the address census names an unmodelled address form instead of absorbing it
- **Traceability:** US-85-3
- **Statement:** When the address census is taken, the system shall report the set difference between the observed address-argument forms and the modelled set `{literal, name, fstring}`, and shall name every member of that difference.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_address_origin.py -k "b85"`; tree pre-state = 1574 sites, difference `set()`; synthetic pre-state = `{'other:Attribute'}`.
- **Numeric pass threshold:** tree difference **0** members; synthetic difference **1** member named `other:Attribute`; **2** arms, both executed, both non-vacuous.
- **Acceptance:** `AT-B85-03`

### HLR-85.4 — the per-surface retrofit cost is reported as measured figures
- **Traceability:** US-85-4
- **Statement:** When the batch closes, the system shall report six named per-surface figures, each traceable to an executed measurement, together with the explicit statement of which factor of the retrofit estimate remains unmeasured.
- **Validation:** `analysis`
- **Executed verification:** inspection of `05-close.md` against §7.4.
- **Numeric pass threshold:** **6** of 6 figures present and non-null; **1** explicit statement that the surface count is unmeasured; **0** totals computed from the disputed factor.
- **⚠ Partially unobservable, declared:** no oracle can verify the number *is the true cost*. What is observable is **derivability and internal consistency**. A green `AT-B85-04` must not be read as *"the cost is correct."*
- **Acceptance:** `AT-B85-04`

---

## 4. Low-level requirements (LLR)

### LLR-85.1 — the panel's readout flow is declared node-by-node, every node owned
- **Traceability:** HLR-85.1
- **Statement:** The requirements document shall declare a `FLOW` block for the panel's readout chain in which every node names an `owner` that this document defines as a `##`-to-`#####` heading.
- **Validation:** `test (integration)`
- **Executed verification:** the `V10` line of the validator run.
- **Numeric pass threshold:** `V10` reports **9** `FLOW` node(s), every one owned; **0** BLOCKs.
- **Acceptance criteria (informative):** No node names `LLR-120.*` — those ids are not headings anywhere in the corpus (P-10), and naming one would BLOCK.
- **Symbol citations:** `render_slots`, `_build_project_row`, `_slot_state`, `_build_slot_row`, `_build_unload_all_row` in `s19_app/tui/screens_directionb.py`; `_refresh_loaded_panel` in `s19_app/tui/app.py`. All EXISTING.

### LLR-85.2 — the `artifact_slots` output declares address, arity, ordering and its complete consumer set
- **Traceability:** HLR-85.1
- **Statement:** The `loaded_panel` component record shall declare the `artifact_slots` output with `address : query(".loaded-detail"), INDEXED POSITIONALLY`, `cardinality : 3`, and a `consumers` list naming every measured dependant.
- **Validation:** `test (integration)`
- **Executed verification:** the `V11`, `V13`, `V14` lines; consumer set independently measured by `grep -rlF '.loaded-detail'`.
- **Numeric pass threshold:** `V11` **0** BLOCKs for this output; `V14` resolves **4** consumer entries; `V13` at most **1** undeclared reacher and that reacher is the archived spec of §7.3 F-3 — **0** unexplained reachers.
- **Acceptance criteria (informative):** `INDEXED POSITIONALLY` is written even though no rule enforces ordering yet · `cardinality : 3` is the arity the origin defect crossed while set equality held · the consumer list contains `styles.tcss`, because renaming the class silently stops its rule applying.

### LLR-85.3 — the `project_row` output declares its own address and consumer set
- **Traceability:** HLR-85.1
- **Statement:** The record shall declare `project_row` with `address : query(".loaded-project-detail")`, `cardinality : 1`, and its measured consumer list.
- **Validation:** `test (integration)`
- **Executed verification:** the `V11`, `V13`, `V14` lines; `grep -rlF '.loaded-project-detail'`.
- **Numeric pass threshold:** `V14` resolves **2** consumer entries; `V13` reports **0** undeclared reachers for it.
- **Acceptance criteria (informative):** the `V13` result for this address is clean, which is this batch's **positive control** on the rule: it finds strays where strays exist and stays quiet where they do not.

### LLR-85.4 — the record is placed where the merged corpus reads it, and the pre-state is recorded
- **Traceability:** HLR-85.1
- **Statement:** The IFC blocks shall live inside `.dev-flow/2026-08-21-batch-85/01-requirements.md`, and the batch record shall carry the validator's verbatim `V10`–`V14` output from **before** the record existed alongside the output from after.
- **Validation:** `inspection`
- **Executed verification:** the validator run twice — pre-state at `a112eeb` (§5.5), post-state at the increment gate.
- **Numeric pass threshold:** **2** recorded runs; pre-state shows **5** rules reporting *"no FLOW/COMPONENT blocks declared"*; post-state shows **0**.
- **Acceptance criteria (informative):** this LLR owns **no** `FLOW` node, deliberately — it constrains placement, not a transform. Without the pre-state, *"the rules report a verdict"* is unfalsifiable.

### LLR-85.5 — every in-repo consumer note is corrected to the measured set
- **Traceability:** HLR-85.2
- **Statement:** Each of the five in-repo sites asserting a two-reader dependant set shall be corrected to enumerate the four measured dependants, and the design record shall receive an appended errata block rather than a rewritten original claim.
- **Validation:** `inspection` + `test`
- **Executed verification:** the two-form grep census, **plus the differential block-parse of `TC-B85-07`**.
- **Numeric pass threshold:** **0** surviving two-reader claims; **4** sites enumerate 4 dependants; **1** errata block; `styles.tcss` block count **284 → 284** with **0** differing `(selector, body)` pairs.
- **The five sites, measured:** `screens_directionb.py:1954` · `styles.tcss:252` · `tests/test_tui_commandbar.py:1301` (**split f-string fragment**) · `.dev-flow/design/C-54-information-flow-contract.md:19` · the same record's two-entry `consumers` sketch at `:157`.
- **⚠ B3 discharge — re-running the two named tests is NOT sufficient, and that is measured.** A `{`-in-comment corruption shifts **259 of 284** blocks and **both named tests stay GREEN**. The differential block parse is the **gate**; the test run is corroboration. See `TC-B85-07`.
- **Binding constraint:** the corrected `.tcss` comment shall contain **no `{` or `}`** and exactly one terminating `*/`. Derived by reading `tests/test_legend_two_pane.py:651-658` (`split("}")` → `partition("{")` → `split("*/")[-1]`).

### LLR-85.6 — the census reports the unmodelled-form difference, with an executed RED arm
- **Traceability:** HLR-85.3
- **Statement:** `tools/address_origin.py` shall expose a public function returning `{site.form for site in sites} - {"literal", "name", "fstring"}`, `report()` shall name every member when non-empty, and the guard shall be exercised by two arms: the real tree and a synthetic module the tree does not contain.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_address_origin.py -k "b85"`; tree → `set()` over 1574 sites; synthetic `self._sel = "#" + x; app.query_one(self._sel)` → `{'other:Attribute'}`.
- **Numeric pass threshold:** tree arm **0**; synthetic arm **1**; **2** arms; **0** new test files.
- **⚠ PLACEMENT IS THE CRITERION.** The set shall be taken over **`Census.sites`**, never over `resolve_origins` / `bare_name_candidates`. **Measured:** a tree of pure `other:*` sites yields **0 rows** from `resolve_origins`, so an assertion placed there sees `{"name"}` on **every possible input** and passes its RED arms vacuously by never seeing them. `Census.loose` carries the sentinel form `loose` by construction and is a different population.
- **C-55 discharge:** the green arm is green *because the population is empty*. Emptiness is why the guard is needed and never a reason to skip its red arm. The synthetic module is a **deliverable**.
- **Symbol citations:** `census_source`, `_argument_form`, `Census.sites` / `Census.loose` in `tools/address_census.py` — all EXISTING; the new predicate is **NEW — created in Phase 3**.

### LLR-85.7 — the per-surface cost record
- **Traceability:** HLR-85.4
- **Statement:** The close record shall carry six labelled per-surface figures and shall state that the retrofit's surface count remains unmeasured.
- **Validation:** `analysis`
- **Numeric pass threshold:** **6** figures non-null; **3** `V13` findings each classified as dependant / mention / provider; **1** stated gap; **0** retrofit totals computed.
- **⚠ Measurement validity, n = 1.** One surface gives a point estimate with **no dispersion**. The close shall carry an explicit **non-extrapolation caveat**, or declare a multiplier with its basis. An uncaveated per-surface number becomes the next batch's "estimate with three disagreeing values".

---

## 5. Information Flow Contract (C-54)

> Syntax per R2. **One field per line**; the validator anchors on the `FLOW:` / `COMPONENT:` keywords.

### 5.1 Part A — the panel's readout flow

```
FLOW: loaded_artifacts_readout
  SOURCE : the LoadedFile snapshot plus the composed project string, handed to LoadedArtifactsPanel.render_slots by S19TuiApp._refresh_loaded_panel
  NODES  :
    - fn    : render_slots
      owner : LLR-85.1
      in    : Optional[LoadedFile] + project display string
      out   : a cleared #loaded_slots and an ordered row list
    - fn    : _build_project_row
      owner : LLR-85.3
      in    : project display string
      out   : one row whose detail cell carries loaded-project-detail
    - fn    : _slot_state
      owner : LLR-85.2
      in    : Optional[LoadedFile] + artifact key
      out   : (present, name, counts/sizes summary)
    - fn    : _build_slot_row
      owner : LLR-85.2
      in    : (present, name, summary)
      out   : one row whose detail cell carries loaded-detail
    - fn    : _build_unload_all_row
      owner : LLR-85.1
      in    : any_loaded flag
      out   : the footer row
  SINK   : the mounted children of #loaded_slots, reached by the addresses declared in 5.3
```

### 5.2 Part A — this batch's own authoring flow

```
FLOW: ifc_pilot_authoring
  SOURCE : the shipped tree (s19_app, tests, s19_app/tui/styles.tcss, prototypes)
  NODES  :
    - fn    : measure_address_consumers
      owner : LLR-85.2
      in    : a declared literal address
      out   : the measured set of files that reach it
    - fn    : correct_stale_consumer_notes
      owner : LLR-85.5
      in    : the measured set
      out   : five in-repo sites agreeing with it
    - fn    : assert_census_form_membership
      owner : LLR-85.6
      in    : the address census's form column
      out   : pass, or the name of the unmodelled form
    - fn    : measure_per_surface_cost
      owner : LLR-85.7
      in    : the executed authoring work
      out   : six labelled per-surface figures
  SINK   : this record, the corrected notes, and the recorded V10-V14 verdict
```

### 5.3 Part B — boundary decomposition

**Trigger question: does the system's boundary have components a consumer can address
independently?** ✅ **Yes** — a consumer selects `#loaded_panel` and indexes its children.

```
COMPONENT: loaded_panel
  PARENT : screen_workspace
  INPUTS : loaded: Optional[LoadedFile] ; project: str
  OUTPUTS:
    - id          : panel_handle
      value       : the mounted panel widget itself
      address     : query_one("#loaded_panel")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_refresh_loaded_panel
                    s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-85.1
    - id          : slots_container
      value       : the re-mount target holding every row
      address     : query_one("#loaded_slots")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_variants.py::_project_label
      owner       : LLR-85.1
    - id          : slot_rows
      value       : project row, then S19/MAC/A2L, then the unload-all footer
      address     : query("#loaded_slots > Horizontal"), cells within a row INDEXED POSITIONALLY as kind then detail then optional unload
      cardinality : 5
      consumers   : tests/test_tui_variants.py::_project_label
      owner       : LLR-85.1
    - id          : artifact_slots
      value       : the three artifact detail texts, in _SLOTS order
      address     : query(".loaded-detail"), INDEXED POSITIONALLY
      cardinality : 3
      consumers   : s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-85.2
    - id          : project_row
      value       : the active project string in the caller's display form, or the absent sentinel
      address     : query(".loaded-project-detail")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
      owner       : LLR-85.3
```

### 5.4 Design decisions inside the record, and what each costs

| # | Decision | Alternative rejected | Why | Cost |
|---|---|---|---|---|
| **D-A** | **Five outputs, not the two the design sketched** | declare only `artifact_slots` + `project_row` | Every shipped reader reaches the detail cells *through* `#loaded_panel`, and two further external readers reach `#loaded_slots` and its `> Horizontal` row set — one of which (`tests/test_tui_variants.py`) **indexes a row's children positionally**. Declaring only two outputs would reproduce the original defect one level down. | 3 extra outputs, 11 extra consumer entries, 2 of the 3 `V13` findings. **The single largest contributor to the measured per-surface cost** |
| **D-B** | **`PARENT : screen_workspace`, left undeclared** | declare it, or write `PARENT : SYSTEM` | Declaring it is out of one-surface scope. `SYSTEM` would be **false** — the panel is not the top of the boundary; it buys a silent `V12` at the price of a lie. | A permanent `V12` NOTICE — *"balancing was NOT checked; this is not a pass"* — the honest state of a staged retrofit |
| **D-C** | **Retrofit-ownership convention:** a retrofitted node's `owner` is the batch-85 LLR that declares it, not the historical LLR that asked for it | cite `LLR-120.1…5` | `LLR-120.*` is **not citable**: batch-78 wrote its LLRs as bold text, so `_declared_ids` cannot see them and `V10` would BLOCK on correct work (P-10). | The ownership chain points at the *declaring* requirement, not the *originating* one. **A real semantic weakening, flagged not hidden** — §7.3 R-5 |
| **D-D** | **Do not declare mentions or the provider as consumers** | list every grep hit to silence `V13` | A dependant is *anything that would break if the address moved*. An archived spec does not break; the provider is not a consumer of itself. Listing them would make `consumers` mean "whatever grep found". | 3 standing `V13` NOTICEs, itemised in §7.3 |

### 5.5 Measured validator verdicts

**Pre-state**, executed 2026-08-21 at `a112eeb`, before any record existed:

```
  [-] V10  01-requirements.md: no FLOW blocks declared - nothing to check
  [-] V11  01-requirements.md: no COMPONENT blocks declared - Part B is conditional, so this may be correct
  [-] V12  01-requirements.md: no COMPONENT blocks declared - nothing to balance
  [-] V13  01-requirements.md: no COMPONENT blocks declared - nothing to search
  [-] V14  01-requirements.md: no COMPONENT blocks declared - nothing to resolve
```

**Post-state** — recorded at the Inc-1 gate by running the real validator over this file.

> ⚠️ **The acceptance must assert on the MESSAGE, not the severity.** `V10`, `V11` and `V14` report
> `SKIP` **both before and after** — the severity is identical in the failing and the passing case.
> An acceptance keyed on severity would be green over an empty document. **That is a misaddressed
> observable inside the batch built to close misaddressed observables**, and both review lenses
> found it independently.

---

## 6. Validation strategy

### 6.1 Methods

- **Layer A — white-box (`TC-B85-*`)**: `test (unit)`, `test (integration)`, `inspection`, `analysis`.
- **Layer B — black-box (`AT-B85-*`)**: run the validator, run the census, grep the tree, read the close record.
- **Id regime:** letter-initial ⇒ ungoverned (P-13). No reservation owed. Provisional-until-Phase-3 per V-5.

### 6.2 Dual traceability

| US | Observable outcome | Shipped surface | AT | Observed? |
|----|--------------------|-----------------|----|-----------|
| US-85-1 | Five `V10`–`V14` lines carry counted verdicts naming `loaded_panel` | `devflow-validate.py` | `AT-B85-01` | pre-state ✅ §5.5 |
| US-85-2 | Zero surviving "two shipped readers" claims; four sites enumerate four dependants | the tree as read by `grep` | `AT-B85-02` | pre-state ✅ 5 sites |
| US-85-3 | Guard silent on the tree, names `other:Attribute` on a synthetic instance | `tools/address_origin.py` + pytest | `AT-B85-03` | both pre-states ✅ |
| US-85-4 | Six labelled figures and one stated gap | `05-close.md` | `AT-B85-04` | 5 of 6 ✅ §7.4 |

| Requirement | Method | Test case |
|---|---|---|
| LLR-85.1 | test (integration) | `TC-B85-01` — `V10`, 9 nodes owned |
| LLR-85.2 | test (integration) | `TC-B85-02`/`03`/`04` — `V11`/`V14`/`V13` on `artifact_slots` |
| LLR-85.3 | test (integration) | `TC-B85-02`/`03`/`04` on `project_row` |
| LLR-85.4 | inspection | `TC-B85-05` — placement + two recorded runs |
| LLR-85.5 | inspection + test | `TC-B85-06` (two-form grep census) · **`TC-B85-07` (differential block parse — the B3 gate)** |
| LLR-85.6 | test (unit) | `TC-B85-08` (tree arm) · `TC-B85-09` (synthetic arm — C-55 discharge) |
| LLR-85.7 | analysis | `TC-B85-10` |

**Predicates labelled PIN, not gate (C-40):** the tree arm `TC-B85-08` is **invariant under every
edit this batch makes** — it fails only the day the *tree* grows a fourth form. Useful pin, worthless
gate. `TC-B85-09`'s synthetic arms are the gate. Likewise the upstream `--selftest` is cited as a
consumer-contract guard, never as this batch's gate.

**Trigger obligations:** **B4** — `AT-B85-01` observes the *validator* over the *authored* record, never a hand-built fixture. **B3** — `TC-B85-07` is a differential block parse, because re-running the two named modules is measurably insufficient. **B1** — `tests/test_id_registry.py` re-run; `EXPECTED_SCANNED_TEST_FILES` stays **155**, two independent derivations.

### 6.3 Batch acceptance criteria

- **7** LLRs covered by **10** TCs; **4** stories by **4** ATs.
- **0** BLOCK findings attributable to this document.
- `V12` and `V13` NOTICEs **enumerated and explained** in §7.3, not suppressed: exactly **1** and **3**.
- Ledger: `base = 2684 passed / 2 skipped / 21 deselected / 3 xfailed`, `D = 0`, `A = 2`.
- **0** new test files (`EXPECTED_SCANNED_TEST_FILES` stays 155); **0** engine-frozen edits.

---

## 7. Appendices

### 7.3 Open risks and findings

| id | Risk / finding | Status |
|---|---|---|
| **R-1** | A `styles.tcss` comment edit drifts a structural parser test (**B3**). | Open — discharged only by `TC-B85-07`'s differential parse |
| **R-2** | The record's `consumers` lists go stale exactly as the five prose sites did. | Open **by design**. `V13` is the control; this is its first real application |
| **R-3** | **C-55 — load-bearing emptiness** in `LLR-85.6`'s tree arm. | Discharge is a deliverable: `TC-B85-09` |
| **R-4** | ~~Author reviews author~~ | ✅ **CLOSED** — operator reversed D-7; lenses ran as independent sub-agents |
| **R-5** | **Historical LLRs are uncitable as owners.** Batch-78 wrote `LLR-120.*` as bold text. Every retrofitted surface inherits D-C's weaker ownership. | Open — register in `BACKLOG-PROCESS.md`. Fix is a flow-repo change |
| **R-7** | `V13` ships as `NOTICE`; escalation to `BLOCK` is the project's call per surface. This batch does **not** escalate. | Open decision |
| **F-1** | `V13` reaches two files via `#loaded_panel` that are **mentions, not dependants**. | Classified, left undeclared (D-D) |
| **F-2** | `V13` reports **the provider itself** as an undeclared consumer of `#loaded_slots`. A structural bound of the rule. The CSS-class addresses escape only because the provider writes `"loaded-detail"` while the address is `".loaded-detail"` — **an accident of syntax, not a property of the rule.** | New finding — register for the flow repo |
| **F-3** | `.fast-dev-flow/` is **not** in `_V13_SKIP_DIRS` while `.dev-flow/` is. Batch specs appear as reachers of every address they discuss. **This session's own archived spec is a live instance.** | New finding — one-line asymmetry in a shared asset; register, do not fix here |
| **F-4** | `V10`/`V11`/`V14` severity is `SKIP` in both the failing and passing case. | **Closed in this document** — all thresholds stated over counted quantities |
| **F-5** | `AddressSite`'s docstring lists a form `type` that `_argument_form` cannot produce. | Registered, **not** fixed (surgical-change rule) |
| **F-6** | The stale claim at `test_tui_commandbar.py:1301` is **invisible to the single-line grep that would maintain it**. | The defect class one layer up; drives HLR-85.2's two-form verification |

### 7.4 Per-surface cost — measured at Phase 1

| # | Figure | Measured |
|---|---|---|
| 1 | Declared `OUTPUTS` | **5** (design sketch predicted 2 → **2.5×**) |
| 2 | Consumer entries · distinct dependant files | **15** · **6** (sketch predicted 3 → **5×**) |
| 3 | Addresses literal-greppable | **5 of 5 (100 %)** |
| 4 | `V13` findings, classified | **3** — 2 mentions, 1 provider; **0** genuine undeclared dependants |
| 5 | Stale in-repo claims found | **5 sites in 4 files** (registered estimate 3 → **1.67×**); 1 invisible to single-line grep |
| 6 | Authoring effort | **captured at close** |

**Stated gap:** the retrofit is *surfaces × per-surface*. This pilot measures the second factor.
**The first is 27, 31 or ~40** depending on a definition nobody has written (P-9). **No total is
computed here, and none may be computed until that definition exists.**
