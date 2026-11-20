# Inc 3 — E1 rulings: prepared-load parity and boundaries

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`. Requirements: `01-requirements.md`; planned cases: `02-test-cases.md`; slice: `E1-slice.md`. These are E1 design rulings inside the approved Inc 3 boundary, not operator approvals or runtime verdicts.

## 1. Executed evidence and mechanical allocation

| Evidence | Executed result and limit |
|---|---|
| `evidence-e1/qwen-census.txt` | Qwen CLI 0.27.4 was actually invoked read-only with `--safe-mode --approval-mode plan --max-wall-time 120s --max-tool-calls 8 --output-format text`, closed stdin and outer `timeout 150s`. It exited **55** after about 28 s: `Run aborted: tool-call budget of 8 exceeded (--max-tool-calls); observed 9.` It returned no substantive census. No edit/yolo permission was granted and no Qwen-derived claim is made. |
| `evidence-e1/premise_census.py` → `premise-census.txt` | Direct standard-library AST census of all 132 `s19_app/**/*.py` files at `d658dfea`; all six executed static premises and both known-present/known-absent instrument controls passed. This is static evidence, not application behavior. |
| `evidence-e1/premise-census-initial-red.txt`, `premise-census-second-red.txt`, `premise-census-route-red.txt` | Regenerated RED runs using `--red-case=initial`, `second` and `route`: the wrong generation-read count, docstring assumption and call-only callback omission each fail again against disk with exit 1. Tracebacks are redacted by the generator before output; the source tree was untouched. |
| `evidence-e1/case06_probe.py` → `case06-probe.txt` | Real parser fixture probe from this tree: 37,742,888 bytes, SHA-256 `45243458427f43da695f4e01e494d69444c1b921588bcd040cfcaf025fed43d9`, 220,040 tags/distinct names, 0 errors. No load-route timing was measured. Package/fixture paths are emitted as `<repo>` relative. |
| `evidence-e1/case06-probe-path-red.txt` | Regenerated real import failure with isolated `python -I -S -B`; the successful probe used `PYTHONPATH=.` and printed its redacted package path. |
| `evidence-e1/redaction.py` | Shared source redactor for repository/home paths. The validator runs known root/home controls and scans every Inc3 Markdown/Python/text/JSON artifact for personal paths. |
| `evidence-e1/trace-check.txt` | Executed `trace_check.py` with base/source scope: US, CASE and SLICE reported no gap. The 10 TEST gaps name future test files and the one EVID gap names future E5 `04-validation.md`; this is not an E5 pass. |
| `evidence-e1/validate_e1.py` → `structural-validation.txt` | Final E1/E3 structure PASS: 10 EARS rows/thresholds/controls, 39 cases with no results (19 normal + 4 performance + 16 robustness), 13 nodes/4 SOURCE, baseline 9 change functions + 3 context functions, executed premises, the synchronous-stage invariant and expected trace gaps. The validator's ID-padding, subject-case and ledger-scope REDs are regenerated through `--red-case=initial`, `case` and `ledger`, with source redaction, as `structural-validation-initial-red.txt`, `structural-validation-case-red.txt` and `structural-validation-ledger-red.txt`. |
| `evidence-e3/stage_invariant.py` → `stage-invariant.txt` | Executed static proof of D-10's synchronous P5/reset/L1 sequence, zero await/yield, UI-only runtime generation writers and known-await/known-yield instrument controls. STAGE_RACE is unreachable and no rollback exists; this is disk evidence, not a functional test. |

Provenance correction: the initial Qwen run and subsequent Qwen retries failed; no Qwen output contributed to the design. DeepSeek audited this packet through `pi`, producing `../evidence/deepseek-e1-audit-inc3.txt`; that audit is the external input to F1–F5, not a command executed by this lane. This lane invoked no DeepSeek CLI. No clipboard or secret access occurred.

## 2. Design rulings

### D-1 — Inc 2 is the sole prepared-snapshot producer design

Inc 3 consumes the future Inc 2 interface for enrichment, summary and definition preparation on direct attach, image+A2L, project pair and A2L-only routes. Direct-attach internals remain Inc 2's ownership. Inc 3 adds capture/adaptation and installation code only; it does not add another call to `enrich_tags_and_render`, another definition builder or another generation identity.

A project containing image+MAC+A2L prepares its A2L payload **once**, for the final MAC-after-image stage. Its image-stage bundle still carries explicit generation expectations for stale rejection but has no A2L enrichment key and performs no A2L enrichment. A project with image+A2L and no MAC prepares that payload in its image bundle. This avoids duplicate work while preserving stage-specific freshness.

### D-2 — Exact SOURCE boundary: four files, cap notice

Planned edits are limited to:

1. `s19_app/tui/app/file_load.py` — explicit UI-captured request context, shared snapshot consumption and removal of the candidate's synchronous preparation fallback.
2. `s19_app/tui/app/project_load.py` — prepared project bundles, one A2L-only snapshot, stage-aware pre-reset preflight and final-only publication.
3. `s19_app/tui/app/loaded_state.py` — preflight every precomputed bundle carrying either expected generation, including an image-stage bundle with no A2L enrichment key; install the accepted Inc 2 picker-snapshot mapping before common refresh; retain the existing signature, `bool` result and publication policy.
4. `s19_app/tui/app/shared.py` — add a defaulted optional `PreparedLoad.a2l_preparation` handoff for Inc 2's `A2LAttachSnapshot`, including its Check/Patch definition maps. A type-checking-only reference avoids a runtime `shared.py` ↔ `file_load.py` import cycle; existing constructors remain valid.

`a2l_view.py`, parser/reader modules and all other SOURCE remain unchanged. The budget is **4/4 SOURCE**, a declared cap notice rather than an E0 blocker. It cannot be cut responsibly by dropping the picker maps, hiding them in an untyped dynamic attribute or mutating app state from a worker. `E1-slice.md` counts **13 implementation nodes: 12 existing nodes changed and 1 request data node new**.

### D-3 — Generation expectations belong to the installation stage

`A`/`I` below are the counters captured on the UI thread before worker launch. Reset always calls the single A2L writer, image apply increments image and attaches A2L, and MAC apply after image increments both again when A2L is present.

| Route/stage | Required pair at that stage | Prepared A2L payload |
|---|---|---|
| Direct attach, Inc 2 context | `(A+1,I)` | yes, Inc 2 owns it |
| Loose image+A2L | `(A+1,I+1)` | yes |
| Project image+MAC+A2L, image after reset | `(A+2,I+1)` | no; generation-only preflight |
| Project image+MAC+A2L, MAC after image | `(A+3,I+2)` | yes, once |
| Project image+A2L without MAC, image after reset | `(A+2,I+1)` | yes, once |
| Project A2L-only after reset | `(A+2,I)` | yes, once |

`_install_prepared_project` checks all expected pairs against these captured stage values **before reset**. `_apply_prepared_load` repeats its existing immediately-before-install check after prior stages; its guard must no longer be conditioned solely on `a2l_enriched_key is not None`, or the generation-only image stage would be invisible. A mismatch returns `False` before candidate mutation. A2L-only preflight occurs before reset and then uses the existing single A2L writer and prepared cache assignment after reset.

The existing project rule remains monotonicity, not exactly one A2L increment per user action. No third generation, path identity or object identity substitutes for these counters.

### D-4 — Publication is final and singular

Image loads publish only after the final image/A2L installation. Projects keep reset and image/MAC installation unpublished, publish once after final project identity/artifact state, and only then announce success. No worker paints and no per-bundle callback yields an intermediate A2L state. Existing reset behavior unrelated to A2L publication is preserved; the test oracle samples visible state at actual UI yields rather than treating every internal helper call as a painted frame.

### D-5 — Preparation failure never selects a slow candidate fallback

A producer exception follows the route's existing failure handler. The image route may not construct its current minimal `PreparedLoad(loaded=loaded)` after preparation failure, and project routes may not continue with non-precomputed bundles. Previous session/views/project files remain unchanged, no success is shown and no synchronous UI preparation occurs. This changes only candidate-load failure handling; it does not weaken parser diagnostics or existing refusal texts.

### D-6 — Same-path reload distinguishes changed content from reinstall generation movement

Path equality never short-circuits an admitted reload. Changed content publishes under a strictly newer generation of each changed artifact. Unchanged source content/bytes remain byte-identical, but no unchanged-artifact generation freeze follows: the existing writer/reset/reinstallation stages may increment that generation exactly as the stage matrix requires. The equal-size OLD/NEW arms therefore prove content identity and changed-artifact generation separately.

For EX-I3-047-A, the A2L's bytes remain identical and its writer reinstallation permits the loose final pair `(A+1,I+1)`; the former unchanged-A2L-generation assertion is withdrawn. Project B keeps unchanged image bytes while allowing image-stage generation movement, and project C keeps unchanged A2L bytes while allowing reset/writer generation movement. D changes only A2L content and still fabricates no image/MAC. This applies the root I-ALP-3 rule and closes CW-I3-F-05/E2-P-03 without changing NEW/OLD or any total/responsiveness budget.

Inc 3 does not introduce a content-hash cache design or change the A2L parser; the existing admitted parse/cache route must supply the changed bytes. Direct attach retains REFRESH.014 and confirmed replacement retains REFRESH.023.

### D-7 — Total-load budget and UI responsiveness have independent oracles

The performance arms use real case_06 loads on the E1 host. For each of .040/.041/.042, total duration is measured independently from product-route request before admission/copy through final outcome, parse included: the median of 3 runs is ≤45 s and every run is <60 s. Admission/copy, parse, post-parse preparation and install/publication are separately reported; A2L-only has admission but no fabricated copy phase. .041 runs both project shapes, with and without MAC, three times each.

The existing UI oracle is not weakened: a 50 ms timer still runs from post-parse entry through final publication, with canon’s ≤100 ms lateness and the declared CI adaptation through `timing_bound`. A 0.20 s producer-worker gate supplies at least three timer opportunities; zero observations fails. Moving the real producer and gate onto UI makes the timer RED. Independently, an otherwise responsive 61 s worker hold makes the total-duration assertion RED even if all timer ticks pass; starting total after parse makes the phase-boundary assertion RED. Final content and one publication remain mandatory oracles.

No timing measurement is claimed from E1. The executed 220,040-tag fixture probe and the planned 45 s/60 s/100 ms bounds are different kinds of record.

### D-8 — Inc 3 is not closed as unnecessary

The unnecessary-increment option is rejected for design, on executed static premise P04: project image/MAC bundles are constructed non-precomputed on the UI install route and the project worker never calls `_prepare_load_payload`. P03 additionally shows live session reads in the file worker. These facts establish that the planned prepared-parity route does not yet exist; they do **not** claim a measured freeze duration. Any later closure as unnecessary would require new executed route evidence after Inc 2, not this static finding alone.

### D-9 — Existing contracts and hostile-input perimeter stay intact

No canon row is changed or retired. REFRESH.002/.003/.004/.005/.014/.023/.026/.028 and their generations remain binding. No parser, path admission, depth/size/control-character or project-security rule is relaxed; no new external text surface is introduced. The new tests use isolated temporary workareas and never the real clipboard or secrets.

### D-10 — Agent84 E3 adverse coverage and the synchronous project-stage invariant

Agent84's correction adds ten reachable cases without adding implementation nodes: .043/4 no-MAC preparation failure; .045/3 no-MAC final publication; .047/5 and /6 no-MAC same-path A2L/image changes; .048/7 and /8 keyless P-PAIR image-stage A2L/image mismatches; .048/9 and /10 live P-PAIR A2L/image changes after capture but before P5 entry; and .048/11 and /12 no-MAC A2L/image mismatches. Every project adverse arm rejects before reset, with previous state/project hashes and the exact superseded/failure outcome as applicable.

The STAGE_RACE entries formerly derived from EX-I3-048-C/D are **withdrawn as unreachable inputs**, not kept as mutants. Executed AST evidence in `evidence-e3/stage-invariant.txt` proves:

- P5 is a synchronous UI install function: preflight `project_load.py:1595-1607`, reset `:1609`, direct L1 calls `:1633` and `:1643`, final publication `:1653`; only the outcome callback at `:1684` is deferred.
- P5, `_reset_project_session` and L1 contain zero `await`/`yield`; L1's `call_later` sites `loaded_state.py:785`, `:799` and `:828` come after its apply work and do not create a P5→L1 interval.
- The only runtime generation increments are the A2L single writer at `a2l_view.py:768` and L1's image increment at `loaded_state.py:642`; class default/initialization are `core.py:251` and `:398`. All five A2L-writer calls are UI install/unload routes.

Therefore no live generation can advance between P5's completed preflight and its direct L1 calls while this invariant holds. **There is no rollback.** A future await/yield/callback between those operations reopens design and blocks implementation rather than claiming that L1 rejection can restore the already-reset project. The new pre-P5 live-change arms remain reachable and must not be confused with the removed post-preflight race.

## 3. Control discharge and forward applicability

**Reverse census:** direct AST execution over all `s19_app/**/*.py`, keyed on preparation/install/publication call categories rather than a hand-listed caller set; counts and every site are in `premise-census.txt:3-34`. A second name/attribute/exact-string census covered 498 SOURCE/test files for every planned existing node, including callbacks (`:40-410`). Qwen's aborted run is not part of either census. The slice names all 13 planned implementation nodes and the baseline extractor's findings require rulings before E2 design.

**Correction population:** the DeepSeek F1–F5 and agent84 E3 corrections span requirements, ledger, slice, this rulings file, every F/P/L+S graph/report, the integrated graph/report and regenerated evidence. Agent84 adds ten ledger alternatives and removes two unreachable STAGE_RACE examples; implementation scope remains 13 nodes/4 SOURCE. Census/validator REDs, stage-invariant evidence, all lints and trace are regenerated with source redaction and no product/test/canon edit.

**Fork preconditions:** none — E1 runs one lane. Any later E4 split requires a frozen Inc 2 interface, disjoint file ownership and a crossed reverse census shared before forking.

| E1 output | Declared later consumer and use |
|---|---|
| `01-requirements.md` | Inc 3 E2 graph examples/contracts and E4 independent test design; batch-end canon fold by id. |
| `02-test-cases.md` | E4 tester implements each named on-disk node and executes each negative control; E5 reconciles collected counts. |
| `E1-slice.md` | E2 baseline comparison and E4 file ownership; integrator checks SOURCE/node counts. |
| `codewire/baseline.md` and extractor output | E2 author layers Inc 1/Inc 2 graphs and rules every extraction finding before writing the delta. |
| `evidence-e1/premise_census.py` and transcripts | E2/E4 re-run premises after Inc 2 integration; reviewers distinguish disk facts from planned behavior. |
| `evidence-e1/qwen-census.txt` | E1 provenance/audit only; it supplies no design decision or census content. |

## 4. DeepSeek E1 audit dispositions

Audit input: `../evidence/deepseek-e1-audit-inc3.txt`, produced by DeepSeek through `pi`.

| Finding | Disposition | Applied ruling |
|---|---|---|
| F-1 baseline/slice count | Corrected and re-executed | `E1-slice.md` now reconciles 12 baseline functions as 9 planned-change functions F2–F6/P3–P5/L1 plus 3 unchanged context functions. P1/P2/S1/F1 are data nodes outside the extractor; the 13-node implementation map is unchanged. |
| F-2 uncovered no-MAC branch | Corrected | Added .039/5 for project image+A2L without MAC and .041/2 for its total/responsiveness timing. .039 is 5/5 routes and .041 covers both project shapes. |
| F-3 node-id wording | Corrected | The ledger now claims one planned test function per alternative and a distinct **collected node id** through parameterization, not a distinct on-disk function per case. |
| F-4 missing total budget | Corrected | .040/.041/.042 now require median-of-3 ≤45 s and every run <60 s on the E1 host, request-to-outcome with parse included and separate phases; the 50 ms/100 ms timer remains unchanged and has an independent UI mutant. |
| F-5 L1 mapping query | Explained; no mapping change required | Project routes with an image traverse L1 for image/MAC bundles, so .041 remains mapped. A2L-only has no `current_file`, uses P5's direct snapshot/A2L-writer path and never traverses L1, so .042 remains intentionally absent. |

## 5. E1 boundary

E1/E3 has 10 new requirements, 39 planned cases (19 normal + 4 performance + 16 robustness), 13 planned implementation nodes and 4 planned SOURCE files. There are no invented case results, RED/GREEN claims, timing measurements or Qwen census findings. Inc 2's finished interface is a declared sequential prerequisite for the E2 delta and E4, not an assumed fact about this base.

## 6. E4 design returns (executed evidence)

| Finding | Ruling | Applied correction |
|---|---|---|
| **D-14 — the .040/.041/.042 total-duration budgets were miscalibrated at E1.** Executed at E4 on the E1 host: medians 62.7–71.5 s against the 45 s median / 60 s run bounds, with parse 15.2 s, post-parse preparation 37.5–51.1 s (the frozen I-ALP-2.2 producer: enrich + two 220,040-name describes, GC-managed per D-13) and install/publication 9.8–12.1 s. The E1 numbers came from "unexecuted oracle inputs" (44–46 s guesses), never measured. Responsiveness (50 ms/100 ms timer, ≥3 ticks in the 0.20 s gate, named phases, one producer call per load) passes completely — the user story holds. | ACCEPTED — budget re-calibration | `.040/.041/.042` thresholds amended in place to median ≤80 s and every run <100 s on the E1 host (D-14); the negative-control holds move from 61 s to 105 s so they still exceed the individual bound. Responsiveness clauses unchanged. |
| **D-15 — the Inc 2 `.037/4` adapter-mismatch arm is superseded by I-ALP-3.** The Inc 2-era arm expected an image reload / project install to invalidate the accepted picker mapping to empty and describe on UI; I-ALP-3 (and the new `.039` arms) require L1 to replace the mapping with the fresh S1 snapshot on every prepared load, zero UI describes. The two expectations are mutually exclusive for the same UI sequence. | ACCEPTED — I-ALP-3 wins | The Inc 2 `.037/4` route arms are amended to assert replacement semantics (fresh snapshot wins, no stale definition paints, 0 UI describes); the adapter's own mismatch→empty→describe guard remains covered by directly constructing the mismatch state and calling the mounted adapters. Inc 2's requirements/rulings record the amendment. |
