# Inc 3 E2 — G-I3-P `project_load.py`

Batch `2026-11-18-a2l-load-performance`; E1 commit `85e68957`; owner group `G-I3-P`. Graph: `codewire/graph-inc3-project-load.md`. Scope is exactly P1–P5 in `E1-slice.md`; no product, test, canon, plan, step or frozen-interface edit is part of this record.

This is a graph-only prototype. The examples below and in the graph are planned contracts and acceptance-oracle examples. No functional test, application load, timing run, mutation or integrated Inc2/Inc3 execution was performed.

## 1. Inputs and baseline disposition

Read: batch `PLAN.md`, frozen `interfaces.md`, Inc3 `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `codewire/baseline.md` and its extractor report; Code-Wire `Metodologia.md` and `Notation-Grammar.md`; the relevant base source ranges and Inc2 E1 contracts.

The supplied baseline lint reports `not read=0`; baseline extraction reports 12 marks, 12 graph nodes, 7 calls, 0 findings and 0 parse failures. There are therefore no inherited baseline drift findings to rule. The extractor's 19 ambiguous name resolutions remain a resolver limitation; the executed E1 AST/reference census, not a guessed call graph, remains the broader consumer source.

E2-P-01's graph dependency is now resolved: the corrected Inc2 graph exists, is lint-clean and supplies the accepted producer/data contracts. This integration phase intentionally creates no clone, marks or product extraction and claims no completed Inc2 product tree. Any later product layering/extraction must use a throwaway clone, rule every finding and delete that clone before E4.

## 2. P1–P5 design

### P1 — `ProjectLoadRequest`

Retain all eight existing positional fields and their order. The root-accepted trailing fields are `captured_a2l_generation: Optional[int] = None` and `captured_image_generation: Optional[int] = None`. P3 fills both for every product request on the UI thread before worker launch. The frozen request supplies worker inputs; it never supplies a worker with live session counters. Default `None` is only legacy direct-construction compatibility, never worker-isolation evidence.

### P2 — `PreparedProjectLoad`

Retain request/refusal/variant/manifest/problem/cache/install/unreadable/document data and existing field order. The root-accepted `image` and `mac` types are `PreparedLoad | LoadedFile | None`; product workers return `PreparedLoad`, while `LoadedFile` remains only for legacy direct tests. Add trailing `a2l_only: Optional[A2LAttachSnapshot] = None`. The frozen handoff carries no synthetic image for A2L-only and no mutable app/session reference.

### P3 — `ProjectLoadMixin._handle_load_project`

Preserve busy, cancellation, path/admission, manifest and cheap-refusal order. After admission, capture current A2L/image generations into P1 and start the existing project worker. A lexical path/project-name match does not suppress an admitted reload: equal-size NEW content with a normal changed write timestamp follows the same worker route without an intervening clear.

### P4 — `ProjectLoadMixin._prepare_project_load`

Keep parsing, variant selection, diagnostics and document preparation. On product requests, derive expected pairs from the captured `(A,I)` and prepare off UI as follows:

| Route/stage | Expected pair | A2L production |
|---|---|---|
| Image+MAC+A2L, image after reset | `(A+2,I+1)` | F5 with `prepare_a2l=False`; generation-only bundle |
| Image+MAC+A2L, MAC after image | `(A+3,I+2)` | F5 with `prepare_a2l=True`; one Inc2 snapshot |
| Image+A2L without MAC, image after reset | `(A+2,I+1)` | F5 with `prepare_a2l=True`; one Inc2 snapshot |
| A2L-only after reset | `(A+2,I)` | Same Inc2 snapshot producer once, with parsed A2L and `image_mem_map=None`; no `LoadedFile` |

Thus each A2L-bearing project load invokes the snapshot producer exactly once. F5 remains owned by G-I3-F; this lane only specifies its project call adaptation. A2L-only uses the root-accepted explicit-input producer in §5 because constructing a route-admission request or synthetic image merely to call the producer would violate the design.

A producer/preparation exception propagates to the existing project worker failure route. P4 returns no fallback candidate; P5 is not called; reset, candidate installation, UI preparation, publication and success remain at zero. Legacy `None` generations alone retain non-prepared direct-test behavior.

### P5 — `ProjectLoadMixin._install_prepared_project`

At UI installation entry, read the **current** UI generations `(A_now,I_now)` and derive every required stage pair from them. Compare both expected fields of every prepared image/MAC bundle, including a generation-only bundle with `a2l_enriched_key=None`, and compare the A2L-only snapshot where present. Complete all comparisons before reset, cache store, session/widget/project mutation or publication.

Any mismatch discards the whole candidate and ends with `Load superseded — current state kept.`. In particular, EX-I3-048-F changes `I_now` after capture: P5 must reject even though A2L-only installs no image. Reusing only P1's captured counters for this check would be wrong.

After a complete match:

1. Reset without common publication and install project metadata/caches in the existing order.
2. Apply image/MAC `PreparedLoad` values directly through L1 with `publish_a2l=False`; L1 repeats its immediately-before-stage guard. Do not recompute preparation on UI.
3. For A2L-only, call the existing A2L writer after reset, install the snapshot's enrichment key/tags/summary and read-only Check/Patch mapping, and apply empty image/MAC state. Do not construct `LoadedFile` or call F5 on UI.
4. Establish final project identity and all final artifacts, then call the existing common A2L-dependent-view refresh exactly once. Only after that publication compose/show the existing successful outcome. Reset, image-only and MAC-stage publications remain zero.

Legacy `LoadedFile` normalization is confined to default-generation direct tests and is not a product prepared-route fallback.

## 3. Concrete example coverage

All sources below are planned E1 ledger IDs. Timing numbers are synthetic oracle inputs chosen to exercise the threshold arithmetic, not observed durations. `A=7,I=4` gives image-stage `(9,5)`, MAC-after-image `(10,6)` and A2L-only `(9,4)`.

| Requirement | Concrete examples in this graph | Coverage outside this lane |
|---|---|---|
| REFRESH.039 | C: P-PAIR one producer at MAC, image `(9,5)` without A2L payload and MAC `(10,6)` with it; D: P-ONLY `(9,4)` without synthetic image; E: no-MAC image `(9,5)` with one snapshot. | A direct attach: Inc2; B loose image: G-I3-F. |
| REFRESH.041 | A: P-PAIR totals 44/45/46 s → median 45, max 46, budget passes; totals 44/45/60 s fail the individual bound despite median 45. B: no-MAC totals 42/43/44 s → median 43; at least 3 ticks in the 0.20 s hold. Final-pair oracles use the stage matrix and P5's single publication. | No route ownership outside P for the two project shapes; full runtime proof remains E4. |
| REFRESH.042 | A: P-ONLY totals 43/44/45 s → median 45, max 45; admission/parse/preparation/install phases and no fabricated copy phase. A responsive 61 s hold fails total independently. Final A2L-only state follows EX-I3-046. | Full runtime proof remains E4. |
| REFRESH.043 | B/C/D: producer failure reaches the existing project failure route with zero candidates, resets, UI preparation and success; D is P-PAIR-NOMAC and fabricates no MAC. | A loose image: G-I3-F. |
| REFRESH.045 | A/B: P-PAIR empty/outgoing final pair and one F; C: empty P-PAIR-NOMAC preflights image `(2,1)`, publishes final image+A2L once, and has zero reset/stage publications or MAC. | None for project installation; integrated route proof remains E4. |
| REFRESH.046 | A: empty `(0,0)` → P-ONLY `(2,0)`; B: outgoing `(7,4)` → P-ONLY `(9,4)`. Both have one final F, `current_file=None`, unchanged image generation and no phantom image/MAC. | None for project installation; integrated route proof remains E4. |
| REFRESH.047 | B/C/D retain the corrected project/A2L-only arms. E/F add no-MAC A2L/image OLD→NEW at final `(9,5)`: changed content gets a newer generation, unchanged bytes remain identical and reset/writer/reinstall may move the unchanged artifact's generation; no MAC/OLD/mixed state survives. | A loose image: G-I3-F. E2-P-03 is closed by E1 D-6/root I-ALP-3. |
| REFRESH.048 | C/D/E/F retain original stale arms. G/H reject keyless image-stage A2L/image mismatches before reset; I/J reject live A2L/image changes after capture but before P5; K/L reject no-MAC A2L/image mismatches before reset. Every arm has exact outcome and zero reset/candidate/L1/publication effects. | A/B loose image: G-I3-F. D-10 removes unreachable STAGE_RACE and adds no rollback. |

The requested graph examples cover `.039/.041/.042/.043/.045/.046/.047/.048`. `.040` and `.044` belong to the loose-image lane and are not claimed here.

## 4. Findings and required rulings

The authoritative finding entries are in the graph's `## Findings`; none is a runtime-proven product defect.

- **E2-P-01 — closed for E2 graph integration:** the corrected Inc2 graph exists and is lint-clean, so its accepted contracts are integrated. No product marks/extraction or completed-Inc2 product-tree claim is made in this phase; any later product extraction remains a throwaway-clone prerequisite.
- **E2-P-02 — closed in this graph:** P5 uses current UI counters at installation entry, not only captured request counters. Required consumer: E4 implementer and tester, especially EX-I3-048-F.
- **E2-P-03 — closed by the corrected requirement:** REFRESH.047 and project B/C now distinguish changed-artifact generation from unchanged byte identity and allow reset/apply/reinstall generation movement. The stage matrix remains authoritative; E1 D-6 records the ruling.
- **E2-P-04 — closed by root interfaces:** I-ALP-3 pins the exact P1/P2 adaptation fields and I-ALP-2.2 pins the A2L-only producer call. The former proposals in §5 are accepted without this lane editing root rules.

## 5. Root interface rulings — accepted

### PROP-I3-P-01 — exact project handoff accepted in I-ALP-3

```text
ProjectLoadRequest trailing fields after routed:
  captured_a2l_generation: int | None = None
  captured_image_generation: int | None = None

PreparedProjectLoad:
  image: PreparedLoad | LoadedFile | None
  mac: PreparedLoad | LoadedFile | None
  trailing a2l_only: A2LAttachSnapshot | None = None
```

The accepted names distinguish worker capture from P5's current-generation preflight; unions retain only legacy direct-test compatibility; the trailing default preserves existing constructors. Consumers are G-I3-P and independent E4 tests. This lane made no root edit.

### PROP-I3-P-02 — explicit pure-input producer accepted in I-ALP-2.2

```text
FileLoadMixin._prepare_a2l_attach_snapshot(
    self, *, a2l_path: Path,
    a2l_data: dict,
    image_mem_map: Mapping[int, int] | None,
    expected_a2l_generation: int,
    expected_image_generation: int,
) -> A2LAttachSnapshot
```

Direct attach, F5 and P4/A2L-only call this same producer; `image_mem_map=None` preserves the no-image `mem_size=-1` key. The producer remains worker-only and returns the frozen I-ALP-2.2 snapshot. No `A2LAttachRequest` admission fields or synthetic `LoadedFile` are manufactured. Consumers are Inc2/Inc3 graph owners before E4.

No accepted ruling changes the frozen public definition/picker APIs, parser, project admission, persistence format or outcome text.

## 6. Lint and structural evidence

The corrected graph was re-linted at integration with direct Python, UTF-8 output and repository-relative paths. Final exit code: **0**. Verbatim stdout is `evidence-e2/integrated/project-load-lint.txt` and full parser output is `project-load-lint.json` beside it:

```text
not read=0 nodes=5 entities=4 edges=7
```

The integrated structural checker verifies the exact five P-node names, empty `unread`, all findings/examples and coverage across the combined graph; its generated output is `evidence-e2/integrated/integration-check.txt`. This is graph-parse coverage only, not functional validation.

No product/test execution, performance result, mutation verdict, real clipboard access, secret access, marks, extraction, product stub or commit occurred in this lane.
