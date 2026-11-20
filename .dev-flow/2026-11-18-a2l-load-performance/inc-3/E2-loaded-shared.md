# Inc 3 E2 — L+S prepared-load installation and handoff

Batch `2026-11-18-a2l-load-performance`; lane G-I3-L+S. Product/E1 commit `85e689572f7ae97a467354a960750436a7ba3877`; Code-Wire commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (v3.2.0). Graph: `codewire/graph-inc3-loaded-shared.md`. This is a graph-only design record: no product, test, canon, PLAN, step or frozen-interface edit was made, and no functional test or load-timing arm was run.

## Deliverables and ownership

| Artifact | Owner/content |
|---|---|
| `codewire/graph-inc3-loaded-shared.md` | L1 `LoadedStateMixin._apply_prepared_load`, S1 `PreparedLoad`, stage data flow, 25 planned examples after STAGE_RACE removal and four findings |
| `evidence-e2/loaded-shared/lint.txt` | Final tool-generated lint summary |
| `evidence-e2/loaded-shared/lint.json` | Final tool-generated parse, including `unread: []` |
| `evidence-e2/loaded-shared/lint-negative-control.txt` | Known-bad lint input; an instrument fixture, not a second design graph |
| `evidence-e2/loaded-shared/lint-negative-control-output.txt` | Tool-generated unread diagnostic and summary |

Only `s19_app/tui/app/loaded_state.py` L1 and `s19_app/tui/app/shared.py` S1 are designed here. Direct-attach production/install remains Inc2; F/P nodes and A2L-only P2/P5 installation remain their Inc3 lanes. This lane did not edit `graph-inc3.md` or root `interfaces.md`.

## L1 design — generation preflight and accepted installation

The baseline guard at `loaded_state.py:589-599` runs only when `a2l_enriched_key` is non-`None`. L1 replaces that proxy with the following contract, without changing the method signature or `bool` result:

1. Collect every supplied generation expectation. The legacy pair is supplied when either `prepared.a2l_view_generation` or `prepared.a2l_image_generation` is non-`None`; that arm requires both. A non-`None` `prepared.a2l_preparation` supplies the snapshot's complete expected pair even if both legacy fields are `None`.
2. If neither representation is supplied, retain the legacy non-prepared compatibility path. That arm is not evidence of product-worker preparation.
3. If both representations are supplied, require their pairs to be equal. Require every supplied pair to equal the live installation-stage pair `(current_A2L + int(bool(prepared.loaded.a2l_data)), current_image + 1)`. Incomplete, disagreeing or stale input returns `False` before A2L cache storage, pending-variant/current-file/session changes, widgets, mapping changes, publication or outcome work.
4. Preserve the existing accepted installation/finalization. When a snapshot is present, its enrichment key, enriched tags and summary lines are authoritative for the existing A2L cache installation; duplicate legacy payload fields cannot select different content. Matching Inc2 A4, L1 makes one shallow `list` conversion of each tag/summary tuple to preserve the existing cache attribute types, never a deep copy or content rebuild. Its already read-only `check`/`patch` picker mapping replaces `_accepted_a2l_picker_snapshots` without another copy or a merge, before any common refresh. No describe or enrichment is performed by L1.
5. A keyless generation-only project image stage performs preflight but leaves the accepted picker mapping unchanged. A stale candidate also leaves it unchanged. Existing adapter generation/signature/source invalidation remains the fallback guard for routes without an accepted snapshot.
6. `publish_a2l=True` retains the existing single common refresh after accepted state/mapping installation. Project image/MAC stages pass `False`; P5 alone performs the final project publication before success. L1's `False` is consumed by the existing route wrapper, which retains `Load superseded — current state kept.`.

The project stage pairs remain exactly those frozen in I-ALP-3 and E1 D-3: image+MAC+A2L uses image `(A+2,I+1)` then MAC `(A+3,I+2)`; image+A2L without MAC uses `(A+2,I+1)`; A2L-only uses `(A+2,I)` in P5. P5 performs pre-reset preflight, while L1 repeats the bundle-stage check immediately before that bundle installs. Agent84/D-10's executed AST probe (`evidence-e3/stage-invariant.txt`) proves this is one synchronous UI sequence without await/yield and with UI-only runtime generation writers, so no live change can intervene after valid P5 preflight. The two STAGE_RACE inputs are removed as unreachable; .048/7-/12 instead exercise keyless, pre-P5 live-change and no-MAC rejection before reset. There is no rollback, and adding a yield must reopen/block design rather than claim rollback coverage.

## S1 design — typed handoff without an import cycle

Append `a2l_preparation` after the existing `a2l_cache` field, with type `Optional[A2LAttachSnapshot]` and default `None`. Keep every existing `PreparedLoad` field, default, positional order and the existing mutable dataclass behavior. The new nested snapshot is the frozen/read-only Inc2 value; legacy construction with no snapshot remains valid and is not product-route proof.

`shared.py` already has deferred annotations, while `file_load.py` imports `PreparedLoad` from `shared.py`. Therefore `shared.py` must not import `A2LAttachSnapshot` at runtime. The root-accepted design adds the name to `TYPE_CHECKING` and imports it from `.file_load` only in that branch; runtime annotation evaluation performs no reverse import. No dynamic attribute, untyped carrier or second app-global channel is introduced.

S1 is represented as a Code-Wire data entity, not a fake callable node. This matches the E1 baseline boundary: dataclass data contracts are outside the function extractor's baseline count.

## Examples by assigned requirement

All entries below are planned oracles derived from E1, not executed results. The graph carries 23 original ledger examples plus two remaining derived discrimination examples, 25 total after removing two unreachable STAGE_RACE inputs. New agent84 alternatives are carried by P4/P5 and have explicit no-L1 boundaries rather than being misrepresented as L+S calls.

| Requirement | Ledger examples in the graph | Concrete L+S expectation |
|---|---|---|
| R-A2L-REFRESH.039 | `EX-I3-039-A`, `EX-I3-039-B`, `EX-I3-039-C`, `EX-I3-039-D`, `EX-I3-039-E` | Direct attach remains Inc2 and does not call L1; loose image uses `(A+1,I+1)`; project MAC uses keyless `(A+2,I+1)` then snapshot `(A+3,I+2)`; no-MAC uses `(A+2,I+1)`; A2L-only remains P2/P5 and does not synthesize `PreparedLoad`. Accepted snapshots supply authoritative caches and both picker entries with zero UI preparation. |
| R-A2L-REFRESH.040 | `EX-I3-040-A` | Three planned serial case_06 image runs include request/admission/copy/parse through outcome, four named phases, median ≤45 s and every total <60 s; the 0.20 s worker hold provides at least three ticks no more than 100 ms late, and L1 accepts only the final current pair. |
| R-A2L-REFRESH.041 | `EX-I3-041-A`, `EX-I3-041-B` | Both project shapes run three times with the same independent total/UI bounds. With MAC, both stage pairs preflight and no intermediate F occurs; without MAC, the image-stage snapshot is consumed once and no MAC is fabricated. |
| R-A2L-REFRESH.042 | `EX-I3-042-A` | P-ONLY has four named phases without a fabricated copy phase, the same total/UI bounds, unchanged image generation and no image/MAC/current_file. Its explicit L1 `expect none` prevents a synthetic image bundle from satisfying the case. |
| R-A2L-REFRESH.043 | `EX-I3-043-A`, `EX-I3-043-B`, `EX-I3-043-C` | Producer failure leads to no L1 call on image, P-PAIR or P-ONLY; D's no-MAC arm is owned by P4/P5 and likewise has no L1 call, reset, candidate, UI preparation or success. |
| R-A2L-REFRESH.044 | `EX-I3-044-A`, `EX-I3-044-B`, `EX-I3-044-C` | First image, different-path replacement and same-path equal-size/different-content replacement each install the final pair and accepted mapping/caches before exactly one F; OUTCOME follows F and OLD/intermediate values are absent. |
| R-A2L-REFRESH.045 | `EX-I3-045-A`, `EX-I3-045-B` | Empty/outgoing P-PAIR installs keep all L1 stages unpublished; C's no-MAC arm is owned by P5 and has one final F without reset/stage publication or MAC. |
| R-A2L-REFRESH.048 | `EX-I3-048-A`, `EX-I3-048-B`, `EX-I3-048-C`, `EX-I3-048-D`, `EX-I3-048-E`, `EX-I3-048-F` | Original image/project/A2L-only mismatches retain kept-state outcomes. G–L are P4/P5 pre-reset keyless/live/no-MAC arms with no L1 call. STAGE_RACE is removed as unreachable by D-10; only `INCOMPLETE_PAIR` and `DISAGREEING_PAIRS` remain derived L1 discrimination examples. There is no rollback. |

R-A2L-REFRESH.046 and R-A2L-REFRESH.047 are outside this lane's assigned example set and are not claimed here.

## Findings and dispositions

| Finding | Evidence and disposition |
|---|---|
| E2-LS-1 — keyless generation expectations bypass the baseline guard | Static baseline `loaded_state.py:589-599` and `baseline.md` show the enrichment-key condition. The graph guards every supplied generation representation and covers keyless, incomplete and disagreeing pairs; agent84's keyless P-PAIR arms reject before P5 reset. D-10's executed invariant removes the unreachable STAGE_RACE arms rather than using them as evidence. This is disk/design evidence, not a functional defect result. |
| E2-LS-2 — a runtime import would create `shared.py` → `file_load.py` → `shared.py` | Static imports confirm the existing reverse dependency. S1 uses deferred annotations plus a `TYPE_CHECKING`-only import and appends the default after all existing fields. No import was added to product in E2. |
| E2-LS-3 — A2L-only does not traverse L1/S1 | E1's stage matrix and static `project_load.py:1618-1623` show P5's direct A2L-writer route with no `current_file`. The graph records `expect none` boundaries; P2/P5 remain the carrier/installer. This avoids phantom `LoadedFile` state rather than broadening L1. |
| E2-LS-4 — Inc2 interface ruling/product extraction dependency | **Interface/design closed:** root I-ALP-2.2/I-ALP-2.3/I-ALP-3 accept all six A7 names, S1's carrier, coherent generation pairs and accepted mapping installation, and the corrected Inc2 graph is lint-clean. No product extraction is permitted in this integration phase and no completed-Inc2 product tree or runtime success is claimed; any later extraction remains a throwaway-clone prerequisite. |
| Baseline extraction | The supplied E1 extraction reports seven resolved calls, 19 ambiguous name resolutions, zero drift/info findings and zero parse failures. There are no baseline drift findings to carry into this delta. The broader E1 AST reference census, not name-only call resolution, remains the caller authority. |

## Interface rulings — accepted in root

All four L+S proposals are accepted in the current root interfaces; this lane changed no root rule. No functional or product-extraction gate is claimed by that acceptance.

1. **I-ALP-3 carrier:** root pins `PreparedLoad.a2l_preparation: Optional[A2LAttachSnapshot] = None` immediately after `a2l_cache`, using deferred annotations and a `TYPE_CHECKING`-only `.file_load` import. Existing positional and non-prepared construction remains compatible.
2. **Inc2 snapshot consumer surface:** root adopts the concurrent Inc2 graph's six names: `expected_a2l_generation: int`, `expected_image_generation: int`, `enrichment_key: tuple[int, int, int]`, `enriched_tags: tuple[dict, ...]`, `summary_lines: tuple[str, ...]` and `picker_snapshots: Mapping[str, A2LPickerSnapshot]`. The stored picker mapping is a `MappingProxyType` with independent `check` and `patch` entries, installed without another copy. Matching Inc2 A4, accepted installation converts each tag/summary tuple once to a shallow `list` to preserve existing cache types.
3. **I-ALP-3 generation coherence:** root states that a snapshot pair is complete and sufficient without legacy duplication; if legacy fields coexist, both legacy members are required and both representations must agree. Every pair is checked against the route's stage-specific live expectation before candidate mutation.
4. **I-ALP-2.3 consumption on prepared-load routes:** root states that accepted L1 installation uses the snapshot as the authoritative source for enrichment/summary caches and replaces the existing read-only picker mapping before common refresh. It does not merge mappings, perform describes, or replace the mapping on stale/keyless stages.

## Lint evidence and limits

The corrected graph was re-linted at integration with direct Python, UTF-8 output and repository-relative paths. Exit 0; `evidence-e2/integrated/loaded-shared-lint.txt` reports the following, with the full parse in `loaded-shared-lint.json` beside it:

```text
not read=0 nodes=1 entities=5 edges=7
```

The JSON has `unread: []`, 25 examples after STAGE_RACE removal and four parsed findings. The earlier known-bad lint input and output remain under `evidence-e2/loaded-shared/`; it produced the expected unread diagnostic, `not read=1 nodes=1 entities=0 edges=0`, and exit 1. This proves only that lint reports its target failure class, not a product behavior.

No pytest node, real application route, performance benchmark, mutation, recorder/C16 run, clipboard action or secret access was executed. No marks or extractor declarations entered product. No product extraction was performed in this integration phase; any future layered extraction remains pending rather than being reported as done.
