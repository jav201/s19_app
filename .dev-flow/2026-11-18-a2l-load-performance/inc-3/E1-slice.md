# Inc 3 — E1 slice: image/project prepared-load parity

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`; line references are base lines. Requirements: `01-requirements.md`; rulings: `E1-rulings.md`; baseline graph: `codewire/baseline.md`. Names marked **new** are design proposals only; E1 made no product/test edit.

## 1. Count and ownership

| Owner group | SOURCE file | Planned state | Nodes |
|---|---|---|---:|
| G-I3-F | `s19_app/tui/app/file_load.py` | 5 existing functions changed; 1 frozen request data node new | 6 |
| G-I3-P | `s19_app/tui/app/project_load.py` | 3 existing functions and 2 existing dataclasses changed | 5 |
| G-I3-L | `s19_app/tui/app/loaded_state.py` | 1 existing function changed | 1 |
| G-I3-S | `s19_app/tui/app/shared.py` | 1 existing dataclass changed | 1 |
| **Total** | **4 SOURCE files of at most 4** | **12 existing changed + 1 new** | **13** |

One group per file keeps any later E4 lanes disjoint. No shared file has two owners. The Inc 2 producer interface must be frozen before any E4 fork; Inc 3 never edits that provider. Tests are not counted against the SOURCE cap. **Cap notice:** the fourth file is necessary to carry Inc 2's Check/Patch definition snapshots through the typed `PreparedLoad` handoff; dropping them, using a dynamic untyped attribute or writing app state from a worker would violate the contract rather than reduce the design responsibly.

## 2. Exact implementation map

| Id | Node and base location | Planned change | Requirements |
|---|---|---|---|
| F1 | `FileLoadRequest` — **new frozen data node** in `file_load.py` | Carry the admitted path, optional explicit A2L paths, captured A2L path/data/cache, captured existing-file snapshot, expected A2L/image generations, busy generation and sync flag. Fields are fixed after UI capture; workers treat captured payloads as read-only and read no live session member. | .039, .040, .043, .047, .048 |
| F2 | `FileLoadMixin.load_from_path` — `file_load.py:438` | After existing admission/copy, construct F1 on the UI thread and start the worker with that explicit context; preserve recents, busy and outcome behavior. | .039, .040, .043, .044, .047, .048 |
| F3 | `FileLoadMixin._load_workarea_file` — `file_load.py:945` | In the admitted non-A2L `go` arm, construct F1 on the UI thread and start the same worker contract; preserve in-place/no-copy and refusal behavior. | .039, .040, .043, .044, .047, .048 |
| F4 | `FileLoadMixin._parse_loaded_file` — `file_load.py:1203` | Add keyword-only `context=None`; product workers always supply F1 and consume only its explicit A2L/current-file/cache inputs. The `None` arm retains current synchronous/legacy-test reads and is never evidence of worker isolation; preserve parser calls and cache handoff. | .039, .040, .047, .048 |
| F5 | `FileLoadMixin._prepare_load_payload` — `file_load.py:1277` | Replace direct enrichment with Inc 2's producer using explicit expected generations; retain existing defaults and non-A2L derived-data preparation for synchronous callers. Add keyword-only `prepare_a2l=True`: a project image followed by MAC carries generation expectations but skips A2L payload production, and the MAC stage produces that payload once. | .039, .040, .041, .042, .043, .047, .048 |
| F6 | `FileLoadMixin._start_load_worker` — `file_load.py:1441` | Add keyword-only `context=None` after `sync_project`; F2/F3 always supply F1. On that product arm read no live counters/current artifacts, call F5 with explicit stage inputs, remove the minimal-bundle candidate fallback on preparation failure and retain one UI completion dispatch. `None` retains legacy direct-call test behavior only. | .039, .040, .043, .044, .047, .048 |
| P1 | `ProjectLoadRequest` — `project_load.py:83` | Add defaulted optional UI-captured A2L/image generation fields after `routed`; every product request populates both, while legacy direct constructions retain their old defaults and are not worker-proof. Retain all existing positional fields and admission data. | .039, .041, .042, .043, .048 |
| P2 | `PreparedProjectLoad` — `project_load.py:98` | Carry prepared image/MAC bundles and add defaulted `a2l_only=None` for the Inc 2 snapshot; retain request/refusal/manifest/problem/document data, field order and frozen handoff. Existing `LoadedFile` members remain accepted solely for legacy test construction. | .039, .041, .042, .043, .045, .046, .047, .048 |
| P3 | `ProjectLoadMixin._handle_load_project` — `project_load.py:1197` | Capture both generations while constructing P1 on the UI thread; preserve every cheap refusal, busy gate, admission and worker-start order. | .039, .041, .042, .043, .047, .048 |
| P4 | `ProjectLoadMixin._prepare_project_load` — `project_load.py:1408` | After existing parse/variant selection, prepare image/MAC through F5 off UI; for image+MAC+A2L skip image-stage A2L production and prepare the final MAC-stage A2L snapshot once; for image+A2L without MAC prepare at image stage; for A2L-only prepare through the same Inc 2 interface with `(A+2,I)`. Return P2, never a product UI-fallback bundle; only a request with legacy `None` generations retains the current non-prepared test behavior. | .039, .041, .042, .043, .047, .048 |
| P5 | `ProjectLoadMixin._install_prepared_project` — `project_load.py:1560` | Consume P2's prepared bundles directly; preflight every expected stage pair before reset; reject A2L-only mismatch before reset; install accepted bundles with `publish_a2l=False`; install A2L-only prepared values after reset without synthesis/recompute; publish once only after final state/project identity. Legacy `LoadedFile` normalization remains only for old direct test construction, never a product prepared route. | .039, .041, .042, .043, .045, .046, .047, .048 |
| L1 | `LoadedStateMixin._apply_prepared_load` — `loaded_state.py:548` | Preserve signature and `bool` acceptance. Run preflight for every precomputed bundle carrying either expected generation, not only when `a2l_enriched_key` is non-`None`; keep it before all candidate cache/session/widget/outcome work; install S1's accepted picker-snapshot mapping before common refresh and retain existing publication/finalization behavior. | .039, .040, .041, .044, .045, .048 |
| S1 | `PreparedLoad` — `shared.py:117` | Add defaulted optional `a2l_preparation=None` after existing fields to carry Inc 2's `A2LAttachSnapshot` and its Check/Patch maps. Use a type-checking-only annotation to avoid a runtime import cycle with `file_load.py`; retain every existing field/default and legacy construction. | .039, .040, .041, .042, .043, .048 |

No other implementation node is planned. In particular, Inc 3 does not add a producer helper, enrichment pipeline, definition builder, generation counter, event bus or picker API.

## 3. Stage and publication matrix

`A` and `I` are captured before worker launch. Every row's preflight occurs before reset at project level and again at the existing apply boundary immediately before that stage installs.

| Route/stage | Expected pair | A2L production | Common publication |
|---|---|---|---|
| Direct attach (Inc 2 context, unchanged here) | `(A+1,I)` | Inc 2 producer | Inc 2 install, once |
| Loose image+A2L | `(A+1,I+1)` | F5 through Inc 2 | F6 completion → L1, once |
| Project image+MAC+A2L: image after reset | `(A+2,I+1)` | none; generation-only prepared bundle | none |
| Project image+MAC+A2L: MAC after image | `(A+3,I+2)` | F5 through Inc 2, once | none until P5 final |
| Project image+A2L without MAC: image after reset | `(A+2,I+1)` | F5 through Inc 2, once | none until P5 final |
| Project A2L-only after reset | `(A+2,I)` | P4 through Inc 2, once | P5 final, once |

**L1 mapping is intentional and unchanged after the census:** .041 is included because both project routes with a primary image traverse L1 for image/MAC bundles (`project_load.py:1633` and `:1643`), whereas .042 is excluded because the A2L-only branch has no `current_file` and installs through `_replace_current_a2l` at `project_load.py:1619` without calling L1. P5 owns the single final publication in either case; L1's `publish_a2l=False` suppresses only intermediate bundle publication.

**Agent84 E3 invariant:** `evidence-e3/stage-invariant.txt` proves P5's preflight/reset/direct-L1 sequence is synchronous UI work with no await/yield and runtime generation writes only in UI routes. The two derived STAGE_RACE examples are therefore removed as unreachable; new live-change arms .048/9-/10 happen before P5 entry, while keyless/no-MAC mismatches reject before reset. No rollback exists, and adding any await/yield/callback between preflight and L1 must reopen/block the design rather than claiming rollback. This changes no implementation node or SOURCE owner.

A stale result produces no candidate cache/session/view/project/reset/publication mutation and retains REFRESH.028's exact `Load superseded — current state kept.` outcome. Accepted project installation still schedules no common refresh from L1 because `publish_a2l=False`; P5 alone calls the existing common refresh after the final pair.

## 4. Reused unchanged context

| Node/file | Why it remains unchanged |
|---|---|
| `A2LAttachSnapshot` / `A2LPickerSnapshot` — Inc 2's root-accepted I-ALP-2.2 | Inc 3 consumes its expected pair, enrichment key, tags/summary and per-picker definition maps without changing the producer/data contract; the current root/Inc2 graph is a design dependency, not evidence that product code exists. |
| `A2lViewMixin._replace_current_a2l` — `a2l_view.py:732` | Sole A2L path/data writer and generation owner; no publication is added to it. |
| `A2lViewMixin._refresh_a2l_dependent_views` — `a2l_view.py:1191` | Existing common UI fan-out and final publication surface. |
| `enrich_tags_and_render` — `services/a2l_service.py:10` | Canonical service reached through Inc 2's producer; Inc 3 adds no direct call. |
| `_complete_prepared_load` — `file_load.py:1557` | Existing loose acceptance/superseded outcome wrapper already consumes L1's `bool`. |
| Parser, project admission, busy and picker modules | Existing contracts are inputs, not edit targets. |

## 5. Executed census and baseline extraction

### 5.1 Full symbol-reference census

`evidence-e1/premise_census.py` executed over **498 Python files: 132 SOURCE plus 366 test files**. For the slice symbols it records names, attributes and exact string literals, so callbacks and monkeypatch strings are visible; this is a reference census, not a claim that every reference is a runtime caller. Full sites: `evidence-e1/premise-census.txt:40-410`.

| Planned node | References in SOURCE+tests |
|---|---:|
| `PreparedLoad` | 10 |
| `ProjectLoadRequest` | 7 |
| `PreparedProjectLoad` | 5 |
| `load_from_path` | 81 |
| `_load_workarea_file` | 16 |
| `_parse_loaded_file` | 23 |
| `_prepare_load_payload` | 9 |
| `_start_load_worker` | 8 |
| `_handle_load_project` | 160 |
| `_prepare_project_load` | 7 |
| `_install_prepared_project` | 19, including its callback handoff |
| `_apply_prepared_load` | 13 |

The earlier call-only expansion went RED because the callback handoff has no `Call` node; `premise-census-route-red.txt` retains that limitation. The final reference census includes all 12 planned existing node names and does not infer runtime coverage from them.

### 5.2 Code-Wire baseline

Local Code-Wire commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (`README.md` status v3.2) ran against a sparse throwaway clone containing only `s19_app`; marks never entered the main worktree.

- `codewire/baseline.md`: **12 baseline function nodes = 9 planned-change functions (F2–F6, P3–P5, L1) + 3 unchanged context functions (`_reset_project_session`, `_replace_current_a2l`, `enrich_tags_and_render`)**. Dataclass data nodes P1/P2/S1 and new F1 are not extractor functions; this baseline count is therefore independent of the 13-node implementation map.
- `codewire/baseline-lint.txt`: `not read=0 nodes=12 entities=0 edges=0`.
- `codewire/baseline-marks.txt`: `12 marks written, 0 nodes without code`.
- `codewire/baseline-extract.txt`: `marks=12 graph_nodes=12 calls=7 findings=0 parse_failures=0`.
- `codewire/baseline-extract/diff-report.md`: 7 resolved calls and 19 ambiguous name resolutions; tests and callable-values are outside extractor resolution. The direct AST reference census above, not the extractor's partial resolver, supplies the broader consumer list. There are no baseline drift findings to rule.

Resolved route calls are F3→F6, F2→F6, F6→F4, F6→F5, F5→`enrich_tags_and_render`, P3→P4 through the worker lift, and P5→reset. Top-level product references include `load_from_path` from the typed-load lambda and startup route, plus `_handle_load_project` from project routing. The initial full clone failed checkout on a historical over-long evidence path; the sparse retry succeeded and touched no main-tree file.

E2 must layer the applicable Inc 1/Inc 2 graphs oldest first, re-run extraction on the completed Inc 2 tree, and rule every new finding before authoring Inc 3's delta. This E1 baseline does not pretend to contain that future interface.

## 6. Planned test ownership and close conditions

| Test group | Planned file | Cases |
|---|---|---:|
| G-T-I3-S | `tests/test_alp_inc3_snapshot_parity.py` | 35 functional/robustness cases (19 normal + 16 robustness) |
| G-T-I3-PERF | `tests/test_alp_inc3_load_responsiveness.py` | 4 serial-timing alternatives: 3 runs each for .040/.042 and 3 per shape for .041 (12 runs total) |
| Re-run only | Existing REFRESH and worker/load suites plus law guards | No deletion or weakened oracle |

E4 must prove base RED on the completed Inc 2 base, integrated GREEN and every planned negative control with separate transcripts and the tested package path printed. E5 reconciles 39 distinct collected parameter node ids and runs the full blast-radius/law-guard suites. No runtime result exists at E1/E3.

**E0 budget status:** not blocked; exactly **4 SOURCE** files fit the ≤4 boundary, with the cap notice in §1. **Sequential status:** E2 graph integration is complete; E4 remains dependent on the finished Inc2 product interface and any required throwaway-clone extraction. **Unnecessary-increment status:** not taken; executed static premise P04 shows the non-precomputed project route, without claiming an unmeasured runtime freeze.
