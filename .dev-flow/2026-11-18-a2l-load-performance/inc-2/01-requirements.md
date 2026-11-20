# Inc 2 — responsive direct A2L attach — requirements (E1)

Batch `2026-11-18-a2l-load-performance`, increment 2. Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`; branch `a2l-load-performance`. Authority: `../PLAN.md` row Inc 2 and shared contracts 5–7. Canon: `REQUIREMENTS.md`. Decisions: `E1-rulings.md`. Counted slice: `E1-slice.md`. Planned cases: `02-test-cases.md`. Baseline graph: `codewire/baseline.md`.

E0 changed no file under `s19_app/`, `tests/` or `REQUIREMENTS.md` relative to the base; the executed diff is recorded under **Premise evaluation**. Line references below are therefore valid at both commits. Inc 1 is a future dependency: this increment neither designs nor assumes the presence of its index at this base.

## User stories

- **US-ALP-01 — large A2L loads remain usable.** As the operator, I want a large A2L to load within a measured budget while the application continues responding, so that I can work without a blocked interface.
- **US-103-02 — current views.** Every A2L-dependent view shows the current generation without manual refresh; the existing story remains binding.
- **US-103-04 — true picker metadata.** The shared picker reports true declared sizes and formats; the existing story remains binding.

## Definitions (terms and formats only)

```text
direct attach       The typed-path, Workarea Files or start-up route that loads an A2L
                    through the existing A2L attach worker, including the confirmed
                    project-A2L replacement after its normal worker hand-off.
post-parse work     Enrichment, summary construction and picker definition construction
                    after the A2L bytes have been parsed and before installation.
attach snapshot     The generation-bound, read-only hand-off of enriched tags, summary
                    lines and picker snapshots for one direct attach.
picker snapshot     The read-only bulk definitions for one picker (`check` or `patch`),
                    its A2L source and its complete enrichment signature.
expected pair       The predicted post-install A2L generation and the unchanged image
                    generation captured before the worker starts.
immutable hand-off  Frozen dataclasses with tuple or read-only mapping containers; the
                    image mapping is copied before the worker starts, while parsed payloads
                    and Definition objects are shared read-only and never mutated after
                    hand-off. It is not a recursive freeze of every parser object.
key acknowledgement The product has processed a key and run its existing action or focus
                    behavior; a queue timestamp alone is not acknowledgement.
progress update     A visible change of the existing busy spinner or elapsed-time field;
                    byte-derived bar movement remains the separate R-A2L-004.11 contract.
enrichment key      `(A2L view generation, image generation, mem_size)`, where mem_size
                    is `-1` without an image and `len(mem_map)` otherwise.
```

## New requirements

Each row is one EARS sentence with one `shall`. Thresholds are acceptance obligations, not measurements already obtained. Every negative control is planned for execution in E4 and names the observable corruption it must cause.

| Id | Form | Requirement | Numeric pass threshold | Negative control (must turn the named case RED) | US | Status |
|---|---|---|---|---|---|---|---|
| R-A2L-REFRESH.029 | When | When a direct A2L attach has parsed its admitted source, the system shall build one immutable attach snapshot containing its enriched tags, summary lines and per-picker bulk definitions on the existing attach worker before dispatching installation. | 3/3 product routes: typed path, Workarea Files pick and start-up; each route records enrichment, summary and both picker describes off the UI thread before the install callback. | Move any one preparation call back to the UI thread or dispatch a result without it → the corresponding thread/content/timeline assertion is RED. | US-ALP-01, US-103-02, US-103-04 | new |
| R-A2L-REFRESH.030 | While | While the direct A2L attach worker performs post-parse work, the system shall confine its inputs to the immutable request and parsed payload, including the expected pair and read-only image mapping, without reading widgets or mutable application state. | 2/2 full product-route runtime arms (no image and image-bearing) plus 1/1 partial static AST census of every worker/helper node; both runtime requests carry the expected pair and reject container writes, and the separate census finds 0 widget/session-state reads. | Add a read of `self.current_file`, `self.current_a2l_data`, a widget or a live generation in the worker/helper, or make a snapshot mapping writable → the respective census/runtime arm is RED. | US-ALP-01, US-103-02 | new |
| R-A2L-REFRESH.031 | When | When a direct attach result's recorded pair matches the live expected post-install pair, the system shall install its parsed A2L and attach snapshot coherently before starting the common refresh. | 3/3: first attach without an image, attach with an image and changed-content same-path reload; each asserts the literal key `(previous_A2L + 1, previous_image, mem_size)` with `mem_size=-1` in the no-image arm and the independently measured map size in both image arms, plus one coherent current view before refresh. | Install only part of the snapshot, reuse the old key or refresh before installation → the generation/key/view assertion is RED. | US-103-02 | new |
| R-A2L-REFRESH.032 | If | If a direct attach result's recorded A2L or image generation differs from its live expected post-install generation, then the system shall discard the whole result before any recent, cache, session, view or project-sync mutation and end with `Load superseded — current state kept.` | 2/2: A2L-generation mismatch and image-generation mismatch; previous paths/data/generations/views are exact, with 0 installs, refreshes, recent writes, project syncs or success outcomes. | Accept any part of the stale result, recompute from it or paint success → the affected negative assertion is RED. | US-103-02 | new |
| R-A2L-REFRESH.033 | While | While a direct A2L attach copies, parses or performs post-parse work on its worker, the system shall acknowledge each operator key within 1.0 second of its delivery to the application; while the attach captures its request snapshot on the UI thread, the system shall keep the existing busy progress line visible and shall not delay any key until parse or preparation completes. | 6/6 scenarios, each with 2/2 keys (12/12 total): held copy, parse, enrichment and definition preparation, the real `case_06` attach through post-parse preparation and installation, and snapshot capture over a 1,000,000-byte image; for the five worker-window scenarios every individual latency is ≤1.0 s on the recorded reference host with no median substitution; the capture scenario records each capture latency individually, asserts visible busy progress, asserts both keys acknowledge without waiting for parse or preparation and asserts the worker receives the independent read-only mapping (D-11). | Run the held phase or real post-parse work on the UI thread, or replace the copied image snapshot with a slow UI-thread alias/copy → at least one acknowledgement exceeds 1.0 s → RED; acknowledging only after the success outcome also fails the phase-bound assertion. | US-ALP-01 | amended at E4 (D-11) |
| R-A2L-REFRESH.034 | While | While a direct A2L attach captures its input snapshot or performs post-parse work, the system shall keep its existing busy progress line visible and produce a progress update at least once per 1.0 second; the preserved common refresh keeps the busy line visible without the 1.0 s cadence (HLR-176, outside the commission). | 4/4: enrichment and definition preparation each held for 1.5 s, the real `case_06` attach sampled through post-parse preparation and installation, and snapshot capture over a 1,000,000-byte image with the busy line visible; every interval between visible progress updates in those windows is ≤1.0 s, the preserved-refresh gap is recorded unasserted (D-12), and the existing step labels/bar bounds remain unchanged. | Clear/freeze the progress line during a held phase, stop its timer or add an out-of-range bar value → the visible-text/timing/bar assertion is RED. | US-ALP-01 | amended at E4 (D-12) |
| R-A2L-REFRESH.035 | When | When an accepted direct attach snapshot completes installation, the system shall run exactly one common refresh on the UI thread after all snapshot state is installed and before the successful load outcome. | 3/3: first attach, different-A2L replacement and confirmed same-path project replacement; each timeline is install → one UI refresh → outcome, with no manual refresh or screen re-entry. | Omit the refresh, run it twice, run any part off the UI thread or paint success first → the count/thread/order assertion is RED. | US-103-02 | new |
| R-A2L-REFRESH.036 | When | When the common refresh consumes an accepted direct attach snapshot, the system shall reuse its installed enriched tags and summary lines without recomputing either on the UI thread. | 2/2: without an image and with an image; each records exactly one enrichment/summary construction on the worker, 0 further constructions on the UI thread and the exact current rows/summary at the outcome. | Drop or mismatch the installed cache so `enrich_tags_and_render` runs again on main → thread/call-count assertion is RED even if the painted rows happen to match. | US-ALP-01, US-103-02 | new |
| R-A2L-REFRESH.037 | When | When a picker handles an accepted direct-attach generation or a later population request, the system shall make that picker's single worker-built bulk definition snapshot available exclusively to a matching mounted request while preserving the legacy `a2l_data=None` call and the accepted snapshot for an unmounted panel. | 5/5 scenarios: initial Check+Patch population, changed-content same-path replacement of both, 20 filter/page rebuilds plus an unchanged-signature request per picker, adapter mismatch with 2/2 wrong-source/wrong-signature variants, and an unmounted Check+Patch call followed by mount; accepted direct generations describe once per picker off UI, rebuild/no-op arms describe 0 times, mismatches invalidate without consuming stale definitions, unmounted calls read no app/mapping and preserve snapshot identity until a matching mount consumes it, and current declared lengths/formats stay exact. | Describe per row/page, describe on main, share one describe between both pickers, reuse a stale generation, describe on an unchanged signature, consume a mismatched adapter snapshot, read app/invalidate while unmounted or fail to consume the surviving snapshot at mount → the corresponding count/thread/value/invalidation/survival assertion is RED. | US-ALP-01, US-103-04 | new |
| R-A2L-REFRESH.038 | If | If enrichment, summary construction or picker definition preparation raises an exception during a direct attach, then the system shall keep the current image and all previous A2L-dependent state/views, retain the existing Workarea Files refresh and its possible new-copy listing, run no common refresh or project sync and end with `File NOT loaded: '<file>' could not be read — check that the file can be opened, then load again.` | 3/3: enrichment failure, summary-renderer failure after real enrichment and bulk-describe failure; generations and all A2L-dependent state/views remain exact, each copying arm retains the existing Workarea Files refresh and may list the copied `new.a2l`, with 0 install/common-refresh/sync/success calls and the exact existing failure outcome. | Install a partial snapshot, paint success, run the common refresh, suppress the existing Workarea Files refresh or replace the existing failure route with a generic/unhandled failure → the affected assertion is RED. | US-103-02, US-103-04 | new |

## Preserved canon — no edits, splits or threshold replacements

These rows remain byte-for-byte outside this increment's new-ID allocation. Their current product-route nodes are regression pins in `02-test-cases.md`; inclusion here is not an execution claim.

| Preserved id (reference, not an active E1 row) | Inc 2 obligation | Existing numeric oracle retained |
|---|---|---|
| `R-A2L-004.10` | Input and screen updates continue during copy/parse; .033 extends the responsiveness observation through post-parse work and refresh. | Existing worker/timer alternatives remain; new latency rows do not weaken them. |
| `R-A2L-004.11` | The parse bar remains proportional to bytes read. | Existing `case_06` arm requires at least 2 increases within step 2, values 33–66 and at most 101 forwarded reports. |
| `R-A2L-004.12` | Workarea Files starts at the existing Parse progress line. | Existing route/node remains required; no progress-label redesign. |
| `R-BUSY-RUN.1` | Non-held steps continue to act on keys. | Existing key alternatives remain; .033 adds per-key ≤1.0 s evidence rather than replacing them. |
| `R-A2L-REFRESH.001` | Common refresh precedes direct-attach success. | 3/3 existing direct-attach alternatives. |
| `R-A2L-REFRESH.012` | Visible Check prefill refreshes without re-entry. | 4/4 existing Check alternatives. |
| `R-A2L-REFRESH.013` | Visible Patch prefill refreshes without re-entry. | 4/4 existing Patch alternatives. |
| `R-A2L-REFRESH.018` | MAC records/page survive while A2L-dependent status refreshes. | 2/2 existing page-2 alternatives. |
| `R-A2L-REFRESH.023` | Confirmed project replacement uses the normal worker/install/refresh route. | 2/2 existing accepted-replacement alternatives, including no project-file rewrite. |
| `R-A2L-REFRESH.026` | Workers prepare data; every view mutation stays on UI. | 3/3 existing direct/image/project thread-census alternatives. |
| `R-A2L-REFRESH.027` | Direct attach bumps A2L only, never the image generation. | 4/4 existing generation alternatives. |
| `R-A2L-REFRESH.028` | Prepared file/project loads retain their whole-bundle stale-generation rejection. | 2/2 existing mismatch alternatives; .032 adds the direct-attach arm without narrowing this row. |
| `R-PICKER-CORRECT.018` | Unchanged signatures remain no-ops and each changed generation describes once per picker. | 4/4 existing picker alternatives. |
| `R-PICKER-CORRECT.019` | The 13,990-object batch describe retains its ≤2.0 s median-of-3 budget and 20 filter/page rebuilds describe nothing. | 2/2 existing alternatives, including the 200-row page cap; Inc 1 owns the index needed by this existing performance contract. |

## Acceptance boundaries

Three batch-scoped black-box cases are planned, not run: **AT-ALP-I2-1** drives typed, Workarea Files and start-up attaches and reads all current views at each success; **AT-ALP-I2-2** drives the real `case_06` direct attach with keys and visible progress sampled until the success outcome; **AT-ALP-I2-3** replaces A2L content at the same path with Check and Patch mounted, then filters/pages both ledgers and asserts exact formats and describe counts. No acceptance case invokes a private installer as a substitute for the product route, reads the real clipboard or changes the operator's real home/recent-files state.

## Premise evaluation

Verdicts below come from executed probes against disk at E0, not from the PLAN or from another requirements artifact. Commands were read-only except for writing this increment's evidence files. No functional test, timing arm or real clipboard arm ran in E1.

| Premise | Verdict | Executed observation |
|---|---|---|
| The checked-out branch/HEAD and base are the commissioned revisions. | TRUE | `git status --short --branch` printed `## a2l-load-performance` with no dirty rows; `git rev-parse HEAD` and `git rev-parse d658dfea` printed `d658dfeaa336dea54b99001b52df52fa1fd434d0`; `git rev-parse f44e8bc4` printed `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`. |
| E0 did not change the product, tests or canon from the base. | TRUE | `git diff --name-only f44e8bc4..d658dfea -- s19_app tests REQUIREMENTS.md` and the corresponding `--stat` both produced empty output. |
| The existing direct attach worker copies/parses and returns before post-parse preparation. | TRUE | `s19_app/tui/app/file_load.py:806-841`; AST body census in `evidence-e1/direct-census.txt:13,47` contains copy, parse and result dispatch, but no enrichment or describe call. |
| Enrichment and picker describes currently execute after the worker hand-off. | TRUE | `file_load.py:843-887`, `s19_app/tui/app/a2l_view.py:1323-1324` and `s19_app/tui/a2l_parameter_picker.py:622-630`; reverse-call census `direct-census.txt:34-43`. |
| Common refresh currently precedes direct-attach success. | TRUE | `file_load.py:887` runs `_refresh_a2l_dependent_views`; `file_load.py:908-913` registers `end_busy` afterward. |
| Existing generation/key and picker no-op seams can be consumed without editing their owners. | TRUE | `a2l_view.py:732-818` owns replacement and the three-part key; `a2l_parameter_picker.py:622-665` no-ops on an equal non-`None` signature and otherwise describes once. |
| The Check and Patch adapters consume the accepted snapshot through their existing population seams. | TRUE | `s19_app/tui/screens_directionb/check_editor.py:201-234` (C1) and `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py:25-45` (PA1); both named in `E1-slice.md` as changed nodes. |
| A complete explicit-snapshot slice fits four source files. | TRUE | `E1-slice.md` enumerates exactly four existing paths; `direct-census.txt:4-7` confirms all four exist and `:18-25,40-42` confirms the adapter/prefill seams. This is a static feasibility verdict, not an implementation result. |
| The discriminating large fixture and existing worker test node exist. | TRUE | Executed `Path.is_file()`/`stat()` and AST probe: `examples/case_06_large_nested_a2l/firmware.a2l` exists, size 37,742,888 bytes; `tests/test_b100_workers.py:963-999` defines `test_tc_b100_53_case06_a2l_attach_keeps_the_loop_free_and_reports_parse_bytes` (`direct-census.txt:123-125`). |
| The commissioned report that this `case_06` node currently takes over 90 s. | UNDECIDABLE — declared out of E1 scope | The operator supplied the report but prohibited running this slow node in E1. No >90 s measurement is claimed or reused as a pass threshold; E4 must measure the actual run and the new per-key/progress arms independently. |
| New IDs .029 through .038 and the proposed snapshot names are unused on the base. | TRUE | Exact-ID recursive grep over repository Markdown returned no matches; the snapshot-name grep over `s19_app/**/*.py` found no proposed attach/preparation class. |
| The local Code-Wire checkout is the PLAN-pinned tooling revision. | TRUE | `git -C <code-wire> rev-parse HEAD` printed `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`, matching PLAN's v3.2.0 pin; `git describe --tags --always` printed `v3.1.0-8-gb6cd30d`. The personal absolute path is redacted in this record. |
| Qwen produced a mechanical census. | FALSE — non-blocking tool failure | The required read-only command actually ran with closed stdin and outer `timeout 150s`; after 31.848 s it exited 55. `evidence-e1/qwen-census.txt` contains only the Node warning, safe-mode notice and `Run aborted: tool-call budget of 8 exceeded (--max-tool-calls); observed 9.` No Qwen finding is cited. The independent AST/read census above supplies the census instead. Conductor-supplied provenance states that the conductor's later Qwen retries also failed; their output is not represented by this lane's transcript. |

**Fork preconditions:** none — this batch runs one lane at E1; any E4 fork must use disjoint files from `E1-slice.md`, the frozen interfaces in `E1-rulings.md` and a crossed reverse census before dispatch.

**Reverse census:** executed by `evidence-e1/direct_census.py`; full output `evidence-e1/direct-census.txt`. Dynamic callback hand-offs that a call-only AST walk cannot see are explicitly supplied from `file_load.py:836-846` rather than reported as absent callers.

**Correction population:** DeepSeek audited E1 through `pi`; its F1–F8 report is `../evidence/deepseek-e1-audit-inc2.txt`. The conductor subsequently supplied agent83's E3-I2-01 through E3-I2-03 findings. Before each correction, a category census covered every Markdown artifact, evidence generator and generated output under `inc-2/`. E1 edits landed in the requirements/cases/rulings/slice/baseline and E1 generators; E3 edits land in the requirements/cases/rulings/slice, `E2-report.md`, `codewire/graph-inc2.md`, `evidence-e1/validate_e1.py` and `evidence-e2/validate_graph.py`. Generated outputs are regenerated rather than patched. No canon sentence, root interface or directory outside `inc-2/` is edited.

**Emitted-form assertion:** none — E1 emits design records only; E4 UI assertions must read emitted/painted widget content and exact status text, never a producer-only proxy.

**Instrument RED-proof:** the census is an observation instrument, not a functional gate. Its known-present controls are the non-zero `_start_a2l_load` (2), `_a2l_attach_worker` (1), `set_parameters` (2) and `enrich_tags_and_render` (6) call populations in `direct-census.txt:29-43`; zero-count dynamic callbacks are not treated as proof of absence. Functional instruments and their known-bad arms remain planned in `02-test-cases.md`, not executed here.

## Counts

10 new requirements (`.029` through `.038`), 0 changed canon rows, 0 retired rows, 14 explicitly preserved canon rows, 3 planned black-box ATs, 34 planned requirement alternatives (37 planned collected items including the ATs) and exactly 4 SOURCE files. No case has an executed functional result in E1.
