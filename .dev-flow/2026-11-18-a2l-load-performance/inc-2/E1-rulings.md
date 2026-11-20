# Inc 2 — E1 rulings: evidence, scope, interfaces and decisions

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`. Requirements: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Baseline: `codewire/baseline.md`. Design decisions below are **PROPOSED — awaiting orchestrator ruling**; all E1 artifacts consistently follow option A of each decision. No source, product test, canon, PLAN or `steps.log` file was edited.

## 0. Executed evidence

| Evidence | Exact scope and result |
|---|---|
| `evidence-e1/qwen-census.txt` | Required Qwen CLI invocation ran read-only with `--safe-mode --approval-mode plan --max-wall-time 120s --max-tool-calls 8 --output-format text`, closed stdin and outer `timeout 150s`. Wall time 31.848 s; exit **55**. Literal output: Node.js 24.15.0 temporary-memory warning; safe-mode notice; `Run aborted: tool-call budget of 8 exceeded (--max-tool-calls); observed 9.` It produced no census and no Qwen conclusion is used anywhere. No edit permission, yolo mode, clipboard or secret access was used. |
| `evidence-e1/direct_census.py` → `direct-census.txt` | Executed `python -I -B .dev-flow/2026-11-18-a2l-load-performance/inc-2/evidence-e1/direct_census.py`, exit 0, 4.156 s. Parsed every `s19_app/**/*.py` file, confirmed the four slice paths, listed definitions and reverse calls, enumerated direct-attach body calls and confirmed the `case_06` fixture/test node. It ran no application or test. |
| `evidence-e1/validate_e1.py` → `structural-validation.txt` | Executed with `python -I -B`, exit 0. Both in-memory known-bad inputs were RED (single-`shall` and fabricated-result detectors); current counts are 10 new requirements, 14 preserved references, 4 SOURCE files, 34 alternatives, 3 ATs and 37 collected items, `errors=[]`. The runtime/static split is 33 full + 1 partial. |
| `evidence-e1/trace-check.txt` | Executed the local flow's `trace_check.py` with `--base f44e8bc4... --src s19_app`, exit 1 as expected before E4/E5. Final line: `3 US, 10 active requirements ... 11 gap(s)`; the gaps are exactly 10 TEST requirement gaps (one per new requirement ID) plus absent `04-validation.md`; US/CASE/SLICE gaps are 0. They are not 37 collected-item gaps: the 37 planned items are 34 alternatives plus 3 ATs. |
| Git probes | Executed status/revision probes confirmed clean initial tree, branch and both commits. `git diff --name-only` and `--stat` from base to E0 over `s19_app`, `tests` and `REQUIREMENTS.md` returned empty output. |
| Direct source reads | `file_load.py:728-935`, `a2l_view.py:633-818,1191-1332`, `a2l_parameter_picker.py:590-665`, both panel adapters and the real caller/prefill modules. These are static observations, not runtime claims. |
| Existing test reads | Read the direct worker routes at `tests/test_b100_workers.py:636-701`, the large attach node at `:963-999`, the picker oracles at `tests/test_b103_picker_model.py:590-809` and refresh nodes in `tests/test_b103_a2l_refresh.py`. No test was executed. |

This lane did not retry its failed Qwen command. Conductor-supplied provenance states that the conductor's later Qwen retries also failed; no output from those retries is attributed to this lane's transcript. The direct census is authored and executed independently and carries no Qwen authority. DeepSeek performed the independent F1–F8 E1 audit through `pi`; the report read by this lane is `../evidence/deepseek-e1-audit-inc2.txt`.

## 1. Scope

**In:** direct A2L attach through typed path, Workarea Files, start-up and the confirmed project replacement after it rejoins the normal worker; request-time image snapshot; worker enrichment/summary/per-picker bulk definitions; immutable generation-bound result; all-or-nothing direct-install preflight; installed enrichment/summary caches; existing common refresh and outcome order; existing picker filter/page/no-op behavior; keys and visible progress through request capture, copy, parse, post-parse work and common refresh.

**Out, with reason:**

- Inc 1's occupancy index and `a2l_definition.py` internals — future dependency, not designed here.
- Image+A2L and project+A2L prepared routes — Inc 3 consumes the snapshot interface later; no second route is implemented in Inc 2.
- `a2l_view.py`, `checks_diff.py`, `patch.py`, `mac_view.py`, `loaded_state.py`, `project_load.py`, parser modules and all styles — existing seams suffice.
- MAC/validation precompute for direct attach — its cache key depends on the identity of the live `LoadedFile` (`mac_view.py:390-441`), so moving it would require replacing that object or editing another contract. It remains in the existing common refresh and is covered by R-A2L-REFRESH.018 and the new real-refresh timing arms.
- Eager decoding, per-row describes, page-expanded occupancy and visual/interaction changes — prohibited by the PLAN and unnecessary to this slice.
- Real clipboard, real home/recent-files mutation and WinCI clipboard arms — no clipboard behavior changes.

## 2. Canon disposition

No existing requirement is changed, split, retired or replaced. Only `R-A2L-REFRESH.029`, `.030`, `.031`, `.032`, `.033`, `.034`, `.035`, `.036`, `.037` and `.038` are allocated. Exact recursive grep found none on the base.

The preservation set is exactly 14 rows: `R-A2L-004.10`, `.11`, `.12`; `R-BUSY-RUN.1`; `R-A2L-REFRESH.001`, `.012`, `.013`, `.018`, `.023`, `.026`, `.027`, `.028`; `R-PICKER-CORRECT.018`, `.019`. `02-test-cases.md` names their regression nodes and leaves every result `not_run` in E1.

The canon fold at batch end belongs in S2's existing A2L refresh block. No canon edit is made at E1.

## 3. Decisions

| # | Question | Options and consequences | Recommendation and rationale |
|---|---|---|---|
| D-1 | How to deliver worker definitions without exceeding four SOURCE files | **A:** extend the existing `set_parameters` population input through the two existing panel adapters (4 files total). **B:** let the picker discover private app state itself (2 files, but hidden coupling and ambiguous picker identity). **C:** edit both app prefill hosts as well (6 files, over cap). | **A.** Explicit producer→adapter→picker flow, no widget access by the worker, no new app-host edits and exactly four source files. B hides the contract; C requires return to E0. |
| D-2 | What “immutable image snapshot” means without an existing immutable `LoadedFile.mem_map` | **A:** at request capture on main, copy the current map once and expose the copy through a read-only mapping in the frozen request; add explicit 1,000,000-byte capture latency/progress arms. **B:** mapping-proxy view over the live map (no copy cost, but later source writes alter the snapshot). **C:** read the live map in the worker (violates the worker-state contract). | **A.** Only A makes the source-mutation control discriminate a copy from an alias and keeps all worker inputs request-owned. Its main-thread cost is not claimed negligible: R-A2L-REFRESH.033/6 and .034/4 must prove the numeric bound or return the design for review. Parsed A2L/Definition payloads remain read-only shared objects, not recursively deep-copied. |
| D-3 | Snapshot contents and identity | **A:** one frozen attach snapshot with expected A2L/image generations, the existing three-part enrichment key, tuple containers for tags/summary and a read-only map of two picker snapshots; each picker snapshot carries `check`/`patch`, source identity, full signature and its own read-only bulk-definition map. **B:** path or `id()` as identity. **C:** one definition map shared by both pickers. | **A.** It preserves R-A2L-REFRESH.027 and the existing picker signature while making stale detection and per-picker call counts observable. B reintroduces recycled-identity defects; C violates one describe per picker. |
| D-4 | Where installation and stale rejection occur | **A:** `_install_attached_a2l` first compares the recorded pair with current A2L+1/current image before recents, files refresh, cache, session, widgets or sync; on match it uses `_replace_current_a2l`, then installs prepared caches/snapshot map and runs the existing common refresh. **B:** reject after installation or recompute on mismatch. | **A.** Fail-closed before the first mutation; B leaves partial state and cannot satisfy .032. A copy already written to the workarea by the worker is not installed session state and is never project-synced on rejection. |
| D-5 | Legacy direct-construction tests, unmounted panels and non-direct routes | **A:** new request/result fields have defaults and `preparation=None` preserves the legacy install helper; only the real worker route supplies a snapshot. Mounted adapters consume a picker snapshot only when both source identity and full signature match; an unmounted panel keeps the legacy `a2l_data=None` call without reading `self.app` or the accepted mapping, so the snapshot survives until mount; other routes retain their existing describe behavior until Inc 3. **B:** require preparation or app access for every caller now. | **A.** Existing `tests/test_b102_a2l_refresh.py` constructors and the unmounted caller at `tests/test_b103_picker_editor.py:846-870` remain valid and cannot masquerade as worker-proof because new tests inspect real product requests and mount survival. B expands into Inc 3 and breaks unrelated or headless direct-picker uses. |
| D-6 | Progress grammar | **A:** retain the three existing A2L steps and labels. Request capture starts under the existing busy run; parse-byte reports retain step-2 bounds 33–66; post-parse worker preparation leaves the byte bar at its completed step-2 value while spinner/elapsed continue; `_on_a2l_attached` still enters step 3 before install/common refresh. **B:** add a fourth preparation step or rename Parse. | **A.** No visual/interaction change is commissioned. R-A2L-004.11/.12 stay intact; .034 measures visible activity rather than pretending byte progress measures definition work. |
| D-7 | Preparation failure | **A:** keep enrichment, the existing `a2l_service.render_a2l_view` summary seam and both describes inside the worker's existing `Exception` boundary and route each failure to `_on_a2l_attach_failed`, with no result install; retain that handler's existing Workarea Files refresh for copying requests and allow the new copy to appear there. **B:** partial install, generic `_busy_fail` only, suppression of Workarea Files refresh or UI retry. | **A.** Reuses the exact current read-failure outcome and preserves only current image and A2L-dependent state/views, not the unrelated file list. The three .038 arms independently inject enrichment, summary and describe failures while checking the existing Workarea Files behavior; B either publishes a partial generation or changes the failure contract. |
| D-8 | Performance evidence | **A:** deterministic off-thread holds prove keys/progress during named phases; the enrichment and definition holds each last 1.5 s, exceeding the 1.0 s gap bound; real `case_06` and 1,000,000-byte image arms cover integrated post-parse/refresh and request capture; every individual key/gap must be ≤1.0 s. **B:** reuse historical average/total runtime, shorten the holds below the bound or stop at `current_a2l_path`. | **A.** Averages, short holds and path-only stopping hide the exact post-parse stall. No >90 s baseline is claimed as an E1 measurement; the operator's report remains explicitly unexecuted here. |

## 4. Interfaces to pin before E4

### I-ALP-2.1 — request/result hand-off

`A2LAttachRequest` remains frozen and gains defaulted fields after `sync_project`: `expected_a2l_generation`, `expected_image_generation` and `image_mem_map`. Product requests always populate them; `image_mem_map` is `None` without an image or a read-only independent mapping copy with one. Existing positional construction remains valid.

`A2LAttachResult` gains defaulted `preparation=None`. The worker's successful product result always has a preparation. The install callback's `None` arm is compatibility for legacy direct construction, not an acceptable worker result under .029.

### I-ALP-2.2 — attach snapshot

The new frozen attach snapshot carries the expected generation pair, exact enrichment key, enriched-tag tuple, summary-line tuple and read-only `check`/`patch` picker-snapshot mapping. The new frozen picker snapshot carries its picker key, full enrichment signature, A2L source reference and read-only definitions mapping. Containers and frozen fields reject writes; all shared parse/Definition objects are read-only by contract after hand-off.

The worker never receives or queries a picker/widget. It performs two independent `describe_definitions` calls for the same measurable-name sequence, one for each picker. The worker returns before any view mutation. Inc 3 may consume this data contract, but its route adaptation is not designed here.

### I-ALP-2.3 — panel/picker consumption

The application exposes `_accepted_a2l_picker_snapshots: Mapping[str, A2LPickerSnapshot]`, a private attribute whose value is always a read-only mapping (`MappingProxyType`), installed before common refresh. A4 replaces the attribute with the accepted attach's two-entry mapping; the empty default is an empty read-only mapping. Check's existing adapter selects `check`; Patch's selects `patch`. Each passes an entry to the picker only when its A2L source identity and full signature match the population request.

Before any `self.app` or accepted-mapping access, C1 and PA1 check `self.is_mounted`. For an unmounted panel they call P1 with the legacy `a2l_data=None` and omitted prepared definitions, perform no mapping read or invalidation and preserve the accepted mapping's identity. A later mounted matching request consumes the surviving snapshot. The .037/5 arm covers both panels, references `tests/test_b103_picker_editor.py:846-870` and asserts both the unmounted legacy call and mount-time reuse.

A generation/signature mismatch or A2L-source mismatch invalidates the whole accepted mapping: the adapter that observes it replaces the attribute on the UI thread with the empty read-only mapping before any population. It then uses the existing route's describe behavior; it never consumes the mismatched definitions. A4's next accepted direct attach replaces that empty mapping. Thus stale objects left by unload, image reload or project routes are inert even though those unchanged route owners do not edit the attribute themselves.

`A2LParameterPicker.set_parameters` gains a keyword-only optional prepared-definitions input. A supplied map, including an empty map, is used without calling `describe_definitions`; omitted input retains the existing direct-picker describe path. Equal non-`None` signatures still return `False` before any definition work. `definitions` and `definitions_source` continue to describe the last real population, so R-PE-DEF.10/.11/.12 and filter/page behavior remain intact.

Install-time generation mismatch remains whole-result rejection under .032, before `_accepted_a2l_picker_snapshots` changes. Post-install adapter mismatch is the separate .037/4 arm, with wrong-source and wrong-signature variants plus a matching control; it is not conflated with .032.

## 5. Risks and mandatory review questions

- **Capture cost:** copying 1,000,000 image bytes on main can violate the 1.0 s key/progress bound on a loaded host. This is an explicit unmeasured risk, not a claim of safety. If the E4 arms fail, do not silently replace the copy with a live alias; return to design.
- **UI refresh cost:** MAC/validation and table painting remain existing UI work. The real `case_06` key/progress arms include them and can fail even when every worker spy is correct. A thread-only green is insufficient.
- **Snapshot depth:** frozen containers do not recursively freeze parser objects. E3 must review every consumer for mutation; the current AST grep is not offered as a proof of deep immutability. Any discovered mutation requires an explicit copy/freeze design, not an undocumented exception.
- **Spy relocation:** existing picker tests patch the picker/definition modules. E4 must also observe the worker's actual describe binding, with a known-bad main-thread/describe-per-row arm, or zero counts would be vacuous.
- **Dynamic callbacks:** the AST call census reports zero syntactic calls for `_on_a2l_attached` and `_install_attached_a2l` because they are passed as callbacks. `file_load.py:836-846` supplies the actual dispatch chain; zero AST calls is not an absence finding.
- **E3 required:** I-ALP-2.1 through I-ALP-2.3 are contracts Inc 3 will consume and the design reads image/application state across a thread boundary. One independent architecture/security review must rule on these risks before E4.

## 6. What E1 did not run

No pytest node, application load, performance benchmark, mutation, real terminal capture, clipboard arm or Code-Wire source extraction ran. In particular, the reported >90 s `case_06` node was not executed. The valid baseline lint command `python -I -B <code-wire>/tools/codewire_lint.py --json .../codewire/lint.json .../codewire/baseline.md` ran with exit 0; `codewire/lint.txt` reports `not read=0 nodes=6 entities=7 edges=2`, and `codewire/lint.json` contains `unread: []`. An earlier invocation that omitted the required `--json` value exited 2 before reading the graph and is not counted as a graph verdict.

## 7. DeepSeek E1 audit dispositions (F1–F8)

Audit source: `../evidence/deepseek-e1-audit-inc2.txt`, produced by DeepSeek through `pi` and read by this lane. Every finding is accepted and corrected in place; no finding remains open and no source/test/canon file was edited.

| Finding | Ruling | Targeted correction and census |
|---|---|---|
| F1 — worker start-line drift | ACCEPTED — corrected | A2 and the requirements premise use `file_load.py:806-841`, explicitly including `@work(thread=True...)` at line 806. The census generator derives decorated function ranges from `decorator_list`; regenerated output uses the same range. |
| F2 — exact key missing in two arms | ACCEPTED — corrected | `.031/1`, `/2` and `/3` each assert the full three-tuple against pre-trigger generations and independently measured map size. The no-image literal is `(a2l_before + 1, image_before, -1)`; both image arms use `image_size`. Requirements, cases and Code-Wire examples now agree. |
| F3 — holds too short for the gap bound | ACCEPTED — corrected | `.034/1` and `/2` each hold for 1.5 s and assert every measured inter-update gap ≤1.0 s across the whole hold. The secondary spinner-count oracle is retained, not substituted. |
| F4 — summary failure unobserved | ACCEPTED — corrected | `.038` is 3/3: enrichment, real `a2l_service.render_a2l_view` summary failure after enrichment, then bulk-describe failure. Adding `.038/2` moved the ledger from 31 to 32 before the adapter-mismatch correction. |
| F5 — runtime/static threshold mixed | ACCEPTED — corrected | `.030` is explicitly 2/2 full product-route runtime plus 1/1 partial static AST. The static arm remains supplementary. After the later E3 headless arm, current coverage is 33 full + 1 partial = 34 alternatives. |
| F6 — accepted mapping unpinned | ACCEPTED — corrected | Pins `_accepted_a2l_picker_snapshots: Mapping[str, A2LPickerSnapshot]`, stored through `MappingProxyType`. A4 replaces it on accepted direct attach; an adapter replaces it with an empty read-only mapping on generation/signature or A2L-source mismatch before existing-route fallback. Rulings, slice, cases, baseline and session-census retarget use the same name and semantics. |
| F7 — adapter mismatch untested | ACCEPTED — corrected | `.037` gained `/4`, driving existing image-reload and project-install routes for wrong-signature and wrong-source variants, asserting invalidation/current output and retaining a matching control. Adding it moved the ledger from 32 to 33; the E3 headless arm below subsequently gives .037 five alternatives. |
| F8 — TEST granularity unstated | ACCEPTED — corrected | The current 37 planned collected items are 34 alternatives + 3 ATs. `trace_check.py` emits 10 TEST gaps because it works per requirement ID, not per planned collected item; with one absent future `04-validation.md`, the expected total remains 11 gaps. |

## 8. E3 review dispositions (agent83)

The conductor supplied review findings E3-I2-01 through E3-I2-03 from agent83. All are accepted and visible in the requirements, cases, slice, graph and E2 report; no finding remains open. The root interface file was not edited by this lane.

| Finding | Ruling | Targeted correction |
|---|---|---|
| E3-I2-01 — unmounted panel must not touch app/snapshot | ACCEPTED — corrected | C1/PA1 check `is_mounted` before any app/mapping access. Unmounted calls retain `a2l_data=None` and omitted prepared definitions, with no read/invalidation; accepted snapshot identity survives until a matching mount consumes it. `.037/5` covers both panels and cites `tests/test_b103_picker_editor.py:846-870`. |
| E3-I2-02 — failure preservation was too broad | ACCEPTED — corrected | `.038` and all three cases preserve the current image and A2L-dependent state/views only. The existing Workarea Files refresh remains mandatory for the copying failure route and the new copy may appear in that list; no common refresh, install, sync or success is allowed. |
| E3-I2-03 — counts after headless arm | ACCEPTED — corrected | Current totals are 34 requirement alternatives + 3 ATs = 37 planned collected items, with 33 full + 1 partial, 4 SOURCE files and unchanged one-describe-per-picker contracts. E1/E2 validators and reports derive or assert these totals. |

## 9. E4 design returns (executed evidence)

| Finding | Ruling | Applied correction |
|---|---|---|
| **D-11 — request-snapshot capture is main-thread by frozen contract and cannot meet the 1.0 s key bound.** Executed at E4: `.033/6` measured capture latencies 1.84 s / 0.17 s on the 1,000,000-byte image. The copy is mandated on UI before worker launch (I-ALP-2.1; E1 D-3 option A, alias rejected). E1 D-8 already declared this cost "not claimed negligible" and required proof or design return. | ACCEPTED — return and re-scope | `.033/6` (and the capture half of `.034/4`) drops the 1.0 s latency bound for the capture window and instead asserts: busy progress visible during capture, each capture latency recorded individually, both keys acknowledge without waiting for parse or preparation, and the worker receives the independent read-only mapping (the source-mutation control remains). The `.033` and `.034` rows are amended in place; the frozen capture contract I-ALP-2.1 is unchanged. |
| **D-12 — the preserved common refresh blocks the UI loop.** Executed at E4: case_06 common-refresh/tag-table gaps of 2.5–3.6 s (`.034/3`, AT-I2-2); HLR-176 documents the tag-table build as "blocks the loop by design" and `_refresh_a2l_dependent_views` is frozen unchanged in the E1 slice. The commission scopes responsiveness to post-parse preparation. | ACCEPTED — return and re-scope | The `.034/3` and AT-I2-2 sampling windows end when post-parse preparation and installation complete; the preserved-refresh gap is recorded unasserted as HLR-176 territory outside this commission. The `.034` row and the two ledger rows are amended in place. Removing the refresh block itself is a separate batch. |
| **D-13 — post-parse preparation itself starves the UI tick through generational GC.** Executed at E4 after the D-12 re-scope: the case_06 preparation (enrichment 4.5 s + two 220,040-name describes) holds the GIL in 1.2–2.2 s stretches from mid-run generational collections, so the amended 1.0 s cadence still failed inside the commissioned window (probes d12b–d12f; mechanism isolated by probe-d13-mechanism.txt: plain peak ticker gap 1.125 s vs 0.406 s with the collector disabled, describes ~20 % faster). | ACCEPTED — two-phase product fix within the Inc 2 slice | `_prepare_a2l_attach_snapshot` disables the cycle collector for the duration of enrichment and both describes; on success the collector stays disabled, and `_install_attached_a2l` re-enables it and runs the one big collection AFTER the preserved common refresh (D-12 territory), so no collection pause lands inside the commissioned window; the superseded-reject and worker-failure paths re-enable it immediately. Consumers of the snapshot (Inc 3 routes) must re-enable after their preserved refresh. The two case_06 arms must turn GREEN without further weakening. **E5 amendment (executed evidence):** on install-exception paths the invariant holds through the worker-side handlers — `call_from_thread` re-raises UI-thread exceptions in the calling worker, whose `except BaseException` re-enables the collector (attach worker file_load.py:971-972; loose-load worker file_load.py:1994-1995) before ending the busy. Two permanent E5 arms lock the invariant on both routes (test_r038_install_exception_reenables_gc, test_r043_install_exception_reenables_gc). |

Both returns leave I-ALP-2.1 through I-ALP-2.4, the four-SOURCE slice and every preserved canon row untouched.

## 10. E4 amendment recorded for Inc 3 (D-15, superseded arm)

The Inc 2 `.037/4` adapter-mismatch route variants (image reload / project install) are superseded by I-ALP-3: prepared loads replace the accepted picker mapping with the fresh S1 snapshot (0 UI describes), so invalidation-to-empty no longer occurs on those routes. The arm's route variants now assert replacement semantics; the adapter mismatch→empty→describe guard is covered by a directly constructed mismatch state. The `.037` requirement sentence and thresholds are unchanged — only the arm's execution content moved. Ruled in inc-3's E1-rulings §6 (D-15).
