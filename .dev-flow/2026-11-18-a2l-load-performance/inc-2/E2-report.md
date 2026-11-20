# Inc 2 — E2 Code-Wire report

Stage E2, based on E1 commit `85e68957`. Deliverable: `codewire/graph-inc2.md`. Code-Wire: commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`, `v3.1.0-8-gb6cd30d` (the PLAN-pinned v3.2.0 tooling revision). This is a graph-only design record. No functional test, application load, recording, timing arm, clipboard arm or performance result was executed or is claimed.

## 1. Scope and ownership

The delta contains exactly seven function nodes: changed A1, A2, A4, P1, C1 and PA1, plus new A3. It also realizes changed A5/A6 and new A7/A8 as frozen data contracts, preserves the seven baseline entities and adds five hand-off entities. Integrated I-ALP-2.2 makes A3 route-neutral: after `self`, it takes keyword-only `a2l_path`, `a2l_data`, `image_mem_map`, `expected_a2l_generation` and `expected_image_generation`. A2 supplies its parsed `path`/`entry[1]` and request-owned image mapping/expected pair; A3 no longer accepts the route-specific request. The accepted sequence is worker → UI callback → preflight → install → one common refresh on UI → outcome; stale and preparation-failure sequences stop before install/common refresh.

| Owner | Sole SOURCE file | Nodes / contracts |
|---|---|---|
| G-A | `s19_app/tui/app/file_load.py` | A1–A4; A5–A8 |
| G-P | `s19_app/tui/a2l_parameter_picker.py` | P1 |
| G-C | `s19_app/tui/screens_directionb/check_editor.py` | C1 |
| G-PA | `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` | PA1 |

Exactly four SOURCE files are represented. No `a2l_view.py`, prefill host, app core, parser, service, stylesheet, product test, canon, PLAN, steps or frozen interface edit is proposed as part of this delta. G-A owns the ten requirements; consumer-file ownership remains disjoint as shown.

## 2. Concrete examples by requirement

Every alternative below has a literal `examples:` line in the graph. Values are expected oracles from E1/E2, not measurements. The graph defines OLD/NEW, ARR12/AUX2 and the non-uniform three-byte IMG1 fixture; case_06 retains its independently pinned `37,742,888` bytes.

| Requirement | Concrete graph examples and expected result | Nodes |
|---|---|---|
| R-A2L-REFRESH.029 | `/1` typed NEW, `/2` Workarea Files with copy `False`, `/3` start-up `load_path=new.a2l`: each builds one complete A7 with enrichment `1`, summary `1`, Check describe `1` and Patch describe `1`, all off UI before install; the workarea arm has `0` copies. | A2, A3 |
| R-A2L-REFRESH.030 | `/1` generations `0/0` produce expected `1/0` and image `None`, and the frozen result, tuples and read-only picker mappings reject writes; `/2` IMG1 retains `0x1000: 0x10` after the source changes to `0xFF`, with expected `3/7`, size `3` and write refusal; `/3` resolves both worker/helper nodes, finds `0` forbidden reads and detects one synthetic `self.current_file` read. | A1, A2, A3 |
| R-A2L-REFRESH.031 | `/1` key generations/mem_size `1/0/-1`; `/2` `2/3/3` with IMG1 identity and bytes retained; `/3` same-path NEW installs `3/3/3`, ARR12 length `8`, `f32`, unchanged image and no OLD `u16`. | A4 |
| R-A2L-REFRESH.032 | `/1` recorded A2L `5` versus live expected `6`; `/2` recorded image `1` versus expected `2`: both end exactly `Load superseded — current state kept.` with complete OLD/IMG1/MAC preservation and `0` install-side effects, common refreshes, syncs or successes. | A4 |
| R-A2L-REFRESH.033 | `/1` copy, `/2` parse, `/3` enrichment, `/4` definitions, `/5` real case_06 through common refresh and `/6` capture over `1,000,000` image bytes: two existing keys per arm, every acknowledgement within `1.0` s and before the relevant phase/install boundary; parse values stay `33`–`66`. | A1, A2, A3 |
| R-A2L-REFRESH.034 | `/1` enrichment and `/2` definitions each hold `1.5` s with at least `2` spinner/elapsed changes and every gap ≤`1.0` s; `/3` case_06 maintains progress through common refresh; `/4` image capture over `1,000,000` bytes has no timer freeze or bar regression. | A1, A2, A3 |
| R-A2L-REFRESH.035 | `/1` first OLD, `/2` OLD→NEW and `/3` confirmed same-path project replacement: exactly install → one common refresh(UI) → `A2L loaded: <name>`; project arm has sync_project `False` and unchanged project bytes. | A4 |
| R-A2L-REFRESH.036 | `/1` without image and `/2` with IMG1: worker enrichment `1`, worker summary `1`, UI constructions `0`; common refresh consumes installed tags/summary and paints exact current cells. | A3, A4 |
| R-A2L-REFRESH.037 | `/1` OLD describes all measurable names once per picker and paints ARR12 `12/u16`, AUX2 `2/u16`; `/2` NEW describes once more per picker and paints ARR12 `8/f32`; `/3` `20` filter/page rebuilds plus unchanged-signature requests add `0` describes and at most `200` mounted rows; `/4` wrong-signature and wrong-source variants empty the whole read-only accepted mapping before fallback, while a matching control consumes the worker map; `/5` unmounted Check/Patch calls retain `a2l_data=None`, omitted prepared input, zero app/mapping reads or invalidation and unchanged snapshot identity until matching mount consumes it. | A3, A4, P1, C1, PA1 |
| R-A2L-REFRESH.038 | `/1` enrichment ValueError, `/2` summary-renderer ValueError after real enrichment and `/3` first bulk-describe ValueError after real enrichment/summary: all use the exact existing `File NOT loaded: 'new.a2l' could not be read — check that the file can be opened, then load again.`, preserve current image and A2L-dependent state/views, retain the existing Workarea Files refresh/new-copy listing behavior and perform no install, common refresh, sync or success. | A2, A3 |

Structural coverage result after E3 correction: 10 requirements, 34 unique alternatives, 45 node-example links, seven function nodes, 12 entities, 20 edges and four SOURCE files. The .037 alternatives intentionally thread through several nodes; the 45 links are not represented as 45 distinct test cases. Together with the three ATs, the requirement alternatives plan 37 collected items.

## 3. Lint and static extraction evidence

`<inc-2>` means `.dev-flow/2026-11-18-a2l-load-performance/inc-2`; `<code-wire>` and `<throwaway-clone>` redact tool/clone locations. Commands used Python with `-I -B`.

- Graph lint:
  `python -I -B <code-wire>/tools/codewire_lint.py --json <inc-2>/evidence-e2/codewire-lint.json <inc-2>/codewire/graph-inc2.md`
  Exit `0`; `evidence-e2/codewire-lint.txt`: `not read=0 nodes=7 entities=12 edges=20`. JSON `unread` is `[]`.
- Structural validation:
  `python -I -B <inc-2>/evidence-e2/validate_graph.py`
  Exit `0`; `evidence-e2/structural-validation.txt` reports the counts above, `route_neutral_a3=1` and per-requirement alternative counts `3,3,3,2,6,4,3,2,5,3`.
- Validator known-bad controls:
  `python -I -B <inc-2>/evidence-e2/validate_graph.py --self-test`
  Exit `0`; `evidence-e2/structural-validation-red.txt` reports RED for an unread line, deletion of .029/1, outcome-before-refresh, restoration of route-bound A3's old `request` input, removal of the unmounted guard and removal of the Workarea Files preparation-failure sequence. These mutate only in-memory parsed design data, never source or the graph.
- Baseline marks:
  `python -I -B <code-wire>/tools/codewire_marks.py --repo <throwaway-clone> --graph <inc-2>/codewire/baseline.md --out <inc-2>/evidence-e2/baseline-extract/marks.json`
  Exit `0`; six marks, zero nodes without code. Output: `evidence-e2/baseline-extract/marks.txt` and `marks.json`.
- Baseline extraction:
  `python -I -B <code-wire>/tools/codewire_extract.py --repo <throwaway-clone> --graph <inc-2>/codewire/baseline.md --path s19_app/tui/app/file_load.py --path s19_app/tui/a2l_parameter_picker.py --path s19_app/tui/screens_directionb/check_editor.py --path s19_app/tui/screens_directionb/patch_editor/a2l_picker.py --out <inc-2>/evidence-e2/baseline-extract`
  Exit `0`; `evidence-e2/baseline-extract/extract.txt`: `marks=6 graph_nodes=6 calls=3 findings=0 parse_failures=0`. `diff-report.md` and `extract.json` retain the details.

The throwaway clone was checked out at E1 and deleted after extraction. Extraction was baseline-only because A3 and the changed contracts are not implemented; no delta extractor result is claimed. The 55 ambiguous name resolutions are a static-tool limitation, not 55 defects. The three confirmed marked calls are A1→A2, C1→P1 and PA1→P1. Dynamic worker/install callbacks remain supplied by E1's direct source census and the graph sequences.

## 4. Findings and dispositions

No functional defect is asserted: E2 made static observations and authored expected examples only. Baseline extraction reported zero drift/info findings. The conductor has integrated the five interface dispositions into the root contracts; the graph and this report now reflect those decisions rather than proposing alternatives.

| Finding | Static observation | Integrated disposition |
|---|---|---|
| E2-1 — cache containers | A7 requires tuples; existing app cache annotations/types are lists; `app/core.py` is outside the slice. | ACCEPTED/INTEGRATED in I-ALP-2.3: A4 shallow-converts tags and summary once with `list(...)`, resets summary start to `0`, and installs the read-only picker mapping without another copy or merge. No enrichment/summary recomputation and no fifth file. |
| E2-2 — absent accepted mapping | No core initializer may be added, but non-direct routes can run before the first direct attach. | ACCEPTED/INTEGRATED in I-ALP-2.3: C1/PA1 read absence as `MappingProxyType({})`; a missing key retains the existing route and a present-entry mismatch empties the whole mapping before fallback. |
| E2-3 — pair authority | The expected pair exists in both A5 and A7 and needs one preflight source of truth. | ACCEPTED/INTEGRATED in I-ALP-2.4: A4 preflights A7's pair, which the .032 examples mutate. For direct attach, A2 maps A5's values into route-neutral A3, so A7 carries the same pair. |
| E2-4 — progress versus install views | The unchanged UI callback paints step 3 before A4; .032 forbids result-driven installation while .034 requires progress and .032 requires an outcome. | ACCEPTED/INTEGRATED in I-ALP-2.4: existing busy step/progress and required terminal outcome are control transitions, not installation of A2L result data. Preflight still precedes every install-side mutation. |
| E2-5 — extractor visibility | Baseline extraction is clean but has 55 name ambiguities and cannot see callback values. | No caller absence is inferred; E1's callback census and explicit sequences remain authoritative design inputs. This static-tool limitation needs no interface ruling. |
| E3-I2-01 — unmounted legacy call | The caller at `tests/test_b103_picker_editor.py:846-870` invokes an unmounted Check panel; eager app/mapping access would change its legacy behavior and could invalidate a snapshot before mount. | ACCEPTED/CORRECTED: both adapters guard on `is_mounted` before app access, retain `a2l_data=None` and omitted prepared input, perform no mapping read/invalidation and preserve snapshot identity for matching mount. `.037/5` covers Check and Patch. |
| E3-I2-02 — failure-view preservation | Existing `_on_a2l_attach_failed` refreshes Workarea Files for a copying request; preserving every view would suppress that obligation. | ACCEPTED/CORRECTED: `.038` and its three arms preserve current image and A2L-dependent state/views only, retain Workarea Files refresh/new-copy behavior and still forbid install/common refresh/sync/success. |
| E3-I2-03 — corrected totals | The headless alternative changes the ledger and graph-example population, not the source or graph structure. | ACCEPTED/CORRECTED: 34 alternatives + 3 ATs = 37 collected items; 45 graph-example links; 7 nodes, 12 entities, 20 edges, 4 SOURCE files and one describe per picker per accepted direct generation remain unchanged. |

## 5. Integrated interface decisions

The root `interfaces.md` contains the five E2 decisions. The E2 lane edited neither that root file nor requirement/case files. The E3 corrections in this packet modify only `inc-2/**`; their headless and failure-preservation refinements are visible in the graph and E1 rulings and are handed to the conductor for any required root fold, not represented as already root-integrated.

1. **P-E2-1 — ACCEPTED/INTEGRATED.** I-ALP-2.2 pins A7's `expected_a2l_generation`, `expected_image_generation`, `enrichment_key`, `enriched_tags`, `summary_lines`, `picker_snapshots` and A8's `picker`, `signature`, `a2l_source`, `definitions`, with the graph's types. It also pins route-neutral A3's five explicit keyword-only inputs; A2 supplies `path`, `entry[1]`, `request.image_mem_map` and both request generation fields.
2. **P-E2-2 — ACCEPTED/INTEGRATED.** I-ALP-2.3 pins one shallow `list` conversion of each A7 tag/summary tuple, summary start `0` and as-is installation of the picker mapping. This preserves cache types without an `app/core.py` edit; UI latency remains subject to .033/.034, not assumed negligible.
3. **P-E2-3 — ACCEPTED/INTEGRATED.** I-ALP-2.4 makes A7's expected pair the preflight authority compared with `(current_A2L + 1, unchanged_current_image)`. A2/A3 preserve equality with the direct request values. `preparation=None` remains invalid as a product-worker success and exists only for legacy direct construction.
4. **P-E2-4 — ACCEPTED/INTEGRATED.** I-ALP-2.3 pins absent-attribute reading as empty `MappingProxyType`, missing-key legacy behavior and whole-mapping invalidation on any present-entry key/generation/signature/source mismatch before fallback.
5. **P-E2-5 — ACCEPTED/INTEGRATED.** I-ALP-2.4 explicitly classifies existing busy step/progress and the required terminal outcome as control transitions, not A2L result installation. No callback or counted-slice expansion is needed.

## 6. Limits and next consumer

The E2 interface findings remain integrated as recorded above; E3-I2-01 through E3-I2-03 are accepted corrections with no open design finding, but this lane did not edit root `interfaces.md`. E4 must consume the corrected graph, preserve read-only-depth review and assess the two explicit performance risks from E1: main-thread copying of `1,000,000` image bytes and unchanged common-refresh work. It must also read the unmounted caller at `tests/test_b103_picker_editor.py:846-870`, execute all real product routes and all planned negative controls. This E2/E3 packet supplies no GREEN, timing pass or functional validation verdict.
