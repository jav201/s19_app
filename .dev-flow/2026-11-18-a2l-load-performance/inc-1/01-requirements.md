# INC 1 — Central occupancy index: requirements (E1)

Batch `2026-11-18-a2l-load-performance`, increment 1. Product base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`. Canon: `REQUIREMENTS.md`. Plan: `../PLAN.md`. Rulings: `E1-rulings.md`. Slice: `E1-slice.md`. Planned cases: `02-test-cases.md`. Baseline graph: `codewire/graph-baseline.md`.

Every requirement row below is new, has one EARS response and one `shall`, and names its user story. Every negative control is a planned E4 mutation, not an executed result. Existing requirements are preserved in place and are not renumbered, split or restated as new requirements.

## User stories

### US-ALP-01 — large A2L loads remain usable

As the operator, I want a large A2L to load within a measured budget while the application continues responding, so that I can work without a blocked interface. INC 1 owns only the occupancy work after parsing; worker responsiveness belongs to INC 2 and INC 3.

### US-103-05 — editing by definition preserves overlap safety

As the operator, I want definition-based editing to preserve aliases, homonyms, final spans, mask exemptions and overlap refusals, so that an occupancy optimization cannot permit an unsafe write.

## Scope

In scope: one central compact interval index per batch-describe request; next-overlap selection in section-walk `position` order; identity by `position`; no global candidate sweep for disjoint definitions; no gather/sort of all aliases; existing lazy final-span materialization; no 16-byte-page expansion; narrow queries that do not eagerly describe the file; measured full `case_06` behavior.

Out of scope: parser changes, UI or interaction changes, worker scheduling, picker implementation, clipboard access, new external inputs, new refusal messages and any edit to `s19_app/tui/a2l.py`. No new hostile-input failure path is introduced because the increment consumes the same parse payload and names; existing refusal behavior remains binding.

## Definitions

- **occupancy record**: a MEASUREMENT, CHARACTERISTIC, BLOB, INSTANCE or AXIS_PTS entry with a declared address, including a declared-address point when its final length is unreadable.
- **position**: the unique preorder section-walk ordinal assigned to an occupancy record; it is identity and ordering information, not a name or address.
- **candidate-overlap check**: one evaluation of the existing inclusive overlap predicate for a candidate selected by the index; interval-navigation comparisons are not candidate-overlap checks.
- **final-span materialization**: resolving a not-yet-final occupancy entry to the final byte length and byte order used by overlap evaluation, reusing an already requested definition when available; a requested definition supplies its final fields directly and needs no second materialization.
- **narrow query**: a describe request whose unique requested names are a strict subset of the parsed A2L's names.
- **alias population**: all occupancy records that overlap a definition; it is not limited to records sharing its name.
- **case_06**: `examples/case_06_large_nested_a2l/firmware.a2l`, SHA-256 `45243458427f43da695f4e01e494d69444c1b921588bcd040cfcaf025fed43d9`, 37,742,888 bytes, 220,040 unique tags, all addressed and length-bearing, zero declared spans outside the tags and zero parse errors.
- **MiB**: 1,048,576 bytes.

## Reference host and measurement protocol

The E1 reference host is the executed workstation recorded in `evidence-e1/case06-baseline.json`: Windows 11 build 10.0.26300, AMD64 Family 25 Model 97 Stepping 2 AuthenticAMD, 16 logical CPUs, CPython 3.12.7 packaged by Anaconda, with `CI` unset. Timed cases run serially under `pytest.mark.serial_timing`, with no concurrent benchmark and no clipboard access.

Each timing case performs one untimed warm-up and then 3 measured runs. Parsing, fixture generation, independent-oracle construction and all actual-versus-expected comparisons are excluded from timed regions; each integrated measured run uses a freshly parsed payload with the pinned case digest, and each isolated run starts with a fresh index over the same real entry tuples. For R-A2L-DEF.163 and R-A2L-DEF.165, the source-text oracle and its 220,040 expected outcomes are computed once per test invocation before the warm-up, then reused by every run; report `oracle_seconds` once and `comparison_seconds` per run, all outside the product limits. A separate 120 s watchdog bounds that one-time oracle preparation; expiry is `ORACLE INVALID`, never a product PASS or a measured sample. Garbage collection is disabled only inside a timed region and restored afterward. The reported product time is the median of 3 runs. A run exceeding its bound is a failure, not a sample to discard; an external temporal watchdog twice the product time bound stops a runaway case. The memory case uses `tracemalloc`, reports the peak additional bytes attributable to building and retaining the index over a snapshot immediately before construction, and requires each of 3 runs to meet the bound. A separate 96 MiB allocation watchdog applies only to the known-bad memory mutant: it exceeds the 64 MiB requirement but is below the mutant's 112,660,480-byte added allocation, and is intentionally not a two-times bound. Reference-host evidence is required; a CI run does not redefine these thresholds.

The exploratory figures supplied at batch opening — isolated build 0.839 s, query 6.148 s and peak 9.342 MiB — are design hypotheses only. Their script and transcript were not present in this repository. They are not formal evidence and were not used as PASS results. The normative limits below deliberately allow headroom and must be measured afresh.

## Requirements

| Id | Form | Requirement | Numeric pass threshold | Negative control planned for E4 | US | Status | Executed base observation |
|---|---|---|---|---|---|---|---|
| R-A2L-DEF.156 | When | When the system describes one or more A2L object names in one request, the system shall use one central occupancy index for all occupancy records evaluated by that request. | 3/3 request shapes; exactly 1 index construction for a single name, several names and a repeated name; 0 per-name index reconstructions | Construct the index once per requested name → the several-name arm observes more than 1 construction → RED | US-ALP-01 | new | No central index is constructed: `a2l_definition.py:865-876` assigns the same global list under `None` for every addressed result |
| R-A2L-DEF.157 | When | When the system indexes an occupancy record, the system shall represent its span with one compact interval record and zero per-page expansion records. | 3/3 spans of 1, 64 and 1,048,577 bytes; exactly 1 interval record per occupancy record and 0 page-expansion records at every length | File the span under every 16-byte page → the 64-byte and over-cap arms create more than 1 record → RED | US-ALP-01 | new | Partly: the current central route has no page expansion, but it stores scan entries rather than compact query intervals (`:642`, `:865-876`) |
| R-A2L-DEF.158 | When | When the system evaluates pairwise-disjoint definitions, the system shall perform at most 20,000 candidate-overlap checks for 1,000 definitions and at most 100,000 candidate-overlap checks for 4,000 definitions. | Each scalar and valid 4-byte VAL_BLK parametrization of both arms meets its check total, observes exactly 1 total index construction with 0 additional per-definition constructions, has 0 known-final records with open upper reachability and invokes 0 describes/materializations during index build | Force open-ended reachability for VAL_BLKs despite their known final 4-byte spans → the known-final open count exceeds 0 and the VAL_BLK disjoint checks exceed their bound → RED; restore a global entry scan per definition → both variants exceed their totals → RED | US-ALP-01 | new | No: the global loop is at `:3856-3888`; on the overlapping `case_06` prefixes, executed checks were 500,000 at 1,000 and 7,385,600 at 4,000 (`evidence-e1/case06-baseline.json`) |
| R-A2L-DEF.159 | When | When more than one occupancy record overlaps a definition, the system shall give the name of the first non-exempt record in section-walk position order without collecting or sorting the complete alias population. | 3/3 arms: exact `LATE`, exact first of 4,000 aliases, and exact second overlap after an exempt first; at most 1, 1 and 2 consumed candidate yields; 0 complete-alias gathers and sorts in each arm; at most 2, 2 and 3 final-span materializations respectively | Select by address → the cross-page arm returns `EARLY` → RED; gather the complete alias population without sorting → the no-gather source arm is RED even with 0 sorts; consume another candidate after the required answer → the 1/1/2 yield bounds are RED | US-ALP-01, US-103-05 | new | Current global route already stops at the first non-exempt overlap in position order (`:3872-3888`); inherited `.138/22` is executed GREEN |
| R-A2L-DEF.160 | When | When the system excludes a definition's own occupancy record, the system shall identify that record by its section-walk position rather than by name, address or span equality. | 3/3 arms; only the requested position is excluded; 0 same-name or same-address exclusions of another position | Exclude every entry matching the definition's name or address → the same-span homonym arm and the different-name same-address arm lose their real overlaps and return no overlap → RED; the disjoint homonym arm separately guards against name grouping | US-103-05 | new | Partly: current `own_entry` uses name, section, address, length and byte order, not `position` (`:3872-3884`); existing external outcomes pass, but the new identity rule is not implemented |
| R-A2L-DEF.161 | When | When the system describes a narrow query, the system shall materialize final spans only for requested definitions and candidates selected by the central occupancy index. | 3/3 arms: 0 additional final-span materializations and 1 definition build for one of 4,000 disjoint objects; exactly 1 additional materialization and 2 definition builds when one earlier-starting unresolved candidate is selected; exactly 1 additional materialization of `CX` and one build each of `V` and `CX` for the repeated request | Eagerly describe every occupancy record before the query → the first arm builds 4,000 definitions instead of 1 → RED | US-ALP-01, US-103-05 | new | Current lazy route holds: `materialize` and `entry_cache` are at `:830-850`; existing `.140/9` single-materialization case is executed GREEN |
| R-A2L-DEF.162 | When | When the system builds the central occupancy index for all 220,040 occupancy records of case_06, the system shall finish within 2.5 seconds as the median of 3 measured runs on the E1 reference host. | The warm-up and each of 3 measured runs index exactly 220,040 unique positions; median ≤ 2.5 s | Rebuild or globally rescan the entry population per record under a 5.0 s watchdog → timeout or bound excess → RED | US-ALP-01 | new | Unmeasured as an isolated stage; no full-index build time is claimed |
| R-A2L-DEF.163 | When | When the system resolves the next overlap for every occupancy record of case_06 after its index has been built, the system shall finish all 220,040 resolutions within 18.0 seconds as the median of 3 measured runs on the E1 reference host. | 3 measured runs after 1 warm-up; median ≤ 18.0 s; every run resolves exactly 220,040 positions with 0 `shared_with` differences from the independent full-case oracle and returns the pinned known-answer fixtures of R-A2L-DEF.159 and R-A2L-DEF.160 | Restore the current global candidate route under a 36.0 s watchdog → timeout or bound excess → RED | US-ALP-01 | new | Full baseline not run; only the two bounded prefix observations in `case06-baseline.json` were executed |
| R-A2L-DEF.164 | When | When the system builds and retains the central occupancy index for all 220,040 occupancy records of case_06, the system shall keep its peak additional traced allocation at or below 64 MiB in each of 3 measured runs on the E1 reference host. | Each of 3/3 runs retains exactly 220,040 unique indexed positions, uses ≤ 67,108,864 bytes and has 0 page-expansion records | Retain an additional 512-byte alias allocation per entry under a 96 MiB watchdog → the memory bound or watchdog fails → RED | US-ALP-01 | new | Unmeasured; the exploratory 9.342 MiB figure is not evidence |
| R-A2L-DEF.165 | When | When the system describes every unique name of case_06 through the public batch-describe route, the system shall return all 220,040 requested definitions within 30.0 seconds as the median of 3 measured runs on the E1 reference host. | 3 measured runs after 1 warm-up; median ≤ 30.0 s; each result has exactly the 220,040 requested keys in request order and 0 `shared_with` differences from the independent full-case oracle; the semantic pins of R-A2L-DEF.159 and R-A2L-DEF.160 also pass | Restore the global candidate route under a 60.0 s watchdog → timeout or bound excess → RED; return an empty or partial mapping quickly → the exact key count fails → RED | US-ALP-01, US-103-05 | new | Full baseline not run; the executed 1,000-name and 4,000-name prefixes took 1.160490200 s and 3.557036500 s respectively on this host, observation only |

## Preserved canon and regression pins

The following canon rows retain their exact text and thresholds. Their existing test functions were enumerated by `evidence-e1/census.py` over every `tests/**/*.py` file; the full node list is in `evidence-e1/census.json`. Counts are on-disk test functions, not claims about parametrized case totals.

| Requirement | Existing test functions | INC 1 disposition |
|---|---:|---|
| R-A2L-DEF.58.1 | 8 | rerun at E5; input immutability remains binding |
| R-A2L-DEF.58.2 | 48 | rerun at E5; hostile content produces refusals, not exceptions |
| R-A2L-DEF.136 | 8 | rerun all functional and serial-timing arms; the existing 2.0 s bound is not replaced |
| R-A2L-DEF.138 | 23 | rerun all; includes mask, point, cross-page order and homonym safety |
| R-A2L-DEF.139 | 4 | rerun all; homonyms remain fail-closed |
| R-A2L-DEF.140 | 11 | rerun all; includes lazy final spans, over-cap and earlier-starting spans |
| R-A2L-DEF.148 | 38 | rerun all; shared-section scaling is unchanged |
| R-A2L-DEF.149 | 14 | rerun all; direct shared-section scaling is unchanged |
| R-PICKER-CORRECT.018 | 4 | rerun all; one bulk describe per changed generation per picker |
| R-PICKER-CORRECT.019 | 2 | rerun both; the existing 2.0 s bound and zero filter/page describes remain |

Total preserved regression population: 160 existing test functions. Only the 38 functions of R-A2L-DEF.138, R-A2L-DEF.139 and R-A2L-DEF.140 were executed during this E1 pass; their transcript is `evidence-e1/preserved-overlap-tests.txt`. All other reruns are planned, not claimed.

## Premise evaluation

| Id | Premise | Verdict | Executed evidence against disk |
|---|---|---|---|
| P-1 | The E0 commit changes no product code from the declared base. | TRUE | Executed `git diff --name-only f44e8bc4..d658dfea`: only the batch `PLAN.md` and `steps.log`; `census.json` records both full commits and the source hash |
| P-2 | Current integrated occupancy evaluation scans a global candidate list rather than using a compact interval query. | TRUE | AST census plus `a2l_definition.py:865-876` and `:3856-3888`; executed counters exactly 500,000 and 7,385,600 in `case06-baseline.json` |
| P-3 | Current final-span handling is lazy, cached by position and includes final, over-cap and earlier-starting candidates. | TRUE | `a2l_definition.py:778-850`, `:3818-3834` and `:3856-3888`; all 11 existing R-A2L-DEF.140 functions executed in the 38-test GREEN run |
| P-4 | Case_06 contains the 220,040 unique addressed records used by the scale requirements. | TRUE | Real parser execution in `case06-baseline.json`: 220,040 tags, 220,040 unique names, 220,040 addressed tags, 0 tags without length, 0 parse errors; file SHA-256 pinned |
| P-5 | Existing order, homonym, mask and final-span semantics have discriminating regression oracles. | TRUE | 38/38 selected existing tests passed; concrete examples include `.138/22`, `.138/23`, `.140/9`, `.140/10` and `.140/11`, with source nodes enumerated in `census.json` |
| P-6 | Public describe consumers are limited to the known delegation, picker and two patch call sites. | TRUE | AST census of every `s19_app/**/*.py`: 4 calls total at `a2l_definition.py:607`, `a2l_parameter_picker.py:629`, `app/patch.py:393` and `app/patch.py:458`; import census also recorded |
| P-7 | The ten new IDs are unused, predecessor R-A2L-DEF.155 exists and every preserved canon ID still has exactly one canon row. | TRUE | `census.json`: count 0 for each new ID, predecessor count 1 and count 1 for each preserved R-A2L-DEF and R-PICKER-CORRECT ID; direct canon read locates R-A2L-DEF.155 at `REQUIREMENTS.md:1375`; the same regex finds known-present preserved IDs, so the absence probe can produce non-absence |
| P-8 | The local Code-Wire tool is the requested revision and reads the baseline without unread lines. | TRUE | `codewire/tool-version.txt` records `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`; executed `codewire_lint.py` transcript reports 5 nodes, 4 edges and 0 unread lines |

Hypotheses: the supplied exploratory isolated timings and memory figure remain unverified design inputs. No requirement asserts them as measurements. There are no FALSE or UNDECIDABLE premises in the INC 1 design. Qwen's failure is a tooling result, not a design premise.

**Reverse census:** `census.json` covers every assignment/use of `span_entries`, `span_index`, `entry_cache`, `materialize`, `describe_name`, `_shared_with`, `_entry_overlaps` and `_pair_exempt` in the owner module, every production call of both public describe functions, every import of the definition module, all preserved test functions and all new/preserved canon IDs. Direct symbol counts: `span_entries` 5, `span_index` 6, `entry_cache` 5, `materialize` 5, `describe_name` 4, `_shared_with` 2, `_entry_overlaps` 2 and `_pair_exempt` 2. No completeness claim relies on Qwen.

**Fork preconditions:** none — INC 1 has one source group and one source file; the read-only Qwen process and parallel documentation-only increments have no product-file ownership.

**Instrument RED-proof:** the census's known-present preserved IDs and symbols demonstrate non-empty detection beside the new-ID absences; the overlap counter demonstrated non-zero readings on real calls. New timing, memory, mutation and no-sort instruments are planned and owe their own known-bad RED proofs at E4/E5. No PASS is claimed for them at E1.

## Acceptance and counts

Three black-box acceptance cases are planned in `02-test-cases.md`: full real `case_06` batch describe, narrow real-query laziness, and public describe-to-encode overlap safety. Each maps to exactly one planned on-disk test node, and every partial requirement arm names one of these 3 ATs as its public-route supplement. No UI capture or clipboard arm applies because no visual, interaction or clipboard behavior changes.

Counts: 10 new requirements; 0 existing requirements changed, split or retired; 21 planned requirement cases; 3 planned acceptance cases covering all partial arms; 160 preserved existing test functions covered by the regression census and plan; 10 existing-node regression-link rows that add no tests; 38 preserved functions actually executed at E1; 1 source file and 4 E2 slice nodes planned in `E1-slice.md`; 5 baseline Code-Wire nodes.
