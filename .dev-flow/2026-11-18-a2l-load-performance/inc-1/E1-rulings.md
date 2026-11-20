# INC 1 — E1 rulings

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`. Requirements: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Baseline: `codewire/graph-baseline.md`.

## Scope and canon

- Ten requirements are added with IDs R-A2L-DEF.156, R-A2L-DEF.157, R-A2L-DEF.158, R-A2L-DEF.159, R-A2L-DEF.160, R-A2L-DEF.161, R-A2L-DEF.162, R-A2L-DEF.163, R-A2L-DEF.164 and R-A2L-DEF.165. The executed canon census found every one unused.
- No existing requirement changes. R-A2L-DEF.58.1, R-A2L-DEF.58.2, R-A2L-DEF.136, R-A2L-DEF.138, R-A2L-DEF.139, R-A2L-DEF.140, R-A2L-DEF.148, R-A2L-DEF.149, R-PICKER-CORRECT.018 and R-PICKER-CORRECT.019 remain binding with their current text and thresholds.
- No context-note behavior is redefined. The local definitions in `01-requirements.md` name measurement terms only. There are no new external inputs, messages, failure paths, UI surfaces or clipboard operations.
- Fold-in at batch end: append the ten rows after R-A2L-DEF.155 in the A2L definition performance part of the canon; do not replace R-A2L-DEF.136 or the picker rows.

## Design rulings

**D-1 — Replace the central global scan, not the public model.** `describe_definition` and `describe_definitions` keep their signatures and result shape. `Definition.shared_with` keeps its type and meaning. The only source owner is `s19_app/tui/a2l_definition.py`.

**D-2 — One compact interval index per request.** Build one central index from the existing section-walk entries. One entry corresponds to one compact interval record; no entry is expanded into 16-byte pages. The retired page index in the historical graphs is not restored.

**D-3 — Position is both order and identity.** The next non-exempt overlap is the lowest section-walk `position`, never the lowest address or lexicographic name. Self-exclusion uses the requested record's position. Name and address equality cannot remove another record. Homonym refusal behavior remains R-A2L-DEF.139; cross-kind homonyms cannot inherit masks.

**D-4 — Lazy final spans remain sound and known finals stay bounded.** Existing `materialize`, `entry_cache`, `describe_name`, `axis_span` and `mask_of` behavior stays. The builder consults `entry_cache[position]` and `definitions_by_position[position]` without describing or materializing; every available final length produces an exact bounded interval, with known final `None` represented by the existing point. `last=None` is reserved for an entry absent from both sources whose lazy route can still change its length. An unresolved span may not be pruned by a provisional tag length, a 1 MiB window or an earlier-start address. The index may select a conservative false positive, but may not discard a possible final overlap. Every declared entry remains reachable as a candidate.

**D-5 — No complete alias gathering, sorting or excess consumption.** Candidate traversal returns the next relevant position without collecting all aliases and sorting them afterward. Mask exemptions are applied while advancing, so an exempt first overlap does not hide a later non-exempt overlap. A private generator wrapper counts actual downstream consumption at `_occupancy_candidates`; the planned maxima are 1, 1 and 2 for the three .159 arms. A separate no-gather/no-sort source arm rejects gather-without-sort even when no extra yield is consumed. An unobservable instrument blocks E2, not a reason to claim coverage.

**D-6 — Thresholds are normative targets, not prototype claims.** The supplied isolated build/query/memory figures have no script or transcript on disk and are not evidence. The executed E1 host and baseline are recorded in `case06-baseline.json`. The selected bounds allow approximately three times the reported prototype build/query times and over six times its reported memory, while retaining an absolute integrated ceiling. They will be measured, not inferred, at E4.

**D-7 — Full current baseline remains unrun by design.** The current global route is quadratic on disjoint inputs and its full case_06 run has no measured result. E1 ran only the 1,000-name and 4,000-name prefixes. No full baseline duration or memory number is asserted. E4's full negative control has an external watchdog and is not bypassed by the missing baseline.

**D-8 — Independent oracles and preserved pins are both required.** Small position/order/identity fixtures use hand-computed known answers and an independent exhaustive iterator. Existing real tests cover masks, homonyms, unknown lengths, final spans and encode refusals. The fast-path result count is a non-vacuity guard, never a semantic oracle by itself.

**D-9 — Historical graph review.** Batch-103 Inc 2's graph originally described per-page candidate collection; batch-103 Inc 3's graph and rulings record why partial-page and eager materialization designs were withdrawn. Current code at `a2l_definition.py:865-876` instead places every entry on the global lazy route. INC 1 starts from that current code, not from the obsolete graph mechanism, while preserving the graphs' semantic examples.

**D-10 — No fork of the source.** One E4 implementation group owns the single module. Test groups may be separate but do not edit product. INC 2 and INC 3 of this batch retain their own scopes and receive the unchanged public interface.

## Mechanical census and external-audit ruling

The initial read-only Qwen run was actually executed with `--safe-mode --approval-mode plan --max-wall-time 120s --max-tool-calls 8 --output-format text`, closed stdin and an outer `timeout 150s`. It exited 55 after 22.875 s. Verbatim combined stdout/stderr is stored at `evidence-e1/qwen-census.txt`:

> Warning: Node.js 24.15.0 can cause high temporary memory usage during shell safety checks. Upgrade to Node.js 26.12.1. Qwen Code will continue normally. See https://github.com/QwenLM/qwen-code/issues/15165
> ⚠ SAFE MODE — all customizations disabled (hooks, extensions, skills, MCP servers, QWEN.md). Restart without --safe-mode to resume normal operation.
> Run aborted: tool-call budget of 8 exceeded (--max-tool-calls); observed 9.

The conductor then made two retries, both also failed: `../evidence/qwen-e1-audit-inc1.txt` records the 150 s wall-clock abort and `../evidence/qwen-e1-audit.txt` records the 210 s wall-clock abort. Thus all 3 Qwen attempts failed and returned no census; no finding is attributed to Qwen. No attempt received edit permission or used yolo mode. The conductor performed the direct census with `evidence-e1/census.py`; its regenerated output is `evidence-e1/census.json`.

The external DeepSeek audit was performed through `pi` by the conductor and is recorded at `../evidence/deepseek-e1-audit-inc1.txt`; this worker read that audit and did not invoke a DeepSeek CLI directly. Its findings are disposed as follows.

| Audit finding | Disposition | Applied correction |
|---|---|---|
| 1 — .158 construction counter lacks an assertion | Accepted | Both .158 cases now assert exactly 1 total construction and 0 additional per-definition constructions; the counter is assigned to the builder and batch entry point |
| 2 — .164 retained-position assertion missing | Accepted | Each of the 3 memory runs now asserts exactly 220,040 unique retained positions |
| 3 — .159/3 omitted no-sort | Accepted | .159/3 now asserts 0 whole-alias sorts and runs the same source instrument as the other two arms |
| 4 — .162 population was not explicitly per run | Accepted | The warm-up and every measured run now assert exactly 220,040 unique positions |
| 5 — temporal 2× versus 96 MiB watchdog ambiguity | Accepted | The protocol separates 2× temporal watchdogs from the 96 MiB known-bad allocation watchdog; 96 MiB is deliberately below the mutant's 112,660,480-byte addition and is not a two-times-memory rule |
| 6 — partial rows lacked public AT links | Accepted | Every partial row now names AT-ALP-I1-1 or AT-ALP-I1-3; those AT rows link back to all supplemented requirements |
| 7 — .160 private arms lacked full-chain coverage of the disjoint homonym | Accepted | AT-ALP-I1-3 now covers same-name/same-span and same-name/disjoint public outcomes; .160/1 and .160/3 link to it while retaining their private position witnesses |
| 8 — full-case order inherited the product walk | Accepted | The oracle now uses an independent lexical scan of source bytes, with source line, byte offset and cross-kind declaration ordinal; it never reads product walk, product position or `shared_with` |
| 9 — full-case oracle feasibility was unbounded | Accepted | One-time oracle preparation has a 120 s watchdog, reports `oracle_seconds` outside product bounds and yields `ORACLE INVALID`, never PASS, on expiry |
| 10 — oracle repetition and comparison cost were unspecified | Accepted | Expected outcomes are computed once per test invocation before warm-up and reused; each comparison is timed outside the product region and reported as `comparison_seconds` |
| 11 — .158 construction ownership was missing from the slice | Accepted | R-A2L-DEF.158 is now mapped to `describe_definitions` and `_build_occupancy_index` as well as its candidate consumers |
| 12 — predecessor and census figures were outside the auditor's input set | Closed by direct evidence | R-A2L-DEF.155 was read at `REQUIREMENTS.md:1375`; `census.json` now records predecessor count 1, all new-ID counts 0 and preserved counts; the regenerated test transcript independently reports 38 passed |

## E3 corrective dispositions

| Finding | Disposition | Applied correction |
|---|---|---|
| E3-INC1-01 — known final array spans became open-ended | Accepted | The builder receives `definitions_by_position` and `entry_cache`, consults both by unique position without describe/materialize, and emits bounded intervals for every known final length; `last=None` is limited to genuinely unresolved lazy entries. Both .158 cases now include valid disjoint 4-byte VAL_BLK parametrizations with 0 known-final open ends and 0 builder describe/materialize calls. Forcing open-ended despite final 4 is the planned RED control |
| E3-INC1-02 — candidate consumption was not observable | Accepted | A private generator wrapper at `_occupancy_candidates` counts downstream-consumed yields. The .159 arms now require at most 1, 1 and 2 consumed candidates, with 0 gathers/sorts; gather-without-sort is explicitly RED through the independent source arm |

The correction retains 4 slice nodes, 1 source file and every public interface. No new requirement, case id, acceptance node, public field or public counter is added; the VAL_BLKs are parametrizations of the existing .158 case ids. All controls remain planned and unexecuted.

## Trace and sanitation ruling

The conductor's `../evidence/trace-inc1-e1.txt` reported 10 CASE gaps for preserved requirements. `02-test-cases.md` now has 10 explicit regression-link rows with complete requirement/case IDs and existing on-disk nodes. They add no test and no execution claim. The rerun is stored at `evidence-e1/trace-check-final.txt`; only the 10 TEST gaps for future new tests and the single EVID gap for future `04-validation.md` remain at E1.

Personal paths are replaced by `<repo>` or the `CODE_WIRE` variable in documents and generators. JSON evidence is regenerated with `<repo>` emitted at origin. The pure preserved-test transcript is regenerated with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, which prevents the third-party warning from emitting the local interpreter path; no output line is manually rewritten and the 38-test result is preserved. A final scan checks that no personal path remains under INC 1.

## Evidence disposition

- `evidence-e1/census.py` and `census.json`: repeatable direct AST/regex census over source, production callers, all tests and canon IDs.
- `evidence-e1/case06_baseline.py` and `case06-baseline.json`: repeatable bounded baseline observations on the real parser and public batch route; one run per prefix, not threshold verdicts.
- `evidence-e1/preserved-overlap-tests.txt`: 38 existing overlap/homonym/final-span tests passed at E0.
- `codewire/tool-version.txt` and `lint-baseline.txt`: actual local tool revision and baseline parse/lint result.
- `evidence-e1/qwen-command.txt`: exact Qwen arguments, bounded prompt, redirections and observed exit; `qwen-census.txt` holds its unmodified combined output.

Exact replay commands from the repository root; `CODE_WIRE` names the local Code-Wire checkout and `DEV_FLOW` the local dev-flow skill directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/census.py > .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/census.json
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/case06_baseline.py --limits 1000,4000 --repetitions 1 > .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/case06-baseline.json
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -m pytest tests/test_b103_a2l_definition.py tests/test_b103_a2l_definition_arrays_write.py tests/test_b103_a2l_definition_arrays_decode.py tests/test_b103_synth_definitions.py -k 'a2l_def_138 or a2l_def_139 or a2l_def_140' -q > .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/preserved-overlap-tests.txt 2>&1
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python "$CODE_WIRE/tools/codewire_lint.py" .dev-flow/2026-11-18-a2l-load-performance/inc-1/codewire/graph-baseline.md > .dev-flow/2026-11-18-a2l-load-performance/inc-1/codewire/lint-baseline.txt 2>&1
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python "$DEV_FLOW/trace_check.py" --req .dev-flow/2026-11-18-a2l-load-performance/inc-1/01-requirements.md --tests tests --base f44e8bc4266b6dead6ff24adef71fdb0b7b0154c --src s19_app > .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/trace-check-final.txt 2>&1
status=$?
printf '\nexit=%s\n' "$status" >> .dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e1/trace-check-final.txt
```

All new cases and negative controls remain `not_run` at E1. No performance PASS, mutant kill, full baseline or integrated full-case result is claimed.
