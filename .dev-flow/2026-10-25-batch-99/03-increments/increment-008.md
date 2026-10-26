# Increment 008 — HLR-156 · `PATCH status and run records say what was not applied`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `008` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-145 / HLR-156 / LLR-156.1 · LLR-156.2 · LLR-156.3 · LLR-156.4` |
| Acceptance | `AT-B99-06` · `AT-B99-07` · white-box `TC-B99-17 · TC-B99-18 · TC-B99-19 · TC-B99-20` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: a flow PATCH arm no longer reports `ok` — `applied 0 entries` — for a
document it did not apply. `run_flow`'s PATCH arm
(`s19_app/tui/services/flow_execution_service.py`) now derives its block
status from the arm's own dispositions and refusals, first match wins:
`error` when the document could not be read (a document-level `MF-*` /
`CHG-V1-FORMAT` refusal), was refused document-wide (every entry it still
carried `blocked`), or applied 0 of at least 1 entry; `notices` when some
entry was not applied and at least one was; `ok` otherwise. A PATCH `error`
rides the existing `_record_error` abort path, so the flow stops BEFORE any
later WRITE-OUT (P-4's `outside_0x20000 run=ok patch='applied 0 entries'`
with a written `out.s19` is the defect this closes). The error block's LAST
diagnostic is the user-facing cause (UX-C2): the first refusal code
(`[MF-JSON-PARSE] …`), else the count with the first address and its
disposition (`applied 0 of 1 entries: 0x00020000 skipped-outside`). The
`notices` summary names the count (`applied 1 of 2 entries, 1 not applied`);
the all-applied summary keeps its pinned `applied N entries` form.

`ChainRunOutcome` gains `change_records`, `refusals` and `image_ranges`
(default factories, copied from `FlowRunResult` — LLR-156.2), so the fx lane
painters and the chain-set report enumerate what was not applied from the
chain's own record. `compose_chain_set_report` gains three always-present
per-lane sections after Input provenance — **Written files**, **Not applied**,
**Refusals** — a clean lane listing `none`, every file-derived field riding
`md_safe` / `md_code` (LLR-156.3). The flow report
(`s19_app/tui/services/flow_report_service.py`) gains **Not applied** and
**Refusals** sections directly after Change attribution — always present,
`- none` when empty — and `_provisional_status` refuses `CLEAN` when either
list is non-empty, so a run holding a not-applied entry or a refusal can
never head itself `CLEAN` (LLR-156.4; `SECTION_HEADINGS` carries the two new
headings in order). `FlowReportState` gains the positional `refusals` field;
`run_flow` passes the refusals retained SO FAR at the report block, exactly
like `change_records` (D-2).

The lane painter (`s19_app/tui/flow_screens.py`) shows the PATCH cell from
its block status (now `notices`/`error`-capable through the existing
`block_status` map — no glyph, word or colour class changed: `_BLOCK_STATUS_GLYPH`,
`_FX_BLOCK_STYLE`, `_FX_STATUS_STYLE`, `FX_CABLE_GLYPHS`, `_FLOW_STATUS_BANNER`
are untouched in the diff, UX-C3a), and the terminal run-log line carries the
UX-C1 rider for a lane whose PATCH ended `notices`:
`PATCH: <k> of <n> entries not applied (0xADDR DISP)` — count, first address,
disposition, clipped at `FX_ERROR_LINE_MAX`, the umbrella "not applied" wording
never the block-level `skipped` (UX-C3b). The `error` branch already names the
cause through `_failure_detail`'s last-diagnostic arm; file-derived text there
keeps riding `safe_text`. **UX-C1 choice (written down, per PDR-ux.md): the
lane line carries count + first address + disposition; the chain-set and flow
reports list EACH non-applied entry and refusal** — the log is capped at
`FX_LOG_MAX_ROWS`, so per-entry log lines cannot fit; the ledger amendment of
LLR-156.2 (D5 verdict) is the orchestrator's to record.

Shipped surfaces: Flow Execution (`FlowExecutionPanel`, lane cells, `#fx_run`),
the chain-set report under `reports/`, and the flow report.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/flow_execution_service.py` | SOURCE | LLR-156.1, LLR-156.2, LLR-156.3 | PATCH arm status derivation + UX-C2 cause; error stops before WRITE-OUT; `ChainRunOutcome.change_records/refusals/image_ranges` (+ `_run_one` copies); chain-set report Written/Not applied/Refusals sections |
| `s19_app/tui/services/flow_report_service.py` | SOURCE | LLR-156.4 | `FlowReportState.refusals`; `SECTION_HEADINGS` += Not applied/Refusals; the two always-present sections; `_provisional_status` never `CLEAN` with either list non-empty |
| `s19_app/tui/flow_screens.py` | SOURCE | LLR-156.2 (UX-C1) | `_patch_not_applied_note` + the terminal-line rider in `_log_lines`; `DISPOSITION_APPLIED` import |
| `tests/test_b99_patch_truth.py` | test | HLR-156 | new: TC-B99-17 (8-case matrix + UX-C2 cause + refusal retention + empty-doc boundary), TC-B99-18 (outcome fields), TC-B99-19 (chain-set report), TC-B99-20 (flow report), AT-B99-06, AT-B99-07 (hostile markup arm) — 17 nodes |
| `tests/test_changes_symbol_entries.py` | test | LLR-156.1 (re-pins) | TC-714 re-pin; TC-716 + the TC-717/718 census fixture re-pinned to the new law |
| `tests/test_flow_chainset_b94.py` | test | LLR-156.3 (re-pins) | TC-B94-28/TC-B94-30 provenance-line census filtered to ` input ` lines (3 sites) |
| `tests/goldens/batch71/ac6-unscoped-flow-report.md` | golden | LLR-156.4 | surgical rebaseline (C-24): +8 lines, the two new `- none` sections only |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-008.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-8/*` | doc | — | transcripts, hashes, emitted reports (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 4 (uncapped; 1 new, 3 re-pinned) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
pytest tests/test_b99_patch_truth.py -q               # -> 17 passed
pytest tests/test_b99_patch_truth.py -k tc_b99_17     # -> 11 passed (matrix + companions)
pytest tests/test_b99_patch_truth.py -k tc_b99_18     # -> 2 passed
pytest tests/test_b99_patch_truth.py -k tc_b99_19     # -> 1 passed
pytest tests/test_b99_patch_truth.py -k tc_b99_20     # -> 1 passed
pytest tests/test_b99_patch_truth.py -k at_b99_06     # -> 1 passed
pytest tests/test_b99_patch_truth.py -k at_b99_07     # -> 1 passed
pytest tests/test_address_census.py -q                # -> 23 passed (in the affected-suite run)
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-B99-17..20` ↔ LLR-156.1..156.4 | `core` · `full` | `test_tc_b99_17_patch_status_matrix[8]` · `test_tc_b99_17_error_cause_is_the_last_diagnostic` · `test_tc_b99_17_named_refusals_are_retained` · `test_tc_b99_17_empty_document_is_ok` · `test_tc_b99_18_chain_outcome_carries_refusals` · `test_tc_b99_18_chain_outcome_carries_change_records` · `test_tc_b99_19_chain_set_report_lists_what_was_not_applied` · `test_tc_b99_20_flow_report_lists_what_was_not_applied` | 15 passed |
| **B · black-box** `AT-B99-06/07` ↔ HLR-156, through the Textual pilot (`S19TuiApp(base_dir=tmp)`, `#fx_run`) | `core` · `full` | `test_at_b99_06_flow_execution_patch_truth` · `test_at_b99_07_hostile_symbol_name_renders_literally` | 2 passed |

Total on the new file: **17 passed** (`green-tc17-20-at06-07.txt`).

Re-pinned regression nodes: **7 passed** (`green-repins.txt`) — the census
file and the chain-set file re-ran clean in the affected suite below.

Reverse-census affected suite (19 files, incl. `tests/test_address_census.py`):
**362 passed, 0 failed** in 535.60 s (`green-affected-suite.txt`, `EXIT=0`).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | four, one per LLR + PQ-7 (see Mutation verdicts below) |
| Instrument | the implementer's own hand via the Edit tool; restore checked by SHA-256 against `baseline-hashes.txt` (recorded before the first mutation) |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc8`), run by the implementer |
| Transcript | `evidence/inc-8/mut-LLR-156.1.txt` · `mut-LLR-156.2.txt` · `mut-LLR-156.4.txt` · `mut-PQ7.txt` (each: the targeted node FAILED) |
| Restore proven by | all six touched files returned to their pre-mutation SHA-256 (`baseline-hashes.txt`): flow_execution_service.py `165d9457…`, flow_report_service.py `26cb97bf…`, flow_screens.py `bfbfb9e7…` |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | per mutation run, asserted ≥1 node FAILED |
| Arms that stayed GREEN | none — the first PQ-7 attempt (safe_text removed at `_failure_detail`) SURVIVED because the reader echoes the symbol through `repr`, so no real control byte reaches that sink; the sink that IS observable is the report's `md_safe` (payload brackets reach the file raw) — re-applied there and KILLED (`mut-PQ7.txt`) |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED on the unmodified tree: `red-tc17-20-at06-07.txt` — 15 failed, 2 passed in 10.10 s. Every new TC/AT group fails (TC-17 matrix ×7 rows, TC-18 ×2, TC-19, TC-20, AT-06, AT-07). The 2 pre-fix passes are the QC-3 boundary rows by design: `all_applied` → ok and `empty_document` → ok — they pin the rule's lower bound (an over-broad rule that errors on 0-entry or all-applied documents goes RED on them) |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-156.1 · TC-B99-17: the `applied 0 of ≥1` error arm disabled (`if entries and applied == 0:` → `… and False`) · KILLED — `outside`, `straddle` and the UX-C2 cause node FAILED (`mut-LLR-156.1.txt`, 3 failed / 8 passed / 6 deselected) · restore `165d9457…` ‖ LLR-156.2 · TC-B99-18: the `refusals=` copy dropped from `_run_one` · KILLED — `outcome.refusals` empty, `test_tc_b99_18_chain_outcome_carries_refusals FAILED` (`mut-LLR-156.2.txt`) · restore `165d9457…` ‖ LLR-156.4 · TC-B99-20: the `put(not_applied_lines, "Not applied")` made conditional on content · KILLED — the always-present section vanished on the malformed run (`mut-LLR-156.4.txt`) · restore `26cb97bf…` ‖ PQ-7 · AT-B99-07: `_md_safe(refusal.message)` → raw `refusal.message` in the Refusals section · KILLED — the raw `[bold]x[/]` brackets reached the emitted report (`mut-PQ7.txt`) · restore `26cb97bf…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the new tests on the unmodified tree | 15 failed / 2 passed (`red-tc17-20-at06-07.txt`) |
| `pytest` + TC-B99-17 | the applied-0 error arm disabled | `outside`/`straddle`/cause nodes FAILED (`mut-LLR-156.1.txt`) |
| `pytest` + TC-B99-18 | the `refusals=` outcome copy dropped | `test_tc_b99_18_chain_outcome_carries_refusals FAILED` (`mut-LLR-156.2.txt`) |
| `pytest` + TC-B99-20 | the Not-applied section made content-conditional | `test_tc_b99_20_flow_report_lists_what_was_not_applied FAILED` (`mut-LLR-156.4.txt`) |
| `pytest` + AT-B99-07 | `md_safe` removed from the Refusals detail cell | `test_at_b99_07_hostile_symbol_name_renders_literally FAILED` (`mut-PQ7.txt`) |
| direct driver (`python -`, no pytest) | the mix / bad documents through `run_flow` | the EMITTED reports: `mix` → `Status: COMPLETED WITH ISSUES` naming `0x00020000`/`skipped-outside`; `bad` → `Status: FAILED` naming `MF-JSON-PARSE` (`emitted-reports.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 6 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the flow report for `mix.json` / `bad.json` (emitted by `run_flow`'s REPORT arm) | read back from `<project>/reports/*.md` and inspected | `mix`: `## Not applied` table row `#2 | mix\.json | 0x00020000 | skipped-outside`, `## Refusals` → `- none`, no `CLEAN` header; `bad`: `## Refusals` row names `MF-JSON-PARSE`, `## Not applied` → `- none`, `Status: FAILED` (`emitted-reports.txt`) |
| the chain-set report (emitted by `compose_chain_set_report`) | composed from a live `run_chain_set` record and inspected | per-lane `- Chain mix: 0x00020000 skipped-outside (mix\.json)`, `- Chain bad: [MF-JSON-PARSE] …`, `- Chain good: none` in Written/Not applied/Refusals, `out_mix.s19` / `out_good.s19` in backtick spans (`emitted-reports.txt`) |
| the WRITE-OUT images | read with `tests/support/independent_reader.py` (never the app's loader) | the notices image holds `DE AD` at `0xEB10` and no byte at `0x20000`; no file exists for the error lanes (TC-B99-17 / AT-B99-06 assert this) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifact families, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-8/`
(`SHA256SUMS.txt` is the folder's own digest list, LF; it excludes itself).

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline on the unmodified tree (15 failed, 2 passed) | `red-tc17-20-at06-07.txt` | `9710bf0e…` |
| GREEN full new-file run (17 passed) | `green-tc17-20-at06-07.txt` | `6cc4333c…` |
| GREEN re-pinned census/chain-set nodes (7 passed) | `green-repins.txt` | `d9a88332…` |
| GREEN reverse-census affected suite (362 passed, EXIT=0) | `green-affected-suite.txt` | `85581ee7…` |
| Mutation LLR-156.1 (KILLED — applied-0 arm disabled) | `mut-LLR-156.1.txt` | `6fe273e1…` |
| Mutation LLR-156.2 (KILLED — outcome `refusals` copy dropped) | `mut-LLR-156.2.txt` | `1a8251fd…` |
| Mutation LLR-156.4 (KILLED — Not-applied section made conditional) | `mut-LLR-156.4.txt` | `8bea7b19…` |
| Mutation PQ-7 (KILLED — `md_safe` removed from the Refusals cell; first attempt at `_failure_detail` survived and was re-aimed) | `mut-PQ7.txt` | `8ac6f583…` |
| Reverse census probe (19 files) | `reverse-census.txt` | `4b0ce926…` |
| Emitted reports (flow + chain-set, direct driver) | `emitted-reports.txt` | `bb5b90f5…` |
| Pre-mutation hashes of every touched file | `baseline-hashes.txt` | `f958198e…` |

| Field | Value |
|---|---|
| **Evidence files** | 11 artifacts, each at the declared home and cited with the digest of its stored bytes (full digests in `SHA256SUMS.txt`) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) no flow report on a non-`ok` run says `CLEAN`; (2) 0 markup spans / 0 control bytes from the hostile payload reach the painted strip; (3) 0 WRITE-OUT files exist after a PATCH `error` |
| If the result is an ABSENCE, what made the search wide enough | (1)(3) are asserted over EVERY report file / output name the run produced, not a sample; (2) spans are read off every painted widget of the lane (`#fx_log`, head, card bodies, card statuses) via the compositor strips |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_17_empty_document_is_ok` — pins the rule's lower bound (a 0-entry document is `ok`); `test_tc_b99_17_patch_status_matrix[all_applied]` — pins the upper bound (all-applied is `ok`) |
| Conjunctive criteria: one mutation per conjunct | the status rule is disjunctive (three error arms); the mutation disables the `applied-0` conjunct only and TC-17 catches it — the other conjuncts have their own matrix rows (v1/malformed → rule 1, blocked → rule 2) |
| Synthetic instance of the absent case | each mutant IS the synthetic instance (applied-0 arm disabled; outcome field dropped; section made conditional; escaper removed) — transient, reverted by SHA-256 |
| **Positive control for every probe that returned an ABSENCE** | (1) the clean `good.json` run DOES emit `- **Status:** CLEAN` — asserted in TC-B99-20; (2) the PQ-7 mutant makes the identical payload-visible probe return raw brackets in the report (`mut-PQ7.txt`); (3) the `mix` lane's WRITE-OUT file DOES exist — asserted in TC-B99-17/AT-B99-06 |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "BLOCK_STATUS_OK\|ChainRunOutcome\|compose_chain_set_report\|applied 0 entr\|Status: CLEAN\|flow_report" tests/` (`reverse-census.txt`) | 19 files — every one re-validated in the affected suite (362 passed); 7 nodes in 3 files + 1 golden pinned the old behaviour and were re-pinned (see Correction population); the remaining 15 files pass unchanged |
| B2 file moved on disk | n/a — no pre-existing file moved | — |
| B3 byte-identical golden captures this source | `grep -rl "ac6" tests/goldens/` | 1 hit: `tests/goldens/batch71/ac6-unscoped-flow-report.md` — drifts by the always-present sections (LLR-156.4 rationale, C-24); rebaselined surgically: `git diff` shows +8 lines only (the two new `- none` sections), nothing else moves |
| B4 artifact produced here is consumed elsewhere | `grep -rln "FlowReportState\|compose_chain_set_report\|ChainRunOutcome" s19_app/ tools/` | the consumers are `flow_screens.py` (fx painters, same diff), `flow_fused_report_service.py` / `diff_report_service.py` (read `FlowRunResult`, whose fields are unchanged — only `ChainRunOutcome`/`FlowReportState` grew additive defaulted fields), `app.py` (passes no `FlowReportState` by keyword) — additive-defaulted dataclass fields keep every existing constructor call valid |
| A3 interface consumed by another module changed | additive only: `ChainRunOutcome` +3 defaulted fields, `FlowReportState` +1 defaulted field, `SECTION_HEADINGS` +2 headings (a consumer iterating it in order keeps working; the order pin in `test_tc001u_sections_present_in_order` passes) | no hit possible beyond the additive set |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared (B1, B3, B4, A3 executed; B2 n/a) — 1 B3 golden drift, rebaselined per C-24; 7 nodes re-pinned, all recorded below |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| a PATCH arm that applied 0 of ≥1 / was refused / was blocked reported `ok` and let WRITE-OUT run | `grep -rln "applied 0 entr" tests/` + the reverse-census list | enumerated before the first SOURCE edit | 4 re-pins + 1 golden | `tests/test_changes_symbol_entries.py` (TC-714, TC-716, `_census_flow_result`), `tests/test_flow_chainset_b94.py` (3 filter sites), `tests/goldens/batch71/ac6-unscoped-flow-report.md` | the 15 other census files needed no pin (they drive all-applied patches or non-patch surfaces) |

Re-pin records (`test::node — old value → new value — requirement`):

1. `test_changes_symbol_entries.py::test_tc714_no_declared_ref_refuses_symbol_entries_no_implicit_a2l` — `patch.summary == "applied 0 entries"` + `out.s19` written with source bytes → PATCH `error` (`"change document refused"`), `out.s19` never written, block `skipped`, refusal `CHG-SYMBOL-UNRESOLVED` named — LLR-156.1.
2. `test_changes_symbol_entries.py::test_tc716_flow_report_change_attribution_section` — `result.status == ok` → `completed-with-issues`; fixture: the outside-only `c3.json` arm (an error under the new law, cannot feed a WRITE-OUT fixture) replaced by an outside entry inside `c1.json` (→ `notices`); the attribution section scoped to its own heading because the new `## Not applied` census legitimately names `0x00002000` — LLR-156.1.
3. `test_changes_symbol_entries.py::_census_flow_result` (feeds TC-717 ×4 + TC-718) — `result.status == ok` → `error`; the refused Ghost document is a document-level refusal (PATCH `error`) under the new law, so the WRITE-OUT arm moved BETWEEN the two patch arms (the image under diff is the one it already produced) — LLR-156.1.
4. `test_flow_chainset_b94.py::{test_tc_b94_28_run_consumes_each_chains_own_bindings, test_tc_b94_30_chain_set_report_provenance_lines}` (3 sites) — provenance-line census `ln.startswith("- Chain ")` → `… and " input " in ln`, because the LLR-156.3 sections legitimately add `- Chain <name>:` lines — LLR-156.3.
5. `tests/goldens/batch71/ac6-unscoped-flow-report.md` — 33 → 41 lines, +8 (`## Not applied` / `## Refusals`, each `- none`); the flow stays fully clean and `Status: CLEAN` — LLR-156.4 (C-24 surgical rebaseline; the byte diff shows additions only).

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `applied 0 entries` as a PATCH success summary | `grep -rn "applied 0 entr" s19_app/` | yes — only the new error summary `applied 0 of N entries` exists; the old fixed string is gone from the PATCH arm | `s19_app/tui/services/flow_execution_service.py` (PATCH arm); the surviving `applied 0 entr` hits in `tests/b97_fixtures.py:704` and `tests/test_flow_chainset_b94.py` doc prose are historical records of the P-4 defect, not behaviour pins |
| `Status: CLEAN` on a run with not-applied entries | `grep -rn "CLEAN" s19_app/tui/services/flow_report_service.py` | yes — `CLEAN` is now gated by the block rollup AND the records/refusals check | `_provisional_status` |

### Signed-balance test ledger

`post = base − deleted + added` → `17 = 0 − 0 + 17` ✓ reconciles
(`tests/test_b99_patch_truth.py`: 0 baseline nodes — new file — 0 deleted, 17
added). Re-pins are value changes inside existing nodes, not deletions: 7 nodes
across `tests/test_changes_symbol_entries.py` (4), `tests/test_flow_chainset_b94.py`
(2) and 1 golden; no test node was deleted anywhere.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: Block (F1 HIGH two report-reading regressions the census missed; F2 HIGH ATs not black-box; F3, F4 MEDIUM; F5 LOW) · round 2: OK to advance, F1–F5 closed; N1 MEDIUM (notices painted red in Flow Builder) fixed by Kimi in round 3 and closed; N2 MEDIUM (stale SHA256SUMS) regenerated by the orchestrator with `sha256sum` over every evidence file (`sha256sum -c`: all OK) |

---

## 5 · Risks

- The `not applied` umbrella wording (UX-C3b) now appears in the PATCH summary
  (`applied X of Y entries, Z not applied`) and the UX-C1 log line. The Patch
  Editor's per-entry counts (`applied / skipped / blocked`) are a different
  surface and were intentionally left untouched.
- The reader echoes a refused symbol through `repr`, so refusal messages carry
  `\xNN` spellings rather than raw control bytes; `safe_text` remains the guard
  for messages that DO carry raw control bytes (OS-error diagnostics). Review
  round 1 (F4) added the missing PQ-7 painted-sink mutant: switching the lane
  log's failure-detail sink (`flow_screens.py` lane terminal line) to
  `Text.from_markup(...)` makes AT-B99-07 go RED — Rich parses the hostile
  name and render raises `MissingStyle: '@click app.quit'` — transcript
  `mut-f4-painted.txt`. The original report-side `md_safe` mutants stand.
- `_provisional_status` now derives `ISSUES` from `change_records`/`refusals`
  as well as block statuses. A positional mid-flow REPORT before a not-applied
  entry still reads `CLEAN` for the prefix (D-2) — that is the declared
  positional contract, not a leak.
- Two earlier evidence runs of the affected suite were invalidated (three
  concurrently-launched runs truncated each other's evidence file; the orphans
  were killed) and re-run as a single clean run — the only surviving affected-
  suite transcript is `green-affected-suite.txt` (362 passed, EXIT=0).

## 6 · Pending items / spec deviations

- The LLR-156.2 ledger amendment recording the UX-C1 choice (lane line = count
  + first + disposition; reports list each) is the orchestrator's to file
  (PDR-ux.md UX-C1's "either way, write the choice down" — the choice is
  written down here and in `HANDOFF.md`).
- No spec deviations. The 8-case matrix's 8th case (all applied) had no probe
  document anywhere; it was authored for this increment (single in-image
  entry), as the threshold line requires.

## 7 · Suggested next task

Batch-99 Increment 9 (per the increment map, the SOURCE-integrity /
WRITE-OUT-verify increment): the fx lane surfaces and the report sections this
increment added are its declared carriers (PDR-ux.md UX-C2 names Inc 9 for the
SOURCE `error` cause line).

---

## 8 · Review round 1 fixes (code-reviewer F1–F5)

All five findings fixed; every figure below is present in a transcript cited in
the evidence table of this section.

### F1 [HIGH] — the two provenance-census regressions

`tests/test_tui_flow_execution_b94.py` counted every `- Chain ` line as a
provenance line; the new report sections pushed the count from 2 to 8. Re-pins
(the census now filters on the `" input "` form, the `test_flow_chainset_b94.py`
idiom):

- `test_at_b94_20_rebind_run_reads_each_chains_own_inputs` (:596) —
  `- Chain ` prefix count == 2 (over ALL `- Chain` lines) → `startswith("- Chain ")
  and " input " in ln` count == 2 — LLR-156.3.
- `test_at_b94_23_run_log_inline_failure_and_report_provenance` (:816) —
  same filter, count == 2 — LLR-156.3.
- `test_at_b94_24_save_reload_rerun_regenerates_and_notices` (:981) — the
  filter applied for precision (the node asserted `any(...)`, pass/fail
  unchanged) — LLR-156.3.

RED: `red-f1-b94.txt` (AT-B94-20 and AT-B94-23 FAIL, `assert 8 == 2`).
GREEN: `green-f1-b94.txt` (11 passed). Widened census — every test that reads
the chain-set or flow report text (`- Chain` / `## ` headings /
`compose_chain_set_report` / `write_chain_set_report` / report paths):
`test_b99_patch_truth.py`, `test_tui_flow_execution_b94.py`,
`test_flow_chainset_b94.py`, `test_b97_flow_execution.py`,
`test_flow_report_service.py`, `test_flow_report_wire.py`,
`test_changes_symbol_entries.py`, `test_flow_report_ac6_golden.py`,
`test_address_census.py` — one run, `green-full.txt` (**236 passed**, EXIT=0).

### F2 [HIGH] — AT-B99-06/07 made black-box

Both ATs no longer touch `b97_fixtures`' app-internal helpers
(`_handle_load_project`, `action_show_screen`, `Button.press()`, `run.press()`).
New idiom (mirrors `tests/test_b99_s0.py`): the project folder, change
documents and flow templates are written on disk (setup); the project loads
through the Load project dialog (rail key `p`, click the project item in
`#project_list`, `#project_ok`); Flow Execution opens by its rail key (`]`);
each flow imports by clicking `#fx_import`, its `ListItem` in `#flow_list` and
`#flow_load_ok`; the run is `pilot.click("#fx_run")` and the waits observe
PAINTED lane heads (`#fx_lane_<i>_head` marks) — no internal attribute reads.
AT-B99-06 additionally asserts the mix lane's PATCH card paints `notices`
(`#fx_card_1_1 .fx-card-status`, PDR-ux row 97). Stability: 8 consecutive
runs of both ATs, 16/16 passed (`green-at-8x.txt`).

### F3 [MEDIUM] — LLR-156.1 names every non-applied address and refusal code

`_record_error` gained a `detail` parameter (inserted before the note; the
note stays LAST — UX-C2). All three PATCH error arms pass per-entry detail
lines (`0x<ADDR> <disposition>`) and per-refusal lines (`[CODE] message`);
the `notices` arm extends `patch_result.diagnostics` with one
`0x<ADDR> <disposition>` line per non-applied entry. The block summary and
the lane's terminal log line are unchanged (count + first address, UX-C1).
New TC arm `test_tc_b99_17_diagnostics_name_every_non_applied_address`: the
`notices` arm with 3 non-applied entries (2 outside + 1 straddling) names all
3 addresses; the 0-applied error arm names all 3 with the cause last; the
unresolved-symbol arm names `CHG-SYMBOL-UNRESOLVED`. RED first:
`red-f3-arm.txt`.

### F4 [MEDIUM] — PQ-7 painted-arm mutant

The first PQ-7 mutant survived because `Text.append(str)` never parses markup.
Genuine killing mutant: the lane terminal line's failure-detail sink
(`flow_screens.py`) switched to `Text.from_markup(...)` → AT-B99-07 goes RED —
Rich parses the hostile name and render raises
`MissingStyle: '@click app.quit'` (`mut-f4-painted.txt`). Reverted; §5 text
corrected accordingly.

### F5 [LOW]

`test_b99_patch_truth.py`'s `_FX_BLOCK_STYLE` constant-map read (the TC-B99-18
glyph arm) dropped — the painted-cell assertion lives in AT-B99-06; the
mis-annotated `-> Path` helper went away with the F2 rewrite (its replacement
returns the staged path); the now-unused `flow_screens` import removed.

### Registry bump

`tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES` 199 → **205**,
MEASURED (`scanned_test_files()` reports 205 with the new module; 204 already
at `c62c842` — five earlier batch-99 modules were never bumped on this base).
`green-id-registry.txt` (13 passed).

### Mutation re-runs (5/5 KILLED, all reverted)

| Mutant | Targeted node | Verdict | Transcript |
|---|---|---|---|
| LLR-156.1 — applied-0 arm disabled | `outside`, `straddle`, UX-C2 cause | KILLED (3 failed) | `mut-LLR-156.1.txt` |
| LLR-156.2 — `refusals=` outcome copy dropped | `test_tc_b99_18_chain_outcome_carries_refusals` | KILLED | `mut-LLR-156.2.txt` |
| LLR-156.4 — Not-applied section made conditional | `test_tc_b99_20_flow_report_lists_what_was_not_applied` | KILLED | `mut-LLR-156.4.txt` |
| PQ-7 — `md_safe` removed from the Refusals cell | AT-B99-07 | KILLED | `mut-PQ7.txt` |
| PQ-7 painted (F4) — `Text.from_markup` at the lane terminal sink | AT-B99-07 | KILLED | `mut-f4-painted.txt` |

### Evidence files (review round 1)

| Transcript | Content | SHA-256 |
|---|---|---|
| `red-f1-b94.txt` | F1 RED: AT-B94-20/23 `assert 8 == 2` | `e49ab909…` |
| `green-f1-b94.txt` | re-pinned file, 11 passed | `58d231fb…` |
| `red-f3-arm.txt` | F3 RED: diagnostics `[]` | `44022054…` |
| `green-full.txt` | widened census run, **236 passed**, EXIT=0 | `87d6b4c5…` |
| `green-at-8x.txt` | AT-B99-06/07 × 8, 16/16 passed | `1356277d…` |
| `green-id-registry.txt` | registry guard, 13 passed | `a8fb35ca…` |
| `mut-LLR-156.1.txt` | 3 failed / 15 deselected | `e715d2ce…` |
| `mut-LLR-156.2.txt` | 1 failed | `7c66d66c…` |
| `mut-LLR-156.4.txt` | 1 failed | `a7d21bb9…` |
| `mut-PQ7.txt` | 1 failed | `7289ac28…` |
| `mut-f4-painted.txt` | 1 failed (MissingStyle) | `f9f6c970…` |

---

## 9 · Review round 2 fix (N1)

**Finding (round 2, MEDIUM):** a PATCH block with `notices` painted red in Flow
Builder. The notices arm put its not-applied lines in `diagnostics`
(`flow_execution_service.py`), and Flow Builder paints block diagnostics as
`sev-error` (`flow_screens.py` render path).

**Fix:** the `notices` PATCH arm now puts its not-applied lines in `findings`
as `FINDING_WARN` — the funnel arm's existing idiom (same block, 30 lines
below). `diagnostics` stays the `error` arm's channel, whose cause stays LAST
(UX-C2). One SOURCE file touched: `s19_app/tui/services/flow_execution_service.py`
(the `if non_applied:` body + its comment). No report reader needed a change:
the chain-set report enumerates non-applied entries and refusals from
`ChainRunOutcome.change_records` / `.refusals` (LLR-156.3), the Flow Execution
lane log line reads the change records (UX-C1), and the flow / fused reports
already render BOTH `br.findings` and `br.diagnostics` into their Findings
sections — so LLR-156.3/156.4 and UX-C1 outputs are byte-for-byte unchanged
(proven by the unchanged GREEN runs of `test_tui_flow_execution_b94.py`,
`test_flow_chainset_b94.py` and the Flow Builder suites below).

**Test arm added (sub-node of TC-B99-17):**
`test_tc_b99_17_notices_lines_paint_warning` — service-side every not-applied
line is a `FINDING_WARN` finding with `diagnostics` left empty, the `error`
arm keeps its census + cause LAST in `diagnostics`; painted through Flow
Builder (real `#flow_run`), the PATCH node's lines carry the `sev-warning`
severity class and no `sev-error` line exists.

**Re-pin (recorded per trigger B1):**
`test_b99_patch_truth.py::test_tc_b99_17_diagnostics_name_every_non_applied_address` —
notices-arm needles read from `patch.diagnostics` → read from
`patch.findings` messages (+ `diagnostics == []` + `FINDING_WARN` severities) —
N1 (a notices arm is a warning, not an error). The same test's `error`-arm
assertions are unchanged.

| Transcript | Content | SHA-256 |
|---|---|---|
| `red-n1-notices-lines.txt` | N1 baseline RED on the unmodified tree: both arms FAILED (2 failed, 17 deselected) | `36d45eec…` |
| `green-n1-patch-truth.txt` | full file after the fix: **19 passed** (18 round-1 nodes + the new N1 arm) | `ca3a9802…` |
| `green-n1-affected.txt` | required suites — `test_tui_flow_execution_b94.py` + `test_flow_chainset_b94.py` + the Flow Builder files of the `sev-error\|FINDING_WARN` census (`test_b97_flow_builder.py`, `test_flow_builder_render.py`) + `test_address_census.py`: **122 passed**, EXIT=0 | `a616d019…` |
| `mut-N1.txt` | N1 mutant (lines back in `diagnostics`) KILLED — both arms FAILED (2 failed, 17 deselected); restore proven by SHA-256 `fbdbc0bf…` | `91b2f6be…` |

Signed-balance ledger update: `19 = 18 − 0 + 1` ✓ (one node added to
`tests/test_b99_patch_truth.py`; one value re-pin inside an existing node; no
deletions). No new test module — `EXPECTED_SCANNED_TEST_FILES` unchanged.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 SOURCE files (`git status` — the three named files only) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_patch_truth.py` (18 nodes after review round 1, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — the four LLRs are integration/unit-over-services, verified by TC-B99-17..20 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED + 4 mutations with transcripts and SHA-256 restores |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, 1 golden rebaseline (C-24), 7 nodes re-pinned, affected suite 362 passed |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — the 3 SOURCE files + 4 test artifacts + `.dev-flow/**` only |
| 8 | Frozen interfaces untouched | all | ✓ | additive defaulted dataclass fields only; the five UX-C3a maps are byte-identical in the diff |
| 9 | Coverage claims verified **on disk** | all | ✓ | AT-06/07 drive the real panel and read real files; TC-17/18/19/20 read the reports the run wrote, and images via the independent reader |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (the `good.json` CLEAN control, the mix WRITE-OUT control, the PQ-7 mutant) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED; the survived-first-attempt PQ-7 mutant re-aimed and KILLED |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 6 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 1 population, enumerated before the first SOURCE edit; 4 re-pins + 1 golden, each recorded |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: flow report, chain-set report and WRITE-OUT images asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` |
| 16 | **Evidence files** declared | all | ✓ | §4: 11 artifacts with stored-byte SHA-256 digests (`SHA256SUMS.txt`) |
