# Inc 8 — E3 rulings, round 1 (and E4 addenda)

Reviews: `E3-architect.md` (FAIL: A-1, A-2 MAJOR; A-3 … A-8 MINOR) and `E3-security.md` (FAIL: S-1, S-2 MAJOR; S-3 … S-8 MINOR), both on records `5aac5c9`. Upheld by both reviews: the CRC model (D13-20, verified independently 300/300), the Designer-template refusal (D-1) and the rebind decision D-2 over rotate / overwrite.
Rulings: the orchestrator's, relayed 2026-11-02. Corrective pass: E1/E2 agent (architect role, Opus), targeted edits to `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `codewire/graph-inc8.md`; no code, no tests. Changed lines carry the finding id in brackets.
Re-review scope (independent): **A-1, A-2, S-1, S-2 only.**

## 1. Slice after the round

**4 source files — at the cap.** `flow_model.py` joins (`FlowRunResult.in_place_reads`, needed so the chain-set report can name the copy, S-2); no other increment of the plan owns it. No ruling pushed the slice past 4. `workspace.py` and `variant_execution_service.py` stay untouched.

## 2. Findings ruled and corrected (MAJOR)

| Id | Ruling | What changed in the records |
|---|---|---|
| **A-1** (+ S-2) report integrity: the A2L read in place is still named by its typed ref | Every block that reads a copy in place names the copy in its summary and in every record or report that names that input | **R-FLOW-EXT.10 widened** to "change document ref **or effective A2L ref**" (the PATCH's own, or the LOAD's it inherits); cases R-FLOW-EXT.10/4 (flow report A2L cell `cal_1.a2l`) and /5 (inherited A2L). **New R-FLOW-EXT.12**: the block's summary ends with the read suffix ` · read <copy file name> in place of <ref>`, once per in-place ref in read order — PATCH, CHECK, CRC, LOAD, A2B, error summaries (cases R-FLOW-EXT.12/1 … /8). Graph: I-4 widened to `a2l_ref`, new I-7 (suffix), `run_flow` steps (3) and (6) |
| **S-2** (+ A-1) the rebind is invisible for CHECK, CRC, A2L and the chain-set inputs | as A-1; in addition the chain-set report's Input provenance names the copy | **New R-FLOW-EXT.13**: a rebound LOAD input's provenance line gives the copy's path and the read suffix (cases R-FLOW-EXT.13/1, /2). Slice: `run_chain_set._run_one` corrects the rebound entries after the run; `ChainRunOutcome.in_place_inputs` (new field, `inputs` keeps its 2-tuples that tests unpack); `compose_chain_set_report` appends the suffix; `FlowRunResult.in_place_reads` (new field, `flow_model.py`). Graph: I-6, nodes `run_chain_set`, `compose_chain_set_report`, entities `[Data: FlowRunResult.in_place_reads]`, `[Data: ChainRunOutcome.in_place_inputs]`, `[Interface: block summary]`, `[Interface: chain-set Input provenance]`. The summary text change this needs is ruled in (it was "unchanged" at E1) |
| **A-2** (+ S-2) the rebind also changes a first run, by name only | Admit it in the records; the read suffix makes it visible | Definition *In place of* states that the rebind depends on the name only, including a first run into a folder that already holds a different file under the output file name. **R-FLOW-EXT.9** Base column and threshold admit it; new case **R-FLOW-EXT.9/13** (a foreign `step.changes.json` with Doc(`CC`), first run Doc(`AA`), copy `_1`, PATCH summary with the read suffix, `out.s19` `S1071000414103045F`; base `S1071000434303045B`). The exact suffix text is in the *Read suffix* definition and R-FLOW-EXT.12. "What changes for an operator (F-49 …)" section added to `01-requirements.md`. The suffix appears exactly when the copy is another file than the ref names (so `./step.changes.json` resolving to the copy itself gets none) |
| **S-1** `<value>` echoed without a bound (regression from CPython's 200-character clip) | Clip at 64 characters with `…` | Definition `<value>`: the first 64 characters of the JSON text, then `…` (U+2026) when it is longer. R-CRC-CONFIG-001.11 threshold and negative control (remove the clip → RED); new case **R-CRC-CONFIG-001.11/7** (1 MB string, 10 000-element list; each reason ≤ fixed text + 65 characters). Graph: `_number_field` (`VALUE_CLIP = 64`), I-2 |

## 3. Findings ruled and corrected (MINOR, done in this pass)

| Id | Ruling | What changed |
|---|---|---|
| A-8 | "Run" = one chain | Definition *Run* (one `run_flow`, one chain; no rebind across chains, F-48 open); case **R-FLOW-EXT.9/14** (a later chain names an earlier chain's output: no rebind, no suffix) |
| S-3 | Refuse a relative path that climbs above the project | **New R-FLOW-EXT.14**: summary `external step refused`, cause `<log or output> '<path as given>' climbs above the project folder - give an absolute path for a file outside the project`; checked by text (normalised join), the log (climb, existence) before the output (climb, existence). Cases R-FLOW-EXT.14/1 … /3. D-5 marked superseded in `E1-rulings.md` |
| S-4 | The copy passes the same per-read link check | `_resolve_block_ref`: the typed ref is guarded first, and a found copy is passed through `_resolve_manifest_entry(project_dir, copy.name, …)`. New case **R-FLOW-EXT.9/15** (the orchestrator's "9/13-bis"; numbered /15 so case ids stay numeric): an absolute ref and a junction ref naming the output file stay refused after a rebind; mutant "rebind lookup before the guard" → RED |
| S-5 | Fold the size-bounded read into the Flow CRC block | `run_flow` CRC branch reads through `read_crc_config_text` (256 MiB limit); **new R-FLOW-CRC.9** (exact summary and cause) and case R-FLOW-CRC.9/1 (cap lowered by monkeypatch). The decode-error half stays in BL-I8-5 |
| S-6 | Catch `RecursionError` in the JSON read | `parse_crc_config` now changed; **new R-CRC-CONFIG-001.17** (`CRC config is not valid JSON: nesting too deep`); cases /1 (parse) and /2 (Operations Execute survives, AT) |
| S-7 | Pin `"[/]"` | Case **R-CRC-CONFIG-001.11/8** through the Operations dialog: exact plain-text reason, no markup error |
| S-8 | Release note is a tracked batch-end deliverable | `release-note-crc.md` written (detection rule and exact migration) |

## 4. E4 addenda (MINOR, for the implementers and testers)

- **A-3** — R-CRC-ENGINE-001.1/5 asserts only `computed_crc` from `check_regions` (the region line belongs to `screens.py`); /6 uses the Operations write route `write_crc_image` and reads the written file back. Both cases are edited accordingly in `02-test-cases.md`.
- **A-4** — R-CRC-CONFIG-001.11 brings only the reasons to the row: the string grammar of `_parse_int` stays lenient (`" 10 "`, `"+10"`, `"1_0"`, `"0x_1"`, `"-1"`). Recorded on the row; backlog **BL-I8-6** (D13-21/22/24 family). Do not widen this increment.
- **A-5** — known limit under D-1: the Designer template shape also matches the evolved CRC job shape (`algorithm` + `targets`, `crc_designer_model.emit_job`), for which "it has no regions or groups" is misleading; an `algorithm_ref` job falls to `field 'reverse' is missing`. Not reachable today (`emit_job` / `parse_job` have no product caller). No row change.
- **A-6** — C-5 in `E1-rulings.md`: the canon edit C-2 also corrects "rule texts — The <rule text> of R-CRC-CONFIG-001.10" to **.9**.
- **A-7** — BL-I8-3 extended with `docs/user-guide/ch17-flow-builder.md:62` and `docs/user-guide/DOSSIER.md:737`, `:758`.
- **Suffix mechanism** (E4 note for G2): the read suffix must be applied once per block whatever path the branch leaves by (normal end, `continue`, the per-block `except Exception`); a `try/finally` around the branch body or a step at the top of the next iteration plus one after the loop are both fine. The suffix reads `result.in_place_reads` for that block index only.
- **Order of checks** (G2): in the external-step branch, log climb → log exists → output climb → output exists → copy.

## 5. Counts after the round

- Rows: **18** (17 + R-CRC-DESIGNER-001.1 cited). New this round: R-CRC-CONFIG-001.17, R-FLOW-CRC.9, R-FLOW-EXT.12, R-FLOW-EXT.13, R-FLOW-EXT.14. Widened: R-FLOW-EXT.10 (A2L). Records-only changes: R-CRC-CONFIG-001.11 (threshold, residual), R-FLOW-EXT.9 (threshold, Base).
- Cases: **82** (+23): 3 covered, 1 partial, 78 gap, all `not_run`.
- Graph: 16 nodes (12 changed or new), 9 entities, 12 edges; lint 0 lines not read.
- New canon ids for the requirements session (all rounds): R-CRC-ENGINE-002.2, R-CRC-CONFIG-001.16, R-CRC-CONFIG-001.17, R-FLOW-CRC.9, R-FLOW-EXT.9, .10, .11, .12, .13, .14. Changed wording: R-FLOW-CRC.1, .3, .4. CTX additions: C-2 … C-5.

## 6. Interfaces after the round

- **Inc 9** (works after Inc 8 in `flow_execution_service.py`): Inc 8 now also changes `run_chain_set._run_one`, `ChainRunOutcome` (field `in_place_inputs`) and `compose_chain_set_report` (Input provenance). Inc 9 must keep both new fields and the suffix when it edits `run_chain_set` / `write_chain_set_report`. `change_doc_ref` and `a2l_ref` values change for rebound PATCH refs (I-4).
- **Inc 7**: `diff_report_service.py` prints `change_doc_ref` (value only, escaped as before).
- Every surface that paints a block summary gains the read suffix only on an in-place read (I-7); no existing test run reads a copy in place (architect E3 §4).

## Round 2 (2026-11-02)

Re-review (E3-r2.md): PASS-WITH-NOTES — A-1, A-2, S-1, S-2 closed. Rulings on the new MINORs (E4 addenda, binding):
- N-1: case R-CRC-CONFIG-001.11/7(a) uses a non-hex string, `z` × 1 000 000, expecting `"` + 63 × `z` + `…`; graph :106 corrected the same way.
- N-2: option (c), no 5th source file: when a block's summary ends with a refusal/status token that a consumer matches by suffix (e.g. `unresolved`, read by flow_screens._failure_detail), the read suffix ` · read <copy> in place of <ref>` is inserted BEFORE that final token, so the token stays last; R-FLOW-EXT.12's text states the placement; new case 12/10 (an in-place read followed by a junction-refused A2L keeps `[MANIFEST-PATH-ESCAPE]` in the lane line).
- N-3: the new dataclass fields use `field(default_factory=list|dict)`.
- N-4: the suffix's `finally` wraps the per-block `except`, so error results carry it; new case 12/9 (apply_change_document raises after an in-place read).
