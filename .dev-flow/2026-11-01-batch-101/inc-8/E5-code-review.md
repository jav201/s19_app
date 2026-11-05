# Inc 8 — E5 code review

Batch 2026-11-01-batch-101, increment 8, stage E5 (independent code review). Reviewer: `code-reviewer` (Opus), not an author of the code, the tests or the design.
Scope: `git diff main...HEAD -- s19_app tests` at `e455a07` (branch `b101-inc8`): `s19_app/tui/operations/crc.py`, `crc_config.py`, `s19_app/tui/services/flow_execution_service.py`, `flow_model.py`, `tests/test_b101_crc_model_and_reasons.py`, `tests/test_b101_flow_ext_copy.py`, `tests/test_id_registry.py`. Read against `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `codewire/graph-inc8.md`, `E3-rulings.md` (rounds 1, 2 and the E4 addenda), `E4-impl-notes.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `release-note-crc.md`.

## Verdict

**FAIL — BLOCK-UNTIL: F1, F2.**

The CRC model fix, the named-field reasons, the template refusal, the rebind, the read suffix, the report and provenance naming and the climb refusal follow the approved graph. Two defects remain:
- **F1** is a regression that this diff introduces. A config whose number field holds a deeply nested list now crashes the Operations dialog.
- **F2** puts the external-step checks in an order that differs from the canon row R-FLOW-EXT.14 and from the E4 addendum. `E4-impl-notes.md` says the order matches, but it does not.

The other findings do not block. Both blocking fixes are small. They are discharged only when this reviewer re-reads the corrected diff and the new tests that pin them.

## Findings

| Id | Tag | Severity | Where | Finding | Failure scenario | Suggested fix |
|---|---|---|---|---|---|---|
| F1 | impl | MAJOR (blocking) | `s19_app/tui/operations/crc_config.py:99` (`_number_field`), `:510` (`parse_crc_config` catches only `KeyError, TypeError, ValueError`) | `_number_field` serialises the rejected value in full with `json.dumps(raw)` before clipping it. The value has already been parsed by `json.loads` at a shallower stack depth. Serialising it runs deeper, so a value that nests just under the limit parses and then fails to encode. The `RecursionError` is raised inside the `except ValueError` handler and escapes `parse_crc_config`, which breaks its "never raises" contract. On base, `_parse_int` raised `ValueError("expected an int or hex string, got list")` and no serialisation was done, so this is a regression. | Probed. (a) Called directly (py3.11): Config V with `"init"` = a list nested 993 deep → `parse_crc_config` raises `RecursionError`. (b) In the Operations dialog, through keys: editor text with `"init"` nested 976 deep, then Execute → `RecursionError: maximum recursion depth exceeded while encoding a JSON object`, and the app exits with return code 1. The depths 700–973 gave the correct `is not a number` reason. In a flow, the same config makes the CRC block's per-block `except` give summary `error`, not R-FLOW-CRC.4's `config malformed`. This breaks R-CRC-CONFIG-001.11 (no reason is given) and reopens the crash class that R-CRC-CONFIG-001.17/2 pins ("the app still running"). | Bound the serialisation so it cannot raise. For example: `try: text = json.dumps(raw)` / `except RecursionError: text = "[" * (VALUE_CLIP + 1) if isinstance(raw, list) else "{" * (VALUE_CLIP + 1)`. The clip then cuts it to 64 characters plus `…`, which is the exact first 64 characters of the real JSON text, because every character of a structure nested that deep is an opening bracket. Alternatively, add `RecursionError` to `parse_crc_config`'s structural catch and map it to the R-CRC-CONFIG-001.17 reason. That choice changes the reason text, so E1 must rule on it. Add a test for each surface: `parse_crc_config` with a 990-deep `init`, and the Operations Execute with the same text, checking that the app is still running. |
| F2 | impl | MINOR (blocking: a canon threshold is not met, and the record says it is) | `s19_app/tui/services/flow_execution_service.py:1163-1205` | The order is log climb → **output climb** → log exists → output exists. R-FLOW-EXT.14 threshold: "The log is checked (climb, then existence) before the output (climb, then existence)". The E3 addendum *Order of checks (G2)* says the same. `E4-impl-notes.md` §4 says the code follows that order. It does not. | Probed. Log `missing.log` (relative, inside the project, absent) and output `../../x.json`. Canon cause: `log 'missing.log' does not exist - the log is mandatory evidence, never optional`. Tree cause: `output '../../x.json' climbs above the project folder - …`. The step is refused either way, but the operator gets a different reason from the one the row fixes. | Move the `if not log_path.is_file()` check up, so it runs before the `source_path` join and the output climb check. Correct `E4-impl-notes.md` §4. Add a case to R-FLOW-EXT.14 (log missing + output climbing → the log cause) to pin the order. No current test tells the two orders apart. |
| F3 | design-gap | MINOR | `tests/test_b101_flow_ext_copy.py:767-846` (9/15 b), `:1239-1276` (12/10); SR-4 | Under SR-4, arm (b) and case 12/10 now use a junction to a folder **outside** the project. The guard has always refused that, on base too, so arm (b) no longer tests the rebind at all. Only arm (a) kills the negative control "rebind lookup before the guard". The original premise was false at E2: the graph example `jl` → `<proj>` was never probed. Behind it sits a pre-existing guard gap. `_resolve_manifest_entry` does not refuse a junction back into the project, although its docstring says a link below the project root is refused. On the tree, such a ref now reads the copy in place. The read suffix shows it, so nothing is hidden. | A ref `jl/step.changes.json` with `jl` → `<proj>` passes the guard and reads `step.changes_1.json` in place, with the suffix. That is visible and does not escape, but no test pins it. | Security reviewer: rule on the guard (D15-18 family, outside this slice). Records: correct 9/15(b) and the graph example as the integrator lists (§6.7). Pin the junction-back-inside arm as it behaves today: in place with the suffix. |
| F4 | design-gap | MINOR | `flow_execution_service.py:1373-1389` (`_apply_block_read_suffixes`); `01-requirements.md` R-FLOW-EXT.12; `tests/test_b101_flow_ext_copy.py:1270-1275` | Under ruling N-2, the suffix goes before a trailing `unresolved`. The operator then reads `a2l reference · read step.changes_1.json in place of step.changes.json unresolved`, and the head and the token are split by the suffix. The row text still says "end that block's summary with the read suffix" (integrator §6.3, not yet corrected). Test 12/10 checks only `endswith("unresolved")` and that the suffix appears somewhere, not the exact summary. | A mutant that puts the suffix in another place before the token, for example at the very start, still passes 12/10. | Records: state the placement in the R-FLOW-EXT.12 row. Test: assert the exact summary string. |
| F5 | impl | NIT | `flow_execution_service.py:317-505`, `:779-790`, `:848-863`, `:1008-1019` | The seven call sites each repeat `if <x>_in_place: result.in_place_reads.append((index, label, ref, path))`. `_resolve_block_ref` already receives the label and the ref, so it could take `result` and `index` and append the entry itself. | No defect. A later block kind that forgets the append would show no suffix and no provenance. | Optional. Fold the append into `_resolve_block_ref`. |
| F6 | impl | NIT | `crc_config.py:99` | `json.dumps` keeps `ensure_ascii=True`, so a non-ASCII value is echoed as `\uXXXX` escapes (`"é"` → `"é"`). The clip can also cut an escape sequence in half. The *`<value>`* definition does not say which form is meant. | `{"init": "é"}` → `… is not a number: "é"`. | Leave as is, or define it in the records. No action is needed for this increment. |
| F7 | impl | NIT | `flow_execution_service.py:536-538` | `effective_a2l_ref = (block.a2l_ref or source_a2l_ref) if not override_in_place else override_path.name` is correct but hard to read. | — | `effective_a2l_ref = override_path.name if override_in_place else (block.a2l_ref or source_a2l_ref)`. |

## Conformance to the graph (check 1)

Each node was checked against its graph `func:` and examples:
- `crc32_stream`: matches the graph. One line changes; the zlib fast path is unchanged and the docstring is updated. The oracle was checked independently with a right-shift model implementation (scratch, not in the repo): KAT, poly 0x04C11DB7, init 0x12345678, reverse, xorout 0xFFFFFFFF → 0x0F8B7431. The release note's migration init 0x12345678 → 0x1E6A2C48 is the exact 32-bit reversal. No other place in `s19_app` reflects an init or compensates for the old behaviour (grep).
- `_required_field` and `_build_group` match the graph.
- `_number_field` matches the graph's text. F1 is a fault the graph did not foresee: it is the full `json.dumps` the graph itself prescribes.
- `_build_config` matches the graph. The template check runs first, and the condition is `"algorithm" in data and "polynomial" not in data`.
- `parse_crc_config` (`RecursionError` → the .17 reason) matches the graph.
- `run_flow` (1)–(6), `_resolve_block_ref` (guard first, then the copy re-checked through `copy.name`), `run_chain_set._run_one`, `compose_chain_set_report`, `FlowRunResult.in_place_reads` and `ChainRunOutcome.in_place_inputs` (`default_factory`, N-3) match the graph, except the check order in F2.
- The rebind key (`copied.parent / Path(source_path).resolve().name`) and the lookup key (`_resolve_manifest_entry` resolves the path) are both resolved, so the two sides compare like for like. The placement resolves its destination (`workspace.py:1189`).
- One consumer reads block summaries by suffix: `flow_screens._failure_detail`, `endswith("unresolved")` (grep over `s19_app`). `_SUFFIX_GUARDED_TOKENS` covers it.

## Seam rulings (check 5)

| SR | Consistent with canon? | Note |
|---|---|---|
| SR-1 | Yes: R-FLOW-CRC.7 (CRC before PATCH → `notices`) is canon and unchanged | The test pins the exact finding, the run status and the model bytes. Nothing is weakened. |
| SR-2 | Yes: R-TUI-006.2 numbered placement | `_written_image` reads the name from the run's own WRITE-OUT summary. A stale image would have the old bytes, so the byte assertions still fail on the defect. |
| SR-3 | Yes: the drift refusal (CHG-SYMBOL-VALUE) is canon | 9/12, 10/4 and 10/5 now tell the copy from the stale file by A2L agreement, not by the A2L supplying the address. Base reads the stale A2L, refuses with drift and writes no record, so the test is RED. That is still discriminating. |
| SR-4 | Consistent, but it **hides a pre-existing guard gap** | See F3. Security reviewer to rule. |
| SR-5 | Yes: report cells use the shipped `md_safe`, and the records hold the raw name | Exact escaped text is asserted. |
| SR-6 | Yes: `<stem>_<n><last suffix>` | — |

## Tests (check 4)

- Each test of the two new files asserts the exact expected text or value: reasons, summaries, causes, the I-6 tuple, record fields and image bytes. The exception is 12/10 (F4). Each would fail if the behaviour broke. The CRC grid and random tests compare against the Designer engine, which the six catalogue checks pin independently.
- Integration fixes, a sample of 10 of the 22: 001.1/7 (SR-1), 9/1 (I-6 tuple), 9/5 run 1, 9/9 (tuples), 9/11 (dwell; image from `last_outputs`, loop guarded by `name != terminal_out.s19`), 9/12, 10/4 and 10/5 (SR-3), 10/1 and 10/2 (SR-5), 12/6 (SR-6), 12/7 (keys 0 and 2). I diffed the `assert` lines between `499d15d` and `e455a07`. No assertion was loosened. Two were replaced by stricter ones: the run status `ok` became `notices` plus the exact finding, and the attribute probe became the exact tuple. One run-level `first.status == "ok"` (9/5 run 1) was replaced by block-level checks, which agrees with SR-1. **The integrator's statement "no assertion was weakened" holds for the sample.**
- Gaps: no test for F1, and none pins the F2 order.

## What I ran

All runs on win32 with the `s19env` interpreter (Python 3.11.15). Environment: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, `LOCALAPPDATA` redirected under a temp folder, `--basetemp` under a temp folder, `-p no:cacheprovider`. `s19_app.__file__` was printed first and named the worktree's `s19_app/__init__.py`.

| Run | Result |
|---|---|
| `tests/test_b101_crc_model_and_reasons.py tests/test_b101_flow_ext_copy.py` | 82 passed |
| `tests/test_id_registry.py tests/test_crc_config.py tests/test_crc_engine.py tests/test_flow_crc_block.py tests/test_flow_external_step_b96.py tests/test_flow_chainset_b94.py` | 95 passed |
| Probe F1 (direct): `parse_crc_config` with Config V and a nested `init`, depth 100 upward | raises `RecursionError` at depth 993 |
| Probe F1 (Operations dialog, Textual pilot, through the Execute button): nested `init`, depths 700–999 in steps of 3 | reason shown up to depth 973; at 976 the app exits (return code 1) with the `RecursionError` |
| Probe F2: log `missing.log` and output `../../x.json` | cause `output '../../x.json' climbs above …`, where canon gives the log cause |
| Independent CRC oracle (right-shift model, no repository code) | 0x0F8B7431, 0xCBF43926; reversal of 0x12345678 = 0x1E6A2C48 |

The probes ran from the session scratchpad and touched no file of the worktree. I did not run the full suite or the mutants (the mutants belong to the parallel E5 mutant run), and I did not touch the parallel reviewers' files.

## Evidence states

F1: `executed`, probed and reproduced. F2: `executed`, probed. F3–F7: `executed`, by reading. Fixes for F1 and F2: `not-run`. They are owed, and they are verified by re-reading the corrected diff.

## Re-review (2026-11-05)

Scope: F1 and F2 only (`E5-rulings.md` C-1, C-2), on `git diff e455a07..HEAD -- s19_app` (head includes `a27b9ee`) and the tests for cases R-CRC-CONFIG-001.11/9, 001.11/10, R-FLOW-EXT.14/4, 14/5. Read against `E5-corrective-notes.md` §2 (C-1, C-2).

### Verdict

**PASS — F1 and F2 discharged.** No new finding from the fixes. Two notes, neither blocking.

| Id | Verdict | Evidence state |
|---|---|---|
| F1 | PASS | `executed` (diff re-read, probes, RED on the old code, GREEN on head) |
| F2 | PASS | `executed` (diff re-read, RED on the old order, GREEN on head) |

### F1 — `_number_field` / `_clipped_json`

- **It cannot raise for any value `json.loads` returns.** `_clipped_json` encodes with `JSONEncoder().iterencode` and returns once the text is longer than 64 characters. The pure-Python encoder yields `[`, `{` or the key before it goes down a level, so it never goes deeper than about 65 levels, whatever the value's depth. `json.loads` output has no cycles, and `allow_nan` is on, so neither `ValueError` path of the encoder can be reached. The `except ValueError` in `_number_field` is unchanged, and `parse_crc_config` still collects the reason.
- **Probes** (scratch, py3.11 `s19env`, no file of the worktree touched):
  - Six number fields of Config V (`polynomial`, `init`, `final_xor`, region `start`, `end`, `output_address`). Values: a nested list, a nested object and a list with a leading scalar. Depths 60–69 and 850–1000. Caller stack depths 0, 200, 600, 850, 900 and 920. **0 exceptions escaped.** Each run gave either the 001.11 reason or the 001.17 reason.
  - **Headroom.** With a deep `init`, the first raise comes at caller stack depth 997. A valid Config V also raises from depth 997. The echo therefore adds no stack exposure beyond what the parser already has.
  - **Deep values.** Lists, objects and leading-scalar lists at depths 63, 64, 65, 66, 100, 5 000 and 100 000 all return text of at most 65 characters. Where `json.dumps` can still compare (depth up to 300), the text equals `json.dumps(v)[:64] + "…"`.
  - **Huge flat values.** A list of 5 000 000 items and a dict of 1 000 000 keys take about 0 s. A 20 000 000-character string takes 0.03 s, because it arrives as one chunk. Each result is 65 characters.
- **Echo is exact.** 25 values were compared with the old formula and none differed. They included strings, `true`/`false`/`null`, floats, `Infinity`, `NaN`, `-0.0`, a 4 000-digit int, control characters, `"é"`, a lone surrogate, CJK text, a long key, nested objects, `[[[]]]` and `[0, [[[[1]]]]]`. `JSONEncoder()` has the same defaults as `json.dumps` (separators, `ensure_ascii`, `sort_keys`), so the `<value>` is the first 64 characters of the JSON text.
- **The message text is unchanged:** `field '<key>' is not a number: <value>`.
- **The dialog path is fixed.** On head, 001.11/10 (keys only: `x`, the typed path, Load config, Execute) bisects to the reader's limit inside the handler and the app stays up. On the old `crc_config.py`, 001.11/9 and 001.11/10 fail with `RecursionError … while encoding a JSON object`. 001.11/10 dies with `NoMatches #operation_result_status`, which means the app exited.
- **The corrective used a different means from the ruling, and the change is accepted.** The ruling's "catch and echo a fixed form" was my own F1 suggestion. That fixed form is the exact `<value>` only for a list whose first item nests. For an object (`{"a": {"a": …`) or a list with a leading scalar (`[0, [0, …`) it is not, so it would break S-1. The lazy encoder gives the exact prefix for every shape. It also removes the raise instead of catching it after the fact. It is simpler and more correct than the suggestion. The deviation is recorded with its reason (corrective notes §2, C-1).

### F2 — external-step check order

- `flow_execution_service.py` (external branch of `run_flow`) now checks in this order: log climb → log exists → output join and climb → output exists → copy. That matches R-FLOW-EXT.14 and the E3 addendum. The moved block is unchanged apart from its position.
- **The order is pinned.** 14/5 uses `missing.log`, relative, inside the project and absent, with output `../../x.json`. It asserts the log's existence cause exactly. On the old order it fails (`"output '../../x.json' climbs above …" != "log 'missing.log' does not exist …"`). 14/4 (both paths climb) passes on either order, as the corrective notes say. It is kept as the audit's owed case and does not pin the order.

### Notes (not blocking)

- **N-R1 (LOW, records).** `codewire/graph-inc8.md`, node `_number_field`, still prescribes a whole `json.dumps`. It now disagrees with the code. This is already listed in corrective notes §6 for the graph session.
- **N-R2 (NIT, test).** 001.11/9 relies on the reader's limit falling inside depths 800–1000 at the test's stack depth. It does on win32/py3.11, where the limit is about 993. A runner that adds about 200 frames would make the `seen` assertion fail loudly, not pass vacuously, so no action is needed.

### What I ran

Environment: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=.`, `LOCALAPPDATA` redirected under a temp folder, `--basetemp` under a temp folder, `-p no:cacheprovider`. `s19_app.__file__` was checked first in each tree.

| Run | Result |
|---|---|
| Head: `tests/test_b101_crc_model_and_reasons.py tests/test_b101_flow_ext_copy.py tests/test_crc_config.py` | 132 passed |
| Scratch export of head with `crc_config.py` and `flow_execution_service.py` from `e455a07`: 001.11/9, 001.11/10, 14/4, 14/5 | 3 failed (001.11/9 and 001.11/10 `RecursionError`, 14/5 on the cause), 14/4 passed |
| F1 probes (equivalence, huge values, deep values, field × shape × depth × caller-depth sweep, headroom) | as above, 0 escapes |
