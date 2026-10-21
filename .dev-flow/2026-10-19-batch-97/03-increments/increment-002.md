# Increment 002 — HLR-146 / HLR-147 · `Flow foundations: NUL refusal, English service strings, role tokens`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-002.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `002` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-146 / LLR-146.14, LLR-146.6 (token half)` · `HLR-147 / LLR-147.5 (service scope, 11 strings)` |
| Acceptance | AT: none owned at Inc-2 (AT-B97-08 NUL arm → Inc-5, AT-B97-23 `nul_bind` → Inc-6) · unit (layer 0) `TC-B97-62` (15 arms + 3 Code-Wire arms), `TC-B97-18` token arm, `TC-B97-25` service arm |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-20` |
| Design refs | `PDR-2026-10-19-batch-97#I6` (PC-17 fold in I-6), `#D11` / I-5, D18; Code-Wire H-N1/H-N2/H-N3 (`design/codewire/graph-nul-refusal.md`) |

---

## 1 · What changed

A NUL character in any ref of a flow file, a chain-set file, a project manifest or a bound lane input is now refused with a finding, never raised. The Flow Execution service writes its run summaries in English. The two flow role colours exist as tokens, ready for Inc-5/6 to paint.

- **NUL refusal (LLR-146.14, PC-17 placement):** a NUL is a path-shape pre-reject, like the shipped drive-relative one, placed before the shared guard and before any field-specific shape check.
  - `dict_to_flow`: `image_ref`, `change_doc_ref`, `check_doc_ref`, `config_ref`, `output_name`, and the optional `a2l_ref` → `FLOW-UNSAFE-REF`.
  - `_parse_a2b_entry`: each binding `ref` → `FLOW-UNSAFE-REF`.
  - `_parse_external_step_entry`: `log_ref` and `output_path` → `FLOW-UNSAFE-REF`. Both were accepted on `main`.
  - `dict_to_chain_set`: the template (through `_is_plain_template_stem`) and each input ref → `CHAIN-SET-UNSAFE-REF`.
  - `_resolve_manifest_entry`: every other caller → `MANIFEST-PATH-ESCAPE`. That covers manifest entries, `run_flow` read refs, `_chain_inputs` and a bound lane input (P-50).
  - The `stat()` guards of `load_flow_json` / `load_chain_set` catch `(OSError, ValueError)` → `FLOW-JSON-PARSE` / `CHAIN-SET-JSON-PARSE` (the carried S2-2).
- **English service strings (LLR-147.5 service scope):** the 11 `ES_48_9C7BEAF` values of `flow_execution_service.py` are rewritten:
  - the pause summary → `paused - waiting for a human: command|instruction '<i>' | LOG '<l>' + OUTPUT '<o>' pending`
  - `log '<l>' does not exist - the log is mandatory evidence, never optional`
  - `output '<o>' does not exist - run the external step before confirming`
  - `log '<name>' received · output copied to <name> (session)`
  - `funnel: ${NAME} is not declared in the flow — the placeholder stays intact`
- **Tokens (I-5, D11):** `insight_style.WAITING_HUMAN = "#e8ad3d"` and `CRC_FAMILY = "#c9562b"`, with role comments. The TCSS mirrors land at Inc-5.
- **User-visible effect:** loading a flow or set with a NUL ref now shows a refusal finding instead of a traceback. The flow screens paint the English summaries in the run log. The `FlowExecutionPanel`'s own Spanish strings stay until Inc-6.

---

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/flow_persistence_service.py` | source | HLR-146, LLR-146.14 | NUL pre-rejects in `dict_to_flow` (V5 + V6b), `_parse_a2b_entry`, `_parse_external_step_entry`, `_is_plain_template_stem`, `dict_to_chain_set` inputs; two `stat()` guards widened; module docstring |
| `s19_app/tui/services/variant_execution_service.py` | source | HLR-146, LLR-146.14 | NUL branch in `_resolve_manifest_entry` → `MANIFEST-PATH-ESCAPE`, before `resolve()` |
| `s19_app/tui/services/flow_execution_service.py` | source | HLR-147, LLR-147.5 | 11 service strings in English |
| `s19_app/tui/insight_style.py` | source | HLR-146, LLR-146.6 | `WAITING_HUMAN`, `CRC_FAMILY` |
| `tests/test_b97_flow_builder.py` | test | HLR-146, LLR-146.14, LLR-146.6 | NEW — 12 functions / 20 nodes (TC-B97-62, TC-B97-18 token arm) |
| `tests/test_b97_flow_execution.py` | test | HLR-147, LLR-147.5 | NEW — 5 functions / 6 nodes (TC-B97-25 service arm) |
| `tests/b97_fixtures.py` | fixture | HLR-146 | A.5 builders `patch_chain_blocks`, `nul_flow`, `nul_set` |
| `tests/b97_probes.py` | fixture | HLR-146, HLR-147 | `string_constants(source, scope)` (docstrings excluded, `JoinedStr` parts included; reused by Inc-5/6 TC-B97-19/25) |
| `tests/test_flow_external_step_b96.py` | test | LLR-147.5 | service-string pins `:265, 266, 302, 333, 345` rewritten to English (+2 docstrings) |
| `tests/test_tui_patch_json.py` | test | LLR-146.6 | the two tokens added to `_CLAIMED_HUES` (the tc079_5c colour-literal sweep, found by the census) |
| `tests/test_id_registry.py` | test | LLR-146.14 (D18 registry re-measure) | `EXPECTED_SCANNED_TEST_FILES` 192 → 194, measured |
| `design/design-proposal.md` | doc | LLR-146.14 (PC-17) | I-6 row: placement and code per field |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** |
| Test files | `7` (uncapped: 2 new modules, 2 helpers, 3 edits) |
| Doc / design files | `1` (I-6 row; outside the count) |

---

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1; unset NO_COLOR
python -m pytest tests/test_b97_flow_builder.py tests/test_b97_flow_execution.py tests/test_flow_external_step_b96.py tests/test_id_registry.py -rA -p no:cacheprovider --color=no
python .dev-flow/2026-10-19-batch-97/evidence/inc-2/mutate.py      # 15 mutants / 24 arms, restore by hash
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | all 26 `test_tc_b97_*` nodes of the two new modules (service calls, AST census, token values) | 26 passed (`evidence/inc-2/green.txt`) |
| **A · white-box** | `core` · `full` | 8 nodes of `test_flow_external_step_b96.py` (5 pins rewritten) + 13 registry nodes | 21 passed, same run — **47 passed** total |
| **B · black-box** | `core` · `full` | none at Inc-2 — AT-B97-08 (Inc-5), AT-B97-11 / AT-B97-23 (Inc-6) | n/a — not this increment |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new tests run against the unchanged source (HEAD `d5d0ff9`, `git diff -- s19_app` empty, recorded in the transcript header) |
| Instrument | pytest, one complete run |
| Where it ran | the main worktree, by the `software-dev` sub-agent |
| Transcript | `evidence/inc-2/red.txt` — **24 failed, 2 passed** |
| Restore proven by | n/a (no source edit); mutation restores are hashed per arm in `mutations.txt` |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 26 nodes — expected 26, collected 26 |
| Verdict granularity | per node (`-rfE`) |
| Arms that stayed GREEN | 2, both expected green on `main`: `test_tc_b97_62_clean_arms_flow_loads` (positive control: the envelope the field arms mutate loads clean) and `test_tc_b97_25_service_reach_guard_on_9c7beaf` (reads `git show 9c7beaf`, independent of the tree) |

**PC-11 classification:** all 24 failures are `AssertionError` at the named clause. None is an `ImportError`, a `NoMatches` or a collection error, so all 24 are **RED**. The new names are reached as `hasattr` / module attributes. Every NUL call is wrapped, so a raise reaches the named `raised ValueError` clause.

What the RED run measured on `main`, per arm:
- **Raise `ValueError`:** the 5 guard-delegated fields, the A2B ref and `a2l_ref`; the NUL input ref; the shared guard; the manifest file; the bound lane via `_chain_inputs`; both `stat()` paths.
- **Accepted, no raise:** `output_name`, `log_ref`, `output_path`, and the template.
- **Block error, no raise:** `run_flow` over the NUL `change_doc_ref`. The run's own catch-all records the raw `ValueError: stat: embedded null character`, so the arm is RED on its `MANIFEST-PATH-ESCAPE` clause.

| Field | Value |
|---|---|
| **RED counterfactual** | 24 of 26 new nodes RED at their named assertion on the unchanged source; `evidence/inc-2/red.txt` (sha256 `ba7677b3…cbc434`); no source edit |

| Field | Value |
|---|---|
| **Mutation verdicts** | `mutations.txt`: 15 mutants, 24 arms, **24 KILLED / 0 SURVIVED / 0 BAD**, each restored by sha256. M1 (the `dict_to_flow` pre-reject removed): the read-ref arms then get `MANIFEST-PATH-ESCAPE` from the guard and fail on the **code**, and `output_name` loads — the executed form of Code-Wire H-N1. M2–M5: A2B ref, `log_ref`, `output_path`, `a2l_ref`. M6/M7: the `stat()` guards narrowed back to `except OSError` → path arms raise (the S2-2 widening). M8/M9: template term / input-ref branch. M10: the guard's NUL branch → 4 arms (guard, `run_flow`, bound lane, manifest). M11: `"instruction"` → `"instruccion"` → census + manual pause arm. M12: missing-output diagnostic back to Spanish → census + confirm arm. M13: `WAITING_HUMAN = "#e8a33d"` (prototype amber, 19.5°). M14: `CRC_FAMILY` = the waiting value. M15: funnel notice back to Spanish → funnel arm + census |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `tests/test_b97_flow_*.py` | the unchanged base source | 24 failed (`red.txt`) |
| `b97_probes.string_constants` + `ES_MARKER` | `git show 9c7beaf:` service source | finds exactly the 11 frozen values. It is GREEN as a guard; its RED is the base-tree census node in `red.txt` listing the 11 values |
| `mutate.py` | 15 one-edit mutants | 24 `RED (KILLED)` lines; asserts each anchor occurs exactly once and that the edit applied |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | none — no artifact file is emitted. The outputs are findings and `BlockResult` strings, read directly from the service return values |

### Evidence files

| Evidence artifact | Path — under `.dev-flow/2026-10-19-batch-97/evidence/inc-2/` | SHA-256 |
|---|---|---|
| RED transcript | `red.txt` | `ba7677b3b5522b7c9a9fbabde4e753a4bca5984e0e2f8dbf4ead5b74aaa39e33` |
| GREEN transcript | `green.txt` | `4a596f4367fa9ebc4af7d4c23020d7752a6ae652c0832d51aabf8ab16fa06f4f` |
| Reverse-census greps | `census.txt` | `a3e07b52122488b850fd3370f12773ab870c236d6b1eaa3110e7fdfd1afdc7ef` |
| Reverse-census run | `census-run.txt` | `1a452754e095dfcf2c080ed9ba43c640df09e0191a6a7248363c0b1dd3a4ad38` |
| Mutation battery transcript | `mutations.txt` | `b2b36cddbb667686d59a524507d9037d69bdced6a885c5cd1fcfcdd96cdbc434` |
| Mutation battery script | `mutate.py` | `5d3914093e347698a0a8c65fe73f2b037bc662f21f331f151f8c7ee80177d61f` |
| Residual probe (in-memory NUL refs) | `residual-probe.txt` | `0c12cc6bd518890677f271156882ba93ca9eac9b3b2b1d9b667f6ac3556d46cf` |

Final source digests: `flow_persistence_service.py 4cc0f65a…095e8c`, `variant_execution_service.py 86d1b4ec…87047b`, `flow_execution_service.py 31297498…d56d4`, `insight_style.py 08f7bb6d…298069`. These equal the "before" hash on every restore line.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: "0 Spanish constants in the service" (TC-B97-25), "no test outside the rewritten pins asserts a service string", "no golden capture holds a service string", "no source parses a service summary" |
| If the result is an ABSENCE, what made the search wide enough | an AST walk over every string constant of the module (not a grep of lines); `grep -rn` over all of `tests/` and `s19_app/`; all `tests/__snapshots__` |
| Guard labelled as protecting a CONCLUSION | TC-B97-25 (a)/(b) is a standing guard over the service scope; the census greps are one-time probes |
| Conjunctive criteria: one mutation per conjunct | refusal = no raise (M6/M7/M10), no artifact (M3/M4/M8: accepted), the code (M1: `MANIFEST-PATH-ESCAPE` instead), the field named (asserted on every arm, not separately mutated) |
| Synthetic instance of the absent case | `NUL` in each field; a reach guard on `9c7beaf`, where the Spanish values exist |
| **Positive control** | the reach guard (census finds 11 on `9c7beaf`); `test_tc_b97_62_clean_arms_flow_loads`; B3 `grep -rl S19 tests/__snapshots__` → 10 files, while the service words → 0 |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1a service strings asserted by other tests | `git grep` over `tests/` at HEAD for each Spanish service word (`census.txt`) | the census split the pins in `test_flow_external_step_b96.py`. Service strings: `:265` `esperando humano`, `:266` `pendientes`, `:302` `salida copiada`, `:333` `constancia`, `:345` `correr el paso externo` — **rewritten here**. UI strings (`FlowExecutionPanel`): `:507` `ESPERANDO HUMANO`, `:508` `pendiente`, `:509` the `#fx_log` line (its `or` arm is satisfied by the panel constant), `:514` `re-run tras confirmar` — **left for Inc-6**. `test_flow_funnel_b96.py:197` asserts only `"MISSING" in message` (still holds); `:350` and `:108` hold `constancia.txt` as fixture data, not a pin |
| B1b changed behaviour (codes, guard, stat, tokens) | `grep -rl` for the 4 codes, `_resolve_manifest_entry`, `_is_plain_template_stem`, `file unreadable`, the tokens and hexes | 9 files besides the new ones. The re-run below is green |
| B1c hex-literal sweep | `test_tui_patch_json.py::test_tc079_5c_hue_census_is_complete` sweeps every `#rrggbb` in `s19_app/` | the 2 new tokens were unaccounted → **claimed in `_CLAIMED_HUES`**. My first comment also carried the prototype hex and tripped the sweep, so the comment was reworded. MAGENTA's optimality test stays green: both hues are inside the RED..YELLOW flank |
| B2 file moved | — | none |
| B3 golden captures | `grep -rl` for the service words over `tests/__snapshots__` | 0 hits (positive control 10) |
| B4 artifact consumed elsewhere | — | none written |
| A3 consumers outside the owning modules | `grep -rnE` in `s19_app/` | no source parses a service summary. `flow_screens.py:2389` tests `endswith("unresolved")`, which is unchanged. Remaining Spanish there (`:223`, `:740`, `:1431`, `:2280`) belongs to Inc-5/6 |

Census run (`census-run.txt`, 16 files: persistence, chain-set, A2B, symbol entries, manifest verify/writer, variant execution, multi-image, execution service, funnel, patch_json, import census, insight style, builder render, the two b94 flow UI modules): **228 passed, 0 failed**.

| Field | Value |
|---|---|
| **Reverse census** | B1a 9 pins split 5 service (rewritten) / 4 UI (Inc-6); B1b 9 files; B1c 1 sweep fixed; B2–B4 none; A3 none; run 228 passed |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 11 service values, enumerated by the AST census (`ES_48_9C7BEAF` scope `flow_execution_service`), not by grep, all 11 corrected (TC-B97-25 (b) GREEN). Comments in the service that quote `"esperando humano"` (`:826`) are prose, not constants, and were left untouched (surgical) |

### Signed-balance test ledger

`post = base − deleted + added` → gate set: `47 = 21 − 0 + 26` ✓. Base 21 = 8 `test_flow_external_step_b96.py` + 13 registry nodes. 0 nodes deleted. 5 assertions rewritten in place.

---

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a named agent (agents/code-reviewer.md) · approve (F1–F3 LOW, text only: template refusal message names NUL, two mutation docstrings name `MANIFEST-PATH-ESCAPE`, b96 module docstring wording; all three folded by the orchestrator, gate set re-run `evidence/inc-2/green-after-fold.txt` 64 passed). security-reviewer — spawned as a named agent · LOW, 0 HIGH, S2-2 RED → GREEN closed; S4-1 (NUL pasted in the Builder reaches the raw `ValueError` via `_make_flow_block`, `flow_screens.py:158`) → Inc-5; S4-2 (reserved device names) and S4-3 (`log_ref`/`output_path` accept UNC/absolute, shipped batch-96 behaviour) → backlog at close |

---

## 5 · Risks

- **Two codes for `output_name`:**
  - A NUL gets `FLOW-UNSAFE-REF`, because LLR-146.14 says so and the check precedes V7.
  - A traversal gets `FLOW-UNSAFE-OUTPUT-NAME`, as shipped.
  - The same split applies to `ExternalStepBlock.output_path`. This is the H-N2 choice, made explicit in I-6.
- **Residual (in-memory flows, `residual-probe.txt`):**
  - A `WriteOutBlock` built in memory with a NUL `output_name` does not raise. `run_flow`'s catch-all records `ValueError: unlink: embedded null character` as a block error. The raw exception text is the only message.
  - A NUL `log_ref` at confirm time is reported as `does not exist`.
  - Loaded files never reach either path. The Builder add form is Inc-5's.
- **English wording is my choice.** No frozen English text exists for the service strings (A.2 freezes only the Spanish values). Inc-6's panel strings and the I-9 statuses should read alongside them.
- **Reach guard needs `git`** and commit `9c7beaf`. It **skips** (labelled) on a shallow clone, following the `test_tui_issues_triage_b94.py` idiom.

## 6 · Pending items / spec deviations

- **PC-17 — discharged by an I-6 fold, no ledger amendment.** LLR-146.14's codes are met as written. The design-proposal I-6 row now names the owner functions and the code per field. That is the only edit outside the file set, and the brief allowed it.
- **LLR-146.14 negative control needs a ledger amendment (H-N3, orchestrator).** The NC says "4 of the 5 arms raise". The executed RED shows otherwise:
  - The template arm loads.
  - `run_flow` does not raise: it records a block error carrying the raw `ValueError`.
  - The `output_name`, `log_ref` and `output_path` arms are RED by acceptance.
- **`nul_bind` builder deferred to Inc-6.** It is a UI procedure (paste into `#fx_in_0_0`, then Bind). Its service half is `test_tc_b97_62_p50_bound_lane_input_is_a_block_error` via `ChainSpec.bindings`.
- **Appendix A.4 TC-B97-25** says its pins are "rewritten in the Flow Execution increment". The design §6.1 Inc-2 row moves the service-string pins here, and that was followed.
- **Extra arms beyond the 15:** `a2l_ref`, the manifest file (`read_project_manifest`), and the bound lane (`run_chain_set`). They come from the Code-Wire graph examples.
- The field-named clause of each refusal is asserted on every arm but not separately mutated.
- Pre-existing flakes from Inc-1 are not touched by this increment.

## 7 · Suggested next task

The orchestrator runs the full suite node by node against the baseline (PC-12 command), the `code-reviewer`, and the `security-reviewer` S2-2 lens. Then Inc-3 (Check Editor), with the PC-5 / PC-8 / PC-14 / PC-19 conditions due before it opens.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | §2: 4 / 4 |
| 2 | Tests written in this same increment | all | ✓ | 2 new modules, 26 nodes |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | 26 layer-0 nodes |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 24/26 RED at named assertions |
| 5 | Reverse census declared | `core` · `full` | ✓ | `census.txt`, `census-run.txt` (228 passed) |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | approve, F1–F3 LOW folded (§4b) |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched (or returned to trunk) | all | ✓ | I-5 as frozen; I-6 return shapes unchanged, placement folded (PC-17) |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt` `-rA` PASSED lines |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 table |
| 11 | Mutation verdicts per arm | all | ✓ | `mutations.txt` 24 KILLED / 0 SURVIVED |
| 12 | Instrument RED-proof | all | ✓ | §4, 3 instruments |
| 13 | Correction population | all | ✓ | 11 values by AST census |
| 14 | Emitted-form assertion | all | ✓ | none — no artifact emitted |
| 15 | Independent review names somebody | all | ✓ | code-reviewer + security-reviewer (§4b) |
| 16 | Evidence files with digests | all | ✓ | 7 files, §4 |

## Gate — full suite, node by node against the baseline (orchestrator, 2026-10-20)

- **Run:** `evidence/inc-2/full-suite.txt` (SHA-256 `2f0bffab…25be8`) — 8 failed, 3153 passed, 3 skipped, 32 xfailed in 1:11:32. A first run was stopped by the host for low memory at 81 % and discarded; this run started after the F1–F3 text fold and LED-.8, so it measured the folded tree. The Inc-8 spec delta (documents only, no `s19_app/` or `tests/` file) was written while it ran.
- **Comparison** (PC-12 command, `comm` over `FAILED`/`ERROR` node ids vs `evidence/baseline-pytest-51ee191.txt`):
  - not in the baseline (3): `test_tui_patch_editor_v2.py::test_at068a_undo_redo_roundtrip_through_surface`, `::test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded`, `test_tui_patch_layout.py::test_at063c_reparent_safety_at_120`. Re-run in isolation (`evidence/inc-2/rerun-nonbaseline.txt`, SHA-256 `173b6bb7…ecf22`): 3 passed. None touches a flow service or the two new tokens (Inc-2's file set is the three flow services and `insight_style.py`). **Verdict: no regression; same Patch Editor order/timing flake class as Inc-1.**
  - baseline nodes green in this run (5): `at057b`, `at064c`, `at_batch41_escape`, `at077c`, `undo_redo ac1` — recorded, not claimed as fixed.
  - counts reconciled: xfailed 32 = baseline 32, skipped 3 = 3, XPASS 0.
- **Routed:** the flakes → backlog at close (suite hygiene); S4-2, S4-3 → backlog at close; S4-1 → Inc-5.
