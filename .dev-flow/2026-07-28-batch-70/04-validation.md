# Validation — batch-70 · FB-P2 multi-image flow runs + report fusion

## Verdict: **PASS-WITH-NOTES**

All seven ACs plus D-4 and LLR-104.6 are observed through the shipped surface, the full suite is
green, and AC-5's bound is falsified against an unbounded copy. **Not `PASS`, because three gaps are
real and stated rather than closed** — AC-6 is carried structurally with no byte-golden; the fused
document's `O(V × ~6 lines)` heading overshoot sits outside the byte budget; and the per-variant caps
bound rows, not bytes. All three are recorded as non-claims in `REQUIREMENTS.md` R-TUI-099 and carried
as P3 in `BACKLOG-CODE.md`. See §7.

Base `244c5d9` (Phase 0) → implementation `ebca4cc` · `4573d43` · `2b6c3a5` → merged `b457ef8` (PR #159).

## 1. Acceptance matrix

Every AC is observed through the shipped surface. **No AC is discharged by a citation** — each row
names the node that ran and what it asserted.

| AC | Node(s) | Observation | Verdict |
|---|---|---|---|
| **AC-1** V variants → V executions | `AT-205`, `TC-500`, `TC-501` | an injected counting iterable is consumed **exactly 3 times** for 3 variants, a counting executor records `["a","b","c"]`, and `len(variant_outcomes) == 3`. Also driven from `build_variant_set` + `plan_variant_executions` so the D-1 reuse — not a parallel image list — is what is observed. | ✅ |
| **AC-2** variant *k* aborts, *k+1…V* run | `AT-206`, `TC-502` | with `b`'s image absent: statuses `[ok, error, ok]`, roll-up `error`, counts `(2,0,1)`. `TC-502` breaks `run_flow`'s no-raise contract on purpose and the remaining variant still executes. | ✅ |
| **AC-3** one section per variant, id escaped | `AT-207` ×2, `TC-503` | `### a / ### b / ### c` exactly; an id `ev\|il\`x` renders escaped **and no unescaped occurrence survives anywhere in the document**. | ✅ |
| **AC-4** worst roll-up + invertible counts | `AT-208`, `TC-504`, `TC-504b` | header reads `FAILED` + `2 ok / 1 issues / 1 error` and the three sum to 4; the `issues` and `clean` arms are separately pinned. | ✅ |
| **AC-5** every variant survives, cuts named, **producer** bounded | `AT-209` ×2, `TC-505`, `TC-505b`, `TC-505c` | 3 variants each 25 over the cap: all 3 sections present · each cut names `findings: 25 omitted (cap 60 per variant)` · **each counting sequence reports `consumed <= 60`**. A 20×-over variant does not evict a 1-finding neighbour. Negative control: nothing under the cap emits a notice. | ✅ |
| **AC-6** unscoped run unchanged | `AT-210`, `TC-506`, `test_d4_an_unscoped_run_still_writes_its_own_report`, `test_llr1046_this_image_still_takes_the_single_image_path` | the unscoped binding is the identity; `compose_flow_report` has no variant parameter, no `variant` token in its source, and `FlowReportState` is unchanged; an unscoped run still writes its own `# Flow report —` document; the default scope's pane gains no fused line. | ✅ |
| **AC-7** containment rejection is per variant | `AT-211`, `TC-507`, `TC-508` | a variant resolving outside the project yields `[ok, error, ok]` with `MANIFEST-PATH-ESCAPE` **recorded in the block's diagnostics**, not merely a failure; the code is a `REJECTING_CODES` member so the shipped C-31 census covers the variant path. | ✅ |
| **D-4** ONE report file | `test_d4_*` (4 nodes) | an **artifact-on-disk** count — `len(sorted(reports.iterdir())) == 1` after a 3-variant run with a REPORT block. | ✅ |
| **LLR-104.6** scope wiring | `test_llr1046_*` (7 nodes) | the real `#flow_scope` Select + the real `#flow_run` Button through `S19TuiApp`'s handler. | ✅ |

## 2. AC-5's counterfactual — executed, and it fails on its ASSERTION

D-7 requires AC-5 to be shown RED against an unbounded implementation. Running it against the
**pre-change tree** would fail at import (`flow_fused_report_service` does not exist there) and would
prove nothing, so the bound was reverted on a **copy of the fixed tree** — the only form where the
test's own assertion is what breaks.

**Method.** `s19_app/`, `tests/` and `pyproject.toml` copied to a scratch tree; three sites reverted
in the copy only: `islice(section.block_results, MAX_FUSED_LEDGER_ROWS_PER_VARIANT)` →
`list(section.block_results)`, `islice(br.findings, max(0, remaining))` → `list(br.findings)`,
`islice(br.diagnostics, max(0, remaining))` → `list(br.diagnostics)`.

```
$ python -m pytest -q tests/test_flow_report_fusion.py -k "at209"

E       AssertionError: assert 1200 <= 60
E        +  where 1200 = [Finding(severity='warn', message='huge 0'), … 'huge 1199')].consumed

E       AssertionError: the cut in a must be named with its count
E       assert '> **Cut in `a`:** findings: 25 omitted (cap 60 per variant).' in '# Fused flow report …'

2 failed, 11 deselected in 0.77s
```

Both failures are **on the assertion**. `1200` is the number of findings the unbounded producer
formatted where the bound formats `60` — the distinction batch-63 proved wall-clock and peak-memory
cannot make. On the fixed tree the same two nodes pass.

## 3. Frozen-source guards (C-27, both arms)

```
$ python -m pytest -q tests/test_engine_unchanged.py                                  1 passed
$ python -m pytest -q tests/test_tui_directionb.py -k "tc031 or tc032 or engine"      7 passed
```

Planned-edit set vs `_ENGINE_PATHS` intersection = ∅ (premise **P-6**, executed). No unfreeze was
requested and none was needed.

## 4. Suite

| | |
|---|---|
| Base (`-m "not slow"`, collected) at `244c5d9` | **2319** |
| New nodes | **35** — `test_flow_multi_image.py` 11 · `test_flow_report_fusion.py` 13 · `test_flow_multi_image_ui.py` 11 |
| After | **2355** — `+36` |
| Flow-suite regression (`-k flow`, at Inc-2+3) | **194 passed** |

**The `+36` is `+35` plus one, and the one is attributed, not assumed.** The delta was re-derived by
diffing collected node ids against the base worktree at `244c5d9`:

```
$ comm -13 base.txt now.txt | grep -v "test_flow_multi_image\|test_flow_report_fusion"
tests/test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input[flow_fused_report_service.py]

$ comm -23 base.txt now.txt        # nodes lost
(none)
```

A pre-existing **parametrised per-module guard** adopted the new module by itself. No node was lost.

## 5. Lint

`ruff check tests/ s19_app/` → **7 findings, all pre-existing and none in this batch's files**:
`app.py:5682` (`F821 Dict`), `test_flow_crc_ribbon.py` ×2, `test_flow_crc_ui.py` ×4. Adjacent code was
deliberately not touched. Every file this batch created or edited is clean.

## 6. Executed full-suite run

```
$ python -m pytest -q -m "not slow"

--------------------------- snapshot report summary ---------------------------
29 snapshots passed.
2350 passed, 2 skipped, 21 deselected, 3 xfailed in 1420.84s (0:23:40)
```

**Zero failures.** `2350 + 2 + 3 = 2355`, which reconciles exactly with the collected count. The 29
snapshots passed unchanged — **no golden was re-baselined**, which matters because `tui-ci` is blind
to snapshot drift and a silently regenerated baseline is invisible in a green run.

**One honesty note on ordering.** This run started before `REQUIREMENTS.md` was appended and before
the backlog/state reconciliation, so it did not cover them. The six test files that read those
documents were re-run afterwards — `test_color_policy_round_trip`, `test_report_addendum_bound`,
`test_tui_legend`, `test_tui_patch_json`, `test_tui_public_api`, `test_validation_engine` →
**102 passed, 2 xfailed**. Nothing else in the suite reads a document this batch edited.

## 7. What was NOT validated

- **No byte-golden for AC-6.** AC-6 asks for byte-identity with today's single-image output. What is
  executed is the **structural** form — the single-image composer is a different module and is not
  edited, and `compose_flow_report`'s source contains no `variant` token. A true byte-golden captured
  from `origin/main` would be strictly stronger and is **carried to `BACKLOG-CODE.md`**, not claimed
  here.
- **The `O(V × ~6 lines)` heading overshoot is measured by construction, not by a test.** No node
  drives V high enough to observe the document exceeding `FLOW_REPORT_MAX_TOTAL_BYTES`. Recorded as
  non-claim (a) in `REQUIREMENTS.md` R-TUI-099 and carried.
- **No performance number is claimed.** The bound is asserted as a *count of formatting operations*,
  which is the oracle D-7 specifies; no wall-clock or RSS figure is stated anywhere in this batch.
