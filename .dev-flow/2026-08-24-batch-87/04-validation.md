# Validation — s19_app — Batch `2026-08-24-batch-87`

> Phase 4, qa-reviewer. Branch `claude/batch-87-ifc-reauthor-surface-3`, HEAD `4e43a4b`,
> merge-base `943e54a`. The suite gate is the orchestrator's single complete run (C-25); this
> phase **consumed** it and did not re-run it. Everything else below was executed by this phase:
> isolated node re-runs, five kill-mutation arms on disposable copies, and one read-only
> validator pass over the live tree.

---

## ⚠️ BLOCKER — RAISED, AND RULED BY THE ORCHESTRATOR (read before the verdict)

> **RULING, 2026-08-24, orchestrator, at this gate.** The class-membership criterion proposed
> below is **ADOPTED verbatim**: empty source-scope diff against merge-base **AND** N ≥ 10
> isolated re-runs **AND** failure signature within the recorded family, with the isolated-failure
> **RATE recorded as a figure, never the word "passes"**. Two grounds, stated for the record:
> **C-53** — the `n = 1` "passes isolated" binary just false-failed correct work — and **the
> batch's own method**, which is the figure rather than the narration. The three isolated failures
> are dispositioned **pre-existing timing races of the modal push/mount family, NOT product
> blockers**; the evidence is the structural argument (0 source files, empty diff, no ordering
> plugin), not an appeal to how flaky they look.
>
> **`01b-qa-validation-plan.md` §7 carries the amendment** as a Before/After block at the head of
> that section. The BEFORE text — the six-id whitelist, the "passes isolated" rule, and the
> `conda run` invocation — is **kept verbatim and not erased**: it is the record of what was
> refuted. The blocker is therefore **CLOSED by ruling**, and the analysis below is preserved as
> the evidence that produced it, not rewritten to match its outcome.

**What was raised.** The pre-registered flaky-node disposition of `01b-qa-validation-plan.md` §7
is REFUTED by measurement, and three of the six failing nodes fail in ISOLATION. Under §7's rule
as pre-registered — *"a FAILED node not on this list → BLOCKER, regardless of how flaky it
looks"* — this gate could not be signed off on the disposition as written.

What is **not** in doubt, and is what keeps this from being a product blocker:

- The batch's source-scope diff against merge-base is **empty, exit 0** (`s19_app/`, `tests/`,
  `tools/`, `pyproject.toml`), so `tests/` is byte-identical to `943e54a` and the batch has no
  mechanism by which it could redden any node.
- `s19_app` imports from the working tree (`C:\Users\jjgh8\Github\s19_app\s19_app\__init__.py`),
  not from a stale install; `build/` is dated 2026-08-03 and is not on `sys.path`.
- `pytest` runs with `plugins: textual-snapshot-1.1.0, syrupy-4.8.0` — **no `pytest-randomly`**,
  so collection order is deterministic and the run-to-run change in WHICH nodes fail is not an
  ordering artifact.

So the finding is about the **gate's model of the failures**, not about the batch's product:

1. **Five of the six failing nodes are NOT on the pre-registered list**, and one of them
   (`test_at006_report_bearing_flow_shows_report_row`) is a node §7 explicitly named and
   **excluded** in its disambiguation paragraph.
2. **Five of the six pre-registered nodes did not recur at all.**
3. **Batch-86's diagnosis that "every one of the 6 passes in isolation" is a vacuous check.**
   It rests on single-shot isolated runs. Re-sampled at ten isolated runs per node this phase,
   the one pre-registered node that *did* recur — `test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces`
   — **fails 4 of 10 alone**. A single isolated pass on a node that passes 60% of the time is a
   coin landing heads, not a diagnosis.

**Disposition of the blocker: RULED, and the rule re-authored.** This phase did not have the
authority to waive a pre-registered rule it was handed, so it raised the blocker and proposed a
replacement; the orchestrator adopted it verbatim (ruling above), and this phase then wrote the
amendment into `01b-qa-validation-plan.md` §7 as a Before/After block. The enlarged node set —
**11 distinct node ids**, enumerated in the close-carry section below — goes to
`BACKLOG-CODE.md` at close, together with the finding that batch-86's flaky diagnosis was
**n = 1 and therefore vacuous**. Detail and transcripts are in the disposition section below.

---

## ✅ Verdict (read first)

| Layer | Result |
|---|---|
| **Layer B (black-box acceptance)** | ✓ **4 gating ATs + 2 pins, all observed** — every one through the shipped validator/Atlas toolchain, each deliverable read as a **thing** (stdout line or file bytes), each re-observed live by this phase rather than taken from the record |
| **Layer A (functional, per-requirement)** | ✓ **11 of 11 pass** (3 HLR + 8 LLR) · **0 blocker fails** · every Executed-verification cell resolves to a real transcript |
| **Gates G-87** | ✓ **G1 · G2 · G3 · G4 · G5 · G6 · G7 · G8 · G10 GREEN** (re-measured live this phase) · **G9 (pin) GREEN** · **G11 (pin) GREEN** — ledger reconciles and all 6 failures disposition pre-existing under the criterion adopted at this gate |
| **Kill mutations owed batch-local** | ✓ **5 arms executed on disposable copies** — K1, K3, K7, K8 as pre-registered, plus K5 discharged batch-locally as a by-product. Live tree never mutated (`git status --porcelain` empty after every arm) |
| **Surface-reachability (bidirectional)** | ✓ **6 named input dimensions · 6 named outputs/deliverables**, all reached or observed through the real handler, **0 gaps** |
| **Test ledger** | ✓ arithmetic reconciles: `2714 = 2702 + 6 + 3 + 3`, `post = 2714 − 0 + 0`; all **6** failures dispositioned **pre-existing** (4 timing races, 2 order-dependent), each with a measured isolated rate. **11 node ids carried to close** |
| **Evidence checklist** | ✓ 11 of 11 items cited below |

Two results worth the reader's time beyond the blocker:

> **(1) K1 is the only proof the census entry was cleared by removing its CAUSE.** Re-absorbing
> one line back into the pilot block makes the validator print
> `UNPARSED census rose 1 -> 2` as a V20 BLOCK. Without that arm, "the census fell to 1" is
> equally consistent with the parser having gone quiet.
>
> **(2) K3's first arm refuted its own prediction, and the refutation is a measurement of the
> parser defect this batch exists to fix.** Deleting the `consumers` field line moved V14 by
> **−2**, not −1: the orphaned continuation line was absorbed by the field above it, exactly the
> no-block-terminator mechanism M-3 documented. The arm is repaired by a second, surgical arm
> (K3b) that lands on the predicted −1, and the wrong prediction is **not** overwritten.

---

## Detail (reference)

### Flaky-node disposition — the headline

**Source of the pre-registered list.** `01b-qa-validation-plan.md` §7 resolves batch-86's
truncated names to six full node ids in a table at lines 328 through 333, sourced from
`BACKLOG-CODE.md:7` ("New carries from batch-86", item 1) and from
`.dev-flow/2026-08-24-batch-86/04-validation.md:327`, which names them only in truncated form
(`test_at_061a…`, `test_at006…`, `test_at005…`, `test_at023c…`, `test_at057b…`,
`test_at064b…`). Because the prior record truncates, **node-id-to-node-id comparison had to go
through §7's resolutions and through `BACKLOG-CODE.md:7`'s longer truncations**; both were used,
and both agree.

**Isolated re-runs, executed this phase on this tree**, invoked directly (never through
`conda run` — see the probe-incident note):

```
PYTHONIOENCODING=utf-8 /c/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest -q "<nodeid>"
```

**Verdicts are stated under the ADOPTED criterion** (`01b-qa-validation-plan.md` §7 AFTER):
**A-1** = the batch's source-scope diff against merge-base is empty at exit 0 — **satisfied once,
for the whole batch**, so it holds for every row below · **A-2** = the isolated failure **rate**,
recorded as a figure · **A-3** = the failure signature is a member of the recorded **modal
push / mount race** family. The list-membership column is retained because it is the evidence
that refuted the old rule, **not** because membership decides anything any more.

| # | FAILED node (gate run) | Definition | On the pre-registered list? *(historical)* | Isolated, 1 run *(the refuted n = 1)* | **A-2 rate, N = 10** | **A-3 family?** | **Disposition under the adopted criterion** |
|---|---|---|---|---|---|---|---|
| 1 | `tests/test_tui_flow_persistence_ui.py::test_at006_report_bearing_flow_shows_report_row` | `tests/test_tui_flow_persistence_ui.py:158` | **NO — explicitly EXCLUDED** by §7's disambiguation paragraph (`01b-qa-validation-plan.md:336` through `:339`), which names this exact definition line as *"not on this list"* | **FAIL** (1.82 s) | **1 of 10** | ✓ `NoMatches` on `#flow_load_ok` | **pre-existing · TIMING RACE** |
| 2 | `tests/test_tui_flow_persistence_ui.py::test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` | `tests/test_tui_flow_persistence_ui.py:295` | **YES** — §7 row 3 (`01b-qa-validation-plan.md:330`) | PASS (2.33 s) — **this single pass is the vacuous check** | **4 of 10** | ✓ `NoMatches` on `#flow_load_ok`, `#flow_list`, `#flow_discard_cancel` | **pre-existing · TIMING RACE** — reclassified out of "order-dependent" by the rate |
| 3 | `tests/test_tui_map_big.py::test_at072a_bands[size1]` | `tests/test_tui_map_big.py:264` | **NO** — no row of §7 names this file at all | PASS (1.19 s) | **0 of 10** | ✓ same suite family, `AttributeError` on an unmounted-state read | **pre-existing · ORDER-DEPENDENT** |
| 4 | `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` | `tests/test_tui_patch_editor_v2.py:2472` | **NO** — §7's two rows in this file are at `:2361` and `:2766` | PASS (1.74 s) | **1 of 10** | ✓ `AssertionError` — a binding that did not route before mount completed | **pre-existing · TIMING RACE** |
| 5 | `tests/test_tui_patch_editor_v2.py::test_at_batch41_escape_cancels_changeset_json_popup` | `tests/test_tui_patch_editor_v2.py:2894` | **NO** | PASS (1.98 s) | **0 of 10** | ✓ `NoMatches` on `#changeset_json_text` | **pre-existing · ORDER-DEPENDENT** |
| 6 | `tests/test_tui_patch_editor_v2.py::test_tc329_popup_seed_and_load_text_apply_seam` | `tests/test_tui_patch_editor_v2.py:3057` | **NO** | **FAIL** (3.65 s) | **4 of 10** | ✓ `NoMatches` on `#changeset_json_text`, `#changeset_json_cancel`, `#changeset_json_confirm` — **three different selectors across four failures** | **pre-existing · TIMING RACE** |

**Result: 6 of 6 disposition as pre-existing · 0 product blockers · 4 timing races · 2
order-dependent.** No node required an appeal to how flaky it looked, and no node was
dispositioned on the strength of a single isolated run.

**The five pre-registered nodes that did NOT recur**, each named so the absence is a statement
and not a silence: `test_at_061a_persistent_control_survives_then_writes_pair_and_clears`
(`tests/test_before_after_report.py:1078`) ·
`test_at006_quarantine_card_painted_and_flow_unchanged`
(`tests/test_tui_flow_persistence_ui.py:190`) · `test_at023c_issues_legend_button_opens`
(`tests/test_tui_legend.py:197`) · `test_at057b_regroup_wiring_and_binding_regression`
(`tests/test_tui_patch_editor_v2.py:2361`) ·
`test_at064b_json_popup_edit_confirm_cancel_and_geometry`
(`tests/test_tui_patch_editor_v2.py:2766`).

**Overlap between the pre-registered set and the observed set: exactly ONE node of six.**

#### Why this is one failure family, not eleven bugs

Every failing selector observed across the gate run and the sixty isolated runs is a **modal
screen widget id**, and every failure is a `NoMatches` raised at query time — with the single
exception of node 4, which raises an `AssertionError` about a binding that did not route:

| Failure signature | Where observed |
|---|---|
| `No nodes match '#flow_load_ok' on LoadFlowScreen` | gate run node 1; isolated nodes 1 and 2 |
| `No nodes match '#flow_list'` | isolated node 2 |
| `No nodes match '#flow_discard_cancel' on Confirm…` | gate run node 2 |
| `No nodes match '#changeset_json_text' on Screen(id='_default')` | gate run nodes 5 and 6; isolated node 6 |
| `No nodes match '#changeset_json_cancel'` · `No nodes match '#changeset_json_confirm'` | isolated node 6 |
| `AttributeError: 'str' object has no attribute 'name'` | gate run node 3 |
| `AssertionError: pressing Run checks must still route run_checks after the r…` | gate run node 4 |

The same node fails on a **different selector on different runs** (node 6 produced three distinct
ones across four isolated failures). That is the signature of a **modal push/mount race** — the
test queries a child before the modal's `compose()` children are mounted — not of cross-test state
pollution. Cross-test pollution would fail deterministically once the polluting neighbour ran, and
would never fail a node running alone.

#### Consequence for the disposition rule, stated as a criterion the orchestrator can adopt

§7's rule is unsound in both directions, and each direction was measured:

- **As a whitelist it under-covers.** The failing population is resampled every run. Five nodes
  reddened this run that no prior record carries; batch-86's gate run output
  (`batch86_baseline.txt`) is not retained on this machine, so the claim "these five passed in
  batch-86's run" rests on batch-86's record enumerating a different six — an inference, and it
  is labelled one here rather than dressed as a measurement.
- **As a diagnosis it is vacuous.** "Passes in isolation" was established by one isolated run per
  node. Three of the six nodes measured this phase fail alone at a rate between 1 in 10 and 4 in
  10, so a single isolated pass carries almost no information.

**Replacement, proposed by this phase and ADOPTED VERBATIM by the orchestrator at this gate:**
disposition by CLASS with repeated-isolation evidence — a FAILED node is *pre-existing* when
(i) the source-scope diff against merge-base is empty, **and** (ii) the node is re-run **N ≥ 10**
times in isolation on the same tree and its failure signature is a member of the recorded family,
**and** (iii) its isolated failure rate is recorded **as a figure** rather than as the word
"passes". A node whose isolated failure rate is 0 of 10 is **order-dependent**; a node with a
non-zero isolated rate is a **timing race**, which is a worse and separately tracked class.
Under that criterion all six nodes of this run disposition cleanly (table above), and the
enlarged carry is **eleven distinct node ids** across the two batches, enumerated below.

The rule now lives in `01b-qa-validation-plan.md` §7 as a Before/After amendment block, with the
refuted BEFORE text kept verbatim beneath it.

#### Close carry — the exact eleven node ids for `BACKLOG-CODE.md`

**One test-hygiene carry, one family, eleven ids.** Six were observed failing at this gate and
five are the batch-86 pre-registered nodes that did not recur — carried anyway, because
non-recurrence in one run is not evidence of repair under the criterion that just replaced the
one that assumed it was.

*Observed failing at the batch-87 gate (6), each with its measured isolated rate:*

1. `tests/test_tui_flow_persistence_ui.py::test_at006_report_bearing_flow_shows_report_row` — **timing race, 1 of 10**
2. `tests/test_tui_flow_persistence_ui.py::test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` — **timing race, 4 of 10**
3. `tests/test_tui_map_big.py::test_at072a_bands[size1]` — **order-dependent, 0 of 10**
4. `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` — **timing race, 1 of 10**
5. `tests/test_tui_patch_editor_v2.py::test_at_batch41_escape_cancels_changeset_json_popup` — **order-dependent, 0 of 10**
6. `tests/test_tui_patch_editor_v2.py::test_tc329_popup_seed_and_load_text_apply_seam` — **timing race, 4 of 10**

*Pre-registered at batch-86, did NOT recur at the batch-87 gate (5) — rate UNMEASURED, and
labelled unmeasured rather than assumed:*

7. `tests/test_before_after_report.py::test_at_061a_persistent_control_survives_then_writes_pair_and_clears`
8. `tests/test_tui_flow_persistence_ui.py::test_at006_quarantine_card_painted_and_flow_unchanged`
9. `tests/test_tui_legend.py::test_at023c_issues_legend_button_opens`
10. `tests/test_tui_patch_editor_v2.py::test_at057b_regroup_wiring_and_binding_regression`
11. `tests/test_tui_patch_editor_v2.py::test_at064b_json_popup_edit_confirm_cancel_and_geometry`

**Carried with them, as the finding the test-hygiene batch actually needs:**

> **batch-86's flaky diagnosis was n = 1, and therefore vacuous.** It recorded *"every one of the
> 6 passes in isolation on main"* from a single isolated run per node. Re-sampled at **N = 10**
> this gate, node 2 above — one of that very six — **fails 4 of 10 alone**, and two off-list nodes
> fail 4 of 10 and 1 of 10 alone. The whole "order-dependent suite pollution" classification was
> an artifact of stopping at the first isolated pass. **The repair batch must not re-run the same
> check**: any node it declares fixed needs a rate at N ≥ 10, and ids 7 through 11 need their
> first real rate measured before anyone claims they were only order-dependent.

**Root-cause direction for that batch, from the signatures rather than from a guess:** the family
is a **modal push / mount race** — a `NoMatches` raised at query time against a modal-screen
widget id, where the same node fails on a **different selector on different runs**. The suspect is
the seam between pushing a modal screen and its children being mounted, not any individual test's
assertions.

### Probe-incident note — evidence destroyed by `conda run`

**Finding, measured this session: never invoke the gate suite through `conda run -n s19env`.**
`conda run` buffers the child's stdout and re-prints it through a `cp1252` writer. The suite emits
`U+FFFD` (the replacement character) in at least one assertion diff, and the re-print dies:

```
File "C:\Users\jjgh8\anaconda3\Lib\encodings\cp1252.py", line 19, in encode
  return codecs.charmap_encode(input,self.errors,encoding_table)[0]
UnicodeEncodeError: 'charmap' codec can't encode character '\ufffd' in position 29589: character maps to <undefined>
```

(`p4-gate-run.txt:4` for the traceback head, `:19` for the exception; conda then offered to file a
crash report and the run exited 1 with **no test summary at all** — 8 KB of conda diagnostics
where a 40-minute suite result should have been.)

**The whole first gate run's evidence was destroyed**, and it had to be re-run from scratch. The
working invocation, used for the re-run and for every isolated run in this artifact, calls the
environment's interpreter directly:

```
PYTHONIOENCODING=utf-8 /c/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest -q -m "not slow"
```

**This supersedes the command printed in `01b-qa-validation-plan.md` §7**, which specifies
`conda run -n s19env python -m pytest -q -m "not slow"`. That command is not merely slower or
noisier — on this corpus it **cannot complete**. The rest of §7's protocol (redirect the whole run
to a file, never pipe through `tail`, strip ANSI before grepping `^FAILED`) was followed exactly
and is what produced the six node ids above.

### Kill-mutation transcripts (the Phase-4 debt from `01b-qa-validation-plan.md` §3 and the record's §3)

**Protocol executed verbatim** (`01b` §3): `T=$(mktemp -d); cp -r "$W"/. "$T"; rm -rf "$T/.git"`,
then `python ~/.claude/docs/tools/devflow-validate.py "$T"`. One copy per arm, each `rm -rf`'d at
the end of its arm. **Restore is proven by construction — the live tree is never touched — and
verified after every arm** by `git status --porcelain` scoped to the mutated paths, which returned
**empty after all five arms**. Every mutation is described by **POSITION + OPERATION only**; the
only operations used are **deletion** and **indent change**, so no mangled or invented token is
spelled anywhere in this file (C-56 — this file is scanner corpus).

**Baseline on the live tree, read-only, measured immediately before the arms:**

```
[-] V11  01-requirements.md: 79 OUTPUT(s), each with an address and a declared consumer list
[-] V14  01-requirements.md: 251 declared consumer(s), every one resolved
[-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once
[-] V21  01-requirements.md: 79 OUTPUT owner(s), every one declared
[!] V22  REQUIREMENTS.md: 276 of 544 batch-declared ids are not reflected in the living canon (HLR 75 · LLR 193 · US 8)
0 block · 284 notice · 15 not applicable
V13 rows: 52          rows naming artifact_row_set or unload_all_row: 0
canon grep for LLR-87.6: 1        canon grep for LLR-87.5: 3
```

#### K1 — re-absorb one line into the pilot block (indent change)

**Position + operation, and a correction to the arm as specified.** `01b` §3 K1 says *"take the
first prose line following the block's LAST field and increase its indentation"*. **There is no
such line**: the batch-85 record is 558 lines long and the block's closing fence is line 557, so
the block is the last thing in the file — which is precisely what LLR-87.4 mandates and what the
post-state census proves. The arm was therefore executed on the only line it could move as a pure
indent change: **the block's closing fence line itself, indented from column 0 to depth 1**. No
token is inserted, deleted or altered.

```
total lines in file: 558 ; fence at line 557
INDENTING line 557 (was column 0)

UNPARSED census: 2 item(s)                                 <- was 1
[x] V20  .dev-flow/_derived/ATLAS-ORPHANS.md: UNPARSED census rose 1 -> 2 — the parser is now blind to more than the committed Atlas admits
[-] V21  01-requirements.md: 79 OUTPUT owner(s), every one declared
5 block · 284 notice · 14 not applicable
```

**Verdict: prediction confirmed on both figures.** The census rises 1 → 2 and V20 BLOCKs with the
census-rise message. **This is the arm that makes G1 non-vacuous** — it shows the committed census
of 1 is the state of a parser that is still reading, not one that has gone quiet. (The four other
V20 rows in the `5 block` tail are derived-file drift caused by the mutation itself, expected on
any mutated copy.)

#### K3 — delete one consumer entry from the re-authored pilot's `artifact_row_set` (deletion) — FIRST ARM, PREDICTION REFUTED

**Position + operation:** delete the whole `consumers` field line of the `artifact_row_set` OUTPUT
in the batch-85 record (line 531), whose value is the single reacher of that output's address.

```
REMOVING line 531: '      consumers   : s19_app/tui/styles.tcss'

[x] V11  .dev-flow/2026-08-21-batch-85/01-requirements.md:527: COMPONENT loaded_panel: output `artifact_row_set` omits `consumers`. Write `none` if there are none — an omitted field is a question nobody asked
[-] V14  01-requirements.md: 249 declared consumer(s), every one resolved         <- predicted 250, measured 249
[!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:527: COMPONENT loaded_panel/artifact_row_set: reached by 1 undeclared file(s) — s19_app/tui/styles.tcss
V13 rows: 53          6 block · 285 notice · 13 not applicable
```

**Verdict: the V13 half flipped as predicted; the V14 half did NOT.** V14 moved **−2** where the
arm removes **one** consumer entry. The cause is the mechanism this batch exists to fix: deleting
the field's header line orphans its continuation line, which the parser then appends to the field
**above** it (`cardinality`), so a second consumer entry silently leaves the consumer set too.
The arm as executed is a hybrid of K3 and K5 rather than K3 alone.

**Two things follow, and neither is swept.** First, **K5 is thereby discharged batch-locally** —
`01b` §3 dispositioned K5 as *"cite, do not re-execute"*, and the V11 BLOCK above is the omitted-
field limb executed on this corpus instead of cited. Second, the prediction is repaired by a
second, surgical arm below rather than overwritten.

#### K3b — the surgical repair: delete the first consumer ENTRY, field and sibling intact (deletion)

**Position + operation:** on the same line, delete the entry token that follows the `consumers`
key, leaving the key, its colon, and the continuation entry beneath it untouched.

```
BEFORE line 531: '      consumers   : s19_app/tui/styles.tcss'
AFTER  line 531: '      consumers   :'

[-] V11  01-requirements.md: 79 OUTPUT(s), each with an address and a declared consumer list   <- clean; this is NOT the K5 shape
[-] V14  01-requirements.md: 250 declared consumer(s), every one resolved                      <- 251 -> 250, exactly -1
[!] V13  .dev-flow/2026-08-21-batch-85/01-requirements.md:527: COMPONENT loaded_panel/artifact_row_set: reached by 1 undeclared file(s) — s19_app/tui/styles.tcss
V13 rows: 53          4 block · 285 notice · 14 not applicable
```

**Verdict: all three figures as predicted.** V14 −1 · V13 stray pair count +1 with the new pair
**named** (`artifact_row_set` × `s19_app/tui/styles.tcss`, where the baseline had **0** rows for
that output) · V11 unmoved, which is what separates this arm from K3's first one. The `4 block`
tail is derived-file drift only.

**On the file-set union**, which `01b` K3 asked to be recorded either way: the union does not enter
this verdict, because the pair census moved and the pair is named. batch-86's M4 measured the union
blind at 15 → 15 while a real declaration was deleted; this arm confirms the pair form is the one
that sees the deletion.

#### K7 — delete the `PARENT` line of surface #3 (deletion)

**Position + operation:** delete the `PARENT` line from the `COMPONENT: workspace_body` block in
this batch's record.

```
REMOVING line 846: '  PARENT : workspace_shell'

[x] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: no PARENT declared — write `SYSTEM` if it is the top of the boundary
5 block · 283 notice · 14 not applicable
```

**Verdict: prediction confirmed, and it does two jobs.** The standing `[!]` NOTICE becomes an
`[x]` **BLOCK**, which (i) proves the `PARENT` field is **read** rather than defaulted — directly
refuting the C-31 reading that the honest declaration could have been omitted and still passed —
and (ii) proves **V12 is BLOCK-capable on this real corpus**, which is the positive control that
lets `AT-B87-03`'s "0 V12 BLOCK rows" be an observation rather than a silenced rule. The notice
count falling 284 → 283 is the same finding from the other side: the residual notice was consumed
by the block.

#### K8 — delete the canon clause mirroring one batch-87 id (deletion)

**Position + operation:** delete the single canon line in `REQUIREMENTS.md` that mirrors
`LLR-87.6`, keeping every neighbouring line verbatim.

```
REMOVING line 6177 (the LLR-87.6 clause)

per-id grep for LLR-87.6 : 1 -> 0
per-id grep for LLR-87.5 : 3 -> 3           <- the INERT arm; the neighbour is untouched
[!] V22  REQUIREMENTS.md: 277 of 544 batch-declared ids are not reflected in the living canon (HLR 75 · LLR 194 · US 8)
2 block · 284 notice · 14 not applicable
```

**Verdict: prediction confirmed, and batch-86's M7 lesson is measurably ADOPTED.** batch-86
measured that its canon mirror **packs two ids per line**, so a whole-line deletion moved V22 by
**+2** and refuted its prediction. This batch's canon tranche writes **one id per line**, so the
whole-line shape and the surgical shape coincide and the aggregate moves by exactly **+1**
(276 → 277) while the neighbour id still greps 3. G8's per-id predicate is proven sensitive
per id, which is the only form in which the aggregate may be called secondary.

#### Arms discharged by live RED or by citation, with the reason stated

| Arm | Disposition | Why |
|---|---|---|
| **K2** (delete one `INPUTS` name → V12 BLOCK naming the parent) | **discharged by a LIVE RED on the real corpus** | the record's §5.6 **state A** transcript carries `[x] V12 … COMPONENT loaded_panel: emits artifact_row_set, unload_all_row, which screen_workspace does not declare — unbalanced`, taken on the merged corpus during authoring and cleared by exactly the edit LLR-87.5 mandates. That is the balancing rule reddening and greening on this record — stronger than a synthetic arm. Its parent-side twin is K7 above, executed this phase |
| **K4** (delete an `owner` line → V21 BLOCK) | **discharged by LIVE REDs** | §5.6 states A and B carry **6** and **8** `[x] V21 … names owner …, which no document in the corpus defines` rows respectively, at named `file:line` positions, cleared by this record declaring the owner headings |
| **K5** (omit `consumers` → V11 BLOCK) | **executed batch-locally**, better than `01b`'s "cite, do not re-execute" | the V11 BLOCK in K3's first arm above |
| **K6** (duplicate the COMPONENT anchor → V19 NOTICE naming both positions) | **not owed batch-local; cited** | `01b` §3 made K6 conditional on `D-87-A` resolving toward a shape that re-declares an id. It did not: V19 reports **3 COMPONENT id(s), each declared exactly once**, live. The duplicate-anchor behaviour is covered by the record's M-4 arms 1 and 4 and by the shipped selftest |
| **K9** (append a byte to a derived file → V20 drift BLOCK) | **cited, plus four free REDs observed** | every mutated copy in this phase printed the four `[x] V20 … committed copy differs from what the corpus derives` rows without being asked; the increment's own first post-edit run read `2 block` for the same reason (`03-increments/increment-001.md` §4 Gate 2). A manufactured arm would add nothing |

### Layer 0 — unit

**n/a — no population.** The increment authored **0 source files**
(`03-increments/increment-001.md` §4 Gate 3: `git diff --stat 943e54a -- s19_app/` empty at exit
0), so no unit meets either criterion. Stating "n/a" is the honest form. The mutation discipline
the layer exists to enforce is **not** skipped — it is relocated to the record and discharged by
K1, K3, K3b, K7 and K8 above, which redden the real rules over the real corpus.

### UX walkthrough — trigger family D

**Did not fire.** Nothing this batch writes changes what a TUI user sees or touches: the
source-scope diff is empty, and the batch's edits are three `.dev-flow/` records plus one canon
section in `REQUIREMENTS.md`. **Mechanism used: none, and no inspection is claimed either** —
there is no interaction to inspect. **Evaluation with real users was NOT performed**
(ISO 9241-210), and nothing here implies it was needed.

### Layer A — functional (white-box): per-requirement results

Method is `inspection (executed)` for every row except the two `analysis` rows: the validator is
operator-local and lives outside the repository, so a `test` label would assert a pytest node that
cannot exist (C-18). **Every Executed-verification cell below was checked to resolve to a real
transcript**, and the counted figures were **re-measured live by this phase** rather than copied
from the record.

| Req | Method | Executed verification (cited transcript) | Numeric threshold | Result | Evidence measured this phase |
|---|---|---|---|---|---|
| HLR-87.1 | inspection (executed) | record §5.6 pre-state (M-1, M-2) and post-state; live run this phase | V19 = 3 COMPONENT ids each declared once · UNPARSED census = 1 item with **0** of class `[IFC]` · the pilot block declares 6 outputs | **pass** | live `[-] V19 … 3 COMPONENT id(s), each declared exactly once`; `ATLAS-ORPHANS.md` on disk reads `UNPARSED census: 1 item(s)` and its only bullet is the `[BATCHES]` one. **Sensitivity proved by K1**, which raises the census to 2 |
| HLR-87.2 | inspection (executed) | record §5.6 post-state; M-4 arms; live run this phase | exactly **1** V12 finding naming `workspace_body` and `workspace_shell` · **0** naming `screen_workspace` or `loaded_panel` · V11, V14, V21 at §5.6's figures with **0** BLOCK | **pass** | live V12 is a single `[!]` row at the record's `:845`, naming exactly that pair; `[-] V11 … 79` · `[-] V14 … 251` · `[-] V21 … 79`; tail `0 block`. **RED arm K7** |
| HLR-87.3 | analysis | record §5.6 figure table against batch-85 §7.4 and batch-86 §5.6; effort span from `git log` | 6 of 6 figures non-null at n=3 · 1 dispersion statement in range form · 1 duplication figure from the pair census · **0** extrapolated totals | **pass at this station, CLOSE-owed** | §5.6 carries the figure table and the duplication derivation. ⚠️ The **restatement in `05-close.md` does not exist yet** — the HLR's own statement quantifies over that file. Recorded as gap **G4-02**, not counted as a failure, because the artifact is due at Phase 5 by design (`TC-B87-03` is labelled "at Phase 5" in the record's traceability table) |
| LLR-87.1 | inspection (executed) | record §5.6 census M-7, M-9; live V11, V13, V14 | **0** V11 BLOCK over the two handles · V14 resolves their 8 consumer entries · V13 stray pairs exactly 3 | **pass** | live `[-] V11` and `[-] V14` clean; V13's rows for the two handles present at the batch-85 lines. **RED arm K3b**, which shows a single deleted entry moves V14 by 1 and the pair census by 1 |
| LLR-87.2 | inspection (executed) | M-5, M-6 (runtime cardinalities 4 and 1); live V11, V13, V14 | 2 outputs replace 1 · cardinalities 4 and 1 · V13 stray pairs for both exactly **0** · 0 occurrences of the positional annotation on either | **pass** | measured live: **0** V13 rows name `artifact_row_set` or `unload_all_row` in the baseline. **That zero is exactly what K3b reddens** — the arm turns it into 1, named — so the absence is observed, not assumed |
| LLR-87.3 | inspection (executed) | M-5's second half (three cited consumer sites), M-6 | cardinality 3 and 1 · V14 resolves 7 consumer entries across the two · V13 stray pairs 1 and 0 | **pass** | the cited consumer sites resolve (`tests/test_help_toggle_and_a2l_panel.py:73`, `tests/test_unload_feature.py:260` through `:272`, `tests/test_tui_commandbar.py:1300`); live V14 clean |
| LLR-87.4 | inspection (executed) | M-3 (the mechanism, by running the parser); post-state census | **0** indented lines after the block · every parsed field ≤ the text written for it · census reports 0 `[IFC]` items | **pass** | **measured directly this phase**: the batch-85 record is **558 lines** and the block's closing fence is line **557**, so the population "every line after the block" is empty by construction. **K1 is its counterfactual** — indenting that fence re-absorbs and the census rises |
| LLR-87.5 | inspection (executed) | the live pre-fix run in §5.6 **state A** (V12 emits BLOCK) and the post-fix run where it is absent | 6 re-exported ids · **0** V12 emits BLOCKs · 0 other sections of the batch-86 document modified | **pass** | state A's `[x] V12 … emits artifact_row_set, unload_all_row … unbalanced` is a real transcript on the real corpus; live post-state has **0** V12 rows containing `loaded_panel`. This is the RED-to-GREEN transition, not an assertion |
| LLR-87.6 | inspection (executed) | M-6, M-7, M-8, M-9; live V10, V11, V13, V14 | 11 own outputs · `screen_slot_set` cardinality 10 · V13 stray pairs over the eleven exactly the 26 enumerated · 0 undeclared dependants | **pass** | live `[-] V10 … 23 FLOW node(s), every one owned` · `[-] V11 … 79` · `[-] V14 … 251, every one resolved`; V13 emits **52** rows corpus-wide, and §5.6 enumerates the per-output pairs row-for-row |
| LLR-87.7 | inspection (executed) | M-4 arm 5 (the V12 BLOCK enumerating the owed ids); M-6 (parent identity); live V12 | 31 re-exported ids · **0** V12 emits and **0** consumes BLOCKs · exactly **1** V12 NOTICE naming the pair · declared `PARENT` reads `workspace_shell` | **pass** | live V12 is that one NOTICE and nothing else; tail `0 block`. **RED arm K7**, which shows the declaration is read |
| LLR-87.8 | analysis | §5.6 figure table against M-1 through M-9 | 6 figures non-null · duplication figure derived by subtraction, never estimated · dispersion as a range · 0 extrapolated totals | **pass at this station, CLOSE-owed** | same disposition and same gap as HLR-87.3 (**G4-02**) |

**Note on the two expected unowned-LLR notices.** `LLR-87.4` and `LLR-87.8` appear in a live V22
notice, and both were **enumerated in advance** in the record's batch acceptance criteria. That is
the only form in which a standing notice may be called green. Measured live, the unowned-LLR
notices name exactly: `LLR-85.4`, `LLR-85.5`, `LLR-85.6`, `LLR-85.7` (batch-85), `LLR-86.7`,
`LLR-86.8` (batch-86), `LLR-87.4`, `LLR-87.8` (this batch) — **0 unexpected**, which is the
threshold, rather than "0 notices", which would be a lie about a staged retrofit.

### Layer B — behavioral (black-box) acceptance

The "user" is the operator auditing addressability. The shipped surface is the real
`devflow-validate` toolchain plus the Atlas generator it drives, run over the merged corpus —
the **real consumer executed against the authored records on disk**, never a hand-fed dict
(trigger B4). **Every deliverable below was re-observed live by this phase.** The
`01b`-to-record id reconciliation is the record's §3 mapping table; ids in this section are the
**record's**, which is where `01b`'s rows are realized.

| US | AT | Surface driven (shipped) | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----|--------------------------|---------------------------------------|----------------------------|--------|
| US-87-1 | `AT-B87-01` | `devflow-validate.py --atlas --write`, then a plain run | **`.dev-flow/_derived/ATLAS-ORPHANS.md` bytes on disk**: `UNPARSED census: 1 item(s)`, whose only bullet is `- [BATCHES] .dev-flow/2026-07-23-batch-n8`; **no** line begins `- [IFC]` | ✓ · ✓ · ✓ | **pass** |
| US-87-1 | `AT-B87-02` | same run, V12 filter | stdout: **0** V12 rows whose message contains `loaded_panel`; V19 reports each COMPONENT id declared exactly once | ✓ · ✓ · ✓ | **pass** |
| US-87-2 | `AT-B87-03` | same run, V12 filter | stdout: **exactly one** V12 finding, and it names `workspace_body` and `workspace_shell` — the enumerated residual, at the record's `:845`; **0** V12 BLOCK rows | ✓ · ✓ · ✓ | **pass** |
| US-87-2 | `AT-B87-04` | `--atlas --write`, then the file's bytes | **`.dev-flow/_derived/ATLAS-IFC.md` bytes on disk**: `### COMPONENT` heading total = **3**, one of them naming `workspace_body` at `:96`; each declaration keeps its own row set, no collapse | ✓ · ✓ · ✓ | **pass** |
| US-87-1 + US-87-2 | `AT-B87-05` (PIN) | git | `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` → **empty output, exit 0** | ✓ · ✓ · n/a | **pass** |
| US-87-1 + US-87-2 | `AT-B87-06` (PIN) | the orchestrator's gate suite run | `6 failed, 2702 passed, 3 skipped, 21 deselected, 3 xfailed`, one complete run | ✓ · ✓ · n/a | **pass** — ledger reconciles; all 6 failures dispositioned pre-existing under the criterion adopted at this gate, each with a measured isolated rate |

**Arm provenance — where each boundary and negative arm was actually executed.** This is the
column that stops an AT from being a claim.

| AT | representative | boundary | negative / error |
|---|---|---|---|
| `AT-B87-01` | live `ATLAS-ORPHANS.md`, census 1, surviving bullet read as TEXT not as a count | the surviving `[BATCHES]` bullet is the **positive control** in the same census block — the renderer still emits | **K1 (this phase, copy):** re-absorb one line → `UNPARSED census rose 1 -> 2`, V20 BLOCK. The `[IFC]` class reappears |
| `AT-B87-02` | live V12, **0** rows containing `loaded_panel` | the split changes the emitted id set by one removal and two additions, and both directions ran | **the record's §5.6 state A LIVE BLOCK** on the real corpus (`emits … which screen_workspace does not declare`), cleared by the LLR-87.5 edit; plus **K3b** for the consumer-set limb |
| `AT-B87-03` | live V12, exactly one NOTICE, pair named | the `INPUTS` superset is exact and M-4 arm 5 ran with that set | **K7 (this phase, copy):** delete the `PARENT` line → the NOTICE becomes a `[x]` **BLOCK**. This is also the positive control proving V12 is BLOCK-capable here, which is what makes "0 V12 BLOCK rows" an observation |
| `AT-B87-04` | live `ATLAS-IFC.md`: 3 `### COMPONENT` headings at `:41`, `:56`, `:96` | the predicate is the **heading form**, not a bare substring — the bare grep returns 2 in the pre-state and is green before any work (R2-06) | **negative control in the same probe:** the `screen_workspace` heading returns 1 in the pre-state **and** 1 in the post-state, so a post-state 1 for `workspace_body` is a change and not an artifact of the predicate |
| `AT-B87-05` | empty diff, exit 0, executed this phase | the scope names four source paths explicitly, in merge-base form | **executed this phase:** the same command with `.dev-flow/` added returns **12 files changed, 2766 insertions, 172 deletions** — the diff command is not a silent no-op |
| `AT-B87-06` | the orchestrator's one complete run | the six failures dispositioned node-by-node, each with an isolated rate at N = 10 | **the disposition rule itself was the refuted arm** — the `n = 1` "passes isolated" check was executed against its own claim and failed it (4 of 10). The rule was replaced at this gate; see the blocker section |
| G8 (canon) | increment gate: 13 ids each grep ≥ 1 (`03-increments/increment-001.md` §4 Gate 1) | one grep per id, one id per line | **K8 (this phase, copy):** remove one id's clause → that id 0, the neighbour still 3, V22 +1 exactly |

### Bidirectional surface-reachability matrix

Every named INPUT dimension and every named OUTPUT or deliverable, exercised or observed through
the **real handler** — a validator process reading files off disk and an Atlas generator writing
them — never through an in-memory API.

| Direction | Dimension / deliverable | Producer / consumer | Reached or observed at the surface? | AT / gate | Status |
|---|---|---|---|---|---|
| input | `PARENT` field of the COMPONENT header | the record's IFC block, parsed by the header parser; judged by V12 | **yes** — V12 quotes `workspace_shell` back by name; **K7** proves the field is read, not defaulted | `AT-B87-03` · G2 | ✓ |
| input | `INPUTS` name list | same block; V12 containment | **yes** — the record's M-4 arm 5 BLOCK enumerated the owed ids name-by-name; batch-86's M5 is the same limb one level down | `AT-B87-03` | ✓ |
| input | OUTPUT declarations (id + address literal) | same block; V11, V19, V13 | **yes** — V11 counts 79 and V13 greps each address literal across the corpus, emitting 52 rows | `AT-B87-02` · G5 | ✓ |
| input | consumer entries | same block; V14 resolution + V13 stray classification | **yes** — V14 resolves 251; **K3b** shows one deleted entry moves V14 by 1 and names a new stray pair | `AT-B87-02` · G6 | ✓ |
| input | `owner` id on each OUTPUT | same block; V21 + V22's unowned-LLR check | **yes** — V21 counts 79 owners, every one declared; §5.6 states A and B carry 6 and 8 live owner BLOCKs before the headings existed | `AT-B87-02` · G5 | ✓ |
| input | canon mirror id lines | `REQUIREMENTS.md`, read by V22 and by the per-id grep loop | **yes** — 13 of 13 per-id greps at the increment gate; **K8** proves the read is sensitive per id | G8 | ✓ |
| output | counted validator verdicts | `devflow-validate` stdout | **yes** — pasted from one read-only run below | `AT-B87-02` · G5 | ✓ |
| output | the balancing verdict for surface #3 | V12 | **yes** — observed as one specific NOTICE with its `file:line`, with **K7** as its counterfactual | `AT-B87-03` · G2 | ✓ |
| output | the balancing verdict for the pilot | V12 | **yes** — observed as an **absence** (0 rows containing `loaded_panel`) with the state-A BLOCK as its positive control | `AT-B87-02` · G3 | ✓ |
| output | the UNPARSED census | **`.dev-flow/_derived/ATLAS-ORPHANS.md` on disk** — 1 item, the `[BATCHES]` bullet | **yes** — read off disk as TEXT, not inferred from V20's word; **K1** raises it | `AT-B87-01` · G1 | ✓ |
| output | the derived IFC Atlas | **`.dev-flow/_derived/ATLAS-IFC.md` on disk** — 3 `### COMPONENT` headings at `:41`, `:56`, `:96` | **yes** — read off disk. V20's currency line does **not** imply rendering, which is why G7 and G10 are separate gates | `AT-B87-04` · G10 | ✓ |
| output | source-scope neutrality | `git diff --stat` over the four declared paths | **yes** — empty output, exit 0, with the non-empty widened-scope control | `AT-B87-05` · G9 | ✓ |

**0 gaps.** Every output row observes a **thing** — a stdout line or a file's bytes — never only
"the command exited 0". An exit code is not a deliverable.

### Supersession-completeness inspection

| Superseded marker | Live grep result | All surviving refs negative? | Evidence |
|---|---|---|---|
| batch-86's V12 NOTICE *"COMPONENT screen_workspace: parent `workspace_body` is not declared … NOT checked"* at `.dev-flow/2026-08-24-batch-86/01-requirements.md:386` | **0 occurrences** in the live validator output | **yes** — the only surviving references are this batch's own **absence assertions** (the record's §5.6 pre-state, `AT-B87-03`, and this row). No artifact depends on the notice still firing | live V12 emits a single `[!]` row, at `.dev-flow/2026-08-24-batch-87/01-requirements.md:845`. **Positive control:** that surviving row proves V12 still emits NOT-checked notices where they apply, so the absence is a real retirement and not a silenced rule. **Second control:** **K7** makes the rule speak again — as a BLOCK |
| the pilot's `slot_rows` union OUTPUT, re-exported verbatim by batch-86 | superseded by `artifact_row_set` and `unload_all_row` in both records | **yes** | the record's §5.6 **state A** BLOCK is the observed RED of the half-migrated state; the live post-state has 0 V12 rows containing `loaded_panel` |

### Signed-balance test ledger

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|---|---|---|---|---|---|---|
| **2714** selected (2735 collected − 21 deselected) | **0** | **0** | **2714** | **2714** | **2702 passed · 6 failed · 3 skipped · 3 xfailed** — one complete run, 2443.72 s (0:40:43), process exit 1 | **✓ with the 6 dispositioned pre-existing under the adopted criterion** |

**Arithmetic, checked term by term:** `2702 + 6 + 3 + 3 = 2714` ✓ and `2735 − 21 = 2714` ✓. The
21 deselected are the `slow`-marked stress and perf smoke nodes excluded by `-m "not slow"`; the
collection figure `2714/2735 tests collected (21 deselected)` was verified independently this
session.

**`D = 0` and `A = 0` are PROVED, not assumed.** `git diff --stat 943e54a -- tests/` produces
empty output at exit 0, so the `tests/` tree is byte-identical to merge-base and `post = base` is
structural whatever the base turns out to be. The increment record says the same from the other
direction (`03-increments/increment-001.md` §4 Gate 3).

**Disposition of the 6 failures: all six PRE-EXISTING**, under the class-membership criterion
adopted at this gate — 4 timing races (isolated rates 1 of 10, 4 of 10, 1 of 10, 4 of 10) and 2
order-dependent (0 of 10, 0 of 10), every rate a measured figure. What did **not** hold, and was
replaced rather than patched, is the pre-registered claim about *which* nodes may fail and *why*.
Eleven node ids carried to close.

### Gate criterion set G-87 — status at Phase 4

Every LIVE gate below was **re-measured by this phase** on the live tree, read-only.

| Gate | Status at Phase 4 | Pointer (executed this phase unless noted) |
|---|---|---|
| **G1** (headline) | **GREEN** | `ATLAS-ORPHANS.md` on disk: `UNPARSED census: 1 item(s)`, sole bullet `- [BATCHES] .dev-flow/2026-07-23-batch-n8`; **0** lines beginning `- [IFC]`. Counterfactual **K1** (census rises 1 → 2) |
| **G2** (headline) | **GREEN** | live V12 is exactly one `[!]` row, naming `workspace_body` and `workspace_shell` at the record's `:845`; **0** rows name `loaded_panel` or `screen_workspace`. Counterfactual **K7** |
| **G3** | **GREEN** | live V12: **0** rows whose message contains `loaded_panel`. Its RED arm is a real run — the record's §5.6 **state A** `[x] V12 … unbalanced` |
| **G4** | **GREEN** | `[-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once` |
| **G5** | **GREEN** | `[-] V10 … 23 FLOW node(s), every one owned` · `[-] V11 … 79 OUTPUT(s)` · `[-] V14 … 251 declared consumer(s), every one resolved` · `[-] V21 … 79 OUTPUT owner(s), every one declared`; final line `0 block · 284 notice · 15 not applicable`. The tail is `0 block` outright, so the attribution clause over the three batch directories and `_derived/` is satisfied trivially and honestly |
| **G6** | **GREEN** | live V13 emits **52** rows; §5.6 enumerates the pair set row-for-row as an addition of disjoint per-line sets. Counterfactual **K3b**, which adds one **named** pair while leaving V11 clean — and **K3**'s first arm, which shows why the field-line shape moves two entries and not one |
| **G7** | **GREEN** | `[-] V20  .dev-flow/_derived/: atlas current (4 files, census 1)` — census as in G1. ⚠️ **will re-red when this file lands**, see the note below |
| **G8** | **GREEN at the increment gate; CLOSE re-measurement owed** | `03-increments/increment-001.md` §4 Gate 1: 13 of 13 declared ids grep ≥ 1, one grep per id. Live secondary: `[!] V22  REQUIREMENTS.md: 276 of 544 … (HLR 75 · LLR 193 · US 8)`, at or below the 278 batch-open baseline. Counterfactual **K8** (+1 per id, neighbour inert). CLOSE must re-measure because V22 moves whenever any batch adds ids |
| **G9** (PIN) | **GREEN** | source-scope diff empty, exit 0, with the widened-scope non-empty control |
| **G10** | **GREEN** | `ATLAS-IFC.md` on disk: `grep -c '^### COMPONENT '` = **3**, at `:41` (`loaded_panel`), `:56` (`screen_workspace`), `:96` (`workspace_body`). The `screen_workspace` heading returns 1 in both states — the negative control. Currency (G7) does not imply rendering, which is why this gate is separate |
| **G11** (PIN) | **GREEN** | the ledger table above: `2714 = 2702 + 6 + 3 + 3` and `post = 2714 − 0 + 0`, with all 6 failures dispositioned pre-existing under the criterion adopted at this gate, each carrying a measured isolated rate at N = 10 rather than the word "passes" |

> **G7 fixpoint note, disclosed rather than smoothed.** `.dev-flow/**` is corpus input, so **this
> file re-stales the Atlas the moment it exists**: `ATLAS-BATCHES.md` is a batch file inventory and
> this is a new file in the batch directory. The V20 reading quoted above was taken **before** this
> artifact was written. **This phase deliberately did not run `--atlas --write`** — its mandate is
> to write one file, and writing derived files is outside it. **The orchestrator owes one
> `--atlas --write` plus a confirming re-run before close**, and the expected shape is a single
> `[x] V20 … ATLAS-BATCHES.md` that clears on regeneration with every counted figure identical
> either side of it. Ids in this file are described rather than minted, so the id-space should not
> move.

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|---|---|---|---|---|
| **G4-01** | `AT-B87-06` / G11 / `01b` §7 | **The pre-registered flaky-node disposition is refuted by measurement.** 5 of 6 failing nodes are off-list; 5 of 6 pre-registered nodes did not recur; 3 of 6 failing nodes fail in isolation, including the one on-list node (4 of 10) | **BLOCKER — RULED at this gate, now CLOSED** | **RULED 2026-08-24 by the orchestrator: the class-membership criterion is ADOPTED VERBATIM** (empty source-scope diff vs merge-base **AND** N ≥ 10 isolated re-runs **AND** signature within the recorded family, rate recorded **as a figure**, never "passes"). Grounds: **C-53** — the `n = 1` binary just false-failed correct work — and the batch's own method, the figure over the narration. The 3 isolated failures are **pre-existing timing races of the modal push/mount family, NOT product blockers**, on the structural evidence (0 source files, empty diff, no ordering plugin). **Done at this gate:** `01b-qa-validation-plan.md` §7 carries the Before/After amendment with the refuted BEFORE text kept verbatim; the disposition table is restated under the criterion; **11 node ids enumerated for the `BACKLOG-CODE.md` carry**, with the n = 1 vacuity finding attached |
| **G4-02** | HLR-87.3 / LLR-87.8 | Both quantify partly over `05-close.md`, which does not exist yet. Their §5.6 half is executed and passes; their close-record half cannot be checked at Phase 4 | minor (declared, due at Phase 5 by design) | `TC-B87-03` is already labelled "at Phase 5" in the record's traceability table. Phase 5 restates the six figures beside surfaces #1 and #2 with the range-form dispersion statement. **Not counted green here** |
| **G4-03** | `01b` §7 protocol | The prescribed invocation `conda run -n s19env python -m pytest …` **cannot complete on this corpus** — it dies with `UnicodeEncodeError` under `cp1252` and destroyed the first gate run's evidence entirely | major (found by execution) — **CLOSED at this gate** | **Done:** `01b-qa-validation-plan.md` §7's amendment block carries the direct-interpreter form as the AFTER invocation, with the `conda run` command kept in the BEFORE table and the reason stated. Also recorded in the probe-incident note above, so the next batch does not rediscover it at the cost of a 40-minute run |
| **G4-04** | `01b` §3 K1 | K1 as specified is **inapplicable**: it asks for the first prose line following the block's last field, and no such line exists — the batch-85 record ends at the block's closing fence (line 557 of 558) | minor (finding, not a defect) | The arm was re-shaped to a pure indent change on the fence line and executed; the substitution and its reason are recorded above. Future statements of K1 should say "the first line at or after the block's terminator", which is applicable in both file shapes |
| **G4-05** | `01b` §2 id note | `AT-B87-*` and `TC-B87-*` are letter-initial and therefore ungoverned by `AT-TC-REGISTRY.jsonl`, exactly as `AT-B86-*` was. The record's own §3 already records the consequence: two Phase-1 artifacts minted overlapping `AT-B87-*` ids with different meanings and nothing mechanical caught it | minor (pre-existing, already dispositioned) | No action proposed here beyond the record's amendment of D-87-F's cost cell. Noted so the postmortem has it in one place |

### Escaped-bug regression

**None — no defect escaped the suite, because this batch ships no product code.** There is no
shipped-surface regression to write and no counterfactual owed. The nearest analogues are all
**caught before shipping**: the P2 iteration's spliced-evidence defect (one fence carrying two
mutually exclusive states, R2-01), the false pre-state grep in the qa plan's `AT-B87-06` (R2-06),
and the dropped Atlas-rendering acceptance (R2-07) — each corrected in the record with a
re-measurement rather than an argument.

### Live validator run, read-only, at this artifact's authoring

Taken **before** this file existed, so it is the state the gates above were measured against.
This phase ran the validator only in read mode and never with `--write`.

```
[-] V10  01-requirements.md: 23 FLOW node(s), every one owned
[-] V11  01-requirements.md: 79 OUTPUT(s), each with an address and a declared consumer list
[!] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
[-] V14  01-requirements.md: 251 declared consumer(s), every one resolved
[-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once
[-] V20  .dev-flow/_derived/: atlas current (4 files, census 1)
[-] V21  01-requirements.md: 79 OUTPUT owner(s), every one declared
[!] V22  .dev-flow/2026-08-21-batch-85/01-requirements.md: LLR(s) never used as an owner — LLR-85.4, LLR-85.5, LLR-85.6, LLR-85.7
[!] V22  .dev-flow/2026-08-24-batch-86/01-requirements.md: LLR(s) never used as an owner — LLR-86.7, LLR-86.8
[!] V22  .dev-flow/2026-08-24-batch-87/01-requirements.md: LLR(s) never used as an owner — LLR-87.4, LLR-87.8
[!] V22  REQUIREMENTS.md: 276 of 544 batch-declared ids are not reflected in the living canon (HLR 75 · LLR 193 · US 8)
0 block · 284 notice · 15 not applicable
```

V13's rows are not re-pasted here: there are **52** of them, they are enumerated per output in the
record's §5.6, and this phase verified the count and the two zero-rows that LLR-87.2's threshold
turns on (**0** rows naming `artifact_row_set`, **0** naming `unload_all_row`) — the exact figures
**K3b** reddens.

Derived files read off disk in the same state:

```
.dev-flow/_derived/ATLAS-ORPHANS.md   UNPARSED census: 1 item(s)
                                      - [BATCHES] .dev-flow/2026-07-23-batch-n8 — dated dir does not match the batch pattern — census, not silence
.dev-flow/_derived/ATLAS-IFC.md       ### COMPONENT headings: 3
                                      :41  loaded_panel      — .dev-flow/2026-08-21-batch-85/01-requirements.md:504
                                      :56  screen_workspace  — .dev-flow/2026-08-24-batch-86/01-requirements.md:386
                                      :96  workspace_body    — .dev-flow/2026-08-24-batch-87/01-requirements.md:845
```

### Evidence checklist — qa-reviewer (full)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✓ | the record's §3 uses the batch's fixed **Observable outcome / Shipped surface / Deliverable + observation / Boundary catalog** form — this project's Given/When/Then equivalent and the one its gate table indexes. Conforming to the codebase's convention over the template's wording (global rule 11), flagged here rather than forked silently |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | every Layer A row carries a numeric threshold (23 · 79 · 251 · 3 · 79 · 52 · 1 · 276) and every mutation states its expected flip **before** its transcript — including the one that was **wrong** (K3's V14 −1 prediction, measured −2) |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | **empty** = the 0-row V13 baseline for the two split outputs, reddened by **K3b** · **boundary** = **K3b**'s one-entry deletion and **K8**'s one-id deletion, each with a named inert arm · **invalid** = **K1**'s re-absorbing indent and **K7**'s missing `PARENT` · **error** = the shipped selftest arm `V14 BLOCK-nofile` (`devflow-validate.py:2667`) for the absent-file mode, cited because V12 and V13 have no file-resolution failure mode and saying so beats inventing an arm |
| 4 | Regression checklist exists | ✓ | the supersession-completeness table (two superseded markers, each with a positive control and a counterfactual) + all eleven G-87 rows **re-measured live at this gate** + the node-by-node flaky disposition |
| 5 | Exit criteria stated | ✓ | the Verdict block: 6 ATs observed with arm provenance, 11 of 11 requirements pass, 0 reachability gaps, ledger reconciles, all 6 suite failures dispositioned pre-existing with measured rates — **and the one BLOCKER stated FIRST, before the verdict**, then ruled by the orchestrator and closed by amending the rule it refuted rather than by relaxing the reading. An exit criterion that hides a refuted gate rule is not an exit criterion |
| 6 | No real PII / secrets | ✓ | repo-relative paths, validator stdout, pytest node ids and git metadata only. The one absolute path that appears is the environment interpreter, which is required to state the harness finding and carries no credential |
| 7 | Results left blank unless actually run | ✓ | the suite was run **once, by the orchestrator** (C-25) and consumed from its own output file; every isolated re-run, every mutation arm and every live validator figure in this artifact was executed by this phase. **Nothing is asserted that was not run**, and the two CLOSE-owed analysis halves are marked owed rather than green (**G4-02**) |
| 8 | **Layer B** — deliverable observed through the SHIPPED surface, with boundary + negative evidence | ✓ | the Layer B table plus the arm-provenance table: `AT-B87-01` and `AT-B87-04` observe `.dev-flow/_derived/` **bytes on disk**, not V20's word for it; boundary and negative arms are **K1, K3, K3b, K7, K8 executed this phase on copies**, plus the record's own LIVE state-A BLOCK on the real corpus |
| 9 | **Bidirectional surface-reachability** | ✓ | the 12-row matrix, **0 gaps**. Six input dimensions are each reddened by a **distinct** arm — `PARENT` by K7, `INPUTS` by the state-A and M-4 arm-5 BLOCKs, OUTPUT declarations by K1, consumer entries by K3b, `owner` ids by the state-A and state-B V21 BLOCKs, canon lines by K8 — which is what distinguishes "reached" from "present" |
| 10 | **No unfilled template** | ✓ | 0 placeholders of the `<...>` form, 0 `TC-NNN` stubs, 0 empty required rows. The rows that are `n/a` (Layer 0, UX walkthrough, escaped-bug) say **why** the population is empty; the rows that are owed say **who** completes them and **when** |
| 11 | **C-56** — no mangled token spelled; kill mutations run on copies, live tree never mutated | ✓ | every arm is described by **position + operation**, and the only operations are deletion and indent change, so no phantom id is written into this file for the Atlas id-scanner to adopt. Five copies made and discarded; `git status --porcelain` scoped to the mutated paths returned **empty after every arm** |

**An item without a citation is not satisfied — it is asserted.**
