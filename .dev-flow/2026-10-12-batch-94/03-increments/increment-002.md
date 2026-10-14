# Increment 002 — HLR-013…016 · `fb_a Flow Builder + B2 move + templates`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/increment-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `SOURCE files` · `Instrument RED-proof` · `Correction population` · `Mutation verdicts` · `Emitted-form assertion` · `Reverse census` · `RED counterfactual` · `Independent review` · `Evidence files` · `Traces to` · `File` · `Kind` · `source` · `test` · `doc` · `config` · `generated` · `fixture` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Where this lives:** the **repo**, next to the diff it describes —
> `.dev-flow/2026-10-12-batch-94/03-increments/increment-002.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

> **A table you may delete.** A table whose `| **Field** |` row reads `none — <reason>`, or whose question one line of the gate checklist answers, may be deleted, its field row kept: `stations/core-runbook.md` §*A minimal increment packet* is a one-function change written that way.

| Field | Value |
|---|---|
| Batch | `2026-10-12-batch-94` |
| Increment | `002` |
| Lane (if the batch forked) | `none — single-lane trunk batch` · `n/a` (§2.8 fork preconditions, the declared empty; one worktree, one lane) |
| Requirement(s) | `US-005` · `HLR-013…016` · `LLR-013.1/.2/.3` · `LLR-014.1/.2` · `LLR-015.1/.2` · `LLR-016.1` (the realized Inc-002 subset) |
| Acceptance | `AT-B94-15…18` (4 black-box) · `TC-B94-04, 20…25` (7 white-box) · unit layer-0: none minted standalone — the layer-0 candidates host inside the named TCs (`design-proposal.md` §5) |
| Agent | `software-dev` |
| Date | `2026-10-14` |

---

## 1 · What changed

*(BLUF: state the outcome first, then the mechanism. Name the shipped surface the user reaches.)*

**BLUF.** The Flow Builder is no longer the list-based tracer. `FlowBuilderPanel` moved to its new
R8 address `s19_app/tui/flow_screens.py` (the B2 move, with `app.py`'s import repointed in the same
commit) and carries the fb_a rework: a **block-palette rail** with the three placeable types
(patch · CRC · A2B-diff), a **framed canvas** painted by the NEW `_Grid` painter (`┤├` typed in/out
stubs, `─│└┐` cable runs, `·` grid dots, box-drawn block frames), and an **A2B diff block** whose two
image inputs bind — per the HLR-014 grammar — to a flow output (`#n.out`) or an external file, with
the "≥1 input from the current flow" rule enforced at wiring time and each input's provenance stated
in the emitted report. Saving a flow persists a named template under `flows/*.json` with
dedup-suffix collision handling (never a silent clobber). Realized story: **US-005 →
HLR-013…016.** 11 test nodes minted (one AT = one on-disk node per C-18): AT-B94-15…18 and
TC-B94-04, 20…25. The user reaches all of it through the existing `8` rail entry — the rail itself
is untouched (11 entries; the Flow Execution entry and the `]` key are Inc-003).

**Mechanism, seam by seam:**

1. **The B2 move** — `FlowBuilderPanel` (and its runner wiring) left `screens_directionb.py`
   (759-line vacate, pure removal — the only remaining mention there is a tombstone module-docstring
   line) and reopened at `flow_screens.py` (NEW, 1 272 lines, R8). `app.py` repoints the import and
   the two type references in the same commit (2-line diff). Every other reader (5 test files + the
   two service modules' doc refs) re-pointed in-commit per the C-2 census (§4 Reverse census).
2. **fb_a palette + canvas + cables** (HLR-013, AT-B94-15 / TC-B94-20) — the palette rail composes
   one `Button` per placeable kind (`flow_palette_{patch,crc,a2b}`); the canvas is append-built
   literal `Text` on a `markup=False` Static — zero `from_markup` / `markup=True` sites anywhere in
   the module (the `test_tc_042_10` source census FOLLOWS the moved panel, C-17). Empty canvas
   renders the empty state; placed blocks render typed stubs and at least one cable run inside the
   boxed 96×18 workspace at 120×30.
3. **A2B block + binding grammar** (HLR-014, AT-B94-16 / TC-B94-23/24) — `flow_model.py` gains
   `BLOCK_A2B`, the `A2BBlock` dataclass, `parse_a2b_binding` (the operator-typed text grammar:
   `#n.out` flow bindings and bare file names) and `validate_a2b_bindings` — refused at wiring time:
   both-external, cross-flow, out-of-range/downstream/self references, flow bindings to non-image
   outputs (A2B/REPORT), and any malformed binding (0 reports produced). Accepted: (flow,flow),
   (flow,file), (file,flow).
4. **Templates** (HLR-015, AT-B94-17 / TC-B94-04) — `save_flow_json` gains the builder-template
   envelope branches (per-kind serialization incl. the A2B bindings) and the dedup-suffix collision
   rule; the empty arm saves the zero-block flow as the schema-v1 envelope (§6). `dict_to_flow`'s
   V1–V7 fail-closed read path is additive-extended, never re-opened (§4, batch-95 compat).
5. **A2B run arm + provenance** (HLR-013/014, TC-B94-22/24) — `flow_execution_service.py` runs the
   A2B block through the existing `generate_diff_report` producer under `reports/*flow-a2b*.md`,
   emitting one `- Image X: …` provenance line per input (`[flow]` lines name the producing block,
   e.g. `block 2 (patch).out`; `[external]` lines match the executed base form pinned by
   `p1_probe_diff_report_emitted.txt`). Union-compatible with batch-95's change-attribution: the
   same `run_flow` populates both `result.change_records` (batch-95's ReportBlock reads them) and
   the A2B results (§4 reverse census A3).
6. **Markup safety** (HLR-016, AT-B94-18 / TC-B94-25) — every file-derived string on the canvas and
   in the report rides `safe_text` / `markdown_safety.md_safe` (`Mode-A` cells never carry a raw
   path); the hostile payload renders literally — 0 markup spans, 0 control bytes.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/flow_screens.py` | source | HLR-013 · HLR-014 · HLR-016 · LLR-013.1 · LLR-014.1 | NEW (R8, 1 272 lines) — `FlowBuilderPanel` at its B2 address: the palette rail (`_PALETTE_TYPES`), the framed canvas + NEW `_Grid` painter, the A2B block compose with the `#flow_ref_a`/`#flow_ref_b` binding inputs, the wiring-notice arm, template save control; every file-derived string markup-safe (C-17) |
| `s19_app/tui/services/flow_model.py` | source | HLR-014 · LLR-013.2 · LLR-014.1 | `BLOCK_A2B` + `A2BBlock` + `A2BInputBinding` + `parse_a2b_binding` + `validate_a2b_bindings` — the binding grammar and the ≥1-from-this-flow wiring rule (additive to batch-95's flow shapes) |
| `s19_app/tui/services/flow_persistence_service.py` | source | HLR-015 · LLR-013.2 · LLR-015.1/015.2 | builder-template save: per-kind serialization branches incl. the A2B bindings (TC-B94-21 round-trip), the dedup-suffix collision rule (AT-B94-17/TC-B94-04), the zero-block v1-envelope empty arm (TC-B94-04); V1–V7 fail-closed read path additive-extended only |
| `s19_app/tui/services/flow_execution_service.py` | source | HLR-013 · HLR-014 · LLR-013.3 · LLR-014.2 | the A2B run arm through `generate_diff_report` (provenance lines per input, `filename_stem="flow-a2b"`), upstream-failure arms (`skipped` downstream, 0 writes — TC-B94-22, the C-1 re-arm); union-compatible with batch-95's change-records (`result.change_records` populated on the same run) |
| `s19_app/tui/app.py` | source | HLR-013 | the B2 repoint only — the `flow_screens` import + the two `FlowBuilderPanel` type references (2-line diff; the rail tuple and routing untouched) |
| `s19_app/tui/screens_directionb.py` | source | HLR-013 | the vacate side of the B2 move — 759 lines removed, pure removal; the only surviving mention is a tombstone module-docstring line (doc-only, 0 live refs) |
| `tests/test_tui_flow_builder_b94.py` | test | HLR-013 · HLR-014 · HLR-015 · HLR-016 · LLR-013.1 · LLR-014.1/.2 · LLR-015.1/.2 · LLR-016.1 | NEW — AT-B94-15/16/17/18, TC-B94-20 (the fb_a surface, wiring rule + report provenance, template dedup, hostile names) |
| `tests/test_flow_a2b_b94.py` | test | HLR-014 · HLR-015 · HLR-016 · LLR-013.2/.3 · LLR-014.1/.2 · LLR-015.1/.2 · LLR-016.1 | NEW — TC-B94-04 (save/reload/dedup/sanitiser/empty arms), TC-B94-21…25 (round-trip, run records, binding matrix, provenance paste, md mode truth table + hostile report arm) |
| `tests/test_flow_builder_render.py` | test | HLR-013 | rewritten — the B2 import repoint (1 line) |
| `tests/test_flow_crc_ribbon.py` | test | HLR-013 | rewritten — the B2 import repoint (1 line) |
| `tests/test_flow_crc_ui.py` | test | HLR-013 | rewritten — the B2 import repoint (1 line) |
| `tests/test_flow_multi_image_ui.py` | test | HLR-013 | rewritten — the B2 import repoint (1 line) |
| `tests/test_flow_report_ui.py` | test | HLR-013 | rewritten — the B2 import repoint (1 line) |
| `tests/test_tui_flow_persistence_ui.py` | test | HLR-015 · LLR-015.1 | rewritten — the B2 import repoint + the bounded-wait settle hardening (`_wait_for` poll; the load-flaky settle family, §5/§6) |
| `tests/test_tui_directionb.py` | test | HLR-013 · HLR-016 | the C-17 census FOLLOWS the moved panel — `test_tc_042_10` extended to `flow_screens.py` (0 `from_markup`, 0 `markup=True` sites; architect finding 3, second extension) |
| `tests/test_id_registry.py` | test | HLR-013 · HLR-014 · HLR-015 · HLR-016 | corpus census `EXPECTED_SCANNED_TEST_FILES` 175→177, measured (this increment's 2 new files) |

| Count | Value |
|---|---|
| **SOURCE files** | **`5` / 4 — over the cap; the PDR-declared reason is stated below** |
| Test files | `10` (uncapped) — 2 new · 5 repoint-only · 2 repoint + census/settle moves · 1 census constant |
| Doc files | `0` (outside the count) |

- ⚠ **Above 4 source files (5):** declared per the budget rule's conversation clause at the PDR
  (`design-proposal.md` §Inc-002; PLAN.md roadmap #2): `flow_screens.py` is the R8-mandated NEW home
  of the moved panel; `flow_model.py` / `flow_persistence_service.py` / `flow_execution_service.py`
  are the three one-module-one-seam contract bindings the blocks/persistence/run semantics already
  own; and **the fifth could not be avoided** — the moment `FlowBuilderPanel`'s address changes,
  `app.py`'s import and type references must repoint in the same commit (a deferred repoint leaves
  the app importing a moved panel — a stale address), and a compat re-export in
  `screens_directionb.py` was REJECTED because it would keep two live addresses and double the B2
  census surface the move exists to close. Four of the five files are contract bindings, not sprawl;
  the design/close review looks at it here, as declared. `screens_directionb.py`'s vacate is the
  removal side of the same single move, not a sixth deliverable.
- ✗ If a file belongs to another lane's file set, stop: lanes may not share a file. — n/a, one lane.

---

## 3 · How to test

```bash
# the 11 minted batch-94 nodes (ONE complete run — the battery's own baseline arm)
python -m pytest tests/test_tui_flow_builder_b94.py tests/test_flow_a2b_b94.py -q
# the 8-arm / 11-node-run mutation battery (full) + the C-20 move-aside
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc002_battery.py
# the fb_a smoke probe (canvas paste, wiring refusal, run, provenance lines)
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc002_smoke_probe.py
# the guard host (rail census 11, the from_markup census over flow_screens.py — 184 passed at gate)
python -m pytest tests/test_tui_directionb.py -q
# the 11-file flow family at the union (124 passed at gate)
python -m pytest tests/test_flow_a2b_b94.py tests/test_tui_flow_builder_b94.py tests/test_flow_builder_render.py tests/test_flow_crc_block.py tests/test_flow_crc_ribbon.py tests/test_flow_crc_ui.py tests/test_flow_execution.py tests/test_flow_execution_service.py tests/test_flow_model.py tests/test_flow_persistence.py tests/test_flow_report_fusion.py -q
# the editors + variants five-file set (52 passed at gate)
python -m pytest tests/test_tui_check_editor.py tests/test_tui_patch_editor_b94.py tests/test_tui_check_chain_b94.py tests/test_tui_variants.py tests/test_variant_execution.py -q
# the patch-family rewrite group (74 passed at gate)
python -m pytest tests/test_tui_patch_variant.py tests/test_tui_patch_big.py tests/test_tui_patch_layout.py tests/test_tui_patch_chips.py tests/test_tui_patch_card.py -q
# the snapshot matrix (3 passed + 29 xfailed, per-cell census)
python -m pytest tests/test_tui_snapshot.py -q -rf
# the batch-95 compat probes (loader-law battery + change-attribution — 86 passed at gate)
python -m pytest tests/test_flow_persistence.py tests/test_changes_symbol_entries.py -q
# the R-7 golden observers (ac6 + addendum-bound 32 passed; the batch35 pair observer)
python -m pytest tests/test_flow_report_ac6_golden.py tests/test_report_addendum_bound.py -q
python -m pytest tests/test_before_after_report.py -q
# the corpus census + registry guard (14 passed at gate)
python -m pytest tests/test_id_registry.py -q
```

(The probe/battery commands carry `PYTHONIOENCODING=utf-8` because the canvas paste prints
box-drawing characters — a stock Windows cp1252 console cannot encode them; this is the same
discipline the battery runner sets for its own subprocesses.)

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | none minted standalone — the candidates (binding-grammar parser, dedup-suffix, template sanitiser authority, md mode selection) host inside TC-B94-04/21/23/25 per `design-proposal.md` §5 | hosted arms all green (see layers A/B) |
| **A · white-box** `TC-B94-04, 20…25` ↔ LLR | `core` · `full` | 7 ids (18 collectable node instances across the 2 new files) | 7/7 ids green — the battery's ONE clean-tree baseline run of all 11 minted node-runs (`11 passed`, tail read from `inc002_battery.txt`), corroborated by the flow-family transcript (`124 passed`) and the b95-compat transcript (`86 passed`) |
| **B · black-box** `AT-B94-15…18` ↔ story, through the shipped surface | `core` · `full` | 4 ids (one AT = one node, C-18) | 4/4 green — battery baseline + the flow-family transcript (`124 passed`) + the smoke probe's shipped-surface drive (`SMOKE OK`, `inc002_smoke_probe.txt`) |

**Evidence digest — the increment's verification runs** (counts as returned by this gate's runs and
the stored transcripts cited in *Evidence files* below; the stored bytes are the authority):

- `tests/test_tui_directionb.py` — **184 passed** (the guard host at the 11-entry rail census; the
  extended `test_tc_042_10` over `flow_screens.py` included; `inc002_suite_directionb.txt`).
- editors + variants five-file set — **52 passed** (`inc002_suite_editors.txt`, produced at this
  gate, one complete run).
- patch-family rewrite group — **74 passed** (`inc002_suite_patch_family.txt`, produced at this
  gate, one complete run).
- snapshot matrix — **3 passed + 29 xfailed**, predicted=observed per-cell
  (`inc002_suite_snapshot.txt`, produced at this gate).
- the 11-file flow family at the union — **124 passed** (`inc002_suite_flow_family.txt`; §3's
  command re-derives the figure — run at this gate, `124 passed in 46.31s`. Note: the
  implementer's session note recorded 120 pre-union; the stored transcript's real number is 124 —
  the union re-base (batch-95's flow shapes) carries 4 more collected arms; the packet cites the
  transcript, §6 records the reconciliation).
- batch-95 compat probes — **86 passed** (`inc002_suite_b95_compat.txt`, produced at this gate:
  the loader-law battery `tests/test_flow_persistence.py` + the change-attribution suite
  `tests/test_changes_symbol_entries.py`, one complete run, exit 0).
- the R-7 golden observers — ac6 + addendum-bound **32 passed**; the batch35 pair observer host
  `test_before_after_report.py` — **14 passed + 1 failed**: the failure is
  `test_tc330_before_after_row_reveal_hide_state_machine`, the documented pre-existing flake
  (batch-95 verified the at_061a/tc330 flake pair pre-existing at HEAD pristino by a git-worktree
  probe, 3/6 and 0/4; at_061a is green in this capture; §6 records the naming).
- the corpus census + registry guard — **14 passed** (`inc002_suite_registry_guard.txt`).
- **V2 station-expected note:** at this gate the remaining unlanded ATs are **AT-B94-02 (Inc-003),
  AT-B94-14 (Inc-004), AT-B94-19…24 (Inc-003)** — station-expected reds at the gate run, the
  Inc-001 precedent (they mint at their mapped increments per `design-proposal.md` §5).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **C-20 move-aside of the net-new `s19_app/tui/flow_screens.py`** (rename out of the tree — never stash): the minted builder nodes fail at collection with `ModuleNotFoundError: No module named 's19_app.tui.flow_screens'` and the import probe fails the same way — the trigger-absent run. Per resolved node, the eight battery arms below are the per-node counterfactuals (each by position and operation): canvas→placeholder (arm 01); both-external refusal suppressed (arm 02); dedup-suffix suppressed (arm 03); canvas-label scrub dropped (arm 04); the report Mode-A escaper bypassed (arm 05); A2B bindings dropped at serialize (arm 06); the missing-CRC-config refusal flipped to OK-skip — the C-1 re-arm (arm 07); the external-arm source-kind drifted off the C-42 pasted form (arm 08) |
| Instrument | project code: own hand through the battery runner — `PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc002_battery.py` (a script in the project's stack; field guide §`Mutation verdicts`) |
| Where it ran | **this tree** (`C:/Users/jjgh8/Github/s19_app-b94`), run by the implementer's increment session at Phase 3 — the same session that wrote the code; no other lane's tree. The move-aside capture is stamped UTC 2026-10-14T02:44:16Z |
| Transcript | `.dev-flow/2026-10-12-batch-94/evidence/inc002_move_aside.txt` (the move-aside RED + restore) and `inc002_battery.txt` (the 8-arm battery with the clean-tree baseline) |
| Restore proven by | **file hash returned to its pre-mutation value** — the move-aside transcript prints `before-hash: a480fd6145f952945999804217ffd995b6b1adde4ed0be371b666a63776d4942` … `after-hash: a480fd6145f952945999804217ffd995b6b1adde4ed0be371b666a63776d4942` / `RESTORE PROVEN (hash identical)`; the committed blob's sha256 verified identical to the restored bytes. Every battery arm likewise prints `restore-ok=True` and the verdict table prints `restore-hash OK`; `git status` was not accepted as proof |
| Bytecode cache | cleared — the runner invokes `python -B` with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 18 collectable nodes resolved via `pytest --collect-only` across the 2 new files; **11 node-runs** planned and run in ONE clean-tree baseline run — the count asserted up front (`arms: 8; node-runs: 11`) |
| Verdict granularity | **per resolved node id** — the transcript's `VERDICT TABLE` prints one row per arm→node with its own verdict; the process exit code is never the verdict |
| Arms that stayed GREEN | **none** — `TOTALS: 11 node-runs | RED 11 | SURVIVED 0 | CRASH/BAD 0`; the runner exits `0 (all arms killed)` |

| Field | Value |
|---|---|
| **RED counterfactual** | the C-20 move-aside of net-new `flow_screens.py` — the trigger-absent run makes THIS increment's own new nodes fail at collection/import (`ModuleNotFoundError`), hash-proven restored to `a480fd6145f952945999804217ffd995b6b1adde4ed0be371b666a63776d4942` before=after, the committed blob sha256-verified identical · transcript: `evidence/inc002_move_aside.txt` · the per-node counterfactuals are the eight battery mutations below, 11/11 node-runs RED, transcripts `evidence/inc002_battery.{py,txt}` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 8 arms / 11 node-runs, **11/11 RED, 0 SURVIVED, 0 CRASH/BAD** — per resolved node, by position and operation (C-56: no corrupted tokens spelled here; the transcript holds the literals): arm 01 `flow_screens.py` canvas compose replaced by a placeholder → AT-B94-15 RED, TC-B94-20 RED; arm 02 `flow_model.py` both-external refusal suppressed — the (file,file) pair accepted → AT-B94-16 RED, TC-B94-23 RED; arm 03 `flow_persistence_service.py` collision dedup-suffix suppressed — a second same-name save clobbers → AT-B94-17 RED, TC-B94-04 RED; arm 04 `flow_screens.py` canvas-label scrub dropped — control bytes survive into the paint → AT-B94-18 RED; arm 05 `flow_execution_service.py` the Mode-A label escaper bypassed — raw markup reaches the report → TC-B94-25 RED; arm 06 `flow_persistence_service.py` A2B bindings dropped at serialize — the round-trip loses them → TC-B94-21 RED; arm 07 `flow_execution_service.py` **the C-1 re-arm**: the missing-CRC-config refusal flipped to an OK-skip, the chain proceeds → TC-B94-22 RED; arm 08 `flow_execution_service.py` the external-arm source-kind drifted off the C-42 pasted form → TC-B94-24 RED. Restore: every arm `restore-ok=True`, `restore-hash OK` in the verdict table. Arms that stayed GREEN: **none**. Transcripts: `evidence/inc002_battery.txt` (+ runner `inc002_battery.py`) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the battery runner | a mutation arm whose anchor does not match exactly once (the C-40 BAD-anchor guard, exercised in Inc-001's round and carried by the same runner here) | `CRASH/BAD (anchor count 0)` — the runner reports that nothing was measured, not a pass; every arm here anchored 1:1 (no BAD in the totals line) |
| the C-20 move-aside probe | the tree with `flow_screens.py` renamed out (the trigger-absent state) | collection of the minted builder nodes interrupted: `ModuleNotFoundError: No module named 's19_app.tui.flow_screens'` + `1 error during collection` — the probe's failure mode, before any PASS from it was believed (`inc002_move_aside.txt`) |
| the smoke probe's wiring-refusal arm | a both-external A2B binding (`#flow_ref_a="base.s19"`, `#flow_ref_b="#nope"`) pressed through the real Add control | the wiring notice surfaces — `notice.display is True and "refused" in …plain` — and the block count stays at 3; the probe would fail the assert if the refusal stopped working (the same acceptance battery arm 02 turns RED on that defect) |
| the golden observer host (`test_before_after_report.py`) | the pre-existing tc330 flake under the reworked chrome (a real defect-bearing state, batch-95-documented) | `FAILED … WorkerFailed … NoMatches` — `1 failed, 14 passed`, exit 1 recorded in `inc002_suite_goldens.txt`: the observer reports failures instead of swallowing them, and its 14 green rows stand beside a real reported failure |

| Field | Value |
|---|---|
| **Instrument RED-proof** | `4` instruments — the battery runner (BAD-anchor guard), the C-20 move-aside probe (the trigger-absent failure mode), the smoke probe's wiring-refusal arm (the both-external refusal exercised through the real control), the golden observer host (the tc330 failure reported, not swallowed) — each shown able to report FAILURE before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the A2B flow report's provenance lines (`generate_diff_report`, `filename_stem="flow-a2b"`) | TC-B94-24 pins the flow arm character-for-character against the increment's own paste — the smoke probe's actual run emits `- Image A: patch.out [flow] path=`block 2 (patch).out` parse-errors=0` and the external arm `- Image B: base [external] path=`…\base.s19` parse-errors=0` (the fixed shape of `p1_probe_diff_report_emitted.txt`); battery arm 08 drifts the source-kind → `AssertionError` RED, restore-hash OK | the two lines above verbatim in `inc002_smoke_probe.txt` (`SMOKE OK`); the report file `reports/20261014T043223Z-flow-a2b.md` written under the project |
| the builder-template envelope (`save_flow_json`) | TC-B94-04 runs the shipped writer and re-reads the file: the emitted bytes parse as `{"schema_version": 1, "name": …, "blocks": […]}`; the empty arm's envelope is `schema_version == 1` with `blocks == []`; the dedup-suffix arm's second save lands under the suffixed name (0 clobbers) | envelope fields asserted in-test; arm 03 (dedup-suffix suppression) → RED, restore-hash OK |
| the canvas render (the `_Grid` painter) | the smoke probe queries the real canvas Static and pastes its `render().plain` — box-drawn `┌─┐` block frames, `┤├` typed stubs, `└┐` cable bends, `·` grid dots, every line ≤ 88 cells, plus the empty-state arm at first mount | the 14-line paste verbatim in `inc002_smoke_probe.txt`, both arms (`SMOKE OK`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | `3` artifacts — the A2B report provenance lines (the flow-arm paste + the executed base form's external arm), the builder-template v1 envelope (incl. the zero-block empty arm), the `_Grid` canvas render (the verbatim paste) — each asserted against the bytes its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| battery runner (8 arms / 11 node-runs, hash restores, the clean-tree baseline) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_battery.py` | `a06c892d49138415e0aa488427cb6f055d3c30728bd72d1cfff15bc63278e3d8` |
| main battery transcript — baseline, 8 arms, verdict table, totals | `.dev-flow/2026-10-12-batch-94/evidence/inc002_battery.txt` | `fe58a39dcc9f0cb6ed62bc6f80a0d43538f31ac4e79230d1bf51bd99f1b0da64` |
| C-20 move-aside transcript — RED + hash-proven restore (`a480fd61…` before=after) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_move_aside.txt` | `c6f2c1475dba5095d52866d6158b3458880f1de0657fe5fcabdeae4af850920b` |
| fb_a smoke probe runner (canvas paste, wiring refusal, run, provenance) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_smoke_probe.py` | `7a55e3e67b3d41e542a9a0901b95c5515acdacc2eac50fda7114a7fabf0e1359` |
| smoke probe transcript — `SMOKE OK`, the canvas + provenance pastes | `.dev-flow/2026-10-12-batch-94/evidence/inc002_smoke_probe.txt` | `c0c35c2b46ad3feb7306c5cce7379f38f493c1d5778c485c3de45071c834aeab` |
| suite transcript — the FULL guard host `test_tui_directionb.py`, one complete run (184 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_directionb.txt` | `b89267f7795a1a2da0ec752707be34465263dee02ca9bd9c6a283652ef1ad346` |
| suite transcript — the 11-file flow family at the union (124 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_flow_family.txt` | `d280225869c2cc497b92f986a5e5af5927dd3c3a2329466e2f579eb205a001b0` |
| suite transcript — the R-7 golden observers (ac6+addendum 32 passed; batch35 host 14 passed + the tc330 flake) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_goldens.txt` | `1ef71c0de5082b25653a4c7640c1aeb4dfd4251620e1b4715453213c4b32f2e` |
| suite transcript — the corpus census + registry guard (14 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_registry_guard.txt` | `b99cf1ae6a21b120e3d40aef130c404f9956df7c75606bb4db5530884fb0ea72` |
| suite transcript — editors + variants five-file run (52 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_editors.txt` | `5dec117c6bc922ed1dd0ac924f1ae2d32e6aec8d1a5a8709fc65490b84d39d22` |
| suite transcript — the patch-family rewrite group (74 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_patch_family.txt` | `e96bcaf16a9f0fd719d69ce68fb8a13dd122e30166c6d51647e607a07a9c00e6` |
| suite transcript — snapshot matrix (3 passed + 29 xfailed, per-cell census) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_snapshot.txt` | `c67da2b420e675eb997c4a349e1dc350dcc13246d357da2ae2412571ef93b895` |
| suite transcript — batch-95 compat probes (loader-law battery + change-attribution, 86 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc002_suite_b95_compat.txt` | `52806822f571f572eea6777ca2fb5aee4a08750f39cb93b77eae9cb36253bc23` |

| Field | Value |
|---|---|
| **Evidence files** | `13` rows at `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each cited with the SHA-256 of its stored bytes as listed above — digests re-derived from the bytes at those paths at this gate. The §4 suite figures (184 / 124 / 52 / 74 / 3+29 / 86 / 32 / 14 / 11-baseline) are the tails of the stored transcripts named in this table (one complete run each; the snapshot's `29 mismatched snapshots` banner is the plugin's per-cell report of the 29 predicted xfails, exit 0); the smoke/battery/move-aside proof set is the stored runner + transcripts above |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | `yes` — (1) 0 `from_markup` / `markup=True` sites in `flow_screens.py`; (2) 0 reports produced for refused A2B bindings (both-external / cross-flow / malformed); (3) 0 silently clobbered templates (dedup-suffix); (4) 0 image files written when an upstream block fails (C-1) |
| If the result is an ABSENCE, what made the search wide enough | (1) the AST census walks every `Call` node in the module (not a marker list) — `test_tc_042_10`'s extension; (2) the binding matrix enumerates every accept/refuse pair over the grammar's input space (TC-B94-23); (3) the census counts every same-name second save (AT-B94-17's listing arm); (4) the run record enumerates `written_paths` after a failed chain (TC-B94-22 asserts it empty) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | TC-B94-20/AT-B94-15 (the fb_a composition census — names the canvas/palette conclusion); AT-B94-16 / TC-B94-23 (the wiring-rule conclusion, 0 refused reports); AT-B94-17 / TC-B94-04 (the dedup-suffix conclusion); TC-B94-22 (the C-1 skip-chain conclusion) |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each absence is a single conjunct with its own arm (arms 04, 02, 03, 07 respectively) |
| Synthetic instance of the absent case | (1) a `from_markup`/`markup=True` construction would trip the AST census — the batch-77 hostile payload is the synthetic markup-bearing instance (AT-B94-18); (2) battery arm 02 ACCEPTS the both-external pair — the synthetic illegal report; (3) battery arm 03 removes the dedup-suffix — the synthetic clobber; (4) battery arm 07 flips the refusal to an OK-skip — the synthetic write-proceeding chain |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified probe on the known-present case: plain file names render unchanged through the canvas scrub (identity on printable text — the smoke probe's `prg.s19`/`hotfix.json` labels); the (flow,file) and (flow,flow) bindings ARE accepted and produce reports (the smoke probe's accepted wiring — uniformity avoided: the accepted and refused arms return different, expected answers); a same-name second save lands under the suffixed name AND the first file survives (dedup listing arm); a CLEAN chain writes the image and `written_paths` carries it (TC-B94-22's happy twin `test_tc_b94_22_patch_write_out_run_records_per_block_results`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "FlowBuilderPanel\|screen_flow" tests/ s19_app/ --exclude-dir=__pycache__` (the C-2 census re-run at this cut) | **13 files post-move**: the new home `flow_screens.py` + the new node host `test_tui_flow_builder_b94.py`, the 8 live readers (`app.py`, `flow_execution_service.py`, `flow_model.py` doc refs, `test_flow_builder_render.py`, `test_flow_crc_ui.py`, `test_flow_crc_ribbon.py`, `test_flow_multi_image_ui.py`, `test_flow_report_ui.py`), the guard host `test_tui_directionb.py` (the screen_flow census) and `test_tui_flow_persistence_ui.py`; the old definition site `screens_directionb.py` carries ONE doc-only tombstone hit (module docstring, 0 live refs — verified in the grep output) |
| B2 file moved on disk | the C-2 pre/post census: pre-move **11** files (C-2-corrected membership: `+s19_app/tui/screens_directionb.py` the definition site, `−tests/test_flow_crc_block.py` the block machinery, 0 panel hits — count 11 unchanged) → post-move **8** live reader files re-pointed in-commit (5 test imports + `app.py` + the two service doc refs) with the panel reopened at `flow_screens.py` | every surviving reader re-pointed in the SAME commit (`846273b`); 0 stale-address imports; the guard host's `screen_flow` arms pass (184 passed); the tombstone docstring is doc-only, named here so it is not mistaken for a live ref |
| B3 byte-identical golden captures this source | the R-7 sweep (`01-requirements.md` §6.3 R-7): `tests/goldens/batch35/at054b-before-after-report.{md,html}` (host `test_before_after_report.py`), `tests/goldens/batch71/ac6-unscoped-flow-report.md` (host `test_flow_report_ac6_golden.py`), `tests/test_report_addendum_bound.py` | 0 of the increment's 5 touched sources is byte-captured by a golden; the batch71 golden IS batch-95's re-captured bytes — its line 17 is the `## Change attribution` section (batch-95's inc-004 re-capture, verified at `tests/goldens/batch71/ac6-unscoped-flow-report.md:17`); the ac6 observer is 3/3 green with **zero drift from the A2B side** — the A2B arm threads `change_records` alongside, never into, the unscoped golden's bytes (32 passed incl. addendum-bound) |
| B4 artifact produced here is consumed elsewhere | who reads the `flows/*.json` template and the `reports/*flow-a2b*.md` report | the template envelope is consumed by Flow Execution's import listing + `load_flow_json`/`dict_to_flow` (LLR-017.1 — Inc-003's surface, in-batch consumer); `list_saved_flows` feeds the import dropdown; the report is an operator artifact (no in-tree consumer) — no outside-lane reader |
| A3 interface consumed by another module changed | `run_flow`'s `FlowResult` — batch-95's ReportBlock consumes `result.change_records`; this increment adds the A2B results on the same object | the union `run_flow` populates BOTH `change_records` (batch-95's ReportBlock reads them, `flow_execution_service.py:746`) and the A2B block results — the 86-test b95-compat transcript green (loader-law battery + change-attribution) is the union compatibility proof; `_A2L_REF_KINDS` stays `frozenset({BLOCK_SOURCE, BLOCK_PATCH})` at `flow_persistence_service.py:125` — UNEXTENDED by the A2B branches (verified by grep) |
| did-NOT-fire probes (C-48) | named, with their probes: (a) the ac6 golden fixture carries NO A2B block → the A2B snapshot/provenance gate never fires there (probe: the fixture's flow is one-of-each-kind EXCEPT a2b — read in `test_flow_report_ac6_golden.py`; that absence is exactly why zero A2B drift is observable on batch71); (b) `git diff <cut-base>..HEAD -- s19_app \| grep -c RECOGNIZED_A2L_BLOCKS` → **0** (the A2L engine stays frozen — US-004 is Inc-004); (c) the rail census — `RAIL_ENTRIES_B94` still 11 entries at `app.py:223`, 0 hunks (the 12th entry + `]` key are Inc-003); (d) `screens.py` — 0 hunks (the SaveFlowScreen F1 text defect lives there, outside this increment's file set — §4b/§6) | every named probe executed or byte-verified at this gate; no silent "was not evaluated" |
| supporting censuses | the guard host `screen_flow` arms pass inside the 184; the directionb census moves are the `test_tc_042_10` extension to `flow_screens.py` (C-17 follows the panel) — directionb itself stays at 11 rail entries; the b95 compat probes: `python -m pytest tests/test_flow_persistence.py tests/test_changes_symbol_entries.py -q` → 86 passed (V1–V7 fail-closed unreopened — the zero-block reload refusal still reports `FLOW-BAD-STRUCTURE`, pinned by TC-B94-04's empty arm) | every hit re-validated; no hit left unowned |

| Field | Value |
|---|---|
| **Reverse census** | `9` probes run of B1 · B2 · B3 · B4 · A3 (+4 did-NOT-fire + supporting censuses): B1 13 files post-move (8 live readers + new home + new host + guard host + persistence UI; the old site's hit is doc-only) · B2 the C-2 pre-move 11 → post-move 8 readers re-pointed in-commit, 0 stale addresses · B3 0 goldens capture the 5 touched sources; batch71 = batch-95's re-captured bytes (`## Change attribution`), ac6 3/3 green, zero A2B drift · B4 the template's consumer is Inc-003's import (in-batch); the report is operator-facing · A3 the union run populates both change-records and A2B results, `_A2L_REF_KINDS` unextended, 86 compat green — **the did-NOT-fire probes named per C-48: the ac6 fixture's missing A2B (its snapshot gate never fires there) · `RECOGNIZED_A2L_BLOCKS` 0 hits · the rail census 0 hunks (11 entries) · `screens.py` 0 hunks** |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the B2 move re-points every live reader (HLR-013) | every file naming `FlowBuilderPanel`/`screen_flow` across tests + product | `grep -rl "FlowBuilderPanel\|screen_flow" tests/ s19_app/` (the C-2 census, run at PDR BEFORE the first edit of the move; `__pycache__` excluded per the C-2 note) | 11 pre-move (C-2-corrected) | the 8 live readers re-pointed in `846273b`; the definition site content moved to `flow_screens.py` | the guard host `test_tui_directionb.py` keeps its `screen_flow` census string by design (it guards the rail mount, not the panel import); `test_tui_flow_persistence_ui.py` re-pointed in-commit |
| the C-17 source census follows the moved panel (HLR-016) | every `from_markup` / `markup=True` AST site in the touched render modules | `test_tc_042_10`'s source scan, extended in the same commit | 2 module surfaces (directionb legacy + the new flow_screens) | `test_tc_042_10` extended to `flow_screens.py` | none — the census covers both surfaces from this commit on |
| the corpus census moves with the minting increment | the scanned-test-file bound vs the on-disk test roster | `tests/test_id_registry.py` (`EXPECTED_SCANNED_TEST_FILES`, the measured bound) | 175 → 177 | the one constant, in the landing commit | none — the bound moves with its landing increment, never before (LLR-002.2 idiom) |

| Field | Value |
|---|---|
| **Correction population** | `3` corrections, each enumerated with its command before its first site was edited (the C-2 grep at PDR; the AST-census extension in-commit; the registry bound at the landing commit) — the sites left are named with their reason above |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `FlowBuilderPanel` at the `screens_directionb.py` address | 1 hit in `s19_app/` — the tombstone module-docstring line (`- ``FlowBuilderPanel`` — MOVED to …`); 0 live imports/refs; every code hit names the NEW address | yes — the surviving ref is a move notice, not a dependency | `s19_app/tui/screens_directionb.py:16`; the B1 grep output above |
| the list-based tracer builder (pre-fb_a compose) | 0 live compose sites — the old panel body left with the vacate; the new compose is palette+canvas | yes | `s19_app/tui/flow_screens.py` (the fb_a compose, `:408-540` region); the 759-line removal in `846273b` |
| the direct `screens_directionb` import of the panel in `app.py` | 0 — repointed to `flow_screens` | yes | `app.py` 2-line diff in `846273b` |

### Signed-balance test ledger

`post = base − deleted + added` → `177 = 175 − 0 + 2`  ✓ reconciles — the measured corpus census
(`tests/test_id_registry.py`: 175 → 177, this increment's 2 NEW files). The 8 changed test files
post as in-place edits; the 5 repoint-only files carry no balance change beyond the edited lines.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean |

Review record:

- **Verdict: clean — one LOW finding, no HIGH, no MEDIUM.** F1 (LOW): the SaveFlowScreen
  overwrite-notice text is stale — it still reads "(overwrites existing)" while the dedup-suffix
  save no longer overwrites; the notice lives in `screens.py` (`SaveFlowScreen`,
  `screens.py:733`, the notice arm `:785-789`), which is OUTSIDE this increment's five-file source
  set, so the fix cannot ride this increment — recorded as a lane-A follow-up (§6).
- **The nine load claims verified with executed evidence:** the reviewer re-derived the packet's
  load-bearing figures against executed bytes — the battery baseline + 8 arms (11/11 RED,
  `inc002_battery.txt`), the C-20 move-aside restore (`a480fd61…` before=after), the guard host
  (184), the flow family (124), the editors (52) / patch (74) / snapshot (3+29) sets, the b95
  compat probes (86), and the golden observers (ac6 3/3 green; the batch71 `## Change attribution`
  re-capture) — each claim checked against its transcript, not the prose.
- **Discharge:** F1 is lane-A (file outside the set); nothing else open. The cell stays `clean`.

---

## 5 · Risks

*(What could break that this increment does not cover. Be specific enough to act on.)*

- **C-3 — carried to Inc-003:** AT-B94-02's pilot-size pin (12 entries ≤ 21 rows at 80×24) needs the
  twelfth rail entry; it discharges at Inc-003's gate (the census constants move with their landing
  increment, never before).
- **Assumption register (design §5/§6):** **A3** (fx_a two-lane layout) verifies at Inc-003;
  **A5** (no shared mutable service state across chains — AT-B94-21's error arm) at Inc-003;
  **A6** (template/provenance emitted forms until the C-42 pastes) discharged HERE for the builder
  side (the A2B provenance paste + the v1 envelope); **A2** (fb_a canvas inside 96×18) verified
  here by AT-B94-15/TC-B94-20; **A4** (real-terminal key delivery, unmeasurable headlessly) stays
  field-verification debt — the `8` entry predates this increment and is unchanged by it.
- **The settle-flaky family (bounded):** the reworked builder screen carries more chrome, so a bare
  `pilot.pause()` no longer guarantees a pushed modal's compose under load. The bounded-wait
  hardening SHIPPED here test-side (`_wait_for` in `tests/test_tui_flow_persistence_ui.py`, the
  load-flaky family; AT-B94-17's save drive uses it) — the product surface is unchanged. Residual
  risk: other pre-existing TUI suites with the same bare-pause idiom remain latent flake sources
  (lane-A hygiene, not batch-94 scope).
- **The SaveFlowScreen prefill race (pre-existing, lane A):** the modal's `on_mount` prefill +
  notice refresh (`screens.py:777`) races the input-changed path — pre-existing, outside this
  increment's file set; carried to lane A with F1.
- **main-moved-again regime (RC-1 #5):** this increment was built and gated across FIVE RC-1
  rebases onto batch-95's landed work (the base_ref re-stamps through `8a37713`); the union
  re-verification rides every transcript above. **The next RC-1 reconciliation is at Inc-003's
  cut** — do not re-stamp between increments.

---

## 6 · Pending items / spec deviations

*(Anything surfaced and not closed here. Every line lands in the canonical backlog at batch close —
if the increment surfaced it, the backlog owns it.)*

- **The empty-arm reconciliation (HLR-015):** the realized zero-block flow SAVES as the schema-v1
  envelope (`{"schema_version": 1, "blocks": []}`); its reload refusal is the pre-existing
  batch-53 V4 law (`flow has no blocks` → `FLOW-BAD-STRUCTURE`, pinned by that batch's security
  battery) — the V1–V7 fail-closed discipline is not re-opened. Pinned by TC-B94-04's empty arm;
  the reconciliation is recorded here per the deviation rule.
- **The palette census wording (TC-B94-20):** "3 placeable types" are on the PALETTE RAIL
  (`_PALETTE_TYPES` — patch · CRC · A2B-diff, `flow_screens.py:453-456`); the `#flow_kind` Select
  separately carries the CHAIN kinds (source · patch · crc · write-out · a2b, `_KIND_OPTIONS`) —
  the census counts palette placeables only, the chain kinds are a different surface. The wording
  is pinned here so the two lists are never conflated.
- **F1 (lane A):** the stale SaveFlowScreen overwrite-notice text (§4b) — `screens.py` is outside
  this increment's file set; the fix rides lane A. Owner: lane A.
- **A2B Markdown-only emission:** the flow A2B arm emits Markdown only (`generate_diff_report`,
  `reports/*flow-a2b*.md`); the base report's HTML twin (`generate_diff_report_html`) is NOT
  invoked from the flow path — recorded, not silently assumed; the A2B acceptance pins the
  Markdown form.
- **The batch-95 golden re-capture note:** the batch71 golden on disk is batch-95's inc-004
  re-captured bytes (the `## Change attribution` section) — not this increment's; the post-union
  ac6 observer was re-verified green here (3/3, zero A2B drift). The chain-set/provenance drift
  naming rides Inc-003 (R-7 plan).
- **The flow-family count reconciliation:** the implementer's session note recorded 120 for the
  11-file family pre-union; the stored transcript (`inc002_suite_flow_family.txt`) reads **124** —
  the union re-base onto batch-95's flow shapes carries 4 more collected arms. The packet cites
  the transcript's real number (124), re-derived at this gate by the §3 command.
- **The golden-capture flake naming:** the stored golden transcript's failing row is tc330; the
  at_061a/tc330 pair are the batch-95-documented pre-existing flakes (HEAD-pristino worktree
  probe, 3/6 and 0/4), green in isolation. The packet cites the bytes (tc330 the failing row in
  this capture; at_061a among the 14 green).

---

## 7 · Suggested next task

**Increment 003 — Flow Execution fx_a** (US-007; HLR-017…021; AT-B94-02, 19…24; TC-B94-05, 08,
26…31): the fx_a two-lane panel + run-log at `flow_screens.py`, template import, per-chain input
rebinding, sequential(default)/parallel-per-chain control, chain-set save/load, the twelfth rail
entry + the `]` key (the guard-host census moves 11→12 in the same commit, LLR-002.2) —
discharging C-3 and the A3/A5 assumptions at its gate. The next RC-1 reconciliation rides
Inc-003's cut (§5).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 5/4 — §2 ⚠ over-cap with the PDR-declared reason (the B2 repoint cannot ride elsewhere; the compat re-export rejected — two live addresses would double the census surface; `design-proposal.md` §Inc-002, PLAN.md roadmap #2) |
| 2 | Tests written in this same increment | all | ✓ | 2 NEW files mint the 11 nodes with the product change (§2; commit `846273b`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | no standalone layer-0 nodes — the candidates host inside TC-B94-04/21/23/25 (design §5); one complete run owned by the orchestrator = the battery's clean-tree baseline, ONE run, `11 passed`, tail read from `inc002_battery.txt` |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 field — the C-20 move-aside of net-new `flow_screens.py` (collection RED, `ModuleNotFoundError`) + the 8 per-node battery mutations; transcript `evidence/inc002_move_aside.txt` / `inc002_battery.txt`; restore digest `a480fd6145f952945999804217ffd995b6b1adde4ed0be371b666a63776d4942` before=after, committed blob sha256-verified |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 field — B1 13 post-move · B2 C-2 11→8 readers re-pointed · B3 0 goldens over the 5 sources (batch71 = batch-95's re-capture, ac6 zero A2B drift) · B4 the template consumer (Inc-003, in-batch) · A3 union run populates change-records + A2B results, `_A2L_REF_KINDS` unextended; did-NOT-fire named: the ac6 fixture's missing A2B · `RECOGNIZED_A2L_BLOCKS` 0 · rail 0 hunks (11) · `screens.py` 0 hunks |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ✓ | §4b — clean; one LOW (F1, stale SaveFlowScreen overwrite-notice text — screens.py outside the file set → lane A, §6); the nine load claims verified with executed evidence |
| 7 | No file from another lane touched | all | ✓ | single-lane trunk batch (§2.8 declared empty); the B1 census shows every touched file re-pointed in-commit, no foreign-lane file |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `RECOGNIZED_A2L_BLOCKS` 0 hits · the rail census 0 hunks · `screens.py` 0 hunks (F1 is text-stale, not an interface change); the V1–V7 loader laws unreopened (86 compat green); the A2B additions are additive to batch-95's flow shapes |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | counts read from the stored transcripts' tails (184 / 124 / 52 / 74 / 3+29 / 86 / 32 / 14 / 11-baseline); digests re-derived from the bytes at the evidence home (§4 Evidence files) |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 — 4 absences, each with its guard + synthetic instance (arms 04/02/03/07) + positive controls (the accepted-bindings / clean-chain / plain-name twins) |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 field — 8 arms / 11 node-runs, per resolved node, 11/11 RED; inert arms: none (0 SURVIVED / 0 CRASH-BAD in the totals); transcripts cited with hash restores |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 field — 4 instruments (the runner's BAD-anchor guard; the move-aside trigger-absent failure; the smoke probe's wiring-refusal arm; the golden host's tc330 failure reported) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 field — 3 corrections, each with its enumeration command (the C-2 PDR grep; the AST-census extension; the registry bound) and its sites-left reasons |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 field — 3 artifacts (the A2B provenance lines incl. the flow-arm paste; the v1 template envelope incl. the zero-block arm; the `_Grid` canvas paste) |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ✓ | §4b cell — `code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean` |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 field — 13 artifacts under `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each with its SHA-256; the count-reconciliation notes (flow family 124; the golden-flake naming) are recorded in the field itself and §6 |
