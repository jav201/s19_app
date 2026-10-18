# Increment 004 — US-004 · HLR-012 · `Issues warnings triage`

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
> `.dev-flow/2026-10-12-batch-94/03-increments/increment-004.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

> **A table you may delete.** A table whose `| **Field** |` row reads `none — <reason>`, or whose question one line of the gate checklist answers, may be deleted, its field row kept: `stations/core-runbook.md` §*A minimal increment packet* is a one-function change written that way.

| Field | Value |
|---|---|
| Batch | `2026-10-12-batch-94` |
| Increment | `004` |
| Lane (if the batch forked) | `none — single-lane trunk batch` · `n/a` (§2.8 fork preconditions, the declared empty; one worktree, one lane) |
| Requirement(s) | `US-004` · `HLR-012` · `LLR-012.1/.2` |
| Acceptance | `AT-B94-14` (1 black-box) · `TC-B94-18, 19` (2 white-box) — 3 ids minted across 1 new on-disk file (C-18: one AT = one node — AT-B94-14 was the LAST unlanded AT) · **ALL 24 acceptance ids (AT-B94-01…24) are now landed** |
| Agent | `software-dev` |
| Date | `2026-10-18` |

---

## 1 · What changed

*(BLUF: state the outcome first, then the mechanism. Name the shipped surface the user reaches.)*

**BLUF.** The Issues warnings triage is real — the last increment of the batch. The Issues surface
(`GroupedIssuesPanel`, the surface HLR-012 names) now presents `A2L_UNRECOGNIZED_BLOCK` findings
whose block name belongs to the curated ASAP2 standard-keyword set as **INFO with a stated
justification — never as warnings** — reclassification, never suppression (D-6): no row is dropped,
the caller's engine list is never mutated, and genuinely unknown blocks (the executed `FROBNICATE`
negative control) **stay warnings**. On the stand-in fixture
(`examples/case_00_public/software_a.a2l`, 13 990 tags) all **1 023** curated findings move
WARNING → INFO: the panel reads `WARNING == 0 / INFO == 1 023`, and the app's headline chrome —
the severity strip (`Warnings 0 · Info 1023`), the summary line (`errors=0 · warnings=0 ·
info=1023`) and the group headers — reports the same triaged census, because all three ride ONE
arithmetic site. The engine (`validation/rules.py`, `tui/a2l.py`) stays **frozen** — byte-equal to
`main`, pinned by TC-B94-18's in-run byte-check and battery arm 06. The curated set is a
view-owned constant (`CURATED_STANDARD_A2L_BLOCKS`, 21 families seeded from the executed
2026-10-13 tally) — the engine's `RECOGNIZED_A2L_BLOCKS` is never imported by the view. With
AT-B94-14 landed, **all 24 batch-94 acceptance ids are on disk**; the V2 station-expected family
is EMPTY at the next gate.

**Mechanism, seam by seam:**

1. **The curated set + the predicate** (LLR-012.1, TC-B94-18) — `CURATED_STANDARD_A2L_BLOCKS`
   (frozenset, 21 names pasted from the executed tally: 437 REF_CHARACTERISTIC + 221
   REF_MEASUREMENT + 180 AXIS_DESCR + 69 COMPU_VTAB_RANGE + 69 SUB_GROUP + 22 DEF_CHARACTERISTIC
   + 6 PAGE + 3 SEGMENT + 3 SUB_FUNCTION + 2 PROTOCOL_LAYER + 1 each of A2ML / CAN_FD / DAQ /
   EVENT / FORMULA / MOD_COMMON / MOD_PAR / PAG / STIM / TIMESTAMP_SUPPORTED / XCP_ON_CAN =
   1 023 findings; every member uppercase A2L vocabulary, `FROBNICATE` absent).
   `a2l_reclassified_severity(issue)` returns INFO only for a WARNING `A2L_UNRECOGNIZED_BLOCK`
   whose message matches the emitter's exact anchored shape (`Unrecognized A2L block
   '<NAME>'.` — names the engine already stripped + uppercased) AND whose name is a member;
   everything else returns `None` — non-matching codes, non-WARNING severities, shape
   mismatches (the hostile `EVIL[red]` arm fails closed) and non-curated names keep their engine
   severity.
2. **The render remap** (LLR-012.2, TC-B94-19) — `GroupedIssuesPanel.render_groups` remaps each
   mounted row through `dataclasses.replace` — a presentation-level copy; the caller's list is
   never mutated and every file-derived string stays markup-safe through `safe_text` (C-17; the
   justification is an author constant, safe by construction). The reclassified rows land under
   the INFO group with `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` rendered beside the header;
   the panel mounts the caller-supplied `group_counts` verbatim (LLR-042.6's contract) and
   remaps rows only.
3. **The counts fold** (HLR-012 "shall not present them as warnings" — every presentation) —
   `adjust_counts_for_a2l_triage` is the single arithmetic site: it counts the predicate's
   remaps and moves that delta WARNING → INFO in a counts dict. `app.py`'s strip/summary
   painters and the panel's `group_counts` all ride this helper, so the three headline surfaces
   can never disagree; with zero reclassifiable rows the helper returns the input dict unchanged
   — the no-op is byte-identical to the pre-Inc-004 painters (TC-B94-19's degenerate arm).
4. **The shipped-surface drive** (AT-B94-14) — the fixture loads through the real engine
   (`parse_a2l_file` + `validate_a2l_structure`, the P1 probe's exact path), then renders through
   the live app chrome: the strip, the summary Static, the group headers and the row classes are
   all asserted on `render().plain` on a 120×30 pilot. The 1 023-arm (`Warnings 0 / Info 1023`),
   the tail-window arm (the last 40 rows render INFO too — no row dropped), the mixed arm (38
   curated + `FROBNICATE` + one error: `ERRORS 1 · WARNINGS 1 · INFO 38`, the unknown block's
   chip still `A2L_UNRECOGNIZED_BLOCK` under WARNINGS) and the negative control (`FROBNICATE`
   still warns; the caller's engine list keeps raw severities).
5. **The freeze** (D-1) — TC-B94-18 pins it in the SAME run as the membership: `git diff
   --name-only main` over `validation/rules.py` / `tui/a2l.py` is empty and the worktree bytes
   equal `main`'s blobs (CRLF-aware); battery arm 06 touches the frozen engine constant → RED.
   The two sets are disjoint by construction — the emitter only fires for names the engine does
   NOT recognize (`RECOGNIZED_A2L_BLOCKS` has 15 entries; the curated tally has 21 families; §6
   records the reconciliation). The view deliberately never imports the engine constant — the
   byte-check is the only contact.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/issues_view.py` | source | US-004 · HLR-012 · LLR-012.1/.2 | +256/−5 (261 lines total, `git diff --numstat 3d76f2a..b43f8ad`) — `CURATED_STANDARD_A2L_BLOCKS` (the 21-family curated set) + `a2l_reclassified_severity` (the public predicate) + `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` (author constant) + `_UNRECOGNIZED_BLOCK_RE` (the emitter-anchored strict shape) + `adjust_counts_for_a2l_triage` (the single arithmetic site) + the `render_groups` row remap (`dataclasses.replace` presentation copy, caller counts verbatim) + the module-doc seam note (no engine import) |
| `s19_app/tui/app.py` | source | US-004 · HLR-012 · LLR-012.2 | +53/−14 (67 lines total) — the fold: the strip/summary painters' three raw severity counts and the grouped panel's `group_counts` now ride `adjust_counts_for_a2l_triage` (import + two call sites + the two doc notes); zero-delta → identical bytes to the pre-Inc-004 painters |
| `tests/test_tui_issues_triage_b94.py` | test | US-004 · HLR-012 · LLR-012.1/.2 | NEW — 525 lines, 3 nodes: AT-B94-14 (the fixture-scale shipped-surface drive: the 1 023-census arm, the tail-window no-drop arm, the mixed arm, the negative control, the app-chrome arm) + TC-B94-18 (membership + the in-run engine byte-check) + TC-B94-19 (the panel matrix: split, empty state, the byte-identical no-op, the C-17 hostile arm) |
| `tests/test_id_registry.py` | test | US-004 · HLR-012 | corpus census `EXPECTED_SCANNED_TEST_FILES` 179→180, measured (this increment's 1 new file) |

| Count | Value |
|---|---|
| **SOURCE files** | **`2` / 4 — raised from the declared 1; the reason is stated below** |
| Test files | `2` (uncapped) — 1 new · 1 census move |
| Doc files | `0` (outside the count) |

- ⚠ **Raised from the declared 1 (PLAN §Roadmap: "Inc-004 — 1 source file (`issues_view.py`)") to 2 by
  the fold:** HLR-012's statement binds EVERY presentation — "shall present them as informational …
  and shall not present them as warnings". Landing the triage in the view alone would leave the
  app's strip, summary line and group headers broadcasting the triaged rows as raw warnings — the
  three surfaces would disagree by construction. The fold round made `app.py`'s two count sites
  (the strip/summary painters + `group_counts`) ride the view's `adjust_counts_for_a2l_triage`,
  which is exactly the "one arithmetic site" seam; `app.py` is the sole legal chrome owner, so no
  third file was possible. Declared here per the budget rule; the increment stays 2/4, under the cap.
- ✗ If a file belongs to another lane's file set, stop: lanes may not share a file. — n/a, one lane.

---

## 3 · How to test

```bash
# the 3 minted nodes / 3 ids (ONE complete run — the battery's own baseline arm)
python -m pytest tests/test_tui_issues_triage_b94.py -q
# the 7-arm / 12-node-run mutation battery + the C-20 move-aside
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc004_battery.py
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc004_move_aside.py
# the guard host (rail census — 184 passed at gate)
python -m pytest tests/test_tui_directionb.py -q
# the Issues-surface family: the grouped-panel hosts (21 passed at gate)
python -m pytest tests/test_tui_issues_view.py tests/test_tui_a2l_issue_recolor.py -q
# the snapshot matrix (3 passed + 29 xfailed, per-cell census — zero-delta this increment)
python -m pytest tests/test_tui_snapshot.py -q -rf
# the R-7 golden observers (32 passed at gate)
python -m pytest tests/test_flow_report_ac6_golden.py tests/test_report_addendum_bound.py -q
# the batch35 pair observer (15 passed at gate — the at_061a flake stayed green this run)
python -m pytest tests/test_before_after_report.py -q
# the corpus census + registry guard (14 passed at gate)
python -m pytest tests/test_id_registry.py -q
```

(The battery/move-aside runners carry `PYTHONIOENCODING=utf-8` for the same reason as Inc-003's —
the runner's own subprocesses must not trip on a stock Windows console encoding.)

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | none minted standalone — the candidates (the predicate's fail-closed branch chain, the count-delta arithmetic, the no-op identity) host inside TC-B94-18/19 per the contract's LLR binding | hosted arms all green (see layers A/B) |
| **A · white-box** `TC-B94-18, 19` ↔ LLR | `core` · `full` | 2 ids / 2 nodes | 2/2 ids green — the battery's ONE clean-tree baseline run of the three minted nodes (3 passed, tail read from `inc004_battery.txt`) |
| **B · black-box** `AT-B94-14` ↔ story, through the shipped surface | `core` · `full` | 1 id / 1 node (C-18 — the last AT of the batch) | 1/1 green — battery baseline + the fixture-scale shipped-surface drive through the live app chrome (strip/summary/headers asserted on render().plain) |

**Evidence digest — the increment's verification runs** (counts as returned by this gate's runs and
the stored transcripts cited in *Evidence files* below; the stored bytes are the authority):

- `tests/test_tui_directionb.py` — **184 passed** (the guard host at the 12-entry rail census;
  `inc004_suite_directionb.txt`).
- the Issues-surface family (the grouped-panel hosts `test_tui_issues_view.py` +
  `test_tui_a2l_issue_recolor.py`) — **21 passed** (`inc004_suite_issues_family.txt`, produced at
  this gate, one complete run).
- the snapshot matrix — **3 passed + 29 xfailed**, predicted=observed per-cell
  (`inc004_suite_snapshot.txt`; the `29 mismatched snapshots` banner is the plugin's per-cell
  report of the 29 predicted xfails, exit 0 — zero-delta this increment, §6).
- the R-7 golden observers — ac6 + addendum-bound **32 passed** (`inc004_suite_goldens.txt`).
- the batch35 pair observer — **15 passed** (`inc004_suite_goldens_batch35.txt`; the at_061a/tc330
  flake family stayed green in this run — §6).
- the corpus census + registry guard — **14 passed** (`inc004_suite_registry_guard.txt`).
- the battery baseline — **3 passed** in ONE clean-tree run of the minted nodes
  (`inc004_battery.txt`).
- **V2 station-expected note:** with AT-B94-14 landed the V2 station-expected family is **EMPTY**
  at the next gate — every V2 red from here is a true regression, none is a minting-plan leftover.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **C-20 move-aside of the net-new test file** (`tests/test_tui_issues_triage_b94.py` — rename out of the tree, never stash): the minted nodes fail at collection (`no tests ran`, exit 4 — the trigger-absent run). Per resolved node, the seven battery arms below are the per-node counterfactuals (each by position and operation): the predicate's INFO return replaced with None (arm 01); the justification constant swapped out of the INFO group (arm 02); the count helper's delta zeroed (arm 03); the row remap dropped — rows keep WARNING (arm 04); a non-standard name admitted to the curated set (arm 05); the frozen engine constant touched (arm 06); the panel's `group_counts` left untriaged while the strip/summary triage — the fold-consistency arm (arm 07) |
| Instrument | project code: own hand through the battery runner and the move-aside probe — `PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc004_battery.py` / `…/inc004_move_aside.py` (scripts in the project's stack; field guide §`Mutation verdicts`) |
| Where it ran | **this tree** (`C:/Users/jjgh8/Github/s19_app-b94` — the batch worktree), run by the implementer's increment session at Phase 3 — the same session that wrote the code; no other lane's tree. The evidence captures are stamped 2026-10-18 (16:14–16:25, commit `b43f8ad` 16:26) |
| Transcript | `.dev-flow/2026-10-12-batch-94/evidence/inc004_move_aside.txt` (the move-aside RED + restore) and `inc004_battery.txt` (the 7-arm battery with the clean-tree baseline) |
| Restore proven by | **file hash returned to its pre-mutation value** — the move-aside transcript prints before=after `6311f7c3a98bd876a68717a5c2d5b2e98382662d9ebd5eef02e528e7d10db89b` and `restore proven: True` (the digest matches the committed bytes of `tests/test_tui_issues_triage_b94.py` to this day); the battery transcript prints before=after `a70e08decbe6c5afbad0eac5513b255a3bbce88735553e4b2d5ec56c88a56e23` (rules.py), `1c2c200367299b361a6e6ab5b55e8c4f9c94a8f0cfebd7d431b4591ef97a8d37` (app.py), `96f29f49422bce0d5f0278d97fc05caeeeed17fcd4d759fd787ef3b9b65605cf` (issues_view.py), then `RESTORE PROVEN (hash identical) for every mutated file` — each equals the live committed bytes at this gate; `git status` was not accepted as proof |
| Bytecode cache | cleared — the runners invoke `python -B` with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 3 collectable nodes resolved via `pytest --collect-only` on the new file; **12 node-runs** planned and run in ONE clean-tree baseline run — the count asserted up front (`arms: 7 node-runs: 12`; AT-B94-14 arms arms 01/02/03/04/05/07, TC-B94-18 arms 05/06, TC-B94-19 arms 01/02/04/05) |
| Verdict granularity | **per resolved node id** — the transcript prints one verdict row per arm→node; the process exit code is never the verdict (the runner exits non-zero if ANY arm survives) |
| Arms that stayed GREEN | **none** — `TOTALS: 12 node-runs | RED 12 | SURVIVED 0 | CRASH/BAD 0` |

| Field | Value |
|---|---|
| **RED counterfactual** | the C-20 move-aside of the net-new test file — the trigger-absent run makes THIS increment's own new nodes fail at collection (exit 4, `no tests ran`), hash-proven restored (before=after `6311f7c3a98bd876a68717a5c2d5b2e98382662d9ebd5eef02e528e7d10db89b`, matching the committed bytes) · transcript: `evidence/inc004_move_aside.txt` · the per-node counterfactuals are the seven battery mutations below, 12/12 node-runs RED, transcripts `evidence/inc004_battery.{py,txt}` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 7 arms / 12 node-runs, **12/12 RED, 0 SURVIVED, 0 CRASH/BAD** — per resolved node, by position and operation (C-56: no corrupted tokens spelled here; the transcript holds the literals): arm 01 `issues_view.py` the predicate's sole INFO return replaced with None — the triage never fires → AT-B94-14 RED, TC-B94-19 RED; arm 02 `issues_view.py` the justification constant swapped out of the INFO group render → AT-B94-14 RED, TC-B94-19 RED; arm 03 `issues_view.py` the count helper's reclassified-delta term zeroed (the fold's arithmetic neutralized) → AT-B94-14 RED; arm 04 `issues_view.py` the row remap dropped — reclassified rows keep WARNING → AT-B94-14 RED, TC-B94-19 RED; arm 05 `issues_view.py` one non-standard name admitted to the curated set (the strict-membership conjunct) → AT-B94-14 RED, TC-B94-18 RED, TC-B94-19 RED; arm 06 `rules.py` the frozen engine constant touched → TC-B94-18 RED (the freeze fails loud, not silent); arm 07 `app.py` the panel's `group_counts` left untriaged while the strip/summary triage (the fold-consistency arm — the two chrome halves would disagree) → AT-B94-14 RED. Restore: `before:` = `after:` for all three mutated files in the transcript, `RESTORE PROVEN (hash identical)`. Arms that stayed GREEN: **none**. Transcripts: `evidence/inc004_battery.txt` (+ runner `inc004_battery.py`) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the battery runner | a mutation arm whose anchor does not match exactly once (the C-40 BAD-anchor guard carried by the same runner since Inc-001) | `BAD (anchor count …)` + runner exit 1 — it reports that nothing was measured, not a pass; every arm here anchored 1:1 (0 CRASH/BAD in the totals line) |
| the C-20 move-aside probe | the tree with the net-new test file renamed out (the trigger-absent state) | collection of the minted nodes fails: `no tests ran in 0.00s`, pytest exit 4 — `verdict: RED (KILLED — trigger absent, collection failed)`, before any PASS from it was believed (`inc004_move_aside.txt`) |
| the freeze byte-check (TC-B94-18's in-run instrument) | battery arm 06's engine touch — a real corruption of exactly what it certifies (`rules.py`) | `1 failed … test_tc_b94_18_curated_set_and_engine_freeze` — the `git diff --name-only main` line goes non-empty and the CRLF-aware blob hash mismatches; the freeze reports RED, not silently green |
| the chrome/surface asserts (AT-B94-14's strip/summary/header reads on `render().plain`) | battery arm 07's untriaged `group_counts` on the live chrome drive — the panel half of the fold disabled | the painted-census assertions fail (`WARNINGS` header / strip counts disagree with the triaged list) → AT-B94-14 RED, restore-hash OK — the emitted-form reader reports the painted lie, not the model's truth |

| Field | Value |
|---|---|
| **Instrument RED-proof** | `4` instruments — the battery runner (BAD-anchor guard), the C-20 move-aside probe (the trigger-absent failure mode), the freeze byte-check (arm 06's engine touch reported), the chrome/surface emitted-form asserts (arm 07's split-fold lie reported) — each shown able to report FAILURE before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the severity-strip Static (`#issues_severity_strip`) | AT-B94-14's app-chrome arm reads `Static.render().plain` on the live drive — asserts `Warnings 0` + `Info 1023` (1 023-arm) and `Errors 1` / `Warnings 1` / `Info 38` (mixed arm) | the painted text, verbatim asserts in-test; arm 07 (`group_counts` raw) → the header census disagrees → RED |
| the summary Static (`#validation_issues_summary`) | same arm — asserts `errors=0` / `warnings=0` / `info=1023` (and `errors=1` / `warnings=1` / `info=38` on the mixed drive) | idem — the summary's own bytes, not the model |
| the grouped panel's emitted rows, headers + justification (`GroupedIssuesPanel.render_groups`) | TC-B94-19 reads every mounted row's `_sev_class` + chip code + each group header's `issue_count` + the `.issue-reclassify-note` Static's `render().plain` — the INFO/WARNING split (3/2 on the mixed matrix), the byte-identical no-op degenerate arm, the hostile `[red]` payload rendered with 0 spans | the matrix asserts in-test; arm 04 (rows keep WARNING) and arm 02 (justification swapped) → RED, restore-hash OK |

| Field | Value |
|---|---|
| **Emitted-form assertion** | `3` artifacts — the severity-strip Static, the summary Static, the grouped panel's rows/headers/justification — each asserted against the bytes its producer emitted (`render().plain`), never the in-memory model |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| battery runner (7 arms / 12 node-runs, hash restores, the clean-tree baseline) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_battery.py` | `3cf1e573c34cf17378e259d905e39a591f9c86bcab6b0012c2c40e9461f1e40f` |
| main battery transcript — baseline, 7 arms, per-node verdicts, totals | `.dev-flow/2026-10-12-batch-94/evidence/inc004_battery.txt` | `ba1819fe8a4bc1576c022834b80a8b258299ec1d02e176d988279ff354e8eb7b` |
| C-20 move-aside runner (the net-new file, hash before/after) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_move_aside.py` | `caabf0d62a59982712ade09edbba210315a80c0662d28340a24676a7a664e97b` |
| C-20 move-aside transcript — exit-4 RED + hash-proven restore | `.dev-flow/2026-10-12-batch-94/evidence/inc004_move_aside.txt` | `8ea0e6e1cf98be3cfe0abd94218a275e6b46eab6a397a84e921ab3b3135589fb` |
| suite transcript — the FULL guard host `test_tui_directionb.py`, one complete run (184 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_directionb.txt` | `00979f620bef2ee2dd7c532460ce358221c176538c755bf41543845ae73f35fd` |
| suite transcript — the Issues-surface family, the grouped-panel hosts (21 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_issues_family.txt` | `0061b6d1a2bc6f1dd47a8d463e8c70ece7e5000688ebd7f880f3a5827b89b2d1` |
| suite transcript — the snapshot matrix (3 passed + 29 xfailed, per-cell census) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_snapshot.txt` | `a278dbfeaa2c63bb02c0f0a7a1f4160d113b2cf96f14b6d83a9550ac867ba553` |
| suite transcript — the R-7 golden observers, ac6 + addendum-bound (32 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_goldens.txt` | `e52c904c022d8a290d95656a97f1b15e3186ff6cf583899cadce4577f8cd8c12` |
| suite transcript — the batch35 pair observer (15 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_goldens_batch35.txt` | `7506a9851f8f2a7157e1f8246013b8beb04955391c3a5309af9f7aa090751c12` |
| suite transcript — the corpus census + registry guard (14 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc004_suite_registry_guard.txt` | `bc301347b4859d11419f715827af3ac3e3b8866dbd2841186e4c01659f41828c` |

| Field | Value |
|---|---|
| **Evidence files** | `10` rows at `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each cited with the SHA-256 of its stored bytes as listed above — digests re-derived from the bytes at those paths at this gate (the evidence home carries the `-text` mark; index bytes equal worktree bytes). The §4 suite figures (184 / 21 / 3+29 / 32 / 15 / 14 / 3-baseline) are the tails of the stored transcripts named in this table (one complete run each; the snapshot's `29 mismatched snapshots` banner is the plugin's per-cell report of the 29 predicted xfails, exit 0); the battery/move-aside proof set is the stored runners + transcripts above |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | `yes` — (1) 0 dropped rows (reclassification, never suppression — D-6: a suppressed row vanishes); (2) 0 non-curated names reclassified (the `FROBNICATE` negative control stays a warning); (3) 0 WARNINGS group header when the mounted window is all-curated; (4) 0 engine hunks (the freeze is itself an absence — the byte-equality claim); (5) 0 snapshot cells own an A2L-issues surface (the zero-delta no-drift claim) |
| If the result is an ABSENCE, what made the search wide enough | (1) AT-B94-14 drives the full 1 023-list AND the tail-40 window and counts mounted rows before/after (1 024 = 1 023 + `FROBNICATE` on the negative-control drive); (2) the negative control is an executed probe family (the fixture load + the synthetic unknown block); (3) the TC-B94-19 matrix's mixed split + the all-inert degenerate arm + the hostile arm; (4) the in-run byte-check + battery arm 06 + 0-hunk diffs against BOTH the increment base and `origin/main`; (5) the per-cell census of the 29 marked snapshot cells (C-22) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | AT-B94-14 (the no-suppression conclusion); TC-B94-19 (the split / no-op / fail-closed conclusions); TC-B94-18 (the freeze + membership conclusions) |
| Conjunctive criteria: one mutation per conjunct | arm 05 = the synthetic non-standard name admitted (the strict-membership conjunct); arm 01 = the synthetic never-fires predicate (the code+severity+shape+membership chain's verdict conjunct); arm 04 = the synthetic un-remapped rows; the hostile `EVIL[red]` arm = the shape-mismatch conjunct (fails closed, stays a warning) — one mutation per conjunct |
| Synthetic Instance of the absent case | arms 01/04/05 (the never-fires / un-remapped / over-admitted mutations); TC-B94-19's hostile payload (a file-derived block name that can never match the strict shape) |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified probe on the known-present case: `FROBNICATE` DOES warn on the same predicate (the known-present warning); the curated PAGE / REF_CHARACTERISTIC rows DO render INFO (the known-present reclassification); the freeze byte-check returns identity on the untouched engine bytes; the snapshot run DOES report its 29 marked cells as xfailed (the known-present marks) — uniformity avoided everywhere: the refused and accepted arms return different, expected answers |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "a2l_reclassified_severity\|adjust_counts_for_a2l_triage\|CURATED_STANDARD_A2L_BLOCKS" s19_app/ tests/ --exclude-dir=__pycache__` (re-run at this cut) | **3 files**: `s19_app/tui/issues_view.py` (the definitions), `s19_app/tui/app.py` (the painters — the only consumers), `tests/test_tui_issues_triage_b94.py` (the minted host) — 0 stale readers; **0 service imports of the view** (`grep -rln "from ..issues_view\|from .issues_view\|import issues_view" s19_app/tui/services/` → 0). The pre-existing `GroupedIssuesPanel` symbol: 6 test readers (`test_tui_a2l_issue_recolor` / `test_tui_app` / `test_tui_directionb` / `test_tui_issues_triage_b94` / `test_tui_issues_view` / `test_validation_service_supplemental`) — all re-validated green by the 21-node family run |
| B2 file moved on disk | n/a — no file moved in this increment | the B2 probe is not owed; declared `n/a` rather than silently skipped |
| B3 byte-identical golden captures this source | `grep -rln "GroupedIssuesPanel\|A2L_UNRECOGNIZED_BLOCK\|WARNINGS" tests/goldens/` | **0** — the grep names no golden file (no byte-identity golden captures the issues surface); no rebaseline; the golden observers run green (ac6 + addendum 32; batch35 host 15) |
| B4 artifact produced here is consumed elsewhere | who reads the triaged rows/counts | in-batch only — the app's strip/summary Statics and the grouped panel consume the helper's counts and the remapped rows; nothing is written to disk; no outside-lane reader |
| A3 interface consumed by another module changed | `git diff 3d76f2a..b43f8ad -- s19_app/validation/rules.py s19_app/tui/a2l.py` + the view's import census (`grep -n "import" s19_app/tui/issues_view.py \| grep -i "rules\|a2l"` → no match) | **0 hunks on both engine paths** (byte-equal to `main`) — the frozen interface is consumed, never changed; `render_groups` / `build_issues_severity_strip` keep their signatures — the 6 pre-existing panel readers stay green; the engine constant is never imported by the view |
| did-NOT-fire probes (C-48) | named, with their probes: (a) `git diff 3d76f2a..b43f8ad -- s19_app/validation/rules.py s19_app/tui/a2l.py` → **0 hunks** (the engine stays frozen — battery arm 06 touched the constant and was hash-restored); (b) the snapshot matrix owns no A2L-issues cell → **0 owned-cell drift** (the seeded snapshot content has no A2L rows — zero-delta no-op); (c) the view's engine-import census → **no match** (the curated set is view-owned; the byte-check is the only engine contact) | every named probe executed or byte-verified at this gate; no silent "was not evaluated" |
| freeze probes | TC-B94-18's in-run byte-equality against `main`'s blobs (CRLF-aware) + `git diff origin/main..b43f8ad` over the two engine paths → 0 hunks + battery arm 06 | the freeze holds at every instrument; every hit re-validated |

| Field | Value |
|---|---|
| **Reverse census** | `7` probes run of B1 · B2 · B3 · B4 · A3 (+ did-NOT-fire + freeze probes): B1 3 readers, all this increment's own set, 0 stale, 0 service imports of the view · B2 `n/a` — no move · B3 0 goldens capture the issues surface; observers green, no rebaseline · B4 in-batch consumers only; nothing on disk · A3 0 engine hunks at both bases, the panel/strip signatures unchanged, the 6 pre-existing readers green · did-NOT-fire named per C-48: engine 0 hunks · 0 owned snapshot cells · the view never imports the engine constant |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the strip/summary + `group_counts` fold | every whole-list severity painter / counter in the app whose surface HLR-012's "shall not present them as warnings" reaches | `grep -n "severity == ValidationSeverity\|build_issues_severity_strip\|group_counts\|update_workspace_stats\|validation_issue_filter_mode" s19_app/tui/app.py`, enumerated before the first edit | 5 surfaces: the strip/summary painters, the panel's `group_counts`, the `#ws_stats` workspace stat pane, the severity filter buttons | `s19_app/tui/app.py` — the 3 presentation sites ride `adjust_counts_for_a2l_triage` | the 2 residuals left raw **deliberately**, with the owner ruling recorded: `#ws_stats` (F1 — folding would amend LLR-042.9-pinned behavior) and the severity filter buttons (F2 — needs an owner decision on the LLR-042.x filter semantics); §4b/§6 name them |
| the corpus census moves with the minting increment | the scanned-test-file bound vs the on-disk test roster | `tests/test_id_registry.py` (`EXPECTED_SCANNED_TEST_FILES`, the measured bound) | 179 → 180 | the one constant, in the landing commit | none — the bound moves with its landing increment, never before (LLR-002.2 idiom) |
| the curated-set lineage | the 21-name set vs the executed 2026-10-13 tally | the tally pinned in the minted test as `EXPECTED_TALLY` (437+221+180+69+69+22+6+3+3+2+1×11 = 1 023), re-derived from the fixture load before the constant was seeded | 21 families / 1 023 findings | `issues_view.py` — the constant | none |

| Field | Value |
|---|---|
| **Correction population** | `3` corrections, each enumerated with its method before its first site was edited (the five-surface app census before the fold; the registry bound at the landing commit; the tally lineage pinned in the minted test) — the 2 surfaces left raw are named with their owner ruling, not silently skipped |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the raw painters in `app.py` (the `sum(1 for … severity == …)` triple + the raw `group_counts` dict) | the two triaged sites now call `adjust_counts_for_a2l_triage`; surviving raw severity reads: the `#ws_stats` painter (`update_workspace_stats`) and the severity filter predicate (`validation_issue_filter_mode`) — both named, owner-ruled residuals (F1/F2) | yes — every surviving raw count is a declared F1/F2 site, not a missed fold | `s19_app/tui/app.py` (the two helper call sites + the two F1/F2 sites); §4b/§6 name the ruling |
| the pre-Inc-004 `render_groups` row mount | the raw mount is superseded by the predicate-gated `dataclasses.replace` remap; the no-reclassification arm proves the byte-identical no-op (counts untouched, 0 justification notes) | yes | TC-B94-19's degenerate arm (`tests/test_tui_issues_triage_b94.py`) |

### Signed-balance test ledger

`post = base − deleted + added` → `180 = 179 − 0 + 1`  ✓ reconciles — the measured corpus census
(`tests/test_id_registry.py`: 179 → 180, this increment's 1 NEW file). The registry edit posts as
an in-place census move; it carries no balance change beyond the one constant.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean |

Review record:

- **Verdict: clean — no HIGH, no MEDIUM; two findings recorded.** F1 (**major, recorded with
  owner**): the Workspace `#ws_stats` aggregate line still speaks raw severity — on the stand-in
  fixture it shows `Warnings: 1 023` while the Issues surface around it reads the triaged census.
  Folding it would amend LLR-042.9-pinned behavior (the batch-28/29 frozen artifact's stat pane:
  coverage %, range/error/warning counts), so it was NOT folded; the owner ruling is recorded
  here — **owner: the P4/close review or lane A**. F2 (**minor**): the severity filter-button
  selection chrome speaks raw severity — selecting "Warnings" still lets the reclassified rows
  through (they render as INFO); this is label-vs-content only — **no wrong severity is rendered
  anywhere**. Fold only with an owner decision on the LLR-042.x filter semantics.
- **The explicit judgment question, answered:** does the shipped surface violate HLR-012's
  "shall not present them as warnings"? The reviewer's answer: **no violation on the shipped
  surface** — under the "Warnings" filter the reclassified rows render as INFO; the filter button
  is selection chrome, not a presentation of the findings as warnings; every counted presentation
  (strip, summary, group headers) reports the triaged census (the AT's chrome arm proves all
  three on the live drive).
- **The load claims verified with executed evidence:** the reviewer re-derived the packet's
  load-bearing figures against the stored bytes — the battery baseline + 7 arms (12/12 RED,
  `inc004_battery.txt`), the C-20 move-aside restore (before=after `6311f7c3…`), the guard host
  (184), the Issues-surface family (21), the snapshot matrix (3+29), the golden observers
  (ac6 + addendum 32; the batch35 host 15), the registry guard (14) — each claim checked against
  its transcript, not the prose.
- **Discharge:** F1/F2 recorded with owners (this cell + §6); nothing else open. The cell stays
  `clean`.

---

## 5 · Risks

*(What could break that this increment does not cover. Be specific enough to act on.)*

- **F1/F2 await the owner ruling.** `#ws_stats` and the severity filter buttons speak raw
  severity by design until the owner decides (P4/close review or lane A for F1; an owner decision
  on the LLR-042.x filter semantics for F2). Until then the two surfaces can disagree with the
  triaged Issues census — visible, named, and bounded to those two surfaces.
- **The canonical-CI snapshot regen (29 marks) must land before the next chrome change** —
  carried from Inc-001/003, unchanged this increment (the seeded snapshot content has no A2L
  rows: zero-delta no-op here). Under `strict=False` a stale mark XPASSes silently and masks
  regressions; the batch-77 retirement note is the precedent. Owner: the canonical CI regen
  workflow, before any further chrome move.
- **The R-2 register (contract §6.2):** a future standard block outside the curated 21-name set
  floods INFO instead of WARNING (operator blindness by classification). Mitigation stands: the
  curated set is a named, reviewable constant; additions are ledger entries; the D-2 re-open
  condition stands.
- **The freeze disjointness holds only while the engine does not learn a curated name.** The
  curated 21 and the engine's recognized 15 are disjoint by construction (the emitter fires only
  for unrecognized names); if a future engine change recognized one of the 21, the emitter would
  stop firing for it and the census would move silently at the engine level. TC-B94-18's in-run
  byte-check + battery arm 06 pin the engine bytes — an engine edit fails loud, not silent.
- **The 1 023-count oracle keys on the stand-in fixture.** AT-B94-14 pins the exact census
  (1 023 findings, the 21-family tally as a literal); a fixture change fails loudly — the tally
  is pinned, never derived at run time.

---

## 6 · Pending items / spec deviations

*(Anything surfaced and not closed here. Every line lands in the canonical backlog at batch close —
if the increment surfaced it, the backlog owns it.)*

- **The KEY-FACTS reconciliation — 21 vs the brief's 15 framing (deviation a):** the increment
  brief's framing carried the probe's `RECOGNIZED_A2L_BLOCKS has 15 entries` — the ENGINE's
  recognized-set size. The executed tally seeds **21 families** (disjoint from the engine's 15 by
  construction — the emitter only fires for names the engine does NOT recognize). Recorded: the
  contract's view-owned 21-name set governs (LLR-012.1); all 1 023 findings move to INFO;
  `FROBNICATE` / non-curated names stay warnings; the engine constant is never imported by the
  view (byte-check only — TC-B94-18). The 15 is the engine's figure, not the curated set's.
- **The strip/summary fold — 2 source files (deviation b):** the SOURCE count rose from the
  declared 1 (`issues_view.py`) to 2 by the fold round — HLR-012 binds every presentation, so
  `app.py`'s strip/summary painters and `group_counts` ride the same helper (§2 states the
  reason; the increment stays 2/4, under the cap).
- **The workspace-stats / filter chrome carried, recorded (deviation c):** F1 (`#ws_stats` raw
  `Warnings: 1 023`) and F2 (the filter-button chrome speaks raw severity) ship un-folded with
  the owner ruling recorded (§4b): owner = the P4/close review or lane A (F1); an owner decision
  on the LLR-042.x filter semantics (F2).
- **Snapshot: zero-delta no-op (deviation d):** no issues-cell drift occurred — the seeded
  snapshot content has no A2L rows, so Inc-004 repaints nothing; the 29 marks stand, all
  xfailed as predicted (3 passed + 29 xfailed, exit 0). The canonical-CI regen retires them (§5).
- **The at_061a/tc330 flake family (deviation e):** documented pre-existing (batch-95 verified
  the at_061a/tc330 pair pre-existing at HEAD pristino; Inc-003's gate run recorded 14+1 with
  the failure named). Green in isolation (Inc-003: 3/3 + reviewer 1/1) and **green in this
  gate's run** — 15 passed, `inc004_suite_goldens_batch35.txt`. The packet cites the bytes; the
  family stays named until the canonical-CI regen.

---

## 7 · Suggested next task

**Phase 4 — validation.** The batch's requirement coverage is complete: every contracted story
is realized and **all 24 acceptance ids (AT-B94-01…24) are landed** — AT-B94-14 was the last.
Next is the P4/DDR validation station: the traceability matrix over the four increment packets,
the V-model validation runs against `04-validation.md`, and the batch-95 IFC-debt baseline
re-derivation (0 new fails over the declared baseline). Note for the next gate: the V2
station-expected family is now **EMPTY** — every V2 red is a true regression. The F1/F2 owner
ruling rides the P4/close review; the canonical-CI snapshot regen (29 marks, §5) should land
before any further chrome move.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2/4 — the raise from the declared 1 is stated (§2): the fold round made app.py's strip/summary painters + group_counts ride the view's helper (HLR-012 binds every presentation); under the cap |
| 2 | Tests written in this same increment | all | ✓ | 1 NEW file mints the 3 ids / 3 nodes with the product change (§2; commit `b43f8ad`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | no standalone layer-0 nodes — the candidates host inside TC-B94-18/19 (§4); one complete run owned by the orchestrator = the battery's clean-tree baseline, ONE run, 3 passed, tail read from `inc004_battery.txt` |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 field — the C-20 move-aside of the net-new file (collection RED, exit 4) + the 7 per-node battery mutations; transcript `evidence/inc004_move_aside.txt` / `inc004_battery.txt`; restore digests `6311f7c3a98bd876a68717a5c2d5b2e98382662d9ebd5eef02e528e7d10db89b` (move-aside, before=after) / `a70e08de…` / `1c2c2003…` / `96f29f49…` (battery, before=after, `RESTORE PROVEN`) |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 field — B1 3 readers, all this increment's own, 0 service imports of the view · B2 n/a (no move) · B3 0 goldens (`grep -rln "GroupedIssuesPanel\|A2L_UNRECOGNIZED_BLOCK\|WARNINGS" tests/goldens/` names nothing) · B4 in-batch consumers only · A3 0 engine hunks at both bases, signatures unchanged; did-NOT-fire named: engine 0 hunks · 0 owned snapshot cells · the view never imports the engine constant |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ✓ | §4b — clean; no HIGH / no MEDIUM; F1 (major, `#ws_stats` raw — owner ruling recorded: P4/close review or lane A) + F2 (minor, filter chrome — owner decision on LLR-042.x semantics); the HLR-012 judgment question answered (no violation on the shipped surface); the load claims verified with executed evidence |
| 7 | No file from another lane touched | all | ✓ | single-lane trunk batch (§2.8 declared empty); the B1 census shows every touched file is this increment's own, no foreign-lane file |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | 0 hunks on `validation/rules.py` + `tui/a2l.py` against both the increment base and `origin/main`; TC-B94-18's in-run byte-check + battery arm 06; the view never imports the engine constant |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | counts read from the stored transcripts' tails (184 / 21 / 3+29 / 32 / 15 / 14 / 3-baseline); digests re-derived from the bytes at the evidence home (§4 Evidence files) |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 — 5 absences, each with its guard + synthetic instance (arms 01/04/05 + the hostile arm) + positive controls (the FROBNICATE warning / the curated-INFO rows / the untouched-freeze identity / the 29 known-present marks) |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 field — 7 arms / 12 node-runs, per resolved node, 12/12 RED; inert arms: none (0 SURVIVED / 0 CRASH-BAD in the totals); transcripts cited with hash restores |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 field — 4 instruments (the runner's BAD-anchor guard; the move-aside trigger-absent failure; the freeze byte-check under arm 06; the chrome/surface emitted-form asserts under arm 07) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 field — 3 corrections, each with its enumeration command (the five-surface app census before the fold; the registry bound at the landing commit; the tally lineage pinned in the minted test); the 2 raw residuals named with their owner ruling |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 field — 3 artifacts (the severity-strip Static; the summary Static; the grouped panel's rows/headers/justification), each asserted on `render().plain` |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ✓ | §4b cell — `code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean` |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 field — 10 artifacts under `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each with its SHA-256 re-derived from the stored bytes; the `-text` mark holds (index bytes = worktree bytes) |
