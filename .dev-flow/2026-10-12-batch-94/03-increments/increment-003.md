# Increment 003 — US-007 · HLR-017…021 · `fx_a Flow Execution + rail 12`

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
> `.dev-flow/2026-10-12-batch-94/03-increments/increment-003.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

> **A table you may delete.** A table whose `| **Field** |` row reads `none — <reason>`, or whose question one line of the gate checklist answers, may be deleted, its field row kept: `stations/core-runbook.md` §*A minimal increment packet* is a one-function change written that way.

| Field | Value |
|---|---|
| Batch | `2026-10-12-batch-94` |
| Increment | `003` |
| Lane (if the batch forked) | `none — single-lane trunk batch` · `n/a` (§2.8 fork preconditions, the declared empty; one worktree, one lane) |
| Requirement(s) | `US-007` · `HLR-017…021` · `LLR-017.1/.2` · `LLR-018.1/.2` · `LLR-019.1/.2` · `LLR-020.1/.2` · `LLR-021.1/.2` (the realized Inc-003 subset) |
| Acceptance | `AT-B94-02, 19…24` (7 black-box) · `TC-B94-05, 08, 26…31` (8 white-box) — 15 ids minted across 19 collectable nodes · **AT-B94-14 is now the ONLY unlanded AT** (Inc-004) |
| Agent | `software-dev` |
| Date | `2026-10-14` |

---

## 1 · What changed

*(BLUF: state the outcome first, then the mechanism. Name the shipped surface the user reaches.)*

**BLUF.** Flow Execution is real. `FlowExecutionPanel` opened at the R8 address
`s19_app/tui/flow_screens.py` (+742 lines) with its two lane dataclasses (`FxLaneSpec` — the payload
posted to the app; `_FxLane` — the live view state): Import… mounts one **lane** per builder
template, side by side; each lane paints its pinned inputs in a boxed `_Grid` frame with a shaded
`▓/░` progress bar and a `▶✗✓` status glyph; per-input **rebinding** touches exactly that lane's
record; **Run** dispatches the set through the service's new `ChainSpec`/`run_chain_set` —
sequential by default, parallel per chain on demand — and paints the **RUN LOG** strip whose inline
`✗` names the failed chain's block and its missing config (the operator's suggestion #1);
**Save Set / Load Set** persist and restore the whole set (`flowsets/<name>.json` — chains + bound
inputs + recorded outputs) so a reloaded set re-runs without re-binding. The operator reaches it
through the **twelfth rail entry** — `▶`/`>`, after Flow Builder, on the `]` binding
(`show=False`, the R-1 closure's idiom; the footer does not drift, C-13). Realized story: **US-007 →
HLR-017…021**, with HLR-002's census half (the guard-host constants move 11→12 in the same commit,
LLR-002.2). 15 ids minted (one AT = one on-disk node per C-18; AT-B94-24 and TC-B94-05/30/31 carry
a second service-side node each — 19 collectable nodes across the 2 new files). **C-3 discharges
here**: the 80×24 pilot arm measures the 12-entry rail at 12 rows inside the 21-row budget.

**Mechanism, seam by seam:**

1. **The fx_a panel** (HLR-017, AT-B94-19 / TC-B94-26) — `FlowExecutionPanel` composes the name
   strip (the C-10 dirty-guard idiom), the help line, the run row (Import… / mode Select /
   Run), the set row (name / Save Set / set picker / Load Set), the notice line, the scrollable
   lane container and the run-log Static. Import… posts `ImportRequested`; the app reuses the
   EXISTING `LoadFlowScreen` picker (`screens.py`, containment-guarded — no fifth file) and loads
   through the hardened `load_flow_json`: a cancelled picker adds 0 lanes (the cancel arm), a
   corrupt template is refused with the notice (0 lanes mounted), a valid one mounts one lane
   (duplicate imports uniquify `_<N>`, 0 duplicate lanes).
2. **Per-chain rebinding** (HLR-018, AT-B94-20 / TC-B94-27/28) — each `_FxLane` owns its
   `bindings` dict (LLR-018.1's independent state); the Bind control writes only its own lane;
   `lane_specs()` emits the EFFECTIVE inputs (every SOURCE ref with the operator overrides merged),
   and the runner consumes each chain's own plan (LLR-018.2) — a rebind never names a stale input.
3. **Mode control + dispatch** (HLR-019, AT-B94-21/22 / TC-B94-05) — the mode Select's untouched
   default is `sequential`; `run_chain_set` dispatches sequential in that arm and parallel
   per chain otherwise (the C-10 non-default arm), wrapping the union `run_flow` per chain — the
   panel and the app re-implement no block semantics. The `ChainSetRunRecord` captures the mode,
   per-lane outcomes and the report path; a parallel lane's failure isolates to its own chain.
4. **Run log + provenance** (HLR-020, AT-B94-23 / TC-B94-29/30) — `render_run` repaints each lane
   and emits the strip: one `▶ … started` and one terminal line per chain, plus the inline
   `✗ <chain> · block i/n <KIND> — <detail> · chain halted` for a mid-chain failure (the recorded
   diagnostic, never invented text). The chain-set report (`# Chain-set report — <name>`) records
   each chain's input provenance — one `- Chain <name> input <i>: <ref> [bound] path=…` line per
   bound input (the C-42 paste, `inc003_smoke_probe.txt`).
5. **Chain-set save/reload** (HLR-021, AT-B94-24 / TC-B94-31) — `save_chain_set` writes the v1
   envelope (`schema_version` 1, `kind` "chain-set", chains with template/bound-inputs/recorded-
   outputs) through the write-side sanitiser and the `import_flow_file` containment idiom; an
   empty set or a sanitised-away name writes NOTHING and surfaces one status line. `load_chain_set`
   reads fail-closed (the V1–V6 chain-set vocabulary, `dict_to_chain_set`); a successful reload
   REPLACES the lanes (the C-12 chain — a restore, never a merge); a moved bound input is not a
   refusal — the lane mounts with the per-lane provenance-mismatch notice (never a silent stale
   run); a chain whose template is gone is skipped and NAMED.
6. **Rail 12 + `]`** (AT-B94-02 / TC-B94-08, LLR-002's census half) — `RAIL_ENTRIES_B94` lands
    12 entries (Flow Execution after Flow Builder; the `▶`/`>` glyph pair is the Phase-3 chrome
   census), `Binding("right_square_bracket", …, show=False)` routes it, `SCREEN_CONTAINER_IDS` /
   `_FIND_GOTO_INPUTS` gain the `flow_execution` key, and the set picker repopulates on entry
   (the `_prefill_check_editor` idiom). The guard-host census constants move 11→12 in the SAME
   commit (LLR-002.2 — never before): `SCREEN_IDS`/`SCREEN_KEYS`/`EXPECTED_RAIL` 12,
   `_NON_DIGIT_SCREEN_KEYS = ("check_editor", "flow_execution")` replaces the single-key
   exclusion, and TC-001's positions re-derive.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/flow_screens.py` | source | HLR-017 · HLR-018 · HLR-020 · LLR-017.1/.2 · LLR-018.1 · LLR-020.1 | +742 — `FlowExecutionPanel` + `FxLaneSpec` + `_FxLane`: the lane compose/paint (boxed `_Grid` frame, `▓/░` bar, status glyph), per-lane binding widgets, the run-log strip composer, the save/load-set messages; every file-derived string markup-safe (C-17) |
| `s19_app/tui/services/flow_execution_service.py` | source | HLR-019 · HLR-020 · LLR-018.2 · LLR-019.1/.2 · LLR-020.2 | +434 — `ChainSpec` + `run_chain_set` (sequential default, parallel-per-chain dispatch, per-lane failure isolation), the `ChainSetRunRecord` (mode capture), the chain-set report composer with per-run input provenance lines; wraps the union `run_flow` per chain — no block semantics re-implemented |
| `s19_app/tui/services/flow_persistence_service.py` | source | HLR-021 · LLR-021.1/.2 | +449 — the `ChainSet`/`ChainSetEntry` envelope + `save_chain_set`/`load_chain_set`/`list_chain_sets`: the write-side sanitiser and `import_flow_file` containment idiom, the V1–V6 fail-closed `dict_to_chain_set` read (existence NOT required — a moved input is the LLR-021.2 notice arm, not a refusal) |
| `s19_app/tui/app.py` | source | US-007 · HLR-017 · LLR-002.1 | +314 — the twelfth `RAIL_ENTRIES_B94` entry + the `]` binding (`show=False`) + `SCREEN_CONTAINER_IDS`/`_FIND_GOTO_INPUTS` + `_compose_screen_flow_execution` + the four `on_flow_execution_panel_*` handlers (template import through the reused `LoadFlowScreen` picker, run dispatch, set save/load) + the on-entry set-picker prefill |
| `tests/test_tui_flow_execution_b94.py` | test | HLR-017 · HLR-018 · HLR-019 · HLR-020 · HLR-021 · LLR-017.1/.2 · LLR-018.1/.2 · LLR-019.1/.2 · LLR-020.1 · LLR-021.1/.2 | NEW — 956 lines, 11 nodes: AT-B94-02/19/20/21/22/23 + TC-B94-08/26/27/28/29 + AT-B94-24's UI half (rail census + pilot sizes, lane mounting/render census, binding isolation, mode arms, run-log emission, save/reload notices; `_PILOT_SIZES` + the pinned `_DECLARED_RAIL_ORDER` literal) |
| `tests/test_flow_chainset_b94.py` | test | HLR-018 · HLR-019 · HLR-020 · HLR-021 · LLR-018.2 · LLR-019.1/.2 · LLR-020.2 · LLR-021.1/.2 | NEW — 562 lines, 8 nodes: TC-B94-05/28/30/31's service-side halves + AT-B94-24's service half (mode capture in record+report, parallel dispatch, run-consumes-bindings, the C-42 provenance-line paste, compose determinism + md safety, the envelope round-trip, the empty-set/hostile-set fail-closed arms) |
| `tests/test_tui_directionb.py` | test | LLR-002.1 · LLR-002.2 | the guard-host census moves 11→12 — `SCREEN_IDS`/`SCREEN_KEYS`/`EXPECTED_RAIL` 12 (the `("flow_execution", "▶", ">")` row), `_NON_DIGIT_SCREEN_KEYS` + the derived digit censuses, TC-001's positions |
| `tests/test_tui_commandbar.py` | test | LLR-002.1 · LLR-002.2 | the five per-screen counts on the batch-78/79 frozen artifact move 11→12 (and the notice path 8→9 of 12) — the second named live-only delta (§6) |
| `tests/test_tui_snapshot.py` | test | LLR-002.2 | the batch-94 drift-mark extended — the 11→12 rail census repaints the SAME 29 cells, measured per cell before the mark was written (C-22); the canonical-CI regen note now retires BOTH generations |
| `tests/test_id_registry.py` | test | HLR-017 · HLR-018 · HLR-019 · HLR-020 · HLR-021 | corpus census `EXPECTED_SCANNED_TEST_FILES` 177→179, measured (this increment's 2 new files) |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4 — at the cap; the PDR-declared reason is stated below** |
| Test files | `6` (uncapped) — 2 new · 4 census moves |
| Doc files | `0` (outside the count) |

- ⚠ **At the 4-file cap (4/4):** declared per the budget rule at the PDR
  (`design-proposal.md` §Inc-003): the four files map one-to-one onto four contract-bound seams —
  the R8 panel home (`flow_screens.py`), the executor that owns run semantics
  (`flow_execution_service.py`, LLR-019/020), the persistence service that owns work-area-contained
  save/load (`flow_persistence_service.py`, LLR-021), and the sole legal rail/routing site
  (`app.py`). The chain-set report emission rides in the executor (the run owns the report) rather
  than adding a fifth service file; the template picker REUSES the existing `LoadFlowScreen`
  (`screens.py`) instead of forking a new one — `screens.py` stays a zero-hunk contact surface (§4
  Reverse census).
- ✗ If a file belongs to another lane's file set, stop: lanes may not share a file. — n/a, one lane.

---

## 3 · How to test

```bash
# the 19 minted nodes / 15 ids (ONE complete run — the battery's own baseline arm)
python -m pytest tests/test_tui_flow_execution_b94.py tests/test_flow_chainset_b94.py -q
# the 10-arm / 15-node-run mutation battery (full) + the C-20 move-aside
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_battery.py
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_move_aside.py
# the rail-12 probe (the shipped-tree reachability census at 120x30 and 80x24 — C-3's arm)
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_rail12_probe.py
# the fx_a smoke probe (lane paints, run-log strip, run record, the C-42 provenance paste)
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_smoke_probe.py
# the guard host (rail census 12 — 184 passed at gate)
python -m pytest tests/test_tui_directionb.py -q
# the 13-file flow family at the union (150 passed at gate)
python -m pytest tests/test_flow_a2b_b94.py tests/test_tui_flow_builder_b94.py tests/test_flow_builder_render.py tests/test_flow_crc_block.py tests/test_flow_crc_ribbon.py tests/test_flow_crc_ui.py tests/test_flow_execution.py tests/test_flow_execution_service.py tests/test_flow_model.py tests/test_flow_persistence.py tests/test_flow_report_fusion.py tests/test_tui_flow_execution_b94.py tests/test_flow_chainset_b94.py -q
# the commandbar batch-78/79 frozen artifact (45 passed at gate)
python -m pytest tests/test_tui_commandbar.py -q
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
# the corpus census + registry guard (13 passed at gate)
python -m pytest tests/test_id_registry.py -q
# the engine-frozen guard (1 passed at gate)
python -m pytest tests/test_engine_unchanged.py -q
```

(The probe/battery commands carry `PYTHONIOENCODING=utf-8` because the lane paints and run-log
prints box-drawing characters — a stock Windows cp1252 console cannot encode them; this is the same
discipline the battery runner sets for its own subprocesses.)

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | none minted standalone — the candidates (the envelope V1–V6 reader, the mode-dispatch branch, the provenance-line composer, the lane-name uniquifier) host inside TC-B94-05/28/30/31 per `design-proposal.md` §5 | hosted arms all green (see layers A/B) |
| **A · white-box** `TC-B94-05, 08, 26…31` ↔ LLR | `core` · `full` | 8 ids (13 collectable node instances across the 2 new files — TC-B94-05/28/30/31 carry service-side halves) | 8/8 ids green — the battery's ONE clean-tree baseline run of the minted nodes (`14 passed` at baseline, tail read from `inc003_battery.txt`), corroborated by the new-files transcript (`19 passed`) and the flow-family transcript (`150 passed`) |
| **B · black-box** `AT-B94-02, 19…24` ↔ story, through the shipped surface | `core` · `full` | 7 ids (one AT = one node, C-18; AT-B94-24 spans a UI half and a service half) | 7/7 green — battery baseline + the new-files transcript (`19 passed`) + the smoke probe's shipped-surface drive (`SMOKE OK`, `inc003_smoke_probe.txt`) + the rail-12 probe's shipped-tree run (`PROBE: PASS`) |

**Evidence digest — the increment's verification runs** (counts as returned by this gate's runs and
the stored transcripts cited in *Evidence files* below; the stored bytes are the authority):

- `tests/test_tui_directionb.py` — **184 passed** (the guard host at the 12-entry rail census;
  `inc003_suite_directionb.txt`).
- the 2 new files — **19 passed** (`inc003_suite_new_files.txt`, produced at this gate, one
  complete run).
- the 13-file flow family at the union — **150 passed** (`inc003_suite_flow_family.txt`, produced
  at this gate, one complete run).
- the commandbar batch-78/79 frozen artifact — **45 passed** (`inc003_suite_commandbar.txt`,
  produced at this gate).
- editors + variants five-file set — **52 passed** (`inc003_suite_editors.txt`, produced at this
  gate, one complete run).
- patch-family rewrite group — **74 passed** (`inc003_suite_patch_family.txt`, produced at this
  gate, one complete run).
- snapshot matrix — **3 passed + 29 xfailed**, predicted=observed per-cell
  (`inc003_suite_snapshot.txt`; the `29 mismatched snapshots` banner is the plugin's per-cell
  report of the 29 predicted xfails, exit 0).
- batch-95 compat probes — **86 passed** (`inc003_suite_b95_compat.txt`, produced at this gate:
  the loader-law battery `tests/test_flow_persistence.py` + the change-attribution suite
  `tests/test_changes_symbol_entries.py`, one complete run, exit 0).
- the R-7 golden observers — ac6 + addendum-bound **32 passed** (`inc003_suite_goldens_ac6.txt`);
  the batch35 pair observer host `test_before_after_report.py` — **14 passed + 1 failed**: the
  failure is `test_at_061a_persistent_control_survives_then_writes_pair_and_clears`, the documented
  pre-existing flake (`inc003_suite_goldens_batch35.txt`; §6 records the naming).
- the corpus census + registry guard — **13 passed** (`inc003_suite_registry_guard.txt`).
- the engine-frozen guard — **1 passed** (`inc003_engine_guard.txt`).
- **V2 station-expected note:** at this gate the ONLY remaining unlanded AT is **AT-B94-14**
  (Inc-004) — every other batch-94 acceptance id has landed (Inc-001/002/003).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **C-20 move-aside of the 2 net-new test files** (`tests/test_tui_flow_execution_b94.py`, `tests/test_flow_chainset_b94.py` — rename out of the tree, never stash): the minted fx_a nodes fail at collection with `ERROR: file or directory not found` — the trigger-absent run. Per resolved node, the ten battery arms below are the per-node counterfactuals (each by position and operation): the 12th rail row dropped (arm 01); a cancelled import mounts a lane (arm 02); one shared bindings dict across lanes (arm 03); the mode field hard-coded (arm 04); parallel-always dispatch (arm 05); the inline `✗` line suppressed (arm 06); the all-clean arm emits an `✗` (arm 07); the reload drops input bindings (arm 08); the runner ignores the bindings (arm 09); the outputs field omitted from the envelope (arm 10) |
| Instrument | project code: own hand through the battery runner — `PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_battery.py` (a script in the project's stack; field guide §`Mutation verdicts`) |
| Where it ran | **this tree** (`C:/Users/jjgh8/Github/s19_app-b94`), run by the implementer's increment session at Phase 3 — the same session that wrote the code; no other lane's tree. The battery capture is stamped 2026-10-14 (UTC); the smoke probe's report header reads `2026-10-14 06:59:07 UTC` |
| Transcript | `.dev-flow/2026-10-12-batch-94/evidence/inc003_move_aside.txt` (the move-aside RED + restore) and `inc003_battery.txt` (the 10-arm battery with the clean-tree baseline) |
| Restore proven by | **file hash returned to its pre-mutation value** — the move-aside transcript prints before=after `db680d482b1d150ffdff12a7201bc42c14230c229821cc3937f0fd52c090f412` for the execution file and `d4db68d3e1e4c7b0b8ef0e4146f9f3f3e2b2fe09459065b84590a035d9c3869f` for the chain-set file, then `RESTORE PROVEN (hash identical) for every moved-aside file`. ⚠ L1 (§4b): the recorded execution-file hash pins the PRE-C-56-fix bytes — the C-56 round edited that file afterwards (§6); the chain-set file's hash matches the committed bytes to this day. Every battery arm likewise prints `restore-hash OK`; `git status` was not accepted as proof |
| Bytecode cache | cleared — the runner invokes `python -B` with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 19 collectable nodes resolved via `pytest --collect-only` across the 2 new files; **15 node-runs** planned and run in ONE clean-tree baseline run — the count asserted up front (`arms: 10; node-runs: 15`); the baseline tail reads `14 passed` (the plan lists AT-B94-20 twice — it arms two battery arms — and the single baseline invocation collects it once) |
| Verdict granularity | **per resolved node id** — the transcript's verdict table prints one row per arm→node with its own verdict; the process exit code is never the verdict |
| Arms that stayed GREEN | **none** — `TOTALS: 15 node-runs | RED 15 | SURVIVED 0 | CRASH/BAD 0`; the runner exits `0 (all arms killed)` |

| Field | Value |
|---|---|
| **RED counterfactual** | the C-20 move-aside of the 2 net-new files — the trigger-absent run makes THIS increment's own new nodes fail at collection (`file or directory not found`), hash-proven restored (before=after `db680d482b1d…` / `d4db68d3e1e4…`; the execution-file digest pins pre-C-56-fix bytes — L1, §4b/§6) · transcript: `evidence/inc003_move_aside.txt` · the per-node counterfactuals are the ten battery mutations below, 15/15 node-runs RED, transcripts `evidence/inc003_battery.{py,txt}` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 10 arms / 15 node-runs, **15/15 RED, 0 SURVIVED, 0 CRASH/BAD** — per resolved node, by position and operation (C-56: no corrupted tokens spelled here; the transcript holds the literals): arm 01 `app.py` the 12th rail row (and its container/binding census) dropped from the shipped rail → AT-B94-02 RED, TC-B94-08 RED; arm 02 `app.py` the cancelled-import early-return made to mount a "cancelled" lane → AT-B94-19 RED, TC-B94-26 RED; arm 03 `flow_screens.py` one shared bindings dict across lanes — editing A writes every lane → AT-B94-20 RED, TC-B94-27 RED; arm 04 `flow_execution_service.py` the mode field hard-coded at record construction — the record never changes from the default → AT-B94-21 RED, TC-B94-05 RED; arm 05 `flow_execution_service.py` parallel-always dispatch — an untouched default run overlaps chains → AT-B94-22 RED; arm 06 `flow_screens.py` the inline `✗` line suppressed — the failure is visible only elsewhere → AT-B94-23 RED; arm 07 `flow_screens.py` the all-clean arm emits an `✗` — the log invents a failure → TC-B94-29 RED; arm 08 `flow_execution_service.py` the reload silently drops input bindings — a stale run by construction → AT-B94-24 RED; arm 09 `flow_execution_service.py` the runner ignores the bindings — a stale input is named after a rebind → AT-B94-20 RED, TC-B94-30 RED; arm 10 `flow_persistence_service.py` the outputs field omitted from the envelope — the round-trip loses it → TC-B94-31 RED. Restore: every arm `restore-hash OK` in the verdict table. Arms that stayed GREEN: **none**. Transcripts: `evidence/inc003_battery.txt` (+ runner `inc003_battery.py`). **The C-56 first-round catch:** the battery's FIRST round surfaced 2 SURVIVED test-side defects — the rail-order assert derived from the app's own census (it compared the app against itself, so arm 01 stayed GREEN) and the missing cancel arm (arm 02 had no test-side hook) — both fixed test-side (the rail order pinned as the `_DECLARED_RAIL_ORDER` literal; the cancel arm added) and the FULL battery re-run for ONE clean transcript (the stored bytes) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the battery runner | a mutation arm whose anchor does not match exactly once (the C-40 BAD-anchor guard, exercised in Inc-001/002's rounds and carried by the same runner here) | `CRASH/BAD (anchor count …)` — the runner reports that nothing was measured, not a pass; every arm here anchored 1:1 (no BAD in the totals line) |
| the C-20 move-aside probe | the tree with both net-new files renamed out (the trigger-absent state) | collection of the minted fx_a nodes fails: `ERROR: file or directory not found: tests/test_tui_flow_execution_b94.py`, exit 4 — `verdict: RED (KILLED)`, before any PASS from it was believed (`inc003_move_aside.txt`) |
| the smoke probe's error-chain arm | a two-lane parallel run whose second chain carries a CRC block with its config file missing (a real defect-bearing state) | the lane paints 50% `✗`, the run-log strip carries the inline `✗ base_crc · block 3/4 CRC — config 'crc_regions.json' missing · chain halted`, and the record reports `status=error` for that lane while the clean lane completes — the probe's own asserts fail if the inline failure line stops being painted (`SMOKE OK` only after the failure form is exact) |
| the golden observer host (`test_before_after_report.py`) | the pre-existing at_061a flake under the 12-entry chrome (a real defect-bearing state, batch-95-documented) | `FAILED … test_at_061a_persistent_control_survives_then_writes_pair_and_clears` — `1 failed, 14 passed`, exit 1 recorded in `inc003_suite_goldens_batch35.txt`: the observer reports failures instead of swallowing them, and its 14 green rows stand beside a real reported failure |

| Field | Value |
|---|---|
| **Instrument RED-proof** | `4` instruments — the battery runner (BAD-anchor guard), the C-20 move-aside probe (the trigger-absent failure mode), the smoke probe's error-chain arm (the CRC-config-missing failure painted inline), the golden observer host (the at_061a failure reported, not swallowed) — each shown able to report FAILURE before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the chain-set report's provenance lines (the service's chain-set report composer) | TC-B94-30 pins the provenance lines character-for-character against the increment's own paste — the smoke probe's actual parallel run emits `- Chain base input 1: base\.s19 [bound] path=`C:\…\workarea\proj\base.s19`` and `- Chain base\_crc input 1: variant\_b\.hex [bound] path=`C:\…\workarea\proj\variant_b.hex`` (the fixed `[bound] path=` shape); battery arm 09 drifts the runner's binding consumption → the stale input is named → RED, restore-hash OK | the report verbatim in `inc003_smoke_probe.txt` (`SMOKE OK`), from the header `# Chain-set report — chain-set` through the `## Input provenance` section to `*Generated by the s19_app Flow Execution (chain-set run).*` |
| the chain-set envelope (`save_chain_set`) | TC-B94-31 runs the shipped writer and re-reads the file through `load_chain_set`: the emitted bytes parse as the v1 envelope (`schema_version == 1`, `kind == "chain-set"`, chains with template/inputs/outputs); the empty-set and hostile-name arms write NOTHING (0 files, one status line each); the hostile-payload arms refuse fail-closed (`CHAIN-SET-*` findings) | envelope fields asserted in-test; arms 08/10 (binding-drop / outputs-omitted) → RED, restore-hash OK |
| the lane paint + run-log strip (`render_run`) | the smoke probe queries the real lane Statics and the `#fx_log` Static and pastes their `render().plain` — the boxed lane frames (`┌─[ base ]…┐`, `tpl base· 3 blocks`, the `▓▓▓… 100% ✓` / `▓▓▓░░░ 50% ✗` bars) and the strip's `▶ base · started` / `✓ base · done · wrote base_out.s19` / `✗ base_crc · block 3/4 CRC — config 'crc_regions.json' missing · chain halted` | the paints verbatim in `inc003_smoke_probe.txt`, both arms (`SMOKE OK`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | `3` artifacts — the chain-set report's provenance lines (the C-42 paste), the chain-set v1 envelope (incl. the empty-set and hostile-set arms), the lane paint + run-log strip (the verbatim paste) — each asserted against the bytes its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| battery runner (10 arms / 15 node-runs, hash restores, the clean-tree baseline) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_battery.py` | `d01568915f04559d6dbc2213b081fbccdb6503054c116dad06b3718ed6f16337` |
| main battery transcript — baseline, 10 arms, verdict table, totals | `.dev-flow/2026-10-12-batch-94/evidence/inc003_battery.txt` | `6be41194b4cd8bce06aab00c1d8054f1199ad1ae59d4214b9a4a0560950475a8` |
| C-20 move-aside runner (the 2 net-new files, hash before/after) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_move_aside.py` | `25d3767f258c425bfe4d09885a0ea038b67f3d3ee198c905bff8f60182652005` |
| C-20 move-aside transcript — RED + hash-proven restore | `.dev-flow/2026-10-12-batch-94/evidence/inc003_move_aside.txt` | `fd670f389c754136edbe5e087a1a5bd781ab55bd85766488a5664168101cd394` |
| rail-12 probe runner (the shipped-tree census at 120x30 + 80x24) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_rail12_probe.py` | `ac00fa94326802e5dc63a3ab97a6f6cb7d5fa3eabddc16f4a2e2655bd59fa13d` |
| rail-12 probe transcript — `PROBE: PASS`, 12 ≤ 21 rows at 80x24, `]` routes, zero collisions | `.dev-flow/2026-10-12-batch-94/evidence/inc003_rail12_probe.txt` | `f29f872820f8f0f1ca27318ecda62e8059ec42dc1a86e3f704290ca33d5da2c1` |
| fx_a smoke probe runner (lane paints, run-log, record, provenance paste) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_smoke_probe.py` | `f29d471652eed9727b06b94e43022b759960172a6d4c5e801a45496fa7dea827` |
| smoke probe transcript — `SMOKE OK`, the lane + run-log + report pastes | `.dev-flow/2026-10-12-batch-94/evidence/inc003_smoke_probe.txt` | `39fa4abf6c05c149bca2c24399b2f36c51d9450d33d4c83e948c7c68b21ce742` |
| suite transcript — the FULL guard host `test_tui_directionb.py`, one complete run (184 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_directionb.txt` | `a1d6e779035ffc7894698f50aaa3c5420549a651cd4eaa61221c73eeff67dbf4` |
| suite transcript — the 2 new files (19 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_new_files.txt` | `09b1a7c5fe470545576c9def35dc05da547c846ea15abb3ccd58f94ff9d3cb0a` |
| suite transcript — the 13-file flow family at the union (150 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_flow_family.txt` | `745a0638f67915cdbd512eb8f16ea6f23338302a2d64bffc17b44f44c3a5dcbe` |
| suite transcript — the commandbar batch-78/79 frozen artifact (45 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_commandbar.txt` | `5ced964b33865d96b5d0b5d394f34fee221ac342fa927611557bf965b8fd49ed` |
| suite transcript — editors + variants five-file run (52 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_editors.txt` | `268aac9afca0e91461d488f8bf3ba5c6758320f8d74096551eafefbb85eaeb5f` |
| suite transcript — the patch-family rewrite group (74 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_patch_family.txt` | `ac10a55b7d97ccc5525862e2369095b2756a09012e4a5233c6bb8d2c6481a159` |
| suite transcript — the snapshot matrix (3 passed + 29 xfailed, per-cell census) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_snapshot.txt` | `fdc958e8973124cbfd090c66a25ffde33a73f90b31f5b46abae4e5d51c4a8c23` |
| suite transcript — batch-95 compat probes (loader-law battery + change-attribution, 86 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_b95_compat.txt` | `3ca26b3f34b79b8a9966710ca7e213ff9a78b4d9fcedb3b56211b769eb90f864` |
| suite transcript — the R-7 golden observers (ac6 + addendum-bound, 32 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_goldens_ac6.txt` | `972ae2eb36cacdb1381cecd9da78e483776338074b205539ff201a1e479c6ffe` |
| suite transcript — the batch35 pair observer (14 passed + the at_061a flake) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_goldens_batch35.txt` | `c8fd89945b677a5d5a714508ed20961acc0e589d292239eec45a1fb9066901a9` |
| suite transcript — the corpus census + registry guard (13 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_suite_registry_guard.txt` | `fc13f47e3fffa499169755fab271818de87e39b7ef9719a147abcb8e4fa45844` |
| suite transcript — the engine-frozen guard (1 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc003_engine_guard.txt` | `8ad57cbc4d8db15412b66082549e8911659560cbb57b5b814b8a722c2227bc6f` |

| Field | Value |
|---|---|
| **Evidence files** | `20` rows at `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each cited with the SHA-256 of its stored bytes as listed above — digests re-derived from the bytes at those paths at this gate. The §4 suite figures (184 / 19 / 150 / 45 / 52 / 74 / 3+29 / 86 / 32 / 14+1 / 13 / 1 / 15-baseline) are the tails of the stored transcripts named in this table (one complete run each; the snapshot's `29 mismatched snapshots` banner is the plugin's per-cell report of the 29 predicted xfails, exit 0; the golden transcript's 1 failure is the documented at_061a flake, §6); the battery/move-aside/rail-12/smoke proof set is the stored runners + transcripts above |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | `yes` — (1) 0 lanes mounted by a cancelled import (LLR-017.1 cancel arm); (2) 0 duplicate lanes (the `_<N>` uniquifier); (3) 0 stale input names after a rebind (per-lane bindings consumed by the run); (4) 0 files written for an empty set or a sanitised-away name; (5) 0 golden captures of the chain-set report's emitted form |
| If the result is an ABSENCE, what made the search wide enough | (1) the cancel drive presses the picker's real Cancel control and counts lanes before/after (AT-B94-19, both pilot sizes); (2) the census imports the same template twice and counts lanes + names (TC-B94-26); (3) the rebind matrix rebinds A, runs, and reads B's consumed plan (TC-B94-27/28 + AT-B94-20); (4) the arms enumerate the 0-lane save and the hostile-name save and assert `flowsets/` gained no file (TC-B94-31); (5) the R-7 sweep greps every golden for the report's title string (§4 Reverse census B3) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | AT-B94-19 / TC-B94-26 (the lane-census conclusion — cancel mounts 0, duplicates uniquify); AT-B94-20 / TC-B94-27 (the binding-isolation conclusion); AT-B94-24 / TC-B94-31 (the restore-fidelity conclusion — bindings + outputs survive the round-trip) |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each absence is a single conjunct with its own arm (arms 02, 03, 08, 10 respectively; arm 01 for the rail census) |
| Synthetic Instance of the absent case | battery arm 02 ACCEPTS a cancelled import as a mounted lane — the synthetic illegal lane; arm 03 shares one bindings dict — the synthetic cross-lane write; arm 08 drops the reloaded bindings — the synthetic stale run; arm 10 omits the outputs field — the synthetic information-losing envelope |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified probe on the known-present case: a completed import DOES mount a lane (the smoke probe's two-lane drive); a same-template second import lands under `base_2` with both lanes live (TC-B94-26); a rebind DOES change exactly the rebound lane's consumed input (TC-B94-27's A-vs-B read); a valid 2-lane set save writes exactly one envelope file and reload restores 2 lanes (TC-B94-31's round-trip + AT-B94-24's re-run); a chain-set report IS emitted with one provenance line per bound input (the smoke paste) — uniformity avoided everywhere: the accepted and refused arms return different, expected answers |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "FlowExecutionPanel" s19_app/ tests/ --exclude-dir=__pycache__` (re-run at this cut) | **3 files**: `s19_app/tui/app.py` (the compose + handlers), `s19_app/tui/flow_screens.py` (the definition), `tests/test_tui_flow_execution_b94.py` (the minted host) — every reader is THIS increment's own file set; 0 stale readers |
| B2 file moved on disk | n/a — no file moved in this increment | the B2 probe is not owed; declared `n/a` rather than silently skipped |
| B3 byte-identical golden captures this source | the R-7 sweep (`01-requirements.md` §6.3 R-7): the three observers `tests/test_flow_report_ac6_golden.py`, `tests/test_report_addendum_bound.py`, `tests/test_before_after_report.py` + `grep -rl "Chain-set report" tests/goldens/` | **0** — the grep names no golden file (the chain-set report's emitted form is captured by NO byte-identity golden); the ac6 golden's `## Change attribution` section remains batch-95's re-captured bytes, untouched by the chain-set side; the observers run green (ac6 + addendum 32; batch35 host 14 + the at_061a flake) — clean, no rebaseline |
| B4 artifact produced here is consumed elsewhere | who reads the `flowsets/<name>.json` envelope and the chain-set report | the envelope's only consumer is this increment's own Load Set path (`load_chain_set` + the app's restore handler — in-batch); the report is an operator artifact (no in-tree consumer) — no outside-lane reader |
| A3 interface consumed by another module changed | `run_chain_set` wraps the union `run_flow`; batch-95's ReportBlock consumes `result.change_records` on the same `FlowResult` | the chain-set runner consumes `run_flow`'s result without changing its contract — batch-95's change-attribution still reads what it read (86-test b95-compat transcript green); no batch-95-frozen signature moved |
| did-NOT-fire probes (C-48) | named, with their probes: (a) `git diff <cut-base>..HEAD -- s19_app \| grep -c RECOGNIZED_A2L_BLOCKS` → **0** (the A2L engine stays frozen — AT-B94-14/Inc-004's surface); (b) `git diff … -- s19_app/tui/rail.py` → 0 hunks (rail.py stays the batch-93 record by design — the B94 rail is built in `app.py`); (c) `git diff … -- s19_app/tui/screens.py s19_app/tui/window_help.py` → 0 hunks (the `LoadFlowScreen` picker is REUSED, not forked; the `?` help chip is omitted rather than forking the batch-95-frozen section table — §6); (d) the snapshot matrix owns no `flow_execution` cell (`#screen_flow_execution` is not a matrix surface) → 0 owned-cell drift; the 29 marks are the shared-chrome rail census only | every named probe executed or byte-verified at this gate; no silent "was not evaluated" |
| supporting censuses | the batch-95 contact probes: `python -m pytest tests/test_flow_persistence.py tests/test_changes_symbol_entries.py -q` → 86 passed (the V1–V7 loader laws unreopened by the additive chain-set vocabulary — the zero-block reload refusal still reports `FLOW-BAD-STRUCTURE`); `tests/test_engine_unchanged.py` → 1 passed (the engine guard) | every hit re-validated; no hit left unowned |

| Field | Value |
|---|---|
| **Reverse census** | `7` probes run of B1 · B2 · B3 · B4 · A3 (+ did-NOT-fire + supporting censuses): B1 3 readers, all this increment's own file set, 0 stale · B2 `n/a` — no move · B3 0 goldens capture the chain-set report (`grep -rl "Chain-set report" tests/goldens/` names nothing); the three observers green, no rebaseline · B4 the envelope's consumer is in-batch; the report is operator-facing · A3 `run_chain_set` wraps the union `run_flow` without changing its contract — 86 compat green · did-NOT-fire named per C-48: `RECOGNIZED_A2L_BLOCKS` 0 hits · `rail.py` 0 hunks · `screens.py`/`window_help.py` 0 hunks · 0 owned snapshot cells |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the guard-host census moves 11→12 (LLR-002.2) | every rail-census constant in the guard host keyed on the entry count/order | the directionb census re-derivation (the `SCREEN_IDS`/`SCREEN_KEYS`/`EXPECTED_RAIL`/`_NON_DIGIT_SCREEN_KEYS` block + TC-001's positions), enumerated at the PDR before the first edit | 4 constant groups + TC-001 | `tests/test_tui_directionb.py`, in the landing commit | none — the constants move with their landing increment, never before |
| the batch-78/79 frozen artifact's per-screen counts | every screen-count / notice-path assertion across the commandbar host | `grep -n "== 11\|== 8" tests/test_tui_commandbar.py` + the per-screen drive census, enumerated before the first edit | 5 count sites (the `11→12` pair-census rows + the notice path `8→9 of 12`) | `tests/test_tui_commandbar.py`, in the landing commit | none — the second named live-only delta rides THIS increment (§6); the counts move with the landing increment per LLR-002.2's analog |
| the snapshot drift-mark extension | the batch-94 drift-mark cells + their retirement note | the per-cell census of the gate run (predict THEN verify, C-22): the 11→12 rail repaint predicted on the SAME 29 cells, measured against the actual run before the mark was extended | the same 29 cells + the note | `tests/test_tui_snapshot.py`, in the landing commit | none — the mark retires only at the canonical-CI regen (§5) |
| the corpus census moves with the minting increment | the scanned-test-file bound vs the on-disk test roster | `tests/test_id_registry.py` (`EXPECTED_SCANNED_TEST_FILES`, the measured bound) | 177 → 179 | the one constant, in the landing commit | none — the bound moves with its landing increment, never before (LLR-002.2 idiom) |

| Field | Value |
|---|---|
| **Correction population** | `4` corrections, each enumerated with its method before its first site was edited (the directionb census at the PDR; the commandbar count census; the snapshot per-cell C-22 census; the registry bound at the landing commit) — no sites left unedited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the 11-entry rail census (pre-Inc-003) | 0 live 11-entry asserts in the guard host — `EXPECTED_RAIL` is 12 rows; `RAIL_ENTRIES_B94` is 12 entries | yes — every surviving count reads 12 | `s19_app/tui/app.py` (`RAIL_ENTRIES_B94`); `tests/test_tui_directionb.py:497` (`EXPECTED_RAIL`); `inc003_rail12_probe.txt` (`RAIL_ENTRIES_B94 declares 12`) |
| the single-key digit exclusion (`!= "check_editor"`) | 0 surviving single-key exclusions — the tuple `_NON_DIGIT_SCREEN_KEYS = ("check_editor", "flow_execution")` replaced both derivation sites | yes | `tests/test_tui_directionb.py:178` (+ the two derived censuses at `:181-183`) |
| the "Flow Execution is Inc-003's (`]`, not bound here)" placeholder | 0 — the binding ships; `right_square_bracket` resolves to `show_screen('flow_execution')`, `show=False` | yes | `s19_app/tui/app.py` (`Binding("right_square_bracket", …)`); `inc003_rail12_probe.txt` (`right_square_bracket resolves …`) |

### Signed-balance test ledger

`post = base − deleted + added` → `179 = 177 − 0 + 2`  ✓ reconciles — the measured corpus census
(`tests/test_id_registry.py`: 177 → 179, this increment's 2 NEW files). The 4 changed test files
post as in-place census moves; they carry no balance change beyond the edited constants.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean |

Review record:

- **Verdict: clean — two LOW findings, no HIGH, no MEDIUM.** L1 (LOW): the C-20 move-aside's
  recorded execution-file hash (`db680d482b1d…`) pins the PRE-C-56-fix bytes of
  `tests/test_tui_flow_execution_b94.py` — the C-56 round edited that file after the move-aside
  ran (the test-side fix for the two SURVIVED defects, §4 Mutation verdicts). Reconstructible and
  harmless: the chain-set file's recorded hash matches the committed bytes, the battery's own
  restore hashes are post-fix, and the packet names the skew here and in §6 rather than letting
  the two digests stand unexplained. L2 (LOW): `dict_to_chain_set` accepts an empty `outputs`
  list per chain — a hand-edited foreign-set leniency (a chain saved before its first run);
  fail-closed is preserved everywhere else (V1–V6, containment, per-entry field checks). Recorded
  in the known-leniency register (§5/§6); no fix owed.
- **The load claims verified with executed evidence:** the reviewer re-derived the packet's
  load-bearing figures against executed bytes — the battery baseline + 10 arms (15/15 RED,
  `inc003_battery.txt`), the C-20 move-aside restore (both files before=after), the rail-12 probe
  (`PROBE: PASS`, 12 ≤ 21 rows at 80×24), the guard host (184), the new files (19), the flow
  family (150), the commandbar artifact (45), the editors (52) / patch (74) / snapshot (3+29)
  sets, the b95 compat probes (86), the golden observers (ac6 32; the batch35 at_061a failure
  reported), the registry guard (13) and the engine guard (1) — each claim checked against its
  transcript, not the prose.
- **Discharge:** L1 reconstructible + named (§6); L2 registered as a declared leniency (§5/§6).
  Nothing else open. The cell stays `clean`.

---

## 5 · Risks

*(What could break that this increment does not cover. Be specific enough to act on.)*

- **The canonical-CI snapshot regen (29 marks) must land before the next chrome change.** The
  11→12 rail census repaints the same 29 cells the Inc-001 mark already carried; the mark's
  retirement note now names BOTH generations (one regen retires both). Under `strict=False` a
  stale mark XPASSes silently and masks regressions — the batch-77 retirement note is the
  precedent. Owner: the canonical CI regen workflow, before any further chrome move.
- **The parallel-overlap AT is statistical + structurally barrier-proven.** AT-B94-21 proves the
  parallel mode by overlapping time windows (`window=(t0, t1)` pairs intersect across lanes)
  plus per-lane failure isolation; the sequential default is the untouched-path pin
  (AT-B94-22). The overlap assertion is statistical in nature — a pathologically fast sequential
  run could masquerade — which is why the mode capture (TC-B94-05) and the dispatch arm
  (battery arm 05) pin the mechanism, not only the timing.
- **Assumption register (design §5/§6):** **A3** (fx_a two-lane layout inside the boxed budgets)
  and **A5** (no shared mutable service state across chains) DISCHARGE here — A3 by
  AT-B94-19/TC-B94-26 at `_PILOT_SIZES = ((120,30),(80,24),(160,40))` (two 46-cell lanes in the
  96×18 workspace; the 80×24 fallback scrolls inside `#fx_lanes_scroll`, LLR-017.2) and A5 by
  AT-B94-21's error arm + battery arm 03; **A6**'s chain-set half (the envelope + provenance
  emitted forms) discharges with the C-42 pastes; **A4** (real-terminal key delivery,
  unmeasurable headlessly) stays field-verification debt — the `]` binding is probe-verified
  headlessly (`right_square_bracket` resolves; zero collisions) but a human hand on a real
  terminal is the residual check.
- **C-3 discharged, with the receipt named:** the 80×24 pilot arm measures the rail at 12 rows
  inside the 21-row budget (`inc003_rail12_probe.txt`); the declared rail order is pinned
  test-side as the `_DECLARED_RAIL_ORDER` literal — the C-56 lesson that a derived oracle
  compares the app against itself.
- **Known-leniency register (L2):** `dict_to_chain_set` accepts a per-chain empty `outputs` list
  (hand-edited foreign sets). Revisit only if a consumer starts relying on outputs being
  non-empty; no fix owed this batch.

---

## 6 · Pending items / spec deviations

*(Anything surfaced and not closed here. Every line lands in the canonical backlog at batch close —
if the increment surfaced it, the backlog owns it.)*

- **The second named live-only delta on the batch-78 frozen artifact (deviation a):** the five
  per-screen counts in `tests/test_tui_commandbar.py` moved 11→12 (the notice path 8→9 of 12) —
  the same live-only pattern Inc-001 established for the Check Editor's `=` landing (the counts
  move WITH the landing increment, LLR-002.2's analog for that frozen guard; the comment at
  `test_tc_b79_03` names the regime). Recorded per the deviation rule; the artifact itself is a
  test surface, not a product file.
- **The `?` chip omitted on the new screen (deviation b):** `window_help.py` is batch-95-frozen
  and names no `flow_execution` section, so `#screen_flow_execution` ships no focused-`?` chip
  rather than forking the frozen table — zero hunks on `window_help.py` (and on `screens.py`,
  whose `LoadFlowScreen` is reused as the import picker). Composed around the freeze; the help
  gap is named here for the batch-95 coordination lane.
- **The at_061a flake (deviation c):** the batch35 observer's failing row is
  `test_at_061a_persistent_control_survives_then_writes_pair_and_clears` — the documented
  pre-existing flake (isolated 3/3 green + reviewer re-run 1/1 green; batch-95 verified the
  at_061a/tc330 pair pre-existing at HEAD pristino). The packet cites the bytes: 14 passed + 1
  failed, exit 1, in `inc003_suite_goldens_batch35.txt`.
- **No fifth file (deviation d):** the chain-set report rides in `flow_execution_service.py`
  (the run owns the report) and the template picker reuses `screens.py`'s `LoadFlowScreen` — the
  SOURCE set stays 4/4 at the cap per the PDR's one-to-one seam mapping (`design-proposal.md`
  §Inc-003).
- **The C-56 first-round catch (L1's origin):** the battery's first round surfaced 2 SURVIVED
  test-side defects — the rail-order assert derived from the app's own census, and the missing
  cancel arm — fixed test-side (`_DECLARED_RAIL_ORDER` pinned as a literal at
  `tests/test_tui_flow_execution_b94.py:180`; the cancel arm added) and the FULL battery re-run
  for one clean transcript (the stored bytes). Consequence recorded per L1 (§4b): the move-aside
  transcript's execution-file hash pins the pre-fix bytes (`db680d482b1d…`); the committed bytes
  hash `d50fa7c9d85a…` — the skew is reconstructible from the battery's post-fix restores and is
  named here so the two digests are never mistaken for a failed restore.
- **L2 (the known leniency):** `dict_to_chain_set` accepts a per-chain empty `outputs` list — a
  hand-edited foreign-set leniency (§5). Registered; no fix owed.

---

## 7 · Suggested next task

**Increment 004 — Issues warnings triage** (US-004; HLR-012; AT-B94-14 — the last unlanded AT;
TC-B94-18/19): the view-level reclassification of `A2L_UNRECOGNIZED_BLOCK` in the Issues surface
via a curated ASAP2 standard-keyword constant seeded from the executed tally
(`evidence/p1_probe_a2l_unrecognized.txt`), one source file (`issues_view.py`), the engine
(`rules.py`, `a2l.py`) frozen — the A2L census this increment's did-NOT-fire probes already hold
at 0 hits. The canonical-CI snapshot regen (29 marks, §5) should land before Inc-004's chrome
moves, if any.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4 — at the cap with the PDR-declared reason (one-to-one contract seams; the report rides in the executor; the picker is reused — no fifth file; `design-proposal.md` §Inc-003) |
| 2 | Tests written in this same increment | all | ✓ | 2 NEW files mint the 15 ids / 19 nodes with the product change (§2; commit `e3d6001`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | no standalone layer-0 nodes — the candidates host inside TC-B94-05/28/30/31 (design §5); one complete run owned by the orchestrator = the battery's clean-tree baseline, ONE run, `14 passed`, tail read from `inc003_battery.txt` |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 field — the C-20 move-aside of the 2 net-new files (collection RED, `file or directory not found`) + the 10 per-node battery mutations; transcript `evidence/inc003_move_aside.txt` / `inc003_battery.txt`; restore digests `db680d482b1d150ffdff12a7201bc42c14230c229821cc3937f0fd52c090f412` (pre-C-56-fix bytes — L1 named) / `d4db68d3e1e4c7b0b8ef0e4146f9f3f3e2b2fe09459065b84590a035d9c3869f` (matches committed), before=after, `RESTORE PROVEN` |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 field — B1 3 readers, all this increment's own · B2 n/a (no move) · B3 0 goldens (`grep -rl "Chain-set report" tests/goldens/` names nothing), observers green · B4 in-batch consumer; report operator-facing · A3 the union `run_flow` contract unchanged, 86 compat green; did-NOT-fire named: `RECOGNIZED_A2L_BLOCKS` 0 · `rail.py` 0 hunks · `screens.py`/`window_help.py` 0 hunks · 0 owned snapshot cells |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ✓ | §4b — clean; two LOWs (L1 the recorded execution-file hash pins pre-C-56-fix bytes — reconstructible, named §6; L2 `dict_to_chain_set` accepts empty outputs — registered leniency §5/§6, no fix owed); the load claims verified with executed evidence |
| 7 | No file from another lane touched | all | ✓ | single-lane trunk batch (§2.8 declared empty); the B1 census shows every touched file is this increment's own, no foreign-lane file |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `RECOGNIZED_A2L_BLOCKS` 0 hits · `rail.py` 0 hunks (stays the batch-93 record) · `screens.py`/`window_help.py` 0 hunks (picker reused; `?` chip omitted) · the V1–V7 loader laws unreopened (86 compat green); the chain-set vocabulary is additive |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | counts read from the stored transcripts' tails (184 / 19 / 150 / 45 / 52 / 74 / 3+29 / 86 / 32 / 14+1 / 13 / 1 / 14-baseline); digests re-derived from the bytes at the evidence home (§4 Evidence files) |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 — 5 absences, each with its guard + synthetic instance (arms 02/03/08/10/01) + positive controls (the completed-import / uniquified-duplicate / rebound-lane / valid-round-trip / provenance-paste twins) |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 field — 10 arms / 15 node-runs, per resolved node, 15/15 RED; inert arms: none (0 SURVIVED / 0 CRASH-BAD in the totals — the first round's 2 SURVIVED test-side defects were fixed and the battery fully re-run, one clean transcript); transcripts cited with hash restores |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 field — 4 instruments (the runner's BAD-anchor guard; the move-aside trigger-absent failure; the smoke probe's error-chain arm; the golden host's at_061a failure reported) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 field — 4 corrections, each with its enumeration command (the directionb census at the PDR; the commandbar count census; the snapshot per-cell C-22 census; the registry bound at the landing commit) and its sites |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 field — 3 artifacts (the chain-set report provenance lines incl. the C-42 paste; the chain-set v1 envelope incl. the empty-set/hostile-set arms; the lane paint + run-log strip) |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ✓ | §4b cell — `code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean` |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 field — 20 artifacts under `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each with its SHA-256; the naming notes (the at_061a flake; L1's pre-C-56-fix digest skew) are recorded in the field itself and §6 |
