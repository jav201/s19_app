# Increment 001 — `HLR-122` · `LLR-122.1` – `LLR-122.5` — the foundation adoption: 41 unpinned test modules become the contract's verifiers

> **Agent note.** The commission's named route — Kimi K2.7-code via opencode — was
> attempted first and failed at the provider: `inc001-run.log` records
> `Error: Incorrect API key provided` (opencode's Moonshot provider holds no key on
> this machine). The increment ran on a **Kimi coder subagent under the coordinator's
> brief** instead (`inc001-brief.md` is that brief, verbatim). Declared here rather
> than smoothed: the brief, the sandbox rules and the report-back contract were
> opencode's; the executor changed, the contract did not.

| Field | Value |
|---|---|
| Batch | `2026-10-08-batch-91` |
| Increment | `001` |
| Lane (if the batch forked) | none — one lane on the main checkout; the three increments hold disjoint file sets by construction (`01-requirements.md` §2.8) |
| Requirement(s) | `HLR-122` · `LLR-122.1` · `LLR-122.2` · `LLR-122.3` · `LLR-122.4` · `LLR-122.5` |
| Acceptance | `AT-284` · white-box `TC-617` – `TC-648` (32 ids) · unit = the adopted modules' own 358 nodes |
| Agent | `kimi-k2.7-code` (coder subagent), coordinator-briefed |
| Date | `2026-10-11` (batch id carries the 2026-10-08 commission date; `state.json`'s `created_at` is 2026-10-11) |

---

## 1 · What changed

**The foundation engines carry the contract they never had, and not one line of
shipped behaviour moved.** 32 RESERVED entries (`TC-617` – `TC-648`, chartered by
this batch at P0) became LIVE in `AT-TC-REGISTRY.jsonl`, each with its statement
from the LLR's pinned law and its `nodes` — **358 `file::function` pairs derived
by `tools/id_registry.py`'s own machinery** (`inc001_derive_nodes.py`, same
`ast.walk` and same rendering as `derive_named_nodes`, every emitted name checked
against `defined_names()` before write — a node that does not exist on disk is a
lie the registry cannot carry). Each of the **41 adopting test modules** gained a
docstring block naming its TC (`# TC-NNN — <mapping>`), written by
`inc001_docstrings.py` under four pre-write assertions: still parses, the token
lands in the docstring, the token DELTA is exactly the module's own TC (measured
with the registry's own `iter_tokens`), and the diff is **additions-only** (difflib;
the single allowed exception is `test_a2l_enriched.py`'s one-line docstring
expanded to multi-line — one modified line, still inside the docstring).

**The acceptance arm is new and batch-scoped:** `tests/test_batch91_adoption.py`
(`AT-284`, two arms — every TC in 617..648 is LIVE with a non-empty `nodes` list;
every named node exists on disk). The generic guard (`tests/test_id_registry.py`)
checks every LIVE entry's nodes; this module adds the completeness direction — no
chartered TC left RESERVED, dropped, or bound to nothing.

**The guard itself needed repair, and the repair was measured, not incremented.**
The P0 reservation had moved the ids past the declared water marks without updating
them (G7 red on the untouched tree): `_meta.high_water` 283/616 → **287/650**,
`next_free` 288/651 (`inc001_registry.py`). `EXPECTED_SCANNED_TEST_FILES` 156 → **158**
in two measured moves — the P0 repair's `tests/__init__.py` (156 → 157) and this
increment's new test file (157 → 158) — each re-derived by two paths that share no
code (`scanned_test_files()` and an independent glob re-derivation), per the note
now standing at `tests/test_id_registry.py:81-89`.

---

## 2 · Files modified

**The budget counts SOURCE files only. This increment touches no `s19_app/` module: 0 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `AT-TC-REGISTRY.jsonl` | `config` | HLR-122 | 32 RESERVED→LIVE conversions **in place** (same line position, no duplicates — the script asserts the id sequence is unchanged); `_meta` high-water repair |
| `tests/test_core_srecord_validation.py` | `test` | TC-617 · LLR-122.1 | docstring token block (additions-only) |
| `tests/test_hexfile.py` | `test` | TC-618 · LLR-122.1 | docstring token block |
| `tests/test_hex_emit.py` | `test` | TC-619 · LLR-122.1 | docstring token block |
| `tests/test_range_index.py` | `test` | TC-620 · LLR-122.1 | docstring token block |
| `tests/test_address_census.py` | `test` | TC-621 · LLR-122.1 | docstring token block |
| `tests/test_address_origin.py` | `test` | TC-621 · LLR-122.1 | docstring token block |
| `tests/test_a2l_enriched.py` | `test` | TC-622 · LLR-122.2 | docstring token block (one-line docstring expanded — the single allowed line edit) |
| `tests/test_a2l_missing_length_fix.py` | `test` | TC-623 · LLR-122.2 | docstring token block |
| `tests/test_a2l_record_layout_length.py` | `test` | TC-624 · LLR-122.2 | docstring token block |
| `tests/test_tui_a2l.py` | `test` | TC-625 · LLR-122.2 | docstring token block |
| `tests/test_validation_a2l.py` | `test` | TC-626 · LLR-122.2 | docstring token block |
| `tests/test_tui_mac.py` | `test` | TC-627 · LLR-122.3 | docstring token block |
| `tests/test_validation_mac.py` | `test` | TC-628 · LLR-122.3 | docstring token block |
| `tests/test_crc_kernel.py` | `test` | TC-629 · LLR-122.4 | docstring token block |
| `tests/test_crc_designer_model.py` | `test` | TC-630 · LLR-122.4 | docstring token block |
| `tests/test_crc_template_loader.py` | `test` | TC-630 · LLR-122.4 | docstring token block |
| `tests/test_crc_word_codec.py` | `test` | TC-630 · LLR-122.4 | docstring token block |
| `tests/test_unload_feature.py` | `test` | TC-631 · LLR-122.5 | docstring token block |
| `tests/test_undo_redo_ux.py` | `test` | TC-632 · LLR-122.5 | docstring token block |
| `tests/test_universal_paste.py` | `test` | TC-633 · LLR-122.5 | docstring token block |
| `tests/test_capped_text_area.py` | `test` | TC-634 · LLR-122.5 | docstring token block |
| `tests/test_discoverability.py` | `test` | TC-635 · LLR-122.5 | docstring token block |
| `tests/test_filename_markup_safety.py` | `test` | TC-636 · LLR-122.5 | docstring token block |
| `tests/test_tui_hostile_map.py` | `test` | TC-637 · LLR-122.5 | docstring token block |
| `tests/test_tui_helpers.py` | `test` | TC-638 · LLR-122.5 | docstring token block |
| `tests/test_tui_services.py` | `test` | TC-638 · LLR-122.5 | docstring token block |
| `tests/test_map_click_chain.py` | `test` | TC-639 · LLR-122.5 | docstring token block |
| `tests/test_memmap_entropy_merge.py` | `test` | TC-640 · LLR-122.5 | docstring token block |
| `tests/test_patch_dual_entry.py` | `test` | TC-641 · LLR-122.5 | docstring token block |
| `tests/test_flow_execution.py` | `test` | TC-642 · LLR-122.5 | docstring token block |
| `tests/test_flow_multi_image_ui.py` | `test` | TC-642 · LLR-122.5 | docstring token block |
| `tests/test_legend_n8.py` | `test` | TC-643 · LLR-122.5 | docstring token block |
| `tests/test_legend_scope_and_logwidth.py` | `test` | TC-643 · LLR-122.5 | docstring token block |
| `tests/test_report_logging.py` | `test` | TC-644 · LLR-122.5 | docstring token block |
| `tests/test_report_progress.py` | `test` | TC-644 · LLR-122.5 | docstring token block |
| `tests/test_report_off_ui_thread.py` | `test` | TC-644 · LLR-122.5 | docstring token block |
| `tests/test_workspace_variants.py` | `test` | TC-645 · LLR-122.5 | docstring token block |
| `tests/test_tui_evidence_packs.py` | `test` | TC-646 · LLR-122.5 | docstring token block |
| `tests/test_examples_pilot_gifs.py` | `test` | TC-646 · LLR-122.5 | docstring token block |
| `tests/test_sync_evidence.py` | `test` | TC-647 · LLR-122.5 | docstring token block |
| `tests/test_cli.py` | `test` | TC-648 · LLR-122.5 | docstring token block |
| `tests/test_batch91_adoption.py` | `test` | AT-284 · HLR-122 | **new** — the adoption-completeness acceptance, 2 arms |
| `tests/test_id_registry.py` | `test` | HLR-122 | the registry guard — `EXPECTED_SCANNED_TEST_FILES` 156 → 158 with the measured two-path note |

**The P0 collection repair, carried by this packet.** Found at P0 (before any
increment existed — the suite could not collect; the close's *Found before the
batch* holds the mechanism and the evidence), executed by the coordinator as the
batch's first shipped change, and recorded here because no earlier packet exists.
These twelve files are otherwise untouched by the batch:

| File | Kind | Traces to | Change |
|---|---|---|---|
| `tests/__init__.py` | `test` | HLR-122 | **new** — the repo's own `tests` package wins the import over an editable install's stray one (the `.pth` shadow; 22 collection errors before, 2760 collected / 0 errors after) |
| `tests/test_before_after_report.py` | `test` | HLR-122 | P0 repair: `from conftest import …` → `from tests.conftest import …` |
| `tests/test_flow_crc_ribbon.py` | `test` | HLR-122 | P0 repair: bare `from test_* import` × 2 → `tests.`-qualified |
| `tests/test_flow_crc_ui.py` | `test` | HLR-122 | P0 repair: bare `from test_* import` × 2 → `tests.`-qualified |
| `tests/test_report_addendum_bound.py` | `test` | HLR-122 | P0 repair: `from conftest import …` → `tests.`-qualified |
| `tests/test_report_document_bound.py` | `test` | HLR-122 | P0 repair: `from conftest import …` → `tests.`-qualified |
| `tests/test_report_field_census.py` | `test` | HLR-122 | P0 repair: bare `from test_* import` × 2 → `tests.`-qualified |
| `tests/test_report_producer_bound.py` | `test` | HLR-122 | P0 repair: `from conftest import …` → `tests.`-qualified |
| `tests/test_tui_commandbar.py` | `test` | HLR-122 | P0 repair: bare `from test_* import` → `tests.`-qualified |
| `tests/test_tui_patch_variant.py` | `test` | HLR-122 | P0 repair: bare `from test_* import` → `tests.`-qualified |
| `tests/test_tui_report_filter_surface.py` | `test` | HLR-122 | P0 repair: `from conftest import …` → `tests.`-qualified |
| `tests/test_tui_report_seam.py` | `test` | HLR-122 | P0 repair: `from conftest import …` **and** `from test_* import` → `tests.`-qualified |

(Three further files carry both the P0 import fix and an adoption/hygiene token —
`tests/test_report_logging.py`, `tests/test_report_progress.py`,
`tests/test_report_document_bytes.py`; they sit in their adoption/hygiene rows
above and in `increment-003.md`.)

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 |
| Test files | 55 (41 adopted modules + 1 new + the guard + the 12 P0-repair files) (uncapped) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`; outside the count) |

---

## 3 · How to test

```bash
# the adopted modules — byte-identical green (docstring lines only)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_core_srecord_validation.py \
  tests/test_hexfile.py tests/test_hex_emit.py tests/test_range_index.py tests/test_address_census.py \
  tests/test_address_origin.py tests/test_a2l_enriched.py tests/test_a2l_missing_length_fix.py \
  tests/test_a2l_record_layout_length.py tests/test_tui_a2l.py tests/test_validation_a2l.py \
  tests/test_tui_mac.py tests/test_validation_mac.py tests/test_crc_kernel.py \
  tests/test_crc_designer_model.py tests/test_crc_template_loader.py tests/test_crc_word_codec.py \
  tests/test_unload_feature.py tests/test_undo_redo_ux.py tests/test_universal_paste.py \
  tests/test_capped_text_area.py tests/test_discoverability.py tests/test_filename_markup_safety.py \
  tests/test_tui_hostile_map.py tests/test_tui_helpers.py tests/test_tui_services.py \
  tests/test_map_click_chain.py tests/test_memmap_entropy_merge.py tests/test_patch_dual_entry.py \
  tests/test_flow_execution.py tests/test_flow_multi_image_ui.py tests/test_legend_n8.py \
  tests/test_legend_scope_and_logwidth.py tests/test_report_logging.py tests/test_report_progress.py \
  tests/test_report_off_ui_thread.py tests/test_workspace_variants.py tests/test_tui_evidence_packs.py \
  tests/test_examples_pilot_gifs.py tests/test_sync_evidence.py tests/test_cli.py -q -p no:cacheprovider

# the guard + the batch's own acceptance
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest \
  tests/test_id_registry.py tests/test_batch91_adoption.py -q -p no:cacheprovider

# the executed RED counterfactuals (in-memory mutations; the shipped registry is hash-pinned)
PYTHONDONTWRITEBYTECODE=1 C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-08-batch-91/evidence/inc001_counterfactuals.py
```

The ONE complete gate-suite run is the coordinator's (`C-25`), in flight at this
packet's write; this increment ran per-area runs only, per the brief's discipline.

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | the adopted modules' own 358 registry nodes | 474 collected across the 41 modules at close-out re-measurement (the increment's per-area runs: 472 passed + 2 xfail, byte-identical green — docstring lines only); **0 failures** |
| **A · white-box** `TC-617`–`TC-648` ↔ LLR-122.1–.5 | `core` · `full` | 358 | LIVE with nodes, every named node on disk (`AT-284` arm b) |
| **B · black-box** `AT-284` ↔ US-102 | `core` · `full` | 2 arms | 2 passed (`tests/test_batch91_adoption.py`) |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **M1 (RESERVED-flip):** `TC-617`'s entry flipped LIVE → RESERVED in an in-memory copy of the registry → arm (a) must redden. **M2 (phantom node):** `TC-618` gains a node naming `test_phantom_node_does_not_exist` — defined nowhere, and that is the mutation → arm (b) must redden |
| Instrument | `evidence/inc001_counterfactuals.py` — drives the **shipped arm functions** imported unmodified; only their `_batch91_entries` data source is redirected at the corrupted copy. The shipped `AT-TC-REGISTRY.jsonl` is never written |
| Where it ran | this tree, read-only — the mutations live in memory; chosen deliberately because the coordinator's `C-25` full-suite run was in flight and an on-disk mutation would have contaminated it |
| Transcript | `evidence/inc001_counterfactuals.txt` — M1: `TC-617 is RESERVED, not LIVE — the adoption is incomplete`; M2: `TC-618 names '…::test_phantom_node_does_not_exist' but … is not defined in tests/test_hexfile.py` |
| Restore proven by | sha256 of the shipped registry identical before/after (`cf88ca52…2030f`, printed by the harness and asserted) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | **2** — both named in the transcript's header; positive control (unmutated registry) GREEN × 2 printed before any mutation was believed |
| Verdict granularity | per resolved node id — each arm function invoked separately, its own `AssertionError` captured |
| Arms that stayed GREEN | under M1, arm (b) GREEN (named in the transcript); under M2, arm (a) GREEN |

| Field | Value |
|---|---|
| **RED counterfactual** | M1 RESERVED-flip on `TC-617` (status field, LIVE→RESERVED) reddened `test_at284_every_batch91_tc_is_live_with_nodes`; M2 phantom-node append on `TC-618` (nodes list, +1 nonexistent function) reddened `test_at284_every_named_node_exists_on_disk`. Transcript `evidence/inc001_counterfactuals.txt`; restore digest `cf88ca52e4ffd2661f748515f42e4bc686e852860e641dbfc9ad67b86292030f` before == after |

| Field | Value |
|---|---|
| **Mutation verdicts** | `test_at284_every_batch91_tc_is_live_with_nodes`: M1 (TC-617 status flip) **KILLED**. `test_at284_every_named_node_exists_on_disk`: M2 (phantom node append) **KILLED**. Arms that stayed GREEN: arm (b) under M1, arm (a) under M2. 0 SURVIVED · 0 CRASH · 0 BAD. Transcript `evidence/inc001_counterfactuals.txt`; restore digest as above |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `inc001_counterfactuals.py` (the counterfactual harness) | the two corrupted registry views (M1, M2) | both arms RED with the offender named — before its `VERDICT: … 0 SURVIVED` line was believed; the positive control had to print GREEN × 2 first (asserted) |
| `inc001_derive_nodes.py` / `inc001_docstrings.py` / `inc001_registry.py` (the write scripts) | none planted | their pre-write asserts (existence oracle, additions-only diff, exact token delta, id-sequence unchanged, `converted == 32`) were the failure surface; no known-bad input was fed — declared, not claimed |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 1 instrument (the counterfactual harness) shown RED twice before its PASS was believed; the three write scripts carry internal asserts and were **not** separately RED-proven — declared |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the 41 docstring token blocks | re-scan of every adopted module's emitted bytes for its `# TC-NNN —` line (loop over the 41-module map) | `modules checked: 41; TCs: 32; missing tokens: []` |
| the 32 LIVE registry entries | `AT-284` arm (a)/(b) against the emitted `AT-TC-REGISTRY.jsonl` | 2 passed; census at close-out: 32 LIVE entries, 358 nodes total |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 2 artifact classes, each asserted against the emitted bytes on disk (module sources; the registry file), not against the scripts' intent |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | no absence claim — arm (a) is a bounded positive census over the 32 chartered ids; arm (b) a bounded positive existence check |
| If the result is an ABSENCE, what made the search wide enough | n/a |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `tests/test_batch91_adoption.py`'s module docstring states the module guards the batch's completeness claim, not the engines' behaviour |
| Conjunctive criteria: one mutation per conjunct | arm (a) is conjunctive (registered ∧ LIVE ∧ non-empty nodes): M1 exercises the LIVE conjunct; the empty-nodes conjunct is subsumed by M2's existence machinery — declared rather than mutated separately |
| Synthetic instance of the absent case | M2's phantom node **is** the synthetic instance of "a named node that does not exist" |
| **Positive control for every probe that returned an ABSENCE** | no probe returned an absence; the harness's positive control (unmutated registry → GREEN × 2) is printed in the transcript |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "test_batch91_adoption\|BATCH91_TC_STEMS" tests/ tools/` | the new module is referenced by no other test; the adopted modules' functions are named by `AT-TC-REGISTRY.jsonl`'s nodes and re-validated by `tests/test_id_registry.py`'s G-arms and `AT-284` arm (b) — all green |
| B2 file moved on disk | `git diff --name-status HEAD -- tests/ \| grep -c "^R"` | **0** renames — adoption moves nothing |
| B3 byte-identical golden captures this source | `grep -rl "TC-61\|TC-62" tests/__snapshots__/ tests/goldens/ 2>/dev/null` | **0** hits — no golden captures a docstring; the snapshot-bearing adopted modules re-ran green in the per-area runs |
| B4 artifact produced here is consumed elsewhere | `grep -rln "AT-TC-REGISTRY.jsonl" tools/ tests/` | consumers: `tools/id_registry.py`, `tests/test_id_registry.py`, `tests/test_batch91_adoption.py`, `tests/test_batch91_registry_hygiene.py` — every consumer re-validated green |
| A3 interface consumed by another module changed | the per-edit difflib assertion in `inc001_docstrings.py` (additions-only, token delta == the module's own TC) | no interface moved: 41/41 edits are docstring/comment lines; the one modified line stays inside `test_a2l_enriched.py`'s docstring |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 · B2 · B3 · B4 · A3) with their commands and verdicts above; B2/B3 returned 0 hits, each with its command printed; every B4 consumer re-validated green |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the registry `_meta` high-water trailed the P0 reservation (G7 red) | every chartered id must sit at or below `high_water` | G7 itself (`tests/test_id_registry.py::test_tc606_g7_no_stem_exceeds_the_high_water_mark`) over the untouched tree | 1 site (the `_meta` line) | 1 | 0 — single-site correction |
| the 41 modules must carry their TC token | one token block per adopting module | the adoption map is the contract's own (LLR-122.1–.5 name every module); `inc001_docstrings.py` iterates exactly that map | 41 | 41 | 0 — the map is closed by the contract |

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, each enumerated from its authority (the guard's own RED; the contract's own module lists) before the first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the 32 RESERVED entries for `TC-617`–`TC-648` | the conversions replaced the RESERVED lines **in place** — `inc001_registry.py` asserts the pre/post id sequence is identical and duplicate-free | yes — `AT-284` arm (a) fails on any survivor (`is RESERVED, not LIVE`); M1 proved that arm fires | `AT-TC-REGISTRY.jsonl` lines for TC-617..648; `inc001_counterfactuals.txt` M1 |

### Signed-balance test ledger

`post = base − deleted + added` → `2762 = 2760 − 0 + 2` at this increment's gate ✓ reconciles (2760 = the P0 post-repair collection; +2 = AT-284's arms). Batch-level balance, including increment 003's +3, is in `04-validation.md`.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — reviewed the adoption map against the contract's LLR-122.1–.5 module lists (41/41 accounted), the registry diff in place (id sequence unchanged, `_meta` repaired to the measured 287/650), the guard bumps against their two-path derivations, and the byte-identical-green requirement on the per-area runs. No HIGH. The reviewer is the same human who owns the `C-25` suite run — declared, so the reader knows the lens and the runner are one pair of eyes |

---

## 5 · Risks

- **Adoption pins the suite as it stands, flake included.** The adopted modules run
  green per-area; the full-suite figure is the coordinator's `C-25` run, and the
  known Textual-surface flaky family (BACKLOG-CODE, 2026-09-03) can move its
  membership between runs without touching this increment's claim.
- **The contract says what the code does, not what it should.** Where a module pins
  behaviour no prose stratum covered, the statement was written from the shipped
  law (characterization). A future reader must not read these TCs as design intent.
- **`TC-649`/`TC-650` stay RESERVED** (chartered spares) — the registry still holds
  46 RESERVED entries; that is a fact, not a defect, and AT-284's range (617–648)
  deliberately excludes them.

## 6 · Pending items / spec deviations

- None owed by this increment. The batch-level carries (the un-minted `AT-285`
  harness, the spare reservations) land in `05-close.md` §4 and the backlog lanes.

## 7 · Suggested next task

Increment 002 — the docs catch-up (`HLR-123`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **0** source files — no `s19_app/` module touched; the diff is tests + the registry |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_batch91_adoption.py` (AT-284, 2 arms), new in this increment |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the adopted 358 nodes ARE the layer-0 layer — existing unit tests adopted, not duplicated; re-deriving them would be the re-implementation the contract forbids |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | M1/M2 above; transcript `evidence/inc001_counterfactuals.txt`; restore digest `cf88ca52…2030f` before == after |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes with commands and verdicts; B2/B3's zero-hits carry their commands |
| 6 | `code-reviewer` passed — verdict and reviewer in **§4b** | `core` · `full` | ⚠ | no `code-reviewer` agent lens ran; `human:coordinator` reviewed instead — the substitution is declared in §4b, not hidden behind a name |
| 7 | No file from another lane touched | all | ✓ | single lane; increments 002/003's file sets are disjoint from this one by the contract §2.8 |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | no `s19_app/` file in the diff; the engine-frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, …) untouched |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | nodes derived by `inc001_derive_nodes.py` against `defined_names()`; 41/41 token re-scan over emitted bytes |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | no absence claim; M2's phantom node is the synthetic instance |
| 11 | **Mutation verdicts** declared — per arm, inert arms named | all | ✓ | per-node verdicts above; arms staying GREEN named under each mutation; 0 inert (the 2-arm baseline printed) |
| 12 | **Instrument RED-proof** declared | all | ✓ | the harness shown RED twice before its VERDICT; the write scripts' reliance on internal asserts declared |
| 13 | **Correction population** declared | all | ✓ | 2 corrections, enumerated from the guard's RED and the contract's lists before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | docstring tokens re-scanned on emitted bytes (41/41); registry entries asserted by AT-284 over the emitted file |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared — digests of the STORED bytes | all | ✓ | 8 artifacts below, each re-hashable at its path |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-08-batch-91/evidence/inc001-brief.md` | `46dad73d9117d44862ff78dbad4be9d2d04954448671d23466a71dbd57bfe8fa` |
| the failed opencode launch (provider key absent) | `.dev-flow/2026-10-08-batch-91/evidence/inc001-run.log` | `418935dfa1cad1f8eacca319ae4e5ae7c80adc3ee16ec66509a62d85933b9021` |
| node-derivation script (the library's machinery) | `.dev-flow/2026-10-08-batch-91/evidence/inc001_derive_nodes.py` | `df27271da3ce02e8c144d57fe94e2a90cffb7b2574734a5d870a60e601aa54f7` |
| docstring-insertion script (additions-only verified) | `.dev-flow/2026-10-08-batch-91/evidence/inc001_docstrings.py` | `c31ea555a40fd998f44ea60969faaaf808824f5b83dc0905a310849400692b2f` |
| the derived 358-node map | `.dev-flow/2026-10-08-batch-91/evidence/inc001_nodes.json` | `db7c5e2817a583f917d5bdcb8475d4928e146b38cb83743f8e12ad41fbdc2169` |
| registry conversion + `_meta` repair script | `.dev-flow/2026-10-08-batch-91/evidence/inc001_registry.py` | `aa776161ba86e88932cd51d85613d25fc6fcb69a65b1e19117108dea3d6cf955` |
| counterfactual harness (M1/M2) | `.dev-flow/2026-10-08-batch-91/evidence/inc001_counterfactuals.py` | `bd6922e8b9b9ebec5bb591f1fea880d02ec87ad6223c926fe18ba044f81266ec` |
| counterfactual transcript | `.dev-flow/2026-10-08-batch-91/evidence/inc001_counterfactuals.txt` | `e6f4290a4c788fa58bb1975274e76e13bf4c93e6b9400f3c3fddfb68ebc8c2c1` |

| Field | Value |
|---|---|
| **Evidence files** | 8 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes |
