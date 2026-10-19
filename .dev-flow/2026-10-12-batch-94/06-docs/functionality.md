# Functionality — s19_app — Batch 2026-10-12-batch-94

> **Roles:** `docs-writer` (this artifact). Batch `2026-10-12-batch-94`, repo `s19_app-b94`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 At a glance (read first)

- **What this batch added:** the Cambio1–7 commission shipped — the Patch/Check editor split with a `.chk.json` check-spec pipeline into the A2B diff report, the fb_a block-diagram Flow Builder with a configurable A2B block and templates, the fx_a Flow Execution surface with per-chain lanes and saveable chain-sets, and the Issues warnings triage — behind a 12-entry rail.
- **Capabilities:** write/validate check specs that flow into comparison reports · build flows as block diagrams (patch / CRC / A2B-diff blocks) with per-input provenance · run several chains side by side (sequential default, parallel per chain) and save/reload the whole set · a warning-free Issues view for standard A2L blocks.
- **How to use it:** launch the Direction-B TUI (`s19_app/tui/app.py`); the rail carries the surfaces — Patch Editor `6`, Check Editor `=`, Flow Builder `8`, Flow Execution `]`, Issues `9` (rail census `tests/test_tui_directionb.py:137-169`; probes `evidence/pdr_rail_key_probe.txt`, `evidence/inc003_rail12_probe.txt`).

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

### How it works (flow)

The batch ships four operator-facing surfaces behind one rail, in one new module and five changed ones (as-built declarations: `docs/architecture.md` §10 "Batch-94 declarations"; per-increment file sets: `03-increments/increment-001…004` §2):

1. **Check Editor → `.chk.json` → A2B Diff report (the C-12 chain).** The Check Editor (`CheckEditorPanel`, in `screens_directionb.py`) collects A2L parameters and memory locations and writes a v2 change document with `kind="check"` under a `.chk.json` name (`write_change_document`, `changes/io.py:1285`); the double suffix survives `_safe_name`. The A2B Diff dropdown lists check specs suffix-distinguished from patch files; loading one appends the declared items to the emitted report through `_check_addendum_lines` (`diff_report_service.py`) — the `## Checks` addendum. Acceptance observes the shipped chain only: writer → THAT file on disk → the report (AT-B94-11/12; TC-B94-13/15/16; diagram `diagrams/sequence-checks-chain.md`).
2. **Flow Builder (fb_a).** `FlowBuilderPanel` lives at its new R8 address `flow_screens.py` (B2 move): a palette rail with three placeable block types (patch · CRC · A2B-diff), a framed canvas painted by the `_Grid` painter (typed `in`/`out` stubs, box-drawn frames, refined cable runs), and template save through `save_flow_json` (`flows/*.json`, dedup-suffix collision handling). The A2B block binds each image input to a flow output (`#n.out`) or an external file; wiring validation enforces ≥1 input from the current flow and refuses both-external / cross-flow pairs at the Add control. Running a flow through Flow Execution executes each block through the existing services and emits one provenance line per A2B input in the report (AT-B94-15…17; TC-B94-04/20…24).
3. **Flow Execution (fx_a).** `FlowExecutionPanel` (`flow_screens.py`) imports builder templates — one lane per chain, side by side, with per-lane input rebinding. Run dispatches the set through `run_chain_set` (`flow_execution_service.py`): sequential by default, parallel per chain on demand, wrapping the existing `run_flow` per chain; the run record captures the mode; the RUN LOG strip prints one start + one terminal line per chain and an inline `✗` naming a failed chain's block and its missing config. Save Set / Load Set persists `flowsets/<name>.json` (chains + bound inputs + recorded outputs); a reload replaces the lanes and re-runs without re-binding; a moved input mounts a per-lane provenance-mismatch notice, never a silent stale run (AT-B94-19…24; TC-B94-05/26…31; diagram `diagrams/sequence-chain-set.md`).
4. **Issues triage.** The Issues surface reclassifies `A2L_UNRECOGNIZED_BLOCK` findings whose block name is in the curated ASAP2 standard-keyword set (`CURATED_STANDARD_A2L_BLOCKS`, 21 families) to INFO with a displayed justification — reclassification, never suppression: no row is dropped, the caller's engine list is never mutated, and genuinely unknown blocks still warn. One arithmetic site (`adjust_counts_for_a2l_triage`) folds the strip, the summary line, and the group headers so all three agree. The engine (`validation/rules.py`, `tui/a2l.py`) stays frozen — pinned by an in-run byte-check (AT-B94-14; TC-B94-18/19).

**The rail chrome.** The activity rail grew 10→12: Check Editor lands after Patch Editor on `=`, Flow Execution after Flow Builder on `]`, both `Binding(…, show=False)` — the digit key space `1`–`0` is exhausted at ten, the F-keys were rejected as terminal-swallow hazards, and the bindings were probe-verified at 80×24 + 120×30 with zero collisions (`PLAN.md` key decisions, PDR row; `evidence/pdr_rail_key_probe.txt`). All twelve entries render inside the rail's 21-row chrome budget at 80×24; the footer does not drift (`evidence/inc003_rail12_probe.txt`). The guard-host census constants moved with the landing increments (11 at Inc-001, 12 at Inc-003), never before (LLR-002.2).

### Operator rulings honored (the decision pins)

- **Schema unchanged (R10):** `.chk.json` is a suffix distinction on the existing v2 grammar — `kind="check"` already exists in `DOCUMENT_KINDS` (`changes/io.py:120-123`); no new package, no v3 envelope, no `from`/`to` fields.
- **Write/validate only:** a check spec can never be applied — `apply_change_document` already gates on `kind != "change"` (zero writes, `apply.py:320`); the Check Editor composes no apply control (the struck-APPLY ghost is an inert `Static`), and the gate over a check doc is the executed negative control (`blocked: 2`, `mem_map` untouched, `evidence/p1_probe_chk_roundtrip.txt`).
- **Provenance per block (D1):** the A2B report states each input's provenance (flow-output lines name the producing block; external lines match the executed base form verbatim), and the chain-set report records one provenance line per bound input per run.
- **Sequential default / parallel per chain (D4):** the untouched run is strictly sequential; the parallel mode is operator-selected per run, isolates a failed chain to its lane, and the selected mode is captured in the run record (C-10: the AT drives the non-default value).
- **Suffix distinction:** check specs are listed by their `.chk.json` suffix, distinguished from patch files in the same directory, in every listing surface.

### Components / modules touched
| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/flow_screens.py` | NEW module (R8) — the fb_a Flow Builder palette/canvas/cables + the fx_a Flow Execution lanes/run-log; pure view layer (`docs/architecture.md` §10) |
| `s19_app/tui/screens_directionb.py` | the pe_b Patch Editor rework + the NEW ce_a Check Editor + `LoadGuardScreen`; B2 vacate of the old Flow Builder (tombstone docstring only) |
| `s19_app/tui/changes/io.py` | the `.chk.json` suffix predicate + suffix-distinguished listing (`CHECK_SPEC_SUFFIX` / `is_check_spec_name` / `list_change_documents`) |
| `s19_app/tui/services/diff_report_service.py` | the `## Checks` report addendum (`_check_addendum_lines`, producer-side `md_safe` scrub) |
| `s19_app/tui/services/flow_model.py` | `BLOCK_A2B` + `A2BBlock` + `parse_a2b_binding` / `validate_a2b_bindings` — the binding grammar and the ≥1-from-this-flow rule |
| `s19_app/tui/services/flow_persistence_service.py` | builder-template save/load (dedup suffix, V1–V7 fail-closed read) + the chain-set envelope (`save_chain_set` / `load_chain_set`, V1–V6 fail-closed) |
| `s19_app/tui/services/flow_execution_service.py` | the A2B run arm through `generate_diff_report` + `run_chain_set` (sequential default / parallel per chain) + the `ChainSetRunRecord` report composer |
| `s19_app/tui/issues_view.py` | the curated standard-keyword set + the reclassification predicate + the row remap + the single counts site |
| `s19_app/tui/app.py` | the rail 10→12 with the `=` / `]` bindings + routing handlers for both new panels + the Issues counts fold |

### Usage / examples
```bash
# the batch's own verification (from the packets' §3)
pytest tests/test_tui_check_editor.py tests/test_tui_patch_editor_b94.py tests/test_tui_check_chain_b94.py   # Inc-001
pytest tests/test_tui_flow_builder_b94.py tests/test_flow_a2b_b94.py                                        # Inc-002
pytest tests/test_tui_flow_execution_b94.py tests/test_flow_chainset_b94.py                                 # Inc-003
pytest tests/test_tui_issues_triage_b94.py                                                                  # Inc-004
```
Operator walkthrough (all behaviors above): write a check spec in the Check Editor → open A2B Diff and load that file → the report carries the `## Checks` addendum; place patch/CRC/A2B blocks in the Flow Builder, bind the A2B inputs, save a template → import it twice in Flow Execution, bind different input files per lane, run, Save Set → Load Set and re-run; load a standard A2L and open Issues — standard blocks read as INFO, unknown blocks still warn.

### Batch-95 coexistence (the union `run_flow`)
While batch-94 was in flight, the parallel lane (batch-95) landed its own increments on `main`; every cut was reconciled with an RC-1 rebase onto the union tree — both lanes green at every union (`PLAN.md` decision log 2026-10-13; the intersection register in the coordination note). The load-bearing fact for the code: batch-94's `run_chain_set` **wraps the union `run_flow` per chain** — no block semantics re-implemented — and the same run populates both batch-95's `result.change_records` (its ReportBlock reads them) and batch-94's A2B results (`increment-002` §1 seam 5; `increment-003` §1 seam 3; the A3 reverse census: 86 batch-95 compat probes green at every gate). The html twin of the A2B report is not invoked from the flow path (Markdown-only emission, `increment-002` §6).

### Diagrams
- `06-docs/diagrams/architecture.md` — the batch-94 architecture block (the new module, the four surfaces, the rail).
- `06-docs/diagrams/sequence-checks-chain.md` — the C-12 chain: Check Editor writes `.chk.json` → A2B Diff loads → the `## Checks` addendum.
- `06-docs/diagrams/sequence-chain-set.md` — the chain-set save → load → re-run sequence.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] Audience and purpose declared at the top of the doc (or implicit and obvious). — ✓ header: technical stakeholder, phase 6, docs-writer role.
- [x] Structure follows the relevant template (or a justified deviation is noted). — ✓ the seeded `functionality.md` template's sections kept verbatim; the at-a-glance bullets filled.
- [x] Code/CLI snippets actually run (or marked "untested"). — ✓ the pytest commands are the packets' own §3 commands (`inc001…inc004` §3); the operator walkthrough is the AT-B94-11/12/15…24 scenario verified at the gates.
- [x] Assumptions listed. — ✓ operator rulings section (schema unchanged · write/validate only · provenance per block · sequential-default/parallel · suffix distinction) + the batch-95 union premise.
- [x] Risks / limitations called out. — ✓ the Markdown-only A2B emission; the carried notes (04-validation N-1…N-6) summarized in the executive summary.
- [x] Next steps stated. — ✓ the carries (parked US-006, the F1/F2 owner rulings, the `=`/`]` field check) in `executive-summary.md` §Next steps and the matrix §4.
- [x] Diagrams included where flow is non-trivial. — ✓ three mermaid blocks under `06-docs/diagrams/`, linked above.
- [x] No invented APIs / version numbers / metrics. — ✓ every figure traces to the record (24 ATs · 31 TCs · 12 rail entries · 1 023 INFO rows · 86 compat probes · gate run 3 040 passed — `04-validation.md` §✅ Verdict and the packets).
