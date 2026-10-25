# Design proposal — s19_app — Batch 2026-10-25-batch-99

> Authored between P2 and PDR, against the contract as amended in LED-2026-10-25-batch-99.3.
> Staged here. Its canonical home is the vault (`artifact_homes.design_pdr`), published by `/dev-flow-sync`.

| Field | Value |
|---|---|
| Id | `PDR-2026-10-25-batch-99` |
| Requirements covered | HLR-152..HLR-162 with their LLRs (40), as of LED-2026-10-25-batch-99.3 (40 LLRs; stories US-141..US-152) |
| Modules touched (from `docs/ARCHITECTURE.md` §10 batch-99 declarations) | engine (`core.py`, `hexfile.py`, `tui/a2l.py` — frozen §7, crossings named), render (`render/hexview.py`), changes (`tui/changes/apply.py`), workspace (`tui/workspace.py`), services (`change_service.py`, `flow_execution_service.py`, `flow_report_service.py`), operations (`operations/crc.py`), screens (`app.py`, `flow_screens.py`, `screens_directionb.py`, `window_help.py`), split/join (`segment_split_view.py`, `s19_app/segment_ops.py`); tests (`tests/support/`, `tests/fixtures/synth/`) |
| Triggers that fired | A2 · A3 · B1 · B3 · B4 · C6 · C8 · D1 · E1 · E2 |
| Author / reviewers | orchestrator (author) · `architect` · `qa-reviewer` · `ux-reviewer` (D1 fired) |

## 1 · Objective and scope

Close H-1..H-10, PH-3, CW-D-4/7/10 and the CW-U-1 test gap so that every written image, report and run record says what was and was not applied. No new screen. No new file format. Out of scope: the Load+projects findings (PH-1/2/4/5, the picker, CW-U-2), the MEDIUM/LOW investigation rows, and a symbol-entry surface (backlog feature).

## 2 · Modules and boundaries

| Module | What it owns here | What it exposes | What it must NOT reach into |
|---|---|---|---|
| engine `core.py` / `hexfile.py` | the data-record predicate (R18); terminator, EOF and count checks; the five notice codes | `S19File` maps, ranges, record lookup, overlap map; `IntelHexFile`'s map; issues carrying the codes | the TUI, the flow runner |
| render `hexview.py` | map and validity builders over the R18 predicate | `build_mem_map_s19`, `build_range_validity_s19` | `core.py` internals beyond the predicate |
| changes `apply.py` | private staging for `save_patched_image`; `before_bytes` = source byte | `save_patched_image` (same signature) | the work-area naming rules (it asks `workspace`) |
| workspace `workspace.py` | the placement: staging directory, exclusive claim, `_<N>`, `os.replace` with retries, `RESERVED_WORKAREA_HOMES` | `copy_into_workarea` (same signature and `Path` return; raises `WorkareaPlacementError`, a `WorkareaContainmentError` subclass, on exhausted retries), the reserved tuple | the caller's source file (never moved) |
| services `change_service.py` | the journal of original bytes; re-derive on apply and save; `parse_new_bytes` grammar (D1) | `ChangeService` API unchanged; `SymbolPickResult` unchanged | `LoadedFile` construction |
| services `flow_execution_service.py` | PATCH status rule; the SOURCE mapping of the five codes; `ChainRunOutcome` fields; the start check (D7); WRITE-OUT verify (D9); CRC arm status | `run_flow`, `run_chain_set`, `compose_chain_set_report` | the TUI widgets |
| services `flow_report_service.py` | the always-present not-applied and refusal sections | the report text | the runner's internals |
| operations `crc.py` | empty-region error; partial-coverage count; CRC write through `workspace` placement | the CRC op result | shared `temp/<name>` paths |
| screens | lane PATCH cell from block status (`flow_screens.py`); the chain-set refusal in the status line and the Save project missing-source notice (`app.py`); `refresh_files` stored names and load folder; the Bytes placeholder and help (`screens_directionb.py`, `window_help.py`) | painted text only | service internals beyond their result types |
| split/join | one sanitiser; plan-time collision pass; containment under the work-area root; header-only MAC export; placement through `workspace` | the export result | anything outside the work-area root |

## 3 · Diagrams

**Write placement (HLR-155), one call:**

```
caller ──► copy_into_workarea(source, dest)
             │ 1. temp and temp/.staging are real dirs?  (reparse point → refusal)
             │ 2. stage_dir = mkdtemp(temp/.staging/)   owned=True
             │ 3. copy2(source → stage_dir/<name>)       source never moved
             │ 4. B8: dest/<name> exists, non-empty, bytes equal? → reuse (a 0-byte target may be another writer's claim: never reused)
             │ 5. claim dest/<name> with O_EXCL; taken → <stem>_<N><ext>; close handle
             │ 6. os.replace(stage file → claimed name); PermissionError → retry ≤5 in ≤1 s
             │        └─ still failing → remove own claim, raise WorkareaPlacementError
             │ 7. rmtree(stage_dir) only while owned=True
             ▼
           final path (bytes == this write's bytes)
```

**Truthfulness chain after HLR-156:**

```
apply_change_document ─► ChangeSummary (dispositions, refusals)        unchanged
      │
PATCH arm ─► status = error | notices | ok  (first match wins) ──► error stops before WRITE-OUT
      │
FlowRunResult ─► ChainRunOutcome (+change_records, +refusals, +image_ranges)
      │                      │
lane PATCH cell (safe_text)  chain-set report (md_safe: paths, non-applied, refusals)
flow report (always-present sections; never CLEAN when non-empty)
```

**Editor image (HLR-157):**

```
load ─► image (dict D)            journal J = {}  (addr → source byte)
apply(doc) ─► for a in J: D[a] = J[a]  (in place)   J cleared
           ─► apply entries: for each written a: J.setdefault(a, D[a]); D[a] = new
save ─► re-derive as apply(doc) ─► emit D ─► status names entries not applied before
before_bytes(a) = J[a] (source byte), even on a repeated apply
```

## 4 · Interfaces that change — and which ones FREEZE

| Interface | Current | After | Consumers | LLR | **Frozen for the fork?** |
|---|---|---|---|---|---|
| B99-I1 S19 memory-map contract | every record type walked | R18 data-record predicate only | 32 test files calling a builder (ARQ §3); hexview; validation | 153.1, 153.2 | n/a — no fork |
| B99-I2 placement | `temp/<name>` stage, check-then-copy | `temp/.staging/<mkdtemp>/` + `O_EXCL` claim + `os.replace`; `WorkareaPlacementError` on exhausted retries; B8 reuse never of a 0-byte target | 14 paths: 13 `copy_into_workarea` callers + `changes/io.py:1586` (converted in Inc 3a, PDR C2) | 155.1, 155.2, 155.3, 155.7 | n/a |
| B99-I2a group placement (NEW) | none | `place_group_into_workarea(sources: Sequence[Path], destination: Path, *, max_size_bytes: int \| None = None) -> list[Path]` in `tui/workspace.py`: one staging dir, one `_<N>` claimed for every name before any write, `os.replace` per file, reuse only when the whole group is identical, rollback of every own claim and placed file on any failure; built in Inc 6; `segment_ops` writes into the staging dir and never imports `tui.workspace` (`segment_split_view` calls the function) | `segment_split_view.py` export writer | 160.4, 155.7 | n/a |
| B99-I3 `ChainRunOutcome` | status, block_results, written_paths… | + `change_records`, `refusals`, `image_ranges` (default factories) | `flow_screens.py`; chain-set report | 156.2, 156.3 | n/a |
| B99-I4 A2L codec | tag → layout → endian → little; RAT_FUNC phys = f(raw) | + `MOD_COMMON`; RAT_FUNC INT = f(PHYS); `TAB_NOINTP` exact, `TAB_INTP` range-checked with a written-value flag | A2L window; `resolve_symbol_entry` | 158.1, 158.2, 158.3 | n/a |
| B99-I5 CRC coverage | empty region → CRC of empty stream | error; partial → notices count, carried on the CRC region result (ARCH R23 confirmed at PDR, condition C5), read by the flow arm, `write_crc_image` and the operation path | flow CRC arm; CRC write | 159.1, 159.2, 155.8 | n/a |
| B99-I6 export writer | `dest_dir/f"{stem}_{name}"` | sanitiser + plan pass + work-area containment + B99-I2 / I2a placement | `SegmentSplitView` | 160.1, 160.2, 160.4, 160.5 | n/a |
| B99-I7 editor image | in-place mutation, no revert | journal restore in place; save re-derives; `before_bytes` = source byte | `app.py` aliases (`:9894`, `:9946`), reports | 157.1, 157.2, 157.4 | n/a |
| B99-I8 Bytes grammar | base 0 then 16 | per D1 (provisional: hex only) | `add_entry` / `edit_entry` | 161.1, 161.2 | n/a |
| B99-I9 project and files lists | every folder but `temp`; root listing | minus `RESERVED_WORKAREA_HOMES`; load folder; stored names | Load project dialog, `_load_from_item` | 162.1, 162.2, 162.3 | n/a |
| B99-I10 loader notice codes | none | five stable codes | SOURCE arm, issues panel | 154.1, 154.2, 154.3 | n/a |
| B99-I11 chain-set start check | none | refusal on duplicate names (D7) | `app.py:2800`, `:2890` | 155.5 | n/a |
| B99-I12 WRITE-OUT verify | none | `verify_written_image` after placement (D9) | lane cell, flow report | 155.6 | n/a |

## 5 · Proposed test cases

Every TC and AT is listed in `01-requirements.md` §3–§4 with its Negative control. The table names the mutation that turns each group RED. Each one is declared here, at authoring time.

| Id | Layer | What it asserts | **The mutation that would turn it RED** |
|---|---|---|---|
| TC-B99-01..03, AT-B99-01 | 0/A, B | corpus determinism, coverage, reader exactness; `--check` exit codes | timestamp in S0; drop a class; reader copies S0 |
| TC-B99-04..07, AT-B99-02 | A, B | S0 excluded from every walk; no undeclared data written; `0x0` entry skipped | re-admit S0 in the R18 predicate |
| TC-B99-08..10, AT-B99-03 | A, B | five codes; count only after the end; SOURCE error | drop the terminator / EOF check; map to `notices` |
| TC-B99-11..16, 39, AT-B99-04/05 | A, B | private staging; same-name concurrency 0 mismatches; B8 race; Save project survives; D7 refusal; D9 verify; delete-only-owned | shared `temp/<name>`; check-then-copy; no verify; re-derived unlink |
| TC-B99-17..20, AT-B99-06/07 | A, B | status matrix (8 cases); outcome fields; reports list non-applied and refusals; hostile name literal | hard-coded `ok`; drop a field; omit the section |
| TC-B99-21, 22, 40, AT-B99-08 | A, B | journal restore in place; save re-derive; `before_bytes` source | skip restore; rebind instead of in place; image byte as before |
| TC-B99-23..25, AT-B99-09, AT-B99-14 | A, B | byte-order fallback; RAT_FUNC both ways and root pick; COMPU_TAB rules; A2L window decode (US-147); codec API encode (US-152) | `little` fallback; old direction; nearest/clamp with no flag |
| TC-B99-26, 27, 38, AT-B99-10 | A, B | empty region error, flow stops; partial count; CRC write staging | CRC of empty stream; shared staging |
| TC-B99-28..31, 41, AT-B99-11 | A, B | sanitiser and stem cap; containment; header-only MAC export; `_<N>` with paired sidecar and reuse; plan-time collisions | bypass sanitiser; destination-rooted check; MAC placeholders as data; per-file `_<N>`; collision check in the loop |
| TC-B99-32, 33, AT-B99-12 | A, B | hex grammar; placeholder and help say hex | base-0 first |
| TC-B99-34..36, AT-B99-13 | A, B | stored names; reserved tuple; load-folder listing | `str(Label)`; `!= WORKAREA_TEMP` only; root listing |

## 6 · Risks and rejected alternatives

- **Re-pin masking:** S0 shifts range counts in 12+ test files. Mitigation: each re-pin is named old → new → LLR in the packet's reverse census, and the full suite runs at every increment cut against `evidence/baseline-pytest-a293213.txt`.
- **Windows placement:** antivirus and cloud-sync locks. Mitigation: bounded retries, then a refusal (LLR-155.2).
- **RAT_FUNC display change:** a user sees different physical values for RAT_FUNC symbols. Mitigation: release note in the batch close.

| Alternative considered | Why it was rejected |
|---|---|
| `tempfile.mkstemp` staging files | `copy_into_workarea` names the target after the source, so files would land as `tmpXXXX.s19` (ARQ R19, P2 A-2) |
| Snapshot copy of the whole source map for the editor | the dict is aliased (`app.py:9894`, `:9946`); a rebind leaves the aliases stale. The journal restores in place (R20) |
| Export overwrite by atomic replace (D8 `reemplazar`) | contradicts H-9's closure and HLR-155's delete invariant, and lets projects clobber each other in `splits/` (P2 A-19, S-4); recommendation flipped to `sufijo` |
| A symbol-entry UI to make the encoder black-box testable | a new UI surface needs a prototype round; routed to the backlog, and the encode stays TC-only under a recorded exception |
| `validate_project_files` allow-list for projects | would hide legacy projects without `project.json`; a closed reserved tuple is testable and keeps them |
| Forking into 4 lanes | four file intersections; S0 shifts suite-wide expectations; decisions gate 4 increments (ARQ §3) |

## 7 · Forward-applicability table — **the section that makes this document honest**

| Output of this PDR | Named consumer downstream | Where the consumer will read it |
|---|---|---|
| design characteristics | the Phase-3 increments | §2 and §3 above, quoted in each Kimi brief (`kimi/BRIEF-inc-<N>.md`) |
| enablers (fixtures, data, scaffolding, env) | Phase 3 and validation | Inc 1's corpus `tests/fixtures/synth/` + `tests/support/independent_reader.py`; `kimi/BRIEF-COMMON.md` (env, PYTHONPATH, NO_COLOR) |
| proposed test cases | layers 0/A/B and the DDR | §5 above and `01-requirements.md` §3–§4; each packet's RED counterfactual and mutation rows |
| design → requirement traceability | the matrix and the DDR | §4 (B99-I1..I12 ↔ LLRs) and `06-docs/traceability-matrix.md` at P6 |

## 8 · Parallelisation plan *(only if the batch forks)*

Not applicable. The batch runs one lane, in sequence (ARQ verdict; `01-requirements.md` §2.8).
