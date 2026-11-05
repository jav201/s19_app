# Inc 4 — E1 rulings: scope, canon changes, decisions

Batch 2026-11-01-batch-101, increment 4, base `b7b77c4`. Rows: `01-requirements.md`. Slice: `E1-slice.md`.

## 1. Scope

### Census of document reads (rule 8: read before you write)

`grep -rn "read_change_document(\|parse_change_document(\|service.load(\|\.load_text(\|edit_entry_json(" s19_app` on `b7b77c4`, every product call that turns document text into a `ChangeDocument`:

| # | Site (`b7b77c4`) | Surface | Declared A2L today | Finding | This increment |
|---:|---|---|---|---|---|
| 1 | `app.py:7106` `_patch_editor_load` → `ChangeService.load` | Patch Editor file load (dropdown, typed path, dirty-guard accept) | none (the `a2l_context` parameter exists, unused) | F-01 | session read (1) → loaded A2L |
| 2 | `app.py:4810` `on_patch_editor_panel_action_requested` `parse_paste` arm → `ChangeService.load_text` | Patch Editor paste | none (parameter exists, unused) | F-01 root, **not in the triage** | session read (2) |
| 3 | `app.py:5404` `_apply_changeset_json_edit` pre-check, then the posted `parse_paste` (site 2) | whole-document Edit JSON confirm | none | F-01 root, **not in the triage** | session read (3) |
| 4 | `app.py:5523` `_apply_entry_json_edit` → `ChangeService.edit_entry_json` (`change_service.py:1516`) | per-entry Edit JSON confirm | none (no parameter) | T-12 | session read (4) + R-TUI-058.9 |
| 5 | `app.py:7437` `on_check_editor_panel_spec_file_selected` | Check Editor Spec pick | none | F-01 | session read (5) |
| 6 | `app.py:7763` `on_ab_diff_panel_check_file_selected` | A2B Diff check-spec pick | none | F-01 (third site, plan §a) | session read (6) |
| 7 | `variant_execution_service.py:2557` `_execute_one_variant` | Execute scope variant run | none (the project A2L is parsed into `a2l_data` 3 lines up and used only for linkage) | T-04 | R-CHG-SYM.11 |
| 8 | `change_service.py:3224` `run_checks_for_project` | headless check run (no product caller) | none (parses `a2l_path` only for linkage) | T-03 | D-1: delete (D9-7) |
| 9 | `app.py:2520` `recorded_document_state` (project reopen) | Load project | the project's A2L | — | unchanged |
| 10 | `flow_execution_service.py:178`, `:182`, `:522`, `:803` | flow PATCH / CHECK blocks | the flow's declared A2L | — | unchanged |

Sites 2 and 3 share F-01's root and sit in `app.py`; leaving them would leave the paste and Edit JSON surfaces refusing what the file load now accepts, and R-CHG-SYM.9 already names paste. T-12 (site 4) is unreachable on base: the only product way to put a symbol entry into a draft is a paste with the A2L loaded (`ChangeService.add_symbol_entry` has no app caller, symbol input deferred by D10-13), and the paste drops symbol entries today. Fixing site 2 makes T-12 reachable, so site 4 must change in the same increment.

### Painted lines that change (no layout change)

1. Patch Editor load / paste of `demo_patch.changes.json` with the A2L loaded: `Loaded change: 5 entries, 2 error(s)` plus two `[CHG-SYMBOL-UNRESOLVED] …` lines → `Loaded change: 7 entries, 0 error(s)`; the load now counts as clean (`result.ok`), so `PatchEditorPanel.mark_loaded` runs (base: it did not).
2. Check Editor Spec pick of `demo_check.chk.json`: `Check Editor: spec NOT loaded.` → `Check Editor: loaded 'demo_check.chk.json' (3 fields).` (the 3 rows are still unlabelled memory rows: F-27, Inc 5).
3. A2B Diff check-spec pick: `Check spec not loaded — …` → `Check spec 'demo_check.chk.json' loaded — 3 declared field(s) will ride the report.`; the next diff report carries the check addendum.
4. Whole-document Edit JSON of a draft with symbol entries: `Edit JSON refused: …` → the draft is replaced.
5. Per-entry Edit JSON of a symbol entry: rejected → replaced (A2L loaded); with no A2L loaded, one new line at the end (R-TUI-058.9).
6. Execute scope: a document with symbol entries is no longer blocked; a patched variant file is written where none was.

All are status lines or the documented outcome of an existing action; the user guide's ch08 §8.2, ch10 and ch17 notes on F-01 become stale (Inc 14 owns help and docs text; listed for it in §4).

### Out of scope (where each goes)

- **T-02** (one unresolved symbol entry blocks the whole check run, `doc-fault`; ruling `saltar`): not in the batch plan. Without it, a check document with a symbol entry still blocks when no A2L is declared (R-CHG-SYM.10, .12 keep that). Decision D-4.
- **F-27** (Check Editor names lost on reload): Inc 5, same handler (`on_check_editor_panel_spec_file_selected`). Interface I-3 in the graph.
- **D10-29** (per-entry status names the address, `entry at 0x<X> updated.`, canon R-TUI-058.4): not taken; the cases of this increment assert the replaced entry, not that text.
- **D10-23** (per-entry Edit JSON for file-backed documents): not taken; the per-entry popup stays draft-only (`app.py:5469-5474`).
- A plain-language line for the other five session reads with no A2L loaded: the ruling `sesion` names only the per-entry edit; the finding text already says no A2L context is declared. Backlog suggestion only.
- `variant_execution_service._resolve_manifest_entry` (`:823`): not touched. Inc 9 takes D15-18 and the security routes S8-1 / S8-2 there (links checked after resolve). Interface I-4.

## 2. Changes to existing canon rows

- **R-CHG-SYM.9 — amended in place.** Was: `When the operator loads or pastes a change document while an A2L is loaded, the system shall use that A2L as the declared A2L.` Now: `When the system makes a session read while an A2L is loaded, the system shall use that A2L as the declared A2L.` Reason: "loads or pastes a change document" is ambiguous (29148 *unambiguous*, *complete*): it does not say whether a check document picked in the Check Editor or the A2B Diff, or an Edit JSON confirm, is a load, and the code shows six surfaces with one defect. The six are listed in a new CTX-CHGDOC term, **session read** (rule E6: the note defines, the row requires), and they share the response (rule E3), so each is one test case. The subject becomes "the system" for the read, as rule E1 asks.
- **R-CHG-SYM.10 — amended in place**, the same way (its "loads or pastes" becomes "makes a session read").
- **CTX-CHGDOC — two terms added**: *session read* and *loaded A2L* (definitions in `01-requirements.md`). *Declared A2L* keeps its text.
- **R-VAR-002.27 — not changed; observation forwarded.** `When the system runs a variant, the system shall use the project's MAC and A2L files.` names two objects and does not say what the A2L is used for (linkage only, on base). It is not singular (rule E2). This increment does not split it; R-CHG-SYM.11 states the symbol half where the canon keeps the declared-A2L rows (S8.3) and cites R-VAR-002.27 in its definition. The requirements session may split .27 into MAC linkage / A2L linkage.

New rows: R-CHG-SYM.11, .12, .13 (S8.3) and R-TUI-058.9 (S10). Each id was checked absent from `REQUIREMENTS.md`, from `docs/requirements/` and from every `01-requirements.md` of this batch (`grep -rn "R-CHG-SYM.1[1-9]\|R-TUI-058.9"`: no hit).

Reasons for the new rows' shape:
- **R-CHG-SYM.11 / .12** follow the ruling `declarado`: the A2L the call receives or the project declares, nothing implicit. The variant service receives the project's A2L file from `execute_project_variants` (`validate_project_files`, the one A2L of the folder); that file is the project's declared A2L. .12 is the failure path and the "nothing implicit" control; it holds on base.
- **R-CHG-SYM.13** exists because the fix moves a cost onto the screen thread. E1 probe (`parse_change_document`, Windows host, `b7b77c4`): 100 symbol entries × 2 000 tags 0.03 s; × 20 000 tags 0.31 s; 1 000 × 20 000 3.12 s, linear in entries × tags, because `_resolve_symbol_tag` (`io.py:1062`) rebuilds the whole name index for every symbol entry. On base the editors never paid it (no context → refused at once). The Patch Editor load, the Check Editor and A2B Diff picks run on the screen thread, so F-01's fix alone would freeze the screen for seconds on a production-size A2L. 0.5 s is the bound; the index-once design is expected near 0.05 s (to be measured at E4). Decision D-2.
- **R-TUI-058.9** follows the ruling `sesion` ("if no A2L is loaded, the edit says so instead of failing with a code"). The finding line stays (R-CHG-001.21 shows a finding line for each finding of a load; the per-entry confirm uses the same reporter, `_report_change_result`); the plain line is painted last, so the status bar the operator reads ends on words, not on the code. Its text has no placeholder, so no file-derived text reaches it (trigger C8). The condition is the R-CHG-SYM.2 finding, not the code alone: with no A2L, `CHG-SYMBOL-UNRESOLVED` is also R-CHG-SYM.1's code (a `symbol` that is not a string), where "no A2L is loaded" would be the wrong reason; the negative arm pins that.

## 3. Decisions (for the orchestrator)

- **D-1 — T-03: delete `run_checks_for_project` (recommended) instead of passing it the A2L.** The canon removed the headless entry point (S9 review: "Removed (D9-7)"); CODE-CHANGES D9-7 says to delete it and `tests/test_checks_engine.py::test_headless_project_run`. A guard on a function the canon deletes is wasted work, and the flow rule prefers removing a feature over guarding it. Cost: one test node removed (it is in the parallel session's node list, `s19w/test-cases/evidence/collected-e279c8b.txt:2458`) and one import line edited in `tests/test_checks_engine.py`; `change_service.py`'s module docstring loses its paragraph; the imports only that function used go (E4 checks each with grep). A stale mention stays in `changes/check.py:278` (docstring; outside the file cap) — backlog line. **Needs the orchestrator's ruling because a test node goes away.** Fallback if ruled "keep": parse `a2l_path` before the read and pass it as `a2l_context` (two lines), under a new row `R-CHK-HEADLESS.1 | E | When the system runs a check document headless with an A2L file, the system shall use that A2L file as the declared A2L.` (id checked free), and CODE-CHANGES D9-7 stays open.
- **D-2 — add `s19_app/tui/changes/io.py` as the 4th source file (recommended).** Build the tag-name index once per read (`_parse_entries`) and look each symbol up in it; first-match and case rules unchanged (R-CHG-SYM.7, .8). Also expose the R-CHG-SYM.2 reason text as one module constant, so R-TUI-058.9's condition and the reader share one string. Without D-2, F-01's fix ships a measured 3 s freeze at 1 000 symbol entries × 20 000 tags; R-CHG-SYM.13 would then be dropped and the freeze recorded as a known risk. The file count stays at the cap of 4 (`app.py`, `change_service.py`, `variant_execution_service.py`, `io.py`).
- **D-3 — R-TUI-058.9 is an added last line, not a replaced message.** Alternatives: (a) replace `Patch Editor: entry edit rejected - see findings.` in that case — conflicts with R-TUI-058.3, whose condition still holds, so .3 would need an "unless" (rule E2 forbids); (b) hide the finding line — breaks "every finding is shown". Chosen: append. Recorded so E3 can challenge it.
- **D-4 — T-02 stays out.** The ruling `saltar` changes R-CHK-001.4's blocking set (`check.py` `_CHECK_NON_BLOCKING_CODES`), a fifth file. With Inc 4, a check document resolves whenever an A2L is declared, so T-02 matters only when none is. Recommend a backlog line "T-02 (`saltar`) still open after batch-101 Inc 4" unless the orchestrator wants it here (it would replace D-2's file).

Decisions taken here (no ruling needed):
- **E1-D1 — the session's loaded A2L is `S19TuiApp.current_a2l_data`**, the one value the single-writer seam `_replace_current_a2l` (`app.py:19507`) sets on attach, project install, file-load install and clear. Read on the screen thread only (all six sites are screen-thread handlers). No copy, no new state.
- **E1-D2 — no re-resolution when the A2L changes later.** A document read with one A2L keeps its entries when another A2L is loaded; the next session read uses the new one. As base for every other A2L-dependent view; not a requirement here.
- **E1-D3 — sites 2 and 3 are taken (not in the plan row's site list)** for the reasons in §1; they are in `app.py`, already in the slice.

## 4. Forwarded

- To the requirements session: R-CHG-SYM.9, .10 amended; R-CHG-SYM.11, .12, .13, R-TUI-058.9 new; CTX-CHGDOC terms *session read*, *loaded A2L*; observation on R-VAR-002.27 (§2). CODE-CHANGES: D8-22 done by this increment; D9-7 done if D-1 is ruled "delete".
- To Inc 14 (help and docs text): `docs/user-guide/ch08-patch-editor.md` §8.2 ("A change-set with symbol entries is refused"), `ch10-check-editor.md` (the F-01 sentence), `ch17-flow-builder.md` (the F-01 note), DOSSIER F-01 row ("Project Execute scope does resolve them" is false on `b7b77c4`: variant execution passed no A2L, T-04).

## Orchestrator rulings (2026-11-05)

- **D-1: delete** `ChangeService.run_checks_for_project` and `tests/test_checks_engine.py::test_headless_project_run` (with its import). Reason: the strict canon already removed the headless entry point (S9, "Removed (D9-7)") and CODE-CHANGES D9-7 asks for it; guarding a removed function is waste. The node removal is forwarded to the requirements/test-case session.
- **D-2: yes** — `s19_app/tui/changes/io.py` is the 4th source file (not an engine-frozen file); R-CHG-SYM.13 stays. Reason: once F-01 is fixed the editors pay the per-entry index rebuild on the screen thread (3.12 s measured for 1 000 entries x 20 000 tags).
- **D-3: accepted** — the R-TUI-058.9 line is an extra last line; the finding line with its code stays (R-TUI-058.3).
- **D-4: accepted** — T-02 stays out (needs a 5th file, `check.py`); a backlog row records it open after Inc 4.
- **Process note:** the E1 timing probe of `parse_change_document` ran on the Windows PC; from now on probes and timings run on the LAN Linux host (operator rule). The 3.12 s / 0.31 s figures are re-measured there at E4/E5 before they set any threshold.
