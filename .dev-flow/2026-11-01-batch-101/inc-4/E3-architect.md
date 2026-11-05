# Inc 4 — E3 architect review (code-free design review)

Batch 2026-11-01-batch-101, increment 4, base `b7b77c4` (branch `b101-inc4`). Reviewed: `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings D-1 … D-4), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc4.md`, the code in scope and its callers, canon rows R-CHG-SYM.1 … .10 (`REQUIREMENTS.md:3075-3084`). Read-only: nothing else was edited.

**Verdict: PASS-WITH-NOTES.** The design is right: pass the declared A2L the caller already holds at each of the six session reads and the variant read, build the name index once per read, delete the dead headless entry point. Fold A-1 … A-4 into the records before E4 starts. A-1 is a slice omission that turns the suite RED. A-2 and A-3 change one graph node and one row. A-4 is a records-only admission. A-5 … A-9 are notes.

## Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| A-1 | HIGH | D-1, `E1-slice.md` §3, `run_checks_for_project` node | `AT-TC-REGISTRY.jsonl:610` (TC-023, `LIVE`) lists `tests/test_checks_engine.py::test_headless_project_run` in its `nodes`. `tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes` (G2, "every LIVE entry's declared nodes exist", `:354-371`) goes RED once the node is deleted. The slice §2 census names only `tests/test_checks_engine.py:46/:348`. | Add the registry edit to the slice §3 as a data-file change: drop that one node from TC-023's `nodes`. TC-023 stays `LIVE` with its 10 other nodes. Run `tests/test_id_registry.py` in E4's targeted set. |
| A-2 | MAJOR | `_parse_entries` / `_symbol_name_index` (D-2), R-CHG-SYM.13 | The index is built **eagerly**, once before the loop. So every read that declares an A2L pays O(tags), even for a document with no symbol entry, which is the common case. LAN Linux probe (below): with `examples/case_06_large_nested_a2l/firmware.a2l` (36.7 MB, 220 040 tags) declared, a 1-entry address-only read goes from 0.0–0.1 ms (base) to 189–231 ms. The cost lands on every session read (screen thread), every flow PATCH/CHECK read, and every document × variant in Execute scope and the report run. | Build the index **lazily** on the first entry that carries a string `symbol`, then reuse it for the rest of the read (one build at most per read). Add an arm to R-CHG-SYM.13, or a sibling row: a read of a document with no symbol entry builds no index. Oracle: a call counter on `_symbol_name_index` = 0, not timing. Mutant: eager build gives 1, so the arm goes RED. Graph example on `_parse_entries`: address-only `demo`-style document with CTX gives `_symbol_name_index` called `0` times. |
| A-3 | MAJOR | R-CHG-SYM.13 (threshold and sizing) | (a) 20 000 tags is an order of magnitude below the repository's own large-A2L case (case_06, 220 040 tags), and US-SYM-1 promises no stall "on a large A2L". (b) The LAN Linux host is about 3.4× slower than the Windows E1 host. Base 1 000 × 20 000 is 10.5–11.0 s (Windows E1: 3.12 s). Projected index-once 1 000 × 20 000 is 184–238 ms. Projected 1 000 × 220 040 is 404–502 ms, at the 0.5 s bound (that synthetic run also raised 848 collision/drift findings, so treat it as indicative). (c) `timing_bound` scales only under `CI`, so the local Linux margin is the real one. | Size the row on case_06's tag count, or on the canon's A2L ceiling if one exists. Set the bound from the E4 Linux measurement with ≥ 2× margin: on the projection, "1 000 symbol entries × 220 000 tags within 1.0 s". Make the primary oracle structural (`_symbol_name_index` built once per read, already a graph example). Keep the wall-clock ceiling as the secondary check. The per-entry rebuild mutant then fails on the count at once, instead of only after a run of about 110 s. |
| A-4 | MAJOR | `E1-rulings.md` §1 "Painted lines that change", item 6; R-CHG-SYM.11 | The project report run (`app.py:6566`, the report worker when no execution precedes it) also calls `execute_project_variants`, and the save-back runs there too (`variant_execution_service.py:2578-2585`). After Inc 4, generating a report for a project whose batch holds `demo_patch` writes `<variant>-patched.s19` into the project folder (base: blocked, no file). The report's change and check sections also change from blocked / `doc-fault` to applied / pass / fail. The records admit Execute scope only. | Records-only change: list the report run in §1 item 6 as a second surface whose saved files and report content change. Either add case R-CHG-SYM.11/3 (report run of the case-08 project shows `demo_check` 3 pass, not `doc-fault`), or state that /1 covers it because both surfaces share the same service call. |
| A-5 | MINOR | R-TUI-058.9, `_apply_entry_json_edit` | The `current_a2l_data is None` guard carries real weight. With an A2L loaded, a symbol whose text contains `no A2L context is declared for this change-set` produces an R-CHG-SYM.3 message (`the symbol '<that text>' resolves to no tag…`) that contains the I-1 constant. No case kills a mutant that drops the guard (/3 uses `NO_SUCH_TAG`). | Add a negative arm to R-TUI-058.9/3: A2L loaded, `"symbol": "no A2L context is declared for this change-set"`, so the R-CHG-SYM.3 line appears and 0 plain lines. |
| A-6 | MINOR | R-CHG-SYM.9, "Base" column | It says "Only alternative (1) had a parameter for it (`ChangeService.load`)". `ChangeService.load_text` (`change_service.py:1608`, forwarded at `:1648`) has the parameter too, and `read_change_document` / `parse_change_document` (alternatives 3, 5, 6) accept it. Only alternative 4 (`edit_entry_json`) lacks one. | Correct the wording. |
| A-7 | MINOR | Alternative 3, `_apply_changeset_json_edit` | The whole-document Edit JSON confirm reads twice on the screen thread: the pre-check (`app.py:5404`), then the posted `parse_paste`. So it pays the symbol read twice: about 2 × 0.2 s at case_06 size on Linux with A-2's lazy index. The double parse already existed on base; R-CHG-SYM.13 bounds one read. | At E4, time the confirm end to end on Linux at the R-CHG-SYM.13 size. Change no design unless it exceeds the bound; reusing the pre-check result is out of scope. |
| A-8 | MINOR | D-1 leftovers | (a) `tests/test_checks_engine.py:411` docstring of `test_no_textual_in_static_import_graph` says "The engine + headless entry point reach no Textual import". It goes stale, but the test stays valid because `change_service.py` keeps its no-Textual contract. (b) `.dev-flow/BACKLOG-CODE.md:1822` (T-03) and `docs/requirements/review/CODE-CHANGES.md:222` (D9-7, `open`) need closing. (c) The 2026-10-26 ruling for T-03 was `declarado` ("use the A2L the call receives"), and D-1 closes T-03 by deletion instead. | (a) Update the docstring (tests are uncapped). (b) Close both rows at E5. (c) Word the backlog close as "T-03 superseded by D9-7 (function deleted); the `declarado` ruling still governs T-04 (R-CHG-SYM.11)", so the packet shows the earlier ruling was overtaken, not ignored. |
| A-9 | MINOR | I-3 (Inc 5) | After Inc 4 a resolved entry carries `ChangeEntry.symbol` (the tag's spelling, R-CHG-SYM.8). Inc 5's F-27 re-resolves names from the loaded A2L by address. Two sources for one fact can disagree when two tags share an address. The app already has a name index (`app.py:1059` `_build_a2l_name_index`, list-valued) that differs from the reader's first-match index. | Pin in I-3: Inc 5 uses `entry.symbol` when it is set and looks up by address only for address-only entries. Inc 5 adds no third name index. |

## Focus questions

### 1. The six session reads: does any other product read of a change document still go without the loaded A2L?

No. Census on `b7b77c4` of every product call that turns document text into a `ChangeDocument` (`grep -rnE "read_change_document\(|parse_change_document\(|\.load_text\(|service\.load\(" s19_app`, docstrings excluded):

| Call | Disposition after Inc 4 |
|---|---|
| `app.py:7106` (load), `:4810` (paste), `:5404` (Edit JSON pre-check), `change_service.py:1516` via `app.py:5523` (per-entry), `app.py:7437` (Check Editor), `:7763` (A2B Diff) | the six session reads, loaded A2L |
| `variant_execution_service.py:2557` | the project's A2L (R-CHG-SYM.11); reached by Execute scope (`app.py:6036`) **and the report run (`app.py:6566`)**, see A-4 |
| `change_service.py:3224` | deleted (D-1) |
| `app.py:2520` (project reopen) | the project's A2L, unchanged |
| `flow_execution_service.py:178/182/522/803` | the flow's A2L, unchanged |
| `change_service.py:1581`, `:1648` | the bodies of `load` / `load_text`, forwarding the caller's context |

Neighbouring reads that are not document reads: the Check Editor run (`app.py:7363`) runs the already-parsed spec. `json.loads` in `workspace.py:2576` reads the recent-sources store. Flow Builder screens and the Save project gather read no document (grep: no hit). The census in E1-rulings §1 is complete apart from the report-run surface of site 7 (A-4).

### 2. Screen-thread cost after the fix: should the read move off the screen thread?

**No; keep the reads synchronous, with A-2's lazy index.** Measured on the LAN Linux host (below):

| Case | Linux host |
|---|---|
| base, symbol read 1 000 × 20 000 tags | 10.46–11.03 s |
| base, 100 × 20 000 | 1.04–1.18 s |
| index once, 20 000 / 100 000 tags | 9–18 ms / 64–72 ms |
| index once, case_06 (220 040 tags) | ~200 ms |
| projected index-once read, 1 000 × 20 000 | 184–238 ms |
| projected index-once read, 1 000 × 220 040 | 404–502 ms (indicative, see A-3) |
| projected index-once read, 1 symbol entry, case_06 | 184–231 ms |
| address-only 1-entry read, case_06 declared: base / eager index | 0.0–0.1 ms / 189–231 ms |
| A2L parse of case_06 (already off the screen thread at load) | 12.65 s |

Why the read stays on the screen thread:
- With the lazy index, a session read costs the base's time for address-only documents and about O(tags) + O(entries) for symbol documents: at most about 0.2 s at the repository's largest A2L for small documents, and about 0.5 s at 1 000 symbol entries.
- Moving six synchronous handlers to workers would change their lifecycle. The draft can change while the read is in flight, and status ordering changes. That lands on Inc 6's Patch Editor lifecycle work and on Inc 5's Check Editor handler, which would make it a large change and a merge hazard. A ≤ 0.5 s worst case does not justify it.

**What would change this.** If E4's Linux measurement of a session read at case_06 size exceeds the bound with margin, the next lever is still not a worker read. It is a per-A2L name index built once in the A2L attach worker and keyed by `_a2l_view_generation`, never by `id()`, as the code already warns at `app.py:19521` and `:19559-19560`. The reader would then accept it. That widens the reader's interface, so it gets its own row. All of these are reversible; there is no one-way door here.

### 3. Does deleting `run_checks_for_project` (D-1) leave a caller or a doc?

- **No product caller.** `grep -rn "run_checks_for_project"` outside `.git`: only the definition, its module-docstring paragraph (`change_service.py:16-20`), `changes/check.py:278` (docstring, already a backlog line), `tests/test_checks_engine.py:19/46/329/348`, and records.
- **No canon row.** `REQUIREMENTS.md` has no hit. `docs/requirements/review/S9-ears-strict.md:26/288` and `CODE-CHANGES.md:222` ask for the deletion; `docs/requirements/history/` is history.
- **No user-guide text.** `docs/user-guide` has no hit.
- **Left behind:**
  - the registry node (A-1, turns the suite RED);
  - the stale test docstring (A-8a);
  - the backlog and CODE-CHANGES rows to close (A-8b);
  - the earlier T-03 ruling to be recorded as superseded (A-8c).
- The imports only that function uses (`S19File`, `IntelHexFile`, `parse_mac_file`, `build_loaded_s19`/`build_loaded_hex`, `enrich_tags_and_render`, and possibly `parse_a2l_file`) each need the per-symbol grep the slice already plans. Several are used elsewhere in the module.

## Interfaces with the other increments

- **Inc 5 (I-3):** the read line and Inc 5's item-building lines are disjoint. Pin the name source (A-9).
- **Inc 6:** disjoint lines (`:7106`, `:4810` against `_patch_editor_load_tail` and the load arms). One behavioural coupling to note for Inc 6's E1: after Inc 4, a symbol document loaded with the A2L counts as clean, so `PatchEditorPanel.mark_loaded` now runs for it (`E1-rulings.md` §1 item 1). Inc 6's lifecycle cases should include one symbol-document load. The F-06 project-folder listing will also feed more files into the same read.
- **Inc 9 (I-4):** sound. `_execute_one_variant`'s signature is unchanged, and Inc 9 only narrows the `files` it receives via `_resolve_manifest_entry`, which this increment does not touch.

## Requirement quality

- Rows R-CHG-SYM.9 … .12 and R-TUI-058.9 are singular and verifiable, and they name no function or file in their statements. The six alternatives are defined once (CTX-CHGDOC *session read*), and every row has a negative control that can fail.
- R-CHG-SYM.11 follows the `declarado` ruling: `project.json` declares no A2L, and the folder holds at most one (`workspace.py:2189-2191`).
- R-CHG-SYM.13 is the row to reshape (A-2, A-3).
- D-3 (append the plain line, keep the finding line) is the right call. Replacing the line would need an "unless" on R-TUI-058.3, and hiding the finding breaks R-CHG-001.21.

## Probe (LAN Linux host)

The LAN Linux host, interpreter `/data/miniconda3/envs/s19ci/bin/python -I`, worktree `/tmp/s19e3i4/wt`. `b7b77c4` is local-only (not on origin), so the probe ran on **`origin/main` = `aa17f851`**. `git diff --stat aa17f851 b7b77c4 -- s19_app/tui/changes/io.py s19_app/tui/services/variant_execution_service.py` is empty, so the measured code is the same. Scripts: the scratchpad's `e3i4_probe.py` and `e3i4_probe2.py`. The "index-once" numbers patch `_resolve_symbol_tag` with a prebuilt index, which projects D-2. The worktree and `/tmp/s19e3i4` were removed and pruned afterwards. Nothing ran on the Windows PC.

## Architect evidence checklist

- ✓ Constraints stated: screen-thread budget (R-CHG-SYM.13), file cap 4 (`E1-slice.md` §1), no implicit A2L (`declarado`), Inc 5/6/9 line ownership. Cost in $ is `n/a — local desktop app, no metered service`.
- ✓ Alternatives where a real decision exists:
  - screen thread vs worker vs per-generation cache (§2);
  - eager vs lazy index (A-2);
  - substring-plus-guard vs structured reason for R-TUI-058.9 (A-5: keep, add the arm).
  - Where the choice is already made: D-1 by D9-7, D-3 by R-TUI-058.3.
- ✓ Rationale tied to constraints (§2).
- ✓ Risks: the suite goes RED on the registry (A-1); cost on every read with a large A2L declared (A-2); report-run side effect (A-4); name-source drift with Inc 5 (A-9).
- ✓ Cost and latency measured: `executed` on the LAN Linux host (§2 table). Post-fix numbers are `planned` (E4).
- n/a — diagram: a one-parameter change at six sites; the graph's tables carry the flow.
- ✓ What would change the recommendation: §2, last paragraph.
- ✓ Two-layer trace: every story has rows and cases (`01-requirements.md` coverage table; 19 cases in `02-test-cases.md`). A-4 and A-5 each add one arm.
