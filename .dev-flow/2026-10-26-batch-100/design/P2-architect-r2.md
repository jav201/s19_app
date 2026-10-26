# P2 — architect re-review, round 2 — batch 2026-10-26-batch-100

Reviewer: `architect`. This review is read-only: nothing else was edited, and nothing was committed.
- **Under review:** `01-requirements.md`, `01-requirements-ledger.md` (LED .2–.13) and `02-review.md` at `0c7ca1d`. Dispositions: `design/P2-dispositions-r1.md` §4.
- **Code:** `1d677ba`. `git diff 1d677ba 0c7ca1d -- s19_app tests` is empty.
- **Probes:** each ran with `PYTHONPATH` set to the tree under test and `s19_app.__file__` printed first. Scratch trees (`git archive 1d677ba`) and scripts are in the session scratchpad. Nothing was committed.

## Verdict

**Gate: `iterate-to-refine`.** One new HIGH (B-01): the round-2 emit rule makes Save project refuse any session that holds a check document with entries. Six new MAJORs.

All 18 round-1 findings close: 15 as proposed and 3 differently but acceptably. None stays open. Three new findings (B-01, B-04, B-06) come from how A-06, A-17 and A-09 were closed.

**Counts:**
- **Round 1:** closed 18 · still open 0.
- **New findings:** HIGH 1 · MAJOR 6 · MINOR 7.

## 1. Closure of A-01..A-18

| id | state | where | note |
|---|---|---|---|
| A-01 | closed differently, acceptable | §1.2; LLR-169.5 (`not recorded`); LED .7; `BACKLOG-CODE.md:1468` | Option (b): the problem kind is restored and the routing goes to the backlog. The false premise is gone. |
| A-02 | closed | HLR-168; LLR-168.3; LED .7 | `active_document` is carried, plus a reopen arm. |
| A-03 | closed | AT-B100-20; LLR-168.3 (conversion and a negative control); LED .7 | The chain runs through a fresh Load and Execute scope. |
| A-04 | closed | LLR-169.4; LLR-169.8 | The code is asserted per arm. Residual wording: B-13. |
| A-05 | closed | LLR-169.5 ("shall not parse images"); LLR-169.9 | — |
| A-06 | closed | HLR-167; LLR-167.2; LED .4 | `save_patched` is kept, so B99-I7 is one rule. The emit trigger it introduced fails on check documents: B-01. |
| A-07 | closed | LLR-165.1 (the 11 names reset); LLR-165.2 (derived domain, classification arm); LED .8 | — |
| A-08 | closed | §1.3; LLR-167.1 / LLR-167.5; the LLR-167.2 negative control | The two predicates are named and kept apart. |
| A-09 | closed | LLR-164.2 (b); §5.4 row; LED .5 | The scheduling of its arm is B-06. |
| A-10 | closed | LLR-164.3 | Re-checked: the file limit (`+53 ≤ 259`) is tighter than the directory limit (`+8 ≤ 247`), so one check is enough. |
| A-11 | closed | LED .13 | — |
| A-12 | closed | LLR-170.2 ("0 new imports" arm) | — |
| A-13 | closed | LLR-169.2 | — |
| A-14 | closed | LLR-171.2 | — |
| A-15 | closed | LLR-169.2 → LLR-170.1 / TC-B100-28 | — |
| A-16 | closed | LLR-178.1 (in `variant_execution_service.py`) | — |
| A-17 | closed differently, acceptable | HLR-177; LLR-177.1 | The fix both copies on the main thread and refuses Patch apply/undo during a save. The `save_patched` split it needs is unnamed: B-04. |
| A-18 | closed | LLR-169.5; LLR-178.1 (the reason "no `project.json`") | — |

## 2. New findings

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| B-01 | HIGH | HLR-167 ("when the loaded image differs from its source **or the change document holds at least one entry**"); LLR-167.2; LLR-167.4; HLR-170 ("or `checks/` by kind") | **A check document turns every Save project into a refusal.** The Patch Editor can hold a check document (`kind = "check"`, `changes/io.py:140`). With one entry, the round-2 trigger fires and Save project calls `save_patched`. The apply gate blocks every entry of a non-change document (`apply.py:227` docstring: "`kind` ≠ `"change"` trips the apply gate … every disposition blocked"). `save_patched` therefore returns `ok=False`, and LLR-167.4 refuses the whole save with `blocked entries`. Today the same session saves, and the check document is gathered into `checks/`. HLR-170 still promises that. | `checkdoc.py`: a valid check document (`value_mode: text`), one `add_entry` → `save_patched ok: False \| Patched image not saved - 1 entry blocked - see issues`, `files: []` | The trigger reads "image differs from source, or the document is a **change** document with ≥ 1 entry". Add a TC-B100-15 arm: a check document with entries → byte copy, the document placed in `checks/`, 0 refusals. Re-check that LLR-174.1's W term (Patch Editor dirty) and the save-plan rows treat check documents the same way. |
| B-02 | MAJOR | HLR-174 ("It shall sit in the Load dialog's route, not inside `_handle_load_project`"); LLR-174.1; LLR-173.1 | **Two load entry points bypass the guard, so HLR-174's "when a load would lose unsaved work" is not met.**<br>- **Workarea Files rail pick:** `on_list_view_selected` → `_load_from_item` → `load_selected_file` (`app.py:8879`, `:9021-9037`).<br>- **Variant switch:** `v`, the variant selector, and from Inc 6 the panel's `v` → `_handle_select_variant` → `load_from_path` (`app.py:6736`, `+54`).<br>Both replace `current_file`, so an unsaved patch is dropped with no question. | `sed -n 9015,9035p app.py` → `self.load_selected_file(candidate)`; `_handle_select_variant` body → `self.load_from_path(descriptor.path)` | Either route both entry points through the same guard (both are in `app.py`, so no file is added) and add them to LLR-174.1's table, or name them out of scope with a reason. One arm each in TC-B100-44. |
| B-03 | MAJOR | LLR-169.8 (the shared predicate is tightened; "§5.4 names its callers' tests"); §5.4 row "manifest API … `test_flow_persistence.py` re-run" | **The tightening breaks a batch-97 test the census does not name.** Applied to `_resolve_manifest_entry` in a scratch tree, the 20 test files touching the manifest and flow-persistence APIs give `1 failed, 108 passed`. The failure is `tests/test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally` (`assert 0 == 2`: hostile flow refs now refused instead of rendered). It passes on base. The shared predicate also serves flow references (`flow_persistence_service.py:82-85`), so this changes flow behaviour, not only manifests. | `patch_p8.py` (drive/root, `:`, trailing dot/space, device names → `MANIFEST-PATH-ESCAPE`) + pytest on `p8subset.txt` → `FAILED tests/test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally`; on base → `1 passed` | Put the tightening in a manifest-key path only (a wrapper used by `read_project_manifest` and `_reject_unsafe_entry`), leaving the flow-reference use unchanged. Or keep it shared, name the test in §5.4, and re-pin it with a ledger entry. Run the full flow-persistence family at Inc 7's gate. |
| B-04 | MAJOR | LLR-167.6 (the plan's SHA-256 "of the bytes the emitter would write, derived on a copy"); LLR-177.1 ("run `save_patched`'s re-derive on the main thread … the worker shall emit … from a copy"); LLR-175.1 ("on every change of the name"); LED .4 ("B99-I7 is unchanged") | **Both requirements need `save_patched` split into "re-derive onto a copy" and "emit + verify".** No LLR names that API. Today `save_patched` re-derives in place on the session map and then emits and verifies in one call (`change_service.py:2009-2190`). The split also raises two more problems:<br>- `plan_project_save` would need an import edge `project_gather_service` → `change_service` / `changes` to re-derive and emit on its own.<br>- Re-deriving, emitting and hashing an image of up to 256 MB **on every keystroke** in the name field is a main-thread cost that ARQ §4 explicitly avoided (the dialog predicate "must be cheap"). | Code read: `change_service.py:2009-2040` (docstring), `:2140-2190`; the `project_gather_service.py:62-76` imports (no `changes` / `change_service`); `apply.py:100-103` (pure emitters `emit_s19_from_mem_map` / `emit_intel_hex_from_mem_map` exist) | Name the split as NEW `ChangeService` API in Inc 5, for example `rederive_for_save(copy) -> (map, summary)` with `save_patched` composed from it, so B99-I7's rule is unchanged. The app computes the emitted image's bytes and digest once per dialog open and passes them into `plan_project_save` as input. A name change recomputes only folder, landing names and actions. Inc 12b then uses the same split, and the evidence row "no new import edge" stays true. |
| B-05 | MAJOR | LLR-167.6 ("`_handle_save_dialog` shall execute exactly that plan"); HLR-175 / AT-B100-21; LLR-163.1 | **The handler cannot force a landing name.** `copy_into_workarea` and `place_into_workarea` choose the name themselves (reuse, or the lowest free `_<N>`, skipping anything `os.lstat` sees). If the plan predicts names with its own logic, that is a second rule for one fact, and it diverges whenever a directory, link or concurrent claim takes a `_<N>`. LLR-167.6's negative control ("the handler recomputes a landing name") tests the wrong direction. | Code read: `workspace.py:546-620` (the claim loop: `os.lstat`, `O_EXCL`, retry on `FileExistsError`) | Predict with the placement code itself: a `predict_placement(source_bytes, destination, name) -> PlacementResult` in `workspace.py` that shares `find_identical` and the free-name walk with `place_into_workarea`. The handler then checks that each landed `PlacementResult` equals the planned row, and paints a mismatch as such (never silently). TC arm: a directory named `firmware_1.s19` in the target → the plan says `firmware_2.s19`, and so does the file. |
| B-06 | MAJOR | LLR-164.2 (b) at Inc 2; TC-B100-59 at Inc 5; TC-B100-12 at Inc 4; ARQ §8 hard order | **Three TC arms are scheduled before the increment that makes them possible.** §5.3 handles this for ATs, but not for TCs.<br>- **LLR-164.2 (b), Inc 2:** "keeps the target's … `gathered`, `active_document`". The reader parses `gathered` only from Inc 6 (LLR-168.1) and `active_document` from Inc 8a (LLR-170.1). The carry and conversion machinery is LLR-168.3 (Inc 6).<br>- **TC-B100-59, Inc 5:** its "save-as with sub-folders" scenario needs Inc 8b (LLR-171.1), and its document row needs Inc 8a.<br>- **TC-B100-12, Inc 4:** it closes the panel (Inc 6), the question (Inc 10) and the dialog (Inc 9b). | Dependency walk over the amended LLRs (§3 of this record) | Add the TC rows to §5.3 with written-at and extended-at increments, or move each arm. Inc 2 carries only `batch` / `assignments` / `declared_regions`; Inc 6 and Inc 8a extend the merge arm. |
| B-07 | MAJOR — owner: the ARQ record (orchestrator / architect), not P1 | `docs/ARCHITECTURE.md` §11 B100-I1..I12; `design/ARQ-batch-100.md` | **Round 2 changes or adds interfaces that the map still states in their round-1 form.** Neither file has changed since `11763af`. Each needs an amendment row before PDR freezes it (trigger A3), with consumers measured:<br>- **B100-I2:** the reader caps, and a predicate tightened on a path shared with flow references (B-03).<br>- **B100-I3:** problem kinds changed (`not readable` moved out, `not recorded` and `no project.json` in).<br>- **B100-I4:** S1–S13 + 11 names, and `_session_snapshot()`.<br>- **B100-I5:** use narrowed. NEW: `mark_saved` / `differs_from_last_saved`.<br>- **B100-I6:** `find_identical`, `place_into_workarea`, `PlacementResult`; the export consumer.<br>- **B100-I7:** carry every non-owned key, project-relative.<br>- **B100-I8:** `p` opens it; `LoadProjectScreen` and `#project_list` retire.<br>- **B100-I9:** returns `RecentSources(entries, problem)`, not `list`.<br>- **B100-I12:** `begin_busy(key, label, steps)`, the action table, `#status_text`.<br>- **NEW:** `plan_project_save` / `SavePlan`; `contained_in_workarea`, which also tightens B99-I2's containment for every `copy_into_workarea` caller; the `save_patched` split (B-04). | `git log -- docs/ARCHITECTURE.md design/ARQ-batch-100.md` → last `11763af`; `grep -c "PlacementResult\|plan_project_save\|differs_from_last_saved\|_session_snapshot\|contained_in_workarea"` → 0 in both | Amend §11 (and ARQ §8's file table, see §3) in one commit before the P2 gate, each row with its "Frozen:" point and measured consumers. |
| B-08 | MINOR | P-34 ("17 call sites in 7 product files"); LLR-163.1 | **The count includes 2 docstring lines.** `crc.py:1443` and `flow_persistence_service.py:1096` are docstrings, so there are 15 call sites. The decision does not change. | `git grep -n "copy_into_workarea(" 1d677ba -- s19_app` → 17 lines; 1443 and 1096 are docstring text (read at round 1) | Restate P-34 as 15 calls plus 2 docstring mentions. |
| B-09 | MINOR | HLR-163 ("Every status that reports a placement shall say whether the file was reused") vs the §6.3 deviation | **The HLR asks more than the deviation delivers.** Only the variant append and the export use `PlacementResult`. Other placement statuses ("Saved change-set to X", `change_service.py:1773`; the save-back suffix) cannot tell reuse apart. They are true either way. | `grep` of placement statuses in `screens.py`, `crc.py`, `flow_execution_service.py`, `changes/io.py`, `change_service.py` | Narrow the clause to statuses that claim "added" or "wrote" (the variant append and the export), and name those two. |
| B-10 | MINOR | LLR-176.2 ("every `set_progress` site … shall map to exactly one action's begin or end") | **Step sites are neither begin nor end.** At least 4 of the 24 sites are mid-action steps, so the census as written cannot pass. | `sed` of the 24 sites: `:4951` `set_progress, 55`; `:6210` `55`; `:8769` `50, "Parsing …"`; `:8841` `50, "Parsing …"` | "…map to exactly one action's begin, step or end." |
| B-11 | MINOR | LLR-176.1 (the busy seam paints `#status_text`); LLR-178.2 (sets `#status_text` to project and file); `set_file_status` (`app.py:13587-13590`) | **Three writers share one label with no ownership rule.** The `#status_text` file-state line is owned by `set_status` / `set_file_status` (comment `app.py:2097`). An install's `set_file_status` during a worker action overwrites the spinner, and `end_busy`'s outcome overwrites the file state. | `sed -n 2084,2101p` and `13584-13590p app.py` | State the ownership: while an action is busy the seam owns the label, and `end_busy` restores the file-state text, or the spinner gets its own sibling widget. |
| B-12 | MINOR | LLR-164.1; LLR-169.8; LLR-172.2 (device names) | **Three new uses of a device-name rule, with two different lists already in the code.** `changes/apply.py:107` has `COM1–9` / `LPT1–9`. `segment_split_view.py:524` adds `CONIN$` / `CONOUT$`. The contract's list differs from both (`COM0`, superscripts). | `grep -rn '"CON"' s19_app` | Name one shared predicate in `workspace.py` for the three new uses. Leaving the two existing lists is acceptable if a backlog line names them. |
| B-13 | MINOR | LLR-169.4 threshold ("→ 8 × `MANIFEST-PATH-ESCAPE` (or the scope refusal)") | **No code is set for an out-of-scope but contained key** (`sub/x.s19`). The per-arm code assertion cannot be written. | text read | Name the code for the scope refusal, for example `MANIFEST-BAD-STRUCTURE`, and assert it on the `sub/x.s19` arm. |
| B-14 | MINOR | LLR-163.6 ("decide reuse through `find_identical` (`place_into_workarea` for single files)") | **The wording allows two decisions.** A `find_identical` call for the status word plus a separate placement call can disagree (time of check vs time of use). | text read; `segment_split_view.py:939-946` | The export's single-file status comes only from the `PlacementResult` of the placement it performed. `place_group_into_workarea` keeps requested-name-only, as stated. |

## 3. Design questions asked by the orchestrator

- **`place_into_workarea` → `PlacementResult` as a wrapper over `copy_into_workarea` (the QA-05 deviation).** This is a **sound seam and one rule**, provided the contract says so explicitly:
  - (a) `copy_into_workarea` is `return place_into_workarea(...).path`, with no second claim loop;
  - (b) the export takes its word from the placement it performed (B-14);
  - (c) the save plan predicts with the same code (B-05).

  Keeping the `Path` return avoids touching 15 call sites, and the `Path` is still true for every caller (LLR-155.3 holds).
- **The emit rule ("differs from source OR the document holds ≥1 entry") against A-06 / A-08.**
  - **Consistent with A-06:** source + document through `save_patched`, so B99-I7 stays one rule.
  - **Consistent with A-08:** it keys on the source predicate, never on `differs_from_last_saved`, and the LLR-167.2 negative control proves that.
  - **Defect:** it must count **change** documents only (B-01, HIGH).
  - **Side effect, accepted:** a document whose entries all skip re-emits the image at 32 bytes per line, so the file differs from the source's record layout and lands as a new variant. P-C's summary must show it.
- **`p` opens the one Load dialog with Projects highlighted.** Sound, and consistent with "one Load dialog" (US-163) and B100-I8.
  - It retires `LoadProjectScreen`; §5.4 re-pins the 7 test files that use it.
  - `_handle_load_project(name)` stays the direct entry for tests.
  - It deviates from `pa_C`, which had no `p`. §6.3 states the deviation, which is acceptable.
  - Executed: P-31 (`app.py:1437-1439`); P-30's ids all present in `prototypes/load_projects/variants/` (`AUTO_FOCUS` `#load_list` / `#confirm_no` / `#project_name` / `#result_ok`, `●` at `pa_C.py:44`).
- **Hard order.** Inc 5 lands `mark_saved` / `differs_from_last_saved` and `plan_project_save`, and Inc 10 depends on Inc 5. Consistent: increments run sequentially, so 10 follows 5. B-06 lists the TC arms that run ahead of their enabling increment. 12a+12b as one unit is consistent with ARQ §8's 12a → 12b.
- **A3 / map amendments:** needed (B-07).

### Per-increment source-file count, re-derived from the amended LLRs

The contract states file sets only for Inc 1 and Inc 5, and PLAN's table is round-1 (Inc 1 "workspace (+app)", Inc 6 without `screens.py`). `styles.tcss` counts as a source file.

| Inc | Source files from the amended LLRs | Count | Cap |
|---|---|---|---|
| 1 | `workspace.py`, `segment_split_view.py`, `app.py` | 3 | ok |
| 2 | `app.py`, `workspace.py` (+ `variant_execution_service.py` if B-06's merge carry is pulled forward) | 2–3 | ok |
| 3 | `app.py` | 1 | ok |
| 4 | `app.py` | 1 | ok |
| 5 | `app.py`, `change_service.py`, `project_gather_service.py` | 3 | ok. B-04's split lands here, in a file already counted. |
| 6 | `app.py`, `variant_execution_service.py`, `screens.py` (the panel, LLR-178.3) (+ `styles.tcss`) | 3–4 | ok, at cap with styles |
| 7 | `manifest_writer.py`, `variant_execution_service.py`, `app.py` (+ `project_gather_service.py` if the plan's manifest-key row shows `files`) | 3–4 | ok |
| 8a | `app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py` | 4 | at cap. No slack: any further file needs a re-cut. |
| 8b | `app.py`, `project_gather_service.py`, `workspace.py` (`contained_in_workarea`) (+ `manifest_writer.py` if the seam's containment lives in `_check_destination_contained`) | 3–4 | ok |
| 9a | `workspace.py`, `app.py` | 2 | ok |
| 9b | `screens.py`, `app.py`, `styles.tcss` (+ `variant_execution_service.py` if LLR-173.6's shared "what installs" function lives there) | 3–4 | ok |
| 10 | `screens.py`, `app.py` (+ `styles.tcss`) (+ `screens_directionb.py` if the W flag needs a public accessor in place of `_dirty`) | 2–4 | ok |
| 11 | `screens.py`, `app.py`, `styles.tcss` | 3 | ok |
| 12a+12b (one unit) | `app.py`, `styles.tcss` (+ `change_service.py` if B-04's split is not already in Inc 5) (+ `screens.py`) | 2–4 | ok |

**No increment exceeds 4 source files** as derived. Inc 8a is at 4. Inc 6, 7, 8b, 9b, 10 and 12 reach 4 depending on where the conditional pieces land. The contract (or ARQ §8) should carry this table, with each conditional decided.

## 4. Claims executed in the new text

| Claim | Result |
|---|---|
| LLR-174.1 "16 cells, 11 ask, 5 load; dropping F → 1 wrong" | ✓ re-enumerated: `ask 11 load 5`, `dropF 1` |
| P-34 "17 call sites in 7 product files" | ✗: 17 grep lines, 15 calls (B-08) |
| P-35 "35 test sources" | ✓ `grep -rl --include=*.py … tests \| wc -l` → 35 |
| P-30 prototype ids and bindings | ✓, with one unlisted extra: `Binding("alt+c"` |
| P-31 `p` / `v` bindings, `action_select_variant` at `:6687` | ✓ |
| P-32 `LoadGuardScreen` `:4279`, `_dirty` `:4808` | ✓ |
| `safe_text` at `utils.py:44` | ✓ (`def safe_text(value: str, style: str = "") -> Text`) |
| `#status_text` exists | ✓ `app.py:2100`, owned by `set_file_status` (B-11) |
| LLR-169.8 tightening is safe for its callers | ✗ (B-03): 1 regression in the batch-97 flow tests |
| HLR-167 emit trigger with a check document | ✗ (B-01): `save_patched ok: False`, 1 blocked |
| LLR-164.3 arithmetic (`207 + 1 + 0 + 53 = 261 > 259`) | ✓, and the file limit dominates the directory limit |
| LLR-169.2 constants (`workspace.py:75-77`) | ✓ `A2L_EXTENSIONS` `:75`, `PROJECT_DATA_EXTENSIONS` `:77` |

## Evidence checklist (architect)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | All `executed`: the 4-file cap (§3 table); the frozen B99-I7 / B99-I2 (B-04, B-07); `LongPathsEnabled = 0` (A-10 re-check); the batch-97 flow surface (B-03). |
| 2+ alternatives where a real decision exists | ✓ | B-02 (guard vs scope-out); B-03 (manifest-only wrapper vs re-pin); B-04 (split API vs plan-side emit); B-11 (ownership vs sibling widget). Elsewhere `n/a — decided by the round-2 rulings`. |
| Non-applying constraints marked n/a | ✓ | Network, auth, secrets: `n/a — no external surface`. |
| Recommendation tied to constraints | ✓ | Each closure names the rule it keeps: one rule per fact, A3 freeze, C-12, the cap. |
| Risks listed | ✓ | B-01..B-14; §3 (conditional file counts) |
| Cost / latency estimated | ✓ `planned` | B-04: a per-keystroke re-derive, emit and hash, bounded by the 256 MB copy cap (not measured). The B-03 run is measured at 5 min 25 s for 20 files. |
| Diagram when flow is non-trivial | `n/a — no new flow; ARQ §3.4 holds` | — |
| What would change the recommendation | ✓ | B-02 drops to MINOR if the operator scopes the rail and the variant switch out. B-03 needs no re-pin if the tightening is manifest-only. |
| Two-layer requirements, both chains | ✓ | Every story has an AT. A-03's chain is AT-B100-20, and B-06 is a scheduling gap, not a missing chain. |
