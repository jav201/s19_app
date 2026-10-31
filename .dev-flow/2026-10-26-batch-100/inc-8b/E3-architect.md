# E3 — architect review of the Inc 8b design (Code-Wire graphs, no code)

Stage E3 (code-free design review, PDR) of the `design-first-increment` pipeline, round 1. Reviewer: architect. Read-only toward the design; this file is the only write. A security reviewer runs in parallel.

**Inputs read:** `inc-8b/E1-scope.md`; `01-requirements.md` (§3 token table, HLR-171, 171a, 171b, LLR-167.6, 167.6a–g, LLR-171.1–171.1i, 171.2–171.2e, 171.3, 171.3a, 171.4–171.4j, 171.5, glossary); `codewire/baseline-notes.md`, `interfaces-8b.md` including the 11 E3 pre-rulings, `proto-8b-app.md` (G1), `proto-8b-gather.md` (G2); `experiment-8a/E3-rulings.md` (R1–R20). Code checked at `ebe6d0c` (the worktree HEAD); every claim below cites `file:line`.

## Verdict

**FAIL**: 3 MAJOR findings are open (A3-1, A3-2, A3-3). There is no HIGH.
- A3-1 is a prototype edit: the save order breaks the pasted-document arm.
- A3-2 and A3-3 need an orchestrator ruling. Both concern the `batch` / `assignments` records that LLR-171.1h carries.
- The 14 MINOR / LOW findings can go to E4 as addenda once the three MAJORs are settled.

## What holds (evidence, not findings)

- **Refusals before the first `mkdir`.** Today's order is parent → name guards → missing sources → target link → plan → `mkdir` (`app.py:9387`, `:9407-9520`, `:9527-9550`, `:9555-9565`, `:9567-9660`, `:9681`). G1 adds the foreign parent before the name guards, and adds the source-folder, MAC, A2L and cap refusals to the plan and free space after it. So every new refusal lands before `mkdir`. The body's remaining `validate_project_files` error (`:9739`) fires only for an existing target that already holds two MACs or two A2Ls. There, `mkdir` raises `FileExistsError` and creates nothing.
- **Rollback on a mid-copy failure is complete.**
  - `_abort_save` removes exactly `placed_files`, then `created_dirs` plus the project folder, deepest first, each only while empty (`app.py:9192-9232`).
  - `_copy_project_subfolders` appends each folder it creates and each non-reused landing before the next copy. A raise from `place_into_workarea` reaches the existing handlers.
  - `place_into_workarea`'s own `mkdir(parents=True, exist_ok=True)` (`workspace.py:1121`) is a no-op once G1 has created the folder, so it never creates a folder that is not on the list.
- **A fresh Q never reuses.** In a fresh Q a sub-folder copy cannot hit a byte-identical reuse that lands under another name. `_reuse_candidate_names` matches `<name>` and `<stem>_<digits><suffix>` only (`workspace.py:790-856`), and the copy order (POSIX text) puts `a.json` before `a_1.json`. So G1's "did not land at its path" check (step 5) fires only on a real fault.
- **The A2L-only load.**
  - `build_variant_set(name, [])` returns a set with 0 variants, not `None` (`workspace.py:1950-1977`). So LLR-171.2c's later append has a set to write.
  - `choose_install_set` returns `InstallSet(None, None, a2l_files[0])` for an A2L-only folder (`app.py:1582` ff.).
  - The load's tail, from the reopen to `_publish_flow_session_dir` (`app.py:11350-11427`), runs with `install.variant is None`. G1's steps 6–8 therefore need no second announcement path.
- **Execute on an A2L-only project does not crash (ruling Q11).** `_start_execute_scope_worker` returns on `not variant_set.variants` with one status line (`app.py:5039-5041`). The wording of that line is A3-15.
- **`_manifest_carry` needs no change (G1 F-1 confirmed).** It makes every record relative to the folder it was read from (`app.py:11612-11630`). The serializer does not check that a file exists (`variant_execution_service.py:889-890`), so a carried record never makes the write refuse.
- **Load of Q never reports a dangling `batch` as `missing`.** `check_project_files` builds `missing` from `files` and `active_document` only (`manifest_writer.py:1221-1290`). This is why A3-2 shows up on Execute and in LLR-171.1h's own threshold, not on Load.
- **Inc 8a rules kept:**
  - R12: the target is spelled from `self.workarea`, so the save and the load spell it the same way.
  - R11 / R18: there is one classifier, called with the unresolved source.
  - R13: `gathered` is carried for a merge only. Save as is a new target kind with its own carry (Q7), so R13 is not reopened.
  - R1: Q is fresh, so nothing is overwritten.
  - LED .53: the rollback stays exact.
  - Inc 5: no payload digests in the planner (see A3-17 on the wording of pre-ruling 5).

## Findings

Severity: HIGH / MAJOR / MINOR / LOW. **Route:** `ruling` means the orchestrator decides (a requirement or a pre-ruling changes); `proto` means a prototype text edit with no new decision.

### A3-1 — MAJOR — the pasted document is placed before the sub-folder copy, so a save as with a clashing pasted document aborts · route: proto (G1), plus the wording of pre-ruling 8

- **Where:**
  - G1 `_handle_save_dialog` step (11): the copy runs "right after the rows loop".
  - G1 `[I/O: project folder]` sequence `saveAs`: `place_into_workarea (top-level rows) → _copy_project_subfolders → gather`.
  - G2 `plan_project_save` step (6) and the DR-1 pasted example (G2 line 97).
  - Pre-ruling 3 ("predicted against the copy list") and pre-ruling 8 ("sub-folder copy before the gather").
- **Why:**
  - The pasted document is not placed by the gather. It is placed inside the rows loop by `_write_editor_document` (`app.py:9803-9817`).
  - That placement is checked against its row by `_plan_row_mismatch`, which compares the path and the reuse flag (`app.py:1701-1722`).
  - G2 predicts the pasted row against `inventory.root / home` (P's folder), because the copy will fill Q's home. At the moment the rows loop runs, Q's home is still empty.
- **Scenario:**
  1. P holds `patches/changes.json` (an earlier pasted save).
  2. The engineer pastes new entries (a new pasted document, `changes.json`) and saves as Q.
  3. The plan predicts `Q/patches/changes_1.json` (`new`).
  4. The rows loop writes into the empty `Q/patches`, so the file lands at `changes.json`.
  5. `_plan_row_mismatch` gives "Project NOT saved: the plan named …changes_1.json (new) but the file landed at …changes.json (new) — save again." The save rolls back. Saving again fails the same way.
  6. With the same bytes, the plan says `keep`, the write is `new`, and the save aborts the same way.
- **Fix:**
  - Run `_copy_project_subfolders` right after `mkdir` and the body's `validate_project_files`, before the rows loop. The top-level rows (image, MAC, A2L) never land in a sub-folder, so moving the copy earlier changes nothing for them. The pasted write and the gather then both place into a home that already mirrors P.
  - `_write_editor_document` finds the home already created and returns `created_home=None`, so the rollback lists stay exact.
  - Edit G1 step (11) and the `saveAs` sequence. Reword pre-ruling 8 to "the sub-folder copy runs before the first home placement (the pasted document in the rows loop) and before the gather".
  - Add a G1 example (TC-B100-59 / LLR-167.6e): P `patches/changes.json` (other bytes) plus a pasted `changes.json`, save as Q → Q holds P's file byte-equal at `patches/changes.json` and the pasted one at `patches/changes_1.json`, 0 plan-mismatch lines. The same with identical bytes → document row `keep`, 1 file.

### A3-2 — MAJOR — the carried `batch` / `assignments` name top-level files that a save as does not copy, and LLR-171.1h's fixture uses a form the dialog never produces · route: ruling

- **Where:** LLR-171.1h's threshold ("every file they name present in Q (copied with the tree, LLR-171.1)"); G1 `_handle_save_dialog` step (13) and the LLR-171.1h examples (G1 lines 40-42, `batch "patches/a.json"`); pre-ruling 9.
- **Why:**
  - The only producer of `batch` / `assignments` is the Save dialog. Its candidates are `_assignment_candidate_files`, which returns the bare names of the open project's **top-level** `*.json` files (`app.py:7366-7397`: `project_dir.glob("*.json")`). The dialog lists them (`screens.py:577-597`).
  - A save as copies sub-folder files only (HLR-171) plus the session's image, MAC, A2L and document rows. A top-level `a.json` is never copied.
  - A carried `batch: ["a.json"]` therefore names `Q/a.json`, which does not exist. The same holds for a dialog selection made during the save as, because the candidates are P's files.
  - The gather does not help. It resolves the name against Q, then copies the common-library file of that name into a home (`project_gather_service.py:634-647`). `batch` still names the top-level path.
  - `patches/a.json` (the fixture's form) can come only from a hand-written manifest. A test built on it passes while the production form fails. This is the vacuous-check pattern.
- **Scenario:** P holds `a.json` at the top level, and `batch` = `["a.json"]` (selected in an earlier Save). Save as Q → Q's `project.json` has `batch: ["a.json"]`, and Q holds no `a.json`. Load of Q paints nothing (Load does not check `batch`). Execute on Q resolves `Q/a.json` and fails to open it. LLR-171.1h's "every file they name present in Q" is false.
- **Fix (ruling, pick one):**
  - **(a) Recommended.** The copy list also holds each **top-level** regular file of P that the effective `batch` / `assignments` name (an `InventoryFile` with a top-level `relative`, link-checked, cap-checked, counted in `total_bytes`, landing at the same path).
    - It needs one plan row for top-level copies, e.g. a `PlannedFolder` named `.` or a `role="carried"` row, so LLR-167.6e and R-PC still hold.
    - The LLR-171.1h fixture moves to the dialog's form (`batch ["a.json"]`, top-level).
    - Mutant: drop the top-level carried copies → `Q/a.json` absent → RED.
  - **(b)** Narrow LLR-171.1h. Carried entries are kept as text. A top-level entry whose file Q lacks is named in one status line ("not copied") and `Q` keeps it. The "present in Q" clause then applies to sub-folder entries only.
  - **(c)** Copy every top-level regular `.json` file of P except `project.json` and `project.json.previous-*`. This is simplest to state, but it may copy files no record names.
- **Out of scope, record only:** Q also lacks P's other variants (a save as writes the session image only). Their carried `assignments` and `derived_from` entries name variants Q does not have. They do no harm on Load, and Execute plans only Q's variants. Keep this out of 8b unless the ruling picks (c) and widens it.

### A3-3 — MAJOR — C-7 is confirmed: Save project writes the dialog selection, empty by default, over the target's `batch` / `assignments` · route: ruling

- **Evidence:**
  - The dialog's `SelectionList`s are built from `(name, name)` pairs with no selected flag (`screens.py:577-597`). `on_mount` sets only the parent path (`screens.py:611-612`).
  - When a project has no candidate files, the lists are not drawn at all (`screens.py:541-548`), and the payload keeps `batch=()`, `assignments={}` (`screens.py:180-181`).
  - `_handle_save_dialog` writes `batch=payload.batch, assignments=payload.assignments` for every target kind (`app.py:10097-10098`).
  - The gather's composition list is also built from the payload only (`app.py:9932`).
  - Conclusion: every Save project into the open project, and every merge, with no selection made replaces the target's `batch` / `assignments` with empty values. The four in-project carry writers keep them, because they carry them through `_manifest_carry`; Save project is the one writer that drops them.
- **Scenario (why it matters to 8b):** Load P (`batch ["a.json"]`) → Save project into P (nothing selected) → P's `batch` is now `[]` → Save as Q → Q carries `[]`. LLR-171.1h's carry is defeated by the save most engineers make just before a save as.
- **Fix (recommended):** one rule for every Save project target: `batch` = `payload.batch` if non-empty, else the carried value; `assignments` the same.
  - The carried value is the source carry for a save as and the target carry for an open-project save or a merge.
  - It is one expression in place of G1's save-as-only branch, so there is less code than in the prototype.
  - Add one requirement arm, in LLR-164.2 or a new LLR-171.1h sibling: an open-project save with nothing selected keeps P's `batch`. Mutant: write `payload.batch` only → `batch` empty → RED.
  - Accept G1 R-10: an empty selection cannot clear a `batch`. No "clear" exists today, because an empty selection and an untouched dialog cannot be told apart.
  - Also feed the gather's `composition_names` from the effective `batch` (`app.py:9932`), so `gathered` agrees with the written `batch`.
- If the orchestrator keeps C-7 out of 8b, LLR-171.1h's AT must state "no Save project into P between the load and the save as". That precondition should be written down, not left implicit.

### A3-4 — MINOR — prototype and requirement text that the pre-rulings already changed · route: proto (design pass)

The rulings win. These lines must change so that E4 implements one contract:

| Pre-ruling | Stale text | Edit |
|---|---|---|
| 1 | G1 uses `PlannedCopy(rel, size)` (nodes `_copy_project_subfolders` in:, P-1); G2 still has `PlannedFolder.files` as "proposed" | `InventoryFile(relative, size)` and `SavePlan.copies` in both |
| 2 | G2 `ProjectInventory` keeps `total_bytes` (node + examples "total_bytes `1560`", "`1200`"); G1 P-4 offers to keep it | drop the field and its example values; keep `root` |
| 4 | G2 `plan_project_save` in: is fine; G1 step (5) does not pass `size_cap` | G1 passes nothing (call-time read); state it |
| 5 | G1 step (4), P-2 and the LLR-167.6f examples use `a2l_exempt: bool` (A2L only); G2 `_second_file_refusal` decides by `predict_placement` | `exempt: frozenset[str]` (MAC and A2L names), computed by G1; G2's helper tests name ∈ `exempt` and drops `predict_placement` |
| 5 / DR-6 | LLR-167.6c says "not one of the target's data files" (today's name-only rule, `app.py:9746-9758`) | requirement text: "not the same path, and not the same name with the same bytes", plus an arm: same name, other bytes → refused |
| 6 | neither graph has an `unreadable` field, node text or example | see A3-5 |
| 7 | G1 example line 55 and LLR-171.5's threshold say "a gathered **flow** row" | "a gathered row" (composition / CRC template), e.g. `patches/con.json` |
| 8 | G1 order | see A3-1 |
| 9 | G1 step (13) and F-6: "`derived_from` not carried from P" | see A3-8 |
| 11 | G1 rows 4–6 and G2's texts disagree | see A3-7 |

### A3-5 — MINOR — the unreadable sub-folder (pre-ruling 6) is a line on success or a refusal; the ruling does not say which · route: ruling + proto

- **Where:**
  - `walk_tree_no_links` swallows `os.scandir`'s `OSError` (`workspace.py:296-299`).
  - G2 also drops an entry whose `lstat` raises.
  - Pre-ruling 6 says "named, never silently skipped; one status line", with the next step "… then save again".
- **Scenario:** `P/reports/locked` cannot be listed, and the engineer saves as Q.
  - If it is a line on success, Q lacks those files and HLR-171's "0 missing" is false. The engineer is told, but the next step "save again" suggests the save did not happen.
  - If it is a refusal, nothing is written and the next step is true.
- **Recommendation:**
  - Make it a plan refusal before `mkdir`, the same way the inventory's `OSError` refuses today (`app.py:9647-9662`): `Project NOT saved: reports/locked could not be read — check that the folder can be opened, then save again.` This matches R16's wording for a file.
  - Report it from the one walker: give `walk_tree_no_links` an optional `unreadable: list[Path] | None = None` argument (its only consumers are save-as and its unit test, `workspace.py:288-291`), rather than a second walk.
  - Add a G2 example (`unreadable ("reports/locked",)` → refusal naming it, 0 rows) and a G1 example (0 `mkdir` calls).
  - `workspace.py` becomes the third source file (cap 4).

### A3-6 — MINOR — R-8: specify LLR-171.2d · route: ruling (requirement text)

- **Problem:** "whose project.json records no missing file" leaves one arm with no requirement: `project.json` records `firmware.s19`, the file is gone, and the folder holds no data or A2L file.
  - Today this case paints `No supported files` (`app.py:11288-11291`) before `check_project_files` ever runs (`:11313`).
  - G1 paints `no data or A2L file` for both arms.
- **Recommendation:**
  - Drop the qualifier: "If a project folder that holds a `project.json` holds neither a data file nor an A2L file, then … `no data or A2L file`." One line for both arms.
  - "load a file and Save project" is a true next step in both: the save rebuilds `files`.
  - Naming the missing records would need the manifest read and checked before the refusal. That is a second path for one message, and the `missing` problem already names them once the project loads, so leave it out.
  - Add an example to G1 `_handle_load_project`: a manifest recording the absent `firmware.s19`, no data or A2L file → 1 line holding `no data or A2L file`, 0 resets.

### A3-7 — MINOR — token rows: one wording each · route: ruling (confirm), then proto

These reuse the §3 table's existing next steps wherever one is true, so one next step keeps one wording across the app. "Project NOT saved:" / "Project NOT loaded:" lead each refusal.

| # | Case | Reason token | Next-step token | Note |
|---|---|---|---|---|
| 1 | Save parent not this work area (LLR-171.3) | `not the work area folder` | `choose the work area as the parent folder` | G1 as drafted |
| 2 | Load: folder is a link or junction (171.4e) | `link or junction` | `pick a project in the list` | existing step (the "not a project" row); G1's "pick **another** project" is a second wording |
| 3 | Load: folder resolves outside (171.4f) | `outside the work area` | `copy the folder into the work area` | existing row |
| 4 | Second MAC (167.6c) | `already has a MAC file` + the target's MAC name | `choose another name` | existing Save step; G1 "save under another name" and G2 "remove it … or save to a new project" both go; "choose another name" is true: a new name is a new project |
| 5 | Second A2L (167.6d) | `already has an A2L file` + its name | `choose another name` | as row 4 |
| 6a | Sub-folder file over the cap (167.6g) | `too large to copy` + the file + the limit | `move it out of the project folder, then save again` | limit in MiB, or in bytes when under 1 MiB, so the lowered-cap test paints a real number |
| 6b | Session file (image / MAC / A2L / document) over the cap (G2 top-level arm) | `too large to copy` + the file + the limit | `a project cannot hold files over <limit>` | 6a's step is false for a file that is not in the project; one row per true next step |
| 7 | Skipped links (171.1c), one line after the success line | `links or junctions not copied` + every path | `copy those files into the project if it needs them` | G1 as drafted |
| 8 | Copied but not recorded (171.5), one line per file | `copied but not recorded` + the file + why ("Windows reserves that name", or "the path is too long to record") | `rename it in the common folder, select the new name, then Save project` | G1's "rename it and Save project" is false: the gather re-copies the common-library file under the refused name (`project_gather_service.py:634-641`), so renaming the copy in Q records nothing |
| 9 | Save as: the open project folder became a link or left the work area | `link or junction` / `outside the work area` | `pick a project in the list` | existing step (same as row 2) |
| 10 | Load: no project.json and no data or A2L file (171.2e) | `no project.json` | `load a file and Save project` | G1 as drafted; the problem row's `Save project writes it` is false here |
| 11 | Copy found a link after the plan, or a copy landed under another name | `could not save` + the file + "changed while saving" / "did not land at its path" | `check the folder` | existing row |
| — | Free space (171.1e) | `not enough free space` (needs N, F free) | `free disk space or remove files from the project` | existing row |
| — | Unreadable sub-folder (pre-ruling 6, A3-5) | `could not be read` | `check that the folder can be opened, then save again` | aligned with R16 |

### A3-8 — MINOR — the `derived_from` carry (pre-ruling 9) needs two lines in G1 · route: proto (+ LLR-171.1h text)

- **The flag:** for a save as, `carried_derived` must come from the source carry. Today it is built from `target_carry` only (`app.py:9597-9600`), so `derived=bool(carried_derived)` and the plan's `manifest_keys` would leave the key out even if the write includes it. That is the plan-and-write disagreement 8a F3 closed.
- **The scope:** carry only the records whose key is a top-level file this save writes into Q (the image row's landing name). The other keys describe P's other variants, which Q lacks (A3-2, record only).
  - The record holds only the base's name and digest (`variant_execution_service.py:398-412`), so it stays true without the base file.
  - LLR-171.1h gains `derived_from` with that scope.
  - Example: P's image `firmware.s19` copied unchanged → Q's `derived_from["firmware.s19"]` equals P's; P's `other.s19` record is not carried.

### A3-9 — MINOR — what the pasted / outside document landing is "predicted against" · route: ruling (confirm)

- **The two texts:** pre-ruling 3 says "against the copy list". G2 predicts with `predict_placement` against `inventory.root / home`, P's folder on disk.
- **Where they differ:** only when P's home holds a name that is not in `copies`: a skipped link, an unreadable entry, or a non-regular entry.
  - A copy-list predictor would need a second implementation of the `_N` rule over a name list. A second implementation is the drift that SEC2-7 removed.
- **Recommendation:**
  - Confirm G2's form, which reuses `predict_placement`. The residual case (a link in `P/patches` named like the document) ends in `_plan_row_mismatch` and a rollback: loud, not silent.
  - Specify the landing in the resolved form, `Path(target).resolve() / home / predicted.name`. `_plan_row_mismatch` compares `normcase(str(...))` text against `PlacementResult.path`, which is resolved (`app.py:1713-1716`). An unresolved `W/Q/...` breaks whenever W has another resolved spelling.

### A3-10 — MINOR — AT-B100-09 cannot tell Q's flow list from P's · route: proto (G1 F-5 confirmed)

- **Why:** `P/flows/f1.json` still exists after the save as, so "Q's flow list shows f1" passes even if the list read P.
- **Fix:** in the AT, remove `P/flows/f1.json` after the save (setup through the filesystem, not app privates), then open the list → `f1` is shown. A mutant that copies no sub-folder then turns RED.

### A3-11 — MINOR — after a save as, session state still points at P · route: ruling

- **The flow panels:** `_publish_flow_session_dir` has one caller, the load (`app.py:11427`). After a save as, the open project is Q, but the Flow panels keep `P` as their session folder. That folder is the paste-validation base in `flow_screens.py:1861-1863` and the lanes' `session_dir` (`flow_screens.py:2775-2777`). 8b makes save as a project switch with content, so this stale value matters more than before.
  - **Recommendation:** in 8b, call `self._publish_flow_session_dir()` in the save commit block. It is one line, on every successful save.
- **The Patch Editor document:** a file-backed document whose source is in P stays bound to `P/patches/…`. The 8a bind (R12) covers pasted documents only (`app.py:10237-10238`). Whether the Patch Editor's own save then writes into P was **not verified**.
  - **Recommendation:** probe it in E4. If it writes into P, either rebind a document whose source is in P's home to Q's landing (the R12 form), or move it to the backlog with the probe attached.

### A3-12 — LOW — `_copy_project_subfolders` step (1) can be one containment call · route: proto (optional)

- **Today's text:** a per-component `lstat` loop (depth + 1 calls per file).
- **Simpler:** `contained_in_workarea(source_dir / rel, source_dir)` (`workspace.py:588`) resolves once and refuses any link component that leads outside P. A link that stays inside P is harmless, because those bytes are P's. `place_into_workarea` already refuses a link at the file itself (`workspace.py:1100-1103`).
- This is one call to an existing helper. Defer to the security reviewer if they prefer `lstat` semantics.

### A3-13 — LOW — refusal precedence in `_plan_project_save` · route: proto

`plan_project_save` takes one `refusal=`. G1 step (2) produces row 9 (source folder) while `image_step.refusal` may also be set. State the order: the source-folder refusal first, with no walk and no re-derive message. Today a passed refusal wins over the MAC clash (G2 line 98, `test_tc_b100_59_refused_plan_writes_nothing`); keep that.

### A3-14 — LOW — `total_bytes` rule wording · route: proto

- **The two rules:** pre-ruling 2 says "the top-level planned file sizes". G2 step (7) says "the planned files whose row is `new`".
- **Where they differ:** for a `keep` document row (an outside document identical to P's file that the copy places). G2's rule counts what is written.
- **Recommendation:** adopt G2's rule and reword the pre-ruling. Both examples (7000, 1384) are unchanged. DR-3 (`project.json` not counted) is accepted: the margin is a few hundred bytes, and the tests simulate free space.

### A3-15 — LOW — Execute's line on an A2L-only project · route: backlog (ruling Q11)

It does not crash (see "What holds"). But it paints "Execute: no project variants - load a project first." (`app.py:5040`) while a project is open. That next step is false. Backlog the wording with the Q11 item.

### A3-16 — LOW — glossary "Project" excludes an A2L-only folder · route: requirement text

- **The mismatch:** `01-requirements.md:37` defines a project as holding "a `project.json` or a data file". Under 8b, a folder holding only an A2L, with no `project.json`, loads (LLR-171.2e refuses only a folder with neither). The name-clash scan already counts the A2L (`app.py:9473`, `PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS`).
- **Fix:** add "or an A2L file" to the definition.

### A3-17 — LOW — race and wording records

- **G1 R-9 race.** A MAC added to a merge target between the plan and the placement is no longer refused. It lands as `_N`, the variant rebuild's `validate_project_files` returns "more than one MAC file" (`app.py:9906-9927`), `_variant_set` becomes `None`, and `_write_and_verify_manifest` then writes no manifest and reports success (`app.py:10858-10859`). The save says "Saved" over a stale `project.json`. This is the same TOCTOU class as 8a R-15. Backlog it, and send it to the security reviewer.
- **Pre-ruling 5's wording.** The premise "Planning computes no digests" is wider than the Inc 5 rule. The rule is "no **payload** digests", and `predict_placement` already hashes an existing target file of equal size (`project_gather_service.py:1103`). The ruling's outcome (G1 passes `exempt`) is fine. Fix the wording only, so a later reader does not take it as a new constraint.
- **Accepted as written:** G1 R-6 (the listing's `outside` arm cannot fire; the load covers it), R-7 (an A2L-only folder with an unparsable A2L resets and then refuses; backlog b), R-11, R-12, R-13; G2 DR-2 / PC-5 (backlog, pre-ruling 10), DR-4, DR-9.

## Review item map

| Item asked | Findings |
|---|---|
| (1) examples that fail; graphs agree | A3-1, A3-2 (a vacuous fixture), A3-4, A3-10, A3-14 |
| (2) seams G1↔G2 | A3-1, A3-4 (copy list, exempt set, totals), A3-5 (unreadable), A3-9 (landing), A3-13 |
| (3) ordering, rollback | A3-1 (the copy must precede the rows loop); the rest holds (see "What holds") |
| (4) save-as carry, C-7 | A3-2, A3-3 (C-7 **confirmed**), A3-8 |
| (5) listing / load / Save check, A2L-only attach | holds; A3-6, A3-16 |
| (6) LLR-171.2d R-8 | A3-6 |
| (7) token rows | A3-7 |
| (8) complexity | A3-3 (one rule instead of two), A3-9 (no second predictor), A3-12 |
| (9) Inc 7 / 8a rules | none reopened; A3-4 row 5/DR-6 changes the Inc 5 MAC rule by ruling 5 (requirement text owed); A3-17 |

## Wall time

About 12 minutes by the shell clock (19:58:55 → 20:10:42).

## Round 2

Stage E3 round 2 (code-free), architect. **Inputs read:** `E3-rulings.md` (R1–R12), `codewire/interfaces-8b.md` ("E3 round-1 rulings applied"), `proto-8b-app.md` (G1), `proto-8b-gather.md` (G2), `01-requirements.md` (HLR-171, LLR-167.6, .6c, LLR-171.1, .1a–.1m, .2d–.2g, .5, .6, .6a, .6b, .7, .7a, .7b, §1.3, §3 token rows), `01-requirements-ledger.md` LED .78. Code checked at `ebe6d0c`.

### Verdict

**FAIL, text only.** One MAJOR is open (A3R2-1): R11 is not yet written into any design text, and as the text stands, the unchanged rows loop also executes the new "carried" rows. Neither fix needs a new ruling. After the edits below, re-checking the edited lines is enough; the design needs no full review. The other open items are 3 MINOR and 2 LOW.

### (1) Round-1 findings: status

| Item | Status | Where it is closed (node / example) |
|---|---|---|
| A3-1 | closed. R11 keeps the sub-folder copy before the rows loop. | G1 `_handle_save_dialog` step (11); G1 example "TC-B100-59, LLR-167.6e, R2, A3-1" (`changes_1.json`); G2 `plan_project_save` example "DR-1, pasted document, R2" |
| A3-2 | closed (R3) | G1 examples "TC-B100-31, LLR-171.1, R3, A3-2" and "LLR-171.1h … A3-2 dialog form" (Q holds `a.json`, `c.json`); G2 step (4a), `ProjectInventory.top_level`; LLR-171.1h fixture moved to `["a.json"]` |
| A3-3 | closed (R4). Two residues: A3R2-3, A3R2-4. | G1 step (14) one rule for every target; G1 examples "LLR-171.6, LLR-171.6a, R4" (3 targets); LLR-171.6 / .6a / .6b |
| A3-4 | closed | `InventoryFile` / `SavePlan.copies` in both graphs; `ProjectInventory.total_bytes` dropped; `exempt: frozenset[str]` (G1 step 4, G2 `_second_file_refusal`); LLR-167.6c text plus the other-bytes arm; LLR-171.5 says "a gathered row" |
| A3-5 | closed (R8) | G2 `walk_tree_no_links(…, unreadable=)`, `inventory_project_tree`, `plan_project_save` step (3); G1 example "LLR-171.1k, R8, A3-5" (0 `mkdir`) |
| A3-6 | closed | G1 `_handle_load_project` step (4); example "LLR-171.2d, A3-6"; LLR-171.2d statement |
| A3-7 | closed | G1 token table rows 1–11 plus 4 unnumbered rows; §3 rows 353–368; G2 `_second_file_refusal` text says `choose another name` |
| A3-8 | closed | G1 step (5) (`carried_derived` taken from the source carry), step (14) `derived_from` scope; example "derived_from scope, A3-8" |
| A3-9 | closed | G2 step (8) resolved landing; example "A3-9, landing form" |
| A3-10 | closed | G1 example "AT-B100-09 …" (removes `P/flows/f1.json`) |
| A3-11 | closed (R9) | G1 step (16); examples "LLR-171.1l, LLR-171.1m, R9"; LLR-171.1l / .1m |
| A3-12 | closed | G1 `_copy_project_subfolders` step (1) |
| A3-13 | closed | G2 refusal precedence (1)–(7); G1 example "A3-13, refusal precedence"; G2 example "A3-13, precedence" |
| A3-14 | closed | G2 step (9) |
| A3-15 | backlog (ruled) | — |
| A3-16 | closed | `01-requirements.md:37` |
| A3-17 | backlog (ruled); the wording fix is applied | G1 `_plan_project_save` step (4) says "no payload digests in the planner" |

### (2) R1–R12 across the graphs, the interfaces and the requirements

- **R1, R5–R9:** consistent across G1, G2, interfaces and LLR-171.1j, .1k, .1l, .1m, .2f, .2g, .7, .7a, .7b.
- **R7:** the arithmetic checks in every place it appears: G1 110 592 and its mutants 106 496 / 72 536 / 45 056; G2 90 112 and 86 016 / 77 824 / 70 896 / 24 576; LLR-171.1i.
- **R12:** consistent (LLR-171.1j "measured at E4, not gated"; G1 F-9).
- **R4:** consistent across texts, but the gather list drops the assignments (A3R2-3).
- **R2 / R3:** written. They are now superseded in part by R10 / R11, which are not written yet: A3R2-1 (R11) and A3R2-2 (R10).

### (3) The new order against `_plan_row_mismatch`, the document row and rollback

What holds once A3R2-1's text is in:
- **Sub-folder copy, then the rows loop.** The pasted document is predicted against `inventory.root / home` (G2 step 8) and written into a home that already mirrors P. So `_plan_row_mismatch` (`app.py:1701-1724`) sees the predicted path and reuse flag, and the A3-1 arms still hold.
- **The file-backed document row.** It is still skipped by the rows loop (`app.py:9786-9789`) and placed by the gather, which runs after both copy phases.
- **The image row, then the top-level copy.** The image row is predicted against the empty Q (G2 step 8: top-level rows against `target`). It is placed before any top-level copy, so F-8's reuse of a byte-identical `firmware_1.s19` cannot happen. A copy named `firmware_1.s19` has the reuse candidates `firmware_1.s19` and `firmware_1_<d>.s19` only, never `firmware.s19`.
- **The gather after the top-level copy.** A dialog-form `batch` name (`a.json`) is found at `Q/a.json` and skipped (`project_gather_service.py:633-635`). So `gathered` gets no duplicate, and Q's `batch` names the copied file.
- **Rollback.** Both copy phases append to `placed_files` / `created_dirs` before the next step. A failure in either phase, including one after the emit, reaches `_abort_save` with exact lists, the same path the rows loop's mismatch abort already takes (`app.py:9877-9888`). One condition: the top-level phase must run before `self._report_filter_path = None` (`app.py:9898-9900`), otherwise a rollback leaves that reset done (A3R2-1 fix, item 2).

### (4) R4 for every target

G1 step (14) and LLR-171.6 / .6a give the carried value for each target:

| Target | Carried value | Where stated |
|---|---|---|
| save as | `source_carry` | G1 step (14); LLR-171.6 / .6a |
| open project | `target_carry` | G1 step (14); LLR-171.6 / .6a |
| merge (open project present, or fresh session) | `target_carry` | G1 step (14); LLR-171.6 / .6a |
| new folder from a fresh session | nothing, so the selection is written | G1 step (14); LLR-171.6 "none for a fresh session's new folder" |

- The three-target arm exists in G1's examples and in LLR-171.6.
- A refused save as (`source_reason`) reads no carry (G1 step 4).
- Open residues: the composition list (A3R2-3) and LLR-171.6b's fixture (A3R2-4).

### Open items

#### A3R2-1 — MAJOR — R11 is not written, and the unchanged rows loop also executes the "carried" rows · route: proto + requirement text (no new ruling)

- **Why it fails as written:**
  - G2 step (8) adds one plan row per top-level copy (role `carried`, action `new`).
  - G1 step (12) keeps the rows loop "unchanged". Its `else` branch places every row that is not the manifest, the document or the emitted image (`app.py:9861-9866`), so it would place each carried row's source again.
  - Under the text as written (G1 step 11: top-level copies run before the rows loop), that second placement finds `Q/a.json` byte-identical. It returns `reused=True` against the action `new`, and `_plan_row_mismatch` aborts (`app.py:1715-1718`). So every save as of a P with a top-level file the save does not write aborts.
  - Under R11 with the loop still unchanged, the carried rows would be placed by the rows loop. That path lacks the copy's R6 / S3-5 handling: an exception would paint `[WinError n]`, which is the LLR-171.7b negative control.
- **Text to change:**
  1. **G1 `_handle_save_dialog` step (11):** "copies P's top-level files that the save does not write itself (R3) and its sub-folder files" → "copies the entries of `plan.copies` that lie under a sub-folder (`'/' in relative`)". Keep the rest of the step (before the rows loop, R2).
  2. **G1 new step (12b), right after the rows loop and BEFORE `self._report_filter_path = None` and the variant rebuild (`validate_project_files`, `app.py:9898-9906`):** "(R11) `_copy_project_subfolders(P_dir, project_dir, <the top-level entries of plan.copies>, placed_files, created_dirs)`; a failure → painted, `_abort_save`, return".
     - It must come before the rebuild so that `_variant_set`, the manifest's variants and the active-variant id include P's other variants (`other.s19`).
     - The top-level phase also checks each landing against its carried row with `_plan_row_mismatch` (path and reuse flag), which covers A3R2-5.
  3. **G1 step (12):** "unchanged" → "unchanged except that it skips `row.role == "carried"` (those rows are executed by step 12b)".
  4. **G1 entity `[I/O: project folder]`:**
     - `desc`: replace "the copy (top-level files …, R3, and the sub-folder files) runs right after `mkdir`, before the rows loop and the gather (R2)" with "the sub-folder copy runs right after `mkdir`, before the rows loop (R2); the top-level copy runs after the rows loop, before the variant rebuild and the gather (R11)".
     - `sequence saveAs`: `… wins (mkdir) → _copy_project_subfolders (sub-folder entries, R2) → place_into_workarea (image, MAC, A2L rows; pasted document) → _copy_project_subfolders (top-level entries, R11) → build_variant_set → gather_project_artifacts → write_project_manifest → _publish_flow_session_dir`.
  5. **G1 `_copy_project_subfolders` func:** "It runs right after the target folder is created, before the rows loop and the gather (R2)" → "Called twice: with the sub-folder entries right after the target folder is created (R2), and with the top-level entries after the rows loop (R11)".
  6. **G1 example "(R2, order)":**
     - The call order becomes `mkdir, _copy_project_subfolders, _write_editor_document, _copy_project_subfolders, gather_project_artifacts, write_project_manifest`.
     - Add the F-8 arm: P holds `firmware.s19` and `firmware_1.s19` byte-identical to this save's emitted image → saved, Q holds both names, 0 lines holding "the plan named". Mutant: top-level copies before the rows loop → that arm aborts → RED.
     - Add: a carried row executed twice → mutant: the rows loop does not skip `carried` → spy on `place_into_workarea` with `P/a.json` 2 calls → RED.
  7. **G1 finding F-8:** decision → "R11: the top-level copy runs after the rows loop".
  8. **G2:**
     - `SavePlan.copies` text: "top-level copies first (R3)" → keep, adding "G1 executes the sub-folder entries before the rows loop and the top-level entries after it (R11)".
     - Example "DR-1, pasted document, R2": "G1 copies before the rows loop" → "G1 copies the sub-folder entries before the rows loop".
     - DR-11 decision: replace "(`SavePlan.copies`, top-level copies of R3 included) → the rows loop" with "sub-folder copies → the rows loop → top-level copies (R11) → gather → manifest".
  9. **interfaces-8b.md R2 line:** append "R11: the top-level entries of `copies` run after the rows loop and before the variant rebuild and the gather".
  10. **LLR-171.1 threshold, last sentence:** → "The sub-folder copy runs right after the project folder is created, before the first home placement; the top-level copy runs after the image, MAC and A2L rows are placed and before the gather (orchestrator rulings R2, R11)."

#### A3R2-2 — MINOR — R10 (no `project.json.previous-*`) is not written, and HLR-171 / LLR-171.1 as worded require copying them · route: proto + requirement text

- **Where the text contradicts R10:**
  - HLR-171 statement and LLR-171.1 statement: "every regular file … that the save does not write itself". A backup is a regular file the save does not write, so these statements require copying it.
  - G2 `plan_project_save` example "(LLR-171.1, R3)" asserts that `project.json.previous-20261030T000000Z` is copied.
  - G1 F-7's decision says the backups are copied.
- **The ceiling it breaks:**
  - The walk stops at `SAVE_AS_FILE_CEILING + 6` collected files, on the premise "at most 5 files the copy list leaves out" (G2 `inventory_project_tree`).
  - The number of backups has no bound. A P with 2 010 regular files, of which 2 000 are to be copied, 4 are left out and 6 are backups, stops at 2 006 and is refused with "too many files to copy (over 2 000)". LLR-171.1j's 2 000 arm says "saved".
- **Text to change:**
  - HLR-171 and LLR-171.1 statements: append "…, other than `project.json` backups (`project.json.previous-*`)".
  - LLR-171.1 threshold's list of files the save writes itself: append "; P's `project.json.previous-*` backups are not copied (R10)".
  - G2 `inventory_project_tree`: top-level `project.json` and `project.json.previous-*` are not added to `top_level` and do not count toward the stop. The stop becomes `SAVE_AS_FILE_CEILING + 4` (image, MAC, A2L, the document's own file).
  - G2 step (4a): "minus `project.json`" → "(those names are already absent from `top_level`)".
  - G2 example "(LLR-171.1, R3)" → copies hold "a.json" only, 1 carried row. Add: P with `2 000` copyable files plus `6` backups → refusal `None`.
  - G1 F-7 decision → "backups are not copied (R10)".
  - interfaces-8b.md R3 line: append "not `project.json.previous-*` (R10)".
  - Add a LED entry for the HLR-171 change.

#### A3R2-3 — MINOR — R4's resolved composition list leaves out the assignments · route: proto + requirement text

- **The difference:** today the gather list is `payload.batch` plus every name in `payload.assignments` (`app.py:9932-9936`). G1 step (13), interfaces R4, G2 `gather_project_artifacts` and LLR-171.6b all say "from the resolved `batch`" only.
- **Effect:** an implementation that follows the text stops gathering the documents an assignment names, which is a regression of LLR-138.1.
- **Text to change:** "from the resolved `batch`" → "from the resolved `batch` plus the names in the resolved `assignments` (LLR-171.6, .6a)" in all four places. LLR-171.6b's statement takes the same words.

#### A3R2-4 — MINOR — LLR-171.6b's fixture cannot turn GREEN in the dialog's form, and its gathered-row kill is vacuous · route: requirement text + proto

- **Why it fails in the dialog's form:**
  - In the dialog's form, `batch` `["a.json"]` names P's top-level `a.json` (`_assignment_candidate_files`, `app.py:7366-7397`).
  - The gather skips a name that resolves to a file in the project (`project_gather_service.py:633-635`).
  - So with `P/a.json` present, "`P/patches/a.json` present again" is false even with the correct code.
- **Why the kill is vacuous:** G1 example "LLR-171.6b, R4" ("P's gathered still holds the composition row of a.json") and its mutant ("feeding the gather from payload.batch → … absent → RED") rely on `gathered`. But `gathered` keeps P's rows by carry (LLR-164.2: the target's rows ∪ this save's rows), so that mutant survives.
- **Text to change:**
  - LLR-171.6b threshold: "P with `batch` `["a.json"]`, P's top-level `a.json` and `patches/a.json` removed, the common library holding `a.json`, Save project into P with nothing selected → `P/patches/a.json` present (gathered this save)".
  - G1 example: assert the `composition_names` spy holds "a.json" and `P/patches/a.json` reappears. Drop "gathered still holds the row" as the mutant's kill.

#### A3R2-5 — LOW — the mirror of F-8 under R11 · route: proto (covered by A3R2-1 item 2) or backlog

- **Scenario:**
  1. The image row lands at `fw_2.s19` (the session image is P's `fw_2.s19`).
  2. P also holds `fw.s19` with the same bytes.
  3. The top-level copy of `fw.s19` reuses `Q/fw_2.s19`, since `<stem>_<digits>` is a reuse candidate (`workspace.py:790-856`).
  4. The save aborts with "did not land at its path".
- **Impact:** loud, and reachable only through a hand-made identical pair, because the app's own placements and emits reuse identical files rather than writing a second copy.
- **Fix:** A3R2-1 item 2 (check the top-level phase with `_plan_row_mismatch`) keeps it loud and names both paths. If not, backlog it.

#### A3R2-6 — LOW — pending items the rulings file names, still open · route: requirement text

- LLR-167.6's threshold does not name the `carried` top-level rows. G2 step (8) produces them, so add: "a save as with top-level copies → 1 `carried` row per copy, `new`, equal to the written tree".
- §5.3 has no TC rows for LLR-171.1j–.1m, .2f, .2g, .6–.6b, .7–.7b.
- LED .78 still lists F-7 / F-8 / F-9 as open. Add an entry recording R10–R12.

### Wall time

About 7 minutes by the shell clock (20:36:01 → about 20:43).

## Round 3

Stage E3 round 3 (verification only, code-free), architect. **Scope:** the A3R2-1 … A3R2-6 lines, the R11 order across both graphs and LLR-171.1, and anything MAJOR / HIGH introduced by design pass 2 (the `+4` stop, the `carried` keyword, R13's entry ceiling). **Inputs read:** `E3-rulings.md` (R10–R13), `codewire/proto-8b-app.md` (G1), `codewire/proto-8b-gather.md` (G2), `codewire/interfaces-8b.md` ("E3 round-2 rulings applied"), `01-requirements.md` (HLR-171, LLR-167.6, LLR-171.1, .1i, .1j, .6b, §5.3), `01-requirements-ledger.md` LED .79, `app.py` `_plan_row_mismatch`.

### Verdict

**PASS-WITH-NOTES.** A3R2-1 … A3R2-6 are closed. The order is the same in G1, G2, the interfaces and LLR-171.1. The pass introduced no MAJOR or HIGH. Two items are open: 1 MINOR (A3R3-1, the size total counts each top-level copy twice) and 1 LOW (A3R3-2). Neither needs a ruling or another architect round; they can be fixed in the text before E4, and E5 can confirm them.

### (1) A3R2 items: status

| Item | Status | Where it is closed |
|---|---|---|
| A3R2-1 (MAJOR) | closed | G1 `_handle_save_dialog` step (11) (sub-folder entries only, `'/' in relative`), step (12) (rows loop skips `row.role == "carried"`), step (12b) (top-level entries after the rows loop, before `self._report_filter_path = None` and the variant rebuild, each landing checked with `_plan_row_mismatch`); entity `[I/O: project folder]` `desc` and `sequence saveAs`; `_copy_project_subfolders` func ("Called twice"); G1 examples "(R2, R11, order, A3R2-1)", "(R11, F-8, A3R2-1)", "(R11, A3R2-1, carried rows)", "(R11, A3R2-1, rebuild after the top-level copy)"; F-8 decision; G2 header, `SavePlan` func, `gather_project_artifacts` func, DR-11 decision; interfaces R2 and R11 lines; LLR-171.1 threshold (last two sentences) and its R11 mutant |
| A3R2-2 (MINOR) | closed | HLR-171 and LLR-171.1 statements ("other than `project.json` backups"); LLR-171.1 threshold and R10 mutant; G2 `ProjectInventory` (`top_level` excludes them, `normcase`), `inventory_project_tree` (stop after more than `SAVE_AS_FILE_CEILING + 4`), step (4a) wording, examples "(LLR-171.1, R3, R10)" (copies hold "a.json" only) and "(LLR-171.1j, R10, A3R2-2)" (2 000 + 6 backups → refusal `None`); G1 F-7 decision; interfaces R3 and R10 lines; LED .79 |
| A3R2-3 (MINOR) | closed | G1 step (13); G2 `gather_project_artifacts`; interfaces R4 line; LLR-171.6b title and statement |
| A3R2-4 (MINOR) | closed | LLR-171.6b threshold (P's top-level `a.json` removed too; oracle = `composition_names` spy + `P/patches/a.json` present) and negative control; G1 examples "(LLR-171.6b, R4, A3R2-4)", "(LLR-171.6b, A3R2-3)" and the negative-control example (the vacuous `gathered` kill is gone) |
| A3R2-5 (LOW) | closed | G1 step (12b) and `_copy_project_subfolders` step (6); G1 example "(R11, A3R2-5, mismatch check)" (`fw.s19` / `fw_2.s19` → loud abort, Q absent, mutant → RED) |
| A3R2-6 (LOW) | closed | LLR-167.6 threshold ("1 `carried` row per copy, action `new`"); G1 example "(TC-B100-59, LLR-171.1, R3)"; §5.3 rows for LLR-171.1j–.1m, .2f, .2g, .6–.6b, .7–.7b; LED .79 records R10–R13 |

### (2) The order across the texts

One order everywhere: `mkdir` → sub-folder copy → rows loop (carried rows skipped) → step 12b top-level copy with `_plan_row_mismatch` → variant rebuild → gather → manifest.

- G1: steps (9)–(14); `sequence saveAs` (`… _copy_project_subfolders (sub-folder entries, R2) → place_into_workarea (… rows loop, carried rows skipped) → _copy_project_subfolders (top-level entries, R11, checked with _plan_row_mismatch) → build_variant_set → gather_project_artifacts → write_project_manifest`); the order example.
- G2: header ("R11: G1 executes the sub-folder entries of `copies` before its rows loop and the top-level entries after it"); `plan_project_save` step (8) (home rows predicted against `inventory.root / home`, top-level rows against the empty top level, each carried landing the one G1 places after its rows loop); DR-11 decision.
- interfaces-8b.md: R2 line and R11 line (names the report-filter reset and the rebuild).
- LLR-171.1 threshold: "the sub-folder copy runs right after the project folder is created, before the first home placement; the top-level copy runs after the image, MAC and A2L rows are placed and before the gather". It does not name the variant rebuild, which is a design detail. G1 pins it with the `other.s19` example.

Rollback holds: step 12b runs before the filter reset, and both copy phases keep `placed_files` / `created_dirs` exact, as round 2 (3) required.

### (3) What the pass added: checked

- **`+4` stop.** It is read as "more than `SAVE_AS_FILE_CEILING + 4` counted files". The arithmetic holds: the image, MAC and A2L slots plus the document's own file are the only files the copy list leaves out, so 2 004 counted files → at least 2 000 copies (the G2 2 004 / 2 005 examples, and the 2 000 + 6 backups example). The residual (extra MAC / A2L files of P beside a session MAC / A2L can reach the stop early) is recorded in interfaces "Interpretation recorded". It only refuses early and never copies more than the ceiling, and a P with two MACs is already a load problem (LED .63 (b)). No item.
- **The `carried` keyword.** `Optional[Mapping[str, SavePlanRow]]`, keyed by landing name. G2 step (8) gives every carried row the landing `target / name`, action `new`, so the landing name equals the entry's `relative`, and the lookup is well defined. `_plan_row_mismatch` (`app.py`) compares `normcase` path and `reused == (action == keep)`, the same check the rows loop applies to the image row in the same resolved form (A3-9). The two-call mutant in G1's example "carried rows" is right under R11: without the skip, the rows loop places `P/a.json` first (`new`, accepted), and step 12b's copy then reuses `Q/a.json` and aborts. No item beyond A3R3-2.
- **R13 entry ceiling.** It is consistent across G2 (`inventory_project_tree`, `walk_tree_no_links(max_entries=)`), G1 step (6), the token table, interfaces R13, LLR-171.1j and §3 row 360. The 10 000 / 10 001 fixtures agree: 2 top-level files + `reports` + 9 997 folders. Every entry counts, `project.json` included, which matches the LLR text. The walker reads exactly 10 000 → yields all; it reads 10 001 → stops before sorting and yields 10 001. Note (no item): the "< 2 s" arm passes only because the stop falls while `reports/` is being listed, before any of its 9 998 sub-folders is opened. Security's executed 4.70 s for 20 000 opened folders is about 2.35 s for 10 000. So the timed arm must keep this flat shape, and a nested fixture would miss 2 s with correct code.

### Open items

#### A3R3-1 — MINOR — the size total counts each top-level copy twice · route: proto text + one example

- **Where:** G2 `plan_project_save` step (9): "Σ round_up_4k(size) over the planned rows whose action is "new" and over every copy". G2 `SavePlan` func: "the "new" rows and the copies". Since R3, each top-level copy is both a plan row (role `carried`, action `new`) and an entry of `copies`.
- **Scenario:** a save as of P with the top-level `a.json` (12 bytes). As written, T includes 4 096 for the carried row and 4 096 again for the copy. With the free space at the true total (LLR-171.1i: "every file the save as copies or writes … each rounded up"), the save is refused "not enough free space". A test written from LLR-171.1i and an implementation written from G2 disagree by 4 096 per top-level copy. No existing example has a top-level copy (the 110 592 and 90 112 fixtures both have 0), so nothing catches it.
- **Text to change:**
  - G2 step (9) → "over the planned rows whose action is "new" and whose role is not "carried", and over every copy (a top-level copy is counted once, through `copies`)". Make the same change in the `SavePlan` func.
  - Add to the G2 example "(LLR-171.1, R3, R10)": `total_bytes` counts "a.json" once (+4 096).
  - Mutant: summing the carried rows as well → +4 096 → RED.

#### A3R3-2 — LOW — the step 12b mismatch line paints a name from P's tree unscrubbed · route: proto text (E5 confirms)

- **Where:** `_copy_project_subfolders` step (6) returns `_plan_row_mismatch(row, placed)`. That function (`app.py`) formats the raw `row.landing` and `placed.path`. For a carried row, both hold a file name from P's tree. The same func says "Every failure names `relative` through `painted_names` (R6)", and LLR-171.7 says so too.
- **Reach:** only with a mismatch (the hand-made identical pair of A3R2-5) and a name holding control, bidi or zero-width characters. Loud either way, so LOW.
- **Text to change:** in step (6), on a mismatch, paint the same "the plan named … landed at …" line built from `painted_names` of the two project-relative names, or pass the line through `painted_names` before painting; add a scrubbed-name arm to the "(R11, A3R2-5, mismatch check)" example.

### Wall time

About 4 minutes by the shell clock (20:54:19 → about 20:58).
