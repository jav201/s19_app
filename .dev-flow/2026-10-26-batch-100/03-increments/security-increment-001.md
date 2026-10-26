# Security check — batch-100 Inc 1 (F1 routed from the code review)

| Field | Value |
|---|---|
| **Reviewer** | `security-reviewer`, independent |
| **Subject** | The uncommitted F1 fix in worktree `C:\Users\jjgh8\Github\s19_app-b100-inc1` (base `e044112`): a shared `_guarded_destination` in `workspace.py`, used by `place_into_workarea` and `place_group_into_workarea`, with a case-folded anchor, an 8.3 short-name fallback and an explicit `workarea_root` parameter. Read against the code review `review-increment-001.md` (F1) and ruling LED .49 (contract at `5f0ef66`). |
| **Execution** | Two probes ran against the worktree, which went first on `sys.path` (`python -I`, path inserted by the script). Each printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc1\s19_app\__init__.py`. Runtime: Python 3.12.7 on Windows 11. Scripts and outputs: `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\sec_inc1_probe.py` / `.out` and `sec_inc1_probe2.py` / `.out`. Each probe built one scratch folder (`scratchpad\inc1work`, `scratchpad\inc1work2`), removed its junctions with `rmdir`, then removed the folder. Both outputs end `junctions removed then scratch folder removed: True`. The worktree was not edited. |
| **VERDICT** | **`BLOCK — BLOCK-UNTIL: SEC-1`** (1 HIGH). This verdict authorises nothing, and it is not the operator's authorization. |

## Answers to the three questions

1. **Is the S-02 class closed for every writer touched so far?** **No.** It is closed only for callers that hand the guard an unresolved destination. In the probe, every unresolved shape was refused (A1–A5). But the app hands the guard already-resolved paths:
   - `current_project_dir` is stored as `project_dir.resolve()` (`app.py:8506`).
   - Save project builds `project_dir = (parent_resolved / cleaned).resolve()` (`app.py:8135`).

   Once a destination is resolved, the guard takes "this work area" from the *other* work area's own text. The probe showed this for 4 of 4 placement routes (B1–B4): each wrote, or was cleared to write, into another work area through a junction.
2. **Do the case-fold and 8.3 fallbacks open a bypass?** **No.** The fallbacks only choose which root to compare against. Resolved containment is still checked afterwards, and the 8.3 walk reparse-checks every component before it resolves anything. Every crafted shape was refused:
   - an upper-case anchor through a junction (C2);
   - the 8.3 spelling through a junction (S2);
   - a `.s19tool` that is a junction, reached both textually (C6) and through its 8.3 name (S4);
   - real folders whose long names are literally `S19TOO~1\WORKAR~1` (S5);
   - a nested `.s19tool` junction inside a project (C8).
3. **Is the explicit-root parameter safe when omitted?** **No.** With no root, "this work area" becomes whatever `.s19tool/workarea` the destination's text names, so a pre-resolved destination is enough to accept another work area (B1). Passing the root closes it (B5 is refused). No caller in the worktree passes it, and `copy_into_workarea` and `place_group_into_workarea` cannot accept it.

## Findings

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC-1 | **HIGH** | `workspace.py:553` `_guarded_destination` (root from the destination's text when `workarea_root` is None); callers: `app.py:8598` (variant append, touched in Inc 1), `app.py:8174`, `:8179`, `:8182` (Save project copies), `:8646`, `:8654`, `:8676` (MAC and A2L syncs), `project_gather_service._check_home_contained` (home under the resolved project folder), the Split/Join export (`dest_dir` from the resolved active project folder); `app.py:8135`, `:8506` (where the resolution happens) | **The S-02 escape is still live, one step earlier in the chain.** LED .49 makes the guard correct for an *unresolved* destination. It does nothing about the fact that the app resolves its project folders before any guard sees them. If `workarea/evil` is a junction into another work area, reached by loading it (`list_projects` still lists junctions until Inc 8b) or by saving under its name, then `current_project_dir` and Save's `project_dir` already *are* the other work area. Every placement into them passes the guard, because the anchor the guard finds is the other work area's own `.s19tool/workarea`. This is the class F1 rated HIGH, and it covers the writer Inc 1 rewired (the variant append, LLR-163.5). It breaks LLR-171.4's "covered by construction" claim. | `executed` (`sec_inc1_probe.out`). B1 `place_into_workarea(resolved evil)`, B2 `copy_into_workarea(resolved evil)` and B3 `place_group_into_workarea(resolved evil)` each gave `ACCEPTED -> …\other\.s19tool\workarea\T\firmware.s19`. B4 gave `_check_home_contained(resolved evil/patches): ACCEPTED`. `bytes now in the OTHER work area: ['firmware.s19']`. Control: B5, the same call with `workarea_root=<this work area>`, was `refused`. The unresolved forms A1–A5 were `refused`. | Every app-level placement passes **this** app's root. Add a keyword `workarea_root` to `copy_into_workarea` and to `place_group_into_workarea`, with the call sites unchanged otherwise, so P-34 still holds. Pass `workarea_root=self.workarea` at every `app.py` placement call and thread it through the gather and the export from their app callers. Add an AST census arm: every placement call in `app.py`, `project_gather_service.py` and `segment_split_view.py` names `workarea_root`. Add a TC arm per route (variant append, Save copy, gather home, export single and group), each placing into a *resolved* junction target and giving 0 bytes outside `self.workarea`. Making the root mandatory for app callers is the stronger form. Storing `current_project_dir` unresolved alone is not enough, because Save's `project_dir` and any future caller would re-open the gap. |
| SEC-2 | MINOR | `workspace.py:553` (`Path(destination).resolve()` / `root.resolve()` inside `_guarded_destination`) | An invalid path spelling makes `resolve()` raise a bare `OSError` (`WinError 123`) out of the guard rather than `WorkareaContainmentError`. Callers that catch only the containment class would let it escape. The base behaved the same way, and the reach is low because project names are sanitised. LLR-164.4's `OSError` handler (Inc 2) covers Save project. | `executed` (incidental, `sec_inc1_probe.out` C3/C4 with a malformed path): `raised OSError: [WinError 123]`. | Wrap both `resolve()` calls in the guard so an `OSError` becomes `WorkareaContainmentError` with the outcome-first message. Add a TC arm with a path containing `"`. |
| SEC-3 | MINOR | `workspace.py:339` `_find_workarea_root_shortname` | The 8.3 fallback reparse-checks every component from the drive root. The textual route checks only from `.s19tool` down. So a legitimate base under a reparse point is refused only on the 8.3 route; examples are a redirected or synced folder, or a junctioned user folder. That is a false refusal, not a bypass. | `not-run`: reasoned from the code. 8.3 names are enabled on this volume (`GetShortPathNameW` returned `S19TOO~1`), but no junctioned base was built. | Either accept this and state it in the docstring, or limit the fallback's pre-resolve reparse walk to the components from the resolved anchor down, matching the textual route. TC arm: a base reached through a junction with an 8.3 spelling. |

## Evidence checklist

- [x] Each finding has what, where, why and recommendation (table columns, SEC-1 to SEC-3).
- [x] Each finding has a severity: 1 HIGH, 2 MINOR.
- [x] No secret values or real names appear in the output; the paths are scratch paths.
- [x] The verdict is explicit: `BLOCK — BLOCK-UNTIL: SEC-1`, and the HIGH carries no applied-and-verified mitigation yet.
- [x] Probes ran against the worktree with `s19_app.__file__` printed. The worktree was not edited. Both scratch folders and their junctions were removed.
- [ ] Not tested: per-directory case-sensitive folders (the case-fold anchor) and Python 3.11. My reasoning: the anchor only selects the root to compare against, so with SEC-1's explicit root it cannot widen containment.

---

## Round 2: re-read of fix pass 2 (LED .50, main checkout at `412de63`)

| Field | Value |
|---|---|
| **Subject** | The uncommitted fix pass 2 in `C:\Users\jjgh8\Github\s19_app-b100-inc1`, per `HANDOFF.md` §"Fix pass 2" and the packet. Under LED .50: app paths stay unresolved; the 9 `app.py` placement calls pass `workarea_root=self.workarea`; the gather and the export thread the root through; with no root, the guard walks to the outermost anchor; SEC-2 raises the containment refusal. The four out-of-cap callers (apply, crc, flow_execution, flow_persistence) and SEC-3 are routed to the backlog. |
| **Execution** | Four probes ran against the worktree (`python -I -B`, the worktree first on `sys.path`). Each printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc1\s19_app\__init__.py`. Runtime: Python 3.12.7. Scripts and outputs are in `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\probes\`: `sec_inc1_r2_probe.py`, `sec_inc1_r2_emit_probe.py` and `sec_inc1_r2_flow_probe.py`, each with an `.out`. The main probe drives the **real app routes** in Textual `run_test`, using the worktree's own test helpers read-only. Each probe made one scratch folder and removed its junctions with `rmdir` before the folder. One folder (`inc1r2work`) was left at first because the app's log file was still open; I removed it afterwards by its literal path, and none of these folders remains. The worktree was not edited. |
| **VERDICT** | **`PASS-WITH-NOTES`**. SEC-1 is discharged by this re-read, and there is no HIGH. Two MAJORs (SEC-4, SEC-5) are in callers outside this increment's files. They go to their owners with their RED probes, and Inc 1 does not wait for them. This verdict authorises nothing beyond the increment gate; it is not the operator's authorization. |

### Closure of Round 1

| id | state | evidence |
|---|---|---|
| SEC-1 (HIGH) | **closed (discharged)** | **App routes, driven end to end** (`sec_inc1_r2_probe.out`). Project `evil` is a junction into another work area. It still loads, because the listing and load refusal comes in Inc 8b, and `current_project_dir` is stored unresolved (`equals its resolved form: False`). Then every route below was refused, and the other work area got 0 new files (`new files: []`):<br>- the variant append: `Project sync rejected: Refusing to place: … reparse point`;<br>- the MAC sync: the same refusal;<br>- the A2L sync: `A2L sync rejected: …`;<br>- Save project into `evil`: `Cannot save project: Refusing to place …`.<br>**Gather and export, with the app's root**, were refused for both unresolved and pre-resolved destinations: G1–G3 (`_check_home_contained`, `_gather_copy`) and E1–E3 (the export guard and `place_group_into_workarea`).<br>**Nested anchor:** N1, a `P2/.s19tool` junction with no root, was refused.<br>**Source:** all 9 `app.py` placement calls pass `workarea_root=self.workarea` (`app.py:8183`, `:8191`, `:8197`, `:8621`, `:8670`, `:8681`, `:8706`, `:8809`, `:8880`). `gather_project_artifacts(…, workarea_root=self.workarea)` is at `app.py:8278`. The export passes `workarea_root=Path(self._app().workarea)` (`segment_split_view.py:2066`). |
| SEC-2 (MINOR) | **closed** | W1 (no root) and W2 (root), both with an invalid spelling, now give `refused (WorkareaContainmentError)`. The wrap re-raises and never falls through. |
| SEC-3 (MINOR) | **routed** (backlog, LED .50) | Agreed: it is a false refusal, not a bypass. |

### Question 2: do the four routed callers receive only unresolved app paths?

- **`crc.write_crc_image`:** yes. `dest_dir` is `None` from its one caller (`screens.py:2694`), so the target is `ensure_workarea(base_dir) / crc`, which is unresolved.
- **`flow_execution_service` (`:1108`):** yes. It receives `ctx.project_dir` from `FlowContext(project_dir=self._active_project_dir())`, which is the stored, unresolved `current_project_dir`. With no root it was refused (D1).
- **`flow_persistence_service.import_flow_file` (`:1106`):** yes. It receives `project_dir / flows`. With no root it was refused (D2).
- **`changes/apply.save_patched_image`:** it receives the unresolved `self._active_project_dir() or self.workarea` (`app.py`, save-back). Its final `copy_into_workarea` is refused. But the function **resolves the path internally** to choose its staging root (SEC-4).
- **Latent path:** `_active_project_dir()`'s fallback returns `(self.workarea / self.current_project).resolve()` (`app.py:1911`). I found it unreachable today, because `current_project` and `current_project_dir` are only ever set together (`app.py:8223-8224`, `:8524-8529`). If it were reached, it would hand a resolved path to all four callers, and D3 shows a resolved path with no root is accepted. This is SEC-6.

### Question 3: new bypasses from the outermost-anchor walk or the SEC-2 wrap

None found:
- the nested-anchor junction is refused (N1);
- a junction from an app base nested inside an outer work area to an outer sibling is refused, with and without the root (N2, N3);
- a plain legitimate folder there is accepted (N4).

One semantic note, not a bypass: when the app base itself sits inside another work area, a no-root caller is bounded by the **outer** work area. N5 accepted a textual destination in the outer sibling. Today's routed callers build destinations from app paths plus fixed sub-folder names, so this cannot be reached. It belongs with SEC-6.

### Findings, round 2

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| SEC-4 | MAJOR (routed, outside Inc 1's files) | `changes/apply.py:741` (`_find_workarea_ancestor`) and `:885` (`resolved = dest_dir.resolve()`), used by `save_patched_image` (the save-back emit) | The emit picks its staging root by **resolving** `dest_dir` and walking the resolved path. With a junction project open, which can still be loaded until Inc 8b, the staging root is the *other* work area. The emit then creates `temp/` and `temp/.staging/` there and writes the emitted image into a private staging folder there. The final placement is refused (`MF-WRITE-CONTAINMENT`) and the staging folder is removed, but the bytes were transiently written outside this work area and the two folders stay. This is the S-02 class in a routed caller. | `executed` (`sec_inc1_r2_emit_probe.out`): `staging root the emit derives: …\other\.s19tool\workarea`, `staging dirs created by the emit: […\other\.s19tool\workarea\temp\.staging\stage-…]`, and `inside the OTHER work area after the emit: ['T', 'temp', 'temp\\.staging']`. | Take the staging root from `_guarded_destination(dest_dir, workarea_root)`, which runs before any staging, rather than from a resolved walk. Thread the app root from the save-back caller. TC arm: a save-back into a junction project creates 0 entries in the other work area. Route it to the increment that next touches `apply.py`, or to the backlog item LED .50 opened, with this probe as the RED side. |
| SEC-5 | MAJOR (pre-existing, routed) | `flow_persistence_service.save_flow_json` (`:976-1033`) and the flowset writer (`:1480-1510`) | Both writers use plain `mkdir` and `write_text` into `project_dir / flows` (or `flowsets`), outside the placement seam, with **no containment check at all**. A junction `flows/` inside a normal project sends a saved flow to any folder. A name that already exists is never overwritten (the `_<N>` suffix), but new files land outside the work area. The base has the same gap, LLR-171.4's writer list does not name these writers, and Inc 1 did not touch them. | `executed` (`sec_inc1_r2_flow_probe.out`): `junction P/flows -> outside: True`, then `files in the OUTSIDE folder: ['probe.json']`. | Route both writers through `_guarded_destination(project_dir / flows, workarea_root)` before `mkdir`, or through `place_into_workarea`. Add them to LLR-171.4's writer list by a ledger entry. TC arm: a junction `flows/` gives 0 files outside. Inc 8b's load refusal closes only the junction-*project* route, not a junction *sub-folder*. |
| SEC-6 | MINOR | `app.py:1911` (`_active_project_dir()` fallback) | The one remaining `.resolve()` on an app project path. It cannot be reached today (see question 2). If a later change sets `current_project` without `current_project_dir`, all four no-root callers would get a resolved path, and D3 shows that form accepted. | `executed` for the consequence: D3 `copy_into_workarea(RESOLVED evil) no root: ACCEPTED`. `not-run` for reachability, which I established from the assignment census: `current_project` and `current_project_dir` are assigned only at `app.py:8223-8224` and `:8524-8529`. | Return `self.workarea / self.current_project` unresolved, matching LED .50. This is a one-line change in `app.py`, a file Inc 1 already touches. |

### Evidence checklist (round 2)

- [x] SEC-1 was re-read on the diff and **executed through the real app routes**: variant append, Save project copies, MAC and A2L syncs, plus gather, export and the nested anchor at API level with the app's own arguments.
- [x] All four routed callers were traced to their app inputs. The one internal resolution I found is SEC-4.
- [x] The outermost-anchor walk and the SEC-2 wrap were probed for bypasses (N1–N5, W1–W2): none found.
- [x] Each finding has what, where, why, a recommendation and a severity: 0 HIGH, 2 MAJOR (routed), 1 MINOR.
- [x] No secret values or real names appear in the output. The worktree was not edited, and every scratch folder and junction I created was removed.
