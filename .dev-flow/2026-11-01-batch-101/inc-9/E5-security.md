# Inc 9 — E5 security review (implemented code, probed)

Batch 2026-11-01-batch-101, increment 9, branch `b101-inc9`, head `b204c7d`, base `e07fb00`. Reviewer: security-reviewer (Opus), independent of the implementers, the testers and the integrator. I also reviewed this lens at E3 (`E3-security.md`, both rounds). Scope: `git diff e07fb00 -- s19_app tests`. That is 4 source files (`tui/app.py`, `tui/flow_screens.py` (docstring only), `tui/services/flow_execution_service.py`, `tui/services/flow_persistence_service.py`) and 5 test files (2 new). Records read: `E3-security.md`, `E3-rulings.md`, `E4-rulings.md` (E4-R1, E4-R3), `codewire/graph-inc9.md` (I-2, I-3, I-5, I-7), `E4-integration-notes.md` (I-D8, the mutant table), `E1-rulings.md` §6 (BL-I9-4 … BL-I9-7), and the R-FLOW-FILE.14 row and case /14/5. Model: `inc-6/E5-security.md`. No product file was edited and nothing was committed.

Lens (as at E3): no byte written outside the work area through a link, a junction or a swapped home; the guard before any folder or file is made; removal of our own claim only; the confirm re-run's report; no new writer; no clipboard; tests touch no real user state; the residual stated truthfully. Severity: HIGH / MEDIUM / LOW / INFO (flow scale: MEDIUM = MAJOR, LOW = MINOR, INFO = note). Tags: `impl` (the code differs from the design), `design-gap` (the design itself leaves the risk), `records`.

## Verdict

**PASS-WITH-NOTES.** HIGH 0, MEDIUM 0, LOW 3, INFO 3.

- **The rulings hold as built.** Every E3 security ruling is `executed` in the code: S-1, S-2, S-3, R2-1, R2-2, E4-R1, E4-R3 and the TC-B99-13 census change. For the cases the rulings name, I approve the code by reading it, by an executed Windows probe of the exact helper text (arms P0–P8 below), and by the Windows nodes another run executed (`win-01`, 17 link nodes PASSED; not my run). The cases are a link or junction at the name before the save, a dangling junction or file link put in at the free name, and a home swapped once after the guard.
- **Three LOW notes, none blocking.** The check after the claim and its cleanup work through the name, not through the descriptor. A concurrent writer that swaps the home twice can therefore still:
  - put the content into a new file outside the work area (SE5-1; probes P3, P4);
  - make the cleanup delete a file of the claimed name outside the work area (SE5-2; probe P9).
  BL-I9-4 and the helper's docstring promise "an empty file at most, never content" (SE5-3, `records`). That is not true under such a race. Both need an active hostile process with write access to the project folder and timing inside a few microseconds. Neither can overwrite an existing file (`O_EXCL`). The house claim in `place_into_workarea` has the same class (BL-I9-4: "the same TOCTOU class as every guarded write"). The record wording (SE5-3) is owed before the batch closes; whether SE5-1 and SE5-2 are fixed in Inc 9 or go to the backlog is the orchestrator's ruling, because both change I-7.
- This clearance covers the security lens of the E5 gate only. It does not authorise the merge or the push.

## How it was checked

- **Reading.** The full diff, `workspace.py` (`_guarded_destination` `:680-797`, `_is_reparse_point` `:226-271`, the house claim `:1242-1330`), the two report writers and the confirm handler.
- **Probe (Windows PC, executed).** A Python 3.12.7 script extracted by AST the source text of `_create_new_json` (`flow_persistence_service.py`) and of the house guard helpers (`workspace.py`: `_guarded_destination`, `_is_reparse_point`, `_path_traverses_reparse_point`, `_find_workarea_root`, `_find_workarea_root_shortname`, `contained_in_workarea`, `WorkareaContainmentError`, the anchor constants). It exec'd that text in one namespace. **Nothing from `s19_app` was imported.** The driver `save()` runs `save_flow_json`'s steps in its order: guard → `mkdir` → `_create_new_json`, with a `render` that returns a 44-byte JSON. Links were real NTFS junctions (`_winapi.CreateJunction`, no privilege needed), real file symbolic links (the account holds the privilege) and real hard links. They were made in a scratch folder with `LOCALAPPDATA` pointed at a scratch folder and no clipboard; races were driven by wrapping `os.open` / `os.lstat` / `os.close`. Transcript (paths redacted) and script: `../evidence/inc-9/e5s-probe.txt`, `../evidence/inc-9/e5s-probe.py.txt`. This is evidence for the helper's logic on Windows, **not** for the product nodes. The scratch folders were removed afterwards.
- **Cited, not mine.** `int-01`, `int-06`, `int-09` (LAN Linux host 2, the integrator). `win-01` (Windows PC, Python 3.11.15, E3A-08 Windows-only arms; 34 passed, 2 skipped by the POSIX-mode skip). It explains the `cpython-311` bytecode written in this worktree at 14:33.
- **Not run by me.** The mutant table of `E4-integration-notes.md` (M1–M19); any `pytest` run.

### Probe arms (Windows, extracted helper text, `executed`)

| # | Set-up | Result |
|---|---|---|
| P0 | Plain save | `flows/z.json`, 44 B, `nlink=1`; one CR per line (the `O_BINARY` fd plus the text wrapper) |
| P5 | A dangling **junction** at `flows/z.json` before the save (the catalogue's Windows arm of /14/1, which has no node, I-D8) | taken by `lexists` → `z_2.json`; the junction left; nothing at its target |
| P1 | A dangling junction put in at the free name between `lexists` and the create | The create does **not** follow a junction at the final component: it fails, the name is taken and the save lands in `z_2.json`. Nothing outside. |
| P6 | A dangling **file symlink** put in at the free name (house finding S-F1, real Windows follow) | The create follows it: `outside/t.json` **0 B**, then the check refuses (`WorkareaContainmentError`). The link is left and nothing is written. This is the stated residual. |
| P2 | `flows/` swapped once for a junction to O, at the create | refused; O holds **no** file (the claim was removed, `owned`) |
| P7 | `flows/` a junction to O before the save | guard refuses (`traverses a symbolic link or reparse point`); nothing made |
| P8 | The project folder a junction | guard refuses; nothing made |
| **P3** | `flows/` swapped for a junction to O before the create, and **back** after the check's `lstat` (before `realpath`) | **Content outside.** The check passes, the 44-byte JSON is written to `outside/z.json`, and the call returns `flows/z.json`, which does not exist. At the check, `GetFinalPathNameByHandleW` on the fd already read `…\outside\z.json` (SE5-1). |
| **P4** | P6's real S-F1 follow, then the link replaced by a **hard link** to the followed target | **Content outside.** `lstat` is regular, `samestat` is true (a hard link is the same file), there is no reparse point and the real parent is the home, so the check passes. The JSON is in `outside/t.json`, `nlink=2`; the fd's final path read `…\outside\t.json` (SE5-1). |
| **P9** | As P2, then `flows/` re-pointed at folder V (holding `z.json` = `VICTIM`) between the `close` and the cleanup `unlink` | **The victim file outside the work area is deleted.** `outside/z.json` (0 B) remains (SE5-2). |
| P10 | The `lstat`-failure branch: home swapped while the claim is open | Not reachable on Windows. The open claim pins the home folder's name: a rename with the claim open gives `PermissionError` 5, and is allowed after the close. The probe ended in its own `rmdir`. On POSIX this shape is reachable by reading (SE5-2). |

## E3 / E4 rulings — state in the code

| Ruling | State | Code (`flow_persistence_service.py` unless named) | Evidence |
|---|---|---|---|
| Guard before any folder or file (D-10, I-2) | `executed` · `approved` | `save_flow_json` `:1217` guard, then `:1218` `mkdir`; `save_chain_set` `:1708` / `:1709`. The empty-set and empty-name returns come before the guard and create nothing. The only callers pass `workarea_root=self.workarea` (`app.py:4017-4019`, `:4580-4582`); `None` still derives the anchor and refuses without one. | P7, P8; `int-06` (guard removed → 5 files land at the link targets); `win-01` R-FLOW-FILE.11/1–/3, R-FLOW-SET.7/1–/2 PASSED |
| Name check by `lexists` (S-1 a, S-2 a) | `executed` · `approved` | `:1059`; also on a non-`FileExistsError` claim failure `:1085` (house F1) | P5; `win-01` /14/1–/3, /8/1–/3 PASSED |
| Payload before the claim (S-3) | `executed` · `approved` (read) | `render` at `:1066`, before `os.open` `:1071` | read; no node (integration notes: a coverage gap for the E5 audit) |
| Exclusive create, mode `0o666`, `O_BINARY` (S-1 c, E4-R3) | `executed` · `approved` | `:1071-1076` | P0; `int-09` (POSIX mode, its negative control RED) |
| Check after the claim: regular, same file as the fd, not a reparse point, real parent == the already-resolved home (S-1 d, E4-R1) | `executed`; `approved` for the static and single-race cases | `:1096-1129`; the clause `:1114` compares with `resolved_home` from the guard, never resolved again; `contained_in_workarea` is no longer imported (M13's form is gone) | P2, P6; `win-01` /14/4, /14/5, /8/4 PASSED. **Not** robust against a double swap or a hard link: SE5-1 |
| Error paths (R2-2) | `executed` | `lstat` failure → close, best-effort unlink, `WorkareaContainmentError` (`:1097-1108`); check failure → close, unlink only when `owned` (`:1116-1129`); write failure → the `with` owns the close, then unlink and re-raise (`:1134-1142`) | read. The unlink in the `lstat` branch is unconditional, and every unlink is by name after the close: SE5-2 |
| Removal only of our own claim | `executed` for the static case; **not** guaranteed under a re-swap | `:1118-1124` (`owned` gate), `:1103`, `:1139` | P2 (removed the right file); P9 (deleted a file outside): SE5-2 |
| TC-B99-13 census (E3A-09) | `executed` · `approved` (read) | `tests/test_b99_staging.py`: `_create_new_json` is the one exempt function; the module's declared-exception key is removed | `int-01` PASSED (cited) |
| BL-I9-4 residual stated truthfully | **not met** | `E1-rulings.md:69`, docstring `:1041-1043`, `01-requirements.md:56` (R-FLOW-FILE.14 note) | SE5-3 |

## Other items of the brief

- **Confirm re-run (F-45).** Clear: the re-run can write no report outside the project and none of another lane.
  - The change is the mode token only (`app.py:4468-4472`, `:4531`).
  - The token is checked (`flow_execution_service.py:2007-2008`), dispatched like `sequential` (`:2092-2097`) and painted as a constant in the content (`:2155`).
  - The report path is `ctx.project_dir / reports / <timestamp>-chain-set-report.md` (`:2321-2327`). `project_dir` is `_active_project_dir()`, and no typed text reaches the path.
  - `chains` holds exactly the confirmed lane `specs[lane_index]`, after the bounds and waiting checks (`app.py:4493-4521`).
  - The confirm wrote this report on base too; the unguarded `reports/` is the existing BL-I9-7.
- **Status texts.** The two refusals are fixed text with no path and no markup (`app.py:4020-4025`, `:4583-4588`); the guard's message, which holds paths, is never painted.
- **No new writer, no clipboard.** The diff adds no writer beyond the two guarded saves and calls no clipboard API. No new test presses a copy or paste key (`c` is `confirm_attention`, `app.py:2759`).
- **Tests touch no real user state.**
  - Every path is under `tmp_path`, including every link, junction and swap target. The app is built with `base_dir=tmp_path` (`test_b101_flow_names_ui.py:70`), so its log and work area are under it (`app.py:2819-2821`).
  - `LOCALAPPDATA` is isolated per session and per test, with a digest check of the real store (`tests/conftest.py:66-98`).
  - The `os.open` wrappers create their targets only in `tmp_path/outside`.

## Findings

| Id | Severity · tag | Where | Scenario | Fix |
|---|---|---|---|---|
| SE5-1 | LOW · `design-gap` | `_create_new_json` (d), `flow_persistence_service.py:1096-1115` | The check after the claim proves the file's identity and place through the **name** (`lstat`, `realpath`). The write goes through the **descriptor**. (a) **Double home swap** (P3, executed, junctions, no privilege; on Linux by `renameat2(RENAME_EXCHANGE)`, by reading): the home is a link to O at the create and the real folder again by `realpath`, so every clause passes and the JSON is written into a new file in O. The call returns a home path that does not exist, and the app says "saved". (b) **Hard link after a followed create** (P4, executed; needs the Windows symlink privilege, as S-F1 does): this defeats R-FLOW-FILE.14's race arm in one more step. In both cases the app creates, as a deputy, a new file outside with the content; it never overwrites. | (1) Add `st.st_nlink == 1` to `owned`; one clause, closes (b). (2) Bind the place to the descriptor: compare the parent of the fd's own final path with `resolved_home`. On Windows use `GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd))`; P3 and P4 read `…\outside\…` there. On Linux use `os.readlink(f"/proc/self/fd/{fd}")`. Or do the POSIX steps relative to a `dir_fd`. This closes (a) and (b). It changes I-7, so it is a ruling: fold it in Inc 9, or backlog it beside BL-I9-4 and reword per SE5-3. A node: P3's double swap as an `os.open` / `os.lstat` wrapper; expected: the raise and 0 B in O; mutant without (2) → RED. |
| SE5-2 | LOW · `design-gap` (destructive) | cleanup unlinks `:1103`, `:1121`, `:1139` | Each cleanup unlinks **by name after the close**. P9 (executed): after a refused swapped-home claim, `flows/` is re-pointed at a folder V between the `close` and the `unlink`, and the unlink **deletes `V/z.json`**, an existing file outside the work area. The `lstat`-failure branch (`:1103`) unlinks with no ownership test at all; on POSIX a swap there plus a re-point after the close does the same (by reading). On Windows the open claim pins the home folder's name (`PermissionError` 5), so only the post-close window exists there. | Unlink by name only when the name provably still leads to our file inside the approved home. In the (d) refusal, unlink only when `owned` **and** the real parent equals `resolved_home`; after the real-path clause fails, leave the empty file (it is the stated residual) and never unlink through a name that resolves outside. In the `lstat`-failure branch, unlink only if a fresh `lstat` is `samestat` with `fstat(fd)` taken before the close and the real parent is the home; else leave it. With SE5-1 (2), use the descriptor's final path for this test. A node: P9 as wrappers; expected: `V/z.json` unchanged. |
| SE5-3 | LOW · `records` | BL-I9-4 `E1-rulings.md:69`; docstring `flow_persistence_service.py:1041-1043`; R-FLOW-FILE.14 note `01-requirements.md:56`; my own E3 S-1 text ("narrows the home-swap race to that same 0-byte residual") | "Can still leave an empty file …; no content goes there", "nothing but an empty file … can ever sit at a link's target" and "the helper removes its own same-stat file" are false under SE5-1 and SE5-2. Two smaller inaccuracies: on Windows a **junction** at the free name is never followed (P1), so the empty-file case needs a file symlink and its privilege (P6); and a project folder swapped between the guard and the `mkdir` can leave an **empty folder** outside (`mkdir(parents=True)` follows it; by reading). | Reword these three texts to the true residual: "With no concurrent writer: nothing outside. A file symlink put in at the free name on Windows (privilege needed): an empty file at its target. One home swap: an empty file (removed) or an empty folder. A concurrent writer that swaps the home twice, or puts in a hard link after a followed create, can still get the content written into a new file outside or the cleanup to delete a file of the claimed name outside (SE5-1, SE5-2); never an overwrite (`O_EXCL`). The same TOCTOU class as the house claim (`workspace.py:1242-1330`: `os.replace` and the cleanup unlink are by name)." `planned` until applied. |
| SE5-4 | INFO · `records` | `E4-rulings.md:8` and `E4-integration-notes.md:139` vs `E1-rulings.md:16`, `:70` | The id BL-I9-5 is used twice: for the Clear stale name (E1) and for `_keep_previous_manifest`'s default `0o777` claim mode (`app.py:11464`, confirmed: no mode argument). The security-hygiene row could be lost in the merge of the two. | Renumber the E4 row (e.g. BL-I9-8) in both E4 records. |
| SE5-5 | INFO | Windows evidence | The product's Windows link nodes ran in `win-01` (not mine): 17 PASSED, including /14/1–/14/5, /8/1–/8/4, .11/x, .7/x and AT-I9-3. Neither `win-01` nor any node covers the dangling **junction** at the file name (the catalogue's Windows arm of /14/1) or the real S-F1 follow; P5 and P6 show both at helper level only. The file-link nodes still call `os.symlink` with no named skip (I-D8). | Record `win-01` in `02-test-cases.md`'s Windows column. Leave P5 and P6 as helper evidence, or add a junction-at-the-name node. |
| SE5-6 | INFO | handlers `app.py:4016-4025`, `:4579-4588` | An `OSError` that is not a containment refusal (a write failure such as a full disk, a name too long (BL-I9-6), a home that cannot be written) leaves the handlers uncaught, as `write_text` did on base. Since S-3 the claim is removed first, so no empty file takes the name. No regression. | None for Inc 9; BL-I9-6 covers the handler catch. |

## Evidence states

- SE5-1: P3, P4 `executed` (Windows, extracted helper text); the Linux form `not-run` (read). Fix `planned`.
- SE5-2: P9 `executed`; the `lstat`-branch shape on POSIX `not-run` (read); the Windows rename pin `executed`. Fix `planned`.
- SE5-3: `executed` by reading the records against P1, P3, P4, P6 and P9. Rewording `planned`.
- SE5-4, SE5-6: read. SE5-5: `win-01` cited (`executed` by another run); P5, P6 `executed`.
- Mutants M10–M15 (the claim defences): `not-run` by me. Their nodes are GREEN on Linux (`int-01`) and on Windows (`win-01`), cited.

## Evidence checklist

- [x] Each finding has what · where · why · fix: the Findings table (Where / Scenario / Fix).
- [x] Each finding has a severity: LOW SE5-1, SE5-2, SE5-3; INFO SE5-4, SE5-5, SE5-6.
- [x] No secret values in this report: no secrets were read; paths and code citations only. The probe transcript redacts the home path and the account name.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH or MEDIUM is open. Every ruled mitigation is `executed`; the static and single-race cases are `approved` on executed evidence. The residual race (SE5-1, SE5-2) and its wording (SE5-3) are `planned`.
- [x] New tool or integration: none. The write surface is the one helper `_create_new_json`; it is scoped in the rulings table and in SE5-1 and SE5-2.
