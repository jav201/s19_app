# E3 — architect review of the Inc 9a design (Code-Wire graphs, no code)

Stage E3 (code-free design review, PDR) of the `design-first-increment` pipeline, round 1. Reviewer: architect. Read-only toward the design; this file is the only write. A security reviewer runs in parallel.

**Inputs read:** `inc-9a/E1-scope.md`, `inc-9a/E1-rulings.md` (Q1–Q9, C1–C8); `codewire/interfaces-9a.md` including §Proposals and "Orchestrator rulings on the E2 proposals (pre-E3)"; `codewire/proto-9a-workspace.md` (G1); `codewire/proto-9a-app.md` (G2); `01-requirements.md` HLR-172 (:569), HLR-172a (:587), HLR-172b (:605), LLR-172.1 … LLR-172.6a (:1668–:2044), AT-B100-12/13. Code checked at `4fef292` (worktree HEAD, `s19_app/` clean); every code claim cites `file:line`.

## Verdict

**FAIL**: 2 MAJOR findings are open (A9-1, A9-2). There is no HIGH.
- A9-1: an accepted proposal (P9a-G1-2) has no requirement line and contradicts HLR-172 and LLR-172.1j as written. The `resolve()` it builds on also drops every source on a mapped network drive, which LLR-172.2e's own note expects to be kept.
- A9-2: the "absolute-only project route" ruling is not in G2's graph. With it, the outcome for a relative typed folder path is undefined, and HLR-172a / LLR-172.5 … .5d (unqualified "the path typed") contradict the ruled design.
- Both close with a ruling plus requirement and prototype text. No source decision is reopened.
- The 10 findings below MAJOR (5 MINOR: A9-3 … A9-7; 5 LOW: A9-8 … A9-12) can go to E4 as addenda once the two MAJORs are settled.

## What holds (evidence, not findings)

- **Record point and thread (S1, Q1/C1).** `load_from_path` reaches `copy_into_workarea` (`app.py:12811-12812`), its early returns sit before it (not found `:12792-12797`, unsupported `:12798-12802`, guard `:12813-12818`), and `_start_load_worker(copied)` comes after (`:12830`). Inserting the record between `copy_done` (`:12820-12825`) and `set_progress(50)` (`:12826`) satisfies LLR-172.1d's 4 arms by construction. The same holds for `load_a2l_from_path` (copy `:12882-12888`, `refresh_files` `:12890`, guards before). Both run on the UI thread: the dialog defers through `call_after_refresh` (`app.py:12765`) and start-up calls synchronously from `on_mount` (`app.py:7225-7227`). So the ruling that rejected the lock (P9a-G1-4) is right on its premise.
- **Inside test (S2).** `contained_in_workarea` resolves both sides and reports `False` on `OSError` (`workspace.py:618-640`). A relative `normalized` from `resolve_input_path` (`workspace.py:2020-2034`) is therefore safe to pass. The three LLR-172.1e callers: variant switch (`app.py:7606`), A2L pick through `_load_from_item` (`app.py:13081-13091`), typed inside file. All three pass a path inside W → 0 record calls.
- **Lister seam (S3, C5).** `_load_from_item` reads `item.data` and joins it to `W/temp` (`app.py:13082-13085`). G2 keeps `item.data = p.name` and paints `safe_text(p.name)` (`utils.py:44` returns a `Text`), so LLR-172.6a holds. The two label readers outside the slice still work. `tests/test_b99_load_project.py:59-64` reads `str(Label.render())`, which is unchanged for plain names. `tests/test_b100_focus.py:357-363` reads `data`.
- **Suffix sets agree (G2 S7, C6).** `SUPPORTED_EXTENSIONS = S19 | HEX | MAC` and `A2L_EXTENSIONS` (`workspace.py:107-111`) are exactly the sets `recent_kind` maps. Every suffix the classifier routes to a load has a kind.
- **Reserved homes come from one tuple.** `RESERVED_WORKAREA_HOMES` (`workspace.py:43`) feeds `_is_reserved_home`. Calling it in both the classifier (step 9) and `_handle_load_project` is justified: the classifier must refuse before `validate_project_files` lists `W/temp`.
- **Callers outside the slice.**
  - Start-up load (`on_mount` `:7225-7227`): records an outside file (Q2). A project path opens the Load-result panel (G2 R-1, accepted).
  - Save-dialog refresh (`:10596`) and the other `refresh_files` callers: they repaint through the lister and read no labels.
  - `_handle_load_project` reverse census: **20** test files (`grep -rln "_handle_load_project(" tests` → 20), not 13. None passes a reserved name (G2 F-1 confirmed).
  - `tools/e13/run.py:125` reaches only `_route_load_project("P")`, and `docs/images/capture_readme_media.py:88` only `_apply_prepared_load`. Neither reaches the record (G2 F-4 confirmed).
- **Two-source-file cap is realistic.** `workspace.py` gains 5 functions, 2 helpers and 2 dataclasses (about 150 lines). `app.py` changes 5 functions and adds 2 (about 120 lines). Tests (`tests/conftest.py`, `tests/test_b100_recents.py`) are not capped. Even counting the two C8 tool scripts, the total is 4, at the cap.
- **G1 read-side hardening is sound and evidenced by probe**: `RecursionError` (R-4), `type(v) is int` (R-5), `ensure_ascii=True` for lone surrogates (R-11), one bounded read (LLR-172.2a).

## Seams S1–S8: G1 vs G2

| Seam | Agree? | Note |
|---|---|---|
| S1 record after copy | yes | — |
| S2 inside test = caller | yes | — |
| S3 lister returns `Path`s | yes | — |
| S4 `None` store path | **no** | G1: no warning (1 debug). G2: 1 warning on every `False`. Ruled for G2 (P-2); G1 not updated (A9-3). |
| S5 problem word | yes | no G2 consumer at 9a |
| S6 who logs | **no** | G1 still logs 1 warning per failed write; with G2's warning that is 2 (LLR-172.1i wants 1). Ruled for G2; G1 not updated (A9-3). |
| S7 | **ids collide** | G1 S7 = "argument of the record call"; G2 S7 = "every suffix has a kind". The content is compatible (A9-3). |
| S8 | **ids collide** | G1 S8 = census shape; G2 S8 = `LOCALAPPDATA` read at call time. The content is compatible (A9-3). |

## Findings

Severity: HIGH / MAJOR / MINOR / LOW. **Route:** `ruling` = the orchestrator decides (requirement or pre-ruling changes); `proto` = prototype text edit with no new decision; `req` = requirement text.

### A9-1 — MAJOR — P9a-G1-2 is accepted with no requirement line, and recording `resolve()` silently drops mapped-drive sources · route: ruling + req + proto (G1)

- **Where:**
  - G1 `record_recent_source` steps (3), (4), (6) and examples at G1 lines 153–154.
  - G1 R-6, U-1, U-2.
  - interfaces-9a.md rulings: P9a-G1-2 accepted, G2 P-1 accepted.
  - HLR-172 (:571), LLR-172.1a (:1681), LLR-172.1j (:1771), LLR-172.2e (:1830, note).
- **Why:**
  - HLR-172 says "shall record that file's path" with no exception. LLR-172.1j's statement writes back "only those existing entries that the store read returns", so on `could not be read` its literal reading is a 1-entry rewrite.
  - The accepted P9a-G1-2 does two things no requirement states: (a) it refuses a source whose path the read would drop; (b) it writes nothing over an unreadable store. Tests for (a) and (b) would have no requirement to trace to (the batch's code→R rule).
  - (a) has a user-visible consequence the rulings do not name. LLR-172.1a records the `resolve()` form. On Windows, `Path.resolve()` asks for the final path, and for a mapped SMB drive that can come back as `\\server\share\…` (G1 R-6 says "can return"; not run here either, because no SMB drive is available). LLR-172.2e then drops it, and P9a-G1-2 refuses to write it.
  - LLR-172.2e's own note (:1838) assumes the opposite: "A mapped network drive letter cannot be told from a local one by syntax; the guard … is that a recent is never touched before Enter (LLR-173.4)". The requirements expect `Z:\…` entries in the store; the design removes them.
- **Scenario:** an engineer loads `Z:\releases\fw.s19` (Z: mapped to `\\nas\eng`). The load succeeds. `resolve()` gives `\\nas\eng\releases\fw.s19`. `record_recent_source` returns `False` and G2 logs a warning. The 9b recents list never shows any file from Z:, with no visible reason. The same happens for every typed UNC source, a common setup in engineering teams.
- **Fix:**
  1. Record the lexical absolute form `os.path.abspath(normalized)` instead of `resolve()`, and de-duplicate by `normcase(abspath)`. This keeps `Z:\…` (which passes LLR-172.2e), folds case and `..`, and makes no network call at record time. Cost: two link spellings of one file make two entries (convenience list; acceptable). Amend LLR-172.1a ("absolute path") and LLR-172.1b ("compared with `normcase` after `abspath`"). If the orchestrator keeps `resolve()`, LLR-172.1a must instead state that a mapped-drive source is not recorded, and the 9b UI owes the reason.
  2. Add two UW lines in the 172.1 family:
     - **LLR-172.1k:** "If the store read reports `could not be read`, then the system shall leave the recent-sources store unchanged." Threshold: open raising `PermissionError` (injected) → SHA-256 unchanged, `False`.
     - **LLR-172.1l:** "If the path to record would be dropped by LLR-172.2e, LLR-172.2f or LLR-172.2g, then the system shall not record it." Threshold: `\\host\share\x.s19`, a name holding U+009B, `C:\CON\a.s19` → 0 writes.
  3. Add "except LLR-172.1k/.1l" to HLR-172's decomposition, so the HLR stays true.

### A9-2 — MAJOR — the absolute-only project route is not in G2's graph, and relative typed folders get no defined outcome · route: ruling + req + proto (G2)

- **Where:**
  - interfaces-9a.md ruling on G2 F-5 / R-6 ("the project route applies only to an ABSOLUTE typed path … A relative typed path keeps today's file route unchanged").
  - G2 `_typed_load_route` steps (1)–(11): there is no absolute test.
  - HLR-172a (:589), LLR-172.5 (:1940), .5a, .5b (:1960), .5c (:1970), .5d (:1980), .5f (:2000).
- **Why:**
  - "Today's file route" for a folder is `Unsupported file type: ` (`app.py:12727-12729`). G2 deletes that line, and LLR-172.5e covers files only. So a relative folder path matches no requirement.
  - LLR-172.5b/.5c/.5d say "the path typed into Load names a folder …" with no qualifier. A relative `.s19tool/workarea/temp` typed from the base folder is a folder inside W: LLR-172.5b demands `not a project`, while the ruling sends it down the file route.
  - HLR-172a demands that a relative `.s19tool/workarea/ab` load; the ruling refuses it.
  - Steps (1)–(2) still call `resolve_input_path` on every path. Its base and repo fallbacks resolve (`workspace.py:2026`, `:2031`), which is the F-5 junction-follow the ruling meant to remove.
- **Scenario:** from the base folder, the engineer types `.s19tool\workarea\ab`. Today's file route gives `Unsupported file type: `, which no 9a requirement names. Yet HLR-172a says "load that project". A tester cannot write the arm, and the implementer has to guess.
- **Fix:**
  1. In HLR-172a, LLR-172.5, .5a, .5b, .5c and .5d, write "the absolute path typed into Load".
  2. Add one UW line, **LLR-172.5h:** "If a relative path typed into Load names a folder, then the system shall load nothing and paint the `not a supported file` and `check the path` tokens." Threshold: `.s19tool/workarea/ab` from the base folder, and a relative junction alias → 0 loads, 0 resets, 1 line each. This also closes G2 R-6 / F-5 with an executed arm.
  3. In G2, add step (0): `Path(typed_text).is_absolute()` on the stripped text (`C:x` and `\x` count as relative on Windows); when false, take only the file branch of step (4) with the folder → `not a supported file`. Drop R-6 and F-5 from the risks once that arm exists.

### A9-3 — MINOR — G1 is not reconciled with the pre-E3 rulings; the seams disagree on paper · route: proto (G1, both seam tables)

- **Where:**
  - G1 `read_recent_sources` / `record_recent_source` "under `_RECENT_LOCK`" (G1 lines 92, 127), the entity `[Data: _RECENT_LOCK]` (G1 line 208) and the `record` sequence (line 205). P9a-G1-4 was rejected.
  - G1 logging, P9a-G1-1, rejected: line 127 "1 warning per failed write", and examples at lines 142, 147, 148 ("1 log warning" from G1).
  - G1 S4 and S6 rows. G1 S7/S8 vs G2 S7/S8 ids.
- **Scenario:** an implementer follows G1 and G2 as drawn. A failed `os.replace` then logs 2 warnings, one from G1 and one from G2's `False` branch, and LLR-172.1i's "1 log warning" arm is RED. The lock code and its entity are built against a ruling.
- **Fix:** in G1, remove `_RECENT_LOCK` and its entity. Make every G1 log line DEBUG (failures included; never a path). Change the 3 "1 log warning" examples to "0 G1 warnings; G2 logs 1". Rename the seams to one list: S6 logging; S7 record argument; S8 census shape; S9 `LOCALAPPDATA` read at call time; S10 suffix-kind sets.

### A9-4 — MINOR — LLR-172.1h's 2 × 50-thread arm is non-deterministic once the lock is gone, and models a scenario that does not occur · route: req + proto (G1 line 145)

- **Where:** LLR-172.1h threshold (:1756), "2 threads × 50 records → … 20 entries"; G1 example line 145 ("`100` returns `True`").
- **Why:**
  - Records run on the UI thread only (see What holds), so two in-process writers do not exist in the product.
  - Under a test's 2 threads on Windows without the lock, `os.replace` onto a file another thread has open fails with `PermissionError` (→ `False`). Under A9-1's LLR-172.1k, a read during a replace gives `could not be read` (→ no write). The final entry count then depends on scheduling.
  - The real concurrency (two processes) is G1 R-8, accepted as last-writer-wins.
- **Fix:** drop the thread arm, and keep the deterministic arms: 100 distinct staging names, 100 `os.replace`, 0 staging left. If an arm must stay, assert only "parses as version 1, ≤ 20 entries, 0 staging files left". Prefer removing.

### A9-5 — MINOR — the writer byte cap (P9a-G1-3) guards a case unreachable on a default Windows setup; if kept, it needs one singular line · route: ruling (challenge) + req

- **Where:** G1 `_encode_recent_store`; interfaces ruling "P9a-G1-3 accepted; E3 fix adds one ubiquitous LLR".
- **Evidence (arithmetic, from G1's own probe formula):** with long paths off (the Windows default), a path is at most 259 UTF-16 units. The worst encoding is a non-ASCII BMP character at 6 bytes (`\uXXXX`); an astral character is 2 units and 12 bytes, still 6 bytes per unit. So one entry is at most about 259 × 6 + 26 ≈ 1 580 bytes, and 20 entries are about 31.6 KB, under 65 536. R-3 needs `LongPathsEnabled` plus paths over about 545 non-ASCII or about 3 240 ASCII characters. The outcome without the rule is a store reset to 1 entry: no crash, no data loss beyond the convenience list.
- **Fix (recommended):** drop the size loop and the new LLR, and keep LLR-172.1j's 1-entry rewrite as the declared degraded outcome (prefer removing over guarding). **If kept:** state it as one ubiquitous line, "The system shall write a recent-sources store file of at most 65 536 bytes." Its threshold carries both arms (20 × 3 245-char paths → 19 entries; 1 entry that cannot fit → 0 writes). Do not split "drop oldest" and "not recorded" into a two-"shall" statement.

### A9-6 — MINOR — the temp-is-a-link arm (P9a-G1-5) belongs in LLR-172.4c's statement, not as an extra threshold arm of LLR-172.4b · route: req

- **Where:** interfaces ruling "E3 fix adds the arm to LLR-172.4*"; LLR-172.4b (:1920) speaks of entries only, and LLR-172.4c (:1930) of the folder.
- **Why:** an arm in 4b's threshold that its statement does not cover is not verifiable against the statement (ISO/IEC/IEEE 29148 traceability).
- **Fix:** LLR-172.4c becomes "If the work-area temp folder is missing, is a link or junction, or cannot be listed, then the system shall show an empty Workarea Files list." That is one "shall" with three conditions. Add the threshold arm `temp` a junction to `<tmp>/elsewhere` holding `z.s19` → 0 rows. The base `glob` follows the junction and lists `z.s19` → RED (executed when a junction can be made).

### A9-7 — MINOR — the store-write skip of P9a-G1-6 does not cover G2's case-spelling arms, which also cannot pass on the Linux CI · route: proto (G2) + packet

- **Where:**
  - LLR-172.5: `<workarea>` in upper case.
  - LLR-172.5a: `PROJECT.JSON`.
  - LLR-172.5b / HLR-172a: `<workarea>/TEMP`.
  - G2 F-2: `W/temp.`.
  - CI: `.github/workflows/tui-ci.yml:25` `runs-on: ubuntu-latest`.
- **Scenario:** on Linux, `W/TEMP` does not exist. `resolve_input_path` returns `None` → `not found`, not `not a project`, and LLR-172.5b's "1 line holding both tokens" is RED. `abspath` keeps the trailing dot on POSIX, so `W/temp.` → `not found`.
- **Fix:** mark these arms `win32`-only with the reason ("case-insensitive file system" / "Win32 trailing-dot rule"), reported "not run" on CI and executed on Windows for the gate. List them beside P9a-G1-6 in the packet.

### A9-8 — LOW — LLR-172.5g's trailing dot/space arms: statement wording, a base-passing arm, and an inferred RED · route: req

- **Where:** interfaces ruling on G2 P-4 ("E3 fix adds `temp.` / `temp ` arms to LLR-172.5g"); LLR-172.5g (:2010) "compared case-folded"; G2 F-2.
- **Why:**
  - The statement must name the new comparison: "compared case-folded after trailing dots and spaces are removed".
  - G2 F-2 shows `W/"temp "` → `WinError 3` at `lstat`, so at `4fef292` `_handle_load_project("temp ")` already fails to load. That arm has no RED.
  - The `temp.` RED is inferred from an OS probe, not run through the app.
  - Neither input is reachable from a product caller. `list_projects` yields on-disk names, the typed route folds through `abspath`, and `resolve_input_path` strips whitespace (`workspace.py:2022`).
- **Fix:** keep the free `rstrip(" .")`, and add only the `temp.` arm, executed through `_handle_load_project` at E4. Drop the `temp ` arm, or declare it as passing on base.

### A9-9 — LOW — AT-B100-12 is not an output-then-consume chain at 9a · route: req (wording)

- **Where:** E1 Q8 / ruling Q8 ("one output-then-consume chain (load → store → typed path)"); AT-B100-12 (:581, :599).
- **Why:** at 9a the typed half never reads the store (G2 S5: `read_recent_sources` has 0 callers in `app.py`). The two halves are independent behaviours under one id, linked only by "the store still holds the entry".
- **Fix:** keep the single id, but write in the AT that the halves are independent at 9a and that the consume link (pick a recent) is 9b (LLR-173.4). Alternatively mint a typed-path AT for HLR-172a.

### A9-10 — LOW — classifier step (10) is self-declared dead and repeated downstream · route: proto (G2)

- **Where:** G2 `_typed_load_route` step (10): "This step is defence only: after (6) and (8) a plain direct child cannot fail it".
- **Why:** `_handle_load_project` runs `_project_folder_refusal` again on the same folder (`app.py:11679`) before any reset. The classifier copy adds a branch and three reason mappings that no test can reach.
- **Fix:** remove step (10). Step (11) still yields `unreadable` on a listing `OSError`.

### A9-11 — LOW — the C8 edits to the two tool scripts guard a path neither script reaches · route: ruling (optional)

- **Where:** ruling C8; G2 F-4; `tools/e13/run.py:125`; `docs/images/capture_readme_media.py:88`.
- **Fix:** prefer removing. Drop both script edits; they touch two non-test files for a call neither makes. If kept, record them in the packet as defence only, as G2 F-4 already does.

### A9-12 — LOW — stale text in E1 · route: req (E1 record)

- E1 §3 (line 125) says "13 test files" call `_handle_load_project`; the census at `4fef292` gives 20 (G2 F-1).
- E1 §1 lists LLR-172.1h's thread arm and LLR-172.5g's two-case threshold; refresh both after A9-4 and A9-8.

## E1 lines the pre-rulings (and this review) require

| Source | Requirement change |
|---|---|
| P9a-G1-2 (accepted) | new LLR-172.1k (unreadable store → unchanged), LLR-172.1l (unrecordable path → not recorded); HLR-172 decomposition (A9-1) |
| G2 P-1 (accepted) / A9-1 | LLR-172.1a and LLR-172.1b say "absolute path" (`abspath`), or LLR-172.1a states mapped drives are not recorded |
| P9a-G1-3 (accepted) | none if A9-5's removal is taken; else one ubiquitous line, "store file ≤ 65 536 bytes" |
| P9a-G1-5 (accepted) | LLR-172.4c statement gains "is a link or junction", plus 1 arm (A9-6) |
| G2 P-4 (accepted) | LLR-172.5g statement "after trailing dots and spaces are removed", plus the `temp.` arm (A9-8) |
| Absolute-only ruling | HLR-172a, LLR-172.5 … .5d say "absolute path"; new LLR-172.5h for a relative folder (A9-2) |
| P9a-G1-4 rejected | LLR-172.1h thread arm removed or weakened (A9-4) |
| P9a-G1-6 (accepted) | no requirement text; packet lists the `win32` arms, the G2 case arms included (A9-7) |

## Evidence checklist (architect)

- [✓] Constraints stated: two-file cap (realistic, see What holds); Windows-only store vs Linux CI (A9-7); UI-thread record (`app.py:12765`, `:7225-7227`).
- [✓] Alternatives where a real decision exists: `resolve()` vs `abspath` for the recorded path (A9-1); keep vs drop the byte cap (A9-5). The lister, store location and project route are settled by rulings Q1–Q9, C1–C8 (n/a — decided).
- [✓] Recommendation tied to constraints: each finding's Fix.
- [✓] Risks listed: mapped-drive loss (A9-1), undefined relative route (A9-2), double warning (A9-3), flaky thread arm (A9-4).
- [✓] Cost / latency: n/a beyond G2 R-4 (one ≤ 65 537-byte read and one write per outside load on the UI thread, estimated, not measured; E4 logs it once).
- [✓] Diagram: n/a — the flows are linear and the graphs' entity sequences already draw them.
- [✓] What would change the recommendation: an executed probe showing `Path.resolve()` keeps a mapped drive letter would remove the mapped-drive half of A9-1 (the requirement-line half stays).
- [✓] Two-layer requirements: AT-B100-12/13 and TC-B100-34 … 39 exist; A9-9 notes AT-B100-12's chain wording.

## Round 2

Narrow re-review against `E3-rulings.md` R1–R13. Read: `01-requirements.md` HLR-172 (:569), HLR-172a (:587), LLR-172.1 … .1m (:1668–:1808), .2c, .2e, .3, .4c (:1959), .5 … .5h (:1969–:2058), .6/.6a, TC index (:2880–:2887); LED .83 (`01-requirements-ledger.md:1085`); G1 `proto-9a-workspace.md`; G2 `proto-9a-app.md`; `interfaces-9a.md` §"Applied after E3 r1" (:88). Code at `4fef292`: `list_projects` (`app.py:12057-12087`), `resolve_input_path` (`workspace.py:2018-2034`), `painted_names` (`project_gather_service.py:965`, returns `str`), the load's own path logging (`app.py:12808`, so G2's warning holding the source path stays inside LLR-172.3 arm (2)'s log exemption).

### Verdict

**PASS-WITH-NOTES.** Both MAJORs are closed. Every MINOR and LOW is handled as ruled except a part of A9-12. The edits add no new MAJOR, only 3 LOW notes (A9R2-1 … A9R2-3).

### Status of the round-1 findings

| Id | Status | Evidence |
|---|---|---|
| A9-1 MAJOR | **closed** | LLR-172.1a :1678 now uses `abspath` and adds the junction arm plus the `resolve()` mutant. LLR-172.1b uses `normcase` after `abspath`. New LLR-172.1k (:1778) and LLR-172.1l (:1788) each carry a threshold and a negative control. HLR-172 :571 says "absolute path", and its decomposition names .1k/.1l as exceptions. G1 `record` steps (3)/(4)/(6) match the requirements, and G1 R-6 is closed. |
| A9-2 MAJOR | **closed** | HLR-172a and LLR-172.5 … .5d say "absolute path". New LLR-172.5h (:2049) has 3 arms and the `os.path.isabs` mutant. G2 step (0) runs `is_absolute()` on the stripped text. Step (1)'s claim that the fallbacks run only for a relative path holds (`workspace.py:2025`). G2 R-6 and F-5 are closed. |
| A9-3 MINOR | closed | G1 has no `_RECENT_LOCK` and logs only DEBUG lines. Its examples say "0 G1 warnings; G2 logs 1". S1–S10 mean the same thing in G1 :226-235 and G2 :253-262. |
| A9-4 MINOR | closed | The thread arm is gone from LLR-172.1h. A per-record read checks the whole-file property. |
| A9-5 MINOR | closed (R10: cap kept) | LLR-172.1m is one ubiquitous line, and its note holds the arithmetic. I re-ran it: 65 492 / 65 592 / 62 314 bytes, and 66 065 for the single unfit entry, so that arm holds. |
| A9-6 MINOR | closed | LLR-172.4c's statement now names "a link or junction" and adds the junction arm. |
| A9-7 MINOR | closed | .1b, .5, .5a, .5b, .5g and .5h mark their Windows-only arms with a reason. |
| A9-8 LOW | closed (superseded by R3) | The strip is dropped. `temp.` is refused because the listing match fails (.5b, .5g). |
| A9-9 LOW | closed | HLR-172a :599 describes two independent halves, and the consume link is 9b. |
| A9-10 LOW | closed | G2's old step (10) is removed. |
| A9-11 LOW | closed | The tool edits are dropped (G2 :245). |
| A9-12 LOW | **partial** | E1 :125 now says 20. The other stale E1 rows are listed under A9R2-1. |

### New findings

- **A9R2-1 — LOW — stale E1 rows.**
  - Where: `E1-scope.md` :32, :58, :70 and :117.
    - :32 still lists the 2×50-thread arm.
    - :58 describes .5g as "names a reserved home, 3 names".
    - :70 gives the TC-B100-38 range without .5h.
    - :117 says "refuses a reserved home, case-folded, before `_project_folder_refusal`". That is the opposite of R3's order.
  - Fix: refresh those rows, or put a "superseded by LED .83" banner on §1 and §3.
- **A9R2-2 — LOW — HLR-172 decomposition (:573) says "the two declared exceptions".** LLR-172.1m's third arm, one entry that cannot fit, leaves the source unrecorded, so it is a third exception. Fix: say "three", naming 1m's unfit-entry arm.
- **A9R2-3 — LOW — G2 entity sequence `repaint` (:215) still reads `Label(safe_text(name))`.** The node (:27) and S3 say `painted_names`. Fix: align :215.

Note, not a finding (security lane): G2 R-11 is an on-disk folder literally named `temp.`. It can only be made through `\?\`, the listing would show it, and a dialog pick of it opens `W\temp`. It is declared and not run.
