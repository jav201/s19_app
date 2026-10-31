# Inc 9a — E3 round 1 rulings (orchestrator)

Inputs: `E3-architect.md` (FAIL, A9-1/A9-2 MAJOR, 5 MINOR, 5 LOW) and `E3-security.md` (FAIL, S9-1 MAJOR, 2 MINOR, 3 LOW). Prefer removing a feature over guarding it.

| Id | Finding | Ruling |
|---|---|---|
| R1 | A9-1 MAJOR — `resolve()` turns a mapped drive into UNC, refused; P9a-G1-2 unstated | Record **`os.path.abspath`**, de-dup on `normcase(abspath)`; G2 P-1 is **revoked**. Add **LLR-172.1k** (If the store could not be read, then the system shall leave it unchanged) and **LLR-172.1l** (If the read would drop the new entry, then the system shall not record it), each with threshold + negative control. HLR-172 and LLR-172.1j text aligned. |
| R2 | A9-2 MAJOR — absolute-only route not written | HLR-172a, LLR-172.5–.5d say "absolute path"; add **LLR-172.5h** (If a relative typed path names a folder, then `not a supported file` + `check the path`). G2 gets step 0 `is_absolute()`. "Absolute" = `Path.is_absolute()` on Windows (drive + root); the base-folder fallback never runs for the project route (closes S9-6). |
| R3 | S9-1 MAJOR — `temp::$INDEX_ALLOCATION`, 8.3 `TEMPLA~1` reach reserved homes | **Name matching by listing, not by spelling.** The typed route takes the parent = this work area (lexical, no resolve) and routes only when the typed final component equals (Windows: `normcase`) the name of an entry from one `os.scandir(W)` that `list_projects` lists; it passes the **on-disk entry name**. `_handle_load_project` applies the same rule: a name that `list_projects` does not list is refused (`not a project` + `pick a project in the list`). The fix pass verifies at 4fef292 that `list_projects` excludes every reserved home; if it does not, the reserved case-fold check stays as an extra arm. The trailing-dot/space strip of P-4 is **dropped** (superseded: `temp.` matches no entry). LLR-172.5b/.5g restated on this rule with arms `temp::$INDEX_ALLOCATION`, `TEMPLA~1`, `temp.`, `TEMP` → 0 loads. |
| R4 | S9-2 MINOR — surrogate/bidi passes `safe_text` | Workarea Files labels use `painted_names` (8b gather service, `PAINTED_NAME_LIMIT`); `item.data` keeps the on-disk name. LLR-172.6/.6a arms updated. |
| R5 | S9-3 MINOR — drive-rooted regex accepts a relative path off Windows | `recent_store_path` requires `^[A-Za-z]:[\/]` on every platform; otherwise `None`. |
| R6 | S9-4 LOW — reader opens the store without a link check | Reader returns `problem="could not be read"` for a link store file or folder; 0 bytes read. |
| R7 | S9-5 LOW — `mkdir(parents=True)` | Create only `s19_app` under an existing `LOCALAPPDATA` (`parents=False`); a missing `LOCALAPPDATA` folder → no write. |
| R8 | A9 MINOR — G1 still draws the rejected lock and its own warnings; S7/S8 ids collide | Remove lock and warnings from G1; renumber seams so each id means one thing in both graphs. |
| R9 | A9 MINOR — LLR-172.1h 2×50-thread arm flaky without a lock | Drop the thread arm (all writes run on the UI thread); keep the whole-file arm (`mkstemp` + `os.replace`: a reader sees the old or the new file, 0 partial). |
| R10 | A9 MINOR — the byte cap guards an unreachable case | Drop the cap **if** the reader's per-entry length bound × 20 entries, JSON-escaped, plus overhead ≤ 65 536 bytes (the fix pass computes it from LLR-172.2*'s actual bound and writes the arithmetic into the requirement's note); otherwise keep the cap as an LLR. With R1's LLR-172.1l, the writer never stores what the reader drops. |
| R11 | A9 MINOR — `temp`-is-a-link arm belongs in LLR-172.4c | Move it into LLR-172.4c's statement/threshold. |
| R12 | A9 MINOR — Linux CI cannot pass case-spelling arms | Windows-only skips with a named reason, declared in the packet (as P9a-G1-6). |
| R13 | LOWs — trailing-dot wording; AT-B100-12 "chain"; dead classifier step; C8 tool edits; "13 test files" | Fix in passing: wording follows R3; AT-B100-12 described as two halves; remove the dead step; **drop the tool edits** (neither tool reaches a record) — the autouse `tests/conftest.py` fixture stays; correct to 20 test files. |

## E3 round 2 — PDR approved (architect PASS-WITH-NOTES, security PASS). Addenda for E4

| Id | Addendum |
|---|---|
| R14 | S9R2-1 LOW: `list_projects` skips a folder whose on-disk name ends in a dot or a space (Win32 opens `temp.` as `temp`). G2 owns it; the tester adds one arm (create the folder with a `\?\` path; Windows-only skip off Windows). |
| R15 | A9R2-1 LOW: `E1-scope.md` rows 32, 58, 70, 117 are stale; the graphs and `01-requirements.md` are the specification for E4. Orchestrator corrects E1-scope at close. |
| R16 | A9R2-2 LOW: HLR-172's "two declared exceptions" — LLR-172.1m's entry-that-cannot-fit arm is a third; the close pass aligns the HLR text. Implementers follow LLR-172.1m. |
| R17 | A9R2-3 LOW: G2 `repaint` entity reads `painted_names`, not `safe_text` (R4 governs). |
