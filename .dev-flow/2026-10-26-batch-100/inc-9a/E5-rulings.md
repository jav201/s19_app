# Inc 9a — E5 orchestrator rulings (code review CR9-*, security review SEC9-*)

Inputs: `review-increment-017.md` (PASS-WITH-NOTES, 0 HIGH / 0 MAJOR / 7 MINOR / 4 NIT), `security-increment-017.md` (PASS-WITH-NOTES, 0 HIGH / 0 MAJOR / 3 MINOR / 5 NIT), the mutation summary (survivors added below once the run ends). No HIGH or MAJOR is open, so the increment advances. One corrective pass handles the rows marked **fix**. The rows marked **backlog** go to `.dev-flow/BACKLOG-CODE.md`, and the rows marked **declare** go to the packet's Risks.

Rule applied (skill E3): prefer removing a feature over guarding it; fix now when the fix is one condition in a function 9a already owns.

| Finding | Tag | Ruling | Where |
|---|---|---|---|
| SEC9-1 lister shows names ending in a dot or space | design-gap | **fix** — `list_workarea_files` skips a name with `name != name.rstrip(" .")` (same rule as R14). New requirement LLR-172.4d (Unwanted form) + test arms `a.s19.` / `b.s19 ` (Windows-only, made through `\\?\`). | workspace.py |
| SEC9-3 store read accepts ADS / device / bidi / surrogate entries | design-gap | **fix** — `_recent_entry_ok` refuses any of `<>:"|?*` after the 2-character drive prefix, and any character of Unicode category Cf, Zl, Zp or Cs. One check serves both the record (LLR-172.1l) and the read. New requirement LLR-172.2k (Unwanted form) + read and record test arms (`a:b.s19`, `CON:.s19`, `a::$DATA.s19`, U+202E, U+2028, U+DC80). | workspace.py |
| SEC9-4 `\??\` typed path recorded as `C:\??\C:\…` | impl | **fix** — covered by SEC9-3 (the `?` is refused, so the record returns False and the load logs its 1 warning). One record arm for `\??\`. | workspace.py |
| CR9-3 route decided from the abspath suffix (trailing dot dropped) | impl | **fix** — `_typed_load_route` takes the data / A2L decision from the suffix of the text the loader receives (`normalized`), so `fw.s19.` gets the LLR-172.5e unsupported-type line. Test arm `fw.s19.`. | app.py |
| CR9-4 NUL test says abspath refuses; M28 cannot be killed | impl (test) | **fix** — correct the docstring of `tc_b100_34_record_with_an_embedded_nul_never_raises` to name `_recent_entry_ok` as the refusing arm. M28 is recorded as an equivalent mutant (the `ValueError` arm is unreachable on Windows / Python 3.11), not as a weak test. Keep the `except` (it is the "never raises" guard on other platforms). | tests |
| CR9-10 docstring says `[listing refused]` RED on base, but it passed | impl (test) | **fix** — correct the docstring to the base result recorded in `red-01-vs-base.txt`. | tests |
| CR9-6 four `OSError → could not be read` arms untested | impl (test) | **fix** — add monkeypatched arms for: the walk, `list_projects` (both call sites), `validate_project_files`. Each asserts 1 status line containing "could not be read" and no exception. | tests |
| CR9-9 R14 skip runs on Linux | impl | **fix** — guard the R14 skip with `os.name == "nt"` (Win32 is the only platform that strips the trailing dot or space). The R14 test arms are already Windows-only. | app.py |
| SEC9-5 (part) file descriptor leak if `fdopen` fails | impl | **fix** — close the `mkstemp` descriptor when `os.fdopen` raises. `fsync` and leftover staging cleanup → **backlog** (the store is a convenience list; a lost update is acceptable). | workspace.py |
| SEC9-7 conftest guard hashes only the store file | impl (test) | **fix** — the session guard also records whether `%LOCALAPPDATA%\s19_app` exists, and the set of names in it, at session start, and fails if either changed at session end. | tests |
| CI tc_b100_33[upper case] fails on Linux | impl (test, Inc 8b) | **fix** — skip the `upper case` arm unless `os.name == "nt"` (a case-insensitive filesystem is the precondition). | tests |
| CR9-1 relative fallback path reaches the record already resolved | design-gap | **backlog → Inc 9b** (9b reads and reopens the store; decide there whether a fallback-resolved source is recorded at all). | — |
| CR9-2 8.3 spelling of the work area refuses a listed project's long path | design-gap | **declare** in Risks next to R-9 (`\\?\`); fails closed. **backlog → Inc 12a** for a normcase+`GetLongPathName` comparison. | — |
| CR9-5 / SEC9-8 reparse-attribute files (OneDrive placeholders) hidden | design-gap | **declare** in Risks (fails safe: 0 rows, no wrong file loaded). **backlog → Inc 12a**: tell a name-surrogate link from a cloud placeholder by reparse tag. | — |
| CR9-7 refusal lines and listing-match written twice / three times | impl | **backlog → Inc 12a** (refactor; out of a corrective pass). | — |
| CR9-8 relative text with a NUL raises in `_typed_load_route` | impl (pre-existing) | **backlog → Inc 12a**. | — |
| CR9-11 one-lister census misses a literal `"temp"` | impl (test) | **backlog → Inc 9b** (where the dialog's files section lands; widen the census there). | — |
| SEC9-2 pick-time recheck of a listed file | design-gap (pre-existing code) | **backlog → Inc 12a**, merged with the open SEC TOCTOU row. | — |
| SEC9-6 check-then-open on the store | design-gap | **declare** (same-user only, accepted at E3). | — |

Requirements added by this ruling (E1 discipline: one EARS sentence, numeric threshold, negative control; ledger entry names each id one by one):
- LLR-172.4d — If a regular file in the temp folder has a name that ends in a dot or a space, then the system shall leave that file out of the Workarea Files list. Threshold: `a.s19.` and `b.s19 ` present → 0 rows naming either, the regular file `c.s19` → 1 row. Negative control: the skip removed → 2 extra rows.
- LLR-172.2k — If a store entry's path holds any of `<>:"|?*` after its drive prefix, or a character of Unicode category Cf, Zl, Zp or Cs, then the system shall drop that entry when it reads the store and refuse to record that path. Threshold: 6 such entries among 2 valid → read yields the 2 valid in order; record of each → False, store bytes unchanged. Negative control: the check removed → 8 entries read.

## Mutation survivors (`evidence/inc-9a/mutation-summary.md`: 70 KILLED / 9 SURVIVED / 0 INVALID of 79; DeepSeek v4 Pro)

| Mutant | Ruling |
|---|---|
| M24, M28, M42 | **equivalent** — an inner `except` removed is caught by the outer never-raise guard with the same result (False / "could not be read"). Recorded as equivalent; no test change. (M28 matches CR9-4.) |
| M21 | **equivalent under test** — the write-side link check after `mkdir` is masked by the read-side check of `store.parent`; it remains as a race guard (folder created as a link between the read and the `mkdir`). Declared; no test change. |
| M57 | **fix (test)** — `os.scandir` returns NTFS order, which already matches the sort. Add an arm that monkeypatches `os.scandir` (in `workspace`) to yield entries in reverse order and asserts the `(casefold, name)` order. |
| M19 | **fix (test)** — the "failed load records nothing" arm uses `bad.s19`, which installs with 2 errors. Replace it with a source the loader does not install (find one in `examples/` or build bytes that make the load refuse; prove it leaves `current_file` unchanged). |
| M61, M64, M65 | **fix (test)** — the route's own listing match / reserved-home step / on-disk name are masked by `_handle_load_project`'s second check (defence in depth, kept). Add direct arms that call `app._typed_load_route(text)` and assert the returned tuple (the on-disk name for a case-different spelling; refusal for a reserved home and for an unlisted name). |

## Addendum after the corrective pass (orchestrator)

- The lister skip (LLR-172.4d) has no `os.name` gate, while the R14 project-list skip now has one (CR9-9). **Ruling: declare and backlog → Inc 12a** (unify both skips behind one helper with the same platform rule). On Linux a regular file named `x.s19.` is left out of the Workarea Files list; low impact, and it fails safe.
- Five existing LLRs (LLR-172.5e and siblings) gained test arms without a threshold-text change. Their threshold sentences still hold (the arms are extra cases of the same count). No change.
- Re-review: no HIGH or MAJOR was open after the reviews, so nothing was blocking. The narrow re-review is satisfied by the corrective pass's RED/GREEN/mutant evidence (`red-02-corrective.txt`, `green-03-recents.txt`, `mut-c-*.txt`).
