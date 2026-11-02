# Inc 9a — E5 corrective-pass notes

Scope: the rows marked **fix** in `E5-rulings.md` (code review CR9-*, security review SEC9-*, the 5 weak-test mutation survivors, the Linux CI failure). Worktree `<HOME>\Github\s19_app-b100-inc9a`, branch `b100-inc9a`, base `4fef292`, uncommitted. Author: `software-dev` sub-agent.

- **Source files touched:** `s19_app/tui/workspace.py` and `s19_app/tui/app.py`. That is 2 of the 2 allowed. CRLF line endings were kept.
- **Tests touched:** `tests/test_b100_recents.py` (LF, kept), `tests/conftest.py` (CRLF), `tests/test_b100_project_homes.py` (CRLF).
- **Assertions:** none was weakened. One test input was replaced (M19, see the table). The new input is stricter: the old file installed, the new one does not.
- **Requirements:** LLR-172.4d and LLR-172.2k were added to `01-requirements.md`. Each sits after its sibling (after LLR-172.4c and after LLR-172.2j). Each was also added to its HLR decomposition (HLR-172b, HLR-172) and to the §5.3 TC index (3 rows). The table rows escape `|` as `\|`.
- **Ledger:** one entry was added to `01-requirements-ledger.md`, LED-2026-10-26-batch-100.84. It names every id one by one. The Ledger line of each new requirement lists only LED .84. LED .84 was also appended to the Ledger lines of HLR-172 and HLR-172b, because their decomposition changed.

## 1 · Ruling row → change → proving node → mutant

T = `tests/test_b100_recents.py`. "pre-fix" means the worktree as E4 integration left it (`workspace.py` `a3342ed048ebe157`, `app.py` `6223201188232562`), copied to scratch before any edit. RED transcript: `evidence/inc-9a/red-02-corrective.txt`.

| Ruling row | What changed (final file:line) | Proving node(s) | RED (pre-fix) | Mutant |
|---|---|---|---|---|
| SEC9-1 (LLR-172.4d) | `workspace.py:2584-2585` skips a name with `entry.name != entry.name.rstrip(" .")` in `list_workarea_files`. The check runs before the reparse `lstat`, which Win32 would otherwise point at the aliased name. Docstring line `:2564-2565`. | T `test_tc_b100_37_lister_skips_a_name_ending_in_a_dot_or_space[a.s19.]`, `[b.s19 ]` (Windows-only, `\\?\`-made; T:1975) | RED 2/2: `['a.s19.', 'c.s19']`, `['b.s19 ', 'c.s19']` | `mut-c-SEC9-1`: skip removed → **KILLED** (2 failed, same lists) |
| SEC9-3 (LLR-172.2k) | `workspace.py:13` adds `import unicodedata`. `workspace.py:2232-2235` makes `_recent_entry_ok` refuse any of `<>:"\|?*` in `path[2:]` and any character of category Cf, Zl, Zp or Cs. The check sits after the drive-rooted check (so `path[0:2]` is the drive) and before the device check. Docstring line `:2204-2206`. One check serves the read and the record. | T `test_tc_b100_35_entry_with_a_win32_forbidden_character_is_dropped` (T:1600, all platforms); T `test_tc_b100_34_source_with_a_win32_forbidden_character_is_not_recorded` (T:1244, Windows-only, store write) | RED: 8 entries read; 7/7 records True | `mut-c-SEC9-3`: check removed → **KILLED** (2 failed) |
| SEC9-4 | Covered by SEC9-3: the `?` in `C:\??\C:\…` is refused, so the record returns False. | The `NT prefix \??\` key of the SEC9-3 record node | RED: `'NT prefix \\??\\': True` | covered by `mut-c-SEC9-3` |
| CR9-3 | `app.py:12828`: `_typed_load_route` takes the data / A2L decision from `normalized.suffix.lower()`, the spelling the loaders test, no longer from `PurePath(typed).suffix`. `typed` is still used for the inside test and the walk. `is_manifest` is unchanged (still `typed`; the ruling names the data / A2L decision only). | T `test_tc_b100_38_typed_unsupported_file_is_refused[fw.s19.]` (Windows-only; T:2405) | RED: `['Unsupported file type: ']` | `mut-c-CR9-3`: suffix from abspath → **KILLED** |
| CR9-4 | Docstring of T `test_tc_b100_34_record_with_an_embedded_nul_never_raises` (T:1314) now names `_recent_entry_ok`'s control-character check as the refusing arm. It records M28 as equivalent. The `except (ValueError, OSError)` in `record_recent_source` is kept. | — (docstring) | n/a — no behaviour | M28 equivalent (ruling) |
| CR9-10 | Docstring of T `test_tc_b100_37_unlistable_temp_shows_no_rows` (T:2131) now gives the base result recorded in `red-01-vs-base.txt`: `[temp removed]` and `[listing refused]` PASS at base, so M59 is their only RED. | — (docstring) | n/a | M59 (E4, KILLED) |
| CR9-6 | No source change. 4 monkeypatched arms in one parametrised node, each injecting `PermissionError` (an `OSError`): the route's walk `os.lstat` of `<W>\ab`; the route's `list_projects`; the route's `validate_project_files` (listed project `cd`, a data file, no `project.json`); `_handle_load_project`'s `list_projects`. Each asserts 0 raises, 0 project loads, 0 resets, and 1 line holding `could not be read` + `check that the folder can be opened, then load again`. | T `test_tc_b100_38_unreadable_folder_paints_could_not_be_read[4 arms]` (T:2649) | PASS pre-fix (the catches exist); declared | `mut-c-CR9-6a`…`6d`: each catch removed → **KILLED** 4/4 (`('PermissionError', [])`) |
| CR9-9 | `app.py:12125` gates the R14 skip with `os.name == "nt" and …`; comment `:12124`. | T `test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows` (T:2548). Natively on Windows, `fw-v1.` is not listed. With `app.py`'s `os` seen as `posix` (a proxy class `_OsAsPosix`, T:2538, scoped to `app_module` for one call), it is listed. On Linux the native half lists it. | RED: off-Windows half `['ab', 'fw-v1']` | `mut-c-CR9-9`: gate removed → **KILLED** |
| SEC9-5 (part) | `workspace.py:2508-2513`: `os.fdopen` is wrapped. When it raises, `os.close(fd)` runs and the error is re-raised, so the `finally` can unlink the staging file. `fsync` and the staging sweep → backlog (ruling). | T `test_tc_b100_34_failed_store_write_returns_false_and_keeps_the_store[staging open refused]` (T:1032; helper `_fail_staging_open` T:276) | RED: `['.recent_sou…tmp'] == []` (the open fd blocked the unlink) | none run. The pre-fix RED is the "fd not closed" mutant itself. |
| SEC9-7 | `tests/conftest.py:47-56` adds `_real_store_folder_names` (the name set of the real `%LOCALAPPDATA%\s19_app`, or None when absent). The session guard records it at start and asserts it unchanged at end (`:79`). It only reads. | Probe `scratchpad/e5fix/probes/probe_sec9_7.py` (in `red-02-corrective.txt`): folder created → pre-fix guard misses it, fixed guard catches it; staging file left → the same. | as left | n/a (a session-end guard; it cannot be RED inside one session) |
| CI `tc_b100_33[upper case]` | `tests/test_b100_project_homes.py:1207-1221`: the `upper case` arm is skipped unless `os.name == "nt"`, with the reason "needs a case-insensitive file system". | the node runs and passes on Windows (`green-04-targeted.txt`, 4 of 4) | n/a on Windows | not-run: the Linux half (no case-sensitive run here) |
| M57 | No source change. A new node makes `os.scandir` (in `workspace`) yield the temp entries in reverse, on `a.hex`, `B.s19`, `c.a2l`. It asserts the `(casefold, name)` order `[a.hex, B.s19, c.a2l]` and that the injection ran once. | T `test_tc_b100_37_lister_sorts_whatever_order_the_folder_yields` (T:1926) | PASS pre-fix (declared) | `mut-c-M57`: no sort → **KILLED** (`['c.a2l', 'B.s19', 'a.hex']`) |
| M19 | `bad.s19` is now `b"\xff\xfe\x00not records\x80\x81\r\n"`. `S19File` raises `UnicodeDecodeError` in both UTF-8 and cp1252 (probe `e5fix/probe_parse.py`), so nothing installs. The node now also asserts 1 `Load failed:` line, `current_file is None`, and the work copy in `temp/`. | T `test_tc_b100_34_source_that_copies_then_fails_to_parse_is_recorded` (T:865) | PASS pre-fix (declared) | `mut-c-M19`: record moved to `_apply_prepared_load` → **KILLED** (`[] == [(…bad.s19, 's19')]`) |
| M61, M64, M65 | No source change. Direct calls of `app._typed_load_route(Path(text))` assert the tuple: `<W>\AB` → `("project", "ab")`; `<W>\temp`, `<W>\temp::$INDEX_ALLOCATION` and the 8.3 name of `templates` → `("refuse", "not a project")`. | T `test_tc_b100_38_route_matches_the_typed_folder_against_the_listing[4 arms]` (T:2605) | PASS pre-fix (declared) | `mut-c-M61` → **KILLED** (`('project', 'AB')`); `mut-c-M64` → **KILLED** 2/2 (`('project', '…X_ALLOCATION')`, `('project', 'TEMPLA~1')`); `mut-c-M65` → **KILLED** (`('project', 'temp')`) |

How the mutants ran:

- **Copy:** `scratchpad/e5fix/mutwt`, a `tar` copy of the post-fix worktree minus `.git`, `.dev-flow` and `__pycache__`. Every transcript prints `s19_app.__file__` inside that copy. The worktree was never mutated.
- **Restore:** after each run the file was byte-restored and its sha256 compared. 13 of 13 printed `restored = True` (`workspace.py` `0af4b924…`, `app.py` `bbf04117…`).
- **Driver:** `scratchpad/e5fix/mut_driver.py`.
- **`LOCALAPPDATA`:** a fresh scratch folder for every run.
- **Result:** **13 KILLED / 0 SURVIVED.** Every kill is an `AssertionError` with a behavioural message, never an import or collection error.

## 2 · Runs

| Transcript | Content | Result |
|---|---|---|
| `evidence/inc-9a/red-02-corrective.txt` | 30 new or changed nodes, cwd = pre-fix copy, plus the SEC9-7 probe | 7 failed (all RED for the expected reason) / 23 passed (each declared) |
| `evidence/inc-9a/green-03-recents.txt` | `tests/test_b100_recents.py` in full, cwd = worktree | **157 passed**, 0 skipped, 0 failed, 251.6 s |
| `evidence/inc-9a/green-04-targeted.txt` | the new or changed arms outside `test_b100_recents.py`: `test_b100_project_homes.py::test_tc_b100_33_…` (4 arms), `test_b99_staging.py::test_tc_b99_13_…` (E4 re-pin), `test_id_registry.py` tc607 (scanned-file bound) and tc600–tc603 (id and citation registration) | **10 passed**, 0 failed, 14.1 s |

Touched-module run deferred to the batch-end battery by operator override (2026-10-31); failures found there get fix rounds.

(The 33-module `green-04-touched` run had been started; it was stopped at about 36 % on the override, with no failure printed up to that point. Its process was killed and its partial transcript deleted. No result from it is claimed.)
| `evidence/inc-9a/guards-02.txt` | the guards-01 command | **75 passed**, 29 snapshots passed, 0 failed, 129.4 s (same count as guards-01) |
| `evidence/inc-9a/mut-c-*.txt` | 13 kill checks | 13 KILLED |

## 3 · Final hashes

- `s19_app/tui/workspace.py` sha256[:16] = `0af4b92489233ff2`
- `s19_app/tui/app.py` sha256[:16] = `bbf04117fbf0d3f5`

## 4 · What I could not do, or did differently (plainly)

1. **Linux CI is not reproduced.** The CI fix (`tc_b100_33[upper case]`) and CR9-9's native Linux half were not run on Linux. CR9-9's off-Windows behaviour was shown only through the `os.name` proxy. State: `not-run` for the Linux halves.
2. **Lister and R14 now behave differently off Windows.** As ruled, SEC9-1's lister skip has **no** `os.name` gate. CR9-9 now gates R14's project-list skip. So on Linux, a project folder `fw-v1.` is listed, while a temp file `a.s19.` stays hidden. Both fail safe. This needs a ruling if the two rules should match.
3. **No dedicated mutant for SEC9-5.** The pre-fix RED (1 staging file left) is the "descriptor not closed" mutant.
4. **Threshold text of other LLRs was not updated.** My brief limited requirement edits to the two new ids. Arms were added under LLR-172.1d, .1i, .4a, .5, .5b and .5e without changing their threshold text. The LLR-172.5e text still says "3 of 3", while the node now has 4 arms (the `fw.s19.` arm is Windows-only). LED .84 lists these ids. A threshold touch-up is pending for the orchestrator.
5. **SEC9-7's guard has a residual.** It sees a net change only. A store, or the folder, created and then deleted inside the session still leaves no trace (probe case C). The reviewer named this case as well. Declared, not fixed.
6. **The pre-fix conftest was reconstructed.** For the SEC9-7 probe it was rebuilt by reversing the E5 edit, because the copy had already received the new conftest. Its sha `aa7f1b6f…` equals the pre-edit copy's hash, so it is byte-identical.
7. **E5 rows not handled.** The backlog and declare rows (CR9-1, CR9-2, CR9-5/SEC9-8, CR9-7, CR9-8, CR9-11, SEC9-2, SEC9-6, SEC9-5 `fsync`/sweep) were not written to `.dev-flow/BACKLOG-CODE.md` or to the packet's Risks. That is outside this pass's brief.
