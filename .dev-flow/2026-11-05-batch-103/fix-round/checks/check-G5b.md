# check-G5b — verdict: GO

| # | Check | Evidence |
|---|---|---|
| 1 | Diff hygiene | files=2 (tests/test_b97_check_editor.py, tests/test_changes_symbol_entries.py) = allowed list; CR=0; skipadd=0; sleepadd=0; no test def removed. Saved: diffs/G5b.diff |
| 2 | Intent | Row 1: Drifty-210 re-pinned VALUE/"drifts" -> UNRESOLVED/"without an address", still refused (R-A2L-READ.61), as ordered. Row 2: hostile name swapped to a local comment-free name; assertions unchanged (literal markup, no control chars). b97_fixtures.py untouched (not in allowed list). |
| 3 | GREEN | 3 nodes -n 0: 10 passed (parametrised). Both files -n 4: 82 passed (base: 3 failed, 79 passed; same 82 total). No new RED. |
| 4 | Negative controls | Re-applied both mutations (a2l.py:3777 `or not agree` dropped; a2l_parameter_picker.py:233 Text.from_markup): 3 failed, 7 passed; RED on CHG-SYMBOL-VALUE == UNRESOLVED and on 'b97[bold]x[/]y' missing from ledger. |
| 5 | Laws | 3 failed / 112 passed / 2 skipped = exactly the base set (r_tst_070_2, canon two-shall, address census). All allowed base-red; no other law RED. |
| 6 | Worker claims | Verified: file list/stat, CR=0, 82 passed, 3 nodes green, both mutation lines and RED text, `//` diagnosis. No false claim found. |

## Extra point: `//` diagnosis — CONFIRMED
One run of `parse_a2l_file(hostile_a2l(tmp))` on the base fixture: HOSTILE_CONTENT = `b97[bold]x[/]y[red]z[link=https://e.invalid]l[/link][@click=app.quit]q\x07`; the tag name read = `b97[bold]x[/]y[red]z[link=https:` (cut at `//`). Hostility preserved in HOSTILE_PARAM_NAME: control char \x07, markup ([bold], [red]), link tag `[link=e.invalid]`, click action `[@click=app.quit]` all kept. Lost: only the URL scheme `https://` (the `//`), so the "link target with //" variant is no longer exercised by these two nodes.
Notes: HOSTILE_CONTENT in b97_fixtures.py still carries `//` (P-057 open); copy dirs deleted.
