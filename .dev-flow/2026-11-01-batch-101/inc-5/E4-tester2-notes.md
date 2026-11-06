# Inc 5 - E4 tester 2 notes (Check Editor)

Files: `tests/test_b101_check_spec_keep.py` (new, 26 nodes) and the one approved body edit of `tests/test_b101_symbol_reads.py::test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` (name unchanged, E1 D-5). Evidence: `evidence/inc-5/red-01-tester2-base.txt` (one complete run on base `c2cba35`, LAN host 2, 27 nodes: 21 failed, 6 passed; exit 1). Evidence state: RED on base `executed`; GREEN on the implementation `not-run` (product files were still being edited; nothing ran on the Windows PC but py_compile).

## Tests per case (node names start with the case id)
All cases are `full` (driven through keys, the Load dialog, the Spec dropdown, space on ledger rows, buttons) except:
- R-CHKED-041.3/5 `partial`: a pick cannot reach two entries naming one parameter (E3 round 2 NOTE), so two items go through `CheckEditorPanel.load_spec`.
- R-CHKED-041.3/6 `partial`: items through the panel seam (E4 addendum 4); ledger set by `set_a2l_parameters`.
- Change of an image byte uses the Patch Editor path field, Load and Apply buttons (button `press()`, not a pilot click).
R-CHKED-010/1, 010/2, 010/3, 055/1, 054/1, 041.1/1, 041.2/1, 041.2/3, 041.3/1..6, 025/1..3, 026/1..4, 027/1, 027/2, 056/1..3 are in the new file; 041.2/2 is the re-pinned symbol-reads node.
Oracles: status log, the Check Editor's own painted Fields lines / memory table / ledger marks / Validate rows, the written `.chk.json`. Expected bytes from the independent S19 reader; names, addresses, sizes parsed from the generated A2L; planted moved / renamed / resized / twin / only-VALUE_0002 A2Ls written by the test from the generated one; address A taken from the generated image.
Shared waits (`wait_until`) before every state read; LOCALAPPDATA isolated by the suite's autouse fixture; no OS clipboard.

## RED on base (reason per node)
- Behavioural RED (21): 010/2, 010/3 (picks `[]` after reload), 055/1, 041.2/1, 041.2/3, 041.3/2, /3, /4, /5, /6 (nothing included: no name resolution), 025/2, 025/3 (picks `[]`), 026/1 (`0x0` = `93`), 026/2 (`Checks: 3 passed, 0 failed, 0 uncheckable`), 026/3 (`00 00 00 00`), 026/4, 027/2 (`3 field(s) outside the loaded image`, 0 entries), 056/1..3, symbol_reads 9 (`VALUE_0185` not included).
- Standing guards, pass on base, declared (6): 010/1 (batch-102 signature reuse), 054/1 (F-26 not reproduced), 041.1/1 (count only), 041.3/1 (no A2L: no resolution to prove), 025/1, 027/1.
- To keep 041.3/3, /4, /6 from passing vacuously, each carries a same-session positive control (a second spec/item that must include a parameter); that control is what is RED on base. 041.3/2 also asserts the other two entries are included.

## Findings
1. Deviations from case text (strengthening, not weakening): 041.3/2 asserts the included pair; 041.3/3, /4, /6 add a positive control; 027/1 adds an inside-image memory row so "left out" is selective.
2. Test-harness defects found and fixed in the first run: a typed `l` went into a focused text field (now `go_workspace` blurs focus); reload waits use the app's generation counters (`_a2l_view_generation`, `_image_generation`), because the same A2L reload yields no new identity observable otherwise.
3. Generated "VALUE_000n" are `VALUE` CHARACTERISTIC blocks (record layouts), not MEASUREMENTs; the planted A2Ls use that form. `symbol_reads` 9: the symbol entry's tag is `VALUE_0185` in the pilot case.
4. The named-parameter reference rule inside symbol_reads 9 is computed from the ledger (`_param_rows`) by the Definition; it is a reference of the requirement, not of the implementation.
5. Not run against the implementation: expect possible assertion mismatches (field order after demotion, 025/2 exclude/include timing, 056 memory-row order) to surface at GREEN; those would be test or product findings to triage then.
6. Known limitation (E1-D5, SEC5-4): the fast exclude-then-include race is not tested (025/2 awaits each toggle).
