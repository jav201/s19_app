# Inc 11 E5: AT-B103-I11-2 and AT-B103-I11-3 rulings (orchestrator, 2026-11-08)

- **Real application coverage accepted.** Both tests drive `S19TuiApp` through the repository's `run_app`/`run_test`/Pilot harness and actual load actions. Assertions read the mounted A2L DataTable, GroupedIssuesPanel, Workspace Static and application log; parser dictionaries and direct validator calls are not used as acceptance evidence.
- **AT-B103-I11-2.** The image and RP-B28 A2L are loaded through `load_selected_file` and `load_a2l_from_path`. The Explorer has exactly one X row at `0x00001234`, Issues has no `A2L_DUPLICATE_SYMBOL`, and Workspace names X at `0x00001234`, never `0x00009999`.
- **AT-B103-I11-3.** V171 is loaded through `load_a2l_from_path`. The application log says `A2L loaded: ASAP2_Demo_V171.a2l`; Workspace contains `A2L Sections:` and `A2L Tags:` and no `A2L parse errors:` block.
- **RED base deviation accepted.** The brief named `e07fb00`, but that commit lacks Inc 2a's `a2l_definition.py`, which the test module imports. RED therefore ran on `10d01dc1`: `s19_app/tui/a2l.py` is byte-identical to `e07fb00` while `a2l_definition.py` exists. Both ATs execute and fail for the old reader behavior, not for an import or fixture failure (`at-i11-red-base-ruling.txt`, `at-i11-2-3-red-base.txt`).
- **Evidence.** RED 2 failed; current 2 passed; reader regression 183 passed; id/hygiene laws 79 passed. Transcripts are under `inc-11/evidence-e5/at-i11-*.txt`.
- **Coverage.** Both AT Tests and Coverage cells may change from `partial` to `full` / `covered`. No product file changed and no acceptance limitation remains.
- **Roles.** DeepSeek v4 Pro wrote and ran the tests. The orchestrator reviewed the observable chains and the RED-base deviation and owns the records and commit.
