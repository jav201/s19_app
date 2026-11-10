# E4 handoff — Inc 2b independent tester

Role: write the 2b tests from the corrected requirements, cases and graph. Do not write product code and do not communicate with the implementer.

Worktree: `C:\Users\<user>\Github\s19_app-b103-inc2b-tests`, branch `b103-inc2b-tests` (created by the orchestrator after E3 closes). Own only `tests/test_b103_a2l_definition.py`, `tests/test_b103_synth_definitions.py`, `tests/test_b103_a2l_definition_perf.py` if a timing oracle genuinely needs adjustment, and the Tests / Coverage / Result columns of `inc-2/02-test-cases.md`. Do not add test files or edit the id registry. Do not edit requirements, graph, source or steps.log. Do not commit or push.

Read corrected `inc-2/02-test-cases.md`, `01-requirements.md`, `codewire/graph-inc2.md`, `E3-rulings.md` final section and existing test helpers. Cover every 2b case and every waiting encode arm, including mixed 2a cases, AT-B103-I2-1 and AT-B103-I2-2. Re-derive V171 overlap names through the current parser, never from the old census text. AT-I2-1 applies only UNKNOWN; its other nine objects refuse overlap. The `.43/.44/.45` V171 cases first assert overlap and then clear `shared_with` only as a test device.

Use exact expected bytes, codes and messages from the requirements. Test through public I-2 names wherever possible. Cover BLOB, sized/unsized INSTANCE, unknown-length addresses, CLEAN masks, duplicate names, duplicate BIT_MASK/BYTE_ORDER, parse errors and their order, operator echo cap, text overlap, immutability and both acceptance round trips. Extend the existing `.58.1` immutability checks to `shared_with`. No vacuous assertions: every negative control must identify an observable wrong result.

Run no pytest or import of `s19_app` on Windows. Use the Linux runner with `python -I -B`, isolated HOME/XDG/LOCALAPPDATA, closed stdin, `PYTHONDONTWRITEBYTECODE=1`, and print `s19_app.__file__` at the start of every transcript. Save transcripts under `inc-2/evidence-e4/`.

First prove RED on the committed 2b base. Collection RED from the missing public API is necessary but insufficient: also use a runner-only behavioural stub that leaves every expected result wrong, never in either worktree, and record per-arm RED rather than one aggregate exit code. Do not mutate the real tree. Report each test file, full/partial counts, RED nodes and reasons, commands and exit codes, and anything not run in at most 300 words.
