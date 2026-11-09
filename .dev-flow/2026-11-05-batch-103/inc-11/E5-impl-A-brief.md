# Inc 11 E5: product correction pass A (Kimi)

Baseline `c4fe7e52`. You are the implementer, not the tester. Edit **only** `s19_app/tui/a2l.py`. Do not edit tests, requirements, records or any other file. Do not commit.

Read `inc-11/E5-rulings.md` P1–P8 and the corresponding tests in `tests/test_b103_a2l_reader_e5.py`. All 8 finding groups reproduce RED on the baseline. Correct only those behaviors with targeted edits; do not rewrite the module or change public payload shapes.

Required outcomes:

- **P1:** quoted numeric words stay distinguishable from unquoted numbers until `_number_word`; quoted CHARACTERISTIC/BLOB/INSTANCE addresses and sizes are not numbers.
- **P2:** the bounded quoted-word reader consumes backslash + LF/CRLF/CR without leaking structural words. Preserve the time/memory bounds; no per-character catastrophic regex.
- **P3:** a nested MODULE without its own BYTE_ORDER carries the enclosing source and invalid-source refusal instead of resetting to little.
- **P4:** `/end` spans and diagnostics use the `/end` word's line; the depth error uses the `/begin` word's line, not a later name line.
- **P5:** pending words flush at every non-string element boundary before the line advances, including multiline comments.
- **P6:** quoted keyword arguments retain boundaries and correct unquoting. Do not naively split canonical keyword items. Numeric/byte-order words retain quoted status for validation.
- **P7:** external-axis disagreement uses the section's local `start_line`, not `Line None`; do not add a public tag key.
- **P8:** argument diagnostics use the offending argument's line. Preserve that line through the same structured representation used for P6.

Keep interfaces compatible with the reference oracle and Inc 2a, but do not edit the oracle or tests to match a product regression. Follow existing docstring/type conventions. P15 and later P9–P14 are outside this pass; leave them alone unless a shared helper is unavoidable, and then explain it.

On this PC run only `python -m py_compile s19_app/tui/a2l.py`. Do not run pytest or other Python here. Do not push, merge, reset, write the OS clipboard or use proprietary A2L material. If a finding cannot be corrected without a broader design change, stop and report it rather than expanding scope.

Report each changed helper with file:line, the P id it addresses, and anything not completed. The orchestrator runs all RED tests on Linux and owns the next pass.
