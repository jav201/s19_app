# Inc 11 E5: reproduce product-review findings before any fix (DeepSeek)

Baseline `f4206433`, branch `b103-inc11-code`. You are an independent tester. Do not edit product code and do not commit.

Read `inc-11/E5-rulings.md` P1–P14, the relevant requirements in `01-requirements.md`, and the existing test helpers in `tests/test_b103_a2l_reader.py`. Create **one new file only**, `tests/test_b103_a2l_reader_e5.py`, reusing helpers rather than copying large fixtures. It must import nothing proprietary and use synthetic A2L text except for existing public fixtures.

For each P1–P14, write the smallest discriminating public-route test(s), with the requirement id in the docstring:

- P1 quoted CHARACTERISTIC/BLOB/INSTANCE numeric words give no number;
- P2 backslash + LF/CRLF/CR inside a quoted string cannot leak `/begin` or `/end`;
- P3 nested MODULE inheritance of valid and invalid BYTE_ORDER sources;
- P4 `/end` and `/begin` line identities when the section name is on a later line;
- P5 words after a multiline comment close get their actual line, not the comment-opening line;
- P6 quoted DISPLAY_IDENTIFIER/UNIT/conversion/symbol arguments retain boundaries and correct unquoting;
- P7 external-axis disagreement never reports `Line None`;
- P8 argument diagnostics name the argument's line;
- P9 unrelated invalid byte order/number does not suppress independent address or size disagreement errors;
- P10 every invalid BYTE_ORDER argument is diagnosed once, including duplicates;
- P11 a typedef's refused length cannot reappear as an INSTANCE length (explicit mismatch, duplicate mismatch, and NUMBER/MATRIX_DIM disagreement);
- P12 declared FNC_VALUES datatype wins over a misleading deposit name, with no fallback when the layout resolves;
- P13 CUBOID/CUBE_4/CUBE_5 layout-span disagreement is refused like CURVE/MAP;
- P14 READ.70: unclosed BLOB, unclosed INSTANCE, and an INSTANCE whose typedef is unclosed all give no address and no length;
- P15 a MAP with `LENGTH 0` and an inline STD_AXIS must keep length None and the size-disagreement error, never re-derive 13 from the inline span (mutant B M09).

Use the public parser and, where the case concerns the real write/definition path, its actual public consumer. Do not use private helpers merely to force a red. Do not edit requirements, the graph, other test files, or product code.

## Execution

On this PC run only `python -m py_compile tests/test_b103_a2l_reader_e5.py`. Run pytest only on the Linux runner with the absolute s19ci Python, `PYTHONDONTWRITEBYTECODE=1`, closed stdin and HOME/XDG/LOCALAPPDATA under `/tmp/b103-e5-11-product-red/zq_iso_user` (never a final component named `home`). Use a fresh full Git clone of `f4206433` and print `s19_app.__file__` first.

Run the new file on the unmodified baseline and save the complete transcript plus exit code to `inc-11/evidence-e5/product-findings-red.txt`. Each P finding must be classified: reproduced for the stated behavioral reason, already correct, or wrong test premise. Do not modify the product to make the reds pass and do not run the full integration or timing suite in this task.

Report the exact list of reproduced findings and any finding that did not reproduce. Do not add generic coverage tests; the coverage completion pass is separate. Do not push, merge, write the OS clipboard, or touch `~/work/b103-int11`.
