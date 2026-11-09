# Inc 11 E5: product correction pass B (Kimi)

Start after pass A has landed and its RED tests have been re-run. You are the implementer, not the tester. Edit **only** `s19_app/tui/a2l.py`. Do not edit tests, requirements, records or any other file. Do not commit.

Read `inc-11/E5-rulings.md` P9–P15 and the corresponding tests in `tests/test_b103_a2l_reader_e5.py`. All these findings except P15 reproduce RED on the baseline. Correct only those behaviors with targeted edits and preserve pass A's changes.

Required outcomes:

- **P9:** address and size disagreement errors are diagnosed independently of unrelated invalid byte-order/number conditions before the combined refusal.
- **P10:** every invalid BYTE_ORDER argument is diagnosed once for READ.68, including repeated or valid-plus-invalid duplicates; existing source selection/refusal stays intact.
- **P11:** typedef refusal is final. `_tag_sizes` agreement/no-number gates apply before `_infer_length_characteristic` and INSTANCE MATRIX_DIM multiplication, so a refused typedef cannot acquire an INSTANCE length.
- **P12:** declared FNC_VALUES/layout datatype is resolved before deposit-name hints, consistently in agreement checks and inference. A misleading deposit name cannot override a resolvable layout.
- **P13:** CUBOID/CUBE_4/CUBE_5 use `_CURVE_MAP_FAMILY` consistently for inline/external span resolution and standing-size refusal, not only CURVE/MAP.
- **P14 READ.70:** an unclosed BLOB/INSTANCE gives no address and no length; an unclosed typedef cannot size an INSTANCE.
- **P15:** no product change is required; the direct MAP with LENGTH 0 and an inline STD_AXIS is already refused and kills mutant B M09. Preserve that behavior.

Keep public payload shapes and Inc 2a/reference-oracle contracts compatible. Do not re-derive a refused length later in any pass. Follow existing docstring/type conventions and do not rewrite the module.

On this PC run only `python -m py_compile s19_app/tui/a2l.py`. Do not run pytest or other Python here. Do not push, merge, reset, write the OS clipboard or use proprietary A2L material. If a finding cannot be corrected without a broader design change, stop and report it rather than expanding scope.

Report each changed helper with file:line, the P id it addresses, and anything not completed. The orchestrator runs all RED tests and integration on Linux.
