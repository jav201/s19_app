# E5 gap pass 2 — Inc 2a code

Worktree `C:\Users\<user>\Github\s19_app-b103-inc2a-code` (branch `b103-inc2a-code`).

**Rules:** `.dev-flow/2026-11-05-batch-103/inc-2/E4-handoff-impl-2a.md`, sections 1, 3 (unit A: only `s19_app/tui/a2l_definition.py`), 4 and 5. **On this PC run only `python -m py_compile` and `codewire_extract.py`. Do not run pytest or any Python that imports or loads the module or `s19_app`.**

**Authority:** in `inc-2/E3-rulings.md`, the sections "Inc 2a E5 — gap pass 2 rulings", its round-6 addendum, and the "records done" rulings (P-2: the two private `Definition` fields are `field(compare=False, repr=False)`).

**Design:**
- `inc-2/codewire/graph-inc2.md` as committed at `e9b9feac`: the `_EnumForm` and `_TabForm` entities, `_echo`, `_table_value` (v2's two rules), the method record's derived keys, the name echo, and the fail-closed decode.
- `inc-2/01-requirements.md` rows R-A2L-DEF.149, .150, .151 and .58.2.
- The cases in `inc-2/02-test-cases.md`: .149/5–10, .150/1–9, .151/1–3, .58.2/18–19.

The functions to change (records report):
- `Definition`: add `_name_echo` and `_table_form`.
- New: `_echo`, `_EnumForm`, `_TabForm`, `_table_value`.
- `_read_method_record`: new signature, plus 5 derived keys.
- `_read_enum_table`: return the form with its index.
- `_describe_one`, including the name echo.
- The echoes at `_find_tag` and `_read_stored_value`.
- `decode_definition`: the table route and the non-number refusal.
- `_enum_entry_text` and `_enum_text`.

Implement exactly that, and keep every other behaviour: the behaviour tests of `tests/test_b103_a2l_definition.py` must stay GREEN, except the cases the new rows change on purpose. Name those cases in the report. Run the extractor on a throwaway copy, with the marks outside the worktree; it must exit 0. Save its transcript to `inc-2/evidence-e5/gap2-extract.txt`. Do not commit: a tester edits tests in the same worktree.

**Report (≤ 150 words):** the changes (function, line), the line count, the commands with their exit codes, and any deviations.
