# E5 fix pass — Inc 2a code

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code` (branch `b103-inc2a-code`).

**Rules:** `.dev-flow/2026-11-05-batch-103/inc-2/E4-handoff-impl-2a.md`, sections 1, 3 (unit A: only `s19_app/tui/a2l_definition.py`; unit B: only `tools/synth/make_release_case.py`, for CR-6), 4 and 5. **On this PC run only `python -m py_compile` and `codewire_extract.py`. Do not run pytest or any Python that imports or loads the module or `s19_app`.**

**Authority:** `inc-2/E5-rulings.md`, whole. The findings it rules: `inc-2/E5-code-review.md` (CR-1 … CR-11, column "Concrete fix") and `inc-2/E5-security.md` (E5S-01, -02, -04, -05, column "Fix"). Where this brief and a ruling disagree, the ruling wins; write the deviation down.

**Design:**
- `inc-2/codewire/graph-inc2.md` as the E5 fix pass records left it: the nodes `describe_definitions` (the iterative walk, the number writer, the 1,024-character bound), `_object_kind`, `_read_method_record` (`type_verdict`), `decode_definition`, `_read_stored_value` and `_table_value`.
- `inc-2/01-requirements.md`: the CTX placeholders and rows R-A2L-DEF.12, .58.2, .150 and .151 (the number rule).
- The cases in `inc-2/02-test-cases.md`: .12/4, .58.2/20 … /24, .150/10, .151/4 … /6.

The functions and lines to change (line numbers at HEAD `2f43d6d1`; the product files are as at `069171cd`, `a2l_definition.py` 1,428 lines):

**Unit A — `s19_app/tui/a2l_definition.py`**
1. **CR-1 = E5S-02**, `_table_value` `:1336-1339`. Replace `lo = i - 1` and the two lines of the `while` loop with `lo = bisect_left(xs, xs[i - 1])`: one bisect gives the first index of the run. `_first_equal_below` is unchanged. The docstring's "in O(log n)" (`:1322-1323`) is then true; keep it.
2. **The number rule** (CR-2 + E5S-01, E5S-03, CR-3; R-A2L-DEF.151). Add a private helper `_number_text(number: int, address: bool = False) -> str` right after `_fmt_address` (`:214-219`):
   - when `number.bit_length() <= 64` (magnitude at most 2^64 − 1): `_fmt_address(number)` if `address`, else `str(number)`;
   - else `_echo(_fmt_address(number))`: `0x` (`-0x`) and the upper-case hexadecimal digits, cut at 256 characters with `…`.

   Use it at every number placeholder of a message:
   - `_describe_one` `:564-565` (.7.2): `{byte_length}` → `{_number_text(byte_length)}`; `{_fmt_address(address)}` → `{_number_text(address, address=True)}`.
   - `:576` (.9): `{byte_length}` → `{_number_text(byte_length)}`. The span check already bounds it at 1,048,576; this keeps one home for the rule. Leave `{DATATYPE_SIZES[datatype]}` (`:577`) alone: it is a module constant, not a file number.
   - `_object_kind` `:710`: see item 4.
   - `_read_stored_value` `:1239-1240` (.26): `{missing}` and `{length}` through `_number_text`.

   No decimal text of a file number is left in a message. `_raw_text` (the `<raw>` of a display text, at most 8 bytes) is not a message number; leave it unchanged.
3. **CR-4 = E5S-05**, `_read_method_record` `:839-843`. Write `type_verdict = conversion_type if conversion_type in _SUPPORTED_CONVERSION_TYPES else None`, with no `.upper()`; a missing or empty word stays `None`. The readers at `:700`, `:708` (`_object_kind`), `:1179` (`decode_definition`'s `interpolate`), `:1415` and `:1420` (`display_text`) already compare exactly. Leave them, and add no case folding anywhere.
4. **CR-5, and the number rule for MATRIX_DIM**, `_object_kind` `:686-711`. Return the `<kind>` text already written as the message writes it:
   - `:704`: `return None, _echo(str(char_type))`;
   - `:710`: `return None, f"MATRIX_DIM {_number_text(matrix_dim)} MEASUREMENT"`;
   - `(none)` and the scalar kinds stay as they are.

   Update the docstring (`:687-692`). In `_describe_one` `:544-551`, drop the prefix test: `kind_echo` and the `if` at `:546-547` go, and the message writes `kind_text`.
5. **E5S-04**, the nested `_walk` of `describe_definitions` (`:350-362`). Make it iterative, with an explicit stack and the visit order of the recursion: a node, then its children in file order, before its next sibling. For example: `stack = list(reversed(roots))`; `while stack:` pop a node, run today's body, then `stack.extend(reversed(node.get("children") or []))`. The three maps keep `setdefault` (first in file order wins). No recursion may remain.
6. **CR-9**, `decode_definition` `:1155-1160` and `_read_stored_value` `:1212-1241`. Compute `name_echo` once in `decode_definition` (as now), call `_read_stored_value(definition, image, name_echo)`, and delete the second fallback at `:1232-1236`.
7. **CR-10**, docstrings:
   - `decode_definition` `:1136-1139`: a number goes through `_table_value` for a TAB form, through `_apply_compu_method` otherwise, and is the stored value for `NO_COMPU_METHOD`; a value that is not a number is refused `A2L-DEF-DECODE`.
   - `describe_definition` Args `:303-305`: the keys read are `sections`, `tags`, `record_layouts_by_name` and `compu_tabs_by_name`. `compu_methods_by_name` is built from `sections`, not read.
   - The new helper gets Summary / Args / Returns / Raises, per `PROJECT_RULES.md`.

**Unit B — `tools/synth/make_release_case.py`**
8. **CR-6**, `build_definition_objects` (`:977-1113`) and `emit_definitions_a2l` (`:1115-1205`):
   - add one constant `DEFINITIONS_ENUM_TEXTS = ("OFF", "IDLE", "RUN", "FAULT")` beside `DEFINITIONS_LONG_IDS` (`:960`);
   - emit the four COMPU_VTAB pairs (`:1174-1177`) from it, each line byte-identical to today's;
   - set `"planned_text": DEFINITIONS_ENUM_TEXTS[enum_raw]` at `:1058`.

   The definitions files of seed 20260001 stay byte-identical (raw 1 gives `IDLE`, as today). Case 08 (`generate`) is not touched.

**Not in this brief:**
- CR-7 and CR-11 are test changes and belong to the tester.
- CR-8 is a record-only note.
- E5S-06 goes to the backlog.
- E5S-07 needs no change.
- E5-3 changes the tests only.

**The tester owns these files; do not edit them:**
- `tests/test_b103_a2l_definition.py`:
  - the new cases .12/4, .58.2/20 … /24 (/24 parses and describes in fresh threads), .151/4 … /6, and .150/10's equality arm if the tester puts it there;
  - CR-7 (the P-2 checks of .149/5);
  - CR-11 (remove the 3-argument branch of `_method_record`, `:1689-1695`).
- `tests/test_b103_a2l_definition_perf.py`:
  - E5-3's measure in `_scaling` (`:193-222`) and in `_gp2_run`'s describe cases (`:400-441`; `_describe_first` goes away there, and the decode cases keep their measure);
  - .150/10.
- `tests/test_b103_synth_definitions.py`: CR-6's test (seeds 1 … 5). It has no case in the records yet.
- `tests/test_id_registry.py`, if the new test ids are registered there.

Implement exactly that, and keep every other behaviour. The behaviour tests of `tests/test_b103_a2l_definition.py` must stay GREEN, except the cases the new rows change on purpose; name those in the report (none is expected: every word and number of the fixtures is within the rule's bound, and 0 corpus methods use a type word in another letter case). Run the extractor on a throwaway copy, with the marks outside the worktree; it must exit 0. Save its transcript to `inc-2/evidence-e5/fix-extract.txt`. Do not commit: a tester edits tests in the same worktree.

**Report (≤ 150 words):** the changes (item, function, line), the line count of each file, the commands with their exit codes, and any deviations.
