# Spec — `tools/modularize/move.py` (the mover)

Audience: an implementer with no other context. Read `design/interfaces.md` (I-1..I-7) first;
this spec does not restate the rules, it says how to apply them. Python ≥ 3.12 (AST positions
inside f-strings are exact from 3.12). Standard library only. Requirements: R-MOD.1, R-MOD.2,
R-MOD.5.x, R-MOD.6.x, R-MOD.7.1, R-MOD.9, R-MOD.10, R-MOD.11, R-MOD.13, R-MOD.15, R-MOD.16.x.

## Command

```
python -I tools/modularize/move.py --repo <tree> --rev <base> --map <module-map.json> [--dry-run]
```

- `<tree>`: a git work tree (a scratch clone, never the operator's checkout). The mover reads
  the two old modules with `git -C <tree> show <rev>:<path>` (not from the work tree file), writes
  the new package files into `<tree>`, then deletes `<tree>/s19_app/tui/app.py` and
  `<tree>/s19_app/tui/screens_directionb.py`.
- `--dry-run`: do everything except writing/deleting; print the same summary.
- Exit 0 only after the acceptance self-check (below) passes.

## Inputs

- `module-map.json` (from `plan_map.py`): `base`; per package `top[]` (key, kind, names, span,
  module), `d1_names`, `deps_defined`, `reexports`; app also `methods[]` (name, line, span,
  module), `class_statements[]` (span, module = core), `mixin_order`, `class_header`.
  Spans are 1-based inclusive line ranges of the base file that already include each unit's
  leading comments and blank lines (span start = previous sibling's end + 1).
- The map's `base` must equal `<rev>` resolved to a commit or the map's base string
  (`git rev-parse` both; compare full shas). Mismatch → error E1.

## Algorithm

### 1. Load and re-derive
1. Read base text of each old module; `lines = text.splitlines(keepends=True)`.
2. `tree = ast.parse(text)`; `st = symtable.symtable(text, path, "exec")`.
3. Recompute units with `plan_map.top_units` and `plan_map.method_units` (import them from
   `tools/modularize/plan_map.py`; do not re-implement spans). Every unit's span must equal the
   map's span for the same key/name and line → else E2 (stale map).
4. Coverage: every top unit key and every method/class-statement of `S19TuiApp` appears in the
   map exactly once with one module → else E3 (missing) / E4 (duplicate). Every module named
   must be in the allowed set (app: `__init__`-excluded set `{core, deps, shared, shared_io}` ∪
   `mixin_order`; top units with module `imports` are the import statements; sdb:
   `{__init__, deps, shared, map_parts, memory_map, loaded_artifacts, patch_editor,
   check_editor, ab_diff, imports}`) → else E5.

### 2. Safety checks before any rewrite
- E6: a D1 name is bound in any non-module scope (symtable `is_local`, `is_parameter`,
  `is_free`, `is_nonlocal`, `is_declared_global`) — the rewrite would be ambiguous.
- E7: a method assigned to a mixin loads the name `S19TuiApp` outside an annotation.
- E8: a method assigned to a mixin has a decorator whose source is `on(...)` / `textual.on(...)`.
- E9: a method assigned to a mixin contains a zero-argument `super()` call.
- E10: a method assigned to a mixin is named `_on_X` or `on_X` while the other spelling of the
  same handler is assigned to a different class (`_on_X` and `on_X` must share a class).
- E11: two units assigned to `S19TuiApp` ∪ mixins bind the same name, except the property
  group (`@property` getter followed by `@<name>.setter`/`.deleter`) which must map to one module.

### 3. Text rewrites (per unit, on the unit's span lines only)
Collect edits as `(line, col_start_char, col_end_char, new_text)`; apply per line right-to-left.

**Column conversion (mandatory):** `ast` `col_offset`/`end_col_offset` are UTF-8 *byte*
offsets. Convert with `len(line_bytes[:col].decode("utf-8"))` on that physical line. The base
files contain non-ASCII characters (`—`, `·`, `→`) in strings and comments; byte offsets used as
character offsets corrupt those lines.

a. **D1 rewrite** (skip for units whose module is `deps`): for every `ast.Name` in the unit with
   `id in d1_names`, `isinstance(ctx, ast.Load)`, not inside an annotation subtree
   (`arg.annotation`, `FunctionDef.returns`, `AnnAssign.annotation`), and global per symtable for
   the innermost enclosing scope → replace `[col_offset, end_col_offset)` with `deps.<id>`.
   Name nodes spanning lines do not exist; assert `lineno == end_lineno`.
b. **Relative imports**: for every `ast.ImportFrom` in the unit with `level ≥ 1` → on its first
   line, from `col_offset`, match `from\s+(\.+)` and insert one `.` (level + 1).
c. **CSS_PATH** (app core only): the class statement `CSS_PATH = 'styles.tcss'` →
   replace the string literal token with `"../styles.tcss"`. Assert exactly one such statement.

Record every edit in a list `edits[module].append({kind, unit, line, before, after})`.

### 4. Generated imports (per new module, deterministic)
For module M with units U:
1. `used` = every `ast.Name` Load id in U **after** rewrite semantics (i.e. D1 Loads outside
   annotations count as `deps`, not as the name), plus names in decorators, defaults, bases,
   annotations.
2. Remove: names bound at module level by U itself; Python builtins (`dir(builtins)`) that no
   old top-level statement binds; `deps`.
3. For each remaining name, the source is, in priority:
   - the old module's top-level import statement that binds it → emit that statement reduced to
     the used aliases, same form (`import os`, `import a.b as c`, `from X import n as m`), relative
     level + 1. Statements stay in old source order; one statement per old statement.
   - the old sdb `if TYPE_CHECKING:` block → emit `from typing import TYPE_CHECKING` (if not
     already imported) and `if TYPE_CHECKING:` + the reduced statement, level + 1.
   - a package home module from the map (`module` of the unit that binds it) →
     `from .<home> import (<names sorted by old source line>)`. Homes in map module order.
   - anything else → E12 (unresolvable name), listing module and name.
4. If M has any D1 rewrite → `from . import deps` after the external imports.
5. A name a mixin would import from `core` → E13 (forbidden direction; I-1).
6. Wrap long `from` imports in parenthesised one-name-per-line form when > 99 chars.
7. **deps carries every imported D1 name (I-3 item 2; review F1, 2026-11-13).** For `deps.py`, `used` additionally
   includes every D1 name that the old module binds by a top-level import (`n in import_by_name`), whether or not a
   deps-homed unit uses it, because other modules load it as `deps.<n>`. Builtins (e.g. `open`) are not added.
8. **String annotations (review F5).** Names inside string-constant annotations (`Optional["LoadedFile"]`, parsed with
   `ast.parse(s, mode="eval")`) count as `used` for the `if TYPE_CHECKING:` source only: a name bound only in the old
   `if TYPE_CHECKING:` block and mentioned only in a string annotation is emitted in that module's own
   `if TYPE_CHECKING:` block.

### 5. Emit files
Header for every file except `__init__.py`:
```
"""<package>.<module> — <role> (moved verbatim from <old path> at <base short sha>)."""
from __future__ import annotations

<generated imports>
```
`<role>`: `S19TuiApp core`, `S19TuiApp mixin: <module>`, `test seam (D1)`, `shared helpers`,
`shared helpers that read the D1 seam`, `<ClassName>` for an sdb panel module.

Body:
- top units of M, original order, each unit's span text after rewrites, separated exactly as in
  the base (spans already carry their blank lines). Strip leading blank lines of the first unit
  and normalise to two blank lines before each top-level `def`/`class` that follows another unit.
- Mixin modules: after the top units, two blank lines, `class <Name>Mixin:`, then the method
  units of M in base order (their spans are already indented 4 spaces).
- `core.py`: core top units (old order), then the leading comment lines of the old
  `S19TuiApp` top unit (span start … class line − 1), the I-4 header line, then every
  class-body unit mapped to core in base order (docstring, statements, methods), then `main`.
- Trailing: exactly one newline at EOF.

`__init__.py`: docstring (sdb: old module docstring verbatim; app: generated one line),
`from __future__ import annotations`, the old import statements that bind any re-exported
name (level + 1, reduced to re-exported aliases, old order, the `TYPE_CHECKING` block omitted),
then `from .<home> import (<names>)` per home in map order covering every remaining name of
`reexports`. Every name of `reexports` is bound exactly once.

Delete the two old files. Write files with `newline="\n"`, UTF-8, no BOM.

### 6. Determinism
No set/dict iteration without sorting by base line; no timestamps; two runs give identical
bytes (R-MOD.15).

## Acceptance self-check (printed, then exit code)

After writing (or in `--dry-run`, on the in-memory texts):
1. Every new file parses (`ast.parse`) → else E14.
2. For each package, a fresh subprocess per new module: `python -I -c "import <dotted>"` with
   `cwd=<tree>` and `PYTHONPATH=<tree>` → all exit 0 (R-MOD.6.1).
3. Static internal import graph acyclic (R-MOD.6.2) and direction rule holds (R-MOD.6.3).
4. `python -I -c "import <pkg>; [getattr(<pkg>, n) for n in <reexports>]"` → 0 missing
   (R-MOD.1 / R-MOD.2).
5. Physical line count per file ≤ cap (R-MOD.5).

Print exactly:
```
MOVE base=<sha> app_files=<n> sdb_files=<n> units=<n> d1_rewrites=<n> relimport_rewrites=<n> css_rewrites=1
MOVE imports_fresh=<ok>/<total> cycles=0 reexports_missing=0 caps_over=0
MOVE OK
```
On any failure print `MOVE FAIL E<k>: <detail>` lines and exit 1 (2 for usage errors).
Write `edits` as `<tree>/.modularize/move-edits.json` (sorted) for the verifier's report.

## Error cases (each exits 1, writes nothing — R-MOD.16)

| Code | Condition |
|---|---|
| E1 | map base ≠ `--rev` |
| E2 | a recomputed span differs from the map (stale map) |
| E3 / E4 | a unit missing from / duplicated in the map |
| E5 | unknown target module |
| E6 | D1 name bound in a non-module scope |
| E7 | runtime `S19TuiApp` reference in a mixin |
| E8 | `@on` handler mapped to a mixin |
| E9 | zero-argument `super()` in a mixin method |
| E10 | `_on_X` / `on_X` split across classes |
| E11 | name bound in two classes of the app |
| E12 | unresolvable name while generating imports |
| E13 | import direction violated |
| E14 | a written file does not parse |

## Negative controls (the implementer proves each; paste the output)

| Control | Mutation | Expected |
|---|---|---|
| NC-MV-1 | delete one method entry from a copy of the map | `MOVE FAIL E3` naming it |
| NC-MV-2 | duplicate one method entry with another module | `MOVE FAIL E4` |
| NC-MV-3 | map `check_action` to `navigation` | `MOVE FAIL E9` |
| NC-MV-4 | map `_variant_set` getter and setter to two modules (edit the JSON) | `MOVE FAIL E11` |
| NC-MV-5 | change the map `base` | `MOVE FAIL E1` |
| NC-MV-6 | rename a top-level helper in a scratch base commit so a mixin loads an unknown name | `MOVE FAIL E12` |
| NC-MV-7 | run twice | identical `sha256` of every written file |
| NC-MV-8 | put `from .core import S19TuiApp` in a generated mixin (patch the emitter in a scratch copy) | fresh-import or cycle check fails, `MOVE FAIL` |
