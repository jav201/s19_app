# Spec — `tools/modularize/verify.py` (identity verifier) and `compare_outcomes.py` (suite equality)

Audience: an implementer with no other context. Read `design/interfaces.md` first (I-6 is the
closed list of allowed rewrites). Python ≥ 3.12, standard library only. The verifier must be
written **independently of `move.py`**: it may import `plan_map.top_units/method_units` for
unit discovery on the BASE text only; it must not import `move.py`. Requirements: R-MOD.1–R-MOD.4,
R-MOD.5.1, R-MOD.6.x, R-MOD.7.1, R-MOD.9–R-MOD.13.

## Part A — `verify.py`

```
python -I tools/modularize/verify.py --repo <tree> --base-rev <sha> --map <module-map.json> [--json <out>]
```
Reads the old modules from `git -C <tree> show <base-rev>:<path>` and the new packages from the
work tree `<tree>/s19_app/tui/app/` and `<tree>/s19_app/tui/screens_directionb/`.

### A.1 Unit inventory (old)
For each old module: top units (functions, classes, assignments, annotated assignments; imports
are inventoried separately), and for `S19TuiApp` every class-body statement and method.
Identity key: `(package, qualified name, ordinal)` where ordinal disambiguates repeated names
(the `_variant_set` getter = 0, setter = 1).

### A.2 Unit inventory (new)
Parse every `.py` file of each new package. Top-level units per file; for `core.py` the class
`S19TuiApp` body; for each `class <X>Mixin:` its methods. A unit's new qualified name maps back
to the old key by name (`<X>Mixin.m` ↔ `S19TuiApp.m`).

### A.3 Checks (each failure is reported, all are run, exit 1 if any fails)

| Id | Check | Fails when |
|---|---|---|
| V1 missing | every old unit key is present in the new inventory | an old unit has no new unit |
| V2 duplicate | every old unit key appears once | a key appears in 2+ places (two files, or twice in one class) |
| V3 extra | every new unit maps to an old key, except the allowed additions (I-6 item 5, mixin `class` statements, the I-4 header) | an unknown function/class/assignment exists |
| V4 body | normalised AST of old unit == normalised AST of new unit | any node differs |
| V5 rewrite list | every rewrite found while normalising is in I-6 | e.g. a non-D1 name turned into `deps.X`, a D1 name rewritten inside `deps.py`, a relative import changed by other than +1 |
| V6 bare D1 | no `Name` Load of a D1 name outside annotations in any new module except `deps.py` | a bare `os.` / `Label(` survives |
| V7 D1 counts | for each D1 name, (# of `deps.<name>` Attribute loads across new modules) + (# of global Loads inside `deps.py` units) == (# of global non-annotation Loads in the old module) | a site lost or added |
| V8 placement | each unit sits in the file `module-map.json` names | a unit in the wrong module |
| V9 core pins | I-5 units are in `core.py`'s `S19TuiApp` body; `S19TuiApp.__dict__` (at runtime) contains `on_button_pressed`, `on_flow_execution_panel_external_step_confirmed`, `__init__`, `compose`, `on_mount`, `check_action`, `on_event`, `action_show_help_panel`, `watch_current_file`, `copy_to_clipboard`, `action_help_quit`, `action_quit` | a pin moved |
| V10 header/MRO | runtime: `S19TuiApp.__bases__` equals the map's header order + `App`; no name in two of `{S19TuiApp} ∪ mixins` `__dict__`s; every mixin's `__bases__ == (object,)` | |
| V11 re-exports | runtime: every name of `reexports` is an attribute of the package; for names homed in the package, `getattr(pkg, n) is getattr(home_module, n)` | |
| V12 old files gone | `s19_app/tui/app.py` and `s19_app/tui/screens_directionb.py` do not exist | either exists |
| V13 imports fresh | one subprocess per new module `python -I -c "import <dotted>"` (cwd = tree) exits 0 | any non-zero |
| V14 acyclic | static graph of package-internal module-level imports has no cycle and obeys I-1 direction | |
| V15 caps | physical lines per file ≤ max(2,200, largest whole class in the file + 500) | |
| V16 CSS | runtime: `(Path(inspect.getfile(S19TuiApp)).parent / S19TuiApp.CSS_PATH).resolve()` (the rule Textual's `_make_path_object_relative` applies) equals `(<tree>/s19_app/tui/styles.tcss).resolve()` and the file exists | |
| V17 imports equivalence | for every name a new module imports from outside the package, the imported object `is` the object the old module bound under that name. Load the old module in the same process by writing the base text to `<tree>/s19_app/tui/_verify_old_<name>.py` (same directory, so its relative imports resolve), importing `s19_app.tui._verify_old_<name>`, and deleting the file in a `finally` | a generated import binds a different object |
| V18 names resolve (review F2, 2026-11-13) | (a) static, per new module: every module-global Load found by `symtable` in any scope (annotations excluded; PEP 709 inlined comprehension targets excluded) is bound at the module's top level, or is a builtin that the old module does not bind at top level; (b) runtime (in the subprocess probe): for every `deps.X` Attribute load in a package, `hasattr(deps, X)`; for every imported D1 name X, `deps.X is old.X` (old module loaded as in V17) | a used name is unbound (NameError/AttributeError at call time), or `deps.X` is missing or a different object |
| V19 TYPE_CHECKING shape (review F5) | every top-level `if TYPE_CHECKING:` in old and new modules has an empty `orelse` and only import statements in its body | an `else:` branch or non-import code under `TYPE_CHECKING` (would be skipped by the inventory) |

### A.4 Normalisation (the only transformations applied before comparing)
Compare `ast.dump(node, annotate_fields=True, include_attributes=False)` after these node
transforms on the NEW side, each counted per kind:
1. `Attribute(value=Name('deps'), attr=X, ctx=Load)` with `X ∈ D1` and the unit not in
   `deps.py` → `Name(X, Load)`. (count: `d1`)
2. `ImportFrom(level=L)` with `L ≥ 2` → `level = L − 1`. Applied to every ImportFrom inside
   units; top-level import statements are not units. (count: `relimport`)
3. In `core.py` class body: `Assign(targets=[Name('CSS_PATH')], value=Constant('../styles.tcss'))`
   → `Constant('styles.tcss')`. Exactly one. (count: `css`)
4. Methods: compare the `FunctionDef`/`AsyncFunctionDef` node whole (name, args, decorators,
   returns, body, type comment). Classes moved whole (all sdb classes, the top-level classes of
   app): compare the whole `ClassDef`.
Any difference left after these is V4. A transform applied where its precondition is false is V5.
Docstrings and comments: docstrings are AST (compared); comments are not compared.

### A.5 Output
```
VERIFY base=<sha> units_old=<n> units_new=<n> missing=<n> duplicate=<n> extra=<n> body_diff=<n> unlisted_rewrite=<n>
VERIFY d1_sites=<new>/<old> relimports=<n> css=<n> bare_d1=<n> pins=<ok>/<total> reexports_missing=<n> fresh_imports=<ok>/<total> cycles=<n> caps_over=<n> old_files=<n>
VERIFY OK            (or: VERIFY FAIL <check id>: <unit> <detail>  — one line per failure, then VERIFY FAIL)
```
`--json` writes the same numbers plus per-failure details. Exit 0 iff every count of failures is 0.

### A.6 Negative controls (in scratch copies of a moved tree; paste the output of each)

| Control | Mutation of the NEW tree | Expected |
|---|---|---|
| NC-VF-1 missing | delete one method (e.g. `NavigationMixin._land_focus`) | `VERIFY FAIL V1` naming `S19TuiApp._land_focus` |
| NC-VF-2 duplicate | copy one method into a second mixin | `V2` (and `V10` at runtime) |
| NC-VF-3 altered body | change one integer constant inside `ShellMixin._busy_tick` | `V4` naming it |
| NC-VF-4 unlisted rewrite | rewrite one `Path` (non-D1) to `deps.Path` and add `Path` to `deps.py` | `V5` |
| NC-VF-5 bare D1 | turn one `deps.os` back into `os` (and import `os`) | `V6` and `V7` |
| NC-VF-6 wrong file | move one top-level helper from `shared.py` to `shell.py` (fix imports) | `V8` |
| NC-VF-7 pin moved | move `on_button_pressed` to `NavigationMixin` | `V9` |
| NC-VF-8 re-export | delete one name from `app/__init__.py` | `V11` |
| NC-VF-9 cycle | add `from .navigation import NavigationMixin` at top of `shared.py` | `V13` or `V14` |
| NC-VF-10 css | restore `CSS_PATH = "styles.tcss"` | `V4` (no transform applies) and `V16` |
| NC-VF-11 old file | recreate an empty `s19_app/tui/app.py` | `V12` |
| NC-VF-12 import binds other object | change one generated `from ..render.hexview import X` to import a same-named object from elsewhere | `V17` |
| NC-VF-13 level | make one relative import `+2` | `V4`/`V5` |
| NC-VF-14 unbound deps name | remove `Label` from `deps.py`'s imports | `V18` naming `deps.Label` |
| NC-VF-15 unbound global | delete one top-level import used only inside a function body of a mixin | `V18` naming module and name |
| NC-VF-16 TYPE_CHECKING else | add `else: X = 1` to a `TYPE_CHECKING` block | `V19` |

## Part B — `compare_outcomes.py` (suite node-set equality, R-MOD.4)

```
python -I tools/modularize/compare_outcomes.py <before outcomes.tsv> <after outcomes.tsv> [--flaky <file>]
```
Inputs: `outcomes.tsv` as written by `tools/modularize/run_suite.sh` (`nodeid<TAB>outcome`,
outcome ∈ passed/failed/error/skipped/xfailed/xpassed), one run of base `4f721985` (or later
base) and one of the moved tree, same runner, same Python, same worker count.

Rules:
1. Node sets: `before_ids == after_ids` exactly. Adapted tests keep their names (the adaptation
   spec forbids renames), so no id map exists. A missing or new id is a failure (`B1`).
2. Outcomes: for each id, `before == after`. A differing id is a failure (`B2`) unless listed in
   `--flaky` (one id per line, each with a reason, produced only by re-running BOTH revs 3 times
   and observing ≥ 2 distinct outcomes on the SAME rev).
3. Collection errors (`error` on an id whose name ends in a module path, or pytest exit code 2/4)
   on either side → failure (`B3`).
4. File-swept families (`B4`): ids under the prefix
   `tests/test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input[` are
   removed from rules 1–2 and compared as a family: after-family size = before-family size − 2
   + (number of `.py` files under the two new packages), and every after id is `passed`.
   (Its ids are `p.name`; duplicate names get pytest suffixes, so individual ids renumber.)
   Prefixes come from `--families <file>`; it holds exactly this one prefix (hazards H-21).
5. **Run integrity (review F3/F4, 2026-11-13).** `run_suite.sh` deletes `$OUT/junit.xml` and `$OUT/outcomes.tsv`
   before running and writes pytest's exit code to `$OUT/rc`. `compare_outcomes.py` takes `--before-rc <file>`
   `--after-rc <file>` (required): rc not in {0, 1} on either side → `B3`. Either side with 0 ids → exit 1
   (`B6 empty`). A node id that appears twice in one TSV → exit 2 naming the id (no silent merge).
Output:
```
COMPARE before=<n> after=<n> missing=<n> new=<n> outcome_diff=<n> flaky_excused=<n>
COMPARE OK | COMPARE FAIL (then one line per failing id: B<k> <id> <before> -> <after>)
```
Negative controls:
- NC-CMP-1: drop one line from the after file → `B1 missing=1`.
- NC-CMP-4: after rc file holds `2` → `B3`. NC-CMP-5: empty after TSV → `B6`. NC-CMP-6: duplicate id → exit 2.
- NC-CMP-2: flip one `passed` to `failed` in the after file → `B2`.
- NC-CMP-3 (end to end, once, on a runner): a moved tree with one moved method body broken
  (`return` inserted at the top of `ShellMixin.set_status`) → the run differs from base on ≥ 1 id
  → `COMPARE FAIL`. This proves the suite comparison can fail on a real behaviour change.
