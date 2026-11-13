# Code Review — P0 tools (mover + identity verifier + compare_outcomes)

Reviewer: code-reviewer (Opus), one pass, read-only. Repo `s19_app-modular`, branch `batch-modular`
HEAD 62b6e712; generated output inspected on `batch-modular-apply` (d29033ba) via `git archive` +
AST/symtable only (no project code or tests run).

## Scope reviewed
- `tools/modularize/verify.py`, `verify_units.py`, `verify_norm.py`, `verify_check.py`,
  `verify_scope.py`, `verify_static.py`, `verify_runtime.py`, `verify_probe.py`, `compare_outcomes.py`
- `tools/modularize/move_emit.py`, `move_names.py`, `move_check.py` (+ grep of `move_derive.py`,
  `move_rewrite.py`), `run_suite.sh`
- `B/design/spec-verify.md`, `spec-move.md` §4, `interfaces.md` I-3/I-6, `hazards.md`
- Generated `s19_app/tui/app/*.py`, `s19_app/tui/screens_directionb/*.py` at d29033ba

## Findings

### F1 — `deps.py` does not bind 27 of the 30 imported D1 names: every `deps.X` call for them raises AttributeError  [BLOCK]
- **What:** `interfaces.md` I-3 "deps.py contents" item 2 requires deps to carry "the old import
  statement of every *imported* D1 name". The generated `s19_app/tui/app/deps.py` imports only what
  the deps-defined units themselves use (`os`, `IntelHexFile`, `parse_a2l_file`, ...). Not bound in
  deps, but loaded as `deps.X` elsewhere: `Label`, `ListItem`, `datetime`, `_is_reparse_point`,
  `_mirror_and_write_os_clipboard`, `_private_stage_dir`, `compare_images`,
  `compose_before_after_report`, `compose_load_announcement`, `copy_into_workarea`,
  `find_string_in_mem`, `gather_project_artifacts`, `generate_diff_report`,
  `generate_diff_report_html`, `generate_project_report`, `inventory_project_tree`,
  `place_into_workarea`, `plan_project_save`, `read_project_manifest`, `render_hex_view_text`,
  `resolve_input_path`, `save_patched_image`, `validate_project_files`, `verify_written_image`,
  `verify_written_manifest`, `write_change_document`, `write_project_manifest`. deps.py has no
  module `__getattr__`, and no module assigns attributes onto `deps`. (sdb deps is fine: its only
  D1 name `_json_clock` is deps-defined.)
- **Where:** root cause `tools/modularize/move_names.py:88-92` (a D1 Load in a non-deps module only
  sets `has_d1`; the name is never routed to deps) + `move_emit.py:139-147` (deps' imports come only
  from deps' own units). `spec-move.md` §4 omits the I-3 item-2 rule, so the mover follows its spec
  and still breaks the interface. Example sites: `app/core.py:587` `deps.Label("Ready.", ...)` inside
  `compose()`; `app/core.py:1186` `deps._mirror_and_write_os_clipboard(...)`.
- **Why it matters:** `S19TuiApp.compose()` raises AttributeError, so the app cannot start; every
  load/save/report/diff path calling one of these names fails at call time. Tests doing
  `monkeypatch.setattr(app.deps, "Label", ...)` (raising=True) fail too. Import-time checks (V13 and
  the mover's fresh-import self-check) pass because module attribute access is lazy.
- **Suggested fix (software-dev applies):** in `move_emit._emit_module`, for `module == "deps"` add
  the imported D1 names before `_resolve`:
  `if module == "deps": runtime |= {n for n in pkg.d1_names if n in pkg.import_by_name}`
  (`open` stays out: it is a builtin, not in `import_by_name`). Amend `spec-move.md` §4 to say so.
  Re-run MOVE + VERIFY (with F2 in place) and confirm deps.py imports all 30 imported D1 names.
- **State:** executed (AST check over d29033ba: set of `deps.X` attributes minus deps.py top-level
  bindings); fix not-run.

### F2 — Verifier never checks that a name or `deps.X` used in a new module resolves  [BLOCK]
- **What:** V4 undoes `deps.X -> X` and compares bodies; V6/V7 count sites; V13 only imports; V17
  only checks names that *are* imported at top level. Nothing checks (a) that each `deps.X` exists on
  the deps module, or (b) that each module-global Load in a new module is bound at its top level (or
  is a builtin that no old top-level statement shadows). So F1 passed with
  `VERIFY OK, body_diff 0, d1_sites 222/222`. The same gap admits any missing import used only inside
  function bodies (NameError at call time), and silently admits builtin shadowing (old module binds
  e.g. `format`, new module forgets the import, builtin is used, no error at all — not present at this
  base, and the mover guards it, but the verifier does not).
- **Where:** `verify_check.py:99-121` (V6/V7), `verify_runtime.py:110-141` (V17 scope),
  `verify_probe.py:243-253`.
- **Why it matters:** this is precisely a blind spot shared by both tools: identity is reported while
  behaviour changed.
- **Suggested fix:** add V18 "names resolve":
  1. static: per new module, `symtable` module-global Loads (all scopes, annotations excluded,
     PEP 709 inlined comprehension targets excluded) must be a subset of top-level bindings union
     (builtins minus names the old module binds at top level);
  2. runtime in the `equiv` probe: for every `deps.X` attribute load in the package,
     `hasattr(deps, X)`, and for imported D1 names `deps.X is old.X`.
  Add NC-VF-14: remove `Label` from deps.py's imports -> must fail V18 (today the real tree is in
  that state and passes).
- **State:** executed (static reproduction above); fix not-run.

### F3 — Suite comparison can report OK on a run that never happened  [MAJOR]
- **What:** `run_suite.sh` deletes `tree/` and `state/` but not `$OUT/junit.xml` / `outcomes.tsv`;
  if pytest dies before writing junit (rc 2/3/4, crash, timeout), the stale junit from an earlier run
  is re-parsed into a fresh-looking outcomes.tsv. `RC` is only echoed. `compare_outcomes.py` has no
  exit-code input, so spec B3 "pytest exit code 2/4 -> failure" is unimplemented; and two empty TSVs
  give `before=0 after=0 ... COMPARE OK` with exit 0.
- **Where:** `run_suite.sh:9-10,19-35`; `compare_outcomes.py:72-94,117-132`.
- **Why it matters:** the suite is the backstop for verifier blind spots (F2); a stale or empty run
  defeats it silently.
- **Suggested fix:** `rm -f "$OUT/junit.xml" "$OUT/outcomes.tsv"` before the run; record rc (e.g.
  `$OUT/rc`); in `compare_outcomes.py` fail B3 when rc is not in {0,1} on either side, and fail when
  either side has 0 ids.

### F4 — `compare_outcomes.read_tsv` silently collapses duplicate node ids  [MINOR]
- **What:** `out[node] = outcome` overwrites. The junit-to-id mapping in `run_suite.sh` can emit two
  rows for one id (call failure plus a separately reported teardown error; synthetic paths for
  class-based tests). A `failed` row can be hidden by a later `passed` row.
- **Where:** `compare_outcomes.py:22-31`.
- **Suggested fix:** exit 2 on a duplicate id, or keep the worst outcome.

### F5 — `if TYPE_CHECKING:` blocks are invisible to the verifier; sdb `LoadedFile` import dropped  [MINOR]
- **What:** `verify_units.is_import_like` skips any top-level `if TYPE_CHECKING:` whole, including a
  possible `else:` branch with runtime code (none at this base). The mover collects only `Name`
  loads, so the string annotation `Optional["LoadedFile"]` in
  `screens_directionb/loaded_artifacts.py:140,252` lost its `if TYPE_CHECKING: from ..models import
  LoadedFile`. Runtime behaviour unchanged (the old module never bound it at runtime either), but
  type checkers now report an undefined name, contrary to I-6 item 5 which lists that block as copied.
- **Where:** `verify_units.py:46-49`; `move_names.py:75-98`.
- **Suggested fix:** verifier: refuse (V3) an `If TYPE_CHECKING` with a non-empty `orelse`; mover:
  also collect names from string-constant annotations (`ast.parse(s, mode="eval")`), or copy the
  TYPE_CHECKING import into every module whose annotations mention the bound name.

## Checked and found sound
- V4/V5/V7 jointly: a mover rewrite of a *local* D1-named variable to `deps.X` passes V4 (undo) but
  raises the V7 count; a lost global site leaves a bare name (V6) or a body diff (V4).
- Decorators, defaults, argument lists, class-level statements and same-key ordinals (property
  getter/setter) are compared; class-statement reorders that matter fail at import (V13).
- Probe exceptions are reported (BaseException caught; errors mapped to V9/V11/V13/V17); no exception
  path exits 0.
- Comments: multiset of every `#` comment, old vs new: app 1566/1566, sdb 968/968, 0 lost, 0 added.
- No module-identity-dependent code (`__name__`, `__file__`, `inspect`, `globals()`); the logger is
  the literal `"s19tui"` (H-10/H-11 confirmed).
- No old module binds a builtin name at top level, and no name is bound twice; no non-deps module
  imports a D1 name statically from `.deps` (only `__init__` re-exports deps-defined names).
- Old `class S19TuiApp(App):` has no decorators/keywords; only `main` follows the class; mover
  emission order is deterministic.

## Verdict
- [ ] OK to advance
- [ ] BLOCK-UNTIL: F1, F2
- [x] Block — HIGH findings open (F1, F2)

verdict: FAIL

## Evidence checklist
- [x] Diff read: verifier modules in full; mover emit/names/check in full; generated packages via AST.
- [x] Correctness pass (F1-F5).
- [x] Simplicity pass — no over-engineering finding raised.
- [x] Reuse — n/a (tools are new and intentionally independent).
- [x] Tests for intent — NC-VF-1..13 do not cover a missing deps binding (F2 proposes NC-VF-14).
- [x] Verdict explicit: Block, F1 and F2 open (no fix applied or verified).

Hand-off: no security item. qa-reviewer: once F1 is fixed, the full suite on a runner (with F3 in
place) is the end-to-end confirmation.
