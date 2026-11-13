# Spec — `tools/modularize/retarget_tests.py` (test patch retargeter)

Audience: an implementer with no other context. Read `design/interfaces.md` I-3 first.
Python ≥ 3.12, standard library only. Requirements: R-MOD.7.2, R-MOD.7.3, R-MOD.7.4, R-MOD.16.4.
Scope: **only** the rewrites below. Source-reading tests (hazards H-12/H-13) are adapted by
hand by four workers, not by this tool.

## Command

```
python -I tools/modularize/retarget_tests.py --repo <tree> --map <module-map.json> [--check]
```
- Scans every `*.py` under `<tree>/tests/` (recursive).
- Default: rewrites files in place and prints the summary. `--check`: rewrites nothing, prints
  the sites still needing a rewrite, exits 1 if any (used after the rewrite as a negative check).

## Inputs
- D1 lists from the map: `app.d1_names` (37, package `s19_app.tui.app`),
  `screens_directionb.d1_names` (1, package `s19_app.tui.screens_directionb`).

## Binding discovery (per test file, AST)
A local name is a **module alias** for package P when bound by any of:
`import P as A`; `import P` (alias = the dotted chain `P`); `from s19_app.tui import <last> [as A]`;
`A = importlib.import_module("P")` / `A = import_module("P")`. Same discovery as
`tools/modularize/test_patch_census.py::_aliases` — import and reuse it.

## Rewrites (text edits at AST positions; UTF-8 byte columns converted to characters per line)

| Id | Pattern (X ∈ D1 of P) | Rewrite |
|---|---|---|
| T1 | call `*.setattr(A, "X", …)` / `*.delattr(A, "X", …)` / `patch.object(A, "X", …)` / `mocker.patch.object(A, "X", …)` / builtin `setattr(A, "X", …)` / `delattr(A, "X")` — first argument is a module alias expression of P | first argument `A` → `A.deps` |
| T2 | first argument is a string constant `"P.X"` (or `"P.X.attr…"`) to a call whose last dotted name is `setattr`, `delattr`, `patch`, `object`, `setitem`, `delitem` | `"P.X…"` → `"P.deps.X…"` (only the first `P.` prefix) |
| T3 | assignment / augmented assignment / `del` target `A.X` | `A.X` → `A.deps.X` |
| T4 | any other attribute read `A.X` (Load) | `A.X` → `A.deps.X` (equivalent when unpatched; required when a test patches X and later reads it back, e.g. `A.compare_images.call_count`) |

Only names in D1 are touched. `A.S19TuiApp…`, `A.SaveProjectPayload`, `A.__file__`, and any
non-D1 `A.Y` are never rewritten. Patches on `S19TuiApp` (class patches) are never rewritten.

## Refusals (exit 1, no file written — R-MOD.16.4)

| Code | Condition |
|---|---|
| R1 | a D1 name of P is reached through a form the table does not cover: `vars(A)`, `A.__dict__`, `getattr(A, "X")` / `getattr(A, name)` with a non-constant name, `patch.multiple(A, …)`, `patch.dict(A.__dict__…)`, `sys.modules["P"]`, `monkeypatch.setattr(A, name_var, …)` with a non-constant second argument |
| R2 | a string target `"P.X"` appears in any other call or as a bare constant (e.g. kept in a list and patched in a loop) |
| R3 | a test imports a D1 name by value (`from P import X`) **and** the same file patches X on P — the by-value binding was never affected by the patch; flag for a human, do not rewrite |
| R4 | a file fails to parse |
Each refusal prints `RETARGET REFUSE R<k> <file>:<line> <source line>`.

## Output and acceptance

```
RETARGET files_scanned=<n> files_changed=<n> T1=<n> T2=<n> T3=<n> T4=<n> refused=<n>
RETARGET CHECK remaining=<n>
RETARGET OK
```
Acceptance (printed by the tool after writing, R-MOD.7.2/7.3):
1. Re-run the census logic in memory on the rewritten files: every `module_patches` entry whose
   name ∈ D1 now targets `P.deps` (0 left on `P`).
2. The textual diff of each changed file touches only the rewritten spans (compare
   `old_text` with `new_text` after undoing the recorded edits → identical).
3. Every changed file still parses.
4. Idempotent: a second run reports `files_changed=0`.

Expected counts on base `4f721985` (from the census, for the implementer's cross-check — the
tool computes its own): T1+T2+T3 sites = 150 app patch sites over 37 names + 1 sdb site
(sum of the "Patch sites" column of interfaces.md I-3; computed from `test-patch-census.json`).
R3 fires on 0 files at base (checked by script). T4 is whatever the files contain.

## Negative controls (paste output)

| Control | Mutation | Expected |
|---|---|---|
| NC-RT-1 unlisted form | add `monkeypatch.setattr(vars(app_module), "os", x)` to a scratch test file | `REFUSE R1` |
| NC-RT-2 dynamic name | add `monkeypatch.setattr(app_module, name, x)` with `name` a variable | `REFUSE R1` |
| NC-RT-3 missed site | after a run, revert one rewrite by hand, run `--check` | `remaining=1`, exit 1 |
| NC-RT-4 non-D1 untouched | a scratch file with `monkeypatch.setattr(app_module, "S19TuiApp", x)` and `app_module.SaveProjectPayload` | no rewrite of either |
| NC-RT-5 string target | `monkeypatch.setattr("s19_app.tui.app.find_string_in_mem", f)` | becomes `"s19_app.tui.app.deps.find_string_in_mem"` |
| NC-RT-6 idempotent | run twice | second run `files_changed=0` |

## Amendment 2026-11-13 (P2 diagnosis RC-A/RC-C, review/P2-after1-diff-diagnosis.md)
- **T6 — module passed to a patching helper.** A call `H(..., A, ...)` in a test file where `A` is a module alias of P (app or
  screens_directionb) passed as a positional/keyword ARGUMENT (not as the target of T1–T5) is rewritten `A` → `A.deps` iff every call of
  `H` in that file passes `A` and, in the same call, a string constant that is a D1 name of P (the helper patches `owner.<name>`; e.g.
  `Hold(monkeypatch, app_module, "parse_a2l_file")`, `Spy(...)`). Any call of such an `H` passing `A` with a non-D1 constant, a
  non-constant name, or no name → **R5 refuse** (listed, exit 1). Calls where `A` is passed to non-patching functions (`inspect.*`,
  `getsource`, `Path(A.__file__)`, `importlib.reload`) are not T6 (they are H-12 source readers).
- **R1 extended:** writes through `<fn>.__globals__` (`X.__globals__[...] = `, `monkeypatch.setitem(X.__globals__, ...)`,
  `monkeypatch.setattr` on such a dict) where `X` resolves to an attribute of P or of `S19TuiApp` → R1 refuse (listed). The one known
  site (tests/test_b103_copy_views.py fixture, `_mirror_and_write_os_clipboard`) is adapted by hand after the run (P2 RC-C).
- **Census (test_patch_census.py) must see T6 sites:** a string constant D1 candidate passed together with a P module alias to a
  helper that `setattr`s its owner parameter counts as a patch site of that name. Recomputing D1 with this rule adds at least
  `render_patched_image`, `check_project_files`, `build_loaded_s19` (P2 RC-B); D1 in module-map.json is regenerated with plan_map.py.
- Negative controls: NC-RT-9 (T6 rewrite on a scratch helper call), NC-RT-10 (helper call with a non-D1 constant → R5),
  NC-RT-11 (`__globals__` write → R1), NC-CEN-1 (census without the T6 rule misses the 3 names; with it, finds them).
