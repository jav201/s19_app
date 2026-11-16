# batch-modular — test cases (E1/E2 design)

Cases for the batch's mechanical evidence. Rows follow `roles/tester.md`:
`<requirement id>/<n> | case id | check (tool + control) | full or partial`, then the expected
result. Results come from the tool runs in E4/E5 (transcripts under `evidence/`), never typed
here. "Tree" = a scratch clone with the mover applied; "scratch copy" = a further copy mutated
for one control and thrown away. Specs: `design/spec-move.md`, `design/spec-verify.md`,
`design/spec-retarget-tests.md`; source-reading rows: `design/hazards.md` H-12.

## A. Verifier negative controls (each must print `VERIFY FAIL <id>`)

| Req/alt | Case | Check | Kind | Expected |
|---|---|---|---|---|
| R-MOD.2.1/1 | TC-MOD-01 | verify on tree | full | `missing=0` and `VERIFY OK` |
| R-MOD.2.1/2 | TC-MOD-02 | NC-VF-1: delete `NavigationMixin._land_focus` | full | `VERIFY FAIL V1` naming `S19TuiApp._land_focus` |
| R-MOD.2.2/1 | TC-MOD-03 | NC-VF-2: copy `_busy_line` into `HexViewMixin` | full | `V2` and `V10` |
| R-MOD.2.3/1 | TC-MOD-04 | add `def _helper(): pass` to `shell.py` | full | `V3` |
| R-MOD.2.4/1 | TC-MOD-05 | NC-VF-3: change one integer in `ShellMixin._busy_tick` | full | `V4` naming the method |
| R-MOD.2.5/1 | TC-MOD-06 | NC-VF-4: `Path` → `deps.Path` (+ bind in `deps.py`) | full | `V5` |
| R-MOD.2.5/2 | TC-MOD-07 | NC-VF-13: one relative import level +2 | full | `V4` or `V5` |
| R-MOD.2.6/1 | TC-MOD-08 | NC-VF-6: move a `shared.py` helper to `shell.py` | full | `V8` |
| R-MOD.6.1/1 | TC-MOD-09 | NC-VF-5: one `deps.os` → bare `os` | full | `V6` and `V7` (`os` count off by 1) |
| R-MOD.6.1/2 | TC-MOD-10 | verify on tree: per-name D1 counts | full | every D1 name `new == old` |
| R-MOD.6.2/1 | TC-MOD-27 | verify on tree (V8 placement of the 7 + 1 deps-defined units); then map `_is_link_stat` to `shared` in a scratch map | full | 8/8 in `deps.py`; scratch map → `V8` |
| R-MOD.8.4/1 | TC-MOD-28 | verify on tree: no method with an `on(...)` decorator in a mixin; scratch: decorate a mixin method with `@on(Button.Pressed)` | full | 0; scratch → `V9` / mover `E8` |
| R-MOD.8.1/1 | TC-MOD-11 | NC-VF-7: `on_button_pressed` → `NavigationMixin` | full | `V9` |
| R-MOD.8.2/1 | TC-MOD-12 | = TC-MOD-03 (runtime half) | full | `V10` duplicate name |
| R-MOD.8.3/1 | TC-MOD-13 | swap two mixins in the core header | full | `V10` header order |
| R-MOD.1.1/1 | TC-MOD-14 | NC-VF-8: delete one name from `app/__init__.py` | full | `V11 reexports_missing=1` |
| R-MOD.1.2/1 | TC-MOD-15 | delete `CHECK_GLYPHS` from the sdb `__init__` | full | `V11` |
| R-MOD.1.3/1 | TC-MOD-16 | replace one re-export by a copy | full | `V11` identity |
| R-MOD.5.1/1 | TC-MOD-17 | NC-VF-9 / NC-MV-8: `from .core import S19TuiApp` atop `navigation.py` | full | `V13` (fresh import of `navigation` fails) |
| R-MOD.5.2/1 | TC-MOD-18 | NC-VF-9: `from .navigation import NavigationMixin` atop `shared.py` | full | `V14` cycle |
| R-MOD.5.3/1 | TC-MOD-19 | import `FlowMixin` in `patch.py` | full | `V14` direction |
| R-MOD.5.4/1 | TC-MOD-20 | NC-VF-12: same-named object from another module | full | `V17` |
| R-MOD.4.1/1 | TC-MOD-21 | verify with the cap constant set to 500 | full | `V15 caps_over>0` |
| R-MOD.4.2/1 | TC-MOD-22 | verify on tree | full | header has 18 mixins (≥ 16) |
| R-MOD.9.1/1 | TC-MOD-23 | NC-VF-10: restore `CSS_PATH = "styles.tcss"` | full | `V4` and `V16` |
| R-MOD.9.2/1 | TC-MOD-24 | NC-VF-11: recreate empty `s19_app/tui/app.py` | full | `V12` |
| R-MOD.9.3/1 | TC-MOD-25 | `find_packages(include=["s19_app*"])` on tree; then without `screens_directionb/__init__.py` | full | 2/2; then 1/2 |
| R-MOD.10.8/1 | TC-MOD-26 | table of all NC-VF-1..13 | full | 13/13 RED, 0 survivors |

## B. Mover cases

| Req/alt | Case | Check | Kind | Expected |
|---|---|---|---|---|
| R-MOD.10.1/1 | TC-MOD-30 | NC-MV-7: run twice | full | equal sha256 for every file |
| R-MOD.10.2/1 | TC-MOD-31 | NC-MV-5: map base edited | full | `MOVE FAIL E1`, exit 1, `git status` clean |
| R-MOD.10.3/1 | TC-MOD-32 | NC-MV-1: drop a method from the map | full | `E3` naming it, nothing written |
| R-MOD.10.3/2 | TC-MOD-33 | NC-MV-2: duplicate a method entry | full | `E4` |
| R-MOD.10.4/1 | TC-MOD-34 | map a unit to `../x` | full | `E5`, nothing written |
| R-MOD.10.5/1 | TC-MOD-35 | NC-MV-3: `check_action` → `navigation` | full | `E9` |
| R-MOD.10.5/2 | TC-MOD-36 | NC-MV-4: split `_variant_set` getter/setter | full | `E11` |
| R-MOD.10.5/3 | TC-MOD-37 | `on_button_pressed` → mixin (map edit) | full | refused (core pin; V9 if forced) |
| R-MOD.10.6/1 | TC-MOD-38 | scratch base with local `os = …` in a method | full | `E6` |
| R-MOD.10.7/1 | TC-MOD-39 | NC-MV-6: unknown name | full | `E12` |
| R-MOD.10.10/1 | TC-MOD-40 | mover on a clean clone, then `git status --porcelain` | full | only the two package dirs, the two deletions, `.modularize/` |
| R-MOD.5.1/2 | TC-MOD-41 | mover acceptance self-check | full | `imports_fresh=32/32 (corrected at E5 from 33/33) cycles=0 reexports_missing=0 caps_over=0` |

## C. Re-export check

| Req/alt | Case | Check | Kind | Expected |
|---|---|---|---|---|
| R-MOD.1.1/2 | TC-MOD-45 | `python -I -c` import app package; `getattr` every `app.reexports` name | full | 443/443 |
| R-MOD.1.2/2 | TC-MOD-46 | same for sdb | full | 155/155 |
| R-MOD.1.3/2 | TC-MOD-47 | `getattr(pkg, n) is getattr(home, n)` for package-defined names | full | 0 mismatches |

## D. Retargeter

| Req/alt | Case | Check | Kind | Expected |
|---|---|---|---|---|
| R-MOD.6.3/1 | TC-MOD-50 | retarget on tree, then re-run census | full | 151/151 D1 sites on `.deps`, 0 on the package root |
| R-MOD.6.3/2 | TC-MOD-51 | NC-RT-3: revert one rewrite, `--check` | full | `remaining=1`, exit 1 |
| R-MOD.6.4/1 | TC-MOD-52 | acceptance 2 (undo recorded edits → identical text) | full | 0 lines outside spans |
| R-MOD.6.5/1 | TC-MOD-53 | NC-RT-4: non-D1 / class patch untouched | full | 0 rewrites |
| R-MOD.6.3/3 | TC-MOD-54 | NC-RT-5: string target | full | `"s19_app.tui.app.deps.find_string_in_mem"` |
| R-MOD.10.9/1 | TC-MOD-55 | NC-RT-1: `vars(app_module)` form | full | `REFUSE R1` |
| R-MOD.10.9/2 | TC-MOD-56 | NC-RT-2: dynamic name | full | `REFUSE R1` |
| R-MOD.6.3/4 | TC-MOD-57 | NC-RT-6: second run | full | `files_changed=0` |

## E. Suite equality

| Req/alt | Case | Check | Kind | Expected |
|---|---|---|---|---|
| R-MOD.3.1/1 | TC-MOD-60 | compare base vs tree outcomes (runner) | full | `missing=0 new=0` outside the B4 family |
| R-MOD.3.1/2 | TC-MOD-61 | NC-CMP-1: drop one line of after | full | `B1 missing=1` |
| R-MOD.3.1/3 | TC-MOD-62 | B4: drop one id of the paste family from after | full | `B4` family size mismatch |
| R-MOD.3.2/1 | TC-MOD-63 | compare outcomes | full | `outcome_diff=0` (flaky excused only with the 3×2 re-run record) |
| R-MOD.3.2/2 | TC-MOD-64 | NC-CMP-2: flip one outcome | full | `B2` |
| R-MOD.3.2/3 | TC-MOD-65 | NC-CMP-3: `return` atop `ShellMixin.set_status`, full suite on the runner | full | `COMPARE FAIL`, ≥ 1 id differs |
| R-MOD.3.3/1 | TC-MOD-66 | collection on tree | full | 0 collection errors |

## F. Law and source-reading adaptations (R-MOD.7)

One case per adapted H-12 row: the adapted test is GREEN on the tree and RED on the tree plus
the row's negative control. Case ids `TC-MOD-7G<g>-<row>` (group g ∈ 1..4, row = hazards.md
row number), e.g. `TC-MOD-7G1-02` = row 2, `test_tc_b100_50_…`, mutant "`self.begin_busy(...)`
in another mixin". Each group worker writes its own `02-test-cases-g<g>.md` with these rows and
pastes the mutant table (control, killed/survived). NONE rows get a single GREEN-on-tree case
(no adaptation) and their listed control as a survivor probe.

| Req/alt | Case family | Rows | Kind |
|---|---|---|---|
| R-MOD.7.1/1 | TC-MOD-7G1-* | hazards rows 1–18 (non-NONE) | full |
| R-MOD.7.1/2 | TC-MOD-7G2-* | rows 20–42 (non-NONE) | full |
| R-MOD.7.1/3 | TC-MOD-7G3-* | rows 43–72 (non-NONE) | full |
| R-MOD.7.1/4 | TC-MOD-7G4-* | rows 73–83 | full |
| R-MOD.7.2/1 | TC-MOD-7L-* | H-13 law rows: the law's control RED on the tree | full |
| R-MOD.7.1/5 | TC-MOD-7H-01 | `tests/support/package_source.py` floors: point it at an empty dir / a package without `core.py` | full — must fail loudly |
