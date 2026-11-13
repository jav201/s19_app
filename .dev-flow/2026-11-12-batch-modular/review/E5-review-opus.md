# Code Review — batch-modular E5 (one reviewer, one pass, read-only)

- Repo / branch: `s19_app-modular`, `batch-modular-apply`, range `62b6e712..5b67c844` (24 commits, 132 files).
- Reviewer: `code-reviewer` (claude-opus-5-5), 2026-11-13. Read-only. Used git, grep and `ast.parse` only. Ran no tests, imported no project code, ran no `py_compile`.
- Taken as given (not redone): move identity (VERIFY OK, d1_sites 226/226, names=0) and the after2 suite diagnosis. I spot-checked three moved bodies against base with `deps.X` mapped back to `X` (`_restore_manifest`, `update_memory_strip`, `_busy_tick`). All three ASTs are equal.

## Verdict

**BLOCK-UNTIL: F1.** Do not merge until F1 is fixed and re-read. F2 is MAJOR and should be fixed before merge. Everything else is MINOR (backlog).

Counts: **BLOCK 1 · MAJOR 1 · MINOR 7.**

Root cause shared by F1 and F2: the D1 seam turns every bare `X(...)` / `os.replace(...)` in the moved code into `deps.X(...)` / `deps.os.replace(...)`. That changes the code's AST shape. Any check that recognises a call only as a bare `ast.Name` (or as `os.<attr>` with `os` a bare Name) is now blind to it inside the app package. Hazard tables H-12 and H-13 list path keys and importer sets. They do not list this class. Group 4 found one case (row 82, `test_tc570`, made alias-aware). The class was not swept, and TC-MOD-7L (per-law mutants) has no recorded run (`04-validation.md`: NO-EVIDENCE).

---

## Findings

### F1 — The D1 rewrite left two law limbs unable to fail on the app package  [Severity: BLOCK]
- **What:** Two repo laws still match a guarded call only in its pre-split form. After the rewrite, those calls can no longer be detected anywhere in `s19_app/tui/app/`:
  1. `tests/test_b99_staging.py:2257-2263` (`_final_name_census`, used by `test_tc_b99_13_no_final_name_replace_outside_placement`, LLR-155.3). The `os.replace` limb needs `isinstance(func.value, ast.Name) and func.value.id == "os"`. `os` is a D1 name, so every `os.replace` in the app package is now `deps.os.replace` (`func.value` is an `Attribute`). Live site: `s19_app/tui/app/save_commit.py:382` `deps.os.replace(staged, manifest_path)`. The limb never sees it.
  2. `tests/test_tui_directionb.py:8957-8975` (`test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers`). `calls` collects only `ast.Name` callees. The forbidden set includes `parse_a2l_file`, which is D1. Any parse call in `update_memory_strip` (`s19_app/tui/app/workspace_view.py:413`) must now be `deps.parse_a2l_file(...)`, so that member of the forbidden set is dead.
- **Why it matters:** Each law's limb now gives false confidence for the whole app package. Two mutants pass at HEAD and would have gone RED at base:
  - `deps.os.replace(tmp, final)` in any app-package function outside the staging allow-list.
  - `deps.parse_a2l_file(...)` inside `update_memory_strip`.

  This breaks R-MOD.7.2 ("keep each law of H-13 able to fail on the new packages"). The test can no longer fail when the behaviour it guards breaks.
- **Suggested fix** (`software-dev`):
  - `test_b99_staging.py:2257`: accept the module either as a bare name or as the last part of a dotted chain.
    ```python
    def _tail(expr):  # "os" for both `os` and `deps.os`
        return expr.id if isinstance(expr, ast.Name) else (expr.attr if isinstance(expr, ast.Attribute) else None)
    ...
    elif func.attr == "replace" and _tail(func.value) == "os":
        primitive = "os.replace"
    ```
    Also add a positive control next to the existing two:
    ```python
    seam_sample = "from . import deps\n\ndef f(a, b):\n    deps.os.replace(a, b)\n"
    assert len(_final_name_census("seam.py", seam_sample)) == 1
    ```
    For consistency, apply the same `_tail(...) == "shutil"` to the `copy2` limb.
  - `test_tui_directionb.py:8957`: collect Attribute callees as well, as the sibling test at `:5975` already does:
    `calls = {n.func.id for ... ast.Name} | {n.func.attr for ... ast.Attribute}`.
    Check that the `<=` subset assertion on the three helpers still holds.
  - Close the class. Add a hazards.md H-13 row: "Name-keyed call matchers vs the D1 rewrite". Re-run the sweep (method below) and paste the mutant RED lines under TC-MOD-7L. Sweep method: in every test that reads the app package (rglob of `s19_app`, `package_tree`, `merged_class`, `getsource(S19TuiApp.*)`), find call matchers keyed on `ast.Name` ids, or on `func.value.id == "<D1 module>"`, whose name set intersects D1. My sweep found exactly these two. `test_tui_directionb.py:6412/6456` are Name-only too, but they read sdb panels, where only `_json_clock` is D1, so they are unaffected.
- **Evidence state:** `executed` (static AST read; both sites quoted). Mutant runs: `not-run` (Windows read-only constraint).

### F2 — No permanent guard for the D1 seam: the old patch idiom now silently patches nothing  [Severity: MAJOR]
- **What:** `s19_app/tui/app/__init__.py` still re-exports every D1 name from its original module (`os`, `compare_images`, `place_into_workarea`, …), as R-MOD.1.1 requires. Before the split, the house idiom across about 25 test files was `monkeypatch.setattr(app_module, "<D1>", fake)`. That call now succeeds (the attribute exists) but reaches no product code, because the moved code reads `deps.<D1>`. With `raising=False` it would succeed even for a typo.

  The same gap exists on the product side. A future mixin that writes `from ..services.compare_service import compare_images` (or `from .deps import X`) bypasses the seam, and tests patching `deps.X` stop reaching it.

  The only things enforcing the seam today are one-shot batch tools (`verify.py` V6/V7, `retarget_tests.py --check`). Neither runs in the suite. Nothing in `CLAUDE.md`, `PROJECT_RULES.md` or `docs/architecture.md` tells future authors about the `deps` seam. The doc edits in this range only rename paths.
- **Where:** `s19_app/tui/app/__init__.py` (re-exports), `s19_app/tui/app/deps.py`, `s19_app/tui/screens_directionb/deps.py`. No law test exists.
- **Why it matters:** This batch's purpose (US-MOD-01) is parallel workers on these packages, mostly agent-written. The first new test that uses the base-era idiom gets a vacuous patch. A failure-injection test ("patch X to raise; assert the app survives") then passes green without exercising anything. P2 after1 showed the scale of this risk: 57 regressions came from exactly this mismatch.
- **Suggested fix:**
  1. Add one law test, e.g. `tests/test_d1_seam_law.py`. Pure AST, reuse `tests/support/package_source.py`:
     - (a) For each package, the names bound in `deps.py` (top-level imports, defs and assigns) form the seam set.
     - (b) No module of the package other than `deps.py` / `__init__.py` imports a seam name or loads it bare (annotations excluded). This is V6/V7 made permanent.
     - (c) No test file targets the package root with a seam name. That means: `setattr` / `delattr` / `patch.object` on an alias of `s19_app.tui.app` or `s19_app.tui.screens_directionb`, a string target `"s19_app.tui.app.<seam>"`, or `alias.<seam> = ...`. `tools/modularize/test_patch_census.py` already has the resolver; import or copy its `_aliases` / `_resolve` logic.
     - Negative controls: a scratch test text `monkeypatch.setattr(app_module, "compare_images", f)` → RED; `from ..services.compare_service import compare_images` in a scratch mixin text → RED.
  2. Add one paragraph to `docs/architecture.md` (and a line in `CLAUDE.md`): "names a test rebinds live in `<pkg>/deps.py`; patch `app_module.deps.X`; product modules read them as `deps.X`."
- **Evidence state:** `executed` (static). I checked that the current tree is clean: every `app_module.deps` / `app_deps` / `"…deps.X"` patch target is bound in `deps.py`, except `open` (H-18, deliberate). No test still patches a D1 name on the package root.

### F3 — `test_tc081_4_no_binding_diff` is looser than at base  [Severity: MINOR]
- **What:** `tests/test_tui_patch_history_strip.py` (`test_tc081_4_no_binding_diff`, hunk at ~681-805) now compares the NET multiset of stripped `Binding(` lines across `app.py` plus `app/`. A reordering of `BINDINGS` entries, or moving a `Binding(` line between classes inside `app/`, now nets to zero. At base, any `+`/`-` `Binding(` line failed.
- **Why it matters:** Binding order drives the key bar and help order, and that change is now invisible to this guard. Low risk: there is one `BINDINGS` holder in the package, and this guard is batch-local (`git diff main`).
- **Suggested fix:** Keep the net check for the move, and also compare the ordered list of `Binding(` lines of `S19TuiApp.BINDINGS` (core.py) against the same list extracted from `git show main:s19_app/tui/app.py`.

### F4 — Retargeter T6 is not fail-loud for helper forms it cannot see  [Severity: MINOR]
- **What:** `tools/modularize/retarget_t6.py`:
  - `patching_helpers` recognises only helpers defined in the same test file whose `setattr` uses two bare parameters.
  - `find_t6_calls` considers only bare-Name callees.
  - `if owner_arg is None: continue` (`:192-194`) silently skips an owner passed through `**kwargs`. The docstring of `arg_for_param` says such cases are "treated as refusing".

  A module alias passed to a helper imported from `tests/support/`, called as `x.helper(...)`, or passed via `**kw` is neither rewritten nor refused. That falls short of R-MOD.10.9 ("a form the retargeter does not rewrite → exit 1").
- **Why it matters:** The suite run is the only backstop, and a vacuous failure-injection patch can pass. On the current tree I found no such call: the only places `app_module` is passed as an argument are `getattr` / `hasattr` reads at `test_b100_load_question.py:3158` and `test_b100_workers.py:1176/1306`.
- **Suggested fix:** Add a catch-all R6. Any P module alias passed as a call argument to anything other than `getattr` / `hasattr` / `inspect.*` / `Path` / `importlib.*` / a recognised T6 helper → refuse. Make the `owner_arg is None` branch refuse when the helper's owner parameter could be supplied by `*args` / `**kwargs`. F2's permanent law covers the same ground going forward.

### F5 — `--accept-refusal` does not report stale entries  [Severity: MINOR]
- **What:** `tools/modularize/retarget_tests.py` `_load_accept`, and its use in `main`. Entries are keyed on `(path, line, code)`. An entry that matches no refusal is silently ignored. The one entry (`tests/test_b103_copy_views.py:111 R1`) is already stale after the hand edit `ff7bf7e0`.
- **Why it matters:** A line-keyed allowlist drifts. A stale entry can later accept an unrelated refusal that lands on the same line.
- **Suggested fix:** After the scan, print `RETARGET NOTE stale-accept <entry>` for unmatched entries and exit 1 on them, or require `--allow-stale`.

### F6 — Test-semantics changes outside R-MOD.6.4's allowed set are not reflected in the requirement or hazards  [Severity: MINOR]
- **What:**
  - R-MOD.6.4 allows test edits only inside retargeter spans and H-12 rows. Three hand edits sit outside that set: `ff7bf7e0` (copy_views fixture, RC-C), `5b67c844` (`test_suite_hygiene.py:1229` literal), `a248edb8` (`test_id_registry.py` bound 307→309).
  - `d3556273` row 74 also drops the stale `s19_app.tui.a2l_parameter_picker` entry from `MEASURED_SAFE_TEXT_CONSUMERS` (`tests/test_import_census.py:66`). That turns a base failure into a pass (`test_tc653` failed→passed in after2). This is a test-semantics change, not a move.
  - All are recorded in `steps.log` / `g4-report.md`. None is in R-MOD.6.4, H-12 or the R-MOD.3.2 excuse list.
- **Why it matters:** Each edit is correct on its own (I checked all four; none weakens an assertion). The trace gap is that the batch's canon says these lines cannot change. The picker entry deserves separate attention: batch-102's comment says the picker escapes A2L names via `safe_text`. If the picker no longer does, that may be a pre-existing product gap. Dropping the entry closes the test without asking that question.
- **Suggested fix:** Add the three hand edits as rows to H-12 (or as an R-MOD.6.4 note), and list `test_tc653` as a known failed→passed with its reason. Open a backlog item: "a2l_parameter_picker: confirm hostile A2L names are scrubbed (batch-102 said via safe_text)".

### F7 — `package_source` merged-class floors have no negative test  [Severity: MINOR]
- **What:** `tests/test_package_source_helper.py` exercises the file floor (`test_too_small_package_trips_the_floor`) and the unknown-package refusal. It does not exercise the `merged_class` floors (`_MIN_MERGED_METHODS = 374`, `_MIN_CONTRIBUTING_CLASSES = 19`, `tests/support/package_source.py:36-37`). These floors are the only guard against `_merged_body` silently dropping a mixin whose base is not a bare `Name`, or that was removed from the header. Twelve adapted tests rely on that.
- **Suggested fix:** Add a test that copies the package to `tmp_path`, deletes one mixin from `core.py`'s class header, and asserts `merged_class(root=tmp_path)` raises `AssertionError` matching `expected at least 19`.

### F8 — Stale docstring after T6  [Severity: MINOR]
- **What:** `tests/test_b100_workers.py:399` still says "the Save worker's first placement (``app_module.place_into_workarea``)". The hold is on `app_module.deps` (`:402`).
- **Suggested fix:** Change it to `app_module.deps.place_into_workarea`.

### F9 — Code-size rule (report only; P3 owns it)  [Severity: MINOR]
Counted with `ast` (function length = decorator to `end_lineno`, docstrings included). Module length = physical lines.

| Package | Files | Modules > 300 lines | Functions | Functions > 40 lines | > 100 | > 200 |
|---|---|---|---|---|---|---|
| `s19_app/tui/app/` | 23 | 22 (all except `shared_io.py`, 33). Largest: `patch.py` 1851, `project_load.py` 1709, `file_load.py` 1645, `save_plan.py` 1616, `save_commit.py` 1588. `deps.py` 301, `__init__.py` 439 | 461 | 195 | 46 | 5 |
| `s19_app/tui/screens_directionb/` | 9 | 7. Largest: `patch_editor.py` 2806, `memory_map.py` 1911 (`deps.py` 9, `__init__.py` 199) | 225 | 62 | 7 | 1 |

Largest functions: `save_commit._save_project_files` 625, `save_plan._prepare_project_save` 416, `save_plan._plan_project_save` 323, `loaded_state._apply_prepared_load` 282, `patch.on_patch_editor_panel_action_requested` 223; sdb `patch_editor.compose` 357. R-MOD.4.1's own cap holds: the largest is `patch_editor.py` at 2806 lines against a cap of 3110. The known tool MINORs (`_scan_call` 63, `retarget_tests.main` 57, `scan_file` 49) stand as logged.

---

## Focus-area notes (checked, no finding)

- **deps.py / late binding.** No module outside `deps.py` / `__init__.py` imports a D1 name or loads one bare (an AST scan over both packages found 0 bare loads; the only D1 imports are `os` and `ListItem`, used in annotations, H-17). Every module reaches the seam through `from . import deps` (19 app modules plus `patch_editor`). `__init__` uses `from .deps import parse_a2l_cached` / `_json_clock` only as a re-export. Functions defined in deps (`parse_a2l_cached`, `_file_digest`, `recorded_document_state`, …) read `parse_a2l_file`, `os` and `open` as deps globals, so patches on `deps.X` reach them (RU-7). `deps.py` imports only `.shared` inside the package; `shared.py` imports nothing from the package, so there is no cycle. There are no `global` statements, and the `_LOG` logger name is unchanged (`"s19tui"`).
- **RC-C (`ff7bf7e0`).** The fixture now patches `app_deps._mirror_and_write_os_clipboard` unconditionally, replacing a conditional `__globals__` write. `core.py:1186` calls `deps._mirror_and_write_os_clipboard`. The patch is at least as strong as before.
- **Hygiene (`5b67c844`).** The literal now pins the `app_module.deps` form, which also guards against a revert. Correct.
- **id_registry (`a248edb8`).** +2 files (helper + its test). Correct.
- **package_source helper.** Fails loudly on floors, unknown package and missing `core.py`. It parses each file separately and merges in header order. `package_text` includes `__init__`/`deps`, but I found no presence assertion that the re-export lines make vacuous: presence checks target `from ...utils import safe_text` and label regexes.
- **P1c groups 1–4.** I read every hunk of `ce51e964`, `226867f1`, `d3556273` and `3093f618`. Path keys moved to the hosting files. Censuses now read `merged_class` / `package_tree` with the same or wider scope. `_callee_name` / `via_module` widenings keep exact-count assertions (9 placements, 2 emits). `test_tc_b100_72` narrows `funcs` to class methods, but lookups are by method name, so a miss would raise KeyError (loud). I found no removed assertion, no new skip/xfail and no loosened count, except F3.
- **Retargeter output.** Of 38 distinct `deps` patch targets, all are bound in `deps.py` except `open` (H-18). `test_b103_a2l_refresh` `module` is `importlib.import_module("s19_app.tui.app")`, so `module.deps` is correct.

## Requirements coverage (delta to `04-validation.md`, which already tracks the rest)

| Req | This review |
|---|---|
| R-MOD.7.2 | **FAIL:** two law-limb survivors (F1); TC-MOD-7L still has no run. |
| R-MOD.6.4 | Deviations not recorded in the canon (F6). |
| R-MOD.10.9 | Partially met (F4); current tree verified clean by grep/AST. |
| R-MOD.9.3 | Static evidence: both `__init__.py` exist and `pyproject.toml:104-105` uses `packages.find include=["s19_app*"]`, so 2/2 by construction. The negative half (delete `__init__` → 1/2) is not run. |
| R-MOD.3.1–3.3 | PENDING (after3). The after2 failed→passed set includes `test_tc653` (F6). |
| Others | As `04-validation.md`. I add no new evidence. |

## Evidence checklist

- [x] Diff read: all non-generated hunks of `tests/` (P1c four commits, RC-C, hygiene, id_registry, retargeter output sampled per file), `tests/support/package_source.py`, `tests/test_package_source_helper.py`, both `deps.py`, both `__init__.py` (imports), `shared_io.py`, `tools/modularize/{retarget_t6,retarget_scan,retarget_tests,test_patch_census,verify_names,compare_outcomes}.py`, `run_suite.sh` diffs since `94419c90`. Moved bodies: three spot-checked (equal).
- [x] Correctness pass: late binding, cycles, `global`, logger name, CSS path (`test_b100_workers.py:1131` resolves `../styles.tcss` correctly).
- [x] Simplicity pass: nothing over-built; T6 is the most complex addition and is scoped.
- [x] Reuse: F2 suggests reusing the census resolver for a permanent law.
- [x] Tests reviewed for intent: F1 (two dead limbs), F3 (looser), F7 (untested floor).
- [x] Verdict explicit: **BLOCK-UNTIL: F1**. F2 is MAJOR, recommended before merge.

Evidence states: F1 `executed` (static), mutants `not-run`; F2 `executed`; F3–F8 `executed`; F9 `executed`; suite outcomes `n/a — after3 is the orchestrator's`.

---

## Re-read (2026-11-13, commits `bd63404b`, `d71eec14`)

**Verdict: CLEAR. F1 and F2 are closed, and the batch can advance on this review.** The remaining MINOR items (F3–F9) go to the backlog. I re-read the diffs only: read-only, AST and git, nothing run.

- **F1, closed.**
  - `tests/test_b99_staging.py`: `_module_tail` now matches both `os.replace` and `deps.os.replace`, and does the same for `shutil.copy2`. The new positive control `test_tc_b99_13_census_sees_primitives_called_through_deps` checks two things: unlisted `deps.os.replace` and `deps.shutil.copy2` calls are reported (2 violations), and the same call inside the allow-listed `_restore_manifest` is not.
  - `tests/test_tui_directionb.py:8957`: the call set now includes attribute-form callees, so `deps.parse_a2l_file` hits the forbidden set.
  - Runner evidence (`evidence/e5-fix/f1nc.txt`): fixed laws GREEN on the tree; both mutants RED with the fixed laws; the same mutants GREEN with the pre-fix laws. That pair proves the gap was real and is now closed. Evidence state: `executed` (runner) / `approved` (re-read).
- **F2, closed.**
  - `tests/test_deps_seam_law.py` derives each seam set from the package's own `deps.N` reads, with floors (app ≥ 35, sdb ≥ 1) and two named spot names.
  - Product half: it flags any bare read of a seam name that no scope shadows, outside `deps.py` and `__init__.py`. An import does not count as a shadowing binding.
  - Test half: it flags every way of patching a seam name on a package root (`setattr`, `delattr`, `patch.object`, a string target, attribute assignment) and recognises the import-as, from-import and `import_module` alias forms. It has file and alias floors.
  - Three control tests cover both halves, including the shadowing and dead-import cases.
  - The docs note (`docs/architecture.md`, `CLAUDE.md`) states the rule.
  - Its limits are written in its own docstring: aliases passed through helpers are not followed, `open` is excluded (H-18), and an import with no bare read is not flagged. All three are acceptable.
  - Runner evidence is cited only in `steps.log` (6 passed; mutant A and mutant B RED). There is no transcript file under `evidence/e5-fix/`. That is a MINOR record gap, not a block. Evidence state: `executed` (runner, per steps.log) / `approved` (re-read).
- **No product or tool code changed** in these commits (`git diff 5b67c844..d71eec14 -- s19_app tools` is empty), so the move-identity evidence still holds.
- **New MINOR items:**
  - F2's mutant transcript is not committed.
  - `_test_violations` is 47 lines, over the 40-line function rule.
  - Dead seam-name imports remain (`ListItem` ×4, `os` in `file_load.py`) and go to P3.
  - The `CLAUDE.md` TUI bullet still says `app.py::S19TuiApp`.

  All four are already in the steps.log backlog line.
