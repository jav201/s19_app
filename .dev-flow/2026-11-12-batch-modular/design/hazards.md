# batch-modular — hazards and rulings (E2)

Base `4f721985`. Each hazard was checked in the real code (AST / `symtable` probes over the two
old modules) and, where Textual is involved, in the installed Textual 8.2.8 source
(`textual/message_pump.py`, `dom.py`, `app.py`, `_path.py`, `reactive.py`,
`_work_decorator.py`; `textual.__version__ == "8.2.8"` in both local interpreters). Rulings are
binding on the mover (spec-move.md) and checked by the verifier (spec-verify.md).

## Summary

| Id | Hazard | Found at base | Ruling |
|---|---|---|---|
| H-1 | `@on(...)` handlers are collected by `_MessagePumpMeta.__new__` from the *class dict being created* into `_decorated_handlers`; dispatch reads `cls.__dict__["_decorated_handlers"]` per MRO class. A plain mixin has no metaclass → its `@on` handlers would never fire. | 0 `@on` methods in `S19TuiApp` | Any `@on` method stays in core (I-5); mover E8 refuses one in a mixin. |
| H-2 | `@work` | 8 methods (`thread=True`, explicit `group=`) | Safe to move: no class registry; worker name = `method.__name__`, group explicit. Moves with its decorator text. |
| H-3 | Naming-convention dispatch (`_get_dispatch_methods`): for **each** class in the MRO it calls `cls.__dict__.get("_on_X") or cls.__dict__.get("on_X")`. (a) `_on_X`+`on_X` split across classes would both fire. (b) A test that rebinds `S19TuiApp.on_X` while the original lives in a mixin gets **both** called (fake in `S19TuiApp.__dict__`, original in the mixin's). | (a) 0 pairs. (b) 2 handlers rebound on the class: `on_button_pressed` (test_b100_load_question.py:1098), `on_flow_execution_panel_external_step_confirmed` (test_b97_flow_execution.py:393) | (a) mover E10. (b) both pinned to core (I-5). Other handlers move: each name is defined once, so per-message dispatch order (S19TuiApp → mixins → App) is unchanged. |
| H-4 | Zero-argument `super()` binds `__class__` to the defining class. | 4 methods: `__init__`, `check_action`, `action_show_help_panel`, `on_event` (sdb: 24 calls, classes move whole) | Pinned to core; mover E9. (Moving would still resolve to `App` because names are unique, but pinning removes the question.) |
| H-5 | `reactive`/`var`, `watch_*`, `compute_*` | 1 reactive (`current_file`), 1 watcher | Reactives stay in core (class statements). `DOMNode.__init_subclass__` collects reactives over `reversed(cls.__mro__)` and watchers are found with `getattr`, so mixins would work, but `watch_*`/`compute_*`/`validate_*` are pinned for clarity. |
| H-6 | `CSS_PATH` is resolved by `_make_path_object_relative` against `inspect.getfile(obj.__class__)`'s directory, then `.resolve()`. `S19TuiApp` moves from `tui/` to `tui/app/`. | `CSS_PATH = 'styles.tcss'` | Rewrite to `"../styles.tcss"` (I-6 item 3) → resolves to the same file. test_b100_workers `_recording_app_cls` joins `Path(app_module.__file__).parent / css` → `tui/app/../styles.tcss`, exists. |
| H-7 | `BINDINGS` merged over `reversed(cls.__mro__)` (DOMNode bases only); actions via `getattr(namespace, "action_X")`; CSS bases via `_css_bases` (first DOMNode base). | — | Mixins are non-DOMNode: no binding/CSS change. `BINDINGS`, `ENABLE_COMMAND_PALETTE` (both rebound on the class by tests) stay in core. |
| H-8 | Name-mangled `self.__x` | 0 in both files | Nothing to do; mover would need no rewrite anyway since mangling uses the class name — a future `__x` in a mixin is mangled with the mixin name: E2 review item for the later pass. |
| H-9 | `nonlocal` / closures / nested classes | 1 `nonlocal` inside `_save_project_files` (stays inside the method); 0 nested classes in `S19TuiApp`; 18 nested `Message` classes in sdb widgets and `A2LTagTable.Measured` | All move with their enclosing unit. Message handler names come from `__qualname__.rsplit(".", 2)[-2:]` (`PatchEditorPanel.ActionRequested` → `on_patch_editor_panel_action_requested`), unchanged because the outer classes move whole. |
| H-10 | Module globals reassigned at runtime | 0 `global` statements; 0 product writes to these modules; logger is `logging.getLogger("s19tui")` (literal, no `__name__`) | Only tests rebind module globals → D1 seam (I-3). D1 names bound in a non-module scope: 0 (`symtable`), mover E6 guards it. |
| H-11 | `__file__` / `inspect` in product code | 0 uses in both files | Textual itself calls `inspect.getfile` for `CSS_PATH` (H-6) and for `CSS`/`DEFAULT_CSS` location labels (`read_from` tuples used in error messages and stylesheet de-duplication): moved widget/screen classes report their new file — no rendering change. |
| H-12 | Tests reading source text | 34 files / 81 functions + 1 module-level path (inventory below) | 54 need adaptation (11 would turn silently GREEN), 27 none. Four groups below; a shared helper first. |
| H-13 | Repo laws that census source/test files | see "Laws" below | Path keys, importer sets and the docs path law need edits; totals-only laws need none. |
| H-14 | Package namespace side effects | — | `dir(s19_app.tui.app)` gains submodule names; moved methods' `__qualname__`/`__module__` change (`ShellMixin.set_status`). Product code reads neither (grep 0). No star-import of either module exists. Accepted. |
| H-15 | Relative imports | app 52 top-level + 23 inside functions (`.services.*` 15, `.changes.io`, `..validation.model`, …); sdb 14 top-level + `TYPE_CHECKING` `.models` + 1 nested | Level + 1 everywhere (I-6 item 2). |
| H-16 | AST columns are UTF-8 byte offsets | both files contain non-ASCII text | Mover converts byte → character offsets per line (spec-move §3). |
| H-17 | D1 names in annotations | app: `os` ×2 (`os.stat_result`), `ListItem` ×4 | Not rewritten (annotations are strings under `from __future__ import annotations`); module imports the name normally. Verifier excludes annotations from V6/V7. |
| H-18 | `open` rebound with `raising=False` | `open(` only in `_file_digest`, `recorded_document_state` | Both live in `deps`; a test setting `deps.open` shadows the builtin there as before. `deps` binds no `open`. |
| H-19 | Class patches on `S19TuiApp` (37 names) | all via `monkeypatch.setattr` | pytest reads `target.__dict__` for classes and deletes on undo when the attribute was inherited, so patching a mixin-held method on `S19TuiApp` shadows and restores correctly. Only Textual handlers suffer H-3(b). |
| H-20 | Methods overriding a Textual `App` member | 8: `__init__`, `compose`, `check_action`, `action_show_help_panel`, `on_event`, `copy_to_clipboard`, `action_help_quit`, `action_quit` | All pinned to core (RU-9): the reach law `test_b101_reach_and_reports_escape` gives an action its `toolkit` reason only on a class with a Textual base, and `test_b103_copy_quit_dialog` looks up the label `S19TuiApp.action_help_quit`. |
| H-21 | File-name parametrised test ids | `test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input[<p.name>]` sweeps `tui/**/*.py` with `ids=lambda p: p.name` | Ids `[app.py]`, `[screens_directionb.py]` vanish, ~33 appear, and duplicate names (`__init__.py`, `shared.py`, `deps.py`) renumber pytest's suffixes. Suite comparison treats this one family as a family (spec-verify B4). |
| H-22 | `pkgutil` / module walks | `test_address_census.py` imports `pkgutil` but never calls it | Nothing to do. |
| H-23 | Pre-existing vacuous test | `test_tui_patch_editor_b94.py::test_at_b94_08_variant_machinery_retired` reads `__import__("s19_app.tui.screens_directionb").__file__` = `s19_app/__init__.py` (top package) | Fixed as READ-PACKAGE in group 3 (stays GREEN: the only `patch_variant` text in sdb is a comment). Logged as a finding of this batch. |

## H-12 Source-reading tests — inventory and adaptation

Vocabulary. **MERGED-CLASS**: parse every `.py` of `s19_app/tui/app/` separately (sorted;
never concatenate for AST work — every file starts with `from __future__`), build one synthetic
`S19TuiApp` body = `S19TuiApp` body + bodies of every class that is a base of `S19TuiApp`
inside the package; assert a floor (`core.py` exists, ≥ 374 methods, ≥ 19 classes).
**READ-PACKAGE**: module-wide walk over all files of the package (merged `ast.Module` list);
text concatenation only for pure regex/substring tests. **GETSOURCE-METHOD-OK**:
`inspect.getsource(S19TuiApp.m)` still returns the method from its mixin file (works for
`@work` methods; starts at the decorator). **PATH-KEY**: a path literal / derived path / key.
**[V]** = silently GREEN after the split if left alone (no floor).

Prerequisite (integrator, before the groups): `tests/support/package_source.py` with
`package_modules(pkg)`, `merged_class("S19TuiApp")`, `package_text(pkg)` (regex use only),
`tui_dir()`; each asserts its floor. It must pass `test_suite_hygiene` (no sleeps / wait loops).
Workers keep every test function name (`AT-TC-REGISTRY.jsonl` and `test_requirements_canon`
key on node ids).

Each row: test · how it reads · asserts · adaptation · negative control (one-line product
mutation on the moved tree that must turn the adapted test RED).

### Group 1 — app-class censuses, part 1 (7 files, 18 rows)

| # | Test | Reads | Asserts | Adaptation | Negative control |
|---|---|---|---|---|---|
| 1 | test_b100_a2l_progress::test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged | `rglob`, skips name `app.py`/`a2l.py` | `parse_a2l_file(` outside app has 1 positional arg | PATH-KEY: exclude by the `tui/app/` directory; assert it exists | 2-arg call in a services file |
| 2 | test_b100_busy::test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper | `APP_SOURCE` class body | `begin_busy(` only in `_busy_begin_action` | MERGED-CLASS [V] | `self.begin_busy(...)` in another mixin |
| 3 | test_b100_busy::test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event | class body | seam events per CENSUS fn, total 24 | MERGED-CLASS | delete a `step_busy` in `_start_generate_report_worker` |
| 4 | test_b100_busy::test_tc_b100_51_only_the_seam_sets_the_bar | class body | `set_progress`/`#progress_bar` only in the seam | MERGED-CLASS [V] | `query_one("#progress_bar")` in another method |
| 5 | test_b100_busy::test_tc_b100_51_workers_take_the_run_generation | module walk | 4 workers always get `gen=` (≥ 4 calls) | READ-PACKAGE | call `_start_load_worker(p)` without `gen=` |
| 6 | test_b100_busy::test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers | class body | 17 seam calls in named methods | MERGED-CLASS | remove `end_busy` from `_on_a2l_attach_failed` |
| 7 | test_b100_busy::test_tc_b100_51_every_save_abort_return_ends_its_run_first | 2 methods | abort returns use `_save_failure_outcome` | MERGED-CLASS | one abort arm returns a plain string |
| 8 | test_b100_busy::test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker | `load_from_path` | `copied.stat()` before worker start | MERGED-CLASS or GETSOURCE | swap the two lines |
| 9 | test_b100_load_dialog::test_tc_b100_40_one_router_receives_every_dialog_result | `tui/app.py` text | `LoadDialog` push sites = 2, one callback | READ-PACKAGE | own callback in `action_load_project` |
| 10 | test_b100_reuse::test_tc_b100_57_export_holds_no_byte_identity_rule | `rglob` + key `("s19_app/tui/app.py","_abort_save")` | byte-identity rule set | PATH-KEY → `s19_app/tui/app/save_commit.py` | add `a.read_bytes()==b.read_bytes()` elsewhere |
| 11 | test_b100_reuse::test_tc_b100_01_app_placements_name_the_workarea_root | `tui/app.py` text | 9 placements + 2 emits pass `workarea_root=` | READ-PACKAGE | drop `workarea_root=` once |
| 12 | test_b100_save_guards::test_tc_b100_07_ast_census_every_post_creation_return_removes | `tui/app.py` | 4 fns: rollback discipline | READ-PACKAGE | `raise` after mkdir in `_save_project_files` |
| 13 | test_b100_session_reset::test_tc_b100_09_domain_matches_the_live_source_census | class `self.X =` | census ≥ 60, all classified | MERGED-CLASS [V] | `self._brand_new = 1` in a mixin |
| 14 | test_b100_session_reset::test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag | same | census − base = `{_quit_pending}` | MERGED-CLASS | `self._pending_request = r` in a mixin |
| 15 | test_b100_session_reset::test_tc_b100_08_call_site_census | `rglob` | callers of `_reset_project_session` = `["tui/app.py"]` | PATH-KEY → the mixin file hosting `_install_prepared_project` (`project_load.py`) | second caller in another file |
| 16 | test_b100_session_reset::test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler | `rglob`, fn names | owners = `[_install_prepared_project]` | NONE | call it from `_handle_load_project` |
| 17 | test_b100_workers::test_tc_b100_53_workers_read_only_their_frozen_request | class methods + module fn | workers read only frozen request; reachability via `self.m()` | MERGED-CLASS [V] (callee in another mixin silently skipped) + READ-PACKAGE for `parse_a2l_cached` (now in `deps.py`) | `self.current_file` read in `_parse_data_file` |
| 18 | test_b100_workers::test_tc_b100_53_session_is_written_only_on_the_main_thread | class `self.X =` + CSS path | no off-main writes | MERGED-CLASS [V]; CSS path works with `"../styles.tcss"` (H-6) | worker-side write of a mixin-only attribute |

### Group 2 — app-class censuses, part 2 + name-keyed laws (10 files, 23 rows; 9 NONE)

| # | Test | Reads | Asserts | Adaptation | Negative control |
|---|---|---|---|---|---|
| 20 | test_b100_load_question::test_tc_b100_44_no_private_dirty_read_outside_the_panel | `Path(app_module.__file__).parents[1]` `rglob`, skips `screens_directionb.py` | 0 `<x>._dirty` reads outside the panel | PATH-KEY [V — narrows to `tui/`]: root `Path(s19_app.__file__).parent`, skip files under `screens_directionb/`; floor ≥ 60 files | `panel._dirty` in a mixin and in a non-tui module |
| 21 | test_b100_load_question::test_tc_b100_45_modal_imports_nothing_from_the_app | `Path(app_module.__file__).parent/"screens.py"` | modal uses no app/service names | PATH-KEY → `Path(s19_app.tui.screens.__file__)` | use a `..workspace` name in the modal |
| 22 | test_b100_load_question::test_tc_b100_46_project_load_handler_asks_nothing | module, `_handle_load_project` | 0 `push_screen` / `_confirm_then_load` | READ-PACKAGE or GETSOURCE | `self.push_screen(...)` in the handler |
| 23 | test_b100_load_question::test_tc_b100_72_every_load_call_passes_the_seam | class body loop | 0 loader calls outside the confirm seam | MERGED-CLASS [V] | direct `self.load_from_path(x)` in a leaf |
| 24 | test_b100_recents::test_tc_b100_37_one_function_enumerates_the_temp_folder | `rglob` | one enumerator (`workspace.py`) | NONE | `.iterdir()` on temp in a mixin |
| 25 | test_b100_recents::test_tc_b100_37_widened_census_and_one_enumeration_at_dialog_open | same | same + runtime | NONE | same |
| 26 | test_b100_recents::test_tc_b100_37_files_list_shows_loadable_suffixes_only_through_one_predicate | 2 methods | both call `recent_kind` | MERGED-CLASS | literal suffix set in `refresh_files` |
| 27 | test_b100_recents::test_tc_b100_38_one_project_match | class | one holder of list+normcase | MERGED-CLASS [V] | second holder in a mixin |
| 28 | test_b100_recents::test_tc_b100_38_one_wording_table | 3 methods + module | token pairs defined once | MERGED-CLASS + READ-PACKAGE (total stays 1) | duplicate a token tuple in a mixin |
| 29 | test_b100_save_dialog::test_tc_b100_47_one_preparation_ast_census | class `if name in methods` | save rules only in `_prepare_project_save` | MERGED-CLASS [V] | `sanitize_project_name` in `_confirm_project_save` |
| 30 | test_b100_save_dialog::test_tc_b100_65_the_preview_and_the_dialog_list_nothing_themselves | 2 methods | no listing calls | MERGED-CLASS | `predict_placement` in `_compose_save_preview` |
| 31 | test_b100_save_dialog::test_tc_b100_65_first_frame_before_the_image_decision | `action_save_project` | no heavy calls | MERGED-CLASS or GETSOURCE | `self._decide_project_image()` in it |
| 32 | test_b99_staging::test_tc_b99_13_no_final_name_replace_outside_placement | `rglob`, allowlist key `s19_app/tui/app.py` | per-file function allowlist | PATH-KEY: one key per hosting mixin file (`_abort_save`, `_keep_previous_manifest`, `_restore_manifest` → `save_commit.py`; `_drop_orphan_md` (a nested function of `_start_diff_report_worker`) → `reports.py`; `action_dump_a2l_json` → `a2l_view.py`) | `path.unlink()` in an unlisted function |
| 33 | test_b103_copy_quit_dialog::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener | `_read_tree()["s19_app/tui/app.py"]` | label `S19TuiApp.action_help_quit` reasons {string, toolkit}; one `_CopyQuitScreen(` | PATH-KEY → `s19_app/tui/app/core.py` (action pinned to core, H-20) | remove the construction |
| 34 | test_b101_reach_and_reports_escape::test_r_dlg_14_1_every_dialog_has_an_opener | `rglob` | every dialog reached | NONE | delete a dialog's only opener |
| 35 | test_b101_reach_and_reports_escape::test_r_shell_keys_3_1_every_action_has_a_reach | `rglob` | every action reached | NONE given H-20 (App overrides stay in core) | `def action_dead(self)` in a mixin |
| 36 | test_command_bar_interlock::test_tc678_interlock_arm_shipped_surface_is_clean | `tui` `rglob` | 0 retired ids | NONE | `Static(id="command_bar_row")` in a mixin |
| 37 | test_crc_designer_view::test_orphaned_per_toggle_helper_is_deleted | `rglob` | helper name 0 hits | NONE | re-add the name |
| 38 | test_crc_designer_view::test_tc514_every_switch_construction_site_is_on_the_crc_designer | `rglob` | `Switch(` only in crc view | NONE | `Switch(` in a panel |
| 39 | test_universal_paste::test_ac1_no_tui_module_constructs_a_stock_input[*] | per-file param | no stock `Input(` | NONE in code; ids change (H-21) | `Input(...)` in a mixin |
| 40–42 | test_b103_clipboard_core: `test_r_tui_044_1_18_…`, `test_r_paste_18_8_…`, `test_r_paste_19_1_and_33_1_…` | `rglob`, totals | box class totals | NONE | stock `Input(` / `TextArea(` in a mixin |

### Group 3 — screens_directionb side, patch strips and the docs law (9 files, 27 rows; 10 NONE)

| # | Test | Reads | Asserts | Adaptation | Negative control |
|---|---|---|---|---|---|
| 43 | test_b101_doc_hygiene::test_r_doc_dev_11_1_overview_names_every_window | regex over `rail.py` + `app.py` text | 12 rail labels; one split/join palette entry | READ-PACKAGE (text join ok) | delete one RailEntry / duplicate the palette entry |
| 44 | test_b101_doc_hygiene::test_r_doc_ref_1_1_named_paths_exist | tracked docs naming paths | every named path exists | PATH-KEY in **docs**: README.md:101, PROJECT_RULES.md:136, CLAUDE.md:79, docs/architecture.md:18,237,241,243,251,261,268,271,276,283,284 → the folder or the new file (new files must be git-added; do not rely on the "moved" removal word) | leave one old path |
| 45 | test_b97_patch_editor (module constant `STYLES = Path(sdb.__file__).parent/"styles.tcss"`) | path | — | PATH-KEY → `.parent.parent` | — |
| 46 | test_b97_patch_editor::test_tc_b97_03_columns_once_and_no_geometry_pass | `Path(sdb.__file__).parent/"app.py"` | `_apply_window_geometry` absent from app | PATH-KEY + READ-PACKAGE (app package) | add the name in an app mixin |
| 47–50 | test_b97_patch_editor: `test_tc_b97_04_e3_pairs_absent`, `…_patch_rules_scoped_and_check_rule_untouched`, `…_no_unscoped_patch_rule_in_the_whole_stylesheet`, `test_tc_b97_40_labelled_form_and_chips_in_the_inspector` | `STYLES` | stylesheet rules | via row 45 | restore a banned rule / change `$rule` |
| 51 | test_tui_directionb::test_tc028_screens_directionb_imports_no_processing_libs | `mod.__file__` text | no bincopy/pya2l/crcmod import | READ-PACKAGE [V] | `import bincopy` in a panel file |
| 52 | test_tui_directionb::test_tc028_screens_directionb_imports_no_processing_libs_after_inc10 | same | same | READ-PACKAGE [V] | `import crcmod` in `shared.py` |
| 53 | test_tui_directionb::test_tc026_patch_editor_panel_is_presentational | `getsource(getmodule(PatchEditorPanel))` | module imports nothing from changes/cdfx | READ-PACKAGE (getmodule narrows to one file) | `from ...changes.io import x` in any sdb file |
| 54 | test_tui_directionb::test_tc_042_10_markup_safe_renderables_and_no_from_markup | sdb text | 0 `Text.from_markup`; exactly one `markup=True` | READ-PACKAGE [partly V] | `Text.from_markup(x)` in a panel |
| 55 | test_tui_directionb::test_tc_042_12_memory_strip_touches_no_frozen_path | `getsourcefile(...).endswith("app.py")` + identity | renderer lives in the app module | OTHER: assert the file is under `tui/app/` | move the method out of the package |
| 56–59 | test_tui_directionb: `test_tc028_memory_map_renderer_adds_no_coverage_computation`, `…_patch_editor_renderer_invokes_no_patch_logic`, `…_diff_renderer_invokes_no_diff_logic`, `test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers` | getsource of one method | — | NONE (GETSOURCE) | add a forbidden call |
| 60 | test_tui_patch_card::test_writer_census_every_app_site_pushes_mem_map | app module text | `refresh_entries` passes `mem_map=` (≥ 4) | READ-PACKAGE | drop `mem_map=` once |
| 61 | test_tui_patch_card::test_writer_census_panel_selfcall_supplies_none | panel module text | one self-call without `mem_map` | OTHER: `inspect.getfile(PatchEditorPanel)` | pass `mem_map=None` |
| 62–64 | test_tui_patch_card: `test_tc080_5_no_apply_path_reachable`, `test_tc080_2_c7_purity_probe`, `test_tc080_7_card_renders_no_file_derived_row_text` | getsource method/class | purity | NONE | `self.app.x` / `.write_text(` |
| 65 | test_tui_patch_checks_strip::test_tc078_3_both_sites | `getsource(app_module)` | exactly 3 `refresh_check_results` sites with aggregates | READ-PACKAGE | drop `aggregates=` |
| 66 | test_tui_patch_checks_strip::test_tc078_2_aggregates_param | getsource(class) | purity | NONE | `self.app` |
| 67 | test_tui_patch_history_strip::test_tc081_2_strip | getsource(class) | purity | NONE | `self.app` |
| 68 | test_tui_patch_history_strip::test_tc081_3_sites | `Path("s19_app/tui/app.py")` | 4 `set_undo_redo_enabled` calls pass depths | READ-PACKAGE | 5th call without depths |
| 69 | test_tui_patch_history_strip::test_tc081_4_no_binding_diff | `git diff main -- s19_app/tui/app.py` | no unsanctioned `Binding(` change | OTHER: net multiset of `Binding(` lines over `s19_app/tui/app.py` + `s19_app/tui/app/` | new `Binding("x","y")` in core |
| 70 | test_capped_text_area::test_five_construction_sites_yield_capped_text_area | sdb text + `getattr(sdb, ctor)` | ids built by `CappedTextArea` subclass | READ-PACKAGE (re-export of imported names exists, I-2) | bare `TextArea` for `#patch_paste_text` |
| 71 | test_tui_patch_editor_b94::test_at_b94_08_variant_machinery_retired | reads `s19_app/__init__.py` (H-23) | no `patch_variant` constant | READ-PACKAGE (fixes a pre-existing vacuity) | `id="patch_variant_select"` in a panel |
| 72 | test_tui_insight_style::test_tc078_4_microbar_unfloored | getsource method | no `floor=True` | NONE | add `floor=True` |

### Group 4 — set-equality / key-table laws and app text readers (8 files, 13 rows)

| # | Test | Reads | Asserts | Adaptation | Negative control |
|---|---|---|---|---|---|
| 73 | test_b97_key_bar::test_tc_b97_69_derived_rows_follow_their_guards | `DERIVED_GUARDS` keyed `(file, "Class.name")` — 17 app rows, 4 `AbDiffPanel.BINDINGS` rows; `__import__("s19_app.tui."+stem)` | guards sit in the named node; keys reach them | PATH-KEY + class key per row (`(…/app/navigation.py, "NavigationMixin.action_page_next_context")`; class attributes stay `core.py`/`S19TuiApp`); import the class from the package, not by stem | delete the `_active_screen_key != "a2l"` guard |
| 74 | test_import_census::test_tc653_safe_text_import_census | importer module-name set + sdb text | importer set; sdb has `from ..utils import safe_text` | COUNT/PATH-KEY: real importer module names (`s19_app.tui.app.<m>`), read all sdb files, expect `from ...utils import safe_text`; catch imports from `screens_directionb.*` | `def safe_text` in a panel |
| 75 | test_render_hexview::test_tc651_import_census_all_consumers_read_render_hexview | importer set | set equality | COUNT/PATH-KEY (as 74) | extra importer not in the set |
| 76 | test_render_hexview::test_tc652_wrapper_absence_and_renderer_surface | `tui/app.py` parsed with owner package `s19_app.tui` | app imports range_index + render.hexview, no tui.hexview | READ-PACKAGE with owner `s19_app.tui.app` | drop the range_index import |
| 77 | test_tui_commandbar::test_at_b78_13_the_seven_symbols_and_six_selectors_are_gone | class methods | deleted adapters absent | MERGED-CLASS [V] | re-add an adapter in a mixin |
| 78 | test_tui_commandbar::test_tc_b79_05_every_cited_symbol_anchor_resolves | corpus incl. both old files; members of `S19TuiApp` | every cited anchor resolves | PATH-KEY + MERGED-CLASS: corpus = all files of both packages | cite `S19TuiApp.no_such_member` in a mixin comment |
| 79 | test_tui_hexview::test_tc_023_app_does_not_import_private_hexview_helpers | app text | no `_x` from `tui.hexview` | READ-PACKAGE [V] | `from s19_app.tui.hexview import _x` in a mixin |
| 80 | test_tui_variants::test_no_new_parse_loaded_file_call_sites | app text, fn-keyed | caller sets | READ-PACKAGE | new caller of `_parse_loaded_file` |
| 81 | test_filename_markup_safety::test_at_s3_dynamic_notify_sites_pass_markup_false | app text | dynamic `notify` passes `markup=False` (≥ 3) | READ-PACKAGE | remove one `markup=False` |
| 82 | test_tui_report_attribution::test_tc570_generation_is_outside_every_valueerror_guarded_span | `getsource(app_module)` | no ValueError guard around generation | GETSOURCE on `S19TuiApp._start_generate_report_worker` | wrap in `try/except ValueError` |
| 83 | test_tui_report_attribution::test_tc572_the_tool_failure_sequence_exists_exactly_once | same, text slice | failure sequence once | GETSOURCE | duplicate the `Report failed:` build |

File counts: group 1 = 7, group 2 = 10, group 3 = 9, group 4 = 8 (34). Effective rows ≈ 18 / 14 / 15 / 13.

Mention-only (docstrings, comments, messages) and scan hits that target other modules need
nothing; they are listed in the inventory transcript summary: e.g. `b97_fixtures.py:173`,
`test_b100_reuse.py:887`, `test_tui_directionb.py` messages, and the `getsource` hits on
`flow_screens`, `services/*`, `screens.py`, `render/format`.

Out of the inventory (the retargeter's job, I-3): 150 + 1 patch sites.

## H-13 Laws

| Law | Breaks on | Action |
|---|---|---|
| a2l_progress row 1, load_question row 20 | file-name exclusion / `parents[1]` depth | rows 1, 20 |
| session_reset row 15, reuse row 10, staging row 32, copy_quit row 33 | path keys `s19_app/tui/app.py` | rows above |
| import_census 74, render_hexview 75–76 | importer sets name the old modules | rows above |
| doc_hygiene 43–44 | app text; docs name old paths | rows above + doc edits |
| patch_history_strip 69 | `git diff main -- app.py` | row 69 |
| test_universal_paste 39 | parametrised ids (H-21) | spec-verify B4 |
| reach_and_reports_escape 34–35, command_bar_interlock, crc_designer_view, clipboard_core, recents 24–25, session_reset 16, test_tui_patch_json hue census, test_address_census/origin, checks_engine import graph, tc028 root census, engine-unchanged | totals or name keys only | none |
| test_suite_hygiene, test_requirements_canon, test_id_registry, AT-TC-REGISTRY | constrain test edits | keep test names; no sleeps |
| `.github` workflows | path filters name neither file | none |

## Blocks for the mover

None. Two inputs the orchestrator must keep in step: re-run `test_patch_census.py` and
`plan_map.py` if Inc 1b changes product or tests later (D3), and refresh the map's `base`.
