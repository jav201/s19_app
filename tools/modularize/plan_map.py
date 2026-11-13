"""Generate the module map for the batch-modular split (read-only on product code).

Every top-level node of ``s19_app/tui/app.py`` and ``s19_app/tui/screens_directionb.py``
and every ``S19TuiApp`` method / class-body statement gets exactly one target module.

Order of decisions (app):
  1. core pins     -- class-body statements, ``__init__``/``compose``/``on_mount``,
                      methods with a zero-argument ``super()``, reactive watchers,
                      and Textual naming-convention handlers a test patches on the class;
  2. domain rules  -- first matching regex in ``APP_RULES``;
  3. affinity      -- unmatched methods go to the module holding most of their
                      self-call neighbours (both directions), iterated to a fixed point;
                      ties and isolated methods follow the previous method in source order.
Top-level defs (both files):
  * the D1 seam    -- names tests rebind on the module (from the test patch census) that
                      are DEFINED in the old module, plus every def they reference that itself
                      loads a D1 name, live in ``deps``;
  * private        -- a def used by exactly one target module goes to that module;
  * shared         -- anything else (several users, no users, or needed by a shared def);
  * shared_io      -- (app) a non-deps def that loads a D1 name, or needs one that does;
                      it sits above ``deps`` so ``deps`` stays a leaf.

Usage: python -I plan_map.py <repo_root> <test_patch_census.json> <out_module_map.json>
       [--rev <git rev>]   (default: working tree)
Exit 1 when a rule leaves a method unplaced, a module graph has a cycle, or a cap is exceeded.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

APP = "s19_app/tui/app.py"
SDB = "s19_app/tui/screens_directionb.py"
APP_PKG = "s19_app.tui.app"
SDB_PKG = "s19_app.tui.screens_directionb"

# Caps for THIS pass (R-MOD.5.x). The <=300 / <=40 caps are the later per-module pass.
CAP_MODULE = 2000      # body lines of any new module ...
CAP_CLASS_EXTRA = 300  # ... or its largest whole class plus this many lines, whichever is larger

CORE_PINNED = {"__init__", "compose", "on_mount"}

try:  # names the Textual App base defines; an override of one stays on S19TuiApp itself
    from textual.app import App as _TextualApp
    _APP_MEMBERS = frozenset(dir(_TextualApp))
except ImportError:  # pragma: no cover - the map must be generated with textual 8.2.8 installed
    sys.exit("plan_map: textual is required (pinned 8.2.8)")

# First match wins. Patterns are matched with re.search against the method name.
APP_RULES: list[tuple[str, str]] = [
    ("compose_screens", r"^_compose_screen_|^_compose_flow_builder_panel$|^_setup_datatable_columns$"),
    ("flow", r"^on_flow_|^_flow_|^_prefill_flow_|^_apply_flow_ref_choice$|^_open_file_ref_chooser$|^on_browse_requested$|^_publish_flow_session_dir$|^_loaded_artifact_paths$"),
    ("save_commit", r"^_abort_save$|^_restore_manifest$|^_keep_previous_manifest$|^_confirm_project_save$|^_commit_project_save$|^_save_project_worker$|^_save_project_files$|^_on_project_saved$|^_write_manifest_for_save$|^_write_and_verify_manifest$|^_surface_manifest_verify_result$"),
    ("reports", r"^_patches_dir$|^_scan_patch_change_files$|^_prefill_patch_change_files$|before_after"),
    ("patch", r"^on_patch_editor_panel_|patch|^_apply_changeset_json_edit$|^_apply_entry_json_edit$|^_strip_source_map$|^_hide_replaced_document_controls$|verify|^_report_change_result$|^_report_execution_results$|execute_scope|^_note_image_bytes_written$|after_write$"),
    ("checks_diff", r"check_editor|^_check_items_to_document$|ab_diff|^_diff_|^_prefill_diff_|^_apply_compare_request$|^_apply_diff_regime$"),
    ("reports", r"report|^_confirm_filter_selection$|^_change_|^_check_home$|^_spec_homes$|^_scan_spec_files$|^_resolve_listed_file$|^_refill_document_lists$|^_reopen_active_document$"),
    ("save_plan", r"save|^_decide_project_image$|^_plan_project_save$|^_assignment_candidate_files$|^_unrecorded_document_lines$|^_document_home_contained$"),
    ("project_load", r"^action_load_project$|^_confirm_then_load$|^_load_would_lose$|^_load_question_text$|^_route_load_project$|^_load_dialog_|^_file_preview_marks$|^_handle_load_result$|^_reset_project_session$|^_session_snapshot$|^_handle_load_project$|^_project_load_worker$|^_prepare_project_load$|^_on_project_load|^_install_prepared_project$"),
    ("file_load", r"^load_from_path$|^load_a2l_from_path$|^load_selected_file$|^action_load_file$|^_typed_load_route$|^_load_path_from_user_input$|^_handle_load_dialog$|^_start_a2l_load$|^_a2l_attach_worker$|^_on_a2l_attach|^_install_attached_a2l$|^_load_from_item$|^_load_workarea_file$|^_load_mac_file$|^_parse_loaded_file$|^_apply_loaded_file$|^_prepare_load_payload$|^_start_load_worker$|^_complete_prepared_load$|^_handle_load_error$|^refresh_files$|^action_refresh_files$|^action_open_workarea$|^_confirm_project_a2l_replacement$"),
    ("loaded_state", r"^_apply_prepared_load$|^_format_coexistence_status$|unload|^_refresh_loaded_panel$|^_merge_|^_log_loaded_file_summary$"),
    ("workspace_view", r"^update_sections$|^update_workspace_stats$|^update_memory_|^on_memory_map_panel_|^_jump_to_section$|^update_project_labels$|^_clip_to$|^_compose_context_line$|^_compose_project_label$"),
    ("projects", r"project|^_listed_project_name$|^_manifest_|^_a2l_admission$|^_derived_record$|^_sync_loaded_|^record_template_load$|^_parse_data_file$|variant|^action_operations_view$"),
    ("navigation", r"^on_list_view_|^on_data_table_row_|^on_input_changed$|^action_show_screen$|^key_condition$|^action_confirm_attention$|^action_open_split_join_export$|^action_show_legend$|^_apply_empty_state$|^on_rail_selected$|^_build_palette_entries$|command_bar|^on_key$|^action_cycle_density$|^_apply_width_regime$|^on_resize$|^action_page_|settings_menu|^_apply_viewer_setting$|^_is_layout_visible$|^_active_view_name$|^action_focus_|^_focus_local_input$|^_focus_needs_rehome$|^_focus_activity_rail$|^_fallback_focus_target$|^_resolve_focus_target$|^_rehome_|^_note_focus_landing$|^_land_focus$|^_load_tree_gone$"),
    ("a2l_view", r"a2l|^_tag_matches_filter$|^_jump_to_tag"),
    ("mac_view", r"mac|^_get_range_index$"),
    ("issues_checks", r"issue|^update_checks_view$|^on_check_row_selected$|^_update_checks_hex_pane$"),
    ("hex_view", r"hex|goto|search|^_snapped_focus_row_index$|^_row_start_for_near_top_focus$|^_reset_scroll_to_top$|^_get_window_bounds$|^_shift_window_for_index$|^_clamp_viewer_page_size$"),
    ("shell", r"^set_status$|^set_file_status$|^_append_log_line$|^_render_log_lines$|^set_progress$|^_paint_status_text$|busy|^_running_session_action$|^_progress_forwarder$|^_flush_logger$|clipboard|^_right_click_text$|quit"),
]

SDB_PANELS = {
    "RegionRow": "map_parts",
    "BandSegment": "map_parts",
    "BandBar": "map_parts",
    "MapRuler": "map_parts",
    "LoadedArtifactsPanel": "loaded_artifacts",
    "MemoryMapPanel": "memory_map",
    "PatchEditorPanel": "patch_editor",
    "CheckEditorPanel": "check_editor",
    "AbDiffPanel": "ab_diff",
}


def read_source(root: Path, rel: str, rev: str | None) -> str:
    if rev is None:
        return (root / rel).read_text(encoding="utf-8")
    out = subprocess.run(["git", "-C", str(root), "show", f"{rev}:{rel}"], capture_output=True, check=True)
    return out.stdout.decode("utf-8")


def bound_names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [(a.asname or a.name).split(".")[0] for a in node.names]
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    return [x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)]


def loads(node: ast.AST) -> set[str]:
    return {x.id for x in ast.walk(node) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}


def spans(body: list[ast.stmt], first_line: int) -> list[tuple[int, int]]:
    """Source line span of each statement, leading comments/blank lines included."""
    out, prev_end = [], first_line - 1
    for n in body:
        out.append((prev_end + 1, n.end_lineno))
        prev_end = n.end_lineno
    return out


def top_units(tree: ast.Module) -> list[dict]:
    """Top-level statements; an attribute docstring (bare string Expr) joins the previous unit."""
    units: list[dict] = []
    sp = spans(tree.body, 1)
    for node, (a, b) in zip(tree.body, sp):
        is_doc = isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        if is_doc and units and units[-1]["kind"] not in ("Import", "ImportFrom"):
            units[-1]["end"] = b
            units[-1]["nodes"].append(node)
            continue
        names = bound_names(node)
        units.append({"kind": type(node).__name__, "names": names, "start": a, "end": b, "nodes": [node],
                      "key": names[0] if names else f"{type(node).__name__}@{node.lineno}"})
    return units


def method_units(cls: ast.ClassDef) -> list[dict]:
    body = cls.body
    first = body[0]
    has_doc = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
    sp = spans(body, cls.lineno + 1)
    units = []
    for node, (a, b) in zip(body, sp):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            units.append({"kind": "method", "name": node.name, "start": a, "end": b, "node": node})
        else:
            label = "docstring" if (node is first and has_doc) else ",".join(bound_names(node)) or type(node).__name__
            units.append({"kind": "class_stmt", "name": label, "start": a, "end": b, "node": node})
    return units


def self_calls(fn: ast.AST) -> set[str]:
    return {n.func.attr for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "self"}


def has_zero_arg_super(fn: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "super" and not n.args
               for n in ast.walk(fn))


def core_pins(units: list[dict], class_patched: set[str]) -> dict[str, str]:
    pins = {}
    for u in units:
        name, node = u["name"], u["node"]
        if u["kind"] != "method":
            continue
        handler = re.match(r"^_?on_", name) is not None
        if name in CORE_PINNED:
            pins[name] = "pinned (constructor / compose / mount)"
        elif has_zero_arg_super(node):
            pins[name] = "zero-argument super()"
        elif name.startswith("watch_") or name.startswith("_watch_") or name.startswith("compute_") or name.startswith("validate_"):
            pins[name] = "reactive watcher/compute/validate"
        elif name in _APP_MEMBERS:
            pins[name] = "overrides a Textual App member (reach laws label it S19TuiApp.<name>, reason toolkit)"
        elif handler and name in class_patched:
            pins[name] = "Textual handler a test patches on the class (double dispatch if moved)"
        elif any(isinstance(d, ast.Attribute) and d.attr in ("setter", "deleter") for d in node.decorator_list):
            pins[name] = "PROPERTY_GROUP"  # resolved below: follows its getter
    return pins


def assign_methods(units: list[dict], class_patched: set[str]) -> tuple[dict[str, str], dict[str, str]]:
    methods = [u for u in units if u["kind"] == "method"]
    pins = core_pins(units, class_patched)
    target: dict[str, str] = {}
    how: dict[str, str] = {}
    for u in methods:
        n = u["name"]
        if n in pins and pins[n] != "PROPERTY_GROUP":
            target[n], how[n] = "core", "core: " + pins[n]
            continue
        if n in target:  # a property setter shares its getter's name
            continue
        for mod, pat in APP_RULES:
            if re.search(pat, n):
                target[n], how[n] = mod, f"rule {mod}"
                break
    _affinity(methods, target, how)
    return target, how


def _affinity(methods: list[dict], target: dict[str, str], how: dict[str, str]) -> None:
    edges: dict[str, Counter] = defaultdict(Counter)
    names = {u["name"] for u in methods}
    for u in methods:
        for c in self_calls(u["node"]) & names:
            if c != u["name"]:
                edges[u["name"]][c] += 1
                edges[c][u["name"]] += 1
    changed = True
    while changed:
        changed = False
        for u in methods:
            n = u["name"]
            if n in target:
                continue
            score = Counter()
            for nb, w in edges[n].items():
                if nb in target and target[nb] != "core":
                    score[target[nb]] += w
            if score:
                best = sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
                target[n], how[n] = best, f"affinity {dict(score)}"
                changed = True
    prev = "core"
    for u in methods:
        n = u["name"]
        if n not in target:
            target[n], how[n] = prev, "isolated: follows previous method"
        prev = target[n]


def place_top_defs(units: list[dict], users_of: dict[str, set[str]], d1: set[str], with_shared_io: bool) -> dict[str, str]:
    """Place top-level defs (non-import) of one old module; returns key -> module."""
    defs = {u["key"]: u for u in units if u["kind"] not in ("Import", "ImportFrom")}
    name_to_key = {n: u["key"] for u in defs.values() for n in u["names"]}
    refs = {k: {name_to_key[x] for n in u["nodes"] for x in loads(n) if x in name_to_key} - {k} for k, u in defs.items()}
    direct_d1 = {k for k, u in defs.items() if any(loads(n) & d1 for n in u["nodes"])}
    seam = {k for k, u in defs.items() if set(u["names"]) & d1}
    # a def a seam def needs that itself loads a D1 name must see deps' globals: it joins deps.
    grow = True
    while grow:
        grow = False
        for k in list(seam):
            for r in refs[k]:
                if r in direct_d1 and r not in seam:
                    seam.add(r)
                    grow = True
    place: dict[str, str] = {k: "deps" for k in seam}
    for k in defs:
        if k in place:
            continue
        mods = users_of.get(k, set())
        place[k] = next(iter(mods)) if len(mods) == 1 else "shared"
    _close_downward(place, refs, seam)
    if with_shared_io:
        _lift_io(place, refs, direct_d1, seam)
    return place


def _refs(units: list[dict]) -> dict[str, set[str]]:
    name_to_key = {n: u["key"] for u in units if u["kind"] not in ("Import", "ImportFrom") for n in u["names"]}
    return {u["key"]: {name_to_key[x] for n in u["nodes"] for x in loads(n) if x in name_to_key} - {u["key"]}
            for u in units if u["kind"] not in ("Import", "ImportFrom")}


def _direct_d1(units: list[dict], d1: set[str]) -> set[str]:
    return {u["key"] for u in units if u["kind"] not in ("Import", "ImportFrom") and any(loads(n) & d1 for n in u["nodes"])}


def _close_downward(place: dict[str, str], refs: dict[str, set[str]], seam: set[str]) -> None:
    """A shared (or deps) def may only need shared/deps defs: pull private ones down into shared."""
    changed = True
    while changed:
        changed = False
        for k, mod in list(place.items()):
            if mod not in ("shared", "deps"):
                continue
            for r in refs[k]:
                if place[r] not in ("shared", "deps"):
                    place[r] = "shared"
                    changed = True


def _lift_io(place: dict[str, str], refs: dict[str, set[str]], direct_d1: set[str], seam: set[str]) -> None:
    """Shared defs that load a D1 name (directly or through another shared def) go above deps."""
    lifted = {k for k, m in place.items() if m == "shared" and k in direct_d1}
    changed = True
    while changed:
        changed = False
        for k, m in place.items():
            if m == "shared" and k not in lifted and refs[k] & lifted:
                lifted.add(k)
                changed = True
    for k in lifted:
        place[k] = "shared_io"


def users_by_module(units_top: list[dict], method_units_: list[dict], mtarget: dict[str, str], extra_users: dict[str, set[str]]) -> dict[str, set[str]]:
    name_to_key = {n: u["key"] for u in units_top if u["kind"] not in ("Import", "ImportFrom") for n in u["names"]}
    users: dict[str, set[str]] = defaultdict(set)
    for u in method_units_:
        mod = mtarget.get(u["name"], "core") if u["kind"] == "method" else "core"
        for x in loads(u["node"]):
            if x in name_to_key:
                users[name_to_key[x]].add(mod)
    for k, mods in extra_users.items():
        users[k] |= mods
    return users


def module_graph(place: dict[str, str], units: list[dict], method_mod_loads: dict[str, set[str]]) -> dict[str, set[str]]:
    """Module -> modules it imports by name (the deps seam counts as an edge too)."""
    defs = {u["key"]: u for u in units if u["kind"] not in ("Import", "ImportFrom")}
    name_to_key = {n: u["key"] for u in defs.values() for n in u["names"]}
    g: dict[str, set[str]] = defaultdict(set)
    for k, u in defs.items():
        for n in u["nodes"]:
            for x in loads(n):
                if x in name_to_key and place[name_to_key[x]] != place[k]:
                    g[place[k]].add(place[name_to_key[x]])
    for mod, names in method_mod_loads.items():
        for x in names:
            if x in name_to_key and place[name_to_key[x]] != mod:
                g[mod].add(place[name_to_key[x]])
    return g


def find_cycle(g: dict[str, set[str]]) -> list[str] | None:
    color: dict[str, int] = {}
    stack: list[str] = []

    def visit(v: str) -> list[str] | None:
        color[v] = 1
        stack.append(v)
        for w in sorted(g.get(v, ())):
            if color.get(w) == 1:
                return stack[stack.index(w):] + [w]
            if w not in color:
                found = visit(w)
                if found:
                    return found
        stack.pop()
        color[v] = 2
        return None

    for v in sorted(g):
        if v not in color:
            c = visit(v)
            if c:
                return c
    return None


def plan_app(src: str, d1: set[str], class_patched: set[str]) -> dict:
    tree = ast.parse(src)
    units = top_units(tree)
    cls_unit = next(u for u in units if u["key"] == "S19TuiApp")
    cls = cls_unit["nodes"][0]
    munits = method_units(cls)
    mtarget, how = assign_methods(munits, class_patched)
    method_loads: dict[str, set[str]] = defaultdict(set)
    for u in munits:
        mod = mtarget.get(u["name"], "core") if u["kind"] == "method" else "core"
        method_loads[mod] |= loads(u["node"])
    other_units = [u for u in units if u["key"] not in ("S19TuiApp", "main")]
    users = users_by_module(other_units, munits, mtarget, {})
    main_unit = next(u for u in units if u["key"] == "main")
    for x in loads(main_unit["nodes"][0]):
        for u in other_units:
            if x in u["names"]:
                users[u["key"]].add("core")
    method_loads["core"] |= loads(main_unit["nodes"][0])
    place = place_top_defs(other_units, users, d1, with_shared_io=False)
    _settle_private(place, [u for u in other_units if u["kind"] not in ("Import", "ImportFrom")], set())
    _close_downward(place, _refs(other_units), set())
    _lift_io(place, _refs(other_units), _direct_d1(other_units, d1), set())
    graph = module_graph(place, other_units, method_loads)
    for mod in set(method_loads):
        if method_loads[mod] & d1:
            graph[mod].add("deps")
    for k, m in place.items():
        u = next(x for x in other_units if x["key"] == k)
        if m != "deps" and any(loads(n) & d1 for n in u["nodes"]):
            graph[m].add("deps")
    for mod in set(mtarget.values()) - {"core"}:
        graph["core"].add(mod)  # core imports every mixin for its class header
    return {"tree": tree, "units": units, "munits": munits, "mtarget": mtarget, "how": how,
            "place": place, "graph": graph}


def plan_sdb(src: str, d1: set[str]) -> dict:
    tree = ast.parse(src)
    units = top_units(tree)
    panel_keys = set(SDB_PANELS)
    users: dict[str, set[str]] = defaultdict(set)
    name_to_key = {n: u["key"] for u in units if u["kind"] not in ("Import", "ImportFrom", "If", "Expr") for n in u["names"]}
    for u in units:
        if u["key"] in panel_keys:
            for x in loads(u["nodes"][0]):
                if x in name_to_key and name_to_key[x] != u["key"]:
                    users[name_to_key[x]].add(SDB_PANELS[u["key"]])
    defs_units = [u for u in units if u["kind"] not in ("Import", "ImportFrom", "If", "Expr")]
    place = place_top_defs([u for u in defs_units if u["key"] not in panel_keys], users, d1, with_shared_io=False)
    # a private def used by another private def of a different module, transitively: settle by fixed point
    _settle_private(place, defs_units, panel_keys)
    for k, mod in SDB_PANELS.items():
        place[k] = mod
    for k, mod in list(place.items()):  # memory-map helpers live beside the map's parts
        if mod == "memory_map" and k != "MemoryMapPanel":
            place[k] = "map_parts"
    graph = module_graph(place, defs_units, {})
    return {"tree": tree, "units": units, "place": place, "graph": graph}


def _settle_private(place: dict[str, str], defs_units: list[dict], panel_keys: set[str]) -> None:
    name_to_key = {n: u["key"] for u in defs_units for n in u["names"]}
    changed = True
    while changed:
        changed = False
        for u in defs_units:
            k = u["key"]
            if k in panel_keys or place.get(k) in ("shared", "deps", "shared_io"):
                continue
            for x in set().union(*(loads(n) for n in u["nodes"])):
                r = name_to_key.get(x)
                if r and r not in panel_keys and r != k and place.get(r) not in ("shared", "deps", "shared_io", place.get(k)):
                    place[r] = "shared"
                    changed = True


def sizes_app(plan: dict) -> dict[str, int]:
    size: Counter = Counter()
    for u in plan["munits"]:
        mod = plan["mtarget"].get(u["name"], "core") if u["kind"] == "method" else "core"
        size[mod] += u["end"] - u["start"] + 1
    for u in plan["units"]:
        if u["kind"] in ("Import", "ImportFrom"):
            continue
        if u["key"] == "S19TuiApp":
            continue
        mod = "core" if u["key"] == "main" else plan["place"][u["key"]]
        size[mod] += u["end"] - u["start"] + 1
    return dict(size)


def sizes_sdb(plan: dict) -> dict[str, int]:
    size: Counter = Counter()
    for u in plan["units"]:
        if u["kind"] in ("Import", "ImportFrom", "If", "Expr"):
            continue
        size[plan["place"][u["key"]]] += u["end"] - u["start"] + 1
    return dict(size)


def reexports(units: list[dict]) -> list[str]:
    names: list[str] = []
    for u in units:
        if u["kind"] == "Expr":
            continue
        if u["kind"] == "If":  # TYPE_CHECKING block binds nothing at runtime
            continue
        for n in u["names"]:
            if n not in names and n != "annotations":
                names.append(n)
    return names


def emit(plan_a: dict, plan_s: dict, d1_app: list[str], d1_sdb: list[str], base: str) -> tuple[dict, list[str]]:
    errors: list[str] = []
    size_a, size_s = sizes_app(plan_a), sizes_sdb(plan_s)
    for mod, n in size_a.items():
        cap = CAP_MODULE
        if n > cap:
            errors.append(f"app.{mod}: {n} body lines > cap {cap}")
    biggest: dict[str, int] = {}
    for u in plan_s["units"]:
        if u["kind"] == "ClassDef":
            mod = plan_s["place"][u["key"]]
            biggest[mod] = max(biggest.get(mod, 0), u["end"] - u["start"] + 1)
    for mod, n in size_s.items():
        cap = max(CAP_MODULE, biggest.get(mod, 0) + CAP_CLASS_EXTRA)
        if n > cap:
            errors.append(f"screens_directionb.{mod}: {n} body lines > cap {cap}")
    for label, g in (("app", plan_a["graph"]), ("screens_directionb", plan_s["graph"])):
        cyc = find_cycle(g)
        if cyc:
            errors.append(f"{label}: import cycle {' -> '.join(cyc)}")
    app_methods = [{"name": u["name"], "line": u["node"].lineno, "span": [u["start"], u["end"]],
                    "module": plan_a["mtarget"][u["name"]], "how": plan_a["how"][u["name"]]}
                   for u in plan_a["munits"] if u["kind"] == "method"]
    class_stmts = [{"name": u["name"], "line": u["node"].lineno, "span": [u["start"], u["end"]], "module": "core"}
                   for u in plan_a["munits"] if u["kind"] == "class_stmt"]
    app_top = [{"key": u["key"], "kind": u["kind"], "names": u["names"], "span": [u["start"], u["end"]],
                "module": "core" if u["key"] in ("S19TuiApp", "main") else ("imports" if u["kind"] in ("Import", "ImportFrom") else plan_a["place"][u["key"]])}
               for u in plan_a["units"]]
    sdb_top = [{"key": u["key"], "kind": u["kind"], "names": u["names"], "span": [u["start"], u["end"]],
                "module": ("imports" if u["kind"] in ("Import", "ImportFrom", "If") else ("__init__" if u["kind"] == "Expr" else plan_s["place"][u["key"]]))}
               for u in plan_s["units"]]
    used = set(plan_a["mtarget"].values())
    mixin_mods = list(dict.fromkeys(m for m, _ in APP_RULES if m in used))
    out = {
        "base": base,
        "caps_this_pass": {"module_lines": CAP_MODULE, "largest_class_plus": CAP_CLASS_EXTRA},
        "app": {
            "package": APP_PKG,
            "mixin_order": mixin_mods,
            "class_header": "class S19TuiApp(" + ", ".join(_mixin_class(m) for m in mixin_mods) + ", App):",
            "d1_names": d1_app,
            "deps_defined": sorted(k for k, m in plan_a["place"].items() if m == "deps"),
            "reexports": reexports(plan_a["units"]),
            "sizes": dict(sorted(size_a.items())),
            "graph": {k: sorted(v) for k, v in sorted(plan_a["graph"].items())},
            "methods": app_methods,
            "class_statements": class_stmts,
            "top": app_top,
        },
        "screens_directionb": {
            "package": SDB_PKG,
            "d1_names": d1_sdb,
            "deps_defined": sorted(k for k, m in plan_s["place"].items() if m == "deps"),
            "reexports": reexports(plan_s["units"]),
            "sizes": dict(sorted(size_s.items())),
            "graph": {k: sorted(v) for k, v in sorted(plan_s["graph"].items())},
            "top": sdb_top,
        },
    }
    return out, errors


def _mixin_class(mod: str) -> str:
    return "".join(p.capitalize() for p in mod.split("_")) + "Mixin"


def main() -> int:
    args = sys.argv[1:]
    rev = None
    if "--rev" in args:
        i = args.index("--rev")
        rev = args[i + 1]
        del args[i:i + 2]
    root, census_path, out = Path(args[0]), Path(args[1]), Path(args[2])
    census = json.loads(census_path.read_text(encoding="utf-8"))
    d1_app = sorted(census[APP_PKG]["module_patches"])
    d1_sdb = sorted(census[SDB_PKG]["module_patches"])
    class_patched = set(census[APP_PKG]["class_patches"])
    plan_a = plan_app(read_source(root, APP, rev), set(d1_app), class_patched)
    plan_s = plan_sdb(read_source(root, SDB, rev), set(d1_sdb))
    result, errors = emit(plan_a, plan_s, d1_app, d1_sdb, rev or "WORKTREE")
    out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    for label in ("app", "screens_directionb"):
        r = result[label]
        print(label, "modules:", len(r["sizes"]), "sizes:", r["sizes"])
    hows = Counter(m["how"].split(" ")[0] for m in result["app"]["methods"])
    print("app methods:", len(result["app"]["methods"]), "by decision:", dict(hows))
    print("D1 app:", len(d1_app), "D1 sdb:", len(d1_sdb), "deps defined app:", result["app"]["deps_defined"], "sdb:", result["screens_directionb"]["deps_defined"])
    for e in errors:
        print("ERROR:", e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
