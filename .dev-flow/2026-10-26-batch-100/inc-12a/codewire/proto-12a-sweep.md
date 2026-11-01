# Code-Wire prototype — Inc 12a, group G-B: the labels and the backlog sweep (`s19_app/tui/app.py`)

Stage E2 of the design-first pipeline (`dev-flow-v3-beta`) for Inc 12a. This group covers the "Load" / "Projects" labels and the backlog sweep. It is a graph only: no stub, mark or other change in `s19_app/` of any tree. A new function is a node whose `func:` starts with "new". Base: main `8947666` (Inc 9a merged), plus three graphs that run before 12a:
- the 9b graph (`../../inc-9b-design/codewire/proto-9b-app.md`, `interfaces-9b.md`);
- the 10 graph (`../../inc-10-design/codewire/proto-10-app.md`, `interfaces-10.md`);
- the 11 graph (`../../inc-11-design/codewire/proto-11-app.md`, `interfaces-11.md`).

Line numbers are `8947666` lines of `s19_app/tui/app.py` unless another file is named. A node that one of those increments changes starts from that graph's body ("post-9b", "post-10").

Inputs:
- `../E1-requirements-draft.md` (§C LLR-173.2m; §C' LLR-172.4e, .4f, .5i, .5j, .5k, .6b, .6c; §D.2 token rows; §D.4 the 29 files);
- `../E1-scope.md` (§3 G-B slice B1–B7, G2);
- `../E1-rulings.md` (Q6, Q7, backlog);
- `../E2-rulings.md` (B5 rationale, LLR-172.5i absolute arms, re-pins);
- `baseline-12a.md`, `baseline-notes.md` (census B and C);
- `interfaces-12a.md` (FIXED: S-h, S-i, S-j, S-k, S-l are G-B's; this file changes no interface; see "Proposals to the orchestrator").

Probes. Four small probes ran on throwaway copies under `../work/gb/`, never on the checkout. They used the s19env interpreter (Python 3.11, Textual 8.2.8), `python -I`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1`, `LOCALAPPDATA=../work/gb/lad`, and no `NO_COLOR`.
- `../work/gb/tree` is `s19_app/` with only the 3 label edits of S-l, applied by `patch_labels.py` (each replacement matched exactly 1 line). `../work/gb/base` is the unmodified copy.
- `probe_gb.py` → `probe_gb.out.txt`: G1 palette, G3 the `lstat` predicate, G4 NUL, G5 suffixes. G2 (an SVG text count) is a broken probe and is not used; the SVG export encodes the key bar differently.
- `probe_gb2.py` → `probe_gb2.out.txt`: G6, other characters that the path calls refuse, through the base classifier.
- `probe_gb3.py` → `probe_gb3.out.txt` (labels) and `probe_gb3-base.out.txt` (base): G7, the key-bar rows at 80, 99 and 118 columns.
- `tests/test_b97_key_bar.py -k "row_one or tc_b97_70"` on `../work/gb/tree` with `GLOBAL_TEXTS` re-pinned to `^l Load` → `9 passed` (`keybar-run.txt`). With the old pin it gave `3 failed` (row 1 reads `^l Load`).

Conventions (as 9b, 10 and 11):
- `W` = this work area (`<base>/.s19tool/workarea`); `W/temp` = its temp folder; `<tmp>` = a temporary folder outside `<base>`.
- `pn(x)` = `painted_names([x])`, the batch's one scrub: Cc, Cf, Zl and Zp removed, an unpaired surrogate as U+FFFD, clipped to 120 characters ending in `…`.
- `LC(k, v)` = `LoadChoice(k, v)`.
- "Session digest" is the E1 tuple (`current_file.path`, image SHA-256, `current_project`, `current_a2l_path`, MAC path).
- "D set" = an unsaved patched byte, the Inc 10 question's trigger.
- `T[k]` = `_TYPED_REFUSAL_TOKENS[k]`, the 9b module constant.
- Every example states the 12a target unless it says "holds on base".

## E1 guess decision

| Guess | Decision | Reason |
|---|---|---|
| G2 `_loadable_suffix(name)` | **Dropped** (interface S-h) | The predicate already exists as `recent_kind(path) is not None` (`workspace.py:2139`). 9b's `_load_dialog_rows` reads it. A new function would be a second definition of the same rule, which LLR-172.4f forbids. |

## Owned nodes (8) and context (8)

- **6 changed:** `list_projects` (post-9b), `refresh_files`, `_typed_load_route` (post-9b), `_load_path_from_user_input` (post-10), `_handle_load_project` (post-10; G-B's part only: the listing block and the 6 shared refusal sentences, all before G-A's begin), `_load_workarea_file` (post-10).
- **1 data node changed:** `BINDINGS` (3 descriptions).
- **1 new:** `_listed_project_name`.
- **Retired:** none.
- **Context (unchanged, with a new reader or a new output):**
  - `_build_palette_entries` (its output follows `BINDINGS`);
  - `_TYPED_REFUSAL_TOKENS` (9b data, unchanged, now read by 7 painting sites);
  - `_load_dialog_rows` and `_load_dialog_verdict` (9b);
  - `_load_from_item` and `on_list_view_selected`;
  - `recent_kind` and `list_workarea_files` (`workspace.py`).

**Imports (app.py):** none new.
- `os`, `stat`, `workspace` and `_is_reparse_point` are imported on base and used by `_typed_load_route` and the A2L admission.
- `painted_names` and `safe_text` are imported on base.
- `recent_kind` joins the `.workspace` import at 9b (proto-9b-app "Imports").
- `_TYPED_REFUSAL_TOKENS` is a module constant of `app.py` itself (9b).

**State:** G-B adds no `self.<name> =` attribute, so TC-B100-09's live-source census (`test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census`) gains no row from this group.

## Nodes

S19TuiApp.BINDINGS (data)
req: LLR-173.2m, LLR-173.7
in:
out:
func: changed (`app.py:2122`, `:2127`, `:2135`), interface S-l. Three descriptions change; every key, action, `priority` and `show` value stays:
- `Binding("ctrl+l", "load_file", "Load", priority=True)` (was `"Load file"`);
- `Binding("l", "load_file", "Load", show=False)` (was `"Load file"`);
- `Binding("p", "load_project", "Projects", show=False)` (was `"Load project"`).
- `Button("Load project (p)", id="ws_load_project_button")` (`:2892`) is not a binding and keeps its text (ruling Q6).
- The palette (`_build_palette_entries`, one entry per action, first description wins), the key bar (`window_help.py`, reads the descriptions) and the `?` help panel follow with no other code change.
- The comment above `BINDINGS` (`:2115`–`:2118`) does not name the labels, so it is unchanged.
callers: `_build_palette_entries` (extractor: `compose`, direct :2767); the key bar (`window_help.py`, unmarked); Textual's binding dispatch and help panel.
module: s19_app/tui/app.py
examples: B12-01 (LLR-173.2m, palette, 4 assertions; probe G1, executed on the label copy) `app._build_palette_entries()` → the `load_file` entry is `PaletteEntry("Load", "load_file")` and the `load_project` entry is `PaletteEntry("Projects", "load_project")`. Labels `Load file` and `Load project` occur in `0` entries (`4` of `4`). Negative control: holds on base (probe p12a U3.1) → `('Load file', 'load_file')`, `('Load project', 'load_project')` → RED.
examples: B12-02 (LLR-173.2m, key bar row 1; executed on the label copy, `keybar-run.txt` and probe G7). At 118×54 and 220×60, on each of the 13 windows plus `split_join`, with the focus on the rail, on the first control and in the palette `Input`, row 1 is exactly `^k Palette`, `^d Density`, `^l Load`, `^s Save project`, `x Operations`, `? Help`, `q Quit`, `^p palette`. Row 1 holds `0` tokens `^l Load file`. At 99×30 row 1 is the same 8 tokens (G7). At 80×24 row 1 is the first 6 tokens, `^k Palette` … `? Help`, so `q Quit` and `^p palette` still drop: `^s Save project` alone keeps row 1 wider than the bar, so `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]` keeps its shape (measured, P-B2). Result: `9 passed` with `GLOBAL_TEXTS` re-pinned. Negative control (executed): the label copy with the base pin `^l Load file` → `3 failed` (`row == list(GLOBAL_TEXTS)` at 118×54 and 220×60; `row == list(GLOBAL_TEXTS_80)` at 80×24) → RED.
examples: B12-03 (LLR-173.2m boundary, key bar row 2 on Workspace; probe G7 against G7-base) row 2 at 80×24 is `Workspace`, `/ Find`, `g Go-to`, `, Hex-`, `. Hex+`, `k Legend`, `p Projects`, `? more`. At 99×30, `o Open workarea` follows `p Projects`; at 118×54, `o Open workarea` and `r Refresh workarea` follow. On base the same rows hold `p Load project` in the same place: the shorter label lets no extra token in at 80, 99 or 118 columns.
examples: B12-04 (ruling Q6) the Workspace window → `#ws_load_project_button` paints `Load project (p)` (holds on base; unchanged). In the 4 workspace cells at 120×30 and 160×40, the snapshot text `Load&#160;project&#160;(p)` stays after the regeneration.
examples: B12-05 (LLR-173.2m, structural; re-pins `test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` rows and `test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` markers) the `(key, action, description, show)` rows of `S19TuiApp.BINDINGS` hold `('ctrl+l', 'load_file', 'Load', True)`, `('l', 'load_file', 'Load', False)` and `('p', 'load_project', 'Projects', False)`. Every other row equals the base row, and `len(S19TuiApp.BINDINGS) == 42` is unchanged (executed on the base copy). `git diff main -- s19_app/tui/app.py` shows exactly 3 changed `Binding(` line pairs. The `ctrl+l` line is already sanctioned by the marker `'"ctrl+l", "load_file"'`. The `l` and `p` lines need two new markers, `'"l", "load_file"'` and `'"p", "load_project"'`. The `l` marker does not match the `ctrl+l` line, because that line has `+l"` where the marker has `"l"`. Negative control: without the two markers, `test_tc081_4_no_binding_diff` lists the 2 lines → RED. `test_at_b78_32` is already RED on base (baseline-notes census B2): see P-B4.
examples: B12-06 (LLR-173.7, the labels half of the TC-B100-66 scan) `Load` and `Projects` → `0` matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-` or `HLR-`.

S19TuiApp.list_projects
req: LLR-172.4e
in:
out: List[str] projects
func: changed (post-9b body, `:12096`). Step (3) loses its platform gate: `if os.name == "nt" and item.name.endswith((".", " ")):` (`:12122`) becomes `if item.name.endswith((".", " ")):`. The comment above it becomes: "E3 R14 / LLR-172.4e: Win32 opens `temp.` / `ab ` as `temp` / `ab`, so a name ending in a dot or a space would load another folder; it is left out on every platform, as the lister skips it (LLR-172.4d)." Every other step, the order, the on-disk spelling and the `OSError` propagation of `iterdir` are unchanged, and so are 9b's step (5) (`_folder_holds_project`) and its fail-open rule.
callers: `_handle_load_project` (via `_listed_project_name`; extractor on base: direct :11714); `_typed_load_route` (via `_listed_project_name`; extractor on base: direct :12871); post-9b `_load_dialog_rows`; plus 7 test files (E1 §3). After 12a the direct caller set is `_listed_project_name` and `_load_dialog_rows`. `action_load_project` stopped being a caller at 9b.
module: s19_app/tui/app.py
examples: B12-07 (LLR-172.4e, 2 platform arms; TC-B100-37 `tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform`) `W` holds `P`, `fw-v1.` and `fw-v2 `, each holding `project.json` and `firmware.s19`. On Windows the two folders are made through `\\?\` beside plain `fw-v1` and `fw-v2` folders (so their `lstat` finds a folder, as the existing test does). On the Linux CI they are made with plain names. Result: `list_projects() == ["P"]` on both. On Windows a second reading runs with `app.py`'s `os` seen as `posix` (the existing `_OsAsPosix` view, `tests/test_b100_recents.py:2538`) and also gives `["P"]`, so the Linux arm also runs on the Windows host (P-B1). Negative controls: holds on base (probe p12a U2.8) → the Windows arm already gives `['P']`. With the gate present (P12a-4, executed code read `:12122`) the Linux CI lists 3 projects, and the `_OsAsPosix` reading on Windows lists `fw-v1.` and `fw-v2 ` → RED on both hosts.
examples: B12-08 (re-pin, census C1) `tests/test_b100_recents.py::test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows` (`:2548`) pins the old CR9-9 scope: `assert "fw-v1." in off_windows`. At 12a it turns RED on every host. It is re-pinned as B12-07: `"fw-v1." not in native` and `"fw-v1." not in off_windows`. Its docstring cites LLR-172.4e as superseding CR9-9. Its negative-control sentence becomes "the gate put back → the `posix` reading lists `fw-v1.` → RED".
examples: B12-09 (LLR-172.4e consequence, Linux CI) the typed absolute `<W>/fw-v1.` → `_typed_load_route`: inside `W`; suffix `''` (probe G5: `Path("fw-v1.").suffix == ''`); the lstat walk finds a folder; `_listed_project_name("fw-v1.")` → `None` → `("refuse", "not a project")` → the status line `Project NOT loaded: '<W>/fw-v1.' is not a project — pick a project in the list.` On base the Linux CI routed it as `("project", "fw-v1.")`.
examples: B12-10 (holds, 9b) `W` holds `ab`, `cd`, `temp`, `patches`, an empty `e` and a junction `jx` → `["ab", "cd"]` (proto-9b-app B17, B18, unchanged).

S19TuiApp.refresh_files
req: LLR-172.4f
in:
out: None
func: changed (`:7302`), interface S-h. `files = list_workarea_files(self.workarea)` becomes `files = [p for p in list_workarea_files(self.workarea) if recent_kind(p) is not None]`. This is the same expression as 9b's `_load_dialog_rows` step (2), so both readers use the one predicate. Each kept path appends `ListItem(Label(safe_text(painted_names([path.name]))))` with `entry.data = path.name`, as on base. The log line `Workarea refreshed. files=%d` counts the kept rows (no test pins the text; grep of `tests/` → `0`). The docstring gains: "Only names whose suffix a loader accepts are listed (`recent_kind`, the predicate the Load dialog's files section reads; LLR-172.4f), so a sidecar dump such as `x.a2l.json` is not offered."
callers: `on_mount` (:7195) and `action_refresh_files` (:7327), unmarked. Extractor: `_handle_save_dialog` (direct :10601; post-11 in `_commit_project_save`), `load_a2l_from_path` (direct :13134), `load_from_path` (direct :13075, inside the `call_later` closure). All unchanged; G-A edits those three bodies but keeps the calls (seam SG-2).
module: s19_app/tui/app.py
modify: [UI: #files_list] (rows)
examples: B12-11 (LLR-172.4f, 1 list equality; TC-B100-37 `tc_b100_37_files_list_shows_loadable_suffixes_only`) `W/temp` holds `a.s19`, `b.hex`, `c.mac`, `d.a2l`, `d.a2l.json` and `e.txt` → `#files_list` rows (`item.data`, in order) `["a.s19", "b.hex", "c.mac", "d.a2l"]`, with `0` rows `d.a2l.json` or `e.txt`. Log `Workarea refreshed. files=4`. Negative control: holds on base (probe p12a U2.1) → 6 rows → RED.
examples: B12-12 (LLR-172.4f boundary; probe G5) `W/temp` holds `F.S19`, `g.srec`, `h.ihex`, `notes` (no suffix) and `x.a2l.json` → rows `["F.S19", "g.srec", "h.ihex"]`: the upper-case suffix is listed (`recent_kind(Path("F.S19")) == "s19"`), while `recent_kind(Path("x"))` and `recent_kind(Path("d.a2l.json"))` are `None` (`3` of `3` kept, `2` of `2` dropped). A `W/temp` holding only `d.a2l.json` → `0` rows: an empty list, as on base for an empty folder. `#files_list` paints no token line (none is asked).
examples: B12-13 (LLR-172.4f, structural, 1 assertion; TC-B100-37) an AST read of `app.py` finds a call `recent_kind(...)` in the body of `refresh_files` and in the body of `_load_dialog_rows` (`2` of `2`). Neither body compares a `.suffix` against a literal set or calls `.endswith(` with a suffix literal, so there is 1 loadable-suffix predicate. Negative control: `refresh_files` with its own `p.suffix.lower() in {".s19", …}` → no `recent_kind` call in it → RED. The B12-11 row count alone would pass that mutant, so this AST check is its RED.
examples: B12-14 (holds; census C2, C3) the TC-B100-39 hostile names (`[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, …; all `.s19`) are still listed with literal labels, and a pick loads the on-disk name (`tests/test_b100_recents.py:2771`, `:2805`, unchanged and passing). `test_tui_directionb.py::test_ac5_files_list_grows_beyond_legacy_cap` lists `.s19` files only, so it still holds.

S19TuiApp._typed_load_route
req: LLR-172.5i, LLR-172.5j
in: Path path
out: Tuple[str, str] route
func: changed (post-9b body, `:12759`), interfaces S-j and S-k. Two edits; every return value is otherwise unchanged:
- (S-j) The one post-9b `normalized = resolve_input_path(path, self.base_dir)` call (SEC9b-1) is wrapped as `try: normalized = resolve_input_path(path, self.base_dir)` / `except (OSError, ValueError, RuntimeError): return ("refuse", "not found")` (S12a-01). The catch must never narrow below that tuple.
- (S-k) The listing step (`:12870`–`:12882`) becomes `try: name = self._listed_project_name(typed_name)` / `except OSError: return ("refuse", "unreadable")`, then `if name is None: return ("refuse", "not a project")`. These are the same tuples as on base.
- The docstring's "never raises — every `OSError` becomes a reason" becomes "never raises: every `OSError`, and the `OSError` / `ValueError` / `RuntimeError` of a text the path calls refuse (a NUL, EACCES, ENAMETOOLONG), becomes a reason".
callers: `_load_path_from_user_input` (extractor: direct :12934); post-9b `_load_dialog_verdict`. Unchanged.
module: s19_app/tui/app.py
examples: B12-15 (LLR-172.5i, the relative NUL arm, regression, GREEN on the post-9b base) `_typed_load_route(Path("fw\x00.s19"))` → `("refuse", "not found")`, with `0` exceptions (probe p12a U2.6 and probe G6 on the 9b base).
examples: B12-16 (LLR-172.5i, the absolute NUL arms, regression, GREEN on the post-9b base; E2 ruling) `_typed_load_route(Path(<tmp> + "\\fw\x00.s19"))` → `("refuse", "not found")`, and `_typed_load_route(Path(<W> + "\\a\x00b"))` → `("refuse", "not found")` (probe G6, base). They stay green; they are not the requirement's RED.
examples: B12-17 (LLR-172.5i boundary; probe G6, base, Windows) the relative texts `fw?.s19`, `fw|.s19`, `fw<.s19` and `a:b.s19`, and the absolute `<tmp>\fw?.s19` → `("refuse", "not found")` each (`5` of `5`). Holds on base: on Windows only NUL raises; the other characters the path calls refuse already give `not found`.
examples: B12-38 (LLR-172.5i, the RED arm, S12a-01) `Path.exists` monkeypatched to raise `PermissionError` (EACCES) for the typed text, then to raise `OSError(errno.ENAMETOOLONG)`, each through `_typed_load_route` and through `_load_dialog_verdict`'s `#load_reason` (4 arms) → `("refuse", "not found")`, 0 exceptions, 0 loads, the token pair painted (4 of 4). Negative control: on base the catch is only `ValueError` / `RuntimeError`, so the `PermissionError` leaves the classifier and stops the app → RED.
examples: B12-18 (LLR-172.5j, unchanged tuples) with `W` holding `ab` (listed) and an unlisted, empty folder `zz`: `<W>\AB` → `("project", "ab")` on Windows (case folded by `normcase`); `<W>/zz` → `("refuse", "not a project")`; `list_projects` raising `PermissionError` (monkeypatched on the instance; `_listed_project_name` calls `self.list_projects()`) and the typed `<W>/ab` → `("refuse", "unreadable")`. Every 9b `_typed_load_route` example (proto-9b-app B23, B50, B53, B97) returns the same tuple. Negative control: a `_listed_project_name` that drops `normcase` → the `AB` arm gives `not a project` on Windows → RED (TC-B100-38 `route_matches_the_typed_folder_against_the_listing`, `:2605`).

S19TuiApp._listed_project_name
req: LLR-172.5j
in: str name
out: Optional[str] listed
func: new (interface S-k). The one comparison of a name against the project list: `return next((entry for entry in self.list_projects() if os.path.normcase(entry) == os.path.normcase(name)), None)`.
- It returns the on-disk spelling of the match (E3 R3), or `None`.
- An `OSError` from `list_projects()` propagates; each caller maps it as it does today.
- It paints nothing, writes nothing and keeps no state.
- Docstring: Summary (the one match, LLR-172.5j); Args; Returns; Raises `OSError`; Used by `_handle_load_project`, `_typed_load_route`.
callers: `_handle_load_project` (listing block); `_typed_load_route` (listing step). Exactly 2.
module: s19_app/tui/app.py
examples: B12-19 (LLR-172.5j, unit) `W` holds `ab` and `cd`, both listed:
  - `"ab"` → `"ab"`;
  - `"AB"` → `"ab"` on Windows and `None` on Linux (`normcase` folds case only on Windows);
  - `"ab."` → `None` (`normcase` keeps the dot, so a trailing-dot spelling never matches; E3 R14);
  - `"zz"` → `None`;
  - `""` → `None`.
  - Result `5` of `5`.
  - `list_projects` raising `PermissionError` → `pytest.raises(PermissionError)` (`1` of `1`).
examples: B12-20 (LLR-172.5j, AST census, 1 assertion; TC-B100-38 `tc_b100_38_one_project_match`) every `FunctionDef` in `app.py` whose body calls both `self.list_projects` and `os.path.normcase` → `["_listed_project_name"]` (exactly 1). `_typed_load_route` still calls `os.path.normcase` for its inside test, but it no longer calls `list_projects`. `_load_dialog_rows` calls `list_projects` without `normcase`. Negative control: executed P12a-4 → `["_handle_load_project", "_typed_load_route"]` (2) → RED.

S19TuiApp._load_path_from_user_input
req: LLR-172.5i, LLR-172.5k
in: Path path
out: None
func: changed (post-10 body, `:12905`).
- The NUL arm needs no edit here. `_typed_load_route` now returns `("refuse", "not found")` (B12-15), so the existing `not found` arm paints the line.
- (S-k) Two arms of the refusal chain read the table:
  - `value == "not a project"` → `reason, step = _TYPED_REFUSAL_TOKENS["not a project"]`, then `line = f"Project NOT loaded: '{t}' is {reason} — {step}."`;
  - the final `else` (`unreadable`) → `reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]`, then `line = f"Project NOT loaded: '{t}' {reason} — {step}."`.
  - Both texts equal the base sentences character for character (`:12950`, `:12962`–`:12965`).
- The other four arms (`not found`, `not a supported file`, `outside`, `link`) are unchanged. `link` keeps "passes through a link or junction", which is not the table's `link or junction` pair (9b G2 reason; outside the Q-7 census).
- `t = painted_names([str(path)])`, `self.set_status(safe_text(line).plain)` and the warning log are unchanged.
callers: `on_mount` (start-up `load_path`; extractor top-level :7228); post-9b `_handle_load_dialog` (`path`, `recent`, deferred). Unchanged.
module: s19_app/tui/app.py
examples: B12-21 (LLR-172.5i, the status-line NUL route, regression, GREEN on the post-9b base; TC-B100-38 `tc_b100_38_nul_in_typed_path_is_refused`) `_load_path_from_user_input(Path("fw\x00.s19"))` → `1` status line `File NOT loaded: 'fw.s19' not found — check the path.`. `pn` removes the NUL, a Cc character (probe G4: `painted_names(["fw\x00.s19"]) == "fw.s19"`). The arm also gives `0` exceptions, `0` loads (spies on `load_from_path` and `load_a2l_from_path`), the session digest unchanged, and `0` questions. The absolute `<tmp>\fw\x00.s19` → `1` line `File NOT loaded: '<pn(<tmp>\fw.s19)>' not found — check the path.` (the text is clipped to 120 characters when `<tmp>` is long). The RED for this requirement is the EACCES / ENAMETOOLONG arm (B12-38).
examples: B12-22 (LLR-172.5i, the Load dialog NUL route, regression, GREEN on the post-9b base) path mode, the `#load_path` value set to `fw\x00.s19`, then `enter` → `_load_dialog_verdict(LC("path", "fw\x00.s19"))` → `("not found", "check the path")` → `#load_reason` paints `not found — check the path`. The dialog stays open with the field unchanged: `0` dismisses, `0` status lines, `0` exceptions. The same holds for the absolute `<tmp>\fw\x00.s19`. With B12-21 that is `4` of `4` regression arms.
examples: B12-23 (LLR-172.5k, texts unchanged; TC-B100-38, -40 and -63 stay green) the typed `<W>/empty` (empty, not listed) → `Project NOT loaded: '<W>\empty' is not a project — pick a project in the list.` The typed `<W>/cd`, listed fail-open, with `_list_project_files` raising `PermissionError` (proto-9b-app B19) → `Project NOT loaded: '<W>\cd' could not be read — check that the folder can be opened, then load again.` Each line equals its base text (`2` of `2`).

S19TuiApp._handle_load_project
req: LLR-172.5j, LLR-172.5k
in: Optional[str] name
out: None
func: changed (post-10 body, `:11675`); G-B's part only (interface S-k). G-A's begin, steps, outcome and ends follow these refusals and are G-A's (seam SG-1).
- (a) The listing block (`:11709`–`:11739`) becomes:
  - `try: match = self._listed_project_name(name)`;
  - `except OSError:` → `reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]`; `self.set_status(safe_text(f"Project NOT loaded: '{painted_names([name])}' {reason} — {step}.").plain)`; the warning `Project load refused (could not be read): %r` unchanged; `return`;
  - `if match is None:` → `reason, step = _TYPED_REFUSAL_TOKENS["not a project"]`; `self.set_status(safe_text(f"Project NOT loaded: '{painted_names([name])}' is {reason} — {step}.").plain)`; the warning `Project load refused (not listed): %r` unchanged; `return`;
  - `name = match`; `project_dir = self.workarea / name`.
  - The `next(…normcase…)` expression leaves this function.
- (b) The other 4 shared sentences read the same table with the same two templates (A12a-01: after Inc 10 there are 6 sites here, 8 in all with `_load_path_from_user_input`):
  - the folder-refusal `unreadable` arm (`:11694`, `painted` already computed);
  - post-9b, the `_list_project_files` `OSError` catch (proto-9b-app B96);
  - post-9b, the `project.json` lstat gate `OSError` arm (proto-9b-app B99) — the `unreadable` pair;
  - post-9b, the `project.json` lstat gate not-regular arm (proto-9b-app B99) — the `unreadable` pair (corrected at close, SR-12a-3).
  - Every painted text is unchanged character for character.
- (c) Unchanged: the `link` and `outside` folder-refusal sentences; `Project not found: <pn(name)>` (post-9b); the A2L refusal (its reason is a variable); the `No supported files in project: <pn(name)>` line (post-10); and every logger message.
- All 6 G-B sentences sit before G-A's `project_load` begin (interface S-n, A12a-02: the begin is immediately before `build_variant_set`), so they paint no progress line and need no end.
callers: `_route_load_project` (inside Inc 10's `go`; extractor: direct :7478); 13 test files call it directly (post-10 census). Unchanged.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace, unchanged)
examples: B12-24 (LLR-172.5j, LLR-172.5k; TC-B100-38 `project_load_of_an_unlisted_name_is_refused` `:2460`) `_handle_load_project("E")`, where `E` is an empty folder that is not listed (9b) → `1` status line `Project NOT loaded: 'E' is not a project — pick a project in the list.`, `0` resets (spy on `_reset_project_session`), session digest unchanged. Negative control: a mutation that skips the `None` test → `validate_project_files` / `_list_project_files` runs on `E` → the TC's text assertion fails → RED.
examples: B12-25 (LLR-172.5j, Windows; TC-B100-38 `another_case_loads_the_listed_name` `:2487`) `_handle_load_project("AB")` with `ab` on disk → `current_project == "ab"` (the on-disk spelling) and `1` load.
examples: B12-26 (LLR-172.5k, 4 unreadable arms, texts unchanged) with project `P` and a `PermissionError` injected in turn into each place:
  - `list_projects` → `Project NOT loaded: 'P' could not be read — check that the folder can be opened, then load again.`;
  - `_project_folder_refusal` returning `"unreadable"` → the same line;
  - post-9b `_list_project_files` (proto-9b-app B96) → the same line;
  - post-9b, the `project.json` lstat gate `OSError` arm (proto-9b-app B99) → the same line.
  - Each arm gives `0` resets, `0` raises and the session digest unchanged (`4` of `4`); TC-B100-38 `unreadable_folder_paints_could_not_be_read` (`:2649`) stays green.
  - Negative control: a template that drops `is` from the `not a project` arm, or adds it to the `unreadable` arm → B12-24 or B12-26 reads `'E' not a project` / `'P' is could not be read` → RED.

S19TuiApp._load_workarea_file
req: LLR-172.6b, LLR-172.6c, LLR-173.7
in: str name
out: None
func: changed (post-10 body; 9b's G1 node), interface S-i. The 10 body is: `candidate = self.workarea / WORKAREA_TEMP / name`; `if not candidate.exists(): return`; `kind`; `go`; `self._confirm_then_load(kind, name, go)`. 12a replaces its `exists()` test with a pick-time re-check that runs inside `go`, after the Inc 10 question is answered and immediately before the open (S12a-03):
- (1) Before the question: only `try: os.lstat(candidate)` / `except FileNotFoundError: return`, silent (9b B88 kept). The full re-check does not run here.
- (2) In `go`, immediately before the open:
  - `try: st = os.lstat(candidate)`:
    - `except FileNotFoundError: return`, silent (the entry vanished after the question);
    - `except OSError: st = None`, so the re-check fails closed.
  - `st is None or not stat.S_ISREG(st.st_mode) or _is_reparse_point(candidate)`:
    - `self.set_status(safe_text(f"File NOT loaded: '{painted_names([name])}' is not a regular file — pick another file.").plain)`;
    - `self.logger.warning("Workarea pick refused (not a regular file): %r", name)`;
    - `return`.
  - `st.st_size > workspace.DEFAULT_COPY_SIZE_CAP_BYTES`, read through the module at call time:
    - `self.set_status(safe_text(f"File NOT loaded: '{painted_names([name])}' is too large to open — load a smaller file.").plain)`;
    - `self.logger.warning("Workarea pick refused (too large): %r", name)`;
    - `return`.
- (3) Unchanged from Inc 10: `kind = "attach"` for a MAC or A2L suffix, else `"image"`; `go`; `self._confirm_then_load(kind, name, go)`.
- The re-check runs once, at use, so a refused pick may ask the question first. Both surfaces reach this function: `_load_from_item` (`#files_list`) and the 9b router (`workarea`). The A2L arm is re-checked too, before `load_a2l_from_path` and its own copy cap; the re-check matters mainly for the data arm, which has no other check (E2 ruling B5).
- The tokens are the §D.2 rows. Each line holds the name and paints with markup off (`set_status` → `_append_log_line`).
callers: `_load_from_item` (post-9b wrapper; its extractor caller is `on_list_view_selected`, direct :13183); `_handle_load_dialog` (`workarea` kind, deferred through `call_after_refresh`). Unchanged. The base caller check (extractor) lists `_load_from_item` ← `on_list_view_selected` only, and the node has no code on base.
module: s19_app/tui/app.py
modify: [I/O: workarea temp] (metadata read only)
examples: B12-27 (LLR-172.6b arm (a), `#files_list` route; TC-B100-39 `tc_b100_39_pick_rechecks_the_entry`) `W/temp/fw.s19` listed by `refresh_files`; the test replaces it with a folder `fw.s19` and does not refresh, then picks the stale row:
  - `1` status line `File NOT loaded: 'fw.s19' is not a regular file — pick another file.`;
  - `0` `_parse_loaded_file` calls (spy), the session digest unchanged;
  - with D set, the Inc 10 question is asked, and after `y` there are `0` parses (the re-check runs inside `go`, S12a-03).
  - Probe G3 (executed): `os.lstat` of a folder → `S_ISREG False`, so it is refused.
  - Negative control (executed, probe p12a U2.2): on base the pick parses the folder (`parse calls ['fw.s19']`, log `Load failed: [Errno 13] Permission denied: …`) → RED.
examples: B12-28 (LLR-172.6b arm (b)) as B12-27, with `fw.s19` replaced by a junction to a folder outside `W` (Windows; on Linux a directory symbolic link) → the same `1` line and `0` parses. Probe G3: `junc.s19` → `S_ISREG False`, `_is_reparse_point True`. Negative control (executed, probe p12a U2.3): on base the pick parses it → RED.
examples: B12-29 (LLR-172.6b arm (c)) as B12-27, with `fw.s19` replaced by a file symbolic link to `<tmp>/outside.s19` → the same `1` line, `0` parses, and `current_file` unchanged. Probe G3: `link.s19` → `S_ISREG False`, `_is_reparse_point True`. This arm needs the symbolic-link privilege; it was available on this host (probe p12a U2.4, probe G3). Where the link cannot be made, the arm is reported not run, never passed. Negative control (executed, probe p12a U2.4): on base the link's target is parsed and installed → RED.
examples: B12-30 (LLR-172.6b, the Load dialog route, 3 arms) as B12-27 to B12-29, but the pick is `LC("workarea", "fw.s19")` from the Load dialog's work-area row:
  - `_load_dialog_verdict` returns `None` with `0` `os.lstat` calls (9b B55 holds), so the dialog closes and `#load_reason` stays empty;
  - after the refresh the router calls `_load_workarea_file("fw.s19")` → the same `1` status line, `0` parses, the session digest unchanged.
  - With B12-27 to B12-29 that is `6` of `6` arms.
  - The refusal is a status line after the dialog closed, never a `#load_reason` token (E2 ruling B5).
examples: B12-31 (LLR-172.6c, 2 arms; TC-B100-39 `tc_b100_39_pick_over_cap_is_refused`) `monkeypatch.setattr(workspace, "DEFAULT_COPY_SIZE_CAP_BYTES", 1024)`:
  - `big.s19` of 1 025 bytes, picked → `1` line `File NOT loaded: 'big.s19' is too large to open — load a smaller file.`, `0` parses;
  - `edge.s19` of 1 024 bytes, picked → `1` parse (`_parse_loaded_file` called with it), no refusal line.
  - Result `2` of `2`.
  - The A2L arm: `c.a2l` of 1 025 bytes → the same refusal, with `0` calls of `load_a2l_from_path` (spy).
  - Negative control (executed, probe p12a U2.5): on base both picks parse (`parse calls ['edge.s19', 'big.s19']`) → RED. A mutation that reads the cap at import (`from .workspace import DEFAULT_COPY_SIZE_CAP_BYTES`) → the patch is not seen → `big.s19` parses → RED.
examples: B12-32 (failure path, 9b B88 kept) `W/temp/x.s19` deleted after it was listed, then picked → `os.lstat` raises `FileNotFoundError` → `0` loads, `0` status lines, `0` questions. Probe G3: a missing name gives `FileNotFoundError`.
examples: B12-33 (failure path, fail closed) `os.lstat` inside `go` raising `PermissionError` for `W/temp/x.s19` (monkeypatched for that call only) → `1` line `File NOT loaded: 'x.s19' is not a regular file — pick another file.`, `0` parses, `0` raises. Negative control: a re-check that lets other `OSError`s through to the `exists()` route → the parse runs, or the `PermissionError` leaves the `go` callback → RED.
examples: B12-34 (go arm, holds post-10) a regular `W/temp/x.s19` under the cap: with D set → `1` question (proto-10-app C38); without D → `1` load and `0` questions (C09 timing). A regular `x.mac` → `0` questions (attach). The re-check adds one `os.lstat` before the question and one inside `go` per pick, and changes nothing else.
examples: B12-39 (S12a-03, the swap arm) `W/temp/fw.s19` is a regular file when the pick starts (D set, the question is asked); before the user answers, the test swaps `fw.s19` for a folder; the user then answers `y` → the re-check inside `go` runs `os.lstat` on the swapped entry → `1` line `File NOT loaded: 'fw.s19' is not a regular file — pick another file.`, `0` parses. The pre-question `os.lstat` had already passed, so the question was asked; the swap is caught at use.
examples: B12-35 (LLR-172.6 hostile name in the refusal) `W/temp/[bold]x.s19` listed, then replaced by a folder → the line `File NOT loaded: '[bold]x.s19' is not a regular file — pick another file.` paints literally, with `0` spans (markup off).
examples: B12-36 (LLR-173.7, the G-B token half of the TC-B100-66 scan) the two refusal lines of B12-27 and B12-31 → `0` matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-` or `HLR-`. Each holds its §D.2 pair verbatim: `not a regular file` + `pick another file`, and `too large to open` + `load a smaller file` (`2` of `2`).

## Context nodes (unchanged)

_TYPED_REFUSAL_TOKENS (9b data) — unchanged. It holds the 6 pairs of proto-9b-app "Module constants". It is now read by the 8 shared Load-path sentences: 2 in `_load_path_from_user_input` and 6 in `_handle_load_project` (A12a-01).
req: LLR-172.5k
examples: B12-37 (LLR-172.5k, AST census, 2 assertions; TC-B100-38 `tc_b100_38_one_wording_table`, scope ruling Q-7) in `_handle_load_project`, `_load_path_from_user_input` and `_typed_load_route`, the literal text of every `str` constant, and of every f-string with its placeholders written `{}` (adjacent literals already joined by the parser, docstrings excluded), is checked:
  - (1) `0` texts contain `Project NOT loaded` together with `not a project` or `could not be read`;
  - (2) the module defines each of the two pairs once, and every painted Load refusal sentence in those functions reads one of the two pairs — no sentence paints either reason as a literal. No exact site count is asserted (A12a-01: the count breaks on every future site and adds no protection).
  - Out of scope by name (Q-7): reason keys (`("refuse", "not a project")`, `value == "not a project"`); logger arguments (`Project load refused (could not be read): %r`); the A2L reason word (`a2l_reason = "could not be read"`, whose sentence takes it as a variable).
  - Negative control: on base, (1) counts `5`: `_load_path_from_user_input` `:12950`, `:12962`; `_handle_load_project` `:11694`, `:11716`, `:11733`. The `:11716` and `:11733` sentences are split over two literals, so they are found only after the join, which the AST gives (probe p12a U4.1 lists the pieces). Post-9b it counts `7` → RED.
  - A mutation that keeps one sentence literal → (1) counts `1` → RED.

_build_palette_entries — unchanged (`:7911`). Its output follows `BINDINGS` (B12-01). Extractor caller: `compose` (direct :2767).

_load_dialog_rows (9b) — unchanged. It is the second reader of `recent_kind` (B12-13). It still offers `.a2l` rows; `refresh_files` now offers the same set (`.mac` included), so the two lists agree on one fixture.

_load_dialog_verdict (9b) — unchanged. Its NUL arms change through the classifier (B12-22). For `workarea` it stays free of filesystem calls (B12-30).

_load_from_item, on_list_view_selected — unchanged (post-9b wrapper → `_load_workarea_file`). Extractor: `_load_from_item` ← `on_list_view_selected` (direct :13183).

recent_kind, list_workarea_files (`workspace.py`) — unchanged, read only. Extractor: `list_workarea_files` ← `refresh_files` (direct :7319). After 12a `refresh_files` also calls `recent_kind`.

load_from_path, load_a2l_from_path — G-A's nodes. Their own `resolve_input_path` calls (`:13033`, `:13089`) are reached only after the classifier accepted the text. A NUL text never reaches them by a typed route, so no `ValueError` arm is added there (no requirement asks for one).

## Entities

[UI: BINDINGS descriptions]
desc: one source for three surfaces (palette, key bar, help panel); 3 of 40 descriptions change.
sequence:
  palette: S19TuiApp.compose → S19TuiApp._build_palette_entries → BINDINGS (first description per action) → PaletteEntry("Load", "load_file"), PaletteEntry("Projects", "load_project")
  keyBar: window_help key bar → BINDINGS descriptions → row 1 `^l Load`; Workspace row 2 `p Projects`
  button: compose → Button("Load project (p)") (unchanged, Q6)

[I/O: workarea temp]
desc: enumerated only by `list_workarea_files`; both readers filter through `recent_kind`; a pick re-checks the entry with one `os.lstat`.
sequence:
  filesList: S19TuiApp.refresh_files → list_workarea_files → recent_kind filter → #files_list rows (data = on-disk name)
  dialogRows: S19TuiApp._load_dialog_rows → list_workarea_files → recent_kind filter → rows
  pick: S19TuiApp._load_from_item / S19TuiApp._handle_load_dialog (workarea) → S19TuiApp._load_workarea_file → os.lstat → [regular, under cap] → S19TuiApp._confirm_then_load → go
  pickRefused: S19TuiApp._load_workarea_file → os.lstat (folder | junction | link | over cap | other OSError) → set_status (1 line) → expect none (0 parses, 0 questions)
  pickVanished: S19TuiApp._load_workarea_file → os.lstat (FileNotFoundError) → expect none (0 lines)

[state: project list]
desc: listed by `list_projects` (trailing dot or space skipped on every platform); matched in one place.
sequence:
  typedProject: S19TuiApp._typed_load_route → S19TuiApp._listed_project_name → S19TuiApp.list_projects → normcase match → ("project", on-disk name) | ("refuse", "not a project") | OSError → ("refuse", "unreadable")
  pickedProject: S19TuiApp._handle_load_project → S19TuiApp._listed_project_name → match | None → T["not a project"] sentence | OSError → T["unreadable"] sentence

[path: typed text]
desc: a text the path calls refuse is classified, never raised.
sequence:
  nulStatus: S19TuiApp._load_path_from_user_input → S19TuiApp._typed_load_route → resolve_input_path (OSError | ValueError | RuntimeError) → ("refuse", "not found") → set_status `File NOT loaded: '<pn>' not found — check the path.`
  nulDialog: LoadDialog load → S19TuiApp._load_dialog_verdict → S19TuiApp._typed_load_route → ("refuse", "not found") → T["not found"] → #load_reason `not found — check the path` (dialog open)
  errnoStatus: S19TuiApp._load_path_from_user_input → _typed_load_route → resolve_input_path (PermissionError raised by Path.exists) → ("refuse", "not found") → set_status (the same `not found` line)

## Callers and what changes for each

| Caller (line) | Reaches | What changes for it |
|---|---|---|
| `compose` (:2767), palette | `_build_palette_entries` → `BINDINGS` | Entries `Load` / `Projects` (B12-01). |
| key bar, `?` help panel | `BINDINGS` | Row 1 `^l Load`; row 2 `p Projects`; packing unchanged (B12-02, B12-03). |
| `_load_dialog_rows` (9b) | `list_projects` | Never sees a dot- or space-ending folder, on any platform. |
| `_handle_load_project`, `_typed_load_route` | `_listed_project_name` (new) → `list_projects` | Same results; the one match lives in the new function (B12-18, B12-24, B12-25). |
| `on_mount`, `action_refresh_files`, `load_from_path` (`call_later`), `load_a2l_from_path`, `_commit_project_save` (post-11) | `refresh_files` | Loadable rows only (B12-11). |
| `_load_path_from_user_input`, `_load_dialog_verdict` | `_typed_load_route` | A NUL text is refused `not found`, never raised (B12-15, B12-21, B12-22). |
| `_load_from_item`, `_handle_load_dialog` (`workarea`) | `_load_workarea_file` | A folder, junction, link or over-cap file paints 1 refusal line and loads nothing, inside `go`, after the question (B12-27 … B12-33) (corrected at close, D-6). |

## Seams with G-A (the indicator, same file)

| Id | Seam | G-B side (this design) | G-A must | Example |
|---|---|---|---|---|
| SG-1 (S-k) | `_handle_load_project`, the one shared function | G-B edits 6 sentence sites and the listing block, all before the `project_load` begin; E4 runs G-B first (E1 "Sequencing") | place the begin immediately before `build_variant_set` (A12a-02), after every G-B refusal (the `project.json` gate included); do not add an end to a G-B refusal (no run exists there) | B12-24, B12-26 |
| SG-2 | `refresh_files` call sites in G-A bodies | the body filters; the signature `refresh_files() -> None` and its main-thread use are unchanged | keep the calls in `load_from_path` (`call_later`), `load_a2l_from_path` and `_commit_project_save`; their order relative to `step_busy` / `end_busy` does not matter to the list | B12-11 |
| SG-3 | `_load_workarea_file` → `load_a2l_from_path` (G-A begins `a2l_load`) and `load_selected_file` (not a long action at 12a) | the re-check and its two refusals run before the Inc 10 question and before any begin | nothing; a refused pick never reaches a begin. 12b's C4 (data arm onto `_start_load_worker`) goes after step (4) | B12-27, B12-31 |
| SG-4 | status writers | every G-B line is a `set_status` (status log) line; G-B never calls `set_file_status` | the pending rule (LLR-176.1h) applies to `set_file_status` only; a G-B refusal written while a run shows the progress line adds 1 log line and leaves `#status_text` alone | B12-21, B12-27 |
| SG-5 | TC-B100-66 scan (LLR-173.7) | supplies the labels `Load`, `Projects` and the two token lines | supplies the 7 progress labels and the step names; one scan, two string sets | B12-06, B12-36 |
| SG-6 | TC-B100-09 attribute census | `0` new `self.<name> =` | adds `_busy` to `SNAPSHOT_EXCLUSIONS` (interface S-b) | — |
| SG-7 | snapshot cells | the label change moves the 29 files (re-pin note below) | its one `styles.tcss` rule moves `0` cells (interface S-g); one regeneration run at close covers both | B12-02 |
| SG-8 | shared test files | `test_b100_recents.py` (TC-B100-37, -38, -39 arms), `test_b100_load_dialog.py` (TC-B100-41 labels arm), `test_b97_key_bar.py`, `test_tui_diff_screen.py`, `test_tui_patch_history_strip.py` | `test_b100_load_dialog.py` (TC-B100-66 extension), `test_b100_busy.py`, `test_report_progress.py`, …; E4 merges the two edits of `test_b100_load_dialog.py` | — |

No seam needs an interface change.

## Re-pin note (tests; the implementer and tester act on it at E4)

| # | Test | Re-pin | Source |
|---|---|---|---|
| R-1 | `tests/test_b97_key_bar.py` `GLOBAL_TEXTS` (`:35`) | `"^l Load file"` → `"^l Load"`. `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]` keeps its shape (measured, B12-02). The comment at `:46`–`:48` becomes "with `^s Save project` still on row 1, `q Quit` and `^p palette` drop". | census B1; executed `9 passed` |
| R-2 | `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` (`:3690`–`:3716`) | rows `('l', 'load_file', 'Load', False)`, `('p', 'load_project', 'Projects', False)`; the `ctrl+l` row already says `Load`. Already RED on base for `ctrl+s` (`'Save'` vs `'Save project'`): see P-B4 | census B2 |
| R-3 | `tests/test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` (`:739`) | add the markers `'"l", "load_file"'` and `'"p", "load_project"'`, with a comment naming LLR-173.2m (Inc 12a) | census B3; B12-05 |
| R-4 | `tests/test_b100_recents.py::test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows` (`:2548`) | becomes B12-07 (skip on every platform; both readings `["P"]`-shaped) | census C1 |
| R-5 | the 29 snapshot files below | regenerated only through `.github/workflows/snapshot-regen.yml` | §D.4 |

**The 29 snapshot files (LLR-173.2m).** All live under `tests/__snapshots__/test_tui_snapshot/` and are named `test_tc016s_density_layout_snapshot[<cell>].svg`. The census was re-run on `8947666` by this group (grep of the pinned SVGs): 29 files hold `Load&#160;file` once each. The 6 workspace cells also hold the key-row token `Load&#160;project`, and 4 of those (120×30 and 160×40) also hold the button `Load&#160;project&#160;(p)`, which stays (ruling Q6). That makes 35 label cells, and no other pinned text changes: grep finds `0` SVGs holding `json` or `.txt`, so the `refresh_files` filter moves no cell.
1. `a2l-comfortable-120x30`
2. `a2l-comfortable-160x40`
3. `a2l-comfortable-80x24`
4. `a2l-compact-120x30`
5. `a2l-compact-160x40`
6. `a2l-compact-80x24`
7. `diff-comfortable-120x30`
8. `issues-comfortable-120x30`
9. `issues-comfortable-160x40`
10. `issues-comfortable-80x24`
11. `issues-compact-120x30`
12. `issues-compact-160x40`
13. `issues-compact-80x24`
14. `mac-comfortable-120x30`
15. `mac-comfortable-160x40`
16. `mac-comfortable-80x24`
17. `mac-compact-120x30`
18. `mac-compact-160x40`
19. `mac-compact-80x24`
20. `map-comfortable-120x30`
21. `map-comfortable-80x24`
22. `patch-comfortable-120x30`
23. `patch-comfortable-80x24`
24. `workspace-comfortable-120x30` (also `Load project`, and the button)
25. `workspace-comfortable-160x40` (also `Load project`, and the button)
26. `workspace-comfortable-80x24` (also `Load project`)
27. `workspace-compact-120x30` (also `Load project`, and the button)
28. `workspace-compact-160x40` (also `Load project`, and the button)
29. `workspace-compact-80x24` (also `Load project`)

**How they are regenerated.** They are regenerated only through `.github/workflows/snapshot-regen.yml` (`ubuntu-latest`, Python 3.11, `pytest-textual-snapshot==1.1.0`, `pytest tests/test_tui_snapshot.py -m snapshot --snapshot-update`), at close. Its artifact is downloaded, only these 29 files are committed, and the packet names them one by one. They are never regenerated locally on Windows. If Inc 9b, 10 or 11 rebaselines any of them first (none of their designs does: baseline-notes surprise 8), the census is re-run on the 12a tree and the packet names the final list. Expected drift per cell: row 1 `^l Load file` → `^l Load`. In the workspace cells, row 2 `p Load project` → `p Projects`, with the same tokens after it (B12-03, measured at 80, 99 and 118 columns).

## Findings

finding F-B1 the key bar's 80-column row does not regain `q Quit`
anchor: S19TuiApp.BINDINGS
seen: LLR-173.2m's threshold says the 80×24 set is "re-measured with the shorter label (the drop of `q Quit` and `^p palette` was caused by the longer labels …)". Measured on the label copy (B12-02, G7): row 1 at 80×24 is still the first 6 tokens. `^s Save project` keeps its long label (not in VS-PA-4), so row 1 stays wider than the bar.
decision: designed as measured: `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]` holds. P-B2 asks the orchestrator to correct the threshold's parenthesis.

finding F-B2 the Linux arm of LLR-172.4e can run on Windows
anchor: S19TuiApp.list_projects
seen: the existing test already reads `list_projects` with `app.py`'s `os` seen as `posix` (`_OsAsPosix`). With the gate removed, that reading must leave `fw-v1.` out, and the gate mutant lists it on Windows too.
decision: B12-07 keeps the `posix` reading. P-B1 proposes dropping E1's declaration that the Linux arm is not run on Windows. The Windows `\\?\` arm is still not run on Linux.

finding F-B3 two 9b dialog literals still hold the `unreadable` pair verbatim
anchor: _TYPED_REFUSAL_TOKENS
seen: `_load_dialog_rows`' projects token line (LLR-173.4m) and `_load_dialog_preview`'s error line (LLR-173.6k) paint `could not be read — check that the folder can be opened, then load again` as one literal each.
decision: out of LLR-172.5k's census by ruling Q-7 (Load-path sentences that reach `set_status` only), and not "project refusals". Left unchanged; P-B3 asks whether to read them from the table as well (2 lines).

finding F-B4 a work area on a cloud-synced volume
anchor: S19TuiApp._load_workarea_file
seen: `_is_reparse_point` is true for any file carrying `FILE_ATTRIBUTE_REPARSE_POINT`, which includes cloud placeholder files on some sync clients.
effect: such a file would be refused `not a regular file` at pick time. But `list_workarea_files` already refuses the same entries ("regular, non-link"), and `_typed_load_route` and `copy_into_workarea` use the same rule, so they are not listed in the first place.
decision: declared, consistent with the existing rule; no change.

## Design risks

- **R-B1 (time of check, time of use).** The re-check is one `os.lstat` inside `go`, immediately before the open (S12a-03); the window between the re-check and the open is microseconds, a declared residual. The pre-question `os.lstat` is a vanish probe only. The re-check closes the stale-row case SEC9-2 names (an entry replaced after the list was painted) and an entry swapped while the question is open (B12-39), not a hostile local race inside the microsecond window.
- **R-B2 (sentence frames still repeated).** LLR-172.5k puts the two token pairs in one table. The frame `Project NOT loaded: '<t>' [is ]<reason> — <step>.` is still written at the 7 sites. A helper would remove that copy, but the fixed interface lists only `_listed_project_name` for G-B and no requirement asks for it. B12-24 and B12-26 pin the frames' text, so a drifting frame turns RED.
- **R-B3 (`ctrl+s` row of `test_at_b78_32`).** It is RED before 12a. Re-pinning it is outside every 12a requirement (P-B4).

## Platform-dependent arms (reported not run where the platform cannot make the fixture, never passed)

- B12-07: the Windows `\\?\` arm on Linux.
- B12-18, B12-19, B12-25: the case-folding arms (`AB`) on Linux. Under `normcase` the expected Linux result is the `None` / `not a project` arm, so those arms run on Linux with the Linux expectation.
- B12-28: a junction on Linux, where a directory symbolic link stands in for it.
- B12-29: a file symbolic link where the privilege is missing.
- B12-17: the Windows-only characters.

## Proposals to the orchestrator

No interface change is proposed. Four decisions or text corrections are proposed:

- **P-B1 (LLR-172.4e threshold; E1-scope "Platform-dependent arms").** Keep the `_OsAsPosix` reading in TC-B100-37, so the gate mutant is RED on the Windows development host as well as on the Linux CI. Drop "its Linux arm on Windows" from E1's not-run declaration. Recommended: yes; it costs nothing, because the test already exists (B12-07, F-B2).
- **P-B2 (LLR-173.2m threshold text).** Replace "re-measured with the shorter label (the drop of `q Quit` and `^p palette` was caused by the longer labels; the measured set is recorded in the packet)" with "re-measured: the first 6 tokens of the re-pinned `GLOBAL_TEXTS` (`^s Save project` keeps row 1 wider than 80 columns, so `q Quit` and `^p palette` still drop)". Measured by B12-02 (F-B1).
- **P-B3 (LLR-172.5k scope).** The 9b dialog lines of LLR-173.4m and LLR-173.6k hold the `unreadable` pair as literals (F-B3). Option 1, recommended: leave them, as ruling Q-7 scopes the census to Load-path sentences. Option 2: read them as `" — ".join(_TYPED_REFUSAL_TOKENS["unreadable"])` (2 lines in 9b code, same text).
- **P-B4 (`test_at_b78_32_app_bindings_block_is_untouched`).** It is RED on base, because its `ctrl+s` row says `Save` and the code says `Save project` (batch-97 Inc-8 gate fold, LED-…97.38). Option 1, recommended: re-pin all three rows (`l`, `p`, `ctrl+s`) so the test turns green, and record in the packet that the `ctrl+s` row was red before 12a. Option 2: re-pin only `l` and `p` and leave it red.

## Requirement coverage (G-B)

| Requirement | Examples |
|---|---|
| LLR-173.2m | B12-01, B12-02, B12-03, B12-04, B12-05 (+ the 29-file re-pin note) |
| LLR-172.4e | B12-07, B12-08, B12-09 |
| LLR-172.4f | B12-11, B12-12, B12-13 |
| LLR-172.5i | B12-15, B12-16, B12-17, B12-21, B12-22, B12-38 |
| LLR-172.5j | B12-18, B12-19, B12-20, B12-24, B12-25 |
| LLR-172.5k | B12-23, B12-26, B12-37 |
| LLR-172.6b | B12-27, B12-28, B12-29, B12-30, B12-33, B12-35, B12-39 |
| LLR-172.6c | B12-31 |
| LLR-173.7 (G-B half: labels and the 2 token pairs, TC-B100-66 extension) | B12-06, B12-36 |
| TC-B100-41 (labels arm) | B12-01, B12-02 |
| TC-B100-37 (new arms) | B12-07, B12-11, B12-13 |
| TC-B100-38 (new arms) | B12-15, B12-20, B12-21, B12-22, B12-37 |
| TC-B100-39 (new arms) | B12-27 … B12-31 |

Failure paths, each with its own example:
- NUL relative (B12-15, B12-21, B12-22) and absolute (B12-16), regression; EACCES / ENAMETOOLONG (B12-38);
- listing `OSError` (B12-18, B12-19, B12-26);
- unlisted name (B12-24);
- pick: folder (B12-27), junction (B12-28), link (B12-29), dialog route (B12-30), over cap (B12-31), vanished (B12-32), other `OSError` (B12-33), swap between the question and `y` (B12-39).

Hold examples (no requirement, regression): B12-10, B12-14, B12-34.

**G-B requirements left uncovered: none.** Nodes: 8 owned (6 changed, 1 data, 1 new). Examples: 39 (B12-01 … B12-39).
