# Measurements — batch-86 Phase 1 · probe transcripts (C-39)

> Executed 2026-08-24 at this worktree (`claude/batch-82-lane-a-scoping`, base `a112eeb`),
> Git Bash + `grep`, Python from `~/.claude/docs/tools/devflow-validate.py` imported for the
> in-memory rule arms. **§2.7 of `01-requirements.md` cites these blocks by id (M-1 … M-10).**
> If a number in the requirements disagrees with a transcript here, the transcript wins —
> and if a transcript disagrees with re-running its command, the re-run wins.
> **P2-iteration additions:** M-10 (the systematic bare-literal sweep — blocker B86-R2-01's
> discharge and the declared C-55 search-width guard), the M-1 line correction (B86-R2-03),
> the M-4 reclassification note, and M-9's invocation snippet (QA-F5).

## M-1 · Surface identification — who IS `screen_workspace`, and who mounts `#loaded_panel`

```
$ grep -rn "loaded_panel" s19_app   (excerpt)
s19_app\tui\screens_directionb.py:1837:        super().__init__(id="loaded_panel")
s19_app\tui\app.py:2066:            LoadedArtifactsPanel(),          # inside _compose_screen_workspace
s19_app\tui\app.py:8907:  panel = self.query_one("#loaded_panel", LoadedArtifactsPanel)

$ grep -c "screen_workspace" s19_app/tui/screens_directionb.py
1        # a docstring mention — the workspace is NOT in this file
$ grep -n "screen_workspace" s19_app/tui/screens_directionb.py
1784:            - ``S19TuiApp._compose_screen_workspace`` (mounts the widget).
# ⚠ CORRECTED at the P2 iteration (B86-R2-03): the first version located the hit at ":211",
# which its own command contradicts — :211 mentions #workspace_body, not screen_workspace.
# The count (1) and the verdict (docstring mention, wrong file for the surface) stand.

app.py structure (read, lines 1845-2071):
  compose()                 :1845 — yields #workspace_body holding the 10 rail screens
  _compose_screen_workspace :1963 — returns Container(_memstrip, LoadedArtifactsPanel(),
                                    _panes, EmptyStatePanel(), id="screen_workspace",
                                    classes="db-screen")            :2064-2071
```

**Verdict: the surface is an anonymous `Container` with `id="screen_workspace"`, built by
`S19TuiApp._compose_screen_workspace` (`s19_app/tui/app.py:1963-2071`). It is the mounter of
`#loaded_panel` (`app.py:2066`). The PLAN's candidate file (`screens_directionb.py`) holds the
PANELS, not the screen.**

## M-2 · Address enumeration over `_compose_screen_workspace` (app.py:2010-2071)

Read directly from the compose body. 24 id literals + 2 class literals + 1 id-less child type:

```
ids:   ws_load_project_button files_title files_list sections_title sections_list ws_left
       hex_title search_input search_button goto_input goto_button hex_controls hex_view
       hex_scroll ws_center ws_stats_title ws_stats a2l_title a2l_view a2l_scroll ws_right
       workspace_panes ws_memstrip screen_workspace
classes: db-pane (x3: :2017 :2033 :2044)  db-screen (:2070)
id-less child: EmptyStatePanel() (:2068) — class EmptyStatePanel(Static) at
       screens_directionb.py:144 sets NO id; queried BY TYPE at app.py:6049
       (screen.query_one(EmptyStatePanel))
```

## M-3 · Reacher census, in-scope (`grep -rl -F --include='*.py' --include='*.tcss' -- "$L" s19_app tests`)

```
== #ws_load_project_button :: 3  s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_patch_chips.py
== #files_title :: 1             s19_app/tui/styles.tcss
== #files_list :: 4              s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_snapshot.py
== #sections_title :: 1          s19_app/tui/styles.tcss
== #sections_list :: 4           s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_app.py tests/test_tui_directionb.py
== #ws_left :: 4                 s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_workspace_layout.py
== #hex_title :: 1               s19_app/tui/styles.tcss
== #search_input :: 7            s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_commandbar.py tests/test_tui_directionb.py tests/test_tui_goto_marker.py tests/test_tui_search_pagination.py tests/test_universal_paste.py
== #search_button :: 3           s19_app/tui/app.py tests/test_tui_commandbar.py tests/test_tui_patch_chips.py
== #goto_input :: 5              s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_commandbar.py tests/test_tui_directionb.py tests/test_tui_goto_marker.py
== #goto_button :: 2             s19_app/tui/app.py tests/test_tui_patch_chips.py
== #hex_controls :: 2            s19_app/tui/app.py s19_app/tui/styles.tcss
== #hex_view :: 5                s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_patch_variant.py tests/test_tui_workspace_layout.py
== #hex_scroll :: 5              s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_mac_layout.py tests/test_tui_workspace_layout.py
== #ws_center :: 3               s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_workspace_layout.py
== #ws_stats_title :: 1          s19_app/tui/styles.tcss
== #ws_stats :: 5                s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_snapshot.py tests/test_tui_workspace_insight.py
== #a2l_title :: 1               s19_app/tui/styles.tcss
== #a2l_view :: 3                s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py
== #a2l_scroll :: 2              s19_app/tui/styles.tcss tests/test_tui_directionb.py
== #ws_right :: 4                s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_workspace_layout.py
== #workspace_panes :: 3         s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py
== #ws_memstrip :: 5             s19_app/tui/app.py s19_app/tui/styles.tcss tests/test_tui_directionb.py tests/test_tui_snapshot.py tests/test_tui_workspace_insight.py
== #screen_workspace :: 3        s19_app/tui/app.py tests/test_tui_checks_screen.py tests/test_tui_directionb.py
== .db-pane :: 3                 s19_app/tui/styles.tcss tests/test_tui_snapshot.py tests/test_tui_theme.py
== .db-screen :: 1               s19_app/tui/styles.tcss
```

## M-4 · Per-PAIR classification — code reach vs docstring/comment mention

First code-like hit per `(address, .py file)` pair; `NO-CODE-LIKE-HIT` pairs re-probed with
quoted-literal grep (`"$L"` / `'$L'`), and by reading the hit line. Result classes:

**Code reachers (dependants)** — one probe line each (excerpt of the full first-hit sweep):

```
#ws_load_project_button | tests/test_tui_directionb.py | 8562: button = app.query_one("#ws_load_project_button")
#files_list   | s19_app/tui/app.py            | 5421: list_view = self.query_one("#files_list", ListView)   [in refresh_files, def :5419]
#files_list   | tests/test_tui_directionb.py  | 8463: files_h = app.query_one("#files_list").outer_size.height
#sections_list| s19_app/tui/app.py            | 10198: sections = self.query_one("#sections_list", ListView) [in update_sections]
#sections_list| tests/test_tui_app.py         | 1106: monkeypatch ... if selector == "#sections_list" ...
#sections_list| tests/test_tui_directionb.py  | 1047: "sections_list" if left.query("#sections_list") ...
#ws_left      | tests/test_tui_directionb.py  | 998:  app.query_one("#ws_left").region.width
#ws_left      | tests/test_tui_workspace_layout.py | 104: app.query_one("#ws_left").region.width
#search_input | s19_app/tui/app.py            | 11931: query = self.query_one("#search_input", Input)...     [in _handle_search]
#search_input | tests/test_tui_commandbar.py  | 234 · tests/test_tui_directionb.py 6422 · goto_marker 360 ·
                search_pagination 108 · test_universal_paste.py 172  (all query_one code)
#goto_input   | s19_app/tui/app.py            | 12001: raw = self.query_one("#goto_input", Input)...         [in _handle_goto]
#goto_input   | tests/test_tui_commandbar.py 415 · tests/test_tui_goto_marker.py 151 (code)
#hex_view     | s19_app/tui/app.py 10568 · directionb 1048 · patch_variant 108 · workspace_layout 95 (code)
#hex_scroll   | tests/test_tui_directionb.py  | 8178: "#hex_scroll", "#sections_list", "#ws_stats",  (selector list in code)
#hex_scroll   | tests/test_tui_workspace_layout.py | 96 (code)
#a2l_scroll   | tests/test_tui_directionb.py  | 8179: "#a2l_scroll", "#ws_memstrip",                 (same code list)
#ws_center    | directionb 999 · workspace_layout 105 (code)   #ws_right | app? NO / directionb 1000 · workspace_layout 97 (code)
#ws_stats     | app.py 10314 [in update_workspace_stats, def :10275] · directionb 7926 · workspace_insight 18→code (code)
#a2l_view     | app.py 11043 [in update_a2l_view] · directionb 1049 (code)
#workspace_panes | tests/test_tui_directionb.py | 2401: "hidden" in app.query_one("#workspace_panes").classes
#ws_memstrip  | app.py 10385 [in update_memory_strip] · directionb 8214 · workspace_insight 64 (code)
#screen_workspace | tests/test_tui_checks_screen.py 138 · tests/test_tui_directionb.py 1958 (code)
```

**Docstring/comment-only pairs (mentions — deliberately NOT declared, pilot D-D):**

```
(#ws_load_project_button, tests/test_tui_patch_chips.py)  :40  docstring id inventory
(#search_button, tests/test_tui_patch_chips.py)           :41  same docstring
(#goto_button,  tests/test_tui_patch_chips.py)            :41  same docstring
(#search_button, tests/test_tui_commandbar.py)            :224 docstring
(#goto_input,   tests/test_tui_directionb.py)             :6345 docstring
(#hex_scroll,   tests/test_tui_mac_layout.py)             :12  docstring
(#files_list,   tests/test_tui_snapshot.py)               :391 comment
(#ws_stats,     tests/test_tui_snapshot.py)               :537 comment
(#ws_memstrip,  tests/test_tui_snapshot.py)               :540 comment
(#ws_left,      s19_app/tui/app.py)                       :677 comment
(#ws_right,     s19_app/tui/app.py)                       :10278 docstring
(#hex_controls, s19_app/tui/app.py)                       :1981 docstring (compose docstring; provider)
(#hex_scroll,   s19_app/tui/app.py)                       :1982 docstring
(#search_button/#goto_button/#screen_workspace, s19_app/tui/app.py) — docstring hits only, BUT see M-5
(.db-pane,      tests/test_tui_snapshot.py)               :720 comment
```

> ⚠ **RECLASSIFIED at the P2 iteration (blocker B86-R2-01, discharged by M-10):** two of the
> pairs listed above as mentions are DEPENDANTS — the cited hit line is genuinely a docstring,
> but the same FILE also couples by BARE id elsewhere, which this probe (first-`#`-hit only)
> could not see: `(search_button, tests/test_tui_commandbar.py)` — `_B78_SEARCH_SURFACES`
> drives it at `:686`; `(goto_input, tests/test_tui_directionb.py)` — live assertion at
> `:6375`. The M-4 classification rule was per-pair; its EVIDENCE channel was `#`-literal
> only. M-10 is the width guard that closes that channel gap.

## M-5 · Bare-name couplings — dependants whose grep hit is prose (the F-2 accident mirrored)

```
$ grep -n '"ws_load_project_button"\|"search_button"\|"goto_button"' s19_app/tui/app.py
11837:  if event.button.id == "search_button":            [in on_button_pressed, def :11833]
11839:  elif event.button.id == "ws_load_project_button":
11843:  elif event.button.id == "goto_button":

$ sed -n '6008,6013p' s19_app/tui/app.py       (consumed by _apply_empty_state via f"#{id}")
    _EMPTY_STATE_SCREENS = (
        ("screen_workspace", "workspace_panes"), ...
```

`app.py` couples to `search_button` / `goto_button` / `ws_load_project_button` by BARE id
(event routing) and to `screen_workspace` / `workspace_panes` via f-string composition — real
dependants whose `#`-literal hits are docstrings. **Declared as consumers on that evidence.**

## M-6 · Population probes — shared classes and the one prefix collision

```
$ grep -rn 'classes="db-pane"' s19_app/         → 7 instances app-wide
  app.py:2017 :2033 :2044   (the 3 workspace panes)
  app.py:5196 :5219 :5279 :5297  (4 panes on OTHER screens; 5196 is `db-pane density-compact`)
$ tests/test_tui_theme.py:266  panes = app.query(".db-pane")   → app-wide query, `.first()` at :268
.db-screen: one per rail screen container (compose, 10 screens); only reacher = styles.tcss.

Prefix collision #ws_stats ⊂ #ws_stats_title — bare (non-title) hits per hit file:
  s19_app/tui/app.py            total=8 title=0 bare=8
  s19_app/tui/styles.tcss       total=2 title=1 bare=1
  tests/test_tui_directionb.py  total=5 title=0 bare=5
  tests/test_tui_snapshot.py    total=1 title=0 bare=1
  tests/test_tui_workspace_insight.py total=8 title=0 bare=8
→ every file in `#ws_stats`'s reacher set reaches the BARE id at least once; no file enters
  that population through the `_title` superstring alone.
```

## M-7 · V13-visible strays (tree minus `_V13_SKIP_DIRS`, V13 extensions, outside s19_app/tests)

```
#files_list      1  .fast-dev-flow/archive/2026-07-09-batch-31-quick-strike-spec.md
#sections_list   2  .fast-dev-flow/archive/2026-07-07-sections-label-spec.md · batch-31-quick-strike-spec.md
#ws_left         2  sections-label-spec.md · prototypes/screen_upgrades.HANDOFF-PLAN.md
#search_input    1  prototypes/cmdbar_a2bdiff.HANDOFF.md
#goto_input      1  prototypes/cmdbar_a2bdiff.HANDOFF.md
#hex_view        2  batch-31-quick-strike-spec.md · REQUIREMENTS.md
#hex_scroll      1  REQUIREMENTS.md
#ws_center       2  REQUIREMENTS.md · screen_upgrades.HANDOFF-PLAN.md
#ws_stats        1  REQUIREMENTS.md
#ws_right        1  screen_upgrades.HANDOFF-PLAN.md
#ws_memstrip     3  REQUIREMENTS.md · prototypes/legend_n8.INVENTORY.md · screen_upgrades.HANDOFF-PLAN.md
#screen_workspace 4 .fast-dev-flow/archive/2026-07-20-unload-feature-spec.md · REQUIREMENTS.md ·
                    docs/architecture.md · prototypes/legend_n8.INVENTORY.md
.db-pane         1  REQUIREMENTS.md
(all other enumerated literals: 0 strays)
Σ out-of-scope stray pairs over the DECLARED outputs = 21 (the `.db-pane` pair drops out with
D-86-A; `#screen_workspace`'s 4 count toward `screen_root`).
```

## M-8 · Pre-state verdicts (before this batch's record existed — the recorded RED arm)

```
$ python ~/.claude/docs/tools/devflow-validate.py .        (2026-08-24, pre-edit; excerpt)
  [-] V10  01-requirements.md: 9 FLOW node(s), every one owned
  [-] V11  01-requirements.md: 5 OUTPUT(s), each with an address and a declared consumer list
  [!] V12  .dev-flow/2026-08-21-batch-85/01-requirements.md:334: COMPONENT loaded_panel: parent
           `screen_workspace` is not declared in this document, so balancing was NOT checked; this is not a pass
  [!] V13  ...:339 loaded_panel/panel_handle: 2 undeclared file(s) — n6-n7-spec.md, legend_n8.INVENTORY.md
  [!] V13  ...:349 loaded_panel/slots_container: 1 undeclared file(s) — s19_app/tui/screens_directionb.py
  [!] V13  ...:363 loaded_panel/artifact_slots: 1 undeclared file(s) — 2026-08-21-batch-85-ifc-pilot-promoted-spec.md
  [-] V14  01-requirements.md: 15 declared consumer(s), every one resolved
  [-] V19  01-requirements.md: 1 COMPONENT id(s), each declared exactly once
  [-] V21  01-requirements.md: 5 OUTPUT owner(s), every one declared
tail: 2 block · 233 notice · 14 not applicable
  [x] V20 ATLAS-ORPHANS.md + [x] V20 ATLAS-TRACE.md — Atlas stale at batch open (pre-existing;
  regenerated at this station's gate)
```

## M-9 · In-memory RED/GREEN arms for the balancing claim (pure rule cores; tree untouched — C-40)

`_v12_outcome` / `_v21_outcome` imported from the validator and fed the pilot's parsed shape
plus the PLANNED `screen_workspace` declaration. **Scope of proof (per QA-F3): these arms
demonstrate RULE SENSITIVITY — they feed pre-parsed dicts and bypass the parse path; the
parse-path evidence over the real record is the LIVE counted GREEN run (V21's counted
owners line, V12's single specific finding), and one copy-protocol M5 execution is owed at
Phase 4 beside M4/M7.** Invocation (re-runnable, QA-F5):

```python
import importlib.util, os
spec = importlib.util.spec_from_file_location(
    "dv", os.path.expanduser("~/.claude/docs/tools/devflow-validate.py"))
dv = importlib.util.module_from_spec(spec); spec.loader.exec_module(dv)
pilot = {"id": "loaded_panel", "line": 334, "src": "b85",
         "outputs": [{"id": i} for i in ("panel_handle", "slots_container",
                                         "slot_rows", "artifact_slots", "project_row")],
         "fields": {"parent": "screen_workspace",
                    "inputs": "loaded: Optional[LoadedFile] ; project: str"}}
def ws(inputs, outs):
    return {"id": "screen_workspace", "line": 1, "src": "b86",
            "outputs": [{"id": o} for o in outs], "fields": {"parent": "workspace_body",
            "inputs": inputs}}
# GREEN: dv._v12_outcome([pilot, ws(FULL_IN, OWN + RE)])   # FULL_IN/OWN/RE per section 5.3
# RED 1: FULL_IN without "loaded: ..."  · RED 2: OWN only (re-export omitted)
# V21 RED: dv._v21_outcome([comp with owner "LLR-86.99"], {"LLR-86.2"})
```

```
GREEN arm (planned record):
  ('NOTICE', ..., 'COMPONENT screen_workspace: parent `workspace_body` is not declared ...')   ← the ONLY finding
RED arm 1 (INPUTS drops `loaded`):
  BLOCK  COMPONENT loaded_panel: consumes loaded, which `screen_workspace` does not declare — unbalanced
RED arm 2 (the 5 re-export outputs omitted):
  BLOCK  COMPONENT loaded_panel: emits artifact_slots, panel_handle, project_row, slot_rows, slots_container ... — unbalanced
V21 RED arm (owner names undefined LLR-86.99):
  BLOCK  COMPONENT screen_workspace: output `screen_root` names owner `LLR-86.99`, which no document ... defines
```

Both directions of the balancing claim and the owner rule are demonstrated live: the planned
record passes, and each single-field mutation of it BLOCKs.

## M-10 · Systematic bare-literal sweep — ALL 24 ids × BOTH `s19_app/` and `tests/` (P2 iteration, blocker B86-R2-01)

**This transcript IS the declared C-55 search-width guard protecting G4's "0 genuine
undeclared dependants" conclusion.** The original bare-name probe (M-5) ran over `app.py`
only; G4's emptiness claim therefore rested on an unswept population — C-55's exact shape.
This sweep covers every declared id over both roots and both quote styles; any future
widening of the search (new roots, new coupling channels) re-opens G4, and G4 may not be
cited without citing this guard.

```
$ for id in <all 24 ids>; do grep -rn --include='*.py' -e "\"$id\"" -e "'$id'" s19_app tests \
    | grep -v __pycache__; done          # executed 2026-08-24, P2 iteration

Hits, classified (provider `id=...` assignment lines are the PROVIDER, not consumers — D-D):

ws_load_project_button : app.py:2011 (provider) · app.py:11839 on_button_pressed  [already declared]
files_title            : app.py:2012 (provider)                                    [no coupling]
files_list             : app.py:2013 (provider) · app.py:7512 on_list_view_selected  [NEW entry]
sections_title         : app.py:2014 (provider)                                    [no coupling]
sections_list          : app.py:2015 (provider) · app.py:7517 on_list_view_selected  [NEW entry]
                         · tests/test_tui_directionb.py:1047,:1063               [already declared]
ws_left / hex_title / hex_controls / hex_scroll / ws_center / ws_stats_title / ws_stats /
a2l_title / a2l_scroll / ws_right / ws_memstrip / hex_view* / a2l_view*
                       : provider line only (*hex_view/a2l_view also directionb:1047-1063,
                         already declared)                                        [no new coupling]
search_input           : app.py:2022 (provider) · app.py:5789 _FIND_GOTO_INPUTS   [NEW entry]
                         · tests/test_tui_commandbar.py:194,:326,:686,:2118,:2420,:2501
                         · tests/test_tui_directionb.py:6374,:6450               [files already declared]
search_button          : app.py:2023 (provider) · app.py:11837                    [already declared]
                         · tests/test_tui_commandbar.py:686 _B78_SEARCH_SURFACES  [NEW DEPENDANT PAIR — reclassifies the M-4 mention]
goto_input             : app.py:2024 (provider) · app.py:5789 _FIND_GOTO_INPUTS   [NEW entry]
                         · tests/test_tui_commandbar.py:422,:686,:2118            [file already declared]
                         · tests/test_tui_directionb.py:6375 (live assertion)     [NEW DEPENDANT PAIR — reclassifies the M-4 mention]
goto_button            : app.py:2025 (provider) · app.py:11843                    [already declared]
                         · tests/test_tui_commandbar.py:686 _B78_SEARCH_SURFACES  [NEW DEPENDANT PAIR]
workspace_panes        : app.py:2058 (provider) · app.py:6009 _EMPTY_STATE_SCREENS [already declared]
screen_workspace       : app.py:2069 (provider) · app.py:5749 SCREEN_CONTAINER_IDS [NEW entry]
                         · app.py:6009 _EMPTY_STATE_SCREENS                        [already declared]
                         · tests/test_tui_commandbar.py:135 (composes f"#{sid}"), :306,:316,
                           :329,:481,:491 (assertions)                             [NEW DEPENDANT PAIR]
                         · tests/test_tui_directionb.py:137,:201                   [already declared]
```

**Verdict: 4 new dependant PAIRS** — `(search_button, tests/test_tui_commandbar.py)`,
`(goto_input, tests/test_tui_directionb.py)`, `(goto_button, tests/test_tui_commandbar.py)`,
`(screen_root, tests/test_tui_commandbar.py)` — **plus 5 new function-granular in-app
entries** on already-declared `app.py` (`SCREEN_CONTAINER_IDS` → screen_root;
`_FIND_GOTO_INPUTS` → search_input, goto_input; `on_list_view_selected` → files_list,
sections_list). **No pair beyond the P2 review's list appeared.** Constant names verified in
place: `SCREEN_CONTAINER_IDS` `app.py:5748` · `_FIND_GOTO_INPUTS` `app.py:5788` ·
`_B78_SEARCH_SURFACES` `tests/test_tui_commandbar.py:685`.
