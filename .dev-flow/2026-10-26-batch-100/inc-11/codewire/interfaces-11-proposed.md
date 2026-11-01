# Inc 11 — proposed interfaces between G-A (`screens.py` + `styles.tcss`) and G-B (`app.py` + `project_gather_service.py`)

PROPOSED by the E2 baseline. The orchestrator fixes it as `interfaces-11.md`; a group never changes an interface alone. Base: `8947666` plus the fixed 9b interfaces (`../../inc-9b-design/codewire/interfaces-9b.md`: `LoadDialog`, `LoadChoice`, `_LOAD_DIALOG_INERT_ACTIONS`, the whole-stack guard) and the fixed 10 interfaces (`../../inc-10-design/codewire/interfaces-10.md`: `ConfirmQuestionScreen` in the same guard, `PatchEditorPanel.is_dirty` read at `_handle_save_dialog`). Evidence ids (`p11b Un`, `P11-n`) are lines of `probe-p11b*.out.txt` and of `../work/probe_*.out.txt`. Node names are those of `baseline-11.md`.

```python
# screens.py (G-A)
WhereKind = Literal["info", "refusal"]
WhereLine = tuple[str, WhereKind]          # S-a: one painted plain line for #save_where (G-B scrubs; markup off in G-A)

@dataclass(frozen=True)
class SavePreview:                          # S-a: the app -> dialog value for one name
    where: tuple[WhereLine, ...]            # target folder + kind ("info"), or the refusal's reason + next step ("refusal")
    rows: tuple[str, ...]                   # #save_summary lines, in order, one line each, already composed by G-B
    plan: Optional[SavePlan]                # the plan these rows paint; None when nothing is planned (empty name, name refusal)
    refused: bool                           # True -> Save keeps the dialog open (LLR-175.3f)

class SaveProjectScreen(ModalScreen[Optional[SaveProjectPayload]]):   # S-b
    AUTO_FOCUS = "#project_name"                                       # LLR-175.3d
    BINDINGS = [
        Binding("escape", "cancel", show=False),                       # LLR-175.3
        Binding("alt+s", "save", show=False, priority=True),           # LLR-175.3c (priority: 9b A9b-01)
    ]
    def __init__(
        self,
        *,
        preview: Callable[[str], SavePreview],                          # called after the first refresh and by the 150 ms timer
        confirm: Callable[[str, Optional[SavePlan]], Optional[SavePreview]],  # Save: None = go; else repaint with it and stay
        initial_name: Optional[str] = None,                             # LLR-175.3h: the open project's on-disk name
        variants: Optional[List[Tuple[str, str]]] = None,               # Q4, unchanged meaning and attribute name
        candidate_files: Optional[List[str]] = None,                    # Q4, unchanged meaning and attribute name
    ) -> None: ...
    @property
    def plan(self) -> Optional[SavePlan]: ...                           # S8 / LLR-175.4k: the painted plan, read-only
    # compose: Container#save_box.modal-dialog
    #            Label.modal-title ("Project name")      Input#project_name (OsClipboardInput)
    #            Static#save_where (markup off)          VerticalScroll#save_summary (focusable, markup off rows)
    #            [assignment rows #assign_batch / #assign_<i>, unchanged, only when enabled]
    #            Container#saveproject_buttons.modal-buttons
    #              Button#save_ok.modal-confirm "Save (alt+s)"   Button#save_cancel "Cancel (esc)"
    # dismiss: SaveProjectPayload(parent_folder=<work area text>, project_name=<typed>, batch, assignments[, plan])
```

```python
# app.py (G-B)
@dataclass(frozen=True)
class _SaveSession:                         # S-d: once per dialog open (LLR-175.5), after the first frame (LLR-175.5b)
    image_step: _ProjectImageStep           # _decide_project_image() or _ProjectImageStep(emit=False) with no image
    digests: Mapping[Path, Tuple[str, int]] # image (copy case), MAC, A2L: _file_digest once each
    refusal: Optional[str]                  # missing source (G11), unreadable source (G16), blocked entries (image_step.refusal)

@dataclass(frozen=True)
class _PreparedSave:                        # S-c: the guard-and-plan half's result (the 12 values that cross :9856)
    typed_name: str
    cleaned: str
    project_dir: Path
    save_as_source: Optional[Path]
    source_gone: Optional[str]
    image_step: _ProjectImageStep
    existing: Optional[ProjectManifest]
    target_carry: Mapping[str, object]
    carried_derived: Mapping[str, DerivedFrom]
    carried_active_document: Optional[str]
    carried_document_line: Optional[str]
    emitted_record: Optional[DerivedFrom]
    plan: Optional[SavePlan]
    refusal: Optional[str]                  # the status text the direct path paints; its token pair is what the dialog paints
    toast: bool                             # the direct path also notifies (G11, G16, G17, the G18 shortfall), as today

def _save_session_inputs(self) -> _SaveSession: ...                                       # N2
def _prepare_project_save(self, name: str, session: _SaveSession) -> _PreparedSave: ...   # N1, G4-G18 of _handle_save_dialog
def _save_dialog_preview(self, name: str, session: _SaveSession) -> SavePreview: ...      # N3, composes painted plain text
def _plan_project_save(self, project_dir, project_name, image_step, derived=False,
                       carried_active_document=None, source_reason=None, *,
                       save_as_source: Optional[Path] = None,
                       digests: Optional[Mapping[Path, Tuple[str, int]]] = None) -> SavePlan: ...   # A4: keyword-only additions
def _commit_project_save(self, prepared: _PreparedSave, payload: SaveProjectPayload) -> None: ...  # the commit half, :9856-:10605
def _handle_save_dialog(self, payload: Optional[SaveProjectPayload]) -> None: ...         # A3: router, signature unchanged

# project_gather_service.py (G-B, ruling Q10)
def plan_project_save(...same signature...) -> SavePlan: ...    # carried / owner-document rows predicted against the tree the copy produces
```

## Seams

- **S-a, `SavePreview`, the app → dialog value.**
  - G-B composes every string. G-A only places lines and paints them with markup off. `screens.py` imports `SavePlan` for typing only and calls no service (LLR-175.4's AST arm).
  - Every name in `where` and `rows` goes through `painted_names` in G-B (LLR-175.4g). On the base, three refusal texts embed raw names: G6 (`'<typed>' is a device name`), G10 (`'<typed>' is already a project as '<item>'`), G13 link (`'<cleaned>'`, safe because it is sanitised). N1 scrubs them, so the status line and the dialog read the same scrubbed text.
  - One line per row. G-B cuts nothing; G-A sets `text-wrap: nowrap` / `text-overflow: ellipsis` on the rows (LLR-175.4j, the 9b S9b-8 pattern).
  - Evidence: P11-2 (`#save_summary: 0 #save_where: 0`); p11b U6 (the refusal texts as painted today).
- **S-b, `SaveProjectScreen` construction and keys.**
  - Keyword-only constructor. `action_save_project` pushes `SaveProjectScreen(preview=…, confirm=…, initial_name=self.current_project, variants=…, candidate_files=…)`.
  - The old positional `default_parent` is gone. 3 tests build the screen directly and are re-pinned (census A).
  - `screen.variants` and `screen.candidate_files` stay as attributes: `test_tc304` and `test_tc305` read them.
  - `alt+s` is `priority=True`. 9b found that a non-priority `alt+<letter>` loses to the focused `Input` (A9b-01).
  - `enter` in `#project_name` → the same save action (ruling Q8). `escape` and `#save_cancel` → `dismiss(None)`. A `_dismissed` flag is checked first in the close and save paths, as in 9b A9b-02 and Inc 10 Q-5.
  - The outer id is `#save_box`, never `#load_dialog`: 8 modals in `screens.py` carry `id="load_dialog"` (p11b U7). The class `.modal-dialog` stays, because `test_tc033_modals_render_with_calm_dark_tokens` queries `.modal-dialog`, `.modal-title` and a `.modal-confirm` button.
- **S-c, how the handler finds the prepared save (the split).**
  - `_handle_save_dialog(payload)` keeps its one positional parameter. 56 direct test calls use it (LLR-175.4l), and `test_tui_manifest_save._capture_save_payload` replaces it with a one-argument lambda that the dismiss callback must still call.
  - Router body:
    1. `None` → log, return (G0).
    2. The payload checks G1–G3 stay here: nothing loaded, parent not a folder, parent ≠ work area. They read the payload, not the name.
    3. `prepared = <the dialog's confirmed _PreparedSave when it matches the payload> or self._prepare_project_save(payload.project_name, self._save_session_inputs())`.
    4. `prepared.refusal` → `set_status` (+ `notify` when `toast`), return.
    5. Otherwise `_commit_project_save(prepared, payload)`.
  - The commit is its own function. Then LLR-175.4a's spy "on the commit step" has a target, and the router stays short.
  - `test_tc_b100_07_ast_census_every_post_creation_return_removes` reads `_handle_save_dialog` by name for `mkdir`, so it is re-pinned to `_commit_project_save` (one string, census H).
  - The match test (step 3) is open: Q-2.
  - Evidence: `split-flow.out.txt` (12 crossing values; the first half writes no `self.` attribute; 19 / 10 returns).
- **S-d, the per-open session.**
  - `_save_session_inputs()` runs once per open, from the dialog's first `preview` call, which runs after the first refresh. `_decide_project_image` is therefore called after the first frame (LLR-175.5b).
  - The session is dropped when the router returns, or when the dialog dismisses with `None`.
  - Where the session lives is open: Q-1.
  - The session holds the digests of the image, MAC and A2L. `_plan_project_save` takes them through its new keyword `digests` and digests nothing else for the session's files.
  - The existing positional call `app._plan_project_save(app.workarea / "P9", "P9", step)` (`test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload`) keeps working with `digests=None`, which digests as today.
  - Evidence: p11b U1 / U2 (`_file_digest` 1 / 3 per save; `_save_as_source_for` 2 per save); P11-1 (26.1 ms for the case_06 A2L).
- **S-e, the priority guard.** In `check_action` (post-10), the whole-stack test becomes `any(isinstance(s, (LoadDialog, ConfirmQuestionScreen, SaveProjectScreen)) for s in self.screen_stack)`. The action set (`_LOAD_DIALOG_INERT_ACTIONS`) is unchanged.
  - Ruling Q3 and E1 S-e spell the stack-top form `isinstance(self.screen, …)`. 9b (S9b-1) and Inc 10 fixed the whole-stack form; this proposal follows them.
  - Evidence: P11-2 and P11-3 (`ctrl+l` stacks a Load dialog over Save, `ctrl+s` a second Save dialog, `ctrl+d` changes the density).
- **S-f, ids and style (G-A).**
  - Ids: `#save_box`, `#project_name`, `#save_where`, `#save_summary`, `#saveproject_buttons`, `#save_ok`, `#save_cancel`, plus the unchanged `#assign_batch` / `#assign_<i>`.
  - New rules go inside the Calm Dark modal block of `styles.tcss` and use only `$`-tokens (TC-033 forbids hex there).
  - `#save_summary` needs a bounded height and a scroll, so the docked `.modal-buttons` stay on screen (LLR-175.4h). `.modal-dialog` today is `height: auto` with no cap (baseline-notes "Selectors").
  - The marker comment `Calm Dark modal re-skin (batch-02 increment 8` stays verbatim (9b A9b-12).
- **S-g, timer ownership (G-A).**
  - The dialog owns one `set_timer`. The first change after a quiet period of at least 150 ms recomputes at once; later changes inside the window schedule one trailing call (LLR-175.5a).
  - Every recompute calls `preview(current text)` synchronously and paints the result.
  - The timer is stopped on dismiss.
  - `confirm` is called synchronously on Save, Enter or `alt+s`.
- **S-h, the out-of-date summary (LLR-175.4b).**
  - G-A passes `self.plan`, the painted plan or `None`, to `confirm(name, plan)`.
  - G-B re-prepares `name` with the same session. A refusal returns a refused `SavePreview`.
  - If `prepared.plan != plan` (dataclass equality of the frozen plan; `None` never matches), it returns the fresh preview with one extra `where` line `the summary changed — check it, then save again` (kind `refusal`).
  - Otherwise it keeps the prepared save for the router (S-c) and returns `None`.
  - Blank text never reaches `confirm`. The dialog paints `name is empty — type a project name` itself (LLR-175.3b), as 9b's V-1 does for a blank path. See Q-3.
- **S-i, Q10 in `project_gather_service.py` (G-B).**
  - `plan_project_save` predicts the carried rows and the owner document row against the tree the copy will produce. The signature is unchanged; `_plan_copies` may return the extra facts the prediction needs.
  - Evidence: p11b U3. The plan says `('document', 'changes.json', 'new')` with copies `['patches/changes_1.json']`, while Q then holds and records `patches/changes_1.json`.
  - The file-backed document row is never checked by `_plan_row_mismatch`: the rows loop skips it and the gather places it. That is why the base saves, with a plan that does not match what it wrote.
- **R2-2 closes through N1.** `_save_as_source_for` is evaluated once, in `_prepare_project_save`, and passed to `_plan_project_save` through the new keyword `save_as_source`. On the base it runs twice per save (p11b U1).
- **Removed by evidence: LLR-175.1n.** p11b U4 / U4b show that no loadable kind reaches `render_patched_image → None`. A MAC-only session gets `ranges []`, so every entry is `skipped-outside`. It is never blocked or emitted, and the save completes as a copy. Per ruling Q11, the requirement and its token row are withdrawn. G-B adds no `cannot be written` line. The `_decide_project_image` branch stays as defence; that code is untouched.

## Open questions (one per undecided seam)

- **Q-1 (S-d), where the session lives.**
  - Option 1: an app attribute `self._save_session`, set at the first preview and cleared when the router returns or on `None`. It is simple to spy on (LLR-175.5). It adds one `self.<name> =` to `S19TuiApp`, so `test_tc_b100_09_domain_matches_the_live_source_census` fails until the name is classified (census H).
  - Option 2: a small holder object captured by the `preview` / `confirm` closures and by the dismiss callback. It adds no app attribute and needs no re-pin. The dismiss callback would then have to call `self._handle_save_dialog(payload)` and hand over the prepared save some other way (see Q-2).
  - Recommendation: option 1. One test re-pin buys a plain, spy-able seam, and the router needs no hidden channel.
- **Q-2 (S-c), the match between the dismissed payload and the prepared save.**
  - Option 1: `SaveProjectPayload` gains `plan: Optional[SavePlan] = field(default=None, compare=False)`. The dialog sets it to `self.plan`. The router commits the session's last confirmed `_PreparedSave` only when `prepared.plan is payload.plan` and `prepared.typed_name == payload.project_name`; otherwise it prepares fresh. The 11 test files that build the payload are unaffected (default `None`).
  - Option 2: no payload field; the router commits the session's confirmed prepared save whenever one exists. A stale one could then leak into a later direct call.
  - Recommendation: option 1, because the identity test makes "executed = painted" checkable (LLR-175.4a).
- **Q-3 (S-h), the empty-name pair.** Option 1: the dialog paints `name is empty` / `type a project name` itself for blank text (the 9b V-1 precedent), and N1 keeps the same rule for direct payloads. Option 2: `confirm("")` returns the refusal from N1. Option 2 keeps LLR-175.6's "one function decides" literal, but makes the dialog call the app for a case it can see by itself. Recommendation: option 2. LLR-175.6's AST census counts the empty rule as a Save-path site, and the cost is one call.
- **Q-4 (S-d), what is per-open and what is per-name.**
  - LLR-175.5 names the image decision and the digests of the image, MAC and A2L. Three more per-call costs exist on the base:
    - the file-backed document's `_file_digest(source)`;
    - the save-as `inventory_project_tree(open project)`, measured at 189.4 ms for 2 000 files (p11b U8);
    - the exempt check's `_file_digest(target item)`, which is per name.
  - The first two do not depend on the typed name.
  - Recommendation: put the document digest and the save-as inventory in the session (computed once, lazily, the inventory only when the first new-folder name is previewed with a project open), and keep the exempt digests per name. Otherwise a 2 000-file save as costs about 190 ms on every recompute, against LLR-175.5a's 300 ms limit for the final paint.
  - LLR-175.5's spy then counts `_file_digest` per session file, not per call, and the TC must filter by path.
- **Q-5 (S-i), the scope of the Q10 fix.**
  - Option 1: only the owner document row (F5 (b), the case ruling Q10 cites).
  - Option 2: the owner document row and the top-level carried rows (F5 (a): session image `fw_2.s19` plus an identical `fw.s19` in P).
  - Option 2 is the backlog's wording. It turns `test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts`, which pins today's abort with "the plan named … fw.s19 … fw_2.s19", into a successful save with a `keep` row, so that test is re-pinned (census I).
  - Recommendation: option 2, because HLR-175 forbids the dialog from painting a row the save will not write, in either case.
- **Q-6 (S-c), the toast on a dialog refusal.** Today G11, G16, G17 and the G18 shortfall also raise a 10-second toast. With the refusal painted in the dialog before Save (ruling Q5), a toast would duplicate it. Recommendation: the dialog path never toasts; the direct path keeps the toast (`_PreparedSave.toast`) as today. No test asserts the toast title "Project not saved" (grep: 0 lines), so either option keeps the suite green.
