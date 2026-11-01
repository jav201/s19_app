# Inc 10 — proposed interfaces between G-A (`screens.py` + `screens_directionb.py` + `styles.tcss`) and G-B (`app.py`)

PROPOSED by the E2 baseline. The orchestrator fixes it as `interfaces-10.md`; a group never changes an interface alone. Base: `8947666` plus the fixed 9b interfaces (`../../inc-9b-design/codewire/interfaces-9b.md`: `LoadDialog`, `LoadChoice`, `_handle_load_dialog(choice: Optional[LoadChoice])`, `_load_workarea_file(name)`, `_LOAD_DIALOG_INERT_ACTIONS` with the whole-stack `LoadDialog` test). Evidence ids (`p10b Un`) are lines of `probe-p10b.out.txt`.

```python
# screens.py (G-A)
class ConfirmQuestionScreen(ModalScreen[bool]):          # S-a; True = replace (y), False = cancel (n / escape)
    AUTO_FOCUS = "#confirm_no"                            # LLR-174.2b
    BINDINGS = [                                          # LLR-174.2c / .2d; nothing else at screen level (no enter, no s)
        Binding("y", "answer(True)", show=False),
        Binding("n", "answer(False)", show=False),
        Binding("escape", "answer(False)", show=False),
    ]
    def __init__(self, title: str, body: str, yes_label: str, no_label: str) -> None: ...   # LLR-174.2a; plain str, already scrubbed by the caller
    # compose: Container#confirm_box.modal-dialog
    #            Label#confirm_title.modal-title   (markup off)
    #            Static#confirm_body               (markup off)
    #            Container#confirm_buttons.modal-buttons
    #              Button#confirm_yes.modal-confirm (yes_label, markup off)
    #              Button#confirm_no               (no_label,  markup off)
    # on_button_pressed: confirm_yes -> dismiss(True); confirm_no -> dismiss(False); event.stop()   # LLR-174.2e / .2f
    # action_answer(value: bool) -> dismiss(value)

# screens_directionb.py (G-A)
class PatchEditorPanel:
    @property
    def is_dirty(self) -> bool: ...                       # S-c; returns self._dirty; no setter; LLR-174.1c

# app.py (G-B)
QuestionKind = Literal["image", "attach", "project"]
UnsavedItem = tuple[Literal["image", "document", "flow"], str]    # S-e; (kind, raw unscrubbed name); "document" carries ""

def _confirm_then_load(self, kind: QuestionKind, target: str, go: Callable[[], None]) -> None: ...   # S-b
def _load_would_lose(self, kind: QuestionKind) -> list[UnsavedItem]: ...                            # guard (E1 A2)
def _load_question_text(self, kind: QuestionKind, target: str, items: list[UnsavedItem]) -> tuple[str, str]: ...  # (title, body), both painted plain str (E1 A3)
```

## Seams

- **S-a, the modal contract.**
  - `ConfirmQuestionScreen(title, body, yes_label, no_label)` is a `ModalScreen[bool]`, never dismissing `None`.
  - It imports nothing from `app.py`, `services` or `workspace`. Inc 12 builds the quit question from it (LLR-174.2a's quit arm).
  - Every text widget paints with markup off. `Button` parses a `str` label as markup (Textual 8.2.8 `Button.validate_label` → `Content.from_text`), so G-A passes each label as `rich.text.Text` (Q-1).
  - Outer id `#confirm_box`. Not `#load_dialog`: 8 modals share that id, and `pb_A` reused it. Not `#load_box` either, which is 9b's.
  - Evidence:
    - `Button.BINDINGS == ['enter']` (p10b U0), so `enter` acts on the focused button with no screen binding (LLR-174.2e).
    - Under a `ModalScreen` the non-priority app keys `l` / `p` / `q` do not reach the app (p10b U11), so LLR-174.2g needs no catch-all.
    - `ConfirmDiscardScreen` focuses Discard and ignores `escape` / `n` (p10b U12): it is not reused.
- **S-b, `_confirm_then_load(kind, target, go)`.**
  - `items = self._load_would_lose(kind)`. Empty → `go()` runs at once. Every caller already runs after its modal popped: the 9b router defers through `call_after_refresh`, and a dismiss callback runs through `call_next` after the pop (Textual `ResultCallback.__call__`).
  - Otherwise `title, body = self._load_question_text(kind, target, items)`, then `push_screen(ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)"), answer)`:
    - `True` → `self.call_after_refresh(go)`, so the question has popped before the load (the 9b router's reason);
    - `False` → `self._rehome_focus_after_load()` and nothing else: 0 status lines (ruling Q3), no reset, no flag change (LLR-174.3a, LLR-166.1 Inc 10 arm).
  - `target` is the raw name: the on-disk project name for `project`, the requested file's name otherwise. The composer adds `project ` and scrubs it (Q-2).
  - The seam never reads `_dirty` directly (LLR-174.1c).
- **S-c, `PatchEditorPanel.is_dirty`.**
  - A read-only property over `_dirty`.
  - G-A also corrects the attribute comment at `screens_directionb.py:4808-4815`: the writer census becomes five sites (w5 `mark_pasted`), and the readers gain the load guard and `_handle_save_dialog`.
  - G-B replaces `panel._dirty` at `app.py:10576` with `panel.is_dirty`.
  - Evidence: p10b U0 (`is_dirty` absent); E1 p10 (1 private read at `:10576`).
- **S-d, placement: the seam lives in the four leaves; the 9b router stays as 9b writes it.**
  - `_route_load_project(name)`: `kind="project"`, `target=name`, and `go` is today's body (`_handle_load_project` + the Load-result panel).
  - `_load_path_from_user_input(path)`, on the `data` and `a2l` arms only:
    - `a2l` → `attach`;
    - `data` → `attach` when the suffix is a MAC suffix, else `image`, with `target = <file name>` (LLR-174.4b, Q-4);
    - `project` calls `_route_load_project` as today, so it is asked once there (LLR-174.4a);
    - `refuse` paints its line with no question.
  - `_load_workarea_file(name)`, after `candidate.exists()`: `attach` for a MAC or A2L suffix (case-folded), else `image` (LLR-174.4c). `_load_from_item` is unchanged.
  - `_handle_select_variant(variant_id)`, after the descriptor and file checks: `kind="image"`, `target=descriptor.path.name`. `go` holds both `self._pending_variant_id = variant_id` and `load_from_path(...)`. On the base the stamp comes before the load (p10b U8), so a stamp outside `go` would survive a cancel and label the next install.
  - `_handle_load_project` holds no seam and no push (LLR-174.3b). `on_mount` passes through `_load_path_from_user_input` and asks nothing, because D, W and F are all false at mount.
  - Count per request:
    - typed project folder → router → `_load_path_from_user_input` (project arm, no seam) → `_route_load_project` (seam) = 1;
    - project row → router → `_route_load_project` = 1;
    - recent data → `_load_path_from_user_input` (data arm) = 1;
    - `v` and the panel's `v` → `_handle_select_variant` = 1;
    - Workarea (either surface) → `_load_workarea_file` = 1.
- **S-e, the item model and the guard.**
  - `_load_would_lose(kind)` returns an ordered `list[UnsavedItem]`:
    - `image` when D, with `current_file.path.name`;
    - `document` when W (`PatchEditorPanel.is_dirty`), with name `""`;
    - `flow` when F (`FlowBuilderPanel.is_dirty`), with `current_flow.name`.
  - By kind:
    - `attach` → always `[]`;
    - `image` → the `image` item only;
    - `project` → all three, in that order.
  - D is `self._change_service.differs_from_last_saved(self.current_file.mem_map if self.current_file else None)`.
  - Evidence:
    - p10b U2 (a same-byte patch → D false);
    - p10b U3 (a typed `.mac` keeps the patch, D true);
    - p10b U7 (D false right after a project load);
    - p10b U10 (F survives a project load).
- **S-f, the priority guard.** `check_action` (post-9b): the first test becomes `action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, (LoadDialog, ConfirmQuestionScreen)) for s in self.screen_stack)` → `False`. One screen type is added; the action set is unchanged.
  - Evidence: p10b U11 shows, under a `ModalScreen[bool]` on base, all four of `load_file`, `save_project`, `focus_palette` and `cycle_density` running, with `ctrl+l` stacking `LoadFileScreen` and `ctrl+s` stacking `SaveProjectScreen`. That is LLR-174.2h's `planned` control, executed here.
- **S-g, ids and style.**
  - Ids: `#confirm_box`, `#confirm_title`, `#confirm_body`, `#confirm_buttons`, `#confirm_yes`, `#confirm_no`.
  - `.modal-dialog` already gives `height: auto` and `width: 70%`, so LLR-174.2r may need no new rule (Q-6).
- **Composer (G-B), what G-A receives.**
  - Title: `Replace <current>?`, where `<current>` is `painted_names([current_project])`, else `painted_names([current_file.path.name])`, else `the current session` (LLR-174.2k).
  - Body: two sentences, `unsaved changes` once, ending `Load <target> anyway?`. `<target>` is `project <pn(name)>` for a project load, `<pn(file name)>` otherwise (LLR-174.2o / .2q).
  - Items paint as:
    - `image` → `pn(name)`;
    - `document` → `Patch Editor entries`;
    - `flow` → `flow <pn(name)>`.
  - The exact sentence is Q-3.
- **Interim removal (G-B).** Delete `app.py:11943-11953` (the `if discarded_unsaved:` block) and the `discarded_unsaved =` binding (`:11821`) (ruling Q2). What happens to `_reset_project_session`'s return is Q-7.

## Open questions (one per undecided seam)

- **Q-1 (S-a), the label markup.** Should G-A wrap `yes_label` / `no_label` in `Content(label)`, so that a label holding `[` paints literally? Recommendation: yes. The two load labels hold no `[`, but Inc 12 passes other labels, and the modal's contract is "markup off".
- **Q-2 (S-b), the `target` form.** Option 1: a raw name, with the composer adding `project ` from `kind` and scrubbing. Option 2: the caller passes the full painted target. Recommendation: option 1, so that the scrub happens in exactly one place.
- **Q-3 (composer), the exact body sentence.** Recommendation: `There are unsaved changes in <items>. Load <target> anyway?`, with `<items>` joined as `A`, `A and B`, `A, B and C`. It has no verb agreement to get wrong (`Patch Editor entries` is plural), holds the token once, and has 2 sentence ends. Alternative: `pb_A`'s `<items> has/have unsaved changes.`, which needs a plural rule per item.
- **Q-4 (S-d), the MAC test for a typed or recent path.** `_typed_load_route` returns `("data", "")` for `.s19`, `.MAC` and `.mac` alike (p10b U3), so the route reads the suffix itself.
  - Option 1: `path.suffix.lower() in MAC_EXTENSIONS` on the typed `Path`.
  - Option 2: `recent_kind(path) == "mac"`.
  - Executed (`probe-p10b-q4.out.txt`): a typed absolute `<tmp>\x.mac.` is refused by the classifier itself (`("refuse", "not a supported file")`), so the trailing-dot form never reaches the seam on the outside branch. `PureWindowsPath("x.mac.").suffix == ""` and `recent_kind` gives `None` for it, so options 1 and 2 agree on every path the classifier accepts as `data`.
  - Recommendation: option 1, which reads the same constant the loader reads. Residual risk, declared and not probed: a typed `W\temp\x.mac.` goes through the inside-work-area branch, where `abspath` drops the dot (CR9-3). It would ask as an image, and `load_from_path` would then refuse it as `Unsupported file type`. One needless question; nothing is lost.
- **Q-5 (S-a), a double dismiss.** Textual's `dismiss` pops `app.pop_screen()` each time it is called. If two dismissing messages queue on the question, the second pops the screen under it. 9b guards the same case with `_dismissed` (A9b-02). Should the question copy that guard? Recommendation: yes, one line. Not probed on base (the pilot delivers keys one at a time).
- **Q-6 (S-g), `styles.tcss`.** Option 1: no change; the question uses `.modal-dialog`'s 70% width and auto height, and the slice drops to 3 source files. Option 2: add `#confirm_box { width: 60%; max-width: 72; min-width: 44; }` from `pb_A`. Recommendation: option 1, with LLR-174.2r's 99 / 118 / 220-column arms as the check. Option 2 only if E4's layout arm clips at 99 columns.
- **Q-7 (A10), the return of `_reset_project_session`.** Once the interim line is gone, nothing reads the `int`. Recommendation: return `None` and drop the Returns paragraph. The two tests that monkeypatch it (`test_b100_project_homes.py:918`, `test_b100_recents.py:415`) pass the value through and still pass. The alternative keeps a value nobody reads.

## Orchestrator rulings (2026-10-31): this file is now FIXED

The orchestrator owns this file. A prototype group proposes a change in its notes and never edits an interface alone.

- **Q-1, superseded by P-GA10-1.** Button labels are `rich.text.Text(label)`: they paint literally and add no new module to screens.py.
- **Q-2, raw name.** `target` is the raw name. The composer adds `project ` and scrubs through `painted_names`, so the scrub sits in one place.
- **Q-3, as recommended.** The body text is `There are unsaved changes in <items>. Load <target> anyway?`.
- **Q-4, as recommended.** A path is a MAC path when `Path(str(path).strip().strip('"')).suffix.lower() in MAC_EXTENSIONS`, and the question's target is that stripped path's `name`. The leftover `W\temp\x.mac.` case (the question asks once, then the load is refused) is declared in the risks.
- **Q-5, yes.** Copy 9b's `_dismissed` guard as the first line of the modal's close.
- **Q-6, no `styles.tcss` change.** Leave it alone unless the 99-column arm clips. G-A probes this at prototype time. If it clips, G-A proposes one selector on `#confirm_box`. The slice is 3 files unless that happens.
- **Q-7, yes.** `_reset_project_session` returns `None`.
- **Outer id:** `#confirm_box`, not `#load_dialog`.
- **Placement:** the question sits in the four leaf functions, and the 9b router is unchanged. `go` runs through `call_after_refresh` after `y`. Cancel calls `_rehome_focus_after_load()` and paints 0 status lines. `check_action` adds the question's screen type to 9b's whole-stack test.
