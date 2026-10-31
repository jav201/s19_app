# Inc 9b — fixed interfaces between G-A (`screens.py` + `styles.tcss`) and G-B (`app.py`)

The orchestrator owns this file. A group proposes a change here and never changes an interface alone.

```python
# screens.py (G-A)
LoadKind = Literal["project", "workarea", "recent", "path"]

@dataclass(frozen=True)
class LoadChoice:                       # S-a
    kind: LoadKind
    value: str                          # on-disk project name | work-area file name | recorded path text | typed text (verbatim)

LoadRow = tuple[str, str, Optional[LoadChoice]]      # S-c (section_id, painted plain label, choice); choice None = heading / token line (disabled option)
PreviewLine = tuple[str, bool]                        # S-d (painted plain text, marked); the dialog prefixes "● " only where marked

class LoadDialog(ModalScreen[Optional[LoadChoice]]):  # S-b
    def __init__(
        self,
        *,
        mode: Literal["path", "list"],
        highlight: Optional[str],                                       # project name to highlight, or None
        rows: Callable[[], list[LoadRow]],                              # called on mount; app side paints labels (safe_text / painted_names happen in G-B)
        verdict: Callable[[LoadChoice], Optional[tuple[str, str]]],     # None = go; else (reason_token, step_token) painted in #load_reason, dialog stays open
        preview: Callable[[LoadChoice], list[PreviewLine]],                  # synchronous for every kind (Q2); returns the lines, the dialog paints them
    ) -> None: ...
    def show_preview(self, lines: list[PreviewLine]) -> None: ...          # S8: paints what preview() returned (no generation, no stale check)
```

- S-e: `verdict` runs on the event loop and only reads metadata. `preview` runs on the event loop and returns the lines synchronously for every kind (Q2); there is no `deliver` and no generation. The dialog paints what `preview` returns.
- S-f: the dialog records which of `#load_list` / `#load_path` gained the focus last, through `on_descendant_focus`. Load (Enter, or `#load_ok`) acts on that one.
- S-g: the guard for the priority keys is `S19TuiApp.check_action`. It returns `False` for `load_file`, `save_project`, `focus_palette`, and the density toggle bound to `ctrl+d`, while `any(isinstance(s, LoadDialog) for s in self.screen_stack)`. G-B confirms the exact action names from `BINDINGS`.
- Dismiss: `LoadDialog` dismisses with a `LoadChoice` only after `verdict` returned `None`. Cancel and escape dismiss with `None`. The app's one router is `_handle_load_dialog(choice: Optional[LoadChoice])`.
- Ids: `#load_box`, `#load_panes` (`.stacked` below 100 columns), `#load_left`, `#load_path`, `#load_list` (OptionList), `#load_preview` (focusable), `#load_reason`, `#load_buttons`, `#load_ok`, `#load_cancel`.

## Applied after E2 (orchestrator, `E2-rulings.md`)

- Outer container id is `#load_box`, not `#load_dialog`, because eight existing modals already use `#load_dialog`.
- P-1: `preview` is synchronous for every kind and returns the lines; there is no `deliver`, no thread and no generation.
- P-3: `_close` returns at once when `_dismissed` is set, so two queued close/load requests dismiss once (A9b-02).
- V-1: the dialog never calls `verdict` for blank path text (it paints `nothing selected` / `pick a row or type a path` itself) nor for a row whose choice is `None`.
- H-1: the dialog highlights the row whose choice is `LoadChoice("project", highlight)`. With no highlight it takes the first project row, and with 0 projects the first loadable row.
- `s19_app/tui/__init__.py` exports `LoadDialog` and `LoadChoice`; the old screens are no longer exported.
