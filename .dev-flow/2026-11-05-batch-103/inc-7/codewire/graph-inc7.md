# Code-Wire graph — Inc 7 (A2L Viewer: list of labels), batch-103

Stage E2 of the design-first flow (skill `dev-flow`). **Graph only:** no stub, mark or declaration in any tree; the baseline marks sat in a throwaway `git archive` copy outside the worktree (`baseline-extract.md`, `extractor-baseline/`). Base `2dbd7d5a` (branch `b103-inc7`). Requirements `../01-requirements.md` (95 active rows after E3R1; 85 at E1), cases `../02-test-cases-{L,V,AT}.md`, slice `../E1-slice.md`, decisions `../E1-rulings.md` (§9 rulings) and `../E3-rulings.md` (the E3 rulings; **E3R1** applied them here: every node or block it changed says `E3R1` and names its finding). Notation: Code-Wire core (`C:\Users\<user>\Github\code-wire`, `git describe --tags` = **`v3.1.0-8-gb6cd30d`**), `docs/Notation-Grammar.md`; layout as `../../inc-4/codewire/graph-inc4.md`. No lint, coherence or STE gate was run (memory rule: core only).

How to read it:
- Every node's `func:` starts with **new** or **changed**. A tag **[D-n]** marks a contract or an example that follows decision D-n's recommendation; a different ruling changes only the lines so tagged (the decision's row in `../E1-rulings.md` §3 says how).
- Example sources: the case ids of `../02-test-cases-*.md` (`R-A2L-LIST.<nnn>/<k>` = item k of the row's threshold); `P1` = `../evidence-e1/i7e1-pilot-transcript.txt`, `P2` = `../evidence-e1/i7e1-app-pilot-transcript.txt` (the values E1 measured with the shipped I-3, I-5 and app on case 08); **derived** = a value that follows from a row and the definitions, no pilot printed it.
- Fixtures: **C08** = case 08 (`tools/synth/make_release_case.py --seed 20260001`), 462 tags (P1 §1); **G2L** = the G2 scene's list text (9 lines, 12 names; P1 §3); **SWA** = `examples/case_00_public/software_a.a2l` (13,990 names); **HOST** = a fixture A2L with a tag named `A[red]` + U+001B + `B` + U+0000 + U+0085 (built by the test, E4).
- Every example is writable as a test that fails on `2dbd7d5a` (the behaviour does not exist there: `../01-requirements.md` Base column) and passes after.

## 1. Groups, files and interfaces

### Groups for E4 (file ownership; pinned by the orchestrator in `interfaces.md` before E4)

| Group | Files (≤ 4) | Owns |
|---|---|---|
| G-L list module (implementer) | `s19_app/tui/a2l_label_list.py` (new), `s19_app/tui/os_clipboard_input.py` (the I-1 hook) | nodes L1–L30 below (E3R1 added L29 `ListAwareFilterInput.action_move_choice`, L30 `LabelRanker._work`); entities `[Data: LabelListEntry]`, `[Data: LabelListResolution]`, `[Data: LabelRanker]` |
| G-V viewer (implementer) | `s19_app/tui/app/a2l_view.py`, `s19_app/tui/app/compose_screens.py`, `s19_app/tui/styles.tcss` (`app/patch.py` stays out: E3A-07's list-mode write is routed through V4 and V8, below) | nodes V1–V13; entities `[Data: A2lViewMixin._a2l_list_resolution]`, `[Data: A2lViewMixin._a2l_label_ranker]`, `[Config: styles.tcss A2L panes]` |
| G-T-L (tester) | `tests/test_b103_label_list.py` (new; the R-A2L-LIST.078/3 timing test `@pytest.mark.serial_timing`) | `../02-test-cases-L.md` (103 cases); I-7 interface checks |
| G-T-V (tester) | `tests/test_b103_a2l_list_view.py` (new; the R-A2L-LIST.035 timing test `@pytest.mark.serial_timing`) | `../02-test-cases-V.md` (116 cases) |
| E4 retargets (owner: Inc 7 E4, after `b103-inc1b` is final, DF-10) | the Inc 1a/1b clipboard tests, the session census, the tc019/tc016s layout tests | `../E1-slice.md` §5 (E3R1, E3A-01, E3A-09, E3A-11) |
| G-T-AT (tester) | `tests/test_b103_a2l_list_at.py` (new) | `../02-test-cases-AT.md` (10 cases) |

Order inside E4: G-L and G-V in parallel against the pinned I-7; testers in parallel against this graph; then the integrator. G-V needs G-L's module to run its examples; G-L's examples need no G-V code (a host app in the tests).

### Interfaces

| Id | State | Pinned form | Producer → consumers |
|---|---|---|---|
| I-1 | **pinned additive change** (orchestrator, D-5 A; placement re-pinned at E3R1, E3S-03 and E3A-16) | `OsClipboardInput._take_paste(self, text: str) -> bool`, default `False` (L26). Both routes call it at one place: after the 65,536-character cap — in `action_paste` also after the empty-text check (`os_clipboard_input.py:1075-1093`), so the read-failure warning keeps its route — and before the first-line cut, **only when `self.restrict` is not set**, with `_strip_paste_controls(text, multiline=True)` of the capped text (every override gets a stripped text and never has to strip). `True` → the box took the paste; nothing more is inserted. | Inc 1a → G-L (`ListAwareFilterInput`); later Inc 8/9 editors inherit the same placement |
| I-3 | consumed, unchanged | `build_label_index`, `rank`, `LabelMatch`, `MatchRule` (`../../inc-4/codewire/graph-inc4.md` §Groups); limits 20 (dropdown) and 3 (closest names), never more than 20 (obligation 6) | Inc 4 → G-L (`LabelRanker`) |
| I-4 | consumed, unchanged | `_a2l_view_generation` keys the prepared name list; the common refresh ends in `update_a2l_view` (`a2l_view.py:910`) | Inc 5 → G-V (V9) |
| I-5 | consumed, unchanged | `parse_parameter_list(text: str) -> list` (`a2l_parameter_picker.py:69`) | existing → G-L (L1, L3), G-V (V2) |
| I-7 | **re-pinned at E3R1 (E3A-03; E3A-02, -04, -05, -06, -10, -12, -14, E3S-01)**, new, G-L → G-V; the orchestrator copies it to `interfaces.md` before E4 | the code block below, complete enough for G-L and G-V to build in parallel | G-L → G-V, G-T-* |

```python
# s19_app/tui/a2l_label_list.py — imports: rich.text, textual (app, binding, containers, screen, widgets, events),
# s19_app.tui.a2l_parameter_picker.parse_parameter_list (I-5), s19_app.tui.services.label_match (I-3),
# s19_app.tui.os_clipboard_input.OsClipboardInput (I-1), s19_app.tui.capped_text_area.CappedTextArea.
# Never imports s19_app.tui.app (the package imports this module: an import cycle).

# E3R1 (E3A-03): this block is the whole G-L → G-V contract; G-V needs nothing of G-L that is not named here.

FOUND, MISSING, DUPLICATE, HIDDEN = "found", "missing", "duplicate", "hidden"
GLYPH = {FOUND: "●", MISSING: "✗", DUPLICATE: "=", HIDDEN: "◐"}
MODE_LABEL = {"all": "All", "invalid": "Invalid", "inmem": "In-memory"}
LIST_COLUMNS = ("#", "Tag", "Status", "Kind", "Address", "Len", "Physical", "Unit", "Limits")   # [D-4]
TEXT_CELL_LABELS = ("Address", "Length", "Physical", "Unit", "Limits")   # E3A-03 (e): the shipped text-mode column
                                  # labels; list_row_cells reads text_cells by exactly these keys
DROPDOWN_ROWS = 8; RANK_LIMIT = 20; CLOSEST_LIMIT = 3; SIMILAR_MAX = 10; MISSING_MAX = 20     # [D-8] [D-9]
VIEWER_RIBBON = 80; WINDOW_RIBBON = 50; SHORT_AT = 64; PREVIEW_MAX = 200                      # E3S-01: PREVIEW_MAX
WIDE_AT = 180; STACK_MIN_WIDTH = 110; STACK_MIN_HEIGHT = 32                                   # [D-2]; E3A-10

def is_list_text(text: str) -> bool: ...
def display_text(name: str, cap: int | None = None) -> str: ...      # cap 64 = the short text (E3S-02)
def resolve_label_list(names: Sequence[str], tags: Sequence[dict],
                       hidden: Callable[[dict], bool] | None = None) -> LabelListResolution: ...
def list_summary_texts(res: LabelListResolution, budget: int) -> tuple[Text, Text, Text]: ...  # counts, ribbon, missing
def list_row_cells(entry: LabelListEntry, text_cells: Mapping[str, Text] | None, mode: str) -> tuple[Text, ...]: ...
def list_card_text(entry: LabelListEntry, closest: Sequence[str] | None) -> Text: ...

@dataclass(frozen=True, slots=True)
class LabelListEntry:                                # E3A-02: no back-reference; two equal resolutions compare equal
    pos: int                      # 1-based pasted position
    name: str                     # the pasted name, as pasted
    status: str                   # FOUND | MISSING | DUPLICATE | HIDDEN
    tag: dict | None              # the enriched tag (FOUND, DUPLICATE, HIDDEN); None for MISSING
    first_pos: int | None         # DUPLICATE: the position of the first occurrence

@dataclass(frozen=True, slots=True)
class LabelListResolution:
    entries: tuple[LabelListEntry, ...]
    rows: tuple[dict, ...]        # E3A-02, E3A-07: same order as entries; what row key a2l:<i> maps to.
                                  # FOUND, DUPLICATE, HIDDEN → the tag object itself (`is`, so the write route's id()
                                  # map holds); MISSING → {"name": <name>, "_list_pos": <pos>} (a new dict, no cycle)
    def count(self, status: str) -> int: ...

class LabelRanker:                                   # one per app; G-V creates it (V9)
    def __init__(self, app: App) -> None: ...
    @property
    def ready(self) -> bool: ...
    def prepare(self, names: Sequence[str], generation: int) -> None: ...
    def request(self, key: str, query: str, limit: int,
                deliver: Callable[[list[LabelMatch]], None], current: Callable[[], bool]) -> None: ...
    # E3A-04: keys "filter", "add", "card", "similar:1" … "similar:10" (the slot among the first 10 missing names);
    #   one token per key, so the 10 similar requests of one preview never cancel each other.
    # E3A-06: per key at most one ranking runs and one waits (the latest query); a request while one runs replaces
    #   the waiting one; when the running one ends its result is dropped if stale and the waiting one starts.
    # E3A-05: workers run as app.run_worker(work, thread=True, exit_on_error=False, group="a2l_label_list"); the
    #   worker body (L30) catches every exception of build_label_index / rank and returns through
    #   app.call_from_thread inside `except RuntimeError: return`; _install and _deliver begin
    #   `if not app.is_running: return`. `current` and `deliver` hold the widget they serve and return False /
    #   do nothing when `not widget.is_attached` — never query_one.
    # deliver for a dropdown is functools.partial(box.show_ranked, query) (E3A-03 (f)).

class LabelSuggestBox(Static):                       # ids: #a2l_filter_suggest (viewer), #a2l_list_add_suggest (window)
    def __init__(self, *, accept: str, id: str) -> None: ...   # accept: "tab complete" | "enter add to the list"
    def show_ranked(self, query: str, matches: Sequence[LabelMatch]) -> None: ...
    def close(self) -> None: ...
    def move(self, step: int) -> None: ...
    is_open: bool; choice: str | None                # choice = LabelMatch.name of the highlighted row

class ListAwareFilterInput(OsClipboardInput):        # id #a2l_tags_filter_input (kept)
    def __init__(self, *, suggest: LabelSuggestBox, list_enabled: Callable[[], bool],
                 placeholder: str, id: str) -> None: ...
    # E3A-03 (a), (g): `suggest` is the sibling dropdown G-V composes under the filter row (#a2l_filter_suggest);
    #   `list_enabled()` is True while the filter field is `name` or `all` (D-3, E3A-12).
    # bindings: escape → action_esc, up → action_move_choice(-1), down → action_move_choice(1),
    #   tab → action_complete; each raises textual.actions.SkipAction when it does not apply (dropdown closed,
    #   nothing to clear), so the key reaches its shipped handling.
    def action_move_choice(self, step: int) -> None: ...
    def action_esc(self) -> None: ...
    def action_complete(self) -> None: ...
    def _take_paste(self, text: str) -> bool: ...    # the I-1 override; `text` arrives stripped (I-1 placement)

class LabelListHost(Protocol):                       # E3A-03 (b): the app as G-L sees it; A2lViewMixin implements it
    def a2l_open_label_list(self) -> None: ...

class LabelListPasteModal(ModalScreen[list[str] | None]):
    # E3A-03 (c): the one route back is dismiss(names) / dismiss(None) and the push_screen callback; no message
    def __init__(self, *, tags: Sequence[dict], ranker: LabelRanker, names: Sequence[str], wide: bool) -> None: ...
    # wide is fixed when the window opens (E3A-14)
    def refresh_tags(self, tags: Sequence[dict]) -> None: ...
    # ids: #a2l_list_dialog, #a2l_list_add, #a2l_list_add_suggest, #a2l_list_text, #a2l_list_counts,
    #      #a2l_list_preview, #a2l_list_more (E3S-01), #a2l_list_missing, #a2l_list_similar, #a2l_list_note,
    #      #a2l_list_apply, #a2l_list_cancel; its preview debounce is the screen's own set_timer (stops with it)

class A2LExplorerBody(Container):                    # E3A-03 (d)
    def __init__(self, tags_pane: Widget, hex_pane: Widget, *, id: str) -> None: ...   # id "a2l_panes" (kept)
    # children: tags_pane = #a2l_tags_pane; hex_pane = #a2l_hex_pane, which holds #a2l_detail_card and #a2l_hexbox
    #   (the hex controls and #alt_hex_scroll); classes set by on_resize: -wide (wide body), -short (short body),
    #   neither (stacked body) (E3A-10); bindings alt+p, alt+a (priority)
```

Errors and purity (I-7; G-T-L checks them as interface checks): `resolve_label_list` and the three text builders are pure (same inputs → equal outputs, and two resolutions of the same inputs compare equal with `==`, with no `RecursionError` — E3A-02; they are not hashable, since they hold dicts, and nothing hashes them; no input mutated; a found, duplicate or hidden row *is* the tag object, so the jump handler and the write route read the real tag); `display_text` never raises for any `str`; `LabelRanker.request` never raises and never calls `rank` on the UI thread (R-A2L-LIST.073); `LabelRanker` keeps no reference to a widget after `deliver` ran. The operator-visible failure paths of the deferred work are rows (R-A2L-LIST.084–.086).

## 2. Baseline (the code in scope at `2dbd7d5a`, real callers)

The extractor's baseline run and the callers of every changed function are in `../E1-slice.md` §3 (`marks=21 graph_nodes=21 calls=13 findings=0`). The flows the prototype changes:
- **Filter:** `NavigationMixin.on_input_changed` (`navigation.py:1494-1497`) sets `a2l_tags_filter_text` = the stripped value and calls `_schedule_a2l_filter_refresh` → 0.15 s → `_refresh_a2l_filtered_tags` → `_filter_a2l_tags` (mode, then substring via `_tag_matches_filter`) → `update_a2l_tags_view` (one page, text-mode cells by `_build_a2l_table_cells`, then `call_after_refresh(_fit_a2l_tag_cells)`).
- **Modes:** `core.py:1108-1116` set `a2l_tags_filter_mode` and call `_refresh_a2l_filtered_tags`; nothing marks the active button there (Inc 5 marks `All` in `_refresh_a2l_dependent_views`, `a2l_view.py:899-908`).
- **Card and jump:** `on_data_table_row_highlighted` → `A2LDetailCard.show_tag(tag)` (`navigation.py:1421`); `on_data_table_row_selected` → `_jump_to_tag_by_data(tag)` (`navigation.py:1374`), both through `_a2l_row_key_to_tag`.
- **Paste:** `OsClipboardInput._on_paste` (`os_clipboard_input.py:926-951`) and `.action_paste` (`:1038-1104`) keep the first line; the right-click route calls `action_paste` (`:975`).
- **A2L transition:** `_refresh_a2l_dependent_views` (four routes, `E1-slice.md` §3) → `update_a2l_view` (`:938-998`), which re-reads the filter box (`:995-996`), so a list text survives a transition.
- **Layout:** `#a2l_panes` horizontal, tags `4fr`, hex `3fr` (`styles.tcss:440-456`); the hex view is 42 columns at 118 and 78 at 220, and the 81-character hex row wraps at both (P2 §3).

## Nodes

is_list_text
req: R-A2L-LIST.001, R-A2L-LIST.006, R-A2L-LIST.062
in: str text
out: bool is_list
module: s19_app/tui/a2l_label_list.py
func: new. `len(parse_parameter_list(text)) >= 2` (I-5; the definition *list text*).
examples: (R-A2L-LIST.001/1) G2L → `True` (12 names, P1 §3)
examples: (R-A2L-LIST.062/2) `0042 val` → `True` (2 names; the G2 page's effect (2))
examples: (R-A2L-LIST.062/1) `0017` → `False`; ` ,;\n ` → `False` (R-A2L-LIST.001/3: 0 names)

display_text
req: R-A2L-LIST.076, R-A2L-LIST.077, R-A2L-LIST.019, R-A2L-LIST.025, R-A2L-LIST.066
in: str name; int? cap = None
out: str shown
module: s19_app/tui/a2l_label_list.py
func: new; E3R1 (E3S-06, E3S-02). Replace each character U+0000–U+001F, U+007F–U+009F, U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069 with U+FFFD, one for one (offsets kept, so match spans still index it); then, when `cap` is given and the result is longer than `cap` characters, keep its first `cap - 1` characters and `…`. `display_text(x, 64)` is the *short text* of the definitions, for a name and for an operator text alike. Callers paint the result as `Text(shown)` — never markup.
examples: (R-A2L-LIST.076/1) `A[red]` + U+001B + `B` + U+0000 + U+0085 → `A[red]\ufffdB\ufffd\ufffd` (length 10 kept)
examples: (R-A2L-LIST.076/7) `A` + U+202E + `B` + U+2066 + `C` → `A` + U+FFFD + `B` + U+FFFD + `C` (length 5 kept) [E3R1, E3S-06]
examples: (R-A2L-LIST.066/3) a 300-character text with NUL at index 10 and ESC at index 20, cap `64` → 64 characters: the first 63, with U+FFFD at indexes 10 and 20, then `…` [E3R1, E3S-02]
examples: (R-A2L-LIST.077/1) a 300-character name, cap `64` → its first 63 characters + `…` (64 characters)
examples: (R-A2L-LIST.077/2) a 64-character name, cap `64` → the name, whole

resolve_label_list
req: R-A2L-LIST.001, R-A2L-LIST.002, R-A2L-LIST.003, R-A2L-LIST.004, R-A2L-LIST.005, R-A2L-LIST.035
in: Sequence[str] names; Sequence[dict] tags; (Callable) dict->bool? hidden = None
out: LabelListResolution res
module: s19_app/tui/a2l_label_list.py
func: new; E3R1 (E3A-02, E3A-07). One map `name → first tag with that name` built once (`str(tag.get("name") or "")`), then one pass over `names` in order: a name seen before → DUPLICATE of its first position; else absent from the map → MISSING; else `hidden(tag)` true → HIDDEN; else FOUND. Case kept: no fold. Builds `rows` beside `entries` (I-7): the tag object itself for FOUND, DUPLICATE and HIDDEN; `{"name": name, "_list_pos": pos}` for MISSING. No entry refers to a row or to itself. Cost: one map build plus one lookup per name (R-A2L-LIST.035's control is the scan per name).
examples: (R-A2L-LIST.002/1) names of G2L over C08 → FOUND at 1–6, 8, 9, 12; MISSING at 7 `MAP_0024`, 11 `CURVE_0071`; DUPLICATE at 10 (first_pos `1`) (P1 §3)
examples: (R-A2L-LIST.002/2) [`value_0002`] over C08 → MISSING (case kept)
examples: (R-A2L-LIST.003/2) [`X`, `X`, `X`] over C08 → MISSING, DUPLICATE first_pos `1`, DUPLICATE first_pos `1`
examples: (R-A2L-LIST.004/3) G2L names over `[]` (no A2L) → 11 MISSING, 1 DUPLICATE
examples: (R-A2L-LIST.005/1) G2L over C08 with `hidden` = "mode Invalid leaves the tag out" (C08 has 0 invalid tags, P2 §2) → the 9 found names HIDDEN
examples: (I-7) G2L over C08 → `rows[0] is` the `VALUE_0002` tag of `tags`, `rows[9] is` the same object (DUPLICATE #10), `rows[6] == {"name": "MAP_0024", "_list_pos": 7}` [E3R1, E3A-02, E3A-07]
examples: (I-7, E3A-02) two calls with G2L over C08 → `res1 == res2` is `True` (no `RecursionError`); with `hidden` = mode Invalid likewise
examples: (R-A2L-LIST.035/1) the P1 §5 `software_a` paste (65,522 characters → 2,048 names) over SWA → 2,048 entries, `683` MISSING, `0` DUPLICATE; parse + resolve median 1.2 ms (P1 §5); the whole list-mode refresh (one page of ≤ 200 rows, counts and missing lines) median of 3 ≤ 1.0 s (E4 measures)

list_summary_texts
req: R-A2L-LIST.017, R-A2L-LIST.018, R-A2L-LIST.022, R-A2L-LIST.024, R-A2L-LIST.046, R-A2L-LIST.048, R-A2L-LIST.077
in: LabelListResolution res; int budget
out: tuple(Text counts, Text ribbon, Text missing) lines
module: s19_app/tui/a2l_label_list.py
func: new. The three lines of the definitions: the *counts line*; the *ribbon* of at most `budget` glyphs (spaced when `2 × n ≤ budget`, then ` +<k>`); the *missing line* with at most 20 names of each kind then ` +<k>` [D-9], each name as its short text `display_text(name, 64)`. Styles as the scene (`_av_common.py`): found accent, missing red, duplicate and hidden yellow, the rest muted.
examples: (R-A2L-LIST.017/1) G2L over C08 → counts plain `12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate`
examples: (R-A2L-LIST.017/2) G2L with 9 HIDDEN → counts plain ends `= 1 duplicate  ·  ◐ 9 hidden by mode`
examples: (R-A2L-LIST.018/1) G2L, budget `80` → ribbon plain `● ● ● ● ● ● ✗ ● ● = ✗ ● ` (12 glyphs, spaced)
examples: (R-A2L-LIST.018/2) 100 found names, budget `80` → ribbon plain = 80 × `●` + ` +20`
examples: (R-A2L-LIST.046/2) 60 found names, budget `50` → 50 × `●` + ` +10`
examples: (R-A2L-LIST.022/1) G2L → missing plain `Missing 2 ▸ #7 MAP_0024 · #11 CURVE_0071    Duplicates 1 ▸ #10 VALUE_0002 (= #1)`
examples: (R-A2L-LIST.022/2) 3 found names → missing plain `Missing 0     Duplicates 0 `
examples: (R-A2L-LIST.024/1) 25 missing names → 20 listed + ` +5`
examples: (R-A2L-LIST.024/2) the P1 §5 case-08 paste (4,906 names: 1,636 missing, 2,962 duplicates) → `… +1616` and `… +2942`
examples: (R-A2L-LIST.077/1) a 300-character missing name → in the missing line as 63 characters + `…`

list_row_cells
req: R-A2L-LIST.011, R-A2L-LIST.012, R-A2L-LIST.013, R-A2L-LIST.014, R-A2L-LIST.015, R-A2L-LIST.076
in: LabelListEntry entry; Mapping[str, Text]? text_cells; str mode
out: tuple cells
module: s19_app/tui/a2l_label_list.py
func: new. The nine cells of `LIST_COLUMNS` [D-4]: `#` = the position; `Tag` = glyph + space + `display_text(name)`; `Status` = the status word (hidden: `hidden: ` + `MODE_LABEL[mode]`); `Kind` = `char_type`, else `MEASURE` for section `MEASUREMENT`, else the section; `Address`, `Len`, `Physical`, `Unit`, `Limits` = the given text-mode cells read by the keys `TEXT_CELL_LABELS` (`Address`, `Length`, `Physical`, `Unit`, `Limits`: the shipped column labels, P2 §1; G-V passes `_build_a2l_table_cells(tag)` keyed by column label — E3R1, E3A-03 (e)); MISSING: those five and `Kind` blank. Every cell a `Text` built from plain strings.
examples: (R-A2L-LIST.011/1) FOUND `VALUE_0002` → Tag `● VALUE_0002`
examples: (R-A2L-LIST.011/2) MISSING `MAP_0024` → Tag `✗ MAP_0024`
examples: (R-A2L-LIST.015/1) MISSING `MAP_0024` → cells 4–9 `''`
examples: (R-A2L-LIST.012/3) DUPLICATE #10 → Status `dup of #1`; (R-A2L-LIST.012/4) HIDDEN, mode `inmem` → `hidden: In-memory`
examples: (R-A2L-LIST.013/3) `MEASUREMENT_0005` (char_type `None`, section `MEASUREMENT`, P2 §1) → Kind `MEASURE`; (R-A2L-LIST.013/1) `VALUE_0002` → `VALUE`
examples: (R-A2L-LIST.014/1) `VALUE_0002` with its text cells (P2 §1) → Address `0x00000014`, Len `2`, Physical `347190.0`, Limits `0..655350`
examples: (R-A2L-LIST.014/1, E3A-03 (e)) `text_cells` keyed by the 16 shipped column labels (P2 §1) → read only the keys of `TEXT_CELL_LABELS`; a mapping that lacks `Length` raises `KeyError` in the interface check, not a blank cell [E3R1]
examples: (R-A2L-LIST.076/1) HOST name FOUND → Tag plain `● A[red]\ufffdB\ufffd\ufffd`, `spans == []`

list_card_text
req: R-A2L-LIST.027, R-A2L-LIST.028, R-A2L-LIST.029, R-A2L-LIST.030, R-A2L-LIST.076, R-A2L-LIST.077
in: LabelListEntry entry; Sequence[str]? closest
out: Text lines
module: s19_app/tui/a2l_label_list.py
func: new; E3R1 (E3S-09). MISSING: `✗ <short text of the name>  not in this A2L`, `pasted #<p>`, and — when `closest` is not `None` — `closest ` + the names joined by ` · `, or `closest —` for `[]` [D-12]. DUPLICATE: `duplicate of pasted #<first_pos>`. HIDDEN: `hidden by the active filter mode`. FOUND: empty `Text`. (G-V appends this to the shipped card text for DUPLICATE and HIDDEN.)
examples: (R-A2L-LIST.027/1) MISSING #7 `MAP_0024`, closest `None` → plain `✗ MAP_0024  not in this A2L\npasted #7`
examples: (R-A2L-LIST.028/2) the same, closest `[]` → adds `closest —` (P1 §4: no ranked name)
examples: (R-A2L-LIST.028/1) MISSING `VALUE_002`, closest [`VALUE_0020`, `VALUE_0021`, `VALUE_0022`] (P1 §4) → adds `closest VALUE_0020 · VALUE_0021 · VALUE_0022`
examples: (R-A2L-LIST.029/1) DUPLICATE #10 → `duplicate of pasted #1`; (R-A2L-LIST.030/1) HIDDEN → `hidden by the active filter mode`
examples: (R-A2L-LIST.077/4) MISSING #1, a 300-character name, closest `None` → line 1 plain = `✗ ` + its first 63 characters + `…` + `  not in this A2L` [E3R1, E3S-09]

LabelRanker.prepare
req: R-A2L-LIST.072, R-A2L-LIST.074, R-A2L-LIST.084
in: Sequence[str] names; int generation
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelRanker] (replace)
func: new [D-13]; E3R1 (E3A-05). If `generation` equals the generation already prepared or being prepared, return. Else record it, drop the old index (`ready` becomes `False`) and start one thread worker (`app.run_worker(work, thread=True, exit_on_error=False, group="a2l_label_list")`) whose body is `_work` (L30) running `build_label_index(names)` and handing the index to `_install`. `names` is copied to a tuple on the UI thread before the worker starts.
examples: (R-A2L-LIST.072/1) C08 names, generation `1` → a worker on a thread ≠ the UI thread builds an index of `462`; `ready` `True` after `_install`
examples: (R-A2L-LIST.072/2) `[]` (unload), generation `2` → an index of `0`; any request then delivers `[]`
examples: (derived) the same names and generation twice → one build only
examples: (R-A2L-LIST.084/2) a spy on `app.run_worker` → called once with `thread=True`, `exit_on_error=False` [E3R1, E3A-05]

LabelRanker._install
req: R-A2L-LIST.072, R-A2L-LIST.074, R-A2L-LIST.084
in: int generation; LabelIndex? index
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelRanker] (replace)
func: new; E3R1 (E3A-05, E3A-04). UI thread. First `if not self._app.is_running: return` (the index and every held request are dropped with the ranker). `index` `None` (the build raised, L30) → drop it and every held request; `ready` stays `False`. If `generation` is not the latest prepared generation, drop the index (a newer A2L won). Else keep it, set `ready`, and re-issue, through `request`'s ready path, the one held request per key whose token is still that key's latest (R-A2L-LIST.074).
examples: (R-A2L-LIST.074/1) build held; `0017` requested for key "filter" (held); build released → the held request runs and delivers 5 matches (P1 §2)
examples: (R-A2L-LIST.084/3) the same, positive arm of the teardown case → 5 rows painted
examples: (R-A2L-LIST.084/1) build held, `0017` held for "filter"; `run_test` closes the app; build released → `_work`'s `call_from_thread` raises `RuntimeError` inside `except RuntimeError: return` (or `_install` runs and returns at `is_running`): 0 exceptions, `rank` never called, nothing painted [E3R1]
examples: (R-A2L-LIST.084/2) `build_label_index` stand-in raising `ValueError` → `_install(gen, None)`: `ready` `False`, held request dropped, `app.is_running` `True`, no unhandled exception [E3R1]
examples: (derived) generation 1 built after generation 2 was requested → index of 1 dropped, `ready` stays `False`

LabelRanker.request
req: R-A2L-LIST.071, R-A2L-LIST.073, R-A2L-LIST.075, R-A2L-LIST.050
in: str key; str query; int limit; (Callable) list->None deliver; (Callable) ->bool current
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelRanker] (replace)
func: new; E3R1 (E3A-04, E3A-06, E3S-04). UI thread. Give the *key* a new token (the latest token per key wins; keys of I-7: `filter`, `add`, `card`, `similar:1` … `similar:10`). Not ready → hold `(token, query, limit, deliver, current)` for `_install`, one per key (a newer request replaces it). Ready and a ranking for this key running → keep the request as the key's one waiting request (replacing any earlier one); no worker starts. Ready and none running → mark the key running and start one thread worker (`app.run_worker(work, thread=True, exit_on_error=False, group="a2l_label_list")`) whose body is `_work` running `rank(query, index, min(limit, 20))` and handing the result to `_deliver` with the key, the token and the generation. `rank` never runs on the UI thread.
examples: (R-A2L-LIST.073/1) "filter", `cuvre_00`, 20 → `rank` called on a worker thread (thread id ≠ UI thread); `deliver` receives 20 matches, first `CURVE_0001` fuzzy `e1` (P1 §2)
examples: (R-A2L-LIST.073/2) "similar:1", `MAP_0024`, 3 → `rank` on a worker thread; `deliver` receives `[]` (P1 §4)
examples: (I-3 obligation 6) limit `100` → `rank` called with `20`
examples: (R-A2L-LIST.050/1) G2L preview: "similar:1" `MAP_0024` and "similar:2" `CURVE_0071` requested in turn → 2 tokens, 2 workers, both delivered (one token per consumer would drop the first) [E3R1, E3A-04]
examples: (R-A2L-LIST.075/1) "filter" `cuvre_00` running (held); then `cuvre_001`, `cuvre_0012`, `cuvre_00`, `cuvre_0`, `cuvre_00x` requested → no new worker; on release: `cuvre_00`'s result dropped (stale token), one worker for `cuvre_00x` → `rank` called 2 times in all [E3R1, E3A-06]

LabelRanker._deliver
req: R-A2L-LIST.052, R-A2L-LIST.071, R-A2L-LIST.073, R-A2L-LIST.075, R-A2L-LIST.085
in: str key; int token; int generation; list? matches; (Callable) list->None deliver; (Callable) ->bool current
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelRanker] (replace)
func: new; E3R1 (E3A-04, E3A-05, E3A-06). UI thread. First `if not self._app.is_running: return`. Mark the key not running; if the key has a waiting request, start it now (`request`'s ready path). Then call `deliver(matches)` only when `matches` is not `None` (the ranking did not raise, L30), `token` is still the key's latest, `generation` is still the prepared generation and `current()` is true (`current` holds its widget: `False` once `not widget.is_attached`, then the box or text area still holds the query); otherwise drop the result.
examples: (R-A2L-LIST.071/1) "filter": `cu` requested, then `cuvre_00` requested before `cu`'s result → `cu`'s result dropped; only `cuvre_00`'s 20 matches delivered
examples: (R-A2L-LIST.071/2) a result whose generation `1` arrives after an A2L transition prepared generation `2` → dropped
examples: (R-A2L-LIST.052/1) "similar:1" result for a text the operator has edited since (`current()` `False`) → dropped, no similar line painted
examples: (R-A2L-LIST.085/4) "similar:1" held; the paste window dismissed (`#a2l_list_text` detached); released → `current()` `False` without a query → dropped, 0 exceptions, `app.is_running` `True` [E3R1, E3A-05]
examples: (R-A2L-LIST.085/1) "filter" `cuvre_00` held; `run_test` closes the app; released → 0 exceptions, `show_ranked` never called [E3R1, E3A-05]
examples: (R-A2L-LIST.085/5) `rank` stand-in raising `ValueError` → `_deliver(..., None, ...)`: nothing delivered, the key's waiting request (if any) starts, `app.is_running` `True` [E3R1, E3A-05]
examples: (R-A2L-LIST.085/6) positive arm: the same held "filter" and "similar:1" requests released while the box and the window are shown → `show_ranked` and `_on_similar` each called once [E3R1]

LabelRanker._work
req: R-A2L-LIST.084, R-A2L-LIST.085, R-A2L-LIST.072, R-A2L-LIST.073
in: (Callable) ->object job; (Callable) object->None hand_over
out: None
module: s19_app/tui/a2l_label_list.py
func: new (E3R1, E3A-05; the slice's L30). The body of every `LabelRanker` worker, on the worker thread: `try: result = job()` (`build_label_index(names)` or `rank(query, index, limit)`) `except Exception: result = None` (logged as the exception type and the key only, never a name: E3S-08); then `try: app.call_from_thread(hand_over, result) except RuntimeError: return` (the app has stopped: `call_from_thread` raises `RuntimeError("App is not running")`, E3 Probe A §3). Never raises; touches no widget.
examples: (R-A2L-LIST.084/1) the app stopped before the build ends → `call_from_thread` raises `RuntimeError` → returns; 0 exceptions reach the worker manager (`exit_on_error=False` keeps the app from an error exit either way)
examples: (R-A2L-LIST.085/5) `rank` stand-in raising `ValueError("x")` → `hand_over(None)`; the log line names `ValueError` and the key `filter`, not the query
examples: (R-A2L-LIST.073/1) `rank` returns 20 matches → `hand_over` receives the same 20 on the UI thread

LabelSuggestBox.show_ranked
req: R-A2L-LIST.060, R-A2L-LIST.061, R-A2L-LIST.063, R-A2L-LIST.064, R-A2L-LIST.065, R-A2L-LIST.066, R-A2L-LIST.067, R-A2L-LIST.076, R-A2L-LIST.077
in: str query; Sequence[LabelMatch] matches
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelSuggestBox.rows] (replace)
func: new; E3R1 (E3S-02, E3S-09). Keep the first 8 matches, set the choice to row 1, open (class `-open`) and paint: title `<k> of <n> similar names` with <n> = `len(matches)`, written `20+` when it is 20 [D-6]; each row `▸ ` (choice) or two spaces, `display_text(name, 64)` with its spans' characters in the highlight style (spans past the cut are dropped), a space pad, the rule tag (`fuzzy · 1 edit`, `fuzzy · <k> edits`, else the rule word); then the key line of its `accept` and `rank: exact › prefix › substring › token › fuzzy › subsequence`. No match: title `no similar name`, lines `nothing matches '<display_text(query, 64)>'` and `digits must match exactly; a word may have 1–2 typos`, the choice `None`. The choice keeps the real `LabelMatch.name`, never the shown text.
examples: (R-A2L-LIST.063/1) `cuvre_00`, the 20 matches of P1 §2 → 8 rows; row 1 plain starts `▸ CURVE_0001` and ends `fuzzy · 1 edit`
examples: (R-A2L-LIST.065/2) `cuvre_00`, 20 matches → title `8 of 20+ similar names`
examples: (R-A2L-LIST.063/2) `0017`, 5 matches → 5 rows, row 1 `▸ MAP_0017 … substring`
examples: (R-A2L-LIST.065/1) `0017`, 5 matches → title `5 of 5 similar names`
examples: (R-A2L-LIST.064/1) row `CURVE_0001` → characters (0,5) and (6,10) in the highlight style, (5,6) not
examples: (R-A2L-LIST.064/2) row `MAP_0017` for `0017` → (4,8) highlighted
examples: (R-A2L-LIST.066/1) `zzzz`, `[]` → title `no similar name`; lines `nothing matches 'zzzz'` and `digits must match exactly; a word may have 1–2 typos`
examples: (R-A2L-LIST.066/2) a 257-character query, `[]` → `nothing matches '` + its first 63 characters + `…'` [E3R1, E3S-02]
examples: (R-A2L-LIST.077/3) a 1,024-character tag `LONG_…` matched for `LONG_` (prefix) → its row shows `▸ ` + 63 characters + `…`, then the rule tag `prefix`; `choice` = the whole 1,024-character name [E3R1, E3S-09]
examples: (R-A2L-LIST.067/1) accept `tab complete` → key line `↑↓ choose  tab complete  esc close`; (R-A2L-LIST.067/2) accept `enter add to the list` → `↑↓ choose  enter add to the list  esc close`
examples: (R-A2L-LIST.061/1) add line `0042 val` → rows `VALUE_0042 … token`, `VAL_BLK_0042 … token` (P1 §2)
examples: (R-A2L-LIST.076/1) HOST name as a match → its row shows `A[red]\ufffdB\ufffd\ufffd`, no markup span

LabelSuggestBox.move
req: R-A2L-LIST.068
in: int step
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelSuggestBox.rows] (replace)
func: new. Move the choice by `step`, clamped to the shown rows; repaint. No-op while closed.
examples: (R-A2L-LIST.068/1) `cuvre_00` open, `+1` → choice `CURVE_0002`; (R-A2L-LIST.068/2) `+1` × 9 → `CURVE_0008`; (R-A2L-LIST.068/3) `-1` at row 1 → `CURVE_0001`

ListAwareFilterInput._take_paste
req: R-A2L-LIST.033, R-A2L-LIST.034, R-PASTE.1, R-TUI-043.4, R-PASTE.29
in: str text
out: bool taken
module: s19_app/tui/a2l_label_list.py
modify: [Data: Input.value] (replace)
func: new, overrides L26 [D-5]; E3R1 (E3S-03, E3A-12). The text arrives already stripped by the route (I-1 placement: `_strip_paste_controls(text, multiline=True)`), so this override only parses. `list_enabled()` false (filter field not `name` or `all`) → return `False`. Else take its pasted names; 2 or more → `value` = the names joined by `, `, cursor `0`, return `True`; else return `False` (the box's first-line paste runs as today). The joined value is not cut (E3S-05).
examples: (R-A2L-LIST.033/1) G2L → `True`; value `VALUE_0002, CURVE_0001, MAP_0003, MEASUREMENT_0005, VALUE_0042, CURVE_0017, MAP_0024, MAP_0001, MEASUREMENT_0012, VALUE_0002, CURVE_0071, VALUE_0118` (P1 §3); cursor `0`
examples: (R-A2L-LIST.034/1) the route delivers `VALUE_0002\x1b[31m\nMAP_0003`, stripped by the route to `VALUE_0002[31m\nMAP_0003` → value `VALUE_0002[31m, MAP_0003`
examples: (R-A2L-LIST.034/2) `A\u202eB\nC` → value `AB, C`
examples: (R-PASTE.1/2) `VALUE_0002` (one name) → `False`; the stock route inserts `VALUE_0002`
examples: (R-PASTE.1/3) `P_CTRL` (`tests/support/b103_clipboard.py:291`), stripped by the route → one name → `False`; the stock route inserts `A[13DB\x00C` [E3R1, E3A-01 (2)]
examples: (R-A2L-LIST.033/4) G2L with `list_enabled()` `False` (field `source`) → `False`; the stock route inserts `VALUE_0002` [E3R1, E3A-12]
examples: (R-A2L-LIST.033/5) 32,768 one-character names joined by new lines (65,535 characters) → `True`; `len(value)` `98302` [E3R1, E3S-05]

ListAwareFilterInput.action_esc
req: R-A2L-LIST.032, R-A2L-LIST.070
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: Input.value] (replace)
func: new (binding `escape`); E3R1 (E3A-03 (a)). Dropdown open → close it, text kept. Else the value is a list text → value `''` (text mode). Else `raise SkipAction()` (the shipped Esc handling runs).
examples: (R-A2L-LIST.070/1) `cuvre_00` with the dropdown open → closed; value `cuvre_00`
examples: (R-A2L-LIST.032/1) value = G2L joined, no dropdown → value `''`; after the debounce 462 rows
examples: (derived, E3A-03 (a)) value `VALUE`, no dropdown, Esc → `SkipAction`; value `VALUE` kept [E3R1]

ListAwareFilterInput.action_complete
req: R-A2L-LIST.069
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: Input.value] (replace)
func: new (binding `tab`; P1 §7: a box-level tab binding runs before the app's focus move). Dropdown open with a choice → value = the chosen `LabelMatch.name` (never its display text, I-3 obligation 3), cursor at the end, dropdown closed. Else `raise SkipAction()`, so the app's tab moves the focus on, as tab does today (E3R1, E3A-03 (a)).
examples: (R-A2L-LIST.069/1) `cuvre_00`, choice row 1 → value `CURVE_0001`, cursor `10`, dropdown closed
examples: (R-A2L-LIST.069/2) ↓ then tab → value `CURVE_0002`
examples: (R-A2L-LIST.069, control) a name holding U+0007 chosen → value holds U+0007, not U+FFFD
examples: (derived) tab with no dropdown → the focus moves to the next widget

ListAwareFilterInput.action_move_choice
req: R-A2L-LIST.068
in: int step
out: None
module: s19_app/tui/a2l_label_list.py
func: new (E3R1, E3A-03 (a); the slice's L29; bindings `up` → `-1`, `down` → `+1` on the box). Dropdown open → `suggest.move(step)`. Closed → `raise SkipAction()`, so ↑/↓ keep their shipped handling in the box.
examples: (R-A2L-LIST.068/1) `cuvre_00` with the dropdown open, ↓ → `#a2l_filter_suggest` choice `CURVE_0002`
examples: (R-A2L-LIST.068/3) ↑ at row 1 → choice `CURVE_0001` (clamped by `move`)
examples: (derived) `VALUE` with no dropdown, ↓ → `SkipAction`; the box's value and cursor as on base

LabelListPasteModal.compose
req: R-A2L-LIST.043, R-A2L-LIST.044, R-A2L-LIST.045, R-A2L-LIST.047
in: (none)
out: ComposeResult widgets
module: s19_app/tui/a2l_label_list.py
func: new. The scene's dialog: title `Paste a list of labels`; left: `add` + an `AddNameInput` (`#a2l_list_add`, placeholder `part of a name — start, middle, end, a typo`), its `LabelSuggestBox` (accept `enter add to the list`), the label `or paste names — new line , ; space`, a `CappedTextArea` (`#a2l_list_text`, I-1 cap); right: the counts `Static`, the preview `DataTable` (columns `#`, `Name`, `Status`, `Kind`, `Address`, plus `Value`, `Unit` when `wide`; the columns are set once here, from the `wide` given at open — E3R1, E3A-14) and the `Static` `#a2l_list_more` (hidden; E3R1, E3S-01); under: missing, similar, note (`The list filters the viewer (LIST mode, pasted order); nothing is saved. Missing names stay listed so you can fix them.`), buttons `Filter viewer by list  alt+f` and `Cancel  esc`. Every label is a plain string (no markup).
examples: (R-A2L-LIST.043/1) mounted at 118×54 → `#a2l_list_add` placeholder `part of a name — start, middle, end, a typo`; a label reads `or paste names — new line , ; space`
examples: (R-A2L-LIST.044/1) `#a2l_list_note` plain = the note text above
examples: (R-A2L-LIST.045/1) button labels `Filter viewer by list  alt+f`, `Cancel  esc`
examples: (R-A2L-LIST.047/1) `wide` `False` → preview columns `#`, `Name`, `Status`, `Kind`, `Address`; (R-A2L-LIST.047/2) `True` → plus `Value`, `Unit`
examples: (R-A2L-LIST.047/3) `wide` `True` at 220×60, the app resized to 118×54 → still 7 columns [E3R1, E3A-14]

LabelListPasteModal.on_mount
req: R-A2L-LIST.041, R-A2L-LIST.042
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: TextArea.text] (replace)
func: new. Load the given `names` into the text area, one per line, each followed by a new line [D-7]; focus the text area; run the first preview.
examples: (R-A2L-LIST.041/1) names = G2L's 12 → text area holds 12 lines, `VALUE_0002` first, `VALUE_0118` last
examples: (R-A2L-LIST.041/2) names `[]` (text mode) → text `''`
examples: (R-A2L-LIST.042/1) focus = `#a2l_list_text`

LabelListPasteModal._preview
req: R-A2L-LIST.046, R-A2L-LIST.047, R-A2L-LIST.048, R-A2L-LIST.051, R-A2L-LIST.056, R-A2L-LIST.059, R-A2L-LIST.076, R-A2L-LIST.078, R-A2L-LIST.086, R-A2L-LIST.075
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelListPasteModal.res] (replace)
func: new; E3R1 (E3S-01, E3A-04, E3A-05). Runs 0.15 s after the last text-area change, through the screen's own `set_timer` (a token-checked timer, as `_schedule_a2l_filter_refresh`; it stops with the screen). First `if not self.is_attached or not self.app.is_running: return` (R-A2L-LIST.086). Resolve the text's pasted names over the window's tags (no mode: never HIDDEN); paint counts + ribbon (budget 50) over all names; the preview rows (as `list_row_cells`, `Name` = glyph + display text; `Value` = the Physical text) for the first `PREVIEW_MAX` = 200 entries only, and, when there are more, show `#a2l_list_more` with the *more line* `  +<k> more names (the counts above cover all <n>)` (hidden otherwise); the missing line; clear the similar lines and request key `similar:<s>` for the s-th of the first 10 MISSING names in pasted order (limit 3, `deliver` = `functools.partial(self._on_similar, entry)`, `current` = "`#a2l_list_text` is attached and its text is unchanged") [D-8]; with more than 10 missing add `  similar names are shown for the first 10 missing names`. Never writes the text area.
examples: (R-A2L-LIST.046/1) G2L pasted → counts plain `12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate`; ribbon `● ● ● ● ● ● ✗ ● ● = ✗ ● `
examples: (R-A2L-LIST.047/1) G2L at 118×54 → 12 preview rows; row 7 `✗ MAP_0024`, `not in A2L`
examples: (R-A2L-LIST.048/1) G2L → missing plain as `list_summary_texts` R-A2L-LIST.022/1
examples: (R-A2L-LIST.051/1) 11 missing → 10 requests, keys `similar:1` … `similar:10`, and the line `  similar names are shown for the first 10 missing names`; (R-A2L-LIST.051/2) 10 missing → 10 requests, no line
examples: (R-A2L-LIST.078/1) the P1 §5 case-08 paste (4,906 names) → 200 preview rows; `#a2l_list_more` plain `  +4706 more names (the counts above cover all 4906)`; counts line `4906 pasted  ·  …` [E3R1, E3S-01]
examples: (R-A2L-LIST.078/2) 32,768 one-character names → 200 rows; `  +32568 more names (the counts above cover all 32768)` [E3R1, E3S-01]
examples: (R-A2L-LIST.078/3) the same, one `_preview` call timed → median of 3 ≤ 0.25 s on <runner> (200 rows: 0.128 s, E3 security Probe A §4) [E3R1]
examples: (R-A2L-LIST.086/1) the debounce callback captured by a spy on `set_timer`, run after `dismiss(None)` → returns at `is_attached`, 0 exceptions; (R-A2L-LIST.086/2) run after `run_test` closed the app → 0 exceptions; (R-A2L-LIST.086/3) run while open with G2L → counts line painted [E3R1, E3A-05]
examples: (R-A2L-LIST.075/2) 11 missing, the similar rankings held, 3 edits → per key at most one running and one waiting: ≤ 2 `rank` calls per `similar:<s>`, ≤ 20 in all [E3R1, E3S-04]
examples: (R-A2L-LIST.059/1) G2L + `VALUE_002` → text area text identical before and after the similar lines paint
examples: (R-A2L-LIST.076/4) HOST name pasted → its preview row plain `● A[red]\ufffdB\ufffd\ufffd`

LabelListPasteModal._on_similar
req: R-A2L-LIST.049, R-A2L-LIST.050, R-A2L-LIST.052, R-A2L-LIST.077
in: LabelListEntry entry; list matches
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelListPasteModal.similar] (replace)
func: new (the `similar:<s>` `deliver`, called only through `_deliver`, bound as `functools.partial(self._on_similar, entry)`). Set the entry's line `  similar to #<p> <display_text(name, 64)>: ` + the names joined by ` · `, or `none (digits must match exactly)` for `[]` [D-10]; repaint the similar lines in pasted order. E3R1 (E3A-04): each slot sets only its own line, so the lines of #7 and #11 coexist.
examples: (R-A2L-LIST.050/1) #7 `MAP_0024`, `[]` → `  similar to #7 MAP_0024: none (digits must match exactly)` (P1 §4); then #11 `CURVE_0071`, `[]` → both lines shown, #7 first [E3R1, E3A-04]
examples: (R-A2L-LIST.049/1) #3 `VALUE_002`, [`VALUE_0020`, `VALUE_0021`, `VALUE_0022`] → `  similar to #3 VALUE_002: VALUE_0020 · VALUE_0021 · VALUE_0022` (P1 §4)
examples: (R-A2L-LIST.049/2) `value_0002` → `…: VALUE_0002` (P1 §4: exact, case folded by I-3)
examples: (R-A2L-LIST.077/1) a 300-character missing name → its similar line shows 63 characters + `…`, then `: none (digits must match exactly)` (R-A2L-MATCH.38: more than 256 characters → `[]`)

LabelListPasteModal.on_input_submitted
req: R-A2L-LIST.057, R-A2L-LIST.058
in: Input.Submitted event
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: TextArea.text] (append); [Data: Input.value] (clear)
func: new. Only for `#a2l_list_add`. Dropdown open with a choice → append (a new line first when the text is not empty and does not end in one) the chosen `LabelMatch.name` and a new line; add line `''`; dropdown closed. Else nothing.
examples: (R-A2L-LIST.057/1) text = G2L (ends in a new line), add `0042 val`, choice `VALUE_0042` → text = G2L + `VALUE_0042\n`; add line `''`
examples: (R-A2L-LIST.057/2) text `MAP_0003` (no final new line), choice `VALUE_0042` → `MAP_0003\nVALUE_0042\n`
examples: (R-A2L-LIST.058/1) add `zzzz` (no ranked name, no choice) → text and add line unchanged

LabelListPasteModal.action_apply
req: R-A2L-LIST.053, R-A2L-LIST.054
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
func: new (binding `alt+f`, priority; the apply button) [D-11]. `dismiss(names)` with the text's pasted names, or `dismiss(None)` when there is none.
examples: (R-A2L-LIST.053/1) G2L → dismissed with the 12 names; (R-A2L-LIST.054/1) text `''` → dismissed with `None`

LabelListPasteModal.action_cancel
req: R-A2L-LIST.055, R-A2L-LIST.070
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
func: new (binding `escape`; the cancel button). The add line's dropdown open → close it only. Else `dismiss(None)`.
examples: (R-A2L-LIST.070/2) add `0042 val` with its dropdown open, Esc → dropdown closed, window still open
examples: (R-A2L-LIST.055/1) Esc with no dropdown → dismissed with `None`; (R-A2L-LIST.055/2) Cancel → `None`

LabelListPasteModal.refresh_tags
req: R-A2L-LIST.056
in: Sequence[dict] tags
out: None
module: s19_app/tui/a2l_label_list.py
modify: [Data: LabelListPasteModal.res] (replace)
func: new. Keep the new tags and run `_preview` at once (the text is unchanged).
examples: (R-A2L-LIST.056/1) G2L open over C08; tags of an A2L that also holds `MAP_0024` → counts `… ● 10 found  ·  ✗ 1 missing …`

A2LExplorerBody.on_resize
req: R-A2L-LIST.047, R-A2L-LIST.080, R-A2L-LIST.081, R-A2L-LIST.082, R-A2L-LIST.083, R-TUI-037.1, R-TUI-037.2, R-TUI-069.6, R-TUI-069.7
in: events.Resize event
out: None
module: s19_app/tui/a2l_label_list.py
func: new [D-2]; E3R1 (E3A-10). From the body's own size: `-wide` exactly when its width ≥ `WIDE_AT` (180); else `-short` exactly when its width < `STACK_MIN_WIDTH` (110) or its height < `STACK_MIN_HEIGHT` (32); else neither (the stacked body). The stylesheet does the layout (`[Config: styles.tcss A2L panes]`).
examples: (R-A2L-LIST.080/1) body at 118×54 (P3: 112×39) → no `-wide`, no `-short` (stacked); (R-A2L-LIST.081/1) at 220×60 (196 wide) → `-wide`
examples: (R-TUI-037.1/1) 80×24 (P3: 74×9) → `-short`; (R-TUI-037.1/2) 120×30 (96×15) → `-short`; (R-TUI-037.1/3) 160×40 (136×25) → `-short`; (R-A2L-LIST.082/2) 80×54 (74×39) → `-short` [E3R1]
examples: (derived) a body of 112×31 → `-short`; 112×32 → stacked; 109×39 → `-short`
examples: (R-TUI-069.7/3) 120×30 → `-short`, so the card's cap is 5 lines; a card 4 lines longer than that scrolls (`[Config: styles.tcss A2L panes]`) [E3R1, E3A-11]

A2LExplorerBody.action_paste_list
req: R-A2L-LIST.040
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
func: new (binding `alt+p`, priority, on the body; and the `#a2l_paste_list_button` press, stopped here). Call `app.a2l_open_label_list()` (V11).
examples: (R-A2L-LIST.040/1) focus in `#a2l_tags_list`, alt+p → the screen stack's top is a `LabelListPasteModal` titled `Paste a list of labels`

A2LExplorerBody.action_mode_all
req: R-A2L-LIST.026
in: (none)
out: None
module: s19_app/tui/a2l_label_list.py
func: new (binding `alt+a`, priority). Press `#a2l_filter_all` (the shipped handler `core.py:1108` sets the mode and refreshes).
examples: (R-A2L-LIST.026/1) mode `invalid`, focus in the filter box, alt+a → `a2l_tags_filter_mode` `all`

OsClipboardInput._take_paste
req: R-PASTE.1, R-TUI-043.4, R-PASTE.29
in: str text
out: bool taken
module: s19_app/tui/os_clipboard_input.py
func: new (I-1 hook) [D-5]; placement pinned at E3R1 (E3S-03). Return `False`. Called by L27 and L28 with `_strip_paste_controls(capped, multiline=True)`, before the first-line cut, and never on a box whose `restrict` is set; a subclass that takes the paste returns `True`.
examples: (R-PASTE.1/1) a stock `OsClipboardInput` (the Load box) → `False`, so a two-line paste inserts its first line as today
examples: (R-PASTE.1/4) a test subclass with `restrict` set whose override returns `True` and counts its calls; the G2 list pasted → 0 calls; R-LOADDLG.20's whole-line refusal as on base [E3R1, E3S-03]

OsClipboardInput._on_paste
req: R-PASTE.1, R-A2L-LIST.033, R-A2L-LIST.034
in: events.Paste event
out: None
module: s19_app/tui/os_clipboard_input.py
func: changed; E3R1 (E3S-03). After the 65,536-character cap (`os_clipboard_input.py:940-941`) and before the first-line cut (`:943`): `if not self.restrict and self._take_paste(_strip_paste_controls(capped, multiline=True))`: `prevent_default()`, `stop()`, return. The rest unchanged (first-line cut, then the `restrict` branch `:944-949` or the single-line strip).
examples: (R-A2L-LIST.033/1) the terminal paste of G2L into `#a2l_tags_filter_input` → value = G2L joined by `, ` (no stock insert after it)
examples: (R-PASTE.1/1) the same paste into the Load box → its first line `VALUE_0002`
examples: (R-A2L-LIST.034/3) the terminal paste of `VALUE_0002\x1b[31m\nMAP_0003` into the filter box → the hook's argument is `VALUE_0002[31m\nMAP_0003` (no ESC) [E3R1, E3S-03]
examples: (R-PASTE.1/3) the terminal paste of `P_CTRL` into the filter box → the hook returns `False`; value `A[13DB\x00C` (the stock cut and strip) [E3R1, E3A-01 (2)]

OsClipboardInput.action_paste
req: R-TUI-043.4, R-PASTE.29, R-A2L-LIST.033
in: (none)
out: None
module: s19_app/tui/os_clipboard_input.py
func: changed; E3R1 (E3S-03, E3A-16). After the read cascade, the cap (`read_os_clipboard` `:636` or the internal fallback `:1073`) and the empty-text check (`:1075-1093`, so the read-failure warning keeps its route), before the first-line cut (`:1094`): `if not self.restrict and self._take_paste(_strip_paste_controls(text, multiline=True))`: return. The rest unchanged (the `restrict` branch `:1095-1103`, the log line of counts and lengths `:1108-1112`); the right-click route (`:975`) calls this, so it follows.
examples: (R-A2L-LIST.033/2) Ctrl+V with the clipboard seam (`deps`/module patch, never the real clipboard) returning G2L → value = G2L joined
examples: (R-A2L-LIST.033/3) right-click with no selection, same seam → the same value
examples: (R-TUI-043.4/1) Ctrl+V of G2L in the Load box → `VALUE_0002`
examples: (R-PASTE.29/1) right-click with no selection in the Load box, the seam returning G2L → `VALUE_0002` inserted at the press
examples: (R-TUI-043.4/3) Ctrl+V in the filter box, the seam returning `P_CTRL` → `A[13DB\x00C`; (R-PASTE.29/3) the same by right-click → at the press [E3R1, E3A-01 (2)]
examples: (derived, E3A-16) the seam failing (no text) → the read-failure warning as on base; the hook not called

ComposeScreensMixin._compose_screen_a2l
req: R-A2L-LIST.007, R-A2L-LIST.008, R-A2L-LIST.010, R-A2L-LIST.033, R-A2L-LIST.040, R-A2L-LIST.080, R-A2L-LIST.081
in: (none)
out: Container section
module: s19_app/tui/app/compose_screens.py
func: changed; E3R1 (E3A-03). The scene's composition, every shipped id kept. The dropdown is built first, `suggest = LabelSuggestBox(accept="tab complete", id="a2l_filter_suggest")`, and handed to the box: `ListAwareFilterInput(suggest=suggest, list_enabled=lambda: self.a2l_tags_filter_field in ("name", "all"), placeholder=…, id="a2l_tags_filter_input")` [D-3]. The filter row = mode tag `Label` (`#a2l_filter_mode_tag`), that `ListAwareFilterInput` (placeholder `type part of a name — or paste a list (new line , ; space)`), `Button("Paste list…  alt+p", id="a2l_paste_list_button")`, `Field: name`, `All`, `Invalid`, `In-Memory`; `suggest` (composed here, under the filter row); the find row (find box, `Find next`, `Page Prev`, `Page Next` — shipped ids and labels); `#a2l_filter_menu`; `Static` `#a2l_list_chips`; `Static` `#a2l_list_missing` (hidden); the `A2LTagTable` (`fixed_columns=2`, unchanged); the summary. Tags pane: a `Vertical` `#a2l_tags_pane` holding the above. Hex pane: a `Container` `#a2l_hex_pane` holding `ListAwareDetailCard` (`#a2l_detail_card`) and a `Container` `#a2l_hexbox` with the hex controls and `#alt_hex_scroll`. Body: `A2LExplorerBody(tags_pane, hex_pane, id="a2l_panes")` (I-7).
examples: (R-A2L-LIST.008/1) mounted, empty filter → `#a2l_filter_mode_tag` plain `FILTER`
examples: (R-A2L-LIST.040/2) `#a2l_paste_list_button` label `Paste list…  alt+p`; a click → the paste window
examples: (R-A2L-LIST.010/1) list mode at 80×54 scrolled fully right → the `#` and `Tag` cells at their unscrolled x (fixed columns 2 of `LIST_COLUMNS`)
examples: (derived) every id the shipped tests query (`#a2l_tags_filter_input`, `#a2l_filter_all`, `#a2l_tags_list`, `#a2l_tags_summary`, `#a2l_detail_card`, `#alt_hex_view`, `#alt_search_input`, `#alt_goto_input`, `#a2l_tag_find_input`, `#a2l_tags_pane`, `#a2l_hex_pane`) is present once
examples: (R-A2L-LIST.033/4) field set to `source` → the box's `list_enabled()` `False`; `name` or `all` → `True` [E3R1, E3A-12]
examples: (I-7) `query_one("#a2l_tags_filter_input").suggest is query_one("#a2l_filter_suggest")` [E3R1, E3A-03]

A2lViewMixin._a2l_list_names
req: R-A2L-LIST.006, R-A2L-007.2, R-A2L-LIST.008
in: (none)
out: list? names
module: s19_app/tui/app/a2l_view.py
func: new [D-3]; E3R1 (E3A-08). An A2L is loaded (`self.current_a2l_data`), the filter field is `name` or `all` and `a2l_tags_filter_text` is a list text → its pasted names; else `None` (text mode).
examples: (R-A2L-LIST.006/1) text = G2L joined, field `name` → the 12 names
examples: (R-A2L-LIST.006/3) the same, field `all` → the 12 names [D-3]
examples: (R-A2L-007.2/1) `synthetic`, field `all` → `None` (one name: text mode)
examples: (derived) G2L joined, field `address` → `None`
examples: (R-A2L-LIST.008/3) G2L joined, field `name`, no A2L loaded (after an unload) → `None` [E3R1, E3A-08]

A2lViewMixin._filter_a2l_tags
req: R-A2L-LIST.005, R-A2L-LIST.006, R-A2L-007.1, R-A2L-007.6, R-A2L-007.7, R-A2L-007.8
in: list tags
out: list rows
module: s19_app/tui/app/a2l_view.py
modify: [Data: A2lViewMixin._a2l_list_resolution] (replace)
func: changed; E3R1 (E3A-02, E3A-07). List mode (`_a2l_list_names()` not `None`): resolve those names over `tags` with `hidden` = "the active mode's own test leaves the tag out" (the shipped mode test, the text ignored); keep the resolution; return `list(resolution.rows)` in pasted order. Text mode: resolution `None`; the shipped mode-then-substring filter, unchanged.
examples: (R-A2L-LIST.006/1) G2L over C08 → 12 rows; rows[0] `is` the `VALUE_0002` tag; rows[9] `is` the same tag (DUPLICATE #10); rows[6] `== {"name": "MAP_0024", "_list_pos": 7}` [E3R1]
examples: (R-A2L-LIST.005/2) A2L only (no image), mode `inmem`, G2L → the 9 found names HIDDEN; 12 rows still
examples: (R-A2L-007.1/2) `cuvre_00` (text mode) → `[]` (G2 scene hoy.av-typo)
examples: (R-A2L-007.7/1) text mode, `Invalid` over C08 → `[]` (P2 §2: 0 invalid)
examples: (R-A2L-007.6/1) text mode, `All`, `''` over C08 → `462` rows (P2 §2)
examples: (R-A2L-007.8/1) text mode, `In-Memory`, `''` over C08 → `402` rows (P2 §2)

A2lViewMixin._refresh_a2l_filtered_tags
req: R-A2L-LIST.025, R-A2L-LIST.019, R-A2L-LIST.006, R-A2L-LIST.036
in: bool preserve_anchor
out: None
module: s19_app/tui/app/a2l_view.py
func: changed; E3R1 (E3A-07, E3S-02). **List mode with `preserve_anchor=True`** (the in-place write route's fallback, `patch.py:1847`, its only `True` caller — `E1-slice.md` §3): call `_repaint_a2l_tag_cells()` (V8: it re-resolves over the new enriched tags and writes the page in place, no clear) and `_paint_a2l_filter_chips()`; return. Every other call as today (filter, anchor, `update_a2l_tags_view`), then `_paint_a2l_filter_chips()`. In text mode with no row, a non-empty text and a mode other than `all`: when the text matches at least one tag under `all`, pass the empty message `No tag matches '<display_text(text, 64)>' with mode <mode label> — <n> match with mode All alt+a` (else today's `No A2L tags match '<text>'.`).
examples: (R-A2L-LIST.025/1) A2L only, mode `inmem`, `VALUE_0002` → summary `No tag matches 'VALUE_0002' with mode In-memory — 1 match with mode All alt+a`
examples: (R-A2L-LIST.025/2) the same with `VALUE` → `… — 208 match with mode All alt+a` (derived: C08 has 208 VALUE names, P1 §1)
examples: (R-A2L-LIST.025/3) a fixture tag (A2L only) named by a 300-character text holding NUL and ESC, that text, mode `inmem` → `No tag matches '` + 63 characters (U+FFFD for NUL and ESC) + `…' with mode In-memory — 1 match with mode All alt+a` [E3R1, E3S-02]
examples: (R-A2L-LIST.036/3) G2L shown (missing #7, duplicate #10); the write route maps `_a2l_filtered_tags` by `id()`, #7 is not an enriched tag → the fallback calls this with `preserve_anchor=True` → no `clear()`; the written tag's Physical cell updated in place [E3R1, E3A-07]

A2lViewMixin._paint_a2l_filter_chips
req: R-A2L-LIST.007, R-A2L-LIST.008, R-A2L-LIST.017, R-A2L-LIST.018, R-A2L-LIST.019, R-A2L-LIST.020, R-A2L-LIST.021, R-A2L-LIST.022, R-A2L-LIST.023, R-A2L-LIST.024
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: new. Mark the active mode's button (class `-on`; R-A2L-007.9). List mode: mode tag `LIST`; chips = ` LIST ` + 2 spaces + counts, a new line, `order ` + ribbon (budget 80) + `   field ignored in LIST mode · esc back to text filter · alt+p edit the list`, a new line, the mode line; `#a2l_list_missing` shown with the missing line. Text mode: mode tag `FILTER`; chips = ` TEXT ` + 2 spaces + (`'<text>' in <field>` or `no text filter`) + `  ·  showing <n> of <T>` + `   paste several names, or alt+p, to filter by a LIST`, a new line, the mode line; `#a2l_list_missing` hidden. Mode line: `mode All · no tag hidden by mode (<T> tags)`, or `mode <label> · hides <h> of <T> tags  alt+a All` with <h> = T − the tags the mode keeps with no text. Every text built from plain strings; the filter text as its short text `display_text(text, 64)` (E3R1, E3S-02).
examples: (R-A2L-LIST.017/1) G2L over C08 → chips line 1 plain ` LIST   12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate`
examples: (R-A2L-LIST.018/1) chips line 2 plain `order ● ● ● ● ● ● ✗ ● ● = ✗ ●    field ignored in LIST mode · esc back to text filter · alt+p edit the list`
examples: (R-A2L-LIST.019/1) `VALUE` in `name` → ` TEXT   'VALUE' in name  ·  showing 208 of 462   paste several names, or alt+p, to filter by a LIST`; (R-A2L-LIST.019/2) `''` → ` TEXT   no text filter  ·  showing 462 of 462   …`
examples: (R-A2L-LIST.020/1) mode `all` → `mode All · no tag hidden by mode (462 tags)`
examples: (R-A2L-LIST.021/1) mode `invalid` → `mode Invalid · hides 462 of 462 tags  alt+a All`; (R-A2L-LIST.021/2) `inmem`, image + A2L → `mode In-memory · hides 60 of 462 tags  alt+a All` (P2 §2: 402 kept); (R-A2L-LIST.021/3) `inmem`, A2L only → `… hides 462 of 462 …`
examples: (R-A2L-LIST.007/1) G2L → mode tag `LIST`
examples: (R-A2L-LIST.023/1) text mode → `#a2l_list_missing` hidden
examples: (R-A2L-LIST.019/3) field `unit`, a 300-character text holding NUL and TAB → ` TEXT   '` + 63 characters (U+FFFD for NUL and TAB) + `…' in unit  ·  showing 0 of 462   …` [E3R1, E3S-02]
examples: (R-A2L-LIST.023/2) G2L shown, A2L unloaded → resolution `None`; mode tag `FILTER`; `#a2l_list_missing` hidden; no ` LIST ` line [E3R1, E3A-08]
examples: (R-A2L-LIST.022/1) G2L → `#a2l_list_missing` plain = R-A2L-LIST.022/1's line

A2lViewMixin.update_a2l_tags_view
req: R-A2L-LIST.009, R-A2L-LIST.014, R-A2L-LIST.016, R-A2L-LIST.031, R-TUI-042a.4
in: list tags; str? empty_message = None
out: None
module: s19_app/tui/app/a2l_view.py
func: changed; E3R1 (E3A-02). List mode (a resolution is kept): set the table's columns to `LIST_COLUMNS` when they differ (clear with columns, add, `fixed_columns` stays 2); paint the page of entries with `list_row_cells(entry, text cells of _build_a2l_table_cells(tag) by label, mode)`; map `a2l:<i>` → `resolution.rows[i]` (the entry is `resolution.entries[i]`, the same index); summary `LIST  rows <a>-<b> / <n> in pasted order`; no fit is scheduled. Text mode: set the shipped 16 columns back when they differ; then today's body unchanged.
examples: (R-A2L-LIST.009/1) G2L at 118×54 → column labels `#`, `Tag`, `Status`, `Kind`, `Address`, `Len`, `Physical`, `Unit`, `Limits`
examples: (R-A2L-LIST.016/1) G2L → summary `LIST  rows 1-12 / 12 in pasted order`; (R-A2L-LIST.016/2) 250 names, page 2 → `LIST  rows 201-250 / 250 in pasted order`
examples: (R-A2L-LIST.014/1) row 1 cells 5–9 = the text-mode `Address`, `Length`, `Physical`, `Unit`, `Limits` of `VALUE_0002` (P2 §1: `0x00000014`, `2`, `347190.0`, …, `0..655350`)
examples: (R-A2L-LIST.031/1) row key `a2l:2` → the `MAP_0003` tag; enter → status `Tag at 0x00804FD0` (G2 scene av-list; P2 §1 address)
examples: (R-A2L-LIST.031/4) row key `a2l:6` → `{"name": "MAP_0024", "_list_pos": 7}`; enter → `_jump_to_tag_by_data` returns at its missing address (`a2l_view.py:468-470`): the status line and the hex pane unchanged [E3R1, E3A-13]
examples: (R-TUI-042a.4/1) back to text mode → the 16 shipped columns, `Address`, `Length` first and fixed (Inc 12's cases)

A2lViewMixin._fit_a2l_tag_cells
req: R-A2L-LIST.036
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: changed. List mode → return (the list page has no width-dependent cell). Text mode unchanged.
examples: (R-A2L-LIST.036/1) G2L shown, resize 118 → 80 → 118 → column labels still `LIST_COLUMNS`; row 1 cell 1 `1`

A2lViewMixin._repaint_a2l_tag_cells
req: R-A2L-LIST.036
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: changed; E3R1 (E3A-07). List mode → first re-resolve the list over the current `_a2l_enriched_tags` (the write route has just replaced the written tags with new dicts; same names, so the same statuses and positions), keep that resolution and set `_a2l_filtered_tags = list(resolution.rows)` and the shown row keys' map; then write the shown page in place, as text mode does: for each shown row key `a2l:<i>` (the pasted position − 1, the stable key), rebuild `list_row_cells(resolution.entries[i], …)` and `update_cell` each changed cell; no `clear()`, so the cursor row, the first shown row and the scroll stay. Text mode unchanged. Both write-route paths end here: a list of found rows only passes the route's `id()` map and calls this directly (`patch.py:1851`); a list with a missing row falls back to V4 with `preserve_anchor=True`, which calls this.
examples: (R-A2L-LIST.036/3) G2L shown (a missing and a duplicate row), Inc 10b's Save project commit route (R-A2L-048/2) → columns `LIST_COLUMNS`, 12 rows, the written tag's Physical cell updated in rows 1 and 10 (the same tag)
examples: (R-A2L-LIST.036/4) 250 names with a missing row, scrolled so row 30 is the first shown row, the same commit → row 30 still first shown (R-A2L-049/1's measure, `scroll_y` kept) [E3R1]
examples: (R-A2L-LIST.036/5) the same with the cursor on row 40 → cursor row 40; the detail card names the same entry (R-A2L-105/1's measure) [E3R1]
examples: (R-A2L-LIST.036/2) 250 names, page change → `LIST  rows 201-250 / 250 in pasted order`

A2lViewMixin.update_a2l_view
req: R-A2L-LIST.072, R-A2L-LIST.008, R-A2L-LIST.023
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
modify: [Data: A2lViewMixin._a2l_label_ranker] (replace)
func: changed; E3R1 (E3A-08). Create `self._a2l_label_ranker = LabelRanker(self)` once; after the enrichment (A2L present) or the clear (absent), `prepare` it with the distinct tag names in table order and `_a2l_view_generation` [D-13]. The absent branch also sets `self._a2l_list_resolution = None` before its `update_a2l_tags_view([])` (`a2l_view.py:983`), so the outgoing A2L's rows are never painted and the summary is `No A2L tags.` (R-TUI-068.3). The rest unchanged.
examples: (R-A2L-LIST.072/1) attach C08 (generation `1`, P2 §1) → `prepare(462 names, 1)`
examples: (R-A2L-LIST.072/2) unload → `prepare([], <new generation>)`
examples: (R-A2L-LIST.008/3) G2L shown in list mode over C08, then unload → `_a2l_list_resolution` `None`; 0 rows; summary `No A2L tags.`; mode tag `FILTER` [E3R1, E3A-08]

A2lViewMixin._schedule_a2l_filter_refresh
req: R-A2L-LIST.060, R-A2L-LIST.062, R-A2L-LIST.074, R-A2L-LIST.085
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: changed; E3R1 (E3A-04, E3A-05). Inside the debounced callback, after the refresh (the callback is guarded by R-COPY.26's `if not self.is_running: return`, landed from Inc 1b before E4 — D-1 ruling): the stripped text empty or a list text → close `#a2l_filter_suggest`; else, with `box` and `suggest` the widgets it already holds (looked up once, before the debounce, never inside `current`), `ranker.request("filter", text, 20, functools.partial(suggest.show_ranked, text), current = lambda: box.is_attached and box.value.strip() == text)`.
examples: (R-A2L-LIST.060/1) `0017` → after 0.15 s and the worker, `#a2l_filter_suggest` open with 5 rows, `MAP_0017` first
examples: (R-A2L-LIST.060/3) `map_002` → row 1 `MAP_0020 … prefix` (P1 §2)
examples: (R-A2L-LIST.062/1) `0017` then `''` → dropdown closed
examples: (R-A2L-LIST.074/1) build held; `0017` typed and debounced (request held); build released → dropdown with 5 rows, no new keystroke
examples: (R-A2L-LIST.085/1) `cuvre_00` debounced, its ranking held; `run_test` closes the app; released → `_deliver` returns at `is_running`; `current` would return `False` (box detached) without a `query_one`; 0 exceptions [E3R1, E3A-05]

A2lViewMixin.a2l_open_label_list
req: R-A2L-LIST.040, R-A2L-LIST.041, R-A2L-LIST.053, R-A2L-LIST.054
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: new (I-7, called by L24). Push `LabelListPasteModal(tags=self._a2l_enriched_tags, ranker=…, names=<_a2l_list_names() or []>, wide=<#a2l_panes width ≥ 180>)` with a callback: a non-empty name list → the filter box value = the names joined by `, ` (cursor 0; the box's Changed event runs the debounced refresh) and the dropdown closed; `None` → nothing.
examples: (R-A2L-LIST.041/1) viewer in list mode with G2L → the window opens with 12 lines
examples: (R-A2L-LIST.053/1) callback with G2L's 12 names → filter value `VALUE_0002, CURVE_0001, …, VALUE_0118`; after the debounce 12 list rows
examples: (R-A2L-LIST.053/2) callback [`MAP_0003`] → filter `MAP_0003`, text mode, 1 row
examples: (R-A2L-LIST.054/1) filter `VALUE`, callback `None` → filter `VALUE`

A2lViewMixin._refresh_a2l_dependent_views
req: R-A2L-LIST.056
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: changed. After `update_a2l_view`: when the screen on top is a `LabelListPasteModal`, call its `refresh_tags(self._a2l_enriched_tags)`. The rest of Inc 5's fan-out unchanged (it keeps the filter text, R-A2L-REFRESH.007, so list mode survives).
examples: (R-A2L-LIST.056/1) window open with G2L; attach an A2L that also holds `MAP_0024` → `refresh_tags` called once; counts `10 found`, `1 missing`

ListAwareDetailCard.show_tag
req: R-A2L-LIST.027, R-A2L-LIST.028, R-A2L-LIST.029, R-A2L-LIST.030, R-A2L-LIST.085, R-A2L-LIST.077
in: dict? tag
out: None
module: s19_app/tui/app/a2l_view.py
func: new (subclass of `A2LDetailCard`, `shared.py:540`, so the type queries `a2l_view.py:919` and `navigation.py:1418` still match; defined in G-V because `a2l_label_list.py` may not import the app package); E3R1 (E3A-02, E3A-05). The caller (`navigation.py:1421`, unchanged) passes the row's dict, which no longer carries an entry, so the card finds it: no resolution kept (text mode) or `tag` `None` → `super().show_tag(tag)`. A MISSING row dict (`"_list_pos" in tag`) → `entry = resolution.entries[tag["_list_pos"] - 1]`. Else the entry of the tag table's cursor row (`a2l:<i>` → `resolution.entries[i]`), used only when `entry.tag is tag` (a DUPLICATE row is the same tag object as its FOUND first occurrence, so only the row position tells them apart); otherwise `super().show_tag(tag)`. FOUND → `super().show_tag(tag)`. MISSING → `list_card_text(entry, None)`, then `ranker.request("card", name, 3, deliver, current)` with `deliver` and `current` holding this card: `current` = "`self.is_attached` and this entry is still the shown one", `deliver` repaints with `list_card_text(entry, matches)` [D-12]. DUPLICATE, HIDDEN → the shipped card text of the tag + a new line + `list_card_text(entry, None)`.
examples: (R-A2L-LIST.027/1) highlight row 7 → `✗ MAP_0024  not in this A2L` / `pasted #7`; after the worker `closest —` (R-A2L-LIST.028/2)
examples: (R-A2L-LIST.028/1) a list with `VALUE_002` → after the worker `closest VALUE_0020 · VALUE_0021 · VALUE_0022`
examples: (R-A2L-LIST.029/1) row 10 → the card of `VALUE_0002` + `duplicate of pasted #1`
examples: (R-A2L-LIST.030/1) mode `invalid`, row 1 → card + `hidden by the active filter mode`
examples: (derived) a text-mode row → the shipped card, unchanged
examples: (R-A2L-LIST.029/1, E3A-02) rows 1 and 10 pass the same tag object; with the cursor on row 1 → the plain shipped card; on row 10 → card + `duplicate of pasted #1` [E3R1]
examples: (R-A2L-LIST.085/2) highlight row 7 (`MAP_0024`), its "card" ranking held; `run_test` closes the app; released → 0 exceptions, nothing painted; positive arm: released while the card is shown → `closest —` painted [E3R1, E3A-05]
examples: (R-A2L-LIST.036/5) after the in-place write the cursor row 40 is kept, so the card still names the same entry [E3R1]

## Entities

[Data: LabelListEntry]
desc: new (I-7). Frozen slots dataclass: `pos`, `name`, `status`, `tag`, `first_pos` (§1 code block). E3R1 (E3A-02): no `row` field, no back-reference. Built only by `resolve_label_list`.

[Data: LabelListResolution]
desc: new (I-7). `entries: tuple[LabelListEntry, ...]`, `rows: tuple[dict, ...]` (E3R1, E3A-02/E3A-07: same order; the tag object itself, or `{"name", "_list_pos"}` for MISSING), `count(status)`. The viewer keeps the last one in `[Data: A2lViewMixin._a2l_list_resolution]` (`None` in text mode); the paste window keeps its own.

[Data: LabelRanker]
desc: new (I-7). `_app`, `_generation: int | None`, `_index: LabelIndex | None`, and per request key (E3R1, E3A-04/E3A-06): `_tokens: dict[str, int]`, `_held: dict[str, tuple]` (one request held until ready), `_running: set[str]`, `_waiting: dict[str, tuple]` (one request waiting for the running one). Written only on the UI thread (`prepare`, `_install`, `request`, `_deliver`); a worker (`_work`) reads only the `LabelIndex` it was handed (read-only after its build, I-3) and the query.

[Data: LabelSuggestBox.rows]
desc: new. The shown matches (≤ 8), the choice index, `is_open`.

[Data: A2lViewMixin._a2l_list_resolution]
desc: new. The viewer's resolution in list mode, else `None`; written by `_filter_a2l_tags` and `_repaint_a2l_tag_cells` (re-resolve), cleared by `update_a2l_view`'s absent branch (E3R1, E3A-08); read by `update_a2l_tags_view`, `_paint_a2l_filter_chips` and `ListAwareDetailCard.show_tag`. Session census (E3R1, E3A-09): `tests/test_b100_session_reset.py` `SNAPSHOT_EXCLUSIONS["_a2l_list_resolution"] = "derived from the filter text and the enriched tags at every refresh (Inc 7)"` — sound because every reset route reaches `update_a2l_view`, whose absent branch clears it (a G-T-V test edit, `../E1-slice.md` §5).

[Data: A2lViewMixin._a2l_label_ranker]
desc: new. One `LabelRanker` per app, created in `update_a2l_view`. Session census (E3R1, E3A-09): `SNAPSHOT_EXCLUSIONS["_a2l_label_ranker"] = "one worker host per app; not session state (Inc 7)"`.

[Config: styles.tcss A2L panes]
desc: changed [D-2]. Replaces `styles.tcss:440-456` (`#a2l_panes` horizontal; tags `4fr`, hex `3fr`): `#a2l_panes { layout: vertical; height: 1fr; }`; `#a2l_tags_pane { width: 100%; height: 1fr; }`; `#a2l_hex_pane { width: 100%; height: 14; layout: horizontal; }`; `#a2l_detail_card { width: 1fr; height: 100%; max-height: 100%; }`; `#a2l_hexbox { width: 86; }`; and under `#a2l_panes.-wide`: `layout: horizontal`; tags `width: 1fr; height: 100%`; hex `width: 90; height: 100%; layout: vertical`; card `width: 100%; height: auto; max-height: 8`; hexbox `width: 100%; height: 1fr`. E3R1 (E3A-10), under `#a2l_panes.-short` (the short body): the pre-Inc-7 rules restored — `layout: horizontal`; tags `width: 4fr; height: 100%`; hex `width: 3fr; height: 100%; layout: vertical`; card `width: 100%; height: auto; max-height: 5`; hexbox `width: 100%; height: 1fr` (R-TUI-037.1/.2 as changed, R-A2L-LIST.082). The dropdown: `LabelSuggestBox { overlay: screen; constrain: none inside; display: none; width: 64; max-height: 14; }`, `.-open { display: block; }` (the scene's CSS, `av_mix.py` `AV_CSS`). R-TUI-037.1/.2 hold in the short body only (E3R1: no longer retired); R-TUI-069.6 as changed; R-TUI-069.7: the card scrolls whenever its content is longer than its height (`overflow-y: auto` in all three bodies).
examples: (R-A2L-LIST.080/1) 118×54 → `#a2l_hex_pane` region height `14`, below `#a2l_tags_pane`; `#alt_hex_view` content width ≥ 81, every painted hex row on one line (P2 §3 measures 81)
examples: (R-A2L-LIST.081/1) 220×60 → `#a2l_hex_pane` width `90`, right of `#a2l_tags_pane`
examples: (R-TUI-069.6/1) 220×60 → `#a2l_detail_card` height ≤ 8, its bottom ≤ the top of `#alt_hex_scroll`
examples: (R-TUI-037.1/2) 120×30 → `#a2l_tags_pane` width 54 of a 96-column body, `#a2l_hex_pane` 42, right of it (P3: base widths, kept) [E3R1, E3A-10]
examples: (R-TUI-037.2/1) 80×24 → `#a2l_hex_pane` 32 of 74 (P3) [E3R1]
examples: (R-A2L-LIST.082/1) 120×30 → `#a2l_detail_card` height ≤ 5, above `#alt_hex_scroll` [E3R1]
examples: (R-A2L-LIST.083/2) 160×40 (short: 136×25), the G2 list → the tags pane 25 rows; 9 base lines + 4 list-mode lines leave the table 12 rows: ≥ 11 body rows (derived from P3; E4 measures) [E3R1]
examples: (R-TUI-069.7/2) 118×54 (stacked), a card whose content is 4 lines longer than its 14-row region → `max_scroll_y` ≥ 1, one scroll step changes its first shown line [E3R1, E3A-11]

[Interface: A2L Explorer filter]
desc: the filter row, the dropdown and the list table of the A2L Explorer.
offers: (AT-B103-I7-1/1) "terminal paste in #a2l_tags_filter_input" → OsClipboardInput._on_paste
offers: (AT-B103-I7-3/1) "typing in #a2l_tags_filter_input" → A2lViewMixin._schedule_a2l_filter_refresh
offers: (AT-B103-I7-3/2) "↓ / ↑ in #a2l_tags_filter_input" → ListAwareFilterInput.action_move_choice
offers: (AT-B103-I7-3/2) "tab in #a2l_tags_filter_input" → ListAwareFilterInput.action_complete
offers: (AT-B103-I7-1/3) "esc in #a2l_tags_filter_input" → ListAwareFilterInput.action_esc
offers: (AT-B103-I7-2/1) "alt+p on the A2L Explorer / #a2l_paste_list_button" → A2LExplorerBody.action_paste_list
offers: (R-A2L-LIST.026/1) "alt+a on the A2L Explorer" → A2LExplorerBody.action_mode_all

[Interface: paste window]
desc: `LabelListPasteModal`.
offers: (AT-B103-I7-2/2) "enter in #a2l_list_add" → LabelListPasteModal.on_input_submitted
offers: (AT-B103-I7-2/2) "↓ / ↑ in #a2l_list_add" → LabelSuggestBox.move
offers: (AT-B103-I7-2/3) "alt+f / #a2l_list_apply" → LabelListPasteModal.action_apply
offers: (R-A2L-LIST.055/1) "esc / #a2l_list_cancel" → LabelListPasteModal.action_cancel

[Outside: keys on Windows Terminal]
desc: alt+p, alt+f, alt+a reach Textual as those names only in their kitty form; a legacy `ESC f` is `ctrl+right` (P1 §6). P-1 (`../E1-rulings.md` D-11) checks the real terminal.

## Edges

[Outside: keys on Windows Terminal] ──▶ A2LExplorerBody.action_paste_list
when: alt+p, any focus inside the A2L Explorer, no modal open
[Outside: keys on Windows Terminal] ──▶ LabelListPasteModal.action_apply
when: alt+f while the paste window is open
A2lViewMixin.update_a2l_view ──▶ [Data: A2lViewMixin._a2l_label_ranker]
A2lViewMixin.update_a2l_view ──▶ LabelRanker.prepare
LabelRanker.prepare ──▶ [Data: LabelRanker]
LabelRanker._install ──▶ [Data: LabelRanker]
[Data: LabelRanker] ──▶ LabelRanker.request
LabelRanker.prepare ──▶ LabelRanker._work
when: a thread worker, exit_on_error=False (E3R1, E3A-05)
LabelRanker.request ──▶ LabelRanker._work
when: a thread worker, only when no ranking for the key runs (E3R1, E3A-06)
LabelRanker._work ──▶ LabelRanker._install
when: through app.call_from_thread inside `except RuntimeError: return`; index None when the build raised
LabelRanker._work ──▶ LabelRanker._deliver
when: through app.call_from_thread inside `except RuntimeError: return`; matches None when rank raised
LabelRanker._deliver ──▶ LabelRanker.request
when: the key has a waiting request (E3R1, E3A-06)
LabelRanker._deliver ──▶ LabelSuggestBox.show_ranked
when: key "filter" or "add", the app running, token, generation and text current, widget attached
LabelRanker._deliver ──▶ LabelListPasteModal._on_similar
when: key "similar:<s>", the app running, token, generation and text current, widget attached
LabelRanker._deliver ──▶ ListAwareDetailCard.show_tag
when: key "card", the app running, the entry still highlighted, card attached
ListAwareFilterInput.action_move_choice ──▶ LabelSuggestBox.move
when: the dropdown is open (else SkipAction)
A2lViewMixin._filter_a2l_tags ──▶ [Data: A2lViewMixin._a2l_list_resolution]
[Data: A2lViewMixin._a2l_list_resolution] ──▶ A2lViewMixin.update_a2l_tags_view
[Data: A2lViewMixin._a2l_list_resolution] ──▶ A2lViewMixin._paint_a2l_filter_chips
ListAwareFilterInput._take_paste ──▶ A2lViewMixin._schedule_a2l_filter_refresh
when: through the box's Input.Changed → NavigationMixin.on_input_changed (unchanged, navigation.py:1494-1497)
A2lViewMixin.a2l_open_label_list ──▶ A2lViewMixin._schedule_a2l_filter_refresh
when: the dismiss callback sets the box value (Input.Changed)
A2lViewMixin._refresh_a2l_dependent_views ──▶ LabelListPasteModal.refresh_tags
when: the paste window is the top screen
A2lViewMixin._refresh_a2l_filtered_tags ──▶ A2lViewMixin._repaint_a2l_tag_cells
when: list mode and preserve_anchor=True (the write route's fallback, patch.py:1847) (E3R1, E3A-07)

## Findings

> E2-1 (deviations from `../E1-slice.md`, for the orchestrator). The slice named 40 functions; the graph has **42 nodes (31 new, 11 changed; §Size)**. Two nodes were added and one moved: (a) `LabelRanker._install` — the index hand-over from the build worker is its own UI-thread step (the held requests of R-A2L-LIST.074 run there); (b) `list_card_text` — the missing/duplicate/hidden card lines as a pure function in G-L; (c) the card subclass moved from G-L (`E1-slice.md` L22) to G-V as `ListAwareDetailCard.show_tag` in `a2l_view.py`, because `a2l_label_list.py` cannot import `s19_app.tui.app` (the package imports it: a cycle). `E1-slice.md` §2 is corrected in the E2 commit; `../E1-rulings.md` D-1 likewise.
> E2-2 (for the orchestrator, I-7). I-7 is PROPOSED here (§1). Its consumers are G-V and the three testers; nothing outside Inc 7 consumes it. I-1's hook (L26) is the only change to an interface another increment produced: additive, a default that keeps every other box unchanged.
> E2-3 (for E3, if the orchestrator runs it: the increment reads outside input — the OS clipboard and pasted text — and changes I-1). The threads: `rank` and `build_label_index` run on workers; every widget write is on the UI thread (`_install`, `_deliver`), as Inc 5's R-A2L-REFRESH.026 requires. The hostile-input rows are .024, .034, .035, .051, .076, .077; the paste cap is I-1's (65,536 characters).

> E3R1-1 (the E3 corrections, `../E3-rulings.md` §E3R1 corrections). Two nodes added: `ListAwareFilterInput.action_move_choice` (E3A-03 (a): the ↑/↓ bindings had no node) and `LabelRanker._work` (E3A-05: the one worker body that catches every error and survives teardown). Contracts changed (each line tagged `E3R1`): I-1's placement (E3S-03), the whole I-7 block (E3A-03), `resolve_label_list`'s rows (E3A-02), the keyed and coalesced ranker (E3A-04, E3A-06), the teardown guards (E3A-05), the preview cap (E3S-01), the short texts (E3S-02, E3S-09), the bidi controls (E3S-06), list mode written in place (E3A-07, without `patch.py`), the unload reset (E3A-08), the short body (E3A-10), the field scope of a list paste (E3A-12), the paste window's fixed columns (E3A-14). The real callers of every changed existing function are in `extractor-e3r1/callers.txt` (code-wire `v3.1.0-8-gb6cd30d`) and `../E1-slice.md` §3.

### Size

**After E3R1: 44 nodes: 33 new, 11 changed** — G-L: 31 (E2's 29 + `ListAwareFilterInput.action_move_choice`, `LabelRanker._work`), G-V: 13 (unchanged count). Under the E3 rulings' ceiling of about 48.

At E2: **42 nodes: 31 new, 11 changed** — G-L: 29 (`a2l_label_list.py` 26 new: L1–L5, `list_card_text`, `LabelRanker.prepare`, `._install`, `.request`, `._deliver`, `LabelSuggestBox.show_ranked`, `.move`, `ListAwareFilterInput._take_paste`, `.action_esc`, `.action_complete`, `LabelListPasteModal.compose`, `.on_mount`, `._preview`, `._on_similar`, `.on_input_submitted`, `.action_apply`, `.action_cancel`, `.refresh_tags`, `A2LExplorerBody.on_resize`, `.action_paste_list`, `.action_mode_all`; `os_clipboard_input.py` 1 new, 2 changed); G-V: 13 (`a2l_view.py` 4 new — `_a2l_list_names`, `_paint_a2l_filter_chips`, `a2l_open_label_list`, `ListAwareDetailCard.show_tag` — and 8 changed — `_filter_a2l_tags`, `_refresh_a2l_filtered_tags`, `update_a2l_tags_view`, `_fit_a2l_tag_cells`, `_repaint_a2l_tag_cells`, `update_a2l_view`, `_schedule_a2l_filter_refresh`, `_refresh_a2l_dependent_views`; `compose_screens.py` 1 changed) plus the stylesheet entity. Above the cap of about 40 by 2 (`../E1-rulings.md` D-0).

### Coverage — every active requirement → nodes and examples (none uncovered)

An example `.nnn/k` is `R-A2L-LIST.nnn/k` in the nodes above.

| Requirement | Node(s) | Example(s) |
|---|---|---|
| R-A2L-LIST.001 | is_list_text, resolve_label_list | .001/1 |
| R-A2L-LIST.002 | resolve_label_list | .002/1, .002/2 |
| R-A2L-LIST.003 | resolve_label_list | .003/2 |
| R-A2L-LIST.004 | resolve_label_list | .004/3 |
| R-A2L-LIST.005 | resolve_label_list, _filter_a2l_tags | .005/1, .005/2 |
| R-A2L-LIST.006 | _a2l_list_names, _filter_a2l_tags, is_list_text | .006/1, .006/3 |
| R-A2L-LIST.007 | _paint_a2l_filter_chips, _compose_screen_a2l | .007/1 |
| R-A2L-LIST.008 | _compose_screen_a2l, _paint_a2l_filter_chips, _a2l_list_names, update_a2l_view | .008/1, .008/3 (E3R1) |
| R-A2L-LIST.009 | update_a2l_tags_view | .009/1 |
| R-A2L-LIST.010 | _compose_screen_a2l | .010/1 |
| R-A2L-LIST.011 | list_row_cells | .011/1, .011/2 |
| R-A2L-LIST.012 | list_row_cells | .012/3, .012/4 |
| R-A2L-LIST.013 | list_row_cells | .013/1, .013/3 |
| R-A2L-LIST.014 | list_row_cells, update_a2l_tags_view | .014/1 |
| R-A2L-LIST.015 | list_row_cells | .015/1 |
| R-A2L-LIST.016 | update_a2l_tags_view | .016/1, .016/2 |
| R-A2L-LIST.017 | list_summary_texts, _paint_a2l_filter_chips | .017/1, .017/2 |
| R-A2L-LIST.018 | list_summary_texts, _paint_a2l_filter_chips | .018/1, .018/2 |
| R-A2L-LIST.019 | _paint_a2l_filter_chips, display_text | .019/1, .019/2, .019/3 (E3R1) |
| R-A2L-LIST.020 | _paint_a2l_filter_chips | .020/1 |
| R-A2L-LIST.021 | _paint_a2l_filter_chips | .021/1–/3 |
| R-A2L-LIST.022 | list_summary_texts, _paint_a2l_filter_chips | .022/1, .022/2 |
| R-A2L-LIST.023 | _paint_a2l_filter_chips, update_a2l_view | .023/1, .023/2 (E3R1) |
| R-A2L-LIST.024 | list_summary_texts | .024/1, .024/2 |
| R-A2L-LIST.025 | _refresh_a2l_filtered_tags, display_text | .025/1, .025/2, .025/3 (E3R1) |
| R-A2L-LIST.026 | A2LExplorerBody.action_mode_all | .026/1 |
| R-A2L-LIST.027 | list_card_text, ListAwareDetailCard.show_tag | .027/1 |
| R-A2L-LIST.028 | list_card_text, ListAwareDetailCard.show_tag | .028/1, .028/2 |
| R-A2L-LIST.029 | list_card_text, ListAwareDetailCard.show_tag | .029/1 |
| R-A2L-LIST.030 | list_card_text, ListAwareDetailCard.show_tag | .030/1 |
| R-A2L-LIST.031 | update_a2l_tags_view, resolve_label_list (rows) | .031/1, .031/4 (E3R1) |
| R-A2L-LIST.032 | ListAwareFilterInput.action_esc | .032/1 |
| R-A2L-LIST.033 | ListAwareFilterInput._take_paste, OsClipboardInput._on_paste, .action_paste, _compose_screen_a2l | .033/1–/3, .033/4–/5 (E3R1) |
| R-A2L-LIST.034 | ListAwareFilterInput._take_paste, OsClipboardInput._on_paste | .034/1, .034/2, .034/3 (E3R1) |
| R-A2L-LIST.035 | resolve_label_list (one map), update_a2l_tags_view (one page) | .035/1 |
| R-A2L-LIST.036 | _fit_a2l_tag_cells, _repaint_a2l_tag_cells, _refresh_a2l_filtered_tags, ListAwareDetailCard.show_tag | .036/1–/3, .036/4–/5 (E3R1) |
| R-A2L-LIST.040 | A2LExplorerBody.action_paste_list, a2l_open_label_list, _compose_screen_a2l | .040/1, .040/2 |
| R-A2L-LIST.041 | LabelListPasteModal.on_mount, a2l_open_label_list | .041/1, .041/2 |
| R-A2L-LIST.042 | LabelListPasteModal.on_mount | .042/1 |
| R-A2L-LIST.043 | LabelListPasteModal.compose | .043/1 |
| R-A2L-LIST.044 | LabelListPasteModal.compose | .044/1 |
| R-A2L-LIST.045 | LabelListPasteModal.compose | .045/1 |
| R-A2L-LIST.046 | LabelListPasteModal._preview, list_summary_texts | .046/1, .046/2 |
| R-A2L-LIST.047 | LabelListPasteModal.compose, ._preview, A2LExplorerBody.on_resize | .047/1, .047/2, .047/3 (E3R1) |
| R-A2L-LIST.048 | LabelListPasteModal._preview | .048/1 |
| R-A2L-LIST.049 | LabelListPasteModal._on_similar | .049/1, .049/2 |
| R-A2L-LIST.050 | LabelListPasteModal._on_similar, LabelRanker.request | .050/1 (E3R1: both lines) |
| R-A2L-LIST.051 | LabelListPasteModal._preview | .051/1, .051/2 |
| R-A2L-LIST.052 | LabelRanker._deliver, LabelListPasteModal._on_similar | .052/1 |
| R-A2L-LIST.053 | LabelListPasteModal.action_apply, a2l_open_label_list | .053/1, .053/2 |
| R-A2L-LIST.054 | LabelListPasteModal.action_apply, a2l_open_label_list | .054/1 |
| R-A2L-LIST.055 | LabelListPasteModal.action_cancel | .055/1, .055/2 |
| R-A2L-LIST.056 | LabelListPasteModal.refresh_tags, _refresh_a2l_dependent_views | .056/1 |
| R-A2L-LIST.057 | LabelListPasteModal.on_input_submitted | .057/1, .057/2 |
| R-A2L-LIST.058 | LabelListPasteModal.on_input_submitted | .058/1 |
| R-A2L-LIST.059 | LabelListPasteModal._preview | .059/1 |
| R-A2L-LIST.060 | _schedule_a2l_filter_refresh, LabelSuggestBox.show_ranked | .060/1, .060/3 |
| R-A2L-LIST.061 | LabelSuggestBox.show_ranked | .061/1 |
| R-A2L-LIST.062 | _schedule_a2l_filter_refresh, is_list_text | .062/1, .062/2 |
| R-A2L-LIST.063 | LabelSuggestBox.show_ranked | .063/1, .063/2 |
| R-A2L-LIST.064 | LabelSuggestBox.show_ranked | .064/1, .064/2 |
| R-A2L-LIST.065 | LabelSuggestBox.show_ranked | .065/1, .065/2 (in .063/1, .063/2) |
| R-A2L-LIST.066 | LabelSuggestBox.show_ranked, display_text | .066/1, .066/2–/3 (E3R1) |
| R-A2L-LIST.067 | LabelSuggestBox.show_ranked | .067/1, .067/2 |
| R-A2L-LIST.068 | LabelSuggestBox.move, ListAwareFilterInput.action_move_choice | .068/1–/3 |
| R-A2L-LIST.069 | ListAwareFilterInput.action_complete | .069/1, .069/2 |
| R-A2L-LIST.070 | ListAwareFilterInput.action_esc, LabelListPasteModal.action_cancel | .070/1, .070/2 |
| R-A2L-LIST.071 | LabelRanker.request, ._deliver | .071/1, .071/2 |
| R-A2L-LIST.072 | LabelRanker.prepare, ._install, update_a2l_view | .072/1, .072/2 |
| R-A2L-LIST.073 | LabelRanker.request | .073/1, .073/2 |
| R-A2L-LIST.074 | LabelRanker._install, _schedule_a2l_filter_refresh | .074/1 |
| R-A2L-LIST.075 | LabelRanker.request, ._deliver, LabelListPasteModal._preview | .075/1, .075/2 (E3R1, new) |
| R-A2L-LIST.076 | display_text, list_row_cells, LabelSuggestBox.show_ranked, ._preview | .076/1, .076/4, .076/7 (E3R1) |
| R-A2L-LIST.077 | display_text, list_summary_texts, ._on_similar, LabelSuggestBox.show_ranked, list_card_text | .077/1, .077/2, .077/3–/4 (E3R1) |
| R-A2L-LIST.078 | LabelListPasteModal._preview, .compose | .078/1–/3 (E3R1, new) |
| R-A2L-LIST.080 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | .080/1 |
| R-A2L-LIST.081 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | .081/1 |
| R-A2L-LIST.082 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | .082/1, .082/2 (E3R1, new) |
| R-A2L-LIST.083 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | .083/2 (E3R1, new; /1, /3 measured the same way) |
| R-A2L-LIST.084 | LabelRanker.prepare, ._install, ._work | .084/1–/3 (E3R1, new) |
| R-A2L-LIST.085 | LabelRanker._work, ._deliver, _schedule_a2l_filter_refresh, ListAwareDetailCard.show_tag | .085/1, .085/2, .085/4–/6 (E3R1, new; /3 as /1 for key `similar:1`) |
| R-A2L-LIST.086 | LabelListPasteModal._preview | .086/1–/3 (E3R1, new) |
| R-A2L-007.1 | _filter_a2l_tags | R-A2L-007.1/2 |
| R-A2L-007.2 | _a2l_list_names | R-A2L-007.2/1 |
| R-A2L-007.6 | _filter_a2l_tags (text mode unchanged) | R-A2L-007.6/1 |
| R-A2L-007.7 | _filter_a2l_tags | R-A2L-007.7/1 |
| R-A2L-007.8 | _filter_a2l_tags (text mode unchanged) | R-A2L-007.8/1 |
| R-PASTE.1 | OsClipboardInput._take_paste, ._on_paste, ListAwareFilterInput._take_paste | R-PASTE.1/1, R-PASTE.1/2, R-PASTE.1/3–/4 (E3R1) |
| R-TUI-043.4 | OsClipboardInput.action_paste | R-TUI-043.4/1, R-TUI-043.4/3 (E3R1) |
| R-PASTE.29 | OsClipboardInput.action_paste | R-PASTE.29/1, R-PASTE.29/3 (E3R1), R-A2L-LIST.033/3 (right-click) |
| R-TUI-042a.4 | update_a2l_tags_view | R-TUI-042a.4/1 |
| R-TUI-069.6 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | R-TUI-069.6/1 |
| R-TUI-069.7 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | R-TUI-069.7/2, R-TUI-069.7/3 (E3R1, changed; /1 the same check at 220×60) |
| R-TUI-037.1 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | R-TUI-037.1/1–/3 (E3R1, changed) |
| R-TUI-037.2 | [Config: styles.tcss A2L panes], A2LExplorerBody.on_resize | R-TUI-037.2/1 (E3R1, changed; /2, /3 at 120×30, 160×40) |

Black-box cases: AT-B103-I7-1 … -4 → the `offers:` of `[Interface: A2L Explorer filter]` and `[Interface: paste window]`, and the nodes their rows list (`../02-test-cases-AT.md`).

### E4 notes (for G-L, G-V, the testers and the integrator)

- **Law guards** (CLAUDE.md, `tests/`): the markup AST guard must cover `a2l_label_list.py` (I-3 obligation 5: extend its file list; a test-file edit, not source); every new public function carries the PROJECT_RULES docstring sections; the `deps` seam law (`tests/test_deps_seam_law.py`) — G-V reaches `LabelRanker` and the modal through module imports, not through `deps`, unless a test needs a seam (then add it to `app/deps.py`, a G-V file edit to be ruled); `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` grows by 3 (re-measured at integration).
- **Tests patch, never touch** the OS clipboard (`read_os_clipboard` patched in the module that calls it), `LOCALAPPDATA`, the recent-files store (tester rule 4). Threads: the "held" seams of .052, .071, .074 hold the worker with a `threading.Event` the test owns; no sleep-based waits (`tests/support/timing.py::wait_until`).
- **Inc 12's tests** (`tests/test_b103_inc12_tag_table.py`) read the table at 80–220 columns; under D-2 A the table is wider in the stacked body (118×54) and unchanged in the short body (80 columns, E3R1), and those tests take *w* from the measured width — run them at integration; a failure is a finding against D-2, not a test to weaken.
- **The scene is not code to copy**: `av_mix.py` and `_av_common.py` are design evidence; the graph's contracts and examples are the source (`_av_common.closest` uses `difflib`; I-3 replaces it).
- **Extractor at E2 (record, not a gate):** the baseline copy with `--graph baseline-extract.md --graph graph-inc7.md --layered` → `marks=21 graph_nodes=54 calls=13 findings=37 parse_failures=0` (`extractor-prototype/diff-report.md`): 54 = 21 + 42 − 9 replaced; the 37 are 33 graph nodes with no code yet (the 31 new nodes and the 2 changed nodes the baseline did not mark, `_fit_a2l_tag_cells`, `_repaint_a2l_tag_cells`) and 4 info lines (1 layered-replacement note, 3 loose `list` matches); no signature drift on any of the 9 changed nodes the baseline marked.
- **Extractor at E3R1 (record, not a gate):** `e3r1-extract.md` (the 11 existing functions whose contract E3R1 changes or reuses) marked by `codewire_marks.py` in a throwaway clone on <runner>, then `codewire_extract.py` → `marks=11 graph_nodes=11 calls=5 findings=0 parse_failures=1` (`tools/mutation_harness.py`, an f-string the 3.11 parser rejects; outside the slice); `e3r1-callers.py` names each site's enclosing function (`extractor-e3r1/callers.txt`). The extractor's name-based resolution saw no site in `core.py`, `patch.py` or `navigation.py:1374/1483/1497` (35 ambiguous resolutions); `git grep` on `2dbd7d5a` adds them (`../E1-slice.md` §3, E3R1 column). No drift on any marked signature.
- **Retargets (E3R1):** `../E1-slice.md` §5 lists every existing test E4 must retarget, re-run or leave to the canonical CI, with its row and owner.
- **Extractor at integration:** copy the merged tree outside the worktree, put `# node: <name>` above the 44 nodes, run `codewire_extract.py --repo <copy> --graph baseline-extract.md --graph graph-inc7.md --layered --out <dir>`; expected exit 0, no drift.
