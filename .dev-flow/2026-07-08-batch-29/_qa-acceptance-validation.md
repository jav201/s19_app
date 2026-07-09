# Phase 1 — QA Acceptance & Validation Strategy (batch-29)

Author: qa-reviewer · Scope: TUI-side only (engine-frozen set READ-only) · V-model Phase 1.
Merged by orchestrator into `01-requirements.md`.

LLR ids are **placeholders** (`LLR-044.x`, `LLR-043-retire.x`) pending the architect's HLR/LLR
decomposition — mapping *intent* is stated so the architect can bind real ids.

Two-layer contract reminder: a requirement is complete only when BOTH
`US → AT-NNN → observed outcome (shipped surface)` AND `US → HLR → LLR → TC-NNN` exist. ATs below
drive the **real** mechanism and assert **content** through the shipped surface (Textual Pilot
`App.run_test()`), never a proxy; each carries its pre-fix **counterfactual**.

---

## STORY US-042 — Bound the PowerShell clipboard read against oversized clipboards

### Source facts (read on disk)
- `s19_app/tui/os_clipboard_input.py`:
  - `read_os_clipboard(strategies=...)` (lines 219-274) iterates an **injectable** cascade and
    returns the first non-`None` strategy result. **No length bound today** — a strategy returning a
    multi-MB blob is returned verbatim.
  - `OsClipboardInput.action_paste` (315-348) is async, runs the cascade via
    `loop.run_in_executor(None, read_os_clipboard)`, then inserts `text.splitlines()[0]` only.
  - The PowerShell layer `_read_via_powershell` (159-206) uses `Get-Clipboard -Raw` with a 0.5 s
    subprocess timeout — the timeout bounds *latency*, not *payload size*; a 50 MB clipboard read
    inside the budget still returns 50 MB.
- Reuse harness confirmed on disk: **`tests/test_loadfilescreen_input.py`** — the injectable-strategies
  idiom is `read_os_clipboard(strategies=(("tkinter", fn), ("ctypes-win32", fn), ("powershell", fn)))`
  (lines 308-402), and the Ctrl+V end-to-end idiom is monkeypatch `os_clip_mod.read_os_clipboard` →
  push `LoadFileScreen()` → `pilot.press("ctrl+v")` → read `input_widget.value` (lines 220-283,
  547-581). **No real OS clipboard is touched** by either idiom; US-042's ATs reuse both verbatim.

### Acceptance block
- **Observable outcome:** a pathological clipboard payload (multi-MB, and specifically a
  single-line multi-MB blob with no newline so `splitlines()[0]` alone cannot bound it) cannot flood
  the Input or the paste path; the value read/inserted is bounded to a fixed cap. A normal short path
  is delivered **byte-for-byte unchanged** — the cap never truncates legitimate input.
- **Shipped surface:** (a) `read_os_clipboard(strategies=...)` return value; (b) the `LoadFileScreen`
  `OsClipboardInput` `.value` after a real `ctrl+v`, under Pilot.

Let `CAP = <architect: _MAX_CLIPBOARD_CHARS>` (proposed 64 KiB — comfortably above any real filesystem
path yet a hard bound on work; the architect fixes the exact value).

| AT | Input (representative / boundary / negative) | Real mechanism driven | Observed deliverable (asserted content) |
|---|---|---|---|
| **AT-042a** (oversized, representative) | fake strategy returns a `"A"*(CAP + 5_000_000)` single-line blob (no `\n`) | `read_os_clipboard(strategies=(("fake", huge),))` | return value length `== CAP` and it is the leading `CAP` chars (`result == blob[:CAP]`); **not** the full blob |
| **AT-042b** (oversized reaches Input) | monkeypatch `read_os_clipboard` → the same huge single-line blob; real `ctrl+v` on `#load_path` | Pilot `press("ctrl+v")` → `OsClipboardInput.action_paste` | `input_widget.value` length `<= CAP` and equals `blob[:CAP]` — only the bounded first line reached the Input; the widget did not receive multi-MB |
| **AT-042c** (boundary — at cap) | fake strategy returns `"p"*CAP` (exactly at cap, single line) | `read_os_clipboard(strategies=...)` **and** `ctrl+v` | value `== "p"*CAP` unchanged (length `CAP`) — the cap is inclusive, an exactly-cap payload is **not** truncated |
| **AT-042d** (boundary — one over) | fake strategy returns `"p"*CAP + "X"` | `read_os_clipboard(strategies=...)` | value length `== CAP`, last char is `"p"` not `"X"` — the `CAP+1`-th char is dropped |
| **AT-042e** (negative / normal path — MUST pass through untouched) | fake strategy returns the real colliding path `C:\Users\jjgh8\...\firmware.s19` (~120 chars); real `ctrl+v` | `read_os_clipboard` + `ctrl+v` | `input_widget.value` `==` the exact path, unchanged — the cap is a no-op below `CAP` |
| **AT-042f** (multi-line normal — first-line semantics preserved) | fake strategy returns `"first\nsecond\nthird"` | `ctrl+v` | `input_widget.value == "first"` — capping did not disturb the existing `splitlines()[0]` policy |

- **Counterfactual (non-vacuous, C-10):** on the **pre-cap** tree AT-042a returns a string of length
  `CAP + 5_000_000` (the full blob) → the `len(result) == CAP` assertion FAILS; AT-042b likewise
  inserts the full blob into `.value`. AT-042c/e/f already pass pre-cap (guarding against a cap that
  is too aggressive and eats normal input). This split — some ATs red pre-fix, the pass-through ATs
  green pre-fix — proves the cap is both present and correctly bounded.
- **Performance note (V-5 provisional):** a wall-clock "completes fast" assertion is **flaky** in CI
  and is *not* the primary evidence. "Doesn't scale with input size" is proven **structurally** by the
  length bound (AT-042a/b): once `read_os_clipboard` returns `<= CAP`, no downstream consumer
  (`splitlines`, `replace`) sees more than `CAP` chars regardless of clipboard size. If a timing
  guard is wanted, mark it provisional and give it a generous ceiling (e.g. the huge-blob AT-042a must
  return in `< 1 s`), and confirm the actual ceiling against measured host numbers in Phase 3.

### White-box TC ↔ LLR
| TC | LLR (placeholder) | Mechanism (HOW) |
|---|---|---|
| **TC-042.1** | LLR-044.1 (cap constant) | `_MAX_CLIPBOARD_CHARS` exists, is a positive `int`, and is `>= 4096` (a real path never exceeds it) — a sanity pin so a future edit to `0`/`None` trips |
| **TC-042.2** | LLR-044.2 (bound helper) | the cap helper (e.g. `_bound_clipboard_text(text)`): returns `text` unchanged when `len(text) <= CAP`; returns `text[:CAP]` when longer; handles `""`/`None` without raising (empty/None passthrough) |
| **TC-042.3** | LLR-044.3 (wired into cascade) | `read_os_clipboard` applies the bound to the **selected** strategy result before returning (unit-level, via an injected huge-return strategy) — asserts the bound lives at the read boundary, not only in `action_paste`, so **all** callers are protected |

- **Validation METHOD (US-042):** **Test** (automated — AT + TC). No manual/demo/analysis needed;
  fully drivable headless with injected fakes.
- **LLR mapping intent for architect:** cap constant `LLR-044.1`; pure bound helper `LLR-044.2`;
  bound applied inside `read_os_clipboard` `LLR-044.3`; `action_paste` first-line extraction operates
  on already-bounded text (no second cap needed) `LLR-044.4`. Placing the cap in `read_os_clipboard`
  (not only `action_paste`) is the recommended locus so the guarantee is caller-independent — this is
  a design point for the architect, flagged not decided here.

---

## STORY US-043 — Fully retire the hidden legacy Issues DataTable

### Source facts (read on disk)
- `s19_app/tui/app.py`:
  - `_compose_screen_issues` (1430-1499) mounts the `GroupedIssuesPanel(id="validation_issues_groups")`
    as the **sole visible** surface, with the `DataTable(id="validation_issues_list", ...)` beside it
    (1482-1486) kept mounted but `display: none` — the docstring (1475-1481) explicitly calls the
    DataTable a "Hidden compatibility surface … Full retirement of the table is a backlog item." **This
    batch is that retirement.**
  - `update_validation_issues_view` (5779-5840) queries `#validation_issues_list`, `clear()`s it, and
    `_populate_issues_datatable(...)` (5830) fills it; then `_render_validation_issues_groups()` (5833,
    5842-5904) renders the grouped panel from the **same** filtered list + window.
  - `on_data_table_row_selected` (5243-5290) has a `validation_issues_list` branch (5281-5285) routing
    an `issue:<index>` row-key through `_issue_row_key_to_index` → `_jump_to_validation_issue_by_index`.
  - `on_issue_row_selected` (5905+) already consumes `IssueRow.Selected` → hex pane — the **surviving**
    selection path.
  - Other DataTable touch points to remove/adjust: `app.py:3301` (`query_one("#validation_issues_list")`),
    `_populate_issues_datatable` (5928+), and the `precompute_issue_datatable_payload` /
    `_validation_issue_cell_rows` / `_validation_issue_cell_styles` caches (DataTable-only).
- `s19_app/tui/issues_view.py`: `GroupedIssuesPanel.render_groups` (250-321) caps mounted rows at
  `_GROUP_DISPLAY_MAX = 40` (50) and mounts **only the current paging window** (headers still carry the
  **whole-filtered** count via `IssueGroupHeader.issue_count`). Cells are built through `safe_text`
  (C-17). Read-back handles: `IssueRow.issue` / `IssueRow._sev_class` / `IssueRow.address`,
  `IssueGroupHeader.severity_label` / `.issue_count`, chips via `.issue-code-chip` render text.

### Acceptance block — the retirement itself
- **Observable outcome:** after loading/seeding issues and opening the Issues screen, the legacy
  DataTable is **gone from the widget tree**, the `GroupedIssuesPanel` is the populated Issues surface,
  and issue selection still drives the hex pane.
- **Shipped surface:** `app.query("#validation_issues_list")`, `app.query("#validation_issues_groups")`
  / `IssueRow` / `IssueGroupHeader`, `#issues_hex_pane`, all under Pilot.

| AT | Input | Real mechanism | Observed deliverable |
|---|---|---|---|
| **AT-043a** (retirement, representative) | `action_show_screen("issues")` + seed a small error/warning/info mix (reuse `_seed_issue_objects`) | Pilot render of `#screen_issues` | `len(app.query("#validation_issues_list")) == 0` (DataTable gone tree-wide) **AND** `len(app.query("#validation_issues_groups")) == 1` with `>= 1` `IssueRow` mounted — grouped panel is the populated surface |
| **AT-043b** (selection still works post-retirement) | same seed; focus a NON-default addressed `IssueRow`, press `Enter` | `IssueRow.on_key` → `IssueRow.Selected` → `on_issue_row_selected` → hex pane | `#issues_hex_pane` render contains the issue's `0x…` address row + a known byte, and CHANGES vs the pre-select pane; an `address is None` row → neutral placeholder, no stale bytes (subsumes AT-020a/AT-039c, now asserting the retirement invariant alongside) |
| **AT-043c** (retirement is total — no orphan reference) | boot app, `action_show_screen("issues")` | tree query on every rail screen | `app.query("#validation_issues_list")` is empty on `#screen_issues` **and** `#screen_workspace` (0 everywhere) — proves no second mount survived |

- **Counterfactual (C-10):** on the **pre-retirement** tree `app.query("#validation_issues_list")`
  returns **1** (the `display:none` DataTable is still mounted) → AT-043a/AT-043c FAIL. AT-043b passes
  both before and after (selection already goes through `IssueRow`), so it guards against a retirement
  that also breaks selection.

### Acceptance block — C-17 markup-safety (MUST NOT regress; now the sole guard)
Once the DataTable is gone, `IssueRow` (via `safe_text`) is the **only** render path for file-derived
issue text — the retirement removes the second surface, so the C-17 guard must ride on the grouped panel.

| AT | Input (hostile, **file-derived**) | Real mechanism | Observed deliverable |
|---|---|---|---|
| **AT-043-c17** (C-17 MANDATORY) | load an A2L whose GROUP `REF_*` names a hostile ghost symbol, e.g. `MAP_Model[bold]` (extends the `_BROKEN_REF_A2L` idiom in `test_tui_a2l_issue_recolor.py`) so the shipped chain emits an `A2L_BROKEN_REFERENCE` issue carrying that literal symbol; also cover a raw ANSI byte `\x1b[31m` and an OSC-8 `x[link=file:///etc]` in the symbol/message | full load chain → `update_validation_issues_view` → `GroupedIssuesPanel` mounts `IssueRow`s | run does **not** raise `rich.errors.MarkupError`; the code-chip/detail **plain text** contains the literal `MAP_Model[bold]` (brackets intact) and the literal `[link=file:///etc]` (token NOT consumed → no OSC-8 hyperlink, no style/ANSI leak, no crash) |

- **Note on AT-039e:** the existing `tests/test_tui_directionb.py::test_at_039e_c17_...` (5090-6115) already
  asserts literal rendering over a **seeded** hostile `ValidationIssue`. AT-043-c17 **strengthens** it to a
  **file-derived** symbol through the real load chain (the C-17 discipline the memory encodes: hostile
  input must be file-derived, not constructed). Keep AT-039e; add AT-043-c17 as the file-derived
  variant. Neither may be weakened by the retirement.
- **Counterfactual (C-17):** if `safe_text` were bypassed (e.g. an `IssueRow` cell handed the raw string
  to a markup-parsing widget), the run raises `MarkupError` on `[bold]`/`[link=...]` or the `[link=...]`
  token is consumed (absent from plain text) → AT-043-c17 FAILS.

### White-box TC ↔ LLR (retirement mechanism)
| TC | LLR (placeholder) | Mechanism (HOW) |
|---|---|---|
| **TC-043-retire.1** | LLR-043-retire.1 | `_compose_screen_issues` no longer yields a `DataTable(id="validation_issues_list")` — inspect the composed subtree; `#issues_list_stack` holds only the `GroupedIssuesPanel` |
| **TC-043-retire.2** | LLR-043-retire.2 | `update_validation_issues_view` no longer calls `query_one("#validation_issues_list")` / `_populate_issues_datatable`; the empty and populated paths both route only through `_render_validation_issues_groups` (drive with the fake-`query_one` harness that returns only `#validation_issues_summary`) |
| **TC-043-retire.3** | LLR-043-retire.3 | `on_data_table_row_selected` drops the `validation_issues_list` branch (mac + a2l branches intact); `_issue_row_key_to_index` and the `issue:<index>` row-key emission are removed |
| **TC-043-retire.4** | LLR-043-retire.4 | dead-code census clean: `precompute_issue_datatable_payload` / `_validation_issue_cell_rows` / `_validation_issue_cell_styles` are either removed or, if the architect keeps `precompute_issue_datatable_payload` as a pure formatter, it is no longer referenced by any screen — grep `tests/` + `s19_app/` confirms no live caller |

- **Validation METHOD (US-043):** **Test** (automated AT + migrated TC) for the retirement and C-17.
  **Inspection** for TC-043-retire.1/.4 (compose subtree + dead-code grep). **Analysis / provisional
  Test (V-5)** for snapshot neutrality (below).

---

## C-14 TEST-MIGRATION CENSUS (the central QA task)

`#validation_issues_list` is read by the 5 files below (grep-verified on disk, line numbers cited).
For each, the **faithful re-point** re-observes the same invariant on the grouped panel. The
`#a2l_tags_list` DataTable is a **different** widget and is **NOT** retired — the batch-24 *recolor*
colour assertions live there (`_a2l_row_list`) and are untouched; only the **Issues-list content**
read-backs (`_issue_rows`) migrate.

**Grouped-panel cap nuance:** `GroupedIssuesPanel` mounts `<= _GROUP_DISPLAY_MAX (40)` rows and only the
current page. A suite that iterated **all** DataTable rows must either (i) reseed `<= 40` issues on one
page, or (ii) assert visible colour/content on `query(IssueRow)` **and** whole-list counts via
`IssueGroupHeader.issue_count`. Every batch-24 recolor fixture emits `<= ~4` issues (well under 40 and
under one page) → **no reseed needed there**; the re-point reads `IssueRow.issue` directly.

### Census table

| # | File · test / helper (line) | Current assertion | What it observes **today** | Migrated observation (faithful re-point) | Reseed `<=40`? |
|---|---|---|---|---|---|
| 1 | `test_tui_issues_view.py` · `_select_issue_row` (95-113) + `test_at020a…` (116-155) | hex-pane content on issue select | already `IssueRow` focus+Enter → `#issues_hex_pane` (DataTable only imported, unused) | no change; drop the unused `DataTable` import | No |
| 2 | `test_tui_issues_view.py` · `test_at021_issues_list_shows_related_artifacts` (158-204) | `get_row_at(0)[3]=="a2l, mac"`, `[1][3]=="-"` (Related column) | the **Related-artifacts** cell — a column that exists **only** in the DataTable payload | **DECISION REQUIRED (gap):** the grouped `IssueRow._detail_text` renders `symbol · address · message` and does **not** show related artifacts. Faithful path A (preferred, keeps it black-box): extend `IssueRow` to render related artifacts in a dedicated node, re-point AT-021 to read that node's plain text. Path B (weakens to white-box): downgrade AT-021 to a TC on the formatter — the Related info is then **no longer user-visible**, a real acceptance regression. Flag to architect. | No (2 issues) |
| 3 | `test_tui_issues_view.py` · `test_tc021_precompute_payload_emits_related_cell` (207-238) | 8-tuple rows, Related at index 3 | pure white-box on `precompute_issue_datatable_payload` | survives **iff** the formatter is retained; if the formatter retires with the DataTable (TC-043-retire.4), retire this TC and move Related coverage onto the `IssueRow` node from row #2 | N/A |
| 4 | `test_tui_app.py` · empty-issues test (~830-866) | fake `query_one` for table+summary; empty → summary `"No validation issues."` | `update_validation_issues_view` empty path writing the summary via a fake table | drop the `#validation_issues_list` branch from `_query`; keep `#validation_issues_summary`; assert the summary text as before | No |
| 5 | `test_tui_app.py` · `test_update_validation_issues_view_pages_large_issue_list` (888-928) | `len(row_keys)==150`, keys `issue:*` | the DataTable **windowing math** (page-sized `add_row` calls + `issue:` row-keys) | the windowing invariant re-observed via the **summary** line (`"page 1/…"`, `rows 1-150/…`) + `_get_window_bounds`; the mounted-row / row-key assertion **retires with the DataTable** (grouped caps at 40, so 150 mounted rows is no longer the contract). Re-point to summary/window-bounds, not mounted rows | N/A (window math, not rows) |
| 6 | `test_tui_app.py` · `test_validation_issues_paging_actions_advance_window` (931-…) | wraps `update_…`, asserts `window_start` advances | paging state; does **not** read table cells (fake table is inert) | drop the table branch from `_query`; assertion on `window_start` unchanged | No |
| 7 | `test_tui_app.py` · `test_update_validation_issues_view_uses_worker_precomputed_cells` (1687-1728) | `add_row` receives the precomputed cache rows verbatim (`recorded[0][0]==precomputed_rows[0][0]`) | the DataTable precompute-**cache reuse** optimization | DataTable + cache are retired → **retire this TC** (the reuse path ceases to exist). If the architect keeps `precompute_issue_datatable_payload`, convert to a pure formatter unit test with no table | N/A |
| 8 | `test_tui_app.py` · `test_on_data_table_row_selected_dispatches_by_id` (1600-1634) | dispatch map `{"mac":…, "issue":2, "a2l":…}` | the `on_data_table_row_selected` issue branch via `_issue_row_key_to_index` | drop the `"issue": 2` line + `_issue_row_key_to_index` seed; keep mac + a2l branches. Issue selection is now covered by AT-043b (`on_issue_row_selected`) | No |
| 9 | `test_tui_app.py` · `_query_issues_panel_codes` (1741-1765) + `test_snapshot_harness_renders_issues_panel` (1769-1809) | reads all DataTable Code cells (index 1); asserts `>=1` expected code present | issue **codes** reaching the panel widget tree | re-point to `str(chip.render())` over `app.query(".issue-code-chip")` (the AT-039a idiom); assert `>=1` expected code appears | **Recommended** — `large_project` may exceed 40; grouped shows `<=40` of page 1. Reseed to `<=40` issues (or assert against the first page explicitly) so the intersection can't silently miss |
| 10 | `test_tui_directionb.py` · `test_tc023_issues_table_is_primary_content` (1841-1878) | `#validation_issues_list` is a `DataTable` descendant of `#screen_issues` | asserts the **DataTable EXISTS** | **INVERT** — assert `len(query("#validation_issues_list"))==0` and `#validation_issues_groups` (`GroupedIssuesPanel`) is the primary descendant of `#screen_issues`. This is AT-043a's natural home + counterfactual | No |
| 11 | `test_tui_directionb.py` · `test_tc023_issues_not_nested_in_workspace` (1881-1930) | `#validation_issues_list` in `#screen_workspace` == 0 (+ status/log widgets) | table-absence from workspace | still holds trivially (table gone everywhere); keep. Optionally re-point the "issues surface present" meaning to the grouped panel | No |
| 12 | `test_tui_directionb.py` · `test_tc024_issues_severity_filters_narrow` (1973-2009) | `table.row_count` all/err/warn; `err+warn==all` (30) | whole-list severity **partition** | re-point the partition to `IssueGroupHeader.issue_count` (whole-filtered counts, error+warning summed); visible-window sanity via `len(query(IssueRow))` | No (30<40) |
| 13 | `test_tui_directionb.py` · `test_tc024_issues_filter_buttons_route` (2011-2043) | `table.row_count` before/after Errors button | filter button narrows the surface | `len(query(IssueRow))` before/after (or header counts) | No (30<40) |
| 14 | `test_tui_directionb.py` · `test_tc024_issues_paging_advances` (2046-2087) | reads `#validation_issues_summary` + `window_start` | paging state via the **summary**, not the table | **no migration** — already surface-agnostic | No |
| 15 | `test_tui_directionb.py` · `test_tc024_issues_severity_color_round_trips` (2090-2153) | white-box payload styles + tail `row_count==12` | `precompute_issue_datatable_payload` styles + a rendered row count | tail → `len(query(IssueRow))==12`; colour source-of-truth re-observed via `IssueRow._sev_class` == `css_class_for_severity(sev)` (the grouped panel's colour path). Payload half follows the formatter decision (row #7) | No (12<40) |
| 16 | `test_tui_directionb.py` · `test_tc024_issues_row_select_jumps_to_source` (2156-2194) | builds `issue:` row-key `_Evt` → `on_data_table_row_selected`, asserts no-raise | the retired `issue:` row-key selection path | **retire the row-key path**; replace with `IssueRow` focus+Enter → `on_issue_row_selected` → `#issues_hex_pane` (covered by AT-043b / AT-039c) | No |
| 17 | `test_tui_a2l_issue_recolor.py` · `_issue_rows` (153-159) → AT-037a obs-3 (201-210), AT-037b (239-248) | `_issue_rows(app)[i][_CODE/_SEV/_SYMBOL]` — issue-list **content** (recolor oracle **secondary** observable) | the Issues-list content of the **shipped chain** (the A2L-table colour oracle `_a2l_row_list` on `#a2l_tags_list` is untouched) | re-point `_issue_rows` to iterate `app.query(IssueRow)` and read `row.issue.code / .symbol / .severity / .message` (same objects, stronger typing — `_SEV` compares against `ValidationSeverity.ERROR`, not `"ERROR"`). For "exactly one X" asserts, additionally guard `total issues < page_size` (fixtures ≤4 → safe) so the capped query can't miss rows | No (fixtures ≤4) |
| 18 | `test_validation_service_supplemental.py` · `_issue_rows` (174-181) → AT-036a (193-236), AT-036b (245-276), AT-036c (285-321) | same `_issue_rows` content read-back | Issues-list content of the shipped chain (recolor colour oracle `_a2l_row_list` on `#a2l_tags_list` untouched; zero-tag `a2l_table.row_count==0` at 312 untouched) | same re-point as row #17: read `IssueRow.issue.*`; whole-list "exactly one" via count-guard or `IssueGroupHeader.issue_count` | No (fixtures small) |

### Faithful re-point of the TWO batch-24 recolor oracles (explicit, do NOT weaken)
The batch-24 acceptance oracle is **two-surface**: (1) the **A2L-table row colour** (`_a2l_row_list`
reading `#a2l_tags_list` — **NOT retired**, unchanged), and (2) the **Issues-list content**
(`_issue_rows` reading `#validation_issues_list` — retired). Only surface (2) migrates:

- Replace the `_issue_rows` helper in **both** `test_tui_a2l_issue_recolor.py` and
  `test_validation_service_supplemental.py` with a grouped-panel read: iterate `app.query(IssueRow)`,
  return `[(r.issue.severity, r.issue.code, r.issue.artifact, r.issue.symbol, r.issue.message) for r
  in rows]` (read the `ValidationIssue` object the row carries, not rendered text — robust against the
  detail-string format).
- Adjust the tuple-index constants (`_SEV, _CODE, _SYMBOL, _MESSAGE`) to the new order and change
  `_SEV` comparisons from `ValidationSeverity.ERROR.value.upper()` (DataTable string cell) to the enum
  `ValidationSeverity.ERROR` — this is **stronger**, not weaker.
- **Whole-list count integrity:** the "exactly ONE `A2L_DUPLICATE_SYMBOL`" (AT-037a) and "exactly ONE
  ERROR for DUP_RPM" (AT-036b) asserts are whole-list-count claims. Because these fixtures emit `<=4`
  issues on a single page, `query(IssueRow)` == the whole filtered list, so the count is faithful. Add
  a one-line guard `assert len(app._filtered_validation_issues()) < app.validation_issues_page_size`
  (or assert the corresponding `IssueGroupHeader.issue_count`) so a future larger fixture cannot make
  the capped read pass a count vacuously.
- The A2L red/green/white assertions (`cell.style == _severity_style(...)`) stay **exactly as-is** —
  they read `#a2l_tags_list`, which this batch does not touch.

---

## Snapshot-suite note (V-5 provisional)
`tests/test_tui_snapshot.py:423-435` references the *retained* `#validation_issues_list` DataTable as
part of the Issues-screen SVG. Because that DataTable is `display: none` (zero layout footprint),
**removing it should be SVG-neutral** — the grouped panel already owns all visible space. Treat this as
**Analysis** (expected neutral) + **provisional Test (V-5)**: any baseline delta must be confirmed by a
regen in the **canonical CI** only (`snapshot-regen.yml`, pinned `textual==8.2.8`) — local regen is
FORBIDDEN and drifts unrelated baselines (per `reference_snapshot_regen_env`). Do not hand-edit
baselines. Flagged for Phase 3, not asserted here.

## Out-of-census incidental matches (dev grep-verify)
`test_tui_app.py:306` (`row_count = 0`, a local counter) and `test_tui_app.py:476`
(`_FakeDataTable(row_count=50)`) matched the `row_count`/`DataTable` grep but appear **unrelated** to
`#validation_issues_list` (generic/other-widget). Dev should grep-confirm before touching; excluded
from the migration scope here.

---

## Evidence checklist
- [x] Acceptance criteria drive the shipped surface — ATs use Pilot `query`/`press`/`focus`, not internal proxies. Evidence: AT-042a-f, AT-043a-c, AT-043-c17 above.
- [x] Test cases have explicit Expected, not vague "works" — every AT row states the asserted content (lengths, exact strings, tree counts).
- [x] Edge cases include empty/boundary/invalid/error — US-042 at-cap (AT-042c), over-cap (AT-042d), normal pass-through (AT-042e), multi-line (AT-042f); US-043 zero-issue empty state (AT-039d reused), hostile file-derived (AT-043-c17).
- [x] Regression checklist exists — the C-14 census (18 rows) is the regression map; batch-24 recolor oracles explicitly preserved.
- [x] Exit criteria stated — dual traceability (US→AT + US→LLR→TC) per story; retirement counterfactual (`query("#validation_issues_list")` was 1, now 0).
- [x] No real PII/secrets — all fixtures synthetic (`"A"*N`, public colliding path, synthetic A2L). No real OS clipboard touched (injected fakes / monkeypatch).
- [x] Test results left BLANK — this is strategy only; no runs claimed. `_qa-acceptance-validation.md` carries no results section.
- [x] Layer B (black-box) — every output story observed through the shipped surface: US-042 via `.value` after real `ctrl+v`; US-043 via `query(IssueRow)`/`IssueGroupHeader`/`#issues_hex_pane`. Boundary + negative present (AT-042c/d/e, AT-043-c17).
- [x] Bidirectional surface-reachability — inputs (injected huge/at-cap/short strategy returns; hostile file-derived A2L) AND outputs (Input `.value`; grouped panel rows/headers/chips; hex pane) exercised through the handler, not only the service API.
- [x] No unfilled template — no `<...>`/`TC-NNN`/empty rows remain, except the one deliberate architect-owned value `CAP = <architect: _MAX_CLIPBOARD_CHARS>` (proposed 64 KiB), explicitly flagged as a design decision.

## Open decisions handed to architect (flag, not decided by QA)
1. **AT-021 Related-artifacts gap (census #2/#3):** the grouped `IssueRow` does not render
   related-artifacts. Extend `IssueRow` (keep black-box) or accept the acceptance regression
   (downgrade to white-box). QA recommends extending `IssueRow`.
2. **`precompute_issue_datatable_payload` fate (census #3/#7/#15):** retire with the DataTable, or keep
   as a pure formatter. Drives whether TC-021.1 / TC-024-color / TC-1728 retire or convert.
3. **US-042 cap value + locus:** exact `_MAX_CLIPBOARD_CHARS` and whether the bound lives in
   `read_os_clipboard` (QA-recommended, caller-independent) vs `action_paste`.
