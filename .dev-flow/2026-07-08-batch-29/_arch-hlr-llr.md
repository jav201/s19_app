# Batch-29 — HLR / LLR (Architect, Phase 1)

Scope: TUI-side only. Engine-frozen set (`core.py, hexfile.py, range_index.py,
validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py`) is READ-only here and
untouched by every LLR below. All line cites verified against disk on 2026-07-08
(see the Draft-time verification log at the end).

**Requirement-id map (non-colliding, stated explicitly):**
- US-042 → new requirement **R-TUI-044** (clipboard read bound). HLR **HLR-044.1-clip**;
  LLRs **LLR-044.1 … LLR-044.5**. Chosen as a fresh `R-TUI-044` family so it does not
  collide with batch-28's `HLR-042.*` / `LLR-042.*` (Issues grouped view) or
  `R-TUI-043`.
- US-043 → retirement HLRs on the existing Issues families **R-TUI-042 / R-TUI-043**.
  HLR **HLR-043.R1-retire**; LLRs **LLR-043.R1 … LLR-043.R7** (the `.R` suffix marks
  "retirement" and avoids collision with batch-28's `LLR-042.1…10` / `LLR-043.*`).

`shall` is used only inside HLR/LLR normative statements. No `should` appears as a
modal inside any HLR/LLR (see the "should-misuse avoided" note at the end).

---

## US-042 — Bound the PowerShell/OS clipboard read against oversized clipboards

**Restatement.** When a user presses Ctrl+V in the Load dialog, the paste path reads
the entire OS clipboard into a Python `str` and then uses only the first line
(`text.splitlines()[0]`, `os_clipboard_input.py:341`) to fill a short path field. If
the OS clipboard holds a huge blob, every read layer materializes the whole string in
memory and `splitlines()` allocates a large list — a memory/latency spike for a value
of which only the first line is ever consumed. We want the read to stay
memory-bounded and fast regardless of clipboard size, with the paste still succeeding
on the (bounded) first line and never crashing.

### Q1 resolution (cap approach) — decision + justification

**Decision: adopt option (b) — a single post-read length cap applied centrally in
`read_os_clipboard` (`os_clipboard_input.py:219`), truncating whatever ANY layer
returns before the value is used.** Rejected option (a) (bound PS stdout only).

Rationale, tied to constraints (small team, maintainability, minimal surface, the
operator's named pragmatic scope):
- **Coverage.** All three layers materialize the full clipboard string, not just
  PowerShell: tk `clipboard_get()` (`:87`), ctypes `wstring_at(pointer)` (`:152`),
  and PS `capture_output=True` + `result.stdout` (`:183`,`:205`). Option (a) would
  guard only the third and least-used layer (tk usually wins the cascade,
  `_STRATEGIES` order `:212`). Option (b) guards all three at one site.
- **Simplicity.** One constant + one `len`/slice at the single funnel
  (`read_os_clipboard`) versus a Popen-based bounded-read rewrite of
  `_read_via_powershell` (streaming `stdout.read(n)` + process kill). A boring
  one-line guard the team can read beats a subprocess-streaming refactor.
- **Reversibility.** A pure post-read slice is a fully reversible, low-blast-radius
  change (no process-management, no new failure modes).

**Honest tradeoff (must be recorded).** Option (b) is a *functional* bound, not a
*true source* memory bound. tk/ctypes/PS each still allocate the entire clipboard
string transiently in memory *before* the cap slices it — the cap prevents the large
string from flowing downstream (into `splitlines()`, into the widget, into logs) and
bounds the O(N) `splitlines` cost, but it does not stop the momentary full
materialization inside each reader. A true source bound for the PS layer would require
`subprocess.Popen(...).stdout.read(cap+1)` then terminate — deferred. The backlog item
named the PS layer specifically; the operator's approved scope is the pragmatic
post-read cap. **Residual risk R-044-1 (below) records this**, and a future
`LLR-044.6` (bounded Popen read for PS) is named as the follow-up if a real memory
bound is later required.

### HLR-044.1-clip (traces to US-042; requirement R-TUI-044)

*The system shall bound the length of any OS-clipboard value it reads for the Load
dialog paste to a fixed maximum before the value is used, so that an oversized OS
clipboard cannot cause a memory spike, an unbounded `splitlines` cost, or a hang, and
the paste still inserts the (bounded) first line without crashing.*

Observable deliverable: a Ctrl+V against a multi-megabyte OS clipboard inserts a
bounded first-line path into the Load `Input`, completes within the existing sub-second
budget, and raises no exception; the value handed downstream never exceeds the cap.

#### LLR decomposition

**LLR-044.1 — Define the cap constant.**
Statement: *The system shall define a module-level maximum clipboard-read length
`_CLIPBOARD_READ_CAP_CHARS` in `os_clipboard_input.py`.*
Parent: HLR-044.1-clip.
Touches: `s19_app/tui/os_clipboard_input.py` — new constant beside the existing budget
constants (`:64`–`:68`, `_TK_RETRIES … _POWERSHELL_TIMEOUT_S`).
Value + justification: **65536 (64 Ki characters)**. A Windows path is bounded by
`MAX_PATH` (260) or the extended `\\?\` form (~32 767); 64 Ki is ~2× the largest legal
path, so it never truncates a legitimate pasted path yet caps a hostile blob to at
most 64 KiB of `str` flowing downstream. (Cap is expressed in **characters**, because
every layer returns a Python `str`, not bytes — this keeps the guard a pure `len`/slice
with no encoding step.)
Observable deliverable: the named constant exists with value 65536.

**LLR-044.2 — Apply the cap centrally in `read_os_clipboard`.**
Statement: *When a cascade layer returns a non-`None` string, the system shall
truncate it to at most `_CLIPBOARD_READ_CAP_CHARS` characters before returning it.*
Parent: HLR-044.1-clip.
Touches: `s19_app/tui/os_clipboard_input.py` — inside the loop of `read_os_clipboard`,
at the `text is not None` branch (`:265`–`:269`, before the `len`-logging + `return`).
Applied at this single funnel so it covers all three layers and any test-injected
`strategies` cascade (the `strategies=` param, `:220`, `:258`) uniformly.
Observable deliverable: `len(read_os_clipboard()) <= 65536` for any clipboard/strategy;
a returned value longer than the cap is impossible.

**LLR-044.3 — Truncation preserves a successful, non-`None` paste.**
Statement: *When the OS clipboard value exceeds the cap, the system shall still return
the capped prefix (never `None`) so `action_paste` inserts the bounded first line and
does not fall through to the internal-buffer path or the failure notification.*
Parent: HLR-044.1-clip.
Touches: `s19_app/tui/os_clipboard_input.py` — interaction of LLR-044.2 with
`action_paste` (`:315`–`:343`): the capped string is truthy, so the `text is None`
fallback (`:323`) and the empty-value warning branch (`:326`–`:340`) are NOT taken; the
insert path `first_line = text.splitlines()[0]` → `self.replace(...)` (`:341`–`:343`)
runs on the bounded string.
Observable deliverable: pasting an oversized clipboard inserts a (bounded) first line
and emits no `_PASTE_FAIL_NOTIFICATION`.

**LLR-044.4 — First-line semantics on truncation are well-defined and crash-free.**
Statement: *The system shall derive the inserted value from `splitlines()[0]` of the
capped string; when the first line itself exceeds the cap, the inserted value shall be
the capped first-line prefix, and in no case shall truncation raise.*
Parent: HLR-044.1-clip.
Touches: `s19_app/tui/os_clipboard_input.py:341` (`text.splitlines()[0]`), consuming
the LLR-044.2 output. Because the cap runs first, `splitlines` operates on ≤64 Ki
chars, bounding its allocation. A clipboard whose first line is longer than the cap
(no newline within 64 Ki) yields the 64 Ki prefix — acceptable: such a value is not a
valid path and the field is a path input.
Observable deliverable: for a cap-exceeding single-line clipboard, the inserted text
length equals the cap and no exception is raised.

**LLR-044.5 — Bounded logging.**
Statement: *The system shall log the post-cap length, so the existing success log
(`read_os_clipboard succeeded via %s (len=%d)`) reports the bounded value, not the raw
clipboard size.*
Parent: HLR-044.1-clip.
Touches: `s19_app/tui/os_clipboard_input.py:266`–`:268` (the `len(text)` in the debug
log now reads the capped `text`).
Observable deliverable: the logged `len=` never exceeds the cap.

**Deferred / named-not-built:** `LLR-044.6` (true source memory bound for PS via
`subprocess.Popen(...).stdout.read(cap+1)` + terminate) — NOT in this batch; recorded
so the residual is a decision, not an oversight.

**Risks (R-TUI-044):**
- **R-044-1 (operational, low).** Post-read cap does not prevent transient full-string
  materialization inside tk/ctypes/PS (see Q1 tradeoff). Mitigation: cap bounds all
  downstream cost + a hostile blob is still capped; true source bound deferred to
  LLR-044.6.
- **R-044-2 (UX, negligible).** A legitimate path longer than 64 Ki would be truncated
  — impossible for any real Windows path. No mitigation needed.
- **R-044-3 (correctness, low).** The internal-buffer fallback path
  (`self.app.clipboard`, `:324`) is NOT routed through `read_os_clipboard` and so is
  not capped by LLR-044.2. That buffer is app-populated (Ctrl+C of the input's own
  text) and inherently short, so risk is low; if defense-in-depth is wanted later, the
  same cap can be applied in `action_paste` after the fallback assignment. Flagged, not
  fixed (scope).
- **Cost/latency:** negligible. One `len` + one slice per paste; removes a potential
  O(N) `splitlines` over an unbounded string. No new process, no new dependency, no
  lock-in.
- **What would change the recommendation:** if profiling shows the transient
  full-materialization itself (R-044-1) is the real spike — not the downstream use —
  then option (a)/LLR-044.6 (bounded Popen read) becomes necessary and (b) alone is
  insufficient.

---

## US-043 — Fully retire the hidden legacy Issues DataTable

**Restatement.** `GroupedIssuesPanel` (`s19_app/tui/issues_view.py`) is already the
sole *visible* Issues surface; the old `#validation_issues_list` `DataTable` was kept
mounted but `display:none` in batch-28 purely as a test-compat shim
(`app.py:1475`–`:1481` comment; `styles.tcss:783`–`:791` comment). We want that shim
gone: remove the widget from compose, remove its two CSS rules, and strip its
population + row-key + `on_data_table_row_selected` routing — while preserving the
grouped panel and all live behavior around it.

**Dependency finding (verified): summary + paging do NOT depend on the DataTable.**
- `#validation_issues_summary` (`Label`) is updated from `self._validation_issues`
  counts only (`app.py:5780`, `:5804`–`:5814`); no DataTable read feeds it.
- Paging actions `action_validation_issues_page_next/prev` (`app.py:5974`–`:5994`)
  mutate `_validation_issues_window_start` and call `update_validation_issues_view()`;
  they never touch the DataTable directly. The grouped panel already re-renders from
  the same window via `_render_validation_issues_groups()` (`app.py:5842`–`:5903`).
- Selection→peek is already the grouped path: `IssueRow.Selected` →
  `on_issue_row_selected` (`app.py:5905`–`:5926`) → `_update_issues_hex_pane`,
  independent of the DataTable's `on_data_table_row_selected`.

Therefore after removal, summary + paging route entirely through the grouped panel with
no re-wiring needed beyond deleting the DataTable-specific code.

### HLR-043.R1-retire (traces to US-043; requirements R-TUI-042 / R-TUI-043)

*The system shall make `GroupedIssuesPanel` the sole mounted Issues surface: the
`#validation_issues_list` DataTable, its CSS, its column init, its population, its
row-key map, and its `on_data_table_row_selected` routing shall be removed, while the
grouped view, the `#issues_hex_pane` live peek, the `IssueRow.Selected →
_update_issues_hex_pane` wiring, PgUp/PgDn paging, the `#validation_issues_summary`
label, the `_GROUP_DISPLAY_MAX` bound, and C-17 markup-safety are preserved unchanged.*

Observable deliverable: the Issues screen renders identically to today from a user's
view; `query("#validation_issues_list")` returns empty; the engine-frozen diff stays 0.

#### LLR decomposition

**LLR-043.R1 — Remove the DataTable from compose.**
Statement: *The system shall not mount a `#validation_issues_list` DataTable in the
Issues screen; `GroupedIssuesPanel(#validation_issues_groups)` shall be the sole child
of the issues list column.*
Parent: HLR-043.R1-retire.
Touches: `s19_app/tui/app.py:1482`–`:1486` (the `DataTable(id="validation_issues_list",
…)` inside `#issues_list_stack`, `:1472`–`:1488`, within `_compose_screen_issues`).
Preserve the surrounding `#issues_columns` / `#issues_hex_pane` (`:1489`–`:1490`) and
`#validation_issues_summary` (`:1492`). Decide whether the now-single-child
`#issues_list_stack` wrapper stays or collapses — architect recommendation: keep the
wrapper id to avoid churning `#issues_list_stack` CSS; flagged for software-dev.
Observable deliverable: `app.query("#validation_issues_list")` is empty after mount.

**LLR-043.R2 — Remove the two DataTable CSS rules.**
Statement: *The system shall remove the `#validation_issues_list` style block and the
`#issues_columns #validation_issues_list { display: none }` rule.*
Parent: HLR-043.R1-retire.
Touches: `s19_app/tui/styles.tcss:532`–`:535` (`#validation_issues_list { height:1fr;
border: round $rule }`) and `:783`–`:791` (the `display:none` compat rule + its
comment). Preserve `#validation_issues_summary` (`:537`–`:541`) and the `.issue-*`
grouped rules (`:793`+).
Observable deliverable: neither selector remains in `styles.tcss`.

**LLR-043.R3 — Remove the DataTable column initialization.**
Statement: *The system shall not initialize columns for `#validation_issues_list`.*
Parent: HLR-043.R1-retire.
Touches: `s19_app/tui/app.py:3300`–`:3314` (the `query_one("#validation_issues_list",
DataTable)` + `add_columns(...)` try/except block). Leave the sibling MAC (`:3285`) and
A2L (`:3315`) column-init blocks untouched.
Observable deliverable: no code references `#validation_issues_list` column init.

**LLR-043.R4 — Strip DataTable population + row-key from `update_validation_issues_view`.**
Statement: *`update_validation_issues_view` shall compute the filtered list, update
`#validation_issues_summary`, and render the grouped panel, without querying,
clearing, or populating a DataTable or building any `issue:<index>` row-key map.*
Parent: HLR-043.R1-retire.
Touches: `s19_app/tui/app.py:5779`–`:5840` — remove `issue_table = query_one(…)`
(`:5779`), `issue_table.clear` (`:5782`), the `use_precomputed`/`precompute…`/
`_populate_issues_datatable` block (`:5815`–`:5832`), and the `_issue_row_key_to_index
= {}` reset (`:5781`); KEEP the summary computation + `.update` (`:5780`,`:5793`–
`:5814`) and both `_render_validation_issues_groups()` calls (`:5786`, `:5833`). Also
remove the now-orphaned helper `_populate_issues_datatable` (`:5928`–`:5972`).
Observable deliverable: `update_validation_issues_view` contains no DataTable
reference; summary text + grouped render are byte-for-byte what they were with the
table present.

**LLR-043.R5 — Remove the `validation_issues_list` branch from row-select routing.**
Statement: *`on_data_table_row_selected` shall no longer route
`validation_issues_list`; the `_issue_row_key_to_index` map and the now-unreachable
`_jump_to_validation_issue_by_index` jump shall be removed, with the MAC and A2L
routing branches preserved.*
Parent: HLR-043.R1-retire.
Touches: `s19_app/tui/app.py:5281`–`:5285` (the `if table_id ==
"validation_issues_list":` branch); the map init `_issue_row_key_to_index` (`:939`) and
its only remaining writer/reader after LLR-043.R4; and `_jump_to_validation_issue_by_index`
(`:5596`, whose sole caller is that branch, `:5284`). KEEP the `mac_records_list`
(`:5276`) and `a2l_tags_list` (`:5286`) branches.
Rationale: the DataTable has been `display:none` since batch-28, so this branch was
already unreachable by user interaction — removing it loses no user-facing behavior
(the live selection path is `IssueRow.Selected`, preserved by LLR-043.R6). Note: the
"issues-row jump moves the main hex view" behavior only ever existed via this table and
is being retired with it; the grouped panel's selection drives the `#issues_hex_pane`
peek, not the main hex view — an intentional, documented behavior narrowing, not a
regression.
Observable deliverable: `on_data_table_row_selected` has no `validation_issues_list`
branch; `_jump_to_validation_issue_by_index` and `_issue_row_key_to_index` no longer
exist.

**LLR-043.R6 — Preserve grouped-panel behavior + C-17 markup-safety (regression guard).**
Statement: *The removal shall not alter the `#issues_hex_pane` peek, the
`IssueRow.Selected → on_issue_row_selected → _update_issues_hex_pane` wiring, PgUp/PgDn
paging, the `#validation_issues_summary` label, the `_GROUP_DISPLAY_MAX` mounted-row
bound, or the `safe_text` C-17 literal-render path.*
Parent: HLR-043.R1-retire.
Touches (must remain unchanged): `s19_app/tui/app.py` `on_issue_row_selected`
(`:5905`–`:5926`), `_update_issues_hex_pane` (`:5619`), paging actions (`:5974`–
`:5994`), summary update (`:5814`), `_render_validation_issues_groups` (`:5842`–
`:5903`); `s19_app/tui/issues_view.py` `_GROUP_DISPLAY_MAX = 40` (`:50`) and the
`safe_text(...)` cells in `IssueRow.compose` (`:176`–`:180`).
Observable deliverable: selecting a grouped row still repaints `#issues_hex_pane`;
`address is None` still yields the neutral peek (no crash); paging still re-renders the
grouped window; mounted `IssueRow` count stays `<= 40`; a hostile `sensor[red]` symbol
still renders literal.

**LLR-043.R7 — Engine-frozen diff stays 0.**
Statement: *No change in this story shall modify any engine-frozen module.*
Parent: HLR-043.R1-retire.
Touches (READ-only, must show 0 diff vs `main`): `core.py`, `hexfile.py`,
`range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`.
All US-043 edits are confined to `tui/app.py`, `tui/issues_view.py` (guard only), and
`tui/styles.tcss` — none frozen.
Observable deliverable: `git diff main -- <frozen set>` is empty; the
`test_engine_unchanged.py` / `test_tui_directionb.py::test_tc031_*` guards pass.

### C-14 location/surface-move census — observers to re-point (invariant per file)

The `#validation_issues_list` DataTable is read by 5 test files. The qa-reviewer owns
the test migration; these LLRs name the **invariant each observer must still assert
after re-pointing off the retired widget** onto the grouped surface:

| Test file (sites) | Current oracle | Invariant to preserve after re-point |
|---|---|---|
| `test_tui_issues_view.py` (3) | grouped panel + peek (already) | `IssueRow.Selected → _update_issues_hex_pane`, `address None` → neutral (LLR-043.R6). Likely least-affected. |
| `test_tui_app.py` (8) | `_populate_issues_datatable` / `_issue_row_key_to_index` (`:1594`–`:1615`), `_jump_to_validation_issue_by_index` monkeypatch (`:1609`) | Row-key/jump mechanics are being deleted (LLR-043.R4/R5). Re-point to assert summary counts + grouped window from `update_validation_issues_view`, or delete the row-key-specific cases as testing-removed behavior. |
| `test_tui_directionb.py` (8) | `_issue_row_key_to_index` + `_jump_to_validation_issue_by_index` (`:2161`,`:2181`) | Same as above — the "row-select jumps hex" invariant is retired with the table; migrate to the grouped `IssueRow.Selected → peek` invariant. |
| `test_tui_a2l_issue_recolor.py` (5) | `DataTable.get_row_at` as **severity-COLOUR oracle** | Severity→colour mapping must still hold — re-point the colour assertion to `css_class_for_severity(issue.severity)` / `IssueRow._sev_class` (`issues_view.py:171`), the grouped panel's actual colour source, instead of `get_row_at`. |
| `test_validation_service_supplemental.py` (5) | `DataTable.get_row_at` as **severity-COLOUR oracle** | Same colour invariant; re-point to `css_class_for_severity` / `IssueRow._sev_class`. |

**Orphan flag (architect → software-dev/qa decision).** Once LLR-043.R4 removes
population, `precompute_issue_datatable_payload` (`app.py:752`) and the worker caches
`_validation_issue_cell_rows` / `_validation_issue_cell_styles` (`:934`–`:935`,
populated at `:6649`–`:6651`, `:6955`–`:6956`, `:7161`) become dead for *rendering*
(the grouped view colours via `css_class_for_severity`, not via the precomputed cell
styles). Deleting them is out of this story's named scope but should be tracked: if the
colour-oracle tests re-point to `css_class_for_severity` (as above) rather than to the
precompute payload, the precompute path can be retired in a follow-up batch. Flagged,
not scheduled.

**Risks (US-043):**
- **R-043-1 (test-migration, medium).** 5 test files, 2 of them using the removed
  widget as a colour oracle. If migration is incomplete the suite goes red. Mitigation:
  C-14 census table above; qa-reviewer designs the migration before code lands.
- **R-043-2 (behavior-narrowing, low, intentional).** The "issues row-select shifts the
  main hex view" path (via `_jump_to_validation_issue_by_index`) is retired. This was
  unreachable by users since batch-28 (`display:none`); recorded as an intentional
  narrowing, not a regression (LLR-043.R5 rationale).
- **R-043-3 (dead-code drift, low).** Orphaned `precompute_issue_datatable_payload` +
  caches (see Orphan flag). Mitigation: tracked for a follow-up; not deleted here to
  keep the increment surgical.
- **Cost/latency:** net reduction — one fewer non-virtualized widget mounted +
  populated per Issues refresh, and the O(window) `_populate_issues_datatable` loop
  (`:5962`–`:5972`) is deleted.
- **What would change the recommendation:** if any external (non-test) consumer reads
  `#validation_issues_list` — none found in `s19_app/` — removal would need a compat
  shim instead. Census shows only the 5 test files, so straight removal stands.

---

## Draft-time verification log

All cites read from disk on 2026-07-08 (worktree
`…\.claude\worktrees\heuristic-wu-1c7c49`). PASS = verified; no `assumed` items remain.

**US-042 / `s19_app/tui/os_clipboard_input.py`:**
- `_POWERSHELL_TIMEOUT_S = 0.5` at `:68` — PASS.
- Budget constants `_TK_RETRIES … _POWERSHELL_TIMEOUT_S` at `:64`–`:68` — PASS.
- `_read_via_tk` `root.clipboard_get()` at `:87` — PASS.
- `_read_via_ctypes` `ctypes.wstring_at(pointer)` at `:152` — PASS.
- `_read_via_powershell` `capture_output=True` at `:183`; `result.stdout.rstrip(...)`
  at `:205` — PASS.
- `_STRATEGIES` cascade tk→ctypes→powershell at `:212`–`:216` — PASS.
- `read_os_clipboard(strategies=…)` signature `:219`–`:221`; cascade loop + `text is
  not None` return at `:258`–`:274` (log/return `:265`–`:269`) — PASS.
- `action_paste` async at `:315`; `run_in_executor(None, read_os_clipboard)` at `:321`;
  internal fallback `:323`–`:325`; empty-value warning `:326`–`:340`;
  `text.splitlines()[0]` + `self.replace` at `:341`–`:343` — PASS.
- `_CLIPBOARD_READ_CAP_CHARS` — NEW constant (to be added by LLR-044.1); named as
  new, not cited as existing.

**US-043 / `s19_app/tui/app.py`:**
- DataTable compose `id="validation_issues_list"` at `:1482`–`:1486` (inside
  `#issues_list_stack` `:1472`–`:1488`; compat comment `:1475`–`:1481`) — PASS.
- `#issues_hex_pane` `:1489`; `#validation_issues_summary` `:1492` — PASS.
- Column init block `:3300`–`:3314` — PASS.
- `on_data_table_row_selected` `validation_issues_list` branch `:5281`–`:5285`; MAC
  `:5276`, A2L `:5286` — PASS.
- `update_validation_issues_view` query `:5779`, clear `:5782`, summary `:5780`/`:5804`–
  `:5814`, precompute/populate block `:5815`–`:5832`, grouped calls `:5786`/`:5833` —
  PASS.
- `_render_validation_issues_groups` `:5842`–`:5903` — PASS.
- `on_issue_row_selected` `:5905`–`:5926`; `_update_issues_hex_pane` `:5619` — PASS.
- `_populate_issues_datatable` (row-key `issue:<index>`) `:5928`–`:5972`;
  `_issue_row_key_to_index` init `:939`, reset `:5781`, write `:5968` — PASS.
- `_jump_to_validation_issue_by_index` `:5596`, sole caller `:5284` — PASS.
- Paging actions `:5974`–`:5994` — PASS.
- `precompute_issue_datatable_payload` `:752`; caches `_validation_issue_cell_rows/…styles`
  `:934`–`:935` (writers `:6649`–`:6651`, `:6955`–`:6956`, `:7161`) — PASS.

**US-043 / `s19_app/tui/styles.tcss`:**
- `#validation_issues_list { height:1fr; border:round $rule }` `:532`–`:535` — PASS.
- `#issues_columns #validation_issues_list { display:none }` + comment `:783`–`:791` —
  PASS.
- `#validation_issues_summary` `:537`–`:541` (preserve) — PASS.

**US-043 / `s19_app/tui/issues_view.py`:**
- `_GROUP_DISPLAY_MAX = 40` `:50` — PASS.
- `IssueRow.compose` `safe_text(...)` cells `:176`–`:180`; `_sev_class =
  css_class_for_severity(issue.severity)` `:171` — PASS.
- C-17 header docstring `:12`–`:23` — PASS.

**C-14 census / `tests/`:** occurrence counts confirmed by grep of
`validation_issues_list|get_row_at`: `test_tui_a2l_issue_recolor.py` (5),
`test_tui_app.py` (8), `test_tui_directionb.py` (8), `test_tui_issues_view.py` (3),
`test_validation_service_supplemental.py` (5) — PASS. Colour-oracle usage
(`get_row_at`) attributed to the last two per the task brief — noted as brief-provided,
verified present by count (per-line role to be confirmed by qa-reviewer during
migration design).

**Engine-frozen check:** none of `os_clipboard_input.py`, `app.py`, `issues_view.py`,
`styles.tcss` is in the frozen set (`core.py, hexfile.py, range_index.py, validation/,
tui/a2l.py, tui/mac.py, tui/color_policy.py`) — PASS.

## `should`-misuse avoided
Informative prose above uses "should" only in non-normative recommendation contexts
(e.g. "should be tracked", "software-dev/qa decision"). Every HLR/LLR normative
statement uses `shall`. No `should` appears as a modal verb inside any HLR/LLR
statement — checked line by line.

## Evidence checklist
- [✓] Constraints stated — memory/latency bound, sub-second budget, TUI-only,
  engine-frozen=0, small-team maintainability (US-042 HLR; US-043 dependency finding).
- [✓] ≥2 alternatives — Q1 option (a) vs (b) evaluated + one rejected with rationale.
- [✓] Recommendation tied to constraints — (b) chosen for coverage+simplicity;
  straight removal chosen over compat shim (census shows no non-test consumer).
- [✓] Risks listed — R-044-1..3, R-043-1..3 (operational/UX/correctness/test-migration).
- [✓] Cost/latency estimated — negligible add (one len+slice) / net reduction (widget +
  populate loop removed).
- [✓] Diagram — flow is linear (cascade funnel; widget removal); dependency finding table
  substitutes; no mermaid needed.
- [✓] What would change the recommendation — stated for both stories.
- [✓] Two-layer requirements — each story: black-box Acceptance (observable deliverable
  per HLR/LLR) + functional US→HLR→LLR chain; behavioral US→AT→outcome and functional
  US→HLR→LLR→TC to be completed by qa-reviewer (AT-NNN) and increment (TC-NNN); C-14
  observer invariants named per file.
