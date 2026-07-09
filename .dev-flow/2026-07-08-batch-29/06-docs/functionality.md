# Functionality · batch-29 — clipboard read cap + Issues DataTable retirement

Two TUI-side changes ship in this batch. One is a robustness fix on the Load-dialog paste path; the
other is a tech-debt cleanup that makes the Issues screen have a single source of truth while restoring
a display that had been invisible since batch-28. Neither touches the parsers, the range/validation
engine, or any other engine-frozen module (git diff against `main` over the frozen set is empty).

---

## 1. Clipboard read is now length-bounded (US-042 · R-TUI-044)

### What changed
`read_os_clipboard` (`s19_app/tui/os_clipboard_input.py`) now caps any clipboard value it returns to a
fixed **`_CLIPBOARD_READ_CAP_CHARS = 65536`** (64 Ki characters). A new module-private helper
`_bound_clipboard_text` performs the truncation at a **single funnel** inside `read_os_clipboard`: when
any cascade layer returns a non-`None` value, the value is truncated to `<= CAP` *before* it is logged
or returned. Because the cap sits at that one funnel, it covers every layer of the existing cascade —
`tkinter` → `ctypes` (Win32) → `powershell.exe Get-Clipboard` — and any injected `strategies=` used by
tests, with no per-layer duplication.

### Why 64 KiB
64 Ki characters is roughly **twice the largest legal Windows extended path** (~32 Ki). A real file
path can therefore never be truncated by the cap; only a pathological multi-megabyte clipboard blob is
shortened. `action_paste` is unchanged: it still inserts `splitlines()[0]` of the (now bounded) value,
so a huge single-line clipboard yields the `CAP`-length prefix instead of feeding an unbounded string
into `splitlines`, into the Load-dialog `Input`, or into the logs. Truncation returns the capped prefix
(never `None`), so paste never falls through to the internal-buffer fallback or the failure
notification, and never raises.

### Honest scope note (functional bound, not a source memory bound)
This is a **functional** bound on all *downstream* use of the clipboard value — it stops the oversized
value from flowing into `splitlines`, the widget, or the logs, and stops a paste-driven hang. It does
**not** prevent the transient full-string materialization that happens *inside* each reader layer
(tk/ctypes/PS each read the whole OS clipboard before the cap applies). That residual is disclosed as
**R-044-1** and would be addressed by the **deferred, named-not-built LLR-044.6** (a true source bound
via a bounded `subprocess.Popen(...).stdout.read(CAP+1)` + terminate for the PowerShell layer). Building
it is only warranted if profiling ever shows the transient materialization is the real cost. The
requirement statement (HLR-044.1-clip) was deliberately worded to avoid a "memory spike" overclaim and
to carry this caveat in-line.

Also flagged, not fixed (scope): the internal-buffer fallback (`self.app.clipboard`) is not routed
through `read_os_clipboard`, so it is not capped — but it is app-populated and short (**R-044-3**).

---

## 2. The Issues screen now has one surface (US-043 · extends R-TUI-042)

### Background
batch-28 introduced `GroupedIssuesPanel` (the grouped-by-severity Issues view with per-group counts,
code chips, and the live hex-peek pane) but left the **legacy `#validation_issues_list` DataTable
mounted with `display:none`** as a transitional shim — two Issues surfaces coexisting, one of them
invisible and unmaintained. batch-29 retires that shim.

### What changed — retirement
`GroupedIssuesPanel` is now the **sole** mounted Issues surface. The removal deleted, atomically:
- the `DataTable(id="validation_issues_list")` from `_compose_screen_issues` (the grouped panel is now
  the only child of the `#issues_list_stack` wrapper);
- its two CSS rules and their compat comment in `styles.tcss`;
- its column-init block, its population / row-key map, and the `use_precomputed` /
  `_populate_issues_datatable` path in `update_validation_issues_view`;
- the `validation_issues_list` branch of `on_data_table_row_selected`, plus the now-unreachable
  `_issue_row_key_to_index` map and `_jump_to_validation_issue_by_index` method.

A grep of `s19_app/` for `#validation_issues_list` (and the removed helpers) returns **0 source hits**.
The MAC and A2L DataTables — and the batch-24 recolor **colour** oracle that reads the separate
`#a2l_tags_list` DataTable — are untouched.

### What is preserved
A verified finding drove the low-risk sequencing: **the summary and the paging window never depended on
the DataTable.** Both route through `_validation_issues` counts and `_render_validation_issues_groups`.
So the following are preserved with no re-wiring beyond deletion:
- **Selection → hex peek** — selecting an issue (`IssueRow.Selected` → `on_issue_row_selected` →
  `_update_issues_hex_pane`) still repaints `#issues_hex_pane`; an address-less issue shows the neutral
  placeholder, not stale bytes.
- **Paging** — PgUp/PgDn window preserved via `_get_window_bounds` / `window_start`.
- **Summary** — `#validation_issues_summary` still updates.
- **The bounded display window** — `_GROUP_DISPLAY_MAX = 40` still caps mounted rows so a hostile
  large-N issue list cannot flood the widget tree.

### What changed — restoration (operator Path A)
The "Related artifacts" information had been **invisible since batch-28** (it lived only on the hidden
DataTable's Related column). batch-29 restores it: `IssueRow.compose` now appends a dedicated
**`.issue-related`** node (`issues_view.py:188`) rendering `", ".join(issue.related_artifacts) or "-"`.
The value is the same one the retired Related column showed; it is queryable black-box via the
`.issue-related` selector, which is how the restored AT-021 observes it through the shipped surface.

### C-17 markup-safety posture
Every file-derived string on the grouped `IssueRow` — the code chip, the `.issue-detail` span, and now
the new `.issue-related` node — is built with the frozen `safe_text` helper, producing a literal
`rich.text.Text` that is **never markup-parsed**. So a hostile symbol such as `MAP_Model[bold]` or
`x[link=file:///etc]` renders literally (brackets intact, link token not consumed, no OSC-8 leak, no
`MarkupError`), even when the symbol is **file-derived** and reaches the panel through the real load
chain and the frozen `a2l.py` lexer (proven end-to-end by AT-043-c17). Today `related_artifacts` values
are fixed engine type-tokens (all producers are in `validation/engine.py`; no file-derived text), so the
`safe_text` build on the new node is **defense-in-depth** — it guarantees a future file-derived value
cannot become a silent injection sink. TC-043-restore.1 pins that invariant on the new node.

### Known follow-up (not a regression)
The load worker still invokes `precompute_issue_datatable_payload`, whose caches
(`_validation_issue_cell_rows` / `_validation_issue_cell_styles`) are now **dead-written on every load,
never read** (the consumer was the removed DataTable population). This is **R-043-3**: named,
surgically left in place this batch, and scoped as a follow-up batch (retire the worker calls, the
caches, and the two formatter TCs that pin them). It is dead work, not a user-visible defect.

---

## Provenance & verification

Both stories ran the full `/dev-flow` (English artifacts). Phase-2 tri-agent review caught 1 blocker +
5 majors + 5 minors + 2 security-minors, **all folded pre-code, 0 escaped**. The retirement was
sequenced **readers-first, widget-last** (the grouped panel had already run in parallel with the hidden
DataTable since batch-28), so the suite stayed green at every increment boundary — no big-bang removal.
Final suite: **1158 passed / 2 skipped / 23 xfailed / 0 failed** (1183 collected), **0 production
regressions**, **0 engine-frozen diffs**. The 23 xfails are batch-28/29 snapshot cells awaiting a
canonical-CI regen (pinned `textual==8.2.8`; local regen forbidden).
