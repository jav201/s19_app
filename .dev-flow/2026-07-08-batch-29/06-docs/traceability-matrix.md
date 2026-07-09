# Traceability Matrix · batch-29 — clipboard read cap (R-TUI-044) + legacy Issues DataTable retirement

Two TUI-side stories, **0 engine-frozen diffs**, full suite **1158 passed / 2 skipped / 23 xfailed /
0 failed** (1183 collected). Every provisional `AT-`/`TC-` id in the v2 spec reconciles to a real
on-disk `def test_…` node (verified in `04-validation.md` §5); each is **green**. Rows below cite the
function name + `file:line` verbatim from `04-validation.md`. No gaps.

Legend: **Test** = an automated `def test_…` observes the predicate. **Inspection** = grep / diff /
compose-subtree read (no dedicated node — the mechanism is a removal or a corollary). **Retention** =
covered by an unchanged pre-existing test that would break if the guarded behaviour regressed.

---

## US-042 — bound the OS-clipboard read (R-TUI-044)

Surface: `read_os_clipboard()` return + `OsClipboardInput.value` after a real Pilot `ctrl+v`.
All nodes in `tests/test_loadfilescreen_input.py`. Cap `_CLIPBOARD_READ_CAP_CHARS = 65536`
(`os_clipboard_input.py:72`); single funnel `_bound_clipboard_text` in `read_os_clipboard`
(`os_clipboard_input.py:223`/`:306`).

| US | HLR | LLR | Black-box AT (node · line) | White-box TC (node · line) | Method | Status |
|----|-----|-----|----------------------------|----------------------------|--------|--------|
| US-042 | HLR-044.1-clip | LLR-044.1 (define `_CLIPBOARD_READ_CAP_CHARS = 65536`) | — | TC-042.1 `test_tc042_1_cap_constant_is_positive_int_at_least_4096` · `:775` | Test | pass |
| US-042 | HLR-044.1-clip | LLR-044.2 (truncate `<= CAP` at the single non-`None` funnel) | AT-042a `test_at042a_read_os_clipboard_caps_huge_single_line_blob` · `:639` | TC-042.2 `test_tc042_2_bound_helper_behavior` · `:785`; TC-042.3 `test_tc042_3_read_os_clipboard_bounds_selected_strategy_result` · `:809` | Test | pass |
| US-042 | HLR-044.1-clip | LLR-044.3 (capped prefix never `None` → paste inserts, no failure-notify fall-through) | AT-042b `test_at042b_ctrl_v_inserts_capped_value_via_real_read` · `:657`; AT-042e `test_at042e_real_path_passes_through_untouched` · `:718` | (via TC-042.3) | Test | pass |
| US-042 | HLR-044.1-clip | LLR-044.4 (`splitlines()[0]` of the already-capped string; never raises) | AT-042c `test_at042c_boundary_at_cap_is_unchanged` · `:691`; AT-042d `test_at042d_boundary_over_cap_by_one_drops_last_char` · `:704`; AT-042f `test_at042f_multiline_clipboard_inserts_only_first_line` · `:747` | — | Test | pass |
| US-042 | HLR-044.1-clip | LLR-044.5 (success `len=` debug-log reports post-cap length) | — | **by-inspection** (corollary of LLR-044.2 — `_bound_clipboard_text` runs *before* the `len=%d` funnel, so the logged length is post-cap; arch-m4: non-independent, no separate node) | Inspection | n/a |
| US-042 | HLR-044.1-clip | LLR-044.6 (true source memory bound via bounded `Popen`) | — | — | **DEFERRED** (named-not-built; residual risk R-044-1) | deferred |

**B-1 fix (Phase-2 blocker, folded pre-code).** AT-042b injects at `os_clip_mod._STRATEGIES`
(BELOW the capped `read_os_clipboard`), NOT a wholesale `read_os_clipboard` monkeypatch — the latter
would bypass the very cap it asserts. The real cap therefore runs inside `action_paste`.

**Perf (V-5).** "Doesn't scale" is proven **structurally** by the length bound (`len == CAP`), not by
a flaky wall-clock timer — AT-042a/b are the length-bound proof.

---

## US-043 (retire) — `GroupedIssuesPanel` is the sole Issues surface

Surface: widget tree, grouped nodes, `#issues_hex_pane`. HLR-043.R1-retire (traces US-043; extends
R-TUI-042). Grep of `s19_app/` for `#validation_issues_list` / `_populate_issues_datatable` /
`_issue_row_key_to_index` / `_jump_to_validation_issue_by_index` = **0 source hits**.

| US | HLR | LLR | Black-box AT (node · line) | White-box TC (node · line) | Method | Status |
|----|-----|-----|----------------------------|----------------------------|--------|--------|
| US-043 | HLR-043.R1-retire | LLR-043.R1 (remove `DataTable(id=validation_issues_list)` from `_compose_screen_issues`) | AT-043a `test_at043a_datatable_retired_grouped_panel_populated` · `directionb:1943` | TC-043-retire.1 `test_tc023_grouped_panel_is_primary_content_of_screen_issues` · `directionb:1841` (**inverted** TC-023) | Test | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R2 (remove both `#validation_issues_list` CSS rules + compat comment; keep `.issue-*` / `#validation_issues_summary`) | — | **by-inspection / grep** (`styles.tcss`; 0 source hits; snapshot-neutral — `display:none` had zero layout) | Inspection | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R3 (remove `#validation_issues_list` column-init block; MAC/A2L untouched) | — | **by-inspection / grep** (`app.py`; 0 source hits) | Inspection | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R4 (strip DataTable query/clear/populate from `update_validation_issues_view`; remove orphan `_populate_issues_datatable`; keep summary + both `_render_validation_issues_groups()` calls) | AT-043c `test_at043c_no_datatable_orphan_on_any_screen` · `directionb:2024` | TC-043-retire.2 `test_update_validation_issues_view_empty_state` · `app:836` (+ `…_pages_large_issue_list` · `app:876`) | Test | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R5 (remove `validation_issues_list` branch from `on_data_table_row_selected` + `_issue_row_key_to_index` + `_jump_to_validation_issue_by_index`; update docstring; MAC/A2L branches kept) | AT-043b `test_at043b_selection_preserved_after_retirement` · `directionb:1980` | TC-043-retire.3 `test_on_data_table_row_selected_dispatches_by_id` · `app:1542` | Test | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R6 (removal does not alter existing `IssueRow` cell markup-safety / hex-pane / paging / summary / `_GROUP_DISPLAY_MAX = 40`) | AT-043-c17 `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` · `test_tui_a2l_issue_recolor.py:326`; AT-039e `test_at_039e_c17_hostile_code_symbol_message_render_literal` · `directionb:6250` | **by-retention** (recolor + AT-039* suites green: code-chip + `.issue-detail` safety, `#issues_hex_pane`, paging, summary, cap unchanged) | Test + Retention | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R7 (engine-frozen diff stays 0) | — | `tests/test_engine_unchanged.py` + `test_tui_directionb.py::test_tc031_*` + `git diff main -- <frozen set>` EMPTY | Test + Inspection | pass |
| US-043 | HLR-043.R1-retire | LLR-043.R4/R7 (dead-code census; no *consumer* of cached rows remains; frozen diff 0) | — | TC-043-retire.4 **by-inspection / grep** — `_populate_issues_datatable` gone, `use_precomputed` block deleted; retired `test_populate_issues_datatable_records_filtered_index` | Inspection | pass |

---

## US-043 (restore) — related artifacts back on the grouped `IssueRow`

Surface: the `.issue-related` node on the mounted `IssueRow` (`issues_view.py:188`, built via
`safe_text`). HLR-043.R1-retire / LLR-043.R8 (Path A, operator decision).

| US | HLR | LLR | Black-box AT (node · line) | White-box TC (node · line) | Method | Status |
|----|-----|-----|----------------------------|----------------------------|--------|--------|
| US-043 | HLR-043.R1-retire | LLR-043.R8 (`IssueRow.compose` appends a `.issue-related` node rendering `", ".join(related_artifacts) or "-"` via `safe_text`) | AT-021 `test_at021_issues_list_shows_related_artifacts` · `test_tui_issues_view.py:174` (migrated `get_row_at` → `.issue-related`) | TC-043-restore.1 `test_tc043_restore1_related_node_is_markup_safe` · `test_tui_issues_view.py:227` | Test | pass |

**AT-021 re-point (§6.5 Before/After).** *Before* — asserted the "Related" cell of the batch-28-hidden
`#validation_issues_list` DataTable via `get_row_at` (green but user-invisible). *After* — asserts the
**restored `.issue-related` node** via its dedicated selector, so the info is user-visible again and the
acceptance is genuinely black-box. Rows ordered error→warning by `SEVERITY_ORDER`; multi-artifact row
plain text `== "a2l, mac"`, bare row `== "-"`.

**AT-043-c17 (C-17, closed Inc5).** The spec's *file-derived* multi-REF hostile-symbol AT was covered
only in parts across Inc2–4 (seeded render leg + service parse leg) and only joined into one on-disk
node in Inc5: `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal`
(`test_tui_a2l_issue_recolor.py:326`) drives `MAP_Model[bold]` + `x[link=file:///etc]` through the REAL
load chain, positively guards that both round-trip verbatim into `issue.symbol` via the frozen `a2l.py`
lexer, then asserts the rendered grouped `.issue-detail` plain text contains both literally (brackets
intact, `[link=…]` not consumed, no `MarkupError`). Counterfactual demonstrated (a markup-parsing node
consumes both tokens). Seeded `test_at_039e_c17_…` retained as the constructed companion.

---

## C-14 test-migration census (5 files · 18 rows)

`#validation_issues_list` was read by 5 test files; each invariant was re-observed on the grouped
panel (readers-first, widget-last sequencing kept the suite green at every increment boundary).

| Census row(s) | File | Migration | Status |
|---|---|---|---|
| #12/#13/#15/#16 | `test_tui_directionb.py` | `row_count` → `sum(IssueGroupHeader.issue_count)` (+ async `pilot.pause()` + `<= _GROUP_DISPLAY_MAX` guard); row-key select → real `IssueRow` focus+`Enter` → `on_issue_row_selected` → `#issues_hex_pane` | green |
| #14 | `test_tui_directionb.py` | left unchanged (already surface-agnostic: summary + `window_start`) | green |
| #10/#11 | `test_tui_directionb.py` | tc023 **inverted** → DataTable absent + grouped panel primary (AT-043a home) | green |
| #17 | `test_tui_a2l_issue_recolor.py` | `_issue_rows` → `query(IssueRow)`; `_SEV` string → enum; `_assert_within_cap` on every whole-list claim | green |
| #18 | `test_validation_service_supplemental.py` | same re-point + enum `_SEV` + `_assert_within_cap` on counts AND `not any(...)` absences | green |
| #1/#4/#5/#6/#8/#9 | `test_tui_issues_view.py`, `test_tui_app.py` | doc corrections + `query_one("#validation_issues_list")` branches dropped; `.issue-code-chip` re-point | green |

Notes carried by the census:
- The batch-24 recolor **colour** oracle reads `#a2l_tags_list` (a **different** DataTable, NOT
  retired) — left untouched. Only the `_issue_rows` **content** read-back migrated.
- Count-guard (qa M-2): every migrated whole-list claim — counts AND absences — asserts
  `len(filtered) <= _GROUP_DISPLAY_MAX` (40), NOT `< page_size` (200), so a capped `query(IssueRow)`
  cannot satisfy a claim vacuously.
- Census-missed direct-caller: `test_populate_issues_datatable_records_filtered_index` called the
  removed `_populate_issues_datatable` directly (not via the widget id) → retired in Inc4 (drove the
  `−1` ledger deviation). Root cause + candidate control C-CAND-B in `05-postmortem.md` §6/§7.
- `test_tc021_precompute_payload_emits_related_cell` survives as a formatter-only white-box TC (the
  worker `precompute_issue_datatable_payload` is kept, now dead-written — R-043-3 follow-up).

---

## Snapshot disposition (V-5)

23 snapshot xfails (20 batch-28 Issues/workspace `xfail(strict=False)` cells absorbing the restyle +
`.issue-related` node drift + the SVG-neutral DataTable removal, plus 3 pending baselines). DataTable
removal was SVG-neutral (`display:none` had zero layout). Cleared only by canonical-CI regen (pinned
`textual==8.2.8`, `snapshot-regen.yml`); local regen FORBIDDEN. No hard fail, no ERROR.

## Gaps

None. Every US → HLR → LLR chain terminates in a real black-box AT node AND a real white-box TC node
(or an explicitly recorded by-inspection / by-retention row for CSS/removal/frozen LLRs), all green in
the 1183-collected run.
