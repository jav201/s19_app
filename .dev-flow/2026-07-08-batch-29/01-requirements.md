# 01 — Requirements · batch-29 · clipboard read cap + legacy Issues DataTable retirement

**BLUF.** Two functional/tech-debt stories, both TUI-side, **0 engine-frozen** modules touched.
**US-042** bounds the OS-clipboard read (`read_os_clipboard`) to a 64 KiB cap so an oversized
clipboard can't spike memory / stall Ctrl+V in the Load dialog. **US-043** fully retires the hidden
`#validation_issues_list` DataTable (kept `display:none` since batch-28) so `GroupedIssuesPanel` is the
sole Issues surface — and, per operator decision, **restores** the "Related artifacts" info (invisible
since batch-28) onto the grouped `IssueRow`. Requirements: **R-TUI-044** (clipboard) + retirement HLRs
extending **R-TUI-042/043**. Totals (v2, post Phase-2 fold): **2 US · 2 HLR · 13 LLR** (5 clip + 8 retire; +1 deferred) **· 11 AT
· 9 TC** plus an 18-row C-14 test-migration census. `shall`/`should` clean; every cite disk-verified
(see `_arch-hlr-llr.md` draft-time log). Agent source artifacts: `_arch-hlr-llr.md` (HLR/LLR),
`_qa-acceptance-validation.md` (AT/TC + full census).

Language: English. Route: full /dev-flow (supervised — no standing authorization this session).

---

## 1. Scope & context
- **US-042 code:** `s19_app/tui/os_clipboard_input.py` (+ `tests/test_loadfilescreen_input.py`).
- **US-043 code:** `s19_app/tui/app.py`, `s19_app/tui/issues_view.py`, `s19_app/tui/styles.tcss` (+ 5 test files).
- **Engine-frozen set (READ-only, 0 diff target):** `core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py, tui/color_policy.py`. `issues_view.py` imports `css_class_for_severity` as a reader; `ValidationIssue.related_artifacts` (model.py:128) is read, not modified.
- **Out of scope (operator-filtered):** clipboard backlog #2 (`<1s` benchmark — CI guard) and #3 (empty-vs-None per layer). Deferred `LLR-044.6` (true source memory bound via bounded Popen). `precompute_issue_datatable_payload` kept as tracked-orphan (follow-up batch).

## 2. User stories & Definition of Ready

**US-042** — *As a user pasting a path into the Load dialog, I want the clipboard read to stay fast and
memory-bounded even when the OS clipboard holds a huge blob, so Ctrl+V never spikes memory or hangs.*
READY. Value: robustness of the Load paste path. Observable through `read_os_clipboard()` return and the
`OsClipboardInput.value` after a real `ctrl+v` under Pilot.

**US-043** — *As a maintainer, I want `GroupedIssuesPanel` to be the sole Issues surface (the hidden
legacy DataTable gone), with the "Related artifacts" info preserved for the user.* READY. Value:
one source of truth for the Issues screen + restoration of a display invisible since batch-28. Observable
through the widget tree (`query("#validation_issues_list") == 0`), the grouped panel nodes, the
`#issues_hex_pane` peek, and the restored related-artifacts node on `IssueRow`.

## 3. Acceptance (black-box) blocks

### US-042 — clipboard cap (surface: `read_os_clipboard` return + `OsClipboardInput.value` after `ctrl+v`)
Cap `CAP = _CLIPBOARD_READ_CAP_CHARS = 65536`. Harness reuse: injectable `strategies=` + Ctrl+V
monkeypatch idiom in `tests/test_loadfilescreen_input.py` (no real OS clipboard).

| AT | Input (rep / boundary / negative) | Real mechanism | Observed deliverable |
|----|-----------------------------------|----------------|----------------------|
| **AT-042a** | `"A"*(CAP+5_000_000)` single-line | `read_os_clipboard(strategies=((fake),))` | return len `== CAP`, `== blob[:CAP]` |
| **AT-042b** *(v2 — qa B-1: inject BELOW `read_os_clipboard`)* | same blob injected via `monkeypatch.setattr(os_clip_mod, "_STRATEGIES", (("fake", lambda: blob),))` (NOT the wholesale `read_os_clipboard` monkeypatch — that bypasses the cap); real `ctrl+v` | `press("ctrl+v")` → `action_paste` → real capped `read_os_clipboard` | `input.value` len `<= CAP`, `== blob[:CAP]` |
| **AT-042c** (boundary at cap) | `"p"*CAP` | read + `ctrl+v` | value unchanged, len `CAP` (inclusive) |
| **AT-042d** (boundary +1) | `"p"*CAP + "X"` | `read_os_clipboard` | len `CAP`, last char `"p"` (X dropped) |
| **AT-042e** (negative — pass-through) | real ~120-char path | read + `ctrl+v` | `value ==` exact path, untouched |
| **AT-042f** (multi-line) | `"first\nsecond\nthird"` | `ctrl+v` | `value == "first"` (splitlines policy intact) |

**Counterfactual (C-10):** pre-cap, AT-042a/b return/insert the full multi-MB blob → FAIL; AT-042c/e/f
pass pre-cap (guarding against an over-aggressive cap). **Perf (V-5):** "doesn't scale" is proven
*structurally* by the length bound, not by a flaky wall-clock timer.

### US-043 — retirement + restoration (surface: widget tree, grouped nodes, `#issues_hex_pane`)

| AT | Input | Real mechanism | Observed deliverable |
|----|-------|----------------|----------------------|
| **AT-043a** (retirement) | seed err/warn/info mix; open Issues | Pilot render of `#screen_issues` | `query("#validation_issues_list")==0` AND `query("#validation_issues_groups")==1` with `>=1 IssueRow` |
| **AT-043b** (selection preserved) | focus a non-default addressed `IssueRow`, `Enter` | `IssueRow.on_key` → `Selected` → `on_issue_row_selected` | `#issues_hex_pane` shows the issue's `0x…` bytes and CHANGES; `address None` → neutral, no stale bytes |
| **AT-043c** (total, no orphan) | boot; open Issues | tree query on every rail screen | `query("#validation_issues_list")==0` on `#screen_issues` AND `#screen_workspace` |
| **AT-021** (RESTORED — related artifacts) | seed one issue with `related_artifacts=["a2l","mac"]` + one bare issue | grouped `IssueRow` render (rows ordered by `SEVERITY_ORDER` error→warning) | the multi-artifact row's `.issue-related` node plain-text `== "a2l, mac"`; the bare row `== "-"` — **read through the shipped surface** via the dedicated `.issue-related` selector, not the payload formatter |
| **AT-043-c17** (C-17, file-derived) *(v2 — qa M-1: multiple REF entries, assert on detail node)* | load an A2L with **multiple** GROUP `REF_*` entries, each a hostile no-whitespace ghost symbol (`MAP_Model[bold]`, `x[link=file:///etc]`) → shipped chain emits `A2L_BROKEN_REFERENCE` issues carrying those literals in `.symbol` | full load chain → `GroupedIssuesPanel` | no `MarkupError`; the **`.issue-detail`** node plain-text contains literal `MAP_Model[bold]` (brackets intact) + literal `[link=file:///etc]` (token NOT consumed, no OSC-8, no style leak, no crash). *(The code chip renders the fixed constant `A2L_BROKEN_REFERENCE`; ANSI-byte + code-field coverage stays with the retained seeded AT-039e. Verify token survival through the frozen `a2l.py` lexer in Phase 3 before committing the fixture.)* |

**Counterfactuals:** pre-retirement `query("#validation_issues_list")==1` (hidden DataTable still mounted)
→ AT-043a/c FAIL. AT-021 pre-restoration: `IssueRow` has no related node → FAIL. AT-043-c17: if
`safe_text` were bypassed, `[bold]`/`[link]` raises `MarkupError` or the link token is consumed → FAIL.
Keep the existing seeded `test_at_039e_c17_...`; AT-043-c17 strengthens it to a **file-derived** symbol.

## 4. Requirements (HLR / LLR)

### R-TUI-044 · HLR-044.1-clip (traces US-042)  *(reworded v2 — arch M1: no "memory spike" overclaim)*
*The system shall bound the length of any OS-clipboard value it reads for the Load-dialog paste to a
fixed maximum before the value is used downstream, so an oversized clipboard cannot cause an unbounded
`splitlines` cost, an oversized value flowing into the Input widget or logs, or a hang, and the paste
still inserts the (bounded) first line without crashing. (This bounds downstream use; it does not prevent
the transient full-string materialization inside each read layer — see R-044-1 — which the deferred
LLR-044.6 would address.)*
- **LLR-044.1** — define `_CLIPBOARD_READ_CAP_CHARS = 65536` in `os_clipboard_input.py` (beside `:64`–`:68`). 64 Ki chars ≈ 2× the largest legal Windows extended path → never truncates a real path.
- **LLR-044.2** — in `read_os_clipboard`, when a layer returns non-`None`, truncate to `<= CAP` before returning (single funnel at `:265`–`:269`; covers tk/ctypes/PS and any injected `strategies`).
- **LLR-044.3** — truncation returns the capped prefix (never `None`), so `action_paste` inserts the bounded first line and does NOT fall through to the internal buffer or the failure notification.
- **LLR-044.4** — inserted value derives from `splitlines()[0]` of the already-capped string; a single-line over-cap clipboard yields the `CAP` prefix; truncation never raises.
- **LLR-044.5** — the success debug-log `len=` reports the post-cap length.
- **LLR-044.6 (DEFERRED, named-not-built)** — true source memory bound for PS via `subprocess.Popen(...).stdout.read(CAP+1)` + terminate. Not this batch (operator's pragmatic scope). Residual risk R-044-1: the post-read cap does not stop transient full-string materialization inside each reader.

### HLR-043.R1-retire (traces US-043; extends R-TUI-042/043)
*The system shall make `GroupedIssuesPanel` the sole mounted Issues surface — removing the
`#validation_issues_list` DataTable, its CSS, its column init, its population, its row-key map, and its
`on_data_table_row_selected` routing — while preserving the grouped view, the `#issues_hex_pane` peek,
the `IssueRow.Selected → _update_issues_hex_pane` wiring, PgUp/PgDn paging, `#validation_issues_summary`,
the `_GROUP_DISPLAY_MAX` bound, and C-17 markup-safety; and the system shall render each issue's
related-artifacts on the grouped `IssueRow` so that information (invisible since batch-28) is restored.*

Verified finding: **summary + paging do NOT depend on the DataTable** — both route through
`_validation_issues` counts + `_render_validation_issues_groups`; no re-wiring needed beyond deletion.

- **LLR-043.R1** — remove the `DataTable(id="validation_issues_list")` from `_compose_screen_issues` (`app.py:1482`–`:1486`) **and its adjacent compat comment** (`:1475`–`:1481`); `GroupedIssuesPanel` is the sole child of `#issues_list_stack` (keep the wrapper id).
- **LLR-043.R2** — remove the two CSS rules: `#validation_issues_list {…}` (`styles.tcss:532`–`:535`) and `#issues_columns #validation_issues_list { display:none }` **plus its adjacent compat comment** (`:783`–`:791`). Preserve `#validation_issues_summary` + `.issue-*`.
- **LLR-043.R3** — remove the `#validation_issues_list` column-init block (`app.py:3300`–`:3314`); MAC/A2L init untouched.
- **LLR-043.R4** — strip DataTable query/clear/populate + `_issue_row_key_to_index` reset from `update_validation_issues_view` (`:5779`–`:5840`); keep the summary computation + both `_render_validation_issues_groups()` calls. Remove the orphaned `_populate_issues_datatable` (`:5928`–`:5972`).
- **LLR-043.R5** — remove the `validation_issues_list` branch from `on_data_table_row_selected` (`:5281`–`:5285`); remove `_issue_row_key_to_index` (`:939`) and the now-unreachable `_jump_to_validation_issue_by_index` (`:5596`); **update the `on_data_table_row_selected` Data Flow/Dependencies docstring** (`:5259`/`:5265`) to drop the removed path. MAC/A2L branches preserved. *Intentional narrowing (R-043-2): the "row-select shifts the main hex view" path retires — already user-unreachable since batch-28's `display:none`.*
- **LLR-043.R6** *(v2 — qa m-1: guard behavior, not literal lines)* — regression guard: the removal shall not alter the **markup-safety and behavior of the existing `IssueRow` cells** (code chip + `.issue-detail`), the `#issues_hex_pane`, the `IssueRow.Selected → on_issue_row_selected → _update_issues_hex_pane` wiring, paging, the summary label, or the `_GROUP_DISPLAY_MAX = 40` bound (`issues_view.py:50`). *(R8 legitimately ADDS a third `safe_text` node to `IssueRow.compose`; R6 guards the existing cells' safety, it does not forbid the addition.)*
- **LLR-043.R7** — engine-frozen diff stays 0 (`git diff main -- <frozen set>` empty; `test_engine_unchanged.py` / `test_tc031_*` pass).
- **LLR-043.R8 (NEW — Path A, operator decision)** *(v2 — named selector)* — `IssueRow.compose` shall **append** a dedicated markup-safe related-artifacts node carrying the queryable class **`.issue-related`**, rendering `", ".join(issue.related_artifacts) or "-"` (source: `ValidationIssue.related_artifacts`, model.py:128; the value the retired Related column showed, app.py:786) built via `safe_text`, so the info is user-visible again and AT-021 observes it black-box through `.issue-related`. *related_artifacts values are fixed engine type-tokens today (security-F1: all producers in `validation/engine.py`; no file-derived text) — the `safe_text` build is defense-in-depth so a future file-derived value cannot become a silent injection sink; TC-043-restore.1 pins it. Exact layout/CSS is a Phase-3 detail; the invariant is: plain text readable + literal, queried via `.issue-related`.*

## 5. Dual traceability (both chains required)

| US | HLR | LLR | Black-box AT | White-box TC |
|----|-----|-----|--------------|--------------|
| US-042 | HLR-044.1-clip | LLR-044.1–.5 | AT-042a–f | TC-042.1–.3 |
| US-043 (retire) | HLR-043.R1-retire | LLR-043.R1–.R7 | AT-043a, AT-043b, AT-043c, AT-043-c17 | TC-043-retire.1–.4 |
| US-043 (restore) | HLR-043.R1-retire | LLR-043.R8 | AT-021 (migrated → `.issue-related` node) | TC-043-restore.1 (white-box on the shipped node; + census #3 formatter TC retained for the orphan payload) |

## 6. Validation methods + white-box TCs
Both stories: **Test** (automated AT + TC), fully headless. US-043 adds **Inspection** (compose subtree +
dead-code grep for TC-043-retire.1/.4) and **Analysis + provisional Test (V-5)** for snapshot neutrality.

| TC | LLR | Mechanism (HOW) |
|----|-----|-----------------|
| TC-042.1 | LLR-044.1 | `_CLIPBOARD_READ_CAP_CHARS` exists, positive int, `>= 4096` |
| TC-042.2 | LLR-044.2 | bound helper: `len<=CAP` → unchanged; longer → `[:CAP]`; `""`/`None` no-raise |
| TC-042.3 | LLR-044.2/.3 | `read_os_clipboard` applies the bound to the selected strategy result (caller-independent) |
| TC-043-retire.1 | LLR-043.R1 | `_compose_screen_issues` yields no `DataTable(id="validation_issues_list")`; `#issues_list_stack` holds only `GroupedIssuesPanel` |
| TC-043-retire.2 | LLR-043.R4 | `update_validation_issues_view` makes no `query_one("#validation_issues_list")`/`_populate_issues_datatable`; empty+populated paths route only through `_render_validation_issues_groups` |
| TC-043-retire.3 | LLR-043.R5 | `on_data_table_row_selected` drops the issues branch (mac+a2l intact); `_issue_row_key_to_index` + `issue:<index>` emission gone |
| TC-043-retire.4 *(v2 — arch M3: precise predicate)* | LLR-043.R4/R7 | dead-code census: `_populate_issues_datatable` gone; **no *consumer* of the cached rows remains** (the `use_precomputed` block deleted). `precompute_issue_datatable_payload` may STILL be invoked by the load worker (`app.py:6649/:7161`) — its caches are dead-written pending follow-up (R-043-3); frozen diff 0 |
| TC-043-restore.1 *(NEW — arch M2 + security F1)* | LLR-043.R8 | `IssueRow.compose` yields a `.issue-related` node whose plain text is `", ".join(related_artifacts) or "-"` built via `safe_text`; a bracket/ANSI/OSC-8 payload injected into a test issue's `related_artifacts` renders **literal** (no `MarkupError`, no token consumption) — pins the C-17 invariant on the new node |

### 6.1 C-14 test-migration census (summary; full 18-row table in `_qa-acceptance-validation.md`)
`#validation_issues_list` is read by **5** test files. Faithful re-point re-observes each invariant on the
grouped panel. Key points:
- The batch-24 recolor **colour** oracle reads `#a2l_tags_list` (a **different** DataTable, **NOT** retired) — unchanged. Only the `_issue_rows` **content** read-back migrates (→ iterate `query(IssueRow)`, read `row.issue.*`; stronger enum typing). Fixtures ≤4 issues → under the 40-row cap.
- **Count-guard (v2 — qa M-2):** because `GroupedIssuesPanel` mounts at most `_GROUP_DISPLAY_MAX = 40` rows regardless of `page_size` (200), every migrated whole-list claim — **counts AND absences** (`not any(...)` in `test_at_036a/036c/037a`, not only "exactly one") — must guard `assert len(filtered) <= _GROUP_DISPLAY_MAX` (or assert the `IssueGroupHeader.issue_count`), NOT `< page_size`, so a capped `query(IssueRow)` can never satisfy the claim vacuously.
- `test_tc023_issues_table_is_primary_content` **inverts** → asserts DataTable absent + grouped panel primary (AT-043a's home).
- Windowing/row-key tests (`pages_large_issue_list`, `row_select_jumps`, `dispatches_by_id` issue line, `uses_worker_precomputed_cells`) re-point to the **summary/window-bounds** + `IssueRow.Selected`, or retire with the row-key path.
- **AT-021** (`test_at021_issues_list_shows_related_artifacts`) re-points to the **restored IssueRow related node** (Path A) — stays black-box.
- `test_tc021_precompute_payload_emits_related_cell` survives as a **formatter-only white-box TC** (precompute kept).

### 6.5 Requirement amendments (Before/After)
Net-new batch (no locked requirement edited). One decision recorded:
- **AT-021 re-point (Deleted → New):** *Before* — AT-021 asserted the "Related" cell of the (batch-28-hidden) `#validation_issues_list` DataTable via `get_row_at` (green but user-invisible). *After* — AT-021 asserts the **restored IssueRow `.issue-related` node** (LLR-043.R8), making the info user-visible again and the acceptance genuinely black-box. Rationale: operator chose Path A (restore) over Path B (accept narrowing).

### 6.6 Phase-2 review fold (v2)
Tri-agent cross-review (`02-review.md`): 1 blocker, 5 majors, 5 minors, 2 security-minors — **all folded here**, 0 iterate-to-Phase-1.
- **B-1 (blocker)** → AT-042b re-targeted to inject at `_STRATEGIES` (below the capped `read_os_clipboard`), not the wholesale monkeypatch. §3.
- **arch M1** → HLR-044.1-clip reworded (no "memory spike" overclaim; transient-materialization caveat in-statement). §4.
- **arch M2 + security F1** → NEW **TC-043-restore.1** (white-box on the `.issue-related` node via `safe_text` + hostile-`related_artifacts` renders literal). §5/§6.
- **arch M3** → TC-043-retire.4 predicate tightened + R-043-3 names the dead-write worker calls (precompute is worker-invoked, cache-unconsumed — not orphaned). §6/§7.
- **qa M-1** → AT-043-c17 restructured (multiple no-whitespace REF entries; assert on `.issue-detail`, not the chip; ANSI stays with retained AT-039e). §3.
- **qa M-2** → count-guard corrected to `len(filtered) <= _GROUP_DISPLAY_MAX` (40), on **counts AND absences**. §6.1.
- **minors** → `.issue-related` selector named (R8); stale compat comments removed (R1/R2); `on_data_table_row_selected` docstring update (R5); AT-021 `SEVERITY_ORDER` note. §3/§4.
- **noted (no change):** LLR-044.5 is a corollary of LLR-044.2 (bounded logging follows from capping before `len`); two preserved behaviors (capped-paste notification-not-fired; paging-advances) are covered **by-retention** (retained tests), not by new named ATs.

## 7. Assumptions / risks
- **R-044-1** (low): post-read cap is a functional bound, not a true source memory bound (transient full materialization inside each reader remains). Mitigation: cap bounds all downstream cost; deferred LLR-044.6.
- **R-044-3** (low): the internal-buffer fallback (`self.app.clipboard`) isn't routed through `read_os_clipboard` so isn't capped — that buffer is app-populated + short. Flagged, not fixed (scope).
- **R-043-1** (medium): 5 test files migrate; incomplete migration reddens the suite. Mitigation: the 18-row census is the map; migration lands with the code per increment.
- **R-043-2** (low, intentional): "row-select shifts main hex view" retires (user-unreachable since batch-28).
- **R-043-3** (low, v2 — arch M3): after LLR-043.R4 removes the cache *consumer*, `precompute_issue_datatable_payload` is still invoked by the load worker (`app.py:6649/:7161`) and its caches (`_validation_issue_cell_rows`/`_validation_issue_cell_styles`, written at `:6650-6651/:6955-6956`) are **dead-written every load, never read** — not orphaned, but dead work. Follow-up batch scope: retire the worker precompute calls + caches (named here so the follow-up has exact scope). Not deleted this batch (surgical).
- **Snapshot (V-5):** DataTable is `display:none` (zero layout) → removal expected SVG-neutral; any delta regenerated in canonical CI only (local FORBIDDEN); xfail-until-baseline for any shifted Issues cell.

## 8. Evidence checklist (Phase 1)
- [✓] Every US has ≥1 black-box AT observing the shipped surface — AT-042a–f; AT-043a/b/c, AT-021, AT-043-c17.
- [✓] Every output-producing requirement names its observable deliverable — §3 tables + §4 LLR deliverables.
- [✓] Dual traceability complete — §5 (no US without both chains).
- [✓] `shall`/`should` discipline — architect line-checked; no modal `should` in any HLR/LLR.
- [✓] Draft-time verification — all cites disk-verified (`_arch-hlr-llr.md` log; LLR-043.R8 grounded at app.py:786 / model.py:128).
- [✓] C-10 AT-authoring — counterfactuals shown; boundary (AT-042c/d) + negative (AT-042e) + hostile (AT-043-c17); no default-value-reliant pilot.
- [✓] C-14 census — 5 files mapped (18 rows); recolor colour oracle correctly scoped to the untouched `#a2l_tags_list`.
- [✓] C-17 — retirement AT rides on the grouped panel (AT-043-c17, file-derived); `safe_text` preserved (LLR-043.R6) + used for the new related node (LLR-043.R8).
- [✓] 0 engine-frozen — LLR-043.R7; none of the touched files is frozen.
