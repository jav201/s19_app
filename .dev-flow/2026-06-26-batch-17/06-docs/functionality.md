# Functionality — s19_app — Batch 2026-06-26-batch-17

> **Artifact language:** English.
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (operator + maintainer).

## 🔑 At a glance (read first)

- **What this batch added:** four operator-facing TUI improvements — a readable Workspace hex row, an operator-chosen CRC save width, an Issues hex pane, and a Related column on the Issues list. Three previously-deferred features under full /dev-flow rigor; one (CRC width) session-emergent.
- **Capabilities:**
  - **Workspace hex row on one line** — the Workspace hex column now shows all 16 bytes + their ASCII decode on a single line; on a narrow terminal you scroll horizontally to reach the rest, and all three Workspace panes stay visible.
  - **Operator-selected CRC save width** — the CRC write-confirm dialog now has a **Width** selector (16 or 32 bytes/line, default 32); the written `.s19` honours your choice.
  - **Issues hex pane** — selecting a validation-issue row now renders the bytes at that issue's address in a hex pane beside the list (a clear placeholder when the issue has no address).
  - **Issues Related column** — the issues list now has a **Related** column showing each issue's related artifacts (`-` when none).
- **How to use it:** launch `s19tui` (optionally `s19tui --load <file>`); the Workspace hex pane and Issues screen are reached from the normal TUI navigation, and the CRC Width selector appears on the "Write CRC image" confirm dialog.

> Enough to know what shipped and how to reach it. Detail below for how it works and where the seams are.

---

## Detail (reference)

### How it works (flow)

**(a) Workspace hex row on one line (US-018).**
The Workspace hex view (`#hex_view`, a Textual `Static`) previously reflowed the ~81-cell hex row down to the ~30-cell center pane, wrapping it. The fix content-sizes the view with `#hex_view { width: auto }`, so it sizes to a full row instead of the pane; the pre-existing scroll container `#hex_scroll { overflow: auto }` supplies a horizontal scrollbar when the center pane is narrower than a row. Both fixed side panes (left + right context) stay on-screen.

> The earlier, rejected approach (a `#ws_center { min-width: 82 }` floor, mirroring the MAC pane) is **not** used — see the §6.5 A2 amendment in `01-requirements.md`. The Workspace is a three-pane layout with two fixed sides, so a center floor pushed the right context pane off-screen; that is the likely reason prior attempts at this fix never stuck.

**(b) Operator-selected CRC save width (US-019).**
The CRC write-confirm modal (`ConfirmWriteScreen`) now owns a width-cycle button over `(32, 16)` defaulting to 32. Confirming dismisses the modal with a `ConfirmWriteResult(confirmed, bytes_per_line)`; the handler threads `bytes_per_line` through the worker into `write_crc_image`, which passes it to `emit_s19_from_mem_map`. The CRC algorithm/config and the S0-header policy are unchanged; only the data-record framing width changes. Declining the write still produces no file.

**(c) Issues hex pane (US-020a).**
The Issues screen compose tree gained a hex `Static` (`#issues_hex_pane`) beside the issues list. When a row is selected, the existing jump handler resolves the `ValidationIssue` and calls `_update_issues_hex_pane(address)`, which renders the bytes at that address via the shared `render_hex_view_text`. An issue with no address shows the placeholder `"(issue has no address — nothing to show)"` and clears any prior bytes (no stale carry-over).

**(d) Issues Related column (US-020b).**
The issues DataTable payload builder (`precompute_issue_datatable_payload`) now emits each issue's `related_artifacts` as a comma-joined `Related` cell (`-` when empty), and the table gained a matching `Related` column header. The cell tuple widened from 7 to 8 fields, kept index-aligned with the per-row severity styles and the column count (8 == 8). No new validation logic — only existing `ValidationIssue` fields are exposed.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/styles.tcss` | `#hex_view { width: auto }` (US-018) so the hex row content-sizes; relies on existing `#hex_scroll { overflow: auto }` for horizontal scroll. |
| `s19_app/tui/screens.py` | `ConfirmWriteScreen` + `ConfirmWriteResult` (width selector + width-bearing dismiss); `_on_confirm_write` / `_run_crc_write_worker` thread `bytes_per_line` (US-019). |
| `s19_app/tui/operations/crc.py` | `write_crc_image` gained `bytes_per_line: int = 32`, passed to `emit_s19_from_mem_map` (US-019). |
| `s19_app/tui/app.py` | `_compose_screen_issues` adds `#issues_hex_pane`; `_update_issues_hex_pane` renders bytes / placeholder (US-020a); `precompute_issue_datatable_payload` emits the Related cell (US-020b). |
| `tests/test_tui_workspace_layout.py` (new), `tests/test_tui_issues_view.py` (new), `tests/test_tui_crc_surface.py`, `tests/test_crc_operation.py`, `tests/test_tui_app.py` | Two-layer validation (AT + TC). |

> All modules are **outside** the engine-frozen set; `changes/io.py` was **not** edited (the `bytes_per_line` kwarg already existed at the emitter).

### Key implementation seams (for maintainers)

- **Workspace hex row** — `s19_app/tui/styles.tcss:381` (`#hex_view { width: auto }`); horizontal scroll from `s19_app/tui/styles.tcss:370` (`#hex_scroll { overflow: auto }`).
- **CRC width selector + carry** — `s19_app/tui/screens.py:672` (`ConfirmWriteResult` dataclass, `bytes_per_line: int = 32`); `:689` (`ConfirmWriteScreen`); width cycle at `:759`; dismiss with width at `:770`/`:774`; consumed at `_on_confirm_write` `:1370`; threaded via `_run_crc_write_worker` `:1432`.
- **CRC width to disk** — `s19_app/tui/operations/crc.py:790` (`write_crc_image`, kwarg at `:796`); emit at `:884` (`emit_s19_from_mem_map(working_mem, working_ranges, bytes_per_line=bytes_per_line)`).
- **Issues hex pane** — `s19_app/tui/app.py:1128` (`_compose_screen_issues` builds `#issues_hex_pane`, declared `:1143`); render/placeholder at `_update_issues_hex_pane` `:4784`; called from `_jump_to_validation_issue_object` `:4859`; row-select entry `on_data_table_row_selected` `:4408` → `_jump_to_validation_issue_by_index` `:4761`.
- **Issues Related cell** — `s19_app/tui/app.py:475` (`precompute_issue_datatable_payload`); Related cell built at `:509` (`related = ", ".join(issue.related_artifacts) if issue.related_artifacts else "-"`), placed at column index 3 of the 8-tuple (`:511-519`).

### Usage / examples

```bash
# Launch the TUI (optionally pre-load a file)
s19tui
s19tui --load examples/case_00_public/prg.s19

# Workspace: open a file; the hex column shows a full 16-byte + ASCII row on one line.
#   On a narrow terminal, scroll the hex pane horizontally to reach the rest.

# CRC write width: run "Write CRC image"; the confirm dialog shows a
#   "Width: 32 bytes/line" button. Click it to cycle to 16, then Confirm.
#   The written .s19 (under .s19tool/workarea/crc/) uses the chosen width.

# Issues screen: select an issue row.
#   - If the issue has an address, the hex pane shows the bytes at that address.
#   - If not, the pane shows "(issue has no address — nothing to show)".
#   The Related column shows each issue's related artifacts (e.g. "a2l, mac"), or "-".
```

### Diagrams

- `06-docs/diagrams/batch-17-flows.md` — (1) CRC width threading chain; (2) Issues row-select → hex pane flow.

### Evidence checklist — docs-writer

- [x] **Audience + purpose declared** — "Audience: technical stakeholder (operator + maintainer)"; purpose = describe the 4 shipped behaviors + maintainer seams (top of doc).
- [x] **Structure follows the template** — mirrors `~/.claude/templates/dev-flow/functionality-template.md` (At a glance → Detail → How it works → Components → Usage → Diagrams → Evidence).
- [x] **Code/CLI snippets** — `s19tui` invocations are the documented entry points (`CLAUDE.md` Common commands); behavior steps describe the shipped UI, not re-run here (Phase 4 already validated; this doc does not re-run tests per task scope).
- [x] **Assumptions listed** — a file is loaded for the Workspace hex row; issues carry `address` / `related_artifacts` from `ValidationIssue` (existing fields, no new validation logic).
- [x] **Risks / limitations** — G-1 snapshot baseline regeneration (CI-only); CRC S0-header synthesis remains out of scope (US-019); US-020c/d deferred.
- [x] **Next steps stated** — sync to Obsidian after PR merge; regenerate SVG baselines in canonical CI; US-020c/d own batch + design spike.
- [x] **Diagrams included** — flow is non-trivial for the CRC threading chain + issues row-select; both in `06-docs/diagrams/batch-17-flows.md`.
- [x] **No invented APIs / versions / metrics** — every symbol + file:line grep-verified against the shipped tree; ledger 883→892 and node names taken from `04-validation.md`.
