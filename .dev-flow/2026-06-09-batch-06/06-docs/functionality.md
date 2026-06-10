# Functionality — s19_app — Batch 2026-06-09-batch-06

**Audience:** technical stakeholder (firmware/test engineer, tech lead). Not a code walkthrough.
**Purpose:** understand what changed for the user in the MAC View layout, why it matters, and the one deliberate tradeoff that was accepted.
**Scope:** TUI-only (`s19tui`), CSS-only. No parser, range-engine, validation-engine, or `app.py` behavior changed — the A2L Explorer layout is byte-identical to the previous build.

This batch closes one user story (US-001): the MAC View hex pane now uses the same proportional, responsive layout as the A2L Explorer, with a guarantee that a full hex row never truncates.

---

## The MAC hex pane now grows with the terminal

### What the user sees

- **Before (batch-05 model):** the MAC tab's embedded hex pane was pinned to a fixed 82 cells. That made a full hex row readable, but the pane never grew on wide terminals — side by side with the A2L Explorer (whose hex pane scales proportionally), MAC looked artificially narrow on a big screen. Below 120 columns a *separate* layout regime kicked in (hex pane at 35% of the body), so MAC had two different sizing behaviors depending on terminal width.
- **After (batch-06 model):** the MAC View mirrors the A2L Explorer's flat proportional split — records pane `4fr`, hex pane `3fr` (the hex pane takes 3/7 of the content width) — at **all** terminal widths, plus a `min-width: 82` floor on the hex pane. One regime, no breakpoint:
  - On wide terminals the hex pane grows proportionally, exactly like A2L.
  - When the proportional share would drop below a full hex row, the floor takes over and holds the pane at 82 cells, so the row (`> ` marker + address + 16 bytes + ASCII gutter) is always readable without wrapping or clipping.

### Width before → after at representative terminal sizes

`body_w` is the laid-out width of the workspace body (terminal minus the activity rail and borders: `term − 24` at ≥120 cols). Hex width = `max(82, round(3/7 · body_w))`.

| Terminal cols | body_w | Hex pane (before, fixed) | Hex pane (after, proportional+floor) | Records pane (after) |
|---|---|---|---|---|
| 120 | 96 | 82 | **82** (floor active) | 14 |
| 160 | 136 | 82 | **82** (floor active; 3/7·136 ≈ 58 < 82) | 54 |
| 250 | 226 | 82 | **97** (proportional active; round(3/7·226)) | 129 |

### The accepted tradeoff (operator-confirmed at the Phase-2 gate)

Because the activity rail consumes 24 columns at ≥120 cols, the proportional share `round(3/7·body_w)` only overtakes the 82-cell floor when `body_w ≥ 192` — i.e. terminals of roughly **216 columns or wider**. In practice:

- **120–215 columns:** the hex pane sits at the floor (82), identical in width to the old fixed model — and actually *wider* than A2L's hex pane at those sizes (A2L shows ~42 at 120 cols).
- **≥ ~216 columns:** proportional growth becomes visible and MAC scales just like A2L (validated at 250 cols: hex = 97).

The operator explicitly chose this over strict A2L parity, because strict parity would have *shrunk* the MAC hex pane to ~41 cells at 120 columns — regressing the very complaint that motivated the batch. The priority was "a full hex row is always readable"; visible growth on very wide terminals is the bonus, not the guarantee.

### What was removed

The two `width-narrow #mac_*` CSS rules (the sub-120-column 35% regime) were deleted. The `width-narrow` class itself still toggles at 120 columns, but it now drives **only** the workspace activity rail collapse — it has no effect on MAC pane sizing. Below the documented 120-column minimum the floor still holds the hex pane at 82 and the records pane clips gracefully (no crash); that region remains out of scope.

### How it works

The entire change is three CSS edits in `s19_app/tui/styles.tcss` (the screen composition in `app.py` was already structurally identical to A2L's and needed no change):

- `#mac_records_pane`: `width: 1fr` → `width: 4fr`
- `#mac_hex_pane`: `width: 82` → `width: 3fr; min-width: 82`
- Both `#workspace_body.width-narrow #mac_*` blocks deleted

Textual's layout solver honors `min-width` as a clamp over an `fr` width: when the `3fr` share computes below 82, the pane is widened to 82 and the records pane absorbs the difference. This clamp behavior was empirically verified by both Phase-2 reviewers before any code was written.

---

## Assumptions, risks, next steps

**Assumptions**
- A full hex row is 82 cells (carried from batch-05 arithmetic; `HEX_WIDTH = 16`).
- Documented minimum supported terminal width remains 120 columns.

**Risks / limitations**
- Proportional growth is only observable on ≥ ~216-column terminals (accepted tradeoff above). If the operator later reports MAC "still not growing", this is the documented floor behavior, not a regression.
- Validation ran locally on Python 3.14.4; CI on Python 3.11 is the authoritative gate, but `tui-ci.yml` only triggers on `main-tui` PRs — the trigger gap is a High-priority post-mortem action (A-3).
- No test exercises the ~216-column knee itself (LOW, accepted); batch-07 may add one parametrized width (post-mortem A-9).

**Next steps**
- Update the living `REQUIREMENTS.md` `R-TUI-039` row to the proportional+floor model and repoint its file/test pointers (post-mortem A-2).
- Add `main` to the CI workflow trigger branches (post-mortem A-3).
- After commit/push/merge, run `dev-flow-sync` to mirror `.dev-flow/` into the Obsidian vault.
