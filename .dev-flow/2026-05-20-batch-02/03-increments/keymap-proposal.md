# Keymap Proposal — Direction B — s19_app — batch-02-direction-b-restyle

**Phase:** 3 — Implementation, increment 1 deliverable
**Status:** PROPOSAL — requires owner sign-off before increments 2-4 wire bindings against it
**Date:** 2026-05-20
**Closes:** OQ-8 (final Direction B keymap deferred to Phase 3 increment 1)
**Unblocks:** TC-030 (status bar shows the active screen's `show=True` bindings) — the per-screen `show=True` set below is TC-030's expected column

---

## 1. Purpose and scope

OQ-8 deferred the final Direction B keybinding map to this increment. This document pins:

1. the **global binding set** — active on every Direction B screen;
2. the **per-screen `show=True` footer set** for each of the 8 rail screens, which is what the footer/status bar displays (TC-030).

This is a **design artifact, not code.** No binding is wired in increment 1. Increments 2-4 implement these bindings (`app.py BINDINGS`, the routing actions, the per-screen footer set). The keymap is held to the constraints already in the contract:

- **C-9 — keyboard reachability:** every action reachable by mouse is reachable by keyboard.
- **A-02 / A-07:** the pre-batch `1`/`2`/`3` view-toggle and the `#view_bar` button bar are **superseded** by rail items 1/2/3; this is intended supersession, not a regression (LLR-004.4, TC-011).
- **LLR-004.5 (Q-05 / A-07):** while a command-bar `Input` holds focus, **all unmodified single-key bindings** are suppressed (routed as text into the input); **modified-key bindings stay live.**

### 1.1 Pre-batch `BINDINGS` baseline (for traceability)

The pre-batch `S19TuiApp.BINDINGS` (app.py) is the supersession baseline TC-011 checks against:

| Key | Action | Disposition in Direction B |
|-----|--------|----------------------------|
| `l` | `load_file` | kept (global) |
| `r` | `refresh_files` | kept (global) |
| `o` | `open_workarea` | kept (global) |
| `s` | `save_project` | kept (global) |
| `p` | `load_project` | kept (global) |
| `j` | `dump_a2l_json` | kept (global) |
| `1` | `view_main` | **superseded** → rail item 1 (Workspace) |
| `2` | `view_alt` | **superseded** → rail item 2 (A2L Explorer) |
| `3` | `view_mac` | **superseded** → rail item 3 (MAC View) |
| `q` | `quit` | kept (global) |
| `+` | `page_next_context` | kept (per-screen, paging) |
| `-` | `page_prev_context` | kept (per-screen, paging) |
| `comma` | `hex_page_prev` | kept (per-screen, paging) |
| `period` | `hex_page_next` | kept (per-screen, paging) |

No pre-batch action loses a key path. The `1`/`2`/`3` keys change meaning (view-toggle → rail activation) but the underlying Workspace / A2L / MAC screens stay reachable on those same keys plus the command palette.

---

## 2. Global bindings — active on every Direction B screen

These are mounted on `S19TuiApp` and apply regardless of the active rail screen. `show` indicates whether the binding is surfaced in the footer/status bar.

| Key | Action id | Description | `show` | Notes |
|-----|-----------|-------------|--------|-------|
| `ctrl+k` | `focus_palette` | Open / focus the command palette | `True` | modified key — stays live during input focus (A-07) |
| `ctrl+d` | `cycle_density` | Cycle density compact ↔ comfortable | `True` | modified key — stays live during input focus (A-07) |
| `ctrl+l` | `load_file` | Load file | `True` | modified-key alias of legacy `l` (palette + footer discoverability) |
| `ctrl+s` | `save_project` | Save project | `True` | modified-key alias of legacy `s` |
| `/` | `focus_find` | Focus the find input | `True` | unmodified — suppressed while a command-bar input has focus |
| `g` | `focus_goto` | Focus the go-to-address input | `True` | unmodified — suppressed while a command-bar input has focus |
| `1`–`8` | `show_screen(<n>)` | Activate rail screen 1–8 | `False` | unmodified — suppressed during input focus; shown on the rail, not the footer |
| `q` | `quit` | Quit | `True` | unmodified — suppressed during input focus |
| `l` | `load_file` | Load file | `False` | legacy single-key; kept reachable, not footer-shown (superseded in footer by `ctrl+l`) |
| `r` | `refresh_files` | Refresh workarea | `False` | legacy single-key; kept reachable |
| `o` | `open_workarea` | Open workarea | `False` | legacy single-key; kept reachable |
| `s` | `save_project` | Save project | `False` | legacy single-key; kept reachable (footer shows `ctrl+s`) |
| `p` | `load_project` | Load project | `False` | legacy single-key; kept reachable |
| `j` | `dump_a2l_json` | Dump A2L JSON | `False` | legacy single-key; kept reachable; also a palette entry |

**Rationale for the `ctrl+*` aliases:** Direction B surfaces the high-traffic actions (load, save) on modified keys so they (a) appear in the footer without crowding it with 14 single-key chips and (b) remain operable while a command-bar input is focused (the legacy unmodified `l`/`s` are suppressed during input focus by LLR-004.5). The legacy single keys are retained for muscle memory and keyboard reachability (TC-011) but are `show=False`.

**Footer global set (always shown):** `ctrl+k` · `ctrl+d` · `ctrl+l` · `ctrl+s` · `/` · `g` · `q`.

---

## 3. Per-screen `show=True` footer binding set

Each rail screen contributes its own bindings on top of the global footer set. The footer for a screen = **global footer set + that screen's per-screen `show=True` set**. The per-screen sets below are TC-030's expected column.

The 8 rail screens (rail order, keys `1`–`8`): Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Bookmarks.

### 3.1 Screen 1 — Workspace (key `1`)

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| `period` | `hex_page_next` | Hex + | `True` |
| `comma` | `hex_page_prev` | Hex − | `True` |
| `plus` | `page_next_context` | Page + | `True` |
| `minus` | `page_prev_context` | Page − | `True` |

### 3.2 Screen 2 — A2L Explorer (key `2`)

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| `period` | `a2l_tags_page_next` | A2L page + | `True` |
| `comma` | `a2l_tags_page_prev` | A2L page − | `True` |
| `plus` | `page_next_context` | Hex page + | `True` |
| `minus` | `page_prev_context` | Hex page − | `True` |

### 3.3 Screen 3 — MAC View (key `3`)

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| `period` | `mac_records_page_next` | MAC page + | `True` |
| `comma` | `mac_records_page_prev` | MAC page − | `True` |
| `plus` | `page_next_context` | Hex page + | `True` |
| `minus` | `page_prev_context` | Hex page − | `True` |

### 3.4 Screen 4 — Memory Map (key `4`)

New scaffold (increment 9). No paging or screen-specific actions this batch — the Memory Map is a read-only coverage visualization.

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| — | — | (no per-screen bindings — global footer set only) | — |

### 3.5 Screen 5 — Issues Report (key `5`)

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| `period` | `validation_issues_page_next` | Issues page + | `True` |
| `comma` | `validation_issues_page_prev` | Issues page − | `True` |

### 3.6 Screen 6 — Patch Editor (key `6`)

New scaffold (increment 10). Inputs are inert (LLR-012.2); no patch-apply binding is wired.

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| — | — | (no per-screen bindings — global footer set only; inputs inert) | — |

### 3.7 Screen 7 — A↔B Diff (key `7`)

New scaffold (increment 10). Static placeholder (LLR-012.3); no diff-compute binding is wired.

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| — | — | (no per-screen bindings — global footer set only; static placeholder) | — |

### 3.8 Screen 8 — Bookmarks (key `8`)

Placeholder screen (LLR-002.2). No persistence binding is wired.

| Key | Action id | Description | `show` |
|-----|-----------|-------------|--------|
| — | — | (no per-screen bindings — global footer set only; placeholder) | — |

---

## 4. Input-focus suppression rule (LLR-004.5 — restated for the implementer)

While a command-bar `Input` (find or go-to) holds focus:

- **suppressed (routed as text into the input):** every unmodified single key — `/`, `g`, `1`–`8`, `q`, `l`, `r`, `o`, `s`, `p`, `j`, `+`, `-`, `,`, `.`;
- **stays live:** every modified-key binding — `ctrl+k`, `ctrl+d`, `ctrl+l`, `ctrl+s`.

This is implemented in increment 4 (`app.py` key handler checks `isinstance(self.focused, Input)` and the input identity). TC-008 / TC-009 / TC-029 verify both directions.

---

## 5. Open points for owner sign-off

1. **`ctrl+l` / `ctrl+s` aliases** — added so load/save survive input-focus suppression and are footer-discoverable. Confirm this is wanted, or keep load/save footer-shown on the legacy unmodified `l`/`s` only.
2. **`q` quit during input focus** — proposed suppressed (typing `q` into find should insert `q`, not quit). Confirm.
3. **Memory Map / Patch Editor / A↔B Diff / Bookmarks** carry no per-screen bindings this batch (scaffolds / placeholder). Their footers show only the global set. Confirm acceptable for TC-030.

Once signed off, this keymap is the contract for increments 2-4 and the TC-030 expected column.
