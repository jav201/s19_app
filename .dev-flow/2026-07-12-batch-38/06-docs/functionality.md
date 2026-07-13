# Functionality — s19_app — Batch 2026-07-12-batch-38

> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder. Language: English (`state.json.language = en`).

## 🔑 At a glance (read first)

- **What this batch added:** Five Patch-Editor / validation quality-of-life improvements — the last four P3 backlog items (B-16..B-19) — shipping clearer change-set labels, a defensive over-32-bit A2L address warning, a variant-selector help modal, and change-set undo/redo plus a per-entry JSON editor. All five stay on the TUI side; the engine-frozen set is untouched (0 frozen diffs vs `main`).
- **Capabilities:**
  - Change-document field copy that reads as an *alternative to the dropdown* (US-065) · Defensive **WARNING** naming any A2L tag whose address exceeds `0xFFFFFFFF` (US-066) · Variant-selector **"?" info modal** (US-067) · **Undo/Redo** for change-set edits (US-068a) · **Per-entry JSON edit popup** (US-068b).
- **How to reach it:** all five surface inside the **Patch Editor** (`s19tui`, patch-editor panel) except the A2L warning, which appears on the **validation Issues panel** (`GroupedIssuesPanel`) after loading an A2L.

> Term note: an **A2L** is the ASAM calibration-description file that names memory tags and their addresses. A **change-set / change document** is the JSON list of patch entries the Patch Editor applies to an S19/HEX image.

---

## Detail (reference)

### US-065 — Change-set free-path label clarity (R-TUI-054)

- **What it does:** Removes the misleading "v2 file" framing from the Patch Editor's change-document controls. The user was reading the free-path input as pointing at a *second, different* file; the copy now says it is another way to point at the **same** change-set.
- **Surface:** `PatchEditorPanel` (`screens_directionb.py`).
  - Entries-pane section title (`:1854`): now **`"Change document (JSON)"`** (was `"Change document (v2 JSON)"`).
  - Free-path input `#patch_doc_path_input` placeholder (`:1904`): now **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`** (was `"path to v2 change-set .json"`). It sits directly under the `patches/` dropdown `#patch_doc_file_select`.
- **How to use it:** open the Patch Editor — the wording is static, no interaction needed. The dropdown remains the primary selector; the input is the manual-path alternative for the same file.
- **Note:** copy-only change; no widget id or CSS class churn (only the `:1854` instance of `patch-section-title` was touched).

### US-066 — Defensive WARNING for A2L addresses > 0xFFFFFFFF (R-TUI-055)

- **What it does:** When an A2L tag carries an address larger than 32 bits (`> 0xFFFFFFFF`), the validation Issues panel now shows a **WARNING** that names the offending tag. This turns a previously-unreproducible "two extra characters" symptom into a diagnosable condition, and a hostile/oversized address never crashes the app or leaks markup.
- **Surface:** produced **TUI-side** (the engine-frozen `validation/` package is not edited) in `validation_service.build_validation_report`, rendered on `GroupedIssuesPanel` under the WARNING group.
  - New producer `supplemental_a2l_oversized_address_issues` (`validation_service.py:111`) — sibling of `supplemental_a2l_row_issues`.
  - Issue: `ValidationIssue(code="A2L_ADDRESS_EXCEEDS_32BIT", severity=WARNING, artifact="a2l", symbol=<tag name>, address=<addr>)` (`:179`).
  - Merged into **both** report branches (MAC-only + primary-backed) before `dedupe_issues`, so it appears regardless of session kind. Colour flows through the existing `css_class_for_severity` → `sev-warning`.
- **Behaviour boundaries:**
  - `0xFFFFFFFF` (32-bit max) → **no** warning (boundary is exclusive).
  - `0x100000000` and above → **one** warning per oversized tag.
  - `None` / non-int address → no warning.
  - A tag name carrying Rich-markup metacharacters (`[red]evil[/red]`, `[link=…]`) renders **verbatim** (no style applied); an ANSI-escape payload is neutralized/stripped. No `MarkupError`. This reuses the existing markup-safe `issues_view.py` `safe_text` render path (C-17); no new render code.
- **How to use it:** load an A2L; if any tag address exceeds 32 bits, the WARNING appears on the Issues panel naming that tag.

### US-067 — Variant-selector info/help popup (R-TUI-056)

- **What it does:** Adds a **"?" info button** beside the firmware-variant selector. Pressing it opens a modal that explains what the selector does — it picks which firmware image loads, and it appears when at least two images exist in the project directory.
- **Surface:**
  - Info button `#patch_variant_info_button` (`screens_directionb.py:2098`), nested in a new `Horizontal(#patch_variant_select_row)` inside `#patch_variant_row` (deliberately placed so the existing `#patch_pane_variant` child-order census is unperturbed — C-26).
  - Pressing it posts `PatchEditorPanel.VariantHelpRequested`, handled by `S19TuiApp` which does `push_screen(VariantHelpScreen())`.
  - Help modal `VariantHelpScreen` (`screens.py:355`) — static, markup-free help text plus a close control; reuses the shared `.modal-dialog` CSS. Geometry pilot-measured to fit 80×24 and 120×30 (C-23).
- **How to use it:** with ≥2 firmware images in the project directory, the variant selector and its "?" button render; click "?" to open the help modal, dismiss to return.
- **Note:** the info button is always rendered whenever the variant selector renders (the selector itself already requires ≥2 images).

### US-068a — Patch-editor change-set undo/redo (R-TUI-057)

- **What it does:** Adds **Undo** and **Redo** to the Patch Editor. After a change-set edit (add / edit / remove / paste-load), Undo restores the immediately-prior change-set and Redo re-applies it, up to a bounded history depth.
- **Surface:**
  - `Undo` / `Redo` buttons (`#patch_undo_button` / `#patch_redo_button`, `screens_directionb.py:1981-1982`) in a **new** `#patch_history_controls` row (kept out of the census-pinned `#patch_doc_controls` row on purpose).
  - Backed by `ChangeService.undo()` (`change_service.py:445`) / `redo()` (`:474`). Each document-mutating operation (`add_entry`, `edit_entry`, `remove_entry`, `load`, `load_text`, per-entry edit) first pushes a **deep-copy** snapshot onto a bounded undo stack (`_HISTORY_MAX = 20`, `:92`); a fresh mutation clears the redo stack; the oldest snapshot is evicted past the bound.
  - Buttons post messages the app handles by calling `undo`/`redo` and re-rendering the entries table via the existing `PatchEditorPanel.refresh_entries`.
- **Behaviour boundaries:**
  - Empty history → Undo/Redo is a **no-op** (returns the document unchanged).
  - Each snapshot is a true deep copy — mutating the live document never aliases a stored snapshot.
  - **A-01 data-loss guard:** when a change *file* is loaded (`document.source_path is not None`), Undo/Redo are **DISABLED** (`set_undo_redo_enabled`, `screens_directionb.py:2607`) so a file-backed document is never clobbered; a paste-authored document (`source_path is None`) has them enabled.
- **How to use it:** in the Patch Editor, edit the change-set (add/edit/remove/paste), then click Undo to step back and Redo to step forward. (Discoverability is below-fold; a `ctrl+z`/`ctrl+y` binding is a batch-39 polish carry.)

### US-068b — Per-entry JSON edit popup (R-TUI-058)

- **What it does:** Lets the user edit **one** change-set entry's JSON in a popup, scoped to the row selected in the entries table. Distinct from batch-37's *whole-set* JSON popup. Confirming an edit changes only that entry; malformed JSON is rejected without touching any other entry and without crashing.
- **Surface:**
  - Per-entry control `#patch_entry_edit_json_button` (`screens_directionb.py:1971`), joined to `#patch_doc_entry_buttons`; targets the row selected in `#patch_doc_entries_table` (`cursor_type="row"`). Distinct from the whole-set `#patch_edit_json_button` and the field-based `#patch_entry_edit_button`.
  - Modal `EntryJsonScreen` (`screens.py:255`) — mirrors `ChangeSetJsonScreen` but seeded with a **single** entry's JSON (its own `#entry_json_text` TextArea).
  - On Confirm, `S19TuiApp` routes the edited text to `ChangeService.edit_entry_json(index, text)` (`change_service.py:738`), which splices the entry into a one-entry envelope and parses it through the **existing validated** `parse_change_document` seam — the same collect-don't-abort path `load_text` uses — then replaces only `entries[index]`. A successful edit is history-eligible (snapshots first, per US-068a).
- **Behaviour boundaries:**
  - First / middle / last selected row all scope correctly — only the selected index changes; sibling entries stay byte-identical.
  - Malformed JSON on Confirm surfaces a collect-don't-abort finding (`MF-JSON-PARSE`), no crash, no mutation of other entries.
  - No selected entry → the control is a no-op.
  - **A-01 data-loss guard:** disabled when `source_path is not None` (`set_entry_edit_json_enabled`, `screens_directionb.py:2633`); enabled for paste-authored documents.
  - By-design note: a per-entry edit can introduce a cross-entry address collision; the per-entry parse validates byte-validity only, and the collision is re-detected at the document Validate/Apply/Save gate (never silently written).
- **How to use it:** open the Patch Editor with a paste-authored change-set of ≥2 entries, select an entry row, click **Edit JSON** (per-entry), edit the single-entry JSON, Confirm.

### How it works (flow)

1. **US-065** is static compose-time copy on `PatchEditorPanel`.
2. **US-066:** A2L load → `build_validation_report` runs `supplemental_a2l_oversized_address_issues` over the effective tags → oversized tags become WARNING `ValidationIssue`s merged into `ValidationReport.issues` → `update_validation_issues_view` → `GroupedIssuesPanel` renders each via markup-safe `safe_text`.
3. **US-067:** `pilot`/user click on `#patch_variant_info_button` → `PatchEditorPanel.VariantHelpRequested` → app `push_screen(VariantHelpScreen())`.
4. **US-068a:** any mutating `ChangeService` op → `_push_history` deep-copy snapshot → Undo/Redo buttons → app handler → `undo()`/`redo()` swaps the document between undo/redo stacks → `refresh_entries` re-renders the table.
5. **US-068b:** select row → `#patch_entry_edit_json_button` → `EntryJsonScreen(seed)` → Confirm → `edit_entry_json(index, text)` via `parse_change_document` → replace `entries[index]` → `refresh_entries`.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/screens_directionb.py` | Change-doc copy (US-065); info button + help message (US-067); Undo/Redo buttons + per-entry control + A-01 enable-state helpers (US-068a/b) |
| `s19_app/tui/services/validation_service.py` | New oversized-address WARNING producer + merge into both report branches (US-066) |
| `s19_app/tui/services/change_service.py` | Bounded deep-copy undo/redo history + `undo`/`redo` + `edit_entry_json` (US-068a/b) |
| `s19_app/tui/screens.py` | `VariantHelpScreen` (US-067) and `EntryJsonScreen` (US-068b) modals |
| `s19_app/tui/app.py` | Handlers/push for the variant help modal, undo/redo, and per-entry JSON edit (US-067/068a/068b) |
| `s19_app/tui/issues_view.py` | Reused, unchanged — markup-safe `safe_text` render path for the US-066 WARNING |

> Engine-frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) is **untouched** — 0 frozen SOURCE + 0 frozen TEST diffs vs `main`.

### Usage / examples

```bash
# Launch the TUI and open the Patch Editor to reach US-065 / US-067 / US-068a / US-068b
s19tui

# US-066: load any A2L; if a tag address exceeds 0xFFFFFFFF the WARNING
# "A2L_ADDRESS_EXCEEDS_32BIT" naming that tag appears on the Issues panel.
```

### Diagrams

See `06-docs/diagrams/`:
- `us066-oversized-warning-sequence.md` — A2L load → `validation_service` → `GroupedIssuesPanel` WARNING flow.
- `us068a-undo-redo-sequence.md` — edit → push snapshot → undo → restore.
- `us068b-per-entry-popup-sequence.md` — select row → `EntryJsonScreen` → `edit_entry_json` → refresh.

### Evidence checklist — docs-writer

- [✓] Audience & purpose declared at top (technical stakeholder; understand what shipped + how to reach it) — At-a-glance section.
- [✓] Structure follows the Phase-6 functionality template — At-a-glance + Detail (flow / modules / usage / diagrams).
- [✓] Code/CLI snippets run — `s19tui` is the shipped entry point (`pyproject.toml`); symbol/line citations verified against the working tree (grep, this session).
- [✓] Assumptions listed — variant selector requires ≥2 images (US-067); A-01 guard predicate `source_path is not None` (US-068a/b).
- [✓] Risks / limitations called out — undo/redo discoverability below-fold, uncapped native paste on `#entry_json_text` (batch-39 carry), cross-entry collision by-design (US-068b).
- [✓] Next steps stated — batch-39 carries in the traceability-matrix §3 non-gating notes + post-mortem open items.
- [✓] Diagrams included where flow is non-trivial — 3 Mermaid sequences for the two data-flow-bearing stories + per-entry popup.
- [✓] No invented APIs / version numbers / metrics — every symbol (`supplemental_a2l_oversized_address_issues`, `A2L_ADDRESS_EXCEEDS_32BIT`, `_HISTORY_MAX=20`, `VariantHelpScreen`, `EntryJsonScreen`, button ids) grep-confirmed in source.
