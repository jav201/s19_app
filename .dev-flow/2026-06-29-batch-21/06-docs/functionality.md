# Functionality — s19_app TUI — Batch 2026-06-29-batch-21

> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder / maintainer.
> Feature #8 (patch-editor overhaul), **slice 1**: change-file management + Checks clarity.

## 🔑 At a glance (read first)

- **What this batch added:** the patch editor now **saves change documents into a dedicated `patches/` folder** and **lists them in a dropdown** so a previously-saved change file can be reopened without retyping a path; the **Checks button gained a one-line description** of what it does.
- **Capabilities:**
  - Save a change document → it lands in `.s19tool/workarea/patches/` (US-027).
  - Reopen the patch editor → pick a saved change file from `Select#patch_doc_file_select` → it loads (US-026).
  - The Checks control now reads: *"Checks: runs the loaded change document's checks against the loaded image."* (US-029).
- **How to use it:** launch `s19tui`, open the patch editor, and use the change-file **dropdown** at the top of the change-file row to load; **save** as before — the file is now placed in `patches/` automatically.

> Enough to know what shipped and how to reach it. Detail below.

---

## Detail (reference)

### How it works (flow)

**Producer → consumer, one round-trip (the C-12 chain):**

1. **Save (US-027, producer).** When the operator saves a change document, `write_change_document` (`changes/io.py:1354`) now resolves its write target under `workarea/patches/` — a dedicated global folder, no longer the workarea root. `temp/` remains staging-only. The folder is guaranteed to exist because `ensure_workarea` creates it (`workspace.py:47-48`) using the new `WORKAREA_PATCHES="patches"` constant (`workspace.py:19`).
2. **Scan (US-026, consumer).** The patch screen scans `patches/` via `_scan_patch_change_files` (`app.py:2217-2240`), returning a **sorted** set of `.json` change files while **ignoring non-change files and skipping symlinks** (see Security below). The scan runs on patch-screen activation and again after each save (`_prefill_patch_change_files`, `app.py:1428-1431`) so a file saved while the screen is open appears without re-activation.
3. **Populate.** `set_change_files` (`screens_directionb.py:549`, `:587`) feeds the scanned set into `Select#patch_doc_file_select` (`screens_directionb.py:649`). An empty `patches/` renders a placeholder — no crash.
4. **Select → load.** Choosing an entry fires the `Select.Changed` handler (`screens_directionb.py:889`), which loads the change document through `ChangeService.load`, with the read-path containment guard applied first (`app.py:2315-2322`).

**Checks clarity (US-029, independent).** A static description Label `#patch_checks_help` (`screens_directionb.py:665-670`, styled at `styles.tcss:680-685`) sits under the Checks button and states *what* the button does and *which* artifact it acts on. The button id (`patch_checks_run_button`, `:662`) and its `run_checks` action (`:856`) are **unchanged** — this slice adds explanatory text only, no behavior change.

### Security property — read-path containment guard (F1)

The `patches/` scan and load are hardened against path-escape:

- **At scan:** symlink entries are skipped (`_scan_patch_change_files`, `app.py:2217-2240`) — a symlink pointing outside `patches/` never enters the dropdown. Covered by the adversarial node **F1** (`test_f1_symlink_entry_is_skipped_by_scan`).
- **At load:** the selected path is checked with `is_relative_to(patches/)` before `ChangeService.load` (`app.py:2315-2322`) — a resolved path that escapes the folder is rejected.

This means a directly-dropped, legitimate change file is listed and loadable (**AT-030c**, consumer guard), while a symlink-based escape is not.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/workspace.py` | New `WORKAREA_PATCHES` const (:19); `ensure_workarea` creates `patches/` (:47-48) |
| `s19_app/tui/changes/io.py` | `write_change_document` routes saves to `workarea/patches/` (:1354) |
| `s19_app/tui/screens_directionb.py` | `Select#patch_doc_file_select` (:649), `set_change_files` (:549/:587), `Select.Changed` handler (:889); Checks help Label `#patch_checks_help` (:665-670) |
| `s19_app/tui/app.py` | `_scan_patch_change_files` sorted+symlink-skip (:2217-2240); `_prefill_patch_change_files` post-save (:1428-1431); load handler + F1 containment (:2315-2322) |
| `s19_app/tui/styles.tcss` | `#patch_checks_help` Label CSS (:680-685) |
| `tests/test_tui_patch_editor_v2.py`, `tests/test_unified_write.py` | AT / TC / F1 nodes |

> Engine-frozen modules untouched (frozen-engine diff = 0): save-placement logic lives in `changes/io.py` (not `hexfile.py`), per the CLAUDE.md engine-frozen guard.

### Usage / examples

```bash
# Launch the TUI and open the patch editor
s19tui

# Inside the patch editor:
#  1. Save a change document  → it now lands in .s19tool/workarea/patches/
#  2. Reopen the patch editor  → the change-file dropdown lists it (sorted)
#  3. Select it                → it loads via ChangeService.load
#  4. Read the label under Checks:
#     "Checks: runs the loaded change document's checks against the loaded image."
```

On-disk layout after a save:

```
.s19tool/workarea/
├── temp/                     # transient loads (staging only)
└── patches/                  # NEW — dedicated change-document saves
    └── <change-document>.json
```

### Deferred (out of this slice — BACKLOG, not gaps)

- **US-028** — change-file delete / rename from the dropdown.
- **US-030**, **US-031** — remaining patch-editor slice-1 follow-ons.

These are logged as future patch-editor slices; they are intentionally out of scope and are **not** coverage gaps.

### Diagrams

- `06-docs/diagrams/batch-21-flows.md` — (a) save → `patches/` → dropdown-scan → select → load sequence (US-027 producer → US-026 consumer, the C-12 chain); (b) component/data view of the patch-editor change-file row.

### Evidence checklist — docs-writer

| Item | ✓/✗ | Evidence |
|------|-----|----------|
| Audience + purpose declared at top | ✓ | Header: technical stakeholder / maintainer, feature #8 slice 1 |
| Structure follows template | ✓ | `~/.claude/templates/dev-flow/functionality-template.md` (At a glance → Detail → modules → usage → diagrams) |
| Code/CLI snippets actually run | ✓ | `s19tui` is a real console entry point (`pyproject.toml`); on-disk layout verified via `workspace.py:19,47-48` |
| Assumptions listed | ✓ | Producer→consumer round-trip is the design; `temp/` staging-only; behavior of Checks unchanged |
| Risks / limitations called out | ✓ | Security §F1 (symlink/path-escape) + Deferred §(US-028/030/031) |
| Next steps stated | ✓ | Deferred BACKLOG stories named |
| Diagrams included where flow non-trivial | ✓ | `diagrams/batch-21-flows.md` (sequence + component) |
| No invented APIs / versions / metrics | ✓ | Every file:line and node name taken from the verified final tree; seams cross-checked (`workspace.py:19,47-48` read) |
