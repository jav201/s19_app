# Functionality — s19_app — Batch 2026-06-29-batch-20

> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder.
> Artifact language: English.

## 🔑 At a glance (read first)

- **What this batch added:** the operator's declared memory regions now **survive a project save/reload** and the Reports dialog warns when region lines are mistyped. This wires batch-19's region serialization layer to the actual UI (closing the deferred D-1 and D-2 items).
- **Capabilities:**
  - **D-1 (round-trip):** declare regions in the Reports dialog → Generate → Save the project → reopen later → the regions are restored, pre-filled in the dialog.
  - **D-2 (skip notice):** mistyped or invalid region lines produce a single count-only toast ("`N region line(s) skipped`"); blank lines are ignored, not counted.
- **How to use it:** rail → Issues Report (Reports dialog), type `name,start,end` lines in **Declared regions**, press **Generate**, then **Save project**. On the next project Load the same lines reappear.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

### What the operator does (walkthrough)

**Round-trip (D-1):**
1. Open the Reports dialog and type one region per line in the **Declared regions** field, format `name,start,end` — `start`/`end` accept `0x`-hex or decimal (e.g. `calib_table,0x80040000,0x80040040`).
2. Press **Generate new report**. At that moment the regions are *captured* into app state (capture-on-Generate). A region typed but never Generated is intentionally **not** captured.
3. **Save the project.** The captured regions are written into `project.json` under an optional `declared_regions` array. If there are no regions, the key is omitted and the saved file is byte-identical to a pre-batch-20 save (back-compat).
4. Later, **Load the project.** The saved regions are read back into app state and, when the Reports dialog is reopened, its **Declared regions** field is pre-filled with the same lines.
5. Loading a **legacy / no-region project** clears the field — a previous project's regions never leak into the newly loaded one.

**Skip notice (D-2):**
- If any region line is malformed (wrong field count) or invalid (a field won't parse, or the `DeclaredRegion` constructor rejects it), Generate still succeeds with the good lines and shows one toast: `N region line(s) skipped`.
- The toast is **count-only** by design — it never echoes the offending line text (that text would render pre-scrub).
- **Blank / whitespace-only** lines are treated as intentional spacing and are excluded from the count.
- All-valid input shows no notice at all.

### How it works (flow)

The feature is pure UI wiring around batch-19's frozen serialization layer; no new persistence or validation logic was added to the engine.

- **Capture:** `GenerateRequested` handler stores `tuple(message.declared_regions)` into `self._declared_regions` (the single source of truth).
- **Save:** `_handle_save_dialog` → `_write_and_verify_manifest` threads `self._declared_regions` into `write_project_manifest(declared_regions=...)`. The verify leg is deliberately not threaded (it re-reads from disk).
- **Persist:** the reused `serialize_manifest` writes the array only when non-empty.
- **Load:** `_handle_load_project` adopts `manifest.declared_regions` into `self._declared_regions`, with an `else ()` reset for no-manifest/no-key projects.
- **Seed:** `action_view_reports` passes the state to `ReportViewerScreen`, whose `compose` renders the lines back into the `#report_declared_regions` TextArea — the seed format is the exact inverse of the parser.
- **Skip count:** `_parse_declared_regions` returns `(regions, skipped)`; `on_button_pressed` raises a count-only notify only when `skipped >= 1`.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/app.py` | App-state field `self._declared_regions`; capture-on-Generate; thread to save; adopt on load; pass seed to the dialog. |
| `s19_app/tui/screens.py` | `_parse_declared_regions` returns a skip count; `ReportViewerScreen` accepts + seeds regions; count-only notify with zero-suppression. |
| `tests/test_tui_report_seam.py` | All 7 TC + 9 AT nodes; plus the rewritten batch-19 `TC-024.5`. |
| `report_addendum.DeclaredRegion` | **Reused read-only** (batch-19) — name scrub at `__post_init__`. |
| `manifest_writer.write_project_manifest` / `serialize_manifest` | **Reused read-only** (batch-19) — writes the array, omits the key when empty. |
| `variant_execution_service.read_project_manifest` → `ProjectManifest.declared_regions` | **Reused read-only** (batch-19) — reads regions back. |

### Maintainer seams (file:line, final tree)

- **App state:** `app.py:713` (init `self._declared_regions: Tuple[DeclaredRegion, ...] = ()`), captured `app.py:1899`/`:1908` (`GenerateRequested` handler).
- **Save path:** `_handle_save_dialog` `app.py:3791` → `_write_and_verify_manifest` `app.py:3802` (param) → `app.py:3867` `write_project_manifest(declared_regions=...)` (verify leg NOT threaded).
- **Load path:** `_handle_load_project` `app.py:3977` (adopt `manifest.declared_regions`, `else ()` reset — no cross-load leak) → `action_view_reports` `app.py:1874` → `ReportViewerScreen.__init__` `screens.py:667` → `compose` seed `screens.py:691`–`698` / `:703`–`708`.
- **Skip count (D-2):** `_parse_declared_regions` `screens.py:543` (returns `(regions, skipped)`, two mutually-exclusive count sites, blank excluded) → `on_button_pressed` `screens.py:804` / `:807`–`813` (count-only notify, zero-suppression).

### Security property

- **Region names are scrubbed on both ends.** Region names are operator free text that reach the Markdown report and `project.json`. The `DeclaredRegion` constructor scrubs + length-caps the name via `validation.model._scrub_issue_message` at construction (write path), and the batch-19 reader re-scrubs each name on read. This batch adds no new sink that bypasses that defense.
- **The skip notice is count-only.** The D-2 toast never interpolates the offending line text, so unscrubbed operator input is never echoed to the UI.

### Scoped-out edge

- **Comma in a region name:** the line format `name,start,end` is comma-delimited, so a name containing a comma is not representable and would be skipped as malformed. Deliberately out of scope — the construction-time scrub still neutralizes injection content regardless of how the line is parsed.

### Usage / example

In the Reports dialog **Declared regions** field:

```
calib_table,0x80040000,0x80040040
boot_vector,524288,524800
```

Generate → Save. Reopen the project and the dialog shows the same two lines. A line like `oops,0x10` (only two fields) yields the toast `1 region line(s) skipped` and is dropped; the two valid lines still apply.

### Diagrams

- `06-docs/diagrams/batch-20-flows.md` — (a) D-1 round-trip sequence; (b) D-2 skip-count flow.

### Evidence checklist — docs-writer

- [✓] Audience and purpose declared at top — "technical stakeholder", Phase-6 functionality.
- [✓] Structure follows the functionality template (At a glance → Detail → flow → modules → usage → diagrams → evidence).
- [✓] Code/CLI snippets run — region-line examples match `_parse_declared_regions` accepted grammar (`screens.py:543`); no invented commands.
- [✓] Assumptions listed — capture-on-Generate, `else ()` reset semantics stated explicitly.
- [✓] Risks / limitations called out — comma-in-name scoped out; count-only notice rationale (no pre-scrub echo).
- [✓] Next steps stated — none open for D-1/D-2; both batch-19 BACKLOG items closed.
- [✓] Diagrams included — round-trip + skip-count flows in `diagrams/batch-20-flows.md`.
- [✓] No invented APIs / version numbers / metrics — every file:line verified against the final tree; test names are the real on-disk nodes; ledger 958→974 / 942 passed from batch facts.
