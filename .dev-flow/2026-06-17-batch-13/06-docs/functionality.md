# Functionality — s19_app — Batch 2026-06-17-batch-13

> **Audience:** technical stakeholder (firmware operator / reviewer who reads the TUI and the code).
> **Purpose:** describe, operationally, what shipped in batch-13 and how to use it.
> Owner: `docs-writer`. Validation verdict: **PASS** (`04-validation.md`).

## 🔑 At a glance (read first)

- **What this batch added:** two existing-substrate TUI ergonomics — load a CRC config from a file into the CRC surface, and paste a whole change-document into the Patch Editor. **No new engine math, no new write mechanism.**
- **Capabilities:** (1) CRC surface — type a `.json` config path + "Load config" → fills the editable config view · (2) Patch Editor (rail key 6) — a paste field pre-loaded with a dummy `s19app-changeset` reference + "Parse pasted" → entries load, then the EXISTING apply / verify / save-back path takes over.
- **How to reach it:** `s19tui` → CRC operation on the Operations screen; `s19tui` → Patch Editor via rail key `6`.

> Enough to know what shipped and how to reach it. Detail below for how it works and what is FAKE / safe.

---

## Feature 1 — Load CRC config from a file

**Goal:** run a CRC check against a real on-disk config without hand-copying it into the editor.

### Operator walkthrough
1. Launch the TUI (`s19tui`) and open the **CRC operation** on the Operations screen.
2. The CRC surface now shows a **config-path `Input`** and a **"Load config" `Button`**, next to the existing editable config view (`#operation_config` `TextArea`). They appear only while the CRC operation is highlighted (they hide on any non-CRC operation, same as the existing config view).
3. On first open, the config view is pre-loaded with `DUMMY_CONFIG_TEXT` — a FAKE-valued reference so you can see the expected shape.
4. Type (or point at) a `.json` config path and press **"Load config"**.
   - **On success:** the config view is replaced with the file's **raw text**. The check does NOT run automatically.
   - **On any fault** (empty path, unresolvable path, file over the size cap, unreadable): an **error surfaces** on the operations status surface, the config view is left **unchanged**, and **no CRC check runs** (collect-don't-abort).
   - **If you load nothing or hit an error:** the dummy reference stays in place.
5. Run the CRC check exactly as before — Execute still parses whatever text is in the editor (`parse_crc_config(text)`). The editor remains the single source of truth; nothing about the CRC run path changed.

### What's new under the hood
- A new raw-text reader `read_crc_config_text(raw_path, base_dir, size_probe=None) -> (Optional[str], list[str])` in `crc_config.py` (NON-frozen). It performs **resolve → size-cap → read** and returns the raw text **without parsing** — it deliberately does NOT reuse `read_crc_config`, which returns a *parsed* config (wrong type for a `TextArea`).
- The Load button is wired through `OperationsScreen.on_button_pressed` → `_load_config_from_path` (`screens.py:795 / 801 / 841`).

---

## Feature 2 — Paste a change-document into the Patch Editor

**Goal:** drive a multi-entry patch from a pasted document, at CRC-surface parity, instead of typing entries field-by-field or only loading from a file path.

### Operator walkthrough
1. Open the **Patch Editor** via rail key **`6`** (`PatchEditorPanel`).
2. The new paste `TextArea` (`#patch_paste_text`) is **pre-loaded with a dummy `s19app-changeset`** (`kind=change`, FAKE values) as a format reference. The existing change-file path `Input` is untouched — loading from a file still works.
3. Paste your own change-document into the paste field and press **"Parse pasted"**.
   - The panel posts an `ActionRequested(action="parse_paste", paste_text=…)`; `app.py` routes it to `ChangeService.load_text`, which parses the text into the owned `ChangeDocument` via the new string seam (collect-don't-abort).
   - Entries load and are classified **INSIDE / PARTIAL / OUTSIDE** against the loaded image, exactly as a file-loaded document.
   - **Malformed paste** surfaces the collected findings (a JSON-decode failure yields `MF-JSON-PARSE`) and does **not** crash.
4. Apply the parsed document with the **existing** apply action, then **confirm the save-back**. The patched S19 is written into the **contained work-area** and **re-read to verify** (reader-as-oracle) — identical to a file-loaded document, down to the pre-filled save-back name.

> **Key property:** US-014 introduces **no new write mechanism.** Apply, INSIDE/PARTIAL/OUTSIDE containment, the contained emit (`emit_s19_from_mem_map` via `copy_into_workarea`), and `verify_written_image` are the shipped, already-verified write path — reused verbatim. The only genuine delta is the paste field, the dummy pre-load, and a text→document parse seam.

### What's new under the hood
- `parse_change_document(text: str) -> ChangeDocument` added to `changes/io.py` (NON-frozen). It factors the post-`json.load` interpretation out of `read_change_document` and decodes from a string (`json.loads(text)`) instead of a file handle. `read_change_document` now **delegates** to it after resolve + size-cap + read (pinned: `call_count == 1`).
- The same three-exception catch (`json.JSONDecodeError`, `RecursionError`, `UnicodeDecodeError`) was re-homed around `json.loads`, so a malformed paste still emits `MF-JSON-PARSE`.
- A string seam has no path, so `parse_change_document` sets `source_path=None`; the save-back prompt name derives from the loaded image's `variant_id`, NOT the change-document path — so a paste-parsed apply matches a file-loaded one.
- `ChangeService.load_text(text) -> ChangeActionResult` mirrors `ChangeService.load`, setting `self.document` identically so the existing `apply_doc` routing applies unchanged.

---

## Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/operations/crc_config.py` | NEW `read_crc_config_text` raw-text reader (resolve + size-cap + read, no parse) |
| `s19_app/tui/screens.py` | CRC config-path `Input` + "Load config" `Button` + Load handler; visibility toggle |
| `s19_app/tui/changes/io.py` | NEW `parse_change_document` (string seam) + `DUMMY_CHANGESET_TEXT`; `read_change_document` refactored to delegate; both exported in `__all__` |
| `s19_app/tui/services/change_service.py` | NEW `ChangeService.load_text` mirroring `load` (no write code) |
| `s19_app/tui/screens_directionb.py` | paste `TextArea` pre-loaded with the dummy + `ActionRequested.paste_text` field |
| `s19_app/tui/app.py` | `parse_paste` token in `PATCH_ACTIONS_V2` (9→10) + router `elif` → `load_text`; corrected the stale `app.py:938` docstring (surgical truth-fix) |

---

## What is FAKE / dummy, and the safety properties

**FAKE / dummy data (config and patch data are NEVER real in the repo):**
- `DUMMY_CONFIG_TEXT` (`crc_config.py:47`) — a FAKE-valued CRC config shown as the editable reference until a real file is loaded.
- `DUMMY_CHANGESET_TEXT` (`changes/io.py`) — a FAKE-valued `s19app-changeset` (kind=change) shown as the paste-field reference. Real per-firmware values are never committed.
- A tripwire test (`test_no_changeset_under_examples`, TC-211) asserts `examples/**/*changeset*.json` stays empty, so the FAKE dummy cannot later leak in as a real-looking file (mirrors the CRC tripwire TC-114).

**Safety properties (preserved, not newly invented):**
- **Size-capped read** — both readers enforce `READ_SIZE_CAP_BYTES` **before** reading, so an over-cap file is rejected without being read.
- **Collect-don't-abort** — faults are returned as collected error strings / `ValidationIssue`s; the readers never raise, and a load fault runs no CRC check / does not crash the Patch Editor.
- **Contained write** — the patched S19 is emitted only into the `.s19tool/` work-area via `copy_into_workarea` (no arbitrary path, no clobber). US-014 adds no new write surface.
- **Verify-on-write** — the written image is re-read and checked (`verify_written_image`, reader-as-oracle). The standing write-surface gate confirms 0 changed lines in `apply.py` / `verify.py` / `workspace.py` and in the `emit_s19_from_mem_map` / `save_patched` bodies vs `febd843`.

---

## Diagrams
- CRC config-load flow + paste-changeset flow → [`diagrams/batch-13-flows.md`](diagrams/batch-13-flows.md)

---

## Evidence checklist — docs-writer

- [✓] **Audience and purpose declared** — top of this doc (technical stakeholder; operational walkthrough).
- [✓] **Structure follows the relevant template** — section 0 "06 - Documentación Cliente" functionality layout (at-a-glance + detail + components + usage + diagrams).
- [✓] **Code/CLI snippets actually run** — `s19tui`, rail key `6`, and CRC Execute are the shipped entry points; function signatures cited from `01-requirements.md` §4 + `03-increments/increment-002.md`.
- [✓] **Assumptions listed** — editor stays single source of truth; shipped write path reused; readers collect-don't-abort (`01-requirements.md` §6.1 A-D1..A-D8, all verified).
- [✓] **Risks / limitations called out** — visual `.tcss` polish deferred (non-blocking, `04-validation.md` §6 note 6); malformed-paste behavior bounded to surfaced findings.
- [✓] **Next steps stated** — run the CRC check as before; apply + confirm save-back drives the existing contained-emit + verify path.
- [✓] **Diagrams included** — two Mermaid flows in `diagrams/batch-13-flows.md`.
- [✓] **No invented APIs / version numbers / metrics** — every symbol (`read_crc_config_text`, `parse_change_document`, `load_text`, `DUMMY_CHANGESET_TEXT`, `MF-JSON-PARSE`) is cited from the requirements / validation / increment artifacts; node ids reconciled at Phase 4.
