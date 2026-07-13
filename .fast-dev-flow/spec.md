# fast-dev-flow spec — batch 39 — Untrusted-text hardening

- **Status:** closed 2026-07-13 (AC-1.1..3.2 green; gate 1390 passed / 0 failed / 3 xfailed pre-existing; security PASS-with-carries; 0 frozen diffs)
- **Created:** 2026-07-13
- **Branch:** `claude/batch-39-untrusted-text-hardening` @ `be62c97` (= origin/main; RC-1 clean)
- **Route:** /fast-dev-flow (3 small, isolated robustness/markup-safety fixes; each an independent AC)
- **Run mode:** autonomous + self-merge (operator-stated); decisions recorded in this spec + the closing artifact.
- **security_required:** true (see §6)

## 1. Objective

Close the standing untrusted-text carries from batches 34–38: cap the three uncapped paste surfaces and escape two file-derived-text sinks. No new features — three small, independently-testable robustness/markup-safety fixes. Engine-frozen set untouched.

## 2. User stories

- **S1 — Paste cap.** As a user pasting a large blob into a patch/JSON editor, I want the editor to cap the paste at 64 KiB so a huge accidental/malicious paste can't bloat memory or freeze the UI — matching the cap the Ctrl+V clipboard path already enforces.
- **S2 — Report symbol sanitize (S-F7).** As a user generating a report over a change-set whose linkage symbol carries markup/table-breaking characters, I want that symbol rendered safely in the report so a file-derived symbol can't inject markup or corrupt the output.
- **S3 — Filename markup hygiene (P-3).** As a user loading a file whose name contains markup metacharacters, I want the status line and notifications to show the name literally so a hostile filename can't leak styling or crash the render.

## 3. Out of scope

- The OsClipboardInput Ctrl+V path (already capped at `_CLIPBOARD_READ_CAP_CHARS = 65536`).
- What a report contains (S2 only changes how the symbol is *escaped*, not which rows appear).
- Any engine-frozen module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) and the frozen TEST files (`_ENGINE_TEST_FILES`) — C-27 dual-guard every increment.
- Batch-40/41 items (UX fixes, repo/test hygiene) and the Flow Builder.

## 4. Acceptance criteria (observable)

**S1 — Paste cap (64 KiB = 65,536 chars, mirroring `_CLIPBOARD_READ_CAP_CHARS`):**
- **AC-1.1:** When a native bracketed `Paste` of > 65,536 chars is delivered to any of the FIVE stock-`TextArea` paste surfaces — `#patch_paste_text`, `#changeset_json_text`, `#entry_json_text`, `#report_declared_regions`, `#operation_config` (F4: cap all 5, not 3) — the widget inserts at most 65,536 chars (excess dropped) — asserted via a Pilot `Paste` event whose payload exceeds the cap, reading the widget's resulting `.text` length.
- **AC-1.2:** When a `Paste` of ≤ 65,536 chars is delivered, the widget inserts the full text unchanged (no truncation regression) — boundary at exactly 65,536.
- **AC-1.3 (F3, second ingress):** the ctrl+v path `TextArea.action_paste()` (reads `app.clipboard`) is ALSO capped to 65,536 on these widgets — a shared `CappedTextArea(TextArea)` overrides BOTH `_on_paste` and `action_paste`.

**S2 — Report symbol sanitize (S-F7):**
- **AC-2.1:** When a report is generated over an entry whose `linkage_symbol` contains **table-breaking / markup metacharacters** (a pipe `|`, a newline, a backslash) at the render sink `report_service.py:977` (`f"| {entry.linkage_symbol or '-'} |"`), the rendered `.md` report bytes contain the symbol escaped (no raw `|` breaking the markdown table); a benign symbol is unchanged. *(F2: report is `.md`, not Textual markup — the load-bearing threat is table-break via `|`/newline, which `_md_table_cell` neutralizes; backtick/`[](url)` residual is accepted, identical to batch-34's Before/After byte cells.)*
- **AC-2.2 (golden double-proof, C-24):** the byte-identity report goldens capturing this Modifications-table line are re-derived from the base ref and drift ONLY for hostile-symbol fixtures; benign-symbol goldens stay byte-identical.

**S3 — Filename markup hygiene (P-3):**
- **AC-3.1:** When a file whose name contains markup metacharacters (`[red]evil[/]`, brackets) drives `set_file_status` → `#status_text` (the `Label` built markup-ENABLED at `app.py:1296`; source `_format_coexistence_status` `app.py:7643` embeds raw `path.name`), the status renders the filename literally (brackets verbatim, no `MarkupError`, no style leak) — asserted via a Pilot load with a hostile filename, reading rendered `#status_text`. Fix: `markup=False` on the `#status_text` `Label` (batch-33 log-line precedent).
- **AC-3.2 (F6, enumerated sinks):** the `notify()` sites embedding file-derived text — `app.py:2228` (save name), `app.py:5337` (manifest issue messages), `app.py:5397` (drift keys/messages) — render it literally under hostile input (pass `markup=False`; `notify` supports it in textual 8.2.8, default is `markup=True`). The false-premise docstring at `app.py:5364-5366` (claims plain interpolation is markup-safe — it is NOT) is corrected.

## 5. Design notes / seams (verified @ be62c97; `assumed` flags noted)

- **S1 (hook CONFIRMED by security pre-pass):** `os_clipboard_input.py:72` `_CLIPBOARD_READ_CAP_CHARS = 65536` = the cap to mirror (import it, don't redefine). Native bracketed paste → `TextArea._on_paste(self, event: events.Paste)` (`textual/widgets/_text_area.py:1982`, calls `_replace_via_keyboard(event.text, …)`); ctrl+v → `TextArea.action_paste()` (`:2661`, reads `app.clipboard`) is a SECOND ingress. Shared `CappedTextArea(TextArea)` overrides BOTH, truncating to the cap. 5 construction sites: `#changeset_json_text` (`screens.py:232`), `#entry_json_text`, `#patch_paste_text` (`screens_directionb.py`), `#report_declared_regions` (`screens.py:1599`), `#operation_config` (`screens.py:2025`). *Private `_replace_via_keyboard` dependency OK only because textual==8.2.8 is pinned.*
- **S2 (line CORRECTED, F1):** render sink = `report_service.py:977` `f"| {entry.linkage_symbol or '-'} |"` in `_modifications_lines` (NOT `:625`, which is the filter matcher `_matches_entry` — escaping there breaks filtering). `linkage_symbol` is the ONLY unescaped file-derived field on the row (`entry.linkage` = controlled constants; `_format_bytes` = hex). Reuse `diff_report_service.py:282 _md_table_cell` (strips ctl chars, doubles `\`, escapes `|`) — do NOT invent a new sanitizer. Flows into report goldens → C-24 census + double-proof. (Out-of-S2-scope note: `report_service.py:1086` interpolates raw `check.source_path` into a `####` heading — separate carry, not this batch.)
- **S3 (sinks ENUMERATED, F5/F6):** `#status_text` `Label` built markup-ENABLED at `app.py:1296` → `markup=False`; fed by `set_file_status` (`app.py:9607`) ← `_format_coexistence_status` (`app.py:7643`, raw `path.name`). `notify` sites `app.py:2228/5337/5397` embed file-derived text (markup default True) → `markup=False`; correct the false-premise docstring `app.py:5364-5366`. `set_status`/log-lines already markup=False (batch-33) — no change.
- **C-26:** touched symbols to reverse-grep across `tests/`: `#patch_paste_text`, `#changeset_json_text`, `#entry_json_text`, `#status_text`, `set_file_status`, `linkage_symbol`.

## 6. Security flags (auto-detection)

**security_required: TRUE.** Fired patterns: `sanitize` / `escape` (S2, S3 — file-derived text into report + status); `user input` / paste ingress (S1 — uncapped paste, DoS-adjacent memory/UI); markup-injection surface (S2, S3 — C-17 family).

**Handling:** this batch IS the hardening. Phase-B pre-code: a `security-reviewer` mini-pass on the 3 patterns (cap correctness + no-bypass; escape covers the real metacharacters; no existing sanitizer weakened). Phase-C: final security pass confirms each mitigation + the hostile-input AT per story.

## 7. Increment plan (≤5 files each)

1. **Inc-1 (S1):** shared `CappedTextArea(TextArea)` (caps `_on_paste` + `action_paste`) applied to all 5 sites + AC-1.1/1.2/1.3 tests.
2. **Inc-2 (S2):** escape `linkage_symbol` at `report_service.py:977` via `_md_table_cell` + AC-2.1 test + golden double-proof (C-24).
3. **Inc-3 (S3):** `markup=False` on `#status_text` + the 3 notify sites + docstring fix + AC-3.1/3.2 tests.

(3 increments = the fast-flow soft ceiling; a 4th → reassess vs promotion to /dev-flow.)

## 8. Amendment record (Phase-B pre-code security fold, 2026-07-13)

Security-reviewer pre-pass (0 HIGH) drove these spec corrections BEFORE Inc-1:
- **F1 (S2 sink):** `report_service.py:625` → **`:977`** (`:625` is the filter matcher; escaping it would break filtering).
- **F4 (S1 scope):** 3 → **5** TextAreas (`#report_declared_regions`, `#operation_config` added) — shared subclass makes it ~free; autonomous decision, operator may object.
- **F3 (S1 second ingress):** cap `action_paste` (ctrl+v internal clipboard) in addition to `_on_paste`; import `_CLIPBOARD_READ_CAP_CHARS`.
- **F5/F6 (S3 sinks):** confirmed `#status_text` (`app.py:1296`) markup-enabled gap + enumerated notify sites `2228/5337/5397` + a false-premise docstring at `5364-5366` to correct.
- **F2 (S2 wording):** threat reframed to markdown table-break (`|`/newline), not Textual `[red]` markup; backtick/link residual accepted (batch-34 precedent).
