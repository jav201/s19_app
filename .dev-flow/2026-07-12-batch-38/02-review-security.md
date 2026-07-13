# 02 — Security Review (Phase 2, independent) — 2026-07-12-batch-38

> **Reviewer:** security-reviewer (independent). **Inputs:** `01-requirements.md`, `01b-qa-strategy-and-verification.md`, `PLAN.md`, verified against source at `origin/main` tip `5a6c45b` (primary checkout `s19_app/…`).
> **Threat model:** a malicious firmware / A2L / change-set JSON must not crash the TUI, corrupt the screen via markup injection, or cause silent data loss. Single-user local desktop tool; no network/secret surface.

## BLUF

**Verdict: PASS (with mitigations).** No blockers. **1 major** (a spec-completeness gap that re-opens the batch-37 A-01 data-loss class), **1 minor**, **2 low**. The design is fundamentally safe: markup-safety is correctly routed through the existing `safe_text`/`IssueRow` sink, the per-entry editor reuses the validated `json.loads`-based parse path (no `eval`/`pickle`/`exec`), undo/redo history is explicitly bounded, and no new secret / network / external-write surface is introduced. The engine-frozen `validation/` package is imported, not edited, and no sanitizer is weakened. The one item that must be discharged before Inc-5 implements US-068b is the **A-01 file-loaded guard**, which the requirements are currently silent on.

---

## Scope reviewed

`01-requirements.md` §2.6/§3/§4 (HLR/LLR for US-065, US-066, US-067, US-068a, US-068b), `01b-qa-strategy-and-verification.md` (AT/TC strategy), `PLAN.md`. Source cross-checks: `issues_view.py:38,173-206` (render sink), `screens_directionb.py:374` (`safe_text`), `validation/model.py:19-137` (message scrub), `services/change_service.py:581-683` (`load`/`load_text`), `changes/io.py:440-540` (`parse_change_document`), `app.py:1739-1958,3262-3264` (batch-37 A-01 guard + whole-set apply), `os_clipboard_input.py:70-74` (64 Ki clipboard cap).

---

## Findings

### F1 — US-068b per-entry JSON popup: batch-37 A-01 file-loaded guard is unspecified  [Severity: MAJOR]
- **What:** Batch-37 established the **A-01 data-loss guard**: the whole-set JSON popup is *disabled* whenever the change document is file-backed (`ChangeService.document.source_path is not None`), and the handler *refuses* even if invoked, so a file-loaded document is never silently clobbered by an in-memory edit (`app.py:1739-1743`, `1907-1913`, `3262-3264`). US-068b adds a **new** per-entry JSON control + modal + `ChangeService.edit_entry_json(index, text)` that mutates `document.entries[i]` in memory. The requirements (§3.5, HLR-068b, LLR-068b.1/.2/.3) are **silent** on whether this new control carries the same A-01 disable/guard for file-loaded documents. As written, per-entry edit would mutate a file-backed document while the whole-set edit is blocked on the identical state — an unresolved asymmetry that re-opens the exact class A-01 closed.
- **Where:** `01-requirements.md` §3.5 / LLR-068b.1 (`screens_directionb.py` control) + LLR-068b.3 (`app.py` handler + `change_service.py:edit_entry_json`). Precedent: `app.py:1739-1743,1907-1913`.
- **Why it matters:** State confusion / silent in-memory mutation of a document the user believes is the on-disk file, without the guard the codebase already enforces for the sibling control. Not an irreversible/secret-leak issue (undo/redo lands in the same batch; save is a separate explicit step), hence major not blocker — but it is a security-relevant completeness gap on the data-loss axis that batch-37 treated as a blocker.
- **Recommendation (required before Inc-5):** Phase 2 must record an explicit A-01 stance for the per-entry control — either (a) mirror the batch-37 guard: disable `#patch_entry_edit_json_button` when `source_path is not None` and re-check in the handler (preferred, consistent with `#patch_edit_json_button`), or (b) explicitly justify that a scoped single-entry in-memory edit of a file-backed doc is intended, and specify how it is surfaced to the user and reconciled on save-back. Add the decision as an LLR acceptance clause and an AT branch (file-loaded → control guarded/refused). Also state the same stance for US-068a undo/redo mutating a file-backed document's in-memory state.

### F2 — US-068a history bound present but depth value unverified  [Severity: MINOR]
- **What:** LLR-068a.1 correctly bounds the undo history (`_HISTORY_MAX`, evict-oldest, deep snapshot, redo cleared on fresh mutation), which contains the DoS-ish unbounded-growth risk. The bound *value* (default 20) is flagged `assumed — verify in Phase 3`, and R-B correctly notes the snapshot must be a true deep copy (no aliasing into `document.entries`).
- **Where:** `01-requirements.md` LLR-068a.1 (`change_service.py`); risk R-B §6.3.
- **Why it matters:** The security-relevant property (a fixed upper bound on retained snapshots) is designed in, so memory growth is contained. Residual: an aliasing bug would let a later mutation corrupt a stored snapshot (state confusion), and the numeric bound is unconfirmed.
- **Recommendation:** Keep the bound; add a Phase-3 unit assertion that (a) stack depth never exceeds `_HISTORY_MAX` and (b) mutating `document.entries` after a snapshot leaves the stored snapshot byte-identical (deep-copy proof) — TC-340 covers the bound; add the aliasing assertion to TC-338/339.

### F3 — New `#entry_json_text` TextArea inherits the uncapped native-paste carry  [Severity: LOW]
- **What:** The 64 Ki ingress cap (`_CLIPBOARD_READ_CAP_CHARS = 65536`) lives on `OsClipboardInput` (single-line inputs), not on the `TextArea` used by the JSON popups. PLAN.md already lists "native-paste 64 KiB cap on `#patch_paste_text`+popup" as an **out-of-scope batch-37 carry**. US-068b's per-entry modal mirrors `ChangeSetJsonScreen` (a `TextArea`), so it adds a second uncapped paste target feeding `json.loads`.
- **Where:** `os_clipboard_input.py:70-74`; new `EntryJsonScreen` TextArea (LLR-068b.2); PLAN.md out-of-scope carries.
- **Why it matters:** Low — single-user local tool; `json.loads` is memory-bounded and the parse is collect-don't-abort (`io.py:519-529`), so a huge paste degrades responsiveness at worst, no crash/leak.
- **Recommendation:** When the batch-39 TextArea-paste cap carry is implemented, include `#entry_json_text` in its scope. No action required inside batch-38.

### F4 — US-066 WARNING message must not be pre-formatted with markup (confirm at implementation)  [Severity: LOW]
- **What:** The oversized-address WARNING is built TUI-side in `validation_service.py` as a `ValidationIssue`. Rendering is safe *by construction* of the existing sink: `IssueRow` wraps `symbol`/`address`/`message` through `safe_text` (literal `rich.text.Text`, `issues_view.py:187,201,195`; `_scrub_issue_message` additionally strips control/ANSI from `message` at `model.py:137`, brackets handled by `safe_text`). LLR-066.3 correctly mandates the tag name reach render only via `symbol` and/or a **non-markup-formatted** message. The one implementation footgun: the producer must not build the message with Rich markup (e.g. `f"[yellow]{name}[/]…"`) — that would style-inject via the developer-supplied part even though the file-derived name is safe.
- **Where:** LLR-066.1/.3 (`validation_service.py` producer); render sink `issues_view.py:38,187,201`.
- **Why it matters:** Low — the requirement already forbids it and AT-066b (hostile bracket/ANSI/link payload in the tag name) is a genuine hostile-input test with a valid RED counterfactual. This is a confirm-at-code note, not a spec defect.
- **Recommendation:** Implementer builds the message as a plain literal (address formatted as hex digits, inherently safe); AT-066b already gates the file-derived branch. No spec change needed.

---

## Cleared (verified safe, no finding)

- **US-065 (label copy):** Copy-only on two string literals (`screens_directionb.py:1854,1904`); ids/CSS classes preserved (LLR-065.1/.2). No logic/path change. Low risk confirmed.
- **US-067 (variant help modal):** Static help text; LLR-067.3 mandates `markup=False`/literal `Text`; no untrusted interpolation. C-16 real-click AT. Safe.
- **US-068b parse route:** `edit_entry_json`/confirm routes through the validated `json.loads`-based parser (`changes/io.py:520`, catches `JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`, collect-don't-abort). No `eval`/`pickle`/`exec`; TC-343 asserts the validated route, no direct-bypass write.
- **Engine-freeze / sanitizer integrity:** WARNING built in non-frozen `services/validation_service.py`; `validation/model.py` (incl. `_scrub_issue_message`) is imported and consumed, not edited. No existing sanitizer weakened.
- **No new external surface:** undo/redo and per-entry edit are in-memory `ChangeService` operations; no new file-write, network, secret, or credential handling. Save-back remains the existing explicit path.

---

## Evidence checklist

- [✓] Each finding has what · where · why · recommendation — F1–F4 above.
- [✓] Each finding has a severity rating — MAJOR / MINOR / LOW / LOW.
- [✓] No secret values in output — n/a (no secrets in scope; none printed).
- [✓] Verdict explicit — PASS (with mitigations); F1 to be discharged at Phase 2 before Inc-5.
- [✓] New tool/integration scope + blast radius — no new external integration; in-memory-only new capabilities reviewed (F1/F2 blast radius = local in-memory document state).

## Verdict

- [ ] OK to ship
- [x] **OK to proceed to implementation with the listed mitigations** — F1 (major) must be resolved and recorded at Phase 2 before Inc-5 implements US-068b; F2 folded into US-068a Phase-3 tests; F3/F4 are advisory.
- [ ] Block

No HIGH/blocker findings. The requirements are security-sound to proceed; the single substantive gap (F1, A-01 stance for the per-entry popup) is a Phase-2 spec-completeness obligation, not a shipped vulnerability.
