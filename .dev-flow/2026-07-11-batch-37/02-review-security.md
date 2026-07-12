# 02 — Security Review (Phase-2 cross-review) · batch-37

> Reviewer: security-reviewer (independent). Tree: worktree `heuristic-wu-1c7c49` @ base
> `978a900` (RC-1 PASS). Scope: the 5 stories US-061 / US-062 / US-063 / US-064a / US-064b as
> specified in `01-requirements.md` + `01b-qa-strategy-and-verification.md`. This is a review of
> the SPEC/seams (no code shipped yet); Phase-3 verification items are folded, not blocking.

## Scope reviewed
- `01-requirements.md` (HLR/LLR + probe ledger P1–P20 + decisions D-061..D-SPLIT).
- `01b-qa-strategy-and-verification.md` (AT/TC plan, boundary/negative sets, supersession census).
- Seams read at base `978a900`:
  - `s19_app/tui/services/change_service.py:581` `load`, `:633` `load_text` (US-064a/b apply path).
  - `s19_app/tui/changes/io.py:296` `read_change_document`, `:440` `parse_change_document`
    (the validated path-guard + JSON-decode seam behind both).
  - `s19_app/tui/app.py:1652` `load_doc` / `:1660` `parse_paste` routing; `:1856`
    `action_before_after_report` (US-061 single report writer).
  - `s19_app/tui/screens.py:569` `ENTROPY_BAND_COLOUR`, `:722` `on_list_view_selected`
    dismiss-with-address contract (US-062/063).
  - `s19_app/tui/os_clipboard_input.py:72` `_CLIPBOARD_READ_CAP_CHARS = 65536` (paste bound).

## Headline
**No story adds a new external-write, network, credential, or destructive surface.** All three
risk axes the task flagged resolve clean against the code:
1. **US-061** routes to the *existing single* report writer — no new write path, no new
   file-path input, output funneled through markup-inert `set_status` (paths/diagnostics only,
   never entry byte content — `app.py:1863-1864`).
2. **US-064a refresh RE-INGESTS untrusted file content through the SAME validated load**
   (`ChangeService.load` → `read_change_document`): `resolve_input_path` + pre-read size cap
   (`READ_SIZE_CAP_BYTES`, `io.py:399`) + `OSError` guard (`io.py:419`) + collect-don't-abort
   JSON decode. No guard bypass, no new read code (`app.py:1658`).
3. **US-064b popup routes edited text through the SAME validated parse seam**
   (`parse_paste` → `ChangeService.load_text` → `parse_change_document` → `json.loads`,
   `io.py:520`): **no `eval`/`exec`, no unsafe deserialization**; `JSONDecodeError`,
   `RecursionError` (nesting-bomb) and `UnicodeDecodeError` are all caught (`io.py:521`). The
   popup edits an *in-memory* document — it does **not** write files itself.

## Findings

### S-01 | LOW | US-064b | Popup paste path must reuse the clipboard 64 KiB funnel; `load_text` itself has no size cap
- **What:** The file path (`read_change_document`) enforces `READ_SIZE_CAP_BYTES` *before* the
  read (`io.py:392-413`). The paste/popup path (`load_text` → `parse_change_document`) has **no
  equivalent size cap** — it hands the raw string straight to `json.loads` (`io.py:520`). The
  only bound today is the clipboard read cap `_CLIPBOARD_READ_CAP_CHARS = 65536`
  (`os_clipboard_input.py:72`), which applies to clipboard *paste* ingress only.
- **Where:** `change_service.py:667` `load_text`; new `ChangeSetJsonScreen.#changeset_json_text`
  TextArea (LLR-064b.1).
- **Why it matters:** Operator-controlled, local-desktop input — blast radius is the operator's
  own memory/process, not a remote or multi-tenant surface. Low. The concern is only that the
  new popup `TextArea` not become a *second, uncapped* paste ingress that bypasses the batch-29
  R-TUI-044 clipboard funnel.
- **Recommendation:** Route the popup's paste into `#changeset_json_text` through the existing
  `os_clipboard_input` funnel (same as `#patch_paste_text`) so the 65536-char cap holds; do
  **not** introduce a new direct-clipboard read in the modal. No new size cap on `load_text` is
  required for this batch (unchanged existing seam) — just don't widen the ingress.
- **Fold:** Phase-3 implementation note on Inc-5; verify in the AT-064b boundary leg.

### S-02 | LOW | US-064a | Refresh inherits the existing symlink-follow + stat/open TOCTOU of `read_change_document` — acceptable, no regression
- **What:** `read_change_document` size-probes via `stat()` then `open("rb")` (`io.py:398,417`),
  and `resolve_input_path` + `.open` follow symlinks. Refresh re-invokes this on operator
  action, so a file swapped between probe and read, or a symlink repointed, is read as-resolved.
- **Where:** `io.py:376-418`; US-064a re-dispatch (LLR-064a.1, `app.py:1658`).
- **Why it matters:** This is **pre-existing** behavior of the initial `load`; refresh adds no
  new TOCTOU window and no new path source (it re-reads the *already-selected*
  `#patch_doc_path_input`/`#patch_doc_file_select`). The operator chose the path; local trust
  boundary. The size cap fires on the second read too, so a file that grows past the cap between
  load and refresh is refused, not loaded.
- **Recommendation:** None required for this batch. Confirm at Phase-3 that refresh dispatches
  the *same* `ChangeService.load(path, base_dir)` (not a hand-rolled `open`) so all guards ride
  along — AT-064a's boundary legs (R2 no-doc, R3 deleted, R4 invalid-JSON) already assert this.
- **Fold:** Verify seam identity in TC-328 (refresh calls `ChangeService.load` once).

### S-03 | LOW | US-063 | Legend meaning strings and clickable-strip cells are self-authored/in-repo, not file-derived — C-17 correctly N/A; two authoring pins to hold
- **What:** (a) The band-legend meanings are rendered from `ENTROPY_BAND_COLOUR` in-repo literals
  (`screens.py:569-574`) — no file-derived text flows through the markup-enabled `Label`, so
  there is no injection surface (C-17 discharged, §3 of requirements). The residual is a
  *self-inflicted* markup bug if a meaning string carried `[`/`]`; LLR-063.1 + TC-326 already pin
  "no `[`/`]`". (b) The clickable strip dismisses with `window.start`, an address drawn from
  `compute_entropy` over the loaded `mem_map` — **bounded to real in-image windows**, never an
  arbitrary/attacker-chosen offset.
- **Where:** `screens.py:569` (bands), `:722-728` (bounded dismiss `0 <= index < len`);
  LLR-063.2 `action_jump(i)`.
- **Why it matters:** Confirms the task's two US-063 questions: (i) no untrusted text through
  markup, (ii) the click address is bounded. Both hold by construction.
- **Recommendation:** In Inc-4, mirror the existing `on_list_view_selected` bounds guard
  (`0 <= index < len(sorted_windows)`) in `action_jump` so an out-of-range click (padding past
  the last cell) is a no-op, not a wrong-window dismiss or IndexError. TC-327 + AT-063b boundary
  already require this.
- **Fold:** Hold the C-17 authoring constraint (no `[`/`]`) + the click-index bound at Phase-3.

### S-04 | LOW | US-061 | Persistent report control is a second trigger onto one writer — confirm it adds no `reports/` path input and preserves the refusal-writes-nothing arm
- **What:** US-061 reveals a `.hidden` row and routes to the existing
  `action_before_after_report` (single writer into `<project>/reports/`, `app.py:1924-1935`).
  No new report-writing code, no operator-supplied output path, and the refusal arm
  (`app.py:1937`) writes 0 files and surfaces only a diagnostic.
- **Where:** `app.py:1856` (writer), LLR-061.2 (single-source trigger).
- **Why it matters:** Confirms the task's US-061 question — no new external-write surface beyond
  what `action_before_after_report` already writes; no new file-path injection. The report
  filter read inside the handler (`app.py:1904-1915`) is the *existing* batch-35 path, itself
  refusal-guarded — US-061 does not touch it.
- **Recommendation:** In Inc-2, the persistent control must invoke `action_before_after_report`
  with **no new arguments** (LLR-061.2) — do not let the button carry an operator-typed output
  path. AT-061a's byte-identical `b`-path-vs-control assertion pins this.
- **Fold:** Verify single-writer routing in TC-330.

## Scope-change / external-write-surface scan
- **New write surfaces:** none. US-061 = second trigger on the one report writer; US-064b popup =
  in-memory document mutation via `load_text` (no file write); US-064a = read-only re-ingest;
  US-062/063 = presentation over an in-memory snapshot.
- **New read surfaces:** US-064a re-reads an *already-selected* path through the existing guarded
  loader — not a new path source. No new network, subprocess, env, or credential access anywhere.
- **Deserialization:** `json.loads` only; no `pickle`/`eval`/`exec`/`yaml.load`. RecursionError
  caught → no nesting-bomb crash.
- **Frozen-engine guard:** all touched files (`screens.py`, `screens_directionb.py`, `app.py`,
  `services/change_service.py`, `services/entropy_service.py`) are non-frozen (census §5 of the
  QA strategy confirmed); `ENTROPY_BAND_COLOUR` lives in non-frozen `screens.py`. No frozen
  module is edited.
- **Secrets:** none introduced; fixtures are synthetic (`large_s19` generator + in-memory
  `mem_map` + synthetic v2 JSON). No client artifact, no PII, no tokens.

## Verdict
- [ ] OK to ship
- [x] **OK to ship (PASS) with the 4 LOW fold-items carried into Phase-3** — none block Phase-2
- [ ] Block

**All findings are LOW.** No HIGH, no MEDIUM. The two re-ingest paths reuse validated seams with
no bypass:
- **US-064a refresh CONFIRMED to reuse the validated load** — `ChangeService.load`
  (`change_service.py:581`) → `read_change_document` (`io.py:296`) with `resolve_input_path` +
  size cap (`io.py:399`) + `OSError` guard (`io.py:419`) + collect-don't-abort. Dispatched from
  `app.py:1658`.
- **US-064b popup CONFIRMED to route through the validated parse seam** — `parse_paste` →
  `ChangeService.load_text` (`change_service.py:667`) → `parse_change_document` (`io.py:440`) →
  `json.loads` (`io.py:520`) with `JSONDecodeError`/`RecursionError`/`UnicodeDecodeError` caught
  (`io.py:521`). No `eval`, no new write surface. Dispatched from `app.py:1661`.

## Evidence checklist
- [x] Each finding has what · where · why · recommendation — S-01..S-04.
- [x] Each finding has a severity rating — all LOW.
- [x] No secret values in output — none present; fixtures synthetic.
- [x] Verdict explicit — PASS (OK to ship) with 4 LOW fold-items.
- [x] New tool/integration scope + blast radius addressed — N/A (no MCP/Composio/n8n/external
      integration added; scope-change scan above confirms no new external-write/read/network
      surface).
