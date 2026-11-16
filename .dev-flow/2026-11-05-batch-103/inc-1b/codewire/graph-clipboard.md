# Code-Wire delta — Inc 1b group B, `os_clipboard_input.py`

Stage E3 corrective design, graph only; E2 baseline is commit `6adb6337`. Code-Wire v3.1.0 (`e436a08`). This is the group-B fragment for the orchestrator's `graph-app.md`, not a competing full graph. Authority: `../E2-interfaces.md` I-1, `../01-requirements.md`, `../02-test-cases.md`, and G2 `../../evidence/G2/veredicto-b103-r2.json` (`q3_body=B`, `q4_q=B`, `q6_notices=approve`). This revision adds only the orchestrator's E3-02 NUL ruling and E3-03 hostile-fixture coverage in this fragment. Current product references are `os_clipboard_input.py:638-754`, `:834-944` and `capped_text_area.py:242-308`; only the first file changes in this group. No example or negative control below is a claim of an E2/E3 execution; they are inputs for independent E4 tests and later mutation runs.

### Delta and consumed contracts

**2 implementation nodes (1 new + 1 changed) + 6 unchanged context nodes = 8 function nodes.** The implementation nodes are `_copy_notice_text` and `_mirror_and_write_os_clipboard`. Context is `write_os_clipboard`, both classes' `action_copy` / `action_cut`, and `OsClipboardInput._on_paste`; their behavior is not redesigned here. Data and I/O endpoints in Edges are not counted as function nodes.

I-1 is consumed with exactly one orchestrator-ruled exception, E3-02; every other I-1 contract remains unchanged:

- Group A's `S19TuiApp.copy_to_clipboard(text: str) -> None` is the synchronous view entry and schedules this module's async tail exactly once. Group A owns selection/row extraction and press/release ordering. This fragment does not specify an override body, a scheduler, a right-click handler, or a second writer.
- For a capped payload without NUL, the tail alone mirrors, writes, and notifies. It retains the original text across the await, derives `capped_text = original_text[:_CLIPBOARD_CAP_CHARS]`, invokes the **unbound toolkit base** `App.copy_to_clipboard(app, capped_text)` exactly once, and awaits exactly one `loop.run_in_executor(None, write_os_clipboard, capped_text)` call. “One write” means one cascade invocation; the unchanged cascade may try its ordered strategies.
- `_copy_notice_text` lives here, not in `app.py`. This module must never import `s19_app.tui.app` or a symbol from it. `app.py` already imports `OsClipboardInput` from this module (`app.py:87`), so the reverse import would close a cycle.
- The tail calls the base unbound, never `app.copy_to_clipboard(...)`, `super().copy_to_clipboard(...)`, or the group-A override. Text-box copy/cut enters the tail directly, so it never schedules the override. Thus the override and tail cannot recurse into each other. There is no shared copy buffer, re-entry flag, or global notice/write guard; overlapping independent copies are not dropped.
- `_CLIPBOARD_CAP_CHARS = 65536`, `_CLIPBOARD_READ_CAP_CHARS`, `_WRITE_FAIL_NOTIFICATION`, `write_os_clipboard`, and the four box action signatures keep their contracts. The writer's internal cap remains as defense in depth, but does not replace the tail cap needed by the app clipboard and OSC 52.
- **E3-02, fail closed:** immediately after deriving `capped_text`, and before the base, writer, or `_copy_notice_text`, test only `capped_text` for U+0000. If present, return after exactly one `app.notify("Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.", severity="warning", timeout=6.0)` and one fixed WARNING `OS clipboard copy refused; payload contains NUL`. Base/writer/OSC 52/process/success-notice counts are all zero, the helper is not called, and both pre-seeded clipboards remain unchanged. Never log the payload, a prefix, or an escaped representation; never write a sanitized or truncated replacement.
- The guard examines `capped_text`, not `original_text`: NUL solely after character 65,536 is discarded by the cap and takes the normal base/writer path, with the successful cut notice using the original length. No other C0 character, markup, ESC/BEL/OSC-like text, or LF is sanitized or refused by this branch.
- On non-NUL success, the tail emits exactly one `app.notify(_copy_notice_text(original_text), severity="information")`; the over-cap helper result substitutes the cut notice for the ordinary copy notice. On writer failure it emits no success/cut notice and preserves exactly one existing warning with `severity="warning"`, `timeout=6.0`, plus the existing WARNING log. Notice emission happens only after the awaited writer returns. Existing best-effort mirror and failure-notification exception handling stays unchanged.

### Route cardinality (every row is one user copy)

| Source and gesture | Entry into the tail | Required new effects per gesture |
|---|---|---|
| View selection, Ctrl+C, no capped NUL | Group-A override → schedule once | base copy 1; executor write 1; OSC 52 request 1; result notice 1 |
| View selection, button-3 press/release, no capped NUL | Group-A override → schedule once | same; the text is the whole selection captured before toolkit dispatch |
| A2L/MAC row, button 3, no capped NUL | Group-A override → schedule once | same; the payload is the mapped full row name |
| `OsClipboardInput`, Ctrl+C / Ctrl+X / right-click copy, no capped NUL | Existing action → direct tail; override 0 | base copy 1; executor write 1; OSC 52 request 1; result notice 1 |
| `CappedTextArea`, Ctrl+C / Ctrl+X (including line cut) / right-click copy, no capped NUL | Existing action → direct tail; override 0 | base copy 1; executor write 1; OSC 52 request 1; result notice 1 |
| Any non-NUL route whose cascade returns `False` | Same single tail call | mirror and OSC 52 still 1; `Copied…` notices 0; existing failure warning 1 |
| Any route whose `capped_text` contains NUL | Same single tail call; view override 1, direct-box override 0 | tail 1; base/writer/OSC 52/process/helper 0; fixed refusal warning 1; success notices 0; both seeds unchanged |

### Example fixtures and independent observations

- `S3` is the three-line, non-uniform hex selection read after the drag and before the copy; assert its three lines differ and `S3.count("\n") == 2`. `S5` is the five-line stats selection. `S6` is a cross-view selection whose non-empty, distinct `stats_first` and `a2l_first` parts occur in that order; `S6` must not equal the clicked widget's fragment. Expected clipboard bytes are these independently captured input selections, not values recomputed by the tail.
- `J75210` is the shown JSON selected with F7, with `len(J75210) == 75210`, a kept marker at index `65535`, and a different discarded marker at index `65536`. `P70000 = "P" * 70000`; `P65536 = "x" * 65536`; `P65537 = "x" * 65537`. Length and boundary assertions precede each copy, so a wrong fixture cannot make its oracle vacuous.
- `NUL3 = "A\x00B"`; `NUL_AFTER = P65536 + "\x00"`, with `len(NUL_AFTER) == 65537`, `NUL_AFTER[:65536] == P65536`, and its only NUL at index `65536`, exactly as R-COPY.25/3 requires. Before each refusal case, independently seed the app clipboard with `SEED-APP-1b` and the OS clipboard with `SEED-OS-1b`; assert both seeds immediately before and after the gesture.
- `HOSTILE = '[red]\x1b\x07\x1b]52;c;U0VFRF9PU0M=\x07\nSUFFIX'` is exactly the ledger's `HOSTILE_NAME`, stored as the raw full name in the A2L model: it contains markup, ESC, BEL, an OSC-like sequence and one LF, but `"\x00" not in HOSTILE`. Its expected value is this independently constructed model string, never the painted cell or a U+FFFD/sanitized projection; assert `HOSTILE.count("\n") == 1` before copying.
- The **call ledger** wraps but otherwise preserves the real base copy, group-A override, tail, writer, and `_copy_notice_text` to record entry count, thread, and payload. The **notice ledger** is the app's settled notification list, not a fabricated return message. WinCI uses a separate `Get-Clipboard -Raw` reader. OSC 52 observations count and decode actual driver requests and detect any additional terminal sequence. The forced-PowerShell ledger separately records strategy calls, process arguments, and stdin without deriving expected clipboard content from those observations. Linux failure uses the existing failing cascade; WinCI failure uses the 8-second held clipboard.

### Requirement → node and negative-control ledger

| Requirement | Design/example owner | Negative control and the observable that must go RED |
|---|---|---|
| R-COPY.1 | Tail; view producer is group A | Remove the executor write → WinCI separate read remains `SEED-1b`; remove the view's scheduled tail → base/write/notice counts all 0 |
| R-COPY.2 | Tail/base mirror | Skip the base call or write only the OS clipboard → app clipboard remains `SEED-1b`; failure arm must still mirror the exact row name |
| R-COPY.4 | Group-A full-name producer → tail | Supply highlighted row 2 instead of clicked row 5, a shortened painted cell, internal key, or glyph-prefixed cell → exact separate-read assertion fails; these are integration pins, not new module parsing logic |
| R-COPY.7 | Helper + tail + four box actions | Use plural for 1, count a final LF, notify before the result, bypass the tail for a box, or notify in both override and tail → respectively wrong exact text, notice on failure, zero notices, or two notices; every non-NUL copy/cut route asserts one write and one notice |
| R-COPY.8 | Tail cap + unchanged writer cap | Remove only the tail cap → app clipboard and OSC 52 hold 75,210 characters even though the writer's own cap may hide the defect on the OS read; use `[:65535]` → all three payloads have 65,535 and miss the kept marker |
| R-COPY.9 | Helper original-length contract + tail result branch | Pass capped text to the helper → `(65,536 in all)`; use `>=` → `P65536` gets a cut notice; emit ordinary as well as cut → two notices; emit cut on writer failure → forbidden success notice on failure |
| R-COPY.10 | Exactly one base call | Replace the base call with OS-only writing → 0 OSC 52 requests; call base twice, or group A calls `super()` and the tail calls base → 2 requests |
| R-COPY.12 | Group-A early whole-selection capture → tail | Feed only the clicked A2L fragment → `S6` loses `stats_first`; read after toolkit press/release dispatch → back-to-back case copies empty/partial text; both separate-read and write-count assertions fail |
| R-PASTE.1 | Unchanged terminal-paste consumer; real tail artifact | Insert all lines or insert twice in the consumer → T1 has a second line or duplicated first line; bypassing the OS artifact with direct `events.Paste(S3)` is a vacuous acceptance control and is forbidden |
| R-PASTE.9 | Tail failure branch | Drop the failure warning → 0 warnings; additionally emit copy/cut success on `False` → a forbidden `Copied…` notice appears; duplicate warning in override → 2 warnings |
| R-PASTE.10 | Existing writer + tail WARNING lines | Remove both failure logs → no WARNING; remove only the tail line → its exact-message assertion fails; interpolate copied text into either log → secret-absence assertion fails |
| R-PASTE.12 | Existing box actions → tail cap | Apply the cap only in the writer → box copy/cut leaves app clipboard and OSC 52 at 70,000; passing the original text to base is the discriminating mutation even if the OS read stays capped |
| R-PASTE.13 | Unchanged strategy budgets + tail await | Retry until the holder releases, add a second sequential cascade, or add another 2-second PowerShell wait → warning exceeds `timing_bound(2.5)` seconds and/or write count is 2 |
| R-PASTE.14 | Executor edge | Call `write_os_clipboard` directly on the event-loop thread → held-clipboard ticks stall beyond `timing_bound(0.1)`; asserting only eventual completion would not catch this and is not an acceptable oracle |
| R-TUI-043.13 | Tail and writer logging | Log the payload or its first 16 characters at any level → exact secret-substring absence fails on both successful and failing copy routes |
| E3-02 ruling (R-COPY/R-PASTE clipboard contracts) | Tail capped-NUL guard; view override and all direct box routes | Check `original_text` or test before cap → `NUL_AFTER` is refused instead of one capped write/cut notice; move the guard after base → app seed/base/OSC 52 assertions go RED; retain writer/helper/success in the refusal arm → zero-count assertions go RED; alter either fixed string or interpolate payload → exact-message/log-absence assertions go RED; sanitize NUL → an altered write/success is forbidden |
| E3-03 coverage (R-COPY.4, R-TUI-043.13) | Group-A raw full-name producer → tail → base/OSC 52/forced PowerShell | Use the painted/U+FFFD value or strip markup/ESC/BEL/LF → exact app/OSC 52/Win mismatch; put `HOSTILE` in process arguments rather than stdin → static-argv assertion goes RED; emit its OSC-like text as another terminal sequence → sequence count exceeds 1; log raw/prefix/escaped payload → log-absence assertion goes RED |

### E4 review gates for this fragment

1. **Cardinality census:** every route in the table asserts tail/base/writer/OSC 52/notice counts, including text-box cut and right-click routes; a check that asserts only clipboard content is insufficient. NUL cases additionally assert helper/process counts and both seeds.
2. **No-reentry probe:** a non-NUL view copy has override/tail/base counts `1/1/1`; every non-NUL box copy/cut has `0/1/1`. The capped-NUL arms instead require view `1/1/0` and box `0/1/0`. An `app.copy_to_clipboard` call inside the tail must make the normal probe recurse or exceed its count. A static import check also rejects any `s19_app.tui.app` import in this module.
3. **Original-length probe:** the 75,210-character and exact-65,536/65,537 fixtures run independently; no expected `<N>` may be read back from the emitted notice or from a capped payload.
4. **Emitted-artifact acceptance:** at least one copy→separate-read→terminal-paste case per target class consumes the OS clipboard result. Directly invoking `_on_paste` with the source text without the copy/write/read chain does not discharge the acceptance example.
5. **Timing discrimination:** held-clipboard tests record writer thread and timer lateness, not merely test duration. Removing the executor and extending retries must each produce a named RED arm at E4/E5.
6. **NUL discrimination:** run `NUL3` through view key/right-click and both box classes' copy/cut/right-click actions, plus `NUL_AFTER`; assert the capped-only boundary, zero sinks on refusal, exact fixed notice/WARNING, no payload logs, intact seeds, and original `65,537` cut total. Testing only the view override is insufficient.
7. **Hostile-sink fidelity:** copy the raw `HOSTILE` model name through the real tail and independently compare app clipboard, decoded OSC 52, and separate WinCI read; force the real PowerShell strategy, inspect static argv/stdin, count terminal sequences, and capture logs at every level. The painted cell cannot supply the expected value.

## Nodes

_copy_notice_text
req: R-COPY.7, R-COPY.9
in: str text
out: str notice_text
func: **new pure helper.** Take the original, uncapped copied text. Read no app/widget state and perform no I/O. If `len(text) > _CLIPBOARD_CAP_CHARS`, return exactly `Copied the first 65,536 characters to the clipboard (<N> in all).`, with `<N>` the original `len(text)` formatted by `:,`. Otherwise count `text.count("\n") + 1`, subtracting one when `text.endswith("\n")`; return `Copied 1 line to the clipboard.` for one line, else `Copied <n> lines to the clipboard.`. The over-cap branch takes precedence over line counting. Do not slice `text` inside this helper and never use a capped length for `<N>`.
module: s19_app/tui/os_clipboard_input.py
examples: (R-COPY.7/1) `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING` → exactly `Copied 1 line to the clipboard.`
examples: (R-COPY.7/2) `s1\ns2\ns3\ns4\ns5` → exactly `Copied 5 lines to the clipboard.`
examples: (R-COPY.7/5) `L1\nL2\nL3` and `L1\nL2\nL3\n` → both exactly `Copied 3 lines to the clipboard.`, never four lines
examples: (R-COPY.7/1 neg) singular rendered as `Copied 1 lines to the clipboard.` → exact-string assertion RED
examples: (R-COPY.7/5 neg) counting the final LF without the exclusion → `Copied 4 lines to the clipboard.` → RED
examples: (R-COPY.9/1) `J75210` → exactly `Copied the first 65,536 characters to the clipboard (75,210 in all).`
examples: (R-COPY.9/1 boundary) `P65536` → `Copied 1 line to the clipboard.`; `P65537` → `Copied the first 65,536 characters to the clipboard (65,537 in all).`
examples: (R-COPY.9/1 neg) passing `J75210[:65536]` as `text`, or formatting the capped length, → `(65,536 in all)` instead of `(75,210 in all)` → RED

_mirror_and_write_os_clipboard
req: R-COPY.1, R-COPY.2, R-COPY.4, R-COPY.7, R-COPY.8, R-COPY.9, R-COPY.10, R-COPY.12, R-COPY.25, R-PASTE.9, R-PASTE.10, R-PASTE.12, R-PASTE.13, R-PASTE.14, R-TUI-043.13
in: App app; str text
out: None
func: **changed.** Preserve `original_text = text` and therefore its original length for the entire call, including across the await. Derive one local `capped_text = original_text[:_CLIPBOARD_CAP_CHARS]`. Immediately after that derivation and before any base/writer/helper call, if `"\x00" in capped_text`, make zero base/writer/OSC 52/process/helper calls, emit exactly one `app.notify("Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.", severity="warning", timeout=6.0)`, log exactly one fixed WARNING `OS clipboard copy refused; payload contains NUL`, and return. Emit no ordinary/cut success notice and leave both the app and OS clipboard seeds unchanged; never write a sanitized or truncated replacement. Test only `capped_text`, so NUL solely beyond the cap does not refuse. On the non-NUL path, make exactly one unbound base `App.copy_to_clipboard(app, capped_text)` call, retaining the existing DEBUG-only best-effort mirror failure behavior; then make exactly one default-executor `write_os_clipboard(capped_text)` call and await it. On `True`, call `_copy_notice_text(original_text)` and emit its one result as information; the original, not `capped_text`, supplies `<N>`, including when a discarded suffix contains NUL. On `False`, emit only `_WRITE_FAIL_NOTIFICATION` as a 6-second warning and retain the exact existing WARNING `OS clipboard write failed; retained Textual internal clipboard only`. Keep the writer's WARNING and its strategy/time budgets unchanged. Never log `original_text`, `capped_text`, a prefix, or an escaped representation of either. No direct writer call on the event-loop thread, no `app.copy_to_clipboard` dispatch, no second tail schedule, no notification before the non-NUL writer result, and no import from `app.py`. Do not sanitize or refuse any other C0 character, markup, ESC/BEL/OSC-like text, or LF. Update this function's docstring Data Flow/Dependencies to name the capped-NUL refusal, base mirror, one executor write, success/cut/failure notices, and all four box actions plus the group-A override as callers.
module: s19_app/tui/os_clipboard_input.py
modify: [Data: App._clipboard] (replace); [I/O: terminal] (append); [I/O: Windows clipboard] (replace); [I/O: user notices] (append)
examples: (R-COPY.1/1, R-COPY.2/1, R-COPY.7/3, R-COPY.10/1) WinCI, view `S3`, Ctrl+C → separate read and app clipboard equal `S3`; base/write/OSC 52 counts `1/1/1`; exactly one information `Copied 3 lines to the clipboard.`; override/tail counts `1/1`
examples: (R-COPY.12/1, R-COPY.2/2, R-COPY.10/2) WinCI, the same `S3`, button-3 press and release posted back to back → the same clipboard, OSC 52, and one-notice result; the release cannot change the already captured payload
examples: (R-COPY.12/6) WinCI, cross-view `S6`, right-click on the A2L part → separate read equals all of `S6`, including `stats_first` before `a2l_first`, one write and one notice; the clicked fragment alone is a failed oracle
examples: (R-COPY.12/7) WinCI, `S3` captured before posting press/release with no pause → separate read still equals `S3`; app override 1, tail 1, writer 1
examples: (R-COPY.4/1, R-COPY.7/1, R-COPY.10/3) WinCI, A2L row 3 while row 1 is highlighted → separate read/app clipboard/OSC 52 payload exactly `ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING`, with no glyph or tab; one write and one `Copied 1 line to the clipboard.`
examples: (R-COPY.4/2) WinCI, MAC row 3 → exactly `Curve_ExternalAxis`; (R-COPY.4/3) row 5 while row 2 is highlighted → row 5's full mapped tag, neither row 2's name nor a shortened painted cell
examples: (E3-03, R-COPY.4 raw-name arm) WinCI, A2L model row `HOSTILE` with a deliberately different U+FFFD painted projection → app clipboard, decoded OSC 52, and separate read each equal the exact raw `HOSTILE`, including `[red]`, ESC/BEL/OSC-like text, and LF; base/write/OSC 52 counts `1/1/1`; exactly one information `Copied 2 lines to the clipboard.`; no additional terminal sequence and no raw/prefix/escaped payload in any log record
examples: (E3-03, R-COPY.4 forced-PowerShell arm) WinCI, wrap the one tail writer call so it delegates to the unchanged writer with `strategies=(("powershell", _write_via_powershell),)` for the same `HOSTILE` → win32 strategy 0, PowerShell strategy/process 1, tail writer 1; argv is only the absolute system executable plus the existing static `_POWERSHELL_WRITE_COMMAND`, with no payload, and stdin is exactly `HOSTILE`; app clipboard, decoded OSC 52, and separate read equal `HOSTILE`; one two-line information notice, no extra terminal sequence, and no payload logs
examples: (R-COPY.7/4) WinCI, single-line `abc`, Ctrl+C → base/write/OSC 52 `1/1/1`, exactly one information `Copied 1 line to the clipboard.`, override 0, box value and selection unchanged
examples: (R-COPY.7/5) WinCI, multi-line `L1\nL2\nL3`, Ctrl+C → one write and exactly one information `Copied 3 lines to the clipboard.`, override 0, document unchanged
examples: (R-COPY.7/6) WinCI, single-line `abc`, Ctrl+X → one write and one `Copied 1 line to the clipboard.`, box empty, override 0; repeat on `CappedTextArea` selection and line-cut routes → the same cardinality and one result notice per cut
examples: (R-COPY.7/7) WinCI, single-line selected `abc`, Inc 1a right-click route → one tail entry, one write, one information notice; no group-A view copy and no second notice
examples: (R-COPY.2/4, R-COPY.7/8, R-PASTE.9/101, R-PASTE.9/102, R-PASTE.9/103) Linux, clear notices then fail a view-key copy, a view-right-click copy, and a row-right-click copy in turn → per gesture app clipboard holds the copied text and OSC 52 count is 1, writer count is 1, `Copied…` count is 0, and exactly one warning says `Clipboard write failed — copied inside the app only.` with timeout `6.0`
examples: (R-COPY.8/1, R-COPY.8/2, R-COPY.9/1, R-COPY.9/2) WinCI, `J75210` selected with F7 then copied by Ctrl+C, and separately by right-click → app clipboard, decoded OSC 52, and separate read each have length `65536` and equal `J75210[:65536]`; one write; exactly one information `Copied the first 65,536 characters to the clipboard (75,210 in all).`; zero ordinary copy notices
examples: (R-COPY.8/1 boundary) `P65536` reaches base/writer uncut and produces the ordinary one-line notice; `P65537` reaches both as exactly 65,536 x characters and produces `(65,537 in all)`, proving `>` rather than `>=`
examples: (R-COPY.9/1 failure arm) over-cap `J75210` with a failing writer → no cut or ordinary success notice, only the one existing failure warning; a cut notice is conditional on a successful capped write
examples: (E3-02 view refusal) WinCI, seed app/OS with `SEED-APP-1b`/`SEED-OS-1b`, then copy `NUL3` from a view by Ctrl+C and separately by button 3, and from an A2L row by button 3 → per gesture override/tail `1/1`, base/writer/OSC 52/process/helper `0/0/0/0/0`, zero success notices, exactly one 6.0-second warning `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.`, exactly one WARNING `OS clipboard copy refused; payload contains NUL`, both seeds intact, and no payload/prefix/escaped payload logged
examples: (E3-02 direct-box refusal) Repeat independently for `OsClipboardInput` and `CappedTextArea`, selected `NUL3`, Ctrl+C, right-click copy, and Ctrl+X → per gesture override 0, tail 1, base/writer/OSC 52/process/helper 0, the same one fixed warning/WARNING, zero success, both seeds intact; copies preserve value/selection, while each local cut stays deleted and is not restored by refusal
examples: (E3-02 after-cap boundary) WinCI, view and each direct box class copying `NUL_AFTER` → no refusal; base/write/OSC 52/helper counts `1/1/1/1`, app clipboard/decoded OSC 52/separate read each exactly `P65536`, zero refusal warnings, and exactly one information `Copied the first 65,536 characters to the clipboard (65,537 in all).`; checking `original_text` instead of `capped_text` makes this arm RED
examples: (E3-02 mutation controls) Move the guard after the base or writer, call the helper, emit ordinary/cut success, sanitize NUL, or interpolate the payload into either fixed message → respectively nonzero sink counts/changed seeds, helper count 1, forbidden success, altered OS content, or exact-message/log-absence assertions go RED
examples: (R-PASTE.9/1 regression) Linux, single-line and multi-line boxes, copy and cut with a non-empty selection in each class → each of the four gestures mirrors its exact selected text, calls the writer once, emits zero `Copied…` notices, and emits exactly one `Clipboard write failed — copied inside the app only.` warning with timeout `6.0`; each local cut stays deleted
examples: (R-PASTE.12/1) Linux and WinCI, single-line and multi-line boxes holding `P70000`, Ctrl+C in each → app clipboard and decoded OSC 52 are each `P70000[:65536]`; one write and one information `Copied the first 65,536 characters to the clipboard (70,000 in all).` per copy
examples: (R-PASTE.12/2) WinCI, the same two box copies → separate read is `P70000[:65536]` in each class, with the kept prefix independently asserted
examples: (R-PASTE.12/3) Linux and WinCI, the same payload copied by each class's right-click route → app clipboard/OSC 52 and WinCI separate read are each capped identically; one write and one cut notice per copy
examples: (R-COPY.7/6 over-cap arm) WinCI, `P70000`, Ctrl+X in each box class → local selection deleted, one write, and exactly one information `Copied the first 65,536 characters to the clipboard (70,000 in all).` per cut; no ordinary copy notice
examples: (R-PASTE.10/101, R-TUI-043.13/101) Linux, copy `SECRET-COPY-43` with a failing writer → WARNING records include the exact tail line and the writer cascade line, while no record contains `SECRET-COPY-43` or its first 16 characters
examples: (R-TUI-043.13/101 success arm) WinCI, DEBUG log capture during successful view-key, view-right-click, and row-right-click copies of `SECRET-COPY-43` → every route writes the exact payload once, and no log record contains the payload or its first 16 characters
examples: (R-PASTE.13/101) WinCI, 8-second held clipboard, row-name copy → writer returns `False` and the one failure warning appears within `timing_bound(2.5)` seconds of the gesture (`5.0` seconds on CI); no success/cut notice and no extra retry/write
examples: (R-PASTE.14/101, R-PASTE.14/102, R-PASTE.14/103) WinCI, held clipboard and a 50 ms timer during view-key, view-right-click, and row-right-click copies → writer runs off the event-loop thread and every tick until completion is late by at most `timing_bound(0.1)` seconds; one write/notice per gesture
examples: (AT-I1b-6/2, cited R-PASTE.1) WinCI, right-click a two-line JSON selection, separately read the OS result, then post that text as one terminal `events.Paste` to empty single-line T1 → T1 contains exactly the selection's first line once, with no second line and no duplicated text; the tail's emitted OS artifact, not a direct helper injection, is the paste input

write_os_clipboard
req: R-COPY.1, R-COPY.4, R-COPY.8, R-COPY.12, R-PASTE.9, R-PASTE.10, R-PASTE.12, R-PASTE.13
in: str text; tuple[tuple[str, Callable[[str], bool]], ...]? strategies = None
out: bool written
func: **unchanged context.** Existing blocking cascade at `os_clipboard_input.py:638-695`: cap once, try ordered strategies, return `True` at first success, otherwise log the cascade WARNING and return `False`; no app mirror, notice, executor, or second public entry is added here. The tail is its only new caller path in this delta.
module: s19_app/tui/os_clipboard_input.py
examples: (R-COPY.8/1 neg) removing only the tail cap still leaves this writer's defensive cap, so the OS read can remain correct while app clipboard/OSC 52 wrongly hold `J75210`; those two independent surfaces must go RED
examples: (R-PASTE.13/101 neg) retrying Win32 until the 8-second holder releases → warning at about 8 seconds, one held-clipboard timing assertion RED

OsClipboardInput.action_copy
req: R-COPY.7, R-PASTE.12
in:
out: None
func: **unchanged context.** At `os_clipboard_input.py:891-916`, empty selection raises `SkipAction`; otherwise await the tail once. Copy does not modify value or selection. Right-click copy reaches this same action, not the group-A override.
module: s19_app/tui/os_clipboard_input.py
examples: (R-COPY.7/4 neg) routing this action through `self.app.copy_to_clipboard` after the tail → override entries greater than 0, two base/write/notice effects or recursion → cardinality assertions RED

OsClipboardInput.action_cut
req: R-COPY.7, R-PASTE.12
in:
out: None
func: **unchanged context.** At `os_clipboard_input.py:918-944`, preserve local deletion and empty-selection `SkipAction`; await the tail once with the captured text. Clipboard failure does not restore the deleted text.
module: s19_app/tui/os_clipboard_input.py
examples: (R-COPY.7/6 neg) suppressing the tail for cuts → box empty but writer 0 and notices 0 → RED; adding a second tail to report the cut → writer 2 and notices 2 → RED

CappedTextArea.action_copy
req: R-COPY.7, R-PASTE.12
in:
out: None
func: **unchanged external context.** At `capped_text_area.py:242-270`, empty selection raises `SkipAction`; otherwise await this module's tail once. No edit to `capped_text_area.py` is authorized in this group.
module: s19_app/tui/capped_text_area.py
examples: (R-COPY.7/5) three lines copied through this action produce one tail entry, one write, one OSC 52 request, and one `Copied 3 lines to the clipboard.`; document unchanged

CappedTextArea.action_cut
req: R-COPY.7, R-PASTE.12
in:
out: None
func: **unchanged external context.** At `capped_text_area.py:272-308`, preserve read-only return, selection/line deletion, and exactly one direct tail await with `edit_result.replaced_text`. No new notice or writer belongs in this action.
module: s19_app/tui/capped_text_area.py
examples: (R-COPY.7/6) a multi-line selection cut and a cursor-line cut each produce one write and one information result; read-only and failed edit-result routes produce no copy effects

OsClipboardInput._on_paste
req: R-PASTE.1
in: events.Paste event
out: None
func: **unchanged context.** Existing terminal-paste first-line behavior at `os_clipboard_input.py:834-859`; it is a consumer in the acceptance chain, not a new clipboard writer and not changed by this delta.
module: s19_app/tui/os_clipboard_input.py
examples: (AT-I1b-1/2, cited R-PASTE.1) copy `S3` through the real tail, separately read it, and post the read text as a terminal paste → single-line T1 holds only `S3.split("\n", 1)[0]` once; this assertion consumes the OS artifact rather than trusting the copy helper's own report

## Edges

S19TuiApp.copy_to_clipboard ──▶ _mirror_and_write_os_clipboard
when: group A schedules exactly once for a view-selection or row-name copy; the override itself does not mirror, write, or notify
OsClipboardInput.action_copy ──▶ _mirror_and_write_os_clipboard
OsClipboardInput.action_cut ──▶ _mirror_and_write_os_clipboard
CappedTextArea.action_copy ──▶ _mirror_and_write_os_clipboard
CappedTextArea.action_cut ──▶ _mirror_and_write_os_clipboard
when: all four box actions enter directly and await once; none passes through S19TuiApp.copy_to_clipboard
[Data: _CLIPBOARD_CAP_CHARS] ──▶ _mirror_and_write_os_clipboard
[Data: _CLIPBOARD_CAP_CHARS] ──▶ _copy_notice_text
_mirror_and_write_os_clipboard ──▶ [Data: App._clipboard]
when: non-NUL capped_text only; exactly one unbound toolkit base App.copy_to_clipboard call; a capped-NUL refusal returns before this edge and preserves the app seed
_mirror_and_write_os_clipboard ──▶ [I/O: terminal]
when: the same single non-NUL base call emits one OSC 52 request; capped NUL emits zero and hostile raw text adds no terminal sequence
_mirror_and_write_os_clipboard ──▶ write_os_clipboard
when: non-NUL capped_text only; exactly one call in the default executor, never inline on the UI thread; capped NUL emits zero writer calls/processes and preserves the OS seed
write_os_clipboard ──▶ [I/O: Windows clipboard]
_mirror_and_write_os_clipboard ──▶ _copy_notice_text
when: the non-NUL awaited writer returned True; pass original_text, never capped_text, including an after-cap NUL suffix; capped NUL never reaches this edge
_copy_notice_text ──▶ [I/O: user notices]
when: exactly one information notice; over-cap text selects the cut form instead of the ordinary form
[Data: _WRITE_FAIL_NOTIFICATION] ──▶ _mirror_and_write_os_clipboard
_mirror_and_write_os_clipboard ──▶ [I/O: user notices]
when: disjoint arms: non-NUL writer False emits exactly one existing 6-second warning and zero Copied notices; capped NUL emits exactly one 6-second warning `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.` and zero Copied notices before any sink
[I/O: Windows clipboard] ──▶ OsClipboardInput._on_paste
when: acceptance only, through the existing read route and a terminal Paste event; unchanged consumer
