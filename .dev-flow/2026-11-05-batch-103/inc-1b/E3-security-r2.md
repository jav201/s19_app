# Inc 1b — E3 Security, round 2

## Verdict

**PASS-WITH-NOTES.** No **BLOCKER, HIGH or MAJOR** remains open. One **minor** implementation-binding note, E3R2-01, is explicitly routed to E4 below.

The original security findings **E3-01, E3-02 and E3-03 are closed**, and **E3A-02 is closed**. The behavioral correction for **E3A-01** is sound, subject to the minor import-binding addendum. This verdict is based on an independent reading of the corrected design and real source, not on the DeepSeek mechanical PASS or the lint.

## Scope and evidence

- HEAD: `6adb633711661f072113ffd601cf90ac34d2c26c`. The corrective design is present as uncommitted changes already supplied for review.
- Reviewed: `E3-rulings.md`, corrected `codewire/graph-inc1b.md`, `graph-app.md`, `graph-clipboard.md`, `01-requirements.md`, `02-test-cases.md`, `E2-interfaces.md`, and `evidence-e2/deepseek-census-final.txt`.
- Static source checks: `s19_app/tui/app.py`, `os_clipboard_input.py`, `capped_text_area.py`, and installed Textual 8.2.8.
- No tests, application runs, probes or clipboard writes were performed. Every ledger result remains `not_run`; this is a design/security verdict, not runtime certification.
- No artifact other than this new report was edited.

## Finding carried to E4

### E3R2-01 — minor — implementation binding: `textual.actions.SkipAction` needs an explicit import

**Label:** not a new security `design-gap`; a required E4 implementation/verification addendum.

**Evidence.** N1 mandates `raise textual.actions.SkipAction` (`codewire/graph-inc1b.md:166`; also `E2-interfaces.md:9`). The real `app.py` imports `events` and `work` from `textual`, plus individual symbols from Textual submodules, but binds neither the name `textual` nor `SkipAction`: `s19_app/tui/app.py:18-25`. No corrected artifact adds `import textual.actions` or `from textual.actions import SkipAction`. Textual's dispatcher continues the binding chain only for its actual `SkipAction` exception (`textual/app.py:4272-4289`), not for a `NameError` raised by an unbound qualified name.

**Impact.** A verbatim implementation without the import would fail only the newly added materialized-empty-selection arm before creating a worker, but would not deliver the intended idle body-B fallback. The limited, deterministic binding omission does not change the security design or justify MAJOR severity; it does require an explicit correction rather than assuming the mechanical PASS proves executability.

**Concrete E4 addendum.** Add `import textual.actions` beside the Textual imports in `app.py` and record that dependency in N1; the already specified `raise textual.actions.SkipAction` can then remain unchanged. As a required E4 assertion, `copy_to_clipboard("")` must raise `textual.actions.SkipAction`, never return normally and never raise `NameError`, before coroutine/worker construction. Re-run the designed idle and modal arms: idle opens one body-B dialog with zero clipboard effects; modal opens no second dialog and preserves both seeds.

## Verification of the corrective findings

### E3-01 — CLOSED: deferred valid-release copy, movement cancellation and reentry safety

The corrected N3 now separates capture from effect (`codewire/graph-inc1b.md:206-224`):

- Button-3 `MouseDown` captures text, `screen_offset`, screen and widget with `valid=True`, but never calls N1 on press.
- Any changed-offset `MouseMove` sets `valid=False` permanently; returning to the original cell cannot revalidate it.
- Every not-forwarded `MouseUp` moves the candidate to a local and clears `_right_gesture` **before** any possible N1 call. Only button 3, valid state, non-empty text and identical offset/screen/widget permit one copy.
- A new press replaces old state; mismatched, replayed and forwarded releases cannot copy. Every event, including cancelled and copied routes, still takes exactly one `await super().on_event(event)` path.
- Concrete negatives cover selection drag, row drag, out-and-return, changed context and reentry; the back-to-back positive preserves the pre-dispatch snapshot and copies once on release (`graph-inc1b.md:213-223`). The reentry example consumes the replacement candidate without copying and requires a fresh valid press/release for the next copy (`:222`).

The ledger independently defines the same state machine (`02-test-cases.md:18-19`) and gives discriminating cases: valid release/cardinality (`:74-75`), drag (`:67`, `:82`), exit-return (`:83`) and zero-notice controls (`:85-86`). This closes the unintended clipboard-write risk from round 1 without reintroducing the press/release race.

### E3-02 — CLOSED: exact capped-NUL refusal and after-cap behavior

The tail derives `capped_text` and tests it immediately, before base, writer or helper (`codewire/graph-inc1b.md:401-405`). On capped NUL it specifies:

- zero toolkit-base, writer, OSC 52, process and `_copy_notice_text` calls;
- zero ordinary/cut success notices and unchanged app/OS seeds;
- exactly one 6-second warning, `Clipboard copy refused — NUL cannot be represented in the Windows text clipboard.`;
- exactly one WARNING, `OS clipboard copy refused; payload contains NUL`;
- no raw payload, prefix or escaped representation in either message or any log.

The refusal and mutation examples are explicit for view and direct-box routes (`graph-inc1b.md:424-427`), and R-COPY.25/1…3 repeats the zero-sink oracle in the ledger (`02-test-cases.md:113-115`). Direct-box cuts preserve the already approved local-deletion semantics rather than restoring text (`graph-inc1b.md:425`).

The guard examines only the capped payload. NUL solely beyond character 65,536 follows the normal one-base/one-writer/one-OSC-52 route and retains the original total in the cut notice. The ledger's 65,537-character arm expects `(65,537 in all)` (`02-test-cases.md:115`); the graph's independently longer `NUL_AFTER = P65536 + "\x00TAIL"` arm expects `65,541` (`graph-inc1b.md:101`, `:426`). These are distinct, internally consistent fixtures, not a length discrepancy. On capped-NUL refusal the helper is never called; on after-cap success it receives `original_text` only to format the original length, and neither arm logs the payload.

### E3-03 — CLOSED: one exact hostile model payload, including forced PowerShell

`HOSTILE_NAME` in the ledger is:

`'[red]\x1b\x07\x1b]52;c;U0VFRF9PU0M=\x07\nSUFFIX'` (`02-test-cases.md:20`).

The integrated graph's `HOSTILE` is byte-for-byte the same escaped literal and is independently stored as the raw A2L model name, with one LF and no NUL (`codewire/graph-inc1b.md:102`). The expected value is never the U+FFFD painted projection.

The graph and ledger require exact equality of app clipboard, decoded OSC 52 and separate Windows read; one base/write/OSC 52 sequence; one `Copied 2 lines to the clipboard.` notice; no additional terminal sequence; and no payload/prefix in logs (`graph-inc1b.md:414-415`; `02-test-cases.md:125`). The forced-PowerShell arm invokes the unchanged writer with only its PowerShell strategy, requires Win32=0 and PowerShell/process=1, exact `HOSTILE` on stdin, and no payload in argv (`graph-inc1b.md:415`). This matches the real static `$input | Set-Clipboard` command and `shell=False` subprocess input (`s19_app/tui/os_clipboard_input.py:120-131`, `:441-456`). Exact WinCI transport remains an E4 observation, not a result claimed here.

### E3A-01 — behavior accepted, E3R2-01 import addendum required

Textual's `Screen.action_copy_text` raises only for `None` and otherwise forwards even `""` (`textual/screen.py:985-991`), so putting the empty-string skip in N1 is necessary and correctly located (`codewire/graph-inc1b.md:327`). The specified early raise precedes any worker and propagates to the binding dispatcher, which returns `False` for `SkipAction` (`textual/app.py:4272-4289`). Idle and materialized-empty modal oracles are concrete at `graph-inc1b.md:167-168` and `02-test-cases.md:90`, `:101`. The only residual is the import binding recorded above.

### E3A-02 — CLOSED: out-of-bounds padding cannot copy or select

N2 now rejects `out_of_bounds=True` before row-key/cell resolution even with a valid row index (`codewire/graph-inc1b.md:189`). N5 prevents the default and returns before cursor movement for the same flag (`:241`). The real toolkit emits exactly `{"row": row_index, "column": 0, "out_of_bounds": True}` for horizontal padding (`textual/widgets/_data_table.py:2350-2390`), so the guard addresses real metadata rather than a synthetic special case.

Negative A2L/MAC arms require zero copy/cursor/`RowSelected`/hex effects (`02-test-cases.md:84`). The same real cells with only `out_of_bounds=False` are positive copy/highlight/cardinality controls (`:75`; `graph-inc1b.md:242-243`). No residual copy-through-padding route was found.

## Supporting mechanical evidence and residual boundary

The DeepSeek final PASS accurately supports its literal/count checks, including the shared hostile literal and NUL observables (`evidence-e2/deepseek-census-final.txt:1-11`). It does not establish Python name binding, event-dispatch semantics or WinCI transport; those were reviewed separately above. Its unrelated `E1-slice.md` historical-wording note was not used as a security verdict input.

No additional HIGH/MAJOR/BLOCKER was found in no-reentry/cardinality, cap/original-length handling, text-box exclusion, modal/busy quit, existing process surfaces or payload logging. E4 must consume E3R2-01 and all corrected negative controls; this report claims no runtime PASS.
