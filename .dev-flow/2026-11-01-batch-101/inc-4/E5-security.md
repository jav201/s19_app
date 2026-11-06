# Inc 4: E5 security review (implemented code)

Batch 2026-11-01-batch-101, increment 4, branch head `149e3bf`, base `b7b77c4`. Stage E5 of `dev-flow-v3-beta`, security lens. Scope: `git diff main...HEAD -- s19_app` (`app.py`, `changes/io.py`, `services/change_service.py`, `services/variant_execution_service.py`), read against `E3-security.md` (S4-1 … S4-9), `E3-rulings.md` and `E4-integration-notes.md`.

Where the probes ran: on the LAN Linux host, `s19ci` Python 3.11 with `-I`, in a detached worktree of `origin/main` `f9f3cb09` (no difference from `b7b77c4` under `s19_app/`, `tests/` or `tools/`). The local `git diff b7b77c4 149e3bf` was applied on top. The md5 sums of the four source files matched `149e3bf`. `s19_app.__file__` printed the worktree path. The worktree and every probe directory were removed afterwards. Nothing ran on the Windows PC. The probe scripts carried the `s4sec_` prefix and are not committed. Evidence state of every probe line below: `executed`.

## Verdict

**OK to ship (PASS-WITH-NOTES).** No finding is HIGH or MEDIUM. Every property the brief asked for holds on the implemented code:

- An A2L, whether the session's or the project's, can only admit a symbol entry or refuse it. It never moves a write.
- Inc 4 does not widen S4-1 beyond what E3 recorded.
- Hostile names are escaped at every sink.
- A read builds the index at most once, and a document with no symbols builds none.
- The variant run cannot see the session A2L.

The findings are 1 LOW (record) and 4 INFO.

## Probe results (31 checks; 30 passed on the first run, and the one failure was a defect in the probe, fixed and re-run)

| # | Property | Result |
|---|---|---|
| P1a–d | Drift limb (`io.py:1061–1078`). Synthetic A2L with tag `SYM` at 0x1000, length 4. A match is admitted at the declared address with the declared bytes. Address +4, address −1, length 8 and length 2 are each refused with `CHG-SYMBOL-VALUE`. A case or whitespace variant of the name resolves to the A2L spelling and leaves the write unchanged. With two tags of the same name, the first wins and the second cannot admit an entry. | pass |
| P1g | Fuzz: 1 500 random documents × 6-tag A2Ls. 331 entries were admitted. None of them carried an address or bytes other than its own declaration, and none differed from its resolved tag. | pass |
| P1h | `parse_a2l_file` on the case-08 A2L (462 tags) emits `int` or `None` for every address and length (`a2l.py:2509–2525`, `int(…, 0)`). | pass |
| P4d | Hostile **linked** A2L outside the project, with the two demo symbols' addresses shifted by +0x40. The variant run refuses both entries (`CHG-SYMBOL-VALUE … drifts from the declared address`), and the apply gate blocks the document. No byte is written at the shifted addresses. (On the first run the probe failed to shift the inline `VALUE 0x00805960` form, because its replace did not match the zero-padded spelling. Re-run with the padded spelling: pass.) | pass |
| P2a–b | The hostile name `[b]Ev<BEL>il\|`<i>&<ESC>[31m<RLO>*_#` survives the real A2L parser. A variant run then applies the matching entry, and `ChangeEntry.symbol` carries the A2L's spelling. | pass |
| P2c | Variant report row (`report_service.py:1918`, `md_safe`): no raw C0, C1 or bidi character. `[ ] \| ` < > & * _ #` are each escaped. | pass |
| P2d–e | A2B Diff addendum, Markdown (`_md_text`) and HTML (`_esc(_strip_ctl(…))`) cells: no raw control character, and `<` and `&` are entity-escaped. | pass |
| P2f–h | Findings: the drift refusal that names the A2L tag, and the no-A2L refusal that names the document symbol. Both come through `repr` (`\x07`, `\x1b`, `‮` spelled out), and `safe_text(...).plain` leaves no control character. The status-log labels are `markup=False` (`app.py:3422–3425`), and so is `#diff_status` (`screens_directionb.py:8273`). | pass |
| P2i | The JSON record serializes the name with every control character escaped. | pass |
| P3a | 1 000 symbol entries × 220 040 tags: index built **once** per read, in 0.140–0.147 s (3 runs). | pass |
| P3b, P3e | A document with no symbol entries, or whose `symbol` values are not strings, builds **no** index. | pass |
| P3c | Symbol entries with no A2L: one index call at most, and that call returns `None` (the `index_built` flag, `io.py:901`). | pass |
| P3d | 5 000 and 10 000 symbol entries × 220 040 tags: the index is built once per read. A symbol read costs 2.01 s and 7.76 s. The same document with plain entries and no A2L costs 1.95 s and 7.67 s. The pre-existing collision check alone takes 1.86 s and 7.60 s, which is the whole cost (see E5S4-3). | pass |
| P4a | `execute_project_variants` has no A2L parameter. Its only A2L source is `validate_project_files` (`variant_execution_service.py:2758`). `app.py` passes no session data to it at `:6059` or `:6589`. | pass |
| P4b | A project with no A2L file and a symbol document: both symbol entries are refused with the no-context finding, and none is applied. | pass |
| P4c | S4-1 still open as recorded: a `firmware.a2l` link to a file outside the folder is returned as the project's A2L. | pass (open, recorded) |

## Findings

| Id | Tag | Severity | Where | Scenario | Recommendation |
|---|---|---|---|---|---|
| E5S4-1 | design-gap | LOW | `.dev-flow/BACKLOG-CODE.md` (no row); `workspace.py:2139` `validate_project_files`; `variant_execution_service.py:2758` | **Inc 4 does not widen S4-1.** The diff adds no A2L discovery path. The project's A2L still comes from `validate_project_files` only, and the A2L is parsed once per plan (`:2665`), as on base. The only change is the new consumer, which E3 recorded: the parsed payload is passed as `a2l_context` to each per-file read (`:2558`). P4d shows the bound: a hostile linked A2L can refuse entries but cannot move them. The definition note is in `01-requirements.md:27`. **However**, the backlog row that the E3 ruling S4-1 requires (refuse a link or reparse point through `lstat`, with a planted-link test, routed with Inc 9 S8-1/S8-2) is only "forwarded" (`E4-integration-notes.md` §8). It is not in `BACKLOG-CODE.md` on this branch. | Land the row in `BACKLOG-CODE.md` before Inc 4 closes, so that the open state is a record and not just a note. No code change in Inc 4. |
| E5S4-2 | design-gap | INFO | `io.py:1061–1066` (drift limb, unchanged by Inc 4) | The length test runs only when the tag's `length` is an `int` that is not a `bool`. A synthetic `a2l_context` whose length is `True`, `4.0` or `"4"` admits a 9-byte entry. With a string `address` and a matching declaration, the drift message's `int(tag_address)` raises `ValueError` out of the read. Neither case is reachable through `parse_a2l_file`, which emits only `int` or `None` (P1h). Even when admitted, the write is still the document's declared address and bytes (P1e), so no write moves. | None in Inc 4. If an A2L source other than `parse_a2l_file` is ever introduced, treat a non-`int` address or length as unresolved in `_resolve_symbol_tag`. |
| E5S4-3 | impl (pre-existing) | INFO | `changes/validate.py:45` `collision_issues` (outside the slice) | The read is bounded on the symbol side: O(tags + entries), with the index built once (P3a, P3d). The remaining cost of a large document is the **O(n²) collision check**, which runs on plain entries as well: 10 000 entries take 7.6 s, and the 100 000-entry ceiling (`MF_ENTRY_COUNT_CEILING`) projects to roughly 12 minutes. A probe at 100 000 entries was stopped after more than 10 minutes. Session reads run on the screen thread, so a hostile change document at the ceiling freezes the TUI. This is the same on base, with or without symbols. Inc 4 neither adds nor removes the cost: with an A2L, symbol entries now reach the collision check, but plain entries could always reach the ceiling. | Backlog: replace the pairwise loop with a sort-and-sweep pass (O(n log n)) and pin it with a test at the ceiling. Not this increment's defect. |
| E5S4-4 | impl | INFO | `app.py:5533–5547` (R-TUI-058.9 line) | The new line is a fixed string. Its condition requires `current_a2l_data is None`, the code `CHG-SYMBOL-UNRESOLVED`, and the `SYMBOL_NO_A2L_CONTEXT_TEXT` substring (`io.py:253`). A document symbol that spells the constant can only cause the fixed line in the no-A2L state, where it is true anyway. This confirms S4-5 on the code; the negative arm (A-5) is in the tests. | None. |
| E5S4-5 | impl | INFO | `change_service.py` (deleted `run_checks_for_project`); `changes/check.py:278` | Deleting the headless entry point removes one path-taking API. `grep` over `s19_app/` and `tests/` finds no remaining caller and no import. Only the stale docstring mention at `check.py:278` remains, which is already forwarded (S4-7). | None. |

## Checks of the E3 items on the code

- S4-2: implemented. R-CHG-SYM.11/2 unloads the session A2L before Execute scope (`tests/test_b101_symbol_reads.py:868`), and R-CHG-SYM.12 has the converse arm (`:959`). Together with P4a, the "session never reaches a variant run" claim is held both by structure and by tests.
- S4-3: holds (P3a, P3b, P3c). The call counter is the primary oracle in the tests (`:1038`).
- S4-6: the diff adds no new paint of `ChangeEntry.symbol`. The existing sinks escape the A2L spelling (P2c–P2e).

## Security review summary

- **Secrets / credentials:** none involved. No values printed.
- **External tools / data flow:** none. Local files only; nothing leaves the machine.
- **Auth:** not applicable.
- **Destructive surface:** variant runs write `<variant>-patched.s19` for documents with symbol entries. The save-back path is unchanged. The drift limb holds against a hostile session or project A2L, including a linked one (P1, P4d).
- **Supply chain / deploy:** no dependency or deploy change.

## Evidence checklist

- [x] Each finding has what · where · why · recommendation: the table above, E5S4-1 … E5S4-5.
- [x] Each finding has a severity: LOW ×1, INFO ×4.
- [x] No secret values in this report: none handled. No host, user or path of the host is named.
- [x] Verdict explicit: OK to ship (PASS-WITH-NOTES); no HIGH.
- [x] New tool / integration: `n/a — no external integration`.

Evidence states: probes P1–P4 `executed` (LAN Linux host, tree identical to `149e3bf` under `s19_app/`); E5S4-1 recommendation `planned` (record row); E5S4-3 `planned` (backlog); the rest `n/a — informational`.
