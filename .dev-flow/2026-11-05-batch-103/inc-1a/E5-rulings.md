# Inc 1a: E5 rulings (2026-11-07, orchestrator Opus 5.5)

**Inputs:**
- Code review: PASS-WITH-NOTES.
- Security review: PASS-WITH-NOTES, with 1 MEDIUM, 2 LOW and 2 INFO.
- Mutants: 34 applied. 32 killed, 2 survived, and 10 not realisable because they are Windows-only and the Windows CI run is still pending.

All three reviews were run by DeepSeek.

| Item | Ruling |
|---|---|
| SEC-1 MEDIUM: `_own_write` without `surrogatepass` (`tests/support/b103_clipboard.py:596`) | **Fix (test).** Encode with `surrogatepass`, as E3S-26 says. R-PASTE.35/2 and /4 must not raise on WinCI. |
| SEC-2 LOW: the workflow guard lacks E3S-07(b)'s asserts | **Fix (test).** Assert no `cache:` and no job-level `permissions:`. |
| SEC-3 LOW: the E3S-25(c) marker is missing (exposure 0) | **Backlog** as BL-I1A-1. |
| SEC-4 INFO: the redaction gate is RED | It stays RED until the pre-push redaction sweep, as expected. |
| SEC-5 INFO: PowerShell stdout is unbounded | A residual we accept. |
| M-PASTE.10 survived: an oracle gap | **Fix (test).** Pin the row's exact WARNING text, not just "≥ 1 WARNING". |
| M-PASTE.6 survived | It cannot be observed on LinuxH. The WinCI arm kills it. Record it as `pending Windows CI`. |
| 3 failures: the A2L filter debounce fires after teardown (`NoMatches '#a2l_tags_list'`) | **Two sides.** (1) **Inc 1a, test:** each affected test lets the debounce settle, or clears the filter, before the app ends, so 1a's tests do not depend on a defect outside its slice. (2) **Product:** BD-1A-1 is routed to Inc 12, which guards the refresh when the table is absent, adds a case, and checks it against the base code. |
| 1 failure: `#search_input` right-click copy never fires (walk `[workspace]`) | **Fix (test).** The workspace walk needs a loaded file, through the `needs_project` path. If the cause turns out to be a product fault, stop and report it. |

**Next:**
1. Test-fix pass by DeepSeek in the tester role.
2. GREEN on cachyos under Xvfb.
3. `04-validation.md` and `trace_check`.
4. Merge into `batch-103`.
5. The redaction sweep and the push for WinCI.
