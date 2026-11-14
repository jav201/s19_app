# Inc 1b E5 final re-review (PENDING P-101)

- **Reviewer:** code-reviewer, claude-opus-5-5, one pass (DF-03). Code and security lens; read-only toward the diff.
- **Reviewed tree:** `53bd5fc8` (pushed tip). Record commit `290d80ae` read for its claims only.
- **Range:** `541a3d50..53bd5fc8`. `541a3d50` is the squash that carries the last E5 reviews (`E5-rereview-*.md`, `E5-final*-review-*.md`); every later commit is a WinCI fix, a diagnostic or a record.
- **Verdict:** **PASS-WITH-NOTES** (record token: *OK to advance*, with notes). No HIGH. One MEDIUM and three LOW, all routed to PENDING (DF-03).

## 1. Scope read in full

| File | Lines changed | Kind |
|---|---|---|
| `s19_app/tui/app.py` | +5 (`_schedule_a2l_filter_refresh._apply_filter`, line 22188) | product: the P-002 guard |
| `tests/test_b103_a2l_filter_teardown.py` | +66 (new) | regression R-COPY.26/1 |
| `tests/support/b103_clipboard.py` | `arm_tick_lateness` window plus `trace` | F-1 window (bf43ec2f) |
| `tests/support/b103_artifact_safety.py` | `HOSTED_RUNNER_ACCOUNT` lookahead | F-3 scanner (bf43ec2f) |
| `tests/test_b103_copy_paste_matrix.py` | `_assert_copy_notice` waits for the notice | F-2 (bf43ec2f) |
| `tests/test_b103_clipboard_windows.py` | `t_start` / `t_end` stamps | F-1 window |
| `tests/test_b103_clipboard_tail.py` | +452 / −58 | C1, C2, sampler, GC hook and freeze, R-PASTE.13/101 diagnostic |
| `tests/support/b103_winci_gate.py`, `b103_winci_manifest.json`, `tests/test_b103_winci_gate.py`, `tests/test_id_registry.py` | population 256 → 260, scanned files 307 → 308 | census pins |

## 2. Checks

| # | Check | State | Evidence |
|---|---|---|---|
| C-1 | Only one product change | executed | The diffstat outside `.dev-flow/` shows `s19_app/` = `app.py` +5 only: a docstring bullet and `if not self.is_running: return`. |
| C-2 | Guard covers the whole teardown window | executed | In Textual 8.2.8 `App._shutdown`, `self._running = False` runs before `_close_all()` prunes the screens. A debounce that fires during any later `await` of shutdown sees `is_running False`. No `await` sits between the guard and the synchronous `_refresh_a2l_filtered_tags`. |
| C-3 | No assertion weakened | executed | Every removed `_require` / `assert` comes back with the same condition. Only the messages grow (`_failure` line 362; `_assert_responsive`). The bound stays `timing_bound(0.1)`, and the ≥ 10 ticks rule is unchanged. Three changes narrow what is measured, and each is a recorded decision, not a silent change: (a) the tick window `[t_start, t_end]` (`b103_clipboard.py:597`; R-PASTE.14 says "while writing", E3A-11 (c)); (b) the sleep-poll wait plus `gc.collect(); gc.freeze()` (`test_b103_clipboard_tail.py:2555`, `:2569`; the operator's option 2, with BL-I1B-GC-1 in the backlog); (c) C2 is report-only (operator decision (a), and it is not an obligation). `gc.freeze()` takes only the heap that existed before the gesture out of GC. Allocations the product makes in the window are still collected and timed. |
| C-4 | The manifest still has 108 obligations | executed | I extracted the obligation entries of `b103_winci_manifest.json` at `541a3d50` and at `53bd5fc8` and diffed them: the set is IDENTICAL, 108 entries with 108 unique requirements. The new entries `test_r_paste_14_c1_…[key|right|row]` and `test_r_paste_14_c2_…` carry no obligation. The loader still requires `obligations == 108` (`b103_winci_gate.py:284`). |
| C-5 | Diagnostics cannot change product behaviour | executed | `_r13_diag_install` wraps `_mirror_and_write_os_clipboard` in the same three modules where `_instrument` already put `tail_spy`, so the product routing is unchanged: `app.py:23205` and `capped_text_area.py:270/308` call the module name. It also wraps `write_os_clipboard`, `app.notify` and `app._notifications.add`. All are pass-through, with the same arguments, return value and exceptions. The snapshots and `_responsive_report` read only (`time_left`, `has_expired` and `_notice_rows` are pure reads). `_trace_screen_spans` and `message_hook` time and count only. `_StallSampler` reads `sys._current_frames()` from a daemon thread. Its only effect is microseconds of cost, which can only push lateness up (fail-safe). The R-PASTE.13/101 `except AssertionError` re-raises with the message extended. Skips and other exception types propagate unchanged. The post-observe `_settle(pilot, 2)` runs after `obs` is captured. |
| C-6 | Diagnostics leak no paths | executed | `_frame_module` returns a dotted name relative to the repo, site-packages or the stdlib, else the basename, never a path. Notices are cut to two alphabetic words. The R-PASTE.13/101 text keeps 40 characters of each message, with no payload. Any user path that slipped through would still fail the artifact scanner (fail-closed). |
| C-7 | The F-3 scanner exemption is narrow | executed | Only the whole segment `runneradmin`, case-insensitive, followed by a separator, a quote or the end, is exempt. `runneradmin2`, `runneradmins` and `person` stay RED (canaries in `test_b103_winci_gate.py`). WSL and Unix forms got no exemption (fail-closed). |
| C-8 | Records carry no hosts, accounts or home paths | executed | Delta `541a3d50..290d80ae`, diff plus commit messages: the PP-02 pattern 0 hits; the local needle list 0 hits (counted, not printed). Path forms in the added record lines are only `~/work/…` and `C:/Users/<runner>/…` or `person` (PP-03 tokens). |
| C-9 | DF-06 redaction and manifest checks | executed | Run on the Linux runner, in a scratch clone of `53bd5fc8`, in the HT-02 env. Output in §4. Scratch deleted. `evidence-e4/refresh_manifests.py` was not run. |

## 3. Independent coverage of the changed product function (read, not run)

| Product function | Mutation | Killing test | Why it dies |
|---|---|---|---|
| `S19TuiApp._schedule_a2l_filter_refresh._apply_filter` (`app.py:22188`) | guard removed | `tests/test_b103_a2l_filter_teardown.py::test_r_copy_26_1_filter_refresh_due_after_teardown_is_dropped` | The last `captured[0]()` runs after `run_test` closed the app and the table is gone (asserted with `pytest.raises(NoMatches)`), so it raises `NoMatches`. Worker record: RED on `8e778f8a`. |
| same | guard inverted, or always return | same test, positive arm | The callback captured while the app runs must set the summary to `No A2L tags match 'KEEP'.`. The worker record shows the always-drop mutant RED. |
| same | the guard put after `_refresh_a2l_filtered_tags` | same test | Same as "removed": the refresh queries the missing table first. |
| (unchanged) token check | — | `tests/test_b102_a2l_refresh.py` (pre-existing) | Not in this delta. |

No other product function changed. The test-support changes are not product, but here is what kills them. A widened F-1 window is fail-safe: more ticks count, so the gate only gets stricter. A narrowed or empty window fails the ≥ 10 ticks rule on WinCI. Removing the F-3 lookahead fails `test_artifact_scanner_allows_only_the_hosted_runner_account`. Dropping its segment boundary fails the `runner-prefix-account*` canaries.

## 4. DF-06 outputs (scratch clone of `53bd5fc8`, Linux runner, HT-02 env)

```
=== redact_e5 --check
EXCEPTION matrix/contract_probe.py retained=5
EXCEPTION quit/validate_routes.py retained=2
EXCEPTION legacy/redaction_runtime_probe.py retained=1
REDACTION_CHECK PASS files=295 residual=0 exceptions=8
rc=0
=== refresh_manifests --check
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/SHA256SUMS.txt files=25 sha256=bbcefa31254ca7e2b51af7dfc9cc68192136e0a2cd5cd862df75cfde11b5378f
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/legacy/SHA256SUMS.txt files=8 sha256=d8ab101b346d0c65c687a2ae8a8120960d08598395a8f7a143135c6ce9465aeb
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/matrix/SHA256SUMS.txt files=22 sha256=5eba5f5be565e626d7a80c3eb54b1c4abd9fc94ae9ef801ce241fab4aca39707
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/mutants/SHA256SUMS.txt files=5 sha256=ebf353322fe1c9e08439cbbda3da0bc391b6f04a9e7677a7d80b567bed8c7c91
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/quit/SHA256SUMS.txt files=7 sha256=b36c0acc6553f78be8aee16539545200042f8c21088f1181929ae685fed609e1
MANIFEST_VERIFY PASS .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/tail/SHA256SUMS.txt files=16 sha256=0596023ba9a594cdf1a8560fbed0b4c82979abb6d61d58eaff55fffb72147934
MANIFEST_VERIFY_RESULT PASS manifests=6 files=83
rc=0
```

The clone's `git status` after both checks showed 0 changed files. `redact_e5.py` scans only `evidence-e5/`. The newer records (`E5-winci-*.md`, `evidence-e5-r2/`, `evidence-e5-r4/`) are covered by C-8 instead.

## 5. Findings (all to PENDING; none blocks)

- **RR-1 (MEDIUM: the test can fail with no product fault; it gives no false confidence)**
  - **Where:** `tests/test_b103_clipboard_tail.py:2285-2293`.
  - **What:** R-PASTE.13/101 reads the notices in `_observe` as soon as `_wait` sees `tail_done`. `App.notify` only posts `Notify`. The `53bd5fc8` diagnostic tally (9 runs) shows the notice arriving within about 16 ms of `tail_end`.
  - **Why this node:** /101–/103 call `_settle(pilot)` after their wait (line 2570), and the F-2 matrix fix waits for the notice (`test_b103_copy_paste_matrix.py:292`). This node does neither.
  - **Consequence:** this is the likely mechanism of the `observed_warnings=[] notices_seen=[]` failures on `3c064348` (2/10). It agrees with H5 in `E5-winci-r13-101-diagnostic.md`, which is not yet proved.
  - **Fix:** after `elapsed` is taken, wait for the warning the way F-2 waits (bounded), then observe. The 2.5 s timing stays unaffected.
- **RR-2 (LOW)**
  - **Where:** `tests/support/b103_clipboard.py:597`.
  - **What:** no Linux unit control pins the `[t_start, t_end]` window. Narrowing it is caught only on WinCI, by the ≥ 10 ticks rule.
  - **By design (E3A-11 (c)):** a loop block between the gesture and the writer's start is outside R-PASTE.14. An inline writer is still caught by the `writer_threads` check.
- **RR-3 (LOW)**
  - **Where:** `tests/test_b103_clipboard_tail.py`, the R-PASTE.13/101 wrappers.
  - **What:** `raise AssertionError(...) from None` drops the original traceback.
  - **Impact:** the message stays unique per `_require`, so diagnosis is not lost; only the line number is.
- **RR-4 (LOW, records)**
  - **Where:** `inc-1b/steps.log`, entries 2026-11-13 06:31 and 06:32.
  - **What:** they record `redact_e5 --check … files=304`. The committed `evidence-e5/` is identical at `541a3d50` and `53bd5fc8`, with 297 tracked files, and the check reports `files=295`. The earlier count included untracked files from that working tree. Residual is 0 either way.
  - **Fix:** do not edit those lines (PP-06). Note the reconciliation forward.

## 6. Packet §4b cell

`code-reviewer` · OK to advance (PASS-WITH-NOTES) · no HIGH; RR-1 (MEDIUM) and RR-2…RR-4 (LOW) to PENDING; 108 obligations unchanged; DF-06 checks PASS.

## 7. RR-1 fix (relevo-10)

**Ruling:** DF-04 (a), a test defect fixed to the requirement. WinCI evidence `E5-winci-53bd5fc8-n10-2.md` (commit 0dd75cd3): in both failing captures `App.notify` had returned while the Notify message was still queued (`raw_count=0, queue_size=2`) when the test read the notices; the notice appeared at `snap_settled`. H5 (test-side race), not a product defect. Rate 2/19 with the diagnostic.

**What changed** (`tests/test_b103_clipboard_tail.py::test_r_paste_13_101_held_row_copy_warns_within_bound`, 9 lines, no product change): after the writer/tail wait, a second `_wait` (the file's own `pilot.pause()` loop, 20 ms sleep + pause, timeout 10 s) polls `_notice_rows(app)` until the `WRITE_FAIL` warning is present. `elapsed` is now taken after that wait, from the same `started`, so the 2.5 s bound covers the notice. The `r13_101_diag` property gains `notice_wait_s`.

**Why not weaker:** the bound, the `report_margin` comparison, `_failure` (text, severity `warning`, timeout 6.0, exactly one warning, no success notice) and the writer count are untouched. A notice that never arrives still fails (wait times out); one that arrives after 2.5 s fails the bound.

**Controls** (rtx scratch `~/work/zq-y1/`, HOME `<runner-home>`, `s19_app.__file__` printed, `timeout 300`). The node is WinCI-only (`_winci_ready_or_skip` skips on Linux; the OS holder is Windows), so the controls ran through a scratch-only Linux seam that stubs the Windows holder/probe and forces `writer_result=False`, then calls the unmodified test function:
- (a) product mutant dropping `app.notify(_WRITE_FAIL_NOTIFICATION…)`: FAIL (`fixture predicate not satisfied before timeout`, `notify=[]`).
- (b) `App.notify` delayed 3.5 s: FAIL (`elapsed 3.709 s > 2.5`).
- (c) unmutated: PASS (0.782 s of 2.500 s).
- (d) notify delayed 0.5 s (inside the bound; the queued-notice case): PASS (0.763 s).

**Not run:** the real WinCI node (held Windows clipboard) cannot run on Linux; it is confirmed only by the next WinCI N>=10 (HT-07).
