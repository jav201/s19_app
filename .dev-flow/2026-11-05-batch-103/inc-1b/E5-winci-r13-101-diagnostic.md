# R-PASTE.13/101 diagnostic instrumentation (P-001, test-only)

## Purpose

`test_r_paste_13_101_held_row_copy_warns_within_bound` failed 2/10 on 3c064348 and 1/10 on 7804b500 with `observed_warnings=[] ... notices_seen=[]` while the `_wait` on `writer_done and tail_done` returned normally. This change adds instrumentation only. Product code, assertions, the gate and the manifest (108 obligations) are unchanged. All new code is in `tests/test_b103_clipboard_tail.py`: three helpers (`_r13_diag_install`, `_r13_diag_snapshot`, `_r13_diag_text`) used by this one node. No shared helper changed, so every other node behaves identically.

## Source reading that shapes the hypotheses (Textual 8.2.8, the version the runner resolves; checked on the CI-equivalent Linux env)

- `App.notify` does NOT add to `app._notifications`. It builds a `Notification` (`raised_at = time.time()`) and calls `self.post_message(Notify(...))`. The notification enters `app._notifications` only when the app message pump runs `_on_notify` (`app.py` around lines 4620 to 4685).
- `Notifications` prunes lazily: `__iter__`, `__len__`, `add` and `__delitem__` call `_reap()`, which deletes entries where `has_expired` is true. `has_expired` is `(raised_at + timeout) - time.time() <= 0`, so the clock is the wall clock `time.time()`, not `monotonic`.
- The test's `_notice_rows` iterates `app._notifications`, so it reaps. With a 6.0 s timeout expiry needs a 6 s wall-clock jump or delay between notify and observe.
- `tail_spy` sets `ledger.tail_done` in a `finally` right after the product tail returns. The tail posted the Notify message just before returning. `_wait` checks its predicate before it yields, and `_observe` then runs with no `await` before `_notice_rows`, so the Notify message may still be queued when the snapshot is taken.

## Hypotheses

- H1 notify never called (other path, `written` truthy, or the spied tail was not the one that ran).
- H2 notify called but raised, swallowed by the bare `except Exception: pass`.
- H3 notify succeeded and the notice reached the collection but was reaped (wall-clock expiry) or otherwise gone at observe time.
- H4 the observation ran against a different app or screen state.
- H5 (new, from the source reading) notify succeeded and posted `Notify`, but `_on_notify` had not yet run when `_observe` snapshotted: an ordering race in the test, no product defect. This is the leading candidate by reading alone; it is not established.

## What is recorded

All fields go into `record_property("r13_101_diag", ...)` (passing runs too) and, when any assertion fails, into the failure message as `| r13_diag=<json>`; both are capped at 3500 characters. Offsets are `time.monotonic()` minus the install time, in seconds.

| field | content | decides |
|---|---|---|
| `writer` | `written=<bool>` or `raised <type>: <msg>` from the real writer | H1: `written=True` means the success path ran and a failure notice is not owed |
| `events` | ordered `tail_start`, `writer_start`, `writer_end`, `tail_end`, `wait_returned` with offsets and `same_app` | H1: order, and whether the spied tail ran for this app; H5: gap between `tail_end` and `wait_returned` |
| `notify` | per call: offsets, wall time, message prefix, severity, timeout, screen type, `app_id`, `raised` (exception) and `returned_mono` | H1: empty list means never called; H2: `raised` present; H4: `screen` and `app_id` |
| `added` | per `Notifications.add` call: offset, message prefix, `raised_at`, timeout | H5: `notify` row exists but no `added` row before the first snapshot, or an `added` offset later than `snap_pre`/`snap_observe` offsets; H3: `added` row present |
| `snap_pre` | state right after the wait, before `_observe`: `raw_count` (unreaped dict), each raw entry's `raised_at`, `time_left`, `has_expired`, reaped rows, `queue_size`, screen type, `app_id`, wall and monotonic | H3: `raw_count>0` with `has_expired=true` or negative `time_left` means reaped; H5: `queue_size>0`, or `raw_count=0` here and `added` later |
| `snap_observe` | same, after `_observe` (which includes the blocking OS-clipboard read) | H5 vs H3: notice appears here but not in the assertion's `notices_seen` is impossible (same loop turn), so differences between pre and observe show real expiry or later dispatch |
| `snap_settled` | same, after `_settle(pilot, 2)` | H5: notice now present with `added` after the failing snapshot; H3: still absent although `added` exists |

## Reading a failing run

1. `notify` empty: H1. Check `writer` (`written=True` would mean the other branch) and `events`/`same_app`.
2. `notify` has `raised`: H2, the exception text is the cause.
3. `notify` ok, `added` empty at `snap_pre`, `queue_size>=1` or `added` offset later than the assertion snapshot, notice present in `snap_settled`: H5, the test observed before dispatch. The fix would be test-side (settle or wait for the notice before observing).
4. `added` ok earlier than the snapshot, `raw_count=0` or `has_expired=true`: H3. The `raised_at` against `wall` gives the wall-clock jump.
5. `screen` or `app_id` differ between `notify` and the snapshots: H4.

## Verification (Linux, rtx, HT-01/HT-02 environment, runner scratch under the work folder, deleted afterwards)

- `ast.parse` of the file: ok.
- Collection: 35 tests collected, the same count as the base (33 test functions before and after; the 35 includes the C1 parametrization).
- Full file run on the patched clone: `27 passed, 8 skipped in 388.77s`. The 8 skips are the WinCI-only nodes (`tests/test_b103_clipboard_tail.py:1460`, "not_run on Linux"), including this node. The instrumentation itself is therefore `not-run` on Linux and first executes on WinCI; it is exercised only by `ast`/collection here.
- Diff: 0 CR (`git diff | grep -c $'\r'` is 0).
