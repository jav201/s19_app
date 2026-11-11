## Inc 5 — Review Packet

### 1. What changed

Every live A2L-dependent view is refreshed from the installed image/MAC/A2L state before the load or unload outcome. The increment preserves filter text/field, resets only filter mode, invalidates stale Detail Card/modal/highlight/Split selection state, retains manual Split content and ranges when appropriate, confirms project-A2L replacement without project writes, rechecks busy and identity, and rejects superseded prepared loads atomically. Scope: 28 requirements and 103 cases.

### 2. Files modified

- `s19_app/tui/app.py` — common publication fan-out, confirmed replacement and prepared-load preflight.
- `s19_app/tui/segment_split_view.py` — A2L selection invalidation and same-image range preservation.
- `tests/test_b103_a2l_refresh.py` — 103 operator-route cases with visible and model oracles.
- `.dev-flow/2026-11-05-batch-103/inc-5/` — requirements, graph, ledger, reviews, validation and evidence.
- `.dev-flow/2026-11-05-batch-103/evidence/inc-5/` — canonical committed transcripts.

### 3. How to test

On a committed Linux checkout with the `s19ci` interpreter and isolated HOME/XDG/LOCALAPPDATA:

```bash
python -I -B -c "import sys;sys.path.insert(0,'.');import s19_app;print(s19_app.__file__);import pytest;raise SystemExit(pytest.main(['-q','-p','no:cacheprovider','tests/test_b103_a2l_refresh.py','tests/test_b102_a2l_refresh.py','tests/test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later']))"
python -I -B -c "import sys;sys.path.insert(0,'.');import pytest;raise SystemExit(pytest.main(['-q','-p','no:cacheprovider','tests/test_suite_hygiene.py']))"
```

Run `.dev-flow/2026-11-05-batch-103/inc-5/evidence-e5/run_5_mutants.py` with `S19CI_PYTHON` set to the runner interpreter. It uses isolated copies and prints each imported package path. Trace and law commands are indexed in `04-validation.md`.

### 4. Test results

- Base RED: **88 failed / 15 passed**; corrected `.011` rerun **3 failed / 2 passed**.
- Final functional family: **112 passed in 1713.14s (0:28:33)** — 103 Inc 5 cases plus 9 historical cases, with import from `/tmp/b103-inc5-e5/s19_app/__init__.py`.
- Mutant baseline: **103 passed in 1690.58s**. Final mutants: **28 killed / 0 survived / 0 ERROR / 0 TIMEOUT**; corrected M-024 failed all four busy cases.
- Laws: **502 passed, 3 skipped, 1 inherited redaction failure** (254+1 skip; 184; 64+2 skips+1 failure).
- Inc 5 redaction: **inc5_redaction_hits=0** over both evidence roots.
- Static trace: **1 US, 28 active requirements, no US/requirement/test or SLICE gap**; committed EVID check pending.
- Reviews: code/security **PASS**, coverage **PASS-WITH-NOTES**.

### 5. Risks

- The inherited redaction failure is outside Inc 5 and remains open; it is not hidden or called GREEN.
- `.028` injects generation mismatches deliberately into real prepared worker results; it does not attempt to reproduce race timing nondeterministically.
- Generic Split SNAP read-back may repaint while changing tabs; dedicated `.016` cases keep the A2L tab live throughout the actual transition.
- Results apply to Linux Python 3.11.18. The complete suite will run after Inc 6 but, by explicit operator amendment, will not block the push to `main`; its findings go to the next batch and no full-suite PASS may be inferred.

### 6. Pending items

- Complete the committed trace and merge-clone verification, then write the requested session handoff.
- Integrate into `batch-103`; no push of additional branches is authorized.

### 7. Suggested next task

**Inc 6 — continue from its existing approved batch-103 artifacts only after Inc 5 is closed and integrated.**
