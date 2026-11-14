# Carried into the modular base (b103-base2)

Inc 1b final (`b103-inc1b-push` `99075449`, then the records-only close commit `aba3b947`)
is merged into `b103-base2` = `a95d0ea9` (batch-modular + patch_editor split), merges
`d8555d03` and `c3760226`. Local only; pushing `batch-modular` or `main` needs the
operator's OK (PENDING P-011, P-012).

- Inc 1b up to `541a3d50` was already in that base through main's squash `645253ba`.
- The only later product hunk, the P-002 guard (R-COPY.26/1: `_apply_filter` returns
  when the app is no longer running), now lives in `s19_app/tui/app/a2l_view.py`
  (`_schedule_a2l_filter_refresh`). This is P-002's carry-over (and BD-1A-1's) on the
  modular base; closing those items is the orchestrator's call.
- `tests/test_b103_clipboard_tail.py`: the R-PASTE.13/101 diagnostic patches
  `app_module.deps` (the deps seam), not the package root.
- Records: main's redacted versions win wherever Inc 1b did not change the text after
  `541a3d50`.

Record, hunk -> module table and checks:
`.dev-flow/2026-11-12-batch-modular/evidence/p4-base2-inc1b/RECORD.md`.
