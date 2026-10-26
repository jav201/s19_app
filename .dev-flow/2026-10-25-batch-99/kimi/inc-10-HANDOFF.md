# HANDOFF — batch-99 Increment 10 (HLR-158, map row B99-I4)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc10` (branch b99-inc10). Working
tree only — **no commit**, per the brief. The orchestrator commits.

## What was done

HLR-158 (US-147 decode / US-152 encode): A2L values now encode and decode as
the A2L declares.

- `s19_app/tui/a2l.py` (SOURCE 1/2):
  - LLR-158.1 — new `_extract_mod_common_byte_order`; the effective-byte-order
    fallback chain in `extract_a2l_tags` is now tag → RECORD_LAYOUT → tag
    endian → `MOD_COMMON BYTE_ORDER` → little.
  - LLR-158.2 — new `_eval_rat_func` (encode: INT = f(PHYS) directly);
    `_invert_rat_func` re-purposed as the decode solve (quadratic, root inside
    the tag limits when exactly one, else smaller magnitude, no-real-root =
    failure); `_apply_compu_method` gained an optional `limits` parameter,
    fed by the enrichment and the E9 FNC-values call sites.
  - LLR-158.3 — `_reverse_table_lookup` refuses non-table `TAB_NOINTP` values
    naming the two nearest and out-of-range `TAB_INTP` values naming the
    range; in-range `TAB_INTP` returns the nearest raw plus a flag naming the
    written physical value when it differs. `_invert_physical_to_raw` now
    returns `(raw, error, flags)`; both encode paths merge the flags.
  - UX-C8/UX-C10 — `_short_decode_reason` + `_DECODE_REASON_TOKENS`
    (enum-derived, never A2L text); `describe_curve_tag` carries
    `scalar_reason`; `render_curve_description` renders
    `Scalar value: n/a (<reason>)`.
- `s19_app/tui/app.py` (SOURCE 2/2): the A2L Physical cell shows `n/a` when
  bytes are present but the conversion failed; blank stays blank (no bytes).
- `tests/test_b99_a2l_encode.py` (new): TC-B99-23/24/25 + AT-B99-09 (pilot,
  118x40 and 80x24) + AT-B99-14 (codec API surface).
- Packet: `.dev-flow/2026-10-25-batch-99/03-increments/increment-010.md`
  (§4b left `pending — orchestrator`).
- Evidence: `.dev-flow/2026-10-25-batch-99/evidence/inc-10/` (17 files +
  `SHA256SUMS.txt`).

## Verification status (all GREEN, all in stored transcripts)

- RED baseline on the unmodified tree: 5 failed (`red-initial.txt`).
- GREEN: new module 5 passed; affected files + census 158 passed / 3 skipped /
  1 xfailed; `test_tui_app.py` 62 passed / 1 xfailed; A2L pilot companions
  16 passed; snapshots 33 passed / 29 snapshots passed.
- Mutations (C-40): LLR-158.1 (skip MOD_COMMON), LLR-158.2 (old RAT_FUNC
  direction), LLR-158.3 (silent nearest/clamp) — all three KILLED, each
  reverted; `a2l.py` restored to digest `3d88647a…` (verified after the last
  revert and again in the final sweep).
- Reverse census: 11 test files re-validated, 0 re-pins; B3 golden hit
  unrelated; full suite intentionally not run (orchestrator's gate).
- CRLF preserved in both SOURCE files (CRLF == LF counts throughout).

## Open questions / notes for the orchestrator

- RAT_FUNC axis-point decodes (E9 curve axes, external axis points) pass no
  limits — axis limits are not parsed; the smaller-magnitude root applies
  there (documented in `_invert_rat_func`). No fixture exercises it.
- `_invert_physical_to_raw`'s return contract changed (2-tuple → 3-tuple);
  shipped callers are only the two encode paths in the same file.
- `AT-B99-09` reads the modal text via `Static.content` and painted strips;
  the 80x24 table paints only a sliver, so the narrow-width limb is proven by
  the cell `Text.plain` map (AT-069c idiom) plus the painted modal line.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/a2l.py, s19_app/tui/app.py (2 SOURCE), tests/test_b99_a2l_encode.py (new), packet + evidence under .dev-flow/.
Tests added: 5 nodes — TC-B99-23/24/25, AT-B99-09 (pilot 118x40 + 80x24), AT-B99-14 (codec API).
RED/GREEN: RED 5 failed on the unmodified tree; GREEN 5 passed, plus 158+62+16+33 regression/snapshot passes, census included.
Mutations: 3 run (LLR-158.1/158.2/158.3), all KILLED, all reverted to digest 3d88647a….
Open questions: axis-point RAT_FUNC decode passes no limits (documented fallback); independent review pending — orchestrator.
