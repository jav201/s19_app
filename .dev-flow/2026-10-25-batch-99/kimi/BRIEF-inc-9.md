# Kimi brief — batch-99 Increment 9 · US-143 / HLR-154 · truncated and inconsistent images are reported

Read `BRIEF-COMMON.md` first.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-154 (D6 = `flujo_para`, final), LLR-154.1..154.3; TC-B99-08..10; AT-B99-03. Map row B99-I10 (the five codes). PDR conditions:
- **UX-C2:** the SOURCE `error`'s last diagnostic names the code and path.
- **UX-C7:** already in HLR-154. An interactive load leads its status with the defect, e.g. `Loaded firmware.s19 with integrity notices: S19-NO-TERMINATOR`.
- **UX-C10:** a hostile file name in the integrity-notice path renders literally.

## SOURCE files (max 4)
`s19_app/core.py`, `s19_app/hexfile.py` (both frozen engine — the crossing is named in LLR-154.1/154.2), `s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/app.py` (the interactive load status, near `app.py:11013`).

## What to build
1. S19 `_load`:
   - `S19-NO-TERMINATOR`;
   - `S19-COUNT-MISMATCH`: compare S5 only when the data-record count is ≤ 0xFFFF, and S6 when ≤ 0xFFFFFF;
   - `S19-AFTER-TERMINATOR`: after the terminator, count non-empty lines only — no parse, no per-line issue, no image write — with one notice per kind stating the count. Those records never enter the image.
2. HEX `_load`: `HEX-NO-EOF`, and `HEX-AFTER-EOF` stating the count of non-empty trailing lines. Same count-only rule.
3. Flow SOURCE arm: exactly these five codes map to `error`; other load notices keep `notices`. No file is written.
4. Interactive load status (UX-C7).

## Tests — `tests/test_b99_truncation.py`
- **TC-B99-08 / 09:** the corpus defect files (Inc 1); controls: every `examples/**/*.s19` and every well-formed corpus file → 0 of these notices; the 100 000-line junk tail → 1 notice and 0 image bytes, for S19 AND HEX; trailing blank lines → no notice; an S6 image of more than 65 535 records → no notice (generate it in the test into tmp; do not commit a big file).
- **TC-B99-10:** 5 defect sources through a flow → SOURCE `error`, 0 files.
- **AT-B99-03** (pilot): Load file (`l`) of the cut S19 → the status leads with `integrity notices: S19-NO-TERMINATOR` and the issues panel names it; Flow Execution `#fx_run` over it → SOURCE failed, no file. RED today (P-10).
- Mutations: drop the terminator check; drop the EOF check; map the codes to `notices`. Revert each one.

## Reverse census
Today's S19 loader KEEPS records after the terminator (`rw-p04` `s19_data_after_term` ranges include `0x2000`). That changes now: re-pin any test that relied on it. `grep -rln "S7\|S8\|S9\|terminator\|EOF\|_load(" tests/`. Test fixtures with no terminator (qa census risk) will now get a notice. A test that only loads them is fine; a test that asserts 0 notices on them must be re-pinned with the reason.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-009.md`, REQ-ID `HLR-154`.
