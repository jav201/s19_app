# Inc 5 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` **FAIL** (1 MAJOR A-1, 5 MINOR); `E3-security.md` **FAIL — BLOCK-UNTIL SEC5-1** (1 HIGH, 2 MAJOR, 2 MINOR, 1 INFO). Both approve the D-4 design and the census of in-place writes. Rulings under the operator's standing commission:

| Finding | Ruling | Why |
|---|---|---|
| SEC5-1 (HIGH) = A-1 (MAJOR) | Accept the security form. A spec's bytes are keyed by **(name, address, size)**. On a repopulation (a new A2L), a loaded field whose name no longer resolves to the same address and size becomes an unlabelled memory row at the spec's own address carrying the spec's entry; its bytes never move to a new address. Amend the *field loaded from a spec* definition and E1-D6; scope R-CHKED-055 to fields added in the session; add the cases both reviewers named (R-CHKED-025/3 and the two SEC5-1 cases). | Declared expected bytes judged at a different address is a wrong verdict an operator would trust. Keeping the entry at its declared address loses nothing and moves nothing silently (dropping the bytes would lose the operator's declaration). |
| SEC5-2 (MAJOR) + A-2 | Accept. Add R-CRC-PREVIEW-002.5/7 (a save-back refused as blocked still reverts the session image → the designer refreshes) and /8 (an apply with 0 applied that undoes an earlier apply). The hook is placed so that neither `ok` nor `applied > 0` gates it. | The LAN probe on `c2cba35` showed the revert with "not saved"; without these cases a wrongly gated hook passes. |
| SEC5-3 (MAJOR) + A-3 | Accept the record part: §1 of `E1-rulings.md` admits the two visible changes (Write no longer re-baselines a spec field from the image; a rewritten spec lists parameters first) and the guide section that describes Write is updated in E4 (text only). The visible cue distinguishing spec bytes from image bytes is a **backlog row** for the UI iteration (prototype round, KF-101 family). | The behaviour change is the D9-11 fix itself and must be stated; a new visual cue is a UI change, out of scope by the operator's P0 ruling. |
| SEC5-4 (MINOR) | Accept: record the fast exclude-then-include race as a known limitation in `E1-rulings.md`. | Honest record; no wrong value reaches a saved file. |
| SEC5-5 (MINOR) | Backlog row: bidi controls in A2L names survive `safe_text` (pre-existing, not introduced here). | Outside the slice; no spec-file string reaches the screen. |
| SEC5-6 (INFO) | Keep: the D-4 LAN probe (A2L explorer value column, Split/Join) runs before Inc 10's E1 (E1 ruling D-4). | Already routed. |
| A-4 (MINOR) | Accept: the graph's interface table adds Inc 6's D9-15 (re-roots the guard in `on_check_editor_panel_spec_file_selected`) and a note that the new helper must not call `refresh_window` (focus move) — for Inc 10. | Serial-chain interface record. |
| A-5 (MINOR) | Accept: record the diff-report naming difference (R-DIFF-CHK.11) as deliberate. | Two consumers, two documented forms. |
| A-6 (MINOR) | Accept: the address rule matches a symbol by address **and** size; fold if it is a one-line edit, otherwise an E4 addendum. | Same root as SEC5-1. |

Correction: one design-correction agent, targeted edits only. Round 2: the security reviewer re-checks SEC5-1, SEC5-2, SEC5-3 and A-1 only.
