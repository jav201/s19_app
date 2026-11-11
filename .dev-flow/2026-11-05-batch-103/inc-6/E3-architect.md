# Inc 6 — E3 code-free design review: architecture

Review at `635270a0`; independent architecture reviewer (plan subagent), returned 2026-11-10. Read-only; no app/tests run and no product/test/stub edits.

**Initial verdict: FAIL.** One HIGH contradiction, one LOW oracle gap and one INFO count wording issue. No architectural infeasibility was found in the two-file design.

| Id | Severity | Finding | Required fix |
|---|---|---|---|
| E3A-01 | HIGH | `.003/18` requires unknown datatype → `?`, while `.017/3` requires a 400-cell unknown datatype to leave a clipped ellipsis. Normalization leaves no long text, so both cannot hold (`01-requirements.md:36,50`; `02-test-cases.md:44,85`; `codewire/graph-inc6.md:79-84`). | Keep unknown → `?`; make `.017/3` a 400-cell unit and assert bounded literal clipping. |
| E3A-02 | LOW | `.018/3` expects two real `None`-signature populations but does not assert an observable that distinguishes the second from a no-op (`02-test-cases.md:89`). | Assert two `True` returns and reset of seeded filter/page/picks after each call, or two describes with A2L data. |
| E3A-03 | INFO | Slice header says two new Patch host functions, but N10 groups two and N11 adds a third. Node totals are nevertheless coherent (`E1-slice.md:10,28-29`). | Say two new host groups (three functions); retain 11 implementation / 19 total nodes. |

## Checked and clear

- Positive non-boolean `length` as sole size source correctly closes both `or 1` and enriched/layout-size paths; refused I-2 definitions cannot revive length.
- ARR12, VB4, MAP10 and TXT5 distinguish whole-object length from element decode size. Datatype/kind are available through the existing panel shims without an `app.py` edit.
- The optional keyword preserves positional callers. Equal-signature early return precedes work; one batch describe per real population is compatible with the 2.0 s design budget and filtering/paging reuse normalized rows.
- Existing Check `(address,size)` match/demotion consumes corrected length without a new rule or third file.
- Patch pick mode, independent `highlighted_parameter`, shared `include_names` and modal are coherent. Picker-local bulk selection without document writes is explicit and safe.
- Missing-length guard can precede lookups while preserving existing address, partial-map and strict over-cap behavior.
- The 76-case arithmetic initially reconciled; all other reviewed cases use concrete independent oracles. The 11 implementation + 8 context = 19-node structure is sound.

## Round 1 disposition

Orchestrator rulings are in `E3-rulings.md`. Re-review after the targeted correction covers only E3A-01…03 and touched claims.

## Round-2 re-review — PASS

Independent architecture re-review of the corrected records returned **PASS**. E3A-01 is closed by unknown→`?` plus a UWORD/long-unit discriminating case; E3A-02 by two explicit `True` returns, state reset and one describe per call; E3A-03 by host-group wording with unchanged 11/19 node totals. No new blocking issue was found. Counts are consistently 20 requirements, 75 cases, 56 normal and 19 robustness.
