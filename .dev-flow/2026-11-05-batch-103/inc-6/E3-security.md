# Inc 6 — E3 code-free design review: security

Review at `635270a0`; independent security reviewer (explore subagent), returned 2026-11-10. Read-only; no app/tests run and no product/test/stub edits. Lack of runtime evidence was not treated as a finding.

**Initial verdict: FAIL.** One MAJOR scope/design contradiction and two MEDIUM issues.

| Id | Severity | Finding | Required fix |
|---|---|---|---|
| E3S-01 | MAJOR | `.017` requires C0/C1→U+FFFD, including Patch first-missing text, but unchanged shared modal uses `safe_text`, which deletes controls (`screens.py:1051-1053`; `utils.py:44-49`). The two-file boundary forbids the needed modal change. | Either authorize a narrow `screens.py` change or narrow the replacement rule to picker-owned I-2 surfaces and retain the modal's existing literal/control-removal contract. |
| E3S-02 | MEDIUM | Same unknown-datatype/`?` versus long-unknown-datatype/ellipsis contradiction as E3A-01. | Keep `?`; use a known datatype with a 400-cell hostile unit for clipping. |
| E3S-03 | MEDIUM | Long format/unit is clipped in the ledger but current full-name line appends it whole (`a2l_parameter_picker.py:848-855`). Design does not explicitly assign a full-name budget. | Pin clipping of full-name format/unit to the remaining cell budget before fitting the name; test both surfaces at 80 and 118. |

## Explicitly clear

- Missing length has no `or 1`, enriched `byte_size`, or I-2 fallback. Direct fixtures do not create a production fallback.
- Missing-length, over-cap and partial-map designs prevent lookups, giant ranges and zero-filled/partial output. Exact cap remains allowed.
- No second A2L writer or global mutable cache; changed generations describe once per picker.
- Ledger names/formats are the only new I-2 string surfaces. No encode/masked/document write or raw-name/paste logging path is added.
- Bulk selection changes only picks/marks; Patch close does not touch document/history/ledger. Modal target and Check/Patch ids remain separate.

## Round 1 disposition

The orchestrator declined source expansion for E3S-01 and instead narrowed the U+FFFD obligation to picker-owned A2L/I-2 surfaces, dropping the redundant modal case from this increment. The existing shared modal remains literal, clipped and control-free under R-B102-BULK-006. Other findings accepted. See `E3-rulings.md`.

## Round-2 re-review — PASS

Independent security re-review returned **PASS**. E3S-01 is closed by the explicit picker-owned I-2/operator-modal boundary with no third file; E3S-02 by the consistent unknown/long-unit oracles; E3S-03 by the full-name cell budget and two-width assertions. No directly caused regression and no additional security note.
