# Phase 6 (docs) — declared **NOT APPLICABLE**, with the reason

Per the hand-off's §6.4 and PLAN §6: *"Produce each phase's artifact or declare in writing why it does
not apply."* batch-74 reached MERGE with no `04-validation.md` and no `06-docs/`, and `/dev-flow-sync`
caught it rather than the gate. This file is that declaration, not an omission.

## Why there is no user-facing documentation for the merge-gate increment

**No operator-observable behaviour changed. This is verified, not assumed.**

The increment's four closures (`H-1` … `H-4`) are entirely in **acceptance strength**: test
calibration, test oracles, a restored pin, and a rendered-value equality assertion. The one production
edit — `REPORT_VARIANT_ID_MAX_BYTES`, replacing `REPORT_CELL_CHARS` in two `_disclosure_allowance`
terms — is **output-neutral by construction**:

| Evidence | Result |
|---|---|
| Production readers of `REPORT_VARIANT_ID_MAX_BYTES` | **only** `_disclosure_allowance` (`:881`, `:891`) |
| Production callers of `_disclosure_allowance` | **zero** — census over `s19_app/`, non-docstring |
| `AT-256` — under-cap report byte-identical to the Inc-0 golden | **passed** |
| Snapshot count | unchanged (no TUI file touched) |

Since `_disclosure_allowance` is consulted by no runtime path, changing its arithmetic cannot alter a
single emitted byte. `AT-256` pins that independently against a golden captured at Inc-0 from the
**shipped** producer in its own commit (C-12), so the claim rests on a measurement rather than on the
call-site census alone.

There is therefore no new screen, key binding, CLI flag, output format, config value, or failure
message for an operator to learn.

## Where the substantive documentation did go

The change is a **contract** clarification, and it landed in the contract:

* **`REQUIREMENTS.md`** — `R-TUI-102`'s statement now qualifies the bound with *"for every
  `variant_id` the workspace surface can produce"*, and **new non-claim (h)** states the domain
  (`3 × 255 = 765 B`, derived from the filename component cap), the measured witness (255 × U+4E00 →
  777 B), and the measured excess **outside** that domain (+3 747 / +54 200 / +356 922 B at
  `V = 50/100/400`). Previously the bound was asserted unconditionally while its derivation charged a
  **character** cap as a **byte** bound.
* **`report_service.py:452`** — the constant carries its full derivation, its measurement, and the
  reason the precondition is load-bearing.
* **`tools/mutation_harness.py`** — module docstring documents the harness contract for the next
  batch, which is the audience that needed it.

## What was deliberately NOT written

A "how to keep your report under the cap" operator note. `REPORT_MAX_TOTAL_BYTES` is not
operator-configurable through the shipped surface, and non-claim (a) already declines any residency or
generation-time claim; a note implying the operator has a dial here would over-claim.
