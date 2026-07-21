# batch-57 — Review (independent code-review at the increment gate)

Given the batch adopts already-adversarially-refined design requirements + mostly-built tested code,
the Phase-2 rigor was concentrated where it matters: an **independent `code-reviewer` pass** over the
real diff (`1341fd3` vs `f2109cf`), focused on LUT correctness and gap-safety enforcement. (Streamlining
recorded as an autonomous decision; the security surface is unchanged — additive modules, size-cap/path
reuse intact, no new external write path — so no separate security-reviewer blocker was warranted; the
reviewer explicitly confirmed no security concern.)

## Findings (classified) + resolution

| # | Sev | Finding | Resolution |
|---|-----|---------|------------|
| F1 | **HIGH** | `parse_job` raised `AttributeError` on a non-object `algorithm` value (the "meant `algorithm_ref`" typo) — broke the collect-don't-abort contract. Confirmed live. | **FIXED** `063bea5`: `_require(isinstance(inline, dict), …)` guard + `algorithm_name: null` falls back to inline name (not literal "None"). +2 regression tests. |
| F2 | MEDIUM | LUT differential input set omitted non-multiple-of-8 widths (C-31 input-set gap) — a broken `shift=width-8` on odd widths would pass the suite. | **FIXED** `063bea5`: differential now covers widths 12 & 24 × both refin × both refout vs the `crc_stream` oracle. |
| F3 | LOW | warn/ignore branch tests asserted `crc is not None` rather than the exact value. | **FIXED** `063bea5`: both pin `0x2A8A3950`. |

## Reviewer's explicit confirmations (not by omission)
- **LUT correctness:** `crc_lut`/`make_crc_table` proven + empirically confirmed byte-identical to the
  `crc_stream` bitwise oracle for ALL widths 8..64 incl. non-multiples of 8, both refin/refout
  independently (0 mismatches over widths {8,9,11,12,13,17,24,31,33,55,63,64}).
- **Differential is non-vacuous** and externally anchored (KAT catalogue `check` at 8/16/32/64 — not a
  two-buggy-implementations-agree trap).
- **Gap-safety enforcement correct;** branch tests satisfy C-10b (one AT per policy, distinct outcome).
- **Conventions:** docstring section order, type hints, collect-don't-abort + `READ_SIZE_CAP_BYTES`/
  `resolve_input_path` reuse mirror `crc_config.py`; round-trip holds.

## Gate
HIGH F1 blocked → fixed at the gate (autonomous, per the increment-gate rule; not a merge-blocking
final-PR HIGH). MEDIUM/LOW also applied. Post-fix: 45 designer tests green, ruff clean, 0 frozen diffs.
Axis: Coverage (every US→AT, E-item→TC), Certainty (LUT differential incl. odd widths; branch ATs
value-discriminating), Evidence (reviewer proof + on-disk nodes). → **approve**.
