## Verdict: FAIL — one remaining MAJOR implementation defect

Static review of the current working tree and diff. No tests were executed.

### Finding

- **MAJOR — impl — P16 does not honor a valid `DATA_SIZE` when the full span is not resolved inline.**
  R-A2L-013 requires a tag with agreeing sizes and a `DATA_SIZE` or `LENGTH` keyword to take its length from that keyword (`.dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md:229`). P16 repeats the standing `DATA_SIZE`/`LENGTH` rule (`.dev-flow/2026-11-05-batch-103/inc-11/E5-rulings.md:24`).

  `_tag_sizes` recognizes `DATA_SIZE` and can accept it as agreeing (`s19_app/tui/a2l.py:536-541`, `:560-580`). The new family fallback then calls `_infer_length_characteristic` whenever either standing keyword is present (`s19_app/tui/a2l.py:3737-3745`), but that helper reads only `LENGTH` (`s19_app/tui/a2l.py:1989-1994`). With `DATA_SIZE` alone it falls through to the scalar deposit size (`s19_app/tui/a2l.py:2011-2036`).

  Concrete static trace: a CURVE on a UWORD layout with `DATA_SIZE 4` and no inline-resolvable span gets length 2, not the required 4. If an external-axis post-pass subsequently resolves span 4, the standing size and span agree, so the post-pass emits no refusal and also does not replace the already assigned scalar length (`s19_app/tui/a2l.py:3821-3833`). Thus the resolved full span still loses to scalar inference on this path.

  The added P16 test covers only an inline span with no standing size (`tests/test_b103_a2l_reader_e5.py:431-448`). The reference oracle also has a LENGTH-only standing-length helper (`tests/support/b103_a2l_ref.py:1253-1260`), so it does not supply an independent oracle for the required DATA_SIZE behavior.

### Static checks that pass

- The originally reported P16 inline-axis case is corrected: a resolved full family span is selected before generic inference, and generic scalar inference is excluded when neither a span nor a standing size exists (`s19_app/tui/a2l.py:3717-3724`, `:3737-3745`). This addresses the UWORD/two-axis-points reduction from 2 to 4 bytes, but does not close the DATA_SIZE finding above.
- P15 final refusals remain intact. Size refusal marks the tag before the new precedence branch (`s19_app/tui/a2l.py:3731-3733`), bounded-length refusal remains marked (`s19_app/tui/a2l.py:3750-3758`), and the external-axis pass still skips refused tags (`s19_app/tui/a2l.py:3807-3810`).
- P17 is statically correct for scalar decode. `TAB_VERB` is recognized (`s19_app/tui/a2l.py:84-94`) through the existing COMPU_METHOD parsing routes (`s19_app/tui/a2l.py:1596-1604`, `:1671-1681`, `:1714-1736`). `_apply_compu_method` resolves the referenced table and returns text only for an exact raw entry (`s19_app/tui/a2l.py:2729-2736`). A missing table or missing raw entry returns `(None, "error", ...)`; there is no nearest-entry or identity fallback. A non-numeric scalar is not coerced through `float` and therefore misses numeric entries cleanly. Lists retain the pre-existing generic `array` result before conversion dispatch (`s19_app/tui/a2l.py:2710-2713`). The public READ.54/4 happy path is pinned at `tests/test_b103_a2l_reader_coverage.py:1796-1819`; the negative branches are established here statically, not by that test.
- No P1–P15 regression is visible in the current product diff, which contains only the P16 and P17 edits. Full-family D8 handling remains at `s19_app/tui/a2l.py:251-252` and `:3717-3724`. READ.70 closure gates remain at `s19_app/tui/a2l.py:3853-3858`, `:3863-3865`, and `:3913-3946`.

### Pending evidence — not closed by this review

The supplied transcripts record 136 passed for the coverage/E5 slice (`evidence-e5/coverage-and-e5-green.txt:2-5`) and integration groups A–C with 319, 200, and 389 passed plus 1 skip (`evidence-e5/int-green8.txt:11-38`). Group D is incomplete in that transcript (`evidence-e5/int-green8.txt:39-44`), and READ.52 remains pending. These are validation gaps, not additional static findings. This review neither reran them on Windows nor closes integration D or READ.52.
