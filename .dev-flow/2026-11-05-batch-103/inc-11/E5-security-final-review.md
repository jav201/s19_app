# E5 final independent security review

## Verdict: FAIL — one remaining MAJOR implementation finding

Static, bounded review of the current working tree. No tests or probes were run, no product or test files were edited, and no commits were made. P17 is statically closed. The main P16 ordering correction is present, but its standing-size fallback is incomplete for `DATA_SIZE`-only family tags.

## Finding

### MAJOR — impl — P16 still returns a scalar length for a standing `DATA_SIZE` without `LENGTH`

`has_standing_size` is set for either `DATA_SIZE` or `LENGTH` at `s19_app/tui/a2l.py:3566-3568`. When no inline span resolves, the new family branch calls `_infer_length_characteristic` whenever that flag is set (`s19_app/tui/a2l.py:3737-3745`). That helper reads only `LENGTH`; it never reads `DATA_SIZE` (`s19_app/tui/a2l.py:1986-2012`). With no `LENGTH`, it falls through to the deposit/layout element size and returns that scalar, possibly multiplied by a count (`s19_app/tui/a2l.py:2013-2036`).

Consequently, a CURVE/MAP-family tag on a UWORD layout with `DATA_SIZE 4`, no `LENGTH`, and an unresolved span can export length 2 instead of the standing 4. This violates P16's requirement to accept the standing `DATA_SIZE`/`LENGTH`, not generic scalar inference (`.dev-flow/2026-11-05-batch-103/inc-11/E5-rulings.md:24`) and the byte-size/full-span contract (`.dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md:126-127`). An under-reported length can also restrict downstream byte extraction (`s19_app/tui/a2l.py:4053-4059`).

The external-axis pass does not fully repair this case. It assigns the resolved span only when the current length is `None`; for a non-null standing-size fallback it checks agreement but leaves the existing scalar in place when agreement holds (`s19_app/tui/a2l.py:3821-3833`). Thus a later-resolved full span can still fail to take precedence.

**Required closure:** through the public parse route, a `DATA_SIZE`-only family tag must use its standing byte size when the span is unresolved, and a subsequently resolved full span must replace the provisional standing value when the sizes agree. Existing no-number/disagreement refusals must remain final. Add discriminating coverage for both unresolved and external-axis resolution; the current P16 test covers only an inline span with no standing size (`tests/test_b103_a2l_reader_e5.py:431-448`). This finding is a code-path correction, not a threshold change.

## P16 controls that are correct

- `_CURVE_MAP_FAMILY` contains CURVE, MAP, CUBOID, CUBE_4 and CUBE_5 (`s19_app/tui/a2l.py:251-252`). Inline axis counts and the record-layout full span are resolved before length selection (`s19_app/tui/a2l.py:3717-3723`).
- Family size agreement compares standing byte sizes with the resolved full span rather than with scalar count products (`s19_app/tui/a2l.py:560-565`). A resolved inline span is selected before generic inference (`s19_app/tui/a2l.py:3737-3739`), so the original UWORD/two-point case selects 4, not 2; its regression is at `tests/test_b103_a2l_reader_e5.py:431-448`.
- With no resolved span and no standing size, family length is `None`; generic scalar inference is not called (`s19_app/tui/a2l.py:3744-3745`). The finding above is limited to the `DATA_SIZE`-only standing branch.
- No-number and disagreement paths add the tag to `refused_length_ids` and set length to `None` (`s19_app/tui/a2l.py:3725-3733`). The external-axis post-pass skips those tags before any assignment (`s19_app/tui/a2l.py:3807-3810`). Out-of-range lengths also join the refusal set (`s19_app/tui/a2l.py:3750-3758`). P15's final-refusal guard therefore remains intact.

## P17: statically closed

- `TAB_VERB` is in `COMPU_CONVERSION_KEYWORDS` (`s19_app/tui/a2l.py:84-93`), so both body and metadata conversion parsers recognize it (`s19_app/tui/a2l.py:1596-1604`, `:1671-1681`). `COMPU_TAB_REF` is retained on the extracted method (`s19_app/tui/a2l.py:1714-1736`).
- `_apply_compu_method` resolves the referenced table and returns the entry text only on exact raw-key equality (`s19_app/tui/a2l.py:2729-2735`). A missing table returns `(None, "error", "lookup table missing")`; an unmatched raw value returns `(None, "error", "raw value not in verbal table")` (`s19_app/tui/a2l.py:2730-2736`). Neither case reaches the raw-preserving `unknown_method` fallback at `s19_app/tui/a2l.py:2748`.
- Enrichment propagates the returned physical value, status and error without substituting raw text or another value (`s19_app/tui/a2l.py:4075-4107`).
- The positive public-route regression checks extraction and raw 1 → `on` (`tests/test_b103_a2l_reader_coverage.py:1796-1819`). The two scoped test files do not add direct enrichment regressions for missing table or missing raw entry; those paths are established statically here, but dynamic negative-path evidence is still worth adding.

## Regression check: P1–P15, D8 and READ.70

No reopening was found in the reviewed source and regressions:

- **P1–P6:** quoted-number rejection, line-end-aware quoted words, nested byte-order inheritance, structural line identities, comment boundaries and quoted argument grouping remain at `s19_app/tui/a2l.py:342-349`, `:376-378`, `:457-517`, `:3655-3678` and `:3779-3801`; their public-route regressions remain at `tests/test_b103_a2l_reader_e5.py:47-187`.
- **P7–P10:** argument/source lines, independent address and size disagreement reporting, and per-word BYTE_ORDER diagnostics remain at `s19_app/tui/a2l.py:3529-3583`, `:3660-3669`, `:3680-3691`, `:3725-3733` and `:3825-3833`; regressions are at `tests/test_b103_a2l_reader_e5.py:213-282`.
- **P11–P12:** typedefs retain the `_tag_sizes` refusal gate (`s19_app/tui/a2l.py:3863-3900`), and declared layout datatype still precedes the deposit-name hint (`s19_app/tui/a2l.py:583-594`). Regressions are at `tests/test_b103_a2l_reader_e5.py:291-331`.
- **P13 / D8:** the complete family is used for inline span resolution, standing-size tracking and the external-axis pass (`s19_app/tui/a2l.py:3717-3723`, `:3760-3769`, `:3811-3826`). CUBOID/CUBE refusal regressions remain at `tests/test_b103_a2l_reader_e5.py:340-361`; no source change narrowing D8's full-span rule was found.
- **P14 / READ.70:** unclosed typedefs cannot size instances, and unclosed BLOB/INSTANCE sections export neither address nor length (`s19_app/tui/a2l.py:3853-3858`, `:3863-3865`, `:3913-3946`). Regressions remain at `tests/test_b103_a2l_reader_e5.py:370-392` and `tests/test_b103_a2l_reader_coverage.py:1268-1283`.
- **P15:** refusal finality is preserved by the guards cited above and by `tests/test_b103_a2l_reader_e5.py:401-422`.

## Evidence status and pending evidence

- Supplied targeted transcript: **136 passed**, exit 0 (`.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-and-e5-green.txt:1-5`). It was not rerun in this review.
- Supplied integration transcript is green for groups **A** (319 passed), **B** (200 passed), and **C** (389 passed, 1 skipped) (`evidence-e5/int-green8.txt:1-38`). **Group D is not verified**: its output stops after a remote connection closes, with no result or exit status (`evidence-e5/int-green8.txt:39-44`).
- **READ.52 remains pending**; this review does not treat it as verified.
- Required before gate closure: a Linux public-route RED reproduction and regression for the `DATA_SIZE`-only finding, followed by the relevant targeted and integration evidence. Complete group D and the separately ruled READ.52 protocol. Direct P17 missing-table/missing-entry enrichment regressions remain advisable; their absence does not alter the static P17 conclusion.
