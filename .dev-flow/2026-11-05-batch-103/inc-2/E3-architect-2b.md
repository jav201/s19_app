# Inc 2b E3 — ARCHITECT review

**Verdict: FAIL.** Two blockers remain (one MAJOR residual, one HIGH). The reader
premise is now sound — Inc 11 closes E3S-36, -38, -39, -40 and -43 — and the
encode-side design is otherwise implementable against today's code. The blockers
are (a) E3S-37's `/include` arm has no machine-checkable signal and its V171
cases/AT are stale under option (a), and (b) E3S-41's CLEAN `mask_of` rule is not
pinned in the graph, which can still produce a false exemption. Both are concrete
and bounded; neither requires re-opening E1/E2.

## Executed vs read

- **Read (documents):** `E3-rebrief-2b.md`; `01-requirements.md:190-218,243-345`;
  `02-test-cases.md:170-244,284-305,345-390`; `codewire/graph-inc2.md:302-314,370-498,611-752`;
  `E3-rulings.md:138-167`; `E3-security.md:200-272`; `E1-rulings.md:101-136`;
  `E1-slice.md:87-116`; `../inc-11/04-validation.md`.
- **Executed (read-only probes of current code):** `s19_app/tui/a2l_definition.py`
  (`Definition` 100-169; `describe_definitions`/`_describe_one` 521-851;
  `decode_definition`/`_decode_stored` 2545-2660; `_read_stored_value` 2912-3121;
  `_read_object_lines` 2444-2544; `_parse_bit_mask`/`_mask_shift` 360-490) and
  `s19_app/tui/a2l.py` (`extract_a2l_tags` 3411-3831; `extract_declared_spans`
  3897-4010; `parse_a2l_file` 4012-4110; `_number_word`/`_bounded_length`/
  `_section_words` 344-464). Grepped for `shared_with`/`_shared_with`/
  `_selected_bits`/span index (all **absent** from current `a2l_definition.py`; only
  the docstring note at line 118 mentions the future `shared_with` field) and for
  `encode_physical_to_raw_bytes`/`_decode_scalar`/`_apply_compu_method` (present in
  `a2l.py`, frozen). No pytest, no probes, no git mutations, per the brief.

## Verified reader premise (Inc 11)

- `parse_a2l_file` now returns `declared_spans` (BLOB + INSTANCE spans with
  `_bounded_length` applied) — `a2l.py:4074`. This makes E3S-37 option (a)
  implementable for BLOB/INSTANCE **without touching the frozen `a2l.py`**.
- Tag address / length / MATRIX_DIM / BYTE_ORDER / BIT_MASK are read through the
  comment-aware `_section_words` stream (`extract_a2l_tags`, `a2l.py:3469-3736`),
  not raw lines. Commented-out keywords no longer count, and addresses glued to a
  comment are read (E3S-38). `_number_word` accepts only `0x`+1..16 hex or 1..20
  decimal digits (E3S-38's `int(...,0)` raise is gone).
- `_bounded_length` caps every tag length to 1..`MAX_A2L_DECODE_BYTES` (1 MiB),
  else `None` (`a2l.py:354-362`; applied at `:3772-3777`). A hostile length is
  `None`, so it is not indexed — E3S-39's page-fill DoS is closed at the reader.
- MATRIX_DIM is the product of its numbers (`_matrix_dim_product`, `:614`;
  `extract_a2l_tags` `:3620-3633`) — E3S-40 closed.
- Duplicated/missing/unreadable BYTE_ORDER sets `address_invalid` → `tag["address"]=None`
  → `A2L-DEF-ADDRESS` (`:3690-3750`) — E3S-36's misread byte order no longer feeds
  the exemption.

## Disposition of E3S-36 … E3S-44

| Id | Sev | Disposition |
|---|---|---|
| E3S-36 | MAJOR | **Closed by Inc 11.** Byte order now read comment-aware; any ambiguity → `address_invalid` → `A2L-DEF-ADDRESS` → `mask_of` `None` (via CLEAN). Residual: no 2b case exercises C1/C2/C3 (see F-3). |
| E3S-37 | MAJOR | **Partially closed — BLOCKER.** BLOB/INSTANCE: closed via `declared_spans`. `/include`: still open (see B-1). AXIS_PTS: still owned by Inc 3 (documented limit). Cases `.44/1,.44/2,.45/1,.45/2` and AT-B103-I2-1's SBYTE/UBYTE arms are stale under option (a) (see B-2). |
| E3S-38 | MAJOR | **Closed by Inc 11.** The proposed `.7.1` C-rule cross-check is superseded (redundant once the tag is comment-aware). |
| E3S-39 | MAJOR | **Closed by Inc 11** (`_bounded_length`). Residual: H1–H4 absent from the 2b corpus (F-4). |
| E3S-40 | MEDIUM | **Closed by Inc 11** (MATRIX_DIM product). Superseded. |
| E3S-41 | MINOR | **Accept-fix, NOT applied — BLOCKER** (see B-2). Graph `mask_of` wording is narrower than CLEAN. |
| E3S-42 | MINOR | **Accept-fix, NOT applied.** Graph step-2 wording and case `.138/20` still missing (F-5). |
| E3S-43 | LOW | **Closed by Inc 11** (comment is a word break; mask reads `0x000F`, not `0x000F0`). Residual: no commented-mask-word case (F-6). |
| E3S-44 | LOW | **Accept-fix, NOT applied.** Graph `_shared_with` still reads "up to the first that is not left out" without the overlap test (F-7). |

## Blockers (MAJOR / HIGH)

**B-1 — E3S-37 `/include` has no machine-checkable signal (design-gap, HIGH).**
The frozen reader records `/include` only as a human string in
`a2l_data["errors"]` (`a2l.py:1000-1004`: `Line <n>: /include <word> is not read`);
it keeps no structured flag and the directive is not in the section tree. Option (a)
requires "refuse every encode of a file that holds `/include`", which has nothing
clean to key on, and `a2l.py` is engine-frozen (unfreeze only under operator grant).
The graph's span-index node (`graph-inc2.md:253`) was written before Inc 11 and
mentions only MEASUREMENT/CHARACTERISTIC tags — it is **stale**: it must consume
`a2l_data["declared_spans"]` for BLOB/INSTANCE and define the `/include` and
unsized-INSTANCE (fail-closed) arms.
**Correction:** rule now, one of: (i) refuse every encode when
`a2l_data["errors"]` contains an entry whose text starts with the frozen prefix
`"/include "` (document the frozen-message coupling), or (ii) grant an explicit
`a2l.py` unfreeze to add a structured `includes` flag to the payload and re-freeze,
or (iii) accept option (b) for `/include` and write the limit into R-A2L-DEF.138 +
CTX *span* + AT-B103-I2-1, with the Inc-3-closes-before-Inc-8/9 condition stated.
Update the span-index node to file `declared_spans` entries (BLOB length, INSTANCE
size by the reader's rule) and to treat an unsized/address-bearing entry as
overlapping its first byte (fail closed).

**B-2 — E3S-41 CLEAN `mask_of` not pinned (design-gap, HIGH).** The graph still
defines `mask_of(position)` = "the bit mask this walk reads for that object
(R-A2L-DEF.18) when the rules of R-A2L-DEF.19 give it no refusal, else `None`"
(`graph-inc2.md:253`). That is narrower than CLEAN: a neighbour refused
`A2L-DEF-LENGTH` / `A2L-DEF-ADDRESS` / `A2L-DEF-KIND` / `A2L-DEF-NAME` still
contributes its mask, and the current `_describe_one` sets `bit_mask` even on a
refused definition (`a2l_definition.py:818`, `bit_mask=mask_number if kind in ...`
regardless of `refusal`). A length-mismatched neighbour's mask over the wrong span
can then look disjoint and falsely exempt a write (the round-1 HIGH consequence).
**Correction:** pin `mask_of(other)` = `other.bit_mask` when `other.refusal is None`,
else `None` — i.e. the mask counts **only from a definition with no refusal**. This
is simplest as a second pass: build every definition first (refusal + `bit_mask` +
span), then compute `shared_with` from the built definitions, so CLEAN falls out by
construction rather than re-running the refusal order on demand. Update the graph's
`describe_definitions` and `_shared_with` nodes accordingly.

## Other findings

- **F-1 (contract, LOW).** The E1 I-2 `Definition` field list
  (`E1-rulings.md:101-136`) omits `bit_mask_text`, `coeffs_linear`, `coeffs`,
  `compu_tab_ref` and the Inc 3 fields now present (`a2l_definition.py:114-150`).
  Pre-existing drift, not a 2b blocker, but the I-2 note should be re-synced when 2b
  inserts `shared_with`. The insertion point is fine: after `compu_tab_ref` and
  before `refusal`, both no-default, so `dataclasses.replace(d, shared_with=None)` in
  the cases works; all four `Definition(...)` construction sites must be updated.
- **F-2 (contract, LOW).** `shared_with` is `str | None` → the immutability contract
  (`.58.1`, `.149/5`) holds; no new mutable field. The `.149/5` "every stored form
  immutable" case must add `shared_with` (a plain `str`) to its write-resistance set —
  a trivial extension, but currently the case does not name it.
- **F-3 (coverage, MEDIUM).** No 2b case covers the E3S-36 shapes C1/C2/C3
  (duplicated/commented/MOD_COMMON BYTE_ORDER beside a masked neighbour). Inc 11's
  reader cases cover the reading, but not the overlap-exemption consequence. Add a
  `.138`-family case: a masked X beside a masked N whose BYTE_ORDER is ambiguous →
  `shared_with` for X is N (not `None`), encode → `A2L-DEF-OVERLAP`.
- **F-4 (coverage, MEDIUM).** E3S-39's H1–H4 (hostile `NUMBER`/`MATRIX_DIM`/`LENGTH`/
  `DATA_SIZE`) are not in the `.58.2` corpus nor any `.138` case. With `_bounded_length`
  they become `length=None` (not indexed), but a discriminating case must assert the
  span index still builds within `.136`'s 2.0 s bound and the hostile tag is simply not
  an entry.
- **F-5 (coverage, MEDIUM).** E3S-42's case `.138/20` (ASCII `NUMBER 4` at 0x10 beside
  a UBYTE VALUE at 0x12 → encode `AB` → `A2L-DEF-OVERLAP`, 0 bytes) is still absent,
  and the graph's encode step 2 (`graph-inc2.md:611`) still reads "…, the step-6
  image-span check, then `Encoded`" with the step-9 text branch only in a later
  sentence. Apply both.
- **F-6 (coverage, LOW).** E3S-43: add a case with `BIT_MASK 0x000F/*nibble*/0` to
  pin that the mask reads `0x000F` (comment is a word break), so a masked neighbour is
  not falsely exempted.
- **F-7 (impl, LOW).** E3S-44: rewrite the `_shared_with` scan sentence to "…up to the
  first whose span overlaps and that is not left out" (`graph-inc2.md:462`).
- **F-8 (coverage, LOW).** The `.138` census ("223,524 refusals in 10 files") was run
  on clone `e07fb00` (pre-Inc-11 reader). It is a ruling, not a threshold, so no test
  depends on the number; but the V171 `shared_with` names the cases cite (e.g.
  `ASAM.C.SCALAR.SWORD.LINEAR_MUL_2`, `ASAM.C.SCALAR.UWORD.IDENTICAL`) should be
  re-confirmed against the current reader at E4, and the `.44/.45` names corrected if
  option (a) lands (B-2's stale set).

## Case coverage / vacuous checks (Inc 11 + Inc 3a)

- **Stale after option (a):** `.44/1, .44/2, .45/1, .45/2` use
  `ASAM.C.SCALAR.SBYTE.IDENTICAL` (0x810001) / `ASAM.C.SCALAR.UBYTE.IDENTICAL`
  (0x810000), which E3S-37 shows overlap INSTANCE `ASAM_I_SCALAR_VALUE_UWORD_SINGLE`.
  Under option (a) they would get `A2L-DEF-OVERLAP`, not the expected bytes/notice.
  AT-B103-I2-1's SBYTE/UBYTE arms and the graph's AT example (`graph-inc2.md:752`)
  have the same defect. The rebrief's "V171 cases now expect the refusal" note under
  S2.7c lists `.41/.46/.48/.53/.56` but **omits `.43/.44/.45`** — the omission is the
  bug. Correct: add `dataclasses.replace(d, shared_with=None)` to these four cases (as
  `.41/2` already does) or change the object; update AT-B103-I2-1 to apply only
  `UNKNOWN` if option (a) lands.
- **Non-vacuous:** every 2b case I read has a discriminating negative control and a
  numeric/exact expected result; `.55/1` (≥300 accepted, 0 disagreement) and `.56/1`
  (≥32 texts, 0 differ) are property cases with counts, not smoke. No vacuous case
  found in the 109.
- **Inc 3a interaction (design note, INFO):** `_describe_one` already routes
  `array/curve/map` kinds through `_describe_array` with `byte_length`/`address` set,
  and `describe_definitions` already collects AXIS_PTS for decode. The 2b span index
  must (i) index array/curve/map spans too (their `byte_length` is the whole span), and
  (ii) explicitly not index AXIS_PTS (Inc 3 owns it) while stating the
  Inc-3-closes-before-Inc-8/9 condition in CTX *span* and R-A2L-DEF.138. The graph's
  "MEASUREMENT or CHARACTERISTIC tag" wording already covers arrays; make it explicit.

## What blocks E4

B-1 and B-2 must land before Inc 2b E4. F-3, F-4, F-5 are MEDIUM coverage gaps that
should land in the same pass (they are the discriminating tests for the fixes they
track); F-1/F-2/F-6/F-7/F-8 are LOW and can accompany.
