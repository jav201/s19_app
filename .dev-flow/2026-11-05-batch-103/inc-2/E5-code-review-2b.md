# Inc 2b E5 — code review

**Verdict: FAIL.** One HIGH working-tree regression blocks integration. The committed
HEAD `cb083d07` (the product diff `b73fb886..cb083d07`) is otherwise clean: every area the
brief flags — span-index identity and cross-kind order, CLEAN `mask_of`, duplicate names,
byte-order sources, numeric vs enum precision, parse-error ordering, image/mask merging,
immutable input and exact messages — is implemented as the approved design states. The
blocker is an **uncommitted** edit to `_shared_with` in the current working tree that
silently breaks the R-A2L-DEF.138 overlap guard. Reverting that edit (and its companion
page-size change) restores PASS.

## Executed vs read-only

- **Executed:** nothing. Read-only review on Windows. No pytest, no probes, no git
  mutations, per the brief. (`python`/`pytest` are not run here; the runner evidence is
  read only.)
- **Read (source):** `s19_app/tui/a2l_definition.py` (working tree and `git show HEAD`),
  `s19_app/tui/a2l.py` `extract_declared_spans`/`parse_a2l_file`, the tag layout-name
  resolution at `a2l.py:3117`.
- **Read (documents):** `01-requirements.md` (full), `E3-rulings.md` final sections,
  `E3-architect-2b.md` + `E3-architect-2b-r2.md`, `E4-handoff-impl-2b.md`,
  `E4-handoff-tests-2b.md`.
- **Read (tests, working tree):** `tests/test_b103_a2l_definition.py` (2b arm) and
  `tests/test_b103_synth_definitions.py` (2b arm), plus the case ledger `02-test-cases.md`
  diff.

## Blocking findings

### F-1 — `_shared_with` broken in the working tree (impl, HIGH, blocks integration)

`_shared_with` (`s19_app/tui/a2l_definition.py:3561-3580`, **uncommitted**, modified
2026-11-10 00:22:43) drops the committed `candidates`/`sort` structure and leaves the
own-entry skip and the overlap test at the `for page` level, outside the `for entry` loop:

```python
3561    seen: set[int] = set()
3562    own_entry = True
3563    for page in pages:
3564        for entry in span_index.get(page, ()):
3565            key = id(entry)
3566            if key in seen:
3567                continue
3568            seen.add(key)
3569        if own_entry and (                       # <-- 8-space indent: runs once per PAGE
3570            entry[1] == definition.name          #     `entry` = the LAST entry of that page
...
3578        if _entry_overlaps(definition, entry) and not _pair_exempt(   # once per page too
3579            definition, entry, mask_of
3580        ):
3581            return entry[1]
```

Three concrete defects, all against R-A2L-DEF.138 (`codewire/graph-inc2.md`
`describe_definitions` / `_shared_with`, the E3 close "first overlapping entry in
cross-kind file order"):

1. **Only the last entry of each page is tested for overlap.** Any overlapping neighbour
   that is not the last entry of its page is never examined, so `shared_with` is `None`
   and the encode proceeds — the exact clobber-the-neighbour hazard the guard exists to
   prevent. Discriminating case: objects `OA` (0x10, UWORD), `OB` (0x11, UBYTE,
   overlaps), `OC` (0x30, UWORD, same page, no overlap) → `_shared_with(OA)` returns
   `None` instead of `"OB"`.
2. **Broken own-entry skip.** The skip fires only when the definition's own entry happens
   to be the last entry of its page; otherwise the own entry is treated as a candidate and
   `shared_with` can become the definition's own name. Discriminating case: `.138/19`
   `Z1`/`Z2` at 0x0 → `_shared_with(Z2)` returns `None` instead of `"Z1"` (its own entry
   `Z2` is last, so it is skipped, and the overlapping `Z1` is never tested).
3. **Cross-kind file order lost.** The committed `candidates.sort(key=lambda e: e[0])`
   (position sort) is gone, so "first in file order" is no longer guaranteed even on the
   entries that are tested.

This is an `impl` defect, not a design gap: the committed HEAD at `cb083d07` has the
correct form (collect candidates across pages, dedupe by `id(entry)`, `sort` by position,
scan for the first overlapping non-exempt entry). It is also **not** caught by the current
suite, whose overlap cases mostly place two objects per page (so the overlapping object is
the last entry), which is why the GREEN run predates this edit.

**Correction (bounded):** revert the uncommitted hunk at `:3561-3580` to HEAD `cb083d07`
(`git show HEAD:s19_app/tui/a2l_definition.py`, the `candidates` list + `sort` + own-entry
scan). No new design work.

### F-2 — span-index page granularity changed `>> 8` → `>> 4` (impl, MEDIUM, uncommitted)

The same uncommitted edit changes the page size in **both** the index build
(`describe_definitions`, `:678-682`) and the lookup (`_shared_with`, `:3557`, `:3560`)
from 256-byte (`>> 8`) to 16-byte (`>> 4`) pages. The two sides stay consistent, so this is
not an index mismatch, but it is an un-reviewed deviation from the approved design
(`codewire/graph-inc2.md` `describe_definitions`, the `.136` example that counts the index)
and is not reflected in any record. It does not mitigate the 0x0-heavy files (all 0x0
entries still share one page) and changes the `.136` re-measure surface.

**Correction:** revert to `>> 8`, or land it deliberately with a record note and the
pending `.136`/serial-timing re-measure (the brief notes those are still running).

## Non-blocking findings

### F-3 — `.138/9` does not pin H1's address before using its declared-address point (test, LOW)

`tests/test_b103_a2l_definition.py::test_r_a2l_def_138_9_hostile_unknown_length_tag_covers_its_declared_address`
asserts `d.shared_with == "H1"` but never asserts the hostile ASCII `H1` keeps
`address == 0x10` first. The E3 close lists exactly that as an E4 addendum ("Assert hostile
ASCII H1 keeps `address == 0x10` before using its declared-address point in `.138/9`").
The overlap assertion implies it (VH is at 0x10 and overlaps H1), so the case is not
vacuous, but the explicit pin is owed. **Correction:** add
`assert describe_definition("H1", clean).address == 0x10` before the OVERLAP assertion.

## What I verified as correct in the committed HEAD `cb083d07`

- **Span-index identity / cross-kind order:** `describe_definitions` builds `span_entries`
  from one pre-order walk with a monotonic `position`; MEASUREMENT/CHARACTERISTIC consume
  tags per name via `tag_consumed` (duplicate-named neighbours each get an entry, so
  `.138/11` names the right one); BLOB/INSTANCE align with `declared_spans` in walk order
  (`extract_declared_spans` in `a2l.py` walks the same tree in the same order). `_shared_with`
  dedupes by `id(entry)` (correct across multi-page spans), sorts by position, skips its own
  entry, and returns the first overlapping non-exempt entry. Fail-closed point for an
  unreadable length is in `_entry_overlaps`.
- **CLEAN `mask_of`:** built on demand and cached by name; a neighbour's mask counts only
  when `refusal is None` **and** `byte_length is not None`, else `None` — matches
  `E3-rulings.md` (no whole-file second describe). `_pair_exempt` re-checks the definition's
  own refusal/length. `.138/10` (length-refused neighbour) and `.138/11` (duplicate-named
  neighbour) are discriminating.
- **Byte-order sources:** `_mask_byte_order_ambiguous` (`:3629`) counts live `BYTE_ORDER`
  in the object record (`_read_object_lines.byte_order_count`), the record layout and
  MOD_COMMON (via `mod_common_of`), returning `A2L-DEF-MASK "… byte order cannot be read"`
  before the mask-value refusals, matching `.19/7`. Layout name resolves through
  `record_layout_name or deposit`, consistent with `a2l.py:3117`.
- **Numeric vs enum precision:** `_agrees_at_display_precision` applies the 6-digit clause
  to FLOAT32_IEEE only (FLOAT64 never at 6 digits, `.54/3`); the exact-`Decimal` integer
  check fires only for integer datatypes with `None`/`IDENTICAL` conversion (`.54/4`).
- **Parse-error ordering:** `encode_definition` checks the definition's refusal, then
  `a2l_data["errors"]` → `A2L-DEF-PARSE`, then operator-value checks, then OVERLAP — the
  strict order `.57/5` and `.152/1 … /5` pin.
- **Image/mask merging:** `_merge_bit_mask` keeps untouched bits, shifts the field by
  `_mask_shift`, rejects `field < 0` or out-of-mask bits (`.47/1-/3`), and emits the whole
  span in the definition's byte order; big-endian mask bits are placed in the least
  significant byte (`_selected_bits`, `.138/17`).
- **Immutable input:** `_describe_one` copies the tag; encode builds new bytes and reads
  `image`/`a2l_data` only (`.58.1/1,/2`).
- **Exact messages:** `_operator_echo` preserves spaces and non-control Unicode, replaces
  controls with U+FFFD, caps at 256 with `…` (`.151/7`); `_echo`/`_number_text`/`_fmt_address`
  follow R-A2L-DEF.151; every refusal message stays ≤ 1,024 characters.
- **Discriminating negatives:** the 2b tests I read (`.19/6-/7`, `.26/2-/4`, `.40`,
  `.42/1-/11`, `.43 … .45`, `.46/1-/4`, `.47`, `.48/.49`, `.50 … .52`, `.53`, `.54`,
  `.55`, `.56`, `.57`, `.138/1 … /20`, `.152`, `.151/7`, `.58.2` encode arms, AT-B103-I2-1
  and AT-B103-I2-2 write arms) each carry an exact expected bytes/code/message or an
  isolation device (`_clear`, `_clear_parse_errors`); none is smoke.

## Not run (deferred to the runner, as the brief states)

- `tests/test_b103_a2l_definition_perf.py` / `serial_timing`: R-A2L-DEF.136 re-measure
  with the span index and `shared_with` in the walk. This is the one remaining thing that
  could change the verdict after the `_shared_with` revert — the index is O(n) to build but
  `_shared_with` per name is O(entries on the overlapping pages), which is worst-case
  quadratic for the 0x0-heavy fixtures (software_a 3,189 at 0x0). The pending runner
  timing must confirm the ≤ 2.0 s bound; nothing in this review pre-empts that measurement.
- Law guards (`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*`)
  — the 2b diff touches only `s19_app/tui/a2l_definition.py`, which is **not** in the
  `_ENGINE_PATHS` frozen set, so these should stay GREEN; still to be confirmed by the
  runner.
