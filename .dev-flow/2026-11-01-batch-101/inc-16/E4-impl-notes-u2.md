# E4 implementation notes — U2 (architecture)

Unit U2 of batch-101 Inc 16. Files owned: `docs/architecture.md` (edited in place, CRLF kept) and
`.dev-flow/design/archive/architecture-batch-declarations-88-100.md` (new). No other file was touched;
`docs/diagrams/` and the three moved notes were left to their owning units.

## 1. docs/architecture.md — in-place corrections (kept sections)

| Block | Before (c2cba35) | After | Rows |
|---|---|---|---|
| Header link to the diagrams file | `:6` sentence "For the visual call-graph … [diagrams/architecture.md]" | deleted; the overview link sentence stays | REF.2 |
| §2 activity-rail probe paths | `:28` cited `evidence/pdr_rail_key_probe.txt` + `evidence/inc003_rail12_probe.txt` | repointed to `.dev-flow/2026-10-12-batch-94/evidence/…`, wrapped in code spans | REF.1, DEV.12 |
| §2 modal count + rail count | `:48` "Fourteen modal screens … (batch-94 grew the rail 10→12: …)" | "Modal screens …" with the modal list kept, the `10→12` clause dropped | DEV.12 |
| §2 diagrams sentence | `:59` "The diagrams in [diagrams/architecture.md] …" | deleted | REF.2 |
| §8 test count | `:154` "Roughly **2760 tests** … (collected 2026-10-11)" | "The test suite under `tests/` is organised by module …" | DEV.13 |
| §9 increment cap | `:173` "capped at ≤ 5 files" | "capped at ≤ 4 source files" | ARCH.6 |

## 2. docs/architecture.md — §10 and §11 rebuilt (D-4 shape as amended at E3)

**§10 (`:178`–`:218`).** The module table keeps the five `path/**` prefixes
(`s19_app/**`, `tests/**`, `tools/**`, `.dev-flow/**`, `docs/**`); the `prototypes/**` row and
rationale row #2 are gone; the rationale header and row #1 read "five" (renumbered #3→#2); the
`docs` row no longer names the removed diagrams. The batch-92/94/97/99/100 declarations are replaced
by one present-tense sub-module table at `:213` with the columns
`Sub-module | Encapsulates | Exposes | Must not import` and three rows
(`s19_app/render/hexview.py`, `s19_app/render/format.py`, `s19_app/tui/flow_screens.py`). The two
`render/` rows state "no `s19_app.tui` import" (held by TC-651); the `flow_screens.py` import cell
reads `not declared` — no import rule is restated.

**§11 (`:219`–`:285`).** One Interfaces table (header `Interface | Owner module | Consumers | Shape | Frozen?`
at `:227`). **57 contracts**: the 12 named contracts (3 Part B, 4 batch-92 surfaces, 5 batch-94
surfaces) plus the 45 landed batch-97/99/100 rows carrying 46 source tags
(`B97-I-1`…`B97-I-11` with `I-2`/`I-3` on one row, `B99-I1`…`B99-I12` + `B99-I2a`, `B100-I1`…`B100-I22`).
Every row is present tense, carries no `.py:<line>` citation and no `Current`/`After` column; every
`Frozen?` cell is `no`. Five Shape cells say `saved file` (`.chk.json`, flow template / chain-set,
`B100-I1`, `B100-I9`, `B100-I16`); the rail-invariant row states twelve and no "ten".

## 3. .dev-flow/design/archive/architecture-batch-declarations-88-100.md (new)

One-line header (origin + reason), then the verbatim blocks moved out of `docs/architecture.md`.
The archive holds the original `:180`–`:685` in full — the `---` separator and the four amendment
notes of batches 88/92/94 (`:180`–`:224`), the whole of §10 (`:226`–`:574`, which includes the retired
`prototypes/**` row at `:238` and rationale row #2 at `:256`), and the whole of §11 (`:575`–`:685`).
Capturing §10 and §11 in full (not only the strictly-removed lines) is deliberate: it guarantees that
every line removed inside §10, §11 or an amendment note appears in the archive (R-DOC-ARCHIVE.2/1),
with no risk of a missed line. A `git diff` check confirmed 338 removed lines in that scope, 0 missing
from the archive. The archive adds no local identity (verbatim copy of a source already scanned clean).

## 4. Deviations

- **Archive line endings are LF**, not CRLF like the source: the sibling archive files (the three
  moved notes) are LF, and the new file matches that convention; the E5 archive check compares
  stripped lines, so this is behaviour-neutral. `docs/architecture.md` itself keeps CRLF.
- **The archive contains the full §10 and §11, not only the moved lines.** Reason: bulletproof
  R-DOC-ARCHIVE.2/1 coverage (removed lines ⊆ archive) with no line-by-line extraction that could
  drop one.

No other deviation from the D-4 shape, the E3 rulings or the E4 addenda.
