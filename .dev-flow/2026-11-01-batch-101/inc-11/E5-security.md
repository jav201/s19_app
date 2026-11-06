# Inc 11 — E5 security review (implemented code)

Batch 2026-11-01-batch-101, increment 11, stage E5 (`dev-flow-v3-beta`). Reviewer lens: security (untrusted A2L input). Scope: `git diff main...HEAD -- s19_app` at head `688ca2b` (`tui/a2l.py`, `validation/rules.py`, `tui/app.py`, `tui/issues_view.py`). Records read: `E3-security.md` (S-1 … S-11), `E3-rulings.md` (incl. round 2 N-1 … N-4), `E4-integration-notes.md`. Severity: HIGH / MEDIUM / LOW / INFO (flow scale: MEDIUM = MAJOR, LOW = MINOR, INFO = note). Tags: `impl` (code vs design), `design-gap` (the design itself leaves the risk).

## Verdict

**PASS-WITH-NOTES** — no HIGH finding. S-1, S-2 (as ruled), S-5 and S-6 are closed on the implemented code (probed). The IF_DATA skip adds no hang and no new crash; the recursion limit and its crash point are unchanged and stay contained. The curve-description change adds a constant line only. Removing the WARNING → INFO re-labelling hides no defect beyond the accepted D-1 / S-4 IF_DATA cases. One MEDIUM design gap remains open as a backlog item and does not block (E5-1): the ruled bound (base + size ≤ 2^32) still admits a segment that covers the whole 32-bit address space, and the Split fill path that would materialise it has no size guard. This report clears risks only. It does not authorise the merge or the push.

## Evidence (probes, operator run rule)

Two read-only probes (`s11sec_probe.py`, `s11sec_probe2.py`) ran on the LAN Linux host (`s19ci`, Python 3.11.18, recursion limit 1000). They used two detached worktrees of `origin/main` `f9f3cb09` (identical to `b7b77c4` in `s19_app/`): one had `git diff b7b77c4 688ca2b` applied (branch), the other was left pristine (base). Both worktrees and every temporary file were removed afterwards, and the host's own checkout was not touched. Nothing ran on the Windows PC. State of every probe below: `executed`.

| # | Probe | Branch result | Base (where compared) |
|---|---|---|---|
| P1 | `_a2l_number` on `٣`, `１２`, `1_000`, `0x_10`, `0x1_000`, `0o17`, `0b101`, `0x` + 9 hex, `0x` + 5 000 hex, 11 decimal digits, `1e3`, `0x1G`, `0x`, `+`, `""`, `12 ` | all `None` | — |
| P1 | `0xFFFFFFFF`, `9999999999`, `0400`, `+0x10`, `-0`, `0X1f` | 4294967295, 9999999999, 400, 16, 0, 31 | — |
| P2 | real parser, `S1b … 0x1000 BAD -1 -1 -1 -1 -1` / `S1c … 0xZZ 0x1000 0x400 0x800 -1 -1 -1` | base / size / offset / usage / kind all `None` (S-1 closed) | — |
| P2 | full-width, underscore, `0o`, `0b`, 40-hex-digit size, `0x0 0x100000001`, `0x2 0xFFFFFFFF`, `-0x100 0x1000`, `0x0 0x0` | no base, no size | — |
| P2 | `0x1 0xFFFFFFFF`, `0x0 0xFFFFFFFF`, `0 4294967296` | **accepted**; the last one is `[0, 2^32)`, the whole 32-bit space (E5-1) | — |
| P2 | Arabic-Indic `٣ 0x10 0x20` | base 0x10, size 0x20 (the accepted N-2 residual, as recorded) | — |
| P2 | `"0x1000" 0x200 0x300 -1 …` (quoted address) | base 0x200, size 0x300 (E5-3) | — |
| P2 | S-6: meta `S7 "oops` + `/* 0x10 0x20 */ DATA FLASH INTERN 0x1000 0x200 -1`; a mid-line `DATA "x /* 0x10 0x20 */`; an escaped `"a\\"` on the `/begin` line | base 0x1000, size 0x200 in all three (S-6 closed: the quote state resets per line) | — |
| P2 | unterminated `/*` on the `/begin` line | no base | — |
| P2b | 4 000 random MEMORY_SEGMENT records (hostile word set incl. `/*`, `//`, lone `"`) | 0 exceptions; 0 half pairs; 0 pairs outside `base ≥ 0, size > 0, base + size ≤ 2^32` | — |
| P2c | one 4.2 MiB MEMORY_SEGMENT block (20 000 lines × 53 words) | one `extract_memory_segments` 0.98 s; `parse_a2l_file` 2.02 s | 0.00 s / 0.01 s (E5-2) |
| P3 | balanced IF_DATA holding `FROBNICATE` | 0 issues | 1 WARNING |
| P3 | IF_DATA never closed (counts unbalanced) | `A2L_STRUCTURE_ERROR` kept | same + WARNING |
| P3 | IF_DATA not closed, a stray `/end` balances the counts | 0 issues (S-4, accepted, backlog) | 1 WARNING |
| P3 | top-level `FROBNICATE` + `PAGE` | 2 WARNINGs (the former curated `PAGE` now surfaces) | 2 + wrapper |
| P3 | nesting under IF_DATA root / plain root: depth 900, 960 | parse + validate OK, < 0.03 s | same |
| P3 | depth 990 IF_DATA root; depth 3 000 both roots; 5 000 unclosed `/begin` | `RecursionError` in **parse**, before validation | identical thresholds |
| P3 | 5 000 stray `/end` under IF_DATA | 4 999 structure errors, 0.01 s | same |
| P3 | 200 000 sibling blocks under IF_DATA | parse 0.66 s, validate 0.22 s, 0 issues | 0.71 s / 0.59 s, 200 001 WARNINGs |
| P3 | synthetic tree fed straight to `validate_a2l_structure`: depth 950 / 1 200 | OK / `RecursionError` | identical (the parser fails first, below 990, so 1 200 cannot be reached through a file) |
| P5 | `_filtered_validation_issues` on [OK, INFO, NEUTRAL, ERROR, WARNING, ERROR, OK], filters all / error / warning | `e1 e2 w1 i1 ok1 n1 ok2` / `e1 e2` / `w1`; no `KeyError`, stable (S-5 closed) | — |
| P7 | `render_curve_description`: all points index-only; mixed points; name `C[/b]\x1b[31m`, long identifier `[red]x\x07` | one constant line `  x: point index (axis points unavailable)` and no per-row suffix; mixed points keep the per-row suffix; the file text passes through unchanged, with `\x1b` and `\x07` (pre-existing, E5-5) | — |
| P8 | `safe_text("… 'EVIL\x1b[31m[/b]\x07'.")` | control bytes removed, no spans, `[/b]` literal | — |
| P8 | `A2L_UNRECOGNIZED_BLOCK` census on `software_a`, V171, `xcp_test`, `memorysegment`, `synth_a2l` | 0 on all five | 1 023 / 169 / 52 / 7 / 4 (all recognised now, or nested inside IF_DATA) |
| P4 | `fill_range({}, 0, 2^22, intra_gap="fill")` | 0.29 s, +326 MiB RSS; scaled to 2^32: about 5 min and about 326 GiB | same |

## Verification of the E3 items

| E3 item | State on 688ca2b | Evidence |
|---|---|---|
| S-1 broken record gives no base | **closed** (`approved`) | `a2l.py:1097-1110`, anchored rule, no further scan; P2 S1b / S1c |
| S-2 Number by ASCII pattern; bound | **closed as ruled** (`approved`) | `a2l.py:949-979`; P1; `base + size ≤ 2^32` at `a2l.py:1110`; P2. The whole-space residual is E5-1 |
| S-3 recursion | unchanged and contained (`approved`) | the flag is passed down (`rules.py:457`), one frame per level, same thresholds on both trees (P3); the attach worker catches the error as a load failure (`app.py` `_a2l_attach_worker`, `except Exception`) |
| S-4 stray `/end` | as accepted (backlog) | P3 |
| S-5 OK / NEUTRAL sort | **closed** (`approved`) | `app.py:16395` (`.get`, default `len(SEVERITY_ORDER)`); P5 |
| S-6 quote state per line | **closed** (`approved`) | `a2l.py:982-1060` (`in_string` reset per text; a block comment may still span texts); P2 |
| S-8 re-labelling removal | no defect newly hidden beyond D-1 / S-4 | P3 / P8; hostile names still go through `safe_text` (P8). Test half owed: E5-4 |
| S-9 modal title / body | unchanged, backlog | P7 (E5-5) |
| S-11 record-word cost | measured; LOW | E5-2 |

## Findings

| Id | Tag | Severity | Where | Scenario | Recommendation |
|---|---|---|---|---|---|
| E5-1 | design-gap | MEDIUM | `a2l.py:1110` (bound `≤ 2**32`); `segment_split_view.py:480` (guard only on `join` + `fill`); `segment_ops.py:319` (`fill_range` builds one dict entry per address) | A hostile A2L declares `… DATA FLASH INTERN 0 4294967296 -1 …` (or `0x0 0xFFFFFFFF`). The reader accepts it (P2): it appears as an `a2l` row in Split / Join, and `classify_address` gives every tag in the image that segment's region. If the user picks that row and exports Split with intra-gap `fill`, there is no guard and no confirm, and `fill_range` tries to build about 4.3 G entries (P4: about 326 GiB, about 5 min of CPU before it runs out of memory). The TUI session is lost and so is any unsaved work. Join + `fill` asks for a two-step confirm, but the confirm does not say what the export will cost. This is not new: the base accepted any size, even larger ones. Inc 11 narrows the risk but does not close it. Only the user's own session is affected, and only after they pick the row and press export. The brief's statement "a whole-address-space segment can no longer be produced" does **not** hold. | Backlog (the size-cap item E3 already deferred; promote it to a named item): refuse, or ask a confirm that names the byte count, before any Split / Join fill materialises more than N MiB (e.g. 256 MiB). Optionally tighten the reader bound so that `size < 2^32`. Evidence: `executed`; fix: `planned`. |
| E5-2 | impl | LOW | `a2l.py:982-1060` (`_memory_segment_record_words` tokenises every own line); callers `extract_a2l_tags`, `parse_a2l_file`, `segment_split_view._a2l_rows` | A hostile 4.2 MiB MEMORY_SEGMENT block takes about 1 s per call (P2c). That is about 2 s inside the attach worker and about 1 s more on the Split / Join window path (`_a2l_rows`, cached per A2L). The base took 0.01 s. The cost is linear (about 4 MiB/s), the same order as the per-byte cost of parsing a whole A2L, with no hang. Real files are not affected: their blocks are a few lines (E4 case_06: parse 10.8 s vs 11.0 s). | Optional: stop collecting words once the anchor and the two words after it (`k + 2`) are known, which is the S-11 fix. No change needed for Inc 11. |
| E5-3 | design-gap | INFO | `a2l.py:1097` (anchor skips quoted words) | A quoted address (`"0x1000" 0x200 0x300 -1`) moves the anchor one word to the right, so base = the size word and size = the first offset (P2). With the standard `-1` offsets the record yields no base. This is invalid A2L, the same class as the accepted N-3 residual, and the R-A2L-036.4/8 case (`"1" "0x10"`) still gives no base. | Record it beside N-2 / N-3 in D-5. No code change. |
| E5-4 | impl | INFO | `tests/test_tui_issues_triage_b94.py:403-416` (C-17 hostile arm) | E3 S-8 asked the rewritten arm to assert both halves. It uses `EVIL[red]` only, so no control byte is tested on this surface. P8 shows that `safe_text` does scrub `\x1b` / `\x07` and keeps `[/b]` literal, so there is no product defect, only missing test strength. | Extend the arm's name to `EVIL\x1b[31m[/b]` and assert that no C0 byte appears in `rendered.plain`. |
| E5-5 | design-gap (pre-existing) | INFO | `a2l_describe.py:68` (`Label(f"Parameter: {title}")`, markup on); `a2l.py:3347` body text | A tag named `C[/b]` makes `Text.from_markup` raise `MarkupError` when the modal opens. Control bytes in the name, long identifier and unit reach the `markup=False` body unscrubbed (P7). Inc 11's change (`a2l.py:3421-3428`) adds only a constant line and code-set notes. | Already in the backlog as S-9: route the title and body through `safe_text`. |
| E5-6 | design-gap (latent) | INFO | `issues_view.py` `GroupedIssuesPanel.render_groups` (loops `SEVERITY_ORDER` only) | An OK / NEUTRAL issue now sorts last without error (P5). It would count in the total but render in no group. No code creates such issues today (MAC-row states only). | None for Inc 11. If such issues ever reach the list, give them a group or filter them out at assignment. |

No secrets, credentials, external tools, connectors, auth or deploy surface are touched by this increment. The export name of an `a2l` row still passes through `sanitize_export_segment`.

## Items for the batch end (not security blockers)

- E5-1 → backlog: Split / Join fill size cap or a confirm that names the byte count.
- E5-4 → test strengthening; can fold into the batch-end test round.
- E5-3 → D-5 note.

## Evidence checklist

- [x] Each finding has what · where · why · recommendation: Findings table (scenario column = what / why).
- [x] Each finding has a severity: column 3.
- [x] No secret values in this report: none exist in scope.
- [x] Verdict explicit (PASS-WITH-NOTES); no HIGH open; the E3 MEDIUMs S-1 / S-2 are closed with executed probes (P1, P2, P2b).
- [x] New tool / integration: none (`n/a — no external tool, connector or credential in scope`).
