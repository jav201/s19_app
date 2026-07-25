# 02 — Phase-2 cross-review (consolidated) — batch-62

> Sources: `02-review-architect.md` · `02-review-qa.md` · `02-review-security.md`. This file is the consolidated verdict and the fold list Phase 1 must discharge.

## VERDICT: **FAIL → `iterate-to-refine` (Phase 1).** Iteration 1 of Phase 2.

| Reviewer | Verdict | blocker | major | minor |
|---|---|---|---|---|
| architect | **FAIL** | 7 | 8 | 7 |
| qa-reviewer | **FAIL** | 7 | 6 | 5 |
| security-reviewer | OK-with-folds | 0 | 6 | 5 (+2 LOW) |

Blockers exist → the gate is forced, not discretionary.

## What SURVIVED adversarial re-measurement (do not re-litigate in Phase 1)

The **design core holds**. Two reviewers attacked it independently and neither could refute:

- **D-4** — the leaf module `markdown_safety.py`. The circular-import cycle is real and verified (`flow_report_service.py:63`, `diff_report_service.py:97`). *Correction to the rationale:* `report_service` is **not** "the base of the DAG" — it imports 5 sibling modules (`:52-60`). It is merely **upstream of the two generators**, which is all the argument needs.
- **D-5's ordering claim** — `_MD_ESCAPE[0] == '\\'`, `[1] == '|'`, replaced in tuple order. Verified.
- **D-6** — Mode B forbidden in table cells.
- **R-1 / Mode B sufficiency** — the spec's strongest ruling, verified end-to-end against the real `canonical_report_bytes`: Mode A leaks the drive letter, Mode B does not, because the substitution is a raw byte replace and `_RUN_ROOT_SPAN_RE` (`conftest.py:967`) already excludes the backtick.
- **Field inventory** — independently re-derived by a different method (enumerate every interpolation form, read all six composer bodies, classify by provenance, diff). **No missed file-derived field.**
- **Negative controls** — `10.1.2.3` and `evil.tld` measured inert under *both* parsers, and sharp.
- **Mode B's grammar inertness** — attacked with backtick-run lengths, fences, newline/CRLF, U+2028, trailing backslash, empty value. All inert.

## Independent convergence (strongest signal)

Both FAIL reviewers reached these **separately**, which is why they are not judgement calls:

1. **Golden drift is 3 lines, not 2.** Same root cause found twice: a field emitted **twice** was sampled **once**. The golden carries `| a | a.s19 |` (line 14) *and* `| b | b.s19 |` (line 15), plus line 51.
2. **`TC-376…387` are bare identifiers with no content** — they appear once under a "TC (proposed)" column. D-3's mapping is therefore unimplementable.
3. **`assert_field_inert` is unsound and unimplementable** — clause 1 is false on every benign table row; clause 2 joins raw and cooked token content.
4. **HLR-097 is false at merge** — "no report generator shall define its own grammar-escaping helper" vs D-8's deferral of `diff_report_service._md_table_cell`.
5. **Block-starter injection has no ruling** — carried into Phase 2 as a blocker, and no `D-*` disposed of it.

## Blockers to discharge in Phase 1

**Orchestrator errors (mine — 4, all now measured false):**

| # | My claim | Measured reality |
|---|---|---|
| E-1 | D-2: AT-157/158/159 map 1:1 "to be confirmed" | **REFUTED.** architect = closed 7-type enumeration; qa = "all tokens are `text`". A `hr` token from the block-starter leak is caught by the second and **not** the first — so the adopted AT-157 cannot see the registry's own Blocker #1. Same duplicate-id-divergent-meaning pattern D-1 fixed for US ids, waved through on ATs. |
| E-2 | §7: batch-39's guard is "blind to this class" | **OVER-CLAIMED.** It counts pipes in the **raw source** (`test_report_symbol_escape.py:150`), so a hostile pipe yields 8 ≠ 7 → RED. It is blind to the other 32 fields, not to this class. Justifying a rewrite as "blind" would have weakened a working guard. |
| E-3 | D-7: drift is "exactly 2 lines", 3rd blocks | **WRONG — it is 3** (14, 15, 51). A correct implementation would have tripped my own gate. |
| E-4 | D-5: "the benign no-op arm still holds" | **FALSE.** `_md_safe('SYM_A') → 'SYM\_A'`. Three assertion sites break across two files — `test_report_symbol_escape.py:166`, `test_report_service.py:260`, `:1403` — and `test_report_service.py` is **in no C-27 target list**. |

**Spec blockers:**

6. **Block starters** — `_MD_ESCAPE` lacks `-`, `+`, `=`; safe in `flow_report_service` only via the newline collapse at `:173`. Ruling supplied: keep the collapse (escaping `-` would make `mac-linked` → `mac\-linked`), pin it three ways — normative LLR + delete-it-goes-RED counterfactual + a **new static column-0/prefix guard**. Also unnamed in my list: `1) item` → `ordered_list_open`.
7. **G-1 vs G-4 contradict each other** — `html_inline`/`html_block` are in `ACTIVE_RULES` with **no payload row** (G-1 RED on its own table), while G-4 kills 3 of 31 payloads (`entity`, `escape`, `table-pipe`) that G-1 mandates. `TC-376` is unimplementable as written. `table-pipe` is inert only because G-4 parses **context-free** — the batch-60 "assert at the SINK" lesson violated inside the C-31 deliverable itself.
8. **AT-160/161/162 UNREALIZED** — no prospective on-disk node; §8's target table predates D-2. AT-160 is satisfiable only in parts and its clause 1 is **vacuous** (byte-identity against a golden re-captured from the code under test is true by construction).
9. **`<in-memory document>`** (`:894`, `:1093`) emits `html_inline` under the default parser → **breaks AT-158's unqualified "zero `html_inline`" clause on a benign fixture.**
10. **Non-idempotence has no over-application detector** — LLR-095.3's census catches under-application only. New **AT-163** required (plant `SYM_A`, require `SYM\_A`, forbid `SYM\\\_A`).

**Security folds F1–F6 (prerequisites to Phase 3, not post-merge carries):**

11. **`&` is not escaped** — verified independently: `_md_safe` passes `&vert;`, `&num;`, `&ast;`, `&lt;script&gt;` through unchanged. `SYM_A&vert;PASSED` renders a forged table fragment while every token stays `text`, so **`assert_field_inert` scores it GREEN**. The oracle is blind to the class.
12. **`:x:` / `$…$` / `==mark==` survive** — a filename can put a red ❌ beside a PASSED row on GitHub.
13. **U+202E / U+200B / U+FEFF / C1 survive** (`ch >= " "` kills C0 only). TC-382's expectation is "no exception, no mojibake" — a robustness test that proves nothing about deception.
14. **`_redact_absolute_paths` exists** (`flow_report_service.py:239`, batch-60 F2) and batch-62 **never mentions it**. Not applied to `issue.message` (`:1026`) — the highest-risk field. Mode B's justification **requires the path to stay raw**, making the control structurally harder to add later. Batch-60 raised exactly this from LOW to MAJOR on shareability grounds; that ruling was silently dropped. Needs an explicit decision either way.
15. **Fail-closed is entirely unspecified** — correct today only by accident (single sink at `:1613`).
16. **`_declaration_error_lines` (`:1025`) is uncapped** — no counterpart to flow-report's `MAX_REPORT_FINDINGS_PER_BLOCK = 200`, and LLR-098.3 **doubles** its per-issue cost (240→500). TC-397 passes vacuously on exactly the section the batch grows.
17. **Mode B removes backticks rather than escaping** — violates the catalog's own no-sanitise-by-deleting clause; `` FOO`BAR `` is silently recorded as `FOOBAR`, a different symbol. Payloads #8/#9/#10 will **fail clause 2 against a correct implementation**, whose predictable outcome is someone weakening the clause under time pressure.
18. **`MAX_REPORT_CELL_CHARS = 240` silently truncates ~20 Mode-A fields** with nothing covering it; qa's TC-396 is written *conditionally* ("if the design introduces a cap"), making it optional. Mode B's 240 on absolute paths makes truncation depend on the operator's tmp-root depth → a **machine-dependent golden**, R-1's family through another door. `TRUNCATION_MARKER` is two different constants (`validation/model.py:21` vs `flow_report_service.py:85`).

## Increment cut (C-21 fires — the AT set changed, so the cut is re-derived)

7 ATs, one owning increment each, ≤5 files each:

1. **Inc-1 (3 files)** — `markdown_safety.py` (new) · `flow_report_service.py` (aliases; `MAX_REPORT_CELL_CHARS` stays there) · `tests/test_report_markup_safety.py` (new). Owns **no AT**. Exit: `test_flow_report_*.py` 0 edits / 0 failures.
2. **Inc-2 (5 files)** — `report_service.py` (tables + paths; remove the deferred import at `:965-968` and the call at `:978`) · the golden (**3-line** recapture) · `test_report_symbol_escape.py` · `test_report_service.py` · `test_tui_report_filter_surface.py`. Owns **AT-159, AT-160, AT-162, AT-163**. Kept together so the golden is never RED across a boundary.
3. **Inc-3 (3 files)** — `report_service.py` (headings, issues, addendum, filter; drop `_strip_ctl_local`) · `tests/test_report_field_census.py` (new — 24-site sweep + four static guards). Owns **AT-157, AT-158**.
4. **Inc-4 (2 files)** — hexdump-fence + `_format_bytes` pins · `REQUIREMENTS.md`. Owns **AT-161**.

## Process note

Both Phase-2 sub-agents self-corrected in their own reports (the architect withdrew a false finding about `LLR-095.2` after a bad grep; qa found 4 of its 7 blockers in its own catalog). Adversarial self-review is doing real work here and should be preserved in Phase 1's fold.
