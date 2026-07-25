# 02 — Phase-2 cross-agent review · batch-60 (FB-P1b flow-run report generation)

**BLUF:** The spec **FAILED** its first gate and was revised. Two independent reviewers
converged on the same three defects, each **verified by execution against the real parser**
(not inferred): the markup contract was written for the wrong grammar, the operator's D-6
decision was unimplementable at the specified wire point, and the status rollup keyed on a
string proxy that matches 1 of 9 real abort sites. Resolutions **AMD-1..AMD-14 below are
authoritative (§6.5): on any conflict, they OVERRIDE the §3/§4 body of `01-requirements.md`
and the `01b-qa-catalog.md` bodies.** Phase 3 implements the amended contract.

## Reviewers + verdicts
- **qa-reviewer:** **FAIL** — 3 HIGH, 9 MAJOR, 7 minor. "Do not enter Phase 3 as specified."
- **security-reviewer:** **0 HIGH**, OK-to-ship **only with F1–F6 folded in before Phase 3**;
  6 MAJOR, 5 LOW. No secret, no external tool/scope, no auth surface, no destructive action.
- **Convergence:** qa H-1 ≡ sec F1+F2 · qa H-2 ≡ sec F5 · qa H-3 ≡ sec F4 · qa M-3 ≡ sec F3 ·
  qa M-4 ≡ sec F6. Independent agreement on all three HIGHs.

## Self-verification (main loop, before accepting)
I re-ran the load-bearing claims myself rather than taking them on trust:
- `MarkdownIt("gfm-like")` → `linkify enabled: True`; a ledger cell containing
  `http://evil.example ~~VOID~~` renders `<a href=…>` **and** `<s>` — **CONFIRMED**.
- `flow_execution_service.py:119-124` — the `if aborted:` skip guard sits **above** the
  `try` that holds the `ReportBlock` branch (`:378`) — **CONFIRMED**.
- `_record_error` summaries (`"source unresolved"`, `"no image"`, …) ≠ `"error"` — the
  prototype's `summary == "error"` proxy matches only the generic `except` — **CONFIRMED**.
- Prior-art escapers exist (`diff_report_service.py:256/:282`, `report_service.py:512`) —
  **CONFIRMED** (and assessed below: weaker, different sink).
- `tests/test_flow_persistence.py:350` asserts `"deferred" in report.summary` — **CONFIRMED**
  it will break.

## Findings → authoritative resolutions (AMD-1..14)

| # | Src | Sev | Finding | Resolution (AMD) |
|---|-----|-----|---------|------------------|
| AMD-1 | qa H-1 · sec F1/F2 | HIGH | `_md_safe` escapes a CommonMark set; the sink is `MarkdownIt("gfm-like")` with `linkify=True` → bare URLs become live links, `~~x~~` becomes strikethrough (a **deception** primitive in an audit record). AT-003's declared payload only used `[..]` links, so TC-004 could never catch it. | **LLR-001.3 rewritten to NAME THE GRAMMAR** ("gfm-like as configured by `textual.widgets.Markdown`, linkify enabled") and add **`~` and `/`** to the escape set. **Escaping `/` is the adopted control** — I probed both candidates against the real parser: escaping `/` kills `http://…` **and** protocol-relative `//evil.example/x`, whereas sec's scheme-colon regex leaves protocol-relative **LIVE**; and `\/` renders **invisibly** (`out\/prg\_patched.s19` → `out/prg_patched.s19`), so paths stay readable. |
| AMD-2 | qa H-1 fix 3 | HIGH | A character-list assertion is a moving target against a parser we do not control. | **TC-004's mechanism changes:** the test shall render the composed report through `MarkdownIt("gfm-like")` and assert the **token stream** contains no `link_open`, `s_open`, `code_inline`, `heading_open`, nor any `td_open` beyond the declared column count. This stays true when the escape set is wrong in a way nobody predicted. Per-payload sub-cases (`http://`, `//host/path`, `~~x~~`, backtick, `#`, `[..]`, `<`) are retained as the C-31 per-branch battery. |
| AMD-3 | qa H-2 · sec F5 | HIGH | D-6 ("an aborted run still writes a report") is **unimplementable** at `:378`: the `aborted` guard at `:119-124` appends SKIPPED and `continue`s before the `try`. D-6 also had no LLR, no AT and no §7 row. | **Option (a) adopted** (D-6 is an operator-approved decision; keep it, make it real). **NEW LLR-003.3:** the `aborted` skip guard shall exempt `ReportBlock` so a post-abort report still writes; the report emits `BLOCK_STATUS_OK`, threads `aborted=True` into the state (→ FAILED label), and **does not clear `aborted`** (blocks after it still skip). **NEW AT-009** (D-6 discriminator) + §7 rows for **D-5 and D-6**. |
| AMD-4 | qa H-3 · sec F4 | HIGH | The FAILED rule had no defined input: the prototype infers `status==error and summary=="error"`, which matches only the generic `except` (`:390`) — all 8 `_record_error` shapes (`"source unresolved"`, `"no image"`, `"write failed"`, …) would misclassify a FAILED run as COMPLETED WITH ISSUES. | **The state object carries an explicit `aborted: bool`** threaded from `run_flow`; **LLR-001.2 shall key FAILED on that field and shall NOT infer abort from `BlockResult.summary` or status.** Threshold rewritten to a countable oracle: **all 9 abort sites (8 `_record_error` + the generic `except`) yield FAILED; the 2 non-aborting `_record_check_own_op` shapes yield COMPLETED WITH ISSUES.** TC-013 splits into **TC-013a** (a `_record_error` abort — custom summary) and **TC-013b** (CHECK own-op error = the negative control). |
| AMD-5 | qa M-3 · sec F3 | major | The Written-files section wraps paths in a code span, where **backslash escapes are not processed** → a benign path renders with a stray `\`, and `` a`b`c `` breaks out of the span into live inline context (where AMD-1's vectors then fire). | **Drop the backtick wrapping** in Written files (verified: `- {_md_safe(p)}` renders correct and inert), and make `_md_safe` **context-free** by **removing** backticks rather than escaping them. **NEW TC-014:** a written path containing a backtick produces no early `code_inline` close and no live structure; a benign path round-trips **character-identical** (no stray `\`). |
| AMD-6 | qa M-3 · sec F11 | major | `_md_safe` was specified as NEW with no reuse analysis, while `diff_report_service._md_cell` (`:256`) / `_md_table_cell` (`:282`) / `report_service._strip_ctl_local` (`:512`) already exist. | **RULING: a new symbol is CORRECT here, and the spec must say why.** I read the prior art: it strips control chars and escapes `|` (and `\`) **only** — it does not touch `#`, backticks, `[`, `~`, `/` or linkify, and it is scoped to a different, never-linkify-audited sink. Reusing it would be a **downgrade**, and extending it would silently change two shipped report generators inside a batch that does not test them. LLR-001.3 shall carry this rationale explicitly (anti-silent-fork, rule 11). **CARRY (not this batch): `report_service` embeds file-derived text into markdown with NO escaping at all (sec F11) — a separate hardening batch.** |
| AMD-7 | sec F6 · qa M-4 | major | No byte budget. SOURCE emits **one Finding per parser error, uncapped** (`:164-167`); `_md_safe` ~doubles worst-case length. A corrupt image → an arbitrarily large `.md` → disk/UI cost **and** the report can exceed `VIEWER_SIZE_CAP_BYTES` (4 MiB, `screens.py:77`) → **refused by the very viewer US-002 promises**. | **LLR-001.1 binds a size policy, REUSING `report_service._ByteBudget`/`_line_bytes` (`:358-386`)** — the same reuse-not-fork rule already applied to `_report_filename`: `FLOW_REPORT_MAX_TOTAL_BYTES` (≤ `VIEWER_SIZE_CAP_BYTES`), `MAX_REPORT_CELL_CHARS = 240` with a `… (truncated)` marker applied **before** escaping, and a per-block findings cap with an "N more suppressed" line. **NEW TC-015** asserts the boundary PAIR (exactly-MAX not truncated; MAX+1 truncated + marker) and that a 64-block × many-findings run stays ≤ cap. |
| AMD-8 | sec F7 | major (raised from LOW) | `written_paths` holds **absolute** host paths → `C:\Users\<user>\OneDrive\…` lands in a document explicitly positioned as a shareable client record. | **LLR-001.1: render `path.relative_to(project_dir)` with `path.name` as fallback — never `str(absolute)`.** **NEW TC-016:** no drive letter and no `Users` segment appears in the output. (Raised above the reviewer's LOW because the batch objective is a *shareable* artifact and the fix is one line.) |
| AMD-9 | qa M-1 | major | The footprint fields are **empty at report time**: `result.image_ranges` is assigned only **after** the loop (`:420`). An implementation reading `result.image_ranges` emits `Final: (none)` in every report **and AT-005 still passes** (it only inspects ledger rows). | **LLR-001.1/003.1 shall state the source PER FIELD:** `image_ranges` ← the **local threaded `ranges`** (`(none)` when `None`); `pre_crc_ranges` ← `result.pre_crc_ranges` **as-is at that instant** (so a pre-CRC report legitimately omits the "Before CRC" line — this asymmetry vs the post-loop default at `:423-424` is intentional and is now written down); `written_paths` ← `result.written_paths` (live at `:227`). **NEW AT-010:** `LOAD → REPORT#1 → CRC → REPORT#2` ⇒ #1 has no "Before CRC" and a Final equal to the source footprint; #2 has "Before CRC" and a **strictly larger** Final total. |
| AMD-10 | qa M-2 | major | AT-007 ("two files exist, second has `-01`, neither empty") does not discriminate D-4 — collapsing N report blocks into one composition written twice passes. | **AT-007's Then adds:** the two reports **differ**, and report#2's ledger has **strictly more rows** than #1's, with **#1's rows a prefix of #2's**. Pins D-4 (N independent reports) and D-2 (positional) in one assert; the `-01` assert stays as the `_report_filename`-reuse discriminator. |
| AMD-11 | qa M-5 | major | Whether the report path joins `result.written_paths` is undefined and observable (a D-4 report#2 would list report#1; the ledger's written-path lines would list reports beside images). | **RULING: NO.** `written_paths` is the image-output contract consumed by the ribbon and ledger; a report is a **record, not an image output** — the same reasoning LLR-003.1 already uses for degrade-not-abort. AT-007 gains the assert: report#2's Written files does **not** list report#1. |
| AMD-12 | qa M-7 · sec F8 | major | AT-008's "unwritable `reports/`" is a **no-op on Windows** (`os.chmod` does not remove dir write perms) → the test would pass proving nothing. The caught exception set was also undefined, and `_report_filename` raises `FileExistsError` after 99 slots — a real degrade path nobody mentioned. | **AT-008's Given becomes a portable REAL failure:** create a regular **file** named `reports` in `project_dir`, so the production `mkdir(parents=True, exist_ok=True)` genuinely raises on both platforms (no mock). **LLR-003.1 pins the contract:** catch `Exception` (never `BaseException`); the diagnostic is `f"{type(exc).__name__}: {exc}"` mirroring `:395-399`; the whole-flow rollup still degrades to ISSUES (an `error` block satisfies `:405-408`) so a failed write can never read CLEAN — **AT-008 asserts that too**. Given's shape pinned to **`LOAD → REPORT(fails) → WRITE-OUT`**, asserting WRITE-OUT is `ok` **and its file exists**. **NEW TC-011b:** the 99-slot `FileExistsError` degrades through the same path. |
| AMD-13 | qa M-8 · sec F10 | major | AT-004 was excluded from the C-20 RED-verify list despite being the **zero-code-change** test (highest false-confidence profile), and its `spans == []` assert is a **tautology** (a tool-derived summary rendered `markup=False` cannot inject a span). Separately, the whole markup story rests on the ambient `open_links=False` (`screens.py:1405`) with nothing pinning it. | **AT-004 joins the C-20 list** (RED-verify: revert the summary to `report written` → filename assert RED) and its read is **scoped to the REPORT block's own `.flow-node-summary` Static**, not a substring search of the pane; the `spans == []` claim is **dropped** (relabelled a non-load-bearing invariant). **NEW AT-011 (render-side hardening, sec F1 control 1 + F10):** the report `Markdown` widget is constructed with an explicit hardened `parser_factory` (**`linkify=False`, `html=False`**, tables on) and `open_links=False`, with a test pinning it — counterfactual: flipping either → RED. This is the **enforcing** control; AMD-1 is the best-effort control for the `.md` once it leaves the app. |
| AMD-14 | qa M-6 · M-9 · minors | major | (M-6) No regression checklist — `tests/test_flow_persistence.py:350` (`"deferred" in report.summary`) **will break**, and an undeclared assert edit during Phase 3 is indistinguishable from silencing a failure. (M-9) C-21 broken: AT-001/AT-005 claimed by increments with no writer. | **NEW Regression checklist (§ below), declared NOW.** **C-21 remap:** AT-001, AT-005, AT-009, AT-010 → **Inc-2** (they need the writer + wire); Inc-1 owns unit precursors under their own ids (**TC-001u**, **TC-008u**) that claim no AT ownership; AT-004 + AT-011 → **Inc-3**. Folded minors: **m-1** AT-001 asserts exactly one **new** report vs a pre-run snapshot; **m-2** the "golden-structure match" threshold is replaced by "the five section headings present, in order" + the existing per-block clauses; **m-3** the body timestamp format is pinned and TC-001 asserts **determinism** (same state + same `generated_at` → byte-identical); **m-4** every test read uses `encoding="utf-8"` and a unicode TC (CJK + emoji + ZWSP) is added — the composer already emits a non-ASCII en dash; **m-5** a flow named `../../evil` writes into `<project>/reports/` with a `REPORT_FILENAME_REGEX` name (pins sec F9's no-influence claim) + the `_md_safe` → `(empty)` case; **m-6** the report keeps its own status vocabulary **deliberately** (markdown record vs TUI banner) and says so; **m-7** AT-002 is upgraded to drive `ReportViewerScreen` over the flow report (full C-12 output-then-consume — this is the assert that would have caught AMD-1). |

## Regression checklist (declared before Phase 3 — AMD-14)
- **`tests/test_flow_persistence.py::test_report_noop_keeps_rollup_ok`** — the `"deferred" in
  report.summary` assert is **REPLACED** by `"reports/" in report.summary`; the
  rollup-stays-`ok` assert is **PRESERVED** (the batch-53 AMD-1 contract is still live). This
  edit is declared here, in advance, so it cannot be mistaken for silencing a failure.
  Note the same test now **writes a file** as a side effect (it runs against a real
  `project_dir`) — that is expected, not a leak.
- **`tests/test_tui_flow_persistence_ui.py::test_at006_report_bearing_flow_shows_report_row`**
  — must stay green, now with a real write behind it.
- **`list_project_reports` ordering** unchanged when flow and project reports interleave in
  one `reports/` dir (the D-3 side effect nobody had checked).
- **`render_result` written-path lines** unchanged (ties to AMD-11's ruling).
- **Snapshot baselines** — the AMD-13 viewer hardening touches `ReportViewerScreen`; confirm
  0 new snapshot drift at the Inc-3 gate (the 19 known `tc016s` fails stay the only ones).

## Axis check (gate, post-amendment)
- **Coverage** — RESTORED: D-5 and D-6 now have owning LLRs/ATs and §7 rows; AT-009/010/011
  + TC-011b/013a/013b/014/015/016 close the aborted, footprint, code-span, size, path-leak
  and render-hardening gaps; the C-21 map has exactly one owning increment per AT.
- **Certainty** — RESTORED: the markup oracle is now a **token-stream** assert against the
  real parser (not a character list); the status oracle is an **enumerated abort-site**
  census (not a string proxy); AT-007 compares **content**, not existence; AT-008 forces a
  **real** portable failure; AT-004 is RED-verifiable.
- **Evidence** — every finding is file:line-grounded and **execution-verified** (both
  reviewers ran payloads through `MarkdownIt("gfm-like")`; I independently re-ran the three
  load-bearing claims plus the escape-option probe that decided AMD-1).

## Gate recommendation
`iterate-to-refine` applied inline as **AMD-1..14** (recorded here, §6.5-authoritative).
The three HIGHs and both blocking checklist items are resolved in the amended contract; no
residual blocker. **Ready for Phase 3** on the amended contract, with the revised C-21 map.

## Carries out of Phase 2
- **sec F11 (separate batch):** `report_service.generate_project_report` embeds file-derived
  text into markdown with **no escaping at all** against the same linkify-enabled sink. Not a
  batch-60 blocker (pre-existing, different generator), but it is the same class of hole this
  batch just closed — place `_md_safe` so that generator can adopt it later.
- **sec F9 hardening (in-scope, cheap):** name `report_service.REPORTS_DIR_NAME` explicitly in
  LLR-002.1 so the write dir cannot desync from `list_project_reports`.
