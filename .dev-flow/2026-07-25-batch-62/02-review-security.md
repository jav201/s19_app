# 02 — Security review (Phase 2) — batch-62 `report_service` markdown escaping

- **Reviewer:** `security-reviewer` · **Base:** `claude/batch-62-report-escaping` @ `8d3c504`
- **Reviewed:** `01-requirements.md`, `01-requirements-architect.md`, `01b-qa-catalog.md`
- **Method:** every finding below is backed by an executed probe against the tree at `8d3c504`
  (`markdown_it` 4.2.0, Python 3.14). Probe script:
  `…/scratchpad/sec62.py`. No claim in this report is derived by analogy.

---

## Verdict

**OK to ship with the listed mitigations applied first (folds F1–F6 into the requirement set before Phase 3).**
No blocker. The design is sound where it commits; the failures are all of one shape —
**the batch reasons rigorously about the grammar and stops reasoning at the document.**
Every major below is a property of the *audit record*, which is how this batch itself framed the
deliverable, and which the requirement set then does not defend.

| Severity | Count | IDs |
|---|---|---|
| **blocker** | 0 | — |
| **major** | 6 | F1, F2, F3, F4, F5, F6 |
| **minor** | 5 | F7, F8, F9, F10, F11 |
| **LOW** | 2 | F12, F13 |

Credit where due, and it is not small: the field inventory (33 sites, exhaustively grepped),
G-4 non-vacuity, the positional-cell oracle, and the import-DAG ruling (D-4) are all correct and
all measured. The Mode-B grammar claim **holds** under attack (§B below). What follows is what
the set does not reach.

---

## Scope reviewed

The requirement set for batch-62: 3 stories, 5 HLR, 13 LLR, 6 AT, 23 TC, a 32-payload battery,
and rulings D-1…D-9. Attack surface = `generate_project_report`
(`s19_app/tui/services/report_service.py:1473`, single sink `:1613`) and the two consumers it
feeds — the in-app viewer (`screens.py:1443` → `_hardened_markdown_parser()`, `screens.py:112`)
and the exported `.md` read by an arbitrary reader. Not reviewed: implementation (none exists yet).

---

## Findings

### F1 — Named HTML entities are not escaped: rendered text ≠ on-disk bytes  [Severity: MAJOR]

- **What:** `&` and `;` are absent from `_MD_ESCAPE` (`flow_report_service.py:120`), so named and
  numeric HTML entities pass **both** modes unmodified and are then decoded by markdown-it's
  `entity` inline rule. The rendered document displays characters the file does not contain.
  Measured through the real `_md_safe`:

  | on disk (post-`md_safe`) | rendered |
  |---|---|
  | `&vert;` | `\|` |
  | `&num;` | `#` |
  | `&ast;` | `*` |
  | `&lowbar;` | `_` |
  | `&sol;` | `/` |
  | `&lt;script&gt;` | `<script>` |
  | `&NewLine;` | newline |
  | `&Tab;` | tab |

- **Where:** `s19_app/tui/services/flow_report_service.py:120` (`_MD_ESCAPE`), inherited by
  `markdown_safety.MD_ESCAPE` per LLR-095.1. Reachable from every Mode-A field, most sharply
  F-20 `issue.message` (`report_service.py:1026`) and F-16 `entry.linkage_symbol` (`:978`).
- **Why it matters:** this is a **content-spoofing primitive in an evidentiary document**, which
  is precisely the class question A asks about. A hostile A2L symbol name of
  `SYM_A&vert;PASSED&vert;0x0` renders in the report as `SYM_A|PASSED|0x0` — visually a forged
  table fragment — while the on-disk bytes are innocuous and every token stays `text`. The
  batch's whole assertion apparatus is token-type-based, so **`assert_field_inert` scores this
  GREEN**: `{t.type} <= {"text"}` holds. The payload set *does* contain `&amp;` (#10), but its
  declared expectation is only "inert", so the spoofing property is never asserted and the
  payload will be recorded as covered.
- **Recommendation:** add `&` to `MD_ESCAPE`. Probe-verified: `\&amp;` renders as the literal
  text `&amp;` with zero live tokens — i.e. **faithful reproduction, which is what an audit
  record owes**. Cost: widens golden drift beyond LLR-098.1's 2-line prediction only if a benign
  value contains `&` (none do in the AT-055b golden — re-verify at Phase 3). Add a payload whose
  expectation is `rendered_text == on_disk_text`, not merely "inert".

### F2 — `assert_field_inert` clause 2 fails on a *correct* implementation (3 of 32 payloads)  [Severity: MAJOR]

- **What:** `01b-qa-catalog.md:271` mandates
  `assert all(ch in "".join(t.content …) for ch in visible(payload))`, justified at §3.4 as the
  clause that *"forbids sanitise by silently dropping data — a real risk on a report meant to be
  evidentiary."* But both modes **delete** backticks (`flow_report_service.py:175`; Mode B by
  definition), and the entity rule **collapses** entities. Measured:

  ```
  payload '`code`'          -> rendered content 'code'            MISSING: ` `
  payload 'a` **PWNED** `b' -> rendered content 'a **PWNED** b'   MISSING: ` `
  payload '&amp;'           -> rendered content '&'               MISSING: a m p ;
  ```

  Payloads **#8, #9, #10** will fail the mandated helper against a correctly-built escaper.
- **Where:** `01b-qa-catalog.md:267-272` (helper) vs `flow_report_service.py:175` (removal) vs
  `01b-qa-catalog.md:286-288` (the no-deleting clause).
- **Why it matters:** this is a **gate-integrity defect, and the third occurrence in three
  batches** of the standing *assert-the-emitted-encoding* pattern (batch-60 wrong-grammar sink;
  batch-60 doc-vocabulary asserts; batch-61 NBSP-entity predicate false-failing a correct
  artifact 0/19). The predictable outcome at Phase 3 is that the helper red-lines, someone
  "fixes" it by weakening clause 2 to an exemption list, and the batch ships with its only
  anti-data-destruction control neutered — silently, under time pressure, at the last gate.
- **Recommendation:** resolve it **now, in the spec**, not at Phase 3. Two clauses:
  (a) rule on F3 (below) — escaping the backtick removes two of the three failures;
  (b) restate clause 2 as a comparison against the **mode's declared output**, not the raw
  payload: `rendered_text == expected_display(payload, mode)`, where `expected_display` is
  written down per mode. That is the assert-the-emitted-encoding form and it cannot be
  weakened by exemption creep.

### F3 — Silent backtick deletion falsifies the audit record, and its justification has evaporated  [Severity: MAJOR]

- **What:** Mode A **removes** backticks rather than escaping them
  (`flow_report_service.py:175`, comment: *"context-free: remove, never escape (AMD-5)"*). The
  stated justification is that a backslash escape is inert inside a code span, so removal makes
  the helper safe to use *inside* a code span. **Batch-62 introduces Mode B precisely so Mode A
  never lands inside a code span** (D-6, LLR-097.1) — the premise no longer holds.
- **Where:** `flow_report_service.py:175`; adopted verbatim by LLR-095.1/§7.2 Mode A.
- **Why it matters:** the backtick is a legal NTFS filename character (the architect says so at
  P-8). A symbol recorded as `` FOO`BAR `` is written to the audit record as `FOOBAR` — a
  **different symbol**, silently. In a document whose function is correlating symbols to
  addresses for a firmware release, that is data falsification, not sanitisation, and it fails
  the batch's own §3.4 clause-2 principle.
- **Recommendation:** Mode A **escapes** the backtick — add `` ` `` to `MD_ESCAPE`.
  Probe-verified: `` \`code\` `` → rendered `` `code` ``, live tokens `[]`. Mode B must keep
  removal (escaping is impossible inside a code span), so the requirement must **declare Mode B
  lossy** and require a visible substitution marker (e.g. U+2422 or `?`) so the reader can see
  that a character was dropped rather than silently reading a wrong name.
  **Cost, stated honestly for the operator's call:** this changes `_md_safe` output, so
  LLR-095.2's *"zero flow-report behaviour change"* and LLR-095.1's *"byte-equals current output,
  0 differences"* both break, and the flow-report goldens move. That is a real price. It is the
  right one — a shared escaper whose contract is "quietly drops characters" is worse the more
  callers it acquires, and this batch's whole purpose is to acquire callers.

### F4 — Block-starter injection is unruled, and the shared module's contract will be false  [Severity: MAJOR]

- **What:** `01-requirements.md:37` carries this as Phase-2 blocker #1 (*"`_MD_ESCAPE` leaks block
  starters — no `-`, `+`, `=`. Pin it, or fix the escape set."*) and **no D-ruling resolves it.**
  Measured through the real `_md_safe`:

  ```
  _md_safe('+ item')   -> '+ item'   -> bullet_list_open
  _md_safe('1) item')  -> '1) item'  -> ordered_list_open
  ```

  (`1)` is an ordered-list marker the registry's `-`/`+`/`=` list does not even name.)
- **Where:** `flow_report_service.py:120` / `:173` — the mitigation is the newline collapse at
  `:173` plus the *situational* fact that no current site emits at column 0.
- **Why it matters:** two things, and the second is the load-bearing one.
  (i) The mitigation is a property of the **call sites**, not of the escaper — an unpinned
  invariant, exactly as the registry says.
  (ii) LLR-095.1 promotes `md_safe` to a **public API in a new shared leaf module**, and its
  inherited docstring (`flow_report_service.py:139-141`) claims it renders a value inert
  *"anywhere in the report — table cell, list item or heading."* **That contract is false for a
  column-0 caller**, and the batch is about to publish it to a fourth and fifth consumer.
  The asymmetry is the argument: the batch built a static tripwire (LLR-097.2) for the Mode-B
  table hazard and left the strictly larger Mode-A column-0 hazard to an invariant nobody asserts.
- **Recommendation:** rule explicitly, either way, and record it:
  (a) **preferred** — state the column-0 precondition as a normative part of `md_safe`'s
  contract, and add the mirror of LLR-097.2: a guard asserting every `md_safe(` interpolation in
  `report_service.py` is preceded by a non-empty literal prefix; **or**
  (b) escape `-`, `+`, `=` and a leading digit-run, making the helper genuinely context-free and
  the docstring true.
  Do not ship the current state, where the docstring asserts a property the code does not have.

### F5 — Absolute-path disclosure: batch-60's MAJOR ruling was dropped, not re-argued  [Severity: MAJOR]

- **What:** batch-60 raised absolute-path disclosure from LOW to MAJOR at its final gate (F2) and
  shipped a control for it:

  ```
  flow_report_service.py:122-127  _ABSOLUTE_PATH_RE
  flow_report_service.py:239      _redact_absolute_paths
  flow_report_service.py:363,382  applied to findings and diagnostics
  ```

  with the rationale stated verbatim in the source comment (`:125-126`): an OSError diagnostic
  carrying `'C:\\Users\\me\\…'` reaches the report *"disclosing the operator's username and local
  layout in a document meant to be shareable."*
  **Batch-62 does not mention `_redact_absolute_paths` once** across all three artifacts. It is
  not promoted into `markdown_safety`, and it is not applied to `issue.message` (F-20) — the
  architect's own "highest-risk field", carrying parsed file text including exception strings.
- **Where:** `flow_report_service.py:239` (the control) vs `report_service.py:1026` (the
  unprotected sibling site) vs `01-requirements-architect.md:66` (CN-7, which addresses
  confidentiality only as "the module performs no logging").
- **Why it matters:** the framing is *identical* — US-B62-2's entire premise is *"the file is
  safe once it leaves the app."* Batch-62 hardens that file's grammar while leaving the operator's
  username and directory layout in it. Worse, it does not merely omit the control: **Mode B's
  whole justification (CN-6 / R-1) requires the absolute path to stay raw in the file**, so the
  batch makes the batch-60 control structurally harder to add afterwards. A severity ruling
  reached at a prior gate may be revisited, but it must be revisited **out loud**.
- **Recommendation:** add an explicit ruling (D-10). Either apply `_redact_absolute_paths` (or
  `_display_path`-style project-relative rendering) to the Mode-B path fields and `issue.message`
  and re-derive the golden strategy around the shortened span — the canonicaliser substitutes a
  *prefix*, so a project-relative path is compatible with it — or record a written, operator-
  approved acceptance that project reports disclose host paths where flow reports do not, and
  why. Do not leave the divergence undocumented; the two report generators will otherwise carry
  opposite privacy postures with no trace of the decision.

### F6 — The external-reader threat model is narrower than the story it is asked to support  [Severity: MAJOR]

- **What:** US-B62-2 claims *"the file is safe once it leaves the app"* and AT-158
  (`01b-qa-catalog.md:113-115`) says the file is *"opened by **any** standard GitHub-flavoured
  markdown reader — modelled as `MarkdownIt("gfm-like", {linkify: True, html: True})`."*
  markdown-it's `gfm-like` is a **strict subset** of what GitHub, VS Code, and Obsidian actually
  render. The payload derivation (G-1/G-2) enumerates from `VIEWER.get_active_rules()` and
  `DEFAULT.linkify._schemas` — i.e. from the **local** parser — so it is complete for the model
  and structurally blind to everything outside it. Measured survivors through the real `_md_safe`:

  ```
  ':x:'         -> ':x:'          gfm-like: inert   GitHub: renders ❌
  '$x^2$'       -> '$x^2$'        gfm-like: inert   GitHub: renders as math
  '==mark=='    -> '==mark=='     gfm-like: inert   VS Code/Obsidian: highlight
  ```

  (Correctly covered, for the record: `> [!WARNING]` alerts, `[^1]` footnotes, `#123`/`@user`
  autolinks — all dead via the escaped `>`, `[`, `]`, `#`, `@`.)
- **Where:** `01b-qa-catalog.md:113-115` (AT-158's "any"), `:171-178` (the derivation),
  `01-requirements-architect.md:44` (the "conservative model" claim).
- **Why it matters:** the concrete consequence in an audit record is **verdict forgery on the
  actual sharing target**. A variant id or filename containing `:x:` puts a red ❌ next to a
  PASSED row on GitHub; `:heavy_check_mark:` puts a green tick next to a FAILED one. The escaper
  is inert, every token is `text`, AT-157 and AT-158 are both GREEN, and the shared document
  lies. This is the same shape as **batch-60's own recorded lesson** — *"the approved prototype
  escaped for the WRONG GRAMMAR"* — measured against the wrong sink, one layer further out.
  Calling the model "conservative" (`architect §1`) when it is a subset of the real target is the
  specific error.
- **Recommendation:** two parts, both cheap.
  (a) **Mandatory:** narrow US-B62-2 and AT-158 from "any standard GFM reader" to "a default
  `markdown-it` `gfm-like` reader (linkify + html on)", and add a named **residual-risk** row
  stating that reader-specific extensions (emoji shortcodes, `$` math, `==` highlight) are out of
  model. An honest narrow claim is worth more than a broad one the tests cannot support.
  (b) **Operator's call:** add `$`, `:`, `=` to `MD_ESCAPE`. Kills the residual risk; widens
  golden drift and hurts readability of any value containing a colon (paths do:
  `C:/…` — but those are Mode B, so unaffected). I do not require this; I require (a).

### F7 — `TC-397` cannot fail on the sections this batch grows  [Severity: minor]

- **What:** `_ByteBudget` is consumed at **hexdump-block granularity only** — measured call sites
  are `report_service.py:1255`, `:1287`, `:1569`, all inside `_hexdump_section` / the top-level
  batch loop, and the class docstring says so (`:362-363`). `_declaration_error_lines` (`:1025`)
  emits one line per issue with **no cap** — no counterpart to `flow_report_service.py:82`'s
  `MAX_REPORT_FINDINGS_PER_BLOCK = 200`. `REPORT_MAX_REGIONS_PER_VARIANT = 128` (`:76`) caps
  regions, not issues.
- **Why it matters:** unbounded file-content → report size is pre-existing, but **batch-62 makes
  it worse**: LLR-098.3 raises `issue.message`'s escape limit from 240 to ≥500, roughly doubling
  the per-issue cost of the one uncapped section. TC-397 asserts *"the `REPORT_MAX_TOTAL_BYTES`
  accounting still holds"* — and the accounting does not cover that section, so **TC-397 passes
  vacuously on exactly the lines the batch grows**. C-31, again.
- **Recommendation:** either add a `MAX_REPORT_ISSUES_PER_VARIANT` mirroring the flow-report cap,
  or extend `_ByteBudget` to the declaration-error and checklist sections; and rewrite TC-397 so
  its fixture drives the **uncapped** section past the budget. Per the batch-60 lesson, state the
  fixture's multiple of the limit in the test docstring.

### F8 — Bidi, zero-width, and C1 characters survive both modes  [Severity: minor]

- **What:** the control strip is `ch if ch >= " " else " "` (`flow_report_service.py:174`) — it
  removes C0 only. Measured survivors through the real `_md_safe`: U+202E RLO, U+200B ZWSP,
  U+FEFF BOM, U+2066/2069 bidi isolates, U+009F (C1), U+2028 LINE SEPARATOR.
- **Why it matters:** RLO reverses a displayed filename so the rendered name differs from the
  bytes; ZWSP makes two distinct symbol names render identically in a symbol↔address record.
  TC-382 covers these characters but its expectation is *"no exception; no mojibake"* — a
  robustness assertion, not a security one, so the payloads are present and prove nothing.
- **Recommendation:** filter by Unicode category in both modes — drop `Cc` and `Cf` (replace with
  a visible marker per F3's reasoning, not silently) — and change TC-382's expectation from
  "no exception" to a rendered-text equality assertion.

### F9 — LLR-097.2's static guard is refactor-fragile and has no inverse  [Severity: minor]

- **What:** the guard asserts *"no `md_code(` call site in `report_service.py` lies inside a line
  template containing a `|` column separator"* — a source-text pattern match. D-6's underlying
  hazard is real and confirmed by probe: Mode B in a table cell still splits it
  (`| \`a|b\` |` → cells `['A','B','\`a','b\`']`).
- **Why it matters:** the guard false-negatives the moment a row is built by `" | ".join([...])`
  or the template moves into a helper — normal refactors, no warning. And there is no inverse
  guard for the Mode-A column-0 hazard (F4).
- **Recommendation:** replace the source-text guard with an assert-the-painted-result form (C-32):
  generate a report from a hostile fixture, parse **every** table in it, and assert each row's
  cell count equals its header's. That guard survives refactoring and subsumes both hazards.

### F10 — Fail-closed behaviour is entirely unspecified  [Severity: minor]

- **What:** no requirement states what happens when escaping cannot complete. `md_safe` calls
  `str(value)` (`flow_report_service.py:172`); an object whose `__str__` raises propagates out of
  the composer. Today that is fail-closed by accident — the single sink at `report_service.py:1613`
  means nothing is written — but it is **incidental, not required**, and nothing forbids a later
  `try/except Exception: return str(value)` "robustness" patch from turning it into a bypass.
  TC-381 covers `None`, `""`, whitespace; it does not cover a raising `__str__` or `bytes`.
- **Recommendation:** add a normative statement: *escaping failure shall abort report generation;
  no partially-escaped or unescaped document shall be written; no escaping path shall catch a
  broad exception and fall through to the raw value.* Add a TC with a raising-`__str__` object
  asserting no file exists afterwards. (`bytes` is safe as-is — `str(b"\x00")` yields a
  backslash, and `\` is escaped first at `:179-180`.)

### F11 — `md_code`'s empty-value contract is undefined  [Severity: minor]

- **What:** `md_safe` returns `"(empty)"` when nothing survives (`:181`). LLR-095.1 specifies
  `md_code`'s signature but **not** its empty behaviour, and TC-381 does not distinguish the modes.
- **Why it matters:** not a security hole — probed all four source/saved combinations in the real
  two-span bullet (`report_service.py:892-901`); an empty Mode-B value yields a literal `` `` ``
  and stays inert in every case. But an unspecified contract is whatever the implementer picks,
  shipped unreviewed.
- **Recommendation:** specify `md_code("") -> "(empty)"`, matching Mode A, so the report never
  emits a bare double-backtick.

### F12 — `limit` is applied *after* per-character normalisation  [Severity: LOW]

- **What:** `flow_report_service.py:172-178` runs three `.replace()` passes and a per-character
  generator join over the **full** input, then truncates at `:177`. A 10 MB A2L symbol name costs
  ~4 full-string passes plus a 10M-element genexp before the 240-char cap fires.
- **Why it matters:** modest amplification, not a practical DoS. Noted mainly because TC-382's
  boundary case is **10 000 chars** — three orders of magnitude under the interesting size. That
  is the batch-60 *"fixture sat 2.8× under its limit"* failure in miniature.
- **Recommendation:** clamp at entry (`text = str(value)[: limit * 8]`) before normalisation, and
  raise TC-382's case to a size that would actually show the cost.

### F13 — `!` is absent from the escape set; the image construct is dead anyway  [Severity: LOW]

- **What:** question A asks whether `!` is escaped. It is not. Probed: the outbound-request
  primitives are nonetheless all dead under Mode A —
  `![a](http://evil.com/x.png)` → `[]`, `![a][r]` → `[]` (killed by the escaped `[`/`]`),
  `<img src=x>` → `[]` (killed by `<`/`>`). **No beacon / IP-disclosure primitive survives Mode A
  in either modelled grammar.**
- **Why it matters:** the safety is *incidental* — it depends entirely on `[`/`]`, and a future
  reader trimming the escape set for readability (a live temptation, cf. R-5) would silently
  reopen it.
- **Recommendation:** record the dependency in the `MD_ESCAPE` docstring: *"`!` is not escaped;
  the image construct is dead only because `[` and `]` are. Removing either re-enables outbound
  image requests from the exported file."*

---

## Rulings on A–F

**A. Is the threat model complete? — NO.** Link forgery, defacement, HTML injection, heading /
table-row / reference-link / footnote injection are all covered and correctly reasoned. Beacon
images are dead (F13). **Not covered:** HTML-entity spoofing (F1), Unicode bidi/zero-width
deception (F8), reader-extension constructs outside markdown-it's `gfm-like` (F6), and — the
category error underneath all three — the batch defends the *grammar* thoroughly and the
*document* not at all, despite framing the deliverable as an audit record. The three attacks the
payload set does not cover, concretely: `&vert;` rendering as a forged pipe; `:x:` rendering as a
red ❌ next to a PASSED row on GitHub; U+202E reversing a displayed filename.

**B. Does Mode B hold? — YES on grammar, NO on faithfulness.** Attacked it directly: differing
backtick-run lengths, fence sequences, newline and CRLF injection, U+2028, trailing backslash,
empty value, and the empty value inside the real two-span bullet — **all inert**, because
backtick removal plus newline collapse leaves nothing to break out with. The "fully inert in both
grammars including linkify" claim is **sustained**. Two riders: the `|`-in-a-table-cell limit is
real and its guard is weak (F9), and the empty-value contract is undefined (F11). On the second
half of the question — **silent removal is the wrong call for an audit record, and it does
violate the catalog's own no-sanitise-by-deleting clause** (F2, F3). Mode B has no alternative
(escaping is impossible inside a code span), so it must be *declared lossy* with a visible
marker. **Mode A does have an alternative and should take it** — the "context-free" premise for
removal dies the moment Mode B exists.

**C. Path handling / information disclosure — R-1's severity is right, its mitigation is
necessary but not sufficient; and the batch-60 shareability ruling was silently dropped.**
R-1 (HIGH) is correctly identified and Mode B does neutralise it. But the mitigation is a single
assertion over a single golden. Fold F6a below moves it into `canonical_report_bytes`
(`tests/conftest.py:1009-1016`) so every consumer inherits it — detection over prevention, four
lines. On the separate disclosure question: **the batch-60 reasoning was not applied and not
re-argued** (F5). Batch-60 raised exactly this to MAJOR because the artifact is shareable;
batch-62 asserts the same shareability premise in US-B62-2 and ships raw host paths, with Mode B
structurally depending on them staying raw. That needs an explicit D-10 ruling, either way.

**D. Is the mitigation at the right layer? — YES. PASS, no finding.** The composer half is added
where it belongs; **no requirement weakens the batch-60 enforcing half**. Verified: no LLR's
touched-symbol list includes `screens.py`; LLR-095.2 preserves the flow-report aliases; both
report viewers share one factory (`screens.py:1443` → `:82` → `:112`), so there is one thing to
pin, not two. And it **is** pinned — `tests/test_flow_report_ui.py:69` asserts
`md.options.get("linkify") is False`. The two halves therefore cannot drift silently: the
enforcing half is pinned by that test, the composer half by G-1/G-2's re-derivation from the live
parsers. Recommend citing `test_flow_report_ui.py:69` in the batch so the anti-drift pin is not
re-litigated. One spec-integrity defect at this layer: **HLR-097 is false at merge** (F14 below).

**E. Fail-closed — unspecified; must be specified.** See F10. Required behaviour: escaping
failure aborts report generation, no partial document is written, and no escaping path catches a
broad exception and falls through to the raw value. Today's behaviour is correct by accident.

**F. DoS / resource — one real gap, one cosmetic.** The unbounded path from file content to
report size **exists and is not closed**: `_declaration_error_lines` (`report_service.py:1025`)
is uncapped and outside `_ByteBudget`'s coverage, and batch-62 doubles its per-issue cost.
TC-397 cannot fail on it (F7). `MAX_REPORT_CELL_CHARS = 240` and the `_DEFAULT_MESSAGE_MAX_LENGTH
= 500` reconciliation (LLR-098.3) are correctly handled. F12 is cosmetic.

---

## Required folds before Phase 3

| # | Fold | Closes |
|---|---|---|
| **F1** | Add `&` to `MD_ESCAPE`; add a payload asserting `rendered == on_disk`, not merely "inert". | F1 |
| **F2** | Mode A escapes `` ` `` instead of removing it; Mode B declared lossy with a visible substitution marker; restate catalog clause 2 as a per-mode `expected_display` comparison. Accept the flow-report golden drift and record it under §6.5. | F2, F3 |
| **F3** | Rule on block starters (D-10): either pin the column-0 precondition in `md_safe`'s contract **plus** a mirror of LLR-097.2, or escape `-`, `+`, `=`, leading digit-runs. Do not ship a docstring asserting a property the code lacks. | F4 |
| **F4** | Add D-11 ruling on host-path disclosure: apply `_redact_absolute_paths`/project-relative rendering to the Mode-B path fields and `issue.message`, **or** record an operator-approved written acceptance of the divergence from batch-60. | F5 |
| **F5** | Narrow US-B62-2 / AT-158 from "any standard GFM reader" to the modelled parser, and add a named residual-risk row for reader extensions (`:emoji:`, `$` math, `==`). Escape-set extension optional. | F6 |
| **F6** | (a) Move the R-1 assertion into `canonical_report_bytes` (`tests/conftest.py:1014`): after substitution, assert no `[A-Za-z]:[\\/]`, `/Users/`, or `/home/` survives — every golden consumer inherits it. (b) Cap or budget `_declaration_error_lines` and rewrite TC-397 to drive the uncapped section past the limit. (c) Specify fail-closed (F10) and `md_code("")` (F11). (d) Category-filter `Cc`/`Cf` and upgrade TC-382's expectation. (e) Replace LLR-097.2's static guard with a parse-every-table assertion. (f) Record the `!`/`[`/`]` dependency in the `MD_ESCAPE` docstring. | F7–F13 |

**F14 (spec integrity, fold with F5):** HLR-097 states *"no report generator **shall** define its
own grammar-escaping helper"* — but D-8/§7.1 explicitly defers `diff_report_service._md_cell` and
`._md_table_cell`, which are exactly that, in a report generator. The requirement is **false on
the day it merges** and will read as satisfied to a future auditor, because the violation lives
in a file the requirement does not name. Rewrite HLR-097 to name the covered surfaces and carry
the diff-report exclusion *inside* the requirement, not only in a deferral ruling.

---

## Evidence checklist

- [x] Each finding has what · where · why · recommendation — F1–F13, all with `file:line`.
- [x] Each finding has a severity rating — 0 blocker / 6 major / 5 minor / 2 LOW.
- [x] No secret values appear in this output — no paths beyond repo-relative; no operator
      username, token, or key is reproduced. F5 references the *class* of disclosure, never a value.
- [x] Verdict is explicit — **OK to ship with the listed mitigations applied first**; folds F1–F6
      are prerequisites to Phase 3, not post-merge carries.
- [x] New tool/integration scope and blast radius — **N/A, and verified so**: no MCP, Composio,
      n8n, network, or third-party dependency is added. CN-8 holds (`markdown_it` already a
      dependency); the new leaf module is pure-stdlib with zero service imports; no new outbound
      sink. The batch's only reach-widening effect is on an existing local file artifact, which is
      the subject of F5.
- [x] Every load-bearing claim probe-executed against `8d3c504`, not reasoned by analogy — F1, F2,
      F3, F4, F6, F8, F13 each quote measured output; F7, F9, F10, F12 quote `file:line` from
      source read at review time.
