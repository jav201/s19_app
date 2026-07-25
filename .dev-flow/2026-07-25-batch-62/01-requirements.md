# 01 — Requirements (canonical registry + reconciliation) — batch-62

> **This file is the authoritative registry.** Full derivations live in two source artifacts:
> - `01-requirements-architect.md` — HLR/LLR derivation, field inventory, design ruling.
> - `01b-qa-catalog.md` — validation methods, payload derivation, assertion helper.
>
> **Both source artifacts are PARTIALLY SUPERSEDED by §6.5 of this file.** Where any of the three
> collide, this file rules, and §6.5 records what changed. Base ref `8d3c504`. Language: English.

**Revision 2 — Phase-1 refinement fold, iteration 1 of 3** (2026-07-25). Discharges the 14 blockers
and ~20 majors in `02-review.md`. Every threshold restated below was **measured on the tree at
`8d3c504`**, not predicted — the Phase-2 gate failed because three acceptance thresholds were
predictions. The discharge matrix is §11.

---

## 0. Ruling register

Rulings **D-1…D-9** were issued at Phase 1 revision 1. Four were measured wrong at Phase 2 and are
**re-issued** here; five stand. **D-10…D-27** are new, and each closes a named blocker.

| # | Status | Ruling | Evidence |
|---|---|---|---|
| **D-1** | STANDS | US ids `US-B62-1/-2/-3` (collision with batch-37's `US-062`). | `REQUIREMENTS.md:3686`, `:3749`. |
| **D-2** | **RE-ISSUED** | **AT ids `AT-157…163` (architect's numbering) carry qa's PREDICATES.** The architect's closed 7-type live-set enumeration is **deleted**; the acceptance predicate is qa's allow-list. See A-01. | Range free (max `AT-129`). qa measured an injected `hr` passing the closed enumeration and failing the allow-list. |
| **D-3** | **RE-ISSUED** | **The qa catalog's `TC-376…398` IS the TC registry.** The architect's `TC-376…387` are twelve bare ids with no content and are **dropped**, not mapped. No renumbering occurs. See A-02. | `01-requirements-architect.md` §10 ("TC (proposed)" column, no titles/steps/expected) vs `01b-qa-catalog.md` §4. |
| **D-4** | STANDS | New leaf module `s19_app/tui/services/markdown_safety.py` exporting `md_safe` (Mode A) + `md_code` (Mode B). *Rationale corrected:* `report_service` is **upstream of the two generators**, not "the base of the DAG" — it imports 5 siblings (`report_service.py:52-60`). The argument needs only the former. | Cycle verified: `flow_report_service.py:63`, `diff_report_service.py:97`. |
| **D-5** | **RE-ISSUED** | The `_md_table_cell` call (`report_service.py:978`) and its deferred import (**`:965-968`**, not `:974-976`) are REMOVED. **The "benign no-op arm still holds" clause is DELETED — it is false.** See A-03. | `_MD_ESCAPE` ordering verified. `_md_safe('SYM_A') → 'SYM\_A'` measured; 3 assertion sites break across 2 files. |
| **D-6** | STANDS | Mode B forbidden in table cells. | Measured: a raw `\|` inside a code span still splits the cell. |
| **D-7** | **RE-ISSUED** | Golden re-capture IN scope. **Drift is exactly 3 lines — 14, 15, 51 — and the gate asserts the LINE NUMBERS, not the count.** See A-04. | Measured this session over every golden value; probe transcript §7. |
| **D-8** | STANDS | `diff_report_service._md_cell` / `_md_table_cell` DEFERRED to the backlog. **The deferral is now carried inside HLR-097 itself** (A-07), not only here. | Own goldens, own un-audited HTML sink. |
| **D-9** | STANDS | `diagnostics` rendering stays OUT. | Functionality gap, not security. |
| **D-10** | NEW | **Block starters: KEEP the newline collapse, do NOT extend the escape set with `-`/`+`/`=`.** Pinned three ways (A-23). | Escaping `-` makes `mac-linked` → `mac\-linked` at every kebab identifier. Both Phase-2 reviewers converged on this disposition. |
| **D-11** | NEW (operator) | **Host-path disclosure: partial fold.** `issue.message` is redacted; Mode-B path fields stay raw **by design**. Accepted divergence recorded + carried. See A-24. | Operator ruling 2026-07-25. Mode B's raw bytes are load-bearing for CN-6/R-1. |
| **D-12** | NEW | **Mode A ESCAPES the backtick instead of removing it.** Mode B keeps removal (escaping is impossible inside a code span) and is **declared lossy**, substituting U+FFFD per dropped backtick. See A-11. | Measured cost: **1 flow-report test re-baselined, 0 goldens moved** (§7 C-3). |
| **D-13** | NEW | **`&` is added to `MD_ESCAPE` at index 1.** | Measured: `\&vert;` renders as literal `&vert;`, live tokens `[]`; backslash-first ordering preserved (`x\&y` → `x\\\&y`); **0 added golden drift**. |
| **D-14** | NEW | **`assert_field_inert` is rewritten** — inline descendants for types, `text`-tokens only for content, clause 2 compares against `expected_display(payload, mode)`. See A-20. | Closes the oracle-blindness class (§7 C-4). |
| **D-15** | NEW | Truncation is a **policy**, not a per-field patch: Mode A takes an explicit `limit` at every site; **Mode B does not truncate**. See A-18. | Mode B's 240 made truncation depend on the operator's tmp-root depth → machine-dependent golden, R-1's family through another door. |
| **D-16** | NEW | One on-disk node per AT is **named** in this file; `AT-160`'s vacuous byte-identity clause is replaced by the one-shot line-number diff gate; its readability clause demotes to `TC-395`. See A-30. | C-18. |
| **D-17** | NEW | **`<in-memory document>` → `(in-memory document)`.** | Measured: the literal appears **only** at `report_service.py:894` and `:1093` — no test, no golden asserts it, so the change is free and removes AT-158's need for provenance scoping. |
| **D-18** | NEW | **Fail-closed is normative**: escaping failure aborts report generation; no partial document is written; no escaping path catches a broad exception and falls through to the raw value. See A-25. | Correct today only by accident (single sink at `report_service.py:1613`). |
| **D-19** | NEW | **`Cc` and `Cf` Unicode categories are filtered in both modes**, with a visible marker, not silently. See A-26. | U+202E/U+200B/U+FEFF/C1 measured surviving `ch >= " "`. |
| **D-20** | NEW | **`MAX_REPORT_ISSUES_PER_VARIANT = 200`** (mirroring `MAX_REPORT_FINDINGS_PER_BLOCK`) caps `_declaration_error_lines`. See A-27. | `report_service.py:1025-1032` verified uncapped and outside `_ByteBudget`; LLR-098.3 doubles its per-issue cost. |
| **D-21** | NEW | **The threat model is narrowed and its residue named**: US-B62-2 and AT-158 model *a default `markdown-it` `gfm-like` reader (linkify + html ON)* — **not** "any standard GFM reader". Reader-specific extensions are a declared residual risk. See A-31. | `:x:`, `$x^2$`, `==mark==` measured inert under `gfm-like` and live on GitHub/VS Code/Obsidian. |
| **D-22** | NEW | **The `$`/`:`/`=` escape-set extension is DECLINED.** | `:` appears in every address-bearing string and the readability cost is large; the constructs it would kill are out of the modelled grammar and are carried as residual risk instead (D-21). Recorded so it is a decision, not an omission. |
| **D-23** | NEW | `md_code("")` → `"(empty)"`, matching Mode A, so the report never emits a bare double-backtick. | F11. |
| **D-24** | NEW | `LLR-097.2`'s source-text guard is **replaced** by an assert-the-painted-result guard (C-32): parse every table in a hostile report and assert each row's cell count equals its header's. See A-15. | The source-text match false-negatives on `" \| ".join([...])` and on any template moved into a helper. |
| **D-25** | NEW | The payload set gains `html-inline` and `html-block`; **G-4 parses each payload in its EMISSION CONTEXT**, not context-free; `entity`/`escape` move to a named `MUTATING_RULES` set with a fidelity predicate. Count is **33 active + 2 negative controls**. See A-21. | G-1 was RED on its own table; G-4 killed 3 payloads G-1 mandates. |
| **D-26** | NEW | The static census keys on the **24 escape-required sites**, never on the literal "33". | ~50 interpolating emission sites exist; 33 was a curated list, so a census keyed on it asserts an arbitrary number. |
| **D-27** | NEW | **The batch-39 structural-pipe guard is RETAINED** alongside the new token assertions. | It is measurably sensitive to the raw-pipe class (8 vs 7 → RED). Removing it as "blind" would delete a working guard (§7 C-2). |

---

## 1. Stories

- **US-B62-1** — file-derived text renders **literally in the app viewer**: every token attributable
  to it is in `{text, softbreak}`.
- **US-B62-2** — the **exported `.md`** is inert when read by **a default `markdown-it` `gfm-like`
  reader (linkify + html ON)**. *(Narrowed by D-21; residual risk §10.)*
- **US-B62-3** — table rows preserve **positional cell content** regardless of file-derived input.

---

## 2. Derived structure

**5 HLR** (`HLR-095…099`, EARS, `shall`-only) · **13 LLR + 3 new** · **7 AT** (`AT-157…163`) ·
**`TC-376…398`** (qa catalog, sole registry). Both traceability chains present; HLR-099's parent US
is repaired (A-09).

---

## 3. The five carried blockers — each now RULED

1. **Block starters** — **RULED (D-10).** `_MD_ESCAPE` lacks `-`, `+`, `=`; `1) item` →
   `ordered_list_open` is a member of the same class the original list did not name. Safe **only**
   because `flow_report_service.py:173` collapses newlines first, and every file-derived
   interpolation in `report_service.py` carries a literal prefix (`# `, `## `, `#### `, `### `,
   `- `, `| `, or `` saved as ` ``). Keep the collapse; pin it three ways (A-23).
2. **Code-span breakout at `report_service.py:901`** — **RULED.** Disposition Mode B; the backtick
   wrap already exists at `:901` and must be **added** at `:897` and `:1097` (A-14).
3. **`md_safe` is not idempotent** — **RULED.** Exactly-once becomes a **sink-level** obligation
   with a detector in both directions (A-17, `AT-163`).
4. **Truncation** — **RULED (D-15).** Policy, not a per-field patch (A-18).
5. **Golden canonicaliser (R-1)** — **RULED.** Mode B is the mitigation, verified end-to-end. The
   residue predicate is promoted to normative and moved **into `canonical_report_bytes`** so every
   golden consumer inherits it (A-16). **Severity downgraded HIGH → LOW-MED**: golden line 51
   already carries a backticked run-root path that canonicalises correctly today, so Mode B's shape
   is proven by an existing passing golden, not merely predicted.

---

## 4. Field inventory — 33 curated sites

**24 need escaping** (21 Mode A + 3 Mode B) · 7 trusted · 2 out-of-scope-but-pinned. Independently
re-derived at Phase 2 by a different method (enumerate every interpolation form, classify by
provenance): **no missed file-derived field**. The census keys on the **24**, not on "33" (D-26).

Mode selection is a **truth table**, not 24 judgement calls (closes the "new path field silently
takes Mode A" hole):

| Value can contain the run root / an absolute path | Emission context is a table cell | Mode |
|---|---|---|
| no | no | **A** |
| no | yes | **A** (`\|` is at `MD_ESCAPE` index 2, `\` at 0 — one pass) |
| yes | no | **B** |
| yes | **yes** | **FORBIDDEN** — Mode B splits the cell (measured); Mode A breaks CN-6. No such site exists; adding one requires an ADR. |

Backstop: `AT-162`'s mode-agnostic canonicaliser-residue predicate fires regardless of how a future
field is classified.

Hexdump fence proven **unbreakable** (all-`0x60` image → exactly 1 `fence` token in both grammars,
because every gutter line carries the `0x%08X` prefix, `hexview.py:356`). Scope exclusion ships with
`AT-161`.

---

## 5. Payload set (qa-authoritative, amended by D-25)

**33 active + 2 negative controls**, derived from the parser's own rule table. Five guards: G-1 rule
coverage vs `get_active_rules()`; G-2 vs `linkify._schemas` + `_opts`; G-3 floor `>= 33`; **G-4
non-vacuity, evaluated in each payload's EMISSION CONTEXT**; G-5 negative controls stay inert.
`MUTATING_RULES = {entity, escape}` carry a **fidelity** predicate (cooked text differs from input)
instead of a live-token predicate, each entry justified in-table.

Negative controls `10.1.2.3` and `evil.tld` are measured inert under **both** parsers and are sharp,
not lucky: `http://evil.tld/x`, `//evil.tld/x` and `http://10.1.2.3/x` all fire. Unchanged.

---

## 6. Assertion discipline

`assert_field_inert(md, document, marker, payload, mode)`:

1. **Grammar clause** — every token attributable to the field, computed over **inline descendants
   only** with an explicit container allow-list, is in `{text, softbreak}`. *(Allow-list, never the
   closed 7-type enumeration; never baseline subtraction — a benign report already emits
   `heading_open`, `bullet_list_open`, `strong_open`.)*
2. **Fidelity clause** — the join of **`text`-typed tokens only** equals
   `expected_display(payload, mode)`, computed from the design:
   - **Mode A**: `Cc`/`Cf` → marker · `\r\n\t` → space · strip · truncate at the site's explicit
     `limit`. Nothing else changes, because escapes render invisibly and `&` and `` ` `` are now
     escaped rather than dropped.
   - **Mode B**: same, minus truncation, plus each backtick → U+FFFD.

Clause 2 replaces the unimplementable "payload characters still present" form, which fails against a
**correct** implementation on payloads #8/#9/#10 and whose predictable outcome was someone weakening
it under time pressure at the last gate. It keeps the anti-"sanitise by deleting" intent — deletion
changes `expected_display` too — and it is the only form that can fail on the entity-spoofing class
(§7 C-4). No character-membership checks; no `md.render()`.

---

## 6.5 Amendment log (Before → After)

> Every statement changed by this fold. No locked requirement is silently edited.

| # | Statement | Before | After | Closes |
|---|---|---|---|---|
| **A-01** | D-2 / AT predicate | "Semantic 1:1 match of 157/158/159 **to be confirmed at Phase 2**"; acceptance = closed live-set `{s_open, strong_open, em_open, link_open, html_inline, html_block, code_inline}` is empty | **DELETED** the closed enumeration. **NEW:** every token attributable to a file-derived field is in `{text, softbreak}`. Architect ids retained, qa predicates adopted. | qa B-1, E-1 |
| **A-02** | D-3 / TC registry | "TC registry = the architect's `TC-376…387` (12); qa's additional cases renumber to `TC-388+`" | **NEW:** the qa catalog's `TC-376…398` **is** the registry. The architect's twelve bare ids are **DELETED**. No renumbering, therefore no old→new map is needed. | qa B-2, M-4 |
| **A-03** | D-5 / blast radius | "its benign-no-op arm still holds / still passes unchanged" (also in LLR-096.1 and R-4) | **DELETED.** Measured `_md_safe('SYM_A') → 'SYM\_A'`. **NEW:** three assertion sites re-baseline — `test_report_symbol_escape.py:166`, `test_report_service.py:260`, `:1403` — and the hostile arm's expected string changes (`_md_table_cell` **deletes** ctl chars, `md_safe` **replaces them with a space**). | arch B-2, E-4 |
| **A-04** | D-7 / golden drift | "Predicted drift **exactly 2 lines**; an unpredicted 3rd line blocks" | **NEW:** drift is **exactly 3 lines — 14, 15, 51 — measured**. The gate asserts the **line numbers**, not the count (a count-only gate is GREEN when one predicted line fails to drift and one unpredicted line does). Pinned command in §9. | qa B-6, E-3 |
| **A-05** | HLR-095 | "zero live Markdown constructs", defined by the §4 enumeration | Restated in allow-list terms (A-01). | qa B-1 |
| **A-06** | HLR-096 | "the rendered cell text **shall** equal the input value verbatim after control-character removal" | **NEW:** "…verbatim except for the declared transformations: `Cc`/`Cf` substitution, newline/tab collapse to a single space, Mode-A truncation at the site's explicit `limit`, and Mode-B backtick substitution." The exclusion list is explicit and matches `expected_display`. | arch M-2 |
| **A-07** | HLR-097 | "no report generator **shall** define its own grammar-escaping helper" — **false on the day it merges** | **NEW:** names the covered surfaces (`report_service`, `flow_report_service`, `markdown_safety`) and carries the `diff_report_service` exclusion **inside the requirement**, so a future auditor sees the carve-out where the requirement is, not only in a deferral ruling. | arch B-7, sec F14 |
| **A-08** | HLR-098 | "filesystem paths **shall** render without inserted escape characters" — false for F-09 (`a.s19` → `a\.s19`) | **NEW:** narrowed to **run-root-bearing paths** (the Mode-B set). | arch M-1 |
| **A-09** | HLR-099 | US parent = `—` (anti-regression) | **NEW:** parent `US-B62-1/2` — the hexdump gutter is a file-derived surface, so it belongs to them naturally. Chain repaired. | arch M-3 |
| **A-10** | `MD_ESCAPE` | `("\\", "\|", "*", "_", "[", "]", "<", ">", "#", "~", "/", ".", "@")` | **NEW:** `&` inserted at **index 1**. Measured: ordering preserved (`x\&y` → `x\\\&y`), `\&vert;` renders as literal `&vert;` with live tokens `[]`, and **0 added drift** on the AT-055b golden. | sec F1 |
| **A-11** | Mode A backtick | `text.replace("`", "")` — **removal**, justified as "context-free" | **NEW:** Mode A **escapes** `` ` `` (appended to `MD_ESCAPE`). The "context-free" premise died when Mode B was introduced (D-6 keeps Mode A out of code spans). Mode B keeps removal — impossible to escape inside a code span — and is **declared lossy**, substituting **U+FFFD** per dropped backtick so the reader sees that a character was dropped. | sec F2, F3 |
| **A-12** | LLR-095.1 threshold | "byte-equals the current `_md_safe` on a ≥30-case corpus, 0 differences" | **NEW:** byte-equals the current helper on all inputs **except** those containing `` ` `` or `&`, whose new outputs are stated in-table. The corpus is **named**, not "≥30 cases", and **must** contain a backtick case, an `&` case, and a newline case. | sec F2/F3, arch B-5 |
| **A-13** | LLR-095.2 threshold | "zero flow-report behaviour change" | **NEW (measured, not predicted):** exactly **one** flow-report case re-baselines — `test_flow_report_service.py:415`, `flow_name="```"`, which sanitises to `(empty)` today and to `` \`\`\` `` after. 51 of 52 flow-report tests pass unmodified; **no golden moves** (the repo has 3 goldens, none of them flow-report). Recorded here as the §6.5 record that re-baseline requires. | sec F2 cost claim (§7 C-3) |
| **A-14** | LLR-097.1 | all three path fields "shall be emitted wrapped in a single-backtick code span" | **NEW, per field:** `:901` is **already** wrapped (adding one would double it); `:897` and `:1097` **must** be wrapped. | arch m-3 |
| **A-15** | LLR-097.2 guard | source-text match: "no `md_code(` call site lies inside a line template containing a `\|`" | **NEW:** parse **every** table in a hostile-fixture report; assert each row's cell count equals its header's (C-32). Survives `" \| ".join([...])` and template extraction, and subsumes both the Mode-B and Mode-A table hazards. | sec F9 |
| **A-16** | LLR-098.1 / R-1 | "assumed — verify in Phase 3"; severity HIGH; one assertion over one golden | **NEW:** normative, mode-agnostic predicate — *`canonical_report_bytes(raw, run_root)` shall contain `RUN_ROOT_TOKEN` and shall not match `[A-Za-z]:[\\/]`, `/Users/`, or `/home/`* — **implemented inside `canonical_report_bytes` (`tests/conftest.py:1014`)** so every golden consumer inherits it. Severity **HIGH → LOW-MED** (golden line 51 already proves the backtick case). | arch A.5, qa m-4, sec F6a |
| **A-17** | LLR-098.2 | test that `md_safe(md_safe(x)) != md_safe(x)` — a property of the **helper** | **DELETED** as the control (kept only as a helper unit test). **NEW sink-level predicate:** for a benign escapable value `v` planted at each file-derived site, the emitted line **shall** contain `md_safe(v)` and **shall not** contain `md_safe(md_safe(v))` — e.g. plant `SYM_A`, require `SYM\_A`, forbid `SYM\\\_A`. Detects over- **and** under-application. → **`AT-163` (new)**. | arch M-4 |
| **A-18** | LLR-098.3 | explicit `limit >= 500` for `issue.message` only | **NEW policy:** (a) **Mode A** takes an **explicit** `limit` at every site — 500 for `issue.message`, 80 for `region.name`, a stated report-wide default elsewhere; (b) **Mode B does not truncate**, closing the machine-dependent-golden door (truncation would otherwise depend on the operator's tmp-root depth and username length). `issue.code`, `issue.symbol`, `related_artifacts`, `project_name`, `variant_id`, `descriptor.file_type` are uncapped upstream (`ValidationIssue.__post_init__` scrubs `message` **only**) and would each have been newly truncated at 240. | arch M-5, qa M-2 |
| **A-19** | `TRUNCATION_MARKER` | "renders with 0 occurrences of `TRUNCATION_MARKER`" — ambiguous between two constants | **NEW:** pinned by name as `markdown_safety.TRUNCATION_MARKER`, plus an assertion that it differs from `validation/model.py:21`'s `_TRUNCATION_MARKER` so a future merge of the two is a conscious act. | qa M-3 |
| **A-20** | `assert_field_inert` | clause 1 `{t.type for t in toks} <= {"text","softbreak"}` over a walk including containers (**false on every benign table row**); clause 2 `all(ch in "".join(t.content …) for ch in visible(payload))` (`visible()` **undefined**; joins raw `inline.content` with cooked `text.content`) | **NEW:** §6 above. Types over inline descendants with a container allow-list; content over `text` tokens only; clause 2 compares to `expected_display(payload, mode)`. | qa B-5, arch B-4, sec F2 |
| **A-21** | Payload set | 30/31/"all 31" stated three ways; no `html_inline`/`html_block` row; G-4 context-free | **NEW:** **33 active + 2 negative**; `html-inline` (`<img src=x onerror=alert(1)>`) and `html-block` (`\n\n<div>x</div>\n`) added; **G-4 parses in emission context** (the batch-60 "assert at the SINK" lesson, which the guard itself violated); `MUTATING_RULES = {entity, escape}` take a fidelity predicate; `G-3` floor `>= 33` with the `>=` justified. G-1's two ignored rule chains (`core`, `inline2`) are justified in-table as orchestration-only. | qa B-3, B-4, m-1, m-2 |
| **A-22** | Registry §7 batch-39 claim | "batch-39's surviving guard (`structural == 7`) is **blind to this class**" | **DELETED — measurably false.** It counts pipes in the **raw source** (`test_report_symbol_escape.py:150`), so a hostile pipe yields 8 ≠ 7 → **RED**. **NEW:** it is blind to (i) the other 32 fields and (ii) every pipe-free grammar payload. **The guard is RETAINED** (D-27); the rewrite is justified by `_md_table_cell`'s removal, not by a false blindness claim. | qa M-1, E-2 |
| **A-23** | Block starters | "Pin it, or fix the escape set" — an open question, no D-ruling | **NEW (D-10), three pins:** (1) normative LLR — `md_safe`/`md_code` **shall** collapse `\r\n\t` to a single space **before** truncation and escaping, and the docstring **shall** record that this collapse, not the escape set, is the control that defuses `-`, `+`, `=`, `>`, `1)`/`1.` and indented code; (2) counterfactual TC — delete the collapse line → RED; (3) **new static guard** — every `md_safe(`/`md_code(` interpolation in `report_service.py` sits in a line template whose text before the interpolation is non-empty. Pin 3 is what keeps the argument true as the module evolves: the collapse alone does not protect a field emitted at column 0. **Implementability constraint (measured):** pin 3 **shall** evaluate the *assembled line template*, not the source line. A per-source-line heuristic false-positives on **11** sites in `report_service.py` (`:230`, `:241`, `:242`, `:247`, `:252`, `:259`, `:266`, `:409`, `:898`, `:1276`, `:1293`) — exception messages, int-derived continuations, and the second physical line of the multi-line bullet at `:897-898`. A guard that must be suppressed at 11 sites on day one is a guard nobody will keep. | arch B-5, sec F4 |
| **A-24** | Host-path disclosure | **unmentioned across all three artifacts** | **NEW (D-11, operator-ruled): partial fold.** (a) `_redact_absolute_paths` is promoted into the leaf module and applied to **`issue.message`** (`report_service.py:1026`) before Mode-A escaping — the highest-risk field, carrying parsed file text and exception strings. (b) **Mode-B path fields stay raw by design**, because CN-6/R-1's mitigation is a raw-byte substitution in `canonical_report_bytes`; this is an **explicitly accepted divergence** from batch-60's shareability posture, not an omission. (c) Recorded as residual risk §10 and carried to `BACKLOG.md` at MAJOR, the severity batch-60 set. | sec F5 |
| **A-25** | Fail-closed | unspecified | **NEW (D-18):** escaping failure **shall** abort report generation; no partially-escaped or unescaped document **shall** be written; no escaping path **shall** catch a broad exception and fall through to the raw value. TC: an object whose `__str__` raises → assert no file exists afterwards. | sec F10 |
| **A-26** | Control-character filter | `ch if ch >= " " else " "` — C0 only | **NEW (D-19):** filter by Unicode **category** in both modes, dropping **`Cc`, `Cf`, `Zl`, `Zp`** and substituting a **visible** marker. `TC-382`'s expectation changes from "no exception, no mojibake" — which proves nothing about deception — to a **rendered-text equality** assertion. **Self-correction (measured this session):** an earlier draft of this amendment named only `Cc`/`Cf` and claimed to close the survivor list. **It does not** — `U+2028 LINE SEPARATOR` is category **`Zl`**, so it passes a `Cc`/`Cf` filter *and* the `\r\n\t` collapse, and it is in the survivor list precisely because it displays as a line break the bytes do not contain. `Zl`/`Zp` are therefore normative, and the counterfactual TC **shall** include U+2028. | sec F8 |
| **A-27** | `_declaration_error_lines` budget | uncapped; `TC-397` asserts the `REPORT_MAX_TOTAL_BYTES` accounting "still holds" | **NEW (D-20):** `MAX_REPORT_ISSUES_PER_VARIANT = 200`, mirroring `MAX_REPORT_FINDINGS_PER_BLOCK`. `TC-397` is rewritten so its fixture drives the **uncapped** section past the budget, and its docstring states the fixture's **multiple** of the limit (batch-60's lesson: a fixture 2.8× under the limit passed with the guard deleted). Verified: `_ByteBudget` is consumed at hexdump granularity only (`:1255`, `:1287`, `:1569`). | sec F7 |
| **A-28** | `md_code("")` | undefined | **NEW (D-23):** `"(empty)"`, matching Mode A, so the report never emits a bare double-backtick. | sec F11 |
| **A-29** | `"(empty)"` substitution | audited at 1 of 21 Mode-A sites | **NEW:** the remaining 20 sites are audited for a reachable empty value; where one exists, the site keeps an explicit conditional (as `report_service.py:977-981` already does, which is why golden line 57 reads `\| standalone \| - \|`). Named candidates: `issue.symbol`, `issue.related_artifacts` (both `Optional`), `descriptor.file_type` (absent when un-sniffed). Mechanical census, not a per-site judgement. | qa M-5 |
| **A-30** | AT realization | `AT-160/161/162` named in no target file; `AT-160` clause 1 vacuous, clause 2 has no oracle | **NEW (D-16), one node each:** `AT-160` → `test_at160_benign_report_matches_recaptured_golden`; `AT-161` → `test_at161_hostile_image_cannot_close_hexdump_fence`; `AT-162` → `test_at162_paths_render_without_inserted_escapes`. `AT-160`'s byte-identity-vs-recaptured-golden clause is **replaced** by the one-shot **line-number diff gate** (byte identity against a golden re-captured from the code under test is true by construction); the readability clause **demotes to `TC-395`**, which already has a concrete oracle. `AT-162`'s canonicaliser clause becomes its own TC (it asserts on a test helper, not a shipped surface). | qa B-7 |
| **A-31** | Threat model | US-B62-2: "the file is safe once it leaves the app"; AT-158: "**any** standard GitHub-flavoured markdown reader" | **NEW (D-21):** narrowed to *a default `markdown-it` `gfm-like` reader (linkify + html ON)*, with a named residual-risk row for reader extensions. An honest narrow claim is worth more than a broad one the tests cannot support — `:x:` next to a PASSED row is verdict forgery on the real sharing target, and every token stays `text`. | sec F6 |
| **A-32** | Census key | "33 emission sites" | **NEW (D-26):** the census keys on the **24 escape-required** sites. ~50 interpolating sites exist; 33 was a curated list, so a census keyed on it asserts an arbitrary number. | arch m-1 |
| **A-33** | Anchors | deferred import at `report_service.py:974-976` | **Corrected:** comment `:965-967`, `from .diff_report_service import _md_table_cell` at **`:968`**. The `_md_table_cell` call at `:978` and `validation/model.py:22` were correct. Verified on disk this session. | qa m-5, arch m-7 |
| **A-34** | C-27 target list | "Extended: `tests/test_report_symbol_escape.py`" | **NEW:** adds `tests/test_report_service.py`, `tests/test_tui_report_filter_surface.py` (byte pin `:85`, `_md_table_cell` dependence `:290`), and `tests/test_flow_report_service.py` (A-13). `tests/test_report_service.py` was in **no** C-27 list. | arch B-2, M-8 |
| **A-35** | Increment cut | Inc-1 = 3 files, exit "`test_flow_report_*.py` 0 edits / 0 failures" | **NEW:** Inc-1 = **4 files** (adds `tests/test_flow_report_service.py`); exit is **exactly 1 edit** (A-13), 0 failures. The old exit criterion was false against the measured behaviour. | A-13 |
| **A-36** | `<in-memory document>` | module literal, in neither the 24-field list nor the 7 trusted rows; emits `html_inline` under the default parser | **NEW (D-17):** changed to `(in-memory document)`, matching `diff_report_service.py:540,1541`. Measured **zero** test/golden impact. Removes the need to provenance-scope AT-158's html clause. Mode-B wrap applies to the **path branch only**; the fallback literal is trusted and unwrapped. | arch M-6 |
| **A-37** | `md_safe` docstring | claims the value is inert "anywhere in the report — table cell, list item or heading" | **NEW:** the column-0 precondition is part of the published contract (A-23), and the docstring records that `!` is not escaped and the image construct is dead **only** because `[` and `]` are — removing either re-enables outbound image requests from the exported file. | sec F4, F13 |
| **A-38** | `limit` application | applied after a full-string per-character pass | **NEW:** clamp at entry (`str(value)[: limit * 8]`) before normalisation, and raise `TC-382`'s boundary case above 10 000 chars, which is three orders of magnitude under the interesting size. | sec F12 |
| **A-39** | `MAX_REPORT_CELL_CHARS` placement | moves into the shared leaf | **NEW:** **stays in `flow_report_service`**. A-18 already proves the two consumers need different caps; the leaf exports functions with an explicit `limit`, not one shared cap policy. | arch m-6 |
| **A-41** | qa catalog's "no private symbol" claim | "No AT references an escaping helper, a private function, or any symbol introduced by this batch" — false: `AT-157` parses with `_hardened_markdown_parser()` (`screens.py:82`) | **NEW:** restated as *no AT references **the mechanism under change***. Parsing with the app's real parser factory is **correct** (C-12: observe the real consumer, so the AT cannot drift from what the app renders); promoting a public factory to satisfy a doc sentence would be the tail wagging the dog. The claim moves, not the test. | qa M-6 |
| **A-42** | P-4's probe framing | titled "values actually present in the AT-055b golden", but `issue.code`, `check.source_path` and `region.name` are **not** in that golden (it reads `None.`, `No checklists were executed for this variant.`, and has no addendum section) | **DELETED** as evidence. The drift set is now derived by applying the mode to **every** golden value and diffing (A-04), which is why the mis-scoped probe no longer gates anything. *This mis-scoping is precisely how the 2-line prediction slipped through.* Residual minors folded here: `G-2`'s `- {""}` subtraction is dead code (measured: `_schemas` has no `""` key), and `G-1`'s two ignored rule chains (`core`, `inline2`) are orchestration-only and now justified in-table rather than silently omitted. | arch M-7, qa m-2, m-3 |
| **A-40** | `US-062-*` spelling | source artifacts still say `US-062-*` throughout | **NEW:** superseded banners added to both source artifacts; a C-26 census must use `US-B62-`. `screens.py:97`'s reference to `flow_report_service._md_safe` becomes `markdown_safety.md_safe` at Inc-1. | arch m-4, m-5 |

---

## 7. Corrections to my own Phase-1 evidence (the four orchestrator errors, plus what measurement changed)

- **C-1 (E-1)** — I adopted an AT id set on a semantic match marked "to be confirmed". The two
  definitions diverge, and the adopted one **cannot see the registry's own Blocker #1** (an injected
  `hr` passes it). Closed by A-01. *Rule: never adopt an id whose predicate is unread.*
- **C-2 (E-2)** — I called batch-39's guard "blind to this class". It counts **raw-source** pipes and
  goes **RED** on a hostile pipe. Closed by A-22; the guard is retained (D-27). *Rule: measure a
  guard before justifying its replacement — "it was broken" is a claim, not a premise.*
- **C-3 (E-3)** — I predicted "exactly 2 lines" of golden drift and made the prediction the
  acceptance criterion. It is **3** (the golden carries two `.s19` rows; the probe sampled once a
  field the fixture emits twice). A **correct** implementation would have tripped my own gate.
  Closed by A-04. **Same class, second instance, found this session:** the security review's stated
  cost for A-11/A-13 — *"the flow-report goldens move"* — is also wrong. Measured: **1 test, 0
  goldens** (A-13). I did not adopt that cost claim; I executed it.
- **C-4 (E-4)** — I wrote that the benign no-op arm "still holds". `_md_safe('SYM_A') → 'SYM\_A'`
  breaks three sites in two files, one outside every C-27 list. Closed by A-03 + A-34.
- **C-5 (the oracle was blind)** — `&` was unescaped, so `SYM_A&vert;PASSED` renders a forged table
  fragment while every token stays `text` and `assert_field_inert` scores it **GREEN**. A control
  that cannot fail on its own class. Closed **structurally, not by a note**: A-10 escapes `&` so the
  attack no longer works, **and** A-20's fidelity clause gives the oracle a way to fail on it —
  either fix alone would have left the class open in one direction.
- **C-6 (found in THIS fold, by measuring my own amendment)** — A-26 as first drafted named `Cc`/`Cf`
  and claimed to close the surviving-character list. **U+2028 is `Zl`**, so it passed both the
  proposed filter and the `\r\n\t` collapse. Corrected in-place to `Cc`/`Cf`/`Zl`/`Zp` with U+2028
  named in the counterfactual. *This is the fourth instance of the batch's own recurring class — an
  acceptance threshold asserted from a category I had not enumerated — and it was caught only
  because the fold's new thresholds were executed rather than reasoned.*
- **Measurements that CONFIRMED a fold decision** (recorded so Phase 3 does not re-derive them):
  U+FFFD is category `So`, survives the C0 filter, and is inert bare in both grammars, so it is a
  safe Mode-B marker (A-11); all **three** existing goldens pass A-16's residue predicate **today**,
  so moving it into `canonical_report_bytes` breaks no consumer on day one.

---

## 8. Test targets (C-27)

**New:** `tests/test_report_markup_safety.py`, `tests/test_report_field_census.py`.
**Extended:** `tests/test_report_symbol_escape.py` (both arms), `tests/test_report_service.py`
(`:260`, `:1403`), `tests/test_tui_report_filter_surface.py` (`:85`, `:290`),
`tests/test_flow_report_service.py` (`:415`, A-13).
**Frozen:** none of the touched source files is in `_ENGINE_PATHS`; neither new test file is in
`_ENGINE_TEST_FILES` (`tests/test_engine_unchanged.py:120-130`,
`tests/test_tui_directionb.py:5443-5454`). **Both guards run at every increment.**

---

## 9. Increment cut (C-21 fired; corrected by A-35)

7 ATs, one owning increment each, ≤5 files each.

1. **Inc-1 — the leaf helper · 4 files · owns no AT.** `markdown_safety.py` (new) ·
   `flow_report_service.py` (aliases; `MAX_REPORT_CELL_CHARS` stays, A-39) ·
   `tests/test_report_markup_safety.py` (new) · `tests/test_flow_report_service.py` (**exactly one**
   re-baselined case, A-13). **Exit:** 51/52 flow-report tests unmodified, 0 failures.
2. **Inc-2 — golden-affecting sites · 5 files · owns AT-159, AT-160, AT-162, AT-163.**
   `report_service.py` (tables + paths; remove the deferred import `:965-968` and the call `:978`) ·
   the golden (**3-line** recapture) · `test_report_symbol_escape.py` · `test_report_service.py` ·
   `test_tui_report_filter_surface.py`. Kept together so the golden is never RED across a boundary.
3. **Inc-3 — remaining Mode A sites · 3 files · owns AT-157, AT-158.** `report_service.py`
   (headings, issues + redaction, addendum, filter; drop `_strip_ctl_local` at `:512`; the
   `(in-memory document)` literal) · `tests/test_report_field_census.py` (new) · `conftest.py`
   (A-16's residue assertion).
4. **Inc-4 — scope pins and closeout · 2 files · owns AT-161.** hexdump-fence + `_format_bytes`
   pins · `REQUIREMENTS.md`.

**The golden gate (one-shot, pasted verbatim into the Inc-2 packet — not a surviving test):**

```bash
git show HEAD:tests/goldens/batch35/at055b-project-report.md > golden.before
# regenerate the golden
diff --unified=0 golden.before tests/goldens/batch35/at055b-project-report.md
# gate: the changed-line set is EXACTLY {14, 15, 51} — assert the line numbers, not the count
```

---

## 10. Residual risks (named, not hidden)

| # | Risk | Disposition |
|---|---|---|
| RR-1 | **Reader extensions outside the modelled grammar** — `:emoji:`, `$…$` math, `==highlight==` render on GitHub/VS Code/Obsidian and are inert under `gfm-like`. A filename containing `:x:` can put a red ❌ beside a PASSED row. | Declared out of model (D-21); escape-set extension declined with reasons (D-22). |
| RR-2 | **Mode-B path fields disclose host paths** in project reports where flow reports redact them. | Operator-accepted divergence (D-11/A-24); carried to `BACKLOG.md` at **MAJOR**, batch-60's severity. |
| RR-3 | **Mode B is lossy** on backtick-bearing values. | Declared, with a visible U+FFFD marker (A-11) so the loss is legible rather than silent. |
| RR-4 | `diff_report_service`'s own escaping helpers remain. | D-8 deferral, now carried inside HLR-097 itself (A-07). |

---

## 11. Discharge matrix

| Blocker (`02-review.md`) | Amendment |
|---|---|
| E-1 AT id adopted unread | A-01 |
| E-2 batch-39 guard over-claimed | A-22, D-27 |
| E-3 golden drift 2 vs 3 | A-04 |
| E-4 benign arm "holds" | A-03, A-34 |
| 6. Block starters unruled | A-23 (D-10) |
| 7. G-1 vs G-4 contradiction | A-21 |
| 8. AT-160/161/162 UNREALIZED | A-30 |
| 9. `<in-memory document>` breaks AT-158 | A-36 |
| 10. Non-idempotence has no over-application detector | A-17 (`AT-163`) |
| 11. `&` unescaped → oracle blind | A-10 + A-20 (§7 C-5) |
| 12. `:x:` / `$…$` / `==` survive | A-31, D-22 |
| 13. U+202E / U+200B / U+FEFF / C1 survive | A-26 |
| 14. `_redact_absolute_paths` dropped | A-24 (D-11) |
| 15. Fail-closed unspecified | A-25 |
| 16. `_declaration_error_lines` uncapped | A-27 |
| 17. Mode B removes backticks | A-11 |
| 18. `MAX_REPORT_CELL_CHARS` silent truncation | A-18, A-19 |
| arch B-3 / qa B-2 TC registry | A-02 |
| arch B-4 / qa B-5 assertion helper | A-20 |
| arch B-6 mode selection is prose | §4 truth table |
| arch B-7 HLR-097 false at merge | A-07 |
| qa B-1 AT predicate | A-01 |
| qa B-6 golden prediction | A-04 |
| qa B-7 AT nodes | A-30 |
| majors M-1…M-8 (arch), M-1…M-6 (qa), F7–F13 (sec) | A-06, A-08, A-09, A-14, A-15, A-16, A-17, A-18, A-19, A-21, A-22, A-26, A-27, A-28, A-29, A-32, A-33, A-36, A-37, A-38, A-39, A-41, A-42 |
| minors m-1…m-7 (arch), m-1…m-5 (qa) | A-21, A-32, A-33, A-39, A-40, A-42 + the superseded banners on both source artifacts |
