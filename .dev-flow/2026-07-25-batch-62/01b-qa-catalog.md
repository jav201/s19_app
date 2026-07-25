# 01b — QA acceptance catalog — batch-62 `report_service` markdown escaping

> ⚠ **PARTIALLY SUPERSEDED (2026-07-25, Phase-1 fold iteration 1).** Preserved as the validation-method
> record; `01-requirements.md` rules on collisions and its §6.5 carries every Before/After. **This
> artifact's `TC-376…398` ARE the TC registry (A-02).** Superseded here: `assert_field_inert` §3.4
> (A-20 — clause 1 is false on every benign table row, clause 2 joins raw and cooked content and
> `visible()` is undefined), the payload table and `G-1`/`G-3`/`G-4` (A-21 — +2 HTML payloads,
> emission-context parsing, `MUTATING_RULES`), `TC-382` (A-26, A-38), `TC-396` (A-18 — no longer
> conditional), `TC-397` (A-27), the AT→file target map (A-30), the "no private symbol" claim
> (restated: *no AT references the mechanism under change*), and the `US-062-*` spelling.

**Phase:** 1 (validation method + acceptance catalog). **Language:** English.
**Base:** `claude/batch-62-report-escaping` @ `8d3c504`.
**Author:** `qa-reviewer`. **Status:** READY for Phase-2 review.

---

## 0. BLUF

Three ATs, twenty TCs, and a payload set of **30 active + 2 negative-control**
payloads **derived from the parser's own rule table** — not hand-listed.

Independent re-measurement confirmed the Phase-0 ground truth and produced
**four findings Phase-0 did not have**, all of which change the test design:

| # | Finding | Consequence |
|---|---|---|
| **F-1** | A raw `\|` in a table field does **not** grow the column count — markdown-it caps a row at the header's width, so surplus cells are **shifted and silently dropped**. Measured: benign inventory row `['BENIGN','a.s19','s19','yes']` → hostile `['EVIL','INJECTED','COL','a.s19']`. The file type and active flag are **gone**. | US-062-3's observable is **positional cell content**, not pipe count. The batch-39 raw-pipe-count assertion is a proxy that cannot see this. |
| **F-2** | The reference escaper `flow_report_service._md_safe` **leaks block starters**: `- item` → `bullet_list_open`, `---` → `hr` pass through unescaped (`_MD_ESCAPE` at `flow_report_service.py:120` contains `>` and `#` but **not** `-`, `+`, `=`). | `_md_safe` is safe in `flow_report_service` **only because** it collapses newlines first. That coupling is load-bearing and currently unpinned. TC-380 pins it. |
| **F-3** | `report_service.py:901` embeds a file-derived value **inside a backtick code span** (``saved as `{summary.saved_path}` ``). A raw backtick closes the span: measured ``a` **PWNED** `b`` → `code_inline`, **`strong_open`**, `code_inline`. Applying `_md_safe` there fixes the breakout but renders `C:\out.s19` as visible `C:\\out\.s19` — every path contains `.` and `/`. | **Design blocker — see §6.1.** `_md_safe` cannot serve both the plain and the code-span site correctly; its docstring's "context-free" claim (AMD-5) does not hold at this site. |
| **F-4** | `evil.tld` is **not a real TLD**, so fuzzy linkify never fires on it — measured `default_links=[]`. `evil.com` fires three ways. | A payload set using `.tld` domains is **vacuous against exactly the class batch-60 missed**. The non-vacuity guard (§3.3) is the machine check that catches this. I made this mistake myself in probe #2 and the guard is what surfaced it. |

---

## 1. Scope, surfaces, and re-measured ground truth

### 1.1 Surfaces under test

| Surface | What it is | Story |
|---|---|---|
| **S-A — app report viewer** | `ReportViewerScreen` (`s19_app/tui/screens.py:1261`) rendering through the hardened parser `_hardened_markdown_parser()` (`screens.py:82`, returns `MarkdownIt("gfm-like", {"linkify": False, "html": False})` at `screens.py:112`) | US-062-1 |
| **S-B — the exported `.md` on disk** | the file written by `generate_project_report` (`s19_app/tui/services/report_service.py:1473`) to `<project_dir>/reports/<UTC>-report.md`, consumed by **any** default `gfm-like` reader (linkify + html **ON**) | US-062-2 |
| **S-C — table rows inside S-A/S-B** | the inventory / overview / modifications / checklist tables | US-062-3 |

Both stories drive the **same shipped entry point** — `generate_project_report`
— and differ only in the parser the produced artifact is then read with. This
is C-12 output-then-consume: the AT observes a **consumer** over the
**handler-produced artifact**, never a hand-built string.

### 1.2 Measured RED on the current tree

Executed against `8d3c504` through the real generator (probe transcripts in
§7). Baseline benign report active tokens: `{bullet_list_open, heading_open,
strong_open}` under both parsers.

| Field | Site | Measured today |
|---|---|---|
| `project_name` | `report_service.py:769` (`# Project report: {…}`), `:771` | `~~REVOKED~~ **fake** [c](http://evil.tld)` reaches the file **raw**; viewer gains `s_open` + `link_open` |
| `variant_id` | `:807`, `:862`, `:1593` (`## Variant: {…}`), `:1280`, `:1297`, `:1453`, `:1459`, `:1466` | raw; `EVIL\|INJECTED\|COL` corrupts the inventory row (**F-1**) |
| `descriptor.path.name`, `descriptor.file_type` | `:807` | raw, in a table |
| `summary.source_path` | `:897` | raw |
| `summary.saved_path` | `:901` | raw, **inside a code span** (**F-3**) |
| `entry.linkage` | `:987` | raw |
| `entry.linkage_symbol` | `:988` | **only escaped field** — `_md_table_cell` (batch-39, shape-only) |
| `issue.code` / `severity` / `message` / `symbol` / `related_artifacts` | `:1026`–`:1032` | raw — the richest untrusted surface in the document |
| `check.source_path` | `:1097` (`#### Checklist: {…}`) | raw |
| `entry.result` | `:1117` | raw |
| `region.name` | `:1445` | raw |
| `filter_name` | `:729` | `_strip_ctl_local` (`:512`) only — **control chars, no grammar** |

**Column-0 reachability (measured):** no field is emitted at column 0 — every
site carries a `# `, `## `, `#### `, `- ` or `| ` prefix. A file-derived value
therefore cannot start a block **unless it embeds a newline**. Measured:
`project_name = "p\n\n---\n"` → `hr` fires **today**. This is why the newline
collapse is a load-bearing control and not an incidental tidy-up (**F-2**).

---

## 2. Acceptance tests (black-box, one per story)

Each AT drives `generate_project_report` — the shipped entry point — with a
project whose file-derived fields carry the derived payload set, then observes
the produced artifact through a real parser. No AT references an escaping
helper, a private function, or any symbol introduced by this batch.

### AT-157 — file-derived text renders literally in the app report viewer
*(US-062-1)*

- **Given** a project whose file-derived fields (project name, variant id,
  source/saved paths, linkage, declaration-error code/severity/message/symbol/
  related artifacts, checklist source, check result, region name, filter name)
  each carry one payload from the derived active-grammar set (§3),
- **When** the operator generates a project report and opens it in the app's
  report viewer,
- **Then** for every such field, **every token the viewer's parser produces
  from that field's text is of type `text`** — no `em_open`, `strong_open`,
  `s_open`, `link_open`, `image`, `code_inline`, `hardbreak`, and no new
  block-level token (`heading_open`, `hr`, `bullet_list_open`,
  `ordered_list_open`, `blockquote_open`, `fence`) is attributable to it —
  **and** the payload's visible characters are all still present in the joined
  text content (escaped, not deleted).
- **Surface:** S-A. Artifact read back from disk, parsed with
  `_hardened_markdown_parser()` — the viewer's own factory, so the AT cannot
  drift from what the app actually renders.
- **Oracle:** **provenance-based**, per §3.4 — *not* a set-difference against a
  benign baseline. A benign report already contains `heading_open`,
  `bullet_list_open` and `strong_open`, so subtraction is blind to any payload
  that produces one of those three. Measured: `project_name = "p\n\n# PWNED\n"`
  injects a heading and the subtraction oracle reports **no change**.
- **Counterfactual (proven RED at `8d3c504`):** with
  `project_name = "proj ~~REVOKED~~ **fake** [c](http://evil.tld)"` the viewer
  token stream gains `s_open` and `link_open` over the benign baseline. AT-157
  reproduces this by asserting the *project-name inline token has only `text`
  children* — which fails on today's tree at the first payload.
- **Type:** integration (pytest), automatable.

### AT-158 — the exported `.md` is inert under a DEFAULT `gfm-like` reader
*(US-062-2)*

- **Given** the same project and payload set as AT-157,
- **When** the report file is taken off the machine and opened by **any**
  standard GitHub-flavoured markdown reader — modelled as
  `MarkdownIt("gfm-like", {"linkify": True, "html": True})`, i.e. **both**
  mitigations the app viewer relies on turned **off**,
- **Then** the same all-`text` condition of AT-157 holds, **and** the document
  contains **zero** `link_open` tokens whose `href` is attributable to
  file-derived text, **and zero** `html_inline` / `html_block` tokens.
- **Surface:** S-B — the artifact after it leaves the app. This is the story
  that the batch-60 viewer hardening explicitly does **not** cover
  (`screens.py:100-101` names project reports as a carried follow-up).
- **Counterfactual (proven RED at `8d3c504`):** with `variant_id` = each of
  `http://evil.com/x`, `ftp://evil.com`, `mailto:a@evil.com`, `//evil.com/x`,
  `www.evil.com`, `evil.com`, `user@evil.com`, `www.рф.рф`, the default parser
  emits `link_open` with hrefs `http://evil.com/x`, `ftp://evil.com`,
  `mailto:a@evil.com`, `//evil.com/x`, `http://www.evil.com`, `http://evil.com`,
  `mailto:user@evil.com`, `http://www.xn--p1ai.xn--p1ai` respectively — **all
  eight measured, three occurrences each**. With
  `variant_id = "<img src=x onerror=alert(1)>"` it emits three `html_inline`
  tokens. **The viewer parser emits none of these** — which is precisely why
  US-062-2 needs its own AT and cannot be folded into AT-157.
- **Type:** integration (pytest), automatable.

### AT-159 — table rows keep their column shape and their column *meaning*
*(US-062-3)*

- **Given** a project where the file-derived fields that land in table cells
  (`variant_id`, `path.name`, `file_type`, `linkage`, `linkage_symbol`,
  `entry.result`) carry values containing raw `|`, `\`, and newline,
- **When** a report is generated and its tables are parsed,
- **Then** every table row has **exactly the cell count declared by its header
  row**, **and** each cell's content equals the corresponding field's value —
  i.e. no field's value has been shifted into a neighbouring column and no
  field has been dropped off the end of the row.
- **Surface:** S-C, asserted at **token level** (`tr_open` → `td_open` count
  and the positional `inline` contents), not on the raw text.
- **Counterfactual (proven RED at `8d3c504`, and the reason this AT is not a
  restatement of the batch-39 test):** `variant_id = "EVIL|INJECTED|COL"` in
  the 4-column inventory table yields a row whose token-level **cell count is
  still 4** — markdown-it truncates to the header width — but whose contents
  are `['EVIL','INJECTED','COL','a.s19']` instead of
  `['BENIGN','a.s19','s19','yes']`. **`file_type` and the active flag are
  silently destroyed.** A pipe-count or column-count assertion alone is
  **GREEN** on this input; only the positional-content assertion is RED. This
  is the assertion `tests/test_report_symbol_escape.py:…` (`structural == 7`)
  cannot make.
- **Type:** integration (pytest), automatable.

---

## 3. The payload set — derived from the grammar, guarded for completeness

> **This section is the batch's C-31 deliverable.** Batch-60's TC-004 shipped
> 11 hand-listed payloads with **zero** fuzzy-linkify cases; the input set was
> the vacuous oracle. The fix is not "list more payloads" — it is to make the
> **parser itself** enumerate the set and to make a **dropped or dead payload
> go RED**.

### 3.1 Derivation (machine, at test-collection time)

```python
VIEWER  = _hardened_markdown_parser()                                  # S-A
DEFAULT = MarkdownIt("gfm-like", {"linkify": True, "html": True})      # S-B

ACTIVE_RULES   = VIEWER.get_active_rules()          # {'block':…, 'inline':…, …}
LINKIFY_SCHEMES = set(DEFAULT.linkify._schemas) - {""}
LINKIFY_FUZZY   = {k for k, v in DEFAULT.linkify._opts.items() if v}
```

Measured at `markdown_it 4.2.0`:

- `ACTIVE_RULES['inline']` = `autolink, backticks, emphasis, entity, escape,
  html_inline, image, link, linkify, newline, strikethrough, text`
- `ACTIVE_RULES['block']` = `blockquote, code, fence, heading, hr, html_block,
  lheading, list, paragraph, reference, table`
- `LINKIFY_SCHEMES` = `{'http:', 'https:', 'ftp:', '//', 'mailto:'}`
- `LINKIFY_FUZZY` = `{'fuzzy_link', 'fuzzy_email'}` (`fuzzy_ip` is **False**)

### 3.2 The payload table (30 active + 2 negative controls)

`PAYLOADS: dict[str, Payload]` where `Payload = (rule_key, text, parser)`.
`parser` = which of the two parsers the payload is proven active under.

| # | key | rule / family | payload | active under |
|---|---|---|---|---|
| 1 | `emphasis-star` | `emphasis` | `*em*` | both |
| 2 | `emphasis-underscore` | `emphasis` | `_em_` | both |
| 3 | `strong` | `emphasis` | `**strong**` | both |
| 4 | `strikethrough` | `strikethrough` | `~~REVOKED~~` | both |
| 5 | `inline-link` | `link` | `[click](http://evil.com)` | both |
| 6 | `autolink` | `autolink` | `<http://evil.com>` | both |
| 7 | `image` | `image` | `![a](http://evil.com/x.png)` | both |
| 8 | `code-span` | `backticks` | `` `code` `` | both |
| 9 | `code-span-breakout` | `backticks` | ``a` **PWNED** `b`` | both (**F-3** site) |
| 10 | `entity` | `entity` | `&amp;` | both |
| 11 | `escape-backslash` | `escape` | `\*not\*` | both |
| 12 | `hardbreak` | `newline` | `line  ⏎next` | both |
| 13 | `atx-heading` | `heading` | `⏎⏎# PWNED⏎` | both |
| 14 | `setext-underline` | `lheading` | `⏎⏎Title⏎===⏎` | both |
| 15 | `thematic-break` | `hr` | `⏎⏎---⏎` | both |
| 16 | `bullet-list` | `list` | `⏎⏎- injected⏎` | both |
| 17 | `ordered-list` | `list` | `⏎⏎1. injected⏎` | both |
| 18 | `blockquote` | `blockquote` | `⏎⏎> quoted⏎` | both |
| 19 | `fence` | `fence` | ``⏎⏎```⏎x⏎```⏎`` | both |
| 20 | `indented-code` | `code` | `⏎⏎␣␣␣␣code⏎` | both |
| 21 | `reference-def+use` | `reference` | 2-field: `[c][r]` **and** `⏎⏎[r]: http://evil.com⏎` | both |
| 22 | `table-pipe` | `table` | `EVIL\|INJECTED\|COL` | both (**F-1**) |
| 23 | `linkify-http` | `http:` | `http://evil.com/x` | DEFAULT |
| 24 | `linkify-https` | `https:` | `https://evil.com/x` | DEFAULT |
| 25 | `linkify-ftp` | `ftp:` | `ftp://evil.com` | DEFAULT |
| 26 | `linkify-protocol-relative` | `//` | `//evil.com/x` | DEFAULT |
| 27 | `linkify-mailto` | `mailto:` | `mailto:a@evil.com` | DEFAULT |
| 28 | `linkify-fuzzy-www` | `fuzzy_link` | `www.evil.com` | DEFAULT |
| 29 | `linkify-fuzzy-tld` | `fuzzy_link` | `evil.com` | DEFAULT |
| 30 | `linkify-fuzzy-email` | `fuzzy_email` | `user@evil.com` | DEFAULT |
| 31 | `linkify-idn` | `fuzzy_link` | `www.рф.рф` | DEFAULT |
| **N1** | `neg-fuzzy-ip` | `fuzzy_ip` (**off**) | `10.1.2.3` | **neither** — negative control |
| **N2** | `neg-fake-tld` | — | `evil.tld` | **neither** — negative control (**F-4**) |

Rows 28–31 are the class batch-60 shipped **zero** coverage of.
Row 9 is the class **no** batch has covered (**F-3**).
Rows 13–21 are reachable **only** through an embedded newline — they are what
pins the newline collapse (**F-2**).

### 3.3 Completeness guard — the companion assertion

A single test, `TC-376`, that goes RED if the set is weakened in **any** of
five ways:

| Guard | Assertion | Goes RED when |
|---|---|---|
| **G-1 total rule coverage** | `{p.rule_key for p in PAYLOADS} ⊇ (ACTIVE_RULES['inline'] ∪ ACTIVE_RULES['block']) − INERT_RULES` | markdown-it adds a rule, or a payload is deleted |
| **G-2 total linkify coverage** | `LINKIFY_KEYS_COVERED == LINKIFY_SCHEMES ∪ LINKIFY_FUZZY` | a new scheme ships, or `fuzzy_ip` is enabled upstream |
| **G-3 pinned floor** | `len(ACTIVE_PAYLOADS) >= 30` (literal, with the `>=` justified in the docstring) | anyone trims the battery |
| **G-4 NON-VACUITY** ⭐ | for **every** active payload, parsing the **raw** payload through its declared parser yields ≥1 token outside `{text, paragraph_open, paragraph_close, inline, softbreak}` | a payload becomes dead — e.g. a TLD leaves the linkify list, `evil.tld` is used by mistake (**F-4**), or `[c][ref]` is shipped without its definition |
| **G-5 negative controls stay negative** | `10.1.2.3` and `evil.tld` produce **no** active token under either parser | linkify semantics change under us and the battery's assumptions silently rot |

**G-4 is the highest-value assertion in this batch.** It is the mechanical
form of "the input set is an oracle": a payload that cannot fire proves
nothing, and hand-inspection does not catch it — I shipped a `.tld` domain in
my own first probe and only G-4's logic surfaced it. `INERT_RULES` must be an
explicit, per-entry-justified named constant (`text`, `paragraph`,
`html_block`/`html_inline` are *not* inert and must not be listed) so that
adding to it is visible in review rather than silent.

### 3.4 The assertion helper — assert the EMITTED encoding, never the rendered form

Every AT/TC assertion in this catalog goes through **one** helper. No test may
assert on a character-membership check (`"|" not in text`), on a rendered HTML
string, or on `md.render(...)`.

```python
def field_tokens(md, report_text, marker) -> list[Token]:
    """Every token markdown-it produces from the line(s) carrying `marker`,
    including .children — the EMITTED token stream, walked recursively."""

def assert_field_inert(md, report_text, marker, payload) -> None:
    toks = field_tokens(md, report_text, marker)
    assert toks, "marker not found — the fixture did not reach the report"
    assert {t.type for t in toks} <= {"text", "softbreak"}
    assert all(ch in "".join(t.content for t in toks) for ch in visible(payload))
```

Rationale, per the standing *assert-the-emitted-encoding* control candidate
(third occurrence in three batches: batch-60's wrong-grammar linkify sink,
batch-60's doc-vocabulary asserts, batch-61's NBSP-entity predicate
false-failing a correct artifact 0/19):

1. **Provenance, not subtraction.** A benign report already emits
   `heading_open`, `bullet_list_open`, `strong_open`; subtracting a benign
   baseline is blind to any payload producing one of those. Measured in probe
   #2 §E: an injected `# PWNED` heading reports **"no change"** under
   subtraction. The helper instead asserts the *field's own* tokens are all
   `text`.
2. **The second clause is not decoration.** `{t.type} <= {"text"}` alone is
   satisfied by an escaper that **deletes** the payload. The
   characters-still-present clause is what forbids "sanitise by silently
   dropping data" — a real risk on a report meant to be evidentiary.

---

## 4. White-box test cases (TC-376 … TC-398)

Mapped to the LLR families the architect is deriving in parallel: **(A)** an
escaping helper, **(B)** its application at each field site, **(C)** table-shape
composition, **(D)** byte-identity no-op on benign input, **(E)** caps.
`ID`s continue from the repo's current maxima (`AT-156`, `TC-375`).

### LLR-A — the escaping helper

| ID | Title | Steps | Expected | Priority |
|---|---|---|---|---|
| **TC-376** | Payload-set completeness guard | Derive `ACTIVE_RULES` / `LINKIFY_SCHEMES` / `LINKIFY_FUZZY` from the two live parsers; run G-1…G-5 (§3.3) | All five guards hold; `len(ACTIVE_PAYLOADS) >= 30`; both negative controls inert | **HIGH** |
| **TC-377** | Per-metacharacter neutralisation — **one case per class**, parametrised over all 31 active payloads | For each payload independently, escape it and assert `assert_field_inert` under its declared parser | Each of the 31 goes GREEN **individually**. Not one collapsed mega-payload — batch-53's qa M-1 collapsed-proxy miss: a single string containing many metacharacters proves nothing about *which* are handled | **HIGH** |
| **TC-378** | Escaping is idempotent-safe / never double-escapes | Escape a value already containing `\|` and `\\` | Backslash is handled first; a round-trip through the helper twice does not grow the backslash run without bound; visible characters preserved | MEDIUM |
| **TC-379** | Control characters and newlines are removed, not escaped | Values with `\x00`–`\x1f`, `\r`, `\n`, `\t` | No control byte survives; `\r`/`\n`/`\t` become a single space; result stays one line | **HIGH** |
| **TC-380** | ⭐ **Newline collapse is load-bearing — pinned** (**F-2**) | Value `"p\n\n---\n"`, `"p\n\n# PWNED\n"`, `"p\n\n- x\n"`, `"p\n\n> q\n"`, `"p\n\n1. x\n"`, `"p\n\n```\nx\n```\n"`, `"p\n\n    code\n"` at the `project_name` site | Zero block token attributable to the field. **Counterfactual: delete the newline-collapse line from the helper and TC-380 must go RED** — measured RED today for the `hr` case. Required because the escape set does **not** cover `-`, `+`, `=` and therefore relies entirely on the collapse | **HIGH** |
| **TC-381** | Empty / null / whitespace-only input | `""`, `None`, `"   "`, `"\n\n"` | A defined, non-crashing, non-empty placeholder; no `IndexError`; the surrounding row/heading keeps its shape | **HIGH** |
| **TC-382** | Unicode boundary | 4-byte astral chars, RTL override `U+202E`, zero-width `U+200B`, NBSP, combining marks, a 10 000-char string | No exception; no mojibake; UTF-8 round-trip through the written file is exact for the characters that survive | MEDIUM |

### LLR-B — application at each field site

| ID | Title | Steps | Expected | Priority |
|---|---|---|---|---|
| **TC-383** | ⭐ **Field-site census — every file-derived field is escaped** | For **each** of the 15 sites in §1.2, generate a report with that field (and only that field) carrying payload #4 `~~REVOKED~~`, and assert `assert_field_inert` under the viewer parser | All 15 GREEN. **This is the C-26 control**: batch-39 fixed `linkage_symbol` and never swept its siblings — a per-site parametrised case is what makes "we missed one" fail loudly instead of shipping | **HIGH** |
| **TC-384** | The census list cannot silently shrink | Assert the site list used by TC-383 has ≥15 entries and that each named site's marker is actually found in the generated report (`assert toks` in the helper) | A site that stops appearing in the output (renamed, refactored away, filtered out by a default option) goes RED rather than vacuously passing | **HIGH** |
| **TC-385** | Heading sites specifically | `project_name` at `report_service.py:769`, `variant_id` at `:1593`, `check.source_path` at `:1097` | The heading's `inline` children are all `text`; the heading level is unchanged (a payload cannot promote `##` to `#`) | **HIGH** |
| **TC-386** | ⭐ **Code-span site** (`report_service.py:901`, `saved_path`) — **F-3** | Payload #9 ``a` **PWNED** `b`` as `saved_path`; then a benign Windows path `C:\proj\out.s19` | (a) no `strong_open` — measured **RED today**; (b) the benign path renders **without visible backslash noise**. Blocked on §6.1 | **HIGH** |
| **TC-387** | Declaration-error compound line (`:1026`–`:1032`) | `issue.code`, `severity.value`, `message`, `symbol`, and each element of `related_artifacts` hostile simultaneously | Every segment inert; the `related=` comma join is not broken by a comma or `\|` inside an element | **HIGH** |
| **TC-388** | Filter-header site (`:729`) is upgraded from `_strip_ctl_local` to grammar escaping | Hostile `filter_name` | Inert under both parsers. Today `_strip_ctl_local` (`:512`) handles control chars only | MEDIUM |
| **TC-389** | Truncation-appendix path (`:1280`, `:1297`, `:1608`) | Force the region cap with a hostile `variant_id` so a note is emitted | The note's `- {note}` bullet is inert — a second-order path that only fires under truncation and is easy to miss | MEDIUM |

### LLR-C — table-shape composition

| ID | Title | Steps | Expected | Priority |
|---|---|---|---|---|
| **TC-390** | ⭐ **Positional cell integrity** (**F-1**) | `variant_id = "EVIL\|INJECTED\|COL"`; parse; compare the row's positional `inline` contents against the benign report's | Cells equal `['EVIL\|INJECTED\|COL','a.s19','s19','yes']`. **RED today**: measured `['EVIL','INJECTED','COL','a.s19']` — `file_type` and the active flag destroyed. A pipe-count assertion is GREEN on this input | **HIGH** |
| **TC-391** | Cell count == header width, all four tables | Hostile values in inventory / overview / modifications / checklist rows | Every `tr` emits exactly its header's `td` count | **HIGH** |
| **TC-392** | Backslash and control chars in a cell | `"a\\b"`, `"a\x01b"` | Backslash doubled, control stripped, row shape intact — preserves the batch-39 contract | MEDIUM |
| **TC-393** | Batch-39 regression — `linkage_symbol` still behaves | Re-run the two existing cases in `tests/test_report_symbol_escape.py` | Both stay GREEN, **or** are consciously re-baselined with a §6.5 before/after record if the new helper changes their output | **HIGH** |

### LLR-D — byte-identity no-op on benign input (C-24)

| ID | Title | Steps | Expected | Priority |
|---|---|---|---|---|
| **TC-394** | ⭐ **Benign round-trip is byte-identical** | Generate a report with an entirely benign fixture on `main`, then on the branch, with the clock pinned | The two files are **byte-identical**. This is what protects the existing goldens across the five consumer test files (§5) and is the single most likely source of collateral damage in this batch | **HIGH** |
| **TC-395** | Common benign shapes are untouched | Windows path `C:\proj\out.s19`, POSIX path `/tmp/out.s19`, `SYM_A`, `0x0800_0000`, `v1.2.3`, `a.s19`, `check-1_result` | Each round-trips character-identical. **Note:** a naive reuse of `flow_report_service._md_safe` **fails this** — its `_MD_ESCAPE` includes `/`, `.` and `\`, so every path and every version string acquires visible backslashes. See §6.1 | **HIGH** |

### LLR-E — caps

| ID | Title | Steps | Expected | Priority |
|---|---|---|---|---|
| **TC-396** | ⭐ **Any new length cap is pinned** | If the design introduces a per-cell/per-field char cap `N`: feed a value of exactly `N`, `N+1`, and `10*N` | At `N` unchanged; at `N+1` truncated with the truncation marker; at `10*N` the output length is `≤ N + len(marker)`. **The fixture must exceed the cap** — batch-60's byte budget was entirely unpinned because its fixture sat **2.8× under** the limit. **Deleting the cap must turn this RED** | **HIGH** |
| **TC-397** | Escaping does not blow the document byte budget | Fill a report with worst-case escapable values (every char escapable → ~2× growth) and assert the `REPORT_MAX_TOTAL_BYTES` (`report_service.py:83` = 2 097 152) accounting still holds | Budget is computed on the **escaped** bytes, not the raw ones — otherwise the cap under-counts by up to 2× and the guarantee is void | **HIGH** |
| **TC-398** | Truncation happens **before** escaping | A value longer than the cap containing `|` at the boundary | Truncation never splits an escape pair (`\` orphaned at the end) — escaping only grows the string, so it must run last | MEDIUM |

**Total: 3 ATs + 23 TCs.**

---

## 5. Regression checklist

Reverse census of consumers (C-26) — every test file that calls
`generate_project_report`, all currently GREEN, all must stay GREEN or be
consciously re-baselined with a §6.5 before/after record:

- [ ] `tests/test_report_service.py` — the main golden set, incl.
      `test_report_omits_entropy_when_disabled_byte_identical:1051` and the
      AT-055b golden at `:1472`
- [ ] `tests/test_report_symbol_escape.py` — batch-39 contract (TC-393)
- [ ] `tests/test_report_filter.py` — the `filter_name` header path (TC-388)
- [ ] `tests/test_report_addendum.py` — `region.name` site (`:1445`)
- [ ] `tests/test_report_progress.py`
- [ ] `tests/test_tui_report_seam.py`, `tests/test_tui_report_view.py`
- [ ] `tests/test_flow_report_service.py` — **if** `_md_safe` is promoted/shared
- [ ] `tests/test_diff_report_service.py` — owns `_md_table_cell`, imported by
      `report_service.py:968`
- [ ] `tests/test_filename_markup_safety.py` — adjacent markup-safety contract
- [ ] Engine guards: `tests/test_engine_unchanged.py` **and**
      `tests/test_tui_directionb.py::test_tc031_*` — **run both** (C-27)
- [ ] Full suite `pytest -q`; the 19 `tc016s` snapshot baselines are current as
      of batch-61 (`4cac228`) so a snapshot failure this batch is **new**, not
      pre-existing

---

## 6. Testability blockers and open design questions

### 6.1 ⭐ BLOCKER — `_md_safe` cannot be reused verbatim (two independent reasons)

The PLAN's open design question ("reuse `_md_safe` or create new") has a
**measured** answer, and it is neither of the two options as stated:

1. **It fails the benign no-op requirement (TC-395).** `_MD_ESCAPE`
   (`flow_report_service.py:120`) contains `/`, `.`, `@` — the linkify triggers.
   That is correct for `flow_report_service`, whose fields are short labels.
   Applied to `report_service`, **every file path and every version string**
   acquires visible backslashes: `C:\proj\out.s19` → `C:\\proj\\out\.s19`. The
   report's dominant content is paths. This is a user-visible regression
   affecting the majority of benign rows, not an edge case.
2. **It is not context-free at the code-span site (F-3).** `report_service.py:901`
   wraps `saved_path` in backticks. Measured: `_md_safe` **removes** the
   backtick so the breakout is closed — but its backslash escapes are **inert
   inside a code span** and render literally. Inside a code span the *only*
   escaping needed is backtick handling; anything more is corruption. The
   docstring's "context-free" claim (AMD-5) does not survive contact with this
   site.

**Question for the architect (needs an explicit ruling, recorded):** does the
design (a) drop the backticks at `:901` and route it through the one general
escaper, or (b) ship a second, code-span-aware sanitiser? I recommend **(a)** —
one escaper, one grammar, one test battery; a second context multiplies the
payload matrix by two and is the kind of split that batch-60 showed goes stale.
If (b) is chosen, TC-377 and TC-383 must be parametrised over **both** contexts
and §3.3's G-3 floor doubles.

**Note on the linkify triggers:** whichever helper is built, `/`, `.`, `@`
**must** be escaped for US-062-2 (the exported file is read with linkify **ON**
— measured `evil.com` → `http://evil.com`). So the benign-no-op requirement
(TC-395) and the US-062-2 requirement are in **direct tension**. This tension
is real, is not resolvable by escaping alone, and Phase 2 must rule on it
explicitly. Options: escape `.`/`@`/`/` and accept path noise; or wrap
path-shaped fields in code spans (inert without backslashes — measured:
`` `a\|b\*c\*` `` stays one `code_inline`) and escape only backticks there.
**The second option satisfies both** and is worth costing.

### 6.2 Non-blocking, recorded

- **`filter_name` (`:729`) is a half-fix.** `_strip_ctl_local` (`:512`) covers
  control chars only. It must be superseded, not layered (TC-388).
- **`_md_table_cell` is imported lazily** (`report_service.py:968`, with a
  circular-import comment). If the new helper lives in `report_service`, that
  import may become removable — a diff-shrinking opportunity, not a requirement.
- **Reference-link composition needs two fields** (payload #21). It is
  currently inert *only because* no field reaches column 0. TC-380 pins the
  control that keeps it that way; it is not independently safe.

### 6.3 What I could not determine and did **not** invent

- Whether `sanitize_project_name` constrains `project_name` upstream. The probe
  shows raw markup **does** reach the report, so the AT counterfactual stands
  regardless — but if a Phase-2 decision leans on an upstream sanitiser, that
  claim needs its own execution probe. I have not asserted either way.

---

## 7. Probe transcripts (evidence)

Scripts: `…/scratchpad/probe_grammar.py`, `probe_generator.py`, `probe3.py`.
Environment: `markdown_it 4.2.0`, Python 3.14, tree at `8d3c504`.

```
### A) BENIGN baseline
  viewer  active tokens: ['bullet_list_open', 'heading_open', 'strong_open']
  default active tokens: ['bullet_list_open', 'heading_open', 'strong_open']

### B) HOSTILE project_name
  viewer NEW vs benign : ['link_open', 's_open']
   | # Project report: proj ~~REVOKED~~ **fake** [c](http://evil.tld)

### (a) POSITIONAL CELL CORRUPTION — inventory table (4 cols)
  benign : ['BENIGN', 'a.s19', 's19', 'yes']
  hostile: ['EVIL', 'INJECTED', 'COL', 'a.s19']        <-- F-1

### (b) NEWLINE REACHES COLUMN 0 (today, raw)
  project_name='p\n\n---\n'   new=['hr']
  project_name='p [c][r]\n\n[r]: http://evil.tld\n'  links=['http://evil.tld', …]

### (c) FUZZY LINKIFY, real TLDs (variant_id site)
  www-real   'www.evil.com'  default=['http://www.evil.com' x3]        viewer=[]
  tld-real   'evil.com'      default=['http://evil.com' x3]            viewer=[]
  email-real 'user@evil.com' default=['mailto:user@evil.com' x3]       viewer=[]
  idn        'www.рф.рф'     default=['http://www.xn--p1ai.xn--p1ai']  viewer=[]
  protorel   '//evil.com/x'  default=['//evil.com/x' x3]               viewer=[]
  ftp/mailto/http                    all three fire
  tld-fake   'evil.tld'      default=[]   <-- F-4 VACUOUS
  ip         '10.1.2.3'      default=[]   <-- fuzzy_ip=False, negative control

### (d) HTML through the EXPORTED file
  default: ['html_inline' x3]   viewer: []

### (F-3) code-span site
  backtick-breakout  `a` **PWNED** `b`  -> [code_inline, strong_open, code_inline]
  _md_safe applied   -> [code_inline 'a \\*\\*PWNED\\*\\* b']   (safe, but noisy)

### derived oracles
  linkify schemas: ['//', 'ftp:', 'http:', 'https:', 'mailto:']
  linkify opts   : {'fuzzy_link': True, 'fuzzy_email': True, 'fuzzy_ip': False}
```

---

## 8. Target and forbidden test files (C-27)

**Frozen — new tests MUST NOT be added to these** (`_ENGINE_TEST_FILES`,
`tests/test_tui_directionb.py:5458`):

`tests/test_core_srecord_validation.py` · `tests/test_hexfile.py` ·
`tests/test_range_index.py` · `tests/test_validation_a2l.py` ·
`tests/test_validation_engine.py` · `tests/test_validation_mac.py` ·
`tests/test_tui_a2l.py` · `tests/test_tui_mac.py` ·
`tests/test_color_policy_round_trip.py`

Also off-limits (engine-frozen source): `core.py`, `hexfile.py`,
`range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`,
`tui/color_policy.py`.

**Target — new (not frozen, and no existing file is a natural home for a
30-payload battery):**

| File | Contents |
|---|---|
| `tests/test_report_markup_safety.py` | **new** — AT-157/158/159, TC-376…382, TC-390…392, TC-394…398, plus the derived payload set and `assert_field_inert` |
| `tests/test_report_field_census.py` | **new** — TC-383/384/385/386/387/388/389 (the per-site sweep; separate file because it is the C-26 census and should be readable as one list) |

**Existing, extended (not rewritten):** `tests/test_report_symbol_escape.py` —
TC-393 only, and only if the new helper changes its output (then with a §6.5
before/after record).

Both target files are new, so neither collides with a frozen path and neither
risks a spurious engine-guard trip.

---

## 9. Evidence checklist

- [x] **Acceptance criteria use Given/When/Then** — §2, AT-157/158/159.
- [x] **Test cases have explicit Expected, not vague "works"** — §4; every
      Expected is a token-stream predicate or a byte-identity claim.
- [x] **Edge cases include empty, boundary, invalid, error** — TC-381 (empty/
      null/whitespace), TC-382 (unicode/10k boundary), TC-396 (`N`/`N+1`/`10N`),
      TC-379 (control chars), TC-398 (truncation boundary).
- [x] **Regression checklist exists** — §5, 11 items, derived by reverse census
      of `generate_project_report` consumers, not guessed.
- [x] **Exit criteria stated** — §10.
- [x] **No real PII / secrets** — all fixtures synthetic; domains are
      `evil.com` / `evil.tld`; paths are `tmp_path`-relative. No operator
      firmware, no real project name.
- [x] **Test results section left blank** — no TC has been run; the only
      executed artefacts are the Phase-0/1 **probes** in §7, whose outputs are
      quoted verbatim and labelled as measurements of the **current** tree.
- [x] **Layer B (black-box)** — AT-157/158/159 all drive
      `generate_project_report` (the shipped entry) and observe the
      artifact-on-disk through a real parser. Boundary evidence: TC-396/398.
      Negative evidence: G-5 negative controls, TC-394/395 benign no-op.
- [x] **Bidirectional surface-reachability** — every named input dimension
      (§1.2's 15 field sites, swept by TC-383/384) **and** every named output
      (the viewer render S-A, the exported file S-B, table cells S-C) is
      exercised through the handler, never through a helper called directly.
- [x] **No unfilled template** — no `<…>`, no `TC-NNN`; all 3 ATs and 23 TCs
      are concrete and numbered from the repo's live maxima (`AT-156`,
      `TC-375`).
- [x] **Payload set derived, not hand-listed** — §3.1 derivation + §3.3 G-1…G-5.
- [x] **Per-metacharacter, not collapsed** — TC-377 parametrises over all 31
      payloads individually.
- [x] **Caps pinned** — TC-396/397/398.

---

## 10. Exit criteria

1. AT-157, AT-158, AT-159 each demonstrated **RED at `8d3c504`** before the fix
   and **GREEN** after — the RED run captured in the increment packet.
2. All HIGH TCs pass: TC-376, 377, 379, 380, 381, 383, 384, 385, 386, 387, 390,
   391, 393, 394, 395, 396, 397.
3. TC-394 (benign byte-identity) passes, **or** every golden it moves has a
   §6.5 before/after record and an explicit ruling.
4. The §5 regression checklist is fully ticked; `pytest -q` shows **0** new
   failures against the batch-61 baseline; **both** engine guards run.
5. §6.1 has a recorded architect ruling in the PLAN decision log.
6. Final `qa-reviewer` **and** `security-reviewer` passes over the whole diff
   vs `main` return **0 HIGH**.
