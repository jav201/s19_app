# 01 — Requirements (architect derivation) · batch-62 · `report_service` markdown escaping

> ⚠ **PARTIALLY SUPERSEDED (2026-07-25, Phase-1 fold iteration 1).** This artifact is preserved as
> the derivation record. Where it collides with `01-requirements.md`, the canonical registry rules,
> and **`01-requirements.md` §6.5 records every change with Before/After.** Superseded here:
> the closed 7-type live-token enumeration (A-01), the bare `TC-376…387` ids (A-02), the "benign
> no-op arm still holds" claim (A-03), the 2-line golden drift prediction (A-04), `HLR-095…099`'s
> wording (A-05…A-09), `LLR-095.1/.2`, `LLR-097.1/.2`, `LLR-098.1/.2/.3` (A-12…A-18), the
> `:974-976` anchor (A-33) and the `US-062-*` spelling — **a C-26 census must grep `US-B62-`**.

- **Batch:** `2026-07-25-batch-62` · **Branch:** `claude/batch-62-report-escaping` @ `8d3c504`
- **Author role:** Phase-1 architect · **Artifact language:** English
- **Method:** IEEE 830 + EARS. Every anchor below is `file:line` verified on disk at draft time;
  every design claim is backed by an **executed probe** (C-35), not analogy.
- **Probe script (re-runnable):**
  `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-OneDrive-Documents-Github-s19-app--claude-worktrees-upbeat-khorana-997280\dee40864-ca78-4cbc-b64b-c028cc6a2c2d\scratchpad\probe62.py`
  (run with `PYTHONPATH=<repo root>`; `markdown_it` 4.2.0)

---

## §0 BLUF

**The escaper must be PROMOTED to a new leaf module, not imported and not forked** — because
`flow_report_service.py:63` already imports *from* `report_service`, so a top-level import of
`_md_safe` back into `report_service` is a **hard circular import**. Ruling: **(b) promote**.

**Two escaping modes are required, not one.** `_md_safe` already covers `|` (correct
backslash-first order), so table-shape and grammar escaping are **one pass, not a composition** —
composing it with `diff_report_service._md_table_cell` **double-escapes** (measured). But
`_md_safe` is **byte-destructive on paths** (`C:/x/a.s19` → `C:\/x\/a\.s19`), which (i) renders a
visibly corrupted path and (ii) **breaks the golden canonicaliser** at `tests/conftest.py:1009-1016`,
which substitutes the *raw* run-root string. Path-valued fields therefore take a **code-span mode**
(backtick-strip + wrap), proven inert in both grammars including linkify.

**C-24 is NOT zero-drift.** `tests/goldens/batch35/at055b-project-report.md` **will drift by exactly
2 lines**. Predicted, bounded, and stated as a Phase-3 threshold.

---

## §1 Restated problem

`generate_project_report` composes a Markdown document from values read out of operator-supplied
files (project manifest, change docs, check docs, A2L/MAC symbols, image bytes, filter files) and
writes it to `<project_dir>/reports/<UTC>-report.md`
(`s19_app/tui/services/report_service.py:1473`, write at `:1613`).

That document is consumed twice, by **two different Markdown grammars**:

1. **In-app viewer** — `ReportViewerScreen`, parser built at `s19_app/tui/screens.py:112`:
   `MarkdownIt("gfm-like", {"linkify": False, "html": False})`.
2. **The exported file** — once the `.md` leaves `.s19tool/`, whatever the reader opens it with.
   The conservative model is a **default** `gfm-like` parser (**linkify ON, html ON**).

The composer performs **no grammar-level escaping**. Its only sanitiser is `_strip_ctl_local`
(`report_service.py:512`), which strips control characters from **one** field, and its own docstring
concedes the gap (`report_service.py:516-519`): *"this module performs no escaping on its existing
lines and none is added; ONLY the new filter-derived audit-header text passes through here"*.

The problem is therefore: **make every file-derived value inert in both grammars, without
destroying the report's readability, its column shape, or its byte-identity goldens.**

---

## §2 Constraints (stated explicitly — architect hard rule)

| # | Constraint | Source (verified) |
|---|-----------|-------------------|
| CN-1 | **Two grammars, one artifact.** Viewer has linkify OFF; the exported file must be assumed linkify ON + html ON. A single file must satisfy the stricter of the two. | `screens.py:112`; probe P2/P3 |
| CN-2 | **Frozen set excludes all three report services.** `_ENGINE_PATHS` = `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` (+ `tui/color_policy.py` in the second guard). | `tests/test_engine_unchanged.py:120-130`; `tests/test_tui_directionb.py:5443-5454` |
| CN-3 | **`s19_app/validation/` IS frozen** → `ValidationIssue` cannot be changed; escaping must happen at the report composer, never at the model. | `tests/test_engine_unchanged.py:124` |
| CN-4 | **Import direction is fixed.** `flow_report_service.py:63` → `from .report_service import (...)`. Also `diff_report_service.py:97` → `from .report_service import (...)`. `report_service` is the **base** of the service import DAG. | grep, verified |
| CN-5 | **Byte-identity goldens exist** and are asserted: `tests/goldens/batch35/at055b-project-report.md` via `tests/test_tui_report_seam.py:1237`; plus the no-filter byte-identity pin `tests/test_report_service.py:1487-1489` (TC-314) and `tests/test_tui_report_filter_surface.py:85`. | verified |
| CN-6 | **The golden canonicaliser rewrites RAW path bytes.** `canonical_report_bytes` (`tests/conftest.py:970`, body `:1009-1016`) replaces `str(run_root)` verbatim, then normalises `\`→`/` **only inside run-root spans**. Escaping a path *before* it reaches the file defeats this substitution. | verified |
| CN-7 | **Confidentiality.** Reports carry raw memory bytes; the module performs **no logging at all** (F-S-07, `report_service.py:32-38`). Any new helper must not log and must not widen the artifact's reach. | verified |
| CN-8 | **No new runtime dependency.** `markdown_it` is already a dependency (viewer); the escaper stays pure-stdlib. | verified |

No constraint is missing, so the architect failure-mode ("stop and ask") does not fire.

---

## §3 Verified anchors (draft-time, `file:line`)

| Anchor | Location | Fact |
|--------|----------|------|
| A-1 | `s19_app/tui/services/report_service.py:1473` | `generate_project_report` — the composer under change |
| A-2 | `s19_app/tui/services/report_service.py:1613` | `target.write_text("\n".join(lines), encoding="utf-8")` — the single sink |
| A-3 | `s19_app/tui/services/report_service.py:512-538` | `_strip_ctl_local` — ctl-strip only, one field |
| A-4 | `s19_app/tui/services/report_service.py:974-976` | deferred `from .diff_report_service import _md_table_cell` — the module's own comment names it a circular-import workaround |
| A-5 | `s19_app/tui/services/diff_report_service.py:282` | `_md_table_cell` — ctl-strip + `\`-double + `\|`; **table shape, not grammar** |
| A-6 | `s19_app/tui/services/flow_report_service.py:120` | `_MD_ESCAPE = ("\\", "|", "*", "_", "[", "]", "<", ">", "#", "~", "/", ".", "@")` |
| A-7 | `s19_app/tui/services/flow_report_service.py:135` | `_md_safe(value, limit=MAX_REPORT_CELL_CHARS)` — batch-60's grammar-true escaper |
| A-8 | `s19_app/tui/services/flow_report_service.py:78,85` | `MAX_REPORT_CELL_CHARS = 240`; `_TRUNCATION_MARKER = "… (truncated)"` |
| A-9 | `s19_app/tui/services/flow_report_service.py:63` | `from .report_service import (...)` → **cycle blocker** |
| A-10 | `s19_app/tui/screens.py:112` | viewer parser `linkify=False, html=False` |
| A-11 | `s19_app/tui/hexview.py:355-356` | ASCII gutter emits `chr(b)` for `32 ≤ b ≤ 126` — **includes `` ` `` (0x60)** |
| A-12 | `s19_app/validation/model.py:137` | `ValidationIssue.__post_init__` → `_scrub_issue_message` (ctl/ANSI + cap, **no grammar escape**) |
| A-13 | `s19_app/tui/services/report_addendum.py:37,40-41` | `DeclaredRegion.name` scrubbed + capped (**no grammar escape**) |
| A-14 | `s19_app/tui/services/report_service.py:213` | `ReportOptions.__post_init__` validates `execution_mode` / `assignment_source` against closed domains → those two are **trusted** |
| A-15 | `tests/conftest.py:1009-1016` | golden canonicaliser body (raw run-root substitution) |

---

## §4 Executed probes (the evidence base)

### P-1 — Does `_md_safe` already cover the table-shape character `|`?
```
_MD_ESCAPE = ('\\', '|', '*', '_', '[', ']', '<', '>', '#', '~', '/', '.', '@')
'|' in set: True   index: 1    backslash index: 0
_md_safe('a|b')        -> 'a\|b'
_md_table_cell('a\|b') -> 'a\\\|b'
_md_safe('a\|b')       -> 'a\\\|b'          # identical to _md_table_cell
```
**YES.** `|` is escaped, and `\` is escaped **first** — which is precisely the correctness property
`_md_table_cell`'s docstring (`diff_report_service.py:288-292`) was created to guarantee.
`_md_safe` is a strict superset of `_md_table_cell` on that axis.

### P-2/P-3 — Token stream, RAW vs `_md_safe`, in a table cell AND a heading, in BOTH grammars
Live-token set = `{s_open, strong_open, em_open, link_open, html_inline, html_block, code_inline}`.

| Input | viewer RAW | default RAW | viewer SAFE | default SAFE |
|---|---|---|---|---|
| `~~REVOKED~~` | `s_open` | `s_open` | `[]` | `[]` |
| `**fake**` | `strong_open` | `strong_open` | `[]` | `[]` |
| `_em_` | `em_open` | `em_open` | `[]` | `[]` |
| `[click](http://evil.tld)` | `link_open` | `link_open` | `[]` | `[]` |
| `http://evil.tld/x` | `[]` | **`link_open`** | `[]` | `[]` |
| `//evil.tld/x` | `[]` | **`link_open`** | `[]` | `[]` |
| `<b>bold</b>` | `[]` | **`html_inline`×2** | `[]` | `[]` |
| `<script>x</script>` | `[]` | **`html_inline`×2** | `[]` | `[]` |
| `` `code` `` | `code_inline` | `code_inline` | `[]` | `[]` |

**Conclusions.** (i) `_md_safe` is **complete** against both grammars in both contexts — every SAFE
column is `[]`. (ii) The viewer and the exported file have **different minimum escape sets**:
`/ . @` matter only for the exported file (linkify), `< >` only for the exported file (html).
Because one artifact serves both consumers, the **union** (i.e. the full `_MD_ESCAPE`) is the
requirement. This is the load-bearing reason US-062-2 forces golden drift.

### P-4 — Byte-level no-op check on the values actually present in the AT-055b golden
```
NO-OP  variant_set.project_name   'proj'                  -> 'proj'
NO-OP  descriptor.variant_id      'a'                     -> 'a'
DRIFT  descriptor.path.name       'a.s19'                 -> 'a\.s19'
NO-OP  descriptor.file_type       's19'                   -> 's19'
NO-OP  result.status              'ok'                    -> 'ok'
NO-OP  entry.linkage              'standalone'            -> 'standalone'
DRIFT  summary.source_path        'C:/x/.s19tool/.../chg.json'
                                  -> 'C:\/x\/\.s19tool\/...\/chg\.json'
DRIFT  summary.saved_path         (same shape)
DRIFT  check.source_path          'checks.json'           -> 'checks\.json'
NO-OP  entry.result               'passed'                -> 'passed'
DRIFT  issue.code                 'CROSS_MAC_S19_OUT_OF_RANGE'
                                  -> 'CROSS\_MAC\_S19\_OUT\_OF\_RANGE'
NO-OP  region.name                'bootloader'            -> 'bootloader'
DRIFTING FIELDS: 5/12
```
**`_md_safe` is NOT a byte-level no-op on benign values.** `.`, `/`, `_`, `@` are ubiquitous in
filenames, paths and issue codes. Full-`_md_safe`-everywhere is therefore **incompatible with a
zero-drift claim** — the mitigation is §7's mode split plus a bounded, re-captured golden.

### P-5 — Column shape (US-062-3), measured on the **rendered cell contents**
3-column table, cell value `v1|INJECTED|COL`:
```
rendered cells -> ['1', 'v1', 'INJECTED']      # 'COL' DROPPED, real value TRUNCATED to 'v1'
```
GFM truncates a row to the header's column count, so the failure is **content displacement and
silent data loss**, not merely "extra columns". With `_md_safe`: `td_open` count = 2 (benign) and the
value round-trips whole. This is the correct oracle for US-062-3 — assert **cell contents**, not
`td_open` count alone (`td_open` is 2 in *both* the raw and escaped 2-column case; a count-only
assertion is a C-31 false-confidence test).

### P-5b — Composition: `_md_table_cell(_md_safe(x))` vs `_md_safe(x)`
```
'a|b'   -> _md_safe='a\|b'     composed='a\\\|b'      (DOUBLE-ESCAPED)
'sym\x' -> _md_safe='sym\\x'   composed='sym\\\\x'    (DOUBLE-ESCAPED)
```
**Do not compose.** The composed form renders a *visible literal backslash* to the operator.

### P-6 — Idempotence
```
'a.s19' once='a\.s19'  twice='a\\\.s19'   idempotent=False
'plain' once='plain'   twice='plain'      idempotent=True
'a|b'   once='a\|b'    twice='a\\\|b'     idempotent=False
```
**`_md_safe` is NOT idempotent.** It is a no-op only on values free of the escape set. The design
must guarantee **exactly one application per value** — double application is a defect class the
Phase-3 tests must cover.

### P-7 — Escaping *inside* a backtick code span (`report_service.py:901`)
```
raw       - saved as `C:/x/a-patched.s19`  -> <code>C:/x/a-patched.s19</code>
_md_safe  - saved as `C:\/x\/a-patched\.s19` -> <code>C:\/x\/a-patched\.s19</code>
```
**Escaping inside a code span is HARMFUL** — backslashes are literal inside `<code>`, so the operator
is shown a corrupted path.

### P-8 — But a raw code span is escapable from inside
```
- saved as `x` **live** `y`  -> ['code_inline', 'strong_open', 'code_inline']
```
A value containing a backtick **breaks out** of the span (backtick is a legal NTFS filename
character). `_md_safe`'s backtick-**removal** step (`flow_report_service.py:172`) closes this.

### P-9 — Code-span containment as a mode (ctl-strip + backtick-remove + wrap, **no** escaping)
```
'http://evil.tld/x'          -> default=[]  viewer=[]
'**fake**' '~~x~~' '[t](..)' -> default=[]  viewer=[]
'<b>y</b>' '<script>..'      -> default=[]  viewer=[]
'//evil.tld'                 -> default=[]  viewer=[]
'x` **live** `y'             -> 'x **live** y' -> default=[] viewer=[]
```
**Code-span mode is fully inert in both grammars, including linkify**, and leaves the value's bytes
**raw** (so CN-6's canonicaliser keeps working).
**Limit measured:** a raw `|` inside a code span **still splits a table cell** (`td_open`=2 with the
extra content dropped) → **code-span mode is not admissible inside a table cell.**

### P-10 — Can the hexdump fence be broken out of? (A-11: the gutter emits raw backticks)
An image of all-`0x60` bytes renders `|````````````````|` inside the ```` ```text ```` fence.
```
default fence tokens: ['paragraph_open','inline','paragraph_close','fence']   fence count: 1
viewer  fence tokens: ['paragraph_open','inline','paragraph_close','fence']   fence count: 1
first char of each rendered line: ['0x', '0x']
```
**NO.** Every gutter line begins with the `0x%08X` address prefix (`hexview.py:356`), so no line can
ever start with a fence-closing backtick run. The hexdump section is **inert by construction**, and
escaping it would corrupt the byte-exact dump. **Explicitly out of scope — with a regression test.**

### P-11 — Linkify edge cases (why `.` escaping is over-broad but retained)
```
'a.s19'   -> no link       'chg.json' -> no link       'foo.com' -> link_open
```
A filename whose extension happens to be a real TLD **does** linkify. Discriminating would require
a TLD table — i.e. re-implementing a parser inside a sanitiser, the exact anti-pattern batch-60
recorded ("name the parser a sanitiser defends against"). **Retain the blanket `.` escape.**

---

## §5 File-derived field inventory (exhaustive grep of `report_service.py`)

Derived by grepping every interpolation site in the module, **not** from the kickoff examples
(C-31: the field set is itself an oracle). `Ctx` = the Markdown context the value lands in.

| ID | Field | file:line | Value provenance | Ctx | Sanitised today | Verdict |
|----|-------|-----------|------------------|-----|-----------------|---------|
| F-01 | `variant_set.project_name` | `:769` | project manifest / work-area dir name | **H1 heading** | none | **Mode A** |
| F-02 | `variant_set.project_name` | `:771` | same | bullet | none | **Mode A** |
| F-03 | `generated_at.isoformat()` | `:772` | tool clock | bullet | n/a | trusted |
| F-04 | `__version__` | `:773` | package metadata | bullet | n/a | trusted |
| F-05 | `options.context_bytes` | `:774` | validated `int` | bullet | n/a | trusted |
| F-06 | `options.execution_mode` | `:775` | closed domain, `:213` | bullet | domain-validated | trusted (A-14) |
| F-07 | `options.assignment_source` | `:776` | closed domain, `:213` | bullet | domain-validated | trusted (A-14) |
| F-08 | `descriptor.variant_id` | `:807` | project manifest | **table cell** | none | **Mode A** |
| F-09 | `descriptor.path.name` | `:807` | filesystem basename | **table cell** | none | **Mode A** |
| F-10 | `descriptor.file_type` | `:808` | manifest / sniffed | **table cell** | none | **Mode A** |
| F-11 | `result.variant_id` | `:862` | project manifest | **table cell** | none | **Mode A** |
| F-12 | `result.status` | `:862` | execution-layer token | **table cell** | none | **Mode A** (uniform; cheap) |
| F-13 | `str(summary.source_path)` | `:892` → emitted `:897` | change-doc path (operator) | bullet | none | **Mode B** (CN-6) |
| F-14 | `summary.saved_path` | `:901` | written-image path | **already in backticks** | none | **Mode B** |
| F-15 | `entry.linkage` | `:987` | change-doc linkage token | **table cell** | none | **Mode A** |
| F-16 | `entry.linkage_symbol` | `:978` | A2L / MAC symbol | **table cell** | `_md_table_cell` (shape only) | **Mode A** — replaces `_md_table_cell` |
| F-17 | `_format_bytes(before/after)` | `:985-986` | image bytes | table cell | inert by construction (`:391-410`, hex digits + space only) | out of scope, pin with a test |
| F-18 | `issue.code` | `:1026` | validation code constant | bullet | none | **Mode A** |
| F-19 | `issue.severity.value` | `:1026` | enum | bullet | n/a | trusted |
| F-20 | `issue.message` | `:1026` | **parsed file text** — highest-risk field | bullet | ctl/ANSI scrub only (A-12) | **Mode A** |
| F-21 | `issue.symbol` | `:1030` | A2L / MAC symbol | bullet | none | **Mode A** |
| F-22 | `",".join(issue.related_artifacts)` | `:1032` | artifact names | bullet | none | **Mode A per element**, join after |
| F-23 | `str(check.source_path)` | `:1091` → emitted `:1097` | check-doc path | **H4 heading** | none | **Mode B** (CN-6) |
| F-24 | `entry.result` | `:1117` | check-result token | **table cell** | none | **Mode A** |
| F-25 | `result.variant_id` | `:1280`, `:1297` | manifest | truncation note → bullet `:1608` | none | **Mode A** |
| F-26 | `region.name` | `:1445` | operator-declared region | **H3 heading** | ctl/ANSI scrub + cap (A-13) | **Mode A** |
| F-27 | `issue.code` | `:1458`, `:1465` | validation code | bullet | none | **Mode A** |
| F-28 | `result.variant_id` | `:1453`, `:1459`, `:1466` | manifest | bullet | none | **Mode A** |
| F-29 | `_filter_display_name(...)` | `:729` (via `:563`) | **filter FILE NAME** | bullet | `_strip_ctl_local` only | **Mode A** — supersedes `_strip_ctl_local` |
| F-30 | `result.variant_id` | `:1593` | manifest | **H2 heading** | none | **Mode A** |
| F-31 | `render_hex_view(...)` gutter | `:1197-1200` | **image bytes**, incl. `` ` `` (A-11) | **fenced block** | none | **out of scope — proven inert (P-10)**, pin with a test |
| F-32 | `LEGEND_TABLE` rows | `:1330-1334` | static module constant | heading/bullet | n/a | trusted static |
| F-33 | `ENTROPY_BANDS` labels | `:1396` | static module constant | bullet | n/a | trusted static |

**Counts:** 33 emission sites · **24 require escaping** (21 Mode A + 3 Mode B) · 7 trusted ·
2 out-of-scope-but-pinned (F-17, F-31).

**Uniformity note (simple > clever).** F-06/F-07/F-12/F-15/F-19/F-24 are token-domain values that
*today* cannot carry metacharacters. F-06/F-07/F-19 are enforced by an explicit validator (A-14) and
stay trusted. F-12/F-15/F-24 are **not** validator-enforced at the report boundary, so they take
Mode A — a value-independent rule at the sink is cheaper to audit than a per-field trust argument,
and `_md_safe` is a proven no-op on their current benign values (P-4: `ok`, `standalone`, `passed`).

---

## §6 User stories (operator-approved at Phase 0) and their black-box evaluability

| US | Statement | Status |
|----|-----------|--------|
| **US-062-1** | As an operator reading a project report **in the app**, I want file-derived text to render literally, so a hostile filename cannot forge report structure in front of me. | READY |
| **US-062-2** | As an operator **sharing the exported `.md`**, I want it to carry no live constructs under a default `gfm-like` parser (linkify + html ON), so the file is safe once it leaves the app. | READY |
| **US-062-3** | As an operator reading a report table, I want rows to keep their column shape and their values whole regardless of file-derived content. | READY |

**Evaluability (black-box, at the shipped surface):**
- US-062-1 → *"Generate a report from a project whose every file-derived field carries a hostile
  payload; parse the written file with the **viewer's own** parser factory. The live-token set
  originating from file-derived text is empty."* → **AT-157**.
- US-062-2 → *"Parse the same written file with a **default** `MarkdownIt("gfm-like")`. The live-token
  set originating from file-derived text is empty."* → **AT-158**.
- US-062-3 → *"With `variant_id = "v1|INJECTED|COL"`, the rendered Variant-inventory row yields
  exactly the header's column count AND the first cell's text equals `v1|INJECTED|COL` verbatim."*
  → **AT-159**.
- Readability rider → *"A benign report is byte-identical to the re-captured golden, and every
  benign field is human-readable."* → **AT-160**.
- Out-of-scope pins → **AT-161** (hexdump fence unbreakable), **AT-162** (path fields readable +
  run-root canonicalisation still fires).

> **⚠ ID-collision hazard (flag).** `US-062` **already exists** in `REQUIREMENTS.md:3749` (batch-37,
> a different feature). The batch-scoped `US-062-N` spelling disambiguates on paper but a C-26
> reverse-census grep for `US-062` will hit both. **Recommendation:** rename this batch's stories to
> `US-B62-1/2/3` before Phase 2, or add an explicit disambiguation row to `REQUIREMENTS.md`.
> Architect call: rename. `assumed — confirm with operator in Phase 2.`

---

## §7 THE DESIGN RULING

### §7.1 Ruling 1 — **Where the shared escaper lives: (b) PROMOTE.**

**Decision:** create a new **leaf** module `s19_app/tui/services/markdown_safety.py` exporting
`md_safe()` (Mode A) and `md_code()` (Mode B). It imports **nothing** from the services package.
`flow_report_service`, `report_service`, and (optionally, later) `diff_report_service` import from it.

**Probe-backed rationale — why not (a) import `flow_report_service._md_safe`:**

```
s19_app/tui/services/flow_report_service.py:63 →  from .report_service import (...)
s19_app/tui/services/diff_report_service.py:97 →  from .report_service import (...)
```
`report_service` is the **base** of the service import DAG. A top-level
`from .flow_report_service import _md_safe` inside `report_service` is a **hard import cycle**.
The only way to make (a) work is a *second* deferred in-function import — and the file already
carries one, with its own comment naming it a workaround (`report_service.py:974-976`):
> *"``diff_report_service`` imports from this module at load time, so a top-level import of
> ``_md_table_cell`` would be a circular import — resolve it lazily here"*

Adding a second instance of a pattern the codebase already documents as a wart, to import a
**private** symbol across a service boundary, fails both "simple > clever" and "reversibility".

**Why not (c) fork a third escaper:** the tree already carries **five** escaper-ish helpers across
three modules — `diff_report_service._strip_ctl`, `._md_cell`, `._md_table_cell`,
`report_service._strip_ctl_local`, `flow_report_service._md_safe`. Batch-60's "create new" ruling
was correct **then** because `_md_cell` targeted a different, un-audited sink. That reasoning **does
not transfer**: batch-62's sink is the *same* viewer parser and the *same* exported-file grammar that
`_md_safe` was written against (P-2/P-3 show it is complete for both). Forking would create a sixth
helper with an identical contract and a guaranteed divergence surface.

**Why promotion is safe:** `report_service.py`, `flow_report_service.py`, and
`diff_report_service.py` are **all outside** both frozen guards (CN-2). Verified.

**Blast radius / reversibility:** the promotion is a **move + re-export**, not a rewrite.
`flow_report_service` keeps `_md_safe = md_safe` (module-level alias) so batch-60's tests
(`tests/test_flow_report_service.py:40,232,271-272,414`) and the `screens.py:97` docstring reference
remain valid with **zero flow-report behaviour change**. Fully reversible; **not** a one-way door.

**Deliberately deferred (reversible):** `diff_report_service._md_cell` / `._md_table_cell` are
**not** migrated in this batch. They belong to the before/after report, which has its **own**
byte-identity golden (`at054b-before-after-report.{md,html}`, `tests/test_before_after_report.py:707,827`)
and its own un-audited HTML sink. Migrating them would double the golden churn and mix two
audits. **Carry it forward as an explicit backlog item.**

### §7.2 Ruling 2 — **Composition: single pass, TWO modes, never chained.**

**(a) Table-shape and grammar escaping are ONE pass, not a composition.** `_md_safe`'s `_MD_ESCAPE`
already contains `|` at index 1 with `\` at index 0 (P-1) — the exact ordering property
`_md_table_cell` exists to provide (A-5). Chaining them **double-escapes** (P-5b:
`a|b` → `a\\\|b`), showing the operator a literal backslash.

> **Consequence:** the `_md_table_cell` call at `report_service.py:978` and its deferred import at
> `:974-976` are **REMOVED**, replaced by `md_safe`. This also deletes the module's circular-import
> wart. `tests/test_report_symbol_escape.py` asserts on `_md_table_cell` output shape and **must be
> updated** (its benign-no-op arm still holds; its hostile arm's expected string changes).

**(b) Two modes are required, because `_md_safe` is byte-destructive on paths.**

| Mode | Definition | Applies to | Proof |
|------|-----------|-----------|-------|
| **A — `md_safe(v, limit=…)`** | batch-60's `_md_safe` verbatim: ctl-strip → newline/tab collapse → **remove** backticks → truncate → escape `\ \| * _ [ ] < > # ~ / . @` (backslash first) | every non-path file-derived field (21 sites) | P-2/P-3: all-`[]` in both grammars, cell + heading |
| **B — `md_code(v, limit=…)` + caller wraps in `` ` ``** | ctl-strip → newline/tab collapse → **remove** backticks → truncate. **No escaping.** | the 3 **path** fields F-13, F-14, F-23 | P-9: all-`[]` in both grammars incl. linkify; P-8: backtick removal closes the break-out |

**Why paths need Mode B — two independent reasons, both measured:**
1. **Readability (P-7):** backslashes are literal inside `<code>`; escaping renders
   `C:\/x\/a-patched\.s19` to the operator. A report whose paths are unusable defeats its purpose.
2. **Golden canonicalisation (CN-6):** `canonical_report_bytes` (`tests/conftest.py:1009-1016`)
   substitutes the **raw** `str(run_root)`. Escaping a path before it reaches the file makes that
   substitution miss, so the operator's absolute run-root path leaks into the compared bytes and the
   golden becomes machine-dependent. Mode B keeps path bytes **raw**, so the canonicaliser keeps working.

**Mode B's measured limit (P-9):** a raw `|` inside a code span **still splits a table cell**.
Therefore **Mode B is forbidden inside a table cell** — enforced as an LLR. No current path field is
in a table cell: F-09 (`descriptor.path.name`, `:807`) is a **basename**, never contains the run
root, and takes **Mode A**.

**(c) Exactly-once application (P-6).** `md_safe` is **not** idempotent. The LLRs place the call at
the **line-assembly site** for each field, and the Phase-3 suite must include a
double-application negative control.

### §7.3 Ruling 3 — **The hexdump fence and byte cells are OUT of scope, and pinned.**

`_format_bytes` (`:391-410`) emits only `[0-9A-F ]` or `-` — inert by construction. The hexdump
fence cannot be closed from inside because every gutter line starts with the `0x%08X` prefix
(P-10, `hexview.py:356`). Escaping either would corrupt byte-exact output. **Scope exclusion with a
regression test** (AT-161), not a silent omission.

---

## §8 High-level requirements (EARS)

> Modal discipline: **`shall` only.** No `should`/`may` appears in any normative statement below.
> (Rider: I flagged and rejected two draft phrasings containing `should`; none survive.)

### HLR-095 — Composer-side neutralisation (US-062-1, US-062-2)
**When** `generate_project_report` composes a report line containing a file-derived value, the
system **shall** render that value through the shared Markdown-safety helper appropriate to its
context, such that the written file yields **zero** live Markdown constructs originating from
file-derived text when parsed by **either** the viewer parser (`gfm-like`, linkify off, html off)
**or** a default `gfm-like` parser (linkify on, html on).

### HLR-096 — Column-shape and value integrity (US-062-3)
**When** a file-derived value is emitted into a Markdown table cell, the system **shall** emit it
such that the rendered row has exactly the column count declared by its header row **and** the
rendered cell text equals the input value verbatim after control-character removal.

### HLR-097 — Single shared, non-circular escaper (US-062-1, US-062-2 — maintainability)
The system **shall** define the Markdown-safety helpers in one module that imports no other service
module, and the project-report, flow-report, and viewer-hardening surfaces **shall** consume that
one definition; no report generator **shall** define its own grammar-escaping helper.

### HLR-098 — Readability and bounded golden drift (C-24)
The system **shall** keep every benign file-derived value human-readable in the rendered report —
in particular, filesystem paths **shall** render without inserted escape characters — and the
resulting byte drift against `tests/goldens/batch35/at055b-project-report.md` **shall** be confined
to the lines enumerated in LLR-098.1.

### HLR-099 — Scope exclusions pinned (anti-regression)
The system **shall** leave the fenced hexdump blocks and the hex byte cells byte-unmodified, and
**shall** carry a test proving a hostile image cannot terminate a hexdump fence.

---

## §9 Low-level requirements

> **C-26 declaration:** every LLR that changes a code symbol or shared surface names the touched
> symbol(s) explicitly, so the reverse census can grep them.

### LLR-095.1 — New leaf module `markdown_safety`
- **Statement:** The system **shall** provide `s19_app/tui/services/markdown_safety.py` exporting
  `md_safe(value: object, limit: int = MAX_REPORT_CELL_CHARS) -> str` and
  `md_code(value: object, limit: int = MAX_REPORT_CELL_CHARS) -> str`, plus the constants
  `MD_ESCAPE`, `MAX_REPORT_CELL_CHARS`, `TRUNCATION_MARKER`. The module **shall** import nothing
  from `s19_app.tui.services`.
- **Touched symbols (NEW):** `markdown_safety.md_safe`, `markdown_safety.md_code`,
  `markdown_safety.MD_ESCAPE`, `markdown_safety.MAX_REPORT_CELL_CHARS`,
  `markdown_safety.TRUNCATION_MARKER`.
- **Validation:** `test (unit)` · **Threshold:** `md_safe` output byte-equals the current
  `flow_report_service._md_safe` output on a ≥30-case corpus — **0** differences.

### LLR-095.2 — `flow_report_service` re-export, zero behaviour change
- **Statement:** `flow_report_service` **shall** import `md_safe`/`md_code` from `markdown_safety`
  and **shall** retain `_md_safe`, `MAX_REPORT_CELL_CHARS`, `_TRUNCATION_MARKER`, `_MD_ESCAPE` as
  aliases so existing importers and tests resolve unchanged.
- **Touched symbols (MOVED→ALIAS):** `flow_report_service._md_safe`, `._MD_ESCAPE`,
  `.MAX_REPORT_CELL_CHARS`, `._TRUNCATION_MARKER`.
- **Validation:** `test (regression)` · **Threshold:** the whole `tests/test_flow_report_*.py` set
  passes unmodified — **0** edits to those files, **0** failures.

### LLR-095.3 — Mode A applied at the 21 non-path sites
- **Statement:** Each of F-01, F-02, F-08, F-09, F-10, F-11, F-12, F-15, F-16, F-18, F-20, F-21,
  F-22 (per element, before `join`), F-24, F-25, F-26, F-27, F-28, F-29, F-30 **shall** pass through
  `md_safe` exactly once, at its line-assembly site.
- **Touched symbols (MODIFIED):** `report_service._header_lines`, `._inventory_lines`,
  `._overview_lines`, `._modifications_lines`, `._declaration_error_lines`, `._checklist_lines`,
  `._hexdump_section`, `._addendum_lines`, `._audit_header_lines`, `generate_project_report`.
- **Validation:** `test (integration)` + `test (static)` · **Threshold:** a hostile-everything
  fixture yields **0** live tokens under both parsers (AT-157/AT-158); a static census asserts
  **0** un-wrapped file-derived interpolations remain in the module.

### LLR-095.4 — `_strip_ctl_local` superseded
- **Statement:** `_audit_header_lines` **shall** render the filter display name through `md_safe`,
  and `_strip_ctl_local` **shall** be removed.
- **Touched symbols (REMOVED):** `report_service._strip_ctl_local`. **(MODIFIED):**
  `report_service._audit_header_lines`.
- **Validation:** `test (unit)` · **Threshold:** a filter filename containing `~~`, `**`, `|`, `[..](..)`
  yields **0** live tokens; **0** remaining references to `_strip_ctl_local` in the tree.

### LLR-096.1 — `_md_table_cell` call removed from `report_service`
- **Statement:** `_modifications_lines` **shall** render `entry.linkage_symbol` through `md_safe`,
  and the deferred `from .diff_report_service import _md_table_cell` **shall** be removed.
- **Touched symbols (MODIFIED):** `report_service._modifications_lines`. **(UNCHANGED, still used by
  `diff_report_service`):** `diff_report_service._md_table_cell`.
- **Validation:** `test (regression)` · **Threshold:** `tests/test_report_symbol_escape.py` updated
  to the `md_safe` expectation; its benign-no-op arm still passes unchanged; **0** deferred imports
  remain in `report_service.py`.

### LLR-096.2 — Column-shape and value-integrity oracle
- **Statement:** For every table-emitting section, a row whose file-derived cell contains `|`
  **shall** render with exactly the header's column count **and** that cell's rendered text
  **shall** equal the input verbatim.
- **Touched symbols:** none (test-only).
- **Validation:** `test (integration)` · **Threshold:** with `variant_id = "v1|INJECTED|COL"`,
  rendered cells == `['v1|INJECTED|COL', <file>, <type>, <active>]` — 4 cells, first cell verbatim.
  **C-31 rider:** the assertion **shall** read cell *contents*, not `td_open` count alone (P-5:
  the count is identical in the RAW and escaped 2-column cases).

### LLR-097.1 — Mode B for the three path fields
- **Statement:** F-13 (`summary.source_path`), F-14 (`summary.saved_path`) and F-23
  (`check.source_path`) **shall** pass through `md_code` and **shall** be emitted wrapped in a
  single-backtick code span. `md_code` **shall not** be used inside a Markdown table cell.
- **Touched symbols (MODIFIED):** `report_service._modified_files_lines`,
  `report_service._checklist_lines`.
- **Validation:** `test (integration)` · **Threshold:** a path containing a backtick, `|`, `**`, and
  `http://` yields **0** live tokens under both parsers; the rendered code-span text equals the
  input with backticks removed and nothing else changed.

### LLR-097.2 — `md_code` never reaches a table cell (static guard)
- **Statement:** A static test **shall** assert that no `md_code(` call site in `report_service.py`
  lies inside a line template containing a `|` column separator.
- **Touched symbols:** none (test-only).
- **Validation:** `test (static)` · **Threshold:** **0** violations.

### LLR-098.1 — Bounded golden re-capture (C-24)
- **Statement:** The re-captured `tests/goldens/batch35/at055b-project-report.md` **shall** differ
  from the current golden in **exactly two** lines:
  1. `| a | a.s19 | s19 | yes |` → `| a | a\.s19 | s19 | yes |` (F-09, Mode A)
  2. the Modified-files bullet, where `summary.source_path` gains a surrounding code span
     (`- <RUN-ROOT>/…/chg.json (applied entries: 1)` → ``- `<RUN-ROOT>/…/chg.json` (applied entries: 1)``);
     the trailing `` - saved as `…` `` span is **byte-unchanged**.
  Every other line — title, `- Project: proj`, overview row, legend, hexdump, entropy — **shall** be
  byte-identical.
- **Touched artefacts (MODIFIED):** `tests/goldens/batch35/at055b-project-report.md`.
- **Validation:** `test (golden)` + a reviewed `diff` · **Threshold:** `diff old new` reports
  **exactly 2** changed lines; the byte-identity pins
  `tests/test_tui_report_seam.py:1237` and `tests/test_report_service.py:1487-1489` (TC-314) pass.
- **Risk (must verify in Phase 3):** the run-root canonicalisation must still fire on the
  now-backticked path. `assumed — verify in Phase 3` by asserting `RUN_ROOT_TOKEN` is present and no
  absolute drive-letter path survives in the canonicalised bytes.

### LLR-098.2 — Exactly-once application (P-6)
- **Statement:** No value **shall** pass through `md_safe` more than once; a negative-control test
  **shall** assert `md_safe(md_safe(x)) != md_safe(x)` for an escape-bearing `x`, documenting the
  non-idempotence the design relies on.
- **Touched symbols:** none (test-only). **Validation:** `test (unit)` · **Threshold:** 1 case, RED
  if double application ever ships.

### LLR-098.3 — Truncation-limit reconciliation (**measured conflict**)
- **Measured:** `_DEFAULT_MESSAGE_MAX_LENGTH = 500` (`s19_app/validation/model.py:22`) but
  `MAX_REPORT_CELL_CHARS = 240` (`flow_report_service.py:78`). A validated `ValidationIssue.message`
  can therefore be **500 chars, and `md_safe`'s default limit would silently truncate it to 240** —
  a real, currently-latent data-loss defect this batch would introduce if the default were used.
  (`DECLARED_REGION_NAME_MAX = 80`, `report_addendum.py:26`, is safely under the cap — F-26 is fine.)
- **Statement:** `_declaration_error_lines` **shall** call `md_safe` on `issue.message` with an
  explicit `limit` of at least `500`, so the report does not truncate a message a second time.
- **Touched symbols (MODIFIED):** `report_service._declaration_error_lines`.
- **Validation:** `test (unit)` · **Threshold:** a message at the 500-char validation cap renders
  with **0** occurrences of `TRUNCATION_MARKER`.

### LLR-099.1 — Hexdump fence and byte cells pinned unmodified
- **Statement:** `_hexdump_block` and `_format_bytes` **shall** remain unchanged, and a test
  **shall** prove that a memory map of all-`0x60` bytes produces exactly **one** `fence` token
  under both parsers.
- **Touched symbols:** none (assertion of non-change). **Validation:** `test (integration)` ·
  **Threshold:** `fence` count == 1; `0` diff on `_hexdump_block` / `_format_bytes`.

---

## §10 Traceability

**Behavioural chain (US → AT → outcome):**

| US | AT | Observable outcome at the shipped surface |
|----|----|-------------------------------------------|
| US-062-1 | **AT-157** | Written report parsed by the **viewer** parser → 0 live tokens from file-derived text |
| US-062-2 | **AT-158** | Same file parsed by a **default** `gfm-like` parser → 0 live tokens from file-derived text |
| US-062-3 | **AT-159** | Hostile `variant_id` row → correct column count **and** verbatim first-cell text |
| US-062-1/2/3 | **AT-160** | Benign report byte-identical to the re-captured golden; all values readable |
| US-062-1/2 | **AT-161** | All-`0x60` image → hexdump fence unbroken (1 `fence` token) |
| US-062-1 | **AT-162** | Paths render readable (no inserted `\`) and run-root canonicalisation still fires |

**Functional chain (US → HLR → LLR → TC):**

| US | HLR | LLR | TC (proposed) |
|----|-----|-----|---------------|
| US-062-1, US-062-2 | HLR-095 | LLR-095.1, LLR-095.2, LLR-095.3, LLR-095.4 | TC-376, TC-377, TC-378, TC-379 |
| US-062-3 | HLR-096 | LLR-096.1, LLR-096.2 | TC-380, TC-381 |
| US-062-1, US-062-2 | HLR-097 | LLR-095.1, LLR-097.1, LLR-097.2 | TC-376, TC-382, TC-383 |
| US-062-1/2/3 | HLR-098 | LLR-098.1, LLR-098.2, LLR-098.3 | TC-384, TC-385, TC-386 |
| — (anti-regression) | HLR-099 | LLR-099.1 | TC-387 |

**Numbering basis:** global high-water at draft time is `HLR-094` (`.dev-flow/2026-07-22-batch-52/01-requirements.md:242`),
`AT-156` and `TC-375` (both **superseded, never landed** — `.dev-flow/2026-07-23-batch-n8/01-requirements.md:392`).
This batch therefore starts at HLR-095 / AT-157 / TC-376, leaving the 150-156 / 370-375 band as a
documented supersession gap.

---

## §11 Risks

| ID | Risk | Severity | Mitigation |
|----|------|----------|------------|
| **R-1** | **Golden canonicalisation break (CN-6).** The backticked path may not match `_RUN_ROOT_SPAN_RE` (`tests/conftest.py:1014`), leaking an absolute operator path into the compared bytes → machine-dependent golden failure. | **HIGH** | Mode B keeps path bytes raw. LLR-098.1 makes it a Phase-3 assertion: `RUN_ROOT_TOKEN` present, no drive-letter path survives. **The single highest-risk item in this batch.** |
| **R-2** | **Golden drift wider than predicted.** The 2-line prediction is derived from field-level probes (P-4), not from a full regeneration. | MED | LLR-098.1 threshold is an exact `diff` count; a wider diff blocks the gate. |
| **R-3** | **Double escaping** — a field already escaped by a helper gets `md_safe` again (P-6, non-idempotent). | MED | LLR-095.3 places calls at line-assembly sites only; LLR-096.1 removes the pre-existing `_md_table_cell`; LLR-098.2 negative control. |
| **R-4** | **`tests/test_report_symbol_escape.py` breaks.** Its hostile arm asserts `_md_table_cell` output shape. | LOW | LLR-096.1 explicitly requires updating it; the benign arm is unaffected. |
| **R-5** | **Over-escaping harms usability.** `.`/`/`/`_` escaping is blunt (P-11: only TLD-shaped names actually linkify). | LOW-MED | Accepted deliberately — a TLD-aware escaper is a parser inside a sanitiser (batch-60 lesson). Mode B removes the pain where it matters most (paths). |
| **R-6** | **US-062 ID collision** with `REQUIREMENTS.md:3749` (batch-37). Corrupts the C-26 reverse census. | MED | §6 flag — rename to `US-B62-*` in Phase 2. |
| **R-7** | **New module = new import surface.** A leaf module is one more file to keep in the audit set. | LOW | Leaf with zero service imports; a static test asserts no service import creeps in. |
| **R-8** | **`diff_report_service` divergence persists** — it keeps `_md_cell`/`_md_table_cell` against an un-audited HTML sink. | MED | Explicit deferral (§7.1) + a backlog carry item. **Not** silently dropped. |
| **R-9** | **Cost/latency.** `md_safe` is O(13·n) string replaces per field, ≤ a few thousand fields per report. Estimated added time per report: **< 5 ms**; added bytes: **< 1 %** of `REPORT_MAX_TOTAL_BYTES` (2 MiB). No model calls, no network, **$0/month** marginal. | LOW | Measure in Phase 4 against the `large_project` fixture. |

---

## §12 Alternatives considered (and why rejected)

| Option | Verdict | Reason (probe-backed) |
|--------|---------|----------------------|
| **(a)** Import `flow_report_service._md_safe` | **Rejected** | Hard import cycle (`flow_report_service.py:63`); needs a second deferred-import wart on a **private** symbol. |
| **(c)** Fork a third escaper in `report_service` | **Rejected** | Would be the **6th** escaper helper across 3 modules; identical contract to `_md_safe` (P-2/P-3 prove completeness) → guaranteed divergence. batch-60's "create new" rationale does not transfer (same sink, same grammar). |
| **Single Mode A everywhere (paths included)** | **Rejected** | P-7: renders corrupted paths. CN-6: breaks golden canonicalisation. |
| **Single Mode B everywhere (wrap everything in code spans)** | **Rejected** | P-9 limit: a raw `\|` inside a code span still splits a table cell → US-062-3 fails. Also turns the whole report monospace. |
| **Escape only the viewer-relevant set (drop `/ . @ < >`)** | **Rejected** | P-3: bare URLs and raw HTML go live in the exported file → US-062-2 fails outright. |
| **Harden the consumer instead of the producer** | **Rejected** | Already done (batch-60, `screens.py:112`) and **measured insufficient** (P-2). It also cannot protect the exported file, which is US-062-2's whole point. |
| **HTML-entity encoding instead of backslash escaping** | **Rejected** | Only works when `html` is enabled; the viewer disables it (`screens.py:112`), so entities would render literally. |
| **Migrate `diff_report_service` in the same batch** | **Deferred** | Doubles the golden churn (`at054b-*.md`/`.html`) and mixes two sink audits. Reversible; carried to backlog. |

---

## §13 What would change the recommendation

1. **If the viewer parser were ever reconfigured to `linkify: True`** — the two grammars converge and
   the Mode-A/Mode-B split's *readability* justification weakens (the canonicaliser justification, R-1, stands).
2. **If `report_service` stopped being the base of the service DAG** (e.g. `REPORTS_DIR_NAME` moved
   out) — option (a) becomes viable and the new module could be skipped.
3. **If the operator accepts dropping the byte-identity goldens** — the whole C-24 tension
   evaporates and a single Mode A everywhere becomes the simplest design.
4. **If a path field ever lands in a table cell** — Mode B must gain `|` escaping (P-9); LLR-097.2's
   static guard is the tripwire that surfaces it.
5. **If a fifth report generator appears** — promotion pays for itself immediately; the argument
   only strengthens.

---

## §14 Unverified claims (flagged)

- ~~`_DEFAULT_MESSAGE_MAX_LENGTH`~~ **CLOSED at draft time** — measured `= 500`
  (`s19_app/validation/model.py:22`) vs `MAX_REPORT_CELL_CHARS = 240`; the conflict is real and is
  now a normative requirement (LLR-098.3), not an assumption.
- `assumed — verify in Phase 2` — the exact provenance of `result.status`, `entry.linkage`,
  `entry.result`, `descriptor.file_type` (assumed tool-internal tokens; treated as Mode A anyway, so
  the assumption is **not load-bearing**).
- `assumed — verify in Phase 3` — the golden drift is **exactly 2 lines** (predicted from P-4, not
  from a regeneration).
- `assumed — verify in Phase 3` — run-root canonicalisation still fires on the backticked path (R-1).
- `assumed — confirm with operator in Phase 2` — the `US-062` ID collision rename (R-6).
- `assumed — verify in Phase 4` — the `< 5 ms` / `< 1 %` cost estimate (R-9).

---

## Evidence checklist

- [x] **Constraints stated explicitly** — §2, CN-1..CN-8, each with a `file:line`.
- [x] **At least 2 alternatives considered** — §12, seven options weighed.
- [x] **Recommendation has rationale tied to constraints** — §7.1 ties to CN-4 (import DAG) and
      CN-2 (frozen set); §7.2 ties to CN-1 (two grammars) and CN-6 (canonicaliser).
- [x] **Risks listed** (operational, security, cost, lock-in) — §11, R-1..R-9.
- [x] **Cost / latency estimated** — R-9: `< 5 ms`/report, `< 1 %` byte growth, `$0/month`.
- [ ] **Diagram** — not included; the flow is a single linear composer → one `write_text` sink
      (`report_service.py:1613`) with no branching worth a diagram. **Justified omission**, not a skip.
- [x] **What would change the recommendation is stated** — §13.
- [x] **Two-layer requirements** — §6 gives every US a first-class black-box Acceptance block +
      `AT-157..AT-162`; §10 carries BOTH chains (US→AT→outcome and US→HLR→LLR→TC).
- [x] **Privacy / data handling** — CN-7: reports carry raw memory bytes; the new helper is pure,
      logging-free, and adds no new sink. Escaping **reduces** exfiltration surface by killing
      `link_open` in the exported file (P-3).
- [x] **Modal discipline** — `shall` only inside HLR/LLR statements; **zero** `should` in any
      normative statement (self-checked; two draft phrasings rejected).
- [x] **C-26 symbol declarations** — every code-touching LLR names its symbols (§9).
- [x] **C-31 field-set-as-oracle** — §5 derived by exhaustive grep, not from the kickoff examples;
      it surfaced 4 fields the kickoff hint did not name (F-20 `issue.message`, F-22
      `related_artifacts`, F-29 filter name, F-31 hexdump gutter).
- [x] **C-35 execution probes** — 11 probes, §4, all re-runnable from the named script.
