# 02 — Phase-2 QA review (testability + validation-method viability) — batch-62

- **Reviewer role:** Phase-2 `qa-reviewer` · **Base:** `claude/batch-62-report-escaping` @ `8d3c504`
- **Scope reviewed:** `01-requirements.md` (canonical registry, D-1…D-9) · `01-requirements-architect.md` (HLR/LLR/AT, 33-site inventory) · `01b-qa-catalog.md` (**my own** Phase-1 artifact) · `PLAN.md`
- **Method:** every ruling below is backed by an **executed measurement** at `8d3c504`, not by reading. Probes:
  `…/scratchpad/qa62_g4.py` · `qa62_rules.py` · `qa62_table.py` · `qa62_e2e.py`
  (`markdown_it 4.2.0`, Python 3.14.4, run with cwd = repo root)
- **Language:** English.

---

## VERDICT: **FAIL** — 7 blockers, 6 major, 5 minor

The requirement set is not yet buildable. Six of the seven blockers are **contradictions between the
two Phase-1 artifacts, or inside a single artifact's own guard set** — not missing coverage. Four of
the seven are in **my own catalog**, and the single most valuable one (B-6) refutes the acceptance
prediction the orchestrator elevated to *"the prediction is itself the acceptance"*.

| Severity | Count | IDs |
|---|---|---|
| **blocker** | 7 | B-1 … B-7 |
| **major** | 6 | M-1 … M-6 |
| **minor** | 5 | m-1 … m-5 |

**What survives review intact** (stated up front so Phase 3 does not re-litigate it):

- The **negative controls are correct** — `10.1.2.3` and `evil.tld` measured **inert under BOTH** the
  hardened and the default parser (probe `qa62_g4.py`). D-(iii) **CONFIRMED**.
- **G-2's linkify derivation is sound** — `_schemas` == `{'//','ftp:','http:','https:','mailto:'}` and
  `_opts` == `{'fuzzy_link': True, 'fuzzy_email': True, 'fuzzy_ip': False}`, exactly as catalogued.
- **AT-159's oracle is sound.** The positional-content assertion works and the verbatim round-trip is
  real — measured escaped cells `['EVIL|INJECTED|COL', 'a.s19', 's19', 'yes']` at the `text`-child level.
- **All three AT counterfactuals reproduce end-to-end through `generate_project_report`** (the shipped
  entry point), not through a hand-built string. Layer-B is genuine.
- **Provenance-over-subtraction is justified** — a benign report's live set already contains
  `strong_open` (measured), so baseline subtraction is blind exactly as claimed.
- **D-4 and D-5 (the design rulings) are unaffected** by every finding below.

---

## A. AT/TC reconciliation (D-2 / D-3) — **REFUTED**

### B-1 — `blocker` — The architect's `AT-157`/`AT-158` are **materially weaker** than mine under the same id

D-2 (`01-requirements.md:16`) adopts the architect's `AT-157…162` and records the 1:1 semantic match
as *"to be confirmed at Phase 2"*. **It does not hold.**

The architect defines the acceptance predicate as a **closed 7-element enumeration**
(`01-requirements-architect.md:110`):

```
Live-token set = {s_open, strong_open, em_open, link_open, html_inline, html_block, code_inline}
```

and `AT-157`/`AT-158`/§10 then assert *"the live-token set … is empty"*. That set omits
`hr`, `heading_open`, `bullet_list_open`, `ordered_list_open`, `blockquote_open`, `fence`,
`code_block`, `image`, and `hardbreak`.

My `AT-157` (`01b-qa-catalog.md:88-91`) instead asserts *every token the field produces is of type
`text`*, and explicitly enumerates the block-level types.

**Measured through the shipped entry point** (`qa62_e2e.py`), `project_name = "a\n\n---\n"`:

```
NEW token types vs benign      : ['hr']
caught by ARCHITECT live-set?  : False
caught by 'all children text'? : True
```

An injected `hr` **passes** the architect's `AT-157` and **fails** mine. This is not a stylistic
difference: it is precisely the defect class the registry itself carries as **Blocker #1**
(`01-requirements.md:37` — *"`_MD_ESCAPE` leaks block starters — no `-`, `+`, `=`"*). The adopted AT
cannot see the batch's own top-listed blocker.

This is the identical failure mode D-1 was created to prevent, one artifact over: **a duplicate id
carrying divergent meaning**. D-1 correctly renamed the colliding `US-062`; D-2 waved the same
collision through on the ATs.

**Required before Phase 3:** replace the enumerated live-set with an **allow-list** predicate —
*every token attributable to a file-derived field is in `{text, softbreak}`* — and restate `HLR-095`
in those terms (`HLR-095`'s *"zero live Markdown constructs"* is currently defined only by §4's
enumeration). Do not carry both definitions.

### B-2 — `blocker` — `TC-376…387` are **12 ids with no content**, adopted as the canonical TC registry

D-3 (`01-requirements.md:17`) rules *"TC registry = the architect's `TC-376…387` (12)"*. Those ids
appear **exactly once** in the architect's document — in the §10 traceability table
(`01-requirements-architect.md:578-582`), under a column literally headed **"TC (proposed)"**. No
title, no steps, no expected result, no priority exists for any of them anywhere in the artifact.

Meanwhile my catalog defines `TC-376…TC-398` **with** content — and my `TC-376` ("payload-set
completeness guard") is a **different test** from the architect's `TC-376` (mapped to `LLR-095.1`,
the ≥30-case byte-equality corpus).

So the registry simultaneously (a) adopts 12 empty ids as canonical and (b) leaves 12 populated ids
of the same number in a source artifact that D-3 says is authoritative for *how each requirement is
proven*. This trips my own gate criterion **"No unfilled template"** (`01b-qa-catalog.md:540`).

**Required:** either populate `TC-376…387` with real cases, or rule that the qa catalog's
`TC-376…398` **are** the registry and drop the architect's proposed ids. Pick one; do not merge.

### AT-160 / AT-161 / AT-162 — additional surface? **Two yes, one no**

- **`AT-161`** (hexdump fence unbreakable) — **genuinely additional**. Covers F-31, backed by P-10
  and by `hexview.py:356`'s `0x%08X` prefix. No qa AT covers it. Keep.
- **`AT-162`** (paths readable + run-root canonicalisation fires) — **genuinely additional**. Covers
  R-1. Keep, but see B-7 and m-4.
- **`AT-160`** (benign report byte-identical to the **re-captured** golden) — **partly circular**.
  The golden is re-captured *from the changed code*, so byte-identity is true **by construction**.
  The assertion carries information only via `LLR-098.1`'s exact-diff-count prediction — which is
  itself refuted (B-6). Its second clause, *"every benign field is human-readable"*, has **no machine
  oracle**. Rated as a restatement of `TC-394`/`TC-395` with a weaker oracle. See B-7.

---

## B. Is every AT genuinely black-box? — **mostly yes, with one self-contradiction**

| AT | Drives shipped surface | Asserts outcome | References no internal symbol | Counterfactual reproducible @ `8d3c504` |
|---|---|---|---|---|
| AT-157 | ✓ `generate_project_report` | ✓ token stream of the on-disk file | **✗ — see M-6** | ✓ measured: `['link_open','s_open']` new vs benign |
| AT-158 | ✓ same artifact | ✓ default-parser token stream | ✓ | ✓ measured: all 9 linkify/HTML payloads fire |
| AT-159 | ✓ same artifact | ✓ positional cell content | ✓ | ✓ measured: `['EVIL','INJECTED','COL','a.s19']` |
| AT-160 | ✓ | **partly — "human-readable" is not an oracle** | ✓ | n/a (no defect) |
| AT-161 | ✓ | ✓ `fence` count | ✓ | n/a (proves non-defect) |
| AT-162 | ✓ report text | **✗ — clause 2 asserts on the test harness** | ✗ `canonical_report_bytes` | n/a |

### M-6 — `major` — `AT-157` references a private function, contradicting the catalog's own claim

`01b-qa-catalog.md:75-76` states: *"No AT references an escaping helper, a private function, or any
symbol introduced by this batch."* `AT-157` then specifies parsing with `_hardened_markdown_parser()`
(`s19_app/tui/screens.py:82` — leading underscore, private).

The **choice is right** (C-12: observe the real consumer, so the AT cannot drift from what the app
renders) but the **claim is false as written**. Either restate the claim to *"no AT references the
mechanism under change"*, or promote a public `build_report_parser()` factory in `screens.py`. I
recommend restating — promoting a symbol to satisfy a doc sentence is the tail wagging the dog.

### AT-162, clause 2 — not black-box

*"run-root canonicalisation still fires"* is an assertion about `tests/conftest.py:970`'s
`canonical_report_bytes` — a **test helper**, not a shipped surface. It is a legitimate and
necessary check (R-1), but it is a **TC**, not an AT clause. Split it out (see B-7).

---

## C. C-18 realization — **UNREALIZED for 3 of 6 ATs**

### B-7 — `blocker` — `AT-160`, `AT-161`, `AT-162` have **no prospective on-disk node**, and `AT-160` is satisfiable only in parts

The only test-target mapping in the batch is `01b-qa-catalog.md:501-508`, which predates D-2 and
names **only** `AT-157/158/159`:

| File | ATs named |
|---|---|
| `tests/test_report_markup_safety.py` | AT-157, AT-158, AT-159 |
| `tests/test_report_field_census.py` | *(TCs only)* |

`AT-160/161/162` are named in **no** target file. C-18 requires exactly one prospective node per AT
driving the whole named chain end-to-end.

Worse, `AT-160` cannot be one node even in principle as specified. Its chain is spread across
**pre-existing** assertions in two other files:

- byte-identity golden — `tests/test_tui_report_seam.py:1237`
- no-filter byte-identity pin — `tests/test_report_service.py:1487-1489` (TC-314)
- "every benign field is human-readable" — **no node, no oracle**

That is the textbook "satisfiable in parts" pattern. **UNREALIZED — blocks.**

**Required:** name one node per AT. Concretely:
`AT-160` → `test_at160_benign_report_matches_recaptured_golden` (single node that regenerates and
compares, with the readability clause **demoted to `TC-395`** where it already has a concrete oracle);
`AT-161` → `test_at161_hostile_image_cannot_close_hexdump_fence`;
`AT-162` → `test_at162_paths_render_without_inserted_escapes` (+ the canonicaliser clause as its own TC).

**ATs I judge UNREALIZED:** `AT-160` (in parts + no oracle for clause 2), `AT-161` and `AT-162` (no
node named — mechanically fixable).
**ATs I judge VACUOUS:** `AT-160` clause 1 as currently written (byte-identity against a golden
re-captured from the code under test is true by construction; it carries information **only** through
`LLR-098.1`, which B-6 refutes).

---

## D. C-31 turned on my own payload set — **three blockers, all mine**

### B-3 — `blocker` — (i) The derivation is **incomplete**: `html_inline` / `html_block` have no payload

Measured `get_active_rules()` at `markdown_it 4.2.0` (`qa62_rules.py`), identical for both parsers:

```
block   (11): blockquote, code, fence, heading, hr, html_block, lheading, list, paragraph, reference, table
inline  (12): autolink, backticks, emphasis, entity, escape, html_inline, image, link, linkify, newline, strikethrough, text
```

`G-1` requires `{p.rule_key} ⊇ (inline ∪ block) − INERT_RULES`, and §3.3 explicitly forbids listing
HTML as inert: *"`html_block`/`html_inline` are **not** inert and must not be listed"*
(`01b-qa-catalog.md:253-254`).

**But the payload table (`01b-qa-catalog.md:194-228`) contains no `html_inline` and no `html_block`
row.** HTML appears only in `AT-158`'s prose counterfactual (`:130`) and in probe transcript §7(d)
(`:470`) — never as a numbered, guarded payload. `G-1` therefore goes **RED at collection time** on
its own table. The guard is correct; the table it guards is short by two.

**Fix:** add `html-inline` (`<img src=x onerror=alert(1)>`) and `html-block`
(`\n\n<div>x</div>\n`) as payloads #32/#33, both `active under: DEFAULT`.

### B-4 — `blocker` — (ii) `G-4` **does** fire per-payload — and it contradicts `G-1` on three rules

The reviewer's concern was "inert-but-counted". The measured reality is the **opposite and worse**:
`G-4` fires correctly, and it kills three payloads `G-1` mandates. Measured (`qa62_g4.py`), raw
payload through its declared parser, live = types − `{text, paragraph_open, paragraph_close, inline, softbreak}`:

```
10 entity              &amp;               live=NONE  <-- VACUOUS
11 escape-backslash    \*not\*             live=NONE  <-- VACUOUS
22 table-pipe          EVIL|INJECTED|COL   live=NONE  <-- VACUOUS
```

(all other 28 fire; the full transcript is in the probe.)

- `entity` and `escape` are **structurally incapable** of emitting a non-`text` token — that is what
  those rules *do*. `G-1` demands a payload for rule `entity` and rule `escape`; `G-4` forbids that
  payload from being inert. **Direct contradiction. `TC-376` is unimplementable as specified.**
- `table-pipe` is the important one. It is inert **only because `G-4` parses the payload
  context-free** — a bare `|` outside a table row is just text. It fires only at its emission site.
  This is the batch-60 lesson (*"assert at the SINK, not a character list"*) violated inside the very
  guard the catalog offers as the C-31 deliverable. My ATs assert at the sink; my `G-4` does not.

**Fix (both):**
1. Re-scope `G-4` from *"parse the raw payload"* to *"parse the payload **embedded in its emission
   context**"* (table row for `table`, bullet/heading otherwise). That makes `table-pipe` fire.
2. For `entity` and `escape`, replace the live-token predicate with the **fidelity** predicate they
   actually threaten: the cooked `text` content **differs from the input** (`&amp;` → `&`,
   `\*not\*` → `*not*`). Add a named `MUTATING_RULES` set, per-entry justified, so it is visible in
   review — same discipline §3.3 already demands of `INERT_RULES`.

### B-5 — `blocker` — `assert_field_inert` (§3.4) is **unimplementable and unsound as written**

Both clauses fail on measurement (`qa62_table.py`, `qa62_e2e.py`).

**Clause 1 is a false-RED on benign input.** `field_tokens` walks `.children`, so the returned set
includes container tokens. Measured token types for one escaped inventory row:
`inline`, `text`, plus `td_open`/`tr_open`/`th_open`/`table_open` in the enclosing walk. The
assertion `{t.type for t in toks} <= {"text", "softbreak"}` (`01b-qa-catalog.md:270`) is therefore
**False for every table row and every heading in a benign report**. It cannot be run as written.

**Clause 2 is unsound — it mixes raw and cooked content.** Measured on the same escaped row:

```
inline  content='a\\.s19'      <-- RAW markdown source
text    content='a.s19'        <-- COOKED rendered value
```

`"".join(t.content for t in toks)` over the walked list concatenates **both**, double-counting every
value and admitting the raw source as evidence. Measured join over all walked tokens:
`'VariantVariantFileFileTypeTypeActiveActive…'`.

The concrete failure: for the `entity` payload the raw `inline.content` is `&amp;` while the cooked
`text.content` is `&`. The membership clause — whose stated purpose is to forbid *"sanitise by
deleting"* — **passes on a value the parser demonstrably mutated**, because it reads the source it
was supposed to be checking against.

**Fix:** compute the type set over the field's **inline descendants only**, with an explicit
container allow-list; and compute the content join over **`text`-typed tokens only**. Both are
one-line changes, but the helper is the single point every AT and TC in this batch routes through —
shipping it unfixed makes all of them false-confidence tests.

### (iii) Negative controls — **CORRECT, confirmed under both parsers**

This is the one part of my catalog that holds up unmodified. Measured (`qa62_g4.py`):

```
N1 neg-fuzzy-ip   10.1.2.3   viewer live=INERT   default live=INERT   hrefs=[]
N2 neg-fake-tld   evil.tld   viewer live=INERT   default live=INERT   hrefs=[]
```

Corroborating measurements that show the controls are *sharp*, not merely lucky:

```
default 'http://evil.tld/x'  live=['link_close','link_open']   <-- scheme still fires
default '//evil.tld/x'       live=['link_close','link_open']
default 'www.evil.tld'       live=INERT
default 'http://10.1.2.3/x'  live=['link_close','link_open']
```

So both controls are inert **specifically** because of `fuzzy_ip=False` and the 17-entry `_tlds`
list — exactly the semantics `G-5` is meant to pin. If either changes upstream, `G-5` goes RED.
**Ruling: D-(iii) CONFIRMED, no change required.**

---

## E. The golden re-capture prediction (D-7) — **REFUTED before the change lands**

### B-6 — `blocker` — Drift is **3 lines, not 2**. The prediction blocks its own batch.

D-7 (`01-requirements.md:21`) and `LLR-098.1` (`01-requirements-architect.md:516-524`) predict
**exactly two** drifting lines and rule that *"an unpredicted 3rd line blocks"*.

`tests/goldens/batch35/at055b-project-report.md` has **two** variant-inventory rows:

```
14: | a | a.s19 | s19 | yes |
15: | b | b.s19 | s19 | no  |
```

`LLR-098.1` names only line 14. Measured (`_md_safe` on every value in the golden):

```
DRIFT 'a.s19' -> 'a\.s19'
DRIFT 'b.s19' -> 'b\.s19'      <-- line 15, UNPREDICTED
no-op 'proj' 'a' 'b' 's19' 'yes' 'no' 'ok' 'standalone' '-' '1' '0' 'low'
```

Predicted drift set = lines **14, 15, 51** = **3 lines**. A correct implementation therefore trips
D-7's own blocking condition.

**Root cause — C-31, applied to the probe itself.** Architect probe P-4
(`01-requirements-architect.md:130-146`) sampled `descriptor.path.name` **once** (`'a.s19'`) for a
field the fixture emits **twice**. The probe's input set was the vacuous oracle. This is the third
occurrence of that class in this batch's own artifacts (with B-3 and B-4).

### Is the prediction checkable *before* the change lands, and how is a 3rd line detected?

**Yes — and I just did it**, which is the proof that it is checkable: enumerate the golden's 81
lines, apply `md_safe`/`md_code` per the F-01…F-33 inventory, and diff against the stored bytes.
No code change required. That method must be written into `LLR-098.1` as the **pre-implementation**
gate, not left as *"assumed — verify in Phase 3"*.

**Detection mechanism for a 3rd line — currently absent and must be specified:**

```bash
git show HEAD:tests/goldens/batch35/at055b-project-report.md > /tmp/golden.before
# regenerate golden
diff --unified=0 /tmp/golden.before tests/goldens/batch35/at055b-project-report.md
# gate: exactly N changed lines, and each changed line number is in the predicted set
```

The assertion must be on the **line numbers**, not the count. A count-only gate is GREEN when one
predicted line fails to drift and one unpredicted line does — the same count-vs-content blindness
`AT-159` exists to defeat. Note this is a **one-shot Phase-3 gate artifact**, not a surviving
regression test: after merge the old bytes are gone. It must therefore be pasted into the increment
packet verbatim.

**Required:** correct the prediction to **3 lines (14, 15, 51)**, name them, and pin the diff command.

---

## F. Caps must be pinned — **two of three caps are unpinned or ambiguous**

### M-2 — `major` — `MAX_REPORT_CELL_CHARS = 240` becomes silent truncation on ~20 fields, covered by nothing

`LLR-095.3` routes all 21 Mode-A sites through `md_safe` and specifies **no `limit`**, so they take
the default `240` (`flow_report_service.py:78`). `md_safe` truncates **before** escaping and appends
a marker (`flow_report_service.py:178-180`). `LLR-098.3` reconciles the cap for **`issue.message`
only**.

Verified: the only upstream length cap in the whole field inventory is
`DECLARED_REGION_NAME_MAX = 80` (`report_addendum.py:26`, covers F-26). There is **no** cap on
`variant_id`, `descriptor.path.name`, `issue.symbol`, `linkage_symbol`, or `project_name`
(`sanitize_project_name` imposes none). An NTFS basename alone reaches 255 characters.

So this batch introduces **new silent data loss at 240 characters on ~20 fields**, and no HLR, LLR,
or AT addresses it. This is the *same defect class* the architect correctly found for
`issue.message` — found once, fixed once, not swept. (C-26: the sibling sweep.)

My own `TC-396` is complicit: it is written **conditionally** — *"If the design introduces a
per-cell/per-field char cap `N`"* (`01b-qa-catalog.md:343`). Under the adopted design it definitely
does. A conditional test is an optional test.

**Required:**
1. Rule explicitly whether 240 is acceptable for the other 20 sites, or pass a wider `limit`.
2. Rewrite `TC-396` unconditionally, naming a field with **no upstream cap** — `descriptor.path.name`
   is the right choice, since it is file-derived, uncapped, and lands in a table cell.
3. **The RED test:** generate a report whose `descriptor.path.name` is `"x"*241`; assert the rendered
   cell text equals the input verbatim. Deleting the `limit=` argument makes it truncate → RED.
   Confirmed the fixture crosses the limit: `241 > 240`. This is the batch-60 lesson (fixture 2.8×
   *under* the limit → every test passed with the guard deleted) applied.

### M-3 — `major` — `TRUNCATION_MARKER` is ambiguous: **two different constants exist**

```
s19_app/validation/model.py:21        _TRUNCATION_MARKER = "…[truncated]"
s19_app/tui/services/flow_report_service.py:85   _TRUNCATION_MARKER = "… (truncated)"
```

`LLR-098.3`'s threshold — *"renders with **0** occurrences of `TRUNCATION_MARKER`"* — does not say
which. A test importing the wrong one is a false-GREEN of exactly the assert-the-emitted-encoding
class (now its **fourth** occurrence).

**Required:** pin `markdown_safety.TRUNCATION_MARKER` by name in the threshold, and add an assertion
that the two constants are distinct so a future merge of them is a conscious act.

### The `issue.message` cap (`LLR-098.3`) — **pinned correctly, verified sensitive**

Verified `_scrub_issue_message` (`validation/model.py:25-84`) guarantees the returned string is
`<= max_length` **including** the marker, so a fixture of exactly 500 `x` survives scrubbing
unmarked. `md_safe(msg)` at the default 240 then truncates → marker appears → **RED**.
`md_safe(msg, limit=500)` → no marker → GREEN. **The guard is genuinely sensitive and the fixture
genuinely crosses the limit.** No finding.

### M-5 — `major` — `md_safe` substitutes the literal `"(empty)"`, unaudited at 20 of 21 sites

`_md_safe` returns `"(empty)"` when nothing survives (`flow_report_service.py:181`). Applying it at
21 sites means **any field that is legitimately empty today renders as the literal string
`(empty)`**.

Verified safe at exactly **one** site: `report_service.py:977-981` guards with
`if entry.linkage_symbol else "-"` (which is why golden line 57 reads `| standalone | - |`). The
other 20 sites are unaudited. `issue.symbol` and `issue.related_artifacts` are `Optional`;
`descriptor.file_type` may be absent when un-sniffed.

This is also a **4th candidate golden-drift line** and therefore feeds directly into B-6.

**Required:** audit the 20 remaining sites for a reachable empty value; where one exists, either keep
the existing conditional or pass through a variant that preserves empty.

---

## G. The Phase-0→Phase-1 correction (registry §7) — **half confirmed, half over-claimed**

### CONFIRMED — the data-loss mechanism and the count-blindness

Measured on the real 4-column inventory header (`qa62_table.py`):

```
benign       | BENIGN | a.s19 | s19 | yes |          cells=['BENIGN','a.s19','s19','yes']
hostile RAW  | EVIL|INJECTED|COL | a.s19 | s19 | yes |  cells=['EVIL','INJECTED','COL','a.s19']
hostile SAFE | EVIL\|INJECTED\|COL | a\.s19 | ... |   cells=['EVIL|INJECTED|COL','a.s19','s19','yes']

token-level cell COUNT: benign=4 rawhostile=4  -> count-only assertion GREEN? True
```

`file_type` and the active flag are silently destroyed while the **cell count stays 4**. The
registry's core claim — that a **column-count** assertion is GREEN on this input, and that
`AT-159`'s verbatim positional-content assertion is what catches it — is **fully confirmed**, and
reproduced end-to-end through `generate_project_report` (`qa62_e2e.py` emits
`| v1|INJECTED|COL | a.s19 | s19 | yes |`).

### M-1 — `major` — but the claim about **batch-39's guard** is measurably false

Registry §7 (`01-requirements.md:61`) states: *"A pipe-count or column-count assertion is therefore
GREEN on this input, which also means batch-39's surviving guard (`structural == 7`,
`tests/test_report_symbol_escape.py:151`) is **blind to this class**."*

That guard is **not** a column-count assertion. It is a **raw-source structural-pipe count**
(`tests/test_report_symbol_escape.py:150`: `re.findall(r"(?<!\\)\|", row)`). Replayed on its own
subject, the modifications row:

```
UNESCAPED symbol  structural=8  guard(==7) -> FAIL/RED
ESCAPED   symbol  structural=7  guard(==7) -> PASS
```

And on the inventory row: benign `5`, hostile-raw **`7`**, hostile-safe `5`. **A structural-pipe
count is RED on this input.** The guard is precisely sensitive to the raw-pipe class for the one
field it covers.

What batch-39's guard *is* blind to — the accurate and still-damning statement:
1. **The other 32 fields.** It inspects only `linkage_symbol` on the modifications row.
2. **Every pipe-free grammar payload** — `**`, `~~`, `[](…)`, linkify, HTML, headings, `hr`. Those
   emit no pipe at all, so no pipe count can see them.

This matters operationally: `LLR-096.1` requires rewriting that test. Justifying the rewrite with
"the old guard was blind" would **weaken a guard that works**. Rewrite it because `_md_table_cell`
is being replaced, and **keep the structural-pipe assertion** alongside the new token assertions —
it is cheap, and it is the only thing that currently catches a raw pipe in the markdown *source*
(as opposed to the parsed result).

**Required:** correct registry §7's sentence; state the two real blind spots; retain the pipe count.

---

## Remaining findings

### M-4 — `major` — D-3's TC renumbering is under-specified

*"qa's additional cases renumber to `TC-388+`"* (`01-requirements.md:17`). But my catalog already
uses `TC-388` ("Filter-header site") and `TC-389` ("Truncation-appendix path") for named cases, and
D-3 does not define which of my 23 cases are "additional" versus same-numbered duplicates of the
architect's 12. Combined with B-2, `TC-376…387` currently carry two meanings each.
**Required:** an explicit old→new id map, or resolve B-2 by dropping one of the two sets.

### m-1 — `minor` — payload count is stated three ways

BLUF and §3.2 say *"30 active"*; the table has **31** numbered active rows; `TC-377` says *"all 31"*;
`G-3` pins `len(ACTIVE_PAYLOADS) >= 30`. With B-3's two HTML additions it becomes 33. Fix the count
so `G-3`'s floor is unambiguous, and state why the floor is `>=` and not `==`.

### m-2 — `minor` — `G-1` silently ignores two rule chains

`G-1` unions only `inline` and `block`. Measured, the ignored chains are
`core = {block, inline, linkify, normalize, text_join}` and
`inline2 = {balance_pairs, emphasis, fragments_join, strikethrough}`. **Verified harmless** — they
contain only orchestration/post-process rules, and `linkify`/`emphasis`/`strikethrough` are already
covered via `inline`. But nothing records that this was reasoned rather than accidental. Add the
justification, or union all four chains and put the orchestration rules in `INERT_RULES`.

### m-3 — `minor` — dead code in the `G-2` derivation

`LINKIFY_SCHEMES = set(DEFAULT.linkify._schemas) - {""}` (`01b-qa-catalog.md:176`). Measured
`_schemas` keys are `['//','ftp:','http:','https:','mailto:']` — there is no `""` key, so the
subtraction is a no-op written from assumption rather than measurement. Harmless; remove it.

### m-4 — `minor` — R-1 is over-rated `HIGH`; the golden already proves the backtick case

`_RUN_ROOT_SPAN_RE = rb"<RUN-ROOT>[^\s\`\"'|)\]]*"` (`tests/conftest.py:967`) — the character class
**already excludes the backtick**, and golden line 51 **already** carries a backticked run-root path
(`` - saved as `<RUN-ROOT>/.s19tool/workarea/proj/a-patched.s19` ``) that canonicalises correctly
today. Mode B's exact shape is therefore proven by an existing, passing golden, not merely predicted.
Downgrade R-1 to `LOW-MED`, cite golden line 51 as the evidence, and change
*"assumed — verify in Phase 3"* to a resolved claim. (`AT-162`'s canonicaliser clause is still worth
keeping as a TC — see B-7.)

### m-5 — `minor` — anchor error on the line an LLR instructs you to delete

A-4 and D-5 cite the deferred import at `report_service.py:974-976`. Measured: the comment is at
`:965-967` and `from .diff_report_service import _md_table_cell` is at **`:968`**. The
`_md_table_cell` call at `:978` is correct. All other spot-checked anchors verified accurate
(`:769`, `:892`, `:901`, `:987`, `:1091`, `:1445`, `:729`, `:563`, `validation/model.py:22`). Given
the architect's stated method (*"every anchor is file:line verified on disk at draft time"*), record
the miss.

---

## What must happen before Phase 3 opens

| # | Action | Closes |
|---|---|---|
| 1 | Replace the enumerated live-token set with the `{text, softbreak}` allow-list; restate `HLR-095` in those terms | B-1 |
| 2 | Resolve the `TC-376…387` double-meaning: populate or drop | B-2, M-4 |
| 3 | Add `html-inline` / `html-block` payloads | B-3 |
| 4 | Re-scope `G-4` to parse **in emission context**; add `MUTATING_RULES` for `entity`/`escape` | B-4 |
| 5 | Rewrite `assert_field_inert`: inline descendants for types, `text` tokens only for content | B-5 |
| 6 | Correct the golden prediction to **3 lines (14, 15, 51)**; pin the line-number diff gate | B-6 |
| 7 | Name one on-disk node per AT; demote `AT-160`'s readability clause to `TC-395` | B-7 |
| 8 | Correct registry §7's batch-39 claim; keep the structural-pipe assertion | M-1 |
| 9 | Rule on the 240-cap for the other 20 sites; make `TC-396` unconditional on `descriptor.path.name` | M-2 |
| 10 | Pin `markdown_safety.TRUNCATION_MARKER` by name | M-3 |
| 11 | Audit the `"(empty)"` substitution at the 20 unguarded sites | M-5 |
| 12 | Restate the catalog's "no private symbol" claim | M-6 |

---

## Evidence checklist

- [x] **Acceptance criteria use Given/When/Then** — reviewed as authored; B-1 rules on the predicate, not the form.
- [x] **Test cases have explicit Expected, not vague "works"** — ✗ for `TC-376…387` (no Expected at all) → B-2; ✗ for `AT-160` clause 2 ("human-readable") → B-7.
- [x] **Edge cases include empty, boundary, invalid, error** — empty: M-5 finds the `"(empty)"` substitution unaudited; boundary: M-2 finds the 240-cap unpinned at 20 sites; invalid/error: covered by the payload set once B-3/B-4 land.
- [x] **Regression checklist exists** — `01b-qa-catalog.md:351-373`, 11 items, reverse-census derived. Reviewed; no finding.
- [x] **Exit criteria stated** — `01b-qa-catalog.md:550-562`. Exit criterion 1 ("AT-157/158/159 RED at `8d3c504`") is **verified reproducible** (`qa62_e2e.py`).
- [x] **No real PII / secrets** — all probes use synthetic `tmp_path` fixtures and `evil.com`/`evil.tld`; no operator firmware, no absolute operator path quoted in this review.
- [x] **Test results section left blank** — no TC has been executed. Everything reported here is a **probe measurement of the current tree at `8d3c504`**, labelled as such, run against the shipped `generate_project_report` and the live `markdown_it` parsers.
- [x] **Layer B (black-box)** — B-7 rules three ATs UNREALIZED at the shipped surface; M-6 records the private-symbol reference. AT-157/158/159 confirmed to drive the shipped entry point end-to-end.
- [x] **Bidirectional surface-reachability** — input side: B-3/B-4 find the payload set short by two and contradictory on three. Output side: B-7 finds three deliverables (golden, fence, path-readability) with no observing node.
- [x] **No unfilled template** — ✗ **fails for the batch**: `TC-376…387` are 12 ids with no content (B-2). This review itself contains no placeholders.
