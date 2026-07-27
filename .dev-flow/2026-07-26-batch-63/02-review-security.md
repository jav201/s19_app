# batch-63 — Phase-2 INDEPENDENT security review of the SPEC

> **Reviewer:** `security-reviewer`, independent lane. **Tree:** `claude/batch-63-report-table-caps`
> @ `031ca8d`. **No worktree mutation** — every probe ran against a `git archive HEAD` export in the
> session scratchpad (`git status --porcelain` shows only `.dev-flow/`, as at session start).
> **Reviewed before any code exists.**

---

## BLUF

**Verdict: BLOCK.** One blocker, five majors, three minors.

The design ruling I was asked to attack hardest — **D-15, the truncation indicator goes OUTSIDE the
byte cell so `_format_bytes`'s alphabet stays closed** — is **correct, and I confirm its premise by
execution**. The alphabet is closed for every input reachable through the shipped path, the new
marker text interpolates no file-derived value, and the `Length` column is a faithful corroborator
derived from the same `encoded_bytes` length as the run it describes.

**But the normative document does not say what the ruling says.** `01-requirements-architect.md`
REV 4 still mandates the *withdrawn* in-cell indicator in **four places**, two of them inside the
`shall`-bearing traceability chain (§3 AT-170, §3 AT-171, §4.1 M10, §4.2 K11 — and LLR-091.3
"**Traces to:** truth table M10/K11"). §12.8 then lists "the truth tables (§4)" under **Unchanged**.
An implementer following the normative chain implements the thing D-15 withdrew, and TC-409 as
drafted would be written to *bless* it. That is **B-1** and it blocks.

Answering the three questions posed to me, in order of what I think matters:

1. **"Does the fix bound the document, or does the byte-cap marker still assert something false?"**
   **It still asserts something false.** Measured, post-batch-63 simulated: **2 variants at cap →
   2 918 330 B = 1.39× the budget, with `> TRUNCATED: … (report size cap: 2097152 bytes)` FIRED.**
   The batch narrows M-2 from ~12 700 entries to ~2 variants; it does not close it. The batch's own
   premise — *a marker asserting an unhonoured bound is worse than no bound* — is therefore not
   discharged, and the architect's own A-1 "If REJECTED" clause already prescribes the fix
   (reword `:1352-1355` to the blocks it governs). Cost: one f-string. → **F2**, must ship.
2. **A third cell in these same two tables is still unbounded.** `_parse_address` accepts
   `^0x[0-9A-Fa-f]+$` with no digit limit. **One entry → a 1 000 055 B row = 0.48× the whole budget**,
   with the 500-row cap and `REPORT_CELL_BYTES = 64` both inert against it. The architect's §1.3
   refutation ("a cap of 200 rows on a table whose first row can be 3× the budget bounds nothing")
   applies verbatim to a cell A-1 does not cover. → **F3**.
3. **In-band forgery gets worse, not better.** R-TUI-092 promotes the truncation appendix to the
   authoritative *"an absent appendix means nothing was cut"* oracle. Executed: a file-derived
   `variant_id` (= a filename stem) forges a second, fully plausible truncation statement **in the
   rendered view** — `\.` renders as `.`. Grammar stays inert; the *evidence* does not. → **F4**.

I also **independently corroborate the qa lane's B-5** (evidence deletion): `_applied_regions`
filters `disposition == DISPOSITION_APPLIED`, and no checklist byte reaches it at all, so the
mandated marker text *"full bytes in the Memory regions section"* is false for every non-applied
modification row and 100 % of checklist rows. Read at source, same conclusion, different route.
→ **F6**.

Overlap with the qa lane, stated rather than merged: my **B-1** and qa's **B-3** are the same root
cause seen from two documents (mine: the *architect* spec is self-contradictory; qa's: the *catalog*
validates the withdrawn design). Both edits are required. My **F6** is qa's **B-5**, corroborated.
**F2, F3, F4, F5** are not in the qa review.

---

## Scope reviewed

| artifact | rev | read |
|---|---|---|
| `.dev-flow/2026-07-26-batch-63/PLAN.md` | living | full |
| `…/00-measurements.md` | — | full |
| `…/01-requirements.md` | §2.6 | full |
| `…/01-requirements-architect.md` | **REV 4 (normative)** | §0–§13 |
| `…/01b-qa-catalog.md` | REV 2 | §0–§10 |
| `…/02-review-qa.md` | — | headings + B-5 (overlap reconciliation only) |
| `s19_app/tui/services/report_service.py` | `031ca8d` | full-relevant |
| `s19_app/tui/services/markdown_safety.py` | `031ca8d` | full |
| `s19_app/tui/changes/{io,model,apply,check}.py` | `031ca8d` | input-domain trace |
| `REQUIREMENTS.md` R-TUI-077 | `:4770-4800` | full |

**Threat model.** Project reports embed values read from operator-supplied firmware, A2L/MAC and
JSON change/check documents. Those files are the untrusted input; the `.md` travels out of the app
as an evidentiary record. Trust boundary: **parse layer → composer → exported document → human
reader**. No new external integration, no MCP/Composio connector, no auth surface, no credential
handling, no destructive command, no dependency change in this batch — **sections 1, 2, 3, 4, 5 and
6 of my standard checklist are N/A and are stated as such below, not silently omitted.**

---

## Findings

### B-1 — the REV-4 normative spec still mandates the WITHDRAWN in-cell indicator, inside the `shall` chain  [Severity: **BLOCKER**]

- **What:** D-15 / §12.2 withdrew the in-cell truncation indicator because it would open
  `_format_bytes`'s closed alphabet and invalidate **locked R-TUI-077**'s
  inertness-*by-construction* premise. Four surviving statements in the same document still require
  it, two of them load-bearing for traceability:

  | where | text |
  |---|---|
  | `01-requirements-architect.md:458` (AT-170) | "…and **the cell states the exact omitted byte count**." |
  | `:460` (AT-171) | "The truncation marker emitted **inside a byte-run cell** is inert…" |
  | `:491` (truth table M10) | "row emitted with the cell truncated + **its own in-cell marker**" |
  | `:509` (truth table K11) | "truncated cell + **in-cell marker**" |

  §4's own preamble (`:473-476`) declares the truth tables **normative by reference** — "*A row with
  no LLR citing it is a specification gap, not a soft preference*" — and **LLR-091.3 (`:616`) traces
  to "truth table M10/K11"**. So the withdrawal is contradicted *by the normative chain itself*, not
  merely by stale prose. `:1283` and `:1487` then list the truth tables under **Unchanged**, which is
  the assertion that hides it.

  The qa catalog compounds it: `01b-qa-catalog.md:326` ("**the cell** states that it was cut"),
  `:438` TC-406 ("`CELL_BYTES + 1` → bounded **+ indicator**"), `:441` TC-409 ("asserts **the chosen
  indicator's** character set … or records a §6.5 Before/After **amending F-17**"). TC-409 as
  drafted offers an explicit route to weakening the security pin.
- **Where:** `01-requirements-architect.md:458,460,491,509` (+ `:1283`, `:1487`);
  `01b-qa-catalog.md:326,438,441`.
- **Why it matters:** this is not a documentation nit. `_format_bytes` is the ONE report field
  R-TUI-077 exempts from escaping, and the exemption's entire justification is that its alphabet is
  closed. An implementer who resolves the contradiction toward §4 (a table explicitly labelled
  normative) puts `…`/`+`/letters into that cell, and the exemption silently loses its basis — the
  batch would relax a batch-62 security invariant as collateral for a resource fix. §13.1 named the
  exact failure mode ("*a number that was true when written and never re-checked when its basis
  changed*") one section earlier; here the same mechanism recurs on the security-relevant axis, with
  §12.8/§13.8 asserting "Unchanged" over rows the ruling invalidated.
- **Recommendation:** before Phase 3, in one edit:
  1. Rewrite M10 → "**row emitted with the byte cell rendered as a `REPORT_CELL_BYTES`-token prefix;
     the cell alphabet is unchanged; the cut is stated by the per-section marker (LLR-091.3) and the
     `Length` column**"; same for K11.
  2. Rewrite AT-170's "the cell states the exact omitted byte count" → "**the per-section marker
     states the exact count of prefixed cells, and the row's `Length` column states the true run
     length**".
  3. Replace AT-171 with the assertion the ruling actually needs: "**every byte cell in the emitted
     document satisfies `set(cell) <= set('0123456789ABCDEF ')`, asserted over the composer-produced
     document, and the per-section marker is inert on the token stream**". As written, AT-171
     validates a construct that must not exist.
  4. Remove §12.8/§13.8's "Unchanged: the truth tables (§4)" claim — it is false for M10/K11.
  5. qa catalog: retire the in-cell arms of AT-172/TC-406, and **delete TC-409's "or … amending
     F-17" escape hatch** — under ruling (b) F-17 must stay GREEN unamended, and offering an
     amendment route re-opens what §12.2 closed.

---

### F2 — after this batch the document is still unbounded, and the byte-cap marker still asserts a bound it violates  [Severity: **MAJOR**]

- **What:** the caps are per-variant; no `MAX_VARIANTS` exists (re-verified independently:
  `grep -rn "MAX_VARIANT\|max_variants\|MAX_PROJECT_FILES\|len(variants) >" s19_app/` → **0 hits**).
  `_hexdump_section` keeps emitting `(report size cap: {REPORT_MAX_TOTAL_BYTES} bytes)`
  (`report_service.py:1352-1355`), which reads as a whole-document guarantee. Executed, simulating
  the batch-63 design (`CAP = 500`, `REPORT_CELL_BYTES = 64`) over the **real composer**, worst-case
  cells, documents re-read from disk:

  ```
  CAP=500 rows/table/variant   REPORT_CELL_BYTES=64   budget = 2,097,152 B

    main today           variants= 1 entries=    1  size= 12,587,675 B ( 6.00x) bytecap_marker=FIRED  over=YES
    post-b63 (simulated) variants= 1 entries= 1000  size=  1,470,509 B ( 0.70x) bytecap_marker=no     over=no
    post-b63 (simulated) variants= 2 entries= 1000  size=  2,918,330 B ( 1.39x) bytecap_marker=FIRED  over=YES  <== asserts a bound the file violates
    post-b63 (simulated) variants= 3 entries= 1000  size=  4,366,151 B ( 2.08x) bytecap_marker=FIRED  over=YES
    post-b63 (simulated) variants= 4 entries= 1000  size=  5,813,972 B ( 2.77x) bytecap_marker=FIRED  over=YES
  ```

  (`scratchpad/x63/sec2_residual.py`. My single-variant figure is 1 470 509 B vs the architect's
  measured 1 279 244 B because I also made `linkage` hostile, not only `linkage_symbol`; the breach
  point is the same ~1.6–2 variants.)
- **Where:** `report_service.py:1352-1355`; carry recorded at `01-requirements-architect.md:703-706`
  as "reword or carry — do not leave unexamined".
- **Why it matters:** the operator's own question, and the batch's own premise. M-2 was raised above
  resource hygiene precisely because *a reader takes the notice as proof the bound held*. After this
  batch a 2-variant project — **entirely ordinary; the module exists to compare variants** — produces
  a 2.9 MB evidentiary document that prints a 2 MiB cap. The batch would ship having narrowed the
  false assertion while leaving the false assertion. The architect's A-1 "If REJECTED" clause
  (`:677`) already rules that in the unbounded case the marker "**must** be reworded to scope its
  claim to the hexdump blocks it actually governs" — the document *is* still unbounded, so that
  clause's condition holds even though A-1 was accepted.
- **Recommendation:** in scope for this batch, as a one-line change with one golden touch:
  `f"{omitted_blocks} hexdump block(s) omitted (hexdump budget: {REPORT_MAX_TOTAL_BYTES} bytes for
  the whole document; the document itself is not bounded — see the Truncation appendix)"` — or any
  wording that scopes the claim to hexdump blocks. Add an AT that asserts **no marker in the emitted
  document claims a whole-document size bound**. Keep the variant axis as a carry, but the *claim*
  must not outrun the *mechanism* in the batch whose thesis that is.

---

### F3 — the Address cell is unbounded; one entry still produces a 0.48×-budget row after both new caps  [Severity: **MAJOR**]

- **What:** `_parse_address` (`s19_app/tui/changes/io.py:952-957`) accepts a JSON string matching
  `^0x[0-9A-Fa-f]+$` — `+`, no upper bound — or any non-negative JSON integer, with no ceiling
  anywhere (`grep -rn "ADDRESS_CEILING\|MAX_ADDRESS\|address >" s19_app/tui/changes/` → only the
  `raw_address >= 0` sign check). `_modifications_lines:995` and `_checklist_lines:1170` render it
  as `f"0x{entry.address_start:08X}"`, unbounded. Entries outside the image are **not** dropped —
  they render with a `skipped-*` disposition. Executed through the shipped emitter:

  ```
  budget = 2,097,152 B;  row cap = 500 (batch-63);  REPORT_CELL_BYTES = 64 (batch-63)
    address literal '0x'+'F'*8         -> ONE row =        63 B (0.00x budget)
    address literal '0x'+'F'*1000      -> ONE row =     1,055 B (0.00x budget)
    address literal '0x'+'F'*100000    -> ONE row =   100,055 B (0.05x budget)
    address literal '0x'+'F'*1000000   -> ONE row = 1,000,055 B (0.48x budget)
  ```

  (`scratchpad/x63/sec5_address_cell.py`.) Three such entries breach 2 MiB; 500 of them —
  **exactly at the new cap, so the cap never fires** — produce ~500 MB. The same value reaches
  `_declaration_error_lines` via `line += f" @ 0x{issue.address:X}"` (`report_service.py:1064`) and
  the addendum at `:1500`/`:1520`, both likewise unbounded.
- **Where:** `s19_app/tui/changes/io.py:235` (`_ADDRESS_RE`), `:952-957`;
  `s19_app/tui/services/report_service.py:995`, `:1170`, `:1064`.
- **Why it matters:** the alphabet is closed (verified: `set(cell) - set("0123456789ABCDEFx") == []`
  at every size), so this is invisible to every grammar-based control — it is the **C-13 reuse-transfer
  trap the architect names in §1.3, recurring on a cell A-1 does not cover**. R-TUI-091's HLR would
  be satisfied while its why-clause ("a single change entry can no longer produce a report larger
  than the byte budget it declares", `:451`) remains false. AT-171 in the qa catalog
  ("a single variant's worst-case contribution is bounded") would be a **vacuous** guard: it fixes
  the address width in its fixture, so it cannot fail on this axis.
- **Recommendation:** pick one and state it — do not leave it unexamined, because F2's whole point is
  that unstated residuals are what make markers lie.
  (a) **Preferred, cheapest, closes it at the source:** bound the address at the parse layer —
  reject `raw_address >= 2**64` (or `len(literal) > 18`) with an existing `CHG-ADDRESS-SYNTAX`
  issue. This is the same shape as `MF_RUN_LENGTH_CEILING`/`MF_ENTRY_COUNT_CEILING`, which A-1 leans
  on as "the schema's own declared input domain"; the address field is the one member of that domain
  with no ceiling.
  (b) Bound the *cell* the way A-1 bounds the byte cell, keeping the alphabet closed.
  (c) Record it as an explicit MAJOR carry with a measured figure. Acceptable only if F2's marker is
  reworded, so the document does not claim a bound this defeats.

---

### F4 — appendix-entry forgery via `variant_id`, on a signal this batch promotes to authoritative  [Severity: **MAJOR**]

- **What:** R-TUI-092 exists so that "*an absent `## Truncation appendix` is a sound 'nothing was
  cut' signal*" (LLR-092.2, `:639`). The shipped note template
  (`report_service.py:1337-1340`) is `f"Variant '{md_safe(variant_id, …)}': {text}."`, emitted as a
  list item at `:1677`. `variant_id` is a **filename stem** (`s19_app/tui/workspace.py:485`) — i.e.
  fully file-derived. `md_safe` makes it grammar-inert but *not* semantically inert: escapes render
  invisibly by design, so `\.` reaches the reader as `.`. Executed against the real `md_safe` +
  a `markdown-it` `gfm-like` render:

  ```
  hostile variant_id : "a': 4000 of 4500 modification rows omitted (cap: 500 rows per variant). Variant 'b"
  emitted line       : - Variant 'a': 4000 of 4500 modification rows omitted (cap: 500 rows per variant)\. Variant 'b': 3 of 503 modification rows omitted (cap: 500 rows per variant).
  RENDERED TO READER : Variant 'a': 4000 of 4500 modification rows omitted (cap: 500 rows per variant). Variant 'b': 3 of 503 modification rows omitted (cap: 500 rows per variant).
  extra <li> emitted?: 1 list item(s)      any live link/html?: False
  ```

  (`scratchpad/x63/sec3_forgery.py`. `:` and `'` are POSIX-legal in filenames; on Windows a
  `:`-free variant reads just as plausibly.) **The complementary direction is safe and I verified
  it:** a hostile *table cell* cannot forge an in-section `> TRUNCATED:` marker — `>` is escaped and
  a cell cannot reach column 0; no `<blockquote>` in the rendered HTML.
  The batch-62 carry F7 is unchanged and still live: `md_safe("X… (truncated)")` returns its input
  unchanged and a genuine truncation ends with the identical marker (both executed).
- **Where:** `report_service.py:1337-1340`, `:1357-1360`, `:1677`; `s19_app/tui/workspace.py:485`.
- **Why it matters:** batch-63 adds **three** new mechanisms writing into this one appendix and makes
  its absence load-bearing. Raising a signal to "authoritative" while its entries remain forgeable in
  the view a human actually reads is the same class as M-2 — the document says something a reader
  trusts and the mechanism does not support. Blast radius is bounded (no link, no script, no extra
  list item, machine counts still correct), which is why this is MAJOR and not a blocker.
- **Recommendation:** one of, decided rather than defaulted —
  (a) **delimit the id visually**: emit `` - Variant `{md_code(variant_id)}`: {text}. `` — Mode B is
  permitted outside a table cell (truth table, `markdown_safety.py:12-19`) and the module already
  does exactly this for `check.source_path` at `:1148`. Inside a code span the injected prose is
  visibly part of the name. Costs one golden (`test_tc389_truncation_appendix_note_is_escaped`).
  (b) **make the entry machine-shaped**, counts first, id last and quoted:
  `- modification rows: 3 of 503 omitted (cap: 500 per variant) — variant: '…'`.
  Either way, add the assertion to qa's AT-175: **the number of appendix entries equals the number of
  fired mechanisms** (it already counts exact strings — extend it with a hostile-id arm so the count
  is proven immune, not merely observed).

---

### F5 — LLR-091.2 does not require slicing BEFORE formatting; the naive reading is a self-inflicted DoS  [Severity: **MAJOR**]

- **What:** LLR-091.2 (`:600-604`) says `_format_bytes` "shall render at most `limit` tokens and
  nothing else". Both `itertools.islice(values, limit)` and
  `" ".join(...)[: limit * 3 - 1]` satisfy that sentence. Measured on a 1 MiB run at `limit = 64`:

  ```
    slice-then-format        0.02 ms   out=191 chars   peak intermediate ~= 192 B
    format-then-slice      155.91 ms   out=191 chars   peak intermediate ~= 3,145,728 B
  ```

  (`scratchpad/x63/sec4_length_and_cost.py`.) At the cap that is 2 000 byte cells per variant
  (500 rows × 2 cells, both tables) → **~312 s of CPU and 6.3 GB of transient allocation for a single
  variant**, on input that is inside the change schema's declared domain. Both tails are identical,
  so no test asserting the *output* can tell the two implementations apart.
- **Where:** `01-requirements-architect.md:600-604` (LLR-091.2); `report_service.py:430-448`.
- **Why it matters:** the batch exists to remove a resource-exhaustion path. Shipping a bound whose
  enforcement costs more than the unbounded emission did on the same input would convert a
  disk/size DoS into a CPU DoS, and every acceptance test would stay green. `_format_bytes`'s
  signature is `Optional[Iterable[int]]`, so `values[:limit]` is not even generally available —
  which makes the join-then-slice form the *likely* accident.
- **Recommendation:** make it normative in LLR-091.2: "shall consume **at most `limit` elements** of
  `values` (`itertools.islice`), so the bound is enforced before formatting rather than after". Add
  a white-box TC that passes a generator and asserts **at most `limit + 1` elements were consumed** —
  that is the only assertion that can distinguish the two implementations. Note the truncation
  *count* (LLR-091.3's `k`) then needs `len(values)`, which the four shipped call sites supply as
  tuples; state that dependency rather than leaving it to be discovered.

---

### F6 — evidence deletion: the mandated marker text points at a section that does not hold the bytes  [Severity: **MAJOR** — corroborates qa B-5]

- **What:** LLR-091.3 mandates the literal clause "*full bytes in the Memory regions section*"
  (`:611-614`), and §12.3 makes "the tables are an INDEX, `_hexdump_section` is the EVIDENCE" the
  argument that legitimises a 64-byte display bound. Read at source, independently of the qa lane:
  `_applied_regions` (`report_service.py:1180`, consumed at `:1315`) collects
  `if entry.disposition == DISPOSITION_APPLIED` **only**, and no `CheckRunEntry` field reaches it at
  all. `ChangeSummaryEntry.after_bytes` is non-Optional (`changes/model.py:369`), so every
  `blocked` / `skipped-*` entry renders its full declared run into the **After** cell and contributes
  nothing to any hexdump. Even for `applied`, the hexdump materialises only when the variant carries
  a `mem_map`.
- **Where:** `report_service.py:1180-1223`, `:1315`, `:1325-1327`; `changes/model.py:369`, `:674-675`.
- **Why it matters:** for a blocked 128-byte patch entry, or a **failing** 128-byte calibration
  check, a 64-byte bound deletes bytes that exist nowhere else in the document, while the document
  states in writing that they are recoverable. In an audit record that is worse than the unbounded
  case, because it is silent and specific. It is M-2's own class, reintroduced by M-2's fix.
- **Recommendation:** as qa states — either scope the marker text to what it can honour (emit the
  pointer clause only on an `applied` + `mem_map` fixture) **or** raise `REPORT_CELL_BYTES` above the
  legitimate check/patch run width and re-derive the pair. **The security-relevant addition from my
  lane:** whichever is chosen, the *architect* must re-rule §12.3, because "index vs evidence" is the
  sole justification for the bound's magnitude — if the premise is false for most rows, the value 64
  loses its anchor and reverts to being a taste call. Add an AT that **asserts the marker's own
  pointer resolves**; a marker whose claim is never checked is how this class recurs.

---

### F7 — the appendix note's escaping is normative only in the qa catalog, not in the architect spec  [Severity: **MINOR**]

- **What:** R-TUI-092(a) (`:382-384`) requires the appendix entry to "name the affected variant" and
  LLR-092.1 (`:631-636`) requires mirroring `_hexdump_section`'s contract — **neither says the
  variant id must be escaped**. Only the qa catalog carries it, at the TC layer (`TC-402`, `TC-410`,
  `01b-qa-catalog.md:434,442`). The shipped precedent does escape (`report_service.py:1338`).
- **Why it matters:** three new emitters gain a notes channel in one batch. The safety property is
  covered by locked R-TUI-077 in general, but an HLR/LLR that names the field and omits its escaping
  requirement is exactly where a per-site `limit` gets forgotten — batch-62 M-5's failure mode.
- **Recommendation:** add to LLR-092.1: "…and every file-derived value in a note **shall** be
  escaped via `md_safe` with an explicit `limit`, per R-TUI-077." One sentence.

---

### F8 — R-TUI-077's exclusion text understates `_format_bytes`'s actual alphabet  [Severity: **MINOR**]

- **What:** `REQUIREMENTS.md:4780-4782` excludes `_format_bytes` as "hex digits and spaces only".
  Executed over every reachable input:

  ```
  None            -> '-'      outside "0123456789ABCDEF ": ['-']   (documented, inert)
  empty tuple     -> ''       outside: []                          (renders an EMPTY cell)
  0..255          -> CLOSED   outside: []
  bytes/bytearray -> CLOSED   generator -> CLOSED   bool -> CLOSED
  ```
  (`scratchpad/x63/sec1_alphabet.py`.) The requirement's own words do not cover the `-` it emits.
- **Why it matters:** B-1 makes this exclusion load-bearing for the whole batch. A requirement whose
  text is narrower than the code is the thing a future reviewer checks against.
- **Recommendation:** while R-TUI-077's row is being touched for `R-TUI-089…092`, correct the phrase
  to "two-hex-digit tokens and spaces, or `-` when no run was captured". `-` is not in `MD_ESCAPE`
  and cannot start a block inside a cell, so no behaviour changes.

---

### F9 — first-N-in-document-order is an attacker-selectable cut; only the aggregates line reconciles it  [Severity: **MINOR**]

- **What:** LLR-089.2/090.2 cut the **first** `CAP` rows in document order. A party who controls the
  change/check document controls which rows survive: place the entries that matter at position 501+
  and they appear in **no table row** — and if the variant also exceeds 128 applied regions, in **no
  hexdump either** (`REPORT_MAX_REGIONS_PER_VARIANT`, also first-N in document order,
  `report_service.py:1329-1331`). For a checklist this means every `fail` can be pushed past the cut
  while 500 `pass` rows render.
- **Mitigation that already exists, verified:** the per-file aggregates line is **pre-cut and
  pre-filter** (`_checklist_lines:1156-1158`, `check.aggregates` is producer-supplied) and
  `_modified_files_lines:909` prints `summary.counts[applied]`, also pre-cut. So a reader comparing
  "Failed: 37" against 0 visible failing rows can detect it — **if they know to**. Truth-table row K7
  makes this reconciliation normative; nothing states it in the document the reader holds.
- **Recommendation:** two cheap, non-blocking improvements. (1) Say the ordering in the marker:
  `> TRUNCATED: {omitted} of {total} … omitted (cap: {cap} rows per variant; the **first** {cap} in
  document order are shown)`. A reader currently cannot tell whether the cut was head, tail or
  sampled. (2) Raise, as an architect question rather than a requirement: should the checklist cut
  **prefer `fail`/`uncheckable` rows over `pass`**? It keeps the row *count* deterministic (the
  property §1.2 defends) while removing the suppression primitive. If declined, decline it in
  writing — it is the single highest-value evidentiary decision left in this batch.

---

## Things I checked and found SOUND — do not weaken these in the rework

| # | claim | verdict | evidence |
|---|---|---|---|
| S-1 | `_format_bytes`'s alphabet is closed for every input reachable through the shipped path | **SOUND** | `sec1_alphabet.py`: 0..255, `bytes`, `bytearray`, generators, `bool` all CLOSED. Values outside 0..255 are **unreachable by construction**: `encoded_bytes` comes from `str.encode()` (`changes/io.py:1095`) or 2-hex-digit tokens validated by `_BYTES_TOKEN_RE` (`:1152-1179`); `before/actual_bytes` are memory-map reads. Non-`int` inputs raise `ValueError` and **abort report generation — fail-closed, which is the correct posture** and matches `md_safe`'s D-18 propagate rule. |
| S-2 | D-15 (indicator outside the cell) is the right ruling | **SOUND, and I would have ruled the same** | Trading a proven structural invariant (closed alphabet ⇒ inert by construction) for a formatting convenience is backwards. §12.2's reasoning is correct and its I-0 transcript reproduces on my tree. |
| S-3 | the new marker text interpolates no file-derived value | **SOUND** | LLR-089.3 (`:551`), LLR-090.4 (`:582`), LLR-091.3 (`:611-614`): every substitution is an `int` count or a module constant. The only file-derived value anywhere in the new output is `variant_id` in the appendix note → F4/F7. |
| S-4 | the `Length` column is a faithful corroborator and cannot carry hostile text | **SOUND** | `addressed_range` = `(address, address + len(encoded_bytes))` (`changes/model.py:185`), so `address_end - address_start` **is** the run length by construction, for all four byte fields. Bounded by `MF_RUN_LENGTH_CEILING` ⇒ ≤ 7 digits. Digits-only, non-negative (`_parse_address` rejects negatives, `io.py:956`). A negative would print `-`, but is unreachable. |
| S-5 | a hostile table cell cannot forge an in-section `> TRUNCATED:` marker | **SOUND** | `sec3_forgery.py` §A: `>` is escaped, a cell cannot reach column 0, no `<blockquote>` in the render. |
| S-6 | the two-constants ruling, the row-cap shape, and §1.3's refutation | **SOUND** | Not re-litigated; §0.1–§0.9 reproduce. |

---

## Standard checklist sections that do not apply to this batch

| section | status | evidence |
|---|---|---|
| Secrets & credentials | **N/A / clean** | `grep -rniE "C:\\\\Users\|/home/[a-z]\|AppData\|api[_-]?key\|token\|secret\|password\|BEGIN .*PRIVATE KEY" .dev-flow/2026-07-26-batch-63/` → only false positives on the word "token" used for hex tokens. No `.env`, no credential, no key material in scope. |
| External tool / MCP / Composio | **N/A** | No connector, no outbound call, no new external action surface. `markdown_safety.py` is a stdlib-only leaf. |
| Auth flows | **N/A** | No auth surface in this module. |
| Destructive commands | **N/A** | Composer writes one new `.md` under `reports/`; no delete, no overwrite of existing artifacts (`_report_filename` resolves same-second collisions, `report_service.py:451`). |
| Dependencies / supply chain | **N/A** | No new package; no lockfile change. |
| Deploy / release | **N/A** | Library batch; no deploy surface. |
| Frozen-file guard | **CLEAN** | Touched set = `s19_app/tui/services/report_service.py`, `tests/*`, `REQUIREMENTS.md`. `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-130`) = `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` — **no intersection**. |
| Pre-existing host-path exposure (batch-62 D-11, withdrawn) | **UNCHANGED, carried** | `md_code(check.source_path)` (`:1148`) and `md_code(summary.source_path)` (`:904`) still emit absolute operator paths into the exported document. batch-63 neither worsens nor fixes it; no new note embeds a path. Remains a named MAJOR carry. |

---

## Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|:--:|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | B-1, F2–F9 all four-part. |
| 2 | Each finding has a severity rating | ✓ | 1 BLOCKER · 5 MAJOR · 3 MINOR. |
| 3 | No secret values appear in this output | ✓ | No credential material exists in scope; the secrets sweep above returned only hex-"token" false positives, and no matched line is reproduced. |
| 4 | Verdict is explicit | ✓ | **Block** — §Verdict. |
| 5 | New tool/integration scope + blast radius addressed | ✓ (N/A) | None added — table above; stated rather than omitted. |
| 6 | Claims executed, not reasoned to | ✓ | 4 probes, all transcripts pasted: `sec1_alphabet.py` (S-1/F8) · `sec2_residual.py` (F2) · `sec3_forgery.py` (F4/S-5) · `sec4_length_and_cost.py` + `sec5_address_cell.py` (F5/F3/S-4). |
| 7 | The specific ruling I was asked to attack (D-15) was verified end to end | ✓ | Alphabet closure over 19 input classes incl. `None`, empty runs, out-of-range and non-`int`; reachability traced to `changes/io.py:1095,1179` and `apply.py:334`; marker text audited for file-derived interpolation; `Length` provenance traced to `changes/model.py:185`. |
| 8 | Worktree not mutated | ✓ | All probes ran in `…/scratchpad/x63`, a `git archive HEAD` export. `git status --porcelain` → `M .dev-flow/state.json`, `?? .dev-flow/2026-07-26-batch-63/` only (unchanged from session start). |
| 9 | `MAX_VARIANTS` absence independently re-verified, not inherited | ✓ | `grep -rn "MAX_VARIANT\|max_variants\|MAX_PROJECT_FILES\|len(variants) >" s19_app/` → 0 hits. |
| 10 | Overlap with the qa lane reconciled, not merged or averaged | ✓ | B-1 ≙ qa B-3 (different documents, both edits required); F6 ≙ qa B-5 (corroborated at source, plus the §12.3 re-ruling ask). F2/F3/F4/F5/F9 are not in the qa review. |
| 11 | Frozen-file set checked against the touched set | ✓ | Row above; `tests/test_engine_unchanged.py:120-130`. |
| 12 | A finding was measured against the batch's OWN premise, not a generic rule | ✓ | F2: the batch's thesis is "a marker asserting an unhonoured bound is worse than no bound"; measured 2 variants → 1.39× budget with the marker fired. |
| 13 | Every probe predicate stated so a false-GREEN is visible (project P-3 lesson) | ✓ | Alphabet predicate = `set(out) - set("0123456789ABCDEF ")` printed per case, not summarised. Marker predicate = exact literal `(report size cap: {REPORT_MAX_TOTAL_BYTES} bytes)` matched against the on-disk text, with `over_budget` printed independently so a fired-and-under case would be visible. Forgery predicate = rendered HTML with tags stripped, i.e. **what the reader sees**, plus `<li>` count and link presence separately. |

---

## Verdict

- [ ] OK to ship
- [ ] OK to ship with the listed mitigations applied first
- [x] **Block — must fix the BLOCKER before Phase 3**

**Blocking:** **B-1**. The normative spec contradicts its own security ruling inside the `shall`
chain. Fix the four statements + the two false "Unchanged" claims + the three qa-catalog nodes, then
this lane clears on that axis.

**Required before merge (not blocking Phase 3 entry, but blocking the merge gate):**
- **F2** — reword `_hexdump_section`'s marker, or the batch ships the defect it exists to fix. This
  is the operator's headline question and my answer is: **the marker still asserts something false**.
- **F3** — rule the address axis: bound it, or record it as a measured MAJOR carry. Not both silent.
- **F6** — architect must re-rule §12.3; the value 64 loses its anchor if "index vs evidence" is
  false for most rows.

**Recommended, non-blocking:** F4 (pick a mitigation, do not default), F5 (one normative sentence +
one generator TC), F7, F8, F9.

**Returned to the operator?** No. Every blocker and major here is a spec edit inside the batch's own
scope, decidable by the architect lane. Nothing requires vendor documentation, a permission change,
or an authorisation I do not have.
