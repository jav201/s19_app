# 02 — Phase-2 architect review · batch-62 `report_service` markdown escaping

- **Reviewer role:** Phase-2 architect (adversarial; did not author the Phase-1 spec)
- **Base:** `claude/batch-62-report-escaping` @ `8d3c504` · **Language:** English
- **Method:** every ruling below was re-verified on disk or by an executed probe. Where I could
  not refute a Phase-1 claim, I say what I checked.
- **Probe environment:** Python 3.14, `markdown_it` 4.2.0, tree at `8d3c504`.

---

## §0 BLUF — VERDICT: **FAIL. Iterate to Phase 1.**

| Severity | Count |
|---|---|
| **blocker** | **7** |
| major | 8 |
| minor | 7 |

**The design core is sound and survives adversarial re-measurement.** D-4 (leaf module), D-5's
ordering claim, D-6, and — most importantly — **R-1/Mode B, the batch's highest-risk item — all
hold under independent execution.** I could not refute any of them.

**What fails is the layer above the design: the normative thresholds and the ID registry.** Four
of the five carried blockers are ruled correctly in substance; the artifacts that encode those
rulings contain measurable falsehoods that a Phase-3 implementation would trip on:

1. **The golden drift is 3 lines, not 2** — the spec's exact-count threshold would go RED on a
   *correct* implementation (the `b.s19` inventory row was missed).
2. **"The benign no-op arm still holds" is false** — `SYM_A` → `SYM\_A`, measured. Three assertion
   sites break across two files, one of which is not declared as a C-27 target.
3. **The TC registry ruling (D-3) is unimplementable** — the architect's `TC-376…387` are twelve
   *undefined* identifiers; qa's `TC-376…387` are twelve *defined* tests. There is no mapping.
4. **The mandated assertion helper contradicts the adopted design** — its "payload characters
   still present" clause fails against `md_safe`'s backtick **removal**, and payload #9 is a
   backtick payload that TC-377 parametrises individually.

This is the batch-60 failure mode repeating one level up: batch-60's operator decision was
unimplementable *at the wire point*; batch-62's decisions are implementable, but three of their
**acceptance thresholds are false against the shipped artifact**. Same class, different layer.

**Fix cost is low.** No blocker requires re-deciding the architecture. Six are threshold/registry
corrections; one (B-5) is a missing ruling I supply below. Phase 1 should be able to close all
seven in a single revision.

---

## §1 Rulings on A.1 – A.5 (the five carried blockers)

### A.1 — `_MD_ESCAPE` leaks block starters (`-`, `+`, `=`) · **BLOCKER B-5 — NO RULING EXISTS**

**Verified on disk.** `s19_app/tui/services/flow_report_service.py:120`:

```
_MD_ESCAPE = ("\\", "|", "*", "_", "[", "]", "<", ">", "#", "~", "/", ".", "@")
```

No `-`, `+`, `=`. The newline collapse is at `flow_report_service.py:173`
(`text.replace("\r"," ").replace("\n"," ").replace("\t"," ")`) and runs **before** everything
else — so the coupling is real and load-bearing exactly as §3 item 1 states.

**The disposition is missing.** Canonical §3 item 1 ends *"Pin it, or fix the escape set"* — that
restates the open question. **D-1…D-9 contain no ruling on it**, and no LLR in
`01-requirements-architect.md` §9 covers it. LLR-095.1's threshold ("byte-equals the current
`_md_safe` on a ≥30-case corpus") is a characterisation test whose corpus is unspecified — it pins
the collapse only if someone happens to include a newline case. That is not a pin.

**My ruling (supplied, since Phase 1 did not make one): KEEP the collapse; do NOT extend the
escape set; PIN it three ways.**

- *Why not extend the set:* `-` is escapable (`\-`) but it is a hyphen, not a rarity — `mac-linked`
  (`report_service.py:987`, measured no-op today) would become `mac\-linked`, and every kebab-case
  identifier in the report acquires visible noise. Escaping a character to defuse a **line-start**
  construct is over-broad by two orders of magnitude. This is the same reasoning the architect
  correctly applied to `.` in P-11, applied consistently.
- *Why the collapse is sufficient:* I independently re-derived qa's column-0 reachability claim by
  reading every emission site. **Every** file-derived interpolation in `report_service.py` carries a
  literal prefix — `# `, `## `, `#### `, `### `, `- `, `| `, or `saved as \``. With newlines
  collapsed, a field cannot reach column 0, so no single-line block starter can fire.
- *The pin, three parts:*
  1. **Normative LLR (new):** `md_safe` **shall** collapse `\r`, `\n`, `\t` to a single space
     **before** truncation and escaping, and its docstring **shall** record that this collapse —
     not the escape set — is the control that defuses block starters (`-`, `+`, `=`, `>`, digits+`.`,
     indented code).
  2. **Counterfactual TC:** delete the collapse line → the test goes RED. qa's TC-380 already
     specifies exactly this; it must be promoted from a qa-catalog case to a normative threshold.
  3. **Static guard (new, mechanically checkable):** assert that every `md_safe(` / `md_code(` call
     site in `report_service.py` sits in a line template whose text before the interpolation is
     non-empty. This is what keeps the *second* half of the argument true as the module evolves —
     the collapse alone does not protect a field emitted at column 0.

**Verdict: BLOCKER (unruled).** Implementable at the named seam; ruling supplied above.

---

### A.2 — Code-span breakout at `report_service.py:901` · **PASS** (1 minor)

**Verified on disk.** `report_service.py:901`:

```python
bullet += f" - saved as `{summary.saved_path}`"
```

The backticks are **literal, already in the f-string**. Disposition = Mode B (`md_code`:
ctl-strip → newline collapse → backtick **removal** → truncate, **no escaping**).

**Can the fix land at this line?** Yes — it is a one-token change (`{summary.saved_path}` →
`{md_code(summary.saved_path)}`); the wrap already exists. I confirmed the breakout closure
mechanism is backtick *removal* (`flow_report_service.py:175`,
`text = text.replace("\`", "")`), which is inherited by Mode B by construction.

**Minor (m-3):** LLR-097.1 says all three path fields "**shall** be emitted wrapped in a single-
backtick code span". At `:901` the wrap **already exists** (adding one would double it); at `:897`
and `:1097` it must be **added**. The LLR conflates the two cases. Reword per-field.

**Verdict: correct, sufficient, implementable as specified.**

---

### A.3 — `md_safe` non-idempotence → exactly-once obligation · **MAJOR M-4 — insufficient**

**Verified by probe.** `md_safe('a.s19')` → `'a\.s19'` → `'a\\\.s19'`. Non-idempotent, as stated.

**The disposition is a category error.** LLR-098.2 requires a test asserting
`md_safe(md_safe(x)) != md_safe(x)`. That test **documents a property of the helper**. It does not
and cannot detect double application **in the composer** — the actual defect class (R-3). The only
other control is LLR-095.3's prose "exactly once, at its line-assembly site", and LLR-095.3's
static census ("0 un-wrapped file-derived interpolations remain") detects **under**-application
only. **Over-application has no detector at all.**

**Required replacement (mechanically checkable, one predicate, catches both directions):**

> For a benign escapable value `v` planted at each file-derived site, the emitted line **shall**
> contain `md_safe(v)` and **shall not** contain `md_safe(md_safe(v))`.

Concretely: plant `SYM_A`; the Modifications row must contain `SYM\_A` and must not contain
`SYM\\\_A`. This is black-box at the shipped surface, so it is an **AT, not a TC** — see
**AT-163 (new)** in §6. C-21 fires: the increment cut is re-derived below.

**Verdict: MAJOR — disposition correct in intent, insufficient as specified.**

---

### A.4 — `_DEFAULT_MESSAGE_MAX_LENGTH = 500` vs `MAX_REPORT_CELL_CHARS = 240` · **MAJOR M-5 — correct but under-scoped**

**Verified on disk.** `s19_app/validation/model.py:22` → `_DEFAULT_MESSAGE_MAX_LENGTH = 500`;
`flow_report_service.py:78` → `MAX_REPORT_CELL_CHARS = 240`. The conflict is real and LLR-098.3's
fix (explicit `limit >= 500` at `_declaration_error_lines`) is correct and implementable.

**It closes one of at least six instances of the same defect.** I read
`ValidationIssue.__post_init__` (`validation/model.py:~135`) — **it scrubs `message` only**:

```python
def __post_init__(self) -> None:
    self.message = _scrub_issue_message(self.message)
```

`code`, `symbol`, and `related_artifacts` are **neither scrubbed nor capped** upstream. Neither is
`project_name`, `variant_id`, or `descriptor.file_type`. Every one of them is emitted **whole**
today and would be **silently truncated at 240** by `md_safe`'s default — introducing data loss
into an evidentiary document at ~6 sites while fixing it at 1.

**Second, unflagged instance — and this one is a golden hazard, i.e. R-1's family.** Mode B's
default limit is also 240. `str(summary.source_path)` on a pytest tmp root is
`C:\Users\<user>\AppData\Local\Temp\pytest-of-<user>\pytest-N\<testname>0\.s19tool\workarea\proj\chg.json`
— comfortably under 240 today, but **whether truncation fires depends on the operator's tmp-root
depth and username length**. A deeper root on one machine truncates the path; on CI it does not.
That is a machine-dependent golden — the exact failure mode CN-6 exists to prevent, arriving
through a different door.

**Required:** state truncation as a **policy**, not a per-field patch —
(a) Mode A: explicit `limit` at every site, defaulting to the field's own upstream cap where one
exists (500 for `message`, 80 for `region.name`) and to a stated report-wide cap otherwise;
(b) Mode B: **no truncation**, or a limit pinned above `MAX_PATH` (260) with a test proving a
run-root of realistic depth does not trip it.

**Verdict: MAJOR — correct as far as it goes; the policy gap is larger than the one field fixed.**

---

### A.5 — R-1, `canonical_report_bytes` and Mode B · **PASS — verified end-to-end. This is the spec's strongest ruling.**

**Verified on disk.** `tests/conftest.py:967` →
`_RUN_ROOT_SPAN_RE = re.compile(rb"<RUN-ROOT>[^\s\`\"'|)\]]*")` — the exclusion class **contains
the backtick**. `canonical_report_bytes` body (`:1013-1019`): CRLF undo → replace `str(run_root)`
and `str(run_root.resolve())` verbatim, longest-first → normalise `\`→`/` **inside spans only**.

**Executed trace, both modes, real helper, real canonicaliser:**

```
MODE B  -> - `<RUN-ROOT>/.s19tool/workarea/proj/chg.json` (applied entries: 1)
             - saved as `<RUN-ROOT>/.s19tool/workarea/proj/a-patched.s19`
MODE A  -> - C:\\Users\\op\\AppData\\Local\\Temp\\pytest-of-op\\pytest-9\\test\_x0\\\.s19tool\\...\\chg\.json
MODE A leaks drive letter: True
MODE B leaks drive letter: False
```

**Mode B is sufficient, and I can state exactly why:** the substitution is a **raw byte replace**
of `str(run_root)`, so any transformation that rewrites path bytes before the write defeats it.
Mode B rewrites nothing on a benign path (ctl-strip, newline collapse, backtick removal and
truncation are all no-ops), so the substring survives; the span regex then terminates cleanly on
the **closing backtick**, which is already in its exclusion class — no regex change is needed.
Mode A escapes `\`, `.`, `/` and `_`, destroying both the substring **and** the separator
normalisation, leaking `C:\Users\op\...` into the compared bytes. **The architect's ruling is
correct and the mechanism is load-bearing exactly as claimed.**

**Two riders, both cheap:**
- **Promote the R-1 check from a risk note to a normative AT predicate.** LLR-098.1 currently
  carries it as `assumed — verify in Phase 3`. The predicate should be mode-agnostic and stated
  once: *`canonical_report_bytes(raw, run_root)` **shall** contain `RUN_ROOT_TOKEN` and **shall
  not** match `[A-Za-z]:[\\/]` nor contain the operator's home-directory name.* Written that way
  it also becomes the mechanical guard B-6 asks for — it fires regardless of which mode a future
  field picks. → **AT-162 (re-scoped normative).**
- See M-5 above: Mode B's 240 truncation is the one path by which R-1 can still re-enter.

**Verdict: PASS. The single highest-risk item in this batch is correctly ruled and independently
confirmed.**

---

## §2 Ruling on **B** — D-4, the `markdown_safety.py` leaf module

### B.1 Circular-import claim — **VERIFIED**

```
s19_app/tui/services/flow_report_service.py:63  → from .report_service import (...)
s19_app/tui/services/diff_report_service.py:97  → from .report_service import (...)
```

Both confirmed on disk. A top-level `from .flow_report_service import _md_safe` inside
`report_service` is a hard cycle. The precedent wart is real and its own comment says so —
**`report_service.py:965-968`** (the architect cites `:974-976`; see m-7):

```python
# Deferred import: ``diff_report_service`` imports from this module at load
# time, so a top-level import of ``_md_table_cell`` would be a circular
# import — resolve it lazily here, where both modules are fully loaded.
from .diff_report_service import _md_table_cell
```

**Correction to the rationale (not the conclusion):** `report_service` is **not** "the base of the
service import DAG" — it imports `entropy_service`, `report_addendum`, `report_filter`,
`variant_execution_service`, and `..models` (`report_service.py:52-60`). It is an *upstream* node
relative to the two report generators, which is all the argument needs. The looser claim is
harmless but should be corrected so a later reader does not build on it.

### B.2 Is a leaf module correct? — **YES**

`md_safe`/`md_code` need only `str`; no `re`, no service imports. The leaf is achievable, the move
is reversible (move + alias), and all three service files are outside both frozen guards
(`tests/test_engine_unchanged.py:120-130`; `tests/test_tui_directionb.py:5443-5454`) — I confirmed
none of `report_service.py`, `flow_report_service.py`, `diff_report_service.py`,
`markdown_safety.py` is in either set. **No new problem is created**, with one caveat:

**Minor (m-6):** moving `MAX_REPORT_CELL_CHARS` into the shared leaf couples two consumers' cap
*policy* to one constant, and LLR-098.3 **already establishes that report_service needs a different
limit**. The leaf should export the *functions* (with a required-or-explicit `limit`) and let each
consumer own its cap; `flow_report_service` keeps `MAX_REPORT_CELL_CHARS = 240` as its own.

### B.3 Is the two-mode split the right seam? — **YES, but the selection rule is prose · BLOCKER B-6**

The split itself is right, and I re-verified both of its load-bearing measurements:

- **D-6 (Mode B forbidden in table cells) — VERIFIED by probe.** A code span containing a raw `|`
  inside a 2-column table row:
  ```
  td_open count 2 · cells ['`v1', 'INJECTED']
  ```
  The cell splits *and* the backtick is left unbalanced. Mode B genuinely protects grammar, not
  table structure. LLR-097.2's static guard is the right control.
- **P-7 / P-9 (paths need Mode B) — confirmed by the A.5 trace above.**

**The blocker is the selection rule.** §7.2's table is a *definition* table (mode → definition →
applies-to). It is not a decision procedure keyed on observable properties, and the C-36 rider
requires an explicit truth table for any matrix an AT keys on. As written, mode selection is
**24 independent judgement calls**, guarded in one direction only (LLR-097.2 catches
`md_code`-in-a-cell). **Nothing catches the inverse and more dangerous error:** a new
run-root-bearing path field added later takes Mode A by default, silently re-opening R-1 with no
detector. The prose that currently holds the line — *"F-09 is a basename, never contains the run
root"* — is true today (`Path.name`, verified) but is exactly the kind of per-field trust argument
the spec's own "Uniformity note" argues against.

**Required — the truth table, keyed on two observables:**

| Value can contain the run root / an absolute path | Emission context is a table cell | Mode | Rationale |
|---|---|---|---|
| no | no | **A** | grammar escape; readable |
| no | yes | **A** | `\|` is in `MD_ESCAPE` at index 1, `\` at 0 — one pass |
| yes | no | **B** | CN-6 raw-byte substitution + P-7 readability |
| yes | **yes** | **FORBIDDEN** | Mode B splits the cell (measured); Mode A breaks CN-6. **No such site exists today; adding one requires an ADR.** |

Plus **AT-162's re-scoped residue predicate** (§1 A.5) as the mode-agnostic backstop — it is the
one assertion that stays true no matter how a future field is classified.

**Verdict: leaf module correct; two-mode split correct; selection rule is a BLOCKER until it is a
truth table with a mechanical backstop.**

---

## §3 Ruling on **C** — D-5, removing `_md_table_cell` at `report_service.py:978`

### C.1 The ordering claim — **VERIFIED**

```
_MD_ESCAPE = ('\\', '|', '*', '_', '[', ']', '<', '>', '#', '~', '/', '.', '@')
index of '\\' = 0 · index of '|' = 1
```

`_md_safe` (`flow_report_service.py:179-180`) replaces **in tuple order**, so the backslash is
escaped first. `diff_report_service.py:282` `_md_table_cell` is
`_strip_ctl(v).replace("\\","\\\\").replace("|","\\|")` — its docstring
(`diff_report_service.py:283-292`) states the backslash-first ordering is precisely the property it
exists to provide. **`md_safe` is a strict superset on that axis. D-5's core claim holds.**

`_md_table_cell` remains **in use** by `diff_report_service._linkage_table_lines`, so removing the
`report_service` call orphans nothing.

### C.2 The blast radius — **WRONG · BLOCKER B-2**

D-5, LLR-096.1's threshold, and R-4 (severity LOW) all assert *"its benign-no-op arm still holds /
still passes unchanged"*. **Measured:**

```
DRIFT  'SYM_A' -> 'SYM\_A'
```

`_` is at index 3 of `_MD_ESCAPE`. The benign arm **breaks**. And the blast radius is not one file:

| Site | Assertion | Breaks? |
|---|---|---|
| `tests/test_report_symbol_escape.py:166` | `"\| 0x00001000 \| 2 \| 01 02 \| AA BB \| mac-linked \| SYM_A \|" in text` | **YES** |
| `tests/test_report_service.py:260` | same literal | **YES** |
| `tests/test_report_service.py:1403` | same literal | **YES** |
| `tests/test_report_symbol_escape.py:145` (hostile arm) | `"EVIL\\\|SYM\\\\PATHEND" in row` | **YES** — and not only in the escape: `_md_table_cell` **deletes** ctl/newline, `md_safe` **replaces them with a space**, so the expected string becomes `...PATH  END` (two spaces), a semantic change the spec does not mention |
| `tests/test_report_symbol_escape.py:150` (`structural == 7`) | pipe count | no — still 7 (traced by hand) |
| `tests/test_tui_report_filter_surface.py:290` + byte pin `:85` | `_md_table_cell` dependence + byte identity | **likely** — undeclared |

`tests/test_report_service.py` and `tests/test_tui_report_filter_surface.py` appear in **neither**
the canonical §7 test-target declaration ("Extended: `tests/test_report_symbol_escape.py`") nor the
architect's §9 thresholds. **C-27's target declaration is incomplete, and the ≤5-file increment
budget is built on a wrong file count.**

**Is the removal net-safe?** *Yes, on the merits* — `md_safe` strictly dominates `_md_table_cell`
on the security axis, deletes a documented circular-import wart, and eliminates a divergence
surface. **No, as specified** — three of its stated thresholds are false.

**Verdict: BLOCKER on the blast-radius claim; the removal decision itself is correct.**

---

## §4 Ruling on **D** — completeness of the 33-site field inventory

### D.1 My method (stated, per the brief — I did not read their list first)

1. Enumerated **all** interpolation forms in `s19_app/tui/services/report_service.py`, not just
   f-strings: `grep -n 'f"'`, `grep -n '\.format(\|%[sdr]'`, and
   `grep -n 'lines\.append(\|lines\.extend(\|out\.extend(\|notes\.append(\|bullets\.append(\|hits\.append(\|put(\|emit(\|bullet +=\|line +='` filtered to **non**-f-string lines.
2. Result: **`.format()` and `%` interpolation do not occur in the module** (only
   `REPORT_TIMESTAMP_FORMAT` and a docstring match). Every interpolation is an f-string or a
   splat of a rendered block (`*rendered.splitlines()`, `:1197`).
3. Read every composer body end-to-end — `:500-600`, `:690-1130`, `:1180-1210`, `:1260-1340`,
   `:1385-1480`, `:1560-1614` — and classified each interpolated expression by **provenance**
   (operator file / tool clock / package metadata / validated domain / module literal / int).
4. Diffed my set against §5.

### D.2 Result: **no missed file-derived field. The set is complete.**

I confirm all 24 escape-requiring fields and both scope exclusions. Specifically I re-derived and
agree with the four the kickoff hint missed — `issue.message` (`:1026`), `related_artifacts`
(`:1032`), the filter name (`:729`), and the hexdump gutter (`:1197-1200`). I checked the
non-obvious candidates for hidden file provenance and cleared each:

| Candidate | Line | Why it is not a hole |
|---|---|---|
| `check.aggregates.get('passed', 0)` | `:1099-1101` | interpolated directly (not summed) — but the `, 0` default and the aggregate contract keep it int-valued; **flag for a one-line Phase-3 type assertion**, not a spec change |
| `entry.address_end - entry.address_start` | `:984`, `:1114` | arithmetic forces numeric |
| `0x{...:08X}` | `:983`, `:1113`, `:1195` | format spec rejects `str` |
| `label` in the filter header | `:737` | static tuple literal, `:733-736` |
| truncation `text` | `:1276`, `:1293` | ints + module constants |
| `_zero_match_notice(total)` | `:591` | int |

### D.3 Two framing defects (major/minor, not holes)

- **MAJOR M-6 — the `<in-memory document>` literal.** `report_service.py:894` and `:1093` emit the
  module literal `<in-memory document>` when `source_path is None`. It appears in **neither** the
  24-field list nor the 7 "trusted" rows. It is not file-derived, so it is out of US-B62's scope —
  **but I measured it under the default parser:**
  ```
  '- <in-memory document> (applied entries: 1)'   default: [... 'html_inline' ...]   viewer: []
  '#### Checklist: <in-memory document>'          default: ['heading_open','html_inline','heading_close']  viewer: []
  ```
  `<in-memory document>` is a syntactically valid HTML open tag. **AT-158 as written** ("the
  document contains … **zero** `html_inline` / `html_block` tokens") therefore goes **RED on a
  benign fixture even after a perfectly correct fix.** Phase 1 must either (a) scope AT-158's
  html clause to *file-derived provenance* (consistent with its own first clause), or (b) change
  the literal to `(in-memory document)` — which is what `diff_report_service.py:540,1541` already
  uses, making (b) the consistency-restoring choice. **Also unresolved:** whether the Mode-B wrap
  applies to the fallback branch or only the path branch (`source` is one variable holding either).
- **MINOR m-1 — "33 emission sites" is not the emission-site count.** By my enumeration the module
  has roughly **50** interpolating emission sites; 33 is a curated list of *interesting* ones. The
  curation is correct, the label is not. A census test keyed on the literal `33` (LLR-095.3's
  "static census") would be asserting an arbitrary number — it must key on the **24 escape-required
  sites**, which is the set that actually carries meaning.

**Verdict on D: the inventory is COMPLETE. I could not find a missed field with an independent
method. Two framing defects, one of which (M-6) breaks an AT.**

---

## §5 Ruling on **E** — normative hygiene

### E.1 Modal discipline — **PASS**

I read every HLR (§8) and every LLR (§9) statement. **Zero `should` / `may` in any normative
statement.** `shall` only. The architect's self-check holds.

### E.2 Traceability — **one break (MAJOR M-3)**

- Every LLR traces to a parent HLR ✓ (LLR-095.1 has a dual parent HLR-095 + HLR-097 — acceptable,
  and declared in §10).
- **HLR-099 has NO parent US.** §10's functional chain shows `— (anti-regression)` in its US
  column. Every HLR must trace to a US. Either derive it from US-B62-1/2 (the hexdump fence is a
  file-derived surface, so it belongs to US-B62-1/2 naturally) or add an explicit anti-regression
  story. Currently the chain is broken.

### E.3 Three normative contradictions (blocker + 2 major)

| # | Statement | Contradicted by | Sev |
|---|---|---|---|
| **B-7** | **HLR-097:** "no report generator **shall** define its own grammar-escaping helper" | **D-8** explicitly **defers** `diff_report_service._md_cell` / `._md_table_cell`, which escape `\|` and `\` — table-grammar characters. The requirement is **false at merge** by the batch's own ruling. | **blocker** |
| **M-1** | **HLR-098:** "filesystem paths **shall** render without inserted escape characters" | **F-09** (`descriptor.path.name`, `:807`) is a filesystem path component taking **Mode A** → `a.s19` → `a\.s19`, **measured**. | major |
| **M-2** | **HLR-096:** "the rendered cell text **shall** equal the input value verbatim **after control-character removal**" | Three non-ctl transformations violate it: backtick **removal** (`flow_report_service.py:175`), newline→**space** (`:173`), and **truncation** (`:177-178`). | major |

B-7 is a one-clause amendment ("no *new* grammar-escaping helper; `diff_report_service`'s pair is
carried under D-8"). M-1 needs the word "paths" narrowed to *run-root-bearing paths* (the Mode-B
set). M-2 needs the exclusion list made explicit — and M-2 is not cosmetic, because:

### E.4 **BLOCKER B-4 — the mandated assertion helper contradicts the adopted design**

`01b-qa-catalog.md` §3.4 makes **one** helper the single assertion path for every AT and TC:

```python
assert all(ch in "".join(t.content for t in toks) for ch in visible(payload))
```

Two defects, both fatal at Phase 3:

1. **`visible()` is never defined.** An undefined function is doing load-bearing work in the
   batch's only assertion primitive.
2. **The clause contradicts backtick removal.** `md_safe` **deletes** backticks. Payload **#9**
   (`code-span-breakout`, ``a` **PWNED** `b``) is a backtick payload, and **TC-377 parametrises all
   31 payloads individually** — so this fires deterministically. Same for the newline payloads
   (#12–#21, collapsed to spaces) and any over-cap value (truncated).

The clause's *intent* is right and must be kept — it is what forbids "sanitise by deleting". The
correct form asserts against **what the design says survives**, not against the raw payload:

> `assert_field_inert(md, report, marker, payload)` asserts (a) the field's own tokens are all
> `{text, softbreak}`, **and** (b) the joined text equals **`md_safe(payload)` with its escape
> backslashes removed** — i.e. the *specified* survivor set, computed from the design, not from
> the input.

That is the "assert the emitted encoding" control the batch itself prioritised, applied to the
*sanitiser's own contract* rather than to the payload. Written this way it still fails an escaper
that deletes data, because deletion changes `md_safe(payload)` too.

---

## §6 Increment cut (C-18 / C-21)

**C-21 fires.** My findings change the AT set, so the cut is re-derived, not adjusted:

- **AT-157 / AT-158** — re-scoped to *file-derived provenance* (M-6), oracle clause (b) rewritten
  per B-4.
- **AT-159** — adopt **qa's stronger form** (all cells positional, not just the first). I confirm
  D-2's deferred question: the architect's and qa's AT-157/158/159 **are semantically 1:1**; qa's
  AT-159 is strictly stronger and should win.
- **AT-160** — threshold corrected to **3 lines** (see B-1 below).
- **AT-161** — unchanged (hexdump fence).
- **AT-162** — **promoted to normative**, predicate restated as the mode-agnostic canonicaliser-
  residue check (§1 A.5) so it doubles as B-6's backstop.
- **AT-163 — NEW** — exactly-once at the sink (§1 A.3).

**7 ATs. Each owned by exactly one increment. Each increment ≤5 files.**

### Inc-1 — the leaf helper and its battery · **3 files** · owns **no AT** (helper-only)

1. `s19_app/tui/services/markdown_safety.py` — **NEW.** `md_safe`, `md_code`, `MD_ESCAPE`,
   `TRUNCATION_MARKER`. Explicit `limit` parameters (M-5). Docstring records the newline collapse
   as the load-bearing block-starter control (B-5).
2. `s19_app/tui/services/flow_report_service.py` — import + `_md_safe = md_safe`, `_MD_ESCAPE`,
   `_TRUNCATION_MARKER` aliases. `MAX_REPORT_CELL_CHARS = 240` **stays here** (m-6).
   *(Confirmed necessary: `tests/test_flow_report_service.py:33,40` imports both names.)*
3. `tests/test_report_markup_safety.py` — **NEW.** Derived payload set + G-1…G-5, per-payload
   parametrised neutralisation, the **newline-collapse counterfactual**, caps, empty/unicode.

**LLRs:** 095.1, 095.2, 098.2 (revised), + the new collapse-pin LLR.
**Exit:** `tests/test_flow_report_*.py` unmodified, **0** edits, **0** failures.
*Why first:* nothing else can be written against an undefined helper.

### Inc-2 — the golden-affecting sites (tables + paths) · **5 files** · owns **AT-159, AT-160, AT-162, AT-163**

1. `s19_app/tui/services/report_service.py` — F-08…F-16, F-24 (Mode A); F-13/F-14/F-23 (Mode B);
   remove the deferred import at **`:965-968`** and the `_md_table_cell` call at **`:978`**.
2. `tests/goldens/batch35/at055b-project-report.md` — re-capture. **3-line** diff.
3. `tests/test_report_symbol_escape.py` — re-baseline **both** arms with a §6.5 before/after record.
4. `tests/test_report_service.py` — re-baseline `:260` and `:1403`.
5. `tests/test_tui_report_filter_surface.py` — verify/re-baseline the `:85` byte pin and `:290`.

*Why these together:* they are exactly the sites that move the golden. Splitting them leaves the
golden RED across an increment boundary, which violates "stop at a clean boundary".

### Inc-3 — the remaining Mode A sites · **3 files** · owns **AT-157, AT-158**

1. `s19_app/tui/services/report_service.py` — F-01/02 (headings), F-18…F-22 (issues, with the
   explicit `limit`), F-25…F-30; remove `_strip_ctl_local` (`:512`); resolve the
   `<in-memory document>` literal (M-6).
2. `tests/test_report_field_census.py` — **NEW.** The 24-site sweep; the static
   "no un-escaped file-derived interpolation" census; **LLR-097.2**'s md_code-not-in-a-cell guard;
   the **column-0/prefix static guard** (B-5); the **exactly-once AST guard** (A.3).
3. `tests/test_report_progress.py` **or** `tests/test_tui_report_view.py` — only if measured to drift.

### Inc-4 — scope pins and traceability closeout · **2 files** · owns **AT-161**

1. `tests/test_report_markup_safety.py` — AT-161 (all-`0x60` fence → exactly 1 `fence` token in
   both grammars) + the F-17 `_format_bytes` inertness pin.
2. `REQUIREMENTS.md` — `R-*` rows for the new surface.

---

## §7 Finding register

### Blockers (7) — each forces iterate to Phase 1

| # | Finding | Evidence |
|---|---|---|
| **B-1** | **LLR-098.1's drift threshold is wrong: the golden drifts by exactly 3 lines, not 2.** The prediction names only the `a` inventory row; the golden has **two** `.s19` rows. A correct implementation would fail the stated gate. | `tests/goldens/batch35/at055b-project-report.md` lines `\| a \| a.s19 \| s19 \| yes \|` **and** `\| b \| b.s19 \| s19 \| no \|`; probe: `_md_safe('b.s19') -> 'b\.s19'`. My independent line-by-line derivation of the golden gives: (1) `a` row, (2) `b` row, (3) the Modified-files bullet (Mode B wrap). |
| **B-2** | **"The benign no-op arm still holds" is false**, and the blast radius spans 2 undeclared files. | probe `_md_safe('SYM_A') -> 'SYM\_A'`; `tests/test_report_symbol_escape.py:166`, `tests/test_report_service.py:260`, `tests/test_report_service.py:1403`. C-27 target list names only the first file. |
| **B-3** | **D-3 is unimplementable.** The architect's `TC-376…387` are **twelve bare identifiers with no titles or content** (they exist only in §10's traceability table); qa's `TC-376…387` are twelve fully specified tests. "qa's *additional* cases renumber to TC-388+" presupposes a mapping that does not exist and is not derivable. | `01-requirements-architect.md` §10 vs `01b-qa-catalog.md` §4. |
| **B-4** | **The single mandated assertion helper contradicts the adopted design** — its "payload chars still present" clause fails against backtick removal (payload #9), newline collapse (#12–#21) and truncation; `visible()` is undefined. | `01b-qa-catalog.md` §3.4; `flow_report_service.py:173,175,177-178`. |
| **B-5** | **Carried blocker 1 has no ruling.** §3 item 1 says "Pin it, or fix the escape set"; D-1…D-9 do not decide, and no LLR covers the newline collapse. Ruling supplied in §1 A.1. | canonical §3; `01-requirements-architect.md` §9 (no matching LLR). |
| **B-6** | **Mode selection is prose, not a truth table** (C-36 rider), with a guard in one direction only. A new run-root-bearing field defaults to Mode A → silent R-1 recurrence, no detector. | §7.2 definition table; LLR-097.2 guards only `md_code`-in-a-cell. Truth table + backstop supplied in §2 B.3. |
| **B-7** | **HLR-097 is false at merge** — "no report generator shall define its own grammar-escaping helper" vs D-8's explicit deferral of `diff_report_service._md_cell` / `._md_table_cell`. | HLR-097 §8; D-8; `diff_report_service.py:270,282`. |

### Majors (8)

| # | Finding |
|---|---|
| **M-1** | HLR-098 "paths shall render without inserted escape characters" vs F-09 Mode A (`a.s19` → `a\.s19`, measured). |
| **M-2** | HLR-096 "verbatim after control-character removal" — false under backtick removal, newline collapse, and truncation. |
| **M-3** | **HLR-099 has no parent US** (§10 shows `—`). Traceability chain broken. |
| **M-4** | Exactly-once (A.3) has **no detector**. LLR-098.2 tests the helper, not the composer. Sink-level predicate + AT-163 supplied. |
| **M-5** | Truncation policy under-scoped (A.4): `issue.code` / `.symbol` / `.related_artifacts` are uncapped upstream (`ValidationIssue.__post_init__` scrubs `message` **only**) and would be newly truncated at 240; Mode B's 240 on absolute paths makes truncation **run-root-depth dependent** → machine-dependent golden. |
| **M-6** | `<in-memory document>` (`:894`, `:1093`) emits `html_inline` under the default parser (**measured**); in neither the inventory nor the trusted list; **breaks AT-158 as written**; Mode-B-wrap applicability to the fallback branch unspecified. |
| **M-7** | **P-4's framing is false.** It is titled "values actually present in the AT-055b golden", but `issue.code`, `check.source_path`, and `region.name` are **not** in that golden (it reads `None.`, `No checklists were executed for this variant.`, and has no addendum section). The 2-line prediction rests on a mis-scoped probe — which is *why* B-1 slipped through. |
| **M-8** | `tests/test_tui_report_filter_surface.py` (byte pin `:85`, `_md_table_cell` dependence `:290`) is in neither the C-27 target list nor the increment budget. |

### Minors (7)

| # | Finding |
|---|---|
| **m-1** | "33 emission sites" is not the emission-site count (~50 exist). Key the census on the **24 escape-required** sites. |
| **m-2** | `md_safe("")` → `"(empty)"`. Semantics for empty file-derived fields and empty `related_artifacts` elements unspecified. |
| **m-3** | LLR-097.1 conflates "already wrapped" (`:901`) with "must wrap" (`:897`, `:1097`). |
| **m-4** | D-1's `US-B62-*` rename is applied in the canonical file only; both source artifacts still say `US-062-*` throughout — a C-26 census will hit the stale spelling. |
| **m-5** | `screens.py:97` names `flow_report_service._md_safe` as the composer half; after promotion it should name `markdown_safety.md_safe`. |
| **m-6** | `MAX_REPORT_CELL_CHARS` should stay in `flow_report_service`, not move to the shared leaf — LLR-098.3 already proves the two consumers need different caps. |
| **m-7** | Citation drift: the deferred import is at **`:965-968`**, not `:974-976` (`:974-976` is the header-row `extend`'s closing bracket). `report_service.py:978` (the `_md_table_cell` call) and `validation/model.py:22` are **correct**. |

### Claims I checked and could NOT refute

- **D-4's circular-import claim** — verified at `flow_report_service.py:63` and
  `diff_report_service.py:97`.
- **D-5's ordering claim** — verified: `_MD_ESCAPE[0] == "\\"`, `[1] == "|"`, replaced in tuple order.
- **D-6** — verified by probe: a code span with a raw `|` still splits a cell (`td_open`=2,
  cells `['\`v1','INJECTED']`).
- **R-1 / Mode B sufficiency** — verified end-to-end against the real `canonical_report_bytes`.
  Mode A leaks the drive letter; Mode B does not.
- **The 24-field inventory** — re-derived independently by a different method (all interpolation
  forms, provenance classification). **No missed field.**
- **ID ranges** — `AT-157…162`, `TC-376…387`, `HLR-095…099`, `LLR-095…099.x`, `US-B62-*` return
  **zero** hits outside this batch's directory. D-1/D-2's ranges are safe. (D-3's *content* is not
  — see B-3.)
- **Frozen-guard clearance** — none of the four touched source files is in `_ENGINE_PATHS`; neither
  new test file is in `_ENGINE_TEST_FILES`.
- **`tests/test_flow_report_service.py:33,40`** imports `MAX_REPORT_CELL_CHARS` and `_md_safe` —
  LLR-095.2's alias retention is **necessary**, as claimed. (My first grep wrongly excluded this
  file; corrected.)

---

## §8 Evidence checklist

- [x] **Constraints stated explicitly** — CN-1…CN-8 re-verified; CN-4's wording corrected (§2 B.1).
- [x] **At least 2 alternatives considered** — §12's seven options re-weighed; I concur with all
      seven verdicts. Mode selection gains a third option (truth table + mode-agnostic backstop).
- [x] **Recommendation tied to constraints** — §1 A.5 ties Mode B to CN-6 with an executed trace.
- [x] **Risks listed** — 7 blockers / 8 majors / 7 minors, each with `file:line` or probe output.
- [x] **Cost / latency** — R-9's `<5 ms` / `<1 %` / `$0` estimate is plausible and unchallenged;
      I add that M-5's truncation policy is the only place cost interacts with correctness.
- [x] **Diagram** — omitted, and I concur with the omission: one linear composer, one
      `write_text` sink (`report_service.py:1613`). The only branching worth drawing is the mode
      truth table, which §2 B.3 supplies as a table.
- [x] **What would change the recommendation** — §13's five triggers stand. I add a sixth:
      *if the `<in-memory document>` literal is changed to the parenthesised form, AT-158's html
      clause needs no provenance scoping.*
- [x] **Privacy / data handling** — CN-7 holds; the new leaf logs nothing. **Escaping reduces**
      exfiltration surface (kills `link_open` in the exported file). **The one privacy regression
      risk is M-5**: Mode B truncation at 240 is the only path by which an absolute operator path
      can re-enter the compared bytes.
- [x] **Two-layer requirements** — both chains present; **HLR-099's US parent is missing (M-3)**
      and the AT set changes (C-21) — the cut in §6 is re-derived accordingly.
