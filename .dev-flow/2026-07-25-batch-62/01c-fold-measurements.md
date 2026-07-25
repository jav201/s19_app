# 01c — Fold measurements (Phase-1 iteration 1) — batch-62

> Every acceptance threshold in `01-requirements.md` revision 2 that could be executed, **was**.
> This file is the evidence, kept in-repo because the Phase-2 reviewers' own probes lived in a
> scratchpad that does not survive the session. Tree: `8d3c504`. Python 3.14.4, `markdown_it` 4.2.0.
>
> The Phase-2 gate failed because three thresholds were *predictions*. The rule this file enforces:
> **a threshold that can be executed before the code exists must be executed before it is promoted
> to an acceptance criterion.**

---

## M-1 — Golden drift set (closes A-04 / qa B-6 / E-3)

Method: apply the mode to **every** file-derived value in `tests/goldens/batch35/at055b-project-report.md`
per the F-01…F-33 inventory, and record which golden lines move. No code change required.

```
no-op 'proj'         -> 'proj'           lines=[1, 3]
no-op 'a'            -> 'a'              lines=[14, 21, 47]
no-op 'b'            -> 'b'              lines=[15]
DRIFT 'a.s19'        -> 'a\.s19'         lines=[14]
DRIFT 'b.s19'        -> 'b\.s19'         lines=[15]
no-op 's19'          -> 's19'            lines=[14, 15]
no-op 'standalone'   -> 'standalone'     lines=[57]
no-op '-'            -> '-'              lines=[57]

line 51 (Mode B): the source path at report_service.py:897 is NOT wrapped today
(:901's saved-as IS) — adding the md_code wrap moves the line structurally.

MEASURED DRIFT LINE SET = [14, 15, 51]   (count = 3)
```

**Why the original prediction said 2:** architect probe P-4 sampled `descriptor.path.name` **once**
(`'a.s19'`) for a field the fixture emits **twice**. C-31 applied to the probe itself.

**Gate form:** assert the **line-number set**, not the count. A count-only gate is GREEN when one
predicted line fails to drift and one unpredicted line does.

---

## M-2 — The enlarged escape set adds no further golden drift (closes A-10 / A-11)

Proposed set: `("\\", "&", "|", "*", "_", "[", "]", "<", ">", "#", "~", "/", ".", "@", "`")`
— `&` inserted at index 1, backtick appended and **escaped** rather than removed.

```
values whose output changes under the proposed set: NONE
-> the golden drift set is UNCHANGED at [14, 15, 51]
```

Ordering is preserved (the property `_md_table_cell` existed to provide):

```
'a\b'   -> 'a\\b'        (backslash still escaped first)
'x\&y'  -> 'x\\\&y'      (& escaped once, not doubled)
'a|b'   -> 'a\|b'
```

---

## M-3 — Fidelity restored: rendered text now equals on-disk bytes (closes A-10, A-11 / sec F1, F3)

The spoofing class the token-type oracle could not see:

| payload | on disk today | renders today | on disk proposed | renders proposed | live |
|---|---|---|---|---|---|
| `&vert;` | `&vert;` | `\|` | `\&vert;` | `&vert;` | `[]` |
| `&num;` | `&num;` | `#` | `\&num;` | `&num;` | `[]` |
| `&lt;script&gt;` | `&lt;script&gt;` | `<script>` | `\&lt;script&gt;` | `&lt;script&gt;` | `[]` |
| `&NewLine;` | `&NewLine;` | newline | `\&NewLine;` | `&NewLine;` | `[]` |

Silent falsification of the audit record:

```
'FOO`BAR'          today: disk='FOOBAR'           rendered='FOOBAR'      <-- a DIFFERENT symbol
                proposed: disk='FOO\`BAR'         rendered='FOO`BAR'  live=[]
'a` **PWNED** `b'  today: disk='a \*\*PWNED\*\* b'
                proposed: disk='a\` \*\*PWNED\*\* \`b'  rendered='a` **PWNED** `b'  live=[]
```

Escaping keeps the payload inert **and** faithful. Removal keeps it inert and **wrong**.

---

## M-4 — Flow-report blast radius (closes A-13; corrects the security review's cost claim)

The security review stated the cost as *"LLR-095.2's zero flow-report behaviour change and
LLR-095.1's byte-equals both break, and the flow-report goldens move."* Half right. Executed with
the proposed helper patched over `flow_report_service._md_safe`:

```
BASELINE (unpatched):        52 passed in 3.38s
WITH PROPOSED HELPER:   1 failed, 51 passed in 3.51s

FAILED tests/test_flow_report_service.py::test_name_that_sanitises_to_nothing_renders_empty_marker
  assert "(empty)" in compose_flow_report(_state(flow_name="```"), _AT)
  actual: '# Flow report — \`\`\`'
```

**Exactly one test, and it is the one that encodes the lossy behaviour being removed.** No golden
moves — the repo has **three** goldens (`at054b .md/.html`, `at055b .md`) and **none is a flow
report**. `test_tc014_backtick_bearing_written_path_is_inert_and_clean` — the one flow-report test
that plants a backtick in a path — **passes unchanged**, because it asserts token classes, not bytes.

Re-run:

```bash
# with a pytest plugin that patches flow_report_service._md_safe to the proposed helper
python -m pytest tests/test_flow_report_service.py tests/test_flow_report_ui.py tests/test_flow_report_wire.py -q -p _b62_plug
```

---

## M-5 — `(in-memory document)` costs nothing (closes A-36)

```
./s19_app/tui/services/report_service.py:894:  else "<in-memory document>"
./s19_app/tui/services/report_service.py:1093: else "<in-memory document>"
```

Repo-wide grep across `*.py` and `*.md`: **two hits, both source.** No test, no golden asserts the
literal, so switching to the parenthesised form (matching `diff_report_service.py:540,1541`) is free
and removes the need to provenance-scope AT-158's `html_inline` clause.

---

## M-6 — U+FFFD is a safe Mode-B loss marker (closes A-11)

```
category(U+FFFD) = So        <-- NOT Cc/Cf, so the A-26 category filter does not eat it
survives 'ch >= " "'  : True
bare 'a<FFFD>b.s19'   : viewer live=[]  default live=[]
```

---

## M-7 — A-26 as first drafted was WRONG (self-caught)

```
RLO   U+202E  cat=Cf  filtered=True
ZWSP  U+200B  cat=Cf  filtered=True
BOM   U+FEFF  cat=Cf  filtered=True
LRI   U+2066  cat=Cf  filtered=True
C1    U+009F  cat=Cc  filtered=True
LSEP  U+2028  cat=Zl  filtered=FALSE   <-- survives a Cc/Cf filter AND the \r\n\t collapse
```

A `Cc`/`Cf` filter does **not** close the survivor list the finding named. Amendment corrected to
`Cc`/`Cf`/**`Zl`**/**`Zp`**, with U+2028 named in the counterfactual TC. Fourth instance in this
batch of *asserting a threshold from a category I had not enumerated*.

---

## M-8 — A-16's residue predicate passes on today's goldens (closes A-16)

Moving the check into `canonical_report_bytes` only works if the existing consumers already satisfy
it. They do:

```
PASS  at054b-before-after-report.html   drive=[]  /Users/=False  /home/=False  RUN-ROOT=True
PASS  at054b-before-after-report.md     drive=[]  /Users/=False  /home/=False  RUN-ROOT=True
PASS  at055b-project-report.md          drive=[]  /Users/=False  /home/=False  RUN-ROOT=True
```

---

## M-9 — A-23 pin 3 must read the assembled template, not the source line (closes A-23)

A per-source-line "does an f-string start with an interpolation" heuristic flags **11** sites in
`report_service.py` — `:230`, `:241`, `:242`, `:247`, `:252`, `:259`, `:266`, `:409`, `:898`,
`:1276`, `:1293` — all of which are exception messages, int-derived continuations, or the second
physical line of the multi-line bullet at `:897-898`. None is a file-derived field at column 0.

A guard that needs 11 suppressions on day one is a guard nobody keeps. Pin 3 is therefore normative
**against the assembled line template**.

---

## Anchors re-verified on disk this session

| Claim | Verdict |
|---|---|
| deferred import comment `report_service.py:965-967`, import at `:968` | **correct** (the `:974-976` citation was wrong) |
| `_md_table_cell` call at `:978` | correct |
| modified-files bullet `:891-902`, source fallback at `:894` | correct |
| `_declaration_error_lines` loop `:1025-1032`, `issue.message` at `:1026`, **uncapped** | correct |
| `_strip_ctl_local` at `:512`, used at `:729` | correct |
| `REPORT_MAX_REGIONS_PER_VARIANT = 128` `:76`, `REPORT_MAX_TOTAL_BYTES` `:83` | correct |
