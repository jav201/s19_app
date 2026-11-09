# Inc 11 E5 — mutants A: lexer and section tree (Linux canonical)

Baseline `14fdc3b9`, isolated copy `/tmp/b103-e5-11-mutA-laptop/tree`
(the real worktree was never mutated or committed). Host: `lnx1` (the
operator-provided alternative CachyOS laptop), Python `/data/miniconda3/envs/s19ci/bin/python`, textual
8.x, pytest. Every arm ran in a fresh process with `PYTHONDONTWRITEBYTECODE=1`,
closed stdin, isolated `HOME`/`XDG_*`/`LOCALAPPDATA`/`TMPDIR` under
`zq_iso_user`, `python -I -B`, explicit `sys.path.insert(0, tree)`, and
`s19_app.__file__` printed first. A verdict is read from the pytest summary
**and** the assertion text in the per-arm transcript, never from the process
exit code alone. Scope: the graph nodes `_lex_a2l_lines`, `_line_words`/
`_section_words` and `_build_section_tree_into` in `s19_app/tui/a2l.py`.

The table was rebuilt against this tree's current bytes; `Applied` is the
number of occurrences of the anchor in `a2l.py`, and the runner asserted it
equals the table count (a 0-count mutation is BAD, not SURVIVED — the M-BAD
control proves that gate works). Two anchors differ from the Windows reference
copy (noncanonical): **M6** (the tree now holds two `if backslashes % 2 == 0:`
lines, so the anchor is pinned to the `_find_string_end` occurrence followed by
`return j`) and **M19** (the tree now writes `matched = top["name"] == word` +
`if not matched:` instead of `if top["name"] != word:`).

| Id | Requirement | Mutation | Exact unique anchor | Discriminating test | Applied | Verdict |
|---|---|---|---|---|---|---|
| M1 | R-A2L-READ.7 | comment is no longer a word break (`/*` glues neighbours) | `_SLOW_WORD_RE = re.compile(r'(?:[^ \t\x0b\x0c"/\r\n]|/(?![/*]))+')` | `test_r_a2l_read_7_comment_between_digits_splits` | 1 | KILLED |
| M2 | R-A2L-READ.9 | `//` opens a block comment (runs past the line end) | `if ch == "/" and i + 1 < n and body[i + 1] == "/":` … `i += 2` / `while` body | `test_r_a2l_read_9_line_comment_ends_at_line_end` (3 params) | 1 | KILLED |
| M3 | R-A2L-READ.10 | unclosed block comment records no error | `errors.append(f"Line {comment_line}: comment not closed")` | `test_r_a2l_read_10_comment_not_closed` | 1 | KILLED |
| M4 | R-A2L-READ.11 | stray `*/` records no error | `if "*/" in word:` | `test_r_a2l_read_11_stray_close` | 1 | KILLED |
| M5 | R-A2L-READ.8 | block comment ends at the **last** `*/` (comments nest) | `j = body.find("*/", i)` | `test_r_a2l_read_8_comments_do_not_nest` | 1 | KILLED |
| M6 | R-A2L-001.3.2 | an escaped quote closes the string (backslash parity ignored) | `if backslashes % 2 == 0:` + `return j` (in `_find_string_end`) | `test_r_a2l_001_3_2_escapes` | 1 | KILLED |
| M7 | R-A2L-READ.15 | unclosed quoted string records no error | `errors.append(f"Line {string_line}: quoted string not closed")` | `test_r_a2l_read_15_quoted_string_not_closed` | 1 | KILLED |
| M8 | R-A2L-001.3.1 | a quoted string is split at internal blanks | `return _WORD_SPLIT_RE.findall(text)` | `test_r_a2l_001_3_1_quoted_string_one_word` | 1 | KILLED |
| M9 | R-A2L-READ.16 | a double quote glues into a word (does not end it) | `_SLOW_WORD_RE = re.compile(r'(?:[^ \t\x0b\x0c"/\r\n]|/(?![/*]))+')` (drop the `"` exclusion) | `test_r_a2l_read_16_quote_ends_word` | 1 | KILLED |
| M10 | R-A2L-READ.1 | a CRLF inside a body counts as two line ends | `if ch == "\r" and i + 1 < n and body[i + 1] == "\n":` | `test_r_a2l_read_1_cr_cr_lf_counts_two_ends`, `test_r_a2l_read_1_crlf_cr_mixed_read_as_lf` | 1 | **NOT_REALISABLE** (public route; test gap) |
| M11 | R-A2L-READ.5 | UTF-8 BOM is kept (not dropped) | `utf8_bom = head[:3] == b"\xef\xbb\xbf"` | `test_r_a2l_read_5_bom_before_project_dropped` | 1 | KILLED |
| M12 | R-A2L-READ.6 | UTF-16 BOM is not refused | `if head[:2] in (b"\xff\xfe", b"\xfe\xff"):` | `test_r_a2l_read_6_utf16_refusal` (2 params) | 1 | KILLED |
| M13 | R-A2L-READ.55 | a NUL byte is not refused | `if "\x00" in body:` | `test_r_a2l_read_55_nul_after_address_refused` | 1 | KILLED |
| M14 | R-A2L-001.1 | `/begin` and `/end` recognized only at the start of a line | `or "/" in text` | `test_r_a2l_001_1_begin_end_words` | 1 | KILLED |
| M15 | R-A2L-READ.64 | nesting cap raised to 10000 | `_MAX_NESTING = 32` | `test_r_a2l_read_64_nesting_cap` | 1 | KILLED |
| M16 | R-A2L-READ.22 | `/include` records no error | `if low == "/include":` | `test_r_a2l_read_22_include_error` | 1 | KILLED |
| M17 | R-A2L-READ.56 | error cap removed (`append` never caps) | `if len(self._texts) < self._cap:` | `test_r_a2l_read_56_cap_at_edge` | 1 | KILLED |
| M18 | R-A2L-READ.19 | `/begin` matches by prefix (glued `/beginMEASUREMENT` opens a section) | `if low == "/begin":` | `test_r_a2l_read_19_glued_begin_end` | 1 | KILLED |
| M19 | R-A2L-001.5 | `/end` name mismatch records no error | `matched = top["name"] == word` | `test_r_a2l_001_5_end_name_mismatch` | 1 | KILLED |
| M20 | R-A2L-001.4 | stray `/end` records no error | `errors.append(f"Line {pending_end_line}: /end without /begin")` | `test_r_a2l_001_4_stray_end` | 1 | KILLED |
| M-BAD | control | known-bad control: a non-existent anchor applies zero times | `def _no_such_anchor_xyz_mutant_control():` (absent) | `test_r_a2l_read_7_comment_between_digits_splits` | 0 | **BAD** (gate works) |

## Totals

| Verdict | Count |
|---|---|
| KILLED | 19 |
| NOT_REALISABLE | 1 (M10) |
| SURVIVED | 0 |
| CRASH | 0 |
| BAD | 1 (M-BAD control) |

20 applied mutations, 1 zero-application control. Applied-count assertion:
every applied mutation matched its table count exactly (all 1); the only
mismatch is the intentional M-BAD control (0), which the runner flagged as BAD
rather than SURVIVED.

## The unreachable M10 arm

**M10 — R-A2L-READ.1 (CRLF counted as two line ends).** The mutation targets the
lexer's embedded line-end handling:

```python
if ch == "\r" and i + 1 < n and body[i + 1] == "\n":   # -> ... and False:
```

It **is** a real semantic defect in `_lex_a2l_lines` — proven directly on this
Linux tree (see `mutants-A/M10-probe.txt`): the direct lexer route
`_lex_a2l_lines(["A\r\r\nB\r\nC\rD"], _CappedErrors())` changes from
`[(1,"A"),(3,"B"),(4,"C"),(5,"D")]` (baseline) to `[(1,"A"),(4,"B"),(6,"C"),(7,"D")]`
(CRLF and CR-LF pairs double-counted). The acceptance tests do not kill it
because no acceptance test reaches that branch through the reader's call graph:

- `_build_section_tree_into` opens files with `path.open("r", encoding="utf-8",
  errors="replace")` — default `newline=None` (universal newlines), which
  normalizes CRLF and lone CR to LF *before* `_lex_a2l_lines` ever sees an
  element. So the lexer's `\r`/`\n` body scan and the `element.endswith("\r")`
  strip are unreachable from `parse_a2l_file`.
- `_flatten_body_tokens` (the only other caller) passes canonical body lines,
  which `_lex_a2l_lines` itself built and are therefore CR-free.

**NOT_REALISABLE via the public route, with executed proof.** On this Linux
host the two CR/CRLF acceptance tests are green at baseline and stay green under
the M10 mutation (transcript `mutants-A/M10.txt`: `2 passed in 46.07s`), because
universal newlines removes the `\r` the mutation targets. The direct-lexer probe
(`mutants-A/M10-probe.txt`) shows the mutation is live only when `_lex_a2l_lines`
is fed raw `\r`-bearing elements, which the public route never does. R-A2L-READ.1
is satisfied today by the file-open mode, not by the lexer's own line-end scan.

**Test gap.** The CR/CRLF requirement is *satisfied* by universal newlines, not
by the lexer's embedded-line-end path that graph node `_lex_a2l_lines` documents
(DE-1, examples READ.1/4, READ.9/3). Those examples are not covered by any
acceptance test. If a future change reads files with `newline=""` (or calls
`_lex_a2l_lines` with raw elements), the lexer's line-end handling becomes live
and must then be pinned by a test. This is reported, not fixed: the orchestrator
owns any source change.

## Harness proof

- **Known-bad control (M-BAD):** an anchor that occurs 0 times is reported BAD,
  not SURVIVED — proving the applied-count gate fails closed (`mutants-A/M-BAD.txt`,
  `applied count: 0`, the discriminating test still green).
- **KILLED arms show the observable, not an exit code:** every mutant transcript
  (`mutants-A/M*.txt`) carries the pytest FAILURE block with the concrete
  assertion, e.g. M1 `assert None == 472727040` (the glued address lost), M9
  `no MEASUREMENT tag 'X' in ['X"long"']`, M14 `assert None == '0x0FF0'` (the
  mid-line `/begin IF_DATA` no longer opens), M19 `assert False` (no mismatch
  error). No verdict rests on the process exit code alone.
- **Restoration proof:** after each arm the runner rewrote `a2l.py` from the
  pristine copy and verified the sha256 (every transcript records
  `restored hash: 39752794…6c82da5c`, the pristine hash). After all arms the
  full reader baseline reproduced exactly: `332 passed` (see
  `mutants-A/final-baseline-green.txt`).

## Coverage of the required categories

comments (M1–M5) · quoted strings and escapes (M6–M9) · CR/CRLF (M10) · BOM/NUL
(M11–M13) · one-line sections and mid-line `/begin` (M14) · nesting cap (M15) ·
`/include` (M16) · error caps (M17) · malformed `/begin`/`/end` (M18–M20).

No proprietary A2L material and no OS clipboard were used; every fixture is
synthetic or a tracked example already in the tree. No source change was made to
kill a survivor.
