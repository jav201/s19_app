# E4 implementer notes — Inc 14 (G2 documents: README, SECURITY, CHANGELOG)

Unit scope (per the E4 brief): `README.md`, `SECURITY.md` (new), `CHANGELOG.md` (new).
The graph's other G2 documents (`docs/user-guide/*`, `DOSSIER.md`) and the G1 product
constants (`window_help.py`, `legend.py`) belong to parallel units and were not touched.
No test file was written or edited. `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` and
`tests/test_id_registry.py` were not touched.

## What changed per file

### README.md (edited in place; CRLF line endings preserved, 437 lines)

- Rail paragraph + window table: "ten single-context screens / keys `1`-`0`" replaced by
  "twelve windows, one key each", a `| Key | Window |` table in rail order
  `1 2 3 4 5 6 = 7 8 ] 9 0`, and the Split / Join / Export palette note (graph block 1).
- Global key intro + `| Key | Action |` table: rewritten to the 26-key census, adding
  `Ctrl+P`, `d`, `c`, `q` / `Ctrl+Q`, and the `=`, `]` rail keys (graph block 2).
- Footer paragraph replaced (graph block 3).
- `### Patch Editor`: last sentences rewritten — **Apply loaded changes**, **Write file**
  (under **Save patched image as**), and "in a project the file becomes a new variant"
  (graph block 4).
- New `### Check Editor` section inserted after Patch Editor (graph block 5).
- `### A↔B Diff` renamed to `### A2B Diff`, body rewritten (graph block 6).
- `### Flow Builder` body rewritten; new `### Flow Execution` inserted after it (graph
  blocks 7 and 8).
- `### CRC Designer` left unchanged (graph block 9).
- New `### Split / Join / Export` inserted before Operations (graph block 10).
- `### Operations modal` body rewritten to name `crc` and the two placeholders (graph
  block 11).
- `### Projects and variants` last sentences rewritten (graph block 12).
- `### Workarea` table rewritten with six rows (graph block 13).
- `## Known rough edges`: the `project.toml` bullet deleted (graph block 14).
- `## Documentation` table: `SECURITY.md` and `CHANGELOG.md` rows added (graph block 15).

### SECURITY.md (new, CRLF)

`# Security policy` with `## Supported versions` (rows `1.0.x` yes, `0.x and the 1.0.0
release candidates` no), `## Reporting a vulnerability` (Security tab / Report a
vulnerability, no public issue, an "Include:" list), and `## Scope` (offline, the file
content and pasted text it must withstand, the two processes it starts on purpose, the
external-step command it never runs, and example vulnerability classes). No response-time
promise, no public-issue fallback, no e-mail address.

### CHANGELOG.md (new, CRLF)

`# Changelog`, the one-line intro, then `## 1.0.0` with `### CRC: init is taken as written
when reverse is true` (the four release-note sections copied verbatim as `####` headings),
`### Reports` (six paragraphs), `### Flows` (four paragraphs), `### CRC config: refusal
reasons`, and `### Projects`.

## Deviations from the graph, and why

- **SECURITY.md "Include:"**: the graph gives the three items joined by semicolons rather
  than a single verbatim block; I rendered them as a three-item bullet list, keeping the
  words verbatim. The tested substrings ("Security", "Report a vulnerability", "not in a
  public issue") are unchanged by this layout choice.
- **SECURITY.md supported-versions table**: the graph gives a rule ("rows `1.0.x` → yes,
  `0.x and the 1.0.0 release candidates` → no"), not a literal table; I wrote the table
  with those exact cell strings.
- **CHANGELOG CRC section**: the graph's rule is "copy the four release-note sections
  verbatim as `####` headings, without the file's first line". Followed: the four
  sections are verbatim (including the `0x18026B2A` / `0x0F8B7431` and `0x12345678` /
  `0x1E6A2C48` examples), the process-text first line and the release note's H1 title are
  omitted.
- **CHANGELOG `### Reports` and `### Flows`**: the graph lists each statement as a quoted
  sentence; I placed each as its own paragraph under the subsection. Wording is verbatim;
  the substrings the cases assert are all present, and the negative controls (`cut each
  window at 512 rows`, `names and paths carry a backslash`, `random`) are all absent.
- **Line wrapping**: the graph does not fix wrap points. New README paragraphs are written
  on single long lines (existing tables and short paragraphs keep the existing wrapping);
  no substring the tests assert is split across a hard wrap in a way that matters, since
  the doc cases normalise whitespace or assert on phrases that I kept contiguous.

## py_compile

None — this unit changed no `.py` file (README.md, SECURITY.md, CHANGELOG.md only), so
`python -m py_compile` was not applicable and not run.

## Verification run (self-check, not pytest)

Local reads confirmed: README CRLF intact (437 CRLF, 0 lone LF); all 11 R-DOC-README.4/1
stale claims absent and the Check Editor present phrase present; all 13 `### <window>`
headings present; rail keys in order `1 2 3 4 5 6 = 7 8 ] 9 0`; CHANGELOG's only `##`
heading is `## 1.0.0` with every R-DOC-RELNOTE substring present and its negative controls
absent (two U+FFFD occurrences, `CAL\_A` / `img\.s19` literal); SECURITY.md holds the
supported-versions rows and the private reporting path. The SECURITY.md merge precondition
(private vulnerability reporting enabled) is an E5 evidence check, not part of this unit.
