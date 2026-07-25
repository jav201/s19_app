# 05 — Postmortem · batch-60 (FB-P1b flow-run report generation)

**BLUF:** The batch shipped in 3 increments, but the story of batch-60 is **Phase 2**: the
spec failed its gate, and the failure was worth more than the implementation. Two reviewers
independently found that the approved prototype's markup escaping targeted the **wrong
grammar** — a hole that would have shipped as a security defect with a fully green suite,
because the acceptance test's payload had been chosen to match the escape set instead of the
parser. Two further defects (an operator decision that was unimplementable at the specified
wire point, and a status rollup keyed on a string that matches 1 of 9 real cases) were caught
in the same pass. All three were fixed in the **contract**, before any code existed.

## What went well
- **Prototype-first paid off in an unexpected direction.** The prototype's job was to settle
  layout with the operator. It also became the concrete artifact reviewers could *execute* —
  which is how the linkify hole was found by running payloads through the real parser rather
  than reading the spec.
- **Reviewing the SPEC, not the code.** Every one of the three HIGHs was a *contract* defect.
  Fixing them cost a document edit; fixing them post-implementation would have cost a rewrite
  of the composer, the wire, and their tests.
- **Independent convergence as a confidence signal.** qa and security ran blind to each other
  and agreed on all three HIGHs (qa H-1 ≡ sec F1+F2, H-2 ≡ F5, H-3 ≡ F4). That agreement is
  what justified accepting a FAIL verdict and re-cutting the contract without further debate.
- **Reuse-not-fork held where it was right, and was declined where it was wrong** — see
  lesson 3.

## Lessons (candidate carries)
1. **Escape for the GRAMMAR YOUR SINK PARSES, not for "markdown".** `_md_safe` escaped a
   textbook CommonMark set. The sink is `textual.widgets.Markdown` → `MarkdownIt("gfm-like")`
   with **linkify enabled**, where a bare `http://…` autolinks and `~~x~~` strikes through. In
   an *audit record*, strikethrough is not cosmetic — it is a deception primitive that can make
   a ledger row read as retracted. **The general rule: a sanitiser's spec must name the exact
   parser + configuration it defends against; "escape markdown" is not a specification.**
2. **A character-list assertion cannot verify a sanitiser against a parser you do not own.**
   The original TC-004 asserted specific escaped characters, using a payload built from the
   same list — a closed loop that could only confirm what the author already believed. The fix
   is an **oracle at the sink**: render the output through the real parser and assert the
   *token stream* contains no `link_open`/`s_open`/`code_inline`/`html_*`/extra `td_open`. That
   assertion stays true for vectors nobody predicted. **Move-aside proof: reverting to the
   CommonMark set makes 6 payloads produce live structure** — the oracle bites, the old
   assertion did not.
3. **"Reuse, don't fork" is a question, not a reflex — and the answer must be written down.**
   Prior art existed (`diff_report_service._md_cell` / `_md_table_cell`). Reusing it would have
   been a **downgrade**: it escapes only `|`/`\` for a sink never audited against linkify.
   Extending it would have silently changed two shipped report generators this batch does not
   test. The right call was a new symbol **plus an explicit in-code rationale**, so the next
   reader sees a decision rather than a silent fork. (`_report_filename` and `_ByteBudget`, by
   contrast, were genuinely reused.)
4. **An operator decision can be approved and still be impossible — check the control flow
   before promising it.** D-6 ("an aborted run still writes a report") was mine to recommend
   and the operator approved it, but `run_flow`'s `if aborted:` skip guard sits *above* the
   `try` holding the ReportBlock branch, so the run you most need a record of would have
   silently produced none. **The failure mode is the worst kind: a decision that is neither
   implemented, nor tested, nor contradicted** — it would have surfaced post-merge as "we said
   it writes an honest record and it doesn't."
5. **A proxy signal drawn from a human-readable string is a bug waiting for a rename.** The
   FAILED rollup keyed on `summary == "error"`, which matches exactly one of the nine aborting
   sites; the other eight carry descriptive summaries (`"source unresolved"`, `"no image"`, …)
   and would have labelled a broken image "COMPLETED WITH ISSUES". The fix threads the real
   `aborted` boolean. **Where a caller already knows the truth, pass it — do not re-derive it
   from display text.**
6. **Test-side bugs cluster where the code's vocabulary differs from the prose.** Five of my
   own test failures during Phase 3 were assertion bugs, not code bugs, and all five came from
   the same root: asserting against *what I wrote in the doc* instead of *what the code emits*
   — `write_out` (not `WRITE-OUT`), the `-01-report.md` collision shape (not a `-01` suffix),
   escaped markdown source vs rendered text, and alphabetical `sorted()` putting the *second*
   report first. Cheap to fix, but each one briefly looked like a product bug.

## Process notes
- **Authorization re-confirmed at kickoff** (per-batch, never carried): autonomous + self-merge
  with a **plan/prototype-first** precondition, satisfied by the approved prototype.
- **Model:** the operator switched the session to **Opus 5** mid-batch via the UI. The standing
  rule was updated from "else Opus 4.8" to "else inherit the current session model".
- **The regression edit was declared IN ADVANCE.** `test_flow_persistence.py`'s `"deferred"`
  assert had to become `"reports/"` once the block stopped being a no-op. Declaring it in the
  Phase-2 checklist means the edit is a planned contract change, not an assertion quietly
  relaxed to make a failure disappear — the distinction is invisible in a diff.
- **Every load-bearing AT was move-aside RED-verified** (C-20): the escape set, the abort
  signal, the skip-guard exemption, the ledger path, the parser hardening.
- **Defense in depth, deliberately split:** the composer's `_md_safe` travels with the `.md`
  once it leaves the app; the viewer's hardened parser holds regardless of what text reaches
  it. Neither alone was judged sufficient.

## Carries out
- **`report_service` markdown escaping (sec F11) — a real, pre-existing hole.**
  `generate_project_report` embeds file-derived text (variant ids, filenames, declaration
  errors) into markdown with **no escaping at all**, against the same linkify sink. batch-60's
  viewer hardening now blunts it at render time, but the `.md` file itself is still unescaped
  once shared. Same class as the bug this batch fixed → its own hardening batch.
- **AT-002 could go further (qa m-7):** it consumes the report via `list_project_reports`;
  driving `ReportViewerScreen` over the file would be the fuller C-12 loop (and is the assert
  that would have caught the linkify hole end-to-end).
- **Strikethrough survives the hardened parser** (it is a gfm-like plugin, not an option). The
  composer escapes `~`, so the shipped path is covered; a future viewer-side plugin disable
  would close it at the render layer too.
