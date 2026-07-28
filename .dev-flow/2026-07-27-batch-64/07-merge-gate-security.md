# Security Review — batch-64 FINAL PRE-MERGE GATE (PR #144)

**BLUF: BLOCKED — 1 HIGH, 3 MEDIUM, 1 LOW. The HIGH is not batch-64's content.**
Batch-64's installed text is clean on every lane I was asked to check, and I verified that by
re-derivation rather than by reading the evidence file. The blocker is that **the tree I was asked to
certify is being edited by another session while I measure it**: `origin/main` has moved
`c779e3d → 082ada9` and an unresolved merge of that new main is in progress in this worktree right
now. One of batch-64's five destination files, `.dev-flow/BACKLOG.md`, has been **structurally
superseded on main** (split into two lane files), so the merge result batch-64 would produce does not
yet exist. `03-out-of-vcs-evidence.md §6`'s scope-confinement evidence is now false of this tree.

This is the batch-62 incident — gate evidence taken from a tree another session is editing —
recurring against the security gate itself, in the batch that encodes the control forbidding it.

---

## Scope reviewed

| item | how |
|---|---|
| 22 committed files, `origin/main...HEAD` (merge-base `c779e3d`, verified) | full diff + pattern scans |
| 5 installed destinations, live on disk | content hash, LF-normalised diff vs `.PRE`, substring proof |
| 4 `.PRE` backups in the session scratchpad | sha256 vs `03-out-of-vcs-evidence.md §2` |
| 6 frozen blocks, `01-requirements-consolidated.md §3.1–3.6` | re-extracted, hashed, substring-tested in situ |
| 6 review folds | word-level diff, frozen block vs installed line |
| `~/.claude/commands/dev-flow.md`, `~/.claude/skills/tui-design/VERIFY.md` | whole-file literal + injection sweep |

Per the discipline note, every "unchanged / intact" claim below is a **content-hash or byte-substring
result**, never a grep.

---

## Findings

### F1 — The gate is being run against a live tree with a moved base; §6's scope evidence is now false  [Severity: HIGH]

- **What.** Three separate facts, one root cause:
  1. **`origin/main` moved.** The brief states base `origin/main = c779e3d`. It is now
     `082ada9` — `9874da6` + `183ce96` (README docs) + **`082ada9` "split the backlog into a code lane
     and a process lane (#143)"**.
  2. **An unresolved merge of that new main is in progress in this worktree.** `MERGE_HEAD` =
     `082ada9`, `MERGE_MODE`, `MERGE_MSG` and `AUTO_MERGE` all present;
     `.dev-flow/BACKLOG.md` is `UU` (both-modified).
  3. **The tree changed under me mid-review.** I hashed `.dev-flow/BACKLOG.md` at
     `83711f07…`, 82 389 B. Minutes later, in the same session, the same file was
     `781c82e9…`, **26 057 B** — replaced wholesale, conflict markers already gone. A second
     re-sample confirmed the merge is still live and `BACKLOG-CODE.md` / `BACKLOG-PROCESS.md`
     are `AM` (being edited in the working tree as I write).

- **Where.** The worktree itself; `03-out-of-vcs-evidence.md:168-183` (§6 Scope confinement).

- **Why it matters.**
  - **§6 asserts a state that no longer holds.** It records `git status --porcelain` as three
    modified files plus the untracked batch dir, and concludes *"Zero production source, zero tests,
    zero fixtures, zero build config."* The tree now additionally carries `.gitignore`, `README.md`,
    `REQUIREMENTS.md`, eight `docs/images/*` binaries and a **Python script**
    `docs/images/capture_readme_media.py`. I verified by `git diff --name-only c779e3d 082ada9` that
    **all fifteen are attributable to the moved main, not to batch-64** — batch-64 still introduces
    zero production surface. But the *evidence statement* as written is false of this tree, and a
    merge-gate reader would be misled by it.
  - **Block 6's destination has been restructured on main.** Batch-64 inserted 7 265 B of
    reconciliation text into `.dev-flow/BACKLOG.md`. On `082ada9` that file is a router and the
    content lives in `BACKLOG-CODE.md` / `BACKLOG-PROCESS.md`. In the current working tree,
    batch-64's block-6 strings have already migrated: `PROCESS, new — sec F5` = 0 hits in
    `BACKLOG.md`, **2 in `BACKLOG-CODE.md`**; `test_report_document_bytes.py:266` = 0 / **1**;
    `batch-64 §7.1`, `§7.2`, `§7.8`, `FOUR vacuous predicates`, `FALSE COUNTERFACTUAL`,
    `worktree-mutation hygiene` — each 0 in `BACKLOG.md`, **1 in `BACKLOG-CODE.md`**. The
    resolution therefore *relocates* one of the six installed blocks. Whether it does so completely
    and exactly once cannot be certified while it is still running.
  - **No measurement taken from this tree is stable**, which I demonstrated empirically rather than
    asserted. C-42 is confirmed **absent from `082ada9`**, so `docs/engineering-rules.md` is
    unaffected by the merge — but `.dev-flow/BACKLOG.md` squarely is.

- **Recommendation.** Do not merge from this tree. Sequence:
  1. Let the in-progress merge settle, or `git merge --abort`, and confirm no other session is
     writing before re-measuring.
  2. Re-verify block 6 on the settled tree: batch-64's reconciliation text present **exactly once**,
     in whichever lane file the split assigns it, with the three folds intact. Grep-anchors, all of
     which I confirmed present pre-merge: `PROCESS, new — sec F5` (F1 fold),
     `test_report_document_bytes.py:266` (F3 fold), and the **absence** of `(and \`:36\`)` (F4 fold).
  3. Re-record `03-out-of-vcs-evidence.md §2` POST rows and §6 `git status` against the settled tree.
  4. Re-run this gate. Everything under "Cleared explicitly" below is destination-local and will
     carry forward unchanged for the four non-`BACKLOG` files; only block 6 needs re-derivation.

---

### F2 — §2's POST hashes are stale for three of five files; two of those are out of VCS  [Severity: MEDIUM]

- **What.** `03-out-of-vcs-evidence.md §2` is the authoritative PRE/POST table. Measured live:

  | file | §2 POST | live sha256 | verdict |
  |---|---|---|---|
  | `docs/engineering-rules.md` | `5618029c…` | `5618029cb8d8fd89…` | ✅ match |
  | `~/.claude/skills/tui-design/VERIFY.md` | `3c6016fc…` | `3c6016fc005dd4e5…` | ✅ match |
  | `~/.claude/commands/dev-flow.md` | `85979683…` | `fe3fdcbd87e69073…` | ✗ **stale** |
  | `…/memory/project_devflow_control_lineage.md` | `1a366bf4…` | `50cf146e5764eb93…` | ✗ **stale** |
  | `.dev-flow/BACKLOG.md` | `f6768bd0…` | (now mid-merge) | ✗ **stale** |

  §5b discloses that blocks 1/5/6 were amended, but **§2's file-level POST rows were never
  re-recorded**. For `dev-flow.md` and the lineage memory — both out of VCS — the record contains **no
  hash of the shipped state at all**.

- **Where.** `03-out-of-vcs-evidence.md:33-40`.

- **Why it matters.** Reversal is intact: I verified all four `.PRE` hashes match §2 exactly
  (`23cf75e6…`, `44660d7c…`, `278b808d…`, `d9f84f9e…`), so rollback works. What is missing is
  **detection of drift from the shipped state**. A future reader comparing hashes gets a false tamper
  signal on three rows. Reconstruction is possible — I did it — but it takes a frozen-block
  re-extraction plus the fold list, not a hash comparison.

- **Recommendation.** Append post-fold POST rows for the three amended files, labelled
  `POST-FOLD`, keeping the Phase-3 rows for lineage. One command, no design change.

---

### F3 — The only rollback for three out-of-VCS files lives in a session-scoped Temp directory  [Severity: MEDIUM]

- **What.** The `.PRE` backups are at
  `%LOCALAPPDATA%\Temp\claude\<project-slug>\<session-uuid>\scratchpad\b64-baselines\`. §2 correctly
  says the three out-of-VCS files are recoverable *only* from these copies. They are in a **temp
  directory keyed to a session UUID** — subject to OS temp cleanup and to session teardown.

- **Where.** `03-out-of-vcs-evidence.md:44-48`.

- **Why it matters.** Detection > prevention > recovery: the recovery leg is the one leg these three
  files have, and it is stored in the least durable location on the machine. All four files verified
  present and hash-correct **today**; that is not a property temp storage preserves.

- **Recommendation.** Before merge, copy the four `.PRE` files to a durable location (the vault, or
  `.dev-flow/2026-07-27-batch-64/baselines/` if the operator accepts them in-repo) and cite the new
  path in §2. Not a blocker on its own.

---

### F4 — C-40's restore-confirmation is dischargeable vacuously for an untracked file  [Severity: MEDIUM]

- **What.** My F1 text landed verbatim and I confirm it below. But as installed, the confirmation is a
  disjunction: *"confirming the restore in the same transcript (`git status` clean, **or** the file's
  hash back at its pre-mutation value)"*. For a file **not tracked by the repo under test** — which is
  exactly the class batch-64 just mutated five of, including the global command carrying C-40 itself —
  `git status` is clean **whether or not the mutation was reverted**. A future agent can satisfy the
  clause with a check that cannot fail.

- **Where.** `~/.claude/commands/dev-flow.md`, the C-40 bullet, DISCHARGE sentence (byte offset
  36 863; the disjunction is inside the 495 B I recommended).

- **Why it matters.** This is a vacuous check inside the control whose entire purpose is to forbid
  vacuous checks — C-40 LIMB 1's own definition of inert: *a predicate whose value is invariant under
  the change it gates*. Blast radius if it bites: a mutation left applied in a global command or skill
  contaminates every subsequent agent session on this machine until noticed. It is MEDIUM and not
  HIGH because the **obligation** to restore is stated unconditionally and correctly; only one of the
  two named confirmation methods is inapplicable, and the correct one is present alongside it. I own
  this — it is my Phase-2 wording.

- **Recommendation.** Amend the parenthetical, ~15 words, no design change:
  `(git status clean for a tracked file; for an untracked or out-of-repo file the hash form is required, not optional)`.
  This does not need to gate the merge — it can ride the same follow-up as F2.

---

### F5 — Host paths and Windows account name ship to a PUBLIC repo, not only to the private vault  [Severity: LOW]

- **What.** The committed artifacts carry `jjgh8` (Windows account),
  `G:/My Drive/Courses/textual/PENDING-UPDATES.md`,
  `$HOME/.claude/projects/C--Users-jjgh8-OneDrive-Documents-Github-s19-app/memory/…`, and one pasted
  `ls -l` line with uid `197609`.

- **Where.** `01-requirements-architect.md:400`, `PLAN.md`, `01-requirements.md`,
  `01-requirements-consolidated.md`, `state.json`, `02c-discharge-audit.md`.

- **Why it matters — and this is a correction to my own Phase-2 F2.** At Phase 2 I ruled no-action on
  the grounds that *"the sync destination is the operator's own vault on the operator's own Drive; no
  third party receives these artifacts."* **That rationale was incomplete.** `gh repo view` returns
  `"visibility":"PUBLIC"`. `.dev-flow/` is committed and pushed to a public GitHub repo, so these
  strings are world-readable — the exact case my own Phase-2 recommendation named as the trigger
  (*"if any batch artifact is ever routed to a client **or a public repo**, `jjgh8` and the `G:` paths
  are the two strings to strip"*). The trigger was already true; I did not check it.

- **Why it stays LOW and does not gate this merge.** No credential, token, key or client data — I
  scanned the full added diff for `sk-*`, `ghp_`/`gho_`/`github_pat_`, `AKIA`, `-----BEGIN`,
  `xox[baprs]-`, `AIza`, bearer tokens and `api_key`/`secret`/`password` assignments: **zero hits**.
  The exposure is a Windows username and a personal Drive folder name. It is also long-standing and
  operator-known: `jjgh8` already appears in **38 files** and `My Drive` in **16** on `origin/main`,
  dating to batch-01. Batch-64 adds ~4 more of the same class. Blocking this batch for it would be
  theatre. The project's settled position (batch-62's D-11 redaction withdrawn after three integrity
  defects) also cuts against retroactive byte-substitution.

- **Recommendation.** No change to this batch. Raise a PROCESS backlog item to decide the standing
  posture on a public repo — the honest options are *accept explicitly* or *stop emitting absolute
  host paths at authoring time* (cheap, forward-only, no redaction pass). Do not retro-scrub history.

---

## Cleared explicitly — what I checked that could have produced a HIGH and did not

**Instruction integrity, in situ (scope item 1) — CLEAR.** I parsed all five destination files line
by line. Every adversarial literal sits **mid-line inside a code span**; **zero occurrences at a line
start** after stripping list/quote markers — `# PWNED` (1, `engineering-rules.md:127`),
`SYM_A&vert;PASSED` (1, `:128`), `&#160;` (`:131`), `](` (`:129`, `:134`), `#### Checklist` (`:130`).
Fence balance: `dev-flow.md` 4, `VERIFY.md` 8, `engineering-rules.md` 0, lineage 0, `BACKLOG.md` 0 —
all even. `&vert;` inside a code span is not entity-resolved by CommonMark and is not in a table row,
so the spoof cannot forge a cell. All literals are framed as *illustrations of payloads*, not as
directives. An injection sweep of both globally-loaded files
(`ignore previous|disregard|you are now|reveal the system prompt|exfiltrat|curl|wget|Invoke-WebRequest|base64 -d`)
returns **clean**. Note `# PWNED` never enters the global command or the skill — it exists only in the
in-repo project doc.

**F1 landed verbatim (scope item 2) — CONFIRMED.** My 495 B recommendation
(`sha256=d24b133a45c53504…`) is an exact substring of the live `dev-flow.md` at offset 36 863,
immediately after *"for the wrong reason)."* and before *"A predicate that stays GREEN…"* — the
specified position. It bounds all three axes the brief asks about: **where** (*"your own increment
tree or a `git archive`/worktree export, never a tree a concurrent review or a parallel batch is
measuring"*), **reverted** (*"RESTORE it before the next gate"*), **not in a tree another session is
reading** (explicit). **Ruling on the installed mutation clause: sufficient as installed, with the
single defect in F4.** The irony is not lost — F1 exists to prevent exactly the condition F1-the-HIGH
found this gate running in.

**Fold completeness (scope item 5) — CLEAR, and this is the strongest result.** I re-extracted the
six frozen blocks and word-diffed each against its installed line. Blocks 2, 3, 4 are **byte-exact
substrings** of their destinations. Blocks 1, 5, 6 differ by **exactly nine word-level edits, all
nine declared** in §5b: C-40 — `Five`→`Three of the five`, `string join`→`byte count`, drop
`for one defect`, `(:206)`→`(:207)`; lineage — `authored`→`known at batch-63's close`, `defect,`→
`defect (batch-64 measured the corpus at NINE across three subjects),`; BACKLOG — `(:266)`→
`(tests/test_report_document_bytes.py:266)`, `(and :36) record`→`records`, `at .dev-flow/BACKLOG.md:50`
→`carried in this file as (PROCESS, new — sec F5)`. **Zero undeclared changes.**

**The C-40 normative-body claim — REPRODUCED EXACTLY.** §5b's load-bearing claim that the acceptance
figures still bind: I measured the region before `(Origin:` at **4 564 B,
`sha256=026bb4c6709f2ed64ecc51323c0209d62d325029d94b2e0958be8ee01cb795ec`** — matching the quoted
figure and prefix exactly, identical between frozen block and installed text, and containing
`**LIMB 1`, `**LIMB 2`, `DISCHARGE for both limbs`, plus both halves of my F1 text.

**The CRLF / D3 defect — content-neutrality VERIFIED INDEPENDENTLY, not accepted.** I LF-normalised
each `.PRE` and its live counterpart and diffed at line level:
`dev-flow.md` **+2/−1**, `VERIFY.md` **+20/−0**, lineage **+7/−0**, `engineering-rules.md` **+12/−0**.
Ordinary insertions; no whole-file rewrite. Line-ending state matches §5b: `dev-flow.md` 276/276 and
lineage 96/96 (uniform CRLF), `VERIFY.md` 182/202 and `engineering-rules.md` 125/137 (mixed,
untouched). `.gitattributes` pins only `tests/__snapshots__/**/*.svg` and `tests/goldens/**` — neither
is in scope, so no CI oracle is affected. **Not a security finding.**

**Data exposure in the travelling blocks (scope item 4) — CLEAR, and this is the half that matters.**
I regex-scanned **every added line** of all four out-of-VCS destinations for
`[A-Za-z]:\ | /Users/ | jjgh8 | jav201 | javgranados | OneDrive | AppData | G:\ | My Drive | ConsultIA | GRNDIA`.
Result: **NONE**, on every added line, in every file — including the two that load into every future
session. Every path inside the blocks is repo-relative. My Phase-2 clearance of this lane holds
without qualification; only the *committed-artifact* half needed the F5 correction.

**Credentials — CLEAR.** Zero hits across the 22 committed files (patterns listed in F5).
`state.json`'s `merge_authority` / `operator_phrasing` fields are governance metadata, not secrets.

**Blast-radius surface — CLEAR.** No new MCP, Composio, n8n or third-party connector. No new
dependency, no lockfile change, no auth flow, no network egress, no deploy path. `git diff
--name-only origin/main...HEAD -- s19_app tests examples pyproject.toml requirements.txt .github`
returns **0 files**; the whole batch-64 diff is `.md` + `.json` only, **zero executables**. Sections
2, 3, 5 and 6 of my standing checklist are N/A by construction and I am not manufacturing findings
against them.

---

## Evidence checklist

- [x] Each finding has what · where · why · recommendation — F1–F5 above.
- [x] Each finding has a severity rating — 1 HIGH, 3 MEDIUM, 1 LOW.
- [x] No secret values in this output — none existed to redact; scan results reported as counts.
- [x] Verdict explicit — below.
- [x] New tool/integration scope + blast radius addressed — **none added**; stated affirmatively
      rather than skipped, with the command that proves it.
- [x] Every "unchanged/intact" claim is a hash or byte-substring result, per the discipline note.

## Verdict

- [ ] OK to ship
- [ ] OK to ship with the listed mitigations applied first
- [x] **BLOCK — must fix the HIGH before ship**

**BLOCKED. 1 HIGH · 3 MEDIUM · 1 LOW.**

Stated plainly, because it would be easy to read this as worse than it is: **batch-64's own content
carries genuinely low residual risk.** I attacked it on every lane the brief named and it held — the
installed text is byte-faithful, the folds are exactly what was declared and nothing more, the
adversarial literals are inert in situ, the CRLF defect is content-neutral by measurement, the
travelling blocks are free of host paths, and there are no credentials, no executables and no new
external surface. If the tree were quiet I would clear this at 0 HIGH.

It is not quiet. The base moved, a merge of the new main is running in this worktree as I write, one
of the five destination files has been restructured on main, and §6's scope evidence is now false.
The unblock is mechanical, not a redesign: settle the merge, re-verify block 6 against the anchors in
F1, re-record §2 and §6, re-run this gate. F2–F4 ride the same follow-up; F5 is a backlog item.
