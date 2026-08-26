# Handoff — batch-88 open at the PDR station, and the session that found eight defects in the flow's own rules

> **Written 2026-08-25 (local, `-06:00`), session "batch-87 landing → batch-88 through P1".**
> **Supersedes** [[HANDOFF-devflow-session-2026-08-24-post-batch-87]] for everything after batch-87's
> merge. That document stays correct about batch-87 and about the flow's state at that cut.
>
> **Re-derive every figure below. If a command disagrees, the command is right.**
>
> ⚠ **Run every validator command with `PYTHONIOENCODING=utf-8`.** Without it `sys.stdout.encoding`
> is `cp1252` on this machine — in Anaconda base AND in `s19env` — and the `·` separator emits as a
> raw byte. **The numbers are never affected; the pasted transcript is.** This session pasted
> corrupted separators for hours before measuring it. The earlier handoff blamed `conda run`; that
> was wrong, the encoding is `cp1252` however the interpreter is invoked.

## 0 · Verify the ground

```bash
cd C:\Users\jjgh8\Github\s19_app          # branch claude/batch-88-audit-closures
export PYTHONIOENCODING=utf-8
python ~/.claude/docs/tools/devflow-validate.py .          # expect: 0 block · 294 notice · 13 n/a
python ~/.claude/docs/tools/devflow-validate.py --selftest # expect: SELFTEST PASSED, 192 arms, exit 0
grep -E "flow_version|^flow_hash" ~/.claude/docs/FLOW-VERSION.md
#   expect 2026.08.24-rev46 · 9c1449ed815d267c
git log --oneline -1                                       # expect 876f44e or later
```

**Notice composition, so a delta is legible:** V9 **226** (80% of all notices — it judges every batch
of closed history) · V13 **52** (its own declared ambiguity: *"grep cannot tell a dependant from a
mention"*) · V23 **9** · V22 **4** · V8 · V16 · V12 one each.

**The V23 nine are our own worked examples.** `01-requirements.md` specifies the strict grammar, and
specifying a grammar means writing the shapes the *current* grammar rejects. V23's scan has **no
code-fence awareness**, so a worked example that is meant to be checkable is indistinguishable from a
real citation. This is a live instance of a ruling the QA plan deliberately declined to make.

## 1 · State at the cut

| | |
|---|---|
| `main` | `4131a38` — batch-87 merged, synced, and the first design record sealed |
| branch | **`claude/batch-88-audit-closures`**, `876f44e`, pushed, tree clean |
| batch-88 | **open at the PDR station.** P0 ✓ · ARQ ✓ · P1 ✓. A station-4 review was dispatched as an independent lens and had not returned when this was written |
| flow | `2026.08.24-rev46` · `9c1449ed815d267c` · selftest 192 arms exit 0 |
| gate | **0 block · 294 notice · 13 n/a** |
| vault | batch-85 (retro-synced), batch-86, batch-87 READMEs · `design/` holds the pre-intake design record · `docs/CENSUS-BASELINE-canon-mirror.md` in the REPO |
| hygiene | the operator runs a **parallel session authoring `.excalidraw` diagrams** in `~/.claude` for external human audit of the process. **Not this session's work — never sweep it (C-44).** It trips V16 while uncommitted |

## 2 · Eight defects found in the flow's own rules — all one shape

**A rule whose BEHAVIOUR does not match what its DESCRIPTION promises.** Ordered by what they cost.

| # | Rule | Defect | Realized harm |
|---|---|---|---|
| 1 | **V5** | *"the ledger's arithmetic adds up"* matches digits on both sides of `=`; the project writes `post = 2714 − 0 + 0`. Falls to `SKIP: "no ledger expression found"` — **identical for a correct ledger and for none** | **57 of 61 batches. 34 of them claim a reconciling ledger in prose.** Its selftest arm asserts only *"not red"*, which the no-op branch satisfies, so **the arm cannot fail** |
| 2 | **`_artifacts`** | fills every basename first-wins across all batch dirs, then overrides **only** basenames present in the active dir. At P0 that dir holds `PLAN.md` alone, so `01-requirements.md` keeps batch-01's May document | **14 spurious blocks at every batch's P0.** Bounded honestly: **10 of the 14** clear the moment any batch authors its record, so the subject is the WINDOW, not the count |
| 3 | **V22** | its message says *"batch-declared"* over a heading-only population; and its membership test is **substring**, so `US-064` reads as present because `US-064a` is | 4 ids, the whole gap between the published **276** and the correct **280** |
| 4 | **V23** | cannot tell a citation from a **filename**; and `batch-[A-Za-z0-9]+` admits no hyphen, so a **version** is unrepresentable — contradicting the seal rule that demands one | latent; 9 notices today from our own worked examples |
| 5 | **V8** | reads `docs/ARCHITECTURE.md`; the repo tracks `docs/architecture.md`. Resolves only on a case-insensitive filesystem | **latent, not firing** — no CI step, git hook or settings hook invokes the validator anywhere. It has only ever run on Windows |
| 6 | **V8** | no `path/**` prefix can match a repository-root file, yet the message asserts *"the map is stale"* | 1 notice, permanent, unfixable by amending the map |
| 7 | **V2** | substring membership — `AT-1` resolves because `AT-10` is on disk | not yet realized |
| 8 | **V6** | requires the `**Statement` marker and the modal on the **same physical line**; a wrapped statement false-passes | **0 realized.** Measured: 930 statements, 207 wrap, 5 carry a modal, V6 caught all 5. The hole is real and nothing has fallen through it |

**Also:** `_ATLAS_ID_REQ` harvests **129 non-ids** — 97 range notations taken whole, 32 English prose
compounds. rev45's lookahead guard was applied to the AT/TC tokenizer and **not** to this one.

## 3 · The frozen baseline, and what the single number was hiding

`docs/CENSUS-BASELINE-canon-mirror.md` — **1004 rows, each attributed to the batch dir that first
declares it.** Placement measured with a **positive control** (a sentinel id existing nowhere else),
because seven candidate locations all returned delta zero and that null result alone would have been
vacuous. `.dev-flow/**/*.md` **is** scanned; `_derived/` is a hard V20 BLOCK; `docs/` is unreachable.

| Class | N | |
|---|---|---|
| declared requirement, unmirrored | **269** | the true backlog |
| heading in a non-`01-requirements` artifact | **51** | **invisible to V22 by construction** |
| citation only | 426 | judgement zone |
| retired on every occurrence | 7 | |
| **not ids at all** | **129** | tokenizer garbage |
| padding variant of a canon id | 11 | `LLR-085.1` vs `LLR-85.1` |
| singleton citation | 111 | |

**320 unambiguously owed. 251 (25%) are not requirement debt.** A hypothesis was **falsified**:
*"much of this predates the canon"* is unavailable — the canon was added **2026-03-29**, the earliest
batch dir is **2026-05-05**. Every absent id postdates it.

## 4 · Operator rulings this session

1. **Scope cut ACCEPTED.** batch-88 = the nine rule-integrity fixes + Story C. Stories A, B and E move
   to batch-89 over a still oracle. The binding argument was not file count (6 files, 10 increments,
   max 3 each — passes with headroom) but **four oracle moves of which exactly one is sequenced**.
2. **The V22 oracle fix lands FIRST**, with the re-baseline **276 → 280** recorded before any
   canon-seeding evidence exists.
3. **The V23 grammar is STRICT** — a record, a decision inside it, and a version each distinctly
   expressible. The permissive form conflating a version with a hyphenated batch dir is REJECTED.
4. **Pillow: option C** — a new `evidence` extra in `pyproject.toml`, CI's install line routed
   through it, the ad-hoc line removed. **Not** the `dev` extra, which pins `textual==8.2.8` for the
   snapshot env only and would silently pin the runtime that 2702 tests exercise.
5. **The three Part B interfaces are re-declared frozen for batch-89.** `docs/architecture.md` freezes
   them **by literal string** for batch-88 — **amend that line when batch-89 opens or the Layer C rule
   debuts with zero real consumers.**
6. **A human review marker is required**, framed as a **REVIEW-DEBT LEDGER**: each batch proceeds
   autonomously and ACCRUES review debt; the marker discharges it with reviewer name
   **`Javier Granados`**, a reserved `reviewer-id` for organisational context, the DATE, the PHASE at
   which review happened, and `authored-by` beside `reviewed-by` so a one-sided sign-off is visible.
   Findings go to the backlog. **The guard must not claim to verify the review's QUALITY.** Moved to
   batch-89 with Story B, whose PDR allocates its rule number.

## 5 · Why the review marker is the right control, in the QA plan's own words

> *"Description-vs-behaviour agreement is unmechanisable. `COVERS-complete` proves a description
> EXISTS, never that it is TRUE. The new rules' descriptions have no arm and can have none — which is
> exactly the gap the review marker exists to carry."*

Eight defects this session live in that gap. The marker is not administrative overhead; it is the
only available control for the one thing no rule can check about itself.

## 6 · Corrections this session made to its own claims

Recorded because a session that only reports its findings and not its errors is selling something.

1. **"V22 reads only 3 files" — WRONG.** `_ifc_corpus` walks 64. The 3 are only those carrying
   FLOW/COMPONENT blocks, which govern a different census. The error was measuring one set and
   reporting it as the rule's scope.
2. **"Pillow is undeclared" — WRONG.** It is declared at `.github/workflows/tui-ci.yml:42` with a
   rationale comment. The defect is its HOME. **The fix as first proposed would have broken CI:**
   line 43 is `pip install -e .` with no extra.
3. **"The map is invisible in CI" — TRUE BUT VACUOUS.** No workflow, hook or settings entry invokes
   the validator. CI produces no such verdict at all. A subagent refused to write "observed" and
   demanded a transcript; it was right, about a claim already committed to a message.
4. **The F-7 count is 10, not 14.** Ten clear the moment any batch authors its record.
5. **A phantom was minted twice and caught twice** — once from a story label, once from a forward
   reference to an id no heading declares. Both fixed at the SOURCE, never in the derived plane;
   census verified back each time. **Each guard discovers the next form.**
6. **Local dates.** This project dates in `-06:00`. A UTC reading produced a wrong stamp that was
   renamed and corrected.

## 7 · Next actions, in order

1. **Finish the station-4 PDR** over the authored requirements. The pre-intake record does **not**
   discharge it: it reviewed the proposal, and its item *"every requirement has foreseen coverage"* is
   a ⚠ for that reason. A review was dispatched as an independent lens; check the vault's
   `s19_app/design/` folder for a record dated **2026-08-25** against this batch.
   ⚠ **Its path is described and not written, and that is the defect, not the style.** Writing
   the filename raises a V23 notice, because the token matcher swallows paths and the grammar
   demands a `#D<n>` suffix a filename cannot carry. **This session tripped that trap three
   times — the third being in this very paragraph, in the handoff that documents it.** A rule
   whose grammar forbids the convention its own command prescribes is not avoided by care; it
   is avoided by fixing the rule, which is why it is in this batch.
2. **Then the increment ladder**, V22's oracle first per ruling 2. **Every new or patched rule owes a
   `PASS != NOOP` arm, and its GREEN arm must assert the pass SENTENCE.** The QA plan REJECTED **5 of
   29** proposed arms — including the one carrying the case-sensitivity fix, whose own comment names
   its kill mutation and which **passes when that mutation is applied**. Do not adopt the proposed
   arms without reading that audit.
3. **Rule for the V23 fenced-example question** — should `_strip_code` be added to its scan? Silencing
   fenced citations is probably right for template prose and probably wrong for a worked example meant
   to be checkable. We now have nine live instances to rule on instead of an abstraction.
4. **Refresh the visual-evidence gallery** once the `evidence` extra lands. Newest asset **2026-08-07**
   vs last UI commit **2026-08-13** (`f198447`). ⚠ The copy helper's GIF line is a blanket glob that
   re-stamps a retired case; the SVG helper must be the **flattening** loop, never `-Recurse` — a
   recursive copy already destroyed the nested set once.
5. **batch-89**: Stories A, B and E, plus the interface re-freeze (ruling 5) and the marker's rule
   number.
6. **Candidate for batch-89, found while answering an operator question:** V8's extension list is
   `(".py", ".ts", ".tsx", ".js")`. A Rust, Go or Java project passes V8 with **zero files
   classified** — and after this session's findings, that silence would read as "clean map".

## 8 · Is the flow stack-agnostic? Measured, because it was asked

**The engine is clean:** `textual` and `rich` appear **0** times in `devflow-validate.py`. The
templates deliberately show **several** ecosystems side by side — `npm run typecheck`, `vitest run`,
`pytest node`, `signature-diff inspection` — as examples of what "executed verification" means, which
is evidence **of** agnosticism. "Textual Pilot" appears three times and **always inside a menu**
(`<Textual Pilot | browser-automation | CLI subprocess | artifact on disk | none>`).

The single stack assumption in code is the extension list above (§7.6).

And the project already met this exact ambiguity: `req-template.md:65`'s **Purity-probe form rule**
exists because, in batch-09, `rg -c "textual"` matched the *word* "textual" in a docstring. The
adjective and the package name collided once already, and the collision became a standing rule.
