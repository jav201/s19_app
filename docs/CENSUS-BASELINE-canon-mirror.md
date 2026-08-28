# Baseline census — the canon-mirror backlog, frozen

> ## ✅ THE NEXT DELTA LANDED, 2026-08-26 — which is the one thing this file exists for
>
> **Increment 1 of batch-88 IS the delta this file was frozen to be diffed against**, and it
> shipped without anyone opening the file. Recorded now, by an adversarial review that noticed
> the omission — not by the increment.
>
> **The move: `302 → 306 of 570`, measured 2026-08-25.** `v22_canon_mirror` stopped testing
> SUBSTRING containment and now tests TOKEN membership. The `+4` are named rather than sampled:
> `HLR-053`, `HLR-056`, `US-064`, `US-068` — each present in the canon as a substring of a
> longer id and absent as a token.
>
> **⚠ And the +4 is not four seeding gaps, which is exactly what a frozen attributed list is
> for.** Two of the four (`HLR-053`, `HLR-056`) surface because the canon writes the range
> `HLR-053..HLR-056`, which the tokenizer swallows as ONE phantom id — a separate defect this
> batch does not fix, and the same family as the 129 non-ids this file's own table records. The
> other two appear in the canon only as their `a`/`b` splits: superseded, not unseeded. **Not
> one of the four is retired by plain seeding.** A rolling number could not have said that.
>
> **The table below is two supersessions old and is preserved, not corrected.** Its `276` and
> `280` are over a denominator of **544**; the live denominator is **570**, because every batch
> declares ids of its own — batch-88 declared 26 while the figure was being written. **The +4
> delta survives every re-measurement; the baseline survives none.** The table's diagnosis of
> the substring bug, and its quantified error of exactly 4 ids, were both CORRECT and are what
> Increment 1 confirmed by execution.

> **Frozen 2026-08-24 by `2026-08-24-batch-88`, station P0/ARQ.** Derived by command, not by hand.
> **Why this file exists:** until now the backlog was a rolling number in validator output. A number
> that moves cannot answer *"did this increment insert a hole?"* — a `+1` inside a census of 1436 is
> invisible, and this session proved it: a phantom id was minted and caught only because someone
> happened to regenerate and diff. **A frozen, attributed list makes the next delta a diff against a
> named file.** That is the whole purpose; it is not a work order.

> **Home: `docs/`, and the placement was MEASURED, not assumed.** Any `.md` under `.dev-flow/` is
> read by the Atlas id-scanner (control C-56: *an evidence transcript is corpus input*), so a file
> listing 1004 ids could perturb the very counters it records. Verified in a throwaway copy with a
> **positive control** — a sentinel id existing nowhere else — because the null result alone would
> have been vacuous:
>
> | Candidate location | sentinel reaches the census? | verdict |
> |---|---|---|
> | `.dev-flow/…/*.md` (root, batch dir, or `design/`) | **YES, +1** | scanned — safe only as a *discipline*, never a property |
> | `.dev-flow/**/01-requirements.md` | **YES**, and V22's denominator moves **+34** | reserved name, joins the IFC corpus |
> | `.dev-flow/_derived/` | no | **hard V20 BLOCK** — a file no derivation produces |
> | `.dev-flow/…/*.txt` (non-`.md`) | no | safe |
> | **`docs/` or repo root** | **no** | **safe — outside the scanner's walk. Chosen.** |

## The number was contested. Here is the reconciliation, measured.

Four figures circulated for "ids not reflected in the canon". They differ because **three different
tokenizers** answer three different questions.

| Figure | Tokenizer | Population | Verdict |
|---|---|---|---|
| **276** | `_declared_ids`, **headings only** in the 64 `01-requirements.md`, tested by **substring** | heading-declared ids | ⚠ carries a **substring-containment bug**: `HLR-007a` reads as *present* because `HLR-007` is. Quantified error: **4 ids** |
| **280** | same population, tested by **token** | heading-declared ids | the corrected form of 276 |
| **1004** | `_ATLAS_ID_REQ`, **every occurrence** in every `.md` under `.dev-flow/` except `_derived/` | headings **plus** citations | **the defensible figure** — the only token-boundary count over the full realm, and the one V20 already digest-guards |
| **1192** | a hand-rolled sweep | — | inflated by **192 punctuation artifacts** (`HLR-001.`, `HLR-045A..D.`) — a trailing `.` glued on by a permissive character class |

⚠ **Correction to a claim made earlier in this batch.** It was stated that V22 "reads only 3 files".
**That is wrong.** `_ifc_corpus()` walks all of `.dev-flow/` and collects **64** files named
`01-requirements.md`. Only **3** of them carry `FLOW`/`COMPONENT` blocks, and that 3 governs a
*different* V22 census — the unowned-LLR notices. The `276 of 544` spans all 64. The error came from
measuring the FLOW/COMPONENT source set and reporting it as the rule's scope.

## The 1004 are NOT homogeneous — and this is what the number was hiding

| Class | Count | What it is |
|---|---|---|
| **A** `declared_req` | **269** | Heading-declared in a batch `01-requirements.md`. A real requirement the canon never absorbed. **The true backlog.** |
| **B** `heading_elsewhere` | **51** | Heading-declared, but in `_arch-hlr-llr.md` / `01-requirements-architect.md` / etc. **Invisible to V22 by construction**, since it reads only `01-requirements.md`. A metric hole, not a seeding hole. |
| **C** `citation_only` | **426** | Never declared anywhere; referenced in prose or tables. Largest class. |
| **D** `retired` | **7** | Every occurrence carries a retirement marker. |
| **E** `nonatomic` | **129** | ⚠ **Not ids at all.** 97 are **range notations** harvested whole (`HLR-001..004`, `US-001..US-006`); 32 are **English prose compounds** (`LLR-level`, `US-less`, `HLR-threshold-vs-LLR`). `_ATLAS_ID_REQ` requires no digit and carries no lookahead guard. |
| **F** `spellvariant` | **11** | Zero-padding drift only: the record writes `LLR-085.1`, the canon holds `LLR-85.1`. Not debt — a normalisation bug. |
| **G** `singleton_citation` | **111** | Mentioned exactly once, ever. |

**E + F + G = 251 (25%) are not requirement debt.** **A + B = 320 (32%) are unambiguously owed.**
C + D = 433 are the judgement zone.

**A hypothesis was falsified, and it matters for any boundary decision.** *"Much of this predates the
canon"* is **not available as an explanation**: `REQUIREMENTS.md` was added **2026-03-29**; the
earliest batch directory is **2026-05-05-batch-01**. **Every absent id postdates the canon.**

**Retirement, bounded from both sides:** 7 ids carry a retirement marker on *every* occurrence
(strict floor); **189** carry one on *at least one* occurrence (loose ceiling). The 182-id gap cannot
be resolved by regex — those ids appear once in a retirement context and elsewhere in a live one.

**Shape: long-tail, not concentrated.** Top-5 dirs 22.8% · top-10 39.8% · top-20 63.9% · top-30
79.9%. Max 60, median 12; 18 of 64 contributing dirs carry ≤5 ids each. **No single batch is the
problem**, so a per-batch remediation plan needs ~30 batches to reach 80% — which is why the class
split above, not the batch ranking, is where a decision should be taken.

**Not measured:** whether any class-C citation refers to an id the canon carries under a *semantic*
rename (as opposed to the padding drift of class F). Detecting that requires reading requirement
text, not tokens.

## How to re-derive

`python ~/.claude/docs/tools/devflow-validate.py . --atlas --write`, then compare
`.dev-flow/_derived/ATLAS-ORPHANS.md`'s *"never in the canon"* line against the row count below.
**Any divergence is either progress or a new hole — and this file is what makes the two
distinguishable.**

---

|---|---|---|---|
| `HLR-001..004` | E_nonatomic | `2026-06-14-batch-11` | `2026-06-14-batch-11` |
| `HLR-001..005` | E_nonatomic | `2026-06-16-batch-12` | `2026-06-16-batch-12` |
| `HLR-001..008` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `HLR-001..009` | E_nonatomic | `2026-05-05-batch-01` | `2026-05-05-batch-01` |
| `HLR-001..HLR-003` | E_nonatomic | `2026-06-11-batch-08` | `2026-06-11-batch-08` |
| `HLR-001..HLR-005` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09`, `2026-06-16-batch-12` |
| `HLR-001..HLR-008` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-06-10-batch-07` |
| `HLR-001..HLR-009` | E_nonatomic | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-21-batch-04` |
| `HLR-001..HLR-015` | E_nonatomic | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `HLR-002-side` | E_nonatomic | `2026-06-14-batch-11` | `2026-06-14-batch-11` |
| `HLR-005-TC` | G_singleton_citation | `2026-06-11-batch-09` | `2026-06-11-batch-09` |
| `HLR-007a` | A_declared_req | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-08-24-batch-86`, `2026-08-24-batch-87` |
| `HLR-007b` | A_declared_req | `2026-05-05-batch-01` | `2026-05-05-batch-01` |
| `HLR-009` | A_declared_req | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-20-batch-02`, `2026-05-21-batch-04` |
| `HLR-010` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `HLR-011` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `HLR-012` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `HLR-033.1` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-033.2` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-033.3` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-033.4` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-033.5` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-034.1` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-034.2` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-034.3` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `HLR-038.a` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-038.b` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-039.b` | A_declared_req | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-040.b` | A_declared_req | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-040.c` | A_declared_req | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-041` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-042` | G_singleton_citation | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `HLR-042.a` | C_citation_only | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-042.b` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-042.c` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-042.d` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-042.x` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `HLR-045A` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `HLR-045A..D` | E_nonatomic | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `HLR-045B` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `HLR-045C` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `HLR-045D` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `HLR-050` | A_declared_req | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `HLR-051` | A_declared_req | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `HLR-052` | A_declared_req | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `HLR-053` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `HLR-053..HLR-057` | E_nonatomic | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `HLR-054` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `HLR-055` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `HLR-056` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `HLR-065..074` | E_nonatomic | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `HLR-072-1..7` | E_nonatomic | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `HLR-072-2` | A_declared_req | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `HLR-072-3` | A_declared_req | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `HLR-072-4` | A_declared_req | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `HLR-072-8` | A_declared_req | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `HLR-077` | A_declared_req | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `HLR-078` | A_declared_req | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `HLR-080` | A_declared_req | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `HLR-081` | A_declared_req | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `HLR-082` | A_declared_req | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `HLR-083` | A_declared_req | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `HLR-084` | A_declared_req | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `HLR-085` | G_singleton_citation | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `HLR-086` | G_singleton_citation | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `HLR-087` | G_singleton_citation | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `HLR-088` | G_singleton_citation | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `HLR-089` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-090` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-091` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-092` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-093` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-094` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-25-batch-62` |
| `HLR-096` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `HLR-097` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) BACKLOG.md` |
| `HLR-098` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `HLR-099` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `HLR-100` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-28-batch-65` |
| `HLR-101` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `HLR-107` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74`, `2026-07-31-batch-75`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-108` | A_declared_req | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76`, `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) HANDOFF-2026-07-31-batch-76-merge-gate.md` |
| `HLR-109` | A_declared_req | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76`, `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) HANDOFF-2026-07-31-batch-76-merge-gate.md` |
| `HLR-11` | G_singleton_citation | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `HLR-110` | A_declared_req | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76`, `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) HANDOFF-2026-07-31-batch-76-merge-gate.md` |
| `HLR-118` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-119` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-120` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-121` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-122` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `HLR-123` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `HLR-124` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `HLR-125` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `HLR-126` | A_declared_req | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `HLR-86` | G_singleton_citation | `2026-08-24-batch-86` | `2026-08-24-batch-86` |
| `HLR-A56` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `HLR-B2` | C_citation_only | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `HLR-B64-1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-B64-2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-B64-3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-B64-4` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-B64-5` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-B64-6` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `HLR-DoS` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `HLR-E4` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-E4..V8` | E_nonatomic | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-E5` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-E6` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-F841` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `HLR-L1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `HLR-L1..L5` | E_nonatomic | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `HLR-L2` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `HLR-L4` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `HLR-L5` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `HLR-LLR` | C_citation_only | `2026-07-11-batch-36` | `2026-07-11-batch-36`, `2026-07-11-batch-37`, `2026-07-12-batch-38`, `2026-07-27-batch-64` |
| `HLR-LLR-089..094` | E_nonatomic | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `HLR-ML1-1` | A_declared_req | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `HLR-ML1-2` | A_declared_req | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `HLR-ML2-1` | A_declared_req | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `HLR-N8-1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-1..6` | E_nonatomic | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-2..6` | E_nonatomic | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-3` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-4` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-5` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-N8-6` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `HLR-NNN` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `HLR-P1b` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50`, `2026-07-20-batch-55`, `2026-07-20-batch-56` |
| `HLR-P2` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `HLR-P2b` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `HLR-P2b56` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `HLR-SAFE-1` | A_declared_req | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `HLR-U8` | C_citation_only | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `HLR-V1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V3` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V4` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V5` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V6` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V7` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-V8` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `HLR-level` | E_nonatomic | `2026-06-13-batch-10` | `2026-06-13-batch-10`, `2026-07-16-batch-48`, `2026-07-20-batch-51` |
| `HLR-reread` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09` |
| `HLR-threshold-vs-LLR` | E_nonatomic | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `LLR-001` | C_citation_only | `2026-05-26-batch-05` | `2026-05-26-batch-05`, `2026-06-13-batch-10`, `2026-06-16-batch-12` |
| `LLR-001.1..001.4` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-05-26-batch-05`, `2026-06-11-batch-08`, `2026-06-13-batch-10` |
| `LLR-001.1..001.5` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09`, `2026-06-14-batch-11` |
| `LLR-001.1..001.8` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-001.1..003.2` | E_nonatomic | `2026-06-11-batch-08` | `2026-06-11-batch-08` |
| `LLR-001.1..003.6` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-001.1..4` | E_nonatomic | `2026-06-13-batch-10` | `2026-06-13-batch-10` |
| `LLR-001.1..LLR-003.6` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-001.3b` | G_singleton_citation | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-001.6` | A_declared_req | `2026-06-09-batch-06` | `2026-06-09-batch-06`, `2026-06-10-batch-07`, `2026-08-24-batch-86`, `2026-08-24-batch-87` |
| `LLR-001.7` | C_citation_only | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-001.8` | C_citation_only | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-001.x` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-05-26-batch-05`, `2026-06-11-batch-09` |
| `LLR-002` | D_retired | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-002.1..002.3` | E_nonatomic | `2026-06-11-batch-08` | `2026-06-11-batch-08`, `2026-06-13-batch-10`, `2026-06-14-batch-11` |
| `LLR-002.1..002.4` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-05-26-batch-05` |
| `LLR-002.1..002.6` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07`, `2026-06-11-batch-09` |
| `LLR-002.6` | A_declared_req | `2026-06-10-batch-07` | `2026-06-10-batch-07`, `2026-06-11-batch-09`, `2026-07-24-batch-53` |
| `LLR-002.8` | A_declared_req | `2026-06-10-batch-07` | `2026-06-10-batch-07`, `2026-07-24-batch-53` |
| `LLR-002.8-local` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-002.9` | C_citation_only | `2026-07-24-batch-53` | `2026-07-24-batch-53` |
| `LLR-002.x` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09` |
| `LLR-003.1..003.2` | E_nonatomic | `2026-06-11-batch-08` | `2026-06-11-batch-08` |
| `LLR-003.1..003.3` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04`, `2026-06-13-batch-10`, `2026-06-14-batch-11` |
| `LLR-003.1..003.4` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09` |
| `LLR-003.1..003.5` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-003.1..003.6` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-003.1..6` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-003.1..LLR-003.6` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-003.3b` | G_singleton_citation | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-003.4` | A_declared_req | `2026-05-26-batch-05` | `2026-05-26-batch-05`, `2026-06-10-batch-07`, `2026-06-11-batch-09`, `2026-06-16-batch-12`, `2026-07-24-batch-53` |
| `LLR-003.6` | A_declared_req | `2026-05-26-batch-05` | `2026-05-26-batch-05`, `2026-07-24-batch-53` |
| `LLR-003.7` | A_declared_req | `2026-07-24-batch-53` | `2026-07-24-batch-53` |
| `LLR-003.x` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09` |
| `LLR-004` | G_singleton_citation | `2026-06-16-batch-12` | `2026-06-16-batch-12` |
| `LLR-004.1..004.3` | E_nonatomic | `2026-06-14-batch-11` | `2026-06-14-batch-11` |
| `LLR-004.1..004.4` | E_nonatomic | `2026-06-11-batch-08` | `2026-06-11-batch-08` |
| `LLR-004.1..004.5` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04`, `2026-06-10-batch-07` |
| `LLR-004.1..004.6` | E_nonatomic | `2026-05-20-batch-02` | `2026-05-20-batch-02`, `2026-06-11-batch-09` |
| `LLR-004.1..004.7` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09` |
| `LLR-004.1..004.8` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-004.1..004.9` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-004.6-resolved` | E_nonatomic | `2026-06-11-batch-09` | `2026-06-11-batch-09` |
| `LLR-004.x` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09` |
| `LLR-005` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-06-11-batch-09`, `2026-06-16-batch-12` |
| `LLR-005.1..005.4` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09` |
| `LLR-005.1..005.6` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-06-10-batch-07` |
| `LLR-005.1..5` | E_nonatomic | `2026-05-05-batch-01` | `2026-05-05-batch-01` |
| `LLR-005.x` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09`, `2026-06-16-batch-12`, `2026-08-06-batch-78` |
| `LLR-006` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-006.1..006.5` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-006.1..006.6` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-006.1..006.8` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-006.2-8` | G_singleton_citation | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-006.2..006.8` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-006.x` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-11-batch-09` |
| `LLR-007.1..007.4` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-007.1..007.5` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-007.1..007.6` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-007.1..007.7` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-007.1..007.8` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-007.1..LLR-007.5` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-007.1..LLR-007.6` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `LLR-007.5-local` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-007.8` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-06-10-batch-07` |
| `LLR-007.x` | C_citation_only | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-10-batch-07`, `2026-06-11-batch-09` |
| `LLR-008` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-20-batch-02`, `2026-05-21-batch-03` |
| `LLR-008.1..008.3` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04` |
| `LLR-008.1..008.5` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-008.4` | C_citation_only | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-008.5` | G_singleton_citation | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-008.x` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-21-batch-03`, `2026-05-21-batch-04`, `2026-06-10-batch-07`, `2026-06-11-batch-09` |
| `LLR-009` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-009.1..009.3` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-009.1..LLR-009.3` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-009.x` | C_citation_only | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-010` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-010.1` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-010.2` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-011` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-013` | G_singleton_citation | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `LLR-013.2` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02`, `2026-06-17-batch-13` |
| `LLR-013.x` | G_singleton_citation | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `LLR-014.2` | A_declared_req | `2026-05-20-batch-02` | `2026-05-20-batch-02`, `2026-06-17-batch-13`, `2026-07-12-batch-38` |
| `LLR-014.x` | G_singleton_citation | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `LLR-015` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `LLR-015.4` | A_declared_req | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `LLR-015.5` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `LLR-015.x` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `LLR-016` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `LLR-016.2` | A_declared_req | `2026-06-23-batch-14` | `2026-06-23-batch-14`, `2026-06-24-batch-15` |
| `LLR-016.3` | A_declared_req | `2026-06-23-batch-14` | `2026-06-23-batch-14`, `2026-06-24-batch-15` |
| `LLR-017` | C_citation_only | `2026-06-25-batch-16` | `2026-06-25-batch-16` |
| `LLR-017.2` | A_declared_req | `2026-06-25-batch-16` | `2026-06-25-batch-16` |
| `LLR-017.4` | A_declared_req | `2026-06-25-batch-16` | `2026-06-25-batch-16` |
| `LLR-019.2` | A_declared_req | `2026-06-26-batch-17` | `2026-06-26-batch-17` |
| `LLR-020.2` | A_declared_req | `2026-06-26-batch-17` | `2026-06-26-batch-17` |
| `LLR-023.2` | A_declared_req | `2026-06-26-batch-18` | `2026-06-26-batch-18` |
| `LLR-024.3` | A_declared_req | `2026-06-29-batch-19` | `2026-06-29-batch-19` |
| `LLR-027.2` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-027.3` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-027.4` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-028.2` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-028.3` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-028.4` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-029.2` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-029.3` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-029.4` | C_citation_only | `2026-06-29-batch-20` | `2026-06-29-batch-20` |
| `LLR-030.2` | C_citation_only | `2026-06-29-batch-21` | `2026-06-29-batch-21` |
| `LLR-030.3` | C_citation_only | `2026-06-29-batch-21` | `2026-06-29-batch-21` |
| `LLR-031.2` | C_citation_only | `2026-06-29-batch-21` | `2026-06-29-batch-21` |
| `LLR-032.2` | C_citation_only | `2026-06-29-batch-21` | `2026-06-29-batch-21` |
| `LLR-033.1-033.4` | G_singleton_citation | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `LLR-033.2` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-033.3` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-033.3b` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22`, `2026-07-10-batch-35` |
| `LLR-033.4` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-033.5` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-034.2` | C_citation_only | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-034.3` | G_singleton_citation | `2026-07-01-batch-22` | `2026-07-01-batch-22` |
| `LLR-035.1..LLR-035.5` | E_nonatomic | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-035.2` | A_declared_req | `2026-07-01-batch-23` | `2026-07-01-batch-23`, `2026-07-06-batch-26` |
| `LLR-035.3` | A_declared_req | `2026-07-01-batch-23` | `2026-07-01-batch-23`, `2026-07-06-batch-26` |
| `LLR-035.4` | A_declared_req | `2026-07-01-batch-23` | `2026-07-01-batch-23`, `2026-07-06-batch-26` |
| `LLR-035.5` | A_declared_req | `2026-07-01-batch-23` | `2026-07-01-batch-23`, `2026-07-06-batch-26` |
| `LLR-035.6` | A_declared_req | `2026-07-01-batch-23` | `2026-07-01-batch-23` |
| `LLR-035.N` | C_citation_only | `2026-07-01-batch-23` | `2026-07-01-batch-23` |
| `LLR-036.1..036.6` | E_nonatomic | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-036.1..6` | E_nonatomic | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-036.2` | A_declared_req | `2026-07-02-batch-24` | `2026-07-02-batch-24`, `2026-07-06-batch-26` |
| `LLR-036.3` | A_declared_req | `2026-07-02-batch-24` | `2026-07-02-batch-24`, `2026-07-06-batch-26`, `2026-07-11-batch-37` |
| `LLR-036.4` | A_declared_req | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-036.5` | A_declared_req | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-036.6` | A_declared_req | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-037.1-.3` | G_singleton_citation | `2026-07-02-batch-24` | `2026-07-02-batch-24` |
| `LLR-037.1..3` | E_nonatomic | `2026-07-06-batch-26` | `2026-07-06-batch-26` |
| `LLR-037.4-fixed` | E_nonatomic | `2026-07-02-batch-24` | `2026-07-02-batch-24` |
| `LLR-038.4` | A_declared_req | `2026-07-02-batch-24` | `2026-07-02-batch-24` |
| `LLR-038.5` | A_declared_req | `2026-07-02-batch-24` | `2026-07-02-batch-24` |
| `LLR-041` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-041.1..041.11` | E_nonatomic | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.1..11` | E_nonatomic | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.2` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-041.3` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.4` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.5` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.6` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.8` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.9` | A_declared_req | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-041.x` | G_singleton_citation | `2026-07-06-batch-27` | `2026-07-06-batch-27` |
| `LLR-042` | G_singleton_citation | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-042.10` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.13` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.2` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.4` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.5` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.6` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.8` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.9` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-042.N` | C_citation_only | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `LLR-043` | D_retired | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043-retire.1` | E_nonatomic | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043-retire.2` | E_nonatomic | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043-retire.3` | E_nonatomic | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043-retire.4` | E_nonatomic | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043-retire.x` | E_nonatomic | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R1` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R2` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R3` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R4` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R5` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R6` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-043.R7` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-044.2` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-044.3` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-044.4` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-044.5` | C_citation_only | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-044.x` | D_retired | `2026-07-08-batch-29` | `2026-07-08-batch-29` |
| `LLR-045` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045A.1` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045A.3` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045A.4` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045A.6` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045B` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045C` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045C.2` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045D.1` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045D.2` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-045D.4` | G_singleton_citation | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `LLR-050.1` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-050.2` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-050.3` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-050.4` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.1` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.2` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.4` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.4-.8` | G_singleton_citation | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.5` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.6` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.7` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-051.8` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-052.1` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-052.2` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-052.3` | C_citation_only | `2026-07-09-batch-33` | `2026-07-09-batch-33` |
| `LLR-053.2` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-053.3` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-053.4` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-053.5` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-053.6` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-053.7` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-054.2` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-054.3` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-054.4` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-054.5` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-055.2` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-055.3` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-055.4` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-056.2` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-056.3` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35`, `2026-07-16-batch-48` |
| `LLR-056.4` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-056.5` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-057.1-.4` | G_singleton_citation | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-057.2` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `LLR-057.3` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35`, `2026-07-11-batch-36` |
| `LLR-057.4` | A_declared_req | `2026-07-10-batch-35` | `2026-07-10-batch-35`, `2026-07-11-batch-36` |
| `LLR-058.2` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-058.3` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36`, `2026-07-11-batch-37` |
| `LLR-058.4` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-059.2` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-059.3` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-060.2` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-060.3` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36`, `2026-07-11-batch-37` |
| `LLR-060.4` | A_declared_req | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-060.5` | G_singleton_citation | `2026-07-11-batch-36` | `2026-07-11-batch-36` |
| `LLR-061.2` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-061.3` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-062.2` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-062.3` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-063.1-063.4` | G_singleton_citation | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `LLR-063.2` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37`, `2026-07-15-batch-46` |
| `LLR-063.3` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37`, `2026-07-15-batch-46` |
| `LLR-063.5` | D_retired | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `LLR-064.2` | A_declared_req | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `LLR-064.3` | A_declared_req | `2026-07-15-batch-46` | `2026-07-15-batch-46` |
| `LLR-064a.2` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-064b.2` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-064b.3` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-064b.4` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `LLR-065.2` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38`, `2026-07-15-batch-47` |
| `LLR-066.2` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38`, `2026-07-15-batch-47` |
| `LLR-066.3` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38`, `2026-07-15-batch-47` |
| `LLR-066.4` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-066.5` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-066.6` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-067.2` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38`, `2026-07-15-batch-47` |
| `LLR-067.4` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-068.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-068.3` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-068a` | G_singleton_citation | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068a.1-3` | G_singleton_citation | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068a.2` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068a.3` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068a.4` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068b.1-3` | G_singleton_citation | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068b.2` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068b.3` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-068b.4` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `LLR-069.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-069.3` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-069.4` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-070` | G_singleton_citation | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-070.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-071.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-072` | C_citation_only | `2026-07-30-batch-72` | `2026-07-30-batch-72`, `2026-08-01-batch-77` |
| `LLR-072-1.2` | B_heading_elsewhere | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-2.1` | B_heading_elsewhere | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-2.2` | B_heading_elsewhere | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-2.3` | D_retired | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-2.4` | B_heading_elsewhere | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-6.1` | C_citation_only | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-6.2` | C_citation_only | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072-7.1` | C_citation_only | `2026-07-30-batch-72` | `2026-07-30-batch-72`, `2026-08-01-batch-77` |
| `LLR-072-8.1` | B_heading_elsewhere | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-072.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47`, `2026-08-01-batch-77` |
| `LLR-072.3` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47`, `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) HANDOFF-2026-08-01-batch-77-phase3.md` |
| `LLR-072.4` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47`, `2026-08-01-batch-77` |
| `LLR-072.x` | G_singleton_citation | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-073.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-073.3` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-074.2` | C_citation_only | `2026-07-15-batch-47` | `2026-07-15-batch-47` |
| `LLR-075` | G_singleton_citation | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-075.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-075.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-075.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-075.5` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-075.6` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-076.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-076.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-076.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.1` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.5` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-077.6` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-078.1` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-078.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-078.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-078.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-078.5` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-079.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48`, `2026-07-26-batch-63` |
| `LLR-079.5` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48`, `2026-07-26-batch-63` |
| `LLR-079.x` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-080.1` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.5` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.6` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-080.7` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-081.1` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-081.2` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-081.3` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-081.4` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-082.1` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.1-.5` | G_singleton_citation | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.1-.6` | G_singleton_citation | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.2` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.3` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.4` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.5` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-082.6` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.1` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.1-.6` | G_singleton_citation | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.2` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.3` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.4` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.5` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-083.6` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.1` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.1-.6` | G_singleton_citation | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.1-.8` | G_singleton_citation | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.2` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.3` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.4` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.5` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.6` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.7` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-084.8` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `LLR-085` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-085.1` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-085.1..088.7` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-085.2` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-085.3` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-085.x` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.1` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.1..086.5` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.2` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.3` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.4` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.5` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-086.x` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-087.1` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-087.2` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-087.3` | F_spellvariant | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-087.x` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088` | G_singleton_citation | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `LLR-088.1` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.1..088.7` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.2` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.3` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.4` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51`, `2026-07-22-batch-52` |
| `LLR-088.5` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.6` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.7` | A_declared_req | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-088.x` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-089` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-089.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-089.1-3` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-089.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-089.3` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-089.4` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-089.5` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-089.6` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-089.x` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-089.x..094.x` | E_nonatomic | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `LLR-090.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-090.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-090.3` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-090.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-090.5` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-090.6` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-091.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-091.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-091.3` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-091.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-092.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-092.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-092.3` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-092.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-093.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-093.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-093.3` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-093.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-093.x` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-094` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-094.1` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-094.2` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52`, `2026-07-26-batch-63` |
| `LLR-094.3` | A_declared_req | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `LLR-095` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62`, `2026-07-26-batch-63` |
| `LLR-095.1` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-095.2` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-095.3` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-095.4` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-096.1` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-096.2` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-097` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-097.1` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-097.2` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-098.1` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-098.2` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-098.3` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-099.1` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-0XX.Y` | C_citation_only | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-100` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-100.1` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-100.1..4` | E_nonatomic | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-28-batch-65` |
| `LLR-100.2` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-27-batch-64` |
| `LLR-100.3` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-100.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-100.x` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101` | G_singleton_citation | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101.1` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101.1..4` | E_nonatomic | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101.2` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101.3` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-101.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-102.1-.4` | G_singleton_citation | `(.dev-flow root file) BACKLOG.md` | `(.dev-flow root file) BACKLOG.md` |
| `LLR-102.1..4` | E_nonatomic | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-102.2` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-102.3` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-31-batch-75` |
| `LLR-102.4` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-31-batch-75`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-102.5` | C_citation_only | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-07-31-batch-75` |
| `LLR-102.6` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `LLR-102.x` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-103.x` | C_citation_only | `2026-07-28-batch-65` | `2026-07-28-batch-65` |
| `LLR-104.3` | A_declared_req | `2026-07-28-batch-70` | `2026-07-28-batch-70` |
| `LLR-104.4` | A_declared_req | `2026-07-28-batch-70` | `2026-07-28-batch-70` |
| `LLR-104.5` | A_declared_req | `2026-07-28-batch-70` | `2026-07-28-batch-70` |
| `LLR-105.3` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-105.6` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-105.9` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-106` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `LLR-106.2` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-106.4` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74`, `(.dev-flow root file) HANDOFF-2026-07-31-batch-74-resume.md` |
| `LLR-106.x` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-107` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-107.2` | G_singleton_citation | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-107.4` | G_singleton_citation | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `LLR-107.x` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74`, `2026-07-31-batch-75` |
| `LLR-108.1` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.2` | G_singleton_citation | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `LLR-108.3` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.4` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.5` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.6` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.7` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76`, `(.dev-flow root file) HANDOFF-2026-07-31-batch-76-merge-gate.md` |
| `LLR-108.8` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.9` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-108.x` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `LLR-109.1` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-109.2` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-109.3` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-109.4` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-109.5` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-109.6` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-11` | G_singleton_citation | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-110` | G_singleton_citation | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-110.1` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-110.2` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-110.3` | C_citation_only | `2026-07-31-batch-75` | `2026-07-31-batch-75`, `2026-07-31-batch-76` |
| `LLR-111` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.1` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.3` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.4` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) HANDOFF-2026-08-01-batch-77-phase3.md` |
| `LLR-111.5` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.6` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) HANDOFF-2026-08-01-batch-77-phase3.md` |
| `LLR-111.7` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md`, `(.dev-flow root file) HANDOFF-2026-08-01-batch-77-phase3.md` |
| `LLR-111.8` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-111.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-112.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-112.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-113.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-113.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-114.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-114.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-115.1` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-115.3` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-115.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116` | G_singleton_citation | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116.3` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116.4` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116.5` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-116.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-117` | G_singleton_citation | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-117.2` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-117.x` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `LLR-118` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-118.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-118.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-118.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-118.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-119.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-119.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-119.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-119.4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-119.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-120` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85` |
| `LLR-120.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `2026-08-21-batch-85` |
| `LLR-120.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `2026-08-21-batch-85`, `2026-08-24-batch-87`, `(.dev-flow root file) BACKLOG-CODE.md`, `design` |
| `LLR-120.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-120.4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-120.5` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `design` |
| `LLR-120.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-121.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-121.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-121.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-121.4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-121.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-122.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79` |
| `LLR-122.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-122.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-122.4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-122.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-123.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-123.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-123.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-123.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-124.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-124.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-124.3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-124.4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-124.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-125.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-125.2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-125.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-126.1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `2026-08-07-batch-79`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `LLR-126.x` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-86` | G_singleton_citation | `2026-08-24-batch-86` | `2026-08-24-batch-86` |
| `LLR-86.99` | C_citation_only | `2026-08-24-batch-86` | `2026-08-24-batch-86` |
| `LLR-87` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85`, `2026-08-24-batch-87` |
| `LLR-99.9` | G_singleton_citation | `2026-08-24-batch-86` | `2026-08-24-batch-86` |
| `LLR-A` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-A56.1` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.1..5` | E_nonatomic | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.1..6` | E_nonatomic | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.2` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.3` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.4` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.5` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.n` | G_singleton_citation | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-A56.x` | G_singleton_citation | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-AC` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13`, `2026-06-24-batch-15` |
| `LLR-ALIGN.1` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.2` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.3` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.4` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.5` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.6` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.7` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.8` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.9` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.n` | G_singleton_citation | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-ALIGN.x` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-B` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-B64-1.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-1.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-1.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-1.4` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-1.5` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-2.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-2.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-2.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-3.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-3.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-3.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-4.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-4.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-4.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-4.4` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-5.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-5.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-5.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-5.4` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-6.1` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-6.2` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-6.3` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-6.4` | C_citation_only | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-B64-7.1` | G_singleton_citation | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-C` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-D` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-DoS.1` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-E` | B_heading_elsewhere | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `LLR-E4..V8` | E_nonatomic | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-E4.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E4.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E4.3` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E5.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E5.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E6.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E6.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-E6.3` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-F841.1` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `LLR-GRP-001.10` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.11` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.12` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.14` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.15` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.3` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.4` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.5` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.6` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.7` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.8` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-GRP-001.x` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-L1.1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L1.2` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L1.3` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L1.4` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L2.1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L2.2` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L2.4` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L3.1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L4.1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L4.2` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-L5.1` | A_declared_req | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `LLR-ML1-1.1` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.1..1.6` | E_nonatomic | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.2` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.3` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.4` | G_singleton_citation | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.5` | G_singleton_citation | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-1.6` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-2.1` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML1-2.2` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-ML2-1.1` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-N8-1` | G_singleton_citation | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-1.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-1.1..6.2` | E_nonatomic | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-1.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-1.3` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-1.4` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-2.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-2.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-3.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-3.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-3.3` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-4.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-4.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-4.3` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-5.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-5.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-6.1` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-N8-6.2` | A_declared_req | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `LLR-NNN.M` | C_citation_only | `2026-05-20-batch-02` | `2026-05-20-batch-02`, `2026-06-16-batch-12` |
| `LLR-P1b.1` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50`, `2026-07-20-batch-55` |
| `LLR-P1b.1-4` | D_retired | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `LLR-P1b.2` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-P1b.3` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-P1b.4` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-P1b.5` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-P1b.6` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `LLR-P2.1` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50`, `2026-07-20-batch-55`, `2026-07-20-batch-56` |
| `LLR-P2.2` | A_declared_req | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `LLR-P2b.1` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55`, `2026-07-20-batch-56` |
| `LLR-P2b56.1` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-SAFE-1.1` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `LLR-SENSE-2` | G_singleton_citation | `design` | `design` |
| `LLR-SENSE-3` | G_singleton_citation | `design` | `design` |
| `LLR-SENSE-4` | C_citation_only | `design` | `design` |
| `LLR-SUP.1` | A_declared_req | `2026-07-20-batch-55` | `2026-07-20-batch-55`, `2026-07-20-batch-56` |
| `LLR-SUP.2` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-SUP56.1` | A_declared_req | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `LLR-V1.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V1.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V2.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V2.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V3.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V4.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V5.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V5.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V5.3` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58`, `2026-07-30-batch-72` |
| `LLR-V5.4` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V6.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V6.2` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V6.x` | G_singleton_citation | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V7.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-V8.1` | A_declared_req | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `LLR-WID-001.1..6` | E_nonatomic | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-WID-001.3` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-WID-001.5` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-WID-001.x` | G_singleton_citation | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `LLR-aligned` | E_nonatomic | `2026-07-01-batch-23` | `2026-07-01-batch-23`, `2026-07-02-batch-24` |
| `LLR-binding` | E_nonatomic | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `LLR-by-HLR-group` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03`, `2026-05-21-batch-04` |
| `LLR-cluster` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-defined` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-four` | E_nonatomic | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `LLR-interaction` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-level` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07`, `2026-06-11-batch-08`, `2026-06-11-batch-09`, `2026-06-16-batch-12`, `2026-07-12-batch-38`, `2026-07-15-batch-47`, `2026-07-16-batch-48`, `2026-07-27-batch-64`, `2026-07-30-batch-72` |
| `LLR-mapped` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `LLR-named` | E_nonatomic | `2026-05-26-batch-05` | `2026-05-26-batch-05` |
| `LLR-nnn.n` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `LLR-one-intent` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04` |
| `LLR-required` | E_nonatomic | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `LLR-rewriting` | E_nonatomic | `2026-07-30-batch-72` | `2026-07-30-batch-72` |
| `LLR-spec` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `LLR-traced` | E_nonatomic | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `LLR-verify` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `US-001..006` | E_nonatomic | `2026-05-05-batch-01` | `2026-05-05-batch-01` |
| `US-001..US-005` | E_nonatomic | `2026-05-21-batch-04` | `2026-05-21-batch-04`, `2026-06-11-batch-08` |
| `US-001..US-006` | E_nonatomic | `2026-05-05-batch-01` | `2026-05-05-batch-01` |
| `US-001..US-007` | E_nonatomic | `2026-05-21-batch-03` | `2026-05-21-batch-03` |
| `US-001..US-014` | E_nonatomic | `2026-05-20-batch-02` | `2026-05-20-batch-02` |
| `US-002..005` | E_nonatomic | `2026-06-10-batch-07` | `2026-06-10-batch-07` |
| `US-002..US-005` | E_nonatomic | `2026-06-09-batch-06` | `2026-06-09-batch-06`, `2026-06-10-batch-07` |
| `US-006..US-009` | E_nonatomic | `2026-06-14-batch-11` | `2026-06-14-batch-11` |
| `US-013-a` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-013-b` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-013-c` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-014-a` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-014-b` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-014-c` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-014-d` | C_citation_only | `2026-06-17-batch-13` | `2026-06-17-batch-13` |
| `US-020` | B_heading_elsewhere | `2026-06-26-batch-17` | `2026-06-26-batch-17` |
| `US-022c` | G_singleton_citation | `2026-06-26-batch-18` | `2026-06-26-batch-18` |
| `US-026-F1` | C_citation_only | `2026-07-01-batch-23` | `2026-07-01-batch-23` |
| `US-036` | B_heading_elsewhere | `2026-07-02-batch-24` | `2026-07-02-batch-24`, `2026-07-06-batch-26`, `2026-07-06-batch-27` |
| `US-037` | B_heading_elsewhere | `2026-07-02-batch-24` | `2026-07-02-batch-24`, `2026-07-06-batch-26`, `2026-07-06-batch-27`, `2026-07-07-batch-28` |
| `US-040a` | G_singleton_citation | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `US-040b` | C_citation_only | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `US-041` | B_heading_elsewhere | `2026-07-07-batch-28` | `2026-07-07-batch-28` |
| `US-044..047` | E_nonatomic | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
| `US-045d` | C_citation_only | `2026-07-14-batch-45` | `2026-07-14-batch-45` |
| `US-053..US-057` | E_nonatomic | `2026-07-10-batch-35` | `2026-07-10-batch-35` |
| `US-062-1` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-062-2` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-062-3` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-062-N` | G_singleton_citation | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-064` | A_declared_req | `2026-07-11-batch-37` | `2026-07-11-batch-37`, `2026-07-12-batch-38` |
| `US-064-adjacent` | E_nonatomic | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `US-064c` | G_singleton_citation | `2026-07-11-batch-37` | `2026-07-11-batch-37` |
| `US-065..068` | E_nonatomic | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `US-068` | A_declared_req | `2026-07-12-batch-38` | `2026-07-12-batch-38` |
| `US-082` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `US-083` | C_citation_only | `2026-07-18-batch-49` | `2026-07-18-batch-49` |
| `US-085` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-085..087` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-085..088` | E_nonatomic | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-086` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-087` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-088` | C_citation_only | `2026-07-20-batch-51` | `2026-07-20-batch-51` |
| `US-77-1` | B_heading_elsewhere | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `US-77-3` | B_heading_elsewhere | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `US-77-4` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77` |
| `US-77-7` | B_heading_elsewhere | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `US-77-8` | C_citation_only | `2026-08-01-batch-77` | `2026-08-01-batch-77`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `US-78-1` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-2` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-3` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78`, `design` |
| `US-78-4` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-5` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-6` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-7` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-8` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-78-9` | C_citation_only | `2026-08-06-batch-78` | `2026-08-06-batch-78` |
| `US-85-1` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85` |
| `US-85-2` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85` |
| `US-85-3` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85` |
| `US-85-4` | C_citation_only | `2026-08-21-batch-85` | `2026-08-21-batch-85`, `design` |
| `US-A` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14`, `2026-07-03-batch-25` |
| `US-A56` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `US-ALIGN` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `US-B` | C_citation_only | `2026-06-23-batch-14` | `2026-06-23-batch-14`, `2026-07-03-batch-25` |
| `US-B62` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-B62-2` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-B62-3` | C_citation_only | `2026-07-25-batch-62` | `2026-07-25-batch-62` |
| `US-B63-1` | A_declared_req | `2026-07-26-batch-63` | `2026-07-26-batch-63`, `2026-08-24-batch-86`, `2026-08-24-batch-87` |
| `US-B63-2` | A_declared_req | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `US-B63-3` | B_heading_elsewhere | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `US-B63-D1` | B_heading_elsewhere | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `US-B63-D2` | B_heading_elsewhere | `2026-07-26-batch-63` | `2026-07-26-batch-63` |
| `US-B64-1..3` | E_nonatomic | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `US-B64-2-over-optimisation` | E_nonatomic | `2026-07-28-batch-65` | `2026-07-28-batch-65` |
| `US-B64-3` | A_declared_req | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `US-B64-4` | A_declared_req | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `US-B64-5` | A_declared_req | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `US-B64-6` | A_declared_req | `2026-07-27-batch-64` | `2026-07-27-batch-64` |
| `US-B74-3` | C_citation_only | `2026-07-31-batch-74` | `2026-07-31-batch-74` |
| `US-B75-1` | A_declared_req | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `US-B75-3` | A_declared_req | `2026-07-31-batch-75` | `2026-07-31-batch-75` |
| `US-C` | G_singleton_citation | `2026-07-03-batch-25` | `2026-07-03-batch-25` |
| `US-C52-1` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-1..6` | E_nonatomic | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-2` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-3` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-4` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-4a` | G_singleton_citation | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-4b` | G_singleton_citation | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-5` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-C52-6` | C_citation_only | `2026-07-22-batch-52` | `2026-07-22-batch-52` |
| `US-CRC1` | C_citation_only | `2026-07-20-batch-57` | `2026-07-20-batch-57` |
| `US-CRC2` | C_citation_only | `2026-07-20-batch-57` | `2026-07-20-batch-57` |
| `US-CRC3` | C_citation_only | `2026-07-20-batch-57` | `2026-07-20-batch-57` |
| `US-CRC4` | C_citation_only | `2026-07-20-batch-57` | `2026-07-20-batch-57` |
| `US-D` | D_retired | `2026-07-03-batch-25` | `2026-07-03-batch-25` |
| `US-DoS` | C_citation_only | `2026-07-20-batch-55` | `2026-07-20-batch-55` |
| `US-E4` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58`, `2026-07-21-batch-59` |
| `US-E5` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-E6` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-F841` | C_citation_only | `2026-07-19-batch-50` | `2026-07-19-batch-50` |
| `US-FBP2-2` | C_citation_only | `2026-07-28-batch-70` | `2026-07-28-batch-70` |
| `US-H` | G_singleton_citation | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `US-I` | G_singleton_citation | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `US-J` | G_singleton_citation | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `US-K` | G_singleton_citation | `2026-06-23-batch-14` | `2026-06-23-batch-14` |
| `US-L1` | C_citation_only | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `US-L1..L5` | E_nonatomic | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `US-L2` | C_citation_only | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `US-L4` | C_citation_only | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `US-L5` | C_citation_only | `2026-07-21-batch-59` | `2026-07-21-batch-59`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `US-ML1` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `US-ML2` | C_citation_only | `2026-07-20-batch-54` | `2026-07-20-batch-54` |
| `US-N8-1` | C_citation_only | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-N8-1..5` | E_nonatomic | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-N8-2` | C_citation_only | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-N8-3` | C_citation_only | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-N8-4` | C_citation_only | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-N8-5` | C_citation_only | `2026-07-23-batch-n8` | `2026-07-23-batch-n8` |
| `US-NNN` | C_citation_only | `2026-05-05-batch-01` | `2026-05-05-batch-01`, `2026-05-20-batch-02`, `2026-06-11-batch-08`, `2026-06-11-batch-09`, `2026-06-13-batch-10`, `2026-06-14-batch-11`, `2026-06-16-batch-12`, `2026-06-17-batch-13`, `2026-06-23-batch-14`, `2026-06-24-batch-15`, `2026-06-25-batch-16`, `2026-06-26-batch-17`, `2026-06-26-batch-18`, `2026-06-29-batch-19`, `2026-07-20-batch-51` |
| `US-P1b` | C_citation_only | `2026-07-19-batch-50` | `2026-07-19-batch-50`, `2026-07-20-batch-55` |
| `US-P2` | B_heading_elsewhere | `2026-07-16-batch-48` | `2026-07-16-batch-48`, `2026-07-19-batch-50` |
| `US-P2b` | C_citation_only | `2026-07-20-batch-55` | `2026-07-20-batch-55`, `2026-07-20-batch-56` |
| `US-P2b56` | C_citation_only | `2026-07-20-batch-56` | `2026-07-20-batch-56` |
| `US-P3` | B_heading_elsewhere | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `US-P5` | B_heading_elsewhere | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `US-P6` | B_heading_elsewhere | `2026-07-16-batch-48` | `2026-07-16-batch-48` |
| `US-V1` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V1..V8` | E_nonatomic | `2026-07-21-batch-59` | `2026-07-21-batch-59` |
| `US-V2` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V3` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V4` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V5` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V6` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58`, `2026-08-06-batch-78`, `(.dev-flow root file) BACKLOG-CODE.md` |
| `US-V7` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58` |
| `US-V8` | C_citation_only | `2026-07-20-batch-58` | `2026-07-20-batch-58`, `2026-07-21-batch-59`, `2026-07-30-batch-72` |
| `US-less` | E_nonatomic | `2026-07-06-batch-26` | `2026-07-06-batch-26`, `2026-07-07-batch-28` |
| `US-nnn` | C_citation_only | `2026-07-09-batch-32` | `2026-07-09-batch-32` |
