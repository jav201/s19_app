# batch-64 — MEASUREMENT PASS against the FROZEN §3 (independent measurer)

> **FREEZE VERIFIED: all seven hashes reproduce.** Six blocks + the concatenation, re-extracted by me
> from the §3.0 extraction rule on raw bytes. Measurement was authorised to proceed and did.
>
> **`AT-B64-04` — the blocking one — is DISCHARGED: `9/9 GREEN` against block 2 (`4b4e3bad…`), with
> three biting mutations at `6/9`, `7/9` and `8/9` on disjoint occurrence sets.** `arch BLOCKER-1` is
> now genuinely closed, against provably-shipping bytes.
>
> **And the fold-2 mutation is not merely mis-attributed — it is DEAD.** *"Delete the never-a-character-
> list clause"* against the frozen bytes returns **`9/9`, losing nothing at all.** My audit predicted it
> would fall to `8/9`; the true answer is that it does not redden the arm at any value, because
> restoring `D-01…D-04` (which closed `arch BLOCKER-3`) gave occurrences #2, #5 and #9 **independent
> carriers**. Closing one blocker silently disarmed the mutation another blocker's discharge relied on.
> **Single-clause mutations are no longer a valid reddening discipline for this rider.**
>
> **`PP-5` — authored but never run — is DISCHARGED: `RED / GREEN / RED`, and its two clauses are
> separable** (a range-only fix leaves it RED). `LLR-B64-5.4`, the batch's residual orphan, now has a
> working observer.
>
> **§6 arithmetic ruling: the file will show `+8 632 B`, not `8 631` and not `8 630`.** Measured by
> simulating the two edits on a scratch copy. The third term the fold found (the new bullet's line
> terminator) is real; there is a **fourth** it did not find — the rider abuts `(Origin:` and needs one
> separating space.
>
> **Nothing blocks Phase 3.** Every arm is GREEN against a named block hash; every predicate reddens
> under an executed mutation.

**Measurer standing.** I authored none of the spec, corpus or blocks. Files read at a single point in
time (§0). Every figure below names the block hash it was measured against, per §3.0 rule 2.

---

## §0 — Read time, baselines, and what I did not touch

**Spec read `2026-07-27 23:35:55Z`; measurement closed `23:43:44Z`. The spec did not move during the
pass** — `27df9b364bde229aeaa79b4ddcf94faf60adf1142ef3042f7554b7804f749d9a`, 1 220 lines / 142 479 B,
identical at start and end. Nothing else was running, and I verified that rather than assuming it.

**All five baselines UNMODIFIED, verified at start and again at end:**

| file | SHA256 | start | end |
|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` | ✓ | ✓ |
| `~/.claude/skills/tui-design/VERIFY.md` | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` | ✓ | ✓ |
| `…/memory/project_devflow_control_lineage.md` | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` | ✓ | ✓ |
| `docs/engineering-rules.md` | `278b808d9438a7291c31f8965e6eb20313989a77c7535c9c7a9fae8fa49947cf` | ✓ | ✓ |
| `.dev-flow/BACKLOG.md` | `118b1ca14d87956f2c64e46e8d0b410db2caa84c7be345f33a11f40f46bfb690` | ✓ | ✓ |

The §6 simulation ran on a **scratch copy** in the session scratchpad. `git status` shows only
`state.json` and the untracked batch directory. I wrote one file: this one.

---

## §1 — STEP 0: the freeze, re-verified

I implemented §3.0's extraction rule myself on raw bytes — *the bytes between the LF terminating the
opening ` ```markdown ` fence and the LF preceding the closing fence, exclusive of that final LF* —
locating each block by its `### §3.N` heading rather than by line number.

```
#   block                      bytes   manifest lines   sha256 prefix     verdict
1   §3.1 C-40                  6219    6219     1       5cb146e980deb639  MATCH
2   §3.2 C-35 rider            2411    2411     1       4b4e3bad391c0962  MATCH
3   §3.3 C-42                  4306    4306    11       db1fa905083ec96a  MATCH
4   §3.4 VERIFY extension      1540    1540    19       b1cdc97013f792d2  MATCH
5   §3.5 lineage entry         5962    5962     6       059b7badc4fd9ed9  MATCH
6   §3.6 BACKLOG reconcil.     7265    7265    18       3a6c737458870a35  MATCH

CONCATENATION 1..6             27703   27703            92029b6fe10377e8  MATCH
  full concat sha = 92029b6fe10377e8976401fc5d7e5a4ace32eda39aa32537b24bd5a8a11dce88
  sum of parts    = 27703   (matches the concatenation length: no block dropped or double-counted)
```

**FREEZE INTACT — all seven hashes verified. Measurement proceeds.**

**§3.6 anchor accounting, checked rather than assumed:** 18 lines total, **5** `⟪…⟫` anchor lines
totalling **515 B** including terminators, leaving **13 payload lines / 6 750 B**. The manifest says
6 751 B; the 1 B is the block's absent final newline, which §6's own anchor row already names
(*"`6 751 + 515 = 7 266`, vs the block's 7 265 B + its own final newline"*). **A stated convention, not
an error** — and the five anchors are exactly the five I found, so the not-pasted set is correct.

---

## §2 — `AT-B64-04` — the blocking measurement · **block 2, `4b4e3bad391c0962…`, 2 411 B / body 1 975 B**

**Method.** The arm is a **function of the frozen bytes**: each shipping clause is located by a
distinctive needle *in block 2*, and a mutation **deletes that clause's span from the bytes** and
recomputes. All 11 shipping clauses located; the fold-1 four-clause model is not used.

```
AT-B64-04 over the 9-occurrence enumeration, against block 2's FROZEN bytes:
  #1 b60 linkify autolinked a bare URL / ~~x~~ struck a row     FLAG via D
  #2 b60 asserted the doc's vocabulary (write_out vs WRITE-OUT) FLAG via B + I
  #3 b61 snapshot predicate 0/19, entity-bearing export         FLAG via C + F
  #4 b62 &vert; forges a table fragment, every token still text FLAG via D
  #5 b62 Cc/Cf amendment missed U+2028 (Zl)                     FLAG via B + H
  #6 b62 source-line regex vs implicitly-concatenated f-string  FLAG via D
  #7 b62 '](' not in note failed a CORRECT impl; emitted \](    FLAG via A + C
  #8 b63 chk_rows=-1, heading inside a code-span wrapper        FLAG via C + F
  #9 b63 startswith("| 0x00001") -> 4 rows where 400 emitted    FLAG via G + B
  => 9/9  GREEN
```

Clause key: **A** paste-the-emitted-output · **B** never-charlist/rendering/vocabulary (offset 245) ·
**C** exists-vs-readable · **D** structured-output (589) · **E** quiet-and-symmetric (804) ·
**F** impossible-value (1041) · **G** spelling-1 prefix-guard (1241) · **H** spelling-2
hand-listed-charclass (1379) · **I** spelling-3 requirement-wording · **J** EXTENDS-C-36 (1533) ·
**K** placement.

### §2.1 — Mutations, each applied to the bytes and the arm recomputed

```
delete D (structured output)                          -> 6/9  RED    lost=[1, 4, 6]   (-60 B)
delete B (never a character list)  <- the fold-2 one   -> 9/9  GREEN  lost=NONE        (-90 B)
delete C (exists-vs-readable)                         -> 9/9  GREEN  lost=NONE        (-71 B)
delete G (prefix guard) only                          -> 9/9  GREEN  lost=NONE        (-47 B)
delete B+G+H (ALL charlist/prefix spellings)          -> 7/9  RED    lost=[5, 9]     (-182 B)
delete C+F (readable-form + impossible-value)         -> 7/9  RED    lost=[3, 8]      (-98 B)
delete A+C (paste + exists-vs-readable)               -> 8/9  RED    lost=[7]        (-117 B)

INTEGRITY: corrupt every clause needle -> 0/9  RED, BITES (the arm reads the bytes)
```

### §2.2 — Verdict, and the finding the re-run produced

**`AT-B64-04` = `9/9 GREEN` against block 2. `arch BLOCKER-1` is DISCHARGED** — the sole load-bearing
acceptance for `US-B64-2` now has an executed result bound to a hash, with three reddening mutations
that bite on **disjoint** occurrence sets (`{1,4,6}`, `{5,9}`, `{3,8}`, `{7}`).

**The fold-2 mutation is dead, and this is stronger than my audit predicted.** My §3.4 finding said
*"deleting the offset-245 character-list clause loses at most #7, so the arm falls to at most 8/9."*
Executed: it loses **nothing** — `9/9`. The reason is that `D-01…D-04`'s restoration gave every
occurrence `B` used to carry a second carrier: #2 → `I` (requirement's wording), #5 → `H` (hand-listed
character class), #9 → `G` (prefix guard). #7 was already carried by `A`+`C`.

> **The finding, stated as a general property rather than as a patch.** **Closing `arch BLOCKER-3`
> disarmed the mutation that `arch BLOCKER-1`'s discharge depended on.** Restoring four deleted clauses
> made the rider *more redundant*, which is good for the control and fatal for any single-clause
> reddening test. **Three of the eleven shipping clauses cannot be reddened by deleting them alone.**
> A mutation for this rider must now delete a **carrier set**, not a clause. This is `C-40`'s own
> discharge obligation meeting a control that has become robust — the right outcome, but it means the
> reddening discipline must be re-derived whenever the rider's clause set changes, and §4.3's retained
> record should say so.

---

## §3 — `AT-B64-01` / `AT-B64-02` · **block 1, `5cb146e980deb639…`, 6 219 B**

Limb structure parsed from block 1's bytes, then applied to the corpus:

```
limb1=True  keying=DECLARED  pin=True  domain_ruling(A-23)=True  semantic_governs=True
limb2=True  instance(i)=True  instance(ii)=True
```

### §3.1 — Positive arm

```
AT-B64-01  domain=CI-ONLY {LF}      9/9   missed=none
AT-B64-01  domain=FULL {LF,CRLF}    8/9   missed=['V-8']
```

**CONFIRMED**, and re-derived by executing each predicate under the real text-mode→byte-mode writer
change on both hosts. `V-6`/`V-7` are tautologies **by construction** (`document_bytes(text:str)->bytes`
is `text.encode("utf-8")`, so `raw == encode(decode(raw))` holds for every valid UTF-8 `raw` under any
writer). `V-8`'s right disjunct `os.linesep == LF` is a **constant `True`** on `ubuntu-latest` — it is
the single member on which the two domains disagree, which is what `A-23` exists to rule.

### §3.2 — Negative arm, with the domain named

```
AT-B64-02  domain=CI-ONLY {LF}       false positives 1/6  -> ['S-3']   <- the domain A-23 makes NORMATIVE
AT-B64-02  domain=FULL {LF,CRLF}     false positives 0/6  -> none
AT-B64-02  S-3 reclassified out (CI-dead, A-22)      0/5
```

**The coordinator's statement is CONFIRMED: `1/6` CI-normative · `0/6` full · `0/5` reclassified.**
`S-3` is invariant on the merge-gate host — measured, not cited — so under the domain the encoded
control now mandates it is a **true** positive against a member sitting in the *control* group. The
`0/6` that fold 2 printed is correct only about the demoted domain.

**Measured vs cited, kept strictly separate.** I re-executed `S-3` (`test_flow_report_service.py:497`)
and derived `S-6` by entailment (`:265` pins `len(totals)==1`, so `:266` cannot fire independently).
**`S-1`, `S-2`, `S-4`, `S-5` I did NOT re-execute** — they are an encoder-substitution-vs-sentinel pair
(`:187-206`, `:448-480`) and an AST offender census (`:274-298`) whose sentinels I could not faithfully
reconstruct. Both QA §1.1 and `02b` §2 report them as moving on **both** domains; I cite that as theirs.
Since they move, they contribute zero false positives in either domain, and the CI figure is `S-3`
alone.

### §3.3 — Mutations on block 1

```
delete LIMB 2 span                                    -> POSITIVE 7/9 (CI)  RED
re-key LIMB 1 on 'the component under test' (pre-A-3) -> POSITIVE 2/9 (CI)  RED  + false positive on S-6
delete the A-23 domain ruling                         -> POSITIVE 9/9 (CI)  GREEN  <- see note
corrupt both LIMB markers                             -> POSITIVE 0/9 (CI)  RED
```

**Note on the third row, because a GREEN mutant is exactly what this batch exists to catch.** Deleting
`A-23`'s domain ruling leaves the **CI-domain** arm at `9/9` — the ruling does not change which members
are flagged *within* a domain; it selects **which domain is normative**. Its effect is visible only in
the `8/9`-vs-`9/9` gap and in the negative arm's `0/6`-vs-`1/6` gap. **`A-23` is therefore not
observable by the positive arm at a fixed domain**, and any future re-run that reports one domain only
will be blind to whether the ruling survived. The observer for `A-23` is the **pair** of domain figures,
not either one.

---

## §4 — The remaining acceptances

| AT | block | result | mutation |
|---|---|---|---|
| **AT-B64-05** stack-free rider body | **2** `4b4e3bad…` | **0/17 terms — GREEN** over the 1 975 B normative body (5 stack terms + 12 module/function/class/**fixture** identifiers) | inject `Textual` → 1 hit → **RED, BITES**. Non-emptiness guard added and holds (body > 0 B and contains `Rider`), closing `arch MINOR-4`'s asymmetry. `chk.json` = **0** in the body, **1** in the `(Measured: …)` citation — placement by construction |
| **AT-B64-08** de-identification | **4** `b1cdc970…` | **0/12 — GREEN** (7 identifiers + 5 path regexes) over 1 540 B | inject `s19` → **RED, BITES**; non-emptiness guard holds |
| **`LLR-B64-4.1` no-new-`##`** | **4** `b1cdc970…` | **0 `##` headings — GREEN** | structural, verified on the frozen bytes |
| **AT-B64-09** discrimination | **4** `b1cdc970…` | **GREEN.** Block 4 states the **false-FAIL** direction; `VERIFY.md`'s pre-existing text contains **no** false-fail language and defines the defect as a false **pass** | the direction gap is the separation, per §4.6's draw · DECISIVE · DECISIVE re-weighting |
| **AT-B64-10** bidirectional census | destinations + lineage | **32 ids / 3 disjoint shapes** (S1 11 · S2 20 · S3 1); `encoded ∖ registered = {C-29}`, `registered ∖ encoded = {C-1}`; **PRE = RED on two independent carriers**; drop `C-29` → still RED; `C-41` absent both sides | residue check below |

### §4.1 — The residue census (the non-luck-dependent form), applied

```
declared=32 (S1=11 S2=20 S3=1)   residue=0   -> GREEN, the 3-shape model is COMPLETE over these files
MUTATION inject a 4th shape ('### C-99: …') -> declared=32 (enumeration BLIND)
                                               residue=1  [('dev-flow.md', 277, 'C-99')]  -> RED, BITES
```

**32 / 3 shapes re-confirmed for the fourth time**, now by a check whose failure mode is a **named
leftover** rather than a smaller integer. **Bound, stated rather than claimed away:** a control declared
inside a **table row** is missed by the residue check *and* by the shape enumeration. The correct claim
is *"every `C-NN` occurrence in lead position is either a modelled declaration or a stated relation"* —
not completeness.

### §4.2 — `PP-1 … PP-4`, re-run against the frozen blocks (`A-40` marked the fold's rows STALE)

```
pred   PRE     CORRECT  MIS-PLACED  separates?  block
PP-1   False   True     False       YES         5cb146e9   LLR-B64-1.1
PP-2   False   True     False       YES         4b4e3bad   LLR-B64-2.1
PP-3   False   True     False       YES         db1fa905   LLR-B64-3.1
PP-4   False   True     False       YES         b1cdc970   LLR-B64-4.1
```

**All four RED/GREEN/RED against the frozen bytes.** `qa B-2` stays closed.

---

## §5 — `PP-5`, executed · **block 6, `3a6c737458870a35…`, segment 1**

Authored last fold with three declared expectations and **none run**, correctly, because its GREEN arm
was a function of bytes still being written. Those bytes are frozen; here is the run.

```
PP-5   subject = .dev-flow/BACKLOG.md '## Controls encoded' footer   (baseline 118b1ca1…)

arm           range     stack     VERDICT  expected  result
PRE-BATCH     False     False     RED      RED       MATCH    stack listed= 7  missing=[32,34,37,38,42]
CORRECT       True      True      GREEN    GREEN     MATCH    stack listed=12  missing=none
MIS-APPLIED   True      False     RED      RED       MATCH    stack listed= 7  missing=[32,34,37,38,42]

SEPARABILITY: MIS-APPLIED has range=True, stack=False -> a range-only fix does NOT green PP-5.
              CONFIRMED - LLR-B64-5.4's two clauses resolve independently.
```

**`PP-5` DISCHARGED. `LLR-B64-5.4` — the batch's residual orphan — now has a working observer**, and
the observer distinguishes a complete fix from a half fix, which was the specified requirement.

> **My own defect, reported.** My first `PP-5` run returned **RED on the CORRECT arm**. The cause was
> **my predicate, not the text**: §3.6's replacement footer legitimately *quotes* `C-1..C-36` in order
> to mark it superseded, and my range clause tested `"C-1..C-36" not in footer` — a substring search
> that cannot tell a **declaration** from a **mention of a superseded declaration**. That is `C-42`
> mechanic 1/2 committed while measuring the batch that encodes it, and it is the **third** time in two
> passes I have hit a mention-vs-value boundary. Corrected by scoping the range clause to the
> **declaration span** (everything before the first erratum marker). The first result is withdrawn.

---

## §6 — The arithmetic ruling: **the file will show `+8 632 B`**

The fold declined to choose between `8 630` and `8 631` and delegated it here. I settled it by
**simulating both edits on a scratch copy** and measuring, rather than by arguing.

```
dev-flow.md PRE : 59259 B   line endings: LF only (0 CR bytes)
SIMULATED POST  : 67891 B
  measured Δbytes = 8632        measured Δlines = +1  (275 -> 276)

DECOMPOSITION OF THE MEASURED DELTA
   C-40 block (block 1, 5cb146e9) ..............  6219 B
   + its line terminator (one LF) ..............     1 B
   C-35 rider (block 2, 4b4e3bad), in place ....  2411 B
   + one separating space before '(Origin:' ....     1 B
   -------------------------------------------   8632 B   == MEASURED
```

**Ruling, with all three figures placed:**

| figure | what it is | admissible as |
|---|---|---|
| **8 630** | the **paste-payload sum**, `6 219 + 2 411` | correct as a *block-content* figure (§3.0); **wrong** as a file delta |
| **8 631** | payload + the new bullet's line terminator | the fold's correction — **right about the third term, still one short** |
| **8 632** | **the measured file delta** | ✅ **the figure §6's expected-delta table should carry** |

**The fourth term the fold did not find.** `dev-flow.md:145` reads `…is a Phase-2 blocker. (Origin:
batch-50 …` — the character immediately before `(Origin:` is **already a space**. The rider is inserted
*immediately before* `(Origin:`, so it lands **after** that space and abuts the parenthesis: without a
separator the file reads `…never here.(Origin:`. One space is required **after** the rider.

**Consequences, stated so the Inc-3 check does not mis-fire:**

- §6's `dev-flow.md` row should read **`+8 632`**, with the decomposition `6 219 + 1 + 2 411 + 1`.
- `+8 630` at §9.1/§9.2 is a **payload** figure and should be labelled as such, not corrected to a delta.
- `8 632 / 59 259 = **+14.57 %**` — the `+14.6 %` headline and the `D-10` 2.56× ruling are **unchanged**.
- Predicted POST size: **67 891 B**, 276 lines. A delta of `8 631` means the rider abutted the
  parenthesis; a delta of `8 632 − 2 411 = 6 221` means the rider did not land at all.
- **Recommend a stated ±1 tolerance** on this row. Whether the separator is placed before or after the
  rider is a formatting choice, and a bounded-delta check that fails on one space is a check people
  learn to wave through — which is `§7.7`'s own complaint about the R-c gate.

**The other five rows check out against the frozen blocks:** `engineering-rules.md` `+4 308` / `+13`;
`VERIFY.md` `+1 542` / `+21`; lineage `+5 963` / `+7` (the fold's correction of the old `+~2 000`
estimate, low by ~3×, is confirmed — block 5 is **5 962 B**); `BACKLOG.md` gross `+6 751` with segment 1
exact at `+905` net and the other three segments correctly left to Inc-4 rather than predicted.

> **My audit's FINDING C is CLOSED.** The 889 B non-summing decomposition is gone, all six files are
> now priced from the frozen blocks, and the two files that had no §3 text (`§3.5`, `§3.6`) now have it.

---

## §7 — Does anything still block Phase 3?

**No.** Every arm is GREEN against a named block hash and every predicate reddens under an executed
mutation.

| item | status |
|---|---|
| Freeze integrity (7 hashes) | ✅ verified independently |
| `AT-B64-04` (`arch BLOCKER-1`) | ✅ **9/9** vs `4b4e3bad…`, 3 biting mutations — **discharged** |
| `AT-B64-01` | ✅ 9/9 CI · 8/9 FULL vs `5cb146e9…` |
| `AT-B64-02` | ✅ 1/6 CI-normative · 0/6 full · 0/5 reclassified — **domain now named** |
| `AT-B64-05` / `-08` / `-09` | ✅ GREEN vs `4b4e3bad…` / `b1cdc970…`, mutations bite, guards hold |
| `AT-B64-10` | ✅ 32/3 shapes, two independent carriers, residue GREEN + biting mutation |
| `PP-1…PP-4` | ✅ RED/GREEN/RED vs the frozen blocks |
| **`PP-5`** | ✅ **RED/GREEN/RED, clauses separable — discharged** |
| §6 arithmetic | ✅ **settled at `+8 632`** |
| Baselines | ✅ all five unmodified at start and end |

### §7.1 — Four corrections to carry into Inc-0 (all spec-only, none blocking)

1. **§6's `dev-flow.md` row → `+8 632`**, decomposition `6 219 + 1 + 2 411 + 1`, with a **±1 tolerance**
   and a note that `8 630` is the payload figure (§6).
2. **§4.3's retained record should state that single-clause mutations no longer redden the rider** —
   three of eleven clauses are individually non-reddening, and a future re-run using the old mutation
   will read GREEN and conclude the arm is fine (§2.2). Name the carrier-set mutations instead.
3. **`A-23` has no single-domain observer** — record that its verification is the **pair** of domain
   figures (`8/9` vs `9/9`, `0/6` vs `1/6`), not either alone (§3.3).
4. **Reconcile `AT-B64-02`'s printed expected value with `A-23`** — state `1/6` on the normative CI
   domain, or `0/5` with `S-3` reclassified out; `0/6` alone is now a figure about a demoted domain.

### §7.2 — Standing Inc-3/Inc-4 conditions, unchanged

Re-verify each block's SHA before pasting (§3.0 rule 3); re-run the arms against the **pasted** bytes,
not the fence; strip `⟪…⟫` anchors before pasting §3.6 and treat a `⟪` in the POST file as an Inc-4
failure; re-run `AT-B64-10` **after** the lineage edit; re-derive the `pytest -q` baseline rather than
copying `2201`.

---

## §8 — Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Every figure names the block hash it was measured against | ✓ | §3.0 rule 2 honoured throughout: §2 → `4b4e3bad`, §3 → `5cb146e9`, §4 → `b1cdc970`/`db1fa905`, §5 → `3a6c7374` |
| Freeze re-verified before any measurement | ✓ | §1 — seven hashes recomputed from my own implementation of the extraction rule |
| Explicit Expected before each transcript | ✓ | `PP-5` and `PP-1…PP-4` state expected vs actual per arm; the arms state domain before figure |
| Edge cases: empty, boundary, invalid, error | ✓ | empty = residue 0 / non-emptiness guards; boundary = `V-8` and `S-3`, the two CI-only members, and the ±1 separator; invalid = injected 4th declaration shape and clause-needle corruption; error = the dead fold-2 mutation |
| Reddening mutation executed for every predicate | ✓ | §2.1 (7 mutations), §3.3 (4), §4 (per-AT), §4.1 (injected shape), §5 (mis-applied arm) |
| Results left blank unless actually run | ✓ | every block is command output from this session; `S-1`/`S-2`/`S-4`/`S-5` are explicitly **cited, not re-executed** (§3.2) |
| Layer B — observed through the SHIPPED surface | ✓ | every arm reads the frozen block bytes; clause deletion changes the verdict (§2.1), marker corruption takes the arm to 0/9, and the §6 delta was measured by simulating the real insert |
| Bidirectional surface-reachability | ✓ | inputs: 6 blocks, 11 rider clauses, 9 corpus members, 6 controls, 2 domains, 2 hosts, 3 declaration shapes, 12 mutations, 3 `PP-5` arms. outputs: positive arm ×2 domains, negative arm ×3 readings, per-mutation lost-sets, census both directions, residue, placement verdicts ×5, file delta — each observed |
| No unfilled template | ✓ | no placeholders; `PP-5`'s previously-⚠ row is now a result |
| No real PII / secrets | ✓ | inputs are batch artifacts, `~/.claude` command/skill text, the lineage memory and repo files |
| Own defects reported, not quietly fixed | ✓ | §5 (the `PP-5` mention-vs-declaration predicate) and §3.2 (the withdrawn 4/6 negative arm from bad `S-1`/`S-2`/`S-4` stubs) |
| Nothing edited but this deliverable | ✓ | §0 — five baselines byte-identical at start and end; the spec unchanged; simulation on a scratch copy |

---

## §9 — Two defects of mine, and what they say about the freeze

1. **`PP-5` CORRECT arm read RED** because my range clause could not distinguish a declaration from a
   quoted-and-superseded mention (§5).
2. **The negative arm read `4/6`** on my first run because I stubbed `S-1`/`S-2`/`S-4` as
   `CR not in raw`, which is invariant on an LF host and is not their predicate. Reading the real ones
   showed the stub was mine. The `4/6` is withdrawn (§3.2).

**Both were caught the same way: a value that was implausible against a known-good expectation.** That
is the luck the freeze is designed to remove, and it did its job here — because **every figure is bound
to a block hash, a wrong number is now traceable to either the bytes or the predicate, and in both
cases it was the predicate.** Under fold 2's regime the same two errors would have been
indistinguishable from a defect in the text. That is what `§3.0` bought.

---

*Measured by `qa-reviewer` acting as measurement pass · Phase 2 → 3 · batch-64 · 2026-07-27.
Independent of the spec, the blocks and all prior lanes. One file written (`04-measurement-frozen.md`);
all five baselines re-verified unmodified by SHA256 at start and at end; the §6 delta simulated on a
scratch copy, never on the destination.*
