# batch-64 — Phase-2 DISCHARGE AUDIT (independent auditor)

> **VERDICT: `DISCHARGED-WITH-FOLDS`.** Phase 3 may start **after four folds land, three of them before
> the first destination write.** No destination file has been touched — all four baselines verified
> byte-identical this session — so nothing is contaminated and every fold is cheap.
>
> **Source findings: 38 enumerated across the three reviews. 35 properly dispositioned (closed, or
> carried with an explicit stated reason). 3 not.** The claim under audit — *all nine consolidated
> blockers closed* — is **true for eight and false for one**: `arch BLOCKER-1`'s discharge
> (`AT-B64-04`, executed at §4.3) **measured a rider body that is not the one that ships.**
>
> **On the orchestrator's two refutations: both are CORRECT, and the ledger had already disclosed the
> cause itself.** `01d` §M-1 states in its own method section that it snapshotted the fold at **441
> lines / 55 593 B / sha `a0868db7…` at 15:50:02**. The shipping document is **821 lines / 87 656 B /
> sha `ffc44366…`** — **+381 lines and +32 063 B were written after the ledger read it.** `U-2` and
> `U-1` are true of the snapshot and false of the shipping bytes. **But the orchestrator's third
> conclusion is half wrong: `U-3` does not "genuinely stand" — one of its two items is discharged by
> §10.2 of the final document.**
>
> **Every headline figure re-derived independently reproduces** — 6 219 B · 2 427 B · **2.5624×** ·
> 1 540 B · 2 411 B · 8/9 full-domain · 9/9 CI-only · **32 encoded ids across 3 declaration shapes** ·
> two independent RED carriers. **Two numbers do not:** the negative arm is **1/6, not 0/6**, under the
> domain the fold's own `A-23` makes normative; and §6's expected-delta decomposition **misses its own
> total by 889 B**, inside the bounded-delta check that `MAJOR-10` was raised to restore.

**Auditor standing.** I authored none of the spec, corpus, measurements, or reviews. Every number below
is output of a command run in this session against files read at a single point in time (§0.1).
Where I agree with a prior lane, that is independent confirmation, not carriage.

---

## §0 — Integrity of the audit itself

### §0.1 — Snapshot discipline

A prior agent in this batch was misled by a file changing under it. All artifacts were hashed at the
start of this session and re-hashed at the end; **none moved during the audit.** Citations below are
to **sections**, not `:line`, wherever a file could shift.

```
ffc44366f9c482de172995576d88f1967678dc4678a88a58d324344d572a6b19  01-requirements-consolidated.md  (822 lines, 87656 B)
047cd17953bf34ca08459528d333e74dd5d38d13f35543d5466f675a30a2db9a  01d-union-ledger.md              (824 lines, 87709 B)
5f7c137b3516bddde9030b671256723db1dc7f85aa342dc800ebee238fcf7ca1  02-review-architect.md
87815f25e233bce9863a1ce8162f66bc17e89847f00cee086bd404c82ac1e729  02-review-qa.md
0f61257d210c8b595c3a7f99d002260e0c964608bd4b1a7f3c4702f3f919ffa7  02-review-security.md
ea58be878ae97b0a92b5bdaa6b2489a58f78b7b0a40c8c4d6d41a1ab8a5670b8  02b-trimc-measurement.md
```

### §0.2 — Baseline integrity: ALL FOUR DESTINATIONS UNMODIFIED

Content hashes, measured this session, against the brief's stated baselines and §6's PRE table:

| file | lines | bytes | SHA256 measured now | vs baseline |
|---|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | 275 | 59 259 | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` | **MATCH** |
| `~/.claude/skills/tui-design/VERIFY.md` | 182 | 10 142 | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` | **MATCH** |
| `…/memory/project_devflow_control_lineage.md` | 89 | 36 401 | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` | **MATCH** |
| `docs/engineering-rules.md` *(in VCS)* | 125 | 15 127 | `278b808d9438a7291c31f8965e6eb20313989a77c7535c9c7a9fae8fa49947cf` | **MATCH** |

```
$ git status --porcelain
 M .dev-flow/state.json
?? .dev-flow/2026-07-27-batch-64/
```

**Nothing has been encoded.** Independently corroborated by the census (§4): `C-40`, `C-41`, `C-42` all
return `encoded=False, registered=False`. I wrote exactly one file — this one.

---

## §1 — CHARGE 1: the orchestrator's two refutations, checked independently

### §1.1 — The race is real, and the ledger documented it before anyone asked

The orchestrator's diagnosis was that `01d` snapshotted the fold mid-write. **That is not a
reconstruction — it is stated in `01d` §M-1**, with the timestamp and the hash:

> *"`01-requirements-consolidated.md` was 398 lines / 45 377 B at 14:58 when this task began; it was
> 430 lines / 53 281 B when first re-tested; it was **441 lines / 55 593 B at 2026-07-27 15:50:02
> -0600** when snapshotted."* — sha `a0868db7ba0313876b67be3ba54fa0241cbf760cfdd02a2a25c556db92d3e129`

Measured against the shipping document:

```
FINAL consolidated: 822 lines  87656 B  sha=ffc44366f9c482de
LEDGER snapshot   : 441 lines  55593 B  sha=a0868db7ba031387   (01d §M-1)
=> +381 lines, +32 063 B written AFTER the ledger snapshotted
```

The ledger also names the consequence per item: §M-3's `LANDED` / `NOT LANDED` table records `D-01…D-04`
LANDED and `D-05…D-20` + `R-8` **NOT LANDED at snapshot time**. `01d` is not wrong; it is *pinned*, and
it says so. **The orchestrator's read/write race diagnosis is CONFIRMED**, and the concurrency was the
orchestrator's own dispatch, correctly owned.

### §1.2 — `U-2`: REFUTED against the shipping bytes

`U-2` claims `§4.0 / §4.2 / §4.3 / §4.4 / §4.5 / §9.2` "do not exist", therefore `D-05…D-20` never
landed. Heading census over the shipping file:

```
§0 §1 §1.1 §2 §2.1 §2.2 §2.3 §3 §3.1 §3.2 §3.3 §3.4 §4 §4.0 §4.1 §4.1.1 §4.2 §4.3 §4.4 §4.5 §4.6
§5 §6 §7 §8 §9 §9.2 §9.3 §9.1 §10 §10.1 §10.2
```

All six cited sections exist. `§4.0` is headed *"RESTORED — D-12"*; `§9.2` *"RESTORED — D-14"*;
`§10.1` carries `D-05 / D-06 / D-07 / D-09` and, inline, `D-15…D-20`. **`U-2` is TRUE of the 15:50:02
snapshot and FALSE of the shipping document. The refutation stands.**

### §1.3 — `U-1`: REFUTED

`U-1` claims `HLR-B64-6`'s four-parent traceability note was dropped with no restoration chartered, and
records having searched for `IEEE 830`, `many-to-one`, `four parent` — **0 each**. Re-run on the
shipping file:

```
IEEE 830                 2        US-B64-1, -2, -4, -6     1     (§2.1 HLR-B64-6)
many-to-one              1        US-B64-1/-2/-4/-6        1     (§4.1.1 traceability row)
four parents             1
```

§4.1.1 states it explicitly: *"HLR-B64-6's four parents are named in the US column … it is the batch's
only many-to-one edge and IEEE 830 permits it provided each parent is named."* **The refutation stands.**

*(One cosmetic residue: §4.1.1's row still prints `*(cross-cutting)*` beside the four named parents,
which the same paragraph says it no longer does. Naming is satisfied; the sentence is over-stated.)*

### §1.4 — `U-3` and `U-4`: the orchestrator is HALF WRONG on `U-3`

| | claim | ruling |
|---|---|---|
| **`U-3`(a)** | QA §6's naive-AT self-application (*"the string `can it go RED` appears in `dev-flow.md`"*) dropped | **STANDS.** `grep "can it go RED"` → **0**; `grep "naive"` → **0** |
| **`U-3`(b)** | QA §3.1's `subject(D)` definition is the M-1 mutant and was never corrected; `A-3` blames the architect draft alone | **DOES NOT STAND — discharged.** §10.2's first bullet quotes `subject(D)`, cites `01b-qa-catalog.md:218-220`, and states *"A-3 attributed the defect to the architect draft alone; it was in **both** lanes."* Verified: `subject(D)` ×1, `01b-qa-catalog.md:218-220` ×1, `both** lanes` ×1 |
| **`U-4`** | the review's 163 is not reproducible from the review | **STANDS**, and is unclosable by the fold — it is a finding about `02-review-architect.md`'s output format (§1.1 publishes a summary integer; §1.2 enumerates only the 20 drops; the 136 carried are listed nowhere). `01d`'s per-row format is the correct successor |

**Ruling on the orchestrator's refutations: 2 of 2 refutations CORRECT; the accompanying conclusion that
`U-3` and `U-4` "genuinely stand" is right for `U-4` and for `U-3`(a), and wrong for `U-3`(b).**
`U-3`(b) was closed by the same +32 063 B that closed `U-2` — the orchestrator applied the race
correction to `U-2`/`U-1` but not to `U-3`, which was snapshotted under the identical condition.

---

## §2 — CHARGE 2: are the restorations REAL, or headings with amendment rows?

I re-ran **the ledger's own §M-3 needles** against the shipping file, and required each hit to fall in
the document **body** (after §2), not in the §1.1 amendment table — which is exactly the container/
evidence distinction `C-40` instance (ii) turns on.

```
id    needle                    hits  in BODY?  body lines
D-01  Also EXTENDS C-36          1     YES      [223]        D-11  cross-reference obligation  1  YES  [551]
D-02  prefix guard               2     YES      [223]        D-12  Inspection                  3  YES  [307,313,319]
D-03  quiet and symmetric        1     YES      [223]        D-13  unfilled template           1  YES  [643]
D-04  luck, not detection        1     YES      [223]        D-14  collision                   2  YES  [648,655]
D-05  C-19                       1     YES      [776]        D-15  R-TUI-097                   1  YES  [569]
D-06  will drift                 1     YES      [783]        D-16  second reddening mutation   -  YES  [801]
D-07  no purchase                1     YES      [787]        D-17  word boundaries             1  YES  [803]
D-08  one third                  1     YES      [725]        D-18  TC-441                      1  YES  [805]
D-09  already in violation       1     YES      [792]        D-19  or fixture                  2  YES  [191,796]
D-10  expected deltas, all three 1     YES      [541,548,549] D-20 :202                        1  YES  [798]
R-8   placement predicate       10     YES      [207,318,350,469]
```

**All 21 chartered restorations (`D-01…D-20` + `R-8`) land substantively in the body.**

> **Two apparent misses were MY OWN probe defects, and I report them as mine.** My first pass scored
> `D-10` and `D-17` as NOT LANDED on zero hits. Both were needle-phrasing artifacts — the document says
> *"word boundaries"* where my needle said *"word-boundary"*, and states `D-10` as a three-row table
> rather than the phrase `` VERIFY.md` gains ``. That is C-42 mechanic 2 (*the variant spelling of a
> string is not the string*) committed by the auditor, inside the audit of the batch that encodes it.

### §2.1 — The four blocker-grade samples, checked for substance

| restoration | present? | substantive? |
|---|---|---|
| **Validation-method table** (D-12, `arch BLOCKER-5`) | §4.0, **7 rows** | **YES.** `Inspection` ×3, `Analysis` ×2 — **non-zero**, which was the review's exact test. Each row carries a method **and** a justification; `US-B64-4` is `Analysis` with the reason *"labelled honestly rather than dressed as a test"*, which is the distinction the review said keeps `AT-B64-09` from being over-claimed |
| **Evidence checklist** (D-13, `arch BLOCKER-5`) | §9 | **YES.** 8 architect rows **+ 10 QA rows** merged and prefixed `(qa)`; the **declared G/W/T deviation** survives as `⚠ partial — DEVIATION DECLARED`, plus *no unfilled template*, *edge cases*, *Layer B through the shipped surface*, *bidirectional reachability*, *no PII* |
| **Lineage-census re-run AFTER the edit** (D-14, `arch BLOCKER-6`) | §9.2 row 1 | **YES**, and it carries the review's own qualifier: *"A simulation over proposed text is not the post-edit run."* Mirrored as a mandate in §5 Inc-4 |
| **`BACKLOG.md` collision check** (D-14, `arch BLOCKER-6`) | §9.2 row 2 | **YES.** *"re-read before reconciling; do not re-apply"*, citing `PLAN.md:217` and `LLR-B64-5.4`. `grep -c "collision"` → **2** (was 0) |

**No sampled restoration is a hollow heading.** The fold's `01d` §M-3 self-check (`LANDED`/`NOT LANDED`
per row) is the right mechanism and it was honestly applied to the state it could see.

---

## §3 — CHARGE 3: headline figures re-derived against the bytes that will ship

Harness: my own fence extractor, which locates each `### §3.x` block and reads the fenced content
**by byte offset**, then measures. Nothing copied from `01c`, `01d`, `02b`, or the fold.

### §3.1 — Byte figures: every one reproduces

```
§3.1  C-40                     6219 B   sha=5cb146e980de     spec: 6 219 B   MATCH
§3.2  C-35 rider (whole)       2411 B   sha=4b4e3bad391c     spec: 2 411 B   MATCH
§3.2  C-35 rider (body only)   1975 B                        spec: 1 976 B   MATCH (±1: the fold counts the space before "(Measured:")
§3.3  C-42                     4306 B   sha=db1fa905083e
§3.4  VERIFY.md extension      1540 B   sha=b1cdc97013f7     spec: 1 540 B   MATCH
      C-39 bullet on disk      2427 B   (dev-flow.md:147)    spec: 2 427 B   MATCH
      ratio C-40 / C-39      = 2.5624x                       spec: 2.56x     MATCH
      +8630 / 59259          = +14.56%                       spec: +14.6%    MATCH
```

`AT-B64-05` re-run independently over the **grown 1 975 B** normative body: **0 hits across 15 terms**
(`markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`, plus 10 module/function/class/**fixture**
identifiers). `chk.json` returns **0** in the body and **1** in the `(Measured: …)` citation — the
placement is by construction, as §3.2 claims. **`LLR-B64-2.2` is satisfied by the shipping bytes.**

### §3.2 — `AT-B64-01`: the corpus arm reproduces exactly

Executed against the real text-mode→byte-mode writer change on an LF and a CRLF host, using the real
seam (`report_service.py:406`, `def document_bytes(text: str) -> bytes`). Every cited predicate was
first confirmed to exist verbatim at its cited line.

```
id     host   pre-fix(text)  post-fix(byte)  invariant under the change?
V-6    LF     True           True            INVARIANT      test_report_document_bytes.py:217
V-6    CRLF   True           True            INVARIANT
V-7    LF     True           True            INVARIANT      test_flow_report_service.py:496
V-7    CRLF   True           True            INVARIANT
V-8    LF     True           True            INVARIANT      test_report_document_bytes.py:221
V-8    CRLF   False          True            moves
S-3    LF     True           True            INVARIANT   << CI-DEAD negative control  :497
S-3    CRLF   False          True            moves

LIMB-1 SEMANTIC FLAGS
   CI-ONLY {LF}     flags ['V-6','V-7','V-8']      -> POSITIVE ARM 9/9
   FULL {LF,CRLF}   flags ['V-6','V-7']            -> POSITIVE ARM 8/9, missed = ['V-8']
```

**`8/9` full-domain and `9/9` CI-only both reproduce, row for row.** `V-6`/`V-7` are tautologies **by
construction**, not by measurement: `document_bytes` is `text.encode("utf-8")`, so
`raw == encode(decode(raw))` holds for every valid UTF-8 `raw` under *any* writer — 0 RED cells in all
four cells, independent of any harness. `V-8`'s right disjunct `os.linesep == LF` is a **constant
`True`** on `ubuntu-latest`, which is why it is the member the two domains disagree on.

### §3.3 — **FINDING A (blocker-grade): the negative arm is `1/6`, not `0/6`, under the fold's own normative domain**

`A-23` rules — in the encoded text at §3.1 — that *"when the syntactic test and the semantic test
DISAGREE, the semantic one governs, **and its domain includes the platform**."* Under that ruling,
applied to the merge-gate host:

- `S-3` is **INVARIANT on LF** (executed above). It is a listed member of the *negative* control group.
- Limb 1's semantic test therefore **flags `S-3`** → **one false positive → negative arm `1/6`.**

The fold's §4 `AT-B64-02` row still reads **`expected 0/6`** and *"`0/6` stands"*. `grep "0/5"` →
**0 occurrences.** `0/6` is correct only under the **full** domain, which `A-23` has just demoted.
**The fold's flagship domain ruling and its flagship negative-arm figure contradict each other.**

This is `02b-trimc-measurement.md` §0(4), which the fold does not carry — see §3.5.

### §3.4 — **FINDING B (blocker-grade): `AT-B64-04`'s discharge measured a rider body that is not the one that ships**

`arch BLOCKER-1` was *"`AT-B64-04` is the sole load-bearing acceptance for `US-B64-2`, and it has never
been executed."* `A-17` claims discharge: *"**EXECUTED** against the rider's **890 B**."* §4.3 pastes
`8/8` → `9/9`, with two mutations biting at `6/9` on disjoint sets.

**The shipping rider body is 1 975 B, not 890 B** (measured, §3.1). The fold knows this: §9.1 prices the
body at 1 976 B, and §10.4 says `AT-B64-05` was *"re-run over the **grown** 1 976 B body"*. **`AT-B64-05`
was re-run against the grown body; `AT-B64-04` was not.**

This is decidable **mechanically, with no judgment about clause semantics.** I decomposed the shipping
body and located the two clauses the mutation turns on:

```
`startswith`/prefix guard        offset 1241   segment 5   <- restored by D-01..D-04 (the "Three spellings" clause)
never against a character list   offset  245   segment 1
hand-listed character class      offset 1379   segment 6
```

These are **three textually distinct spans, ~1 000 B apart.** Therefore:

- §4.3's mutation *"delete the 'never a character list' clause → **6/9**, loses **#5, #7, #9**"* is
  **impossible against the shipping bytes.** Occurrence **#9** is `startswith("| 0x00001")`; the
  shipping body names `` `startswith`/prefix guard `` **verbatim** in a *different* span (offset 1241).
  Deleting offset 245 cannot remove the rider's ability to flag it. Occurrence **#5** (a hand-listed
  `Cc/Cf` character class) is likewise independently carried at offset 1379.
- Against the shipping bytes that mutation loses **at most #7**, so the arm falls to **8/9, not 6/9**.

**The only consistent reading: §4.3's transcript was produced against the fold-1 890 B body — before
`D-02`'s prefix-guard spelling and `D-03`/`D-04` were restored — and then labelled as the shipping
text.** The transcript's own four-clause model (`C1-paste`, `C2-not-charlist`, `C3-exists-vs-readable`,
`C4-structured`) is the fold-1 clause set; the shipping body has ten segments.

**This is `C-40` limb 1 committed by the discharge of `C-40` limb 1's own blocker**: the declared
subject (*the rider that ships*) is not the subject in the expression (*the superseded 890 B rider*).
`arch BLOCKER-1` is **not genuinely closed.**

Corroborating stale residue: §3.2's prose still reads **"Rider normative body length: ~890 B"** — wrong
by **2.2×** against its own fenced block twelve lines above. `qa m-4` asked for `~890 → 889`; the fold
answered in `A-28` but never fixed the sentence, and the sentence has since become far more wrong.

### §3.5 — `AT-B64-10`: PRE-RED on two independent carriers — CONFIRMED

Re-derived from the rule (§4), not from the fold:

```
encoded, NOT registered : ['C-29']     (docs/engineering-rules.md:64, '## C-29 - two-axis geometry-budget...')
registered, NOT encoded : ['C-1']      (lineage, '- **C-1 dev-flow-sync unfilled-template reject-check:**')
PRE verdict = RED        independent carriers = 2
drop C-29 -> still RED? True
C-40 encoded=False registered=False | C-41 encoded=False registered=False | C-42 encoded=False registered=False
```

**Confirmed.** The carriers run in opposite directions, so no single re-scope re-greens the AT —
`arch MAJOR-1` and `qa m-2` are genuinely closed, and `C-41`'s expectation (`arch MAJOR-2`) is covered.

**One undisclosed asymmetry.** The census uses a **declaration-shaped** predicate on the encoded side
(3 shapes) and a **mention-shaped** predicate on the lineage side. `C-1` does survive a
registration-shaped probe (`- **C-1 …:**`), so the carrier is real — but the batch's own `A-8` records
*"the RC-1 census counted mentions, not encodings"* as the orchestrator's instance of this defect class,
and the reverse limb now uses exactly that predicate shape without saying so. **Minor; state the
asymmetry in §4.4.**

### §3.6 — Staleness has recurred: the normative document predates `02b` by 8 minutes

`arch BLOCKER-4` was *"the normative document is stale against `01c-arms-measurement.md`."* The fold
closed that (`A-28`, `A-29`). **The same pattern has recurred one lane later:**

```
02b-trimc-measurement.md   16:05:14   <- newest executed measurement
01d-union-ledger.md        15:59:30
01-requirements-consolidated.md  15:57:26   <- NORMATIVE, predates 02b
02-review-qa.md            15:41:07
```

`grep` over the consolidated: `02b` → **0**, `TRIM-C` → **0**, `0/5` → **0**. Three things `02b`
executed are therefore not in the normative document:

1. The negative-arm reclassification (**FINDING A**).
2. **`TRIM-C` is disqualified twice over** — it drops security `F1`'s mutation-hygiene bound (`0 of 4`
   needles in its named components) and it is a **one-limb** form measuring **6/9**. §9.1 still offers
   trim **(c)** as *"the cheapest form"* with **no mention that taking it would silently revert the
   mandated `A-25` security clause.** That is an operator-facing hazard, not a bookkeeping one: the
   trim menu invites a ruling that reverses a mitigation the security lane required before ship.
3. `02b`'s independent confirmations of the 32-id census and the two carriers — which *agree* with the
   fold and would strengthen it if cited.

---

## §4 — CHARGE 4: the census, derived a fourth time, and what a non-luck check looks like

### §4.1 — `32 encoded ids across 3 declaration shapes` — CONFIRMED

```
dev-flow.md            21 ids     engineering-rules.md   11 ids     VERIFY.md   0 ids
  S1 '## C-NN --'          11 : C-13 13.1 22 23 28 29 30 32 34 37 38
  S2 bullet bold (C-NN)    20 : C-10 11 12 14 15 15.1 16 17 18 19 20 21 24 25 26 27 31 35 36 39
  S3 bold lead '**C-NN --'  1 : C-33
  overlap between shapes    : none
ENCODED UNION = 32
```

**Fourth independent derivation, and it agrees.** Shapes are disjoint, so `11 + 20 + 1 = 32` is a true
partition, not a coincidence of set union.

> **I became the fourth agent to mis-scope this census, and in a fourth new way.** My first pass omitted
> a **left word boundary** (`(?<![A-Za-z0-9])`), so `QC-2`, `QC-3` and `TC-035.2` were harvested as
> `C-2`, `C-3` and `C-035.2` — inflating the reverse direction from 1 carrier to 4. I caught it only
> because `C-035.2` is an **impossible id**. That is the `C-42` mechanic-3 / `D-04` corollary firing on
> the auditor: *an impossible value is luck, not detection.* Four agents, four distinct failure modes
> (`re.MULTILINE` omission · declaration-shape miss on `C-33` · mention-vs-encoding · missing word
> boundary), **every one caught by implausibility of the total.**

### §4.2 — The non-luck-dependent form, built and mutation-tested

The census fails silently because its output is **a plausible integer**. The fix is to change the
failure mode from *a smaller number* to *a named leftover* — which is `C-40` limb 2 applied to the
census itself: draw the set from the rule (*every encoded control id*), not from a list of shapes the
author happened to think of.

**Method.** Classify **every** `C-NN` occurrence in each destination. An occurrence in a line's
structural *lead* that matches no modelled shape, and is not governed by a relation word
(`extends|refines|generalizes|…`), is **residue**. Assert residue is empty.

```
declared ids = 32 | RESIDUE = 0  -> BASELINE GREEN (the 3-shape model is COMPLETE over these files)

MUTATION                        shape-enumeration        residue check
'### C-99: ...'                 declared=32  (BLIND)     1  RED, BITES   -> dev-flow.md:277 'C-99'
'**C-98) ...**'                 declared=32  (BLIND)     1  RED, BITES   -> dev-flow.md:277 'C-98'
'| C-97 | ... |' (table row)    declared=32  (BLIND)     0  GREEN, MISSES
```

**Two consequences, and the second is the honest one.**

1. The residue check **catches an unmodelled 4th declaration shape by name and line, while the shape
   enumeration is completely blind** — the count stays 32 in every mutant. This is the check
   `AT-B64-10` should carry, since the AT's soundness depends on the census being complete. It also
   supplies the reddening mutation the census currently lacks: today's integrity mutation (marker
   corruption) proves the harness *reads the bytes*; it does **not** prove the shape set is *complete*.
2. **My own residue check is itself incomplete** — a control declared in a table row is missed by both.
   Residue is *strictly stronger*, not *sufficient*. The correct claim is bounded: *"every `C-NN`
   occurrence in lead position is either a modelled declaration or a stated relation."* State the bound
   rather than claim completeness — which is the failure `U-4` names one level up.

---

## §5 — CHARGE 5: is the batch executable at Phase 3?

### §5.1 — Does every `shall` clause have an observer?

§4.1.1 claims *"Zero orphans, and the claim now covers all four edges."* **The `LLR→AT` edge is real but
the claim is again shaped to what holds** — its own qualifier is *"for every LLR carrying a placement
`shall`."* Two classes fall outside it:

| LLR | `shall` | observer | status |
|---|---|---|---|
| `LLR-B64-1.1 / 2.1 / 3.1 / 4.1` | within-file placement | **PP-1…PP-4** | **observed** — `qa B-2` genuinely closed; §4.5's table shows all four RED/GREEN/RED while `AT-B64-08`/`-09` are identical on both inserts |
| **`LLR-B64-5.4`** | correct `## Controls encoded` footer in `.dev-flow/BACKLOG.md` | **NONE** | **UNOBSERVED.** `AT-B64-10` excludes `.dev-flow/**` from both directions by `A-6`, so the census cannot see the file `LLR-B64-5.4` edits |
| `LLR-B64-6.1…6.4` | out-of-VCS evidence rows | `AT-B64-11` | observed only by a thing the spec declares **"BOOKKEEPING, NOT ACCEPTANCE … counts toward no story"** — **disclosed** (`A-10`), acceptable |

**`LLR-B64-5.4` is the residual orphan.** Cheap to close: a 3-line predicate over `BACKLOG.md:143-144`
asserting the footer's id range equals the measured encoded space — RED pre-batch (it currently reads
`C-1..C-36` against a measured `C-10…C-39` ∪ `{C-40, C-42}`), GREEN post-edit.

### §5.2 — Is §3's paste-ready text complete for all destinations? **NO — 2 of 6 edited files have none**

| file edited | §3 paste block |
|---|---|
| `docs/engineering-rules.md` | §3.3 (C-42, 4 306 B) |
| `~/.claude/skills/tui-design/VERIFY.md` | §3.4 (extension, 1 540 B) |
| `~/.claude/commands/dev-flow.md` | §3.1 (C-40) + §3.2 (rider) |
| **lineage memory** (`LLR-B64-5.1/5.2/5.3`) | **NONE** |
| **`.dev-flow/BACKLOG.md`** (`LLR-B64-5.4`) | **NONE** |

This defeats a restoration the fold just made. §6's `D-11` says: *"The exact inserted text is in §3 …
The evidence artifact must cite §3 by name **for each file**. For three of four legs this is **the only
external reviewer they get** — there is no PR, no CI, and no diff."* **The lineage memory is one of
those legs, and it has no §3 text to diff against.** `D-11`'s obligation is undischargeable for the
destination that needs it most.

### §5.3 — **FINDING C (blocker-grade): §6's expected-delta arithmetic does not sum to its own total**

§6 row for `dev-flow.md`, restored this fold to close `arch MAJOR-10` / `D-10`:

> *"**+8 630** — C-40 **6 219 B** as a new line, plus **+1 522 B** lengthening `:145` in place (rider
> 2 411 B less the 889 B fold-1 body it replaces). Measured from §3's bytes, not estimated"*

```
stated decomposition : 6219 + 1522 = 7741
stated TOTAL         : 8630
DISCREPANCY          :  889 B
correct against DISK : 6219 + 2411 = 8630   <- the rider adds its FULL 2 411 B
```

**Nothing is encoded yet.** `dev-flow.md:145` is 1 774 B and contains no rider (verified §0.2, and the
security lane's `S-1`). There is no *"889 B fold-1 body it replaces"* on disk — that subtraction is
against fold 1's **plan**, not against the file. The headline `+8 630` is right; the decomposition that
justifies it is wrong by exactly the phantom 889 B.

**Why this is blocker-grade rather than cosmetic:** §6 names bounded delta as one of *"three properties
that make this a check rather than a log"*, and the implementer at Inc-3 will reconcile a measured delta
against a stated expectation whose two halves disagree. It is `arch MINOR-1`'s defect class (`59 259` vs
`59 260`) at **889×** the magnitude, sitting inside the very table raised to fix `MAJOR-10`.

### §5.4 — Other Phase-3 friction (non-blocking)

- **Title staleness.** Line 1 still reads *"fold iteration **1**"*; §1.1 is *"Fold iteration 2"*.
- **§9 ordering.** §9.1 (reader cost) is placed **after** §9.2 and §9.3. A reader following the numbering
  meets the sections out of order.
- **§9 malformed table.** An empty table header + separator at the top of §9 precedes a prose line and
  then a second header — the first two rows render as an empty table.
- **`AT-B64-05` has no non-emptiness guard** — carried openly at §10.2 with `PP-2` named as the paired
  cover. Correctly disclosed; run them as a pair at Inc-3.
- **The `2201 passed` baseline** is still carried by five lanes and re-derived by none (§10.5). Phase-3
  gate item, correctly named as the oldest un-re-derived number in the batch.

---

## §6 — Source-findings disposition map (all 38, audited against the reviews, not the amendment table)

**ARCHITECT — 6 blockers / 10 majors / 8 minors**

| finding | disposition | evidence |
|---|---|---|
| BLOCKER-1 `AT-B64-04` never run | **NOT CLOSED** | `A-17` §4.3 executed against the **superseded 890 B** body; shipping body is 1 975 B (§3.4) |
| BLOCKER-2 two false "Unchanged" | **CLOSED** | §3.3/§3.4 both relabelled **CHANGED** with executed diffs (`A-16`) |
| BLOCKER-3 four clauses deleted | **CLOSED** | `D-01…D-04` located in the shipping rider at offsets 1533 / 1241 / 804 / 1041 |
| BLOCKER-4 stale vs `01c`; `D-9` unrecorded | **PARTIAL** | `A-27/28/29` fold `01c` in; `PLAN`/`state.json` write still pending (§9.3 item 7 ⚠, §10.2); **and the pattern recurred vs `02b`** (§3.6) |
| BLOCKER-5 method table + checklist, 16 rows | **CLOSED** | §4.0 7 rows (`Inspection` 3, `Analysis` 2); §9 merges 10 `(qa)` rows incl. the declared G/W/T deviation |
| BLOCKER-6 4 of 6 regression rows | **CLOSED** | §9.2, 8 rows incl. post-edit `AT-B64-10`, `BACKLOG` collision, `[travels]` fallback, R-d SHA before/after |
| MAJOR-1 `AT-B64-10` implementation-shaped | **CLOSED** | rule-derived 32-id set; 2 carriers — re-derived §3.5 |
| MAJOR-2 `C-41` zero coverage | **CLOSED** | `C-41` in the set, `encoded=False ∧ registered=False` verified |
| MAJOR-3 C-42 distinctness has no AT | **CARRIED, declared** | §10.1 `D-07` — *"a known asymmetry, not closed"* |
| MAJOR-4 C-36 relation dropped | **CLOSED** | *"Also EXTENDS C-36"* at body offset 1533 |
| MAJOR-5 one-third alternative dropped | **CLOSED** | §9.1 trim (c) restored — *but see §3.6(2): it is now known-disqualified and the fold does not say so* |
| MAJOR-6 alternative F-1 ruling | **CLOSED** | §10.1 `D-09` |
| MAJOR-7 idea pre-exists in 3 places | **PARTIAL** | §10.1 `D-05` restores the *finding*; §3.1's **encoded** EXTENDS clause still names the Certainty clause alone |
| MAJOR-8 `LLR-B64-1.5` rationale | **CLOSED** | §10.1 `D-06`, incl. the drift argument |
| MAJOR-9 "or fixture" narrowed | **CLOSED** | `LLR-B64-2.2` restored + §10.1 `D-19` |
| MAJOR-10 expected deltas 2 of 3 missing | **CLOSED (defective)** | §6 has all three rows — **but the `dev-flow.md` row's arithmetic is wrong by 889 B (FINDING C)** |
| MINOR-1 `59 259` vs `59 260` | **CLOSED** | §9.1 now `59 259`; measured 59 259 ✓ |
| MINOR-2 unqualified invariance sentence | **CLOSED** | *"see the corollary below"* bridge present in §3.1's fence |
| MINOR-3 QA `subject(D)` is the mutant | **CLOSED** | §10.2 bullet 1 |
| MINOR-4 `AT-B64-05` no non-emptiness guard | **CARRIED, declared** | §10.2 bullet 2, `PP-2` named as the pair |
| MINOR-5 four-parent note | **CLOSED** | §4.1.1 + §2.1 (§1.3) |
| MINOR-6 `R-TUI-097` | **CLOSED** | §7.1 |
| MINOR-7 `D-16/17/18` | **CLOSED** | §10.1 final bullet, all three |
| MINOR-8 `D-11`, `D-20` | **CLOSED** | §6 (D-11) + §10.1 (D-20) |

**QA — 2 blockers / 4 majors / 5 minors**

| finding | disposition | evidence |
|---|---|---|
| B-1 corpus under-drawn, `6/6` wrong | **CLOSED** | corpus 9, `8/9`·`9/9` re-derived §3.2; encoded Origin no longer carries a count |
| B-2 Layer A `N/A` refuted | **CLOSED** | §4.1 withdrawn; §4.5's four `PP` predicates separate correct from mis-placed where both ATs are blind |
| M-1 `S-3` CI-dead | **CLOSED as disclosure** | `A-22`; but the arm figure not reclassified — **FINDING A** |
| M-2 limb 1 conflates semantic/syntactic | **CLOSED** | `A-23` ruling present in the encoded text |
| M-3 `AT-B64-09` rests on test 1 | **CLOSED** | §4.6 re-weighted draw · DECISIVE · DECISIVE |
| M-4 `S-6`'s second assert dead | **CLOSED** | `A-22` + §7.1; `:265`/`:266` and the docstring `:250-252` verified on disk |
| m-1 `encoded()` misses `C-33` | **CLOSED** | 3 shapes; `C-33` in S3 — re-derived §4.1 |
| m-2 `C-29` load-bearing unrecorded | **CLOSED** | §4 `AT-B64-10` row's ⚠ |
| m-3 `S-5` not a shipped test | **CLOSED** | `A-22` + §10.1 |
| **m-4 `~890 B` stale** | **NOT CLOSED — regressed** | `A-28` says 889 B, but §3.2's prose still reads *"~890 B"* against a measured **1 975 B** body (§3.4) |
| m-5 §10 carries closed items | **CLOSED** | §10 preamble shuts items 1 and 5 |

**SECURITY — 0 blockers / 1 major / 2 minors**

| finding | disposition | evidence |
|---|---|---|
| **F1** mutation execution unbounded | **CLOSED** | `A-25`; verified present in §3.1's fence: *"Run the mutation where **no other session is reading** … and **RESTORE it before the next gate**"* + contamination rationale |
| F2 host-path disclosure | **N/A — no action required**, correctly | reviewer ruled no change; the four travelling blocks re-verified free of host paths |
| F3 POST-hash deferred | **CLOSED** | `A-26`; §5 Inc-2/Inc-3/Inc-4 each record their own POST row |

### §6.1 — Count

| | |
|---|---|
| source findings enumerated | **38** (arch 24 · qa 11 · sec 3) |
| **genuinely closed** | **31** |
| carried with an explicit stated reason (properly dispositioned) | **4** — arch MAJOR-3, MAJOR-7, MINOR-4; sec F2 |
| **NOT closed** | **3** — arch **BLOCKER-1**, arch **BLOCKER-4** (partial + recurred), qa **m-4** (regressed) |
| **claimed** | *"all nine consolidated blockers closed"* — **true for 8 of 9** |

Plus **3 new findings this audit**: **A** (negative arm `1/6` vs the fold's own `A-23`), **B**
(`AT-B64-04` measured superseded bytes — the mechanism of BLOCKER-1's non-closure), **C** (§6 delta
arithmetic off by 889 B). One new gap: §3 has no paste text for 2 of 6 edited files (§5.2), and
`LLR-B64-5.4` is unobserved (§5.1).

---

## §7 — The folds required before Phase 3

**Pre-write (before Inc-0 — all are spec edits, no destination is touched):**

- **F-1 — Fix §6's `dev-flow.md` expected delta.** Replace *"6 219 B … plus +1 522 B … less the 889 B
  fold-1 body it replaces"* with `6 219 + 2 411 = 8 630`. The total is already correct. *(FINDING C)*
- **F-2 — Correct §3.2's *"~890 B"* to the measured **1 975 B**, and correct `A-17`'s *"890 B"*.**
  *(qa m-4, regressed)*
- **F-3 — Reconcile `AT-B64-02`'s expected value with `A-23`.** Either state the arm as **`1/6` on the
  normative CI domain**, or reclassify `S-3` out of the control group and state **`0/5`**, or name the
  domain each figure ranges over. Carry `02b`'s finding that **`TRIM-C` is disqualified** by dropping
  `A-25`, so §9.1's trim menu cannot invite a ruling that reverts a mandated security clause.
  *(FINDING A + §3.6)*
- **F-4 — Author §3.5, the lineage-memory paste block, and §3.6, the `BACKLOG.md` footer text.** Without
  them `D-11`'s restored obligation is undischargeable for an out-of-VCS destination that gets no PR, no
  CI and no diff. *(§5.2)*

**Inside Phase 3, as an Inc-3 gate condition:**

- **F-5 — Re-run `AT-B64-04` against the 1 975 B shipping body**, with mutations chosen from the
  *shipping* clause set (the prefix-guard span at offset 1241 is now an independent carrier of
  occurrence #9, so the old mutation no longer bites there). §9.2 already carries the obligation for
  `AT-B64-01/02/04/05`; this makes it a **blocking** condition rather than a checklist line, because
  `AT-B64-04` is the sole load-bearing acceptance for `US-B64-2`. *(FINDING B / arch BLOCKER-1)*

**Cheap and recommended, not blocking:**

- Add a 3-line observer for `LLR-B64-5.4` (§5.1); adopt the residue census as `AT-B64-10`'s completeness
  guard with the injected-4th-shape mutation (§4.2); state the census's encoded/registered predicate
  asymmetry (§3.5); record `D-9` in `PLAN.md` + `state.json` (§9.3 item 7, still ⚠); fix the title
  *"fold iteration 1"*, §9's section ordering, and §9's empty leading table.

---

## §8 — My own errors, reported rather than quietly fixed (`C-40` self-application)

**Declared subject of this audit's predicates** = *the bytes of the shipping artifacts*. Present in
every expression: each figure is a command over a hashed file (§0.1). **Reddening mutations, executed:**
the residue census returns `0` at baseline and **`1` under two injected declaration shapes** (§4.2), and
the census total is a function of the destination bytes, so the harness is not inert.

1. **Missing left word boundary** in my first census regex → `QC-2`/`QC-3`/`TC-035.2` harvested as
   control ids, inflating the reverse direction 1 → 4 carriers. Caught by an **impossible id**, not by
   the predicate. I am the fourth agent to mis-scope this census and the fourth distinct failure mode
   (§4.1).
2. **Needle-phrasing false negatives** on `D-10` and `D-17` — I scored two genuine restorations as
   NOT LANDED because the document's wording differed from the ledger's probe string. That is `C-42`
   mechanic 2 committed inside the audit of `C-42` (§2).
3. **My residue census is itself incomplete** — a table-row declaration is missed by it *and* by the
   shape enumeration. Reported as a bound on my own recommendation, not omitted (§4.2).

---

## §9 — Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Audited against SOURCE reviews, not the fold's amendment table | ✓ | §6 maps all 38 findings from `02-review-{architect,qa,security}.md`; the amendment table was used only to locate claims, never to score them |
| Explicit Expected, not vague "works" | ✓ | every figure states the spec's claim and my derivation side by side (§3.1, §3.2, §4.1, §5.3) |
| Edge cases: empty, boundary, invalid, error | ✓ | empty = residue `0` at baseline; boundary = `V-8`/`S-3`, the two CI-only members; invalid = injected 4th declaration shapes; error = the 889 B non-summing decomposition and the 890-vs-1 975 B subject mismatch |
| Regression checklist exists | ✓ | §7, split pre-write vs Inc-3 gate condition |
| Exit criteria stated | ✓ | §7 F-1…F-5, each with the finding it closes |
| No real PII / secrets | ✓ | inputs are repo docs, `~/.claude` command/skill text, and git blobs; no credentials read or printed |
| Results left blank unless actually run | ✓ | every transcript is command output from this session; the reviews' figures are cited as theirs and re-derived independently before use |
| **Layer B — observed through the SHIPPED surface** | ✓ | the shipped surface is the bytes a future agent reads: fences extracted by byte offset from the normative file and hashed (§3.1); the census reads the three destination files; the corpus arm executes the real `document_bytes` seam; baselines verified by content hash, not grep |
| **Bidirectional surface-reachability** | ✓ | inputs: 4 paste blocks, 3 destinations + lineage, 9 corpus members, 2 hosts, 2 writers, 3 declaration shapes, 3 injected mutants, 21 restoration needles. outputs: byte counts, ratio, positive arm (2 domains), invariance per cell, census both directions, residue verdict, delta arithmetic, restoration landing — each observed |
| No unfilled template | ✓ | no `<…>`, no `TC-NNN`, no empty required rows |
| Auditor's own defects reported | ✓ | §8 — three, including the one that would have changed a reported number |

---

## §10 — Verdict

### `DISCHARGED-WITH-FOLDS`

**Phase 3 may start once F-1…F-4 land (spec-only, no destination touched), with F-5 as a blocking Inc-3
gate condition.**

**Why not `DISCHARGED`.** Two source findings are not closed and one regressed. `arch BLOCKER-1`'s
discharge measured a rider body superseded by the same fold that discharged it — the batch's own defect
class, one level up, for the third consecutive time (fold 1 vs `01c`; this fold vs `02b`; `AT-B64-04` vs
its own restored clauses). `qa m-4` was answered in the amendment table and left wrong in the body,
where it has since grown 2.2× worse.

**Why not `NOT-DISCHARGED`.** The batch's design survives the audit intact and the repair is genuine,
not cosmetic. **35 of 38 source findings are properly dispositioned.** Every restoration I probed is
substantive — the validation-method table returns non-zero `Inspection`/`Analysis`, the evidence
checklist carries all ten QA rows including the declared deviation, and both load-bearing regression
rows are present with their reasoning. `qa B-2` is closed by *building* the layer three parties said
could not exist. The union ledger is the correct successor artifact and is honest about its own limits.
No destination byte has moved, so every remaining defect is a cheap spec edit rather than a rollback.
**If the operator prefers the stricter reading, `arch BLOCKER-1`'s non-closure alone would justify
`NOT-DISCHARGED`** — I record that the choice turns on whether F-5 is accepted as an Inc-3 gate
condition or demanded before Phase 3 opens.

**The datum worth keeping.** `C-40` has now caught its own authors **eight** times inside one batch —
the architect's limb-1 wording, the orchestrator's id census, `V-6` itself, QA's run-1 harness, fold 1's
twenty dropped observables, the fold's own `re.MULTILINE` defect, this auditor's missing word boundary,
and — the one that matters most — **the fold's discharge of `AT-B64-04` against bytes that no longer
exist.** A control that catches the discharge of its own blocker is not a restatement of
`dev-flow.md:99`.

---

*Audited by `qa-reviewer` acting as discharge auditor · Phase 2 re-gate · batch-64 · 2026-07-27.
Independent of the spec, the corpus, the measurements, and all three reviews. One file written
(`02c-discharge-audit.md`); all four destination baselines re-verified unmodified by SHA256 at audit
start and audit end.*
