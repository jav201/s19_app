# Increment 005 — `LLR-88.5` — the artifact loader: a scope, not a preference

> **⚠ C-56 SUBSTITUTION IN THIS PACKET, inherited from Inc 4 and applied from the first draft.**
> Acceptance ids are written with the prefix `ID-`. The real prefix appears only inside the arms.
> Spelling it here would re-declare the id into `_atlas_id_scan`'s `batches` realm — de-minting
> from one rule's population is RELOCATION into another's. Measured after writing: the Atlas
> census is unmoved at **1 unparsed item** and the four Atlas hashes are unchanged by this file.

| Field | Value |
|---|---|
| Batch | `2026-08-24-batch-88` |
| Increment | `005` of 7 |
| Requirement(s) | `LLR-88.5` (the artifact loader) + the docstring correction the design review required to travel with the body + `R-88-12` (the stale kill-mutation comment) |
| Acceptance | `ID-B88-02` (shared with `HLR-88.2`) |
| Date | `2026-08-27` |

---

## 1 · What changed

**`_artifacts` stopped PREFERRING the declared batch and started being SCOPED to it.**

The shipped loader prefilled every `.md` basename it could reach anywhere under `.dev-flow/`,
first-wins, and then overrode only the basenames the active batch happened to hold. An override is
not a scope. Every basename the active batch had **not yet authored** kept whichever copy `os.walk`
reached first — silently, in the same map, with the same type, indistinguishable at the call site.

Measured on this tree on 2026-08-27, before the change:

| | |
|---|---|
| keys in the live map | **206** |
| `.md` basenames the active batch directory holds | **10** |
| keys that came from a **foreign** batch | **196 of 206 — 95.1 %** |
| `art["04-validation.md"]` | **byte-identical** to `.dev-flow/2026-05-05-batch-01/04-validation.md` |

So `V5` was judging **May 2026** at every gate this batch has run. Four documents in this batch
have said the window closed; what closed was the window for the one artifact the batch had already
authored. **There are as many windows as there are basenames**, and a preference cannot close them.

The new loader resolves the batch directory once. If it resolves, the map is built **from that
directory alone** and a basename that directory does not contain has **its key omitted entirely** —
not carried over, and not supplied as an empty string. If it does **not** resolve, the whole-tree
walk survives unchanged as the fallback.

**The fallback condition is written over the DIRECTORY, not over `state.json`, and that is a
narrowing of the requirement's own sentence.** `_active_batch_state` distinguishes four reasons for
resolving nothing — `absent`, `unreadable`, `nobatch`, `ghost` — and `_active_batch_dir` flattens
all four. A **ghost** `batch_id` **is declared**, so a fallback conditioned on *"no batch is
declared"* would read as obedience while letting one typo in `state.json` restore all 197 foreign
documents. `LLR-88.5`'s own ⚠ bullet narrows the clause to *"only when no batch DIRECTORY
resolves"*; the code and the docstring both say that, and `A9` exercises all four codes.

**The docstring travelled with the body**, because the design review required it to. The shipped
text said the declared batch's *"copies WIN"* and that the walk *"survives only as the fallback for
a project with no `state.json`"*. Both sentences describe a preference over a whole-tree map, and
both would have been false the instant the body landed. The replacement states the exclusion, the
representation of absence, the directory-scoped fallback condition, the INVARIANT its key set
satisfies (a count of a living corpus rots — see F3 below), the unreadable-as-empty trade, and the
one arbitrary choice this function makes (below). Nine typed anchors hold it — `A10`.

**`R-88-12`, the stale comment.** The arm comment at `devflow-validate.py:3958` named *"delete the
active-batch override"* as its kill mutation. **This increment deletes that override**, so the
comment was stale the moment the body landed and no harness could ever notice: a comment naming a
mutation is a claim about code that nothing reddens when the code moves under it. It now names the
mutation that exists — pointing `src` at `.dev-flow` unconditionally, verified by running it — and
records why the rot was invisible. **This was a human inspection item, not a machine-detectable
one**, and it is the only item in this increment that no arm can defend.

### The one arbitrary choice, stated rather than assumed

Inside a batch directory the walk stays first-wins over `os.walk` top-down, so **a basename at the
batch root beats the same basename in a sub-directory**. `LLR-88.5` does not specify this case and
the live corpus holds **0** instances of it. The choice is therefore written into the docstring and
pinned by `A8`, so that changing it later is a decision and not an accident.

---

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py` | source | `_artifacts` body (9 lines, including the direct-child traversal guard) + full docstring replacement; two new helpers `_art_live_root` / `_art_why`, following the `_v2_live_root` / `_v2_why` pattern; the `rev39` arm comment at `:3958` corrected (`R-88-12`); **32** arms added |
| `C:\Users\jjgh8\.claude\skills\dev-flow\scripts\devflow-validate.py` | build output | `--sync-bundle` mirror; `V15` reports *bundle identical* |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-08-24-batch-88\03-increments\increment-005.md` | record | this packet |
| `C:\Users\jjgh8\Github\s19_app\.dev-flow\_derived\` | derived | Atlas regenerated with `--atlas --write` **after** this packet existed |

| **SOURCE files** | **`1`** / 4 — the bundle is a declared build output, the packet is a record, the Atlas is derived |
|---|---|

**`_active_batch_dir` and `_active_batch_state` are unchanged**, as `LLR-88.5`'s acceptance
criterion requires. **Nothing was committed.** `prototypes/`, `build/` and every untracked file
were left alone.

---

## 3 · Test results

**Selftest:** `SELFTEST PASSED`, exit 0, **376** arm lines — **344** before, **+22** in the first pass and **+10** after the independent review (`A3-foreign-shapes`, `A9-dot`, `A9-dotdot`, `A9-nested`, `A12-live`, `A13-v4-absent`, `A14-v1-cardinality`, `A10-depth-text`, `A10-signflip-count`, `A10-forbidden-vocab`).
`LLR-88.5`'s numeric threshold is **≥ 4**; its ⚠ bullets mandate ten shapes the number does not,
and the brief's kill table names all ten. Every one is present.

**Gate, live:** **`3 block · 287 notice · 14 not applicable`**, exit 1 — **identical to the
baseline in every count**. The three blocks are the flow-repo lifecycle, unchanged: `V7` hash drift
until Inc 7's bump, and `V16` ×2 for this increment's uncommitted edit to both flow repos.
**No fourth block appeared.**

### The whole live delta, diffed line by line

Pre and post output were captured in one process by swapping only the loader, so nothing else could
move. **307 lines in, 307 lines out, one line changed:**

```
-  [-] V5   04-validation.md: no ledger expression this rule can read — the record states no
             `post = base − deleted + added` in any admitted form, so NOTHING was checked here …
+  [-] V5   -: no 04-validation.md
```

`SKIP` on both sides. No severity change, no count change. The map went **206 → 10** keys, and of
the 10 keys that survive, **0** changed value — the override had already been getting those 9 right,
which is exactly why the defect was invisible in counts. `LLR-88.5`'s original acceptance,
`BLOCK 14 → 0`, does not reproduce and is `0 → 0`; the record already supersedes it, and the live
evidence is this sentence, asserted as typed text by `A5-v5-absent`.

**That the counts stayed still is not evidence the change landed** — the arm block is.

### The arm block — 32 arms, and why a point probe would have been worthless

A mapping has **three** deliverables: the **key set**, the key→value **binding**, and the
representation of **absence**. An arm of the form `art["01-requirements.md"] == <active copy>` is
total over one cell of one row, and *every* mutant below that keeps that cell correct walks past
it. A dict is also the only return type where **"not there" can be forged**.

| arm | asserts | the shape it exists to kill |
|---|---|---|
| `A1-scoped-absent` / `A1-scoped-green` | **membership** (`k not in art`), both directions | revert-to-first-wins; and walk-active-then-tree, which is the defect but READS like the fix |
| `A2-absent-text` | key absent **and** `V2`'s sentence is `no 01-requirements.md`, typed | absence supplied as `""` — every severity kept, no count moved, only the sentence changes |
| `A3-key-set` | the key set **equals** the active basenames, as a set, over a fixture carrying the corpus's root-level and sibling-subdirectory shapes | narrowed key set · lowercased keys (63 of 206 live keys carry uppercase) · a relaxed extension filter |
| `A4-key-binding` | **per key**, the value equals **that file's** bytes | every key bound to the first file in its directory — 7 of 9 live keys wrong, and a total key-set sweep stays green |
| `A5-v5-absent` / `A5-v5-present` | the absent/present pair on `04-validation.md`, **through `V5`** | a partial fix that scopes `01-requirements.md` and leaves the basename `V5` actually reads |
| `A6-fallback-order` | two batch dirs, **no** `state.json` → **which** wins, by name | flipped fallback walk order, invisible on the natural one-batch fixture |
| `A7-empty-declared` | a truly empty declared dir → `art == {}` | any "nothing here, try the tree" retry — the window reopened at its first instant |
| `A8-depth-first-wins` | same basename at two depths → the ROOT copy wins | `setdefault` → `[]=`; `topdown=False` |
| `A9-absent/unreadable/nobatch/ghost/ok` | each of the four codes plus `ok` → the **resolved map**, never a severity | the four codes flattened to one branch; `ghost` accepted without an `isdir` check |
| `A10` ×5 | docstring: **positive** on the exclusion · **negative** ×2 on the superseded preference wording · one phrase that **inverts** under a sign flip | every docstring mutant — all semantic no-ops, killable only by typed text |
| `A12-live` | the **live** map equals the active dir's own `.md`, values included — guarded, fails loud off-corpus | the three F1 shapes no synthetic fixture modelled |
| `A13-v4-absent` / `A14-v1-cardinality` | V4's absent sentence · V1's finding count over 3 documents | the two unarmed consumers (F5) |
| `A11-unreadable` | an unreadable file is **present and empty**, never forged absent | `_read(...)` without `or ""` — `None` reaches `V2`/`V5`/`V6`'s `is None` and a document that EXISTS announces itself as absent |
| `CONTROL-defective` | a declared batch holding a **defective** copy still yields ≥ 1 BLOCK, asserted here | `return {}`, which satisfies `A1`–`A3` outright |

**The control is asserted, not inherited.** `return {}` collapses the arm count to **353** and
reddens **33** arms — but 20 of those 33 are the consumers' own RED arms, which never mention this
loader, and before this block existed they were its only killers. A control that lives in someone
else's arm block goes silently missing when that block moves.

**`A11` supplies the failure as DATA** (`_read` stubbed for one basename) because this filesystem
will not hand out an unreadable file on demand, and a conditional arm that skips itself when it
cannot build one is the vacuous check. It is the same forgery as `A2`, one level down.

### Battery 1 — the mandated kill table: **20 mutants, 0 survivors on the first arm set**

Every mutant is a COPY under `jobs/…/tmp/mut/`; the live file was never mutated. Each is scored on
the **triple** `(exit code, arm count ≥ 376, FAIL count)`, never on FAIL alone — `B1-crash-nameerror`
is the reason: a `NameError` inside `_artifacts` gives **exit 1, 0 arm lines, 0 FAIL**, and a
harness reading FAIL alone would record it as green.

| mutant | killed by |
|---|---|
| `revert-override` | `A1-scoped-absent`, `A2`, `A3`, `A5-v5-absent`, `A7`, `A8`, `A9-ok` (7) |
| `active-then-tree` | `A1-scoped-absent`, `A2`, `A3`, `A5-v5-absent`, `A7`, `A9-ok` (6) |
| `absence-as-empty` | `A1-scoped-absent`, `A2`, `A3`, `A5-v5-absent`, `A6`, `A7`, `A8`, `A9-ok` (8) |
| `lowercase-keys` | `A3`, `A4`, `A9`×4 (6) |
| `narrow-keyset` | `A3`, `A4` |
| `bind-first-file` | `A4` **alone** |
| `partial-01-only` | `A3`, `A5-v5-absent`, `A5-v5-present`, `A9-ok` |
| `fallback-order-flip` | `A6` **alone** |
| `empty-retry` | `A7` **alone** |
| `setdefault-to-assign` | `A6`, `A8` |
| `flatten-four-codes` | `A9-ghost`, `A9-nobatch`, `A9-unreadable` |
| `return-empty` | 39 arms, **arm count 363 < 376** |
| `drop-md-filter` | `A3` **alone** |
| `md-containment` | `A3` **alone** |
| `nonrecursive` | 30 arms, **arm count 365 < 376** |
| `crash-nameerror` | **exit 1, 0 arms, 0 FAIL** — scored by the triple |
| `doc-drop-exclusion` | `A10-exclusion` **alone** |
| `doc-restore-prefer` | `A10-no-prefer`, `A10-no-override` |
| `doc-signflip` | `A10-signflip` **alone** |
| `doc-drop-omission` | `A10-omission` **alone** |

**Seven of the twenty are killed by exactly one arm.** That is the whole argument for the sixth
shape: drop `A4` and a loader binding every key to one file ships green; drop `A6` and the fallback
order is unpinned; drop `A10-signflip` and the docstring can say the opposite of the code.

### 🛑 Battery 2 — **12 mutants nobody named, 5 SURVIVORS on the first arm set**

This is the useful half of the report, and it is the third increment in a row where the real defect
came from here rather than from the mandated table.

| mutant | first pass | what it was |
|---|---|---|
| `src-parent-dir` | killed (9 arms) | — |
| `topdown-false` | killed (`A8`) | — |
| `value-stripped` | killed (7 arms) | — |
| `ghost-unchecked` | killed (`A9-ghost`) | — |
| `key-mangled` | killed (38 arms, arm count 363) | — |
| `drop-one-basename` | killed (`A5-v5-present` + `V5 RED`) | — |
| `empty-dir-none` | killed (`A7`) | — |
| **`skip-subdirs-of-active`** | **SURVIVED** | **a real defect, and a fixture accident of my own making** |
| **`read-without-default`** | **SURVIVED** | **a real latent defect: absence forged from an unreadable file** |
| `values-from-active-keys-from-tree` | **SURVIVED** | a genuine no-op — measured mapping-equal |
| `doc-reflow-noop` | SURVIVED, by construction | a declared no-op, built to prove `A10` is not asserting the whole docstring |
| `comment-revert-R8812` | SURVIVED, by construction | reverts `R-88-12`; **no harness can notice, and the packet says so** |

**`skip-subdirs-of-active`** prunes `03-increments/` from the walk of the active directory. It
survived because **my own `A3`/`A4` fixture laid all nine basenames flat at the batch root, while
the live batch keeps 5 at the root and 4 under `03-increments/`.** The test's shape differed from
the corpus's shape, so a mutation that silently drops every increment record the batch has authored
sat inside a green selftest with 365 arms. The fixtures were rebuilt to the corpus's own shape
(`_art_nine`); the mutant now dies on `A3` and `A4`. **This is the fixture-accident failure, and
the mandated arm table could not have caught it — the table specifies assertions, not fixtures.**

**`read-without-default`** drops the `or ""` after `_read`. `_read` returns `None` only on
`OSError`, so it is a no-op on every fixture and on the live tree today — but `V2`, `V5` and `V6`
all test `is None`, so the day a document exists and cannot be read, the map forges its absence and
three rules report `no 01-requirements.md` about a file that is right there. `A11` was written for
it.

**`values-from-active-keys-from-tree`** iterates keys from the whole tree, filtered to the active
map, with values from the active map. Measured on the live tree: **`mapping equal: True`** — every
key of the active map is reachable from the `.dev-flow` walk, so the two mappings are equal and only
their **insertion order** differs. Ordering is not in `LLR-88.5`'s population and no arm pins it;
the caveat is in §4 rather than in an arm.

**Second pass, after `_art_nine` and `A11`: 32 mutants built, 3 no-ops, 29 scored, 29 killed,
0 survivors.**

---

### \U0001f6d1\U0001f6d1 Independent review: **BLOCK**, 24 mutants, none from either of my batteries

The reviewer's closing is the right frame and I am repeating it before my own account: **the
shipped code was correct.** Every finding was about what the arm block and the docstring can
*see*, which on this batch's standard is the deliverable.

Its verdict on my own §6 lesson is the part worth keeping. I wrote *"check the fixture's SHAPE
against the corpus's shape"* and then **closed that class at exactly one more point** — I taught
`_art_tree` about `03-increments/` and stopped. The corpus has two more shapes the helper could
not even express: **`.md` files at `.dev-flow/` ROOT** (9 of them live — `BACKLOG.md`,
`AT-TC-REGISTRY-SPEC.md`, four `HANDOFF-*.md`) and **sibling batches with their own
sub-directories**. That is the seventh shape, and there was an eighth behind it.

| # | Finding | Fix that landed |
|---|---|---|
| **F1** | **HIGH.** Three loader mutants pass every arm with the gate unmoved: scoped walk **+ every sibling batch sub-directory** (10 → **125** live keys, **115** foreign documents re-admitted — `LLR-88.5`'s own defect at 12×); scoped walk **+ `.dev-flow/*.md`** (10 → 19); **fallback pruned below one level** (206 → 95, 111 documents silently dropped) | `_art_tree` gained a `""` sub-key (`.dev-flow/` root) and an `outside` payload; `A3`'s fixture carries both foreign shapes and a new `A3-foreign-shapes` arm names which one leaked; `A9`'s sibling now holds a document at depth 1 **and** depth 2 |
| **F3** | **MEDIUM — the eighth shape.** The docstring said the active dir holds **9** and the map falls **206 → 9**. It is **10**, and it is 10 *because this increment wrote `increment-005.md`*. **Writing the packet changed the population the docstring measures.** `R-88-12` was a claim that rotted when CODE moved under it; this one rotted when the CORPUS moved under it, in the same commit, by the increment's own hand | **`A12-live`**, the unifying fix: the invariant `set(_artifacts(root)) == {the active dir's own .md basenames}`, plus no foreign basename admitted, none of its own dropped, **and every value equal to that file's bytes** — asserted against the **real tree**, guarded by `_art_live_root`/`_art_why` so it **fails loud and named** off-corpus rather than skipping. The docstring now states the **invariant** and carries its counts as a dated measurement |
| **F2** | **MEDIUM.** All five docstring anchors were substring-**presence**, and three mutants defeat them: (1) keep every anchor and **ADD** a sentence restoring rev39's semantics — the negative anchors never match, because nothing was removed; (2) **contain** the sign-flip anchor inside a negation; (3) **flip the depth claim** while `setdefault` is untouched — `A8` pinned the code and nothing pinned the sentence, `R-88-12`'s class recurring **inside the increment that corrected `R-88-12`** | `A10-depth-text` (the depth sentence as typed text), `A10-signflip-count` (a `.count()` — each load-bearing clause stated **exactly once**), `A10-forbidden-vocab` (a sweep of a banned layering/negation vocabulary). Anchors now match against a **whitespace-flattened** docstring, because the depth sentence — the longest and most load-bearing claim — **wraps**, which is how it went unanchored |
| **F4** | **MEDIUM.** `batch_id: "."` restored the **206**-key map while `V18` reported a clean `ok` — strictly worse than the ghost case I armed, because ghost at least announces itself. `".."` escaped `.dev-flow/` entirely at **271** keys, and `"../.."` walked the project's parent. `_active_batch_dir` joins unchecked and `LLR-88.5` freezes it | A direct-child test **in `_artifacts`**: `os.path.dirname(abspath(active)) == abspath(base)` or it is not a batch directory. Three rows — `A9-dot`, `A9-dotdot`, `A9-nested` |
| **F5** | **MEDIUM.** Two consumers unarmed. `art.get("01-requirements.md", "")` in **V4** survived everything: V2 dies on `A2`, V5 on `A5`, V6 on `NO-DOCUMENT`, and **V4 had no absent-state arm at all** — so the state this increment newly creates for every unauthored basename would turn V4's honest `no 01-requirements.md` into a **pass sentence**, in the one consumer that emits BLOCKs. And **V1 had no cardinality arm**: `list(art.items())[:1]` survived, in the rule whose population this increment just cut by ~95%. Inc 4's `[:1]` shape, still open one rule over | `A13-v4-absent` (V4's typed absent sentence, count asserted first) and `A14-v1-cardinality` (3 documents, 3 findings, each named) |
| **F6** | **LOW, one sentence not a change.** `A11` correctly pins *unreadable → `""`* — but that state makes V2 say `no AT ids declared` for a file that exists and could not be read. Absence is not forged; **unreadability is reported as emptiness**, the shape `LLR-88.1` removed from V5 in this same batch. `or ""` is pre-existing; the finding is that `A11` **freezes** it without recording the trade | Recorded in the docstring and in §4 as a known trade, with what changing it would cost (`_read`'s contract and three rules) |
| **F7** | **LOW.** `9` → `10` | Docstring ×2, §1's table, §3's delta, checklist item 9 |

### The third battery: **10 named mutants, and where my two batteries were blind**

| mutant | first pass | now killed by |
|---|---|---|
| `F1a-plus-batch-subdirs` | **SURVIVED** | `A3-key-set`, `A3-foreign-shapes`, `A9-ok`, **`A12-live`** |
| `F1b-plus-root-md` | **SURVIVED** | `A3-key-set`, `A3-foreign-shapes`, **`A12-live`** |
| `F1c-fallback-pruned` | **SURVIVED** — and it survived my *first* repair too, because every fallback arm I had was one level deep | all seven fallback rows: `A9-absent/unreadable/nobatch/ghost/dot/dotdot/nested` |
| `F2a-restore-rev39` | **SURVIVED** | `A10-forbidden-vocab` |
| `F2b-negation-contains` | **SURVIVED** | `A10-forbidden-vocab`, `A10-signflip-count` |
| `F2c-depth-flip` | **SURVIVED** | `A10-depth-text`, `A10-signflip-count` |
| `F4a-drop-guard` | **SURVIVED** | `A9-dotdot`, `A9-nested` |
| `F4b-guard-dotdot-only` | **SURVIVED**, and survived my first repair — `.` and `..` cannot separate a direct-child test from `".." in active` | `A9-nested` **alone** |
| `F5a-v4-default-empty` | **SURVIVED** | `A13-v4-absent` **alone** |
| `F5b-v1-head1` | **SURVIVED** | `A14-v1-cardinality` **alone** |

**Two of the ten survived my first repair of them**, which is the finding I would keep if I could
keep only one: `F1c` because I widened the *active* fixture's depth and left the *fallback*
fixture flat, and `F4b` because I armed the two traversal ids that are easy to think of (`.`,
`..`) and neither can discriminate the guard I wrote from the cheaper one. **A repair aimed at a
named mutant closes that mutant, not its class** — the same sentence, one level up, that the
reviewer wrote about my §6.

**Final battery: 42 mutants, 3 no-ops, 39 scored, 39 killed, 0 survivors.** The three no-ops are
`doc-reflow-noop` (by construction — it stays a no-op under whitespace flattening, deliberately),
`comment-revert-R8812` (unarmable, see §4), and `values-active-keys-tree` (measured mapping-equal).

## 4 · Risks, and the things I could NOT arm

- **`A10-forbidden-vocab` is a CLOSED LIST and cannot be a class.** Seven banned phrases kill
  the three measured docstring mutants; an eighth wording defeats it, and there is no closing
  condition on English. This is `LLR-88.9`'s own argument about the harvester's discard set,
  arriving at the opposite answer because prose has no grammar to derive a class from. Stated,
  not hidden behind the three green rows.
- **`A12-live` computes its expected key set with the same primitive the loader uses**
  (`os.walk` over the active directory), so the key-set half is near-tautological in isolation.
  What it is NOT tautological about is the tree it runs on: the real corpus's shape, which is
  what the three F1 mutants exploited. The foreign-disjointness, the not-dropped and the
  per-key BYTES halves are independent properties and are where its strength is.
- **`A9-dot` kills no mutant and is kept anyway.** For `batch_id: "."` the map is
  byte-identical to the fallback on both sides of the guard; the row pins the PAIR (`V18`
  reports `ok`, the map is the fallback) as a decision. `A9-nested` is the row that discriminates.
- **Unreadability is reported as emptiness, knowingly.** `or ""` refuses the forged absence
  `A11` pins, and pays for it by collapsing *could not read* into *is empty* — the shape
  `LLR-88.1` has just removed from V5, one level down. Distinguishing the two states changes
  `_read`'s contract and three rules, and is not this increment's to make.
- **`R-88-12` is unarmable by construction and that is the finding, not an excuse.** Nothing in the
  selftest can read a comment; `comment-revert-R8812` reverts the fix and leaves 376 green arms.
  It is the same gap Inc 4 raised for `LLR-88.4`'s per-arm-comment obligation, now with a measured
  instance: **a comment named a mutation, the mutation ceased to exist, and the harness was
  serene.** Raised, not solved.
- **Insertion order of the returned map is unpinned.** `V1` iterates `art.items()` and emits one
  finding per placeholder, so the ORDER of `V1`'s findings follows the map's order. `V1` fires
  nothing live today, and `LLR-88.5`'s population is a mapping — two mappings that compare equal
  are the same deliverable — so pinning order would be pinning an incidental. Stated instead.
- **`A6`'s "`a` wins" rests on `os.walk` returning sibling directories in the filesystem's order**,
  which on this NTFS volume is alphabetical. The shipped `MULTIFILE` and `ACTIVE` arms already rest
  on the same assumption. If that ever changes, `A6` reddens for a filesystem reason and not a
  validator reason — which is the correct failure, but the message will not say so.
- **`A8`'s choice is arbitrary and the corpus cannot arbitrate it.** 0 live instances of a basename
  at two depths in one batch dir. The arm pins today's behaviour; it does not argue for it.
- **The 718 discarded documents are untouched.** 924 `.md` files exist under `.dev-flow/` and
  first-wins collapses them to 206 before any rule sees one. This increment takes the map to 9 by
  SCOPE, which is a different operation; the 718 are not repaired here and `LLR-88.5` says so.
- **`V5` now reports `no 04-validation.md` and will keep reporting it until this batch authors a
  validation record.** That is the correct sentence and a worse-looking one: the tool used to print
  a reassuring `ledger` line derived from a stranger's document. **The reassurance was the defect.**
- **The batch's own documents are now judgeable by `V1`–`V9`**, stated as a consequence in the
  requirement and confirmed here: 3 blocks before, 3 blocks after, none of them from this batch's
  documents. If a later edit to `01-requirements.md` introduces a placeholder or a modal, this
  batch's gate will now say so — which it could not before for any basename the batch had not
  authored.
- **`_active_batch_dir` → `_active_batch_state(root)[0]` was declared a no-op and not scored**
  (literally equivalent). **Symlink following was declared a no-op and not scored** (0 symlinks in
  the corpus). Both are the brief's declarations, re-stated rather than silently honoured.
- **No mutant of `_active_batch_state` was scored**, because `LLR-88.5`'s acceptance requires that
  function unchanged. `A9` reaches it only to assert the code it returned alongside the map.

---

## 5 · Pending

- **`LLR-88.5`'s numeric threshold still reads `BLOCK 14 → 0`** in the Statement's own field, with
  the correction living in a ⚠ bullet below it. The bullet supersedes it correctly; the figure in
  the field is still the first thing a reader meets. Not edited here — this increment does not own
  the requirements document.
- **The traversal guard belongs in `_active_batch_dir`, not in `_artifacts`.** `LLR-88.5`'s
  acceptance freezes that function, so the direct-child test lives in the caller and any
  future second caller of `_active_batch_dir` inherits the hole. A one-line amendment to the
  requirement would let it move to where it belongs. **Raised as a requirement defect.**
- **`A11`'s trade (F6) is a candidate `LLR` of its own**: `_read` returning a sentinel that
  distinguishes *absent* from *unreadable*, and three rules learning to say so.
- **The insertion-order question above deserves one sentence somewhere**, either in `LLR-88.5` or in
  `V1`, before someone "tidies" the loader and moves `V1`'s output order for free.
- **A comment-checking obligation has now been raised twice** (Inc 4 for `LLR-88.4`, here for
  `R-88-12`). Two instances is a pattern; the third will be found the same way, by reading.
- `V7` stays red until Inc 7's bump, by design. `V16` ×2 — this increment's uncommitted edit to
  both flow repos. **Nothing was committed.**
- The derived Atlas was regenerated with `--atlas --write` AFTER this packet existed.

---

## 6 · Suggested next task

**Inc 6** — the census oracle (`LLR-88.6`) and the notice that names its population (`LLR-88.7`).
Three carry-overs:

1. **Run the second battery, and expect it to find the real defect.** Three increments in a row
   now: the mandated table verifies the requirement, the invented battery verifies the *code*. Here
   it cost 12 mutants and returned two genuine defects and one measured no-op.
2. **Close the fixture-shape class with a LIVE-CORPUS invariant, not with one more shape.**
   This increment learned the lesson twice and applied it once each time: `03-increments/`
   after my own battery, then root-level `.md` and sibling sub-directories after the review's.
   Enumerating shapes has no closing condition; **`A12-live` does**, because it asserts the
   deliverable against the tree that actually exists. Every rule whose population is the
   corpus is owed one, guarded so it fails loud rather than skipping.
3. **`V22` and `V23` now read THIS batch's documents**, not batch-01's, because of this increment.
   Re-measure `306 of 570` and the `51` conforming citations against that fact before treating
   either as a pre-state; both figures were taken while the loader was still scoped correctly for
   those two rules, so they should be stable — but "should be" is what this batch keeps disproving.

---

## Increment gate checklist

| # | Item | ✓ | Evidence |
|---|---|---|---|
| 1 | ≤ 4 source files | ✓ | **1** authored source + 1 build output (`V15`: *bundle identical*) + 1 record + derived Atlas |
| 2 | Tests in the same increment | ✓ | 22 arms + 10 after review, 344 → **376**, `SELFTEST PASSED`, exit 0 |
| 4 | RED counterfactual | ✓ | **42 mutants built (32 mine + 10 from the independent review), 3 no-ops, 39 scored, 39 killed, 0 survivors.** Each scored on the triple `(exit, arm count ≥ 376, FAIL)`; `crash-nameerror` proves why — exit 1, **0** arms, **0** FAIL. **5 of my own and all 10 of the review's survived a first arm set**, listed by name in §3 with the arms written for each; **2 of the review's survived my FIRST repair of them** (`F1c`, `F4b`) |
| 5 | Reverse census | ✓ | `_artifacts` had **8** call sites before this increment and has **22** after — 1 in `run`, 7 pre-existing selftest arms, 14 new ones (grep, whole file); `_active_batch_dir` has exactly **1**, inside `_artifacts`, and is unchanged. Only **five** rules read the map — `V1` (whole map), `V2`/`V4`/`V6` (`01-requirements.md`), `V5` (`04-validation.md`); `V7`, `V8`, `V9` accept it and never read it |
| 9 | Coverage verified on disk | ✓ | Live map **206 → 10** keys, **0** of the surviving 10 changed value; 196 of 206 foreign (95.1 %); `04-validation.md` byte-identical to batch-01 pre-fix; pre/post output diffed in one process, **307 → 307 lines, 1 changed** |
| 10 | Load-bearing emptiness | ✓ | `A7` asserts `art == {}` for a truly empty declared dir; `A1`/`A2`/`A5` assert **membership** and the consumer's typed absent sentence, never `.get() is None`; `A11` asserts the opposite state — present and empty — so absence and unreadability cannot collapse into one another |
| 11 | Mutation verdicts per arm | ✓ | §3's two tables name, per mutant, which arms reddened, and mark the **seven** killed by exactly one arm. The comment at `:3958` now names a mutation that was **run** (`B1`-style, `src` pointed at `.dev-flow`), not one inferred |
| — | Secrets | ✓ | no key, token, `.env` or credential read, written or printed |
| — | Destructive commands | ✓ | none run; mutants are COPIES under `jobs/…/tmp/mut/`, the live file was never mutated; `prototypes/`, `build/` and all untracked files untouched; **no commit** |

**An item without a citation is not satisfied — it is asserted.**

---
