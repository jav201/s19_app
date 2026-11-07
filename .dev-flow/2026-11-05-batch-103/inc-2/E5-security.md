# Inc 2a — E5 security review (2026-11-07, security-reviewer, Opus 5.5)

**Verdict: FAIL — 2 MAJOR open (E5S-01, E5S-02).** Also 3 MINOR, 1 LOW and 1 INFO. The rest of what the brief asked holds on the real code. 37 of the 39 scaling paths are flat, and 15 of 15 negative controls are RED. Both equality censuses give 0 differences, and the .58.2 corpus raises 0 exceptions.

The two MAJORs both have one-line fixes:
- **E5S-01:** describe raises on a number above Python's int-to-str limit.
- **E5S-02:** decode walks a run of equal x one entry at a time.

## Scope and runner

**Scope.** The real code at HEAD `069171cd`, `git diff a2043cfd HEAD -- s19_app tools tests`. `a2l_definition.py` has md5 `820a4c3a` (code commit `6071a385`), and `a2l.py` is unchanged.

**Runner.** Everything ran on cachyos-rtx, in `/tmp/b103-e5-2a-sec`, which is now deleted:
- the tree was copied from `~/work/b103-int2a` (`e9bad3ca`);
- Python 3.11.18, run with `-I -B`;
- HOME, XDG and LOCALAPPDATA were set to `…/zq_iso_user`, and stdin was `/dev/null`.

**Negative controls.** These are the earlier versions of the module, taken read-only with `git show` as `a2l_definition_82f5` (md5 `f7fa38a5`) and `a2l_definition_f2f9` (md5 `eb750c6f`).

**Load.** The load was 1.0–4.7 on 16 cores, from another session's jobs. Every time below uses the steady measure, so the load does not decide any verdict.

**Corpus.** The corpus is read-only: 35 fixtures (`~/a2l-corpus/fixtures`) and 168 public files. Only derived counts left the runner. Home paths appear as `~` in every transcript.

**Evidence.** Every result is in `inc-2/evidence-e5/sec-e5-*`.

## Results per check

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Per-object work on shared content | **37/39 GREEN** (see the measure below). The 39 paths cover every Inc 2a path of rounds 5–7 in its scalar form (CM-1/2/3/5/7/9/10/11, VT-3/4/5/6/7/9/10, VR-1/2, RL-10/11, CT-3/4/5/6/7) plus E5's own, at least two per shared kind an Inc 2a object can name: RECORD_LAYOUT (RL-18, -19), COMPU_METHOD (CM-2M MEASUREMENTs, CM-12/13/14), COMPU_VTAB (VT-3M, VT-11), COMPU_VTAB_RANGE (VR-3/4/5) and COMPU_TAB (CT-8/9/10/11). Describe on every path is ×0.95–1.04 at both 2S and 8S, with T400(S) 0.011–0.114 s. Every message is ≤ 310 characters. The shapes of E3S3-33 (CT-5, CT-6: one COMPU_TAB named by 400 methods) and VT-10 / VR-3 are flat, because Inc 2a keys the table form by the COMPU_TAB's identity. **RED: CT-8 and CT-9, at decode** (E5S-02). | `sec-e5-scale-steady-transcript.txt` |
| 1n | Negative controls | **15/15 RED** on 82f5 / f2f9 (RL-10, RL-11, CM-2, VT-3 and VR-1 on 82f5; CM-5, CM-7, CM-9, VT-9, VT-3, VT-5, VT-6, VR-2, CT-3 and CT-4 on f2f9). | `sec-e5-scale-neg-transcript.txt` |
| 2 | Decode per element | Time is flat on 37 paths, ×0.97–1.06. Retained size: on VT-5, VT-6, VR-2 and VR-5 every one of the 400 decodes shares **one** text object of 2 MiB. Each definition holds 16–326 characters of its own at every size. | steady transcript |
| 3 | v2 table lookup and range index | **0 differences in a full census.** v2 against the frozen `_table_lookup`: 1,683 tables, 142,164 pairs. Route (`decode_definition` against the frozen `_apply_compu_method`): 131 definitions, 786 decodes. Enum index against 82f5's `_enum_entry_text` / `_enum_text`: 5,921 COMPU_VTAB and 219 COMPU_VTAB_RANGE sections (30 of them overlapping), 183,364 pairs; the reader's entries and defaults are equal in every section. Hostile tables: 3,000 range tables, 2,000 COMPU_VTABs and 3,000 COMPU_TABs (2,615 of them with duplicate x), 790,000 pairs, 0 differences and 0 exceptions. The negatives differ as required: a plain bisect on 766 points in 30 tables; nearest-only on 6,433 corpus pairs and 48,860 hostile pairs. The corpus has no duplicate COMPU_VTAB raw values, so the last-wins negative has nothing to tell apart there (case .29/1 covers it). | `sec-e5-census-transcript.txt` (run 1 hit two harness bugs: `-run1-`) |
| 4 | Fail-closed decode | The .58.2 shapes and V171: 0 exceptions at describe and at decode. **E5's own shapes: 4 describe exceptions** (E5S-01) and a RecursionError at nesting depth 900–985 (E5S-04). The seeded mutation run (seed 20261107) was **stopped at the handback before it finished: `not-run`.** | `sec-e5-hostile-shapes-transcript.txt`, `-nest-` |
| 5 | Echo cap 256 and message ≤ 1,024 | Every echoed file word is ≤ 257 characters (longest word in any message: 257), and no message holds a character outside printable ASCII, U+FFFD and U+2026. **A number written as a number is not capped:** 5 messages of 1,273–1,544 characters (E5S-03). | shapes transcript |
| 6 | Control characters and markup | Display texts hold 0 C0/C1 control characters (.137), and messages hold 0 characters outside .151's set. Bidi-override and line-separator characters stay in display texts (E5S-06). Markup brackets stay in display texts and messages (E5S-07). | shapes transcript |
| 7 | Immutability and decode independence | **The corpus run is `not-run`:** my harness's `pickle` digest of `a2l_data` hit a RecursionError on a deeply nested payload, and the pool stopped. This is a harness defect, not a product finding. What the code shows: every stored form is a frozen dataclass of tuples, or a `MappingProxyType` over a dict nobody else holds (`a2l_definition.py:78-105`, `:853-867`, `:883-898`); `_TabForm` copies x and y into tuples (`:772-773`), so E3S3-36's mutable alias does not exist in 2a; decode writes nothing. Owed: re-run `sec-e5-hostile.py corpus`, with the digest taken over `repr` in place of `pickle`. | `sec-e5-hostile-corpus-transcript.txt` |

**The measure, for check 1.** Each run is a fresh `describe_definitions` walk: the module's `_describe_one` is wrapped, and the 399 names after the first are timed. GC is off, S, 2S and 8S are interleaved, and each figure is the least of 15 runs of process time. The bounds are ×2S ≤ 1.5, ×8S ≤ 2.0, T400 ≤ 0.5 s and messages ≤ 1,024 characters.

## Findings

| Id | Severity | Tag | Where | Row / case | Defect (evidence) | Fix |
|---|---|---|---|---|---|---|
| E5S-01 | **MAJOR** | design-gap | `a2l_definition.py:562-566` (`{byte_length}` in the .7.2 message), `:710` (`MATRIX_DIM {matrix_dim}`); CTX `01-requirements.md:116` (`<length>` "a decimal integer", `<kind>` `MATRIX_DIM <n>`) | R-A2L-DEF.58.2, .7.2, .4 | **Describe raises `ValueError` on a number past Python 3.11's 4,300-digit int-to-str limit.** The frozen reader parses LENGTH, DATA_SIZE, NUMBER and MATRIX_DIM with `int(x, 0)` (`a2l.py:2671`, `:1199-1209`, `:2704`), and base 16 has no digit limit. So `LENGTH 0x` followed by 3,700 `F`s yields a length of 16^3700 > 10^4300, and writing it as a decimal raises. Shapes LEN, DATASIZE, NUMBER and MATRIXDIM-hex3700 each raise from `describe_definitions` (`:564` three times, `:710` once). One such object fails the whole call: every name in a describe-all loses its definition, a denial of service on R-A2L-DEF.136's path. The code writes the formats as the CTX defines them, and the CTX sets no bound. | Bound every number placeholder in the CTX and in code, before formatting: for example, `<length>` and the `<n>` of MATRIX_DIM written in decimal when below 10^20 and as `more than 99999999999999999999` above (sign kept), and `<address>` as at most 16 hexadecimal digits then `…`. The orchestrator fixes the exact text. Add the four shapes to the .58.2 corpus (the negative control is HEAD → `ValueError` → RED), and update .7.2, .4, the CTX and the graph's message texts. |
| E5S-02 | **MAJOR** | impl | `a2l_definition.py:1336-1339` (`while lo > 0 and xs[lo - 1] == xs[lo]: lo -= 1`), against the graph's "in O(log n)" (`codewire/graph-inc2.md:566`) | R-A2L-DEF.150 (/8's class) | **The TAB_NOINTP decode walks back over the run of equal x one entry at a time.** A COMPU_TAB of S of `0 7` with stored 250 (CT-8) decodes in 2.4 / 4.9 / 19.7 ms per element (×1.99, ×8.07), and 400 decodes take 0.98 s at S. CT-9 (the run as the lower neighbour) gives ×2.04 / ×8.34. Hostile only: the corpus has 0 tables with a duplicate x. Inc 3a's `_decode_stored` applies the same v2 rule per element of a VAL_BLK up to 1,048,576 elements (`../inc-3/codewire/graph-inc3.md:796`). | `lo = bisect_left(xs, xs[i - 1])` (the first index of the run). Measured with that fix: CT-8 and CT-9 are flat at 3 / 3 / 3 µs (×0.99, ×1.02), CT-4 and CT-5 are unchanged (`sec-e5-scale-fix-transcript.txt`), and the fix differs from the frozen lookup on 0 of 152,294 hostile duplicate-x pairs (`sec-e5-fixeq-transcript.txt`). Add CT-8 as a .150 case (the negative control is HEAD → RED). Inc 3a's implementer must use the same bisect. |
| E5S-03 | MINOR | design-gap | `:214-219` (`_fmt_address`), `:565`, `:710`; .151 ("a number … is written as it is") | .151 threshold, .7.2, .4 | **A number written as a number escapes the 1,024-character message bound.** An ECU_ADDRESS or header address of 1,500 hexadecimal digits gives messages of 1,543–1,544 characters, and MATRIX_DIM of 1,000 hexadecimal digits gives 1,273. This is the object's own word, so nothing is amplified. | E5S-01's bound closes it; add these shapes to .151/2. |
| E5S-04 | MINOR | impl | `:350-362` (`_walk`, recursive) | .58.2 | **Describe raises `RecursionError` on deep nesting that the frozen parser still reads.** The parser reads a depth of 900–985 at its own stack depth. `describe_definitions` then raises when its caller is 10 to 100 frames deeper (depth 980 fails at +10; depth 900 fails at +100). That fits a parse in a worker thread followed by a describe from a UI handler. At depth ≥ 990 the frozen parser fails itself. | Walk with an explicit stack in file order. Add a depth-980 shape, described at +50 frames, to .58.2. |
| E5S-05 | MINOR | impl | `:1178-1180` (`definition.conversion_type == "TAB_INTP"`), `:700`, `:708`, `:1415`, `:1420` (the raw type word) against the verdict at `:840-852` | .150/9 route; R-A2L-061 | **The interpolation is chosen from the raw word, not from the verdict.** A `tab_intp` method gets a `_TabForm` (its verdict is TAB_INTP), but decode interpolates only when the raw word is `TAB_INTP`. Stored 50 on `0 0` / `100 100` therefore decodes as `0.0`, the TAB_NOINTP answer; `TAB_INTP` decodes it as `50.0`. The frozen view shows 50 by the identity fallback. `tab_verb` likewise gives the number kind while an `_EnumForm` is built. The route census found 0 such words in the corpus. | Carry the verdict on the definition (or upper-case the word everywhere the kind, decode and display read it), and add a lower-case case. |
| E5S-06 | LOW | design-gap | `:170-183` (`_clean`: C0/C1 only); R-A2L-DEF.137 | .137 | **Display texts keep format and separator characters.** The bidi override U+202E and U+200B / U+FEFF (Cf) and the line separator U+2028 (Zl) pass into `Decoded.text`: 2 Cf texts and 1 Zl text in shape TEXT-bidi-sep. A consumer's table cell can then be reordered on screen or split across lines. | Extend .137's set to Cf, Zl and Zp (or at least U+200E/F, U+202A–U+202E, U+2066–U+2069, U+061C, U+2028, U+2029), or write it down as a consumer obligation for Inc 6, 8 and 9. |
| E5S-07 | INFO | — | `_echo` / `_clean` keep `[` and `]` | E3S-04 (a) consumer note | **Markup passes through to consumers, as ruled.** `[bold red]x[/]` and `[link=file:///x]y[/link]` reach display texts (2), and `[` appears in 5 messages. The I-2 consumer note (render with markup off; PLAN rows for Inc 6, 8 and 9) remains the control. No change in 2a. | Keep the consumer rows. |

**Carried from Inc 3a's rounds, checked on 2a.**
- E3S3-33 does not exist in 2a: the table form is keyed by the COMPU_TAB (CT-5 and CT-6 are flat).
- E3S3-36 does not exist in 2a: `_TabForm` holds tuples.
- E3S3-35, at decode: 2a reads the carried form. The undeclared-reference fallback costs one hash-cached `dict.get` (CM-11 is flat).

**Not run** (`not-run`): the corpus immutability and order-independence run (check 7; a harness RecursionError), and the seeded mutation run (stopped at the handback). Their harness is `sec-e5-hostile.py` (modes `corpus` and `mutate`).

## Evidence checklist
- [✓] Each finding has a severity, a tag, a `file:line`, the row it touches and a fix: the table above.
- [✓] No secret values, and no person's or account's name: home paths are written `~` (grep).
- [✓] The verdict is explicit: **FAIL**. E5S-01 and E5S-02 are open, each with its shape transcripts. The proposed fix for E5S-02 is `executed` on the runner as a model; it counts only when applied in code, with a new case RED on HEAD and GREEN after.
- [✗] Check 7's corpus run and the mutation run are `not-run` (above).
- [n/a] No new tool or integration scope.
- Scripts: `sec-e5-run.sh`, `sec-e5-scale.py` (modes `steady`, `neg`, `fix`), `sec-e5-census.py`, `sec-e5-hostile.py` (modes `shapes`, `nest`, `corpus`, `mutate`), `sec-e5-fixeq.py`. The runner scratch is deleted and no `sec-e5` process is left on it (`ps`).

## Round 2 (2026-11-07, security-reviewer, Opus 5.5): narrow re-review of the fix pass

**Verdict: PASS-WITH-NOTES. 0 MAJOR open.**
- Both round-1 MAJORs are closed. Each fix is applied in code and verified on the runner (`executed`, `approved`): E5S-01 (the number rule) and E5S-02 = CR-1 (one `bisect_left`).
- E5S-03, -04 and -05 are closed too. E5S-06 is deferred to BL-I2-18, as ruled. E5S-07 is unchanged, as ruled.
- The two runs owed from round 1 now ran on the fixed code: the corpus immutability and order check, and the seeded mutation run. Neither found anything.
- Two new notes, neither blocking: **E5S-08** (MINOR, design-gap: Inc 3a's records still call 2a contracts that the fix pass changed) and **E5S-09** (LOW, design-gap: the 2S margin of the timing measure under load).

### Scope and runner

**Scope.**
- The fix pass, `git diff 069171cd 26d3e309 -- s19_app tools tests`: `a2l_definition.py` (+64/−46), `make_release_case.py` (+8/−5) and the three test files, all read in full.
- HEAD `a136eaf0` adds only the mutant briefs. The product is unchanged since `a856fab3` (`git diff --quiet`), and `a2l_definition.py` has md5 `f661674b`.
- Authority: `E5-rulings.md`, whole.

**Runner.**
- Everything ran on cachyos-rtx in `/tmp/b103-e5r2-2a-sec`, copied from `~/work/b103-int2a` (`26d3e309`, md5 checked). That scratch is now deleted, and no process of this review is left (`pgrep`).
- Python 3.11.18 ran with `-I -B`. HOME, XDG_* and LOCALAPPDATA were set to `…/zq_iso_user`, and stdin was `/dev/null`.
- The controls were taken read-only with `git show` into the copy: `069171cd` (round 1's code, md5 `820a4c3a`), `82f5f8e5` (`f7fa38a5`) and `f2f955aa` (`eb750c6f`).
- The corpus was read-only: 35 fixtures and 168 public files. Only derived counts left the runner, and home paths are written `~`.

**Load.**
- At the start the load was 0.2. It was 12–15 for most of the review, from another session's 12 xdist workers and the two DeepSeek mutant runs.
- My pool runs used 4 workers. Every timing is process time, the least of 15 runs, so the load decides no verdict. It does show in E5S-09.

**Evidence.** Everything is in `inc-2/evidence-e5/sec-e5r2-*`: the scripts `sec-e5r2-run.sh`, `-batch.sh`, `-scale.py`, `-census.py` and `-hostile.py`, and one transcript per run.

### Results per check

| # | Check (ruling) | Result | Evidence |
|---|---|---|---|
| 1 | **CR-1 = E5S-02**: one `bisect_left`, values unchanged, flat | **Holds.** `a2l_definition.py:1357` reads `lo = bisect_left(xs, xs[i - 1])`, and no walk is left. **Values:** v2 differs from the frozen `_table_lookup` in 0 pairs, and from `069171cd`'s walk back in 0 pairs, on each set: the full corpus (1,683 tables, 142,164 pairs; route 786 decodes; enum index 183,364 pairs); round 1's hostile tables (436,802 pairs, 2,615 tables with a duplicate x); round 1's fix-equality block (152,294 pairs, 3,786 tables with a duplicate x); and new long runs of 2 … 5,000 equal x at the start, middle and end, with ties (15,456 pairs, both interpolations). The negatives still differ: nearest-only on 6,433 and 48,860 pairs, plain bisect on 766 points. **Time:** CT-8, CT-9 and CT-12 (.150/10's shape) decode in 3 / 3 / 3, 4 / 4 / 4 and 4 / 4 / 4 µs (×0.99–1.01), 400 at S in 0.0014–0.0015 s. Round 1 measured 0.98 s and 0.68 s. On `069171cd` the same paths are **RED**: ×2.08 / ×7.23, ×3.25 / ×13.21 and ×2.08 / ×7.63. | `sec-e5r2-census-transcript.txt`, `-scale-steady-`, `-scale-neg-` |
| 2 | **Number rule** (CR-2, CR-3, E5S-01, E5S-03; .151) | **Holds.** `_number_text` (`:222-246`) is used at every file-number placeholder: `:588-589`, `:600`, `:736`, `:1259-1260`. No other decimal text of a file number is left in a message (grep of every f-string). **Direct test:** 60 calls over 15 magnitudes (0 … 2^400000), both signs, both forms, give 0 exceptions, 60 of 60 equal to the rule and at most 257 characters. **Shapes:** 58 shapes (round 1's 34 plus 24 new) give 0 exceptions at describe and at decode. Their 549 messages are at most 555 characters and 0 exceed 1,024. The longest space-free run is 257, and no message holds a foreign character. The new shapes include .58.2/20–23 as written (refusal, 302–326 characters), 4,000 decimal digits of MATRIX_DIM (`0x…`, 326), huge negative LENGTH, DATA_SIZE and MATRIX_DIM (`-0x…`, 304–326), 2^64 − 1 (decimal) against 2^64 (`0x10000000000000000`), and an object whose length and address are both huge (555). **Corpus:** 435,641 messages, at most 176 characters. **Mutants:** 542,238 messages, at most 373 characters, 0 above 1,024. | `-hostile-numtext-`, `-hostile-shapes-`, `-hostile-corpus-`, `-hostile-mutate-` |
| 3 | **CR-4 = E5S-05**: the type word is compared exactly everywhere | **Holds.** The verdict at `:865-867` has no `.upper()`. Every reader compares exactly: `:564`, `:726`, `:734`, `:871-874`, `:1204`, `:1433`, `:1438`. The module's one `.upper()` (`:779`) reads a RECORD_LAYOUT deposit, not a type word. Eight words in another letter case (`tab_intp`, `tab_nointp`, `tab_verb`, `identical`, `linear`, `rat_func`, `Tab_Intp`, `TAB_intp`) each give `A2L-DEF-CONVERSION` at describe and at decode. `TAB_INTP` still decodes stored 50 as 50.0, as the frozen view does. The corpus changes nowhere (check 7, B). | `-hostile-shapes-` |
| 4 | **E5S-04**: an iterative walk | **Holds.** `:378-389` uses an explicit stack in the recursion's order, and no recursion is left. Depths 900–985, parsed in a fresh thread, are each described and decoded at +0, +10, +25, +50, +100, +500 and +900 frames with 0 exceptions. The frozen parser itself fails at 990. Depth 5,000 was parsed with a raised limit, then described at the **default** limit +900 frames, and equals the flat file. File order: check 7 (B) finds 0 differences from the recursive walk of `069171cd` over 353,669 corpus names. | `-hostile-nest-` |
| 5 | **CR-5**: the kind word is echoed | **Holds.** `:730` returns `_echo(str(char_type))`, and the prefix test is gone (`:571-575` writes `kind_text` as is). A quoted kind word `"MATRIX_DIM Z…"` of 2,011 characters gives a 303-character message, with only the space written as U+FFFD. A 5,000-character kind word gives 303. | `-hostile-shapes-` |
| 6 | **CR-6, -7, -9, -10, -11** | **Applied as ruled** (read). CR-6: `DEFINITIONS_ENUM_TEXTS` gives the planned text, and the seeds test is .59/4. CR-7: the P-2 checks are in .149/5. CR-9: one `name_echo`, `:1185`, and `_read_stored_value` has no second fallback. CR-10: both docstrings are updated. CR-11: the 3-argument branch and `inspect` are removed. That these tests pass is the tester's evidence (`fix-tests-green-*`, `fix-tests-red-base-*`), not mine. | diff |
| 7 | **Owed run 1: corpus immutability and order** (non-recursive digest) | **0 findings over 203 files and 353,669 names.** **(I) Immutability:** the `a2l_data` digest is a blake2b over every container and scalar of the payload (42,971,440 nodes), taken with no recursion and keyed back to repeated objects. It is unchanged after describe, after decode and at the end. The stored forms held 1,728 `_EnumForm`, 67 `_TabForm` and 5,830 read-only method records. 930,889 writes were refused, 0 were accepted, and 0 mutable containers were found in forms or definitions. **(O) Order:** every name was described in one walk in file order, in one walk in reversed order, and in a second fresh walk. The three agree name by name in 0 differences, covering the public fields, the private name echo and the table form's content. 2,115 sampled names described alone differ from the walk in 0 cases. Decode in file order equals decode in reversed order on all 4 images. Decoding changes 0 definitions, and 0 table forms are shared across walks. **(B) Fixed code against `069171cd`:** 353,669 definitions and 1,414,676 decodes, with 0 differences. Every corpus number and type word lies within the new rules. | `-hostile-corpus-` |
| 8 | **Owed run 2: seeded mutation** | **0 exceptions.** Round 1's lists were used (md5 `030c3f2f` in both scripts) with the same seeds and file order, so these are the same **1,461 mutants**. Describe and decode raise 0 exceptions, against **32 describe exceptions** in round 1 (`_describe_one:564` 23, `_object_kind:710` 9). The run gives 395,046 definitions, against round 1's 377,789: a file whose describe-all raised lost every definition then. Of the 542,238 messages, 0 exceed 1,024 characters (round 1: 60), the longest is 373 characters and the longest word 258. The display texts hold 0 control characters. The documented refusals are the only outcomes. | `-hostile-mutate-` |
| 9 | **Scaling: 39 paths of round 1 plus CT-12**, with the E5-3 measure | **40 of 40 GREEN.** Each run is a fresh walk, with `names[1:]` timed through a generator, GC off and the least of 15. Every walk consumed the generator lazily, and the 399-name interval at S is 10.1 ms or more (non-vacuity holds). Describe reads ×0.97–1.46 at 2S and ×0.98–1.43 at 8S. T400(S) is at most 0.147 s, and messages are at most 310 characters. Decode reads ×0.67–1.06 and ×0.93–1.11, with 400 decodes at S in at most 0.0023 s. CT-5's ×1.46 / ×1.43 (load 12.3) re-ran at ×0.95 / ×0.99 and ×1.01 / ×1.00 (see E5S-09). **Negative controls:** 7 of 7 RED under the same measure. They are CT-8, CT-9 and CT-12 on `069171cd`, plus RL-10 (×1.98 / ×7.31) and CM-2 (×2.07) on `82f5f8e5` and CM-5 (×2.21) and VT-9 (×2.04) on `f2f955aa`. | `-scale-steady-`, `-scale-recheck-`, `-scale-neg-` |

**A harness note on round 1.** Round 1's pool runs merged their counts with `Counter.update`, which adds up the `… max` keys. So in `sec-e5-hostile-mutate-transcript.txt`, "message max 33205" and "longest word max 25228" are sums, not maxima. Its counts (32 exceptions, 60 messages > 1,024) are right. Round 2 merges a max key with `max()`.

### Status of the round-1 findings and the code review's findings

| Id | Round-1 severity | Status | Evidence |
|---|---|---|---|
| E5S-01 | MAJOR | **Closed** (applied, verified) | checks 2, 8 |
| E5S-02 = CR-1 | MAJOR | **Closed** (applied, verified) | check 1 |
| E5S-03 | MINOR | **Closed** | check 2 (1,500-digit addresses: 298 characters; MATRIX_DIM of 1,000 hexadecimal digits: 325) |
| E5S-04 | MINOR | **Closed** | check 4 |
| E5S-05 = CR-4 | MINOR / MEDIUM | **Closed** | check 3 |
| E5S-06 | LOW | **Deferred**, BL-I2-18 as ruled. The residue stands: shape TEXT-bidi-sep gives Cf 2 and Zl 1. | `-hostile-shapes-` |
| E5S-07 | INFO | **Unchanged**, as ruled: `[` appears in 21,985 corpus messages and in 2 shape texts | `-hostile-corpus-` |
| CR-2, CR-3 | MAJOR, MINOR | **Closed** (the number rule) | check 2 |
| CR-5 | MINOR | **Closed** | check 5 |
| CR-6, -7, -9, -10, -11 | MINOR / LOW | **Closed**, by reading the diff | check 6 |
| CR-8 | INFO | Recorded only, as ruled | — |
| E5-3 | MEDIUM | **Applied** in `_steady_describe` and `_gp2_run` (read). My pass uses the same form. | check 9 |

### New findings

| Id | Severity | Tag | Where | Row / case | Defect (evidence) | Fix |
|---|---|---|---|---|---|---|
| E5S-08 | MINOR | design-gap | `../inc-3/codewire/graph-inc3.md:371`, `:708`, `:781` (calls of `_read_stored_value`), `:5` (Inc 2 nodes "keep their Inc 2 contract"); `../inc-3/E3-security.md:196` (`str(type).upper()` "as Inc 2a's `_describe_one` does") | R-A2L-DEF.151, .12, .150 in Inc 3a | **Inc 3a's records still describe 2a contracts that the fix pass changed.** (a) `_read_stored_value` now takes `name_echo`, from CR-9 (`a2l_definition.py:1237-1238`). (b) The type verdict is exact and is carried on the method record, so a 3a reader that upper-cases the word again would bring back CR-4's silent 0.0. (c) Every number placeholder 3a writes into a message, such as `A2L-DEF-ELEMENTS <n>` and `A2L-DEF-AXIS-BYTES <k>`, must go through `_number_text` wherever it is not already bounded. Otherwise E5S-01's `ValueError` comes back for arrays. Nothing in 2a's code is wrong. | At Inc 3a's next correction, where E5-3 also goes: give the three calls the new signature; read `type_verdict` from the record, with no case folding; route 3a's number placeholders through `_number_text`; and add one huge-number shape per 3a message to 3a's .58.2 set. |
| E5S-09 | LOW | design-gap | R-A2L-DEF.149 / .150 thresholds (×2S ≤ 1.5); `tests/test_b103_a2l_definition_perf.py` `_scaling`, `_gp2_run` | .149/1 … /10, .150/1 … /10 | **Under load, the E5-3 measure's 2S ratio on flat code comes close to the 1.5 bound.** At load 12–14.5 on 16 cores, the readings were: CT-5 ×1.46 / ×1.43 at least of 15, then ×0.95 and ×1.01 on re-runs; CT-6 ×1.00 / ×0.66; CT-9's describe ×1.53 at least of 3, with the same describe code. The negatives read ×1.98–2.21 at 2S and ×7.2+ at 8S, so 8S separates them clearly and 2S only narrowly. A false RED is a flake, not an escape. This adds to the code review's `not-run` loaded block. | Judge growth at 8S (bound 2.0), and keep 2S as a reported margin. Otherwise run the serial_timing set only at load < 2, as E5-1 proposed. The tests use the least of 31, which helps but does not remove the risk. |

### Evidence checklist (round 2)
- [✓] Each finding has a severity, a tag, a `file:line`, the row it touches and a fix: see the table above.
- [✓] No secret values and no person's or account's name appear: every transcript was grepped for the account name (0 hits), and home paths are written `~`.
- [✓] The verdict is explicit: **PASS-WITH-NOTES**. No HIGH, MAJOR or CRITICAL is open. Both round-1 MAJORs carry applied-and-verified evidence: the code lines plus checks 1, 2 and 8, each with its control RED on `069171cd`.
- [✓] Both owed runs ran (checks 7 and 8). Nothing is `not-run` in round 2's scope.
- [n/a] No new tool, integration or dependency scope: the fix pass adds no import. `bisect_left` was already imported at `:22`.
- On this PC I ran only reads, greps and `ast.parse` syntax checks. Nothing imported `s19_app`, no clipboard was touched and no git command wrote. A `py_compile` check made a `__pycache__` in `evidence-e5/`, which I removed.
