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
