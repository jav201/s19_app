# Inc 4 — E1 rulings: scope, canon changes, decisions, interface I-3

Base `e07fb00` (branch `batch-103`). Rows: `01-requirements.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Evidence (`evidence-e1/`, every transcript tool output; scripts and runs on cachyos-rtx, Python 3.11.18, a fresh `HOME`/XDG/`LOCALAPPDATA` under `/tmp/b103-e1-4/`, `s19_app.__file__` printed first, no clipboard, case 08 generated into `/tmp/b103-e1-4/out`, the repository clone read only):

| File | What it shows |
|---|---|
| `i4e1-census.py`, `-transcript.txt` (C) | the A2L name shapes: case 08 (462 + 470 names, `KIND_NNNN`), every tracked `.a2l` (35 files, 234,654 names), the inline A2L names of `tests/*.py` |
| `case08-names.txt`, `case08-issues-names.txt` | the case-08 names the test cases use, as the app's reader lists them |
| `i4e1-pilot.py`, `-transcript.txt` (B, v1) | a definitional oracle of the rows (handoff order A) and a first index; the oracle without preparation: **9.15 s** for one query over 50,000 names |
| `i4e1-pilot2.py`, `-transcript.txt` (B, v2) | an index with tier-by-tier stop and a trie for the fuzzy step: 0 mismatches against the oracle (409 queries × 4 limits); worst ranking median 122.2 ms; build 3.26 s (host load ≈ 12) |
| `i4e1-examples.py`, `i4e1-at-examples.py` + transcripts (B, order A) | the curated and black-box lists under order A |
| `i4e1-order-eval.py`, `-transcript.txt` (B) | decision D-3: rank of the intended name under order A and B, 4 query classes × 60 queries over the 13,990 real-shape names |
| `i4e1-pilot3.py`, `-transcript.txt` (B, v3) | the recommended design (order B): every expected result of `02-test-cases.md` (§1–§2), oracle == index 0 mismatches (§3), the timing of R-A2L-MATCH.35/.36 (§4) |
| `i4e1-base-grep.txt` (R) | the base has no similarity ranking; the existing filter sites; the id checks |

## 1. Scope

**In:** US-103-03's matcher, as a pure module (PLAN row Inc 4): tokenising, the six match rules, one deterministic ranking, the edge cases the brief lists, the per-keystroke bound, and the interface I-3 that Inc 7 consumes.

**Out (with reason):**
- The autocomplete dropdown, the paste modal, the av_A list filter and any key — Inc 7, after prototype round 2 (G2). No row of this increment names a widget or a key.
- Changing the existing substring filters (R-A2L-007.1, R-A2L-090, R-CHKED-003, R-TUI-022.4) — not in the plan row; the matcher sits beside them (`01-requirements.md` *Relation to existing rows*). Backlog BL-I4-1.
- The label-list parser I-5 (`parse_parameter_list`) — Inc 7 joins it to the matcher; unchanged here.
- A memory bound for the prepared list — D-12.

## 2. Changes to existing canon rows and notes

None. Every row is new (`R-A2L-MATCH.1` … `.36`); the context note CTX-A2L-MATCH is new; the proposed home is a new subsection **S2.7 · Label matching (CTX-A2L-MATCH)** of module S2 (D-10), so the Modules table does not change. Ids checked unused in `REQUIREMENTS.md`, `docs/requirements/review/`, `C:\Users\jjgh8\Github\s19w\review\`, every `.dev-flow/*/` folder (the only hits are the batch's own allocation lines in `steps.log` and Inc 2's id census quoting it) and the 17 `b101-*` branches (0 files each): `evidence-e1/i4e1-base-grep.txt`. The black-box ids `AT-B103-I4-1`, `-2` are batch-scoped and letter-initial, outside the registry's authority (`AT-TC-REGISTRY.jsonl` `_meta.governed`), and unused.

## 3. The handoff's proposed rules, one by one

| Proposed rule (handoff / PLAN) | Became | Note |
|---|---|---|
| tokenise on `_`, camelCase and letter/digit boundaries | the CTX-A2L-MATCH term *token* (a format, so a definition, not a row: E6), exercised through the `token` and `fuzzy` rows (.8, .10) and their spans (.30, .32) | Two additions the census asked for: a cut before the last letter of an uppercase run (`OKSAhwvcueaniy` → OKS · Ahwvcueaniy; 1,447 names of the fixtures have this shape, C) and every ASCII character that is not a letter or a digit as a separator, so `.`, `[`, `]` (13,608 and 152 names, C) and `__` runs (561) cut tokens and never join them. A character above U+007F is a letter without case (D-2). |
| substring anywhere | .7, ordered by .21 (a boundary occurrence first), spans .28/.29 | The query is compared character by character, never as a pattern (.7/2, .8/6). |
| subsequence | .9, **ranked last** (D-3 B), spans .31 | Kept: it is the only rule that finds `MAP_0020` from `map 20` and `ASCII_0001` from `ascii 1` (a digit query token is matched as a prefix only, D-4). |
| per-token Damerau-Levenshtein | .10, as a prefix distance of the optimal string alignment distance (D-5), allowed edits .11–.13 (D-4), total edits .33 | |
| one deterministic ranking (exact > prefix > substring > token > subsequence > fuzzy, ties by shorter name then code point) | .14–.25: rule in rank order, rule key, shorter, case-exact, code point — a total order over distinct names, so the input order decides nothing (.25/2) | The order of the last two rules is swapped (D-3); case-exactness added between length and code point (D-6); the rule key added for substring (.21) and fuzzy (.22). |
| `rank(query, names, limit)` | I-3 below: a prepared name list plus `rank(query, index, limit)` (D-1) | |

## 4. Decisions — every one **PROPOSED — awaiting orchestrator ruling**

The rows, cases and slice follow the recommendation of each.

| # | Question | Options and consequences | Recommendation and reason |
|---|---|---|---|
| D-1 | The shape of I-3 | **A** `rank(query, names, limit)`, stateless, as PLAN wrote it: every call reads all names; at 50,000 names one query took 9.15 s (B v1) — R-A2L-MATCH.36 cannot be met and .35 goes. **B** `build_label_index(names) -> LabelIndex` once per name list, then `rank(query, index, limit)`: v3 2.00 s to build, ≤ 122.6 ms per query. **C** `rank(query, names, limit)` with a hidden cache keyed on the names: B's speed after the first call, PLAN's signature, but hidden state in a pure module and a first-keystroke stall of the build time unless the caller warms it. | **B.** The only option that meets a per-keystroke bound without hidden state; the build has a natural home in Inc 7 (once per A2L load, I-4's load generation, off the UI thread: 2 s at 50,000 names). Precedent in the tree: `services/report_filter.py` builds its `ReportFilterMatcher` "ONCE per report run" (its module docstring, D-9 of batch-35). PLAN's I-3 line changes to the two calls below; Inc 7 is the only consumer. |
| D-2 | Case folding | **A** fold `A`–`Z` only; every other character compares as itself. **B** per-character Unicode lowercase where it gives one character (`Ü` → `ü`): .4/1–/2 change (`DRÜCK_MAX` becomes `prefix` for `drück`). **C** no folding (ASAP2 names are case-sensitive): `value_0001` finds no `exact` `VALUE_0001`; every lowercase-typed query falls to nothing — the operator types names lowercase. | **A.** Matching ignores case for typing; case comes back in the order (.24: the case-exact name first; case twins stay two entries, .3/3). A2L identifiers are ASCII (C: 0 non-ASCII among 234,654 fixture names; the ASAM MCD-2 MC identifier grammar is letters, digits, `_`, `.`, `[`, `]` — from memory, **not re-checked against the standard here**). A keeps every folded text the length of its text, so spans index the name directly; it does not depend on Python's Unicode tables, which change between versions. The existing filters use Python's Unicode lowercase; on ASCII names the two agree. |
| D-3 | The order of the rules | **A** the handoff's: … token > subsequence > fuzzy. **B** … token > fuzzy > subsequence. **C** B without a subsequence rule: `map 20` and `ascii 1` give `[]` (.9/2–/3), the only route from a number typed without its zeros. Measured (`i4e1-order-eval-transcript.txt`, 60 generated queries per class over the 13,990 real-shape names; top-1 / top-5 / MRR of the intended name): **one word with a typo** A 9/60 · 18/60 · 0.220, B 46/60 · 56/60 · 0.854; **two words, one with a typo** A 52/60 · 60/60 · 0.923, B 60/60 · 60/60 · 1.000; **partial words** A = B 60/60; **initials** A 1/60 · 4/60 · 0.044, B 1/60 · 1/60 · 0.025. On the operator's own example (AT-B103-I4-2, `jotfa vod`) A puts the intended name third, behind two scattered subsequence matches (`i4e1-at-examples-transcript.txt`); B puts it first. | **B.** The operator asked for "word similarity" independent of where the word is (av note in `veredicto-b103.json`); the fuzzy rule is that judgement, and under A a scattered subsequence (every typed letter somewhere, in order) outranks it — on long real names that is noise, which the measurement shows. Initials-style abbreviations do not work under either order (top-5 ≤ 4/60): a subsequence of 3–4 letters matches hundreds of long names. That is a G2 observation, not something this increment can tune without real queries (BL-I4-2). Under A, the expected results of .8/3, .16/3, .20/3, .32/3 and AT-B103-I4-2 change; the order-A lists are in `i4e1-pilot-transcript.txt` §1, `i4e1-examples-transcript.txt` and `i4e1-at-examples-transcript.txt`. |
| D-4 | Allowed edits per query-token length (the brief's "exact numbers") | **A** a token of digits, or of 1–2 letters: 0; 3–5 letters: 1; 6 or more: 2. **B** as A but digit tokens by length too (`0300` gets 1 edit and lists `VALUE_0200`, `VALUE_0301`…). **C** one edit per 4 letters (0, 1, 2, 3 … at 4, 8, 12). | **A.** A digit token is an index: one edit names another object (`VALUE_0300` must not list `VALUE_0200`, .11/1), so digits match as a prefix only. The 0/1/2 bands are the common full-text practice for short words (Elasticsearch's `AUTO` fuzziness uses the same cut points — from memory, not re-checked here); they keep 1–2-letter tokens exact, where one edit would match almost every token. C allows 3 edits on 12-letter words, where the pilot already lists 2-edit matches for 6-letter queries. |
| D-5 | The edit distance | **A** the optimal string alignment distance (insert, delete, substitute, transpose two adjacent characters; no character edited twice), as a **prefix** distance (to any prefix of the name token). **B** unrestricted Damerau-Levenshtein: differs from A only when an edited pair is edited again (`CA` → `ABC`: 3 in A, 2 in B), never decisive at ≤ 2 edits on words; costs a per-alphabet table. **C** plain Levenshtein: `cuvre` → CURVE and `mpa` → MAP are 2, not 1 (.10/1, /4 fail). **D** a whole-token distance: a word being typed (`maesu`) is 6 edits from `measurement`, so nothing is found until the word is complete. | **A.** Transpositions are the commonest typing slip, so C loses; the prefix form is what autocomplete needs while the operator is still typing the word (`maesu` → `MEASUREMENT_*`, .32/1), which D cannot give. The handoff said "Damerau-Levenshtein": A is the restricted form most libraries call by that name; the rows define it exactly (*edit distance* in CTX-A2L-MATCH). |
| D-6 | Ties after the rule and its key | **A** shorter name, then case-exact, then code-point order. **B** case-exact before length: .23/2 flips (`rpm_x` before `RPMX` for `rpm`). **C** code point only (the handoff's second key without length): `ASCII_0001` before `MAP_0001` for `0001`. | **A.** For completion the shortest name is the nearest one (fewest characters left to type); a lowercase-typed query says little about case, so case only splits names of the same length — exactly the ASAP2 twins (`RPM` / `rpm`), which A still orders by the typed case. Code point last makes the order total over distinct names. |
| D-7 | A limit below 1 | **A** an empty ranked list (.19). **B** refuse with `ValueError` `limit must be at least 1, got <n>` (and .19 becomes that message row). | **A.** The caller derives the limit from the dropdown's free rows, which can be 0 on a small terminal and negative in height arithmetic; "no room, no suggestions" is the right answer for both, and B would need the same guard in every caller. A non-int limit is a type error (I-3), not this row. |
| D-8 | Match spans now, or with the UI | **A** now (.26–.32, .34): the matcher is the only place that knows which characters matched. **B** later, in Inc 7 if G2 asks for a highlight: 8 rows go (.26–.32, .34), I-3 drops `spans`, and Inc 7 re-derives the rules' positions — a second copy of the rules that can drift. | **A.** The highlight is how a fuzzy or subsequence suggestion explains itself (the rule tag alone does not show *which* letters); the spans cost no second pass (each rule finds its positions while matching). If G2 drops the highlight, Inc 7 ignores the field. |
| D-9 | May two query tokens use the same name token? | **A** yes: each query token needs a name token it starts (.8); its span is the leftmost such token (.30). **B** no: a distinct name token per query token — needs an assignment and a rule for which assignment gives the spans. | **A.** Deterministic spans with one sentence; a repeated query word is rare and harmless (`VALUE_0001_VALUE_0001` still finds `VALUE_0001`, .8/9). Under B, .8/9 gives `[]`. |
| D-10 | Where the rows fold into the canon | **A** a new subsection **S2.7 · Label matching (CTX-A2L-MATCH)** of S2 (A2L & MAC symbols), after S2.6. **B** a block inside S2.5 (the A2L Explorer). **C** a new module S18: the Modules table and `tests/test_requirements_canon.py::test_canon_modules_are_s0_to_s17_in_order` change. | **A.** The rows hold no screen behaviour, so they are not S2.5's; they are about A2L tag names, so S2. Inc 7's dropdown and paste-modal rows go to S2.5 and cite S2.7. |
| D-11 | The module's path | **A** `s19_app/tui/services/label_match.py`. **B** `s19_app/tui/label_match.py`, beside `a2l_parameter_picker.py`. | **A.** CLAUDE.md: feature logic goes in a service the app calls; `services/` already holds headless pure modules (`report_filter.py`, `flow_model.py`, `markdown_safety.py`). The module imports only the standard library: no Textual, no `a2l.py` (frozen), no file I/O. |
| D-12 | The performance bounds | **A** N = 50,000 names; preparation ≤ 5.0 s (median of 3); ranking ≤ 200 ms (median of 7 per query, each of the 22 QSET queries, limit 20); on cachyos-rtx; no memory row, the prepared list's memory measured and recorded at E4. **B** ranking ≤ 150 ms (the 0.15 s debounce the existing filters use): v3's worst median is 122.6 ms, a margin of 1.2× that host load can erase (v2 measured 122.2 ms under load ≈ 12). **C** N = 20,000. **D** add a memory row (for example ≤ 64 MiB at 50,000 names): the pilot's dict trie took ~137 MiB, so E2 must choose a compact structure. | **A.** 50,000 is 3.6× the largest real-shape fixture (`software_a.a2l`, 13,990 names) and covers "tens of thousands"; `case_06` (220,040 mechanical names) is a stress file beyond the bound. 200 ms leaves a 1.6× margin over v3's worst (20 of 22 queries ≤ 77 ms); 5.0 s a 2.5× margin over v3's 2.00 s. The measured path is the real one (no fake), as the PLAN's latency rule asks. D is worth ruling: the operator's Windows PC is not measured, and 137 MiB per loaded A2L is not small (BL-I4-4). |
| D-13 | The brief's "query longer than any name" | **A** no row of its own: the rules decide it (.8/9: 21 characters → `token`; .33/2: 18 characters → `fuzzy` with 2 edits; a longer query can never be an exact, prefix or substring match). **B** a row "If the query text is longer than a name, then …". | **A.** A row would restate .5–.10 (29148: necessary, singular); the cases are robustness cases of those rows. |

## 5. Interface I-3 — PROPOSED ruling (names, types, errors; under D-1 B, D-8 A, D-11 A)

```python
# s19_app/tui/services/label_match.py — headless, standard library only (no Textual, no tui/a2l.py)

class MatchRule(str, Enum):          # members in rank order (D-3 B); value = the rule word of the rows
    EXACT = "exact"; PREFIX = "prefix"; SUBSTRING = "substring"
    TOKEN = "token"; FUZZY = "fuzzy"; SUBSEQUENCE = "subsequence"

@dataclass(frozen=True, slots=True)
class LabelMatch:
    name: str                            # the name as listed (case kept)
    rule: MatchRule                      # R-A2L-MATCH.16
    edits: int                           # total edits for FUZZY (.33); 0 for every other rule
    spans: tuple[tuple[int, int], ...]   # half-open [start, end) offsets into name, in the .34 form

class LabelIndex:                        # a prepared name list (.35): immutable, opaque, safe to share with a worker thread
    names: tuple[str, ...]               # the distinct names, in first-occurrence order (.17)
    def __len__(self) -> int: ...

def build_label_index(names: Iterable[str]) -> LabelIndex: ...
def rank(query: str, index: LabelIndex, limit: int) -> list[LabelMatch]: ...
```

Errors (interface contract, no operator-visible behaviour, so no row; E4 tests them as interface checks):
- `build_label_index`: `TypeError("label names must be str, got <type name>")` for an element that is not a `str` (an A2L tag with no name is the caller's to skip: R-A2L-006.3 shows it as `UNKNOWN`); an empty iterable gives an empty index.
- `rank`: `TypeError("query must be str, got <type name>")`; `TypeError("limit must be int, got <type name>")`, a `bool` refused. For any `str` query and `int` limit it does not raise: limit < 1 → `[]` (.19), no letter or digit → `[]` (.2).
- Pure: the same query, index and limit give an equal list (.25); neither call mutates its arguments.

Consumer (Inc 7): build once per A2L load generation (I-4), off the UI thread; rank per debounced keystroke with the dropdown's row count as the limit; the paste modal ranks each missing label (limit 3, say) to offer its closest names, replacing the av_C prototype's `difflib.get_close_matches`.

## 6. Interfaces with other increments

- **Inc 7** (W2, after G2): the only consumer of I-3; also uses I-4 (Inc 5) to rebuild the index after a load and I-5 (the batch-102 bulk parser) for the paste modal. Inc 4 pins I-3 at its E2; Inc 7 proposes changes there, never alone.
- **Inc 1a, 1b, 2, 3, 5, 6, 8, 9:** no shared file or function (Inc 4 adds one new file).
- **Batch-101 (in flight):** no shared file; the module reads no case-08 file at run time (only its tests do, through `tools/synth/make_release_case.py` into a temporary folder, which Amendment A1 keeps byte-stable for batch-101).
- **To the requirements session (canon fold at batch end):** new subsection S2.7, context note CTX-A2L-MATCH, rows R-A2L-MATCH.1 … .37 (S2.8 per the D-10 ruling).

## 7. Backlog rows proposed (for the batch end)

- **BL-I4-1** — after G2, decide whether the Check Editor and Patch Editor parameter filter (R-CHKED-003) should rank with the matcher instead of a substring filter.
- **BL-I4-2** — initials-style abbreviations (`tom` for `TNM_OJJL_MAKAY…`) rank the intended name in the top 5 for ≤ 4 of 60 queries under either order (D-3 evidence); a boundary-anchored abbreviation rule (each typed letter at a token start) would need real operator queries to tune — a G2 question.
- **BL-I4-3** — a number typed without its zeros (`map 20` → `MAP_0020`) is found only by the last rule (subsequence); a rule that compares digit tokens by value would rank it higher. Not requested; noted for G2.
- **BL-I4-4** — the prepared list's memory: measure at E4 on 50,000 names and record; if it is above an operator-accepted figure, rule a bound (D-12 D).

## 8. What E1 could not check

- The ASAP2 identifier grammar (D-2) and Elasticsearch's `AUTO` cut points (D-4) are cited from memory; neither is load-bearing for a row (the rows fix their own numbers), but the reasons lean on them.
- The bounds are for cachyos-rtx; the operator's Windows work PC and the CI runners were not measured. The host load varied between the runs (≈ 12 during v1/v2, ≈ 3 during v3); each transcript prints it.
- The D-3 measurement uses generated queries over obfuscated real-shape names, not queries an operator typed; G2's prototype round is where real typing confirms or overturns it.
- The pilots are my own two implementations of my own rows (oracle and index agree, 0 mismatches), so their agreement shows the rows are unambiguous enough to implement twice, not that they are what the operator wants.
- `codewire_extract.py` was not run: no existing function changes, so there are no callers to extract (`E1-slice.md` §3). Code-Wire's tag `v3.1.0` resolves to `e436a08`, not PLAN's `ebc3bb7`; the two commits have the same tree (`6af5232…`), so the method is the same.

## Orchestrator rulings (2026-11-06T16:18:57-06:00, Opus 5.5)

| Decision | Ruling | Reason / change to the rows |
|---|---|---|
| D-1 | **B** (corrected 2026-11-06 at E2: the earlier text said A, its reason was B) | `build_label_index` + `rank`; a stateless rank misses the bound by 45×. |
| D-2 … D-9, D-11, D-13 | **A** | D-3 (fuzzy before subsequence) is accepted on the measured 46/60 vs 9/60; it changes the handoff's proposed order, not an operator rule. |
| D-10 | **S2.8**, not S2.7 | Inc 2 takes S2.7 ("A value by its A2L definition"); this increment folds into **S2.8 · Label matching (CTX-A2L-MATCH)**. Rows and notes renumber. |
| D-12 | **A + D** | Keep A's time bounds and add a memory row: the prepared index of 50,000 names takes ≤ 64 MiB (tracemalloc peak during `build_label_index`, cachyos-rtx). The pilot's dict trie (~137 MiB) does not meet it; E2 picks a compact structure. If E2 cannot meet 64 MiB with rank ≤ 200 ms, it escalates instead of loosening the row. |

## Erratum (2026-11-06T18:37:50-06:00, orchestrator)
§1, §2 and §6 above were written before the rulings: read **S2.8** for S2.7 and **37 rows** (R-A2L-MATCH.1 … .37) for 36. R-A2L-MATCH.37's negative control and base cite the v3 index at 77.9 MiB (tracemalloc), not the 137 MiB RSS figure (E2-2).
