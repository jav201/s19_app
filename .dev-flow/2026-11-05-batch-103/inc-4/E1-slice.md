# Inc 4 — E1 slice: every file and function to add, counted and mapped

Base `e07fb00`. Line numbers are "as of `e07fb00`". Rows: `01-requirements.md`; decisions: `E1-rulings.md` (the slice follows D-1 B, D-3 B, D-8 A, D-11 A). The names below are E1 proposals; E2 (the Code-Wire graph) fixes them.

## 1. Summary

| File | Functions | Rows |
|---|---|---|
| `s19_app/tui/services/label_match.py` (**new**, D-11 A) | 4 types, 2 public functions, 15 private helpers | R-A2L-MATCH.1 … .41 |

**Totals:** **1 source file of the 4 allowed** (new). 17 functions, 4 types, 18 graph nodes (PLAN estimate ~8). 0 changed, 0 removed functions: nothing in `e07fb00` changes. Not source: none (the user guide gains the autocomplete with Inc 7). Tests (not capped): 2 new files (§4).

## 2. Function map

| Node | Kind | Contract (proposal) | Rows |
|---|---|---|---|
| `MatchRule` | `str` enum | six members in rank order: `exact`, `prefix`, `substring`, `token`, `fuzzy`, `subsequence` | .5–.10, .16, .20 |
| `LabelMatch` | frozen dataclass | `name: str`, `rule: MatchRule`, `edits: int` (total edits for `fuzzy`, else 0), `spans: tuple[tuple[int, int], ...]` | .16, .26–.34 |
| `LabelIndex` | immutable class (opaque) | the prepared name list: distinct names in first-occurrence order, their folded forms, their tokens, their boundary offsets, and a structure of the distinct folded tokens for the token and fuzzy steps | .17, .35, .37 |
| `_Query` | NamedTuple | the parsed query: `text: str` (folded), `tokens: tuple[str, ...]` (folded token strings), `keys: str` (folded) | — |
| `build_label_index(names: Iterable[str]) -> LabelIndex` | public | de-duplicates, folds, tokenises, indexes (E5 round 2, E5S-08: the compact staging of `codewire/graph-inc4.md`: a set of the distinct tokens, then each occurrence's id by bisect; no token-to-id dict); leaves out a name longer than 1,024 characters (.39); `TypeError` for a non-`str` name or a `str`/`bytes` argument (I-3) | .17, .35, .37, .39 |
| `rank(query: str, index: LabelIndex, limit: int) -> list[LabelMatch]` | public | strips the query (.1); `[]` for a limit below 1 (.19), a stripped query longer than 256 characters (.38, checked before the parse) or no letter or digit (.2); takes the query tokens as a multiset, at most one range or table per distinct token (.40), and no fuzzy tier for more than 20 distinct query tokens (.41; E5 round 2, E5S-07); finds each name's first rule (.14–.16), orders (.20–.25), cuts at the limit (.18), each entry with its tier's rule and key (E5 correction, E5S-01: no listed name classified again; `codewire/graph-inc4.md` rank steps 4 and 6); `TypeError` for a non-`str` query or a non-`int` limit (I-3) | .1, .2, .14–.16, .18–.25, .36, .38, .40, .41 |
| `_fold(text: str) -> str` | private | `A`–`Z` → `a`–`z`, every other character kept (same length) | .3, .4 |
| `_tokens(text: str) -> tuple[tuple[int, int], ...]` | private | the token spans of CTX-A2L-MATCH *token*, read on the unfolded text (the case cuts need the case) | .8, .10, .21, .28–.30, .32 |
| `_allowed_edits(token: str) -> int` | private | 0 for digits or 1–2 letters, 1 for 3–5 letters, 2 for 6 or more | .11–.13 |
| `_prefix_distance(query_token: str, name_token: str, cap: int) -> int` | private | the optimal string alignment distance to the nearest prefix, computed on the band \|i − j\| ≤ `cap` (A-3), with an early exit above `cap`; called only by `rank` step 4 after its switch, on the remaining candidates' token ids (E5S-01) | .10, .13, .22, .33, .40 |
| `_classify(query: _Query, name: str, rule: MatchRule, token_ids, tables) -> tuple[tuple[int, int], ...]` | private | E5 correction (E5S-01 (b)): the match spans of one listed name for the rule its tier found, testing no other rule; FUZZY spans from the step-4 tables by the name's token ids, no `_prefix_distance` (E5 round 2, E5S-07 (a), E5S-09 (3): a table is its runs `(los, his, ds)`; each distinct id of the name is looked up once per distinct query token by bisect); a name that does not meet `rule` raises `ValueError` (case-exactness is decided in `rank` by string comparison, not here; until E5 it returned the first rule, key and spans) | .26–.32 |
| `_join_spans(spans) -> tuple[tuple[int, int], ...]` | private | the fewest spans in offset order covering the same offsets | .34 |
| `_order_key(match, case_exact: bool) -> tuple` | private | (rank of the rule, rule key, length, 0 if case-exact else 1, name) | .20–.25 |
| `LabelIndex.__len__(self) -> int` | private | the number of distinct names the index holds: `len(self.names)` | .17 |
| `_char_mask(text: str) -> int` | private | the OR of one bit per character of an already folded `text`: `a`–`z` bits 0–25, `0`–`9` bits 26–35, any other `c` bit `36 + ord(c) % 27` | .9, .36 |
| `_at_boundary(name: str, offset: int) -> bool` | private | whether `offset` is a CTX-A2L-MATCH boundary offset (0; a separator; or a token start, read on the unfolded name); the single source of the token cut rules | .21, .28, .29 |
| `_subsequence(keys: str, text: str) -> tuple[int, ...] \| None` | private | the leftmost offsets of the key characters in `text`, each after the one before, or `None` | .9, .31 |
| `_parse_query(query: str) -> _Query \| None` | private | strips exactly the six CTX whitespace characters (never `str.strip`); `None` when no letter or digit; else text folded, tokens folded, keys folded | .1–.3, .8 |
| `_token_range(tokens: tuple[str, ...], prefix: str) -> tuple[int, int]` | private | the contiguous id range of the sorted distinct tokens that start with `prefix` | .8, .11, .30 |
| `_build_trie(tokens: tuple[str, ...]) -> tuple[str, array, array, array]` | private | the pre-order array trie of the sorted distinct tokens (chars, depth, first, end) | .35–.37 |
| `_fuzzy_token_distances(index: LabelIndex, query_token: str, allowed: int) -> list[tuple[int, int, int]]` | private | the sorted, disjoint runs `(lo, hi, d)` of token ids within `allowed` edits (E5 round 2, E5S-07 (a): one run per pruned trie subtree; until then `{token id: prefix distance}`), at most one trie walk per distinct query token (until `rank` step 4's switch), each run list kept as that token's table for step 6 (E5S-01) | .10–.13, .36, .40 |

Design note: superseded by the graph's compact index (`codewire/graph-inc4.md`, finding E2-1) — flat `array` buffers, a pre-order array trie and a sorted tuple of distinct tokens in place of the pilot's dict trie and bitmasks; the definitional oracle (`evaluate_b`, `naive_rank_b`) is the reference the testers' expected values were checked against, not code to copy.

## 3. Callers read (rule 8: read before you write)

- **No existing function changes**, so no caller of a changed function exists and `codewire_extract.py` has nothing to extract. Code-Wire checked: `git -C C:\Users\jjgh8\Github\code-wire describe --tags` = `v3.1.0` (tag commit `e436a08`; PLAN names `ebc3bb7`, same tree `6af5232…`).
- **Where the names come from:** `parse_a2l_file(path)["tags"][i]["name"]` (`s19_app/tui/a2l.py:2797`, the tag dict built at `:2611-2612`), the reader the census and the pilots used; the A2L views list these names (S2.2).
- **Who will call it (Inc 7, not now):** the A2L Viewer's autocomplete and the paste modal (I-3), building the index on each A2L load (I-4).
- **Beside it, unchanged:** `S19TuiApp._filter_a2l_tags` and `_tag_matches_filter` (`app.py:20475`, `:20494`; R-A2L-007.1, .2), `S19TuiApp._a2l_tag_matches_find_query` (`app.py:16641`; R-A2L-090), the picker filter `A2LParameterPicker.on_input_changed` and its rebuild (`a2l_parameter_picker.py:694-700`, `:806-809`; R-CHKED-003), `parse_parameter_list` (`a2l_parameter_picker.py:75`; I-5). Evidence: `evidence-e1/i4e1-base-grep.txt`.
- **Frozen modules:** the new module imports none of the frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); only its tests read A2L files through `a2l.py`.

## 4. Tests (proposed for E4; testers own them)

- **G-T1 `tests/test_b103_label_match.py`** — the 118 coverage items outside G-T2 and the 2 black-box cases of `02-test-cases.md` (120 cases; .41/1–/5 added by the E5 round-2 pass). Pure: no Textual, no app. Case 08 is generated into `tmp_path` by `tools/synth/make_release_case.py` (seed 20260001; subprocess or its `generate()`), never into the repository; the fixture A2Ls are read with `parse_a2l_file`. Module-scoped fixtures for the prepared lists.
- **G-T2 `tests/test_b103_label_match_timing.py`** — `@pytest.mark.serial_timing`: R-A2L-MATCH.35/1, .36/1, .40/1, .40/2, .40/3 (the CRAFT stress list, added by the E5 correction, E5S-01), .40/4 (BAND, the E5 corrective pass) and .40/5 (U6, the E5 round-2 pass, E5S-07), printing the host load before and after, `time.perf_counter()` around each call (the style of `tests/test_a2l_alignment_sizing.py:248-253`); and R-A2L-MATCH.37/1 and .37/2 (B4MAX, E5S-08), byte bounds with no mark (9 cases in all; the file landed as `tests/test_b103_label_match_perf.py`).
- **Law guards at E5** (CLAUDE.md), with what they ask of this increment:
  - `tests/test_engine_unchanged.py` — the frozen set is untouched (the module is new, outside it).
  - `tests/test_id_registry.py` — the AT ids are outside its authority; **`EXPECTED_SCANNED_TEST_FILES = 267` (`:184`) grows by the 2 new test files**, re-measured at integration because other increments add files too (an E4 edit of a test file, not source).
  - `tests/test_suite_hygiene.py` R-TST-002 (`:392`) — every timing arm carries `serial_timing`: G-T2 is marked, and G-T1 times nothing.
  - `tests/test_import_census.py` TC-654 (`:292-299`) — no `tui/services/*` module imports `insight_style`: the matcher imports the standard library only.
  - `tests/test_requirements_canon.py` — at the canon fold (batch end).
