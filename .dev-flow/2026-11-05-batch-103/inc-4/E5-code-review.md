# E5 code review — Inc 4, label similarity matcher (claude-opus-5-5, role `code`)

## Verdict: PASS-WITH-NOTES

No CRITICAL, HIGH or MAJOR finding. The code follows the approved graph: rule order, ties, edit bands, banded OSA, case-exactness, duplicate collapse, both caps and spans all match it. An independent rows-oracle (written from `01-requirements.md`, sharing no helper with the module) agrees with `rank` on 9,624 checks, with 0 mismatches. The banded `_prefix_distance` agrees with a full OSA on 20,000 pairs. **There is one open drift:** the Code-Wire extractor exits **1** on an `_order_key` return annotation (F1). That is a one-line fix, and the corrective pass must re-run the extractor to exit 0. E4 integration never ran the extractor that the graph's E4 notes require (`graph-inc4.md:492`; `steps.log` has no extractor line), so this drift was never caught there.

Scope: `s19_app/tui/services/label_match.py` (1,050 lines, `git diff a2043cfd HEAD`, read in full: lines 1–1050). I read the tests only where a finding needed them. The test-case audit belongs to another E5 role.

## Findings

| Id | Sev | Tag | Where | Requirement / node | Finding | Fix |
|---|---|---|---|---|---|---|
| F1 | MEDIUM | impl | `label_match.py:848` | node `_order_key` (graph out `tuple[int, int, int, int, str]`) | The code returns a bare `tuple`. The extractor reports "Output type mismatch" and exits 1 (`evidence-e5/code-review-extract.txt`, the only finding of 18 marks / 25 calls). | Annotate `-> tuple[int, int, int, int, str]` and match the docstring's Returns. Re-run the extractor on a marked throwaway copy; expect exit 0. |
| F2 | MINOR | impl | `label_match.py:609-611` | node `_prefix_distance` ("costs at most (2 × cap + 1) cells per query character, never query-token length × name-token length", A-3); R-A2L-MATCH.40 | The column loop runs over every character of the name token. Each pass allocates `[limit] * (m + 1)`, even past column `m + cap`, where the band is empty and `best` can no longer change. The cells are banded, but the cost per call grows with the name-token length: 0.233 ms against 0.004 ms bounded for `('aab', 'a'*1000, 1)`, and 1.035 against 0.474 ms for `('a'*255+'b', 'a'*1020, 2)`. No row is breached on the shapes measured: 300 distinct 701–1,000-letter tokens with 64 distinct near query tokens took 267.4 ms, and LONG with the same query 243.3 ms. Bounding the loop leaves every list equal (`evidence-e5/code-review-probe.txt` Part C). | `for j in range(1, min(n, m + cap) + 1):`. This equals the current result on 20,000 pairs (probe Part C). |
| F3 | LOW | impl | `label_match.py:378-382` | `rank` step 6 ("a mismatch is a defect of the tiers") | `if classified is None: continue` drops a listed name silently. Because the emitted rule comes from `_classify`, a tier that disagrees would also be hidden: the entry would be ordered by the tier's group but show `_classify`'s rule. The branch is dead while the tiers are correct (0 disagreements in the probe), but it hides the defect class the graph names. | Remove the guard and unpack `_classify(...)` directly, so a tier defect raises instead of shortening the list (rule 12, fail loud). |
| F4 | MINOR | impl | `label_match.py:261-393` | `CLAUDE.md` "Function granularity" (split at ~40–60 logical lines) | `rank` holds about 130 logical lines over five stages: text tiers, token tier, fuzzy call, subsequence tier, order and cut. Only the fuzzy tier is extracted. | Extract `_text_tiers`, `_token_tier`, `_subsequence_tier` and `_cut` as private tier helpers. The graph allows these unmarked (`graph-inc4.md:190`). |
| F5 | LOW | impl | `:200` and `:206`; `:541`; `:883-884`; `:33`; `:535-540`, `:548-553`, `:683-690`, `:745-750` | simplicity | (a) `tuple(tokens_sorted)` is built twice. (b) The outer `not _at_boundary(text, i)` branch in `_tokens` can never fire (every non-separator the outer loop reaches is a boundary), yet it costs one `_at_boundary` call per token at build. (c) The empty-prefix branch of `_token_range` is unreachable, because tokens are never empty. (d) `ord(chr(c))` is just `c`. (e) The CTX letter-or-digit test is written inline five times. | (a) `tokens = tuple(sorted(token_map))` once. (b) Drop the `or not _at_boundary(...)` from the outer test. (c) Drop the branch. (d) `{c: c + 32 ...}`. (e) Optional: one `_is_word_char(ch)` used by every site, if the build stays within its 5.0 s bound. |
| F6 | LOW | impl | `label_match.py:177`, `:186`, `:192` | R-A2L-MATCH.35/.37 build | `array("I", bytes(4 * n))` assumes `array('I').itemsize == 4`. That holds on both target platforms (E2-9), but on an ABI where it differs the build would raise or size wrongly. | Use `array("I", [0]) * n`. |
| F7 | LOW | impl | `label_match.py:399-407` | `PROJECT_RULES.md` "Private Helper Policy" | `_fuzzy_tier` is 75 lines and encodes the A-2 / E3A-14 invariants. Its docstring is one paragraph, with no Args or Returns, while every other helper in the module has Summary / Args / Returns. The helper itself is allowed (tier helper called only by `rank`, `graph-inc4.md:190`), so it is not a deviation. | Add Summary / Args / Returns in the module's form. |

## Checks (evidence states)

| Check | State | Evidence |
|---|---|---|
| Diff read in full | executed | `label_match.py:1-1050`; diff stat: 1 source file, 3 test files |
| Graph conformance, 17 nodes + 4 entities (signatures, contracts, I-3 error texts, procedure steps 1–6) | executed | read against `graph-inc4.md:26-60`, `:64-400`; only F1 drifts |
| Extractor, 0 drift | **failed** (1 drift, F1) | `evidence-e5/code-review-extract.txt` (throwaway copy in scratch, 18 marks, `_fuzzy_tier` unmarked; extract rc=1) |
| Correctness: rows-oracle differential (random pools of SWA names, synthetic names, case twins, duplicates, non-ASCII, U+00A0, U+001C, 1,024/1,025-character names; queries ± whitespace, edits, swaps, token subsets; limits 1, 3, 20, 10^6) | executed | `evidence-e5/code-review-probe.txt` Part A: 9,600 checks, 0 mismatches; tokens over 258 characters sharing a 258 prefix (trie truncation) with 256-character queries: 24 checks, 0 mismatches |
| `_prefix_distance` (band, transposition, cap) vs full OSA | executed | Part B: 20,000 pairs, cap 0–2, 0 mismatches |
| Rule order, ties, case-exactness only for exact/prefix/substring (A-1, anywhere), duplicate collapse in the token and fuzzy tiers (A-2), 256 cap before parse, 1,024 cap at build, spans | executed | read (`:265-393`, `:408-470`, `:763-845`) + Part A |
| Determinism | executed | sets hold ints only; str-keyed dicts are insertion-ordered and used for order only after `sorted`; output order comes from the total `_order_key` |
| Purity (stdlib only, no Textual, no I/O, no writes after build) | executed | imports `:19-25`; no module state written; `LabelIndex` frozen, arrays written only inside `build_label_index` |
| Style and docstrings | executed | public functions carry all sections; private helpers exceed the services' precedent (the other services: 180 private defs, 41 `Data Flow:` sections in all, public ones included; grep); F4, F7 |
| Cost of the unbounded column loop | executed | Part C (host load 0.59–0.70; mutant runs active on the host) |

Not run: the behaviour and perf suites (E4 evidence covers GREEN; mutants are other roles); Windows; CPython 3.12.

## Round 2 (2026-11-07T09:06:55Z)

### Verdict: PASS-WITH-NOTES

This round reviews `label_match.py` at sha256 `b97d19eb`, after the three correctives. No CRITICAL, HIGH, MAJOR or MEDIUM finding. The rewritten fuzzy tier follows the corrected graph: variant C postings with the switch at 512, range tables, C-level totals, the N = 20 cap and the 400,000-visit node budget. So do the compact build and the ASCII-only filter.

The checks behind that:
- **Rows oracle:** an oracle updated to the 43 rows agrees with `rank` on 9,600 checks, 0 mismatches. Its results sha256 is the same under PYTHONHASHSEED 0, 4242 and `random`.
- **Switch:** it changes no list. Caps 0, 512 and 10^9 give equal lists on 1,540 checks.
- **Budgeted walk:** at every budget it returns an exact, by-id prefix of the full walk (252,911 budgets, 0 failures).
- **Small budgets:** `rank` raises nothing and breaks no rule invariant (2,400 rankings).
- **Extractor:** exits 0, with 18 marks, 23 calls and 0 drift.
- **Round 1:** F1–F7 stay fixed.

Six notes remain, all LOW:
- F8: docstrings lag the code (security's E5S-15, both items confirmed, plus three more).
- F9: two rules are not checked in `_classify`.
- F10: one helper is not recorded in the graph.
- F11: simplicity residues in `_classify`.
- F12: the length of `_fuzzy_tier`.
- F13: the graph's import lists lag (`design-gap`).

**Scope.** I read the whole file (`label_match.py:1-1276`) against the delta `git diff 2e975987 HEAD -- s19_app/tui/services/label_match.py` (1,054 diff lines). I also read `graph-inc4.md` whole (543 lines) and rows .4, .10–.13, .17, .33, .35, .37 and .39–.43. I read corrective 3 alone as well (`0fd70835..38cf4427`): the budget constant, the `budget` argument with its visit count, and the `isascii` filter after the element type check. It matches graph E5-3 and the E4 note at `:541` line for line; the Sonnet authorship shows no departure. I read the tests only where a check needed them.

### Round-1 findings, re-checked on `b97d19eb`

| Id | State | Evidence |
|---|---|---|
| F1 | fixed, verified | `:1051-1053` returns `tuple[int, int, int, int, str]`. My extractor re-run on a throwaway copy exits 0 with 0 drift (`evidence-e5/code-review-r2-extract.txt`; it agrees with `corrective3-extract.txt`). |
| F2 | fixed, verified | `:804` `range(1, min(n, m + cap) + 1)`. Part B with the switch forced after the first token sends every candidate's token ids through `_prefix_distance`, and the lists stay equal. |
| F3 | fixed, verified (residue: F9) | `rank` no longer classifies. The rule and key come from the tier, and `_classify` raises `ValueError` (`:990`, `:1014`, `:1027`, `:1041`, `:1047`) instead of skipping an entry. Part D: 0 exceptions in 2,400 budget-cut rankings. |
| F4 | fixed | `rank` (`:293-326`) is about 30 logical lines. The tier helpers `_text_tiers` `:329`, `_token_tier` `:388`, `_subsequence_tier` `:439` and `_cut` `:475` are called only by `rank` and left unmarked, as `graph-inc4.md:226` allows. `_fuzzy_tier` has since grown (F12). |
| F5 | fixed | (a) one `tuple(sorted(distinct))` (`:206`). (b) the outer test in `_tokens` is the separator test only (`:742`). (c) no empty-prefix branch in `_token_range` (`:1088-1096`). (d) `{c: c + 32 …}` (`:34`). (e) `_is_word_char` (`:713`) serves 5 of the 6 sites; the keys filter (`:944`) stays inline on folded text, which is equivalent. The helper is not recorded (F10). |
| F6 | fixed | `array("I", [0]) * n` at `:209`, `:217`, `:223`. |
| F7 | fixed | `_fuzzy_tier` has Summary / Args / Returns (`:542-574`); its Returns lags the code (F8 (c)). |

### New findings

| Id | Sev | Tag | Where | Requirement / node | Finding | Fix |
|---|---|---|---|---|---|---|
| F8 | LOW | impl | `label_match.py:9-16`; `:272-280`; `:567-573` | E5S-15; I-3 purity; R-A2L-MATCH.42; `_fuzzy_tier` | **The docstrings lag the code.**<br>(a) E5S-15 is confirmed: the module docstring (`:13-14`) lists five modules, but `collections` is imported at `:23`. Its `:11-13` also says fuzzy candidates are scored by `_prefix_distance`. Since corrective 1 the trie walk `_fuzzy_token_distances` scores them; `_prefix_distance` runs only after the switch.<br>(b) E5S-15 is confirmed: `rank`'s Data Flow names .41's cap but not .42's node budget.<br>(c) `_fuzzy_tier`'s Returns says "Both are empty when the tier finds nothing", but the stops at `:629`, `:634` and `:650` return the tables made so far. It also says each table covers every token id within the allowed edits. After a budget cut a table holds only the ids the walk found; after the switch, only the candidates' ids. No caller misreads this today: `_cut` reads the tables for FUZZY entries only, and there are none then. | (a) List `array`, `bisect`, `collections`, `dataclasses`, `enum`, `typing`. Write "scores fuzzy candidates by the banded optimal-string-alignment prefix distance, walked over a trie of the name tokens (`_fuzzy_token_distances`; `_prefix_distance` after the switch)".<br>(b) Add "; the fuzzy walks of one ranking share 400,000 trie-node visits, and the fuzzy rule keeps what they found (R-A2L-MATCH.42)".<br>(c) Prefer `return {}, {}` at the three stops: it changes no list, and the stated contract then holds. Otherwise, reword the Returns to say what a cut or switched table covers. |
| F9 | LOW | impl | `label_match.py:977-979` (Raises), `:983-986` | node `_classify` (graph `:352`: "a name that does not meet `rule` … raises `ValueError`, never a skipped entry"); round-1 F3; CLAUDE.md rule 12 | **EXACT and PREFIX return spans without testing their rule.** The other four rules raise on a tier defect. A text-tier defect in `_text_tiers` (`:363-367`), such as a prefix name filed as exact, would emit a wrong span with no error. A check costs one string comparison per emitted entry, at most `limit` per ranking. | `if folded != text: raise ValueError(f"exact: {name!r} does not meet its tier")`; `if not folded.startswith(text): raise ValueError(f"prefix: {name!r} does not meet its tier")`. |
| F10 | LOW | impl | `label_match.py:713-720` | `graph-inc4.md:226`, `:540` ("any other new function is a deviation to record"); `PROJECT_RULES.md` Private Helper Policy | **`_is_word_char` is a new function outside the graph, and no record names it.** Corrective 1 added it on my round-1 F5 (e) suggestion. It is not a tier helper of `rank`: `_tokens`, `_at_boundary` and `_parse_query` call it. A grep of `inc-4/` finds it only in my round-1 F5. Its one-line docstring does not state the rule it encodes: every character above U+007F is a letter (CTX *letter*, E2-5), and three sites reuse that rule. This is not a mark gap: the extractor sees the calls through it (0 drift). | Record it in the graph's "Size and deviations" table: one private helper added, origin E5 code review F5 (e). This is a records change, not a code change. Give the helper Summary / Args / Returns that name the CTX rule. |
| F11 | LOW | impl | `label_match.py:1000-1003`, `:1035-1037` | simplicity; node `_classify` | (a) `_tokens(name)` and the query-token `counts` dict are built before the SUBSEQUENCE branch (`:1045`), which uses neither. That is up to `limit` wasted tokenisations of up to 1,024-character names per ranking. Only the dict's keys are read.<br>(b) The tie clause `value == best and pos < best_pos` can never hold. `first_pos` iterates ids by ascending first position, so `value < best` alone already keeps the leftmost (the graph's rule). | (a) Move both into the TOKEN and FUZZY branches, and use `dict.fromkeys(query.tokens)`.<br>(b) Drop the clause, or replace it with a comment saying `first_pos` is in position order. |
| F12 | LOW | impl | `label_match.py:539-667` | `CLAUDE.md` "Function granularity" (~40–60 logical lines) | **`_fuzzy_tier` holds about 80 logical lines.** It contains two table builders, the switched per-id path (`:606-630`) and the walked path (`:631-657`), plus the totals (`:658-667`). This is the class of round-1 F4, on a smaller scale. | Optional: extract the switched path as a private helper returning `(table, kept)`, updating the totals. It is called at most 20 times per ranking, so it adds no hot-loop cost. |
| F13 | LOW | design-gap | `graph-inc4.md:27-28` (I-3 block comment), `:535` (E4 note) | I-3 purity; `rank` step 4 (`:223`, which pins `collections.Counter`) | **The graph's import lists lag its own step 4.** Both lines still say the module imports `array`, `bisect`, `dataclasses`, `enum`, `typing` only. The purity test already accepts `collections` (`tests/test_b103_label_match.py:798`, `:808`), and the code imports it (`:23`). | Add `collections` to both graph lines. This is a records change: no row changes and no code change. |

### Checks (evidence states)

| Check | State | Evidence |
|---|---|---|
| Delta read in full | executed | `label_match.py:1-1276`; `2e975987..HEAD`; the corrective-3 delta `0fd70835..38cf4427` read on its own |
| Graph conformance | executed | Read against the graph: step 1 (cap before the parse), steps 2–6, `_fuzzy_token_distances` (runs, `budget`, `(runs, visits)`, `budget` 0 → `([], 0)`), the compact staging (`del add` before `del distinct`), and the `.43` filter after the type check. Deviations: F10, F13. |
| Extractor, 0 drift | executed | `evidence-e5/code-review-r2-extract.txt`: archive of HEAD `08a703cf`, CR stripped (copy sha256 equals the blob, `b97d19eb`); 18 marks; tier helpers and `_is_word_char` unmarked; rc 0; 23 calls; 0 findings. The marked copy was deleted. |
| Rows oracle (43 rows), random pools | executed | Part A (`code-review-r2-all-0-transcript.txt`): 9,600 checks, 0 mismatches. 1,367 expected lists hold a fuzzy entry; 145 queries exceed the 20-token cap; the most node visits in one ranking is 1,669, so the budget never cut these. The prepared names equal the oracle's `.39` / `.43` / `.17` filter in all 60 pools. |
| Determinism | executed | The Part A results sha256 is `9e6f5ea9…` under PYTHONHASHSEED 0, 4242 and `random` (`code-review-r2-{all-0,det-4242,det-random}-transcript.txt`). By reading: every output order comes from `_order_key`, sets hold ints only, and the tables are sorted lists. |
| The switch is a cost choice only | executed | Part B: `_FUZZY_SWITCH_CAP` 0 (never), 512 and 10^9 (after the first token) give equal lists on 1,540 checks. 215 lists hold a fuzzy entry; 40 of the checks are multi-token queries over a 50,000-name list with 77,256 tokens. |
| Budgeted walk | executed | Part C, probe v2 (`code-review-r2-cd-0-transcript.txt`), on 267 query tokens: the unbudgeted runs equal a brute-force OSA prefix distance over every token (0 mismatches). At every budget from 0 to full + 1 (252,911 budgets) the runs are sorted, disjoint, joined and exact, form a by-id prefix of the full runs and grow with the budget, and the visits equal `min(budget, full)`: 0 failures. |
| Rankings under a cut budget | executed | Part D, budgets 1–300, 2,400 rankings in each run, 0 invariant failures and 0 exceptions in both: exact / prefix / substring / token entries equal the oracle's, fuzzy entries are oracle fuzzy names with edits no lower than the oracle's, subsequence entries carry the oracle's spans, the list is in group order, and every oracle exact..token or subsequence name is listed. The budget moved an oracle fuzzy name to another rule in 66 rankings (v1) and 79 (v2). |
| Purity | executed | Imports `:19-26` (stdlib, `collections` included). `left` is a local of `_fuzzy_tier` (`:589`). Every `.append` / `.extend` targets a local or a build-time buffer (grep), so no index field is written after the build. |
| Dead code left by the rewrites | executed | F11 (b) only. Every import, constant and local is read. The `ord(ch) > 0x7F` branch is still needed for queries, even though names are now ASCII-only. |
| Behaviour and perf suites | not-run | GREEN is in `green-after-corrective3.txt` (145 / 20 / 219); not repeated here |
| Timing | n/a — security and perf own it | Host load was 14–20 during the probe, so no times are reported. |
| Windows, CPython 3.12 | not-run | — |

**Probe note.** Probe v1's Part C drew one 302-character query token from the 301-character name token. That input is outside R-A2L-MATCH.38's 256-character domain: the trie keeps 258 characters per token, so the walk cannot match it, while brute force did. That was the only mismatch (1 of 274 tokens). Probe v2 clamps tokens at 256 characters and re-ran Parts C and D: 0 mismatches. The change is in `code-review-r2-probe-v1-to-v2.diff`; the runner is `code-review-r2-run.sh`. The scratch on <runner> (`/tmp/b103-e5r2-4-code`, HOME `<user>`, a `cp -a` of the read-only `~/work/b103-int4`) was deleted after the runs.
