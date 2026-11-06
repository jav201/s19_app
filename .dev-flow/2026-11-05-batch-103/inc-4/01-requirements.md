# Inc 4 — Label similarity matcher (pure module): requirements (E1)

Batch 2026-11-05-batch-103, increment 4. Base: `e07fb00` (branch `batch-103` = `main` `e07fb00` + the batch-103 records). Stage E1 of the design-first flow (`dev-flow-v3-beta`). Scope: PLAN.md row Inc 4 (US-103-03; the UI that uses the matcher — the autocomplete dropdown and the paste modal — is Inc 7, after prototype round 2) and interface I-3. Decisions and the canon home: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`.

Form column: U = ubiquitous, E = event (`When`), If = unwanted behaviour. **Status:** every row is **new** (family `R-A2L-MATCH`, checked unused: `evidence-e1/i4e1-base-grep.txt`). **Base** (what `e07fb00` does): **No** for every row — no part of `s19_app/` ranks names by similarity (R: `evidence-e1/i4e1-base-grep.txt`; the nearest behaviour is the four substring filters listed under *Relation to existing rows*). The base column therefore says what the E1 evidence shows for the proposed rule: B = the E1 pilots, run on cachyos-rtx (Python 3.11.18, a throwaway reference of these rows; `evidence-e1/i4e1-pilot*.py`), C = the E1 census (`evidence-e1/i4e1-census-transcript.txt`).

The rows follow the E1 recommendations of `E1-rulings.md` (D-1 B … D-13 A); in particular the rule order is **exact · prefix · substring · token · fuzzy · subsequence** (D-3 B: fuzzy before subsequence, which differs from the handoff's order, with the measurement that decides it). If the orchestrator rules otherwise, the rows named in each decision change as that decision says.

## User stories

### US-I4-1 — names found by similarity, in one stable order (US-103-03)
As the operator building a list of labels in the A2L Viewer, I want the names that look like what I typed — matching its start, middle or end, word by word, and forgiving a typo — listed best first in an order that never changes for the same input, so that I can complete a label name without knowing how it begins.

### US-I4-2 — fast enough for every keystroke (US-103-03)
As the operator, I want the suggestions for an A2L of tens of thousands of labels computed within a keystroke's budget, so that typing never waits for the list.

## Definitions (context note CTX-A2L-MATCH, new; terms and formats only)

```text
name list         The names a ranking runs over: the A2L tag names (S2.2), as the A2L
                  views list them. A name may appear more than once (C: case 08's
                  firmware_issues.a2l lists VALUE_0001 twice).
query             The text the operator types to find names.
query text        What the rows compare with the names (R-A2L-MATCH.1).
whitespace        Space, tab, line feed, carriage return, vertical tab, form feed.
uppercase letter  A to Z (U+0041 … U+005A).
lowercase letter  a to z (U+0061 … U+007A).
letter            An uppercase or lowercase letter, or any character above U+007F
                  (a letter that has no case).
digit             0 to 9.
separator         Every other character: _ . [ ] - space * and the rest of ASCII.
token             Of a name or of the query text: a maximal run of digits, or a maximal
                  run of letters cut before an uppercase letter that follows a lowercase
                  letter, and before the last uppercase letter of a run of two or more
                  uppercase letters that a lowercase letter follows. Separators belong
                  to no token. Examples (B, i4e1-pilot-transcript.txt §2):
                    VAL_BLK_0001                         VAL · BLK · 0001
                    model.MainClass.ledRing[0].red       model · Main · Class · led · Ring · 0 · red
                    parameter_instance[0].Knife[1].x     parameter · instance · 0 · Knife · 1 · x
                    ABSValue · AValue · Map3D            ABS · Value | A · Value | Map · 3 · D
                    LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy    Luk · Pvq · JXML · UPQ · BI · OKS · Ahwvcueaniy
                    Aabcx_GgrDwx_kaudIvm_ydmuH_uoz3._5_  Aabcx · Ggr · Dwx · kaud · Ivm · ydmu · H · uoz · 3 · 5
                    Drück_Max                            Drück · Max
name token        A token of a name.   query token   A token of the query text.
digit token       A token of digits.
boundary offset   In a name: offset 0, the first offset of a token, or the offset of a
                  separator.
key characters    The letters and digits of the query text, in their order.
edit distance     Between two texts: the least number of insertions, deletions and
                  substitutions of one character and transpositions of two adjacent
                  characters that turn one text into the other, no character edited
                  twice (the optimal string alignment distance); characters compare as
                  R-A2L-MATCH.3 and .4 say.
prefix distance   From a query token to a name token: the smallest edit distance between
                  the query token and a prefix of the name token, the empty prefix
                  included (cuvre → CURVE: 1; valuee → VALUE: 1; value → VAL: 2).
allowed edits     Of a query token: R-A2L-MATCH.11 … .13.
total edits       Of a fuzzy match: the sum, over the query tokens, of the smallest prefix
                  distance from each query token to a name token of the name.
match rules       exact · prefix · substring · token · fuzzy · subsequence
                  (R-A2L-MATCH.5 … .10). Rank order: that order.
rule key          substring: whether the query text occurs at a boundary offset;
                  fuzzy: the total edits; every other rule: none.
case-exact        A listed name whose rule still holds when an uppercase letter and its
                  lowercase letter are compared as different characters.
listed names      The names the system ranks for a query (R-A2L-MATCH.14), in rank order.
limit             The largest number of names the ranked list may hold.
ranked list       What the system returns: the first listed names (R-A2L-MATCH.18), each
                  with its rule, its total edits (fuzzy only) and its match spans.
match span        [start, end): the offsets of the name characters a match covers.
prepared name list  A name list the system has prepared for ranking (R-A2L-MATCH.35).
```

## Requirements (new module S2.8 · Label matching, CTX-A2L-MATCH; proposed home: `E1-rulings.md` D-10)

### The query (US-I4-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.1 | E | When the system ranks a name list for a query, the system shall take as the query text the query without its leading and trailing whitespace. | 3/3 cases (/1–/3): `  VALUE_0001  ` and `\tVALUE_0001\n` give exactly `VALUE_0001` `exact` [(0,10)]; ` value_000 ` with limit 5 gives the 5 entries of `value_000` with spans [(0,9)] | no strip → `  VALUE_0001  ` keeps its spaces, is no `exact` match and lists `VALUE_0001` as `token` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.2 | If | If the query text holds no letter and no digit, then the system shall return an empty ranked list. | 5/5 cases (/1–/5): ``, `   `, `\t\n`, `_`, `._[]` over the case-08 names → 0 entries | guard removed → the empty text is a prefix of all 462 names (462 `prefix` entries) and `_` a substring of all → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.3 | E | When the system compares a character of the query text with a character of a name, the system shall treat an uppercase letter and its lowercase letter as the same character. | 3/3 cases: `value_0001` and `Value_0001` give `VALUE_0001` `exact`; `rpm` over [`RPM`, `rpm`, `Rpm`] gives all three `exact` | case-sensitive compare → `value_0001` gives no `exact` entry (and `rpm` one, not three) → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.4 | If | If two compared characters are different characters and are not an uppercase letter and its lowercase letter, then the system shall treat them as different characters. | 3/3 cases: `drück` over [`Drück_Max`, `DRÜCK_MAX`, `druck_max`] lists `DRÜCK_MAX` as `fuzzy` with 1 edit, not `prefix`; `DRÜCK` lists `Drück_Max` as `fuzzy` 1; `VALUE-0001` lists `VALUE_0001` as `token`, not `exact` (`-` ≠ `_`) | Unicode case folding (`str.lower`/`casefold`) → `DRÜCK_MAX` becomes `prefix` for `drück` → RED; `-` and `_` treated alike → `exact` → RED | US-I4-1 | new | No (B: holds) |

### The match rules (US-I4-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.5 | U | The system shall count as an `exact` match each name that is the query text. | 3/3 cases: `VALUE_0001` → `VALUE_0001` `exact`; `map_0020` → `MAP_0020` `exact`; `rpm` over the three twins → 3 `exact` | no exact rule (an equal name counted as `prefix`) → rule `prefix` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.6 | U | The system shall count as a `prefix` match each name that starts with the query text. | 3/3 cases: `value_000` (limit 5) → `VALUE_0001` … `VALUE_0005` `prefix`; `span` over case-08 issues → `SPAN_OVER_1`, `SPAN_OVER_2`; `LIMIT` → `LIMIT_BREAKER` | no prefix rule → those names fall to `substring` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.7 | U | The system shall count as a `substring` match each name that contains the query text. | 4/4 cases: `0001` → the 6 `…_0001` names `substring`; `knife[1]` over from_source → the 4 `…Knife[1].x` names `substring`; `[0].Spoon` → `parameter_instance[0].Spoon.x`; `ledRing[1]` (limit 4) → 4 `substring` | the query used as a regular expression → `knife[1]` is a character class and matches no `[1]` → the 4 names are not `substring` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.8 | U | The system shall count as a `token` match each name that has, for each query token, a name token that starts with that query token. | 9/9 cases (/1–/9): word order free (`blk val 00`), camelCase (`stop watch`), an uppercase run (`oks ahw` → `OKSAhwvcueaniy`), digits and brackets (`knife 1 x`), separators of every kind (`out range`, `knife.*`), the cut before the last uppercase letter (`a value` → `AValue`, `ABSValue`), letter/digit cuts (`map 3 d` → `Map3D`), a query longer than every name (`VALUE_0001_VALUE_0001`) | tokens cut on `_` only (no camelCase cut) → `stop watch` is no `token` match → RED; no uppercase-run cut → `oks ahw` misses `OKSAhwvcueaniy` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.9 | U | The system shall count as a `subsequence` match each name that holds the key characters in their order. | 4/4 cases: `mp` (limit 3) → `MAP_0001` … `MAP_0003` `subsequence`; `ascii 1` → `ASCII_0001`, `ASCII_0010`; `map 20` → `MAP_0020`; `gamecontroller timer` (BalanceTube, limit 3) → 2 `subsequence` | no subsequence rule → `map 20` gives 0 entries → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.10 | U | The system shall count as a `fuzzy` match each name that has, for each query token, a name token at a prefix distance from that query token no greater than its allowed edits. | 6/6 cases: `cuvre`, `mpa` (transpositions), `xmap` (insertion), `maq` (substitution), `maesurement_0001`, `vlaue_0001` → the expected `fuzzy` entries with their total edits | edit distance without transpositions (plain Levenshtein) → `cuvre` → CURVE is 2 > 1 and `mpa` → MAP is 2 > 1 → 0 entries → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.11 | U | The system shall give 0 allowed edits to a query token of digits or of 1 or 2 letters. | 3/3 cases → 0 entries: `VALUE_0300` over case 08 (`0300` is 2 edits from `0208` and starts no token), `ab` over [`BA_X`] (prefix distance 1), `ca` over [`abc`] (1) | 1 edit allowed to digit tokens → `VALUE_0300` lists `VALUE_0200` … (`0300` → `0200` is 1) → RED; to 2-letter tokens → `ab` lists `BA_X` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.12 | U | The system shall give 1 allowed edit to a query token of 3 to 5 letters. | 3/3 cases: `maq` (3 letters, 1 edit) and `cuvre` (5 letters, 1 edit) are `fuzzy` matches; `cvure` (5 letters, prefix distance 2) gives 0 entries | 2 edits for 3–5 letters → `cvure` lists the CURVE names → RED; 0 edits → `maq` gives 0 entries → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.13 | U | The system shall give 2 allowed edits to a query token of 6 or more letters. | 3/3 cases: `valuexx_0001` → `VALUE_0001` `fuzzy` 2 edits; `valuexxx_0001` (3 edits) → 0 entries; `curvee` over [`CUVE`, `CURVE_0001`] → both `fuzzy` (1 and 2 edits) | 1 edit for ≥ 6 letters → `valuexx_0001` gives 0 entries → RED; 3 edits → `valuexxx_0001` lists `VALUE_0001` → RED | US-I4-1 | new | No (B: holds) |

### The ranked list (US-I4-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.14 | E | When the system ranks a name list for a query, the system shall list each name that is a match of at least one rule. | 2/2 cases with a limit above the count: `value_000` (limit 100) → exactly 20 entries (9 `prefix`, 11 `subsequence`); `0001` (limit 100) → exactly 6 | a rule left out of the listing (subsequence not listed) → `value_000` gives 9 → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.15 | If | If a name is a match of no rule, then the system shall leave it out of the listed names. | 2/2 cases: `temp_sensor_max` over case 08 → 0 entries; `v` over [``, `   `, `VALUE_0001`] → only `VALUE_0001` | a catch-all rule (every name listed last) → `temp_sensor_max` gives 462 entries → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.16 | E | When the system lists a name, the system shall give it the first rule in rank order of which the name is a match. | 3/3 cases: `value_000` lists `VALUE_0001` as `prefix` (it is also a substring and a fuzzy match); `valu_0001` lists `VALUE_0001` as `token` and `VAL_BLK_0001` as `fuzzy`; `vale_0001` lists `VALUE_0001` as `fuzzy` (it is also a subsequence match) | the last rule met instead of the first → `VALUE_0001` is `fuzzy` for `value_000` → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.17 | If | If the name list holds a name more than once, then the system shall list that name once. | 2/2 cases over case-08 issues (470 names, `VALUE_0001` twice): `VALUE_0001` → 1 entry; `value_000` (limit 20) → the same 20 entries as over case 08 | no de-duplication → `VALUE_0001` twice → RED | US-I4-1 | new | No (B: holds; C: 1 repeated name in case-08 issues, 86 in the union of the fixtures) |
| R-A2L-MATCH.18 | E | When the system ranks a name list for a query with a limit `<n>` of 1 or more, the system shall return the listed names in rank order up to the `<n>`-th. | 3/3 cases: `value_000` limit 5 → 5 entries, limit 1 → `VALUE_0001` alone; `0001` limit 20 → its 6 entries | limit ignored → 20 entries for limit 5 → RED; `<n>` + 1 entries → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.19 | If | If the limit is less than 1, then the system shall return an empty ranked list. | 2/2 cases: `VALUE` with limit 0 and with limit −1 → 0 entries | a slice `[:limit]` → limit −1 returns all but the last listed name → RED | US-I4-1 | new | No (B: holds) |

### The rank order (US-I4-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.20 | E | When the system orders the listed names, the system shall place them by their rule in rank order. | 3/3 cases: `value_000` (limit 20) → the 9 `prefix` entries before the 11 `subsequence` entries; `gamecontroller.timer` (BalanceTube) → `substring` before `subsequence`; `oks ahw` (software_b) → `token`, then `fuzzy`, then `subsequence` | order by name alone → rules interleave → RED; the handoff order (subsequence before fuzzy, D-3 A) → `oks ahw` lists `subsequence` before `fuzzy` → RED | US-I4-1 | new | No (B: holds; D-3 measurement in `evidence-e1/i4e1-order-eval-transcript.txt`) |
| R-A2L-MATCH.21 | E | When the system orders two listed names with the rule `substring`, the system shall place a name in which the query text occurs at a boundary offset before a name in which it occurs at none. | 3/3 cases: `counter` over [`timeCounter`, `Encounter`] → `timeCounter` first though longer; `_0001` (a separator start) → all 6 at a boundary; `ounter` (BalanceTube, limit 4) → 3 entries at no boundary | key left out (length first) → `Encounter` first → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.22 | E | When the system orders two listed names with the rule `fuzzy`, the system shall place the name with fewer total edits first. | 1/1 case: `curvee` over [`CUVE`, `CURVE_0001`] → `CURVE_0001` (1 edit, 10 characters) before `CUVE` (2 edits, 4 characters) | edits left out (length first) → `CUVE` first → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.23 | E | When the system orders two listed names with the same rule and the same rule key, the system shall place the shorter name first. | 2/2 cases: `0001` → `MAP_0001` (8) first and `MEASUREMENT_0001` (16) last; `rpm` over [`rpm_x`, `RPMX`] → `RPMX` (4) before the case-exact `rpm_x` (5) | length left out → `ASCII_0001` before `MAP_0001` → RED; case-exactness before length (D-6 B) → `rpm_x` first → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.24 | E | When the system orders two listed names with the same rule, rule key and length, the system shall place a case-exact name before a name that is not case-exact. | 3/3 cases: `rpm` → `rpm` first; `RPM` → `RPM` first; `drück` → `druck_max` (case-exact fuzzy) before `DRÜCK_MAX` | case-exactness left out → `rpm` gives `RPM`, `Rpm`, `rpm` → RED | US-I4-1 | new | No (B: holds; C: 0 case-twins in the fixtures, 1 in the tests' inline A2L) |
| R-A2L-MATCH.25 | E | When the system orders two listed names with the same rule, rule key, length and case-exactness, the system shall place them in code-point order. | 3/3 cases: `0001` → `ASCII_0001`, `CURVE_0001`, `VALUE_0001` in that order; the same over the reversed list; `rpm` over [`Rpm`, `rpm`, `RPM`] → `rpm`, `RPM`, `Rpm` | input order kept (stable sort, no name key) → the reversed list gives `VALUE_0001` first → RED | US-I4-1 | new | No (B: holds) |

### Match spans and total edits (US-I4-1; for the dropdown's highlight in Inc 7, D-8)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.26 | E | When the system lists a name with the rule `exact`, the system shall give it one match span over the whole name. | 2/2 cases: `VALUE_0001` → [(0,10)]; `map_0020` → [(0,8)] | no span → [] → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.27 | E | When the system lists a name with the rule `prefix`, the system shall give it one match span from offset 0 over the length of the query text. | 3/3 cases: `value_000` → [(0,9)]; `span` → [(0,4)]; ` value_000 ` → [(0,9)] | span over the whole name → [(0,10)] → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.28 | E | When the system lists with the rule `substring` a name in which the query text occurs at a boundary offset, the system shall give it one match span over the leftmost such occurrence. | 2/2 cases: `count` over [`DiscountCount`] → [(8,13)], not the leftmost occurrence (3,8); `0001` on `MAP_0001` → [(4,8)] | leftmost occurrence regardless of boundaries → [(3,8)] → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.29 | If | If the query text occurs in a name listed with the rule `substring` at no boundary offset, then the system shall give the name one match span over the leftmost occurrence of the query text. | 2/2 cases: `ounter` on `model.MainClass.ledController.sw.timeCounter` → [(38,44)]; `sahw` on `LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy` → [(21,25)] | no span when no boundary occurrence → [] → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.30 | E | When the system lists a name with the rule `token`, the system shall give it, for each query token, a match span from the start of the leftmost name token that starts with that query token, as long as that query token. | 3/3 cases: `blk val 00` → [(0,3),(4,7),(8,10)]; `knife 1 x` on `parameter_instance[1].Knife[0].x` → [(19,20),(22,27),(31,32)] (`1` takes the leftmost token that starts with `1`); `a value` on `ABSValue` → [(0,1),(3,8)] | span over the whole name token → `00` gives (8,12) → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.31 | E | When the system lists a name with the rule `subsequence`, the system shall give it a match span for each key character, at the leftmost offset after the offset of the key character before it. | 3/3 cases: `mp` on `MAP_0001` → [(0,1),(2,3)]; `value_000` on `VALUE_0010` → [(0,5),(6,8),(9,10)]; `gamecontroller timer` on `model.MainClass.gameController.stopWatch.timeCounter` → [(16,30),(32,33),(42,45),(51,52)] | each key character at its rightmost possible offset → the BalanceTube name gets other spans (the last `t`, `i`, `m`, `e`, `r` of the name) → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.32 | E | When the system lists a name with the rule `fuzzy`, the system shall give it, for each query token, a match span over the leftmost name token at the smallest prefix distance from that query token. | 3/3 cases: `maesu` on `MEASUREMENT_0001` → [(0,11)] (the whole token, not the 5 query letters); `valu_0001` on `VAL_BLK_0001` → [(0,3),(8,12)]; `vblk` on `VAL_BLK_0001` → [(4,7)] | span as long as the query token → `maesu` gives [(0,5)] → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.33 | E | When the system lists a name with the rule `fuzzy`, the system shall give it its total edits. | 3/3 cases: `maesurement_0001` → 1; `measurementss_0001` → 2; `cuvre maq` over [`Curve_Map_X`] → 2 (1 + 1) | total edits always 0 → RED; the largest edit instead of the sum → `cuvre maq` gives 1 → RED | US-I4-1 | new | No (B: holds) |
| R-A2L-MATCH.34 | E | When the system gives a listed name more than one match span, the system shall give them as the fewest spans, in offset order, that cover the same offsets. | 3/3 cases: `abs value` on `ABSValue` → [(0,8)] (touching spans joined); `blk val 00` → in offset order though the query names `blk` first; `a value` on `AValue` → [(0,6)] | spans in query-token order → `blk val 00` gives [(4,7),(0,3),(8,10)] → RED; touching spans not joined → [(0,3),(3,8)] → RED | US-I4-1 | new | No (B: holds) |

### Performance (US-I4-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-MATCH.35 | E | When the system prepares a name list of 50,000 names for ranking, the system shall finish within 5.0 s. | median of 3 preparations of the reference list (`02-test-cases.md`, fixture REF) ≤ 5.0 s on cachyos-rtx, Python 3.11.18, a `serial_timing` test that prints the host load before and after | a preparation that computes the fuzzy distances of every name token pair (quadratic) → minutes → RED | US-I4-2 | new | No (B, v3: median 2.00 s, host load 3.2–3.4 on 16 cores, `i4e1-pilot3-transcript.txt` §4; v2: 3.26 s under load ≈ 12; the pilot's dict trie added ~137 MiB, `E1-rulings.md` D-12) |
| R-A2L-MATCH.36 | E | When the system ranks a prepared name list of 50,000 names for a query with a limit of 20, the system shall return the ranked list within 200 ms. | each of the 22 queries of fixture QSET over the prepared reference list: the median of 7 consecutive rankings ≤ 200 ms, on cachyos-rtx, Python 3.11.18, `serial_timing`, host load printed | no preparation (every ranking re-reads the 50,000 names: 9.15 s for one query, B v1) → RED; a fuzzy step that scans every distinct token per query token (v1 index: 1,186.7 ms for `qqqq zzzz`) → RED | US-I4-2 | new | No (B, v3: worst median 122.6 ms, `pposbxiifkdgfiajnbbpvb_dyan_xvz1`; 20 of 22 queries ≤ 77 ms; `i4e1-pilot3-transcript.txt` §4; v2 (order A) 122.2 ms under load ≈ 12) |
| R-A2L-MATCH.37 | E | When the system prepares a name list of 50,000 names for ranking, the system shall hold the prepared list in at most 64 MiB. | the tracemalloc peak during the preparation of the reference list (fixture REF, 50,000 names) ≤ 67,108,864 bytes (64 MiB), on cachyos-rtx, Python 3.11.18; the peak printed in the transcript | the pilot's dict trie (about 137 MiB) → RED | US-I4-2 | new (D-12 A + D, orchestrator ruling) | No (B: the pilot v3 index took about 137 MiB) |

## Edge cases the brief names, and where they live

| Edge case | Rows (cases) |
|---|---|
| empty or whitespace query | R-A2L-MATCH.2 (/1–/5), .1 |
| query longer than any name | no row of its own (D-13 A): the rules decide it — .8/9 (`VALUE_0001_VALUE_0001`, 21 > 16 characters, `token`), .13 and .33 (`measurementss_0001`, 18 characters, `fuzzy` 2 edits) |
| case (ASAP2 names are case-sensitive) | .3, .4 (fold A–Z only), .24 (case-exact first), .25 (code-point order, twins kept apart) |
| duplicate names | .17 |
| non-ASCII | .4 (`Drück_Max` / `DRÜCK_MAX` / `druck_max`), the *letter* definition (a character above U+007F is a letter without case); C: 0 non-ASCII names in 234,654 fixture names |
| `limit` ≤ 0 | .19 |
| names with dots or brackets | .7 (`knife[1]`, `[0].Spoon`, `ledRing[1]`: compared as characters, never as a pattern), .8 (`knife 1 x`, `knife.*`), the *token* definition |
| maximum edit distance per token length | .11 (digits, 1–2 letters: 0), .12 (3–5 letters: 1), .13 (≥ 6 letters: 2) |

## Relation to existing rows (cited, unchanged)

The matcher changes no existing row. The four name or text filters of the base are substring filters and stay as they are: R-A2L-007.1 (A2L Explorer filter: the filter field contains the filter text, ignoring case; `app.py:20494-20519`), R-A2L-090 (Find next; `app.py:16641-16644`), R-CHKED-003 (the parameter picker's Filter, also the Patch Editor's; `a2l_parameter_picker.py:694-700`, `:806-809`) and R-TUI-022.4 (the palette). Their "ignoring case" uses Python's Unicode lowercase; the matcher folds `A`–`Z` only (D-2): the two agree on every fixture name (C: 0 non-ASCII names of 234,654). I-5, the label-list parser (`parse_parameter_list`, `a2l_parameter_picker.py:75`), stays as it is; Inc 7 joins it to the matcher. The av_C prototype's "closest names" of a missing label used `difflib.get_close_matches` (cutoff 0.6; `prototypes/b103_ux/variants/_av_common.py:134`, main clone): not product code and not adopted; Inc 7 uses I-3 instead. Whether the Check Editor filter should later use the matcher is a backlog proposal (BL-I4-1), not this increment.

## Acceptance

The increment has no key or dialog of its own (the UI is Inc 7, whose acceptance tests drive the autocomplete through keys). Its black-box cases run at interface I-3 over real names: **AT-B103-I4-1** — a typing sequence over the 462 case-08 names (`m`, `ma`, `map`, `map_`, `map_00`, `map_002`, `map_0020`), each ranked list exact (US-I4-1); **AT-B103-I4-2** — the operator's words over the 13,990 real-shape names of `software_a.a2l`: one name found from its whole text, its start, its middle, its end, two of its words in either order and a typo, first in each list (US-I4-1). Ids are batch-scoped, letter-initial, outside the registry's authority (`AT-TC-REGISTRY.jsonl` `_meta.governed`), and checked unused (`evidence-e1/i4e1-base-grep.txt`).

## Counts

37 new rows (R-A2L-MATCH.1 … .37), 0 changed, 0 retired; 1 new context note (CTX-A2L-MATCH, proposed for a new subsection S2.8). PLAN estimate: ~25 rows / ~8 nodes; E1: 37 rows / 12 slice nodes (`E1-slice.md`), within the caps (80 / 40).
