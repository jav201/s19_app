# Code-Wire graph — Inc 4 (label similarity matcher, a pure module), batch-103

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree; the one extractor mark (`parse_a2l_file`) sat in a throwaway copy in the session's scratch directory. Base `e07fb00` (worktree branch `batch-103` at `cbe56e6`; `git diff --stat e07fb00 HEAD -- s19_app tests tools` is empty). Requirements `../01-requirements.md` (40 rows, R-A2L-MATCH.1 … .40), cases `../02-test-cases.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md` (its section "Orchestrator rulings" overrides the rows above it: D-1 the two calls, D-2 … D-9, D-11, D-13 as recommended, D-10 S2.8, D-12 A + D). Notation: Code-Wire v3.1.0 (`e436a08`), `docs/Notation-Grammar.md`; layout as batch-101 Inc 12 (`b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/codewire/graph-inc12.md`).

How to read it:
- Every node's `func:` starts with **new** or **unchanged**. The increment adds one file and changes nothing in `e07fb00`; the only unchanged node is `parse_a2l_file`, the reader the tests take their names from.
- Example sources: the case ids of `02-test-cases.md`; `B4` = this stage's pilot (`i4e2-pilot4.py`, `i4e2-pilot4-transcript.txt`: the compact index pinned here, checked against the E1 oracle and the E1 v3 index); `B4a` = its first variant (`i4e2-pilot4-variantA-transcript.txt`: the same index with the fuzzy walk over the bare sorted token list; that walk's code is `walk_sorted` in `i4e2-walk-variants.py`); `X` = `i4e2-examples-transcript.txt` (each private helper against the oracle's definition); `O` = `i4e2-order-examples-transcript.txt` (`_classify` and `_order_key` values); `W` = `i4e2-walk-variants-transcript.txt` (one fuzzy walk, four ways); `B3` = the E1 pilot v3 (`../evidence-e1/i4e1-pilot3-transcript.txt`); `R` = read. **derived** = a value that follows from a row and its definitions but is no case of `02-test-cases.md` (E2-6).
- Results use the notation of `02-test-cases.md`: a ranked list `[entry; entry; …]`, an entry `NAME · rule · (s,e),…`, a fuzzy entry adds `· e<k>`. It stands for `list[LabelMatch]`, each `LabelMatch(name=NAME, rule=MatchRule.<RULE>, edits=k or 0, spans=((s, e), …))`. `rank(q, F)` is `rank(q, build_label_index(F), 20)`; "limit n" replaces the 20. Fixtures C08, C08i, C08r, BAL, SRC, SWB, SWA, TW, TW2, NA, CUR, REF, REF6, QSET, PSET and LONG are those of `02-test-cases.md`. `A` = the E3 addenda probe (`../evidence-e3/addenda-probe.py`, `addenda-{check,time}-transcript.txt`: this procedure with steps 1, 3, 4 and 6 as the addenda rule and the banded `_prefix_distance`, on cachyos-rtx at host load 0.3–0.9). `C5` = the E5 correction probe (`../evidence-e5/corr-e5-posting-probe.py`, `corr-e5-{totals,check,time,mem}-{A,C}-transcript.txt`, on cachyos-rtx against a copy of the integrated tree, `label_match.py` sha256 `24564b32…`): variant C = steps 4 and 6 as pinned below; variant A = step 4 walking every distinct query token with no switch.
- Every run: cachyos-rtx, Python 3.11.18, `s19_app.__file__` = the read-only clone at `e07fb00`, scratch `/tmp/b103-e2-4/` with its own HOME, XDG and LOCALAPPDATA, case 08 generated there (seed 20260001); no clipboard; host load printed in each transcript (0.95 to 1.15 during B4). The scripts on the host and in this folder are byte-identical (sha256 checked).

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns |
|---|---|---|
| G1 matcher (implementer) | `s19_app/tui/services/label_match.py` (new; the increment's only source file, 1 of 4) | every node of `## Nodes` but `parse_a2l_file`; the entities `[Data: MatchRule]`, `[Data: LabelMatch]`, `[Data: LabelIndex]`, `[Data: _Query]` |
| G-T1 (tester) | `tests/test_b103_label_match.py` (new) | the 113 coverage items outside G-T2 and AT-B103-I4-1, -2 of `02-test-cases.md` (115 cases); the I-3 interface checks |
| G-T2 (tester) | `tests/test_b103_label_match_timing.py` (new; the .35/.36/.40 timing tests `@pytest.mark.serial_timing`; the .37 memory test carries none) | R-A2L-MATCH.35/1, .36/1, .37/1, .40/1, .40/2, .40/3 (6 cases; E2-4; .40/3 from the E5 correction, E5S-01) |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-3 the matcher | the code block below; errors and purity under it | G1 → Inc 7 (the A2L Viewer autocomplete and paste modal, after G2); G-T1, G-T2 |
| I-4 load generation | not consumed: the module keeps no state between calls; Inc 7 builds a new index for each A2L load generation | Inc 5 → Inc 7 |
| I-5 label-list parser | not consumed, unchanged (`parse_parameter_list`, `a2l_parameter_picker.py:75`) | existing → Inc 7 |
| `PLAN.md` I-3 row | still reads `rank(query, names, limit)`; ruling D-1 replaced it with the two calls below. The PLAN edit is the orchestrator's (E2-2) | — |

```python
# s19_app/tui/services/label_match.py — headless; imports the standard library only
# (array, bisect, dataclasses, enum, typing); no Textual, no s19_app module, no file I/O.

class MatchRule(str, Enum):              # declaration order = rank order (D-3 B)
    EXACT = "exact"
    PREFIX = "prefix"
    SUBSTRING = "substring"
    TOKEN = "token"
    FUZZY = "fuzzy"
    SUBSEQUENCE = "subsequence"

@dataclass(frozen=True, slots=True)
class LabelMatch:
    name: str                            # the name as listed, case kept
    rule: MatchRule                      # the first rule in rank order the name meets (R-A2L-MATCH.16)
    edits: int                           # FUZZY: the total edits (.33); every other rule: 0
    spans: tuple[tuple[int, int], ...]   # [start, end) offsets into name: the fewest, in offset order (.34)

@dataclass(frozen=True, slots=True, eq=False, repr=False)
class LabelIndex:                        # a prepared name list; built only by build_label_index; never changed after
    names: tuple[str, ...]               # the distinct names, in first-occurrence order (.17)
    # private fields: [Data: LabelIndex] below (not part of I-3)
    def __len__(self) -> int: ...        # len(self.names)

def build_label_index(names: Iterable[str]) -> LabelIndex: ...
def rank(query: str, index: LabelIndex, limit: int) -> list[LabelMatch]: ...
```

Errors (I-3, as `../E1-rulings.md` §5; no operator-visible behaviour, so no row; G-T1 checks them as interface checks):
- `build_label_index`: `TypeError("label names must be str, got <type name>")` for an element that is not a `str` (`<type name>` = `type(element).__name__`); `TypeError("label names must be an iterable of str, got str")` for a `str` or `bytes` argument (E3S-06); an empty iterable gives an empty index.
- `rank`: `TypeError("query must be str, got <type name>")`, checked first; then `TypeError("limit must be int, got <type name>")` for a `limit` that is not an `int` or is a `bool`. For any `str` query and `int` limit it does not raise: limit < 1 → `[]` (.19); no letter or digit → `[]` (.2).
- Pure: the same query, index and limit give an equal list (`LabelMatch` compares by value); neither call changes its arguments. A `LabelIndex` is read-only after the build — no function writes a buffer after the build (E3S-07) — so one index can be shared with a worker thread.

Consumer (Inc 7, informative): build once per A2L load generation (I-4) off the UI thread (1.8 s at 50,000 names on cachyos-rtx, B4 §5); rank per debounced keystroke with the dropdown's free rows as the limit, off the UI thread, dropping stale results. The paste modal splits a pasted list into names and ranks each name with a small limit, never the whole paste as one query (E3S-01); it ranks closest names only for the rows on screen (or the first N missing labels), off the UI thread, and drops the results when the paste changes (E3S-05), in place of the av_C prototype's `difflib.get_close_matches`. Display obligations (E3S-04; rows owed by Inc 7's E1): (1) `name` is plain text — render it with markup off (`markup=False` or `Content(text)`), never through `from_markup`; (2) for display, replace each of U+0000–U+001F and U+007F–U+009F with U+FFFD, one for one, before applying the spans (this keeps the offsets); (3) insert `LabelMatch.name`, never the display text; (4) a suggestion is applied only when the operator chooses it, never automatically in place of a missing label; (5) extend the markup AST guard to Inc 7's files.

Order inside E4: G1, G-T1 and G-T2 in parallel (one source file, two test files). Integration: the extractor run of the E4 notes (marks in a throwaway copy), `EXPECTED_SCANNED_TEST_FILES` re-measured (+2), then the GREEN run.

## Nodes

build_label_index
req: R-A2L-MATCH.17, R-A2L-MATCH.35, R-A2L-MATCH.37, R-A2L-MATCH.39
in: Iterable[str] names
out: LabelIndex index
func: new (D-1 as ruled; I-3). Prepares a name list once: refuses a `str` or `bytes` argument (E3S-06) and an element that is not a `str`; leaves out a name longer than 1,024 characters (R-A2L-MATCH.39); keeps each distinct name once, at its first occurrence; folds each (`_fold`) and sets its character mask (`_char_mask`); cuts each into tokens (`_tokens`), gives every distinct folded token an id in code-point order (stored as a tuple), and stores each name's token ids; builds the postings (token id → the names holding it) and the pre-order array trie of the tokens (`_build_trie`, which needs each token's first 258 characters only). The fields are `[Data: LabelIndex]`: strings, one tuple and flat `array` buffers — no dict trie, no per-name tuple of token strings, no dict of Python lists (the 77.9 MiB of v3; E2-1).
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.17/1, derived) C08i (470 names, `VALUE_0001` twice) → `len(index)` `469`, `index.names` in first-occurrence order (X §G)
examples: (R-A2L-MATCH.35/1) REF (50,000 names) prepared 3 times → median `1.798` s ≤ 5.0 s (1.809, 1.798, 1.735 s; host load 1.09 before, 1.15 after, 16 cores; B4 §5)
examples: (R-A2L-MATCH.35/1 neg) a preparation that computes the fuzzy distance of every pair of name tokens (quadratic) → minutes → RED (the row's control; not run)
examples: (R-A2L-MATCH.37/1) REF prepared once under tracemalloc, nothing else alive → peak `18,940,597` bytes (18.1 MiB) ≤ 67,108,864; `17,496,901` bytes held after the build (B4 §4)
examples: (R-A2L-MATCH.37/1 neg) the pinned index with v3's structures added back — a nested-dict trie of the tokens and a per-name tuple of token strings — on REF → peak `79,390,164` bytes (75.7 MiB) > 67,108,864 → RED (probe 1 §D, probe 3); a one-structure regression (one `array` as a Python list, or the dict trie alone, or the token tuples alone) stays under the bound, so it is not caught at 64 MiB
examples: (B4 §3, W) REF → 50,000 names, `77256` distinct tokens (the same sorted token list as v3's), `177148` trie nodes
examples: (I-3) [`VALUE_0001`, `None`] → TypeError `label names must be str, got NoneType`
examples: (I-3) `build_label_index("VALUE")` → TypeError `label names must be an iterable of str, got str`
examples: (R-A2L-MATCH.39/1) a name of 1,024 characters beside short names → listed for its prefix
examples: (R-A2L-MATCH.39/2) a name of 1,025 characters → left out
examples: (R-A2L-MATCH.39/2 neg) the cap removed → the 1,025-character name is listed → RED
examples: (I-3, derived) `[]` → an index of `len` `0`; any ranking over it → `[]` (X §H)

rank
req: R-A2L-MATCH.1, R-A2L-MATCH.2, R-A2L-MATCH.3, R-A2L-MATCH.4, R-A2L-MATCH.5, R-A2L-MATCH.6, R-A2L-MATCH.7, R-A2L-MATCH.8, R-A2L-MATCH.9, R-A2L-MATCH.10, R-A2L-MATCH.11, R-A2L-MATCH.12, R-A2L-MATCH.13, R-A2L-MATCH.14, R-A2L-MATCH.15, R-A2L-MATCH.16, R-A2L-MATCH.17, R-A2L-MATCH.18, R-A2L-MATCH.19, R-A2L-MATCH.20, R-A2L-MATCH.21, R-A2L-MATCH.22, R-A2L-MATCH.23, R-A2L-MATCH.24, R-A2L-MATCH.25, R-A2L-MATCH.26, R-A2L-MATCH.27, R-A2L-MATCH.28, R-A2L-MATCH.29, R-A2L-MATCH.30, R-A2L-MATCH.31, R-A2L-MATCH.32, R-A2L-MATCH.33, R-A2L-MATCH.34, R-A2L-MATCH.36, R-A2L-MATCH.38, R-A2L-MATCH.40
in: str query; LabelIndex index; int limit
out: list[LabelMatch] matches
func: new (I-3). Ranks the prepared names for one query: type checks, then `[]` for a limit below 1, a stripped query longer than 256 characters (R-A2L-MATCH.38, checked before the parse), or a query with no letter or digit; then the rule tiers in rank order over the index, with the query tokens taken as a multiset (at most one range or table per distinct token, R-A2L-MATCH.40), stopping after the tier at which `limit` names are found; then the order of `_order_key` with case-exactness computed only for the `exact`, `prefix` and `substring` groups it reaches, and each entry with its tier's rule and key and the spans of `_classify` for that rule (no listed name classified again, E5S-01). The procedure is pinned in the note under this node (R-A2L-MATCH.36, .40).
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.1/1) C08, `  VALUE_0001  ` → `[VALUE_0001 · exact · (0,10)]` (B4 §1)
examples: (R-A2L-MATCH.1/2) C08, `\tVALUE_0001\n` → `[VALUE_0001 · exact · (0,10)]`
examples: (R-A2L-MATCH.1/3, .27/3) C08, ` value_000 `, limit 5 → `VALUE_0001` … `VALUE_0005`, each `· prefix · (0,9)`
examples: (R-A2L-MATCH.1/4) C08, U+001C then `VALUE_0001` (U+001C is not one of the six whitespace characters: it stays, a separator) → `[VALUE_0001 · token · (0,5),(6,10)]`; a bare `str.strip()` would make it `exact` → RED (X §G, §H; E2-5)
examples: (R-A2L-MATCH.1, derived) C08, U+00A0 then `VALUE_0001` (above U+007F, so a letter: the query token `\xa0value`) → `[VALUE_0001 · fuzzy · (0,5),(6,10) · e1]` (X §G)
examples: (R-A2L-MATCH.2/1 … /5) C08, ``, `   `, `\t\n`, `_`, `._[]` → `[]` each
examples: (R-A2L-MATCH.2/1 neg) guard removed → `` is a prefix of all 462 names → 462 `prefix` entries → RED
examples: (R-A2L-MATCH.3/1, /2) C08, `value_0001` and `Value_0001` → `[VALUE_0001 · exact · (0,10)]` each
examples: (R-A2L-MATCH.3/3) TW, `rpm` → `[rpm · exact · (0,3); RPM · exact · (0,3); Rpm · exact · (0,3)]`
examples: (R-A2L-MATCH.4/1, .24/3) NA, `drück` → `[Drück_Max · prefix · (0,5); DRÜCK_MAX · fuzzy · (0,5) · e1; druck_max · fuzzy · (0,5) · e1]` (`DRÜCK_MAX` and `druck_max` are both fuzzy, 1 edit, 9 characters, so code-point order puts `DRÜCK_MAX` first; fuzzy names are not case-exact)
examples: (R-A2L-MATCH.4/2) NA, `DRÜCK` → `[DRÜCK_MAX · prefix · (0,5); Drück_Max · fuzzy · (0,5) · e1; druck_max · fuzzy · (0,5) · e1]`
examples: (R-A2L-MATCH.4/3) C08, `VALUE-0001` → `[VALUE_0001 · token · (0,5),(6,10)]`
examples: (R-A2L-MATCH.5/1, .26/1) C08, `VALUE_0001` → `[VALUE_0001 · exact · (0,10)]`
examples: (R-A2L-MATCH.5/2, .26/2) C08, `map_0020` → `[MAP_0020 · exact · (0,8)]`
examples: (R-A2L-MATCH.5/3) TW, `rpm` → 3 entries, each `exact`
examples: (R-A2L-MATCH.6/1, .18/1, .27/1) C08, `value_000`, limit 5 → `VALUE_0001` … `VALUE_0005`, each `· prefix · (0,9)`
examples: (R-A2L-MATCH.6/2, .27/2) C08i, `span` → `[SPAN_OVER_1 · prefix · (0,4); SPAN_OVER_2 · prefix · (0,4)]`
examples: (R-A2L-MATCH.6/3) C08i, `LIMIT` → `[LIMIT_BREAKER · prefix · (0,5)]`
examples: (R-A2L-MATCH.7/1, .14/2, .18/2, .23/1, .25/1, .28/2) C08, `0001` (limit 20 or 100) → `[MAP_0001 · substring · (4,8); ASCII_0001 · substring · (6,10); CURVE_0001 · substring · (6,10); VALUE_0001 · substring · (6,10); VAL_BLK_0001 · substring · (8,12); MEASUREMENT_0001 · substring · (12,16)]`
examples: (R-A2L-MATCH.7/2) SRC, `knife[1]` → `[parameter_instance[0].Knife[1].x · substring · (22,30); parameter_instance[1].Knife[1].x · substring · (22,30); parameter_instance[2].Knife[1].x · substring · (22,30); parameter_instance[3].Knife[1].x · substring · (22,30); parameter_instance[1].Knife[0].x · token · (19,20),(22,27)]`
examples: (R-A2L-MATCH.7/3) SRC, `[0].Spoon` → `[parameter_instance[0].Spoon.x · substring · (18,27)]`
examples: (R-A2L-MATCH.7/4) BAL, `ledRing[1]`, limit 4 → `[model.Signals.ledRing[1].red · substring · (14,24); model.Signals.ledRing[1].blue · substring · (14,24); model.Signals.ledRing[1].green · substring · (14,24); model.MainClass.ledController.ledRing[1].red · substring · (30,40)]`
examples: (R-A2L-MATCH.8/1, .30/1, .34/2) C08, `blk val 00`, limit 3 → `VAL_BLK_0001`, `VAL_BLK_0002`, `VAL_BLK_0003`, each `· token · (0,3),(4,7),(8,10)`
examples: (R-A2L-MATCH.8/2) BAL, `stop watch` → `[model.MainClass.gameController.stopWatch.timeCounter · token · (31,40)]`
examples: (R-A2L-MATCH.8/3, .20/3) SWB, `oks ahw` → `[LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy · token · (19,25); AwsQdc.VXAO_CSP_KH.NkshfehlTcyfkjea_IPNR · fuzzy · (0,3),(19,27) · e2; OotGyt.FmcP_UGL_SgvHhu_MME_GEH_kdfba.VsvL_BILR_GtnWga_HGW_RKK_eroog · subsequence · (0,1),(31,32),(38,39),(52,53),(54,55),(56,57)]`
examples: (R-A2L-MATCH.8/4, .30/2) SRC, `knife 1 x` → `[parameter_instance[0].Knife[1].x · token · (22,27),(28,29),(31,32); parameter_instance[1].Knife[0].x · token · (19,20),(22,27),(31,32); parameter_instance[1].Knife[1].x · token · (19,20),(22,27),(31,32); parameter_instance[2].Knife[1].x · token · (22,27),(28,29),(31,32); parameter_instance[3].Knife[1].x · token · (22,27),(28,29),(31,32)]`
examples: (R-A2L-MATCH.8/5) C08i, `out range` → `OUT_OF_RANGE_1`, `OUT_OF_RANGE_2`, `OUT_OF_RANGE_3`, each `· token · (0,3),(7,12)`
examples: (R-A2L-MATCH.8/6) SRC, `knife.*`, limit 4 → `parameter_instance[0].Knife[0].x`, `parameter_instance[0].Knife[1].x`, `parameter_instance[1].Knife[0].x`, `parameter_instance[1].Knife[1].x`, each `· token · (22,27)`
examples: (R-A2L-MATCH.8/7, .30/3, .34/3) CUR, `a value` → `[AValue · token · (0,6); ABSValue · token · (0,1),(3,8)]`
examples: (R-A2L-MATCH.8/8) CUR, `map 3 d` → `[Map3D · token · (0,5)]`
examples: (R-A2L-MATCH.8/9) C08, `VALUE_0001_VALUE_0001` (21 characters, longer than every name) → `[VALUE_0001 · token · (0,5),(6,10)]`
examples: (R-A2L-MATCH.9/1, .31/1) C08, `mp`, limit 3 → `MAP_0001`, `MAP_0002`, `MAP_0003`, each `· subsequence · (0,1),(2,3)`
examples: (R-A2L-MATCH.9/2) C08, `ascii 1` → `[ASCII_0001 · subsequence · (0,5),(9,10); ASCII_0010 · subsequence · (0,5),(8,9)]`
examples: (R-A2L-MATCH.9/3) C08, `map 20` → `[MAP_0020 · subsequence · (0,3),(6,8)]`
examples: (R-A2L-MATCH.9/4, .31/3) BAL, `gamecontroller timer`, limit 3 → `[model.MainClass.gameController.timer.timeCounter · subsequence · (16,30),(31,36); model.MainClass.gameController.stopWatch.timeCounter · subsequence · (16,30),(32,33),(42,45),(51,52)]`
examples: (R-A2L-MATCH.10/1, .12/2) C08, `cuvre`, limit 3 → `CURVE_0001`, `CURVE_0002`, `CURVE_0003`, each `· fuzzy · (0,5) · e1`
examples: (R-A2L-MATCH.10/2, .33/1) C08, `maesurement_0001` → `[MEASUREMENT_0001 · fuzzy · (0,11),(12,16) · e1]`
examples: (R-A2L-MATCH.10/3) C08, `vlaue_0001` → `[VALUE_0001 · fuzzy · (0,5),(6,10) · e1]`
examples: (R-A2L-MATCH.10/4, /5, /6, .12/1) C08, `mpa`, `xmap`, `maq`, limit 3 each → `MAP_0001`, `MAP_0002`, `MAP_0003`, each `· fuzzy · (0,3) · e1`
examples: (R-A2L-MATCH.11/1) C08, `VALUE_0300` → `[]`
examples: (R-A2L-MATCH.11/2, /3) [`BA_X`], `ab`; [`abc`], `ca` → `[]` each
examples: (R-A2L-MATCH.12/3) C08, `cvure` → `[]`
examples: (R-A2L-MATCH.13/1) C08, `valuexx_0001` → `[VALUE_0001 · fuzzy · (0,5),(6,10) · e2]`
examples: (R-A2L-MATCH.13/2) C08, `valuexxx_0001` → `[]`
examples: (R-A2L-MATCH.13/3, .22/1) [`CUVE`, `CURVE_0001`], `curvee` → `[CURVE_0001 · fuzzy · (0,5) · e1; CUVE · fuzzy · (0,4) · e2]`
examples: (R-A2L-MATCH.13/4) C08, `crxuve` → `[]` (the optimal-string-alignment prefix distance is 3 > 2; the unrestricted Damerau-Levenshtein distance is 2, so its 20 `CURVE` entries, fuzzy, 2 edits → RED)
examples: (R-A2L-MATCH.14/1, .20/1) C08, `value_000`, limit 100 → exactly 20 entries: `VALUE_0001` … `VALUE_0009` `· prefix · (0,9)`; then `VALUE_0010`, `VALUE_0020` … `VALUE_0090` `· subsequence · (0,5),(6,8),(9,10)`; then `VALUE_0100`, `VALUE_0200` `· subsequence · (0,5),(6,7),(8,10)`
examples: (R-A2L-MATCH.14/1 neg) the subsequence tier left out → `9` entries → RED
examples: (R-A2L-MATCH.15/1) C08, `temp_sensor_max` → `[]`
examples: (R-A2L-MATCH.15/2) [``, `   `, `VALUE_0001`], `v` → `[VALUE_0001 · prefix · (0,1)]`
examples: (R-A2L-MATCH.16/1, .18/3) C08, `value_000`, limit 1 → `[VALUE_0001 · prefix · (0,9)]`
examples: (R-A2L-MATCH.16/2, .32/2) C08, `valu_0001` → `[VALUE_0001 · token · (0,4),(6,10); VAL_BLK_0001 · fuzzy · (0,3),(8,12) · e1]`
examples: (R-A2L-MATCH.16/3) C08, `vale_0001` → `[VALUE_0001 · fuzzy · (0,5),(6,10) · e1; VAL_BLK_0001 · fuzzy · (0,3),(8,12) · e1]`
examples: (R-A2L-MATCH.17/1) C08i, `VALUE_0001` → `[VALUE_0001 · exact · (0,10)]`
examples: (R-A2L-MATCH.17/2) C08i, `value_000` → the 20 entries of R-A2L-MATCH.14/1, `VALUE_0001` once
examples: (R-A2L-MATCH.18/1 neg) limit ignored → 20 entries for limit 5 → RED
examples: (R-A2L-MATCH.19/1, /2) C08, `VALUE`, limit `0` and limit `-1` → `[]` each
examples: (R-A2L-MATCH.19/2 neg) a slice `[:limit]` → limit -1 returns all but the last listed name → RED
examples: (R-A2L-MATCH.20/2) BAL, `gamecontroller.timer` → `[model.MainClass.gameController.timer.timeCounter · substring · (16,36); model.MainClass.gameController.stopWatch.timeCounter · subsequence · (16,30),(32,33),(42,45),(51,52)]`
examples: (R-A2L-MATCH.21/1) [`timeCounter`, `Encounter`], `counter` → `[timeCounter · substring · (4,11); Encounter · substring · (2,9)]`
examples: (R-A2L-MATCH.21/2) C08, `_0001` → `[MAP_0001 · substring · (3,8); ASCII_0001 · substring · (5,10); CURVE_0001 · substring · (5,10); VALUE_0001 · substring · (5,10); VAL_BLK_0001 · substring · (7,12); MEASUREMENT_0001 · substring · (11,16)]`
examples: (R-A2L-MATCH.21/3, .29/1) BAL, `ounter`, limit 4 → `[model.MainClass.ledController.sw.timeCounter · substring · (38,44); model.MainClass.gameController.timer.timeCounter · substring · (42,48); model.MainClass.gameController.stopWatch.timeCounter · substring · (46,52)]`
examples: (R-A2L-MATCH.23/2) [`rpm_x`, `RPMX`], `rpm` → `[RPMX · prefix · (0,3); rpm_x · prefix · (0,3)]`
examples: (R-A2L-MATCH.24/1) TW, `rpm` → entry 1 `rpm`
examples: (R-A2L-MATCH.24/2) TW, `RPM` → `[RPM · exact · (0,3); Rpm · exact · (0,3); rpm · exact · (0,3)]`
examples: (R-A2L-MATCH.24/4) [`DiscouNTCount`, `DiscountCount`], `count` → `[DiscountCount · substring · (8,13); DiscouNTCount · substring · (8,13)]` (the raw `count` occurs in `DiscountCount` at offset 3, inside a token, so it is case-exact; A check)
examples: (R-A2L-MATCH.24/4 neg) `substring` case-exact only for a raw occurrence at a boundary offset → `[DiscouNTCount …; DiscountCount …]` → RED (A check; E3A-12, E3S-10)
examples: (R-A2L-MATCH.25/2) C08r, `0001` → the 6 entries of R-A2L-MATCH.7/1, in the same order
examples: (R-A2L-MATCH.25/3) TW2, `rpm` → `[rpm · exact · (0,3); RPM · exact · (0,3); Rpm · exact · (0,3)]`
examples: (R-A2L-MATCH.28/1) [`DiscountCount`], `count` → `[DiscountCount · substring · (8,13)]`
examples: (R-A2L-MATCH.29/2) SWB, `sahw` → entry 1 `LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy · substring · (21,25)`
examples: (R-A2L-MATCH.31/2) C08, `value_000` → `VALUE_0010`'s spans `(0,5),(6,8),(9,10)`
examples: (R-A2L-MATCH.32/1) C08, `maesu`, limit 3 → `MEASUREMENT_0001`, `MEASUREMENT_0002`, `MEASUREMENT_0003`, each `· fuzzy · (0,11) · e1`
examples: (R-A2L-MATCH.32/3) C08, `vblk`, limit 2 → `[VAL_BLK_0001 · fuzzy · (4,7) · e1; VAL_BLK_0002 · fuzzy · (4,7) · e1]`
examples: (R-A2L-MATCH.33/2) C08, `measurementss_0001` (18 characters, longer than every name) → `[MEASUREMENT_0001 · fuzzy · (0,11),(12,16) · e2]`
examples: (R-A2L-MATCH.33/3) [`Curve_Map_X`], `cuvre maq` → `[Curve_Map_X · fuzzy · (0,5),(6,9) · e2]`
examples: (R-A2L-MATCH.34/1) CUR, `abs value` → `[ABSValue · token · (0,8)]`
examples: (R-A2L-MATCH.38/1) C08, `'VALUE_0001_' * 23 + 'VAL'` (256 characters) → `[VALUE_0001 · token · (0,5),(6,10)]`
examples: (R-A2L-MATCH.38/2) C08, `'VALUE_0001_' * 23 + 'VALU'` (257 characters) → `[]`
examples: (R-A2L-MATCH.38/2 neg) the cap removed → the 257-character query lists `VALUE_0001` → RED
examples: (R-A2L-MATCH.36/1) REF and REF6 prepared once; each of QSET's 33 queries over REF and each of REF6's 12 queries over REF6, limit 20, ranked 7 times → worst median `66.4` ms on REF (`a` × 256) and `78.4` ms on REF6 (`0`) ≤ 200 ms (A, host load 0.7; `addenda-time-transcript.txt`). Before the collapse, round 2 measured `110.0` ms on REF (`e ` × 128, now 7.0 ms) and `78.5` ms on REF6 (`arch-r2-time-transcript.txt:69`, `:91`; the v3 index: 122.6 ms, B3 §4; the sorted-list variant: 158.3 ms, B4a §5)
examples: (R-A2L-MATCH.36/1 neg) no preparation (every ranking reads the 50,000 names with the oracle) → 9.15 s for one query (E1 v1) → RED; a map for every query token before the candidate check (the E2 tier) → 296.8 ms → RED; case-exactness by a raw re-classification of every member of the group at the cut → `mesa` ≈ 700 ms → RED
examples: (R-A2L-MATCH.40/1) REF and REF6 prepared once; each PSET query over its list, limit 20, ranked 7 times → worst median `121.5` ms on REF (`qza` … `qzz` 3×, cut at 256) and `461.7` ms on REF6 (64 near tokens of `char`, 62 distinct: the collapse does not shorten them) ≤ 1.0 s; `0 ` × 125 + `chax` `56.4` ms, `chr ` × 64 `45.6` ms (A, host load 0.7–0.8)
examples: (R-A2L-MATCH.40/1 neg) a range or map per query token occurrence (no collapse) → REF6 `0 ` × 125 + `chax` `1,136.9` ms > 1.0 s → RED (A; round 2: 1,141–1,350 ms, `sec-r2-dedupe-transcript.txt`); `0 ` × 128 takes only `309.4` ms without the collapse, so it is no control for 1.0 s
examples: (R-A2L-MATCH.40/2) LONG prepared once; `'a' * 255 + 'b'`, `'a' * 254 + 'bb'`, `'a' * 128 + 'b'`, limit 20, ranked 7 times → 20 entries `fuzzy` e1, e2, e1; worst median `77.5` ms ≤ 1.0 s (A, banded `_prefix_distance`)
examples: (R-A2L-MATCH.40/2 neg, E3; superseded by the E5 correction) `_prefix_distance` without the band → `1,534.6` ms for `'a' * 255 + 'b'` → RED (A; round 2: 1.45–1.48 s on 125–200 names, `sec-r2-band-transcript.txt`), while step 6 re-scored each listed name; after the correction LONG's one-token queries are walked and never reach `_prefix_distance`
examples: (R-A2L-MATCH.40/2, C5) the same three LONG queries with steps 4 and 6 as pinned → worst median `59.0` ms (`corr-e5-time-C-transcript.txt`)
examples: (R-A2L-MATCH.40/3, C5) CRAFT prepared once; the 4-token and the 51-token query, limit 20, ranked 7 times → 20 entries `fuzzy` each (51 tokens: e50 each, `corr-e5-check-C-transcript.txt`); medians `29.6` ms and `232.7` ms ≤ 1.0 s, 0 `_prefix_distance` calls (host load 1.0–1.1; `corr-e5-time-C-transcript.txt`); 8, 16 and 32 tokens `44.6`, `77.7`, `150.0` ms; one 51-token ranking peaks at 0.2 MiB under tracemalloc (464.0 MiB before the correction; REF6 `near tokens` 12.9 MiB; `corr-e5-mem-C-transcript.txt`)
examples: (R-A2L-MATCH.40/3 neg) the per-candidate check restored (the E3 step 4: at most 300 candidates, then each remaining query token against every token of each candidate) → 51 tokens `16,713.7` ms, 3,530,910 `_prefix_distance` calls → RED (C5; 15.8 s and 464 MiB in `sec-e5-adv-transcript.txt`); the 4-token query takes `970`–`1,029` ms, so it is no reliable control
examples: (R-A2L-MATCH.40, C5, derived) the switch: 1 crafted name (268 token occurrences ≤ 512) among 49,999 REF names, the 51-token query → the table of each remaining token from its 268 token ids, 13,400 `_prefix_distance` calls, `66.2` ms; 2,000 crafted names whose junk repeats (48,000 REF names; the map path of the E3 step 4: 2,495.7 ms) → `297.7` ms; walking every distinct token with no switch (variant A) → QSET `njraipjtbtu lsuakcoj …` `264.0` ms > .36's 200 ms → RED for .36, which is why the switch stays
examples: (R-A2L-MATCH.40, C5, derived) CRAFT, the subsequence shape (`987654` + 25 tokens, each a hit plus the next hit's first letter, + `eeeeeee`; 139 characters) → 20 `subsequence` entries, `158.6` ms with no `_prefix_distance` call; the integrated `rank` (per-candidate check, then `_classify` re-scoring each listed name up to its FUZZY branch) → `8,795.0` ms, 1,838,646 calls → RED on the 1.0 s bound
examples: (R-A2L-MATCH.33, .40, derived) C08, `cuvre cuvre`, limit 2 → `[CURVE_0001 · fuzzy · (0,5) · e2; CURVE_0002 · fuzzy · (0,5) · e2]`: a repeated query token adds its edits once per occurrence, so the collapse keeps every list (`arch-r2-adv2-transcript.txt:30-31`; A check: 0 differences from the round-2 procedure on 77 REF, REF6 and LONG queries, 0 mismatches against the oracle on 3 fixtures × 35 queries × 3 limits)
examples: (AT-B103-I4-1) C08, limit 5, `m`, `ma`, `map`, `map_`, `map_00` in turn on one index → `MAP_0001` … `MAP_0005`, each `· prefix · (0,k)`, k = 1, 2, 3, 4, 6; `map_002` → `[MAP_0020 · prefix · (0,7); MAP_0002 · subsequence · (0,3),(4,6),(7,8); MAP_0012 · subsequence · (0,3),(4,6),(7,8)]`; `map_0020` → `[MAP_0020 · exact · (0,8)]` (B4 §1)
examples: (AT-B103-I4-2) SWA, limit 5, target `JotafVod_msrqlLzL_kh2C_rWl_pfue._0_` → entry 1 is the target for each query: the target `exact (0,35)`, `jotafvod` `prefix (0,8)`, `msrqlLzL` `substring (9,17)`, `pfue._0_` `substring (27,35)`, `jotaf vod` and `vod jotaf` `token (0,8)`, `jotfa vod` and `jotaf_vdo` `fuzzy (0,8) e1` (B4 §1, target position 0 for all 8)
examples: (purity, derived) the same query, index and limit twice → equal lists; the list passed to `build_label_index` unchanged (X §G)
examples: (I-3) `rank(None, index, 20)` → TypeError `query must be str, got NoneType`; `rank("VALUE", index, True)` → TypeError `limit must be int, got bool`; `rank("VALUE", index, 2.0)` → TypeError `limit must be int, got float`

### rank — the procedure pinned for R-A2L-MATCH.36 and .40 (0 mismatches against the E1 oracle and the v3 index; step 4 and step 6 as E3A-01/E3A-02/E3S-01 ruled; steps 1, 3, 4 and 6 as the E3 addenda A-1, A-2 and A-4 rule; steps 4 and 6 as the E5 correction pins, E5S-01: C5 variant C equals the integrated `rank` on 364 rankings)
1. Type checks (I-3); `limit < 1` → `[]`; strip the six whitespace characters; the stripped query longer than 256 characters → `[]` (R-A2L-MATCH.38), before any fold or tokenising (E3A-16, E3S-13); then `q = _parse_query(query)`; `None` → `[]`; keep the raw stripped query for step 6.
2. Text tiers, one pass over `_folded`: a name that contains `q.text` is EXACT (equal), PREFIX (starts with it) or SUBSTRING; a SUBSTRING name's key is 0 when `_at_boundary(name, p)` holds for an occurrence `p` (`str.find` on the folded name, from left to right), else 1.
3. Fewer than `limit` so far → TOKEN, with the query tokens as a multiset (A-2): one `_token_range(_tokens, qt)` per distinct query token; an empty range → no TOKEN name; else the names = the postings of the range with the fewest postings, intersected (as sets) with the postings of each other range, minus the names already found.
4. Still fewer → FUZZY, with the query tokens as a multiset (A-2), pinned by the E5 correction (E5S-01; the posting variant, C5 variant C): take one distinct query token `qt` at a time in ascending `_allowed_edits` (0, then 1, then 2; ties in query order) and make its *table* `{token id: prefix distance ≤ allowed}`, kept for step 6. The table is the walk `_fuzzy_token_distances(index, qt, allowed)` — the **switch** excepted: once at most 512 candidates remain and they hold at most 512 name-token occurrences in all (counted from `_name_token_starts`), the table of each remaining distinct token is made instead from those candidates' token ids only, one `_prefix_distance(qt, token, allowed)` per (query token, token id), keeping the ids within `allowed`. From each table, by postings: for d = 0 … allowed, the names that hold a token id at distance d (the union of its ids' postings); each name keeps the smallest such d. The candidates = those names minus the names already found, for the first token; intersected with them, for each next token; an empty table or an empty candidate set → no FUZZY name (stop). The candidates left are FUZZY; a candidate's key (total edits) = the sum over the distinct query tokens of its smallest d times the token's count in the query (a repeated token counts its edits once per occurrence, as R-A2L-MATCH.33's sum over the query tokens says). The cost of a walked token is its walk and its table's postings, never candidates × name tokens; after the switch, at most 512 occurrences per remaining distinct token. Without the switch (C5 variant A, a walk for every distinct token) QSET's multi-word query `njraipjtbtu lsuakcoj …` takes 264.0 ms, above R-A2L-MATCH.36's 200 ms (its negative control, the E2 tier; `corr-e5-time-A-transcript.txt`); with the E3 switch (at most 300 candidates, then a per-candidate check against every name token) CRAFT's 51-token query takes 16.0 s (R-A2L-MATCH.40/3 neg).
5. Still fewer → SUBSEQUENCE: each name not yet found whose `_masks` entry holds every bit of `_char_mask(q.keys)` and for which `_subsequence(q.keys, folded name)` is not `None`.
6. Order and cut: group the names found by the first three parts of `_order_key` (rule, key, length) and take the groups in order; in a group whose rule is `exact`, `prefix` or `substring`, a name is case-exact when its rule still holds on the raw stripped query (`==`, `startswith`, or `in`; for `substring` an occurrence at any offset, A-1), and a name listed with any other rule is not case-exact (CTX case-exact, as ruled); sort the group by the last two parts; emit `LabelMatch(name, rule, edits, spans)` until `limit` entries, with the group's rule, edits = the group's key for FUZZY (else 0) and spans = `_classify(q, name, rule, the name's token ids, the step-4 tables)`. No listed name is classified again (E5 correction, E5S-01 (b)): the rule and the key are its tier's, `_classify` computes only that rule's spans, and step 6 calls no `_prefix_distance`; a name that does not meet its tier's rule raises (a defect of the tiers, never a skipped entry).
Helpers called only by `rank` for one tier may stay unmarked (the extractor lifts calls through them); any other new function is a deviation to record.

LabelIndex.__len__
req: R-A2L-MATCH.17
in:
out: int count
func: new (I-3). The number of distinct names the index holds: `len(self.names)`.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.17/1, derived) `build_label_index(C08i)` → `469` (X §G)
examples: (derived) `build_label_index([])` → `0` (X §H); `build_label_index(REF)` → `50000` (B4 §3)

_fold
req: R-A2L-MATCH.3, R-A2L-MATCH.4
in: str text
out: str folded
func: new (D-2 A). `A`–`Z` (U+0041 … U+005A) → `a`–`z`; every other character kept, so the result is as long as `text` and spans index the name directly. `str.translate` with a 26-entry table; never `str.lower` or `str.casefold` (Unicode tables, version-dependent).
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.3/1) `VALUE_0001` → `value_0001`
examples: (R-A2L-MATCH.4/1) `DRÜCK_MAX` → `drÜck_max` (`Ü` kept; `drück` is 1 edit from the token `drÜck`, X §C), so `DRÜCK_MAX` is `fuzzy` for `drück`, not `prefix` (B4 §1)
examples: (R-A2L-MATCH.4/1 neg) `str.lower` → `drück_max` → `DRÜCK_MAX` becomes `prefix` for `drück` → RED

_char_mask
req: R-A2L-MATCH.9, R-A2L-MATCH.36
in: str text
out: int mask
func: new. The OR of one bit per character of an already folded `text`: `a`–`z` → bits 0–25, `0`–`9` → bits 26–35, any other character `c` → bit `36 + ord(c) % 27` (at most 62, so a mask fits `array('Q')`). A name holds the key characters in order only if its mask holds every bit of the keys' mask; a shared bit lets more names through to `_subsequence`, never fewer.
module: s19_app/tui/services/label_match.py
examples: (X §H) `map_0001` → `1125900108206081` (bits of `a`, `m`, `p`, `0`, `1`, and `_` → bit 50)
examples: (R-A2L-MATCH.9/1, X §H) keys `mp` → `36864`; `36864 & ~1125900108206081` → `0`, so `MAP_0001` goes on to `_subsequence`; keys `mpz` → `33591296`, `& ~` → `33554432` (no `z`), so it is skipped

_tokens
req: R-A2L-MATCH.8, R-A2L-MATCH.10, R-A2L-MATCH.21, R-A2L-MATCH.28, R-A2L-MATCH.29, R-A2L-MATCH.30, R-A2L-MATCH.32
in: str text
out: tuple[tuple[int, int], ...] spans
func: new. The [start, end) spans of the CTX-A2L-MATCH *tokens* of `text`, read on the unfolded text (the case cuts need the case): a token starts at each offset that is not a separator and where `_at_boundary` holds, and runs up to the next separator or the next such offset (the cut rules are written once, in `_at_boundary`; E3A-08). Classes by code point, never `str.isalpha`, `isdigit` or `isalnum` (E2-5).
module: s19_app/tui/services/label_match.py
examples: (CTX-A2L-MATCH *token*, X §A) `VAL_BLK_0001` → `((0, 3), (4, 7), (8, 12))`
examples: (X §A) `model.MainClass.ledRing[0].red` → `((0, 5), (6, 10), (10, 15), (16, 19), (19, 23), (24, 25), (27, 30))` (model · Main · Class · led · Ring · 0 · red)
examples: (X §A) `ABSValue` → `((0, 3), (3, 8))`; `AValue` → `((0, 1), (1, 6))`; `Map3D` → `((0, 3), (3, 4), (4, 5))`
examples: (X §A) `LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy` → `((0, 3), (3, 6), (7, 11), (12, 15), (16, 18), (19, 22), (22, 33))`
examples: (X §A) `Drück_Max` → `((0, 5), (6, 9))`; `JVmL` → `((0, 1), (1, 3), (3, 4))` (J · Vm · L)
examples: (X §A) `___` → `()`; `` → `()`
examples: (derived, X §A, §H) U+00A0 then `VALUE_0001` → `((0, 6), (7, 11))` (U+00A0 is a letter); U+001C then `VALUE_0001` → `((1, 6), (7, 11))` (U+001C is a separator); three U+0663 → `((0, 3),)` (one letter token)

_allowed_edits
req: R-A2L-MATCH.11, R-A2L-MATCH.12, R-A2L-MATCH.13
in: str token
out: int allowed
func: new (D-4 A). 0 for a token of digits (its first character is `0`–`9`: tokens are pure runs) or of 1 or 2 letters; 1 for 3 to 5 letters; 2 for 6 or more.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.11, X §B) `0300` → `0`; `1` → `0`; `ab` → `0`; `x` → `0`
examples: (R-A2L-MATCH.12, X §B) `maq` → `1`; `cuvre` → `1`; `drück` → `1`
examples: (R-A2L-MATCH.13, X §B) `valuexx` → `2`; `curvee` → `2`; `measurementss` → `2`
examples: (derived, X §H) three U+0663 → `1` (three letters by CTX-A2L-MATCH; `str.isdigit()` says `True`, which would give 0: E2-5)
examples: (R-A2L-MATCH.12/4) `٣٣٤` → `1` (three letters by CTX-A2L-MATCH; `str.isdigit()` says `True`, which would give 0 and `[]` → RED)
examples: (R-A2L-MATCH.11/1 neg) 1 edit for a digit token → `VALUE_0300` lists `VALUE_0200` → RED

_prefix_distance
req: R-A2L-MATCH.10, R-A2L-MATCH.12, R-A2L-MATCH.13, R-A2L-MATCH.32, R-A2L-MATCH.33, R-A2L-MATCH.40
in: str query_token; str name_token; int cap
out: int distance
func: new (D-5 A). The smallest optimal-string-alignment distance between `query_token` and a prefix of `name_token` (the empty prefix included) when it is at most `cap`, else `cap + 1`; computed only on the band |i − j| ≤ `cap` of the alignment (as `_fuzzy_token_distances` does), so one call costs at most (2 × `cap` + 1) cells per query character, never query-token length × name-token length (A-3, E3S-11); it may stop as soon as a whole column of the alignment is above `cap`. Characters compare as given, both folded. Used only by `rank` step 4 after its switch, on the remaining candidates' token ids (at most 512 token occurrences per remaining distinct query token; E5 correction, E5S-01), never in step 6; `_fuzzy_token_distances` gives the same values for many tokens at once.
module: s19_app/tui/services/label_match.py
examples: (CTX-A2L-MATCH *prefix distance*, X §C) `cuvre`, `curve` → `1`; `valuee`, `value` → `1`; `value`, `val` → `2` (cap 2)
examples: (R-A2L-MATCH.10/4 … /6, X §C) `mpa`, `map` → `1`; `xmap`, `map` → `1`; `maq`, `map` → `1` (cap 1)
examples: (R-A2L-MATCH.12/3, X §C, §H) `cvure`, `curve`, cap 1 → `2` (= cap + 1; the distance is 2)
examples: (R-A2L-MATCH.13/4, X §C) `crxuve`, `curve`, cap 2 → `3` (the optimal-string-alignment prefix distance; the unrestricted Damerau-Levenshtein distance is 2, which would list 20 `CURVE` entries → RED)
examples: (R-A2L-MATCH.32/1, X §C) `maesu`, `measurement`, cap 1 → `1`
examples: (R-A2L-MATCH.13/1, /2, X §C, §H) `valuexx`, `value`, cap 2 → `2`; `valuexxx`, `value`, cap 2 → `3`
examples: (R-A2L-MATCH.11/3, X §C) `ca`, `abc` → `1` (the prefix `a`)
examples: (R-A2L-MATCH.10/1 neg) plain Levenshtein → `cuvre`, `curve` → `2` → RED
examples: (R-A2L-MATCH.40/2, A-3) `'a' * 255 + 'b'`, `'a' * 1000`, cap 2 → `1` (the band visits at most 5 cells per row; A check: the banded and the full alignment agree on 20,000 random pairs, cap 0–2)
examples: (R-A2L-MATCH.40/2 neg, E3; superseded by the E5 correction) the full alignment (no band) → about 256 × 1,020 cells per listed LONG name → `1,534.6` ms for one ranking → RED, while `_classify` re-scored each listed name; after the correction a one-token query is walked and never reaches `_prefix_distance` (derived from step 4), so this mutant no longer turns .40/2 RED

_join_spans
req: R-A2L-MATCH.34
in: list[tuple[int, int]] spans
out: tuple[tuple[int, int], ...] joined
func: new. The fewest spans in offset order that cover the same offsets: sort, then join each span that starts at or before the end of the one before it.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.34/2, X §D) `[(4, 7), (0, 3), (8, 10)]` → `((0, 3), (4, 7), (8, 10))`
examples: (R-A2L-MATCH.34/1, X §D) `[(0, 3), (3, 8)]` → `((0, 8),)`
examples: (R-A2L-MATCH.34/3, X §D) `[(0, 1), (1, 6)]` → `((0, 6),)`; `[(0, 1), (3, 8)]` → `((0, 1), (3, 8))`
examples: (R-A2L-MATCH.31/2, X §D) the eight one-character spans of `value_000` on `VALUE_0010` → `((0, 5), (6, 8), (9, 10))`
examples: (R-A2L-MATCH.34/1 neg) touching spans kept apart → `((0, 3), (3, 8))` → RED

_at_boundary
req: R-A2L-MATCH.21, R-A2L-MATCH.28, R-A2L-MATCH.29
in: str name; int offset
out: bool boundary
func: new (in place of v3's per-name boundary bitmask; E2-1). Whether `offset` of `name` is a CTX-A2L-MATCH *boundary offset*: offset 0; a separator; or the first offset of a token, read on the unfolded name from its neighbours — the character before is a separator; one of the two is a digit and the other a letter; a lowercase letter then an uppercase one; or an uppercase letter before an uppercase letter that a lowercase letter follows. This is the single source of the token cut rules (`_tokens` derives from it; E3A-08).
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.28/1, X §E) `DiscountCount`, `3` → `False`; `DiscountCount`, `8` → `True`
examples: (R-A2L-MATCH.21/2, X §E) `MAP_0001`, `3` (the `_`) → `True`; `4` → `True`; `5` → `False`
examples: (R-A2L-MATCH.21/1, X §E) `timeCounter`, `4` → `True`; `Encounter`, `2` → `False`
examples: (X §E) `ABSValue`, `2` → `False`; `ABSValue`, `3` → `True`; `Map3D`, `3` and `4` → `True`
examples: (R-A2L-MATCH.29/1, /2, X §E) `model.MainClass.ledController.sw.timeCounter`, `38` → `False`; `LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy`, `21` → `False`, `22` → `True`
examples: (X §E) every offset of every name of C08, C08i, SRC, BAL, SWB, SWA and six more (`572,421` offsets) → equal to the oracle's boundary set (from `_tokens` and the separators): `0` disagreements

_subsequence
req: R-A2L-MATCH.9, R-A2L-MATCH.31
in: str keys; str text
out: tuple[int, ...]? offsets
func: new. The leftmost offsets of the key characters in `text`, each after the one before (`str.find` from the previous offset + 1), or `None` when one is missing.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.9/1, .31/1, derived from the spans of B4 §1) `mp`, `map_0001` → `(0, 2)`, spans `(0,1),(2,3)`
examples: (R-A2L-MATCH.9/3, derived from O) `map20`, `map_0020` → `(0, 1, 2, 6, 7)`, spans `(0,3),(6,8)`
examples: (R-A2L-MATCH.31/2, derived from X §D) `value000`, `value_0010` → `(0, 1, 2, 3, 4, 6, 7, 9)`
examples: (derived) `mpz`, `map_0001` → `None`
examples: (R-A2L-MATCH.31/3 neg) each key at its rightmost possible offset → other spans on the BalanceTube name → RED

_parse_query
req: R-A2L-MATCH.1, R-A2L-MATCH.2, R-A2L-MATCH.3, R-A2L-MATCH.8
in: str query
out: _Query? parsed
func: new. Strips exactly the six CTX-A2L-MATCH whitespace characters (space, tab, line feed, carriage return, vertical tab, form feed) from both ends — never a bare `str.strip()`, which also strips U+001C … U+001F, U+0085, U+00A0 and others (E2-5); `None` when what is left holds no letter or digit; else `[Data: _Query]`: `text` = the stripped query, folded by `_fold`; `tokens` = the `_tokens` spans of the stripped (unfolded) query, each token string folded; `keys` = the letters and digits of `text`, in order. `rank` keeps the stripped-but-unfolded query for case-exactness (step 6), the strip before `_fold`.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.1/1) `  VALUE_0001  ` → text `value_0001`, tokens (`value`, `0001`), keys `value0001`
examples: (R-A2L-MATCH.2/1, /2, /4, /5) ``, `   `, `_`, `._[]` → `None`
examples: (R-A2L-MATCH.8, X §A) `JVmL` → tokens (`j`, `vm`, `l`)
examples: (R-A2L-MATCH.1, derived, X §A, §H) U+001C then `VALUE_0001` → text U+001C + `value_0001` (U+001C kept), tokens (`value`, `0001`); U+00A0 then `VALUE_0001` → tokens (U+00A0 + `value`, `0001`)

_classify
req: R-A2L-MATCH.26, R-A2L-MATCH.27, R-A2L-MATCH.28, R-A2L-MATCH.29, R-A2L-MATCH.30, R-A2L-MATCH.31, R-A2L-MATCH.32, R-A2L-MATCH.40
in: _Query query; str name; MatchRule rule; Sequence[int] token_ids; Mapping[str, Mapping[int, int]] tables
out: tuple[tuple[int, int], ...] spans
func: new; contract changed by the E5 correction (E5S-01 (b), E5S-04; until then it re-classified each listed name). The match spans of one listed name for the `rule` its tier found (`rank` step 6): it tests no other rule, never decides the rule or the key (the tiers do), and calls no `_prefix_distance`. `name` is folded here; `query.text` and `query.tokens` are already folded. EXACT: `((0, len(name)),)`. PREFIX: `((0, len(query.text)),)`. SUBSTRING: the leftmost occurrence of `query.text` at a boundary offset (`_at_boundary`), else the leftmost occurrence. TOKEN: for each distinct query token, from the start of the leftmost name token that starts with it, as long as it. FUZZY: for each distinct query token, the leftmost name token whose id has the smallest distance in that token's step-4 table, the name's `_tokens` spans taken in order with `token_ids` (its ids in `_name_token_ids`, the same order and count); span = that name token. SUBSEQUENCE: one span per offset of `_subsequence(query.keys, folded name)`. A repeated query token adds its span once (A-2). Spans pass through `_join_spans`. A name that does not meet `rule` (a defect of the tiers) raises `ValueError`, never a skipped entry (E5 code review F3). Case-exactness is decided in `rank` step 6 by string comparison on the raw texts, not here.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.27, .16/1, O) `value_000`, `VALUE_0001`, PREFIX → `((0, 9),)`
examples: (R-A2L-MATCH.32, .16/3, O) `vale_0001`, `VALUE_0001`, FUZZY, C08's tables → `((0, 5), (6, 10))`
examples: (R-A2L-MATCH.32/2, O) `valu_0001`, `VAL_BLK_0001`, FUZZY, C08's tables → `((0, 3), (8, 12))`
examples: (R-A2L-MATCH.28/1, O) `count`, `DiscountCount`, SUBSTRING → `((8, 13),)`
examples: (R-A2L-MATCH.29/1, O) `ounter`, `model.MainClass.ledController.sw.timeCounter`, SUBSTRING → `((38, 44),)`
examples: (R-A2L-MATCH.30/2, O) `knife 1 x`, `parameter_instance[1].Knife[0].x`, TOKEN → `((19, 20), (22, 27), (31, 32))`
examples: (R-A2L-MATCH.9/3, .31, O) `map 20`, `MAP_0020`, SUBSEQUENCE → `((0, 3), (6, 8))`
examples: (rule 12, derived) `temp_sensor_max`, `VALUE_0001`, TOKEN → `ValueError` (a tier defect raises; nothing returns `None`)
examples: (C5) the same ranked lists as the integrated `rank` (`label_match.py` sha256 `24564b32…`, which re-classified each listed name): 364 rankings over REF, REF6, LONG and CRAFT at limits 1, 20 and 200, 0 mismatches (`corr-e5-check-C-transcript.txt`)
examples: (R-A2L-MATCH.40/3 neg) the E2 contract (each listed FUZZY name re-scored with `_prefix_distance`) → CRAFT 51 tokens: 273,360 calls and 1,128.5 ms for the 20 listed names alone, above 1.0 s before the tier is counted (`sec-e5-adv-transcript.txt`, `sec-e5-fixcheck-transcript.txt`) → RED

_order_key
req: R-A2L-MATCH.20, R-A2L-MATCH.21, R-A2L-MATCH.22, R-A2L-MATCH.23, R-A2L-MATCH.24, R-A2L-MATCH.25
in: MatchRule rule; int key; str name; bool case_exact
out: tuple[int, int, int, int, str] order
func: new (D-3 B, D-6 A). `(position of rule in MatchRule, key, len(name), 0 if case_exact else 1, name)`; tuple and `str` comparison give the rank order, code-point order last, so the order is total over distinct names and the input order decides nothing.
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.23/2, O) query `rpm`: `RPMX` → `(1, 0, 4, 1, 'RPMX')` < `rpm_x` → `(1, 0, 5, 0, 'rpm_x')`
examples: (R-A2L-MATCH.24/2, O) query `RPM`: `(0, 0, 3, 0, 'RPM')` < `(0, 0, 3, 1, 'Rpm')` < `(0, 0, 3, 1, 'rpm')`
examples: (R-A2L-MATCH.22/1, O) query `curvee`: `(4, 1, 10, 1, 'CURVE_0001')` < `(4, 2, 4, 1, 'CUVE')`
examples: (R-A2L-MATCH.21/1, O) query `counter`: `(2, 0, 11, 1, 'timeCounter')` < `(2, 1, 9, 0, 'Encounter')`
examples: (R-A2L-MATCH.20/1, O, B4 §1) query `value_000`: `VALUE_0001` → `(1, 0, 10, 1, 'VALUE_0001')`; every `prefix` key `(1, …)` sorts before every `subsequence` key `(5, …)`
examples: (R-A2L-MATCH.25/2 neg) a stable sort with no name part → C08r gives `VALUE_0001` first for `0001` → RED

_token_range
req: R-A2L-MATCH.8, R-A2L-MATCH.11, R-A2L-MATCH.30
in: tuple[str, ...] tokens; str prefix
out: tuple(int lo, int hi)
func: new. The ids `lo` … `hi - 1` of the sorted distinct tokens that start with `prefix` (contiguous in code-point order): `bisect_left(tokens, prefix)`, then `bisect_left` of `prefix[:-1] + chr(ord(prefix[-1]) + 1)` from `lo`; a prefix that ends in U+10FFFF scans forward instead.
module: s19_app/tui/services/label_match.py
examples: (X §H) C08's 215 tokens, `va` → `(213, 215)` (`val`, `value`); `valu` → `(214, 215)`; `m` → `(211, 213)` (`map`, `measurement`); `0` → `(0, 208)`; `zz` → `(215, 215)`, empty
examples: (R-A2L-MATCH.11/2) [`BA_X`] (tokens `ba`, `x`), `ab` → an empty range: no token and no fuzzy match, so `rank` gives `[]`

_build_trie
req: R-A2L-MATCH.35, R-A2L-MATCH.36, R-A2L-MATCH.37
in: tuple[str, ...] tokens
out: tuple(str chars, array depth, array first, array end)
func: new (E2-1). The pre-order array trie of the sorted distinct tokens: one node per distinct non-empty prefix, in pre-order (= the tokens' code-point order); `chars[j]` is its last character, `depth[j]` its length, `first[j]` the id of the first token under it, `end[j]` the index after its subtree; `first` ends with one sentinel, `len(tokens)`; the arrays are `array('I')`. The tokens under node `j` are the ids `first[j]` … `first[end[j]] - 1`. One pass over the tokens with the common prefix of each and the one before, and a stack of open nodes. With R-A2L-MATCH.38's 256-character query cap, the trie needs each token's first 258 characters only (a prefix test needs at most 256, a prefix distance of at most 2 needs at most 258), which bounds the trie per token (E3S-03).
module: s19_app/tui/services/label_match.py
examples: (X §H) [`0001`, `curve`, `cuve`] → chars `0001curveve`, depth `[1, 2, 3, 4, 1, 2, 3, 4, 5, 3, 4]`, first `[0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 3]`, end `[4, 4, 4, 4, 11, 11, 9, 9, 9, 11, 11]`
examples: (R-A2L-MATCH.37, B4 §4, W) REF's 77,256 tokens → `177148` nodes; chars 177,197 bytes and each array 749,076 bytes, 2.3 MiB in all

_fuzzy_token_distances
req: R-A2L-MATCH.10, R-A2L-MATCH.11, R-A2L-MATCH.12, R-A2L-MATCH.13, R-A2L-MATCH.36, R-A2L-MATCH.40
in: LabelIndex index; str query_token; int allowed
out: dict[int, int] distances
func: new (E2-1). `{token id: prefix distance}` for every distinct token of `index` at a prefix distance of at most `allowed` from `query_token`. For `allowed` 0: every id of `_token_range(index._tokens, query_token)`, with 0. Otherwise one walk of the trie arrays in pre-order: each node's alignment column from its parent's (and its grandparent's, for a transposition), capped at `allowed + 1` and computed only on the band |row − depth| ≤ `allowed`; the best prefix distance so far carried down the path; when the column minimum is above `allowed` or not below the best, every token under the node gets the best (when it is at most `allowed`) and the walk jumps to `end[j]`. The same values as `_prefix_distance` token by token. `rank` calls it at most once per distinct query token (A-2), lazily in ascending edits, until step 4's switch, and keeps each map as that token's table for step 6 (the FUZZY spans; E5 correction, E5S-01, replacing "drops each map once its candidates are taken", E3A-02/E3S-01).
module: s19_app/tui/services/label_match.py
examples: (R-A2L-MATCH.10/1, X §F) C08, `cuvre`, `1` → {`curve`: 1} (ids written as their tokens)
examples: (R-A2L-MATCH.10/4, X §F) C08, `mpa`, `1` → {`map`: 1, `measurement`: 1}
examples: (R-A2L-MATCH.32, X §F) C08, `maesu`, `1` → {`measurement`: 1}; `vblk` → {`blk`: 1}; `valu` → {`val`: 1, `value`: 0}
examples: (R-A2L-MATCH.12/3, X §F) C08, `cvure`, `1` → `{}`
examples: (R-A2L-MATCH.13/3, X §F) [`CUVE`, `CURVE_0001`], `curvee`, `2` → {`curve`: 1, `cuve`: 2}
examples: (R-A2L-MATCH.11/1) C08, `0300`, `0` → `{}` (no token starts with `0300`)
examples: (X §F) REF, 33 query tokens with 1 or 2 allowed edits (from `nzukij` to `pposbxiifkdgfiajnbbpvb`) → equal to brute force (the prefix distance to each of the 77,256 tokens): `0` mismatches
examples: (R-A2L-MATCH.36, W) REF, median of 5 per query token: `nzukij` `45.0` ms (v3 dict trie 46.3, bare sorted list 81.9); `pposbxiifkdgfiajnbbpvb` `40.3` ms (v3 102.0, sorted list 136.7); all 24 tokens `358.0` ms (v3 461.7, sorted list 773.4)

parse_a2l_file
req: to trace
in: Path path; A2LProgress? progress = None
out: dict parsed
func: unchanged (frozen module `tui/a2l.py`; context only). The reader G-T1 takes the fixture names from: `parse_a2l_file(path)["tags"][i]["name"]`, in file order (the tag dict at `a2l.py:2610-2612`; the A2L views list these names, S2.2). The matcher never calls it: the new module imports no `s19_app` code, and no product caller changes. Real callers (the extractor on a throwaway copy, tests excluded; `extract-e2/diff-report.md`, "Top-level sites"): `s19_app/tui/app.py:948`, `:950` (both in `parse_a2l_cached`, `:906`, R), `s19_app/tui/services/flow_execution_service.py:381`, `:500` (in `run_flow`, `:187`, R), `s19_app/tui/services/variant_execution_service.py:2665` (in `execute_variant_plan`, `:2609`, R). Its contract in this node matches the code (no drift on it).
module: s19_app/tui/a2l.py
examples: (fixture C08, B4 header) case 08 `firmware.a2l` (seed 20260001) → `462` names, `VALUE_0001` … `VAL_BLK_0060` (`../evidence-e1/case08-names.txt`)
examples: (fixture C08i, B4 header) `firmware_issues.a2l` → `470` names, `VALUE_0001` twice
examples: (fixtures, B4 header) `software_a.a2l` → `13990`, `software_b.a2l` → `67`, `BalanceTube_STMicro.a2l` → `111`, `from_source.a2l` → `72` names

## Entities

[Data: MatchRule]
in: str enum (class MatchRule(str, Enum))
desc: new (I-3). Six members in rank order, value = the rule word of the rows: EXACT `exact`, PREFIX `prefix`, SUBSTRING `substring`, TOKEN `token`, FUZZY `fuzzy`, SUBSEQUENCE `subsequence` (D-3 B: fuzzy before subsequence). The position of a member in the class is the first part of `_order_key`. Precedent: `MemoryStatus(str, Enum)` (`tui/changes/model.py:48`).

[Data: LabelMatch]
in: frozen dataclass (slots)
desc: new (I-3). `name: str`, `rule: MatchRule`, `edits: int` (FUZZY: the total edits; else 0), `spans: tuple[tuple[int, int], ...]`. Compares by value, so a test asserts a whole ranked list with `==`. Precedent: `@dataclass(frozen=True, slots=True)` in `tui/services/diff_report_service.py:197`.

[Data: LabelIndex]
in: frozen dataclass (slots, eq=False, repr=False)
desc: new (I-3; E2-1). Public: `names: tuple[str, ...]` (distinct, first-occurrence order) and `__len__`. Private, set once by `build_label_index` through the generated `__init__`, never changed (no function writes a buffer after the build; E3S-07): `_folded: tuple[str, ...]` (`_fold(name)` per name); `_masks: array('Q')` (`_char_mask` per folded name); `_tokens: tuple[str, ...]` (the distinct folded name tokens, sorted by code point; id = position); `_name_token_ids: array('I')` and `_name_token_starts: array('I')` (each name's token ids in name order; `len(names) + 1` offsets); `_postings: array('I')` and `_posting_starts: array('I')` (for each token id, the ascending ids of the names that hold it, each once; `len(_tokens) + 1` offsets); `_trie_chars: str`, `_trie_depth`, `_trie_first`, `_trie_end: array('I')` (`_build_trie`). `repr=False` keeps a 50,000-name index out of logs and tracebacks; `eq=False` makes equality identity. Sizes on REF (B4 §4, bytes): names 400,040; folded with strings 4,956,417; tokens with strings 4,797,032; masks 425,104; token ids 1,976,676 + 209,676; postings 1,978,784 + 328,432; trie 177,197 + 3 × 749,076; 17,496,901 held, 18,940,597 peak.

[Data: _Query]
in: NamedTuple
desc: new. `text: str` (folded), `tokens: tuple[str, ...]` (folded token strings), `keys: str` (folded). `rank` makes one per call and keeps the raw stripped query separately for case-exactness (step 6).

[Outside: Inc 7 A2L Viewer]
desc: the consumer of I-3 after prototype round 2: the autocomplete dropdown and the paste modal. Not built in this increment.

## Edges

[Outside: Inc 7 A2L Viewer] ──▶ build_label_index
when: once per A2L load generation (I-4), off the UI thread
[Outside: Inc 7 A2L Viewer] ──▶ rank
when: each debounced keystroke (limit = the dropdown's free rows) and each missing label of the paste modal (the paste splits into names first, never the whole paste as one query, E3S-01; closest names only for the rows on screen, E3S-05)
build_label_index ──▶ [Data: LabelIndex]
[Data: LabelIndex] ──▶ rank
[Data: LabelIndex].names ──▶ LabelIndex.__len__
[Data: LabelIndex]._trie_depth ──▶ _fuzzy_token_distances
[Data: LabelIndex]._tokens ──▶ _token_range

## Findings

> E2-1 (for E3; R-A2L-MATCH.37, D-12 A + D). The compact index. What held the memory in the E1 v3 index (77.9 MiB tracemalloc peak on REF, B4 §4) was a dict trie of the 77,256 distinct tokens, a tuple of token strings per name, a dict of Python lists of Python ints for the postings, and a Python int bitmask per name. The pinned index keeps the folded names and the sorted distinct tokens as strings and puts everything else in flat `array` buffers: token ids per name, CSR postings, a 64-bit character mask per name, and a pre-order array trie (177,148 nodes in one string and three `array('I')`). Measured on REF (B4): peak 18.1 MiB (64 MiB bound, 3.5× margin), build median 1.798 s (5.0 s bound, 2.8×), worst rank median 62.6 ms (200 ms bound, 3.2×; v3: 122.6 ms). Equal results: 0 mismatches against the E1 oracle on every example of `02-test-cases.md` (92 checks), on v3's pool (409 queries × 4 limits), and against the v3 index on REF (22 QSET + 300 generated queries); the boundary test and the trie walk each equal their definition (X §E: 572,421 offsets; X §F: 33 query tokens). A first variant walked the bare sorted token list (no trie arrays): same memory class, worst median 158.3 ms (B4a), a 1.26× margin that host load could erase; W shows the per-token cost of all four walks. No trade-off had to be escalated: both bounds are met with margin.
> E2-2 (for the orchestrator; records outside this folder). (a) The ruling table writes "D-1 | **A**" with the reason "`build_label_index` + `rank`", which is option **B** of `../E1-rulings.md` D-1 (A was the stateless `rank(query, names, limit)`); this graph follows the reason and the brief (the two calls). (b) `PLAN.md`'s I-3 row still reads `rank(query, names, limit)`. (c) `../E1-rulings.md` §1 ("Out: a memory bound — D-12"), §2 ("S2.7", "… .36") and §6 ("rows … .36") predate the rulings (S2.8, 37 rows). (d) The rows cite the v3 index as "~137 MiB": that was the RSS growth over three builds with two indexes alive; its tracemalloc peak is 81,652,763 bytes (77.9 MiB) — still above 64 MiB, so R-A2L-MATCH.37's negative control stays RED.
> E2-3 (for E3). No change to a pinned interface is proposed. The graph pins I-3 as `../E1-rulings.md` §5 wrote it, plus three details §5 left open: `LabelIndex` is a frozen slots dataclass with `eq=False, repr=False`; the query type check runs before the limit check; `LabelMatch` compares by value.
> E2-4 (for E4 G-T2). `../02-test-cases.md` names G-T2's cases as .35/1 and .36/1 in its header but counts 3 for G-T2 (with .37/1) in its Counts line; this graph puts .37/1 in G-T2: it asserts a plain byte bound and carries no `serial_timing` mark (a memory test that compares bytes, not a clock interval, would trip R-TST-002); tracemalloc traces one process and an xdist worker runs one test at a time, so the serial lane gives no extra isolation. REF is built before `tracemalloc.start()` and after `gc.collect()`.
> E2-5 (for E3 and E4 G1; character classes). Python's string methods disagree with CTX-A2L-MATCH on characters outside ASCII (X §H): `str.strip()` strips U+001C … U+001F and U+00A0, which the rows keep (a separator and a letter); `str.isdigit()` is `True` for U+0663 and U+00B2, which the rows call letters; `str.isalnum()` is `False` for U+00A0, a letter in the rows. The graph pins comparisons by code point (`_parse_query`, `_tokens`, `_allowed_edits`) and adds derived examples that turn RED on each shortcut. Whether U+00A0 should count as a letter is the definition's choice (D-2), not this stage's.
> E2-6 (for E4 G-T1; optional cases). The derived examples (U+001C and U+00A0 queries, three U+0663, the empty index, the `TypeError` texts, purity) are no cases of `../02-test-cases.md`. Every row is covered without them; G-T1 may add them as cases of R-A2L-MATCH.1 and .11 and as interface checks.
> E2-7 (for E3; a bare `str`, ruled E3S-06). `build_label_index("VALUE")` now raises `TypeError("label names must be an iterable of str, got str")` — a `str` is an `Iterable[str]`, so a bare `str` would otherwise index five one-character names. The same guard refuses `bytes`.
> E2-8 (extractor and lint). `codewire_extract.py` (v3.1.0) on a throwaway copy of the product tree (`git archive` of `s19_app`, `tests`, `tools` at `cbe56e6`, 363 Python files) with one mark, `# node: parse_a2l_file`: its contract matches the code; its 5 real call sites are listed (tests excluded); the 17 new nodes are reported "Graph node without mark (no code yet)" — the expected state before code, so the run exits 1 by design (`extract-e2/diff-report.md`, `extract.json`, `extract-stdout.txt`). `codewire_lint.py`: 18 nodes, 5 entities, 7 edges, 0 lines not read, exit 0 (`extract-e2/lint.txt`; a record, not a gate).
> E2-9 Not checked: the operator's Windows PC and the CI runners (D-12; `array('I')` is 4 bytes on both CPython builds, so the sizes should carry, but no run shows it); CPython 3.12; real operator queries (BL-I4-2 stays a G2 question).
> E5-1 (the E5 design-gap correction, E5S-01 and E5S-02; for E4 G1 and the orchestrator). Steps 4 and 6 of `rank` and the `_classify` contract changed; no node was added or removed, no signature of I-3 changed. The ruling asked for one walk per distinct query token with the FUZZY entries from the per-word maps. Walking **every** distinct token (C5 variant A) breaks R-A2L-MATCH.36 on QSET's multi-word query (264.0 ms > 200 ms; .36's own negative control), so the pinned posting variant (C5 variant C) keeps a switch, moved from "at most 300 candidates" to "at most 512 name-token occurrences held by the candidates", where the per-id tables cost at most 512 `_prefix_distance` calls per remaining token. Measured: 0 mismatches against the integrated `rank` on 364 rankings; CRAFT 51 tokens 232.7 ms (16.7 s before), the subsequence shape 158.6 ms (8.8 s), .36's sets unchanged, PSET over REF6 309.0 ms (665.7 ms). `_prefix_distance` now runs only after the switch, so the E3 band control no longer reaches LONG; whether a case should cover the band after the switch is left to the orchestrator. The scope of .35, .37 and .40 names their lists' total characters (E5S-02); BL-I4-5 is in `../E1-rulings.md`. Code-only findings stay with E4 G1: F1 (`_order_key` annotation), F2 / E5S-03 (the column loop of `_prefix_distance` must stop at `min(n, m + cap)`, as this node's cost bound already says), F3 (a tier defect raises, now in `_classify`), E5S-04 (distinct query tokens, now in `_classify`).

### Size and deviations from the E1 slice (`../E1-slice.md` §2)
| | E1 slice | This graph |
|---|---|---|
| New function nodes | 9 (`build_label_index`, `rank`, `_fold`, `_tokens`, `_allowed_edits`, `_prefix_distance`, `_classify`, `_join_spans`, `_order_key`) | 17: the 9, plus `LabelIndex.__len__` (part of the slice's `LabelIndex` row), `_char_mask`, `_at_boundary`, `_subsequence`, `_parse_query`, `_token_range`, `_build_trie`, `_fuzzy_token_distances` |
| Types | 3 (`MatchRule`, `LabelMatch`, `LabelIndex`) | 4 entities: the 3, plus `_Query` (the parsed query, folded) |
| Changed / removed | 0 / 0 | 0 / 0; 1 unchanged context node (`parse_a2l_file`) |
| Signatures | `_classify(query, name, folded: bool)`, `_order_key(match, case_exact)` | `_classify(query: _Query, name)` (the fold rides in `_Query`); `_order_key(rule, key, name, case_exact)` |
| Source files | 1 (new) | 1 (new) |
Reason for the 8 added functions: the memory row (.37) removed the trie and the bitmasks the slice's design note assumed, so the trie, its walk, the token range, the boundary test and the mask became functions of their own; `_subsequence` and `_parse_query` are each shared by two callers. 18 nodes and 5 entities in all, under the cap of about 40.

### Coverage — every row and black-box case → nodes and examples (every row has at least one concrete example; none uncovered)
| Row | Nodes | Examples (case ids; derived ones marked) |
|---|---|---|
| R-A2L-MATCH.1 | rank, _parse_query | .1/1–/4; derived U+00A0 |
| .2 | rank, _parse_query | .2/1–/5, neg |
| .3 | rank, _fold, _parse_query | .3/1–/3 |
| .4 | rank, _fold | .4/1–/3, neg |
| .5 | rank | .5/1–/3 |
| .6 | rank | .6/1–/3 |
| .7 | rank | .7/1–/4 |
| .8 | rank, _tokens, _token_range, _parse_query | .8/1–/9 |
| .9 | rank, _subsequence, _char_mask | .9/1–/4 |
| .10 | rank, _prefix_distance, _fuzzy_token_distances | .10/1–/6, neg |
| .11 | rank, _allowed_edits, _token_range, _fuzzy_token_distances | .11/1–/3, neg |
| .12 | rank, _allowed_edits, _prefix_distance, _fuzzy_token_distances | .12/1–/4 |
| .13 | rank, _allowed_edits, _prefix_distance, _fuzzy_token_distances | .13/1–/4 |
| .14 | rank | .14/1–/2, neg |
| .15 | rank | .15/1–/2 |
| .16 | rank | .16/1–/3, neg |
| .17 | build_label_index, LabelIndex.__len__, rank | .17/1–/2 |
| .18 | rank | .18/1–/3, neg |
| .19 | rank | .19/1–/2, neg |
| .20 | rank, _order_key | .20/1–/3 |
| .21 | rank, _order_key, _at_boundary | .21/1–/3 |
| .22 | rank, _order_key | .22/1 |
| .23 | rank, _order_key | .23/1–/2 |
| .24 | rank, _order_key | .24/1–/4, neg |
| .25 | rank, _order_key | .25/1–/3, neg |
| .26 | rank, _classify | .26/1–/2 |
| .27 | rank, _classify | .27/1–/3 |
| .28 | rank, _classify, _at_boundary | .28/1–/2 |
| .29 | rank, _classify, _at_boundary | .29/1–/2 |
| .30 | rank, _classify, _tokens | .30/1–/3 |
| .31 | rank, _classify, _subsequence, _join_spans | .31/1–/3, neg |
| .32 | rank, _classify, _prefix_distance, _fuzzy_token_distances | .32/1–/3 |
| .33 | rank | .33/1–/3 |
| .34 | rank, _join_spans | .34/1–/3, neg |
| .35 | build_label_index, _build_trie | .35/1 (B4: 1.798 s), neg |
| .36 | rank, _fuzzy_token_distances, _build_trie, _char_mask | .36/1 (A: 66.4 ms REF, 78.4 ms REF6), neg; W |
| .37 | build_label_index, _build_trie | .37/1 (B4: 18.1 MiB), neg (75.7 MiB) |
| .38 | rank | .38/1–/2, neg |
| .39 | build_label_index | .39/1–/2, neg |
| .40 | rank, _prefix_distance, _fuzzy_token_distances, _classify | .40/1 (A: 461.7 ms REF6, 121.5 ms REF; C5: 309.0 ms REF6), .40/2 (A: 77.5 ms LONG; C5: 59.0 ms), .40/3 (C5: CRAFT 29.6 / 232.7 ms), neg (no collapse 1,136.9 ms; per-candidate check 16.7 s on CRAFT; the E3 no-band control superseded); derived `cuvre cuvre`, the switch, the subsequence shape |
| AT-B103-I4-1 | rank | typing `m` … `map_0020` |
| AT-B103-I4-2 | rank | 8 queries, target first in each |

### E4 notes (for G1, G-T1, G-T2 and the integration step)
- The module imports `array`, `bisect`, `dataclasses`, `enum`, `typing` only: `tests/test_engine_unchanged.py` (frozen set untouched) and `tests/test_import_census.py` TC-654 (no `tui/services/*` import of `insight_style`) hold by construction; E5 runs them.
- `tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES = 267` (`:184`) grows by 2 for `test_b103_label_match.py` and `test_b103_label_match_timing.py`; re-measured at integration, since other increments add files too (an E4 edit of a test file, not source).
- `tests/test_suite_hygiene.py` R-TST-002 (`:392`): every timing arm carries `serial_timing` (`pyproject.toml:115`); the .35/.36/.40 tests carry `serial_timing`, .37/1 none; G-T1 times nothing.
- G-T1 fixtures: case 08 generated into `tmp_path` by `tools/synth/make_release_case.py --seed 20260001` (never into the repository; Amendment A1 keeps it byte-stable), names read with `parse_a2l_file`; module-scoped prepared indexes. Expected values come from `../02-test-cases.md` and this graph, never from the pilots' code.
- G-T2: REF built before the clock or `tracemalloc.start()` (after `gc.collect()` for .37); `time.perf_counter()` around each call; host load printed before and after (`os.getloadavg()`, POSIX only: skip the print on Windows). The .35/.36/.40 tests assert `median <= report_margin("R-A2L-MATCH.36 <query>", median, timing_bound(0.200))` (5.0 for .35, 1.0 for .40; LONG, PSET and CRAFT built before the clock; CRAFT as `../02-test-cases.md` builds it, its sha256 checked) — not a bare `<= 0.2`, which trips R-TST-040/041 — and the .37 test carries no `serial_timing` mark and asserts a plain byte bound.
- G1 may keep tier helpers private to `rank` unmarked; every other function not in this graph is a deviation to write down. The pilots (`i4e2-pilot4.py`, the E1 pilots) are evidence, not code to copy; the graph's contracts and examples are the source.
- Extractor at integration: copy the merged tree to a scratch directory (never the worktree), put `# node: <name>` above each of the 17 new defs and above `parse_a2l_file`, run `codewire_extract.py --repo <copy> --graph graph-inc4.md --out <dir>` (no `--path`, as at E2); expected: exit 0, no drift, and calls from `rank` and `build_label_index` to the private nodes.
