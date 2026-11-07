# Inc 2a — E5 code review (batch-103), code-reviewer agent (claude-opus-5-5), 2026-11-07

## Verdict: **FAIL** — BLOCK-UNTIL: CR-1, CR-2

Two MAJOR `impl` findings are open. Each has a fix of a few lines. Neither changes a fixture result.
- **CR-1:** the TAB_NOINTP lookup walks a run of equal x values one entry at a time. On a COMPU_TAB that repeats one x below the stored value, the decode time of each element grows with the table: ×2.02 at 2S, ×8.30 at 8S, 0.95 s at S. R-A2L-DEF.150 sets 1.5 / 2.0 / 0.5 s.
- **CR-2:** a MATRIX_DIM word the frozen parser reads as a huge int, here `0x` and 5,000 hexadecimal digits, makes `describe_definition` raise `ValueError`. R-A2L-DEF.58.2 requires a refusal in place of an exception.

The rest of the change matches the records:
- the refusal order and every 2a refusal text;
- the closed list of shared kinds at describe;
- immutable read forms;
- I-2's surface, with P-2 holding as ruled.

The fixes go to `software-dev`. The verdict changes only after a re-read of the fixed diff and a re-run of `cr-probe.py` [P2] and [P3]. A recommended fix does not close a finding.

**Scope reviewed.**
- The diff: `git diff a2043cfd 069171cd -- s19_app tools tests` in `C:\Users\jjgh8\Github\s19_app-b103-inc2a-code`, branch `b103-inc2a-code`. It covers 6 files: `s19_app/tui/a2l_definition.py` (+1428, read in full), `tools/synth/make_release_case.py` (+322/−2), the three new test files and `tests/test_id_registry.py`.
- The commits behind it: E4 (`42165fa4`, `707c9b92`, `82f5f8e5`), gap pass 1 (`f2f955aa`, `37168255`) and gap pass 2 (`6071a385`, `e9bad3ca`). Gap pass 2's own diff is `f2f955aa..6071a385`.
- The records, read in full: `01-requirements.md` (with its split notes), `E3-rulings.md` (with "known design gaps", "gap pass 2 rulings", the round-6 addendum, "records done" and "GREEN"), and `codewire/graph-inc2.md` (the I-2 pin, P-2, the 2a nodes `describe_definitions` … `display_text`, `_table_value` and the entities).
- Also read: `../inc-3/E3-rulings.md` "Round 7 rulings" and the cases of `02-test-cases.md` that the findings cite.

**Evidence.** Every result below comes from a tool run, saved under `evidence-e5/`:
- `cr-probe.py` → `cr-probe-transcript.txt`: sections [P0] … [P7];
- `cr-measure.py` → `cr-measure-transcript.txt` (run 2) and `cr-measure-run1-transcript.txt` (run 1, partial): sections [M0] … [M9];
- `cr-static-census.txt`: a grep at HEAD.

Both scripts ran on cachyos-rtx (Python 3.11.18) in a copy of `~/work/b103-int2a`, made at `/tmp/b103-e5-2-code/tree` (e9bad3ca, `a2l_definition.py` md5 `820a4c3a`, the same product files as 069171cd). HOME, XDG_* and LOCALAPPDATA pointed to `/tmp/b103-e5-2-code/zq_iso_user`. Each transcript prints `s19_app.__file__` = `/tmp/b103-e5-2-code/tree/s19_app/__init__.py`.

Three notes on how the probes ran:
- `cr-probe.py` ran under `python -I`. That flag drops `PYTHONDONTWRITEBYTECODE`, so the copy may have gained `__pycache__` folders. The copy was deleted after the runs (`rm -rf /tmp/b103-e5-2-code`, checked absent, no process left).
- `cr-measure.py` has an opt-in loaded block (`--load`, 18 busy-loop workers killed by PID). It never ran.
  - Run 1 (`cr-measure-run1-transcript.txt`) was stopped by PID (exit 143) before it reached that block, because another reviewer's timing probe (`sec-e5-scale.py … steady`) was running on the host. `ps` showed `-` in the `NI` column for my `nice -n 19` process (sched_ext disabled), so I could not confirm that `nice` would keep my load off its measurement. `ps` showed no worker afterwards.
  - Run 2 (`cr-measure-transcript.txt`) is the quiet block and the mutant control only.
- No pytest run, no app and no clipboard.

## Findings

| Id | Sev | Tag | Where | Requirement / case | What | Concrete fix | Evidence state |
|---|---|---|---|---|---|---|---|
| CR-1 | **MAJOR** | impl | `s19_app/tui/a2l_definition.py:1336-1339` (`_table_value`, TAB_NOINTP) | R-A2L-DEF.150 (decode time does not grow with the conversion table); graph `_table_value` ("in O(log n)") | `while lo > 0 and xs[lo - 1] == xs[lo]: lo -= 1` walks back over the run of `xs[i − 1]` one entry at a time. That costs O(k) per element for a run of k equal x values below the stored value. [P2] used 400 UBYTE VALUEs on one TAB_NOINTP method whose COMPU_TAB is S of `0 0` lines then `1000 5`, image 250: 400 decodes took **948.6 / 1919.9 / 7871.8 ms CPU** at 256 KiB / 512 KiB / 2 MiB (**×2.02, ×8.30**; 0.95 s at S against the 0.5 s bound). The value is right (0.0, equal to the frozen `_table_lookup`). The same sizes with distinct x take 1.8 / 1.8 / 1.9 ms (×1.03, ×1.07). One lookup over 1,000 repeated x makes 1,000 x comparisons. **No case catches it:** .150/8's stored value 250 is nearest the `300 999` entry above, so the lookup never takes the lower side. .150/9's tables have at most 2 equal x. | Delete the loop and keep `lo = i - 1`. `_first_equal_below(xs, x, lo, d)` already returns the first index whose distance equals `d`, and every entry of the run has distance `d`, so the result is the same. (If the run start is wanted explicitly: `lo = bisect_left(xs, xs[i - 1], 0, i - 1)`.) Graph `_table_value`: either drop "`lo` = the first entry of the run of `xs[i − 1]`" or add "(by bisect)". Add case **.150/10** to `02-test-cases.md` and the perf file: the 400 VALUEs of /1 on `CM_N` (TAB_NOINTP), a COMPU_TAB of S, 2S, 8S of `0 0` lines then `1000 5`, image 250 → every value `0.0`, the .150 measure. Negative control: HEAD 069171cd → ×2.02 / ×8.30, 0.95 s at S → RED. | executed (`cr-probe-transcript.txt` [P2]) |
| CR-2 | **MAJOR** | impl | `a2l_definition.py:710` (`_object_kind`: `f"MATRIX_DIM {matrix_dim} MEASUREMENT"`) | R-A2L-DEF.58.2 (a refusal in place of an exception); I-2 "never raises on file content" | The frozen parser reads `MATRIX_DIM` with `int(word, 0)` (`a2l.py:2700-2705`). Base 16 has no digit limit, so `0x` and 5,000 hexadecimal digits become a 20,000-bit int. Writing it in decimal hits CPython's 4,300-digit limit, and `describe_definition` raises `ValueError: Exceeds the limit (4300 digits) for integer string conversion` [P3]. Inc 6's picker describes every object, so one such object in a file takes the whole describe down. | Write `<n>` without decimal conversion of a huge int: `n_text = str(matrix_dim) if matrix_dim.bit_length() <= 64 else _echo(hex(matrix_dim))`. `hex()` has no digit limit, and `_echo` caps the text at 256 characters and `…`. Every existing message stays the same. Add case **.58.2/20**: MEASUREMENT `MD` with `MATRIX_DIM 0x` and 5,000 `F` → `A2L-DEF-KIND`, 0 exceptions, message ≤ 1,024. CR-3 sets the text. | executed ([P3]) |
| CR-3 | MINOR | design-gap | `01-requirements.md` CTX placeholders (`<kind>` … `MATRIX_DIM <n> MEASUREMENT`); R-A2L-DEF.151 ("the system's own text … `MATRIX_DIM <n> MEASUREMENT` … is written as it is"); graph `describe_definitions` (":306", "every message is then at most 1,024 characters whatever the file holds") | R-A2L-DEF.151 (every message ≤ 1,024 characters); R-A2L-DEF.4 | `<n>` comes from the file, but the records treat it as system text. A `MATRIX_DIM` of 4,000 decimal digits gives an `A2L-DEF-KIND` message of **4,069 characters** [P3]. | Records: in CTX `<kind>`, write `<n>` as "the MATRIX_DIM number as a decimal integer; a number above 2^64 − 1 as `0x` and its hexadecimal digits, written as R-A2L-DEF.151 writes a file word". The code is CR-2's fix. Add case **.151/4** (4,000 decimal digits → message ≤ 1,024) and the graph example on `_object_kind`. | executed ([P3]) |
| CR-4 | MEDIUM | design-gap | `a2l_definition.py:839-841` (the verdict is upper-cased); `:700`, `:708` (kind), `:1179` (interpolate), `:1415`, `:1420` (display) read the raw word; graph `_read_method_record` ("`type_verdict` = the type word upper-cased … R-A2L-DEF.12's test as Inc 2a reads it, upper case") against `_object_kind` ("`enum` when `conversion_type` is `TAB_VERB`") | R-A2L-DEF.2, .12, .35, .38; R-A2L-061/062; .150/9 ("giving the (value, error) the frozen lookup gives") | A type word in another letter case passes R-A2L-DEF.12, but three later decisions compare the raw word. [P1]: (a) `tab_intp` decodes **0.0**, by the TAB_NOINTP rule. The frozen `_apply_compu_method` gives **50.0**, and so did `82f5f8e5`, which upper-cased the word there. **This is a regression of gap pass 2**: `_table_value`'s `interpolate` is `conversion_type == "TAB_INTP"`. (b) `tab_verb` is described with no refusal, gets kind `number` and decodes as the raw number `5`. (c) `identical` on UBYTE `%.2` shows `5.00`; `IDENTICAL` shows `5`. Corpus: of the 560 COMPU_METHODs in the 34 parsed tracked files, 0 have such a word (case_06 skipped, > 20 MiB). | Recommended (simplest: the six types are ASAP2 keywords, which the tracked files write in upper case, 0 of 560 otherwise; that the standard requires upper case is my reading, not checked here): make the verdict case-sensitive, `type_verdict = conversion_type if conversion_type in _SUPPORTED_CONVERSION_TYPES else None`. A lowercase word is then refused `A2L-DEF-CONVERSION`, no other decision reads a case-folded word, and 0 fixture objects change. Graph `_read_method_record` gets "the type word when it is one of …", and .12 gets a case `/4` (`tab_intp` → refusal). If the orchestrator keeps case folding: `interpolate = (definition.conversion_type or "").upper() == "TAB_INTP"`, and `_object_kind` and `display_text` compare the upper-cased word, each with a case. | executed ([P1]) |
| CR-5 | MINOR | impl | `a2l_definition.py:545-547` (the echo is skipped when `kind_text.startswith("MATRIX_DIM ")`) | R-A2L-DEF.151 (every file word echoed; ≤ 1,024) | The `<kind>` echo is decided by testing the text's prefix. A CHARACTERISTIC whose kind word is quoted and starts with `MATRIX_DIM ` is a file word, but it is written whole. A 2,011-character kind gives a **2,057-character** message with no `…` [P4]. | `_object_kind` returns the `<kind>` text already written: `_echo(str(char_type))` for a CHARACTERISTIC kind word, and the system text for `MATRIX_DIM <n> MEASUREMENT` and `(none)`. Drop the prefix test at `:546`. Case **.151/5** (the quoted kind). | executed ([P4]) |
| CR-6 | MINOR | impl | `tools/synth/make_release_case.py:1058` (`"planned_text": "IDLE"`) | I-D (graph: `planned_text` = "the display text the model must give for the planned bytes"); R-A2L-DEF.60 | The enum raw is drawn (`rng.choice([0, 1, 2, 3])`), but its planned text is fixed. For seeds 2, 3, 4 and 5 the model decodes `OFF`, `OFF`, `OFF` and `FAULT` while the list says `IDLE` [P7]. Only seed 20260001 (raw 1) is tested, and `--seed` is a public option. | Keep one tuple `DEFINITIONS_ENUM_TEXTS = ("OFF", "IDLE", "RUN", "FAULT")`, use it for the emitted COMPU_VTAB lines, and set `"planned_text": DEFINITIONS_ENUM_TEXTS[enum_raw]`. Add a test case: build_definition_objects for seeds 1 … 5 against the model's decode of the generated case. | executed ([P7]) |
| CR-7 | MINOR | impl | `tests/test_b103_a2l_definition.py` (no test) | P-2 ruling ("`compare=False, repr=False` … I-2's public names, equality and repr do not change"); graph P-2 ("a definition built by hand … decodes as `82f5f8e5` does") | P-2 holds today [P5]: the last two fields are `(compare, repr) = (False, False)`, a described definition equals the same definition stripped of both private fields, neither name appears in `repr`, and the stripped definition decodes the same. No test fails if either property goes. Dropping `repr=False` would put a table form, up to the section's size, into every `repr` and traceback. | In `test_r_a2l_def_149_5_…` (or a .149/5 sibling), for the enum, range, TAB and LINEAR objects: `assert d == dataclasses.replace(d, _name_echo=None, _table_form=None)`; `assert "_table_form" not in repr(d) and "_name_echo" not in repr(d)`; `assert decode_definition(bare, a2l, image) == decode_definition(d, a2l, image)`. Negative control: `compare=True` → RED. | executed ([P5]) |
| CR-8 | INFO | design-gap | `a2l_definition.py:1190-1195` (`decode_definition` passes `a2l_data["compu_tabs_by_name"]` to the frozen `_apply_compu_method`); graph edge `[Data: a2l_data].compu_tabs_by_name ──▶ decode_definition` (`graph-inc2.md:972`) | Inc 3a "Round 7 rulings": "every `a2l_data` section lookup in `a2l_definition.py` goes through `reads`" | **Describe: the list is closed.** Each section an object reaches comes through a map lookup whose result is keyed in `reads` by `id()`: `record_layouts_by_name` `:731` → `:734-749`; COMPU_METHOD `:804-868`; COMPU_VTAB / _RANGE `:974-1025`, reached only from the record at reduction; COMPU_TAB `:765-776`, likewise (`cr-static-census.txt`). MOD_COMMON and AXIS_PTS are not reached in 2a: the byte order comes from the tag. [P6] counts, for 400 objects in one walk: 401–402 flattens (400 object records + the method + the table), 1 layout resolution, 1 enum form or 1 `_TabForm`, 1 `_display_decimals`. **Decode: one lookup by name remains** outside `reads`, in the frozen helper. For a described definition it always misses, because a TAB_INTP / TAB_NOINTP definition whose table exists carries its `_TabForm`: [P6] counts 0 lookups when the table exists, and 400 misses → `A2L-DEF-DECODE lookup table missing` when it does not. It hits only for a definition built by hand, which the graph allows (P-2). | Records only: add to the closed-list rule (Inc 3a `01-requirements.md:267`, graph `:79`) "decode reads `compu_tabs_by_name` only for a definition built by hand". Alternatively, in code, a described TAB definition without a form refuses `lookup table missing` without the lookup. No behaviour change either way. | executed ([P6], static census) |
| CR-9 | LOW | impl | `a2l_definition.py:1155-1159` and `:1232-1236` | — (simplicity) | The name-echo fallback (`definition._name_echo if … is not None else _echo(definition.name)`) is written twice. | Compute it once in `decode_definition` and pass it to `_read_stored_value(definition, image, name_echo)`. | executed (read) |
| CR-10 | LOW | impl | `a2l_definition.py:1136-1139` (`decode_definition` docstring); `:303-305` (`describe_definition` Args) | repo docstring convention | The decode docstring says a number goes through `_apply_compu_method`; it now takes `_table_value` for a TAB form and refuses a value that is not a number. The describe docstring lists `compu_methods_by_name` among the keys it reads, but the module builds that map from `sections`. | Update both docstrings. | executed (read) |
| CR-11 | LOW | impl | `tests/test_b103_a2l_definition.py:1689-1695` (`_method_record`) | — (test hygiene) | `inspect.signature` picks a 3-argument call for the code at `eb750c6f`. That supported the RED-on-base run, but the branch is dead at HEAD. | Remove the 3-argument branch now that GREEN is recorded. The RED evidence stays in `gap2-tests-red-base-*.txt`. | executed (read) |
| E5-3 | MEDIUM | design-gap | `tests/test_b103_a2l_definition_perf.py:193-218` (`_scaling`), `:400-438` (`_gp2_run` with `_describe_first`); the threshold of R-A2L-DEF.149 and cases .149/1 … /10 ("the 400 names less … the first name alone") | R-A2L-DEF.149; Inc 3a E3S3-34 ("each run builds its own walk … and times the 399 names described for the first time in it") | See §E5-3 below. Measured today, the difference of two walks is not only noisy under load: even on a quiet host it is badly conditioned at 8S. | See §E5-3: one walk per round and a single interval, using only the public `Iterable[str]` contract. | executed (`cr-measure-transcript.txt`) |

**Checked and clean** (each read in the diff; numbers from the probes where cited):
- **Refusal order** matches CTX *refusal order*: name `:422-428` → kind → address and length → span bounds → datatype → length against datatype → method → conversion → table → entries → mask (`:543-626`).
- **The 2a refusal texts** of .4, .6, .139, .7.1, .7.2, .8, .9, .11, .12, .13, .17, .19 (2a clauses), .26, .28 and .58.2/18–19 are the rows' texts, character for character.
- **Read forms are immutable.** The method record is a `MappingProxyType` of scalars, tuples and frozen forms. `_EnumForm` holds tuples and a `MappingProxyType`, `_TabForm` holds tuples, and the layout entry stores a `str`. No list or dict is in a form or in a `Definition` field. `reads` is per call and is dropped.
- **The range segment index** (`:906-955`) and the first-of-raw index (`:885-891`) are correct by construction: the heap orders by file position, with lazy expiry. They agree with the hostile cases of graph `:410-411`.
- **`_first_equal_below` and the TAB_INTP branch** follow v2's two rules.
- **I-2.** The public names are unchanged: `Refusal`, `Limits`, `EnumEntry`, `Definition`, `Decoded`, `describe_definition`, `describe_definitions`, `decode_definition` and `display_text`. The field order is as pinned (no `shared_with`, `bit_mask_text` per P-1), with P-2's two fields last, `compare=False, repr=False`.
- **No dead code**, apart from CR-11 in a test.
- **No second copy of a helper.** `_echo` (.151) and `_clean` (.137) are two rules. `_table_value` replaces the frozen lookup by design. The test oracles are verbatim copies by design.
- **Synth.** The case 08 path is unchanged (`generate` untouched; `--case` defaults to `release`).
- **Test hygiene.** There is no skip, xfail or swallowed exception in the three test files.
- **The tests encode the rows' texts**: messages are compared whole, and the .150/6 and /9 oracles are verbatim frozen code.

## E5-3 — the timing measure: proposed test change

**The defect.** `_scaling` and the describe cases of `_gp2_run` compute the per-object part as `min(t(400 names)) − min(t(first name alone))`. These are two separate walks, and each carries the walk build and the shared reduction, which are O(S). The per-object part (about 10 ms) is the small difference of two larger numbers, so it is badly conditioned.

**What [M1] shows on a quiet host.** Load was 0.3–2.5 (another session's single-process probe). The cases were .149/6 (`fmt`) and .149/7 (`type`), 31 interleaved rounds per trial:
- **Today's measure (A):** 11 trials (`cr-measure-transcript.txt`, 6; `cr-measure-run1-transcript.txt`, 5) give a part at S of 9.6–11.0 ms, but at 8S only **1.0 (the floor) to 7.3 ms**. The ratios are ×2S **0.73–1.04** and ×8S **0.10–0.67**.
- **The true part (B, below):** **9.95–10.44 ms at every size**.

So A loses 27–90 % of the 8S part even when the host is quiet. Its error is the size of the effect it measures, and it runs both ways:
- quiet, A hides up to about 9 ms of the 8S part, enough to mask real growth at 8S;
- under load, A fails correct code (the GREEN record: runs 1 and 2 at load 15 failed 4 and 1 ratio checks).

**The proposed measure (B)** reads, over the same 11 trials: ×2S **0.99–1.02** and ×8S **0.99–1.01**, every trial GREEN. **Negative control:** with the mutant "reduction per object" (`_read_method_record` given a fresh `reads` at every call), B reads **×1.98 / ×7.84** (`fmt`) and **×1.99 / ×7.75** (`type`): RED [M3].

The loaded block (`--load`) was not run, because the host was shared (see the evidence notes). B's robustness under load is therefore `not-run`. B removes the subtraction, the one term that load can inflate on its own; that argument is mine, not measured.

**The change (tests only; the module is not touched).** `describe_definitions` takes `names: Iterable[str]` and consumes it once, lazily (`:366`). A generator can therefore read the clock inside one fresh walk:

```python
def _steady_describe(names: list, a2l: dict) -> tuple[float, dict]:
    """CPU time of the 399 names after the first, described for the first time in ONE fresh walk
    (inc-3 E3S3-34): the clock is read when the walk asks for the 2nd name (the 1st has reduced
    every shared section) and when the names run out."""
    marks: list = []

    def gen():
        yield names[0]
        marks.append(time.process_time())
        yield from names[1:]
        marks.append(time.process_time())

    result = describe_definitions(gen(), a2l)
    assert len(marks) == 2 and list(result) == names       # consumed lazily, once
    return marks[1] - marks[0], result
```

How to use it:
- In `_scaling` and in `_gp2_run`'s describe cases, call `_, (t, results[kib]) = _timed(lambda: _steady_describe(names, a2l), time.process_time)`. Keep `best[kib] = min(best[kib], t)` over the interleaved rounds and set `part = best`. That removes the subtraction and the 1 ms floor.
- Add one non-vacuity check: `assert part[SIZE_S_KIB] >= 2e-3`. A module that materialised the names before describing them would give an interval near 0 and fail it.
- `_describe_first` and `first=` go away for the describe cases. The decode cases (.150) keep their measure: decode stores nothing per walk (E3S3-34).

**Records (design-gap).** In R-A2L-DEF.149's threshold and the Expected column of .149/1 … /10, "the process CPU time of the 400 names less that of the first name alone" becomes "the process CPU time of the 399 names after the first, described for the first time in one walk built for that run (the clock read when the walk asks for the second name and when the names run out)".

## Evidence checklist

- [✓] Diff read in full: `a2l_definition.py:1-1429`, `make_release_case.py` hunks `:951-1245` and `:1337-1378`. The tests were read where the rows touch them: `test_b103_a2l_definition.py:1680-2244`, `test_b103_a2l_definition_perf.py:55-618`, and `test_id_registry.py`.
- [✓] Correctness pass, covering edge, None, NaN and error paths: CR-1, CR-2, CR-4, CR-6; the range and TAB lookups were checked against v2.
- [✓] Simplicity pass: CR-1's redundant walk, CR-9, CR-11; no premature abstraction found.
- [✓] Reuse and duplication: CR-9. The frozen helpers are reused (`_flatten_body_tokens`, `_resolve_record_layout`, `_decode_scalar`, `_apply_compu_method` for non-TAB conversions).
- [✓] Tests reviewed for intent: CR-1 (no case reaches the lower side at scale), CR-7 (P-2 unpinned), E5-3 (the measure).
- [✓] Verdict explicit: FAIL, BLOCK-UNTIL CR-1 and CR-2. Neither MAJOR carries applied-and-verified evidence yet.

Handoffs: CR-2, CR-3 and CR-5 (hostile-file messages and the raise) are also in `security-reviewer`'s lane, for its E5 pass. The coverage gaps of CR-1 and CR-7 go to the coverage audit (`qa-reviewer`).
