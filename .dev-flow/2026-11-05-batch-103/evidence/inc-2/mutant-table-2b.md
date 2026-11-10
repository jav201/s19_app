# E5 mutant table — Inc 2b, final tree `e0f4553e`

**34 killed / 0 survived / 0 not realisable.** Every mutant was applied to a separate copy under `/tmp/b103-e5-2b-mut` on <runner>, Python 3.11.18, with isolated HOME/XDG/LOCALAPPDATA, stdin closed and `PYTHONDONTWRITEBYTECODE=1`. The integration tree was never mutated. Each copy was deleted after its serial run; the whole scratch was deleted after the evidence was copied back.

Final driver: `int2b-mutants-run5.txt`; per-mutant unified diff and pytest output: `mutants-2b/out/M-*.txt`; machine-readable result: `mutants-2b/out/summary.json`. Earlier driver runs document harness corrections, not surviving product mutants. `run_2b_mutants.py` is the reproducible driver.

| Id | Row | Negative control realised | Pytest `-k` | Result and discriminating test(s) |
|---|---|---|---|---|
| M-40 | .40 | Python `float()` grammar replaces the number-text grammar | `a2l_def_40` | killed: all 9 invalid forms |
| M-41 | .41 | LINEAR inverted as `(x+b)/a` | `a2l_def_41` | killed: .41/3 |
| M-42 | .42 | encode reason dropped | `a2l_def_42` | killed: all 11 reasons |
| M-43 | .43 | outside limits proceeds instead of refusing | `a2l_def_43` | killed: .43/1–4 |
| M-44 | .44 | accepted without the limits notice | `a2l_def_44` | killed: .44/1–2 |
| M-45 | .45 | extended-limits refusal removed | `a2l_def_45` | killed: .45/1–3 |
| M-46 | .46 | whole word written, other bits not preserved | `a2l_def_46` | killed: .46/1, /2, /3, /4 |
| M-47 | .47 | out-of-mask/negative field accepted | `a2l_def_47` | killed: .47/1–3 |
| M-48 | .48 | last matching enum entry used | `a2l_def_48` | killed: .48/3 |
| M-49 | .49 | default text accepted as an entry | `a2l_def_49` | killed: .49/2 |
| M-49b | .49 | enum text matched ignoring case | `a2l_def_49` | killed: .49/1 |
| M-50 | .50 | ASCII padding removed | `a2l_def_50` | killed: .50/1, /3 |
| M-51 | .51 | overlong text truncated | `a2l_def_51` | killed: .51/1 |
| M-52 | .52 | non-ASCII text encoded as UTF-8 | `a2l_def_52` | killed: .52/1–3 |
| M-53 | .53 | byte order forced to little-endian | `a2l_def_53` | killed: .53/1 |
| M-54 | .54 | precision round-trip guard removed | `a2l_def_54` | killed: .54/1, /3, /4 |
| M-55 | .55 | opposite byte order packed | `a2l_def_55` | killed: .55/1 |
| M-55b | .55 | mask shift off by one | `a2l_def_55 or a2l_def_46` | killed: .46/1–4 (exact-byte oracle) |
| M-55c | .55 | LINEAR inverted as `(x+b)/a` | `a2l_def_55 or a2l_def_41_3` | killed: .41/3 |
| M-55d | .55 | 15-significant-digit pre-rounding removed | `a2l_def_55 or a2l_def_35_5` | killed: .35/5 |
| M-56 | .56 | raw value after the matched text written | `a2l_def_56` | killed: .56/1 |
| M-56b | .56 | text padding removed | `a2l_def_56` | killed: .56/1 |
| M-57 | .57 | mask refusal placed before image-byte refusal | `a2l_def_57_3` | killed: .57/3 |
| M-57b | .57 | encode direction placed before limits | `a2l_def_57_2` | killed: .57/2 |
| M-57c | .57 | shared-bytes refusal placed before number parsing | `a2l_def_57_4` | killed: .57/4 |
| M-138 | .138 | overlap guard removed at both encode exits | `a2l_def_138` | killed: 18 cases, including .138/23 |
| M-138b | .138 | masks compared as integers | `a2l_def_138` | killed: .138/17 |
| M-138c | .138 | missing tag address read as 0x0 in the index | `a2l_def_138_18` | killed: .138/18 |
| M-138d | .138 | 0x0 treated as no address | `a2l_def_138_19` | killed: .138/19 |
| M-138e | .138 | BLOB/INSTANCE omitted from the index | `a2l_def_138` | killed: .138/2–8, /21, /23 |
| M-138f | .138 | unreadable length dropped instead of fail-closed point | `a2l_def_138` | killed: .138/4, /9, /10, /21 |
| M-138g | .138 | BLOB/INSTANCE allowed a homonymous tag's mask | `a2l_def_138_23` | killed: .138/23 |
| M-152 | .152 | parse gate placed after number-text validation | `a2l_def_152 or a2l_def_57_5` | killed: .57/5 |
| M-58.1 | .58.1 | encode writes into the caller's image | `a2l_def_58_1 and encode` | killed: .58.1/2 |

The 2a negative controls remain in `mutant-table-A.md` and `mutant-table-B.md` (63 killed, one then-unrealisable `.58.1` encode arm, now killed here). The residual 2b encode guards `.19/6`, `.19/7`, `.25/2`, `.26/2`–`/4`, `.151/7` and the `.58.2` encode arms also fail on the real encode/`shared_with` stub (`../evidence-e4/int2b-red-stub-final9-main.txt`); their describe/decode negative controls were already killed in the 2a battery.

Harness notes: the final `.55b` selection includes `.46` because a symmetric encode/decode shift can preserve display text while writing the wrong bits; `.55d` includes `.35/5`, the exact 15-significant-digit oracle. These are the negative controls named by `.55`, not additional requirements or unexecuted survivors.
