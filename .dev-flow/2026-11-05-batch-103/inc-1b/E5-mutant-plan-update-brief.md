# Brief — Inc 1b E5: bring the mutant plan and its manifest to the current tree

Worker: DeepSeek v4 Pro, thinking high. One unit. Reviewer behind you: Opus, plus a mechanical collection check on Linux.

## Scope (hard)

You may edit ONLY these two files:
- `.dev-flow/2026-11-05-batch-103/inc-1b/E5-mutant-plan.md`
- `.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/mutants/manifest.json`

And create ONLY:
- `.dev-flow/2026-11-05-batch-103/inc-1b/E5-mutant-plan-update-report.md` (your hand-back).

Never: run git write commands, run pytest or any test, touch product or test code, touch any other record or evidence file, invent a line number, a test name or a count. If a fact cannot be verified by reading the tree, write `not verified` and say why.

## Facts (given; do not re-derive)

- New pinned base for every mutant copy: `287b9dc3` (this worktree's HEAD; get the full 40-char sha with `git rev-parse HEAD`, read-only). Old base: `0d4d4e7c800b27040769a1a10117e62884cc7326`.
- `git diff 0d4d4e7c 287b9dc3 -- s19_app/` changes ONLY `s19_app/tui/os_clipboard_input.py` (binary PowerShell transport: stdin/stdout bytes, explicit UTF-8, no `text=True`, no BOM, no newline normalisation; reader keeps final CR/CRLF/LF and maps `""` to `None`; writer uses `ReadToEnd()` + WPF `SetText`). `app.py` is byte-identical, so the 40 `app.py` anchors keep their text; still verify each occurs exactly once.
- Current baselines (from `inc-1b/evidence-e5/full-six-families-final.txt` and the handoff `HANDOFF-2026-11-12-KIMI-INC1B-E5-EXACT-VALIDATION.md` §6.2): the four mutant families (V, Tail, Q, AT) = **142 nodes, 123 passed / 19 skipped**; the six families = 256 nodes, 160 passed / 96 skipped. The old 122/19 and 141 are historical: say so once, do not keep them as current.
- GC-C14 stays pending / BAD until it has an external timeout plus workers/iterations with override/tail capture. Do not change that.

## Tasks

1. Base: replace the pinned base everywhere in both files (plan header, rules section, manifest `baseline_commit`, `baseline_linux`) with the full sha of `287b9dc3`; update the L baseline numbers to 123 passed / 19 skipped of 142.
2. The 20 `os_clipboard_input.py` rows (GC-*, GN-*, GW-*): for each, re-locate the anchor in the current file. Update `line` and the plan's `:line` reference. If the `old` text changed, write the new exact `old` and an equivalent `new` that makes the SAME semantic mutation; if the mutation is no longer realisable, keep the row, mark it `not realisable on 287b9dc3` with the reason, and do not count it as planned-executable.
3. Exclusions 9 and 10 ("Cobertura dudosa") describe the old tree. Read `tests/test_b103_copy_quit_dialog.py` (the autouse writer/reader fixture and `_assert_no_copy_effects`) and `tests/test_b103_clipboard_tail.py` (the hostile PowerShell test) as they are NOW, and rewrite both items to describe the current tree, each claim with `path:line`. If an exclusion no longer applies, say so and remove it from the exclusion count.
4. Two new product controls (the handoff asks for them; numbering continues GC-C20, GC-C21 unless the oracle is WinCI-only, then GW-W05, GW-W06):
   - regression to `text=True` (text-mode subprocess) in the PowerShell transport;
   - loss of the final LF / CRLF (newline normalisation) in reader or writer.
   For each: exact `old` (occurs once) → `new`, file:line, and the current test node ids that must die, found by reading the tests (cite `path:line` of the assert that discriminates). Decide L vs W by whether that test runs on Linux (read its skip markers). If no current test discriminates, say so and do NOT add the row; report it as a coverage gap.
5. Recompute the "Conteos" section from the final rows (total, per group, L / W, executable vs pending). Do not keep 71 by convenience: if it becomes 73 (or another number), write that.
6. Keep the plan's language (Spanish) and table formats. Keep every untouched row byte-identical.

## Self-check you must run and paste (read-only, static)

From the worktree root, run this Python and paste its full output in the report:

```python
import json, pathlib, subprocess
m = json.loads(pathlib.Path('.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/mutants/manifest.json').read_text(encoding='utf-8'))
head = subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
print('baseline_commit ok:', m['baseline_commit'] == head)
bad = []
for r in m['mutants']:
    src = pathlib.Path(r['source']).read_text(encoding='utf-8')
    n = src.count(r['old'])
    if n != 1: bad.append((r['id'], n))
    lines = src.splitlines(keepends=True)
    if r['old'] not in ''.join(lines[max(0,r['line']-3):r['line']+3]): bad.append((r['id'],'line-off'))
from collections import Counter
print('mutants:', len(m['mutants']), dict(Counter(r['group'] for r in m['mutants'])), dict(Counter(r['baseline'] for r in m['mutants'])))
print('anchor problems:', bad)
```

`anchor problems: []` is required. If the manifest schema differs from the fields above, adapt the script minimally and say how.

## Hand-back (`E5-mutant-plan-update-report.md`)

1. Pasted self-check output.
2. Table: id | old line → new line | `old` text changed? | realisable?
3. Exclusions 9/10: before → after, one line each.
4. New controls: rows added or gaps reported, with the discriminating assert `path:line`.
5. New counts.
6. Anything you could not verify.
