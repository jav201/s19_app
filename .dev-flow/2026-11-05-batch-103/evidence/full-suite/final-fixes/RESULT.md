# Batch-103 G3 — final fixes

Base: `26edef4afff576160a550797b5f9cf3dd3743af0`. Branch: `b103-g3-final-fixes`. Windows local run; environment and isolation are recorded in `environment.txt`. No product file changed and no real clipboard was used.

## Result

The four requested nodes pass together: **4 passed in 27.61 s** (`green-targeted.log`, `green-targeted.junit.xml`). TC-051, the real arm changed for the Inc15 guard, also passes together with that guard: **2 passed** (`green-settled.junit.xml`).

The complete five-file run collected **185** nodes: **180 passed, 5 failed** in 1065.92 s (`full-files.junit.xml`). All 118 nodes in the four functional files passed: B100 load question 59, Inc10 survivors 4, undo/redo 3 and patch editor v2 52. The five failures are confined to unrelated hygiene nodes and are analysed below.

## Fixes and causes

1. **Inc15 / TC-051** — `tests/test_tui_patch_editor_v2.py`: the wait for `not prompt.has_class("hidden")`, with the exact TC-051 description, now immediately follows `request_action("apply_doc")`; the worker wait follows it. This satisfies the pinned AST contract and keeps the real prompt assertions.
2. **Undo/redo real key** — `tests/test_undo_redo_ux.py`: the old driver read the entries table after one fixed pause. The historical RED showed only `0x200` after Add. The driver now waits through `tests.b97_probes.settled` for the real Add, Ctrl+Z and Ctrl+Y states. The three final oracles and real key route are unchanged; product code was not implicated.
3. **Inc10 long written name** — `tests/test_b103_inc10_mu_survivors.py`: the local RED was a save-back wait timeout. A direct probe showed that the handler had finished with `Patched image not saved`; the deepest Windows staging path was 429 characters and was refused before writing. An extended-length `\\?\` test base lets the real Inc10 chain write and verify the same 254-character name. The S0 oracle remains exactly `name.encode("ascii")[:252]`; neither name nor length was weakened.
4. **B100 project load question** — `tests/test_b100_load_question.py`: after the Save project outcome line, the driver now waits for the panel dirty flag to clear before the unchanged setup assertion and question-count expectations. This addresses the observed worker/UI synchronization rather than changing product behaviour.

The initial local `red-before` run reproduced Inc15 and Inc10 (2 failed); the two timing-sensitive undo/B100 nodes passed in that isolated run. Their previous RED signatures remain covered by the unchanged final assertions.

## Full-file residuals, outside the four fixes

- The first complete run's five hygiene failures were associated with the deep in-evidence scratch: MAX_PATH archive extraction, three inner-pytest nodeids carrying the scratch prefix, and the redaction guard encountering live scratch.
- A short-external-scratch rerun of those five nodes made the archive/MAX_PATH node pass. The three QC-TM guards still failed because Windows inner runs root at the temp ancestor and include relative scratch directories in nodeids. The global redaction guard still failed on pre-existing artifacts outside `final-fixes` (including old account/host placeholder spellings and historical POSIX home text).
- The project redaction scanner run directly over this new `final-fixes` subtree reports **PASS**. All delivered XML parses successfully.

Ruff passes for `test_tui_patch_editor_v2.py`, `test_undo_redo_ux.py` and `test_b103_inc10_mu_survivors.py`. The full Ruff invocation also reports only the pre-existing unused `asyncio` and `shutil` imports at `test_b100_load_question.py:48` and `:52`; those unrelated lines were left intact.

## Artifact map

- `red-before.*`: central four-node reproduction.
- `green-settled.*`, `green-undo.*`, `green-inc10.*`, `green-b100.*`: individual directed checks.
- `green-targeted.*`: definitive combined four-node GREEN.
- `full-files.*`: complete five-file run.
- `steps.log`, `environment.txt`, `SHA256SUMS`: dated execution record, environment and integrity manifest.
