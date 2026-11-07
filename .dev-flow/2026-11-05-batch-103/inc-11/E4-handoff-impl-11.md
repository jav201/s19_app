# E4 handoff — Inc 11 implementer (DeepSeek v4 Pro): A2L reader, read side

## 1. Reference (dev-flow v3 + Code-Wire v3.1; latest as of 2026-11-07)
s19_app (Textual 8.2.8 / rich 15), batch `batch-103`, records under `.dev-flow/2026-11-05-batch-103/` (start with `PLAN.md`, amendment A2). Versions: **dev-flow v3 beta** `C:\Users\jjgh8\.claude\skills\dev-flow-v3-beta\SKILL.md` (commit `d858a9a`; read stage E4 whole); **Code-Wire v3.1.0** `C:\Users\jjgh8\Github\code-wire` tag `v3.1.0` = `e436a08` (core only: examples from the requirements; `tools/codewire_extract.py` finds callers and drift; testers turn examples into failing tests). **tui-design:** not used.

## 2. Role
**E4 implementer: implement the approved graph's Inc 11 side; do not write tests.** An independent tester writes the tests in parallel in another worktree.

## 3. Where you work
- Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc11-code` (branch `b103-inc11-code`, cut from `batch-103`). Only there.
- Your unit's files (exactly the Inc 11 source files of `inc-11/E1-slice.md`; respect the 4-source-file cap — Inc 11 uses 3):
  - **`s19_app/tui/a2l.py`** — **unfrozen for Inc 11 by amendment A2.** Every new, changed and removed node of the graph with `module: s19_app/tui/a2l.py` (the reader: `_lex_a2l_lines`/`_lex_a2l_words`, `_number_word`, `extract_declared_spans`, `_bounded_length`, `_tag_sizes`, `_echo_word`, `_CappedErrors`, `_build_section_tree_into`, and the changed nodes of `E1-slice.md` §2).
  - **`s19_app/tui/a2l_extract.py`** — its re-export list (`__all__`) gains `extract_declared_spans` (I-11.7).
  - **`s19_app/tui/a2l_definition.py`** (Inc 2a's file, already merged into `batch-103`) — `_describe_one` loses its MEASUREMENT header fill (`:377-398` at Inc 2a's `82f5f8e5`; re-read the line numbers on the merged tree).
- Touch nothing else: no test, no record, no other source. `app.py` is **not** in Inc 11 — the tag-table view nodes (`_compose_screen_a2l`, `_build_a2l_table_cells`) moved to Inc 12. If the graph needs another file, stop and write it down as a deviation.
- **Do not commit** (another unit works in the same worktree; the orchestrator commits both).

## 4. Read, in this order
1. `.dev-flow/2026-11-05-batch-103/inc-11/codewire/graph-inc11.md` — the design (37 nodes after the split; interfaces I-11.1 … I-11.8, decisions DE-1 … DE-10). Implement **only the G1 reader nodes**; the G2 `app.py` nodes are Inc 12's — do not touch or stub them.
2. `inc-11/01-requirements.md` — rows and definitions; 80 rows in scope after the Inc 12 E3 addendum (READ.69). Its "Defect tags at e07fb00" list is the no-regression exception set.
3. `inc-11/E3-rulings.md` — every section (rounds 1–3, the correction and addenda rulings, and the orchestrator addendum: READ.66's echo cap 64 → 256, and READ.69). Where a ruling and the graph disagree, the ruling wins; write the deviation down.
4. `inc-11/E1-slice.md` (the function map and the pinned interfaces), `inc-11/E1-rulings.md` (D-1 … D-12 with the orchestrator's rulings), `inc-11/E2-rulings.md`.
5. Base code you call: `s19_app/tui/a2l.py` (the helpers the graph lists; `MAX_A2L_DECODE_BYTES`; `_normalize_byte_order`; `parse_begin_meta`; the field rules R-A2L-010 … 036 that keep their code), `s19_app/tui/a2l_definition.py` `_describe_one` (the fill to remove).
6. `CLAUDE.md`, `PROJECT_RULES.md` (style, docstrings with Summary / Args / Returns / Raises / Data Flow / Dependencies).

## 5. Rules
- English code, comments, docstrings; match the repo's style. Standard library only (`re` is fine — the graph's lexer uses a compiled pattern, `E3-rulings.md` round 3). Deterministic; no global mutable state beyond what the graph pins (`_CappedErrors` per parse). No whole-file regex; the open string's continuation is found with `str.find` or the unrolled pattern (READ.52's memory clause, E3A-18).
- **R-A2L-READ.52's 1.5× time bound holds for every file, the 19.8 MB file included** (`E3-rulings.md` "Ruling on the time of the largest file"); peak memory ≤ 2× the base reader's. The tester measures it (`serial_timing`, GC off, least of ≥ 15 runs, host load recorded) — your job is to meet it, not to measure it.
- **On this PC you may run only** `python -m py_compile <your file>` and `python C:\Users\jjgh8\Github\code-wire\tools\codewire_extract.py`. **Do not run pytest, the app, or any Python that imports or loads your module or `s19_app`** (not even through `importlib`; a previous run did that and it was a rule breach). No standalone check scripts either — `py_compile` and the extractor only. The orchestrator runs every test on the Linux runner.
- **Runner facts (cachyos-rtx only):** `ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"` (fish login shell — always `bash -lc`); Python is `/home/javiergr/miniconda3/envs/s19ci/bin/python`, an absolute path because HOME is changed; isolate `HOME`, `XDG_*` and `LOCALAPPDATA` in a directory named `zq_iso_user`; kill processes by PID only. The public corpus `~/a2l-corpus/files` is read-only, and only derived numbers may leave it.
- **The operator's proprietary A2L fragment does not exist in any file, and none may be created.** Use only synthetic data and the derived corpus numbers in `design/a2l-corpus/`; never copy file content from the public corpus into a record.
- Never push, merge, force, `reset --hard`, delete a branch, or commit. Never write the operator's name. No secrets.
- If the graph or a requirement looks wrong, write it down as a deviation. Never change a requirement or a pinned interface to match your code.

## 6. Stop and report (≤ 300 words)
What you implemented (node → function, one line each); the file and its line count; commands run with exit codes; deviations (node, what, why); open questions.
