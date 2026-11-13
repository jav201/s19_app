# Rulings during P0 (orchestrator relevo-1, 2026-11-12/13)

- **RU-12 — interpreters.** Runners' `s19ci` env is Python 3.11; the specs need >= 3.12 for exact AST positions inside f-strings. The tools run
  under the runner's system `/usr/bin/python3` (3.14, stdlib only); everything that imports `s19_app` (fresh imports, re-exports, MRO, CSS,
  object identity) runs in a subprocess under `--py <s19ci python>` with an isolated env. The verifier never imports `s19_app` in-process.
- **RU-13 — parameter-driven patches (retargeter T5).** `tests/test_report_off_ui_thread.py::_record_thread(monkeypatch, name, sink)` patches
  `app_mod.<name>` with `name` a parameter; the census missed it. T5 rewrites `A` → `A.deps` in such a helper only when every call in the file
  passes a string constant that is a D1 name; mixed / non-constant / indirect use → R1. Non-constant `getattr(A, name)` READS elsewhere stay
  (re-export is the same object) and are printed as `RETARGET NOTE dynamic-read` (test_b100_load_question.py:3149, test_b100_workers.py:1310).
- **Spec name.** The handoff said `verify_identity.py`; spec-verify.md says `verify.py` (+ `compare_outcomes.py`). Spec wins.
- **Accepted worker deviations.** Mover: sdb has 9 files (map), not 10 (I-1 prose off by one) → fresh imports 32/32, not 33; annotation-only
  unknown names (`Dict` at base line 10244, never imported, string under `from __future__`) stay bare, not E12; fresh-import subprocess uses
  `python -c` with the isolated env (not `-I`, which drops the tree from sys.path). Verifier: V15 uses the spec caps (2,200 / class+500);
  `CSS_PATH` must be the rewritten constant (else V4); a level-1 relative import inside a unit is V5; added `--state`, `--tree`,
  `--family-new-count`; flaky file is `id<TAB>reason`.
- **B3 question (verifier).** `outcomes.tsv` does not carry pytest's exit code; the orchestrator checks `SUITE_DONE rc=` in the run log (rc 2/4 = B3).
- **MINOR backlog.** Mover/verifier subprocesses leave `__pycache__` in the tree (env lacks PYTHONDONTWRITEBYTECODE=1); untracked and ignored,
  but add it. The repo tracks 8 `s19_app/__pycache__/*.pyc` (py39/310) — candidates for removal in a later batch.
