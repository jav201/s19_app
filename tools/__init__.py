"""
Repo-local developer tooling. **Not** part of the shipped distribution.

``pyproject.toml``'s ``[tool.setuptools.packages.find] include = ["s19_app*"]``
excludes this package from the wheel, and ``[tool.pytest.ini_options] pythonpath
= ["."]`` is what makes ``from tools.id_registry import ...`` resolve under a
bare ``pytest`` invocation in CI.

This file exists so ``tools`` is a real package rather than a namespace package:
a namespace package would silently merge with any other ``tools`` directory that
happened to be on ``sys.path``, and the id registry's guard must not be able to
import a different module than the seeder did.

Contents:

* ``id_registry`` — the AT/TC grammar, corpus bounds and node derivation shared
  by the seeder and ``tests/test_id_registry.py``.
* ``seed_id_registry`` — the one-time seeder for ``AT-TC-REGISTRY.jsonl``.
* ``counterfactual_id_registry`` — the recorded guard-can-fail evidence run.
* ``mutation_harness`` — the PER-ARM counterfactual runner (batch-76 merge gate).
  Imported by nothing: it is a command-line tool, and it mutates a throwaway
  ``git worktree`` rather than the checkout it runs from.
"""
