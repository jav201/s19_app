## Environment (Linux runner, read carefully)
- Your work tree is the current directory (a git clone, branch `work`, HEAD 09fa725b). The batch folder is
  `.dev-flow/2026-11-12-batch-modular/` (call it B). Base product revision: `4f721985` (present in this clone).
- Run the tool with `/usr/bin/python3 -I` (Python 3.14; the spec needs >= 3.12 and the standard library only).
- The project's dependencies (textual, etc.) exist ONLY in `/data/miniconda3/envs/s19ci/bin/python` (Python 3.11).
  RULING RU-12 (overrides the spec where they differ): every check that imports `s19_app` (fresh imports,
  re-export getattr, runtime MRO/`__dict__`/CSS/object-identity checks) runs in a SUBPROCESS using the interpreter given by a
  new option `--py <interpreter>` (default `sys.executable`). Never import `s19_app` in the tool's own process.
- Every subprocess that imports `s19_app` and every run of the tool must use an isolated environment:
  `env -i PATH=/usr/bin:/bin HOME=$S/zq_iso_user XDG_CONFIG_HOME=$S/x/c XDG_DATA_HOME=$S/x/d XDG_CACHE_HOME=$S/x/k TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8`
  with `S=$(realpath ../state)` (create the subdirs), and `< /dev/null`. The tool itself should pass a minimal env like that to its subprocesses too.
- Negative controls mutate SCRATCH COPIES only: `cp -a` the tree (or `git worktree add` from it) under `../scratch/`; never mutate the base commit.
- NO git writes (no commit, no branch, no stash, no reset, no checkout of files). Write LF line endings, UTF-8, no BOM.
- Do not modify any file other than the ones listed as yours. Do not touch the spec/design files.
- Functions <= 40 lines and modules <= 300 lines are the project's target (`codigo modular`); if a single module would
  exceed 300 lines you may split the tool into a small package of helper modules under `tools/modularize/` with your tool's prefix (list them in your report).
- Final report (stdout, last thing you print): files written; the exact acceptance output; each negative control with
  the command and its pasted output; any place where you deviated from the spec and why; open questions.
