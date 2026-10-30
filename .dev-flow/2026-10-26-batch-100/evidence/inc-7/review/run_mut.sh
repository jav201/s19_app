#!/bin/bash
# usage: run_mut.sh <id> <pytest args...>   (cwd = the mutant tree)
R7=/c/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/r7
id=$1; shift
tree=$R7/mut/$id
out=$R7/mut-$id.txt
cd $tree
{
  cat $R7/mut-$id.header.txt
  echo "# cmd: python -m pytest -p no:cacheprovider -q $*"
  echo "# tree: $tree  PYTHONPATH=$tree  NO_COLOR unset"
  env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=$tree C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -c "import s19_app; print('# s19_app import:', s19_app.__file__)"
  env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=$tree C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest -p no:cacheprovider -q "$@" 2>&1
} > $out
tail -5 $out
