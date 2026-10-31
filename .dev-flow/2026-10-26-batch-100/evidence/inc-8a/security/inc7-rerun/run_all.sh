#!/bin/sh
cd /c/Users/jjgh8/Github/s19_app-b100-inc8a
D=/c/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/s8a/inc7
for p in probe_a_dos probe_e_load r2_probe_w r2_probe_w2x r2_probe_s r2_probe_t; do
  start=$(date +%s)
  env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PROBE_TREE=C:/Users/jjgh8/Github/s19_app-b100-inc8a PYTHONPATH=C:/Users/jjgh8/Github/s19_app-b100-inc8a C:/Users/jjgh8/anaconda3/envs/s19env/python.exe $D/$p.py > $D/r3_out_$p.txt 2>&1
  echo "exit=$? wall=$(( $(date +%s)-start ))s" >> $D/r3_out_$p.txt
done
echo done > $D/ALL_DONE
