#!/bin/bash
# Round-3 security probes for Inc 11, in order; each writes /tmp/b103-e3r3-11-S/out-<name>.txt via sec-r3-job.sh.
cd /tmp/b103-e3r3-11-S
J=scripts/sec-r3-job.sh
setsid nohup bash $J model-corpus scripts/sec-r3-p_r3_model.py corpus > /dev/null 2>&1 < /dev/null &
bash $J model-shapes scripts/sec-r3-p_r3_model.py shapes
bash $J model-tracked scripts/sec-r3-p_r3_model.py tracked
bash $J base-addr scripts/sec-r3-p_r3_base.py addr
bash $J base-bo scripts/sec-r3-p_r3_base.py bo
bash $J mem-gen scripts/sec-r3-p_r3_base.py gen /tmp/b103-e3r3-11-S/work/bigbody.a2l 600000
bash $J mem-base scripts/sec-r3-p_r3_base.py mem base /tmp/b103-e3r3-11-S/work/bigbody.a2l
bash $J mem-words scripts/sec-r3-p_r3_base.py mem words /tmp/b103-e3r3-11-S/work/bigbody.a2l
wait
