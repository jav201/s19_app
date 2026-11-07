#!/bin/bash
# usage: e3a11r3-run.sh <out name> <args...> -- Inc 11 E3 addenda (E3S-28) on <runner>: isolated env (HOME basename
# <user>), read-only clone (~/work/s19_app at e07fb00) and corpus, no bytecode writes, no DISPLAY, closed stdin,
# 8 GB address-space cap, 1 h timeout. The runner account's home goes in as B103_RUNNER_HOME, so no account path is
# written into a script or a transcript. Writes /tmp/b103-e3a-11/out/<out name>-transcript.txt.
S=/tmp/b103-e3a-11
name="$1"; shift
out="$S/out/$name-transcript.txt"
mkdir -p "$S/out" "$S/work" "$S/<user>"
clone="$HOME/work/s19_app"
{
  echo "# e3a11r3-mem.py $* | $(date -Iseconds) host $(hostname) clone $(git -C "$clone" rev-parse --short HEAD) status $(git -C "$clone" status --short | wc -l) changed; corpus files $(ls ~/a2l-corpus/files | wc -l) (read-only); load $(cut -d' ' -f1-3 /proc/loadavg)"
  B103_RUNNER_HOME="$HOME" env -i PATH=/usr/bin:/bin B103_RUNNER_HOME="$HOME" HOME="$S/<user>" \
    XDG_CONFIG_HOME="$S/<user>/.config" XDG_DATA_HOME="$S/<user>/.local/share" \
    XDG_CACHE_HOME="$S/<user>/.cache" LOCALAPPDATA="$S/<user>/lad" PYTHONDONTWRITEBYTECODE=1 \
    bash -c "ulimit -v 8000000; cd $S/work; exec timeout 3600 \"\$B103_RUNNER_HOME/miniconda3/envs/s19ci/bin/python\" -I $S/scripts/e3a11r3-mem.py \"\$@\" < /dev/null" _ "$@" 2>&1
  echo "# exit $? ; clone status after: $(git -C "$clone" status --short | wc -l) changed; load $(cut -d' ' -f1-3 /proc/loadavg)"
} > "$out"
