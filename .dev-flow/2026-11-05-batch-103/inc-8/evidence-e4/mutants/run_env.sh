# sourced: defines run_pytest <tree> <scratch> <nodes...> (HT-02 / HT-03 environment)
# Caller exports RUNNER_HOME_NAME = the HT-02 HOME basename (kept out of the repo, PP-03).
PY=$HOME/miniconda3/envs/s19ci/bin/python
run_pytest() {
  local tree=$1 S=$2; shift 2
  mkdir -p "$S/home/$RUNNER_HOME_NAME" "$S/x/config" "$S/x/cache" "$S/x/data" "$S/tmp"
  (cd "$tree" && env -i PATH=/usr/bin:/bin HOME="$S/home/$RUNNER_HOME_NAME" XDG_CONFIG_HOME="$S/x/config" \
    XDG_CACHE_HOME="$S/x/cache" XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. timeout 300 "$PY" -m pytest -p no:cacheprovider \
    -n 2 --maxfail=1 --tb=line -q -rfE "$@" < /dev/null)
}
loadnow() { cut -d' ' -f1 /proc/loadavg; }
wait_quiet() {  # HT-08: no battery above load 8
  while [ "$(loadnow | awk '{print ($1>8)?1:0}')" = 1 ]; do echo "waited at load $(loadnow)" >> "$1"; sleep 30; done
}
