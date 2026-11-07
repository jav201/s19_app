set -e
REAL=/home/javiergr
B=/tmp/b103-e1-3
PY=$REAL/miniconda3/envs/s19ci/bin/python
CLONE=$REAL/work/s19_app
export HOME=$B/home XDG_CONFIG_HOME=$B/home/.config XDG_DATA_HOME=$B/home/.local/share XDG_CACHE_HOME=$B/home/.cache LOCALAPPDATA=$B/home/local
unset DISPLAY
cd $B
SCRIPT=$1; shift
echo "# $SCRIPT transcript $(date -Iseconds) host $(hostname)"
echo "# clone $(git -C $CLONE rev-parse HEAD) status: $(git -C $CLONE status --porcelain | wc -l) changed"
echo "# python $($PY -V 2>&1); HOME=$HOME LOCALAPPDATA=$LOCALAPPDATA DISPLAY=${DISPLAY:-unset}"
$PY -I $B/$SCRIPT $CLONE "$@" 2>&1
