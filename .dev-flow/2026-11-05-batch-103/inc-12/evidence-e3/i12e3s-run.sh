#!/usr/bin/env bash
# Inc 12 E3 security (batch-103), runner cachyos-rtx only. Scratch /tmp/b103-e3-12-S/ (deleted at the end).
#   bash i12e3s-run.sh setup                 -> /tmp/b103-e3-12-S/design: `git archive e07fb00 s19_app` of the read-only
#                                               clone, patched by Inc 12 E2's i12e2-mkproto.py (variant design = the
#                                               graph's prototype as E2 measured it; not the E4 implementation)
#   bash i12e3s-run.sh probe <variant> <scen> -> i12e3s-probe.py against the clone (base) or the design copy
# HOME/XDG/LOCALAPPDATA isolated under $base/zq_iso_user (basename not `home`), no DISPLAY, closed stdin, timeout.
set -u
base=/tmp/b103-e3-12-S
py="$HOME/miniconda3/envs/s19ci/bin/python"
clone="$HOME/work/s19_app"
iso="$base/zq_iso_user"
mkdir -p "$iso/lad" "$base/out" "$base/scratch"
mode="$1"; shift
isoenv=(env -i PATH=/usr/bin:/bin HOME="$iso" XDG_CONFIG_HOME="$iso/.config" XDG_DATA_HOME="$iso/.local/share"
        XDG_CACHE_HOME="$iso/.cache" LOCALAPPDATA="$iso/lad" PYTHONDONTWRITEBYTECODE=1 TERM=xterm-256color
        CLONE="$clone" CORPUS="$HOME/a2l-corpus/files")
head_lines() {
  echo "# $1 transcript $(date -Iseconds) host $(hostname)"
  echo "# clone $(git -C "$clone" rev-parse HEAD) status: $(git -C "$clone" status --short | wc -l) changed; python $("$py" --version 2>&1)"
  echo "# HOME/XDG/LOCALAPPDATA under $iso; no DISPLAY; no clipboard; stdin closed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
}
case "$mode" in
  setup)
    out="$base/out/setup-transcript.txt"
    {
      head_lines setup
      rm -rf "${base:?}/design"; mkdir -p "$base/design"
      git -C "$clone" archive e07fb00 -- s19_app | tar -x -C "$base/design"
      "${isoenv[@]}" "$py" -I "$base/scripts/i12e2-mkproto.py" "$base/design" design < /dev/null 2>&1
      "${isoenv[@]}" "$py" -I -m py_compile "$base/design/s19_app/tui/app.py" < /dev/null 2>&1 && echo "py_compile design: ok"
      echo "diff design vs e07fb00: $(git -C "$clone" show e07fb00:s19_app/tui/app.py | diff - "$base/design/s19_app/tui/app.py" | grep -c '^[<>]') changed lines"
      echo "# clone status after: $(git -C "$clone" status --short | wc -l) changed"
    } > "$out" 2>&1
    cat "$out";;
  probe)
    v="$1"; s="$2"; tmo="${3:-900}"; repo="$base/$v"; [ "$v" = base ] && repo="$clone"
    out="$base/out/probe-$v-$s-transcript.txt"
    {
      head_lines "probe $v $s"
      "${isoenv[@]}" timeout "$tmo" "$py" -I "$base/scripts/i12e3s-probe.py" "$repo" "$base/scratch" "$v" "$s" < /dev/null 2>&1
      echo "# exit $? ; clone status after: $(git -C "$clone" status --short | wc -l) changed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
    } > "$out"
    cat "$out";;
  *) echo "unknown mode $mode"; exit 2;;
esac
