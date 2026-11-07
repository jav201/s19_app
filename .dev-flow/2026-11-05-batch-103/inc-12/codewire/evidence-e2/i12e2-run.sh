#!/usr/bin/env bash
# Inc 12 E2 runner (batch-103) for the LAN host cachyos-rtx. Copied from Inc 11's corr2-e3c2-run.sh; the scratch
# folder, the transcript naming and the copy set-up differ.
#   bash i12e2-run.sh setup                      -> fresh throwaway copies under /tmp/b103-e2-12/<variant>/ from
#                                                   `git archive e07fb00` of the read-only clone (design: the product,
#                                                   tests and their fixtures; the others: s19_app only), each patched
#                                                   by i12e2-mkproto.py (its docstring lists the variants)
#   bash i12e2-run.sh probe <variant> <scenario> -> i12e2-probe.py against the clone (variant base) or the copy;
#                                                   transcript /tmp/b103-e2-12/out/probe-<variant>-<scenario>-transcript.txt
#   bash i12e2-run.sh pytest <variant> <tests..> -> python -m pytest in the copy (cwd = copy, so the copy's s19_app is
#                                                   imported; its __file__ is printed first)
# HOME/XDG/LOCALAPPDATA isolated under /tmp/b103-e2-12/zq_iso_user (basename is not `home`), no DISPLAY, closed
# stdin, a timeout. The clone ~/work/s19_app is only read (git archive, sys.path); its status is printed before and
# after every run.
set -u
base=/tmp/b103-e2-12
py="$HOME/miniconda3/envs/s19ci/bin/python"
clone="$HOME/work/s19_app"
iso="$base/zq_iso_user"
mkdir -p "$iso/lad" "$base/out" "$base/scratch"
mode="$1"; shift
isoenv=(env -i PATH=/usr/bin:/bin HOME="$iso" XDG_CONFIG_HOME="$iso/.config" XDG_DATA_HOME="$iso/.local/share"
        XDG_CACHE_HOME="$iso/.cache" LOCALAPPDATA="$iso/lad" PYTHONDONTWRITEBYTECODE=1 TERM=xterm-256color)
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
      for v in full noshow nopostfit noresize widget widgetonly widgetnoshow widgetnopost design; do
        rm -rf "${base:?}/$v"; mkdir -p "$base/$v"
        if [ "$v" = design ]; then
          git -C "$clone" archive e07fb00 -- s19_app tests examples tools docs pyproject.toml setup.py REQUIREMENTS.md \
              AT-TC-REGISTRY.jsonl CLAUDE.md | tar -x -C "$base/$v"
        else
          git -C "$clone" archive e07fb00 -- s19_app | tar -x -C "$base/$v"
        fi
        "${isoenv[@]}" "$py" -I "$base/scripts/i12e2-mkproto.py" "$base/$v" "$v" < /dev/null 2>&1
        "${isoenv[@]}" "$py" -I -m py_compile "$base/$v/s19_app/tui/app.py" < /dev/null 2>&1 && echo "py_compile $v: ok"
        echo "diff $v vs e07fb00: $(git -C "$clone" show e07fb00:s19_app/tui/app.py | diff - "$base/$v/s19_app/tui/app.py" | grep -c '^[<>]') changed lines"
      done
      echo "# clone status after: $(git -C "$clone" status --short | wc -l) changed"
    } > "$out" 2>&1
    cat "$out";;
  probe)
    v="$1"; s="$2"; repo="$base/$v"; [ "$v" = base ] && repo="$clone"
    out="$base/out/probe-$v-$s-transcript.txt"
    {
      head_lines "probe $v $s"
      "${isoenv[@]}" timeout 1800 "$py" -I "$base/scripts/i12e2-probe.py" "$repo" "$base/scratch" "$v" "$s" < /dev/null 2>&1
      echo "# exit $? ; clone status after: $(git -C "$clone" status --short | wc -l) changed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
    } > "$out"
    wc -l "$out";;
  pytest)
    v="$1"; shift; repo="$base/$v"
    out="$base/out/pytest-$v-transcript.txt"
    {
      head_lines "pytest $v"
      cd "$repo" || exit 2
      "${isoenv[@]}" "$py" -c "import s19_app; print('s19_app.__file__ =', s19_app.__file__)" < /dev/null 2>&1
      "${isoenv[@]}" timeout 3000 "$py" -m pytest -p no:cacheprovider -q -o addopts= "$@" < /dev/null 2>&1 | tail -80
      echo "# exit ${PIPESTATUS[0]} ; clone status after: $(git -C "$clone" status --short | wc -l) changed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
    } > "$out"
    tail -5 "$out";;
  *) echo "unknown mode $mode"; exit 2;;
esac
