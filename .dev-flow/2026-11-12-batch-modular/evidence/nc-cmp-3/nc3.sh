#!/usr/bin/env bash
# NC-CMP-3: return atop ShellMixin.set_status on 5b67c844, full suite (-n 8) on the laptop.
set -u
Z=~/work/zq-mod; R=$Z/nc3; rm -rf $R; mkdir -p $R
git clone -q /tmp/zq-p2c.bundle $R/src && cd $R/src && git checkout -q 5b67c844
python3 - <<'PY'
p="s19_app/tui/app/shell.py"; s=open(p,encoding="utf-8").read()
a="    def set_status(self, message: str) -> None:\n        self._append_log_line(message)\n"
assert s.count(a)==1
open(p,"w",encoding="utf-8",newline="").write(s.replace(a,"    def set_status(self, message: str) -> None:\n        return\n        self._append_log_line(message)\n"))
PY
git checkout -q -b nc-cmp-3 && git -c user.name=nc -c user.email=nc@local commit -qam "NC-CMP-3 mutant" && git bundle create -q $R/nc3.bundle nc-cmp-3 2>/dev/null; git branch -f main origin/main 2>/dev/null; git bundle create -q $R/nc3.bundle nc-cmp-3 main
REV=$(git rev-parse HEAD); echo "MUTANT $REV"; git show --stat HEAD | tail -2
bash $Z/run_suite.sh $R/nc3.bundle $REV $R/out 8
rm -rf $R/src $R/out/tree $R/out/state
echo NC3_DONE
