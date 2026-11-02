#!/bin/bash
# copy worktree files (CRLF) into ~/s19fix3 as LF
W=/mnt<HOME>/Github/s19_app-b100-fix3
for f in "$@"; do sed 's/\r$//' "$W/$f" > ~/s19fix3/"$f"; done
cd ~/s19fix3 && sha256sum "$@" | cut -c1-16
