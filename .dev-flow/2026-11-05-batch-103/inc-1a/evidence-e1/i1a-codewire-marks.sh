#!/usr/bin/env bash
# Inc 1a E1: real callers of the slice functions with Code-Wire v3.1.0 (tag v3.1.0 resolves to e436a08; tools/ identical to the PLAN's ebc3bb7).
# Marks go ONLY into a throwaway copy of s19_app/ (scratchpad), never into a worktree.
# Usage: bash i1a-codewire-marks.sh <scratch dir> <repo root at e07fb00> <code-wire clone at v3.1.0>
# Run on 2026-11-06 as these same commands, inline, with the scratch dir under the session scratchpad,
# the repo root C:/Users/jjgh8/Github/s19_app-b103 and the clone C:/Users/jjgh8/Github/code-wire.
set -euo pipefail
S="$1"; SRC="$2"; CW="$3"
rm -rf "$S"; mkdir -p "$S/repo" "$S/out"
cp -r "$SRC/s19_app" "$S/repo/"
find "$S/repo" -name __pycache__ -type d -prune -exec rm -rf {} +
F="$S/repo/s19_app/tui/os_clipboard_input.py"
for f in _create_tk_root _destroy_tk_root_singleton _prime_tk_root _read_via_tk _read_via_ctypes _read_via_powershell _write_via_ctypes _write_via_tk _write_via_powershell _bound_clipboard_text read_os_clipboard write_os_clipboard; do
  sed -i "/^def $f(/i # node: $f" "$F"
done
sed -i "/^async def _mirror_and_write_os_clipboard(/i # node: _mirror_and_write_os_clipboard" "$F"
sed -i "/^    def get_or_create(/i \    # node: _TkRootSingleton.get_or_create" "$F"
sed -i "/^    def get_existing(/i \    # node: _TkRootSingleton.get_existing" "$F"
for m in action_copy action_cut action_paste; do sed -i "/^    async def $m(/i \    # node: OsClipboardInput.$m" "$F"; done
C="$S/repo/s19_app/tui/capped_text_area.py"
sed -i "/^    def _on_paste(/i \    # node: CappedTextArea._on_paste" "$C"
for m in action_paste action_copy action_cut; do sed -i "/^    async def $m(/i \    # node: CappedTextArea.$m" "$C"; done
printf '# graph stub for caller listing (Inc 1a E1)\n\n## Nodes\n\n' > "$S/stub-graph.md"
cd "$S"
python "$CW/tools/codewire_extract.py" --repo repo --graph stub-graph.md --out out || true
# Site line numbers in out/diff-report.md are in the MARKED copy (each mark adds one line above it);
# E1-slice.md gives the e07fb00 lines read from the unmarked file.
