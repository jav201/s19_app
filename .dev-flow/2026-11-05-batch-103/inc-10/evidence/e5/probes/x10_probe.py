"""Inc 10 E5 (X10) review probes: runs a claim instead of asserting it (reviewer card rule 3).

Run from the tree root with the HT-02 environment: python x10_probe.py <scratch dir>.
P1  the rename rule's trailing-whitespace class equals str.strip()'s (every code point).
P2  an ASCII control character in the typed save name reaches the written name and the S0 header data.
P3  a byte-identical file under another name makes the S0 rounds stop at the cap with a header that
    names a different file than the landing (no path, only bare names).
"""
import re
import sys
from pathlib import Path

from s19_app.tui.changes.apply import _S0_NAME_ROUNDS, _sanitize_s19_filename, render_patched_image, save_patched_image
from s19_app.tui.app.patch import _synth_s0_header_from_filename
from s19_app.tui.screens_directionb.patch_editor.actions import _SUFFIX_RE
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

scratch = Path(sys.argv[1])

# P1
ws = re.compile(r"\s\Z")
diff = [c for c in range(0x110000) if bool(ws.match(chr(c))) != chr(c).isspace()]
print("P1 code points where the regex whitespace class and str.isspace() disagree:", diff)
print("P1 rename 'fw.s19' + U+3000 ->", repr(_SUFFIX_RE.sub(".hex", "fw.s19" + chr(0x3000))))

# P2
typed = "fw" + chr(0x1B) + "x.s19"
safe, issue = _sanitize_s19_filename(typed, suffix=".s19")
print("P2 sanitized name:", repr(safe), "issue:", issue)
print("P2 S0 header data from it:", _synth_s0_header_from_filename(safe or ""))

# P3
area = scratch / "p3" / WORKAREA_DIRNAME / WORKAREA_SUBDIR
area.mkdir(parents=True, exist_ok=True)
mem = {0x1000 + i: i for i in range(16)}
ranges = [(0x1000, 0x1010)]
twin = render_patched_image(mem, ranges, source_kind="s19", bytes_per_line=32,
                            s0_header=_synth_s0_header_from_filename("bar.s19"))
(area / "foo.s19").write_bytes(twin)
path, issues = save_patched_image(mem, ranges, area, "bar.s19", source_kind="s19", bytes_per_line=32,
                                  s0_header=None, workarea_root=area,
                                  s0_header_from_name=_synth_s0_header_from_filename)
first = path.read_text(encoding="ascii").splitlines()[0] if path else None
print("P3 rounds cap:", _S0_NAME_ROUNDS, "landing:", path.name if path else None,
      "header data:", bytes.fromhex(first[8:-2]) if first else None, "issues:", [i.code for i in issues])
print("P3 files:", sorted(p.name for p in area.iterdir()))
