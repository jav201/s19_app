"""Inc 3 E4 — probe of the two test-side fixture/oracle defects found while
running the Inc 3 parity suite on the E1 host (Windows).

Probe 1 (CRLF): ``Path.write_text`` on Windows translates ``\\n`` to ``\\r\\n``
(newline=None, universal newlines). ``_write_image`` (the Inc 2 test helper
the Inc 3 suite reuses) writes through ``write_text``, so every image fixture
it makes is 42 bytes here; ``same.write_bytes(emit_s19_from_mem_map(...).encode
("ascii"))`` writes raw LF bytes (39). r044/3 and r047/3 and r047/6 assert the
two sizes equal — impossible on this host.

Probe 2 (parse path): ``parse_a2l_file`` embeds ``path`` (the lexical file it
parsed) in the returned payload. The shipped routes parse the workarea copy
(attach copies to ``workarea/temp``; project parses ``workarea/<proj>/<file>``),
so ``app.current_a2l_data == parse_a2l_file(<src path>)`` differs in the
``path`` item on every platform. r047/1, /2, /4, /5 (and /6 after its CRLF
assert) use that full-dict comparison.
"""

from pathlib import Path
import tempfile

from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.a2l import parse_a2l_file

IMG1 = {0x1000: 0x10, 0x1001: 0x20, 0x1002: 0x30}
IMG2 = {0x1000: 0x70, 0x1001: 0x80, 0x1002: 0x90}

tmp = Path(tempfile.mkdtemp())

# Probe 1 — the equal-size image fixture.
img_text = tmp / "img_text.s19"
img_text.write_text(
    emit_s19_from_mem_map(dict(IMG1), [(min(IMG1), max(IMG1) + 1)]),
    encoding="ascii",
)
img_raw = tmp / "img_raw.s19"
img_raw.write_bytes(
    emit_s19_from_mem_map(dict(IMG2), [(min(IMG2), max(IMG2) + 1)]).encode("ascii")
)
print(f"probe1: write_text size={len(img_text.read_bytes())} (CRLF) "
      f"write_bytes size={len(img_raw.read_bytes())} (LF)")
print(f"probe1: equal-size assertion on the E1 host -> "
      f"{len(img_raw.read_bytes()) == len(img_text.read_bytes())}")

# Probe 2 — the parse payload embeds the lexical parse path.
a2l_src = tmp / "src" / "probe.a2l"
a2l_src.parent.mkdir(parents=True, exist_ok=True)
a2l_src.write_text(
    "/begin PROJECT probe \"\"\n/end PROJECT\n",
    encoding="ascii",
)
a2l_copy = tmp / "workarea" / "probe.a2l"
a2l_copy.parent.mkdir(parents=True, exist_ok=True)
a2l_copy.write_bytes(a2l_src.read_bytes())
src_payload = parse_a2l_file(a2l_src)
copy_payload = parse_a2l_file(a2l_copy)
print(f"probe2: src payload path={src_payload['path']}")
print(f"probe2: copy payload path={copy_payload['path']}")
print(f"probe2: full-dict equality src vs workarea copy -> "
      f"{src_payload == copy_payload}")
