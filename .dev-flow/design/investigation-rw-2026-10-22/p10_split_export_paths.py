"""P10: Split/Join/Export writer — (a) an A2L MEMORY_SEGMENT name with path
segments flows into the export filename; (b) a second export silently
overwrites the first."""
from common import *
from s19_app.tui.a2l import parse_a2l_file, extract_memory_segments
from s19_app.tui.segment_split_view import write_split_join_export, SegRow
base = Path(tempfile.mkdtemp(prefix="rwsplit_"))
a2l = base / "hostile.a2l"
a2l.write_text('''/begin PROJECT P ""
 /begin MODULE M ""
  /begin MOD_PAR ""
   /begin MEMORY_SEGMENT "x/../../../ESCAPED" ""
    DATA FLASH INTERN 0x1000 0x10 -1 -1 -1 -1 -1
   /end MEMORY_SEGMENT
  /end MOD_PAR
 /end MODULE
/end PROJECT
''')
data = parse_a2l_file(a2l)
segs = extract_memory_segments(data.get("sections") or [])
print("parsed segment block_name:", [s.get("block_name") for s in segs], "base/size:", [(s.get("base"), s.get("size")) for s in segs])
name = str(segs[0].get("block_name")) if segs else "x/../../../ESCAPED"
dest = base / ".s19tool" / "workarea" / "splits"; dest.mkdir(parents=True)
mem = {0x1000 + i: i for i in range(16)}
written = write_split_join_export(mem, [SegRow(name, "a2l", 0x1000, 0x10)], mode="split", gap="fill", pad_byte=0xFF, fmt="s19", stem="prg", dest_dir=dest)
for w in written:
    print("written:", w, "| resolved:", w.resolve(), "| inside dest:", w.resolve().is_relative_to(dest.resolve()))
# (b) overwrite
row = SegRow("range_00", "ranges", 0x1000, 0x10)
p1 = write_split_join_export(mem, [row], mode="split", gap="fill", pad_byte=0xFF, fmt="s19", stem="prg", dest_dir=dest)[0]
first = p1.read_text()
mem2 = {k: 0xEE for k in mem}
p2 = write_split_join_export(mem2, [row], mode="split", gap="fill", pad_byte=0xFF, fmt="s19", stem="prg", dest_dir=dest)[0]
print("second export path == first:", p1 == p2, "| first content survived:", p2.read_text() == first)
