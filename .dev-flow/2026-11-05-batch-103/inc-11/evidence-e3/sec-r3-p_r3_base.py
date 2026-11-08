"""E3 round-3 security probe (Inc 11), runner only, against the read-only e07fb00 clone (~/work/s19_app). Modes:
  addr  - the base reading of the split-address shape `ECU_ADDRESS 0x1C2D 3E00` (which the corrected design keeps,
          per sec-r3-p_r3_model.py [S3-SURPLUS]) and what the write consumers do with it: the Patch Editor symbol
          entry (services/change_service.resolve_symbol_entry) and the picker row behind "Use parameter".
  bo    - a BYTE_ORDER word outside MSB_FIRST / MSB_LAST / BIG_ENDIAN / LITTLE_ENDIAN (a typo, and ASAP2 1.7's
          MSB_FIRST_MSW_LAST) under a MOD_COMMON MSB_FIRST: the tag's effective byte order and the symbol entry's bytes.
  gen   - write the hostile big-body file for 'mem' (one MEASUREMENT whose own words fill the file).
  mem   - peak RSS of one fresh process: 'base' = the e07fb00 parse_a2l_file; 'words' = the e07fb00 tree
          (build_section_tree) plus the graph's _section_words list for the biggest tag section, held as
          (word, line) tuples -- the transient hold the corrected design adds (graph node _section_words).
Every A2L text is synthetic. No corpus file is read here."""
import io, sys, resource, os
RH = os.environ["B103_RUNNER_HOME"]  # the runner account home, set by sec-r3-run.sh before HOME is isolated
sys.path.insert(0, RH + "/work/s19_app")
MODE = sys.argv[1]

HDR_HEAD = """ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_FIRST
/end MOD_COMMON
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
"""
HDR_TAIL = "/end MODULE\n/end PROJECT\n"


class FakePath:
    def __init__(self, text, name):
        self.text, self.name = text, name
    def open(self, *a, **k):
        return io.StringIO(self.text)
    def __str__(self):
        return self.name


if MODE in ("addr", "bo"):
    import s19_app
    from s19_app.tui import a2l as A
    from s19_app.tui.services.change_service import resolve_symbol_entry
    from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
    print("s19_app imported from the read-only clone:", s19_app.__file__.startswith(RH + "/work/s19_app/"))

    def run(label, body):
        text = HDR_HEAD + '/begin MEASUREMENT X ""\nUWORD CM_ID 0 0 0 65535\n' + body + "\n/end MEASUREMENT\n" + HDR_TAIL
        d = A.parse_a2l_file(FakePath(text, "mem.a2l"))
        t = d["tags"][0]
        a = t.get("address")
        print(f"[{label}] base tag: address={hex(a) if isinstance(a, int) else a} length={t.get('length')} "
              f"effective_byte_order={t.get('effective_byte_order')} errors={d['errors']}")
        res = resolve_symbol_entry("X", "4660", d)
        e = res.entry
        print(f"[{label}] symbol entry (Patch Editor, value 4660): "
              + (f"address=0x{e.address:X} bytes={bytes(e.encoded_bytes).hex()}" if e else "refused")
              + f" issues={[i.message for i in res.issues]}")
        en = A.enrich_a2l_tags_with_values(d, {k: 0x11 for k in range(0x0, 0x20000)})
        pk = A2LParameterPicker(mode="highlight")
        pk.set_parameters([r for r in en if isinstance(r.get("address"), int)])
        for name, (addr, size, fmt) in pk._param_rows.items():
            print(f"[{label}] picker row ('Use parameter'): address=0x{addr:X} size={size} fmt={fmt!r}")

    if MODE == "addr":
        run("B3-ADDR ecu 0x1C2D 3E00", "ECU_ADDRESS 0x1C2D 3E00")
        run("B3-ADDR ecu 0x1C2D / 3E00 (next line)", "ECU_ADDRESS 0x1C2D\n3E00")
        run("B3-ADDR ecu 0x1C2D3E00 (whole, control)", "ECU_ADDRESS 0x1C2D3E00")
    else:
        run("B3-BO MSB_FIRST (control)", "ECU_ADDRESS 0x1000\nBYTE_ORDER MSB_FIRST")
        run("B3-BO MSB_LAST (control)", "ECU_ADDRESS 0x1000\nBYTE_ORDER MSB_LAST")
        run("B3-BO MSB_FRIST (typo)", "ECU_ADDRESS 0x1000\nBYTE_ORDER MSB_FRIST")
        run("B3-BO MSB_LAST_MSW_FIRST (ASAP2 1.7 word)", "ECU_ADDRESS 0x1000\nBYTE_ORDER MSB_LAST_MSW_FIRST")

elif MODE == "gen":
    path, n = sys.argv[2], int(sys.argv[3])
    with open(path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(HDR_HEAD + '/begin MEASUREMENT BIG ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x10\n')
        for i in range(n):
            fh.write(" ab1 ab2 ab3 ab4 ab5 ab6 ab7 ab8\n")
        fh.write("/end MEASUREMENT\n" + HDR_TAIL)
    print(f"[GEN] {path} lines={n} bytes={os.path.getsize(path)}")

elif MODE == "mem":
    from pathlib import Path
    from s19_app.tui import a2l as A
    kind, path = sys.argv[2], Path(sys.argv[3])
    size = path.stat().st_size
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if kind == "base":
        d = A.parse_a2l_file(path)
        held = len(d["tags"])
    else:
        sections, errors = A.build_section_tree(path)
        biggest, stack = None, list(sections)
        while stack:
            s = stack.pop()
            stack.extend(s.get("children") or [])
            if s.get("name") in ("MEASUREMENT", "CHARACTERISTIC"):
                if biggest is None or len(s.get("lines") or []) > len(biggest.get("lines") or []):
                    biggest = s
        lines = biggest.get("lines") or []
        words = [(w, ln) for ln, line in enumerate(lines, 1) for w in line.split(" ") if w]
        held = len(words)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KiB on Linux
    print(f"[MEM {kind}] file_bytes={size} held_items={held} peak_rss_MB={peak / 1024:.1f} "
          f"import_baseline_MB={before / 1024:.1f} peak_per_file_byte={peak * 1024 / size:.1f}")
