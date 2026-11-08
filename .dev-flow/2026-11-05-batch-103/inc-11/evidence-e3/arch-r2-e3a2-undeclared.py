"""Inc 11 E3 architect round 2: of the corpus tags whose conversion word names a method, how many name a COMPU_METHOD
that the file does not declare at all (REF's own words)? Compares with e3a2-named's residual 878 identity fallbacks on
CANON2. Counts only. Run on <runner> only.

    python -I e3a2-undeclared.py <scripts dir> <files_dir> <manifest.tsv>
"""
import hashlib
import importlib.util
import pathlib
import sys

sdir, fdir, manifest = (pathlib.Path(x) for x in sys.argv[1:4])
spec = importlib.util.spec_from_file_location("fu", sdir / "e3a2-followup.py")
src = (sdir / "e3a2-followup.py").read_text(encoding="utf-8")
ns: dict = {}
exec(compile(src.split("\nC = collections.Counter()")[0].replace(
    "repo = pathlib.Path(sys.argv[1]); fdir = pathlib.Path(sys.argv[2]); manifest = pathlib.Path(sys.argv[3])", ""),
    "fu", "exec"), ns)
ref_lex, ref_tree, walk, own = ns["ref_lex"], ns["ref_tree"], ns["walk"], ns["own"]
HDR = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}
KEYWORDS = set("""ADDRESS_TYPE ARRAY_SIZE BIT_MASK BYTE_ORDER DISCRETE DISPLAY_IDENTIFIER ECU_ADDRESS ECU_ADDRESS_EXTENSION
ERROR_MASK FORMAT LAYOUT MATRIX_DIM MAX_REFRESH MODEL_LINK PHYS_UNIT READ_WRITE REF_MEMORY_SEGMENT SYMBOL_LINK
CALIBRATION_ACCESS COMPARISON_QUANTITY ENCODING EXTENDED_LIMITS GUARD_RAILS NUMBER READ_ONLY STEP_SIZE
DATA_SIZE LENGTH DATA_TYPE FUNCTION COMPU_METHOD FORMULA UNIT LOWER_LIMIT UPPER_LIMIT VIRTUAL CALIBRATABLE DEPOSIT
MONOTONY AXIS_PTS_REF FIX_AXIS_PAR FIX_AXIS_PAR_DIST CURVE_AXIS_REF MAX_GRAD READ_WRITE""".split())
KW = KEYWORDS
seen, with_method, undeclared, files = set(), 0, 0, 0
for ln in manifest.read_text(encoding="utf-8").splitlines()[1:]:
    parts = ln.split("\t")
    p = fdir / f"{parts[0]}.a2l"
    if not p.exists():
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != parts[6] or h in seen:
        continue
    seen.add(h)
    files += 1
    root = ref_tree(ref_lex(p.read_bytes().decode("utf-8", errors="replace")))
    methods = {own(n)[0][1] for n in walk(root) if n["name"] == "COMPU_METHOD" and own(n)}
    for n in walk(root):
        if n["name"] not in HDR:
            continue
        seq = []
        for k, x in n["items"]:
            if k == "child":
                break
            seq.append(x)
        pos = 2 if len(seq) > 1 and seq[1][0] == "STR" else 1
        hdr = []
        for t in seq[pos:]:
            if len(hdr) == HDR[n["name"]] or (t[0] == "ID" and t[1] in KW):
                break
            hdr.append(t[1])
        if len(hdr) != HDR[n["name"]]:
            continue
        conv = hdr[1] if n["name"] == "MEASUREMENT" else hdr[4]
        if conv == "NO_COMPU_METHOD":
            continue
        with_method += 1
        undeclared += conv not in methods
print(f"[corpus] files {files}; tags with a conversion method {with_method}; naming a COMPU_METHOD the file does not "
      f"declare {undeclared}")
