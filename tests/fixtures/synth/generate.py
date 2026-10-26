"""Batch-99 synthetic fixture corpus generator (HLR-152, LLR-152.1/152.2).

Summary:
    Deterministically writes a small corpus of S19, Intel HEX, MAC and A2L
    fixtures plus ``manifest.json`` (per file: SHA-256, coverage classes,
    expected data bytes as contiguous runs, verdict and header/terminator
    facts). Generation is pure: fixed seeds, no timestamps, no host paths —
    two runs produce byte-identical output (TC-B99-01).

    The A2L pair pins the byte-order and conversion expectations the batch's
    A2L increments assert against (PQ-4 of ``design/PDR-qa.md``); the expected
    physical values live in the manifest under ``a2l_expect``.

CLI:
    python tests/fixtures/synth/generate.py --out <dir>
        write the corpus and manifest into <dir>
    python tests/fixtures/synth/generate.py --check [--corpus <dir>]
        regenerate into a temp dir, compare byte for byte with the committed
        corpus (default: the directory holding this script), then read every
        committed S19/HEX file with the independent reader and compare bytes
        and load facts with the manifest. Prints ``checked N files`` and
        exits 0; on the first difference prints the file name and exits 1.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.support.independent_reader import read_hex, read_s19  # noqa: E402

#: Address-field width per S19 record type.
_S19_ADDR_LEN = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}


def _bytes(seed: int, count: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(count))


def s19_record(rectype: str, addr: int, payload: bytes = b"") -> str:
    """Summary: render one S19 record line with a correct checksum."""
    width = _S19_ADDR_LEN[rectype]
    body = bytes([width + len(payload) + 1]) + addr.to_bytes(width, "big") + payload
    return "S" + rectype + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def hex_record(rectype: int, addr: int, payload: bytes = b"") -> str:
    """Summary: render one Intel HEX record line with a correct checksum."""
    body = bytes([len(payload)]) + addr.to_bytes(2, "big") + bytes([rectype]) + payload
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def _runs(data: dict) -> dict:
    out = {}
    anchor = None
    for addr in sorted(data):
        if anchor is not None and addr == last + 1:
            out[anchor] += f"{data[addr]:02X}"
        else:
            anchor = f"0x{addr:x}"
            out[anchor] = f"{data[addr]:02X}"
        last = addr
    return out


def _s19_content(header, records, s5=None, term=None, trailing=()):
    lines = []
    if header is not None:
        lines.append(s19_record("0", 0, header))
    data = {}
    for rectype, addr, payload in records:
        lines.append(s19_record(rectype, addr, payload))
        for i, b in enumerate(payload):
            data[addr + i] = b
    if s5 is not None:
        lines.append(s19_record("5", s5))
    if term is not None:
        lines.append(s19_record(term[0][1], term[1]))
    lines.extend(trailing)
    return "\n".join(lines) + "\n", data


def _hex_content(records, trailing=()):
    lines = [hex_record(t, a, p) for t, a, p in records]
    lines.extend(trailing)
    data = {}
    upper = 0
    seg = 0
    mode = "lin"
    for rectype, addr, payload in records:
        if rectype == 0:
            for i, b in enumerate(payload):
                full = (upper << 16) + addr + i if mode == "lin" else seg + ((addr + i) & 0xFFFF)
                data[full] = b
        elif rectype == 2:
            seg = int.from_bytes(payload, "big") << 4
            mode = "seg"
        elif rectype == 4:
            upper = int.from_bytes(payload, "big")
            mode = "lin"
    return "\n".join(lines) + "\n", data


def _a2l_text() -> str:
    intp_entries = "\n".join(f"      {i} {i * 2.5}" for i in range(26))
    return f"""/begin PROJECT SYNTH_B99 "Synthetic corpus project for batch-99"
  /begin HEADER
    VERSION "1.0"
    PROJECT_NO 99
  /end HEADER

  /begin MODULE SYNTH_B99_MOD "Synthetic ECU module"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
      ALIGNMENT_BYTE 1
      ALIGNMENT_WORD 2
      ALIGNMENT_LONG 4
      ALIGNMENT_FLOAT32_IEEE 4
    /end MOD_COMMON

    /begin MOD_PAR ""
      EPK "S19TOOL_SYNTH_B99"
    /end MOD_PAR

    /begin RECORD_LAYOUT RL_U16_NO_BO
      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin COMPU_METHOD CM_IDENT "%6.2" IDENTICAL "%6.2" ""
      COEFFS 0 1 0 0 0 1
    /end COMPU_METHOD

    /begin COMPU_METHOD RAT_FUNC_DIV_10 "%6.2" RAT_FUNC "%6.2" ""
      COEFFS 0 10 0 0 0 1
    /end COMPU_METHOD

    /begin COMPU_METHOD CM_LINEAR_MUL_2 "%6.2" LINEAR "%6.2" ""
      COEFFS_LINEAR 2.0 0.0
    /end COMPU_METHOD

    /begin COMPU_METHOD CM_TAB_INTP "%6.2" TAB_INTP "%6.2" ""
      COMPU_TAB_REF TAB_INTP_TBL
    /end COMPU_METHOD

    /begin COMPU_METHOD CM_TAB_NOINTP "%6.2" TAB_NOINTP "%6.2" ""
      COMPU_TAB_REF TAB_NOINTP_TBL
    /end COMPU_METHOD

    /begin COMPU_METHOD CM_TAB_INTP_SPARSE "%6.2" TAB_INTP "%6.2" ""
      COMPU_TAB_REF TAB_INTP_SPARSE_TBL
    /end COMPU_METHOD

    /begin COMPU_TAB TAB_INTP_TBL
      "intp table, 2.5 PHYS per raw step"
      TAB_INTP
      26
{intp_entries}
      DEFAULT_VALUE "0"
    /end COMPU_TAB

    /begin COMPU_TAB TAB_NOINTP_TBL
      "nointp table, entries 10 15 20"
      TAB_NOINTP
      3
      0 10.0
      1 15.0
      2 20.0
      DEFAULT_VALUE "0"
    /end COMPU_TAB

    /begin COMPU_TAB TAB_INTP_SPARSE_TBL
      "sparse intp table, bend at raw 25 (0->0, 25->10, 100->100)"
      TAB_INTP
      3
      0 0.0
      25 10.0
      100 100.0
      DEFAULT_VALUE "0"
    /end COMPU_TAB

    /begin CHARACTERISTIC SYM_U16_MSB "2-byte MSB symbol, no BYTE_ORDER of its own"
      VALUE 0x2000 RL_U16_NO_BO 0 CM_IDENT 0 65535
    /end CHARACTERISTIC
    /begin CHARACTERISTIC RAT_FUNC_SYM "RAT_FUNC INT equals 10 times PHYS"
      VALUE 0x2002 RL_U16_NO_BO 0 RAT_FUNC_DIV_10 0 100
    /end CHARACTERISTIC
    /begin CHARACTERISTIC TAB_INTP_SYM "TAB_INTP symbol, 2.5 PHYS per raw"
      VALUE 0x2004 RL_U16_NO_BO 0 CM_TAB_INTP -10 100
    /end CHARACTERISTIC
    /begin CHARACTERISTIC TAB_NOINTP_SYM "TAB_NOINTP symbol, entries 10 15 20"
      VALUE 0x2006 RL_U16_NO_BO 0 CM_TAB_NOINTP 0 30
    /end CHARACTERISTIC
    /begin CHARACTERISTIC LINEAR_MUL_2 "LINEAR PHYS equals 2 times RAW, MSB_LAST"
      VALUE 0x2008 RL_U16_NO_BO 0 CM_LINEAR_MUL_2 0 100
      BYTE_ORDER MSB_LAST
    /end CHARACTERISTIC
    /begin CHARACTERISTIC TAB_INTP_SPARSE_SYM "sparse TAB_INTP, raw 50 decodes to 40.0"
      VALUE 0x200C RL_U16_NO_BO 0 CM_TAB_INTP_SPARSE 0 100
    /end CHARACTERISTIC

    /begin GROUP GRP_SYNTH_B99 "GRP_SYNTH_B99 group"
      /begin REF_CHARACTERISTIC
      SYM_U16_MSB
      RAT_FUNC_SYM
      TAB_INTP_SYM
      TAB_NOINTP_SYM
      LINEAR_MUL_2
      TAB_INTP_SPARSE_SYM
      /end REF_CHARACTERISTIC
    /end GROUP
  /end MODULE
/end PROJECT
"""


def _a2l_expect() -> dict:
    return {
        "byte_order": "MSB_FIRST",
        "symbols": {
            "SYM_U16_MSB": {
                "address": "0x2000",
                "bytes": "1011",
                "raw": 4113,
                "physical": 4113.0,
                "encode": [{"physical": 4113, "bytes": "1011"}],
            },
            "RAT_FUNC_SYM": {
                "address": "0x2002",
                "bytes": "012C",
                "raw": 300,
                "physical": 30.0,
                "encode": [{"physical": 30, "raw": 300}, {"physical": 25, "raw": 250}],
            },
            "TAB_INTP_SYM": {
                "address": "0x2004",
                "bytes": "0002",
                "raw": 2,
                "physical": 5.0,
                "grid": {"typed": 5.0, "expected_raw": 2, "written_physical": 5.0},
                "off_grid": {
                    "typed": 3.4,
                    "expected_raw": 1,
                    "written_physical": 2.5,
                    "flag_names": "2.5",
                },
                "refused": [-50.0, 500.0],
            },
            "TAB_NOINTP_SYM": {
                "address": "0x2006",
                "bytes": "0001",
                "raw": 1,
                "physical": 15.0,
                "typed_refused": 13.0,
                "named_nearest": [10.0, 15.0],
            },
            "LINEAR_MUL_2": {
                "address": "0x2008",
                "bytes": "0F00",
                "raw": 15,
                "physical": 30.0,
                "byte_order": "MSB_LAST",
                "encode": [{"physical": 30, "bytes": "0F00"}],
            },
            "TAB_INTP_SPARSE_SYM": {
                "address": "0x200C",
                "bytes": "0032",
                "raw": 50,
                "physical": 40.0,
                "interior_exact": {
                    "typed": 40.0,
                    "expected_raw": 50,
                    "written_physical": 40.0,
                },
                "interior_fractional": {
                    "typed": 3.9,
                    "expected_raw": 10,
                    "written_physical": 4.0,
                    "flag_names": "4.0",
                },
                "endpoints": [
                    {"typed": 0.0, "expected_raw": 0},
                    {"typed": 100.0, "expected_raw": 100},
                ],
                "refused": [150.0],
            },
        },
    }


def build_corpus() -> dict:
    """Summary: build the whole corpus in memory.

    Returns:
        dict: file name -> exact file content (``manifest.json`` included).
    """
    files = {}
    entries = []

    def add_s19(name, classes, content, data, header, terminator, s5_count, verdict="ok",
                records_after_end=0, **extra):
        files[name] = content
        entry = {
            "name": name,
            "format": "s19",
            "class": classes,
            "sha256": hashlib.sha256(content.encode("ascii")).hexdigest(),
            "data": _runs(data),
            "verdict": verdict,
            "header": header.hex().upper() if header is not None else None,
            "terminator": terminator,
            "s5_count": s5_count,
            "eof_seen": terminator is not None,
            "records_after_end": records_after_end,
        }
        entry.update(extra)
        entries.append(entry)

    def add_hex(name, classes, content, data, terminator, eof_seen, records_after_end=0, verdict="ok"):
        files[name] = content
        entries.append({
            "name": name,
            "format": "hex",
            "class": classes,
            "sha256": hashlib.sha256(content.encode("ascii")).hexdigest(),
            "data": _runs(data),
            "verdict": verdict,
            "header": None,
            "terminator": terminator,
            "s5_count": None,
            "eof_seen": eof_seen,
            "records_after_end": records_after_end,
        })

    def add_plain(name, fmt, classes, content, verdict="ok", **extra):
        files[name] = content
        entry = {
            "name": name,
            "format": fmt,
            "class": classes,
            "sha256": hashlib.sha256(content.encode("ascii")).hexdigest(),
            "verdict": verdict,
        }
        entry.update(extra)
        entries.append(entry)

    edge1 = _bytes(1521, 16)
    content, data = _s19_content(
        b"SYNTH-B99-S1",
        [("1", 0xFFF0, edge1[:8]), ("1", 0xFFF8, edge1[8:])],
        s5=2,
        term=("S9", 0xFFF0),
    )
    add_s19("synth_s1.s19", ["s19.s1", "s19.s5", "s19.term.s9"], content, data,
            b"SYNTH-B99-S1", ["S9", 0xFFF0], 2)

    edge2 = _bytes(1522, 32)
    content, data = _s19_content(
        b"SYNTH-B99-S2",
        [("2", 0xFFFFE0, edge2[:16]), ("2", 0xFFFFF0, edge2[16:])],
        s5=2,
        term=("S8", 0x010000),
    )
    add_s19("synth_s2.s19", ["s19.s2", "s19.s5", "s19.term.s8"], content, data,
            b"SYNTH-B99-S2", ["S8", 0x010000], 2)

    block3 = _bytes(1523, 16)
    content, data = _s19_content(
        b"SYNTH-B99-S3",
        [("3", 0x80001000, block3)],
        s5=1,
        term=("S7", 0x80001000),
    )
    add_s19("synth_s3.s19", ["s19.s3", "s19.s0", "s19.s5", "s19.term.s7"], content, data,
            b"SYNTH-B99-S3", ["S7", 0x80001000], 1)

    content, data = _s19_content(b"SYNTH-B99-S0-ONLY", [], term=("S9", 0x0000))
    add_s19("synth_s0_only.s19", ["s19.s0_only"], content, data,
            b"SYNTH-B99-S0-ONLY", ["S9", 0x0000], None)

    mac_block = _bytes(1524, 16)
    content, data = _s19_content(None, [("1", 0x1000, mac_block)], term=("S9", 0x1000))
    add_s19("synth_mac.s19", ["s19.s1", "s19.term.s9"], content, data,
            None, ["S9", 0x1000], None, paired="synth_mac.mac")

    add_plain("synth_mac.mac", "mac", ["mac.pair"],
              "; Synthetic MAC\nSYNTH_INSIDE=1000\nSYNTH_OUTSIDE=7FFF0\n",
              paired="synth_mac.s19")

    a2l_block = bytes.fromhex("1011012C000200010F0000000032")
    content, data = _s19_content(None, [("3", 0x2000, a2l_block)], term=("S9", 0x2000))
    add_s19("synth_a2l.s19", ["s19.s3"], content, data,
            None, ["S9", 0x2000], None, paired="synth_a2l.a2l",
            a2l_expect=_a2l_expect())

    add_plain("synth_a2l.a2l", "a2l", ["a2l.pair"], _a2l_text(), paired="synth_a2l.s19")

    first = _bytes(1525, 16)
    second = _bytes(1526, 8)
    merged = {0x3000 + i: b for i, b in enumerate(first)}
    for i, b in enumerate(second):
        merged[0x3008 + i] = b
    content, _ = _s19_content(
        None,
        [("1", 0x3000, first), ("1", 0x3008, second)],
        s5=2,
        term=("S9", 0x3000),
    )
    add_s19("synth_overlap.s19", ["defect.s19_overlap_diff"], content, merged,
            None, ["S9", 0x3000], 2, verdict="defect:overlap")

    truncated = _bytes(1527, 16)
    content, data = _s19_content(None, [("1", 0x4000, truncated)])
    add_s19("synth_no_terminator.s19", ["defect.s19_no_terminator"], content, data,
            None, None, None, verdict="defect:s19_no_terminator")

    wrong_s5 = _bytes(1528, 24)
    content, data = _s19_content(
        None,
        [("1", 0x5000, wrong_s5[:16]), ("1", 0x5010, wrong_s5[16:])],
        s5=3,
        term=("S9", 0x5000),
    )
    add_s19("synth_wrong_s5.s19", ["defect.s19_wrong_s5"], content, data,
            None, ["S9", 0x5000], 3, verdict="defect:s19_wrong_s5")

    after_term = _bytes(1529, 8)
    trailing = [s19_record("1", 0x6100, _bytes(1530, 8))]
    content, data = _s19_content(None, [("1", 0x6000, after_term)], term=("S9", 0x6000),
                                 trailing=trailing)
    add_s19("synth_after_terminator.s19", ["defect.s19_after_terminator"], content, data,
            None, ["S9", 0x6000], None, verdict="defect:s19_after_terminator",
            records_after_end=1)

    content, data = _hex_content([
        (4, 0, (1).to_bytes(2, "big")),
        (0, 0xFF00, _bytes(1531, 0x80)),
        (0, 0xFF80, _bytes(1541, 0x80)),
        (0, 0x0000, _bytes(1532, 16)),
        (5, 0, (0x10000).to_bytes(4, "big")),
        (1, 0, b""),
    ])
    add_hex("synth_hex_basic.hex", ["hex.t00", "hex.t01", "hex.t04", "hex.t05", "hex.64k_boundary"],
            content, data, ["HEX05", 0x10000], True)

    content, data = _hex_content([
        (2, 0, (0x1000).to_bytes(2, "big")),
        (0, 0xFFF0, _bytes(1533, 0x20)),
        (1, 0, b""),
    ])
    add_hex("synth_hex_seg.hex", ["hex.t00", "hex.t01", "hex.t02", "hex.wrap"],
            content, data, None, True)

    content, data = _hex_content([
        (4, 0, (0).to_bytes(2, "big")),
        (0, 0x0100, _bytes(1534, 16)),
    ])
    add_hex("synth_hex_no_eof.hex", ["defect.hex_no_eof"], content, data, None, False,
            verdict="defect:hex_no_eof")

    content, data = _hex_content(
        [(0, 0x0200, _bytes(1535, 8)), (1, 0, b"")],
        trailing=[hex_record(0, 0x0300, _bytes(1536, 8))],
    )
    add_hex("synth_hex_after_eof.hex", ["defect.hex_after_eof"], content, data, None, True,
            records_after_end=1, verdict="defect:hex_after_eof")

    manifest = json.dumps({"files": entries}, indent=2) + "\n"
    files["manifest.json"] = manifest
    return files


def write_corpus(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, content in build_corpus().items():
        (out / name).write_text(content, encoding="ascii", newline="\n")


def _expand_runs(runs: dict) -> dict:
    data = {}
    for key, hex_bytes in runs.items():
        addr = int(key, 16)
        for i, b in enumerate(bytes.fromhex(hex_bytes)):
            data[addr + i] = b
    return data


def check_corpus(corpus: Path) -> int:
    """Summary: verify the committed corpus against a fresh generation.

    Args:
        corpus: directory holding the committed corpus files.

    Returns:
        int: 0 when every byte and every reader fact matches, 1 otherwise (the
        first differing file name is printed to stdout).
    """
    generated = build_corpus()
    committed = {
        p.name: p.read_bytes()
        for p in sorted(corpus.iterdir())
        if p.is_file() and p.name != Path(__file__).name
    }
    for name in sorted(set(generated) | set(committed)):
        gen_bytes = generated[name].encode("ascii") if name in generated else None
        com_bytes = committed.get(name)
        if gen_bytes != com_bytes:
            print(name)
            return 1
    manifest = json.loads(committed["manifest.json"].decode("ascii"))
    for entry in manifest["files"]:
        name = entry["name"]
        path = corpus / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            print(name)
            return 1
        if entry["format"] == "s19":
            image = read_s19(path)
        elif entry["format"] == "hex":
            image = read_hex(path)
        else:
            continue
        expected_header = (
            bytes.fromhex(entry["header"]) if entry["header"] is not None else None
        )
        expected_term = tuple(entry["terminator"]) if entry["terminator"] is not None else None
        if (
            image.data != _expand_runs(entry["data"])
            or image.header != expected_header
            or image.terminator != expected_term
            or image.s5_count != entry["s5_count"]
            or image.eof_seen != entry["eof_seen"]
            or image.records_after_end != entry["records_after_end"]
        ):
            print(name)
            return 1
    print(f"checked {len(manifest['files'])} files")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Batch-99 synthetic fixture corpus generator")
    parser.add_argument("--out", type=Path, help="write the corpus into this directory")
    parser.add_argument("--check", action="store_true",
                        help="compare a fresh generation with the committed corpus")
    parser.add_argument("--corpus", type=Path, default=None,
                        help="corpus directory for --check (default: this script's directory)")
    args = parser.parse_args(argv)
    if args.check:
        return check_corpus(args.corpus or Path(__file__).resolve().parent)
    if args.out is None:
        parser.error("--out or --check is required")
    write_corpus(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
