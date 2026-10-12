"""batch-91 inc-001 — convert the RESERVED block TC-617..TC-648 to LIVE in place.

Same id, same line position, no duplicates: the RESERVED record is REPLACED by
the LIVE one (statement from the LLR's pinned law, nodes derived by
inc001_derive_nodes.py with the shared library). Also repairs the `_meta`
high-water mark, which the P0 reservation moved past without updating (G7 was
red on the untouched tree: AT-284..287 and TC-617..650 sit above the declared
283/616 while `next_free` already acknowledged them).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.id_registry import dump_entry

ROOT = Path(__file__).resolve().parents[3]
NODES = json.loads((Path(__file__).with_name("inc001_nodes.json")).read_text(encoding="utf-8"))

STATEMENTS = {
    "TC-617": "The S-record parser parses S0-S9 with per-record checksum validation, plus overlap and out-of-order detection (LLR-122.1).",
    "TC-618": "The Intel HEX parser handles record types 00-05 with checksums and builds the memory map (LLR-122.1).",
    "TC-619": "The emitters round-trip a parsed image back to records (LLR-122.1).",
    "TC-620": "The range index answers membership in sorted ranges (LLR-122.1).",
    "TC-621": "Parsed images yield their contiguous-range/gap computation and address census (LLR-122.1).",
    "TC-622": "The A2L engine enriches raw and physical values via datatype/COMPU_METHOD (LLR-122.2).",
    "TC-623": "The A2L engine parses ASAP2 structure with missing-length records handled (LLR-122.2).",
    "TC-624": "The A2L engine handles the record-layout length (LLR-122.2).",
    "TC-625": "The A2L engine parses ASAP2 structure and extracts tags behind the TUI viewer (LLR-122.2).",
    "TC-626": "The A2L engine validates its parsed structure internally (LLR-122.2).",
    "TC-627": "The MAC parser reads TAG=hexaddr lines behind the MAC View (LLR-122.3).",
    "TC-628": "The MAC parser's diagnostics collect-don't-abort: malformed lines are kept and flagged (LLR-122.3).",
    "TC-629": "The CRC kernel computes the parameterized Rocksoft kernel (width 8-64) with its catalogue presets (LLR-122.4).",
    "TC-630": "The CRC designer loads/saves *.crc.json templates with the collect-don't-abort loader and encodes/decodes the check word per its store width and endianness (LLR-122.4).",
    "TC-631": "The host surface unloads the image on U (LLR-122.5).",
    "TC-632": "The host surface's undo/redo UX behaves as shipped (LLR-122.5).",
    "TC-633": "The host surface's universal paste behaves as shipped (LLR-122.5).",
    "TC-634": "The capped text area bounds its contents as shipped (LLR-122.5).",
    "TC-635": "The host surface's discoverability arms behave as shipped (LLR-122.5).",
    "TC-636": "Filenames are markup-safe in the TUI (LLR-122.5).",
    "TC-637": "The TUI survives the hostile map arms (LLR-122.5).",
    "TC-638": "The tui helpers/services seams behave as shipped (LLR-122.5).",
    "TC-639": "The map click chain behaves as shipped (LLR-122.5).",
    "TC-640": "The memory-map entropy merge behaves as shipped (LLR-122.5).",
    "TC-641": "The patch dual entry behaves as shipped (LLR-122.5).",
    "TC-642": "The flow execution and multi-image UI arms behave as shipped (LLR-122.5).",
    "TC-643": "The N8 legend and logwidth scope behave as shipped (LLR-122.5).",
    "TC-644": "The report logging/progress/off-thread behaviors behave as shipped (LLR-122.5).",
    "TC-645": "The workspace variants behave as shipped (LLR-122.5).",
    "TC-646": "The evidence packs and the pilot GIFs example behave as shipped (LLR-122.5).",
    "TC-647": "The sync-evidence tooling behaves as shipped (LLR-122.5).",
    "TC-648": "The command-line entry behaves as shipped (LLR-122.5).",
}

CONVERT = {f"TC-{n}" for n in range(617, 649)}
assert set(CONVERT) == set(STATEMENTS) == set(NODES)

path = ROOT / "AT-TC-REGISTRY.jsonl"
original = path.read_text(encoding="utf-8")
lines = original.splitlines()

meta = json.loads(lines[0])["_meta"]
meta["high_water"] = {"AT": 287, "TC": 650}
meta["next_free"] = {"AT": 288, "TC": 651}
lines[0] = json.dumps({"_meta": meta}, ensure_ascii=False)

converted = 0
for i in range(1, len(lines)):
    if not lines[i].strip():
        continue
    record = json.loads(lines[i])
    if record.get("id") in CONVERT:
        assert record["status"] == "RESERVED" and record["reserved_by"] == "batch-91", record["id"]
        tc = record["id"]
        lines[i] = dump_entry({
            "id": tc,
            "space": "TC",
            "status": "LIVE",
            "conforming": True,
            "origin": "batch-91",
            "statement": STATEMENTS[tc],
            "nodes": NODES[tc],
        })
        converted += 1

assert converted == 32, converted
new_text = "\n".join(lines) + ("\n" if original.endswith("\n") else "")

# No id moved position; no duplicates introduced.
old_ids = [json.loads(l).get("id") for l in original.splitlines()[1:] if l.strip()]
new_ids = [json.loads(l).get("id") for l in lines[1:] if l.strip()]
assert old_ids == new_ids and len(new_ids) == len(set(new_ids))

path.write_text(new_text, encoding="utf-8")
print(f"converted {converted} RESERVED -> LIVE; _meta high_water AT 283->287, TC 616->650")
