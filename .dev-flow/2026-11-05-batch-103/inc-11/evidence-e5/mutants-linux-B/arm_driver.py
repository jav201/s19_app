import base64
import hashlib
import os
import sys

TREE = "/tmp/b103-e5-11-mutB-rtx/tree"
os.chdir(TREE)
if TREE not in sys.path:
    sys.path.insert(0, TREE)

import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__, flush=True)

ARMS = {
    "CONTROL": {
        "file": "s19_app/tui/a2l.py",
        "old": "    if not _NUMBER_WORD_RE.fullmatch(word):",
        "new": "    if True:",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_34_hex_words",
    },
    "M01": {
        "file": "s19_app/tui/a2l.py",
        "old": "        if not quoted and word in _TAG_KEYWORD_ARITY:",
        "new": "        if False:",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_27_keyword_ends_header",
    },
    "M02": {
        "file": "s19_app/tui/a2l.py",
        "old": "        header_m = 6 if section_name == \"MEASUREMENT\" else 7",
        "new": "        header_m = 7 if section_name == \"MEASUREMENT\" else 6",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_28_short_header_error",
    },
    "M03": {
        "file": "s19_app/tui/a2l.py",
        "old": "    raw = (token or \"\").strip().upper()",
        "new": "    raw = (token or \"\").strip()",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_68_byte_order_words_no_error",
    },
    "M04": {
        "file": "s19_app/tui/a2l.py",
        "old": "    return int(word, 10)",
        "new": "    return int(word, 0)",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_35_decimal_words",
    },
    "M05": {
        "file": "s19_app/tui/a2l.py",
        "old": "_NUMBER_WORD_RE = re.compile(r\"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}\")",
        "new": "_NUMBER_WORD_RE = re.compile(r\"0[x][0-9A-Fa-f]{1,16}|[0-9]{1,20}\")",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_34_hex_words",
    },
    "M06": {
        "file": "s19_app/tui/a2l.py",
        "old": "_MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF",
        "new": "_MAX_ADDRESS = 0xFFFFFFFFFFFFFFFE",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_69_address_above_64_bits",
    },
    "M07": {
        "file": "s19_app/tui/a2l.py",
        "old": "    return smallest == largest, smallest, largest, no_number",
        "new": "    return True, smallest, largest, no_number",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_61_no_length_when_disagree",
    },
    "M08": {
        "file": "s19_app/tui/a2l_definition.py",
        "old": "    byte_length = tag.get(\"length\")",
        "new": "    byte_length = tag.get(\"length\") or 1",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_38_definition_stays_refused",
    },
    "M09": {
        "file": "s19_app/tui/a2l.py",
        "old": "    if kind in _CURVE_MAP_FAMILY:\r\n        values = list(byte_sizes)\r\n        if span is not None:\r\n            values.append(span)",
        "new": "    if kind in _CURVE_MAP_FAMILY:\r\n        values = list(byte_sizes)",
        "count": 1,
        "test": "tests/test_b103_a2l_reader_e5.py::test_e5_p15_length_zero_inline_axis_refusal_final",
    },
    "M10": {
        "file": "s19_app/tui/a2l.py",
        "old": "        if own_bo_word is not None and own_bo_order is None:\r\n            address_invalid = True",
        "new": "        if False:\r\n            address_invalid = True",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_68_byte_order_error",
    },
    "M11": {
        "file": "s19_app/tui/a2l.py",
        "old": "    _collect_typedefs(sections)",
        "new": "    _collect_typedefs([])",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_42_instance_forward_typedef_ref",
    },
    "M12": {
        "file": "s19_app/tui/a2l.py",
        "old": "                if base is None:\r\n                    return None",
        "new": "                if base is None:\r\n                    base = 1",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_45_instance_unresolvable_value_deposit_ref",
    },
    "M13": {
        "file": "s19_app/tui/a2l.py",
        "old": "\"length\": _bounded_length(length)",
        "new": "\"length\": length",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_r_a2l_read_46_span_length_bounds",
    },
    "M14": {
        "file": "s19_app/tui/a2l_extract.py",
        "old": "from .a2l import enrich_a2l_tags_with_values, extract_a2l_tags, extract_declared_spans",
        "new": "from .a2l import enrich_a2l_tags_with_values, extract_a2l_tags",
        "count": 1,
        "test": "tests/test_b103_a2l_reader.py::test_extract_declared_spans_is_public",
    },
    "P16": {
        "file": "s19_app/tui/a2l.py",
        "old": "                if span is not None:\r\n                    tag[\"length\"] = span",
        "new": "                if span is not None:\r\n                    tag[\"length\"] = element_size",
        "count": 1,
        "test": "tests/test_b103_a2l_reader_e5.py::test_e5_p16_curve_declared_uword_two_axis_points_full_span",
    },
    "P17a": {
        "file": "s19_app/tui/a2l_definition.py",
        "old": "        if char_type == \"VALUE\":\r\n            kind = \"enum\" if conversion_type == \"TAB_VERB\" else \"number\"",
        "new": "        if char_type == \"VALUE\":\r\n            kind = \"number\"",
        "count": 1,
        "test": "tests/test_b103_a2l_definition.py::test_r_a2l_def_2_1_tab_verb_with_long_identifier_on_its_own_line_is_an_enum",
    },
    "P17b": {
        "file": "s19_app/tui/a2l_definition.py",
        "old": "    if refusal is None and kind == \"enum\":",
        "new": "    if refusal is None and kind == \"enum\" and enum_table is not None:",
        "count": 1,
        "test": "tests/test_b103_a2l_definition.py::test_r_a2l_def_13_1_enum_with_no_table_is_refused",
    },
    "P17c": {
        "file": "s19_app/tui/a2l_definition.py",
        "old": "        elif table_form is None:",
        "new": "        elif False:",
        "count": 1,
        "test": "tests/test_b103_a2l_definition.py::test_r_a2l_def_13_2_dangling_table_is_refused",
    },
    "P17d": {
        "file": "s19_app/tui/a2l_definition.py",
        "old": "        elif not enum_entries:",
        "new": "        elif False:",
        "count": 1,
        "test": "tests/test_b103_a2l_definition.py::test_r_a2l_def_17_1_count_zero_is_refused",
    },
    "P18a": {
        "file": "s19_app/tui/a2l.py",
        "old": "                elif has_standing_size:",
        "new": "                elif False:",
        "count": 1,
        "test": "tests/test_b103_a2l_reader_e5.py::test_e5_p18_data_size_only_unresolved_span_uses_standing_size",
    },
    "P18b": {
        "file": "s19_app/tui/a2l.py",
        "old": "            if not agree:",
        "new": "            if True:",
        "count": 1,
        "test": "tests/test_b103_a2l_reader_e5.py::test_e5_p18_external_full_span_agrees_with_standing_data_size",
    },
}


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    arm_id = sys.argv[1]
    arm = ARMS[arm_id]
    path = os.path.join(TREE, arm["file"])
    original = open(path, "rb").read()
    text = original.decode("utf-8")
    count = text.count(arm["old"])
    print(f"== {arm_id} apply ==")
    print("file:", arm["file"])
    print("anchor:", repr(arm["old"]))
    print("applied_count:", count, "(expected", arm["count"], ")")
    assert count == arm["count"], f"anchor applied {count} times, expected {arm['count']}"
    mutated = text.replace(arm["old"], arm["new"], arm["count"])
    assert mutated != text, "mutation produced no change"
    open(path, "wb").write(mutated.encode("utf-8"))
    print("sha256_before:", sha256_of(original))
    print("sha256_after: ", sha256_of(mutated.encode("utf-8")))

    import pytest  # noqa: E402

    print(f"== {arm_id} test ==")
    rc = pytest.main(["-q", "-p", "no:cacheprovider", arm["test"]])
    print(f"== {arm_id} pytest exit code: {rc} ==")

    # Restore and verify hash.
    open(path, "wb").write(original)
    restored = open(path, "rb").read()
    ok = sha256_of(restored) == sha256_of(original)
    print(f"== {arm_id} restore ==")
    print("restore_hash_ok:", ok)
    print("sha256_restored:", sha256_of(restored))
    assert ok, "restore hash mismatch"
    return rc


if __name__ == "__main__":
    sys.exit(main())
