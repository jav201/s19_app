from pathlib import Path

from tests.support.b103_a2l_ref import _section_words
from tests.test_b103_a2l_reader import REPO_ROOT
from tests.test_b103_a2l_reader_coverage import _corpus, _corpus_bytes, _ref_read
from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file

scratch = Path("/tmp/b103-e5-11-p16/probe")
scratch.mkdir(exist_ok=True)

path = REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"
text = path.read_text(encoding="utf-8", errors="replace")
mixed = "".join(
    line + ("\r\n" if i % 3 == 0 else "\r" if i % 3 == 1 else "\n")
    for i, line in enumerate(text.split("\n"))
)
mixed_path = scratch / "mixed.a2l"
mixed_path.write_text(mixed, encoding="utf-8")
normalized = mixed_path.read_text(encoding="utf-8", errors="replace")
print("MIXED normalized equals LF:", normalized == text)
if normalized != text:
    index = next(i for i, (a, b) in enumerate(zip(normalized, text)) if a != b)
    print("MIXED lengths:", len(normalized), len(text), "first difference:", index)
    start = max(0, index - 60)
    print("MIXED normalized slice:", repr(normalized[start:index + 60]))
    print("MIXED LF slice:", repr(text[start:index + 60]))

from tests.test_b103_a2l_reader import _assert_sections_equal, _assert_spans_equal, _assert_tags_equal
from tests.test_b103_a2l_reader_coverage import _cov_errors_equal, _spans

ref = _ref_read()
for entry in _corpus():
    raw = _corpus_bytes(entry)
    corpus_path = scratch / f"{entry['key']}.a2l"
    corpus_path.write_bytes(raw)
    data = parse_a2l_file(corpus_path)
    if data["errors"] == ["File is UTF-16 encoded; save it as UTF-8 and load it again."]:
        continue
    reading = ref(raw.decode("utf-8", errors="replace"))
    try:
        _assert_sections_equal(data["sections"], reading["sections"])
        _assert_tags_equal(data["tags"], reading["tags"])
        _assert_spans_equal(_spans(data), reading["spans"])
        assert _cov_errors_equal(data["errors"], reading["errors"])
    except AssertionError:
        print("CORPUS first failure:", entry["key"])
        print("CORPUS reader tags:", data["tags"])
        print("CORPUS REF tags:", reading["tags"])
        raise
print("CORPUS all compared")

hdr = (
    "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
    "/begin COMPU_VTAB\nVT_K1 \"\"\nTAB_VERB 2\n0 \"off\"\n1 \"on\"\n/end COMPU_VTAB\n"
    "/begin COMPU_METHOD CM_VT \"\" TAB_VERB \"%.0\" \"\"\nCOMPU_TAB_REF VT_K1\n/end COMPU_METHOD\n"
    "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
    '/begin MEASUREMENT XVT ""\nUWORD\nCM_VT\n0\n0\n0\n65535\nECU_ADDRESS\n0x1238\n/end MEASUREMENT\n'
    "/end MODULE\n/end PROJECT\n"
)
vtab_path = scratch / "vtab.a2l"
vtab_path.write_text(hdr, encoding="utf-8")
data = parse_a2l_file(vtab_path)
print("VTAB methods:", data["compu_methods_by_name"])
print("VTAB tag:", data["tags"])
print("VTAB enriched:", enrich_a2l_tags_with_values(data, {0x1238: 0, 0x1239: 1}))
