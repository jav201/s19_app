import pathlib

HERE = pathlib.Path(__file__).resolve().parent
src = (HERE.parent / "e3a11" / "pilot2.py").read_text(encoding="utf-8")
hdr = '''"""Inc 11 E3 architect round 2: pilot2 (E2's lexer + builder model, unchanged otherwise) with the E3 correction's
per-line and per-section rules added, to time what the correction adds (R-A2L-READ.52). Added, as the graph writes them:
  - tier 1 only for a printable-ASCII line (isascii and isprintable); every other line goes to tier 2/3, which tests
    for U+0000 first (READ.55: the reading ends, errors reset to one text);
  - the named-kind rule (DE-3 revised, READ.54): a named kind whose keyword line holds no own word takes its first
    run as meta, and the next run when the first is the name alone and the next starts with a quote;
  - the nesting cap (READ.64): a /begin that would open a 33rd level ends the reading with one error;
  - errors through a capped list (READ.56): 100 texts, then a count.
NOT product code and NOT a stub: a throwaway feasibility model; the candidate path imports nothing from s19_app.
"""
'''
body = src[src.index('"""', 3) + 3:]


def sub(old, new):
    global body
    assert body.count(old) >= 1, old[:80]
    body = body.replace(old, new, 1)


sub('''        if '"' not in s and "/" not in s and "  " not in s and "\\t" not in s and "\\x0b" not in s and "\\x0c" not in s:
            if not (s.isascii() and s.isprintable()):
                for w in s.split(" "):
                    b = _bad_char(w)
                    if b is not None:
                        errors.append(f"Line {i + 1}: unexpected character U+{ord(b):04X}")
                        break
            yield i + 1, s''', '''        if '"' not in s and "/" not in s and "  " not in s and "\\t" not in s and "\\x0b" not in s and "\\x0c" not in s and s.isascii() and s.isprintable():
            yield i + 1, s''')
sub('''        if "/*" not in s and "//" not in s and "*/" not in s''', '''        if "\\x00" in s:
            errors.clear()
            errors.append("File is not UTF-8 text; save it as UTF-8 and load it again.")
            NUL_STOP[0] = True
            return
        if "/*" not in s and "//" not in s and "*/" not in s''')
sub("def _bad_char(word: str):", '''NUL_STOP = [False]
NAMED = {"AXIS_PTS", "BLOB", "CHARACTERISTIC", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB", "COMPU_VTAB_RANGE", "FRAME",
         "FUNCTION", "GROUP", "INSTANCE", "MEASUREMENT", "MEMORY_SEGMENT", "MODULE", "PROJECT", "RECORD_LAYOUT",
         "TRANSFORMER", "UNIT"}


class Capped(list):
    def __init__(self):
        super().__init__()
        self.dropped = 0

    def append(self, x):
        if len(self) < 100:
            super().append(x)
        else:
            self.dropped += 1


def _bad_char(word: str):''')
sub('''    text = path.read_bytes().decode("utf-8", errors="replace")
    errors: list = []''', '''    text = path.read_bytes().decode("utf-8", errors="replace")
    errors: list = Capped()''')
sub('''            if top["_kw_line"] == ln and top["_meta_open"]:
                top["meta"] = c if not top["meta"] else top["meta"] + " " + c
            else:
                top["_meta_open"] = False
                top["lines"].append(c)
                top["line_numbers"].append(ln)
            continue''', '''            if top["_kw_line"] == ln and top["_meta_open"]:
                top["meta"] = c if not top["meta"] else top["meta"] + " " + c
            else:
                top["_meta_open"] = False
                nm = top["_named"]
                if nm:
                    if nm == 1 and not top["meta"]:
                        top["meta"] = c
                        top["meta_line"] = ln
                        top["_named"] = 2 if " " not in c else 0
                        continue
                    top["_named"] = 0
                    if nm == 2 and c[:1] == '"':
                        top["meta"] += " " + c
                        continue
                top["lines"].append(c)
                top["line_numbers"].append(ln)
            continue''')
sub('''            entry = {"name": words[1], "meta": " ".join(words[2:]), "start_line": ln, "lines": [], "children": [],
                     "line_numbers": [], "_kw_line": ln, "_meta_open": True}''', '''            if len(stack) >= 32:
                errors.clear()
                errors.append(f"Line {ln}: sections nested deeper than 32")
                return [], errors
            k1 = words[1]
            entry = {"name": k1, "meta": " ".join(words[2:]), "start_line": ln, "lines": [], "children": [],
                     "line_numbers": [], "_kw_line": ln, "_meta_open": True,
                     "_named": 1 if (len(words) == 2 and (k1 in NAMED or k1.startswith("TYPEDEF_"))) else 0}''')
sub('''                    entry = {"name": "UNKNOWN", "meta": "", "start_line": ln, "lines": [], "children": [],
                             "line_numbers": [], "_kw_line": ln, "_meta_open": True}''', '''                    if len(stack) >= 32:
                        errors.clear()
                        errors.append(f"Line {ln}: sections nested deeper than 32")
                        return [], errors
                    entry = {"name": "UNKNOWN", "meta": "", "start_line": ln, "lines": [], "children": [],
                             "line_numbers": [], "_kw_line": ln, "_meta_open": True, "_named": 0}''')
sub('''                want_kw["name"] = w
                want_kw["_kw_line"] = ln''', '''                want_kw["name"] = w
                want_kw["_kw_line"] = ln
                want_kw["_named"] = 1 if (w in NAMED or w.startswith("TYPEDEF_")) else 0''')
sub('''def _put(sec, ln, c):
    if sec["_kw_line"] == ln and sec["_meta_open"]:
        sec["meta"] = c if not sec["meta"] else sec["meta"] + " " + c
    else:
        sec["_meta_open"] = False
        sec["lines"].append(c)''', '''def _put(sec, ln, c):
    if sec["_kw_line"] == ln and sec["_meta_open"]:
        sec["meta"] = c if not sec["meta"] else sec["meta"] + " " + c
        sec["_named"] = 0
    else:
        sec["_meta_open"] = False
        nm = sec["_named"]
        if nm:
            if nm == 1 and not sec["meta"]:
                sec["meta"] = c
                sec["meta_line"] = ln
                sec["_named"] = 2 if " " not in c else 0
                return
            sec["_named"] = 0
            if nm == 2 and c[:1] == '"':
                sec["meta"] += " " + c
                return
        sec["lines"].append(c)''')
(HERE / "pilot3.py").write_text(hdr + body, encoding="utf-8")
print("ok")
