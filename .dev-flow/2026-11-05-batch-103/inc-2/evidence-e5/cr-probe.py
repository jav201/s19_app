"""E5 code review probe, Inc 2a (batch-103), code-reviewer agent.

Run from a COPY of the integrated tree (cwd = the copy's root), isolated HOME / XDG / LOCALAPPDATA,
PYTHONDONTWRITEBYTECODE=1.  Pure calls only: parse_a2l_file + the definition model; no app, no clipboard.

Sections (each prints a [Pn] tag):
  P0  which s19_app is imported
  P1  type-word letter case: the verdict is upper-cased, the kind / display / interpolate read the raw word
  P2  TAB_NOINTP on a COMPU_TAB whose x values repeat below the stored value: decode time vs table size
  P3  a MATRIX_DIM word the frozen parser reads as a huge int: describe raises / message length
  P4  a quoted CHARACTERISTIC kind word that starts with "MATRIX_DIM ": echo skipped
  P5  P-2: repr / == of the two private fields
  P6  read-once (closed list) by counting: per-walk calls of the readers, decode lookups in compu_tabs_by_name
  P7  definitions case: planned_text for a seed whose enum raw is not 1
"""
from __future__ import annotations

import dataclasses
import gc
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "synth"))

import s19_app  # noqa: E402
from s19_app.tui import a2l as a2lmod  # noqa: E402
from s19_app.tui import a2l_definition as defmod  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402

print("[P0] s19_app.__file__ =", s19_app.__file__)
print("[P0] a2l_definition.__file__ =", defmod.__file__)
print("[P0] python", sys.version.split()[0])

TMP = Path(tempfile.mkdtemp(prefix="cr_", dir=str(ROOT.parent / "out")))
HEAD = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n'
        "BYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n")
TAIL = "/end MODULE\n/end PROJECT\n"


def load(text: str, tag: str) -> dict:
    path = TMP / f"{tag}.a2l"
    path.write_text(text, encoding="utf-8")
    return parse_a2l_file(path)


def val(name: str, addr: int, conv: str, lo: str = "0", hi: str = "255", extra: str = "") -> str:
    return (f'/begin CHARACTERISTIC {name} ""\n VALUE 0x{addr:X} RL_U8 0 {conv} {lo} {hi}\n{extra}'
            "/end CHARACTERISTIC\n")


# ---------------------------------------------------------------------------------------------- P1
print("\n[P1] type-word letter case (verdict upper-cased; kind / display / interpolate read the raw word)")
text = (HEAD
        + '/begin COMPU_METHOD CM_LI "" tab_intp "%.1" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
        + '/begin COMPU_METHOD CM_UI "" TAB_INTP "%.1" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
        + '/begin COMPU_TAB CT "" TAB_INTP 2\n 0 0\n 10 100\n/end COMPU_TAB\n'
        + '/begin COMPU_METHOD CM_LV "" tab_verb "%.0" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
        + '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "OFF"\n 5 "ON"\n/end COMPU_VTAB\n'
        + '/begin COMPU_METHOD CM_LD "" identical "%.2" ""\n/end COMPU_METHOD\n'
        + '/begin COMPU_METHOD CM_UD "" IDENTICAL "%.2" ""\n/end COMPU_METHOD\n'
        + val("LI", 0x10, "CM_LI") + val("UI", 0x11, "CM_UI") + val("LV", 0x12, "CM_LV")
        + val("LD", 0x13, "CM_LD") + val("UD", 0x14, "CM_UD") + TAIL)
a2l = load(text, "p1_case")
image = {0x10 + i: 5 for i in range(5)}
defs = defmod.describe_definitions(["LI", "UI", "LV", "LD", "UD"], a2l)
for name, d in defs.items():
    res = defmod.decode_definition(d, a2l, image)
    print(f"[P1] {name}: kind={d.kind!r} conversion_type={d.conversion_type!r} refusal={d.refusal} -> {res}")
frozen_li = a2lmod._apply_compu_method(5, {"conversion_type": "tab_intp", "compu_tab_ref": "CT"},
                                       a2l.get("compu_tabs_by_name") or {})
print(f"[P1] frozen _apply_compu_method(5, 'tab_intp', CT) = {frozen_li}   (82f5f8e5 decoded TAB_* through it)")

# corpus census: COMPU_METHOD type words whose letter case differs from their upper case
import subprocess  # noqa: E402

files = subprocess.run(["git", "ls-files", "*.a2l"], cwd=ROOT, capture_output=True, text=True).stdout.split()
lower_words: list = []
methods_seen = 0
skipped_large = []
for rel in files:
    if (ROOT / rel).stat().st_size > 20 * 1024 * 1024:
        skipped_large.append(rel)
        continue
    raw = (ROOT / rel).read_bytes()
    if b"COMPU_METHOD" not in raw:
        continue
    data = parse_a2l_file(ROOT / rel)

    def walk(nodes):
        global methods_seen
        for node in nodes:
            if node.get("name") == "COMPU_METHOD":
                methods_seen += 1
                toks = a2lmod._flatten_body_tokens([node.get("meta", "") or ""] + (node.get("lines") or []))
                if len(toks) > 2 and toks[2] != toks[2].upper():
                    lower_words.append((rel, toks[0], toks[2]))
            walk(node.get("children") or [])

    walk(data.get("sections") or [])
print(f"[P1] corpus: {len(files)} tracked .a2l files, {methods_seen} COMPU_METHOD sections, "
      f"{len(lower_words)} type words not in upper case: {lower_words[:5]}; skipped > 20 MiB: {skipped_large}")

# ---------------------------------------------------------------------------------------------- P2
print("\n[P2] TAB_NOINTP decode on a COMPU_TAB whose x repeats below the stored value (400 UBYTE VALUEs, stored 250)")


def p2_text(kib: int, dup: bool) -> tuple[str, int]:
    target = kib * 1024
    if dup:
        line = " 0 0\n"
        k = target // len(line)
        body = line * k + " 1000 5\n"
    else:
        k = target // 12
        body = "".join(f" {j / k * 200.0:.6f} {j}\n" for j in range(k)) + " 1000 5\n"
    objs = "".join(val(f"S{i:05d}", 0x1000 + i, "CM_N") for i in range(400))
    return (HEAD + '/begin COMPU_METHOD CM_N "" TAB_NOINTP "%.3" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
            + f'/begin COMPU_TAB CT "" TAB_NOINTP {k + 1}\n{body}/end COMPU_TAB\n' + objs + TAIL, k + 1)


def least_cpu(fn, rounds: int = 7) -> float:
    best = float("inf")
    for _ in range(rounds):
        gc.collect()
        gc.disable()
        try:
            t0 = time.process_time()
            fn()
            best = min(best, time.process_time() - t0)
        finally:
            gc.enable()
    return best


for dup in (True, False):
    times = {}
    for kib in (256, 512, 2048):
        text, k = p2_text(kib, dup)
        a2l = load(text, f"p2_{'dup' if dup else 'distinct'}_{kib}")
        names = [f"S{i:05d}" for i in range(400)]
        dd = defmod.describe_definitions(names, a2l)
        img = {0x1000 + i: 250 for i in range(400)}
        out = [defmod.decode_definition(d, a2l, img) for d in dd.values()]
        frozen = a2lmod._table_lookup(250.0, a2l["compu_tabs_by_name"]["CT"], False)
        same = all(isinstance(r, defmod.Decoded) and r.value == frozen[0] for r in out)
        times[kib] = least_cpu(lambda: [defmod.decode_definition(d, a2l, img) for d in dd.values()])
        print(f"[P2] {'dup-x' if dup else 'distinct-x'} {kib:5d} KiB, {k} entries: 400 decodes "
              f"{times[kib] * 1000:8.1f} ms CPU (least of 7); value {out[0].value!r}, frozen {frozen}, equal={same}")
    print(f"[P2] {'dup-x' if dup else 'distinct-x'} ratios: 2S/S = {times[512] / times[256]:.2f}, "
          f"8S/S = {times[2048] / times[256]:.2f}   (.150 bounds 1.5 / 2.0; absolute 0.5 s at S)")

# the cause: the run walk of _table_value (counted, not timed)
form = defmod._TabForm(xs=(0.0,) * 1000 + (1000.0,), ys=(0.0,) * 1000 + (5.0,), x_nan=False, ref_echo="CT")
calls = {"eq": 0}


class CountingFloat(float):
    def __eq__(self, other):
        calls["eq"] += 1
        return float.__eq__(self, other)

    __hash__ = float.__hash__


form_c = defmod._TabForm(xs=tuple(CountingFloat(x) for x in form.xs), ys=form.ys, x_nan=False, ref_echo="CT")
calls["eq"] = 0
defmod._table_value(form_c, 250, False)
print(f"[P2] one TAB_NOINTP lookup on 1000 repeated x below 250: {calls['eq']} x comparisons "
      "(the `while lo > 0 and xs[lo - 1] == xs[lo]` walk; a bisect would make ~10)")

# ---------------------------------------------------------------------------------------------- P3
print("\n[P3] MATRIX_DIM words the frozen parser reads as large ints")
for label, word in (("hex 5000 digits", "0x" + "F" * 5000), ("decimal 4000 digits", "1" + "0" * 3999)):
    text = (HEAD + '/begin MEASUREMENT MD "" UBYTE NO_COMPU_METHOD 0 0 0 255\n'
            f" ECU_ADDRESS 0x10\n MATRIX_DIM {word}\n/end MEASUREMENT\n" + TAIL)
    try:
        a2l = load(text, f"p3_{label.split()[0]}")
    except Exception as exc:  # noqa: BLE001
        print(f"[P3] {label}: parse_a2l_file raised {type(exc).__name__}: {str(exc)[:120]}")
        continue
    tag = next(t for t in a2l["tags"] if t["name"] == "MD")
    md = tag.get("matrix_dim")
    print(f"[P3] {label}: parsed; tag matrix_dim is an int of {md.bit_length() if isinstance(md, int) else None} bits")
    try:
        d = defmod.describe_definition("MD", a2l)
        print(f"[P3] {label}: describe -> refusal code {d.refusal.code if d.refusal else None}, "
              f"message length {len(d.refusal.message) if d.refusal else 0} (R-A2L-DEF.151 bound 1,024)")
    except Exception as exc:  # noqa: BLE001
        print(f"[P3] {label}: describe_definition RAISED {type(exc).__name__}: {str(exc)[:110]}")

# ---------------------------------------------------------------------------------------------- P4
print("\n[P4] a quoted CHARACTERISTIC kind word that starts with 'MATRIX_DIM '")
kind_word = '"MATRIX_DIM ' + "x" * 2000 + '"'
text = (HEAD + f'/begin CHARACTERISTIC KQ ""\n {kind_word} 0x10 RL_U8 0 NO_COMPU_METHOD 0 255\n/end CHARACTERISTIC\n'
        + TAIL)
a2l = load(text, "p4_case")
tags = [t for t in a2l["tags"] if t["name"] == "KQ"]
print(f"[P4] tags of KQ: {len(tags)}; char_type starts {str(tags[0].get('char_type'))[:24]!r} "
      f"(length {len(str(tags[0].get('char_type')))})" if tags else "[P4] no tag KQ")
if tags:
    d = defmod.describe_definition("KQ", a2l)
    msg = d.refusal.message if d.refusal else ""
    print(f"[P4] describe -> {d.refusal.code if d.refusal else None}, message length {len(msg)} "
          f"(bound 1,024), ellipsis in message: {chr(0x2026) in msg}")

# ---------------------------------------------------------------------------------------------- P5
print("\n[P5] P-2: the two private fields stay out of == and repr")
text = (HEAD + '/begin COMPU_METHOD CM_E "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
        + '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "OFF"\n 1 "ON"\n/end COMPU_VTAB\n' + val("E1", 0x10, "CM_E") + TAIL)
a2l = load(text, "p5_case")
d = defmod.describe_definition("E1", a2l)
bare = dataclasses.replace(d, _name_echo=None, _table_form=None)
print(f"[P5] fields: {[f.name for f in dataclasses.fields(defmod.Definition)][-4:]}; "
      f"compare/repr of the last two: {[(f.compare, f.repr) for f in dataclasses.fields(defmod.Definition)][-2:]}")
print(f"[P5] described == hand-stripped: {d == bare}; '_table_form' in repr: {'_table_form' in repr(d)}; "
      f"'_name_echo' in repr: {'_name_echo' in repr(d)}")
print(f"[P5] hand-stripped decodes the same: {defmod.decode_definition(bare, a2l, {0x10: 1}) == defmod.decode_definition(d, a2l, {0x10: 1})}")

# ---------------------------------------------------------------------------------------------- P6
print("\n[P6] read-once by counting (400 objects naming one method / table / layout; one walk)")
counts = {"flatten": 0, "resolve_layout": 0, "enum_form": 0, "tab_form_build": 0, "display_decimals": 0}
orig = {
    "_flatten_body_tokens": defmod._flatten_body_tokens,
    "_resolve_record_layout": defmod._resolve_record_layout,
    "_build_enum_form": defmod._build_enum_form,
    "_display_decimals": defmod._display_decimals,
}


def wrap(key, fn):
    def inner(*a, **k):
        counts[key] += 1
        return fn(*a, **k)
    return inner


defmod._flatten_body_tokens = wrap("flatten", orig["_flatten_body_tokens"])
defmod._resolve_record_layout = wrap("resolve_layout", orig["_resolve_record_layout"])
defmod._build_enum_form = wrap("enum_form", orig["_build_enum_form"])
defmod._display_decimals = wrap("display_decimals", orig["_display_decimals"])
orig_tab = defmod._TabForm


class CountedTabForm(orig_tab):
    def __init__(self, *a, **k):
        counts["tab_form_build"] += 1
        super().__init__(*a, **k)


defmod._TabForm = CountedTabForm
try:
    for case, conv, extra in (
        ("enum", "CM_E", '/begin COMPU_METHOD CM_E "" TAB_VERB "%.0" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
                         '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "OFF"\n 1 "ON"\n/end COMPU_VTAB\n'),
        ("tab", "CM_N", '/begin COMPU_METHOD CM_N "" TAB_NOINTP "%.3" ""\n COMPU_TAB_REF CT\n/end COMPU_METHOD\n'
                        '/begin COMPU_TAB CT "" TAB_NOINTP 2\n 0 0\n 10 100\n/end COMPU_TAB\n'),
        ("tab_missing", "CM_M", '/begin COMPU_METHOD CM_M "" TAB_NOINTP "%.3" ""\n COMPU_TAB_REF CT_GONE\n'
                                '/end COMPU_METHOD\n'
                                '/begin COMPU_TAB CT_OTHER "" TAB_NOINTP 1\n 0 0\n/end COMPU_TAB\n'),
    ):
        text = HEAD + extra + "".join(val(f"S{i:05d}", 0x1000 + i, conv) for i in range(400)) + TAIL
        a2l = load(text, f"p6_{case}")
        for key in counts:
            counts[key] = 0
        names = [f"S{i:05d}" for i in range(400)]
        dd = defmod.describe_definitions(names, a2l)
        snapshot = dict(counts)

        class CountingDict(dict):
            gets = 0

            def get(self, key, default=None):
                CountingDict.gets += 1
                return dict.get(self, key, default)

        probe_data = dict(a2l)
        probe_data["compu_tabs_by_name"] = CountingDict(a2l.get("compu_tabs_by_name") or {})
        img = {0x1000 + i: 3 for i in range(400)}
        res = [defmod.decode_definition(d, probe_data, img) for d in dd.values()]
        kinds = {type(r).__name__ + (":" + r.code if isinstance(r, defmod.Refusal) else "") for r in res}
        print(f"[P6] {case:11s} describe of 400 names: {snapshot}; decode of 400: "
              f"{CountingDict.gets} compu_tabs_by_name lookups; results {sorted(kinds)}")
finally:
    defmod._flatten_body_tokens = orig["_flatten_body_tokens"]
    defmod._resolve_record_layout = orig["_resolve_record_layout"]
    defmod._build_enum_form = orig["_build_enum_form"]
    defmod._display_decimals = orig["_display_decimals"]
    defmod._TabForm = orig_tab

# ---------------------------------------------------------------------------------------------- P7
print("\n[P7] definitions case: planned_text against the model's decode, by seed")
import make_release_case as gen  # noqa: E402
from s19_app.core import S19File  # noqa: E402

for seed in (20260001, 1, 2, 3, 4, 5):
    _regions, objects = gen.build_definition_objects(random.Random(seed))
    enum_obj = next(o for o in objects if o["name"] == "ENUM_0001")
    out_dir = TMP / f"defc_{seed}"
    paths = gen.generate_definitions_case(out_dir, seed)
    a2l = parse_a2l_file(paths["a2l"])
    img = S19File(str(paths["s19"])).get_memory_map()
    d = defmod.describe_definition("ENUM_0001", a2l)
    res = defmod.decode_definition(d, a2l, img)
    text = res.text if isinstance(res, defmod.Decoded) else res
    print(f"[P7] seed {seed}: enum raw {enum_obj['planned_stored']}, planned_text {enum_obj['planned_text']!r}, "
          f"model text {text!r}, agree={text == enum_obj['planned_text']}")
print("\n[END] probe done")
