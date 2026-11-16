# Inc 8 — E3 review, security lens

**Verdict: FAIL** — 5 MAJOR open (E3S-01 … E3S-05), 2 MEDIUM, 1 MINOR, 1 INFO. Each MAJOR has a targeted fix; two are one-line changes of a CTX term or an interface sentence.
- **The operator-text path is sound:** I-1 strips controls on paste, I-2 caps and cleans every message, and the status sink scrubs and cuts at the screen width.
- **The defects are where the design meets state it does not own:** which image the stage reads after an Apply (stale bits), the kind of entry an equal-span stage replaces, the busy gate, and file-sized ASCII spans and limits.

Reviewer: architect acting as the single E3 reviewer, security lens (Opus 5.5), one pass, independent of the E1/E2 author. Scope and reads as `E3-architect.md`. Probe: §Evidence below (run on `<runner>`, `~/work/zq-e3-8/`, HOME `<runner-home>`, `-B -I`, `< /dev/null`; deleted after the run).

## Findings

| Id | Sev | Tag | About (file:line) | Defect | Fix |
|---|---|---|---|---|---|
| E3S-01 | MAJOR | design-gap | E3A-07 / E3S-08 carry; CTX *image* (`01-requirements.md:45`); R-PE-DEF.51 (`:189`); node `PatchMixin.on_staging_sheet_stage_requested` (`graph-inc8.md:589`: "stage_definition(…, the loaded image's mem_map)"); nodes P5/P6/P10 (the sheet gets `self._mem_map`) | **The stage and the sheet read two different images, so stale bits come back after an Apply.** Apply writes the document into the live map; the live map then holds the entries' bytes, and a journal keeps the source bytes. The panel's `_mem_map` is `ChangeService.source_image_view(loaded.mem_map)` (`app/patch.py:290-294`, `:1001-1034`; `change_service.py:1885-1912`), i.e. the source bytes. The graph has the sheet preview over source + entries and the stage encode over live + entries. Scenario: stage MASK_FIELD_0001 `255` (entry `1F F7`), Apply, then Remove that entry (or Undo). Stage MASK_BIT_0001 `0`. Probe P2: over the live map the encode is `1F F6`, which writes MASK_FIELD = 255 back although the operator removed it. Over the source view it is `1A E6`. The sheet's Current shows MASK_FIELD `174` and its preview shows `1A E6`, so F-2's premise ("the preview and the stage run the same encode over the same overlay") is false here. No case covers the sequence. | **One image for both:** CTX *image* := "the source view of the loaded image (`ChangeService.source_image_view`), the map the before/after strip reads". A3 passes `self._strip_source_map(loaded)` to `stage_definition`. Add a case to R-PE-DEF.51: stage MASK_FIELD `255`, Apply, Remove, stage MASK_BIT `0` → the entry is `1A E6` and MASK_FIELD decodes `174`. Negative control: the live map → `1F F6` → RED. The graph's A3 `func` names the view. |
| E3S-02 | MAJOR | design-gap | I-8.2 equal-span branch "replace the entry's bytes, keep its symbol" (`graph-inc8.md:34`, node `:577`); R-PE-DEF.52 (`:190`); `ChangeEntry` (`changes/model.py:80-112`); the canonical writer (`changes/io.py:1544-1550`) | **A stage over a `string` entry is lost at save.** A document may hold a `string` entry: `entry_type "string"`, with `value` = the declared text, re-emitted by the writer *instead of* `encoded_bytes`. If its span equals a text row's span, "replace the entry's bytes" leaves `entry_type` and `value` as they were. The in-memory apply then writes the new bytes, but Save writes the old `value`, and a reload restores the old text with no notice. The same holds for any field other than `encoded_bytes` that the implementer leaves in place. | I-8.2 equal span → **replace the entry** with `ChangeEntry("bytes", address, tuple(encoded.data), symbol=<the old entry's symbol>)`. `value` becomes `None` and `entry_type` becomes `"bytes"`. R-PE-DEF.52 gains a case: a `string` entry of 42 characters at 0x810200, stage V171 ASCII `XYZ`, `serialize_change_document` → `"type": "bytes"` with the new bytes. Reload → V171 decodes `XYZ`. Negative control: keep the `string` entry → RED. |
| E3S-03 | MAJOR | design-gap | Canon R-PE-110 (`REQUIREMENTS.md:4267`) and the CTX-BUSY refused list (`:2542-2555`); `_refuse_if_busy` (`app/shell.py:425-447`), called first by every Patch action (`app/patch.py:145`); node A3 (`graph-inc8.md:585-594`) | **A stage is not refused while a session action runs.** A file load, A2L load, project load or Save project runs on a worker. During it, a stage reads `current_a2l_data` and the image mid-change and writes the document that a project load is about to replace. Inc 8 amends R-PE-034/-035 for "a stage" but not R-PE-110, and A3's `func` has no busy check. | R-PE-110 + "a stage (Enter in the formula input)". A3 begins `if self._refuse_if_busy(): return`. Add a case: a session action held running (the existing busy fixture) → Enter on DISPLAY_0001 `25.5` → the busy line, document unchanged, dirty unchanged. Negative control: no check → RED. |
| E3S-04 | MAJOR | design-gap | Hostile size of an A2L ASCII span: I-2 accepts `byte_length` up to `MAX_A2L_DECODE_BYTES = 1_048_576` (`a2l.py:65`, `a2l_definition.py:1004-1014`); R-PE-DEF.35, .38, .40, .42, .58 (`01-requirements.md:165`, `:168`, `:171-172`, `:196`); CTX *text rows* (`:90-91`) | **A text object the A2L declares 1 MiB long reaches the sheet unbounded.** Probe P3: I-2 decodes it (`text_len = 1048576`, 0.16 s) and encodes a 4,096-character text over it (0.06 s). The sheet then: (a) paints 65,536 text rows, in one `Text`, at every repaint and keystroke; (b) fills the formula input with 1,048,576 characters through R-PE-DEF.38. A programmatic fill bypasses `max_length` (P4: `value = 'v' × 5000` → 5,000). Every later keystroke is then refused, because any insert makes the value longer than `max_length`; (c) re-encodes the whole span at every keystroke; (d) puts the full decoded text in `staged as <text>` (the status sink cuts it, but the line is still built). No row has an `If` for the span's size, which the skill's E1 rule asks of every outside input. | Prefer removing the feature to guarding it. New row (If): "If a text object's span is longer than 4,096 bytes, then the system shall show the formula tail `edit <kind word> objects in the Inspector tab` and keep the formula input disabled." That is R-PE-DEF.36's no-editor path, and `Use parameter` + Edit still reach it. Cap the text rows at 4 (`+00` … `+30`), then `… <n> more bytes`. `<text>` in R-PE-DEF.58 is written as the name echo (256 + `…`). Cases: a V171 ASCII widened to 4,097 bytes → input disabled, 5 detail lines; at exactly 4,096 → editable. Negative control: no size check → RED. |
| E3S-05 | MAJOR | design-gap | CTX *Δ text* `p = 100·Δ/(upper − lower)` and *limits cell* `pos = (v − lower)/(upper − lower)` (`01-requirements.md:59-73`); nodes `delta_text`, `limits_cell` (`graph-inc8.md:267-293`); `_read_limits` (`a2l_definition.py:575-585`) | **Equal limits divide by zero at paint time.** I-2 passes any finite pair, with no check that lower < upper. An A2L whose lower limit equals its upper limit raises `ZeroDivisionError` in `delta_text` and in `limits_cell`, inside the paint, i.e. an exception from file content on the UI thread. Inverted limits (lower > upper) give a negative `pos` and a sign-flipped percent. Tracked files hold 0 equal and 0 inverted pairs among 6,646 parsed CHARACTERISTIC headers (scan below), so the input is hand-written or hostile, but legal. | New row (If): "If a row's upper limit is not greater than its lower limit, then the system shall show its limits cell as `<short lower> … <short upper>` and its pending Δ text without the percent." Cases: limits `5 5` and `9 1` on a DISPLAY_0001 copy → no exception, the dots form, Δ `-118.0`. Negative control: the plain division → RED (exception). |
| E3S-06 | MEDIUM | design-gap | R-PE-DEF.42 (`01-requirements.md:172`, base **P**); node `on_input_changed` (`graph-inc8.md:431`) | **The toolkit does not truncate a paste.** It refuses the whole insert. Textual's `Input.replace` refuses any new value longer than `max_length` (`textual/widgets/_input.py:976-1012`); both paste routes reach it (stock `_on_paste` → `insert`; I-1's `action_paste` → `replace`, `os_clipboard_input.py:1038-1112`). Probe P4: a 65,536-character paste → value length 0. A 200-character paste onto a 4,000-character value → 4,000, unchanged. Typed input stops at 4,096. Case .42/2 ("keeps its first 4,096 characters") can therefore never pass with `max_length=4096`, and only an untested override would satisfy the row. The bound itself holds: no route found puts more than 4,096 characters in the value, except the fills of E3S-04. | Reword to the toolkit's behaviour (no new code): "If a typed or pasted text would make the formula text longer than 4,096 characters, then the system shall leave the formula text unchanged." Cases: the P4 pastes (65,536 → unchanged; 4,000 + 200 → unchanged); 5,000 typed → 4,096. Do not override `os_clipboard_input.py` (PLAN: no batch-103 increment changes it). |
| E3S-07 | MEDIUM | impl | R-PE-DEF.70 (`01-requirements.md:210`), CTX *formula bar* (`:92-93`); node S14 `StagingSheet.compose` ("name `Label`, label `Label`, … tail `Static`", `E1-slice.md:40`) | **The formula bar's name label has no markup-off pin or case.** Textual's `Label` and `Static` parse markup in a `str` by default. The bar paints the selected row's A2L name. R-PE-DEF.70's cases cover an enum text, a unit, an action link and the formula text in the tail, but not the bar's name. An implementer writing `Label(name)` passes every case, and a name `A[/x]B` raises `MarkupError` when the row is selected (E3S-04 T1 of Inc 2). | S14's `func` says `markup=False` on the name label, the label and the tail, or `update(Text(…))`. R-PE-DEF.70 gains case /5: select a row named `A[/x]B` → no exception, the bar shows `A[/x]B`. Negative control: markup on → RED. |
| E3S-08 | MINOR | design-gap | R-PE-DEF.62 (`01-requirements.md:202`); node P6 `set_image_mem_map` (`graph-inc8.md:504-510`) | **Masked entries keep the other bits of the image they were staged over.** This is E3A-07's delete hazard reached by a new image. Load a second image after staging MASK_FIELD_0001, and the entry still carries the old image's MASK_BIT bit; Apply writes it. The sheet makes it visible (MASK_BIT shows `●` through the overlay), but no case pins that. | R-PE-DEF.62 gains case /4: stage MASK_FIELD `255` over word `1A E7`, set an image whose word is `1A E6` → MASK_BIT_0001 shows `●`, New `1 (0x01)`. That is the visible cue, and it needs no code change. |
| E3S-09 | INFO | — | The rest of the brief's security list | **Checked and holding.** (1) No write outside the word's span: `Encoded.data` is the span (I-2 contract; P2 `len=2` at 0x800010). Partial overlaps are refused (R-PE-DEF.55). Collisions cannot pre-exist (`changes/validate.py:45-75`). (2) Masked staging in both orders over the overlay: pilot `ORDER.*` and P2 (`1F F7` → `1F F6`). (3) Message shortening (E3S-11): I-2 caps every echoed word at 256 + `…` (`a2l_definition.py:366-379`; pilot `EX-P4` 289 characters). The status sink scrubs C0/C1 and cuts at the screen width (`app/shell.py` `_append_log_line`: `safe_text(...).plain`, `[:max(50, width)]`). The tail cut is R-PE-DEF.41. (4) Control characters: `plain()` replaces C0/C1/DEL as R-A2L-DEF.137 does. I-1 strips C0 except NUL, C1 and the bidi controls from pastes (`os_clipboard_input.py:505-540`). A pasted NUL is painted as U+FFFD by `plain()`, echoed as U+FFFD by I-2, and refused by every encode. (5) No path, user or host name in any new visible text, message or status. A2L names enter the change document as `symbol` (R-PE-DEF.53), as change-5 entries already do: the file stays local unless the operator shares it. **Not covered (pre-existing, every A2L view):** bidi controls inside A2L words are painted as they are; the sheet adds no new class. Recommend that A3 log nothing of the formula text. | — |

## Questions routed to E3 (security lens)

- **Markup off, control characters replaced (E3S-04a):** yes for every cell the graph builds as `Text`. One gap remains, the formula bar labels (E3S-07).
- **Message shortening (E3S-11):** yes. I-2 caps its messages, R-PE-DEF.41 cuts the tail, R-PE-DEF.72 caps names, and the status sink cuts at the screen width. The one unbounded `<text>` is E3S-04 (d).
- **Masked re-encode over the overlay (E3A-07 / E3S-08):**
  - No write outside the word's span: yes (E3S-09 (1)).
  - No stale bits: no. After an Apply the stage reads the live map (E3S-01). An equal-span `string` entry keeps its old declaration (E3S-02). A new image leaves the entry with the old image's other bits (E3S-08).
- **`max_length` on paste:** the bound holds, the row's text does not (E3S-06). Programmatic fills bypass it (E3S-04 (b)).
- **No path or private data in visible texts (cf. Inc 10 BL-I10-E3-8):** holds (E3S-09 (5)). Inc 8 writes no file name into an image or a header.

## Evidence

Probe `probe_e3_inc8.py` (the script is below, verbatim), run once on `<runner>` from a `git archive 593d56a4 s19_app tools examples/case_00_public` extract. Its environment: `env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_*=$S/x/… LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 python -B -I`, `timeout 300`, `< /dev/null`. The scratch `~/work/zq-e3-8/` was deleted after the run. Transcript, verbatim (home path written `~`):

```text
s19_app.__file__ = ~/work/zq-e3-8/tree/s19_app/__init__.py
loadavg = (9.47314453125, 8.30908203125, 6.71142578125)
P1.tags = 13990; P1.addressed = 3452
P1.describe_definitions[1].median_s = 0.1228; max_s = 0.3246
P1.describe_definitions[200].median_s = 0.1956; max_s = 0.3008
P1.describe_definitions[all].median_s = 0.5401; max_s = 0.7295
P1.describe_definition[1].median_s = 0.1167; max_s = 0.2277
P1.decode_200.empty_image.median_s = 0.0002
P1.decode_200.full_image.median_s = 0.0008; max_s = 0.0010
P1.decode_200.full_overlay.median_s = 0.0009; max_s = 0.0009
P1.decode_200.full_image.outcomes = {'A2L-DEF-ELEMENTS': 11, 'Decoded': 189}
P2.source.word = 1A E7; P2.e1 = Encoded(0x800010, 1f f7, len=2)
P2.mask_bit_over_overlay = Encoded(0x800010, 1f f6, len=2)
P2.after_apply_and_remove.stage_over_live = Encoded(0x800010, 1f f6, len=2)
P2.after_apply_and_remove.stage_over_source = Encoded(0x800010, 1a e6, len=2)
P2.after_apply_and_remove.current_over_source.MASK_FIELD = Decoded(stored=174, value=174, text='174')
P3.decode_1MiB.text_len = 1048576; seconds = 0.1589
P3.encode_1MiB_4096chars = Encoded(0x810200, 42 42 42 42 42 42 42 42…, len=1048576); seconds = 0.0623
P3.text_rows_at_16_per_row = 65536
P4.paste_65536.value_len = 0
P4.paste_4000_then.value_len = 4000
P4.paste_200_more.value_len = 4000
P4.typed_5000.value_len = 4096
P4.programmatic_5000.value_len = 5000
PROBE_DONE
exit=0
```

Limits scan (E3S-05), read-only text scan on the PC (`python -I -B`, no `s19_app` import): every `/begin CHARACTERISTIC` header in `examples/**/*.a2l`, tokenised with `shlex`, fields 8–9 read as numbers → `chars 6646 equal 0 inverted 0 []`.

Probe script, verbatim:

```python
"""Inc 8 E3 probe (batch-103): checks the claims the E3 review makes, on base 91d5ae56's product tree.

Run from the root of the extracted tree on the Linux runner, isolated env, `python -B -I probe_e3_inc8.py <scratch>`.
Writes only under <scratch>. Prints `KEY = value` lines.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import statistics
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("loadavg =", os.getloadavg())

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Encoded, Refusal, decode_definition, describe_definition, describe_definitions, encode_definition,
)


class Overlay(Mapping):
    """Stand-in for I-8.1 (image + entries' bytes in document order); not product code."""

    def __init__(self, image, entries):
        self._image = image if image is not None else {}
        self._top = {}
        for address, data in entries:
            for offset, byte in enumerate(data):
                self._top[address + offset] = byte

    def __getitem__(self, address):
        if address in self._top:
            return self._top[address]
        return self._image[address]

    def __iter__(self):
        return iter(set(self._image) | set(self._top))

    def __len__(self):
        return len(set(self._image) | set(self._top))


def show(value):
    if isinstance(value, Refusal):
        return f"Refusal({value.code!r}, {value.message[:80]!r})"
    if isinstance(value, Encoded):
        return f"Encoded(0x{value.address:X}, {value.data[:8].hex(' ')}{'…' if len(value.data) > 8 else ''}, len={len(value.data)})"
    return repr(value)[:120]


def med(fn, n=5):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times), max(times)


scratch = Path(sys.argv[1])

# P1 — cost: is describe_definitions per page or per A2L?
sa = parse_a2l_file(Path("examples/case_00_public/software_a.a2l"))
addressed = [t.get("name") for t in sa.get("tags") or [] if isinstance(t.get("address"), int)]
page = addressed[:200]
print(f"P1.tags = {len(sa.get('tags') or [])}; P1.addressed = {len(addressed)}")
for label, names in (("1", page[:1]), ("200", page), ("all", addressed)):
    m, x = med(lambda: describe_definitions(names, sa), n=3 if label == "all" else 5)
    print(f"P1.describe_definitions[{label}].median_s = {m:.4f}; max_s = {x:.4f}")
m, x = med(lambda: describe_definition(page[0], sa))
print(f"P1.describe_definition[1].median_s = {m:.4f}; max_s = {x:.4f}")
pdefs = describe_definitions(page, sa)
full = {}
for d in pdefs.values():
    if d.address is not None and d.byte_length:
        for i in range(d.byte_length):
            full[d.address + i] = 0x01
m, x = med(lambda: [decode_definition(pdefs[n], sa, {}) for n in page])
print(f"P1.decode_200.empty_image.median_s = {m:.4f}")
m, x = med(lambda: [decode_definition(pdefs[n], sa, full) for n in page])
print(f"P1.decode_200.full_image.median_s = {m:.4f}; max_s = {x:.4f}")
ov = Overlay(full, [])
m, x = med(lambda: [decode_definition(pdefs[n], sa, ov) for n in page])
print(f"P1.decode_200.full_overlay.median_s = {m:.4f}; max_s = {x:.4f}")
codes = {}
for n in page:
    r = decode_definition(pdefs[n], sa, full)
    k = r.code if isinstance(r, Refusal) else "Decoded"
    codes[k] = codes.get(k, 0) + 1
print(f"P1.decode_200.full_image.outcomes = {dict(sorted(codes.items()))}")

# P2 — masked staging: source map vs live (applied) map, over a Mapping overlay.
defc = scratch / "defc"
subprocess.run([sys.executable, "-B", "tools/synth/make_release_case.py", "--case", "definitions", "--out", str(defc)], check=True, stdout=subprocess.DEVNULL)
a2l = parse_a2l_file(defc / "definitions.a2l")
image = S19File(str(defc / "definitions.s19")).get_memory_map()
d = describe_definitions(["MASK_FIELD_0001", "MASK_BIT_0001"], a2l)
w = d["MASK_BIT_0001"].address
e1 = encode_definition(d["MASK_FIELD_0001"], a2l, "255", Overlay(image, []))
print(f"P2.source.word = {image[w]:02X} {image[w + 1]:02X}; P2.e1 = {show(e1)}")
print(f"P2.mask_bit_over_overlay = {show(encode_definition(d['MASK_BIT_0001'], a2l, '0', Overlay(image, [(e1.address, e1.data)])))}")
live = dict(image)
for i, b in enumerate(e1.data):
    live[e1.address + i] = b  # what Apply leaves in the live map
print(f"P2.after_apply_and_remove.stage_over_live = {show(encode_definition(d['MASK_BIT_0001'], a2l, '0', Overlay(live, [])))}")
print(f"P2.after_apply_and_remove.stage_over_source = {show(encode_definition(d['MASK_BIT_0001'], a2l, '0', Overlay(image, [])))}")
print(f"P2.after_apply_and_remove.current_over_source.MASK_FIELD = {show(decode_definition(d['MASK_FIELD_0001'], a2l, image))}")

# P3 — a long ASCII span through I-2 (hostile A2L size).
v171 = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
asc = describe_definition("ASAM.C.ASCII.UBYTE.NUMBER_42", v171)
big = dataclasses.replace(asc, byte_length=1_048_576)
bimg = {asc.address + i: 0x41 for i in range(1_048_576)}
t0 = time.perf_counter()
dec = decode_definition(big, v171, bimg)
t1 = time.perf_counter()
print(f"P3.decode_1MiB.text_len = {len(dec.text)}; seconds = {t1 - t0:.4f}")
t0 = time.perf_counter()
enc = encode_definition(big, v171, "B" * 4096, bimg)
t1 = time.perf_counter()
print(f"P3.encode_1MiB_4096chars = {show(enc)}; seconds = {t1 - t0:.4f}")
print(f"P3.text_rows_at_16_per_row = {1_048_576 // 16}")


# P4 — Input(max_length=4096) under a paste, typing and a programmatic fill (I-1 widget).
async def p4():
    from textual import events
    from textual.app import App, ComposeResult
    from s19_app.tui.os_clipboard_input import OsClipboardInput

    class Probe(App):
        def compose(self) -> ComposeResult:
            yield OsClipboardInput(id="f", max_length=4096)

    app = Probe()
    async with app.run_test(size=(80, 10)) as pilot:
        inp = app.query_one("#f", OsClipboardInput)
        inp.focus()
        await pilot.pause()
        inp.post_message(events.Paste("x" * 65536))
        await pilot.pause()
        await pilot.pause()
        print(f"P4.paste_65536.value_len = {len(inp.value)}")
        inp.value = ""
        await pilot.pause()
        inp.post_message(events.Paste("y" * 4000))
        await pilot.pause()
        await pilot.pause()
        print(f"P4.paste_4000_then.value_len = {len(inp.value)}")
        inp.post_message(events.Paste("z" * 200))
        await pilot.pause()
        await pilot.pause()
        print(f"P4.paste_200_more.value_len = {len(inp.value)}")
        inp.value = ""
        await pilot.pause()
        for _ in range(5000):
            inp.insert_text_at_cursor("k")
        print(f"P4.typed_5000.value_len = {len(inp.value)}")
        inp.value = "v" * 5000
        await pilot.pause()
        print(f"P4.programmatic_5000.value_len = {len(inp.value)}")


asyncio.run(p4())
print("PROBE_DONE")
```

## Checks not run, and why

- **No Windows Terminal check of the keys or of Escape** (the P rows R-PE-DEF.45 … .48). Those are E4 pilots, by the rulings. No PC run (HT-01).
- **P4 drives the paste as a posted `events.Paste`**, not through a real terminal bracketed paste. The handler chain is the same (`_on_paste` on OsClipboardInput, then Input), but the terminal's own paste cap is not exercised.
- **E3S-01's sequence was not run through the app** (Apply, Remove, stage). P2 shows the I-2 result for each image. Which image each caller passes is read (R) at the cited lines.
- **E3S-02 was not run.** The writer's branch is read (R) at `changes/io.py:1544-1550`.
- **E3S-03 was not run.** The busy gate is read (R).
- **Timing values were taken at host load 8–9.5** (HT-08). Only the ratios are used.

## Re-review after E3R1

**Verdict: PASS-WITH-NOTES** — 0 MAJOR open. Every first-round finding E3S-01 … E3S-08 is closed by its fix. 1 new MEDIUM (E3S-10) and 1 new MINOR (E3S-11) go to E4 as addenda.

Reviewer: as in the architect re-review (one pass over the corrected parts, HEAD `24f8d4ae`).

### Closure of the first-round findings

| Finding | Closed? | Evidence |
|---|---|---|
| E3S-01 | yes | CTX *image* = the source view. A3 passes `_strip_source_map(self.current_file)`. Every panel map push already passes the source view: `app/patch.py:293`, `:571`, `:1535`; `app/loaded_state.py:679`; `app/project_load.py:1031`; the unload path `None`, `loaded_state.py:407`, all read (R). R-PE-DEF.51/3 (Apply, Remove, `1A E6`) with the live-map negative control. F-2's premise is corrected. |
| E3S-02 | yes | I-8.2 replaces the equal-span entry with a `bytes` entry that keeps the symbol. R-PE-DEF.52/3 round trip; `X.kept_string_entry` reloads the old text, `X.replaced_by_bytes_entry` reloads `XYZ`. |
| E3S-03 | yes | R-PE-110 + "a stage" (CTX *stage* covers Inc 9's record stage). A3 begins with `_refuse_if_busy()`. The I-8.2 stage seam obliges Inc 9's handler to do the same. Case R-PE-110/1. |
| E3S-04 | yes for (a), (b), (c), (d); residue E3S-10 | (a) at most 4 text rows + `… <n> more B` (`T.span_1048576` → 6 detail lines; the negative control has 65,536). (b) no editor above 4,096 bytes; the input is empty without an editor (R-PE-DEF.78); every fill goes through `formula_fill` with a 4,096 cap (R-PE-DEF.80, `T.fill_cap.enum_text_5000 = 4096`). (c) no preview without an editor. (d) `<text>` echoed. |
| E3S-05 | yes | R-PE-DEF.76/.77; `limits_cell` takes the dots form before any position is computed; `delta_text` divides only while upper > lower (`L.limits_5_5`, `L.limits_9_1`; the negative control raises `ZeroDivisionError`). |
| E3S-06 | yes | R-PE-DEF.42 states the toolkit's refusal, with the three P4 cases. Residue: E3S-11. |
| E3S-07 | yes | `_paint` updates the bar's name, label and tail as `Text`; R-PE-DEF.70/5 (`A[/x]B`). |
| E3S-08 | yes | R-PE-DEF.62/4 (`M.*`: MASK_BIT current `0`, staged `1`). |

New and changed nodes, checked on this lens:
- `ops_for`, `row_window` and `formula_fill` are pure.
- The fallback makes no I-2 call.
- `set_parameters` exposes a `MappingProxyType`, so the definitions are read-only.
- `WINDOW_HELP_SECTIONS` is plain text under R-WHELP.11.
- The record-layout word of the definition line (C-6) is a file word. It is painted inside the body `Text` (no markup parse) and replaced by R-PE-DEF.71's U ("every text the staging sheet paints").
- No path or private datum enters a new text.

### New findings

| Id | Sev | Tag | About (file:line) | Defect | Fix |
|---|---|---|---|---|---|
| E3S-10 | MEDIUM | design-gap | `build_row` (`graph-inc8.md:343-351`): the text ops' `decode` runs over the image and over the overlay at every `show_page` and `set_document`; `_FALLBACK_OPS.staged` reads "a span byte of the overlay differs from the image's" | **A large span is still read whole, twice per row, at every page or document change.** The 4,096-byte bound removes the editor, but a text row's Current still decodes its full span: about 0.16 s per 1 MiB decode (E3 probe `P3`). `_read_stored_value` loops over every offset even when no byte is held (`a2l_definition.py:3196-3204`). A hostile A2L with 200 such ASCII objects on one page costs about 200 × 2 × 0.16 s ≈ 64 s of UI freeze per page turn or stage (derived, not run). The fallback's staged rule walks each span through the overlay the same way, so Inc 9's large arrays cost the same before their bench decodes. | Bound the work by what is shown and by the document, not by the span. (1) A text row over 4,096 bytes (no editor) decodes only its first 64 bytes for Current, written `"<text>…"`: R-PE-DEF.79's 64 bytes are all it paints. (2) `staged` for the fallback, and for a text row over 4,096 bytes, is "an entry of the document intersects the span with a byte that differs from the image's byte". It loops over the entries' bytes (≤ the document), never over the span. Add a case: 200 copies of the 1 MiB ASCII on one page → page change painted ≤ 0.5 s on `<runner>`. Negative control: the full decode → RED. |
| E3S-11 | MINOR | impl | `E1-rulings.md` §5 "Inputs to pilot at E4": "that `Input.max_length` truncates a paste (R-PE-DEF.42)" | **The E4 pilot note contradicts the corrected row.** R-PE-DEF.42 now says the oversized insert is refused (P4). A pilot briefed from this sentence would test for truncation. | Reword: "that a real Windows Terminal bracketed paste longer than 4,096 characters leaves the formula text unchanged (R-PE-DEF.42)". This matches backlog line (2). |

### Checks not run, and why
- **E3S-10's 64 s is derived** from P3's per-decode time and the 200-row page, not run.
- **No new runner probe;** the E3R1 transcript lines cited were checked against the rows.
