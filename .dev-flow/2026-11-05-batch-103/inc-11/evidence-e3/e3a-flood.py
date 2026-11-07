"""Inc 11 E3 architect (batch-103): how many parse errors does the graph's lexer contract give on a file that is not
UTF-8 A2L text, and what do the base consumers of `errors` cost for that many? Run on <runner> only:

    python -I e3a-flood.py <repo> <scratch>

Inputs (synthetic, written to <scratch>, deleted at the end):
  u16  examples/case_00_public/software_a.a2l re-encoded as UTF-16 LE with NO byte order mark (R-A2L-READ.6 refuses
       only a file that starts with FF FE / FE FF);
  bin  5 MiB of pseudo-random bytes (random.Random(11)), standing for a binary file picked by mistake.
Each is read as the product reads it (bytes decoded UTF-8 with errors="replace", R-A2L-001.7) and lexed by the E2
lexer model (pilot2.lex_lines, the graph's _lex_a2l_lines contract: one `Line <n>: unexpected character U+<XXXX>`
per word holding a character outside U+0021..U+007E). Then the e07fb00 consumers of `errors` are timed on a payload
holding that many errors: validate_a2l_internal_issues (one A2L_STRUCTURE_ERROR per error) and render_a2l_view
(every error listed, R-A2L-075/076). The e07fb00 reader's own result on each input is printed for comparison.
"""
import importlib.util, pathlib, random, resource, sys, time

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); scratch.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
spec = importlib.util.spec_from_file_location("pilot2", pathlib.Path(__file__).resolve().parent / "pilot2.py")
pilot2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(pilot2)

src = (repo / "examples/case_00_public/software_a.a2l").read_bytes()
inputs = {
    "u16": src.decode("utf-8", errors="replace").encode("utf-16-le"),
    "bin": random.Random(11).randbytes(5 * 1024 * 1024),
}
for key, raw in inputs.items():
    p = scratch / f"{key}.a2l"
    p.write_bytes(raw)
    base = a.parse_a2l_file(p)
    print(f"[{key}] bytes={len(raw)} first2={raw[:2].hex()} | e07fb00 reader: sections={len(base['sections'])} "
          f"tags={len(base['tags'])} errors={len(base['errors'])}")
    text = raw.decode("utf-8", errors="replace")
    errs: list = []
    t0 = time.perf_counter()
    n_lines = 0
    per_word = []
    for ln, c in pilot2.lex_lines(text, errs):
        n_lines += 1
        for w in pilot2.line_words(c):
            if w[:1] != '"' and pilot2._bad_char(w) is not None:
                per_word.append(f"Line {ln}: unexpected character U+{ord(pilot2._bad_char(w)):04X}")
    dt = time.perf_counter() - t0
    print(f"[{key}] lexer model: {len(errs)} errors as the pilot records them (one per line on its fast tiers), "
          f"{len(per_word)} words holding such a character (the graph's contract: one error per word), "
          f"{n_lines} canonical lines, {dt:.2f} s; first: {per_word[:1]}")
    errs = per_word
    payload = {"path": str(p), "sections": [], "errors": errs, "tags": []}
    t0 = time.perf_counter()
    issues = a.validate_a2l_internal_issues(payload)
    t1 = time.perf_counter()
    view = a.render_a2l_view(payload)
    t2 = time.perf_counter()
    print(f"[{key}] consumers on {len(errs)} errors: validate_a2l_internal_issues {len(issues)} issues in {t1 - t0:.2f} s; "
          f"render_a2l_view {len(view.splitlines())} lines, {len(view) / 1e6:.1f} MB of text in {t2 - t1:.2f} s; "
          f"maxrss {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB")
    p.unlink()
