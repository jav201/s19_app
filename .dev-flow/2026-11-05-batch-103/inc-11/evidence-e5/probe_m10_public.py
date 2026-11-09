from pathlib import Path
import sys
import types

sys.path.insert(0, "/tmp/b103-e5-11-mutA-laptop/tree")
import s19_app

print(s19_app.__file__, flush=True)

source_path = Path("/tmp/b103-e5-11-mutA-laptop/tree/s19_app/tui/a2l.py")
source = source_path.read_text(encoding="utf-8")
anchor = '                if ch == "\\r" and i + 1 < n and body[i + 1] == "\\n":'
replacement = '                if ch == "\\r" and False:'
assert source.count(anchor) == 1
mutated = source.replace(anchor, replacement, 1)


def load(name, text):
    module = types.ModuleType(name)
    module.__package__ = "s19_app.tui"
    sys.modules[name] = module
    exec(compile(text, str(source_path), "exec"), module.__dict__)
    return module


base = load("s19_app.tui._m10_base", source)
mutant = load("s19_app.tui._m10_mutant", mutated)
raw_lines = ["A\r\r\nB\r\nC\rD"]
base_private = list(base._lex_a2l_lines(raw_lines, []))
mutant_private = list(mutant._lex_a2l_lines(raw_lines, []))
print("PRIVATE_BASE", base_private)
print("PRIVATE_MUTANT", mutant_private)
assert base_private != mutant_private

public_path = Path("/tmp/b103-e5-11-mutA-laptop/out/m10-public.a2l")
public_path.write_bytes(
    b'ASAP2_VERSION 1 71\n/begin PROJECT P ""\r/begin MODULE M ""\r\n'
    b'/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\r\n'
    b' ECU_ADDRESS 0x10\r/end MEASUREMENT\n/end MODULE\r\n/end PROJECT\n'
)
base_public = base.parse_a2l_file(public_path)
mutant_public = mutant.parse_a2l_file(public_path)
print("PUBLIC_EQUAL", base_public == mutant_public)
assert base_public == mutant_public
print("M10_NOT_REALISABLE_ON_PUBLIC_ROUTE")
