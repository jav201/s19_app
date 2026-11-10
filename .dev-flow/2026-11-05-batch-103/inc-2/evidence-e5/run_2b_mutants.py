from pathlib import Path
import json
import os
import shutil
import subprocess

BASE = Path("/tmp/b103-e4-2b-int")
ROOT = Path("/tmp/b103-e5-2b-mut")
OUT = ROOT / "out"
PYTHON = Path.home() / "miniconda3/envs/s19ci/bin/python"
PRODUCT = "s19_app/tui/a2l_definition.py"
A2L = "s19_app/tui/a2l.py"

MUTANTS = [
    ("M-40", PRODUCT, "if _NUMBER_TEXT_RE.fullmatch(text):", "if True:", "a2l_def_40"),
    ("M-41", A2L, "return (physical - lin_b) / lin_a, None, []", "return (physical + lin_b) / lin_a, None, []", "a2l_def_41"),
    ("M-42", PRODUCT, 'return Refusal("A2L-DEF-ENCODE", f"{name_echo}: {reason}")', 'return Refusal("A2L-DEF-ENCODE", f"{name_echo}: refused")', "a2l_def_42"),
    ("M-43", PRODUCT, "if not (below or above):", "if True:", "a2l_def_43"),
    ("M-44", PRODUCT, "return Encoded(definition.address, data, notices)", "return Encoded(definition.address, data, ())", "a2l_def_44"),
    ("M-45", PRODUCT, "if ebelow or eabove:", "if False:", "a2l_def_45"),
    ("M-46", PRODUCT, "merged = (word & ~mask) | (field << shift)", "merged = field", "a2l_def_46"),
    ("M-47", PRODUCT, "if field < 0 or ((field << shift) & ~mask) != 0:", "if False:", "a2l_def_47"),
    ("M-48", PRODUCT, "    name_echo = _name_echo_of(definition)\n    for entry in definition.enum_entries:", "    name_echo = _name_echo_of(definition)\n    for entry in reversed(definition.enum_entries):", "a2l_def_48"),
    ("M-49", PRODUCT, "    table_echo = (\n", "    if text == definition.default_text:\n        return 0\n    table_echo = (\n", "a2l_def_49"),
    ("M-49b", PRODUCT, "if entry.text == text:", "if entry.text.casefold() == text.casefold():", "a2l_def_49"),
    ("M-50", PRODUCT, 'return text.encode("ascii") + b"\\x00" * (length - len(text))', 'return text.encode("ascii")', "a2l_def_50"),
    ("M-51", PRODUCT, "if len(text) > length:", "text = text[:length]\n    if False:", "a2l_def_51"),
    ("M-52", PRODUCT, '    for ch in text:\n        if not (0x20 <= ord(ch) <= 0x7E):\n            return Refusal(\n                "A2L-DEF-TEXT-CHAR",\n                f"{name_echo}: \'{_operator_echo(ch)}\' is not a printable ASCII "\n                "character",\n            )\n    return text.encode("ascii") + b"\\x00" * (length - len(text))', '    return text.encode("utf-8") + b"\\x00" * (length - len(text))', "a2l_def_52"),
    ("M-53", PRODUCT, '"effective_byte_order": definition.byte_order,', '"effective_byte_order": "little",', "a2l_def_53"),
    ("M-54", PRODUCT, 'if definition.kind == "number":\n        written_image =', 'if False:\n        written_image =', "a2l_def_54"),
    ("M-55", PRODUCT, '"effective_byte_order": definition.byte_order,', '"effective_byte_order": "little" if definition.byte_order == "big" else "big",', "a2l_def_55"),
    ("M-55b", PRODUCT, "return shift\n\n\ndef _raw_text", "return shift + 1\n\n\ndef _raw_text", "a2l_def_55 or a2l_def_46"),
    ("M-55c", A2L, "return (physical - lin_b) / lin_a, None, []", "return (physical + lin_b) / lin_a, None, []", "a2l_def_55 or a2l_def_41_3"),
    ("M-55d", PRODUCT, 'return format(Decimal(f"{value:.15g}"), f".{d}f")', 'return format(Decimal(value), f".{d}f")', "a2l_def_55 or a2l_def_35_5"),
    ("M-56", PRODUCT, "return entry.raw", "return entry.raw + 1", "a2l_def_56"),
    ("M-56b", PRODUCT, 'return text.encode("ascii") + b"\\x00" * (length - len(text))', 'return text.encode("ascii")', "a2l_def_56"),
    ("M-57", PRODUCT, "    image, else ``None`` (the encode's step-6 check, every kind).\"\"\"\n    missing = 0", "    image, else ``None`` (the encode's step-6 check, every kind).\"\"\"\n    if definition.bit_mask is not None:\n        return Refusal(\"A2L-DEF-MASK-VALUE\", f\"{name_echo}: mask checked before image bytes\")\n    missing = 0", "a2l_def_57_3"),
    ("M-57b", PRODUCT, "    limits_outcome = _check_limits(definition, limit_value, _operator_echo(trimmed))", "    data = _encode_number(definition, a2l_data, limit_value)\n    if isinstance(data, Refusal):\n        return data\n    limits_outcome = _check_limits(definition, limit_value, _operator_echo(trimmed))", "a2l_def_57_2"),
    ("M-57c", PRODUCT, '    trimmed = text.strip(" ")', '    trimmed = text.strip(" ")\n    if definition.shared_with is not None:\n        return Refusal(\n            "A2L-DEF-OVERLAP",\n            f"{name_echo}: its bytes at {_fmt_address(definition.address)} "\n            f"are shared with {_echo(definition.shared_with)}",\n        )', "a2l_def_57_4"),
    ("M-138", PRODUCT, "if definition.shared_with is not None:", "if False:", "a2l_def_138"),
    ("M-138b", PRODUCT, "    my_bits = _selected_bits(\n", "    return (my_mask & other_mask) == 0\n    my_bits = _selected_bits(\n", "a2l_def_138"),
    ("M-138c", PRODUCT, '                        address = tag.get("address")', '                        address = tag.get("address") or 0', "a2l_def_138_18"),
    ("M-138d", PRODUCT, "if address is None:\n        return None", "if not address:\n        return None", "a2l_def_138_19"),
    ("M-138e", PRODUCT, "    for entry in span_entries:\n", "    for entry in span_entries:\n        if entry[2] in (\"BLOB\", \"INSTANCE\"):\n            continue\n", "a2l_def_138"),
    ("M-138f", PRODUCT, "        else:\n            pages = (address >> 4,)\n        for page in pages:", "        else:\n            continue\n        for page in pages:", "a2l_def_138"),
    ("M-138g", PRODUCT, '    if entry[2] in ("BLOB", "INSTANCE"):\n        return False\n', "", "a2l_def_138_23"),
    ("M-152", PRODUCT, "    if errors:\n        return Refusal(", "    if False and errors:\n        return Refusal(", "a2l_def_152 or a2l_def_57_5"),
    ("M-58.1", PRODUCT, "    if definition.refusal is not None:\n        return definition.refusal\n    name_echo = _name_echo_of(definition)\n\n    errors = a2l_data.get(\"errors\") or []", "    image[definition.address] = 0\n    if definition.refusal is not None:\n        return definition.refusal\n    name_echo = _name_echo_of(definition)\n\n    errors = a2l_data.get(\"errors\") or []", "a2l_def_58_1 and encode"),
]

ROOT.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)
results = []
for mid, filename, old, new, selection in MUTANTS:
    work = ROOT / mid
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(BASE, work, symlinks=True)
    path = work / filename
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if mid == "M-138":
        assert count == 2, (mid, count)
    else:
        assert count == 1, (mid, count)
    path.write_text(text.replace(old, new), encoding="utf-8")
    if mid == "M-152":
        marker = "        limit_value = value"
        gate = '''        if errors:
            return Refusal(
                "A2L-DEF-PARSE",
                f"{name_echo}: the A2L cannot be edited while it has parse errors "
                f"— the first is {errors[0]}",
            )
        limit_value = value'''
        assert text.count(marker) == 1
        path.write_text(path.read_text(encoding="utf-8").replace(marker, gate), encoding="utf-8")
    env = dict(os.environ)
    env.update(
        HOME=str(ROOT / "runner"),
        XDG_CACHE_HOME=str(ROOT / "cache"),
        XDG_CONFIG_HOME=str(ROOT / "config"),
        LOCALAPPDATA=str(ROOT / "local"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    command = [
        str(PYTHON), "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
        "tests/test_b103_a2l_definition.py", "tests/test_b103_synth_definitions.py",
        "-k", selection,
    ]
    proc = subprocess.run(
        command, cwd=work, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180,
    )
    diff = subprocess.run(
        ["git", "diff", "--", filename], cwd=work, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True,
    ).stdout
    (OUT / f"{mid}.txt").write_text(
        f"{mid}\npytest -k {selection}\nreturncode={proc.returncode}\n\n{diff}\n{proc.stdout}",
        encoding="utf-8",
    )
    result = "killed" if proc.returncode else "SURVIVED"
    failures = [line for line in proc.stdout.splitlines() if line.startswith("FAILED ")]
    results.append({"id": mid, "selection": selection, "result": result, "failures": failures})
    print(mid, result, *failures, sep="\n  ", flush=True)
    shutil.rmtree(work)
(OUT / "summary.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({"killed": sum(r["result"] == "killed" for r in results), "survived": [r["id"] for r in results if r["result"] != "killed"]}))
