from pathlib import Path
import json
import os
import shutil
import subprocess

BASE = Path("/tmp/b103-e5-3b-98904e82")
ROOT = Path("/tmp/b103-e5-3b-mut")
OUT = ROOT / "out"
PYTHON = Path(os.environ["S19CI_PYTHON"])
PRODUCT = "s19_app/tui/a2l_definition.py"

MUTANTS = [
    ("M-120", PRODUCT, '    if definition.kind in ("array", "curve", "map"):\n        return Refusal(\n            "A2L-DEF-ELEMENTS",\n            f"{name_echo}: it holds {definition.element_count} values — decode and "\n            "encode it value by value",\n        )\n\n    if definition.kind == "text":', '    if False and definition.kind in ("array", "curve", "map"):\n        return Refusal(\n            "A2L-DEF-ELEMENTS",\n            f"{name_echo}: it holds {definition.element_count} values — decode and "\n            "encode it value by value",\n        )\n\n    if definition.kind == "text":', "a2l_def_120"),
    ("M-121", PRODUCT, "        name_echo = _name_echo_of(definition) + suffix", "        name_echo = _name_echo_of(definition)", "a2l_def_121"),
    ("M-122", PRODUCT, "    conversion_type = definition.conversion_type", '    conversion_type = "IDENTICAL"', "a2l_def_122"),
    ("M-123", PRODUCT, "            linear = j + definition.shape[1] * i", "            linear = i + definition.shape[0] * j", "a2l_def_123"),
    ("M-124", PRODUCT, "    decoded = decode_values(definition, a2l_data, image)\n    if isinstance(decoded, Refusal):", "    decoded = decode_values(definition, a2l_data, image)\n    if False and isinstance(decoded, Refusal):", "a2l_def_124"),
    ("M-125", PRODUCT, "            if len(position) != len(definition.shape) or any(\n                index >= definition.shape[dim] for dim, index in enumerate(position)\n            ):", "            if False:", "a2l_def_125"),
    ("M-125b", PRODUCT, "    return _position_label(definition, position)", '    return f"{definition.name}[{position}]"', "a2l_def_125_5"),
    ("M-126", PRODUCT, '            if axis.axis_kind == "FIX_AXIS":', '            if False and axis.axis_kind == "FIX_AXIS":', "a2l_def_126"),
    ("M-127", PRODUCT, '            if axis.axis_kind == "COM_AXIS":', '            if False and axis.axis_kind == "COM_AXIS":', "a2l_def_127"),
    ("M-128", PRODUCT, "            if not axis.has_points:", "            if False and not axis.has_points:", "a2l_def_128"),
    ("M-129", PRODUCT, "    rule = axis.monotony\n    if rule == \"NOT_MON\" or len(stored_points) < 2:", "    rule = axis.monotony\n    return None\n    if rule == \"NOT_MON\" or len(stored_points) < 2:", "a2l_def_129"),
    ("M-130", PRODUCT, "    name_echo = _name_echo_of(definition)\n    errors = a2l_data.get(\"errors\") or []\n    if errors:", "    name_echo = _name_echo_of(definition)\n    errors = a2l_data.get(\"errors\") or []\n    if False and errors:", "a2l_def_130_4 or a2l_def_130_5"),
    ("M-131", PRODUCT, "        if not rejects and not _agrees_at_display_precision(", "        if not rejects and not True:", "a2l_def_122_5 or a2l_def_131_1"),
    ("M-131b", PRODUCT, "    entries = form.inverse_match\n    ys = form.inverse_match_ys", "    entries = form.inverse_match\n    for item in entries:\n        if item[1] == physical:\n            return item\n    ys = form.inverse_match_ys", "a2l_def_131_5"),
    ("M-131c", PRODUCT, "    if raw_fraction is None or not math.isfinite(raw_fraction):", "    if raw_fraction is None:", "a2l_def_131_4"),
    ("M-131d", PRODUCT, '    return message if len(message) <= 1_024 else message[:1_023] + "…"', "    return message", "a2l_def_131_6"),
    ("M-132", PRODUCT, "    record = bytearray(\n        image[address + offset] & 0xFF for offset in range(definition.byte_length)\n    )", "    record = bytearray(definition.byte_length)", "a2l_def_132"),
    ("M-140", PRODUCT, '            elif node_name == "AXIS_PTS":', '            elif False and node_name == "AXIS_PTS":', "a2l_def_140_1"),
    ("M-140b", PRODUCT, "        span_index[None] = span_entries", "        span_index[None] = [entry for entry in span_entries if entry[3] >= address - MAX_A2L_DECODE_BYTES + 1]", "a2l_def_140_10"),
    ("M-140c", PRODUCT, "                matrix[1] is None or _is_multi_value_matrix(matrix[0])", "                matrix[1] is not None and _is_multi_value_matrix(matrix[0])", "a2l_def_140_11"),
    ("M-153", PRODUCT, "    if scalar and len(ordered) == 1 and _scalar_position(ordered[0][0]):", "    if False and scalar and len(ordered) == 1 and _scalar_position(ordered[0][0]):", "a2l_def_153"),
    ("M-154", PRODUCT, "            if axis.monotony not in _SUPPORTED_MONOTONY:", "            if False and axis.monotony not in _SUPPORTED_MONOTONY:", "a2l_def_154"),
    ("M-155", PRODUCT, "        f\"{label}: {_operator_echo(point.text)} breaks the \"", "        f\"{label}: {point.text} breaks the \"", "a2l_def_155_2"),
    ("M-58.1a", PRODUCT, "    ordered = _ordered_edits(definition, edit)\n    scalar =", "    image[definition.address] = 0\n    ordered = _ordered_edits(definition, edit)\n    scalar =", "58_1_arr_1_edit_arm"),
    ("M-58.1b", PRODUCT, "    ordered = _ordered_edits(definition, edit)\n    scalar =", "    image[definition.address] = 0\n    ordered = _ordered_edits(definition, edit)\n    scalar =", "58_1_arr_2_edit_arm"),
    ("M-AT1", PRODUCT, "            linear = j + definition.shape[1] * i", "            linear = i + definition.shape[0] * j", "at_b103_i3_1_edit_arm"),
    ("M-AT2", PRODUCT, '            if axis.axis_kind == "COM_AXIS":', '            if False and axis.axis_kind == "COM_AXIS":', "at_b103_i3_2_edit_arm"),
    ("M-AT3", PRODUCT, "            linear = j + definition.shape[1] * i", "            linear = i + definition.shape[0] * j", "at_b103_i3_3_edit_arm or a2l_def_123_2"),
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
    assert count == 1, (mid, count, old)
    path.write_text(text.replace(old, new), encoding="utf-8")
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
        "tests/test_b103_a2l_definition_arrays_write.py",
        "tests/test_b103_synth_definitions.py", "-k", selection,
    ]
    proc = subprocess.run(
        command, cwd=work, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=240,
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
