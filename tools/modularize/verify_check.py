"""Static, per-package checks V1-V8 (inventory, bodies, D1 counts) and the file loader."""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import verify_norm as norm
import verify_scope as scope
import verify_units as vu

Fail = tuple[str, str]


@dataclass
class Loaded:
    units: list[vu.Unit] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    texts: dict[str, str] = field(default_factory=dict)
    parsed: dict[str, ast.Module] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def order_key(stem: str, mixin_order: list[str]) -> int:
    return mixin_order.index(stem) if stem in mixin_order else -1


def load_new(tree: Path, pkg: str, mapd: dict) -> Loaded:
    out = Loaded()
    d = tree / vu.NEW_DIRS[pkg]
    if not d.is_dir():
        return out
    mixin_order = mapd["app"]["mixin_order"] if pkg == "app" else []
    for f in sorted(d.glob("*.py")):
        stem, text = f.stem, f.read_text(encoding="utf-8")
        out.texts[stem] = text
        try:
            units, extras, mod = vu.parse_new_file(pkg, stem, text, mixin_order)
        except SyntaxError as e:
            out.errors.append(f"{stem}.py: syntax error {e}")
            continue
        out.units += units
        out.extras += extras
        out.parsed[stem] = mod
    for sub in sorted(p for p in d.iterdir() if p.is_dir() and p.name != "__pycache__"):
        out.extras.append(f"{sub.name}/: unexpected sub-directory inside the package")
    out.units.sort(key=lambda u: (order_key(u.stem, mixin_order), u.stem, u.line))
    return out


def match_units(old: list[vu.Unit], new: list[vu.Unit]) -> tuple[list[tuple[vu.Unit, vu.Unit]], list[Fail]]:
    """Pair old and new units by key (i-th with i-th); V1 missing, V2 duplicate, V3 extra."""
    by_old: dict[str, list[vu.Unit]] = defaultdict(list)
    by_new: dict[str, list[vu.Unit]] = defaultdict(list)
    for u in old:
        by_old[u.key].append(u)
    for u in new:
        by_new[u.key].append(u)
    pairs: list[tuple[vu.Unit, vu.Unit]] = []
    fails: list[Fail] = []
    for key, olds in by_old.items():
        news = by_new.get(key, [])
        pairs += list(zip(olds, news))
        for u in olds[len(news):]:
            fails.append(("V1", f"{key}: no unit in the new package (old line {u.line})"))
        if len(news) > len(olds):
            where = ", ".join(f"{u.stem}.py:{u.line}" for u in news)
            fails.append(("V2", f"{key}: {len(news)} units for {len(olds)} old ({where})"))
    for key, news in by_new.items():
        if key not in by_old:
            fails += [("V3", f"{key}: no such old unit ({u.stem}.py:{u.line})") for u in news]
    return pairs, fails


@dataclass
class Counts:
    d1: int = 0
    relimport: int = 0
    css: int = 0


def compare_bodies(pairs: list[tuple[vu.Unit, vu.Unit]], d1: set[str]) -> tuple[list[Fail], Counts]:
    fails: list[Fail] = []
    cnt = Counts()
    for old, new in pairs:
        nodes, rep, pre = norm.normalise(new, d1)
        cnt.d1 += rep.d1
        cnt.relimport += rep.relimport
        cnt.css += rep.css
        fails += [("V5", f"{old.key} ({new.stem}.py:{new.line}): {m}") for m in rep.unlisted]
        if pre:
            fails.append(("V4", f"{old.key} ({new.stem}.py:{new.line}): {pre}"))
        elif norm.dump(old.nodes) != norm.dump(nodes):
            fails.append(("V4", f"{old.key} ({new.stem}.py:{new.line}): {norm.first_diff(old.nodes, nodes)}"))
    return fails, cnt


def d1_checks(old_text: str, loaded: Loaded, d1: set[str]) -> tuple[list[Fail], int, int, int]:
    """V6 bare D1 names, V7 per-name site counts. Returns (fails, new_sites, old_sites, bare)."""
    old_counts, _ = scope.global_loads(old_text, d1)
    new_counts: Counter = Counter()
    fails: list[Fail] = []
    bare = 0
    for stem, text in loaded.texts.items():
        if stem not in loaded.parsed:
            continue
        if stem == "deps":
            new_counts += scope.global_loads(text, d1)[0]
            continue
        new_counts += scope.deps_attr_loads(loaded.parsed[stem], d1)
        _, sites = scope.global_loads(text, d1)
        for name, lines in sorted(sites.items()):
            bare += len(lines)
            fails += [("V6", f"{stem}.py:{ln}: bare D1 name {name}") for ln in lines[:5]]
            if len(lines) > 5:
                fails.append(("V6", f"{stem}.py: ... {len(lines) - 5} more bare {name} sites"))
    for name in sorted(d1):
        if new_counts[name] != old_counts[name]:
            fails.append(("V7", f"D1 {name}: {new_counts[name]} sites in the new package, {old_counts[name]} in the old"))
    return fails, sum(new_counts.values()), sum(old_counts.values()), bare
