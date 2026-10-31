"""Shared helpers for the Inc 8b security probes (security-reviewer, E5)."""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path

import s19_app
from tests.support import b100_projects as bp
from tests.support.b100_links import create_junction

SCRATCH = Path(__file__).resolve().parent / "runs"
print("s19_app.__file__ =", s19_app.__file__, flush=True)

CODE_RE = re.compile(r"\b(MF|CHG|MANIFEST|GATHER|SAVE|PLAN)-[A-Z0-9-]+")
CLASS_RE = re.compile(r"\b[A-Z][A-Za-z]+(Error|Exception)\b")
BAD_RE = re.compile(r"WinError|Refusing|Traceback|errno", re.I)
CTRL_RE = re.compile("[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩؜  ﻿]")

MADE_LINKS: list[Path] = []


def fresh(case: str) -> Path:
    root = SCRATCH / case
    if root.exists():
        remove_links(root)
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    return root


def junction(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    create_junction(link, target)
    MADE_LINKS.append(link)


def symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, link)
    MADE_LINKS.append(link)


def is_link(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def remove_links(root: Path) -> int:
    """Remove every link/junction under root (never following one)."""
    removed = 0
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            p = Path(e.path)
            if is_link(p):
                try:
                    if e.is_dir(follow_symlinks=False) or (os.lstat(p).st_file_attributes & 0x10):
                        os.rmdir(p)
                    else:
                        os.unlink(p)
                except OSError:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
                removed += 1
            elif e.is_dir(follow_symlinks=False):
                stack.append(p)
    return removed


def sweep(root: Path) -> int:
    n = 0
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            p = Path(e.path)
            if is_link(p):
                n += 1
            elif e.is_dir(follow_symlinks=False):
                stack.append(p)
    return n


_TEMPLATE: dict = {}


def template_project(files=("firmware.s19",)) -> Path:
    """A project P saved once by the shipped handler; later cases copy it."""
    key = tuple(files)
    if key in _TEMPLATE:
        return _TEMPLATE[key]
    root = SCRATCH / ("_template_" + "_".join(f.replace(".", "") for f in files))
    base = root / "base"
    project = base / ".s19tool" / "workarea" / "P"
    if not (project / "project.json").exists():
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        bp.save_case01_project(base, "P", files=files)
    _TEMPLATE[key] = project
    return project


def new_base(case: str, files=("firmware.s19",)) -> tuple[Path, Path, Path]:
    """(root, base, W) with a copy of the template P inside W."""
    root = fresh(case)
    base = root / "base"
    tpl = template_project(files)
    W = base / ".s19tool" / "workarea"
    W.mkdir(parents=True)
    shutil.copytree(tpl, W / "P")
    # the app keeps other folders under .s19tool; copy siblings except workarea
    for sib in tpl.parent.parent.iterdir():
        if sib.name != "workarea" and not (base / ".s19tool" / sib.name).exists():
            if sib.is_dir():
                shutil.copytree(sib, base / ".s19tool" / sib.name)
            else:
                shutil.copy2(sib, base / ".s19tool" / sib.name)
    # common sources folder the template used (base_src) is outside base
    src = tpl.parent.parent.parent.parent / "base_src"
    if src.exists():
        shutil.copytree(src, root / "base_src")
    return root, base, W


def digests(root: Path) -> dict:
    if not root.exists():
        return {}
    return bp.tree_digests(root)


def scan_lines(lines) -> dict:
    out = {"codes": [], "classes": [], "bad": [], "ctrl": []}
    for line in lines:
        if CODE_RE.search(line):
            out["codes"].append(line)
        if CLASS_RE.search(line):
            out["classes"].append(line)
        if BAD_RE.search(line):
            out["bad"].append(line)
        if CTRL_RE.search(line):
            out["ctrl"].append(line)
    return {k: v for k, v in out.items() if v}


def run(base: Path, scenario):
    return bp.run_app(base, scenario)


async def open_p(pilot, app, name="P"):
    return await bp.load_project(pilot, app, name)


async def save(pilot, app, log, name):
    return await bp.save_project(pilot, app, log, name)


def short(lines, n=400):
    return [l[:n] for l in lines]
