"""PROTOTYPE — Flow Builder state model (THROWAWAY; delete once folded in).

================================  READ ME  ==================================
This is a *logic* prototype (see .claude/skills/prototype/LOGIC.md). It exists
to answer, by hand-driving, whether the EXTENDED flow-builder state model feels
right BEFORE we commit it through /dev-flow. It deliberately STUBS all real S19
parsing — the questions here are about block-threading semantics, not bytes.

The real tracer today (s19_app/tui/services/flow_model.py + flow_execution_
service.py) ships SOURCE -> PATCH -> WRITE-OUT with an ok/error/skipped status
triad and a single abort-on-first-error rule. Your request adds LOAD-with-
notices, CHECK (read-only, pass-through), CRC (address-space-growing, order-
constrained), config/template inputs, flow save/load, and variant reuse. Each
of those pokes the state model in a way worth *feeling* before locking it.

QUESTIONS THIS PROTOTYPE PUTS ON TRIAL
  Q1  notify-not-block: Load integrity findings must NOT abort the chain; only
      a real show-stopper (unresolved/unopenable image) does. -> new `notices`
      block status + a `WARN`-vs-`STOP` severity split.
  Q2  read-only Check: output is "None, pass the s19 along". Does a CHECK
      *failure* abort downstream? It produces a report nobody consumes, and the
      image is untouched -> prototype says NO: chain continues (image intact).
      Contrast with LOAD/PATCH failure, which breaks the image -> downstream
      SKIPPED. This asymmetry is the whole point.
  Q3  CRC grows the address space: CRC reads the whole post-patch image, writes
      CRC bytes back, and may EXTEND ranges. Watch the working-image range set
      change mid-chain and a later WRITE-OUT pick up the grown image. Also the
      hard ordering PATCH -> CRC (a CRC before any patch is a notice, not a
      crash, but flags "computed over unpatched bytes").
  Q4  external -> project: a Load of an external path must import into the
      project first (provenance recorded), never run straight off the outside
      path.
  Q5  variant reuse: the SAME saved flow, run against a different input image,
      is the automation payoff. `run` with a source override models it.

HOW TO RUN
  python prototypes/flow_builder.prototype.py
  (line-based REPL; type `?` for the command list; `q` to quit.)

The pure model lives in the top section (no I/O, liftable into the real
services). The bottom section is a throwaway ANSI shell over it.
============================================================================
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple

# ============================================================================
# PURE MODEL  (no I/O — this is the bit that could inform the real services)
# ============================================================================

# --- block kinds (JSON persistence tags) ------------------------------------
BLOCK_LOAD = "load"
BLOCK_PATCH = "patch"
BLOCK_CHECK = "check"
BLOCK_CRC = "crc"
BLOCK_WRITE_OUT = "write_out"

# --- block status vocabulary (EXTENDED: +notices) ---------------------------
ST_OK = "ok"            # succeeded, clean
ST_NOTICES = "notices"  # succeeded, produced advisory findings (Q1/Q2)
ST_ERROR = "error"      # block hit its OWN show-stopper
ST_SKIPPED = "skipped"  # an upstream IMAGE-breaking block failed

# --- finding severity (the notify-not-block axis, Q1) -----------------------
SEV_WARN = "WARN"  # advisory: surface it, keep going
SEV_STOP = "STOP"  # show-stopper for THIS block's own task

FLOW_OK = "ok"
FLOW_ERROR = "error"


@dataclass(frozen=True)
class LoadBlock:
    """Seed the working image. `image_ref` is project-relative; if `external`
    is set, the block imports that outside path into the project first (Q4).
    Integrity validation emits NOTICES, never aborts (Q1) — unless the image
    cannot be resolved/opened at all (a STOP)."""
    image_ref: str
    file_type: str = "s19"
    external: bool = False
    kind: str = BLOCK_LOAD


@dataclass(frozen=True)
class PatchBlock:
    """Apply a change document (json) to the working mem_map."""
    change_doc_ref: str
    kind: str = BLOCK_PATCH


@dataclass(frozen=True)
class CheckBlock:
    """Read-only. Verify an address list (json) against the working image and
    emit a report. Passes the image through UNCHANGED (Q2)."""
    check_doc_ref: str
    kind: str = BLOCK_CHECK


@dataclass(frozen=True)
class CrcBlock:
    """Compute a CRC over a region and write it back — may GROW ranges (Q3).
    `config_ref` names a json algo-config; templates live in CRC_TEMPLATES."""
    config_ref: str
    kind: str = BLOCK_CRC


@dataclass(frozen=True)
class WriteOutBlock:
    """Emit the working image to a file under the work area."""
    output_name: str
    fmt: str = "s19"
    kind: str = BLOCK_WRITE_OUT


FlowBlock = object  # Union of the five above (kept loose for the prototype)


@dataclass
class Flow:
    name: str
    blocks: List[FlowBlock] = field(default_factory=list)
    schema_version: int = 2  # v2 = tracer(v1) + check/crc/notices


@dataclass
class Finding:
    severity: str   # WARN | STOP
    message: str


@dataclass
class BlockResult:
    index: int
    kind: str
    status: str
    summary: str = ""
    findings: List[Finding] = field(default_factory=list)


@dataclass
class WorkingImage:
    """The state threaded through the chain (stubbed stand-in for mem_map)."""
    byte_count: int = 0
    ranges: List[Tuple[int, int]] = field(default_factory=list)
    label: str = "(empty)"
    broken: bool = False  # an image-producing block failed -> unusable

    def range_str(self) -> str:
        return " ".join(f"{a:#06x}-{b:#06x}" for a, b in self.ranges) or "-"


@dataclass
class FlowRunResult:
    status: str = FLOW_OK
    block_results: List[BlockResult] = field(default_factory=list)
    produced: List[str] = field(default_factory=list)  # write-out artifacts
    reports: List[str] = field(default_factory=list)    # check reports
    final_image: WorkingImage = field(default_factory=WorkingImage)


# --- STUBBED "project" the blocks resolve against ---------------------------
# Each fixture: (bytes, ranges, integrity findings emitted on load).
IMAGE_FIXTURES: Dict[str, Tuple[int, List[Tuple[int, int]], List[Finding]]] = {
    "good.s19":   (4096, [(0x8000, 0x8FFF)], []),
    "warn.s19":   (4096, [(0x8000, 0x8FFF)],
                   [Finding(SEV_WARN, "record 12: checksum mismatch (0x3A!=0x3B)"),
                    Finding(SEV_WARN, "3 out-of-order address records")]),
    "variant2.s19": (4096, [(0x8000, 0x8FFF)],
                     [Finding(SEV_WARN, "S0 header differs from good.s19")]),
    # a Load whose ref cannot be resolved at all -> STOP (the only Load abort):
    "missing.s19": (0, [], [Finding(SEV_STOP, "image not found in project")]),
}
# change documents (patch inputs)
CHANGE_DOCS: Dict[str, Optional[Tuple[int, List[Tuple[int, int]]]]] = {
    "patch_base.json": (16, []),                 # 16 bytes in-range
    "patch_grow.json": (8, [(0x9000, 0x9007)]),  # adds a new range
    "patch_bad.json": None,                      # unreadable -> STOP
}
# check documents (address lists); value = (n_present, n_absent) once run
CHECK_DOCS: Dict[str, Optional[List[int]]] = {
    "check_core.json": [0x8000, 0x8010, 0x8FF0],
    "check_gaps.json": [0x8000, 0xA000, 0xB000],  # 2 absent -> WARN report
    "check_bad.json": None,                        # unreadable -> STOP (local)
}
# CRC template library (the "library of json configs" you asked for)
CRC_TEMPLATES: Dict[str, dict] = {
    "crc32_le": {"width": 32, "poly": "0x04C11DB7", "endian": "little",
                 "fill_gaps": False, "region": [0x8000, 0x8FFF],
                 "output_address": 0x8FFC},
    "crc16_ccitt_be": {"width": 16, "poly": "0x1021", "endian": "big",
                       "fill_gaps": False, "region": [0x8000, 0x8FFF],
                       "output_address": 0x8FFE},
    # writes OUTSIDE the loaded range -> forces a range GROW (Q3):
    "crc32_append": {"width": 32, "poly": "0x04C11DB7", "endian": "little",
                     "fill_gaps": True, "gap_fill": "0xFF",
                     "region": [0x8000, 0x8FFF], "output_address": 0x9100},
}


def _find_load_upstream(blocks: List[FlowBlock], upto: int) -> bool:
    """Q3 helper: was there any PATCH before this index?"""
    return any(getattr(b, "kind", "") == BLOCK_PATCH for b in blocks[:upto])


def run_flow(flow: Flow, source_override: Optional[str] = None) -> FlowRunResult:
    """Execute blocks in order, threading a WorkingImage.

    The single most important rule this models: **who aborts the chain.**
    - LOAD / PATCH / CRC failures BREAK the image -> downstream SKIPPED.
    - CHECK failures do NOT (image is intact, nobody consumes its output) ->
      recorded as this block's error, chain CONTINUES. (Q2)
    - Integrity/verify findings are NOTICES (WARN) -> never abort. (Q1)
    """
    res = FlowRunResult()
    img = WorkingImage()
    have_image = False

    for i, b in enumerate(flow.blocks):
        kind = getattr(b, "kind", "?")

        # once the IMAGE is broken/absent, image-dependent blocks are skipped
        if img.broken and kind in (BLOCK_PATCH, BLOCK_CRC, BLOCK_WRITE_OUT):
            res.block_results.append(
                BlockResult(i, kind, ST_SKIPPED, "skipped (image broken upstream)"))
            continue

        if kind == BLOCK_LOAD:
            ref = source_override or b.image_ref  # Q5: variant reuse
            byte_count, ranges, findings = IMAGE_FIXTURES.get(
                ref, (0, [], [Finding(SEV_STOP, f"unknown image {ref!r}")]))
            stop = [f for f in findings if f.severity == SEV_STOP]
            if stop:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR, f"load {ref}: show-stopper",
                                findings))
                continue
            provenance = " (imported from external)" if b.external else ""
            img = WorkingImage(byte_count, list(ranges),
                               f"{ref}{provenance}", broken=False)
            have_image = True
            status = ST_NOTICES if findings else ST_OK
            res.block_results.append(
                BlockResult(i, kind, status,
                            f"loaded {ref}: {byte_count}B, {len(ranges)} range(s)"
                            + (f"; {len(findings)} notice(s)" if findings else ""),
                            findings))

        elif kind == BLOCK_PATCH:
            if not have_image:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR, "patch: no upstream image",
                                [Finding(SEV_STOP, "no source loaded")]))
                continue
            doc = CHANGE_DOCS.get(b.change_doc_ref, "??")
            if doc is None:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR,
                                f"patch {b.change_doc_ref}: unreadable",
                                [Finding(SEV_STOP, "change document unreadable")]))
                continue
            n, new_ranges = doc
            img.byte_count += n
            grew = [r for r in new_ranges if r not in img.ranges]
            img.ranges = sorted(img.ranges + grew)
            res.block_results.append(
                BlockResult(i, kind, ST_OK,
                            f"applied {n} entr{'y' if n == 1 else 'ies'}"
                            + (f"; +{len(grew)} new range(s)" if grew else "")))

        elif kind == BLOCK_CHECK:
            # Q2: read-only. Failure here does NOT break the image.
            addrs = CHECK_DOCS.get(b.check_doc_ref, "??")
            if addrs is None:
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR,
                                f"check {b.check_doc_ref}: unreadable "
                                "(image passes through)",
                                [Finding(SEV_STOP, "check document unreadable")]))
                continue  # NB: image NOT marked broken -> chain continues
            if not have_image:
                res.block_results.append(
                    BlockResult(i, kind, ST_NOTICES, "check: no image to verify",
                                [Finding(SEV_WARN, "nothing loaded to check")]))
                continue
            present = [a for a in addrs
                       if any(lo <= a <= hi for lo, hi in img.ranges)]
            absent = [a for a in addrs if a not in present]
            report = (f"check {b.check_doc_ref}: {len(present)}/{len(addrs)} "
                      f"addresses in image")
            res.reports.append(report + (f"; MISSING {[hex(a) for a in absent]}"
                                          if absent else "; all present"))
            findings = [Finding(SEV_WARN, f"{hex(a)} not in image") for a in absent]
            res.block_results.append(
                BlockResult(i, kind, ST_NOTICES if absent else ST_OK,
                            report + ("; pass-through" if not absent
                                      else f"; {len(absent)} missing (notice)"),
                            findings))

        elif kind == BLOCK_CRC:
            if not have_image:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR, "crc: no upstream image",
                                [Finding(SEV_STOP, "no image")]))
                continue
            cfg = CRC_TEMPLATES.get(b.config_ref)
            if cfg is None:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR,
                                f"crc {b.config_ref}: config not found",
                                [Finding(SEV_STOP, "unknown crc config")]))
                continue
            findings: List[Finding] = []
            # Q3 ordering: CRC over unpatched bytes is a NOTICE, not an error.
            if not _find_load_upstream(flow.blocks, i):
                findings.append(Finding(
                    SEV_WARN, "CRC computed with no PATCH upstream "
                              "(may cover unpatched bytes)"))
            out = cfg["output_address"]
            width_bytes = cfg["width"] // 8
            covered = any(lo <= out <= hi for lo, hi in img.ranges)
            if not covered:
                # THE SEAM: CRC extends the address space (Q3)
                img.ranges = sorted(img.ranges + [(out, out + width_bytes - 1)])
                img.byte_count += width_bytes
                findings.append(Finding(
                    SEV_WARN, f"output {out:#06x} outside loaded ranges -> "
                              f"image GREW by {width_bytes}B"))
            else:
                img.byte_count += 0  # in-place overwrite
            res.block_results.append(
                BlockResult(i, kind, ST_NOTICES if findings else ST_OK,
                            f"crc {b.config_ref} ({cfg['width']}b/{cfg['endian']}) "
                            f"-> {out:#06x}",
                            findings))

        elif kind == BLOCK_WRITE_OUT:
            if not have_image:
                img.broken = True
                res.block_results.append(
                    BlockResult(i, kind, ST_ERROR, "write-out: no image",
                                [Finding(SEV_STOP, "no image")]))
                continue
            path = f".s19tool/workarea/<project>/{b.output_name}"
            res.produced.append(f"{path}  [{b.byte_count if False else img.byte_count}B, "
                                f"{img.fmt if False else b.fmt}]")
            res.block_results.append(
                BlockResult(i, kind, ST_OK, f"wrote {b.output_name} ({b.fmt})"))

        else:
            img.broken = True
            res.block_results.append(
                BlockResult(i, kind, ST_ERROR, f"unknown block {kind!r}"))

    res.final_image = img
    # whole-flow status: image-breaking error OR any block error
    if img.broken or any(r.status == ST_ERROR for r in res.block_results):
        res.status = FLOW_ERROR
    return res


# --- flow (de)serialization — the flow.json envelope on trial ---------------
def flow_to_dict(flow: Flow) -> dict:
    return {"name": flow.name, "schema_version": flow.schema_version,
            "blocks": [asdict(b) for b in flow.blocks]}


_BLOCK_CTORS: Dict[str, Callable[[dict], FlowBlock]] = {
    BLOCK_LOAD: lambda d: LoadBlock(d["image_ref"], d.get("file_type", "s19"),
                                    d.get("external", False)),
    BLOCK_PATCH: lambda d: PatchBlock(d["change_doc_ref"]),
    BLOCK_CHECK: lambda d: CheckBlock(d["check_doc_ref"]),
    BLOCK_CRC: lambda d: CrcBlock(d["config_ref"]),
    BLOCK_WRITE_OUT: lambda d: WriteOutBlock(d["output_name"], d.get("fmt", "s19")),
}


def flow_from_dict(d: dict) -> Flow:
    blocks = [_BLOCK_CTORS[b["kind"]](b) for b in d.get("blocks", [])]
    return Flow(d.get("name", "flow"), blocks, d.get("schema_version", 2))


# ============================================================================
# THROWAWAY TUI SHELL  (ANSI full-frame redraw; delete with the prototype)
# ============================================================================

BOLD, DIM, RED, GRN, YEL, CYN, RST = (
    "\x1b[1m", "\x1b[2m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m", "\x1b[0m")
_STATUS_COLOR = {ST_OK: GRN, ST_NOTICES: YEL, ST_ERROR: RED, ST_SKIPPED: DIM}
_KIND_GLYPH = {BLOCK_LOAD: "load ", BLOCK_PATCH: "patch", BLOCK_CHECK: "check",
               BLOCK_CRC: "crc  ", BLOCK_WRITE_OUT: "write"}


def _enable_vt() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # survive cp1252 consoles
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def _clear() -> None:
    sys.stdout.write("\x1b[2J\x1b[H")


def _block_label(b: FlowBlock) -> str:
    k = getattr(b, "kind", "?")
    if k == BLOCK_LOAD:
        return f"{_KIND_GLYPH[k]}  {b.image_ref}{' [EXTERNAL]' if b.external else ''}"
    if k == BLOCK_PATCH:
        return f"{_KIND_GLYPH[k]}  {b.change_doc_ref}"
    if k == BLOCK_CHECK:
        return f"{_KIND_GLYPH[k]}  {b.check_doc_ref}"
    if k == BLOCK_CRC:
        return f"{_KIND_GLYPH[k]}  {b.config_ref}"
    if k == BLOCK_WRITE_OUT:
        return f"{_KIND_GLYPH[k]}  {b.output_name} ({b.fmt})"
    return k


class Shell:
    def __init__(self) -> None:
        self.flow = Flow("untitled-flow")
        self.result: Optional[FlowRunResult] = None
        self.slots: Dict[str, dict] = {}
        self.msg = "welcome — type ? for commands"

    # -- rendering -----------------------------------------------------------
    def render(self) -> None:
        _clear()
        w = "\n"
        out = []
        out.append(f"{BOLD}{CYN}S19 FLOW BUILDER — logic prototype{RST}  "
                   f"{DIM}(throwaway; models block-threading only){RST}")
        out.append(f"{DIM}{'-'*76}{RST}")
        # flow definition
        out.append(f"{BOLD}Flow:{RST} {self.flow.name}   "
                   f"{DIM}schema v{self.flow.schema_version}, "
                   f"{len(self.flow.blocks)} block(s){RST}")
        if not self.flow.blocks:
            out.append(f"  {DIM}(no blocks — add: l/p/c/r/w){RST}")
        for i, b in enumerate(self.flow.blocks):
            out.append(f"  {DIM}{i}{RST} {_block_label(b)}")
        out.append("")
        # last run result
        if self.result:
            r = self.result
            col = GRN if r.status == FLOW_OK else RED
            out.append(f"{BOLD}Last run:{RST} {col}{r.status.upper()}{RST}")
            for br in r.block_results:
                c = _STATUS_COLOR.get(br.status, RST)
                out.append(f"  {DIM}{br.index}{RST} {c}{br.status:<8}{RST} "
                           f"{DIM}{_KIND_GLYPH.get(br.kind, br.kind)}{RST} "
                           f"{br.summary}")
                for f in br.findings:
                    fc = YEL if f.severity == SEV_WARN else RED
                    out.append(f"        {fc}{f.severity}{RST} {DIM}{f.message}{RST}")
            fi = r.final_image
            out.append(f"  {BOLD}working image:{RST} {fi.label}  "
                       f"{fi.byte_count}B  ranges: {CYN}{fi.range_str()}{RST}"
                       + (f"  {RED}[BROKEN]{RST}" if fi.broken else ""))
            if r.reports:
                out.append(f"  {BOLD}check reports:{RST}")
                for rep in r.reports:
                    out.append(f"     {DIM}{rep}{RST}")
            if r.produced:
                out.append(f"  {BOLD}produced:{RST}")
                for p in r.produced:
                    out.append(f"     {GRN}{p}{RST}")
        else:
            out.append(f"{DIM}(no run yet — `x` to run){RST}")
        out.append("")
        if self.slots:
            out.append(f"{BOLD}Saved flows:{RST} {DIM}{', '.join(self.slots)}{RST}")
        # command bar
        out.append(f"{DIM}{'-'*76}{RST}")
        out.append(
            f"{BOLD}l{RST}oad {DIM}<good|warn|variant2|missing|ext:NAME>{RST}  "
            f"{BOLD}p{RST}atch {DIM}<base|grow|bad>{RST}  "
            f"{BOLD}c{RST}heck {DIM}<core|gaps|bad>{RST}\n"
            f"{BOLD}r{RST} crc {DIM}<crc32_le|crc16_ccitt_be|crc32_append>{RST}  "
            f"{BOLD}w{RST}rite {DIM}<name>{RST}   "
            f"{BOLD}mv{RST} i j   {BOLD}rm{RST} i\n"
            f"{BOLD}x{RST} run   {BOLD}X{RST} run-as {DIM}<good|warn|variant2>{RST} "
            f"{DIM}(variant reuse){RST}   {BOLD}tpl{RST} list-crc\n"
            f"{BOLD}save{RST} slot   {BOLD}open{RST} slot   {BOLD}json{RST} "
            f"{BOLD}name{RST} <n>   {BOLD}new{RST}   {BOLD}?{RST} help   {BOLD}q{RST}uit")
        out.append(f"{YEL}>> {self.msg}{RST}")
        sys.stdout.write(w.join(out) + "\n\n")
        sys.stdout.flush()

    # -- command handling ----------------------------------------------------
    def dispatch(self, line: str) -> bool:
        parts = line.strip().split()
        if not parts:
            return True
        cmd, args = parts[0], parts[1:]
        try:
            return self._dispatch(cmd, args)
        except Exception as exc:  # prototype: never die on a bad command
            self.msg = f"{RED}error: {exc}{RST}"
            return True

    def _dispatch(self, cmd: str, args: List[str]) -> bool:
        if cmd in ("q", "quit", "exit"):
            return False
        elif cmd == "?":
            self.msg = ("Q1 notices!=abort | Q2 check failure keeps going | "
                        "Q3 crc grows ranges | Q4 ext->import | Q5 X=variant reuse")
        elif cmd == "l":
            ref = args[0] if args else "good"
            external = ref.startswith("ext:")
            name = ref[4:] if external else ref
            image_ref = name if name.endswith(".s19") else f"{name}.s19"
            self.flow.blocks.append(LoadBlock(image_ref, external=external))
            self.msg = f"added LOAD {image_ref}" + (" (external→import)" if external else "")
        elif cmd == "p":
            ref = (args[0] if args else "base")
            doc = ref if ref.endswith(".json") else f"patch_{ref}.json"
            self.flow.blocks.append(PatchBlock(doc))
            self.msg = f"added PATCH {doc}"
        elif cmd == "c":
            ref = (args[0] if args else "core")
            doc = ref if ref.endswith(".json") else f"check_{ref}.json"
            self.flow.blocks.append(CheckBlock(doc))
            self.msg = f"added CHECK {doc}"
        elif cmd == "r":
            ref = args[0] if args else "crc32_le"
            self.flow.blocks.append(CrcBlock(ref))
            self.msg = f"added CRC {ref}"
        elif cmd == "w":
            name = args[0] if args else "out.s19"
            fmt = "hex" if name.endswith(".hex") else "s19"
            self.flow.blocks.append(WriteOutBlock(name, fmt))
            self.msg = f"added WRITE-OUT {name}"
        elif cmd == "rm":
            i = int(args[0])
            b = self.flow.blocks.pop(i)
            self.msg = f"removed [{i}] {getattr(b,'kind','?')}"
        elif cmd == "mv":
            i, j = int(args[0]), int(args[1])
            b = self.flow.blocks.pop(i)
            self.flow.blocks.insert(j, b)
            self.msg = f"moved {i}→{j}"
        elif cmd == "x":
            self.result = run_flow(self.flow)
            self.msg = f"ran flow → {self.result.status.upper()}"
        elif cmd == "X":
            override = args[0] if args else "good"
            ref = override if override.endswith(".s19") else f"{override}.s19"
            self.result = run_flow(self.flow, source_override=ref)
            self.msg = f"ran flow with source override → {ref} (Q5 variant reuse)"
        elif cmd == "tpl":
            self.msg = "CRC templates: " + " | ".join(
                f"{n}({c['width']}b,{c['endian']})" for n, c in CRC_TEMPLATES.items())
        elif cmd == "name":
            self.flow.name = " ".join(args) or self.flow.name
            self.msg = f"renamed flow → {self.flow.name}"
        elif cmd == "new":
            self.flow = Flow("untitled-flow")
            self.result = None
            self.msg = "new empty flow"
        elif cmd == "save":
            slot = args[0] if args else self.flow.name
            self.slots[slot] = flow_to_dict(self.flow)
            self.msg = f"saved flow → slot '{slot}' (in-memory; JSON envelope ready)"
        elif cmd == "open":
            slot = args[0] if args else ""
            if slot in self.slots:
                self.flow = flow_from_dict(self.slots[slot])
                self.result = None
                self.msg = f"opened flow from slot '{slot}'"
            else:
                self.msg = f"{RED}no slot '{slot}'{RST}"
        elif cmd == "json":
            _clear()
            print(f"{BOLD}flow.json envelope (schema v{self.flow.schema_version}):{RST}\n")
            print(json.dumps(flow_to_dict(self.flow), indent=2))
            input(f"\n{DIM}[enter to return]{RST}")
            self.msg = "showed flow.json envelope"
        else:
            self.msg = f"{RED}unknown command '{cmd}' — type ?{RST}"
        return True

    def loop(self) -> None:
        _enable_vt()
        while True:
            self.render()
            try:
                line = input("cmd> ")
            except (EOFError, KeyboardInterrupt):
                break
            if not self.dispatch(line):
                break
        _clear()
        print("prototype closed. Capture the verdict in prototypes/NOTES.md.")


if __name__ == "__main__":
    Shell().loop()
