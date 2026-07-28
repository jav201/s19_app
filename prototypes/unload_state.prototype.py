"""
PROTOTYPE — throwaway. Models the *intended* unload state machine for s19_app.

QUESTION being answered
-----------------------
The app loads an S19/HEX + a MAC + an A2L that COEXIST inside one LoadedFile
(`current_file`). Today there is no way to unload any of them. "Unload" must be
the INVERSE of the existing merges (_merge_primary_with_existing_mac /
_merge_mac_with_existing_primary): drop ONE artifact's fields, keep the others,
and carry the SURVIVING artifact's derived facts forward (entropy_windows,
out_of_order_count, entry_point). When the last artifact goes, current_file
becomes None.

Does that model feel right when you push it through the hard cases?
  - unload MAC while S19 present  -> entropy_windows MUST survive (this is the
    exact field the live bug drops; here it is preserved).
  - unload S19 while MAC present  -> a MAC-only state (no image); entropy gone.
  - unload the last artifact      -> current_file None (empty state).

Run:  python prototypes/unload_state.prototype.py
(Windows single-key input via msvcrt; press the bracketed keys.)

The LOGIC block below (LoadState + unload_* + load_* + describe) is the KEEPABLE
part — pure, no I/O — designed to lift into app.py as the unload seam. The TUI
shell at the bottom is throwaway.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional


# ===========================================================================
# PORTABLE LOGIC (pure — lift this into the real app; no terminal code here)
# ===========================================================================


@dataclass(frozen=True)
class LoadState:
    """A minimal stand-in for LoadedFile, capturing only what unload touches.

    Three coexisting artifacts + the primary image's DERIVED loader facts. In
    the real app these are fields on one LoadedFile; `current_file is None`
    corresponds exactly to `is_empty` here.
    """

    # --- primary image (s19/hex) + its derived facts ---
    primary_kind: Optional[str] = None       # "s19" | "hex" | None
    primary_name: Optional[str] = None
    mem_map_bytes: int = 0
    ranges: int = 0
    entropy_windows: int = 0                  # DERIVED from the image (bug: dropped on MAC-merge)
    out_of_order_count: int = 0
    entry_point: Optional[int] = None
    # --- MAC ---
    mac_name: Optional[str] = None
    mac_records: int = 0
    # --- A2L ---
    a2l_name: Optional[str] = None
    a2l_tags: int = 0

    @property
    def has_primary(self) -> bool:
        return self.primary_kind is not None

    @property
    def has_mac(self) -> bool:
        return self.mac_name is not None

    @property
    def has_a2l(self) -> bool:
        return self.a2l_name is not None

    @property
    def is_empty(self) -> bool:
        # current_file becomes None exactly here.
        return not (self.has_primary or self.has_mac or self.has_a2l)


# ---- unload operations (each returns a NEW state; the inverse of the merges) ----

_EMPTY = LoadState()


def unload_primary(s: LoadState) -> LoadState:
    """Drop the S19/HEX image + ALL its derived facts; keep MAC + A2L."""
    return replace(
        s,
        primary_kind=None, primary_name=None,
        mem_map_bytes=0, ranges=0,
        entropy_windows=0,            # image gone -> no entropy (correct)
        out_of_order_count=0, entry_point=None,
    )


def unload_mac(s: LoadState) -> LoadState:
    """Drop the MAC; keep the primary image (INCLUDING entropy_windows) + A2L.

    This is the case the live bug gets wrong: the merge rebuild resets
    entropy_windows to []. Here it is carried forward untouched.
    """
    return replace(s, mac_name=None, mac_records=0)


def unload_a2l(s: LoadState) -> LoadState:
    """Drop the A2L; keep the primary image + MAC."""
    return replace(s, a2l_name=None, a2l_tags=0)


def unload_all(_s: LoadState) -> LoadState:
    """Tear everything down -> current_file None."""
    return _EMPTY


# ---- load helpers (only to set up scenarios to unload from) ----

def load_case01() -> LoadState:
    """s19 + mac + a2l coexistence (the exact repro fixture)."""
    return LoadState(
        primary_kind="s19", primary_name="firmware.s19",
        mem_map_bytes=358, ranges=3, entropy_windows=2,
        out_of_order_count=0, entry_point=0xEB00,
        mac_name="firmware.mac", mac_records=1,
        a2l_name="firmware.a2l", a2l_tags=4,
    )


def load_s19_only() -> LoadState:
    return LoadState(
        primary_kind="s19", primary_name="firmware.s19",
        mem_map_bytes=358, ranges=3, entropy_windows=2, entry_point=0xEB00,
    )


def load_mac_only() -> LoadState:
    return LoadState(mac_name="firmware.mac", mac_records=1)


# ---- pure descriptor used by the shell (and handy for an assertion later) ----

def memory_map_would_render(s: LoadState) -> bool:
    """The Memory Map renders iff there is an image with entropy windows.

    Mirrors screens_directionb.py render_ranges: `not ranges or span<=0 or
    not entropy_windows` -> the (mis-labelled) empty note. The point of the fix
    is that this stays True whenever an image is present.
    """
    return s.ranges > 0 and s.entropy_windows > 0


# ===========================================================================
# THROWAWAY TUI SHELL (delete when the question is answered)
# ===========================================================================


def _c(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m"


def render(state: LoadState, last: str) -> str:
    B = lambda t: _c("1", t)      # noqa: E731 bold
    D = lambda t: _c("2", t)      # noqa: E731 dim
    lines = []
    lines.append(B("=== UNLOAD STATE PROTOTYPE ===") + D("  (throwaway — intended logic)"))
    lines.append("")
    cf = D("None  (empty state — no current_file)") if state.is_empty else B("PRESENT")
    lines.append(f"{B('current_file:')} {cf}")
    lines.append("")
    if state.has_primary:
        ep = f"0x{state.entry_point:X}" if state.entry_point is not None else "-"
        lines.append(
            f"  {B('PRIMARY')} {state.primary_kind}: {state.primary_name}  "
            + D(f"mem={state.mem_map_bytes}B ranges={state.ranges} ")
            + _c("1;36", f"entropy_windows={state.entropy_windows}")
            + D(f" ooo={state.out_of_order_count} entry={ep}")
        )
    else:
        lines.append(f"  {D('PRIMARY  (none)')}")
    lines.append(f"  {B('MAC') if state.has_mac else D('MAC')}:  "
                 + (f"{state.mac_name}  " + D(f"records={state.mac_records}") if state.has_mac else D("(none)")))
    lines.append(f"  {B('A2L') if state.has_a2l else D('A2L')}:  "
                 + (f"{state.a2l_name}  " + D(f"tags={state.a2l_tags}") if state.has_a2l else D("(none)")))
    lines.append("")
    mm = _c("1;32", "RENDERS") if memory_map_would_render(state) else _c("1;31", "shows 'No file loaded'")
    lines.append(f"  {B('Memory Map:')} {mm}")
    lines.append("")
    lines.append(D(f"last: {last}"))
    lines.append("")
    lines.append(
        B("[1]") + D(" load case_01(s19+mac+a2l)  ") + B("[2]") + D(" load s19-only  ")
        + B("[3]") + D(" load mac-only")
    )
    lines.append(
        B("[s]") + D(" unload S19/HEX   ") + B("[m]") + D(" unload MAC   ")
        + B("[a]") + D(" unload A2L   ") + B("[x]") + D(" unload ALL   ") + B("[q]") + D(" quit")
    )
    return "\n".join(lines)


def main() -> None:
    try:
        import msvcrt  # Windows
        getch = lambda: msvcrt.getch().decode("utf-8", "ignore").lower()  # noqa: E731
    except ImportError:  # POSIX fallback
        import sys, termios, tty  # noqa: E401

        def getch() -> str:
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                return sys.stdin.read(1).lower()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)

    state = load_case01()
    last = "loaded case_01 (s19 + mac + a2l)"
    actions = {
        "1": (load_case01, "loaded case_01 (s19 + mac + a2l)"),
        "2": (load_s19_only, "loaded s19 only"),
        "3": (load_mac_only, "loaded mac only"),
        "s": (unload_primary, "unloaded S19/HEX"),
        "m": (unload_mac, "unloaded MAC"),
        "a": (unload_a2l, "unloaded A2L"),
        "x": (unload_all, "unloaded ALL -> empty"),
    }
    while True:
        print("\x1b[2J\x1b[H", end="")
        print(render(state, last))
        key = getch()
        if key == "q":
            print("\x1b[2J\x1b[H", end="")
            return
        if key in actions:
            fn, msg = actions[key]
            # load_* take no state; unload_* take state.
            state = fn() if key in {"1", "2", "3"} else fn(state)
            last = msg


if __name__ == "__main__":
    main()
