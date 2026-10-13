"""Throwaway probe (inc-003): hash the other views' legend content on the
pre-change tree, for the byte-identical control's pinned oracle.

Runs the real `action_show_legend` path per view and sha256s the SORTED
`#legend_body Static` plain texts — the same extraction the pinned test uses
(sorted: pane DOCUMENT ORDER flips at the narrow regime, which is layout, not
content). Deleted after the pins are taken.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from s19_app.tui.app import S19TuiApp

VIEWS = ("workspace", "a2l", "mac", "issues", "flow")


async def _hash_view(view: str, base: Path) -> str:
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        app.action_show_screen(view)
        await pilot.pause()
        app.action_show_legend()
        await pilot.pause()
        parts = sorted(
            getattr(w.render(), "plain", str(w.render()))
            for w in app.screen.query("#legend_body Static")
        )
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def main() -> None:
    base = Path(".dev-flow/2026-10-11-batch-93/evidence/inc003_probe_base")
    base.mkdir(parents=True, exist_ok=True)
    for view in VIEWS:
        digest = asyncio.run(_hash_view(view, base))
        print(f"{view}: {digest}")


if __name__ == "__main__":
    main()
