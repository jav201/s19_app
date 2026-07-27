"""Regenerate every image in ``docs/images/`` from the real running application.

Nothing in this directory is hand-drawn or mocked up. Each PNG is a raster of a
native Textual SVG export (``App.export_screenshot()``) taken from a real
``S19TuiApp`` driven headlessly over ``examples/case_07_stress_smoke/`` — the
public, in-repo synthetic fixture triple. The animated GIF is the same frames
in sequence.

Run it::

    python docs/images/capture_readme_media.py

Requirements beyond the package itself (all dev-only, none are runtime
dependencies of ``s19tool``):

* ``playwright`` + a Chromium build — rasterises the Textual SVG to PNG.
* ``ffmpeg`` on ``PATH`` — assembles the PNG sequence into the GIF.

Both are optional: the script always writes the SVG sources, then skips the
raster/GIF stages with a message if the tool is missing.

Fixture policy: this script may only ever read from ``examples/``. Those
fixtures are synthetic and committed to the repository; no client artefact is
opened, matching the snapshot-baseline rule in
``tests/test_tui_snapshot.py`` (LLR-007.2).
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
SVG_DIR = OUT_DIR / "svg"
CASE_DIR = REPO_ROOT / "examples" / "case_07_stress_smoke"

# Terminal geometry. 160x46 sits in the "fixed" layout regime (the >= 120
# column breakpoint), which is the layout the README screenshots should show,
# and is tall enough that the content panes are not clipped to two rows.
TERM_SIZE = (160, 46)

# (rail key, output stem, caption used as the SVG export title)
FRAMES = [
    ("1", "workspace", "Workspace"),
    ("2", "a2l-explorer", "A2L Explorer"),
    ("3", "mac-view", "MAC View"),
    ("4", "memory-map", "Memory Map"),
    ("5", "issues-report", "Issues Report"),
]


def _install_triple(app) -> None:
    """Parse the S19 + A2L + MAC triple and install it through the real load path.

    The triple is built with the same load/parse services the interactive ``L``
    (load) action uses, then handed to ``_apply_prepared_load`` — the single
    install code path every real load funnels through. That is what runs the
    ``update_*`` renderers, so the captured screens show genuine rendered
    output rather than a hand-populated widget.
    """
    import time

    from s19_app.core import S19File
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.tui.mac import parse_mac_file
    from s19_app.tui.app import PreparedLoad
    from s19_app.tui.services.load_service import build_loaded_s19

    s19_path = CASE_DIR / "firmware.s19"
    a2l_path = CASE_DIR / "firmware.a2l"
    mac_path = CASE_DIR / "firmware.mac"

    a2l_data = parse_a2l_file(a2l_path)
    s19 = S19File(str(s19_path))
    loaded = build_loaded_s19(s19_path, s19, a2l_path=a2l_path, a2l_data=a2l_data)
    mac = parse_mac_file(mac_path)
    loaded.mac_path = mac_path
    loaded.mac_records = mac.get("records", [])
    loaded.mac_diagnostics = mac.get("diagnostics", [])

    app.current_a2l_path = a2l_path
    app.current_a2l_data = a2l_data
    app._apply_prepared_load(
        PreparedLoad(loaded=loaded), s19_path, time.perf_counter()
    )
    app.validation_issue_filter_mode = "all"


async def _capture(tmp_workspace: Path) -> list[Path]:
    from s19_app.tui.app import S19TuiApp

    SVG_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    app = S19TuiApp(base_dir=tmp_workspace)
    async with app.run_test(size=TERM_SIZE) as pilot:
        await pilot.pause()
        _install_triple(app)
        for _ in range(12):
            await pilot.pause()

        for key, stem, caption in FRAMES:
            await pilot.press(key)
            for _ in range(6):
                await pilot.pause()
            svg_path = SVG_DIR / f"{stem}.svg"
            svg_path.write_text(
                app.export_screenshot(title=f"s19tui - {caption}"), encoding="utf-8"
            )
            written.append(svg_path)
            print(f"  captured {svg_path.relative_to(REPO_ROOT)}")

    return written


def _rasterise(svg_paths: list[Path]) -> list[Path]:
    """Render each SVG to PNG with headless Chromium."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("! playwright not installed - skipping PNG raster stage")
        return []

    pngs: list[Path] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(device_scale_factor=2)
        for svg_path in svg_paths:
            png_path = OUT_DIR / f"{svg_path.stem}.png"
            page.goto(svg_path.resolve().as_uri())
            page.wait_for_timeout(250)
            element = page.query_selector("svg")
            element.screenshot(path=str(png_path))
            pngs.append(png_path)
            print(f"  rendered {png_path.relative_to(REPO_ROOT)}")
        browser.close()
    return pngs


def _build_gif(pngs: list[Path], out_gif: Path, seconds_per_frame: float = 1.6) -> None:
    """Assemble the PNG frames into a looping GIF with ffmpeg."""
    if not pngs:
        return
    if shutil.which("ffmpeg") is None:
        print("! ffmpeg not on PATH - skipping GIF stage")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        # ffmpeg's image2 demuxer needs a contiguous numbered sequence.
        for idx, png in enumerate(pngs):
            shutil.copyfile(png, tmp_dir / f"frame_{idx:03d}.png")
        palette = tmp_dir / "palette.png"
        pattern = str(tmp_dir / "frame_%03d.png")
        rate = f"{1 / seconds_per_frame:.4f}"
        common = ["-framerate", rate, "-i", pattern]
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", *common,
             "-vf", "scale=1000:-1:flags=lanczos,palettegen=stats_mode=full",
             str(palette)],
            check=True,
        )
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", *common, "-i", str(palette),
             "-lavfi", "scale=1000:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer",
             "-loop", "0", str(out_gif)],
            check=True,
        )
    print(f"  wrote {out_gif.relative_to(REPO_ROOT)}")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # The two stages may need different interpreters: stage "capture" needs the
    # environment s19tool is installed into, stage "render" needs one with
    # playwright. "all" (the default) runs both in-process.
    stage = "all"
    for arg in argv:
        if arg.startswith("--stage="):
            stage = arg.split("=", 1)[1]
    if stage not in {"all", "capture", "render"}:
        print(f"unknown stage: {stage} (use capture, render or all)", file=sys.stderr)
        return 2

    if stage in {"all", "capture"}:
        if not CASE_DIR.is_dir():
            print(f"fixture directory missing: {CASE_DIR}", file=sys.stderr)
            return 1
        print(f"capturing {len(FRAMES)} frames from "
              f"{CASE_DIR.relative_to(REPO_ROOT)} "
              f"at {TERM_SIZE[0]}x{TERM_SIZE[1]}")
        # ignore_cleanup_errors: on Windows the rotating file handler keeps
        # .s19tool/logs/s19tui.log open past app shutdown, which would
        # otherwise raise PermissionError on temp-dir teardown.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            asyncio.run(_capture(Path(tmp) / "workarea"))

    if stage in {"all", "render"}:
        svgs = [SVG_DIR / f"{stem}.svg" for _key, stem, _cap in FRAMES]
        missing = [p for p in svgs if not p.is_file()]
        if missing:
            print(f"missing SVG sources: {missing} - run --stage=capture first",
                  file=sys.stderr)
            return 1
        pngs = _rasterise(svgs)
        _build_gif(pngs, OUT_DIR / "s19tui-rail-tour.gif")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
