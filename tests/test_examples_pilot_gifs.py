"""Pilot-driven TUI smoke + GIF evidence per example case.

For every ``examples/case_*`` (and ``professional_validation/case_*``) this
module launches ``S19TuiApp`` headlessly under ``App.run_test()``, steps it
through a deterministic key sequence that exercises the three primary views
(Main / Alt / MAC) plus a hex paginate, and emits two artefacts per case:

    1. A native Textual SVG snapshot per frame in
       ``tests/_artifacts/svgs/<case>/frame_<n>_<label>.svg``.
    2. A PIL-rendered animated GIF in
       ``tests/_artifacts/gifs/<case>.gif`` whose frames narrate the state
       observed at each step (case id, step label, ranges, errors, A2L tag
       count, MAC record count, issue count, coverage line).

The GIF is intentionally a *narrative* render — not a raster of the SVG —
because converting Textual SVG → PNG would require ``cairosvg`` (declined by
the user). The narrative frames travel well in chat and are sufficient to
prove the pipeline ran end-to-end against each case.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import pytest

# These imports are kept at module scope because they are cheap and let pytest
# parametrize ids correctly even when the test happens to skip.
from s19_app.tui.app import S19TuiApp

EXAMPLES_ROOT = Path(__file__).resolve().parent.parent / "examples"
ARTIFACTS_ROOT = Path(__file__).resolve().parent / "_artifacts"
SVG_ROOT = ARTIFACTS_ROOT / "svgs"
GIF_ROOT = ARTIFACTS_ROOT / "gifs"

# Step plan: (action, label). ``action`` is either a key (press) or a Pilot
# verb. Frame 0 is captured immediately after load to anchor the GIF.
STEP_PLAN = [
    ("loaded", "Loaded"),
    ("1", "View: Main"),
    ("2", "View: Alt"),
    ("3", "View: MAC"),
    ("period", "Hex page+"),
]


def _discover_cases() -> list[tuple[str, Path]]:
    cases: list[tuple[str, Path]] = []
    if not EXAMPLES_ROOT.is_dir():
        return cases
    for entry in sorted(EXAMPLES_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name == "professional_validation":
            for sub in sorted(entry.iterdir()):
                if sub.is_dir():
                    cases.append((f"pv__{sub.name}", sub))
            continue
        cases.append((entry.name, entry))
    return cases


def _pick_primary(case_dir: Path) -> Optional[Path]:
    for candidate in ("firmware.s19", "firmware.hex", "prg.s19", "prg.hex"):
        path = case_dir / candidate
        if path.is_file():
            return path
    for ext in (".s19", ".hex"):
        hits = sorted(p for p in case_dir.glob(f"*{ext}") if p.is_file())
        if hits:
            return hits[0]
    return None


def _summarize_state(app: S19TuiApp) -> dict[str, str]:
    """Pull a compact, narrative summary off a running ``S19TuiApp``."""
    loaded = app.current_file
    lines: dict[str, str] = {}
    if loaded is None:
        lines["status"] = "no LoadedFile yet"
        return lines
    lines["file"] = f"{loaded.path.name} ({loaded.file_type})"
    lines["mem_bytes"] = f"{len(loaded.mem_map):,} bytes mapped"
    lines["ranges"] = f"{len(loaded.ranges)} contiguous ranges"
    valid = sum(1 for v in loaded.range_validity if v)
    lines["valid"] = f"{valid}/{len(loaded.range_validity)} ranges valid"
    lines["errors"] = f"{len(loaded.errors)} loader errors"
    if loaded.a2l_data:
        tag_count = len((loaded.a2l_data or {}).get("tags", []))
        lines["a2l_tags"] = f"A2L: {tag_count} tags"
    if loaded.mac_records:
        lines["mac_records"] = f"MAC: {len(loaded.mac_records)} records"
    issues = getattr(app, "_validation_issues", None) or []
    if issues:
        lines["issues"] = f"Validation: {len(issues)} issues"
    return lines


def _render_frame_png(
    out_path: Path,
    case_id: str,
    step_label: str,
    summary: dict[str, str],
    *,
    width: int = 960,
    height: int = 540,
) -> None:
    """Render a single narrative PNG frame using PIL."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (width, height), color=(20, 22, 30))
    draw = ImageDraw.Draw(img)

    # Try to find a monospaced font; fall back to default if not available.
    font_title: ImageFont.ImageFont
    font_body: ImageFont.ImageFont
    try:
        font_title = ImageFont.truetype("consola.ttf", 28)
        font_body = ImageFont.truetype("consola.ttf", 20)
    except OSError:
        try:
            font_title = ImageFont.truetype("DejaVuSansMono.ttf", 28)
            font_body = ImageFont.truetype("DejaVuSansMono.ttf", 20)
        except OSError:
            font_title = ImageFont.load_default()
            font_body = ImageFont.load_default()

    # Header strip
    draw.rectangle((0, 0, width, 60), fill=(40, 44, 60))
    draw.text((20, 16), f"s19_app TUI — {case_id}", fill=(220, 220, 240), font=font_title)

    # Step label
    draw.text((20, 80), f"Step: {step_label}", fill=(140, 210, 255), font=font_body)

    # State summary
    y = 130
    if summary:
        for key, val in summary.items():
            line = f"{key:>14}  │  {val}"
            draw.text((20, y), line, fill=(220, 220, 220), font=font_body)
            y += 30
            if y > height - 60:
                break
    else:
        draw.text((20, y), "(no state captured)", fill=(180, 90, 90), font=font_body)

    # Footer
    draw.rectangle((0, height - 40, width, height), fill=(40, 44, 60))
    draw.text(
        (20, height - 32),
        "evidence frame · Pilot-driven · headless Textual",
        fill=(160, 160, 200),
        font=font_body,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, format="PNG")


def _assemble_gif(png_paths: list[Path], out_gif: Path, *, ms_per_frame: int = 900) -> None:
    """Combine PNG frames into an animated GIF."""
    from PIL import Image

    if not png_paths:
        return
    out_gif.parent.mkdir(parents=True, exist_ok=True)
    frames = [Image.open(p).convert("P", palette=Image.ADAPTIVE) for p in png_paths]
    frames[0].save(
        out_gif,
        save_all=True,
        append_images=frames[1:],
        loop=0,
        duration=ms_per_frame,
        disposal=2,
    )


_CASES = _discover_cases()


@pytest.mark.slow
@pytest.mark.parametrize(
    ("case_id", "case_dir"),
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_case_pilot_capture_and_gif(case_id: str, case_dir: Path, tmp_path: Path) -> None:
    """Drive the TUI headlessly for one case and emit SVG frames + a GIF."""
    primary = _pick_primary(case_dir)
    if primary is None:
        pytest.skip(f"{case_id}: no S19/HEX image present")

    svg_dir = SVG_ROOT / case_id
    svg_dir.mkdir(parents=True, exist_ok=True)
    png_dir = tmp_path / "frames"
    png_dir.mkdir(parents=True, exist_ok=True)

    png_paths: list[Path] = []
    summaries: list[dict[str, str]] = []

    async def _drive() -> None:
        app = S19TuiApp(load_path=primary, base_dir=tmp_path / "workspace")
        async with app.run_test(size=(160, 48)) as pilot:
            # Initial settle — let the worker finish the load.
            await pilot.pause()
            for _ in range(6):
                await pilot.pause()
            for idx, (action, label) in enumerate(STEP_PLAN):
                if action != "loaded":
                    await pilot.press(action)
                    # Let renderers re-run after the binding fires.
                    await pilot.pause()
                    await pilot.pause()
                summary = _summarize_state(app)
                summaries.append(summary)
                svg_path = svg_dir / f"frame_{idx:02d}_{label.replace(' ', '_').replace(':', '')}.svg"
                try:
                    svg_text = app.export_screenshot(title=f"{case_id} · {label}")
                    svg_path.write_text(svg_text, encoding="utf-8")
                except Exception as exc:  # pragma: no cover — keep test alive
                    svg_path.write_text(f"<!-- export_screenshot failed: {exc} -->", encoding="utf-8")
                png_path = png_dir / f"frame_{idx:02d}.png"
                _render_frame_png(png_path, case_id, label, summary)
                png_paths.append(png_path)
            # Clean shutdown
            await pilot.press("q")

    asyncio.run(_drive())

    # Assemble GIF (Pillow-only, already validated).
    gif_path = GIF_ROOT / f"{case_id}.gif"
    _assemble_gif(png_paths, gif_path)

    # Persistent evidence assertions.
    assert gif_path.is_file(), f"{case_id}: GIF was not written to {gif_path}"
    assert gif_path.stat().st_size > 0, f"{case_id}: GIF is empty"
    svg_count = sum(1 for p in svg_dir.glob("frame_*.svg") if p.is_file())
    assert svg_count == len(STEP_PLAN), (
        f"{case_id}: expected {len(STEP_PLAN)} SVG frames, got {svg_count}"
    )

    # Substantive state assertions — at least one frame should have seen a
    # loaded file with mapped memory; otherwise we proved nothing.
    assert any(
        "mem_bytes" in s and not s.get("mem_bytes", "").startswith("0") for s in summaries
    ), f"{case_id}: no Pilot frame observed mapped memory"
