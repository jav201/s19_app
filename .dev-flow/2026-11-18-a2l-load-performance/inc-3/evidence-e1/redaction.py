from __future__ import annotations

from pathlib import Path
import re


def redact(text: str, root: Path) -> str:
    resolved = root.resolve()
    replacements = (
        (str(resolved), "<repo>"),
        (resolved.as_posix(), "<repo>"),
        (str(Path.home()), "<home>"),
        (Path.home().as_posix(), "<home>"),
    )
    for value, replacement in replacements:
        if value:
            text = text.replace(value, replacement)
    text = re.sub(
        r"(?i)\b[A-Z]:[\\/]+Users[\\/]+[^\\/\s\"']+",
        "<home>",
        text,
    )
    text = re.sub(r"(?i)/(?:home|Users)/[^/\s\"']+", "<home>", text)
    return text
