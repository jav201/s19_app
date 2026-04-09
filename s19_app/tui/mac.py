from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional


class MacFileParser:
    """
    Summary:
        Parser for ``.mac`` address-map text files (one ``TAG=hexaddr`` data line per record).

    Data Flow:
        - ``parse`` reads file text as UTF-8 lines.
        - Non-data lines are skipped via ``_should_skip_line``.
        - Each data line becomes one record via ``_parse_data_line`` with optional diagnostic.

    Dependencies:
        Uses:
            - ``pathlib.Path`` for file I/O
            - compiled regex patterns for tag name and hex validation
        Used by:
            - ``parse_mac_file`` module facade
            - ``S19TuiApp._load_mac_file`` / MAC load path
    """

    _NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
    _HEX_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f]+$")

    @staticmethod
    def _should_skip_line(stripped: str) -> bool:
        """Return True if the line is blank or a comment (``#``)."""
        return not stripped or stripped.startswith("#")

    def _parse_data_line(
        self, line_number: int, raw_line: str, stripped: str
    ) -> tuple[dict[str, Any], Optional[str]]:
        """
        Summary:
            Parse a single non-empty, non-comment line into a MAC record and optional diagnostic.

        Args:
            line_number (int): 1-based source line index for error reporting.
            raw_line (str): Original line text (preserves trailing content intent for ``raw``).
            stripped (str): Same line after ``strip()`` for parsing.

        Returns:
            tuple[dict[str, Any], Optional[str]]: ``record`` with keys ``line_number``, ``raw``,
            ``name``, ``address``, ``parse_ok``, ``parse_error``; and ``diagnostic`` message
            (``Line N: ...``) when the line is invalid, else None.

        Data Flow:
            - Require exactly one ``=``; split into tag name and hex token.
            - Validate name against alphanumeric plus ``_`` and ``-``.
            - Validate hex (optional ``0x`` prefix) and convert to int on success.
            - Emit partial fields on failure so the UI can still show context.

        Dependencies:
            Uses:
                - ``_NAME_RE``, ``_HEX_RE``
            Used by:
                - ``MacFileParser.parse``
        """
        record: dict[str, Any] = {
            "line_number": line_number,
            "raw": raw_line.rstrip("\n"),
            "name": None,
            "address": None,
            "parse_ok": False,
            "parse_error": "",
        }
        if stripped.count("=") != 1:
            record["parse_error"] = "expected one '=' separator"
            return record, f"Line {line_number}: {record['parse_error']}"

        name_text, addr_text = [part.strip() for part in stripped.split("=", maxsplit=1)]
        if not self._NAME_RE.match(name_text):
            record["parse_error"] = "invalid tag name"
            record["name"] = name_text or None
            return record, f"Line {line_number}: {record['parse_error']}"
        if not self._HEX_RE.match(addr_text):
            record["parse_error"] = "invalid hex address"
            record["name"] = name_text
            return record, f"Line {line_number}: {record['parse_error']}"

        address = int(addr_text, 16)
        record["name"] = name_text
        record["address"] = address
        record["parse_ok"] = True
        return record, None

    def parse(self, path: Path) -> dict[str, Any]:
        """
        Summary:
            Read a ``.mac`` file and produce structured records plus line-level diagnostics.

        Args:
            path (Path): Path to the UTF-8 text file.

        Returns:
            dict[str, Any]: Keys ``path`` (str), ``records`` (list of per-line dicts), and
            ``diagnostics`` (list of human-readable strings). On read failure, ``records`` is
            empty and ``diagnostics`` contains a single error message.

        Data Flow:
            - Read entire file as UTF-8 text; on failure return empty records and one diagnostic.
            - Iterate lines; skip blanks and ``#`` comments.
            - For each data line, append record and optional diagnostic from ``_parse_data_line``.

        Dependencies:
            Uses:
                - ``_should_skip_line``
                - ``_parse_data_line``
            Used by:
                - ``parse_mac_file``

        Example:
            >>> from pathlib import Path
            >>> from tempfile import NamedTemporaryFile
            >>> tmp = NamedTemporaryFile("w+", suffix=".mac", delete=False, encoding="utf-8")
            >>> _ = tmp.write("A=10\\n#c\\nB=0x20\\n")
            >>> tmp.close()
            >>> out = MacFileParser().parse(Path(tmp.name))
            >>> len(out["records"])
            2
            >>> out["records"][0]["name"]
            'A'
        """
        records: list[dict[str, Any]] = []
        diagnostics: list[str] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            return {
                "path": str(path),
                "records": [],
                "diagnostics": [f"Failed to read file: {exc}"],
            }

        for index, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if self._should_skip_line(stripped):
                continue
            record, diag = self._parse_data_line(index, raw_line, stripped)
            records.append(record)
            if diag:
                diagnostics.append(diag)

        return {"path": str(path), "records": records, "diagnostics": diagnostics}


def parse_mac_file(path: Path) -> dict[str, Any]:
    """
    Summary:
        Parse a ``.mac`` file into records and diagnostics using ``MacFileParser``.

    Args:
        path (Path): Path to the MAC address map file.

    Returns:
        dict[str, Any]: Same structure as ``MacFileParser.parse`` (``path``, ``records``,
        ``diagnostics``). Each record may include ``line_number``, ``raw``, ``name``, ``address``,
        ``parse_ok``, ``parse_error``.

    Data Flow:
        - Delegate to ``MacFileParser().parse(path)`` without additional transformation.

    Dependencies:
        Uses:
            - ``MacFileParser``
        Used by:
            - ``S19TuiApp._load_mac_file``

    Example:
        >>> from pathlib import Path
        >>> parse_mac_file(Path("nonexistent.mac"))["records"]
        []
    """
    return MacFileParser().parse(path)
