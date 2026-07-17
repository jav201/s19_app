"""In-place JSON syntax-ish colouring for the Patch Editor's paste buffer.

Summary:
    Colours the pasted change-set JSON *inside* the existing
    ``CappedTextArea#patch_paste_text`` (LLR-079.1, operator-decided
    2026-07-16) — no second/preview buffer. A pure tokenizer emits
    ``(start_byte, end_byte, token_name)`` triples into the widget's own
    ``TextArea._highlights`` map, and a registered ``TextAreaTheme`` supplies
    the styles.

    **Why not ``TextArea(language="json")``**: tree-sitter is NOT installed
    (probe A8) — ``TextArea.available_languages`` lists ``'json'`` but the
    grammar is absent, so ``language="json"`` constructs without raising and
    silently applies no highlighting. ``textual[syntax]`` was struck at draft
    (a runtime dependency + CI-pin change for a render-only batch).

    **C-17 (LLR-079.3): the pasted buffer is untrusted, and this module never
    markup-parses it.** Verified at the ``textual==8.2.8`` pin:

    * ``TextArea.get_line`` (``_text_area.py:1440`` → ``:1328``) builds each
      line with the **literal** ``Text(line_string, ...)`` constructor — never
      ``Text.from_markup``. Pasted brackets are data, not tags.
    * Styles resolve through ``theme.syntax_styles.get(name)``
      (``_text_area.py:1501-1503``) and an **unknown name is skipped**
      (``if node_style is not None``), so pasted text can never *name* a style.
    * This module emits token names from a **closed author-fixed vocabulary**
      (:data:`_TOKEN_KEY` / ``_TOKEN_STRING`` / ``_TOKEN_NUMBER`` /
      ``_TOKEN_KEYWORD``) and offsets computed from the text. **No pasted
      character ever reaches a style name, a markup string, or an f-string.**

    So the colouring is a *preservation* obligation, not a repair: the render
    path is safe by construction and this module must not introduce a markup
    path where none exists.

    **Byte offsets, not codepoints (m-2).** ``_highlights`` follows the
    tree-sitter convention: ``_render_line`` encodes the line with
    ``_utf8_encode`` and maps offsets via ``byte_to_codepoint.get(start, 0)``
    (``_text_area.py:1496-1506``). A missed lookup **silently defaults to 0**
    and styles from the line's start with no error, so a codepoint-offset
    tokenizer misstyles non-ASCII pastes *quietly*. :func:`tokenize_json_line`
    therefore emits UTF-8 byte offsets.

    **Spans are rebuilt on every edit (m-3).** ``TextArea._build_highlight_map``
    **clears** ``_highlights`` and returns early when no tree-sitter query is
    set (``_text_area.py:824-830``), and it runs after *every* edit
    (``:1700`` / ``:1765`` / ``:1814``) and on document load (``:1184``).
    :class:`JsonHighlightTextArea` overrides that hook to re-populate after the
    base clears, so the spans survive edits by construction rather than by a
    ``Changed`` handler racing the rebuild.

Data Flow:
    paste / edit → ``TextArea._build_highlight_map`` (base: clears) →
    :meth:`JsonHighlightTextArea._build_highlight_map` (re-populate) →
    :func:`tokenize_json_line` per line → ``self._highlights[i]`` →
    ``TextArea._render_line`` styles a *local* ``Text`` via
    ``theme.syntax_styles``.

Dependencies:
    Uses: ``textual.widgets.TextArea`` internals (``_highlights``,
    ``_build_highlight_map`` — private, guarded by :func:`highlights_supported`
    and pinned at ``textual==8.2.8``), ``TextAreaTheme``,
    ``s19_app.tui.capped_text_area.CappedTextArea`` (the 64 KiB paste cap),
    ``s19_app.tui.insight_style`` (the palette — no new hue).
    Used by: ``s19_app.tui.screens_directionb`` (``#patch_paste_text``),
    ``tests/test_tui_patch_json.py``.

Example:
    >>> from s19_app.tui.json_highlight import tokenize_json_line
    >>> tokenize_json_line('{"a": 1}')
    [(1, 4, 'json.key'), (6, 7, 'json.number')]
"""

from __future__ import annotations

import re
from typing import List, Tuple

from rich.style import Style
from textual.widgets.text_area import TextAreaTheme

from .capped_text_area import CappedTextArea
from .insight_style import CYAN, HILITE, LBLUE, PURPLE

#: The registered theme's name, set on the widget via ``TextArea.theme``.
JSON_THEME_NAME = "s19-json"

#: Closed, author-fixed token vocabulary. These are the ONLY strings that ever
#: reach ``theme.syntax_styles`` — never pasted text (C-17 / LLR-079.3).
_TOKEN_KEY = "json.key"
_TOKEN_STRING = "json.string"
_TOKEN_NUMBER = "json.number"
_TOKEN_KEYWORD = "json.keyword"

#: Token → palette hue. Four distinct styles (AT-079b needs >= 3). Reuses
#: `insight_style` hues only — NO new colour.
#:
#: ⚠ **GREEN / YELLOW / RED are deliberately ABSENT.** The Inc-2b operator
#: decision RESERVES those three hues for **verdicts** inside
#: `#patch_editor_panel` (`_GLYPH_STYLE` = check pass/partial/fail, and the
#: Inc-4 pass/fail strip). A `json.keyword` painted YELLOW would be the exact
#: shared-namespace collision that decision exists to prevent: same container,
#: same finite hue vocabulary, two independent claimants (a JSON literal is
#: NOT a warning). The four hues below are all non-verdict.
_JSON_SYNTAX_STYLES = {
    _TOKEN_KEY: Style(color=CYAN),
    _TOKEN_STRING: Style(color=LBLUE),
    _TOKEN_NUMBER: Style(color=PURPLE),
    _TOKEN_KEYWORD: Style(color=HILITE),
}

#: One regex, one pass, per line. A JSON string (with escapes), a number, or a
#: literal keyword. Cannot raise on any input: no group is optional-backref'd
#: and `finditer` over arbitrary text simply yields no match (LLR-079.2).
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'  # a string (possibly a key — decided by lookahead)
    r"|-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?"  # a number
    r"|\b(?:true|false|null)\b"  # a literal keyword
)


def tokenize_json_line(line: str) -> List[Tuple[int, int, str]]:
    """Emit UTF-8 byte-offset highlight spans for one line of JSON-ish text.

    Summary:
        Scan ``line`` once for JSON strings, numbers and literal keywords, and
        return ``(start_byte, end_byte, token_name)`` triples in the shape
        ``TextArea._highlights`` expects. A string token followed (after
        optional whitespace) by ``:`` is classified as a **key**, otherwise as
        a **string** — the only structural distinction the change-set schema
        needs, and the one that makes a pasted document readable.

        This is a *tokenizer*, not a parser: it never validates the document,
        so malformed / truncated / non-JSON input degrades to whatever tokens
        it can see and raises nothing (LLR-079.2).

    Args:
        line (str): A single line of the pasted buffer. Arbitrary, untrusted
            text — including markup-looking brackets, ANSI escapes, and
            multi-byte characters.

    Returns:
        List[Tuple[int, int, str]]: Zero or more spans, each
        ``(start_byte, end_byte, token_name)``. Offsets are **UTF-8 byte**
        offsets into ``line``, matching ``_render_line``'s
        ``_utf8_encode``/``byte_to_codepoint`` convention — NOT codepoint
        offsets. ``token_name`` is always one of the four closed constants;
        a value derived from ``line`` is never returned.

    Raises:
        None. Every branch is a regex scan or an arithmetic offset conversion.

    Data Flow:
        - ``_TOKEN_RE.finditer(line)`` → per match, classify → convert the
          codepoint span to a byte span via ``len(line[:i].encode("utf-8"))``.
        - Called per line by
          :meth:`JsonHighlightTextArea._build_highlight_map`.

    Dependencies:
        Uses: :data:`_TOKEN_RE` and the four token-name constants.
        Used by: :class:`JsonHighlightTextArea`, ``tests/test_tui_patch_json.py``.

    Example:
        >>> tokenize_json_line('{"a": 1}')
        [(1, 4, 'json.key'), (6, 7, 'json.number')]
        >>> tokenize_json_line('[red]PWNED[/red]')
        []
    """
    spans: List[Tuple[int, int, str]] = []
    # Codepoint index -> byte offset. Built once per line so a multi-byte
    # character before a token cannot shift that token's span (m-2).
    prefix_bytes = [0] * (len(line) + 1)
    total = 0
    for index, char in enumerate(line):
        total += len(char.encode("utf-8"))
        prefix_bytes[index + 1] = total

    for match in _TOKEN_RE.finditer(line):
        token = match.group()
        if token.startswith('"'):
            rest = line[match.end():]
            name = _TOKEN_KEY if rest.lstrip().startswith(":") else _TOKEN_STRING
        elif token in ("true", "false", "null"):
            name = _TOKEN_KEYWORD
        else:
            name = _TOKEN_NUMBER
        spans.append((prefix_bytes[match.start()], prefix_bytes[match.end()], name))
    return spans


def build_json_theme() -> TextAreaTheme:
    """Build the registered ``TextAreaTheme`` carrying the four token styles.

    Summary:
        Supplies ``syntax_styles`` for the closed token vocabulary. Only names
        present here resolve; ``_render_line`` skips any other name
        (``_text_area.py:1502``), which is the mechanical reason pasted text
        cannot name a style (C-17).

    Args:
        None.

    Returns:
        TextAreaTheme: A theme named :data:`JSON_THEME_NAME` whose
        ``syntax_styles`` maps the four token constants to `insight_style`
        hues. No base/cursor styling is set, so the widget keeps the app theme.

    Raises:
        None.

    Data Flow:
        - Called once per :class:`JsonHighlightTextArea` construction and
          registered on that widget instance.

    Dependencies:
        Uses: ``TextAreaTheme``, :data:`_JSON_SYNTAX_STYLES`.
        Used by: :class:`JsonHighlightTextArea`, ``tests/test_tui_patch_json.py``.

    Example:
        >>> sorted(build_json_theme().syntax_styles)
        ['json.key', 'json.keyword', 'json.number', 'json.string']
    """
    return TextAreaTheme(name=JSON_THEME_NAME, syntax_styles=dict(_JSON_SYNTAX_STYLES))


def highlights_supported(widget: object) -> bool:
    """Feature-detect the private ``TextArea`` internals this module drives.

    Summary:
        ``_highlights`` and ``_build_highlight_map`` are **private Textual
        internals** (A9 / R8): present at the pinned ``textual==8.2.8`` but not
        guaranteed across the ``textual>=8.0.2`` runtime floor. This gate keeps
        the failure mode **cosmetic**: when the internals are missing the
        buffer renders unstyled and nothing raises (AT-079d / TC-079.1a).

    Args:
        widget (object): The candidate ``TextArea``-alike.

    Returns:
        bool: ``True`` when a mutable ``_highlights`` mapping is present, else
        ``False``.

    Raises:
        None.

    Data Flow:
        - Read by :meth:`JsonHighlightTextArea._build_highlight_map` on every
          rebuild, so a monkeypatched ``False`` degrades the live widget
          (which is how AT-079d forces the branch CI cannot reach naturally).

    Dependencies:
        Uses: ``builtins.hasattr`` / ``isinstance`` only.
        Used by: :class:`JsonHighlightTextArea`, ``tests/test_tui_patch_json.py``.

    Example:
        >>> highlights_supported(object())
        False
    """
    return isinstance(getattr(widget, "_highlights", None), dict)


class JsonHighlightTextArea(CappedTextArea):
    """A capped paste buffer that colours its own JSON in place (LLR-079.1).

    Summary:
        Keeps every ``CappedTextArea`` behaviour (both paste ingresses stay
        capped at 64 KiB) and adds token colouring by re-populating
        ``_highlights`` after the base clears it.

    Data Flow:
        See the module docstring — the override rides the base's own rebuild
        hook, so load, paste, and every keystroke re-tokenize.

    Dependencies:
        Uses: :func:`tokenize_json_line`, :func:`build_json_theme`,
        :func:`highlights_supported`.
        Used by: ``screens_directionb.PatchEditorPanel.compose``
        (``#patch_paste_text``).
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Construct the buffer and register + select the JSON theme.

        Summary:
            Registers :func:`build_json_theme` on this instance and selects it,
            so ``_render_line``'s ``theme.syntax_styles`` lookup can resolve
            the token names. Registration is unconditional (it is plain public
            API); only the ``_highlights`` *write* is feature-gated.

        Args:
            *args (object): Forwarded to ``CappedTextArea``/``TextArea``.
            **kwargs (object): Forwarded to ``CappedTextArea``/``TextArea``.

        Returns:
            None.

        Raises:
            Propagates whatever the base constructor raises; adds none.

        Data Flow:
            - ``super().__init__`` (which calls ``_build_highlight_map`` via
              the document setter) → ``register_theme`` → ``self.theme``.

        Dependencies:
            Uses: :func:`build_json_theme`, ``TextArea.register_theme``.
            Used by: ``PatchEditorPanel.compose``.

        Example:
            >>> JsonHighlightTextArea('{"a": 1}', id="patch_paste_text")  # doctest: +SKIP
        """
        super().__init__(*args, **kwargs)
        self.register_theme(build_json_theme())
        self.theme = JSON_THEME_NAME
        # `super().__init__` already ran the base rebuild (which cleared the
        # map) BEFORE the theme existed, so populate once now.
        self._build_highlight_map()

    def _build_highlight_map(self) -> None:
        """Re-populate ``_highlights`` after the base clears it.

        Summary:
            The base implementation clears ``_highlights`` and returns early
            with no tree-sitter query set (``_text_area.py:824-830``), and
            Textual calls it after **every** edit and on document load. Riding
            that hook is what makes the spans survive an edit (m-3 / TC-079.1c)
            without a ``Changed`` handler racing the rebuild.

        Args:
            None.

        Returns:
            None.

        Raises:
            None — the feature gate short-circuits before any internal is
            touched, and :func:`tokenize_json_line` cannot raise (LLR-079.2).

        Data Flow:
            - base clear → :func:`highlights_supported` gate → per-line
              :func:`tokenize_json_line` → ``self._highlights[i]``.
            - `_line_cache` is cleared by the base call, so no stale styled
              line survives this rebuild.

        Dependencies:
            Uses: :func:`highlights_supported`, :func:`tokenize_json_line`,
            ``TextArea.document``.
            Used by: Textual's edit/load paths; :meth:`__init__`.

        Example:
            Invoked by the runtime; not called directly.
        """
        super()._build_highlight_map()
        if not highlights_supported(self):
            return
        for index, line in enumerate(self.document.lines):
            spans = tokenize_json_line(line)
            if spans:
                self._highlights[index] = spans
