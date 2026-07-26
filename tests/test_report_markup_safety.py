"""batch-62 Inc-1 — the `markdown_safety` leaf helper battery.

Scope: the ESCAPER only. No report is composed here; the composer sites land in
Inc-2/Inc-3 and carry the ATs. This file owns the helper's contract and the
payload set every later AT/TC draws from.

Two disciplines this file exists to enforce, both learned the hard way:

1. **The payload set is itself an oracle (C-31).** It is derived from the
   parser's own rule table (`G-1`), from linkify's live schema table (`G-2`),
   and every payload must be proven capable of firing *in its emission context*
   (`G-4`) — a set assembled by hand is a set that silently misses a class.
   batch-60's set had eleven payloads and zero fuzzy-linkify cases.

2. **Assert the emitted encoding, not the rendered form.** The acceptance
   predicate is a token stream from a real `markdown_it` parser plus a
   comparison against `expected_display`, which is re-implemented HERE from the
   specification rather than imported from the module under test. Importing it
   would make the oracle agree with the code by construction — the exact
   vacuity `AT-160`'s byte-identity clause was rejected for.
"""

from __future__ import annotations

import unicodedata

import pytest
from markdown_it import MarkdownIt

from s19_app.tui.services.markdown_safety import (
    EMPTY_MARKER,
    LOSS_MARKER,
    MD_ESCAPE,
    TRUNCATION_MARKER,
    md_code,
    md_safe,
)

# --------------------------------------------------------------------------- #
# Parsers — the two grammars the batch models
# --------------------------------------------------------------------------- #

#: What the app's own viewer uses (batch-60 hardened it).
VIEWER = MarkdownIt("gfm-like", {"linkify": False, "html": False})

#: A DEFAULT reader — the file once it leaves the app. NOT "any GFM reader":
#: reader extensions (`:emoji:`, `$…$`, `==mark==`) are declared out of model
#: (RR-1), because a claim the tests cannot support is worse than a narrow one.
DEFAULT = MarkdownIt("gfm-like", {"linkify": True, "html": True})

#: Tokens that carry no live construct. Everything else is a hazard.
_NEUTRAL = {"text", "paragraph_open", "paragraph_close", "inline", "softbreak"}

# --------------------------------------------------------------------------- #
# Rule coverage (G-1) — derived, never hand-listed
# --------------------------------------------------------------------------- #

#: Rules that cannot be a hazard, each justified — the discipline `MUTATING_RULES`
#: below mirrors. `text` IS the desired output; `paragraph` wraps every document.
INERT_RULES = {
    "text": "emits the plain text that is the desired outcome",
    "paragraph": "structural container present in every document",
}

#: Rules structurally incapable of emitting a non-`text` token — escaping and
#: entity decoding are TEXT TRANSFORMS. A live-token predicate is vacuous on
#: them, so they are held to a FIDELITY predicate instead: the cooked text must
#: differ from the input, which is precisely the deception they enable.
MUTATING_RULES = {
    "entity": "&vert; decodes to | — renders a character the file does not contain",
    "escape": r"\*not\* decodes to *not* — the reader sees different bytes",
}


def _active_rules(md: MarkdownIt) -> set:
    """Every enabled block+inline rule name, read from the live parser."""
    rules = set()
    for chain in ("block", "inline"):
        rules.update(md.get_active_rules()[chain])
    return rules


BLOCK_RULES = set(MarkdownIt("gfm-like").get_active_rules()["block"])

# --------------------------------------------------------------------------- #
# The payload set
# --------------------------------------------------------------------------- #


class P:
    """One derived payload: the value, the rule it exercises, its parser."""

    def __init__(self, key: str, rule: str, value: str, parser: str = "both",
                 companion: str = "") -> None:
        self.key = key
        self.rule = rule
        self.value = value
        self.parser = parser
        #: Text appended in the G-4 context only. A reference link is a PAIR —
        #: `[x][ref]` is dead without a `[ref]: url` definition and vice versa —
        #: so the payload needs its other half to be non-vacuous. Without this
        #: the guard would report the payload inert and invite deleting it.
        self.companion = companion

    def __repr__(self) -> str:  # pragma: no cover - pytest id only
        return self.key


ACTIVE_PAYLOADS = [
    # -- inline: emphasis / strikethrough -----------------------------------
    P("strong", "emphasis", "**fake**"),
    P("em", "emphasis", "_fake_"),
    P("strike", "strikethrough", "~~REVOKED~~"),
    # -- inline: links -------------------------------------------------------
    P("link-inline", "link", "[click](http://evil.com/x)"),
    P("link-ref", "link", "[click][ref]", companion="\n\n[ref]: http://evil.com/x"),
    P("autolink", "autolink", "<http://evil.com/x>"),
    P("image", "image", "![a](http://evil.com/x.png)"),
    P("image-ref", "image", "![a][ref]", companion="\n\n[ref]: http://evil.com/x.png"),
    # -- inline: linkify, the three families (G-2) ---------------------------
    P("linkify-scheme", "linkify", "http://evil.com/x", parser="default"),
    P("linkify-proto-rel", "linkify", "//evil.com/x", parser="default"),
    P("linkify-fuzzy-www", "linkify", "www.evil.com", parser="default"),
    P("linkify-fuzzy-bare", "linkify", "evil.com", parser="default"),
    P("linkify-fuzzy-mail", "linkify", "ops@evil.com", parser="default"),
    P("linkify-idn", "linkify", "банк.рф", parser="default"),
    P("linkify-mailto", "linkify", "mailto:ops@evil.com", parser="default"),
    P("linkify-ftp", "linkify", "ftp://evil.com/x", parser="default"),
    # -- inline: code spans --------------------------------------------------
    P("backticks", "backticks", "`code`"),
    P("code-span-breakout", "backticks", "a` **PWNED** `b"),
    # -- inline: HTML (B-3 — the two rows the derivation was short) ----------
    P("html-inline", "html_inline", "<img src=x onerror=alert(1)>", parser="default"),
    P("html-tag", "html_inline", "<b>x</b>", parser="default"),
    # -- inline: text transforms (MUTATING_RULES) ----------------------------
    P("entity-vert", "entity", "&vert;"),
    P("entity-amp", "entity", "&amp;"),
    P("entity-lt", "entity", "&lt;script&gt;"),
    P("escape-backslash", "escape", r"\*not\*"),
    # -- inline: newline -----------------------------------------------------
    P("newline-hard", "newline", "a  \nb"),
    # -- block ---------------------------------------------------------------
    P("heading", "heading", "# PWNED"),
    P("lheading", "lheading", "PWNED\n====="),
    P("hr", "hr", "---"),
    P("bullet", "list", "- item"),
    P("bullet-plus", "list", "+ item"),
    P("ordered-paren", "list", "1) item"),
    P("blockquote", "blockquote", "> quoted"),
    P("fence", "fence", "```\nx\n```"),
    P("indented-code", "code", "    indented"),
    P("html-block", "html_block", "<div>x</div>", parser="default"),
    P("reference", "reference", "[ref]: http://evil.com/x", companion="\n\n[click][ref]"),
    P("table-pipe", "table", "EVIL|INJECTED|COL"),
]

#: Values that must stay inert WITHOUT the escaper doing anything — they pin the
#: parser semantics the set relies on. `fuzzy_ip=False` and the 17-entry TLD
#: table are why these are dead; if either changes upstream, G-5 goes RED.
NEGATIVE_CONTROLS = [
    P("neg-fuzzy-ip", "linkify", "10.1.2.3"),
    P("neg-fake-tld", "linkify", "evil.tld"),
]


# --------------------------------------------------------------------------- #
# Oracle — re-implemented from the spec, NOT imported from the module
# --------------------------------------------------------------------------- #

_DROP = {"Cc", "Cf", "Zl", "Zp"}


def expected_display(value: object, mode: str, limit: int = 240) -> str:
    """What the reader must SEE, derived from `01-requirements.md` §6.

    Independent of the implementation on purpose: `md_safe` adds escape
    backslashes, and the whole claim is that those render INVISIBLY and delete
    nothing. Comparing the parsed text against this function is what proves it.
    """
    text = str(value)
    if mode == "A":
        text = text[: limit * 8]
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(
        LOSS_MARKER if unicodedata.category(c) in _DROP else c for c in text
    )
    if mode == "B":
        text = text.replace("`", LOSS_MARKER)
    text = text.strip()
    if mode == "A" and len(text) > limit:
        text = text[:limit].rstrip() + TRUNCATION_MARKER
    return text or EMPTY_MARKER


def _walk(tokens):
    for tok in tokens:
        yield tok
        if tok.children:
            yield from _walk(tok.children)


def live_tokens(md: MarkdownIt, document: str) -> set:
    """Every token type that is not plain text — the hazard set."""
    return {t.type for t in _walk(md.parse(document))} - _NEUTRAL


def rendered_text(md: MarkdownIt, document: str) -> str:
    """Join `text`-typed tokens only.

    `text` tokens carry the COOKED value; the enclosing `inline` token carries
    the RAW markdown source. Joining both was the defect that let a mutated
    value pass its own fidelity check — the raw source was admitted as evidence
    of the cooked result.
    """
    return "".join(t.content for t in _walk(md.parse(document)) if t.type == "text")


def body_cells(md: MarkdownIt, document: str) -> list:
    """Positional cell text of the first table body row.

    The observable a token-TYPE or cell-COUNT assertion cannot see: injecting
    pipes shifts values between columns while both stay identical. markdown-it
    caps a row at the header width, so nothing grows — data is silently dropped
    and `['BENIGN','a.s19','s19','yes']` becomes `['EVIL','INJECTED','COL','a.s19']`
    with the cell count unchanged.
    """
    tokens = list(md.parse(document))
    cells, inside_body, in_cell = [], False, False
    for tok in tokens:
        if tok.type == "tbody_open":
            inside_body = True
        elif tok.type == "tr_close" and inside_body:
            break
        elif tok.type == "td_open" and inside_body:
            in_cell = True
        elif tok.type == "inline" and in_cell:
            cells.append("".join(c.content for c in _walk([tok]) if c.type == "text"))
            in_cell = False
    return cells


def _parser(name: str) -> MarkdownIt:
    return DEFAULT if name == "default" else VIEWER


# --------------------------------------------------------------------------- #
# G-1 … G-5 — the guards that keep the payload set honest
# --------------------------------------------------------------------------- #


def test_g1_every_active_rule_has_a_payload() -> None:
    """G-1 — coverage is derived from the live parser, not from a hand list."""
    covered = {p.rule for p in ACTIVE_PAYLOADS}
    required = _active_rules(VIEWER) | _active_rules(DEFAULT)
    required -= set(INERT_RULES)
    missing = required - covered
    assert not missing, f"active parser rules with no payload: {sorted(missing)}"


def test_g2_linkify_schemas_are_all_represented() -> None:
    """G-2 — derived from linkify's own tables, so an upstream change is RED."""
    schemas = set(DEFAULT.linkify._schemas)
    opts = DEFAULT.linkify._opts
    assert opts["fuzzy_link"] is True and opts["fuzzy_email"] is True
    assert opts["fuzzy_ip"] is False, "neg-fuzzy-ip is only inert while this is False"
    values = " ".join(p.value for p in ACTIVE_PAYLOADS if p.rule == "linkify")
    for scheme in schemas:
        if scheme in ("//", "http:", "https:"):
            continue  # covered by linkify-proto-rel / linkify-scheme
        assert scheme.rstrip(":") in values, f"linkify scheme unrepresented: {scheme}"


def test_g3_payload_floor() -> None:
    """G-3 — a floor, so ADDING payloads never needs this test edited."""
    assert len(ACTIVE_PAYLOADS) >= 33
    assert len(NEGATIVE_CONTROLS) == 2


@pytest.mark.parametrize("payload", ACTIVE_PAYLOADS, ids=lambda p: p.key)
def test_g4_payload_is_non_vacuous_in_its_emission_context(payload: P) -> None:
    """G-4 — a payload that cannot fire proves nothing when it comes back inert.

    Parsed IN CONTEXT, not context-free: a bare `|` outside a table row is just
    text, so a context-free check scored `table-pipe` vacuous and would have
    deleted the one payload that catches silent cell-shifting. Asserting at the
    sink is the batch-60 lesson; this guard violated it until A-21.
    """
    md = _parser(payload.parser)
    if payload.rule == "table":
        document = f"| h1 | h2 |\n|---|---|\n| {payload.value} | b |"
        baseline = "| h1 | h2 |\n|---|---|\n| benign | b |"
    elif payload.rule in BLOCK_RULES:
        document = payload.value          # block constructs need column 0
        baseline = "benign"
    else:
        document = f"- {payload.value}"   # the realistic prefixed emission site
        baseline = "- benign"
    document += payload.companion
    baseline += payload.companion

    if payload.rule in MUTATING_RULES:
        assert rendered_text(md, document) != payload.value, (
            f"{payload.key}: a mutating rule that does not mutate is vacuous"
        )
    elif payload.rule == "table":
        # Non-vacuity here is POSITIONAL, not token-typed: a pipe injection
        # leaves every token type and the cell count untouched, so the guard
        # must observe the same thing AT-159 does or it scores the one payload
        # that catches silent column-shifting as inert.
        assert body_cells(md, document) != [payload.value, "b"], (
            f"{payload.key}: does not disturb positional cell content"
        )
    else:
        assert live_tokens(md, document) - live_tokens(md, baseline), (
            f"{payload.key}: fires no live token in its emission context"
        )


@pytest.mark.parametrize("payload", NEGATIVE_CONTROLS, ids=lambda p: p.key)
def test_g5_negative_controls_are_inert_before_escaping(payload: P) -> None:
    """G-5 — pins WHY they are dead, so an upstream change cannot pass silently."""
    for md in (VIEWER, DEFAULT):
        assert live_tokens(md, f"- {payload.value}") == {
            "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
        }


# --------------------------------------------------------------------------- #
# The contract — every payload, both clauses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("payload", ACTIVE_PAYLOADS + NEGATIVE_CONTROLS,
                         ids=lambda p: p.key)
def test_mode_a_neutralises_and_preserves(payload: P) -> None:
    """Clause 1 (grammar) AND clause 2 (fidelity), for Mode A.

    Clause 2 is the one that can fail on entity spoofing: `&vert;` unescaped
    keeps every token `text` while rendering as `|`, so a token-type-only
    assertion scores the attack GREEN.
    """
    escaped = md_safe(payload.value, limit=240)
    document = f"- {escaped}"
    for md in (VIEWER, DEFAULT):
        assert live_tokens(md, document) == {
            "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
        }, f"{payload.key}: live construct survived Mode A"
        assert rendered_text(md, document) == expected_display(payload.value, "A"), (
            f"{payload.key}: rendered text differs from the specified survivor set"
        )


@pytest.mark.parametrize("payload", ACTIVE_PAYLOADS + NEGATIVE_CONTROLS,
                         ids=lambda p: p.key)
def test_mode_b_neutralises_and_preserves(payload: P) -> None:
    """Same two clauses for Mode B, in the code span its caller emits."""
    document = f"- `{md_code(payload.value)}`"
    for md in (VIEWER, DEFAULT):
        assert live_tokens(md, document) == {
            "bullet_list_open", "bullet_list_close", "list_item_open",
            "list_item_close", "code_inline",
        }, f"{payload.key}: Mode B lost its span or opened a construct"
        cooked = "".join(
            t.content for t in _walk(md.parse(document)) if t.type == "code_inline"
        )
        assert cooked == expected_display(payload.value, "B")


# --------------------------------------------------------------------------- #
# Escape-set properties
# --------------------------------------------------------------------------- #


def test_backslash_is_escaped_first_and_ampersand_second() -> None:
    """Ordering is the property `_md_table_cell` existed to provide (D-5).

    `&` sits at index 1 so an entity is escaped exactly once: any later position
    would let an inserted `\\` be re-escaped by the `&` pass.
    """
    assert MD_ESCAPE[0] == "\\"
    assert MD_ESCAPE[1] == "&"
    assert md_safe(r"x\&y", limit=240) == r"x\\\&y"


def test_ampersand_escaping_kills_entity_spoofing() -> None:
    """F1 — the class the token-type oracle structurally could not see."""
    on_disk = md_safe("SYM_A&vert;PASSED", limit=240)
    assert "\\&vert;" in on_disk
    assert rendered_text(DEFAULT, f"- {on_disk}") == "SYM_A&vert;PASSED"


def test_backtick_is_escaped_not_deleted() -> None:
    """F3 — deletion rewrote one symbol as another inside an audit record."""
    assert md_safe("FOO`BAR", limit=240) == r"FOO\`BAR"
    assert rendered_text(VIEWER, f"- {md_safe('FOO`BAR', limit=240)}") == "FOO`BAR"


def test_image_construct_is_dead_only_via_bracket_escaping() -> None:
    """`!` is absent from the set on purpose — this pins WHY that is safe.

    Deleting `[` or `]` from MD_ESCAPE re-enables outbound image requests from
    the exported file, so the dependency is asserted rather than commented.
    """
    assert "!" not in MD_ESCAPE
    assert "[" in MD_ESCAPE and "]" in MD_ESCAPE
    assert live_tokens(DEFAULT, f"- {md_safe('![a](http://evil.com/x.png)', limit=240)}") == {
        "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
    }


# --------------------------------------------------------------------------- #
# The newline collapse — the load-bearing block-starter control (D-10)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("starter", ["- item", "+ item", "= h", "1) item", "1. item",
                                     "> quote", "# head", "---", "    indented"])
def test_collapse_defuses_block_starters_pushed_onto_a_new_line(starter: str) -> None:
    """COUNTERFACTUAL for the pin: delete the collapse in `_normalise` and this
    goes RED for every case.

    The escape set does NOT contain `-`, `+` or `=`; escaping them would render
    `mac-linked` as `mac\\-linked` at every kebab-case identifier. What actually
    defuses a block starter is that a value cannot reach column 0 — the collapse
    guarantees it, and the caller's literal prefix does the rest.
    """
    hostile = f"benign\n{starter}"
    assert "\n" not in md_safe(hostile, limit=240)
    assert live_tokens(VIEWER, f"- {md_safe(hostile, limit=240)}") == {
        "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
    }


@pytest.mark.parametrize("value", ["- item", "+ item", "= item", "1) item", "---"])
def test_leading_block_starter_is_defused_behind_a_list_marker(value: str) -> None:
    """A-43 — the collapse alone is NOT sufficient when the prefix is a marker.

    The original ruling was that a non-empty literal prefix keeps the value out
    of column 0. True for `| ` and `# `; false for `- `, which is a real
    emission shape (`f"- {md_safe(path)}"`). Measured before the fix, behind
    a `- ` prefix: `1) item` opened an ordered list, `---` emitted an `hr`, and
    `- item` opened a NESTED list whose marker was consumed — so the reader saw
    `item` while the file said `- item`.

    Both clauses matter here. The third case opens nothing, so a grammar-only
    assertion scored it inert while the display silently lost two characters.
    """
    document = f"- {md_safe(value, limit=240)}"
    assert live_tokens(VIEWER, document) == {
        "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
    }, "a block construct survived at the head of the value"
    assert rendered_text(VIEWER, document) == value, "the value lost its leading token"


def test_interior_hyphen_is_never_escaped() -> None:
    """The reason the whole-set escape was rejected: every kebab-case identifier
    in the report would acquire visible noise. `mac-linked` is real
    (`report_service.py:987`)."""
    assert md_safe("mac-linked", limit=240) == "mac-linked"
    assert md_safe("a-b-c", limit=240) == "a-b-c"


def test_u2028_is_dropped_although_it_is_not_a_control_character() -> None:
    """U+2028 is category `Zl`, so a Cc/Cf-only filter misses it — measured.

    It displays as a line break the bytes do not contain, which is the deception
    the finding named. This case is why `_DROP_CATEGORIES` carries `Zl`/`Zp`.
    """
    assert unicodedata.category(" ") == "Zl"
    assert md_safe("a b", limit=240) == f"a{LOSS_MARKER}b"
    assert md_code("a b") == f"a{LOSS_MARKER}b"


@pytest.mark.parametrize("ch", ["‮", "​", "﻿", "⁦", "",
                                " ", " "])
def test_deceptive_characters_are_replaced_visibly_not_silently(ch: str) -> None:
    """A dropped character must be SEEN. RLO reverses a displayed filename; ZWSP
    makes two distinct symbol names render identically in a symbol↔address
    record. Silent removal would hide both."""
    assert md_safe(f"a{ch}b", limit=240) == f"a{LOSS_MARKER}b"
    assert LOSS_MARKER in md_code(f"a{ch}b")


# --------------------------------------------------------------------------- #
# Caps, empties, fail-closed
# --------------------------------------------------------------------------- #


def test_mode_a_truncation_boundary_pair() -> None:
    """The fixture crosses the cap by exactly one — a fixture UNDER the limit is
    the batch-60 failure (every test passed with the guard deleted)."""
    assert TRUNCATION_MARKER not in md_safe("x" * 240, limit=240)
    assert TRUNCATION_MARKER in md_safe("x" * 241, limit=240)


def test_limit_is_required_and_keyword_only() -> None:
    """Every Mode-A site states its own cap; there is no inheritable default.

    A shared 240 default silently truncated ~20 fields whose upstream bounds
    differ (an `issue.message` is scrubbed at 500; an NTFS basename reaches 255).
    """
    with pytest.raises(TypeError):
        md_safe("x")           # type: ignore[call-arg]
    with pytest.raises(TypeError):
        md_safe("x", 240)      # type: ignore[misc]


def test_mode_b_never_truncates() -> None:
    """A cap on a Mode-B value would fire on one machine and not another — the
    value is an absolute path whose length depends on the operator's home
    directory and temp-root depth, which is a machine-dependent golden."""
    long_path = "/" + "d" * 4000 + "/a.s19"
    assert md_code(long_path) == long_path
    assert TRUNCATION_MARKER not in md_code(long_path)


def test_truncation_marker_is_distinct_from_the_validation_one() -> None:
    """Two markers exist. A test importing the wrong one is a false GREEN, so
    the difference is pinned and merging them must be a conscious act."""
    from s19_app.validation.model import _TRUNCATION_MARKER as VALIDATION_MARKER

    assert TRUNCATION_MARKER != VALIDATION_MARKER


@pytest.mark.parametrize("value", ["", "   ", "\n\t"])
def test_both_modes_render_the_empty_marker(value: str) -> None:
    """Mode B included — otherwise the report emits a bare `` `` `` span."""
    assert md_safe(value, limit=240) == EMPTY_MARKER
    assert md_code(value) == EMPTY_MARKER


def test_a_value_of_only_format_characters_is_not_empty() -> None:
    """A zero-width-only value renders the loss marker, NOT `(empty)`.

    Deliberate: `(empty)` would say "the field had no content", while the field
    actually held characters chosen to be invisible. The marker keeps that
    visible to whoever reads the record.
    """
    assert md_safe("​", limit=240) == LOSS_MARKER
    assert md_code("​") == LOSS_MARKER


def test_escaping_failure_propagates_and_is_never_swallowed() -> None:
    """FAIL-CLOSED (D-18). Correct today only because there is a single write
    sink; this makes it a requirement, so a later `except Exception: return
    str(value)` "robustness" patch is a test failure rather than a silent
    bypass of the entire control."""

    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        md_safe(Hostile(), limit=240)
    with pytest.raises(RuntimeError):
        md_code(Hostile())


def test_bytes_render_without_reopening_the_grammar() -> None:
    """`str(b"\\x00")` yields a backslash — safe only because `\\` is escaped
    first, which is the same ordering property D-5 relies on."""
    assert live_tokens(VIEWER, f"- {md_safe(b'a`b', limit=240)}") == {
        "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
    }
