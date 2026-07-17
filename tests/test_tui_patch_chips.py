"""Patch Editor BIG — chip-button CSS tests (batch-48, Inc-2).

Verdicts HLR-076 (R-TUI-076, US-P1) — the chip family batch-47 DEFERRED — through
the shipped Patch Editor surface:

- **AT-076a** — the structural invariant: EVERY ``Button`` docked in the Patch
  Editor carries a class from the chip family, and buttons from three different
  groups resolve to three DISTINCT chip colours. Enumerated from the live tree
  (never a hard-coded button count — C-29: no all-at-once claim).
- **AT-076b** ★ — the **C-30 leak probe**. This is what makes the batch's
  "C-30 = N/A" verdict FALSIFIABLE rather than asserted (§2.4-8 / LLR-076.1).
- **TC-076.1** — every chip rule's selector is ``#patch_editor_panel``-rooted;
  0 bare ``Button`` selectors were added.
- **TC-076.2** — group assignment across the button-bearing docked containers.

**Why AT-076b uses Textual's own matcher, not a source grep.** A grep over
``styles.tcss`` proves what was WRITTEN; it cannot prove what MATCHES. This AT
asks Textual itself: for every ``Button`` in the live tree that is NOT a
descendant of ``#patch_editor_panel``, does any chip ``RuleSet`` match it
(``textual.css.match.match(rule.selector_set, node)``)? The answer must be no,
for all of them — which is exactly the C-30 re-bind condition §2.4-8 records in
advance.

⚠ **AT-076b and TC-076.1 discriminate DIFFERENT mutations — neither subsumes the
other, and this was MEASURED, not reasoned.** Both mutations below were executed
against the shipped code; the results corrected an earlier draft of this very
docstring, which claimed AT-076b catches the unscoping. **It does not.**

    Mutation A — unscope the class root
      (`#patch_editor_panel .patch-chip` -> `.patch-chip`):
        TC-076.1  RED  -> unrooted: ['.patch-chip', '.patch-chip-entry
                          .patch-chip', '.patch-chip-apply .patch-chip',
                          '.patch-chip-checks .patch-chip']
        AT-076b   GREEN  <-- ⚠ BLIND TO IT

    Mutation B — widen the base rule to a bare type selector
      (`#patch_editor_panel .patch-chip` -> `Button, #patch_editor_panel
      .patch-chip`):
        AT-076b   RED  -> "C-30 LEAK - 26 chip rule/button matches OUTSIDE
                          #patch_editor_panel": #ws_load_project_button,
                          #search_button, #goto_button, #a2l_filter_field,
                          #a2l_filter_all, ... (26 total, both regimes)
        TC-076.1  RED  -> unrooted: ['Button, #patch_editor_panel .patch-chip']

**Why AT-076b is blind to Mutation A:** the chip rules are CLASS-based, and this
increment only ever applies those classes inside the panel — so an unscoped
`.patch-chip` rule still cannot match a non-patch `Button`. The unscoping is
latent: harmless today, a live app-wide leak the moment any future screen
reuses the class name. Only the SOURCE check sees it.

**Why TC-076.1 is not sufficient either:** it proves what was WRITTEN, never
what MATCHES. Mutation B shows the real leak — a rule whose selector text a
reviewer could wave through — and it is the matcher, asking Textual itself,
that counts the 26 real victims.

So the pair is kept deliberately: TC-076.1 guards the latent class of mistake,
AT-076b guards the live one. A class-membership probe ("no outside button
carries `.patch-chip`") is NOT kept as the primary oracle — it passes by
construction and would have stayed green under BOTH mutations; it rides along in
AT-076b only as a cheap structural corroborator.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from textual.css.match import match
from textual.css.model import RuleSet
from textual.dom import DOMNode
from textual.widgets import Button

from s19_app.tui.app import S19TuiApp

# Both pilot regimes — the batch-47 `_SIZES` both-regimes loop, reused.
_SIZES = ((80, 24), (120, 30))

_PANEL_ID = "patch_editor_panel"

# The chip family's group classes and the container each is expected on
# (LLR-076.2). The five NAMED in LLR-076.2 are normative; the remaining four
# were `assumed — Phase-3 confirms` and are resolved here (see the module note
# in `screens_directionb.py::PatchEditorPanel.compose`):
#   * entry (blue)  — undo/redo MOVE the entry document, so they are
#     entry-actions, not apply-path.
#   * apply (green) — the variant group scopes WHAT A RUN TARGETS, and the
#     before/after row is revealed by the same save flow as the save-back row.
_GROUP_BY_CONTAINER = {
    # entry-actions (blue)
    "patch_doc_entry_buttons": "patch-chip-entry",  # LLR-076.2 (named)
    "patch_history_controls": "patch-chip-entry",  # resolved `assumed`
    # apply-path (green)
    "patch_doc_controls": "patch-chip-apply",  # LLR-076.2 (named)
    "patch_saveback_buttons": "patch-chip-apply",  # LLR-076.2 (named)
    "patch_paste_controls": "patch-chip-apply",  # LLR-076.2 (named)
    "patch_variant_select_row": "patch-chip-apply",  # resolved `assumed`
    "patch_execute_buttons": "patch-chip-apply",  # resolved `assumed`
    "patch_before_after_buttons": "patch-chip-apply",  # resolved `assumed`
    # checks (yellow)
    "patch_checks_controls": "patch-chip-checks",  # LLR-076.2 (named)
}

_GROUP_CLASSES = frozenset(_GROUP_BY_CONTAINER.values())

#: The base chip class every docked `Button` carries (HLR-076's invariant).
_CHIP_CLASS = "patch-chip"

_STYLES_TCSS = (
    Path(__file__).resolve().parents[1] / "s19_app" / "tui" / "styles.tcss"
)


def _in_patch_panel(node: DOMNode) -> bool:
    """True when ``node`` is `#patch_editor_panel` or one of its descendants."""
    return any(
        getattr(a, "id", None) == _PANEL_ID
        for a in getattr(node, "ancestors_with_self", ())
    )


def _chip_rule_sets(app: S19TuiApp) -> list[RuleSet]:
    """Every parsed `RuleSet` in the app stylesheet belonging to the chip family.

    Selected on the rule's own SELECTOR text so a NEW chip rule is picked up
    automatically — the probe must not need editing to keep covering the family.
    """
    return [
        rule
        for rule in app.stylesheet.rules
        if _CHIP_CLASS in rule.selectors
    ]


def test_at076a_docked_buttons_are_grouped_chips() -> None:
    """AT-076a — every docked Button is a chip; >=3 groups resolve distinctly.

    Intent (HLR-076): the analyst reads the docked buttons as colour-GROUPED
    chips, so function is legible before the label is. Asserted as a structural
    invariant enumerated from the live tree — "every docked Button carries a
    chip class AND >=3 distinct groups are present" — never "the N buttons all
    render as chips", which would be an unverified all-at-once claim (C-29).
    """

    async def _run(size: tuple[int, int]) -> dict[str, object]:
        app = S19TuiApp(base_dir=Path(_tmp(size)))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one(f"#{_PANEL_ID}")
            buttons = list(panel.walk_children(Button))
            naked = [b.id for b in buttons if _CHIP_CLASS not in b.classes]
            # One button from each of the three groups, through the REAL tree.
            probes = {
                "entry": app.query_one("#patch_entry_add_button", Button),
                "apply": app.query_one("#patch_doc_apply_button", Button),
                "checks": app.query_one("#patch_checks_run_button", Button),
            }
            return {
                "count": len(buttons),
                "naked": naked,
                "colours": {
                    k: b.styles.color.rgb for k, b in probes.items()
                },
                "heights": {k: b.region.height for k, b in probes.items()},
            }

    for size in _SIZES:
        r = asyncio.run(_run(size))
        assert r["count"] > 0, f"@{size}: no docked Buttons found at all"
        assert r["naked"] == [], (
            f"@{size}: {len(r['naked'])} docked Button(s) carry NO chip class "
            f"— the family must cover every one of them: {r['naked']}"
        )
        colours = r["colours"]
        assert len(set(colours.values())) == 3, (
            f"@{size}: the three chip groups must resolve to three DISTINCT "
            f"colours; got {colours}"
        )
        # The chip's own shape: one row, not Textual's 3-row default Button.
        for group, height in r["heights"].items():
            assert height == 1, (
                f"@{size}: the {group} chip must render as a single row "
                f"(Textual's default Button is 3); got height={height}"
            )


def test_at076b_c30_leak_probe_no_chip_rule_matches_outside_patch() -> None:
    """AT-076b ★ — the C-30 leak probe: no chip rule matches outside the panel.

    Intent (LLR-076.1 / §2.4-8): batch-48 is PATCH-SCREEN-SCOPED, so C-30's
    "sequence an app-wide restyle LAST" mandate does not bind — but ONLY because
    the chip family cannot reach a non-patch widget. This AT is what turns that
    verdict from an assertion into evidence: it asks Textual's own selector
    matcher whether any chip `RuleSet` matches any `Button` outside
    `#patch_editor_panel`. If one ever does, the family HAS gone app-wide, C-30
    RE-BINDS, and the chip increment must be re-sequenced last.

    Scope of this AT, measured (see the module docstring): it catches a rule
    that MATCHES outside (Mutation B, 26 victims) and is BLIND to a merely
    unscoped class selector (Mutation A) — `test_tc076_1_*` owns that half.
    """

    async def _run(size: tuple[int, int]) -> dict[str, object]:
        app = S19TuiApp(base_dir=Path(_tmp(size)))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            rules = _chip_rule_sets(app)
            outside = [
                b for b in app.screen.query(Button) if not _in_patch_panel(b)
            ]
            leaks: list[str] = []
            for button in outside:
                for rule in rules:
                    # `selector_set` is the parsed list[SelectorSet] `match`
                    # consumes; `rule.selectors` is its rendered STRING.
                    if match(rule.selector_set, button):
                        leaks.append(f"#{button.id} <- {rule.selectors}")
            return {
                "n_rules": len(rules),
                "n_outside": len(outside),
                "leaks": leaks,
                "outside_carrying_chip_class": [
                    b.id
                    for b in outside
                    if ({_CHIP_CLASS} | _GROUP_CLASSES) & set(b.classes)
                ],
            }

    for size in _SIZES:
        r = asyncio.run(_run(size))
        # Guard the probe itself: with 0 rules or 0 outside buttons it would
        # pass vacuously and prove nothing (the MJ-2 self-voiding shape).
        assert r["n_rules"] >= 1, (
            "the probe found NO chip rules in the stylesheet — it would pass "
            "vacuously; the family or its detection is broken"
        )
        assert r["n_outside"] >= 1, (
            f"@{size}: the probe found NO Buttons outside #{_PANEL_ID} — it "
            "would pass vacuously"
        )
        assert r["leaks"] == [], (
            f"@{size}: C-30 LEAK — {len(r['leaks'])} chip rule/button matches "
            f"OUTSIDE #{_PANEL_ID}. The chip family has gone app-wide; C-30 "
            f"re-binds (§2.4-8): {r['leaks'][:5]}"
        )
        assert r["outside_carrying_chip_class"] == [], (
            f"@{size}: a non-patch Button carries a chip-family class: "
            f"{r['outside_carrying_chip_class']}"
        )


def test_tc076_1_every_chip_selector_is_panel_rooted() -> None:
    """TC-076.1 — source-level containment: every chip selector is panel-rooted.

    Intent (LLR-076.1): the peer of AT-076b at the SOURCE. AT-076b proves no
    chip rule matches the buttons that exist TODAY; this proves the family is
    written so that none ever could — including for a widget no current screen
    mounts. Both are kept: the matcher probe can only see the live tree.
    """
    css = _STYLES_TCSS.read_text(encoding="utf-8")
    # Selector text = everything before each `{`, comments stripped.
    stripped = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    selectors = [
        block.split("}")[-1].strip()
        for block in stripped.split("{")[:-1]
    ]
    chip_selectors = [s for s in selectors if _CHIP_CLASS in s]
    assert chip_selectors, "no chip selectors found in styles.tcss"
    unrooted = [
        s
        for s in chip_selectors
        if not all(
            part.strip().startswith(f"#{_PANEL_ID}")
            for part in s.split(",")
            if part.strip()
        )
    ]
    assert unrooted == [], (
        "every chip rule must be rooted at "
        f"#{_PANEL_ID} (LLR-076.1 — the C-30 containment); unrooted: {unrooted}"
    )
    # No bare `Button` rule was added anywhere by this family.
    bare_button = [
        s for s in selectors if re.fullmatch(r"Button(\s*,\s*Button)*", s)
    ]
    assert bare_button == [], (
        f"a bare `Button` selector would restyle every screen: {bare_button}"
    )


def test_tc076_2_group_assignment_on_docked_containers() -> None:
    """TC-076.2 — each button-bearing docked container carries ONE group class.

    Intent (LLR-076.2): the colour is a FUNCTION cue, so it lives on the
    container that defines the function, and a container may not straddle two
    groups. Every button-bearing container is mapped — 0 left `assumed`.
    """

    async def _run() -> dict[str, object]:
        app = S19TuiApp(base_dir=Path(_tmp((120, 30))))
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one(f"#{_PANEL_ID}")
            # The button-BEARING containers, enumerated from the live tree.
            parents = {
                b.parent.id: set(b.parent.classes)
                for b in panel.walk_children(Button)
            }
            return {"parents": parents}

    parents = asyncio.run(_run())["parents"]
    assert set(parents) == set(_GROUP_BY_CONTAINER), (
        "the live button-bearing containers drifted from the mapped set — a "
        "new one must be assigned a group, not left unmapped (LLR-076.2). "
        f"live={sorted(parents)} mapped={sorted(_GROUP_BY_CONTAINER)}"
    )
    for container_id, classes in parents.items():
        groups = classes & _GROUP_CLASSES
        assert len(groups) == 1, (
            f"#{container_id} must carry EXACTLY ONE chip group class; "
            f"got {sorted(groups)}"
        )
        assert groups == {_GROUP_BY_CONTAINER[container_id]}, (
            f"#{container_id} is in the wrong chip group: got {sorted(groups)}, "
            f"expected {_GROUP_BY_CONTAINER[container_id]}"
        )
    assert len(_GROUP_CLASSES) >= 3, "the family must present >=3 groups"


def _tmp(size: tuple[int, int]) -> str:
    """A per-run scratch base dir (the app writes `.s19tool/` under it)."""
    import tempfile

    return tempfile.mkdtemp(prefix=f"s19chips{size[0]}x{size[1]}-")
