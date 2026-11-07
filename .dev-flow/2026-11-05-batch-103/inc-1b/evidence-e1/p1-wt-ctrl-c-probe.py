"""batch-103 Inc 1b, pilot P-1 — NOT RUN at E1 (the E1 agent may not run anything on the Windows PC).

Question: does Ctrl+C reach a Textual 8.2.8 app as the key ``ctrl+c`` in Windows Terminal (and, optionally,
in conhost) when the terminal holds no selection of its own?

For the orchestrator, under the G1 exception only (real terminal, isolated LOCALAPPDATA, every window
closed afterwards). This probe touches NO clipboard:
- the app has no selectable text (``ALLOW_SELECT = False``) and no text box;
- ``copy_to_clipboard`` is replaced by a recorder that writes nothing (no OSC 52 is ever sent);
- the operator must NOT make a terminal selection (Shift+drag) while it runs: a terminal copy would
  write the real clipboard;
- it records key NAMES only, never text, to ``<out dir>/p1-keys.txt``.

Run:  python p1-wt-ctrl-c-probe.py <out dir>
Then press, in order: Ctrl+C, Ctrl+C, x, q.   Pass: the file lists ``ctrl+c`` twice, then ``x``.
"""
import sys
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Static

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "p1-keys.txt"


class Probe(App):
    ALLOW_SELECT = False
    BINDINGS = [Binding("ctrl+c", "seen_ctrl_c", "seen", priority=True), Binding("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Static("P-1: press Ctrl+C twice, then x, then q. Do not select text in the terminal.", id="msg")

    def on_mount(self) -> None:
        LOG.write_text("", encoding="utf-8")
        self.count = 0

    def copy_to_clipboard(self, text: str) -> None:  # never write any clipboard
        with LOG.open("a", encoding="utf-8") as f:
            f.write("ERROR copy_to_clipboard called (nothing written)\n")

    def on_key(self, event) -> None:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(f"key {event.key}\n")

    def action_seen_ctrl_c(self) -> None:
        self.count += 1
        with LOG.open("a", encoding="utf-8") as f:
            f.write("ctrl+c\n")
        self.query_one("#msg", Static).update(f"ctrl+c received {self.count} time(s). Press x, then q.")


if __name__ == "__main__":
    Probe().run()
