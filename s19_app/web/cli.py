"""CLI entrypoint for the local Flask viewer."""

from __future__ import annotations

import os

from .app import create_app


def main() -> None:
    """Run the Flask development server bound to localhost only."""
    app = create_app()
    port = int(os.environ.get("S19WEB_PORT", "8765"))
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
