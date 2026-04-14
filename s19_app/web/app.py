from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from flask import Flask


def create_app(test_config: Optional[dict[str, Any]] = None) -> Flask:
    """
    Summary:
        Construct the Flask web viewer application with templates and static assets.

    Args:
        test_config (dict | None): Optional overrides for unit tests (e.g. ``SECRET_KEY``).

    Returns:
        Flask: Configured application instance.

    Data Flow:
        - Resolve package paths for templates and static files.
        - Apply default and test configuration.
        - Register HTTP routes from ``register_routes``.

    Dependencies:
        Uses:
            - ``register_routes``
    """
    pkg = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        instance_relative_config=False,
        template_folder=str(pkg / "templates"),
        static_folder=str(pkg / "static"),
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("S19WEB_SECRET_KEY", "dev-insecure-change-for-production"),
        MAX_CONTENT_LENGTH=64 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    from .session_store import SessionStore

    if "VIEWER_STORE" not in app.config:
        app.config["VIEWER_STORE"] = SessionStore()

    from .routes import register_routes

    register_routes(app)
    return app
