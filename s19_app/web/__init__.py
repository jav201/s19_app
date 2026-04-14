"""Local Flask viewer for S19/HEX/MAC + optional A2L (read-focused MVP)."""

from .app import create_app

__all__ = ["create_app"]
