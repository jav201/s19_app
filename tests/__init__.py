"""s19_app's test package — the __init__ that keeps `tests.conftest` home.

Without it this directory is a namespace portion and ANY regular `tests` package
later on sys.path (an editable install's own test dir, e.g. another repo's
editable .pth) shadows it: `from tests.conftest import ...` silently imported the
other repo's conftest (measured 2026-10-08: mapper's editable .pth broke s19_app's
collection with 22 errors). With this file, the repo's own tests package wins by
sys.path order (the repo root is first via pyproject's pythonpath = ["."]).
"""
