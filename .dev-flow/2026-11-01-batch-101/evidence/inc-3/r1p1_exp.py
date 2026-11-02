"""batch-101 Inc 3 E1: the R1-P1 experiments as a pytest plugin (``-p r1p1_exp``), so the real
TC-B100-20 node measures them. Same wrappers as R1-P1-profile-script.py; env R1P1_EXP selects
``gather`` and/or ``memo``. Runtime wrappers only; no source file is edited."""
import os

import s19_app.tui.app as app_module
from s19_app.tui.services import manifest_writer as mw
from s19_app.tui.services import variant_execution_service as ves

EXP = {e for e in os.environ.get("R1P1_EXP", "").split(",") if e}
print(f"r1p1_exp: {sorted(EXP) or 'none'}")
if "gather" in EXP:
    _real_gather = app_module.gather_project_artifacts

    def _gather_once(project_dir, *, composition_names=(), **kw):
        return _real_gather(project_dir, composition_names=list(dict.fromkeys(composition_names)), **kw)

    app_module.gather_project_artifacts = _gather_once
if "memo" in EXP:
    _real_resolve = ves._resolve_manifest_entry
    _memo = {}

    def _resolve_once(project_root, raw_entry, context, issues, mode=ves.ENTRY_MODE_DEFAULT, walk=None):
        key = (id(walk), raw_entry, mode) if walk is not None and isinstance(raw_entry, str) else None
        if key is not None and key in _memo and _memo[key][0] is walk:
            return _memo[key][1]
        before = len(issues)
        result = _real_resolve(project_root, raw_entry, context, issues, mode, walk)
        if key is not None and result is not None and len(issues) == before:
            _memo[key] = (walk, result)
        return result

    ves._resolve_manifest_entry = _resolve_once
    mw._resolve_manifest_entry = _resolve_once
if "isfile" in EXP:
    # The composition limb tests ``is_file()`` on the joined path without ``resolve()`` first
    # (``is_file`` follows links itself); the function is re-compiled from its own source with
    # that one line changed, in its own module namespace.
    import inspect, textwrap
    from s19_app.tui.services import project_gather_service as pgs

    _src = textwrap.dedent(inspect.getsource(pgs.gather_project_artifacts))
    _old = "in_project = (resolved_project / name).resolve()"
    assert _src.count(_old) == 1, "isfile experiment: the line moved"
    exec(compile(_src.replace(_old, "in_project = resolved_project / name"), pgs.__file__, "exec"), pgs.__dict__)
    if "gather" in EXP:
        _real_gather = pgs.gather_project_artifacts
    else:
        app_module.gather_project_artifacts = pgs.gather_project_artifacts
