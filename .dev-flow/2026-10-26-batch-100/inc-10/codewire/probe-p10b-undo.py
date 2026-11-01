"""LLR-174.1 boundary probe: a patch applied then undone (read-only; throwaway tree)."""
import sys
from pathlib import Path
TREE = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(TREE))
from s19_app.tui.services.change_service import ChangeService
svc = ChangeService()
mem = {0x100: 0x11, 0x101: 0x22}
svc.mark_saved(mem)
svc.add_entry("0x00000100", "", "AA")
svc.apply(mem, [(0x100, 0x102)], [], None)
print("UNDO applied: byte", hex(mem[0x100]), "D =", svc.differs_from_last_saved(mem))
svc.undo()
print("UNDO after undo (no re-apply): entries", len(svc.document.entries), "byte", hex(mem[0x100]), "D =", svc.differs_from_last_saved(mem))
svc.apply(mem, [(0x100, 0x102)], [], None)
print("UNDO after undo + apply: byte", hex(mem[0x100]), "D =", svc.differs_from_last_saved(mem))
