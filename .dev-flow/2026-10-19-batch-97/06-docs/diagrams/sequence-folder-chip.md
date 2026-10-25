# Diagram — folder-chip press through the real-directory guard (sequence)

> **Role:** `docs-writer`. Mermaid sequence block: the engineer presses an open-folder chip (US-138; HLR-148, LLR-148.1–148.3, 148.8, 148.10; AT-B97-12, AT-B97-13). Facts: `03-increments/increment-001.md` §1; anchors on the tree at `c899113`.

```mermaid
sequenceDiagram
    autonumber
    actor ENG as Engineer
    participant CHIP as OpenFolderChip (open_folder_chip.py:66)
    participant FOS as folder_open_service.py
    participant OS as OS open seam (open_folder_in_file_manager)

    Note over CHIP: label from chip_label (:204) — "📂 Open flows/", "📂 Open session"
    ENG->>CHIP: press chip
    CHIP->>FOS: resolve_chip_target(family, project) (:340)
    alt no active project (project-only family)
        FOS-->>CHIP: None
        CHIP-->>ENG: chip disabled; status = no_project_reason(family) (:227), naming its folder
    else target resolved
        FOS-->>CHIP: target path
        opt target missing and family is not session
            CHIP->>FOS: create_chip_home (flows only inside the resolved project)
        end
        CHIP->>FOS: is_openable_chip_dir(target, chip_family_root(...)) (:268, :247)
        alt directory, no reparse point, inside the family root
            CHIP->>OS: open (one call)
            CHIP-->>ENG: status "Opened folder: <path>"
        else file, junction, missing or outside the root
            CHIP-->>ENG: status "Refused to open <target>: not a real folder inside <root>/" (0 seam calls)
        end
    end
```

**Reading notes.** `flows` resolves to `<project>/flows` and `session` to `<project>`; `session` is never created. Opening a file manager paints nothing in the terminal, so the acceptance tests spy on the OS seam (the one exception to surface-only observation, `01-requirements.md` §3 preamble). A file or junction in place of `flows` gives 0 seam calls (`04-validation.md` Layer A, HLR-148 row).
