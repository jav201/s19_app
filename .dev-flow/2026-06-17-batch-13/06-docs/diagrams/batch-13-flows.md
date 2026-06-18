# Batch-13 flow diagrams — s19_app

> **Audience:** engineering / reviewers.
> **Purpose:** show the two shipped flows and, for US-014, mark which nodes are NEW batch-13 code vs REUSED (already-shipped) write path.
> Source: `01-requirements.md` §4 (LLR-013.x / LLR-014.x), `04-validation.md`.

---

## 1. CRC config-load flow (US-013 / HLR-013)

The Load button reads a config file's **raw text** into the editable config view. On fault it surfaces an error and runs no check. The CRC run path is unchanged — Execute still parses the editor text.

```mermaid
flowchart TD
    A["Config-path Input<br/>#operation_config_path"] --> B["Load config Button<br/>#operation_config_load"]
    B --> C["on_button_pressed → _load_config_from_path<br/>screens.py:795/801/841"]
    C --> D["read_crc_config_text(raw_path, base_dir, size_probe)<br/>crc_config.py — NEW"]
    D --> E["resolve_input_path<br/>workspace.py:469"]
    E --> F{"size-cap check<br/>READ_SIZE_CAP_BYTES<br/>io.py:192 — BEFORE read"}
    F -->|"over cap / unresolvable / unreadable"| G["return (None, [one error])<br/>collect-don't-abort"]
    F -->|"ok"| H["read_text → return (raw_text, [])"]
    G --> I["surface error on status<br/>#operation_result_status<br/>editor UNCHANGED · 0 CRC checks"]
    H --> J["fill #operation_config TextArea<br/>with raw text · NO parse on load"]
    J --> K["(later) Execute → parse_crc_config(TextArea.text)<br/>screens.py:838-840 — UNCHANGED run path"]

    classDef newcode fill:#1f6f3f,stroke:#0d3b21,color:#ffffff;
    classDef reuse fill:#2b4a6f,stroke:#16263a,color:#ffffff;
    class A,B,C,D newcode;
    class E,F,K reuse;
```

**Legend:** green = NEW batch-13 code · blue = reused existing substrate. The dummy `DUMMY_CONFIG_TEXT` (`crc_config.py:47`) stays pre-loaded whenever no file is loaded or a fault occurs.

---

## 2. Paste-changeset flow (US-014 / HLR-014)

The paste field (pre-loaded with the FAKE `DUMMY_CHANGESET_TEXT`) is parsed into the owned `ChangeDocument` via the NEW string seam, then handed to the **existing** apply / containment / verify / save-back path — no new write surface.

```mermaid
flowchart TD
    A["Paste TextArea<br/>#patch_paste_text<br/>pre-loaded DUMMY_CHANGESET_TEXT — NEW"] --> B["Parse pasted control<br/>ActionRequested(action=parse_paste, paste_text) — NEW"]
    B --> C["app.py router elif<br/>app.py:1336-1338 — NEW"]
    C --> D["ChangeService.load_text(text)<br/>change_service.py — NEW"]
    D --> E["parse_change_document(text)<br/>changes/io.py — NEW · json.loads(text)"]
    E --> F{"3-exception catch<br/>JSONDecodeError / RecursionError / UnicodeDecodeError"}
    F -->|"malformed"| G["collect MF-JSON-PARSE<br/>collect-don't-abort · 0 raises"]
    F -->|"valid"| H["interpret entries<br/>source_path=None"]
    G --> I["owned ChangeDocument<br/>(carries findings) — self.document"]
    H --> I
    I --> J["EXISTING apply_doc router<br/>app.py:1335 region — REUSE"]
    J --> K["classify INSIDE / PARTIAL / OUTSIDE<br/>classify_containment — REUSE"]
    K --> L["save-back confirm<br/>prompt name from variant_id — REUSE"]
    L --> M["contained emit<br/>emit_s19_from_mem_map via copy_into_workarea<br/>io.py:1300 — REUSE · no clobber"]
    M --> N["verify_written_image<br/>reader-as-oracle — REUSE"]

    classDef newcode fill:#1f6f3f,stroke:#0d3b21,color:#ffffff;
    classDef reuse fill:#2b4a6f,stroke:#16263a,color:#ffffff;
    class A,B,C,D,E newcode;
    class J,K,L,M,N reuse;
```

**Legend:** green = NEW batch-13 code · blue = REUSED already-shipped write path (verified unchanged vs `febd843` — 0 new write code paths, LLR-014.3 standing gate). `read_change_document` is refactored to delegate to `parse_change_document` (`call_count == 1`), so the file-read path and the paste path share one interpretation seam.
