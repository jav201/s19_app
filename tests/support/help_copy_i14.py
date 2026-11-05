"""The approved help and legend copy of batch-101 Inc 14 ('Help copy I14' and 'Legend copy I14').

Pinned text, written out from the approved requirement texts; the tests compare the
shipped constants against it. Test support only: nothing under ``s19_app`` imports it.
"""
from __future__ import annotations

#: section key -> (title, steps) of the six rewritten help sections.
REWRITTEN_SECTIONS = {
    'a2l': (
        'A2L Explorer',
        (
            'Load an A2L (`^L`) to list its tags (measurements and characteristics) in the tag table, each with its address, length, values and the memory region it falls in.',
            'Filter tags narrows the table to the tags that match; All, Invalid and In-Memory choose which tags it lists; type in Find in tag table and press Find next to move to the next matching tag; Page Prev and Page Next turn its pages.',
            "`/` puts the cursor in Search ASCII text, the search box of the hex pane: Find Next finds that text in the loaded image's bytes. `g` puts it in Goto 0xADDR: Goto shows that address.",
            "`d` describes the highlighted tag, with its points for a CURVE or MAP tag. `j` writes the parsed A2L as JSON into the work area's `temp\\` folder.",
            "The Region column comes from the A2L's MEMORY_SEGMENT declarations (flash, ram or unknown); the A2L tab of Split / Join / Export lists the same segments.",
        ),
    ),
    'workspace': (
        'Workspace',
        (
            'Load files with `^L` / `l` — S19/HEX images, A2L, MAC. Loaded artifacts appear in the Loaded panel with their diagnostics.',
            'Save a project (`^S` / `s`) to gather the loaded files into one project folder; load one back with `p`.',
            '`o` opens the work area folder in the file manager; `r` refreshes the file list.',
            '`U` unloads everything (with per-artifact unload from the Loaded panel).',
            'Without a project, the files you save stay in the common folders under `.s19tool\\`: change-set and check files in `workarea\\patches\\`, Split / Join / Export files in `workarea\\splits\\`, CRC templates in `templates\\`.',
        ),
    ),
    'checks': (
        'Checks',
        (
            'Checks run in the Patch Editor (Run checks on its Checks tab); this window shows the last run, read-only.',
            'The top line tallies Pass / Fail / Uncheck. The list groups the entries by outcome: failed, then uncheckable, then passed, each under a header with its count.',
            'Click a row, or press Enter on it, to show the bytes around its address in the Hex Peek pane.',
            'An uncheckable entry is not a failure: it could not be verified (no image, address outside the image, declaration fault), and its row names the reason. Fix the change document or load the right image.',
            'The list shows at most 40 entries; when the run holds more, its last line says so.',
            'Run checks again after every edit.',
        ),
    ),
    'crc_designer': (
        'CRC Designer',
        (
            'Pick a preset (e.g. CRC-32/ISO-HDLC); presets are starting points, and every parameter (width, polynomial, init, reflection in and out, XOR out) stays editable.',
            'The self-test computes the CRC of `123456789`; it must read MATCH before you trust a custom set.',
            'Coverage computes CRCs over the ranges you type in Ranges (`start-end`, end excluded), in the loaded image: Intra gap and Join gaps choose how gaps are handled, Pad byte is the fill byte, and On conflict chooses what happens when a padded gap holds image bytes. It is a preview; nothing is written.',
            'Store placement shows where the CRC would be written (Address, Bytes, Store endianness). The CRC Designer never writes the image; Operations (`x`) writes CRCs from a CRC config.',
            "Save writes the algorithm as a template, `<Name>.crc.json`, into the project's `templates\\` folder, or without a project into the common `.s19tool\\templates\\` folder; Load reads the template typed in Load path.",
            'Open templates/ opens the folder Save writes to.',
        ),
    ),
    'reports': (
        'Reports',
        (
            'Reports belong to a project — load or save one first (`p` / `^S`).',
            "The list shows the project's `reports\\*.md` files, its generated reports newest first; pick one to view it.",
            "Filter picks a filter file from the project's `filters\\` folder, or takes a typed filter path, to write only part of a report; blank means the full report.",
            'Declared regions starts with the regions saved with the open project (empty when it has none) and keeps the lines of your last Generate; Save project stores them with the project. Add `name,start,end` lines to annotate region coverage in the generated report.',
            'Context bytes sets how many bytes of surrounding memory accompany each change in the report.',
            "Generate new report writes one Markdown file, `<time>-report.md`, into the project's `reports\\` folder; Open reports/ opens that folder.",
        ),
    ),
    'split_join_export': (
        'Split / Join / Export',
        (
            'The window exports parts of the loaded image (`^L`). Open it from the palette (`^K`, Split / Join / Export); `esc` closes it.',
            "`t` chooses where the ranges come from: the A2L's MEMORY_SEGMENTs, the image's own contiguous ranges (the default), or manual lines `0xSTART-0xEND` that you type, one per line, end included.",
            'Tick the ranges to export: `space` ticks the highlighted row, `a` ticks all, `n` none. The coverage column warns when a range has no bytes in the image.',
            '`m` switches the mode. Split writes one file per ticked range. Join packs the ticked ranges into ONE file: concat puts them back to back, fill keeps their offsets and pads the gaps between them.',
            '`g` switches the gaps: in split mode, skip keeps each file sparse and fill pads the holes in each range; in join mode, concat or fill. `p` switches the pad byte between 0x00 and 0xFF.',
            "`f` switches the format (S19, HEX or BIN) for both modes. `d` switches the destination: project writes into the project's `splits\\` folder (the common one when no project is open), common into `.s19tool\\workarea\\splits\\`.",
            "`e` exports: split writes `‹stem›_‹segment›.‹ext›` per range, join writes one `‹stem›_joined.‹ext›`, where ‹stem› is the loaded image's file name without its extension. The NAMING line shows the name of the first file.",
            'When the export would write a large padded span or an empty file, the first `e` only warns; press `e` again to write.',
        ),
    ),
}

#: Flow Builder step number (1-based) -> the approved text of the six changed steps.
FLOW_STEPS = {
    1: "Build a chain of blocks that runs on the loaded image: the pipeline shows each block as a card, in run order, joined by cables, and the area under Run lists each block's verdict. Flows are project-only: Save… and Load… use the project's `flows\\` folder.",
    5: 'CRC — picks a CRC block: it stamps CRCs from a CRC config file.',
    12: 'CRC template — the CRC config file a CRC block reads (the same format as the Operations CRC config); a template the CRC Designer saves is not a CRC config and is refused.',
    17: "· source — under a card's file input, where that file comes from: project, temp (the workarea temp folder), loaded (an artifact loaded now) or external (imported into the project's `external\\` folder); a bold `missing: <name>` names a ref nothing provides.",
    18: "Browse — beside a file ref field (and in the block edit dialog), opens a chooser listing the project's files, the workarea temp files and the loaded artifacts; a pick only fills the field — the block changes with Add or Save. A temp or loaded file outside the project is copied into the project's `external\\` folder first, so the chain can run it; an existing name gets a `-1`, `-2`, … suffix, never an overwrite.",
    19: "External path — in the chooser, type an absolute path and press Import to bring an outside file into the project's `external\\` folder; without a project the import refuses with `Load or create a project before importing an external file.`, and an unreadable file with `External file not readable: <name>`.",
}

MAP_KEYS_LINE = '↑↓ move · click / ↵ inspect · double-click open hex · Esc close'
MAP_REGION_ROW_FIELD_KEY = 'glyph · start · size · size vs largest · A2L sym · band · ↵ inspect'
