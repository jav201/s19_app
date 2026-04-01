# S19Tool / Hex Edit Tool

**S19Tool** provides a command-line interface and a Textual-based TUI for parsing, visualizing, and patching Motorola S19 firmware files. The TUI also supports Intel HEX files and minimal A2L parsing with JSON export.

---

## 🚀 Features

- Parse and validate `.s19` files
- Parse Intel HEX (`.hex`, `.ihex`) files
- Auto-detect file endianness
- Visualize memory as hex + ASCII
- Highlight memory ranges and gaps
- Patch memory with strings or integers
- Export modified `.s19` files
- Rich CLI output with color
- Textual TUI with hex view, ranges, and A2L summary
- Minimal A2L parsing with JSON export

---

## 📦 Installation

Install locally in editable mode:

```bash
git clone https://github.com/jav201/s19_app.git
cd s19_app
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

If you want tests:

```bash
pip install -r requirements-dev.txt
```

Install locally (non-editable, for users):

```bash
git clone https://github.com/jav201/s19_app.git
cd s19_app
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
```

---

## 🧰 Usage (TUI)
```bash
s19tui
```

Key bindings:
- `L` Load S19/HEX into workarea temp
- `A` Load A2L file
- `S` Save project (copies data + A2L into project folder)
- `P` Load project
- `J` Dump A2L JSON into workarea temp
- `O` Open workarea in Explorer
- `R` Refresh workarea list
- `Q` Quit

Workarea layout:
- `.s19tool/workarea/temp` for transient loads
- `.s19tool/workarea/<project-name>/` for saved projects
- `.s19tool/logs/s19tui.log` for TUI logs (5 MB rotation)

---

## 📦 Usage (CLI)
```bash
# General Info
s19tool firmware.s19 info

# Validation
s19tool firmware.s19 verify

# Memory Layout
s19tool firmware.s19 layout
s19tool firmware.s19 ranges
s19tool firmware.s19 gaps

# Hex Dump
s19tool firmware.s19 dump --start 0x7AF0 --length 64
s19tool firmware.s19 dump-all
s19tool firmware.s19 dump-by-range
s19tool firmware.s19 dump-by-range --output memory.txt

# Patching Memory
s19tool firmware.s19 patch-str --addr 0x00000000 --text "HELLO" --save-as modified.s19
s19tool firmware.s19 patch-hex --addr 0x80040000 --bytes "01 02 03 04" --save-as modified.s19

# Version
s19tool firmware.s19 version
```

---
