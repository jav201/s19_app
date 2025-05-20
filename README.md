# S19Tool

**S19Tool** is a command-line utility for parsing, visualizing, and patching Motorola S19 firmware files. It provides features for memory inspection, structured patching (e.g., inserting strings or integers), and exporting updated `.s19` files.

---

## 🚀 Features

- Parse and validate `.s19` files
- Auto-detect file endianness
- Visualize memory as hex + ASCII
- Highlight memory ranges and gaps
- Patch memory with strings or integers
- Export modified `.s19` files
- Rich CLI output with color

---

## 📦 Installation

Install locally in editable mode:

```bash
git clone https://github.com/jav201/s19_app.git
cd s19tool  # or S19_APP
pip install -e .
```
---

## 📦 Usage
```bash
🔍 General Info

s19tool firmware.s19 info

✅ Validation

s19tool firmware.s19 verify

📊 Memory Layout

s19tool firmware.s19 layout
s19tool firmware.s19 ranges
s19tool firmware.s19 gaps

🧾 Hex Dump

s19tool firmware.s19 dump --start 0x7AF0 --length 64
s19tool firmware.s19 dump-all

🧾 Memory Dump
s19tool firmware.s19 dump --start 0x8000 --length 64
s19tool firmware.s19 dump-by-range
s19tool firmware.s19 dump-by-range --output memory.txt
s19tool firmware.s19 dump-all

✏️ Patching Memory

s19tool firmware.s19 patch-str --addr 0x00000000 --text "HELLO" --save-as modified.s19
s19tool firmware.s19 patch-hex --addr 0x80040000 --bytes "01 02 03 04" --save-as modified.s19
s19tool firmware.s19 patch-hex --addr 0x80040000 --bytes "AA BB CC DD" --save-as modified.s19

📖 View Tool Version
s19tool firmware.s19 version
```
---
