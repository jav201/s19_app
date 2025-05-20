import argparse
from .core import S19File
from rich.console import Console
from .version import __version__
from .utils import format_bytes, safe_decode


console = Console()


def main():
    parser = argparse.ArgumentParser(description="S19 Patcher and Viewer Tool")
    parser.add_argument("file", help="Path to .s19 file")
    subparsers = parser.add_subparsers(dest="command")

    # info
    subparsers.add_parser("info", help="Show general file info")

    # layout
    subparsers.add_parser("layout", help="Show memory layout (ranges + gaps)")

    # ranges
    subparsers.add_parser("ranges", help="Show memory ranges")

    # gaps
    subparsers.add_parser("gaps", help="Show memory gaps")

    # version
    subparsers.add_parser("version", help="Show tool version")

    #verify
    subparsers.add_parser("verify", help="Verify checksums of all records")

    #update-checksums (Not expected to be used but rather haveit as a safety net)
    subparsers.add_parser("update-checksums", help="Force re-calculation of checksums for all records")

    # dump
    dump_parser = subparsers.add_parser("dump", help="Visualize memory window")
    dump_parser.add_argument("--start", type=lambda x: int(x, 0), required=True)
    dump_parser.add_argument("--length", type=int, default=64)

    # dump-by-range
    dump_range_parser = subparsers.add_parser("dump-by-range", help="Visualize memory grouped by used ranges")
    dump_range_parser.add_argument("--output", type=str, help="Optional path to save the memory dump")

    # dump-all
    subparsers.add_parser("dump-all", help="Visualize entire memory")

    # patch-str
    patch_parser = subparsers.add_parser("patch-str", help="Patch a string into memory")
    patch_parser.add_argument("--addr", type=lambda x: int(x, 0), required=True)
    patch_parser.add_argument("--text", type=str, required=True)
    patch_parser.add_argument("--encoding", type=str, default='ascii')

    #patch-hex
    patch_hex_parser = subparsers.add_parser("patch-hex", help="Patch raw hex bytes into memory")
    patch_hex_parser.add_argument("--addr", type=lambda x: int(x, 0), required=True, help="Start memory address")
    patch_hex_parser.add_argument("--bytes", required=True, help="Hex byte values, space-separated (e.g., '01 02 FF')")
    patch_hex_parser.add_argument("--save-as", type=str, help="Optional output file for saving patched result")

    # save
    save_parser = subparsers.add_parser("save", help="Export patched S19 file")
    save_parser.add_argument("--output", type=str, required=True)

    # save-as
    patch_parser.add_argument("--save-as", type=str, help="Optional output path to save the patched file immediately")

    args = parser.parse_args()
    s19 = S19File(args.file)

    if args.command == "info":
        console.print(f"[bold cyan]File:[/bold cyan] {args.file}")
        console.print(f"[bold cyan]Endian:[/bold cyan] {s19.endian}")
        console.print(f"[bold cyan]Valid records:[/bold cyan] {sum(r.valid for r in s19.records)}")
        console.print(f"[bold cyan]Header:[/bold cyan] (see below)")
        s19.print_header()

    elif args.command == "layout":
        s19.show_memory_layout()

    elif args.command == "ranges":
        s19.show_memory_ranges()

    elif args.command == "gaps":
        s19.show_memory_gaps()

    elif args.command == "dump":
        s19.visualize_memory(start=args.start, length=args.length)

    elif args.command == "dump-all":
        s19.visualize_all()

    elif args.command == "patch-str":
        try:
            s19.set_string_at(address=args.addr, text=args.text, encoding=args.encoding)
            console.print(f"[green]Patched string '{args.text}' at 0x{args.addr:08X}[/green]")

            if args.save_as:
                with open(args.save_as, 'w', encoding='utf-8') as f:
                    for record in s19.records:
                        f.write(str(record) + '\n')
                console.print(f"[cyan]Saved modified file to: {args.save_as}[/cyan]")

        except ValueError as e:
            console.print(f"[red]Error:[/red] {str(e)}")

    elif args.command == "save":
        with open(args.output, 'w', encoding='utf-8') as f:
            for record in s19.records:
                f.write(str(record) + '\n')
        console.print(f"[bold green]Saved modified file to:[/bold green] {args.output}")
    
    elif args.command == "version":
        console.print(f"[bold cyan]S19Tool version:[/bold cyan] {__version__}")

    elif args.command == "verify":
        failed = []
        for i, record in enumerate(s19.records):
            if not record._validate():
                failed.append((i, record))
        if not failed:
            console.print("[green]✅ All record checksums are valid.[/green]")
        else:
            console.print(f"[red]❌ {len(failed)} record(s) have invalid checksums:[/red]")
            for i, record in failed:
                console.print(f"  [yellow]Line {i + 1}[/yellow] at 0x{record.address:08X} — Type: {record.type}")
                for err in record.validation_errors:
                    console.print(f"    [red]- {err}[/red]")

    elif args.command == "update-checksums":
        for record in s19.records:
            record.checksum = record._calculate_checksum()
        console.print(f"[cyan]🔄 All checksums updated based on current data.[/cyan]")
    elif args.command == "dump-by-range":
        if args.output:
            with open(args.output, "w", encoding='utf-8') as f:
                s19.visualize_by_ranges(output_stream=f)
            console.print(f"[green]Memory dump saved to {args.output}[/green]")
        else:
            s19.visualize_by_ranges()
    
    elif args.command == "patch-hex":
        try:
            # Parse hex string into a list of integers
            hex_values = args.bytes.strip().split()
            byte_list = [int(h, 16) for h in hex_values]

            s19.set_bytes_at(args.addr, byte_list)
            console.print(f"[green]Patched {len(byte_list)} bytes at 0x{args.addr:08X}[/green]")

            if args.save_as:
                with open(args.save_as, "w", encoding="utf-8") as f:
                    for record in s19.records:
                        f.write(str(record) + "\n")
                console.print(f"[cyan]Saved modified file to: {args.save_as}[/cyan]")

        except ValueError as e:
            console.print(f"[red]Error:[/red] {str(e)}")

    else:
        parser.print_help()
        

if __name__ == "__main__":
    main()
