"""
DiskForensics CLI — Command-line interface for disk image analysis.

Usage:
    python -m diskforensics <command> [options]

Commands:
    analyze     Full analysis (partitions + filesystem summary + hashes)
    partitions  Show partition table (MBR or GPT)
    files       List files in a partition filesystem
    deleted     Show deleted file entries
    timeline    Generate forensic activity timeline
    hash        Compute forensic hashes of image and partitions
    report      Generate HTML/JSON forensic report
    demo        Run a full demonstration using synthetic disk images

Author: Edward Marez
License: MIT
"""

import argparse
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from .image_reader import ImageReader
from .mbr_parser import MBRParser
from .gpt_parser import GPTParser
from .fat32_parser import FAT32Parser
from .ntfs_parser import NTFSParser
from .file_recovery import FileRecovery
from .timeline_generator import TimelineGenerator
from .hash_engine import HashEngine
from .report_generator import ReportGenerator, ForensicReport
from .utils import format_bytes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_reader(image_path: str) -> ImageReader:
    """Open an ImageReader, exiting with an error on failure."""
    try:
        return ImageReader(image_path)
    except FileNotFoundError:
        print(f"[ERROR] Image file not found: {image_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {image_path}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


def _detect_partition_scheme(reader: ImageReader) -> tuple[str, object]:
    """
    Detect whether the image uses MBR or GPT partitioning.

    Returns:
        ('MBR', MBRResult) or ('GPT', GPTResult)
    """
    mbr_parser = MBRParser(reader)
    mbr_result = mbr_parser.parse()

    if mbr_result.has_gpt:
        gpt_parser = GPTParser(reader)
        gpt_result = gpt_parser.parse()
        return "GPT", gpt_result

    return "MBR", mbr_result


def _detect_filesystem(reader: ImageReader, lba_start: int) -> str:
    """
    Detect filesystem type at a partition start LBA.

    Returns 'FAT32', 'NTFS', or 'UNKNOWN'.
    """
    sector = reader.read_sector(lba_start)
    if len(sector) < 90:
        return "UNKNOWN"

    # Check NTFS OEM ID
    if b"NTFS    " in sector[3:11]:
        return "NTFS"

    # Check FAT32 filesystem type string
    fs_type = sector[82:90]
    if b"FAT32" in fs_type:
        return "FAT32"

    # Check FAT12/16
    fs_type_16 = sector[54:62]
    if b"FAT" in fs_type_16:
        return "FAT16"

    # Check boot signature
    if sector[510:512] == b"\x55\xAA":
        # Check bytes per sector field as sanity check
        bps = int.from_bytes(sector[11:13], "little")
        if bps in (512, 1024, 2048, 4096):
            spc = sector[13]
            num_fats = sector[16]
            if num_fats in (1, 2) and spc > 0:
                return "FAT32"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Command: analyze
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> None:
    """Full disk image analysis."""
    reader = _get_reader(args.image)
    print(f"\nDiskForensics — Analyzing: {reader.filename}")
    print(f"Image size: {format_bytes(reader.image_size)} ({reader.image_size:,} bytes)")
    print(f"Sectors:    {reader.sector_count:,} × {reader.sector_size} bytes")
    print()

    scheme, result = _detect_partition_scheme(reader)
    print(f"Partition Scheme: {scheme}")
    print()

    if scheme == "MBR":
        mbr_parser = MBRParser(reader)
        mbr_parser.print_summary(result)
        # Try to identify filesystems
        for p in result.active_partitions:
            fs_type = _detect_filesystem(reader, p.lba_start)
            print(f"  Partition {p.index + 1} — Detected filesystem: {fs_type}")
            if fs_type == "FAT32":
                fat_parser = FAT32Parser(reader, p.lba_start)
                fat_result = fat_parser.parse()
                if fat_result.valid and fat_result.boot_sector:
                    bs = fat_result.boot_sector
                    print(f"    Volume Label: {bs.volume_label or '(none)'}")
                    print(f"    Files: {len(fat_result.files)} active, {len(fat_result.deleted_files)} deleted")
            elif fs_type == "NTFS":
                ntfs_parser = NTFSParser(reader, p.lba_start)
                ntfs_result = ntfs_parser.parse(max_records=500)
                if ntfs_result.valid and ntfs_result.boot_sector:
                    print(f"    Total Sectors: {ntfs_result.boot_sector.total_sectors:,}")
                    print(f"    MFT Records: {len(ntfs_result.active_records)} active, {len(ntfs_result.deleted_records)} deleted")
        print()
    elif scheme == "GPT":
        gpt_parser = GPTParser(reader)
        gpt_parser.print_summary(result)


# ---------------------------------------------------------------------------
# Command: partitions
# ---------------------------------------------------------------------------

def cmd_partitions(args: argparse.Namespace) -> None:
    """Show partition table."""
    reader = _get_reader(args.image)
    scheme, result = _detect_partition_scheme(reader)

    if scheme == "MBR":
        mbr_parser = MBRParser(reader)
        mbr_parser.print_summary(result)
    else:
        gpt_parser = GPTParser(reader)
        gpt_parser.print_summary(result)


# ---------------------------------------------------------------------------
# Command: files
# ---------------------------------------------------------------------------

def cmd_files(args: argparse.Namespace) -> None:
    """List files in a specific partition."""
    reader = _get_reader(args.image)
    partition_index = args.partition - 1

    # Get partition LBA
    lba_start = _get_partition_lba(reader, partition_index, args)
    if lba_start is None:
        return

    fs_type = _detect_filesystem(reader, lba_start)
    print(f"Filesystem: {fs_type} (partition {args.partition}, LBA {lba_start})")
    print()

    if fs_type == "FAT32":
        parser = FAT32Parser(reader, lba_start)
        parser.print_summary()
    elif fs_type == "NTFS":
        parser = NTFSParser(reader, lba_start)
        parser.print_summary()
    else:
        print(f"[WARN] Filesystem type '{fs_type}' is not directly parseable by DiskForensics.")
        print("       Supported: FAT32, NTFS")


# ---------------------------------------------------------------------------
# Command: deleted
# ---------------------------------------------------------------------------

def cmd_deleted(args: argparse.Namespace) -> None:
    """Show deleted file entries in a partition."""
    reader = _get_reader(args.image)
    partition_index = args.partition - 1
    lba_start = _get_partition_lba(reader, partition_index, args)
    if lba_start is None:
        return

    fs_type = _detect_filesystem(reader, lba_start)
    recovery = FileRecovery()

    if fs_type == "FAT32":
        parser = FAT32Parser(reader, lba_start)
        fat_result = parser.parse()
        result = recovery.recover_fat32(parser, fat_result)
        recovery.print_summary(result)
    elif fs_type == "NTFS":
        parser = NTFSParser(reader, lba_start)
        ntfs_result = parser.parse(max_records=10000)
        result = recovery.recover_ntfs(ntfs_result)
        recovery.print_summary(result)
    else:
        print(f"[WARN] Unsupported filesystem type: {fs_type}")


# ---------------------------------------------------------------------------
# Command: timeline
# ---------------------------------------------------------------------------

def cmd_timeline(args: argparse.Namespace) -> None:
    """Generate forensic activity timeline."""
    reader = _get_reader(args.image)

    start_date: Optional[date] = None
    end_date: Optional[date] = None

    if args.start:
        try:
            start_date = date.fromisoformat(args.start)
        except ValueError:
            print(f"[ERROR] Invalid start date format: {args.start}. Use YYYY-MM-DD.", file=sys.stderr)
            sys.exit(1)

    if args.end:
        try:
            end_date = date.fromisoformat(args.end)
        except ValueError:
            print(f"[ERROR] Invalid end date format: {args.end}. Use YYYY-MM-DD.", file=sys.stderr)
            sys.exit(1)

    gen = TimelineGenerator()
    scheme, part_result = _detect_partition_scheme(reader)

    # Collect timeline events from all partitions
    partitions = []
    if scheme == "MBR":
        partitions = [(p.index + 1, p.lba_start) for p in part_result.active_partitions]
    elif scheme == "GPT" and part_result.header:
        partitions = [(p.index + 1, p.lba_start) for p in part_result.active_partitions]

    for idx, lba_start in partitions:
        fs_type = _detect_filesystem(reader, lba_start)
        if fs_type == "FAT32":
            fat_parser = FAT32Parser(reader, lba_start)
            fat_result = fat_parser.parse()
            if fat_result.valid:
                gen.add_fat32_result(fat_result)
        elif fs_type == "NTFS":
            ntfs_parser = NTFSParser(reader, lba_start)
            ntfs_result = ntfs_parser.parse(max_records=5000)
            if ntfs_result.valid:
                gen.add_ntfs_result(ntfs_result)

    timeline = gen.build(start_date=start_date, end_date=end_date, filesystem=scheme)
    print(timeline.to_text())

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(timeline.to_csv())
        print(f"\nTimeline CSV saved to: {out_path}")


# ---------------------------------------------------------------------------
# Command: hash
# ---------------------------------------------------------------------------

def cmd_hash(args: argparse.Namespace) -> None:
    """Compute forensic hashes of the disk image."""
    reader = _get_reader(args.image)
    engine = HashEngine(reader)

    algorithms = ["md5", "sha1", "sha256"]

    print(f"\nComputing hashes for: {reader.filename}")
    print(f"Size: {format_bytes(reader.image_size)}")
    print()

    report = engine.hash_image(algorithms=algorithms)

    # Also hash partitions if present
    scheme, part_result = _detect_partition_scheme(reader)
    if scheme == "MBR" and part_result.active_partitions:
        engine.hash_partitions(part_result.active_partitions, report, algorithms=["sha256"])

    report.print_summary()


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> None:
    """Generate a full forensic report."""
    reader = _get_reader(args.image)
    fmt = args.format.lower()
    output_dir = args.output or "./forensic_report"

    print(f"\nGenerating {fmt.upper()} report for: {reader.filename}")
    print(f"Output directory: {output_dir}")

    fr = ForensicReport(str(reader.image_path), reader.image_size)

    # Hashes
    engine = HashEngine(reader)
    fr.hash_report = engine.hash_image(algorithms=["md5", "sha256"])

    # Partition table
    scheme, part_result = _detect_partition_scheme(reader)
    fr.partition_scheme = scheme

    if scheme == "MBR":
        fr.mbr_result = part_result
        partitions = part_result.active_partitions
    elif scheme == "GPT":
        fr.gpt_result = part_result
        partitions = part_result.active_partitions if part_result.header else []
    else:
        partitions = []

    # Filesystems
    recovery = FileRecovery()
    gen = TimelineGenerator()

    for p in partitions:
        lba_start = p.lba_start
        fs_type = _detect_filesystem(reader, lba_start)

        if fs_type == "FAT32":
            fat_parser = FAT32Parser(reader, lba_start)
            fat_result = fat_parser.parse()
            if fat_result.valid:
                fr.fat32_result = fat_result
                gen.add_fat32_result(fat_result)
                rec = recovery.recover_fat32(fat_parser, fat_result)
                fr.recovery_results.append(rec)
                # Partition hashes
                if scheme == "MBR":
                    engine.hash_partitions([p], fr.hash_report, algorithms=["sha256"])

        elif fs_type == "NTFS":
            ntfs_parser = NTFSParser(reader, lba_start)
            ntfs_result = ntfs_parser.parse(max_records=5000)
            if ntfs_result.valid:
                fr.ntfs_result = ntfs_result
                gen.add_ntfs_result(ntfs_result)
                rec = recovery.recover_ntfs(ntfs_result)
                fr.recovery_results.append(rec)

    fr.timeline = gen.build(filesystem=scheme)

    rgen = ReportGenerator()
    formats = [fmt] if fmt != "both" else ["html", "json"]
    if fmt == "all":
        formats = ["html", "json"]

    paths = rgen.save_all(fr, output_dir, formats=formats)

    print(f"\nReport generated:")
    for fmt_name, path in paths.items():
        print(f"  {fmt_name.upper()}: {path}")


# ---------------------------------------------------------------------------
# Command: demo
# ---------------------------------------------------------------------------

def cmd_demo(args: argparse.Namespace) -> None:
    """Run a demonstration using synthetic disk images."""
    try:
        from sample_images.generate_sample import (
            create_fat32_image,
            create_gpt_image,
            create_ntfs_image,
        )
        sample_dir = Path("sample_images")
    except ImportError:
        # Try relative import
        import importlib.util
        script_dir = Path(__file__).parent.parent / "sample_images"
        spec = importlib.util.spec_from_file_location(
            "generate_sample", script_dir / "generate_sample.py"
        )
        if spec is None:
            print("[ERROR] Cannot find sample_images/generate_sample.py", file=sys.stderr)
            print("        Run from the DiskForensics project directory.", file=sys.stderr)
            sys.exit(1)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        create_fat32_image = mod.create_fat32_image
        create_gpt_image = mod.create_gpt_image
        create_ntfs_image = mod.create_ntfs_image
        sample_dir = script_dir

    print("=" * 70)
    print("DiskForensics DEMO — Synthetic Disk Image Analysis")
    print("=" * 70)

    # --- FAT32 Demo ---
    fat32_path = str(sample_dir / "demo_fat32.dd")
    print(f"\n[1/3] Creating FAT32 demo image: {fat32_path}")
    create_fat32_image(fat32_path)

    reader = ImageReader(fat32_path)
    print(f"      Image: {format_bytes(reader.image_size)}, {reader.sector_count} sectors")

    print("\n--- MBR Partition Table ---")
    mbr_parser = MBRParser(reader)
    mbr_result = mbr_parser.parse()
    mbr_parser.print_summary(mbr_result)

    for p in mbr_result.active_partitions:
        print(f"--- FAT32 Filesystem (Partition {p.index+1}) ---")
        fat_parser = FAT32Parser(reader, p.lba_start)
        fat_result = fat_parser.parse()
        fat_parser.print_summary(fat_result)

        print("--- Deleted File Recovery ---")
        recovery = FileRecovery()
        rec_result = recovery.recover_fat32(fat_parser, fat_result)
        recovery.print_summary(rec_result)

    print("--- Forensic Hashes ---")
    engine = HashEngine(reader)
    hash_report = engine.hash_image(algorithms=["md5", "sha256"])
    engine.hash_partitions(mbr_result.active_partitions, hash_report, algorithms=["sha256"])
    hash_report.print_summary()

    print("--- Timeline ---")
    gen = TimelineGenerator()
    for p in mbr_result.active_partitions:
        fat_parser = FAT32Parser(reader, p.lba_start)
        fat_result = fat_parser.parse()
        gen.add_fat32_result(fat_result)
    timeline = gen.build(filesystem="FAT32")
    print(timeline.to_text())
    reader.close()

    # --- GPT Demo ---
    gpt_path = str(sample_dir / "demo_gpt.dd")
    print(f"\n[2/3] Creating GPT demo image: {gpt_path}")
    create_gpt_image(gpt_path)

    reader = ImageReader(gpt_path)
    print(f"      Image: {format_bytes(reader.image_size)}, {reader.sector_count} sectors")

    print("\n--- GPT Partition Table ---")
    gpt_parser = GPTParser(reader)
    gpt_result = gpt_parser.parse()
    gpt_parser.print_summary(gpt_result)
    reader.close()

    # --- NTFS Demo ---
    ntfs_path = str(sample_dir / "demo_ntfs.dd")
    print(f"\n[3/3] Creating NTFS demo image: {ntfs_path}")
    create_ntfs_image(ntfs_path)

    reader = ImageReader(ntfs_path)
    print(f"      Image: {format_bytes(reader.image_size)}, {reader.sector_count} sectors")

    print("\n--- MBR Partition Table ---")
    mbr_parser = MBRParser(reader)
    mbr_result = mbr_parser.parse()
    mbr_parser.print_summary(mbr_result)

    for p in mbr_result.active_partitions:
        print(f"--- NTFS Filesystem (Partition {p.index+1}) ---")
        ntfs_parser = NTFSParser(reader, p.lba_start)
        ntfs_result = ntfs_parser.parse()
        ntfs_parser.print_summary(ntfs_result)

        print("--- NTFS Deleted File Recovery ---")
        recovery = FileRecovery()
        rec_result = recovery.recover_ntfs(ntfs_result)
        recovery.print_summary(rec_result)

        print("--- Timeline ---")
        gen = TimelineGenerator()
        gen.add_ntfs_result(ntfs_result)
        timeline = gen.build(filesystem="NTFS")
        print(timeline.to_text())

    reader.close()

    print("\n" + "=" * 70)
    print("Demo complete. Sample images saved to:", str(sample_dir))
    print("=" * 70)


# ---------------------------------------------------------------------------
# Utility: get partition LBA
# ---------------------------------------------------------------------------

def _get_partition_lba(
    reader: ImageReader, partition_index: int, args: argparse.Namespace
) -> Optional[int]:
    """
    Resolve partition index to LBA start address.

    Returns LBA or None on error.
    """
    scheme, result = _detect_partition_scheme(reader)

    if scheme == "MBR":
        active = result.active_partitions
        if partition_index < 0 or partition_index >= len(active):
            print(
                f"[ERROR] Partition {partition_index + 1} not found. "
                f"Available: 1-{len(active)}", file=sys.stderr
            )
            return None
        return active[partition_index].lba_start

    elif scheme == "GPT":
        active = result.active_partitions
        if partition_index < 0 or partition_index >= len(active):
            print(
                f"[ERROR] Partition {partition_index + 1} not found. "
                f"Available: 1-{len(active)}", file=sys.stderr
            )
            return None
        return active[partition_index].lba_start

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diskforensics",
        description="DiskForensics — Disk image analysis tool for forensic investigations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m diskforensics demo
  python -m diskforensics analyze --image evidence.dd
  python -m diskforensics partitions --image evidence.dd
  python -m diskforensics files --image evidence.dd --partition 1
  python -m diskforensics deleted --image evidence.dd --partition 1
  python -m diskforensics timeline --image evidence.dd --start 2026-01-01 --end 2026-03-31
  python -m diskforensics hash --image evidence.dd
  python -m diskforensics report --image evidence.dd --format html --output ./report/
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Full analysis: partitions + filesystem + hashes")
    p_analyze.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file (.dd/.raw)")
    p_analyze.set_defaults(func=cmd_analyze)

    # partitions
    p_part = subparsers.add_parser("partitions", help="Show partition table (MBR or GPT)")
    p_part.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_part.set_defaults(func=cmd_partitions)

    # files
    p_files = subparsers.add_parser("files", help="List files in a partition filesystem")
    p_files.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_files.add_argument("--partition", type=int, default=1, metavar="N", help="Partition number (default: 1)")
    p_files.set_defaults(func=cmd_files)

    # deleted
    p_deleted = subparsers.add_parser("deleted", help="Detect and analyze deleted file entries")
    p_deleted.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_deleted.add_argument("--partition", type=int, default=1, metavar="N", help="Partition number (default: 1)")
    p_deleted.set_defaults(func=cmd_deleted)

    # timeline
    p_timeline = subparsers.add_parser("timeline", help="Generate forensic activity timeline")
    p_timeline.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_timeline.add_argument("--start", metavar="YYYY-MM-DD", help="Start date filter")
    p_timeline.add_argument("--end", metavar="YYYY-MM-DD", help="End date filter")
    p_timeline.add_argument("--output", metavar="FILE", help="Save timeline to CSV file")
    p_timeline.set_defaults(func=cmd_timeline)

    # hash
    p_hash = subparsers.add_parser("hash", help="Compute forensic hashes (MD5, SHA-1, SHA-256)")
    p_hash.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_hash.set_defaults(func=cmd_hash)

    # report
    p_report = subparsers.add_parser("report", help="Generate HTML/JSON forensic report")
    p_report.add_argument("--image", required=True, metavar="PATH", help="Path to disk image file")
    p_report.add_argument(
        "--format", default="html", choices=["html", "json", "all"],
        help="Output format (default: html)"
    )
    p_report.add_argument("--output", metavar="DIR", default="./forensic_report", help="Output directory")
    p_report.set_defaults(func=cmd_report)

    # demo
    p_demo = subparsers.add_parser("demo", help="Run demo with synthetic disk images")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[Interrupted]", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
