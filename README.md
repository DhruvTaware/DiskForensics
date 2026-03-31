# DiskForensics

**A professional disk image analysis tool for digital forensic investigations.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

DiskForensics parses raw disk images at the byte level — reading MBR and GPT
partition tables, FAT32 and NTFS filesystem metadata, recovering deleted files,
generating forensic timelines, and producing investigation-ready reports.

This is what tools like **Autopsy**, **FTK (Forensic Toolkit)**, and **EnCase**
do under the hood. DiskForensics is a ground-up Python implementation using only
the `struct` module for binary parsing, with zero native code dependencies.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Forensics Fundamentals](#forensics-fundamentals)
  - [MBR vs GPT](#mbr-vs-gpt)
  - [FAT32 vs NTFS](#fat32-vs-ntfs)
  - [How Deleted File Recovery Works](#how-deleted-file-recovery-works)
  - [Forensic Timeline Analysis](#forensic-timeline-analysis)
  - [Evidence Integrity and Forensic Imaging](#evidence-integrity-and-forensic-imaging)
- [Architecture](#architecture)
- [Sample Output](#sample-output)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Industry Context](#industry-context)

---

## Features

| Capability | Details |
|---|---|
| **Disk Parsing** | Raw/dd image files; MBR (4-entry partition table) and GPT (128-entry, CRC-verified) |
| **FAT32 Analysis** | Boot sector (BPB), File Allocation Table, directory entries, Long Filename (LFN) support |
| **NTFS Analysis** | Boot sector, MFT records, `$STANDARD_INFORMATION` (0x10), `$FILE_NAME` (0x30), `$DATA` (0x80) |
| **File Recovery** | Detects deleted FAT32 entries (0xE5 marker) and NTFS entries (not-in-use flag); assesses data recoverability |
| **Timeline** | Collects all MAC timestamps (Modified/Accessed/Created) from all filesystem sources; outputs CSV or text |
| **Hashing** | MD5, SHA-1, SHA-256, SHA-512 for full images and individual partitions |
| **Reports** | HTML (dark-theme, table-rich) and JSON forensic reports |
| **Pure Python** | Only stdlib + `jinja2` for HTML templates; no C extensions, no OS dependencies |

---

## Quick Start

### Installation

```bash
git clone https://github.com/edwardmarez/diskforensics
cd diskforensics
pip install -r requirements.txt
pip install -e .
```

### Run the Demo

```bash
python -m diskforensics demo
```

This generates three synthetic disk images and runs a full forensic analysis on each,
demonstrating every capability of the tool.

### Analyze a Real Image

```bash
# Acquire image with dd (Linux/macOS)
sudo dd if=/dev/sdb of=evidence.dd bs=4M status=progress

# Or use dcfldd for hashing on-the-fly
sudo dcfldd if=/dev/sdb of=evidence.dd hash=sha256 hashlog=evidence.sha256

# Then analyze with DiskForensics
python -m diskforensics analyze --image evidence.dd
python -m diskforensics report --image evidence.dd --format html --output ./report/
```

---

## CLI Reference

### `analyze` — Full disk analysis

```bash
python -m diskforensics analyze --image evidence.dd
```

Performs a complete examination: detects partition scheme, identifies filesystem
types in each partition, summarizes file counts, and reports detected deletion.

### `partitions` — Partition table

```bash
python -m diskforensics partitions --image evidence.dd
```

Displays the MBR or GPT partition table with LBA ranges, partition types,
sizes, and (for GPT) type GUIDs and partition names.

### `files` — Filesystem contents

```bash
python -m diskforensics files --image evidence.dd --partition 1
```

Lists all files in the specified partition's filesystem (FAT32 or NTFS),
including timestamps, file sizes, and cluster/MFT record numbers.

### `deleted` — Deleted file recovery

```bash
python -m diskforensics deleted --image evidence.dd --partition 1
```

Scans for deleted directory entries (FAT32: 0xE5 marker; NTFS: not-in-use MFT flag).
Reports each deleted file with recovery assessment: whether the original data clusters
are still free (FAT32) or MFT attributes are intact (NTFS).

### `timeline` — Forensic activity timeline

```bash
python -m diskforensics timeline --image evidence.dd
python -m diskforensics timeline --image evidence.dd --start 2026-01-01 --end 2026-03-31
python -m diskforensics timeline --image evidence.dd --output timeline.csv
```

Generates a chronological timeline of all filesystem events (file created,
modified, accessed, deleted) from all partitions. Supports date-range filtering.

### `hash` — Forensic hashing

```bash
python -m diskforensics hash --image evidence.dd
```

Computes MD5, SHA-1, and SHA-256 hashes of the full disk image and each
detected partition. Reports throughput and computation time.

### `report` — Forensic report generation

```bash
python -m diskforensics report --image evidence.dd --format html --output ./report/
python -m diskforensics report --image evidence.dd --format json --output ./report/
python -m diskforensics report --image evidence.dd --format all --output ./report/
```

Generates a complete forensic report including all hashes, partition table,
filesystem contents, deleted file recovery, and timeline.

### `demo` — Built-in demonstration

```bash
python -m diskforensics demo
```

Creates three synthetic disk images and runs full analysis on each:
- `demo_fat32.dd` — 2 MB FAT32 image with active and deleted files
- `demo_gpt.dd` — 1 MB GPT image with EFI, Windows, and Linux partitions
- `demo_ntfs.dd` — 4 MB NTFS image with MFT records including deleted entries

---

## Forensics Fundamentals

### MBR vs GPT

**Master Boot Record (MBR)** — the original partitioning scheme, used since
IBM PC-DOS in the early 1980s. Sector 0 of the disk contains:

- **Bootstrap code** (446 bytes): x86 machine code executed by BIOS
- **Partition table** (64 bytes): 4 entries × 16 bytes, each describing one partition
- **Boot signature** (2 bytes): `0x55 0xAA` — a sanity check for the BIOS

Each partition entry encodes:
- Boot indicator: `0x80` = bootable, `0x00` = not
- CHS addresses: Cylinder/Head/Sector of first and last sector (limited to 1023/255/63)
- Partition type byte: identifies filesystem (`0x07` = NTFS, `0x0B/0x0C` = FAT32, `0x83` = Linux)
- LBA addresses: 32-bit values allowing up to 2 TB on 512-byte sector disks
- Sector count: number of sectors in the partition

MBR limitations: maximum 4 primary partitions, maximum 2 TB disk size (with 512-byte sectors).

**GUID Partition Table (GPT)** — the modern replacement, part of the UEFI specification.

- **Protective MBR** (sector 0): a fake MBR with a single type-`0xEE` entry covering the entire
  disk, preventing MBR-unaware tools from overwriting the GPT
- **Primary GPT Header** (LBA 1): 92-byte header with `EFI PART` signature, disk GUID,
  CRC32 checksums, and pointers to the partition entry array
- **Partition Entry Array** (LBA 2–33): up to 128 entries × 128 bytes each
- **Backup GPT Header** (last sector): duplicate of primary header for redundancy

Each GPT partition entry includes:
- Partition Type GUID: identifies the type (e.g., `C12A7328-...` = EFI System,
  `EBD0A0A2-...` = Microsoft Basic Data, `0FC63DAF-...` = Linux Filesystem)
- Unique Partition GUID: globally unique identifier for this specific partition
- Starting and Ending LBA: 64-bit values, supporting disks up to 9.4 ZB
- UTF-16LE partition name: up to 36 characters

**From a forensic standpoint**, the presence and integrity of both MBR/GPT structures
and their backup copies tells investigators whether data may have been deliberately
modified, and helps establish the disk's original layout.

---

### FAT32 vs NTFS

**FAT32 (File Allocation Table, 32-bit)**

Introduced with Windows 95 OSR2 in 1996. Widely used on removable media (USB drives,
SD cards) and embedded systems because of its simplicity and broad OS support.

Key structures:
- **Boot Sector (BPB)**: First sector of the partition. Contains geometry parameters:
  bytes per sector, sectors per cluster, reserved sectors, FAT count, root cluster number.
- **File Allocation Table**: An array of 32-bit cluster state values. Each entry describes
  one data cluster: `0x00000000` = free, `0x0FFFFFF8–0x0FFFFFFF` = end of chain,
  `0x0FFFFFF7` = bad cluster, or the next cluster number in a chain.
- **Directory Entries** (32 bytes each): Store 8.3 short filename, attributes (read-only,
  hidden, system, directory, archive), creation/modification/access timestamps,
  first cluster number, and file size.
- **Long Filename (LFN) Entries**: Preceding each 8.3 entry, one or more LFN entries
  (attribute `0x0F`) store the full Unicode filename in 13 UTF-16LE characters each.

FAT32 timestamps:
- Date packed into 16 bits: `[year-1980 : 7 bits][month : 4 bits][day : 5 bits]`
- Time packed into 16 bits: `[hour : 5 bits][minute : 6 bits][second/2 : 5 bits]`
- 2-second resolution for modification time; 10ms resolution for creation time via an extra byte

FAT32 limitations: maximum file size 4 GB – 1 byte, no built-in access control, no journaling.

**NTFS (New Technology File System)**

Introduced with Windows NT 3.1 in 1993. Used on all modern Windows systems and increasingly
on Linux (via ntfs-3g). Designed for enterprise reliability, security, and large volumes.

Key structures:
- **Boot Sector**: Contains `NTFS    ` OEM ID, geometry parameters, and the cluster offset
  of the `$MFT` (Master File Table).
- **$MFT (Master File Table)**: The heart of NTFS. Every file and directory is described
  by one or more MFT records (typically 1024 bytes each). The first 16 records are reserved
  for NTFS metadata files (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, etc.).
- **MFT Record**: Begins with `FILE` signature, then a series of attribute headers.
  The `Flags` field indicates if the record is in use (bit 0) and if it's a directory (bit 1).
- **$STANDARD_INFORMATION (0x10)**: Four 64-bit NTFS timestamps (100-nanosecond intervals
  since January 1, 1601) plus security flags. These are the timestamps Windows Explorer
  displays and are user-accessible (can be manipulated by anti-forensic tools).
- **$FILE_NAME (0x30)**: Filename in UTF-16LE plus parent directory MFT reference,
  allocated/real size, and four more timestamps. These timestamps are harder to manipulate
  because the OS updates them internally during rename/move operations.
- **$DATA (0x80)**: For small files, the data is stored directly in the MFT record (resident).
  For larger files, the attribute contains a data run list describing the cluster ranges
  on disk where the file data resides (non-resident).

NTFS timestamps: 100-nanosecond precision, UTC timezone, epoch January 1, 1601.
Converting to Unix time: subtract `116444736000000000` intervals (11644473600 seconds).

**Forensic significance of $SI vs $FN timestamps:**
A key anti-forensic technique called **timestomping** modifies `$STANDARD_INFORMATION`
timestamps to make a file appear older or unrelated to the crime window. However,
`$FILE_NAME` timestamps are updated by the NTFS driver at a different time and are
not accessible via standard Win32 API calls. Discrepancies between `$SI` and `$FN`
timestamps are a strong indicator of manipulation.

---

### How Deleted File Recovery Works

**FAT32 deletion:**

When a file is deleted in FAT32:
1. The first byte of its 8.3 directory entry is overwritten with `0xE5`
2. All FAT entries for the file's cluster chain are set to `0x00000000` (free)
3. The file data on disk is **not touched**

The `0xE5` marker means DiskForensics can still read the directory entry's
timestamps, file size, and the starting cluster number. The 8.3 name's first
character is lost (it becomes `_` in our output). The rest of the entry is intact.

Recovery probability:
- **High**: Starting cluster is still marked free in the FAT and file fits in one cluster.
  The data was never overwritten. A carver can read the sectors directly.
- **Medium**: File spans multiple clusters. First cluster is free, but FAT chain was
  cleared, so we only know the start. We can try to reconstruct by reading sequential
  clusters up to the known file size.
- **Low/Zero**: Starting cluster has been reallocated (FAT entry is non-zero). A new file
  has overwritten the original data. Metadata survives (timestamps, filename stub),
  but file content is gone unless recovered by carving data remnants.

**NTFS deletion:**

When a file is deleted in NTFS:
1. Bit 0 (In Use) of the MFT record's Flags field is cleared
2. The data runs are deallocated in `$Bitmap`
3. The MFT record itself remains on disk until it is reused for a new file

Because the `$STANDARD_INFORMATION` and `$FILE_NAME` attributes are preserved,
NTFS deletion recovery provides:
- Full original filename (no first-character loss)
- All four timestamps from both `$SI` and `$FN`
- Parent directory reference
- Last known file size

This is why NTFS forensics is so powerful: deleted file metadata is nearly always
recoverable unless the MFT record has been overused. Tools like Autopsy, FTK, and
EnCase exploit this exact mechanism to build lists of previously existing files.

---

### Forensic Timeline Analysis

A **forensic timeline** places all filesystem events in chronological order to help
investigators reconstruct what happened and when. DiskForensics collects:

| Event Type | Source | Description |
|---|---|---|
| `FILE_CREATED` | `$SI` / `$FN` / FAT create | When the file first appeared |
| `FILE_MODIFIED` | `$SI` / `$FN` / FAT modify | Last time file content was written |
| `FILE_ACCESSED` | `$SI` / FAT access | Last time file was read |
| `MFT_MODIFIED` | `$SI` only | When the MFT record itself was changed (metadata update) |
| `FILE_DELETED` | 0xE5 / not-in-use flag | Approximate deletion time (last-modified used as proxy) |

**Timeline analysis in practice:**

The timeline is most powerful when combined with other evidence:
- User login/logout times from Windows Event Logs
- Browser history timestamps
- Email timestamps
- System clock changes (look for sudden jumps)
- Periods of intense write activity (potential bulk deletion)

The **MACB** (Modified/Accessed/Changed/Birth) timestamp model is the standard
forensic framework for describing filesystem time evidence:

- **M** = `$DATA` was modified (content written)
- **A** = File was accessed (read)
- **C** = `$MFT` entry was changed (metadata updated, not necessarily content)
- **B** = File was Born (created)

In a normal file lifecycle, Birth ≤ Modified ≤ Accessed ≤ Changed.
Violations of this ordering (e.g., Modified time before Birth time) strongly
suggest timestamp manipulation.

---

### Evidence Integrity and Forensic Imaging

**Chain of custody** in digital forensics requires that every action taken on
evidence be documented and verifiable. For disk images:

1. **Acquisition**: The disk is imaged using a write blocker — a hardware or software
   device that prevents any writes to the evidence disk. `dd`, `dcfldd`, `FTK Imager`,
   and `Guymager` are common acquisition tools. The raw output is a `.dd` (raw) image.

2. **Hashing at acquisition**: Immediately after imaging, compute hash digests of the
   source disk and the resulting image. If they match, the image is a forensically sound
   copy. Common standards: MD5 + SHA-256 together.

3. **Working copies**: Never analyze the original image directly. Mount or analyze copies.
   The original's hash should be reverified at every step.

4. **Hash verification**: DiskForensics computes MD5, SHA-1, and SHA-256 of the full image
   and each partition. These values go directly into the forensic report as evidence
   of image integrity throughout the examination.

**Forensic image formats:**
- **Raw/DD**: Sector-for-sector copy, no metadata wrapper. What DiskForensics supports.
- **E01 (EnCase)**: Compressed, with built-in MD5 hash blocks every 64 sectors.
- **AFF (Advanced Forensic Format)**: Open format with metadata segments.

DiskForensics works with raw/DD images. To convert E01 to raw: `ewfexport image.E01`.

---

## Architecture

```
diskforensics/
├── image_reader.py      Sector-level I/O, range hashing, seeks by offset/LBA
├── mbr_parser.py        Sector 0: 4-entry partition table, boot signature, type names
├── gpt_parser.py        LBA 1: header + 128-entry partition array with CRC32 verification
├── fat32_parser.py      BPB, FAT chain traversal, 32-byte directory entries, LFN assembly
├── ntfs_parser.py       Boot sector, MFT sequential scan, attribute header walking
├── file_recovery.py     FAT32: 0xE5 entries + FAT cluster state; NTFS: not-in-use records
├── timeline_generator.py  MACB event collection, sort, date filtering, CSV/text export
├── hash_engine.py       Multi-algorithm streaming hash with timing + throughput reporting
├── report_generator.py  Jinja2 HTML + JSON serialization of all analysis results
├── utils.py             Timestamp conversions, GUID parsing, hex dump, partition type tables
└── main.py              argparse CLI: analyze, partitions, files, deleted, timeline, hash, report, demo
```

All parsers accept an `ImageReader` instance and a `partition_lba_start` offset,
making them composable: point any parser at any partition within any image.

---

## Sample Output

### MBR Partition Table

```
============================================================
MASTER BOOT RECORD ANALYSIS
============================================================
Image:           evidence.dd
Image Size:      2.0 MB
Boot Signature:  VALID (0x55AA)
GPT Protected:   No
Active Parts:    1

#   Boot   Type                                   LBA Start      LBA End         Size
-------------------------------------------------------------------------------------
1   Yes    FAT32 (0x0B)                               2,048        4,095       1.0 MB
```

### FAT32 Filesystem

```
======================================================================
FAT32 FILESYSTEM ANALYSIS
======================================================================
Volume Label:    EVIDENCE
FS Type:         FAT32
Bytes/Sector:    512
Cluster Size:    512.0 B
Total Sectors:   2,048

Active Files:    2
Deleted Files:   2

Name                                     Size Modified               Del?
--------------------------------------------------------------------------------
REPORT.TXT                             67.0 B 2026-01-10 09:30:00
EVIDENCE.BIN                          600.0 B 2026-02-14 14:00:00
_OTES.TXT                              50.0 B 2026-03-01 10:15:00    [DELETED]
_ASSWD.TXT                            256.0 B 2025-12-05 23:59:58    [DELETED]
```

### Deleted File Recovery

```
======================================================================
DELETED FILE RECOVERY — FAT32
======================================================================
Deleted entries found:   2
Likely recoverable:      1

Filename                                 Size   Modified               Recover?
-------------------------------------------------------------------------------------
_OTES.TXT*                             50.0 B   2026-03-01 10:15:00    YES
_ASSWD.TXT*                           256.0 B   2025-12-05 23:59:58    No

* = First character of filename is unknown (replaced with '_') in FAT32.
```

### Forensic Timeline

```
FORENSIC TIMELINE REPORT
================================================================================
Filesystem:   FAT32
Total Events: 14
Earliest:     2025-12-05 00:00:00
Latest:       2026-03-01 10:15:00

Timestamp              Event            FS     Del  Source                    Filename
-----------------------------------------------------------------------------------------------------------------------
2025-12-05 23:59:58    FILE_DELETED     FAT32  [D]  Directory Entry (0xE5)    /_ASSWD.TXT
2026-01-10 09:30:00    FILE_CREATED     FAT32       Directory Entry (create)  /REPORT.TXT
2026-01-10 09:30:00    FILE_MODIFIED    FAT32       Directory Entry (modify)  /REPORT.TXT
2026-02-14 14:00:00    FILE_CREATED     FAT32       Directory Entry (create)  /EVIDENCE.BIN
2026-03-01 10:15:00    FILE_DELETED     FAT32  [D]  Directory Entry (0xE5)    /_OTES.TXT
```

### Forensic Hash Report

```
======================================================================
FORENSIC HASH REPORT
======================================================================
Image:    evidence.dd
Size:     2.0 MB (2,097,152 bytes)

FULL IMAGE HASHES:
----------------------------------------------------------------------
  MD5        a05e868f9aff0cb24b38f12c4269fb20
  SHA256     c36f7038559310c56b4078403ff1129b6761c66ffed2b03e7817c2fd37be3048

PARTITION HASHES:
----------------------------------------------------------------------
  Partition 1 (FAT32, LBA 2048-4095)
  SHA256     7dae27b740800827f4fc52f14fb93ac0c93a03c39b19863306e85fda45cbca60
```

---

## Project Structure

```
DiskForensics/
├── diskforensics/
│   ├── __init__.py
│   ├── __main__.py            # python -m diskforensics entry point
│   ├── main.py                # CLI: analyze, partitions, files, deleted, timeline, hash, report, demo
│   ├── image_reader.py        # Raw disk image reader with sector-level access
│   ├── mbr_parser.py          # MBR partition table parser
│   ├── gpt_parser.py          # GPT header and partition entries parser
│   ├── fat32_parser.py        # FAT32 filesystem parser
│   ├── ntfs_parser.py         # NTFS filesystem parser (MFT records)
│   ├── file_recovery.py       # Deleted file detection and recoverability assessment
│   ├── timeline_generator.py  # Forensic MACB timeline generation
│   ├── hash_engine.py         # MD5/SHA-256/SHA-512 hashing with chain-of-custody output
│   ├── report_generator.py    # HTML and JSON forensic reports (Jinja2)
│   └── utils.py               # Timestamp conversions, GUID parsing, hex dump
├── sample_images/
│   ├── generate_sample.py     # Synthetic disk image generator (struct.pack only)
│   └── README.md
├── tests/
│   ├── test_mbr_parser.py     # 30 tests: MBR parsing, GPT detection, entry properties
│   ├── test_gpt_parser.py     # 28 tests: GPT header, CRC, partition entries
│   ├── test_fat32_parser.py   # 31 tests: boot sector, FAT chains, directory entries
│   ├── test_ntfs_parser.py    # 31 tests: boot sector, MFT records, timestamps, deletion
│   └── test_file_recovery.py  # 26 tests: FAT32 and NTFS recovery assessment
├── requirements.txt           # jinja2 only
├── setup.py
├── LICENSE                    # MIT
└── README.md
```

---

## Testing

```bash
# Run all 146 tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_fat32_parser.py -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=diskforensics --cov-report=term-missing
```

All tests use synthesized binary disk images created by `sample_images/generate_sample.py`.
No pre-built test fixtures are required — images are generated on-the-fly in temporary
directories and cleaned up after tests complete.

---

## Industry Context

DiskForensics implements the core byte-level parsing that powers commercial forensic suites:

| Tool | Organization | Notes |
|---|---|---|
| **Autopsy** | Basis Technology / open source | GUI frontend to The Sleuth Kit; industry standard for open-source forensics |
| **FTK (Forensic Toolkit)** | Exterro | Commercial; known for fast indexing and registry analysis |
| **EnCase** | OpenText | Long-running commercial standard; E01 image format originator |
| **X-Ways Forensics** | X-Ways | Lightweight and fast; preferred by many practitioners for low-level work |
| **The Sleuth Kit (TSK)** | Open source | C library providing the same parsing as DiskForensics but at C speed |

DiskForensics is designed for education, research, and Python-based forensic automation.
For production investigations on large (500 GB+) disk images, The Sleuth Kit or commercial
tools provide the necessary performance and evidentiary certification.

---

## License

MIT License — Copyright (c) 2026 Edward Marez

See [LICENSE](LICENSE) for full text.
