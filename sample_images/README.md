# Sample Disk Images

This directory contains a generator script that creates synthetic raw disk images
for testing and demonstration purposes.

## Generated Images

Run the generator:

```bash
python sample_images/generate_sample.py
```

This creates three image files:

### `demo_fat32.dd` — 2 MB FAT32 image

- MBR with one FAT32 partition (type 0x0B) starting at LBA 2048
- Valid FAT32 boot sector with volume label "EVIDENCE"
- File Allocation Table with cluster chains
- Root directory entries:
  - `REPORT.TXT` — active file, cluster 3
  - `EVIDENCE.BIN` — active file, clusters 4-5 (2-cluster chain)
  - `_OTES.TXT` — **deleted** (0xE5 marker), cluster 6 is free (recoverable)
  - `_ASSWD.TXT` — **deleted** (0xE5 marker), cluster 7 reallocated (overwritten)

### `demo_gpt.dd` — 1 MB GPT image

- Protective MBR at sector 0 (type 0xEE)
- Primary GPT header at LBA 1 with valid CRC32
- 128 partition entries (3 active):
  1. EFI System Partition (LBA 34–300)
  2. Microsoft Basic Data: "Windows Evidence" (LBA 301–1500)
  3. Linux Filesystem: "Linux Home" (LBA 1501–2014)
- Backup GPT header at last sector
- Backup partition entries before backup header

### `demo_ntfs.dd` — 4 MB NTFS image

- MBR with one NTFS partition (type 0x07) starting at LBA 2048
- Valid NTFS boot sector with `NTFS    ` OEM ID
- $MFT at cluster 4 (LBA 2080), 1024-byte records
- MFT records:
  - Records 0–4: `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef` (system)
  - Record 5: `.` (root directory)
  - Record 16: `report.txt` — active file with $STANDARD_INFORMATION, $FILE_NAME, $DATA
  - Record 17: `evidence.bin` — active file
  - Record 18: `notes.txt` — active file
  - Record 19: `suspects.txt` — **deleted** (in-use flag cleared)
  - Record 20: `passwords.db` — **deleted** (in-use flag cleared)

## Notes

These images do **not** need to mount — they are designed to parse correctly
with DiskForensics' binary parsers. The data structures are byte-accurate
representations of real filesystem layouts.

All binary structures are built with Python's `struct.pack` at exact byte offsets,
matching the specifications in the Microsoft FAT, NTFS, and GPT documentation.
