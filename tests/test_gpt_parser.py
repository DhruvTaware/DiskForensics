"""
Tests for GPT Parser.

Verifies parsing of the GUID Partition Table including:
- Header signature and revision
- Disk GUID
- Partition entries (type GUIDs, names, LBA ranges)
- CRC validation
- Backup header detection
"""

import tempfile
import os
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from diskforensics.image_reader import ImageReader
from diskforensics.gpt_parser import GPTParser, GPTPartitionEntry, GPTHeader
from sample_images.generate_sample import create_gpt_image


class TestGPTParserWithSyntheticImage(unittest.TestCase):
    """Test GPT parsing against a synthesized GPT disk image."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_gpt.dd")
        create_gpt_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = GPTParser(cls.reader)
        cls.result = cls.parser.parse()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_header_not_none(self):
        """GPT header should be found at LBA 1."""
        self.assertIsNotNone(self.result.header)

    def test_header_signature(self):
        """GPT header signature must be 'EFI PART'."""
        self.assertEqual(self.result.header.signature, b"EFI PART")
        self.assertTrue(self.result.header.is_valid_signature)

    def test_revision(self):
        """Revision should be 1.0."""
        self.assertEqual(self.result.header.revision_str, "1.0")

    def test_header_crc_valid(self):
        """Header CRC32 should be valid."""
        self.assertTrue(self.result.header_crc_valid)

    def test_partition_crc_valid(self):
        """Partition array CRC32 should be valid."""
        self.assertTrue(self.result.partition_crc_valid)

    def test_partition_count(self):
        """Should find 3 active partitions."""
        self.assertEqual(len(self.result.active_partitions), 3)

    def test_backup_header_present(self):
        """Backup GPT header should be detected."""
        self.assertTrue(self.result.has_backup_header)

    def test_my_lba(self):
        """My LBA should be 1 for primary GPT header."""
        self.assertEqual(self.result.header.my_lba, 1)

    def test_first_usable_lba(self):
        """First usable LBA should be after GPT header + entries (LBA 34)."""
        self.assertEqual(self.result.header.first_usable_lba, 34)

    def test_disk_guid_format(self):
        """Disk GUID should be in XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX format."""
        guid = self.result.header.disk_guid
        parts = guid.split("-")
        self.assertEqual(len(parts), 5)
        self.assertEqual(len(parts[0]), 8)
        self.assertEqual(len(parts[1]), 4)
        self.assertEqual(len(parts[2]), 4)
        self.assertEqual(len(parts[3]), 4)
        self.assertEqual(len(parts[4]), 12)

    def test_efi_partition_present(self):
        """EFI System Partition should be present."""
        active = self.result.active_partitions
        efi_parts = [
            p for p in active
            if "C12A7328" in p.type_guid.upper()
        ]
        self.assertEqual(len(efi_parts), 1)

    def test_efi_partition_name(self):
        """EFI partition should have correct name."""
        active = self.result.active_partitions
        efi = next(p for p in active if "C12A7328" in p.type_guid.upper())
        self.assertIn("EFI", efi.name)

    def test_windows_basic_data_partition(self):
        """Microsoft Basic Data partition should be present."""
        active = self.result.active_partitions
        mbd = [
            p for p in active
            if "EBD0A0A2" in p.type_guid.upper()
        ]
        self.assertEqual(len(mbd), 1)

    def test_windows_partition_name(self):
        """Windows partition should be named 'Windows Evidence'."""
        active = self.result.active_partitions
        mbd = next(p for p in active if "EBD0A0A2" in p.type_guid.upper())
        self.assertIn("Evidence", mbd.name)

    def test_linux_partition_present(self):
        """Linux Filesystem partition should be present."""
        active = self.result.active_partitions
        linux = [
            p for p in active
            if "0FC63DAF" in p.type_guid.upper()
        ]
        self.assertEqual(len(linux), 1)

    def test_partition_lba_ordering(self):
        """Partitions should be in LBA order."""
        active = self.result.active_partitions
        lba_starts = [p.lba_start for p in active]
        self.assertEqual(lba_starts, sorted(lba_starts))

    def test_partition_lba_ranges_non_overlapping(self):
        """Partition LBA ranges should not overlap."""
        active = sorted(self.result.active_partitions, key=lambda p: p.lba_start)
        for i in range(len(active) - 1):
            self.assertLessEqual(active[i].lba_end, active[i + 1].lba_start - 1)

    def test_sector_count(self):
        """Partition sector count should equal lba_end - lba_start + 1."""
        for p in self.result.active_partitions:
            expected = p.lba_end - p.lba_start + 1
            self.assertEqual(p.sector_count, expected)

    def test_to_dict(self):
        """to_dict should return all expected keys."""
        d = self.result.to_dict()
        self.assertIn("header", d)
        self.assertIn("partitions", d)
        self.assertIn("header_crc_valid", d)
        self.assertEqual(len(d["partitions"]), 3)


class TestGPTParserInvalidImage(unittest.TestCase):
    """Test GPT parser behavior on non-GPT images."""

    def test_non_gpt_image_returns_none_header(self):
        """A plain FAT32 MBR image should return no GPT header."""
        with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
            # 2 sectors of zeros (no GPT signature)
            f.write(b"\x00" * 1024)
            path = f.name
        try:
            reader = ImageReader(path)
            parser = GPTParser(reader)
            result = parser.parse()
            self.assertIsNone(result.header)
            self.assertEqual(len(result.active_partitions), 0)
            reader.close()
        finally:
            os.unlink(path)


class TestGPTPartitionEntry(unittest.TestCase):
    """Unit tests for GPTPartitionEntry properties."""

    def _make_entry(self, type_guid, name, lba_start, lba_end):
        return GPTPartitionEntry(
            index=0,
            type_guid=type_guid,
            unique_guid="A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
            lba_start=lba_start,
            lba_end=lba_end,
            attributes=0,
            name=name,
        )

    def test_empty_entry(self):
        e = self._make_entry("00000000-0000-0000-0000-000000000000", "", 0, 0)
        self.assertTrue(e.is_empty)

    def test_non_empty_entry(self):
        e = self._make_entry("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Data", 34, 1000)
        self.assertFalse(e.is_empty)

    def test_sector_count(self):
        e = self._make_entry("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Data", 34, 1033)
        self.assertEqual(e.sector_count, 1033 - 34 + 1)

    def test_size_bytes(self):
        e = self._make_entry("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Data", 34, 1033)
        self.assertEqual(e.size_bytes, e.sector_count * 512)

    def test_type_name_efi(self):
        e = self._make_entry("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI", 34, 300)
        self.assertIn("EFI", e.type_name)

    def test_type_name_windows(self):
        e = self._make_entry("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Win", 34, 1000)
        self.assertIn("Microsoft", e.type_name)

    def test_to_dict(self):
        e = self._make_entry("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Test", 34, 1000)
        d = e.to_dict()
        self.assertEqual(d["index"], 1)
        self.assertEqual(d["name"], "Test")
        self.assertEqual(d["lba_start"], 34)


if __name__ == "__main__":
    unittest.main()
