"""
Tests for MBR Parser.

Verifies parsing of the 512-byte Master Boot Record including:
- Partition table entries
- Boot signature validation
- GPT protective MBR detection
- CHS and LBA addressing
"""

import struct
import tempfile
import os
import unittest
from pathlib import Path

# Allow running from project root
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from diskforensics.image_reader import ImageReader
from diskforensics.mbr_parser import MBRParser, PartitionEntry
from sample_images.generate_sample import create_fat32_image, create_gpt_image


class TestMBRParserWithSyntheticImage(unittest.TestCase):
    """Test MBR parsing against a synthesized FAT32 disk image."""

    @classmethod
    def setUpClass(cls):
        """Create a temporary FAT32 image for all tests."""
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_fat32.dd")
        create_fat32_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = MBRParser(cls.reader)
        cls.result = cls.parser.parse()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_valid_boot_signature(self):
        """MBR must end with 0x55AA."""
        self.assertTrue(self.result.valid_signature, "Boot signature should be 0x55AA")

    def test_partition_count(self):
        """FAT32 image should have exactly 1 active partition."""
        self.assertEqual(len(self.result.active_partitions), 1)

    def test_partition_type(self):
        """Partition should be FAT32 type (0x0B)."""
        p = self.result.active_partitions[0]
        self.assertEqual(p.partition_type, 0x0B)

    def test_partition_lba_start(self):
        """Partition should start at LBA 2048."""
        p = self.result.active_partitions[0]
        self.assertEqual(p.lba_start, 2048)

    def test_partition_sector_count(self):
        """Partition sector count should be IMAGE_SECTORS - 2048."""
        p = self.result.active_partitions[0]
        self.assertGreater(p.sector_count, 0)
        self.assertEqual(p.lba_start + p.sector_count, 4096)

    def test_partition_is_bootable(self):
        """Partition should be flagged as bootable."""
        p = self.result.active_partitions[0]
        self.assertTrue(p.is_bootable)

    def test_partition_type_name(self):
        """Partition type name should mention FAT32."""
        p = self.result.active_partitions[0]
        self.assertIn("FAT32", p.type_name)

    def test_partition_size_bytes(self):
        """Partition size in bytes should be sector_count * 512."""
        p = self.result.active_partitions[0]
        self.assertEqual(p.size_bytes, p.sector_count * 512)

    def test_lba_end(self):
        """LBA end should be start + count - 1."""
        p = self.result.active_partitions[0]
        self.assertEqual(p.lba_end, p.lba_start + p.sector_count - 1)

    def test_has_gpt_false(self):
        """FAT32 MBR should not indicate GPT."""
        self.assertFalse(self.result.has_gpt)

    def test_empty_partition_entries(self):
        """Entries 2-4 should be empty."""
        empty_count = sum(1 for p in self.result.partitions if p.is_empty)
        self.assertEqual(empty_count, 3)

    def test_to_dict_structure(self):
        """to_dict should return a valid dict with expected keys."""
        d = self.result.to_dict()
        self.assertIn("valid_signature", d)
        self.assertIn("partitions", d)
        self.assertIn("has_gpt", d)
        self.assertTrue(d["valid_signature"])
        self.assertEqual(len(d["partitions"]), 1)


class TestGPTProtectiveMBR(unittest.TestCase):
    """Test MBR detection of GPT protective entry."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.image_path = os.path.join(cls.tmpdir, "test_gpt.dd")
        create_gpt_image(cls.image_path)
        cls.reader = ImageReader(cls.image_path)
        cls.parser = MBRParser(cls.reader)
        cls.result = cls.parser.parse()

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_valid_signature(self):
        self.assertTrue(self.result.valid_signature)

    def test_gpt_detected(self):
        """GPT protective MBR should set has_gpt=True."""
        self.assertTrue(self.result.has_gpt)

    def test_gpt_protective_partition_type(self):
        """First partition should be type 0xEE (GPT protective)."""
        active = self.result.active_partitions
        self.assertGreater(len(active), 0)
        gpt_parts = [p for p in active if p.partition_type == 0xEE]
        self.assertGreater(len(gpt_parts), 0)


class TestMBRParserInvalidImage(unittest.TestCase):
    """Test MBR parser behavior with a minimal/invalid image."""

    def test_invalid_signature(self):
        """Image with wrong signature should report invalid."""
        with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
            # Write 512 bytes with no 0x55AA signature
            f.write(b"\x00" * 512)
            path = f.name
        try:
            reader = ImageReader(path)
            parser = MBRParser(reader)
            result = parser.parse()
            self.assertFalse(result.valid_signature)
            reader.close()
        finally:
            os.unlink(path)

    def test_all_empty_partitions(self):
        """An all-zeros MBR should have no active partitions."""
        with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
            f.write(b"\x00" * 1024)
            path = f.name
        try:
            reader = ImageReader(path)
            parser = MBRParser(reader)
            result = parser.parse()
            self.assertEqual(len(result.active_partitions), 0)
            reader.close()
        finally:
            os.unlink(path)


class TestPartitionEntry(unittest.TestCase):
    """Unit tests for PartitionEntry properties."""

    def _make_entry(self, boot, ptype, lba_start, sector_count, index=0):
        """Helper to create a PartitionEntry directly."""
        return PartitionEntry(
            index=index,
            boot_indicator=0x80 if boot else 0x00,
            chs_first="0/0/1",
            partition_type=ptype,
            chs_last="10/255/63",
            lba_start=lba_start,
            sector_count=sector_count,
        )

    def test_is_bootable(self):
        e = self._make_entry(True, 0x0B, 2048, 4096)
        self.assertTrue(e.is_bootable)

    def test_is_not_bootable(self):
        e = self._make_entry(False, 0x07, 2048, 4096)
        self.assertFalse(e.is_bootable)

    def test_is_empty(self):
        e = self._make_entry(False, 0x00, 0, 0)
        self.assertTrue(e.is_empty)

    def test_is_not_empty(self):
        e = self._make_entry(False, 0x07, 2048, 4096)
        self.assertFalse(e.is_empty)

    def test_is_extended(self):
        e = self._make_entry(False, 0x05, 2048, 4096)
        self.assertTrue(e.is_extended)

    def test_is_gpt_protective(self):
        e = self._make_entry(False, 0xEE, 1, 4095)
        self.assertTrue(e.is_gpt_protective)

    def test_lba_end(self):
        e = self._make_entry(False, 0x0B, 2048, 1024)
        self.assertEqual(e.lba_end, 2048 + 1024 - 1)

    def test_size_bytes(self):
        e = self._make_entry(False, 0x0B, 2048, 1024)
        self.assertEqual(e.size_bytes, 1024 * 512)

    def test_ntfs_type_name(self):
        e = self._make_entry(False, 0x07, 2048, 4096)
        self.assertIn("NTFS", e.type_name)

    def test_fat32_type_name(self):
        e = self._make_entry(False, 0x0B, 2048, 4096)
        self.assertIn("FAT32", e.type_name)

    def test_to_dict(self):
        e = self._make_entry(True, 0x0B, 2048, 4096)
        d = e.to_dict()
        self.assertEqual(d["index"], 1)
        self.assertTrue(d["bootable"])
        self.assertEqual(d["lba_start"], 2048)
        self.assertEqual(d["sector_count"], 4096)


if __name__ == "__main__":
    unittest.main()
