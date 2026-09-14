#!/usr/bin/env python3
"""Release checks reject mismatched, truncated, or non-plugin binary headers."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from package_plugin import package, verify_header


class PackageTests(unittest.TestCase):
    def macho(self, cpu=0x0100000C):
        return struct.pack('<8I', 0xFEEDFACF, cpu, 0, 6, 0, 0, 0, 0)

    def test_macho_platforms(self):
        for cpu, platform in [(0x0100000C, 'macos-arm64'), (0x01000007, 'macos-x86_64')]:
            verify_header(self.macho(cpu), platform)
        with self.assertRaises(ValueError):
            verify_header(self.macho(), 'macos-x86_64')

    def test_elf_platforms(self):
        for machine, platform in [(62, 'linux-x86_64'), (183, 'linux-arm64')]:
            data = bytearray(64)
            data[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', data, 16, 3, machine)
            verify_header(data, platform)
            struct.pack_into('<H', data, 16, 2)
            with self.assertRaises(ValueError):
                verify_header(data, platform)

    def test_pe_platforms(self):
        for machine, platform in [(0x8664, 'windows-x86_64'), (0xAA64, 'windows-arm64')]:
            data = bytearray(128)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<H', data, 68, machine)
            struct.pack_into('<H', data, 86, 0x2000)
            verify_header(data, platform)
            struct.pack_into('<I', data, 60, 0xFFFFFFFF)
            with self.assertRaises(ValueError):
                verify_header(data, platform)

    def test_empty_truncated_and_wrong_format(self):
        for platform in ['macos-arm64', 'linux-x86_64', 'windows-arm64']:
            for data in [b'', b'\x7fELF', b'not a plugin' * 8]:
                with self.assertRaises(ValueError):
                    verify_header(data, platform)

    def test_package_name_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = self.macho() + b'payload'
            (root / 'viy.dylib').write_bytes(content)
            output = package(root, 'macos-arm64', root / 'artifacts')
            self.assertEqual(output.name, 'viy_macos-arm64.dylib')
            self.assertEqual(output.read_bytes(), content)
            with self.assertRaises(ValueError):
                package(root, 'macos-x86_64', root / 'artifacts')
            self.assertFalse((root / 'artifacts/viy_macos-x86_64.dylib').exists())


if __name__ == '__main__':
    unittest.main()
