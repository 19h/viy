#!/usr/bin/env python3
"""Verify a native plugin's architecture before naming a release artifact."""
import argparse
from pathlib import Path
import shutil
import struct

from verify_windows_pe import MACHINES, PEImage

PLATFORMS = {
    'macos-x86_64': ('dylib', 0x01000007),
    'macos-arm64': ('dylib', 0x0100000C),
    'linux-x86_64': ('so', 62),
    'linux-arm64': ('so', 183),
    'windows-x86_64': ('dll', MACHINES['amd64']),
    'windows-arm64': ('dll', MACHINES['arm64']),
}


def verify_header(data, platform):
    extension, machine = PLATFORMS[platform]
    if extension == 'dylib':
        if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
            raise ValueError('expected a thin little-endian Mach-O 64-bit image')
        if struct.unpack_from('<I', data, 4)[0] != machine:
            raise ValueError('Mach-O CPU does not match artifact platform')
        if struct.unpack_from('<I', data, 12)[0] != 6:
            raise ValueError('expected a Mach-O dylib')
    elif extension == 'so':
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
            raise ValueError('expected a little-endian ELF64 image')
        kind, actual = struct.unpack_from('<HH', data, 16)
        if kind != 3 or actual != machine:
            raise ValueError('ELF type or machine does not match artifact platform')
    else:
        if len(data) < 64 or data[:2] != b'MZ':
            raise ValueError('expected a PE image')
        offset = struct.unpack_from('<I', data, 60)[0]
        if offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
            raise ValueError('invalid PE header offset/signature')
        if struct.unpack_from('<H', data, offset + 4)[0] != machine:
            raise ValueError('PE machine does not match artifact platform')
        if not struct.unpack_from('<H', data, offset + 22)[0] & 0x2000:
            raise ValueError('expected a PE DLL')


def package(build_dir, platform, output_dir):
    extension, _ = PLATFORMS[platform]
    source = build_dir / f'viy.{extension}'
    verify_header(source.read_bytes(), platform)
    if extension == 'dll':
        pe = PEImage(source)
        imports = pe.imports()
        if 'PLUGIN' not in pe.exports():
            raise ValueError('Windows plugin does not export PLUGIN')
        if ('ida.dll', 'find_reg_value_info') not in imports:
            raise ValueError('missing expected IDA 9.4 import find_reg_value_info')
        if ('ida.dll', 'reg_finder94_find_reg_value_info') in imports:
            raise ValueError('Windows plugin imports the post-patch IDA 9.4 symbol')
        if any(dll.lower() == 'rax.dll' for dll, _ in imports):
            raise ValueError('Windows plugin unexpectedly depends on rax.dll')
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f'viy_{platform}.{extension}'
    shutil.copy2(source, destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--platform', choices=PLATFORMS, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    print(package(args.build_dir, args.platform, args.output_dir))


if __name__ == '__main__':
    main()
