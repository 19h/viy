#!/usr/bin/env python3
"""Compare the original viy callers with the optimized callers, using one RAX archive."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def command(args):
    return subprocess.check_output(args, cwd=ROOT, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='1aa8a26')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--archive', type=Path,
                        default=ROOT / 'build/rax-capi/cargo/release/librax.a')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('--repeats must be positive')
    compiler = os.environ.get('CXX', 'c++')
    flags = ['-O3', '-std=c++17', '-Isrc', '-Ivendor/rax/capi/include']
    # The repository's native macOS static-link dependencies. Other hosts can
    # use the CMake test targets; this paired runner currently targets macOS.
    system = ['-framework', 'CoreFoundation', '-framework', 'Security',
              '-framework', 'SystemConfiguration', '-liconv', '-lobjc']
    results = []
    with tempfile.TemporaryDirectory(prefix='viy-rax-perf-') as temp:
        work = Path(temp)
        executables = {}
        for version in ['before', 'after']:
            defines = ['-DVIY_LEGACY_MODEL'] if version == 'before' else []
            sources = {}
            for name in ['program_model_core', 'emu_driver']:
                source = ROOT / f'src/{name}.cpp'
                if version == 'before':
                    source = work / f'{name}.cpp'
                    source.write_text(command(['git', 'show',
                                               f'{args.baseline}:src/{name}.cpp']))
                sources[name] = str(source)
            for kind in ['model', 'emu']:
                exe = work / f'{kind}-{version}'
                test = 'program_model_perf_test' if kind == 'model' else 'emu_decode_perf_test'
                inputs = [f'tests/{test}.cpp', sources['program_model_core']]
                if kind == 'emu':
                    inputs += [sources['emu_driver'], 'src/abi_policy.cpp',
                               'src/rax_loader.cpp', str(args.archive.resolve()), *system]
                subprocess.run([compiler, *flags, *defines, *inputs, '-o', str(exe)],
                               cwd=ROOT, check=True)
                # Fail before measuring if independent correctness fixtures fail.
                command([str(exe)])
                executables[kind, version] = exe
        for repeat in range(args.repeats):
            for kind, mode in [('model', '--benchmark'),
                               ('model', '--content-benchmark'), ('emu', '--benchmark')]:
                for version in ['before', 'after']:
                    output = command([str(executables[kind, version]), mode])
                    results.append(dict(repeat=repeat, kind=kind, mode=mode,
                                        version=version, output=output))
        report = dict(baseline=command(['git', 'rev-parse', args.baseline]).strip(),
                      compiler=command([compiler, '--version']), flags=flags,
                      rax=command(['git', '-C', 'vendor/rax', 'rev-parse', 'HEAD']).strip(),
                      os=command(['sw_vers']), cpu=command(['sysctl', '-n', 'machdep.cpu.brand_string']),
                      rustc=command(['rustc', '--version']), results=results)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(args.output)


if __name__ == '__main__':
    main()
