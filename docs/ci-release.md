# CI and release verification

The workflow follows Chernobog's native release matrix at commit
`c4440677e39f296e18bbd6f82eab50b878cebead`, with viy-specific test targets,
output paths, and packaging. The bundled `ida-cmake/` and PE verifier are
copied from that revision, with a trailing blank line removed from the helper;
the build helper retains its MPL-2.0 license.

## Pipeline

Branch pushes, pull requests, and manual dispatch build six native targets:
macOS, Linux, and Windows, each on x86-64 and ARM64. Every lane runs the
packaging regression script and viy's IDA-free CTest suite. Unix lanes also
run the RAX C API tests in release mode. Windows uses native MSVC, the static
CRT, and C++ integration tests against the embedded RAX archive.

Each lane uses an explicit Rust target triple and `cargo --locked`. Cargo and
C++ caches have separate restore/save steps, including saving compilation work
when later tests fail. Action references are pinned to full commit IDs.

After all six lanes succeed on a pushed `v*` tag, the release job downloads
only `viy-*` artifacts, checks that all six expected filenames exist, computes
SHA-256 checksums, and publishes binaries with generated release notes.
A tag containing a hyphen produces a prerelease. Ordinary branch builds do
not have release permissions. The default token is read-only; only the release
job receives `contents: write`.

The native artifact verifier checks binary format, shared-library type, and
architecture before naming each artifact. Windows additionally requires the
`PLUGIN` export and the base SDK `ida.dll!find_reg_value_info` import, and
rejects `ida.dll!reg_finder94_find_reg_value_info` and a separate `rax.dll`
dependency. Runtime plugin loading remains separate from these binary checks.

## SDK and platform assumptions

| ID | Assumption / dependent behavior | Falsification probe and result |
|---|---|---|
| A1 | Chernobog's six runner labels identify the intended native architectures; the build matrix depends on their availability. | Checked against GitHub's runner reference. Artifact header verification rejects a wrong target. Only macOS ARM64 was executed locally. |
| A2 | Chernobog's SDK pins provide the intended IDA 9.4 platform ABI. | Fetched both exact commits and verified the Unix build against `6929db6868a524496eb66e76e4ec6c9d720a0594`. Windows uses `f45fa5149caac89a954d1d82cd9d76b3899ee6a6`; the packaging import checks enforce its ABI distinction. Runtime loading on Windows remains unknown locally. |
| A3 | The SDK release plugin and Rust archive use matching Windows architectures and static CRTs. | CMake passes the matrix Rust triple, expects its target-qualified archive path, and supplies `/MT` and `+crt-static`. Workflow checks the C++ compiler is MSVC. Native Windows link/test execution is a CI gate, not a local result. |
| A4 | Tagging means recording the completed source snapshot locally; remote publication is a separate operation. | The annotated tag is created only after the workflow commit. No remote branch or tag is pushed by this task. When the tag is pushed, the workflow's release gate applies. |
| A5 | Tests which require a licensed IDA executable cannot run on these stock runners. | CI enables IDA-free tests and leaves `VIY_IDA_INTEGRATION_TESTS` off. Full live-IDB behavior remains unknown from this pipeline alone. |

macOS lanes explicitly use deployment target 15.0 to match the pinned SDK's
runtime stub. Linux binaries inherit the selected Ubuntu runner's runtime
baseline. No older operating-system compatibility is inferred from compilation.
The optional Chernobog Linux-to-Windows cross-check was not copied: viy uses
the two native Windows release lanes and has no xwin toolchain or dependency.

## Local verification

- `actionlint .github/workflows/build.yml` passed (actionlint 1.7.12).
- `python3 tests/package_plugin_test.py`: 5 tests passed, including architecture
  mismatch, truncated headers, PE offsets, and exact artifact copying.
- Native Release configure/build passed on macOS ARM64 with stable Rust,
  the pinned Unix IDA SDK, and `RAX_CARGO_TARGET=aarch64-apple-darwin`.
- `ctest --test-dir build --output-on-failure --no-tests=error`: 16/16 passed.
- RAX C API release suite with stable Rust and the ARM64 target: 71 passed,
  zero failures, ignored tests, or filtered tests; zero doctests were defined.
- Real `build/viy.dylib` passed packaging as `viy_macos-arm64.dylib`.
- A fresh Ninja Multi-Config configuration confirmed that Release output is
  `build/viy.dylib`, without an extra `Release/` directory.
- `git diff --check` passed. The existing untracked `idump` was preserved.

Local commands matching the macOS lane (replace the SDK path):

```sh
export IDASDK=/path/to/pinned/ida-sdk
export RUSTUP_TOOLCHAIN=stable
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DRAX_CARGO_TARGET=aarch64-apple-darwin
cmake --build build --config Release --parallel 3
ctest --test-dir build --build-config Release --output-on-failure --no-tests=error
python3 tests/package_plugin_test.py
python3 scripts/package_plugin.py --build-dir build \
  --platform macos-arm64 --output-dir artifacts
```

## Bounded findings and quality gates

- **High impact:** Windows and Linux binaries have not been built locally;
  their native CI gates must succeed before the workflow publishes a release.
- **Medium impact:** runner images and stable Rust can advance. Exact SDK pins,
  the Cargo lockfile, recorded compiler versions, and versioned cache keys
  bound dependency provenance but do not make builds bit-for-bit reproducible.
- **Low impact:** native binary architecture checks do not replace a licensed
  IDA load test; that boundary is retained explicitly.

QG1–QG7 review: no normative decision required; assumptions and probes listed;
workflow, packaging, build integration and local tagging covered; checksums use
standard SHA-256 and no performance calculations are claimed; cross-platform
execution limits are explicit; provenance is the source workflow, fetched
commits, and local executions; adjacent findings are impact-labeled.

Primary references:

- [GitHub-hosted runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Artifact upload action](https://github.com/actions/upload-artifact)
- [Artifact download action](https://github.com/actions/download-artifact)
- [Actions cache](https://github.com/actions/cache)
- [Chernobog source workflow](https://github.com/19h/chernobog/blob/c4440677e39f296e18bbd6f82eab50b878cebead/.github/workflows/build.yml)

## Linux CI repair (2026-09-14)

Run [34821164019](https://github.com/19h/viy/actions/runs/34821164019)
failed in both Linux build jobs on GCC 13's optimized
`-Werror=stringop-overflow` diagnostic in ABI stack-argument serialization.
The implementation validated four/eight-byte pointers, but the variable loop
bound did not retain that proof through optimization. The loop now explicitly
bounds its writes by the eight-byte destination array as well as the validated
ABI width. Exhaustive tests cover all 256 representable widths and both byte
orders, including exact bytes, zero tail bytes and rejection of invalid widths.

A broader GCC 13.4 check also exposed `-Werror=nonnull` in libstdc++'s inlined
initializer-list assignment in the loaded-byte-view test fixture. Resizing the
three-byte mask and filling its entries explicitly preserves the test corpus
and avoids that diagnostic. Warning flags remain enabled.

Verification: the original ABI source reproduces the CI diagnostic with GCC
13.4 at `-O3`; the fixed source and ABI tests pass under the same flags. All
16 C++ test targets pass GCC compilation with the strict warning set: the
12 IDA/RAX-independent executables run successfully in Linux, and the four
RAX-linked targets receive compile checks there. The macOS ARM64 plugin links
and all 16 CTest cases pass, including the RAX-linked cases. This local Linux
check does not claim a Linux plugin or RAX archive link.

The published `v1.0.0` tag identifies the original workflow commit `ff3acea`.
Repair commits do not automatically change that tag or rebuild its release.


The follow-up run [34823157816](https://github.com/19h/viy/actions/runs/34823157816)
linked both Linux plugins, then failed compiling `tests/emu_evidence_test.cpp`:
Ubuntu GCC 13.3 rejects a range-loop copy of a `std::pair` under
`-Werror=range-loop-construct`. The fixture now binds the pair by const reference.
The earlier local GCC 13.4 compile did not emit this diagnostic; compiler patch
versions are therefore distinguished in verification results.

The corrected fixtures also pass an Ubuntu 24.04 GCC 13.3 check: all 17 C++
test targets compile with Release warnings-as-errors; 13 SDK/RAX-independent
executables run successfully. Four RAX-linked targets were compile-checked in
that container and executed in the native macOS 17-case CTest run.
