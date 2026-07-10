# viy

viy is a per-database IDA plugin that combines IDA-native analysis with
optional [rax](https://github.com/hexrayssa/rax) decoding and emulation. Its goal
is to recover useful analysis evidence that the initial disassembly missed while
keeping speculative results distinguishable from proofs.

The current plugin has five integrated analysis paths:

- An IDA-native, read-only provider resolves selected indirect targets and
  proves a small set of branch/structural facts. It works when librax is absent.

- A second read-only deobfuscation provider recognizes bounded get-PC and
  push/return gadgets, local constant chains, entry predicates, wrappers,
  suspicious skipped regions, and dispatcher/CFF candidates. It also works
  without librax.

- Independent off-thread rax engines explore functions under deterministic and
  call-site-derived entry states. They record executed transfers, memory
  accesses, register states, final written bytes, and run outcomes.

- The rax decoder recovers missing encoded direct targets and audits IDA/rax
  instruction-size, flow, and target disagreements.

- Main-thread consumers turn sufficiently guarded observations into references,
  functions, strings, pointer tables, comments, and optional metadata changes.

All producers also feed a typed evidence ledger with provenance, confidence,
run/seed scope, function generation, deterministic identities, conflict
detection, and crash-recoverable per-IDB persistence. See
[Architecture](docs/architecture.md) and the
[verification matrix](docs/verification-matrix.md) for the exact boundaries.

## Capability levels

viy never links against librax. It resolves the C ABI at runtime, gates the
required 1.1 emulation surface as a unit, and probes newer capabilities
independently.

| Runtime | Available behavior |
|---|---|
| No compatible librax | IDA-native and deobfuscation evidence production plus guarded evidence consumption on x86 and ARM; evidence restore/persist; optional Hex-Rays presentation. |
| rax 1.1+ | Dynamic exploration when that architecture/backend reports stepping support and a clean context snapshot can be captured. Memory-derived features additionally depend on working memory hooks and, for exact final bytes, `rax_mem_read`. |
| rax 1.2+ | Static direct-target recovery and the IDA/rax decoder audit through optional `rax_decode`. |
| rax 1.3+ | The decoder audit additionally calls optional `rax_analyze` at existing code heads and records statically resolved SMIR effects. Rich effects are currently defined by the vendored ABI for x86-64, AArch64, RISC-V 64, and Hexagon; other valid decode modes report unsupported/partial effects. |

If librax fails the ABI/symbol gate, only rax-backed paths are unavailable. The
native provider is not disabled with them. viy reports the capability decision,
analysis phases, bounded progress, evidence policy results, and completion in
IDA's Output window and headless log.

## Lifecycle and data flow

1. viy waits for `idb_event::auto_empty_finally`, or starts immediately if IDA
   already reports analysis complete. `VIY_ENABLED=0` suppresses the sweep, but
   persisted evidence is still restored during plug-in construction.

2. On the main thread it snapshots segment bytes, initialized-byte masks,
   permissions, architecture/endianness, and every chunk of each non-library,
   non-thunk function. A rebase-stable byte/topology hash and snapshot generation
   identify the function version that produced later evidence.

3. The native and deobfuscation providers scan live IDA state on the main
   thread. They emit facts; they do not mutate the IDB while scanning.

4. If rax emulation is available, the main thread builds immutable function
   jobs and entry inputs. Worker threads each construct and own one independent
   engine over a shared immutable program snapshot. Results are delivered in
   submission order even when workers finish out of order. All IDA queries and
   mutations remain on the main thread.

5. Each result is normalized and merged into the evidence ledger. Runtime and
   legacy consumers apply guarded additions. The optional static decoder and
   decoder audit run over every function chunk on the main thread.

6. At the end of an epoch, the contradiction-aware evidence consumer runs, the
   optional Hex-Rays view receives an immutable ledger snapshot, and the ledger
   is persisted.

7. If viy changed the database, it waits for IDA autoanalysis and repeats with a
   fresh snapshot. `VIY_MAX_EPOCHS` bounds this fixed-point loop. The default is
   three epochs; a database with no applied changes stops after the first.

Completed dynamic jobs are cached only for the lifetime of this sweep. Before a
later convergence epoch, viy recomputes a deterministic fingerprint over the
complete image content, function bytes/chunks, run/input corpus, dynamic-relevant
configuration, and call-summary set. An exact hit skips redundant rax execution
for that function while still running the main-thread/static processing path.
Any image-byte change invalidates every dynamic fingerprint conservatively.

The UI timer limits submissions and result application per tick. In a headless
runtime without a timer, the main thread drains the same queue inline while rax
execution remains on worker threads.

## Dynamic exploration

Each worker mirrors initialized image bytes into guest memory and applies IDA
segment permissions plus viy's strict hook checks by default. It maps a private
scratch stack, captures a clean baseline context, and restores both context and
guest memory before every run. A sentinel return address, instruction cap,
wall-clock cap, invalid-instruction hook, and bounded result buffers contain bad
paths.

The default corpus uses four deterministic entry-state variants. Across
arguments it rotates zero, one, unsigned/signed 16-bit boundaries,
sign-extended `INT16_MIN`, mapped image/stack pointers, and a deterministic
mixed value. Additional inputs are recovered from incoming call sites when
IDA's register tracker or type information proves a value. The entry-state
adapter supports:

- x86-64 SysV and Windows x64 register arguments; PE selects Windows x64;

- i386 stack arguments from a bounded, linear sequence of preceding `push`
  instructions, plus typed fastcall-style ECX/EDX locations;

- AAPCS32, AAPCS64, RISC-V LP64, Cortex-M AAPCS, and Hexagon integer argument
  registers.

No recovered call-site value is treated as universal. Every event retains its
run ID and seed, and run disagreement is preserved as conflict/variation.

### Library-call summaries

When `VIY_IMPORT_SUMMARIES=1`, named-list entries are canonicalized and selected
calls are modeled rather than blindly entered:

- `memcpy`, `memmove`, `memset`, `strcpy`, `strncpy`, `strlen`, and `strcmp`;

- `malloc`, `calloc`, selected C++ new/delete spellings, and `free`;

- `exit`, `abort`, `terminate`, `quick_exit`, `fatal`, `panic`, and
  `stack_chk_fail`.

Memory/string operations are capped at 1 MiB. Allocation uses deterministic
scratch-heap addresses. A summary that cannot read its arguments or memory
fails closed and lets the real mapped stub execute. Termination summaries stop
the run and produce a definitive process-termination outcome.

## IDA-native analysis without rax

The integrated native provider recognizes x86, AArch32, and AArch64 and scans
all function chunks plus optionally unowned executable code. Depending on
architecture and public SDK support, it emits evidence for:

- indirect call/jump targets proved by IDA regfinder, including a value loaded
  from read-only memory;

- AArch64 architectural-zero-register branch outcomes;

- adjacent opposite-condition branch pairs on x86 and ARM;

- bounded x86 CF/ZF proofs;

- guarded unowned/interior call targets as function candidates; and

- legacy-prefix, code-item-size, undecodable-item, and direct-target
  discrepancies.

The provider deduplicates semantic findings across rescans and attaches an
epoch, function/chunk scope, architecture, proof source, strength, support
count, and deterministic flag. Unsupported rules are skipped independently.

### Structural/deobfuscation provider

The default-on `VIY_DEOBF` provider is independent of rax and complements the
native rules rather than repeating them. It recognizes x86, AArch32, and
AArch64, scans every function chunk under finite instruction/block/classifier
budgets, and emits evidence for:

- bounded x86 call/pop/adjust/push/return get-PC patterns, including exact
  resumed addresses and register values when proved;

- constant `push`/`ret` targets and same-block, width-aware constant chains
  ending in indirect calls/jumps;

- bounded loaded gaps skipped by direct control flow, only after checking for
  names, entries, and inbound refs; these remain heuristic data-region
  candidates;

- first-entry-block predicates, distinguishing ABI-unspecified entry flags
  from an exact locally defined constant comparison. Only the latter can emit
  a proven-unreachable successor;

- small wrapper/thunk shapes with one direct transfer and no disqualifying
  global writes or conditional flow; and

- incomplete comparison-chain dispatch maps, loop-backed CFF-shaped traits,
  and symbolic edges where a predecessor fixes the dispatcher state.

The IDA adapter is read-only. A validating sink admits variations and
ambiguities but transactionally suppresses a new logical contradiction.
Downstream consumers still decide whether an accepted fact is actionable:
proved call/jump targets can become guarded crefs and proved unreachable edges
can become comments, while region/trait/dispatch candidates remain ledger or
Hex-Rays evidence unless another explicit consumer is added.

## Evidence, conflicts, and persistence

The producer-neutral schema currently represents code targets, branch
reachability, memory accesses/values, string and function candidates, function
traits/outcomes, code regions, dispatch maps, CFG edges, register values, and
call observations.

Payloads and observations have versioned canonical encodings. SHA-256 gives
stable identities; semantic identity uses the canonical bytes rather than a
hash alone. The ledger normalizes and deduplicates observations without
manufacturing combined provenance. Support summaries count distinct runs,
seeds, run/seed pairs, producers, methods, and generations.

Conflict detection distinguishes variation, ambiguity, and contradiction. It
covers competing unique targets, reached-versus-proven-unreachable successors,
divergent concrete values/strings/registers/calls/outcomes, incompatible code
regions, and competing function/dispatch/CFG assertions.

The persisted ledger is append-only history, but automatic consumers use a
generation-aware active view. On startup viy allocates generation IDs that do
not collide with any restored observation. Native/deobfuscation scans re-emit a
complete current snapshot at one generation; other scoped evidence must match
the current function/image/job identity. Removed functions, superseded bytes or
inputs, disabled producers, and unknown historical unscoped producers therefore
lose authority without erasing their provenance. Explicit user assertions stay
active, including multiple competing assertions so their conflicts stay
visible. The authoritative lifecycle policy compares exact allocated identities,
not numeric generation ordering.

With `VIY_PERSIST_EVIDENCE=1`, a versioned envelope with a SHA-256 trailer is
stored in two alternating netnode slots. A new slot is completely written,
read back, and decoded before its commit marker changes. Restore falls back to
the retained slot after a corrupt active envelope, merges two valid slots after
a damaged marker, and migrates the former same-node layout. Persistence writes
the full historical ledger; guarded IDB application and Hex-Rays publication
receive only the active view.

## Mutation and confidence policy

viy is additive by default, but “additive” does not mean that every result has
the same proof strength.

- Immediate dynamic code/data references require a real IDA instruction source,
  a mapped target, and—for code—an executable, non-tail target. Existing refs
  are never duplicated. A single observed path can add such a reference; it is
  a recall aid, not a universal proof.

- The generic evidence consumer rejects contradictory payloads. Code targets
  require a static/symbolic/user proof at confidence 90% or two distinct runs
  at at least 80% each. Function candidates require a static proof at 75% or
  the same two-run rule, and never split an existing function.

- Runtime strings, bytes, pointer slots, orphan calls, and tail candidates
  require the exact value/edge in at least two distinct `(run_id, seed)` pairs.
  Any overlapping divergent final value blocks the corresponding mutation.

- Runtime byte patching is disabled unless `VIY_APPLY_RUNTIME_BYTES=1`. Even
  then, viy requires corroboration, no conflict, an unchanged IDB range matching
  the original snapshot, the global byte budget, and write/execute correlation
  before patching executable bytes.

- No-return metadata requires every completed outcome to be conclusive and
  non-returning, with at least three outcomes; enabling no-return analysis
  schedules at least five baseline runs. Stack purge requires every outcome,
  with at least two, to return with the same delta and applies only to previously
  unknown i386 callee cleanup.

- Switch creation, `FUNC_NORET`, runtime bytes, and function-tail sharing have
  separate opt-ins. Opaque predicates and argument registers are comments, not
  proofs that rewrite control flow or types.

Comments are repeatable and are either appended without replacing existing text
or skipped when an older consumer finds an existing comment. viy never removes
user analysis.

## Runtime enrichment

When memory recording and exact readback are available, viy captures bounded
final dirty ranges and can:

- recognize NUL-terminated and bounded Pascal8/Pascal16/Pascal32 ASCII,
  strict UTF-8, UTF-16LE/BE, and UTF-32LE/BE strings with at least four decoded
  characters; multi-byte length prefixes follow target byte order and count
  encoded code units;

- create a string only in undefined non-executable image data whose bytes are
  already present or were safely patched; stack, heap, executable, or
  runtime-only strings become writer comments;

- detect changed writes into executable segments and correlate them with later
  execution in the same `(run_id, seed)` using shared hook sequence numbers;

- cluster at least two contiguous, stable pointer slots, requiring a code
  target or a pointer read that precedes a matching indirect edge in the same
  `(run_id, seed)` before materializing offsets;

- promote a corroborated call target only when it is executable, unowned, and
  a valid code head (or can safely be made code); and

- comment on corroborated function-tail candidates. The optional tail mutation
  only shares an already-defined tail with exact known boundaries; it never
  guesses an orphan tail end.

The older enrichment pass also materializes initialized pointer slots, types
undefined globals by access width, creates ordinary C strings at observed reads,
and comments resolved indirect transfers.

## Decoder audit and SMIR effects

With `rax_decode`, viy compares IDA and rax at each existing code head, records
size/flow/target disagreements as evidence, and independently recovers encoded
direct call/branch targets that lack an outgoing target xref. ARM/Thumb state is
taken from IDA per instruction; Cortex-M is Thumb-only.

With optional rax 1.3 `rax_analyze`, the same per-head walk negotiates a
caller-owned, fixed-layout effect buffer and validates every ABI record. viy
stores only effects that the stateless lift resolves without guessing:

- encoded direct call/branch targets;

- absolute or PC-relative memory addresses with a known access width and kind;
  and

- complete constant register results up to 64 bits.

Complete effects use 99% static-proof confidence; useful partial effects use
85%. Direct-target facts can pass the generic evidence consumer. Memory and
register effects currently enrich the ledger and optional Hex-Rays view; the
generic evidence consumer does not directly materialize them into IDA operands.

## Architectures

Architecture detection and each provider are independently gated.

| IDA target | Snapshot/detection | Native / deobf providers | rax decode request | rax emulation request | Entry ABI |
|---|---:|---:|---:|---:|---|
| x86-16 | Yes | Both are PLFM_386-gated; individual rules may skip | Yes | No: segmented execution is intentionally not modeled | None |
| x86-32 | Yes | Yes / yes | Yes | Yes, if backend supports stepping | Stack; typed ECX/EDX overrides |
| x86-64 | Yes | Yes / yes | Yes | Yes, if backend supports stepping | SysV, or Windows x64 for PE |
| AArch32 | Yes | Yes / yes | ARM/Thumb per address | Yes, if backend supports stepping | AAPCS32 |
| AArch64 | Yes | Yes / yes | Yes | Yes, if backend supports stepping | AAPCS64 |
| RISC-V 64 | When the SDK exposes `PLFM_RISCV` | No / no | Yes | Yes, if backend supports stepping | LP64 integer registers |
| Cortex-M | Only a dedicated processor ID/name | No / no | Thumb | Yes, if backend supports stepping | AAPCS integer registers |
| Hexagon/QDSP6 | Dedicated ID or stable processor name | No / no | Yes | Yes, if backend supports stepping | R0–R5 integer registers |

“Requested” does not promise that every librax build implements every backend;
viy asks `rax_engine_supports_stepping` and disables dynamic discovery for an
engine that cannot be driven.

## Building

rax is a git submodule under `vendor/rax`. The Makefile builds the vendored C
API library and the plugin, staging both in `BUILD_DIR` (default `build`):

```sh
git submodule update --init --depth 1 vendor/rax
export IDASDK=/path/to/ida-sdk
export IDA_CMAKE_DIR=/path/to/ida-cmake
make
```

Useful build variables are `BUILD_DIR`, `DEBUG=1`, `CMAKE_FLAGS`, and
`IDA_CMAKE_DIR`. `make rax`, `make viy`, `make test`, `make test-ida`,
`make clean`, `make distclean`, and `make help` are also available. `make test`
runs the rax C-ABI suite and IDA-free CTest targets; `make test-ida` runs the
licensed persistence/recovery harness. The plugin includes `rax.h` for
declarations but does not link librax.

| Make/CMake setting | Default | Purpose |
|---|---|---|
| `IDASDK` | required | IDA SDK root used by `ida-cmake`. |
| `IDA_CMAKE_DIR` | required | `ida-cmake` checkout; may also be supplied through the environment. |
| `BUILD_DIR` | `build` | Makefile CMake/staging directory. |
| `DEBUG` | `0` | `0` selects Release; `1` selects Debug. |
| `CMAKE_FLAGS` | empty | Additional arguments passed by the Makefile configure step. |
| `RAX_CAPI_DIR` | `vendor/rax/capi` | CMake path containing `include/rax.h`. |
| `BUILD_TESTING` | CTest default (`ON`) | Build/register IDA-free tests. |
| `VIY_TEST_STRICT_WARNINGS` | `ON` | Compile pure tests with strict warnings as errors on Clang/GCC. |
| `VIY_TEST_SANITIZERS` | `OFF` | Add ASan/UBSan to pure tests on Clang/GCC. |
| `VIY_IDA_INTEGRATION_TESTS` | `OFF` | Register the licensed real-IDAT persistence/provider and Hex-Rays bridge tests. |
| `VIY_IDAT` | unset | IDAT executable for the opt-in CTest integration target. |
| `IDAUSR` | unset | First colon-separated path selects the user IDA directory. |
| `PLUGIN_DIR` | `$IDAUSR/plugins` or `~/.idapro/plugins` | `make install` destination. |
| `IDABIN` | required by `install-app` | IDA installation root for application-local deployment. |
| `IDAT` | required | IDAT executable used by `make test-ida`. |

The Makefile's staged artifact naming currently targets macOS and Linux. Use a
platform-appropriate CMake/deployment flow for Windows.

To build and run the IDA-free CTest suite directly:

```sh
cmake -S . -B build-dev \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DVIY_TEST_STRICT_WARNINGS=ON
cmake --build build-dev --parallel
ctest --test-dir build-dev --output-on-failure
```

`-DVIY_TEST_SANITIZERS=ON` adds AddressSanitizer and UndefinedBehaviorSanitizer
to the 14 IDA-free test targets. The two serial licensed real-IDAT integration
targets (persistence/provider recovery and Hex-Rays rendering) are opt-in via
`-DVIY_IDA_INTEGRATION_TESTS=ON -DVIY_IDAT=/path/to/idat`.

## Installing

```sh
make install
make install-app IDABIN=/path/to/ida
```

`make install` honors the first path in `IDAUSR`, otherwise installs to
`~/.idapro/plugins`; `PLUGIN_DIR` overrides it. `install-app` installs under
`$IDABIN/plugins`.

The layout intentionally keeps librax out of IDA's plugin scan:

```text
plugins/viy.dylib          # or viy.so
plugins/viy/librax.dylib   # or librax.so
```

librax search order is:

1. `VIY_RAX_PATH`;

2. the platform loader search path (`librax.dylib`, `librax.so`, or `rax.dll`);

3. the `viy/` companion directory next to the plugin;

4. next to the plugin binary; then

5. next to the IDA executable.

## Runtime observability

By default viy writes bounded, non-modal `[viy]` records to IDA's Output window.
The same records are present in an IDAT `-L` log. Stable `event=` and
`key=value` fields expose loading/restoration, capability gates, snapshot and
provider durations, exact snapshot inclusion/exclusion/read-failure counts,
worker initialization/availability and queue depth, per-epoch function progress,
cache hits, dynamic-job outcomes, evidence-planning/mutation progress,
conflicts/policy skips, persistence, convergence, and terminal state. A
successful run that changes nothing still emits a completion record.

Periodic status is limited by `VIY_PROGRESS_INTERVAL_MS`; phase and terminal
records are emitted immediately. Function addresses and individual worker
outcomes appear only at trace level. Free-form diagnostics are single-line and
bounded. Logging is performed on the main thread and is not part of emulation
job fingerprints or persisted evidence identities. Terminal elapsed time is
frozen, so later manual status requests do not include post-analysis idle time.
Dynamic capability uses `off`, `initializing`, `available`, `partial`, or
`unavailable`; native register-value and operand-address trackers are reported
independently as `unknown`, `available`, or `unavailable` where applicable.

`VIY_LOG_LEVEL` selects the surface:

| Level | Output |
|---:|---|
| `0` | No viy output. |
| `1` | Lifecycle, capability/provider results, diagnostics, evidence policy, persistence, and completion. |
| `2` | Level 1 plus rate-limited live progress; this is the default. |
| `3` | Level 2 plus per-function worker status, run counts, edge counts, and data-access counts. |

The plugin is visible in IDA's plugin menu. Invoking it while analysis is active
or complete prints an immediate status snapshot. Before IDA autoanalysis has
settled, invocation reports the waiting state without starting the sweep; after
that boundary it triggers the normal guarded start path if needed.

## Runtime configuration

Environment variables are read when each per-IDB plugin instance is created.
Boolean values are enabled unless the exact value is `0`, `false`, `no`, or
`off`. Integer values accept C-style base prefixes; negative or unparsable
values, overflow, and trailing non-whitespace retain the default before the
documented clamps are applied.

### Scheduling and providers

| Variable | Default | Meaning and enforced bounds |
|---|---:|---|
| `VIY_ENABLED` | `1` | Master sweep switch. Evidence restore still occurs when disabled. |
| `VIY_LOG_LEVEL` | `2` | `0` quiet, `1` lifecycle/summary, `2` bounded progress, `3` per-function trace. Valid values above 3 are capped at 3; negative or malformed values retain the default as described above. |
| `VIY_PROGRESS_INTERVAL_MS` | `1000` | Periodic progress cadence in milliseconds; zero resets to 1000 and nonzero values are clamped to 100–60000. |
| `VIY_MAX_INSNS` | `200000` | Instruction cap per emulation run. `0` is reset to `200000`. |
| `VIY_TIMEOUT_MS` | `1000` | Wall-clock cap per run. `0` is reset to `1000`. |
| `VIY_MAX_FUNCS` | `0` | Snapshot/scan at most N functions; `0` means all. |
| `VIY_FUNCS_PER_TICK` | `2` | Main-thread submission/application budget per timer tick; minimum 1. |
| `VIY_TICK_MS` | `15` | Timer cadence in milliseconds; minimum 1. |
| `VIY_MAX_EPOCHS` | `3` | Bounded snapshot/apply/autoanalysis convergence; clamped to 1–16. |
| `VIY_EXPLORE_RUNS` | `4` | Deterministic baseline runs per function; clamped to 1–64. Call-site inputs are additional. |
| `VIY_WORKERS` | `0` | Independent rax engines. `0` chooses `min(max(hardware_concurrency-1,1),4)`; explicit values are capped at 64. |
| `VIY_NATIVE` | `1` | Enable the IDA-native evidence provider. |
| `VIY_DEOBF` | `1` | Enable the read-only structural/deobfuscation evidence provider. |
| `VIY_STATIC` | `1` | Enable direct-target recovery and decoder audit when `rax_decode` exists. |
| `VIY_WANT_DREFS` | `1` | Apply observed in-image data references. Memory hooks may still run when runtime-string or SMC evidence needs transient events. |
| `VIY_STRICT_PERMS` | `1` | Apply IDA segment permissions and viy's hook checks instead of treating the guest image as RWX; see the backend caveat below. |
| `VIY_IMPORT_SUMMARIES` | `1` | Model the selected named library/import calls. |
| `VIY_PERSIST_EVIDENCE` | `1` | Restore and persist the versioned per-IDB evidence ledger. |
| `VIY_RAX_PATH` | unset | Explicit librax path; also used first in runtime discovery. |

### References and enrichment

| Variable | Default | Meaning and enforced bounds |
|---|---:|---|
| `VIY_MAKE_CODE` | `1` | Queue newly accepted code targets for code/function analysis. |
| `VIY_PTR_REFS` | `1` | Materialize stable in-image pointer slots observed by the legacy pass. |
| `VIY_TYPE_DATA` | `1` | Type undefined globals by observed access width. |
| `VIY_STRINGS` | `1` | Create ordinary C strings at observed data reads. |
| `VIY_RUNTIME_STRINGS` | `1` | Reconstruct NUL-terminated and bounded Pascal8/Pascal16/Pascal32 strings from exact final writes. |
| `VIY_UNICODE_STRINGS` | `1` | Consider UTF-16/UTF-32 as well as strict UTF-8/ASCII runtime strings. |
| `VIY_TABLES` | `1` | Detect corroborated contiguous runtime pointer tables. |
| `VIY_FUNCTION_RECOVERY` | `1` | Permit guarded promotion of orphan call targets/function evidence. |
| `VIY_TAIL_RECOVERY` | `0` | Share an already-defined exact tail with a corroborated owner. Candidate comments do not require this opt-in. |
| `VIY_SMC_EVIDENCE` | `1` | Detect/comment changed writes to executable image bytes and execution correlation. |
| `VIY_APPLY_RUNTIME_BYTES` | `0` | Explicitly allow guarded runtime-byte patching. |
| `VIY_MAX_RUNTIME_BYTES` | `1048576` | Maximum exact final-write capture per run and patch budget per function pass; capped at 64 MiB. `0` disables capture/patching. |
| `VIY_COMMENTS` | `1` | Allow viy repeatable comments. |

### Function-level and decompiler behavior

| Variable | Default | Meaning and enforced bounds |
|---|---:|---|
| `VIY_SWITCH` | `0` | Create a custom switch from at least two observed targets; the result is labelled potentially incomplete. |
| `VIY_PURGE` | `1` | Set unknown i386 callee cleanup from a corroborated return SP delta. |
| `VIY_NORET` | `1` | Produce a no-return comment/count after conclusive multi-run agreement. |
| `VIY_SET_NORET` | `0` | Also set `FUNC_NORET` and reanalyze callers. |
| `VIY_ARGREGS` | `1` | Comment static read-before-write argument-register hints. |
| `VIY_OPAQUE` | `0` | Comment branches for which exactly one successor was reached by the exploration corpus. |
| `VIY_OPAQUE_RUNS` | `3` | Minimum run corpus requested for opaque analysis; clamped to 2–16. `VIY_EXPLORE_RUNS` may be larger. |
| `VIY_HEXRAYS_BRIDGE` | `0` | Install the optional, non-mutating Hex-Rays warning/hint bridge. |

## Optional Hex-Rays view

`VIY_HEXRAYS_BRIDGE=1` publishes gated evidence as decompiler warning lines and
cursor hints. It requires a build with `hexrays.hpp` and a compatible decompiler
at runtime. It never rewrites microcode, ctree, variables, types, comments, or
IDB state. Static/symbolic/user evidence must reach 85% confidence; dynamic
evidence requires at least two distinct runs at 85%. All detected conflicts,
including mere value variation, are suppressed from the view. See
[Hex-Rays bridge](docs/hexrays-bridge.md).

## Known limitations

- Emulation explores bounded concrete paths from synthesized or observed entry
  states. Non-observation is not proof of unreachability; the opaque feature is
  intentionally worded as an exploration result.

- The immediate dynamic-reference path accepts one observed run after strict
  structural guards. Use the evidence ledger and decompiler view when provenance
  and corroboration matter more than recall.

- Exact final bytes require optional `rax_mem_read`; data events require a
  functioning memory-hook backend. Missing optional capabilities disable only
  their dependent enrichments.

- Final-write snapshots identify the bytes left after a run, not every
  intermediate version. If a range is written, executed, and then rewritten,
  temporal correlation proves the write-before-execution relationship but not
  which intermediate byte version was fetched.

- Strict execute permission is checked before instruction retirement. Strict
  data permission enforcement depends on per-access memory hooks (currently the
  x86 backend); a backend without those hooks cannot fully enforce data-page
  read/write permissions and is therefore less suitable for hostile inputs.

- The call-summary set is deliberately small, name-based, and models only
  integer/pointer ABI arguments. It is not a general OS/runtime environment.

- Automatic function-tail mutation never invents boundaries, and automatic
  function recovery never splits an existing function.

- The Hex-Rays bridge presents evidence only; it does not force constant
  propagation or indirect control-flow rewrites.

- Structural dispatch maps are deliberately incomplete candidates. They are
  not automatically promoted into IDA switch metadata by the neutral evidence
  consumer.
