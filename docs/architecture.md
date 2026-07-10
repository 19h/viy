# viy architecture

This document describes the code currently compiled into and invoked by the
`viy` plugin.

## Design invariants

The implementation is organized around five invariants:

1. IDA APIs are called only on the IDA/main thread.

2. Worker jobs contain copied, IDA-free values and operate on an immutable
   `ProgramImage` snapshot.

3. Analysis producers emit positive, typed evidence. Non-observation is not
   silently converted into unreachability.

4. A producer's proof quality and provenance are retained independently from
   the semantic payload.

5. Database mutation is a separate, guarded consumer decision.

These boundaries are important because a concrete emulator observation, an IDA
decoder result, and a static proof do not have interchangeable meanings.

## Component map

```text
IDA main thread
  autoanalysis event
       |
       v
  ProgramImage snapshot -----> immutable shared snapshot
       |                                |
       |                                v
       |                    EmulationWorkerPool
       |                     N worker threads
       |                     N independent rax engines
       |                                |
       |<---------- ordered pure results+
       |
       +--> NativeAnalysisProvider ------+
       +--> DeobfAnalysisProvider -------+
       +--> rax decoder/audit -----------+--> EvidenceStore
       +--> emulation evidence bridge ---+       |
       |                                         +--> guarded IDB consumer
       +--> direct runtime/legacy consumers      +--> Hex-Rays view
                                                 +--> netnode persistence
```

`src/viy.cpp` owns one instance of this graph per IDB because the plugin uses
`PLUGIN_MULTI`. There is no cross-IDB evidence or native-provider cache.

## Snapshot boundary

`program_model.cpp` reads the live IDB and builds an IDA-free `ProgramImage`.
All lookup and hashing behavior lives in `program_model_core.cpp`, which has no
SDK dependency and is also linked by the pure model, emulation, and SMIR tests.
The snapshot contains:

- sorted mapped segments, bytes, initialized-byte masks, permissions, and
  bitness;

- target architecture and endianness;

- non-library/non-thunk function entries and all of their chunks; and

- a monotonically advancing snapshot generation.

Each `FuncRange` contains the primary entry range for compatibility and a full
chunk vector. Its FNV-1a-based versioned identity includes relative chunk
topology, loaded/unloaded state, and byte values. Absolute addresses are encoded
relative to the function entry, making the identity stable across a pure rebase.
The snapshot model initially retains a prior content generation for an unchanged
function. The lifecycle then assigns a persistence-safe evidence generation
that also accounts for whole-image and emulation-job semantics.

`ProgramImage::content_hash` covers architecture, endianness, rebase-relative
segment topology, permissions, initialized masks, and bytes. It is intentionally
whole-image: a function can load a table or code pointer from another segment,
so changing any visible image byte conservatively invalidates dynamic reuse.

Segment and function lookup methods in `program_model.hpp` contain no IDA types,
so workers may use them without crossing the SDK boundary.

## Configuration boundary

`viy_config.cpp` is IDA-free and reads the environment once per plug-in
instance. Boolean overrides use the documented exact false tokens. Unsigned
integers accept C-style bases and surrounding whitespace, but reject negatives,
overflow, empty values, and trailing non-whitespace; bounded integer conversion
happens before any narrowing cast. Post-parse clamps enforce finite worker/run,
epoch, timing, and memory limits, and zero instruction/time caps are restored to
safe nonzero defaults.

## Native control-flow provider

`native_analysis.cpp` reads live IDA state and emits `NativeFact` values through
`NativeFactSink`. It does not write the database while scanning.

The provider currently recognizes PLFM_386 and PLFM_ARM, distinguishes AArch32
from AArch64, and scans every function chunk. Optional unowned-executable-code
scanning lets it find call candidates before IDA has made a function.

The provider's rules are independently switchable in `NativeAnalysisOptions`:

- regfinder-based indirect control-flow resolution;

- read-only-memory indirection;

- AArch64 zero-register branch proofs;

- x86/ARM opposite-branch-pair structural proofs;

- bounded local x86 carry/zero flag proofs;

- guarded function candidates; and

- decode/item discrepancies.

`NativeAnalysisFactAdapter` maps one native fact to one or more neutral facts.
For example, a proved branch can yield a reached successor and a
`ProvenUnreachable` successor. Native-only details remain in the evidence
method, detail, and support-address fields.

The provider exposes semantic duplicate suppression, invalidation, reset, and an
externally assigned epoch. The integrated lifecycle treats every database scan
as a complete snapshot: it clears the provider cache, assigns one fresh
persistence-safe generation, and re-emits all current facts. This is what lets
the active evidence view retire a fact that disappeared.

## Structural/deobfuscation provider

`deobf_analysis_core.*` defines a small IDA-free instruction/block IR and
bounded semantic classifiers. `deobf_analysis.cpp` is the read-only IDA adapter;
it recognizes x86, AArch32, and AArch64, snapshots all function chunks and CFG
blocks, and translates only instruction forms whose semantics it can represent.

The default budgets are 4096 instructions and 1024 blocks per function. Even a
zero local budget selects finite hard ceilings (one million instructions and
100,000 blocks); no scan is actually unbounded. Classifier limits additionally
bound gadget depth, skipped-gap size, entry-predicate window, wrapper size and
caller count, constant-chain evidence, and dispatch case count.

The integrated analyses are:

- x86 call-target get-PC gadgets that consume, read, or adjust a pushed return;

- direct-control-flow gaps after loaded/name/ref checks;

- entry predicates, with ABI-unspecified entry flags kept as a heuristic trait
  and exact local comparisons emitted as reached/proven-unreachable facts;

- small wrapper/thunk shapes;

- same-block width-aware immediate, read-only-load, copy, arithmetic, boolean,
  shift, and high-half constant chains ending in an indirect call/jump or x86
  push/return; and

- incomplete comparison-chain dispatch maps, CFF-shaped traits, and symbolic
  dispatcher edges from exact predecessor state assignments.

`DeobfEvidenceStoreSink` normalizes every fact before admission. It retains
variations and ambiguities but transactionally rejects a newly introduced
logical contradiction involving the candidate. The provider records a semantic
key only after sink acceptance, so a rejected candidate remains eligible for a
later scan. In the integrated lifecycle, contradiction gating is limited to the
current complete provider generation plus user assertions; stale history cannot
block a new snapshot.

## rax runtime loader

`rax_loader.cpp` is IDA-free and uses `dlopen`/`dlsym`; the plugin has no
link-time dependency on librax. Loading is process-once and thread-safe.

The required surface corresponds to rax 1.1 emulation: engine lifecycle,
mapping/writes, scalar register access, bounded execution, hooks, last-exit
metadata, and context snapshots. A missing required symbol rejects the library
as a whole. The major version must match and the runtime minor version must be
at least 1.

Optional symbols are resolved without rejecting an otherwise usable library:

- decoder (`rax_decode`, API 1.2);

- stateless analysis (`rax_analyze`, API 1.3);

- memory read/unmap/translation/region operations;

- general register read/write/size operations;

- single-step and interrupt operations; and

- block, interrupt, port-I/O, and MMIO hooks.

Only a subset is consumed today. `rax_analyze` is integrated into the decoder
audit; the lifecycle simply skips it when the optional symbol is absent.

## Worker scheduler

`EmulationWorkerPool` has no IDA dependency. Its factory constructs an executor
inside each worker thread, ensuring that a rax engine is born, used, and
destroyed on one thread.

Important scheduler properties are:

- monotonically increasing tickets;

- deterministic delivery in ticket order, even if later work finishes first;

- a bounded queue in the integrated lifecycle (`2 * worker_count`), with
  non-blocking submission and timer-tick backpressure;

- generation-based cooperative cancellation;

- exactly one settled result per accepted ticket;

- retention of completed partial run evidence on cancellation; and

- idempotent shutdown and worker join before the per-IDB object is destroyed.

An in-flight `rax_emu_start` is not asynchronously interrupted. Cancellation
takes effect between bounded runs; the configured instruction and time caps are
therefore part of the shutdown guarantee.

Automatic worker count is one fewer than reported hardware concurrency, at
least one, and no more than four. Explicit configuration is capped at 64. The
small automatic cap limits memory amplification because every engine owns mapped
guest memory and a baseline context.

## Entry-state construction

`entry_state.cpp` runs on the main thread before job submission. It detects the
integer ABI from architecture and file type, enumerates real incoming call xrefs,
and asks IDA's public register tracker for proved argument values. ABI register
sets, pointer widths, stack-argument offsets, input placement, and the fallback
corpus are defined once in the IDA-free `abi_policy.*` module and shared with
`EmuDriver`.

Function type information is used to find explicit register and stack argument
locations. On i386, a bounded backward walk also recovers adjacent `push`
arguments. The walk stops at non-linear predecessors, calls, returns, block
ends, and explicit ESP changes. Unknown push operands retain their position
during the walk, but an input is submitted only if at least one value is known.
Duplicate input signatures are removed.

The fallback corpus rotates zero, one, unsigned/signed 16-bit boundaries,
sign-extended `INT16_MIN`, a mapped image pointer, a wrapping but in-range stack
pointer, and a deterministic mixed value across argument positions. The job
then includes those deterministic runs plus call-site inputs. Opaque analysis
raises the requested run count to its configured corpus; no-return analysis
raises it to at least five. Each run carries an explicit run ID and seed.

Stack arguments are placed after the saved return address on x86. Windows x64
also skips the 32-byte home area, so its fifth integer argument is written at
`entry_rsp + 8 + 32`. AAPCS32/64, RISC-V LP64, Cortex-M AAPCS, and Hexagon use
their shared policy layouts; every computed stack write must remain inside the
scratch stack or the input plan fails closed.

## Emulation driver

`EmuDriver` is IDA-free and thread-confined. Construction:

1. selects architecture/mode and ABI register IDs;

2. chooses a non-overlapping 1 MiB stack region;

3. opens an emulator backend;

4. maps image pages, unions permissions for shared pages, and copies only
   initialized byte runs;

5. maps the scratch stack read/write in strict mode;

6. probes memory-hook support; and

7. captures a bounded baseline context.

Discovery requires a valid engine, backend stepping support, and the baseline
snapshot. Every run restores the complete baseline context (guest memory and
registers), installs a sentinel return, seeds arguments, installs hooks, and
calls `rax_emu_start` with both time and count limits.

The code hook checks execute permission before retiring the next instruction,
decodes the previous instruction when possible, distinguishes a
non-fallthrough transition, records its decoded call/jump/return kind, and
captures a compact register state. If decoding is unavailable, the observed
edge is retained with `Unknown` kind rather than discarded or guessed. A source
is retained only if it belongs to the complete current function, including
tails. Targets must be within the program image at this stage.

The memory hook records image, stack, and modeled-heap accesses with a per-run
sequence number. Code-entry points and control-flow edges use the same sequence
clock, allowing consumers to require write-before-execute and
read-before-indirect-edge ordering. IDB-facing consumers later exclude
synthetic stack/heap addresses. After execution, optional `rax_mem_read`
captures merged final ranges written during that run, up to
`VIY_MAX_RUNTIME_BYTES`.

rax exposes a flat guest mapping, so viy adds strict permission checks in its
hooks. Execute denial is checked before retirement. Forbidden data writes are
rolled back to snapshot bytes, but data read/write enforcement requires
per-access memory hooks (currently provided by the x86 backend); a backend
without those hooks cannot fully enforce strict data permissions. Permission
violations currently surface through the generic stopped outcome.

Events normalize into deterministic order while preserving observations from
different run/seed pairs. Only exact duplicates within the same provenance are
removed.

## Call summaries

`call_summary.cpp` scans IDA's named list and normalizes common import/thunk,
symbol-version, and stdcall decorations. The driver models the selected memory,
string, allocation, deallocation, and termination routines listed in the
[README](../README.md#library-call-summaries).

Summary arguments follow the selected ABI. Stack-return architectures consume
the saved return slot; Windows x64 also skips the 32-byte home area. Successful
summaries write return state, stop at a hook boundary, and resume from the
rewritten PC so the next instruction receives a normal code hook. Resumptions
are capped at 256 and share the original run's total count/time budget.

Modeled memory/string sizes are capped at 1 MiB. `memmove` reads the full source
before writing the destination. `strncpy` pads with zero. Oversized or
overflowing allocations return null. An unreadable summary fails without
claiming success and the mapped target stub executes normally.

## Evidence model

`analysis_facts.*` defines 13 neutral payload kinds. An `AnalysisFact` separates
its payload from one `Evidence` observation.

Evidence contains:

- stable producer and method IDs;

- proof kind and basis-point confidence;

- optional run ID, seed, function start/end, and a required generation value;

- support addresses; and

- a human-readable detail string.

Normalization canonicalizes set-like fields and inactive variant members.
Validation rejects malformed ranges, empty or oversized values, bad enum states,
and impossible scopes. The codec is versioned, endian-independent, bounded, and
transactional: a failed decode leaves the destination unchanged.

`EvidenceStore` keys records by canonical payload bytes. Stable SHA-256 digests
are exposed as IDs but are not used alone for identity. Observations are sorted
and deduplicated without changing their provenance. Merge and serialization are
deterministic regardless of insertion order.

Corroboration counts distinct explicit run IDs, not raw observations. Static
evidence without a run can satisfy a producer-count requirement but cannot
impersonate repeated execution.

### Historical ledger and active view

The in-memory/persisted `EvidenceStore` retains complete history. Automatic IDB
and Hex-Rays consumers receive a derived active store instead.

At plug-in construction, viy collects every restored generation and initializes
a 64-bit allocator at an unused value (with collision-checked wrap handling).
Each complete native/deobfuscation scan receives one fresh generation, clears
its producer-local dedup cache, and re-emits all current facts. Its active facts
must also belong to a function still present in the bounded provider snapshot.

Function-scoped dynamic/decoder/SMIR evidence must match the current lifecycle
identity for that function. The identity changes when the whole image content,
function bytes/chunks, or complete emulation-job fingerprint changes. A
sweep-local cache hit preserves the prior identity and evidence without
rerunning rax. User assertions always remain active. Unknown function-unscoped
historical producers are retained in storage but are not live authority.

Separately, `EvidenceStore::latest_generation_view()` is a general historical
query that selects the maximum numeric generation independently for each
`(producer, function_start)`, retaining ties and function-unscoped records. The
lifecycle deliberately does not use that numeric query for authority: its exact
allocated-identity policy is safe across wrap/reopen and retains every explicit
user assertion so conflicts remain visible.

## Integrated evidence producers

| Producer | Payloads | Proof character |
|---|---|---|
| `viy.native.ida` | Targets, branch/CFG reachability, function candidates, code regions | IDA regfinder, architecture invariants, local proofs, or heuristics depending on rule |
| `viy.deobf.ida` | Targets/registers, reachability, regions, function traits, dispatch maps, CFG candidates | Bounded static/symbolic proofs or explicitly labelled structural heuristics |
| `viy.rax.emulator` | Targets, reached branches/CFG, memory access/value, register state, call observations, function outcomes | Concrete observation under an explicit run/seed and synthesized/observed entry state |
| `viy.rax.decoder` | Direct code targets | Static encoded target |
| `ida.decoder` | Direct code targets | Imported IDA processor-module result |
| `viy.decoder.audit` | Code-region disagreement candidates | Heuristic cross-decoder discrepancy |
| `viy.rax.smir` | Direct targets, resolved memory accesses, constant register results | Static SMIR proof; confidence reflects complete versus partial effect coverage |

The emulator bridge deliberately omits synthetic stack/heap addresses from the
persistent address-space schema. Runtime enrichment consumes those events
directly instead.

## Conflict semantics

Conflicts are recomputed deterministically from record payloads. Severity is:

- `Variation`: different concrete values or outcomes can legitimately occur
  across inputs;

- `Ambiguity`: competing candidates have not proved exclusion; or

- `Contradiction`: both assertions cannot be true, such as a reached and a
  proven-unreachable successor or two unique targets for one transfer kind.

The generic IDB consumer suppresses contradictions. The Hex-Rays presentation
suppresses every conflict severity because displaying one concrete value while
hiding another would mislead a user.

## Persistence protocol

`IdaEvidenceAdapter` uses three netnodes:

```text
$ viy:evidence:v1    commit marker only
$ viy:evidence:v1:a  complete envelope A
$ viy:evidence:v1:b  complete envelope B
```

An envelope contains magic, schema version, observation count, canonical
records, and a SHA-256 trailer. A write stages the inactive slot, reads it back,
compares every byte, fully decodes it, and only then updates the active marker.
The previous committed slot is retained.

Restore validates the complete active envelope. If it is corrupt, the adapter
validates and commits the fallback. If the marker itself is invalid, it validates
both slots and merges both valid ledgers so recovery cannot silently discard an
observation. It also recognizes and migrates the former adjacent-index layout.
The full historical ledger is persisted; active-view filtering is recomputed
from the current IDB snapshot before automatic application/presentation.

## Main-thread consumers

### Immediate dynamic references

`ref_discovery.cpp` classifies dynamic edges with IDA's instruction metadata.
Only indirect calls/jumps become crefs. The target must be mapped, executable,
and not an item tail; the source must be a code head. Existing refs are skipped.
Data refs likewise require a mapped non-code target and code-head source.

These additions are marked `XREF_USER`. With `VIY_MAKE_CODE`, unknown targets
are queued for code or function analysis.

### Generic evidence consumer

`evidence_apply.cpp` currently materializes three neutral fact families. Its
payload/action/confidence decision is implemented in the IDA-free
`evidence_apply_policy.*` module; the SDK adapter performs only the guarded IDB
operations:

- call/jump/table code targets after a static/symbolic/user proof at confidence
  9000, or two distinct runs at confidence 8000;

- function candidates after static confidence 7500 or two distinct runs at
  confidence 8000, provided the target is executable and unowned; and

- repeatable comments for proven-unreachable successors under the general
  actionable policy.

Contradictory payloads are skipped. Unknown/fallthrough/return/exception target
kinds are retained in the ledger but are not guessed into IDA refs.

### Runtime and legacy enrichment

`runtime_enrich.cpp`, `enrich.cpp`, and `advanced.cpp` are described in the
[README](../README.md#runtime-enrichment). `runtime_enrich_core.*` supplies the
IDA-free deterministic grouping, conflict, string-decoding, and temporal
correlation policy. The runtime pass groups exact final bytes by
`(run_id, seed)` and rejects any overlapping divergent observation before
mutation. It recognizes strict NUL-terminated and bounded Pascal8/16/32 ASCII,
UTF-8, UTF-16, and UTF-32 candidates; multi-byte prefixes use target byte order
and lengths count encoded code units. Ambiguous interpretations, malformed
Unicode, arithmetic overflow, insufficient payload, and configured-limit
violations fail closed. The legacy pass is a more direct, single-observation
recall path guarded by current IDB state.

Final memory snapshots do not identify every intermediate version of a range.
If code is written, executed, and rewritten later in the same run, ordering
proves the write preceded execution but not which intermediate bytes were
fetched.

### Hex-Rays bridge

The optional bridge builds a complete immutable annotation index before
atomically publishing it to a callback. It uses function warning collection and
cursor hints only. Callback exceptions are contained and counted. It does not
write microcode, ctree, local variables, decompiler comments, or the IDB. See
[Hex-Rays bridge](hexrays-bridge.md).

## Convergence

At epoch start viy stops old workers, snapshots current IDB state, creates a new
pool, and runs the native and deobfuscation scans. Per-function results are
applied in deterministic snapshot order. At epoch end workers are joined before
the generic evidence consumer, Hex-Rays publication, and persistence.

A sweep-local dynamic cache avoids rerunning an unchanged emulation job in a
later convergence epoch. The versioned fingerprint covers complete image
content, function bytes/chunks, the run and explicit-input corpus,
dynamic-relevant configuration, and the call-summary set. Only a successfully
completed job populates the cache. A cache hit still traverses the main-thread
per-function path with no new dynamic events, so static providers remain active.
The cache is not persisted and is cleared when a new sweep starts. Including the
whole-image content hash intentionally invalidates all jobs after any byte
change; this favors sound reuse over narrowly optimized reuse.

The convergence counter includes successful reference/code/function/string/data
type/comment/metadata changes made by integrated consumers. Evidence insertion
alone is not a database change. If the counter increased, viy waits for IDA
autoanalysis and starts a new epoch until `VIY_MAX_EPOCHS` is reached.

The plug-in-level `started` flag makes the sweep once-per-IDB-lifetime apart
from these internal epochs. There is not yet a user-facing incremental rescan
command.

## Runtime observability

The plugin emits stable, single-line `[viy]` key/value records from the main
thread. Immediate records describe lifecycle transitions, capabilities,
provider results, evidence application, persistence, and completion. Periodic
records sample the current epoch's completed/total functions, worker
availability, queued/running/ready jobs, cumulative result taxonomy, run counts,
cache hits, evidence records, mutation operations, and monotonic elapsed time.
Snapshot, native-provider, structural-provider, and evidence-application
callbacks additionally expose bounded intra-phase progress. Snapshot accounting
is exhaustive across copied/invalid/read-failed segments and
included/null/library-or-thunk/limit-excluded functions.

Worker diagnostics cross the thread boundary only inside ordered result values.
The owner aggregates at most eight distinct, bounded messages and does not call
IDA output APIs from worker threads. Cache hits and native/static-only passes
are accounted separately from actual unavailable worker results. Worker gauges
are sampled before pool destruction. Diagnostic configuration is excluded from
the semantic job fingerprint and evidence model. Pool construction is never
reported as successful dynamic capability: initialization resolves through
`initializing` to `available`, `partial`, or `unavailable`. Register-value
tracking and operand-address tracking remain separate tri-state capabilities.

`VIY_LOG_LEVEL=0..3` selects quiet, lifecycle, progress, or per-function trace
output. Progress defaults to one record per 1000 ms and is clamped to a cadence
of 100–60000 ms. Phase/terminal records bypass that cadence. Manual invocation
prints the current immutable status projection through the same formatter.
Manual invocation cannot bypass the final-autoanalysis boundary, and terminal
elapsed time is frozen before any later status projection.

Automatic evidence application does not materialize the full set of
Variation/Ambiguity conflicts. `contradicted_payload_digests()` indexes only
contradiction-capable subjects and overlapping code regions, hashes only actual
participants, and returns the exact suppression set. Its complexity is
`O(n log n + p)`, where `n` is the canonical record count and `p` contains only
contradiction-capable relations/overlapping-region pairs. Exhaustive
`detect_conflicts()` remains available for audit consumers; it caches each
canonical payload digest once and avoids copying the record ledger. Restore and
recovery paths do not compute exhaustive conflict counts when the report is
discarded.

## Decoder core

`decoder_core.*` is the IDA-free policy shared by direct-target recovery and the
decoder audit. It maps each supported `ViyArch` to a rax architecture/mode,
requires an explicit per-instruction ARM/Thumb state where appropriate, clips
decode windows to the current function chunk, validates every returned size,
flow, indirection, and target invariant, and extracts only encoded direct call
or branch targets. Its comparison result separates size, flow, and target-kind
or address disagreements.

`static_decoder.cpp` and `decoder_audit.cpp` retain the SDK-only surface:
walking IDA code heads, reading the `T` segment register, normalizing IDA
operands/flow, emitting evidence, and applying guarded xrefs. An unavailable or
malformed rax result fails closed for that instruction.

## Integrated SMIR-effect analysis

When `rax_analyze` exists, `viy_audit_decoders` calls it for each existing code
head using the same per-address architecture/mode used by the decoder audit.
`smir_analysis.cpp` reads at most 16 initialized bytes from the immutable image,
performs the ABI's sizing call, caps the required effect count at 4096, allocates
the caller-owned array, and requires an exact non-truncated second call. Summary
and effect struct sizes and ABI versions are validated before publication.

The producer stores only lossless static projections:

- encoded direct call/branch targets;

- register writes with a complete constant value and width of at most 64 bits;
  and

- memory reads/writes whose address is complete, absolute or PC-relative, and
  whose width is known.

Base/index expressions remain in the local result rather than being weakened
into guessed addresses. Complete instruction effects receive confidence 9900;
useful partial effects receive 8500. The rich-effect contract currently covers
x86-64, AArch64, RISC-V 64, and Hexagon. Other decoded modes can return a valid
unsupported/partial summary with no rich effects.

The generic evidence consumer can materialize eligible direct targets. It does
not yet turn neutral SMIR memory/register effects into IDA operand annotations;
those facts remain available to persistence, conflict analysis, and the
optional Hex-Rays view.
