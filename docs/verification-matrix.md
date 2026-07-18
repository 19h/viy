# Requirements and verification matrix

This matrix is an audit of the repository, not a promise inferred from filenames.
“Integrated” means the implementation is in the plugin target and invoked from
the lifecycle. “Automated” means a repository test directly exercises the
property. “Harness” means a reproducible test exists but is not part of the
default CTest run. “Build-only” means compilation catches interface drift but
not semantic behavior.

## Reproducible verification commands

The IDA-free default suite is:

```sh
cmake -S . -B build-dev \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DVIY_TEST_STRICT_WARNINGS=ON
cmake --build build-dev --parallel
ctest --test-dir build-dev --output-on-failure
```

Sanitizer configuration is separate because CMake sanitizer flags are attached
at target creation time:

```sh
cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DVIY_TEST_STRICT_WARNINGS=ON \
  -DVIY_TEST_SANITIZERS=ON
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

The real-IDB persistence/provider and Hex-Rays probes are opt-in and require a
licensed IDA; the Hex-Rays probe is a successful skip when no compatible
licensed decompiler is available:

```sh
cmake -S . -B build-ida-test \
  -DVIY_IDA_INTEGRATION_TESTS=ON \
  -DVIY_IDAT=/path/to/idat
cmake --build build-ida-test --parallel
ctest --test-dir build-ida-test -L integration --output-on-failure
```

The rax C ABI is verified in its submodule:

```sh
cargo test -p rax-capi --manifest-path vendor/rax/Cargo.toml
```

Test-only environment inputs are intentionally separate from plugin
configuration:

| Variable | Harness default | Purpose |
|---|---:|---|
| `VIY_REQUIRE_RAX_TESTS` | unset | Makes real-engine portions fail instead of skip; CMake sets it to `1` for the three targets linked to embedded rax. |
| `IDAT` | required | Text-mode IDA used by the licensed shell harnesses. |
| `BUILD_DIR` | repository `build-dev` | Plugin artifact directory used by the licensed shell harnesses. |
| `VIY_IDA_TEST_DIR` | `/tmp/viy-evidence-persistence` | Disposable isolated IDAUSR/database/log root. |
| `VIY_IDA_HEXRAYS_TEST_DIR` | `/tmp/viy-hexrays-bridge` | Disposable isolated IDAUSR/database/log root for the decompiler probe. |
| `VIY_EVIDENCE_MODE` | `verify` | Internal phase selector for the multi-process persistence probe. |
| `VIY_EVIDENCE_STATE` | required by the persistence probe | JSON handoff between corruption/recovery processes. |
| `VIY_SMOKE_WAIT_MS` | `5000`, minimum `250` | Delay before the worker smoke script exits IDA. |
| `VIY_HEXRAYS_SMOKE_WAIT_MS` | `10000`, minimum `2000` | Deadline for the real decompiler callback to render a published annotation. |

## Default CTest inventory

| CTest name | Source tests | What it directly proves |
|---|---|---|
| `viy.evidence` | `tests/evidence_store_test.cpp`: `test_sha256`, `test_every_payload_codec`, `test_validation`, `test_decoder_robustness`, `test_dedup_merge_and_determinism`, `test_generation_lifecycle_regression`, `test_latest_generation_view`, `test_conflicts`, `test_persistence_adapter` | Standard SHA-256 vectors; all 13 payload codecs; normalization/validation; transactional bounded decoding; deterministic merge/serialization; copy/move/generation regression; general historical latest-generation view; every conflict class; exact fast-vs-exhaustive contradiction-set equivalence including asymmetric dispatch and cross-payload CFG cases; abstract persistence errors and replace/merge behavior. |
| `viy.evidence_lifecycle` | `tests/evidence_lifecycle_test.cpp`: allocator, exact-active-policy, and disappearance tests | Collision-free generation allocation across restored values including `UINT64_MAX`; exact provider/function authority; removed/out-of-scope/unscoped handling; user-assertion retention; historical immutability; retirement without tombstones. |
| `viy.evidence_apply_policy` | `tests/evidence_apply_policy_test.cpp`: all payload/action, code-target, proof-threshold, dynamic-corroboration, function, branch, contradiction, non-contradictory-conflict, and high-cardinality fast-path tests | All 13 payload variants and target kinds; exact 9000/8000/7500 boundaries; two-run corroboration; configuration gates; contradiction suppression; preservation of mere ambiguity/variation; and 2048 distinct register-value variants producing 2048 decisions with zero contradiction pair checks/digests. |
| `viy.config` | `tests/viy_config_test.cpp` | Defaults; exact false tokens; boolean overrides; C-style integer prefixes; whitespace; overflow, negative, empty, and trailing-junk rejection; zero fallbacks; and every numeric clamp. |
| `viy.diagnostics` | `tests/diagnostics_test.cpp` | Stable phase/capability names and key/value formatting; all dynamic worker states; initialized/unavailable gauges; zero-total status; exact 999/1000 ms rate boundary; forced/backwards-time behavior; and bounded single-line diagnostic sanitization/truncation. |
| `viy.emulation_workers` | `tests/emulation_workers_test.cpp`: `test_ordered_delivery`, `test_generation_cancellation`, `test_unavailable_and_backpressure`, `test_cooperative_shutdown`, plus fingerprint assertions | Worker-count bounds, out-of-order completion with in-order delivery, ticket monotonicity, generation cancellation/reuse, unavailable executor settlement, bounded-queue backpressure, cooperative shutdown/join, and deterministic job-fingerprint invalidation. |
| `viy.emu_evidence` | `tests/emu_evidence_test.cpp`: normalization, evidence bridge, real summaries, and real-engine policy tests | Deterministic event normalization; image-only evidence projection; target endianness/register byte order; call/CFG/outcome facts; real x86-64 and i386 summaries; same-engine run isolation; strict RX-write/RW-execute denial with permissive controls; exact instruction-budget termination; jump/return classification; and decode-unavailable `Unknown` fallback. |
| `viy.abi_policy` | `tests/abi_policy_test.cpp` | Shared SysV64, Win64, i386, AAPCS32/64, RISC-V 64, Cortex-M, and Hexagon layouts; register/stack placement and endianness; Win64 home-area/fifth-argument placement; overrides and invalid plans; deterministic scalar/image/stack/mixed corpus; large-count wrapping and address-overflow guards. |
| `viy.program_model` | `tests/program_model_test.cpp` | Segment lookup/gaps, initialized masks, permissions, non-contiguous and shared tails, deterministic exact-entry precedence, saturating sizes, and rebase-invariant/content-sensitive function and whole-image hashes. |
| `viy.hexrays_bridge` | `tests/hexrays_bridge_test.cpp`: four policy/lifecycle tests | Static confidence and dynamic corroboration gates, minimum-two-run floor, conflict/non-observation suppression, deterministic bounded rendering/scope, and fail-closed behavior when compiled without Hex-Rays. |
| `viy.smir_analysis` | `tests/smir_analysis_test.cpp` | Real rax 1.3 two-call effect negotiation; x86-64 constant register, absolute/PC-relative memory, and direct-call projections; unsupported x86-32 degradation; truncated-buffer ABI behavior; wrapper rejection of an inexact second call. |
| `viy.decoder_core` | `tests/decoder_core_test.cpp` | Architecture/mode and fail-closed unknown ARM/Thumb state; chunk-bounded windows; malformed result/invariant rejection; direct-target and disagreement policy; and real x86-64 nop/call/jump/conditional/truncated decoding. |
| `viy.deobf_analysis` | `tests/deobf_analysis_test.cpp`: `test_get_pc`, `test_gap`, `test_entry_predicates`, `test_wrapper`, `test_constants_and_push_ret`, `test_dispatch`, `test_contradiction_gate` | Bounded classifiers, important false-positive guards, width-aware constant transformations, incomplete dispatch/CFF candidates, and validating sink behavior for contradictions versus ambiguity/corroboration. |
| `viy.runtime_enrich_core` | `tests/runtime_enrich_core_test.cpp` | Exact `(run_id, seed)` write/string grouping; divergent-overlap rejection; strict ASCII/UTF-8/UTF-16/UTF-32; Pascal8/16/32 target-endian length prefixes; surrogate/code-unit handling; caps/overflow/ambiguity/scopes/determinism; and same-run sequence-ordered write-before-execute/read-before-edge gates. |

`viy.emu_evidence`, `viy.smir_analysis`, and `viy.decoder_core` link the same
rax static archive as the plugin. CMake sets `VIY_REQUIRE_RAX_TESTS=1` for all
three, so their real-engine portions cannot silently skip in the default CTest
run.

With `VIY_IDA_INTEGRATION_TESTS=ON`, CTest additionally registers two serial
licensed targets:

| CTest name | Direct coverage |
|---|---|
| `viy.ida_evidence_persistence` | Multi-process A/B netnode commit/recovery/migration; disabled-sweep restore; actual dynamic-cache hit; absolute no-dref gate; separate native/deobf producer provenance with embedded rax explicitly disabled; levels 0/1/2/3; ordered phases/subphases; exhaustive snapshot accounting; exact worker/run/cache taxonomy; early-manual autoanalysis guard; and frozen delayed terminal snapshots. |
| `viy.ida_hexrays_bridge` | Real Hex-Rays initialization, native-evidence publication, warning callback/rendering, a live recent cfunc through plug-in teardown, structured lifecycle/subphase invariants, and clean `qexit`; successful skip only when a compatible licensed decompiler is unavailable. |

## Static-link audit execution on 2026-07-18

The following commands were run against the implementation documented here:

| Check | Result |
|---|---|
| Release arm64 plugin build against IDA SDK 9.4 with `VIY_TEST_STRICT_WARNINGS=ON` | Passed; `build/viy.dylib` linked at 13,772,408 bytes. Cargo and its C build-script dependencies received `MACOSX_DEPLOYMENT_TARGET=10.15`. |
| `otool -L`, `nm -gU`, and full `nm` artifact audit | No `librax` load command; no exported `_rax_*` symbol; `_rax_analyze`, `_rax_decode`, and `_rax_version` present as local text symbols. |
| IDA-free CTest in `build` | 14/14 passed. CMake set `VIY_REQUIRE_RAX_TESTS=1` for the embedded-rax emulation, SMIR, and decoder-core targets, so their real rax portions did not silently skip. |
| `cargo test -p rax-capi --manifest-path vendor/rax/Cargo.toml` | 53/53 passed, plus 0 doc tests. |
| `BUILD_DIR=build tests/run_ida_evidence_persistence.sh` | Passed multi-process real-IDAT restore/corruption/marker/legacy phases, actual dynamic-cache reuse, the `VIY_WANT_DREFS=0` gate, separate native/deobf `VIY_RAX_DISABLE=1` producer-provenance runs, levels 0/1/2/3, ordered subphases, exhaustive counter identities, worker-selection policy accounting, trace/terminal taxonomy equality, pre-autoanalysis manual guard, and two delayed frozen terminal snapshots. Enabled runs reported `rax_version="0.1.0 (rax-capi ABI 1.3.0)"`. |
| `BUILD_DIR=build tests/run_ida_hexrays_bridge.sh` | Passed with Hex-Rays 9.4.0.260717: a real `[viy]` native-evidence warning rendered at 100% confidence, its cfunc remained live through `qexit`, structured observability invariants held, and callback teardown completed cleanly. |
| Immediate no-change rebuild | Passed in 0.46 seconds wall time; the always-run Cargo target completed its dependency check in 0.20 seconds without relinking the plugin. |

The plugin build emitted two non-fatal toolchain/SDK warnings: the selected
libc++ deployment platform is no longer supported, and the build targets
macOS 11 while the supplied `libida.dylib` targets macOS 15. These are
environment compatibility warnings, not test failures, but a release build
should align its deployment target with the installed IDA SDK.

## Analysis and lifecycle requirements

| Requirement | Integrated implementation | Verification | Status and remaining limitation |
|---|---|---|---|
| Native analysis remains useful with rax disabled | `viy.cpp` creates native/deobfuscation providers before calling `rax_load`; `begin_epoch` admits either provider without rax | `viy.ida_evidence_persistence` sets `VIY_RAX_DISABLE=1` and checks persisted producer provenance in separate native-only and deobf-only real-IDAT runs | Automated in the opt-in licensed harness for the x86 fixture. Individual native regfinder/ARM rules and downstream mutations are not covered there. |
| Native scans are read-only during production | `NativeAnalysisProvider` emits through `NativeFactSink`; all mutations are downstream | Architectural separation; real native-only provider provenance | Integrated. The real fixture proves the provider emitted facts, but a full before/after IDB snapshot isolating scan-time writes is still needed. |
| Deobfuscation scans are read-only and bounded | `DeobfAnalysisProvider` emits through a sink; finite instruction/block/classifier ceilings | `viy.deobf_analysis`; real rax-disabled deobf-only provider provenance | Core classifiers, contradiction gate, and one real x86 IDA-adapter path are automated. ARM adapter translation, downstream mutation, and a scan-time no-write snapshot remain untested. |
| Complete function chunks are snapshotted and scanned | `FuncRange::chunks`; `viy_snapshot`; native, emulator membership, static decoder, decoder audit, and opaque pass iterate chunks | `viy.program_model`; plugin build | Pure lookup covers non-contiguous/shared tails, exact-entry priority, gaps, and overflow. Live IDA chunk extraction and each adapter's full-chunk traversal remain build-only. |
| Function identity is rebase-stable and content-sensitive | `viy_function_byte_hash`, hash version 1, relative chunk topology, loaded-byte state | `viy.program_model` | Rebase invariance and byte, topology, mask, permission, bitness, architecture, and endian sensitivity are automated for production core code. Live snapshot generation carry-forward remains an IDA lifecycle concern. |
| Bounded fixed-point convergence after IDB changes | `change_count`, `waiting_for_auto`, `begin_epoch`, `VIY_MAX_EPOCHS` | Implementation inspection; plugin build | Integrated, untested semantically. A real-IDAT fixture should cause a first-epoch function/code discovery and assert second-epoch pickup plus maximum-epoch termination. |
| Configuration is bounded and malformed integers fail closed | IDA-free `viy_config.cpp`; post-parse clamps and nonzero execution defaults | `viy.config` | Defaults, booleans, whitespace, C-style bases, negative/empty/trailing-junk/overflow rejection, and every numeric bound are automated. Environment changes after plug-in construction are intentionally not reloaded. |
| Evidence generations remain unique after restore/reopen | Lifecycle scans restored generations and allocates collision-free 64-bit IDs; providers accept externally assigned generations | `viy.evidence_lifecycle`; real multi-process persistence reopen | Collision avoidance including `UINT64_MAX`, wrap, exact authority, removed functions, disappeared facts, and historical immutability are automated. A real IDB fixture that injects an adversarial high historical generation before new application is still absent. |
| Independent off-thread engines; main-thread IDA access | `EmulationWorkerPool`, `RaxEmulationExecutor`, immutable `ProgramImage`, main-thread `process_function` | `viy.emulation_workers`; worker smoke runs inside `viy.ida_evidence_persistence` | Scheduler is automated and the licensed CTest exercises real workers through plug-in teardown. It does not instrument every SDK call to assert thread identity. |
| Deterministic ordered application | Ticket-ordered pool delivery and snapshot-index lookup in `viy.cpp` | `test_ordered_delivery`; malformed ticket/function guards are implementation-audited | Core ordering automated. The lifecycle's mismatch recovery is not directly injected/tested. |
| Bounded queue and non-blocking UI behavior | Queue capacity `2 * workers`, `try_submit`, timer budget | `test_unavailable_and_backpressure` | Queue behavior automated; UI responsiveness itself has no latency test. |
| Unchanged dynamic jobs are not redundantly rerun across convergence epochs | Sweep-local fingerprint cache covers image/function/job/input/config/summary semantics and accepts only completed jobs | Fingerprint determinism/invalidation in `viy.emulation_workers`; licensed real-IDAT log requires a nonzero cache hit | Actual reuse is automated. A real convergence run that changes bytes and proves the corresponding miss/invalidation is still absent. |
| Headless completion | Timer-registration failure enters inline drain while engines remain workers | `tests/ida_worker_smoke.py`, invoked by the licensed persistence CTest | Real headless completion is automated; explicit forced coverage of both timer-registration branches is not. |
| Worker cancellation and safe unload | Generation token, bounded rax calls, `stop_workers`, destructor join | `test_generation_cancellation`, `test_cooperative_shutdown` | Core automated. An in-flight real rax cancellation is bounded by run caps but not force-interrupted or directly tested. |

## Evidence requirements

| Requirement | Integrated implementation | Verification | Status and remaining limitation |
|---|---|---|---|
| Producer-neutral typed facts | `analysis_facts.hpp` defines 13 payload variants and independent `Evidence` | `test_every_payload_codec` | Automated for every current variant. |
| Provenance retains producer/method/proof/confidence/run/seed/function/generation/support | `Evidence`, `EvidenceScope` | Codec round trips; support-summary assertions in `test_dedup_merge_and_determinism` | Automated, including 64-bit provenance values. |
| Stable identity across processes/platforms | Canonical versioned encoding plus SHA-256 | Standard hash vectors, round trips, insertion-order-independent blobs | Automated for host-independent byte encoding assumptions. No cross-platform CI result is recorded here. |
| Transactional, bounded decode | Fact/store codec limits; destination assigned only after full validation | Every strict prefix, byte mutations under sanitizers, size/observation limits, corrupt/checksummed-malformed envelopes | Automated. |
| Semantic dedup does not erase provenance | Payload canonical bytes key records; observations sorted independently | Insert/duplicate/second-run/merge tests | Automated. |
| Corroboration uses distinct explicit runs | `is_corroborated` | Positive two-run and negative three-run cases; Hex-Rays one-run floor | Automated. |
| Conflict classes distinguish variation, ambiguity, contradiction | `EvidenceStore::detect_conflicts` | `test_conflicts` covers every current `ConflictType`, deterministic order, partial calls, and non-observation | Automated. |
| Superseded generations remain historical but lose automatic authority | `ActiveEvidencePolicy` compares exact current function/provider generation identities, retains all user assertions, and rejects unknown unscoped history | `viy.evidence_lifecycle`; `test_latest_generation_view` separately tests the general historical query | Exact reopen-safe allocation, removed/out-of-scope functions, current provider-scoped/unscoped facts, unknown unscoped rejection, user assertions, disappearance without tombstones, and non-mutating derivation are automated. Real-IDB reopen/application remains integration-test work. |
| Generic IDB consumer is contradiction-aware and confidence-gated | `evidence_apply_policy.*` decides; `evidence_apply.cpp` mutates | `viy.evidence_apply_policy` | All payloads, target kinds, exact confidence/run thresholds, configuration gates, contradiction suppression, and ambiguity/variation handling are automated in production policy code. Real-IDB cref/function/comment application remains untested. |
| Dynamic events enter the neutral ledger | `evidence_bridge.cpp` | `test_evidence_bridge`; summary fixture also asserts call/CFG/memory values | Automated for image facts, endianness, final-write attribution, function outcomes, and synthetic-address exclusion. |
| Persistence envelope is deterministic and detects corruption | `EvidenceStore::serialize/deserialize` | Evidence unit suite | Automated without IDA. |
| Netnode persistence is staged, verified, and crash-recoverable | `IdaEvidenceAdapter` marker plus separate A/B slot nodes; lifecycle persists full history and derives active authority separately | `viy.ida_evidence_persistence`: `tests/run_ida_evidence_persistence.sh` and `tests/ida_evidence_persistence.py` | Opt-in licensed CTest covers active-slot corruption, retained-slot fallback, invalid-marker merge, legacy-layout migration, disabled-sweep restore, real cache reuse, the absolute no-dref gate, and rax-disabled provider provenance. |
| Restore works while sweep is disabled | Constructor restores before `VIY_ENABLED` gate | Real-IDAT harness uses `VIY_ENABLED=0` during recovery modes | Covered when the opt-in harness is run. |

## Dynamic exploration and ABI requirements

| Requirement | Integrated implementation | Verification | Status and remaining limitation |
|---|---|---|---|
| Per-run isolation | Baseline `rax_context_save`/restore resets guest memory and registers before every run | `viy.emu_evidence` writes in run A and reads pristine state in run B on the same real engine | Directly automated on x86-64. Cross-backend context semantics remain capability-gated. |
| Hard instruction/time bounds | `max_insns`, `timeout_ms`, bounded resumption loop | Real x86-64 self-loop stops at exactly seven retired instructions with `RAX_STOP_COUNT` | Instruction-count enforcement is automated. A deterministic real wall-clock timeout and the 256-resumption boundary are not directly tested. |
| Strict guest permissions | Snapshot permissions plus pre-retirement execute checks and memory-hook data checks/forbidden-write rollback | Real x86-64 RX-write and RW-execute denials, each with a permissive-mode control | Automated on the x86 backend. rax's flat guest regions do not enforce permissions natively; data enforcement depends on per-access hooks, so non-hook backends cannot fully enforce it. Permission stops are currently reported generically as `RAX_STOP_STOPPED`. |
| Deterministic fallback corpus | Shared `abi_policy.*` scalar boundaries and mapped pointers | `viy.abi_policy` | Zero/one/u16-max/i16-max/sign-extended i16-min/image/in-range wrapping-stack/mixed values, determinism, seed variation, large counts, and invalid stack ranges are automated. |
| Call-site-derived inputs | `entry_state.cpp` uses xrefs, regfinder, function types, and bounded i386 push walk | Plugin build; i386 raw register input is tested at the driver boundary | Integrated, mostly build-only. No IDAT test asserts extracted call-site plans for each ABI. |
| SysV versus Windows x64 | File type chooses the shared ABI layout; driver and entry adapter consume it | `viy.abi_policy`; SysV x86-64 real summaries | Register sets and Win64 fifth-argument placement at `entry_rsp + 8 + 32` are automated in pure production policy. A real PE/Win64 engine fixture and IDA extraction test remain absent. |
| i386 stack arguments and custom registers | Driver stack-argument lookup; entry adapter push walk and typed ECX/EDX | Real i386 memcpy summary and explicit ECX override | Driver behavior automated; IDA extraction remains build-only. |
| AAPCS32/64, RISC-V, Cortex-M, Hexagon argument registers | Shared `abi_policy.*` layouts used by entry construction and the driver | `viy.abi_policy`; plugin build | Register counts/order, widths, stack offsets, and placement are automated. Real per-architecture emulation and IDA extraction remain backend/environment dependent. |
| Classified dynamic call/jump/return edges | rax decode in code hook; typed and sequenced `ExecEdge` | `viy.emu_evidence` real call, jump, return, and decode-null fixtures | Automated on x86-64; an unavailable decoder preserves the edge as `Unknown`. Cross-architecture classifications are not covered. |
| Exact final writes and transient address scopes | Shared event sequence, `rax_mem_read`, `MemoryBytes`, IMAGE/STACK/HEAP/OTHER | Real summaries and isolation; `viy.runtime_enrich_core`; normalization/evidence bridge | Real x86-64/i386 image and modeled-heap behavior plus pure deterministic IMAGE/STACK/HEAP grouping are automated. A real stack-final-string fixture remains absent. |
| Call-summary semantics | Selected libc/C++/termination models | `test_real_summaries` | Automated with real rax for memcpy overlap-safe memmove, memset, strcpy/strncpy padding, strlen/strcmp, malloc/calloc overflow, repeated allocation, free, termination, and unreadable fallback. Name collection/canonicalization from a real IDB is build-only. |
| Summary containment | 1 MiB model cap, allocation overflow checks, 256 resumptions sharing count/time budget | Oversized allocation/overflow and repeated summaries partially covered | Bounds are implementation-audited; exact 1 MiB and resumption-limit boundary cases are absent. |

## IDB mutation and enrichment requirements

| Requirement | Integrated implementation | Verification | Status and remaining limitation |
|---|---|---|---|
| Missing refs are add-only and deduplicated | `viy_try_add_cref`, `viy_apply_missing` | Plugin build; source audit | Integrated, no automated real-IDB xref test. Immediate dynamic refs intentionally need only one guarded observation. |
| New code targets are mapped/executable/non-tail instruction starts | Reference and evidence consumers | Source audit | Integrated. `viy_try_add_cref` accepts an unknown executable target and queues code; it does not require a pre-existing instruction head. This is intentional but should be tested with hostile data. |
| Legacy pointer/data/string/comment enrichment preserves defined items | `enrich.cpp` checks unknown data, stored pointer bytes, names, existing comments | Plugin build | Integrated, no unit/IDAT assertions. |
| Runtime final values require two distinct run/seed pairs | `runtime_enrich_core.*` write/string groups; runtime pointer/edge groups | `viy.runtime_enrich_core` | Duplicate observations from one pair do not corroborate; a different seed with the same run ID does. Exact grouping is automated, while the resulting IDB mutations are not. |
| Any divergent overlapping final value blocks mutation | Production `range_has_conflict` policy used by every runtime mutation path | `viy.runtime_enrich_core` | Equal overlaps, divergent overlaps, disjoint scopes/ranges, empty candidates, and overflow fail-closed behavior are automated. Real-IDB mutation fixtures remain absent. |
| NUL/Pascal ASCII/UTF-8/UTF-16/UTF-32 runtime strings | Strict decoders, at least four characters, target-endian Pascal8/16/32 prefixes | `viy.runtime_enrich_core` | Both target byte orders, surrogate pairs, invalid/overlong Unicode, encoded-unit lengths, prefix endianness, caps, overflow, multiple strings, deterministic scope ordering, and ambiguous-layout rejection are automated. IDA string-item creation is not. |
| Stack/heap/runtime-only strings become comments, not IDB items | `apply_runtime_strings` scope and segment gates | Pure scope grouping in `viy.runtime_enrich_core`; source audit | Recognition/provenance are automated, but real IDB item-versus-comment behavior remains untested. |
| Runtime byte patches are explicit, bounded, and compare against pristine snapshot | `patch_runtime_range`, shared `PatchBudget`, default-off configuration | Source audit | Integrated, untested in IDA. This opt-in path needs before/after and concurrent-change regression tests. |
| Executable-byte patches require write/execute evidence | `apply_smc`; shared sequence-aware `write_then_execute_runs` | `viy.runtime_enrich_core` | Same `(run_id, seed)`, overlapping range, and strict write-before-execute ordering are automated. IDA patch/reanalysis is not; final snapshots still cannot identify which intermediate bytes executed after multiple rewrites. |
| Pointer table requires stable contiguous slots and useful target/correlation | `stable_pointers`, `apply_pointer_cluster`; sequence-aware `read_precedes_edge` | `viy.runtime_enrich_core`; source audit | Same-run/seed strict read-before-edge ordering and negative cases are automated. Cluster/item/offset creation in a real IDB remains untested. |
| Orphan functions require corroborated call edges and guarded code | `apply_orphan_functions`; generic candidate consumer | Source audit | Integrated, untested in IDA. |
| Tail mutation never guesses boundaries | `apply_tail_candidates` only shares an existing exact tail | Source audit | Integrated, untested; default mutation is off. |
| Switch mutation is explicit and labelled incomplete | `advanced.cpp::do_switches` | Plugin build | Integrated, untested; default off. It uses observed target cardinality, not a complete dispatch proof. |
| Stack purge requires returning-run consensus | Consensus in `viy.cpp`, i386-only checks in `advanced.cpp` | Source audit | Integrated, untested in IDA. Every outcome, with at least two, must return with the same delta. |
| No-return metadata requires conclusive multi-run agreement | Minimum-five scheduled baseline corpus; every completed outcome must be definitive/non-returning, with at least three outcomes | Source audit | Integrated, untested. Modeled termination and HLT/shutdown count as definitive; timeout/fault do not. |
| Argument-register and opaque results remain comments | `advanced.cpp` | Plugin build | Integrated, untested; opaque comments describe corpus coverage, not proof. |

## Static decoding, architecture, and decompiler requirements

| Requirement | Integrated implementation | Verification | Status and remaining limitation |
|---|---|---|---|
| Static direct-target recovery is optional by rax capability | `decoder_core.*` policy; `rax_loader` optional `decode`; `static_decoder.cpp` adapter | `viy.decoder_core`; plugin build | Fake and real x86 direct-call/jump/conditional target extraction, malformed results, and chunk truncation are automated. IDA head traversal/xref application remains untested. |
| ARM/Thumb mode follows IDA per instruction | Core requires explicit ARM/Thumb state; adapters read `get_sreg("T")` | `viy.decoder_core`; plugin build | Little/big-endian ARM, Thumb, unknown-state failure, and Cortex-M Thumb-only policy are automated. A real IDA interworking fixture remains absent. |
| Decoder audit records size/flow/target disagreement without directly rewriting regions | `decoder_core.*` comparison; `decoder_audit.cpp` adapter | `viy.decoder_core`; plugin build | Size, flow, target-kind/address, incomparable, malformed, and real x86 agreement/disagreement cases are automated. IDA operand normalization/evidence emission is not. Encoded targets may later be materialized by the evidence consumer. |
| rax 1.3 SMIR effects are negotiated safely and emitted as static evidence | `smir_analysis.cpp` is invoked by the per-head decoder audit; strict count/struct/version/truncation validation | `viy.smir_analysis`; vendored rax C-ABI tests | Integrated and automated on x86-64 for constants, absolute/PC-relative memory, direct calls, unsupported-mode degradation, and truncation. AArch64/RISC-V/Hexagon viy-consumer fixtures are absent. |
| Conservative architecture detection | `program_model.cpp` processor IDs/names; RV64 only | Plugin build | Integrated. Cortex-M is recognized only by a dedicated ID/name, not generic Thumb firmware; per-architecture IDAT tests are absent. |
| Dynamic backends fail independently | Engine open, stepping, baseline, memory-hook, and optional-read gates | Source audit; worker unavailable test | Core fail-closed behavior automated with fake executors. Real backend capability combinations are not matrix-tested. |
| Hex-Rays feature is opt-in and non-mutating | `hexrays_bridge.cpp` warning/hint callbacks only | `viy.hexrays_bridge`; licensed `viy.ida_hexrays_bridge` | Policy is automated. The real x86-64 IDAT test renders a `[viy]` header warning from native evidence, retains the resulting cfunc through `qexit`, and verifies clean teardown; it skips only when no compatible licensed decompiler exists. Cursor hints, other decompiler architectures, and unload with an actually open GUI pseudocode widget remain untested. |
| Hex-Rays suppresses weak/conflicting evidence | Immutable annotation builder | All policy tests | Automated, including the non-weakenable two-run floor. |

## Expansion status

| Expansion | Repository evidence | Runtime status | Work required before claiming support |
|---|---|---|---|
| rax 1.3 stateless SMIR effects | Vendored `rax_analyze` ABI and Rust tests; `src/smir_analysis.*` validates caller-owned sizing/ABI records and maps proved direct targets, resolved absolute/PC-relative accesses, and constant registers | Integrated in the per-head decoder-audit walk and an embedded-rax CTest target | Add AArch64/RISC-V/Hexagon viy-consumer fixtures and decide whether/how neutral memory/register effects should become IDA operand annotations. |
| Bounded deobfuscation analysis | `src/deobf_analysis_core.*`, IDA adapter/store, and `tests/deobf_analysis_test.cpp` cover get-PC, jump gaps, entry predicates, wrappers, constant chains, push/return, dispatch candidates, and contradiction gating | Integrated as default-on `VIY_DEOBF`; pure CTest plus a real x86 deobf-only/rax-disabled provider-provenance run | Add broader x86 and ARM IDB fixtures for downstream crefs/comments, false-positive resistance, and read-only scan snapshots. Incomplete dispatch maps intentionally remain non-mutating evidence. |

## Safety policy summary

| Finding | Default action | Minimum gate | Opt-in mutation |
|---|---|---|---|
| Observed indirect cref/dref | Add guarded missing user ref | One concrete observation plus mapped/source/type guards | None |
| Neutral code-target fact | Add guarded cref | Static/symbolic/user confidence 9000, or 2 runs at 8000; no contradiction | None |
| Function candidate | Create only unowned executable entry | Static confidence 7500, or 2 runs at 8000; no contradiction | Controlled by `VIY_FUNCTION_RECOVERY`, default on |
| Proven-unreachable neutral fact | Repeatable comment | Actionable proof/corroboration; no contradiction | None |
| Runtime string/table/function | Item/comment/function depending on scope | Exact agreement in 2 distinct `(run_id, seed)` pairs and no overlap conflict | Function promotion controlled by `VIY_FUNCTION_RECOVERY` |
| Runtime bytes | No patch | Exact agreement in 2 distinct `(run_id, seed)` pairs, pristine IDB comparison, budget; executable bytes also need a same-run write-before-execute correlation | `VIY_APPLY_RUNTIME_BYTES=1` |
| Tail candidate | Comment | Corroborated edge and guarded target | `VIY_TAIL_RECOVERY=1`, and only an existing exact tail |
| Switch | No switch | At least two observed targets; labelled incomplete | `VIY_SWITCH=1` |
| No-return | Comment/count only | Every completed run definitive/non-returning, at least 3 outcomes; at least 5 baseline runs scheduled | `VIY_SET_NORET=1` sets metadata |
| Opaque predicate | No comment | Exactly one successor reached by the configured corpus | `VIY_OPAQUE=1` enables comment only |
| Hex-Rays evidence | No presentation | Static/symbolic/user 8500 or 2 runs at 8500; suppress every conflict | `VIY_HEXRAYS_BRIDGE=1`; never mutates |

## Priority verification gaps

The highest-value missing tests, in order, are:

1. real-IDB mutation fixtures for NUL/Pascal runtime strings, executable-byte
   patch/reanalysis, pointer tables, orphan functions, tails, and the generic
   evidence cref/function/comment adapter, including changed-IDB rejection;

2. before/after IDB snapshots that isolate native and deobfuscation scan-time
   behavior, plus real regfinder and ARM/AArch64 adapter fixtures;

3. convergence fixtures that require a second epoch, hit the maximum-epoch
   bound, and change image bytes to prove a real dynamic-cache invalidation;

4. IDA call-site extraction and real-engine fixtures for every ABI, especially
   PE/Windows x64 and non-x86 data-permission behavior;

5. IDA-facing decoder fixtures for xref application, discrepancy evidence, and
   ARM/Thumb interworking;

6. real GUI Hex-Rays cursor-hint/open-widget unload tests and licensed
   cross-architecture decompiler coverage; and

7. AArch64/RISC-V/Hexagon viy-side SMIR consumer fixtures and a policy decision
   for neutral memory/register effect annotations.
