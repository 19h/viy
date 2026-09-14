# Post-autoanalysis deobfuscation performance

## Profile and root cause

The user-supplied `/tmp/viy.log`, sampled on 2026-09-14 at 10:18:33 +0200,
contains 678 main-thread samples. All enter
`on_analysis_done -> begin_epoch -> DeobfAnalysisProvider::analyze_database`;
676 enter the provider's fact emission path. The screenshot is a separate
sample of the same path. These sample counts identify a hot stack; they are
not an end-to-end runtime measurement.

For each candidate, the old sink copied the entire `EvidenceStore`, added the
candidate to that copy, flattened the accumulated observations, re-added the
active observations into another ledger, and detected every conflict. This
repeated payload normalization, serialization, hashing and allocation across
all accumulated facts. With one observation per unrelated payload, emitting
N facts required at least quadratic total work.

## Change and preserved behavior

`EvidenceStore::new_contradiction` maintains a lazy index of contradiction-capable
subjects: code-target source/kind, branch/CFG endpoints, return behavior by
function, dispatch site, and code-region intervals. Each candidate compares
only relevant existing records. Payloads that cannot produce contradictions
bypass the index. Index entries refer to stable map nodes; copies rebuild their
own index, moves retain it, and clear/replacement retire it. Direct additions
and merges update an existing index. The persisted representation is unchanged.

Generation zero selects all observations. Otherwise only the requested
generation and user assertions participate. Reactivating a historical payload
still checks for newly introduced conflicts. An already-active payload can
receive additional observations without manufacturing a new payload conflict.
The selected conflict, including diagnostic ordering, matches the exhaustive
before/after gate. Variations and ambiguities remain admissible.

Insertion hashes the canonical payload bytes it already encoded, eliminating
the second encoding formerly performed by `stable_digest`.

The first relevant query builds the index in O(N log N) time and O(N) space.
Subsequent subject queries cost O(log N + K), excluding payload sizes and
observation filtering, where K is the relevant bucket size. Region queries use
start-address ordering and the maximum stored interval length to bound their
search; widely overlapping/very long intervals can still require O(N) visits.
Unrelated-subject insertion sequences are O(N log N), excluding byte processing.
High-cardinality competing facts on one subject can still require quadratic
aggregate work. Hashes remain SHA-256 identifiers; canonical bytes remain the
identity key, so deduplication does not depend on hash collision assumptions.

The plugin schedules deobfuscation on its existing UI timer, processing at most
64 functions or 8 ms per callback, checked after each function. All SDK access
remains on the main thread. Autoanalysis activity pauses these batches. The
function list, generation and provider state persist across ticks, and progress
is cumulative. Headless execution retains the existing inline completion path.
A single function may exceed 8 ms; the existing instruction/block caps apply.

## Reproducible evidence

`tests/evidence_store_test.cpp` compares indexed queries against reconstructed,
generation-filtered before/after ledgers over twelve shuffled sequences covering
all existing conflict fixtures, including preexisting contradictions, user
assertions, and copy/move/replacement. A 20,000-subject regression verifies zero
re-indexing, unrelated comparisons, and query hashes during incremental insertion.
Additional checks cover interval endpoints at zero and UINT64_MAX, adjacent
half-open regions, and digest equivalence. Existing sink regressions cover
invalid observations, duplicates, stale generations and historical reactivation.

Standalone sink benchmark: Apple Clang 21, `-O3 -std=c++17`, ARM64 macOS,
old sources from `ff3acea`, new sources from this change. One timed run per row;
other builds were active, so these are illustrative wall times, with no
statistical uncertainty estimate. Both implementations check the emitted record
count. The benchmark excludes IDA decoding, timer idle time and persistence.

| Independent facts | Count | Before / s | After / s |
|---|---:|---:|---:|
| Function return constants | 1,000 | 0.447 | 0.000661 |
| Function return constants | 2,000 | 1.89 | 0.00108 |
| Function return constants | 4,000 | 7.71 | 0.00223 |
| Reached branch edges | 1,000 | 0.402 | 0.000704 |
| Reached branch edges | 2,000 | 1.66 | 0.00132 |
| Reached branch edges | 4,000 | 6.92 | 0.00260 |

Compile against either source revision (`SRC` points at that revision's `src`):

```sh
/usr/bin/clang++ -O3 -std=c++17 -I"$SRC" tests/deobf_sink_benchmark.cpp \
  "$SRC/analysis_facts.cpp" "$SRC/evidence_store.cpp" \
  "$SRC/deobf_analysis_store.cpp" -o /tmp/viy-sink-benchmark
/tmp/viy-sink-benchmark
```

Verification: the macOS ARM64 Release plugin builds and all 16 CTest cases
pass. GCC 13.4 compiles all 16 test targets under the strict Release warning
flags; all 12 executables without a RAX link pass in Linux. The evidence-store
regressions also pass with AddressSanitizer and UndefinedBehaviorSanitizer,
including queries through transferred indexes after move construction and
assignment. The four Linux RAX-linked targets received compile checks, not
Linux execution, in this local check.

## Assumption register and bounded findings

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| A1 | The supplied sample represents the reported stall. | Both supplied profiles identify the same synchronous deobfuscation stack. End-to-end speedup on the user's IDB remains unknown until reprofiled. |
| A2 | Conflict severity/identity depends on payloads, while view membership depends on observations. | Differential tests reconstruct and compare the exhaustive gate across every existing conflict fixture and multiple generations. New payload kinds must extend the contradiction index if they add contradiction rules. |
| A3 | SDK reads remain on the main thread; the timer can yield between functions. | Plugin compiles against the pinned SDK; timer and headless paths retain the existing scheduler contract. Interactive latency after rebuilding remains unmeasured. |

- **High impact:** this removes the sampled repeated-ledger work and the database-wide deobfuscation callback. Initial image snapshotting, native analysis, and final evidence application still have synchronous work and may become subsequent bottlenecks; this profile does not establish their cost.
- **Medium impact:** one expensive function or many competing regions can exceed a timer time target. The 8 ms target is cooperative, not a hard preemption deadline.
- **Low impact:** the index adds O(N) transient pointer/index storage and is never serialized.

Quality gates: no normative claim is required; assumptions and falsification
probes are explicit; the sampled hotspot and scheduling path are covered;
timings use seconds and are scoped to the measured component; generation,
ordering and lifetime edge cases have differential regressions; provenance is
the supplied profile and repository source; scope limits are recorded above.
