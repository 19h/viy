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


## Xref traversal follow-up

The next supplied profile contained 2,421 main-thread samples, including 2,289
in `viy_apply_missing`, dominated by `xrefblk_t::next_from()` and data-reference
iteration. Each existence check restarted at the first outgoing xref. As a
single source acquired N distinct targets, those checks performed O(N²) cursor
steps. Repeated observations also rewalked existing references.

Exact data/code checks now use the documented SDK
`xrefblk_t::next_from(from, after, flags)` overload to seek immediately after
`target - 1`. Address zero uses `first_from`, and ordinary code flow is checked
separately because it precedes the sorted non-flow group. This affects computed
reference application, shared code-reference insertion, and the native
provider's exact-code-reference check. It preserves existing xref types and
per-reference IDB reads; no cache hides additions or deletions by other plugins.

The primary API contract is in the pinned SDK's `src/include/xref.hpp`, at the
three-argument `next_from` overload. The new helper performs a bounded number
of cursor operations and uses O(1) auxiliary space. Kernel lookup complexity
is supplied by IDA; with logarithmic index seeks, N queries are O(N log N).

`tests/xref_lookup_test.cpp` exercises 50,001 data targets and over 100,000
queries, zero/maximal addresses, missing targets, fall-through ordering, empty
sets and intervening mutations. Its cursor deliberately has no linear-advance
overload, and operation-count checks prevent scan regressions.
`tests/ida_xref_lookup_smoke.py` also passed in an isolated, disposable IDB on
installed IDA 9.4: all queried addresses agreed with the known reference set,
including zero, code flow, and mutations. For 1,000 absent-target queries over
1,025 data refs, the Python-bound old traversal took 0.295 s and the seek took
0.00152 s (one run, approximately 194×). This measures lookup, not insertion
callbacks or complete analysis. macOS Release build, 17 CTest cases, GCC 13.4
xref regression, and the xref ASan/UBSan regression passed.

Run the licensed smoke script only on a disposable x86 IDB using
`VIY_XREF_TEST_RESULT=/path/to/result.json idat -A -S/path/to/ida_xref_lookup_smoke.py /path/to/disposable.i64`.
It creates and mutates a fixture segment at address zero.

The user's subsequent sample at 10:38:04 contained 489 main-thread samples:
361/489 = 73.8% waited in the event loop, 91/489 = 18.6% entered viy's timer,
and seven entered reference application. This is consistent with relief of
the reported main-thread monopolization; it is not a controlled end-to-end
speedup or an assessment of worker-thread CPU usage.

**Medium-impact remaining opportunity:** 41 samples entered instruction-effect
analysis, primarily RAX's JSON-producing oracle. The current pinned
`capi/src/analyze.rs::rax_analyze` always calls `decode_to_json` and then projects
SMIR JSON into effects. viy's caller already provides a preallocated effect
buffer to avoid the normal two-call sizing protocol. The public C API has no
non-JSON equivalent preserving these effects; substituting decode-only or
skipping ordinary instructions would lose evidence. A typed SMIR projection
belongs in RAX and requires separate differential validation.

Additional assumption: the arbitrary-target seek behaves as documented on the
user's alpha IDA build. The stable 9.4 disposable-IDB test validates the API
contract; the user's later sample supports improved occupancy on the alpha
build, but neither proves a hard per-callback latency bound.

## Data references into instruction tails

Read-only inspection of `libclpx.dylib` on the user's IDA 9.4 alpha confirmed
`0x30940 -> 0x3446D` as a user-marked `dr_R` reference. The target is a tail
byte of the instruction at `0x3446C`; analogous references cover all three
tail bytes of successive ARM64 instructions. The source is an `LDP` in
`ClpModel::addRows`. `is_code(get_flags(target))` is false on these tails.
The data-reference gate now checks `get_item_head(target)` before classifying
code. This rejects both instruction heads and interiors while retaining data
item interiors such as structure fields. The disposable-IDB smoke test checks
both cases and passes, as do the Release build and all 17 CTest cases.

Attribution remains unknown: Chernobog's `src/ida_analysis/evidence_apply.cpp`
contains the same target-byte guard, and `XREF_USER` does not identify the
producer. **High-impact shared defect:** either plugin can accept instruction
tails through this predicate. Existing references were not removed from the
live IDB. The assumption that viy alone inserted them is not established;
falsify it by tracing insertion callbacks with one producer enabled at a time.

## Decoder audit worker boundary

The 10:46:42 sample shows 461/714 = 64.6% of main-thread samples in viy's timer,
including 275/714 = 38.5% in instruction-effect analysis and 217/714 = 30.4% in
RAX's JSON oracle. The previous 73.8% event-loop wait fraction was one sample
window, not evidence that all later analysis phases were responsive.

The decoder audit now has three explicit stages:

1. The main thread snapshots IDA instruction heads, decoder projections,
   ARM/Thumb modes and chunk-limited decode windows into the submitted job.
2. The worker executes stateless RAX analysis against the immutable epoch image.
   The analyze/decode fallback, malformed-output rejection and rich effects
   are retained. Cancellation is checked between instructions. Static analysis
   remains available when the dynamic backend cannot emulate the image.
3. The main thread rejects results with changed bytes, item boundaries or modes,
   then records the same SMIR and decoder facts. Direct-cref application reuses
   the worker result instead of invoking RAX or walking the function again.

Dynamic-cache hits submit an audit-only job, because IDA decoder state is not
covered by the emulation cache. Snapshot scope is now the instruction model at
submission; code newly created by applying results is considered in the next
epoch. Failed/mismatched generation metadata and cancelled jobs cannot publish
stale audit results. Thread-initialization failure is reported and does not
silently move RAX work back onto the UI thread.

Result application and job submission share an 8 ms cooperative timer budget,
checked between functions. SDK snapshotting, evidence insertion and a single
function's application may exceed that target. RAX's per-instruction JSON cost
still exists on workers; this change removes it from the main-thread audit.

**High-impact bounded finding:** the old pending-queue limit excluded completed
results waiting behind a slow first ticket. The pool now also caps undelivered
jobs (pending + running + completed) at queue capacity + worker count: 3W with
the plugin's queue configuration. Thus audit result storage is O(WIE), where I
is the per-function instruction bound (65,536) and E is bounded per-instruction
effect storage. This limits retained result count, not total process memory.
The sample's 11.2 GB peak cannot establish allocation ownership; its cause is
unknown without heap instrumentation. Each emulator still owns mapped image
and snapshot state.

Validation: Release plugin build and all 18 CTest cases pass. The production
worker executor test asserts that instrumented RAX analyze/decode callbacks run
off the submitting thread, compares serialized effect evidence to direct RAX
analysis, and covers audit-only jobs, decode fallback, cancellation between
instructions, and generation mismatch. A blocked-first-ticket regression
proves backpressure despite an empty pending queue. Worker scheduling tests
pass ASan/UBSan; changed IDA-free sources also compile under Ubuntu GCC 13.3
with Release warnings-as-errors. End-to-end latency and peak-memory changes
on the user's alpha database remain unmeasured; reprofile after loading this
build to test the claim that the sampled RAX audit stack has left the UI thread.

## Saved pointers misclassified as runtime strings

The supplied `sub_10FC` listing's six alleged UTF-32LE scalars are
`[0xFFC00, 0x7FFD]` repeated three times. Pairing each low/high 32-bit word
reconstructs the same 64-bit value, `0x00007FFD000FFC00`, three times. The
`STP X8, X8` / `STR X8` sequence saves a variadic cursor pointing above the
current stack frame. Ten identical observations corroborate saved pointer
bytes; they do not establish a string.

The automatic detector now rejects candidates overlapping aligned pointer
words that reference known image segments or the actual synthetic scratch
region. Scratch-region selection is shared with the emulator, including its
fallback mappings. Rejection also covers shifted candidate suffixes. Null
words remain eligible as string terminators. Range preparation costs O(R log R)
for R ranges; pointer classification costs O((B/P) log R) for B observed bytes
and P-byte pointers, with O(R + B/P) auxiliary storage. Existing bounded string
decoding costs are unchanged; known pointer interiors skip decoding entirely.

Private-use and noncharacter scalars are also excluded from automatic string
recognition. This is a conservative recognition policy, not a claim that
private-use characters are invalid Unicode. Their semantics require external
agreement; see [Unicode 17.0, sections 23.5 and 23.7](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-23/).
Writer comments now identify string candidates and state that runs agree on
bytes. Existing IDB comments are not automatically removed.

Regression coverage includes the exact ten-run example, a pointer whose halves
are both assigned CJK scalars, both byte orders, 32-bit pointer words in an
unaligned observation, adjacent real text, and legitimate CJK UTF-32. The old
detector fails the exact-example regression; the corrected detector passes.
An ARM64 disposable-IDB plugin run with repeated saved frame pointers produced
no runtime-string annotation and retained SMIR evidence.

Assumptions and limits: the displayed UTF-32 scalars faithfully represent the
observed bytes (the listing independently reconstructs the pointer); mapped
ranges describe the captured image and shared scratch selection (covered by
range/fallback tests). **Medium-impact tradeoff:** private-use text and text
whose bytes also encode mapped pointers are suppressed without additional
type/consumer evidence. Unmapped or unaligned pointer values remain a possible
source of ambiguity; the detector is not a general proof of string semantics.

## Redundant direct-transfer comments

`viy_enrich` previously tested only `CF_CALL | CF_JUMP` before adding a resolved
target comment. These features identify transfers, not indirection. It now
excludes instructions with `o_near` or `o_far` operands, whose encoded targets
IDA already displays. Register/memory indirect-transfer annotations remain.
The additional scan costs O(EK) time and O(1) space for E observed edges and
the SDK's fixed maximum K operands. Existing comments remain in the database.

Assumption: the processor module represents encoded transfer destinations as
near/far operands. Disposable x86-64 and ARM64 IDBs test that assumption: all
9 and 10 direct transfers respectively have no `viy: ->` annotation, while
each fixture retains one indirect-transfer annotation and persisted SMIR
evidence. The Release plugin build and all 18 CTest cases pass.

**Medium-impact adjacent finding:** runtime pointer-table comments currently
describe a heuristic, not a recovered type. Two adjacent slots, each with one
observed in-image target across at least two runs and no conflicting writes,
can qualify when at least one target is executable or a same-function execution
edge follows a matching pointer read. That correlation is not def-use proof
and does not distinguish direct from indirect edges. The repeatable comment
is attached to the first data slot and can therefore appear at multiple code
references. Adjacent globals/import slots can satisfy these conditions; the
object type in the supplied screenshot is unknown.
