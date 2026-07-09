# Read-only deobfuscation evidence provider

`deobf_analysis` is an additional, producer-neutral IDA analysis source. It is
deliberately separate from `native_analysis`: the latter already covers IDA
regfinder targets, ARM64 zero-register branches, opposite conditional pairs,
local x86 CF/ZF proofs, orphan/function-interior call targets, and decoder or
legacy-prefix discrepancies.

## Bounded recognition rules

The provider implements these bounded recognition shapes:

- `call` targets beginning with `pop reg`, `mov reg,[sp]`, `add [sp],imm`, or
  positive `add sp,imm`, including bounded register-delta and `push reg; ret`
  continuation recovery. Other callers, CFG joins, calls, and intervening
  control transfers reject the proof. Ordinary `call $+5` remains IDA's job.
- Forward unconditional branches over a configured small, loaded range. A
  data-region candidate is emitted only when every skipped byte is unnamed,
  has no inbound reference, and is not a function entry.
- Entry-window conditional branches before a local arithmetic-flag definition.
  As entry EFLAGS are ABI-unspecified, this is annotation evidence only; it
  never declares either edge unreachable. A local exact constant followed by
  `cmp/test` is evaluated width-correctly and may prove an outcome.
- Small wrapper shape: one direct call and optional return (including a known
  non-returning callee), no conditional flow, no global write, bounded callers,
  no function tails. Plumbing-only direct transfers additionally yield a thunk
  trait.
- Constant update/load chains over `mov`, copies, read-only scalar loads,
  address loads, add/sub/xor/and/or/shift, and ARM `movt`. State is confined to
  one CFG block and killed on calls/unknown writes. A minimum two-step chain is
  required for indirect targets; adjacent immediate `push; ret` is exact by
  itself.
- Connected equality/inequality comparison chains over one state register are
  emitted as incomplete `DispatchMapFact` candidates. Loop-backed maps with
  moderate selector entropy get a separate CFF-shape trait. A single-successor
  predecessor that fixes the state register can yield a symbolic shortcut CFG
  candidate.

The provider also implements standalone constant `push; ret` recognition,
fixed-width arithmetic (including wraparound and signed-condition evaluation),
ARM constant chains, and a transactional contradiction gate.

## Excluded behavior

The following behaviors are not implemented by this read-only provider:

- `del_items`, `create_byte`, `create_insn`, stack-point changes, cref changes,
  function-tail changes, outlining flags, comments, and all other IDB mutation.
- Hex-Rays ctree/microcode constant folding, write hiding, goto conversion,
  dominance/def-use based CFF rewrites, and dispatcher rewiring. Those require
  the separately optional Hex-Rays evidence consumer and must remain decompile-
  local unless a stronger mutation policy is explicitly enabled.
- CF/ZF, opposite-condition, ARM zero-register, orphan-function, and
  redundant-prefix passes, because `native_analysis` already implements them.
- Cross-block constant propagation through joins. Without SSA/path predicates,
  that would turn alternatives into false sole-target assertions.
- A `complete=true` dispatcher map. Static comparison-chain shape does not prove
  that exception, indirect, or dynamically-computed destinations are absent.

## Safety and evidence policy

All output is an `AnalysisFact` with producer `viy.deobf.ida`, method identity,
proof kind, confidence, function/generation scope, and supporting addresses.
The provider does not mutate the IDB. `DeobfEvidenceStoreSink` validates each
fact against a prospective copy of the ledger. Its active-generation view
contains observations from the current complete static scan plus every
`UserAsserted` observation; generation zero selects the conservative full-
history view. A fact is suppressed only when its observation introduces a new
`Contradiction` in that view. Historical observations remain persisted and can
conflict in the full audit ledger without vetoing a newer snapshot. Existing
payloads are still staged because a new observation can reactivate a stale
payload, while corroboration of an already-active conflict is admitted because
it introduces no new contradiction. Variations and ambiguities remain
available to downstream policy.

Skipped-byte and wrapper classifications are heuristics. Constant comparisons,
same-block constant targets, and structurally complete push-return gadget
targets use static proof strength. Dispatcher maps always remain incomplete.

Scans cover every IDA function chunk. Function, instruction, block, gadget,
gap, and dispatch-case budgets are deterministic and independently bounded.
Per-function canonical payload keys suppress duplicates; `advance_epoch`,
`invalidate_function`, and `reset` provide explicit incremental lifecycle.

## Intended integration wiring

The integration owner should add these plugin sources:

```text
src/deobf_analysis_core.cpp
src/deobf_analysis_store.cpp
src/deobf_analysis.cpp
```

and add an IDA-free test executable from:

```text
src/analysis_facts.cpp
src/evidence_store.cpp
src/deobf_analysis_core.cpp
src/deobf_analysis_store.cpp
tests/deobf_analysis_test.cpp
```

One plugmod/IDB instance should own, in this lifetime order:

```cpp
DeobfEvidenceStoreSink deobf_store_sink(evidence_store);
DeobfAnalysisProvider deobf_provider(deobf_store_sink);
```

Run `deobf_provider.analyze_database(options)` after the ordinary native scan
and before the generic evidence consumer. Advance its epoch with the rest of
the convergence epoch and invalidate a function when its generation/bytes
change. Merge `DeobfAnalysisStats` and `DeobfEvidenceStoreReport` into the
diagnostic summary. No special fact consumer is required: the existing generic
evidence application policy can consume safe fact kinds and ignore annotation-
only `FunctionTraitKind::Other` records.

## Standalone verification

```sh
c++ -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Wconversion \
  -Wsign-conversion -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -Isrc \
  src/analysis_facts.cpp src/evidence_store.cpp \
  src/deobf_analysis_core.cpp src/deobf_analysis_store.cpp \
  tests/deobf_analysis_test.cpp -o /tmp/viy-deobf-analysis-test
ASAN_OPTIONS=detect_leaks=0 /tmp/viy-deobf-analysis-test
```

`src/deobf_analysis.cpp` also compiles and links against the public IDA SDK 9.3
without Hex-Rays headers and uses only public SDK interfaces.
