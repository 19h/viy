# Optional Hex-Rays evidence bridge

The bridge is disabled by default. Set `VIY_HEXRAYS_BRIDGE=1` to publish viy's
accepted evidence in compatible Hex-Rays pseudocode views. It adds two
decompiler-local presentations:

- gated evidence lines in the function-header warning area; and
- address-specific evidence in the cursor hint.

The presentation can include resolved control-flow targets, proved branch
reachability, concrete memory/register values, dispatch maps, function
outcomes, and call observations. Every line reports its confidence and, where
available, its distinct run/producer support.

## Safety policy

The bridge consumes an immutable snapshot of the producer-neutral
`EvidenceStore`. A fact is eligible only when it has either a high-confidence
static, symbolic, or user proof, or the same payload was observed in at least
two explicit runs at the configured minimum confidence. Merely failing to
observe a branch is never presented as unreachability. Both sides of every
detected conflict—including concrete-value variation and candidate ambiguity—
are suppressed. Function warnings and item hints are capped to keep hostile or
pathological evidence stores from flooding pseudocode.

It does not modify microcode, ctree, local-variable metadata, decompiler user
comments, function types, IDB bytes, names, references, functions, or any other
database state. Callback failures are contained at the ABI boundary and do not
abort decompilation.

## Availability and lifecycle

`hexrays_bridge.hpp` has no decompiler dependency. The implementation detects
`hexrays.hpp` at compile time and can be forced into its inert implementation
with `VIY_WITH_HEXRAYS_SDK=0`. At runtime it calls
`init_hexrays_plugin(0)` and installs a callback only if a compatible
decompiler responds. Absence of a decompiler is a benign, fail-closed result.
The callback is removed before the bridge object is destroyed or the viy
plugin unloads.

The opt-in licensed integration smoke (`VIY_IDA_INTEGRATION_TESTS=ON`, CTest
name `viy.ida_hexrays_bridge`) runs the SDK-enabled plugin under real IDAT,
decompiles the x86-64 fixture's complementary-branch function, and requires a
`[viy]` warning in the generated pseudocode header. It then exits with the
rendered cfunc still retained, exercising callback removal during per-IDB
teardown. The test reports a successful skip when no compatible licensed decompiler is
available; once a decompiler initializes, missing annotation or abnormal
teardown is a hard failure.

The owner should call `publish(evidence_store)` on IDA's main thread after an
evidence merge or convergence epoch. Publication constructs a complete new
index first and then atomically replaces the callback snapshot, so a callback
never observes a partially updated ledger.

## Intentional limitations

- The bridge presents concrete-value and indirect-target *hints*; it does not
  rewrite microcode to propagate constants or force indirect calls/gotos. A
  concrete trace is path- and entry-state-dependent, so such rewrites require
  a stronger universal proof than the current ledger encodes.
- Evidence with no function scope is associated with a pseudocode function
  only when its subject address lies in the decompiler's own microcode ranges.
- Header warnings are bounded and may report that lower-priority accepted
  items were omitted. Cursor hints remain available for accepted items at the
  selected address.
- If the selected processor has no compatible Hex-Rays decompiler, or the SDK
  was built without `hexrays.hpp`, viy's native and rax analysis continue but
  no pseudocode annotations are installed.
- The bridge does not initiate decompilation or refresh existing views. New or
  naturally refreshed pseudocode consumes the latest published snapshot.
- The licensed text-mode smoke retains a real rendered cfunc through teardown,
  but deliberately does not call the UI-only `open_pseudocode()` API from
  IDAT. Unload with an actually open GUI widget remains a manual lifecycle
  check; headless widget creation is not a supported proxy for it.

## Integration API

Create one `viy::HexRaysEvidenceBridge` per IDB/plugin instance. When the
opt-in setting is enabled, call `start()`, retain it for the plugin lifetime,
call `publish()` after evidence changes, and call `stop()` before releasing the
IDB state. `start()` can be retried if Hex-Rays was unavailable earlier.
