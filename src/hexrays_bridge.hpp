/*
 * hexrays_bridge.hpp -- optional, non-destructive Hex-Rays evidence view.
 *
 * The public header deliberately has no IDA/Hex-Rays includes.  This keeps viy
 * buildable with SDK installations that do not ship hexrays.hpp and makes the
 * evidence-selection policy independently testable.  The implementation uses
 * decompiler warnings and cursor hints only; it never writes to the IDB or
 * mutates microcode/ctree.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace viy {

namespace analysis {
class EvidenceStore;
}

enum class HexRaysAnnotationKind : uint8_t
{
  ControlFlow = 1,
  Reachability,
  ConcreteValue,
  Memory,
  String,
  Function,
  Dispatch,
  Call,
};

struct HexRaysBridgeOptions
{
  // A single static/symbolic/user assertion at this confidence is sufficient.
  // Dynamic observations must instead meet the corroboration policy below.
  uint16_t minimum_confidence = 8500;
  size_t minimum_distinct_runs = 2;
  size_t maximum_warnings_per_function = 12;
  size_t maximum_hint_lines = 10;
  size_t maximum_value_bytes = 24;
  bool publish_function_warnings = true;
  bool publish_cursor_hints = true;
};

// Producer-neutral, immutable materialization used by the runtime bridge.  It
// is public so the safety/confidence policy can be tested without an IDA or
// Hex-Rays runtime.
struct HexRaysEvidenceAnnotation
{
  uint64_t address = 0;
  std::vector<uint64_t> function_starts;
  HexRaysAnnotationKind kind = HexRaysAnnotationKind::Function;
  uint16_t confidence = 0;
  size_t distinct_runs = 0;
  size_t distinct_producers = 0;
  uint8_t priority = 0; // lower is more important when output must be capped
  std::string text;
};

struct HexRaysBridgeStats
{
  size_t records_considered = 0;
  size_t records_accepted = 0;
  size_t records_conflicted = 0;
  size_t records_below_policy = 0;
  size_t annotations_built = 0;
  size_t warning_lines_published = 0;
  size_t hints_published = 0;
  size_t callback_failures = 0;
};

std::vector<HexRaysEvidenceAnnotation> viy_build_hexrays_annotations(
    const analysis::EvidenceStore &store,
    const HexRaysBridgeOptions &options = {},
    HexRaysBridgeStats *stats = nullptr);

class HexRaysEvidenceBridge
{
public:
  HexRaysEvidenceBridge();
  ~HexRaysEvidenceBridge();

  HexRaysEvidenceBridge(const HexRaysEvidenceBridge &) = delete;
  HexRaysEvidenceBridge &operator=(const HexRaysEvidenceBridge &) = delete;

  // start() is intentionally explicit: callers should invoke it only when the
  // opt-in VIY_HEXRAYS_BRIDGE setting is enabled.  Failure is benign (for
  // example, an architecture without a compatible decompiler).
  bool start(const HexRaysBridgeOptions &options = {},
             std::string *reason = nullptr);
  void stop();

  // Build an immutable snapshot before publishing it to callbacks.  Call this
  // from IDA's main thread after an EvidenceStore merge/convergence step.
  void publish(const analysis::EvidenceStore &store);

  bool installed() const;
  HexRaysBridgeStats stats() const;

  static bool compiled_with_hexrays_sdk();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace viy
