/* IDA-independent runtime diagnostics formatting and rate limiting. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace viy {

enum class ViyDiagnosticPhase : uint8_t
{
  WAITING_FOR_AUTOANALYSIS = 0,
  SNAPSHOTTING,
  NATIVE_ANALYSIS,
  DEOBFUSCATION_ANALYSIS,
  SWEEPING_FUNCTIONS,
  APPLYING_EVIDENCE,
  WAITING_FOR_CONVERGENCE,
  COMPLETE,
  SKIPPED,
};

enum class ViyDynamicCapability : uint8_t
{
  OFF = 0,
  INITIALIZING,
  AVAILABLE,
  PARTIAL,
  UNAVAILABLE,
};

struct ViyRuntimeStatus
{
  ViyDiagnosticPhase phase = ViyDiagnosticPhase::WAITING_FOR_AUTOANALYSIS;
  uint64_t epoch = 0;
  uint64_t epoch_limit = 0;
  uint64_t functions_done = 0;
  uint64_t functions_total = 0;
  uint64_t functions_submitted = 0;
  uint64_t cache_hits = 0;
  uint64_t workers_initialized = 0;
  uint64_t workers_available = 0;
  uint64_t workers_unavailable = 0;
  uint64_t workers_requested = 0;
  uint64_t jobs_queued = 0;
  uint64_t jobs_running = 0;
  uint64_t jobs_ready = 0;
  uint64_t jobs_completed = 0;
  uint64_t jobs_cancelled = 0;
  uint64_t jobs_unavailable = 0;
  uint64_t jobs_failed = 0;
  uint64_t runs_requested = 0;
  uint64_t runs_started = 0;
  uint64_t evidence_records = 0;
  uint64_t changes = 0;
  uint64_t elapsed_ms = 0;
};

const char *viy_diagnostic_phase_name(ViyDiagnosticPhase phase);
const char *viy_dynamic_capability_name(ViyDynamicCapability capability);

// Derive a truthful dynamic-engine state from one atomic worker-stat snapshot.
// requested==0 is OFF. Until every requested worker settles initialization the
// state is INITIALIZING. A complete mixed result is PARTIAL.
ViyDynamicCapability viy_dynamic_capability(
    uint64_t requested, uint64_t initialized,
    uint64_t available, uint64_t unavailable);

// Stable key=value status text. The caller supplies the "[viy]" prefix.
std::string viy_format_runtime_status(const ViyRuntimeStatus &status);

// Keep one diagnostic on one bounded log line. Control characters become
// spaces and quote/escape characters are normalized for message="..." fields.
std::string viy_sanitize_diagnostic(const std::string &text,
                                    size_t maximum_bytes = 192);

// Monotonic rate gate. Phase/terminal events pass force=true. A backwards
// clock observation emits immediately so diagnostics cannot become stuck.
bool viy_diagnostic_due(uint64_t now_ms, uint64_t last_ms,
                        uint64_t interval_ms, bool force = false);

} // namespace viy
