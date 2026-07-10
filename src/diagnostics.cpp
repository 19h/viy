#include "diagnostics.hpp"

#include <algorithm>

namespace viy {

const char *viy_diagnostic_phase_name(ViyDiagnosticPhase phase)
{
  switch ( phase )
  {
    case ViyDiagnosticPhase::WAITING_FOR_AUTOANALYSIS: return "waiting-autoanalysis";
    case ViyDiagnosticPhase::SNAPSHOTTING:             return "snapshotting";
    case ViyDiagnosticPhase::NATIVE_ANALYSIS:          return "native-analysis";
    case ViyDiagnosticPhase::DEOBFUSCATION_ANALYSIS:   return "deobfuscation-analysis";
    case ViyDiagnosticPhase::SWEEPING_FUNCTIONS:       return "sweeping-functions";
    case ViyDiagnosticPhase::APPLYING_EVIDENCE:        return "applying-evidence";
    case ViyDiagnosticPhase::WAITING_FOR_CONVERGENCE:  return "waiting-convergence";
    case ViyDiagnosticPhase::COMPLETE:                 return "complete";
    case ViyDiagnosticPhase::SKIPPED:                  return "skipped";
  }
  return "unknown";
}

const char *viy_dynamic_capability_name(ViyDynamicCapability capability)
{
  switch ( capability )
  {
    case ViyDynamicCapability::OFF:          return "off";
    case ViyDynamicCapability::INITIALIZING: return "initializing";
    case ViyDynamicCapability::AVAILABLE:    return "available";
    case ViyDynamicCapability::PARTIAL:      return "partial";
    case ViyDynamicCapability::UNAVAILABLE:  return "unavailable";
  }
  return "unknown";
}

ViyDynamicCapability viy_dynamic_capability(
    uint64_t requested, uint64_t initialized,
    uint64_t available, uint64_t unavailable)
{
  if ( requested == 0 )
    return ViyDynamicCapability::OFF;
  if ( initialized < requested )
    return ViyDynamicCapability::INITIALIZING;
  if ( available == 0 )
    return ViyDynamicCapability::UNAVAILABLE;
  if ( unavailable != 0 || available < requested )
    return ViyDynamicCapability::PARTIAL;
  return ViyDynamicCapability::AVAILABLE;
}

std::string viy_format_runtime_status(const ViyRuntimeStatus &s)
{
  std::string out = "event=status phase=";
  out += viy_diagnostic_phase_name(s.phase);
  out += " epoch=" + std::to_string(s.epoch) + "/" + std::to_string(s.epoch_limit);
  out += " functions=" + std::to_string(s.functions_done) + "/"
      + std::to_string(s.functions_total);
  out += " submitted=" + std::to_string(s.functions_submitted);
  out += " cache_hits=" + std::to_string(s.cache_hits);
  out += " workers=" + std::to_string(s.workers_available) + "/"
      + std::to_string(s.workers_requested);
  out += " workers_initialized=" + std::to_string(s.workers_initialized);
  out += " workers_unavailable=" + std::to_string(s.workers_unavailable);
  out += " queued=" + std::to_string(s.jobs_queued);
  out += " running=" + std::to_string(s.jobs_running);
  out += " ready=" + std::to_string(s.jobs_ready);
  out += " jobs_completed=" + std::to_string(s.jobs_completed);
  out += " jobs_cancelled=" + std::to_string(s.jobs_cancelled);
  out += " jobs_unavailable=" + std::to_string(s.jobs_unavailable);
  out += " jobs_failed=" + std::to_string(s.jobs_failed);
  out += " runs_requested=" + std::to_string(s.runs_requested);
  out += " runs_started=" + std::to_string(s.runs_started);
  out += " evidence_records=" + std::to_string(s.evidence_records);
  out += " changes=" + std::to_string(s.changes);
  out += " elapsed_ms=" + std::to_string(s.elapsed_ms);
  return out;
}

std::string viy_sanitize_diagnostic(const std::string &text, size_t maximum_bytes)
{
  if ( maximum_bytes == 0 )
    return {};

  const bool truncated = text.size() > maximum_bytes;
  size_t content_limit = std::min(text.size(), maximum_bytes);
  if ( truncated && maximum_bytes >= 3 )
    content_limit = maximum_bytes - 3;

  std::string out;
  out.reserve(maximum_bytes);
  for ( size_t i = 0; i < content_limit; ++i )
  {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if ( c < 0x20u || c == 0x7fu )
      out.push_back(' ');
    else if ( c == static_cast<unsigned char>('"') )
      out.push_back('\'');
    else if ( c == static_cast<unsigned char>('\\') )
      out.push_back('/');
    else
      out.push_back(static_cast<char>(c));
  }
  if ( truncated && maximum_bytes >= 3 )
    out += "...";
  return out;
}

bool viy_diagnostic_due(uint64_t now_ms, uint64_t last_ms,
                        uint64_t interval_ms, bool force)
{
  if ( force || interval_ms == 0 || now_ms < last_ms )
    return true;
  return now_ms - last_ms >= interval_ms;
}

} // namespace viy
