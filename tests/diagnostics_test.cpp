#include "diagnostics.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace viy;

namespace {

#define CHECK(expr) do { if ( !(expr) ) { \
  std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
            << ": " #expr "\n"; std::abort(); } } while ( false )

void test_phase_names()
{
  CHECK(std::string(viy_diagnostic_phase_name(
      ViyDiagnosticPhase::WAITING_FOR_AUTOANALYSIS)) == "waiting-autoanalysis");
  CHECK(std::string(viy_diagnostic_phase_name(
      ViyDiagnosticPhase::SWEEPING_FUNCTIONS)) == "sweeping-functions");
  CHECK(std::string(viy_diagnostic_phase_name(
      ViyDiagnosticPhase::COMPLETE)) == "complete");
  CHECK(std::string(viy_diagnostic_phase_name(
      static_cast<ViyDiagnosticPhase>(255))) == "unknown");

  CHECK(std::string(viy_dynamic_capability_name(
      ViyDynamicCapability::INITIALIZING)) == "initializing");
  CHECK(std::string(viy_dynamic_capability_name(
      static_cast<ViyDynamicCapability>(255))) == "unknown");
  CHECK(viy_dynamic_capability(0, 0, 0, 0)
      == ViyDynamicCapability::OFF);
  CHECK(viy_dynamic_capability(4, 0, 0, 0)
      == ViyDynamicCapability::INITIALIZING);
  CHECK(viy_dynamic_capability(4, 3, 3, 0)
      == ViyDynamicCapability::INITIALIZING);
  CHECK(viy_dynamic_capability(4, 4, 4, 0)
      == ViyDynamicCapability::AVAILABLE);
  CHECK(viy_dynamic_capability(4, 4, 3, 1)
      == ViyDynamicCapability::PARTIAL);
  CHECK(viy_dynamic_capability(4, 4, 0, 4)
      == ViyDynamicCapability::UNAVAILABLE);
}

void test_stable_status_format()
{
  ViyRuntimeStatus status;
  status.phase = ViyDiagnosticPhase::SWEEPING_FUNCTIONS;
  status.epoch = 2;
  status.epoch_limit = 3;
  status.functions_done = 7;
  status.functions_total = 10;
  status.functions_submitted = 9;
  status.cache_hits = 1;
  status.workers_initialized = 4;
  status.workers_available = 3;
  status.workers_unavailable = 1;
  status.workers_requested = 4;
  status.jobs_queued = 2;
  status.jobs_running = 1;
  status.jobs_ready = 1;
  status.jobs_completed = 5;
  status.jobs_cancelled = 1;
  status.jobs_unavailable = 2;
  status.jobs_failed = 3;
  status.runs_requested = 24;
  status.runs_started = 23;
  status.evidence_records = 11;
  status.changes = 6;
  status.elapsed_ms = 1234;
  CHECK(viy_format_runtime_status(status)
      == "event=status phase=sweeping-functions epoch=2/3 functions=7/10 "
         "submitted=9 cache_hits=1 workers=3/4 workers_initialized=4 "
         "workers_unavailable=1 queued=2 running=1 ready=1 "
         "jobs_completed=5 jobs_cancelled=1 jobs_unavailable=2 jobs_failed=3 "
         "runs_requested=24 runs_started=23 "
         "evidence_records=11 changes=6 elapsed_ms=1234");

  CHECK(viy_format_runtime_status(ViyRuntimeStatus{})
      == "event=status phase=waiting-autoanalysis epoch=0/0 functions=0/0 "
         "submitted=0 cache_hits=0 workers=0/0 workers_initialized=0 "
         "workers_unavailable=0 queued=0 running=0 ready=0 "
         "jobs_completed=0 jobs_cancelled=0 jobs_unavailable=0 jobs_failed=0 "
         "runs_requested=0 runs_started=0 "
         "evidence_records=0 changes=0 elapsed_ms=0");
}

void test_rate_gate()
{
  CHECK(!viy_diagnostic_due(999, 0, 1000));
  CHECK(viy_diagnostic_due(1000, 0, 1000));
  CHECK(!viy_diagnostic_due(1999, 1000, 1000));
  CHECK(viy_diagnostic_due(2000, 1000, 1000));
  CHECK(viy_diagnostic_due(5, 10, 1000));
  CHECK(viy_diagnostic_due(1, 1, 1000, true));
  CHECK(viy_diagnostic_due(1, 1, 0));
}

void test_sanitization()
{
  CHECK(viy_sanitize_diagnostic("line\n\"quoted\"\\path")
      == "line 'quoted'/path");
  CHECK(viy_sanitize_diagnostic("abcdef", 5) == "ab...");
  CHECK(viy_sanitize_diagnostic("abcdef", 2) == "ab");
  CHECK(viy_sanitize_diagnostic("abcdef", 0).empty());
}

} // namespace

int main()
{
  test_phase_names();
  test_stable_status_format();
  test_rate_gate();
  test_sanitization();
  return 0;
}
