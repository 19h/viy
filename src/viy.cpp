/*
 * viy.cpp — plugin lifecycle, observability, and the chunked sweep.
 *
 * viy is a multi-IDB, database-modifying plugin. IDA instantiates one
 * plugmod per open database; in its constructor viy hooks HT_IDB and waits for
 * the first auto-analysis pass to finish (idb_event::auto_empty_finally). It
 * then snapshots the program and submits immutable function jobs to independent
 * off-thread rax engines. The UI timer drains results in deterministic function
 * order; every IDA query and database mutation remains on the main thread. If
 * embedded rax is disabled or a backend cannot be driven, native/static
 * providers still run. Bounded, non-modal lifecycle/progress diagnostics are emitted from the
 * main thread to IDA's Output window and headless log.
 */
#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <pro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <funcs.hpp>

#include "rax_loader.hpp"
#include "viy_config.hpp"
#include "diagnostics.hpp"
#include "program_model.hpp"
#include "emu_driver.hpp"
#include "emulation_workers.hpp"
#include "emulation_rax_executor.hpp"
#include "entry_state.hpp"
#include "call_summary.hpp"
#include "analysis_facts.hpp"
#include "evidence_store.hpp"
#include "evidence_lifecycle.hpp"
#include "ida_evidence_store.hpp"
#include "native_analysis.hpp"
#include "deobf_analysis.hpp"
#include "runtime_enrich.hpp"
#include "evidence_bridge.hpp"
#include "evidence_apply.hpp"
#include "decoder_audit.hpp"
#include "hexrays_bridge.hpp"
#include "ref_discovery.hpp"
#include "static_decoder.hpp"
#include "enrich.hpp"
#include "advanced.hpp"

using namespace viy;

//-----------------------------------------------------------------------------
struct viy_t;

struct viy_idb_listener_t : public event_listener_t
{
  viy_t *owner = nullptr;
  ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//-----------------------------------------------------------------------------
struct viy_t : public plugmod_t
{
  struct WorkerJobInfo
  {
    size_t index = 0;
    uint64_t fingerprint = 0;
    size_t requested_runs = 0;
  };
  struct FunctionEvidenceIdentity
  {
    uint64_t byte_hash = 0;
    uint64_t generation = 0;
  };
  ViyConfig cfg;
  viy_idb_listener_t idb;
  qtimer_t timer = nullptr;

  ProgramImage img;
  const RaxApi *api = nullptr;
  std::shared_ptr<const ProgramImage> worker_image;
  std::unique_ptr<EmulationWorkerPool> worker_pool;
  std::map<uint64_t, WorkerJobInfo> worker_jobs; // ticket -> immutable snapshot entry
  std::map<uint64_t, uint64_t> dynamic_cache; // function start -> semantic job identity
  size_t dynamic_cache_hits = 0;

  size_t next = 0;         // next function-entry index to submit/process
  size_t funcs_done = 0;
  size_t epoch_funcs_done = 0;
  int epoch = 0;
  bool waiting_for_auto = false;
  bool inline_mode = false;
  uint64_t epoch_change_base = 0;
  bool can_static = false;
  bool can_native = false;
  bool can_deobf = false;
  std::vector<EmuCallSummary> call_summaries;
  analysis::EvidenceStore evidence;
  analysis::EvidenceGenerationAllocator generation_allocator;
  uint64_t prior_content_hash = 0;
  bool have_prior_content_hash = false;
  std::map<uint64_t, FunctionEvidenceIdentity> function_evidence_identities;
  std::set<uint64_t> provider_function_starts;
  uint64_t provider_generation = 0;
  IdaEvidenceAdapter evidence_adapter;
  std::unique_ptr<NativeEvidenceStoreSink> native_store_sink;
  std::unique_ptr<NativeAnalysisFactAdapter> native_adapter;
  std::unique_ptr<NativeAnalysisProvider> native_provider;
  NativeAnalysisStats native_stats;
  std::unique_ptr<DeobfEvidenceStoreSink> deobf_store_sink;
  std::unique_ptr<DeobfAnalysisProvider> deobf_provider;
  DeobfAnalysisStats deobf_stats;
  RuntimeEnrichStats rstats;
  EvidenceBridgeStats bridge_stats;
  EvidenceApplyStats evidence_stats;
  DecoderAuditStats decoder_stats;
  HexRaysEvidenceBridge hexrays;
  RefStats stats;          // from the emulation (indirect) pass
  RefStats sstats;         // from the static-decode (direct) pass
  EnrichStats estats;      // from the value-derived enrichment pass
  AdvStats astats;         // from the function-level advanced analyses
  bool started = false;
  bool finished = false;

  ViyDiagnosticPhase diagnostic_phase =
      ViyDiagnosticPhase::WAITING_FOR_AUTOANALYSIS;
  std::chrono::steady_clock::time_point diagnostic_start =
      std::chrono::steady_clock::now();
  uint64_t terminal_elapsed_ms = 0;
  bool terminal_elapsed_valid = false;
  uint64_t last_progress_ms = 0;
  EmulationWorkerStats last_worker_stats;
  bool worker_initialization_reported = false;
  ProgramSnapshotStats snapshot_stats;
  uint64_t jobs_completed = 0;
  uint64_t jobs_cancelled = 0;
  uint64_t jobs_unavailable = 0;
  uint64_t jobs_failed = 0;
  uint64_t runs_requested = 0;
  uint64_t runs_started = 0;
  std::map<std::string, size_t> worker_diagnostics;
  std::string completion_reason = "stable";
  std::string last_skip_reason;

  viy_t();
  virtual ~viy_t();
  virtual bool idaapi run(size_t) override;

  void on_analysis_done();
  bool begin_epoch();
  void initialize_generation_allocator();
  uint64_t allocate_generation();
  void assign_function_generations();
  void assign_emulation_generations();
  void snapshot_provider_function_starts();
  analysis::EvidenceStore active_evidence_view() const;
  uint64_t change_count() const;
  EmulationJob build_emulation_job(const FuncRange &func) const;
  void process_function(size_t index, EmulationJobResult result);
  bool log_at_least(ViyLogLevel minimum) const;
  uint64_t current_diagnostic_elapsed_ms() const;
  uint64_t diagnostic_elapsed_ms() const;
  void log_event(ViyLogLevel minimum, const std::string &event) const;
  void log_progress_event(const std::string &event, bool force = false);
  void log_snapshot_progress(const ProgramSnapshotProgress &progress);
  void log_native_progress(const NativeAnalysisProgress &progress);
  void log_deobf_progress(const DeobfAnalysisProgress &progress);
  void log_evidence_progress(const EvidenceApplyProgress &progress);
  void report_worker_initialization();
  ViyRuntimeStatus runtime_status() const;
  void emit_status(bool force = false,
                   ViyLogLevel minimum = ViyLogLevel::PROGRESS);
  void set_diagnostic_phase(ViyDiagnosticPhase phase,
                            const char *detail = nullptr);
  void record_worker_result(const EmulationJobResult &result,
                            size_t requested_run_count);
  void log_skip(const char *reason);
  void stop_workers();
  void start_sweep();
  bool process_batch(int count); // true => more entries remain
  void finish();
};

namespace {

const char *enabled_word(bool enabled)
{
  return enabled ? "on" : "off";
}

const char *arch_name(ViyArch arch)
{
  switch ( arch )
  {
    case ViyArch::X86_16:  return "x86-16";
    case ViyArch::X86_32:  return "x86-32";
    case ViyArch::X86_64:  return "x86-64";
    case ViyArch::ARM64:   return "aarch64";
    case ViyArch::ARM32:   return "aarch32";
    case ViyArch::RISCV64: return "riscv64";
    case ViyArch::CORTEX_M: return "cortex-m";
    case ViyArch::HEXAGON: return "hexagon";
    case ViyArch::UNSUPPORTED: break;
  }
  return "unsupported";
}

const char *worker_status_name(EmulationJobStatus status)
{
  switch ( status )
  {
    case EmulationJobStatus::COMPLETED:   return "completed";
    case EmulationJobStatus::CANCELLED:   return "cancelled";
    case EmulationJobStatus::UNAVAILABLE: return "unavailable";
    case EmulationJobStatus::FAILED:      return "failed";
  }
  return "unknown";
}

const char *native_capability_name(NativeCapabilityState state)
{
  switch ( state )
  {
    case NativeCapabilityState::Unknown:     return "unknown";
    case NativeCapabilityState::Available:   return "available";
    case NativeCapabilityState::Unavailable: return "unavailable";
  }
  return "unknown";
}

NativeCapabilityState merge_native_capability(
    NativeCapabilityState left, NativeCapabilityState right)
{
  if ( left == NativeCapabilityState::Unavailable
    || right == NativeCapabilityState::Unavailable )
  {
    return NativeCapabilityState::Unavailable;
  }
  if ( left == NativeCapabilityState::Available
    || right == NativeCapabilityState::Available )
  {
    return NativeCapabilityState::Available;
  }
  return NativeCapabilityState::Unknown;
}

const char *snapshot_stage_name(ProgramSnapshotStage stage)
{
  switch ( stage )
  {
    case ProgramSnapshotStage::SEGMENTS:  return "segments";
    case ProgramSnapshotStage::FUNCTIONS: return "functions";
    case ProgramSnapshotStage::COMPLETE:  return "complete";
  }
  return "unknown";
}

const char *native_progress_stage_name(NativeAnalysisProgressStage stage)
{
  switch ( stage )
  {
    case NativeAnalysisProgressStage::FUNCTIONS:    return "functions";
    case NativeAnalysisProgressStage::UNOWNED_CODE: return "unowned-code";
    case NativeAnalysisProgressStage::COMPLETE:     return "complete";
  }
  return "unknown";
}

const char *deobf_progress_stage_name(DeobfAnalysisProgressStage stage)
{
  switch ( stage )
  {
    case DeobfAnalysisProgressStage::FUNCTIONS: return "functions";
    case DeobfAnalysisProgressStage::COMPLETE:  return "complete";
  }
  return "unknown";
}

const char *evidence_progress_stage_name(EvidenceApplyProgressStage stage)
{
  switch ( stage )
  {
    case EvidenceApplyProgressStage::PLANNING: return "planning";
    case EvidenceApplyProgressStage::MUTATING: return "mutating";
    case EvidenceApplyProgressStage::COMPLETE: return "complete";
  }
  return "unknown";
}

std::string hex_address(uint64_t address)
{
  char buffer[24];
  qsnprintf(buffer, sizeof(buffer), "0x%llX",
            static_cast<unsigned long long>(address));
  return buffer;
}

} // namespace

//-----------------------------------------------------------------------------
ssize_t idaapi viy_idb_listener_t::on_event(ssize_t code, va_list)
{
  if ( code == idb_event::auto_empty_finally && owner != nullptr )
    owner->on_analysis_done();
  return 0;
}

//-----------------------------------------------------------------------------
static int idaapi viy_sweep_cb(void *ud)
{
  viy_t *self = static_cast<viy_t *>(ud);
  if ( self->process_batch(self->cfg.funcs_per_tick) )
    return self->cfg.tick_ms; // keep firing at the same cadence
  self->timer = nullptr;      // IDA unregisters the timer when we return -1
  self->finish();
  return -1;
}

static void merge_runtime_stats(RuntimeEnrichStats &dst, const RuntimeEnrichStats &src)
{
#define VIY_ADD_RUNTIME_STAT(field) dst.field += src.field
  VIY_ADD_RUNTIME_STAT(final_write_observations);
  VIY_ADD_RUNTIME_STAT(corroborated_write_groups);
  VIY_ADD_RUNTIME_STAT(uncorroborated_write_groups);
  VIY_ADD_RUNTIME_STAT(conflicting_write_ranges);
  VIY_ADD_RUNTIME_STAT(string_observations);
  VIY_ADD_RUNTIME_STAT(string_candidates);
  VIY_ADD_RUNTIME_STAT(strings_corroborated);
  VIY_ADD_RUNTIME_STAT(ascii_strings);
  VIY_ADD_RUNTIME_STAT(utf8_strings);
  VIY_ADD_RUNTIME_STAT(utf16_strings);
  VIY_ADD_RUNTIME_STAT(utf32_strings);
  VIY_ADD_RUNTIME_STAT(strings_created);
  VIY_ADD_RUNTIME_STAT(stack_string_comments);
  VIY_ADD_RUNTIME_STAT(runtime_only_string_comments);
  VIY_ADD_RUNTIME_STAT(strings_skipped_defined);
  VIY_ADD_RUNTIME_STAT(strings_skipped_conflict);
  VIY_ADD_RUNTIME_STAT(smc_candidates);
  VIY_ADD_RUNTIME_STAT(write_execute_correlations);
  VIY_ADD_RUNTIME_STAT(smc_comments);
  VIY_ADD_RUNTIME_STAT(runtime_ranges_patched);
  VIY_ADD_RUNTIME_STAT(runtime_bytes_patched);
  VIY_ADD_RUNTIME_STAT(patches_skipped_conflict);
  VIY_ADD_RUNTIME_STAT(patches_skipped_changed_db);
  VIY_ADD_RUNTIME_STAT(pointer_slot_candidates);
  VIY_ADD_RUNTIME_STAT(pointer_slots_corroborated);
  VIY_ADD_RUNTIME_STAT(pointer_clusters);
  VIY_ADD_RUNTIME_STAT(pointer_clusters_correlated);
  VIY_ADD_RUNTIME_STAT(pointer_offsets_created);
  VIY_ADD_RUNTIME_STAT(orphan_call_candidates);
  VIY_ADD_RUNTIME_STAT(functions_promoted);
  VIY_ADD_RUNTIME_STAT(tail_candidates);
  VIY_ADD_RUNTIME_STAT(tails_appended);
  VIY_ADD_RUNTIME_STAT(comments_added);
  VIY_ADD_RUNTIME_STAT(comments_skipped_existing);
#undef VIY_ADD_RUNTIME_STAT
}

static void merge_deobf_stats(DeobfAnalysisStats &dst,
                              const DeobfAnalysisStats &src)
{
#define VIY_ADD_DEOBF_STAT(field) dst.field += src.field
  VIY_ADD_DEOBF_STAT(functions_scanned);
  VIY_ADD_DEOBF_STAT(chunks_scanned);
  VIY_ADD_DEOBF_STAT(blocks_scanned);
  VIY_ADD_DEOBF_STAT(instructions_scanned);
  VIY_ADD_DEOBF_STAT(decode_failures);
  VIY_ADD_DEOBF_STAT(facts_emitted);
  VIY_ADD_DEOBF_STAT(facts_deduplicated);
  VIY_ADD_DEOBF_STAT(get_pc_gadgets);
  VIY_ADD_DEOBF_STAT(push_return_targets);
  VIY_ADD_DEOBF_STAT(code_region_candidates);
  VIY_ADD_DEOBF_STAT(entry_predicates);
  VIY_ADD_DEOBF_STAT(constant_predicates);
  VIY_ADD_DEOBF_STAT(wrapper_traits);
  VIY_ADD_DEOBF_STAT(constant_targets);
  VIY_ADD_DEOBF_STAT(dispatch_maps);
  VIY_ADD_DEOBF_STAT(cff_edge_candidates);
  VIY_ADD_DEOBF_STAT(budget_truncations);
#undef VIY_ADD_DEOBF_STAT
  dst.architecture = src.architecture;
  dst.epoch = src.epoch;
}

//-----------------------------------------------------------------------------
bool viy_t::log_at_least(ViyLogLevel minimum) const
{
  return static_cast<unsigned>(cfg.log_level)
      >= static_cast<unsigned>(minimum);
}

//-----------------------------------------------------------------------------
uint64_t viy_t::current_diagnostic_elapsed_ms() const
{
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - diagnostic_start).count();
  return elapsed <= 0 ? 0 : static_cast<uint64_t>(elapsed);
}

//-----------------------------------------------------------------------------
uint64_t viy_t::diagnostic_elapsed_ms() const
{
  return terminal_elapsed_valid ? terminal_elapsed_ms
                                : current_diagnostic_elapsed_ms();
}

//-----------------------------------------------------------------------------
void viy_t::log_event(ViyLogLevel minimum, const std::string &event) const
{
  if ( log_at_least(minimum) )
    msg("[viy] %s\n", event.c_str());
}

//-----------------------------------------------------------------------------
void viy_t::log_progress_event(const std::string &event, bool force)
{
  if ( !log_at_least(ViyLogLevel::PROGRESS) )
    return;
  const uint64_t now = diagnostic_elapsed_ms();
  if ( !viy_diagnostic_due(now, last_progress_ms,
                           cfg.progress_interval_ms, force) )
  {
    return;
  }
  log_event(ViyLogLevel::PROGRESS, event);
  last_progress_ms = now;
}

//-----------------------------------------------------------------------------
void viy_t::log_snapshot_progress(const ProgramSnapshotProgress &progress)
{
  const ProgramSnapshotStats &s = progress.stats;
  std::string line = "event=progress phase=snapshotting stage=";
  line += snapshot_stage_name(progress.stage);
  line += " segments=" + std::to_string(s.segments_visited) + "/"
       + std::to_string(s.segments_total);
  line += " segments_copied=" + std::to_string(s.segments_copied);
  line += " segment_read_failures=" + std::to_string(s.segments_read_failed);
  line += " functions=" + std::to_string(s.functions_visited) + "/"
       + std::to_string(s.functions_total);
  line += " functions_included=" + std::to_string(s.functions_included);
  line += " functions_excluded=" + std::to_string(
      s.functions_library_or_thunk + s.functions_excluded_by_limit
    + s.functions_null);
  line += " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms());
  const bool boundary = progress.stage == ProgramSnapshotStage::COMPLETE
                     || (progress.stage == ProgramSnapshotStage::SEGMENTS
                         && s.segments_visited == 0)
                     || (progress.stage == ProgramSnapshotStage::FUNCTIONS
                         && s.functions_visited == 0);
  log_progress_event(line, boundary);
}

//-----------------------------------------------------------------------------
void viy_t::log_native_progress(const NativeAnalysisProgress &progress)
{
  std::string line = "event=progress phase=native-analysis stage=";
  line += native_progress_stage_name(progress.stage);
  line += " functions=" + std::to_string(progress.functions_completed) + "/"
       + std::to_string(progress.functions_total);
  line += " instructions=" + std::to_string(progress.instructions_scanned);
  line += " facts_emitted=" + std::to_string(progress.facts_emitted);
  line += " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms());
  log_progress_event(line, progress.stage_boundary);
}

//-----------------------------------------------------------------------------
void viy_t::log_deobf_progress(const DeobfAnalysisProgress &progress)
{
  std::string line = "event=progress phase=deobfuscation-analysis stage=";
  line += deobf_progress_stage_name(progress.stage);
  line += " functions=" + std::to_string(progress.functions_completed) + "/"
       + std::to_string(progress.functions_total);
  line += " blocks=" + std::to_string(progress.blocks_scanned);
  line += " instructions=" + std::to_string(progress.instructions_scanned);
  line += " facts_emitted=" + std::to_string(progress.facts_emitted);
  line += " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms());
  log_progress_event(line, progress.stage_boundary);
}

//-----------------------------------------------------------------------------
void viy_t::log_evidence_progress(const EvidenceApplyProgress &progress)
{
  std::string line = "event=progress phase=applying-evidence stage=";
  line += evidence_progress_stage_name(progress.stage);
  line += " records=" + std::to_string(progress.records_completed) + "/"
       + std::to_string(progress.records_total);
  line += " conflicted=" + std::to_string(progress.records_conflicted);
  line += " below_policy=" + std::to_string(progress.records_below_policy);
  line += " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms());
  log_progress_event(line, progress.stage_boundary);
}

//-----------------------------------------------------------------------------
void viy_t::report_worker_initialization()
{
  if ( worker_pool == nullptr || worker_initialization_reported )
    return;
  const EmulationWorkerStats workers = worker_pool->stats();
  if ( workers.initialized_workers < workers.requested_workers )
    return;

  const ViyDynamicCapability state = viy_dynamic_capability(
      static_cast<uint64_t>(workers.requested_workers),
      static_cast<uint64_t>(workers.initialized_workers),
      static_cast<uint64_t>(workers.available_workers),
      static_cast<uint64_t>(workers.unavailable_workers));
  std::string line = "event=workers state=";
  line += viy_dynamic_capability_name(state);
  line += " requested=" + std::to_string(workers.requested_workers);
  line += " initialized=" + std::to_string(workers.initialized_workers);
  line += " available=" + std::to_string(workers.available_workers);
  line += " unavailable=" + std::to_string(workers.unavailable_workers);
  const std::string diagnostic = viy_sanitize_diagnostic(
      worker_pool->initialization_diagnostic());
  if ( !diagnostic.empty() )
    line += " message=\"" + diagnostic + "\"";
  line += " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms());
  log_event(ViyLogLevel::SUMMARY, line);
  worker_initialization_reported = true;
}

//-----------------------------------------------------------------------------
ViyRuntimeStatus viy_t::runtime_status() const
{
  ViyRuntimeStatus status;
  status.phase = diagnostic_phase;
  status.epoch = started ? static_cast<uint64_t>(epoch + 1) : 0;
  status.epoch_limit = static_cast<uint64_t>(cfg.max_epochs);
  status.functions_done = static_cast<uint64_t>(epoch_funcs_done);
  status.functions_total = static_cast<uint64_t>(img.entries.size());
  status.functions_submitted = static_cast<uint64_t>(next);
  status.cache_hits = static_cast<uint64_t>(dynamic_cache_hits);

  EmulationWorkerStats workers = last_worker_stats;
  if ( worker_pool != nullptr )
    workers = worker_pool->stats();
  status.workers_initialized = static_cast<uint64_t>(workers.initialized_workers);
  status.workers_available = static_cast<uint64_t>(workers.available_workers);
  status.workers_unavailable = static_cast<uint64_t>(workers.unavailable_workers);
  status.workers_requested = static_cast<uint64_t>(workers.requested_workers);
  status.jobs_queued = static_cast<uint64_t>(workers.queued);
  status.jobs_running = static_cast<uint64_t>(workers.running);
  status.jobs_ready = static_cast<uint64_t>(workers.ready_in_order_or_later);
  status.jobs_completed = jobs_completed;
  status.jobs_cancelled = jobs_cancelled;
  status.jobs_unavailable = jobs_unavailable;
  status.jobs_failed = jobs_failed;
  status.runs_requested = runs_requested;
  status.runs_started = runs_started;
  status.evidence_records = static_cast<uint64_t>(evidence.record_count());
  status.changes = change_count();
  status.elapsed_ms = diagnostic_elapsed_ms();
  return status;
}

//-----------------------------------------------------------------------------
void viy_t::emit_status(bool force, ViyLogLevel minimum)
{
  if ( !log_at_least(minimum) )
    return;
  const uint64_t now = diagnostic_elapsed_ms();
  if ( !viy_diagnostic_due(now, last_progress_ms,
                           cfg.progress_interval_ms, force) )
  {
    return;
  }
  log_event(minimum, viy_format_runtime_status(runtime_status()));
  last_progress_ms = now;
}

//-----------------------------------------------------------------------------
void viy_t::set_diagnostic_phase(ViyDiagnosticPhase phase, const char *detail)
{
  diagnostic_phase = phase;
  const uint64_t now = diagnostic_elapsed_ms();
  std::string line = "event=phase phase=";
  line += viy_diagnostic_phase_name(phase);
  line += " epoch=" + std::to_string(started ? epoch + 1 : 0)
       + "/" + std::to_string(cfg.max_epochs);
  line += " elapsed_ms=" + std::to_string(now);
  if ( detail != nullptr && detail[0] != '\0' )
    line += " detail=\"" + viy_sanitize_diagnostic(detail) + "\"";
  log_event(ViyLogLevel::SUMMARY, line);
  last_progress_ms = now;
}

//-----------------------------------------------------------------------------
void viy_t::record_worker_result(const EmulationJobResult &result,
                                 size_t requested_run_count)
{
  runs_requested += static_cast<uint64_t>(requested_run_count);
  for ( const EmulationRunResult &run : result.runs )
    if ( run.ran )
      ++runs_started;

  switch ( result.status )
  {
    case EmulationJobStatus::COMPLETED:   ++jobs_completed; break;
    case EmulationJobStatus::CANCELLED:   ++jobs_cancelled; break;
    case EmulationJobStatus::UNAVAILABLE: ++jobs_unavailable; break;
    case EmulationJobStatus::FAILED:      ++jobs_failed; break;
  }

  const std::string diagnostic = viy_sanitize_diagnostic(result.diagnostic);
  if ( !diagnostic.empty() )
  {
    auto existing = worker_diagnostics.find(diagnostic);
    if ( existing != worker_diagnostics.end() )
      ++existing->second;
    else if ( worker_diagnostics.size() < 8 )
      worker_diagnostics.emplace(diagnostic, 1);
  }

  if ( log_at_least(ViyLogLevel::TRACE) )
  {
    std::string line = "event=worker-result function=";
    line += hex_address(result.function_start);
    line += " status=";
    line += worker_status_name(result.status);
    line += " runs_started=" + std::to_string(
        static_cast<size_t>(std::count_if(
            result.runs.begin(), result.runs.end(),
            [](const EmulationRunResult &run) { return run.ran; })));
    line += "/" + std::to_string(requested_run_count);
    line += " edges=" + std::to_string(result.merged.edges.size());
    line += " data_accesses=" + std::to_string(result.merged.data.size());
    if ( !diagnostic.empty() )
      line += " message=\"" + diagnostic + "\"";
    log_event(ViyLogLevel::TRACE, line);
  }
}

//-----------------------------------------------------------------------------
void viy_t::log_skip(const char *reason)
{
  const std::string next_reason = reason == nullptr ? "unknown" : reason;
  const bool changed = diagnostic_phase != ViyDiagnosticPhase::SKIPPED
                    || last_skip_reason != next_reason;
  last_skip_reason = next_reason;
  if ( !changed )
    return;
  if ( !terminal_elapsed_valid )
  {
    terminal_elapsed_ms = current_diagnostic_elapsed_ms();
    terminal_elapsed_valid = true;
  }
  diagnostic_phase = ViyDiagnosticPhase::SKIPPED;
  log_event(ViyLogLevel::SUMMARY,
            "event=skip reason=" + last_skip_reason
          + " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms()));
  emit_status(true, ViyLogLevel::SUMMARY);
}

//-----------------------------------------------------------------------------
viy_t::viy_t()
{
  cfg = viy_load_config();
  bool restored = false;
  std::string restore_error;
  if ( cfg.persist_evidence )
  {
    restored = evidence.restore(evidence_adapter, analysis::RestoreMode::Replace,
                                nullptr, &restore_error);
  }
  initialize_generation_allocator();
  if ( cfg.want_native )
  {
    native_store_sink.reset(new NativeEvidenceStoreSink(evidence));
    native_adapter.reset(new NativeAnalysisFactAdapter(*native_store_sink));
    native_provider.reset(new NativeAnalysisProvider(*native_adapter));
  }
  if ( cfg.want_deobf )
  {
    deobf_store_sink.reset(new DeobfEvidenceStoreSink(evidence));
    deobf_provider.reset(new DeobfAnalysisProvider(*deobf_store_sink));
  }
  if ( cfg.want_hexrays_bridge )
  {
    std::string reason;
    const bool installed = hexrays.start({}, &reason);
    std::string line = "event=hexrays requested=on installed=";
    line += enabled_word(installed);
    line += " compiled=";
    line += enabled_word(HexRaysEvidenceBridge::compiled_with_hexrays_sdk());
    if ( !reason.empty() )
      line += " message=\"" + viy_sanitize_diagnostic(reason) + "\"";
    log_event(ViyLogLevel::SUMMARY, line);
  }

  std::string loaded = "event=loaded enabled=";
  loaded += enabled_word(cfg.enabled);
  loaded += " log_level=" + std::to_string(static_cast<unsigned>(cfg.log_level));
  loaded += " progress_interval_ms=" + std::to_string(cfg.progress_interval_ms);
  loaded += " persistence=";
  loaded += enabled_word(cfg.persist_evidence);
  loaded += " restore=";
  if ( restored )
    loaded += "ok";
  else if ( !cfg.persist_evidence )
    loaded += "disabled";
  else if ( restore_error.find("not found") != std::string::npos )
    loaded += "none";
  else
    loaded += "error";
  loaded += " evidence_records=" + std::to_string(evidence.record_count());
  loaded += " evidence_observations=" + std::to_string(evidence.observation_count());
  log_event(ViyLogLevel::SUMMARY, loaded);
  if ( !restored && cfg.persist_evidence && !restore_error.empty()
    && restore_error.find("not found") == std::string::npos )
  {
    log_event(ViyLogLevel::SUMMARY,
              "event=diagnostic scope=persistence operation=restore message=\""
            + viy_sanitize_diagnostic(restore_error) + "\"");
  }
  set_diagnostic_phase(ViyDiagnosticPhase::WAITING_FOR_AUTOANALYSIS);
  idb.owner = this;
  hook_event_listener(HT_IDB, &idb);
  // If the database is already fully analyzed when we load, run right away.
  if ( auto_is_ok() )
    on_analysis_done();
}

//-----------------------------------------------------------------------------
void viy_t::initialize_generation_allocator()
{
  generation_allocator.seed(evidence);
}

//-----------------------------------------------------------------------------
uint64_t viy_t::allocate_generation()
{
  return generation_allocator.allocate();
}

//-----------------------------------------------------------------------------
void viy_t::assign_function_generations()
{
  const bool image_changed = !have_prior_content_hash
                          || prior_content_hash != img.content_hash;
  uint64_t changed_generation = 0;
  std::map<uint64_t, FunctionEvidenceIdentity> next_identities;
  for ( FuncRange &function : img.entries )
  {
    const auto old = function_evidence_identities.find(function.start);
    const bool unchanged = !image_changed
                        && old != function_evidence_identities.end()
                        && old->second.byte_hash == function.byte_hash;
    if ( unchanged )
    {
      function.generation = old->second.generation;
    }
    else
    {
      if ( changed_generation == 0 )
        changed_generation = allocate_generation();
      function.generation = changed_generation;
    }
    next_identities.emplace(
        function.start,
        FunctionEvidenceIdentity{ function.byte_hash, function.generation });
  }
  function_evidence_identities = std::move(next_identities);
  prior_content_hash = img.content_hash;
  have_prior_content_hash = true;
}

//-----------------------------------------------------------------------------
void viy_t::assign_emulation_generations()
{
  uint64_t changed_generation = 0;
  for ( FuncRange &function : img.entries )
  {
    const EmulationJob job = build_emulation_job(function);
    const uint64_t fingerprint = viy_emulation_job_fingerprint(
        job, img.content_hash, call_summaries);
    const auto cached = dynamic_cache.find(function.start);
    if ( cached == dynamic_cache.end() || cached->second != fingerprint )
    {
      if ( changed_generation == 0 )
        changed_generation = allocate_generation();
      function.generation = changed_generation;
      auto identity = function_evidence_identities.find(function.start);
      if ( identity != function_evidence_identities.end() )
        identity->second.generation = changed_generation;
    }
  }
}

//-----------------------------------------------------------------------------
void viy_t::snapshot_provider_function_starts()
{
  provider_function_starts.clear();
  const size_t count = get_func_qty();
  const size_t limit = cfg.max_funcs == 0
                     ? count : std::min(count, size_t(cfg.max_funcs));
  for ( size_t i = 0; i < limit; ++i )
  {
    const func_t *function = getn_func(i);
    if ( function != nullptr )
      provider_function_starts.insert(uint64_t(function->start_ea));
  }
}

//-----------------------------------------------------------------------------
analysis::EvidenceStore viy_t::active_evidence_view() const
{
  analysis::ActiveEvidencePolicy policy;
  policy.provider_generation = provider_generation;
  policy.provider_functions = provider_function_starts;
  for ( const auto &entry : function_evidence_identities )
    policy.function_generations.emplace(entry.first, entry.second.generation);
  return policy.view(evidence);
}

//-----------------------------------------------------------------------------
viy_t::~viy_t()
{
  if ( started && !finished )
    log_event(ViyLogLevel::SUMMARY,
              "event=stop reason=plugin-unload phase="
            + std::string(viy_diagnostic_phase_name(diagnostic_phase))
            + " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms()));
  if ( timer != nullptr )
  {
    unregister_timer(timer);
    timer = nullptr;
  }
  // Workers touch only immutable snapshots, but they must be joined before the
  // per-IDB plugmod and its configuration disappear.
  hexrays.stop();
  stop_workers();
  unhook_event_listener(HT_IDB, &idb);
  native_provider.reset();
  native_adapter.reset();
  native_store_sink.reset();
  deobf_provider.reset();
  deobf_store_sink.reset();
}

//-----------------------------------------------------------------------------
void viy_t::on_analysis_done()
{
  if ( started )
    return;

  if ( !cfg.enabled )
  {
    log_skip("disabled");
    return;
  }

  ViyArch arch;
  bool be;
  if ( !viy_detect_arch(arch, be) )
  {
    log_skip("unsupported-architecture");
    return;
  }

  // Native providers remain useful with embedded rax disabled. Each rax-backed
  // provider is capability-gated independently in begin_epoch().
  api = rax_load();

  started = true;
  finished = false;
  diagnostic_start = std::chrono::steady_clock::now();
  terminal_elapsed_ms = 0;
  terminal_elapsed_valid = false;
  last_progress_ms = 0;
  last_skip_reason.clear();
  completion_reason = "stable";
  epoch = 0;
  funcs_done = 0;
  epoch_funcs_done = 0;
  stats = RefStats{};
  sstats = RefStats{};
  estats = EnrichStats{};
  astats = AdvStats{};
  native_stats = NativeAnalysisStats{};
  deobf_stats = DeobfAnalysisStats{};
  rstats = RuntimeEnrichStats{};
  bridge_stats = EvidenceBridgeStats{};
  evidence_stats = EvidenceApplyStats{};
  decoder_stats = DecoderAuditStats{};
  dynamic_cache.clear();
  dynamic_cache_hits = 0;
  jobs_completed = 0;
  jobs_cancelled = 0;
  jobs_unavailable = 0;
  jobs_failed = 0;
  runs_requested = 0;
  runs_started = 0;
  worker_diagnostics.clear();
  last_worker_stats = EmulationWorkerStats{};
  worker_initialization_reported = false;
  snapshot_stats = ProgramSnapshotStats{};

  std::string start = "event=start arch=";
  start += arch_name(arch);
  start += " endian=";
  start += (be ? "big" : "little");
  start += " native=";
  start += enabled_word(cfg.want_native);
  start += " deobfuscation=";
  start += enabled_word(cfg.want_deobf);
  start += " static_requested=";
  start += enabled_word(cfg.want_static);
  start += " rax=";
  start += api == nullptr ? "unavailable" : "available";
  if ( api != nullptr && api->version_string != nullptr )
    start += " rax_version=\"" + viy_sanitize_diagnostic(api->version_string()) + "\"";
  start += " elapsed_ms=0";
  log_event(ViyLogLevel::SUMMARY, start);
  if ( api == nullptr )
  {
    log_event(ViyLogLevel::SUMMARY,
              "event=diagnostic scope=rax message=\""
            + viy_sanitize_diagnostic(rax_unavailable_reason()) + "\"");
  }
  if ( !begin_epoch() )
  {
    started = false;
    log_skip(last_skip_reason.empty() ? "no-applicable-analysis" :
             last_skip_reason.c_str());
    return;
  }
  start_sweep();
}

//-----------------------------------------------------------------------------
uint64_t viy_t::change_count() const
{
  return uint64_t(stats.crefs + stats.drefs + stats.code_made
                + sstats.crefs + sstats.drefs + sstats.code_made
                + estats.ptr_refs + estats.typed + estats.strings + estats.comments
                + astats.switches + astats.purges + astats.norets
                + astats.argregs + astats.opaque
                + rstats.strings_created + rstats.stack_string_comments
                + rstats.runtime_only_string_comments + rstats.smc_comments
                + rstats.runtime_ranges_patched + rstats.pointer_offsets_created
                + rstats.functions_promoted + rstats.tails_appended
                + rstats.comments_added
                + evidence_stats.refs.crefs + evidence_stats.refs.drefs
                + evidence_stats.refs.code_made
                + evidence_stats.functions_created
                + evidence_stats.comments_added);
}

//-----------------------------------------------------------------------------
bool viy_t::begin_epoch()
{
  stop_workers();
  last_worker_stats = EmulationWorkerStats{};
  worker_initialization_reported = false;
  epoch_funcs_done = 0;
  next = 0;
  worker_jobs.clear();
  waiting_for_auto = false;

  set_diagnostic_phase(ViyDiagnosticPhase::SNAPSHOTTING);
  const uint64_t snapshot_started_ms = diagnostic_elapsed_ms();

  snapshot_stats = viy_snapshot(
      img, cfg,
      [this](const ProgramSnapshotProgress &progress)
      {
        log_snapshot_progress(progress);
      });
  assign_function_generations();
  snapshot_provider_function_starts();
  provider_generation = allocate_generation();
  can_native = cfg.want_native;
  can_deobf = cfg.want_deobf;
  can_static = false;
  call_summaries = cfg.want_import_summaries
                 ? viy_collect_call_summaries() : std::vector<EmuCallSummary>{};
  size_t chunk_count = 0;
  for ( const FuncRange &function : img.entries )
    chunk_count += function.chunks.size();
  const uint64_t snapshot_finished_ms = diagnostic_elapsed_ms();
  log_event(ViyLogLevel::SUMMARY,
            "event=snapshot epoch=" + std::to_string(epoch + 1)
          + "/" + std::to_string(cfg.max_epochs)
          + " segments=" + std::to_string(snapshot_stats.segments_copied)
          + "/" + std::to_string(snapshot_stats.segments_total)
          + " segment_invalid=" + std::to_string(snapshot_stats.segments_invalid)
          + " segment_read_failures="
          + std::to_string(snapshot_stats.segments_read_failed)
          + " functions=" + std::to_string(snapshot_stats.functions_included)
          + "/" + std::to_string(snapshot_stats.functions_total)
          + " functions_null=" + std::to_string(snapshot_stats.functions_null)
          + " functions_library_or_thunk="
          + std::to_string(snapshot_stats.functions_library_or_thunk)
          + " functions_excluded_by_limit="
          + std::to_string(snapshot_stats.functions_excluded_by_limit)
          + " chunks=" + std::to_string(chunk_count)
          + " call_summaries=" + std::to_string(call_summaries.size())
          + " duration_ms=" + std::to_string(
                snapshot_finished_ms - snapshot_started_ms));
  const bool can_attempt_dynamic = api != nullptr && !img.entries.empty();
  const unsigned hardware_threads = std::thread::hardware_concurrency();
  size_t selected_worker_count = 0;
  if ( can_attempt_dynamic )
  {
    // Entry-state/type/import-summary changes can alter semantics even when no
    // image byte changed. Tie the active evidence generation to the complete
    // job fingerprint before publishing the immutable worker snapshot.
    assign_emulation_generations();
    const bool windows_x64 = viy_detect_abi(img.arch) == ViyAbi::X86_64_WIN64;
    // Copy once at the IDA boundary. The shared const snapshot outlives every
    // executor and is never changed while workers are active.
    worker_image = std::make_shared<const ProgramImage>(img);
    RaxWorkerOptions options;
    options.api = api;
    options.image = worker_image;
    options.strict_perms = cfg.strict_perms;
    options.windows_x64 = windows_x64;
    options.call_summaries = call_summaries;

    size_t worker_count = viy_resolve_worker_count_for_hardware(
        cfg.workers, hardware_threads);
    worker_count = std::min(worker_count, std::max<size_t>(img.entries.size(), 1));
    selected_worker_count = worker_count;
    const size_t queue_capacity = worker_count * 2; // cfg.workers is capped at 64
    worker_pool.reset(new EmulationWorkerPool(
        worker_count, viy_make_rax_worker_factory(std::move(options)),
        queue_capacity));
  }
  if ( api != nullptr )
  {
    const bool static_arch_ok = img.arch != ViyArch::UNSUPPORTED;
    can_static = cfg.want_static && api->decode != nullptr && static_arch_ok;
  }

  EmulationWorkerStats initial_workers;
  if ( worker_pool != nullptr )
    initial_workers = worker_pool->stats();
  std::string capabilities = "event=capabilities epoch=";
  capabilities += std::to_string(epoch + 1) + "/" + std::to_string(cfg.max_epochs);
  capabilities += " native=";
  capabilities += enabled_word(can_native && native_provider != nullptr);
  capabilities += " deobfuscation=";
  capabilities += enabled_word(can_deobf && deobf_provider != nullptr);
  capabilities += " dynamic=";
  capabilities += viy_dynamic_capability_name(viy_dynamic_capability(
      static_cast<uint64_t>(initial_workers.requested_workers),
      static_cast<uint64_t>(initial_workers.initialized_workers),
      static_cast<uint64_t>(initial_workers.available_workers),
      static_cast<uint64_t>(initial_workers.unavailable_workers)));
  capabilities += " static_decode=";
  capabilities += enabled_word(can_static);
  capabilities += " smir=";
  capabilities += enabled_word(api != nullptr && api->analyze != nullptr);
  capabilities += " hexrays=";
  capabilities += enabled_word(hexrays.installed());
  capabilities += " persistence=";
  capabilities += enabled_word(cfg.persist_evidence);
  capabilities += " workers_requested="
      + std::to_string(initial_workers.requested_workers);
  capabilities += " workers_policy=";
  capabilities += cfg.workers == 0 ? "auto" : "explicit";
  capabilities += " workers_configured=" + std::to_string(cfg.workers);
  capabilities += " workers_hardware_threads="
      + std::to_string(hardware_threads);
  capabilities += " workers_auto_cap="
      + std::to_string(kViyAutomaticWorkerCap);
  capabilities += " workers_selected="
      + std::to_string(selected_worker_count);
  capabilities += " workers_initialized="
      + std::to_string(initial_workers.initialized_workers);
  capabilities += " workers_available="
      + std::to_string(initial_workers.available_workers);
  capabilities += " workers_unavailable="
      + std::to_string(initial_workers.unavailable_workers);
  log_event(ViyLogLevel::SUMMARY, capabilities);
  report_worker_initialization();

  if ( worker_pool == nullptr && !can_static && !can_native && !can_deobf )
  {
    last_skip_reason = "no-applicable-provider";
    return false;
  }

  // The native provider can discover the first function in an IDB that has no
  // current functions, so an empty function snapshot is not a terminal state.
  if ( img.entries.empty() && !can_native )
  {
    last_skip_reason = "no-functions-and-native-disabled";
    return false;
  }

  if ( can_native && native_provider != nullptr )
  {
    set_diagnostic_phase(ViyDiagnosticPhase::NATIVE_ANALYSIS);
    const uint64_t provider_started_ms = diagnostic_elapsed_ms();
    // A provider scan is a complete snapshot. Re-emitting all current facts at
    // one externally unique generation also retires facts that disappeared.
    native_provider->reset();
    native_provider->set_epoch(provider_generation);
    native_store_sink->reset_report();
    NativeAnalysisOptions options;
    options.max_functions = cfg.max_funcs == 0 ? 0 : size_t(cfg.max_funcs);
    options.progress = [this](const NativeAnalysisProgress &progress)
    {
      log_native_progress(progress);
    };
    NativeAnalysisStats ns = native_provider->analyze_database(options);
    native_stats.functions_scanned += ns.functions_scanned;
    native_stats.chunks_scanned += ns.chunks_scanned;
    native_stats.instructions_scanned += ns.instructions_scanned;
    native_stats.decode_failures += ns.decode_failures;
    native_stats.facts_emitted += ns.facts_emitted;
    native_stats.facts_deduplicated += ns.facts_deduplicated;
    native_stats.indirect_targets += ns.indirect_targets;
    native_stats.zero_register_branches += ns.zero_register_branches;
    native_stats.opposite_branch_pairs += ns.opposite_branch_pairs;
    native_stats.known_flag_branches += ns.known_flag_branches;
    native_stats.function_candidates += ns.function_candidates;
    native_stats.decode_discrepancies += ns.decode_discrepancies;
    native_stats.architecture = ns.architecture;
    native_stats.epoch = ns.epoch;
    native_stats.register_tracker = merge_native_capability(
        native_stats.register_tracker, ns.register_tracker);
    native_stats.operand_address_tracker = merge_native_capability(
        native_stats.operand_address_tracker, ns.operand_address_tracker);
    const NativeEvidenceStoreReport &report = native_store_sink->report();
    log_event(ViyLogLevel::SUMMARY,
              "event=provider provider=native epoch="
            + std::to_string(epoch + 1)
            + " functions=" + std::to_string(ns.functions_scanned)
            + " chunks=" + std::to_string(ns.chunks_scanned)
            + " instructions=" + std::to_string(ns.instructions_scanned)
            + " decode_failures=" + std::to_string(ns.decode_failures)
            + " facts_emitted=" + std::to_string(ns.facts_emitted)
            + " facts_inserted=" + std::to_string(report.inserted_records)
            + " observations_added=" + std::to_string(report.added_observations)
            + " duplicates=" + std::to_string(report.duplicate_observations)
            + " rejected=" + std::to_string(report.rejected_facts)
            + " register_tracker="
            + native_capability_name(ns.register_tracker)
            + " operand_address_tracker="
            + native_capability_name(ns.operand_address_tracker)
            + " duration_ms=" + std::to_string(
                  diagnostic_elapsed_ms() - provider_started_ms));
    if ( native_store_sink->last_error()[0] != '\0' )
      log_event(ViyLogLevel::SUMMARY,
                "event=diagnostic scope=native message=\""
              + viy_sanitize_diagnostic(native_store_sink->last_error()) + "\"");
  }

  if ( can_deobf && deobf_provider != nullptr )
  {
    set_diagnostic_phase(ViyDiagnosticPhase::DEOBFUSCATION_ANALYSIS);
    const uint64_t provider_started_ms = diagnostic_elapsed_ms();
    deobf_provider->reset();
    deobf_provider->set_epoch(provider_generation);
    deobf_store_sink->set_active_generation(provider_generation);
    deobf_store_sink->reset_report();
    DeobfAnalysisOptions options;
    options.max_functions = cfg.max_funcs == 0 ? 0 : size_t(cfg.max_funcs);
    options.progress = [this](const DeobfAnalysisProgress &progress)
    {
      log_deobf_progress(progress);
    };
    const DeobfAnalysisStats ds = deobf_provider->analyze_database(options);
    merge_deobf_stats(deobf_stats, ds);
    const DeobfEvidenceStoreReport &report = deobf_store_sink->report();
    log_event(ViyLogLevel::SUMMARY,
              "event=provider provider=deobfuscation epoch="
            + std::to_string(epoch + 1)
            + " functions=" + std::to_string(ds.functions_scanned)
            + " blocks=" + std::to_string(ds.blocks_scanned)
            + " instructions=" + std::to_string(ds.instructions_scanned)
            + " decode_failures=" + std::to_string(ds.decode_failures)
            + " facts_emitted=" + std::to_string(ds.facts_emitted)
            + " facts_inserted=" + std::to_string(report.inserted_records)
            + " observations_added=" + std::to_string(report.added_observations)
            + " duplicates=" + std::to_string(report.duplicate_observations)
            + " rejected=" + std::to_string(report.rejected_invalid)
            + " contradictions=" + std::to_string(report.contradictions_suppressed)
            + " budget_truncations=" + std::to_string(ds.budget_truncations)
            + " duration_ms=" + std::to_string(
                  diagnostic_elapsed_ms() - provider_started_ms));
    if ( deobf_store_sink->last_error()[0] != '\0' )
      log_event(ViyLogLevel::SUMMARY,
                "event=diagnostic scope=deobfuscation message=\""
              + viy_sanitize_diagnostic(deobf_store_sink->last_error()) + "\"");
  }

  epoch_change_base = change_count();
  set_diagnostic_phase(ViyDiagnosticPhase::SWEEPING_FUNCTIONS);
  return true;
}

//-----------------------------------------------------------------------------
void viy_t::start_sweep()
{
  timer = register_timer(cfg.tick_ms, viy_sweep_cb, this);
  if ( timer == nullptr )
  {
    log_event(ViyLogLevel::SUMMARY,
              "event=scheduler mode=inline tick_ms="
            + std::to_string(cfg.tick_ms)
            + " functions_per_tick=" + std::to_string(cfg.funcs_per_tick));
    // No UI timer available (e.g. headless idalib): run to completion inline.
    inline_mode = true;
    while ( process_batch(cfg.funcs_per_tick ) )
      ; // keep going
    inline_mode = false;
    finish();
  }
  else
  {
    log_event(ViyLogLevel::SUMMARY,
              "event=scheduler mode=timer tick_ms="
            + std::to_string(cfg.tick_ms)
            + " functions_per_tick=" + std::to_string(cfg.funcs_per_tick));
    emit_status(true);
  }
}

//-----------------------------------------------------------------------------
EmulationJob viy_t::build_emulation_job(const FuncRange &func) const
{
  // This method runs only from the UI/main-thread timer. In particular,
  // viy_build_entry_inputs() may use IDA's xrefs and register tracker; its POD
  // result is copied into the job before the worker boundary.
  EmulationJob job;
  job.function = func;
  job.config = cfg;

  int runs = cfg.explore_runs;
  if ( cfg.want_opaque )
    runs = std::max(runs, cfg.opaque_runs);
  if ( cfg.want_noret || cfg.set_noret )
    runs = std::max(runs, 5); // independent corroboration corpus

  const EntryInputPlan entry_plan = viy_build_entry_inputs(
      img.arch, func.start, size_t(std::min(runs, 16)));
  const size_t total_runs = size_t(runs) + entry_plan.inputs.size();
  job.runs.reserve(total_runs);
  for ( size_t k = 0; k < total_runs; ++k )
  {
    EmulationRunRequest request;
    request.run_id = uint32_t(k);
    request.seed = k == 0 ? 0
                         : uint64_t(k) * 0x9E3779B97F4A7C15ull + 1;
    request.record_pcs = true;
    if ( k >= size_t(runs) )
    {
      request.has_input = true;
      request.input = entry_plan.inputs[k - size_t(runs)];
      request.input.run_id = uint32_t(k);
      request.run_id = request.input.run_id;
      request.seed = request.input.seed;
    }
    job.runs.push_back(std::move(request));
  }
  return job;
}

//-----------------------------------------------------------------------------
void viy_t::process_function(size_t index, EmulationJobResult result)
{
  if ( index >= img.entries.size() )
    return;
  const FuncRange &func = img.entries[index];
  const uint64_t fstart = func.start;
  const uint64_t fend = func.end;

  // The result is pure worker data. From this point onward execution is back
  // on IDA's main thread and all evidence/database consumers are safe to call.
  EmuEvents ev = std::move(result.merged);
  ev.normalize();
  EmuOutcome outcome;
  std::vector<ObservedOutcome> outcomes;
  outcomes.reserve(result.runs.size());
  for ( const EmulationRunResult &run : result.runs )
    if ( run.ran )
      outcomes.push_back(ObservedOutcome{ run.outcome, run.run_id, run.seed });

  std::unordered_set<uint64_t> reached;
  reached.insert(ev.exec_pcs.begin(), ev.exec_pcs.end());
  if ( !outcomes.empty() )
    outcome = outcomes.front().outcome;

  EvidenceBridgeStats recorded = viy_record_emulation_evidence(
      evidence, img, func, ev, outcomes);
  bridge_stats.inserted_records += recorded.inserted_records;
  bridge_stats.added_observations += recorded.added_observations;
  bridge_stats.duplicates += recorded.duplicates;
  bridge_stats.rejected += recorded.rejected;

  RuntimeEnrichStats runtime = viy_runtime_enrich(img, ev, cfg);
  merge_runtime_stats(rstats, runtime);

  RefStats s = viy_apply_missing(ev, cfg);
  stats.crefs += s.crefs;
  stats.drefs += s.drefs;
  stats.code_made += s.code_made;

  // Enrichment: turn concrete values into typed pointers/globals/comments.
  EnrichStats en = viy_enrich(ev, cfg);
  estats.ptr_refs += en.ptr_refs;
  estats.typed    += en.typed;
  estats.strings  += en.strings;
  estats.comments += en.comments;

  // Only conclusive, mutually agreeing outcomes can alter function metadata.
  bool noret_corroborated = outcomes.size() >= 3;
  for ( const ObservedOutcome &observed : outcomes )
    if ( observed.outcome.returned || !observed.outcome.definitive_terminal() )
      noret_corroborated = false;

  EmuOutcome consensus = outcome;
  if ( outcomes.size() < 2 || !consensus.returned || !consensus.sp_valid )
    consensus.sp_valid = false;
  for ( const ObservedOutcome &observed : outcomes )
  {
    const EmuOutcome &o = observed.outcome;
    if ( !o.returned || !o.sp_valid || o.sp_delta != consensus.sp_delta )
      consensus.sp_valid = false;
  }

  viy_advanced(img.arch, func, ev, consensus, reached,
               noret_corroborated, cfg, astats);

  // Static decoding and every consumer above execute on this main thread.
  if ( can_static )
  {
    const DecoderAuditStats audited = viy_audit_decoders(api, img, func, evidence);
    decoder_stats.merge_from(audited);
    if ( func.chunks.empty() )
      viy_static_decode_func(api, img.arch, img.big_endian, fstart, fend, cfg, sstats);
    else
      for ( const FuncChunk &chunk : func.chunks )
        viy_static_decode_func(api, img.arch, img.big_endian,
                               chunk.start, chunk.end, cfg, sstats);
  }
  ++funcs_done;
  ++epoch_funcs_done;
}

//-----------------------------------------------------------------------------
void viy_t::stop_workers()
{
  if ( worker_pool != nullptr )
  {
    last_worker_stats = worker_pool->stats();
    worker_pool->shutdown();
    last_worker_stats = worker_pool->stats();
    worker_pool.reset();
  }
  worker_jobs.clear();
  worker_image.reset();
}

//-----------------------------------------------------------------------------
bool viy_t::process_batch(int count)
{
  if ( waiting_for_auto )
  {
    if ( !auto_is_ok() )
    {
      if ( !inline_mode )
      {
        emit_status();
        return true;
      }
      auto_wait();
    }
    ++epoch;
    if ( !begin_epoch() )
    {
      completion_reason = last_skip_reason.empty()
                        ? "no-applicable-analysis" : last_skip_reason;
      log_skip(completion_reason.c_str());
      return false;
    }
  }

  const size_t budget = size_t(std::max(count, 1));
  if ( worker_pool != nullptr )
  {
    report_worker_initialization();
    size_t applied = 0;
    auto apply_one = [&](EmulationJobResult result)
    {
      auto it = worker_jobs.find(result.ticket);
      if ( it == worker_jobs.end() )
      {
        // Delivery is ordered, so recover the expected oldest job if an
        // executor ever returns malformed ticket metadata. Discard its dynamic
        // evidence but still run static/main-thread providers for the function.
        if ( worker_jobs.empty() )
          return;
        it = worker_jobs.begin();
        result.runs.clear();
        result.merged = EmuEvents{};
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = "worker result ticket mismatch";
      }
      const WorkerJobInfo info = it->second;
      const size_t index = info.index;
      worker_jobs.erase(it);
      if ( index >= img.entries.size()
        || result.function_start != img.entries[index].start )
      {
        result.runs.clear();
        result.merged = EmuEvents{};
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = "worker result function mismatch";
      }
      else if ( result.completed() )
      {
        dynamic_cache[result.function_start] = info.fingerprint;
      }
      record_worker_result(result, info.requested_runs);
      process_function(index, std::move(result));
      ++applied;
    };

    EmulationJobResult ready;
    while ( applied < budget && worker_pool->try_take_next(ready) )
      apply_one(std::move(ready));

    size_t submitted = 0;
    while ( submitted < budget && next < img.entries.size() )
    {
      EmulationJob job = build_emulation_job(img.entries[next]);
      const uint64_t fingerprint = viy_emulation_job_fingerprint(
          job, img.content_hash, call_summaries);
      const auto cached = dynamic_cache.find(img.entries[next].start);
      if ( cached != dynamic_cache.end() && cached->second == fingerprint )
      {
        EmulationJobResult unchanged;
        unchanged.function_start = img.entries[next].start;
        unchanged.status = EmulationJobStatus::UNAVAILABLE;
        process_function(next, std::move(unchanged));
        ++dynamic_cache_hits;
        ++next;
        ++submitted;
        ++applied;
        continue;
      }
      uint64_t ticket = 0;
      const size_t requested_runs_count = job.runs.size();
      if ( !worker_pool->try_submit(std::move(job), &ticket) )
        break; // bounded queue backpressure; retry on the next timer tick
      worker_jobs.emplace(ticket,
                          WorkerJobInfo{ next, fingerprint, requested_runs_count });
      ++next;
      ++submitted;
    }

    // Unavailable executors and short functions can settle during submission.
    while ( applied < budget && worker_pool->try_take_next(ready) )
      apply_one(std::move(ready));

    // Headless/idalib has no timer to wake us. Wait briefly for one ordered
    // result instead of spinning; the rax run itself remains off-thread.
    if ( inline_mode && applied == 0 && !worker_jobs.empty()
      && worker_pool->wait_take_next(
          ready, std::chrono::milliseconds(std::max(cfg.tick_ms, 1))) )
    {
      apply_one(std::move(ready));
    }

    if ( next < img.entries.size() || !worker_jobs.empty() )
    {
      emit_status();
      return true;
    }
  }
  else
  {
    // Native/static-only mode still uses the timer budget, but no worker job is
    // required. An empty result preserves the same main-thread consumer path.
    for ( size_t i = 0; i < budget && next < img.entries.size(); ++i, ++next )
    {
      EmulationJobResult empty;
      empty.function_start = img.entries[next].start;
      empty.status = EmulationJobStatus::UNAVAILABLE;
      process_function(next, std::move(empty));
    }
    if ( next < img.entries.size() )
    {
      emit_status();
      return true;
    }
  }

  // Release per-worker engines and their immutable snapshot before applying
  // producer-neutral facts or waiting for the next autoanalysis epoch.
  report_worker_initialization();
  set_diagnostic_phase(ViyDiagnosticPhase::APPLYING_EVIDENCE);
  emit_status(true);
  stop_workers();

  // Apply producer-neutral facts only after all providers have completed the
  // epoch.  The consumer is contradiction-aware and confidence-gated, and its
  // mutations participate in the convergence test below.
  const analysis::EvidenceStore active_evidence = active_evidence_view();
  const uint64_t evidence_apply_started_ms = diagnostic_elapsed_ms();
  const EvidenceApplyStats applied = viy_apply_evidence(
      active_evidence, cfg,
      [this](const EvidenceApplyProgress &progress)
      {
        log_evidence_progress(progress);
      });
  const uint64_t evidence_apply_duration_ms =
      diagnostic_elapsed_ms() - evidence_apply_started_ms;
  evidence_stats.refs.crefs += applied.refs.crefs;
  evidence_stats.refs.drefs += applied.refs.drefs;
  evidence_stats.refs.code_made += applied.refs.code_made;
  evidence_stats.functions_created += applied.functions_created;
  evidence_stats.comments_added += applied.comments_added;
  evidence_stats.records_considered += applied.records_considered;
  evidence_stats.records_conflicted += applied.records_conflicted;
  evidence_stats.records_below_policy += applied.records_below_policy;
  evidence_stats.conflict_relations_examined +=
      applied.conflict_relations_examined;
  evidence_stats.conflict_digests_computed +=
      applied.conflict_digests_computed;

  log_event(ViyLogLevel::SUMMARY,
            "event=evidence-apply epoch=" + std::to_string(epoch + 1)
          + " records=" + std::to_string(active_evidence.record_count())
          + " observations=" + std::to_string(active_evidence.observation_count())
          + " considered=" + std::to_string(applied.records_considered)
          + " conflicted=" + std::to_string(applied.records_conflicted)
          + " below_policy=" + std::to_string(applied.records_below_policy)
          + " contradiction_relations="
          + std::to_string(applied.conflict_relations_examined)
          + " contradiction_digests="
          + std::to_string(applied.conflict_digests_computed)
          + " code_refs=" + std::to_string(applied.refs.crefs)
          + " data_refs=" + std::to_string(applied.refs.drefs)
          + " code_created=" + std::to_string(applied.refs.code_made)
          + " functions_created=" + std::to_string(applied.functions_created)
          + " comments_added=" + std::to_string(applied.comments_added)
          + " duration_ms=" + std::to_string(evidence_apply_duration_ms));

  if ( cfg.want_hexrays_bridge )
  {
    hexrays.publish(active_evidence);
    const HexRaysBridgeStats hs = hexrays.stats();
    log_event(ViyLogLevel::SUMMARY,
              "event=hexrays-publish installed="
            + std::string(enabled_word(hexrays.installed()))
            + " records_considered=" + std::to_string(hs.records_considered)
            + " records_accepted=" + std::to_string(hs.records_accepted)
            + " annotations=" + std::to_string(hs.annotations_built)
            + " conflicted=" + std::to_string(hs.records_conflicted)
            + " below_policy=" + std::to_string(hs.records_below_policy)
            + " callback_failures=" + std::to_string(hs.callback_failures));
  }

  if ( cfg.persist_evidence )
  {
    std::string persist_error;
    const bool persisted = evidence.persist(evidence_adapter, &persist_error);
    std::string line = "event=persistence operation=write result=";
    line += persisted ? "ok" : "error";
    line += " records=" + std::to_string(evidence.record_count());
    line += " observations=" + std::to_string(evidence.observation_count());
    if ( !persist_error.empty() )
      line += " message=\"" + viy_sanitize_diagnostic(persist_error) + "\"";
    log_event(ViyLogLevel::SUMMARY, line);
  }

  const bool changed = change_count() > epoch_change_base;
  if ( changed && epoch + 1 < cfg.max_epochs )
  {
    waiting_for_auto = true;
    completion_reason = "converging";
    set_diagnostic_phase(ViyDiagnosticPhase::WAITING_FOR_CONVERGENCE,
                         "database mutations queued autoanalysis");
    emit_status(true);
    return true;
  }
  completion_reason = changed ? "max-epochs-reached" : "stable";
  return false;
}

//-----------------------------------------------------------------------------
void viy_t::finish()
{
  finished = true;
  terminal_elapsed_ms = current_diagnostic_elapsed_ms();
  terminal_elapsed_valid = true;
  set_diagnostic_phase(ViyDiagnosticPhase::COMPLETE, completion_reason.c_str());
  emit_status(true, ViyLogLevel::SUMMARY);

  log_event(ViyLogLevel::SUMMARY,
            "event=complete reason=" + completion_reason
          + " epochs=" + std::to_string(epoch + 1)
          + " function_passes=" + std::to_string(funcs_done)
          + " evidence_records=" + std::to_string(evidence.record_count())
          + " evidence_observations=" + std::to_string(evidence.observation_count())
          + " mutation_operations=" + std::to_string(change_count())
          + " jobs_completed=" + std::to_string(jobs_completed)
          + " jobs_cancelled=" + std::to_string(jobs_cancelled)
          + " jobs_unavailable=" + std::to_string(jobs_unavailable)
          + " jobs_failed=" + std::to_string(jobs_failed)
          + " runs_started=" + std::to_string(runs_started)
          + "/" + std::to_string(runs_requested)
          + " dynamic=" + std::string(viy_dynamic_capability_name(
                viy_dynamic_capability(
                    static_cast<uint64_t>(last_worker_stats.requested_workers),
                    static_cast<uint64_t>(last_worker_stats.initialized_workers),
                    static_cast<uint64_t>(last_worker_stats.available_workers),
                    static_cast<uint64_t>(last_worker_stats.unavailable_workers))))
          + " workers_available="
          + std::to_string(last_worker_stats.available_workers)
          + "/" + std::to_string(last_worker_stats.requested_workers)
          + " workers_unavailable="
          + std::to_string(last_worker_stats.unavailable_workers)
          + " cache_hits=" + std::to_string(dynamic_cache_hits)
          + " native_facts=" + std::to_string(native_stats.facts_emitted)
          + " deobfuscation_facts=" + std::to_string(deobf_stats.facts_emitted)
          + " dynamic_observations=" + std::to_string(bridge_stats.added_observations)
          + " decoder_compared=" + std::to_string(decoder_stats.instructions_compared)
          + " decoder_disagreements=" + std::to_string(
                decoder_stats.size_disagreements
              + decoder_stats.flow_disagreements
              + decoder_stats.target_disagreements)
          + " evidence_conflicted=" + std::to_string(
                evidence_stats.records_conflicted)
          + " evidence_below_policy=" + std::to_string(
                evidence_stats.records_below_policy)
          + " elapsed_ms=" + std::to_string(diagnostic_elapsed_ms()));

  for ( const auto &entry : worker_diagnostics )
  {
    log_event(ViyLogLevel::SUMMARY,
              "event=diagnostic scope=worker count="
            + std::to_string(entry.second)
            + " message=\"" + entry.first + "\"");
  }

  const unsigned long long ind_c = (unsigned long long)stats.crefs;   // indirect (emulated)
  const unsigned long long dir_c = (unsigned long long)sstats.crefs;  // direct (static decode)
  const unsigned long long ev_c  = (unsigned long long)evidence_stats.refs.crefs;
  const unsigned long long drefs = (unsigned long long)(stats.drefs + evidence_stats.refs.drefs);
  const unsigned long long ptrs  = (unsigned long long)(estats.ptr_refs + rstats.pointer_offsets_created);
  const unsigned long long typed = (unsigned long long)estats.typed;
  const unsigned long long strs  = (unsigned long long)(estats.strings + rstats.strings_created);
  const unsigned long long cmts  = (unsigned long long)(estats.comments + rstats.comments_added
                                                      + evidence_stats.comments_added);
  const unsigned long long fn    = (unsigned long long)(rstats.functions_promoted
                                                      + evidence_stats.functions_created);
  const unsigned long long smc   = (unsigned long long)rstats.write_execute_correlations;
  const unsigned long long sw    = (unsigned long long)astats.switches;
  const unsigned long long pg    = (unsigned long long)astats.purges;
  const unsigned long long nr    = (unsigned long long)astats.norets;
  const unsigned long long ar    = (unsigned long long)astats.argregs;
  const unsigned long long op    = (unsigned long long)astats.opaque;
  if ( log_at_least(ViyLogLevel::SUMMARY)
    && (ind_c || dir_c || ev_c || drefs || ptrs || typed || strs || cmts || sw || pg || nr || ar || op
    || fn || smc )
  )
  {
    const char *rv = (api != nullptr && api->version_string != nullptr)
                   ? api->version_string() : "none";
    msg("viy: %llu code xref(s) [%llu indirect, %llu direct, %llu evidence], %llu data xref(s), "
        "%llu ptr, %llu typed, %llu string(s); "
        "%llu switch(es), %llu purge(s), %llu noret, %llu argregs, %llu opaque; "
        "%llu function(s) promoted, %llu write/execute; "
        "%llu comment(s) across %llu function pass(es), %llu dynamic cache hit(s), "
        "%d epoch(s) [rax %s]\n",
        ind_c + dir_c + ev_c, ind_c, dir_c, ev_c, drefs, ptrs, typed, strs,
        sw, pg, nr, ar, op, fn, smc, cmts,
        (unsigned long long)funcs_done,
        (unsigned long long)dynamic_cache_hits, epoch + 1, rv);
  }
  // Found nothing => say nothing.
}

//-----------------------------------------------------------------------------
bool idaapi viy_t::run(size_t)
{
  // Normally driven by auto_empty_finally. Manual invocation must not bypass
  // that database-consistency boundary: while autoanalysis is active it only
  // reports the waiting state. Once the database is settled, it either starts
  // the sweep or prints an immediate status snapshot to the Output window.
  if ( !started )
  {
    if ( !auto_is_ok() )
    {
      emit_status(true, ViyLogLevel::SUMMARY);
      return true;
    }
    on_analysis_done();
    if ( !started )
      return true; // on_analysis_done() emitted the exact skip reason
  }
  if ( started )
    emit_status(true, ViyLogLevel::SUMMARY);
  return true;
}

//-----------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new viy_t;
}

//-----------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI | PLUGIN_MOD, // per-IDB; visible entry prints the live status
  init,
  nullptr, // term  (must be nullptr for PLUGIN_MULTI)
  nullptr, // run   (must be nullptr for PLUGIN_MULTI; plugmod_t::run is used)
  "viy: recover missed analysis facts and report live progress",
  "Print the current viy analysis status or start the sweep",
  "viy",
};
