/*
 * viy.cpp — plugin lifecycle & the transparent, chunked sweep.
 *
 * viy is a hidden, multi-IDB, database-modifying plugin. IDA instantiates one
 * plugmod per open database; in its constructor viy hooks HT_IDB and waits for
 * the first auto-analysis pass to finish (idb_event::auto_empty_finally). It
 * then snapshots the program and submits immutable function jobs to independent
 * off-thread rax engines. The UI timer drains results in deterministic function
 * order; every IDA query and database mutation remains on the main thread. If
 * librax is absent or a backend cannot be driven, native/static providers still
 * run. There are no dialogs or errors, and at most one summary line when viy
 * actually finds something.
 */
#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
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
  void stop_workers();
  void start_sweep();
  bool process_batch(int count); // true => more entries remain
  void finish();
};

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
viy_t::viy_t()
{
  cfg = viy_load_config();
  if ( cfg.persist_evidence )
  {
    std::string ignored;
    evidence.restore(evidence_adapter, analysis::RestoreMode::Replace,
                     nullptr, &ignored);
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
    std::string ignored;
    hexrays.start({}, &ignored);
  }
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
    return;

  ViyArch arch;
  bool be;
  if ( !viy_detect_arch(arch, be) )
    return;

  // Native providers remain useful without librax. Each rax-backed provider is
  // capability-gated independently in begin_epoch().
  api = rax_load();

  started = true;
  epoch = 0;
  funcs_done = 0;
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
  if ( !begin_epoch() )
  {
    started = false;
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

  viy_snapshot(img, cfg);
  assign_function_generations();
  snapshot_provider_function_starts();
  provider_generation = allocate_generation();
  can_native = cfg.want_native;
  can_deobf = cfg.want_deobf;
  can_static = false;
  call_summaries = cfg.want_import_summaries
                 ? viy_collect_call_summaries() : std::vector<EmuCallSummary>{};
  const bool can_attempt_dynamic = api != nullptr && !img.entries.empty();
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

    size_t worker_count = viy_resolve_worker_count(cfg.workers);
    worker_count = std::min(worker_count, std::max<size_t>(img.entries.size(), 1));
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

  if ( worker_pool == nullptr && !can_static && !can_native && !can_deobf )
    return false;

  // The native provider can discover the first function in an IDB that has no
  // current functions, so an empty function snapshot is not a terminal state.
  if ( img.entries.empty() && !can_native )
    return false;

  if ( can_native && native_provider != nullptr )
  {
    // A provider scan is a complete snapshot. Re-emitting all current facts at
    // one externally unique generation also retires facts that disappeared.
    native_provider->reset();
    native_provider->set_epoch(provider_generation);
    NativeAnalysisOptions options;
    options.max_functions = cfg.max_funcs == 0 ? 0 : size_t(cfg.max_funcs);
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
  }

  if ( can_deobf && deobf_provider != nullptr )
  {
    deobf_provider->reset();
    deobf_provider->set_epoch(provider_generation);
    deobf_store_sink->set_active_generation(provider_generation);
    DeobfAnalysisOptions options;
    options.max_functions = cfg.max_funcs == 0 ? 0 : size_t(cfg.max_funcs);
    merge_deobf_stats(deobf_stats,
                      deobf_provider->analyze_database(options));
  }

  next = 0;
  worker_jobs.clear();
  waiting_for_auto = false;
  epoch_change_base = change_count();
  return true;
}

//-----------------------------------------------------------------------------
void viy_t::start_sweep()
{
  timer = register_timer(cfg.tick_ms, viy_sweep_cb, this);
  if ( timer == nullptr )
  {
    // No UI timer available (e.g. headless idalib): run to completion inline.
    inline_mode = true;
    while ( process_batch(cfg.funcs_per_tick ) )
      ; // keep going
    inline_mode = false;
    finish();
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
}

//-----------------------------------------------------------------------------
void viy_t::stop_workers()
{
  if ( worker_pool != nullptr )
  {
    worker_pool->shutdown();
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
        return true;
      auto_wait();
    }
    ++epoch;
    if ( !begin_epoch() )
      return false;
  }

  const size_t budget = size_t(std::max(count, 1));
  if ( worker_pool != nullptr )
  {
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
      if ( !worker_pool->try_submit(std::move(job), &ticket) )
        break; // bounded queue backpressure; retry on the next timer tick
      worker_jobs.emplace(ticket, WorkerJobInfo{ next, fingerprint });
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
      return true;
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
      return true;
  }

  // Release per-worker engines and their immutable snapshot before applying
  // producer-neutral facts or waiting for the next autoanalysis epoch.
  stop_workers();

  // Apply producer-neutral facts only after all providers have completed the
  // epoch.  The consumer is contradiction-aware and confidence-gated, and its
  // mutations participate in the convergence test below.
  const analysis::EvidenceStore active_evidence = active_evidence_view();
  const EvidenceApplyStats applied = viy_apply_evidence(active_evidence, cfg);
  evidence_stats.refs.crefs += applied.refs.crefs;
  evidence_stats.refs.drefs += applied.refs.drefs;
  evidence_stats.refs.code_made += applied.refs.code_made;
  evidence_stats.functions_created += applied.functions_created;
  evidence_stats.comments_added += applied.comments_added;
  evidence_stats.records_considered += applied.records_considered;
  evidence_stats.records_conflicted += applied.records_conflicted;
  evidence_stats.records_below_policy += applied.records_below_policy;

  if ( cfg.want_hexrays_bridge )
    hexrays.publish(active_evidence);

  if ( cfg.persist_evidence )
  {
    std::string ignored;
    evidence.persist(evidence_adapter, &ignored);
  }

  const bool changed = change_count() > epoch_change_base;
  if ( changed && epoch + 1 < cfg.max_epochs )
  {
    waiting_for_auto = true;
    return true;
  }
  return false;
}

//-----------------------------------------------------------------------------
void viy_t::finish()
{
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
  if ( ind_c || dir_c || ev_c || drefs || ptrs || typed || strs || cmts || sw || pg || nr || ar || op
    || fn || smc )
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
  // Hidden plugin: normally driven by auto_empty_finally. If invoked manually
  // (e.g. via the plugin API), kick off the sweep if it has not run yet.
  if ( !started )
    on_analysis_done();
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
  PLUGIN_MULTI | PLUGIN_MOD | PLUGIN_HIDE, // per-IDB, changes DB, invisible in menus
  init,
  nullptr, // term  (must be nullptr for PLUGIN_MULTI)
  nullptr, // run   (must be nullptr for PLUGIN_MULTI; plugmod_t::run is used)
  "viy: recover indirect xrefs the analysis missed, via rax emulation",
  "",
  "viy",
};
