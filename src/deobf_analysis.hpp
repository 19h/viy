/*
 * deobf_analysis.hpp -- read-only IDA deobfuscation evidence producer.
 *
 * This provider complements native_analysis: it does not repeat regfinder
 * indirect resolution, zero-register/opposite-condition proofs, CF/ZF scans,
 * orphan-function discovery, or decoder-prefix auditing.  It emits only the
 * additional structural/constant/dispatcher evidence described here.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "analysis_facts.hpp"
#include "deobf_analysis_core.hpp"

namespace viy {

namespace analysis {
class EvidenceStore;
}

constexpr uint32_t kDeobfEvidenceSchemaVersion = 1;

class DeobfAnalysisFactSink
{
public:
  virtual ~DeobfAnalysisFactSink() = default;
  // Return true when the fact was accepted (including a duplicate
  // observation). Rejected/suppressed facts remain eligible for a later scan.
  virtual bool emit_deobf_fact(const analysis::AnalysisFact &fact) = 0;
};

struct DeobfEvidenceStoreReport
{
  size_t inserted_records = 0;
  size_t added_observations = 0;
  size_t duplicate_observations = 0;
  size_t rejected_invalid = 0;
  size_t contradictions_suppressed = 0;
};

// Validates every producer output and transactionally rejects a candidate if
// adding its observation would introduce a contradiction involving that
// payload in the active-generation view. Ambiguities/variations are retained;
// stale observations remain in history; user assertions remain active across
// generations; and corroboration that introduces no new conflict is admitted.
class DeobfEvidenceStoreSink final : public DeobfAnalysisFactSink
{
public:
  explicit DeobfEvidenceStoreSink(analysis::EvidenceStore &store);
  ~DeobfEvidenceStoreSink() override;

  bool emit_deobf_fact(const analysis::AnalysisFact &fact) override;
  const DeobfEvidenceStoreReport &report() const { return report_; }
  const char *last_error() const { return last_error_.c_str(); }
  void reset_report();

  // Limit contradiction gating to the current complete static scan (plus
  // explicit user assertions). Historical observations stay in the ledger but
  // cannot suppress evidence from a newer IDB snapshot. Zero restores the
  // conservative all-history view.
  void set_active_generation(uint64_t generation);

private:
  analysis::EvidenceStore &store_;
  DeobfEvidenceStoreReport report_;
  std::string last_error_;
  uint64_t active_generation_ = 0;
};

enum class DeobfAnalysisProgressStage : uint8_t
{
  FUNCTIONS = 0,
  COMPLETE,
};

struct DeobfAnalysisProgress
{
  DeobfAnalysisProgressStage stage = DeobfAnalysisProgressStage::FUNCTIONS;
  size_t functions_completed = 0;
  size_t functions_total = 0;
  size_t instructions_scanned = 0;
  size_t blocks_scanned = 0;
  size_t facts_emitted = 0;
  bool stage_boundary = false;
};

using DeobfAnalysisProgressCallback =
    std::function<void(const DeobfAnalysisProgress &)>;

struct DeobfAnalysisOptions
{
  bool detect_get_pc_gadgets = true;
  bool detect_push_return_gadgets = true;
  bool detect_jump_gaps = true;
  bool detect_entry_predicates = true;
  bool detect_wrappers = true;
  bool resolve_constant_chains = true;
  bool detect_dispatch_maps = true;

  // Deterministic address/index-order budgets. Zero selects the provider's
  // finite hard safety ceiling (1M instructions / 100K blocks); scans are never
  // actually unbounded. max_functions==0 means the finite IDB function count.
  size_t max_functions = 0;
  size_t max_instructions_per_function = 4096;
  size_t max_blocks_per_function = 1024;
  deobf::ClassifierLimits classifier_limits;

  // Observability only. Invoked synchronously after each deterministic
  // function position and at phase boundaries; it must not mutate the IDB.
  DeobfAnalysisProgressCallback progress;
};

struct DeobfAnalysisStats
{
  deobf::Architecture architecture = deobf::Architecture::Unsupported;
  uint64_t epoch = 0;
  size_t functions_scanned = 0;
  size_t chunks_scanned = 0;
  size_t blocks_scanned = 0;
  size_t instructions_scanned = 0;
  size_t decode_failures = 0;
  size_t facts_emitted = 0;
  size_t facts_deduplicated = 0;
  size_t get_pc_gadgets = 0;
  size_t push_return_targets = 0;
  size_t code_region_candidates = 0;
  size_t entry_predicates = 0;
  size_t constant_predicates = 0;
  size_t wrapper_traits = 0;
  size_t constant_targets = 0;
  size_t dispatch_maps = 0;
  size_t cff_edge_candidates = 0;
  size_t budget_truncations = 0;
};

// One instance belongs to one IDB/plugmod and must be called on IDA's main
// thread.  Scans perform no IDB mutations.  Repeated scans suppress identical
// semantic payloads until their function is invalidated.
class DeobfAnalysisProvider
{
public:
  explicit DeobfAnalysisProvider(DeobfAnalysisFactSink &sink);
  ~DeobfAnalysisProvider();

  DeobfAnalysisProvider(const DeobfAnalysisProvider &) = delete;
  DeobfAnalysisProvider &operator=(const DeobfAnalysisProvider &) = delete;
  DeobfAnalysisProvider(DeobfAnalysisProvider &&) noexcept;
  DeobfAnalysisProvider &operator=(DeobfAnalysisProvider &&) noexcept;

  DeobfAnalysisStats analyze_database(
      const DeobfAnalysisOptions &options = DeobfAnalysisOptions{});
  DeobfAnalysisStats analyze_function(
      uint64_t any_ea,
      const DeobfAnalysisOptions &options = DeobfAnalysisOptions{});

  void advance_epoch();
  void set_epoch(uint64_t epoch);
  void invalidate_function(uint64_t any_ea);
  void reset();
  uint64_t epoch() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace viy
