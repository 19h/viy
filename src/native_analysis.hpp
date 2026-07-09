/*
 * native_analysis.hpp -- read-only IDA-native analysis fact producer.
 *
 * This layer deliberately has no dependency on rax and exposes no IDA SDK
 * types.  It can therefore feed the same evidence ledger as emulation without
 * coupling consumers to either implementation.  All addresses are uint64_t;
 * kNativeBadAddress is the producer-neutral equivalent of BADADDR.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

#include "analysis_facts.hpp"

namespace viy {

namespace analysis {
class EvidenceStore;
}

constexpr uint64_t kNativeBadAddress = ~uint64_t(0);

enum class NativeArchitecture : uint8_t
{
  Unsupported = 0,
  X86,
  Arm32,
  Arm64,
};

enum class NativeEvidenceSource : uint8_t
{
  IdaRegfinder = 0,
  ArchitectureInvariant,
  StructuralIdentity,
  LocalFlagProof,
  DirectControlFlow,
  DecoderEquivalence,
  IdaItemDiscrepancy,
};

// Strength describes the proof, not whether a consumer should mutate the IDB.
// This producer never performs mutations; consumers must apply their own policy.
enum class NativeEvidenceStrength : uint8_t
{
  Candidate = 0,
  Strong,
  Exact,
};

struct NativeFactProvenance
{
  // Stable producer/schema identity for persistence adapters.
  static constexpr const char *producer_name = "viy.native.ida";
  static constexpr uint32_t schema_version = 1;

  uint64_t epoch = 0;
  uint64_t function_ea = kNativeBadAddress;
  uint64_t chunk_start = kNativeBadAddress;
  uint64_t chunk_end = kNativeBadAddress;
  NativeArchitecture architecture = NativeArchitecture::Unsupported;
  NativeEvidenceSource source = NativeEvidenceSource::IdaItemDiscrepancy;
  NativeEvidenceStrength strength = NativeEvidenceStrength::Candidate;
  uint32_t supporting_observations = 1;
  bool deterministic = false;
};

enum class NativeControlFlowKind : uint8_t
{
  Call = 0,
  Jump,
};

enum class NativeIndirectResolutionKind : uint8_t
{
  RegisterValue = 0,
  ReadOnlyMemoryValue,
};

struct NativeIndirectTargetFact
{
  uint64_t instruction_ea = kNativeBadAddress;
  uint64_t target_ea = kNativeBadAddress;
  uint64_t definition_ea = kNativeBadAddress;
  uint64_t pointer_ea = kNativeBadAddress;
  NativeControlFlowKind kind = NativeControlFlowKind::Jump;
  NativeIndirectResolutionKind resolution =
      NativeIndirectResolutionKind::RegisterValue;
  int32_t register_id = -1;
  std::string register_name;
  uint8_t value_width = 0;
  bool edge_already_present = false;
};

enum class NativeBranchOutcome : uint8_t
{
  AlwaysTaken = 0,
  NeverTaken,
};

struct NativeZeroRegisterBranchFact
{
  uint64_t instruction_ea = kNativeBadAddress;
  uint64_t target_ea = kNativeBadAddress;
  uint64_t fallthrough_ea = kNativeBadAddress;
  NativeBranchOutcome outcome = NativeBranchOutcome::AlwaysTaken;
  int32_t register_id = -1;
  std::string register_name;
  uint8_t value_width = 0;
};

enum class NativeOppositeBranchFamily : uint8_t
{
  X86Jcc = 0,
  ArmCondition,
  ArmCompareZero,
  ArmTestBit,
};

struct NativeOppositeBranchPairFact
{
  uint64_t first_ea = kNativeBadAddress;
  uint64_t second_ea = kNativeBadAddress;
  uint64_t guaranteed_target_ea = kNativeBadAddress;
  uint64_t unreachable_fallthrough_ea = kNativeBadAddress;
  NativeOppositeBranchFamily family = NativeOppositeBranchFamily::X86Jcc;
  uint16_t first_condition = 0;
  uint16_t second_condition = 0;
};

enum class NativeTrackedFlag : uint8_t
{
  Carry = 0,
  Zero,
};

enum class NativeFlagValue : uint8_t
{
  Clear = 0,
  Set,
};

struct NativeKnownFlagBranchFact
{
  uint64_t instruction_ea = kNativeBadAddress;
  uint64_t target_ea = kNativeBadAddress;
  uint64_t fallthrough_ea = kNativeBadAddress;
  uint64_t defining_instruction_ea = kNativeBadAddress;
  NativeTrackedFlag flag = NativeTrackedFlag::Carry;
  NativeFlagValue value = NativeFlagValue::Clear;
  NativeBranchOutcome outcome = NativeBranchOutcome::AlwaysTaken;
  uint32_t instructions_scanned = 0;
};

enum class NativeFunctionCandidateReason : uint8_t
{
  DirectCallToUnownedCode = 0,
  IndirectCallToUnownedCode,
  DirectCallToFunctionInterior,
  IndirectCallToFunctionInterior,
  DirectCallToDecodableBytes,
  IndirectCallToDecodableBytes,
};

struct NativeFunctionCandidateFact
{
  uint64_t callsite_ea = kNativeBadAddress;
  uint64_t target_ea = kNativeBadAddress;
  NativeFunctionCandidateReason reason =
      NativeFunctionCandidateReason::DirectCallToUnownedCode;
  uint16_t decoded_size = 0;
  bool target_is_code = false;
  bool target_is_function_interior = false;
};

enum class NativeDecodeDiscrepancyKind : uint8_t
{
  RedundantLegacyPrefix = 0,
  DetachedLegacyPrefix,
  CodeItemSizeMismatch,
  UndecodableCodeItem,
  DirectTargetNotCode,
};

struct NativeDecodeDiscrepancyFact
{
  uint64_t address = kNativeBadAddress;
  uint64_t related_ea = kNativeBadAddress;
  NativeDecodeDiscrepancyKind kind =
      NativeDecodeDiscrepancyKind::CodeItemSizeMismatch;
  uint16_t idb_item_size = 0;
  uint16_t decoded_size = 0;
  uint16_t alternate_decoded_size = 0;
  uint8_t observed_byte = 0;
};

using NativeFactPayload = std::variant<
    NativeIndirectTargetFact,
    NativeZeroRegisterBranchFact,
    NativeOppositeBranchPairFact,
    NativeKnownFlagBranchFact,
    NativeFunctionCandidateFact,
    NativeDecodeDiscrepancyFact>;

struct NativeFact
{
  NativeFactProvenance provenance;
  NativeFactPayload payload;
};

// Implementations should copy a fact if it must outlive emit().  emit() is
// called synchronously on IDA's database/main thread and must not mutate the
// IDB while a scan is in progress.
class NativeFactSink
{
public:
  virtual ~NativeFactSink() = default;
  virtual void emit(const NativeFact &fact) = 0;
};

// EvidenceStore-compatible boundary.  The store (or a validating wrapper
// around it) can implement this one-method interface without making the native
// analyzer depend on storage, persistence, or IDA mutation policy.
class NativeAnalysisFactSink
{
public:
  virtual ~NativeAnalysisFactSink() = default;
  virtual void emit_analysis_fact(const analysis::AnalysisFact &fact) = 0;
};

// Lossless-enough bridge from native-specific facts to the shared schema.
// One native branch proof can produce multiple neutral facts (a reached edge
// and a proven-unreachable edge).  Native-only structure is retained in
// Evidence.method/detail/support_addresses.
class NativeAnalysisFactAdapter final : public NativeFactSink
{
public:
  explicit NativeAnalysisFactAdapter(NativeAnalysisFactSink &sink);
  ~NativeAnalysisFactAdapter() override;

  NativeAnalysisFactAdapter(const NativeAnalysisFactAdapter &) = delete;
  NativeAnalysisFactAdapter &operator=(const NativeAnalysisFactAdapter &) = delete;

  void emit(const NativeFact &fact) override;

private:
  NativeAnalysisFactSink &sink_;
};

struct NativeEvidenceStoreReport
{
  size_t inserted_records = 0;
  size_t added_observations = 0;
  size_t duplicate_observations = 0;
  size_t rejected_facts = 0;
};

// Direct validating sink for the shared EvidenceStore.  Rejections are counted
// and the most recent validation error is retained for diagnostics; analysis
// continues so one malformed candidate cannot suppress unrelated evidence.
class NativeEvidenceStoreSink final : public NativeAnalysisFactSink
{
public:
  explicit NativeEvidenceStoreSink(analysis::EvidenceStore &store);
  ~NativeEvidenceStoreSink() override;

  void emit_analysis_fact(const analysis::AnalysisFact &fact) override;
  const NativeEvidenceStoreReport &report() const { return report_; }
  const char *last_error() const { return last_error_.c_str(); }
  void reset_report();

private:
  analysis::EvidenceStore &store_;
  NativeEvidenceStoreReport report_;
  std::string last_error_;
};

struct NativeAnalysisOptions
{
  bool resolve_indirect_control_flow = true;
  bool detect_zero_register_branches = true;
  bool detect_opposite_branch_pairs = true;
  bool track_known_x86_flags = true;
  bool find_function_candidates = true;
  bool detect_decode_discrepancies = true;

  // Also inspect executable code heads which are not owned by a function.
  // This is necessary for discovering chains of orphan callees.
  bool scan_unowned_executable_code = true;

  // By default an IDA-native target is emitted only when the exact IDB edge is
  // absent.  Enabling this lets a ledger use regfinder as corroboration too.
  bool emit_existing_indirect_edges = false;

  // 0 means all.  Limits are deterministic and count in address/index order.
  size_t max_functions = 0;
  size_t max_instructions_per_function = 0;
  size_t max_unowned_instructions = 0;

  // Public IDA semantics: 0 uses REGTRACK_MAX_DEPTH from ida.cfg.  Negative
  // values are rejected rather than acquiring version-specific behavior.
  int regfinder_max_depth = 0;
  uint32_t flag_scan_depth = 8;
};

struct NativeAnalysisStats
{
  NativeArchitecture architecture = NativeArchitecture::Unsupported;
  uint64_t epoch = 0;
  size_t functions_scanned = 0;
  size_t chunks_scanned = 0;
  size_t instructions_scanned = 0;
  size_t decode_failures = 0;
  size_t facts_emitted = 0;
  size_t facts_deduplicated = 0;
  size_t indirect_targets = 0;
  size_t zero_register_branches = 0;
  size_t opposite_branch_pairs = 0;
  size_t known_flag_branches = 0;
  size_t function_candidates = 0;
  size_t decode_discrepancies = 0;
  bool regfinder_supported = true;
};

// One provider must be owned by one IDB/plugmod instance.  There is no global
// cache.  Calls read the live database and must run on IDA's main thread.
class NativeAnalysisProvider
{
public:
  explicit NativeAnalysisProvider(NativeFactSink &sink);
  ~NativeAnalysisProvider();

  NativeAnalysisProvider(const NativeAnalysisProvider &) = delete;
  NativeAnalysisProvider &operator=(const NativeAnalysisProvider &) = delete;
  NativeAnalysisProvider(NativeAnalysisProvider &&) noexcept;
  NativeAnalysisProvider &operator=(NativeAnalysisProvider &&) noexcept;

  // Scan every function, including every tail chunk.  Repeated calls rescan
  // live IDB state but suppress identical facts, making this safe after auto-
  // analysis convergence events.
  NativeAnalysisStats analyze_database(
      const NativeAnalysisOptions &options = NativeAnalysisOptions{});

  // Incremental entry point.  any_ea may be the entry, a tail, or an address
  // inside the function; the complete function (all chunks) is always scanned.
  NativeAnalysisStats analyze_function(
      uint64_t any_ea,
      const NativeAnalysisOptions &options = NativeAnalysisOptions{});

  // Start a new provenance epoch while retaining duplicate suppression.
  void advance_epoch();

  // Assign an externally allocated, persistence-safe provenance generation.
  // Callers that restore historical evidence can use this to avoid reusing a
  // prior process-local epoch. Zero is normalized to one.
  void set_epoch(uint64_t epoch);

  // Forget facts associated with one complete function so a subsequent scan
  // re-emits its current evidence.  The epoch advances even if no state existed.
  void invalidate_function(uint64_t any_ea);

  // Forget all emitted keys and start a new epoch.
  void reset();

  uint64_t epoch() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace viy
