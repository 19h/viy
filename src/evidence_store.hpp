/*
 * evidence_store.hpp -- deterministic, producer-neutral evidence ledger.
 *
 * EvidenceStore is IDA-independent.  An IDA netnode implementation can satisfy
 * EvidencePersistenceAdapter without leaking SDK types into this layer.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "analysis_facts.hpp"

namespace viy {
namespace analysis {

struct EvidenceRecord
{
  FactPayload payload;
  // Canonically sorted and deduplicated.  Every element independently records
  // producer/method/proof/run scope; merging never manufactures provenance.
  std::vector<Evidence> observations;
};

struct SupportSummary
{
  size_t observation_count = 0;
  size_t distinct_run_count = 0;
  size_t distinct_seed_count = 0;
  size_t distinct_run_seed_count = 0;
  size_t distinct_producer_count = 0;
  size_t distinct_method_count = 0;
  size_t distinct_generation_count = 0;
  uint16_t minimum_confidence = 0;
  uint16_t maximum_confidence = 0;
  uint64_t minimum_generation = 0;
  uint64_t maximum_generation = 0;
};

SupportSummary summarize_support(const EvidenceRecord &record);

// Corroboration is intentionally based on distinct explicit run IDs and
// producers, not raw observation count.  Static evidence without a run ID can
// still satisfy the producer requirement but cannot impersonate repeated runs.
bool is_corroborated(const EvidenceRecord &record,
                     size_t minimum_distinct_runs = 2,
                     size_t minimum_distinct_producers = 1,
                     uint16_t minimum_each_confidence = 0);

enum class AddDisposition : uint8_t
{
  InsertedRecord = 1,
  AddedObservation,
  DuplicateObservation,
  RejectedInvalid,
};

struct AddResult
{
  AddDisposition disposition = AddDisposition::RejectedInvalid;
  FactDigest payload_digest;
  std::string error;
};

struct MergeReport
{
  size_t inserted_records = 0;
  size_t added_observations = 0;
  size_t duplicate_observations = 0;
  size_t rejected_observations = 0;
  size_t records_after = 0;
  size_t observations_after = 0;
  size_t conflicts_after = 0;
  std::vector<std::string> errors;
};

enum class ConflictSeverity : uint8_t
{
  Variation = 1,    // inputs/runs produced different concrete values/outcomes
  Ambiguity,        // competing candidates; neither claims a proof of exclusion
  Contradiction,    // assertions cannot simultaneously be true
};

enum class ConflictType : uint8_t
{
  ReachableAndUnreachable = 1,
  DivergentMemoryValue,
  DivergentStringCandidate,
  DivergentFunctionCandidate,
  DivergentFunctionTrait,
  ReturnBehaviorContradiction,
  IncompatibleCodeRegion,
  DivergentDispatchCase,
  DivergentCfgReachability,
  DivergentFunctionOutcome,
  ConflictingUniqueCodeTarget,
  DivergentRegisterValue,
  DivergentCallObservation,
};

struct EvidenceConflict
{
  ConflictType type = ConflictType::ReachableAndUnreachable;
  ConflictSeverity severity = ConflictSeverity::Variation;
  FactDigest left;
  FactDigest right;
  Address subject = 0;
  std::optional<Address> secondary_subject;
  std::string explanation;
};

bool conflict_less(const EvidenceConflict &lhs, const EvidenceConflict &rhs);

struct StoreCodecLimits
{
  size_t max_blob_bytes = 64u * 1024u * 1024u;
  size_t max_observations = 1000000u;
  FactCodecLimits fact_limits;
};

// Storage boundary implemented later by an IDA netnode adapter, a test-memory
// adapter, or another host.  write_blob should replace the prior value only on
// success (atomically where the host supports it).  An empty blob is not an
// encoded store; "not found" should be reported as false with a useful error.
class EvidencePersistenceAdapter
{
public:
  virtual ~EvidencePersistenceAdapter() = default;
  virtual bool read_blob(std::vector<uint8_t> &out, std::string &error) const = 0;
  virtual bool write_blob(const std::vector<uint8_t> &blob, std::string &error) = 0;
};

enum class RestoreMode : uint8_t
{
  Replace = 1,
  Merge,
};

class EvidenceStore
{
public:
  // Keep all special members out of line.  Besides reducing compile-time
  // template expansion at IDA integration sites, this turns a stale mixed-ABI
  // object build into a link failure instead of letting a translation unit
  // instantiate std::map destruction against a different FactPayload schema.
  EvidenceStore();
  ~EvidenceStore();
  EvidenceStore(const EvidenceStore &other);
  EvidenceStore(EvidenceStore &&other) noexcept;
  EvidenceStore &operator=(const EvidenceStore &other);
  EvidenceStore &operator=(EvidenceStore &&other) noexcept;

  AddResult add(AnalysisFact fact);
  MergeReport merge(const EvidenceStore &other);

  void clear();
  bool empty() const { return records_.empty(); }
  size_t record_count() const { return records_.size(); }
  size_t observation_count() const;

  // Returned collections are deterministic regardless of insertion order.
  std::vector<EvidenceRecord> records() const;
  std::vector<AnalysisFact> flattened_facts() const;

  // Return the observations that are active for the current producer
  // snapshots while leaving this store's complete history untouched.
  //
  // A snapshot is keyed by (producer, function_start).  For each such key,
  // only observations whose generation is the maximum generation seen for
  // that key are retained.  All observations tied at that maximum remain
  // active, including observations from different methods, runs and payloads.
  // Generations are producer-local: one producer can never retire another
  // producer's evidence.  Evidence without function_start is not a function
  // snapshot and is retained at every generation.
  //
  // Producers using this view must treat a newer function generation as a
  // complete snapshot: facts omitted from that generation become historical.
  // The returned store has the same canonical ordering/deduplication rules as
  // any EvidenceStore, so its records, flattened facts and serialization are
  // deterministic regardless of insertion order in the source store.
  EvidenceStore latest_generation_view() const;

  // Pointer remains valid until a non-const operation on this store.
  const EvidenceRecord *find(const FactPayload &payload) const;

  std::vector<EvidenceConflict> detect_conflicts() const;

  // The store envelope has magic, schema version, observation count and a
  // SHA-256 trailer.  deserialize is transactional: `out` is unchanged unless
  // the complete blob validates, verifies and decodes successfully.
  bool serialize(std::vector<uint8_t> &out, std::string *error = nullptr) const;
  static bool deserialize(const std::vector<uint8_t> &blob,
                          EvidenceStore &out,
                          std::string *error = nullptr,
                          const StoreCodecLimits &limits = {});

  bool persist(EvidencePersistenceAdapter &adapter,
               std::string *error = nullptr) const;
  bool restore(const EvidencePersistenceAdapter &adapter,
               RestoreMode mode,
               MergeReport *report = nullptr,
               std::string *error = nullptr,
               const StoreCodecLimits &limits = {});

private:
  // Canonical payload bytes are the key.  Hashes are exposed as stable IDs but
  // never used alone for identity, eliminating collision-based mis-dedup.
  std::map<std::vector<uint8_t>, EvidenceRecord> records_;
};

} // namespace analysis
} // namespace viy
