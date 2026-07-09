#include "evidence_store.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace viy {
namespace analysis {
namespace {

constexpr uint8_t kStoreMagic[8] = {'V', 'I', 'Y', 'E', 'V', 'D', 'B', 0};
constexpr uint16_t kStoreMajor = 1;
constexpr uint16_t kStoreMinor = 0;
constexpr uint32_t kStoreFlagSha256 = 1;
constexpr size_t kDigestSize = 32;

bool fail(std::string *error, const std::string &message)
{
  if (error != nullptr)
    *error = message;
  return false;
}

class StoreWriter
{
public:
  void raw(const uint8_t *data, size_t size)
  {
    if (size == 0)
      return;
    bytes_.insert(bytes_.end(), data, data + size);
  }

  void u8(uint8_t value) { bytes_.push_back(value); }

  void u16(uint16_t value)
  {
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }

  void u32(uint32_t value)
  {
    u8(static_cast<uint8_t>(value >> 24));
    u8(static_cast<uint8_t>(value >> 16));
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }

  void u64(uint64_t value)
  {
    for (int shift = 56; shift >= 0; shift -= 8)
      u8(static_cast<uint8_t>(value >> shift));
  }

  const std::vector<uint8_t> &bytes() const { return bytes_; }
  std::vector<uint8_t> take() { return std::move(bytes_); }

private:
  std::vector<uint8_t> bytes_;
};

class StoreReader
{
public:
  explicit StoreReader(const std::vector<uint8_t> &bytes) : bytes_(bytes) {}

  bool raw(uint8_t *out, size_t size)
  {
    if (size > remaining())
      return set_error("truncated evidence-store envelope");
    if (size != 0)
      std::memcpy(out, bytes_.data() + pos_, size);
    pos_ += size;
    return true;
  }

  bool magic()
  {
    uint8_t actual[sizeof(kStoreMagic)]{};
    if (!raw(actual, sizeof(actual)))
      return false;
    if (std::memcmp(actual, kStoreMagic, sizeof(actual)) != 0)
      return set_error("evidence-store envelope has the wrong magic");
    return true;
  }

  bool u8(uint8_t &out)
  {
    if (remaining() == 0)
      return set_error("truncated evidence-store envelope");
    out = bytes_[pos_++];
    return true;
  }

  bool u16(uint16_t &out)
  {
    uint8_t a = 0, b = 0;
    if (!u8(a) || !u8(b))
      return false;
    out = static_cast<uint16_t>((static_cast<uint16_t>(a) << 8) | b);
    return true;
  }

  bool u32(uint32_t &out)
  {
    uint8_t bytes[4]{};
    if (!raw(bytes, sizeof(bytes)))
      return false;
    out = (static_cast<uint32_t>(bytes[0]) << 24) |
          (static_cast<uint32_t>(bytes[1]) << 16) |
          (static_cast<uint32_t>(bytes[2]) << 8) |
          static_cast<uint32_t>(bytes[3]);
    return true;
  }

  bool u64(uint64_t &out)
  {
    uint8_t bytes[8]{};
    if (!raw(bytes, sizeof(bytes)))
      return false;
    out = 0;
    for (uint8_t byte : bytes)
      out = (out << 8) | byte;
    return true;
  }

  bool blob(size_t size, std::vector<uint8_t> &out)
  {
    if (size > remaining())
      return set_error("truncated length-delimited fact in evidence store");
    out.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(pos_),
               bytes_.begin() + static_cast<std::ptrdiff_t>(pos_ + size));
    pos_ += size;
    return true;
  }

  size_t remaining() const { return bytes_.size() - pos_; }
  const std::string &error() const { return error_; }

private:
  bool set_error(const char *message)
  {
    if (error_.empty())
      error_ = message;
    return false;
  }

  const std::vector<uint8_t> &bytes_;
  size_t pos_ = 0;
  std::string error_;
};

std::string hex_address(Address address)
{
  std::ostringstream stream;
  stream << "0x" << std::hex << address;
  return stream.str();
}

bool opposite_reachability(Reachability lhs, Reachability rhs)
{
  return (lhs == Reachability::Reached && rhs == Reachability::ProvenUnreachable) ||
         (rhs == Reachability::Reached && lhs == Reachability::ProvenUnreachable);
}

bool region_kinds_incompatible(CodeRegionKind lhs, CodeRegionKind rhs)
{
  if (lhs == rhs || lhs == CodeRegionKind::Unknown || rhs == CodeRegionKind::Unknown ||
      lhs == CodeRegionKind::Mixed || rhs == CodeRegionKind::Mixed)
    return false;
  const bool left_code = lhs == CodeRegionKind::Code;
  const bool right_code = rhs == CodeRegionKind::Code;
  const bool left_noncode = lhs == CodeRegionKind::Data || lhs == CodeRegionKind::Padding;
  const bool right_noncode = rhs == CodeRegionKind::Data || rhs == CodeRegionKind::Padding;
  return (left_code && right_noncode) || (right_code && left_noncode);
}

bool is_return_trait(FunctionTraitKind trait)
{
  return trait == FunctionTraitKind::Returns || trait == FunctionTraitKind::NoReturn;
}

void canonicalize_conflict_digests(EvidenceConflict &conflict)
{
  if (conflict.right < conflict.left)
    std::swap(conflict.left, conflict.right);
}

void add_conflict(std::vector<EvidenceConflict> &out,
                  ConflictType type,
                  ConflictSeverity severity,
                  const FactPayload &left_payload,
                  const FactPayload &right_payload,
                  Address subject,
                  std::optional<Address> secondary,
                  std::string explanation)
{
  EvidenceConflict conflict;
  conflict.type = type;
  conflict.severity = severity;
  // Store records are always valid, so digest failure cannot occur here.
  std::string ignored;
  stable_digest(left_payload, conflict.left, &ignored);
  stable_digest(right_payload, conflict.right, &ignored);
  canonicalize_conflict_digests(conflict);
  conflict.subject = subject;
  conflict.secondary_subject = secondary;
  conflict.explanation = std::move(explanation);
  out.push_back(std::move(conflict));
}

std::set<Address> dispatch_targets(const DispatchMapFact &fact)
{
  std::set<Address> result;
  for (const DispatchCase &dispatch_case : fact.cases)
    result.insert(dispatch_case.target);
  if (fact.default_target.has_value())
    result.insert(*fact.default_target);
  return result;
}

const CallValue *find_call_value(const std::vector<CallValue> &values,
                                 uint32_t ordinal,
                                 const std::string &location)
{
  const auto found = std::lower_bound(
    values.begin(), values.end(), std::tie(ordinal, location),
    [](const CallValue &value, const auto &key) {
      return std::tie(value.ordinal, value.location) < key;
    });
  if (found == values.end() || found->ordinal != ordinal || found->location != location)
    return nullptr;
  return &*found;
}

bool overlapping_call_values_differ(const std::vector<CallValue> &left,
                                    const std::vector<CallValue> &right)
{
  for (const CallValue &value : left)
  {
    const CallValue *other = find_call_value(right, value.ordinal, value.location);
    if (other != nullptr && other->bytes != value.bytes)
      return true;
  }
  return false;
}

void compare_dispatch_maps(const FactPayload &left_payload,
                           const DispatchMapFact &left,
                           const FactPayload &right_payload,
                           const DispatchMapFact &right,
                           std::vector<EvidenceConflict> &out)
{
  if (left.site != right.site)
    return;

  for (const DispatchCase &left_case : left.cases)
  {
    if (!left_case.selector.has_value())
      continue;
    for (const DispatchCase &right_case : right.cases)
    {
      if (right_case.selector != left_case.selector)
        continue;
      if (right_case.target != left_case.target)
      {
        const ConflictSeverity severity =
          (left.complete || right.complete) ? ConflictSeverity::Contradiction
                                           : ConflictSeverity::Ambiguity;
        add_conflict(out, ConflictType::DivergentDispatchCase, severity,
                     left_payload, right_payload, left.site, *left_case.selector,
                     "dispatch selector maps to competing targets at " +
                       hex_address(left.site));
      }
      break;
    }
  }

  if (left.default_target.has_value() && right.default_target.has_value() &&
      left.default_target != right.default_target)
  {
    const ConflictSeverity severity =
      (left.complete || right.complete) ? ConflictSeverity::Contradiction
                                       : ConflictSeverity::Ambiguity;
    add_conflict(out, ConflictType::DivergentDispatchCase, severity,
                 left_payload, right_payload, left.site, std::nullopt,
                 "dispatch maps have competing default targets at " +
                   hex_address(left.site));
  }

  const std::set<Address> left_targets = dispatch_targets(left);
  const std::set<Address> right_targets = dispatch_targets(right);
  if (left.complete)
  {
    for (Address target : right_targets)
    {
      if (left_targets.count(target) == 0)
      {
        add_conflict(out, ConflictType::DivergentDispatchCase,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left.site, target,
                     "observed dispatch target is absent from a complete map at " +
                       hex_address(left.site));
      }
    }
  }
  if (right.complete)
  {
    for (Address target : left_targets)
    {
      if (right_targets.count(target) == 0)
      {
        add_conflict(out, ConflictType::DivergentDispatchCase,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left.site, target,
                     "observed dispatch target is absent from a complete map at " +
                       hex_address(left.site));
      }
    }
  }
}

void compare_payloads(const FactPayload &left_payload,
                      const FactPayload &right_payload,
                      std::vector<EvidenceConflict> &out)
{
  if (const auto *left = std::get_if<CodeTargetFact>(&left_payload))
  {
    if (const auto *right = std::get_if<CodeTargetFact>(&right_payload))
    {
      if (left->from == right->from && left->kind == right->kind &&
          left->target != right->target && (left->unique || right->unique))
      {
        add_conflict(out, ConflictType::ConflictingUniqueCodeTarget,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->from, std::nullopt,
                     "sole-target assertions disagree at " + hex_address(left->from));
      }
    }
  }

  if (const auto *left = std::get_if<BranchReachabilityFact>(&left_payload))
  {
    if (const auto *right = std::get_if<BranchReachabilityFact>(&right_payload))
    {
      if (left->branch == right->branch && left->successor == right->successor &&
          opposite_reachability(left->state, right->state))
      {
        add_conflict(out, ConflictType::ReachableAndUnreachable,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->branch, left->successor,
                     "the same branch edge is both reached and proven unreachable");
      }
    }
    if (const auto *right = std::get_if<CfgCandidateFact>(&right_payload))
    {
      if (left->branch == right->from && left->successor == right->to &&
          opposite_reachability(left->state, right->state))
      {
        add_conflict(out, ConflictType::ReachableAndUnreachable,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->branch, left->successor,
                     "branch and CFG evidence disagree on edge reachability");
      }
    }
  }
  if (const auto *left = std::get_if<CfgCandidateFact>(&left_payload))
  {
    if (const auto *right = std::get_if<BranchReachabilityFact>(&right_payload))
    {
      if (left->from == right->branch && left->to == right->successor &&
          opposite_reachability(left->state, right->state))
      {
        add_conflict(out, ConflictType::ReachableAndUnreachable,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->from, left->to,
                     "CFG and branch evidence disagree on edge reachability");
      }
    }
    if (const auto *right = std::get_if<CfgCandidateFact>(&right_payload))
    {
      if (left->from == right->from && left->to == right->to &&
          opposite_reachability(left->state, right->state))
      {
        add_conflict(out, ConflictType::DivergentCfgReachability,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->from, left->to,
                     "the same CFG edge is both reached and proven unreachable");
      }
    }
  }

  if (const auto *left = std::get_if<MemoryValueFact>(&left_payload))
  {
    if (const auto *right = std::get_if<MemoryValueFact>(&right_payload))
    {
      if (left->instruction == right->instruction && left->address == right->address &&
          left->kind == right->kind && left->bytes != right->bytes)
      {
        add_conflict(out, ConflictType::DivergentMemoryValue,
                     ConflictSeverity::Variation, left_payload, right_payload,
                     left->address, left->instruction,
                     "memory value varies at " + hex_address(left->address));
      }
    }
  }

  if (const auto *left = std::get_if<StringCandidateFact>(&left_payload))
  {
    if (const auto *right = std::get_if<StringCandidateFact>(&right_payload))
    {
      if (left->address == right->address &&
          (left->encoding != right->encoding || left->bytes != right->bytes ||
           left->decoded != right->decoded ||
           left->null_terminated != right->null_terminated))
      {
        add_conflict(out, ConflictType::DivergentStringCandidate,
                     ConflictSeverity::Ambiguity, left_payload, right_payload,
                     left->address, std::nullopt,
                     "competing string interpretations begin at " +
                       hex_address(left->address));
      }
    }
  }

  if (const auto *left = std::get_if<FunctionCandidateFact>(&left_payload))
  {
    if (const auto *right = std::get_if<FunctionCandidateFact>(&right_payload))
    {
      if (left->entry == right->entry && left->end.has_value() &&
          right->end.has_value() && left->end != right->end)
      {
        add_conflict(out, ConflictType::DivergentFunctionCandidate,
                     ConflictSeverity::Ambiguity, left_payload, right_payload,
                     left->entry, std::nullopt,
                     "function candidates disagree on the end of " +
                       hex_address(left->entry));
      }
    }
  }

  if (const auto *left = std::get_if<FunctionTraitFact>(&left_payload))
  {
    if (const auto *right = std::get_if<FunctionTraitFact>(&right_payload))
    {
      if (left->function == right->function)
      {
        if (is_return_trait(left->trait) && is_return_trait(right->trait) &&
            left->trait != right->trait)
        {
          add_conflict(out, ConflictType::ReturnBehaviorContradiction,
                       ConflictSeverity::Contradiction, left_payload, right_payload,
                       left->function, std::nullopt,
                       "function is asserted both returning and no-return at " +
                         hex_address(left->function));
        }
        else if (left->trait == right->trait)
        {
          // Multiple argument-register and producer-defined Other traits are
          // naturally set-valued rather than competing scalar assertions.
          if (left->trait == FunctionTraitKind::ArgumentRegister ||
              left->trait == FunctionTraitKind::Other)
            return;
          ConflictSeverity severity = ConflictSeverity::Ambiguity;
          if (left->trait == FunctionTraitKind::StackDelta ||
              left->trait == FunctionTraitKind::ReturnConstant)
            severity = ConflictSeverity::Variation;
          add_conflict(out, ConflictType::DivergentFunctionTrait, severity,
                       left_payload, right_payload, left->function, std::nullopt,
                       "function trait has competing values at " +
                         hex_address(left->function));
        }
      }
    }
    if (const auto *right = std::get_if<FunctionOutcomeFact>(&right_payload))
    {
      if (left->function == right->function &&
          left->trait == FunctionTraitKind::NoReturn &&
          right->stop == FunctionStopKind::Returned)
      {
        add_conflict(out, ConflictType::ReturnBehaviorContradiction,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->function, std::nullopt,
                     "a concrete return contradicts a no-return trait at " +
                       hex_address(left->function));
      }
    }
  }
  if (const auto *left = std::get_if<FunctionOutcomeFact>(&left_payload))
  {
    if (const auto *right = std::get_if<FunctionTraitFact>(&right_payload))
    {
      if (left->function == right->function &&
          left->stop == FunctionStopKind::Returned &&
          right->trait == FunctionTraitKind::NoReturn)
      {
        add_conflict(out, ConflictType::ReturnBehaviorContradiction,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     left->function, std::nullopt,
                     "a concrete return contradicts a no-return trait at " +
                       hex_address(left->function));
      }
    }
    if (const auto *right = std::get_if<FunctionOutcomeFact>(&right_payload))
    {
      if (left->function == right->function &&
          (left->stop != right->stop || left->stop_pc != right->stop_pc ||
           left->stack_delta != right->stack_delta ||
           left->instruction_count != right->instruction_count))
      {
        add_conflict(out, ConflictType::DivergentFunctionOutcome,
                     ConflictSeverity::Variation, left_payload, right_payload,
                     left->function, std::nullopt,
                     "function outcomes vary across observations at " +
                       hex_address(left->function));
      }
    }
  }

  if (const auto *left = std::get_if<RegisterValueFact>(&left_payload))
  {
    if (const auto *right = std::get_if<RegisterValueFact>(&right_payload))
    {
      if (left->instruction == right->instruction && left->point == right->point &&
          left->register_id == right->register_id && left->bytes != right->bytes)
      {
        add_conflict(out, ConflictType::DivergentRegisterValue,
                     ConflictSeverity::Variation, left_payload, right_payload,
                     left->instruction, std::nullopt,
                     "register value varies at " + hex_address(left->instruction) +
                       " for " + left->register_id);
      }
    }
  }

  if (const auto *left = std::get_if<CallObservationFact>(&left_payload))
  {
    if (const auto *right = std::get_if<CallObservationFact>(&right_payload))
    {
      if (left->source == right->source)
      {
        const bool target_differs = left->target.has_value() && right->target.has_value() &&
                                    left->target != right->target;
        const bool kind_differs = left->kind != CallKind::Unknown &&
                                  right->kind != CallKind::Unknown &&
                                  left->kind != right->kind;
        const bool result_differs = left->result != CallResult::Unknown &&
                                    right->result != CallResult::Unknown &&
                                    left->result != right->result;
        const bool argument_differs =
          overlapping_call_values_differ(left->arguments, right->arguments);
        const bool return_differs =
          overlapping_call_values_differ(left->returns, right->returns);
        if (target_differs || kind_differs || result_differs ||
            argument_differs || return_differs)
        {
          add_conflict(out, ConflictType::DivergentCallObservation,
                       kind_differs ? ConflictSeverity::Ambiguity
                                    : ConflictSeverity::Variation,
                       left_payload, right_payload, left->source, std::nullopt,
                       "call target, ABI values, or outcome varies at " +
                         hex_address(left->source));
        }
      }
    }
  }

  if (const auto *left = std::get_if<CodeRegionFact>(&left_payload))
  {
    if (const auto *right = std::get_if<CodeRegionFact>(&right_payload))
    {
      const Address overlap_start = std::max(left->start, right->start);
      const Address overlap_end = std::min(left->end, right->end);
      if (overlap_start < overlap_end && region_kinds_incompatible(left->kind, right->kind))
      {
        add_conflict(out, ConflictType::IncompatibleCodeRegion,
                     ConflictSeverity::Contradiction, left_payload, right_payload,
                     overlap_start, overlap_end,
                     "overlapping regions classify bytes as both code and non-code");
      }
    }
  }

  if (const auto *left = std::get_if<DispatchMapFact>(&left_payload))
  {
    if (const auto *right = std::get_if<DispatchMapFact>(&right_payload))
      compare_dispatch_maps(left_payload, *left, right_payload, *right, out);
  }
}

bool conflicts_equal(const EvidenceConflict &lhs, const EvidenceConflict &rhs)
{
  return !conflict_less(lhs, rhs) && !conflict_less(rhs, lhs);
}

} // namespace

SupportSummary summarize_support(const EvidenceRecord &record)
{
  SupportSummary summary;
  summary.observation_count = record.observations.size();
  if (record.observations.empty())
    return summary;

  std::set<uint64_t> runs;
  std::set<uint64_t> seeds;
  std::set<std::pair<uint64_t, uint64_t>> run_seeds;
  std::set<std::string> producers;
  std::set<std::string> methods;
  std::set<uint64_t> generations;
  summary.minimum_confidence = kMaxConfidence;
  summary.minimum_generation = std::numeric_limits<uint64_t>::max();

  for (const Evidence &evidence : record.observations)
  {
    if (evidence.scope.run_id.has_value())
      runs.insert(*evidence.scope.run_id);
    if (evidence.scope.seed.has_value())
      seeds.insert(*evidence.scope.seed);
    if (evidence.scope.run_id.has_value() && evidence.scope.seed.has_value())
      run_seeds.emplace(*evidence.scope.run_id, *evidence.scope.seed);
    producers.insert(evidence.producer);
    methods.insert(evidence.method);
    generations.insert(evidence.scope.generation);
    summary.minimum_confidence = std::min(summary.minimum_confidence,
                                          evidence.confidence);
    summary.maximum_confidence = std::max(summary.maximum_confidence,
                                          evidence.confidence);
    summary.minimum_generation = std::min(summary.minimum_generation,
                                          evidence.scope.generation);
    summary.maximum_generation = std::max(summary.maximum_generation,
                                          evidence.scope.generation);
  }

  summary.distinct_run_count = runs.size();
  summary.distinct_seed_count = seeds.size();
  summary.distinct_run_seed_count = run_seeds.size();
  summary.distinct_producer_count = producers.size();
  summary.distinct_method_count = methods.size();
  summary.distinct_generation_count = generations.size();
  return summary;
}

bool is_corroborated(const EvidenceRecord &record,
                     size_t minimum_distinct_runs,
                     size_t minimum_distinct_producers,
                     uint16_t minimum_each_confidence)
{
  if (minimum_each_confidence > kMaxConfidence)
    return false;
  std::set<uint64_t> runs;
  std::set<std::string> producers;
  for (const Evidence &evidence : record.observations)
  {
    if (evidence.confidence < minimum_each_confidence)
      continue;
    if (evidence.scope.run_id.has_value())
      runs.insert(*evidence.scope.run_id);
    producers.insert(evidence.producer);
  }
  return runs.size() >= minimum_distinct_runs &&
         producers.size() >= minimum_distinct_producers;
}

bool conflict_less(const EvidenceConflict &lhs, const EvidenceConflict &rhs)
{
  return std::tie(lhs.type, lhs.severity, lhs.subject, lhs.secondary_subject,
                  lhs.left, lhs.right, lhs.explanation) <
         std::tie(rhs.type, rhs.severity, rhs.subject, rhs.secondary_subject,
                  rhs.left, rhs.right, rhs.explanation);
}

EvidenceStore::EvidenceStore() = default;
EvidenceStore::~EvidenceStore() = default;
EvidenceStore::EvidenceStore(const EvidenceStore &other) = default;
EvidenceStore::EvidenceStore(EvidenceStore &&other) noexcept = default;
EvidenceStore &EvidenceStore::operator=(const EvidenceStore &other) = default;
EvidenceStore &EvidenceStore::operator=(EvidenceStore &&other) noexcept = default;

AddResult EvidenceStore::add(AnalysisFact fact)
{
  AddResult result;
  if (!normalize_fact(fact, &result.error))
  {
    result.disposition = AddDisposition::RejectedInvalid;
    return result;
  }

  std::vector<uint8_t> key;
  if (!encode_payload(fact.payload, key, &result.error) ||
      !stable_digest(fact.payload, result.payload_digest, &result.error))
  {
    result.disposition = AddDisposition::RejectedInvalid;
    return result;
  }

  auto record_it = records_.find(key);
  if (record_it == records_.end())
  {
    EvidenceRecord record;
    record.payload = std::move(fact.payload);
    record.observations.push_back(std::move(fact.evidence));
    records_.emplace(std::move(key), std::move(record));
    result.disposition = AddDisposition::InsertedRecord;
    return result;
  }

  std::vector<Evidence> &observations = record_it->second.observations;
  auto position = std::lower_bound(observations.begin(), observations.end(),
                                   fact.evidence, evidence_less);
  if (position != observations.end() && evidence_equal(*position, fact.evidence))
  {
    result.disposition = AddDisposition::DuplicateObservation;
    return result;
  }
  observations.insert(position, std::move(fact.evidence));
  result.disposition = AddDisposition::AddedObservation;
  return result;
}

MergeReport EvidenceStore::merge(const EvidenceStore &other)
{
  MergeReport report;
  const std::vector<AnalysisFact> facts = other.flattened_facts();
  for (const AnalysisFact &fact : facts)
  {
    AddResult result = add(fact);
    switch (result.disposition)
    {
      case AddDisposition::InsertedRecord:
        ++report.inserted_records;
        break;
      case AddDisposition::AddedObservation:
        ++report.added_observations;
        break;
      case AddDisposition::DuplicateObservation:
        ++report.duplicate_observations;
        break;
      case AddDisposition::RejectedInvalid:
        ++report.rejected_observations;
        report.errors.push_back(std::move(result.error));
        break;
    }
  }
  report.records_after = record_count();
  report.observations_after = observation_count();
  report.conflicts_after = detect_conflicts().size();
  return report;
}

void EvidenceStore::clear()
{
  records_.clear();
}

size_t EvidenceStore::observation_count() const
{
  size_t total = 0;
  for (const auto &entry : records_)
    total += entry.second.observations.size();
  return total;
}

std::vector<EvidenceRecord> EvidenceStore::records() const
{
  std::vector<EvidenceRecord> result;
  result.reserve(records_.size());
  for (const auto &entry : records_)
    result.push_back(entry.second);
  return result;
}

std::vector<AnalysisFact> EvidenceStore::flattened_facts() const
{
  std::vector<AnalysisFact> result;
  result.reserve(observation_count());
  for (const auto &entry : records_)
  {
    for (const Evidence &evidence : entry.second.observations)
      result.push_back(AnalysisFact{entry.second.payload, evidence});
  }
  return result;
}

EvidenceStore EvidenceStore::latest_generation_view() const
{
  using SnapshotKey = std::pair<std::string, Address>;
  std::map<SnapshotKey, uint64_t> latest_generations;

  // Determine each producer's current generation across all payload records.
  // This must be a separate pass: a fact that exists only in an old generation
  // still has to be retired when a different payload announces the new
  // complete function snapshot.
  for (const auto &entry : records_)
  {
    for (const Evidence &evidence : entry.second.observations)
    {
      if (!evidence.scope.function_start.has_value())
        continue;
      const SnapshotKey key{evidence.producer, *evidence.scope.function_start};
      auto inserted = latest_generations.emplace(key, evidence.scope.generation);
      if (!inserted.second)
        inserted.first->second = std::max(inserted.first->second,
                                          evidence.scope.generation);
    }
  }

  EvidenceStore active;
  for (const auto &entry : records_)
  {
    EvidenceRecord active_record;
    active_record.payload = entry.second.payload;
    active_record.observations.reserve(entry.second.observations.size());
    for (const Evidence &evidence : entry.second.observations)
    {
      bool retain = true;
      if (evidence.scope.function_start.has_value())
      {
        const SnapshotKey key{evidence.producer, *evidence.scope.function_start};
        const auto latest = latest_generations.find(key);
        // Every scoped observation contributed to the first pass, so lookup
        // failure would indicate an internal invariant violation.  Failing
        // closed here cannot accidentally reactivate stale evidence.
        retain = latest != latest_generations.end() &&
                 evidence.scope.generation == latest->second;
      }
      if (retain)
        active_record.observations.push_back(evidence);
    }
    if (!active_record.observations.empty())
      active.records_.emplace(entry.first, std::move(active_record));
  }
  return active;
}

const EvidenceRecord *EvidenceStore::find(const FactPayload &payload) const
{
  std::vector<uint8_t> key;
  if (!encode_payload(payload, key, nullptr))
    return nullptr;
  const auto found = records_.find(key);
  return found == records_.end() ? nullptr : &found->second;
}

std::vector<EvidenceConflict> EvidenceStore::detect_conflicts() const
{
  const std::vector<EvidenceRecord> ordered = records();
  std::vector<EvidenceConflict> conflicts;

  // Index by the smallest subject on which facts can conflict.  This avoids an
  // all-record O(n^2) scan while preserving exhaustive pairwise comparison
  // within genuinely competing subjects.  Overlapping regions use an interval
  // sweep below; its worst case is necessarily proportional to the number of
  // overlapping pairs that may need to be reported.
  std::map<std::pair<Address, uint8_t>, std::vector<size_t>> code_targets;
  std::map<std::pair<Address, Address>, std::vector<size_t>> edges;
  std::map<std::tuple<Address, Address, uint8_t>, std::vector<size_t>> memory_values;
  std::map<Address, std::vector<size_t>> strings;
  std::map<Address, std::vector<size_t>> function_candidates;
  std::map<Address, std::vector<size_t>> function_evidence;
  std::map<Address, std::vector<size_t>> dispatch_maps;
  std::map<std::tuple<Address, uint8_t, std::string>, std::vector<size_t>> registers;
  std::map<Address, std::vector<size_t>> calls;
  std::vector<size_t> regions;

  for (size_t i = 0; i != ordered.size(); ++i)
  {
    const FactPayload &payload = ordered[i].payload;
    if (const auto *fact = std::get_if<CodeTargetFact>(&payload))
      code_targets[{fact->from, static_cast<uint8_t>(fact->kind)}].push_back(i);
    else if (const auto *fact = std::get_if<BranchReachabilityFact>(&payload))
      edges[{fact->branch, fact->successor}].push_back(i);
    else if (const auto *fact = std::get_if<CfgCandidateFact>(&payload))
      edges[{fact->from, fact->to}].push_back(i);
    else if (const auto *fact = std::get_if<MemoryValueFact>(&payload))
      memory_values[{fact->instruction, fact->address,
                     static_cast<uint8_t>(fact->kind)}].push_back(i);
    else if (const auto *fact = std::get_if<StringCandidateFact>(&payload))
      strings[fact->address].push_back(i);
    else if (const auto *fact = std::get_if<FunctionCandidateFact>(&payload))
      function_candidates[fact->entry].push_back(i);
    else if (const auto *fact = std::get_if<FunctionTraitFact>(&payload))
      function_evidence[fact->function].push_back(i);
    else if (const auto *fact = std::get_if<FunctionOutcomeFact>(&payload))
      function_evidence[fact->function].push_back(i);
    else if (const auto *fact = std::get_if<DispatchMapFact>(&payload))
      dispatch_maps[fact->site].push_back(i);
    else if (const auto *fact = std::get_if<RegisterValueFact>(&payload))
      registers[{fact->instruction, static_cast<uint8_t>(fact->point),
                 fact->register_id}].push_back(i);
    else if (const auto *fact = std::get_if<CallObservationFact>(&payload))
      calls[fact->source].push_back(i);
    else if (std::holds_alternative<CodeRegionFact>(payload))
      regions.push_back(i);
  }

  const auto compare_bucket = [&](const std::vector<size_t> &indices) {
    for (size_t i = 0; i < indices.size(); ++i)
      for (size_t j = i + 1; j < indices.size(); ++j)
        compare_payloads(ordered[indices[i]].payload,
                         ordered[indices[j]].payload, conflicts);
  };
  const auto compare_buckets = [&](const auto &buckets) {
    for (const auto &entry : buckets)
      compare_bucket(entry.second);
  };
  compare_buckets(code_targets);
  compare_buckets(edges);
  compare_buckets(memory_values);
  compare_buckets(strings);
  compare_buckets(function_candidates);
  compare_buckets(function_evidence);
  compare_buckets(dispatch_maps);
  compare_buckets(registers);
  compare_buckets(calls);

  std::sort(regions.begin(), regions.end(), [&](size_t lhs, size_t rhs) {
    const auto &left = std::get<CodeRegionFact>(ordered[lhs].payload);
    const auto &right = std::get<CodeRegionFact>(ordered[rhs].payload);
    return std::tie(left.start, left.end, lhs) < std::tie(right.start, right.end, rhs);
  });
  for (size_t i = 0; i < regions.size(); ++i)
  {
    const auto &left = std::get<CodeRegionFact>(ordered[regions[i]].payload);
    for (size_t j = i + 1; j < regions.size(); ++j)
    {
      const auto &right = std::get<CodeRegionFact>(ordered[regions[j]].payload);
      if (right.start >= left.end)
        break;
      compare_payloads(ordered[regions[i]].payload,
                       ordered[regions[j]].payload, conflicts);
    }
  }

  std::sort(conflicts.begin(), conflicts.end(), conflict_less);
  conflicts.erase(std::unique(conflicts.begin(), conflicts.end(), conflicts_equal),
                  conflicts.end());
  return conflicts;
}

bool EvidenceStore::serialize(std::vector<uint8_t> &out, std::string *error) const
{
  const std::vector<AnalysisFact> facts = flattened_facts();
  if (facts.size() > std::numeric_limits<uint64_t>::max())
    return fail(error, "evidence store contains too many observations to serialize");

  StoreWriter writer;
  writer.raw(kStoreMagic, sizeof(kStoreMagic));
  writer.u16(kStoreMajor);
  writer.u16(kStoreMinor);
  writer.u32(kStoreFlagSha256);
  writer.u64(static_cast<uint64_t>(facts.size()));
  for (const AnalysisFact &fact : facts)
  {
    std::vector<uint8_t> encoded;
    if (!encode_analysis_fact(fact, encoded, error))
      return false;
    if (encoded.size() > std::numeric_limits<uint32_t>::max())
      return fail(error, "encoded analysis fact exceeds store length limit");
    writer.u32(static_cast<uint32_t>(encoded.size()));
    writer.raw(encoded.data(), encoded.size());
  }

  const FactDigest digest = sha256_bytes(writer.bytes());
  writer.raw(digest.bytes.data(), digest.bytes.size());
  out = writer.take();
  return true;
}

bool EvidenceStore::deserialize(const std::vector<uint8_t> &blob,
                                EvidenceStore &out,
                                std::string *error,
                                const StoreCodecLimits &limits)
{
  constexpr size_t minimum_size = sizeof(kStoreMagic) + 2 + 2 + 4 + 8 + kDigestSize;
  if (blob.size() > limits.max_blob_bytes)
    return fail(error, "evidence-store blob exceeds configured decode limit");
  if (blob.size() < minimum_size)
    return fail(error, "evidence-store blob is too short");

  std::vector<uint8_t> envelope(blob.begin(), blob.end() -
    static_cast<std::ptrdiff_t>(kDigestSize));
  FactDigest expected = sha256_bytes(envelope);
  uint8_t difference = 0;
  for (size_t i = 0; i != kDigestSize; ++i)
    difference |= expected.bytes[i] ^ blob[blob.size() - kDigestSize + i];
  if (difference != 0)
    return fail(error, "evidence-store SHA-256 integrity check failed");

  StoreReader reader(envelope);
  uint16_t major = 0, minor = 0;
  uint32_t flags = 0;
  uint64_t count = 0;
  if (!reader.magic() || !reader.u16(major) || !reader.u16(minor) ||
      !reader.u32(flags) || !reader.u64(count))
    return fail(error, reader.error());
  if (major != kStoreMajor || minor != kStoreMinor)
    return fail(error, "unsupported evidence-store schema version");
  if (flags != kStoreFlagSha256)
    return fail(error, "unsupported evidence-store feature flags");
  if (count > limits.max_observations || count > std::numeric_limits<size_t>::max())
    return fail(error, "evidence-store observation count exceeds configured limit");

  EvidenceStore decoded;
  std::optional<AnalysisFact> previous;
  for (uint64_t i = 0; i != count; ++i)
  {
    uint32_t fact_size = 0;
    if (!reader.u32(fact_size))
      return fail(error, reader.error());
    if (fact_size > limits.fact_limits.max_fact_bytes)
      return fail(error, "encoded fact exceeds configured decode limit");
    std::vector<uint8_t> fact_bytes;
    if (!reader.blob(fact_size, fact_bytes))
      return fail(error, reader.error());
    AnalysisFact fact;
    std::string fact_error;
    if (!decode_analysis_fact(fact_bytes, fact, &fact_error, limits.fact_limits))
      return fail(error, "invalid fact in evidence store: " + fact_error);
    if (previous.has_value() && !analysis_fact_less(*previous, fact))
      return fail(error, "evidence-store observations are duplicated or non-canonical");
    previous = fact;
    AddResult added = decoded.add(std::move(fact));
    if (added.disposition == AddDisposition::DuplicateObservation ||
        added.disposition == AddDisposition::RejectedInvalid)
      return fail(error, "evidence-store contains a duplicate or rejected observation");
  }
  if (reader.remaining() != 0)
    return fail(error, "evidence-store envelope has trailing bytes");

  // Full byte equality is a strong canonicality check and catches any future
  // encoder/decoder discrepancy not covered above.
  std::vector<uint8_t> canonical;
  std::string canonical_error;
  if (!decoded.serialize(canonical, &canonical_error))
    return fail(error, "failed to re-encode evidence store: " + canonical_error);
  if (canonical != blob)
    return fail(error, "evidence-store blob is valid but non-canonical");

  out = std::move(decoded);
  return true;
}

bool EvidenceStore::persist(EvidencePersistenceAdapter &adapter,
                            std::string *error) const
{
  std::vector<uint8_t> blob;
  if (!serialize(blob, error))
    return false;
  std::string adapter_error;
  if (!adapter.write_blob(blob, adapter_error))
    return fail(error, adapter_error.empty() ? "persistence adapter write failed"
                                             : adapter_error);
  return true;
}

bool EvidenceStore::restore(const EvidencePersistenceAdapter &adapter,
                            RestoreMode mode,
                            MergeReport *report,
                            std::string *error,
                            const StoreCodecLimits &limits)
{
  std::vector<uint8_t> blob;
  std::string adapter_error;
  if (!adapter.read_blob(blob, adapter_error))
    return fail(error, adapter_error.empty() ? "persistence adapter read failed"
                                             : adapter_error);
  EvidenceStore decoded;
  if (!deserialize(blob, decoded, error, limits))
    return false;

  if (mode == RestoreMode::Replace)
  {
    MergeReport replacement;
    replacement.inserted_records = decoded.record_count();
    replacement.added_observations = decoded.observation_count() -
                                     decoded.record_count();
    replacement.records_after = decoded.record_count();
    replacement.observations_after = decoded.observation_count();
    replacement.conflicts_after = decoded.detect_conflicts().size();
    *this = std::move(decoded);
    if (report != nullptr)
      *report = std::move(replacement);
    return true;
  }

  MergeReport merged = merge(decoded);
  if (report != nullptr)
    *report = std::move(merged);
  return true;
}

} // namespace analysis
} // namespace viy
